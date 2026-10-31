package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
)

func (h *oauthHandler) browserCookieName() string {
	if h.secure {
		return "__Host-sharelib_oauth_browser"
	}
	return "sharelib_oauth_browser"
}

// prepareAuthorization reconstructs every request from server-held parameters
// and performs both Fosite's checks and strict application registration checks.
func (h *oauthHandler) prepareAuthorization(ctx context.Context, values url.Values) (fosite.AuthorizeRequester, error) {
	if len(values.Encode()) > 8192 {
		return nil, fosite.ErrInvalidRequest
	}
	for _, items := range values {
		if len(items) != 1 {
			return nil, fosite.ErrInvalidRequest
		}
	}
	for _, forbidden := range []string{"audience", "request", "request_uri", "registration", "claims", "authorization_details"} {
		if values.Has(forbidden) {
			return nil, fosite.ErrInvalidRequest
		}
	}
	if mode := values.Get("response_mode"); mode != "" && mode != "query" {
		return nil, fosite.ErrInvalidRequest
	}
	form := url.Values{}
	for key, items := range values {
		form[key] = append([]string(nil), items...)
	}
	if resource := form.Get("resource"); resource != "" {
		form.Set("audience", resource)
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, h.issuer+oauth.AuthorizePath+"?"+form.Encode(), nil)
	if err != nil {
		return nil, err
	}
	request, err := h.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		return request, err
	}
	_, err = oauth.NewAuthorizationService(h.db).Evaluate(ctx, request, uuid.New())
	return request, err
}

func safeRedirect(req fosite.AuthorizeRequester) bool {
	if req == nil || req.GetClient() == nil || !req.IsRedirectURIValid() {
		return false
	}
	raw := req.GetRequestForm().Get("redirect_uri")
	for _, registered := range req.GetClient().GetRedirectURIs() {
		if raw != "" && raw == registered {
			return true
		}
	}
	return false
}

func (h *oauthHandler) authorizeError(c *gin.Context, req fosite.AuthorizeRequester, err error) {
	if safeRedirect(req) {
		h.provider.WriteAuthorizeError(c.Request.Context(), c.Writer, req, err)
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
}

func (h *oauthHandler) browser(c *gin.Context) (string, error) {
	value, _ := c.Cookie(h.browserCookieName())
	if oauth.ValidBrowserToken(value) {
		return value, nil
	}
	value, err := oauth.RandomBrowserToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(c.Writer, &http.Cookie{Name: h.browserCookieName(), Value: value, Path: "/", HttpOnly: true, Secure: h.secure, SameSite: http.SameSiteLaxMode, MaxAge: 3600})
	return value, nil
}

func (h *oauthHandler) authorize(c *gin.Context) {
	if len(c.Request.URL.RawQuery) > 8192 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	values, parseErr := url.ParseQuery(c.Request.URL.RawQuery)
	if parseErr != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	req, err := h.prepareAuthorization(c.Request.Context(), values)
	if err != nil {
		h.authorizeError(c, req, err)
		return
	}
	browser, err := h.browser(c)
	if err != nil {
		serverError(c, err)
		return
	}
	handle, err := h.store.CreatePending(c.Request.Context(), values, browser)
	if err != nil {
		serverError(c, err)
		return
	}
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(http.StatusSeeOther, oauth.ContinuePath+"?request="+url.QueryEscape(handle))
}

func (h *oauthHandler) pendingRequest(c *gin.Context, handle string) (string, fosite.AuthorizeRequester, error) {
	browser, err := c.Cookie(h.browserCookieName())
	if err != nil {
		return "", nil, oauth.ErrPendingAuthorization
	}
	values, err := h.store.GetPending(c.Request.Context(), handle, browser)
	if err != nil {
		return "", nil, err
	}
	req, err := h.prepareAuthorization(c.Request.Context(), values)
	return browser, req, err
}

func (h *oauthHandler) continueAuthorization(c *gin.Context) {
	c.Header("Referrer-Policy", "no-referrer")
	handle := c.Query("request")
	browser, req, err := h.pendingRequest(c, handle)
	if err != nil {
		h.authorizeError(c, req, err)
		return
	}
	user, authenticatedAt, err := h.service.AuthenticateAt(c.Request.Context(), oauthSessionCookie(c, h.secure))
	if err != nil {
		if !errors.Is(err, identity.ErrUnauthenticated) {
			serverError(c, err)
			return
		}
		if req.GetRequestForm().Get("prompt") == "none" {
			h.authorizeError(c, req, fosite.ErrLoginRequired)
			return
		}
		c.Redirect(http.StatusSeeOther, "/login/?oauth_request="+url.QueryEscape(handle))
		return
	}
	decision, err := oauth.NewAuthorizationService(h.db).Evaluate(c.Request.Context(), req, user.ID)
	if err != nil {
		h.authorizeError(c, req, err)
		return
	}
	if decision.NeedsConsent() && req.GetRequestForm().Get("prompt") == "none" {
		h.authorizeError(c, req, fosite.ErrConsentRequired)
		return
	}
	if decision.NeedsConsent() {
		c.Redirect(http.StatusSeeOther, "/oauth2/v1/auth?request="+url.QueryEscape(handle))
		return
	}
	snapshot, err := decision.Snapshot()
	if err != nil {
		serverError(c, err)
		return
	}
	csrf, err := h.store.IssueConsentCSRF(c.Request.Context(), handle, browser, user.ID, snapshot)
	if err != nil {
		serverError(c, err)
		return
	}
	h.finishAuthorization(c, handle, browser, csrf, user.ID, authenticatedAt, req, true)
}

// consentDetails returns only server-validated information bound to the browser
// and authenticated session. The posted decision is revalidated separately.
func (h *oauthHandler) consentDetails(c *gin.Context) {
	c.Header("Referrer-Policy", "no-referrer")
	if origin := c.GetHeader("Origin"); (origin != "" && origin != h.issuer) || c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		c.Status(http.StatusForbidden)
		return
	}
	values, err := url.ParseQuery(c.Request.URL.RawQuery)
	if err != nil || len(values) != 1 || len(values["request"]) != 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	handle := values.Get("request")
	browser, req, err := h.pendingRequest(c, handle)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	user, _, err := h.service.AuthenticateAt(c.Request.Context(), oauthSessionCookie(c, h.secure))
	if errors.Is(err, identity.ErrUnauthenticated) {
		c.Status(http.StatusUnauthorized)
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	decision, err := oauth.NewAuthorizationService(h.db).Evaluate(c.Request.Context(), req, user.ID)
	if err != nil || !decision.NeedsConsent() || req.GetRequestForm().Get("prompt") == "none" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	snapshot, err := decision.Snapshot()
	if err != nil {
		serverError(c, err)
		return
	}
	csrf, err := h.store.IssueConsentCSRF(c.Request.Context(), handle, browser, user.ID, snapshot)
	if errors.Is(err, oauth.ErrPendingAuthorization) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	type scopeDetails struct {
		Name           string `json:"name"`
		Description    string `json:"description"`
		Purpose        string `json:"purpose"`
		Resource       string `json:"resource"`
		AlreadyGranted bool   `json:"already_granted"`
	}
	missing := make(map[string]bool, len(decision.Missing))
	for _, scope := range decision.Missing {
		missing[scope.Name] = true
	}
	scopes := make([]scopeDetails, 0, len(decision.Scopes))
	for _, scope := range decision.Scopes {
		resource := decision.Resource.Name
		if scope.ResourceID == oauth.IdentityResource {
			resource = "アカウント情報"
		}
		scopes = append(scopes, scopeDetails{scope.Name, scope.Description, scope.PurposeCode, resource, !missing[scope.Name]})
	}
	c.JSON(http.StatusOK, gin.H{
		"client_name": decision.ClientName, "user_name": user.Name, "user_email": user.Email,
		"scopes": scopes, "offline_access": decision.OfflineAccess, "csrf": csrf,
	})
}

func (h *oauthHandler) consent(c *gin.Context) {
	if c.GetHeader("Origin") != h.issuer {
		c.Status(http.StatusForbidden)
		return
	}
	if !strings.HasPrefix(c.GetHeader("Content-Type"), "application/x-www-form-urlencoded") {
		c.Status(http.StatusUnsupportedMediaType)
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
	for _, key := range []string{"request", "csrf", "decision"} {
		if len(c.Request.PostForm[key]) != 1 {
			c.Status(http.StatusBadRequest)
			return
		}
	}
	handle, csrf, choice := c.Request.PostForm.Get("request"), c.Request.PostForm.Get("csrf"), c.Request.PostForm.Get("decision")
	if choice != "allow" && choice != "deny" {
		c.Status(http.StatusBadRequest)
		return
	}
	browser, req, err := h.pendingRequest(c, handle)
	if err != nil {
		h.authorizeError(c, req, err)
		return
	}
	user, authenticatedAt, err := h.service.AuthenticateAt(c.Request.Context(), oauthSessionCookie(c, h.secure))
	if err != nil {
		c.Status(http.StatusUnauthorized)
		return
	}
	h.finishAuthorization(c, handle, browser, csrf, user.ID, authenticatedAt, req, choice == "allow")
}

func (h *oauthHandler) finishAuthorization(c *gin.Context, handle, browser, csrf string, userID uuid.UUID, authenticatedAt time.Time, req fosite.AuthorizeRequester, allow bool) {
	var response fosite.AuthorizeResponder
	err := h.store.Transaction(c.Request.Context(), func(ctx context.Context, tx *gorm.DB) error {
		if !allow {
			if err := h.store.ConsumePending(ctx, handle, browser, csrf, userID, ""); err != nil {
				return err
			}
			return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "authorization_denied", ClientID: req.GetClient().GetID(), Resource: req.GetRequestForm().Get("resource"), Result: "denied", VisibleToUser: true})
		}
		decision, err := oauth.NewAuthorizationService(tx).WithLocks().Evaluate(ctx, req, userID)
		if err != nil {
			return err
		}
		snapshot, err := decision.Snapshot()
		if err != nil {
			return err
		}
		if err := h.store.ConsumePending(ctx, handle, browser, csrf, userID, snapshot); err != nil {
			return err
		}
		grants := append([]uuid.UUID(nil), decision.GrantIDs...)
		service := consent.NewService(consent.NewRepository(tx))
		for _, scope := range decision.Missing {
			grant, err := service.Create(ctx, consent.Grant{UserID: userID, ClientID: req.GetClient().GetID(), Resource: oauth.ConsentResource(scope, decision.Resource), Scopes: []string{scope.Name}, PurposeCode: scope.PurposeCode, PolicyVersion: scope.PolicyVersion})
			if err != nil {
				return err
			}
			grants = append(grants, grant.ID)
		}
		for _, scope := range req.GetRequestedScopes() {
			req.GrantScope(scope)
		}
		for _, audience := range req.GetRequestedAudience() {
			req.GrantAudience(audience)
		}
		session := oauth.NewSession()
		session.SetSubject(userID.String())
		session.GrantIDs = grants
		session.IDTokenClaims().Subject = userID.String()
		session.IDTokenClaims().AuthTime = authenticatedAt
		session.IDTokenClaims().RequestedAt = req.GetRequestedAt()
		response, err = h.provider.NewAuthorizeResponse(ctx, req, session)
		if err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "authorization_approved", ClientID: req.GetClient().GetID(), Resource: req.GetRequestForm().Get("resource"), Result: "success", VisibleToUser: true})
	})
	if errors.Is(err, oauth.ErrPendingAuthorization) {
		c.Status(http.StatusForbidden)
		return
	}
	if err != nil {
		h.authorizeError(c, req, err)
		return
	}
	if !allow {
		h.authorizeError(c, req, fosite.ErrAccessDenied)
		return
	}
	h.provider.WriteAuthorizeResponse(c.Request.Context(), c.Writer, req, response)
}
