package api

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func (h *oauthHandler) metadata() gin.H {
	return gin.H{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.issuer + "/oauth2/authorize",
		"token_endpoint":                        h.issuer + "/oauth2/token",
		"revocation_endpoint":                   h.issuer + "/oauth2/revoke",
		"introspection_endpoint":                h.issuer + "/oauth2/introspect",
		"jwks_uri":                              h.issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
}

func (h *oauthHandler) openIDDiscovery(c *gin.Context) {
	metadata := h.metadata()
	metadata["userinfo_endpoint"] = h.issuer + "/userinfo"
	metadata["subject_types_supported"] = []string{"public"}
	metadata["id_token_signing_alg_values_supported"] = []string{"RS256"}
	metadata["claims_supported"] = []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce"}
	c.JSON(http.StatusOK, metadata)
}

func (h *oauthHandler) oauthDiscovery(c *gin.Context) { c.JSON(http.StatusOK, h.metadata()) }
func (h *oauthHandler) jwks(c *gin.Context) {
	c.JSON(http.StatusOK, h.publicKeys)
}

func (h *oauthHandler) token(c *gin.Context) {
	if !parseOAuthForm(c) {
		return
	}
	ctx := c.Request.Context()
	for _, key := range []string{"resource", "audience", "authorization_details"} {
		if c.Request.PostForm.Has(key) {
			h.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrInvalidRequest.WithHint("resource must be selected during authorization"))
			return
		}
	}
	req, err := h.provider.NewAccessRequest(ctx, c.Request, oauth.NewSession())
	if err != nil {
		h.provider.WriteAccessError(ctx, c.Writer, req, err)
		return
	}
	if c.Request.PostForm.Get("grant_type") == "refresh_token" && c.Request.PostForm.Has("scope") {
		if err := h.store.NarrowRefreshRequest(ctx, req, c.Request.PostForm.Get("scope")); err != nil {
			h.provider.WriteAccessError(ctx, c.Writer, req, err)
			return
		}
	}
	resp, err := h.provider.NewAccessResponse(ctx, req)
	if err != nil {
		// Two refreshes may both read the old token before one rotates it.
		// Fosite rolls back the losing transaction; re-run its authenticated
		// reuse check so the newly issued token family is revoked as well.
		grantType := c.Request.PostForm.Get("grant_type")
		reuse := (grantType == "refresh_token" && errors.Is(err, fosite.ErrInactiveToken)) || (grantType == "authorization_code" && errors.Is(err, fosite.ErrInvalidatedAuthorizeCode))
		if reuse {
			_, replayErr := h.provider.NewAccessRequest(ctx, c.Request, oauth.NewSession())
			if !errors.Is(replayErr, fosite.ErrInvalidGrant) {
				h.provider.WriteAccessError(ctx, c.Writer, req, fosite.ErrServerError)
				return
			}
		}
		h.provider.WriteAccessError(ctx, c.Writer, req, err)
		return
	}
	h.provider.WriteAccessResponse(ctx, c.Writer, req, resp)
}

func (h *oauthHandler) revoke(c *gin.Context) {
	if !parseOAuthForm(c) {
		return
	}
	if c.Request.PostForm.Get("token") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	ctx := c.Request.Context()
	err := h.store.Transaction(ctx, func(txCtx context.Context, _ *gorm.DB) error {
		return h.provider.NewRevocationRequest(txCtx, c.Request)
	})
	// Fosite's response writer maps some storage failures to 200. A failed
	// transaction must be retried rather than reported as a successful revoke.
	if err != nil && !errors.Is(err, fosite.ErrInvalidRequest) && !errors.Is(err, fosite.ErrInvalidClient) && !errors.Is(err, fosite.ErrUnauthorizedClient) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "temporarily_unavailable"})
		return
	}
	h.provider.WriteRevocationResponse(ctx, c.Writer, err)
}

func (h *oauthHandler) introspect(c *gin.Context) {
	resource, ok := h.authenticateResource(c)
	if !ok {
		return
	}
	if !parseOAuthForm(c) {
		return
	}
	if c.Request.PostForm.Get("token") == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	use, request, err := h.provider.IntrospectToken(c.Request.Context(), c.Request.PostForm.Get("token"), fosite.AccessToken, oauth.NewSession())
	if err != nil || request == nil || use != fosite.AccessToken || !request.GetGrantedAudience().Has(resource.Identifier) {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"active": true, "client_id": request.GetClient().GetID(), "sub": request.GetSession().GetSubject(),
		"scope": strings.Join(request.GetGrantedScopes(), " "), "aud": request.GetGrantedAudience(), "iss": h.issuer,
		"exp": request.GetSession().GetExpiresAt(fosite.AccessToken).Unix(), "token_type": "Bearer",
	})
}

// Bound every untrusted protocol field before passing it to Fosite. Its HMAC
// parser splits token values, so this also bounds allocations for malformed tokens.
func parseOAuthForm(c *gin.Context) bool {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" || len(c.GetHeader("Authorization")) > 4096 || c.Request.URL.RawQuery != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return false
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<10)
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return false
	}
	for _, values := range c.Request.PostForm {
		if len(values) != 1 || len(values[0]) > 4096 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return false
		}
	}
	return true
}

func (h *oauthHandler) authenticateResource(c *gin.Context) (*oauth.Resource, bool) {
	if len(c.GetHeader("Authorization")) > 4096 {
		c.Status(http.StatusUnauthorized)
		return nil, false
	}
	id, secret, ok := c.Request.BasicAuth()
	if !ok || id == "" || secret == "" {
		c.Header("WWW-Authenticate", `Basic realm="resource"`)
		c.Status(http.StatusUnauthorized)
		return nil, false
	}
	var credential oauth.ResourceCredential
	err := h.db.WithContext(c.Request.Context()).Where("id = ? AND status = ?", id, "active").First(&credential).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		serverError(c, err)
		return nil, false
	}
	if err != nil || bcrypt.CompareHashAndPassword(credential.SecretHash, []byte(secret)) != nil {
		c.Header("WWW-Authenticate", `Basic realm="resource"`)
		c.Status(http.StatusUnauthorized)
		return nil, false
	}
	var resource oauth.Resource
	err = h.db.WithContext(c.Request.Context()).Where("id = ? AND status = ?", credential.ResourceID, "active").First(&resource).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		serverError(c, err)
		return nil, false
	}
	if err != nil {
		c.Status(http.StatusUnauthorized)
		return nil, false
	}
	return &resource, true
}

func (h *oauthHandler) userinfo(c *gin.Context) {
	if len(c.GetHeader("Authorization")) > 4096 {
		c.Status(http.StatusUnauthorized)
		return
	}
	parts := strings.Fields(c.GetHeader("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		c.Header("WWW-Authenticate", "Bearer")
		c.Status(http.StatusUnauthorized)
		return
	}
	use, request, err := h.provider.IntrospectToken(c.Request.Context(), parts[1], fosite.AccessToken, oauth.NewSession())
	if err != nil || request == nil || use != fosite.AccessToken || !request.GetGrantedScopes().Has("openid") {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
		c.Status(http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, gin.H{"sub": request.GetSession().GetSubject()})
}
