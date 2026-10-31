package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sharelib-jp/auth-service/internal/oauth"
)

func TestBrowserConsentPageUsesValidatedRequest(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "consent-page")
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != http.StatusSeeOther {
		t.Fatalf("authorization: %d %s", start.Code, start.Body.String())
	}
	continueURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	handle := continueURL.Query().Get("request")
	browserRequest := httptest.NewRequest("GET", testOrigin+continueURL.String(), nil)
	browserRequest.Header.Set("Accept", "text/html,application/xhtml+xml")
	for _, cookie := range client.cookies {
		browserRequest.AddCookie(cookie)
	}
	browserResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(browserResponse, browserRequest)
	if browserResponse.Code != http.StatusSeeOther || browserResponse.Header().Get("Location") != "/oauth2/v1/auth?request="+handle {
		t.Fatalf("browser redirect: %d %s", browserResponse.Code, browserResponse.Header().Get("Location"))
	}
	path := "/api/oauth2/consent?request=" + handle
	otherBrowser := httptest.NewRequest("GET", testOrigin+path, nil)
	otherResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(otherResponse, otherBrowser)
	if otherResponse.Code != http.StatusBadRequest {
		t.Fatalf("request was not bound to browser: %d", otherResponse.Code)
	}
	crossOrigin := httptest.NewRequest("GET", testOrigin+path, nil)
	crossOrigin.Header.Set("Origin", "https://evil.example")
	for _, cookie := range client.cookies {
		crossOrigin.AddCookie(cookie)
	}
	crossResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(crossResponse, crossOrigin)
	if crossResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: %d", crossResponse.Code)
	}
	response := oauthHTTP(client, "GET", path, nil, "")
	var details struct {
		Client string `json:"client_name"`
		User   string `json:"user_name"`
		Email  string `json:"user_email"`
		CSRF   string `json:"csrf"`
		Scopes []struct {
			Name           string `json:"name"`
			Description    string `json:"description"`
			Resource       string `json:"resource"`
			AlreadyGranted bool   `json:"already_granted"`
		} `json:"scopes"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &details) != nil || details.Client != "C" || details.User != user.Name || details.Email != user.Email || len(details.CSRF) != 43 || len(details.Scopes) != 1 || details.Scopes[0].Name != "b.orders.read" || details.Scopes[0].Description != "注文履歴を読む" || details.Scopes[0].Resource != "B" || details.Scopes[0].AlreadyGranted {
		t.Fatalf("details: %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers: %v", response.Header())
	}
	// The server must reject an approval when the policy changed after display.
	if err := oauth.NewCatalog(db).UpdateScopePolicy(t.Context(), "read", "新しい利用条件", "orders"); err != nil {
		t.Fatal(err)
	}
	decision := url.Values{"request": {handle}, "csrf": {details.CSRF}, "decision": {"allow"}}
	stale := oauthHTTP(client, "POST", "/api/oauth2/consent", decision, testOrigin)
	if stale.Code == http.StatusSeeOther && strings.Contains(stale.Header().Get("Location"), "code=") {
		t.Fatalf("accepted stale consent: %s", stale.Header().Get("Location"))
	}
	updated := oauthHTTP(client, "GET", path, nil, "")
	if updated.Code != http.StatusOK || json.Unmarshal(updated.Body.Bytes(), &details) != nil || details.Scopes[0].Description != "新しい利用条件" {
		t.Fatalf("updated consent: %d %s", updated.Code, updated.Body.String())
	}
	decision.Set("csrf", details.CSRF)
	decision.Set("decision", "deny")
	denied := oauthHTTP(client, "POST", "/api/oauth2/consent", decision, testOrigin)
	if denied.Code != http.StatusSeeOther || !strings.Contains(denied.Header().Get("Location"), "error=access_denied") {
		t.Fatalf("denial: %d %s", denied.Code, denied.Header().Get("Location"))
	}
	if reused := oauthHTTP(client, "GET", path, nil, ""); reused.Code != http.StatusBadRequest {
		t.Fatalf("consumed request reused: %d", reused.Code)
	}

	start = oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
	continueURL, err = url.Parse(start.Header().Get("Location"))
	if err != nil || start.Code != http.StatusSeeOther {
		t.Fatalf("new request: %d %v", start.Code, err)
	}
	handle = continueURL.Query().Get("request")
	path = "/api/oauth2/consent?request=" + handle
	response = oauthHTTP(client, "GET", path, nil, "")
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &details) != nil {
		t.Fatalf("new details: %d %s", response.Code, response.Body.String())
	}
	decision = url.Values{"request": {handle}, "csrf": {strings.Repeat("x", 43)}, "decision": {"allow"}}
	if badCSRF := oauthHTTP(client, "POST", "/api/oauth2/consent", decision, testOrigin); badCSRF.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF accepted: %d", badCSRF.Code)
	}
	decision.Set("csrf", details.CSRF)
	approved := oauthHTTP(client, "POST", "/api/oauth2/consent", decision, testOrigin)
	callback, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || approved.Code != http.StatusSeeOther || callback.Query().Get("code") == "" {
		t.Fatalf("approval: %d %s", approved.Code, approved.Header().Get("Location"))
	}
	token := oauthHTTP(client, "POST", "/api/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
	if token.Code != http.StatusOK || !strings.Contains(token.Body.String(), `"access_token"`) {
		t.Fatalf("token exchange: %d %s", token.Code, token.Body.String())
	}
}

func TestDiscoveryAndRetiredEndpointPaths(t *testing.T) {
	client, _ := oauthTestService(t)
	response := oauthHTTP(client, "GET", "/.well-known/openid-configuration", nil, "")
	var metadata map[string]any
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &metadata) != nil {
		t.Fatalf("discovery: %d %s", response.Code, response.Body.String())
	}
	for name, path := range map[string]string{
		"authorization_endpoint": "/api/oauth2/authorize",
		"token_endpoint":         "/api/oauth2/token",
		"revocation_endpoint":    "/api/oauth2/revoke",
		"introspection_endpoint": "/api/oauth2/introspect",
		"userinfo_endpoint":      "/api/userinfo",
		"jwks_uri":               "/.well-known/jwks.json",
	} {
		if metadata[name] != testOrigin+path {
			t.Errorf("%s = %v, want %s", name, metadata[name], testOrigin+path)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/.well-known/nodeinfo"}, {"GET", "/api/.well-known/header"},
		{"GET", "/oauth2/authorize"}, {"GET", "/oauth2/continue"},
		{"POST", "/oauth2/consent"}, {"POST", "/oauth2/token"},
		{"POST", "/oauth2/revoke"}, {"POST", "/oauth2/introspect"},
		{"GET", "/userinfo"}, {"POST", "/userinfo"},
	} {
		response := oauthHTTP(client, tc.method, tc.path, nil, "")
		if response.Code != http.StatusNotFound {
			t.Errorf("%s %s: status = %d, want 404", tc.method, tc.path, response.Code)
		}
	}
}
