package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/oauth"
)

type loginOnlyTokens struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	ID      string `json:"id_token"`
}

func TestLoginOnlyOIDCRefreshConsentRotationAndRevocation(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "login-refresh")
	secret := strings.Repeat("r", 32)
	registration := oauth.Client{ID: "repository-service", Name: "Repository", RedirectURIs: []string{"https://c.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "profile", "email", "offline_access"}, Audience: []string{}}
	if err := oauth.NewCatalog(db).RegisterClient(t.Context(), registration, secret); err != nil {
		t.Fatal(err)
	}
	exchange := func(values url.Values, status int) loginOnlyTokens {
		t.Helper()
		req := httptest.NewRequest("POST", testOrigin+"/api/oauth2/token", strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(registration.ID, secret)
		w := httptest.NewRecorder()
		client.handler.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("token endpoint: %d wanted %d: %s", w.Code, status, w.Body.String())
		}
		var tokens loginOnlyTokens
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil || tokens.Access == "" {
				t.Fatal("missing access token")
			}
		} else {
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Error != "invalid_grant" {
				t.Fatalf("unexpected refresh error: %s", w.Body.String())
			}
		}
		return tokens
	}
	authorize := func(scopes string) loginOnlyTokens {
		t.Helper()
		verifier := strings.Repeat("v", 43)
		challenge := sha256.Sum256([]byte(verifier))
		values := url.Values{"client_id": {registration.ID}, "response_type": {"code"}, "redirect_uri": {registration.RedirectURIs[0]}, "scope": {scopes}, "prompt": {"consent"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
		start := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
		if start.Code != 303 {
			t.Fatalf("authorization failed: %d %s", start.Code, start.Body.String())
		}
		details, csrf := oauthReview(t, client, start.Header().Get("Location"))
		if strings.Contains(scopes, "offline_access") && !strings.Contains(details.Body.String(), "トークンの自動更新") {
			t.Fatal("offline-access consent missing")
		}
		pending, _ := url.Parse(start.Header().Get("Location"))
		approved := oauthHTTP(client, "POST", "/api/oauth2/consent", url.Values{"request": {pending.Query().Get("request")}, "csrf": {csrf}, "decision": {"allow"}}, testOrigin)
		callback, err := url.Parse(approved.Header().Get("Location"))
		if err != nil || approved.Code != 303 || callback.Query().Get("code") == "" {
			t.Fatalf("approval failed: %d %s %s", approved.Code, approved.Header().Get("Location"), approved.Body.String())
		}
		return exchange(url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {registration.RedirectURIs[0]}, "code_verifier": {verifier}}, 200)
	}
	userinfo := func(token string, status int) {
		t.Helper()
		req := httptest.NewRequest("GET", testOrigin+"/api/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		client.handler.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("userinfo: %d wanted %d", w.Code, status)
		}
	}
	refresh := func(token string, status int) loginOnlyTokens {
		return exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, status)
	}

	initial := authorize("openid profile email offline_access")
	if initial.Refresh == "" || initial.ID == "" {
		t.Fatal("login-only client did not receive refresh/ID tokens")
	}
	var grants []consent.Grant
	if err := db.Where("user_id = ? AND client_id = ?", user.ID, registration.ID).Find(&grants).Error; err != nil || len(grants) != 3 {
		t.Fatalf("login-only consent grants: %d %v", len(grants), err)
	}
	for _, grant := range grants {
		if grant.Resource != oauth.IdentityResource {
			t.Fatal("login-only consent incorrectly depends on a business resource")
		}
	}
	rotated := refresh(initial.Refresh, 200)
	if rotated.Refresh == "" || rotated.Refresh == initial.Refresh {
		t.Fatal("refresh token was not rotated")
	}
	userinfo(rotated.Access, 200)
	refresh(initial.Refresh, 400)
	userinfo(rotated.Access, 401)
	refresh(rotated.Refresh, 400)

	// New pure-identity sessions have a separately revocable offline grant.
	next := authorize("openid profile email offline_access")
	profileOnly := authorize("openid profile")
	if profileOnly.Refresh != "" {
		t.Fatal("refresh was issued without offline_access")
	}
	grants = nil
	if err := db.Where("user_id = ? AND client_id = ? AND status = ?", user.ID, registration.ID, consent.Active).Find(&grants).Error; err != nil {
		t.Fatal(err)
	}
	found := false
	for _, grant := range grants {
		if len(grant.Scopes) == 1 && grant.Scopes[0] == "offline_access" {
			found = true
			client.do(t, "DELETE", "/api/me/consents/"+grant.ID.String(), nil, 204)
		}
	}
	if !found {
		t.Fatal("offline access has no revocable grant")
	}
	userinfo(next.Access, 401)
	refresh(next.Refresh, 400)
	userinfo(profileOnly.Access, 200)

	// openid + offline_access alone also has a real revocable consent.
	minimal := authorize("openid offline_access")
	if minimal.Refresh == "" {
		t.Fatal("minimal identity refresh was rejected")
	}
	userinfo(refresh(minimal.Refresh, 200).Access, 200)
}

func TestOfflineAccessRequiresRefreshGrantRegistration(t *testing.T) {
	client, db := oauthTestService(t)
	client.register(t, "no-refresh-grant")
	registration := oauth.Client{ID: "login-code-only", Name: "No refresh", Public: true, RedirectURIs: []string{"https://c.example/callback"}, GrantTypes: []string{"authorization_code"}, Scopes: []string{"openid", "offline_access"}, Audience: []string{}}
	if err := oauth.NewCatalog(db).RegisterClient(t.Context(), registration, ""); err != nil {
		t.Fatal(err)
	}
	challenge := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	values := url.Values{"client_id": {registration.ID}, "response_type": {"code"}, "redirect_uri": {registration.RedirectURIs[0]}, "scope": {"openid offline_access"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	start := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
	callback, err := url.Parse(start.Header().Get("Location"))
	if err != nil || callback.Query().Get("error") != "unauthorized_client" {
		t.Fatalf("unregistered refresh grant accepted: %d %s", start.Code, start.Header().Get("Location"))
	}
}
