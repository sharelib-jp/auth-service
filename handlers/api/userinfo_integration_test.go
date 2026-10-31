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

	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/oauth"
)

func TestUserInfoScopesConsentAndRevocation(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "userinfo")
	if err := oauth.NewCatalog(db).RegisterClient(t.Context(), oauth.Client{
		ID: "userinfo-client", Name: "UserInfo client", Public: true,
		RedirectURIs: []string{"https://c.example/callback"},
		GrantTypes:   []string{"authorization_code"}, Scopes: []string{"openid", "profile", "email"},
	}, ""); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	authorize := func(scope string, expectConsent bool, allow bool) string {
		t.Helper()
		values := url.Values{"client_id": {"userinfo-client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {scope}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
		start := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
		if start.Code != http.StatusSeeOther {
			t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
		}
		page := oauthHTTP(client, "GET", start.Header().Get("Location"), nil, "")
		if expectConsent {
			_, csrf := oauthReview(t, client, start.Header().Get("Location"))
			pending, err := url.Parse(start.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			decision := "deny"
			if allow {
				decision = "allow"
			}
			page = oauthHTTP(client, "POST", "/api/oauth2/consent", url.Values{"request": {pending.Query().Get("request")}, "csrf": {csrf}, "decision": {decision}}, testOrigin)
		} else if page.Code != http.StatusSeeOther {
			t.Fatalf("unexpected consent page: %d %s", page.Code, page.Body.String())
		}
		callback, err := url.Parse(page.Header().Get("Location"))
		if err != nil || page.Code != http.StatusSeeOther {
			t.Fatalf("callback: %d %s", page.Code, page.Body.String())
		}
		if !allow {
			if callback.Query().Get("error") != "access_denied" {
				t.Fatalf("denial: %s", callback)
			}
			return ""
		}
		response := oauthHTTP(client, "POST", "/api/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"userinfo-client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
		var token struct {
			Access string `json:"access_token"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &token) != nil || token.Access == "" {
			t.Fatalf("token: %d %s", response.Code, response.Body.String())
		}
		return token.Access
	}
	userinfo := func(token string, status int) map[string]any {
		t.Helper()
		request := httptest.NewRequest("GET", testOrigin+"/api/userinfo", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		client.handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("userinfo: %d %s", response.Code, response.Body.String())
		}
		var claims map[string]any
		if status == http.StatusOK && json.Unmarshal(response.Body.Bytes(), &claims) != nil {
			t.Fatalf("invalid claims: %s", response.Body.String())
		}
		return claims
	}
	// Identity data cannot be requested without openid or without client registration.
	for _, tc := range []struct{ clientID, scope string }{
		{"userinfo-client", "profile"},
		{"client", "openid profile"},
	} {
		values := url.Values{"client_id": {tc.clientID}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {tc.scope}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
		response := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
		callback, err := url.Parse(response.Header().Get("Location"))
		if err != nil || response.Code != http.StatusFound && response.Code != http.StatusSeeOther || callback.Query().Get("error") != "invalid_scope" {
			t.Fatalf("invalid scope accepted: %d %s %s", response.Code, response.Header().Get("Location"), response.Body.String())
		}
	}
	openidToken := authorize("openid", false, true)
	if claims := userinfo(openidToken, 200); len(claims) != 1 || claims["sub"] != user.ID.String() {
		t.Fatalf("openid claims: %#v", claims)
	}
	authorize("openid profile", true, false)
	var count int64
	if err := db.Model(&consent.Grant{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("denied request saved a grant: %d %v", count, err)
	}
	profileToken := authorize("openid profile", true, true)
	claims := userinfo(profileToken, 200)
	if len(claims) != 3 || claims["name"] != user.Name || claims["preferred_username"] != user.UserName || claims["sub"] != user.ID.String() {
		t.Fatalf("profile claims: %#v", claims)
	}
	authorize("openid profile", false, true)
	bothToken := authorize("openid profile email", true, true)
	claims = userinfo(bothToken, 200)
	if len(claims) != 4 || claims["email"] != user.Email || claims["name"] != user.Name {
		t.Fatalf("combined claims: %#v", claims)
	}
	var emailGrant consent.Grant
	var grants []consent.Grant
	if err := db.Where("user_id = ? AND resource = ?", user.ID, oauth.IdentityResource).Find(&grants).Error; err != nil {
		t.Fatal(err)
	}
	for _, grant := range grants {
		if len(grant.Scopes) == 1 && grant.Scopes[0] == "email" {
			emailGrant = grant
		}
	}
	if emailGrant.ID.String() == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("missing email consent")
	}
	client.do(t, "DELETE", "/api/me/consents/"+emailGrant.ID.String(), nil, http.StatusNoContent)
	userinfo(bothToken, http.StatusUnauthorized)
	userinfo(profileToken, http.StatusOK)
	userinfo(openidToken, http.StatusOK)
	client.do(t, "PATCH", "/api/users/me/name", map[string]string{"Name": "新しい名前"}, http.StatusOK)
	if claims := userinfo(profileToken, http.StatusOK); claims["name"] != "新しい名前" {
		t.Fatalf("profile is not current: %#v", claims)
	}
	emailOnly := authorize("openid email", true, true)
	claims = userinfo(emailOnly, 200)
	if len(claims) != 2 || claims["email"] != user.Email {
		t.Fatalf("email claims: %#v", claims)
	}
	if err := db.Model(&user).Update("rp_id", "other.example").Error; err != nil {
		t.Fatal(err)
	}
	userinfo(emailOnly, http.StatusUnauthorized)
}

func TestUserInfoWithBusinessConsentAndRefresh(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "mixed-userinfo")
	var registered oauth.Client
	if err := db.First(&registered, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	registered.Scopes = append(registered.Scopes, "profile", "email")
	if err := oauth.NewCatalog(db).UpdateClient(t.Context(), registered, ""); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid profile email offline_access b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/api/oauth2/authorize?"+values.Encode(), nil, "")
	page, csrf := oauthReview(t, client, start.Header().Get("Location"))
	if !strings.Contains(page.Body.String(), "メールアドレス") || !strings.Contains(page.Body.String(), "注文履歴を読む") {
		t.Fatalf("consent: %d %s", page.Code, page.Body.String())
	}
	pending, _ := url.Parse(start.Header().Get("Location"))
	approved := oauthHTTP(client, "POST", "/api/oauth2/consent", url.Values{"request": {pending.Query().Get("request")}, "csrf": {csrf}, "decision": {"allow"}}, testOrigin)
	callback, _ := url.Parse(approved.Header().Get("Location"))
	token := oauthHTTP(client, "POST", "/api/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
	var issued struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if token.Code != http.StatusOK || json.Unmarshal(token.Body.Bytes(), &issued) != nil || issued.Access == "" || issued.Refresh == "" {
		t.Fatalf("token: %d %s", token.Code, token.Body.String())
	}
	originalAccess := issued.Access
	refresh := oauthHTTP(client, "POST", "/api/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {issued.Refresh}, "scope": {"openid profile"}}, "")
	if refresh.Code != http.StatusOK || json.Unmarshal(refresh.Body.Bytes(), &issued) != nil || issued.Access == "" {
		t.Fatalf("refresh: %d %s", refresh.Code, refresh.Body.String())
	}
	req := httptest.NewRequest("GET", testOrigin+"/api/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+issued.Access)
	res := httptest.NewRecorder()
	client.handler.ServeHTTP(res, req)
	var claims map[string]any
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &claims) != nil || claims["name"] != user.Name || claims["email"] != nil {
		t.Fatalf("narrowed userinfo: %d %s", res.Code, res.Body.String())
	}
	var grants []consent.Grant
	if err := db.Where("user_id = ?", user.ID).Find(&grants).Error; err != nil || len(grants) != 3 {
		t.Fatalf("mixed consent grants: %d %v", len(grants), err)
	}
	for _, grant := range grants {
		if len(grant.Scopes) == 1 && grant.Scopes[0] == "email" {
			client.do(t, "DELETE", "/api/me/consents/"+grant.ID.String(), nil, http.StatusNoContent)
		}
	}
	res = httptest.NewRecorder()
	client.handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unrelated grant revoked narrowed token: %d", res.Code)
	}
	originalRequest := httptest.NewRequest("GET", testOrigin+"/api/userinfo", nil)
	originalRequest.Header.Set("Authorization", "Bearer "+originalAccess)
	res = httptest.NewRecorder()
	client.handler.ServeHTTP(res, originalRequest)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("revoked email consent retained original access: %d", res.Code)
	}
	refreshAfterRevocation := oauthHTTP(client, "POST", "/api/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {issued.Refresh}}, "")
	if refreshAfterRevocation.Code != http.StatusBadRequest {
		t.Fatalf("revoked email consent retained refresh: %d %s", refreshAfterRevocation.Code, refreshAfterRevocation.Body.String())
	}
}
