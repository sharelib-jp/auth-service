package api

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sharelib-jp/auth-service/dao"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/authorization"
	"github.com/sharelib-jp/auth-service/internal/consent"

	"github.com/sharelib-jp/auth-service/internal/oauth"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"gorm.io/gorm"
)

func oauthTestService(t *testing.T) (*testClient, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	driver, dsn := testdb.Config(t)
	db, err := dao.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { sqlDB.Close() })
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "oidc.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OAUTH_HMAC_SECRET", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	conf := &config.Config{SCHEME: "http://", HOSTNAME: "localhost", PORT: ":8080", WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DRIVER: driver, DATABASE_DSN: dsn, OAuth: config.OAuthConfig{Enabled: true, Issuer: testOrigin, SigningKeyFile: keyFile, SigningKeyID: "test-key"}}
	catalog := oauth.NewCatalog(db)
	ctx := t.Context()
	if err := catalog.RegisterResource(ctx, oauth.Resource{ID: "b", Identifier: "https://b.example/api", Name: "B"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RegisterScope(ctx, oauth.Scope{ID: "read", ResourceID: "b", Name: "b.orders.read", Description: "注文履歴を読む", PurposeCode: "orders", PolicyVersion: 1}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RegisterClient(ctx, oauth.Client{ID: "client", Name: "C", Public: true, RedirectURIs: []string{"https://c.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "offline_access", "b.orders.read"}, Audience: []string{"https://b.example/api"}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RegisterResourceCredential(ctx, "b-server", "b", strings.Repeat("p", 32)); err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(conf, db)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{handler: router, cookies: map[string]*http.Cookie{}}, db
}

func oauthHTTP(client *testClient, method, path string, body url.Values, origin string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body.Encode())
	}
	req := httptest.NewRequest(method, testOrigin+path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, cookie := range client.cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	client.handler.ServeHTTP(rec, req)
	for _, cookie := range rec.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(client.cookies, cookie.Name)
		} else {
			client.cookies[cookie.Name] = cookie
		}
	}
	return rec
}

func TestOAuthHTTPLoginConsentAndRevocation(t *testing.T) {
	client, db := oauthTestService(t)
	authenticator, user := client.register(t, "oauthuser")
	client.do(t, "POST", "/api/auth/logout", nil, http.StatusNoContent)
	verifier := strings.Repeat("v", 43)
	challenge := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid offline_access b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "nonce": {strings.Repeat("n", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != 303 {
		t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
	}
	continuePath := start.Header().Get("Location")
	notLoggedIn := oauthHTTP(client, "GET", continuePath, nil, "")
	if notLoggedIn.Code != 303 || !strings.HasPrefix(notLoggedIn.Header().Get("Location"), "/login/") {
		t.Fatalf("login: %d %s", notLoggedIn.Code, notLoggedIn.Body.String())
	}
	login := optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, http.StatusOK))
	client.do(t, "POST", "/api/auth/login/finish", authenticator.assertion(t, login.PublicKey.Challenge, testOrigin, 1, true), http.StatusOK)
	page := oauthHTTP(client, "GET", continuePath, nil, "")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "注文履歴を読む") {
		t.Fatalf("consent page: %d %s", page.Code, page.Body.String())
	}
	csrfMatch := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	requestURL, _ := url.Parse(continuePath)
	if len(csrfMatch) != 2 {
		t.Fatalf("missing CSRF: %s", page.Body.String())
	}
	decision := url.Values{"request": {requestURL.Query().Get("request")}, "csrf": {csrfMatch[1]}, "decision": {"allow"}}
	if response := oauthHTTP(client, "POST", "/oauth2/consent", decision, "https://attacker.example"); response.Code != 403 {
		t.Fatalf("CSRF origin: %d", response.Code)
	}
	badDecision := url.Values{"request": {decision.Get("request")}, "csrf": {strings.Repeat("x", 43)}, "decision": {"allow"}}
	if response := oauthHTTP(client, "POST", "/oauth2/consent", badDecision, testOrigin); response.Code != 403 {
		t.Fatalf("invalid CSRF: %d", response.Code)
	}
	approved := oauthHTTP(client, "POST", "/oauth2/consent", decision, testOrigin)
	if approved.Code != 303 {
		t.Fatalf("approve: %d %s", approved.Code, approved.Body.String())
	}
	callback, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || callback.Query().Get("state") != values.Get("state") || callback.Query().Get("code") == "" {
		t.Fatalf("callback: %s %v", approved.Header().Get("Location"), err)
	}
	tokenValues := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}
	token := oauthHTTP(client, "POST", "/oauth2/token", tokenValues, "")
	if token.Code != 200 {
		t.Fatalf("token: %d %s", token.Code, token.Body.String())
	}
	var tokens struct {
		Access  string `json:"access_token"`
		ID      string `json:"id_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.Unmarshal(token.Body.Bytes(), &tokens); err != nil || tokens.Access == "" || tokens.ID == "" || tokens.Refresh == "" {
		t.Fatalf("token response: %s %v", token.Body.String(), err)
	}
	introspect := func(value string) map[string]any {
		req := httptest.NewRequest("POST", testOrigin+"/oauth2/introspect", strings.NewReader(url.Values{"token": {value}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("b-server", strings.Repeat("p", 32))
		rec := httptest.NewRecorder()
		client.handler.ServeHTTP(rec, req)
		var result map[string]any
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
			t.Fatalf("introspection: %d %s", rec.Code, rec.Body.String())
		}
		return result
	}
	if result := introspect(tokens.Access); result["active"] != true || result["sub"] != user.ID.String() {
		t.Fatalf("active token: %v", result)
	}
	if result := introspect(tokens.ID); result["active"] != false {
		t.Fatalf("ID token accepted as access token: %v", result)
	}
	catalog := oauth.NewCatalog(db)
	if err := catalog.RegisterResource(t.Context(), oauth.Resource{ID: "other", Identifier: "https://other.example/api", Name: "Other"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RegisterResourceCredential(t.Context(), "other-server", "other", strings.Repeat("q", 32)); err != nil {
		t.Fatal(err)
	}
	otherReq := httptest.NewRequest("POST", testOrigin+"/oauth2/introspect", strings.NewReader(url.Values{"token": {tokens.Access}}.Encode()))
	otherReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	otherReq.SetBasicAuth("other-server", strings.Repeat("q", 32))
	otherResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(otherResponse, otherReq)
	var otherResult struct {
		Active bool `json:"active"`
	}
	if otherResponse.Code != 200 || json.Unmarshal(otherResponse.Body.Bytes(), &otherResult) != nil || otherResult.Active {
		t.Fatalf("wrong audience: %d %s", otherResponse.Code, otherResponse.Body.String())
	}
	list := client.do(t, "GET", "/api/me/consents", nil, 200)
	var grants []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &grants); err != nil || len(grants) != 1 {
		t.Fatalf("consents: %s", list.Body.String())
	}
	client.do(t, "DELETE", "/api/me/consents/"+grants[0].ID, nil, 204)
	if result := introspect(tokens.Access); result["active"] != false {
		t.Fatalf("revoked token: %v", result)
	}
	refresh := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {tokens.Refresh}}, "")
	if refresh.Code == 200 {
		t.Fatalf("refresh after revocation: %s", refresh.Body.String())
	}
	history := client.do(t, "GET", "/api/me/security-events", nil, 200).Body.String()
	if !strings.Contains(history, "authorization_approved") || !strings.Contains(history, "access_token_issued") || !strings.Contains(history, "consent_revoked") || strings.Contains(history, tokens.Access) || strings.Contains(history, tokens.Refresh) || strings.Contains(history, "authorization_requested") {
		t.Fatalf("invalid user security history: %s", history)
	}
}

func TestAuditAuthenticatedDeduplicationAndOwnership(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "audituser")
	event := map[string]any{"event_id": "event-001", "subject": user.ID.String(), "client_id": "client", "resource": "https://b.example/api", "action": "read", "data_category": "orders", "result": "success", "occurred_at": time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	send := func(body map[string]any, auth bool) *httptest.ResponseRecorder {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", testOrigin+"/internal/audit/events", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if auth {
			req.SetBasicAuth("b-server", strings.Repeat("p", 32))
		}
		rec := httptest.NewRecorder()
		client.handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(event, false); rec.Code != 401 {
		t.Fatalf("unauthenticated event: %d", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if rec := send(event, true); rec.Code != 202 {
			t.Fatalf("event: %d %s", rec.Code, rec.Body.String())
		}
	}
	event["result"] = "denied"
	if rec := send(event, true); rec.Code != 409 {
		t.Fatalf("collision: %d", rec.Code)
	}
	event["event_id"] = "event-002"
	event["resource"] = "https://other.example/api"
	if rec := send(event, true); rec.Code != 400 {
		t.Fatalf("wrong source: %d", rec.Code)
	}
	event["resource"] = "https://b.example/api"
	if rec := send(event, true); rec.Code != 202 {
		t.Fatalf("second event: %d %s", rec.Code, rec.Body.String())
	}
	event["event_id"] = "event-003"
	failInserts(t, db, "audit_access_events", "audit failure")
	if rec := send(event, true); rec.Code != 500 {
		t.Fatalf("failed persistence should be retried: %d", rec.Code)
	}
	response := client.do(t, "GET", "/api/me/access-events?limit=1", nil, 200)
	var page struct {
		Events []struct {
			EventID string `json:"event_id"`
		} `json:"events"`
		NextCursor string `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Events) != 1 || page.Events[0].EventID != "event-002" || page.NextCursor == "" {
		t.Fatalf("history: %s %v", response.Body.String(), err)
	}
	response = client.do(t, "GET", "/api/me/access-events?limit=1&cursor="+url.QueryEscape(page.NextCursor), nil, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Events) != 1 || page.Events[0].EventID != "event-001" {
		t.Fatalf("second page: %s %v", response.Body.String(), err)
	}
	other := &testClient{handler: client.handler, cookies: map[string]*http.Cookie{}}
	other.register(t, "other-audit-user")
	response = other.do(t, "GET", "/api/me/access-events", nil, 200)
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Events) != 0 {
		t.Fatalf("other user history: %s %v", response.Body.String(), err)
	}
}

func TestBusinessPolicyChecksAreIndependentAndFailClosed(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "policyuser")
	service := authorization.NewService(db)
	if err := service.SetBinding(t.Context(), authorization.RoleBinding{ResourceID: "b", UserID: user.ID, Role: "reader", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	policy := authorization.Policy{ResourceID: "b", Role: "reader", Object: "orders", Action: "read", Status: "active"}
	if err := service.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	check := func(subject, resource, action string, authenticated bool) (int, bool) {
		data, _ := json.Marshal(map[string]string{"subject": subject, "resource": resource, "action": action})
		req := httptest.NewRequest("POST", testOrigin+"/internal/authorize/check", bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.SetBasicAuth("b-server", strings.Repeat("p", 32))
		}
		rec := httptest.NewRecorder()
		client.handler.ServeHTTP(rec, req)
		var result struct {
			Allowed bool `json:"allowed"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
		return rec.Code, result.Allowed
	}
	if code, _ := check(user.ID.String(), "b.orders", "read", false); code != 401 {
		t.Fatalf("unauthenticated check: %d", code)
	}
	if code, allowed := check(user.ID.String(), "b.orders", "read", true); code != 200 || !allowed {
		t.Fatalf("authorized check: %d %t", code, allowed)
	}
	if _, allowed := check(user.ID.String(), "b.orders", "write", true); allowed {
		t.Fatal("ungranted action allowed")
	}
	if _, allowed := check(user.ID.String(), "other.orders", "read", true); allowed {
		t.Fatal("another resource allowed")
	}
	if _, allowed := check(uuid.NewString(), "b.orders", "read", true); allowed {
		t.Fatal("another user allowed")
	}
	policy.Status = "disabled"
	if err := service.SetPolicy(t.Context(), policy); err != nil {
		t.Fatal(err)
	}
	if _, allowed := check(user.ID.String(), "b.orders", "read", true); allowed {
		t.Fatal("disabled policy allowed")
	}
}

func TestConcurrentRefreshReuseRevokesWinningFamily(t *testing.T) {
	client, db := oauthTestService(t)
	if db.Dialector.Name() != "postgres" {
		t.Skip("requires PostgreSQL row locking")
	}
	client.register(t, "refreshuser")
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid offline_access b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "nonce": {strings.Repeat("n", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != 303 {
		t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
	}
	continuePath := start.Header().Get("Location")
	page := oauthHTTP(client, "GET", continuePath, nil, "")
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(csrf) != 2 {
		t.Fatalf("consent: %d %s", page.Code, page.Body.String())
	}
	continueURL, _ := url.Parse(continuePath)
	approved := oauthHTTP(client, "POST", "/oauth2/consent", url.Values{"request": {continueURL.Query().Get("request")}, "csrf": {csrf[1]}, "decision": {"allow"}}, testOrigin)
	callback, _ := url.Parse(approved.Header().Get("Location"))
	if approved.Code != 303 || callback.Query().Get("code") == "" {
		t.Fatalf("approval: %d %s", approved.Code, approved.Body.String())
	}
	initial := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
	var tokens struct {
		Refresh string `json:"refresh_token"`
	}
	if initial.Code != 200 || json.Unmarshal(initial.Body.Bytes(), &tokens) != nil || tokens.Refresh == "" {
		t.Fatalf("initial tokens: %d %s", initial.Code, initial.Body.String())
	}
	lock := db.Begin()
	if lock.Error != nil {
		t.Fatal(lock.Error)
	}
	var resource oauth.Resource
	if err := lock.Raw("SELECT * FROM oauth_resources WHERE id = ? FOR UPDATE", "b").Scan(&resource).Error; err != nil {
		lock.Rollback()
		t.Fatal(err)
	}
	results := make(chan *httptest.ResponseRecorder, 2)
	started := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			started <- struct{}{}
			results <- oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {tokens.Refresh}}, "")
		}()
	}
	<-started
	<-started
	time.Sleep(200 * time.Millisecond)
	if err := lock.Commit().Error; err != nil {
		t.Fatal(err)
	}
	var winner string
	statuses := map[int]int{}
	for i := 0; i < 2; i++ {
		select {
		case response := <-results:
			statuses[response.Code]++
			if response.Code == 200 {
				var result struct {
					Access string `json:"access_token"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				winner = result.Access
			}
		case <-time.After(10 * time.Second):
			t.Fatal("refresh requests blocked")
		}
	}
	if statuses[200] != 1 || winner == "" {
		t.Fatalf("expected one successful refresh: %v", statuses)
	}
	req := httptest.NewRequest("POST", testOrigin+"/oauth2/introspect", strings.NewReader(url.Values{"token": {winner}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("b-server", strings.Repeat("p", 32))
	rec := httptest.NewRecorder()
	client.handler.ServeHTTP(rec, req)
	var result struct {
		Active bool `json:"active"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || result.Active {
		t.Fatalf("concurrent reuse did not revoke family: %d %s", rec.Code, rec.Body.String())
	}
}

func TestConsentDenialAndPolicyChangeDuringReview(t *testing.T) {
	client, db := oauthTestService(t)
	client.register(t, "reviewuser")
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	startReview := func() url.Values {
		start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
		if start.Code != 303 {
			t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
		}
		page := oauthHTTP(client, "GET", start.Header().Get("Location"), nil, "")
		csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
		if len(csrf) != 2 {
			t.Fatalf("consent: %d %s", page.Code, page.Body.String())
		}
		location, _ := url.Parse(start.Header().Get("Location"))
		return url.Values{"request": {location.Query().Get("request")}, "csrf": {csrf[1]}, "decision": {"allow"}}
	}
	decision := startReview()
	if err := oauth.NewCatalog(db).UpdateScopePolicy(t.Context(), "read", "条件変更後の説明", "newpurpose"); err != nil {
		t.Fatal(err)
	}
	if rec := oauthHTTP(client, "POST", "/oauth2/consent", decision, testOrigin); rec.Code != 403 {
		t.Fatalf("changed consent accepted: %d %s", rec.Code, rec.Body.String())
	}
	var count int64
	if err := db.Table("consent_grants").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("changed consent persisted: %d %v", count, err)
	}
	decision = startReview()
	decision.Set("decision", "deny")
	denied := oauthHTTP(client, "POST", "/oauth2/consent", decision, testOrigin)
	location, _ := url.Parse(denied.Header().Get("Location"))
	if denied.Code != 303 || location.Query().Get("error") != "access_denied" || location.Query().Get("state") != values.Get("state") {
		t.Fatalf("denial: %d %s", denied.Code, denied.Header().Get("Location"))
	}
	if err := db.Table("consent_grants").Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("denied consent persisted: %d %v", count, err)
	}
}

func TestOIDCLoginOnlyUserinfo(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "openiduser")
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid"}, "state": {strings.Repeat("s", 32)}, "nonce": {strings.Repeat("n", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != 303 {
		t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
	}
	finish := oauthHTTP(client, "GET", start.Header().Get("Location"), nil, "")
	callback, err := url.Parse(finish.Header().Get("Location"))
	if err != nil || finish.Code != 303 || callback.Query().Get("code") == "" {
		t.Fatalf("callback: %d %s", finish.Code, finish.Body.String())
	}
	response := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
	var tokens struct {
		Access  string `json:"access_token"`
		ID      string `json:"id_token"`
		Refresh string `json:"refresh_token"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.ID == "" || tokens.Refresh != "" {
		t.Fatalf("tokens: %d %s", response.Code, response.Body.String())
	}
	for _, check := range []struct {
		token  string
		status int
	}{{tokens.Access, 200}, {tokens.ID, 401}} {
		req := httptest.NewRequest("GET", testOrigin+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+check.token)
		rec := httptest.NewRecorder()
		client.handler.ServeHTTP(rec, req)
		if rec.Code != check.status || (rec.Code == 200 && !strings.Contains(rec.Body.String(), user.ID.String())) {
			t.Fatalf("userinfo: %d %s", rec.Code, rec.Body.String())
		}
	}
	postUserinfo := httptest.NewRequest("POST", testOrigin+"/userinfo", nil)
	postUserinfo.Header.Set("Authorization", "Bearer "+tokens.Access)
	postUserinfo.Header.Set("Origin", "https://c.example")
	postResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(postResponse, postUserinfo)
	if postResponse.Code != 200 || !strings.Contains(postResponse.Body.String(), user.ID.String()) {
		t.Fatalf("POST userinfo: %d %s", postResponse.Code, postResponse.Body.String())
	}
	restore := failInserts(t, db, "audit_security_events", "audit failure")
	revokeForm := url.Values{"client_id": {"client"}, "token": {tokens.Access}}
	failed := oauthHTTP(client, "POST", "/oauth2/revoke", revokeForm, "")
	if failed.Code != 503 {
		t.Fatalf("failed revocation reported success: %d %s", failed.Code, failed.Body.String())
	}
	restore()
	stillActive := httptest.NewRequest("GET", testOrigin+"/userinfo", nil)
	stillActive.Header.Set("Authorization", "Bearer "+tokens.Access)
	activeResponse := httptest.NewRecorder()
	client.handler.ServeHTTP(activeResponse, stillActive)
	if activeResponse.Code != 200 {
		t.Fatalf("failed revocation did not roll back: %d", activeResponse.Code)
	}
	revoked := oauthHTTP(client, "POST", "/oauth2/revoke", revokeForm, "")
	if revoked.Code != 200 {
		t.Fatalf("revocation: %d %s", revoked.Code, revoked.Body.String())
	}
	responseAfter := httptest.NewRecorder()
	client.handler.ServeHTTP(responseAfter, stillActive)
	if responseAfter.Code != 401 {
		t.Fatalf("revoked token still accepted: %d", responseAfter.Code)
	}
}

func TestOAuthProtocolRejectsOversizedAndDuplicateFields(t *testing.T) {
	client, _ := oauthTestService(t)
	for _, body := range []url.Values{
		{"grant_type": {"authorization_code", "refresh_token"}},
		{"grant_type": {"authorization_code"}, "code": {strings.Repeat(".", 5000)}},
	} {
		response := oauthHTTP(client, "POST", "/oauth2/token", body, "")
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid form: %d %s", response.Code, response.Body.String())
		}
	}
	response := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "resource": {"https://other.example/api"}}, "")
	if response.Code != 400 {
		t.Fatalf("token resource was silently ignored: %d %s", response.Code, response.Body.String())
	}
	query := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"plain"}, "code_challenge": {strings.Repeat("v", 43)}}
	response = oauthHTTP(client, "GET", "/oauth2/authorize?"+query.Encode(), nil, "")
	location, _ := url.Parse(response.Header().Get("Location"))
	if response.Code != 303 || location.Query().Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE accepted: %d %s", response.Code, response.Body.String())
	}
	query.Set("redirect_uri", "https://c.example/callback/other")
	response = oauthHTTP(client, "GET", "/oauth2/authorize?"+query.Encode(), nil, "")
	if response.Code == 303 {
		t.Fatalf("unregistered redirect accepted: %s", response.Header().Get("Location"))
	}
}

func TestAdditionalScopeRequiresOnlyNewConsent(t *testing.T) {
	client, db := oauthTestService(t)
	_, user := client.register(t, "incrementaluser")
	catalog := oauth.NewCatalog(db)
	if err := catalog.RegisterScope(t.Context(), oauth.Scope{ID: "write", ResourceID: "b", Name: "b.orders.write", Description: "注文履歴を更新", PurposeCode: "orders", PolicyVersion: 1}); err != nil {
		t.Fatal(err)
	}
	var registered oauth.Client
	if err := db.First(&registered, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	registered.Scopes = append(registered.Scopes, "b.orders.write")
	if err := db.Save(&registered).Error; err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid b.orders.read"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	authorize := func() (*httptest.ResponseRecorder, string) {
		start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
		if start.Code != 303 {
			t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
		}
		path := start.Header().Get("Location")
		return oauthHTTP(client, "GET", path, nil, ""), path
	}
	approve := func(page *httptest.ResponseRecorder, path string) {
		csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
		if len(csrf) != 2 {
			t.Fatalf("consent page: %d %s", page.Code, page.Body.String())
		}
		parsed, _ := url.Parse(path)
		response := oauthHTTP(client, "POST", "/oauth2/consent", url.Values{"request": {parsed.Query().Get("request")}, "csrf": {csrf[1]}, "decision": {"allow"}}, testOrigin)
		if response.Code != 303 {
			t.Fatalf("approve: %d %s", response.Code, response.Body.String())
		}
	}
	page, path := authorize()
	approve(page, path)
	var initial []consent.Grant
	if err := db.Where("user_id = ?", user.ID).Find(&initial).Error; err != nil || len(initial) != 1 {
		t.Fatalf("initial consent: %+v %v", initial, err)
	}
	values.Set("scope", "openid b.orders.read b.orders.write")
	page, path = authorize()
	if !strings.Contains(page.Body.String(), "注文履歴を更新") {
		t.Fatalf("new scope not shown: %s", page.Body.String())
	}
	approve(page, path)
	var all []consent.Grant
	if err := db.Where("user_id = ?", user.ID).Find(&all).Error; err != nil || len(all) != 2 {
		t.Fatalf("incremental consents: %+v %v", all, err)
	}
	var preserved bool
	for _, grant := range all {
		if grant.ID == initial[0].ID && grant.Status == consent.Active {
			preserved = true
		}
	}
	if !preserved {
		t.Fatal("existing consent was replaced")
	}
	page, _ = authorize()
	if page.Code != 303 {
		t.Fatalf("previously approved scopes requested again: %d %s", page.Code, page.Body.String())
	}
}

func TestConfidentialClientAuthentication(t *testing.T) {
	client, db := oauthTestService(t)
	client.register(t, "confidentialuser")
	var registered oauth.Client
	if err := db.First(&registered, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	registered.Public = false
	secret := strings.Repeat("p", 32)
	if err := oauth.NewCatalog(db).UpdateClient(t.Context(), registered, secret); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != 303 {
		t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
	}
	finish := oauthHTTP(client, "GET", start.Header().Get("Location"), nil, "")
	callback, err := url.Parse(finish.Header().Get("Location"))
	if err != nil || callback.Query().Get("code") == "" {
		t.Fatalf("callback: %d %s", finish.Code, finish.Body.String())
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}
	request := func(password string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", testOrigin+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if password != "" {
			req.SetBasicAuth("client", password)
		}
		rec := httptest.NewRecorder()
		client.handler.ServeHTTP(rec, req)
		return rec
	}
	if rec := request(""); rec.Code == 200 {
		t.Fatal("confidential client authenticated without secret")
	}
	if rec := request(strings.Repeat("x", 32)); rec.Code == 200 {
		t.Fatal("wrong secret was accepted")
	}
	if rec := request(secret); rec.Code != 200 {
		t.Fatalf("correct secret: %d %s", rec.Code, rec.Body.String())
	}
	var sessions []oauth.SessionRecord
	if err := db.Find(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	for _, session := range sessions {
		if strings.Contains(string(session.Payload), secret) {
			t.Fatal("client secret stored in session")
		}
	}
}

func TestRefreshScopeNarrowingAndPartialConsentRevocation(t *testing.T) {
	client, db := oauthTestService(t)
	client.register(t, "narrowuser")
	catalog := oauth.NewCatalog(db)
	if err := catalog.RegisterScope(t.Context(), oauth.Scope{ID: "write", ResourceID: "b", Name: "b.orders.write", Description: "注文履歴を更新", PurposeCode: "orders", PolicyVersion: 1}); err != nil {
		t.Fatal(err)
	}
	var registered oauth.Client
	if err := db.First(&registered, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	registered.Scopes = append(registered.Scopes, "b.orders.write")
	if err := catalog.UpdateClient(t.Context(), registered, ""); err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://c.example/callback"}, "scope": {"openid offline_access b.orders.read b.orders.write"}, "resource": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	start := oauthHTTP(client, "GET", "/oauth2/authorize?"+values.Encode(), nil, "")
	if start.Code != 303 {
		t.Fatalf("authorize: %d %s", start.Code, start.Body.String())
	}
	page := oauthHTTP(client, "GET", start.Header().Get("Location"), nil, "")
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(csrf) != 2 {
		t.Fatalf("consent: %d %s", page.Code, page.Body.String())
	}
	continueURL, _ := url.Parse(start.Header().Get("Location"))
	approved := oauthHTTP(client, "POST", "/oauth2/consent", url.Values{"request": {continueURL.Query().Get("request")}, "csrf": {csrf[1]}, "decision": {"allow"}}, testOrigin)
	callback, _ := url.Parse(approved.Header().Get("Location"))
	if approved.Code != 303 || callback.Query().Get("code") == "" {
		t.Fatalf("approval: %d %s", approved.Code, approved.Body.String())
	}
	initial := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://c.example/callback"}, "code_verifier": {verifier}}, "")
	type tokenResponse struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Scope   string `json:"scope"`
	}
	var original tokenResponse
	if initial.Code != 200 || json.Unmarshal(initial.Body.Bytes(), &original) != nil || original.Refresh == "" {
		t.Fatalf("initial token: %d %s", initial.Code, initial.Body.String())
	}
	invalid := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {original.Refresh}, "scope": {"b.projects.read"}}, "")
	if invalid.Code != 400 || !strings.Contains(invalid.Body.String(), "invalid_scope") {
		t.Fatalf("scope escalation: %d %s", invalid.Code, invalid.Body.String())
	}
	refresh := func(token, scope string) tokenResponse {
		res := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {token}, "scope": {scope}}, "")
		var out tokenResponse
		if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &out) != nil || out.Access == "" || out.Refresh == "" || out.Scope != scope {
			t.Fatalf("narrow refresh: %d %s", res.Code, res.Body.String())
		}
		return out
	}
	readOnly := refresh(original.Refresh, "openid b.orders.read")
	writeOnly := refresh(readOnly.Refresh, "b.orders.write")
	list := client.do(t, "GET", "/api/me/consents", nil, 200)
	var grants []struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &grants); err != nil || len(grants) != 2 {
		t.Fatalf("consents: %s %v", list.Body.String(), err)
	}
	var readGrant string
	for _, grant := range grants {
		if len(grant.Scopes) == 1 && grant.Scopes[0] == "b.orders.read" {
			readGrant = grant.ID
		}
	}
	if readGrant == "" {
		t.Fatal("missing read grant")
	}
	client.do(t, "DELETE", "/api/me/consents/"+readGrant, nil, 204)
	introspection := httptest.NewRequest("POST", testOrigin+"/oauth2/introspect", strings.NewReader(url.Values{"token": {writeOnly.Access}}.Encode()))
	introspection.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspection.SetBasicAuth("b-server", strings.Repeat("p", 32))
	rec := httptest.NewRecorder()
	client.handler.ServeHTTP(rec, introspection)
	var result struct {
		Active bool   `json:"active"`
		Scope  string `json:"scope"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &result) != nil || !result.Active || result.Scope != "b.orders.write" {
		t.Fatalf("unrelated narrowed token revoked: %d %s", rec.Code, rec.Body.String())
	}
	res := oauthHTTP(client, "POST", "/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {writeOnly.Refresh}}, "")
	if res.Code == 200 {
		t.Fatal("refresh token linked to revoked consent remained valid")
	}
}
