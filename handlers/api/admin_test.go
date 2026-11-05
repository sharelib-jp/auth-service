package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Seed real database sessions to exercise authorization without WebAuthn setup.
func adminTestUser(t *testing.T, db *gorm.DB, handler http.Handler, name string, admin bool) (*testClient, *identity.User) {
	t.Helper()
	user := &identity.User{UserName: name, Name: name, Email: name + "@example.com", RPID: "localhost"}
	if err := identity.CreateUser(db, user, &webauthn.Credential{ID: []byte(name)}); err != nil {
		t.Fatal(err)
	}
	if admin {
		if err := identity.GrantAdmin(t.Context(), db, user.ID, user.RPID); err != nil {
			t.Fatal(err)
		}
	}
	// PostgreSQL stores timestamps with microsecond precision; use the persisted
	// version, just as callers do after GET /api/admin/users/:id.
	if err := db.First(user, "id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	token := "admin-test-" + name
	hash := sha256.Sum256([]byte(token))
	if err := identity.SaveAuthSession(db, &identity.AuthSession{TokenHash: hex.EncodeToString(hash[:]), UserId: user.ID, ExpiresAt: time.Now().Add(time.Hour)}, ""); err != nil {
		t.Fatal(err)
	}
	return &testClient{handler: handler, cookies: map[string]*http.Cookie{authCookie: {Name: authCookie, Value: token}}}, user
}

func TestAdminAuthorizationAndUserEditing(t *testing.T) {
	guest, db := testService(t)
	admin, adminUser := adminTestUser(t, db, guest.handler, "admin", true)
	member, user := adminTestUser(t, db, guest.handler, "member", false)
	for _, endpoint := range []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/admin/users", nil}, {"GET", "/api/admin/users/" + user.ID.String(), nil},
		{"PATCH", "/api/admin/users/" + user.ID.String(), map[string]any{"Roles": []string{"admin"}, "UpdatedAt": user.UpdatedAt}},
		{"GET", "/api/admin/roles", nil}, {"POST", "/api/admin/roles", map[string]string{"id": "custom", "name": "Custom"}},
		{"PATCH", "/api/admin/roles/admin", map[string]string{"name": "Changed"}}, {"DELETE", "/api/admin/roles/admin", nil},
		{"GET", "/api/admin/oauth/clients", nil}, {"GET", "/api/admin/oauth/clients/test", nil},
		{"POST", "/api/admin/oauth/clients", nil}, {"PUT", "/api/admin/oauth/clients/test", nil}, {"PATCH", "/api/admin/oauth/clients/test/status", nil},
	} {
		guest.do(t, endpoint.method, endpoint.path, endpoint.body, 401)
		member.do(t, endpoint.method, endpoint.path, endpoint.body, 403)
	}
	// Profile and registration payloads cannot grant privileges.
	member.do(t, "PATCH", "/api/users/me/name", map[string]any{"Name": "X", "Roles": []string{"admin"}}, 400)
	guest.do(t, "POST", "/api/auth/register/begin", map[string]any{"UserName": "intruder", "Name": "X", "Email": "x@example.com", "Roles": []string{"admin"}}, 400)
	me := admin.do(t, "GET", "/api/users/me", nil, 200)
	if !strings.Contains(me.Body.String(), `"Roles":["admin"]`) {
		t.Fatalf("missing roles: %s", me.Body.String())
	}
	admin.do(t, "POST", "/api/admin/roles", map[string]string{"id": "support", "name": "サポート"}, 201)
	admin.do(t, "POST", "/api/admin/roles", map[string]string{"id": "support", "name": "重複"}, 409)
	admin.do(t, "POST", "/api/admin/roles", map[string]string{"id": "INVALID", "name": "無効"}, 400)
	admin.do(t, "PATCH", "/api/admin/roles/support", map[string]string{"name": "支援担当"}, 204)
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"Name": "missing version"}, 400)
	// A rejected role assignment rolls back profile edits too.
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"Name": "not saved", "Roles": []string{"missing"}, "UpdatedAt": user.UpdatedAt}, 400)
	var unchanged identity.User
	json.Unmarshal(admin.do(t, "GET", "/api/admin/users/"+user.ID.String(), nil, 200).Body.Bytes(), &unchanged)
	if unchanged.Name != "member" {
		t.Fatal("invalid update partially persisted")
	}
	var updated identity.User
	json.Unmarshal(admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"UserName": "renamed", "Name": "表示名", "Email": " NEW@EXAMPLE.COM ", "Roles": []string{"support"}, "UpdatedAt": user.UpdatedAt}, 200).Body.Bytes(), &updated)
	if updated.UserName != "renamed" || updated.Name != "表示名" || updated.Email != "new@example.com" || len(updated.Roles) != 1 || updated.Roles[0] != "support" || updated.ID != user.ID || updated.LibraryId != user.LibraryId {
		t.Fatalf("unexpected update: %+v", updated)
	}
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"Name": "stale", "UpdatedAt": user.UpdatedAt}, 409)
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"Email": adminUser.Email, "UpdatedAt": updated.UpdatedAt}, 409)
	admin.do(t, "DELETE", "/api/admin/roles/support", nil, 409)
	admin.do(t, "DELETE", "/api/admin/roles/admin", nil, 400)
	admin.do(t, "PATCH", "/api/admin/users/"+adminUser.ID.String(), map[string]any{"Roles": []string{}, "UpdatedAt": adminUser.UpdatedAt}, 400)
	// Promotion and demotion affect the existing cookie on the next request.
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{"Roles": []string{"admin"}, "UpdatedAt": updated.UpdatedAt}, 200)
	member.do(t, "GET", "/api/admin/users", nil, 200)
	member.do(t, "PATCH", "/api/admin/users/"+adminUser.ID.String(), map[string]any{"Roles": []string{}, "UpdatedAt": adminUser.UpdatedAt}, 200)
	admin.do(t, "GET", "/api/admin/users", nil, 403)
	member.do(t, "DELETE", "/api/admin/roles/support", nil, 204)
	// Users of a different relying party are never exposed, even in search.
	_, other := adminTestUser(t, db, guest.handler, "other-rp", false)
	if err := db.Model(other).Update("rp_id", "other.example.com").Error; err != nil {
		t.Fatal(err)
	}
	member.do(t, "GET", "/api/admin/users/"+other.ID.String(), nil, 404)
	member.do(t, "PATCH", "/api/admin/users/"+other.ID.String(), map[string]any{"Name": "changed", "UpdatedAt": other.UpdatedAt}, 404)
	var page identity.UserPage
	json.Unmarshal(member.do(t, "GET", "/api/admin/users?q=example.com&limit=1&offset=1", nil, 200).Body.Bytes(), &page)
	if page.Total != 2 || len(page.Items) != 1 {
		t.Fatalf("pagination/isolation: %+v", page)
	}
	for _, query := range []string{"limit=0", "limit=101", "offset=-1", "limit=bad"} {
		member.do(t, "GET", "/api/admin/users?"+query, nil, 400)
	}
	member.do(t, "GET", "/api/admin/users/"+uuid.NewString(), nil, 404)
	member.do(t, "GET", "/api/admin/users/invalid", nil, 400)
}

func TestAdminOAuthClientConfiguration(t *testing.T) {
	client, db := testService(t)
	admin, _ := adminTestUser(t, db, client.handler, "admin", true)
	secret := strings.Repeat("s", 32)
	input := map[string]any{"id": "web", "name": "Web", "public": false, "secret": secret, "redirect_uris": []string{"https://web.example/callback"}, "grant_types": []string{"authorization_code", "refresh_token"}, "scopes": []string{"openid", "profile", "email"}, "audience": []string{}}
	admin.do(t, "POST", "/api/admin/oauth/clients", input, 201)
	admin.do(t, "POST", "/api/admin/oauth/clients", input, 409)
	for _, path := range []string{"/api/admin/oauth/clients", "/api/admin/oauth/clients/web"} {
		response := admin.do(t, "GET", path, nil, 200).Body.String()
		if strings.Contains(strings.ToLower(response), "secret") || strings.Contains(response, secret) || strings.Contains(response, "$2") {
			t.Fatalf("leaked credential: %s", response)
		}
	}
	var stored oauth.Client
	if err := db.First(&stored, "id = ?", "web").Error; err != nil {
		t.Fatal(err)
	}
	hash := string(stored.SecretHash)
	if bcrypt.CompareHashAndPassword(stored.SecretHash, []byte(secret)) != nil {
		t.Fatal("secret was not hashed")
	}
	seedSession := func(key string) {
		t.Helper()
		if err := db.Create(&oauth.SessionRecord{Kind: "access", KeyHash: key, RequestID: key, ClientID: "web", Payload: []byte("{}"), Active: true}).Error; err != nil {
			t.Fatal(err)
		}
	}
	seedSession("before-update")
	delete(input, "secret")
	input["name"] = "Updated"
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 204)
	if err := db.First(&stored, "id = ?", "web").Error; err != nil {
		t.Fatal(err)
	}
	if stored.Name != "Updated" || string(stored.SecretHash) != hash {
		t.Fatal("metadata update lost the secret")
	}
	var active int64
	if err := db.Model(&oauth.SessionRecord{}).Where("active = ?", true).Count(&active).Error; err != nil || active != 0 {
		t.Fatalf("sessions not revoked: %d %v", active, err)
	}
	seedSession("before-disable")
	admin.do(t, "PATCH", "/api/admin/oauth/clients/web/status", map[string]string{"status": "disabled"}, 204)
	if err := db.Model(&oauth.SessionRecord{}).Where("active = ?", true).Count(&active).Error; err != nil || active != 0 {
		t.Fatal("disabled client retained sessions")
	}
	admin.do(t, "PATCH", "/api/admin/oauth/clients/web/status", map[string]string{"status": "active"}, 204)
	admin.do(t, "PATCH", "/api/admin/oauth/clients/web/status", map[string]string{"status": "unknown"}, 400)
	input["secret"] = strings.Repeat("r", 32)
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 204)
	if err := db.First(&stored, "id = ?", "web").Error; err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword(stored.SecretHash, []byte(strings.Repeat("r", 32))) != nil {
		t.Fatal("secret rotation failed")
	}
	input["redirect_uris"] = []string{"https://web.example/callback#fragment"}
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 400)
	input["redirect_uris"] = []string{"https://web.example/callback"}
	input["secret_hash"] = "injected"
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 400)
	delete(input, "secret_hash")
	delete(input, "secret")
	input["public"] = true
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 204)
	input["public"] = false
	admin.do(t, "PUT", "/api/admin/oauth/clients/web", input, 400)
	admin.do(t, "GET", "/api/admin/oauth/clients/missing", nil, 404)
	// Admin writes use the same origin policy as profile writes.
	for _, path := range []string{"/api/admin/oauth/clients", "/api/admin/roles"} {
		request := httptest.NewRequest("POST", testOrigin+path, bytes.NewBufferString(`{}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://attacker.example")
		request.AddCookie(admin.cookies[authCookie])
		response := httptest.NewRecorder()
		admin.handler.ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatalf("origin policy: %d", response.Code)
		}
	}
}

func TestConcurrentAdminDemotions(t *testing.T) {
	client, db := testService(t)
	a, alice := adminTestUser(t, db, client.handler, "alice", true)
	b, bob := adminTestUser(t, db, client.handler, "bob", true)
	results := make(chan int, 2)
	for _, entry := range []struct {
		client *testClient
		user   *identity.User
	}{{a, alice}, {b, bob}} {
		go func() {
			raw, _ := json.Marshal(map[string]any{"Roles": []string{}, "UpdatedAt": entry.user.UpdatedAt})
			request := httptest.NewRequest("PATCH", fmt.Sprintf("%s/api/admin/users/%s", testOrigin, entry.user.ID), bytes.NewReader(raw))
			request.Header.Set("Content-Type", "application/json")
			request.AddCookie(entry.client.cookies[authCookie])
			response := httptest.NewRecorder()
			entry.client.handler.ServeHTTP(response, request)
			results <- response.Code
		}()
	}
	one, two := <-results, <-results
	if !((one == 200 && two == 400) || (one == 400 && two == 200)) {
		t.Fatalf("demotions: %d, %d", one, two)
	}
	var count int64
	if err := db.Model(&identity.UserRole{}).Where("role_id = ?", identity.AdminRole).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("remaining admins: %d, %v", count, err)
	}
}

func TestAdminUserEditRollsBackWhenAuditFails(t *testing.T) {
	client, db := testService(t)
	admin, _ := adminTestUser(t, db, client.handler, "admin", true)
	member, user := adminTestUser(t, db, client.handler, "member", false)
	restore := failInserts(t, db, "audit_security_events", "audit unavailable")
	admin.do(t, "PATCH", "/api/admin/users/"+user.ID.String(), map[string]any{
		"Name": "not saved", "Roles": []string{"admin"}, "UpdatedAt": user.UpdatedAt,
	}, 500)
	restore()
	var stored identity.User
	if err := json.Unmarshal(admin.do(t, "GET", "/api/admin/users/"+user.ID.String(), nil, 200).Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Name != user.Name || len(stored.Roles) != 0 || !stored.UpdatedAt.Equal(user.UpdatedAt) {
		t.Fatalf("failed edit partially persisted: %+v", stored)
	}
	member.do(t, "GET", "/api/admin/users", nil, 403)
}
