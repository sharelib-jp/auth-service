package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/oauth"
)

func TestConsentOwnershipHistoryAndCSRF(t *testing.T) {
	client, db := testService(t)
	_, user := client.register(t, "owner")
	service := consent.NewService(consent.NewRepository(db))
	grant, err := service.Create(context.Background(), consent.Grant{UserID: user.ID, ClientID: "c-web", Resource: "https://b.example.com/api", Scopes: []string{"b.orders.read"}, PurposeCode: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	other := &testClient{handler: client.handler, cookies: map[string]*http.Cookie{}}
	other.register(t, "other")
	path := "/api/me/consents/" + grant.ID.String()
	other.do(t, "GET", path, nil, 404)
	other.do(t, "DELETE", path, nil, 404)
	client.do(t, "GET", path, nil, 200)
	request := httptest.NewRequest("DELETE", testOrigin+path, nil)
	request.AddCookie(client.cookies[authCookie])
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatalf("missing origin: got %d", recorder.Code)
	}
	client.do(t, "DELETE", path, nil, 204)
	client.do(t, "DELETE", path, nil, 204)
	stored, err := service.Get(context.Background(), user.ID, grant.ID)
	if err != nil || stored.Status != consent.Revoked || stored.RevokedAt == nil {
		t.Fatalf("revocation: %+v, %v", stored, err)
	}
	var events []consent.Event
	if err := db.Where("grant_id = ?", grant.ID).Find(&events).Error; err != nil || len(events) != 2 {
		t.Fatalf("events: %+v, %v", events, err)
	}
	second, err := service.Create(context.Background(), consent.Grant{UserID: user.ID, ClientID: "c-web", Resource: grant.Resource, Scopes: grant.Scopes, PurposeCode: grant.PurposeCode})
	if err != nil || second.ID == grant.ID {
		t.Fatalf("reconsent: %+v, %v", second, err)
	}
	client.do(t, "GET", "/api/me/consents", nil, 200)
}

func TestConsentValidationAndAtomicHistory(t *testing.T) {
	_, db := testService(t)
	service := consent.NewService(consent.NewRepository(db))
	expired := time.Now().Add(-time.Minute)
	base := consent.Grant{UserID: uuid.New(), ClientID: "c", Resource: "b", Scopes: []string{"b.orders.read"}, PurposeCode: "orders"}
	for _, grant := range []consent.Grant{
		{},
		{UserID: base.UserID, ClientID: "c", Resource: "b", Scopes: []string{"openid"}, PurposeCode: "orders"},
		{UserID: base.UserID, ClientID: "c", Resource: "b", Scopes: base.Scopes, PurposeCode: "orders", ExpiresAt: &expired},
	} {
		if _, err := service.Create(context.Background(), grant); err != consent.ErrInvalidGrant {
			t.Fatalf("expected validation error, got %v", err)
		}
	}
	failInserts(t, db, "consent_events", "event failure")
	if _, err := service.Create(context.Background(), base); err == nil {
		t.Fatal("expected event failure")
	}
	var count int64
	if err := db.Model(&consent.Grant{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("grant was not rolled back: %d, %v", count, err)
	}
}

func TestConsentRevokeRollsBackOnHistoryFailure(t *testing.T) {
	_, db := testService(t)
	service := consent.NewService(consent.NewRepository(db))
	grant, err := service.Create(context.Background(), consent.Grant{UserID: uuid.New(), ClientID: "c", Resource: "b", Scopes: []string{"b.orders.read"}, PurposeCode: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	failInserts(t, db, "consent_events", "event failure")
	if err := service.Revoke(context.Background(), grant.UserID, grant.ID); err == nil {
		t.Fatal("expected event failure")
	}
	stored, err := service.Get(context.Background(), grant.UserID, grant.ID)
	if err != nil || stored.Status != consent.Active || stored.RevokedAt != nil {
		t.Fatalf("revocation was not rolled back: %+v, %v", stored, err)
	}
}

func TestConsentListDisplayMetadata(t *testing.T) {
	client, db := testService(t)
	_, user := client.register(t, "metadata")
	other := &testClient{handler: client.handler, cookies: map[string]*http.Cookie{}}
	other.register(t, "metadata-other")
	if err := db.Create(&oauth.Client{ID: "app", Name: "読書アプリ", Public: true, Status: "disabled", RedirectURIs: []string{}, GrantTypes: []string{}, Scopes: []string{}, Audience: []string{}}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&oauth.Resource{ID: "library", Identifier: "https://library.example/api", Name: "図書館", Status: "disabled"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&oauth.Scope{ID: "loans", Name: "library.loans", ResourceID: "library", Description: "貸出履歴", PurposeCode: "loans", PolicyVersion: 1, Status: "disabled"}).Error; err != nil {
		t.Fatal(err)
	}
	service := consent.NewService(consent.NewRepository(db))
	for _, grant := range []consent.Grant{
		{UserID: user.ID, ClientID: "app", Resource: "https://library.example/api", Scopes: []string{"library.loans"}, PurposeCode: "loans"},
		{UserID: user.ID, ClientID: "app", Resource: oauth.IdentityResource, Scopes: []string{"profile"}, PurposeCode: "oidc_userinfo"},
		{UserID: user.ID, ClientID: "missing", Resource: "urn:missing", Scopes: []string{"missing.scope"}, PurposeCode: "missing"},
		{UserID: user.ID, ClientID: "old", Resource: "https://library.example/api", Scopes: []string{"library.loans"}, PurposeCode: "loans", PolicyVersion: 2},
	} {
		if _, err := service.Create(context.Background(), grant); err != nil {
			t.Fatal(err)
		}
	}
	response := client.do(t, "GET", "/api/me/consents", nil, http.StatusOK)
	var grants []struct {
		ClientID     string            `json:"client_id"`
		ClientName   string            `json:"client_name"`
		Resource     string            `json:"resource"`
		ResourceName string            `json:"resource_name"`
		Descriptions map[string]string `json:"scope_descriptions"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &grants); err != nil || len(grants) != 4 {
		t.Fatalf("list: %s, %v", response.Body.String(), err)
	}
	for _, grant := range grants {
		switch grant.Resource {
		case "https://library.example/api":
			if grant.ClientID == "old" {
				if len(grant.Descriptions) != 0 {
					t.Fatalf("outdated metadata: %+v", grant)
				}
				continue
			}
			if grant.ClientName != "読書アプリ" || grant.ResourceName != "図書館" || grant.Descriptions["library.loans"] != "貸出履歴" {
				t.Fatalf("business metadata: %+v", grant)
			}
		case oauth.IdentityResource:
			if grant.ResourceName != "アカウント情報" || grant.Descriptions["profile"] != "表示名とユーザー名" {
				t.Fatalf("identity metadata: %+v", grant)
			}
		case "urn:missing":
			if grant.ClientName != "missing" || grant.ResourceName != "urn:missing" || len(grant.Descriptions) != 0 {
				t.Fatalf("missing metadata: %+v", grant)
			}
		default:
			t.Fatalf("unexpected grant: %+v", grant)
		}
	}
	if got := other.do(t, "GET", "/api/me/consents", nil, http.StatusOK).Body.String(); got != "[]" {
		t.Fatalf("other user saw grants: %s", got)
	}
}
