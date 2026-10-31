package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/consent"
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
