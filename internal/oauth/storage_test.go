package oauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/database"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"gorm.io/gorm"
)

func testStore(t *testing.T) (*oauth.Store, *consent.Service, *gorm.DB, *fosite.Request, *consent.Grant) {
	t.Helper()
	driver, dsn := testdb.Config(t)
	db, err := database.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { sqlDB.Close() })
	client := oauth.Client{ID: "client", Name: "Client", Status: "active", Public: true, RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "offline_access", "b.orders.read"}, Audience: []string{"https://b.example/api"}}
	if err := db.Create(&client).Error; err != nil {
		t.Fatal(err)
	}
	resource := oauth.Resource{ID: "b", Identifier: client.Audience[0], Name: "B", Status: "active"}
	if err := db.Create(&resource).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&oauth.Scope{ID: "orders-read", ResourceID: resource.ID, Name: "b.orders.read", Description: "Read orders", PurposeCode: "orders", PolicyVersion: 1, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	service := consent.NewService(consent.NewRepository(db))
	userID := uuid.New()
	grant, err := service.Create(context.Background(), consent.Grant{UserID: userID, ClientID: client.ID, Resource: client.Audience[0], Scopes: []string{"b.orders.read"}, PurposeCode: "orders"})
	if err != nil {
		t.Fatal(err)
	}
	store := oauth.NewStore(db)
	fositeClient, err := store.GetClient(context.Background(), client.ID)
	if err != nil {
		t.Fatal(err)
	}
	session := oauth.NewSession()
	session.SetSubject(userID.String())
	session.GrantIDs = []uuid.UUID{grant.ID}
	req := fosite.NewRequest()
	req.Client, req.Session = fositeClient, session
	req.SetID(uuid.NewString())
	req.GrantScope("openid")
	req.GrantScope("b.orders.read")
	req.GrantAudience(client.Audience[0])
	req.Form.Set("redirect_uri", client.RedirectURIs[0])
	return store, service, db, req, grant
}

func TestStorageCodeRotationAndRevocation(t *testing.T) {
	store, service, db, req, grant := testStore(t)
	ctx := context.Background()
	if err := store.CreateAuthorizeCodeSession(ctx, "raw-code", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(ctx, "raw-access", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "raw-refresh", "raw-access", req); err != nil {
		t.Fatal(err)
	}
	var records []oauth.SessionRecord
	if err := db.Find(&records).Error; err != nil {
		t.Fatal(err)
	}
	for _, row := range records {
		if strings.Contains(row.KeyHash, "raw-") || strings.Contains(string(row.Payload), "raw-") {
			t.Fatal("raw token stored")
		}
	}
	if err := store.InvalidateAuthorizeCodeSession(ctx, "raw-code"); err != nil {
		t.Fatal(err)
	}
	if original, err := store.GetAuthorizeCodeSession(ctx, "raw-code", oauth.NewSession()); !errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) || original == nil || original.GetID() != req.ID {
		t.Fatalf("code reuse: %v, %v", original, err)
	}
	txCtx, err := store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RotateRefreshToken(txCtx, req.ID, "raw-refresh"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(txCtx, "next-access", req); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateRefreshTokenSession(txCtx, "next-refresh", "next-access", req); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(txCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "raw-access", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("old access active: %v", err)
	}
	if original, err := store.GetRefreshTokenSession(ctx, "raw-refresh", oauth.NewSession()); !errors.Is(err, fosite.ErrInactiveToken) || original == nil {
		t.Fatalf("old refresh active: %v", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "next-access", oauth.NewSession()); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, grant.UserID, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "next-access", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("revoked consent access: %v", err)
	}
	if _, err := store.GetRefreshTokenSession(ctx, "next-refresh", oauth.NewSession()); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("revoked consent refresh: %v", err)
	}
	if err := store.CreateAccessTokenSession(ctx, "after-revoke", req); err == nil {
		t.Fatal("issued access after revocation")
	}
}

func TestStorageConsentScopeAndTransaction(t *testing.T) {
	store, _, _, req, _ := testStore(t)
	ctx := context.Background()
	req.GrantScope("b.orders.write")
	if err := store.CreateAccessTokenSession(ctx, "not-covered", req); err == nil {
		t.Fatal("issued uncovered scope")
	}
	req.GrantedScope = []string{"openid", "b.orders.read"}
	txCtx, err := store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(txCtx, "rollback", req); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(txCtx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "rollback", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("rollback failed: %v", err)
	}
}

func TestPolicyChangeInvalidatesExistingTokens(t *testing.T) {
	store, _, db, req, _ := testStore(t)
	ctx := context.Background()
	if err := store.CreateAccessTokenSession(ctx, "policy-token", req); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&oauth.Scope{}).Where("name = ?", "b.orders.read").Update("policy_version", 2).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "policy-token", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("policy change was ignored: %v", err)
	}
	if err := store.CreateAccessTokenSession(ctx, "new-token", req); err == nil {
		t.Fatal("issued token using stale policy consent")
	}
}

func TestUnknownConsentConditionsFailClosed(t *testing.T) {
	store, service, db, req, grant := testStore(t)
	ctx := context.Background()
	if _, err := service.Create(ctx, consent.Grant{UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scopes: grant.Scopes, PurposeCode: grant.PurposeCode, ConditionsVersion: 1, Conditions: map[string]any{"organizations": []string{"org-a"}}}); !errors.Is(err, consent.ErrInvalidGrant) {
		t.Fatalf("unsupported condition accepted: %v", err)
	}
	if err := store.CreateAccessTokenSession(ctx, "condition-token", req); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&consent.Grant{}).Where("id = ?", grant.ID).Update("conditions_version", 1).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "condition-token", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("unknown condition accepted for token: %v", err)
	}
}

func TestPartialConsentRevocationPreservesUnrelatedGrantsAndTokens(t *testing.T) {
	store, service, db, req, first := testStore(t)
	ctx := context.Background()
	var client oauth.Client
	if err := db.First(&client, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	client.Scopes = append(client.Scopes, "b.projects.read")
	if err := db.Save(&client).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&oauth.Scope{ID: "projects-read", ResourceID: "b", Name: "b.projects.read", Description: "Read projects", PurposeCode: "projects", PolicyVersion: 1, Status: "active"}).Error; err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(ctx, consent.Grant{UserID: first.UserID, ClientID: first.ClientID, Resource: first.Resource, Scopes: []string{"b.projects.read"}, PurposeCode: "projects"})
	if err != nil {
		t.Fatal(err)
	}
	fositeClient, err := store.GetClient(ctx, "client")
	if err != nil {
		t.Fatal(err)
	}
	req.Client = fositeClient
	combined := *req
	combined.GrantedScope = []string{"b.orders.read", "b.projects.read"}
	combined.Session = req.Session.Clone()
	combined.Session.(*oauth.Session).GrantIDs = []uuid.UUID{first.ID, second.ID}
	separate := *req
	separate.SetID(uuid.NewString())
	separate.GrantedScope = []string{"b.projects.read"}
	separate.Session = req.Session.Clone()
	separate.Session.(*oauth.Session).GrantIDs = []uuid.UUID{second.ID}
	if err := store.CreateAccessTokenSession(ctx, "combined", &combined); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(ctx, "separate", &separate); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, first.UserID, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "combined", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("combined token still active: %v", err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "separate", oauth.NewSession()); err != nil {
		t.Fatalf("unrelated token revoked: %v", err)
	}
	stored, err := service.Get(ctx, second.UserID, second.ID)
	if err != nil || stored.Status != consent.Active {
		t.Fatalf("unrelated grant revoked: %+v %v", stored, err)
	}
}

func TestDisabledRegistrationCannotReactivateOldTokens(t *testing.T) {
	for _, kind := range []string{"client", "resource", "scope"} {
		t.Run(kind, func(t *testing.T) {
			store, _, db, req, _ := testStore(t)
			ctx := context.Background()
			if err := store.CreateAccessTokenSession(ctx, "old-token", req); err != nil {
				t.Fatal(err)
			}
			id := map[string]string{"client": "client", "resource": "b", "scope": "orders-read"}[kind]
			catalog := oauth.NewCatalog(db)
			if err := catalog.SetStatus(ctx, kind, id, "disabled"); err != nil {
				t.Fatal(err)
			}
			if err := catalog.SetStatus(ctx, kind, id, "active"); err != nil {
				t.Fatal(err)
			}
			if _, err := store.GetAccessTokenSession(ctx, "old-token", oauth.NewSession()); err == nil {
				t.Fatal("old token reactivated")
			}
		})
	}
}

func TestIdentityOnlyTokenCannotTargetDisabledResource(t *testing.T) {
	store, _, db, req, _ := testStore(t)
	ctx := context.Background()
	req.GrantedScope = []string{"openid"}
	req.Session.(*oauth.Session).GrantIDs = nil
	if err := oauth.NewCatalog(db).SetStatus(ctx, "resource", "b", "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(ctx, "disabled-resource-token", req); err == nil {
		t.Fatal("issued token for disabled resource")
	}
}

func TestExpiredAndRenewedConsentCannotReactivateOldToken(t *testing.T) {
	store, service, db, req, grant := testStore(t)
	ctx := context.Background()
	if err := store.CreateAccessTokenSession(ctx, "expired-consent-token", req); err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&consent.Grant{}).Where("id = ?", grant.ID).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	var expiredGrant consent.Grant
	if err := db.First(&expiredGrant, "id = ?", grant.ID).Error; err != nil || expiredGrant.ExpiresAt == nil || expiredGrant.ExpiresAt.After(time.Now()) {
		t.Fatalf("failed to expire consent: %+v %v", expiredGrant.ExpiresAt, err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "expired-consent-token", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("expired consent token: %v", err)
	}
	if err := store.CreateRefreshTokenSession(ctx, "expired-refresh", "", req); err == nil {
		t.Fatal("refresh token issued for expired consent")
	}
	renewed, err := service.Create(ctx, consent.Grant{UserID: grant.UserID, ClientID: grant.ClientID, Resource: grant.Resource, Scopes: grant.Scopes, PurposeCode: grant.PurposeCode, PolicyVersion: grant.PolicyVersion})
	if err != nil {
		t.Fatal(err)
	}
	newReq := *req
	newReq.Session = req.Session.Clone()
	newReq.Session.(*oauth.Session).GrantIDs = []uuid.UUID{renewed.ID}
	if err := store.CreateAccessTokenSession(ctx, "renewed-consent-token", &newReq); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "renewed-consent-token", oauth.NewSession()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetAccessTokenSession(ctx, "expired-consent-token", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatal("old token reactivated by new consent")
	}
}

func TestPostgresRevocationSerializesWithIssuance(t *testing.T) {
	store, service, db, req, grant := testStore(t)
	if db.Dialector.Name() != "postgres" {
		t.Skip("requires PostgreSQL row locking")
	}
	ctx := context.Background()
	txCtx, err := store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateAccessTokenSession(txCtx, "concurrent", req); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- service.Revoke(ctx, grant.UserID, grant.ID) }()
	select {
	case err := <-done:
		t.Fatalf("revoke completed before issuance committed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := store.Commit(txCtx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revoke blocked")
	}
	if _, err := store.GetAccessTokenSession(ctx, "concurrent", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("access remained active: %v", err)
	}
}

func TestConcurrentConsentRevocationIsIdempotent(t *testing.T) {
	store, service, db, req, grant := testStore(t)
	if err := store.CreateAccessTokenSession(context.Background(), "concurrent-revoke-token", req); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- service.Revoke(context.Background(), grant.UserID, grant.ID) }()
	}
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	var events []consent.Event
	if err := db.Where("grant_id = ?", grant.ID).Find(&events).Error; err != nil || len(events) != 2 {
		t.Fatalf("duplicate revocation history: %+v %v", events, err)
	}
	if _, err := store.GetAccessTokenSession(context.Background(), "concurrent-revoke-token", oauth.NewSession()); !errors.Is(err, fosite.ErrNotFound) {
		t.Fatalf("token remained active: %v", err)
	}
}
