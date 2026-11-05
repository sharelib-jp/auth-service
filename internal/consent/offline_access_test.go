package consent_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/database"
	"github.com/sharelib-jp/auth-service/internal/testdb"
)

func TestOfflineAccessConsentMustBeDedicatedToIdentitySession(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db, err := database.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	pool, _ := db.DB()
	t.Cleanup(func() { pool.Close() })
	service := consent.NewService(consent.NewRepository(db))
	base := consent.Grant{UserID: uuid.New(), ClientID: "login-client", Resource: consent.IdentityResource, PurposeCode: consent.OfflineAccessPurpose, Scopes: []string{"offline_access"}}
	for _, invalid := range []consent.Grant{
		{UserID: base.UserID, ClientID: base.ClientID, Resource: "https://business.example/api", PurposeCode: base.PurposeCode, Scopes: base.Scopes},
		{UserID: base.UserID, ClientID: base.ClientID, Resource: base.Resource, PurposeCode: "other-purpose", Scopes: base.Scopes},
		{UserID: base.UserID, ClientID: base.ClientID, Resource: base.Resource, PurposeCode: base.PurposeCode, Scopes: []string{"offline_access", "profile"}},
		{UserID: base.UserID, ClientID: base.ClientID, Resource: base.Resource, PurposeCode: base.PurposeCode, Scopes: []string{"offline_access", "b.orders.read"}},
		{UserID: base.UserID, ClientID: base.ClientID, Resource: base.Resource, PurposeCode: base.PurposeCode, Scopes: []string{"openid"}},
	} {
		if _, err := service.Create(t.Context(), invalid); !errors.Is(err, consent.ErrInvalidGrant) {
			t.Fatalf("invalid session grant accepted: %v", err)
		}
	}
	saved, err := service.Create(t.Context(), base)
	if err != nil || saved == nil || saved.Status != consent.Active {
		t.Fatalf("dedicated session grant rejected: %v", err)
	}
	if err := service.Revoke(t.Context(), base.UserID, saved.ID); err != nil {
		t.Fatal(err)
	}
	grant, err := service.Get(t.Context(), base.UserID, saved.ID)
	if err != nil || grant.Status != consent.Revoked {
		t.Fatal("session consent could not be revoked")
	}
}
