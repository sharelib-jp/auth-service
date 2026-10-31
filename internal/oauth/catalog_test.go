package oauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sharelib-jp/auth-service/internal/oauth"
	"golang.org/x/crypto/bcrypt"
)

func TestCatalogRegistration(t *testing.T) {
	_, _, db, _, _ := testStore(t)
	catalog := oauth.NewCatalog(db)
	ctx := context.Background()
	if err := catalog.RegisterResource(ctx, oauth.Resource{ID: "new", Identifier: "https://new.example/api", Name: "New"}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.RegisterScope(ctx, oauth.Scope{ID: "new-read", ResourceID: "new", Name: "new.read", Description: "Read", PurposeCode: "reading", PolicyVersion: 1}); err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "new-client", Name: "Client", RedirectURIs: []string{"https://client.example/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "new.read"}, Audience: []string{"https://new.example/api"}}
	secret := strings.Repeat("z", 32)
	if err := catalog.RegisterClient(ctx, client, secret); err != nil {
		t.Fatal(err)
	}
	var stored oauth.Client
	if err := db.First(&stored, "id = ?", client.ID).Error; err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword(stored.SecretHash, []byte(secret)) != nil || string(stored.SecretHash) == secret {
		t.Fatal("secret was not hashed")
	}
	client.ID = "bad-client"
	client.Audience = []string{"https://b.example/api"}
	if err := catalog.RegisterClient(ctx, client, secret); !errors.Is(err, oauth.ErrInvalidRegistration) {
		t.Fatalf("accepted scope for unregistered audience: %v", err)
	}
	client.Audience = []string{"https://new.example/api"}
	client.RedirectURIs = []string{"https://attacker.example/callback#fragment"}
	if err := catalog.RegisterClient(ctx, client, secret); !errors.Is(err, oauth.ErrInvalidRegistration) {
		t.Fatalf("accepted invalid redirect: %v", err)
	}
}

func TestClientUpdateRevokesPreviouslyIssuedSessions(t *testing.T) {
	store, _, db, req, _ := testStore(t)
	ctx := context.Background()
	if err := store.CreateAccessTokenSession(ctx, "old-client-token", req); err != nil {
		t.Fatal(err)
	}
	var client oauth.Client
	if err := db.First(&client, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	client.Name = "Updated name"
	client.RedirectURIs = []string{"https://client.example/new-callback"}
	if err := oauth.NewCatalog(db).UpdateClient(ctx, client, ""); err != nil {
		t.Fatal(err)
	}
	var updated oauth.Client
	if err := db.First(&updated, "id = ?", "client").Error; err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated name" || len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://client.example/new-callback" || !updated.Public {
		t.Fatalf("client update: %+v", updated)
	}
	if _, err := store.GetAccessTokenSession(ctx, "old-client-token", oauth.NewSession()); err == nil {
		t.Fatal("client update retained token")
	}
}
