package oauth_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/oauth"
)

func TestPendingAuthorizationBoundToBrowserUserAndTransaction(t *testing.T) {
	store, _, _, _, _ := testStore(t)
	ctx := context.Background()
	browser, err := oauth.RandomBrowserToken()
	if err != nil {
		t.Fatal(err)
	}
	otherBrowser, _ := oauth.RandomBrowserToken()
	handle, err := store.CreatePending(ctx, url.Values{"client_id": {"client"}, "state": {"state-value"}}, browser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPending(ctx, handle, otherBrowser); !errors.Is(err, oauth.ErrPendingAuthorization) {
		t.Fatalf("other browser accessed request: %v", err)
	}
	form, err := store.GetPending(ctx, handle, browser)
	if err != nil || form.Get("state") != "state-value" {
		t.Fatalf("request: %v, %v", form, err)
	}
	userID := uuid.New()
	csrf, err := store.IssueConsentCSRF(ctx, handle, browser, userID, "original snapshot")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumePending(tx, handle, browser, csrf, uuid.New(), "original snapshot"); !errors.Is(err, oauth.ErrPendingAuthorization) {
		t.Fatalf("other user consumed request: %v", err)
	}
	if err := store.ConsumePending(tx, handle, browser, csrf, userID, "changed snapshot"); !errors.Is(err, oauth.ErrPendingAuthorization) {
		t.Fatalf("changed snapshot was accepted: %v", err)
	}
	if err := store.ConsumePending(tx, handle, browser, csrf, userID, "original snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := store.Rollback(tx); err != nil {
		t.Fatal(err)
	}
	tx, err = store.BeginTX(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ConsumePending(tx, handle, browser, csrf, userID, "original snapshot"); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(tx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPending(ctx, handle, browser); !errors.Is(err, oauth.ErrPendingAuthorization) {
		t.Fatalf("consumed request returned: %v", err)
	}
}
