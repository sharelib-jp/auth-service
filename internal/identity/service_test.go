package identity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/database"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"gorm.io/gorm"
)

func testService(t *testing.T) (*identity.Service, *gorm.DB) {
	t.Helper()
	driver, dsn := testdb.Config(t)
	db, err := database.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	s, err := identity.NewService(&config.Config{
		SCHEME: "http://", HOSTNAME: "localhost", PORT: ":8080",
		WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DRIVER: driver, DATABASE_DSN: dsn,
	}, db)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

func TestRegistrationValidationWithoutHTTP(t *testing.T) {
	s, db := testService(t)
	ctx := t.Context()
	for _, input := range []identity.RegistrationInput{
		{UserName: "bad name", Name: "太郎", Email: "taro@example.com"},
		{UserName: "taro", Name: " ", Email: "taro@example.com"},
		{UserName: "taro", Name: "太郎", Email: "invalid"},
	} {
		if _, _, err := s.BeginRegistration(ctx, input, ""); !errors.Is(err, identity.ErrInvalidInput) {
			t.Fatalf("invalid registration returned %v", err)
		}
	}
	_, token, err := s.BeginRegistration(ctx, identity.RegistrationInput{
		UserName: " taro ", Name: " 登録 太郎 ", Email: " TARO@EXAMPLE.COM ",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	var session identity.CeremonySession
	if err := db.First(&session).Error; err != nil {
		t.Fatal(err)
	}
	pending := session.PendingUser
	if pending == nil || pending.UserName != "taro" || pending.Name != "登録 太郎" || pending.Email != "taro@example.com" {
		t.Fatalf("registration was not normalized: %+v", pending)
	}
	if token == "" || session.TokenHash == token {
		t.Fatal("ceremony token must be returned to the caller and stored only as a hash")
	}
	// A malformed response still consumes the registration ceremony.
	if _, _, err := s.FinishRegistration(ctx, token, "", strings.NewReader("invalid")); !errors.Is(err, identity.ErrInvalidInput) {
		t.Fatalf("malformed registration returned %v", err)
	}
	if _, _, err := s.FinishRegistration(ctx, token, "", strings.NewReader("{}")); err == nil || err.Error() != "missing or expired ceremony session" {
		t.Fatalf("registration ceremony was reusable: %v", err)
	}
	var count int64
	if err := db.Model(&identity.User{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("unverified registration persisted users: count=%d, error=%v", count, err)
	}
}

func TestLoginCeremonyReplacementAndConsumption(t *testing.T) {
	s, db := testService(t)
	ctx := t.Context()
	_, previous, err := s.BeginLogin(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := s.BeginLogin(ctx, previous)
	if err != nil {
		t.Fatal(err)
	}
	if token == previous {
		t.Fatal("begin must rotate the ceremony token")
	}
	if _, _, err := s.FinishLogin(ctx, previous, "", strings.NewReader("{}")); !errors.Is(err, identity.ErrInvalidInput) {
		t.Fatalf("replaced ceremony was accepted: %v", err)
	}
	if _, _, err := s.FinishLogin(ctx, token, "", strings.NewReader("invalid")); !errors.Is(err, identity.ErrInvalidPasskey) {
		t.Fatalf("malformed login returned %v", err)
	}
	if _, _, err := s.FinishLogin(ctx, token, "", strings.NewReader("{}")); !errors.Is(err, identity.ErrInvalidInput) {
		t.Fatalf("failed login ceremony was reusable: %v", err)
	}
	var count int64
	if err := db.Model(&identity.CeremonySession{}).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("consumed ceremony remained: count=%d, error=%v", count, err)
	}
}

func TestProfileAndAuthenticationWithoutHTTP(t *testing.T) {
	s, db := testService(t)
	ctx := t.Context()
	user := &identity.User{UserName: "taro", Name: "太郎", Email: "taro@example.com", RPID: "localhost"}
	if err := identity.CreateUser(db, user, &webauthn.Credential{ID: []byte("credential")}); err != nil {
		t.Fatal(err)
	}
	const token = "test-session-token"
	hash := sha256.Sum256([]byte(token))
	session := &identity.AuthSession{TokenHash: hex.EncodeToString(hash[:]), UserId: user.ID, ExpiresAt: time.Now().Add(identity.AuthTTL)}
	if err := identity.SaveAuthSession(db, session, ""); err != nil {
		t.Fatal(err)
	}
	authenticated, err := s.Authenticate(ctx, token)
	if err != nil || authenticated.ID != user.ID {
		t.Fatalf("authentication returned %+v, %v", authenticated, err)
	}
	if _, err := s.UpdateUserName(ctx, authenticated.ID, "bad name"); !errors.Is(err, identity.ErrInvalidInput) {
		t.Fatalf("invalid profile update returned %v", err)
	}
	updated, err := s.UpdateEmail(ctx, authenticated.ID, " NEW@EXAMPLE.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Email != "new@example.com" || updated.UserName != user.UserName || updated.Name != user.Name || updated.ID != user.ID || updated.LibraryId != user.LibraryId {
		t.Fatalf("profile update changed unexpected fields: %+v", updated)
	}
	other := &identity.User{UserName: "other", Name: "別人", Email: "other@example.com", RPID: "other.example.com"}
	if err := identity.CreateUser(db, other, &webauthn.Credential{ID: []byte("other-credential")}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateName(ctx, other.ID, "changed"); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("profile from another relying party was accepted: %v", err)
	}
	if err := s.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, token); !errors.Is(err, identity.ErrUnauthenticated) {
		t.Fatalf("logged-out token was accepted: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := s.BeginLogin(cancelled, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation was ignored: %v", err)
	}
}
