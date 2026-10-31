package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func testDB(t *testing.T, driver, dsn string) *gorm.DB {
	t.Helper()
	db, err := OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { sqlDB.Close() })
	return db
}

func TestOAuthMigrationPreservesExistingAuthentication(t *testing.T) {
	driver, dsn := testdb.Config(t)
	var dialector gorm.Dialector
	if driver == "postgres" {
		dialector = postgres.Open(dsn)
	} else {
		dialector = sqlite.Open(dsn)
	}
	legacy, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.AutoMigrate(&identity.User{}, &identity.UserAttributes{}, &identity.PasskeyCredential{}, &identity.LibraryIdSequence{}, &identity.CeremonySession{}, &identity.AuthSession{}); err != nil {
		t.Fatal(err)
	}
	user, credential := testUser(1)
	user.LibraryId = 1
	if err := legacy.Create(user).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Create(&identity.PasskeyCredential{UserId: user.ID, RPID: "localhost", CredentialId: "legacy", Credential: *credential}).Error; err != nil {
		t.Fatal(err)
	}
	if err := legacy.Create(&identity.AuthSession{TokenHash: "legacy-hash", UserId: user.ID, ExpiresAt: time.Now().Add(time.Hour)}).Error; err != nil {
		t.Fatal(err)
	}
	legacySQL, _ := legacy.DB()
	if err := legacySQL.Close(); err != nil {
		t.Fatal(err)
	}
	db := testDB(t, driver, dsn)
	session, err := identity.FindAuthSession(db, "legacy-hash")
	if err != nil || session.User.ID != user.ID {
		t.Fatalf("legacy session changed: %+v %v", session, err)
	}
	var stored identity.PasskeyCredential
	if err := db.Where("user_id = ?", user.ID).First(&stored).Error; err != nil || stored.CredentialId != "legacy" {
		t.Fatalf("legacy credential changed: %+v %v", stored, err)
	}
	for _, table := range []any{&oauth.Client{}, &oauth.SessionRecord{}, &consent.Grant{}} {
		if !db.Migrator().HasTable(table) {
			t.Fatalf("missing migrated table %T", table)
		}
	}
}

func testUser(n int) (*identity.User, *webauthn.Credential) {
	return &identity.User{UserName: fmt.Sprintf("user-%d", n), Name: "Test", Email: fmt.Sprintf("%d@example.com", n), RPID: "localhost"},
		&webauthn.Credential{ID: []byte(fmt.Sprintf("credential-%d", n)), PublicKey: []byte("test")}
}

func TestUnsupportedDatabaseDriver(t *testing.T) {
	if _, err := OpenWithDriver("unsupported", "test.db"); err == nil {
		t.Fatal("unsupported driver must be rejected")
	}
}

func TestSQLiteAttributeMigrationPreservesData(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "legacy.db") + "?_foreign_keys=on&_txlock=immediate"
	legacy, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := legacy.DB()
	defer sqlDB.Close()
	if err := legacy.Exec(`CREATE TABLE user_attributes (user_id uuid PRIMARY KEY, updated_at datetime, value text)`).Error; err != nil {
		t.Fatal(err)
	}
	attrs := &identity.UserAttributes{UserID: uuid.New(), Value: map[string]any{"theme": "dark", "enabled": true}}
	if err := legacy.Create(attrs).Error; err != nil {
		t.Fatal(err)
	}
	db := testDB(t, "sqlite", dsn)
	var stored identity.UserAttributes
	if err := db.First(&stored, "user_id = ?", attrs.UserID).Error; err != nil {
		t.Fatal(err)
	}
	if len(stored.Value) != 2 || stored.Value["theme"] != "dark" || stored.Value["enabled"] != true || !stored.UpdatedAt.Equal(attrs.UpdatedAt) {
		t.Fatalf("migration changed existing attributes: %+v", stored)
	}
}

func TestLibraryIdConcurrentAllocationAndRollback(t *testing.T) {
	driver, dsn := testdb.Config(t)
	dbs := []*gorm.DB{testDB(t, driver, dsn), testDB(t, driver, dsn)}
	const count = 24
	var group sync.WaitGroup
	for i := 0; i < count; i++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			user, credential := testUser(n)
			if err := identity.CreateUser(dbs[n%2], user, credential); err != nil {
				t.Errorf("concurrent create: %v", err)
			}
		}(i)
	}
	group.Wait()
	var users []identity.User
	if err := dbs[0].Order("library_id").Find(&users).Error; err != nil {
		t.Fatal(err)
	}
	if len(users) != count {
		t.Fatalf("got %d users; want %d", len(users), count)
	}
	for i, user := range users {
		if user.LibraryId != i+1 || user.ID.Version() != 7 {
			t.Fatalf("invalid generated IDs: %+v", user)
		}
	}
	user, credential := testUser(0)
	if err := identity.CreateUser(dbs[0], user, credential); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate must fail: %v", err)
	}
	user, credential = testUser(count)
	if err := identity.CreateUser(dbs[0], user, credential); err != nil {
		t.Fatal(err)
	}
	if user.LibraryId != count+1 {
		t.Fatalf("failed create consumed ID: %d", user.LibraryId)
	}
	// A credential conflict also rolls back the user and sequence.
	user, _ = testUser(count + 1)
	if err := identity.CreateUser(dbs[0], user, credential); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate credential must fail: %v", err)
	}
	user, credential = testUser(count + 2)
	if err := identity.CreateUser(dbs[0], user, credential); err != nil || user.LibraryId != count+2 {
		t.Fatalf("credential conflict did not roll back: ID=%d, error=%v", user.LibraryId, err)
	}
	// Reopening must not reuse the highest issued ID, even after deletion.
	if err := dbs[0].Delete(user).Error; err != nil {
		t.Fatal(err)
	}
	reopened := testDB(t, driver, dsn)
	user, credential = testUser(count + 3)
	if err := identity.CreateUser(reopened, user, credential); err != nil || user.LibraryId != count+3 {
		t.Fatalf("sequence did not survive reopen: ID=%d, error=%v", user.LibraryId, err)
	}
}

func TestLibraryIdExhaustion(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db := testDB(t, driver, dsn)
	if err := db.Model(&identity.LibraryIdSequence{}).Where("id = 1").Update("value", identity.MaxLibraryId-1).Error; err != nil {
		t.Fatal(err)
	}
	user, credential := testUser(1)
	if err := identity.CreateUser(db, user, credential); err != nil || user.LibraryId != identity.MaxLibraryId {
		t.Fatalf("last ID: ID=%d, error=%v", user.LibraryId, err)
	}
	user, credential = testUser(2)
	if err := identity.CreateUser(db, user, credential); !errors.Is(err, identity.ErrLibraryIdExhausted) {
		t.Fatalf("overflow must fail: %v", err)
	}
	var count int64
	db.Model(&identity.User{}).Count(&count)
	if count != 1 {
		t.Fatalf("overflow created a user: %d", count)
	}
}

func TestCeremonyConsumedOnce(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db := testDB(t, driver, dsn)
	if err := db.Create(&identity.CeremonySession{TokenHash: "test", Kind: "login", ExpiresAt: time.Now().Add(time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := identity.TakeCeremony(db, "test", "login"); results <- err }()
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			successes++
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("ceremony consumed %d times", successes)
	}
}
