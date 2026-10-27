package dao

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"github.com/sharelib-jp/auth-service/models"
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

func testUser(n int) (*models.User, *webauthn.Credential) {
	return &models.User{UserName: fmt.Sprintf("user-%d", n), Name: "Test", Email: fmt.Sprintf("%d@example.com", n), RPID: "localhost"},
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
	attrs := &models.UserAttributes{UserID: uuid.New(), Value: map[string]any{"theme": "dark", "enabled": true}}
	if err := legacy.Create(attrs).Error; err != nil {
		t.Fatal(err)
	}
	db := testDB(t, "sqlite", dsn)
	var stored models.UserAttributes
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
			if err := CreateUser(dbs[n%2], user, credential); err != nil {
				t.Errorf("concurrent create: %v", err)
			}
		}(i)
	}
	group.Wait()
	var users []models.User
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
	if err := CreateUser(dbs[0], user, credential); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate must fail: %v", err)
	}
	user, credential = testUser(count)
	if err := CreateUser(dbs[0], user, credential); err != nil {
		t.Fatal(err)
	}
	if user.LibraryId != count+1 {
		t.Fatalf("failed create consumed ID: %d", user.LibraryId)
	}
	// A credential conflict also rolls back the user and sequence.
	user, _ = testUser(count + 1)
	if err := CreateUser(dbs[0], user, credential); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate credential must fail: %v", err)
	}
	user, credential = testUser(count + 2)
	if err := CreateUser(dbs[0], user, credential); err != nil || user.LibraryId != count+2 {
		t.Fatalf("credential conflict did not roll back: ID=%d, error=%v", user.LibraryId, err)
	}
	// Reopening must not reuse the highest issued ID, even after deletion.
	if err := dbs[0].Delete(user).Error; err != nil {
		t.Fatal(err)
	}
	reopened := testDB(t, driver, dsn)
	user, credential = testUser(count + 3)
	if err := CreateUser(reopened, user, credential); err != nil || user.LibraryId != count+3 {
		t.Fatalf("sequence did not survive reopen: ID=%d, error=%v", user.LibraryId, err)
	}
}

func TestLibraryIdExhaustion(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db := testDB(t, driver, dsn)
	if err := db.Model(&models.LibraryIdSequence{}).Where("id = 1").Update("value", models.MaxLibraryId-1).Error; err != nil {
		t.Fatal(err)
	}
	user, credential := testUser(1)
	if err := CreateUser(db, user, credential); err != nil || user.LibraryId != models.MaxLibraryId {
		t.Fatalf("last ID: ID=%d, error=%v", user.LibraryId, err)
	}
	user, credential = testUser(2)
	if err := CreateUser(db, user, credential); !errors.Is(err, ErrLibraryIdExhausted) {
		t.Fatalf("overflow must fail: %v", err)
	}
	var count int64
	db.Model(&models.User{}).Count(&count)
	if count != 1 {
		t.Fatalf("overflow created a user: %d", count)
	}
}

func TestCeremonyConsumedOnce(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db := testDB(t, driver, dsn)
	if err := db.Create(&models.CeremonySession{TokenHash: "test", Kind: "login", ExpiresAt: time.Now().Add(time.Minute)}).Error; err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, err := TakeCeremony(db, "test", "login"); results <- err }()
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
