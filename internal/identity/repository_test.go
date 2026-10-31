package identity_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/database"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"gorm.io/gorm"
)

func testRepositoryDB(t *testing.T, driver, dsn string) *gorm.DB {
	t.Helper()
	db, err := database.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	return db
}

func TestUpdateUserAttributes(t *testing.T) {
	driver, dsn := testdb.Config(t)
	db := testRepositoryDB(t, driver, dsn)
	user := &identity.User{ID: uuid.New()}
	other := &identity.User{ID: uuid.New()}
	for _, update := range []struct {
		user  *identity.User
		key   string
		value interface{}
	}{
		{user, "theme", "dark"},
		{user, "enabled", true},
		{user, "theme", "light"},
		{user, "optional", nil},
		{other, "theme", "dark"},
	} {
		if err := identity.UpdateUserAttributes(db, update.user, update.key, update.value); err != nil {
			t.Fatal(err)
		}
	}
	var attrs identity.UserAttributes
	if err := db.First(&attrs, "user_id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	optional, exists := attrs.Value["optional"]
	if len(attrs.Value) != 3 || attrs.Value["theme"] != "light" || attrs.Value["enabled"] != true || !exists || optional != nil || attrs.UpdatedAt.IsZero() {
		t.Fatalf("unexpected persisted attributes: %+v", attrs)
	}
	var otherAttrs identity.UserAttributes
	if err := db.First(&otherAttrs, "user_id = ?", other.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(otherAttrs.Value) != 1 || otherAttrs.Value["theme"] != "dark" {
		t.Fatalf("another user's attributes changed: %+v", otherAttrs)
	}
	// A serialization failure must roll back creation of a new row.
	invalid := &identity.User{ID: uuid.New()}
	if err := identity.UpdateUserAttributes(db, invalid, "invalid", make(chan int)); err == nil {
		t.Fatal("expected a JSON serialization error")
	}
	var count int64
	if err := db.Model(&identity.UserAttributes{}).Where("user_id = ?", invalid.ID).Count(&count).Error; err != nil || count != 0 {
		t.Fatalf("failed create left a row: count=%d, error=%v", count, err)
	}
	// Existing rows may contain a JSON null rather than an initialized map.
	empty := &identity.User{ID: uuid.New()}
	if err := db.Create(&identity.UserAttributes{UserID: empty.ID}).Error; err != nil {
		t.Fatal(err)
	}
	if err := identity.UpdateUserAttributes(db, empty, "theme", "dark"); err != nil {
		t.Fatal(err)
	}
	var initialized identity.UserAttributes
	if err := db.First(&initialized, "user_id = ?", empty.ID).Error; err != nil {
		t.Fatal(err)
	}
	if initialized.Value["theme"] != "dark" {
		t.Fatalf("null map was not initialized: %+v", initialized)
	}
}

func TestConcurrentUserAttributeUpdates(t *testing.T) {
	driver, dsn := testdb.Config(t)
	dbs := []*gorm.DB{testRepositoryDB(t, driver, dsn), testRepositoryDB(t, driver, dsn)}
	user := &identity.User{ID: uuid.New()}
	const count = 24
	var group sync.WaitGroup
	for i := 0; i < count; i++ {
		group.Add(1)
		go func(n int) {
			defer group.Done()
			if err := identity.UpdateUserAttributes(dbs[n%2], user, fmt.Sprintf("key-%d", n), n); err != nil {
				t.Errorf("concurrent attribute update: %v", err)
			}
		}(i)
	}
	group.Wait()
	var attrs identity.UserAttributes
	if err := dbs[0].First(&attrs, "user_id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if len(attrs.Value) != count {
		t.Fatalf("concurrent updates lost keys: got %d, want %d", len(attrs.Value), count)
	}
	for i := 0; i < count; i++ {
		if attrs.Value[fmt.Sprintf("key-%d", i)] != float64(i) {
			t.Fatalf("unexpected value for key-%d: %v", i, attrs.Value)
		}
	}
}

func TestPostgresUserAttributesJSONB(t *testing.T) {
	driver, dsn := testdb.Config(t)
	if driver != "postgres" {
		t.Skip("set TEST_POSTGRES_DSN to verify PostgreSQL JSONB storage")
	}
	db := testRepositoryDB(t, driver, dsn)
	var dataType string
	if err := db.Raw(`SELECT data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'user_attributes' AND column_name = 'value'`).Scan(&dataType).Error; err != nil {
		t.Fatal(err)
	}
	if dataType != "jsonb" {
		t.Fatalf("attributes column type = %q, want jsonb", dataType)
	}
	user := &identity.User{ID: uuid.New()}
	if err := identity.CreateUserAttributes(db, user, map[string]any{"address": map[string]any{"city": "東京"}}); err != nil {
		t.Fatal(err)
	}
	var city string
	if err := db.Raw(`SELECT value->'address'->>'city' FROM user_attributes WHERE user_id = ?`, user.ID).Scan(&city).Error; err != nil || city != "東京" {
		t.Fatalf("nested JSONB query = %q, %v", city, err)
	}
	// Both SQL NULL and JSON null must initialize to an object on the first update.
	for _, nullValue := range []string{"NULL", "'null'::jsonb"} {
		if err := db.Exec("UPDATE user_attributes SET value = "+nullValue+" WHERE user_id = ?", user.ID).Error; err != nil {
			t.Fatal(err)
		}
		if err := identity.UpdateUserAttributes(db, user, "enabled", true); err != nil {
			t.Fatal(err)
		}
		var attrs identity.UserAttributes
		if err := db.First(&attrs, "user_id = ?", user.ID).Error; err != nil || len(attrs.Value) != 1 || attrs.Value["enabled"] != true {
			t.Fatalf("null attributes were not initialized: %+v, %v", attrs, err)
		}
	}
}
