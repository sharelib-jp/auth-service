// Package testdb isolates database tests in a SQLite file or a PostgreSQL schema.
package testdb

import (
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config selects PostgreSQL when TEST_POSTGRES_DSN is set, otherwise SQLite.
// The PostgreSQL role must be able to create and drop schemas in a test dao.
func Config(t *testing.T) (driver, dsn string) {
	t.Helper()
	dsn = os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		return "sqlite", filepath.Join(t.TempDir(), "auth.db") + "?_foreign_keys=on&_busy_timeout=5000&_txlock=immediate"
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		admin.Close()
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		return "postgres", u.String()
	}
	return "postgres", dsn + " search_path=" + schema
}
