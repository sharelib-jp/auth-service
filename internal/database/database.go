package database

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sharelib-jp/auth-service/internal/audit"
	"github.com/sharelib-jp/auth-service/internal/authorization"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

// Open opens SQLite. Retain _txlock=immediate in the DSN for concurrent writes.
func Open(dsn string) (*gorm.DB, error) {
	return OpenWithDriver("sqlite", dsn)
}

// OpenWithDriver opens and migrates SQLite or PostgreSQL. An empty driver uses SQLite.
func OpenWithDriver(driver, dsn string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	switch driver {
	case "", "sqlite":
		dialector = sqlite.Open(dsn)
	case "postgres":
		dialector = postgres.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	db, err := gorm.Open(dialector, &gorm.Config{TranslateError: true, Logger: logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
		SlowThreshold: time.Second, LogLevel: logger.Warn, ParameterizedQueries: true,
	})})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	if db.Dialector.Name() == "sqlite" {
		sqlDB.SetMaxOpenConns(1)
	} else {
		sqlDB.SetMaxOpenConns(10)
	}
	if err = db.AutoMigrate(&identity.User{}, &identity.UserAttributes{}, &identity.PasskeyCredential{}, &identity.LibraryIdSequence{}, &identity.CeremonySession{}, &identity.AuthSession{}, &consent.Grant{}, &consent.Event{}, &consent.SessionLink{}, &oauth.Client{}, &oauth.Resource{}, &oauth.Scope{}, &oauth.ResourceCredential{}, &oauth.SessionRecord{}, &oauth.SessionAudience{}, &oauth.AssertionJTI{}, &oauth.PendingAuthorization{}, &audit.Event{}, &audit.SecurityEvent{}, &authorization.RoleBinding{}, &authorization.Policy{}); err != nil {
		sqlDB.Close()
		return nil, err
	}
	// Seed from existing users without ever resetting an allocated sequence.
	err = db.Transaction(func(tx *gorm.DB) error {
		var max int
		if err := tx.Model(&identity.User{}).Select("COALESCE(MAX(library_id), 0)").Scan(&max).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&identity.LibraryIdSequence{ID: 1, Value: max}).Error; err != nil {
			return err
		}
		return tx.Model(&identity.LibraryIdSequence{}).Where("id = ? AND value < ?", 1, max).Update("value", max).Error
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}
