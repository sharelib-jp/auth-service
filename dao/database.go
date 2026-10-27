package dao

import (
	"errors"
	"fmt"

	"github.com/sharelib-jp/auth-service/models"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrLibraryIdExhausted = errors.New("LibraryId range exhausted")

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
	db, err := gorm.Open(dialector, &gorm.Config{TranslateError: true})
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
	if err = db.AutoMigrate(&models.User{}, &models.UserAttributes{}, &models.PasskeyCredential{}, &models.LibraryIdSequence{}, &models.CeremonySession{}, &models.AuthSession{}); err != nil {
		sqlDB.Close()
		return nil, err
	}
	// Seed from existing users without ever resetting an allocated sequence.
	err = db.Transaction(func(tx *gorm.DB) error {
		var max int
		if err := tx.Model(&models.User{}).Select("COALESCE(MAX(library_id), 0)").Scan(&max).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&models.LibraryIdSequence{ID: 1, Value: max}).Error; err != nil {
			return err
		}
		return tx.Model(&models.LibraryIdSequence{}).Where("id = ? AND value < ?", 1, max).Update("value", max).Error
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}
