package dao

import (
	"time"

	"github.com/sharelib-jp/auth-service/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func SaveCeremony(db *gorm.DB, session *models.CeremonySession, previousHash string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("expires_at <= ?", time.Now()).Delete(&models.CeremonySession{}).Error; err != nil {
			return err
		}
		if err := tx.Where("token_hash = ? AND kind = ?", previousHash, session.Kind).Delete(&models.CeremonySession{}).Error; err != nil {
			return err
		}
		return tx.Create(session).Error
	})
}

// TakeCeremony consumes a challenge once, including on failed verification.
func TakeCeremony(db *gorm.DB, tokenHash, kind string) (*models.CeremonySession, error) {
	var session models.CeremonySession
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("token_hash = ? AND kind = ?", tokenHash, kind).First(&session).Error; err != nil {
			return err
		}
		return tx.Delete(&session).Error
	})
	if err != nil {
		return nil, err
	}
	if !session.ExpiresAt.After(time.Now()) {
		return nil, gorm.ErrRecordNotFound
	}
	return &session, nil
}

// SaveAuthSession replaces the previous session atomically. It can also join a
// registration or login transaction so that account and credential changes roll back together.
func SaveAuthSession(db *gorm.DB, session *models.AuthSession, previousHash string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("expires_at <= ?", time.Now()).Delete(&models.AuthSession{}).Error; err != nil {
			return err
		}
		if err := DeleteAuthSession(tx, previousHash); err != nil {
			return err
		}
		return tx.Create(session).Error
	})
}

func FindAuthSession(db *gorm.DB, tokenHash string) (*models.AuthSession, error) {
	var session models.AuthSession
	if err := db.Preload("User").Where("token_hash = ? AND expires_at > ?", tokenHash, time.Now()).First(&session).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

func DeleteAuthSession(db *gorm.DB, tokenHash string) error {
	return db.Where("token_hash = ?", tokenHash).Delete(&models.AuthSession{}).Error
}
