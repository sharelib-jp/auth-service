package dao

import (
	"encoding/base64"
	"errors"

	"github.com/sharelib-jp/auth-service/models"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// CreateUser persists the account, full public-key credential, and allocation atomically.
func CreateUser(db *gorm.DB, user *models.User, credential *webauthn.Credential) error {
	return db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&models.LibraryIdSequence{}).
			Where("id = ? AND value < ?", 1, models.MaxLibraryId).
			Update("value", gorm.Expr("value + 1"))
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrLibraryIdExhausted
		}
		var sequence models.LibraryIdSequence
		if err := tx.First(&sequence, 1).Error; err != nil {
			return err
		}
		user.LibraryId = sequence.Value
		if err := tx.Create(user).Error; err != nil {
			return err
		}
		return tx.Create(&models.PasskeyCredential{
			UserId: user.ID, RPID: user.RPID,
			CredentialId: base64.RawURLEncoding.EncodeToString(credential.ID),
			Credential:   *credential,
		}).Error
	})
}

func UserExists(db *gorm.DB, userName, email string) (bool, error) {
	var count int64
	err := db.Model(&models.User{}).Where("user_name = ? OR email = ?", userName, email).Count(&count).Error
	return count != 0, err
}

func FindUser(db *gorm.DB, userID uuid.UUID, rpID string) (*models.User, error) {
	var user models.User
	if err := db.Where("id = ? AND rp_id = ?", userID, rpID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUserField takes a column chosen by the service, never by client input.
func UpdateUserField(db *gorm.DB, user *models.User, column, value string) error {
	return db.Model(user).Update(column, value).Error
}

func FindPasskeyUser(db *gorm.DB, rpID string, rawID, userHandle []byte) (*models.User, error) {
	var stored models.PasskeyCredential
	// The login transaction holds this lock through verification and counter update.
	if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("rp_id = ? AND credential_id = ?", rpID,
		base64.RawURLEncoding.EncodeToString(rawID)).First(&stored).Error; err != nil {
		return nil, err
	}
	var user models.User
	err := db.Preload("Credentials", "rp_id = ?", rpID).
		Where("id = ? AND rp_id = ? AND webauthn_handle = ?", stored.UserId, rpID, userHandle).
		First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func UpdateCredential(db *gorm.DB, user *models.User, credential *webauthn.Credential) error {
	var stored models.PasskeyCredential
	if err := db.Where("user_id = ? AND rp_id = ? AND credential_id = ?", user.ID,
		user.RPID, base64.RawURLEncoding.EncodeToString(credential.ID)).First(&stored).Error; err != nil {
		return err
	}
	// Save the entire returned credential, including counters and backup flags.
	stored.Credential = *credential
	return db.Save(&stored).Error
}

func CreateUserAttributes(db *gorm.DB, user *models.User, attributes map[string]any) error {
	return db.Create(&models.UserAttributes{UserID: user.ID, Value: attributes}).Error
}

// UpdateUserAttributes sets one JSON key, creating the attributes row if needed.
// PostgreSQL merges atomically; SQLite requires the recommended _txlock=immediate DSN.
func UpdateUserAttributes(db *gorm.DB, user *models.User, key string, value interface{}) error {
	if db.Dialector.Name() == "postgres" {
		return db.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.Assignments(map[string]any{
				"value":      gorm.Expr("COALESCE(NULLIF(user_attributes.value, 'null'::jsonb), '{}'::jsonb) || EXCLUDED.value"),
				"updated_at": gorm.Expr("EXCLUDED.updated_at"),
			}),
		}).Create(&models.UserAttributes{UserID: user.ID, Value: map[string]any{key: value}}).Error
	}
	return db.Transaction(func(tx *gorm.DB) error {
		var attrs models.UserAttributes
		err := tx.Where("user_id = ?", user.ID).First(&attrs).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&models.UserAttributes{
				UserID: user.ID,
				Value:  map[string]interface{}{key: value},
			}).Error
		}
		if err != nil {
			return err
		}
		if attrs.Value == nil {
			attrs.Value = make(map[string]interface{})
		}
		attrs.Value[key] = value
		return tx.Save(&attrs).Error
	})
}
