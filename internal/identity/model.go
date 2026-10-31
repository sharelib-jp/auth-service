package identity

import (
	"crypto/rand"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == uuid.Nil {
		u.ID, err = uuid.NewV7()
		if err != nil {
			return err
		}
	}
	if u.ID.Version() != 7 {
		return errors.New("user ID must be UUID v7")
	}
	if len(u.WebAuthnHandle) == 0 {
		u.WebAuthnHandle = make([]byte, 32)
		_, err = rand.Read(u.WebAuthnHandle)
	}
	return err
}

type User struct {
	ID             uuid.UUID           `gorm:"type:uuid;primaryKey" json:"ID"`
	LibraryId      int                 `gorm:"not null;uniqueIndex;check:library_id_range,library_id BETWEEN 1 AND 9999999" json:"LibraryId"`
	UserName       string              `gorm:"not null;uniqueIndex" json:"UserName"`
	Name           string              `gorm:"not null" json:"Name"`
	Email          string              `gorm:"not null;uniqueIndex" json:"Email"`
	RPID           string              `gorm:"not null;uniqueIndex:idx_user_handle" json:"-"`
	WebAuthnHandle []byte              `gorm:"column:webauthn_handle;not null;uniqueIndex:idx_user_handle" json:"-"`
	Credentials    []PasskeyCredential `gorm:"foreignKey:UserId;constraint:OnDelete:CASCADE" json:"-"`
	CreatedAt      time.Time           `json:"CreatedAt"`
	UpdatedAt      time.Time           `json:"UpdatedAt"`
}

type PasskeyCredential struct {
	ID           uint                `gorm:"primaryKey"`
	UserId       uuid.UUID           `gorm:"type:uuid;not null;index"`
	RPID         string              `gorm:"not null;uniqueIndex:idx_rp_credential"`
	CredentialId string              `gorm:"not null;uniqueIndex:idx_rp_credential"`
	Credential   webauthn.Credential `gorm:"serializer:json;not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type UserAttributes struct {
	UserID    uuid.UUID      `gorm:"type:uuid;primaryKey" json:"UserID"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	Value     map[string]any `gorm:"type:jsonb;serializer:json" json:"attributes"`
}

func (u *User) WebAuthnID() []byte          { return u.WebAuthnHandle }
func (u *User) WebAuthnName() string        { return u.UserName }
func (u *User) WebAuthnDisplayName() string { return u.Name }

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, len(u.Credentials))
	for i := range u.Credentials {
		credentials[i] = u.Credentials[i].Credential
	}
	return credentials
}
