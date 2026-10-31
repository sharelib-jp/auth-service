package identity

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// PendingRegistration is private server-side data, never supplied by the client.
type PendingRegistration struct {
	ID             uuid.UUID
	WebAuthnHandle []byte
	UserName       string
	Name           string
	Email          string
	Attributes     map[string]any
}

type CeremonySession struct {
	TokenHash   string               `gorm:"primaryKey"`
	Kind        string               `gorm:"not null"`
	SessionData webauthn.SessionData `gorm:"serializer:json;not null"`
	PendingUser *PendingRegistration `gorm:"serializer:json"`
	ExpiresAt   time.Time            `gorm:"not null;index"`
}

type AuthSession struct {
	TokenHash string    `gorm:"primaryKey"`
	UserId    uuid.UUID `gorm:"type:uuid;not null;index"`
	User      User      `gorm:"foreignKey:UserId;constraint:OnDelete:CASCADE"`
	ExpiresAt time.Time `gorm:"not null;index"`
}
