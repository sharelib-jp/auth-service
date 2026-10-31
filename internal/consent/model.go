// Package consent manages the history of permissions granted by a user.
// It does not itself issue or revoke OAuth tokens.
package consent

import (
	"time"

	"github.com/google/uuid"
)

const (
	Active  = "active"
	Revoked = "revoked"
)

// Grant is an immutable permission snapshot, except for its revocation state.
// A new consent creates a new grant rather than overwriting history.
type Grant struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	ClientID      string    `gorm:"not null;index" json:"client_id"`
	Resource      string    `gorm:"not null" json:"resource"`
	Scopes        []string  `gorm:"serializer:json;not null" json:"scopes"`
	PurposeCode   string    `gorm:"not null" json:"purpose_code"`
	PolicyVersion uint      `gorm:"not null;default:1" json:"policy_version"`
	// Conditions are reserved for future fine-grained authorization. Current
	// issuers must reject any nonempty or nonzero-version conditions.
	Conditions        map[string]any `gorm:"serializer:json" json:"conditions,omitempty"`
	ConditionsVersion uint           `gorm:"not null;default:0" json:"conditions_version"`
	Status            string         `gorm:"not null;index" json:"status"`
	GrantedAt         time.Time      `gorm:"not null" json:"granted_at"`
	ExpiresAt         *time.Time     `json:"expires_at"`
	RevokedAt         *time.Time     `json:"revoked_at"`
}

func (Grant) TableName() string { return "consent_grants" }

// Event is kept separately so that granting and revocation remain auditable.
type Event struct {
	ID         uuid.UUID `gorm:"type:uuid;primaryKey"`
	GrantID    uuid.UUID `gorm:"type:uuid;not null;index"`
	UserID     uuid.UUID `gorm:"type:uuid;not null;index"`
	Action     string    `gorm:"not null"`
	OccurredAt time.Time `gorm:"not null"`
}

func (Event) TableName() string { return "consent_events" }

// SessionLink associates each Fosite session with every consent it depends on.
type SessionLink struct {
	GrantID     uuid.UUID `gorm:"type:uuid;primaryKey"`
	SessionKind string    `gorm:"primaryKey"`
	SessionHash string    `gorm:"primaryKey"`
}

func (SessionLink) TableName() string { return "consent_session_links" }
