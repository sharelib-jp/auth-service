package audit

import (
	"time"

	"github.com/google/uuid"
)

// Event records an actual resource-server operation, not token issuance.
// The source is assigned by authentication, never by the sender's payload.
type Event struct {
	SourceResourceID string    `gorm:"primaryKey" json:"-"`
	EventID          string    `gorm:"primaryKey" json:"event_id"`
	Subject          uuid.UUID `gorm:"type:uuid;not null;index:idx_audit_subject_time" json:"subject"`
	ClientID         string    `gorm:"not null" json:"client_id"`
	Resource         string    `gorm:"not null" json:"resource"`
	Action           string    `gorm:"not null" json:"action"`
	DataCategory     string    `gorm:"not null" json:"data_category"`
	Result           string    `gorm:"not null" json:"result"`
	OccurredAt       time.Time `gorm:"not null;index:idx_audit_subject_time" json:"occurred_at"`
	ReceivedAt       time.Time `gorm:"not null" json:"received_at"`
}

func (Event) TableName() string { return "audit_access_events" }

// SecurityEvent excludes tokens, authorization codes, secrets and profile data.
// Events not marked VisibleToUser are restricted to administrators via DB access.
type SecurityEvent struct {
	ID            uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        *uuid.UUID `gorm:"type:uuid;index:idx_security_user_time" json:"-"`
	Type          string     `gorm:"not null" json:"type"`
	ClientID      string     `json:"client_id,omitempty"`
	Resource      string     `json:"resource,omitempty"`
	Result        string     `gorm:"not null" json:"result"`
	VisibleToUser bool       `gorm:"not null" json:"-"`
	OccurredAt    time.Time  `gorm:"not null;index:idx_security_user_time" json:"occurred_at"`
}

func (SecurityEvent) TableName() string { return "audit_security_events" }
