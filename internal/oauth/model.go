package oauth

import "time"

// Client and Resource are provisioned by trusted server-side administration.
// Secrets contain bcrypt hashes, never plaintext client credentials.
type Client struct {
	ID           string `gorm:"primaryKey"`
	Name         string `gorm:"not null"`
	SecretHash   []byte
	Public       bool
	RedirectURIs []string `gorm:"serializer:json;not null"`
	GrantTypes   []string `gorm:"serializer:json;not null"`
	Scopes       []string `gorm:"serializer:json;not null"`
	Audience     []string `gorm:"serializer:json;not null"`
	Status       string   `gorm:"not null;index"`
}

func (Client) TableName() string { return "oauth_clients" }

type Resource struct {
	ID         string `gorm:"primaryKey"`
	Identifier string `gorm:"not null;uniqueIndex"`
	Name       string `gorm:"not null"`
	Status     string `gorm:"not null"`
}

func (Resource) TableName() string { return "oauth_resources" }

type Scope struct {
	ID            string `gorm:"primaryKey"`
	ResourceID    string `gorm:"not null;index"`
	Name          string `gorm:"not null;uniqueIndex"`
	Description   string `gorm:"not null"`
	PurposeCode   string `gorm:"not null;default:''"`
	PolicyVersion uint   `gorm:"not null;default:1"`
	Status        string `gorm:"not null"`
}

func (Scope) TableName() string { return "oauth_scopes" }

// ResourceCredential authenticates a Resource Server independently of OAuth
// clients, and limits introspection to the configured resource.
type ResourceCredential struct {
	ID         string `gorm:"primaryKey"`
	ResourceID string `gorm:"not null;index"`
	SecretHash []byte `gorm:"not null"`
	Status     string `gorm:"not null"`
}

func (ResourceCredential) TableName() string { return "oauth_resource_credentials" }

// SessionRecord stores only hashes of Fosite token signatures or codes.
// Payload contains the sanitized request and must never contain token secrets.
type SessionRecord struct {
	Kind      string `gorm:"primaryKey"`
	KeyHash   string `gorm:"primaryKey"`
	RequestID string `gorm:"not null;index"`
	ClientID  string `gorm:"not null;index"`
	Payload   []byte `gorm:"not null"`
	Active    bool   `gorm:"not null"`
	CreatedAt time.Time
}

func (SessionRecord) TableName() string { return "oauth_sessions" }

// SessionAudience allows disabling a resource to revoke its issued sessions,
// including identity-only sessions which have no business consent link.
type SessionAudience struct {
	SessionKind string `gorm:"primaryKey"`
	SessionHash string `gorm:"primaryKey"`
	Audience    string `gorm:"primaryKey;index"`
}

func (SessionAudience) TableName() string { return "oauth_session_audiences" }

type AssertionJTI struct {
	Hash      string    `gorm:"primaryKey"`
	ExpiresAt time.Time `gorm:"not null;index"`
}

func (AssertionJTI) TableName() string { return "oauth_assertion_jtis" }

// PendingAuthorization holds a validated request server-side while the user
// logs in or decides whether to grant consent. Browser and CSRF values are hashed.
type PendingAuthorization struct {
	HandleHash   string `gorm:"primaryKey"`
	BrowserHash  string `gorm:"not null"`
	Query        string `gorm:"not null"`
	CSRFHash     string
	SnapshotHash string
	UserID       string
	CreatedAt    time.Time
	ExpiresAt    time.Time `gorm:"not null;index"`
	ConsumedAt   *time.Time
}

func (PendingAuthorization) TableName() string { return "oauth_pending_authorizations" }
