package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/sharelib-jp/auth-service/internal/audit"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrInvalidRegistration = errors.New("invalid OAuth registration")

// Catalog is a trusted administrative interface, not an anonymous client
// registration API. Callers must authorize the administrator before use.
type Catalog struct{ db *gorm.DB }

func NewCatalog(db *gorm.DB) *Catalog { return &Catalog{db: db} }

func validIdentifier(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func validCatalogID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validScopeName(s string) bool {
	if len(s) > 255 || !validIdentifier(s) {
		return false
	}
	return !strings.ContainsAny(s, `"\`)
}

func validURI(raw string, resource bool) bool {
	if len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || !u.IsAbs() || u.Opaque != "" {
		return false
	}
	if resource && u.RawQuery != "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && u.Hostname() == "localhost")
}

func isIdentityScope(name string) bool {
	switch name {
	case "openid", "profile", "email", "address", "phone", "offline_access":
		return true
	default:
		return false
	}
}

func (c *Catalog) RegisterResource(ctx context.Context, resource Resource) error {
	if !validCatalogID(resource.ID) || strings.TrimSpace(resource.Name) == "" || len(resource.Name) > 200 || !validURI(resource.Identifier, true) {
		return ErrInvalidRegistration
	}
	resource.Status = "active"
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&resource).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "resource_registered", Resource: resource.Identifier, Result: "success"})
	})
}

func (c *Catalog) RegisterScope(ctx context.Context, scope Scope) error {
	if !validCatalogID(scope.ID) || !validScopeName(scope.Name) || isIdentityScope(scope.Name) || !validIdentifier(scope.PurposeCode) || len(scope.PurposeCode) > 128 || strings.TrimSpace(scope.Description) == "" || len(scope.Description) > 1024 || scope.PolicyVersion == 0 {
		return ErrInvalidRegistration
	}
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var resource Resource
		if err := tx.Where("id = ? AND status = ?", scope.ResourceID, "active").First(&resource).Error; err != nil {
			return err
		}
		scope.Status = "active"
		if err := tx.Create(&scope).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "scope_registered", Resource: resource.Identifier, Result: "success"})
	})
}

// RegisterClient hashes a confidential client's secret before persisting it.
// A public client must not have a secret. Redirect URI values are exact.
func (c *Catalog) RegisterClient(ctx context.Context, client Client, secret string) error {
	return c.saveClient(ctx, client, secret, false)
}

// UpdateClient replaces registered metadata and invalidates existing sessions.
func (c *Catalog) UpdateClient(ctx context.Context, client Client, secret string) error {
	return c.saveClient(ctx, client, secret, true)
}

func (c *Catalog) saveClient(ctx context.Context, client Client, secret string, update bool) error {
	if !validCatalogID(client.ID) || strings.TrimSpace(client.Name) == "" || len(client.Name) > 200 || len(client.RedirectURIs) == 0 || len(client.RedirectURIs) > 50 || len(client.GrantTypes) == 0 || len(client.Scopes) == 0 || len(client.Scopes) > 100 || len(client.Audience) > 50 || (client.Public && secret != "") || (!client.Public && len(secret) < 32) {
		return ErrInvalidRegistration
	}
	redirects := make(map[string]bool)
	for _, redirect := range client.RedirectURIs {
		if !validURI(redirect, false) {
			return ErrInvalidRegistration
		}
		if redirects[redirect] {
			return ErrInvalidRegistration
		}
		redirects[redirect] = true
	}
	grants := make(map[string]bool)
	for _, grant := range client.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			return ErrInvalidRegistration
		}
		if grants[grant] {
			return ErrInvalidRegistration
		}
		grants[grant] = true
	}
	if !grants["authorization_code"] {
		return ErrInvalidRegistration
	}
	if !client.Public {
		hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
		if err != nil {
			return err
		}
		client.SecretHash = hash
	} else {
		client.SecretHash = nil
	}
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var existing Client
		if update {
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", client.ID).First(&existing).Error; err != nil {
				return err
			}
		}
		allowedResources := make(map[string]bool)
		seenAudience := make(map[string]bool)
		for _, identifier := range client.Audience {
			if seenAudience[identifier] {
				return ErrInvalidRegistration
			}
			seenAudience[identifier] = true
			var resource Resource
			if err := tx.Where("identifier = ? AND status = ?", identifier, "active").First(&resource).Error; err != nil {
				return err
			}
			allowedResources[resource.ID] = true
		}
		seen := make(map[string]bool)
		for _, name := range client.Scopes {
			if !validScopeName(name) || seen[name] {
				return ErrInvalidRegistration
			}
			seen[name] = true
			if isIdentityScope(name) {
				if name != "openid" && name != "offline_access" && name != "profile" && name != "email" {
					return ErrInvalidRegistration
				}
				continue
			}
			var scope Scope
			if err := tx.Where("name = ? AND status = ?", name, "active").First(&scope).Error; err != nil {
				return err
			}
			if !allowedResources[scope.ResourceID] {
				return ErrInvalidRegistration
			}
		}
		if !update {
			client.Status = "active"
			if err := tx.Create(&client).Error; err != nil {
				return err
			}
			return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "client_registered", ClientID: client.ID, Result: "success"})
		}
		if err := tx.Model(&existing).Select("name", "secret_hash", "public", "redirect_uris", "grant_types", "scopes", "audience").Updates(client).Error; err != nil {
			return err
		}
		if err := tx.Model(&SessionRecord{}).Where("client_id = ? AND active = ?", client.ID, true).Update("active", false).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "client_updated", ClientID: client.ID, Result: "success"})
	})
}

func (c *Catalog) RegisterResourceCredential(ctx context.Context, id, resourceID, secret string) error {
	if !validCatalogID(id) || len(secret) < 32 {
		return ErrInvalidRegistration
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return err
	}
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var resource Resource
		if err := tx.Where("id = ? AND status = ?", resourceID, "active").First(&resource).Error; err != nil {
			return err
		}
		if err := tx.Create(&ResourceCredential{ID: id, ResourceID: resourceID, SecretHash: hash, Status: "active"}).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "resource_credential_registered", Resource: resource.Identifier, Result: "success"})
	})
}

// SetStatus changes availability without deleting records or their audit trail.
func (c *Catalog) SetStatus(ctx context.Context, kind, id, status string) error {
	if !validCatalogID(id) || (status != "active" && status != "disabled") {
		return ErrInvalidRegistration
	}
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lock := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", id)
		var clientID, resourceID string
		switch kind {
		case "client":
			var client Client
			if err := lock.First(&client).Error; err != nil {
				return err
			}
			if client.Status == status {
				return nil
			}
			if err := tx.Model(&client).Update("status", status).Error; err != nil {
				return err
			}
			clientID = client.ID
			if status == "disabled" {
				if err := tx.Model(&SessionRecord{}).Where("client_id = ? AND active = ?", id, true).Update("active", false).Error; err != nil {
					return err
				}
			}
		case "resource":
			var resource Resource
			if err := lock.First(&resource).Error; err != nil {
				return err
			}
			if resource.Status == status {
				return nil
			}
			if err := tx.Model(&resource).Update("status", status).Error; err != nil {
				return err
			}
			resourceID = resource.Identifier
			if status == "disabled" {
				if err := tx.Exec(`UPDATE oauth_sessions SET active = ? WHERE active = ? AND EXISTS
					(SELECT 1 FROM oauth_session_audiences WHERE audience = ? AND session_kind = oauth_sessions.kind AND session_hash = oauth_sessions.key_hash)`, false, true, resource.Identifier).Error; err != nil {
					return err
				}
			}
		case "scope":
			var scope Scope
			if err := lock.First(&scope).Error; err != nil {
				return err
			}
			if scope.Status == status {
				return nil
			}
			changes := map[string]any{"status": status}
			if status == "disabled" {
				changes["policy_version"] = gorm.Expr("policy_version + 1")
			}
			if err := tx.Model(&scope).Updates(changes).Error; err != nil {
				return err
			}
			resourceID = scope.ResourceID
		case "resource-credential":
			var credential ResourceCredential
			if err := lock.First(&credential).Error; err != nil {
				return err
			}
			if credential.Status == status {
				return nil
			}
			if err := tx.Model(&credential).Update("status", status).Error; err != nil {
				return err
			}
			resourceID = credential.ResourceID
		default:
			return ErrInvalidRegistration
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "registration_status_changed", ClientID: clientID, Resource: resourceID, Result: status})
	})
}

// UpdateScopePolicy deliberately changes the version even when only the
// description changes, forcing users to consent to the new terms again.
func (c *Catalog) UpdateScopePolicy(ctx context.Context, id, description, purpose string) error {
	if !validCatalogID(id) || strings.TrimSpace(description) == "" || len(description) > 1024 || !validIdentifier(purpose) || len(purpose) > 128 {
		return ErrInvalidRegistration
	}
	return c.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var scope Scope
		if err := tx.Where("id = ?", id).First(&scope).Error; err != nil {
			return err
		}
		var resource Resource
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("id = ?", scope.ResourceID).First(&resource).Error; err != nil {
			return err
		}
		result := tx.Model(&Scope{}).Where("id = ? AND resource_id = ?", id, resource.ID).Updates(map[string]any{"description": description, "purpose_code": purpose, "policy_version": gorm.Expr("policy_version + 1")})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return gorm.ErrRecordNotFound
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "scope_policy_updated", Resource: resource.Identifier, Result: "success"})
	})
}
