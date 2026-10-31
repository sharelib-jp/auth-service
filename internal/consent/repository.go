package consent

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"gorm.io/gorm"
)

type GormRepository struct{ db *gorm.DB }

func NewRepository(db *gorm.DB) *GormRepository { return &GormRepository{db: db} }

func (r *GormRepository) Create(ctx context.Context, grant *Grant, event *Event) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(grant).Error; err != nil {
			return err
		}
		if err := tx.Create(event).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &grant.UserID, Type: "consent_granted", ClientID: grant.ClientID, Resource: grant.Resource, Result: "success", VisibleToUser: true})
	})
}

func (r *GormRepository) List(ctx context.Context, userID uuid.UUID) ([]Grant, error) {
	grants := []Grant{}
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("granted_at DESC, id DESC").Find(&grants).Error
	return grants, err
}

func (r *GormRepository) Get(ctx context.Context, userID, id uuid.UUID) (*Grant, error) {
	var grant Grant
	err := r.db.WithContext(ctx).Where("user_id = ? AND id = ?", userID, id).First(&grant).Error
	return &grant, err
}

func (r *GormRepository) Revoke(ctx context.Context, userID, id uuid.UUID, now time.Time) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&Grant{}).Where("id = ? AND user_id = ? AND status = ?", id, userID, Active).
			Updates(map[string]any{"status": Revoked, "revoked_at": now})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			// Repeated deletion is idempotent, but another user's ID is hidden.
			var grant Grant
			if err := tx.Where("id = ? AND user_id = ?", id, userID).First(&grant).Error; err != nil {
				return err
			}
			if grant.Status != Revoked {
				return ErrInvalidGrant
			}
			return nil
		}
		// Invalidate only sessions linked to this particular grant. A token
		// depending on multiple grants is revoked as a whole, not narrowed.
		var activeTokens int64
		if err := tx.Table("oauth_sessions AS s").Joins("JOIN consent_session_links AS l ON l.session_kind = s.kind AND l.session_hash = s.key_hash").Where("l.grant_id = ? AND s.active = ? AND s.kind IN ?", id, true, []string{"access", "refresh"}).Count(&activeTokens).Error; err != nil {
			return err
		}
		if err := tx.Exec(`UPDATE oauth_sessions SET active = ? WHERE active = ? AND EXISTS
			(SELECT 1 FROM consent_session_links WHERE grant_id = ?
			 AND session_kind = oauth_sessions.kind AND session_hash = oauth_sessions.key_hash)`, false, true, id).Error; err != nil {
			return err
		}
		if err := tx.Create(&Event{ID: uuid.New(), GrantID: id, UserID: userID, Action: "revoked", OccurredAt: now}).Error; err != nil {
			return err
		}
		var grant Grant
		if err := tx.Where("id = ? AND user_id = ?", id, userID).First(&grant).Error; err != nil {
			return err
		}
		if err := audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "consent_revoked", ClientID: grant.ClientID, Resource: grant.Resource, Result: "success", VisibleToUser: true}); err != nil {
			return err
		}
		if activeTokens > 0 {
			return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "token_family_revoked", ClientID: grant.ClientID, Resource: grant.Resource, Result: "success", VisibleToUser: true})
		}
		return nil
	})
}
