package consent

import (
	"context"

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
