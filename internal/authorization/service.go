// Package authorization makes central RBAC decisions. Resource servers remain
// responsible for object-level access checks on their own business data.
package authorization

import (
	"context"
	"errors"
	"strings"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrInvalidPolicy = errors.New("invalid authorization policy")

type RoleBinding struct {
	ResourceID string    `gorm:"primaryKey"`
	UserID     uuid.UUID `gorm:"type:uuid;primaryKey"`
	Role       string    `gorm:"primaryKey"`
	Status     string    `gorm:"not null"`
}

func (RoleBinding) TableName() string { return "authorization_role_bindings" }

type Policy struct {
	ResourceID string `gorm:"primaryKey"`
	Role       string `gorm:"primaryKey"`
	Object     string `gorm:"primaryKey"`
	Action     string `gorm:"primaryKey"`
	Status     string `gorm:"not null"`
}

func (Policy) TableName() string { return "authorization_policies" }

type Service struct{ db *gorm.DB }

func NewService(db *gorm.DB) *Service { return &Service{db: db} }

func validName(s string) bool {
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

func (s *Service) SetBinding(ctx context.Context, binding RoleBinding) error {
	if !validName(binding.ResourceID) || binding.UserID == uuid.Nil || !validName(binding.Role) || (binding.Status != "active" && binding.Status != "disabled") {
		return ErrInvalidPolicy
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var resource oauth.Resource
		if err := tx.Where("id = ?", binding.ResourceID).First(&resource).Error; err != nil {
			return err
		}
		var user identity.User
		if err := tx.Where("id = ?", binding.UserID).First(&user).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "resource_id"}, {Name: "user_id"}, {Name: "role"}}, DoUpdates: clause.AssignmentColumns([]string{"status"})}).Create(&binding).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &binding.UserID, Type: "business_role_changed", Resource: resource.Identifier, Result: binding.Status, VisibleToUser: true})
	})
}

func (s *Service) SetPolicy(ctx context.Context, policy Policy) error {
	if !validName(policy.ResourceID) || !validName(policy.Role) || !validName(policy.Object) || !validName(policy.Action) || (policy.Status != "active" && policy.Status != "disabled") {
		return ErrInvalidPolicy
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var resource oauth.Resource
		if err := tx.Where("id = ?", policy.ResourceID).First(&resource).Error; err != nil {
			return err
		}
		if err := tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "resource_id"}, {Name: "role"}, {Name: "object"}, {Name: "action"}}, DoUpdates: clause.AssignmentColumns([]string{"status"})}).Create(&policy).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "business_policy_changed", Resource: resource.Identifier, Result: policy.Status})
	})
}

const rbacModel = `[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act`

// Check loads a single DB snapshot and evaluates it with a request-local Casbin
// enforcer. Absence of matching bindings or policies always denies access.
func (s *Service) Check(ctx context.Context, source oauth.Resource, subject uuid.UUID, resource, action string) (bool, error) {
	prefix := source.ID + "."
	if source.Status != "active" || subject == uuid.Nil || !validName(source.ID) || !strings.HasPrefix(resource, prefix) || !validName(strings.TrimPrefix(resource, prefix)) || !validName(action) {
		return false, ErrInvalidPolicy
	}
	var policies []Policy
	err := s.db.WithContext(ctx).Table("authorization_policies AS p").Select("p.*").Joins("JOIN authorization_role_bindings AS b ON b.resource_id = p.resource_id AND b.role = p.role").Where("p.resource_id = ? AND b.user_id = ? AND p.status = ? AND b.status = ?", source.ID, subject, "active", "active").Scan(&policies).Error
	if err != nil {
		return false, err
	}
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return false, err
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return false, err
	}
	for _, policy := range policies {
		if _, err := enforcer.AddPolicy(policy.Role, source.ID+"."+policy.Object, policy.Action); err != nil {
			return false, err
		}
		if _, err := enforcer.AddGroupingPolicy(subject.String(), policy.Role); err != nil {
			return false, err
		}
	}
	return enforcer.Enforce(subject.String(), resource, action)
}
