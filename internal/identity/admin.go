package identity

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const AdminRole = "admin"

type Role struct {
	ID   string `gorm:"primaryKey;size:64" json:"id"`
	Name string `gorm:"not null" json:"name"`
}

type UserRole struct {
	UserID uuid.UUID `gorm:"type:uuid;primaryKey"`
	RoleID string    `gorm:"primaryKey;size:64"`
	User   User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
	Role   Role      `gorm:"foreignKey:RoleID;constraint:OnDelete:RESTRICT" json:"-"`
}

func LoadUserRoles(db *gorm.DB, user *User) error {
	user.Roles = []string{}
	return db.Session(&gorm.Session{NewDB: true}).Model(&UserRole{}).Where("user_id = ?", user.ID).Order("role_id").Pluck("role_id", &user.Roles).Error
}

func (u *User) IsAdmin() bool { return slices.Contains(u.Roles, AdminRole) }

// The admin role row serializes membership changes, including on PostgreSQL.
// SQLite must use _txlock=immediate, as with other identity writes.
func lockRoles(tx *gorm.DB) error {
	var role Role
	return tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&role, "id = ?", AdminRole).Error
}

// GrantAdmin is reserved for trusted operators with direct database access.
// Public registration never assigns roles.
func GrantAdmin(ctx context.Context, db *gorm.DB, userID uuid.UUID, rpID string) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoles(tx); err != nil {
			return err
		}
		user, err := FindUser(tx, userID, rpID)
		if err != nil {
			return err
		}
		if user.IsAdmin() {
			return nil
		}
		if err := tx.Create(&UserRole{UserID: userID, RoleID: AdminRole}).Error; err != nil {
			return err
		}
		if err := tx.Model(user).Update("updated_at", time.Now().UTC()).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "admin_bootstrapped", Result: "success", VisibleToUser: true})
	})
}

type UserPage struct {
	Items []User `json:"items"`
	Total int64  `json:"total"`
}

func (s *Service) ListUsers(ctx context.Context, query string, limit, offset int) (UserPage, error) {
	page := UserPage{Items: []User{}}
	db := s.db.WithContext(ctx).Model(&User{}).Where("rp_id = ?", s.webAuthn.Config.RPID)
	if query = strings.TrimSpace(query); query != "" {
		pattern := "%" + strings.ToLower(query) + "%"
		db = db.Where("LOWER(user_name) LIKE ? OR LOWER(name) LIKE ? OR LOWER(email) LIKE ?", pattern, pattern, pattern)
	}
	if limit < 1 || limit > 100 || offset < 0 {
		return page, ErrInvalidInput
	}
	if err := db.Count(&page.Total).Error; err != nil {
		return page, err
	}
	if err := db.Order("created_at DESC, id").Limit(limit).Offset(offset).Find(&page.Items).Error; err != nil {
		return page, err
	}
	for i := range page.Items {
		if err := LoadUserRoles(s.db.WithContext(ctx), &page.Items[i]); err != nil {
			return page, err
		}
	}
	return page, nil
}

func (s *Service) AdminUser(ctx context.Context, id uuid.UUID) (*User, error) {
	user, err := FindUser(s.db.WithContext(ctx), id, s.webAuthn.Config.RPID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	return user, err
}

type AdminUserUpdate struct {
	UserName  *string    `json:"UserName"`
	Name      *string    `json:"Name"`
	Email     *string    `json:"Email"`
	Roles     *[]string  `json:"Roles"`
	UpdatedAt *time.Time `json:"UpdatedAt"`
}

func (s *Service) UpdateAdminUser(ctx context.Context, actor, id uuid.UUID, input AdminUserUpdate) (*User, error) {
	if input.UpdatedAt == nil || (input.UserName == nil && input.Name == nil && input.Email == nil && input.Roles == nil) {
		return nil, newError(ErrInvalidInput, "UpdatedAt and at least one editable field are required")
	}
	changes := map[string]any{}
	for _, field := range []struct {
		name, column string
		value        *string
	}{
		{"UserName", "user_name", input.UserName}, {"Name", "name", input.Name}, {"Email", "email", input.Email},
	} {
		if field.value == nil {
			continue
		}
		value, err := validateField(field.name, *field.value)
		if err != nil {
			return nil, err
		}
		changes[field.column] = value
	}
	var user *User
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoles(tx); err != nil {
			return err
		}
		admin, err := FindUser(tx, actor, s.webAuthn.Config.RPID)
		if err != nil {
			return err
		}
		if !admin.IsAdmin() {
			return ErrForbidden
		}
		user, err = FindUser(tx.Clauses(clause.Locking{Strength: "UPDATE"}), id, s.webAuthn.Config.RPID)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !user.UpdatedAt.Equal(*input.UpdatedAt) {
			return newError(ErrConflict, "user was changed; reload before saving")
		}
		if input.Roles != nil {
			seen := map[string]bool{}
			for _, role := range *input.Roles {
				var count int64
				if err := tx.Model(&Role{}).Where("id = ?", role).Count(&count).Error; err != nil {
					return err
				}
				if count != 1 || seen[role] {
					return newError(ErrInvalidInput, "unknown or duplicate role")
				}
				seen[role] = true
			}
			if user.IsAdmin() && !seen[AdminRole] {
				var remaining int64
				if err := tx.Model(&UserRole{}).Joins("JOIN users ON users.id = user_roles.user_id").Where("role_id = ? AND user_id <> ? AND users.rp_id = ?", AdminRole, id, s.webAuthn.Config.RPID).Count(&remaining).Error; err != nil {
					return err
				}
				if remaining == 0 {
					return newError(ErrInvalidInput, "the last administrator cannot be removed")
				}
			}
			if err := tx.Where("user_id = ?", id).Delete(&UserRole{}).Error; err != nil {
				return err
			}
			for _, role := range *input.Roles {
				if err := tx.Create(&UserRole{UserID: id, RoleID: role}).Error; err != nil {
					return err
				}
			}
		}
		changes["updated_at"] = time.Now().UTC()
		if err := tx.Model(&User{}).Where("id = ?", id).Updates(changes).Error; err != nil {
			return err
		}
		if err := audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &id, Type: "user_admin_updated", Resource: actor.String(), Result: "success", VisibleToUser: true}); err != nil {
			return err
		}
		user, err = FindUser(tx, id, s.webAuthn.Config.RPID)
		return err
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		err = newError(ErrConflict, "username or email is already registered")
	}
	return user, err
}

func (s *Service) ListRoles(ctx context.Context) ([]Role, error) {
	roles := []Role{}
	err := s.db.WithContext(ctx).Order("id").Find(&roles).Error
	return roles, err
}

var roleIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func (s *Service) SaveRole(ctx context.Context, role Role, create bool) error {
	role.Name = strings.TrimSpace(role.Name)
	if !roleIDPattern.MatchString(role.ID) || role.Name == "" || utf8.RuneCountInString(role.Name) > 100 {
		return newError(ErrInvalidInput, "invalid role ID or name")
	}
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoles(tx); err != nil {
			return err
		}
		if create {
			return tx.Create(&role).Error
		}
		result := tx.Model(&Role{}).Where("id = ?", role.ID).Update("name", role.Name)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return newError(ErrConflict, "role already exists")
	}
	return err
}

func (s *Service) DeleteRole(ctx context.Context, id string) error {
	if id == AdminRole {
		return newError(ErrInvalidInput, "the admin role cannot be deleted")
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := lockRoles(tx); err != nil {
			return err
		}
		var count int64
		if err := tx.Model(&UserRole{}).Where("role_id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return newError(ErrConflict, "role is assigned to users")
		}
		result := tx.Delete(&Role{}, "id = ?", id)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}
