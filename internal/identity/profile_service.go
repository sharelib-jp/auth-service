package identity

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func validateField(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	limit := 100
	if field == "UserName" {
		limit = 64
	} else if field == "Email" {
		limit = 254
	}
	if value == "" || !utf8.ValidString(value) || utf8.RuneCountInString(value) > limit {
		return "", newError(ErrInvalidInput, fmt.Sprintf("%s must contain 1 to %d characters", field, limit))
	}
	for _, r := range value {
		if unicode.IsControl(r) || (field == "UserName" && unicode.IsSpace(r)) {
			return "", newError(ErrInvalidInput, fmt.Sprintf("%s contains invalid characters", field))
		}
	}
	if field == "Email" {
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value || !strings.Contains(value, "@") {
			return "", newError(ErrInvalidInput, "Email must be a valid email address")
		}
		value = strings.ToLower(value)
	}
	return value, nil
}

// Profile updates take the user ID obtained by the caller through Authenticate.
func (s *Service) UpdateUserName(ctx context.Context, userID uuid.UUID, value string) (*User, error) {
	return s.updateField(ctx, userID, "UserName", "user_name", value)
}

func (s *Service) UpdateName(ctx context.Context, userID uuid.UUID, value string) (*User, error) {
	return s.updateField(ctx, userID, "Name", "name", value)
}

func (s *Service) UpdateEmail(ctx context.Context, userID uuid.UUID, value string) (*User, error) {
	return s.updateField(ctx, userID, "Email", "email", value)
}

func (s *Service) updateField(ctx context.Context, userID uuid.UUID, field, column, value string) (*User, error) {
	value, err := validateField(field, value)
	if err != nil {
		return nil, err
	}
	db := s.db.WithContext(ctx)
	user, err := FindUser(db, userID, s.webAuthn.Config.RPID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	err = UpdateUserField(db, user, column, value)
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return nil, newError(ErrConflict, field+" is already registered")
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}
