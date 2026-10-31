package identity

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// UserInfo returns the current account for an authenticated OAuth subject.
func (s *Service) UserInfo(ctx context.Context, subject string) (*User, error) {
	id, err := uuid.Parse(subject)
	if err != nil || id == uuid.Nil {
		return nil, ErrUnauthenticated
	}
	user, err := FindUser(s.db.WithContext(ctx), id, s.webAuthn.Config.RPID)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUnauthenticated
	}
	return user, err
}
