package lib

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/sharelib-jp/auth-service/dao"
	"github.com/sharelib-jp/auth-service/models"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const AuthTTL = 24 * time.Hour

func newToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func tokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (s *Service) saveCeremony(ctx context.Context, kind string, data *webauthn.SessionData, pending *models.PendingRegistration, previousToken string) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	err = dao.SaveCeremony(s.db.WithContext(ctx), &models.CeremonySession{
		TokenHash: tokenHash(token), Kind: kind, SessionData: *data,
		PendingUser: pending, ExpiresAt: time.Now().Add(CeremonyTTL),
	}, tokenHash(previousToken))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) takeCeremony(ctx context.Context, kind, token string) (*models.CeremonySession, error) {
	if token == "" {
		return nil, newError(ErrInvalidInput, "missing or expired ceremony session")
	}
	session, err := dao.TakeCeremony(s.db.WithContext(ctx), tokenHash(token), kind)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, newError(ErrInvalidInput, "missing or expired ceremony session")
	}
	if err != nil {
		return nil, err
	}
	if session.SessionData.RelyingPartyID != s.webAuthn.Config.RPID {
		return nil, newError(ErrInvalidInput, "invalid ceremony relying party")
	}
	return session, nil
}

func (s *Service) createAuthSession(tx *gorm.DB, userID uuid.UUID, previousToken string) (string, error) {
	token, err := newToken()
	if err != nil {
		return "", err
	}
	err = dao.SaveAuthSession(tx, &models.AuthSession{
		TokenHash: tokenHash(token), UserId: userID, ExpiresAt: time.Now().Add(AuthTTL),
	}, tokenHash(previousToken))
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) Authenticate(ctx context.Context, token string) (*models.User, error) {
	user, _, err := s.AuthenticateAt(ctx, token)
	return user, err
}

// AuthenticateAt also reports the original authentication time for OIDC.
// Sessions use a fixed expiry set at creation, so this works for existing rows.
func (s *Service) AuthenticateAt(ctx context.Context, token string) (*models.User, time.Time, error) {
	if token == "" {
		return nil, time.Time{}, ErrUnauthenticated
	}
	session, err := dao.FindAuthSession(s.db.WithContext(ctx), tokenHash(token))
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, time.Time{}, ErrUnauthenticated
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if session.User.RPID != s.webAuthn.Config.RPID {
		return nil, time.Time{}, ErrUnauthenticated
	}
	return &session.User, session.ExpiresAt.Add(-AuthTTL), nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return dao.DeleteAuthSession(s.db.WithContext(ctx), tokenHash(token))
}
