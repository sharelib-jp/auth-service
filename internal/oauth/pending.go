package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"gorm.io/gorm"
)

var ErrPendingAuthorization = errors.New("authorization request is missing, expired or already used")

func RandomBrowserToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func validRandomToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func ValidBrowserToken(value string) bool { return validRandomToken(value) }

// CreatePending accepts only a request that the caller has already validated
// using Fosite and the catalog. It never trusts a URL submitted during consent.
func (s *Store) CreatePending(ctx context.Context, form url.Values, browser string) (string, error) {
	if !validRandomToken(browser) || len(form.Encode()) > 8192 {
		return "", ErrPendingAuthorization
	}
	handle, err := RandomBrowserToken()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	err = s.query(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&PendingAuthorization{HandleHash: digest(handle), BrowserHash: digest(browser), Query: form.Encode(), ExpiresAt: now.Add(10 * time.Minute)}).Error; err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{Type: "authorization_requested", ClientID: form.Get("client_id"), Resource: form.Get("resource"), Result: "received"})
	})
	return handle, err
}

func (s *Store) GetPending(ctx context.Context, handle, browser string) (url.Values, error) {
	if !validRandomToken(handle) || !validRandomToken(browser) {
		return nil, ErrPendingAuthorization
	}
	var pending PendingAuthorization
	err := s.query(ctx).Where("handle_hash = ? AND browser_hash = ? AND expires_at > ? AND consumed_at IS NULL", digest(handle), digest(browser), time.Now().UTC()).First(&pending).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrPendingAuthorization
	}
	if err != nil {
		return nil, err
	}
	form, err := url.ParseQuery(pending.Query)
	if err != nil {
		return nil, err
	}
	return form, nil
}

// IssueConsentCSRF binds the next decision to this user and browser.
func (s *Store) IssueConsentCSRF(ctx context.Context, handle, browser string, userID uuid.UUID, snapshot string) (string, error) {
	if !validRandomToken(handle) || !validRandomToken(browser) || userID == uuid.Nil {
		return "", ErrPendingAuthorization
	}
	value, err := RandomBrowserToken()
	if err != nil {
		return "", err
	}
	result := s.query(ctx).Model(&PendingAuthorization{}).Where("handle_hash = ? AND browser_hash = ? AND expires_at > ? AND consumed_at IS NULL", digest(handle), digest(browser), time.Now().UTC()).Updates(map[string]any{"csrf_hash": digest(value), "user_id": userID.String(), "snapshot_hash": digest(snapshot)})
	if result.Error != nil {
		return "", result.Error
	}
	if result.RowsAffected != 1 {
		return "", ErrPendingAuthorization
	}
	return value, nil
}

// ConsumePending must be called within the transaction that records consent
// and issues the authorization code, so a failure leaves the request usable.
func (s *Store) ConsumePending(ctx context.Context, handle, browser, csrf string, userID uuid.UUID, snapshot string) error {
	if _, ok := ctx.Value(txKey{}).(*txState); !ok {
		return errors.New("consuming authorization requires a transaction")
	}
	if !validRandomToken(handle) || !validRandomToken(browser) || !validRandomToken(csrf) || userID == uuid.Nil {
		return ErrPendingAuthorization
	}
	now := time.Now().UTC()
	query := s.query(ctx).Model(&PendingAuthorization{}).Where("handle_hash = ? AND browser_hash = ? AND csrf_hash = ? AND user_id = ? AND expires_at > ? AND consumed_at IS NULL", digest(handle), digest(browser), digest(csrf), userID.String(), now)
	// Empty snapshot is allowed only when rejecting a request.
	if snapshot != "" {
		query = query.Where("snapshot_hash = ?", digest(snapshot))
	}
	result := query.Update("consumed_at", now)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrPendingAuthorization
	}
	return nil
}
