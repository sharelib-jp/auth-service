package lib

import (
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sharelib-jp/auth-service/config"
	"gorm.io/gorm"
)

// Service contains the authentication and profile operations shared by API and web handlers.
type Service struct {
	db       *gorm.DB
	webAuthn *webauthn.WebAuthn
}

func NewService(conf *config.Config, db *gorm.DB) (*Service, error) {
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	wa, err := InitWebAuthn(conf)
	if err != nil {
		return nil, err
	}
	return &Service{db: db, webAuthn: wa}, nil
}

var (
	ErrInvalidInput    = errors.New("invalid input")
	ErrConflict        = errors.New("conflict")
	ErrUnauthenticated = errors.New("authentication required")
	ErrInvalidPasskey  = errors.New("passkey login verification failed")
)

type serviceError struct {
	kind    error
	message string
}

func (e *serviceError) Error() string { return e.message }
func (e *serviceError) Unwrap() error { return e.kind }

func newError(kind error, message string) error {
	return &serviceError{kind: kind, message: message}
}
