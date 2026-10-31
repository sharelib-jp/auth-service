package identity

import (
	"context"
	"errors"
	"io"
	"log"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"gorm.io/gorm"
)

const CeremonyTTL = 5 * time.Minute

func InitWebAuthn(conf *config.Config) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: conf.WEBAUTHN_RP_DISPLAY_NAME,
		RPID:          conf.HOSTNAME,
		RPOrigins:     []string{conf.Origin()},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL},
			Login:        webauthn.TimeoutConfig{Enforce: true, Timeout: CeremonyTTL},
		},
	})
}

type RegistrationInput struct {
	UserName   string
	Name       string
	Email      string
	Attributes map[string]any `json:"attributes"`
}

// BeginRegistration returns creation options and a new ceremony token, replacing the previous token.
func (s *Service) BeginRegistration(ctx context.Context, input RegistrationInput, previousToken string) (*protocol.CredentialCreation, string, error) {
	var err error
	if input.UserName, err = validateField("UserName", input.UserName); err == nil {
		input.Name, err = validateField("Name", input.Name)
	}
	if err == nil {
		input.Email, err = validateField("Email", input.Email)
	}
	if err != nil {
		return nil, "", err
	}
	exists, err := UserExists(s.db.WithContext(ctx), input.UserName, input.Email)
	if err != nil {
		return nil, "", err
	}
	if exists {
		return nil, "", newError(ErrConflict, "UserName or Email is already registered")
	}
	user := &User{UserName: input.UserName, Name: input.Name, Email: input.Email, RPID: s.webAuthn.Config.RPID}
	// The UUID and handle must already exist when generating WebAuthn options.
	if err := user.BeforeCreate(nil); err != nil {
		return nil, "", err
	}

	options, data, err := s.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, "", err
	}
	pending := &PendingRegistration{
		ID: user.ID, WebAuthnHandle: user.WebAuthnHandle,
		UserName: user.UserName, Name: user.Name, Email: user.Email,
		Attributes: input.Attributes,
	}
	token, err := s.saveCeremony(ctx, "registration", data, pending, previousToken)
	if err != nil {
		return nil, "", err
	}
	return options, token, nil
}

// FinishRegistration consumes the ceremony even if parsing or verification fails.
// The account, attributes, credential, LibraryId, and authentication session commit together.
func (s *Service) FinishRegistration(ctx context.Context, ceremonyToken, previousAuthToken string, response io.Reader) (*User, string, error) {
	session, err := s.takeCeremony(ctx, "registration", ceremonyToken)
	if err != nil {
		return nil, "", err
	}
	pending := session.PendingUser
	if pending == nil {
		return nil, "", newError(ErrInvalidInput, "invalid registration session")
	}
	user := &User{
		ID: pending.ID, WebAuthnHandle: pending.WebAuthnHandle, RPID: s.webAuthn.Config.RPID,
		UserName: pending.UserName, Name: pending.Name, Email: pending.Email,
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(response)
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "passkey registration verification failed")
	}
	credential, err := s.webAuthn.CreateCredential(user, session.SessionData, parsed)
	if err != nil {
		return nil, "", newError(ErrInvalidInput, "passkey registration verification failed")
	}
	var token string
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := CreateUser(tx, user, credential); err != nil {
			return err
		}
		if pending.Attributes != nil {
			if err := CreateUserAttributes(tx, user, pending.Attributes); err != nil {
				return err
			}
		}
		token, err = s.createAuthSession(tx, user.ID, previousAuthToken)
		if err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &user.ID, Type: "registration_login", Result: "success", VisibleToUser: true})
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return nil, "", newError(ErrConflict, "UserName, Email or passkey is already registered")
	}
	if errors.Is(err, ErrLibraryIdExhausted) {
		return nil, "", newError(ErrConflict, "LibraryId range is exhausted")
	}
	if err != nil {
		return nil, "", err
	}
	return user, token, nil
}

func (s *Service) BeginLogin(ctx context.Context, previousToken string) (*protocol.CredentialAssertion, string, error) {
	options, data, err := s.webAuthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	token, err := s.saveCeremony(ctx, "login", data, nil, previousToken)
	if err != nil {
		return nil, "", err
	}
	return options, token, nil
}

// FinishLogin consumes the ceremony even if parsing or verification fails.
func (s *Service) FinishLogin(ctx context.Context, ceremonyToken, previousAuthToken string, response io.Reader) (user *User, token string, resultErr error) {
	defer func() {
		if resultErr != nil {
			if err := audit.RecordSecurity(s.db.WithContext(ctx), audit.SecurityEvent{Type: "login", Result: "failure"}); err != nil {
				log.Print("failed to record unsuccessful login")
			}
		}
	}()
	session, err := s.takeCeremony(ctx, "login", ceremonyToken)
	if err != nil {
		return nil, "", err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(response)
	if err != nil {
		return nil, "", ErrInvalidPasskey
	}
	// Serialize credential verification and counter updates to avoid lost updates.
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var lookupErr error
		lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
			user, lookupErr = FindPasskeyUser(tx, s.webAuthn.Config.RPID, rawID, userHandle)
			if lookupErr != nil {
				return nil, lookupErr
			}
			return user, nil
		}
		_, credential, err := s.webAuthn.ValidatePasskeyLogin(lookup, session.SessionData, parsed)
		if lookupErr != nil && !errors.Is(lookupErr, gorm.ErrRecordNotFound) {
			return lookupErr
		}
		if err != nil || credential == nil || credential.Authenticator.CloneWarning {
			return ErrInvalidPasskey
		}
		if err := UpdateCredential(tx, user, credential); err != nil {
			return err
		}
		token, err = s.createAuthSession(tx, user.ID, previousAuthToken)
		if err != nil {
			return err
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &user.ID, Type: "login", Result: "success", VisibleToUser: true})
	})
	if err != nil {
		return nil, "", err
	}
	return user, token, nil
}
