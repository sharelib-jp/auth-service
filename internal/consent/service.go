package consent

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidGrant = errors.New("invalid consent grant")

type Repository interface {
	Create(context.Context, *Grant, *Event) error
	List(context.Context, uuid.UUID) ([]Grant, error)
	Get(context.Context, uuid.UUID, uuid.UUID) (*Grant, error)
	Revoke(context.Context, uuid.UUID, uuid.UUID, time.Time) error
}

type Service struct{ repo Repository }

func NewService(repo Repository) *Service { return &Service{repo: repo} }

// Create is intended for a future validated authorization flow, not direct
// use with untrusted request parameters. Authentication scopes are excluded.
func (s *Service) Create(ctx context.Context, grant Grant) (*Grant, error) {
	if grant.UserID == uuid.Nil || strings.TrimSpace(grant.ClientID) == "" || strings.TrimSpace(grant.Resource) == "" || strings.TrimSpace(grant.PurposeCode) == "" || len(grant.Scopes) == 0 || grant.ConditionsVersion != 0 || len(grant.Conditions) != 0 {
		return nil, ErrInvalidGrant
	}
	now := time.Now().UTC()
	if grant.ExpiresAt != nil && !grant.ExpiresAt.After(now) {
		return nil, ErrInvalidGrant
	}
	if grant.ExpiresAt != nil {
		expires := grant.ExpiresAt.UTC()
		grant.ExpiresAt = &expires
	}
	scopes := make(map[string]struct{}, len(grant.Scopes))
	for _, scope := range grant.Scopes {
		if scope == "" || strings.TrimSpace(scope) != scope || strings.ContainsAny(scope, " \t\r\n") || scope == "openid" || scope == "profile" || scope == "email" || scope == "address" || scope == "phone" || scope == "offline_access" {
			return nil, ErrInvalidGrant
		}
		scopes[scope] = struct{}{}
	}
	grant.Scopes = make([]string, 0, len(scopes))
	for scope := range scopes {
		grant.Scopes = append(grant.Scopes, scope)
	}
	sort.Strings(grant.Scopes)
	grant.ID = uuid.New()
	if grant.PolicyVersion == 0 {
		grant.PolicyVersion = 1
	}
	grant.Status, grant.GrantedAt, grant.RevokedAt = Active, now, nil
	event := &Event{ID: uuid.New(), GrantID: grant.ID, UserID: grant.UserID, Action: "granted", OccurredAt: now}
	if err := s.repo.Create(ctx, &grant, event); err != nil {
		return nil, err
	}
	return &grant, nil
}

func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Grant, error) {
	return s.repo.List(ctx, userID)
}

func (s *Service) Get(ctx context.Context, userID, id uuid.UUID) (*Grant, error) {
	return s.repo.Get(ctx, userID, id)
}

func (s *Service) Revoke(ctx context.Context, userID, id uuid.UUID) error {
	return s.repo.Revoke(ctx, userID, id, time.Now().UTC())
}
