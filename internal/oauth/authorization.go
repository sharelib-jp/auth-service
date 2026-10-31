package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AuthorizationService validates registered resources and resolves consent.
// Fosite must first validate the OAuth request and is responsible for its
// protocol responses; this service supplies the application's business rules.
type AuthorizationService struct {
	db   *gorm.DB
	lock bool
}

func NewAuthorizationService(db *gorm.DB) *AuthorizationService { return &AuthorizationService{db: db} }

func (s *AuthorizationService) WithLocks() *AuthorizationService {
	return &AuthorizationService{db: s.db, lock: true}
}

type ConsentDecision struct {
	ClientName      string
	OfflineAccess   bool
	ExplicitConsent bool
	Resource        Resource
	Scopes          []Scope
	GrantIDs        []uuid.UUID
	Missing         []Scope
}

func (s *AuthorizationService) Evaluate(ctx context.Context, req fosite.AuthorizeRequester, userID uuid.UUID) (*ConsentDecision, error) {
	if req == nil || req.GetClient() == nil || userID == uuid.Nil {
		return nil, fosite.ErrInvalidRequest
	}
	form := req.GetRequestForm()
	db := s.db.WithContext(ctx)
	var client Client
	query := db.Where("id = ? AND status = ?", req.GetClient().GetID(), "active")
	if s.lock {
		query = query.Clauses(clause.Locking{Strength: "SHARE"})
	}
	if err := query.First(&client).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fosite.ErrInvalidClient
	} else if err != nil {
		return nil, err
	}
	if !fosite.Arguments(client.GrantTypes).Has("authorization_code") {
		return nil, fosite.ErrUnauthorizedClient
	}
	redirect := form.Get("redirect_uri")
	exact := false
	for _, registered := range client.RedirectURIs {
		if redirect == registered {
			exact = true
			break
		}
	}
	if !exact || redirect == "" {
		return nil, fosite.ErrInvalidRequest
	}
	if !req.GetResponseTypes().ExactOne("code") {
		return nil, fosite.ErrUnsupportedResponseType
	}
	if form.Get("code_challenge_method") != "S256" {
		return nil, fosite.ErrInvalidRequest
	}
	challenge, err := base64.RawURLEncoding.DecodeString(form.Get("code_challenge"))
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != form.Get("code_challenge") {
		return nil, fosite.ErrInvalidRequest
	}
	if len(form.Get("state")) < 8 {
		return nil, fosite.ErrInvalidRequest
	}
	if nonce := form.Get("nonce"); nonce != "" && len(nonce) < 8 {
		return nil, fosite.ErrInvalidRequest
	}
	if form.Get("max_age") != "" || form.Get("id_token_hint") != "" || form.Get("prompt") == "login" || form.Get("prompt") == "select_account" {
		return nil, fosite.ErrInvalidRequest
	}
	if prompt := form.Get("prompt"); prompt != "" && prompt != "none" && prompt != "consent" {
		return nil, fosite.ErrInvalidRequest
	}
	decision := &ConsentDecision{ClientName: client.Name, ExplicitConsent: form.Get("prompt") == "consent", OfflineAccess: req.GetRequestedScopes().Has("offline_access")}
	if decision.OfflineAccess && !req.GetRequestedScopes().Has("openid") {
		return nil, fosite.ErrInvalidScope
	}
	var names []string
	for _, name := range req.GetRequestedScopes() {
		if !fosite.Arguments(client.Scopes).Has(name) {
			return nil, fosite.ErrInvalidScope
		}
		if isIdentityScope(name) && name != "openid" && name != "offline_access" {
			return nil, fosite.ErrInvalidScope
		}
		if !isIdentityScope(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	audience := req.GetRequestedAudience()
	if len(audience) > 1 || (len(names) > 0 && len(audience) != 1) {
		return nil, fosite.ErrInvalidRequest
	}
	if len(audience) == 1 {
		if !fosite.Arguments(client.Audience).Has(audience[0]) {
			return nil, fosite.ErrInvalidRequest
		}
		query = db.Where("identifier = ? AND status = ?", audience[0], "active")
		if s.lock {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&decision.Resource).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrInvalidRequest
		} else if err != nil {
			return nil, err
		}
	}
	if len(names) == 0 {
		// Refresh tokens must be tied to a revocable business-data consent.
		if decision.OfflineAccess {
			return nil, fosite.ErrInvalidScope
		}
		return decision, nil
	}
	seenGrants := make(map[uuid.UUID]bool)
	for _, name := range names {
		var scope Scope
		query = db.Where("name = ? AND resource_id = ? AND status = ?", name, decision.Resource.ID, "active")
		if s.lock {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&scope).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrInvalidScope
		} else if err != nil {
			return nil, err
		}
		decision.Scopes = append(decision.Scopes, scope)
		var grants []consent.Grant
		if err := db.Where("user_id = ? AND client_id = ? AND resource = ? AND purpose_code = ? AND policy_version = ? AND status = ?", userID, req.GetClient().GetID(), decision.Resource.Identifier, scope.PurposeCode, scope.PolicyVersion, consent.Active).Order("granted_at DESC, id DESC").Find(&grants).Error; err != nil {
			return nil, err
		}
		found := false
		if form.Get("prompt") != "consent" {
			for _, grant := range grants {
				if grant.ExpiresAt != nil && !grant.ExpiresAt.After(time.Now()) {
					continue
				}
				if grant.ConditionsVersion != 0 || len(grant.Conditions) != 0 {
					continue
				}
				for _, granted := range grant.Scopes {
					if granted == name {
						found = true
						if !seenGrants[grant.ID] {
							decision.GrantIDs = append(decision.GrantIDs, grant.ID)
							seenGrants[grant.ID] = true
						}
						break
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			decision.Missing = append(decision.Missing, scope)
		}
	}
	return decision, nil
}

// Purpose strings are identifiers selected by the server's catalog, not by
// the browser. Descriptions are displayed through an escaping HTML template.
func (d *ConsentDecision) NeedsConsent() bool {
	return len(d.Missing) != 0 || d.OfflineAccess || d.ExplicitConsent
}

func (d *ConsentDecision) Snapshot() (string, error) {
	data, err := json.Marshal(d)
	return string(data), err
}
