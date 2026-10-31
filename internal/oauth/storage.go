package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	core "github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/pkce"
	"github.com/ory/fosite/storage"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	kindCode    = "code"
	kindAccess  = "access"
	kindRefresh = "refresh"
	kindPKCE    = "pkce"
	kindOIDC    = "oidc"
)

type Store struct{ db *gorm.DB }

var (
	_ fosite.Storage                     = (*Store)(nil)
	_ core.CoreStorage                   = (*Store)(nil)
	_ core.TokenRevocationStorage        = (*Store)(nil)
	_ openid.OpenIDConnectRequestStorage = (*Store)(nil)
	_ pkce.PKCERequestStorage            = (*Store)(nil)
	_ storage.Transactional              = (*Store)(nil)
)

func NewStore(db *gorm.DB) *Store { return &Store{db: db} }

type txKey struct{}

type txState struct {
	db             *gorm.DB
	refreshRequest fosite.Requester
}

func (s *Store) query(ctx context.Context) *gorm.DB {
	if tx, ok := ctx.Value(txKey{}).(*txState); ok {
		return tx.db.WithContext(ctx)
	}
	return s.db.WithContext(ctx)
}

func (s *Store) BeginTX(ctx context.Context) (context.Context, error) {
	if _, ok := ctx.Value(txKey{}).(*txState); ok {
		return nil, errors.New("oauth transaction already exists")
	}
	tx := s.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	return context.WithValue(ctx, txKey{}, &txState{db: tx}), nil
}

func (s *Store) Commit(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return errors.New("oauth transaction missing")
	}
	return tx.db.Commit().Error
}

func (s *Store) Rollback(ctx context.Context) error {
	tx, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return errors.New("oauth transaction missing")
	}
	return tx.db.Rollback().Error
}

// Transaction exposes one database transaction to Fosite and domain
// repositories, keeping consent, request consumption and code creation atomic.
func (s *Store) Transaction(ctx context.Context, fn func(context.Context, *gorm.DB) error) error {
	txCtx, err := s.BeginTX(ctx)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			_ = s.Rollback(txCtx)
		}
	}()
	if err := fn(txCtx, s.query(txCtx)); err != nil {
		return err
	}
	if err := s.Commit(txCtx); err != nil {
		return err
	}
	finished = true
	return nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func (s *Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var c Client
	err := s.query(ctx).Where("id = ? AND status = ?", id, "active").First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &fosite.DefaultClient{ID: c.ID, Secret: c.SecretHash, Public: c.Public, RedirectURIs: c.RedirectURIs, GrantTypes: c.GrantTypes, ResponseTypes: []string{"code"}, Scopes: c.Scopes, Audience: c.Audience}, nil
}

func (s *Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var count int64
	if err := s.query(ctx).Model(&AssertionJTI{}).Where("hash = ? AND expires_at > ?", digest(jti), time.Now().UTC()).Count(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

func (s *Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.query(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("expires_at <= ?", time.Now().UTC()).Delete(&AssertionJTI{}).Error; err != nil {
			return err
		}
		err := tx.Create(&AssertionJTI{Hash: digest(jti), ExpiresAt: exp}).Error
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return fosite.ErrJTIKnown
		}
		return err
	})
}

// requestSnapshot excludes client secrets and serializes only Fosite's
// sanitized request, never the bearer token or authorization code itself.
type requestSnapshot struct {
	ID                string           `json:"id"`
	RequestedAt       time.Time        `json:"requested_at"`
	RequestedScope    fosite.Arguments `json:"requested_scope"`
	GrantedScope      fosite.Arguments `json:"granted_scope"`
	RequestedAudience fosite.Arguments `json:"requested_audience"`
	GrantedAudience   fosite.Arguments `json:"granted_audience"`
	Form              url.Values       `json:"form"`
	Session           *Session         `json:"session"`
}

func (s *Store) checkConsent(db *gorm.DB, req fosite.Requester, lock bool) error {
	session, ok := req.GetSession().(*Session)
	if !ok || session == nil || session.DefaultSession == nil {
		return errors.New("invalid oauth session")
	}
	if req.GetClient() == nil {
		return fosite.ErrInvalidGrant
	}
	var client Client
	clientQuery := db.Where("id = ? AND status = ?", req.GetClient().GetID(), "active")
	if lock {
		clientQuery = clientQuery.Clauses(clause.Locking{Strength: "SHARE"})
	}
	if err := clientQuery.First(&client).Error; errors.Is(err, gorm.ErrRecordNotFound) {
		return fosite.ErrInvalidGrant
	} else if err != nil {
		return err
	}
	if !fosite.Arguments(client.GrantTypes).Has("authorization_code") {
		return fosite.ErrInvalidGrant
	}
	for _, scope := range req.GetGrantedScopes() {
		if !fosite.Arguments(client.Scopes).Has(scope) {
			return fosite.ErrInvalidGrant
		}
	}
	for _, audience := range req.GetGrantedAudience() {
		if !fosite.Arguments(client.Audience).Has(audience) {
			return fosite.ErrInvalidGrant
		}
	}
	ids := append([]uuid.UUID(nil), session.GrantIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
	type requiredScope struct {
		scope    Scope
		resource Resource
	}
	needed := make(map[string]requiredScope)
	scopeNames := append([]string(nil), req.GetGrantedScopes()...)
	sort.Strings(scopeNames)
	var resource Resource
	hasBusiness := false
	for _, name := range scopeNames {
		if !isIdentityScope(name) {
			hasBusiness = true
			break
		}
	}
	if len(req.GetGrantedAudience()) > 1 || (hasBusiness && len(req.GetGrantedAudience()) != 1) {
		return fosite.ErrInvalidGrant
	}
	if len(req.GetGrantedAudience()) == 1 {
		query := db.Where("identifier = ? AND status = ?", req.GetGrantedAudience()[0], "active")
		if lock {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&resource).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrInvalidGrant
		} else if err != nil {
			return err
		}
	}
	for _, name := range scopeNames {
		if scope, ok := identityScope(name); ok {
			if !req.GetGrantedScopes().Has("openid") {
				return fosite.ErrInvalidGrant
			}
			needed[name] = requiredScope{scope: scope, resource: Resource{Identifier: IdentityResource}}
			continue
		}
		if isIdentityScope(name) {
			continue
		}
		var scope Scope
		query := db.Where("name = ? AND status = ?", name, "active")
		if lock {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&scope).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrInvalidGrant
		} else if err != nil {
			return err
		}
		if scope.ResourceID != resource.ID {
			return fosite.ErrInvalidGrant
		}
		needed[name] = requiredScope{scope: scope, resource: resource}
	}
	covered := make(map[string]bool, len(needed))
	for i, id := range ids {
		if id == uuid.Nil || (i > 0 && ids[i-1] == id) {
			return fosite.ErrInvalidGrant
		}
		var grant consent.Grant
		query := db.Where("id = ? AND user_id = ? AND client_id = ? AND status = ?", id, session.GetSubject(), req.GetClient().GetID(), consent.Active)
		if lock {
			query = query.Clauses(clause.Locking{Strength: "UPDATE"})
		}
		if err := query.First(&grant).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrInvalidGrant
		} else if err != nil {
			return err
		}
		if grant.ExpiresAt != nil && !grant.ExpiresAt.After(time.Now()) {
			return fosite.ErrInvalidGrant
		}
		if grant.ConditionsVersion != 0 || len(grant.Conditions) != 0 {
			return fosite.ErrInvalidGrant
		}
		matched := false
		for _, name := range grant.Scopes {
			want, ok := needed[name]
			if ok && grant.Resource == want.resource.Identifier && grant.PurposeCode == want.scope.PurposeCode && grant.PolicyVersion == want.scope.PolicyVersion {
				covered[name] = true
				matched = true
			}
		}
		if !matched {
			return fosite.ErrInvalidGrant
		}
	}
	for name := range needed {
		if !covered[name] {
			return fosite.ErrInvalidGrant
		}
	}
	return nil
}

func (s *Store) create(ctx context.Context, kind, key string, req fosite.Requester) error {
	if key == "" || req.GetClient() == nil {
		return errors.New("invalid oauth storage key or client")
	}
	session, ok := req.GetSession().(*Session)
	if !ok || session == nil {
		return errors.New("invalid oauth session")
	}
	payload, err := json.Marshal(requestSnapshot{ID: req.GetID(), RequestedAt: req.GetRequestedAt(), RequestedScope: req.GetRequestedScopes(), GrantedScope: req.GetGrantedScopes(), RequestedAudience: req.GetRequestedAudience(), GrantedAudience: req.GetGrantedAudience(), Form: req.GetRequestForm(), Session: session})
	if err != nil {
		return err
	}
	write := func(tx *gorm.DB) error {
		if err := s.checkConsent(tx, req, true); err != nil {
			return err
		}
		hash := digest(key)
		if err := tx.Create(&SessionRecord{Kind: kind, KeyHash: hash, RequestID: req.GetID(), ClientID: req.GetClient().GetID(), Payload: payload, Active: true}).Error; err != nil {
			return err
		}
		for _, id := range session.GrantIDs {
			if err := tx.Create(&consent.SessionLink{GrantID: id, SessionKind: kind, SessionHash: hash}).Error; err != nil {
				return err
			}
		}
		for _, audience := range req.GetGrantedAudience() {
			if err := tx.Create(&SessionAudience{SessionKind: kind, SessionHash: hash, Audience: audience}).Error; err != nil {
				return err
			}
		}
		if kind == kindCode || kind == kindAccess || kind == kindRefresh {
			userID, err := uuid.Parse(session.GetSubject())
			if err != nil {
				return fosite.ErrInvalidGrant
			}
			eventType := map[string]string{kindCode: "authorization_code_issued", kindAccess: "access_token_issued", kindRefresh: "refresh_token_issued"}[kind]
			resource := ""
			if len(req.GetGrantedAudience()) == 1 {
				resource = req.GetGrantedAudience()[0]
			}
			if err := audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: eventType, ClientID: req.GetClient().GetID(), Resource: resource, Result: "success", VisibleToUser: true}); err != nil {
				return err
			}
		}
		return nil
	}
	if _, ok := ctx.Value(txKey{}).(*txState); ok {
		return write(s.query(ctx))
	}
	return s.query(ctx).Transaction(write)
}

func (s *Store) get(ctx context.Context, kind, key string) (fosite.Requester, bool, error) {
	var row SessionRecord
	err := s.query(ctx).Where("kind = ? AND key_hash = ?", kind, digest(key)).First(&row).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fosite.ErrNotFound
	}
	if err != nil {
		return nil, false, err
	}
	client, err := s.GetClient(ctx, row.ClientID)
	if err != nil {
		return nil, false, err
	}
	var snapshot requestSnapshot
	if err = json.Unmarshal(row.Payload, &snapshot); err != nil {
		return nil, false, err
	}
	if snapshot.Session == nil || snapshot.Session.DefaultSession == nil {
		return nil, false, errors.New("corrupt oauth session")
	}
	// Refuse records without their audience links, including legacy rows that
	// predate this invariant. This prevents a disabled resource reactivating them.
	for _, audience := range snapshot.GrantedAudience {
		var count int64
		if err := s.query(ctx).Model(&SessionAudience{}).Where("session_kind = ? AND session_hash = ? AND audience = ?", row.Kind, row.KeyHash, audience).Count(&count).Error; err != nil {
			return nil, false, err
		}
		if count != 1 {
			return nil, false, fosite.ErrNotFound
		}
	}
	req := &fosite.Request{ID: snapshot.ID, RequestedAt: snapshot.RequestedAt, Client: client, RequestedScope: snapshot.RequestedScope, GrantedScope: snapshot.GrantedScope, RequestedAudience: snapshot.RequestedAudience, GrantedAudience: snapshot.GrantedAudience, Form: snapshot.Form, Session: snapshot.Session}
	// Return invalidated codes and refresh sessions to let Fosite revoke their family.
	if !row.Active {
		return req, false, nil
	}
	if err := s.checkConsent(s.query(ctx), req, false); err != nil {
		if errors.Is(err, fosite.ErrInvalidGrant) {
			return nil, false, fosite.ErrNotFound
		}
		return nil, false, err
	}
	return req, true, nil
}

func (s *Store) deactivate(ctx context.Context, kind, key string) error {
	return s.query(ctx).Model(&SessionRecord{}).Where("kind = ? AND key_hash = ?", kind, digest(key)).Update("active", false).Error
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, kindCode, key, req)
}
func (s *Store) GetAuthorizeCodeSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	r, active, err := s.get(ctx, kindCode, key)
	if err != nil {
		return nil, err
	}
	if !active {
		return r, fosite.ErrInvalidatedAuthorizeCode
	}
	return r, nil
}
func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, key string) error {
	if err := s.lockConsentForSession(ctx, kindCode, key); err != nil {
		if errors.Is(err, fosite.ErrInactiveToken) {
			return fosite.ErrInvalidatedAuthorizeCode
		}
		return err
	}
	result := s.query(ctx).Model(&SessionRecord{}).Where("kind = ? AND key_hash = ? AND active = ?", kindCode, digest(key), true).Update("active", false)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fosite.ErrInvalidatedAuthorizeCode
	}
	return nil
}
func (s *Store) CreateAccessTokenSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, kindAccess, key, req)
}
func (s *Store) GetAccessTokenSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	r, active, err := s.get(ctx, kindAccess, key)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, fosite.ErrNotFound
	}
	return r, nil
}
func (s *Store) DeleteAccessTokenSession(ctx context.Context, key string) error {
	return s.deactivate(ctx, kindAccess, key)
}
func (s *Store) CreateRefreshTokenSession(ctx context.Context, key, _ string, req fosite.Requester) error {
	if state, ok := ctx.Value(txKey{}).(*txState); ok && state.refreshRequest != nil {
		// RFC 6749 section 6: a rotated refresh token retains the old refresh
		// token's scope even when this particular access token was narrowed.
		original := state.refreshRequest
		oldSession, ok := original.GetSession().(*Session)
		if !ok || oldSession == nil {
			return errors.New("invalid original refresh session")
		}
		currentSession, ok := req.GetSession().(*Session)
		if !ok || currentSession == nil {
			return errors.New("invalid rotated refresh session")
		}
		stored := fosite.NewRequest()
		stored.Merge(req)
		stored.RequestedScope = append(fosite.Arguments(nil), original.GetRequestedScopes()...)
		stored.GrantedScope = append(fosite.Arguments(nil), original.GetGrantedScopes()...)
		stored.RequestedAudience = append(fosite.Arguments(nil), original.GetRequestedAudience()...)
		stored.GrantedAudience = append(fosite.Arguments(nil), original.GetGrantedAudience()...)
		stored.Form.Del("scope")
		refreshSession := currentSession.Clone().(*Session)
		refreshSession.GrantIDs = append([]uuid.UUID(nil), oldSession.GrantIDs...)
		stored.SetSession(refreshSession)
		req = stored
	}
	return s.create(ctx, kindRefresh, key, req)
}
func (s *Store) GetRefreshTokenSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	r, active, err := s.get(ctx, kindRefresh, key)
	if err != nil {
		return nil, err
	}
	if !active {
		return r, fosite.ErrInactiveToken
	}
	return r, nil
}
func (s *Store) DeleteRefreshTokenSession(ctx context.Context, key string) error {
	return s.deactivate(ctx, kindRefresh, key)
}
func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.revokeFamily(ctx, requestID)
}
func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.revokeFamily(ctx, requestID)
}
func (s *Store) revokeFamily(ctx context.Context, requestID string) error {
	if requestID == "" {
		return errors.New("empty oauth request id")
	}
	write := func(tx *gorm.DB) error {
		var row SessionRecord
		err := tx.Where("kind IN ? AND request_id = ? AND active = ?", []string{kindAccess, kindRefresh}, requestID, true).First(&row).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		var snapshot requestSnapshot
		if err := json.Unmarshal(row.Payload, &snapshot); err != nil || snapshot.Session == nil || snapshot.Session.DefaultSession == nil {
			return errors.New("corrupt oauth session")
		}
		userID, err := uuid.Parse(snapshot.Session.GetSubject())
		if err != nil {
			return err
		}
		result := tx.Model(&SessionRecord{}).Where("kind IN ? AND request_id = ? AND active = ?", []string{kindAccess, kindRefresh}, requestID, true).Update("active", false)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}
		resource := ""
		if len(snapshot.GrantedAudience) == 1 {
			resource = snapshot.GrantedAudience[0]
		}
		return audit.RecordSecurity(tx, audit.SecurityEvent{UserID: &userID, Type: "token_family_revoked", ClientID: row.ClientID, Resource: resource, Result: "success", VisibleToUser: true})
	}
	if _, ok := ctx.Value(txKey{}).(*txState); ok {
		return write(s.query(ctx))
	}
	return s.query(ctx).Transaction(write)
}
func (s *Store) RotateRefreshToken(ctx context.Context, requestID, key string) error {
	state, ok := ctx.Value(txKey{}).(*txState)
	if !ok {
		return errors.New("refresh rotation requires a transaction")
	}
	original, active, err := s.get(ctx, kindRefresh, key)
	if err != nil {
		return err
	}
	if !active || original.GetID() != requestID {
		return fosite.ErrInactiveToken
	}
	if err := s.checkConsent(s.query(ctx), original, true); err != nil {
		return err
	}
	result := s.query(ctx).Model(&SessionRecord{}).Where("kind = ? AND key_hash = ? AND request_id = ? AND active = ?", kindRefresh, digest(key), requestID, true).Update("active", false)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return fosite.ErrInactiveToken
	}
	state.refreshRequest = original
	return s.RevokeAccessToken(ctx, requestID)
}

// The grant lock precedes the session row lock, matching consent revocation.
// Fosite calls these operations in a transaction.
func (s *Store) lockConsentForSession(ctx context.Context, kind, key string) error {
	req, active, err := s.get(ctx, kind, key)
	if err != nil {
		return err
	}
	if !active {
		return fosite.ErrInactiveToken
	}
	return s.checkConsent(s.query(ctx), req, true)
}
func (s *Store) CreatePKCERequestSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, kindPKCE, key, req)
}
func (s *Store) GetPKCERequestSession(ctx context.Context, key string, _ fosite.Session) (fosite.Requester, error) {
	r, active, err := s.get(ctx, kindPKCE, key)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, fosite.ErrNotFound
	}
	return r, nil
}
func (s *Store) DeletePKCERequestSession(ctx context.Context, key string) error {
	return s.deactivate(ctx, kindPKCE, key)
}
func (s *Store) CreateOpenIDConnectSession(ctx context.Context, key string, req fosite.Requester) error {
	return s.create(ctx, kindOIDC, key, req)
}
func (s *Store) GetOpenIDConnectSession(ctx context.Context, key string, _ fosite.Requester) (fosite.Requester, error) {
	r, active, err := s.get(ctx, kindOIDC, key)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, fosite.ErrNotFound
	}
	return r, nil
}
func (s *Store) DeleteOpenIDConnectSession(ctx context.Context, key string) error {
	return s.deactivate(ctx, kindOIDC, key)
}
