package oauth

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"gorm.io/gorm"
)

// NarrowRefreshRequest changes only this access-token request. The rotated
// refresh token retains its original scope and consent links in storage.
func (s *Store) NarrowRefreshRequest(ctx context.Context, request fosite.AccessRequester, scope string) error {
	if request == nil || scope == "" || strings.ContainsAny(scope, "\t\r\n") {
		return fosite.ErrInvalidScope
	}
	for i := 0; i < len(scope); i++ {
		b := scope[i]
		if b != ' ' && (b < 0x21 || b > 0x7e || b == '"' || b == '\\') {
			return fosite.ErrInvalidScope
		}
	}
	access, ok := request.(*fosite.AccessRequest)
	if !ok {
		return errors.New("unsupported Fosite access request type")
	}
	session, ok := access.GetSession().(*Session)
	if !ok || session == nil {
		return errors.New("invalid refresh session")
	}
	names := strings.Fields(scope)
	if len(names) == 0 {
		return fosite.ErrInvalidScope
	}
	requested := make(fosite.Arguments, 0, len(names))
	for _, name := range names {
		if !access.GetGrantedScopes().Has(name) || requested.Has(name) {
			return fosite.ErrInvalidScope
		}
		requested = append(requested, name)
	}
	var kept []uuid.UUID
	covered := make(map[string]bool)
	for _, id := range session.GrantIDs {
		var grant consent.Grant
		err := s.query(ctx).Where("id = ? AND user_id = ? AND client_id = ?", id, session.GetSubject(), access.GetClient().GetID()).First(&grant).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrInvalidGrant
		}
		if err != nil {
			return err
		}
		matched := false
		for _, name := range grant.Scopes {
			if requested.Has(name) {
				covered[name] = true
				matched = true
			}
		}
		if matched {
			kept = append(kept, id)
		}
	}
	for _, name := range requested {
		if !isIdentityScope(name) && !covered[name] {
			return fosite.ErrInvalidGrant
		}
	}
	narrowedSession := session.Clone().(*Session)
	narrowedSession.GrantIDs = kept
	access.SetSession(narrowedSession)
	access.GrantedScope = append(fosite.Arguments(nil), requested...)
	access.RequestedScope = append(fosite.Arguments(nil), requested...)
	return nil
}
