package oauth

import (
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Session is serialized with every Fosite request. GrantIDs bind a token
// family to consent snapshots; authorization must populate them after checking
// the resource, scopes, purpose and policy for the authenticated user.
type Session struct {
	*openid.DefaultSession
	GrantIDs []uuid.UUID `json:"grant_ids"`
}

func NewSession() *Session { return &Session{DefaultSession: openid.NewDefaultSession()} }

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	var inner *openid.DefaultSession
	if s.DefaultSession != nil {
		inner = s.DefaultSession.Clone().(*openid.DefaultSession)
	}
	return &Session{DefaultSession: inner, GrantIDs: append([]uuid.UUID(nil), s.GrantIDs...)}
}
