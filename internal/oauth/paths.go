package oauth

// Public protocol endpoints. Discovery and the provider use the same paths.
const (
	AuthorizePath     = "/api/oauth2/authorize"
	ContinuePath      = "/api/oauth2/continue"
	ConsentPath       = "/api/oauth2/consent"
	TokenPath         = "/api/oauth2/token"
	RevocationPath    = "/api/oauth2/revoke"
	IntrospectionPath = "/api/oauth2/introspect"
	UserInfoPath      = "/api/userinfo"
)
