package oauth

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
)

// ProviderConfig holds stable deployment-specific values, not request headers.
type ProviderConfig struct {
	Issuer             string
	HMACSecret         []byte
	RotatedHMACSecrets [][]byte
	SigningKey         *jose.JSONWebKey
}

// NewProvider enables only code, PKCE S256, OIDC, refresh, introspection and
// revocation. Callers must authenticate resource servers and enforce audience
// access separately before exposing introspection to a network.
func NewProvider(store *Store, options ProviderConfig) (fosite.OAuth2Provider, error) {
	u, err := url.Parse(options.Issuer)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "localhost")) {
		return nil, errors.New("issuer must be an HTTPS origin (HTTP allowed for localhost)")
	}
	if store == nil || len(options.HMACSecret) < 32 {
		return nil, errors.New("oauth store and a 32-byte HMAC secret are required")
	}
	for _, key := range options.RotatedHMACSecrets {
		if len(key) < 32 {
			return nil, errors.New("rotated HMAC secret is too short")
		}
	}
	if options.SigningKey == nil || options.SigningKey.KeyID == "" {
		return nil, errors.New("OIDC signing key and key ID are required")
	}
	key, ok := options.SigningKey.Key.(*rsa.PrivateKey)
	if !ok || key == nil || key.N == nil || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("OIDC signing key must be a valid RSA private key of at least 2048 bits")
	}
	if options.SigningKey.Algorithm != "RS256" || options.SigningKey.Use != "sig" {
		return nil, errors.New("OIDC signing key must be designated for RS256 signatures")
	}
	conf := &fosite.Config{
		GlobalSecret: append([]byte(nil), options.HMACSecret...), RotatedGlobalSecrets: options.RotatedHMACSecrets,
		IDTokenIssuer: options.Issuer, TokenURL: options.Issuer + TokenPath,
		EnforcePKCE: true, EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy: fosite.ExactScopeStrategy, AudienceMatchingStrategy: fosite.ExactAudienceMatchingStrategy,
		AuthorizeCodeLifespan: 5 * time.Minute, AccessTokenLifespan: 5 * time.Minute,
		RefreshTokenLifespan: 24 * time.Hour, IDTokenLifespan: 5 * time.Minute,
		RefreshTokenScopes: []string{"offline_access"},
	}
	keyGetter := func(context.Context) (interface{}, error) { return options.SigningKey, nil }
	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2HMACStrategy(conf),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, conf),
		Signer:                     &jwt.DefaultSigner{GetPrivateKey: keyGetter},
	}
	return compose.Compose(conf, store, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2PKCEFactory,
	), nil
}
