package api

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
)

type oauthHandler struct {
	db         *gorm.DB
	store      *oauth.Store
	provider   fosite.OAuth2Provider
	service    *identity.Service
	issuer     string
	publicKeys jose.JSONWebKeySet
	secure     bool
}

func newOAuthHandler(conf *config.Config, db *gorm.DB, service *identity.Service) (*oauthHandler, error) {
	if conf.OAuth.Issuer != conf.Origin() {
		return nil, errors.New("OAuth issuer must match the configured authentication origin")
	}
	secret, err := base64.RawURLEncoding.DecodeString(os.Getenv("OAUTH_HMAC_SECRET"))
	if err != nil || len(secret) < 32 {
		return nil, errors.New("OAUTH_HMAC_SECRET must be base64url-encoded and at least 32 bytes")
	}
	data, err := os.ReadFile(conf.OAuth.SigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read OIDC signing key: %w", err)
	}
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid OIDC private key PEM")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			var ok bool
			key, ok = parsed.(*rsa.PrivateKey)
			if !ok {
				err = errors.New("OIDC signing key is not RSA")
			}
		}
	default:
		err = errors.New("unsupported OIDC private key PEM")
	}
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}
	keyJWK := &jose.JSONWebKey{Key: key, KeyID: conf.OAuth.SigningKeyID, Use: "sig", Algorithm: "RS256"}
	publicKeys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{keyJWK.Public()}}
	if conf.OAuth.PreviousJWKSFile != "" {
		data, err := os.ReadFile(conf.OAuth.PreviousJWKSFile)
		if err != nil {
			return nil, fmt.Errorf("read previous JWKS: %w", err)
		}
		var previous jose.JSONWebKeySet
		if err := json.Unmarshal(data, &previous); err != nil {
			return nil, fmt.Errorf("parse previous JWKS: %w", err)
		}
		seen := map[string]bool{keyJWK.KeyID: true}
		for _, old := range previous.Keys {
			public, ok := old.Key.(*rsa.PublicKey)
			if !ok || public.N == nil || public.N.BitLen() < 2048 || old.KeyID == "" || old.Use != "sig" || old.Algorithm != "RS256" || seen[old.KeyID] {
				return nil, errors.New("invalid or duplicate previous OIDC public key")
			}
			seen[old.KeyID] = true
			publicKeys.Keys = append(publicKeys.Keys, old)
		}
	}
	var previousSecrets [][]byte
	if encoded := os.Getenv("OAUTH_HMAC_PREVIOUS_SECRETS"); encoded != "" {
		for _, entry := range strings.Split(encoded, ",") {
			decoded, err := base64.RawURLEncoding.DecodeString(entry)
			if err != nil || len(decoded) < 32 {
				return nil, errors.New("OAUTH_HMAC_PREVIOUS_SECRETS contains an invalid key")
			}
			previousSecrets = append(previousSecrets, decoded)
		}
	}
	store := oauth.NewStore(db)
	provider, err := oauth.NewProvider(store, oauth.ProviderConfig{Issuer: conf.OAuth.Issuer, HMACSecret: secret, RotatedHMACSecrets: previousSecrets, SigningKey: keyJWK})
	if err != nil {
		return nil, err
	}
	return &oauthHandler{db: db, store: store, provider: provider, service: service, issuer: conf.OAuth.Issuer, publicKeys: publicKeys, secure: strings.HasPrefix(conf.OAuth.Issuer, "https://")}, nil
}

func (h *oauthHandler) register(router *gin.Engine) {
	router.GET("/.well-known/openid-configuration", h.openIDDiscovery)
	router.GET("/.well-known/oauth-authorization-server", h.oauthDiscovery)
	router.GET("/.well-known/jwks.json", h.jwks)
	router.GET(oauth.AuthorizePath, h.authorize)
	router.GET(oauth.ContinuePath, h.continueAuthorization)
	router.POST(oauth.ConsentPath, h.consent)
	router.GET(oauth.ConsentPath, h.consentDetails)
	router.POST(oauth.TokenPath, h.token)
	router.POST(oauth.RevocationPath, h.revoke)
	router.POST(oauth.IntrospectionPath, h.introspect)
	router.GET(oauth.UserInfoPath, h.userinfo)
	router.POST(oauth.UserInfoPath, h.userinfo)
	router.POST("/internal/audit/events", h.receiveAuditEvent)
	router.POST("/internal/authorize/check", h.checkBusinessPolicy)
}
