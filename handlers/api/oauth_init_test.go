package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/sharelib-jp/auth-service/config"
)

func TestOAuthIssuerAndSigningKeyRotation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	active, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	old, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privateFile := filepath.Join(dir, "active.pem")
	if err := os.WriteFile(privateFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(active)}), 0600); err != nil {
		t.Fatal(err)
	}
	previousFile := filepath.Join(dir, "previous.json")
	previous, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &old.PublicKey, KeyID: "old", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(previousFile, previous, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OAUTH_HMAC_SECRET", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32))))
	conf := &config.Config{SCHEME: "https://", HOSTNAME: "another.example", PORT: ":443", WEBAUTHN_RP_ORIGIN: "https://another.example", OAuth: config.OAuthConfig{Enabled: true, Issuer: "https://another.example", SigningKeyFile: privateFile, SigningKeyID: "new", PreviousJWKSFile: previousFile}}
	handler, err := newOAuthHandler(conf, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/.well-known/jwks.json", handler.jwks)
	router.GET("/.well-known/openid-configuration", handler.openIDDiscovery)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest("GET", "https://another.example/.well-known/jwks.json", nil))
	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(response.Body.Bytes(), &keys); err != nil || len(keys.Keys) != 2 || keys.Keys[0].KeyID != "new" || keys.Keys[1].KeyID != "old" {
		t.Fatalf("JWKS: %s %v", response.Body.String(), err)
	}
	if strings.Contains(response.Body.String(), `"d":`) {
		t.Fatal("JWKS exposed private key")
	}
	discovery := httptest.NewRecorder()
	router.ServeHTTP(discovery, httptest.NewRequest("GET", "https://another.example/.well-known/openid-configuration", nil))
	if !strings.Contains(discovery.Body.String(), `"issuer":"https://another.example"`) || strings.Contains(discovery.Body.String(), "auth.sasakulab.com") {
		t.Fatalf("issuer metadata: %s", discovery.Body.String())
	}
	conf.OAuth.Issuer = "https://wrong.example"
	if _, err := newOAuthHandler(conf, nil, nil); err == nil {
		t.Fatal("mismatched issuer accepted")
	}
}
