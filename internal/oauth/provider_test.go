package oauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/ory/fosite"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
)

func TestFositeCodePKCEAndIDToken(t *testing.T) {
	store, service, _, original, grant := testStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewProvider(store, oauth.ProviderConfig{Issuer: "https://issuer.example", HMACSecret: []byte(strings.Repeat("a", 32)), SigningKey: &jose.JSONWebKey{Key: key, KeyID: "key-1", Algorithm: "RS256", Use: "sig"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	authValues := url.Values{
		"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://client.example/callback"},
		"scope": {"openid offline_access b.orders.read"}, "audience": {"https://b.example/api"},
		"state": {strings.Repeat("s", 32)}, "nonce": {strings.Repeat("n", 32)},
		"code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])},
	}
	ctx := context.Background()
	authReq, err := provider.NewAuthorizeRequest(ctx, httptest.NewRequest(http.MethodGet, "https://issuer.example/api/oauth2/authorize?"+authValues.Encode(), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range authReq.GetRequestedScopes() {
		authReq.GrantScope(scope)
	}
	for _, aud := range authReq.GetRequestedAudience() {
		authReq.GrantAudience(aud)
	}
	session := original.GetSession().(*oauth.Session).Clone().(*oauth.Session)
	session.IDTokenClaims().Subject = session.GetSubject()
	session.IDTokenClaims().AuthTime = time.Now().UTC()
	response, err := provider.NewAuthorizeResponse(ctx, authReq, session)
	if err != nil {
		t.Fatal(err)
	}
	values := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {response.GetCode()}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
	tokenReq := httptest.NewRequest(http.MethodPost, "https://issuer.example/api/oauth2/token", strings.NewReader(values.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accessReq, err := provider.NewAccessRequest(ctx, tokenReq, oauth.NewSession())
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := provider.NewAccessResponse(ctx, accessReq)
	if err != nil {
		t.Fatal(err)
	}
	if tokens.GetAccessToken() == "" || tokens.GetExtra("refresh_token") == nil || tokens.GetExtra("id_token") == nil {
		t.Fatalf("missing token: %+v", tokens)
	}
	idToken, err := josejwt.ParseSigned(tokens.GetExtra("id_token").(string))
	if err != nil {
		t.Fatal(err)
	}
	var claims josejwt.Claims
	var extra struct {
		Nonce string `json:"nonce"`
	}
	if err := idToken.Claims(&key.PublicKey, &claims, &extra); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "https://issuer.example" || claims.Subject != grant.UserID.String() || !claims.Audience.Contains("client") || extra.Nonce != authValues.Get("nonce") {
		t.Fatalf("invalid claims: %+v %+v", claims, extra)
	}
	if err := claims.Validate(josejwt.Expected{Issuer: "https://issuer.example", Audience: josejwt.Audience{"client"}, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := claims.Validate(josejwt.Expected{Issuer: "https://wrong.example", Audience: josejwt.Audience{"client"}, Time: time.Now()}); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	if err := claims.Validate(josejwt.Expected{Issuer: "https://issuer.example", Audience: josejwt.Audience{"other-client"}, Time: time.Now()}); err == nil {
		t.Fatal("wrong audience accepted")
	}
	if err := claims.Validate(josejwt.Expected{Issuer: "https://issuer.example", Audience: josejwt.Audience{"client"}, Time: time.Now().Add(20 * time.Minute)}); err == nil {
		t.Fatal("expired ID token accepted")
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if err := idToken.Claims(&otherKey.PublicKey, &claims); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if _, _, err := provider.IntrospectToken(ctx, tokens.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err != nil {
		t.Fatal(err)
	}
	if err := service.Revoke(ctx, grant.UserID, grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.IntrospectToken(ctx, tokens.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err == nil {
		t.Fatal("revoked token was introspected")
	}
}

type flowFixture struct {
	provider fosite.OAuth2Provider
	db       *gorm.DB
	code     string
	verifier string
}

func newFlowFixture(t *testing.T) flowFixture {
	t.Helper()
	store, _, db, original, _ := testStore(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := oauth.NewProvider(store, oauth.ProviderConfig{Issuer: "https://issuer.example", HMACSecret: []byte(strings.Repeat("a", 32)), SigningKey: &jose.JSONWebKey{Key: key, KeyID: "key-1", Algorithm: "RS256", Use: "sig"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 43)
	hash := sha256.Sum256([]byte(verifier))
	values := url.Values{"client_id": {"client"}, "response_type": {"code"}, "redirect_uri": {"https://client.example/callback"}, "scope": {"openid offline_access b.orders.read"}, "audience": {"https://b.example/api"}, "state": {strings.Repeat("s", 32)}, "nonce": {strings.Repeat("n", 32)}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}
	ctx := context.Background()
	req, err := provider.NewAuthorizeRequest(ctx, httptest.NewRequest("GET", "https://issuer.example/api/oauth2/authorize?"+values.Encode(), nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range req.GetRequestedScopes() {
		req.GrantScope(scope)
	}
	for _, audience := range req.GetRequestedAudience() {
		req.GrantAudience(audience)
	}
	session := original.GetSession().(*oauth.Session).Clone().(*oauth.Session)
	session.IDTokenClaims().Subject = session.GetSubject()
	session.IDTokenClaims().AuthTime = time.Now().UTC()
	response, err := provider.NewAuthorizeResponse(ctx, req, session)
	if err != nil {
		t.Fatal(err)
	}
	return flowFixture{provider: provider, db: db, code: response.GetCode(), verifier: verifier}
}

func (f flowFixture) exchange(values url.Values) (fosite.AccessResponder, error) {
	req := httptest.NewRequest("POST", "https://issuer.example/api/oauth2/token", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := context.Background()
	access, err := f.provider.NewAccessRequest(ctx, req, oauth.NewSession())
	if err != nil {
		return nil, err
	}
	return f.provider.NewAccessResponse(ctx, access)
}

func (f flowFixture) codeValues(verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "code": {f.code}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}}
}

func TestFositeCodeAndRefreshReplay(t *testing.T) {
	t.Run("code replay revokes issued tokens", func(t *testing.T) {
		f := newFlowFixture(t)
		tokens, err := f.exchange(f.codeValues(f.verifier))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.exchange(f.codeValues(f.verifier)); err == nil {
			t.Fatal("reused code succeeded")
		}
		if _, _, err := f.provider.IntrospectToken(context.Background(), tokens.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err == nil {
			t.Fatal("code replay did not revoke access token")
		}
	})
	t.Run("refresh replay revokes rotated tokens", func(t *testing.T) {
		f := newFlowFixture(t)
		tokens, err := f.exchange(f.codeValues(f.verifier))
		if err != nil {
			t.Fatal(err)
		}
		values := url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "refresh_token": {tokens.GetExtra("refresh_token").(string)}}
		rotated, err := f.exchange(values)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.exchange(values); !errors.Is(err, fosite.ErrInvalidGrant) {
			t.Fatalf("refresh replay: %v", err)
		}
		if _, _, err := f.provider.IntrospectToken(context.Background(), rotated.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err == nil {
			t.Fatal("refresh replay did not revoke rotated access token")
		}
	})
	t.Run("incorrect verifier consumes PKCE challenge", func(t *testing.T) {
		f := newFlowFixture(t)
		if _, err := f.exchange(f.codeValues(strings.Repeat("x", 43))); err == nil {
			t.Fatal("wrong verifier succeeded")
		}
		if _, err := f.exchange(f.codeValues(f.verifier)); err == nil {
			t.Fatal("code succeeded after invalid verifier")
		}
	})
}

func TestFositeExpiredAndTamperedTokens(t *testing.T) {
	t.Run("expired authorization code", func(t *testing.T) {
		f := newFlowFixture(t)
		var row oauth.SessionRecord
		if err := f.db.Where("kind = ?", "code").First(&row).Error; err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(row.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		session := payload["session"].(map[string]any)
		expires := session["expires_at"].(map[string]any)
		expires["authorize_code"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		data, _ := json.Marshal(payload)
		if err := f.db.Model(&oauth.SessionRecord{}).Where("kind = ? AND key_hash = ?", row.Kind, row.KeyHash).Update("payload", data).Error; err != nil {
			t.Fatal(err)
		}
		if _, err := f.exchange(f.codeValues(f.verifier)); err == nil {
			t.Fatal("expired authorization code succeeded")
		}
	})
	t.Run("tampered access token", func(t *testing.T) {
		f := newFlowFixture(t)
		tokens, err := f.exchange(f.codeValues(f.verifier))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.provider.IntrospectToken(context.Background(), tokens.GetAccessToken()+"x", fosite.AccessToken, oauth.NewSession()); err == nil {
			t.Fatal("tampered access token was accepted")
		}
	})
}

func TestHMACRotationKeepsExistingTokensUntilPreviousKeyRemoved(t *testing.T) {
	f := newFlowFixture(t)
	tokens, err := f.exchange(f.codeValues(f.verifier))
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	options := oauth.ProviderConfig{Issuer: "https://issuer.example", HMACSecret: []byte(strings.Repeat("b", 32)), RotatedHMACSecrets: [][]byte{[]byte(strings.Repeat("a", 32))}, SigningKey: &jose.JSONWebKey{Key: key, KeyID: "new-key", Algorithm: "RS256", Use: "sig"}}
	rotated, err := oauth.NewProvider(oauth.NewStore(f.db), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := rotated.IntrospectToken(context.Background(), tokens.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err != nil {
		t.Fatalf("previous HMAC secret rejected: %v", err)
	}
	options.RotatedHMACSecrets = nil
	withoutOld, err := oauth.NewProvider(oauth.NewStore(f.db), options)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := withoutOld.IntrospectToken(context.Background(), tokens.GetAccessToken(), fosite.AccessToken, oauth.NewSession()); err == nil {
		t.Fatal("old token accepted without previous secret")
	}
}
