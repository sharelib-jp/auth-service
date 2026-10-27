package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/dao"
	"github.com/sharelib-jp/auth-service/internal/testdb"
	"github.com/sharelib-jp/auth-service/lib"
	"github.com/sharelib-jp/auth-service/models"
	"gorm.io/gorm"
)

const testOrigin = "http://localhost:8080"

type testClient struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

func testService(t *testing.T) (*testClient, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	driver, dsn := testdb.Config(t)
	db, err := dao.OpenWithDriver(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	t.Cleanup(func() { sqlDB.Close() })
	conf := &config.Config{SCHEME: "http://", HOSTNAME: "localhost", PORT: ":8080", WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DRIVER: driver, DATABASE_DSN: dsn}
	router, err := NewRouter(conf, db)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{handler: router, cookies: map[string]*http.Cookie{}}, db
}

func (client *testClient) do(t *testing.T, method, path string, body any, status int) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, testOrigin+path, bytes.NewReader(data))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", testOrigin)
	for _, cookie := range client.cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	client.handler.ServeHTTP(recorder, request)
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.MaxAge < 0 {
			delete(client.cookies, cookie.Name)
		} else {
			client.cookies[cookie.Name] = cookie
		}
	}
	if recorder.Code != status {
		t.Fatalf("%s %s: got %d, want %d: %s", method, path, recorder.Code, status, recorder.Body.String())
	}
	return recorder
}

// failInserts injects a database failure on either supported backend.
func failInserts(t *testing.T, db *gorm.DB, table, message string) func() {
	t.Helper()
	name := "fail_" + table
	if db.Dialector.Name() == "postgres" {
		if err := db.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION '%s'; END $$`, name, message)).Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, table, name)).Error; err != nil {
			t.Fatal(err)
		}
	} else if err := db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s
		BEGIN SELECT RAISE(ABORT, '%s'); END`, name, table, message)).Error; err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		query := "DROP TRIGGER " + name
		if db.Dialector.Name() == "postgres" {
			query += " ON " + table
		}
		if err := db.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
		if db.Dialector.Name() == "postgres" {
			if err := db.Exec("DROP FUNCTION " + name + "()").Error; err != nil {
				t.Fatal(err)
			}
		}
	}
}

type testOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		User      struct {
			ID string `json:"id"`
		} `json:"user"`
		AuthenticatorSelection struct {
			ResidentKey      string `json:"residentKey"`
			UserVerification string `json:"userVerification"`
		} `json:"authenticatorSelection"`
	} `json:"publicKey"`
}

func optionsFrom(t *testing.T, response *httptest.ResponseRecorder) testOptions {
	t.Helper()
	var options testOptions
	if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil || options.PublicKey.Challenge == "" {
		t.Fatalf("invalid options: %s, %v", response.Body.String(), err)
	}
	return options
}

type testAuthenticator struct {
	key        *ecdsa.PrivateKey
	id, handle []byte
}

func newAuthenticator(t *testing.T, handle string) *testAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	decodedHandle, err := base64.RawURLEncoding.DecodeString(handle)
	if err != nil {
		t.Fatal(err)
	}
	return &testAuthenticator{key: key, id: id, handle: decodedHandle}
}

func encode(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (auth *testAuthenticator) registration(t *testing.T, challenge, origin string, verified bool) any {
	t.Helper()
	publicKey, err := cbor.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1,
		-2: auth.key.X.FillBytes(make([]byte, 32)), -3: auth.key.Y.FillBytes(make([]byte, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	rpHash := sha256.Sum256([]byte("localhost"))
	authData := append([]byte{}, rpHash[:]...)
	flags := byte(0x41) // User present and attested credential data.
	if verified {
		flags |= 0x04
	}
	authData = append(authData, flags, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(auth.id)))
	authData = append(authData, auth.id...)
	authData = append(authData, publicKey...)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	clientData := mustJSON(t, map[string]any{"type": "webauthn.create", "challenge": challenge, "origin": origin, "crossOrigin": false})
	return map[string]any{
		"id": encode(auth.id), "rawId": encode(auth.id), "type": "public-key",
		"response":               map[string]any{"attestationObject": encode(attestation), "clientDataJSON": encode(clientData), "transports": []string{"internal"}},
		"clientExtensionResults": map[string]any{},
	}
}

func (auth *testAuthenticator) assertion(t *testing.T, challenge, origin string, counter uint32, verified bool) map[string]any {
	t.Helper()
	rpHash := sha256.Sum256([]byte("localhost"))
	authData := append([]byte{}, rpHash[:]...)
	flags := byte(0x01)
	if verified {
		flags |= 0x04
	}
	authData = append(authData, flags)
	authData = binary.BigEndian.AppendUint32(authData, counter)
	clientData := mustJSON(t, map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	clientHash := sha256.Sum256(clientData)
	signedData := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(signedData)
	r, signatureS, err := ecdsa.Sign(rand.Reader, auth.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Use canonical low-S encoding, accepted by restrictive signature policies too.
	if signatureS.Cmp(new(big.Int).Rsh(new(big.Int).Set(auth.key.Params().N), 1)) > 0 {
		signatureS.Sub(auth.key.Params().N, signatureS)
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, signatureS})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": encode(auth.id), "rawId": encode(auth.id), "type": "public-key",
		"response":               map[string]any{"authenticatorData": encode(authData), "clientDataJSON": encode(clientData), "signature": encode(signature), "userHandle": encode(auth.handle)},
		"clientExtensionResults": map[string]any{},
	}
}

func (client *testClient) register(t *testing.T, username string) (*testAuthenticator, models.User) {
	t.Helper()
	response := client.do(t, "POST", "/api/auth/register/begin", lib.RegistrationInput{UserName: username, Name: "登録 太郎", Email: username + "@example.com"}, 200)
	options := optionsFrom(t, response)
	if options.PublicKey.AuthenticatorSelection.ResidentKey != "required" || options.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("registration must require a discoverable, verified credential: %s", response.Body.String())
	}
	auth := newAuthenticator(t, options.PublicKey.User.ID)
	response = client.do(t, "POST", "/api/auth/register/finish", auth.registration(t, options.PublicKey.Challenge, testOrigin, true), 201)
	var user models.User
	if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if user.ID.Version() != 7 || user.LibraryId < 1 || user.UserName != username || strings.Contains(response.Body.String(), "webauthn_handle") || strings.Contains(response.Body.String(), "Credential") {
		t.Fatalf("invalid user response: %s", response.Body.String())
	}
	return auth, user
}

func TestRegistrationLoginAndIndependentUpdates(t *testing.T) {
	client, db := testService(t)
	client.do(t, "PATCH", "/api/users/me/name", map[string]string{"Name": "unauthorized"}, 401)
	auth, user := client.register(t, "taro")
	if user.LibraryId != 1 {
		t.Fatalf("first LibraryId = %d", user.LibraryId)
	}
	response := client.do(t, "GET", "/api/users/me", nil, 200)
	if !strings.Contains(response.Body.String(), `"LibraryIdFormatted":"0000001"`) || !strings.Contains(response.Body.String(), `"Barcode":"00000017"`) {
		t.Fatalf("missing formatted identifiers: %s", response.Body.String())
	}
	cookie := client.cookies[authCookie]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 86400 {
		t.Fatalf("invalid session cookie: %+v", cookie)
	}
	for _, update := range []struct{ path, field, value string }{
		{"username", "UserName", "jiro"}, {"name", "Name", "更新 次郎"}, {"email", "Email", "JIRO@EXAMPLE.COM"},
	} {
		client.do(t, "PATCH", "/api/users/me/"+update.path, map[string]string{update.field: update.value}, 200)
		var stored models.User
		if err := db.First(&stored, "id = ?", user.ID).Error; err != nil {
			t.Fatal(err)
		}
		if stored.ID != user.ID || stored.LibraryId != user.LibraryId {
			t.Fatal("profile change mutated identifiers")
		}
		switch update.field {
		case "UserName":
			if stored.Name != user.Name || stored.Email != user.Email {
				t.Fatal("username update changed other fields")
			}
		case "Name":
			if stored.UserName != "jiro" || stored.Email != user.Email {
				t.Fatal("name update changed other fields")
			}
		case "Email":
			if stored.UserName != "jiro" || stored.Name != "更新 次郎" || stored.Email != "jiro@example.com" {
				t.Fatalf("invalid email update: %+v", stored)
			}
		}
	}
	response = client.do(t, "GET", "/api/users/me/barcode", nil, 200)
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "image/svg+xml") || !strings.Contains(response.Body.String(), "00000017") {
		t.Fatal("missing SVG barcode")
	}
	staleCookie := client.cookies[authCookie]
	client.do(t, "POST", "/api/auth/logout", nil, 204)
	client.cookies[authCookie] = staleCookie
	client.do(t, "GET", "/api/users/me", nil, 401)
	options := optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, 200))
	challengeCookie := client.cookies["sharelib_login"]
	body := auth.assertion(t, options.PublicKey.Challenge, testOrigin, 1, true)
	response = client.do(t, "POST", "/api/auth/login/finish", body, 200)
	if !strings.Contains(response.Body.String(), `"UserName":"jiro"`) || !strings.Contains(response.Body.String(), user.ID.String()) {
		t.Fatal("login after profile updates failed")
	}
	var stored models.PasskeyCredential
	if err := db.First(&stored, "user_id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if stored.Credential.Authenticator.SignCount != 1 {
		t.Fatal("credential counter was not persisted")
	}
	client.cookies["sharelib_login"] = challengeCookie
	client.do(t, "POST", "/api/auth/login/finish", body, 400)
	// A valid signature with a regressing counter is rejected.
	options = optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, 200))
	client.do(t, "POST", "/api/auth/login/finish", auth.assertion(t, options.PublicKey.Challenge, testOrigin, 1, true), 401)
}

func TestConcurrentLoginCounterUpdates(t *testing.T) {
	client, db := testService(t)
	auth, user := client.register(t, "taro")
	var requests []*http.Request
	for i := 0; i < 2; i++ {
		loginClient := &testClient{handler: client.handler, cookies: map[string]*http.Cookie{}}
		options := optionsFrom(t, loginClient.do(t, "POST", "/api/auth/login/begin", nil, 200))
		body := auth.assertion(t, options.PublicKey.Challenge, testOrigin, 1, true)
		request := httptest.NewRequest("POST", testOrigin+"/api/auth/login/finish", bytes.NewReader(mustJSON(t, body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", testOrigin)
		for _, cookie := range loginClient.cookies {
			request.AddCookie(cookie)
		}
		requests = append(requests, request)
	}
	responses := make(chan *httptest.ResponseRecorder, len(requests))
	for _, request := range requests {
		go func() {
			recorder := httptest.NewRecorder()
			client.handler.ServeHTTP(recorder, request)
			responses <- recorder
		}()
	}
	statuses := make(map[int]int)
	for range requests {
		response := <-responses
		statuses[response.Code]++
		if response.Code != 200 && response.Code != 401 {
			t.Errorf("concurrent login returned %d: %s", response.Code, response.Body.String())
		}
	}
	if statuses[200] != 1 || statuses[401] != 1 {
		t.Fatalf("same credential counter must succeed once: %v", statuses)
	}
	var stored models.PasskeyCredential
	if err := db.First(&stored, "user_id = ?", user.ID).Error; err != nil || stored.Credential.Authenticator.SignCount != 1 {
		t.Fatalf("concurrent login did not preserve counter: %+v, %v", stored, err)
	}
}

func TestRegistrationAttributes(t *testing.T) {
	for _, test := range []struct {
		name       string
		attributes map[string]any
		omit       bool
	}{
		{name: "omitted", omit: true},
		{name: "null"},
		{name: "empty", attributes: map[string]any{}},
		{name: "mixed values", attributes: map[string]any{
			"birthDate": "2000-01-01", "visits": float64(3), "enabled": false,
			"interests": []any{"books", float64(2), nil},
			"address":   map[string]any{"city": "東京"}, "optional": nil,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, db := testService(t)
			input := map[string]any{"UserName": "taro", "Name": "太郎", "Email": "taro@example.com"}
			if !test.omit {
				input["attributes"] = test.attributes
			}
			options := optionsFrom(t, client.do(t, "POST", "/api/auth/register/begin", input, 200))
			for _, model := range []any{&models.User{}, &models.UserAttributes{}} {
				var count int64
				if err := db.Model(model).Count(&count).Error; err != nil || count != 0 {
					t.Fatalf("begin registration persisted %T: count=%d, error=%v", model, count, err)
				}
			}
			auth := newAuthenticator(t, options.PublicKey.User.ID)
			response := client.do(t, "POST", "/api/auth/register/finish", auth.registration(t, options.PublicKey.Challenge, testOrigin, true), 201)
			var user models.User
			if err := json.Unmarshal(response.Body.Bytes(), &user); err != nil {
				t.Fatal(err)
			}
			var attrs []models.UserAttributes
			if err := db.Find(&attrs).Error; err != nil {
				t.Fatal(err)
			}
			if test.attributes == nil {
				if len(attrs) != 0 {
					t.Fatalf("registration without attributes created rows: %+v", attrs)
				}
				return
			}
			if len(attrs) != 1 || attrs[0].UserID != user.ID || attrs[0].UpdatedAt.IsZero() || !reflect.DeepEqual(attrs[0].Value, test.attributes) {
				t.Fatalf("registration attributes were not preserved: got %+v, want %+v for user %s", attrs, test.attributes, user.ID)
			}
		})
	}
}

func TestRegistrationAttributesMustBeObject(t *testing.T) {
	client, _ := testService(t)
	for _, attributes := range []any{"text", float64(42), true, []any{}, []any{map[string]any{"key": "value"}}} {
		client.do(t, "POST", "/api/auth/register/begin", map[string]any{
			"UserName": "taro", "Name": "太郎", "Email": "taro@example.com", "attributes": attributes,
		}, 400)
	}
}

func TestRegistrationAttributesFailureRollsBack(t *testing.T) {
	client, db := testService(t)
	options := optionsFrom(t, client.do(t, "POST", "/api/auth/register/begin", map[string]any{
		"UserName": "taro", "Name": "太郎", "Email": "taro@example.com", "attributes": map[string]any{"enabled": true},
	}, 200))
	auth := newAuthenticator(t, options.PublicKey.User.ID)
	failInserts(t, db, "user_attributes", "test attributes failure")
	body := auth.registration(t, options.PublicKey.Challenge, testOrigin, true)
	client.do(t, "POST", "/api/auth/register/finish", body, 500)
	for _, model := range []any{&models.User{}, &models.UserAttributes{}, &models.PasskeyCredential{}, &models.AuthSession{}} {
		var count int64
		if err := db.Model(model).Count(&count).Error; err != nil || count != 0 {
			t.Fatalf("failed attributes insert persisted %T: count=%d, error=%v", model, count, err)
		}
	}
	var sequence models.LibraryIdSequence
	if err := db.First(&sequence, 1).Error; err != nil || sequence.Value != 0 {
		t.Fatalf("failed attributes insert consumed a LibraryId: %+v, %v", sequence, err)
	}
	client.do(t, "GET", "/api/users/me", nil, 401)
	client.do(t, "POST", "/api/auth/register/finish", body, 400)
}

func TestRegistrationValidationAndSessionExpiry(t *testing.T) {
	client, db := testService(t)
	for _, input := range []any{
		map[string]string{"UserName": "taro", "Name": "太郎"},
		lib.RegistrationInput{UserName: "bad name", Name: "太郎", Email: "taro@example.com"},
		lib.RegistrationInput{UserName: "taro", Name: " ", Email: "taro@example.com"},
		lib.RegistrationInput{UserName: "taro", Name: "太郎", Email: "invalid"},
		map[string]string{"UserName": "taro", "Name": "太郎", "Email": "taro@example.com", "ID": uuid.NewString()},
	} {
		client.do(t, "POST", "/api/auth/register/begin", input, 400)
	}
	input := lib.RegistrationInput{UserName: "taro", Name: "太郎", Email: "TARO@EXAMPLE.COM"}
	options := optionsFrom(t, client.do(t, "POST", "/api/auth/register/begin", input, 200))
	auth := newAuthenticator(t, options.PublicKey.User.ID)
	var count int64
	db.Model(&models.User{}).Count(&count)
	if count != 0 {
		t.Fatal("begin registration persisted an unverified user")
	}
	if err := db.Model(&models.CeremonySession{}).Where("kind = ?", "registration").Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	client.do(t, "POST", "/api/auth/register/finish", auth.registration(t, options.PublicKey.Challenge, testOrigin, true), 400)
	_, user := client.register(t, "taro")
	client.do(t, "POST", "/api/auth/register/begin", input, 409)
	client.do(t, "PATCH", "/api/users/me/name", map[string]string{"Name": "valid", "Email": "injected@example.com"}, 400)
	client.do(t, "PATCH", "/api/users/me/email", map[string]string{"Email": "not-an-email"}, 400)
	if err := db.Model(&models.AuthSession{}).Where("user_id = ?", user.ID).Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	client.do(t, "GET", "/api/users/me", nil, 401)
}

func TestInvalidAuthenticatorResponses(t *testing.T) {
	client, db := testService(t)
	for _, mode := range []string{"origin", "challenge", "verification"} {
		t.Run("registration_"+mode, func(t *testing.T) {
			options := optionsFrom(t, client.do(t, "POST", "/api/auth/register/begin", lib.RegistrationInput{UserName: "taro", Name: "太郎", Email: "taro@example.com"}, 200))
			auth := newAuthenticator(t, options.PublicKey.User.ID)
			challenge, origin, verified := options.PublicKey.Challenge, testOrigin, true
			if mode == "origin" {
				origin = "https://attacker.example"
			}
			if mode == "challenge" {
				challenge = encode(make([]byte, 32))
			}
			if mode == "verification" {
				verified = false
			}
			cookie := client.cookies["sharelib_registration"]
			client.do(t, "POST", "/api/auth/register/finish", auth.registration(t, challenge, origin, verified), 400)
			client.cookies["sharelib_registration"] = cookie
			client.do(t, "POST", "/api/auth/register/finish", auth.registration(t, options.PublicKey.Challenge, testOrigin, true), 400)
		})
	}
	var count int64
	db.Model(&models.User{}).Count(&count)
	if count != 0 {
		t.Fatal("invalid registration created a user")
	}
	auth, _ := client.register(t, "taro")
	client.do(t, "POST", "/api/auth/logout", nil, 204)
	for _, mode := range []string{"origin", "challenge", "verification", "signature", "handle"} {
		t.Run("login_"+mode, func(t *testing.T) {
			options := optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, 200))
			challenge, origin, verified := options.PublicKey.Challenge, testOrigin, true
			if mode == "origin" {
				origin = "https://attacker.example"
			}
			if mode == "challenge" {
				challenge = encode(make([]byte, 32))
			}
			if mode == "verification" {
				verified = false
			}
			body := auth.assertion(t, challenge, origin, 1, verified)
			response := body["response"].(map[string]any)
			if mode == "signature" {
				response["signature"] = encode([]byte("invalid"))
			}
			if mode == "handle" {
				response["userHandle"] = encode(make([]byte, 32))
			}
			client.do(t, "POST", "/api/auth/login/finish", body, 401)
			client.do(t, "GET", "/api/users/me", nil, 401)
		})
	}
}

func TestProfileConflictsAndOriginPolicy(t *testing.T) {
	first, _ := testService(t)
	_, user := first.register(t, "first")
	second := &testClient{handler: first.handler, cookies: map[string]*http.Cookie{}}
	second.register(t, "second")
	first.do(t, "PATCH", "/api/users/me/username", map[string]string{"UserName": "second"}, 409)
	first.do(t, "PATCH", "/api/users/me/email", map[string]string{"Email": "SECOND@EXAMPLE.COM"}, 409)
	response := first.do(t, "GET", "/api/users/me", nil, 200)
	if !strings.Contains(response.Body.String(), fmt.Sprintf(`"ID":"%s"`, user.ID)) || !strings.Contains(response.Body.String(), `"UserName":"first"`) {
		t.Fatal("conflict modified the user")
	}
	request := httptest.NewRequest("PATCH", testOrigin+"/api/users/me/name", strings.NewReader(`{"Name":"attacker"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	request.AddCookie(first.cookies[authCookie])
	recorder := httptest.NewRecorder()
	first.handler.ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatalf("cross-origin update returned %d", recorder.Code)
	}
}

func TestRequestPolicyForUnknownRoutes(t *testing.T) {
	client, _ := testService(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, testOrigin+"/missing", nil)
		request.Header.Set("Origin", "https://attacker.example")
		recorder := httptest.NewRecorder()
		client.handler.ServeHTTP(recorder, request)
		status := http.StatusNotFound
		if method == http.MethodPost {
			status = http.StatusForbidden
		}
		if recorder.Code != status || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("request policy was not applied to %s /missing: status=%d, headers=%v", method, recorder.Code, recorder.Header())
		}
	}
}

func TestAuthenticationSessionFailureRollsBack(t *testing.T) {
	for _, kind := range []string{"registration", "login"} {
		t.Run(kind, func(t *testing.T) {
			client, db := testService(t)
			auth, original := client.register(t, "first")
			previousCookie := client.cookies[authCookie]
			var path string
			var body any
			if kind == "registration" {
				options := optionsFrom(t, client.do(t, "POST", "/api/auth/register/begin", lib.RegistrationInput{
					UserName: "second", Name: "次郎", Email: "second@example.com",
					Attributes: map[string]any{"enabled": true},
				}, 200))
				newAuth := newAuthenticator(t, options.PublicKey.User.ID)
				path = "/api/auth/register/finish"
				body = newAuth.registration(t, options.PublicKey.Challenge, testOrigin, true)
			} else {
				options := optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, 200))
				path = "/api/auth/login/finish"
				body = auth.assertion(t, options.PublicKey.Challenge, testOrigin, 1, true)
			}
			// Fail after user/credential changes and deletion of the previous session.
			allowInserts := failInserts(t, db, "auth_sessions", "test session failure")
			response := client.do(t, "POST", path, body, 500)
			if strings.Contains(response.Body.String(), "test session failure") {
				t.Fatal("internal database error was exposed")
			}
			for _, model := range []any{&models.User{}, &models.PasskeyCredential{}, &models.AuthSession{}} {
				var count int64
				if err := db.Model(model).Count(&count).Error; err != nil || count != 1 {
					t.Fatalf("failed %s changed %T: count=%d, error=%v", kind, model, count, err)
				}
			}
			var attributeCount int64
			if err := db.Model(&models.UserAttributes{}).Count(&attributeCount).Error; err != nil || attributeCount != 0 {
				t.Fatalf("failed %s persisted attributes: count=%d, error=%v", kind, attributeCount, err)
			}
			var sequence models.LibraryIdSequence
			if err := db.First(&sequence, 1).Error; err != nil || sequence.Value != 1 {
				t.Fatalf("failed registration consumed a LibraryId: %+v, %v", sequence, err)
			}
			var stored models.PasskeyCredential
			if err := db.First(&stored, "user_id = ?", original.ID).Error; err != nil || stored.Credential.Authenticator.SignCount != 0 {
				t.Fatalf("failed login updated the credential counter: %+v, %v", stored, err)
			}
			if response := client.do(t, "GET", "/api/users/me", nil, 200); !strings.Contains(response.Body.String(), original.ID.String()) {
				t.Fatal("previous session was not preserved after rollback")
			}
			client.do(t, "POST", path, body, 400)
			allowInserts()
			if kind == "registration" {
				_, created := client.register(t, "second")
				if created.LibraryId != 2 {
					t.Fatalf("registration after rollback got LibraryId %d", created.LibraryId)
				}
			} else {
				options := optionsFrom(t, client.do(t, "POST", "/api/auth/login/begin", nil, 200))
				client.do(t, "POST", path, auth.assertion(t, options.PublicKey.Challenge, testOrigin, 1, true), 200)
			}
			stale := &testClient{handler: client.handler, cookies: map[string]*http.Cookie{authCookie: previousCookie}}
			stale.do(t, "GET", "/api/users/me", nil, 401)
		})
	}
}
