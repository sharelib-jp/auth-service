package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sharelib-jp/auth-service/config"
)

func TestNodeinfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	data := `[HOST]
SCHEME = "http://"
HOSTNAME = "localhost"
PORT = ":8080"
[WEBAUTHN]
RP_DISPLAY_NAME = "Test"
[DATABASE]
DATABASE_DSN = "secret-dsn"
[METADATA]
NODE_NAME = "開発図書館"
NODE_DOMAIN = "library.example"
NODE_ADMINS = [{ name = "admin", email = "admin@example.com" }]
MAINTAINER = [{ name = "developer", email = "dev@example.com" }]
`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	conf, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/.well-known/nodeinfo", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"version": "0.1",
		"metadata": map[string]any{
			"nodeName": "開発図書館", "nodeDomain": "library.example",
			"nodeAdmins": []any{map[string]any{"name": "admin", "email": "admin@example.com"}},
			"maintainer": []any{map[string]any{"name": "developer", "email": "dev@example.com"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("response = %#v, want %#v", got, want)
	}
}
