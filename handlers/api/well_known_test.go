package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
	want := map[string]any{
		"version": "0.1",
		"metadata": map[string]any{
			"nodeName": "開発図書館", "nodeDomain": "library.example",
			"nodeAdmins": []any{map[string]any{"name": "admin", "email": "admin@example.com"}},
			"maintainer": []any{map[string]any{"name": "developer", "email": "dev@example.com"}},
		},
	}
	for _, path := range []string{"/.well-known/nodeinfo"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			var got map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("response = %#v, want %#v", got, want)
			}
		})
	}
}

func TestBrandLogo(t *testing.T) {
	for _, tc := range []struct {
		name, key, extension, contentType string
		status                            int
	}{
		{"jpeg", "HEADER", ".jpg", "image/jpeg", http.StatusOK},
		{"jpeg extension", "HEADER", ".jpeg", "image/jpeg", http.StatusOK},
		{"png", "HEADER", ".png", "image/png", http.StatusOK},
		{"svg legacy key", "HEADER_LOGO", ".SVG", "image/svg+xml", http.StatusOK},
		{"unsupported", "HEADER", ".gif", "", http.StatusUnsupportedMediaType},
		{"missing", "HEADER", ".png", "", http.StatusNotFound},
		{"unset", "", "", "", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			logo := filepath.Join(dir, "header"+tc.extension)
			if tc.name != "missing" && tc.key != "" {
				if err := os.WriteFile(logo, []byte("test image"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			content := "[HOST]\nSCHEME = \"http://\"\nHOSTNAME = \"localhost\"\nPORT = \":8080\"\n[WEBAUTHN]\nRP_DISPLAY_NAME = \"Test\"\n"
			if tc.key != "" {
				content += "[BRANDRESOURCES]\n" + tc.key + " = " + strconv.Quote(logo) + "\n"
			}
			configPath := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			conf, err := config.LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			router, err := NewRouter(conf, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/.well-known/header"} {
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
				if response.Code != tc.status {
					t.Fatalf("%s: status = %d, want %d", path, response.Code, tc.status)
				}
				if tc.status == http.StatusOK && (response.Header().Get("Content-Type") != tc.contentType || response.Body.String() != "test image") {
					t.Fatalf("%s: content type = %q, body = %q", path, response.Header().Get("Content-Type"), response.Body.String())
				}
			}
		})
	}
}
