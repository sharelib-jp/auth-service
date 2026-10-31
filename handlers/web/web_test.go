package web

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/handlers/api"
)

func TestFrontendAndAPIRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"index.html":    "<!doctype html><title>frontend</title>",
		"assets/app.js": "console.log('app')",
		"favicon.svg":   "<svg></svg>",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(t.TempDir(), "config.toml")
	configData := "[HOST]\nSCHEME = \"http://\"\nHOSTNAME = \"localhost\"\nPORT = \":8080\"\n[WEBAUTHN]\nRP_DISPLAY_NAME = \"Test\"\n"
	if err := os.WriteFile(configPath, []byte(configData), 0600); err != nil {
		t.Fatal(err)
	}
	conf, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	router, err := api.NewRouter(conf, nil)
	if err != nil {
		t.Fatal(err)
	}
	Register(router, dir)

	for _, tc := range []struct {
		method, path, body, contentType string
		status                          int
		protected                       bool
	}{
		{"GET", "/", "frontend", "text/html", 200, true},
		{"GET", "/login/", "frontend", "text/html", 200, true},
		{"GET", "/register/step2", "frontend", "text/html", 200, true},
		{"GET", "/me/consents", "frontend", "text/html", 200, true},
		{"GET", "/oauth2/v1/auth?request=test", "frontend", "text/html", 200, true},
		{"GET", "/index.html", "frontend", "text/html", 200, true},
		{"GET", "/assets/app.js", "console.log", "javascript", 200, true},
		{"GET", "/favicon.svg", "<svg>", "image/svg+xml", 200, true},
		{"HEAD", "/me", "", "text/html", 200, true},
		{"GET", "/api", "pong", "application/json", 200, false},
		{"GET", "/.well-known/nodeinfo", "metadata", "application/json", 200, false},
		{"GET", "/api/missing", "404", "text/plain", 404, false},
		{"GET", "/.well-known/missing", "404", "text/plain", 404, false},
		{"GET", "/internal/missing", "404", "text/plain", 404, false},
		{"GET", "/assets/missing.js", "404", "text/plain", 404, false},
		{"GET", "/unknown", "404", "text/plain", 404, false},
		{"POST", "/login", "404", "text/plain", 404, false},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.body) || !strings.Contains(w.Header().Get("Content-Type"), tc.contentType) {
				t.Fatalf("status=%d, content-type=%q, body=%q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
			}
			if tc.protected && (w.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" || w.Header().Get("X-Frame-Options") != "DENY") {
				t.Fatalf("missing frame protection headers: %v", w.Header())
			}
		})
	}
}
