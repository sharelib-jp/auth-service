package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sharelib-jp/auth-service/lib"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/config"
)

func TestOAuthUsesHostBoundCookieOnHTTPS(t *testing.T) {
	client, db := testService(t)
	client.register(t, "secure-cookie-user")
	value := client.cookies[authCookie].Value
	conf := &config.Config{SCHEME: "http://", HOSTNAME: "localhost", PORT: ":8080", WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DRIVER: db.Dialector.Name(), DATABASE_DSN: "unused"}
	service, err := lib.NewService(conf, db)
	if err != nil {
		t.Fatal(err)
	}
	s := &handler{service: service, secure: true}
	router := gin.New()
	router.GET("/session", s.oauthSessionStatus)
	router.GET("/protected", s.requireAuth, func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.GET("/set", func(c *gin.Context) { s.setCookie(c, authCookie, value, time.Hour) })
	router.POST("/logout", s.requireLogoutAuth, s.logout)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest("GET", "https://localhost/set", nil))
	var hostCookie *http.Cookie
	for _, candidate := range rec.Result().Cookies() {
		if candidate.Name == secureAuthCookie {
			hostCookie = candidate
		}
	}
	if hostCookie == nil || !hostCookie.Secure || !hostCookie.HttpOnly || hostCookie.Domain != "" || hostCookie.Path != "/" || hostCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("host-bound cookie: %+v", hostCookie)
	}
	legacyOnly := httptest.NewRequest("GET", "https://localhost/session", nil)
	legacyOnly.AddCookie(&http.Cookie{Name: authCookie, Value: value})
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, legacyOnly)
	if rec.Code != 401 {
		t.Fatalf("legacy cookie authorized OAuth: %d", rec.Code)
	}
	hostOnly := httptest.NewRequest("GET", "https://localhost/session", nil)
	hostOnly.AddCookie(hostCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, hostOnly)
	if rec.Code != 204 {
		t.Fatalf("host cookie rejected: %d", rec.Code)
	}
	protected := httptest.NewRequest("GET", "https://localhost/protected", nil)
	protected.AddCookie(&http.Cookie{Name: authCookie, Value: "injected"})
	protected.AddCookie(hostCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, protected)
	if rec.Code != 204 {
		t.Fatalf("legacy cookie overrode host cookie: %d", rec.Code)
	}
	logout := httptest.NewRequest("POST", "https://localhost/logout", nil)
	logout.AddCookie(hostCookie)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, logout)
	if rec.Code != 204 {
		t.Fatalf("logout: %d", rec.Code)
	}
	if _, err := service.Authenticate(t.Context(), value); err == nil {
		t.Fatal("host session survived logout")
	}
}
