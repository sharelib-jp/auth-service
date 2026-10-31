package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/config"
)

func TestRegisterRoutesWithSharedService(t *testing.T) {
	client, db := testService(t)
	_, user := client.register(t, "embedded-user")
	conf := &config.Config{SCHEME: "http://", HOSTNAME: "localhost", PORT: ":8080", WEBAUTHN_RP_DISPLAY_NAME: "Test", DATABASE_DRIVER: db.Dialector.Name(), DATABASE_DSN: "unused"}
	service, err := NewService(conf, db)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	RegisterRoutes(router.Group("/api"), service, testOrigin)
	request := httptest.NewRequest(http.MethodGet, testOrigin+"/api/users/me", nil)
	request.AddCookie(client.cookies[authCookie])
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), user.ID.String()) {
		t.Fatalf("response did not include user ID: %s", response.Body.String())
	}
}
