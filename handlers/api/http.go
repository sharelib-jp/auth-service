package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"

	"github.com/sharelib-jp/auth-service/lib"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/config"
	"github.com/sharelib-jp/auth-service/internal/consent"

	"gorm.io/gorm"
)

type handler struct {
	service  *lib.Service
	origin   string
	secure   bool
	consents *consent.Service
}

func NewRouter(conf *config.Config, db *gorm.DB) (*gin.Engine, error) {
	service, err := lib.NewService(conf, db)
	if err != nil {
		return nil, err
	}
	s := &handler{service: service, origin: conf.Origin(), secure: strings.HasPrefix(conf.Origin(), "https://"), consents: consent.NewService(consent.NewRepository(db))}
	router := gin.New()
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipQueryString: true}), gin.Recovery(), s.requestPolicy)
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, err
	}

	s.registerRoutes(router.Group("/api"))
	if conf.OAuth.Enabled {
		provider, err := newOAuthHandler(conf, db, service)
		if err != nil {
			return nil, err
		}
		provider.register(router)
	}
	return router, nil
}

// RegisterRoutes mounts the JSON API on an existing router using a shared service.
func RegisterRoutes(api *gin.RouterGroup, service *lib.Service, origin string) {
	s := &handler{service: service, origin: origin, secure: strings.HasPrefix(origin, "https://")}
	api.Use(s.requestPolicy)
	s.registerRoutes(api)
}

func (s *handler) registerRoutes(api *gin.RouterGroup) {
	api.GET("", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"message": "pong"}) })

	api.POST("/auth/register/begin", s.beginRegistration)
	api.POST("/auth/register/finish", s.finishRegistration)
	api.POST("/auth/login/begin", s.beginLogin)
	api.POST("/auth/login/finish", s.finishLogin)
	api.POST("/auth/logout", s.requireLogoutAuth, s.logout)
	api.GET("/auth/oauth-session", s.oauthSessionStatus)

	wellKnown := api.Group("/.well-known")
	wellKnown.GET("/nodeinfo", s.Nodeinfo)

	users := api.Group("/users/me", s.requireAuth)
	users.GET("", s.getUser)
	users.GET("/barcode", s.getBarcode)
	users.PATCH("/username", s.updateUserName)
	users.PATCH("/name", s.updateName)
	users.PATCH("/email", s.updateEmail)
	if s.consents != nil {
		consents := api.Group("/me/consents", s.requireAuth)
		consents.GET("", s.listConsents)
		consents.GET("/:id", s.getConsent)
		consents.DELETE("/:id", s.revokeConsent)
	}

}

func (s *handler) requestPolicy(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("X-Content-Type-Options", "nosniff")
	backchannel := c.Request.URL.Path == "/oauth2/token" || c.Request.URL.Path == "/oauth2/revoke" || c.Request.URL.Path == "/oauth2/introspect" || c.Request.URL.Path == "/userinfo" || c.Request.URL.Path == "/internal/audit/events" || c.Request.URL.Path == "/internal/authorize/check"
	if !backchannel && c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead && c.Request.Method != http.MethodOptions {
		if origin := c.GetHeader("Origin"); (origin != "" && origin != s.origin) || c.GetHeader("Sec-Fetch-Site") == "cross-site" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "request origin is not allowed"})
			return
		}
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	c.Next()
}

func decodeJSON(c *gin.Context, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "Content-Type must be application/json"})
		return false
	}
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request must contain a single JSON object"})
		return false
	}
	return true
}

func serverError(c *gin.Context, err error) {
	log.Printf("%s %s: %v", c.Request.Method, c.FullPath(), err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
}

func respondError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, lib.ErrInvalidInput):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, lib.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, lib.ErrUnauthenticated), errors.Is(err, lib.ErrInvalidPasskey):
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	default:
		serverError(c, err)
	}
}
