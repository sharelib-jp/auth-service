package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/lib"
)

const (
	authCookie         = "sharelib_session"
	registrationCookie = "sharelib_registration"
	loginCookie        = "sharelib_login"
)

func cookie(c *gin.Context, name string) string {
	value, _ := c.Cookie(name)
	return value
}

func (s *handler) setCookie(c *gin.Context, name, value string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	if ttl < 0 {
		maxAge = -1
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: time.Now().Add(ttl),
	})
}

func (s *handler) requireAuth(c *gin.Context) {
	token, err := c.Cookie(authCookie)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	user, err := s.service.Authenticate(c.Request.Context(), token)
	if err != nil {
		if errors.Is(err, lib.ErrUnauthenticated) {
			s.setCookie(c, authCookie, "", -time.Hour)
		}
		respondError(c, err)
		c.Abort()
		return
	}
	c.Set("user", user)
	c.Next()
}

func (s *handler) logout(c *gin.Context) {
	if err := s.service.Logout(c.Request.Context(), cookie(c, authCookie)); err != nil {
		respondError(c, err)
		return
	}
	s.setCookie(c, authCookie, "", -time.Hour)
	c.Status(http.StatusNoContent)
}
