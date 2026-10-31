package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/internal/identity"
)

const (
	authCookie         = "sharelib_session"
	secureAuthCookie   = "__Host-sharelib_session"
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
	cookie := &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge, Expires: time.Now().Add(ttl),
	}
	http.SetCookie(c.Writer, cookie)
	if name == authCookie && s.secure {
		copy := *cookie
		copy.Name = secureAuthCookie
		http.SetCookie(c.Writer, &copy)
	}
}

func oauthSessionCookie(c *gin.Context, secure bool) string {
	if secure {
		return cookie(c, secureAuthCookie)
	}
	return cookie(c, authCookie)
}

func (s *handler) currentAuthCookie(c *gin.Context) string {
	if s.secure {
		if token := cookie(c, secureAuthCookie); token != "" {
			return token
		}
	}
	return cookie(c, authCookie)
}

func (s *handler) oauthSessionStatus(c *gin.Context) {
	_, err := s.service.Authenticate(c.Request.Context(), oauthSessionCookie(c, s.secure))
	if err != nil {
		if errors.Is(err, identity.ErrUnauthenticated) {
			c.Status(http.StatusUnauthorized)
		} else {
			serverError(c, err)
		}
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *handler) requireAuth(c *gin.Context) {
	token := s.currentAuthCookie(c)
	if token == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}
	user, err := s.service.Authenticate(c.Request.Context(), token)
	if err != nil {
		if errors.Is(err, identity.ErrUnauthenticated) {
			s.setCookie(c, authCookie, "", -time.Hour)
		}
		respondError(c, err)
		c.Abort()
		return
	}
	c.Set("user", user)
	c.Next()
}

func (s *handler) requireLogoutAuth(c *gin.Context) {
	if s.secure {
		user, err := s.service.Authenticate(c.Request.Context(), oauthSessionCookie(c, true))
		if err == nil {
			c.Set("user", user)
			c.Next()
			return
		}
		if !errors.Is(err, identity.ErrUnauthenticated) {
			respondError(c, err)
			c.Abort()
			return
		}
	}
	s.requireAuth(c)
}

func (s *handler) logout(c *gin.Context) {
	legacy, secure := cookie(c, authCookie), oauthSessionCookie(c, s.secure)
	if err := s.service.Logout(c.Request.Context(), legacy); err != nil {
		respondError(c, err)
		return
	}
	if secure != "" && secure != legacy {
		if err := s.service.Logout(c.Request.Context(), secure); err != nil {
			respondError(c, err)
			return
		}
	}
	s.setCookie(c, authCookie, "", -time.Hour)
	c.Status(http.StatusNoContent)
}
