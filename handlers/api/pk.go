package api

import (
	"net/http"
	"time"

	"github.com/sharelib-jp/auth-service/lib"

	"github.com/gin-gonic/gin"
)

func (s *handler) beginRegistration(c *gin.Context) {
	var input lib.RegistrationInput
	if !decodeJSON(c, &input) {
		return
	}
	options, token, err := s.service.BeginRegistration(c.Request.Context(), input, cookie(c, registrationCookie))
	if err != nil {
		respondError(c, err)
		return
	}
	s.setCookie(c, registrationCookie, token, lib.CeremonyTTL)
	c.JSON(http.StatusOK, options)
}

func (s *handler) finishRegistration(c *gin.Context) {
	s.setCookie(c, registrationCookie, "", -time.Hour)
	user, token, err := s.service.FinishRegistration(c.Request.Context(), cookie(c, registrationCookie), s.currentAuthCookie(c), c.Request.Body)
	if err != nil {
		respondError(c, err)
		return
	}
	s.setCookie(c, authCookie, token, lib.AuthTTL)
	c.JSON(http.StatusCreated, userResponse(user))
}

func (s *handler) beginLogin(c *gin.Context) {
	options, token, err := s.service.BeginLogin(c.Request.Context(), cookie(c, loginCookie))
	if err != nil {
		respondError(c, err)
		return
	}
	s.setCookie(c, loginCookie, token, lib.CeremonyTTL)
	c.JSON(http.StatusOK, options)
}

func (s *handler) finishLogin(c *gin.Context) {
	s.setCookie(c, loginCookie, "", -time.Hour)
	user, token, err := s.service.FinishLogin(c.Request.Context(), cookie(c, loginCookie), s.currentAuthCookie(c), c.Request.Body)
	if err != nil {
		respondError(c, err)
		return
	}
	s.setCookie(c, authCookie, token, lib.AuthTTL)
	c.JSON(http.StatusOK, userResponse(user))
}
