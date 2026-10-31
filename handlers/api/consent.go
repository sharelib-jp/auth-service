package api

import (
	"errors"
	"net/http"

	"github.com/sharelib-jp/auth-service/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"gorm.io/gorm"
)

func (s *handler) listConsents(c *gin.Context) {
	grants, err := s.consents.List(c.Request.Context(), c.MustGet("user").(*models.User).ID)
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, grants)
}

func (s *handler) getConsent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	grant, err := s.consents.Get(c.Request.Context(), c.MustGet("user").(*models.User).ID, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, grant)
}

func (s *handler) revokeConsent(c *gin.Context) {
	// Require an explicit same-origin browser request for this cookie-authenticated operation.
	if c.GetHeader("Origin") != s.origin {
		c.Status(http.StatusForbidden)
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	err = s.consents.Revoke(c.Request.Context(), c.MustGet("user").(*models.User).ID, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		c.Status(http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
