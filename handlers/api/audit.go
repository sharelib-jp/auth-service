package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/audit"
	"github.com/sharelib-jp/auth-service/internal/identity"
)

func (h *oauthHandler) receiveAuditEvent(c *gin.Context) {
	resource, ok := h.authenticateResource(c)
	if !ok {
		return
	}
	var input struct {
		EventID      string    `json:"event_id"`
		Subject      uuid.UUID `json:"subject"`
		ClientID     string    `json:"client_id"`
		Resource     string    `json:"resource"`
		Action       string    `json:"action"`
		DataCategory string    `json:"data_category"`
		Result       string    `json:"result"`
		OccurredAt   time.Time `json:"occurred_at"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	err := audit.NewService(h.db).Record(c.Request.Context(), audit.Source{ID: resource.ID, Identifier: resource.Identifier, Status: resource.Status}, audit.Event{EventID: input.EventID, Subject: input.Subject, ClientID: input.ClientID, Resource: input.Resource, Action: input.Action, DataCategory: input.DataCategory, Result: input.Result, OccurredAt: input.OccurredAt})
	switch {
	case errors.Is(err, audit.ErrInvalidEvent):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event"})
	case errors.Is(err, audit.ErrDuplicateConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "event ID already used"})
	case err != nil:
		serverError(c, err)
	default:
		c.Status(http.StatusAccepted)
	}
}

func (s *handler) listAccessEvents(c *gin.Context) {
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			c.Status(http.StatusBadRequest)
			return
		}
		limit = value
	}
	events, err := s.audit.List(c.Request.Context(), c.MustGet("user").(*identity.User).ID, limit, c.Query("cursor"))
	if errors.Is(err, audit.ErrInvalidEvent) {
		c.Status(http.StatusBadRequest)
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, events)
}

func (s *handler) listSecurityEvents(c *gin.Context) {
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			c.Status(http.StatusBadRequest)
			return
		}
		limit = value
	}
	events, err := s.audit.ListSecurity(c.Request.Context(), c.MustGet("user").(*identity.User).ID, limit, c.Query("cursor"))
	if errors.Is(err, audit.ErrInvalidEvent) {
		c.Status(http.StatusBadRequest)
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, events)
}
