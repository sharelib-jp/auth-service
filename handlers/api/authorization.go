package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/authorization"
)

func (h *oauthHandler) checkBusinessPolicy(c *gin.Context) {
	resource, ok := h.authenticateResource(c)
	if !ok {
		return
	}
	var input struct {
		Subject  uuid.UUID `json:"subject"`
		Resource string    `json:"resource"`
		Action   string    `json:"action"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	allowed, err := authorization.NewService(h.db).Check(c.Request.Context(), *resource, input.Subject, input.Resource, input.Action)
	if errors.Is(err, authorization.ErrInvalidPolicy) {
		c.JSON(http.StatusOK, gin.H{"allowed": false})
		return
	}
	if err != nil {
		serverError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"allowed": allowed})
}
