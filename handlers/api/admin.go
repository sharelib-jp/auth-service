package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
)

func (s *handler) requireAdmin(c *gin.Context) {
	if !c.MustGet("user").(*identity.User).IsAdmin() {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": identity.ErrForbidden.Error()})
		return
	}
	c.Next()
}

func (s *handler) registerAdminRoutes(api *gin.RouterGroup) {
	admin := api.Group("/admin", s.requireAuth, s.requireAdmin)
	admin.GET("/users", s.listUsers)
	admin.GET("/users/:id", s.adminUser)
	admin.PATCH("/users/:id", s.adminUpdateUser)
	admin.GET("/roles", s.listRoles)
	admin.POST("/roles", s.createRole)
	admin.PATCH("/roles/:id", s.updateRole)
	admin.DELETE("/roles/:id", s.deleteRole)
	if s.db != nil {
		admin.GET("/oauth/clients", s.listOAuthClients)
		admin.GET("/oauth/clients/:id", s.getOAuthClient)
		admin.POST("/oauth/clients", s.createOAuthClient)
		admin.PUT("/oauth/clients/:id", s.updateOAuthClient)
		admin.PATCH("/oauth/clients/:id/status", s.oauthClientStatus)
	}
}

func (s *handler) listUsers(c *gin.Context) {
	limit, err := strconv.Atoi(c.DefaultQuery("limit", "25"))
	if err != nil {
		respondError(c, identity.ErrInvalidInput)
		return
	}
	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil {
		respondError(c, identity.ErrInvalidInput)
		return
	}
	page, err := s.service.ListUsers(c.Request.Context(), c.Query("q"), limit, offset)
	if err != nil {
		respondError(c, err)
		return
	}
	items := make([]any, len(page.Items))
	for i := range page.Items {
		items[i] = userResponse(&page.Items[i])
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": page.Total})
}

func userIDParam(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil || id == uuid.Nil {
		respondError(c, identity.ErrInvalidInput)
		return uuid.Nil, false
	}
	return id, true
}

func (s *handler) adminUser(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}
	user, err := s.service.AdminUser(c.Request.Context(), id)
	respondUser(c, user, err)
}

func (s *handler) adminUpdateUser(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}
	var input identity.AdminUserUpdate
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateAdminUser(c.Request.Context(), c.MustGet("user").(*identity.User).ID, id, input)
	respondUser(c, user, err)
}

func (s *handler) listRoles(c *gin.Context) {
	roles, err := s.service.ListRoles(c.Request.Context())
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": roles})
}

func (s *handler) createRole(c *gin.Context) {
	var role identity.Role
	if !decodeJSON(c, &role) {
		return
	}
	if err := s.service.SaveRole(c.Request.Context(), role, true); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusCreated)
}

func (s *handler) updateRole(c *gin.Context) {
	var input struct {
		Name string `json:"name"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	if err := s.service.SaveRole(c.Request.Context(), identity.Role{ID: c.Param("id"), Name: input.Name}, false); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (s *handler) deleteRole(c *gin.Context) {
	if err := s.service.DeleteRole(c.Request.Context(), c.Param("id")); err != nil {
		respondError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// This DTO deliberately excludes stored credential hashes.
type oauthClientInput struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Public       bool     `json:"public"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	Audience     []string `json:"audience"`
	Secret       string   `json:"secret,omitempty"`
}

type oauthClientResponse struct {
	*oauthClientInput
	Status string `json:"status"`
}

func clientResponse(client oauth.Client) oauthClientResponse {
	return oauthClientResponse{&oauthClientInput{ID: client.ID, Name: client.Name, Public: client.Public,
		RedirectURIs: client.RedirectURIs, GrantTypes: client.GrantTypes, Scopes: client.Scopes, Audience: client.Audience}, client.Status}
}

func (s *handler) listOAuthClients(c *gin.Context) {
	clients := []oauth.Client{}
	if err := s.db.WithContext(c.Request.Context()).Omit("secret_hash").Order("id").Find(&clients).Error; err != nil {
		serverError(c, err)
		return
	}
	items := make([]oauthClientResponse, len(clients))
	for i, client := range clients {
		items[i] = clientResponse(client)
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *handler) getOAuthClient(c *gin.Context) {
	var client oauth.Client
	if err := s.db.WithContext(c.Request.Context()).Omit("secret_hash").First(&client, "id = ?", c.Param("id")).Error; err != nil {
		respondCatalogError(c, err)
		return
	}
	c.JSON(http.StatusOK, clientResponse(client))
}

func (s *handler) createOAuthClient(c *gin.Context) { s.saveOAuthClient(c, false) }
func (s *handler) updateOAuthClient(c *gin.Context) { s.saveOAuthClient(c, true) }

func (s *handler) saveOAuthClient(c *gin.Context, update bool) {
	var input oauthClientInput
	if !decodeJSON(c, &input) {
		return
	}
	if update && input.ID != c.Param("id") {
		respondError(c, identity.ErrInvalidInput)
		return
	}
	client := oauth.Client{ID: input.ID, Name: input.Name, Public: input.Public, RedirectURIs: input.RedirectURIs, GrantTypes: input.GrantTypes, Scopes: input.Scopes, Audience: input.Audience}
	catalog := oauth.NewCatalog(s.db)
	var err error
	if update {
		err = catalog.UpdateClient(c.Request.Context(), client, input.Secret)
	} else {
		err = catalog.RegisterClient(c.Request.Context(), client, input.Secret)
	}
	if err != nil {
		respondCatalogError(c, err)
		return
	}
	status := http.StatusCreated
	if update {
		status = http.StatusNoContent
	}
	c.Status(status)
}

func (s *handler) oauthClientStatus(c *gin.Context) {
	var input struct {
		Status string `json:"status"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	if err := oauth.NewCatalog(s.db).SetStatus(c.Request.Context(), "client", c.Param("id"), input.Status); err != nil {
		respondCatalogError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func respondCatalogError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, oauth.ErrInvalidRegistration):
		respondError(c, identity.ErrInvalidInput)
	case errors.Is(err, gorm.ErrDuplicatedKey):
		respondError(c, identity.ErrConflict)
	case errors.Is(err, gorm.ErrRecordNotFound):
		respondError(c, identity.ErrNotFound)
	default:
		serverError(c, err)
	}
}
