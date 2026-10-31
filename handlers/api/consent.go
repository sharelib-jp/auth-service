package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sharelib-jp/auth-service/internal/consent"
	"github.com/sharelib-jp/auth-service/internal/identity"
	"github.com/sharelib-jp/auth-service/internal/oauth"
	"gorm.io/gorm"
)

func (s *handler) listConsents(c *gin.Context) {
	grants, err := s.consents.List(c.Request.Context(), c.MustGet("user").(*identity.User).ID)
	if err != nil {
		serverError(c, err)
		return
	}
	type displayedGrant struct {
		consent.Grant
		ClientName        string            `json:"client_name"`
		ResourceName      string            `json:"resource_name"`
		ScopeDescriptions map[string]string `json:"scope_descriptions"`
	}
	clientIDs, identifiers, scopeNames := []string{}, []string{}, []string{}
	for _, grant := range grants {
		clientIDs = append(clientIDs, grant.ClientID)
		identifiers = append(identifiers, grant.Resource)
		scopeNames = append(scopeNames, grant.Scopes...)
	}
	var clients []oauth.Client
	var resources []oauth.Resource
	var scopes []oauth.Scope
	db := s.db.WithContext(c.Request.Context())
	if len(grants) > 0 {
		if err := db.Select("id", "name").Where("id IN ?", clientIDs).Find(&clients).Error; err != nil {
			serverError(c, err)
			return
		}
		if err := db.Select("id", "identifier", "name").Where("identifier IN ?", identifiers).Find(&resources).Error; err != nil {
			serverError(c, err)
			return
		}
		if err := db.Select("name", "description", "resource_id", "purpose_code", "policy_version").Where("name IN ?", scopeNames).Find(&scopes).Error; err != nil {
			serverError(c, err)
			return
		}
	}
	clientNames := make(map[string]string, len(clients))
	for _, client := range clients {
		clientNames[client.ID] = client.Name
	}
	resourceByIdentifier := make(map[string]oauth.Resource, len(resources))
	for _, resource := range resources {
		resourceByIdentifier[resource.Identifier] = resource
	}
	scopeByName := make(map[string]oauth.Scope, len(scopes))
	for _, scope := range scopes {
		scopeByName[scope.Name] = scope
	}
	result := make([]displayedGrant, 0, len(grants))
	for _, grant := range grants {
		item := displayedGrant{Grant: grant, ClientName: clientNames[grant.ClientID], ScopeDescriptions: make(map[string]string)}
		if item.ClientName == "" {
			item.ClientName = grant.ClientID
		}
		resource := resourceByIdentifier[grant.Resource]
		item.ResourceName = resource.Name
		if grant.Resource == oauth.IdentityResource {
			item.ResourceName = "アカウント情報"
		}
		if item.ResourceName == "" {
			item.ResourceName = grant.Resource
		}
		for _, name := range grant.Scopes {
			if grant.Resource == oauth.IdentityResource {
				if scope, ok := oauth.IdentityScope(name); ok && scope.PolicyVersion == grant.PolicyVersion && scope.PurposeCode == grant.PurposeCode {
					item.ScopeDescriptions[name] = scope.Description
				}
			} else if scope, ok := scopeByName[name]; ok && resource.ID != "" && scope.ResourceID == resource.ID && scope.PolicyVersion == grant.PolicyVersion && scope.PurposeCode == grant.PurposeCode {
				item.ScopeDescriptions[name] = scope.Description
			}
		}
		result = append(result, item)
	}
	c.JSON(http.StatusOK, result)
}

func (s *handler) getConsent(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	grant, err := s.consents.Get(c.Request.Context(), c.MustGet("user").(*identity.User).ID, id)
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
	err = s.consents.Revoke(c.Request.Context(), c.MustGet("user").(*identity.User).ID, id)
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
