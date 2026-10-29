package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/config"
)

func (s *handler) Nodeinfo(c *gin.Context) {
	metadata := s.service.Metadata()
	if metadata.NodeAdmins == nil {
		metadata.NodeAdmins = []config.Contact{}
	}
	if metadata.Maintainer == nil {
		metadata.Maintainer = []config.Contact{}
	}
	c.JSON(http.StatusOK, gin.H{"version": "0.1", "metadata": metadata})
}
