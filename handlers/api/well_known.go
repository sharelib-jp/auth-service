package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

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

// BrandLogo serves the configured header image.
func (s *handler) BrandLogo(c *gin.Context) {
	path := s.service.BrandResources().HeaderPath()
	if path == "" {
		c.Status(http.StatusNotFound)
		return
	}
	var contentType string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".jpg", ".jpeg":
		contentType = "image/jpeg"
	case ".png":
		contentType = "image/png"
	case ".svg":
		contentType = "image/svg+xml"
	default:
		c.Status(http.StatusUnsupportedMediaType)
		return
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			c.Status(http.StatusNotFound)
		} else {
			serverError(c, err)
		}
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		serverError(c, err)
		return
	}
	if !info.Mode().IsRegular() {
		c.Status(http.StatusNotFound)
		return
	}
	c.Header("Content-Type", contentType)
	http.ServeContent(c.Writer, c.Request, info.Name(), info.ModTime(), file)
}
