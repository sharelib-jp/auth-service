// Package web serves the built frontend alongside the API.
package web

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// Register serves files from the Vite build and the entry point for SPA routes.
// API routes must be registered on the router before calling Register.
func Register(router *gin.Engine, distDir string) {
	pages := map[string]bool{
		"/": true, "/login": true, "/logout": true,
		"/me": true, "/me/consents": true,
		"/register": true, "/register/step1": true,
		"/register/step2": true, "/register/step3": true,
		"/oauth2/v1/auth": true,
	}

	router.NoRoute(func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			http.NotFound(c.Writer, c.Request)
			return
		}
		requestPath := c.Request.URL.Path
		for _, prefix := range []string{"/api", "/.well-known", "/internal"} {
			if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
				http.NotFound(c.Writer, c.Request)
				return
			}
		}

		name := strings.TrimPrefix(requestPath, "/")
		page := strings.TrimSuffix(requestPath, "/")
		if page == "" {
			page = "/"
		}
		if pages[page] {
			name = "index.html"
		}
		if !fs.ValidPath(name) {
			http.NotFound(c.Writer, c.Request)
			return
		}
		file, err := os.Open(filepath.Join(distDir, filepath.FromSlash(name)))
		if err != nil {
			http.NotFound(c.Writer, c.Request)
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(c.Writer, c.Request)
			return
		}

		c.Header("Content-Security-Policy", "frame-ancestors 'none'")
		c.Header("X-Frame-Options", "DENY")
		c.Status(http.StatusOK)
		http.ServeContent(c.Writer, c.Request, info.Name(), info.ModTime(), file)
	})
}
