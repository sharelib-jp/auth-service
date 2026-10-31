package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/internal/identity"
)

func userResponse(user *identity.User) any {
	formatted, _ := identity.FormatLibraryId(user.LibraryId)
	barcode, _ := identity.LibraryBarcode(user.LibraryId)
	return struct {
		*identity.User
		LibraryIdFormatted string `json:"LibraryIdFormatted"`
		Barcode            string `json:"Barcode"`
	}{user, formatted, barcode}
}

func (s *handler) getUser(c *gin.Context) {
	c.JSON(http.StatusOK, userResponse(c.MustGet("user").(*identity.User)))
}

func (s *handler) getBarcode(c *gin.Context) {
	svg, err := identity.LibraryBarcodeSVG(c.MustGet("user").(*identity.User).LibraryId)
	if err != nil {
		serverError(c, err)
		return
	}
	c.Data(http.StatusOK, "image/svg+xml; charset=utf-8", []byte(svg))
}

func (s *handler) updateUserName(c *gin.Context) {
	var input struct {
		UserName string `json:"UserName"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateUserName(c.Request.Context(), c.MustGet("user").(*identity.User).ID, input.UserName)
	respondUser(c, user, err)
}

func (s *handler) updateName(c *gin.Context) {
	var input struct {
		Name string `json:"Name"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateName(c.Request.Context(), c.MustGet("user").(*identity.User).ID, input.Name)
	respondUser(c, user, err)
}

func (s *handler) updateEmail(c *gin.Context) {
	var input struct {
		Email string `json:"Email"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateEmail(c.Request.Context(), c.MustGet("user").(*identity.User).ID, input.Email)
	respondUser(c, user, err)
}

func respondUser(c *gin.Context, user *identity.User, err error) {
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, userResponse(user))
}
