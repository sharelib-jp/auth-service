package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sharelib-jp/auth-service/models"
)

func userResponse(user *models.User) any {
	formatted, _ := models.FormatLibraryId(user.LibraryId)
	barcode, _ := models.LibraryBarcode(user.LibraryId)
	return struct {
		*models.User
		LibraryIdFormatted string `json:"LibraryIdFormatted"`
		Barcode            string `json:"Barcode"`
	}{user, formatted, barcode}
}

func (s *handler) getUser(c *gin.Context) {
	c.JSON(http.StatusOK, userResponse(c.MustGet("user").(*models.User)))
}

func (s *handler) getBarcode(c *gin.Context) {
	svg, err := models.LibraryBarcodeSVG(c.MustGet("user").(*models.User).LibraryId)
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
	user, err := s.service.UpdateUserName(c.Request.Context(), c.MustGet("user").(*models.User).ID, input.UserName)
	respondUser(c, user, err)
}

func (s *handler) updateName(c *gin.Context) {
	var input struct {
		Name string `json:"Name"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateName(c.Request.Context(), c.MustGet("user").(*models.User).ID, input.Name)
	respondUser(c, user, err)
}

func (s *handler) updateEmail(c *gin.Context) {
	var input struct {
		Email string `json:"Email"`
	}
	if !decodeJSON(c, &input) {
		return
	}
	user, err := s.service.UpdateEmail(c.Request.Context(), c.MustGet("user").(*models.User).ID, input.Email)
	respondUser(c, user, err)
}

func respondUser(c *gin.Context, user *models.User, err error) {
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, userResponse(user))
}
