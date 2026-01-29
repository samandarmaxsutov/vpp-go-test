package web

import (
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"vpp-go-test/internal/vpp"
)

// IPGroupsHandler handles IP groups operations
type IPGroupsHandler struct {
	Service *vpp.IPGroupsService
}

// NewIPGroupsHandler creates a new IP groups handler
func NewIPGroupsHandler(service *vpp.IPGroupsService) *IPGroupsHandler {
	return &IPGroupsHandler{Service: service}
}

// HandleGetGroups returns all IP groups for rendering on page
func (h *IPGroupsHandler) HandleGetGroups(c *gin.Context) {
	groups := h.Service.GetAll()

	c.JSON(http.StatusOK, gin.H{
		"groups": groups,
	})
}

// HandleCreateGroup creates a new IP group
func (h *IPGroupsHandler) HandleCreateGroup(c *gin.Context) {
	session := sessions.Default(c)

	var req struct {
		Name    string `json:"name" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	group, err := h.Service.Create(req.Name, req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("[%s] Created IP group: %s (ID: %s, %d entries)\n",
		session.Get("user_id"), group.Name, group.ID, group.Count)

	c.JSON(http.StatusOK, gin.H{
		"message": "Group created successfully",
		"group":   group,
	})
}

// HandleUpdateGroup updates an existing IP group
func (h *IPGroupsHandler) HandleUpdateGroup(c *gin.Context) {
	session := sessions.Default(c)

	var req struct {
		ID      string `json:"id" binding:"required"`
		Name    string `json:"name" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	group, err := h.Service.Update(req.ID, req.Name, req.Content)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("[%s] Updated IP group: %s (ID: %s, %d entries)\n",
		session.Get("user_id"), group.Name, group.ID, group.Count)

	c.JSON(http.StatusOK, gin.H{
		"message": "Group updated successfully",
		"group":   group,
	})
}

// HandleDeleteGroup deletes an IP group
func (h *IPGroupsHandler) HandleDeleteGroup(c *gin.Context) {
	session := sessions.Default(c)
	id := c.Param("id")

	group := h.Service.GetByID(id)
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	if err := h.Service.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("[%s] Deleted IP group: %s (ID: %s)\n",
		session.Get("user_id"), group.Name, group.ID)

	c.JSON(http.StatusOK, gin.H{
		"message": "Group deleted successfully",
	})
}

// HandleUploadFile handles file upload for bulk import
func (h *IPGroupsHandler) HandleUploadFile(c *gin.Context) {
	session := sessions.Default(c)

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided: " + err.Error()})
		return
	}

	name := c.PostForm("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Group name is required"})
		return
	}

	// Open the uploaded file
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open file: " + err.Error()})
		return
	}
	defer src.Close()

	// Import from file
	group, err := h.Service.ImportFromFile(name, src)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fmt.Printf("[%s] Imported IP group from file: %s (ID: %s, %d entries, %d invalid)\n",
		session.Get("user_id"), group.Name, group.ID, group.Count, len(group.Invalid))

	c.JSON(http.StatusOK, gin.H{
		"message": "Group imported successfully",
		"group":   group,
	})
}

// HandleDownloadGroup downloads a group as a text file
func (h *IPGroupsHandler) HandleDownloadGroup(c *gin.Context) {
	id := c.Param("id")

	content, err := h.Service.ExportToFile(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	group := h.Service.GetByID(id)
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", group.Name))
	c.String(http.StatusOK, content)
}

// HandleGetGroupByID returns a single group by ID
func (h *IPGroupsHandler) HandleGetGroupByID(c *gin.Context) {
	id := c.Param("id")

	group := h.Service.GetByID(id)
	if group == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Group not found"})
		return
	}

	c.JSON(http.StatusOK, group)
}

// HandleStats returns statistics about IP groups
func (h *IPGroupsHandler) HandleStats(c *gin.Context) {
	stats := h.Service.Stats()
	c.JSON(http.StatusOK, stats)
}
