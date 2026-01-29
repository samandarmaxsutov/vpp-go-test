package web

import (
	"encoding/json"
	"net/http"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/vpp/time_group"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type TimeGroupHandler struct {
	VPP *vpp.VPPClient
}

func NewTimeGroupHandler(vppClient *vpp.VPPClient) *TimeGroupHandler {
	return &TimeGroupHandler{VPP: vppClient}
}

// CreateTimeGroup - POST /api/time-groups
func (h *TimeGroupHandler) CreateTimeGroup(c *gin.Context) {
	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		StartTime   string   `json:"start_time" binding:"required"`
		EndTime     string   `json:"end_time" binding:"required"`
		Weekdays    []string `json:"weekdays" binding:"required,gt=0"`
		IsActive    bool     `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	tg := &time_group.TimeGroup{
		Name:        req.Name,
		Description: req.Description,
		StartTime:   req.StartTime,
		EndTime:     req.EndTime,
		Weekdays:    req.Weekdays,
		IsActive:    req.IsActive,
	}

	created, err := h.VPP.TimeGroupManager.CreateTimeGroup(c.Request.Context(), tg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE", "TIME_GROUP", string(details))

	c.JSON(http.StatusCreated, created)
}

// UpdateTimeGroup - PUT /api/time-groups/:id
func (h *TimeGroupHandler) UpdateTimeGroup(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		StartTime   string   `json:"start_time" binding:"required"`
		EndTime     string   `json:"end_time" binding:"required"`
		Weekdays    []string `json:"weekdays" binding:"required,gt=0"`
		IsActive    bool     `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	tg := &time_group.TimeGroup{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		StartTime:   req.StartTime,
		EndTime:     req.EndTime,
		Weekdays:    req.Weekdays,
		IsActive:    req.IsActive,
	}

	updated, err := h.VPP.TimeGroupManager.UpdateTimeGroup(c.Request.Context(), tg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "UPDATE", "TIME_GROUP", string(details))

	c.JSON(http.StatusOK, updated)
}

// GetTimeGroup - GET /api/time-groups/:id
func (h *TimeGroupHandler) GetTimeGroup(c *gin.Context) {
	id := c.Param("id")

	tg, err := h.VPP.TimeGroupManager.GetTimeGroup(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tg)
}

// ListTimeGroups - GET /api/time-groups
func (h *TimeGroupHandler) ListTimeGroups(c *gin.Context) {
	groups, err := h.VPP.TimeGroupManager.ListTimeGroups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if groups == nil {
		groups = []*time_group.TimeGroup{}
	}

	c.JSON(http.StatusOK, groups)
}

// DeleteTimeGroup - DELETE /api/time-groups/:id
func (h *TimeGroupHandler) DeleteTimeGroup(c *gin.Context) {
	id := c.Param("id")

	err := h.VPP.TimeGroupManager.DeleteTimeGroup(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	logger.LogConfigChange(user, c.ClientIP(), "DELETE", "TIME_GROUP", id)

	c.JSON(http.StatusOK, gin.H{"message": "O'chirildi"})
}

// GetTimeGroupStatus - GET /api/time-groups/:id/status
func (h *TimeGroupHandler) GetTimeGroupStatus(c *gin.Context) {
	id := c.Param("id")

	status, err := h.VPP.TimeGroupManager.GetStatus(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, status)
}

// AssignToRule - POST /api/time-groups/:id/assign
func (h *TimeGroupHandler) AssignToRule(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		RuleType string `json:"rule_type" binding:"required"` // ACL, ABF, POLICER
		RuleID   string `json:"rule_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	err := h.VPP.TimeGroupManager.AssignTimeGroupToRule(c.Request.Context(), req.RuleType, req.RuleID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "ASSIGN_TIME", "TIME_GROUP", string(details))

	c.JSON(http.StatusOK, gin.H{"message": "Tayinlandi"})
}

// UnassignFromRule - DELETE /api/time-groups/:id/assign
func (h *TimeGroupHandler) UnassignFromRule(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		RuleType string `json:"rule_type" binding:"required"`
		RuleID   string `json:"rule_id" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	err := h.VPP.TimeGroupManager.UnassignTimeGroupFromRule(c.Request.Context(), req.RuleType, req.RuleID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "UNASSIGN_TIME", "TIME_GROUP", string(details))

	c.JSON(http.StatusOK, gin.H{"message": "Olib tashlandi"})
}

// GetRuleAssignments - GET /api/time-groups/rule-assignments?rule_type=ACL&rule_id=123
func (h *TimeGroupHandler) GetRuleAssignments(c *gin.Context) {
	ruleType := c.Query("rule_type")
	ruleID := c.Query("rule_id")

	if ruleType == "" || ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type va rule_id majburiy"})
		return
	}

	groups, err := h.VPP.TimeGroupManager.GetRuleTimeAssignments(c.Request.Context(), ruleType, ruleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if groups == nil {
		groups = []*time_group.TimeGroup{}
	}

	c.JSON(http.StatusOK, groups)
}

// CheckRuleActive - GET /api/time-groups/check-rule?rule_type=ACL&rule_id=123
func (h *TimeGroupHandler) CheckRuleActive(c *gin.Context) {
	ruleType := c.Query("rule_type")
	ruleID := c.Query("rule_id")

	if ruleType == "" || ruleID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule_type va rule_id majburiy"})
		return
	}

	isActive, message, err := h.VPP.TimeGroupManager.CheckIfRuleActive(c.Request.Context(), ruleType, ruleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"is_active": isActive,
		"message":   message,
	})
}
