package web

import (
	"fmt"
	"net/http"
	"strconv"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/vpp/policer"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type PolicerHandler struct {
	VPP *vpp.VPPClient
}

func NewPolicerHandler(vppClient *vpp.VPPClient) *PolicerHandler {
	return &PolicerHandler{VPP: vppClient}
}

// HandleListPolicers - GET /api/policer/policies
func (h *PolicerHandler) HandleListPolicers(c *gin.Context) {
	list, err := h.VPP.PolicerManager.ListPolicers(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Enhance with time group info and status
	type PolicerWithStatus struct {
		Name          string                     `json:"name"`
		Cir           uint32                     `json:"cir"`
		Cb            uint64                     `json:"cb"`
		Eir           uint32                     `json:"eir"`
		Eb            uint64                     `json:"eb"`
		Bindings      []policer.InterfaceBinding `json:"bindings"`
		TimeGroupName string                     `json:"time_group_name"`
		TimeGroupID   string                     `json:"time_group_id"`
		IsActive      bool                       `json:"is_active"`
		StatusMessage string                     `json:"status_message"`
	}

	enhancedList := make([]PolicerWithStatus, 0, len(list))
	for _, p := range list {
		enhanced := PolicerWithStatus{
			Name:          p.Name,
			Cir:           p.Cir,
			Cb:            p.Cb,
			Eir:           p.Eir,
			Eb:            p.Eb,
			Bindings:      h.VPP.PolicerManager.GetBindingsForPolicer(p.Name),
			TimeGroupName: "-",
			TimeGroupID:   "",
			IsActive:      true,
			StatusMessage: "Har doim faol",
		}

		// Get time group assignments
		groups, _ := h.VPP.TimeGroupManager.GetRuleTimeAssignments(c.Request.Context(), "POLICER", p.Name)
		if len(groups) > 0 {
			enhanced.TimeGroupName = groups[0].Name
			enhanced.TimeGroupID = groups[0].ID

			// Check if currently active
			isActive, statusMsg, _ := h.VPP.TimeGroupManager.CheckIfRuleActive(c.Request.Context(), "POLICER", p.Name)
			enhanced.IsActive = isActive
			enhanced.StatusMessage = statusMsg
		}

		enhancedList = append(enhancedList, enhanced)
	}

	c.JSON(http.StatusOK, enhancedList)
}

// HandleCreatePolicer - POST /api/policer/policy
func (h *PolicerHandler) HandleCreatePolicer(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
		Cir  uint32 `json:"cir" binding:"required"`
		Cb   uint64 `json:"cb" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ma'lumotlar xato yuborildi"})
		return
	}

	// BU YERDA O'ZGARISh: index va err qabul qilinadi
	index, err := h.VPP.PolicerManager.AddPolicer(c.Request.Context(), req.Name, req.Cir, req.Cb)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE_POLICER", req.Name, fmt.Sprintf("CIR: %d, CB: %d", req.Cir, req.Cb))

	// Muvaffaqiyatli bo'lsa, yaratilgan policer indeksini ham qaytarish yaxshi amaliyot
	c.JSON(http.StatusOK, gin.H{
		"message": "Policer muvaffaqiyatli yaratildi",
		"index":   index,
	})
}

// HandleDeletePolicer - DELETE /api/policer/policy/:index
func (h *PolicerHandler) HandleDeletePolicer(c *gin.Context) {
	indexStr := c.Param("index")
	if index, err := strconv.ParseUint(indexStr, 10, 32); err == nil {
		err = h.VPP.PolicerManager.DeletePolicer(c.Request.Context(), uint32(index))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		// Allow delete by name (UI uses policer name, VPP API supports name-based delete via PolicerAddDel)
		err = h.VPP.PolicerManager.DeletePolicerByName(c.Request.Context(), indexStr)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "DELETE_POLICER", fmt.Sprintf("ID: %s", indexStr), "Deleted")

	c.JSON(http.StatusOK, gin.H{"message": "Policer o'chirildi"})
}

func (h *PolicerHandler) HandleBindInterface(c *gin.Context) {
	var req struct {
		PolicerName string `json:"policer_name" binding:"required"`
		SwIfIndex   uint32 `json:"sw_if_index"`
		Direction   string `json:"direction"` // "input" yoki "output"
		Apply       bool   `json:"apply"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Yo'nalishni tekshirish
	if req.Direction == "" {
		req.Direction = "input"
	}

	err := h.VPP.PolicerManager.BindToInterface(c.Request.Context(), req.PolicerName, req.SwIfIndex, req.Direction, req.Apply)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "BIND_POLICER", req.PolicerName, fmt.Sprintf("Interface: %d, Dir: %s, Apply: %v", req.SwIfIndex, req.Direction, req.Apply))

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Policer %s yo'nalishda bog'landi", req.Direction)})
}
