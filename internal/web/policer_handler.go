package web

import (
	"fmt"
	"net/http"
	"strconv"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"

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
	c.JSON(http.StatusOK, list)
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
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri indeks"})
		return
	}

	err = h.VPP.PolicerManager.DeletePolicer(c.Request.Context(), uint32(index))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "DELETE_POLICER", fmt.Sprintf("Index: %d", index), "Deleted")

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
