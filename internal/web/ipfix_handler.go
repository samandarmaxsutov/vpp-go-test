package web

import (
	"net/http"

	"fmt"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/vpp/ipfix"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type IpfixHandler struct {
	VPP	*vpp.VPPClient
}

func NewIpfixHandler(client *vpp.VPPClient) *IpfixHandler {
	return &IpfixHandler{
		VPP: client,
	}
}

// GET /api/ipfix
func (h *IpfixHandler) ShowSettings(c *gin.Context) {
	status, err := h.VPP.IpfixManager.GetExporterStatus(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusOK, ipfix.IpfixStatus{IsActive: false})
		return
	}
	c.JSON(http.StatusOK, status)
}

// POST /api/ipfix
func (h *IpfixHandler) SaveSettings(c *gin.Context) {
	var cfg ipfix.IpfixConfig

	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto‘g‘ri JSON"})
		return
	}

	if err := cfg.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.VPP.IpfixManager.SetExporter(c.Request.Context(), cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "SAVE_IPFIX_SETTINGS", fmt.Sprintf("Collector: %s:%d", cfg.CollectorAddress, cfg.CollectorPort), fmt.Sprintf("Src: %s, MTU: %d", cfg.SourceAddress, cfg.PathMtu))

	c.JSON(http.StatusOK, gin.H{"message": "IPFIX muvaffaqiyatli sozlandi"})
}

// POST /api/ipfix/flush
func (h *IpfixHandler) FlushFlows(c *gin.Context) {
	if err := h.VPP.IpfixManager.FlushIPFIX(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "FLUSH_IPFIX_FLOWS", "All Flows", "Flushed")

	c.JSON(http.StatusOK, gin.H{"message": "Flowlar yuborildi"})
}

// GET /api/ipfix/flowprobe
func (h *IpfixHandler) GetFlowprobe(c *gin.Context) {
	activeTimeout, recordL4, err := h.VPP.IpfixManager.GetFlowprobeParams(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"active_timeout": activeTimeout,
		"record_l4":      recordL4,
	})
}

// POST /api/ipfix/flowprobe
func (h *IpfixHandler) UpdateFlowprobe(c *gin.Context) {
	var cfg ipfix.FlowprobeParamsConfig

	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Xato parametrlar"})
		return
	}

	if err := h.VPP.IpfixManager.SetFlowprobeParams(
		c.Request.Context(),
		cfg.ActiveTimeout,
		cfg.RecordL4,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "UPDATE_FLOWPROBE", "Params", fmt.Sprintf("ActiveTimeout: %d, L4: %v", cfg.ActiveTimeout, cfg.RecordL4))

	c.JSON(http.StatusOK, gin.H{"message": "Flowprobe yangilandi"})
}

// POST /api/flow/interface
func (h *IpfixHandler) ToggleInterface(c *gin.Context) {
	var req ipfix.InterfaceToggleRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Xato interfeys ID"})
		return
	}

	if err := h.VPP.IpfixManager.InterfaceEnable(
		c.Request.Context(),
		req.SwIfIndex,
		req.Enable,
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "TOGGLE_IPFIX_INTERFACE", fmt.Sprintf("SwIfIndex: %d", req.SwIfIndex), fmt.Sprintf("Enable: %v", req.Enable))

	c.JSON(http.StatusOK, gin.H{"message": "Interfeys holati o‘zgartirildi"})
}

// GET /api/ipfix/interfaces/enabled
func (h *IpfixHandler) GetEnabledInterfaces(c *gin.Context) {
	ids, err := h.VPP.IpfixManager.GetEnabledInterfaces(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ids)
}
