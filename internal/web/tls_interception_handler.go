package web

import (
	"fmt"
	"io"
	"net/http"

	"vpp-go-test/internal/vpp"

	"github.com/gin-gonic/gin"
)

type TLSInterceptionHandler struct {
	manager *vpp.TLSInterceptionManager
}

func NewTLSInterceptionHandler(vppClient *vpp.VPPClient) *TLSInterceptionHandler {
	return &TLSInterceptionHandler{
		manager: vpp.NewTLSInterceptionManager(vppClient),
	}
}

func (h *TLSInterceptionHandler) GetStatus(c *gin.Context) {
	status := h.manager.GetStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

func (h *TLSInterceptionHandler) GetSimpleStatus(c *gin.Context) {
	status := h.manager.GetSimpleStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

func (h *TLSInterceptionHandler) GetConfig(c *gin.Context) {
	config := h.manager.GetConfig()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    config,
	})
}

func (h *TLSInterceptionHandler) UpdateConfig(c *gin.Context) {
	var config vpp.TLSInterceptionConfig
	fmt.Println("  SUBNET REQUEST BODY:")
	fmt.Println(c.Request.Body)

	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid configuration: " + err.Error(),
		})
		return
	}

	if err := h.manager.UpdateConfig(c.Request.Context(), &config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration applied",
		"data":    h.manager.GetConfig(),
	})
}

func (h *TLSInterceptionHandler) Enable(c *gin.Context) {
	fmt.Println(" SUBNET enable is called ")
	// Pass nil to use the configuration already loaded in the manager
	if err := h.manager.Enable(c.Request.Context(), nil); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to enable TLS interception: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Traffic inspection enabled",
		"data":    h.manager.GetSimpleStatus(),
	})
}

func (h *TLSInterceptionHandler) Disable(c *gin.Context) {
	if err := h.manager.Disable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to disable TLS interception: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Traffic inspection disabled",
		"data":    h.manager.GetSimpleStatus(),
	})
}

func (h *TLSInterceptionHandler) GetCertificateInfo(c *gin.Context) {
	certInfo := h.manager.GetCertificateInfo()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    certInfo,
	})
}

// UploadCACert uploads combined key+cert PEM to fixed path /root/.mitmproxy/mitmproxy-ca.pem
// multipart field name: "certificate"
func (h *TLSInterceptionHandler) UploadCACert(c *gin.Context) {
	file, err := c.FormFile("certificate")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No certificate file provided (field name: certificate)",
		})
		return
	}

	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to open uploaded file",
		})
		return
	}
	defer f.Close()

	certData, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to read uploaded file",
		})
		return
	}

	if err := h.manager.UploadCACertificate(certData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "CA file uploaded to /root/.mitmproxy/mitmproxy-ca.pem",
		"data":    h.manager.GetCertificateInfo(),
	})
}
