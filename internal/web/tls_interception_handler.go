package web

import (
	"fmt"
	"net/http"

	"vpp-go-test/internal/vpp"

	"github.com/gin-gonic/gin"
)

// TLSInterceptionHandler handles TLS interception API endpoints
type TLSInterceptionHandler struct {
	manager *vpp.TLSInterceptionManager
}

// NewTLSInterceptionHandler creates a new TLS interception handler
func NewTLSInterceptionHandler(vppClient *vpp.VPPClient) *TLSInterceptionHandler {
	return &TLSInterceptionHandler{
		manager: vpp.NewTLSInterceptionManager(vppClient),
	}
}

// GetStatus returns the current TLS interception status
// GET /api/tls-interception/status
func (h *TLSInterceptionHandler) GetStatus(c *gin.Context) {
	status := h.manager.GetStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

// GetSimpleStatus returns user-friendly status (hides technical details)
// GET /api/tls-interception/simple-status
func (h *TLSInterceptionHandler) GetSimpleStatus(c *gin.Context) {
	status := h.manager.GetSimpleStatus()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

// GetLogs returns recent TLS inspection logs
// GET /api/tls-interception/logs
func (h *TLSInterceptionHandler) GetLogs(c *gin.Context) {
	lines := 50
	if l := c.Query("lines"); l != "" {
		var n int
		if _, err := fmt.Sscanf(l, "%d", &n); err == nil && n > 0 {
			lines = n
		}
	}

	logs, err := h.manager.GetInspectionLogs(lines)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to get logs: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    logs,
	})
}

// GetConfig returns the current TLS interception configuration
// GET /api/tls-interception/config
func (h *TLSInterceptionHandler) GetConfig(c *gin.Context) {
	config := h.manager.GetConfig()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    config,
	})
}

// UpdateConfig updates the TLS interception configuration
// PUT /api/tls-interception/config
func (h *TLSInterceptionHandler) UpdateConfig(c *gin.Context) {
	var config vpp.TLSInterceptionConfig
	if err := c.ShouldBindJSON(&config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid configuration: " + err.Error(),
		})
		return
	}

	h.manager.SetConfig(&config)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration updated",
		"data":    config,
	})
}

// Enable enables TLS interception with current or provided configuration
// POST /api/tls-interception/enable
func (h *TLSInterceptionHandler) Enable(c *gin.Context) {
	var config *vpp.TLSInterceptionConfig

	// Check if config is provided in body
	if c.Request.ContentLength > 0 {
		var cfg vpp.TLSInterceptionConfig
		if err := c.ShouldBindJSON(&cfg); err == nil {
			config = &cfg
		}
	}

	if err := h.manager.Enable(c.Request.Context(), config); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to enable TLS interception: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "TLS interception enabled successfully",
		"data":    h.manager.GetStatus(),
	})
}

// Disable disables TLS interception
// POST /api/tls-interception/disable
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
		"message": "TLS interception disabled successfully",
		"data":    h.manager.GetStatus(),
	})
}

// GetVPPScript returns the generated VPP CLI script
// GET /api/tls-interception/scripts/vpp
func (h *TLSInterceptionHandler) GetVPPScript(c *gin.Context) {
	script := h.manager.GenerateVPPScript()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"type":    "vpp",
			"content": script,
		},
	})
}

// GetKernelScript returns the generated Linux kernel script
// GET /api/tls-interception/scripts/kernel
func (h *TLSInterceptionHandler) GetKernelScript(c *gin.Context) {
	script := h.manager.GenerateKernelScript()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"type":    "kernel",
			"content": script,
		},
	})
}

// GetMitmproxyCommand returns the mitmproxy command
// GET /api/tls-interception/scripts/mitmproxy
func (h *TLSInterceptionHandler) GetMitmproxyCommand(c *gin.Context) {
	cmd := h.manager.GenerateMitmproxyCommand()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"type":    "mitmproxy",
			"content": cmd,
		},
	})
}

// GetAllScripts returns all generated scripts
// GET /api/tls-interception/scripts
func (h *TLSInterceptionHandler) GetAllScripts(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"vpp":       h.manager.GenerateVPPScript(),
			"kernel":    h.manager.GenerateKernelScript(),
			"mitmproxy": h.manager.GenerateMitmproxyCommand(),
		},
	})
}

// SaveScripts saves all scripts to disk
// POST /api/tls-interception/scripts/save
func (h *TLSInterceptionHandler) SaveScripts(c *gin.Context) {
	var req struct {
		Directory string `json:"directory"`
	}

	baseDir := "/etc/sarhad-guard/tls-interception"
	if c.Request.ContentLength > 0 {
		if err := c.ShouldBindJSON(&req); err == nil && req.Directory != "" {
			baseDir = req.Directory
		}
	}

	if err := h.manager.SaveScriptsToFiles(baseDir); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to save scripts: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Scripts saved successfully",
		"data": gin.H{
			"directory": baseDir,
			"files": []string{
				baseDir + "/vpp_tls_setup.conf",
				baseDir + "/kernel_tls_setup.sh",
				baseDir + "/start_mitmproxy.sh",
			},
		},
	})
}

// GetInterfaces returns available interfaces for TLS interception
// GET /api/tls-interception/interfaces
func (h *TLSInterceptionHandler) GetInterfaces(c *gin.Context) {
	// This would need access to VPPClient - we'll get it from the manager
	// For now, return a placeholder
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Use /api/interfaces to get available interfaces",
	})
}

// GetCertificateInfo returns information about the mitmproxy CA certificate
// GET /api/tls-interception/certificates
func (h *TLSInterceptionHandler) GetCertificateInfo(c *gin.Context) {
	certInfo := h.manager.GetCertificateInfo()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    certInfo,
	})
}

// DownloadCACert returns the CA certificate for download
// GET /api/tls-interception/certificates/ca.pem
func (h *TLSInterceptionHandler) DownloadCACert(c *gin.Context) {
	certData, err := h.manager.GetCACertificate()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.Header("Content-Disposition", "attachment; filename=mitmproxy-ca-cert.pem")
	c.Header("Content-Type", "application/x-pem-file")
	c.Data(http.StatusOK, "application/x-pem-file", certData)
}

// UploadCACert uploads a CA certificate
// POST /api/tls-interception/certificates/upload
func (h *TLSInterceptionHandler) UploadCACert(c *gin.Context) {
	file, err := c.FormFile("certificate")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "No certificate file provided",
		})
		return
	}

	// Open the file
	f, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to open uploaded file",
		})
		return
	}
	defer f.Close()

	// Read file content
	certData := make([]byte, file.Size)
	if _, err := f.Read(certData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to read certificate file",
		})
		return
	}

	// Upload the certificate
	if err := h.manager.UploadCACertificate(certData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Certificate uploaded successfully",
	})
}
