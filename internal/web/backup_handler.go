// File: internal/web/backup_handler.go
package web

import (
	"net/http"
	"vpp-go-test/internal/vpp"

	"os"
	"github.com/gin-gonic/gin"
)

type BackupHandler struct {
	client *vpp.VPPClient
}

func NewBackupHandler(client *vpp.VPPClient) *BackupHandler {
	return &BackupHandler{client: client}
}

// SaveBackup - Manual backup trigger
func (h *BackupHandler) SaveBackup(c *gin.Context) {
	if err := h.client.SaveConfiguration(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Failed to save backup: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration backed up successfully",
	})
}

// RestoreBackup - Manual restore trigger
func (h *BackupHandler) RestoreBackup(c *gin.Context) {
	if err := h.client.RestoreConfiguration(); err != nil {
		// Try legacy format
		if err2 := h.client.RestoreFromRawJSON(); err2 != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "Restore failed: " + err.Error() + " | Legacy: " + err2.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Configuration restored from legacy backup",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Configuration restored successfully",
	})
}

// GetBackupStatus - Check if backup exists
func (h *BackupHandler) GetBackupStatus(c *gin.Context) {
	// Check if backup file exists
	const backupPath = "/etc/sarhad-guard/backup/vpp_config.json"
	
	// Simple file existence check
	exists := false
	if _, err := os.Stat(backupPath); err == nil {
		exists = true
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"backup_exists": exists,
		"backup_path":   backupPath,
	})
}