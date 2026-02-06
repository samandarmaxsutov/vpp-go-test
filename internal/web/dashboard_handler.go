package web

import (
	"net/http"
	
	"github.com/gin-gonic/gin"
	"vpp-go-test/internal/vpp"
)



// GetStats - Global interfeys statistikalarini olish
func (h *InterfaceHandler) GetStats(c *gin.Context) {
	stats, err := h.VPP.GetGlobalStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Statistikani yuklash xatosi"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// The Handler Function
func (h *InterfaceHandler) GetStatsHistory(c *gin.Context) {
    if vpp.StatsHistory == nil {
        c.JSON(500, gin.H{"error": "Collector not initialized"})
        return
    }
    history := vpp.StatsHistory.GetHistory()
    c.JSON(200, history)
}