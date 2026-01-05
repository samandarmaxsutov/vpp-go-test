package web

import (
	"net/http"
	"vpp-go-test/internal/vpp/dhcp"
	"github.com/gin-gonic/gin"
)

type DhcpHandler struct {
	DhcpMgr *dhcp.DhcpManager
}

// HandleGetProxies - GET /api/dhcp/proxies?ipv6=false
func (h *DhcpHandler) HandleGetProxies(c *gin.Context) {
	isIPv6 := c.Query("ipv6") == "true"
	proxies, err := h.DhcpMgr.ListProxies(c.Request.Context(), isIPv6)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, proxies)
}

// HandleConfigureProxy - POST /api/dhcp/proxy
func (h *DhcpHandler) HandleConfigureProxy(c *gin.Context) {
	var req struct {
		ServerIP  string `json:"server_ip"`
		SrcIP     string `json:"src_ip"`
		RxVrf     uint32 `json:"rx_vrf"`
		ServerVrf uint32 `json:"server_vrf"`
		IsAdd     bool   `json:"is_add"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	err := h.DhcpMgr.ConfigureProxy(c.Request.Context(), req.ServerIP, req.SrcIP, req.RxVrf, req.ServerVrf, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Proxy configuration updated"})
}

// HandleSetVSS - POST /api/dhcp/vss
func (h *DhcpHandler) HandleSetVSS(c *gin.Context) {
    var req struct {
        VrfID    uint32 `json:"vrf_id"`
        VssType  uint8  `json:"vss_type"`
        VpnID    string `json:"vpn_id"`
        Oui      uint32 `json:"oui"`
        VpnIndex uint32 `json:"vpn_index"`
        IsIPv6   bool   `json:"is_ipv6"`
        IsAdd    bool   `json:"is_add"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    err := h.DhcpMgr.SetVSS(c.Request.Context(), req.VrfID, req.VssType, req.VpnID, req.Oui, req.VpnIndex, req.IsIPv6, req.IsAdd)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "VSS configuration updated"})
}

// Add to internal/web/dhcp_handler.go
func (h *DhcpHandler) HandleGetLeases(c *gin.Context) {
    leases, err := dhcp.GetKeaLeases()
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read leases: " + err.Error()})
        return
    }
    c.JSON(http.StatusOK, leases)
}	