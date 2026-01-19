package web

import (
	"net/http"
	"vpp-go-test/internal/vpp/dhcp"
	"vpp-go-test/internal/vpp"
	"github.com/gin-gonic/gin"
	"strconv"
)

type DhcpHandler struct {
	VPP *vpp.VPPClient
}

// HandleGetProxies - GET /api/dhcp/proxies?ipv6=false
func (h *DhcpHandler) HandleGetProxies(c *gin.Context) {
	isIPv6 := c.Query("ipv6") == "true"
	proxies, err := h.VPP.DhcpManager.ListProxies(c.Request.Context(), isIPv6)
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

	err := h.VPP.DhcpManager.ConfigureProxy(c.Request.Context(), req.ServerIP, req.SrcIP, req.RxVrf, req.ServerVrf, req.IsAdd)
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

    err := h.VPP.DhcpManager.SetVSS(c.Request.Context(), req.VrfID, req.VssType, req.VpnID, req.Oui, req.VpnIndex, req.IsIPv6, req.IsAdd)
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

// // HandleGetLeases - GET /api/dhcp/leases
// func (h *DhcpHandler) HandleGetLeases(c *gin.Context) {
// 	leases, err := dhcp.GetKeaLeases()
// 	if err != nil {
// 		c.JSON(http.StatusInternalServerError, gin.H{"error": "Leaselarni o'qib bo'lmadi: " + err.Error()})
// 		return
// 	}
// 	c.JSON(http.StatusOK, leases)
// }

// HandleGetKeaConfig - GET /api/dhcp/kea-config
func (h *DhcpHandler) HandleGetKeaConfig(c *gin.Context) {
	conf, err := dhcp.GetKeaConfig()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kea dan ma'lumot olishda xato: " + err.Error()})
		return
	}
	if conf == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Konfiguratsiya topilmadi"})
		return
	}
	c.JSON(http.StatusOK, conf)
}

// HandleSaveKeaSubnet - POST /api/dhcp/kea-config
// Bu handler ham yangi qo'shish (Append), ham tahrirlash (Edit) uchun ishlaydi
func (h *DhcpHandler) HandleSaveKeaSubnet(c *gin.Context) {
	var req struct {
		ID      int    `json:"id"` // Agar 0 bo'lsa yangi qo'shadi, >0 bo'lsa tahrirlaydi
		Subnet  string `json:"subnet"`
		RelayIP string `json:"relay_ip"`
		Pool    string `json:"pool"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ma'lumotlar formati noto'g'ri"})
		return
	}

	// Yangi aqlli SaveKeaSubnet funksiyasini chaqiramiz
	err := dhcp.SaveKeaSubnet(req.ID, req.Subnet, req.RelayIP, req.Pool)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kea-ni saqlashda xatolik: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Kea konfiguratsiyasi muvaffaqiyatli saqlandi"})
}

// HandleDeleteKeaSubnet - DELETE /api/dhcp/kea-subnet/:id
func (h *DhcpHandler) HandleDeleteKeaSubnet(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri ID formati"})
		return
	}

	err = dhcp.DeleteKeaSubnet(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Subnetni o'chirishda xatolik: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Subnet muvaffaqiyatli o'chirildi"})
}