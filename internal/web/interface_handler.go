package web

import (
	"net/http"
	"vpp-go-test/internal/vpp"
	"fmt"
	"github.com/gin-gonic/gin"
)

type InterfaceHandler struct {
	VPP *vpp.VPPClient
}

// ListInterfaces - Barcha jismoniy va virtual interfeyslarni olish
func (h *InterfaceHandler) ListInterfaces(c *gin.Context) {
	ifList, err := h.VPP.GetInterfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Interfeyslarni yuklashda xatolik: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, ifList)
}

// SetState - Admin UP/DOWN holatini o'zgartirish
func (h *InterfaceHandler) SetState(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		IsUp  bool   `json:"is_up"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri ma'lumot yuborildi"})
		return
	}
	if err := h.VPP.SetInterfaceState(input.Index, input.IsUp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "Interfeys holati o'zgartirildi"})
}

// SetTag - Interfeysga tavsiflovchi nom (alias) berish
func (h *InterfaceHandler) SetTag(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		Tag   string `json:"tag" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index va Tag bo'lishi shart"})
		return
	}
	if err := h.VPP.SetInterfaceTag(input.Index, input.Tag); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "tag": input.Tag})
}

// SetMAC - Interfeysning MAC manzilini dasturiy o'zgartirish
func (h *InterfaceHandler) SetMAC(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		MAC   string `json:"mac" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MAC manzil noto'g'ri"})
		return
	}
	if err := h.VPP.SetInterfaceMac(input.Index, input.MAC); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "mac": input.MAC})
}

// AddIP - Interfeysga yangi IPv4/v6 manzil qo'shish
func (h *InterfaceHandler) AddIP(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		IP    string `json:"ip" binding:"required"` // masalan: 10.0.0.1/24
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP va Maskani ko'rsating (CIDR)"})
		return
	}
	if err := h.VPP.AddInterfaceIP(input.Index, input.IP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// RemoveIP - Interfeysdan IP manzilni o'chirish
func (h *InterfaceHandler) RemoveIP(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		IP    string `json:"ip" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri parametrlar"})
		return
	}
	if err := h.VPP.DelInterfaceIP(input.Index, input.IP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SetDHCP - Interfeysda DHCP Client rejimini boshqarish
func (h *InterfaceHandler) SetDHCP(c *gin.Context) {
	var input struct {
		Index  uint32 `json:"index" binding:"required"`
		Enable bool   `json:"enable"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.VPP.SetInterfaceDHCP(input.Index, input.Enable); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "dhcp": input.Enable})
}

// CreateLoopback - Yangi virtual Loopback yaratish
func (h *InterfaceHandler) CreateLoopback(c *gin.Context) {
	index, err := h.VPP.CreateLoopback()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Loopback yaratib bo'lmadi"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "created", "index": index, "type": "loopback"})
}

// CreateVhostUser - VMlar uchun vhost-user socket port yaratish
func (h *InterfaceHandler) CreateVhostUser(c *gin.Context) {
	var input struct {
		SocketFile string `json:"socket_file" binding:"required"`
		IsServer   bool   `json:"is_server"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Socket fayl manzili kerak"})
		return
	}
	index, err := h.VPP.CreateVhostUser(input.SocketFile, input.IsServer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "created", "index": index, "type": "vhost-user"})
}

// DeleteInterface - Virtual interfeysni (loop/vhost) o'chirish
func (h *InterfaceHandler) DeleteInterface(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index" binding:"required"`
		Name  string `json:"name" binding:"required"` // 'loop0' yoki 'vhost0' kabi
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index va Name (turini aniqlash uchun) shart"})
		return
	}

	if err := h.VPP.DeleteInterface(input.Index, input.Name); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted", "index": input.Index})
}

// GetStats - Global interfeys statistikalarini olish
func (h *InterfaceHandler) GetStats(c *gin.Context) {
	stats, err := h.VPP.GetGlobalStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Statistikani yuklash xatosi"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

func (h *InterfaceHandler) CreateTap(c *gin.Context) {
    var input struct {
        ID       uint32 `json:"id"`
        HostName string `json:"host_name"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(400, gin.H{"error": "Noto'g'ri ma'lumot yuborildi"})
        return
    }

    // Agar ID yuborilmagan bo'lsa, auto-assign (0xffffffff) qilish mumkin
    if input.ID == 0 {
        input.ID = 4294967295 // ^uint32(0)
    }

    if input.HostName == "" {
        input.HostName = "vpp-tap0"
    }

    index, err := h.VPP.CreateTap(input.ID, input.HostName)
    if err != nil {
        c.JSON(500, gin.H{"error": fmt.Sprintf("VPPda TAP yaratishda xato: %v", err)})
        return
    }

    c.JSON(200, gin.H{
        "status":      "success",
        "index":       index,
        "kernel_name": input.HostName,
    })
}


// CreateVlan - Fizik interfeys ustida VLAN sub-interfeys yaratish
func (h *InterfaceHandler) CreateVlan(c *gin.Context) {
    var input struct {
        ParentIndex uint32 `json:"parent_index" binding:"required"`
        VlanID      uint32 `json:"vlan_id" binding:"required"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Parent Index va VLAN ID (0-4094) talab qilinadi"})
        return
    }

    index, err := h.VPP.CreateVlanSubif(input.ParentIndex, input.VlanID)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "VLAN yaratishda xato: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "status": "created",
        "index":  index,
        "type":   "vlan_subif",
        "vlan":   input.VlanID,
    })
}