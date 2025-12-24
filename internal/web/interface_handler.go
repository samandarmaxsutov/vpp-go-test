package web

import (
	"net/http"
	"fmt" 
	"vpp-go-test/internal/vpp"
	"github.com/gin-gonic/gin"
)

type InterfaceHandler struct {
	VPP *vpp.VPPClient
}

// ListInterfaces - Barcha interfeyslarni olish
func (h *InterfaceHandler) ListInterfaces(c *gin.Context) {
	ifList, err := h.VPP.GetInterfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ifList)
}

// SetState - Admin UP/DOWN holatini o'zgartirish
func (h *InterfaceHandler) SetState(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index"`
		IsUp  bool   `json:"is_up"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.VPP.SetInterfaceState(input.Index, input.IsUp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// AddIP - Interfeysga IP qo'shish
func (h *InterfaceHandler) AddIP(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index"`
		IP    string `json:"ip"` // masalan: 192.168.1.1/24
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.VPP.AddInterfaceIP(input.Index, input.IP); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SetDHCP - DHCP Clientni boshqarish
func (h *InterfaceHandler) SetDHCP(c *gin.Context) {
	var input struct {
		Index  uint32 `json:"index"`
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
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *InterfaceHandler) CreateInterface(c *gin.Context) {
	// Hozircha faqat loopback misolida
	index, err := h.VPP.CreateLoopback()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "created", "index": index})
}

func (h *InterfaceHandler) DeleteInterface(c *gin.Context) {
    var input struct {
        Index uint32 `json:"index"`
    }
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // VPP-da virtual interfeysni o'chirish
    err := h.VPP.DeleteInterface(input.Index)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func (h *InterfaceHandler) RemoveIP(c *gin.Context) {
	var input struct {
		Index uint32 `json:"index"`
		IP    string `json:"ip"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := h.VPP.DelInterfaceIP(input.Index, input.IP); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"status": "deleted"})
}

func (h *InterfaceHandler) GetStats(c *gin.Context) {
    // fmt.Println("--> Stats so'rovi boshlandi") 
    stats, err := h.VPP.GetGlobalStats()
    if err != nil {
        fmt.Println("Xato yuz berdi:", err)
        c.JSON(500, gin.H{"error": "Statistikani olib bo'lmadi: " + err.Error()})
        return
    }
    // fmt.Println("<-- Stats muvaffaqiyatli tayyor")
    c.JSON(200, stats)
}