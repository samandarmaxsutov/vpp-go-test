package web

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"vpp-go-test/internal/vpp"
)

type RoutingHandler struct {
	VPP *vpp.VPPClient
}

// GetRoutes - Marshrutlarni olish
func (h *RoutingHandler) GetRoutes(c *gin.Context) {
	fmt.Println("API: GetRoutes chaqirildi...")
	routes, err := h.VPP.GetRoutingTable()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	fmt.Printf("Topilgan marshrutlar soni: %d\n", len(routes))
	c.JSON(200, routes)
}

func (h *RoutingHandler) CreateRoute(c *gin.Context) {
	var input struct {
		Destination string `json:"destination"` // Masalan: "1.1.1.1/32"
		Gateway     string `json:"gateway"`     // Masalan: "192.168.6.2"
		Interface   uint32 `json:"sw_if_index"`
	}

	fmt.Printf("KELGAN MA'LUMOT: %+v\n", input)

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": "Ma'lumotlar xato"})
		return
	}

	err := h.VPP.AddStaticRoute(input.Destination, input.Gateway, input.Interface)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "Marshrut muvaffaqiyatli qo'shildi"})
}

func (h *RoutingHandler) DeleteRoute(c *gin.Context) {
	prefix := c.Query("prefix") // URL orqali keladi: /api/routes?prefix=10.10.10.0/24
	if prefix == "" {
		c.JSON(400, gin.H{"error": "Prefix ko'rsatilmadi"})
		return
	}

	err := h.VPP.DeleteStaticRoute(prefix)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"status": "Marshrut o'chirildi"})
}