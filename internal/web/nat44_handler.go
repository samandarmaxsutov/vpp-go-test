package web

import (
	"context"
	"net/http"
	"vpp-go-test/internal/vpp/nat44"
	"vpp-go-test/binapi/nat_types"
	"vpp-go-test/binapi/nat44_ed"

	"github.com/gin-gonic/gin"
)

type NatHandler struct {
	NatMgr *nat44.NatManager
}

func NewNatHandler(mgr *nat44.NatManager) *NatHandler {
	return &NatHandler{NatMgr: mgr}
}

// --- TAB 1: Infrastructure (Interfaces & Pool) ---

// HandleSetInterfaceNAT - Interfeysni NAT rejimiga o'tkazish
func (h *NatHandler) HandleSetInterfaceNAT(c *gin.Context) {
	var req struct {
		SwIfIndex uint32 `json:"sw_if_index"`
		IsInside  bool   `json:"is_inside"`
		IsAdd     bool   `json:"is_add"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri ma'lumot yuborildi"})
		return
	}

	err := h.NatMgr.SetInterfaceNAT(context.Background(), req.SwIfIndex, req.IsInside, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Interfeys NAT holati yangilandi"})
}

// HandleAddAddressPool - Tashqi IP poolga IP qo'shish
func (h *NatHandler) HandleAddAddressPool(c *gin.Context) {
	var req struct {
		IPAddress string `json:"ip_address"`
		IsAdd     bool   `json:"is_add"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP manzil formati xato"})
		return
	}

	err := h.NatMgr.AddAddressPool(context.Background(), req.IPAddress, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "IP Pool yangilandi"})
}

// --- TAB 2: Inbound (Static Mapping) ---

func (h *NatHandler) HandleStaticMapping(c *gin.Context) {
    // Backend structiga barcha kerakli maydonlarni qabul qilamiz
    var req struct {
        LocalIP      string `json:"local_ip"`
        LocalPort    uint16 `json:"local_port"`
        ExternalIP   string `json:"external_ip"`
        ExternalPort uint16 `json:"external_port"`
        ExternalIf   uint32 `json:"external_if"` // Interfeys indeksi uchun
        Protocol     string `json:"protocol"`
        IsAdd        bool   `json:"is_add"`
    }

    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Mapping ma'lumotlari xato: " + err.Error()})
        return
    }

    // NatManager uchun StaticMapping obyektini quramiz
    sm := nat44.StaticMapping{
        LocalIP:      req.LocalIP,
        LocalPort:    req.LocalPort,
        ExternalIP:   req.ExternalIP,
        ExternalPort: req.ExternalPort,
        ExternalIf:   req.ExternalIf, // Yangi qo'shilgan maydon
        Protocol:     req.Protocol,
    }

    // NatManager'dagi AddStaticMapping funksiyasiga uzatamiz
    // sm ichidagi IsAdd emas, req.IsAdd dan foydalanamiz (aniqroq bo'lishi uchun)
    err := h.NatMgr.AddStaticMapping(context.Background(), sm, req.IsAdd)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "VPP xatosi: " + err.Error()})
        return
    }

    msg := "Static mapping muvaffaqiyatli qo'shildi"
    if !req.IsAdd {
        msg = "Static mapping muvaffaqiyatli o'chirildi"
    }
    c.JSON(http.StatusOK, gin.H{"message": msg})
}

// --- TAB 3: Global Settings ---

func (h *NatHandler) HandleSetTimeouts(c *gin.Context) {
	var req nat_types.NatTimeouts
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Timeout qiymatlari xato"})
		return
	}

	err := h.NatMgr.SetNatTimeouts(context.Background(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "NAT timeoutlari yangilandi"})
}

// --- TAB 4: Session Management ---

// HandleGetSessions - Faol sessiyalar ro'yxatini olish
func (h *NatHandler) HandleGetSessions(c *gin.Context) {
	sessions, err := h.NatMgr.GetActiveSessions(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, sessions)
}

// HandleClearSessions - Barcha sessiyalarni tozalash
func (h *NatHandler) HandleClearSessions(c *gin.Context) {
	err := h.NatMgr.ClearAllSessions(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Barcha NAT sessiyalari tozalandi"})
}

// --- GET Metodlari (Jadvallarni to'ldirish uchun) ---

// HandleGetInterfaces - NAT statusi bor interfeyslar ro'yxatini olish
func (h *NatHandler) HandleGetInterfaces(c *gin.Context) {
	ifaces, err := h.NatMgr.GetNatInterfaces(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ifaces)
}

// HandleGetPool - NAT hovuzidagi IP manzillar ro'yxatini olish
func (h *NatHandler) HandleGetPool(c *gin.Context) {
	// Bu metodni NatManager'da yozishimiz kerak bo'ladi (pastda ko'rsatilgan)
	pool, err := h.NatMgr.GetAddressPool(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pool)
}

// HandleGetStaticMappings - Mavjud Static Mapping (DNAT) qoidalarini olish
func (h *NatHandler) HandleGetStaticMappings(c *gin.Context) {
	mappings, err := h.NatMgr.GetStaticMappings(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, mappings)
}

func (h *NatHandler) HandleEnableNAT(c *gin.Context) {
	err := h.NatMgr.EnableNat44(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "NAT44 plugin muvaffaqiyatli yoqildi"})
}

// HandleDelSpecificSession muayyan NAT sessiyasini o'chiradi
func (h *NatHandler) HandleDelSpecificSession(c *gin.Context) {
    // Frontend yuborgan butun sessiya obyektini qabul qilamiz
    var session nat44_ed.Nat44UserSessionV3Details
    
    if err := c.ShouldBindJSON(&session); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Sessiya ma'lumotlari xato formatda"})
        return
    }

    // NatManager orqali sessiyani o'chirishga so'rov yuboramiz
    // Avvalgi xatolikni tuzatish uchun InsideIPAddress va ExtHostAddress ishlatamiz
    err := h.NatMgr.DelSpecificSession(context.Background(), session)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "VPP sessiyani o'chira olmadi: " + err.Error()})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Sessiya muvaffaqiyatli uzildi"})
}


// --- TAB 3: Global Settings (Kengaytirilgan) ---

// HandleSetIpfixLogging - NAT hodisalarini IPFIX orqali yuborishni yoqish/o'chirish
func (h *NatHandler) HandleSetIpfixLogging(c *gin.Context) {
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri format"})
		return
	}

	err := h.NatMgr.SetIpfixLogging(context.Background(), req.Enable)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "IPFIX sozlamasini o'zgartirib bo'lmadi: " + err.Error()})
		return
	}

	status := "yoqildi"
	if !req.Enable {
		status = "o'chirildi"
	}
	c.JSON(http.StatusOK, gin.H{"message": "NAT IPFIX logging " + status})
}

// HandleGetNatConfig - NAT ning joriy global sozlamalarini olish (IPFIX holatini bilish uchun)
func (h *NatHandler) HandleGetNatConfig(c *gin.Context) {
	config, err := h.NatMgr.GetRunningConfig(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "NAT konfiguratsiyasini olib bo'lmadi: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, config)
}