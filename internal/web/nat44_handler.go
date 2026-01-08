package web

import (
    "context"
    "net/http"
    "vpp-go-test/internal/vpp/nat44"
    "vpp-go-test/binapi/nat_types"
    "vpp-go-test/binapi/nat44_ed"

    "github.com/gin-gonic/gin"
    "sync"
    "time"
)

// Global kesh ob'ektlari
var (
    sessionCache      *nat44.NATSessionResponse 
    lastCacheUpdate   time.Time
    cacheMutex        sync.RWMutex
)

const CacheTTL = 10 * time.Second // Kesh muddati: 10 soniya

type NatHandler struct {
    NatMgr *nat44.NatManager
}

func NewNatHandler(mgr *nat44.NatManager) *NatHandler {
    return &NatHandler{NatMgr: mgr}
}

// --- TAB 4: Session Management (Optimallashtirilgan) ---

// HandleGetSessions - Faol sessiyalar ro'yxatini kesh orqali olish
// HandleGetSessions - Yangilangan kesh handler
func (h *NatHandler) HandleGetSessions(c *gin.Context) {
    // 1. O'qish uchun lock (Kesh yangi bo'lsa darhol javob berish)
    cacheMutex.RLock()
    if time.Since(lastCacheUpdate) < CacheTTL && sessionCache != nil {
        defer cacheMutex.RUnlock()
        c.JSON(http.StatusOK, sessionCache)
        return
    }
    cacheMutex.RUnlock()

    // 2. Yozish uchun lock (VPP ga murojaat qilish)
    cacheMutex.Lock()
    defer cacheMutex.Unlock()

    // Double-check (Boshqa foydalanuvchi hozirgina yangilagan bo'lishi mumkin)
    if time.Since(lastCacheUpdate) < CacheTTL && sessionCache != nil {
        c.JSON(http.StatusOK, sessionCache)
        return
    }

    // VPP dan yangi formatdagi ma'lumotni olamiz (Sessions + UserSummary)
    // Bu metod nat44.NATSessionResponse qaytaradi
    data, err := h.NatMgr.GetActiveSessions(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Dump xatosi: " + err.Error()})
        return
    }

    // Keshni yangilash
    sessionCache = data
    lastCacheUpdate = time.Now()

    c.JSON(http.StatusOK, sessionCache)
}

// HandleClearSessions - Sessiyalarni tozalash (Keshni ham o'chiramiz)
func (h *NatHandler) HandleClearSessions(c *gin.Context) {
    err := h.NatMgr.ClearAllSessions(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Tozalashdan keyin keshni ham reset qilamiz
    cacheMutex.Lock()
    sessionCache = nil
    lastCacheUpdate = time.Time{}
    cacheMutex.Unlock()

    c.JSON(http.StatusOK, gin.H{"message": "Barcha NAT sessiyalari tozalandi"})
}

// HandleDelSpecificSession - Muayyan sessiyani o'chirish (Keshni reset qiladi)
func (h *NatHandler) HandleDelSpecificSession(c *gin.Context) {
    var session nat44_ed.Nat44UserSessionV3Details
    if err := c.ShouldBindJSON(&session); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Format xato"})
        return
    }

    err := h.NatMgr.DelSpecificSession(context.Background(), session)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // Sessiya o'chirilgach, kesh eskirgan hisoblanadi
    cacheMutex.Lock()
    lastCacheUpdate = time.Time{} // Keyingi so'rovda yangilanadi
    cacheMutex.Unlock()

    c.JSON(http.StatusOK, gin.H{"message": "Sessiya uzildi"})
}

// --- QOLGAN METODLAR (O'zgarishsiz qoladi) ---

func (h *NatHandler) HandleSetInterfaceNAT(c *gin.Context) {
    var req struct {
        SwIfIndex uint32 `json:"sw_if_index"`
        IsInside  bool   `json:"is_inside"`
        IsAdd     bool   `json:"is_add"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Xato ma'lumot"})
        return
    }
    err := h.NatMgr.SetInterfaceNAT(context.Background(), req.SwIfIndex, req.IsInside, req.IsAdd)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Muvaffaqiyatli bajarildi"})
}

func (h *NatHandler) HandleAddAddressPool(c *gin.Context) {
    var req struct {
        IPAddress string `json:"ip_address"`
        IsAdd     bool   `json:"is_add"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "IP format xato"})
        return
    }
    err := h.NatMgr.AddAddressPool(context.Background(), req.IPAddress, req.IsAdd)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Pool yangilandi"})
}

func (h *NatHandler) HandleStaticMapping(c *gin.Context) {
    var req struct {
        LocalIP      string `json:"local_ip"`
        LocalPort    uint16 `json:"local_port"`
        ExternalIP   string `json:"external_ip"`
        ExternalPort uint16 `json:"external_port"`
        ExternalIf   uint32 `json:"external_if"`
        Protocol     string `json:"protocol"`
        IsAdd        bool   `json:"is_add"`
    }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    sm := nat44.StaticMapping{
        LocalIP: req.LocalIP, LocalPort: req.LocalPort,
        ExternalIP: req.ExternalIP, ExternalPort: req.ExternalPort,
        ExternalIf: req.ExternalIf, Protocol: req.Protocol,
    }
    err := h.NatMgr.AddStaticMapping(context.Background(), sm, req.IsAdd)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Static mapping yangilandi"})
}

func (h *NatHandler) HandleGetInterfaces(c *gin.Context) {
    ifaces, err := h.NatMgr.GetNatInterfaces(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, ifaces)
}

func (h *NatHandler) HandleGetPool(c *gin.Context) {
    pool, err := h.NatMgr.GetAddressPool(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, pool)
}

func (h *NatHandler) HandleGetStaticMappings(c *gin.Context) {
    mappings, err := h.NatMgr.GetStaticMappings(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, mappings)
}

func (h *NatHandler) HandleSetTimeouts(c *gin.Context) {
    var req nat_types.NatTimeouts
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Xato qiymat"})
        return
    }
    err := h.NatMgr.SetNatTimeouts(context.Background(), req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "Timeoutlar yangilandi"})
}

func (h *NatHandler) HandleEnableNAT(c *gin.Context) {
    err := h.NatMgr.EnableNat44(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "NAT44 yoqildi"})
}

func (h *NatHandler) HandleSetIpfixLogging(c *gin.Context) {
    var req struct{ Enable bool `json:"enable"` }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Xato"})
        return
    }
    err := h.NatMgr.SetIpfixLogging(context.Background(), req.Enable)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, gin.H{"message": "IPFIX yangilandi"})
}

func (h *NatHandler) HandleGetNatConfig(c *gin.Context) {
    config, err := h.NatMgr.GetRunningConfig(context.Background())
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    c.JSON(http.StatusOK, config)
}