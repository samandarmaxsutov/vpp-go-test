package web

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/vpp/acl"
)

type ACLHandler struct {
	VPP *vpp.VPPClient
}

func NewACLHandler(vppClient *vpp.VPPClient) *ACLHandler {
	return &ACLHandler{VPP: vppClient}
}

// 1. CreateACL - Yangi ACL yaratish (POST /api/acl)
func (h *ACLHandler) CreateACL(c *gin.Context) {
	var req struct {
		Tag        string         `json:"tag" binding:"required"`
		IsStateful bool           `json:"is_stateful"`
		Rules      []acl.WebInput `json:"rules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	var vppRules []acl_types.ACLRule
	for _, r := range req.Rules {
		rule, err := acl.CreateRuleFromWebInput(r, req.IsStateful)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Qoida yaratishda xato: " + err.Error()})
			return
		}
		vppRules = append(vppRules, rule)
	}

	index, err := h.VPP.ACLManager.CreateACL(c.Request.Context(), req.Tag, vppRules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Xato: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"acl_index": index,
		"message":   "ACL yaratildi",
	})
}

// 2. UpdateACL - Mavjud ACLni tahrirlash (PUT /api/acl/:index)
func (h *ACLHandler) UpdateACL(c *gin.Context) {
	indexStr := c.Param("index")
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index noto'g'ri"})
		return
	}

	var req struct {
		Tag        string         `json:"tag" binding:"required"`
		IsStateful bool           `json:"is_stateful"`
		Rules      []acl.WebInput `json:"rules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Update JSON xatosi: " + err.Error()})
		return
	}

	var vppRules []acl_types.ACLRule
	for _, r := range req.Rules {
		rule, err := acl.CreateRuleFromWebInput(r, req.IsStateful)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Rule konvertatsiya xatosi: " + err.Error()})
			return
		}
		vppRules = append(vppRules, rule)
	}

	err = h.VPP.ACLManager.UpdateACL(c.Request.Context(), uint32(index), req.Tag, vppRules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Update xatosi: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ACL muvaffaqiyatli yangilandi"})
}

// 3. ListACLs - (GET /api/acl)
func (h *ACLHandler) ListACLs(c *gin.Context) {
	details, err := h.VPP.ACLManager.GetAllACLs(c.Request.Context())

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if details == nil {
		details = []acl.ACLDetail{}
	}
	c.JSON(http.StatusOK, details)
}

// 4. ApplyToInterface - (POST /api/acl/interface/apply)
func (h *ACLHandler) ApplyToInterface(c *gin.Context) {
	var req struct {
		SwIfIndex  uint32   `json:"sw_if_index"`
		InputACLs  []uint32 `json:"input_acls"`
		OutputACLs []uint32 `json:"output_acls"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := h.VPP.ACLManager.ApplyACLToInterface(c.Request.Context(), req.SwIfIndex, req.InputACLs, req.OutputACLs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Interfeys ACLlari bog'landi"})
}

// 5. DeleteACL - (DELETE /api/acl/:index)
func (h *ACLHandler) DeleteACL(c *gin.Context) {
	indexStr := c.Param("index")
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index xato"})
		return
	}
	err = h.VPP.ACLManager.DeleteACL(c.Request.Context(), uint32(index))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ACL o'chirildi"})
}

// 6. ListInterfaceMaps - (GET /api/acl/interface/all)
func (h *ACLHandler) ListInterfaceMaps(c *gin.Context) {
	maps, err := h.VPP.ACLManager.GetAllInterfaceACLs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if maps == nil {
		maps = []acl.InterfaceACLMap{}
	}
	c.JSON(http.StatusOK, maps)
}

type InterfaceACLStatus struct {
	SwIfIndex   uint32   `json:"sw_if_index"`
	Name        string   `json:"name"`
	InputIP     []uint32 `json:"input_ip"`
	OutputIP    []uint32 `json:"output_ip"`
	AttachedMAC *uint32  `json:"attached_mac"` // MAC ACL bitta bo'ladi
}

func (h *ACLHandler) GetFullInterfaceACLMap(c *gin.Context) {
	ctx := c.Request.Context()

	// 1. IP ACL bog'lamalarini olish
	ipMaps, err := h.VPP.ACLManager.GetAllInterfaceACLs(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 2. MAC ACL bog'lamalarini olish
	macMaps, err := h.VPP.ACLManager.GetMacACLInterfaceList(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// 3. Natijalarni yig'ish (Soddalashtirish uchun xarita ko'rinishida)
	// Bu yerda interfeys nomlarini InterfaceHandler'dan olishingiz mumkin
	// Hozircha faqat indekslar bilan qaytaramiz

	c.JSON(200, gin.H{
		"ip_assignments":  ipMaps,
		"mac_assignments": macMaps,
	})
}

// --- MAC ACL METODLARI ---

// CreateMacACL - Yangi MAC ACL yaratish (POST /api/mac-acl)
func (h *ACLHandler) CreateMacACL(c *gin.Context) {
	var req struct {
		Tag   string            `json:"tag" binding:"required"`
		Rules []acl.MacWebInput `json:"rules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON xatosi: " + err.Error()})
		return
	}

	var vppRules []acl_types.MacipACLRule
	for _, r := range req.Rules {
		// helper.go dagi metoddan foydalanamiz
		rule, err := acl.CreateMacipRuleFromWebInput(r)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "MAC qoida xatosi: " + err.Error()})
			return
		}
		vppRules = append(vppRules, rule)
	}

	// 0xffffffff yangi ACL yaratishni bildiradi
	index, err := h.VPP.ACLManager.CreateMacACL(c.Request.Context(), 0xffffffff, req.Tag, vppRules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MAC xatosi: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"acl_index": index,
		"message":   "MAC ACL yaratildi",
	})
}

// ListMacACLs - Barcha MAC ACLlarni ko'rish (GET /api/mac-acl)
func (h *ACLHandler) ListMacACLs(c *gin.Context) {
	details, err := h.VPP.ACLManager.GetAllMacACLs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if details == nil {
		details = []acl.MacACLDetail{}
	}

	c.JSON(http.StatusOK, details)
}

// DeleteMacACL - MAC ACLni o'chirish (DELETE /api/mac-acl/:index)
func (h *ACLHandler) DeleteMacACL(c *gin.Context) {
	indexStr := c.Param("index")
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Index noto'g'ri"})
		return
	}

	err = h.VPP.ACLManager.DeleteMacACL(c.Request.Context(), uint32(index))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MAC ACL o'chirildi"})
}

// UpdateMacACL - Mavjud MAC ACLni yangilash (PUT /api/mac-acl/:index)
func (h *ACLHandler) UpdateMacACL(c *gin.Context) {
	// 1. Indexni olish
	indexStr := c.Param("index")
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Noto'g'ri ACL indeksi"})
		return
	}

	// 2. Requestni bind qilish
	var req struct {
		Tag   string            `json:"tag" binding:"required"`
		Rules []acl.MacWebInput `json:"rules" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ma'lumotlar formati noto'g'ri: " + err.Error()})
		return
	}

	// 3. WebInput ni VPP MacipACLRule ga aylantirish
	var vppRules []acl_types.MacipACLRule
	for _, r := range req.Rules {
		rule, err := acl.CreateMacipRuleFromWebInput(r)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Qoida xatosi: " + err.Error()})
			return
		}
		vppRules = append(vppRules, rule)
	}

	// 4. Menejer orqali VPP ga yuborish (mavjud index bilan)
	_, err = h.VPP.ACLManager.CreateMacACL(c.Request.Context(), uint32(index), req.Tag, vppRules)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Yangilashda xato: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"acl_index": index,
		"message":   "MAC ACL muvaffaqiyatli yangilandi",
	})
}

// --- MAC ACL INTERFACE BINDING (Alohida endpointlar) ---

// GetMacInterfaceMaps - (GET /api/mac-acl/interface/all)
// Interfeyslarga biriktirilgan barcha MAC ACLlarni ko'rish
func (h *ACLHandler) GetMacInterfaceMaps(c *gin.Context) {
	maps, err := h.VPP.ACLManager.GetMacACLInterfaceList(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MAC bog'lamalarini olishda xatolik: " + err.Error()})
		return
	}

	// Agar ma'lumot bo'lmasa, bo'sh map qaytaradi
	if maps == nil {
		maps = make(map[uint32]uint32)
	}

	c.JSON(http.StatusOK, maps)
}

// ApplyMacToInterface - MAC ACL bog'lash
func (h *ACLHandler) ApplyMacToInterface(c *gin.Context) {
	var req struct {
		SwIfIndex uint32 `json:"sw_if_index"`
		ACLIndex  uint32 `json:"acl_index"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := h.VPP.ACLManager.ApplyMacACLToInterface(c.Request.Context(), req.SwIfIndex, req.ACLIndex, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MAC ACL bog'landi"})
}

// UnbindMacFromInterface - MAC ACL uzish
func (h *ACLHandler) UnbindMacFromInterface(c *gin.Context) {
	var req struct {
		SwIfIndex uint32 `json:"sw_if_index"`
		ACLIndex  uint32 `json:"acl_index"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := h.VPP.ACLManager.ApplyMacACLToInterface(c.Request.Context(), req.SwIfIndex, req.ACLIndex, false)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "MAC ACL bog'lamasi olib tashlandi"})
}
