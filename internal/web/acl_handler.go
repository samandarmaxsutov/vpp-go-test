package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"
	"vpp-go-test/internal/vpp/acl"
	"vpp-go-test/internal/vpp/time_group"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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
		Tag         string         `json:"tag" binding:"required"`
		IsStateful  bool           `json:"is_stateful"`
		Rules       []acl.WebInput `json:"rules" binding:"required"`
		TimeGroupID string         `json:"time_group_id"` // Optional time group
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "JSON validatsiya xatosi: " + err.Error()})
		return
	}

	// Vaqt guruhi tekshiruvi - agar time_group_id berilgan bo'lsa
	if req.TimeGroupID != "" && req.TimeGroupID != "always" {
		// Vaqt guruhi hozir faol emasligini tekshirish
		if !h.VPP.TimeGroupManager.IsTimeGroupActiveNow(req.TimeGroupID) {
			// Vaqt guruhi faol emas - pending qilish
			rulesJSON := make([]map[string]interface{}, len(req.Rules))
			for i, r := range req.Rules {
				ruleBytes, _ := json.Marshal(r)
				var ruleMap map[string]interface{}
				json.Unmarshal(ruleBytes, &ruleMap)
				rulesJSON[i] = ruleMap
			}

			pendingRule := &time_group.PendingACLRule{
				Tag:         req.Tag,
				Rules:       rulesJSON,
				TimeGroupID: req.TimeGroupID,
				IsStateful:  req.IsStateful,
			}

			if err := h.VPP.TimeGroupManager.AddPendingACLRule(pendingRule); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Pending qilishda xato: " + err.Error()})
				return
			}

			// Logging
			session := sessions.Default(c)
			user := "system"
			if userID := session.Get("user_id"); userID != nil {
				user = userID.(string)
			}
			details, _ := json.Marshal(req)
			logger.LogConfigChange(user, c.ClientIP(), "PENDING", "ACL", string(details))

			c.JSON(http.StatusAccepted, gin.H{
				"status":        "pending",
				"pending_id":    pendingRule.ID,
				"message":       "ACL vaqt guruhi faol emas - pending holatda saqlandi",
				"time_group_id": req.TimeGroupID,
			})
			return
		}
	}

	// Vaqt faol yoki time_group yo'q - VPP ga push qilish
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

	// Agar time_group_id berilgan bo'lsa, uni tayinlash
	if req.TimeGroupID != "" && req.TimeGroupID != "always" {
		aclID := fmt.Sprintf("%d", index)
		_ = h.VPP.TimeGroupManager.AssignTimeGroupToRule(c.Request.Context(), "ACL", aclID, req.TimeGroupID)

		// ACL yaratilganda backup yozish (last_active=true) - scheduler tekshiradi
		// Agar vaqt guruhi hozir faol bo'lmasa, scheduler 1 daqiqa ichida o'chiradi
		rulesForBackup := make([]map[string]interface{}, len(req.Rules))
		for i, r := range req.Rules {
			ruleBytes, _ := json.Marshal(r)
			var ruleMap map[string]interface{}
			json.Unmarshal(ruleBytes, &ruleMap)
			rulesForBackup[i] = ruleMap
		}

		backupConfig := map[string]interface{}{
			"acl_index": index,
			"tag":       req.Tag,
			"rules":     rulesForBackup,
		}

		// Backup yaratish - last_active=true bo'lgani uchun scheduler tekshiradi
		_ = h.VPP.TimeGroupManager.SaveDisabledRuleBackup(&time_group.DisabledRuleBackup{
			RuleType:      "ACL",
			RuleID:        aclID,
			Configuration: backupConfig,
			Interfaces:    []time_group.InterfaceBinding{}, // hozircha interface yo'q
			TimeGroupID:   req.TimeGroupID,
			LastActive:    true, // Yangi yaratilgan - scheduler tekshiradi va kerak bo'lsa o'chiradi
		})
	}

	// Logging
	session := sessions.Default(c)
	user := "system"
	if userID := session.Get("user_id"); userID != nil {
		user = userID.(string)
	}
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE", "ACL", string(details))

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	details, _ := json.Marshal(req)
	logger.LogConfigChange(user, c.ClientIP(), "UPDATE", fmt.Sprintf("ACL %d", index), string(details))

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

	// Enhance with time group info and status
	type ACLWithStatus struct {
		acl.ACLDetail
		TimeGroupName string `json:"time_group_name"`
		TimeGroupID   string `json:"time_group_id"`
		IsActive      bool   `json:"is_active"`
		StatusMessage string `json:"status_message"`
	}

	enhancedList := make([]ACLWithStatus, 0, len(details))
	for _, aclDetail := range details {
		aclID := fmt.Sprintf("%d", aclDetail.ACLIndex)
		enhanced := ACLWithStatus{
			ACLDetail:     aclDetail,
			TimeGroupName: "-",
			TimeGroupID:   "",
			IsActive:      true,
			StatusMessage: "Har doim faol",
		}

		// Get time group assignments
		groups, _ := h.VPP.TimeGroupManager.GetRuleTimeAssignments(c.Request.Context(), "ACL", aclID)
		if len(groups) > 0 {
			enhanced.TimeGroupName = groups[0].Name
			enhanced.TimeGroupID = groups[0].ID

			// Check if currently active
			isActive, statusMsg, _ := h.VPP.TimeGroupManager.CheckIfRuleActive(c.Request.Context(), "ACL", aclID)
			enhanced.IsActive = isActive
			enhanced.StatusMessage = statusMsg
		}

		enhancedList = append(enhancedList, enhanced)
	}

	c.JSON(http.StatusOK, enhancedList)
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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "APPLY", fmt.Sprintf("Interface %d", req.SwIfIndex), fmt.Sprintf("In:%v Out:%v", req.InputACLs, req.OutputACLs))

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "DELETE", fmt.Sprintf("ACL %d", index), "")

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE", "MAC ACL", req.Tag)

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "DELETE", fmt.Sprintf("MAC ACL %d", index), "")

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "UPDATE", fmt.Sprintf("MAC ACL %d", index), req.Tag)

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "BIND", fmt.Sprintf("MAC ACL %d -> Iface %d", req.ACLIndex, req.SwIfIndex), "Applied")

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

	// Logging
	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "UNBIND", fmt.Sprintf("MAC ACL %d <- Iface %d", req.ACLIndex, req.SwIfIndex), "Removed")

	c.JSON(http.StatusOK, gin.H{"message": "MAC ACL bog'lamasi olib tashlandi"})
}
