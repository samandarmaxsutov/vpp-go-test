package web

import (
	"fmt"
	"net/http"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type AbfHandler struct {
	VPP *vpp.VPPClient
}

// HandleCreatePolicy - POST /api/abf/policy
func (h *AbfHandler) HandleCreatePolicy(c *gin.Context) {
	var req struct {
		PolicyID uint32 `json:"policy_id"`
		ACLIndex uint32 `json:"acl_index"`
		NextHop  string `json:"next_hop"`
		IsAdd    bool   `json:"is_add"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input noto'g'ri"})
		return
	}

	var paths []fib_types.FibPath
	if req.IsAdd {
		nhAddr, err := ip_types.ParseAddress(req.NextHop)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "IP manzil formati noto'g'ri"})
			return
		}

		// Xatolik tuzatildi: FibNextHop emas, FibPathNh ishlatiladi
		paths = []fib_types.FibPath{
			{
				SwIfIndex:  0xffffffff, // "no interface" yoki "any"
				Weight:     1,
				Preference: 1,
				Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
				Proto:      fib_types.FIB_API_PATH_NH_PROTO_IP4,
				Nh: fib_types.FibPathNh{
					Address: nhAddr.Un, // AddressUnion
				},
			},
		}

		if nhAddr.Af == ip_types.ADDRESS_IP6 {
			paths[0].Proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
		}
	}

	if err := h.VPP.AbfManager.ConfigurePolicy(c.Request.Context(), req.PolicyID, req.ACLIndex, paths, req.IsAdd); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE_ABF_POLICY", fmt.Sprintf("ID: %d", req.PolicyID), fmt.Sprintf("ACL: %d, NextHop: %s, Add: %v", req.ACLIndex, req.NextHop, req.IsAdd))

	c.JSON(http.StatusOK, gin.H{"message": "ABF siyosati saqlandi"})
}

// HandleAttachInterface - POST /api/abf/attach
func (h *AbfHandler) HandleAttachInterface(c *gin.Context) {
	var req struct {
		PolicyID  uint32 `json:"policy_id"`
		SwIfIndex uint32 `json:"sw_if_index"`
		Priority  uint32 `json:"priority"`
		IsIPv6    bool   `json:"is_ipv6"`
		IsAdd     bool   `json:"is_add"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.VPP.AbfManager.AttachToInterface(c.Request.Context(), req.PolicyID, req.SwIfIndex, req.Priority, req.IsIPv6, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "ATTACH_ABF_INTERFACE", fmt.Sprintf("Policy: %d -> Iface: %d", req.PolicyID, req.SwIfIndex), fmt.Sprintf("Priority: %d, IPv6: %v, Add: %v", req.Priority, req.IsIPv6, req.IsAdd))

	c.JSON(http.StatusOK, gin.H{"message": "ABF interfeysga ulandi/uzildi"})
}

// HandleGetPolicies - GET /api/abf/policies
func (h *AbfHandler) HandleGetPolicies(c *gin.Context) {
	policies, err := h.VPP.AbfManager.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Enhance with time group info and status
	type ABFPolicyWithStatus struct {
		PolicyID      uint32 `json:"policy_id"`
		ACLIndex      uint32 `json:"acl_index"`
		TimeGroupName string `json:"time_group_name"`
		TimeGroupID   string `json:"time_group_id"`
		IsActive      bool   `json:"is_active"`
		StatusMessage string `json:"status_message"`
	}

	enhancedList := make([]ABFPolicyWithStatus, 0, len(policies))
	for _, policyDetail := range policies {
		policyIDStr := fmt.Sprintf("%d", policyDetail.Policy.PolicyID)
		enhanced := ABFPolicyWithStatus{
			PolicyID:      policyDetail.Policy.PolicyID,
			ACLIndex:      policyDetail.Policy.ACLIndex,
			TimeGroupName: "-",
			TimeGroupID:   "",
			IsActive:      true,
			StatusMessage: "Har doim faol",
		}

		// Get time group assignments
		groups, _ := h.VPP.TimeGroupManager.GetRuleTimeAssignments(c.Request.Context(), "ABF", policyIDStr)
		if len(groups) > 0 {
			enhanced.TimeGroupName = groups[0].Name
			enhanced.TimeGroupID = groups[0].ID

			// Check if currently active
			isActive, statusMsg, _ := h.VPP.TimeGroupManager.CheckIfRuleActive(c.Request.Context(), "ABF", policyIDStr)
			enhanced.IsActive = isActive
			enhanced.StatusMessage = statusMsg
		}

		enhancedList = append(enhancedList, enhanced)
	}

	c.JSON(http.StatusOK, enhancedList)
}

// HandleGetAttachments - GET /api/abf/attachments
func (h *AbfHandler) HandleGetAttachments(c *gin.Context) {
	attachments, err := h.VPP.AbfManager.ListInterfaceAttachments(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, attachments)
}
