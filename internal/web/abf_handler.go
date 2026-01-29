package web

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/internal/logger"
	"vpp-go-test/internal/vpp"
)

type AbfHandler struct {
	VPP *vpp.VPPClient
}

// ABF Policy with enriched data for frontend
type ABFPolicyEnriched struct {
	PolicyID   uint32   `json:"policy_id"`
	ACLIndex   uint32   `json:"acl_index"`
	ACLTag     string   `json:"acl_tag"`   // ACL name/tag
	NextHops   []string `json:"next_hops"` // List of next-hop IPs
	PathsCount int      `json:"paths_count"`
}

// ABF Attachment with enriched interface data
type ABFAttachmentEnriched struct {
	PolicyID      uint32 `json:"policy_id"`
	SwIfIndex     uint32 `json:"sw_if_index"`
	InterfaceName string `json:"interface_name"` // Interface name
	InterfaceTag  string `json:"interface_tag"`  // Interface tag/alias
	InterfaceIP   string `json:"interface_ip"`   // First IP address
	Priority      uint32 `json:"priority"`
	IsIPv6        bool   `json:"is_ipv6"`
}

// Interface info for ABF dropdown
type ABFInterfaceInfo struct {
	Index       uint32   `json:"index"`
	Name        string   `json:"name"`
	Tag         string   `json:"tag"`
	IPAddresses []string `json:"ip_addresses"`
	DisplayName string   `json:"display_name"` // Formatted display name
}

// HandleCreatePolicy - POST /api/abf/policy
func (h *AbfHandler) HandleCreatePolicy(c *gin.Context) {
	var req struct {
		PolicyID uint32 `json:"policy_id"`
		ACLIndex uint32 `json:"acl_index"`
		NextHop  string `json:"next_hop"`
		IsAdd    bool   `json:"is_add"`
	}

	fmt.Printf("DEBUG: PolicyID=%d, IsAdd=%v\n", req.PolicyID, req.IsAdd)

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input noto'g'ri"})
		return
	}

	nhAddr, err := ip_types.ParseAddress(req.NextHop)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP manzil formati noto'g'ri"})
		return
	}

	// Xatolik tuzatildi: FibNextHop emas, FibPathNh ishlatiladi
	paths := []fib_types.FibPath{
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

	err = h.VPP.AbfManager.ConfigurePolicy(c.Request.Context(), req.PolicyID, req.ACLIndex, paths, req.IsAdd)
	if err != nil {
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

// HandleGetPolicies - GET /api/abf/policies (with enriched ACL info)
func (h *AbfHandler) HandleGetPolicies(c *gin.Context) {
	policies, err := h.VPP.AbfManager.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get ACL list to map ACL index to tag/name
	aclMap := make(map[uint32]string)
	if h.VPP.ACLManager != nil {
		acls, aclErr := h.VPP.ACLManager.GetAllACLs(c.Request.Context())
		if aclErr == nil {
			for _, acl := range acls {
				aclMap[acl.ACLIndex] = acl.Tag
			}
		}
	}

	// Enrich policies with ACL names and next-hop info
	var enrichedPolicies []ABFPolicyEnriched
	for _, p := range policies {
		aclTag := aclMap[p.Policy.ACLIndex]
		if aclTag == "" {
			aclTag = fmt.Sprintf("ACL-%d", p.Policy.ACLIndex)
		}

		// Extract next-hop IPs from paths
		var nextHops []string
		for _, path := range p.Policy.Paths {
			bytes := path.Nh.Address.XXX_UnionData
			ip := fmt.Sprintf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3])
			if ip != "0.0.0.0" {
				nextHops = append(nextHops, ip)
			}
		}

		enrichedPolicies = append(enrichedPolicies, ABFPolicyEnriched{
			PolicyID:   p.Policy.PolicyID,
			ACLIndex:   p.Policy.ACLIndex,
			ACLTag:     aclTag,
			NextHops:   nextHops,
			PathsCount: len(p.Policy.Paths),
		})
	}

	c.JSON(http.StatusOK, enrichedPolicies)
}

// HandleGetAttachments - GET /api/abf/attachments (with enriched interface info)
func (h *AbfHandler) HandleGetAttachments(c *gin.Context) {
	attachments, err := h.VPP.AbfManager.ListInterfaceAttachments(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Get interface list to map sw_if_index to name/tag/IP
	ifaceMap := make(map[uint32]vpp.InterfaceInfo)
	interfaces, ifErr := h.VPP.GetInterfaces()
	if ifErr == nil {
		for _, iface := range interfaces {
			ifaceMap[iface.Index] = iface
		}
	}

	// Enrich attachments with interface info
	var enrichedAttachments []ABFAttachmentEnriched
	for _, a := range attachments {
		iface := ifaceMap[uint32(a.Attach.SwIfIndex)]

		// Get first IP address if available
		interfaceIP := ""
		if len(iface.IPAddresses) > 0 {
			interfaceIP = iface.IPAddresses[0]
		}

		enrichedAttachments = append(enrichedAttachments, ABFAttachmentEnriched{
			PolicyID:      a.Attach.PolicyID,
			SwIfIndex:     uint32(a.Attach.SwIfIndex),
			InterfaceName: iface.Name,
			InterfaceTag:  iface.Tag,
			InterfaceIP:   interfaceIP,
			Priority:      a.Attach.Priority,
			IsIPv6:        a.Attach.IsIPv6,
		})
	}

	c.JSON(http.StatusOK, enrichedAttachments)
}

// HandleGetInterfacesForABF - GET /api/abf/interfaces (enriched interface list for dropdown)
func (h *AbfHandler) HandleGetInterfacesForABF(c *gin.Context) {
	interfaces, err := h.VPP.GetInterfaces()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var result []ABFInterfaceInfo
	for _, iface := range interfaces {
		if iface.Name == "local0" {
			continue // Skip local0
		}

		// Build display name: "name (tag) - IP" or "name - IP"
		displayName := iface.Name
		if iface.Tag != "" && iface.Tag != iface.Name {
			displayName = fmt.Sprintf("%s (%s)", iface.Name, iface.Tag)
		}
		if len(iface.IPAddresses) > 0 {
			displayName = fmt.Sprintf("%s - %s", displayName, iface.IPAddresses[0])
		}

		result = append(result, ABFInterfaceInfo{
			Index:       iface.Index,
			Name:        iface.Name,
			Tag:         iface.Tag,
			IPAddresses: iface.IPAddresses,
			DisplayName: displayName,
		})
	}

	c.JSON(http.StatusOK, result)
}

// HandleCreateMultiplePolicies - POST /api/abf/policies/bulk
// Creates separate ACL and ABF policy for each selected interface
func (h *AbfHandler) HandleCreateMultiplePolicies(c *gin.Context) {
	var req struct {
		BasePolicyID uint32   `json:"base_policy_id"` // Starting policy ID
		BaseACLIndex uint32   `json:"base_acl_index"` // ACL index to use (or 0 to create new)
		NextHop      string   `json:"next_hop"`       // Next-hop IP
		InterfaceIDs []uint32 `json:"interface_ids"`  // List of interface indices
		Priority     uint32   `json:"priority"`       // Attachment priority
		CreatePerACL bool     `json:"create_per_acl"` // Create separate ACL per interface
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Input noto'g'ri: " + err.Error()})
		return
	}

	if len(req.InterfaceIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Kamida bitta interfeys tanlang"})
		return
	}

	nhAddr, err := ip_types.ParseAddress(req.NextHop)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP manzil formati noto'g'ri"})
		return
	}

	paths := []fib_types.FibPath{
		{
			SwIfIndex:  0xffffffff,
			Weight:     1,
			Preference: 1,
			Type:       fib_types.FIB_API_PATH_TYPE_NORMAL,
			Proto:      fib_types.FIB_API_PATH_NH_PROTO_IP4,
			Nh: fib_types.FibPathNh{
				Address: nhAddr.Un,
			},
		},
	}

	if nhAddr.Af == ip_types.ADDRESS_IP6 {
		paths[0].Proto = fib_types.FIB_API_PATH_NH_PROTO_IP6
	}

	ctx := c.Request.Context()
	var createdPolicies []uint32
	var errors []string

	// Get interface names for logging
	interfaces, _ := h.VPP.GetInterfaces()
	ifaceMap := make(map[uint32]string)
	for _, iface := range interfaces {
		ifaceMap[iface.Index] = iface.Name
	}

	for i, ifaceID := range req.InterfaceIDs {
		policyID := req.BasePolicyID + uint32(i)
		aclIndex := req.BaseACLIndex

		// Create ABF policy
		if err := h.VPP.AbfManager.ConfigurePolicy(ctx, policyID, aclIndex, paths, true); err != nil {
			errors = append(errors, fmt.Sprintf("Policy %d: %v", policyID, err))
			continue
		}

		// Attach to interface
		if err := h.VPP.AbfManager.AttachToInterface(ctx, policyID, ifaceID, req.Priority, false, true); err != nil {
			errors = append(errors, fmt.Sprintf("Attach %d to %s: %v", policyID, ifaceMap[ifaceID], err))
			continue
		}

		createdPolicies = append(createdPolicies, policyID)
	}

	session := sessions.Default(c)
	user := session.Get("user_id").(string)
	logger.LogConfigChange(user, c.ClientIP(), "CREATE_BULK_ABF",
		fmt.Sprintf("%d policies", len(createdPolicies)),
		fmt.Sprintf("Interfaces: %v, NextHop: %s", req.InterfaceIDs, req.NextHop))

	if len(errors) > 0 {
		c.JSON(http.StatusPartialContent, gin.H{
			"message":          fmt.Sprintf("%d ta policy yaratildi", len(createdPolicies)),
			"created_policies": createdPolicies,
			"errors":           errors,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":          fmt.Sprintf("%d ta policy muvaffaqiyatli yaratildi", len(createdPolicies)),
		"created_policies": createdPolicies,
	})
}

// getACLTagByIndex helper function to get ACL tag by index
func (h *AbfHandler) getACLTagByIndex(ctx context.Context, aclIndex uint32) string {
	if h.VPP.ACLManager == nil {
		return ""
	}
	acls, err := h.VPP.ACLManager.GetAllACLs(ctx)
	if err != nil {
		return ""
	}
	for _, acl := range acls {
		if acl.ACLIndex == aclIndex {
			return acl.Tag
		}
	}
	return ""
}
