package web

import (
	"net/http"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/internal/vpp/abf_mgr"
	"github.com/gin-gonic/gin"
	"fmt"
)

type AbfHandler struct {
	AbfMgr *abf_mgr.AbfManager
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

	err = h.AbfMgr.ConfigurePolicy(c.Request.Context(), req.PolicyID, req.ACLIndex, paths, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

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

	err := h.AbfMgr.AttachToInterface(c.Request.Context(), req.PolicyID, req.SwIfIndex, req.Priority, req.IsIPv6, req.IsAdd)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "ABF interfeysga ulandi/uzildi"})
}

// HandleGetPolicies - GET /api/abf/policies
func (h *AbfHandler) HandleGetPolicies(c *gin.Context) {
	policies, err := h.AbfMgr.ListPolicies(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, policies)
}

// HandleGetAttachments - GET /api/abf/attachments
func (h *AbfHandler) HandleGetAttachments(c *gin.Context) {
	attachments, err := h.AbfMgr.ListInterfaceAttachments(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, attachments)
}