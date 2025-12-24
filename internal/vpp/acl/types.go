package acl

import (
	"vpp-go-test/binapi/acl_types"
)

// WebInput - Frontenddan (UI) keladigan xom ma'lumotlar formati
type WebInput struct {
	Action       string `json:"action"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Protocol     string `json:"protocol"` // "tcp", "udp", "icmp"
	SrcPortFirst uint16 `json:"src_port_first"`
	SrcPortLast  uint16 `json:"src_port_last"`
	DstPortFirst uint16 `json:"dst_port_first"`
	DstPortLast  uint16 `json:"dst_port_last"`
	TCPMask      uint8  `json:"tcp_mask"`
	TCPValue     uint8  `json:"tcp_value"`
}

// ACLRule - Custom ACL Rule structure that always returns zero values
// OMITEMPTY OLIB TASHLANDI - 0 bo'lsa ham yuboradi!
type ACLRule struct {
	IsPermit               uint8  `json:"is_permit"`                 // 0=deny, 1=permit, 2=permit_reflect
	SrcPrefix              string `json:"src_prefix"`                // "192.168.1.0/24"
	DstPrefix              string `json:"dst_prefix"`                // "10.0.0.0/8"
	Proto                  uint8  `json:"proto"`                     // 6=TCP, 17=UDP, 1=ICMP
	SrcportOrIcmptypeFirst uint16 `json:"srcport_or_icmptype_first"` // Default: 0
	SrcportOrIcmptypeLast  uint16 `json:"srcport_or_icmptype_last"`  // Default: 65535
	DstportOrIcmpcodeFirst uint16 `json:"dstport_or_icmpcode_first"` // Default: 0
	DstportOrIcmpcodeLast  uint16 `json:"dstport_or_icmpcode_last"`  // Default: 65535
	TCPFlagsMask           uint8  `json:"tcp_flags_mask"`
	TCPFlagsValue          uint8  `json:"tcp_flags_value"`
}

// ACLDetail - ACL haqida to'liq ma'lumot (Custom structure)
type ACLDetail struct {
	ACLIndex uint32    `json:"acl_index"`
	Tag      string    `json:"tag"`
	Rules    []ACLRule `json:"rules"` // Custom ACLRule ishlatiladi
}

// InterfaceACLMap - Interfeysga biriktirilgan ACLlar xaritasi
type InterfaceACLMap struct {
	SwIfIndex  uint32   `json:"sw_if_index"`
	InputACLs  []uint32 `json:"input_acls"`
	OutputACLs []uint32 `json:"output_acls"`
}

// ConvertVPPRuleToCustom - VPP ACLRule ni Custom ACLRule ga o'tkazadi
func ConvertVPPRuleToCustom(vppRule acl_types.ACLRule) ACLRule {
	return ACLRule{
		IsPermit:               uint8(vppRule.IsPermit),
		SrcPrefix:              FormatPrefix(vppRule.SrcPrefix),
		DstPrefix:              FormatPrefix(vppRule.DstPrefix),
		Proto:                  uint8(vppRule.Proto),
		SrcportOrIcmptypeFirst: vppRule.SrcportOrIcmptypeFirst,
		SrcportOrIcmptypeLast:  vppRule.SrcportOrIcmptypeLast,
		DstportOrIcmpcodeFirst: vppRule.DstportOrIcmpcodeFirst,
		DstportOrIcmpcodeLast:  vppRule.DstportOrIcmpcodeLast,
		TCPFlagsMask:           vppRule.TCPFlagsMask,
		TCPFlagsValue:          vppRule.TCPFlagsValue,
	}
}


// MacWebInput - Frontenddan MAC ACL uchun keladigan ma'lumot
type MacWebInput struct {
	Action    string `json:"action"`      // "permit", "deny"
	SrcMac    string `json:"src_mac"`     // "00:11:22:33:44:55"
	SrcMask   string `json:"src_mask"`    // "ff:ff:ff:ff:ff:ff"
	SrcPrefix string `json:"src_prefix"`  // "192.168.1.0/24" yoki "any"
}

// MacACLRule - Custom MAC ACL Rule (UI ga yuborish uchun)
type MacACLRule struct {
	IsPermit  uint8  `json:"is_permit"`
	SrcMac    string `json:"src_mac"`
	SrcMask   string `json:"src_mask"`
	SrcPrefix string `json:"src_prefix"`
}

// MacACLDetail - MAC ACL haqida to'liq ma'lumot
type MacACLDetail struct {
	ACLIndex uint32       `json:"acl_index"`
	Tag      string       `json:"tag"`
	Rules    []MacACLRule `json:"rules"`
}