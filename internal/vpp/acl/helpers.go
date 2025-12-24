package acl

import (
	"fmt"
	"net"
	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/binapi/ethernet_types"
)

// CreateRuleFromWebInput UI dan kelgan WebInput ni VPP ACLRule ga aylantiradi
func CreateRuleFromWebInput(input WebInput, isStateful bool) (acl_types.ACLRule, error) {
	// Actionni aniqlash - MUHIM O'ZGARTIRISH
	var action acl_types.ACLAction

	switch input.Action {
	case "deny":
		action = acl_types.ACL_ACTION_API_DENY
	case "permit":
		// Agar isStateful true bo'lsa va action "permit" bo'lsa, reflect qilish
		if isStateful {
			action = acl_types.ACL_ACTION_API_PERMIT_REFLECT
		} else {
			action = acl_types.ACL_ACTION_API_PERMIT
		}
	case "permit_reflect":
		// Explicit permit_reflect - isStateful parametridan qat'iy nazar
		action = acl_types.ACL_ACTION_API_PERMIT_REFLECT
	default:
		action = acl_types.ACL_ACTION_API_DENY
	}

	// IP manzillarni parse qilish
	srcPrefix, err := ParseCIDR(input.Source)
	
	if err != nil {
		return acl_types.ACLRule{}, fmt.Errorf("source IP xatosi: %v", err)
	}

	dstPrefix, err := ParseCIDR(input.Destination)
	if err != nil {
		return acl_types.ACLRule{}, fmt.Errorf("destination IP xatosi: %v", err)
	}

	// Protokolni aniqlash (TCP=6, UDP=17, ICMP=1)
	protoNum := ParseProtocol(input.Protocol)

	return acl_types.ACLRule{
		IsPermit:               action,
		SrcPrefix:              srcPrefix,
		DstPrefix:              dstPrefix,
		Proto:                  ip_types.IPProto(protoNum),
		SrcportOrIcmptypeFirst: input.SrcPortFirst,
		SrcportOrIcmptypeLast:  input.SrcPortLast,
		DstportOrIcmpcodeFirst: input.DstPortFirst,
		DstportOrIcmpcodeLast:  input.DstPortLast,
		TCPFlagsMask:           input.TCPMask,
		TCPFlagsValue:          input.TCPValue,
	}, nil
}

// ParseCIDR string ko'rinishidagi IP/Mask ni VPP Prefix tipiga o'tkazadi
func ParseCIDR(cidr string) (ip_types.Prefix, error) {

	if cidr == "" || cidr == "any" {
		cidr = "0.0.0.0/0"
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip_types.Prefix{}, err
	}

	ones, _ := ipnet.Mask.Size()
	prefix := ip_types.Prefix{Len: uint8(ones)}

	if ip.To4() != nil {
		prefix.Address.Af = ip_types.ADDRESS_IP4
		var addr ip_types.IP4Address
		copy(addr[:], ip.To4())
		prefix.Address.Un.SetIP4(addr)
	} else {
		prefix.Address.Af = ip_types.ADDRESS_IP6
		var addr ip_types.IP6Address
		copy(addr[:], ip.To16())
		prefix.Address.Un.SetIP6(addr)
	}

	return prefix, nil
}

// ParseProtocol protokol nomini raqamga o'tkazadi
func ParseProtocol(proto string) uint8 {
	switch proto {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	default:
		return 0 // any
	}
}

// FormatPrefix VPP Prefix tipini o'qiladigan string ko'rinishiga o'tkazadi
func FormatPrefix(p ip_types.Prefix) string {
	var ip net.IP
	if p.Address.Af == ip_types.ADDRESS_IP4 {
		addr := p.Address.Un.GetIP4()
		ip = net.IP(addr[:])
		
		
	} else {
		addr := p.Address.Un.GetIP6()
		ip = net.IP(addr[:])
	}
	return fmt.Sprintf("%s/%d", ip.String(), p.Len)
}

// ConvertVPPRuleToWebInput - VPP dan kelgan rule ni Web format ga o'tkazish (frontend uchun)
func ConvertVPPRuleToWebInput(rule acl_types.ACLRule) WebInput {
	var action string
	switch rule.IsPermit {
	case acl_types.ACL_ACTION_API_DENY:
		action = "deny"
	case acl_types.ACL_ACTION_API_PERMIT:
		action = "permit"
	case acl_types.ACL_ACTION_API_PERMIT_REFLECT:
		action = "permit_reflect"
	default:
		action = "deny"
	}

	var protocol string
	switch rule.Proto {
	case 6:
		protocol = "tcp"
	case 17:
		protocol = "udp"
	case 1:
		protocol = "icmp"
	default:
		protocol = "tcp"
	}

	return WebInput{
		Action:       action,
		Source:       FormatPrefix(rule.SrcPrefix),
		Destination:  FormatPrefix(rule.DstPrefix),
		Protocol:     protocol,
		SrcPortFirst: rule.SrcportOrIcmptypeFirst,
		SrcPortLast:  rule.SrcportOrIcmptypeLast,
		DstPortFirst: rule.DstportOrIcmpcodeFirst,
		DstPortLast:  rule.DstportOrIcmpcodeLast,
		TCPMask:      rule.TCPFlagsMask,
		TCPValue:     rule.TCPFlagsValue,
	}
}

// NormalizePortRange - Port range ni normalize qiladi (0 bo'lsa ham qaytaradi)
func NormalizePortRange(first, last uint16) (uint16, uint16) {
	// Default qiymatlar
	if first == 0 && last == 0 {
		return 0, 65535
	}
	return first, last
}


// ParseMacAddress - String MAC manzilni VPP formatiga o'tkazadi
func ParseMacAddress(macStr string) (ethernet_types.MacAddress, error) {
	var macAddr ethernet_types.MacAddress
	hw, err := net.ParseMAC(macStr)
	if err != nil {
		return macAddr, err
	}
	copy(macAddr[:], hw)
	return macAddr, nil
}

// FormatMacAddress - VPP MAC manzilni string formatiga o'tkazadi
func FormatMacAddress(mac ethernet_types.MacAddress) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// CreateMacipRuleFromWebInput - UI dan kelgan ma'lumotni VPP MacipACLRule ga o'tkazadi
func CreateMacipRuleFromWebInput(input MacWebInput) (acl_types.MacipACLRule, error) {
	var action acl_types.ACLAction
	if input.Action == "permit" {
		action = acl_types.ACL_ACTION_API_PERMIT
	} else {
		action = acl_types.ACL_ACTION_API_DENY
	}

	mac, err := ParseMacAddress(input.SrcMac)
	if err != nil {
		return acl_types.MacipACLRule{}, fmt.Errorf("invalid source MAC: %v", err)
	}

	mask, err := ParseMacAddress(input.SrcMask)
	if err != nil {
		// Agar maska berilmasa, default full mask ishlatamiz
		mask = ethernet_types.MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}

	prefix, err := ParseCIDR(input.SrcPrefix) // Sizdagi mavjud helperdan foydalanamiz
	if err != nil {
		return acl_types.MacipACLRule{}, fmt.Errorf("invalid src prefix: %v", err)
	}

	return acl_types.MacipACLRule{
		IsPermit:   action,
		SrcMac:     mac,
		SrcMacMask: mask,
		SrcPrefix:  prefix,
	}, nil
}

// ConvertVPPToCustomMacRule - VPP dan kelgan MAC rule ni UI formatiga o'tkazish
func ConvertVPPToCustomMacRule(vppRule acl_types.MacipACLRule) MacACLRule {
	return MacACLRule{
		IsPermit:  uint8(vppRule.IsPermit),
		SrcMac:    FormatMacAddress(vppRule.SrcMac),
		SrcMask:   FormatMacAddress(vppRule.SrcMacMask),
		SrcPrefix: FormatPrefix(vppRule.SrcPrefix),
	}
}