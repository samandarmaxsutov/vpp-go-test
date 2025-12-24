package nat44

import (
	"fmt"
	"net"
	"vpp-go-test/binapi/ip_types"
)

// IPToVppAddress IP stringni VPP ip_types.Address formatiga xavfsiz o'tkazadi
func IPToVppAddress(ipAddr string) (ip_types.Address, error) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return ip_types.Address{}, fmt.Errorf("noto'g'ri IP manzil: %s", ipAddr)
	}

	var addr ip_types.Address
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 mantiqi
		addr.Af = ip_types.ADDRESS_IP4
		var ip4Addr ip_types.IP4Address
		copy(ip4Addr[:], ip4)
		addr.Un.SetIP4(ip4Addr)
	} else {
		// IPv6 mantiqi
		addr.Af = ip_types.ADDRESS_IP6
		var ip6Addr ip_types.IP6Address
		copy(ip6Addr[:], ip.To16())
		addr.Un.SetIP6(ip6Addr)
	}
	return addr, nil
}

// IPToVppIP4Address faqat IPv4 kutayotgan APIlar uchun (masalan nat44_add_del_address_range)
func IPToVppIP4Address(ipAddr string) (ip_types.IP4Address, error) {
	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return ip_types.IP4Address{}, fmt.Errorf("noto'g'ri IPv4 manzil: %s", ipAddr)
	}
	var addr ip_types.IP4Address
	copy(addr[:], ip)
	return addr, nil
}

// ProtoToUint protokollarni VPP binary API (IP protocol numbers) formatiga o'tkazadi
func ProtoToUint(proto string) uint8 {
	switch proto {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmp6":
		return 58
	default:
		// Default sifatida TCP yoki 0 (wildcard) qaytarish loyiha talabiga bog'liq
		return 6 
	}
}

// VppIP4AddressToString VPP dan kelgan IPni stringga o'tkazish (Jadvalda ko'rsatish uchun)
func VppIP4AddressToString(addr ip_types.IP4Address) string {
	return net.IP(addr[:]).String()
}

// IP4Address'ni string'ga o'girish (masalan: [192, 168, 1, 1] -> "192.168.1.1")
func ipToString(ip ip_types.IP4Address) string {
    return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func protoToString(p uint16) string {
    switch p {
    case 6: return "TCP"
    case 17: return "UDP"
    case 1: return "ICMP"
    default: return fmt.Sprintf("%d", p)
    }
}