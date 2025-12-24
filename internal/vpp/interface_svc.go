package vpp

import (
	"fmt"
	"net"

	dhcp "vpp-go-test/binapi/dhcp"
	interfaces "vpp-go-test/binapi/interface"
	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/ip"
	"vpp-go-test/binapi/ip_types"
)

// InterfaceInfo - Frontend uchun interfeys ma'lumotlari strukturasi
type InterfaceInfo struct {
	Index       uint32   `json:"index"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ip_addresses"`
	IsDHCP      bool     `json:"is_dhcp"` // Yangi maydon
}

func (v *VPPClient) GetActiveDHCPClients() map[uint32]bool {
    dhcpMap := make(map[uint32]bool)
    
    // Siz yuborgan bo'sh struktura ishlatiladi
    req := &dhcp.DHCPClientDump{} 
    stream := v.Channel.SendMultiRequest(req)
    
    for {
        reply := &dhcp.DHCPClientDetails{}
        stop, err := stream.ReceiveReply(reply)
        if stop {
            break
        }
        if err != nil {
            fmt.Printf("DHCP Dump xatosi: %v\n", err)
            break
        }
        
        // VPP logingizdagi [4] indeksi shu yerda reply.Client.SwIfIndex orqali keladi
        dhcpMap[uint32(reply.Client.SwIfIndex)] = true
    }
    return dhcpMap
}


func (v *VPPClient) GetInterfaces() ([]InterfaceInfo, error) {
    // 1. DHCP-si bor interfeyslar indekslarini olamiz
    activeDHCPs := v.GetActiveDHCPClients()

    var result []InterfaceInfo
    
    // 2. Barcha interfeyslarni VPP-dan so'raymiz
    req := &interfaces.SwInterfaceDump{
        SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
    }
    stream := v.Channel.SendMultiRequest(req)

    for {
        reply := &interfaces.SwInterfaceDetails{}
        stop, err := stream.ReceiveReply(reply)
        if stop {
            break
        }
        if err != nil {
            return nil, err
        }

        idx := uint32(reply.SwIfIndex)
        
        // UP/DOWN holati
        status := "DOWN"
        if reply.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0 {
            status = "UP"
        }

        result = append(result, InterfaceInfo{
            Index:  idx,
            Name:   reply.InterfaceName,
            Status: status,
            MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
                reply.L2Address[0], reply.L2Address[1], reply.L2Address[2],
                reply.L2Address[3], reply.L2Address[4], reply.L2Address[5]),
            IPAddresses: []string{},
            // Mapdan tekshiramiz: agar index 4 bo'lsa va mapda 4 bo'lsa -> true
            IsDHCP: activeDHCPs[idx], 
        })
    }

    // 3. IP manzillarni to'ldirish
    for i := range result {
        ips, _ := v.getIPsForInterface(result[i].Index)
        result[i].IPAddresses = ips
    }

    return result, nil
}

// getIPsForInterface - Yordamchi funksiya: bitta interfeys IP-larini olish
func (v *VPPClient) getIPsForInterface(swIfIndex uint32) ([]string, error) {
	var ips []string
	// IPv4 uchun tekshirish
	req := &ip.IPAddressDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsIPv6:    false,
	}
	stream := v.Channel.SendMultiRequest(req)
	for {
		reply := &ip.IPAddressDetails{}
		stop, err := stream.ReceiveReply(reply)
		if stop {
			break
		}
		if err != nil {
			continue
		}

		var ipStr string
		if reply.Prefix.Address.Af == ip_types.ADDRESS_IP4 {
			ip4 := reply.Prefix.Address.Un.GetIP4()
			ipStr = net.IP(ip4[:]).String()
		}
		ips = append(ips, fmt.Sprintf("%s/%d", ipStr, reply.Prefix.Len))
	}
	return ips, nil
}

// SetInterfaceState - Interfeysni ADMIN_UP yoki ADMIN_DOWN qilish
func (v *VPPClient) SetInterfaceState(swIfIndex uint32, isUp bool) error {
	var flags interface_types.IfStatusFlags
	if isUp {
		flags = interface_types.IF_STATUS_API_FLAG_ADMIN_UP
	}

	req := &interfaces.SwInterfaceSetFlags{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Flags:     flags,
	}
	reply := &interfaces.SwInterfaceSetFlagsReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}

// AddInterfaceIP - Interfeysga Statik IP biriktirish
func (v *VPPClient) AddInterfaceIP(swIfIndex uint32, ipWithMask string) error {
	address, network, err := net.ParseCIDR(ipWithMask)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	maskSize, _ := network.Mask.Size()

	var vppAddr ip_types.Address
	if address.To4() != nil {
		vppAddr.Af = ip_types.ADDRESS_IP4
		var ip4 ip_types.IP4Address
		copy(ip4[:], address.To4())
		vppAddr.Un.SetIP4(ip4)
	} else {
		vppAddr.Af = ip_types.ADDRESS_IP6
		var ip6 ip_types.IP6Address
		copy(ip6[:], address.To16())
		vppAddr.Un.SetIP6(ip6)
	}

	req := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     true,
		Prefix: ip_types.AddressWithPrefix{
			Address: vppAddr,
			Len:     uint8(maskSize),
		},
	}
	reply := &interfaces.SwInterfaceAddDelAddressReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}

// SetInterfaceDHCP - Interfeysda DHCP Client-ni yoqish yoki o'chirish
func (v *VPPClient) SetInterfaceDHCP(swIfIndex uint32, enable bool) error {
	// 1. DHCPni yoqishdan oldin interfeys mavjudligini tekshirish uchun 
	// kichik dummy request yuboramiz yoki xatoni ushlaymiz.
	
	req := &dhcp.DHCPClientConfig{
		Client: dhcp.DHCPClient{
			SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
			Hostname:      "vpp-gate",
			WantDHCPEvent: false,
		},
		IsAdd: enable,
	}
	
	reply := &dhcp.DHCPClientConfigReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	
	if err != nil {
		return fmt.Errorf("VPP bilan aloqa xatosi: %v", err)
	}

	// 2. Agar VPP -1 (allaqachon yoqilgan) yoki boshqa xato qaytarsa
	if reply.Retval != 0 {
		// Agar biz o'chirmoqchi bo'lsak va u allaqachon yo'q bo'lsa, xato deb hisoblamaymiz
		if !enable && reply.Retval == -1 { 
			return nil 
		}
		return fmt.Errorf("VPP xatosi (Retval: %d). Maslahat: Interfeys o'chirilgan bo'lishi mumkin", reply.Retval)
	}

	return nil
}

// CreateLoopback - Yangi Loopback virtual interfeysini yaratish
func (v *VPPClient) CreateLoopback() (uint32, error) {
	req := &interfaces.CreateLoopback{
		MacAddress: [6]byte{0, 0, 0, 0, 0, 0}, // 0 bo'lsa VPP o'zi generatsiya qiladi
	}
	reply := &interfaces.CreateLoopbackReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return 0, err
	}
	return uint32(reply.SwIfIndex), nil
}

// DeleteInterface - Loopback yoki boshqa virtual interfeyslarni o'chirish
func (v *VPPClient) DeleteInterface(swIfIndex uint32) error {
	// Loopback uchun maxsus o'chirish komandasi
	req := &interfaces.DeleteLoopback{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	reply := &interfaces.DeleteLoopbackReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}

// DelInterfaceIP - Interfeysdan ma'lum bir IPni o'chirish
func (v *VPPClient) DelInterfaceIP(swIfIndex uint32, ipWithMask string) error {
	address, network, err := net.ParseCIDR(ipWithMask)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %v", err)
	}
	maskSize, _ := network.Mask.Size()

	var vppAddr ip_types.Address
	if address.To4() != nil {
		vppAddr.Af = ip_types.ADDRESS_IP4
		var ip4 ip_types.IP4Address
		copy(ip4[:], address.To4())
		vppAddr.Un.SetIP4(ip4)
	}

	req := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     false, // O'chirish uchun false
		Prefix: ip_types.AddressWithPrefix{
			Address: vppAddr,
			Len:     uint8(maskSize),
		},
	}
	reply := &interfaces.SwInterfaceAddDelAddressReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}