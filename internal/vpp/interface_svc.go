package vpp

import (
	"fmt"
	"net"
	"strings"
	dhcp "vpp-go-test/binapi/dhcp"
	interfaces "vpp-go-test/binapi/interface"
	tapv2 "vpp-go-test/binapi/tapv2"
	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/ip"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/binapi/ethernet_types"
	vhost "vpp-go-test/binapi/vhost_user" // vhost-user uchun import
)

// InterfaceInfo - Frontend uchun interfeys ma'lumotlari strukturasi
type InterfaceInfo struct {
	Index       uint32   `json:"index"`
	Name        string   `json:"name"`
	Tag         string   `json:"tag"` // Foydalanuvchi bergan nom (alias)
	Status      string   `json:"status"`
	MAC         string   `json:"mac"`
	IPAddresses []string `json:"ip_addresses"`
	IsDHCP      bool     `json:"is_dhcp"`
}

// --- INTERFACE LIST & STATS ---

func (v *VPPClient) GetActiveDHCPClients() map[uint32]bool {
	dhcpMap := make(map[uint32]bool)
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
		dhcpMap[uint32(reply.Client.SwIfIndex)] = true
	}
	return dhcpMap
}

func (v *VPPClient) GetInterfaces() ([]InterfaceInfo, error) {
	activeDHCPs := v.GetActiveDHCPClients()
	var result []InterfaceInfo

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
		status := "DOWN"
		if reply.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0 {
			status = "UP"
		}

		result = append(result, InterfaceInfo{
			Index: idx,
			Name:  reply.InterfaceName,
			Tag:   reply.Tag, // VPP dagi Tag (Custom name)
			Status: status,
			MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				reply.L2Address[0], reply.L2Address[1], reply.L2Address[2],
				reply.L2Address[3], reply.L2Address[4], reply.L2Address[5]),
			IPAddresses: []string{},
			IsDHCP:      activeDHCPs[idx],
		})
	}

	for i := range result {
		ips, _ := v.getIPsForInterface(result[i].Index)
		result[i].IPAddresses = ips
	}

	return result, nil
}

func (v *VPPClient) getIPsForInterface(swIfIndex uint32) ([]string, error) {
	var ips []string
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

// --- INTERFACE MANAGEMENT ---

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

// SetInterfaceTag - Interfeysga tavsiflovchi nom (Tag) berish (Alias nomi)
func (v *VPPClient) SetInterfaceTag(swIfIndex uint32, tag string) error {
	req := &interfaces.SwInterfaceTagAddDel{
		IsAdd:     true,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Tag:       tag,
	}
	reply := &interfaces.SwInterfaceTagAddDelReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}

func (v *VPPClient) SetInterfaceMac(swIfIndex uint32, macStr string) error {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		return err
	}
	var vppMac ethernet_types.MacAddress
	copy(vppMac[:], mac)

	req := &interfaces.SwInterfaceSetMacAddress{
		SwIfIndex:  interface_types.InterfaceIndex(swIfIndex),
		MacAddress: vppMac,
	}
	reply := &interfaces.SwInterfaceSetMacAddressReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}


// --- IP & DHCP ---

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
	}
	req := &interfaces.SwInterfaceAddDelAddress{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     true,
		Prefix: ip_types.AddressWithPrefix{
			Address: vppAddr,
			Len:     uint8(maskSize),
		},
	}
	return v.Channel.SendRequest(req).ReceiveReply(&interfaces.SwInterfaceAddDelAddressReply{})
}

func (v *VPPClient) DelInterfaceIP(swIfIndex uint32, ipWithMask string) error {
	address, network, err := net.ParseCIDR(ipWithMask)
	if err != nil {
		return err
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
		IsAdd:     false,
		Prefix: ip_types.AddressWithPrefix{
			Address: vppAddr,
			Len:     uint8(maskSize),
		},
	}
	return v.Channel.SendRequest(req).ReceiveReply(&interfaces.SwInterfaceAddDelAddressReply{})
}

func (v *VPPClient) SetInterfaceDHCP(swIfIndex uint32, enable bool) error {
	req := &dhcp.DHCPClientConfig{
		Client: dhcp.DHCPClient{
			SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
			Hostname:      "vpp-node",
			WantDHCPEvent: false,
		},
		IsAdd: enable,
	}
	reply := &dhcp.DHCPClientConfigReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return err
	}
	if reply.Retval != 0 && !(enable == false && reply.Retval == -1) {
		return fmt.Errorf("Error: %d", reply.Retval)
	}
	return nil
}

// --- VIRTUAL INTERFACES (LOOPBACK & VHOST) ---

func (v *VPPClient) CreateLoopback() (uint32, error) {
	req := &interfaces.CreateLoopback{
		MacAddress: [6]byte{0, 0, 0, 0, 0, 0},
	}
	reply := &interfaces.CreateLoopbackReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	return uint32(reply.SwIfIndex), err
}

// CreateVhostUser - VMlar uchun vhost-user interfeys yaratish
func (v *VPPClient) CreateVhostUser(socketFile string, isServer bool) (uint32, error) {
	req := &vhost.CreateVhostUserIf{
		IsServer:     isServer,
		SockFilename: socketFile,
	}
	reply := &vhost.CreateVhostUserIfReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return 0, err
	}
	return uint32(reply.SwIfIndex), nil
}
// CreateTap - Linux Kernel bilan bog'lanuvchi TAP interfeys yaratish
// CreateTap - Linux Kernel bilan integratsiya qilingan TAP yaratish
func (v *VPPClient) CreateTap(id uint32, hostIfName string) (uint32, error) {
    req := &tapv2.TapCreateV2{
        ID:               id,               // Masalan: 0, 1, 2 yoki 0xffffffff (auto)
        UseRandomMac:     true,             // VPP tomoni uchun MAC
        HostIfNameSet:    true,
        HostIfName:       hostIfName,       // Linuxda ko'rinadigan nomi (masalan: "vpp-tap0")
        TapFlags:         0,
        // Agar Linux tomonida IP-ni ham avtomatik bermoqchi bo'lsangiz:
        // HostIP4PrefixSet: false, 
    }

    reply := &tapv2.TapCreateV2Reply{}
    err := v.Channel.SendRequest(req).ReceiveReply(reply)
    if err != nil {
        return 0, err
    }
    
    // Interfeys yaratilgach, uni ADMIN_UP holatiga o'tkazish shart
    swIfIndex := uint32(reply.SwIfIndex)
    _ = v.SetInterfaceState(swIfIndex, true)
    
    return swIfIndex, nil
}
// DeleteInterface - Interfeys turiga qarab to'g'ri API orqali o'chirish
func (v *VPPClient) DeleteInterface(swIfIndex uint32, interfaceName string) error {
    name := strings.ToLower(interfaceName)

    // 1. Loopback bo'lsa
    if strings.HasPrefix(name, "loop") {
        return v.Channel.SendRequest(&interfaces.DeleteLoopback{
            SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
        }).ReceiveReply(&interfaces.DeleteLoopbackReply{})
    }

    // 2. Vhost-user bo'lsa (vhost yoki VirtualEthernet deb nomlanishi mumkin)
    if strings.HasPrefix(name, "vhost") || strings.HasPrefix(name, "virtualethernet") {
        return v.Channel.SendRequest(&vhost.DeleteVhostUserIf{
            SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
        }).ReceiveReply(&vhost.DeleteVhostUserIfReply{})
    }

    // 3. TAP bo'lsa (Firewall uchun yaratganingizda kerak bo'ladi)
    if strings.HasPrefix(name, "tap") {
        return v.Channel.SendRequest(&tapv2.TapDeleteV2{
            SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
        }).ReceiveReply(&tapv2.TapDeleteV2Reply{})
    }

	// VLAN (Sub-interface) bo'lsa. Odatda "parent.vlan" ko'rinishida bo'ladi (masalan: eth0.100)
    if strings.Contains(name, ".") {
        return v.Channel.SendRequest(&interfaces.DeleteSubif{
            SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
        }).ReceiveReply(&interfaces.DeleteSubifReply{})
    }

    return fmt.Errorf("o'chirib bo'lmaydigan interfeys turi: %s (faqat virtual interfeyslar o'chiriladi)", interfaceName)
}

// CreateVlanSubif - Fizik interfeys ustida yangi VLAN (dot1q) sub-interfeys yaratadi
func (v *VPPClient) CreateVlanSubif(parentSwIfIndex uint32, vlanID uint32) (uint32, error) {
    req := &interfaces.CreateVlanSubif{
        SwIfIndex: interface_types.InterfaceIndex(parentSwIfIndex),
        VlanID:    vlanID,
    }
    
    reply := &interfaces.CreateVlanSubifReply{}
    err := v.Channel.SendRequest(req).ReceiveReply(reply)
    if err != nil {
        return 0, fmt.Errorf("VLAN yaratishda xato: %v", err)
    }

    swIfIndex := uint32(reply.SwIfIndex)

    // Sub-interfeysni yoqish
    _ = v.SetInterfaceState(swIfIndex, true)

    return swIfIndex, nil
}