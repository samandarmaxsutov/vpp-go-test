package vpp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	dhcp "vpp-go-test/binapi/dhcp"
	"vpp-go-test/binapi/ethernet_types"
	interfaces "vpp-go-test/binapi/interface"
	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/ip"
	"vpp-go-test/binapi/ip_types"
	tapv2 "vpp-go-test/binapi/tapv2"
	vhost "vpp-go-test/binapi/vhost_user"
	vmxnet3 "vpp-go-test/binapi/vmxnet3"
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
	v.apiMutex.Lock()
	defer v.apiMutex.Unlock()
	return v.getActiveDHCPClientsUnsafe()
}

// getActiveDHCPClientsUnsafe - internal version without mutex (caller must hold lock)
func (v *VPPClient) getActiveDHCPClientsUnsafe() map[uint32]bool {
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
	// Lock to prevent concurrent VPP API calls
	v.apiMutex.Lock()
	defer v.apiMutex.Unlock()

	activeDHCPs := v.getActiveDHCPClientsUnsafe()
	var result []InterfaceInfo

	// 1. Avval interfeyslarni VPPdan o'qiymiz
	req := &interfaces.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
	}
	stream := v.Channel.SendMultiRequest(req)

	// Detallarni vaqtinchalik saqlash (JSON uchun)
	var rawDetails []interfaces.SwInterfaceDetails

	for {
		reply := &interfaces.SwInterfaceDetails{}
		stop, err := stream.ReceiveReply(reply)
		if stop {
			break
		}
		if err != nil {
			return nil, err
		}

		rawDetails = append(rawDetails, *reply)

		// Frontend uchun natijani tayyorlash
		idx := uint32(reply.SwIfIndex)
		status := "DOWN"
		if reply.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0 {
			status = "UP"
		}

		result = append(result, InterfaceInfo{
			Index:  idx,
			Name:   reply.InterfaceName,
			Tag:    reply.Tag, // VPP dagi Tag (Custom name)
			Status: status,
			MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				reply.L2Address[0], reply.L2Address[1], reply.L2Address[2],
				reply.L2Address[3], reply.L2Address[4], reply.L2Address[5]),
			IPAddresses: []string{},
			IsDHCP:      activeDHCPs[idx],
		})
	}

	// 2. IPlarni yuklaymiz (Kanal bo'shagandan keyin)
	for i := range result {
		ips, _ := v.getIPsForInterface(result[i].Index)
		result[i].IPAddresses = ips
	}

	// 3. MANA SHU YERDA SAQLASH KERAK!
	// Hamma ma'lumot tayyor bo'lgach, alohida goroutine yoki to'g'ridan-to'g'ri chaqiring
	go v.SyncFullBackup(rawDetails, result)

	return result, nil
}

// func (v *VPPClient) GetInterfaces() ([]InterfaceInfo, error) {
// 	activeDHCPs := v.GetActiveDHCPClients()
// 	var result []InterfaceInfo

// 	req := &interfaces.SwInterfaceDump{
// 		SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
// 	}
// 	stream := v.Channel.SendMultiRequest(req)

// 	for {
// 		reply := &interfaces.SwInterfaceDetails{}
// 		stop, err := stream.ReceiveReply(reply)
// 		if stop {
// 			break
// 		}
// 		if err != nil {
// 			return nil, err
// 		}

// 		idx := uint32(reply.SwIfIndex)
// 		status := "DOWN"
// 		if reply.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0 {
// 			status = "UP"
// 		}

// 		result = append(result, InterfaceInfo{
// 			Index:  idx,
// 			Name:   reply.InterfaceName,
// 			Tag:    reply.Tag, // VPP dagi Tag (Custom name)
// 			Status: status,
// 			MAC: fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
// 				reply.L2Address[0], reply.L2Address[1], reply.L2Address[2],
// 				reply.L2Address[3], reply.L2Address[4], reply.L2Address[5]),
// 			IPAddresses: []string{},
// 			IsDHCP:      activeDHCPs[idx],
// 		})
// 	}

// 	for i := range result {
// 		ips, _ := v.getIPsForInterface(result[i].Index)
// 		result[i].IPAddresses = ips
// 	}

// 	return result, nil
// }

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
		ID:            id,   // Masalan: 0, 1, 2 yoki 0xffffffff (auto)
		UseRandomMac:  true, // VPP tomoni uchun MAC
		HostIfNameSet: true,
		HostIfName:    hostIfName, // Linuxda ko'rinadigan nomi (masalan: "vpp-tap0")
		TapFlags:      0,
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

type FullInterfaceBackup struct {
	Details  interfaces.SwInterfaceDetails `json:"details"`
	IPs      []string                      `json:"ips"`
	Vmx3Info *vmxnet3.Vmxnet3Details       `json:"vmx3_info,omitempty"`
}

// 2. To'liq saqlash funksiyasi (Details + IP)
// func (v *VPPClient) SaveAllToJSON() error {
//     var fullSnapshots []FullInterfaceBackup

//     // Interfeyslar ro'yxatini olish
//     req := &interfaces.SwInterfaceDump{
//         SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
//     }
//     stream := v.Channel.SendMultiRequest(req)

//     // Avval barcha interfeyslarni xotiraga yig'ib olamiz
//     var tempDetails []interfaces.SwInterfaceDetails
//     for {
//         reply := &interfaces.SwInterfaceDetails{}
//         stop, err := stream.ReceiveReply(reply)
//         if stop { break }
//         if err != nil { return err }
//         if reply.SwIfIndex != 0 {
//             tempDetails = append(tempDetails, *reply)
//         }
//     }

//     // Endi har bir interfeys uchun IP manzillarni alohida-alohida olamiz
//     // Bu loglardagi "already closed" xatosini oldini oladi
//     for _, detail := range tempDetails {
//         ips, _ := v.getIPsForInterface(uint32(detail.SwIfIndex))

//         fullSnapshots = append(fullSnapshots, FullInterfaceBackup{
//             Details: detail,
//             IPs:     ips,
//         })
//     }

//     // JSONga muhrlash
//     data, err := json.MarshalIndent(fullSnapshots, "", "  ")
//     if err != nil {
//         return err
//     }

//     filePath := "/etc/sarhad-guard/raw/interfaces_full.json"
//     os.MkdirAll("/etc/sarhad-guard/raw", 0755)

//     fmt.Printf("Barcha interfeyslar va IPlar saqlanmoqda: %s\n", filePath)
//     return os.WriteFile(filePath, data, 0644)
// }

func (v *VPPClient) SaveAllToJSON() error {
	var fullSnapshots []FullInterfaceBackup

	// 1. Umumiy detallarni olish
	rawDetails, err := v.dumpRawInterfaces()
	if err != nil {
		return err
	}

	// 2. Vmxnet3 detallarini olish (PCI manzillar uchun)
	vmx3List, _ := v.GetVmxnet3Details()
	vmx3Map := make(map[uint32]vmxnet3.Vmxnet3Details)
	for _, item := range vmx3List {
		vmx3Map[uint32(item.SwIfIndex)] = item
	}

	// 3. Ma'lumotlarni birlashtirish
	for _, detail := range rawDetails {
		swIdx := uint32(detail.SwIfIndex)
		ips, _ := v.getIPsForInterface(swIdx)

		snapshot := FullInterfaceBackup{
			Details: detail,
			IPs:     ips,
		}

		// Agar bu Vmxnet3 bo'lsa, PCI va Queue ma'lumotlarini qo'shamiz
		if val, ok := vmx3Map[swIdx]; ok {
			snapshot.Vmx3Info = &val
		}

		fullSnapshots = append(fullSnapshots, snapshot)
	}

	data, _ := json.MarshalIndent(fullSnapshots, "", "  ")
	return os.WriteFile("/etc/sarhad-guard/raw/interfaces_full.json", data, 0644)
}

// Yordamchi dump funksiyasi
func (v *VPPClient) dumpRawInterfaces() ([]interfaces.SwInterfaceDetails, error) {
	var list []interfaces.SwInterfaceDetails
	req := &interfaces.SwInterfaceDump{SwIfIndex: 0xffffffff}
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
		list = append(list, *reply)
	}
	return list, nil
}

func (v *VPPClient) SyncFullBackup(details []interfaces.SwInterfaceDetails, info []InterfaceInfo) {
	var backup []FullInterfaceBackup

	// Har ikkala ro'yxatni birlashtiramiz
	for i, d := range details {
		backup = append(backup, FullInterfaceBackup{
			Details: d,
			IPs:     info[i].IPAddresses,
		})
	}

	data, _ := json.MarshalIndent(backup, "", "  ")
	os.MkdirAll("/etc/sarhad-guard/raw", 0755)
	os.WriteFile("/etc/sarhad-guard/raw/interfaces_raw.json", data, 0644)
}

func (v *VPPClient) RestoreFromRaw() error {
	data, _ := os.ReadFile("/etc/sarhad-guard/raw/interfaces_raw.json")
	var saved []interfaces.SwInterfaceDetails
	json.Unmarshal(data, &saved)

	// Hozirgi yangi indekslarni olish
	currentIfs, _ := v.GetInterfaces()
	nameToNewIdx := make(map[string]uint32)
	for _, c := range currentIfs {
		nameToNewIdx[c.Name] = c.Index
	}

	for _, s := range saved {
		newIdx, exists := nameToNewIdx[s.InterfaceName]
		if exists {
			// Endi s.Flags, s.Tag kabilarni yangi newIdx orqali VPPga yuboring
			v.SetInterfaceState(newIdx, (s.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP) != 0)
			v.SetInterfaceTag(newIdx, s.Tag)
		}
	}
	return nil
}

// CreateVmxnet3 - Yangi Vmxnet3 interfeysini yaratish
func (v *VPPClient) CreateVmxnet3(pciAddr uint32, rxSize uint16, txSize uint16) (uint32, error) {
	// Ham HEX, ham o'nlik (Decimal) ko'rinishida print qilamiz
	fmt.Printf("Attempting to create Vmxnet3 with PCI: %d (Hex: 0x%x)\n", pciAddr, pciAddr)

	// req := &vmxnet3.Vmxnet3Create{
	// 	PciAddr:   pciAddr,
	// 	RxqSize:   rxSize, // Odatda 1024
	// 	TxqSize:   txSize, // Odatda 1024
	// 	RxqNum:    1,
	// 	TxqNum:    1,
	// 	Bind:      1,    // 1: Bind to driver
	// 	EnableGso: false, // Generic Segmentation Offload
	// }

	req := &vmxnet3.Vmxnet3Create{
		PciAddr:   pciAddr,
		RxqSize:   1024,
		RxqNum:    1,
		TxqSize:   1024,
		TxqNum:    1,
		Bind:      1, // uint8 formatida
		EnableGso: false,
	}
	reply := &vmxnet3.Vmxnet3CreateReply{}
	err := v.Channel.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return 0, fmt.Errorf("RPC Error: %v", err)
	}

	// VPP xato qaytarsa (Retval != 0)
	if reply.Retval != 0 {
		return 0, fmt.Errorf("VPP API Error: Retval %d", reply.Retval)
	}

	swIfIndex := uint32(reply.SwIfIndex)
	fmt.Printf("Successfully created Vmxnet3 interface! swIfIndex: %d\n", swIfIndex)

	// Interfeys yaratilgach uni yoqish (Admin UP)
	_ = v.SetInterfaceState(swIfIndex, true)

	return swIfIndex, nil
}

// DeleteVmxnet3 - Vmxnet3 interfeysini o'chirish
func (v *VPPClient) DeleteVmxnet3(swIfIndex uint32) error {
	req := &vmxnet3.Vmxnet3Delete{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	}
	reply := &vmxnet3.Vmxnet3DeleteReply{}
	return v.Channel.SendRequest(req).ReceiveReply(reply)
}

// GetVmxnet3Details - Faqat Vmxnet3 ga xos texnik ma'lumotlarni olish (PCI, Queue size va h.k)
func (v *VPPClient) GetVmxnet3Details() ([]vmxnet3.Vmxnet3Details, error) {
	var details []vmxnet3.Vmxnet3Details
	req := &vmxnet3.Vmxnet3Dump{}

	stream := v.Channel.SendMultiRequest(req)
	for {
		reply := &vmxnet3.Vmxnet3Details{}
		stop, err := stream.ReceiveReply(reply)
		if stop {
			break
		}
		if err != nil {
			return nil, err
		}
		details = append(details, *reply)
	}
	return details, nil
}

func ParsePciAddress(address string) uint32 {
	// Bo'shliqlarni olib tashlaymiz
	address = strings.TrimSpace(address)

	var domain, bus, slot, function uint32

	// Formatni qat'iy tekshiramiz: 0000:03:00.0
	_, err := fmt.Sscanf(address, "%x:%x:%x.%x", &domain, &bus, &slot, &function)
	if err != nil {
		fmt.Printf("PCI Parsing Error: %v for address: %s\n", err, address)
		return 0
	}

	// Bitlarni surish
	pci := domain | (bus << 16) | (slot << 24) | (function << 29)

	// LOG: Statik ishlagan 196608 bilan solishtirish uchun
	fmt.Printf("DEBUG: Address=%s -> Result=%d (Hex: 0x%x)\n", address, pci, pci)

	return pci
}

// PCIDevice - Frontend uchun PCI qurilma ma'lumoti
type PCIDevice struct {
	PciAddr     string `json:"pci_addr"`    // 0000:03:00.0
	PciValue    uint32 `json:"pci_value"`   // 196608
	Description string `json:"description"` // VMware VMXNET3
	IsBound     bool   `json:"is_bound"`    // VPP interfeysi bormi?
}

func (v *VPPClient) GetLinuxPciDevices() ([]PCIDevice, error) {
	var devices []PCIDevice

	// 1. VPP-da allaqachon yaratilgan interfeyslarni olamiz
	boundPciMap := make(map[uint32]bool)
	existingVmx3, _ := v.GetVmxnet3Details()
	for _, item := range existingVmx3 {
		boundPciMap[uint32(item.PciAddr)] = true
	}

	pciRoot := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciRoot)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		pciAddr := entry.Name()

		// Vendor va Device ID o'qish
		vByte, _ := os.ReadFile(filepath.Join(pciRoot, pciAddr, "vendor"))
		dByte, _ := os.ReadFile(filepath.Join(pciRoot, pciAddr, "device"))
		vendor := strings.TrimSpace(string(vByte))
		device := strings.TrimSpace(string(dByte))

		// VMXNET3: 0x15ad & 0x07b0
		if vendor == "0x15ad" && device == "0x07b0" {
			pciVal := ParsePciAddress(pciAddr)

			// Faqat VPP-da interfeys sifatida yaratilmagan bo'lsa
			if !boundPciMap[pciVal] {
				// Drayver nomini aniqlaymiz (vfio-pci yoki vmxnet3)
				// /sys/bus/pci/devices/0000:03:00.0/driver -> ../../../bus/pci/drivers/vfio-pci
				driverPath, _ := os.Readlink(filepath.Join(pciRoot, pciAddr, "driver"))
				driverName := filepath.Base(driverPath)

				// Agar kernelda bo'lsa interfeys nomini olamiz
				linuxName := ""
				netPath := filepath.Join(pciRoot, pciAddr, "net")
				if netEntries, err := os.ReadDir(netPath); err == nil && len(netEntries) > 0 {
					linuxName = netEntries[0].Name()
				}

				description := "VMware VMXNET3"
				if linuxName != "" {
					description = fmt.Sprintf("VMware VMXNET3 (%s)", linuxName)
				}

				devices = append(devices, PCIDevice{
					PciAddr:     pciAddr,
					PciValue:    pciVal,
					Description: fmt.Sprintf("%s [Driver: %s]", description, driverName),
					IsBound:     false,
				})
			}
		}
	}
	return devices, nil
}

// GetInterfaceIndexByName - Get interface index by name
func (v *VPPClient) GetInterfaceIndexByName(name string) (uint32, error) {
	interfaces, err := v.GetInterfaces()
	if err != nil {
		return 0, err
	}

	for _, iface := range interfaces {
		if iface.Name == name || iface.Tag == name {
			return iface.Index, nil
		}
	}

	return 0, fmt.Errorf("interface '%s' not found", name)
}

// CreateTapWithHostIP - Create TAP interface with host-side IP address
func (v *VPPClient) CreateTapWithHostIP(id uint32, hostIfName string, hostIP string) (uint32, error) {
	// Parse host IP to get address and prefix
	ip, ipNet, err := net.ParseCIDR(hostIP)
	if err != nil {
		return 0, fmt.Errorf("invalid host IP: %v", err)
	}

	prefixLen, _ := ipNet.Mask.Size()
	var hostIP4Addr ip_types.IP4Address
	copy(hostIP4Addr[:], ip.To4())

	req := &tapv2.TapCreateV3{
		ID:               id,
		UseRandomMac:     true,
		HostIfNameSet:    true,
		HostIfName:       hostIfName,
		HostIP4PrefixSet: true,
		HostIP4Prefix: ip_types.IP4AddressWithPrefix{
			Address: hostIP4Addr,
			Len:     uint8(prefixLen),
		},
		TapFlags: 0,
	}

	reply := &tapv2.TapCreateV3Reply{}
	err = v.Channel.SendRequest(req).ReceiveReply(reply)
	if err != nil {
		return 0, fmt.Errorf("failed to create TAP: %v", err)
	}

	swIfIndex := uint32(reply.SwIfIndex)

	// Bring interface up
	_ = v.SetInterfaceState(swIfIndex, true)

	return swIfIndex, nil
}
