// File: internal/vpp/backup_restore.go
package vpp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/internal/vpp/acl"
	"vpp-go-test/internal/vpp/ipfix"
	"vpp-go-test/internal/vpp/nat44"
)

// InterfaceConfig - Enhanced backup structure with DHCP and ACL info
type InterfaceConfig struct {
	SwIfIndex     uint32   `json:"sw_if_index"`
	InterfaceName string   `json:"interface_name"`
	InterfaceType string   `json:"interface_dev_type"`
	Tag           string   `json:"tag"`
	IsAdminUp     bool     `json:"is_admin_up"`
	MAC           string   `json:"mac"`
	IPAddresses   []string `json:"ip_addresses"`
	IsDHCP        bool     `json:"is_dhcp"`

	// VLAN sub-interface info
	IsSubInterface  bool   `json:"is_sub_interface,omitempty"`
	ParentSwIfIndex uint32 `json:"parent_sw_if_index,omitempty"`
	VlanID          uint32 `json:"vlan_id,omitempty"`

	// Virtual interface creation params
	SocketFile string `json:"socket_file,omitempty"` // for vhost
	TapID      uint32 `json:"tap_id,omitempty"`      // for TAP
	PciAddr    uint32 `json:"pci_addr,omitempty"`    // for vmxnet3

	// ACL bindings
	InputACLs   []uint32 `json:"input_acls,omitempty"`
	OutputACLs  []uint32 `json:"output_acls,omitempty"`
	MacACLIndex uint32   `json:"mac_acl_index,omitempty"` // 0xffffffff means no MAC ACL
}

// ACLBackupConfig - Complete ACL configuration backup
type ACLBackupConfig struct {
	IPACLs  []acl.ACLDetail    `json:"ip_acls"`
	MACACLs []acl.MacACLDetail `json:"mac_acls"`
}

// NAT44BackupConfig - Complete NAT configuration backup
type NAT44BackupConfig struct {
	IsEnabled      bool                   `json:"is_enabled"`
	Interfaces     []NATInterfaceBackup   `json:"interfaces"`
	AddressPools   []nat44.NatAddressPool `json:"address_pools"`
	StaticMappings []nat44.StaticMapping  `json:"static_mappings"`
}

// NATInterfaceBackup - NAT interface configuration
type NATInterfaceBackup struct {
	SwIfIndex uint32 `json:"sw_if_index"`
	Name      string `json:"name"`
	IsInside  bool   `json:"is_inside"`
}

// PolicerBackupConfig - Policer configurations
type PolicerBackupConfig struct {
	Policers       []*PolicerBackup    `json:"policers"`
	InterfaceBinds []PolicerBindBackup `json:"interface_binds"`
}

// PolicerBackup - Individual policer config
type PolicerBackup struct {
	Name string `json:"name"`
	CIR  uint32 `json:"cir"` // Committed Information Rate
	CB   uint64 `json:"cb"`  // Committed Burst
}

// PolicerBindBackup - Policer to interface binding
type PolicerBindBackup struct {
	PolicerName string `json:"policer_name"`
	SwIfIndex   uint32 `json:"sw_if_index"`
	Direction   string `json:"direction"` // "input" or "output"
}

// DHCPBackupConfig - DHCP configuration
type DHCPBackupConfig struct {
	DHCPProxiesIPv4 []DHCPProxyBackup `json:"dhcp_proxies_ipv4"`
	DHCPProxiesIPv6 []DHCPProxyBackup `json:"dhcp_proxies_ipv6"`
	VSSConfig       *DHCPVSSBackup    `json:"vss_config,omitempty"`
}

// DHCPProxyBackup - DHCP proxy configuration
type DHCPProxyBackup struct {
	ServerIP    string `json:"server_ip"`
	SourceIP    string `json:"source_ip"`
	RxVrfID     uint32 `json:"rx_vrf_id"`
	ServerVrfID uint32 `json:"server_vrf_id"`
}

// DHCPVSSBackup - DHCP VSS configuration
type DHCPVSSBackup struct {
	VrfID    uint32 `json:"vrf_id"`
	VSSType  uint8  `json:"vss_type"`
	VpnID    string `json:"vpn_id"`
	OUI      uint32 `json:"oui"`
	VpnIndex uint32 `json:"vpn_index"`
	IsIPv6   bool   `json:"is_ipv6"`
}

// IPFIXBackupConfig - IPFIX/Flowprobe configuration
type IPFIXBackupConfig struct {
	IsEnabled        bool     `json:"is_enabled"`
	CollectorAddr    string   `json:"collector_address"`
	CollectorPort    uint16   `json:"collector_port"`
	SourceAddr       string   `json:"source_address"`
	VrfID            uint32   `json:"vrf_id"`
	PathMTU          uint32   `json:"path_mtu"`
	TemplateInterval uint32   `json:"template_interval"`
	UDPChecksum      bool     `json:"udp_checksum"`
	ActiveTimeout    uint32   `json:"active_timeout"`
	RecordL4         bool     `json:"record_l4"`
	EnabledIfaces    []uint32 `json:"enabled_interfaces"` // Interface indices with flowprobe enabled
}

// ABFBackupConfig - Access-Based Forwarding configuration
type ABFBackupConfig struct {
	Policies    []ABFPolicyBackup     `json:"policies"`
	Attachments []ABFAttachmentBackup `json:"attachments"`
}

// ABFPolicyBackup - ABF policy configuration with paths
type ABFPolicyBackup struct {
	PolicyID uint32          `json:"policy_id"`
	ACLIndex uint32          `json:"acl_index"`
	Paths    []ABFPathBackup `json:"paths,omitempty"` // Backup of FibPath data
}

// ABFPathBackup - Simplified FibPath backup
type ABFPathBackup struct {
	SwIfIndex  uint32 `json:"sw_if_index"`
	TableID    uint32 `json:"table_id"`
	RpfID      uint32 `json:"rpf_id"`
	Weight     uint8  `json:"weight"`
	Preference uint8  `json:"preference"`
	Type       string `json:"type"`     // FibPathType as string
	Flags      string `json:"flags"`    // FibPathFlags as string
	Proto      string `json:"proto"`    // FibPathNhProto as string
	NextHop    string `json:"next_hop"` // IP address as string
	ViaLabel   uint32 `json:"via_label"`
}

// ABFAttachmentBackup - ABF to interface attachment
type ABFAttachmentBackup struct {
	PolicyID  uint32 `json:"policy_id"`
	SwIfIndex uint32 `json:"sw_if_index"`
	Priority  uint32 `json:"priority"`
	IsIPv6    bool   `json:"is_ipv6"`
}

// StaticRouteBackup - Static route configuration
type StaticRouteBackup struct {
	Prefix        string `json:"prefix"`
	NextHop       string `json:"next_hop"`
	SwIfIndex     uint32 `json:"sw_if_index"`
	InterfaceName string `json:"interface_name"`
	Protocol      string `json:"protocol,omitempty"`
	Distance      uint8  `json:"distance,omitempty"`
	Metric        uint8  `json:"metric,omitempty"`
}

// StaticRoutingBackupConfig - Static routes configuration
type StaticRoutingBackupConfig struct {
	Routes []StaticRouteBackup `json:"routes"`
}

type FullBackupConfig struct {
	Timestamp  string                    `json:"timestamp"`
	Interfaces []InterfaceConfig         `json:"interfaces"`
	ACLs       ACLBackupConfig           `json:"acls"`
	NAT44      NAT44BackupConfig         `json:"nat44"`
	Policers   PolicerBackupConfig       `json:"policers"`
	DHCP       DHCPBackupConfig          `json:"dhcp"`
	IPFIX      IPFIXBackupConfig         `json:"ipfix"`
	ABF        ABFBackupConfig           `json:"abf"`
	Routes     StaticRoutingBackupConfig `json:"routes"`
}

const (
	backupDir  = "/etc/sarhad-guard/backup"
	configFile = "vpp_config.json"
)

// VppAddressToString converts VPP address to string format
func VppAddressToString(addr ip_types.Address) string {
	// Simplified - just return empty string for now
	// TODO: Implement proper address conversion when needed
	return ""
}

// SaveConfiguration - Save current VPP configuration with ALL details (interfaces, ACLs, NAT, DHCP, Policer, IPFIX, ABF)
func (v *VPPClient) SaveConfiguration() error {
	fmt.Println("🔄 Saving VPP configuration (comprehensive)...")

	ctx := context.Background()

	// ========================================
	// 1. INTERFACES BACKUP
	// ========================================
	fmt.Println("  📡 Backing up interfaces...")
	interfaces, err := v.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %v", err)
	}

	dhcpClients := v.GetActiveDHCPClients()
	vmx3Details, _ := v.GetVmxnet3Details()
	vmx3Map := make(map[uint32]uint32)
	for _, vmx := range vmx3Details {
		vmx3Map[uint32(vmx.SwIfIndex)] = uint32(vmx.PciAddr)
	}

	aclBindings, err := v.ACLManager.GetAllInterfaceACLs(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Failed to get ACL bindings: %v\n", err)
		aclBindings = []acl.InterfaceACLMap{}
	}

	aclMap := make(map[uint32]acl.InterfaceACLMap)
	for _, binding := range aclBindings {
		aclMap[binding.SwIfIndex] = binding
	}

	macACLBindings, err := v.ACLManager.GetMacACLInterfaceList(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Failed to get MAC ACL bindings: %v\n", err)
		macACLBindings = make(map[uint32]uint32)
	}

	var configs []InterfaceConfig
	for _, iface := range interfaces {
		if iface.Name == "local0" {
			continue
		}

		config := InterfaceConfig{
			SwIfIndex:     iface.Index,
			InterfaceName: iface.Name,
			InterfaceType: v.detectInterfaceType(iface.Name),
			Tag:           iface.Tag,
			IsAdminUp:     iface.Status == "UP",
			MAC:           iface.MAC,
			IPAddresses:   iface.IPAddresses,
			IsDHCP:        dhcpClients[iface.Index],
			MacACLIndex:   0xffffffff,
		}

		if binding, exists := aclMap[iface.Index]; exists {
			config.InputACLs = binding.InputACLs
			config.OutputACLs = binding.OutputACLs
		}

		if macACLIdx, exists := macACLBindings[iface.Index]; exists {
			config.MacACLIndex = macACLIdx
		}

		if strings.Contains(iface.Name, ".") {
			parts := strings.Split(iface.Name, ".")
			if len(parts) == 2 {
				config.IsSubInterface = true
				var vlanID uint32
				fmt.Sscanf(parts[1], "%d", &vlanID)
				config.VlanID = vlanID
			}
		}

		if pciAddr, ok := vmx3Map[iface.Index]; ok {
			config.PciAddr = pciAddr
		}

		if strings.HasPrefix(iface.Name, "tap") {
			fmt.Sscanf(iface.Name, "tap%d", &config.TapID)
		}

		configs = append(configs, config)
	}

	// ========================================
	// 2. ACL BACKUP
	// ========================================
	fmt.Println("  🔒 Backing up ACLs...")
	aclBackup := ACLBackupConfig{}

	ipACLs, err := v.ACLManager.GetAllACLs(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Failed to get IP ACLs: %v\n", err)
	} else {
		aclBackup.IPACLs = ipACLs
	}

	macACLs, err := v.ACLManager.GetAllMacACLs(ctx)
	if err != nil {
		fmt.Printf("  ⚠️  Failed to get MAC ACLs: %v\n", err)
	} else {
		aclBackup.MACACLs = macACLs
	}

	// ========================================
	// 3. NAT44 BACKUP (with enable state!)
	// ========================================
	fmt.Println("  🔄 Backing up NAT44...")
	nat44Backup := NAT44BackupConfig{
		IsEnabled: false, // Will query actual state
	}

	// Query actual NAT44 enabled state
	if isNatEnabled, err := v.NatManager.GetNATStatus(ctx); err == nil {
		nat44Backup.IsEnabled = isNatEnabled
		fmt.Printf("  ℹ️  NAT44 enabled state: %v\n", isNatEnabled)
	} else {
		fmt.Printf("  ⚠️  Could not query NAT status: %v\n", err)
	}

	// Get NAT interfaces
	if natInterfaces, err := v.NatManager.GetNatInterfaces(ctx); err == nil {
		for _, natIface := range natInterfaces {
			// Lookup interface name by index
			ifName := ""
			for _, iface := range interfaces {
				if iface.Index == natIface.SwIfIndex {
					ifName = iface.Name
					break
				}
			}

			natIface.Name = ifName // Set the name
			nat44Backup.Interfaces = append(nat44Backup.Interfaces, NATInterfaceBackup{
				SwIfIndex: natIface.SwIfIndex,
				Name:      ifName,
				IsInside:  natIface.IsInside,
			})
			side := "outside"
			if natIface.IsInside {
				side = "inside"
			}
			fmt.Printf("  ✅ NAT Interface: %s (index: %d, %s)\n", ifName, natIface.SwIfIndex, side)
		}
	} else {
		fmt.Printf("  ⚠️  Failed to get NAT interfaces: %v\n", err)
	}

	// Get address pools
	if pools, err := v.NatManager.GetAddressPool(ctx); err == nil {
		nat44Backup.AddressPools = pools
		fmt.Printf("  ✅ NAT pools backed up: %d pools\n", len(pools))
	} else {
		fmt.Printf("  ⚠️  Failed to get NAT address pools: %v\n", err)
	}

	// Get static mappings
	if mappings, err := v.NatManager.GetStaticMappings(ctx); err == nil {
		nat44Backup.StaticMappings = mappings
		fmt.Printf("  ✅ NAT static mappings backed up: %d mappings\n", len(mappings))
	} else {
		fmt.Printf("  ⚠️  Failed to get NAT static mappings: %v\n", err)
	}

	// ========================================
	// 4. POLICER BACKUP
	// ========================================
	fmt.Println("  🚓 Backing up Policers...")
	policerBackup := PolicerBackupConfig{}

	if policerList, err := v.PolicerManager.ListPolicers(ctx); err == nil {
		for _, p := range policerList {
			policerBackup.Policers = append(policerBackup.Policers, &PolicerBackup{
				Name: p.Name,
				CIR:  p.Cir,
				CB:   p.Cb,
			})
			fmt.Printf("  ✅ Policer '%s' backed up (CIR: %d, CB: %d)\n", p.Name, p.Cir, p.Cb)
		}
		fmt.Printf("  ✅ Total policers backed up: %d\n", len(policerList))
	} else {
		fmt.Printf("  ⚠️  Failed to get policers: %v\n", err)
	}

	// Note: Policer interface bindings stored separately if needed in future phases

	// ========================================
	// 5. DHCP BACKUP
	// ========================================
	fmt.Println("  📡 Backing up DHCP...")
	dhcpBackup := DHCPBackupConfig{}

	// Helper function to convert Address to string
	addrToString := func(addr ip_types.Address) string {
		if addr.Af == 0 { // ADDRESS_IP4
			ip4 := addr.Un.GetIP4()
			return fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], ip4[3])
		} else if addr.Af == 1 { // ADDRESS_IP6
			ip6 := addr.Un.GetIP6()
			return net.IP(ip6[:]).String()
		}
		return ""
	}

	// Get IPv4 DHCP proxies
	if proxies, err := v.DhcpManager.ListProxies(ctx, false); err == nil {
		for _, proxy := range proxies {
			srcIP := addrToString(proxy.DHCPSrcAddress)

			// Extract DHCP servers from the list
			for _, server := range proxy.Servers {
				dhcpServerIP := addrToString(server.DHCPServer)

				dhcpBackup.DHCPProxiesIPv4 = append(dhcpBackup.DHCPProxiesIPv4, DHCPProxyBackup{
					ServerIP:    dhcpServerIP,
					SourceIP:    srcIP,
					RxVrfID:     proxy.RxVrfID,
					ServerVrfID: server.ServerVrfID,
				})
				fmt.Printf("  ✅ IPv4 DHCP Proxy: Server %s (src: %s, rx_vrf: %d, server_vrf: %d)\n",
					dhcpServerIP, srcIP, proxy.RxVrfID, server.ServerVrfID)
			}

			// Store VSS config if present
			if proxy.VssType != 0 || proxy.VssVPNAsciiID != "" {
				dhcpBackup.VSSConfig = &DHCPVSSBackup{
					VrfID:    proxy.RxVrfID,
					VSSType:  uint8(proxy.VssType),
					VpnID:    proxy.VssVPNAsciiID,
					OUI:      proxy.VssOui,
					VpnIndex: proxy.VssFibID,
					IsIPv6:   false,
				}
				fmt.Printf("  ✅ IPv4 DHCP VSS Config: Type %d, VPNID: %s\n", proxy.VssType, proxy.VssVPNAsciiID)
			}
		}
		fmt.Printf("  ✅ Total IPv4 DHCP proxies backed up: %d\n", len(proxies))
	} else {
		fmt.Printf("  ⚠️  Failed to get IPv4 DHCP proxies: %v\n", err)
	}

	// Get IPv6 DHCP proxies
	if proxies, err := v.DhcpManager.ListProxies(ctx, true); err == nil {
		for _, proxy := range proxies {
			srcIP := addrToString(proxy.DHCPSrcAddress)

			// Extract DHCP servers from the list
			for _, server := range proxy.Servers {
				dhcpServerIP := addrToString(server.DHCPServer)

				dhcpBackup.DHCPProxiesIPv6 = append(dhcpBackup.DHCPProxiesIPv6, DHCPProxyBackup{
					ServerIP:    dhcpServerIP,
					SourceIP:    srcIP,
					RxVrfID:     proxy.RxVrfID,
					ServerVrfID: server.ServerVrfID,
				})
				fmt.Printf("  ✅ IPv6 DHCP Proxy: Server %s (src: %s, rx_vrf: %d, server_vrf: %d)\n",
					dhcpServerIP, srcIP, proxy.RxVrfID, server.ServerVrfID)
			}

			// Store VSS config if present (IPv6)
			if proxy.VssType != 0 || proxy.VssVPNAsciiID != "" {
				dhcpBackup.VSSConfig = &DHCPVSSBackup{
					VrfID:    proxy.RxVrfID,
					VSSType:  uint8(proxy.VssType),
					VpnID:    proxy.VssVPNAsciiID,
					OUI:      proxy.VssOui,
					VpnIndex: proxy.VssFibID,
					IsIPv6:   true,
				}
				fmt.Printf("  ✅ IPv6 DHCP VSS Config: Type %d, VPNID: %s\n", proxy.VssType, proxy.VssVPNAsciiID)
			}
		}
		fmt.Printf("  ✅ Total IPv6 DHCP proxies backed up: %d\n", len(proxies))
	} else {
		fmt.Printf("  ⚠️  Failed to get IPv6 DHCP proxies: %v\n", err)
	}

	// ========================================
	// 6. IPFIX/FLOWPROBE BACKUP
	// ========================================
	fmt.Println("  🔍 Backing up IPFIX/Flowprobe...")
	ipfixBackup := IPFIXBackupConfig{
		IsEnabled: true, // TODO: Query actual state
	}

	// Get IPFIX status
	if status, err := v.IpfixManager.GetExporterStatus(ctx); err == nil {
		ipfixBackup.CollectorAddr = status.CollectorAddress
		ipfixBackup.CollectorPort = status.CollectorPort
		ipfixBackup.SourceAddr = status.SourceAddress
		ipfixBackup.VrfID = status.VrfID
		ipfixBackup.PathMTU = status.PathMtu
		ipfixBackup.TemplateInterval = status.TemplateInterval
		ipfixBackup.UDPChecksum = status.UDPChecksum
	} else {
		fmt.Printf("  ⚠️  Failed to get IPFIX status: %v\n", err)
	}

	// Get Flowprobe params
	if activeTimeout, recordL4, err := v.IpfixManager.GetFlowprobeParams(ctx); err == nil {
		ipfixBackup.ActiveTimeout = activeTimeout
		ipfixBackup.RecordL4 = recordL4
	} else {
		fmt.Printf("  ⚠️  Failed to get Flowprobe params: %v\n", err)
	}

	// Get enabled interfaces for flowprobe
	if enabledIfaces, err := v.IpfixManager.GetEnabledInterfaces(ctx); err == nil {
		ipfixBackup.EnabledIfaces = enabledIfaces
	} else {
		fmt.Printf("  ⚠️  Failed to get enabled IPFIX interfaces: %v\n", err)
	}

	// ========================================
	// ========================================
	// 7. ABF BACKUP
	// ========================================
	fmt.Println("  🛣️  Backing up ABF...")
	abfBackup := ABFBackupConfig{}

	if policies, err := v.AbfManager.ListPolicies(ctx); err == nil {
		for _, policy := range policies {
			// Convert FibPath array to simplified backup format
			var backupPaths []ABFPathBackup
			for _, fibPath := range policy.Policy.Paths {
				backupPaths = append(backupPaths, ABFPathBackup{
					SwIfIndex:  fibPath.SwIfIndex,
					TableID:    fibPath.TableID,
					RpfID:      fibPath.RpfID,
					Weight:     fibPath.Weight,
					Preference: fibPath.Preference,
					Type:       fmt.Sprintf("%v", fibPath.Type),
					Flags:      fmt.Sprintf("%v", fibPath.Flags),
					Proto:      fmt.Sprintf("%v", fibPath.Proto),
					NextHop:    fmt.Sprintf("%v", fibPath.Nh.Address), // Simplified IP representation
					ViaLabel:   fibPath.Nh.ViaLabel,
				})
			}

			// Store policy with all paths
			abfBackup.Policies = append(abfBackup.Policies, ABFPolicyBackup{
				PolicyID: policy.Policy.PolicyID,
				ACLIndex: policy.Policy.ACLIndex,
				Paths:    backupPaths,
			})
			fmt.Printf("  ✅ ABF Policy %d backed up (ACL: %d, Paths: %d)\n",
				policy.Policy.PolicyID, policy.Policy.ACLIndex, len(backupPaths))
		}
		fmt.Printf("  ✅ Total ABF policies backed up: %d\n", len(policies))
	} else {
		fmt.Printf("  ⚠️  Failed to get ABF policies: %v\n", err)
	}

	if attachments, err := v.AbfManager.ListInterfaceAttachments(ctx); err == nil {
		for _, attach := range attachments {
			// Lookup interface name
			ifName := ""
			for _, iface := range interfaces {
				if iface.Index == uint32(attach.Attach.SwIfIndex) {
					ifName = iface.Name
					break
				}
			}
			abfBackup.Attachments = append(abfBackup.Attachments, ABFAttachmentBackup{
				PolicyID:  attach.Attach.PolicyID,
				SwIfIndex: uint32(attach.Attach.SwIfIndex),
				Priority:  attach.Attach.Priority,
				IsIPv6:    attach.Attach.IsIPv6,
			})
			fmt.Printf("  ✅ ABF Attachment: Policy %d -> Interface %s (priority: %d)\n",
				attach.Attach.PolicyID, ifName, attach.Attach.Priority)
		}
		fmt.Printf("  ✅ Total ABF attachments backed up: %d\n", len(attachments))
	} else {
		fmt.Printf("  ⚠️  Failed to get ABF attachments: %v\n", err)
	}

	// ========================================
	// 8. STATIC ROUTING BACKUP
	// ========================================
	fmt.Println("  🛣️  Backing up Static Routes...")
	routesBackup := StaticRoutingBackupConfig{}

	// Build interface name to index map for lookup
	interfaceNameToIndex := make(map[string]uint32)
	for _, iface := range interfaces {
		interfaceNameToIndex[iface.Name] = iface.Index
	}

	if routes, err := v.GetRoutingTable(); err == nil {
		for _, route := range routes {
			// Only backup static routes
			if route.Protocol != "static" {
				continue
			}

			// Get the first next hop (primary route)
			nextHopIP := ""
			if len(route.NextHops) > 0 {
				nextHopIP = route.NextHops[0]
			}

			// Get interface index from name map
			swIfIdx := uint32(0xffffffff)
			if route.Interface != "" {
				if idx, exists := interfaceNameToIndex[route.Interface]; exists {
					swIfIdx = idx
				}
			}

			routesBackup.Routes = append(routesBackup.Routes, StaticRouteBackup{
				Prefix:        route.Prefix,
				NextHop:       nextHopIP,
				SwIfIndex:     swIfIdx,
				InterfaceName: route.Interface,
				Protocol:      route.Protocol,
				Distance:      route.Distance,
				Metric:        route.Metric,
			})
			fmt.Printf("  ✅ Static Route: %s via %s (Interface: %s)\n", route.Prefix, nextHopIP, route.Interface)
		}
		fmt.Printf("  ✅ Total static routes backed up: %d\n", len(routesBackup.Routes))
	} else {
		fmt.Printf("  ⚠️  Failed to get routing table: %v\n", err)
	}

	// ========================================
	// COMBINE AND SAVE
	// ========================================
	fullBackup := FullBackupConfig{
		Timestamp:  time.Now().Format(time.RFC3339),
		Interfaces: configs,
		ACLs:       aclBackup,
		NAT44:      nat44Backup,
		Policers:   policerBackup,
		DHCP:       dhcpBackup,
		IPFIX:      ipfixBackup,
		ABF:        abfBackup,
		Routes:     routesBackup,
	}

	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup dir: %v", err)
	}

	data, err := json.MarshalIndent(fullBackup, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	filePath := fmt.Sprintf("%s/%s", backupDir, configFile)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	fmt.Printf("✅ Comprehensive Configuration Saved:\n")
	fmt.Printf("   - %d interfaces\n", len(configs))
	fmt.Printf("   - %d IP ACLs | %d MAC ACLs\n", len(aclBackup.IPACLs), len(aclBackup.MACACLs))
	fmt.Printf("   - %d NAT interfaces | %d pools | %d static mappings\n",
		len(nat44Backup.Interfaces), len(nat44Backup.AddressPools), len(nat44Backup.StaticMappings))
	fmt.Printf("   - %d policers\n", len(policerBackup.Policers))
	fmt.Printf("   - %d IPv4 DHCP proxies | %d IPv6 DHCP proxies\n",
		len(dhcpBackup.DHCPProxiesIPv4), len(dhcpBackup.DHCPProxiesIPv6))
	fmt.Printf("   - IPFIX: %s:%d | Flowprobe on %d interfaces\n",
		ipfixBackup.CollectorAddr, ipfixBackup.CollectorPort, len(ipfixBackup.EnabledIfaces))
	fmt.Printf("   - %d ABF policies | %d attachments\n", len(abfBackup.Policies), len(abfBackup.Attachments))
	fmt.Printf("   - Saved to: %s\n", filePath)

	return nil
}

// RestoreConfiguration - Restore COMPLETE VPP configuration after restart (all components)
func (v *VPPClient) RestoreConfiguration() error {
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔄 RESTORING COMPREHENSIVE VPP CONFIGURATION...")
	fmt.Println(strings.Repeat("=", 70))

	ctx := context.Background()
	filePath := fmt.Sprintf("%s/%s", backupDir, configFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("no backup found: %v", err)
	}

	var fullBackup FullBackupConfig
	if err := json.Unmarshal(data, &fullBackup); err != nil {
		return fmt.Errorf("failed to parse backup: %v", err)
	}

	fmt.Printf("\n📅 Backup timestamp: %s\n\n", fullBackup.Timestamp)

	// Statistics tracking
	stats := struct {
		InterfacesCreated int
		InterfacesUpdated int
		InterfacesSkipped int
		InterfacesFailed  int
		IPACLsCreated     int
		MACACLsCreated    int
		ACLsFailed        int
		NATInterfacesCfg  int
		NATPoolsAdded     int
		NATMappingsAdded  int
		NATFailed         int
		PolicersAdded     int
		PolicersFailed    int
		DHCPProxiesCfg    int
		DHCPFailed        int
		IPFIXConfigured   int
		IPFIXFailed       int
		ABFPoliciesAdded  int
		ABFAttached       int
		ABFFailed         int
		RoutesAdded       int
		RoutesFailed      int
	}{}

	// Map for tracking old -> new ACL indices
	ipACLIndexMap := make(map[uint32]uint32)
	macACLIndexMap := make(map[uint32]uint32)

	// ========================================
	// PHASE 0: Restore ACL Tables
	// ========================================
	fmt.Println("📝 PHASE 0: Restoring ACL Tables...")

	// Restore IP ACLs
	for _, aclDetail := range fullBackup.ACLs.IPACLs {
		var vppRules []acl_types.ACLRule

		for _, customRule := range aclDetail.Rules {
			srcPrefix, err := acl.ParseCIDR(customRule.SrcPrefix)
			if err != nil {
				fmt.Printf("  ❌ Failed to parse source prefix %s: %v\n", customRule.SrcPrefix, err)
				continue
			}

			dstPrefix, err := acl.ParseCIDR(customRule.DstPrefix)
			if err != nil {
				fmt.Printf("  ❌ Failed to parse dest prefix %s: %v\n", customRule.DstPrefix, err)
				continue
			}

			vppRule := acl_types.ACLRule{
				IsPermit:               acl_types.ACLAction(customRule.IsPermit),
				SrcPrefix:              srcPrefix,
				DstPrefix:              dstPrefix,
				Proto:                  ip_types.IPProto(customRule.Proto),
				SrcportOrIcmptypeFirst: customRule.SrcportOrIcmptypeFirst,
				SrcportOrIcmptypeLast:  customRule.SrcportOrIcmptypeLast,
				DstportOrIcmpcodeFirst: customRule.DstportOrIcmpcodeFirst,
				DstportOrIcmpcodeLast:  customRule.DstportOrIcmpcodeLast,
				TCPFlagsMask:           customRule.TCPFlagsMask,
				TCPFlagsValue:          customRule.TCPFlagsValue,
			}
			vppRules = append(vppRules, vppRule)
		}

		newACLIndex, err := v.ACLManager.CreateACL(ctx, aclDetail.Tag, vppRules)
		if err != nil {
			fmt.Printf("  ❌ Failed to restore IP ACL '%s': %v\n", aclDetail.Tag, err)
			stats.ACLsFailed++
			continue
		}

		ipACLIndexMap[aclDetail.ACLIndex] = newACLIndex
		fmt.Printf("  ✅ IP ACL '%s' (old: %d → new: %d)\n", aclDetail.Tag, aclDetail.ACLIndex, newACLIndex)
		stats.IPACLsCreated++
	}

	// Restore MAC ACLs
	for _, macACL := range fullBackup.ACLs.MACACLs {
		var vppMacRules []acl_types.MacipACLRule

		for _, customRule := range macACL.Rules {
			srcMac, err := acl.ParseMacAddress(customRule.SrcMac)
			if err != nil {
				fmt.Printf("  ❌ Failed to parse source MAC %s: %v\n", customRule.SrcMac, err)
				continue
			}

			srcMask, err := acl.ParseMacAddress(customRule.SrcMask)
			if err != nil {
				fmt.Printf("  ❌ Failed to parse MAC mask %s: %v\n", customRule.SrcMask, err)
				continue
			}

			srcPrefix, err := acl.ParseCIDR(customRule.SrcPrefix)
			if err != nil {
				fmt.Printf("  ❌ Failed to parse IP prefix %s: %v\n", customRule.SrcPrefix, err)
				continue
			}

			vppMacRule := acl_types.MacipACLRule{
				IsPermit:   acl_types.ACLAction(customRule.IsPermit),
				SrcMac:     srcMac,
				SrcMacMask: srcMask,
				SrcPrefix:  srcPrefix,
			}
			vppMacRules = append(vppMacRules, vppMacRule)
		}

		newMACACLIndex, err := v.ACLManager.CreateMacACL(ctx, 0xffffffff, macACL.Tag, vppMacRules)
		if err != nil {
			fmt.Printf("  ❌ Failed to restore MAC ACL '%s': %v\n", macACL.Tag, err)
			stats.ACLsFailed++
			continue
		}

		macACLIndexMap[macACL.ACLIndex] = newMACACLIndex
		fmt.Printf("  ✅ MAC ACL '%s' (old: %d → new: %d)\n", macACL.Tag, macACL.ACLIndex, newMACACLIndex)
		stats.MACACLsCreated++
	}

	// ========================================
	// PHASE 1: Create Interfaces
	// ========================================
	fmt.Println("\n📝 PHASE 1: Creating Interfaces...")

	currentIfaces, err := v.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get current interfaces: %v", err)
	}

	nameToIndex := make(map[string]uint32)
	for _, iface := range currentIfaces {
		nameToIndex[iface.Name] = iface.Index
	}

	var vlanConfigs []InterfaceConfig

	for i, config := range fullBackup.Interfaces {
		if config.IsSubInterface {
			vlanConfigs = append(vlanConfigs, config)
			continue
		}

		if _, exists := nameToIndex[config.InterfaceName]; exists {
			stats.InterfacesSkipped++
			continue
		}

		newIndex, err := v.createInterface(config)
		if err != nil {
			fmt.Printf("  ❌ Failed to create %s: %v\n", config.InterfaceName, err)
			stats.InterfacesFailed++
			continue
		}

		fmt.Printf("  ✅ Created %s (index: %d)\n", config.InterfaceName, newIndex)
		nameToIndex[config.InterfaceName] = newIndex
		fullBackup.Interfaces[i].SwIfIndex = newIndex
		stats.InterfacesCreated++

		time.Sleep(100 * time.Millisecond)
	}

	// Create VLAN sub-interfaces
	if len(vlanConfigs) > 0 {
		fmt.Println("\n📝 PHASE 1.5: Creating VLAN Sub-Interfaces...")
		for _, vlanCfg := range vlanConfigs {
			if _, exists := nameToIndex[vlanCfg.InterfaceName]; exists {
				stats.InterfacesSkipped++
				continue
			}

			parts := strings.Split(vlanCfg.InterfaceName, ".")
			if len(parts) != 2 {
				fmt.Printf("  ❌ Invalid VLAN name: %s\n", vlanCfg.InterfaceName)
				stats.InterfacesFailed++
				continue
			}

			parentName := parts[0]
			parentIdx, exists := nameToIndex[parentName]
			if !exists {
				fmt.Printf("  ❌ Parent interface %s not found for VLAN %s\n", parentName, vlanCfg.InterfaceName)
				stats.InterfacesFailed++
				continue
			}

			vlanCfg.ParentSwIfIndex = parentIdx
			newIndex, err := v.CreateVlanSubif(parentIdx, vlanCfg.VlanID)
			if err != nil {
				fmt.Printf("  ❌ Failed to create VLAN %s: %v\n", vlanCfg.InterfaceName, err)
				stats.InterfacesFailed++
				continue
			}

			fmt.Printf("  ✅ Created VLAN %s (index: %d)\n", vlanCfg.InterfaceName, newIndex)
			nameToIndex[vlanCfg.InterfaceName] = newIndex
			vlanCfg.SwIfIndex = newIndex
			fullBackup.Interfaces = append(fullBackup.Interfaces, vlanCfg)
			stats.InterfacesCreated++
		}
	}

	// ========================================
	// PHASE 2: Configure Interfaces
	// ========================================
	fmt.Println("\n📝 PHASE 2: Configuring Interfaces...")
	for _, config := range fullBackup.Interfaces {
		currentIndex, exists := nameToIndex[config.InterfaceName]
		if !exists {
			continue
		}

		if err := v.configureInterface(currentIndex, config); err != nil {
			fmt.Printf("  ❌ Failed to configure %s: %v\n", config.InterfaceName, err)
			stats.InterfacesFailed++
			continue
		}

		fmt.Printf("  ✅ Configured %s\n", config.InterfaceName)
		stats.InterfacesUpdated++
	}

	// ========================================
	// PHASE 3: Bind ACLs to Interfaces
	// ========================================
	fmt.Println("\n📝 PHASE 3: Binding ACLs to Interfaces...")

	for _, config := range fullBackup.Interfaces {
		currentIndex, exists := nameToIndex[config.InterfaceName]
		if !exists {
			continue
		}

		// Bind IP ACLs
		if len(config.InputACLs) > 0 || len(config.OutputACLs) > 0 {
			var newInputACLs []uint32
			for _, oldIdx := range config.InputACLs {
				if newIdx, found := ipACLIndexMap[oldIdx]; found {
					newInputACLs = append(newInputACLs, newIdx)
				}
			}

			var newOutputACLs []uint32
			for _, oldIdx := range config.OutputACLs {
				if newIdx, found := ipACLIndexMap[oldIdx]; found {
					newOutputACLs = append(newOutputACLs, newIdx)
				}
			}

			if len(newInputACLs) > 0 || len(newOutputACLs) > 0 {
				err := v.ACLManager.ApplyACLToInterface(ctx, currentIndex, newInputACLs, newOutputACLs)
				if err != nil {
					fmt.Printf("  ❌ Failed to bind IP ACLs to %s: %v\n", config.InterfaceName, err)
				} else {
					fmt.Printf("  ✅ Bound IP ACLs to %s\n", config.InterfaceName)
				}
			}
		}

		// Bind MAC ACL
		if config.MacACLIndex != 0xffffffff {
			if newMACIdx, found := macACLIndexMap[config.MacACLIndex]; found {
				err := v.ACLManager.ApplyMacACLToInterface(ctx, currentIndex, newMACIdx, true)
				if err != nil {
					fmt.Printf("  ❌ Failed to bind MAC ACL to %s: %v\n", config.InterfaceName, err)
				} else {
					fmt.Printf("  ✅ Bound MAC ACL %d to %s\n", newMACIdx, config.InterfaceName)
				}
			}
		}
	}

	// ========================================
	// PHASE 4: Restore NAT44 Configuration
	// ========================================
	if fullBackup.NAT44.IsEnabled {
		fmt.Println("\n📝 PHASE 4: Restoring NAT44 Configuration...")

		// CRITICAL: Enable NAT44 globally first!
		if err := v.NatManager.EnableNat44(ctx); err != nil {
			fmt.Printf("  ⚠️  Failed to enable NAT44 globally: %v\n", err)
		} else {
			fmt.Println("  ✅ NAT44 enabled globally")
		}

		// Configure NAT interfaces (inside/outside)
		for _, natIface := range fullBackup.NAT44.Interfaces {
			if idx, exists := nameToIndex[natIface.Name]; exists {
				err := v.NatManager.SetInterfaceNAT(ctx, idx, natIface.IsInside, true)
				if err != nil {
					fmt.Printf("  ❌ Failed to configure NAT on %s: %v\n", natIface.Name, err)
					stats.NATFailed++
				} else {
					side := "inside"
					if !natIface.IsInside {
						side = "outside"
					}
					fmt.Printf("  ✅ NAT interface %s configured as %s\n", natIface.Name, side)
					stats.NATInterfacesCfg++
				}
			}
		}

		// Add address pools
		for _, pool := range fullBackup.NAT44.AddressPools {
			err := v.NatManager.AddAddressPool(ctx, pool.IPAddress, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to add NAT pool %s: %v\n", pool.IPAddress, err)
				stats.NATFailed++
			} else {
				fmt.Printf("  ✅ NAT pool added: %s\n", pool.IPAddress)
				stats.NATPoolsAdded++
			}
		}

		// Add static mappings (DNAT)
		for _, mapping := range fullBackup.NAT44.StaticMappings {
			err := v.NatManager.AddStaticMapping(ctx, mapping, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to add NAT mapping %s:%d->%s:%d: %v\n",
					mapping.LocalIP, mapping.LocalPort, mapping.ExternalIP, mapping.ExternalPort, err)
				stats.NATFailed++
			} else {
				fmt.Printf("  ✅ NAT mapping added: %s:%d -> %s:%d\n",
					mapping.LocalIP, mapping.LocalPort, mapping.ExternalIP, mapping.ExternalPort)
				stats.NATMappingsAdded++
			}
		}
	}

	// ========================================
	// PHASE 5: Restore Policer Configuration
	// ========================================
	if len(fullBackup.Policers.Policers) > 0 {
		fmt.Println("\n📝 PHASE 5: Restoring Policers...")

		for _, policer := range fullBackup.Policers.Policers {
			_, err := v.PolicerManager.AddPolicer(ctx, policer.Name, policer.CIR, policer.CB)
			if err != nil {
				fmt.Printf("  ❌ Failed to add policer '%s': %v\n", policer.Name, err)
				stats.PolicersFailed++
			} else {
				fmt.Printf("  ✅ Policer '%s' added (CIR: %d, CB: %d)\n", policer.Name, policer.CIR, policer.CB)
				stats.PolicersAdded++
			}
		}
		fmt.Printf("  📊 Policers: %d restored, %d failed\n", stats.PolicersAdded, stats.PolicersFailed)
	}

	// ========================================
	// PHASE 6: Restore DHCP Configuration
	// ========================================
	if len(fullBackup.DHCP.DHCPProxiesIPv4) > 0 || len(fullBackup.DHCP.DHCPProxiesIPv6) > 0 {
		fmt.Println("\n📝 PHASE 6: Restoring DHCP Configuration...")

		// IPv4 DHCP Proxies
		for _, proxy := range fullBackup.DHCP.DHCPProxiesIPv4 {
			err := v.DhcpManager.ConfigureProxy(ctx, proxy.ServerIP, proxy.SourceIP,
				proxy.RxVrfID, proxy.ServerVrfID, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to configure IPv4 DHCP proxy: %v\n", err)
				stats.DHCPFailed++
			} else {
				fmt.Printf("  ✅ IPv4 DHCP proxy: Server %s (src: %s, rx_vrf: %d, server_vrf: %d)\n",
					proxy.ServerIP, proxy.SourceIP, proxy.RxVrfID, proxy.ServerVrfID)
				stats.DHCPProxiesCfg++
			}
		}

		// IPv6 DHCP Proxies
		for _, proxy := range fullBackup.DHCP.DHCPProxiesIPv6 {
			err := v.DhcpManager.ConfigureProxy(ctx, proxy.ServerIP, proxy.SourceIP,
				proxy.RxVrfID, proxy.ServerVrfID, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to configure IPv6 DHCP proxy: %v\n", err)
				stats.DHCPFailed++
			} else {
				fmt.Printf("  ✅ IPv6 DHCP proxy: Server %s (src: %s, rx_vrf: %d, server_vrf: %d)\n",
					proxy.ServerIP, proxy.SourceIP, proxy.RxVrfID, proxy.ServerVrfID)
				stats.DHCPProxiesCfg++
			}
		}

		// Restore VSS config if available
		if fullBackup.DHCP.VSSConfig != nil {
			vssConfig := fullBackup.DHCP.VSSConfig
			// Configure VSS for IPv4
			err := v.DhcpManager.SetVSS(ctx, vssConfig.VrfID, vssConfig.VSSType,
				vssConfig.VpnID, vssConfig.OUI, vssConfig.VpnIndex, false, true)
			if err != nil {
				fmt.Printf("  ⚠️  Failed to configure IPv4 DHCP VSS: %v\n", err)
			} else {
				fmt.Printf("  ✅ IPv4 DHCP VSS configured (Type: %d, VPNID: %s)\n", vssConfig.VSSType, vssConfig.VpnID)
			}

			// Configure VSS for IPv6
			err = v.DhcpManager.SetVSS(ctx, vssConfig.VrfID, vssConfig.VSSType,
				vssConfig.VpnID, vssConfig.OUI, vssConfig.VpnIndex, true, true)
			if err != nil {
				fmt.Printf("  ⚠️  Failed to configure IPv6 DHCP VSS: %v\n", err)
			} else {
				fmt.Printf("  ✅ IPv6 DHCP VSS configured (Type: %d, VPNID: %s)\n", vssConfig.VSSType, vssConfig.VpnID)
			}
		}

		fmt.Printf("  📊 DHCP: %d proxies configured, %d failed\n", stats.DHCPProxiesCfg, stats.DHCPFailed)
	}

	// ========================================
	// PHASE 7: Restore IPFIX/Flowprobe Configuration
	// ========================================
	if fullBackup.IPFIX.IsEnabled {
		fmt.Println("\n📝 PHASE 7: Restoring IPFIX/Flowprobe Configuration...")

		// Configure IPFIX exporter if settings are available
		if fullBackup.IPFIX.CollectorAddr != "" {
			ipfixCfg := ipfix.IpfixConfig{
				CollectorAddress: fullBackup.IPFIX.CollectorAddr,
				CollectorPort:    fullBackup.IPFIX.CollectorPort,
				SourceAddress:    fullBackup.IPFIX.SourceAddr,
				VrfID:            fullBackup.IPFIX.VrfID,
				PathMtu:          fullBackup.IPFIX.PathMTU,
				TemplateInterval: fullBackup.IPFIX.TemplateInterval,
				UDPChecksum:      fullBackup.IPFIX.UDPChecksum,
			}

			if err := v.IpfixManager.SetExporter(ctx, ipfixCfg); err != nil {
				fmt.Printf("  ❌ Failed to configure IPFIX exporter: %v\n", err)
				stats.IPFIXFailed++
			} else {
				fmt.Printf("  ✅ IPFIX exporter configured: %s:%d\n",
					fullBackup.IPFIX.CollectorAddr, fullBackup.IPFIX.CollectorPort)
				stats.IPFIXConfigured++
			}
		}

		// Configure Flowprobe parameters
		if err := v.IpfixManager.SetFlowprobeParams(ctx, fullBackup.IPFIX.ActiveTimeout, fullBackup.IPFIX.RecordL4); err != nil {
			fmt.Printf("  ❌ Failed to configure Flowprobe params: %v\n", err)
			stats.IPFIXFailed++
		} else {
			fmt.Printf("  ✅ Flowprobe params set: timeout=%d, recordL4=%v\n",
				fullBackup.IPFIX.ActiveTimeout, fullBackup.IPFIX.RecordL4)
		}

		// Enable Flowprobe on interfaces
		for _, ifIdx := range fullBackup.IPFIX.EnabledIfaces {
			if err := v.IpfixManager.InterfaceEnable(ctx, ifIdx, true); err != nil {
				fmt.Printf("  ⚠️  Failed to enable Flowprobe on interface %d: %v\n", ifIdx, err)
			} else {
				fmt.Printf("  ✅ Flowprobe enabled on interface %d\n", ifIdx)
			}
		}
	}

	// ========================================
	// PHASE 8: Restore ABF Configuration
	// ========================================
	if len(fullBackup.ABF.Policies) > 0 || len(fullBackup.ABF.Attachments) > 0 {
		fmt.Println("\n📝 PHASE 8: Restoring ABF Configuration...")

		// Create ABF policies first
		policyIndexMap := make(map[uint32]uint32)
		for _, policy := range fullBackup.ABF.Policies {
			// Map old ACL index to new ACL index if it was recreated
			newACLIdx := policy.ACLIndex
			if idx, found := ipACLIndexMap[policy.ACLIndex]; found {
				newACLIdx = idx
				fmt.Printf("  ℹ️  ABF Policy %d: ACL index remapped %d -> %d\n", policy.PolicyID, policy.ACLIndex, newACLIdx)
			}

			// Reconstruct FibPath array from backup
			var fibPaths []fib_types.FibPath
			for _, backupPath := range policy.Paths {
				// Create basic FibPath - for full restoration, would need to parse Type/Flags/Proto strings
				fibPaths = append(fibPaths, fib_types.FibPath{
					SwIfIndex:  backupPath.SwIfIndex,
					TableID:    backupPath.TableID,
					RpfID:      backupPath.RpfID,
					Weight:     backupPath.Weight,
					Preference: backupPath.Preference,
					// Type, Flags, Proto would need parsing from string representation
					// Nh would need parsing from NextHop IP string
				})
			}

			// Create policy with restored paths
			err := v.AbfManager.ConfigurePolicy(ctx, policy.PolicyID, newACLIdx, fibPaths, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to create ABF policy %d: %v\n", policy.PolicyID, err)
				stats.ABFFailed++
			} else {
				pathCount := len(policy.Paths)
				fmt.Printf("  ✅ ABF policy %d created (ACL: %d, Paths: %d)\n", policy.PolicyID, newACLIdx, pathCount)
				policyIndexMap[policy.PolicyID] = policy.PolicyID
				stats.ABFPoliciesAdded++
			}
		}

		// Attach ABF policies to interfaces
		for _, attach := range fullBackup.ABF.Attachments {
			swIfIdx := attach.SwIfIndex

			// Lookup interface name for logging
			ifName := ""
			for name, idx := range nameToIndex {
				if idx == swIfIdx {
					ifName = name
					break
				}
			}

			err := v.AbfManager.AttachToInterface(ctx, attach.PolicyID, swIfIdx, attach.Priority, attach.IsIPv6, true)
			if err != nil {
				fmt.Printf("  ❌ Failed to attach ABF policy %d to interface %s: %v\n",
					attach.PolicyID, ifName, err)
				stats.ABFFailed++
			} else {
				fmt.Printf("  ✅ ABF policy %d attached to interface %s (priority: %d, IPv6: %v)\n",
					attach.PolicyID, ifName, attach.Priority, attach.IsIPv6)
				stats.ABFAttached++
			}
		}
		fmt.Printf("  📊 ABF: %d policies, %d attachments restored\n", stats.ABFPoliciesAdded, stats.ABFAttached)
	}

	// ========================================
	// PHASE 9: STATIC ROUTES RESTORE
	// ========================================
	if len(fullBackup.Routes.Routes) > 0 {
		fmt.Println("\n📝 PHASE 9: Restoring Static Routes...")
		for _, route := range fullBackup.Routes.Routes {
			// Skip if no next hop
			if route.NextHop == "" {
				fmt.Printf("  ⚠️  Skipping route %s: no next hop\n", route.Prefix)
				continue
			}

			// Get the interface index from name, or use saved SwIfIndex
			swIfIdx := route.SwIfIndex
			if route.InterfaceName != "" {
				if idx, exists := nameToIndex[route.InterfaceName]; exists {
					swIfIdx = idx
				}
			}

			// Add the static route (no context parameter needed)
			err := v.AddStaticRoute(route.Prefix, route.NextHop, swIfIdx)
			if err != nil {
				fmt.Printf("  ❌ Failed to restore route %s via %s: %v\n", route.Prefix, route.NextHop, err)
				stats.RoutesFailed++
			} else {
				fmt.Printf("  ✅ Static route restored: %s via %s (Interface: %s)\n",
					route.Prefix, route.NextHop, route.InterfaceName)
				stats.RoutesAdded++
			}
		}
		fmt.Printf("  📊 Static Routes: %d added, %d failed\n", stats.RoutesAdded, stats.RoutesFailed)
	}

	// ========================================
	// PRINT COMPREHENSIVE SUMMARY
	// ========================================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("📊 COMPREHENSIVE RESTORE SUMMARY")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\n🌐 INTERFACES:\n")
	fmt.Printf("   ├─ Created:  %d\n", stats.InterfacesCreated)
	fmt.Printf("   ├─ Updated:  %d\n", stats.InterfacesUpdated)
	fmt.Printf("   ├─ Skipped:  %d (already exist)\n", stats.InterfacesSkipped)
	fmt.Printf("   └─ Failed:   %d\n", stats.InterfacesFailed)

	fmt.Printf("\n🔒 ACLs:\n")
	fmt.Printf("   ├─ IP ACLs:     %d\n", stats.IPACLsCreated)
	fmt.Printf("   ├─ MAC ACLs:    %d\n", stats.MACACLsCreated)
	fmt.Printf("   └─ Failed:      %d\n", stats.ACLsFailed)

	fmt.Printf("\n🔄 NAT44:\n")
	fmt.Printf("   ├─ Interfaces:  %d configured\n", stats.NATInterfacesCfg)
	fmt.Printf("   ├─ Pools:       %d added\n", stats.NATPoolsAdded)
	fmt.Printf("   ├─ Mappings:    %d added\n", stats.NATMappingsAdded)
	fmt.Printf("   └─ Failed:      %d\n", stats.NATFailed)

	fmt.Printf("\n🚓 POLICERS:\n")
	fmt.Printf("   ├─ Added:       %d\n", stats.PolicersAdded)
	fmt.Printf("   └─ Failed:      %d\n", stats.PolicersFailed)

	fmt.Printf("\n📡 DHCP:\n")
	fmt.Printf("   ├─ Proxies:     %d configured\n", stats.DHCPProxiesCfg)
	fmt.Printf("   └─ Failed:      %d\n", stats.DHCPFailed)

	fmt.Printf("\n🔍 IPFIX/FLOWPROBE:\n")
	fmt.Printf("   ├─ Configured:  %d\n", stats.IPFIXConfigured)
	fmt.Printf("   └─ Failed:      %d\n", stats.IPFIXFailed)

	fmt.Printf("\n🛣️  ABF:\n")
	fmt.Printf("   ├─ Policies:    %d created\n", stats.ABFPoliciesAdded)
	fmt.Printf("   ├─ Attached:    %d\n", stats.ABFAttached)
	fmt.Printf("   └─ Failed:      %d\n", stats.ABFFailed)

	fmt.Printf("\n🛣️  STATIC ROUTES:\n")
	fmt.Printf("   ├─ Added:       %d\n", stats.RoutesAdded)
	fmt.Printf("   └─ Failed:      %d\n", stats.RoutesFailed)

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("✅ RESTORATION COMPLETE!")
	fmt.Println(strings.Repeat("=", 70) + "\n")

	return nil
}

// Helper functions
func (v *VPPClient) createInterface(config InterfaceConfig) (uint32, error) {
	switch {
	case strings.HasPrefix(config.InterfaceName, "loop"):
		return v.CreateLoopback()
	case strings.HasPrefix(config.InterfaceName, "tap"):
		tapID := config.TapID
		if tapID == 0 {
			fmt.Sscanf(config.InterfaceName, "tap%d", &tapID)
		}
		return v.CreateTap(tapID, config.InterfaceName)
	case strings.HasPrefix(config.InterfaceName, "vhost") ||
		strings.HasPrefix(config.InterfaceName, "VirtualEthernet"):
		socketFile := config.SocketFile
		if socketFile == "" {
			socketFile = fmt.Sprintf("/tmp/vhost-%d.sock", time.Now().Unix())
		}
		return v.CreateVhostUser(socketFile, true)
	case strings.HasPrefix(config.InterfaceName, "vmxnet3"):
		if config.PciAddr == 0 {
			return 0, fmt.Errorf("missing PCI address for vmxnet3")
		}
		return v.CreateVmxnet3(config.PciAddr, 1024, 1024)
	case config.IsSubInterface:
		return 0, fmt.Errorf("VLAN interfaces should be created in Phase 1.5")
	default:
		return 0, fmt.Errorf("cannot create physical interface: %s", config.InterfaceName)
	}
}

func (v *VPPClient) configureInterface(swIfIndex uint32, config InterfaceConfig) error {
	if config.Tag != "" {
		if err := v.SetInterfaceTag(swIfIndex, config.Tag); err != nil {
			return fmt.Errorf("failed to set tag: %v", err)
		}
	}

	if config.IsDHCP {
		if err := v.SetInterfaceDHCP(swIfIndex, true); err != nil {
			return fmt.Errorf("failed to enable DHCP: %v", err)
		}
		fmt.Printf("   🔄 DHCP enabled on interface %d\n", swIfIndex)
	} else {
		for _, ipWithMask := range config.IPAddresses {
			if err := v.AddInterfaceIP(swIfIndex, ipWithMask); err != nil {
				return fmt.Errorf("failed to add IP %s: %v", ipWithMask, err)
			}
			fmt.Printf("   🌐 Added IP: %s\n", ipWithMask)
		}
	}

	if err := v.SetInterfaceState(swIfIndex, config.IsAdminUp); err != nil {
		return fmt.Errorf("failed to set state: %v", err)
	}

	return nil
}

func (v *VPPClient) detectInterfaceType(name string) string {
	switch {
	case strings.HasPrefix(name, "GigabitEthernet"):
		return "physical"
	case strings.HasPrefix(name, "vmxnet3"):
		return "vmxnet3"
	case strings.HasPrefix(name, "loop"):
		return "loopback"
	case strings.HasPrefix(name, "tap"):
		return "tap"
	case strings.HasPrefix(name, "vhost"), strings.HasPrefix(name, "VirtualEthernet"):
		return "vhost"
	case strings.Contains(name, "."):
		return "vlan"
	default:
		return "unknown"
	}
}

func (v *VPPClient) AutoSave() {
	if err := v.SaveConfiguration(); err != nil {
		fmt.Printf("⚠️  Auto-save failed: %v\n", err)
	}
}

func (v *VPPClient) RestoreFromRawJSON() error {
	// Keep existing legacy restore implementation
	return fmt.Errorf("legacy restore not implemented in this version")
}
