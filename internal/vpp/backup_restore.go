// File: internal/vpp/backup_restore.go
package vpp

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"vpp-go-test/binapi/interface_types"
)

// BackupConfig - Enhanced backup structure with DHCP info
type BackupConfig struct {
	SwIfIndex       uint32   `json:"sw_if_index"`
	InterfaceName   string   `json:"interface_name"`
	InterfaceType   string   `json:"interface_dev_type"`
	Tag             string   `json:"tag"`
	IsAdminUp       bool     `json:"is_admin_up"`
	MAC             string   `json:"mac"`
	IPAddresses     []string `json:"ip_addresses"`
	IsDHCP          bool     `json:"is_dhcp"`
	
	// VLAN sub-interface info
	IsSubInterface  bool     `json:"is_sub_interface,omitempty"`
	ParentSwIfIndex uint32   `json:"parent_sw_if_index,omitempty"`
	VlanID          uint32   `json:"vlan_id,omitempty"`
	
	// Virtual interface creation params
	SocketFile      string   `json:"socket_file,omitempty"` // for vhost
	TapID           uint32   `json:"tap_id,omitempty"`      // for TAP
	PciAddr         uint32   `json:"pci_addr,omitempty"`    // for vmxnet3
}

const (
	backupDir  = "/etc/sarhad-guard/backup"
	configFile = "vpp_config.json"
)

// SaveConfiguration - Save current VPP configuration with all details
func (v *VPPClient) SaveConfiguration() error {
	fmt.Println("🔄 Saving VPP configuration...")
	
	// Get all interfaces with IPs
	interfaces, err := v.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %v", err)
	}

	// Get DHCP clients
	dhcpClients := v.GetActiveDHCPClients()
	
	// Get Vmxnet3 details for PCI addresses
	vmx3Details, _ := v.GetVmxnet3Details()
	vmx3Map := make(map[uint32]uint32) // swIfIndex -> pciAddr
	for _, vmx := range vmx3Details {
		vmx3Map[uint32(vmx.SwIfIndex)] = uint32(vmx.PciAddr)
	}

	var configs []BackupConfig
	
	for _, iface := range interfaces {
		// Skip local0 (always exists)
		if iface.Name == "local0" {
			continue
		}

		config := BackupConfig{
			SwIfIndex:     iface.Index,
			InterfaceName: iface.Name,
			InterfaceType: v.detectInterfaceType(iface.Name),
			Tag:           iface.Tag,
			IsAdminUp:     iface.Status == "UP",
			MAC:           iface.MAC,
			IPAddresses:   iface.IPAddresses,
			IsDHCP:        dhcpClients[iface.Index],
		}

		// Handle sub-interfaces (VLANs)
		if strings.Contains(iface.Name, ".") {
			parts := strings.Split(iface.Name, ".")
			if len(parts) == 2 {
				config.IsSubInterface = true
				var vlanID uint32
				fmt.Sscanf(parts[1], "%d", &vlanID)
				config.VlanID = vlanID
				// Find parent interface index (but don't save it - will be different after restart)
				parentName := parts[0]
				for _, p := range interfaces {
					if p.Name == parentName {
						// Store parent name instead of index
						config.ParentSwIfIndex = 0 // Will be resolved during restore
						break
					}
				}
			}
		}

		// Save vmxnet3 PCI address
		if pciAddr, ok := vmx3Map[iface.Index]; ok {
			config.PciAddr = pciAddr
		}

		// Save TAP ID if TAP interface
		if strings.HasPrefix(iface.Name, "tap") {
			fmt.Sscanf(iface.Name, "tap%d", &config.TapID)
		}

		configs = append(configs, config)
	}

	// Create backup directory
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup dir: %v", err)
	}

	// Save to JSON
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	filePath := fmt.Sprintf("%s/%s", backupDir, configFile)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	fmt.Printf("✅ Configuration saved: %d interfaces backed up to %s\n", len(configs), filePath)
	return nil
}

// RestoreConfiguration - Restore VPP configuration after restart
func (v *VPPClient) RestoreConfiguration() error {
	fmt.Println("🔄 Restoring VPP configuration...")

	filePath := fmt.Sprintf("%s/%s", backupDir, configFile)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("no backup found: %v", err)
	}

	var savedConfigs []BackupConfig
	if err := json.Unmarshal(data, &savedConfigs); err != nil {
		return fmt.Errorf("failed to parse backup: %v", err)
	}

	// Get current interfaces
	currentIfaces, err := v.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get current interfaces: %v", err)
	}

	// Map interface names to current indices
	nameToIndex := make(map[string]uint32)
	for _, iface := range currentIfaces {
		nameToIndex[iface.Name] = iface.Index
	}

	// Statistics
	stats := struct {
		Created  int
		Updated  int
		Skipped  int
		Failed   int
	}{}

	// Phase 1: Create missing interfaces (non-VLAN first)
	fmt.Println("\n📝 Phase 1: Creating missing interfaces...")
	var vlanConfigs []BackupConfig // Process VLANs separately
	
	for i, config := range savedConfigs {
		// Skip VLANs for now
		if config.IsSubInterface {
			vlanConfigs = append(vlanConfigs, config)
			continue
		}

		if _, exists := nameToIndex[config.InterfaceName]; exists {
			stats.Skipped++
			continue
		}

		newIndex, err := v.createInterface(config)
		if err != nil {
			fmt.Printf("❌ Failed to create %s: %v\n", config.InterfaceName, err)
			stats.Failed++
			continue
		}

		fmt.Printf("✅ Created %s (index: %d)\n", config.InterfaceName, newIndex)
		nameToIndex[config.InterfaceName] = newIndex
		savedConfigs[i].SwIfIndex = newIndex // Update for next phase
		stats.Created++
		
		time.Sleep(100 * time.Millisecond) // Brief pause between creations
	}

	// Phase 1.5: Create VLAN sub-interfaces (parents should exist now)
	if len(vlanConfigs) > 0 {
		fmt.Println("\n📝 Phase 1.5: Creating VLAN sub-interfaces...")
		for _, vlanCfg := range vlanConfigs {
			if _, exists := nameToIndex[vlanCfg.InterfaceName]; exists {
				stats.Skipped++
				continue
			}

			// Get parent interface name
			parts := strings.Split(vlanCfg.InterfaceName, ".")
			if len(parts) != 2 {
				fmt.Printf("❌ Invalid VLAN name: %s\n", vlanCfg.InterfaceName)
				stats.Failed++
				continue
			}

			parentName := parts[0]
			parentIdx, exists := nameToIndex[parentName]
			if !exists {
				fmt.Printf("❌ Parent interface %s not found for VLAN %s\n", parentName, vlanCfg.InterfaceName)
				stats.Failed++
				continue
			}

			vlanCfg.ParentSwIfIndex = parentIdx
			newIndex, err := v.CreateVlanSubif(parentIdx, vlanCfg.VlanID)
			if err != nil {
				fmt.Printf("❌ Failed to create VLAN %s: %v\n", vlanCfg.InterfaceName, err)
				stats.Failed++
				continue
			}

			fmt.Printf("✅ Created VLAN %s (index: %d)\n", vlanCfg.InterfaceName, newIndex)
			nameToIndex[vlanCfg.InterfaceName] = newIndex
			vlanCfg.SwIfIndex = newIndex
			savedConfigs = append(savedConfigs, vlanCfg) // Add to main list for configuration
			stats.Created++
		}
	}

	// Phase 2: Configure interfaces (IPs, DHCP, state)
	fmt.Println("\n📝 Phase 2: Configuring interfaces...")
	for _, config := range savedConfigs {
		currentIndex, exists := nameToIndex[config.InterfaceName]
		if !exists {
			continue
		}

		if err := v.configureInterface(currentIndex, config); err != nil {
			fmt.Printf("❌ Failed to configure %s: %v\n", config.InterfaceName, err)
			stats.Failed++
			continue
		}

		fmt.Printf("✅ Configured %s\n", config.InterfaceName)
		stats.Updated++
	}

	// Print summary
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("📊 Restore Summary:\n")
	fmt.Printf("   Created:  %d interfaces\n", stats.Created)
	fmt.Printf("   Updated:  %d interfaces\n", stats.Updated)
	fmt.Printf("   Skipped:  %d interfaces (already exist)\n", stats.Skipped)
	fmt.Printf("   Failed:   %d operations\n", stats.Failed)
	fmt.Println(strings.Repeat("=", 50))

	return nil
}

// createInterface - Create interface based on type
func (v *VPPClient) createInterface(config BackupConfig) (uint32, error) {
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
		// This should be handled separately in Phase 1.5
		return 0, fmt.Errorf("VLAN interfaces should be created in Phase 1.5")

	default:
		// Physical interfaces (GigabitEthernet, etc.) already exist
		return 0, fmt.Errorf("cannot create physical interface: %s", config.InterfaceName)
	}
}

// configureInterface - Apply IP, DHCP, tag, and admin state
func (v *VPPClient) configureInterface(swIfIndex uint32, config BackupConfig) error {
	// Set tag/alias
	if config.Tag != "" {
		if err := v.SetInterfaceTag(swIfIndex, config.Tag); err != nil {
			return fmt.Errorf("failed to set tag: %v", err)
		}
	}

	// Configure DHCP or static IPs
	if config.IsDHCP {
		if err := v.SetInterfaceDHCP(swIfIndex, true); err != nil {
			return fmt.Errorf("failed to enable DHCP: %v", err)
		}
		fmt.Printf("   🔄 DHCP enabled on interface %d\n", swIfIndex)
	} else {
		// Add static IP addresses
		for _, ipWithMask := range config.IPAddresses {
			if err := v.AddInterfaceIP(swIfIndex, ipWithMask); err != nil {
				return fmt.Errorf("failed to add IP %s: %v", ipWithMask, err)
			}
			fmt.Printf("   🌐 Added IP: %s\n", ipWithMask)
		}
	}

	// Set admin state (UP/DOWN)
	if err := v.SetInterfaceState(swIfIndex, config.IsAdminUp); err != nil {
		return fmt.Errorf("failed to set state: %v", err)
	}

	return nil
}

// detectInterfaceType - Determine interface type from name
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

// AutoSave - Automatically save configuration after changes
func (v *VPPClient) AutoSave() {
	if err := v.SaveConfiguration(); err != nil {
		fmt.Printf("⚠️  Auto-save failed: %v\n", err)
	}
}

// RestoreFromRawJSON - Legacy restore from old format (for migration)
func (v *VPPClient) RestoreFromRawJSON() error {
	fmt.Println("⚠️  Using legacy raw JSON restore method...")
	
	data, err := os.ReadFile("/etc/sarhad-guard/raw/interfaces_raw.json")
	if err != nil {
		return fmt.Errorf("no raw backup found: %v", err)
	}

	var backups []FullInterfaceBackup
	if err := json.Unmarshal(data, &backups); err != nil {
		return fmt.Errorf("failed to parse raw backup: %v", err)
	}

	currentIfaces, _ := v.GetInterfaces()
	nameToIndex := make(map[string]uint32)
	for _, iface := range currentIfaces {
		nameToIndex[iface.Name] = iface.Index
	}

	for _, backup := range backups {
		if backup.Details.InterfaceName == "local0" {
			continue
		}

		newIdx, exists := nameToIndex[backup.Details.InterfaceName]
		if !exists {
			fmt.Printf("⚠️  Interface %s not found, skipping\n", backup.Details.InterfaceName)
			continue
		}

		// Restore admin state
		isUp := (backup.Details.Flags & interface_types.IF_STATUS_API_FLAG_ADMIN_UP) != 0
		v.SetInterfaceState(newIdx, isUp)

		// Restore tag
		if backup.Details.Tag != "" {
			v.SetInterfaceTag(newIdx, backup.Details.Tag)
		}

		// Restore IPs
		for _, ip := range backup.IPs {
			v.AddInterfaceIP(newIdx, ip)
		}

		fmt.Printf("✅ Restored %s from legacy backup\n", backup.Details.InterfaceName)
	}

	return nil
}