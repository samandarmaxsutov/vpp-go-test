// File: internal/vpp/backup_restore.go
package vpp

import (
    "context"
    "encoding/json"
    "fmt"
    "os"
    "strings"
    "time"
	"vpp-go-test/binapi/ip_types"
    "vpp-go-test/binapi/acl_types"
    "vpp-go-test/internal/vpp/acl"
)

// BackupConfig - Enhanced backup structure with DHCP and ACL info
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
    
    // ACL bindings
    InputACLs       []uint32 `json:"input_acls,omitempty"`
    OutputACLs      []uint32 `json:"output_acls,omitempty"`
    MacACLIndex     uint32   `json:"mac_acl_index,omitempty"` // 0xffffffff means no MAC ACL
}

// ACLBackupConfig - Complete ACL configuration backup
type ACLBackupConfig struct {
    IPACLs  []acl.ACLDetail    `json:"ip_acls"`
    MACACLs []acl.MacACLDetail `json:"mac_acls"`
}

// FullBackupConfig - Complete system backup
type FullBackupConfig struct {
    Timestamp   string             `json:"timestamp"`
    Interfaces  []BackupConfig     `json:"interfaces"`
    ACLs        ACLBackupConfig    `json:"acls"`
}

const (
    backupDir  = "/etc/sarhad-guard/backup"
    configFile = "vpp_config.json"
)

// SaveConfiguration - Save current VPP configuration with all details including ACLs
func (v *VPPClient) SaveConfiguration() error {
    fmt.Println("🔄 Saving VPP configuration...")
    
    ctx := context.Background()
    
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

    // Get ACL bindings for all interfaces
    aclBindings, err := v.ACLManager.GetAllInterfaceACLs(ctx)
    if err != nil {
        fmt.Printf("⚠️  Failed to get ACL bindings: %v\n", err)
        aclBindings = []acl.InterfaceACLMap{} // Continue without ACL data
    }
    
    // Create ACL binding map for quick lookup
    aclMap := make(map[uint32]acl.InterfaceACLMap)
    for _, binding := range aclBindings {
        aclMap[binding.SwIfIndex] = binding
    }

    // Get MAC ACL bindings
    macACLBindings, err := v.ACLManager.GetMacACLInterfaceList(ctx)
    if err != nil {
        fmt.Printf("⚠️  Failed to get MAC ACL bindings: %v\n", err)
        macACLBindings = make(map[uint32]uint32)
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
            MacACLIndex:   0xffffffff, // Default: no MAC ACL
        }

        // Add ACL bindings if they exist
        if binding, exists := aclMap[iface.Index]; exists {
            config.InputACLs = binding.InputACLs
            config.OutputACLs = binding.OutputACLs
        }
        
        // Add MAC ACL binding if exists
        if macACLIdx, exists := macACLBindings[iface.Index]; exists {
            config.MacACLIndex = macACLIdx
        }

        // Handle sub-interfaces (VLANs)
        if strings.Contains(iface.Name, ".") {
            parts := strings.Split(iface.Name, ".")
            if len(parts) == 2 {
                config.IsSubInterface = true
                var vlanID uint32
                fmt.Sscanf(parts[1], "%d", &vlanID)
                config.VlanID = vlanID
                config.ParentSwIfIndex = 0 // Will be resolved during restore
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

    // Backup all ACL configurations
    aclBackup := ACLBackupConfig{}
    
    // Get all IP ACLs
    ipACLs, err := v.ACLManager.GetAllACLs(ctx)
    if err != nil {
        fmt.Printf("⚠️  Failed to get IP ACLs: %v\n", err)
    } else {
        aclBackup.IPACLs = ipACLs
    }
    
    // Get all MAC ACLs
    macACLs, err := v.ACLManager.GetAllMacACLs(ctx)
    if err != nil {
        fmt.Printf("⚠️  Failed to get MAC ACLs: %v\n", err)
    } else {
        aclBackup.MACACLs = macACLs
    }

    // Create full backup structure
    fullBackup := FullBackupConfig{
        Timestamp:  time.Now().Format(time.RFC3339),
        Interfaces: configs,
        ACLs:       aclBackup,
    }

    // Create backup directory
    if err := os.MkdirAll(backupDir, 0755); err != nil {
        return fmt.Errorf("failed to create backup dir: %v", err)
    }

    // Save to JSON
    data, err := json.MarshalIndent(fullBackup, "", "  ")
    if err != nil {
        return fmt.Errorf("failed to marshal config: %v", err)
    }

    filePath := fmt.Sprintf("%s/%s", backupDir, configFile)
    if err := os.WriteFile(filePath, data, 0644); err != nil {
        return fmt.Errorf("failed to write config: %v", err)
    }

    fmt.Printf("✅ Configuration saved:\n")
    fmt.Printf("   - %d interfaces\n", len(configs))
    fmt.Printf("   - %d IP ACLs\n", len(aclBackup.IPACLs))
    fmt.Printf("   - %d MAC ACLs\n", len(aclBackup.MACACLs))
    fmt.Printf("   - Saved to: %s\n", filePath)
    
    return nil
}

// RestoreConfiguration - Restore VPP configuration after restart
func (v *VPPClient) RestoreConfiguration() error {
    fmt.Println("🔄 Restoring VPP configuration...")

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

    fmt.Printf("📅 Backup timestamp: %s\n", fullBackup.Timestamp)

    // Statistics
    stats := struct {
        InterfacesCreated  int
        InterfacesUpdated  int
        InterfacesSkipped  int
        InterfacesFailed   int
        IPACLsCreated      int
        MACACLsCreated     int
        ACLsFailed         int
    }{}

    // ========================================
    // PHASE 0: Restore ACL Tables
    // ========================================
    fmt.Println("\n📝 Phase 0: Restoring ACL tables...")
    
    // Map old ACL indices to new ones
    ipACLIndexMap := make(map[uint32]uint32)
    macACLIndexMap := make(map[uint32]uint32)
    
    // Restore IP ACLs
    for _, aclDetail := range fullBackup.ACLs.IPACLs {
        // Convert custom ACLRule to VPP acl_types.ACLRule
        var vppRules []acl_types.ACLRule
        
        for _, customRule := range aclDetail.Rules {
            // Parse prefixes
            srcPrefix, err := acl.ParseCIDR(customRule.SrcPrefix)
            if err != nil {
                fmt.Printf("❌ Failed to parse source prefix %s: %v\n", customRule.SrcPrefix, err)
                continue
            }
            
            dstPrefix, err := acl.ParseCIDR(customRule.DstPrefix)
            if err != nil {
                fmt.Printf("❌ Failed to parse dest prefix %s: %v\n", customRule.DstPrefix, err)
                continue
            }
            
            // Create VPP rule directly
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
        
        // Create new ACL (VPP will assign new index)
        newACLIndex, err := v.ACLManager.CreateACL(ctx, aclDetail.Tag, vppRules)
        if err != nil {
            fmt.Printf("❌ Failed to restore IP ACL '%s': %v\n", aclDetail.Tag, err)
            stats.ACLsFailed++
            continue
        }
        
        ipACLIndexMap[aclDetail.ACLIndex] = newACLIndex
        fmt.Printf("✅ Restored IP ACL '%s' (old: %d → new: %d)\n", 
            aclDetail.Tag, aclDetail.ACLIndex, newACLIndex)
        stats.IPACLsCreated++
    }
    
    // Restore MAC ACLs
    for _, macACL := range fullBackup.ACLs.MACACLs {
        // Convert custom MAC rules to VPP acl_types.MacipACLRule
        var vppMacRules []acl_types.MacipACLRule
        
        for _, customRule := range macACL.Rules {
            // Parse MAC addresses
            srcMac, err := acl.ParseMacAddress(customRule.SrcMac)
            if err != nil {
                fmt.Printf("❌ Failed to parse source MAC %s: %v\n", customRule.SrcMac, err)
                continue
            }
            
            srcMask, err := acl.ParseMacAddress(customRule.SrcMask)
            if err != nil {
                fmt.Printf("❌ Failed to parse MAC mask %s: %v\n", customRule.SrcMask, err)
                continue
            }
            
            // Parse IP prefix
            srcPrefix, err := acl.ParseCIDR(customRule.SrcPrefix)
            if err != nil {
                fmt.Printf("❌ Failed to parse IP prefix %s: %v\n", customRule.SrcPrefix, err)
                continue
            }
            
            // Create VPP MAC rule directly
            vppMacRule := acl_types.MacipACLRule{
                IsPermit:   acl_types.ACLAction(customRule.IsPermit),
                SrcMac:     srcMac,
                SrcMacMask: srcMask,
                SrcPrefix:  srcPrefix,
            }
            
            vppMacRules = append(vppMacRules, vppMacRule)
        }
        
        // Create new MAC ACL
        newMACACLIndex, err := v.ACLManager.CreateMacACL(ctx, 0xffffffff, macACL.Tag, vppMacRules)
        if err != nil {
            fmt.Printf("❌ Failed to restore MAC ACL '%s': %v\n", macACL.Tag, err)
            stats.ACLsFailed++
            continue
        }
        
        macACLIndexMap[macACL.ACLIndex] = newMACACLIndex
        fmt.Printf("✅ Restored MAC ACL '%s' (old: %d → new: %d)\n", 
            macACL.Tag, macACL.ACLIndex, newMACACLIndex)
        stats.MACACLsCreated++
    }

    // ========================================
    // PHASE 1-2: Restore Interfaces (existing code)
    // ========================================
    
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

    // Phase 1: Create missing interfaces (non-VLAN first)
    fmt.Println("\n📝 Phase 1: Creating missing interfaces...")
    var vlanConfigs []BackupConfig
    
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
            fmt.Printf("❌ Failed to create %s: %v\n", config.InterfaceName, err)
            stats.InterfacesFailed++
            continue
        }

        fmt.Printf("✅ Created %s (index: %d)\n", config.InterfaceName, newIndex)
        nameToIndex[config.InterfaceName] = newIndex
        fullBackup.Interfaces[i].SwIfIndex = newIndex
        stats.InterfacesCreated++
        
        time.Sleep(100 * time.Millisecond)
    }

    // Phase 1.5: Create VLAN sub-interfaces
    if len(vlanConfigs) > 0 {
        fmt.Println("\n📝 Phase 1.5: Creating VLAN sub-interfaces...")
        for _, vlanCfg := range vlanConfigs {
            if _, exists := nameToIndex[vlanCfg.InterfaceName]; exists {
                stats.InterfacesSkipped++
                continue
            }

            parts := strings.Split(vlanCfg.InterfaceName, ".")
            if len(parts) != 2 {
                fmt.Printf("❌ Invalid VLAN name: %s\n", vlanCfg.InterfaceName)
                stats.InterfacesFailed++
                continue
            }

            parentName := parts[0]
            parentIdx, exists := nameToIndex[parentName]
            if !exists {
                fmt.Printf("❌ Parent interface %s not found for VLAN %s\n", 
                    parentName, vlanCfg.InterfaceName)
                stats.InterfacesFailed++
                continue
            }

            vlanCfg.ParentSwIfIndex = parentIdx
            newIndex, err := v.CreateVlanSubif(parentIdx, vlanCfg.VlanID)
            if err != nil {
                fmt.Printf("❌ Failed to create VLAN %s: %v\n", vlanCfg.InterfaceName, err)
                stats.InterfacesFailed++
                continue
            }

            fmt.Printf("✅ Created VLAN %s (index: %d)\n", vlanCfg.InterfaceName, newIndex)
            nameToIndex[vlanCfg.InterfaceName] = newIndex
            vlanCfg.SwIfIndex = newIndex
            fullBackup.Interfaces = append(fullBackup.Interfaces, vlanCfg)
            stats.InterfacesCreated++
        }
    }

    // Phase 2: Configure interfaces (IPs, DHCP, state)
    fmt.Println("\n📝 Phase 2: Configuring interfaces...")
    for _, config := range fullBackup.Interfaces {
        currentIndex, exists := nameToIndex[config.InterfaceName]
        if !exists {
            continue
        }

        if err := v.configureInterface(currentIndex, config); err != nil {
            fmt.Printf("❌ Failed to configure %s: %v\n", config.InterfaceName, err)
            stats.InterfacesFailed++
            continue
        }

        fmt.Printf("✅ Configured %s\n", config.InterfaceName)
        stats.InterfacesUpdated++
    }

    // ========================================
    // PHASE 3: Bind ACLs to Interfaces
    // ========================================
    fmt.Println("\n📝 Phase 3: Binding ACLs to interfaces...")
    
    for _, config := range fullBackup.Interfaces {
        currentIndex, exists := nameToIndex[config.InterfaceName]
        if !exists {
            continue
        }

        // Bind IP ACLs (input/output)
        if len(config.InputACLs) > 0 || len(config.OutputACLs) > 0 {
            // Map old ACL indices to new ones
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
                    fmt.Printf("❌ Failed to bind IP ACLs to %s: %v\n", config.InterfaceName, err)
                } else {
                    fmt.Printf("   🔒 Bound IP ACLs to %s (in: %v, out: %v)\n", 
                        config.InterfaceName, newInputACLs, newOutputACLs)
                }
            }
        }

        // Bind MAC ACL
        if config.MacACLIndex != 0xffffffff {
            if newMACIdx, found := macACLIndexMap[config.MacACLIndex]; found {
                err := v.ACLManager.ApplyMacACLToInterface(ctx, currentIndex, newMACIdx, true)
                if err != nil {
                    fmt.Printf("❌ Failed to bind MAC ACL to %s: %v\n", config.InterfaceName, err)
                } else {
                    fmt.Printf("   🔒 Bound MAC ACL %d to %s\n", newMACIdx, config.InterfaceName)
                }
            }
        }
    }

    // Print summary
    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Printf("📊 Restore Summary:\n")
    fmt.Printf("   Interfaces:\n")
    fmt.Printf("     ├─ Created:  %d\n", stats.InterfacesCreated)
    fmt.Printf("     ├─ Updated:  %d\n", stats.InterfacesUpdated)
    fmt.Printf("     ├─ Skipped:  %d (already exist)\n", stats.InterfacesSkipped)
    fmt.Printf("     └─ Failed:   %d\n", stats.InterfacesFailed)
    fmt.Printf("   ACLs:\n")
    fmt.Printf("     ├─ IP ACLs:  %d restored\n", stats.IPACLsCreated)
    fmt.Printf("     ├─ MAC ACLs: %d restored\n", stats.MACACLsCreated)
    fmt.Printf("     └─ Failed:   %d\n", stats.ACLsFailed)
    fmt.Println(strings.Repeat("=", 60))

    return nil
}

// Helper functions (unchanged)
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
        return 0, fmt.Errorf("VLAN interfaces should be created in Phase 1.5")
    default:
        return 0, fmt.Errorf("cannot create physical interface: %s", config.InterfaceName)
    }
}

func (v *VPPClient) configureInterface(swIfIndex uint32, config BackupConfig) error {
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