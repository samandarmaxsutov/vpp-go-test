// File: internal/vpp/tls_interception.go
package vpp

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
)

// TLSInterceptionConfig - Main configuration for TLS interception
type TLSInterceptionConfig struct {
	// TAP Interface Configuration
	Tap0ID       uint32 `json:"tap0_id"`
	Tap1ID       uint32 `json:"tap1_id"`
	Tap0HostName string `json:"tap0_host_name"` // Linux side name (e.g., vpp-tap0)
	Tap1HostName string `json:"tap1_host_name"` // Linux side name (e.g., vpp-tap1)

	// VPP-side IPs (connected to kernel)
	Tap0VppIP  string `json:"tap0_vpp_ip"`  // e.g., 203.0.113.1/30
	Tap1VppIP  string `json:"tap1_vpp_ip"`  // e.g., 203.0.113.5/30
	Tap0HostIP string `json:"tap0_host_ip"` // e.g., 203.0.113.2/30
	Tap1HostIP string `json:"tap1_host_ip"` // e.g., 203.0.113.6/30

	// LAN subnet to intercept
	InterceptSubnet string `json:"intercept_subnet"` // e.g., 192.168.10.0/24

	// LAN interface in VPP to attach ABF
	LanInterface string `json:"lan_interface"` // e.g., vmxnet3-0/b/0/0

	// ABF/ACL IDs
	ACLIndex  uint32 `json:"acl_index"`
	ABFPolicy uint32 `json:"abf_policy"`

	// mitmproxy settings
	MitmproxyPort    uint16 `json:"mitmproxy_port"`     // Default: 8080
	MitmproxyWebPort uint16 `json:"mitmproxy_web_port"` // Default: 8081

	// Ports to intercept
	InterceptHTTP  bool `json:"intercept_http"`  // Port 80
	InterceptHTTPS bool `json:"intercept_https"` // Port 443
}

// TLSInterceptionStatus - Current status of TLS interception (simplified for web UI)
type TLSInterceptionStatus struct {
	IsEnabled          bool      `json:"is_enabled"`
	Tap0Created        bool      `json:"tap0_created"`
	Tap1Created        bool      `json:"tap1_created"`
	ABFConfigured      bool      `json:"abf_configured"`
	KernelConfigured   bool      `json:"kernel_configured"`
	MitmproxyRunning   bool      `json:"mitmproxy_running"`
	MitmproxyPID       int       `json:"mitmproxy_pid"`
	LastError          string    `json:"last_error,omitempty"`
	ConfiguredAt       time.Time `json:"configured_at,omitempty"`
	AttachedInterfaces []string  `json:"attached_interfaces,omitempty"` // LAN interfaces with ABF attached
}

// TLSInterceptionStatusSimple - User-friendly status for web UI (hides technical details)
type TLSInterceptionStatusSimple struct {
	Enabled            bool     `json:"enabled"`
	SystemReady        bool     `json:"system_ready"`
	InspectionActive   bool     `json:"inspection_active"`
	AttachedInterfaces []string `json:"attached_interfaces"`
	ErrorMessage       string   `json:"error_message,omitempty"`
}

// TLSInterceptionManager - Manages TLS interception lifecycle
type TLSInterceptionManager struct {
	vppClient *VPPClient
	config    *TLSInterceptionConfig
	status    TLSInterceptionStatus
	mu        sync.RWMutex

	// Created interface indices
	tap0SwIfIndex uint32
	tap1SwIfIndex uint32
}

// NewTLSInterceptionManager creates a new TLS interception manager
func NewTLSInterceptionManager(vppClient *VPPClient) *TLSInterceptionManager {
	return &TLSInterceptionManager{
		vppClient: vppClient,
		config:    DefaultTLSInterceptionConfig(),
		status:    TLSInterceptionStatus{},
	}
}

// DefaultTLSInterceptionConfig returns default configuration
func DefaultTLSInterceptionConfig() *TLSInterceptionConfig {
	return &TLSInterceptionConfig{
		Tap0ID:           0,
		Tap1ID:           1,
		Tap0HostName:     "vpp-tap0",
		Tap1HostName:     "vpp-tap1",
		Tap0VppIP:        "203.0.113.1/30",
		Tap1VppIP:        "203.0.113.5/30",
		Tap0HostIP:       "203.0.113.2/30",
		Tap1HostIP:       "203.0.113.6/30",
		InterceptSubnet:  "192.168.10.0/24",
		LanInterface:     "",
		ACLIndex:         100,
		ABFPolicy:        10,
		MitmproxyPort:    8080,
		MitmproxyWebPort: 8081,
		InterceptHTTP:    true,
		InterceptHTTPS:   true,
	}
}

// GetConfig returns current configuration
func (m *TLSInterceptionManager) GetConfig() *TLSInterceptionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// SetConfig updates configuration
func (m *TLSInterceptionManager) SetConfig(config *TLSInterceptionConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.config = config
}

// GetStatus returns current status by actively checking all components
func (m *TLSInterceptionManager) GetStatus() TLSInterceptionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Actively check all components
	m.detectExistingResources()

	return m.status
}

// GetSimpleStatus returns user-friendly status for web UI (hides technical details)
func (m *TLSInterceptionManager) GetSimpleStatus() TLSInterceptionStatusSimple {
	status := m.GetStatus()

	return TLSInterceptionStatusSimple{
		Enabled:            status.IsEnabled,
		SystemReady:        status.Tap0Created && status.Tap1Created && status.KernelConfigured,
		InspectionActive:   status.MitmproxyRunning,
		AttachedInterfaces: status.AttachedInterfaces,
		ErrorMessage:       status.LastError,
	}
}

// detectExistingResources checks for already-existing TLS interception resources
func (m *TLSInterceptionManager) detectExistingResources() {
	// Get interfaces ONCE to avoid multiple VPP API calls
	interfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		// If we can't get interfaces, assume nothing is configured
		m.status.Tap0Created = false
		m.status.Tap1Created = false
		m.status.ABFConfigured = false
		m.status.AttachedInterfaces = nil
		m.status.IsEnabled = false
		return
	}

	// 1. Find TAP interfaces by their IPs (more reliable than name)
	tap0IP := strings.Split(m.config.Tap0VppIP, "/")[0] // 203.0.113.1
	tap1IP := strings.Split(m.config.Tap1VppIP, "/")[0] // 203.0.113.5

	m.tap0SwIfIndex, m.status.Tap0Created = m.findInterfaceByIPFromList(interfaces, tap0IP)
	m.tap1SwIfIndex, m.status.Tap1Created = m.findInterfaceByIPFromList(interfaces, tap1IP)

	// 2. Check mitmproxy running status
	m.status.MitmproxyRunning, m.status.MitmproxyPID = m.checkMitmproxyRunning()

	// 3. Check kernel configuration (IP forwarding + iptables)
	m.status.KernelConfigured = m.checkKernelConfigured()

	// 4. Check ABF configuration and get attached interfaces
	m.status.ABFConfigured, m.status.AttachedInterfaces = m.checkABFAndAttachmentsWithInterfaces(interfaces)

	// 5. Update overall enabled status
	m.status.IsEnabled = m.status.Tap0Created && m.status.Tap1Created &&
		m.status.MitmproxyRunning && m.status.KernelConfigured && m.status.ABFConfigured
}

// findInterfaceByIPFromList finds a VPP interface by IP from a pre-fetched list
func (m *TLSInterceptionManager) findInterfaceByIPFromList(interfaces []InterfaceInfo, targetIP string) (uint32, bool) {
	for _, iface := range interfaces {
		for _, ip := range iface.IPAddresses {
			ifaceIP := strings.Split(ip, "/")[0]
			if ifaceIP == targetIP {
				return iface.Index, true
			}
		}
	}
	return 0, false
}

// checkKernelConfigured checks if kernel networking is configured for TLS interception
func (m *TLSInterceptionManager) checkKernelConfigured() bool {
	// Check IP forwarding
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		return false
	}

	// Check if iptables redirect rules exist for port 80 or 443
	out, err = exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").Output()
	if err != nil {
		return false
	}

	rules := string(out)
	hasHTTPRedirect := strings.Contains(rules, "--dport 80") && strings.Contains(rules, "REDIRECT")
	hasHTTPSRedirect := strings.Contains(rules, "--dport 443") && strings.Contains(rules, "REDIRECT")

	// At least one redirect should be configured
	return hasHTTPRedirect || hasHTTPSRedirect
}

// checkABFAndAttachmentsWithInterfaces checks ABF config using pre-fetched interfaces
func (m *TLSInterceptionManager) checkABFAndAttachmentsWithInterfaces(interfaces []InterfaceInfo) (bool, []string) {
	if m.vppClient.AbfManager == nil {
		return false, nil
	}

	// Get ABF policies
	policies, err := m.vppClient.AbfManager.ListPolicies(context.Background())
	if err != nil {
		return false, nil
	}

	policyExists := false
	for _, p := range policies {
		if p.Policy.PolicyID == m.config.ABFPolicy {
			policyExists = true
			break
		}
	}

	if !policyExists {
		return false, nil
	}

	// Get attached interfaces
	attachments, err := m.vppClient.AbfManager.ListInterfaceAttachments(context.Background())
	if err != nil {
		return policyExists, nil
	}

	var attachedNames []string
	for _, att := range attachments {
		if att.Attach.PolicyID == m.config.ABFPolicy {
			// Get interface name by index from pre-fetched list
			ifaceName := getInterfaceNameFromList(interfaces, uint32(att.Attach.SwIfIndex))
			if ifaceName != "" {
				attachedNames = append(attachedNames, ifaceName)
			}
		}
	}

	return policyExists, attachedNames
}

// getInterfaceNameFromList returns interface name from pre-fetched list
func getInterfaceNameFromList(interfaces []InterfaceInfo, swIfIndex uint32) string {
	for _, iface := range interfaces {
		if iface.Index == swIfIndex {
			if iface.Tag != "" {
				return iface.Tag
			}
			return iface.Name
		}
	}
	return ""
}

// GetInspectionLogs returns recent inspection logs (without exposing mitmproxy name)
func (m *TLSInterceptionManager) GetInspectionLogs(lines int) ([]string, error) {
	if lines <= 0 {
		lines = 50
	}

	// Read from mitmproxy log file or capture output
	logFile := "/tmp/tls_inspection.log"
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		return []string{"No inspection logs available"}, nil
	}

	out, err := exec.Command("tail", "-n", fmt.Sprintf("%d", lines), logFile).Output()
	if err != nil {
		return nil, err
	}

	logLines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return logLines, nil
}

// Enable sets up complete TLS interception
func (m *TLSInterceptionManager) Enable(ctx context.Context, config *TLSInterceptionConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if config != nil {
		m.config = config
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔐 ENABLING TLS INTERCEPTION...")
	fmt.Println(strings.Repeat("=", 70))

	var lastError string

	// Get interfaces once to detect existing TAPs
	interfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		lastError = fmt.Sprintf("Failed to get interfaces: %v", err)
		m.status.LastError = lastError
		return fmt.Errorf(lastError)
	}

	// Check if TAP interfaces already exist by IP
	tap0IP := strings.Split(m.config.Tap0VppIP, "/")[0]
	tap1IP := strings.Split(m.config.Tap1VppIP, "/")[0]

	tap0Idx, tap0Exists := m.findInterfaceByIPFromList(interfaces, tap0IP)
	tap1Idx, tap1Exists := m.findInterfaceByIPFromList(interfaces, tap1IP)

	// Step 1: Create TAP interfaces in VPP (only if not exist)
	fmt.Println("\n📝 Step 1: Checking/Creating TAP interfaces in VPP...")
	if tap0Exists && tap1Exists {
		m.tap0SwIfIndex = tap0Idx
		m.tap1SwIfIndex = tap1Idx
		m.status.Tap0Created = true
		m.status.Tap1Created = true
		fmt.Printf("  ✅ TAP interfaces already exist (tap0: idx=%d, tap1: idx=%d)\n", tap0Idx, tap1Idx)
	} else {
		if err := m.createTAPInterfaces(ctx); err != nil {
			lastError = fmt.Sprintf("TAP creation failed: %v", err)
			fmt.Printf("  ❌ %s\n", lastError)
			m.status.LastError = lastError
			return err
		}
		m.status.Tap0Created = true
		m.status.Tap1Created = true
		fmt.Println("  ✅ TAP interfaces created")
	}

	// Step 2: Configure VPP IPs on TAPs (skip if already configured)
	fmt.Println("\n📝 Step 2: Configuring VPP-side IPs...")
	if tap0Exists && tap1Exists {
		fmt.Println("  ✅ VPP IPs already configured")
	} else {
		if err := m.configureVPPIPs(ctx); err != nil {
			lastError = fmt.Sprintf("VPP IP config failed: %v", err)
			fmt.Printf("  ❌ %s\n", lastError)
			m.status.LastError = lastError
			return err
		}
		fmt.Println("  ✅ VPP IPs configured")
	}

	// Step 3: Create ACL and ABF policy (check if exists)
	fmt.Println("\n📝 Step 3: Creating ACL and ABF policy...")
	abfExists, _ := m.checkABFAndAttachmentsWithInterfaces(interfaces)
	if abfExists {
		m.status.ABFConfigured = true
		fmt.Println("  ✅ ABF policy already exists")
	} else {
		if err := m.configureABF(ctx); err != nil {
			lastError = fmt.Sprintf("ABF config failed: %v", err)
			fmt.Printf("  ❌ %s\n", lastError)
			m.status.LastError = lastError
			return err
		}
		m.status.ABFConfigured = true
		fmt.Println("  ✅ ACL and ABF configured")
	}

	// Step 3.5: Configure NAT44 for tap1 (return traffic goes through VPP NAT)
	fmt.Println("\n📝 Step 3.5: Configuring NAT44 for tap1 (inside interface)...")
	if err := m.configureTap1NAT(ctx); err != nil {
		fmt.Printf("  ⚠️  NAT44 config for tap1 failed: %v (continuing anyway)\n", err)
	} else {
		fmt.Println("  ✅ tap1 configured as NAT44 inside interface")
	}

	// Step 4: Configure Linux kernel (IP forwarding, routes, iptables)
	fmt.Println("\n📝 Step 4: Configuring Linux kernel networking...")
	if m.checkKernelConfigured() {
		m.status.KernelConfigured = true
		fmt.Println("  ✅ Kernel already configured")
	} else {
		if err := m.configureKernel(); err != nil {
			lastError = fmt.Sprintf("Kernel config failed: %v", err)
			fmt.Printf("  ❌ %s\n", lastError)
			m.status.LastError = lastError
			return err
		}
		m.status.KernelConfigured = true
		fmt.Println("  ✅ Kernel networking configured")
	}

	// Step 5: Start mitmproxy (check if running)
	fmt.Println("\n📝 Step 5: Starting mitmproxy...")
	if running, pid := m.checkMitmproxyRunning(); running {
		m.status.MitmproxyRunning = true
		m.status.MitmproxyPID = pid
		fmt.Printf("  ✅ mitmproxy already running (PID: %d)\n", pid)
	} else {
		if err := m.startMitmproxy(); err != nil {
			lastError = fmt.Sprintf("mitmproxy start failed: %v", err)
			fmt.Printf("  ⚠️  %s\n", lastError)
			// Don't fail completely, just warn
		} else {
			m.status.MitmproxyRunning = true
			fmt.Println("  ✅ mitmproxy started")
		}
	}

	m.status.IsEnabled = true
	m.status.ConfiguredAt = time.Now()
	m.status.LastError = ""

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("✅ TLS INTERCEPTION ENABLED SUCCESSFULLY!")
	fmt.Printf("   TAP0: %s (%s) <-> VPP %s\n", m.config.Tap0HostName, m.config.Tap0HostIP, m.config.Tap0VppIP)
	fmt.Printf("   TAP1: %s (%s) <-> VPP %s\n", m.config.Tap1HostName, m.config.Tap1HostIP, m.config.Tap1VppIP)
	fmt.Printf("   Intercepting: %s\n", m.config.InterceptSubnet)
	fmt.Printf("   mitmproxy: http://localhost:%d (web UI: %d)\n", m.config.MitmproxyPort, m.config.MitmproxyWebPort)
	fmt.Println(strings.Repeat("=", 70) + "\n")

	return nil
}

// Disable removes TLS interception
func (m *TLSInterceptionManager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println("\n🔓 DISABLING TLS INTERCEPTION...")

	// Step 1: Stop mitmproxy
	if err := m.stopMitmproxy(); err != nil {
		fmt.Printf("  ⚠️  Failed to stop mitmproxy: %v\n", err)
	}
	m.status.MitmproxyRunning = false

	// Step 2: Remove iptables rules
	if err := m.cleanupKernel(); err != nil {
		fmt.Printf("  ⚠️  Failed to cleanup kernel: %v\n", err)
	}
	m.status.KernelConfigured = false

	// Step 3: Remove NAT44 config for tap1
	if err := m.removeTap1NAT(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to remove NAT44 from tap1: %v\n", err)
	}

	// Step 4: Remove ABF policy
	if err := m.removeABF(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to remove ABF: %v\n", err)
	}
	m.status.ABFConfigured = false

	// Step 5: Delete TAP interfaces
	if err := m.deleteTAPInterfaces(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to delete TAP interfaces: %v\n", err)
	}
	m.status.Tap0Created = false
	m.status.Tap1Created = false

	m.status.IsEnabled = false
	fmt.Println("✅ TLS INTERCEPTION DISABLED")

	return nil
}

// ============================================
// VPP Configuration Methods
// ============================================

func (m *TLSInterceptionManager) createTAPInterfaces(ctx context.Context) error {
	// Create TAP0 (LAN-side, receives intercepted traffic)
	tap0Idx, err := m.vppClient.CreateTapWithHostIP(
		m.config.Tap0ID,
		m.config.Tap0HostName,
		m.config.Tap0HostIP,
	)
	if err != nil {
		return fmt.Errorf("failed to create tap0: %v", err)
	}
	m.tap0SwIfIndex = tap0Idx
	fmt.Printf("  ✅ Created %s (VPP index: %d, Host IP: %s)\n",
		m.config.Tap0HostName, tap0Idx, m.config.Tap0HostIP)

	// Create TAP1 (WAN-side, returns traffic to VPP)
	tap1Idx, err := m.vppClient.CreateTapWithHostIP(
		m.config.Tap1ID,
		m.config.Tap1HostName,
		m.config.Tap1HostIP,
	)
	if err != nil {
		return fmt.Errorf("failed to create tap1: %v", err)
	}
	m.tap1SwIfIndex = tap1Idx
	fmt.Printf("  ✅ Created %s (VPP index: %d, Host IP: %s)\n",
		m.config.Tap1HostName, tap1Idx, m.config.Tap1HostIP)

	return nil
}

func (m *TLSInterceptionManager) configureVPPIPs(ctx context.Context) error {
	// Add VPP-side IP to tap0
	if err := m.vppClient.AddInterfaceIP(m.tap0SwIfIndex, m.config.Tap0VppIP); err != nil {
		return fmt.Errorf("failed to add IP to tap0: %v", err)
	}
	fmt.Printf("  ✅ tap0 VPP IP: %s\n", m.config.Tap0VppIP)

	// Add VPP-side IP to tap1
	if err := m.vppClient.AddInterfaceIP(m.tap1SwIfIndex, m.config.Tap1VppIP); err != nil {
		return fmt.Errorf("failed to add IP to tap1: %v", err)
	}
	fmt.Printf("  ✅ tap1 VPP IP: %s\n", m.config.Tap1VppIP)

	return nil
}

func (m *TLSInterceptionManager) configureABF(ctx context.Context) error {
	// Get LAN interface index
	lanIfIndex, err := m.vppClient.GetInterfaceIndexByName(m.config.LanInterface)
	if err != nil {
		return fmt.Errorf("LAN interface '%s' not found: %v", m.config.LanInterface, err)
	}

	// Create ACL for TCP traffic from LAN subnet + DNS (UDP 53)
	aclRules := []ACLRuleSimple{
		// Allow DNS traffic (UDP port 53) - important for name resolution
		{
			Action:    "permit",
			Protocol:  "udp",
			SrcPrefix: m.config.InterceptSubnet,
			DstPrefix: "0.0.0.0/0",
			DstPort:   53,
		},
		// Allow TCP traffic for HTTP/HTTPS interception
		{
			Action:    "permit",
			Protocol:  "tcp",
			SrcPrefix: m.config.InterceptSubnet,
			DstPrefix: "0.0.0.0/0",
		},
	}

	aclIndex, err := m.vppClient.CreateSimpleACL(ctx, fmt.Sprintf("tls-intercept-%d", m.config.ACLIndex), aclRules)
	if err != nil {
		return fmt.Errorf("failed to create ACL: %v", err)
	}
	m.config.ACLIndex = aclIndex
	fmt.Printf("  ✅ ACL created (index: %d) - TCP from %s\n", aclIndex, m.config.InterceptSubnet)

	// Parse next-hop IP (kernel's tap0 IP without mask)
	nextHopIP := strings.Split(m.config.Tap0HostIP, "/")[0]
	nhAddr, err := parseIPToAddress(nextHopIP)
	if err != nil {
		return fmt.Errorf("failed to parse next-hop IP: %v", err)
	}

	// Create FibPath for ABF
	fibPaths := []fib_types.FibPath{
		{
			SwIfIndex: m.tap0SwIfIndex,
			Proto:     fib_types.FIB_API_PATH_NH_PROTO_IP4,
			Nh: fib_types.FibPathNh{
				Address: nhAddr,
			},
			Weight: 1,
		},
	}

	// Create ABF policy
	if err := m.vppClient.AbfManager.ConfigurePolicy(ctx, m.config.ABFPolicy, aclIndex, fibPaths, true); err != nil {
		return fmt.Errorf("failed to create ABF policy: %v", err)
	}
	fmt.Printf("  ✅ ABF policy created (ID: %d) -> next-hop %s via tap0\n", m.config.ABFPolicy, nextHopIP)

	// Attach ABF to LAN interface
	if err := m.vppClient.AbfManager.AttachToInterface(ctx, m.config.ABFPolicy, lanIfIndex, 10, false, true); err != nil {
		return fmt.Errorf("failed to attach ABF to interface: %v", err)
	}
	fmt.Printf("  ✅ ABF attached to %s (priority: 10)\n", m.config.LanInterface)

	return nil
}

func (m *TLSInterceptionManager) removeABF(ctx context.Context) error {
	// Get LAN interface index
	lanIfIndex, err := m.vppClient.GetInterfaceIndexByName(m.config.LanInterface)
	if err == nil {
		// Detach ABF from interface
		_ = m.vppClient.AbfManager.AttachToInterface(ctx, m.config.ABFPolicy, lanIfIndex, 10, false, false)
	}

	// Delete ABF policy
	_ = m.vppClient.AbfManager.ConfigurePolicy(ctx, m.config.ABFPolicy, m.config.ACLIndex, nil, false)

	// Delete ACL
	_ = m.vppClient.ACLManager.DeleteACL(ctx, m.config.ACLIndex)

	return nil
}

// configureTap1NAT configures tap1 as NAT44 inside interface
// This allows return traffic from kernel (mitmproxy) to go through VPP NAT
func (m *TLSInterceptionManager) configureTap1NAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil {
		return fmt.Errorf("NAT manager not available")
	}

	if m.tap1SwIfIndex == 0 {
		return fmt.Errorf("tap1 not created yet")
	}

	// Set tap1 as NAT44 inside interface
	if err := m.vppClient.NatManager.SetInterfaceNAT(ctx, m.tap1SwIfIndex, true, true); err != nil {
		return fmt.Errorf("failed to set tap1 as NAT inside: %v", err)
	}

	fmt.Printf("  ✅ tap1 (idx=%d) set as NAT44 inside interface\n", m.tap1SwIfIndex)
	return nil
}

// removeTap1NAT removes tap1 from NAT44 configuration
func (m *TLSInterceptionManager) removeTap1NAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil || m.tap1SwIfIndex == 0 {
		return nil
	}

	// Remove tap1 from NAT44 inside
	_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, m.tap1SwIfIndex, true, false)
	return nil
}

func (m *TLSInterceptionManager) deleteTAPInterfaces(ctx context.Context) error {
	if m.tap0SwIfIndex != 0 {
		_ = m.vppClient.DeleteInterface(m.tap0SwIfIndex, fmt.Sprintf("tap%d", m.config.Tap0ID))
	}
	if m.tap1SwIfIndex != 0 {
		_ = m.vppClient.DeleteInterface(m.tap1SwIfIndex, fmt.Sprintf("tap%d", m.config.Tap1ID))
	}
	return nil
}

// ============================================
// Linux Kernel Configuration Methods
// ============================================

func (m *TLSInterceptionManager) configureKernel() error {
	// 1. Enable IP forwarding
	if err := m.runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}
	fmt.Println("  ✅ IP forwarding enabled")

	// 2. Ensure TAP interfaces are up
	if err := m.runCommand("ip", "link", "set", m.config.Tap0HostName, "up"); err != nil {
		fmt.Printf("  ⚠️  Failed to bring up %s: %v\n", m.config.Tap0HostName, err)
	}
	if err := m.runCommand("ip", "link", "set", m.config.Tap1HostName, "up"); err != nil {
		fmt.Printf("  ⚠️  Failed to bring up %s: %v\n", m.config.Tap1HostName, err)
	}
	fmt.Println("  ✅ TAP interfaces are up")

	// 3. Add default route via tap1 (back to VPP)
	tap1VppIP := strings.Split(m.config.Tap1VppIP, "/")[0]
	_ = m.runCommand("ip", "route", "del", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName) // Remove if exists
	if err := m.runCommand("ip", "route", "add", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName, "metric", "10"); err != nil {
		fmt.Printf("  ⚠️  Route already exists or failed: %v\n", err)
	} else {
		fmt.Printf("  ✅ Default route added via %s (%s)\n", m.config.Tap1HostName, tap1VppIP)
	}

	// 4. Configure DNS (1.1.1.1) in resolv.conf
	if err := m.configureDNS(); err != nil {
		fmt.Printf("  ⚠️  Failed to configure DNS: %v\n", err)
	} else {
		fmt.Println("  ✅ DNS configured (1.1.1.1)")
	}

	// 5. Configure iptables NAT (MASQUERADE) on tap1 for return traffic
	// First check if rule already exists
	if !m.iptablesRuleExists("nat", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE") {
		if err := m.runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE"); err != nil {
			fmt.Printf("  ⚠️  MASQUERADE rule failed: %v\n", err)
		} else {
			fmt.Println("  ✅ NAT MASQUERADE configured on tap1")
		}
	} else {
		fmt.Println("  ✅ NAT MASQUERADE already configured on tap1")
	}

	// 6. Configure iptables REDIRECT for HTTP/HTTPS (intercept from tap0 -> mitmproxy)
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)

	if m.config.InterceptHTTP {
		if !m.iptablesRuleExists("nat", "PREROUTING", "-i", m.config.Tap0HostName, "-p", "tcp", "--dport", "80") {
			if err := m.runCommand("iptables", "-t", "nat", "-A", "PREROUTING", "-i", m.config.Tap0HostName,
				"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort); err != nil {
				fmt.Printf("  ⚠️  HTTP redirect rule failed: %v\n", err)
			} else {
				fmt.Printf("  ✅ HTTP (port 80) redirected to mitmproxy (port %s)\n", proxyPort)
			}
		} else {
			fmt.Println("  ✅ HTTP redirect rule already configured")
		}
	}

	if m.config.InterceptHTTPS {
		if !m.iptablesRuleExists("nat", "PREROUTING", "-i", m.config.Tap0HostName, "-p", "tcp", "--dport", "443") {
			if err := m.runCommand("iptables", "-t", "nat", "-A", "PREROUTING", "-i", m.config.Tap0HostName,
				"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort); err != nil {
				fmt.Printf("  ⚠️  HTTPS redirect rule failed: %v\n", err)
			} else {
				fmt.Printf("  ✅ HTTPS (port 443) redirected to mitmproxy (port %s)\n", proxyPort)
			}
		} else {
			fmt.Println("  ✅ HTTPS redirect rule already configured")
		}
	}

	return nil
}

// configureDNS sets up DNS to use 1.1.1.1 (Cloudflare)
func (m *TLSInterceptionManager) configureDNS() error {
	// Backup existing resolv.conf if not already backed up
	if _, err := os.Stat("/etc/resolv.conf.bak.tls"); os.IsNotExist(err) {
		_ = m.runCommand("cp", "/etc/resolv.conf", "/etc/resolv.conf.bak.tls")
	}

	// Write new resolv.conf with Cloudflare DNS
	dnsConfig := "# DNS configured by TLS Interception\nnameserver 1.1.1.1\nnameserver 1.0.0.1\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(dnsConfig), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %v", err)
	}

	return nil
}

// iptablesRuleExists checks if an iptables rule already exists
func (m *TLSInterceptionManager) iptablesRuleExists(table, chain string, ruleArgs ...string) bool {
	args := []string{"-t", table, "-C", chain}
	args = append(args, ruleArgs...)

	// -C checks if rule exists (returns 0 if exists, 1 if not)
	err := exec.Command("iptables", args...).Run()
	return err == nil
}

func (m *TLSInterceptionManager) cleanupKernel() error {
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)
	tap1VppIP := strings.Split(m.config.Tap1VppIP, "/")[0]

	// Remove iptables rules (ignore errors if not exist)
	_ = m.runCommand("iptables", "-t", "nat", "-D", "PREROUTING", "-i", m.config.Tap0HostName,
		"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", proxyPort)
	_ = m.runCommand("iptables", "-t", "nat", "-D", "PREROUTING", "-i", m.config.Tap0HostName,
		"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", proxyPort)
	_ = m.runCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE")

	// Remove route
	_ = m.runCommand("ip", "route", "del", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName)

	// Restore DNS from backup if exists
	if _, err := os.Stat("/etc/resolv.conf.bak.tls"); err == nil {
		_ = m.runCommand("cp", "/etc/resolv.conf.bak.tls", "/etc/resolv.conf")
		_ = m.runCommand("rm", "/etc/resolv.conf.bak.tls")
		fmt.Println("  ✅ DNS restored from backup")
	}

	fmt.Println("  ✅ Kernel rules cleaned up")
	return nil
}

// ============================================
// mitmproxy Management
// ============================================

func (m *TLSInterceptionManager) startMitmproxy() error {
	// Check if already running
	if running, _ := m.checkMitmproxyRunning(); running {
		fmt.Println("  ℹ️  mitmproxy already running")
		return nil
	}

	// Get working directory for the logger script
	wd, _ := os.Getwd()
	loggerScript := fmt.Sprintf("%s/scripts/mitmproxy_logger.py", wd)
	logFile := fmt.Sprintf("%s/url_logs.jsonl", wd)
	errorLogFile := fmt.Sprintf("%s/mitmproxy_error.log", wd)

	// Build command with URL logger addon
	args := []string{
		"--mode", "transparent",
		"--showhost",
		"--set", "block_global=false",
		"--listen-host", "0.0.0.0",
		"--listen-port", fmt.Sprintf("%d", m.config.MitmproxyPort),
		"--set", "termlog_verbosity=error",
	}

	// Add URL logger script if exists
	if _, err := os.Stat(loggerScript); err == nil {
		args = append(args, "-s", loggerScript)
		fmt.Printf("  ℹ️  Using URL logger: %s\n", loggerScript)
	}

	// Create error log file for debugging
	errFile, err := os.OpenFile(errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("  ⚠️  Cannot create error log file: %v\n", err)
		errFile = nil
	}

	// Set environment variable for log file location
	cmd := exec.Command("mitmdump", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("MITMPROXY_LOG_FILE=%s", logFile))
	cmd.Stdout = errFile
	cmd.Stderr = errFile

	if err := cmd.Start(); err != nil {
		if errFile != nil {
			errFile.Close()
		}
		return fmt.Errorf("failed to start mitmproxy: %v", err)
	}

	m.status.MitmproxyPID = cmd.Process.Pid
	fmt.Printf("  ✅ mitmproxy started (PID: %d, port: %d)\n", cmd.Process.Pid, m.config.MitmproxyPort)
	fmt.Printf("  ℹ️  Error log: %s\n", errorLogFile)

	// Don't wait, let it run in background
	go func() {
		_ = cmd.Wait()
		if errFile != nil {
			errFile.Close()
		}
	}()

	return nil
}

func (m *TLSInterceptionManager) stopMitmproxy() error {
	// Kill all mitmproxy processes
	_ = m.runCommand("pkill", "-f", "mitmdump")
	_ = m.runCommand("pkill", "-f", "mitmproxy")
	m.status.MitmproxyPID = 0
	fmt.Println("  ✅ mitmproxy stopped")
	return nil
}

func (m *TLSInterceptionManager) checkMitmproxyRunning() (bool, int) {
	out, err := exec.Command("pgrep", "-f", "mitmdump").Output()
	if err != nil {
		return false, 0
	}

	pidStr := strings.TrimSpace(string(out))
	if pidStr == "" {
		return false, 0
	}

	var pid int
	fmt.Sscanf(pidStr, "%d", &pid)
	return true, pid
}

// ============================================
// Helper Methods
// ============================================

func (m *TLSInterceptionManager) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

// ACLRuleSimple - Simplified ACL rule for interception
type ACLRuleSimple struct {
	Action    string `json:"action"`     // permit/deny
	Protocol  string `json:"protocol"`   // tcp/udp/any
	SrcPrefix string `json:"src_prefix"` // e.g., 192.168.10.0/24
	DstPrefix string `json:"dst_prefix"` // e.g., 0.0.0.0/0
	DstPort   uint16 `json:"dst_port"`   // Optional specific port
}

// parseIPToAddress converts IP string to VPP Address union
func parseIPToAddress(ipStr string) (ip_types.AddressUnion, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ip_types.AddressUnion{}, fmt.Errorf("invalid IP: %s", ipStr)
	}

	var addr ip_types.AddressUnion
	if ip4 := ip.To4(); ip4 != nil {
		var ip4Addr ip_types.IP4Address
		copy(ip4Addr[:], ip4)
		addr.SetIP4(ip4Addr)
	} else {
		var ip6Addr ip_types.IP6Address
		copy(ip6Addr[:], ip)
		addr.SetIP6(ip6Addr)
	}

	return addr, nil
}

// ============================================
// Export Configuration Script
// ============================================

// GenerateVPPScript generates VPP CLI commands for manual execution
func (m *TLSInterceptionManager) GenerateVPPScript() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("## VPP TLS Interception Setup Script\n")
	sb.WriteString("## Generated by vpp-go-test\n\n")

	sb.WriteString("## 1. Create TAP interfaces\n")
	sb.WriteString(fmt.Sprintf("create tap id %d host-if-name %s host-ip4-addr %s\n",
		m.config.Tap0ID, m.config.Tap0HostName, m.config.Tap0HostIP))
	sb.WriteString(fmt.Sprintf("create tap id %d host-if-name %s host-ip4-addr %s\n",
		m.config.Tap1ID, m.config.Tap1HostName, m.config.Tap1HostIP))
	sb.WriteString(fmt.Sprintf("set interface state tap%d up\n", m.config.Tap0ID))
	sb.WriteString(fmt.Sprintf("set interface state tap%d up\n\n", m.config.Tap1ID))

	sb.WriteString("## 2. Give VPP-side IPs\n")
	sb.WriteString(fmt.Sprintf("set interface ip address tap%d %s\n", m.config.Tap0ID, m.config.Tap0VppIP))
	sb.WriteString(fmt.Sprintf("set interface ip address tap%d %s\n\n", m.config.Tap1ID, m.config.Tap1VppIP))

	sb.WriteString("## 3. ABF Policy (The \"Traffic Hook\")\n")
	sb.WriteString("# Define which traffic to intercept\n")
	sb.WriteString(fmt.Sprintf("acl edit %d permit tcp src %s dst 0.0.0.0/0\n\n", m.config.ACLIndex, m.config.InterceptSubnet))

	nextHopIP := strings.Split(m.config.Tap0HostIP, "/")[0]
	sb.WriteString("# Define the path to the kernel\n")
	sb.WriteString(fmt.Sprintf("abf policy add id %d acl %d via %s tap%d\n\n",
		m.config.ABFPolicy, m.config.ACLIndex, nextHopIP, m.config.Tap0ID))

	sb.WriteString("# Attach policy to LAN interface\n")
	sb.WriteString(fmt.Sprintf("abf attach slot 1 policy id %d interface %s\n",
		m.config.ABFPolicy, m.config.LanInterface))

	return sb.String()
}

// GenerateKernelScript generates Linux setup script
func (m *TLSInterceptionManager) GenerateKernelScript() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("#!/bin/bash\n")
	sb.WriteString("## Linux Kernel TLS Interception Setup Script\n")
	sb.WriteString("## Generated by vpp-go-test\n\n")

	sb.WriteString("# Enable IP Forwarding\n")
	sb.WriteString("sysctl -w net.ipv4.ip_forward=1\n\n")

	sb.WriteString("# Ensure TAP interfaces are up\n")
	sb.WriteString(fmt.Sprintf("ip link set %s up\n", m.config.Tap0HostName))
	sb.WriteString(fmt.Sprintf("ip link set %s up\n\n", m.config.Tap1HostName))

	tap1VppIP := strings.Split(m.config.Tap1VppIP, "/")[0]
	sb.WriteString("# Add Route: Send everything back to VPP via tap1\n")
	sb.WriteString(fmt.Sprintf("ip route add default via %s dev %s metric 10\n\n",
		tap1VppIP, m.config.Tap1HostName))

	sb.WriteString("# Configure DNS (Cloudflare 1.1.1.1)\n")
	sb.WriteString("cp /etc/resolv.conf /etc/resolv.conf.bak.tls 2>/dev/null || true\n")
	sb.WriteString("cat > /etc/resolv.conf << EOF\n")
	sb.WriteString("# DNS configured by TLS Interception\n")
	sb.WriteString("nameserver 1.1.1.1\n")
	sb.WriteString("nameserver 1.0.0.1\n")
	sb.WriteString("EOF\n\n")

	sb.WriteString("# NAT: Masquerade traffic leaving tap1\n")
	sb.WriteString(fmt.Sprintf("iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n\n",
		m.config.Tap1HostName))

	sb.WriteString("# Interception: Redirect HTTP/S to mitmproxy\n")
	if m.config.InterceptHTTP {
		sb.WriteString(fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port %d\n",
			m.config.Tap0HostName, m.config.MitmproxyPort))
	}
	if m.config.InterceptHTTPS {
		sb.WriteString(fmt.Sprintf("iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 -j REDIRECT --to-port %d\n",
			m.config.Tap0HostName, m.config.MitmproxyPort))
	}

	sb.WriteString("\necho \"Kernel networking configured.\"\n")

	return sb.String()
}

// GenerateMitmproxyCommand generates mitmproxy command
func (m *TLSInterceptionManager) GenerateMitmproxyCommand() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return fmt.Sprintf("mitmdump --mode transparent --showhost --set block_global=false --listen-host 0.0.0.0 --listen-port %d --set termlog_verbosity=error &",
		m.config.MitmproxyPort)
}

// SaveScriptsToFiles saves generated scripts to files
func (m *TLSInterceptionManager) SaveScriptsToFiles(baseDir string) error {
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return err
	}

	// Save VPP script
	vppScript := m.GenerateVPPScript()
	if err := os.WriteFile(fmt.Sprintf("%s/vpp_tls_setup.conf", baseDir), []byte(vppScript), 0644); err != nil {
		return err
	}

	// Save Kernel script
	kernelScript := m.GenerateKernelScript()
	if err := os.WriteFile(fmt.Sprintf("%s/kernel_tls_setup.sh", baseDir), []byte(kernelScript), 0755); err != nil {
		return err
	}

	// Save mitmproxy command
	mitmCmd := m.GenerateMitmproxyCommand()
	if err := os.WriteFile(fmt.Sprintf("%s/start_mitmproxy.sh", baseDir), []byte("#!/bin/bash\n"+mitmCmd+"\n"), 0755); err != nil {
		return err
	}

	fmt.Printf("✅ Scripts saved to %s/\n", baseDir)
	return nil
}

// ============================================
// VPPClient Helper Methods for TLS Interception
// ============================================

// CreateSimpleACL creates an ACL from simplified rules
func (v *VPPClient) CreateSimpleACL(ctx context.Context, tag string, simpleRules []ACLRuleSimple) (uint32, error) {
	var vppRules []acl_types.ACLRule

	for _, rule := range simpleRules {
		// Parse source prefix
		srcPrefix, err := parsePrefixForACL(rule.SrcPrefix)
		if err != nil {
			return 0, fmt.Errorf("invalid src prefix: %v", err)
		}

		// Parse destination prefix
		dstPrefix, err := parsePrefixForACL(rule.DstPrefix)
		if err != nil {
			return 0, fmt.Errorf("invalid dst prefix: %v", err)
		}

		// Determine action
		var action acl_types.ACLAction
		switch strings.ToLower(rule.Action) {
		case "permit", "allow":
			action = acl_types.ACL_ACTION_API_PERMIT
		case "deny", "drop":
			action = acl_types.ACL_ACTION_API_DENY
		default:
			action = acl_types.ACL_ACTION_API_PERMIT
		}

		// Determine protocol
		var proto ip_types.IPProto
		switch strings.ToLower(rule.Protocol) {
		case "tcp":
			proto = ip_types.IP_API_PROTO_TCP
		case "udp":
			proto = ip_types.IP_API_PROTO_UDP
		case "icmp":
			proto = ip_types.IP_API_PROTO_ICMP
		default:
			proto = 0 // Any protocol
		}

		vppRule := acl_types.ACLRule{
			IsPermit:               action,
			SrcPrefix:              srcPrefix,
			DstPrefix:              dstPrefix,
			Proto:                  proto,
			SrcportOrIcmptypeFirst: 0,
			SrcportOrIcmptypeLast:  65535,
			DstportOrIcmpcodeFirst: 0,
			DstportOrIcmpcodeLast:  65535,
		}

		// If specific dst port
		if rule.DstPort > 0 {
			vppRule.DstportOrIcmpcodeFirst = rule.DstPort
			vppRule.DstportOrIcmpcodeLast = rule.DstPort
		}

		vppRules = append(vppRules, vppRule)
	}

	return v.ACLManager.CreateACL(ctx, tag, vppRules)
}

// parsePrefixForACL parses CIDR string to VPP Prefix format
func parsePrefixForACL(cidr string) (ip_types.Prefix, error) {
	if cidr == "" || cidr == "any" {
		return ip_types.Prefix{
			Address: ip_types.Address{Af: ip_types.ADDRESS_IP4},
			Len:     0,
		}, nil
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip_types.Prefix{}, err
	}

	prefixLen, _ := ipNet.Mask.Size()
	ip := ipNet.IP

	var prefix ip_types.Prefix
	if ip.To4() != nil {
		var ip4Addr ip_types.IP4Address
		copy(ip4Addr[:], ip.To4())
		prefix.Address.Af = ip_types.ADDRESS_IP4
		prefix.Address.Un.SetIP4(ip4Addr)
	} else {
		var ip6Addr ip_types.IP6Address
		copy(ip6Addr[:], ip)
		prefix.Address.Af = ip_types.ADDRESS_IP6
		prefix.Address.Un.SetIP6(ip6Addr)
	}
	prefix.Len = uint8(prefixLen)

	return prefix, nil
}
