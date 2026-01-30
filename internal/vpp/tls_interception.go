package vpp

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vpp-go-test/binapi/acl_types"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip_types"
)

const (
	tlsConfPath      = "/etc/sarhad-guard/tls-interception/tls_conf.conf"
	mitmproxyConfDir = "/root/.mitmproxy"

	urlLogsDir = "/etc/sarhad-guard/url_logs"
)

type TLSInterfaceABFConfig struct {
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex uint32 `json:"interface_index"`
	ACLIndex       uint32 `json:"acl_index"`
	ABFPolicyID    uint32 `json:"abf_policy_id"`
}

type TLSSavedNATState struct {
	InterfaceName  string `json:"interface_name"`
	InterfaceIndex uint32 `json:"interface_index"`
	WasNATInside   bool   `json:"was_nat_inside"`
	WasNATOutside  bool   `json:"was_nat_outside"`
}

type TLSInterceptionConfig struct {
	// TAP Interface Configuration
	Tap0ID       uint32 `json:"tap0_id"`
	Tap1ID       uint32 `json:"tap1_id"`
	Tap0HostName string `json:"tap0_host_name"`
	Tap1HostName string `json:"tap1_host_name"`

	// VPP-side IPs (connected to kernel)
	Tap0VppIP  string `json:"tap0_vpp_ip"`
	Tap1VppIP  string `json:"tap1_vpp_ip"`
	Tap0HostIP string `json:"tap0_host_ip"`
	Tap1HostIP string `json:"tap1_host_ip"`

	// LAN subnet to intercept (fallback)
	InterceptSubnet  string   `json:"intercept_subnet"`
	InterceptSubnets []string `json:"intercept_subnets"`
	// LAN interfaces in VPP to attach ABF
	LanInterfaces []string `json:"lan_interfaces"`
	// Deprecated
	LanInterface string `json:"lan_interface,omitempty"`

	// Deprecated base IDs (kept for compatibility)
	ACLIndex  uint32 `json:"acl_index"`
	ABFPolicy uint32 `json:"abf_policy"`

	// mitmproxy settings
	MitmproxyPort    uint16 `json:"mitmproxy_port"`
	MitmproxyWebPort uint16 `json:"mitmproxy_web_port"`

	// NEW: ports to intercept (TCP dports redirected to mitmproxy port)
	InterceptPorts []int `json:"intercept_ports"`

	// NEW: excluded URL patterns (substring match)
	ExcludedURLs []string `json:"excluded_urls"`

	// Backwards compatibility (old UI)
	InterceptHTTP  bool `json:"intercept_http"`
	InterceptHTTPS bool `json:"intercept_https"`
}

func DefaultTLSInterceptionConfig() *TLSInterceptionConfig {
	return &TLSInterceptionConfig{
		Tap0ID:           100,
		Tap1ID:           101,
		Tap0HostName:     "vpp-tap0",
		Tap1HostName:     "vpp-tap1",
		Tap0VppIP:        "203.0.113.1/30",
		Tap1VppIP:        "203.0.113.5/30",
		Tap0HostIP:       "203.0.113.2/30",
		Tap1HostIP:       "203.0.113.6/30",
		InterceptSubnet:  "192.168.10.0/24",
		InterceptSubnets: []string{},
		LanInterfaces:    []string{},
		LanInterface:     "",
		ACLIndex:         100,
		ABFPolicy:        10,
		MitmproxyPort:    8080,
		MitmproxyWebPort: 8081,
		InterceptPorts:   []int{80, 443},
		ExcludedURLs:     []string{},
		InterceptHTTP:    true,
		InterceptHTTPS:   true,
	}
}

func (c *TLSInterceptionConfig) GetLanInterfaces() []string {
	if len(c.LanInterfaces) > 0 {
		return c.LanInterfaces
	}
	if c.LanInterface != "" {
		return []string{c.LanInterface}
	}
	return []string{}
}

func (c *TLSInterceptionConfig) normalizedInterceptPorts() []int {
	var ports []int
	if len(c.InterceptPorts) > 0 {
		ports = append(ports, c.InterceptPorts...)
	} else {
		// fallback to old booleans
		if c.InterceptHTTP {
			ports = append(ports, 80)
		}
		if c.InterceptHTTPS {
			ports = append(ports, 443)
		}
	}

	// sanitize, dedup, remove mitmproxyPort to avoid loops
	seen := map[int]bool{}
	var out []int
	for _, p := range ports {
		if p <= 0 || p > 65535 {
			continue
		}
		if p == int(c.MitmproxyPort) {
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

func (c *TLSInterceptionConfig) normalizedExcludedURLs() []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range c.ExcludedURLs {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		if len(t) > 300 {
			t = t[:300]
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func (c *TLSInterceptionConfig) Normalize() {
	// normalize LanInterfaces (trim, dedup)
	var lan []string
	seen := map[string]bool{}
	for _, i := range c.GetLanInterfaces() {
		t := strings.TrimSpace(i)
		if t == "" {
			continue
		}
		if !seen[t] {
			seen[t] = true
			lan = append(lan, t)
		}
	}
	c.LanInterfaces = lan
	c.LanInterface = ""

	// normalize ports/excludes
	c.InterceptPorts = c.normalizedInterceptPorts()
	c.ExcludedURLs = c.normalizedExcludedURLs()

	// keep backwards-compat flags consistent
	c.InterceptHTTP = containsInt(c.InterceptPorts, 80)
	c.InterceptHTTPS = containsInt(c.InterceptPorts, 443)
}

func containsInt(arr []int, v int) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

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
	AttachedInterfaces []string  `json:"attached_interfaces,omitempty"`
}

type TLSInterceptionStatusSimple struct {
	Enabled            bool     `json:"enabled"`
	SystemReady        bool     `json:"system_ready"`
	InspectionActive   bool     `json:"inspection_active"`
	MitmproxyRunning   bool     `json:"mitmproxy_running"`
	AttachedInterfaces []string `json:"attached_interfaces"`
	ActivePorts        []int    `json:"active_ports"`
	ErrorMessage       string   `json:"error_message,omitempty"`
}

type TLSInterceptionManager struct {
	vppClient *VPPClient
	config    *TLSInterceptionConfig
	status    TLSInterceptionStatus
	mu        sync.RWMutex

	tap0SwIfIndex uint32
	tap1SwIfIndex uint32

	interfaceABFConfigs []TLSInterfaceABFConfig
	savedNATStates      []TLSSavedNATState
}

func NewTLSInterceptionManager(vppClient *VPPClient) *TLSInterceptionManager {
	cfg := DefaultTLSInterceptionConfig()
	_ = loadTLSConfigFromDisk(cfg) // ignore errors, fallback to default
	cfg.Normalize()

	return &TLSInterceptionManager{
		vppClient: vppClient,
		config:    cfg,
		status:    TLSInterceptionStatus{},
	}
}

func (m *TLSInterceptionManager) GetConfig() *TLSInterceptionConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// return a copy to avoid external mutation
	b, _ := json.Marshal(m.config)
	var out TLSInterceptionConfig
	_ = json.Unmarshal(b, &out)
	return &out
}

// UpdateConfig persists config to disk and if engine is enabled applies changes LIVE (ports/interfaces/excludes).
func (m *TLSInterceptionManager) UpdateConfig(ctx context.Context, newCfg *TLSInterceptionConfig) error {
	if newCfg == nil {
		return fmt.Errorf("config is nil")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load the complete, existing config from disk as the base.
	baseConfig := DefaultTLSInterceptionConfig()
	_ = loadTLSConfigFromDisk(baseConfig)

	// Preserve old values for delta calculation
	oldPorts := baseConfig.normalizedInterceptPorts()
	oldLan := baseConfig.GetLanInterfaces()

	// Normalize the incoming UI config to clean up its data.
	newCfg.Normalize()

	// Merge only the UI-managed fields from the new config into the base config.
	baseConfig.InterceptSubnet = newCfg.InterceptSubnet
	baseConfig.LanInterfaces = newCfg.LanInterfaces
	baseConfig.InterceptPorts = newCfg.InterceptPorts
	baseConfig.ExcludedURLs = newCfg.ExcludedURLs
	baseConfig.InterceptHTTP = newCfg.InterceptHTTP
	baseConfig.InterceptHTTPS = newCfg.InterceptHTTPS

	// The merged config is the new source of truth.
	baseConfig.Normalize()
	m.config = baseConfig
	_ = saveTLSConfigToDisk(m.config)

	// Apply live if enabled
	if m.status.IsEnabled {
		// 1) update iptables redirect ports
		if err := m.applyPortDelta(oldPorts, m.config.normalizedInterceptPorts()); err != nil {
			m.status.LastError = fmt.Sprintf("iptables update failed: %v", err)
			return fmt.Errorf("iptables update failed: %v", err)
		}

		// 2) update ABF attachments per interface
		if err := m.applyInterfaceDelta(ctx, oldLan, m.config.GetLanInterfaces()); err != nil {
			m.status.LastError = fmt.Sprintf("interface update failed: %v", err)
			return fmt.Errorf("interface update failed: %v", err)
		}
	}

	// refresh status
	m.detectExistingResources()
	return nil
}

func setDiff(oldArr, newArr []string) (added []string, removed []string) {
	oldSet := map[string]bool{}
	newSet := map[string]bool{}
	for _, s := range oldArr {
		oldSet[s] = true
	}
	for _, s := range newArr {
		newSet[s] = true
	}
	for s := range newSet {
		if !oldSet[s] {
			added = append(added, s)
		}
	}
	for s := range oldSet {
		if !newSet[s] {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func intSetDiff(oldPorts, newPorts []int) (added []int, removed []int) {
	oldSet := map[int]bool{}
	newSet := map[int]bool{}
	for _, p := range oldPorts {
		oldSet[p] = true
	}
	for _, p := range newPorts {
		newSet[p] = true
	}
	for p := range newSet {
		if !oldSet[p] {
			added = append(added, p)
		}
	}
	for p := range oldSet {
		if !newSet[p] {
			removed = append(removed, p)
		}
	}
	sort.Ints(added)
	sort.Ints(removed)
	return
}

func (m *TLSInterceptionManager) applyPortDelta(oldPorts, newPorts []int) error {
	added, removed := intSetDiff(oldPorts, newPorts)
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)

	// remove first
	for _, p := range removed {
		if m.iptablesRuleExists("nat", "PREROUTING",
			"-i", m.config.Tap0HostName,
			"-p", "tcp",
			"--dport", fmt.Sprintf("%d", p),
			"-j", "REDIRECT", "--to-port", proxyPort) {
			_ = m.runCommand("iptables", "-t", "nat", "-D", "PREROUTING",
				"-i", m.config.Tap0HostName,
				"-p", "tcp",
				"--dport", fmt.Sprintf("%d", p),
				"-j", "REDIRECT", "--to-port", proxyPort)
		}
	}

	// add
	for _, p := range added {
		if !m.iptablesRuleExists("nat", "PREROUTING",
			"-i", m.config.Tap0HostName,
			"-p", "tcp",
			"--dport", fmt.Sprintf("%d", p),
			"-j", "REDIRECT", "--to-port", proxyPort) {
			if err := m.runCommand("iptables", "-t", "nat", "-A", "PREROUTING",
				"-i", m.config.Tap0HostName,
				"-p", "tcp",
				"--dport", fmt.Sprintf("%d", p),
				"-j", "REDIRECT", "--to-port", proxyPort); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *TLSInterceptionManager) applyInterfaceDelta(ctx context.Context, oldLan, newLan []string) error {
	added, removed := setDiff(oldLan, newLan)

	// Ensure we have tracked configs if ABF already existed
	if len(m.interfaceABFConfigs) == 0 && m.status.ABFConfigured {
		_ = m.syncInterfaceABFConfigs(ctx)
	}

	// remove first (detach+delete+restore nat)
	for _, iface := range removed {
		_ = m.removeSingleInterfaceABF(ctx, iface)
		_ = m.restoreNATForInterface(ctx, iface)
	}

	// add new
	for _, iface := range added {
		// save+disable NAT if needed
		_ = m.saveAndDisableNATForInterface(ctx, iface)
		if err := m.addSingleInterfaceABF(ctx, iface); err != nil {
			return err
		}
	}

	return nil
}

func (m *TLSInterceptionManager) GetStatus() TLSInterceptionStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.detectExistingResources()
	return m.status
}

func (m *TLSInterceptionManager) GetSimpleStatus() TLSInterceptionStatusSimple {
	status := m.GetStatus()
	ports := m.config.normalizedInterceptPorts()

	return TLSInterceptionStatusSimple{
		Enabled:            status.IsEnabled,
		SystemReady:        status.Tap0Created && status.Tap1Created && status.KernelConfigured,
		InspectionActive:   status.MitmproxyRunning,
		MitmproxyRunning:   status.MitmproxyRunning,
		AttachedInterfaces: status.AttachedInterfaces,
		ActivePorts:        ports,
		ErrorMessage:       status.LastError,
	}
}

func (m *TLSInterceptionManager) detectExistingResources() {
	fmt.Println("\n🧐 Detecting existing TLS interception resources...")
	interfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		m.status.Tap0Created = false
		m.status.Tap1Created = false
		m.status.ABFConfigured = false
		m.status.AttachedInterfaces = nil
		m.status.IsEnabled = false
		return
	}

	tap0IP := strings.Split(m.config.Tap0VppIP, "/")[0]
	tap1IP := strings.Split(m.config.Tap1VppIP, "/")[0]

	m.tap0SwIfIndex, m.status.Tap0Created = m.findInterfaceByIPFromList(interfaces, tap0IP)
	m.tap1SwIfIndex, m.status.Tap1Created = m.findInterfaceByIPFromList(interfaces, tap1IP)

	m.status.MitmproxyRunning, m.status.MitmproxyPID = m.checkMitmproxyRunning()
	m.status.KernelConfigured = m.checkKernelConfigured()
	fmt.Println("  kernel configured:", m.status.KernelConfigured)

	m.status.ABFConfigured, m.status.AttachedInterfaces = m.checkABFAndAttachmentsWithInterfaces(interfaces)

	m.status.IsEnabled = m.status.Tap0Created && m.status.Tap1Created &&
		m.status.MitmproxyRunning && m.status.KernelConfigured && m.status.ABFConfigured
	fmt.Printf(" Tap0Created: %v, Tap1Created: %v, MitmproxyRunning: %v, KernelConfigured: %v, ABFConfigured: %v, IsEnabled: %v\n",
		m.status.Tap0Created, m.status.Tap1Created, m.status.MitmproxyRunning, m.status.KernelConfigured, m.status.ABFConfigured, m.status.IsEnabled)
}

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

func (m *TLSInterceptionManager) checkKernelConfigured() bool {
	fmt.Println("  🔍 Checking kernel networking configuration...")
	out, err := exec.Command("sysctl", "-n", "net.ipv4.ip_forward").Output()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		fmt.Println("ipforwarding check is failed:", err, string(out))
		return false
	}

	out, err = exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").Output()
	if err != nil {
		fmt.Println("iptables check is failed:", err, string(out))
		return false
	}

	rules := string(out)
	// must have at least one redirect on tap0HostName to mitmproxy port
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)

	// Note: iptables -S may canonicalize --to-port to --to-ports
	hasTapInterface := strings.Contains(rules, "-i "+m.config.Tap0HostName)
	hasRedirectTarget := strings.Contains(rules, "REDIRECT")
	hasToPort := strings.Contains(rules, "--to-port "+proxyPort) || strings.Contains(rules, "--to-ports "+proxyPort)

	isConfigured := hasTapInterface && hasRedirectTarget && hasToPort
	fmt.Printf("  kernel configured: %v\n", isConfigured)

	return isConfigured
}

func (m *TLSInterceptionManager) checkABFAndAttachmentsWithInterfaces(interfaces []InterfaceInfo) (bool, []string) {
	if m.vppClient.AbfManager == nil {
		return false, nil
	}

	policies, err := m.vppClient.AbfManager.ListPolicies(context.Background())
	if err != nil {
		return false, nil
	}

	policyExists := false
	for _, p := range policies {
		if p.Policy.PolicyID >= m.config.ABFPolicy && p.Policy.PolicyID < m.config.ABFPolicy+100 {
			policyExists = true
			break
		}
	}
	if !policyExists {
		return false, nil
	}

	attachments, err := m.vppClient.AbfManager.ListInterfaceAttachments(context.Background())
	if err != nil {
		return policyExists, nil
	}

	var attachedNames []string
	for _, att := range attachments {
		if att.Attach.PolicyID >= m.config.ABFPolicy && att.Attach.PolicyID < m.config.ABFPolicy+100 {
			ifaceName := getInterfaceNameFromList(interfaces, uint32(att.Attach.SwIfIndex))
			if ifaceName != "" {
				attachedNames = append(attachedNames, ifaceName)
			}
		}
	}

	return policyExists, attachedNames
}

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

func (m *TLSInterceptionManager) getInterfaceSubnet(interfaces []InterfaceInfo, ifaceName string) string {
	for _, iface := range interfaces {
		if iface.Name == ifaceName || iface.Tag == ifaceName {
			if len(iface.IPAddresses) > 0 {
				ipWithMask := iface.IPAddresses[0]
				_, ipNet, err := net.ParseCIDR(ipWithMask)
				if err == nil && ipNet != nil {
					return ipNet.String()
				}
				parts := strings.Split(ipWithMask, "/")
				if len(parts) == 2 {
					ipParts := strings.Split(parts[0], ".")
					if len(ipParts) == 4 {
						return ipParts[0] + "." + ipParts[1] + "." + ipParts[2] + ".0/" + parts[1]
					}
				}
			}
		}
	}
	return ""
}

func (m *TLSInterceptionManager) Enable(ctx context.Context, config *TLSInterceptionConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// If a new config is provided by the UI, load the existing full config,
	// merge the UI-specific fields, and save it back.
	if config != nil {
		// Load the full configuration from disk first to not lose static values.
		existingConfig := DefaultTLSInterceptionConfig()
		_ = loadTLSConfigFromDisk(existingConfig)

		// Normalize the incoming UI config to clean up its data.
		config.Normalize()

		// Now, apply ONLY the changes from the UI request onto the existing config.
		existingConfig.InterceptSubnet = config.InterceptSubnet
		existingConfig.LanInterfaces = config.LanInterfaces
		existingConfig.InterceptPorts = config.InterceptPorts
		existingConfig.ExcludedURLs = config.ExcludedURLs
		existingConfig.InterceptHTTP = config.InterceptHTTP
		existingConfig.InterceptHTTPS = config.InterceptHTTPS
		// Other fields like Tap IPs, proxy ports etc., are preserved from existingConfig.

		// Re-normalize the merged config, make it active, and save it.
		existingConfig.Normalize()
		m.config = existingConfig
		if err := saveTLSConfigToDisk(m.config); err != nil {
			m.status.LastError = fmt.Sprintf("Failed to save merged config: %v", err)
			return fmt.Errorf("%s", m.status.LastError)
		}
	} else {
		// If no config is passed, ensure the latest from disk is loaded.
		cfg := DefaultTLSInterceptionConfig()
		_ = loadTLSConfigFromDisk(cfg)
		m.config = cfg
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔐 ENABLING TRAFFIC INSPECTION...")
	fmt.Println(strings.Repeat("=", 70))

	interfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		m.status.LastError = fmt.Sprintf("Failed to get interfaces: %v", err)
		return fmt.Errorf("%s", m.status.LastError)
	}

	tap0IP := strings.Split(m.config.Tap0VppIP, "/")[0]
	tap1IP := strings.Split(m.config.Tap1VppIP, "/")[0]

	tap0Idx, tap0Exists := m.findInterfaceByIPFromList(interfaces, tap0IP)
	tap1Idx, tap1Exists := m.findInterfaceByIPFromList(interfaces, tap1IP)

	fmt.Println("\n📝 Step 1: Checking/Creating TAP interfaces in VPP...")
	if tap0Exists && tap1Exists {
		m.tap0SwIfIndex = tap0Idx
		m.tap1SwIfIndex = tap1Idx
		m.status.Tap0Created = true
		m.status.Tap1Created = true
		fmt.Printf("  ✅ TAP interfaces already exist (tap0 idx=%d, tap1 idx=%d)\n", tap0Idx, tap1Idx)
	} else {
		if err := m.createTAPInterfaces(ctx); err != nil {
			m.status.LastError = fmt.Sprintf("TAP creation failed: %v", err)
			return err
		}
		m.status.Tap0Created = true
		m.status.Tap1Created = true
		fmt.Println("  ✅ TAP interfaces created")
	}

	fmt.Println("\n📝 Step 2: Configuring VPP-side IPs...")
	if tap0Exists && tap1Exists {
		fmt.Println("  ✅ VPP IPs already configured")
	} else {
		if err := m.configureVPPIPs(ctx); err != nil {
			m.status.LastError = fmt.Sprintf("VPP IP config failed: %v", err)
			return err
		}
		fmt.Println("  ✅ VPP IPs configured")
	}

	fmt.Println("\n📝 Step 2.5: Saving and disabling NAT on LAN interfaces...")
	if err := m.saveAndDisableLANInterfacesNAT(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to save/disable NAT on LAN interfaces: %v\n", err)
	}

	fmt.Println("\n📝 Step 3: Creating ACL and ABF policy (per interface)...")
	abfExists, _ := m.checkABFAndAttachmentsWithInterfaces(interfaces)
	if abfExists {
		m.status.ABFConfigured = true
		fmt.Println("  ✅ ABF policy already exists")
		_ = m.syncInterfaceABFConfigs(ctx)
	} else {
		if err := m.configureABF(ctx); err != nil {
			m.status.LastError = fmt.Sprintf("ABF config failed: %v", err)
			return err
		}
		m.status.ABFConfigured = true
		fmt.Println("  ✅ ACL and ABF configured")
	}

	fmt.Println("\n📝 Step 3.5: Configuring NAT44 for tap1 (inside interface)...")
	if err := m.configureTap1NAT(ctx); err != nil {
		fmt.Printf("  ⚠️  NAT44 config for tap1 failed: %v (continuing)\n", err)
	} else {
		fmt.Println("  ✅ tap1 configured as NAT44 inside interface")
	}

	fmt.Println("\n📝 Step 4: Configuring Linux kernel networking...")
	if m.checkKernelConfigured() {
		m.status.KernelConfigured = true
		fmt.Println("  ✅ Kernel already configured")
	} else {
		if err := m.configureKernel(); err != nil {
			m.status.LastError = fmt.Sprintf("Kernel config failed: %v", err)
			return err
		}
		m.status.KernelConfigured = true
		fmt.Println("  ✅ Kernel networking configured")
	}

	fmt.Println("\n📝 Step 5: Starting mitmproxy...")
	if running, pid := m.checkMitmproxyRunning(); running {
		m.status.MitmproxyRunning = true
		m.status.MitmproxyPID = pid
		fmt.Printf("  ✅ mitmproxy already running (PID: %d)\n", pid)
	} else {
		if err := m.startMitmproxy(); err != nil {
			m.status.MitmproxyRunning = false
			m.status.LastError = fmt.Sprintf("mitmproxy start failed: %v", err)
			return fmt.Errorf("%s", m.status.LastError)
		}
		m.status.MitmproxyRunning = true
		fmt.Println("  ✅ mitmproxy started")
		fmt.Printf("  ✅ mitmproxy PID: %d status %v\n", m.status.MitmproxyPID, m.status.IsEnabled)
	}

	m.status.ConfiguredAt = time.Now()
	m.detectExistingResources()

	if !m.status.IsEnabled {
		if m.status.LastError == "" {
			m.status.LastError = "inspection did not become active "
		}
		return fmt.Errorf("%s", m.status.LastError)
	}

	m.status.LastError = ""

	// ensure iptables ports reflect config (covers upgrades)
	_ = m.applyPortDelta([]int{}, m.config.normalizedInterceptPorts())

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("✅ TRAFFIC INSPECTION ENABLED!")
	fmt.Printf("   TAP0: %s (%s) <-> VPP %s\n", m.config.Tap0HostName, m.config.Tap0HostIP, m.config.Tap0VppIP)
	fmt.Printf("   TAP1: %s (%s) <-> VPP %s\n", m.config.Tap1HostName, m.config.Tap1HostIP, m.config.Tap1VppIP)
	fmt.Printf("   Intercept ports: %v -> mitmproxy:%d\n", m.config.normalizedInterceptPorts(), m.config.MitmproxyPort)
	fmt.Println(strings.Repeat("=", 70) + "\n")

	return nil
}

func (m *TLSInterceptionManager) Disable(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Println("\n🔓 DISABLING TRAFFIC INSPECTION...")

	if err := m.stopMitmproxy(); err != nil {
		fmt.Printf("  ⚠️  Failed to stop mitmproxy: %v\n", err)
	}
	m.status.MitmproxyRunning = false

	if err := m.cleanupKernel(); err != nil {
		fmt.Printf("  ⚠️  Failed to cleanup kernel: %v\n", err)
	}
	m.status.KernelConfigured = false

	if err := m.removeTap1NAT(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to remove NAT44 from tap1: %v\n", err)
	}

	if err := m.removeABF(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to remove ABF: %v\n", err)
	}
	m.status.ABFConfigured = false

	fmt.Println("  📝 Restoring NAT state for LAN interfaces...")
	if err := m.restoreLANInterfacesNAT(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to restore NAT on LAN interfaces: %v\n", err)
	}
	m.savedNATStates = nil

	if err := m.deleteTAPInterfaces(ctx); err != nil {
		fmt.Printf("  ⚠️  Failed to delete TAP interfaces: %v\n", err)
	}
	m.status.Tap0Created = false
	m.status.Tap1Created = false

	m.detectExistingResources()
	m.status.IsEnabled = false
	m.status.LastError = ""
	fmt.Println("✅ TRAFFIC INSPECTION DISABLED")

	return nil
}

// ---------------- VPP methods ----------------

func (m *TLSInterceptionManager) createTAPInterfaces(ctx context.Context) error {
	// Create tap0
	tap0Idx, err := m.vppClient.CreateTap(
		m.config.Tap0ID,
		m.config.Tap0HostName,
	)
	if err != nil {
		return fmt.Errorf("failed to create tap0: %v", err)
	}
	m.tap0SwIfIndex = tap0Idx
	if err := m.runCommand("ip", "addr", "add", m.config.Tap0HostIP, "dev", m.config.Tap0HostName); err != nil {
		// Even if this fails, the interface might exist, log and continue
		fmt.Printf("  ⚠️  Failed to set IP for %s: %v (continuing)\n", m.config.Tap0HostName, err)
	}
	fmt.Printf("  ✅ Created %s (VPP index: %d, Host IP: %s)\n",
		m.config.Tap0HostName, tap0Idx, m.config.Tap0HostIP)

	// Create tap1
	tap1Idx, err := m.vppClient.CreateTap(
		m.config.Tap1ID,
		m.config.Tap1HostName,
	)
	if err != nil {
		return fmt.Errorf("failed to create tap1: %v", err)
	}
	m.tap1SwIfIndex = tap1Idx
	if err := m.runCommand("ip", "addr", "add", m.config.Tap1HostIP, "dev", m.config.Tap1HostName); err != nil {
		fmt.Printf("  ⚠️  Failed to set IP for %s: %v (continuing)\n", m.config.Tap1HostName, err)
	}
	fmt.Printf("  ✅ Created %s (VPP index: %d, Host IP: %s)\n",
		m.config.Tap1HostName, tap1Idx, m.config.Tap1HostIP)

	return nil
}

func (m *TLSInterceptionManager) configureVPPIPs(ctx context.Context) error {
	if err := m.vppClient.AddInterfaceIP(m.tap0SwIfIndex, m.config.Tap0VppIP); err != nil {
		return fmt.Errorf("failed to add IP to tap0: %v", err)
	}
	if err := m.vppClient.AddInterfaceIP(m.tap1SwIfIndex, m.config.Tap1VppIP); err != nil {
		return fmt.Errorf("failed to add IP to tap1: %v", err)
	}
	return nil
}

func (m *TLSInterceptionManager) configureABF(ctx context.Context) error {
	lanInterfaces := m.config.GetLanInterfaces()
	if len(lanInterfaces) == 0 {
		return fmt.Errorf("no LAN interfaces configured")
	}

	m.interfaceABFConfigs = nil

	nextHopIP := strings.Split(m.config.Tap0HostIP, "/")[0]
	nhAddr, err := parseIPToAddress(nextHopIP)
	if err != nil {
		return fmt.Errorf("failed to parse next-hop IP: %v", err)
	}

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

	allInterfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces for subnet detection: %v", err)
	}

	for i, lanIface := range lanInterfaces {
		if err := m.addSingleInterfaceABFWithIndex(ctx, lanIface, allInterfaces, fibPaths, nextHopIP, uint32(i)); err != nil {
			return err
		}
	}

	return nil
}

// Incremental add for live update
func (m *TLSInterceptionManager) addSingleInterfaceABF(ctx context.Context, lanIface string) error {
	allInterfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %v", err)
	}

	nextHopIP := strings.Split(m.config.Tap0HostIP, "/")[0]
	nhAddr, err := parseIPToAddress(nextHopIP)
	if err != nil {
		return fmt.Errorf("failed to parse next-hop IP: %v", err)
	}

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

	// choose an unused offset 0..99 for policy id
	offset := m.allocatePolicyOffset()
	return m.addSingleInterfaceABFWithIndex(ctx, lanIface, allInterfaces, fibPaths, nextHopIP, offset)
}

func (m *TLSInterceptionManager) allocatePolicyOffset() uint32 {
	used := map[uint32]bool{}
	for _, cfg := range m.interfaceABFConfigs {
		if cfg.ABFPolicyID >= m.config.ABFPolicy && cfg.ABFPolicyID < m.config.ABFPolicy+100 {
			used[cfg.ABFPolicyID-m.config.ABFPolicy] = true
		}
	}
	for off := uint32(0); off < 100; off++ {
		if !used[off] {
			return off
		}
	}
	// if full, fallback 0 (will likely fail)
	return 0
}

func (m *TLSInterceptionManager) addSingleInterfaceABFWithIndex(
	ctx context.Context,
	lanIface string,
	allInterfaces []InterfaceInfo,
	fibPaths []fib_types.FibPath,
	nextHopIP string,
	offset uint32,
) error {
	if m.vppClient.AbfManager == nil {
		return fmt.Errorf("ABF manager not available")
	}

	lanIfIndex, err := m.vppClient.GetInterfaceIndexByName(lanIface)
	if err != nil {
		return fmt.Errorf("LAN interface '%s' not found: %v", lanIface, err)
	}

	interfaceSubnet := m.getInterfaceSubnet(allInterfaces, lanIface)
	if interfaceSubnet == "" {
		interfaceSubnet = m.config.InterceptSubnet
		fmt.Printf("  ⚠️  Interface %s has no IP, using fallback subnet: %s\n", lanIface, interfaceSubnet)
	}

	// ACL rules: allow DNS + allow all TCP (iptables will decide which ports to send to mitmproxy)
	aclRules := []ACLRuleSimple{
		{
			Action:    "permit",
			Protocol:  "udp",
			SrcPrefix: interfaceSubnet,
			DstPrefix: "0.0.0.0/0",
			DstPort:   53,
		},
		{
			Action:    "permit",
			Protocol:  "tcp",
			SrcPrefix: interfaceSubnet,
			DstPrefix: "0.0.0.0/0",
		},
	}

	tagNum := m.config.ACLIndex + offset
	tag := fmt.Sprintf("tls-intercept-%s-%d", lanIface, tagNum)

	aclIndex, err := m.vppClient.CreateSimpleACL(ctx, tag, aclRules)
	if err != nil {
		return fmt.Errorf("failed to create ACL for %s: %v", lanIface, err)
	}

	abfPolicyID := m.config.ABFPolicy + offset
	if err := m.vppClient.AbfManager.ConfigurePolicy(ctx, abfPolicyID, aclIndex, fibPaths, true); err != nil {
		return fmt.Errorf("failed to create ABF policy for %s: %v", lanIface, err)
	}

	if err := m.vppClient.AbfManager.AttachToInterface(ctx, abfPolicyID, lanIfIndex, 10, false, true); err != nil {
		return fmt.Errorf("failed to attach ABF to interface %s: %v", lanIface, err)
	}

	m.interfaceABFConfigs = append(m.interfaceABFConfigs, TLSInterfaceABFConfig{
		InterfaceName:  lanIface,
		InterfaceIndex: lanIfIndex,
		ACLIndex:       aclIndex,
		ABFPolicyID:    abfPolicyID,
	})

	fmt.Printf("  ✅ ABF attached to %s (Policy: %d, ACL: %d, subnet: %s)\n", lanIface, abfPolicyID, aclIndex, interfaceSubnet)
	return nil
}

func (m *TLSInterceptionManager) removeSingleInterfaceABF(ctx context.Context, ifaceName string) error {
	if m.vppClient.AbfManager == nil {
		return nil
	}

	// find
	idx := -1
	for i, cfg := range m.interfaceABFConfigs {
		if cfg.InterfaceName == ifaceName {
			idx = i
			break
		}
	}
	if idx == -1 {
		// try sync and retry once
		_ = m.syncInterfaceABFConfigs(ctx)
		for i, cfg := range m.interfaceABFConfigs {
			if cfg.InterfaceName == ifaceName {
				idx = i
				break
			}
		}
	}
	if idx == -1 {
		return nil
	}

	cfg := m.interfaceABFConfigs[idx]

	_ = m.vppClient.AbfManager.AttachToInterface(ctx, cfg.ABFPolicyID, cfg.InterfaceIndex, 10, false, false)

	// delete policy
	policies, err := m.vppClient.AbfManager.ListPolicies(ctx)
	if err == nil {
		for _, p := range policies {
			if p.Policy.PolicyID == cfg.ABFPolicyID {
				_ = m.vppClient.AbfManager.ConfigurePolicy(ctx, p.Policy.PolicyID, p.Policy.ACLIndex, p.Policy.Paths, false)
				break
			}
		}
	}

	// delete ACL
	if m.vppClient.ACLManager != nil && cfg.ACLIndex > 0 {
		_ = m.vppClient.ACLManager.DeleteACL(ctx, cfg.ACLIndex)
	}

	// remove from slice
	m.interfaceABFConfigs = append(m.interfaceABFConfigs[:idx], m.interfaceABFConfigs[idx+1:]...)
	fmt.Printf("  ✅ Removed ABF for %s\n", ifaceName)
	return nil
}

func (m *TLSInterceptionManager) syncInterfaceABFConfigs(ctx context.Context) error {
	if m.vppClient.AbfManager == nil {
		return nil
	}

	interfaces, err := m.vppClient.GetInterfaces()
	if err != nil {
		return err
	}

	attachments, err := m.vppClient.AbfManager.ListInterfaceAttachments(ctx)
	if err != nil {
		return err
	}

	policies, err := m.vppClient.AbfManager.ListPolicies(ctx)
	if err != nil {
		return err
	}

	policyToACL := map[uint32]uint32{}
	for _, p := range policies {
		policyToACL[p.Policy.PolicyID] = p.Policy.ACLIndex
	}

	var tracked []TLSInterfaceABFConfig
	for _, att := range attachments {
		pid := att.Attach.PolicyID
		if pid < m.config.ABFPolicy || pid >= m.config.ABFPolicy+100 {
			continue
		}
		ifName := getInterfaceNameFromList(interfaces, uint32(att.Attach.SwIfIndex))
		if ifName == "" {
			continue
		}
		tracked = append(tracked, TLSInterfaceABFConfig{
			InterfaceName:  ifName,
			InterfaceIndex: uint32(att.Attach.SwIfIndex),
			ACLIndex:       policyToACL[pid],
			ABFPolicyID:    pid,
		})
	}

	m.interfaceABFConfigs = tracked
	return nil
}

func (m *TLSInterceptionManager) removeABF(ctx context.Context) error {
	fmt.Println("  📝 Removing ABF configuration...")

	if m.vppClient.AbfManager == nil {
		return nil
	}

	if len(m.interfaceABFConfigs) == 0 {
		_ = m.syncInterfaceABFConfigs(ctx)
	}

	for _, cfg := range m.interfaceABFConfigs {
		_ = m.vppClient.AbfManager.AttachToInterface(ctx, cfg.ABFPolicyID, cfg.InterfaceIndex, 10, false, false)

		policies, err := m.vppClient.AbfManager.ListPolicies(ctx)
		if err == nil {
			for _, p := range policies {
				if p.Policy.PolicyID == cfg.ABFPolicyID {
					_ = m.vppClient.AbfManager.ConfigurePolicy(ctx, p.Policy.PolicyID, p.Policy.ACLIndex, p.Policy.Paths, false)
					break
				}
			}
		}

		if m.vppClient.ACLManager != nil && cfg.ACLIndex > 0 {
			_ = m.vppClient.ACLManager.DeleteACL(ctx, cfg.ACLIndex)
		}
	}

	m.interfaceABFConfigs = nil
	return nil
}

// ---------------- NAT methods ----------------

func (m *TLSInterceptionManager) configureTap1NAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil {
		return fmt.Errorf("NAT manager not available")
	}
	if m.tap1SwIfIndex == 0 {
		return fmt.Errorf("tap1 not created yet")
	}
	if err := m.vppClient.NatManager.SetInterfaceNAT(ctx, m.tap1SwIfIndex, true, true); err != nil {
		return fmt.Errorf("failed to set tap1 as NAT inside: %v", err)
	}
	return nil
}

func (m *TLSInterceptionManager) removeTap1NAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil || m.tap1SwIfIndex == 0 {
		return nil
	}
	_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, m.tap1SwIfIndex, true, false)
	return nil
}

func (m *TLSInterceptionManager) saveAndDisableLANInterfacesNAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil {
		return fmt.Errorf("NAT manager not available")
	}

	lanInterfaces := m.config.GetLanInterfaces()
	if len(lanInterfaces) == 0 {
		return nil
	}

	natInterfaces, err := m.vppClient.NatManager.GetNatInterfaces(ctx)
	if err != nil {
		return fmt.Errorf("failed to get NAT interfaces: %v", err)
	}

	natStateMap := make(map[uint32]struct {
		isInside  bool
		isOutside bool
	})
	for _, natIface := range natInterfaces {
		state := natStateMap[natIface.SwIfIndex]
		if natIface.IsInside {
			state.isInside = true
		} else {
			state.isOutside = true
		}
		natStateMap[natIface.SwIfIndex] = state
	}

	m.savedNATStates = nil

	for _, lanIface := range lanInterfaces {
		lanIfIndex, err := m.vppClient.GetInterfaceIndexByName(lanIface)
		if err != nil {
			continue
		}

		natState, hasNAT := natStateMap[lanIfIndex]
		if !hasNAT {
			continue
		}

		m.savedNATStates = append(m.savedNATStates, TLSSavedNATState{
			InterfaceName:  lanIface,
			InterfaceIndex: lanIfIndex,
			WasNATInside:   natState.isInside,
			WasNATOutside:  natState.isOutside,
		})

		if natState.isInside {
			_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, lanIfIndex, true, false)
		}
		if natState.isOutside {
			_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, lanIfIndex, false, false)
		}
	}

	return nil
}

func (m *TLSInterceptionManager) saveAndDisableNATForInterface(ctx context.Context, lanIface string) error {
	if m.vppClient.NatManager == nil {
		return nil
	}

	lanIfIndex, err := m.vppClient.GetInterfaceIndexByName(lanIface)
	if err != nil {
		return nil
	}

	natInterfaces, err := m.vppClient.NatManager.GetNatInterfaces(ctx)
	if err != nil {
		return nil
	}

	var wasInside, wasOutside bool
	for _, natIface := range natInterfaces {
		if natIface.SwIfIndex != lanIfIndex {
			continue
		}
		if natIface.IsInside {
			wasInside = true
		} else {
			wasOutside = true
		}
	}

	if !wasInside && !wasOutside {
		return nil
	}

	// ensure not duplicated
	for _, s := range m.savedNATStates {
		if s.InterfaceIndex == lanIfIndex {
			return nil
		}
	}

	m.savedNATStates = append(m.savedNATStates, TLSSavedNATState{
		InterfaceName:  lanIface,
		InterfaceIndex: lanIfIndex,
		WasNATInside:   wasInside,
		WasNATOutside:  wasOutside,
	})

	if wasInside {
		_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, lanIfIndex, true, false)
	}
	if wasOutside {
		_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, lanIfIndex, false, false)
	}

	return nil
}

func (m *TLSInterceptionManager) restoreLANInterfacesNAT(ctx context.Context) error {
	if m.vppClient.NatManager == nil {
		return fmt.Errorf("NAT manager not available")
	}

	for _, saved := range m.savedNATStates {
		if saved.WasNATInside {
			_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, saved.InterfaceIndex, true, true)
		}
		if saved.WasNATOutside {
			_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, saved.InterfaceIndex, false, true)
		}
	}
	return nil
}

func (m *TLSInterceptionManager) restoreNATForInterface(ctx context.Context, ifaceName string) error {
	if m.vppClient.NatManager == nil {
		return nil
	}
	// find state
	idx := -1
	for i, s := range m.savedNATStates {
		if s.InterfaceName == ifaceName {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil
	}
	s := m.savedNATStates[idx]

	if s.WasNATInside {
		_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, s.InterfaceIndex, true, true)
	}
	if s.WasNATOutside {
		_ = m.vppClient.NatManager.SetInterfaceNAT(ctx, s.InterfaceIndex, false, true)
	}

	m.savedNATStates = append(m.savedNATStates[:idx], m.savedNATStates[idx+1:]...)
	return nil
}

func (m *TLSInterceptionManager) deleteTAPInterfaces(ctx context.Context) error {
	fmt.Println("  📝 Deleting TAP interfaces...")

	if m.tap0SwIfIndex != 0 {
		_ = m.vppClient.DeleteInterface(m.tap0SwIfIndex, fmt.Sprintf("tap%d", m.config.Tap0ID))
		m.tap0SwIfIndex = 0
	}
	if m.tap1SwIfIndex != 0 {
		_ = m.vppClient.DeleteInterface(m.tap1SwIfIndex, fmt.Sprintf("tap%d", m.config.Tap1ID))
		m.tap1SwIfIndex = 0
	}
	return nil
}

// ---------------- Linux kernel methods ----------------

func (m *TLSInterceptionManager) configureKernel() error {
	if err := m.runCommand("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %v", err)
	}

	_ = m.runCommand("ip", "link", "set", m.config.Tap0HostName, "up")
	_ = m.runCommand("ip", "link", "set", m.config.Tap1HostName, "up")

	tap1VppIP := strings.Split(m.config.Tap1VppIP, "/")[0]
	_ = m.runCommand("ip", "route", "del", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName)
	_ = m.runCommand("ip", "route", "add", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName, "metric", "10")

	_ = m.configureDNS()

	if !m.iptablesRuleExists("nat", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE") {
		_ = m.runCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE")
	}

	// Redirect configured ports
	ports := m.config.normalizedInterceptPorts()
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)

	for _, p := range ports {
		if !m.iptablesRuleExists("nat", "PREROUTING",
			"-i", m.config.Tap0HostName, "-p", "tcp", "--dport", fmt.Sprintf("%d", p),
			"-j", "REDIRECT", "--to-port", proxyPort) {
			_ = m.runCommand("iptables", "-t", "nat", "-A", "PREROUTING",
				"-i", m.config.Tap0HostName, "-p", "tcp", "--dport", fmt.Sprintf("%d", p),
				"-j", "REDIRECT", "--to-port", proxyPort)
		}
	}

	return nil
}

func (m *TLSInterceptionManager) configureDNS() error {
	if _, err := os.Stat("/etc/resolv.conf.bak.tls"); os.IsNotExist(err) {
		_ = m.runCommand("cp", "/etc/resolv.conf", "/etc/resolv.conf.bak.tls")
	}
	dnsConfig := "# DNS configured by Traffic Inspection\nnameserver 1.1.1.1\nnameserver 1.0.0.1\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(dnsConfig), 0644); err != nil {
		return fmt.Errorf("failed to write resolv.conf: %v", err)
	}
	return nil
}

func (m *TLSInterceptionManager) iptablesRuleExists(table, chain string, ruleArgs ...string) bool {
	args := []string{"-t", table, "-C", chain}
	args = append(args, ruleArgs...)
	err := exec.Command("iptables", args...).Run()
	return err == nil
}

func (m *TLSInterceptionManager) cleanupKernel() error {
	proxyPort := fmt.Sprintf("%d", m.config.MitmproxyPort)
	tap1VppIP := strings.Split(m.config.Tap1VppIP, "/")[0]

	// remove redirect rules for CURRENT configured ports
	for _, p := range m.config.normalizedInterceptPorts() {
		if m.iptablesRuleExists("nat", "PREROUTING",
			"-i", m.config.Tap0HostName, "-p", "tcp", "--dport", fmt.Sprintf("%d", p),
			"-j", "REDIRECT", "--to-port", proxyPort) {
			_ = m.runCommand("iptables", "-t", "nat", "-D", "PREROUTING",
				"-i", m.config.Tap0HostName, "-p", "tcp", "--dport", fmt.Sprintf("%d", p),
				"-j", "REDIRECT", "--to-port", proxyPort)
		}
	}

	if m.iptablesRuleExists("nat", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE") {
		_ = m.runCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", m.config.Tap1HostName, "-j", "MASQUERADE")
	}

	if out, _ := exec.Command("ip", "route", "show", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName).Output(); len(out) > 0 {
		_ = m.runCommand("ip", "route", "del", "default", "via", tap1VppIP, "dev", m.config.Tap1HostName)
	}

	if _, err := os.Stat("/etc/resolv.conf.bak.tls"); err == nil {
		_ = m.runCommand("cp", "/etc/resolv.conf.bak.tls", "/etc/resolv.conf")
		_ = m.runCommand("rm", "/etc/resolv.conf.bak.tls")
	}

	return nil
}

// ---------------- mitmproxy ----------------

func (m *TLSInterceptionManager) startMitmproxy() error {
	if running, _ := m.checkMitmproxyRunning(); running {
		return nil
	}

	wd, _ := os.Getwd()
	loggerScript := fmt.Sprintf("%s/scripts/mitmproxy_logger.py", wd)

	// daily log file handled by python itself, but still pass base dir via env
	baseEnvLogFile := filepath.Join(urlLogsDir, "urls_"+time.Now().Format("02_01_2006")+".log")
	errorLogFile := "/etc/sarhad-guard/url_logs/mitmproxy_error.log"

	_ = os.MkdirAll(urlLogsDir, 0755)
	_ = os.MkdirAll(mitmproxyConfDir, 0700)

	args := []string{
		"--mode", "transparent",
		"--showhost",
		"--set", "block_global=false",
		"--listen-host", "0.0.0.0",
		"--listen-port", fmt.Sprintf("%d", m.config.MitmproxyPort),
		"--set", "termlog_verbosity=error",
		"--set", fmt.Sprintf("confdir=%s", mitmproxyConfDir),
	}

	if _, err := os.Stat(loggerScript); err == nil {
		args = append(args, "-s", loggerScript)
	}

	errFile, err := os.OpenFile(errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		errFile = nil
	}

	cmd := exec.Command("mitmdump", args...)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("MITMPROXY_LOG_FILE=%s", baseEnvLogFile),
		fmt.Sprintf("TLS_CONF_FILE=%s", tlsConfPath),
	)
	cmd.Stdout = errFile
	cmd.Stderr = errFile

	if err := cmd.Start(); err != nil {
		if errFile != nil {
			_ = errFile.Close()
		}
		return fmt.Errorf("failed to start mitmproxy: %v", err)
	}

	m.status.MitmproxyPID = cmd.Process.Pid

	go func() {
		_ = cmd.Wait()
		if errFile != nil {
			_ = errFile.Close()
		}
	}()

	return nil
}

func (m *TLSInterceptionManager) stopMitmproxy() error {
	_ = m.runCommand("pkill", "-f", "mitmdump")
	_ = m.runCommand("pkill", "-f", "mitmproxy")
	m.status.MitmproxyPID = 0
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

// ---------------- Certificates (fixed path) ----------------

type CertificateInfo struct {
	CertDir      string `json:"cert_dir"`
	CACertPath   string `json:"ca_cert_path"`
	CACertExists bool   `json:"ca_cert_exists"`
	CAKeyPath    string `json:"ca_key_path"`
	CAKeyExists  bool   `json:"ca_key_exists"`
}

func (m *TLSInterceptionManager) GetCertificateInfo() CertificateInfo {
	certDir := mitmproxyConfDir
	caCertPath := certDir + "/mitmproxy-ca-cert.pem"
	caKeyPath := certDir + "/mitmproxy-ca.pem"

	_, caCertErr := os.Stat(caCertPath)
	_, caKeyErr := os.Stat(caKeyPath)

	return CertificateInfo{
		CertDir:      certDir,
		CACertPath:   caCertPath,
		CACertExists: caCertErr == nil,
		CAKeyPath:    caKeyPath,
		CAKeyExists:  caKeyErr == nil,
	}
}

// UploadCACertificate saves uploaded mitmproxy-ca.pem to /root/.mitmproxy/mitmproxy-ca.pem
func (m *TLSInterceptionManager) UploadCACertificate(certData []byte) error {
	if err := os.MkdirAll(mitmproxyConfDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %v", err)
	}

	caKeyPath := mitmproxyConfDir + "/mitmproxy-ca.pem"
	if err := os.WriteFile(caKeyPath, certData, 0600); err != nil {
		return fmt.Errorf("failed to write certificate file: %v", err)
	}

	return nil
}

// ---------------- Helpers ----------------

func (m *TLSInterceptionManager) runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

type ACLRuleSimple struct {
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	SrcPrefix string `json:"src_prefix"`
	DstPrefix string `json:"dst_prefix"`
	DstPort   uint16 `json:"dst_port"`
}

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

// ---------------- Config persistence ----------------

func loadTLSConfigFromDisk(cfg *TLSInterceptionConfig) error {
	b, err := os.ReadFile(tlsConfPath)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, cfg)
}

func saveTLSConfigToDisk(cfg *TLSInterceptionConfig) error {
	dir := filepath.Dir(tlsConfPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp := tlsConfPath + ".tmp"
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, tlsConfPath)
}

// ---------------- VPP client helpers ----------------

func (v *VPPClient) CreateSimpleACL(ctx context.Context, tag string, simpleRules []ACLRuleSimple) (uint32, error) {
	var vppRules []acl_types.ACLRule

	for _, rule := range simpleRules {
		srcPrefix, err := parsePrefixForACL(rule.SrcPrefix)
		if err != nil {
			return 0, fmt.Errorf("invalid src prefix: %v", err)
		}

		dstPrefix, err := parsePrefixForACL(rule.DstPrefix)
		if err != nil {
			return 0, fmt.Errorf("invalid dst prefix: %v", err)
		}

		var action acl_types.ACLAction
		switch strings.ToLower(rule.Action) {
		case "permit", "allow":
			action = acl_types.ACL_ACTION_API_PERMIT
		case "deny", "drop":
			action = acl_types.ACL_ACTION_API_DENY
		default:
			action = acl_types.ACL_ACTION_API_PERMIT
		}

		var proto ip_types.IPProto
		switch strings.ToLower(rule.Protocol) {
		case "tcp":
			proto = ip_types.IP_API_PROTO_TCP
		case "udp":
			proto = ip_types.IP_API_PROTO_UDP
		case "icmp":
			proto = ip_types.IP_API_PROTO_ICMP
		default:
			proto = 0
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

		if rule.DstPort > 0 {
			vppRule.DstportOrIcmpcodeFirst = rule.DstPort
			vppRule.DstportOrIcmpcodeLast = rule.DstPort
		}

		vppRules = append(vppRules, vppRule)
	}

	return v.ACLManager.CreateACL(ctx, tag, vppRules)
}

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
