# VPP Go Test - AI Coding Agent Guide

## Project Overview

**VPP Go Test** is a comprehensive VPP (Vector Packet Processing) management system written in Go with a web interface. It provides a complete lifecycle management solution for VPP configurations including interfaces, ACLs, NAT, DHCP, Policers, IPFixFlowprobe, and Access-Based Forwarding (ABF).

## Architecture

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   Web UI (Gin Templates)                     │
│  Routes: /api/interfaces, /api/nat, /api/acl, etc.          │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              HTTP Handlers (internal/web)                    │
│  - interface_handler.go: Interface operations                │
│  - nat44_handler.go: NAT4 config                             │
│  - acl_handler.go: ACL management                            │
│  - policer_handler.go: Policer binding                       │
│  - dhcp_handler.go: DHCP server config                       │
│  - ipfix_handler.go: Flow monitoring setup                   │
│  - abf_handler.go: Access-based forwarding                   │
│  - backup_handler.go: Config save/restore                    │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│            VPPClient Manager (internal/vpp)                  │
│  Coordinates all sub-managers and maintains state            │
│  - connector.go: Lifecycle & connection management           │
│  - backup_restore.go: Unified config persistence             │
└──────────────┬─────────────────────┬──────────────┬───────────┘
               │                     │              │
    ┌──────────▼──┐  ┌──────────────▼┐  ┌─────────▼────┐
    │  ACLManager │  │  NatManager   │  │ IpfixManager │
    │  (acl/)     │  │  (nat44/)     │  │  (ipfix/)    │
    └─────────────┘  └───────────────┘  └──────────────┘
               │                     │              │
    ┌──────────▼──┐  ┌──────────────▼┐  ┌─────────▼────┐
    │DhcpManager  │  │PolicerManager │  │ AbfManager   │
    │  (dhcp/)    │  │  (policer/)   │  │ (abf_mgr/)   │
    └─────────────┘  └───────────────┘  └──────────────┘
               │                     │              │
               └─────────────────────┴──────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│       GoVPP API Bindings (binapi/ - Auto-generated)         │
│  Direct mapping to VPP message types                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              VPP Instance (Running Process)                  │
│  All config applied via binapi, persisted in JSON backup     │
└─────────────────────────────────────────────────────────────┘
```

### Component Boundaries

**Key Principle**: Each manager handles a specific VPP domain and maintains bidirectional sync with VPP:
- **Fetch** (read): Query current state from VPP  
- **Apply** (write): Configure via VPP API messages
- **Persist**: Backup/restore via JSON

## Critical Developer Workflows

### 1. Backup & Restore (Most Important!)

The `backup_restore.go` implements **comprehensive configuration persistence** with this flow:

**SaveConfiguration (8 components)**:
```
SaveConfiguration() → FullBackupConfig JSON
  ├─ Phase 1: Interfaces (get config, ACL bindings, DHCP state)
  ├─ Phase 2: ACLs (IP ACLs + MAC ACLs with all rules)
  ├─ Phase 3: NAT44 (enable state, interfaces, pools, mappings)
  ├─ Phase 4: Policers (profiles with CIR/CB)
  ├─ Phase 5: DHCP (IPv4/IPv6 proxies, VSS config)
  ├─ Phase 6: IPFIX/Flowprobe (exporter, flowprobe params, enabled ifaces)
  └─ Phase 7: ABF (policies with ACL indices, interface attachments)
```

**RestoreConfiguration (8 phases)**:
```
RestoreConfiguration() → Restores from saved JSON
  ├─ PHASE 0: Create ACL tables first (map old→new indices)
  ├─ PHASE 1: Create missing interfaces
  ├─ PHASE 1.5: Create VLAN sub-interfaces
  ├─ PHASE 2: Configure interfaces (IPs, DHCP, tags)
  ├─ PHASE 3: Bind ACLs to interfaces
  ├─ PHASE 4: Restore NAT44 (CRITICAL: enable first!)
  ├─ PHASE 5: Add policers
  ├─ PHASE 6: Configure DHCP proxies
  ├─ PHASE 7: Setup IPFIX/Flowprobe
  └─ PHASE 8: Restore ABF policies + attachments
```

**⚠️ CRITICAL GOTCHAS**:
- **NAT enable state**: Must save `IsEnabled` flag; restore ONLY restores if `true`
- **Index mapping**: ACL indices change after recreation; use `ipACLIndexMap`/`macACLIndexMap`
- **DHCP/Policer details**: Simplified for now (TODO fields); enhance when binapi types clarified
- **Restore ordering**: MUST create ACLs before interfaces (for ACL bindings)

### 2. Adding New Configuration Components

**When adding Policer/DHCP/IPFIX support to backup**:

1. **Add backup struct** in `backup_restore.go`:
   ```go
   type ComponentBackupConfig struct {
       IsEnabled   bool         `json:"is_enabled"`  // Track enabled state!
       Settings    []SettingKey `json:"settings"`
   }
   ```

2. **Add to `FullBackupConfig`**:
   ```go
   type FullBackupConfig struct {
       // ...
       Component ComponentBackupConfig `json:"component"`
   }
   ```

3. **Save in `SaveConfiguration()`** (use existing pattern):
   ```go
   // Collect current state
   if items, err := v.ComponentManager.List(ctx); err == nil {
       for _, item := range items {
           backup.Component.Items = append(backup.Component.Items, item)
       }
   } else {
       fmt.Printf("  ⚠️  Failed: %v\n", err)
   }
   ```

4. **Restore in `RestoreConfiguration()`** (add new PHASE):
   ```go
   // PHASE X: Component Restore
   if fullBackup.Component.IsEnabled {
       fmt.Println("\n📝 PHASE X: Restoring Component...")
       for _, item := range fullBackup.Component.Items {
           err := v.ComponentManager.Create(ctx, item)
           if err != nil {
               fmt.Printf("  ❌ Failed: %v\n", err)
               stats.ComponentFailed++
           }
       }
   }
   ```

### 3. Working with Manager Interfaces

Each manager follows this pattern:

```go
type ManagerName struct {
    client someservice.RPCService
}

func NewManagerName(conn api.Connection) *ManagerName {
    return &ManagerName{
        client: someservice.NewServiceClient(conn),
    }
}

// Methods typically return (Result, error)
func (m *ManagerName) GetItems(ctx context.Context) ([]Item, error) { ... }
func (m *ManagerName) Create(ctx context.Context, item Item) error { ... }
func (m *ManagerName) Delete(ctx context.Context, id uint32) error { ... }
```

**Key pattern**: Always pass `context.Context` as first parameter for cancellation support.

## Project-Specific Conventions

### 1. Connection Management (`connector.go`)

```go
// VPPClient holds all managers and connections
type VPPClient struct {
    Conn           *core.Connection        // Main API connection
    Stats          *core.StatsConnection   // Statistics connection
    Channel        api.Channel              // API channel for direct calls
    ACLManager     *acl.ACLManager
    NatManager     *nat44.NatManager
    IpfixManager   *ipfix.IpfixManager
    DhcpManager    *dhcp.DhcpManager
    AbfManager     *abf_mgr.AbfManager
    PolicerManager *policer.Manager
    StartTime      time.Time
    IfNames        map[uint32]string
}

// ConnectVPP establishes connections and initializes all managers
func ConnectVPP(socketPath string, statsSocketPath string) (*VPPClient, error)

// RefreshManagers recreates managers with new API channels
// CRITICAL: Call this after VPP reconnect
func (v *VPPClient) RefreshManagers()
```

### 2. Auto-Reconnection Pattern (`main.go`)

```go
// Watcher goroutine checks connection every 5 seconds
go func() {
    for {
        if !client.IsConnected() {
            // Reconnect and refresh managers
            newClient, err := vpp.ConnectVPP(socketPath, statsSocketPath)
            if err == nil {
                client.Conn = newClient.Conn
                client.Stats = newClient.Stats
                client.RefreshManagers()  // CRITICAL!
                client.RestoreConfiguration()  // Auto-restore on reconnect
            }
        }
        time.Sleep(5 * time.Second)
    }
}()
```

### 3. Web Handlers Structure (`internal/web/`)

All handlers follow this pattern:

```go
type NameHandler struct {
    VPP *vpp.VPPClient  // Reference to client
}

// HTTP handlers typically unmarshal JSON, validate, call manager, return JSON
func (h *NameHandler) HandleCreate(c *gin.Context) {
    var req struct { /*fields*/ }
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    result, err := h.VPP.SomeManager.Create(c.Request.Context(), req)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    
    c.JSON(http.StatusOK, result)
}
```

### 4. NAT Configuration Quirk

NAT has **two modes for external IPs**:
- **Interface-based**: External IP must be `0.0.0.0`, set `ExternalSwIfIndex`
- **IP-based**: External IP set, `ExternalSwIfIndex` must be `0xffffffff`

Always check this in `nat44/nat44.go`:
```go
isInterfaceBased := (sm.ExternalIP == "" || sm.ExternalIP == "0.0.0.0") && sm.ExternalIf != 0
if isInterfaceBased {
    externalIP = ip_types.IP4Address{0, 0, 0, 0}
    swIfIndex = interface_types.InterfaceIndex(sm.ExternalIf)
} else {
    // IP-based mapping
    swIfIndex = 0xffffffff
}
```

## Test/Build Commands

```bash
# Build
go build

# Run (connects to VPP on /run/vpp/api.sock and /dev/shm/vpp/stats.sock)
./vpp-go-test

# Access web UI
open http://localhost:8000/login
# Default: username=admin, password=admin (see auth_handler.go)
```

## Key Files for Common Tasks

| Task | File(s) |
|------|---------|
| Add new VPP component backup | `internal/vpp/backup_restore.go` (structs + phases) |
| Fix interface configuration | `internal/vpp/interface_svc.go` |
| NAT mapping issues | `internal/vpp/nat44/nat44.go` |
| ACL rule parsing | `internal/vpp/acl/` |
| HTTP endpoint | `internal/web/*_handler.go` + `internal/web/routes.go` |
| Bindings to VPP | `binapi/*/` (auto-generated, don't edit) |

## Important Gotchas

1. **Index persistence**: Interface/ACL indices change on VPP restart; always look up by name first
2. **VLAN subif creation**: Parent interface must exist before creating VLAN subif
3. **ACL recreation**: Old ACL indices invalid after restore; use index maps
4. **Manager refresh**: Must call `RefreshManagers()` after reconnection
5. **DHCP/Policer TODOs**: Current backup has simplified fields; enhance as needed
6. **Context cancellation**: Always pass `context.Background()` or proper context with timeout

## Testing Backup/Restore

```bash
# Save configuration
curl -X POST http://localhost:8000/api/backup/save

# Check saved config
cat /etc/sarhad-guard/backup/vpp_config.json | jq .

# Restore
curl -X POST http://localhost:8000/api/backup/restore
```

## References

- **VPP Documentation**: https://s3-docs.fd.io/vpp/latest/
- **GoVPP**: https://github.com/FDio/govpp
- **Binapi Generated**: See `binapi/*/` for message type definitions
