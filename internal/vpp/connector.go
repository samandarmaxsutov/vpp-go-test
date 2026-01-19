package vpp

import (
	"fmt"
	"go.fd.io/govpp"
	"go.fd.io/govpp/adapter/statsclient" // Yangi qo'shildi
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
	"log"
	"time"
	"vpp-go-test/internal/vpp/abf_mgr"
	"vpp-go-test/internal/vpp/acl"
	"vpp-go-test/internal/vpp/dhcp"
	"vpp-go-test/internal/vpp/ipfix"
	"vpp-go-test/internal/vpp/nat44"
	"vpp-go-test/internal/vpp/policer"
)

type VPPClient struct {
	Conn           *core.Connection
	Stats          *core.StatsConnection // Global stats ulanishi
	Channel        api.Channel
	ACLManager     *acl.ACLManager //Acl
	NatManager     *nat44.NatManager
	IpfixManager   *ipfix.IpfixManager
	DhcpManager    *dhcp.DhcpManager
	AbfManager     *abf_mgr.AbfManager
	PolicerManager *policer.Manager
	StartTime      time.Time
	IfNames        map[uint32]string
}

func ConnectVPP(socketPath string, statsSocketPath string) (*VPPClient, error) {
	// 1. Asosiy VPP API ulanishi
	conn, err := govpp.Connect(socketPath)
	if err != nil {
		return nil, fmt.Errorf("Socketiga ulanib bo'lmadi: %v", err)
	}

	ch, err := conn.NewAPIChannel()
	if err != nil {
		conn.Disconnect()
		return nil, fmt.Errorf("API kanal ochib bo'lmadi: %v", err)
	}

	// 2. Global Stats ulanishi (Singleton client)
	sc := statsclient.NewStatsClient(statsSocketPath)
	sConn, err := core.ConnectStats(sc)
	if err != nil {
		// Stats ulanmasa ham API ishlashi mumkin, lekin biz xato qaytaramiz
		ch.Close()
		conn.Disconnect()
		return nil, fmt.Errorf("Stats segmentiga ulanib bo'lmadi: %v", err)
	}

	log.Println("API va Stats segmentiga ulanish muvaffaqiyatli!")
	client := &VPPClient{
		Conn:    conn,
		Stats:   sConn,
		Channel: ch,
	}
	client.ACLManager = acl.NewACLManager(conn)
	client.NatManager = nat44.NewNatManager(conn)
	client.IpfixManager = ipfix.NewIpfixManager(conn)
	client.DhcpManager = dhcp.NewDhcpManager(conn)
	client.AbfManager = abf_mgr.NewAbfManager(conn)
	client.PolicerManager = policer.NewManager(conn)

	return client, nil
}

func (v *VPPClient) Close() {
	if v.Stats != nil {
		v.Stats.Disconnect() // Statsni ham yopamiz
	}
	if v.Channel != nil {
		v.Channel.Close()
	}
	if v.Conn != nil {
		v.Conn.Disconnect()
	}
}

func (v *VPPClient) IsConnected() bool {
    if v.Conn == nil {
        return false
    }

    // We use GetInterfaces as a "Ping". 
    // If VPP is down, this call will fail immediately.
    _, err := v.GetInterfaces()
    return err == nil
}

func (v *VPPClient) RefreshManagers() {
    // 1. Close the old main channel
    if v.Channel != nil {
        v.Channel.Close()
    }

    // 2. Open a new main channel for the client itself
    ch, err := v.Conn.NewAPIChannel()
    if err == nil {
        v.Channel = ch
    }

    // 3. IMPORTANT: Re-link the managers. 
    // If your web routes use client.ACLManager, they point to a specific 
    // place in memory. We must ensure these are fresh.
    v.ACLManager = acl.NewACLManager(v.Conn)
    v.NatManager = nat44.NewNatManager(v.Conn)
    v.IpfixManager = ipfix.NewIpfixManager(v.Conn)
    v.DhcpManager = dhcp.NewDhcpManager(v.Conn)
    v.AbfManager = abf_mgr.NewAbfManager(v.Conn)
    v.PolicerManager = policer.NewManager(v.Conn)

    log.Println("🔄 All Managers memory-swapped with fresh API channels.")
}