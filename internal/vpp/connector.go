package vpp

import (
	"fmt"
	"log"
	"time"

	"go.fd.io/govpp"
	"go.fd.io/govpp/adapter/statsclient" // Yangi qo'shildi
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
	"vpp-go-test/internal/vpp/acl"
	"vpp-go-test/internal/vpp/nat44"
	"vpp-go-test/internal/vpp/ipfix"
	"vpp-go-test/internal/vpp/dhcp"
	"vpp-go-test/internal/vpp/abf_mgr"
)

type VPPClient struct {
	Conn    *core.Connection
	Stats   *core.StatsConnection // Global stats ulanishi
	Channel api.Channel
	ACLManager *acl.ACLManager //Acl 
	NatManager  *nat44.NatManager
	IpfixManager *ipfix.IpfixManager
	DhcpManager *dhcp.DhcpManager
	AbfManager  *abf_mgr.AbfManager
	StartTime time.Time
	IfNames map[uint32]string
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