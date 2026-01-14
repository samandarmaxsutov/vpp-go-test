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
	"sort"
	"strings"
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

// Error counterlarni (show errors) o‘xshatib chiqarish.
// filter bo‘sh bo‘lsa hammasi, aks holda CounterName ichidan qidiradi (mas: "nat44", "arp", "dhcp").
func (v *VPPClient) PrintErrorStats(filter string) error {
	if v.Stats == nil {
		return fmt.Errorf("Stats connection nil (v.Stats)")
	}

	var es api.ErrorStats
	if err := v.Stats.GetErrorStats(&es); err != nil {
		return fmt.Errorf("GetErrorStats failed: %w", err)
	}

	type row struct {
		name  string
		total uint64
	}

	rows := make([]row, 0, len(es.Errors))
	for _, e := range es.Errors {
		if filter != "" && !strings.Contains(strings.ToLower(e.CounterName), strings.ToLower(filter)) {
			continue
		}
		var sum uint64
		for _, v := range e.Values {
			sum += v
		}
		if sum == 0 {
			continue
		}
		rows = append(rows, row{name: e.CounterName, total: sum})
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].total > rows[j].total })

	fmt.Printf("VPP error counters (filter=%q), non-zero only:\n", filter)
	for _, r := range rows {
		fmt.Printf("%10d  %s\n", r.total, r.name)
	}
	return nil
}

func ConnectVPP(socketPath string, statsSocketPath string) (*VPPClient, error) {
	// 1. Asosiy VPP API ulanishi
	conn, err := govpp.Connect(socketPath)
	if err != nil {
		return nil, fmt.Errorf("VPP socketiga ulanib bo'lmadi: %v", err)
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

	log.Println("VPP API va Stats segmentiga ulanish muvaffaqiyatli!")
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