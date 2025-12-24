package ipfix

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"go.fd.io/govpp/api"
	"vpp-go-test/binapi/flowprobe"
	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/binapi/ipfix_export"
)

type IpfixManager struct {
	client          ipfix_export.RPCService
	flowprobeClient flowprobe.RPCService
}

func NewIpfixManager(conn api.Connection) *IpfixManager {
	return &IpfixManager{
		client:          ipfix_export.NewServiceClient(conn),
		flowprobeClient: flowprobe.NewServiceClient(conn),
	}
}

// --- FLOWPROBE (Zond) FUNKSIYALARI ---

// InterfaceEnable - Ma'lum bir interfeysda trafikni kuzatishni yoqish yoki o'chirish
func (m *IpfixManager) InterfaceEnable(ctx context.Context, swIfIndex uint32, enable bool) error {
	req := &flowprobe.FlowprobeInterfaceAddDel{
		IsAdd:     enable,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Which:     flowprobe.FLOWPROBE_WHICH_IP4, // Faqat IPv4 uchun
	}

	_, err := m.flowprobeClient.FlowprobeInterfaceAddDel(ctx, req)
	if err != nil {
		return fmt.Errorf("flowprobe interface error: %w", err)
	}
	return nil
}

// SetFlowprobeParams - Trafikni qanday va qaysi darajada (L3/L4) yozib olishni sozlash
func (m *IpfixManager) SetFlowprobeParams(ctx context.Context, activeTimeout uint32, recordL4 bool) error {
	// L2 va L3 flaglari doim bo‘lishi kerak
	var flags flowprobe.FlowprobeRecordFlags = flowprobe.FLOWPROBE_RECORD_FLAG_L2 |
		flowprobe.FLOWPROBE_RECORD_FLAG_L3

	if recordL4 {
		// VPP versiyangizda L4 support mavjudligini tekshiring
		flags |= flowprobe.FLOWPROBE_RECORD_FLAG_L4
	}

	req := &flowprobe.FlowprobeSetParams{
		RecordFlags:  flags,
		ActiveTimer:  activeTimeout,
		PassiveTimer: activeTimeout * 5,
	}

	// Debug: print qilamiz
	fmt.Printf("SetFlowprobeParams: %+v\n", req)

	resp, err := m.flowprobeClient.FlowprobeSetParams(ctx, req)
	if err != nil {
		fmt.Println("FlowprobeSetParams xato:", err)
		return fmt.Errorf("flowprobe set params error: %w", err)
	}

	// Debug: VPP dan kelgan javobni tekshirish
	fmt.Printf("FlowprobeSetParams javob: %+v\n", resp)

	return nil
}

// GetFlowprobeParams - Hozirgi flowprobe parametrlarini o'qib olish
func (m *IpfixManager) GetFlowprobeParams(ctx context.Context) (uint32, bool, error) {
	resp, err := m.flowprobeClient.FlowprobeGetParams(ctx, &flowprobe.FlowprobeGetParams{})
	if err != nil {
		return 0, false, err
	}
	fmt.Println("GET flowprobe",resp)
	isL4 := (resp.RecordFlags & flowprobe.FLOWPROBE_RECORD_FLAG_L4) != 0
	return resp.ActiveTimer, isL4, nil
}

// GetEnabledInterfaces - IPFIX yoqilgan barcha interfeyslar ID sini olish
func (m *IpfixManager) GetEnabledInterfaces(ctx context.Context) ([]uint32, error) {
	stream, err := m.flowprobeClient.FlowprobeInterfaceDump(ctx, &flowprobe.FlowprobeInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
	})
	if err != nil {
		return nil, err
	}

	var enabledIds []uint32
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		enabledIds = append(enabledIds, uint32(details.SwIfIndex))
	}
	return enabledIds, nil
}

// --- EXPORTER (Yuboruvchi) FUNKSIYALARI ---

// SetExporter - Asosiy IPFIX eksportyorini sozlash
func (m *IpfixManager) SetExporter(ctx context.Context, cfg IpfixConfig) error {
	collIP := net.ParseIP(cfg.CollectorAddress).To4()
	srcIP := net.ParseIP(cfg.SourceAddress).To4()

	if collIP == nil || srcIP == nil {
		return fmt.Errorf("faqat IPv4 manzillari qo'llab-quvvatlanadi")
	}

	var collAddr, srcAddr ip_types.IP4Address
	copy(collAddr[:], collIP)
	copy(srcAddr[:], srcIP)

	req := &ipfix_export.SetIpfixExporter{
		CollectorAddress: ip_types.Address{
			Af: ip_types.ADDRESS_IP4,
			Un: ip_types.AddressUnionIP4(collAddr),
		},
		CollectorPort: cfg.CollectorPort,
		SrcAddress: ip_types.Address{
			Af: ip_types.ADDRESS_IP4,
			Un: ip_types.AddressUnionIP4(srcAddr),
		},
		VrfID:            cfg.VrfID,
		PathMtu:          cfg.PathMtu,
		TemplateInterval: cfg.TemplateInterval,
		UDPChecksum:      cfg.UDPChecksum,
	}

	_, err := m.client.SetIpfixExporter(ctx, req)
	return err
}

// GetExporterStatus - VPP-dagi joriy eksport holatini olish
func (m *IpfixManager) GetExporterStatus(ctx context.Context) (*IpfixStatus, error) {
	stream, err := m.client.IpfixExporterDump(ctx, &ipfix_export.IpfixExporterDump{})
	if err != nil {
		return nil, err
	}

	details, err := stream.Recv()
	if err != nil {
		return &IpfixStatus{IsActive: false}, nil
	}

	cIP := details.CollectorAddress.Un.GetIP4()
	sIP := details.SrcAddress.Un.GetIP4()

	return &IpfixStatus{
		IsActive:         true,
		CollectorAddress: net.IP(cIP[:]).String(),
		CollectorPort:    details.CollectorPort,
		SourceAddress:    net.IP(sIP[:]).String(),
		TemplateInterval: details.TemplateInterval,
		VrfID:            details.VrfID,
		PathMtu:          details.PathMtu,
		UDPChecksum:      details.UDPChecksum,
	}, nil
}

// FlushIPFIX - Keshdagi barcha oqimlarni darhol collectorga yuborish
func (m *IpfixManager) FlushIPFIX(ctx context.Context) error {
	_, err := m.client.IpfixFlush(ctx, &ipfix_export.IpfixFlush{})
	return err
}

// TestConnection - Collector porti ochiqligini tekshirish
func (m *IpfixManager) TestConnection(cfg IpfixConfig) error {
	target := fmt.Sprintf("%s:%d", cfg.CollectorAddress, cfg.CollectorPort)
	conn, err := net.DialTimeout("udp", target, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}
