package nat44

import (
	"context"
	"fmt"
	"io"
	"log"
	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/ip_types"
	"vpp-go-test/binapi/nat44_ed"
	"vpp-go-test/binapi/nat_types"

	"go.fd.io/govpp/api"
)

// NatManager VPP NAT44 xizmati bilan ishlash uchun mas'ul
type NatManager struct {
	client nat44_ed.RPCService
}

// NewNatManager yangi menejer yaratadi
func NewNatManager(conn api.Connection) *NatManager {
	return &NatManager{
		client: nat44_ed.NewServiceClient(conn),
	}
}

// EnableNat44 - NAT44 pluginini global faollashtirish
func (m *NatManager) EnableNat44(ctx context.Context) error {
	// Diqqat: VPP versiyasiga qarab Nat44PluginEnableDisable yoki
	// Nat44EdPluginEnableDisable ishlatiladi.
	req := &nat44_ed.Nat44EdPluginEnableDisable{
		Sessions: 32768, // Bir vaqtdagi sessiyalar soni
		Enable:   true,
	}

	_, err := m.client.Nat44EdPluginEnableDisable(ctx, req)
	if err != nil {
		return fmt.Errorf("NAT pluginni yoqib bo'lmadi: %v", err)
	}
	return nil
}

// --- INFRASTRUCTURE (Tab 1) ---
// SetInterfaceNAT interfeysni inside/outside rejimiga o'tkazadi
func (m *NatManager) SetInterfaceNAT(ctx context.Context, swIfIndex uint32, isInside, isAdd bool) error {
	req := &nat44_ed.Nat44InterfaceAddDelFeature{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		IsAdd:     isAdd,
	}

	// Flaglarni to'g'ri berish
	if isInside {
		req.Flags = nat_types.NAT_IS_INSIDE
	} else {
		req.Flags = nat_types.NAT_IS_OUTSIDE
	}

	_, err := m.client.Nat44InterfaceAddDelFeature(ctx, req)
	return err
}

// AddAddressPool tashqi IP hovuziga manzil qo'shadi (Multi-WAN uchun)
func (m *NatManager) AddAddressPool(ctx context.Context, ipAddr string, isAdd bool) error {
	vppIP, err := IPToVppIP4Address(ipAddr)
	if err != nil {
		return err
	}

	_, err = m.client.Nat44AddDelAddressRange(ctx, &nat44_ed.Nat44AddDelAddressRange{
		FirstIPAddress: vppIP,
		LastIPAddress:  vppIP,
		IsAdd:          isAdd,
		VrfID:          0,
	})
	return err
}

// --- INBOUND / DNAT (Tab 2) ---
// nat44/nat.go ichida
func (m *NatManager) AddStaticMapping(ctx context.Context, sm StaticMapping, isAdd bool) error {
	localIP, _ := IPToVppIP4Address(sm.LocalIP)
	var externalIP ip_types.IP4Address
	// VPP-da interfeys ishlatilmasa 0xffffffff (4294967295) bo'lishi shart
	var swIfIndex interface_types.InterfaceIndex = 0xffffffff

	// 1. Mapping turini aniqlash
	isInterfaceBased := (sm.ExternalIP == "" || sm.ExternalIP == "0.0.0.0") && sm.ExternalIf != 0 && sm.ExternalIf != 4294967295

	if isInterfaceBased {
		// Interface-based: IP 0.0.0.0 bo'lishi shart
		externalIP = ip_types.IP4Address{0, 0, 0, 0}
		swIfIndex = interface_types.InterfaceIndex(sm.ExternalIf)
	} else {
		// IP-based: Interfeys index 0xffffffff bo'lishi shart
		externalIP, _ = IPToVppIP4Address(sm.ExternalIP)
		swIfIndex = 0xffffffff
	}

	// VPP-ga yuboriladigan request
	req := &nat44_ed.Nat44AddDelStaticMapping{
		IsAdd:             isAdd,
		LocalIPAddress:    localIP,
		ExternalIPAddress: externalIP,
		LocalPort:         sm.LocalPort,
		ExternalPort:      sm.ExternalPort,
		Protocol:          ProtoToUint(sm.Protocol),
		ExternalSwIfIndex: swIfIndex,
		VrfID:             0,
		Flags:             nat_types.NAT_IS_ADDR_ONLY, // Agar portlar 0 bo'lsa kerak bo'ladi
	}

	// Agar portlar ko'rsatilgan bo'sa, ADDR_ONLY flagni olib tashlaymiz
	if sm.LocalPort > 0 || sm.ExternalPort > 0 {
		req.Flags = nat_types.NAT_IS_EXT_HOST_VALID // yoki 0
	}

	_, err := m.client.Nat44AddDelStaticMapping(ctx, req)
	if err != nil {
		log.Printf("NAT Static Mapping Error (isAdd=%v): %v | Req: %+v", isAdd, err, req)
	}
	return err
}

// GetStaticMappings mavjud DNAT qoidalarini qaytaradi
func (m *NatManager) GetStaticMappings(ctx context.Context) ([]StaticMapping, error) {
	stream, err := m.client.Nat44StaticMappingDump(ctx, &nat44_ed.Nat44StaticMappingDump{})
	if err != nil {
		return nil, fmt.Errorf("mapping dump error: %v", err)
	}

	var results []StaticMapping
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// VPP dan kelayotgan ma'lumotlarni tekshirish uchun log (Debug uchun juda muhim)
		// fmt.Printf("DEBUG: Found Mapping - ExtIP: %v, ExtIdx: %v, Local: %v\n",
		//    details.ExternalIPAddress, details.ExternalSwIfIndex, details.LocalIPAddress)

		mapping := StaticMapping{
			LocalIP:      VppIP4AddressToString(details.LocalIPAddress),
			LocalPort:    details.LocalPort,
			ExternalPort: details.ExternalPort,
			Protocol:     fmt.Sprintf("%d", details.Protocol),
			// Interfeys indexini uint32 ko'rinishida saqlaymiz
			ExternalIf: uint32(details.ExternalSwIfIndex),
		}

		// Agar mapping interfeysga bog'langan bo'lsa (index != 4294967295)
		// Tashqi IPni "0.0.0.0" deb belgilaymiz, aks holda IPni o'zini yozamiz
		if uint32(details.ExternalSwIfIndex) != 4294967295 {
			mapping.ExternalIP = "0.0.0.0"
		} else {
			mapping.ExternalIP = VppIP4AddressToString(details.ExternalIPAddress)
		}

		results = append(results, mapping)
	}
	return results, nil
}

// SetNatTimeouts NAT sessiyalari uchun timeoutlarni o'rnatadi
func (m *NatManager) SetNatTimeouts(ctx context.Context, timeouts nat_types.NatTimeouts) error {
	_, err := m.client.NatSetTimeouts(ctx, &nat44_ed.NatSetTimeouts{
		UDP:            timeouts.UDP,
		TCPEstablished: timeouts.TCPEstablished,
		TCPTransitory:  timeouts.TCPTransitory,
		ICMP:           timeouts.ICMP,
	})
	if err != nil {
		return fmt.Errorf("timeoutlarni o'rnatib bo'lmadi: %v", err)
	}
	return nil
}

// ClearAllSessions barcha faol NAT sessiyalarini tozalaydi
func (m *NatManager) ClearAllSessions(ctx context.Context) error {
	// VPP-da "Clear all" degan bitta API yo'q, odatda foydalanuvchilar bo'yicha yoki
	// plaginni o'chirib-yoqish orqali qilinadi.
	// Lekin eng to'g'ri yo'li - foydalanuvchilar bo'yicha aylanib chiqish.

	stream, err := m.client.Nat44UserDump(ctx, &nat44_ed.Nat44UserDump{})
	if err != nil {
		return err
	}

	for {
		user, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Har bir foydalanuvchining sessiyalarini o'chirish
		_, _ = m.client.Nat44DelSession(ctx, &nat44_ed.Nat44DelSession{
			Address:  user.IPAddress,
			Protocol: 0, // 0 - barcha protokollar
			VrfID:    user.VrfID,
			Flags:    nat_types.NAT_IS_INSIDE,
		})
	}
	return nil
}

// GetActiveSessions faol sessiyalar ro'yxatini qaytaradi (V3 versiya eng to'liq ma'lumot beradi)

func (m *NatManager) GetActiveSessions(ctx context.Context) (*NATSessionResponse, error) {
	userStream, err := m.client.Nat44UserDump(ctx, &nat44_ed.Nat44UserDump{})
	if err != nil {
		return nil, err
	}

	var allSessions []SessionDisplay
	userMap := make(map[string]*UserTraffic)
	var grandTotalBytes uint64

	for {
		user, err := userStream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		sessionReq := &nat44_ed.Nat44UserSessionV3Dump{
			IPAddress: user.IPAddress,
			VrfID:     user.VrfID,
		}

		sessionStream, err := m.client.Nat44UserSessionV3Dump(ctx, sessionReq)
		if err != nil {
			continue
		}

		for {
			s, err := sessionStream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}

			insideIP := VppIP4AddressToString(s.InsideIPAddress)

			display := SessionDisplay{
				InsideIP:           insideIP,
				InsidePort:         s.InsidePort,
				OutsideIP:          VppIP4AddressToString(s.OutsideIPAddress),
				OutsidePort:        s.OutsidePort,
				ExtHostIP:          VppIP4AddressToString(s.ExtHostAddress),
				ExtHostPort:        s.ExtHostPort,
				Protocol:           getProtoName(s.Protocol),
				TotalBytes:         s.TotalBytes,
				TotalPkts:          s.TotalPkts,
				IsTimedOut:         s.IsTimedOut,
				TimeSinceLastHeard: s.TimeSinceLastHeard,
			}
			allSessions = append(allSessions, display)

			// User Summary Aggregation
			if _, ok := userMap[insideIP]; !ok {
				userMap[insideIP] = &UserTraffic{IP: insideIP}
			}
			userMap[insideIP].SessionCount++
			userMap[insideIP].TotalBytes += s.TotalBytes
			userMap[insideIP].TotalPkts += uint64(s.TotalPkts)
			grandTotalBytes += s.TotalBytes
		}
	}

	// Statistika foizlarini hisoblash
	var userSummary []UserTraffic
	for _, ut := range userMap {
		if grandTotalBytes > 0 {
			ut.Percentage = (float64(ut.TotalBytes) / float64(grandTotalBytes)) * 100
		}
		userSummary = append(userSummary, *ut)
	}

	return &NATSessionResponse{
		Sessions:    allSessions,
		UserSummary: userSummary,
	}, nil
}

// Protokol raqamini nomga o'girish
func getProtoName(p uint16) string {
	switch p {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	default:
		return fmt.Sprintf("PROTO-%d", p)
	}
}

// GetAddressPool NAT address pool'ni dump qilib oladi
func (m *NatManager) GetAddressPool(ctx context.Context) ([]NatAddressPool, error) {
	stream, err := m.client.Nat44AddressDump(ctx, &nat44_ed.Nat44AddressDump{})
	if err != nil {
		return nil, err
	}

	var pool []NatAddressPool
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		pool = append(pool, NatAddressPool{
			IPAddress: VppIP4AddressToString(details.IPAddress),
			VrfID:     details.VrfID,
		})
	}
	return pool, nil
}

// GetNatInterfaces - NAT statusi bor interfeyslarni VPP'dan o'qib oladi
func (m *NatManager) GetNatInterfaces(ctx context.Context) ([]NatInterface, error) {
	stream, err := m.client.Nat44InterfaceDump(ctx, &nat44_ed.Nat44InterfaceDump{})
	if err != nil {
		return nil, fmt.Errorf("NAT interfeyslarini o'qib bo'lmadi: %v", err)
	}

	var results []NatInterface
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		results = append(results, NatInterface{
			SwIfIndex: uint32(details.SwIfIndex),
			IsInside:  (details.Flags & nat_types.NAT_IS_INSIDE) != 0,
			Name:      "", // Will be populated in backup_restore.go
		})
	}
	return results, nil
}

// Nat44DelSession muayyan sessiyani o'chiradi
func (m *NatManager) DelSpecificSession(ctx context.Context, session nat44_ed.Nat44UserSessionV3Details) error {
	_, err := m.client.Nat44DelSession(ctx, &nat44_ed.Nat44DelSession{
		Address:        session.InsideIPAddress, // InsideAddress emas
		Protocol:       uint8(session.Protocol),
		Port:           session.InsidePort,
		VrfID:          0,
		Flags:          nat_types.NAT_IS_INSIDE,
		ExtHostAddress: session.ExtHostAddress, // ExternalHostAddress emas
		ExtHostPort:    session.ExtHostPort,    // ExternalHostPort emas
	})
	return err
}

// SetIpfixLogging - NAT sessiyalari haqidagi loglarni IPFIX orqali yuborishni boshqaradi
func (m *NatManager) SetIpfixLogging(ctx context.Context, enable bool) error {
	req := &nat44_ed.NatIpfixEnableDisable{
		Enable:   enable,
		DomainID: 1,    // Ixtiyoriy ID, odatda 1 qoldiriladi
		SrcPort:  4739, // IPFIX standart porti
	}

	_, err := m.client.NatIpfixEnableDisable(ctx, req)
	if err != nil {
		return fmt.Errorf("NAT IPFIX loggingni o'zgartirib bo'lmadi (enable=%v): %v", enable, err)
	}

	log.Printf("NAT IPFIX Logging holati: %v", enable)
	return nil
}

// GetNATStatus - Query current NAT44 enabled/disabled state
func (m *NatManager) GetNATStatus(ctx context.Context) (bool, error) {
	// Try to get running config to determine if NAT is enabled
	resp, err := m.client.Nat44ShowRunningConfig(ctx, &nat44_ed.Nat44ShowRunningConfig{})
	if err != nil {
		// If error, assume NAT is not enabled
		return false, nil
	}

	// If we got a response without error, NAT is likely enabled
	if resp != nil {
		return true, nil
	}
	return false, nil
}

// GetRunningConfig - NAT44 ning joriy sozlamalarini, jumladan IPFIX holatini tekshirish
func (m *NatManager) GetRunningConfig(ctx context.Context) (*nat44_ed.Nat44ShowRunningConfigReply, error) {
	// Diqqat: binapi-da Nat44ShowRunningConfig xabari mavjudligini tekshiring
	resp, err := m.client.Nat44ShowRunningConfig(ctx, &nat44_ed.Nat44ShowRunningConfig{})
	if err != nil {
		return nil, err
	}

	// Reply struct'ga o'tkazish (siz yuqorida ko'rsatgan struct)
	return (*nat44_ed.Nat44ShowRunningConfigReply)(resp), nil
}
