package vpp

import (
	"context"
	"fmt"
	"time"
	"go.fd.io/govpp/api"
	vpp_int "go.fd.io/govpp/binapi/interface"       // vpp_int xatosi uchun
	"go.fd.io/govpp/binapi/interface_types"
)


// InterfaceStatItem interfeys statistikasi uchun struktura
type InterfaceStatItem struct {
	Index   uint32 `json:"index"`
	Name    string `json:"name"`
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	RxPkts  uint64 `json:"rx_pkts"`
	TxPkts  uint64 `json:"tx_pkts"`
	Drops   uint64 `json:"drops"`
}

// GlobalStats dashboard uchun umumiy ma'lumotlar
type GlobalStats struct {
	Interfaces []InterfaceStatItem `json:"interfaces"`
	TotalDrops uint64              `json:"total_drops"`
	CPUUsage   float64             `json:"cpu_usage"`
	MemUsage   float64             `json:"mem_usage"`
	Uptime     string              `json:"uptime"`
}

func (v *VPPClient) GetUptime() string {
	duration := time.Since(v.StartTime)
	h := int(duration.Hours())
	m := int(duration.Minutes()) % 60
	s := int(duration.Seconds()) % 60
	return fmt.Sprintf("%dh %dm %ds", h, m, s)
}

func (v *VPPClient) GetSystemPerformance() (cpu float64, mem float64, err error) {
	if v.Stats == nil {
		return 0, 0, fmt.Errorf("stats ulanishi mavjud emas")
	}

	// 1. CPU (Vector Rate) hisoblash
	sysStats := new(api.SystemStats)
	if err := v.Stats.GetSystemStats(sysStats); err == nil {
		// VectorRate - bu bir soniyada qayta ishlangan paketlar o'rtacha soni.
		// Odatda 256 gacha bo'lgan qiymat normal yuklama hisoblanadi.
		cpu = float64(sysStats.VectorRate) 
	}

	// 2. Memory (Stat segment va Main heap) hisoblash
	memStats := new(api.MemoryStats)
	if err := v.Stats.GetMemoryStats(memStats); err == nil {
		var total, used uint64

		// Main heap (VPP asosiy xotirasi) dagi barcha heap'larni yig'amiz
		for _, counters := range memStats.Main {
			total += counters.Total
			used += counters.Used
		}

		if total > 0 {
			mem = (float64(used) / float64(total)) * 100
		}
	}

	return cpu, mem, nil
}


func (v *VPPClient) refreshInterfaceNames() error {
    names := make(map[uint32]string)

    // 1. 2 soniyalik timeout bilan context yaratish
    ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
    defer cancel()

    stream, err := v.Conn.NewStream(ctx)
    if err != nil {
        return fmt.Errorf("stream yaratishda xato: %v", err)
    }
    defer stream.Close()

    // 2. Barcha interfeyslarni so'rash
    if err := stream.SendMsg(&vpp_int.SwInterfaceDump{
        SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
    }); err != nil {
        return fmt.Errorf("interfeyslarni so'rashda xato: %v", err)
    }

    // 3. Xabarlarni qabul qilish
    for {
        msg, err := stream.RecvMsg()
        if err != nil {
            // Agar io.EOF bo'lsa yoki context tugasa, sikldan chiqamiz
            break 
        }
        
        iface, ok := msg.(*vpp_int.SwInterfaceDetails)
        if !ok {
            // Yakunlovchi ControlPing xabari kelsa ham bu yerga tushadi
            continue
        }

        names[uint32(iface.SwIfIndex)] = iface.InterfaceName
    }

    // 4. Keshni yangilash
    v.IfNames = names
    return nil
}
func (v *VPPClient) GetGlobalStats() (*GlobalStats, error) {
	if v.Stats == nil {
		return nil, fmt.Errorf("stats ulanishi yo'q")
	}

	// 1. Nomlarni faqat bir marta keshga olamiz
	if len(v.IfNames) == 0 {
		v.refreshInterfaceNames() 
	}

	// 2. Stats olish (0.5s timeout bilan)
	ifStats := new(api.InterfaceStats)
	sysStats := new(api.SystemStats)
	memStats := new(api.MemoryStats)
	
	done := make(chan error, 1)
	go func() {
		_ = v.Stats.GetSystemStats(sysStats)
		_ = v.Stats.GetMemoryStats(memStats)
		done <- v.Stats.GetInterfaceStats(ifStats)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		return nil, fmt.Errorf("vpp stats timeout")
	}

	// 3. CPU va Memory hisoblash
	var memUsage float64
	for _, counters := range memStats.Main {
		if counters.Total > 0 {
			memUsage = (float64(counters.Used) / float64(counters.Total)) * 100
		}
	}

	res := &GlobalStats{
		Interfaces: make([]InterfaceStatItem, 0),
		TotalDrops: 0,
		CPUUsage:   float64(sysStats.VectorRate), // Haqiqiy Vector Rate
		MemUsage:   memUsage,
		Uptime:     v.GetUptime(),
	}

	// 4. Ma'lumotlarni yig'ish
	for _, stats := range ifStats.Interfaces {
		name, exists := v.IfNames[stats.InterfaceIndex]
		if !exists {
			name = fmt.Sprintf("Interface %d", stats.InterfaceIndex)
		}

		res.Interfaces = append(res.Interfaces, InterfaceStatItem{
			Index:   stats.InterfaceIndex,
			Name:    name,
			RxBytes: stats.Rx.Bytes,
			TxBytes: stats.Tx.Bytes,
			RxPkts:  stats.Rx.Packets,
			TxPkts:  stats.Tx.Packets,
			Drops:   stats.Drops,
		})
		res.TotalDrops += stats.Drops
	}

	return res, nil
}