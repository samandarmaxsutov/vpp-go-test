package vpp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.fd.io/govpp/api"
	vpp_int "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/interface_types"

	// Add these libraries for Kernel Stats
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
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
	Timestamp  int64               `json:"timestamp"`
	Interfaces []InterfaceStatItem `json:"interfaces"`
	TotalDrops uint64              `json:"total_drops"`
	CPUUsage   float64             `json:"cpu_usage"` // OS CPU %
	MemUsage   float64             `json:"mem_usage"` // OS RAM %
	Uptime     string              `json:"uptime"`
}

// 2. Create a History Manager
type StatsCollector struct {
	client     *VPPClient
	history    []*GlobalStats
	maxHistory int
	mu         sync.RWMutex
	stopChan   chan struct{}
}

var StatsHistory *StatsCollector

// 3. Initialize the Collector (Call this in your main.go or startup)
func InitStatsCollector(vpp *VPPClient) {
	StatsHistory = &StatsCollector{
		client:     vpp,
		history:    make([]*GlobalStats, 0, 60),
		maxHistory: 60, // Keep last 60 seconds
		stopChan:   make(chan struct{}),
	}
	// Start background polling
	go StatsHistory.run()
}

func (s *StatsCollector) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			stats, err := s.client.GetGlobalStats()
			if err == nil {
				// Manually add timestamp here
				stats.Timestamp = time.Now().UnixMilli()
				s.add(stats)
			}
		}
	}
}

func (s *StatsCollector) add(stat *GlobalStats) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.history = append(s.history, stat)
	// If buffer is full, remove the oldest item (shift left)
	if len(s.history) > s.maxHistory {
		s.history = s.history[1:]
	}
}

// GetHistory returns the safe copy of the history
func (s *StatsCollector) GetHistory() []*GlobalStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy to be thread-safe
	copyHist := make([]*GlobalStats, len(s.history))
	copy(copyHist, s.history)
	return copyHist
}

func (v *VPPClient) GetUptime() string {
	duration := time.Since(v.StartTime)
	h := int(duration.Hours())
	m := int(duration.Minutes()) % 60
	s := int(duration.Seconds()) % 60
	return fmt.Sprintf("%dh %dm %ds", h, m, s)
}

// Helper function to get Kernel Stats
func getKernelStats() (float64, float64) {
	// 1. CPU Usage
	// 0 duration means it calculates since the last call (non-blocking if called repeatedly)
	// or returns 0 on the very first call.
	// To ensure we get a number, we wait a tiny bit (200ms) or handle the state.
	// For a dashboard, 200ms delay is acceptable.
	c, err := cpu.Percent(200*time.Millisecond, false)
	var cpuUsage float64
	if err == nil && len(c) > 0 {
		cpuUsage = c[0] // Total CPU usage across all cores
	}

	// 2. Memory Usage
	m, err := mem.VirtualMemory()
	var memUsage float64
	if err == nil {
		memUsage = m.UsedPercent
	}

	return cpuUsage, memUsage
}

func (v *VPPClient) GetSystemPerformance() (cpu float64, mem float64, err error) {
	// Old logic removed. Now using Kernel stats directly.
	c, m := getKernelStats()
	return c, m, nil
}

func (v *VPPClient) refreshInterfaceNames() error {
	names := make(map[uint32]string)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	stream, err := v.Conn.NewStream(ctx)
	if err != nil {
		return fmt.Errorf("stream yaratishda xato: %v", err)
	}
	defer stream.Close()

	if err := stream.SendMsg(&vpp_int.SwInterfaceDump{
		SwIfIndex: interface_types.InterfaceIndex(0xffffffff),
	}); err != nil {
		return fmt.Errorf("interfeyslarni so'rashda xato: %v", err)
	}

	for {
		msg, err := stream.RecvMsg()
		if err != nil {
			break
		}

		iface, ok := msg.(*vpp_int.SwInterfaceDetails)
		if !ok {
			continue
		}

		names[uint32(iface.SwIfIndex)] = iface.InterfaceName
	}

	v.IfNames = names
	return nil
}

func (v *VPPClient) GetGlobalStats() (*GlobalStats, error) {
	if v.Stats == nil {
		return nil, fmt.Errorf("stats ulanishi yo'q")
	}

	// 1. Refresh Names if needed
	if len(v.IfNames) == 0 {
		v.refreshInterfaceNames()
	}

	// 2. Get Interface Stats (VPP)
	ifStats := new(api.InterfaceStats)
	// We no longer need System/Memory stats from VPP here for the dashboard
	// But we still need to wait for Interface stats

	errChan := make(chan error, 1)
	go func() {
		errChan <- v.Stats.GetInterfaceStats(ifStats)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			return nil, fmt.Errorf("stat xatosi: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		return nil, fmt.Errorf("stats timeout")
	}

	// 3. Get Real CPU/Mem from Kernel (OS)
	cpuVal, memVal := getKernelStats()

	res := &GlobalStats{
		Interfaces: make([]InterfaceStatItem, 0),
		TotalDrops: 0,
		CPUUsage:   cpuVal, // Now shows real OS load (e.g., 5.4%)
		MemUsage:   memVal, // Now shows real OS RAM (e.g., 64.2%)
		Uptime:     v.GetUptime(),
	}

	// 4. Map Interface Data
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
