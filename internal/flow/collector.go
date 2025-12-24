package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type Collector struct {
	Port       int
	Records    []Record
	mu         sync.RWMutex
	maxStorage int
}

func NewCollector(port int, maxEntries int) *Collector {
	return &Collector{
		Port:       port,
		Records:    make([]Record, 0),
		maxStorage: maxEntries,
	}
}

func (c *Collector) Start(ctx context.Context) error {
	addr := &net.UDPAddr{
		Port: c.Port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDP listen error: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			conn.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			c.parsePacket(buf[:n])
		}
	}
}

func (c *Collector) parsePacket(data []byte) {
	// Header (16) + SetHeader (4) + L2(14) + L3(8) + L4(5) = kamida 47 bayt bo'lishi kerak
	if len(data) < 47 {
		return
	}

	setID := binary.BigEndian.Uint16(data[16:18])

	// VPP Flowprobe Data Set
	if setID > 255 {
		// L2 flagi yoqilgan bo'lsa, IP manzillar 34-baytdan boshlanadi
		// (16 Header + 4 SetHeader + 6 SrcMAC + 6 DstMAC + 2 EtherType = 34)
		
		record := Record{
			Timestamp: time.Now(),
			SrcIP:     net.IP(data[34:38]).String(),
			DstIP:     net.IP(data[38:42]).String(),
			Protocol:  data[42],
		}

		// L4 ma'lumotlari (Portlar)
		record.SrcPort = binary.BigEndian.Uint16(data[43:45])
		record.DstPort = binary.BigEndian.Uint16(data[45:47])

		// Protokol nomini aniqlash (oddiyroq usul)
		if record.Protocol == 6 {
			record.ProtocolName = "TCP"
		} else if record.Protocol == 17 {
			record.ProtocolName = "UDP"
		}

		c.addRecord(record)
		fmt.Printf("Yangi Flow: %s:%d -> %s:%d [%s]\n", 
			record.SrcIP, record.SrcPort, record.DstIP, record.DstPort, record.ProtocolName)
	}
}

func (c *Collector) addRecord(r Record) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.Records = append(c.Records, r)
	if len(c.Records) > c.maxStorage {
		c.Records = c.Records[1:] // FIFO: eng eskisini o'chirish
	}
}

func (c *Collector) GetLatest(limit int) []Record {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit > len(c.Records) {
		limit = len(c.Records)
	}
	// Oxirgi qo'shilganlarni qaytarish
	return c.Records[len(c.Records)-limit:]
}