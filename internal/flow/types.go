package flow

import "time"

// Record - tahlil qilingan IP oqimi haqida ma'lumot
type Record struct {
	Timestamp    time.Time `json:"timestamp"`
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	Protocol     uint8     `json:"protocol"`
	ProtocolName string    `json:"protocol_name"`
	Packets      uint64    `json:"packets"`
	Bytes        uint64    `json:"bytes"`
}

// Stats - real-vaqtda statistika uchun
type Stats struct {
	TotalFlows      int            `json:"total_flows"`
	BytesPerSecond  uint64         `json:"bytes_per_sec"`
	ProtocolDist    map[string]int `json:"protocol_dist"`
}