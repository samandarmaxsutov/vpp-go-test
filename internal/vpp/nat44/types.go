package nat44

import (

)

// NAT Interfeys turi
type NatInterface struct {
	SwIfIndex uint32 `json:"sw_if_index"`
	Name      string `json:"name"`
	IsInside  bool   `json:"is_inside"`
}

// Tashqi IP hovuzi
type NatAddressPool struct {
	IPAddress string `json:"ip_address"`
	VrfID     uint32 `json:"vrf_id"`
}

// Static Mapping (Inbound/DNAT)
type StaticMapping struct {
    LocalIP      string `json:"local_ip"`
    LocalPort    uint16 `json:"local_port"`
    ExternalIP   string `json:"external_ip"`   // Agar IP orqali bo'lsa
    ExternalPort uint16 `json:"external_port"`
    ExternalIf   uint32 `json:"external_if"`   // Agar interfeys orqali bo'lsa (Index)
    Protocol     string `json:"protocol"`
    IsAdd        bool   `json:"is_add"`        // Qo'shish yoki o'chirish flagi
}



// Frontend uchun qulay struktura
type SessionDisplay struct {
    InsideIP          string `json:"inside_ip_address"`
    InsidePort        uint16 `json:"inside_port"`
    OutsideIP         string `json:"outside_ip_address"`
    OutsidePort       uint16 `json:"outside_port"`
    ExtHostIP         string `json:"ext_host_address"`
    ExtHostPort       uint16 `json:"ext_host_port"`
    Protocol          string `json:"protocol"`
    TotalBytes        uint64 `json:"total_bytes"`
    TotalPkts         uint32 `json:"total_pkts"`
    IsTimedOut        bool   `json:"is_timed_out"`
    TimeSinceLastHeard uint64 `json:"time_since_last_heard"`
}

type UserTraffic struct {
    IP           string  `json:"ip"`
    SessionCount int     `json:"session_count"`
    TotalBytes   uint64  `json:"total_bytes"`
    TotalPkts    uint64  `json:"total_pkts"`
    Percentage   float64 `json:"percentage"`
}

type NATSessionResponse struct {
    Sessions    []SessionDisplay `json:"sessions"`
    UserSummary []UserTraffic    `json:"user_summary"`
}