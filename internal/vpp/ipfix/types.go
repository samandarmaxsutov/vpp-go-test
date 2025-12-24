package ipfix

import (
	"errors"
	"net"
)

// IpfixConfig represents the desired configuration for the exporter
type IpfixConfig struct {
	CollectorAddress string `json:"collector_address"`
	CollectorPort    uint16 `json:"collector_port"`
	SourceAddress    string `json:"source_address"`
	VrfID            uint32 `json:"vrf_id"`
	PathMtu          uint32 `json:"path_mtu"`
	TemplateInterval uint32 `json:"template_interval"`
	UDPChecksum      bool   `json:"udp_checksum"`
}

// IpfixStatus represents the current state returned from VPP
type IpfixStatus struct {
	IsActive         bool   `json:"is_active"`
	CollectorAddress string `json:"collector_address"`
	CollectorPort    uint16 `json:"collector_port"`
	SourceAddress    string `json:"source_address"`
	VrfID            uint32 `json:"vrf_id"`
	PathMtu          uint32 `json:"path_mtu"`
	TemplateInterval uint32 `json:"template_interval"`
	UDPChecksum      bool   `json:"udp_checksum"`
}

// Validate performs basic checks on the input data
func (c *IpfixConfig) Validate() error {
	if net.ParseIP(c.CollectorAddress) == nil {
		return errors.New("invalid collector IP address")
	}
	if net.ParseIP(c.SourceAddress) == nil {
		return errors.New("invalid source IP address")
	}
	if c.CollectorPort == 0 {
		return errors.New("collector port must be greater than 0")
	}
	if c.TemplateInterval == 0 {
		c.TemplateInterval = 20 // Default value
	}
	if c.PathMtu == 0 {
		c.PathMtu = 1400 // Default value
	}
	return nil
}

type FlowprobeParamsConfig struct {
	ActiveTimeout uint32 `json:"active_timeout"`
	RecordL4      bool   `json:"record_l4"`
}

type InterfaceToggleRequest struct {
	SwIfIndex uint32 `json:"sw_if_index"`
	Enable    bool   `json:"enable"`
}
