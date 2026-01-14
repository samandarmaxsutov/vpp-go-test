package dhcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"vpp-go-test/binapi/dhcp"
	"vpp-go-test/binapi/ip_types"
	"go.fd.io/govpp/api"
)

type DhcpManager struct {
	client dhcp.RPCService
}

func NewDhcpManager(conn api.Connection) *DhcpManager {
	return &DhcpManager{
		client: dhcp.NewServiceClient(conn),
	}
}

// Helper: Correctly builds the ip_types.Address structure VPP expects
func toVppAddress(ipStr string) ip_types.Address {
	ip := net.ParseIP(ipStr)
	if ip.To4() != nil {
		var addr4 ip_types.IP4Address
		copy(addr4[:], ip.To4())
		return ip_types.Address{
			Af: ip_types.ADDRESS_IP4,
			Un: ip_types.AddressUnionIP4(addr4),
		}
	}
	var addr6 ip_types.IP6Address
	copy(addr6[:], ip.To16())
	return ip_types.Address{
		Af: ip_types.ADDRESS_IP6,
		Un: ip_types.AddressUnionIP6(addr6),
	}
}

// ConfigureProxy: matches your DHCPProxyConfig struct literal
func (m *DhcpManager) ConfigureProxy(ctx context.Context, serverIP, srcIP string, rxVrf, serverVrf uint32, isAdd bool) error {
	req := &dhcp.DHCPProxyConfig{
		RxVrfID:        rxVrf,
		ServerVrfID:    serverVrf,
		IsAdd:          isAdd,
		DHCPServer:     toVppAddress(serverIP),
		DHCPSrcAddress: toVppAddress(srcIP),
	}

	reply, err := m.client.DHCPProxyConfig(ctx, req)
	if err != nil {
		return err
	}
	if reply.Retval != 0 {
		return fmt.Errorf("Error: %d", reply.Retval)
	}
	return nil
}

// ListProxies: Uses 'IsIpv6' (lowercase 'v') which is standard for the Dump request
func (m *DhcpManager) ListProxies(ctx context.Context, isIPv6 bool) ([]dhcp.DHCPProxyDetails, error) {
	// If IsIpv6 still fails, check dhcp.ba.go to see if the field exists at all
	stream, err := m.client.DHCPProxyDump(ctx, &dhcp.DHCPProxyDump{
		IsIP6: isIPv6, 
	})
	if err != nil {
		return nil, err
	}

	var list []dhcp.DHCPProxyDetails
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		list = append(list, *details)
	}
	return list, nil
}

// SetVSS: Updated with VPNAsciiID and supporting OUI/VPNIndex
func (m *DhcpManager) SetVSS(ctx context.Context, vrfID uint32, vssType uint8, vpnID string, oui, vpnIndex uint32, isIPv6, isAdd bool) error {
	req := &dhcp.DHCPProxySetVss{
		TblID:      vrfID,
		VssType:    dhcp.VssType(vssType),
		VPNAsciiID: vpnID, // Fixed naming
		Oui:        oui,
		VPNIndex:   vpnIndex,
		IsIPv6:     isIPv6,
		IsAdd:      isAdd,
	}

	reply, err := m.client.DHCPProxySetVss(ctx, req)
	if err != nil {
		return err
	}
	if reply.Retval != 0 {
		return fmt.Errorf("VSS error: %d", reply.Retval)
	}
	return nil
}