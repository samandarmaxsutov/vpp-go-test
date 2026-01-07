package abf_mgr

import (
	"context"
	"fmt"
	"io"
	"vpp-go-test/binapi/abf"
	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/interface_types"

	"go.fd.io/govpp/api"
)

type AbfManager struct {
	client abf.RPCService
}

func NewAbfManager(conn api.Connection) *AbfManager {
	return &AbfManager{
		client: abf.NewServiceClient(conn),
	}
}

// ConfigurePolicy - ABF siyosatini yaratadi yoki o'chiradi.
// Paths maydoni fib_types.FibPath slice-dan iborat.
func (m *AbfManager) ConfigurePolicy(ctx context.Context, policyID uint32, aclIndex uint32, paths []fib_types.FibPath, isAdd bool) error {
	req := &abf.AbfPolicyAddDel{
		IsAdd: isAdd,
		Policy: abf.AbfPolicy{
			PolicyID: policyID,
			ACLIndex: aclIndex,
			Paths:    paths,
		},
	}

	_, err := m.client.AbfPolicyAddDel(ctx, req)
	if err != nil {
		return fmt.Errorf("ABF policy (ID: %d) xatolik: %v", policyID, err)
	}
	return nil
}

// AttachToInterface - ABF siyosatini interfeysga bog'laydi yoki undan uzadi.
func (m *AbfManager) AttachToInterface(ctx context.Context, policyID uint32, swIfIndex uint32, priority uint32, isIPv6 bool, isAdd bool) error {
	req := &abf.AbfItfAttachAddDel{
		IsAdd: isAdd,
		Attach: abf.AbfItfAttach{
			PolicyID:  policyID,
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			Priority:  priority,
			IsIPv6:    isIPv6,
		},
	}

	_, err := m.client.AbfItfAttachAddDel(ctx, req)
	if err != nil {
		return fmt.Errorf("ABF attach xatolik (Policy: %d, Interface: %d): %v", policyID, swIfIndex, err)
	}
	return nil
}

// ListPolicies - Barcha ABF siyosatlari ro'yxatini qaytaradi.
func (m *AbfManager) ListPolicies(ctx context.Context) ([]abf.AbfPolicyDetails, error) {
	stream, err := m.client.AbfPolicyDump(ctx, &abf.AbfPolicyDump{})
	if err != nil {
		return nil, fmt.Errorf("ABF dump xatosi: %v", err)
	}

	var list []abf.AbfPolicyDetails
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ABF stream xatosi: %v", err)
		}
		list = append(list, *msg)
	}
	return list, nil
}

// ListInterfaceAttachments - Interfeyslarga biriktirilgan ABF-lar ro'yxatini olish.
func (m *AbfManager) ListInterfaceAttachments(ctx context.Context) ([]abf.AbfItfAttachDetails, error) {
	stream, err := m.client.AbfItfAttachDump(ctx, &abf.AbfItfAttachDump{})
	if err != nil {
		return nil, fmt.Errorf("ABF attach dump xatosi: %v", err)
	}

	var list []abf.AbfItfAttachDetails
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("ABF attach stream xatosi: %v", err)
		}
		list = append(list, *msg)
	}
	return list, nil
}

// GetVersion - ABF plagin versiyasini tekshirish.
func (m *AbfManager) GetVersion(ctx context.Context) (string, error) {
	resp, err := m.client.AbfPluginGetVersion(ctx, &abf.AbfPluginGetVersion{})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d.%d", resp.Major, resp.Minor), nil
}