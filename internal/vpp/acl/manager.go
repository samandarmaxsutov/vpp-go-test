package acl

import (
	"context"
	"fmt"
	"io"
	"vpp-go-test/binapi/acl"
	"vpp-go-test/binapi/acl_types"

	"go.fd.io/govpp/api"
)

// ACLManager VPP ACL xizmati bilan ishlash uchun mas'ul
type ACLManager struct {
	client acl.RPCService
}

// NewACLManager yangi menejer yaratadi
func NewACLManager(conn api.Connection) *ACLManager {
	return &ACLManager{
		client: acl.NewServiceClient(conn),
	}
}

// GetAllACLs VPP dagi barcha ACL larni olib keladi
// MUHIM: Custom ACLDetail type ishlatadi - 0 qiymatlarni ham qaytaradi!
func (m *ACLManager) GetAllACLs(ctx context.Context) ([]ACLDetail, error) {
	stream, err := m.client.ACLDump(ctx, &acl.ACLDump{
		ACLIndex: ^uint32(0), // 0xffffffff - barchasini olish
	})
	if err != nil {
		return nil, fmt.Errorf("ACL listni olishda xato: %v", err)
	}
	defer stream.Close()

	var result []ACLDetail
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// VPP rules ni Custom rules ga convert qilish
		customRules := make([]ACLRule, len(details.R))
		for i, vppRule := range details.R {
			customRules[i] = ConvertVPPRuleToCustom(vppRule)
		}

		result = append(result, ACLDetail{
			ACLIndex: details.ACLIndex,
			Tag:      details.Tag,
			Rules:    customRules, // Custom type ishlatiladi
		})
	}

	return result, nil
}

// CreateACL yangi ACL yaratadi
func (m *ACLManager) CreateACL(ctx context.Context, tag string, rules []acl_types.ACLRule) (uint32, error) {
	reply, err := m.client.ACLAddReplace(ctx, &acl.ACLAddReplace{
		ACLIndex: ^uint32(0), // Yangi yaratish
		Tag:      tag,
		Count:    uint32(len(rules)),
		R:        rules,
	})
	if err != nil {
		return 0, fmt.Errorf("ACL yaratishda xato: %v", err)
	}
	return reply.ACLIndex, nil
}

// DeleteACL ACL ni o'chiradi
func (m *ACLManager) DeleteACL(ctx context.Context, aclIndex uint32) error {
	_, err := m.client.ACLDel(ctx, &acl.ACLDel{
		ACLIndex: aclIndex,
	})
	return err
}

// UpdateACL - Mavjud ACLni yangilash
func (m *ACLManager) UpdateACL(ctx context.Context, aclIndex uint32, tag string, rules []acl_types.ACLRule) error {
	_, err := m.client.ACLAddReplace(ctx, &acl.ACLAddReplace{
		ACLIndex: aclIndex, // Mavjud index yuboriladi
		Tag:      tag,
		Count:    uint32(len(rules)),
		R:        rules,
	})
	if err != nil {
		return fmt.Errorf("ACL yangilashda xato: %v", err)
	}
	return nil
}

// ReplaceACL - Mavjud ACLni butunlay yangi qoidalar bilan almashtiradi
func (m *ACLManager) ReplaceACL(ctx context.Context, aclIndex uint32, tag string, rules []acl_types.ACLRule) error {
	return m.UpdateACL(ctx, aclIndex, tag, rules)
}
