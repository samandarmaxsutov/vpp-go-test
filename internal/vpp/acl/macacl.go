package acl

import (
	"context"
	"fmt"
	"io"
	"vpp-go-test/binapi/acl"
	"vpp-go-test/binapi/acl_types"
)

// CreateMacACL - Yangi MAC ACL yaratish yoki mavjudini yangilash
func (m *ACLManager) CreateMacACL(ctx context.Context, aclIndex uint32, tag string, rules []acl_types.MacipACLRule) (uint32, error) {
	req := &acl.MacipACLAddReplace{
		ACLIndex: aclIndex, // 0xffffffff yangi yaratish uchun
		Tag:      tag,
		Count:    uint32(len(rules)),
		R:        rules,
	}

	reply, err := m.client.MacipACLAddReplace(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("MAC ACL saqlashda xatolik: %v", err)
	}

	return reply.ACLIndex, nil
}

// GetAllMacACLs - Barcha MAC ACL'larni dump qilish
func (m *ACLManager) GetAllMacACLs(ctx context.Context) ([]MacACLDetail, error) {
	stream, err := m.client.MacipACLDump(ctx, &acl.MacipACLDump{
		ACLIndex: 0xffffffff, 
	})
	if err != nil {
		return nil, err
	}

	var results []MacACLDetail
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		detail := MacACLDetail{
			ACLIndex: msg.ACLIndex,
			Tag:      msg.Tag,
			Rules:    make([]MacACLRule, 0),
		}

		for _, r := range msg.R {
			detail.Rules = append(detail.Rules, ConvertVPPToCustomMacRule(r))
		}
		results = append(results, detail)
	}

	return results, nil
}

// DeleteMacACL - MAC ACLni butunlay o'chirish
func (m *ACLManager) DeleteMacACL(ctx context.Context, aclIndex uint32) error {
	_, err := m.client.MacipACLDel(ctx, &acl.MacipACLDel{
		ACLIndex: aclIndex,
	})
	return err
}