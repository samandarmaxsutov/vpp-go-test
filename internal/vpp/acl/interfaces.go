package acl

import (
	"fmt"
	"context"
	"io"
	"vpp-go-test/binapi/acl"
	"vpp-go-test/binapi/interface_types"
)

// ApplyACLToInterface - ACL-larni interfeysga biriktiradi (Ingress va Egress)
func (m *ACLManager) ApplyACLToInterface(ctx context.Context, swIfIndex uint32, inputACLs []uint32, outputACLs []uint32) error {
	// VPP bitta massiv kutadi: oldin hamma inputlar, keyin hamma outputlar
	allACLs := append(inputACLs, outputACLs...)
	
	_, err := m.client.ACLInterfaceSetACLList(ctx, &acl.ACLInterfaceSetACLList{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Count:     uint8(len(allACLs)),
		NInput:    uint8(len(inputACLs)), // Nechtasi kirish (input) ekanini bildiradi
		Acls:      allACLs,
	})

	if err != nil {
		return fmt.Errorf("interfeysga ACL o'rnatishda xato: %v", err)
	}
	return nil
}
// GetAllInterfaceACLs - Barcha interfeyslardagi ACL bog'lamalarini massivga yig'adi
func (m *ACLManager) GetAllInterfaceACLs(ctx context.Context) ([]InterfaceACLMap, error) {
	stream, err := m.client.ACLInterfaceListDump(ctx, &acl.ACLInterfaceListDump{
		SwIfIndex: ^interface_types.InterfaceIndex(0), // Barcha interfeyslar (0xffffffff)
	})
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	var result []InterfaceACLMap // Natijalarni yig'ish uchun massiv

	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break // Ma'lumot uzatish muvaffaqiyatli tugadi
		}
		if err != nil {
			return nil, err // Haqiqiy tarmoq yoki VPP xatosi
		}

		// Har bir interfeys ma'lumotini massivga qo'shamiz
		mapping := InterfaceACLMap{
			SwIfIndex:  uint32(details.SwIfIndex),
			InputACLs:  details.Acls[:details.NInput],
			OutputACLs: details.Acls[details.NInput:],
		}
		result = append(result, mapping)
	}

	return result, nil // Endi return tsikldan tashqarida, hamma ma'lumot yig'ilgach ishlaydi
}

// GetInterfaceACLs - Faqat bitta interfeysni olish (Xavfsiz ko'rinish)
func (m *ACLManager) GetInterfaceACLs(ctx context.Context, swIfIndex uint32) (*InterfaceACLMap, error) {
	stream, err := m.client.ACLInterfaceListDump(ctx, &acl.ACLInterfaceListDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Birinchi mos kelganini qaytaramiz va funksiyadan chiqamiz
		return &InterfaceACLMap{
			SwIfIndex:  uint32(details.SwIfIndex),
			InputACLs:  details.Acls[:details.NInput],
			OutputACLs: details.Acls[details.NInput:],
		}, nil
	}

	// Agar hech narsa topilmasa
	return &InterfaceACLMap{SwIfIndex: swIfIndex, InputACLs: []uint32{}, OutputACLs: []uint32{}}, nil
}


// ApplyMacACLToInterface - MAC ACLni interfeysga bog'lash
func (m *ACLManager) ApplyMacACLToInterface(ctx context.Context, swIfIndex uint32, aclIndex uint32, add bool) error {
	// binapi strukturasida IsAdd bool tipida bo'lsa:
	_, err := m.client.MacipACLInterfaceAddDel(ctx, &acl.MacipACLInterfaceAddDel{
		IsAdd:     add, // To'g'ridan-to'g'ri bool yuboramiz
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		ACLIndex:  aclIndex,
	})

	if err != nil {
		return fmt.Errorf("MAC ACLni interfeysga biriktirishda xato: %v", err)
	}
	return nil
}

// GetMacACLInterfaceList - Interfeyslarga biriktirilgan MAC ACLlarni olish
func (m *ACLManager) GetMacACLInterfaceList(ctx context.Context) (map[uint32]uint32, error) {
	resp, err := m.client.MacipACLInterfaceGet(ctx, &acl.MacipACLInterfaceGet{})
	if err != nil {
		return nil, fmt.Errorf("MAC ACL bog'lamalarini olishda xato: %v", err)
	}

	// Key: SwIfIndex, Value: ACLIndex
	interfaceMaps := make(map[uint32]uint32)
	for i, aclIdx := range resp.Acls {
		if aclIdx != ^uint32(0) { // ^uint32(0) ya'ni 4294967295 bo'lsa, ACL yo'q degani
			interfaceMaps[uint32(i)] = aclIdx
		}
	}
	return interfaceMaps, nil
}

// UnbindMacACLFromInterface - MAC ACLni interfeysdan uzish
func (m *ACLManager) UnbindMacACLFromInterface(ctx context.Context, swIfIndex uint32, aclIndex uint32) error {
	return m.ApplyMacACLToInterface(ctx, swIfIndex, aclIndex, false)
}


