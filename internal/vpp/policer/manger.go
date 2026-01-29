package policer

import (
	"context"
	"fmt"
	"io"

	"vpp-go-test/binapi/interface_types"
	"vpp-go-test/binapi/policer"
	"vpp-go-test/binapi/policer_types"

	"go.fd.io/govpp/api"
)

type Manager struct {
	rpc       policer.RPCService
	bindStore *bindingStore
}

func NewManager(conn api.Connection) *Manager {
	return &Manager{
		rpc:       policer.NewServiceClient(conn),
		bindStore: newBindingStore("./policer_bindings.json"),
	}
}

// AddPolicer yangi policer profilini yaratadi va uning indeksini qaytaradi
func (m *Manager) AddPolicer(ctx context.Context, name string, cir uint32, cb uint64) (uint32, error) {
	req := &policer.PolicerAdd{
		Name: name,
		Infos: policer_types.PolicerConfig{
			Cir:       cir,
			Cb:        cb,
			RateType:  policer_types.SSE2_QOS_RATE_API_KBPS,
			RoundType: policer_types.SSE2_QOS_ROUND_API_TO_CLOSEST,
			Type:      policer_types.SSE2_QOS_POLICER_TYPE_API_1R2C,
			ConformAction: policer_types.Sse2QosAction{
				Type: policer_types.SSE2_QOS_ACTION_API_TRANSMIT,
			},
			ExceedAction: policer_types.Sse2QosAction{
				Type: policer_types.SSE2_QOS_ACTION_API_DROP,
			},
			ViolateAction: policer_types.Sse2QosAction{
				Type: policer_types.SSE2_QOS_ACTION_API_DROP,
			},
		},
	}

	// DIQQAT: PolicerAddReply dan PolicerIndex ni olish uchun
	// binapi-da PolicerAddReply qandayligini tekshirish kerak.
	// Agar PolicerAddReply-da indeks bo'lmasa, Dump orqali topiladi.
	reply, err := m.rpc.PolicerAdd(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("policer qo'shishda xato: %v", err)
	}

	// Odatda reply-da index qaytadi, agar qaytmasa 0 qaytaramiz
	return 0, api.RetvalToVPPApiError(reply.Retval)
}

// DeletePolicer endi indeks bo'yicha o'chiradi (Siz yuborgan binapi asosida)
func (m *Manager) DeletePolicer(ctx context.Context, index uint32) error {
	req := &policer.PolicerDel{
		PolicerIndex: index,
	}

	reply, err := m.rpc.PolicerDel(ctx, req)
	if err != nil {
		return fmt.Errorf("policerni o'chirishda xatolik: %v", err)
	}

	return api.RetvalToVPPApiError(reply.Retval)
}

// DeletePolicerByName - Policer ni nomi bo'yicha o'chiradi
func (m *Manager) DeletePolicerByName(ctx context.Context, name string) error {
	req := &policer.PolicerAddDel{
		IsAdd: false,
		Name:  name,
	}

	reply, err := m.rpc.PolicerAddDel(ctx, req)
	if err != nil {
		return fmt.Errorf("policerni o'chirishda xatolik: %v", err)
	}

	return api.RetvalToVPPApiError(reply.Retval)
}

// ListPolicers barcha policerlarni ko'rish
func (m *Manager) ListPolicers(ctx context.Context) ([]*policer.PolicerDetails, error) {
	stream, err := m.rpc.PolicerDump(ctx, &policer.PolicerDump{})
	if err != nil {
		return nil, err
	}

	var list []*policer.PolicerDetails
	for {
		details, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		list = append(list, details)
	}

	return list, nil
}

// BindToInterface - Policerni interfeysga yo'nalish bo'yicha bog'laydi
func (m *Manager) BindToInterface(ctx context.Context, name string, swIfIndex uint32, direction string, apply bool) error {
	if direction == "output" {
		// PolicerOutput xabarini yuborish
		_, err := m.rpc.PolicerOutput(ctx, &policer.PolicerOutput{
			Name:      name,
			SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
			Apply:     apply,
		})
		if err != nil {
			return err
		}
		if apply {
			_ = m.bindStore.add(name, swIfIndex, direction)
		} else {
			_ = m.bindStore.remove(name, swIfIndex, direction)
		}
		return nil
	}

	// Default: PolicerInput xabarini yuborish
	_, err := m.rpc.PolicerInput(ctx, &policer.PolicerInput{
		Name:      name,
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
		Apply:     apply,
	})
	if err != nil {
		return err
	}
	if apply {
		_ = m.bindStore.add(name, swIfIndex, direction)
	} else {
		_ = m.bindStore.remove(name, swIfIndex, direction)
	}
	return nil
}

func (m *Manager) GetBindingsForPolicer(name string) []InterfaceBinding {
	if m.bindStore == nil {
		return nil
	}
	return m.bindStore.get(name)
}
