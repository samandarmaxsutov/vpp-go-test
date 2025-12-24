package vpp

import (
	"context"
	"fmt"
	"io"
	"net" // IP formatlash uchun kerak
	"time"
	"strings"

	"vpp-go-test/binapi/fib_types"
	"vpp-go-test/binapi/ip"
	"vpp-go-test/binapi/ip_types"
)

type RouteData struct {
	Prefix    string   `json:"prefix"`
	NextHops  []string `json:"next_hops"`
	Interface string   `json:"interface"`
	Protocol  string   `json:"protocol"`
	Distance  uint8    `json:"distance"` // Qo'shildi
	Metric    uint8  `json:"metric"`
}

func (v *VPPClient) GetRoutingTable() ([]RouteData, error) {
	var routes []RouteData
	rpc := ip.NewServiceClient(v.Conn)
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	stream, err := rpc.IPRouteDump(ctx, &ip.IPRouteDump{
		Table: ip.IPTable{TableID: 0, IsIP6: false},
	})
	if err != nil {
		return nil, err
	}

	for {
		details, err := stream.Recv()
		if err == io.EOF { break }
		if err != nil { return nil, err }

		r := RouteData{
			Prefix:   details.Route.Prefix.String(),
			Protocol: "static",
		}

		for _, path := range details.Route.Paths {
			// 1. Next Hop IP ni baytlardan IP stringga o'tkazish
			// VPP AddressUnion (IPv4 bo'lsa) birinchi 4 baytda IP ni saqlaydi
			addrBytes := path.Nh.Address.GetIP4() 
			nhIP := net.IP(addrBytes[:])
			
			nhStr := nhIP.String()
			if nhStr == "0.0.0.0" || nhStr == "<nil>" {
				nhStr = "directly connected"
			}
			r.NextHops = append(r.NextHops, nhStr)

			// 2. Interfeys nomi
			if name, ok := v.IfNames[path.SwIfIndex]; ok {
				r.Interface = name
			} else if path.SwIfIndex == 4294967295 {
				r.Interface = "punt/drop"
			} else {
				r.Interface = fmt.Sprintf("idx-%d", path.SwIfIndex)
			}

			// 3. Distance va Metric (Bularni RouteData structiga qo'shish kerak)
			r.Distance = path.Preference
			r.Metric = path.Weight // Yoki path.Weight

			if path.Type == fib_types.FIB_API_PATH_TYPE_LOCAL {
				r.Protocol = "connected"
			}
		}
		routes = append(routes, r)
	}
	return routes, nil
}



func (v *VPPClient) AddStaticRoute(prefixStr string, gatewayStr string, swIfIndex uint32) error {
	// 1. Prefixni parse qilish
	ipPart, ipNet, err := net.ParseCIDR(prefixStr)
	if err != nil {
		if ipAddr := net.ParseIP(prefixStr); ipAddr != nil {
			prefixStr = prefixStr + "/32"
			ipPart, ipNet, err = net.ParseCIDR(prefixStr)
		}
		if err != nil {
			return fmt.Errorf("prefix formati xato: %v", err)
		}
	}

	ones, _ := ipNet.Mask.Size()
	
	// IP4Address massiv [4]byte bo'lishi kerak
	var addr4 ip_types.IP4Address
	copy(addr4[:], ipPart.To4())

	prefix := ip_types.Prefix{
		Address: ip_types.Address{
			Af: ip_types.ADDRESS_IP4,
			Un: ip_types.AddressUnionIP4(addr4),
		},
		Len: uint8(ones),
	}

	// 2. Gateway tayyorlash
	var nhAddr ip_types.AddressUnion
	if gatewayStr != "" && gatewayStr != "direct" {
		if strings.Contains(gatewayStr, "/") {
			gatewayStr = strings.Split(gatewayStr, "/")[0]
		}
		
		gwIP := net.ParseIP(gatewayStr).To4()
		if gwIP == nil {
			return fmt.Errorf("gateway IP xato: %v", gatewayStr)
		}
		var gwAddr4 ip_types.IP4Address
		copy(gwAddr4[:], gwIP)
		nhAddr.SetIP4(gwAddr4)
	}

	// 3. VPP so'rovi
	req := &ip.IPRouteAddDel{
		IsAdd: true,
		Route: ip.IPRoute{
			TableID: 0,
			Prefix:  prefix,
			Paths: []fib_types.FibPath{
				{
					SwIfIndex: swIfIndex,
					Proto:     fib_types.FIB_API_PATH_NH_PROTO_IP4,
					Weight:    1,
					Nh: fib_types.FibPathNh{
						Address: nhAddr,
					},
				},
			},
		},
	}

	reply := &ip.IPRouteAddDelReply{}
	return v.Conn.Invoke(context.Background(), req, reply)
}

func (v *VPPClient) DeleteStaticRoute(prefixStr string) error {
	prefix, err := ip_types.ParsePrefix(prefixStr)
	if err != nil {
		return fmt.Errorf("prefix xato: %v", err)
	}

	req := &ip.IPRouteAddDel{
		IsAdd: false, // O'chirish uchun false
		Route: ip.IPRoute{
			TableID: 0,
			Prefix:  prefix,
			// O'chirishda Paths qismini ham yuborish kerak (VPP o'sha pathni qidiradi)
			Paths: []fib_types.FibPath{
				{
					SwIfIndex: 4294967295, // O'chirishda indeks ko'pincha drop sifatida beriladi
					Proto:     fib_types.FIB_API_PATH_NH_PROTO_IP4,
				},
			},
		},
	}

	reply := &ip.IPRouteAddDelReply{}
	return v.Conn.Invoke(context.Background(), req, reply)
}