package dhcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const keaURL = "http://127.0.0.1:8001"

// 1. GET: Kea-dan joriy konfiguratsiyani olish
func GetKeaConfig() (map[string]interface{}, error) {
	cmd := map[string]interface{}{
		"command": "config-get",
		"service": []string{"dhcp4"},
	}

	b, _ := json.Marshal(cmd)
	resp, err := http.Post(keaURL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var raw []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	if len(raw) > 0 && raw[0]["result"].(float64) == 0 {
		return raw[0]["arguments"].(map[string]interface{}), nil
	}
	return nil, fmt.Errorf("Kea configuration not found or error")
}

// 2. INTERNAL: Konfiguratsiyani Kea-ga yozish (config-set)
func PushKeaConfig(args map[string]interface{}) error {
	payload := map[string]interface{}{
		"command":   "config-set",
		"service":   []string{"dhcp4"},
		"arguments": args,
	}

	b, _ := json.Marshal(payload)
	resp, err := http.Post(keaURL, "application/json", bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// 3. ADD/APPEND & EDIT: Subnet qo'shish yoki borini tahrirlash
func SaveKeaSubnet(id int, subnet, relay, pool string) error {
	// Avval mavjud hamma konfni olamiz (global sozlamalar o'chib ketmasligi uchun)
	fullConf, err := GetKeaConfig()
	if err != nil {
		return err
	}

	dhcp4 := fullConf["Dhcp4"].(map[string]interface{})
	subnets, _ := dhcp4["subnet4"].([]interface{})

	newSubnet := map[string]interface{}{
		"id":     id,
		"subnet": subnet,
		"relay":  map[string]interface{}{"ip-addresses": []string{relay}},
		"pools":  []map[string]interface{}{{"pool": pool}},
		"option-data": []map[string]interface{}{
			{"name": "routers", "data": relay},
			{"name": "domain-name-servers", "data": "8.8.8.8, 1.1.1.1"},
		},
	}

	found := false
	// Tahrirlash rejimini tekshiramiz
	if id > 0 {
		for i, s := range subnets {
			sMap := s.(map[string]interface{})
			if int(sMap["id"].(float64)) == id {
				subnets[i] = newSubnet // Borini yangilaymiz
				found = true
				break
			}
		}
	}

	// Agar ID topilmasa yoki id = 0 bo'lsa - YANGI QO'SHISH (APPEND)
	if !found {
		// Yangi ID generatsiya qilish (eng kattasini topib +1)
		maxID := 0
		for _, s := range subnets {
			sID := int(s.(map[string]interface{})["id"].(float64))
			if sID > maxID {
				maxID = sID
			}
		}
		newSubnet["id"] = maxID + 1
		subnets = append(subnets, newSubnet) // Ro'yxat oxiriga qo'shish
	}

	dhcp4["subnet4"] = subnets
	fullConf["Dhcp4"] = dhcp4

	return PushKeaConfig(fullConf)
}

// 4. DELETE: Subnetni ID bo'yicha o'chirish
func DeleteKeaSubnet(id int) error {
	fullConf, err := GetKeaConfig()
	if err != nil {
		return err
	}

	dhcp4 := fullConf["Dhcp4"].(map[string]interface{})
	subnets, _ := dhcp4["subnet4"].([]interface{})

	var updatedSubnets []interface{}
	for _, s := range subnets {
		sMap := s.(map[string]interface{})
		if int(sMap["id"].(float64)) != id {
			updatedSubnets = append(updatedSubnets, s)
		}
	}

	dhcp4["subnet4"] = updatedSubnets
	fullConf["Dhcp4"] = dhcp4

	return PushKeaConfig(fullConf)
}