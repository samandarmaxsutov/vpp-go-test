package dhcp

import (
    "bytes"
    "encoding/json"
    "net/http"
)

// KeaConfig structure to avoid losing global settings
func SetKeaConfig(subnet string, relayIP string, pool string) error {
    url := "http://127.0.0.1:8001" // Kea Control Agent URL

    // To'liq konfiguratsiyani shakllantiramiz
    keaConfig := map[string]interface{}{
        "command": "config-set",
        "service": []string{"dhcp4"},
        "arguments": map[string]interface{}{
            "Dhcp4": map[string]interface{}{
                "interfaces-config": map[string]interface{}{
                    "interfaces": []string{"*"}, // Barcha interfeyslarda tinglash
                },
                "lease-database": map[string]interface{}{
                    "type":    "memfile",
                    "persist": true,
                    "name":    "/var/lib/kea/kea-leases4.csv",
                },
                "control-socket": map[string]interface{}{
                    "socket-type": "unix",
                    "socket-name": "/run/kea/kea-dhcp4-ctrl.sock",
                },
                "subnet4": []map[string]interface{}{
                    {
                        "id":     1,
                        "subnet": subnet,
                        "relay": map[string]interface{}{
                            "ip-address": relayIP,
                        },
                        "pools": []map[string]interface{}{
                            {"pool": pool},
                        },
                        "option-data": []map[string]interface{}{
                            {"name": "routers", "data": relayIP},
                            {"name": "domain-name-servers", "data": "8.8.8.8, 1.1.1.1"},
                        },
                    },
                },
            },
        },
    }

    b, err := json.Marshal(keaConfig)
    if err != nil {
        return err
    }

    resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    return nil
}


func GetKeaConfig() (map[string]interface{}, error) {
    url := "http://127.0.0.1:8001"
    
    cmd := map[string]interface{}{
        "command": "config-get",
        "service": []string{"dhcp4"},
    }
    
    b, _ := json.Marshal(cmd)
    resp, err := http.Post(url, "application/json", bytes.NewBuffer(b))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    // DIQQAT: Kea javobi massiv ko'rinishida keladi []map...
    var rawResponse []map[string]interface{} 
    if err := json.NewDecoder(resp.Body).Decode(&rawResponse); err != nil {
        return nil, err
    }

    // Massiv bo'sh emasligini va birinchi elementda arguments borligini tekshiramiz
    if len(rawResponse) > 0 {
        if args, ok := rawResponse[0]["arguments"].(map[string]interface{}); ok {
            return args, nil
        }
    }

    return nil, nil
}