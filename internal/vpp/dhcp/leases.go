package dhcp

import (
	"encoding/csv"
	"os"
	"strconv"
	"time"
)

type DhcpLease struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Hostname   string `json:"hostname"`
	ExpiresRaw int64  `json:"expires_raw"` // Field name corrected for Go literal
	ExpiresStr string `json:"expires"`     // Human readable
	IsActive   bool   `json:"is_active"`
}

func GetKeaLeases() ([]DhcpLease, error) {
	file, err := os.Open("/var/lib/kea/kea-leases4.csv")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	lines, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	// Map keyed by IP Address to keep only the latest record from Kea CSV
	latestLeases := make(map[string]DhcpLease)
	now := time.Now().Unix()

	for i, line := range lines {
		// address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state
		if i == 0 || len(line) < 10 {
			continue
		}

		ip := line[0]
		expireUnix, _ := strconv.ParseInt(line[4], 10, 64)
		
		// Map overwrites previous entries, ensuring we only see the latest lease state
		latestLeases[ip] = DhcpLease{
			IPAddress:  ip,
			MACAddress: line[1],
			Hostname:   line[8],
			ExpiresRaw: expireUnix, // Corrected field name
			ExpiresStr: time.Unix(expireUnix, 0).Format("2006-01-02 15:04:05"),
			IsActive:   (line[9] == "0" && expireUnix > now), // state 0 = active
		}
	}

	var result []DhcpLease
	for _, lease := range latestLeases {
		result = append(result, lease)
	}
	return result, nil
}