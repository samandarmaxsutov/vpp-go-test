package vpp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const IPGroupsDir = "/etc/sarhad-guard/ip_groups"

// IPGroup represents a group of IPs or subnets
type IPGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Content   string    `json:"content"` // Raw text with IPs/subnets
	IPs       []string  `json:"ips"`     // Parsed IPs
	Subnets   []string  `json:"subnets"` // Parsed subnets (CIDR)
	Invalid   []string  `json:"invalid"` // Invalid entries
	Count     int       `json:"count"`   // Total valid entries
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IPGroupsService manages IP groups
type IPGroupsService struct {
	mu     sync.RWMutex
	groups map[string]*IPGroup
}

// NewIPGroupsService creates a new IP groups service
func NewIPGroupsService() *IPGroupsService {
	service := &IPGroupsService{
		groups: make(map[string]*IPGroup),
	}
	service.LoadAll()
	return service
}

// LoadAll loads all IP groups from disk
func (s *IPGroupsService) LoadAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.groups = make(map[string]*IPGroup)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(IPGroupsDir, 0755); err != nil {
		return fmt.Errorf("failed to create IP groups directory: %w", err)
	}

	// Read all JSON files
	entries, err := os.ReadDir(IPGroupsDir)
	if err != nil {
		return fmt.Errorf("failed to read IP groups directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(IPGroupsDir, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Warning: Failed to read %s: %v\n", filePath, err)
			continue
		}

		var group IPGroup
		if err := json.Unmarshal(data, &group); err != nil {
			fmt.Printf("Warning: Failed to parse %s: %v\n", filePath, err)
			continue
		}

		s.groups[group.ID] = &group
	}

	return nil
}

// GetAll returns all IP groups
func (s *IPGroupsService) GetAll() []*IPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	groups := make([]*IPGroup, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, g)
	}

	// Sort by name
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Name < groups[j].Name
	})

	return groups
}

// GetByID retrieves a group by ID
func (s *IPGroupsService) GetByID(id string) *IPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.groups[id]
}

// GetByName retrieves a group by name
func (s *IPGroupsService) GetByName(name string) *IPGroup {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, g := range s.groups {
		if g.Name == name {
			return g
		}
	}
	return nil
}

// parseIPsAndSubnets parses raw content into IPs and subnets
func parseIPsAndSubnets(content string) (ips, subnets, invalid []string) {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check if it's a CIDR subnet
		if strings.Contains(line, "/") {
			_, _, err := net.ParseCIDR(line)
			if err == nil {
				subnets = append(subnets, line)
			} else {
				invalid = append(invalid, line)
			}
		} else {
			// Try parsing as IP
			if ip := net.ParseIP(line); ip != nil {
				ips = append(ips, ip.String())
			} else {
				invalid = append(invalid, line)
			}
		}
	}

	return ips, subnets, invalid
}

// Create creates a new IP group
func (s *IPGroupsService) Create(name, content string) (*IPGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if name already exists
	for _, g := range s.groups {
		if g.Name == name {
			return nil, fmt.Errorf("group with name '%s' already exists", name)
		}
	}

	// Parse IPs and subnets
	ips, subnets, invalid := parseIPsAndSubnets(content)

	// Generate ID
	id := fmt.Sprintf("%d", time.Now().UnixNano())

	group := &IPGroup{
		ID:        id,
		Name:      name,
		Content:   content,
		IPs:       ips,
		Subnets:   subnets,
		Invalid:   invalid,
		Count:     len(ips) + len(subnets),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Save to disk
	if err := s.saveGroup(group); err != nil {
		return nil, err
	}

	s.groups[id] = group
	return group, nil
}

// Update updates an existing IP group
func (s *IPGroupsService) Update(id, name, content string) (*IPGroup, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	group, exists := s.groups[id]
	if !exists {
		return nil, fmt.Errorf("group with id '%s' not found", id)
	}

	// Check if new name conflicts with other groups
	if name != group.Name {
		for _, g := range s.groups {
			if g.ID != id && g.Name == name {
				return nil, fmt.Errorf("group with name '%s' already exists", name)
			}
		}
	}

	// Parse IPs and subnets
	ips, subnets, invalid := parseIPsAndSubnets(content)

	group.Name = name
	group.Content = content
	group.IPs = ips
	group.Subnets = subnets
	group.Invalid = invalid
	group.Count = len(ips) + len(subnets)
	group.UpdatedAt = time.Now()

	// Save to disk
	if err := s.saveGroup(group); err != nil {
		return nil, err
	}

	return group, nil
}

// Delete deletes an IP group
func (s *IPGroupsService) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	group, exists := s.groups[id]
	if !exists {
		return fmt.Errorf("group with id '%s' not found", id)
	}

	// Delete from disk
	filePath := filepath.Join(IPGroupsDir, group.ID+".json")
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete group file: %w", err)
	}

	delete(s.groups, id)
	return nil
}

// ImportFromFile imports IPs/subnets from a file
func (s *IPGroupsService) ImportFromFile(name string, file io.Reader) (*IPGroup, error) {
	// Read file content
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	content := string(data)
	return s.Create(name, content)
}

// ExportToFile exports a group to a text file format
func (s *IPGroupsService) ExportToFile(id string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, exists := s.groups[id]
	if !exists {
		return "", fmt.Errorf("group with id '%s' not found", id)
	}

	var result strings.Builder
	result.WriteString("# IP Group: " + group.Name + "\n")
	result.WriteString("# Created: " + group.CreatedAt.String() + "\n")
	result.WriteString("# Updated: " + group.UpdatedAt.String() + "\n")
	result.WriteString("# Total entries: " + fmt.Sprintf("%d", group.Count) + "\n\n")

	if len(group.IPs) > 0 {
		result.WriteString("# Individual IPs\n")
		for _, ip := range group.IPs {
			result.WriteString(ip + "\n")
		}
		result.WriteString("\n")
	}

	if len(group.Subnets) > 0 {
		result.WriteString("# Subnets (CIDR)\n")
		for _, subnet := range group.Subnets {
			result.WriteString(subnet + "\n")
		}
		result.WriteString("\n")
	}

	if len(group.Invalid) > 0 {
		result.WriteString("# Invalid entries (not imported)\n")
		for _, invalid := range group.Invalid {
			result.WriteString("# " + invalid + "\n")
		}
	}

	return result.String(), nil
}

// GetGroupAsFirewallRules returns group IPs/subnets as a list for firewall rules
func (s *IPGroupsService) GetGroupAsFirewallRules(id string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	group, exists := s.groups[id]
	if !exists {
		return []string{}
	}

	result := make([]string, 0, len(group.IPs)+len(group.Subnets))
	result = append(result, group.IPs...)
	result = append(result, group.Subnets...)
	return result
}

// saveGroup saves a group to disk
func (s *IPGroupsService) saveGroup(group *IPGroup) error {
	filePath := filepath.Join(IPGroupsDir, group.ID+".json")

	data, err := json.MarshalIndent(group, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal group: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write group file: %w", err)
	}

	return nil
}

// Stats returns statistics about IP groups
func (s *IPGroupsService) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalIPs := 0
	totalSubnets := 0
	totalInvalid := 0

	for _, g := range s.groups {
		totalIPs += len(g.IPs)
		totalSubnets += len(g.Subnets)
		totalInvalid += len(g.Invalid)
	}

	return map[string]interface{}{
		"total_groups":  len(s.groups),
		"total_ips":     totalIPs,
		"total_subnets": totalSubnets,
		"total_invalid": totalInvalid,
	}
}
