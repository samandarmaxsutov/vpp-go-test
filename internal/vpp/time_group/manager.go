package time_group

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Manager struct {
	mu                     sync.RWMutex
	timeGroups             map[string]*TimeGroup          // ID -> TimeGroup
	timeGroupAssignmentMap map[string][]string            // RuleType+RuleID -> []TimeGroupID
	ruleTimeAssignments    map[string]*RuleTimeAssignment // ID -> RuleTimeAssignment
	disabledRuleBackups    map[string]*DisabledRuleBackup // RuleType+RuleID -> Backup
	persistFilePath        string
}

// NewManager - Yangi Manager yaratadi
func NewManager(persistFilePath string) *Manager {
	m := &Manager{
		timeGroups:             make(map[string]*TimeGroup),
		ruleTimeAssignments:    make(map[string]*RuleTimeAssignment),
		timeGroupAssignmentMap: make(map[string][]string),
		disabledRuleBackups:    make(map[string]*DisabledRuleBackup),
		persistFilePath:        persistFilePath,
	}
	// Load from disk if exists
	_ = m.Load()
	return m
}

// CreateTimeGroup - Yangi vaqt grupp yaratadi
func (m *Manager) CreateTimeGroup(ctx context.Context, tg *TimeGroup) (*TimeGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tg.ID == "" {
		tg.ID = uuid.New().String()
	}

	if tg.Name == "" {
		return nil, fmt.Errorf("nomi bo'sh bo'lishi mumkin emas")
	}

	if _, exists := m.timeGroups[tg.ID]; exists {
		return nil, fmt.Errorf("vaqt grupp allaqachon mavjud: %s", tg.ID)
	}

	tg.CreatedAt = time.Now()
	tg.UpdatedAt = time.Now()
	tg.IsActive = true

	m.timeGroups[tg.ID] = tg

	// Persist to disk
	_ = m.saveLocked()

	return tg, nil
}

// UpdateTimeGroup - Vaqt gruppni yangilaydi
func (m *Manager) UpdateTimeGroup(ctx context.Context, tg *TimeGroup) (*TimeGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if tg.ID == "" {
		return nil, fmt.Errorf("ID bo'sh bo'lishi mumkin emas")
	}

	if _, exists := m.timeGroups[tg.ID]; !exists {
		return nil, fmt.Errorf("vaqt grupp topilmadi: %s", tg.ID)
	}

	tg.UpdatedAt = time.Now()
	m.timeGroups[tg.ID] = tg

	// Persist to disk
	_ = m.saveLocked()

	return tg, nil
}

// GetTimeGroup - Vaqt gruppni ID bo'yicha oladi
func (m *Manager) GetTimeGroup(ctx context.Context, id string) (*TimeGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tg, exists := m.timeGroups[id]
	if !exists {
		return nil, fmt.Errorf("vaqt grupp topilmadi: %s", id)
	}

	return tg, nil
}

// ListTimeGroups - Barcha vaqt grupplarini ro'yxatini qaytaradi
func (m *Manager) ListTimeGroups(ctx context.Context) ([]*TimeGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	groups := make([]*TimeGroup, 0, len(m.timeGroups))
	for _, tg := range m.timeGroups {
		groups = append(groups, tg)
	}

	return groups, nil
}

// DeleteTimeGroup - Vaqt gruppni o'chiradi
func (m *Manager) DeleteTimeGroup(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.timeGroups[id]; !exists {
		return fmt.Errorf("vaqt grupp topilmadi: %s", id)
	}

	// Remove all assignments for this time group
	keysToDelete := []string{}
	for key, assignments := range m.timeGroupAssignmentMap {
		newAssignments := []string{}
		for _, tgID := range assignments {
			if tgID != id {
				newAssignments = append(newAssignments, tgID)
			}
		}

		if len(newAssignments) == 0 {
			keysToDelete = append(keysToDelete, key)
		} else {
			m.timeGroupAssignmentMap[key] = newAssignments
		}
	}

	// Remove empty entries
	for _, key := range keysToDelete {
		delete(m.timeGroupAssignmentMap, key)
	}

	delete(m.timeGroups, id)

	// Persist to disk
	_ = m.saveLocked()

	return nil
}

// AssignTimeGroupToRule - Qoidaga vaqt gruppni tayinlaydi
func (m *Manager) AssignTimeGroupToRule(ctx context.Context, ruleType, ruleID, timeGroupID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Validate time group exists (if not empty)
	if timeGroupID != "" && timeGroupID != "always" {
		if _, exists := m.timeGroups[timeGroupID]; !exists {
			return fmt.Errorf("vaqt grupp topilmadi: %s", timeGroupID)
		}
	}

	key := ruleType + ":" + ruleID

	// Check if already assigned
	if assignments, exists := m.timeGroupAssignmentMap[key]; exists {
		for _, tgID := range assignments {
			if tgID == timeGroupID {
				return fmt.Errorf("bu qoida allaqachon tayinlandiQ: %s", timeGroupID)
			}
		}
	}

	m.timeGroupAssignmentMap[key] = append(m.timeGroupAssignmentMap[key], timeGroupID)

	// Persist to disk
	_ = m.saveLocked()

	return nil
}

// UnassignTimeGroupFromRule - Qoidadan vaqt gruppni olib tashaydi
func (m *Manager) UnassignTimeGroupFromRule(ctx context.Context, ruleType, ruleID, timeGroupID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := ruleType + ":" + ruleID

	assignments, exists := m.timeGroupAssignmentMap[key]
	if !exists {
		return fmt.Errorf("tayinlanish topilmadi: %s", key)
	}

	newAssignments := []string{}
	found := false
	for _, tgID := range assignments {
		if tgID != timeGroupID {
			newAssignments = append(newAssignments, tgID)
		} else {
			found = true
		}
	}

	if !found {
		return fmt.Errorf("vaqt grupp tayinlanmadi: %s", timeGroupID)
	}

	if len(newAssignments) == 0 {
		delete(m.timeGroupAssignmentMap, key)
	} else {
		m.timeGroupAssignmentMap[key] = newAssignments
	}

	// Persist to disk
	_ = m.saveLocked()

	return nil
}

// GetRuleTimeAssignments - Qoidaning vaqt tayinlanishlarini oladi
func (m *Manager) GetRuleTimeAssignments(ctx context.Context, ruleType, ruleID string) ([]*TimeGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := ruleType + ":" + ruleID

	assignments, exists := m.timeGroupAssignmentMap[key]
	if !exists {
		return []*TimeGroup{}, nil
	}

	groups := make([]*TimeGroup, 0, len(assignments))
	for _, tgID := range assignments {
		if tg, exists := m.timeGroups[tgID]; exists {
			groups = append(groups, tg)
		}
	}

	return groups, nil
}

// CheckIfRuleActive - Vaqtga asosan qoida faol ekanligini tekshiradi
func (m *Manager) CheckIfRuleActive(ctx context.Context, ruleType, ruleID string) (bool, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := ruleType + ":" + ruleID

	assignments, exists := m.timeGroupAssignmentMap[key]
	if !exists || len(assignments) == 0 {
		// No time restriction - always active
		return true, "vaqt cheklovi yo'q - har doim faol", nil
	}

	now := time.Now()
	currentTime := now.Format("15:04")
	currentDay := WeekdayMap[now.Weekday()]

	// Check each assigned time group
	for _, tgID := range assignments {
		if tgID == "always" {
			continue
		}

		tg, exists := m.timeGroups[tgID]
		if !exists {
			continue
		}

		if !tg.IsActive {
			continue
		}

		// Check if current day matches
		dayMatches := false
		for _, wd := range tg.Weekdays {
			if wd == currentDay {
				dayMatches = true
				break
			}
		}

		if !dayMatches {
			continue
		}

		// Check if current time is within range
		if currentTime >= tg.StartTime && currentTime <= tg.EndTime {
			return true, fmt.Sprintf("%s ichida faol (%s %s-%s)", tg.Name, currentDay, tg.StartTime, tg.EndTime), nil
		}
	}

	// Not within any active time group window
	return false, "hech bir vaqt oynasi ichida emas - o'chirildi", nil
}

// GetStatus - Vaqt grupp holatini oladi
func (m *Manager) GetStatus(ctx context.Context, tgID string) (*TimeCheck, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tg, exists := m.timeGroups[tgID]
	if !exists {
		return nil, fmt.Errorf("vaqt grupp topilmadi: %s", tgID)
	}

	now := time.Now()
	currentTime := now.Format("15:04")
	currentDay := now.Format("Monday")

	// Check if today is in weekdays and time is within range
	dayMatches := false
	for _, wd := range tg.Weekdays {
		if wd == WeekdayMap[now.Weekday()] {
			dayMatches = true
			break
		}
	}

	timeMatches := currentTime >= tg.StartTime && currentTime <= tg.EndTime
	isWithin := dayMatches && timeMatches

	message := ""
	if isWithin {
		message = fmt.Sprintf("Faol: %s ichida (%s %s-%s)", tg.Name, currentDay, tg.StartTime, tg.EndTime)
	} else {
		message = fmt.Sprintf("O'chirildi: %s ichida emas", tg.Name)
	}

	return &TimeCheck{
		IsWithinTimeWindow: isWithin,
		CurrentTime:        currentTime,
		CurrentDay:         currentDay,
		Message:            message,
	}, nil
}

// Save - Diskga saqlaydi
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.saveLocked()
}

func (m *Manager) saveLocked() error {
	data := map[string]interface{}{
		"time_groups":               m.timeGroups,
		"time_group_assignment_map": m.timeGroupAssignmentMap,
		"disabled_rule_backups":     m.disabledRuleBackups,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling xatosi: %v", err)
	}

	if err := os.WriteFile(m.persistFilePath, jsonData, 0644); err != nil {
		return fmt.Errorf("faylga yozish xatosi: %v", err)
	}

	return nil
}

// Load - Diskdan yuklaydi
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	jsonData, err := os.ReadFile(m.persistFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist yet, that's OK
			return nil
		}
		return fmt.Errorf("fayldan o'qish xatosi: %v", err)
	}

	data := map[string]interface{}{
		"time_groups":               map[string]*TimeGroup{},
		"time_group_assignment_map": map[string][]string{},
		"disabled_rule_backups":     map[string]*DisabledRuleBackup{},
	}

	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("JSON parsing xatosi: %v", err)
	}

	// Parse time groups
	if tgData, ok := data["time_groups"]; ok {
		tgBytes, _ := json.Marshal(tgData)
		_ = json.Unmarshal(tgBytes, &m.timeGroups)
	}

	// Parse assignment map
	if assignData, ok := data["time_group_assignment_map"]; ok {
		assignBytes, _ := json.Marshal(assignData)
		_ = json.Unmarshal(assignBytes, &m.timeGroupAssignmentMap)
	}

	// Parse disabled rule backups
	if backupData, ok := data["disabled_rule_backups"]; ok {
		backupBytes, _ := json.Marshal(backupData)
		_ = json.Unmarshal(backupBytes, &m.disabledRuleBackups)
	}

	return nil
}

// GetBackupData - Backup uchun ma'lumotlarni oladi
func (m *Manager) GetBackupData() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"time_groups":               m.timeGroups,
		"time_group_assignment_map": m.timeGroupAssignmentMap,
	}
}

// RestoreBackupData - Backup-dan restore qiladi
func (m *Manager) RestoreBackupData(data map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear current data
	m.timeGroups = make(map[string]*TimeGroup)
	m.timeGroupAssignmentMap = make(map[string][]string)

	// Restore time groups
	if tgData, ok := data["time_groups"]; ok {
		tgBytes, _ := json.Marshal(tgData)
		_ = json.Unmarshal(tgBytes, &m.timeGroups)
	}

	// Restore assignment map
	if assignData, ok := data["time_group_assignment_map"]; ok {
		assignBytes, _ := json.Marshal(assignData)
		_ = json.Unmarshal(assignBytes, &m.timeGroupAssignmentMap)
	}

	return m.saveLocked()
}

// SaveDisabledRuleBackup - O'chirilgan qoidaning backup-ini saqlaydi
func (m *Manager) SaveDisabledRuleBackup(backup *DisabledRuleBackup) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%s", backup.RuleType, backup.RuleID)
	backup.DisabledAt = time.Now()
	m.disabledRuleBackups[key] = backup

	return m.saveLocked()
}

// GetDisabledRuleBackup - O'chirilgan qoidaning backup-ini oladi
func (m *Manager) GetDisabledRuleBackup(ruleType, ruleID string) (*DisabledRuleBackup, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", ruleType, ruleID)
	backup, exists := m.disabledRuleBackups[key]
	return backup, exists
}

// RemoveDisabledRuleBackup - Backup-ni o'chiradi (qoida qayta faollashgandan keyin)
func (m *Manager) RemoveDisabledRuleBackup(ruleType, ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%s:%s", ruleType, ruleID)
	delete(m.disabledRuleBackups, key)

	return m.saveLocked()
}

// ListDisabledRuleBackups - Barcha o'chirilgan qoidalarning ro'yxatini qaytaradi
func (m *Manager) ListDisabledRuleBackups() map[string]*DisabledRuleBackup {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*DisabledRuleBackup)
	for k, v := range m.disabledRuleBackups {
		result[k] = v
	}
	return result
}
