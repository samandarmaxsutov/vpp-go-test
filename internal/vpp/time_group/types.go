package time_group

import (
	"time"
)

// TimeGroup - Vaqt grupp konfiguratsiyasi
type TimeGroup struct {
	ID          string    `json:"id"`          // UUID
	Name        string    `json:"name"`        // "working_hours", "lunch_time" va shunga o'xshash
	Description string    `json:"description"` // Optional description
	StartTime   string    `json:"start_time"`  // Format: "09:00" (HH:MM)
	EndTime     string    `json:"end_time"`    // Format: "18:00" (HH:MM)
	Weekdays    []string  `json:"weekdays"`    // ["M", "T", "W", "TH", "F", "SA", "SU"]
	IsActive    bool      `json:"is_active"`   // Vaqt grupp faol yoki yo'q
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RuleTimeAssignment - Qoidaga vaqt tayinlanishi
type RuleTimeAssignment struct {
	ID           string    `json:"id"`            // UUID
	RuleType     string    `json:"rule_type"`     // "ACL", "ABF", "POLICER"
	RuleID       string    `json:"rule_id"`       // ACL index, ABF policy ID, Policer name
	TimeGroupID  string    `json:"time_group_id"` // TimeGroup ID (bo'sh bo'lsa "always")
	IsEnabled    bool      `json:"is_enabled"`    // Hozirgi vaqtda qoida faol
	LastModified time.Time `json:"last_modified"`
}

// DisabledRuleBackup - O'chirilgan qoidaning backup konfiguratsiyasi (qayta yoqish uchun)
type DisabledRuleBackup struct {
	RuleType      string                 `json:"rule_type"`     // "ACL", "POLICER"
	RuleID        string                 `json:"rule_id"`       // Qoida identifikatori
	Configuration map[string]interface{} `json:"configuration"` // To'liq qoida konfiguratsiyasi
	Interfaces    []InterfaceBinding     `json:"interfaces"`    // Interface bindings
	DisabledAt    time.Time              `json:"disabled_at"`   // O'chirilgan vaqt
	TimeGroupID   string                 `json:"time_group_id"` // Qaysi vaqt guruhi uchun
	LastActive    bool                   `json:"last_active"`   // Oxirgi holat (truechi)
}

// InterfaceBinding - Interface bog'lanish ma'lumotlari
type InterfaceBinding struct {
	InterfaceName string `json:"interface_name"` // Interface nomi
	SwIfIndex     uint32 `json:"sw_if_index"`    // Interface index
	Direction     string `json:"direction"`      // "input" yoki "output"
}

// PendingACLRule - VPP ga hali push qilinmagan ACL qoidasi (vaqt guruhi tashqarisida yaratilgan)
type PendingACLRule struct {
	ID          string                   `json:"id"`            // Unique ID
	Tag         string                   `json:"tag"`           // ACL tag/name
	Rules       []map[string]interface{} `json:"rules"`         // ACL rules in JSON format
	TimeGroupID string                   `json:"time_group_id"` // Assigned time group
	CreatedAt   string                   `json:"created_at"`    // When rule was created
	IsStateful  bool                     `json:"is_stateful"`   // Stateful ACL
}

// TimeCheck - Hozirgi vaqtda qoida faol ekanligini tekshirish natijasi
type TimeCheck struct {
	IsWithinTimeWindow bool   `json:"is_within_time_window"`
	CurrentTime        string `json:"current_time"` // Format: "14:30"
	CurrentDay         string `json:"current_day"`  // "Monday", "Tuesday", etc.
	Message            string `json:"message"`
}

// Weekday constants
const (
	Monday    = "M"
	Tuesday   = "T"
	Wednesday = "W"
	Thursday  = "TH"
	Friday    = "F"
	Saturday  = "SA"
	Sunday    = "SU"
)

// AllWeekdays - Barcha haftaning kunlari
var AllWeekdays = []string{Monday, Tuesday, Wednesday, Thursday, Friday, Saturday, Sunday}

// WeekdayMap - Go weekday-ni string-ga
var WeekdayMap = map[time.Weekday]string{
	time.Monday:    Monday,
	time.Tuesday:   Tuesday,
	time.Wednesday: Wednesday,
	time.Thursday:  Thursday,
	time.Friday:    Friday,
	time.Saturday:  Saturday,
	time.Sunday:    Sunday,
}

// ReverseWeekdayMap - String-ni Go weekday-ga
var ReverseWeekdayMap = map[string]time.Weekday{
	Monday:    time.Monday,
	Tuesday:   time.Tuesday,
	Wednesday: time.Wednesday,
	Thursday:  time.Thursday,
	Friday:    time.Friday,
	Saturday:  time.Saturday,
	Sunday:    time.Sunday,
}
