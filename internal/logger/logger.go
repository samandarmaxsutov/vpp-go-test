package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Log turlari uchun konstantalar (xato qilmaslik uchun)
const (
	TypeWeb    = "web"
	TypeACL    = "acl"
	TypeAuth   = "auth"
	TypeConfig = "config"
)

type ActionLog struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	IP        string `json:"ip,omitempty"` // Added IP
	Type      string `json:"type"`         // Log turi: vpp, web, acl, auth
	Action    string `json:"action"`
	Target    string `json:"target"`
	Details   string `json:"details,omitempty"` // Added Details for config changes
	Status    string `json:"status"`
}

// LogAction endi logTurini (logType) ham qabul qiladi
func LogAction(logType, action, target, status string) {
	logEntry := ActionLog{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		User:      "Administrator",
		Type:      logType,
		Action:    action,
		Target:    target,
		Status:    status,
	}

	// 1. Terminalga chiroyli chiqarish
	fmt.Printf("[LOG-%s] %s | %s -> %s\n", logType, action, target, status)

	// 2. Umumiy log faylga yozish
	// saveToFile("system_logs.jsonl", logEntry)

	// 3. Alohida kategoriya fayliga yozish (vpp.jsonl, web.jsonl va h.k.)
	specificFileName := fmt.Sprintf("%s_logs.jsonl", logType)
	saveToFile(specificFileName, logEntry)
}

// LogConfigChange logs configuration changes to /etc/sarhad-guard/conf_logs/conf_logs.log
func LogConfigChange(user, ip, action, target, details string) {
	logEntry := ActionLog{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		User:      user,
		IP:        ip,
		Type:      TypeConfig,
		Action:    action,
		Target:    target,
		Details:   details,
		Status:    "SUCCESS",
	}

	// 1. Terminal output
	fmt.Printf("[CONFIG] %s | %s (%s) -> %s: %s\n", action, user, ip, target, details)

	// 2. Write to specific config log file
	logDir := "/etc/sarhad-guard/conf_logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creating config log dir: %v\n", err)
	}

	filePath := filepath.Join(logDir, "conf_logs.log")
	saveToFile(filePath, logEntry)

	// 3. Also write to system logs for aggregation
	// saveToFile("system_logs.jsonl", logEntry)
}

// LogAuth logs authentication events to /etc/sarhad-guard/auth_logs/auth_logs.log
func LogAuth(user, ip, action, status string) {
	logEntry := ActionLog{
		Timestamp: time.Now().Format("2006-01-02 15:04:05"),
		User:      user,
		IP:        ip,
		Type:      TypeAuth,
		Action:    action,
		Target:    "System",
		Status:    status,
	}

	fmt.Printf("[AUTH] %s | %s (%s) -> %s\n", action, user, ip, status)

	logDir := "/etc/sarhad-guard/auth_logs"
	_ = os.MkdirAll(logDir, 0755)
	filePath := filepath.Join(logDir, "auth_logs.log")
	saveToFile(filePath, logEntry)
	// saveToFile("system_logs.jsonl", logEntry)
}

func saveToFile(fileName string, entry ActionLog) {
	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Fayl ochishda xato: %v\n", err)
		return
	}
	defer f.Close()

	jsonBytes, _ := json.Marshal(entry)
	f.Write(jsonBytes)
	f.Write([]byte("\n"))
}
