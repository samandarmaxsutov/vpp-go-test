package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Log turlari uchun konstantalar (xato qilmaslik uchun)
const (
	TypeVPP  = "vpp"
	TypeWeb  = "web"
	TypeACL  = "acl"
	TypeAuth = "auth"
)

type ActionLog struct {
	Timestamp string `json:"timestamp"`
	User      string `json:"user"`
	Type      string `json:"type"`   // Log turi: vpp, web, acl, auth
	Action    string `json:"action"`
	Target    string `json:"target"`
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
	saveToFile("system_logs.jsonl", logEntry)

	// 3. Alohida kategoriya fayliga yozish (vpp.jsonl, web.jsonl va h.k.)
	specificFileName := fmt.Sprintf("%s_logs.jsonl", logType)
	saveToFile(specificFileName, logEntry)
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