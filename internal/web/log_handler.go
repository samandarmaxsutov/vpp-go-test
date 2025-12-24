package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"github.com/gin-gonic/gin"
)

type LogHandler struct{}

func (h *LogHandler) GetLogs(c *gin.Context) {
	// URL'dan log turini olish (default: system)
	logType := c.DefaultQuery("type", "system")
	fileName := fmt.Sprintf("%s_logs.jsonl", logType)

	file, err := os.Open(fileName)
	if err != nil {
		// Agar fayl topilmasa, bo'sh massiv qaytaramiz
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer file.Close()

	var logs []interface{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var log interface{}
		if err := json.Unmarshal(scanner.Bytes(), &log); err == nil {
			logs = append(logs, log)
		}
	}

	// Oxirgi loglarni tepaga chiqarish (Reverse)
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	c.JSON(http.StatusOK, logs)
}