package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"regexp"
	"strings"
)

type LogHandler struct{}


// Global regex to parse VPP log lines: [timestamp] process: message
var vppRegex = regexp.MustCompile(`^\[(.*?)\]\s+vpp\[\d+\]:\s+(.*)$`)

func (h *LogHandler) GetLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "system")
	wd, _ := os.Getwd()
	
	var filePath string
	if logType == "acl" {
		filePath = filepath.Join(wd, "logs", "acl.log")
	} else {
		filePath = filepath.Join(wd, fmt.Sprintf("%s_logs.jsonl", logType))
	}

	file, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer file.Close()

	var logs []interface{}
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024) 

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" { continue }

		var logEntry interface{}
		// 1. JSON handling (System/Auth)
		if err := json.Unmarshal([]byte(line), &logEntry); err == nil {
			logs = append(logs, logEntry)
		} else if logType == "acl" {
			// 2. Optimized ACL Parsing
			matches := vppRegex.FindStringSubmatch(line)
			if len(matches) > 2 {
				timestamp := matches[1] 
				rawMessage := matches[2] // e.g., "acl_plugin: ACL_DROP: interface:1..."
				
				// Remove "acl_plugin: " prefix
				cleanMsg := strings.TrimPrefix(rawMessage, "acl_plugin: ")
				
				// Determine Action and Target
				// We set "DROP" as the Action (Harakat) per your request
				action := "DROP"
				target := cleanMsg

				// If the line starts with ACL_DROP or Dropped Pkt, we clean the target further
				target = strings.TrimPrefix(target, "ACL_DROP: ")
				target = strings.TrimPrefix(target, "Dropped Pkt Details: ")

				logs = append(logs, map[string]interface{}{
					"timestamp": timestamp,
					"type":      "ACL",
					"action":    action,    // Shown in "Harakat" column
					"target":    target,    // Shown in "Obyekt" column
					"status":    "SUCCESS", // Shown in "Holat" column (renders green)
				})
			}
		}
	}

	// Reverse (Newest first)
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	c.JSON(http.StatusOK, logs)
}