package web

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type LogHandler struct{}

var vppRegex = regexp.MustCompile(`^\[(.*?)\]\s+vpp\[\d+\]:\s+(.*)$`)

func (h *LogHandler) GetLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "system")
	// wd, _ := os.Getwd()

	var filePath string

	if logType == "acl" {
		defaultACLPath := "/etc/sarhad-guard/acl_logs/acl_logs.log"

		if p := strings.TrimSpace(c.Query("path")); p != "" {
			filePath = p
		} else if p := strings.TrimSpace(os.Getenv("SARHAD_ACL_LOG_PATH")); p != "" {
		
			filePath = p
		} else {
			filePath = defaultACLPath
		}
	} else if logType == "config" {
		filePath = "/etc/sarhad-guard/conf_logs/conf_logs.log"
	} else if logType == "auth" {
		filePath = "/etc/sarhad-guard/auth_logs/auth_logs.log"
	} else if logType == "url" {
		currentDate := time.Now().Format("02_01_2006")
		filePath = filepath.Join("/etc/sarhad-guard/url_logs", fmt.Sprintf("urls_%s.log", currentDate))
	} 
	// else {
	// 	filePath = filepath.Join(wd, fmt.Sprintf("%s_logs.jsonl", logType))
	// }

	file, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusOK, []interface{}{})
		return
	}
	defer file.Close()

	var logs []interface{}

	if logType == "acl" {
		logs = parseACLFile(file)
	} else {
		// JSONL (system/auth/etc)
		scanner := bufio.NewScanner(file)
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var logEntry interface{}
			if err := json.Unmarshal([]byte(line), &logEntry); err == nil {
				logs = append(logs, logEntry)
			}
		}
	}

	// Reverse (newest first)
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	c.JSON(http.StatusOK, logs)
}

func parseACLFile(file *os.File) []interface{} {
	// We need to peek the first non-empty line to detect CSV vs old VPP format.
	// Use a scanner to find it, then rewind.
	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	firstNonEmpty := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			firstNonEmpty = line
			break
		}
	}

	// rewind to start for actual parsing
	_, _ = file.Seek(0, 0)

	if strings.HasPrefix(firstNonEmpty, "ts,") {
		return parseACLCSV(file)
	}

	// fallback: old VPP syslog style
	return parseACLVppSyslog(file)
}

func parseACLCSV(file *os.File) []interface{} {
	r := csv.NewReader(file)
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true

	records, err := r.ReadAll()
	if err != nil || len(records) == 0 {
		return []interface{}{}
	}

	// header -> index map
	header := records[0]
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}

	get := func(row []string, key string) string {
		i, ok := idx[key]
		if !ok || i < 0 || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var logs []interface{}
	for _, row := range records[1:] {
		if len(row) == 0 {
			continue
		}

		ts := get(row, "ts")
		if ts == "" {
			continue
		}

		// pack EVERYTHING except ts into raw string (target)
		// keep it readable, but still "raw"
		raw := fmt.Sprintf(
			"is_ip6=%s proto=%s sport=%s dport=%s sw_if_index=%s fib_index=%s acl_index=%s rule_index=%s action=%s src=%s dst=%s count=%s",
			get(row, "is_ip6"),
			get(row, "proto"),
			get(row, "sport"),
			get(row, "dport"),
			get(row, "sw_if_index"),
			get(row, "fib_index"),
			get(row, "acl_index"),
			get(row, "rule_index"),
			get(row, "action"),
			get(row, "src"),
			get(row, "dst"),
			get(row, "count"),
		)

		logs = append(logs, map[string]interface{}{
			"timestamp": ts,
			"type":      "acl",
			"action":    "DROP",
			"target":    raw,
			"status":    "SUCCESS",
		})
	}

	return logs
}

func parseACLVppSyslog(file *os.File) []interface{} {
	var logs []interface{}

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := vppRegex.FindStringSubmatch(line)
		if len(matches) <= 2 {
			continue
		}

		timestamp := matches[1]
		rawMessage := matches[2] // "acl_plugin: ACL_DROP: ..."

		cleanMsg := strings.TrimPrefix(rawMessage, "acl_plugin: ")

		action := "DROP"
		target := cleanMsg
		target = strings.TrimPrefix(target, "ACL_DROP: ")
		target = strings.TrimPrefix(target, "Dropped Pkt Details: ")

		logs = append(logs, map[string]interface{}{
			"timestamp": timestamp,
			"type":      "ACL",
			"action":    action,
			"target":    target,
			"status":    "SUCCESS",
		})
	}

	return logs
}

func parseIntSafe(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}