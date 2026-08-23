package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// reportItem is one queued offender awaiting an AbuseIPDB report.
type reportItem struct {
	IP        string `json:"ip"`
	Profile   string `json:"profile"`
	Failures  int    `json:"failures"`
	Window    string `json:"window"`
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Mode      string `json:"mode"`
	TS        string `json:"ts"`
}

func queuePath(c *Config) string { return c.Paths.ReportsDir + "/queue.jsonl" }

// cmdEnqueue appends one offender to the report queue (called by the fail2ban action).
func cmdEnqueue(c *Config, it reportItem) int {
	if it.TS == "" {
		it.TS = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(c.Paths.ReportsDir, 0750); err != nil {
		logf("enqueue: mkdir reports dir: %v", err)
		return 1
	}
	line, _ := json.Marshal(it)
	line = append(line, '\n')
	f, err := os.OpenFile(queuePath(c), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		logf("enqueue: open queue: %v", err)
		return 1
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		logf("enqueue: write queue: %v", err)
		return 1
	}
	return 0
}

// readQueue returns the parsed items plus the raw JSONL lines (index-aligned).
func readQueue(c *Config) ([]reportItem, []string, error) {
	b, err := os.ReadFile(queuePath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	var items []reportItem
	var raw []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var it reportItem
		if err := json.Unmarshal([]byte(line), &it); err != nil {
			continue // skip malformed lines
		}
		items = append(items, it)
		raw = append(raw, line)
	}
	return items, raw, nil
}

// writeQueue replaces the queue file with rawLines (or removes it when empty).
func writeQueue(c *Config, rawLines []string) error {
	if len(rawLines) == 0 {
		os.Remove(queuePath(c))
		return nil
	}
	data := strings.Join(rawLines, "\n") + "\n"
	return writeFileAtomic(queuePath(c), []byte(data), 0640)
}
