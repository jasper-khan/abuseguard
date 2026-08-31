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
func processingQueuePath(c *Config) string {
	return c.Paths.ReportsDir + "/queue.processing.jsonl"
}
func queueLockPath(c *Config) string  { return c.Paths.ReportsDir + "/.queue.lock" }
func reportLockPath(c *Config) string { return c.Paths.ReportsDir + "/.report.lock" }

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
	lock, err := acquireFileLock(queueLockPath(c))
	if err != nil {
		logf("enqueue: lock queue: %v", err)
		return 1
	}
	defer lock.Close()
	f, err := os.OpenFile(queuePath(c), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		logf("enqueue: open queue: %v", err)
		return 1
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		logf("enqueue: write queue: %v", err)
		return 1
	}
	if err := f.Close(); err != nil {
		logf("enqueue: close queue: %v", err)
		return 1
	}
	return 0
}

// rotateQueue atomically detaches the current queue for one reporter. New
// enqueues immediately continue in a fresh queue.jsonl. A batch left by a
// crashed reporter is resumed before a new batch is rotated.
func rotateQueue(c *Config) (string, error) {
	lock, err := acquireFileLock(queueLockPath(c))
	if err != nil {
		return "", err
	}
	defer lock.Close()

	processing := processingQueuePath(c)
	if _, err := os.Stat(processing); err == nil {
		return processing, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(queuePath(c), processing); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return processing, nil
}

// readQueueFile returns parsed items plus raw JSONL lines (index-aligned).
func readQueueFile(path string) ([]reportItem, []string, error) {
	b, err := os.ReadFile(path)
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

// writeQueueFile replaces path with rawLines (or removes it when empty).
func writeQueueFile(path string, rawLines []string) error {
	if len(rawLines) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	data := strings.Join(rawLines, "\n") + "\n"
	return writeFileAtomic(path, []byte(data), 0640)
}
