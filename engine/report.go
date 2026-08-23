package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type dedupeStore struct {
	Entries map[string]string `json:"entries"` // sha256(ip) -> RFC3339 timestamp
}

type dailyUsage struct {
	Day      string `json:"day"`
	Attempts int    `json:"attempts"`
}

func dedupePath(c *Config) string { return c.Paths.ReportsDir + "/.dedupe.json" }
func dailyPath(c *Config) string  { return c.Paths.ReportsDir + "/.daily-usage.json" }

func loadDedupe(c *Config) *dedupeStore {
	d := &dedupeStore{Entries: map[string]string{}}
	if b, err := os.ReadFile(dedupePath(c)); err == nil {
		json.Unmarshal(b, d)
		if d.Entries == nil {
			d.Entries = map[string]string{}
		}
	}
	return d
}

func loadDaily(c *Config) *dailyUsage {
	u := &dailyUsage{}
	if b, err := os.ReadFile(dailyPath(c)); err == nil {
		json.Unmarshal(b, u)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if u.Day != today {
		u.Day = today
		u.Attempts = 0
	}
	return u
}

func parseDurationDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	return def
}

// cmdReportSendAuto flushes the queue to AbuseIPDB with dedupe + daily cap.
func cmdReportSendAuto(c *Config) int {
	if !c.AbuseIPDB.Enabled {
		logf("report: reporting disabled; nothing sent")
		return 0
	}
	key := readKeyFile(c.AbuseIPDB.ReportKeyFile)
	if key == "" {
		logf("report: no API key configured; skipping (queue kept)")
		return 0
	}
	items, raw, err := readQueue(c)
	if err != nil {
		logf("report: read queue: %v", err)
		return 1
	}
	if len(items) == 0 {
		return 0
	}
	allow := loadAllowlist(c.AllowlistFile)
	dedupe := loadDedupe(c)
	daily := loadDaily(c)
	window := parseDurationDefault(c.AbuseIPDB.DedupeWindow, 15*time.Minute)
	dailyCap := c.AbuseIPDB.DailyReportCap
	if dailyCap <= 0 {
		dailyCap = 1000
	}
	now := time.Now().UTC()

	var remaining []string
	sent, skipped := 0, 0
	client := &http.Client{Timeout: 30 * time.Second}

	for idx, it := range items {
		if it.IP == "" {
			continue
		}
		if allow.Contains(it.IP) {
			skipped++
			continue // never report a whitelisted IP
		}
		k := hashKey(it.IP)
		if ts, ok := dedupe.Entries[k]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) < window {
				skipped++
				continue // within dedupe window
			}
		}
		if daily.Attempts >= dailyCap {
			remaining = append(remaining, raw[idx:]...)
			logf("report: daily cap %d reached; %d item(s) requeued", dailyCap, len(raw[idx:]))
			break
		}
		cats := c.AbuseIPDB.Categories[it.Profile]
		if cats == "" {
			cats = "21"
		}
		if err := sendReport(client, c.AbuseIPDB.ReportURL, key, it.IP, cats, buildComment(it), it.TS); err != nil {
			remaining = append(remaining, raw[idx:]...)
			logf("report: send failed for %s: %v; %d item(s) requeued", it.IP, err, len(raw[idx:]))
			break
		}
		dedupe.Entries[k] = now.Format(time.RFC3339)
		daily.Attempts++
		sent++
	}

	// prune dedupe entries older than 48h
	for k, ts := range dedupe.Entries {
		if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) > 48*time.Hour {
			delete(dedupe.Entries, k)
		}
	}

	writeQueue(c, remaining)
	saveJSON(dedupePath(c), dedupe, 0640)
	saveJSON(dailyPath(c), daily, 0640)
	logf("report: sent=%d skipped=%d requeued=%d (daily=%d/%d)", sent, skipped, len(remaining), daily.Attempts, dailyCap)
	return 0
}

func hashKey(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

// buildComment is privacy-safe: it never includes host, path, or headers.
func buildComment(it reportItem) string {
	switch it.Profile {
	case "web-probe":
		return "AbuseGuard: automated web probing / scanning for sensitive paths, detected behind a reverse proxy."
	case "web-rate":
		return "AbuseGuard: abusive HTTP request rate, detected behind a reverse proxy."
	default:
		return "AbuseGuard: abusive HTTP behaviour, detected behind a reverse proxy."
	}
}

func sendReport(client *http.Client, reportURL, key, ip, cats, comment, ts string) error {
	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", cats)
	form.Set("comment", comment)
	if ts != "" {
		form.Set("timestamp", ts)
	}
	req, err := http.NewRequest("POST", reportURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("rate limited (HTTP 429)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
