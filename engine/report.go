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

func loadDedupe(c *Config) (*dedupeStore, error) {
	d := &dedupeStore{Entries: map[string]string{}}
	b, err := os.ReadFile(dedupePath(c))
	if err != nil {
		if os.IsNotExist(err) {
			return d, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, d); err != nil {
		return nil, err
	}
	if d.Entries == nil {
		d.Entries = map[string]string{}
	}
	for _, ts := range d.Entries {
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			return nil, fmt.Errorf("invalid dedupe timestamp %q", ts)
		}
	}
	return d, nil
}

func loadDaily(c *Config) (*dailyUsage, error) {
	u := &dailyUsage{}
	b, err := os.ReadFile(dailyPath(c))
	if err == nil {
		if err := json.Unmarshal(b, u); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if u.Day != "" {
		if _, err := time.Parse("2006-01-02", u.Day); err != nil {
			return nil, fmt.Errorf("invalid daily usage day %q", u.Day)
		}
	}
	if u.Attempts < 0 {
		return nil, fmt.Errorf("invalid daily usage attempts %d", u.Attempts)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if u.Day != today {
		u.Day = today
		u.Attempts = 0
	}
	return u, nil
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
	if err := os.MkdirAll(c.Paths.ReportsDir, 0750); err != nil {
		logf("report: mkdir reports dir: %v", err)
		return 1
	}
	reportLock, err := acquireFileLock(reportLockPath(c))
	if err != nil {
		logf("report: lock reporter: %v", err)
		return 1
	}
	defer reportLock.Close()

	batch, err := rotateQueue(c)
	if err != nil {
		logf("report: rotate queue: %v", err)
		return 1
	}
	if batch == "" {
		return 0
	}
	items, raw, malformed, err := readQueueFile(batch)
	if err != nil {
		logf("report: read queue: %v", err)
		return 1
	}
	if len(items) == 0 {
		if err := writeQueueFile(batch, nil); err != nil {
			logf("report: remove empty queue batch: %v", err)
			return 1
		}
		if malformed > 0 {
			return 1
		}
		return 0
	}
	allow, err := loadAllowlist(c.AllowlistFile)
	if err != nil {
		logf("report: load allowlist: %v; nothing sent", err)
		return 1
	}
	dedupe, err := loadDedupe(c)
	if err != nil {
		logf("report: load dedupe state: %v; nothing sent", err)
		return 1
	}
	daily, err := loadDaily(c)
	if err != nil {
		logf("report: load daily usage: %v; nothing sent", err)
		return 1
	}
	window := parseDurationDefault(c.AbuseIPDB.DedupeWindow, 15*time.Minute)
	dailyCap := c.AbuseIPDB.DailyReportCap
	if dailyCap <= 0 {
		dailyCap = 1000
	}
	now := time.Now().UTC()

	var remaining []string
	sent, skipped, deferred, dropped := 0, 0, 0, 0
	hadError := malformed > 0
	client := &http.Client{Timeout: 30 * time.Second}

reportLoop:
	for idx, it := range items {
		if !isReportableIP(it.IP) {
			logf("report: invalid or non-public IP %q discarded", it.IP)
			dropped++
			hadError = true
			continue
		}
		cats, comment, err := reportDetails(it)
		if err != nil {
			logf("report: invalid queued item for %s discarded: %v", it.IP, err)
			dropped++
			hadError = true
			continue
		}
		if allow.Contains(it.IP) {
			skipped++
			continue // never report a whitelisted IP
		}
		k := hashKey(it.IP)
		if ts, ok := dedupe.Entries[k]; ok {
			if t, err := time.Parse(time.RFC3339, ts); err == nil && now.Sub(t) < window {
				remaining = append(remaining, raw[idx])
				deferred++
				continue // AbuseIPDB accepts the same IP again after the window
			}
		}
		if daily.Attempts >= dailyCap {
			remaining = append(remaining, raw[idx:]...)
			logf("report: daily cap %d reached; %d item(s) requeued", dailyCap, len(raw[idx:]))
			break reportLoop
		}
		status, err := sendReport(client, c.AbuseIPDB.ReportURL, key, it.IP, cats, comment, it.TS)
		if err != nil {
			remaining = append(remaining, raw[idx:]...)
			logf("report: send failed for %s: %v; %d item(s) requeued", it.IP, err, len(raw[idx:]))
			hadError = true
			break reportLoop
		}
		if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
			logf("report: AbuseIPDB rejected %s with HTTP %d; record discarded", it.IP, status)
			dropped++
			hadError = true
			continue
		}
		if status < 200 || status >= 300 {
			remaining = append(remaining, raw[idx:]...)
			logf("report: AbuseIPDB returned HTTP %d for %s; %d item(s) requeued", status, it.IP, len(raw[idx:]))
			hadError = true
			break reportLoop
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

	if err := writeQueueFile(batch, remaining); err != nil {
		logf("report: save queue batch: %v", err)
		return 1
	}
	if err := saveJSON(dedupePath(c), dedupe, 0640); err != nil {
		logf("report: save dedupe state: %v", err)
		return 1
	}
	if err := saveJSON(dailyPath(c), daily, 0640); err != nil {
		logf("report: save daily usage: %v", err)
		return 1
	}
	logf("report: sent=%d skipped=%d deferred=%d dropped=%d requeued=%d (daily=%d/%d)", sent, skipped, deferred, dropped, len(remaining), daily.Attempts, dailyCap)
	if hadError {
		return 1
	}
	return 0
}

func hashKey(ip string) string {
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:])
}

func reportWindowLabel(raw string) (string, error) {
	window := strings.TrimSpace(raw)
	d, err := time.ParseDuration(window)
	if err != nil {
		// Fail2Ban also accepts plain integer seconds for findtime.
		d, err = time.ParseDuration(window + "s")
	}
	if err != nil || d <= 0 {
		return "", fmt.Errorf("invalid detection window %q", raw)
	}
	for _, unit := range []struct {
		duration time.Duration
		name     string
	}{
		{time.Hour, "hour"},
		{time.Minute, "minute"},
		{time.Second, "second"},
	} {
		if d%unit.duration == 0 {
			n := int64(d / unit.duration)
			name := unit.name
			if n != 1 {
				name += "s"
			}
			return fmt.Sprintf("%d %s", n, name), nil
		}
	}
	return d.String(), nil
}

// reportDetails keeps each supported profile, category, and privacy-safe
// reason in one closed map. Categories and comments are never caller supplied.
func reportDetails(it reportItem) (string, string, error) {
	if it.Profile != "web-probe" && it.Profile != "ssh-bruteforce" {
		return "", "", fmt.Errorf("unsupported profile %q", it.Profile)
	}
	if it.Failures <= 0 {
		return "", "", fmt.Errorf("invalid failure count %d", it.Failures)
	}
	window, err := reportWindowLabel(it.Window)
	if err != nil {
		return "", "", err
	}
	transport := strings.TrimSpace(it.Transport)
	switch it.Profile {
	case "web-probe":
		switch transport {
		case "HTTP/1.1":
		case "HTTP/2", "HTTP/2.0":
			transport = "HTTP/2"
		default:
			return "", "", fmt.Errorf("unsupported transport %q for profile %q", it.Transport, it.Profile)
		}
		comment := fmt.Sprintf(
			"Repeated probing of common sensitive web application paths: %d requests within %s over %s.",
			it.Failures, window, transport,
		)
		return "21", comment, nil
	case "ssh-bruteforce":
		if transport != "SSH" {
			return "", "", fmt.Errorf("unsupported transport %q for profile %q", it.Transport, it.Profile)
		}
		comment := fmt.Sprintf(
			"Repeated SSH authentication failures: %d failed attempts within %s.",
			it.Failures, window,
		)
		return "18,22", comment, nil
	}
	return "", "", fmt.Errorf("unsupported profile %q", it.Profile)
}

func sendReport(client *http.Client, reportURL, key, ip, cats, comment, ts string) (int, error) {
	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", cats)
	form.Set("comment", comment)
	if ts != "" {
		form.Set("timestamp", ts)
	}
	req, err := http.NewRequest("POST", reportURL, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Key", key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, nil
}
