package main

import (
	"encoding/json"
	"os"
	"strings"
)

const defaultConfigPath = "/etc/caddy-abuseguard/config.json"

// Config mirrors /etc/caddy-abuseguard/config.json.
type Config struct {
	AllowlistFile string `json:"allowlist_file"`
	Paths         struct {
		StateDir   string `json:"state_dir"`
		ReportsDir string `json:"reports_dir"`
	} `json:"paths"`
	Intel struct {
		SourceURL  string `json:"source_url"`
		CommitURL  string `json:"commit_url"`
		TokenFile  string `json:"token_file"`
		MinEntries int    `json:"min_entries"`
		MaxEntries int    `json:"max_entries"`
		MaxAge     string `json:"max_age"` // advisory; reserved
	} `json:"intel"`
	AbuseIPDB struct {
		Enabled        bool   `json:"enabled"`
		ReportURL      string `json:"report_url"`
		ReportKeyFile  string `json:"report_key_file"`
		DailyReportCap int    `json:"daily_report_cap"`
		DedupeWindow   string `json:"dedupe_window"`
	} `json:"abuseipdb"`
}

func configPath() string {
	if p := os.Getenv("ABUSEGUARD_CONFIG"); p != "" {
		return p
	}
	return defaultConfigPath
}

func loadConfig() (*Config, error) {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if c.Paths.StateDir == "" {
		c.Paths.StateDir = "/var/lib/caddy-abuseguard"
	}
	if c.Paths.ReportsDir == "" {
		c.Paths.ReportsDir = c.Paths.StateDir + "/reports"
	}
	if c.AllowlistFile == "" {
		c.AllowlistFile = "/etc/caddy-abuseguard/whitelist"
	}
	return &c, nil
}

// readKeyFile returns the trimmed contents of a key file, or "" if missing/empty.
func readKeyFile(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
