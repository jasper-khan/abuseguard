package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type intelMeta struct {
	GeneratedAt  string `json:"generated_at"`
	SourceCommit string `json:"source_commit"`
	IPv4         int    `json:"ipv4"`
	IPv6         int    `json:"ipv6"`
	SHA256       string `json:"sha256"`
}

func intelTxtPath(c *Config) string  { return c.Paths.StateDir + "/intel.txt" }
func intelMetaPath(c *Config) string { return c.Paths.StateDir + "/intel-last-sync.txt" }

// loadIntelSet loads intel.txt into a set. A missing file yields an empty set,
// which makes the intel jail ignore everyone (fail-safe: no false bans).
func loadIntelSet(c *Config) map[string]struct{} {
	set := map[string]struct{}{}
	f, err := os.Open(intelTxtPath(c))
	if err != nil {
		return set
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}

func httpGet(url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "abuseguard-intel/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s -> HTTP %d", url, resp.StatusCode)
	}
	return body, nil
}

func resolveCommit(c *Config, token string) (string, error) {
	if !strings.Contains(c.Intel.SourceURL, "{commit}") || c.Intel.CommitURL == "" {
		return "", nil
	}
	body, err := httpGet(c.Intel.CommitURL, token)
	if err != nil {
		return "", err
	}
	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &commits); err == nil && len(commits) > 0 && commits[0].SHA != "" {
		return commits[0].SHA, nil
	}
	var one struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &one); err == nil && one.SHA != "" {
		return one.SHA, nil
	}
	return "", fmt.Errorf("could not parse commit sha from %s", c.Intel.CommitURL)
}

// cmdSyncIntel refreshes intel.txt from the configured blocklist source.
func cmdSyncIntel(c *Config) int {
	token := readKeyFile(c.Intel.TokenFile)
	commit, err := resolveCommit(c, token)
	if err != nil {
		logf("sync-intel: resolve commit failed: %v (keeping existing list)", err)
		return 0
	}
	src := c.Intel.SourceURL
	if commit != "" {
		src = strings.ReplaceAll(src, "{commit}", commit)
	}
	body, err := httpGet(src, token)
	if err != nil {
		logf("sync-intel: download failed: %v (keeping existing list)", err)
		return 0
	}
	var out strings.Builder
	count := 0
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i] // some lists append country/comment columns
		}
		ip := net.ParseIP(line)
		if ip == nil || ip.To4() == nil {
			continue
		}
		out.WriteString(line)
		out.WriteByte('\n')
		count++
	}
	if count < c.Intel.MinEntries {
		logf("sync-intel: only %d entries (< min %d); keeping existing list", count, c.Intel.MinEntries)
		return 0
	}
	if c.Intel.MaxEntries > 0 && count > c.Intel.MaxEntries {
		logf("sync-intel: %d entries (> max %d); refusing to load; keeping existing list", count, c.Intel.MaxEntries)
		return 0
	}
	data := []byte(out.String())
	sum := sha256.Sum256(data)
	if err := writeFileAtomic(intelTxtPath(c), data, 0640); err != nil {
		logf("sync-intel: write intel.txt failed: %v", err)
		return 1
	}
	meta := intelMeta{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		SourceCommit: commit,
		IPv4:         count,
		IPv6:         0,
		SHA256:       hex.EncodeToString(sum[:]),
	}
	saveJSON(intelMetaPath(c), meta, 0640)
	logf("sync-intel: loaded %d IPv4 entries (commit %s)", count, short(commit))
	return 0
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
