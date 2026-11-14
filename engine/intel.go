package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

// formatIntel returns canonical bare-IPv4 lines from intel.txt.
//
// The whole file is validated before returning so corrupt, empty, IPv6 or
// out-of-bounds stored data can never reach the kernel as a partial set. Only
// a missing file is treated as an empty list, which lets root bootstrap the
// native set before the first sync; the root applier keeps any existing set
// when an existing file fails validation.
func formatIntel(c *Config) ([]byte, error) {
	f, err := os.Open(intelTxtPath(c))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out strings.Builder
	seen := make(map[string]struct{})
	entries := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		ip := net.ParseIP(line)
		// Reject anything that is not the canonical dotted-quad form, including
		// IPv6, IPv4-mapped IPv6 and tokens with comments or whitespace.
		if ip == nil || ip.To4() == nil || ip.String() != line {
			return nil, fmt.Errorf("invalid intel entry %q", line)
		}
		entries++
		// Enforce the bound during the scan: a locally writable file must not
		// force unbounded allocation before the whole-file rejection at EOF.
		if c.Intel.MaxEntries > 0 && entries > c.Intel.MaxEntries {
			return nil, fmt.Errorf("intel list has %d entries (> max %d)", entries, c.Intel.MaxEntries)
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if entries == 0 {
		return nil, fmt.Errorf("intel list is empty")
	}
	if entries < c.Intel.MinEntries {
		return nil, fmt.Errorf("intel list has %d entries (< min %d)", entries, c.Intel.MinEntries)
	}
	return []byte(out.String()), nil
}

func httpGet(url, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "abuseguard-intel/1.0")
	useToken := token != "" && req.URL.Scheme == "https"
	if useToken {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	if useToken {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
				req.Header.Del("Authorization")
			}
			return nil
		}
	}
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

// warnStaleIntel logs a warning if the existing intel list is older than
// max_age. It never blocks the sync or refuses to use the list.
func warnStaleIntel(c *Config) {
	if c.Intel.MaxAge == "" {
		return
	}
	maxAge, err := time.ParseDuration(c.Intel.MaxAge)
	if err != nil || maxAge <= 0 {
		return
	}
	b, err := os.ReadFile(intelMetaPath(c))
	if err != nil {
		return
	}
	var meta intelMeta
	if json.Unmarshal(b, &meta) != nil || meta.GeneratedAt == "" {
		return
	}
	gen, err := time.Parse(time.RFC3339, meta.GeneratedAt)
	if err != nil {
		return
	}
	if age := time.Since(gen); age > maxAge {
		logf("sync-intel: WARNING: existing intel list is %s old (max_age %s); continuing with it",
			age.Round(time.Hour), c.Intel.MaxAge)
	}
}

// cmdSyncIntel refreshes intel.txt from the configured blocklist source.
func cmdSyncIntel(c *Config) int {
	warnStaleIntel(c)
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
	body, err := httpGet(src, "")
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
		// Store only the canonical dotted-quad form: intel-export rejects
		// anything else, so a non-canonical source spelling must never block
		// later native policy updates.
		out.WriteString(ip.String())
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
