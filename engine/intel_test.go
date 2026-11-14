package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

const intelTestToken = "test-token"

func installIntelTestTransport(t *testing.T, servers ...*httptest.Server) {
	t.Helper()

	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	for _, server := range servers {
		roots.AddCert(server.Certificate())
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		t.Fatal("http.DefaultTransport is not *http.Transport")
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		http.DefaultTransport = previous
	})
}

func TestFormatIntelExportsCanonicalIPv4(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.txt")
	if err := os.WriteFile(path, []byte("192.0.2.1\n198.51.100.2\n192.0.2.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Config{}
	c.Paths.StateDir = dir
	c.Intel.MinEntries = 2
	c.Intel.MaxEntries = 10

	got, err := formatIntel(c)
	if err != nil {
		t.Fatalf("formatIntel returned error: %v", err)
	}
	want := "192.0.2.1\n198.51.100.2\n"
	if string(got) != want {
		t.Fatalf("formatIntel = %q; want %q", got, want)
	}
}

func TestFormatIntelMissingFileIsEmptySuccess(t *testing.T) {
	c := &Config{}
	c.Paths.StateDir = t.TempDir()
	c.Intel.MinEntries = 90000

	got, err := formatIntel(c)
	if err != nil {
		t.Fatalf("missing intel file returned error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("missing intel file returned %q; want empty output", got)
	}
}

func TestFormatIntelRejectsInvalidStoredData(t *testing.T) {
	tests := []struct {
		name string
		data string
		min  int
		max  int
	}{
		{name: "empty file", data: "", min: 0, max: 0},
		{name: "blank line", data: "192.0.2.1\n\n198.51.100.2\n", min: 1, max: 10},
		{name: "ipv6", data: "2001:db8::1\n", min: 1, max: 10},
		{name: "ipv4-mapped ipv6", data: "::ffff:192.0.2.1\n", min: 1, max: 10},
		{name: "comment", data: "# list\n192.0.2.1\n", min: 1, max: 10},
		{name: "trailing field", data: "192.0.2.1 # cn\n", min: 1, max: 10},
		{name: "leading space", data: " 192.0.2.1\n", min: 1, max: 10},
		{name: "undersized", data: "192.0.2.1\n", min: 2, max: 10},
		{name: "oversized", data: "192.0.2.1\n198.51.100.2\n", min: 1, max: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "intel.txt"), []byte(tt.data), 0600); err != nil {
				t.Fatal(err)
			}
			c := &Config{}
			c.Paths.StateDir = dir
			c.Intel.MinEntries = tt.min
			c.Intel.MaxEntries = tt.max

			got, err := formatIntel(c)
			if err == nil {
				t.Fatal("invalid stored intel was accepted")
			}
			if got != nil {
				t.Fatalf("invalid stored intel produced output %q", got)
			}
		})
	}
}

func TestResolveCommitSendsTokenToCommitAPI(t *testing.T) {
	apiAuth := make(chan string, 1)
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `[{"sha":"abc123"}]`)
	}))
	defer api.Close()
	installIntelTestTransport(t, api)

	var cfg Config
	cfg.Intel.SourceURL = "https://example.invalid/list/{commit}"
	cfg.Intel.CommitURL = api.URL

	sha, err := resolveCommit(&cfg, intelTestToken)
	if err != nil {
		t.Fatalf("resolveCommit returned error: %v", err)
	}
	if sha != "abc123" {
		t.Fatalf("resolveCommit returned sha %q, want %q", sha, "abc123")
	}
	select {
	case got := <-apiAuth:
		if got != "Bearer "+intelTestToken {
			t.Fatalf("commit API Authorization = %q, want %q", got, "Bearer "+intelTestToken)
		}
	default:
		t.Fatal("commit API request was not received")
	}
}

func TestCmdSyncIntelDoesNotSendTokenToSource(t *testing.T) {
	apiAuth := make(chan string, 1)
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `[{"sha":"abc123"}]`)
	}))
	defer api.Close()

	sourceAuth := make(chan string, 1)
	sourcePath := make(chan string, 1)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sourceAuth <- r.Header.Get("Authorization")
		sourcePath <- r.URL.Path
		_, _ = io.WriteString(w, "::ffff:192.0.2.1\n192.0.2.2 # country column\n")
	}))
	defer source.Close()
	installIntelTestTransport(t, api, source)

	var cfg Config
	cfg.Paths.StateDir = t.TempDir()
	cfg.Intel.CommitURL = api.URL
	cfg.Intel.SourceURL = source.URL + "/{commit}/list.txt"
	cfg.Intel.MinEntries = 1
	cfg.Intel.TokenFile = filepath.Join(cfg.Paths.StateDir, "token")
	if err := os.WriteFile(cfg.Intel.TokenFile, []byte(intelTestToken), 0600); err != nil {
		t.Fatal(err)
	}

	if code := cmdSyncIntel(&cfg); code != 0 {
		t.Fatalf("cmdSyncIntel returned %d, want 0", code)
	}

	select {
	case got := <-apiAuth:
		if got != "Bearer "+intelTestToken {
			t.Fatalf("commit API Authorization = %q, want %q", got, "Bearer "+intelTestToken)
		}
	default:
		t.Fatal("commit API request was not received")
	}
	select {
	case got := <-sourceAuth:
		if got != "" {
			t.Fatalf("source Authorization = %q, want empty", got)
		}
	default:
		t.Fatal("source request was not received")
	}
	select {
	case got := <-sourcePath:
		if got != "/abc123/list.txt" {
			t.Fatalf("source path = %q, want %q", got, "/abc123/list.txt")
		}
	default:
		t.Fatal("source request was not received")
	}

	stored, err := os.ReadFile(filepath.Join(cfg.Paths.StateDir, "intel.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != "192.0.2.1\n192.0.2.2\n" {
		t.Fatalf("stored intel = %q; want canonical IPv4 lines", stored)
	}
}

func TestHTTPGetDoesNotForwardTokenOnRedirect(t *testing.T) {
	targetAuth := make(chan string, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAuth <- r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	redirectAuth := make(chan string, 1)
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectAuth <- r.Header.Get("Authorization")
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	installIntelTestTransport(t, redirect, target)

	body, err := httpGet(redirect.URL, intelTestToken)
	if err != nil {
		t.Fatalf("httpGet returned error: %v", err)
	}
	if string(body) != "ok" {
		t.Fatalf("httpGet returned body %q, want %q", body, "ok")
	}
	select {
	case got := <-redirectAuth:
		if got != "Bearer "+intelTestToken {
			t.Fatalf("redirect request Authorization = %q, want %q", got, "Bearer "+intelTestToken)
		}
	default:
		t.Fatal("redirect request was not received")
	}
	select {
	case got := <-targetAuth:
		if got != "" {
			t.Fatalf("redirect target Authorization = %q, want empty", got)
		}
	default:
		t.Fatal("redirect target request was not received")
	}
}
