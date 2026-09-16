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
		_, _ = io.WriteString(w, "192.0.2.1\n")
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
