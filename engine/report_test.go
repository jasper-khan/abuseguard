package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type reportTestEnv struct {
	c             *Config
	keyFile       string
	allowlistFile string
}

func newReportTestEnv(t *testing.T) *reportTestEnv {
	t.Helper()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	allowlistFile := filepath.Join(dir, "whitelist")
	if err := os.WriteFile(keyFile, []byte("test-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := &Config{AllowlistFile: allowlistFile}
	c.Paths.StateDir = dir
	c.Paths.ReportsDir = filepath.Join(dir, "reports")
	c.AbuseIPDB.Enabled = true
	c.AbuseIPDB.ReportKeyFile = keyFile
	c.AbuseIPDB.DailyReportCap = 1000
	c.AbuseIPDB.DedupeWindow = "15m"
	return &reportTestEnv{c: c, keyFile: keyFile, allowlistFile: allowlistFile}
}

func validProbe(ip string) reportItem {
	return reportItem{
		IP: ip, Profile: "web-probe", Failures: 5, Window: "10m", Transport: "HTTP/1.1",
	}
}

func requireNoQueue(t *testing.T, c *Config) {
	t.Helper()
	if _, err := os.Stat(queuePath(c)); !os.IsNotExist(err) {
		t.Fatalf("queue exists or stat failed: %v", err)
	}
}

func TestEnqueueSkipsWhenReportingUnavailable(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, *reportTestEnv)
	}{
		{
			name: "disabled",
			setup: func(_ *testing.T, env *reportTestEnv) {
				env.c.AbuseIPDB.Enabled = false
			},
		},
		{
			name: "missing key",
			setup: func(t *testing.T, env *reportTestEnv) {
				if err := os.WriteFile(env.keyFile, nil, 0600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newReportTestEnv(t)
			tt.setup(t, env)
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
				t.Fatalf("enqueue returned %d", rc)
			}
			requireNoQueue(t, env.c)
		})
	}
}

func TestEnqueueRejectsInvalidReportData(t *testing.T) {
	tests := []struct {
		name string
		item reportItem
	}{
		{name: "unsupported profile", item: reportItem{IP: "192.0.2.10", Profile: "web-rate", Failures: 120, Window: "60s", Transport: "HTTP"}},
		{name: "invalid IP", item: validProbe("not-an-ip")},
		{name: "private IP", item: validProbe("10.0.0.1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newReportTestEnv(t)
			if rc := cmdEnqueue(env.c, tt.item); rc == 0 {
				t.Fatal("enqueue accepted invalid report data")
			}
			requireNoQueue(t, env.c)
		})
	}
}

func TestReportDetailsWebProbe(t *testing.T) {
	categories, comment, err := reportDetails(validProbe("192.0.2.10"))
	if err != nil {
		t.Fatal(err)
	}
	if categories != "21" {
		t.Fatalf("categories = %q; want 21", categories)
	}
	want := "AbuseGuard observed 5 HTTP/1.1 requests within 10m to common sensitive web-application paths."
	if comment != want {
		t.Fatalf("comment = %q; want %q", comment, want)
	}
	for _, private := range []string{"192.0.2.10", "host", "uri", "header"} {
		if strings.Contains(strings.ToLower(comment), private) {
			t.Fatalf("comment contains private detail %q", private)
		}
	}
}

func TestReporterStopsWhenAllowlistCannotBeRead(t *testing.T) {
	env := newReportTestEnv(t)
	if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
		t.Fatalf("enqueue returned %d", rc)
	}
	if err := os.Remove(env.allowlistFile); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL

	if rc := cmdReportSendAuto(env.c); rc == 0 {
		t.Fatal("reporter succeeded with an unreadable allowlist")
	}
	if calls.Load() != 0 {
		t.Fatalf("API calls = %d; want 0", calls.Load())
	}
	if _, err := os.Stat(processingQueuePath(env.c)); err != nil {
		t.Fatalf("processing queue was not retained: %v", err)
	}
}

func TestReporterNeverSendsWhitelistedIP(t *testing.T) {
	env := newReportTestEnv(t)
	if err := os.WriteFile(env.allowlistFile, []byte("192.0.2.10 # trusted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
		t.Fatalf("enqueue returned %d", rc)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL

	if rc := cmdReportSendAuto(env.c); rc != 0 {
		t.Fatalf("reporter returned %d", rc)
	}
	if calls.Load() != 0 {
		t.Fatalf("API calls = %d; want 0", calls.Load())
	}
	if _, err := os.Stat(processingQueuePath(env.c)); !os.IsNotExist(err) {
		t.Fatalf("processing queue still exists: %v", err)
	}
}

func TestReporterStopsOnCorruptState(t *testing.T) {
	tests := []struct {
		name string
		path func(*Config) string
	}{
		{name: "dedupe", path: dedupePath},
		{name: "daily usage", path: dailyPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := newReportTestEnv(t)
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
				t.Fatalf("enqueue returned %d", rc)
			}
			if err := os.WriteFile(tt.path(env.c), []byte("{"), 0600); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			env.c.AbuseIPDB.ReportURL = server.URL

			if rc := cmdReportSendAuto(env.c); rc == 0 {
				t.Fatal("reporter succeeded with corrupt state")
			}
			if calls.Load() != 0 {
				t.Fatalf("API calls = %d; want 0", calls.Load())
			}
			if _, err := os.Stat(processingQueuePath(env.c)); err != nil {
				t.Fatalf("processing queue was not retained: %v", err)
			}
		})
	}
}

func TestReporterReturnsFailureWhenStateCannotBeSaved(t *testing.T) {
	for _, statePath := range []struct {
		name string
		path func(*Config) string
	}{
		{name: "dedupe", path: dedupePath},
		{name: "daily usage", path: dailyPath},
	} {
		t.Run(statePath.name, func(t *testing.T) {
			env := newReportTestEnv(t)
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
				t.Fatalf("enqueue returned %d", rc)
			}
			setupDone := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				setupDone <- os.Mkdir(statePath.path(env.c), 0700)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			env.c.AbuseIPDB.ReportURL = server.URL

			if rc := cmdReportSendAuto(env.c); rc == 0 {
				t.Fatal("reporter hid a state save failure")
			}
			if err := <-setupDone; err != nil {
				t.Fatalf("prepare state save failure: %v", err)
			}
		})
	}
}

func TestReporterDropsRecordErrorsAndContinues(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			env := newReportTestEnv(t)
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
				t.Fatalf("first enqueue returned %d", rc)
			}
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.11")); rc != 0 {
				t.Fatalf("second enqueue returned %d", rc)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse form: %v", err)
				}
				if r.Form.Get("categories") != "21" {
					t.Errorf("categories = %q; want 21", r.Form.Get("categories"))
				}
				if call == 1 {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			env.c.AbuseIPDB.ReportURL = server.URL

			if rc := cmdReportSendAuto(env.c); rc == 0 {
				t.Fatal("reporter hid a permanent record error")
			}
			if calls.Load() != 2 {
				t.Fatalf("API calls = %d; want 2", calls.Load())
			}
			if _, err := os.Stat(processingQueuePath(env.c)); !os.IsNotExist(err) {
				t.Fatalf("processing queue still exists: %v", err)
			}
		})
	}
}

func TestReporterRequeuesRetryableErrors(t *testing.T) {
	for _, status := range []int{
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			env := newReportTestEnv(t)
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
				t.Fatalf("first enqueue returned %d", rc)
			}
			if rc := cmdEnqueue(env.c, validProbe("192.0.2.11")); rc != 0 {
				t.Fatalf("second enqueue returned %d", rc)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(status)
			}))
			defer server.Close()
			env.c.AbuseIPDB.ReportURL = server.URL

			if rc := cmdReportSendAuto(env.c); rc == 0 {
				t.Fatal("reporter hid a retryable error")
			}
			if calls.Load() != 1 {
				t.Fatalf("API calls = %d; want 1", calls.Load())
			}
			items, _, malformed, err := readQueueFile(processingQueuePath(env.c))
			if err != nil {
				t.Fatal(err)
			}
			if malformed != 0 || len(items) != 2 {
				t.Fatalf("requeued items=%d malformed=%d; want 2,0", len(items), malformed)
			}
		})
	}
}

func TestReporterLogsAndDropsMalformedQueueLine(t *testing.T) {
	env := newReportTestEnv(t)
	if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
		t.Fatalf("enqueue returned %d", rc)
	}
	valid, err := os.ReadFile(queuePath(env.c))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queuePath(env.c), append([]byte("not-json\n"), valid...), 0640); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL

	if rc := cmdReportSendAuto(env.c); rc == 0 {
		t.Fatal("reporter hid a malformed queue line")
	}
	if calls.Load() != 1 {
		t.Fatalf("API calls = %d; want 1", calls.Load())
	}
	if _, err := os.Stat(processingQueuePath(env.c)); !os.IsNotExist(err) {
		t.Fatalf("processing queue still exists: %v", err)
	}
}
