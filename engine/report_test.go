package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func validSSHBruteForce(ip string) reportItem {
	return reportItem{
		IP: ip, Profile: "ssh-bruteforce", Failures: 5, Window: "600", Transport: "SSH",
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

func TestReportDetails(t *testing.T) {
	tests := []struct {
		name       string
		item       reportItem
		categories string
		comment    string
	}{
		{
			name:       "HTTP/1.1 web probe",
			item:       validProbe("192.0.2.10"),
			categories: "21",
			comment:    "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/1.1.",
		},
		{
			name: "HTTP/2 web probe",
			item: reportItem{
				IP: "192.0.2.10", Profile: "web-probe", Failures: 5, Window: "10m", Transport: "HTTP/2.0",
			},
			categories: "21",
			comment:    "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/2.",
		},
		{
			name:       "SSH brute force",
			item:       validSSHBruteForce("192.0.2.10"),
			categories: "18,22",
			comment:    "Repeated SSH authentication failures: 5 failed attempts within 10 minutes.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			categories, comment, err := reportDetails(tt.item)
			if err != nil {
				t.Fatal(err)
			}
			if categories != tt.categories {
				t.Fatalf("categories = %q; want %q", categories, tt.categories)
			}
			if comment != tt.comment {
				t.Fatalf("comment = %q; want %q", comment, tt.comment)
			}
			for _, private := range []string{
				"abuseguard", "192.0.2.10", ".env", ".git", "phpmyadmin",
				"username", "host=", "uri=", "header=", "authorization", "cookie",
			} {
				if strings.Contains(strings.ToLower(comment), private) {
					t.Fatalf("comment contains private detail %q", private)
				}
			}
		})
	}
}

func TestReportDetailsRejectsInvalidEvidence(t *testing.T) {
	tests := []struct {
		name string
		item reportItem
	}{
		{name: "unsupported profile", item: reportItem{Profile: "web-rate", Failures: 120, Window: "60s", Transport: "HTTP/1.1"}},
		{name: "zero failures", item: reportItem{Profile: "web-probe", Failures: 0, Window: "10m", Transport: "HTTP/1.1"}},
		{name: "zero window", item: reportItem{Profile: "web-probe", Failures: 5, Window: "0", Transport: "HTTP/1.1"}},
		{name: "invalid window", item: reportItem{Profile: "web-probe", Failures: 5, Window: "ten minutes", Transport: "HTTP/1.1"}},
		{name: "unsupported HTTP transport", item: reportItem{Profile: "web-probe", Failures: 5, Window: "10m", Transport: "HTTP/3.0"}},
		{name: "unsupported SSH transport", item: reportItem{Profile: "ssh-bruteforce", Failures: 5, Window: "600", Transport: "HTTP/1.1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := reportDetails(tt.item); err == nil {
				t.Fatal("reportDetails accepted invalid evidence")
			}
		})
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

func TestReporterPersistsConfirmedProgressBeforeNextRequest(t *testing.T) {
	env := newReportTestEnv(t)
	firstIP := "192.0.2.10"
	secondIP := "192.0.2.11"
	for _, ip := range []string{firstIP, secondIP} {
		if rc := cmdEnqueue(env.c, validProbe(ip)); rc != 0 {
			t.Fatalf("enqueue %s returned %d", ip, rc)
		}
	}

	secondStarted := make(chan struct{})
	releaseSecond := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(releaseSecond) })
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusOK)
		case 2:
			close(secondStarted)
			<-releaseSecond
			panic(http.ErrAbortHandler)
		default:
			t.Error("unexpected extra request")
		}
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL

	reportDone := make(chan int, 1)
	go func() { reportDone <- cmdReportSendAuto(env.c) }()
	select {
	case <-secondStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("reporter did not start the second request")
	}

	items, _, malformed, err := readQueueFile(processingQueuePath(env.c))
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 0 || len(items) != 1 || items[0].IP != secondIP {
		t.Fatalf("durable queue=%v malformed=%d; want only %s", items, malformed, secondIP)
	}
	dedupe, err := loadDedupe(env.c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := dedupe.Entries[hashKey(firstIP)]; !ok {
		t.Fatal("confirmed first report was not persisted in dedupe state")
	}
	daily, err := loadDaily(env.c)
	if err != nil {
		t.Fatal(err)
	}
	if daily.Attempts != 1 {
		t.Fatalf("daily attempts=%d; want 1", daily.Attempts)
	}

	releaseOnce.Do(func() { close(releaseSecond) })
	select {
	case rc := <-reportDone:
		if rc == 0 {
			t.Fatal("reporter hid the uncertain second response")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reporter did not stop after the uncertain response")
	}

	var retried []string
	retryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse retry form: %v", err)
		}
		retried = append(retried, r.Form.Get("ip"))
		w.WriteHeader(http.StatusOK)
	}))
	defer retryServer.Close()
	env.c.AbuseIPDB.ReportURL = retryServer.URL
	if rc := cmdReportSendAuto(env.c); rc != 0 {
		t.Fatalf("retry reporter returned %d", rc)
	}
	if len(retried) != 1 || retried[0] != secondIP {
		t.Fatalf("retried IPs=%v; want only %s", retried, secondIP)
	}
}

func TestReporterRecoversCheckpointBeforeSending(t *testing.T) {
	env := newReportTestEnv(t)
	firstIP := "192.0.2.10"
	secondIP := "192.0.2.11"
	for _, ip := range []string{firstIP, secondIP} {
		if rc := cmdEnqueue(env.c, validProbe(ip)); rc != 0 {
			t.Fatalf("enqueue %s returned %d", ip, rc)
		}
	}
	batch, err := rotateQueue(env.c)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, malformed, err := readQueueFile(batch)
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 0 || len(raw) != 2 {
		t.Fatalf("initial batch lines=%d malformed=%d; want 2,0", len(raw), malformed)
	}
	now := time.Now().UTC()
	checkpoint := &reportCheckpoint{
		Version:   reportCheckpointVersion,
		Remaining: raw[1:],
		Dedupe: dedupeStore{Entries: map[string]string{
			hashKey(firstIP): now.Format(time.RFC3339),
		}},
		Daily: dailyUsage{Day: now.Format("2006-01-02"), Attempts: 1},
	}
	if err := saveJSON(checkpointPath(env.c), checkpoint, 0640); err != nil {
		t.Fatal(err)
	}

	var reported []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		reported = append(reported, r.Form.Get("ip"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL
	if rc := cmdReportSendAuto(env.c); rc != 0 {
		t.Fatalf("reporter returned %d", rc)
	}
	if len(reported) != 1 || reported[0] != secondIP {
		t.Fatalf("reported IPs=%v; want only %s", reported, secondIP)
	}
	if _, err := os.Stat(checkpointPath(env.c)); !os.IsNotExist(err) {
		t.Fatalf("checkpoint still exists: %v", err)
	}
	daily, err := loadDaily(env.c)
	if err != nil {
		t.Fatal(err)
	}
	if daily.Attempts != 2 {
		t.Fatalf("daily attempts=%d; want 2", daily.Attempts)
	}
}

func TestReporterStopsOnInvalidCheckpoint(t *testing.T) {
	env := newReportTestEnv(t)
	if rc := cmdEnqueue(env.c, validProbe("192.0.2.10")); rc != 0 {
		t.Fatalf("enqueue returned %d", rc)
	}
	if err := os.WriteFile(checkpointPath(env.c), []byte(`{"version":1}`), 0600); err != nil {
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
		t.Fatal("reporter accepted an invalid checkpoint")
	}
	if calls.Load() != 0 {
		t.Fatalf("API calls=%d; want 0", calls.Load())
	}
	items, _, malformed, err := readQueueFile(queuePath(env.c))
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 0 || len(items) != 1 {
		t.Fatalf("original queue items=%d malformed=%d; want 1,0", len(items), malformed)
	}
	if _, err := os.Stat(checkpointPath(env.c)); err != nil {
		t.Fatalf("invalid checkpoint was not retained: %v", err)
	}
}

func TestReporterDefersSecondProfileForSameIP(t *testing.T) {
	env := newReportTestEnv(t)
	ip := "192.0.2.10"
	if rc := cmdEnqueue(env.c, validProbe(ip)); rc != 0 {
		t.Fatalf("web probe enqueue returned %d", rc)
	}
	if rc := cmdEnqueue(env.c, validSSHBruteForce(ip)); rc != 0 {
		t.Fatalf("SSH enqueue returned %d", rc)
	}

	reports := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		reports <- r.Form.Get("categories") + "|" + r.Form.Get("comment")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	env.c.AbuseIPDB.ReportURL = server.URL

	if rc := cmdReportSendAuto(env.c); rc != 0 {
		t.Fatalf("first reporter run returned %d", rc)
	}
	if got := <-reports; got != "21|Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/1.1." {
		t.Fatalf("first report = %q", got)
	}
	items, _, malformed, err := readQueueFile(processingQueuePath(env.c))
	if err != nil {
		t.Fatal(err)
	}
	if malformed != 0 || len(items) != 1 || items[0].Profile != "ssh-bruteforce" {
		t.Fatalf("deferred items=%v malformed=%d; want one SSH item", items, malformed)
	}

	dedupe := &dedupeStore{Entries: map[string]string{
		hashKey(ip): time.Now().UTC().Add(-16 * time.Minute).Format(time.RFC3339),
	}}
	if err := saveJSON(dedupePath(env.c), dedupe, 0640); err != nil {
		t.Fatal(err)
	}
	if rc := cmdReportSendAuto(env.c); rc != 0 {
		t.Fatalf("second reporter run returned %d", rc)
	}
	if got := <-reports; got != "18,22|Repeated SSH authentication failures: 5 failed attempts within 10 minutes." {
		t.Fatalf("second report = %q", got)
	}
	if _, err := os.Stat(processingQueuePath(env.c)); !os.IsNotExist(err) {
		t.Fatalf("processing queue still exists: %v", err)
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
