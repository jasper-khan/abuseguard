package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConcurrentEnqueueSurvivesReportFlush(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	keyFile := filepath.Join(dir, "key")
	allowlistFile := filepath.Join(dir, "whitelist")
	if err := os.WriteFile(keyFile, []byte("test-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(allowlistFile, nil, 0600); err != nil {
		t.Fatal(err)
	}

	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-releaseRequest
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := &Config{AllowlistFile: allowlistFile}
	c.Paths.StateDir = dir
	c.Paths.ReportsDir = reportsDir
	c.AbuseIPDB.Enabled = true
	c.AbuseIPDB.ReportURL = server.URL
	c.AbuseIPDB.ReportKeyFile = keyFile
	c.AbuseIPDB.DailyReportCap = 1000
	c.AbuseIPDB.DedupeWindow = "15m"
	c.AbuseIPDB.Categories = map[string]string{"web-rate": "4,21"}

	if rc := cmdEnqueue(c, reportItem{IP: "192.0.2.1", Profile: "web-rate"}); rc != 0 {
		t.Fatalf("first enqueue returned %d", rc)
	}
	reportDone := make(chan int, 1)
	go func() { reportDone <- cmdReportSendAuto(c) }()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("report did not reach test endpoint")
	}
	if rc := cmdEnqueue(c, reportItem{IP: "192.0.2.2", Profile: "web-rate"}); rc != 0 {
		close(releaseRequest)
		t.Fatalf("concurrent enqueue returned %d", rc)
	}
	close(releaseRequest)

	select {
	case rc := <-reportDone:
		if rc != 0 {
			t.Fatalf("report returned %d", rc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("report did not finish")
	}

	items, _, err := readQueueFile(queuePath(c))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].IP != "192.0.2.2" {
		t.Fatalf("new queue = %#v; want only concurrent item", items)
	}
	if _, err := os.Stat(processingQueuePath(c)); !os.IsNotExist(err) {
		t.Fatalf("processing batch still exists: %v", err)
	}
}
