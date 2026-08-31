package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowlistRejectsInvalidEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist")
	if err := os.WriteFile(path, []byte("192.0.2.1\nnot-an-ip\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAllowlist(path); err == nil {
		t.Fatal("invalid allowlist entry was accepted")
	}
}

func TestLoadAllowlistParsesCommentsAndCIDRs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist")
	data := "# trusted addresses\n192.0.2.1 # admin\n2001:db8::/32\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	allow, err := loadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		if !allow.Contains(ip) {
			t.Fatalf("allowlist does not contain %s", ip)
		}
	}
}
