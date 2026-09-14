package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAllowlistRejectsInvalidEntry(t *testing.T) {
	for _, entry := range []string{
		"not-an-ip",
		"999.1.2.3",
		"192.0.2.1/33",
		"2001:db8::/129",
	} {
		t.Run(entry, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "whitelist")
			if err := os.WriteFile(path, []byte("192.0.2.1\n"+entry+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAllowlist(path); err == nil {
				t.Fatal("invalid allowlist entry was accepted")
			}
		})
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

func TestAllowlistCheckExitCodes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist")
	if err := os.WriteFile(path, []byte("192.0.2.1\n2001:db8::/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		ip   string
		want int
	}{
		{name: "single IP hit", ip: "192.0.2.1", want: 0},
		{name: "CIDR hit", ip: "2001:db8::10", want: 0},
		{name: "overlapping CIDR hit", ip: "192.0.2.0/24", want: 0},
		{name: "nested CIDR hit", ip: "2001:db8:1::/48", want: 0},
		{name: "valid miss", ip: "198.51.100.1", want: 1},
		{name: "non-overlapping CIDR miss", ip: "198.51.100.0/24", want: 1},
		{name: "invalid input rejected", ip: "not-an-ip", want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowlistCheckCode(path, tt.ip); got != tt.want {
				t.Fatalf("allowlistCheckCode(%q) = %d; want %d", tt.ip, got, tt.want)
			}
		})
	}
	if got := allowlistCheckCode(filepath.Join(t.TempDir(), "missing"), "198.51.100.1"); got != 2 {
		t.Fatalf("unreadable allowlist returned %d; want 2", got)
	}
	invalidPath := filepath.Join(t.TempDir(), "whitelist")
	if err := os.WriteFile(invalidPath, []byte("not-an-ip\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := allowlistCheckCode(invalidPath, "198.51.100.1"); got != 2 {
		t.Fatalf("invalid allowlist returned %d; want 2", got)
	}
}
