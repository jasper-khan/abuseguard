package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestFormatAllowlistCanonicalizesWithoutNarrowing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist")
	data := strings.Join([]string{
		"# trusted addresses",
		"192.0.2.1 # admin",
		"192.0.2.1",
		"::ffff:192.0.2.1",
		"::ffff:192.0.2.9",
		"::ffff:198.51.100.7",
		"198.51.100.5/24",
		"::ffff:203.0.113.77/120",
		"2001:db8::1/32",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	exported, err := formatAllowlist(path)
	if err != nil {
		t.Fatalf("formatAllowlist returned error: %v", err)
	}
	want := "192.0.2.1\n192.0.2.9\n198.51.100.7\n198.51.100.0/24\n203.0.113.0/24\n2001:db8::/32\n"
	if string(exported) != want {
		t.Fatalf("formatAllowlist = %q; want %q", exported, want)
	}

	roundPath := filepath.Join(dir, "exported")
	if err := os.WriteFile(roundPath, exported, 0600); err != nil {
		t.Fatal(err)
	}
	original, err := loadAllowlist(path)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := loadAllowlist(roundPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		ip   string
		want bool
	}{
		{ip: "192.0.2.1", want: true},
		{ip: "::ffff:192.0.2.1", want: true},
		{ip: "192.0.2.2", want: false},
		{ip: "192.0.2.9", want: true},
		{ip: "::ffff:192.0.2.9", want: true},
		{ip: "198.51.100.7", want: true},
		{ip: "::ffff:198.51.100.7", want: true},
		{ip: "198.51.100.255", want: true},
		{ip: "198.51.101.1", want: false},
		{ip: "203.0.113.5", want: true},
		{ip: "::ffff:203.0.113.5", want: true},
		{ip: "2001:db8:1::1", want: true},
		{ip: "2001:db9::1", want: false},
	} {
		if got := original.Contains(tt.ip); got != tt.want {
			t.Fatalf("original allowlist Contains(%q) = %v; want %v", tt.ip, got, tt.want)
		}
		if got := roundTrip.Contains(tt.ip); got != original.Contains(tt.ip) {
			t.Fatalf("exported allowlist Contains(%q) = %v; want %v", tt.ip, got, original.Contains(tt.ip))
		}
	}
}

func TestFormatAllowlistRejectsInvalidWithoutOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist")
	if err := os.WriteFile(path, []byte("192.0.2.1\n999.1.2.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := formatAllowlist(path)
	if err == nil {
		t.Fatal("invalid allowlist was accepted")
	}
	if data != nil {
		t.Fatalf("invalid allowlist produced output %q", data)
	}
	if _, err := formatAllowlist(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing allowlist was accepted")
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
		{name: "IPv4 CIDR target rejected", ip: "192.0.2.0/24", want: 2},
		{name: "IPv6 CIDR target rejected", ip: "2001:db8:1::/48", want: 2},
		{name: "valid miss", ip: "198.51.100.1", want: 1},
		{name: "non-overlapping CIDR rejected", ip: "198.51.100.0/24", want: 2},
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
