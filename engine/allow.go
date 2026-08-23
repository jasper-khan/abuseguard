package main

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// Allowlist holds parsed single IPs and CIDR networks from the whitelist file.
type Allowlist struct {
	nets []*net.IPNet
	ips  []net.IP
}

// loadAllowlist parses the whitelist file. On any error it returns an empty
// allowlist (fail-safe: nothing is treated as whitelisted).
func loadAllowlist(path string) *Allowlist {
	a := &Allowlist{}
	f, err := os.Open(path)
	if err != nil {
		return a
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// strip trailing inline comment / annotation
		if i := strings.IndexAny(line, " \t#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			if _, n, err := net.ParseCIDR(line); err == nil {
				a.nets = append(a.nets, n)
			}
			continue
		}
		if ip := net.ParseIP(line); ip != nil {
			a.ips = append(a.ips, ip)
		}
	}
	return a
}

// Contains reports whether ipStr is covered by the allowlist.
func (a *Allowlist) Contains(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, x := range a.ips {
		if x.Equal(ip) {
			return true
		}
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
