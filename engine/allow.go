package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// Allowlist holds parsed single IPs and CIDR networks from the whitelist file.
type Allowlist struct {
	nets []*net.IPNet
	ips  []net.IP
}

// loadAllowlist parses the whitelist file. Callers decide how to fail safe:
// ignore commands skip a ban, while the reporter stops without sending.
func loadAllowlist(path string) (*Allowlist, error) {
	a := &Allowlist{}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
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
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid CIDR %q", lineNo, line)
			}
			a.nets = append(a.nets, n)
			continue
		}
		ip := net.ParseIP(line)
		if ip == nil {
			return nil, fmt.Errorf("line %d: invalid IP %q", lineNo, line)
		}
		a.ips = append(a.ips, ip)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return a, nil
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
