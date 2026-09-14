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

func parseAllowlistEntry(value string) (net.IP, *net.IPNet, error) {
	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR %q", value)
		}
		return nil, network, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid IP %q", value)
	}
	return ip, nil, nil
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
		ip, network, err := parseAllowlistEntry(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if network != nil {
			a.nets = append(a.nets, network)
		} else {
			a.ips = append(a.ips, ip)
		}
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
