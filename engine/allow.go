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
// the reporter stops without sending, while exports fail closed with no output.
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

// formatAllowlist returns canonical one-entry-per-line output for the
// whitelist. The whole file is parsed before returning, so a bad entry can
// never yield a partial policy. Entries are canonicalized with the same
// net.ParseIP/ParseCIDR semantics used by Contains: IPv4-mapped IPv6 collapses
// to IPv4, and CIDRs are masked, which never narrows what the parser matches.
func formatAllowlist(path string) ([]byte, error) {
	allow, err := loadAllowlist(path)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	seen := make(map[string]struct{}, len(allow.ips)+len(allow.nets))
	write := func(entry string) {
		if _, ok := seen[entry]; ok {
			return
		}
		seen[entry] = struct{}{}
		out.WriteString(entry)
		out.WriteByte('\n')
	}
	for _, ip := range allow.ips {
		write(ip.String())
	}
	for _, network := range allow.nets {
		write(network.String())
	}
	return []byte(out.String()), nil
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
