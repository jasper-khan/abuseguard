package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const version = "0.2.7"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "enqueue":
		runEnqueue(args)
	case "report":
		if len(args) >= 1 && args[0] == "send-auto" {
			os.Exit(cmdReportSendAuto(mustConfig()))
		}
		fatalf("usage: caddy-abuseguard report send-auto")
	case "sync-intel":
		os.Exit(cmdSyncIntel(mustConfig()))
	case "intel-ignore":
		runIntelIgnore(args)
	case "unknown-ignore":
		runUnknownIgnore(args)
	case "allowlist-validate":
		runAllowlistValidate(args)
	case "allowlist-check":
		runAllowlistCheck(args)
	case "version", "-v", "--version":
		fmt.Println("abuseguard-engine " + version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	logf("subcommands: enqueue | report send-auto | sync-intel | intel-ignore --ip <ip> | unknown-ignore --ip <ip> | allowlist-validate (--entry <IP/CIDR> | --file <path>) | allowlist-check --ip <IP> | version")
}

func mustConfig() *Config {
	c, err := loadConfig()
	if err != nil {
		fatalf("load config: %v", err)
	}
	return c
}

// ignoreSafeConfig loads the config for the ignorecommand paths ONLY.
// Those paths must fail SAFE: for fail2ban, exit 1 means "ban this IP", and the
// intel jail matches every request with maxretry=1 -- so a config error must
// never bubble up as exit 1, or an unreadable config would ban every visitor
// (the whitelist check happens after this point and could not save them).
// Any failure therefore exits 0 = "ignore this candidate": we skip one
// possible ban rather than risk banning everyone.
func ignoreSafeConfig() *Config {
	c, err := loadConfig()
	if err != nil {
		logf("ignore: load config failed (%v); ignoring this candidate to avoid a false ban", err)
		os.Exit(0)
	}
	return c
}

func ignoreSafeAllowlist(c *Config) *Allowlist {
	allow, err := loadAllowlist(c.AllowlistFile)
	if err != nil {
		logf("ignore: load allowlist failed (%v); ignoring this candidate to avoid a false ban", err)
		os.Exit(0)
	}
	return allow
}

func runEnqueue(args []string) {
	fs := flag.NewFlagSet("enqueue", flag.ExitOnError)
	ip := fs.String("ip", "", "offending IP")
	profile := fs.String("profile", "", "profile (web-probe or ssh-bruteforce)")
	failures := fs.Int("failures", 0, "failure count")
	window := fs.String("window", "", "detection window")
	transport := fs.String("transport", "", "transport")
	port := fs.Int("port", 443, "target port")
	mode := fs.String("mode", "auto", "mode")
	fs.Parse(args)
	if *ip == "" {
		fatalf("enqueue: --ip required")
	}
	os.Exit(cmdEnqueue(mustConfig(), reportItem{
		IP: *ip, Profile: *profile, Failures: *failures, Window: *window,
		Transport: *transport, Port: *port, Mode: *mode,
	}))
}

// runIntelIgnore is the fail2ban ignorecommand for the intel jail.
// Exit 0 => ignore (no ban); exit 1 => proceed to ban.
func runIntelIgnore(args []string) {
	fs := flag.NewFlagSet("intel-ignore", flag.ExitOnError)
	ip := fs.String("ip", "", "candidate IP")
	fs.Parse(args)
	if *ip == "" {
		os.Exit(0)
	}
	c := ignoreSafeConfig()
	if ignoreSafeAllowlist(c).Contains(*ip) {
		os.Exit(0) // whitelisted => ignore
	}
	if intelContains(c, *ip) {
		os.Exit(1) // on threat list => do NOT ignore (ban)
	}
	os.Exit(0) // not on threat list => ignore
}

// runUnknownIgnore is the fail2ban ignorecommand for the rate/probe jails.
// Exit 0 => ignore (whitelisted); exit 1 => proceed to ban.
func runUnknownIgnore(args []string) {
	fs := flag.NewFlagSet("unknown-ignore", flag.ExitOnError)
	ip := fs.String("ip", "", "candidate IP")
	fs.Parse(args)
	if *ip == "" {
		os.Exit(0)
	}
	c := ignoreSafeConfig()
	if ignoreSafeAllowlist(c).Contains(*ip) {
		os.Exit(0) // whitelisted => ignore
	}
	os.Exit(1) // not whitelisted => proceed to ban
}

func runAllowlistValidate(args []string) {
	fs := flag.NewFlagSet("allowlist-validate", flag.ExitOnError)
	entry := fs.String("entry", "", "one IP or CIDR entry")
	path := fs.String("file", "", "allowlist file")
	fs.Parse(args)
	if (*entry == "") == (*path == "") {
		logf("allowlist-validate: specify exactly one of --entry or --file")
		os.Exit(2)
	}
	var err error
	if *entry != "" {
		_, _, err = parseAllowlistEntry(*entry)
	} else {
		_, err = loadAllowlist(*path)
	}
	if err != nil {
		logf("allowlist-validate: %v", err)
		os.Exit(1)
	}
}

// runAllowlistCheck is used by the root control panel before a manual ban.
// Exit 0 means the IP is covered by the allowlist, 1 means it is not covered,
// and 2 means the input or allowlist could not be read reliably. The command
// accepts a single IP; the allowlist itself may contain IPs and CIDRs.
func runAllowlistCheck(args []string) {
	fs := flag.NewFlagSet("allowlist-check", flag.ExitOnError)
	ip := fs.String("ip", "", "IP address to check")
	fs.Parse(args)
	if *ip == "" || fs.NArg() != 0 {
		logf("allowlist-check: specify exactly one --ip <IP>")
		os.Exit(2)
	}
	c, err := loadConfig()
	if err != nil {
		logf("allowlist-check: load config: %v", err)
		os.Exit(2)
	}
	code := allowlistCheckCode(c.AllowlistFile, *ip)
	if code == 2 {
		logf("allowlist-check: invalid IP or unreadable/invalid allowlist")
	}
	os.Exit(code)
}

// allowlistCheckCode maps the allowlist-check contract to process exit codes.
func allowlistCheckCode(path, rawIP string) int {
	ip, network, err := parseAllowlistEntry(strings.TrimSpace(rawIP))
	if err != nil || network != nil {
		return 2
	}
	allow, err := loadAllowlist(path)
	if err != nil {
		return 2
	}
	if allow.Contains(ip.String()) {
		return 0
	}
	return 1
}
