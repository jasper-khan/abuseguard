package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "dev"

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
	case "allowlist-validate":
		runAllowlistValidate(args)
	case "allowlist-check":
		runAllowlistCheck(args)
	case "allowlist-export":
		runAllowlistExport(args)
	case "intel-export":
		runIntelExport(args)
	case "policy-apply":
		runPolicyApply(args)
	case "version", "-v", "--version":
		fmt.Println("abuseguard-engine " + version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	logf("subcommands: enqueue | report send-auto | sync-intel | allowlist-validate (--entry <IP/CIDR> | --file <path>) | allowlist-check --ip <IP> | allowlist-export [--file <path>] | intel-export | policy-apply (root, Linux) | version")
}

func mustConfig() *Config {
	c, err := loadConfig()
	if err != nil {
		fatalf("load config: %v", err)
	}
	return c
}

func runEnqueue(args []string) {
	fs := flag.NewFlagSet("enqueue", flag.ExitOnError)
	ip := fs.String("ip", "", "offending IP")
	profile := fs.String("profile", "", "profile (web-probe or ssh-bruteforce)")
	failures := fs.Int("failures", 0, "failure count")
	window := fs.String("window", "", "detection window")
	transport := fs.String("transport", "", "transport")
	port := fs.Int("port", 443, "target port")
	fs.Parse(args)
	if *ip == "" {
		fatalf("enqueue: --ip required")
	}
	os.Exit(cmdEnqueue(mustConfig(), reportItem{
		IP: *ip, Profile: *profile, Failures: *failures, Window: *window,
		Transport: *transport, Port: *port,
	}))
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

// runAllowlistExport emits the whitelist as canonical IP/CIDR lines for the
// root-native policy applier. --file previews a candidate whitelist
// transactionally; otherwise the configured whitelist is used. Validation
// covers the whole file before anything is written, so failures produce no
// partial stdout.
func runAllowlistExport(args []string) {
	fs := flag.NewFlagSet("allowlist-export", flag.ExitOnError)
	path := fs.String("file", "", "allowlist file (default: configured whitelist)")
	fs.Parse(args)
	if fs.NArg() != 0 {
		logf("allowlist-export: unexpected arguments")
		os.Exit(2)
	}
	if *path == "" {
		*path = mustConfig().AllowlistFile
	}
	data, err := formatAllowlist(*path)
	if err != nil {
		logf("allowlist-export: %v", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
		os.Exit(1)
	}
}

// runIntelExport emits validated canonical IPv4 lines for the root-native intel
// set. A missing intel.txt succeeds with empty output so root can bootstrap
// before the first sync; any existing invalid file fails with no output.
func runIntelExport(args []string) {
	fs := flag.NewFlagSet("intel-export", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 0 {
		logf("intel-export: unexpected arguments")
		os.Exit(2)
	}
	data, err := formatIntel(mustConfig())
	if err != nil {
		logf("intel-export: %v", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(data); err != nil {
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
