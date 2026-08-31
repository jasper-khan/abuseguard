package main

import (
	"flag"
	"fmt"
	"os"
)

const version = "0.2.2"

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
	case "version", "-v", "--version":
		fmt.Println("abuseguard-engine " + version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	logf("subcommands: enqueue | report send-auto | sync-intel | intel-ignore --ip <ip> | unknown-ignore --ip <ip> | version")
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

func runEnqueue(args []string) {
	fs := flag.NewFlagSet("enqueue", flag.ExitOnError)
	ip := fs.String("ip", "", "offending IP")
	profile := fs.String("profile", "web-rate", "profile (web-rate|web-probe)")
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
	if loadAllowlist(c.AllowlistFile).Contains(*ip) {
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
	if loadAllowlist(c.AllowlistFile).Contains(*ip) {
		os.Exit(0) // whitelisted => ignore
	}
	os.Exit(1) // not whitelisted => proceed to ban
}
