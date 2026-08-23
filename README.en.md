# AbuseGuard

**English** | [简体中文](README.md)

AbuseGuard is a drop-in abuse-mitigation layer for a [Caddy](https://caddyserver.com/) reverse proxy on Debian/Ubuntu. It bans abusive and known-malicious IPs at the firewall (nftables) and can optionally auto-report them to [AbuseIPDB](https://www.abuseipdb.com/) — driven by fail2ban plus a small Go engine.

One command installs a hardened Caddy (with the `caddy-dns/cloudflare` TLS module), the fail2ban jails, a threat-intel sync, the optional reporter, and an interactive `abuseguard` panel.

## How it works

```
visitor ─▶ Caddy (protected site: `import abuseguard`)
             │  writes a privacy-trimmed JSON access log
             ▼
         fail2ban ──(matches)──▶ nftables DROP :80/:443   ← the ban
             │
             └─(rate/probe)─▶ engine enqueue ─▶ report queue ──(timer)──▶ AbuseIPDB
```

- Caddy tags each request to a protected site and logs only what fail2ban needs (client IP, protocol, tags) — no paths, hosts, headers, or query strings.
- fail2ban runs four jails against that log; bans are enforced with nftables (drop on tcp/80+443).
- A Go engine (stdlib only, single static binary) makes the ban/ignore decisions, keeps the threat-intel list fresh, and flushes queued reports.

## Requirements

- Debian 11/12 or Ubuntu 20.04+ (amd64 or arm64), with root (sudo).
- Intended for a public server behind an edge proxy (e.g. Cloudflare). AbuseGuard bans/reports the **real client IP**, so `trusted_proxies` must be correct.

## Install

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jasper-khan/abuseguard/main/install.sh)
```

or clone and run:

```bash
git clone https://github.com/jasper-khan/abuseguard
cd abuseguard
sudo ./install.sh                 # download the prebuilt engine from the latest release
sudo ./install.sh --from-source   # or build the Go engine locally (needs `go`)
```

The installer is idempotent: existing config, whitelist, key, and Caddyfile are never overwritten.

During install you're **interactively prompted** for two optional secrets — the Cloudflare API token (TLS via DNS-01) and the AbuseIPDB API key (auto-reporting). **Just press Enter to skip either**; both can be set later from the panel. When it finishes, the terminal prominently shows how to open the panel:

```bash
abuseguard
```

> With no terminal (CI / nohup / piped), the prompts are skipped automatically; you can also force this with `ABUSEGUARD_NONINTERACTIVE=1`.
>
> Set `ABUSEGUARD_REPO=you/abuseguard` to install from your own fork.

### Slow network / China mirror

The installer's GitHub downloads (repo tarball, engine, and the cloudflare-enabled
Caddy) try a **direct download first** and, only if it stalls, automatically
fall back through a chain of public GitHub proxies until one delivers — so the
plain one-liner works overseas (direct) and from mainland China (auto-proxy)
with no flags.

To skip the direct attempt entirely on a known-blocked network, set
`ABUSEGUARD_MIRROR=cn` — it goes straight to the proxy chain and also points
the threat-intel list at Fastly's jsDelivr CDN:

```bash
sudo ABUSEGUARD_MIRROR=cn ./install.sh          # straight to proxy chain
sudo ABUSEGUARD_MIRROR=https://your.proxy/ ./install.sh   # force one proxy
```

Both the engine and the cloudflare-enabled Caddy are downloaded from this
repo's GitHub release (Caddy is built by CI with `xcaddy`), so both get the
direct→mirror fallback above and need no extra setup in mainland China. The
`abuseguard` panel's update/uninstall reuse whatever `ABUSEGUARD_MIRROR` was
set at install time. If a Caddy with the `caddy-dns/cloudflare` module already
exists, the installer detects and keeps it, skipping the download.

## The panel

Just run `abuseguard` (the panel needs root; a normal user is transparently re-run under sudo, prompting for a password only if needed):

- status of services, jails, and timers
- list currently-banned IPs per jail
- edit the whitelist (reloads fail2ban)
- sync threat-intel now / flush the report queue now
- set the AbuseIPDB key / Cloudflare token
- toggle AbuseIPDB reporting on/off
- view recent logs, update, uninstall

## Protection model

| Jail | Trigger | Threshold | Who gets banned |
| --- | --- | --- | --- |
| `caddy-intel` | any request to a protected site | 1 hit | only IPs on the threat-intel list |
| `caddy-rate-local` | any request to a protected site | 30 in 60s | any non-whitelisted IP + queued for report |
| `caddy-probe-h1` | HTTP/1.1 scan of sensitive paths | 5 in 10m | any non-whitelisted IP + queued for report |
| `caddy-probe-h2` | HTTP/2 scan of sensitive paths | 5 in 10m | any non-whitelisted IP + queued for report |

Ban time is 90 days. Whitelisted IPs (`/etc/caddy-abuseguard/whitelist`) are never banned and never reported. "Sensitive paths" = `/.env`, `/.git`, `/phpmyadmin`, `/vendor/phpunit`, `/cgi-bin` (and subpaths).

## Threat intel

The intel jail bans nothing until the list is synced. The engine pulls a public AbuseIPDB-derived blocklist and refuses a list that is implausibly small (<90k) or large (>120k); on any failure it keeps the previous list. Refresh runs every 6h (and via the panel).

## AbuseIPDB reporting (optional)

Reporting is enabled in the config by default but does nothing until you set an API key (panel → 6). Reports are privacy-safe (no host/path/headers), deduped (15m), and capped (1000/day). The flush runs every 10m. Turn it off entirely with panel → 8.

## Add your sites

Put `import abuseguard` inside each site block in `/etc/caddy/Caddyfile`:

```caddyfile
example.com {
	import abuseguard
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	reverse_proxy localhost:3000
}
```

Then `sudo systemctl reload caddy`. Change the snippet once — every protected site follows.

## Files

```
/usr/local/bin/caddy                          Caddy (with caddy-dns/cloudflare)
/usr/local/bin/abuseguard                     control panel
/usr/local/libexec/caddy-abuseguard           Go engine
/etc/caddy/Caddyfile                          your sites
/etc/caddy/abuseguard.caddy                   the (abuseguard) snippet
/etc/caddy-abuseguard/config.json             engine config
/etc/caddy-abuseguard/whitelist               never-ban list
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key (optional)
/var/lib/caddy-abuseguard/                     intel list + report queue/state
/var/log/caddy/abuseguard-access.json         privacy-trimmed access log
```

## Update / uninstall

```bash
abuseguard                 # → 10 update, → 11 uninstall
sudo ./uninstall.sh             # remove program files, keep config/state
sudo ./uninstall.sh --purge     # also remove config, whitelist, state, logs
sudo ./uninstall.sh --dry-run   # show what would be removed, change nothing
```

Uninstall leaves the Caddy binary, the service accounts, and existing nft bans in place.

## Security notes

- Caddy adds no authentication. Anything you expose is public unless you add auth yourself.
- The installer's self-test site binds `127.0.0.1:8080` only.
- Secrets (`*.key`, `.env`) are mode 0640 and git-ignored; never commit them.

## Build / release

- `engine/` is a single Go module, stdlib only, `go 1.21`.
- Tagging `vX.Y.Z` triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds `caddy-abuseguard-linux-{amd64,arm64}` and attaches them to the release. `install.sh` downloads these by default.

See [docs/design.md](docs/design.md) for the architecture and the fail-safe rules.

## License

MIT — see [LICENSE](LICENSE).
