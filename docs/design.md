# AbuseGuard design

## Goals

- Ban abusive / known-bad IPs that connect directly to the origin at the firewall, with minimal moving parts.
- Optional, privacy-safe AbuseIPDB auto-reporting.
- Fail-safe by default: never ban a whitelisted IP; prefer "do nothing" over a wrong ban; keep last-good data on any fetch failure.
- Debian/Ubuntu, amd64/arm64, systemd.

## Components

- **Caddy** (with `caddy-dns/cloudflare`) — the reverse proxy. The `(abuseguard)` snippet tags requests and writes a privacy-trimmed JSON access log.
- **fail2ban** — watches the log, counts hits, enforces bans with the `nftables` action, and calls the engine for ignore decisions and report queuing.
- **engine** (`/usr/local/libexec/caddy-abuseguard`) — a small stdlib-only Go binary. All state lives on disk; there is no daemon.
- **systemd timers** — periodic intel refresh and report-queue flush.
- **panel** (`abuseguard`) — a numbered bash TUI over the above.

## Request → ban flow

1. A request hits a site with `import abuseguard`. Caddy appends `caddy_abuseguard_site=protected`, and if the path looks like a scan, `caddy_abuseguard_probe=web-probe`, then logs `{ts, client_ip, proto, ...tags}`.
2. fail2ban filters match on those tags (order-independent JSON lookaheads).
3. On enough hits within the window, the jail's `nftables` action drops direct-origin traffic from that IP on tcp/80+443 for 90 days.
4. The rate/probe jails additionally run `enqueue`, appending the offender to the report queue.

## Ignore-command contract (engine ↔ fail2ban)

fail2ban decides "should I skip this candidate?" via `ignorecommand`. The exit code is the contract:

- `intel-ignore --ip X`: exit **1 = ban** (X is on the intel list and not whitelisted), exit **0 = ignore**. This makes the intel jail ban *only* known-bad IPs even though its filter matches every request to a protected site.
- `unknown-ignore --ip X`: exit **1 = ban** (not whitelisted), exit **0 = ignore** (whitelisted). Used by the rate/probe jails.

The whitelist is a single file of IPs/CIDRs (`#` comments, inline annotations tolerated). A parse error yields an *empty* allowlist — fail-safe, so a broken file never silently whitelists everyone.

## Threat intel

`sync-intel` downloads a public blocklist, keeps IPv4 entries, and writes `intel.txt` atomically **only if** the count is within `[min_entries, max_entries]` (default 90k–120k). Any download/parse failure logs and returns 0, keeping the previous list. A missing `intel.txt` = empty set = the intel jail ignores everyone, so there are no false bans before the first successful sync.

## Reporting

`report send-auto` flushes the queue to AbuseIPDB only when reporting is enabled **and** a key is present. One short filesystem lock atomically rotates `queue.jsonl` into a processing batch; new `enqueue` calls then write a fresh queue while the batch is sent. A separate reporter lock prevents two flushers from processing the same batch. It skips whitelisted IPs, dedupes per IP within `dedupe_window`, honors `daily_report_cap`, and keeps the unprocessed batch on a send failure or when the cap is hit. Comments are generic (never host/path/headers); categories are per-profile.

## Privacy

The access log deletes headers, TLS, host, remote_ip/port, method, uri and resp_headers — keeping essentially `ts`, `client_ip`, `proto`, and the abuseguard tags. Reports carry only the IP, a category, and a generic comment.

## Trust boundary

Bans/reports target Caddy's `client_ip`, so Caddy must trust the edge proxy (`trusted_proxies` + `trusted_proxies_strict`) to log and report the correct visitor. The installer pre-fills the current Cloudflare ranges plus loopback when it generates a Caddyfile. Get this wrong and fail2ban acts on the proxy IP instead of the visitor. If the live Cloudflare-range fetch fails, the installer falls back to a bundled snapshot (`assets/caddy/cloudflare-ips.fallback`).

This restored HTTP-layer identity does not change the packet source seen by the origin firewall. In Cloudflare orange-cloud mode, the TCP source is a Cloudflare edge, so an nftables rule keyed by the restored visitor IP cannot block that proxied request. AbuseGuard can still detect and report the visitor, but edge-side blocking is a separate deployment requirement. DNS-only/direct-origin traffic is enforceable locally.

## Users & permissions

- `caddy` runs the proxy and owns the log dir.
- `abuseguard` runs the engine (report / sync / enqueue / ignore) with no shell and no firewall rights.
- fail2ban (root) owns the actual nftables bans; the engine never touches the firewall.
- The config dir is `root:abuseguard 0750`; secrets are `0640`.
- Caddy and both engine timers run under hardened systemd units (`NoNewPrivileges`, `ProtectSystem=strict` with explicit `ReadWritePaths`, restricted address families/capabilities, `SystemCallFilter=@system-service`).

## Supply chain

Prebuilt binaries (engine + cloudflare-enabled Caddy) ship from the repo's GitHub release. Because downloads may traverse third-party GitHub proxies (the mainland-China fallback), `install.sh` verifies each binary against the release `SHA256SUMS.txt`, fetching that sums file over every available route (direct GitHub first, then the mirror chain, with retries). Verification is mandatory: if the sums cannot be obtained, or a checksum is missing or mismatched, the install aborts rather than proceeding unverified. The sums are fetched lazily, only when a binary is actually downloaded. This defeats a passive/caching mirror; a single forced mirror carrying both the sums and the binaries is outside the guarantee. `--from-source` and a caller-supplied `ABUSEGUARD_ENGINE_BIN` skip verification (locally trusted).

An engine is built only for a version tag and remains immutable under that release. Scheduled/manual refreshes download those existing engine assets, rebuild only Caddy against upstream, and regenerate the combined checksums plus metadata while preserving engine provenance.

## Non-goals

- No web UI, no daemon, no database.
- No IPv6 threat intel (the list is IPv4); IPv6 clients can still be rate/probe banned.
- No Cloudflare edge-rule management; orange-cloud deployments must provide edge-side blocking separately.
- No authentication for your sites — that is your application's job.
