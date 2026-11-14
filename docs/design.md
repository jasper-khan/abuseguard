# AbuseGuard design

## Goals

- Ban abusive / known-bad IPs that connect directly to the origin at the firewall, with minimal moving parts.
- Optional, privacy-safe AbuseIPDB auto-reporting.
- Fail-safe by default: never ban a whitelisted IP; prefer "do nothing" over a wrong ban; keep last-good data on any fetch failure.
- Debian/Ubuntu, amd64/arm64, systemd.

## Components

- **Caddy** (with `caddy-dns/cloudflare`) — the reverse proxy. The `(abuseguard)` snippet tags requests and writes a privacy-trimmed JSON access log.
- **fail2ban** — watches the log, counts hits, and enforces behavioural bans with the `nftables` action, using a generated per-jail `ignoreip` from AbuseGuard's allowlist plus each jail's preserved native entries, and the report-queue action on the probe and SSH jails.
- **engine** (`/usr/local/libexec/caddy-abuseguard`) — a small stdlib-only Go binary. It validates/exports allowlist and intel input, syncs the feed, and flushes the report queue. It stays unprivileged and never touches nftables.
- **root applier** (`/usr/local/libexec/caddy-abuseguard-policy`, installed from `assets/policy/abuseguard-policy.sh`; run by the `caddy-abuseguard-policy.service` oneshot) — validates the engine exports under a root-owned lock, applies the independent intel table in one nft transaction, generates the fail2ban `ignoreip`, and writes the root-owned boot snapshot.
- **systemd units** — `caddy-abuseguard-sync.timer` (6h) runs the unprivileged sync command under a root oneshot that invokes the applier afterwards; `caddy-abuseguard-report.timer` flushes the report queue; `caddy-abuseguard-policy.service` restores the intel policy at boot.
- **panel** (`ag`) — a numbered bash TUI over the above.

Installation and updates apply the host input firewall through the panel's noninteractive `ag --firewall-apply` entry and enable boot restoration. Its only persistent state is `/etc/caddy-abuseguard/firewall.nft`; `caddy-abuseguard-firewall.service` loads it at boot. `caddy-abuseguard-policy.service` runs at boot too and restores the native allowlist + intel policy from its root-owned snapshot; install/update applies both after validation. Initial rules allow detected SSH ports, TCP 443 and UDP 443; TCP 80 requires an explicit allowance. Updates preserve saved port choices and add current SSH ports. The panel manages TCP/UDP port allow rules in a dedicated `inet caddy_abuseguard` table, with a default-drop input policy and exceptions for established connections, loopback, ICMP and DHCP. An allow rule may optionally match a source IPv4 or IPv6 address or CIDR; one port can carry several source rules, and closing a rule selects it by number. Two persisted family flags gate inbound traffic: IPv4 is enabled by default and IPv6 is disabled by default, and a disabled family is dropped before the allow rules while established connections, loopback, ICMP, and DHCP remain. Disabling the current SSH session family requires explicit confirmation. Reapplying rules and reinstalling never widen an existing source restriction, and a new SSH port inherits the old port's sources. Port edits validate with `nft -c` and replace only that table in one transaction. IP bans continue to use Fail2Ban, so there is no second ban database or allowlist implementation.

As specified by the [nftables verdict semantics](https://www.netfilter.org/projects/nftables/manpage.html), an accept in the port table cannot override a drop in another base chain. Applying or editing the firewall therefore rejects competing nftables input chains containing rules or a default-drop policy, except the managed table and Fail2Ban's `f2b-table`. Empty accepting input chains and forwarding chains are left alone. Cloud firewalls and forwarded/container traffic remain outside this manager's control.

## Canonical Caddy layout

The main `/etc/caddy/Caddyfile` contains global settings and imports the shared `/etc/caddy/abuseguard.caddy` snippet plus `/etc/caddy/sites/*.caddy`. Every protected site lives in its own `/etc/caddy/sites/<domain>.caddy` file and uses `import abuseguard`.

During install or update, protected single-domain site blocks found in the main Caddyfile are moved to that canonical layout. Legacy inline AbuseGuard log/probe directives are replaced by the shared import while the rest of each site block (TLS, matchers, routes, and upstreams) is preserved. The candidate main file and migrated site files are installed only if the complete Caddy configuration validates; an ambiguous protected block or an existing target filename aborts the migration instead of leaving two configuration layouts active.

## Request → ban flow

1. A request hits a site with `import abuseguard`. Caddy appends `caddy_abuseguard_site=protected`, and if the path looks like a scan, `caddy_abuseguard_probe=web-probe`, then logs `{ts, client_ip, proto, ...tags}`.
2. fail2ban filters match on those tags (order-independent JSON lookaheads).
3. On enough hits within the window, the jail's `caddy-abuseguard-drop` action drops direct-origin traffic from that source IP on all ports and protocols for 90 days. It inherits Fail2Ban's nftables action with no protocol/port matcher. Independent per-jail address sets prevent an unban in one jail from undoing another jail's active ban.
4. The probe jails additionally run `enqueue`, appending the offender to the report queue. The rate jail remains a local firewall ban only, and is also where panel manual bans land, so they are never reported.

The installer enables `[sshd]`, using the same global ban action and generated allowlist as the Web jails, plus the queue action. It keeps the system's SSH log/backend and detection thresholds, and sets the ban time to 90 days. Caddy's JSON `datepattern` is scoped to the three Caddy jails so it cannot replace SSH system-log date detection. A brute-force ban queues only the IP, failure count, effective find window, `ssh-bruteforce` profile, and timestamp; raw authentication matches and usernames never enter the report queue.

Threat-intel enforcement never waits for a request. A separate path syncs the feed, validates it, and applies it to an independent kernel set, so a listed source is dropped at the first packet without a fail2ban filter or per-request ignore lookup.

## Native allowlist + intel policy (engine ↔ root applier)

The engine never touches nftables. Two export subcommands form the trust boundary; a root-run applier consumes their output:

- `allowlist-export [--file <path>]` writes canonical IP/CIDR entries to stdout, one per line, no comments. It validates the whole input before writing anything: an invalid or unreadable allowlist exits nonzero with no partial output. `--file` supports transactional candidate previews.
- `intel-export` writes validated canonical bare IPv4 addresses to stdout from the configured `state_dir/intel.txt`, enforcing the configured entry bounds and rejecting invalid data, IPv6, and unsafe tokens. It validates the whole input before any output. A missing file is success with empty stdout only for first bootstrap; an existing empty, corrupt, undersized or oversized file fails. No whitelist filtering happens here, so a whitelist change never rebuilds the large set.

The applier takes a root-owned lock, checks the exports itself, replaces the intel table in a single nft transaction, and only then writes a root-owned boot snapshot under `/etc/caddy-abuseguard`. The downloaded feed text is never executed as nft content. At boot, when the kernel table is absent, that snapshot is restored before any fail2ban read or fresh export, so a broken fail2ban config cannot leave the feed policy missing. Any fetch/parse/apply/persist failure keeps the last effective kernel and disk policy; an empty set is allowed only when no prior snapshot or set exists, and application failures are never reported as success. fail2ban `ignoreip` is generated per jail from the same allowlist plus that jail's own native `ignoreip`, read at every apply with the generated file moved aside; an sshd-only exemption never widens the Web jails, edits/removals propagate on the next apply, and these native entries never enter the kernel allowlist.

The intel table is independent of the port table and exempted from the competing-input-chain check. Its allowlist exceptions `return` only from the dedicated intel chain, so whitelisted sources remain subject to normal port policy; overlapping IP/CIDR entries work. Adding a whitelist entry also clears behavioural bans that already cover it. On upgrade, bans captured from the retired `caddy-intel`/`sshd-intel` jails are replayed into `caddy-rate-local` as fresh 90-day bans (the supported fail2ban API can read each ban's residual expiry, but its normal restore call re-applies the jail-wide bantime from restore time, so a distinct per-IP remaining duration cannot be restored), whitelisted addresses are skipped, and the old jails are removed without queuing reports. An update stages downloads before touching live protection, then sets the six old jails to idle: detection and `ignorecommand` stop while existing bans stay enforced in the kernel; the new jail files and engine are installed, fail2ban restarts, and captured bans are migrated. A full stop is only the fallback when idle is unavailable (its nft bans are then briefly removed and restored from the database on restart). A failure before the engine swap restores the backed-up jail config and resumes the old detection; a failure after the swap restores the previous engine and jail config and restarts the old detection, with a visible nonzero failure, instead of leaving detection paused. Each jail's native `ignoreip` is preserved per jail and never merged into a shared or kernel exemption.

`allowlist-check --ip X` keeps the exit-code contract used by the panel: **0 = whitelisted**, **1 = not whitelisted**, **2 = input/config/allowlist error**. Manual bans are accepted only on exit 1 and only for single addresses; allowlist entries still support CIDRs. `intel-ignore`, `unknown-ignore`, `intelContains`, and the ignore caches are retired, so no per-request Go lookup remains on a ban path. The reporter still stops without sending if the allowlist cannot be read.

## Threat intel

`sync-intel` downloads a public blocklist, keeps IPv4 entries, and writes `intel.txt` atomically **only if** the count is within `[min_entries, max_entries]` (default 90k–120k). Any download/parse failure logs and returns 0, keeping the previous list. The sync command runs as the unprivileged `abuseguard` user; `caddy-abuseguard-sync.service` is a root oneshot that runs it and then invokes the applier, so the timer, manual sync, allowlist changes, install/update, and boot all reach kernel policy. Enforcement follows the feed: a newly listed source is dropped after the next successful apply, and a delisted source stops being dropped without waiting out a fixed ban. A missing `intel.txt` yields an empty set only when no snapshot or set exists yet; with an existing policy, a failure preserves the last good kernel and snapshot. The panel distinguishes feed entries from timed behaviour-ban counts instead of dumping the set.

## Reporting

`enqueue` writes only when reporting is enabled, a key is present, the IP is public, and the profile is one of the two closed mappings below. `report send-auto` validates those conditions again for old queued data. Categories and comments are generated by the engine, never accepted from the queue or configuration.

| Profile | Evidence source | AbuseIPDB categories | Public comment fields |
| --- | --- | --- | --- |
| `web-probe` | five tagged sensitive-path requests within the Caddy probe jail window | `21` | standardized behavior, count, window, HTTP protocol |
| `ssh-bruteforce` | a ban event from the enabled fail2ban `sshd` jail | `18,22` | standardized behavior, count, window |

Request-rate bans, threat-intel hits, and manual bans never enqueue reports. One short filesystem lock atomically rotates `queue.jsonl` into a processing batch; new `enqueue` calls then write a fresh queue while the batch is sent. A separate reporter lock prevents two flushers from processing the same batch. The reporter strictly loads the whitelist and its dedupe/daily state before sending, skips whitelisted IPs, and honors `daily_report_cap`. After each confirmed 2xx response, one atomic checkpoint records the remaining batch, dedupe state, and daily usage; an interrupted run replays that checkpoint before sending again, so a confirmed report is not repeated. AbuseIPDB's duplicate window is per IP rather than per category: a later queued event for the same IP is retained and retried after `dedupe_window` instead of being discarded. Network failures and responses that end before an HTTP status is known remain queued because the remote result is uncertain. 401/403, 429, 5xx, and unexpected statuses likewise keep the unprocessed batch and return failure. Record-specific 400/422 responses and malformed queue lines are logged and discarded so later valid records can proceed; the run still returns failure so systemd exposes the problem.

Report deduplication records the time of each confirmed successful response,
and checks the current time for each subsequent queued item. Daily accounting
also rolls over at UTC midnight during a long-running batch.

## Privacy

The Caddy access log deletes headers, TLS, host, remote_ip/port, method, uri and resp_headers — keeping essentially `ts`, `client_ip`, `proto`, and the abuseguard tags. Fail2ban converts a matched web path to the generic `web-probe` profile before queuing, so the URI cannot reach the reporter. The SSH action likewise passes no raw auth-log match or username. Reports carry only the IP, fixed categories, timestamp, and an objective comment; comments never name AbuseGuard or include hostnames, paths, query strings, headers, bodies, user agents, usernames, or raw logs.

## Trust boundary

Bans/reports target Caddy's `client_ip`, so Caddy must trust the edge proxy (`trusted_proxies` + `trusted_proxies_strict`) to log and report the correct visitor. The installer pre-fills the current Cloudflare ranges plus loopback when it generates a Caddyfile. Get this wrong and fail2ban acts on the proxy IP instead of the visitor. If the live Cloudflare-range fetch fails, the installer falls back to a bundled snapshot (`assets/caddy/cloudflare-ips.fallback`).

Native intel enforcement matches the packet source address, not Caddy's `client_ip`. Behind a CDN or own proxy those differ: proxied visitor traffic arrives from the proxy edge, so feed blocking cannot act on it, and a behavioural ban decided from `client_ip` cannot stop it at the origin either. Native enforcement therefore protects direct-origin traffic only; it is not a defence against unknown-IP or distributed CC.

## Users & permissions

- `caddy` runs the proxy and owns the log dir.
- `abuseguard` runs the engine (report / sync / enqueue / exports) with no shell and no firewall rights.
- fail2ban (root) owns behavioural nftables bans; the root applier alone replaces the intel table and boot snapshot. The engine never touches the firewall.
- The config dir is `root:abuseguard 0750`; secrets are `0640`.
- Caddy, both engine timers, and the root applier run under hardened systemd units (`NoNewPrivileges`, `ProtectSystem=strict` with explicit `ReadWritePaths`, restricted address families/capabilities, `SystemCallFilter=@system-service`).

## Supply chain

Prebuilt binaries (engine + cloudflare-enabled Caddy) ship from the repo's GitHub release. Because downloads may traverse third-party GitHub proxies (the mainland-China fallback), `install.sh` verifies each binary against the release `SHA256SUMS.txt`, fetching that sums file over every available route (direct GitHub first, then the mirror chain, with retries). Verification is mandatory: if the sums cannot be obtained, or a checksum is missing or mismatched, the install aborts rather than proceeding unverified. Each download is staged beside its destination; checksum, executable mode, and a `version` startup check must pass before an atomic replacement, so a failed update keeps the installed binary. The sums are fetched lazily, only when a binary is actually downloaded. This defeats a passive/caching mirror; a single forced mirror carrying both the sums and the binaries is outside the guarantee. `--from-source` and a caller-supplied `ABUSEGUARD_ENGINE_BIN` skip verification (locally trusted).

Default installs and panel updates resolve the latest published release once, then bootstrap from that tag and fetch its assets and checksums using tag-specific URLs. The staged engine must report the expected version before replacing the installed binary. Explicit local source/preset-binary installs keep using the local checkout.

An engine is built only for a version tag and remains immutable under that release. Scheduled/manual refreshes download those existing engine assets, rebuild only Caddy against upstream, and regenerate the combined checksums plus metadata while preserving engine provenance.

## Non-goals

- No web UI, no daemon, no database.
- No IPv6 threat intel (the list is IPv4); IPv6 clients can still be rate/probe banned.
- No authentication for your sites — that is your application's job.
- No blocking of proxied/CDN visitor traffic by source: kernel enforcement only sees the packet source reaching the origin, so it cannot act on visitors hidden behind an edge proxy.
