# AbuseGuard

**English** | [简体中文](README.md)

AbuseGuard is a drop-in abuse-mitigation layer for a [Caddy](https://caddyserver.com/) or Nginx reverse proxy on Debian/Ubuntu. For connections that reach the origin directly, it bans abusive and known-malicious IPs at the firewall (nftables) and can optionally auto-report them to [AbuseIPDB](https://www.abuseipdb.com/) — driven by fail2ban plus a small Rust engine.

One command installs a hardened Caddy (with the `caddy-dns/cloudflare` TLS module) or the distro Nginx (chosen once at first install, immutable afterwards), an nftables input firewall, the fail2ban jails, a threat-intel sync, the optional reporter, and an interactive `ag` panel.

## How it works

```
visitor ─▶ Caddy or Nginx (protected site)
             │  writes a privacy-trimmed JSON access log
             ▼
         fail2ban ──(rate/probe/SSH behavior)──▶ nftables source-IP DROP on all ports/protocols
             │
             └─(sensitive-path probe)─▶ engine enqueue ─▶ report queue ──(timer)──▶ AbuseIPDB

intel feed ──(6h sync, engine validates)──▶ root apply ──▶ dedicated nft intel set ──▶ drop listed sources
                                                        └─ allowlist exception returns from intel chain only
```

- The reverse proxy (Caddy or Nginx) tags each request to a protected site and logs only what fail2ban needs (client IP, protocol, tags) — no paths, hosts, headers, or query strings.
- Installation enables three behavioural Web jails and `sshd`, sharing one allowlist. A ban from any jail drops that source IP on every port and protocol at the origin, including SSH.
- Threat intel no longer runs through fail2ban: after a sync, the engine's root-only `policy-apply` loads the validated list into a dedicated kernel set, so listed sources are dropped at the first packet before reaching the reverse proxy or SSH. The set is independent of the port firewall table, so port edits never rebuild it.
- The allowlist is one file: panel edits update fail2ban `ignoreip` and the nft intel exception together. Hand edits need an explicit apply; see Threat intel.
- A Rust engine (small locked dependency set, single static binary) validates feeds, flushes queued reports and loads kernel policy. Only the root-only `policy-apply` subcommand writes nftables/fail2ban; sync, report and enqueue still run unprivileged.

## Requirements

- Debian 11/12 or Ubuntu 20.04+ (amd64 or arm64), with root (sudo).
- Every nftables ban matches the source IP that reaches this host, so it only works when clients connect directly to the origin (including Cloudflare DNS-only). Behind a CDN or your own proxy, the kernel sees the proxy edge IP, not the visitor: feed enforcement cannot act on proxied requests, and behavioural jails only decide whom to ban from the reverse proxy's logged `client_ip`, which still cannot stop traffic arriving through the proxy. This does not solve unknown-IP or distributed CC.

## Install

The installer checks both the effective configuration and running state of all four jails. If an existing `jail.local` or `jail.d/*.local` disables a required jail (for example, `[sshd] enabled = false`), installation fails with an error. Resolve that override and retry; the installer does not rewrite custom files automatically.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/jasper-khan/abuseguard/main/install.sh)
```

or clone and run:

```bash
git clone https://github.com/jasper-khan/abuseguard
cd abuseguard
sudo ./install.sh                 # download the prebuilt engine from the latest release
sudo ./install.sh --from-source   # or build the Rust engine locally (needs `cargo`)
sudo ./install.sh --proxy=nginx   # choose Nginx on first install (combines with --from-source)
```

Default installs and panel updates resolve the latest published GitHub release once, then use its source, configuration, and engine, including when launched from a clone. The staged engine must pass checksum, startup, and target-version checks before replacing the old binary. `--from-source` and `ABUSEGUARD_ENGINE_BIN` continue to use the local source and configuration.

The installer is idempotent: existing config, whitelist, key, and unrelated reverse-proxy configuration are preserved. In Caddy mode, protected AbuseGuard sites from an older release, or sites written directly in the main Caddyfile, are migrated to the canonical `/etc/caddy/sites/<domain>.caddy` layout with `import abuseguard`. The main config, existing sites, and protection snippet are prepared in candidate copies and validated together before replacement; a failed replacement rolls back the originals. In Nginx mode existing site files are never rewritten; install/add/delete validate the complete loaded configuration (existing sites plus the candidate) with `nginx -t`.

The installer supplies runtime dependencies such as `fail2ban`, `rsyslog`, and `nftables` automatically. `rsyslog` provides `/var/log/auth.log` for the Debian/Ubuntu default `sshd` jail; AbuseGuard's web protection continues to use its separate privacy-trimmed JSON log. A Cloudflare token already present in a running Caddy service is written safely to `/etc/caddy/.env`; Nginx mode writes `/etc/caddy-abuseguard/cloudflare.ini`. Neither is ever printed.

On the first install you're **interactively prompted** for two optional secrets — the Cloudflare API token (TLS via DNS-01) and the AbuseIPDB API key (auto-reporting). **Just press Enter to skip either**; the AbuseIPDB key is not echoed while you type. Both can be set later from the panel. Updates preserve existing keys, skip these questions, and reload the panel automatically after success. When it finishes, the terminal prominently shows how to open the panel:

```bash
ag
```

> With no terminal (CI / nohup / piped), the prompts are skipped automatically; you can also force this with `ABUSEGUARD_NONINTERACTIVE=1`.
>
> Set `ABUSEGUARD_REPO=you/abuseguard` to install from your own fork.

### Reverse-proxy backend: Caddy or Nginx

The first install must choose one reverse-proxy backend. The choice is written to root-owned `/etc/caddy-abuseguard/web-server` (strictly `caddy` or `nginx`; read only, never sourced) and is fixed for the life of that installation:

- Interactive installs ask for Caddy (default, just press Enter) or Nginx. Non-interactive installs default to Caddy; pass `--proxy=nginx` to choose Nginx.
- `--proxy=caddy|nginx` combines with `--from-source` in either order. Unknown arguments or values fail immediately.
- Updates do not need and do not read the flag; they always reuse the recorded backend. If an explicit `--proxy` differs from the recorded value, install fails before installing packages or changing the host. An existing install without a backend record (a pre-0.6 machine or broken state) aborts and asks to upgrade to 0.6.2 first, rather than silently installing a backend.
- There is no switching or migration between backends. To change it, uninstall and reinstall.
- The installer refuses to coexist with the other reverse proxy: if the other backend's binary, package, or service is present (even inactive), it aborts before changing the host. Remove that backend first.

Both backends share the same Rust engine, fail2ban jail/filter/action identities, nftables allowlist and intel, report queue, and `ag` panel. Only the reverse proxy, TLS issuance, and access-log source differ.

Caddy mode keeps the existing behaviour: hardened `/usr/local/bin/caddy` (with `caddy-dns/cloudflare`), the `/etc/caddy` layout, DNS-01, and `import abuseguard`.

Nginx mode uses the distro `nginx` service, `certbot`, and `certbot-dns-cloudflare`, and does not replace or add an Nginx systemd unit. Before touching sites, install preflights that the distro Nginx has `http_ssl_module`/`http_v2_module` and that the Cloudflare DNS plugin imports:

- Certificates use DNS-01 only (`certbot certonly --dns-cloudflare`), one `--cert-name abuseguard-<domain>` per site; never `--nginx`/`--standalone`/webroot/HTTP-01, and no port 80 listener or firewall opening. Renewal stays with the system certbot timer and stores the authenticator, credentials, and deploy hook. Only a successful certificate deployment runs `/usr/local/libexec/abuseguard-nginx-deploy`: `nginx -t`, reload, and confirmation that new workers actually took over (an ineffective reload is reported as failure, not success).
- The Cloudflare API token lives in root:root 0600 `/etc/caddy-abuseguard/cloudflare.ini`; it is never printed or sourced, and saving it does not restart Nginx. The token may be skipped at install, but adding a site then fails clearly until it is set. There is no acme.sh or HTTP-01 fallback.
- Protected sites live at `/etc/nginx/sites-available/abuseguard-<domain>.conf`, symlinked into `sites-enabled`; shared HTTP-level config is `/etc/nginx/conf.d/abuseguard.conf`. The deploy hook and shared files are project-owned; other Nginx configuration is preserved.
- The access log is `/var/log/nginx/abuseguard-access.json`: minimal JSON with only `ts`, `client_ip`, `proto`, and the AbuseGuard tags — no URI, query, Host, headers, or body. Managed sites do not also write the default combined log.
- Only `CF-Connecting-IP` from official Cloudflare IPv4/IPv6 ranges is trusted; the same header from any other source is ignored and the normalized peer address is logged. If the Cloudflare range fetch fails, the bundled snapshot is used; arbitrary sources are never trusted. The proxy preserves the original `Host` (including port), rewrites `X-Real-IP`/`X-Forwarded-For` to the trusted client, and never forwards client-supplied XFF. A Host/SNI that is not a managed domain gets a direct 404 and never reaches another site's upstream.
- Public listeners are 443/tcp with HTTP/1.1 and HTTP/2 only; HTTP/3/QUIC is not enabled. When the installer installs Nginx it suppresses package autostart and removes only the distro default site it just created; pre-existing Nginx sites are left untouched. AbuseGuard itself generates no `listen 80`, and the self-test binds loopback only.
- Certificates work in Cloudflare grey-cloud (DNS-only) and orange-cloud mode; orange-cloud requires SSL/TLS mode Full (strict). The CDN limitation for origin source-IP blocking is described under Requirements.

### Network and downloads

All GitHub downloads (repo tarball, prebuilt engine and Caddy, the checksum
file, and the `ag` panel's update/uninstall scripts) go **straight to
GitHub**; the project ships no third-party mirror or proxy chain. Update and
uninstall resolve the latest published release tag first and pull the script
from that tag, so the script and everything it installs always belong to one
published release. If your network cannot reach GitHub directly, set the
standard `https_proxy`/`HTTPS_PROXY` environment variables before running
(curl honours them natively; that proxy is then your own chosen trust
anchor), or clone the repo on a machine that can reach GitHub and install
with `--from-source`.

Both the engine and the cloudflare-enabled Caddy are downloaded from this
repo's GitHub release (Caddy is built by CI with `xcaddy`). If a Caddy with
the `caddy-dns/cloudflare` module already exists, the installer detects and
keeps it, skipping the download. Nginx mode only downloads the Rust engine
from the release; Nginx and Certbot come from distro packages.

**Integrity check (mandatory)**: the downloaded engine and Caddy MUST match the
release's `SHA256SUMS.txt`. That file is tiny and is fetched direct from
GitHub, with retries. **A mismatch, or an unobtainable sums file, aborts the
install**; verification never degrades to "skip it and continue". On a network
failure, retry or build locally with `--from-source`. The sums are fetched
lazily, only when a binary is actually downloaded, so `--from-source` and
`ABUSEGUARD_ENGINE_BIN` installs never fetch them.

**Cloudflare range fallback**: when generating the Caddyfile's `trusted_proxies`
or Nginx's trusted-source include, the installer fetches Cloudflare's official
IPv4/IPv6 ranges; if that fetch fails on a restricted network it falls back to
the bundled snapshot (`assets/caddy/cloudflare-ips.fallback`), so trust never
collapses to loopback-only or becomes arbitrary — either mistake would make the
proxy misread visitor addresses and can ban Cloudflare itself or trust spoofed
headers.

**Existing Caddy migration (Caddy mode only)**: if a Caddyfile already exists, the installer
backs it up first, then moves each unambiguous single-public-domain
`reverse_proxy` site into `/etc/caddy/sites/<domain>.caddy` and adds
`import abuseguard`. Existing TLS, routing, headers, and upstream settings are
preserved. Global blocks, snippets, IP/port listeners, and non-proxy sites stay
in the main Caddyfile. The complete migrated configuration must pass Caddy
validation before it is applied. Nginx mode never migrates or rewrites other
sites; it manages only its own `conf.d/abuseguard.conf`,
`abuseguard-<domain>.conf`, and deploy hook.

## The panel

Just run `ag` (the panel needs root; a normal user is transparently re-run under sudo, prompting for a password only if needed). Its title shows the current AbuseGuard engine version, the home screen shows the current SSH ports and protected-site count, and the home-screen ban record count re-queries every jail every 30 minutes without requiring a menu action:

The panel uses `=` rules, aligned `label : value` status rows, and a single-column numbered menu. The home screen shows protection, ban records, intel-set size and behavioural ban counts, reporting state, SSH ports, site count, and version; subpages reuse the same structure. Status values use color (green = healthy/on, yellow = warning/unconfigured, red = failed); all other text follows the terminal's foreground for both light and dark backgrounds:

| Home entry | Available actions |
| --- | --- |
| `[1]` Overview | Services, protected domains, ban counts per jail, scheduled tasks |
| `[2]` Sites and certificates | List, add, or delete reverse-proxy sites; set the Cloudflare API Token |
| `[3]` Firewall | Ports and protocols: open/close TCP or UDP ports with optional source IP/CIDR limits, toggle IPv4/IPv6 inbound; IP access: list, ban, unban, whitelist; rules: inspect or reapply |
| `[4]` SSH and login | Connection: listening ports; authentication: global password/key toggles; root credentials: add/remove public keys, change password |
| `[5]` Intel and reporting | Threat intel: sync now (validates then applies kernel policy); AbuseIPDB reporting: send queue, set API Key, toggle automatic reporting |
| `[6]` Maintenance | Diagnostics: recent logs; version: update; uninstall |

Adding a site takes a domain and upstream (local or remote IP:port), then generates a protected reverse-proxy configuration for the current backend: Caddy writes `import abuseguard` plus TLS as needed; Nginx writes `abuseguard-<domain>.conf` (reverse proxy, 443/h1/h2 only, DNS-01 certificate named `abuseguard-<domain>`). After writing the managed files, Nginx mode validates the complete loaded configuration, including existing sites and the candidate, with `nginx -T` before reloading; a validation or reload failure removes the new site and restores the previous enabled state (certificate material is retained), leaving no half-enabled site. A missing Cloudflare token makes the add fail clearly instead of falling back to HTTP-01. The whitelist supports in-panel add/remove: an edit updates fail2ban `ignoreip` and the nft intel exception together, and **adding an entry also clears the behavioural bans it covers, including addresses inside a CIDR**. If the IP is still on the intel feed, only the whitelist entry lets it through. The home screen shows firewall state, intel-feed entry count and behavioural ban counts separately, and never dumps the full intel set.

Before validation, in Caddy mode an update runs `caddy fmt` on the main Caddyfile and `/etc/caddy/sites/*.caddy`, and removes only the exact `header_up X-Forwarded-Host {host}` or `header_up X-Forwarded-Host {http.request.host}` directives that Caddy identifies as redundant. Other reverse-proxy settings and request headers are preserved.

Installation and updates automatically apply the AbuseGuard firewall and native allowlist/intel policy, and enable boot restoration, without another confirmation. An update sets its jails to idle: detection stops while existing bans stay enforced in the kernel, and fail2ban restarts after the new engine and jail files are installed; a full stop is only the fallback when idle is unavailable (existing behavioural nft bans are then briefly removed and restored from the database on restart). A failure before the engine swap restores the old jail config and keeps detection running; any failure after the swap restores the previous engine and jail config, restarts the old detection, and warns clearly instead of leaving detection paused; existing kernel bans remain in force. Each jail's native `ignoreip` is preserved per jail (an sshd-only exemption never widens the Web jails), and edits/removals in that native config take effect on the next apply. The initial configuration allows all detected SSH ports, TCP 443, and UDP 443, and drops other new inbound connections. TCP 80 is closed by default; allow it explicitly in the panel if HTTP access or redirects are needed. Existing configurations retain user-added and user-closed ports, with current SSH ports added as needed. Established connections, loopback, ICMP (including IPv6 neighbor discovery), and DHCP remain allowed; outbound traffic is unrestricted. The panel refuses to close the current SSH session port and the only SSH port. Closing other ports affects new connections only.

An SSH port change in `[4]` SSH and login keeps both ports listening: it runs `sshd -t`, allows the new port, reloads sshd, and confirms both ports are listening; any failure restores the previous configuration. On success it syncs Fail2Ban's SSH report port. Reconnect on the new port, then close the old one from the firewall menu: the panel removes its `Port` directive and closes the old firewall rule; the current session port and the only SSH port are protected. Without a `Port` directive it writes both ports to `/etc/ssh/sshd_config.d/99-abuseguard-port.conf`; with a single existing directive the original file is kept and the new port goes into that drop-in; multiple directives are refused. The new port inherits the old port's firewall source restrictions; incompatible existing source rules on the new port must first be adjusted in the firewall menu. Allow the new port in the cloud security group first. The panel refuses `ssh.socket` activation.

The login toggles in `[4]` SSH and login manage password and key login through `/etc/ssh/sshd_config.d/00-abuseguard-auth.conf`: the `00-` prefix sorts first and sshd honors the first value read, so the panel naturally outranks global directives in the main config and later-sorting drop-ins such as `50-cloud-init.conf`. Turning either off asks for a `yes` confirmation; disabling password authentication requires an unrestricted valid root public key, safe file permissions, and effective SSH settings that allow the key by itself. Disabling key authentication requires a root password and effective settings that allow password authentication by itself; uncertain cases are refused. The panel refuses only directives it cannot outrank: a foreign `00-` drop-in sorting earlier, a directive inside a `Match` block in the main config or a drop-in, or a missing `Include` (which would make drop-ins inert). `ssh.socket` activation is refused the same way. "Add public key" appends to root's authorized_keys (deduplicated by type and key blob, permissions fixed automatically; ssh-ed25519, ssh-rsa, ECDSA, and sk- hardware keys are accepted); deleting the last valid key requires a usable root password configuration and explicit confirmation. "Change root password" calls `chpasswd` and only applies when both entries match. The panel controls global authentication and does not change `PermitRootLogin`; root password login can remain restricted. When `SSH_CONNECTION` is unavailable, `UseDNS` is enabled, or `ssh-keygen` is missing, the panel cannot confirm a backup login method and refuses dangerous operations. Keyboard-interactive authentication may independently allow passwords.

When opening a port you can enter a source IPv4 or IPv6 address or CIDR; leave it empty to allow every source. One port can have several source rules, and the close action asks for the rule number. Two family switches control inbound: IPv4 is on by default, IPv6 is off by default. Turning a family off drops new inbound connections of that family while established connections, loopback, ICMP, and DHCP stay allowed. Turning off the family of the current SSH session asks for a `yes` confirmation and may require console recovery after the session ends. Reapplying rules and reinstalling only add missing SSH ports and never widen an existing source restriction.

`/etc/caddy-abuseguard/firewall.nft` is the single saved configuration. Changes pass `nft -c` before a transaction replaces only the `inet caddy_abuseguard` table. A oneshot `caddy-abuseguard-firewall.service` restores it at boot, without a new daemon; the separate `caddy-abuseguard-policy.service` oneshot restores the intel policy at boot. The menu can reapply saved rules; uninstalling removes only tables this project created (the port table and the independent `inet caddy_abuseguard_intel` intel table). Behavioural bans retain the Fail2Ban path, allowlist checks, 90-day duration, and exclusion of manual bans from reports; the same allowlist drives fail2ban `ignoreip` and the intel exception, with no per-request `ignorecommand`.

Other scripts can run `ag --firewall-open tcp 12345` or `ag --firewall-open udp 12345` to allow one port noninteractively, using the panel's validation and persistence path; failures return a nonzero status. After editing the whitelist or intel file externally, run `sudo ag --policy-apply` to validate and apply immediately; `ag --firewall-apply` rebuilds only the port table and never touches the intel table. This fork's `sing-box-yg` calls the interface when creating nodes, changing ports, or configuring a private landing inbound. Update AbuseGuard to v0.3.5 or later before using the updated `sb`. Only explicitly requested ports are added, without service scanning or automatic closure of old ports; cloud security groups still need separate rules.

Before applying the firewall or editing ports, AbuseGuard checks existing nftables input chains. Other input rules or default-drop policies (except this project's managed tables and Fail2Ban's `f2b-table`) abort the operation and list the conflicting chains; migrate or disable those rules before retrying so that old rules cannot silently override a panel port allowance. Cloud security groups and forwarded traffic, including published container ports, remain managed by their respective platforms. The IP allowlist exempts addresses from bans, not from port filtering. If another tool flushes the entire nftables ruleset, reapply the firewall rules from the panel. Reverse-proxy upstream ports normally do not need public access.

## Protection model

| Jail | Trigger | Threshold | Who gets banned |
| --- | --- | --- | --- |
| `caddy-rate-local` | any request to a protected site | 120 in 60s | any non-whitelisted IP (local ban only; panel manual bans also land in this jail) |
| `caddy-probe-h1` | HTTP/1.1 scan of sensitive paths | 5 in 10m | any non-whitelisted IP + queued for report |
| `caddy-probe-h2` | HTTP/2 scan of sensitive paths | 5 in 10m | any non-whitelisted IP + queued for report |
| `sshd` (enabled on install) | SSH authentication failures | the jail's effective thresholds | any non-whitelisted IP + queued for report |

The three Web jails and `sshd` ban for 90 days using the same all-port, all-protocol action. The `sshd` jail keeps the system's log source, backend, and detection thresholds (Fail2Ban defaults when not customized). IPs on `/etc/caddy-abuseguard/whitelist` are never banned or reported by AbuseGuard. Manual bans also check the allowlist and accept only single IPv4/IPv6 addresses; allowlist entries still support CIDRs. Each jail tracks bans independently, so one jail's unban cannot undo another jail's active ban; the panel unbans across all jails. Threat-intel enforcement does not use a jail: listed sources are dropped by a dedicated kernel set (see Threat intel). "Sensitive paths" = `/.env`, `/.git`, `/phpmyadmin`, `/vendor/phpunit`, `/cgi-bin` (and subpaths).

Newly generated Caddy configurations enable only HTTP/1.1 and HTTP/2; Nginx sites listen on 443 with HTTP/1.1 and HTTP/2. Neither enables HTTP/3, leaving UDP/443 available for other services. Global source-IP bans do not occupy any port.

## Threat intel

Threat intel is enforced as a kernel set, not as a "one hit then 90-day ban" jail. Every 6h (and on demand from the panel) the engine pulls a public AbuseIPDB-derived blocklist: it keeps IPv4 only, refuses a list that is implausibly small (<90k) or large (>120k), and writes `intel.txt` atomically once validation passes. Any download or parse failure keeps the previous list.

The root-only `caddy-abuseguard policy-apply` (run by `caddy-abuseguard-policy.service` at boot and by `caddy-abuseguard-sync.service` after each sync) then validates the whitelist and feed in-process, rebuilds the set in one nft transaction, and only then writes a root-owned boot snapshot. An empty set is allowed only when no policy was ever established; a missing, corrupt, undersized, oversized, or failed apply keeps the last effective kernel policy and snapshot instead of replacing it with an empty or partial list.

Enforcement follows the feed: a newly listed source is dropped on the next sync, and a source that leaves the list stops being dropped — there is no fixed 90-day intel ban. The allowlist exception only `return`s from the intel chain, never globally accepts traffic, so whitelisted IPs still pass through the normal port firewall; overlapping CIDR exceptions work. Port edits rebuild only the port table; the intel set is independent.

Hand edits to `/etc/caddy-abuseguard/whitelist` need an explicit apply: `sudo ag --policy-apply` (otherwise they wait for the next six-hour sync cycle). Panel edits apply immediately, as do install and update. A failed apply keeps the last effective policy, so fail2ban is never silently split from kernel enforcement.

Unban versus the feed: the panel's unban clears timed behavioural bans only. If the source is still on the intel feed, kernel enforcement continues — add it to the whitelist to let it through.

See Requirements for the proxy/CDN limit: the kernel only matches the source address that reaches this host, so feed enforcement cannot act on proxied visitors.

## AbuseIPDB reporting (optional)

Reporting is enabled in the config by default, but events are queued only after an API key is set. Sensitive-path probes are fixed to category `21` (Web App Attack); authentication brute-force bans from the `sshd` jail are fixed to `18,22` (Brute-Force + SSH). Request-rate bans, threat-intel enforcement, and manual panel bans remain local only.

Public comments contain only a standardized behavior, the observed count and detection window, plus the HTTP protocol for web events. They never name AbuseGuard or include a host, exact path, query, headers, request body, user agent, SSH username, or raw log. Reports honor AbuseIPDB's per-IP 15-minute window; a later event for the same IP stays queued until eligible instead of being discarded. The daily cap remains 1000. A flush atomically rotates the current queue into a separate processing batch, so records enqueued while it sends remain in the new queue. An unreadable allowlist or corrupt state stops the flush; temporary API failures keep records for retry. The flush runs every 10m. Toggle external reporting with panel → `[5]` Intel and reporting → `[4]` Automatic reporting; this never disables local bans.

## Add your sites

### Caddy mode

Use one `/etc/caddy/sites/<domain>.caddy` file per protected site and put `import abuseguard` inside its site block:

```caddyfile
example.com {
	import abuseguard
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
	reverse_proxy localhost:3000
}
```

Then run `sudo systemctl reload caddy || sudo systemctl restart caddy` (the restart fallback is used when Caddy's admin API is disabled). The main `/etc/caddy/Caddyfile` keeps global settings and the imports for `abuseguard.caddy` and `sites/*.caddy`; change the shared snippet once and every protected site follows.

The Cloudflare token in this example is only for DNS-01 certificate issuance.

### Nginx mode

Add sites from the panel's "Sites and certificates" screen. It issues an `abuseguard-<domain>` certificate, writes `/etc/nginx/sites-available/abuseguard-<domain>.conf`, symlinks it into `sites-enabled`, then validates the complete loaded configuration (including existing sites and the candidate) with `nginx -T` before reloading. The reload is only accepted after a new worker generation actually took over, so an occupied listen address no longer reports success; a validation or reload failure removes the new site and restores the previous enabled state (certificate material is retained), leaving no half-enabled site. Managed sites disable response buffering and use a 1h upstream read timeout: SSE/streamed bodies are not delayed, and idle WebSockets are not cut at Nginx's 60s default. Managed site files carry the shared log/tag directives; after manual edits run `sudo nginx -t && sudo systemctl reload nginx`.

Renewal is handled by the system certbot timer: `/etc/letsencrypt/renewal/abuseguard-<domain>.conf` references the DNS-01 authenticator and root-only `/etc/caddy-abuseguard/cloudflare.ini`, and `/usr/local/libexec/abuseguard-nginx-deploy` is the deploy hook. Only a successful deployment validates, reloads and confirms the new worker generation; a reload that did not apply fails the deployment, and a failed renewal does not interrupt the existing HTTPS service.

Both modes accept only `domain + IP:port`; no scheme, HTTPS upstream, or wildcard domain.

## Files

Shared by both backends:

```
/usr/local/bin/ag                             control panel
/usr/local/libexec/caddy-abuseguard           Rust engine (root-only policy-apply subcommand)
/etc/caddy-abuseguard/web-server              recorded backend (strictly caddy or nginx, root-owned)
/etc/caddy-abuseguard/config.json             engine config
/etc/caddy-abuseguard/whitelist               never-ban list
/etc/caddy-abuseguard/firewall.nft            port firewall config + boot restore
/etc/caddy-abuseguard/intel.nft               intel snapshot (root-owned, boot restore)
/etc/caddy-abuseguard/intel-allow.nft         allowlist exception snapshot (root-owned)
/etc/caddy-abuseguard/intel-applied.json      last apply time and entry counts
/etc/caddy-abuseguard/abuseipdb-report.key    AbuseIPDB key (optional)
/etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local  enables SSH protection and reporting
/etc/fail2ban/jail.d/zzz-caddy-abuseguard-policy.local generated native ignoreip
/var/lib/caddy-abuseguard/                     intel list + report queue/state
```

Caddy mode:

```
/usr/local/bin/caddy                          Caddy (with caddy-dns/cloudflare)
/etc/caddy/Caddyfile                          global config + AbuseGuard imports
/etc/caddy/abuseguard.caddy                   the (abuseguard) snippet
/etc/caddy/sites/<domain>.caddy               one file per protected site
/etc/caddy/.env                               CF_API_TOKEN (0640)
/var/log/caddy/abuseguard-access.json         privacy-trimmed access log
```

Nginx mode:

```
/etc/nginx/conf.d/abuseguard.conf             shared HTTP config (log format, maps, trust)
/etc/nginx/conf.d/zz-abuseguard-selftest.conf loopback-only self-test
/etc/nginx/snippets/abuseguard-cloudflare.conf  real_ip trust for official CF ranges only
/etc/nginx/sites-available/abuseguard-<domain>.conf   one file per protected site
/etc/nginx/sites-enabled/abuseguard-<domain>.conf     symlink to sites-available
/usr/local/libexec/abuseguard-nginx.sh        root-owned Nginx runtime helper (source only)
/usr/local/libexec/abuseguard-nginx-deploy    certificate deploy hook (nginx -t, then reload)
/etc/logrotate.d/abuseguard-nginx             access-log rotation and reopen
/etc/caddy-abuseguard/package-ownership       pre-install Nginx/Certbot package ownership (root-owned)
/etc/caddy-abuseguard/cloudflare.ini          DNS-01 credential (root:root 0600)
/etc/letsencrypt/live/abuseguard-<domain>/    certificate lineage per site
/etc/letsencrypt/renewal/abuseguard-<domain>.conf  certbot renewal config
/var/log/nginx/abuseguard-access.json         privacy-trimmed access log
```

## Update / uninstall

```bash
ag                               # panel: [6] Maintenance → [2] update / [3] uninstall
sudo ./uninstall.sh              # interactive: conservative / thorough
sudo ./uninstall.sh --conservative   # conservative: remove AbuseGuard, keep the proxy + your sites
sudo ./uninstall.sh --purge          # thorough: also remove what AbuseGuard installed
sudo ./uninstall.sh --dry-run        # show what would be removed, change nothing
```

A panel-changed SSH port is not reverted on uninstall (the setting stays in `/etc/ssh/sshd_config.d/99-abuseguard-port.conf`), so removal never switches SSH back to the default port and locks you out; change it from `[4]` SSH and login after reinstalling.

Uninstall is **symmetric to install**: install records a manifest (what
AbuseGuard created vs. what you already had). The backend choice is immutable and uninstall never switches it.

- **Conservative**: remove AbuseGuard's components. Caddy mode strips `import abuseguard`, the snippet, and the self-test site from the Caddyfile; Nginx mode keeps managed sites (the default), `conf.d/abuseguard.conf`, certificates, `cloudflare.ini`, renewal configuration, and the deploy hook, removing only the self-test and core components. Only when sites are dropped does it remove managed sites, project HTTP/trust/logrotate config, their certificate lineages, and credentials, and it never touches other Nginx configuration. Both **keep your existing proxy, accounts, and reverse-proxy config**.
- In Nginx mode a conservative uninstall keeps the certificates, `/etc/caddy-abuseguard/cloudflare.ini`, the Nginx snippets needed for renewal, the certbot renewal configuration, and the deploy hook, so HTTPS and automatic renewal keep working after the core is removed.
- **Thorough**: additionally remove the Caddy/Nginx packages, accounts, and config that AbuseGuard installed — but **anything that pre-existed the install is left untouched** (if you already had Caddy or Nginx, it stays). Nginx mode removes only project-owned, unreferenced sites, certificate lineages, credentials, and config; when sites are kept, the Nginx/Certbot packages, certificates, credentials, and renewal configuration are kept too. It never runs `rm -rf /etc/nginx`, `rm -rf /etc/letsencrypt`, a global `apt autoremove`, or disables another service's certbot timer. Falls back to the safest path if the manifest is missing.
- New installations record first-install ownership in root-controlled `/etc/caddy-abuseguard/install-manifest`. Retries and upgrades never overwrite it or promote an old snapshot from `/var/lib/caddy-abuseguard`. Without a trusted manifest, even `--purge` falls back to conservative uninstall and keeps managed sites. If the proxy mode cannot be verified or the engine lacks inventory support, only the core is removed and proxy configuration is left unchanged.
- Managed sites can be kept (de-protected) or deleted. Kept Nginx sites that still need renewal material keep those files even in an otherwise thorough uninstall. A later reinstall restores protection to recognised kept sites without silently switching backends. Your original Caddyfile is backed up at install time as `Caddyfile.pre-abuseguard`.

Uninstall also removes this project's port table, independent intel table, root-owned boot snapshot, and generated allowlist jail configuration; other nftables tables and other fail2ban jails are left untouched.

## Security notes

- The reverse proxy adds no authentication. Anything you expose is public unless you add auth yourself.
- The installer's self-test binds loopback only (Caddy `127.0.0.1:8080`; Nginx also generates no public port 80 site).
- Secrets (`*.key`, `.env`) are mode 0640; the Nginx `/etc/caddy-abuseguard/cloudflare.ini` is root:root 0600. All are git-ignored; never commit them.
- Caddy-mode downloaded binaries are verified against `SHA256SUMS.txt` (see the integrity check under "Network and downloads"). Nginx mode uses distro `nginx`/`certbot` packages, and the install manifest records which packages AbuseGuard installed so uninstall never removes pre-existing software.
- Threat intel takes effect only through a root-owned snapshot and kernel set: the root-only applier validates the whitelist and stored feed in-process line by line and never executes downloaded text as nft rules. `/var/lib/caddy-abuseguard` is writable by the unprivileged `abuseguard` user, so it is never used as executable policy input.
- Caddy runs under a hardened systemd unit (`NoNewPrivileges`, `ProtectSystem=strict`, restricted capability set, syscall filtering); the two engine timers and the root policy applier are hardened too. Nginx uses the distro-provided `nginx.service` (no replacement unit).
- Nginx trusts `CF-Connecting-IP` only from official Cloudflare IPv4/IPv6 ranges; the same header from any other source is ignored. The protected access log has no URI, Host, headers, body, or query, and managed sites do not also write the default combined log.
- `/etc/caddy-abuseguard/web-server` is root-owned, read-not-executed, and strictly validated as `caddy`/`nginx`; a corrupt or ambiguous record never authorises installing the other backend.

## Build / release

- `engine-rs/` is a single Cargo crate with a small, locked dependency set; `engine-rs/Cargo.toml` keeps `version` in sync with the top-level `VERSION` file.
- CI runs the locked Rust engine tests, shell/panel tests, the real Caddy log contract, the real Nginx → JSON → fail2ban-regex contract (HTTP/1.1 and HTTP/2, trusted and spoofed Cloudflare headers, privacy fields, rotation), and the isolated Nginx rollback/certificate-fixture suite; the real nftables and systemd sandbox gates stay separate.
- Tagging `vX.Y.Z` triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds `caddy-abuseguard-linux-{amd64,arm64}` and attaches them to the release. `install.sh` downloads these by default; Nginx mode publishes/downloads no such assets and uses distro packages.
- Versioned engine assets remain immutable after release. Weekly/manual refreshes replace only the upstream-tracking Caddy assets and regenerate checksums plus build metadata for the complete asset set.

See [docs/design.md](docs/design.md) for the architecture and the fail-safe rules.

## License

MIT — see [LICENSE](LICENSE).
