#!/usr/bin/env bash
# AbuseGuard installer for Debian/Ubuntu (amd64/arm64).
#
# Installs a hardened Caddy (with the caddy-dns/cloudflare DNS module),
# fail2ban jails that block abusive IPs with nftables, a threat-intel sync,
# an optional AbuseIPDB auto-reporter, and the `abuseguard` control panel.
#
# Usage:
#   sudo ./install.sh                 # download the prebuilt engine (GitHub release)
#   sudo ./install.sh --from-source   # build the Go engine here (needs `go`)
#   sudo ABUSEGUARD_ENGINE_BIN=/path/engine ./install.sh   # use a prebuilt engine
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-jasper-khan/abuseguard}"

# Optional China/slow-network mirror (default off => direct, overseas unaffected).
#   ABUSEGUARD_MIRROR=cn        use the built-in proxy (https://ghfast.top/) for
#                               github.com downloads + fastly.jsdelivr for intel
#   ABUSEGUARD_MIRROR=<prefix>/ use <prefix> as the github.com proxy prefix
ABUSEGUARD_MIRROR="${ABUSEGUARD_MIRROR:-}"
gh_proxy() {
	local u="$1" p
	case "$ABUSEGUARD_MIRROR" in
		""|0|off|no) printf '%s' "$u"; return ;;
		cn|1|yes|on) p="https://ghfast.top/" ;;
		*)           p="$ABUSEGUARD_MIRROR" ;;
	esac
	printf '%s%s' "$p" "$u"
}

CONF_DIR=/etc/caddy-abuseguard
STATE_DIR=/var/lib/caddy-abuseguard
REPORTS_DIR="$STATE_DIR/reports"
LOG_DIR=/var/log/caddy
LIBEXEC_DIR=/usr/local/libexec
ENGINE_BIN="$LIBEXEC_DIR/caddy-abuseguard"
PANEL_BIN=/usr/local/bin/abuseguard
CADDY_BIN=/usr/local/bin/caddy
CADDY_ETC=/etc/caddy
CADDY_ENV="$CADDY_ETC/.env"
CADDYFILE="$CADDY_ETC/Caddyfile"
SNIPPET="$CADDY_ETC/abuseguard.caddy"

FROM_SOURCE=0
[ "${1:-}" = "--from-source" ] && FROM_SOURCE=1

log()  { printf '\033[1;32m[abuseguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[abuseguard]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[abuseguard]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "please run as root (sudo)."

# --- self-bootstrap ----------------------------------------------------------
# When run detached from the repo (e.g. `curl ... install.sh | bash`), the
# asset/engine trees are missing next to this script. Fetch the repo tarball
# into a temp dir and re-exec from there so the one-command install works.
if [ ! -d "$SRC_DIR/engine" ] || [ ! -d "$SRC_DIR/assets" ]; then
	command -v tar >/dev/null 2>&1 || die "tar is required to bootstrap the installer."
	AG_REF="${ABUSEGUARD_REF:-main}"
	AG_TMP="$(mktemp -d)"
	log "fetching repo $ABUSEGUARD_REPO@$AG_REF ..."
	curl -fsSL "$(gh_proxy "https://github.com/$ABUSEGUARD_REPO/archive/refs/heads/$AG_REF.tar.gz")" \
		| tar -xz -C "$AG_TMP" --strip-components=1 \
		|| die "bootstrap download failed (set ABUSEGUARD_REPO / ABUSEGUARD_REF, or clone the repo and run ./install.sh)."
	export ABUSEGUARD_REPO ABUSEGUARD_REF
	exec bash "$AG_TMP/install.sh" "$@"
fi

# --- OS + arch guard ---------------------------------------------------------
. /etc/os-release 2>/dev/null || die "cannot read /etc/os-release."
case " ${ID:-} ${ID_LIKE:-} " in
	*" debian "*|*" ubuntu "*) : ;;
	*) die "unsupported OS '${PRETTY_NAME:-unknown}'. AbuseGuard supports Debian/Ubuntu only." ;;
esac
case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "unsupported architecture '$(uname -m)'. Only amd64/arm64 are supported." ;;
esac
log "target: ${PRETTY_NAME:-Debian/Ubuntu} ($ARCH)"

# --- dependencies ------------------------------------------------------------
log "installing dependencies (fail2ban, nftables, curl, jq, libcap2-bin)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq fail2ban nftables curl jq ca-certificates libcap2-bin >/dev/null

# --- service accounts --------------------------------------------------------
if ! id caddy >/dev/null 2>&1; then
	log "creating system user 'caddy'"
	useradd --system --user-group --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
fi
if ! id abuseguard >/dev/null 2>&1; then
	log "creating system user 'abuseguard'"
	useradd --system --user-group --shell /usr/sbin/nologin abuseguard
fi

# --- directories -------------------------------------------------------------
install -d -m 0755 "$LIBEXEC_DIR" "$CADDY_ETC"
install -d -m 0750 -o root -g abuseguard "$CONF_DIR"
install -d -m 0750 -o abuseguard -g abuseguard "$STATE_DIR" "$REPORTS_DIR"
install -d -m 0750 -o caddy -g caddy "$LOG_DIR"

# --- engine ------------------------------------------------------------------
install_engine() {
	if [ -n "${ABUSEGUARD_ENGINE_BIN:-}" ]; then
		[ -f "$ABUSEGUARD_ENGINE_BIN" ] || die "ABUSEGUARD_ENGINE_BIN '$ABUSEGUARD_ENGINE_BIN' not found."
		log "installing engine from ABUSEGUARD_ENGINE_BIN"
		install -m 0755 "$ABUSEGUARD_ENGINE_BIN" "$ENGINE_BIN"
		return
	fi
	if [ "$FROM_SOURCE" = "1" ]; then
		command -v go >/dev/null 2>&1 || die "--from-source needs the Go toolchain (install 'go' first)."
		log "building engine from source ($SRC_DIR/engine)"
		( cd "$SRC_DIR/engine" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$ENGINE_BIN" . )
		chmod 0755 "$ENGINE_BIN"
		return
	fi
	local url="https://github.com/$ABUSEGUARD_REPO/releases/latest/download/caddy-abuseguard-linux-$ARCH"
	url="$(gh_proxy "$url")"
	log "downloading engine: $url"
	curl -fsSL -o "$ENGINE_BIN" "$url" || die "engine download failed. Use --from-source or set ABUSEGUARD_ENGINE_BIN."
	chmod 0755 "$ENGINE_BIN"
}
install_engine
log "engine: $("$ENGINE_BIN" version 2>/dev/null || echo installed)"

# --- config, whitelist, key (only if absent) ---------------------------------
if [ ! -f "$CONF_DIR/config.json" ]; then
	install -m 0640 -o root -g abuseguard "$SRC_DIR/assets/config/config.json.template" "$CONF_DIR/config.json"
	# In mirror mode, point the big intel blocklist at fastly.jsdelivr (the
	# commit_url stays on api.github.com, which is small and not proxied).
	if [ -n "$ABUSEGUARD_MIRROR" ] && command -v jq >/dev/null 2>&1; then
		tmp="$(mktemp)"
		jq '.intel.source_url = "https://fastly.jsdelivr.net/gh/borestad/blocklist-abuseipdb@{commit}/abuseipdb-s100-14d.ipv4"' \
			"$CONF_DIR/config.json" > "$tmp" && install -m 0640 -o root -g abuseguard "$tmp" "$CONF_DIR/config.json"
		rm -f "$tmp"
		log "mirror mode: intel source set to fastly.jsdelivr"
	fi
	log "wrote $CONF_DIR/config.json"
else
	log "kept existing $CONF_DIR/config.json"
fi
if [ ! -f "$CONF_DIR/whitelist" ]; then
	install -m 0640 -o root -g abuseguard "$SRC_DIR/assets/whitelist.default" "$CONF_DIR/whitelist"
	log "wrote $CONF_DIR/whitelist"
else
	log "kept existing $CONF_DIR/whitelist"
fi
if [ ! -f "$CONF_DIR/abuseipdb-report.key" ]; then
	install -m 0640 -o root -g abuseguard /dev/null "$CONF_DIR/abuseipdb-report.key"
	log "created empty $CONF_DIR/abuseipdb-report.key (set your key via the panel)"
fi
printf '%s\n' "$ABUSEGUARD_REPO" > "$CONF_DIR/repo"; chmod 0644 "$CONF_DIR/repo"

# --- Caddy binary with the cloudflare DNS module -----------------------------
need_caddy=1
if [ -x "$CADDY_BIN" ] && "$CADDY_BIN" list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
	need_caddy=0
fi
if [ "$need_caddy" = "1" ]; then
	log "downloading Caddy with caddy-dns/cloudflare ($ARCH)..."
	curl -fsSL -o "$CADDY_BIN" "https://caddyserver.com/api/download?os=linux&arch=$ARCH&p=github.com/caddy-dns/cloudflare" \
		|| die "Caddy download failed."
	chmod 0755 "$CADDY_BIN"
else
	log "existing Caddy already has the cloudflare module"
fi
setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" || warn "setcap failed; Caddy may need root to bind :80/:443"

# --- Caddy snippet + env + systemd unit --------------------------------------
install -m 0644 "$SRC_DIR/assets/caddy/abuseguard.caddy" "$SNIPPET"
if [ ! -f "$CADDY_ENV" ]; then
	printf 'CF_API_TOKEN=\n' > "$CADDY_ENV"; chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
	log "created $CADDY_ENV (set CF_API_TOKEN via the panel)"
fi
install -m 0644 "$SRC_DIR/assets/systemd/caddy.service" /etc/systemd/system/caddy.service

# --- Caddyfile (only if absent) ----------------------------------------------
if [ ! -f "$CADDYFILE" ]; then
	log "fetching Cloudflare IP ranges for trusted_proxies..."
	CF_V4="$(curl -fsSL https://www.cloudflare.com/ips-v4 2>/dev/null || true)"
	CF_V6="$(curl -fsSL https://www.cloudflare.com/ips-v6 2>/dev/null || true)"
	CF_RANGES="$(printf '%s\n%s\n' "$CF_V4" "$CF_V6" | grep -E '[0-9a-fA-F:.]+/[0-9]+' | tr '\n' ' ' | sed 's/  */ /g; s/ *$//')"
	[ -n "$CF_RANGES" ] || warn "could not fetch Cloudflare ranges; trusting loopback only"
	cat > "$CADDYFILE" <<EOF
# Generated by AbuseGuard install.sh. Edit freely.
#
# The global block trusts your edge proxy so client_ip is the real visitor.
{
	servers {
		trusted_proxies static 127.0.0.1/8 ::1 ${CF_RANGES}
		trusted_proxies_strict
	}
}

# Load the AbuseGuard logging/probe snippet once.
import ${SNIPPET}

# Loopback-only self-test site created by the installer. Safe to remove.
# It proves the log + fail2ban pipeline works without exposing anything.
http://127.0.0.1:8080 {
	bind 127.0.0.1
	import abuseguard
	respond "abuseguard test ok"
}

# --- Add your real sites below, e.g.: ----------------------------------------
# example.com {
# 	import abuseguard
# 	tls {
# 		dns cloudflare {env.CF_API_TOKEN}
# 	}
# 	reverse_proxy localhost:3000
# }
EOF
	log "wrote $CADDYFILE"
else
	log "kept existing $CADDYFILE (add 'import $SNIPPET' + 'import abuseguard' yourself)"
fi

# ensure the access log exists and is caddy-writable before fail2ban starts
[ -e "$LOG_DIR/abuseguard-access.json" ] || install -m 0640 -o caddy -g caddy /dev/null "$LOG_DIR/abuseguard-access.json"

# --- fail2ban assets ---------------------------------------------------------
log "installing fail2ban filters / action / jails"
install -m 0644 "$SRC_DIR"/assets/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/
install -m 0644 "$SRC_DIR"/assets/fail2ban/action.d/*.conf /etc/fail2ban/action.d/
install -m 0644 "$SRC_DIR/assets/fail2ban/jail.d/caddy-abuseguard.local" /etc/fail2ban/jail.d/caddy-abuseguard.local

# --- systemd timers + panel --------------------------------------------------
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.service" /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.timer"   /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.service"   /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.timer"     /etc/systemd/system/
install -m 0755 "$SRC_DIR/abuseguard.sh" "$PANEL_BIN"

# --- validate + enable -------------------------------------------------------
log "validating Caddyfile"
"$CADDY_BIN" validate --config "$CADDYFILE" --adapter caddyfile >/dev/null || die "Caddyfile validation failed."

systemctl daemon-reload
log "enabling + starting services"
# reload-or-restart (not just enable --now) so a re-run reloads the freshly
# written Caddyfile / fail2ban jails even when the service is already running.
systemctl enable caddy >/dev/null 2>&1 || true
systemctl reload-or-restart caddy || die "failed to start caddy (see: journalctl -u caddy)"
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl reload-or-restart fail2ban || warn "fail2ban did not start cleanly (see: journalctl -u fail2ban)"
systemctl enable --now caddy-abuseguard-report.timer caddy-abuseguard-sync.timer >/dev/null 2>&1 || true

log "AbuseGuard installed."
cat <<EOF

  Panel:        sudo abuseguard
  Caddyfile:    $CADDYFILE
  Whitelist:    $CONF_DIR/whitelist
  Config:       $CONF_DIR/config.json
  Access log:   $LOG_DIR/abuseguard-access.json

Next steps:
  1. sudo abuseguard  ->  option 7 sets your Cloudflare API token (for TLS),
     option 6 sets your AbuseIPDB key (only needed for auto-reporting).
  2. Add your sites to $CADDYFILE (put 'import abuseguard' inside each block),
     then: sudo systemctl reload caddy

SECURITY: Caddy adds no authentication. Any site you expose is public unless
you add auth yourself. The bundled self-test site binds 127.0.0.1 only.
EOF
