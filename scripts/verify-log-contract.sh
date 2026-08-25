#!/usr/bin/env bash
# Verify the Caddy-log <-> fail2ban-filter contract.
#
#   scripts/verify-log-contract.sh /path/to/caddy
#
# AbuseGuard's whole detection chain rests on an unwritten contract: the
# (abuseguard) Caddy snippet must emit an access-log line whose fields still
# match what the fail2ban filters grep for (`client_ip`, `proto`, and our
# appended caddy_abuseguard_* tags). Nothing in Caddy guarantees those names
# across versions, and CI rebuilds Caddy against upstream latest -- so if the
# schema ever changes, every jail would silently stop banning while the service
# still looks healthy.
#
# This script closes that gap: it drives real traffic through the real snippet
# with the given Caddy binary, then runs the REAL filter files against the
# produced log with fail2ban-regex. A mismatch fails loudly, which lets the
# release job abort BEFORE publishing (keeping the last known-good binary).
#
# Requires: the given caddy binary, fail2ban-regex, curl. Run from the repo root.
set -euo pipefail

CADDY="${1:?usage: verify-log-contract.sh /path/to/caddy}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNIPPET="$REPO_ROOT/assets/caddy/abuseguard.caddy"
FILTER_DIR="$REPO_ROOT/assets/fail2ban/filter.d"
LOG=/var/log/caddy/abuseguard-access.json      # hardcoded in the snippet
PORT=8080
DATEPATTERN='"ts":{EPOCH}'

ok()   { printf '\033[1;32m[contract]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[contract]\033[0m %s\n' "$*" >&2; exit 1; }

command -v fail2ban-regex >/dev/null || fail "fail2ban-regex not found (apt-get install fail2ban)"
[ -f "$SNIPPET" ] || fail "snippet not found: $SNIPPET"
[ -x "$CADDY" ]   || fail "caddy binary not executable: $CADDY"

TMP="$(mktemp -d)"
cleanup() {
	[ -n "${CADDY_PID:-}" ] && kill "$CADDY_PID" 2>/dev/null || true
	wait "${CADDY_PID:-}" 2>/dev/null || true
	rm -f "$TMP/Caddyfile"; rmdir "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

# The log path is baked into the snippet, so make it writable for this run.
install -d -m 0755 "$(dirname "$LOG")" 2>/dev/null || sudo install -d -m 0777 "$(dirname "$LOG")"
: > "$LOG" 2>/dev/null || { sudo touch "$LOG"; sudo chmod 0666 "$LOG"; }

# h2c so the HTTP/2 filter can be exercised over cleartext too.
cat > "$TMP/Caddyfile" <<CADDYFILE
{
	admin off
	servers {
		protocols h1 h2c
	}
}

import $SNIPPET

http://127.0.0.1:$PORT {
	bind 127.0.0.1
	import abuseguard
	respond "contract test ok"
}
CADDYFILE

"$CADDY" validate --config "$TMP/Caddyfile" --adapter caddyfile >/dev/null 2>&1 \
	|| fail "the snippet no longer adapts with this Caddy build (run: caddy validate)"

"$CADDY" run --config "$TMP/Caddyfile" >"$TMP/caddy.out" 2>&1 &
CADDY_PID=$!
for _ in $(seq 1 50); do
	curl -fsS --max-time 2 "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && break
	sleep 0.2
done

# real traffic: a normal request, an HTTP/1.1 probe, an HTTP/2 (h2c) probe
curl -fsS --max-time 5 "http://127.0.0.1:$PORT/"     >/dev/null || fail "caddy did not serve (see $TMP/caddy.out)"
curl -fsS --max-time 5 "http://127.0.0.1:$PORT/.env" >/dev/null || fail "probe request failed"
H2=1
curl -fsS --max-time 5 --http2-prior-knowledge "http://127.0.0.1:$PORT/.env" >/dev/null 2>&1 || H2=0
sleep 1                     # let the log writer flush
kill "$CADDY_PID" 2>/dev/null || true
wait "$CADDY_PID" 2>/dev/null || true
CADDY_PID=""

[ -s "$LOG" ] || fail "no access log was written to $LOG -- the snippet's log directive changed?"

# assert the raw fields the filters depend on are still present
grep -q '"client_ip"' "$LOG" || fail "log has no \"client_ip\" field -- Caddy renamed it; every filter would stop matching"
grep -q '"proto"'     "$LOG" || fail "log has no \"proto\" field -- the probe-h1/h2 filters would stop matching"
grep -q '"caddy_abuseguard_site":"protected"' "$LOG" || fail "our log_append tag is missing -- log_append semantics changed"
grep -q '"caddy_abuseguard_probe":"web-probe"' "$LOG" || fail "the probe tag is missing -- the path matcher or log_append changed"
ok "log fields present (client_ip, proto, abuseguard tags)"

# now the authoritative check: the REAL filters against the REAL log
check_filter() {
	local name="$1" min="$2" out n
	out="$(fail2ban-regex --datepattern "$DATEPATTERN" "$LOG" "$FILTER_DIR/$name" 2>&1)" || fail "fail2ban-regex failed for $name"
	n="$(printf '%s' "$out" | sed -n 's/^Success, the total number of match is \([0-9]*\).*/\1/p' | head -1)"
	[ -n "$n" ] || n="$(printf '%s' "$out" | sed -n 's/.*Lines: .*\([0-9]\+\) matched.*/\1/p' | head -1)"
	if [ -z "$n" ] || [ "$n" -lt "$min" ]; then
		printf '%s\n' "$out" | tail -25 >&2
		fail "$name matched ${n:-0} line(s), expected >= $min -- the log format and this filter no longer agree"
	fi
	ok "$name matched $n line(s)"
}

check_filter caddy-abuseguard-any.conf 2
check_filter caddy-abuseguard-probe-h1.conf 1
if [ "$H2" = 1 ]; then
	check_filter caddy-abuseguard-probe-h2.conf 1
else
	printf '\033[1;33m[contract]\033[0m %s\n' "h2c request unavailable; skipped probe-h2 (same structure as probe-h1, only the proto literal differs)"
fi

ok "log <-> filter contract holds for $("$CADDY" version | head -1)"
