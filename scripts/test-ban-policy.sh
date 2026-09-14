#!/usr/bin/env bash
# Exercise the panel's real allowlist gate without touching a running jail.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
	for file in engine functions.sh config.json whitelist calls; do
		rm -f -- "$TMP/$file"
	done
	rmdir -- "$TMP"
}
trap cleanup EXIT
(cd "$ROOT/engine" && go build -o "$TMP/engine" .)
for name in act_ban wl_valid; do
	awk -v signature="$name() {" '
		index($0, signature) == 1 { printing=1 }
		printing { print }
		printing && /^}$/ { exit }
	' "$ROOT/abuseguard.sh" >> "$TMP/functions.sh"
done
source "$TMP/functions.sh"
ENGINE="$TMP/engine"
export ABUSEGUARD_CONFIG="$TMP/config.json"
printf '{"allowlist_file":"%s"}\n' "$TMP/whitelist" > "$ABUSEGUARD_CONFIG"
printf '192.0.2.10\n2001:db8:1::/48\n' > "$TMP/whitelist"
pause() { :; }
fail2ban-client() { printf '%s\n' "$*" >> "$TMP/calls"; }
fail() { echo "ban policy test failed: $*" >&2; exit 1; }
for ip in 192.0.2.10 192.0.2.0/24 2001:db8:1::1 2001:db8::/32; do
	: > "$TMP/calls"
	act_ban <<< "$ip" >/dev/null
	[ ! -s "$TMP/calls" ] || fail "whitelisted address/network reached banip: $ip"
done
: > "$TMP/calls"
act_ban <<< '198.51.100.0/24' >/dev/null
[ ! -s "$TMP/calls" ] || fail 'unsupported CIDR target reached banip'
: > "$TMP/calls"
act_ban <<< '198.51.100.10' >/dev/null
grep -qx 'set caddy-intel banip 198.51.100.10' "$TMP/calls" || fail "non-whitelisted IP was not banned"
printf 'invalid-whitelist\n' > "$TMP/whitelist"
: > "$TMP/calls"
act_ban <<< '198.51.100.10' >/dev/null
[ ! -s "$TMP/calls" ] || fail 'corrupt whitelist allowed a ban'
rm -f -- "$TMP/whitelist"
act_ban <<< '198.51.100.10' >/dev/null
[ ! -s "$TMP/calls" ] || fail 'missing whitelist allowed a ban'
echo 'ban policy tests: pass'
