#!/usr/bin/env bash
# Panel behavior with command doubles; --kernel checks real nft transactions
# inside an isolated network namespace on Linux (requires root + nftables).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
	rm -f -- "$TMP/panel.sh"
	rm -f -- "$TMP/firewall.nft"
	rm -f -- "$TMP/live.nft"
	rm -f -- "$TMP/nft.calls"
	rm -f -- "$TMP/systemctl.calls"
	rm -f -- "$TMP/kernel.nft"
	rm -f -- "$TMP/sshd_config"
	rmdir -- "$TMP/dropin" 2>/dev/null || true
	rmdir -- "$TMP"
}
trap cleanup EXIT
awk '/^# The panel needs root/{exit} {print}' "$ROOT/abuseguard.sh" > "$TMP/panel.sh"

if [ "${1:-}" = --kernel ]; then
	unshare --net bash -s -- "$TMP/panel.sh" "$TMP/kernel.nft" <<'KERNEL'
set -euo pipefail
source "$1"
rules="$2"
# Stand in for Fail2Ban's independent table, including an IPv4 ban set.
nft -f - <<'NFT'
table inet f2b-table {
	set banned { type ipv4_addr; elements = { 198.51.100.10 }; }
	chain input {
		type filter hook input priority -1; policy accept;
		ip saddr @banned drop
	}
}
NFT
before="$(nft list table inet f2b-table)"
firewall_check_conflicts
# The installer's noninteractive entry initializes the same persistent rules
# and boot service as the panel. Use real nft, with only systemd/SSH doubled.
CONF_DIR="$(dirname "$rules")"
FIREWALL_FILE="$rules"
ss() { return 0; }
sshd() { printf 'port 2222\n'; }
SSH_CONNECTION=''
systemctl() {
	case "$1" in
		start) nft -f "$FIREWALL_FILE" ;;
		enable) return 0 ;;
		*) return 1 ;;
	esac
}
firewall_apply </dev/null
nft list table inet caddy_abuseguard | grep -q 'tcp dport 2222 accept'
if nft list table inet caddy_abuseguard | grep -q 'tcp dport 80 accept'; then exit 1; fi
firewall_change_port open tcp 54321 </dev/null
firewall_change_port open udp 54321 </dev/null
nft list table inet caddy_abuseguard | grep -q 'tcp dport 54321 accept'
nft list table inet caddy_abuseguard | grep -q 'udp dport 54321 accept'
printf 'tcp 22\ntcp 8080\nudp 443\n' | firewall_render > "$rules"
nft -c -f "$rules"
nft -f "$rules"
nft list table inet caddy_abuseguard | grep -q 'tcp dport 8080 accept'
printf 'tcp 22\nudp 443\n' | firewall_render > "$rules"
nft -f "$rules"
nft -f "$rules" # repeat application must not duplicate rules
[ "$(nft list table inet caddy_abuseguard | grep -c 'tcp dport 22 accept')" = 1 ]
if nft list table inet caddy_abuseguard | grep -q 'dport 8080'; then exit 1; fi
[ "$(nft list table inet f2b-table)" = "$before" ]
nft delete table inet caddy_abuseguard
[ "$(nft list table inet f2b-table)" = "$before" ]
systemctl start "$FIREWALL_SERVICE" # boot restores the saved policy
nft list table inet caddy_abuseguard | grep -q 'tcp dport 22 accept'
nft 'add table inet foreign_filter; add chain inet foreign_filter input { type filter hook input priority 0; policy drop; }'
if firewall_apply </dev/null; then echo 'conflicting policy was accepted' >&2; exit 1; fi
nft list table inet foreign_filter | grep -q 'policy drop'
nft list table inet caddy_abuseguard | grep -q 'tcp dport 22 accept'
echo 'firewall kernel transaction tests: pass'
KERNEL
	exit
fi

source "$TMP/panel.sh"
CONF_DIR="$TMP"
FIREWALL_FILE="$TMP/firewall.nft"
SSHD_MAIN="$TMP/sshd_config"
SSHD_DROPIN_DIR="$TMP/dropin"
: > "$SSHD_MAIN"
mkdir "$SSHD_DROPIN_DIR"
CHECK_FAIL=0
APPLY_FAIL=0
START_FAIL=0
RULESET_JSON='{"nftables":[]}'
SSH_CONNECTION='192.0.2.1 54321 192.0.2.2 2222'
pause() { :; }
ss() { printf 'LISTEN 0 128 [::]:2222 *:* users:(("sshd",pid=1,fd=3))\n'; }
sshd() { printf 'port 22\nport 2200\n'; }
fail() { echo "firewall test failed: $*" >&2; exit 1; }
nft() {
	printf '%s\n' "$*" >> "$TMP/nft.calls"
	case "$*" in
		'-j list ruleset') printf '%s\n' "$RULESET_JSON" ;;
		'list tables') return 0 ;;
		'list table inet caddy_abuseguard') [ -f "$TMP/live.nft" ] ;;
		'-c -f '*) [ "$CHECK_FAIL" = 0 ] ;;
		'-f '*) [ "$APPLY_FAIL" = 0 ] && cp -- "$2" "$TMP/live.nft" ;;
		'delete table inet caddy_abuseguard') rm -f -- "$TMP/live.nft" ;;
		*) fail "unexpected nft command: $*" ;;
	esac
}
systemctl() {
	printf '%s\n' "$*" >> "$TMP/systemctl.calls"
	case "$1" in
		start) [ "$START_FAIL" = 0 ] && nft -f "$FIREWALL_FILE" ;;
		enable) return 0 ;;
		is-active) return 1 ;;
		*) fail "unexpected systemctl command: $*" ;;
	esac
}
fail2ban-client() { fail 'port management must not modify Fail2Ban'; }

# An existing filtering policy must not be silently layered with ours.
RULESET_JSON='{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}}]}'
if firewall_apply </dev/null >/dev/null 2>&1; then fail 'ignored existing default-drop policy'; fi
[ ! -e "$FIREWALL_FILE" ] && [ ! -e "$TMP/live.nft" ] || fail 'conflict changed firewall'
RULESET_JSON='{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","hook":"input","policy":"accept"}},{"rule":{"family":"ip","table":"filter","chain":"INPUT","expr":[{"jump":{"target":"ufw-before-input"}}]}}]}'
if firewall_apply </dev/null >/dev/null 2>&1; then fail 'ignored existing input rules'; fi
RULESET_JSON='invalid-json'
if firewall_apply </dev/null >/dev/null 2>&1; then fail 'ignored unreadable nft state'; fi
# Empty accepting chains and forwarded/container traffic do not compete with
# the input policy; Fail2Ban and our own table are managed by AbuseGuard.
RULESET_JSON='{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"accept"}},{"chain":{"family":"ip","table":"docker","name":"forward","hook":"forward","policy":"drop"}},{"chain":{"family":"inet","table":"f2b-table","name":"input","hook":"input","policy":"accept"}},{"rule":{"family":"inet","table":"f2b-table","chain":"input"}},{"chain":{"family":"inet","table":"caddy_abuseguard","name":"input","hook":"input","policy":"drop"}}]}'
firewall_apply </dev/null >/dev/null
for rule in 'tcp 22 any' 'tcp 2200 any' 'tcp 2222 any' 'tcp 443 any' 'udp 443 any'; do
	firewall_ports | grep -qxF "$rule" || fail "missing initial rule: $rule"
done
if firewall_ports | grep -qx 'tcp 80 any'; then fail 'initial config opened TCP 80'; fi
cmp "$FIREWALL_FILE" "$TMP/live.nft" || fail 'activation did not load saved config'
grep -qxF "enable $FIREWALL_SERVICE" "$TMP/systemctl.calls" || fail 'boot restore not enabled'

# Add/remove ports and repeated additions preserve unrelated rules.
firewall_change_port open <<< $'tcp\n8080\n' >/dev/null
firewall_change_port open <<< $'tcp\n08080\n' >/dev/null
[ "$(firewall_ports | grep -cx 'tcp 8080 any')" = 1 ] || fail 'duplicate/noncanonical port'
firewall_change_port open <<< $'tcp\n80\n' >/dev/null
firewall_apply </dev/null >/dev/null
firewall_ports | grep -qx 'tcp 80 any' || fail 'update closed an explicitly opened TCP 80'
firewall_change_port close tcp 80 any >/dev/null
if firewall_ports | grep -qx 'tcp 80 any'; then fail 'port was not closed'; fi
firewall_ports | grep -qx 'udp 443 any' || fail 'unrelated UDP rule lost'
cmp "$FIREWALL_FILE" "$TMP/live.nft" || fail 'port change was not applied'
grep -qE '^[[:space:]]*tcp dport 22 accept' "$FIREWALL_FILE" || fail 'allow rule is not dual-stack'
if grep -qE '^[[:space:]]*meta nfproto ipv4 tcp' "$FIREWALL_FILE"; then fail 'allow rule narrowed to IPv4'; fi
grep -q 'meta nfproto ipv6 drop' "$FIREWALL_FILE" || fail 'IPv6 inbound is not closed by default'

# Per-source rules: the same port can be limited to one address and removed alone.
firewall_change_port open tcp 8443 any >/dev/null
firewall_change_port open tcp 8443 203.0.113.5 >/dev/null
firewall_ports | grep -qx 'tcp 8443 203.0.113.5' || fail 'source rule missing'
firewall_change_port close tcp 8443 203.0.113.5 >/dev/null
firewall_ports | grep -qx 'tcp 8443 any' || fail 'closing one source dropped the port rule'
if firewall_ports | grep -qx 'tcp 8443 203.0.113.5'; then fail 'source rule was not closed'; fi
firewall_change_port close tcp 8443 any >/dev/null


# Exercise the real CLI dispatch with the same isolated command doubles.
entry="$(sed -n '/^case "${1:-}" in$/,/^esac$/p' "$ROOT/abuseguard.sh")"
run_cli() { ( set -- "$@"; eval "$entry"; ); }
run_cli --firewall-open tcp 54321 </dev/null >/dev/null
run_cli --firewall-open tcp 054321 </dev/null >/dev/null 2>&1 && fail 'accepted an overlong port'
run_cli --firewall-open udp 54321 </dev/null >/dev/null
run_cli --firewall-open tcp 54321 </dev/null >/dev/null
for rule in 'tcp 54321 any' 'udp 54321 any'; do
	[ "$(firewall_ports | grep -cxF "$rule")" = 1 ] || fail "CLI missing or duplicated $rule"
done
cmp "$FIREWALL_FILE" "$TMP/live.nft" || fail 'CLI did not persist and apply ports'
saved="$(cat "$FIREWALL_FILE")"
for args in '' 'tcp' 'tcp 0' 'udp 65536' 'invalid 80' 'tcp 80;drop' 'tcp 80 extra'; do
	if run_cli --firewall-open $args </dev/null >/dev/null 2>&1; then fail "CLI accepted invalid arguments: $args"; fi
done
if run_cli --firewall-open tcp '' </dev/null >/dev/null 2>&1; then fail 'CLI accepted an empty port'; fi
if firewall_change_port open tcp 8443 example.com >/dev/null 2>&1; then fail 'accepted a hostname source'; fi
for p in 22 2200 2222; do
	if firewall_change_port close tcp "$p" any >/dev/null; then fail "closed SSH port $p"; fi
done
for input in $'tcp\n0\n' $'tcp\n65536\n' $'tcp\n80;drop\n' $'invalid\n80\n'; do
	if firewall_change_port open <<< "$input" >/dev/null; then fail "accepted invalid input"; fi
done
[ "$(cat "$FIREWALL_FILE")" = "$saved" ] || fail 'rejected input changed config'
CHECK_FAIL=1
if run_cli --firewall-open udp 53 </dev/null >/dev/null; then fail 'ignored nft validation error'; fi
CHECK_FAIL=0
APPLY_FAIL=1
if firewall_change_port open <<< $'udp\n53\n' >/dev/null; then fail 'ignored nft apply error'; fi
APPLY_FAIL=0
[ "$(cat "$FIREWALL_FILE")" = "$saved" ] || fail 'nft failure changed saved config'
[ "$(cat "$TMP/live.nft")" = "$saved" ] || fail 'nft failure changed live config'
mv() { return 1; }
if firewall_change_port open <<< $'udp\n53\n' >/dev/null; then fail 'ignored persistence error'; fi
unset -f mv
[ "$(cat "$FIREWALL_FILE")" = "$saved" ] || fail 'persistence failure changed saved config'
[ "$(cat "$TMP/live.nft")" = "$saved" ] || fail 'persistence failure did not restore live rules'

# No SSH detection means no new restrictive rules, rather than guessing port 22.
ss() { return 1; }
sshd() { return 1; }
SSH_CONNECTION=''
if firewall_change_port open <<< $'udp\n53\n' >/dev/null 2>&1; then fail 'changed rules without SSH detection'; fi
sshd() { printf 'port 2222\n'; }

# Re-running installation preserves the user's changes and restores missing
# live rules instead of leaving an optional firewall inactive after updating.
nft delete table inet caddy_abuseguard
: > "$TMP/systemctl.calls"
START_FAIL=1
if firewall_apply </dev/null >/dev/null; then fail 'ignored service start error'; fi
if grep -q '^enable ' "$TMP/systemctl.calls"; then fail 'failed start enabled boot restore'; fi
START_FAIL=0
firewall_apply </dev/null >/dev/null
cmp "$FIREWALL_FILE" "$TMP/live.nft" || fail 'update did not restore saved rules'
firewall_ports | grep -qx 'tcp 8080 any' || fail 'update lost a user-added port'
firewall_ports | grep -qx 'udp 54321 any' || fail 'update lost a script-opened port'
if firewall_ports | grep -qx 'tcp 80 any'; then fail 'update reopened a user-closed port'; fi
if grep -q 'flush ruleset' "$TMP/nft.calls"; then fail 'flushed unrelated rules'; fi
ss() { printf 'LISTEN 0 128 [::]:2222 *:* users:(("sshd",pid=1,fd=3))
'; }
sshd() { printf 'port 22
port 2200
'; }
# Reapplying rules must not widen a restricted SSH port.
printf 'tcp 22 203.0.113.5/32\ntcp 2222 any\ntcp 2200 any\n' | firewall_render > "$FIREWALL_FILE"
firewall_apply </dev/null >/dev/null
firewall_ports | grep -qx 'tcp 22 203.0.113.5/32' || fail 'reapply dropped the SSH source restriction'
if firewall_ports | grep -qx 'tcp 22 any'; then fail 'reapply widened a restricted SSH port'; fi

# A rollback close skips SSH handling and must not re-add the port.
firewall_change_port close tcp 22 203.0.113.5/32 no-ssh >/dev/null
if firewall_ports | grep -qx 'tcp 22 203.0.113.5/32'; then fail 'rollback close kept the rule'; fi
if firewall_ports | grep -qx 'tcp 22 any'; then fail 'rollback close re-added the port'; fi
firewall_apply </dev/null >/dev/null
firewall_ports | grep -qx 'tcp 22 any' || fail 'apply did not restore the SSH port'

# Family toggles persist in the first line and gate each family.
firewall_set_policy ipv6 1 >/dev/null || fail 'could not enable IPv6 inbound'
grep -q '^# policy ipv4-in=1 ipv6-in=1' "$FIREWALL_FILE" || fail 'IPv6 policy not saved'
if grep -q 'meta nfproto ipv6 drop' "$FIREWALL_FILE"; then fail 'IPv6 drop remained after enabling'; fi
# A second panel can change policy while this panel remains open.
firewall_policy_load
(firewall_set_policy ipv4 0 >/dev/null) || fail 'second panel could not disable IPv4'
firewall_change_port open tcp 8787 any >/dev/null
grep -q '^# policy ipv4-in=0 ipv6-in=1' "$FIREWALL_FILE" || fail 'port change restored stale IPv4 policy'
firewall_set_policy ipv4 1 >/dev/null || fail 'could not restore IPv4 for subsequent checks'
firewall_set_policy ipv6 0 >/dev/null || fail 'could not disable IPv6 inbound'
grep -q 'meta nfproto ipv6 drop' "$FIREWALL_FILE" || fail 'IPv6 drop missing after disabling'
firewall_set_policy ipv4 0 >/dev/null || fail 'could not disable IPv4 inbound'
grep -q '^# policy ipv4-in=0' "$FIREWALL_FILE" || fail 'IPv4 policy not saved'
grep -q 'meta nfproto ipv4 drop' "$FIREWALL_FILE" || fail 'IPv4 drop missing after disabling'
firewall_set_policy ipv4 1 >/dev/null || fail 'could not enable IPv4 inbound'
if grep -q 'meta nfproto ipv4 drop' "$FIREWALL_FILE"; then fail 'IPv4 drop remained after enabling'; fi
CHECK_FAIL=1
if firewall_set_policy ipv4 0 >/dev/null 2>&1; then fail 'ignored an nft validation error on a policy change'; fi
CHECK_FAIL=0
grep -q '^# policy ipv4-in=1' "$FIREWALL_FILE" || fail 'a failed policy change altered the saved policy'
RULESET_JSON='{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"drop"}}]}'
if firewall_set_policy ipv4 0 >/dev/null 2>&1; then fail 'policy change ignored a conflicting input policy'; fi
RULESET_JSON='{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","policy":"accept"}},{"chain":{"family":"ip","table":"docker","name":"forward","hook":"forward","policy":"drop"}},{"chain":{"family":"inet","table":"f2b-table","name":"input","hook":"input","policy":"accept"}},{"rule":{"family":"inet","table":"f2b-table","chain":"input"}},{"chain":{"family":"inet","table":"caddy_abuseguard","name":"input","hook":"input","policy":"drop"}}]}'
grep -q '^# policy ipv4-in=1' "$FIREWALL_FILE" || fail 'a conflicting policy change altered the saved policy'

# IPv6 source rules render and round-trip.
firewall_change_port open tcp 8443 2001:db8::5 >/dev/null
grep -q 'ip6 saddr 2001:db8::5 tcp dport 8443 accept' "$FIREWALL_FILE" || fail 'IPv6 source not rendered'
firewall_ports | grep -qx 'tcp 8443 2001:db8::5' || fail 'IPv6 source not parsed'
firewall_change_port close tcp 8443 2001:db8::5 >/dev/null
if firewall_ports | grep -qx 'tcp 8443 2001:db8::5'; then fail 'IPv6 source not closed'; fi
if grep -q 'hook output' "$FIREWALL_FILE"; then fail 'an output chain was added'; fi

echo 'firewall panel tests: pass'
