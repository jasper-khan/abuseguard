#!/usr/bin/env bash
# Real kernel + native fail2ban tests for the AbuseGuard policy applier.
#
# Runs only on Linux as root, inside a private network namespace with a private
# fail2ban server/config directory: no host firewall, jail or daemon is touched.
# CI: sudo --preserve-env=ABUSEGUARD_ENGINE_BIN bash ./scripts/test-native-policy.sh --kernel
#
# Proves behaviour, not source text:
#   - feed IPv4 entries are dropped before the port firewall
#   - one whitelist entry and one overlapping CIDR return only from the intel
#     chain (an independent drop rule still applies)
#   - feed removal unblocks an address; empty/invalid exports keep the last
#     good kernel+disk policy
#   - a broken fail2ban config cannot prevent boot restore of that snapshot
#   - a post-swap installer failure restores the old engine+config and detection
#   - generated fail2ban ignoreip comes from the same whitelist and clears an
#     existing behavioural ban when an address is added
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLIER="$ROOT/assets/policy/abuseguard-policy.sh"
TMP="$(mktemp -d)"
CONF="$TMP/conf"
STATE="$TMP/state"
F2B="$TMP/f2b"
NS_H=ag-policy-host
NS_C=ag-policy-client
VETH_H=ag-policy-host0
VETH_C=ag-policy-cli0
HOST_IP=10.200.0.1
ALLOW_IP=10.200.0.2
CIDR_IP=10.200.0.4
BLOCK_IP=10.200.0.6
SSH_ONLY_IP=10.200.0.8
MIGRATE_IP=10.200.0.10
IDLE_IP=10.200.0.12
IDLE2_IP=10.200.0.13
IDLE3_IP=10.200.0.14
RECOVER_IP=10.200.0.16
F2B_PID=""

cleanup() {
	if [ -f "$F2B/fail2ban.pid" ]; then
		kill "$(cat "$F2B/fail2ban.pid" 2>/dev/null)" 2>/dev/null || true
	fi
	[ -z "$F2B_PID" ] || kill "$F2B_PID" 2>/dev/null || true
	[ -z "${F2B_ROLLBACK_DIR:-}" ] || rm -rf -- "$F2B_ROLLBACK_DIR"
	ip netns del "$NS_C" 2>/dev/null || true
	ip netns del "$NS_H" 2>/dev/null || true
	rm -rf -- "$TMP"
}
trap cleanup EXIT

fail() { echo "native-policy test failed: $*" >&2; exit 1; }

[ "${1:-}" = --kernel ] || { echo "usage: sudo bash $0 --kernel" >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo "requires Linux" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
for bin in nft ip fail2ban-server fail2ban-client python3; do
	command -v "$bin" >/dev/null 2>&1 || { echo "missing: $bin" >&2; exit 2; }
done

ENGINE="${ABUSEGUARD_ENGINE_BIN:-/usr/local/libexec/caddy-abuseguard}"
if [ ! -x "$ENGINE" ]; then
	command -v go >/dev/null 2>&1 \
		|| { echo "engine not found; set ABUSEGUARD_ENGINE_BIN or install go" >&2; exit 1; }
	( cd "$ROOT/engine" && CGO_ENABLED=0 go build -trimpath -o "$TMP/engine" . ) \
		|| fail "could not build the engine"
	ENGINE="$TMP/engine"
fi
[ -x "$APPLIER" ] || fail "missing applier: $APPLIER"

mkdir -p "$CONF" "$STATE" "$F2B/filter.d" "$F2B/action.d" "$F2B/jail.d" "$TMP/bin"

# Engine config: small test feed bounds; the whitelist is the single source.
cat > "$CONF/config.json" <<EOF
{
  "allowlist_file": "$CONF/whitelist",
  "paths": {"state_dir": "$STATE", "reports_dir": "$STATE/reports"},
  "intel": {"min_entries": 1, "max_entries": 1000}
}
EOF
cat > "$CONF/whitelist" <<EOF
# trusted sources
127.0.0.0/8
::1
$ALLOW_IP
$CIDR_IP/31
2001:db8::/64
EOF
cat > "$F2B/fail2ban.conf" <<EOF
[Definition]
loglevel = INFO
socket = $F2B/socket
pidfile = $F2B/fail2ban.pid
dbfile = $F2B/fail2ban.sqlite3
logtarget = $F2B/fail2ban.log
EOF
cat > "$F2B/jail.conf" <<EOF
[DEFAULT]
enabled = false
ignoreip = 127.0.0.1/8 ::1
bantime = 90
findtime = 60
maxretry = 1
backend = polling
usedns = no
EOF
cat >> "$F2B/jail.conf" <<EOF

[caddy-rate-local]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest
EOF
cat > "$F2B/filter.d/agtest.conf" <<'EOF'
[Definition]
failregex = ^ABUSE <HOST>$
ignoreregex =
EOF
# Admin-managed native exemption: applies to sshd only, never to the Web jails.
cat > "$F2B/jail.d/native-sshd.local" <<EOF
[sshd]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest
ignoreip = $SSH_ONLY_IP
EOF
cat > "$F2B/action.d/agtest.conf" <<'EOF'
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = /bin/true
actionunban = /bin/true
EOF
: > "$F2B/access.log"
cat > "$TMP/bin/fail2ban-client" <<EOF
#!/bin/sh
exec $(command -v fail2ban-client) -c "$F2B" -s "$F2B/socket" "\$@"
EOF
chmod 0755 "$TMP/bin/fail2ban-client"

apply() {
	ip netns exec "$NS_H" env \
		AG_CONF_DIR="$CONF" AG_STATE_DIR="$STATE" AG_ENGINE="$ENGINE" \
		AG_F2B_JAIL_DIR="$F2B/jail.d" PATH="$TMP/bin:$PATH" \
		bash "$APPLIER" apply
}

f2bc() { PATH="$TMP/bin:$PATH" fail2ban-client "$@"; }
banned_list() { f2bc status caddy-rate-local 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p'; }
wait_ban() {
	local ip="$1" i
	for i in {1..100}; do
		banned_list | tr ' ' '\n' | grep -qxF "$ip" && return 0
		sleep 0.1
	done
	return 1
}
wait_unban() {
	local ip="$1" i
	for i in {1..100}; do
		banned_list | tr ' ' '\n' | grep -qxF "$ip" || return 0
		sleep 0.1
	done
	return 1
}
start_f2b() {
	fail2ban-server -c "$F2B" -s "$F2B/socket" -x -b || fail "could not start private fail2ban"
	local i
	for i in {1..100}; do f2bc ping >/dev/null 2>&1 && return 0; sleep 0.1; done
	fail "private fail2ban did not start"
}
stop_f2b() {
	f2bc stop >/dev/null 2>&1 || true
	local i
	for i in {1..100}; do f2bc ping >/dev/null 2>&1 || return 0; sleep 0.1; done
	fail "private fail2ban did not stop"
}
# Whether the generated ignoreip file gives JAIL an entry containing IP.
section_has() { # JAIL IP
	awk -v jail="$1" -v ip="$2" '
		/^\[/ { s = $0; gsub(/[][ ]/, "", s) }
		s == jail && index($0, ip) { found = 1 }
		END { exit !found }
	' "$F2B/jail.d/zzz-caddy-abuseguard-policy.local"
}
sshd_banned() { f2bc status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' ' '\n' | grep -qxF "$1"; }

# --- isolated packet path -----------------------------------------------------
# The applier runs in NS_H (where input rules live); the sender is in NS_C.
# Neither namespace is the root one, so no host firewall is touched.
ip netns add "$NS_H"
ip netns add "$NS_C"
ip link add "$VETH_H" type veth peer name "$VETH_C"
ip link set "$VETH_H" netns "$NS_H"
ip link set "$VETH_C" netns "$NS_C"
ip -n "$NS_H" addr add "$HOST_IP/24" dev "$VETH_H"
ip -n "$NS_H" link set "$VETH_H" up
ip -n "$NS_C" link set lo up
ip -n "$NS_C" link set "$VETH_C" up
for ip in "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" "$SSH_ONLY_IP"; do
	ip -n "$NS_C" addr add "$ip/24" dev "$VETH_C"
done
ping_ok() { ip netns exec "$NS_C" ping -c1 -W1 -I "$1" "$HOST_IP" >/dev/null 2>&1; }

# --- first apply: feed drops, IP + overlapping CIDR exceptions --------------
# A bootstrap apply without any feed is allowed only while no policy exists.
apply >/dev/null || fail "bootstrap apply without a feed failed"
ping_ok "$ALLOW_IP" || fail "bootstrap whitelist exception was dropped"
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "initial policy apply failed"
ping_ok "$ALLOW_IP" || fail "whitelisted single IP was dropped"
ping_ok "$CIDR_IP" || fail "whitelisted CIDR address was dropped"
ping_ok "$BLOCK_IP" && fail "feed address was not dropped"

# An independent input drop must still apply to a whitelisted source: the
# intel exception returns from its own chain, it is not a global accept.
ip netns exec "$NS_H" nft add table inet ag_test_port
ip netns exec "$NS_H" nft 'add chain inet ag_test_port input { type filter hook input priority 0; policy accept; }'
ip netns exec "$NS_H" nft "add rule inet ag_test_port input ip saddr $ALLOW_IP icmp type echo-request drop"
ping_ok "$ALLOW_IP" && fail "whitelist bypassed an independent port/input drop"
ip netns exec "$NS_H" nft delete table inet ag_test_port
ping_ok "$ALLOW_IP" || fail "whitelisted IP did not recover after the test drop"
echo 'PASS: native intel drops feed sources; single/CIDR exceptions return only from the intel chain'

# --- bootstrap/last-good: missing or malformed feed never weakens policy -----
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "baseline feed apply failed"
good_sum="$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")"
mv -f -- "$STATE/intel.txt" "$TMP/intel.saved"
# Simulate boot after the kernel table was cleared: the missing feed must fail
# visibly, restore the root snapshot, and keep both feed blocking and exceptions.
ip netns exec "$NS_H" nft delete table inet caddy_abuseguard_intel
if apply >/dev/null 2>&1; then fail "missing feed after a good policy was accepted"; fi
ping_ok "$BLOCK_IP" && fail "snapshot restore did not restore feed blocking"
ping_ok "$ALLOW_IP" || fail "snapshot restore lost the whitelist exception"
[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$good_sum" ] \
	|| fail "missing-feed apply changed the snapshots"
mv -f -- "$TMP/intel.saved" "$STATE/intel.txt"
# Whitespace, invalid and empty stored data must not replace the good policy.
for bad in ' 192.0.2.1' '999.1.2.3'; do
	printf '%s\n' "$bad" > "$STATE/intel.txt"
	if apply >/dev/null 2>&1; then fail "invalid feed was accepted: $bad"; fi
	[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$good_sum" ] \
		|| fail "invalid feed changed the snapshots"
	ping_ok "$BLOCK_IP" && fail "invalid feed lost the last-good block"
done
: > "$STATE/intel.txt"
if apply >/dev/null 2>&1; then fail "empty feed was accepted over a non-empty policy"; fi
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" > "$STATE/intel.txt"
echo 'PASS: missing/invalid feed restores or keeps the last-good policy'

# --- boot restore despite a broken fail2ban config ---------------------------
# At boot the kernel table is gone. The valid root-owned snapshot must be
# restored before the applier reads fail2ban, so an invalid F2B config cannot
# leave the feed policy missing; the failure itself stays visible.
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "baseline apply before broken-config boot test failed"
printf 'this line is not a valid fail2ban config section\n' \
	> "$F2B/jail.d/broken.local"
if f2bc -d >/dev/null 2>&1; then fail "test setup: broken fail2ban config was accepted"; fi
ip netns exec "$NS_H" nft delete table inet caddy_abuseguard_intel
if apply >/dev/null 2>&1; then fail "broken fail2ban config did not fail the apply"; fi
ping_ok "$BLOCK_IP" && fail "broken fail2ban config prevented snapshot restore"
ping_ok "$ALLOW_IP" || fail "snapshot restore lost the whitelist exception"
rm -f -- "$F2B/jail.d/broken.local"
apply >/dev/null || fail "apply after removing the broken fail2ban config failed"
echo 'PASS: broken fail2ban config does not prevent boot snapshot restore'

# A whitelist exception must never bypass the normal port/default-drop policy.
ip netns exec "$NS_H" nft add table inet caddy_abuseguard
ip netns exec "$NS_H" nft 'add chain inet caddy_abuseguard input { type filter hook input priority 0; policy drop; }'
ip netns exec "$NS_H" nft 'add rule inet caddy_abuseguard input ip protocol icmp accept'
ip netns exec "$NS_H" nft 'add rule inet caddy_abuseguard input tcp dport 443 accept'
tcp_result() { # SOURCE_IP PORT -> refused (accepted) | timeout (dropped)
	ip netns exec "$NS_C" python3 - "$1" "$HOST_IP" "$2" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1)
try:
    s.bind((sys.argv[1], 0))
    s.connect((sys.argv[2], int(sys.argv[3])))
    print('open')
except ConnectionRefusedError:
    print('refused')
except OSError:
    print('timeout')
PY
}
[ "$(tcp_result "$ALLOW_IP" 443)" = refused ] \
	|| fail "whitelisted source was not allowed by the open port rule"
[ "$(tcp_result "$ALLOW_IP" 80)" = timeout ] \
	|| fail "whitelist bypassed the closed/default-drop port policy"
[ "$(tcp_result "$BLOCK_IP" 443)" = timeout ] \
	|| fail "feed entry bypassed the intel drop on an open port"
echo 'PASS: whitelist exceptions return only from the intel chain'

# A port edit and unrelated tables must not disturb the independent intel table.
intel_before="$(ip netns exec "$NS_H" nft list table inet caddy_abuseguard_intel)"
ip netns exec "$NS_H" nft add table inet ag_unrelated
ip netns exec "$NS_H" nft 'add chain inet ag_unrelated c'
ip netns exec "$NS_H" nft 'add rule inet ag_unrelated c ip saddr 203.0.113.9 drop'
unrelated_before="$(ip netns exec "$NS_H" nft list table inet ag_unrelated)"
ip netns exec "$NS_H" nft delete table inet caddy_abuseguard
ip netns exec "$NS_H" nft add table inet caddy_abuseguard
ip netns exec "$NS_H" nft 'add chain inet caddy_abuseguard input { type filter hook input priority 0; policy drop; }'
ip netns exec "$NS_H" nft 'add rule inet caddy_abuseguard input tcp dport 8443 accept'
ip netns exec "$NS_H" nft list table inet caddy_abuseguard | grep -q 'tcp dport 8443 accept' \
	|| fail "port edit did not apply"
[ "$(ip netns exec "$NS_H" nft list table inet caddy_abuseguard_intel)" = "$intel_before" ] \
	|| fail "port edit changed the independent intel table"
[ "$(ip netns exec "$NS_H" nft list table inet ag_unrelated)" = "$unrelated_before" ] \
	|| fail "port edit changed an unrelated table"
ip netns exec "$NS_H" nft delete table inet caddy_abuseguard
ip netns exec "$NS_H" nft delete table inet ag_unrelated
echo 'PASS: port edits preserve the intel and unrelated tables'

# An sshd-only native exemption must never become a kernel allow exemption.
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$SSH_ONLY_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "sshd-only feed apply failed"
ping_ok "$SSH_ONLY_IP" && fail "sshd-only ignoreip leaked into the kernel allowlist"
echo 'PASS: native fail2ban exemptions stay out of kernel policy'

# --- feed replacement and last-good preservation -----------------------------
printf '%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "feed replacement apply failed"
ping_ok "$BLOCK_IP" || fail "address removed from the feed stayed blocked"

printf '%s\n' "$BLOCK_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "re-add apply failed"
ping_ok "$BLOCK_IP" && fail "re-added feed address was not dropped"
snapshot_sum="$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")"
printf '999.1.2.3\n' > "$STATE/intel.txt"
if apply >/dev/null 2>&1; then fail "invalid intel export was accepted"; fi
ping_ok "$BLOCK_IP" && fail "failed apply lost the last-good kernel block"
[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$snapshot_sum" ] \
	|| fail "failed apply changed the snapshots"
grep -q "$BLOCK_IP" "$CONF/intel.nft" || fail "intel snapshot missing the blocked entry"
grep -q '"intel_entries":1' "$CONF/intel-applied.json" || fail "applied metadata missing entry count"
[ "$(stat -c %U "$CONF/intel.nft")" = root ] || fail "intel snapshot is not root-owned"
echo 'PASS: feed replacement follows the file; invalid input keeps kernel and disk policy'

# --- native fail2ban ignoreip and ban clearing -------------------------------
printf '%s\n%s\n%s\n' "$ALLOW_IP" "$CIDR_IP" "$BLOCK_IP" > "$STATE/intel.txt"
apply >/dev/null || fail "pre-fail2ban apply failed"

# The admin's sshd-only native exemption must stay in the sshd section and must
# not widen the Web jails or the kernel allowlist.
section_has sshd "$SSH_ONLY_IP" || fail "native sshd-only ignoreip was not preserved"
if section_has caddy-rate-local "$SSH_ONLY_IP" || section_has caddy-probe-h1 "$SSH_ONLY_IP"; then
	fail "sshd-only ignoreip leaked into a Web jail"
fi
echo 'PASS: native ignoreip is preserved per jail and not broadened'

start_f2b

grep -q '^\[caddy-rate-local\]' "$F2B/jail.d/zzz-caddy-abuseguard-policy.local" \
	|| fail "generated ignoreip file missing the jail"
grep -q "$ALLOW_IP" "$F2B/jail.d/zzz-caddy-abuseguard-policy.local" \
	|| fail "generated ignoreip missing the whitelist entry"
grep -q '2001:db8::/64' "$F2B/jail.d/zzz-caddy-abuseguard-policy.local" \
	|| fail "generated ignoreip missing the IPv6 whitelist entry"

# Whitelisted source must not be banned; a non-whitelisted one must be.
printf 'ABUSE %s\nABUSE %s\n' "$ALLOW_IP" "$BLOCK_IP" >> "$F2B/access.log"
wait_ban "$BLOCK_IP" || fail "non-whitelisted source was not banned"
if banned_list | tr ' ' '\n' | grep -qxF "$ALLOW_IP"; then fail "whitelisted source was banned"; fi
ping_ok "$ALLOW_IP" || fail "whitelisted source traffic was dropped"
echo 'PASS: generated ignoreip is enforced by a real fail2ban daemon'

# An sshd-only native exemption must not make the source un-banable in the Web
# jails, and removing it must propagate on the next apply (no frozen snapshot).
printf 'ABUSE %s\n' "$SSH_ONLY_IP" >> "$F2B/access.log"
wait_ban "$SSH_ONLY_IP" || fail "sshd-only ignored source was not banned by caddy-rate-local"
sleep 0.3
if sshd_banned "$SSH_ONLY_IP"; then fail "sshd banned a natively ignored source"; fi
rm -f -- "$F2B/jail.d/native-sshd.local"
apply >/dev/null || fail "apply after native ignoreip removal failed"
if section_has sshd "$SSH_ONLY_IP"; then fail "removed native ignoreip stayed in the generated file"; fi
echo 'PASS: sshd-only ignoreip does not widen Web jails and removal propagates'

# Adding the banned source to the whitelist must apply the kernel exception and
# clear the existing timed ban in the same operation.
printf '%s\n' "$BLOCK_IP" >> "$CONF/whitelist"
apply >/dev/null || fail "whitelist addition apply failed"
wait_unban "$BLOCK_IP" || fail "newly whitelisted source kept its behavioural ban"
ping_ok "$BLOCK_IP" || fail "newly whitelisted source remained blocked in the kernel"
echo 'PASS: one whitelist change updates kernel and clears the existing fail2ban ban'

# --- legacy ban migration against the real daemon ---------------------------
# Extract the installer's own cutover helpers and drive them with a real
# fail2ban daemon: old intel-jail bans must replay into caddy-rate-local after
# the new config is live, while whitelisted entries are skipped.
INSTALL_FUNCS="$TMP/install-funcs.sh"
: > "$INSTALL_FUNCS"
for fn in legacy_intel_bans migrate_legacy_bans pause_fail2ban_for_upgrade \
	resume_fail2ban_after_failure backup_f2b_assets restore_f2b_assets \
	commit_staged_binary commit_engine restore_engine_backup on_install_exit; do
	awk -v signature="$fn() {" '
		index($0, signature) == 1 { printing = 1 }
		printing { print }
		printing && /^}$/ { exit }
	' "$ROOT/install.sh" >> "$INSTALL_FUNCS"
done
# shellcheck disable=SC1090
source "$INSTALL_FUNCS"
ENGINE_BIN="$ENGINE"
ENGINE_BACKUP=""
INSTALL_COMPLETE=0
CONF_DIR="$CONF"
LEGACY_BANS=""
STAGED_BIN=""
F2B_ROLLBACK_DIR=""
F2B_ETC="$F2B"
POLICY_F2B="$F2B/jail.d/zzz-caddy-abuseguard-policy.local"
SRC_DIR="$ROOT"
FAIL2BAN_PAUSED=0
FAIL2BAN_STOPPED=0
ENGINE_SWAPPED=0
PAUSE_JAILS="caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd sshd-intel"
PAUSED_JAILS_DONE=""
log() { printf '[test] %s\n' "$*"; }
warn() { printf '[test warn] %s\n' "$*" >&2; }
die() { fail "$*"; }
systemctl() {
	case "$1" in
		stop) stop_f2b ;;
		start) start_f2b ;;
		restart) stop_f2b; start_f2b ;;
		is-active) f2bc ping >/dev/null 2>&1 ;;
		*) return 1 ;;
	esac
}
export ABUSEGUARD_CONFIG="$CONF/config.json"

# Recreate the pre-upgrade world: old intel jails live, no generated file.
stop_f2b
rm -f -- "$F2B/jail.d/zzz-caddy-abuseguard-policy.local"
cat > "$F2B/jail.d/old-intel.local" <<EOF
[caddy-intel]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest

[sshd-intel]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest
EOF
start_f2b
f2bc set caddy-intel banip "$MIGRATE_IP" >/dev/null || fail "could not seed an old intel ban"
f2bc set sshd-intel banip "$ALLOW_IP" >/dev/null || fail "could not seed a whitelisted old ban"
LEGACY_BANS="$(legacy_intel_bans)"
printf '%s\n' "$LEGACY_BANS" | grep -qxF "$MIGRATE_IP" || fail "old intel ban was not captured"
printf '%s\n' "$LEGACY_BANS" | grep -qxF "$ALLOW_IP" || fail "whitelisted old ban was not captured"
printf '%s\n' "$LEGACY_BANS" > "$CONF/legacy-intel-bans.pending"
stop_f2b
rm -f -- "$F2B/jail.d/old-intel.local"
start_f2b
migrate_legacy_bans
banned_list | tr ' ' '\n' | grep -qxF "$MIGRATE_IP" || fail "legacy ban was not replayed into caddy-rate-local"
if banned_list | tr ' ' '\n' | grep -qxF "$ALLOW_IP"; then fail "whitelisted legacy ban was replayed"; fi
[ ! -f "$CONF/legacy-intel-bans.pending" ] || fail "pending ban file was not cleared"
echo 'PASS: legacy intel bans replay per contract and whitelisted entries are skipped'

# --- idle pause preserves bans and stops detection --------------------------
# Existing ban stays in the jail while idle; new matching lines must not ban.
f2bc set caddy-rate-local idle on >/dev/null || fail "fail2ban idle is unsupported"
banned_list | tr ' ' '\n' | grep -qxF "$MIGRATE_IP" || fail "idle dropped an existing ban"
printf 'ABUSE %s\n' "$IDLE_IP" >> "$F2B/access.log"
sleep 1
if banned_list | tr ' ' '\n' | grep -qxF "$IDLE_IP"; then fail "idle jail still processed log lines"; fi

# The installer helper must idle every existing jail; a pre-swap failure resumes
# them.
pause_fail2ban_for_upgrade
[ "$FAIL2BAN_PAUSED" = 1 ] || fail "installer pause helper did not idle fail2ban"
printf 'ABUSE %s\n' "$IDLE2_IP" >> "$F2B/access.log"
sleep 1
if banned_list | tr ' ' '\n' | grep -qxF "$IDLE2_IP"; then fail "installer-paused jail still banned"; fi
ENGINE_SWAPPED=0
on_install_exit
printf 'ABUSE %s\n' "$IDLE2_IP" >> "$F2B/access.log"
wait_ban "$IDLE2_IP" || fail "pre-swap failure did not resume detection"
printf 'ABUSE %s\n' "$IDLE3_IP" >> "$F2B/access.log"
wait_ban "$IDLE3_IP" || fail "pre-swap recovery did not resume detection"
echo 'PASS: idle pause keeps bans and a pre-swap failure resumes detection'

# --- post-swap failure restores the old engine/config and detection ----------
# Drive the real installer helpers: seed the files it backs up, overwrite them
# with the new versions, idle detection, commit the staged engine, restart with
# the new config, then inject the failure by running the EXIT handler.
PAUSED_JAILS_DONE=""
FAIL2BAN_PAUSED=0
FAIL2BAN_STOPPED=0
printf '[Definition]\nfailregex = ^OLD-ABUSE <HOST>$\nignoreregex =\n' \
	> "$F2B/filter.d/caddy-abuseguard-any.conf"
printf '[caddy-rate-local]\nenabled = true\nmaxretry = 2\n' \
	> "$F2B/jail.d/caddy-abuseguard.local"
printf '# old generated ignoreip\n[caddy-rate-local]\nignoreip = %s\n' "$ALLOW_IP" \
	> "$F2B/jail.d/zzz-caddy-abuseguard-policy.local"
ENGINE_BIN="$TMP/engine-slot"
cp -a -- "$ENGINE" "$ENGINE_BIN"
cp -a -- "$ENGINE" "$TMP/engine.old"
backup_f2b_assets
printf '[Definition]\nfailregex = ^NEW-ABUSE <HOST>$\nignoreregex =\n' \
	> "$F2B/filter.d/caddy-abuseguard-any.conf"
printf '[caddy-rate-local]\nenabled = true\nmaxretry = 3\n' \
	> "$F2B/jail.d/caddy-abuseguard.local"
printf '#!/bin/sh\n# staged new engine\n' > "$TMP/engine.new"
chmod 0755 "$TMP/engine.new"
pause_fail2ban_for_upgrade
STAGED_BIN="$TMP/engine.new"
commit_engine
[ -n "$ENGINE_BACKUP" ] || fail "engine backup was not retained after the swap"
grep -q 'staged new engine' "$ENGINE_BIN" || fail "engine swap did not install the staged binary"
systemctl restart fail2ban
on_install_exit
[ "$INSTALL_COMPLETE" = 0 ] || fail "incomplete install was latched as successful"
cmp -s "$ENGINE_BIN" "$TMP/engine.old" || fail "old engine was not restored after a post-swap failure"
grep -q 'OLD-ABUSE' "$F2B/filter.d/caddy-abuseguard-any.conf" \
	|| fail "old fail2ban filter config was not restored"
grep -q 'maxretry = 2' "$F2B/jail.d/caddy-abuseguard.local" \
	|| fail "old fail2ban jail config was not restored"
[ ! -e "$F2B_ROLLBACK_DIR" ] || fail "rollback directory was not cleaned up"
# maxretry=2 is distinct from the new config's 3: two matching lines ban only
# when the restored config is the one actually running.
printf 'ABUSE %s\nABUSE %s\n' "$RECOVER_IP" "$RECOVER_IP" >> "$F2B/access.log"
wait_ban "$RECOVER_IP" || fail "detection did not resume after a post-swap failure"
echo 'PASS: post-swap failure restores the old engine/config and resumes detection'

echo 'native policy kernel + fail2ban tests: pass'
