#!/usr/bin/env bash
# Real systemd oneshot tests for the AbuseGuard sync and boot policy services.
#
# CI-only: requires ABUSEGUARD_CI_SERVICE_TEST=1, root, systemd as PID 1, an
# engine executable, nftables, fail2ban, python3 and the abuseguard user. The
# real unit files from assets/systemd are copied under test names with
# isolation-only drop-ins (private network namespace, fixture config/state/
# jail paths, fixture engine path). Every production sandbox/capability/user
# directive stays in force; only ExecStart/ExecStartPost, Environment and
# ReadWritePaths are added so the same live install can be tested without
# touching its config, firewall, jails or units.
#
# Fixtures live under /var/lib/agtest.* and are exposed with isolation-only
# ReadWritePaths: the production units set PrivateTmp=true (hiding /tmp and
# /var/tmp) and this host mounts /run noexec, so neither can host the fixture
# engine or the fail2ban-client wrapper.
#
# Proves, through the real sandbox/capability/user directives (not unit text):
#   - the runuser'd sync fetches the feed and writes a validated intel.txt
#   - the root ExecStartPost applies the intel set and whitelist exceptions
#   - the unprivileged user cannot write executables/root policy, run nft, or
#     otherwise cross the capability boundary
#   - boot restores the last-good snapshot when the table is gone and the
#     config/feed is missing (failing visibly), then applies once recovered
#   - generated fail2ban ignoreip is per-jail, root-owned and reloaded by a
#     private real fail2ban daemon
#   - the host network namespace and production config/jails/engine are not
#     modified (fixtures are the only writable policy roots)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE="${ABUSEGUARD_TEST_ENGINE:-/usr/local/libexec/caddy-abuseguard}"
AG_USER=abuseguard
FIX="$(mktemp -d /var/lib/agtest.XXXXXX)"
CONF="$FIX/conf"
STATE="$FIX/state"
F2B="$FIX/f2b"
BIN="$FIX/bin"
FEED="$FIX/feed"
F2B_JAIL_DIR="$F2B/jail.d"
POLICY_F2B="$F2B_JAIL_DIR/zzz-caddy-abuseguard-policy.local"
NS="agci$$"
PORT=18080
SYNC_UNIT="agtest-$$-sync.service"
POLICY_UNIT="agtest-$$-policy.service"
PROD_CONF=/etc/caddy-abuseguard
PROD_ENGINE=/usr/local/libexec/caddy-abuseguard
PROD_F2B=/etc/fail2ban/jail.d/zzz-caddy-abuseguard-policy.local
HTTP_PID=""
F2B_STARTED=0

fail() { echo "policy service test failed: $*" >&2; exit 1; }
dump_unit() { journalctl -u "$1" --no-pager -o cat >&2 2>/dev/null || true; }
start_unit() { # UNIT
	local unit="$1" rc=0
	timeout 120 systemctl start "$unit" || rc=$?
	[ "$rc" = 0 ] || dump_unit "$unit"
	return "$rc"
}
unit_result() { systemctl show -p Result --value "$1"; }
f2bc() { "$BIN/fail2ban-client" "$@"; }
jail_ignoreip() { # JAIL
	f2bc get "$1" ignoreip 2>/dev/null | tr ',' ' '
}
host_tables() { nft list tables | sort; }
prod_probe() { # stable production files that this test must never touch
	{
		for f in "$PROD_CONF/config.json" "$PROD_CONF/whitelist" "$PROD_ENGINE" \
			/etc/systemd/system/caddy-abuseguard-policy.service \
			/etc/systemd/system/caddy-abuseguard-sync.service; do
			if [ -e "$f" ]; then sha256sum "$f"; else echo "absent $f"; fi
		done
	} | sort
}

cleanup() {
	systemctl stop "$SYNC_UNIT" "$POLICY_UNIT" >/dev/null 2>&1 || true
	systemctl reset-failed "$SYNC_UNIT" "$POLICY_UNIT" >/dev/null 2>&1 || true
	rm -f -- "/etc/systemd/system/$SYNC_UNIT" "/etc/systemd/system/$POLICY_UNIT"
	rm -rf -- "/etc/systemd/system/$SYNC_UNIT.d" "/etc/systemd/system/$POLICY_UNIT.d"
	systemctl daemon-reload >/dev/null 2>&1 || true
	if [ "$F2B_STARTED" = 1 ]; then
		f2bc stop >/dev/null 2>&1 || true
	fi
	[ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	rm -rf -- "$FIX"
}
trap cleanup EXIT

[ "${ABUSEGUARD_CI_SERVICE_TEST:-0}" = 1 ] \
	|| { echo "refusing: set ABUSEGUARD_CI_SERVICE_TEST=1 (CI-only destructive test)" >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo "requires Linux" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "systemd is not running as PID 1" >&2; exit 2; }
for bin in ip nft python3 fail2ban-server fail2ban-client systemctl journalctl sha256sum runuser; do
	command -v "$bin" >/dev/null 2>&1 || { echo "missing: $bin" >&2; exit 2; }
done
[ -x "$ENGINE" ] || fail "engine missing or not executable: $ENGINE"
id "$AG_USER" >/dev/null 2>&1 || fail "user $AG_USER missing"
case "$FIX" in
	/var/lib/agtest.*) ;;
	*) fail "fixture root $FIX is not an owned /var/lib/agtest path" ;;
esac
[ ! -e "$CONF/config.json" ] || fail "fixture root already contains a config"

# --- fixtures ----------------------------------------------------------------
chmod 0711 "$FIX"
chown root:root "$FIX"
install -d -m 0750 -o root -g "$AG_USER" "$CONF"
install -d -m 0750 -o "$AG_USER" -g "$AG_USER" "$STATE" "$STATE/reports"
install -d -m 0755 -o root -g root "$BIN" "$FEED" "$F2B" \
	"$F2B/filter.d" "$F2B/action.d" "$F2B_JAIL_DIR"
# Run the exact submitted engine from an exec-capable fixture path so the
# unprivileged sync can execute it without touching /usr/local/libexec.
install -m 0755 -o root -g root "$ENGINE" "$BIN/caddy-abuseguard"
ENGINE="$BIN/caddy-abuseguard"
: > "$F2B/access.log"

cat > "$CONF/config.json" <<EOF
{
  "allowlist_file": "$CONF/whitelist",
  "paths": {"state_dir": "$STATE", "reports_dir": "$STATE/reports"},
  "intel": {
    "source_url": "http://127.0.0.1:$PORT/feed.txt",
    "commit_url": "",
    "token_file": "",
    "min_entries": 3,
    "max_entries": 10,
    "max_age": "48h"
  },
  "abuseipdb": {"enabled": false, "report_url": "", "report_key_file": "", "daily_report_cap": 0, "dedupe_window": ""}
}
EOF
cat > "$CONF/whitelist" <<EOF
# fixture whitelist: loopback plus one feed entry, to prove exceptions are separate.
127.0.0.0/8
203.0.113.7
EOF
chown root:"$AG_USER" "$CONF/config.json" "$CONF/whitelist"
chmod 0640 "$CONF/config.json" "$CONF/whitelist"

cat > "$FEED/feed.txt" <<'EOF'
# deterministic fixture feed
203.0.113.7
198.51.100.9  US
2001:db8::1
192.0.2.33
EOF

# Private fail2ban: own config, socket, pid and DB so the host daemon and its
# ban database are never opened by this test.
cat > "$F2B/fail2ban.conf" <<EOF
[Definition]
loglevel = INFO
logtarget = $F2B/fail2ban.log
socket = $F2B/socket
pidfile = $F2B/fail2ban.pid
dbfile = $F2B/fail2ban.sqlite3
EOF
cat > "$F2B/jail.conf" <<EOF
[DEFAULT]
enabled = false
ignoreip = 127.0.0.1/8 ::1
bantime = 120
findtime = 60
maxretry = 2
backend = polling
usedns = no

[caddy-rate-local]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest

[caddy-probe-h1]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest

[caddy-probe-h2]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest

[sshd]
enabled = true
filter = agtest
logpath = $F2B/access.log
action = agtest
EOF
printf '[Definition]\nfailregex = ^\\s*ABUSE <HOST>$\nignoreregex =\n' > "$F2B/filter.d/agtest.conf"
printf '[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = /bin/true\nactionunban = /bin/true\n' \
	> "$F2B/action.d/agtest.conf"
cat > "$BIN/fail2ban-client" <<EOF
#!/bin/sh
exec $(command -v fail2ban-client) -c "$F2B" -s "$F2B/socket" "\$@"
EOF
chmod 0755 "$BIN/fail2ban-client"

fail2ban-server -c "$F2B" -s "$F2B/socket" -x -b >/dev/null 2>&1 || fail "could not start the private fail2ban"
F2B_STARTED=1
ready=0
for _ in $(seq 1 100); do
	if f2bc ping >/dev/null 2>&1; then ready=1; break; fi
	sleep 0.1
done
[ "$ready" = 1 ] || fail "private fail2ban did not start"
for jail in caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd; do
	f2bc status "$jail" >/dev/null 2>&1 || fail "private jail missing: $jail"
done

# --- private namespace + fixture HTTP feed -----------------------------------
ip netns del "$NS" 2>/dev/null || true # stale namespace from an aborted run of this test
ip netns add "$NS"
ip -n "$NS" link set lo up
ip netns exec "$NS" python3 -m http.server "$PORT" --bind 127.0.0.1 \
	--directory "$FEED" >/dev/null 2>&1 &
HTTP_PID=$!
ready=0
for _ in $(seq 1 100); do
	if ip netns exec "$NS" python3 -c \
		"import socket; socket.create_connection(('127.0.0.1', $PORT), 0.2)" 2>/dev/null; then
		ready=1
		break
	fi
	sleep 0.1
done
[ "$ready" = 1 ] || fail "private feed server did not start"

# --- real unit definitions + isolation-only drop-ins -------------------------
install -m 0644 "$ROOT/assets/systemd/caddy-abuseguard-sync.service" \
	"/etc/systemd/system/$SYNC_UNIT"
install -m 0644 "$ROOT/assets/systemd/caddy-abuseguard-policy.service" \
	"/etc/systemd/system/$POLICY_UNIT"
cat > "$FIX/isolate.conf" <<EOF
[Service]
NetworkNamespacePath=/run/netns/$NS
Environment=AG_CONF_DIR=$CONF AG_F2B_JAIL_DIR=$F2B_JAIL_DIR ABUSEGUARD_CONFIG=$CONF/config.json PATH=$BIN:/usr/sbin:/usr/bin:/sbin:/bin
ReadWritePaths=$CONF $STATE $F2B
EOF
for unit in "$SYNC_UNIT" "$POLICY_UNIT"; do
	install -d -m 0755 "/etc/systemd/system/$unit.d"
	install -m 0644 "$FIX/isolate.conf" "/etc/systemd/system/$unit.d/isolate.conf"
done
# Only the executable path is replaced: the fixture copy runs the exact
# submitted engine while every sandbox directive stays untouched.
{
	printf '[Service]\nExecStart=\n'
	printf 'ExecStart=/usr/sbin/runuser -u %s -- %s sync-intel\n' "$AG_USER" "$ENGINE"
	printf 'ExecStartPost=\nExecStartPost=%s policy-apply\n' "$ENGINE"
} > "/etc/systemd/system/$SYNC_UNIT.d/engine.conf"
{
	printf '[Service]\nExecStart=\n'
	printf 'ExecStart=%s policy-apply\n' "$ENGINE"
} > "/etc/systemd/system/$POLICY_UNIT.d/engine.conf"
systemctl daemon-reload

# Baseline isolation evidence: the host namespace and production files.
HOST_TABLES_BEFORE="$(host_tables)"
PROD_BEFORE="$(prod_probe)"
binary_sum="$(sha256sum "$ENGINE")"

# --- sandboxed sync + root post-apply ----------------------------------------
start_unit "$SYNC_UNIT" || fail "sandboxed sync/policy service failed"
[ "$(unit_result "$SYNC_UNIT")" = success ] || fail "sync service result was not success"

cat > "$FIX/expected-intel.txt" <<EOF
203.0.113.7
198.51.100.9
192.0.2.33
EOF
cmp -s "$FIX/expected-intel.txt" "$STATE/intel.txt" \
	|| fail "sync did not write the validated feed to intel.txt"
[ "$(stat -c '%U:%a' "$STATE/intel.txt")" = "$AG_USER:640" ] \
	|| fail "intel.txt is not owned by the unprivileged sync user"
grep -q '"ipv4": 3' "$STATE/intel-last-sync.txt" \
	|| fail "sync metadata missing the validated entry count"
echo 'PASS: unprivileged sync fetched and wrote the validated feed'

ip netns exec "$NS" nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	|| fail "root ExecStartPost did not apply the nft policy"
set_out="$(ip netns exec "$NS" nft list set inet caddy_abuseguard_intel block4)"
for ip in 203.0.113.7 198.51.100.9 192.0.2.33; do
	grep -qF "$ip" <<<"$set_out" || fail "applied kernel set missing feed entry $ip"
done
chain_out="$(ip netns exec "$NS" nft list chain inet caddy_abuseguard_intel input)"
grep -qF 'ip saddr 203.0.113.7 return' <<<"$chain_out" \
	|| fail "whitelisted intel exception missing from the kernel chain"
grep -qF 'ip saddr 127.0.0.0/8 return' <<<"$chain_out" \
	|| fail "whitelist CIDR exception missing from the kernel chain"
grep -qF 'ip saddr @block4 drop' <<<"$chain_out" \
	|| fail "kernel chain does not drop feed entries"
[ "$(host_tables)" = "$HOST_TABLES_BEFORE" ] \
	|| fail "a test unit changed the host nft table set"
echo 'PASS: root post-apply installed intel + whitelist policy only in the private namespace'

# --- protected paths and unprivileged boundaries ------------------------------
[ "$(stat -c '%U:%G:%a' "$ENGINE")" = "root:root:755" ] \
	|| fail "$ENGINE is not root-owned mode 0755"
[ "$(stat -c '%U:%G:%a' "$CONF")" = "root:$AG_USER:750" ] \
	|| fail "$CONF is writable by the unprivileged user"
[ "$(stat -c '%U:%a' "$CONF/whitelist")" = "root:640" ] \
	|| fail "$CONF/whitelist is not root-owned"
for f in intel.nft intel-allow.nft intel-applied.json; do
	[ "$(stat -c '%U:%G:%a' "$CONF/$f")" = "root:root:640" ] \
		|| fail "$CONF/$f is not a root-owned 0640 snapshot"
done
grep -q '^# Generated by caddy-abuseguard-policy at ' "$CONF/intel.nft" \
	|| fail "intel snapshot is not applier-generated"
[ "$(stat -c '%U:%G:%a' "$POLICY_F2B")" = "root:root:644" ] \
	|| fail "generated fail2ban policy is not root-owned 0644"
for jail in caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd; do
	awk -v jail="$jail" '
		/^\[/ { s = substr($0, 2, length($0) - 2) }
		s == jail && /203\.0\.113\.7/ { found = 1 }
		END { exit !found }
	' "$POLICY_F2B" || fail "generated fail2ban policy missing the whitelist entry for $jail"
	grep -q '127.0.0.0/8' "$POLICY_F2B" \
		|| fail "generated fail2ban policy missing the whitelist CIDR"
	jail_out="$(jail_ignoreip "$jail")"
	grep -qF '203.0.113.7' <<<"$jail_out" \
		|| fail "private fail2ban did not reload the new ignoreip for $jail"
done
grep -q 'enabled = false' "$POLICY_F2B" \
	|| fail "generated fail2ban policy does not retire the old intel jails"
[ "$(sha256sum "$ENGINE")" = "$binary_sum" ] \
	|| fail "sync/apply modified the engine executable"
executables="$(find "$STATE" -maxdepth 1 -type f -perm /111)"
[ -z "$executables" ] || fail "executable appeared in the abuseguard-writable state dir: $executables"
foreign="$(find "$STATE" -maxdepth 1 -type f ! -user "$AG_USER")"
[ -z "$foreign" ] || fail "state dir contains unexpected files not written by $AG_USER: $foreign"
for f in "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json" "$POLICY_F2B" "$ENGINE"; do
	if runuser -u "$AG_USER" -- test -w "$f"; then
		fail "$AG_USER can write protected path $f"
	fi
done
if runuser -u "$AG_USER" -- nft list tables >/dev/null 2>&1; then
	fail "$AG_USER can run nft (missing capability boundary)"
fi
echo 'PASS: unprivileged sync cannot write executables, root policy or nft'

# --- boot restore: last-good snapshot, then normal apply ---------------------
snapshot_sum="$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")"

# At boot the kernel table is gone. A missing config must not prevent restoring
# the validated root snapshot; the service still fails visibly.
mv -- "$CONF/config.json" "$FIX/config.saved"
mv -- "$STATE/intel.txt" "$FIX/intel.saved"
ip netns exec "$NS" nft delete table inet caddy_abuseguard_intel
systemctl start "$POLICY_UNIT" >/dev/null 2>&1 \
	&& fail "boot policy apply accepted a missing config over a non-empty policy"
[ "$(unit_result "$POLICY_UNIT")" = exit-code ] \
	|| fail "missing-config boot apply did not fail as a unit"
systemctl reset-failed "$POLICY_UNIT" >/dev/null 2>&1 || true
ip netns exec "$NS" nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	|| fail "missing-config boot apply did not restore the last-good kernel snapshot"
set_out="$(ip netns exec "$NS" nft list set inet caddy_abuseguard_intel block4)"
for ip in 203.0.113.7 198.51.100.9 192.0.2.33; do
	grep -qF "$ip" <<<"$set_out" || fail "restored snapshot lost feed entry $ip"
done
[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$snapshot_sum" ] \
	|| fail "failed boot apply changed the last-good snapshots"
mv -- "$FIX/config.saved" "$CONF/config.json"
echo 'PASS: boot service restores the last-good snapshot when the config is missing'

# Same boot path with a valid config but a missing feed: restore, fail visibly.
ip netns exec "$NS" nft delete table inet caddy_abuseguard_intel
systemctl start "$POLICY_UNIT" >/dev/null 2>&1 \
	&& fail "boot policy apply accepted a missing feed over a non-empty policy"
[ "$(unit_result "$POLICY_UNIT")" = exit-code ] \
	|| fail "missing-feed boot apply did not fail as a unit"
systemctl reset-failed "$POLICY_UNIT" >/dev/null 2>&1 || true
ip netns exec "$NS" nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	|| fail "missing-feed boot apply did not restore the last-good kernel snapshot"
[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$snapshot_sum" ] \
	|| fail "missing-feed boot apply changed the last-good snapshots"
echo 'PASS: boot service restores the last-good snapshot when the feed is missing'

mv -- "$FIX/intel.saved" "$STATE/intel.txt"
# A whitelist edit forces this run to rewrite the generated fail2ban policy and
# the allow chain under the boot unit's own sandbox (not the sync unit's).
printf '198.51.100.9\n' >> "$CONF/whitelist"
ip netns exec "$NS" nft delete table inet caddy_abuseguard_intel
start_unit "$POLICY_UNIT" || fail "boot policy service failed with a valid feed"
[ "$(unit_result "$POLICY_UNIT")" = success ] || fail "boot policy service result was not success"
ip netns exec "$NS" nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	|| fail "boot policy service did not apply the policy"
set_out="$(ip netns exec "$NS" nft list set inet caddy_abuseguard_intel block4)"
for ip in 203.0.113.7 198.51.100.9 192.0.2.33; do
	grep -qF "$ip" <<<"$set_out" || fail "boot-applied kernel set missing feed entry $ip"
done
chain_out="$(ip netns exec "$NS" nft list chain inet caddy_abuseguard_intel input)"
grep -qF 'ip saddr 198.51.100.9 return' <<<"$chain_out" \
	|| fail "boot policy service did not write the new whitelist exception"
for jail in caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd; do
	awk -v jail="$jail" '
		/^\[/ { s = substr($0, 2, length($0) - 2) }
		s == jail && /198\.51\.100\.9/ { found = 1 }
		END { exit !found }
	' "$POLICY_F2B" || fail "boot policy service did not write the new ignoreip for $jail"
	jail_out="$(jail_ignoreip "$jail")"
	grep -qF '198.51.100.9' <<<"$jail_out" \
		|| fail "private fail2ban did not reload the boot-applied ignoreip for $jail"
done
[ "$(stat -c '%U:%G:%a' "$POLICY_F2B")" = "root:root:644" ] \
	|| fail "boot policy service wrote a non-root fail2ban policy"
[ "$(sha256sum "$ENGINE")" = "$binary_sum" ] \
	|| fail "boot apply modified the engine executable"
echo 'PASS: boot policy service applies the validated feed after a cleared table'

# --- isolation evidence -------------------------------------------------------
[ "$(host_tables)" = "$HOST_TABLES_BEFORE" ] \
	|| fail "test services changed the host nft table set"
[ "$(prod_probe)" = "$PROD_BEFORE" ] \
	|| fail "test services modified production config/whitelist/engine/units"
echo 'PASS: host namespace and production policy files are untouched'

echo 'policy service tests: pass'
