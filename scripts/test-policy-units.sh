#!/usr/bin/env bash
# Real systemd oneshot tests for the AbuseGuard sync and boot policy services.
#
# CI-only: requires ABUSEGUARD_CI_SERVICE_TEST=1, root, systemd as PID 1, the
# installed engine + root policy helper at their production paths, nftables,
# fail2ban's configuration and python3. The real unit files from
# assets/systemd are copied under test names with one drop-in that joins a
# private network namespace, so the nft policy and the feed server never touch
# the host namespace. Production paths are used because the CI runner is
# disposable; a real installation is refused so this can never overwrite one.
#
# Proves, through the real sandbox/capability/user directives (not unit text):
#   - the runuser'd sync fetches the feed and writes a validated intel.txt
#   - the root ExecStartPost applies the intel set and whitelist exceptions
#   - the unprivileged user cannot write the executables, root snapshots or
#     fail2ban policy, and no executable appears in its writable state dir
#   - the boot policy service restores the last-good snapshot when the kernel
#     table is gone and the feed file is missing (failing visibly), then applies
#     the policy once the feed is back
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENGINE=/usr/local/libexec/caddy-abuseguard
POLICY=/usr/local/libexec/caddy-abuseguard-policy
CONF=/etc/caddy-abuseguard
STATE=/var/lib/caddy-abuseguard
F2B_JAIL_DIR=/etc/fail2ban/jail.d
POLICY_F2B="$F2B_JAIL_DIR/zzz-caddy-abuseguard-policy.local"
NS=agci-ns
PORT=18080
SYNC_UNIT=abuseguard-ci-sync.service
POLICY_UNIT=abuseguard-ci-policy.service

fail() { echo "policy service test failed: $*" >&2; exit 1; }
dump_unit() { journalctl -u "$1" --no-pager -o cat >&2 2>/dev/null || true; }
start_unit() { # UNIT
	local unit="$1" rc=0
	systemctl start "$unit" || rc=$?
	[ "$rc" = 0 ] || dump_unit "$unit"
	return "$rc"
}
unit_result() { systemctl show -p Result --value "$1"; }

[ "${ABUSEGUARD_CI_SERVICE_TEST:-0}" = 1 ] \
	|| { echo "refusing: set ABUSEGUARD_CI_SERVICE_TEST=1 (CI-only destructive test)" >&2; exit 2; }
[ "$(uname -s)" = Linux ] || { echo "requires Linux" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 2; }
[ -d /run/systemd/system ] || { echo "systemd is not running as PID 1" >&2; exit 2; }
for bin in ip nft python3 fail2ban-client systemctl journalctl sha256sum; do
	command -v "$bin" >/dev/null 2>&1 || { echo "missing: $bin" >&2; exit 2; }
done
[ -x /usr/sbin/runuser ] || fail "unit ExecStart needs /usr/sbin/runuser (util-linux)"
[ -x "$ENGINE" ] || fail "installed engine missing: $ENGINE"
[ -x "$POLICY" ] || fail "installed policy helper missing: $POLICY"
id abuseguard >/dev/null 2>&1 || fail "user abuseguard missing"
[ ! -e "$CONF/config.json" ] || fail "refusing to overwrite an existing installation ($CONF/config.json)"
[ ! -e "$POLICY_F2B" ] || fail "refusing to overwrite an existing $POLICY_F2B"
AG_GROUP="$(id -gn abuseguard)"

TMP="$(mktemp -d)"
HTTP_PID=""
cleanup() {
	[ -z "$HTTP_PID" ] || kill "$HTTP_PID" 2>/dev/null || true
	systemctl stop "$SYNC_UNIT" >/dev/null 2>&1 || true
	systemctl stop "$POLICY_UNIT" >/dev/null 2>&1 || true
	systemctl reset-failed "$SYNC_UNIT" >/dev/null 2>&1 || true
	systemctl reset-failed "$POLICY_UNIT" >/dev/null 2>&1 || true
	rm -rf -- "/etc/systemd/system/$SYNC_UNIT" "/etc/systemd/system/$SYNC_UNIT.d" \
		"/etc/systemd/system/$POLICY_UNIT" "/etc/systemd/system/$POLICY_UNIT.d"
	systemctl daemon-reload >/dev/null 2>&1 || true
	rm -f -- "$CONF/config.json" "$CONF/whitelist" "$CONF/intel.nft" \
		"$CONF/intel-allow.nft" "$CONF/intel-applied.json" "$CONF/policy.lock" "$POLICY_F2B"
	rm -rf -- "$CONF"/.policy.*
	rm -f -- "$STATE/intel.txt" "$STATE/intel-last-sync.txt" "$STATE/intel.nft" "$STATE"/.tmp-*
	ip netns del "$NS" 2>/dev/null || true
	rm -rf -- "$TMP"
}
trap cleanup EXIT

# Fixtures at the production paths the units hardcode.
install -d -m 0750 -o root -g root "$CONF"
install -d -m 0750 -o abuseguard -g "$AG_GROUP" "$STATE" "$STATE/reports"
chown root:"$AG_GROUP" "$CONF" && chmod 0750 "$CONF"
chown abuseguard:"$AG_GROUP" "$STATE" "$STATE/reports" && chmod 0750 "$STATE" "$STATE/reports"
install -d -m 0755 -o root -g root "$F2B_JAIL_DIR" /run/fail2ban
# Config parsing must work without a daemon; the sync unit is tested, not the
# distro fail2ban service.
systemctl stop fail2ban >/dev/null 2>&1 || true

cat > "$TMP/config.json" <<EOF
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
cat > "$TMP/whitelist" <<EOF
# CI whitelist: loopback plus one feed entry, to prove exceptions are separate.
127.0.0.0/8
203.0.113.7
EOF
install -m 0640 -o root -g "$AG_GROUP" "$TMP/config.json" "$CONF/config.json"
install -m 0640 -o root -g "$AG_GROUP" "$TMP/whitelist" "$CONF/whitelist"

mkdir -p "$TMP/feed"
cat > "$TMP/feed/feed.txt" <<'EOF'
# deterministic CI feed
203.0.113.7
198.51.100.9  US
2001:db8::1
192.0.2.33
EOF

# Private namespace: the feed server and both services share it, so nft and the
# loopback HTTP endpoint stay off the host network namespace.
ip netns del "$NS" 2>/dev/null || true # stale namespace from an aborted run of this test
ip netns add "$NS"
ip -n "$NS" link set lo up
ip netns exec "$NS" python3 -m http.server "$PORT" --bind 127.0.0.1 \
	--directory "$TMP/feed" >/dev/null 2>&1 &
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

# Real unit definitions, one isolation-only drop-in.
install -m 0644 "$ROOT/assets/systemd/caddy-abuseguard-sync.service" \
	"/etc/systemd/system/$SYNC_UNIT"
install -m 0644 "$ROOT/assets/systemd/caddy-abuseguard-policy.service" \
	"/etc/systemd/system/$POLICY_UNIT"
printf '[Service]\nNetworkNamespacePath=/run/netns/%s\n' "$NS" > "$TMP/ci-netns.conf"
for unit in "$SYNC_UNIT" "$POLICY_UNIT"; do
	install -d -m 0755 "/etc/systemd/system/$unit.d"
	install -m 0644 "$TMP/ci-netns.conf" "/etc/systemd/system/$unit.d/ci-netns.conf"
done
systemctl daemon-reload

# Root policy must come from the root-owned snapshot + validated engine export,
# never from a file the unprivileged sync user can write.
printf 'add table inet agci_poison\n' > "$STATE/intel.nft"
chown abuseguard:"$AG_GROUP" "$STATE/intel.nft"

# --- sandboxed sync + root post-apply ----------------------------------------
start_unit "$SYNC_UNIT" || fail "sandboxed sync/policy service failed"
[ "$(unit_result "$SYNC_UNIT")" = success ] || fail "sync service result was not success"

cat > "$TMP/expected-intel.txt" <<EOF
203.0.113.7
198.51.100.9
192.0.2.33
EOF
cmp -s "$TMP/expected-intel.txt" "$STATE/intel.txt" \
	|| fail "sync did not write the validated feed to intel.txt"
[ "$(stat -c '%U:%a' "$STATE/intel.txt")" = "abuseguard:640" ] \
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
nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	&& fail "test policy leaked into the host network namespace"
[ "$(cat "$STATE/intel.nft")" = 'add table inet agci_poison' ] \
	|| fail "applier modified the unprivileged state dir"
ip netns exec "$NS" nft list table inet agci_poison >/dev/null 2>&1 \
	&& fail "root applier consumed policy from the unprivileged state dir"
echo 'PASS: root post-apply installed intel + whitelist policy in the private namespace'

# --- protected paths ----------------------------------------------------------
binary_sum="$(sha256sum "$ENGINE" "$POLICY")"
[ "$(stat -c '%U:%G:%a' "$ENGINE")" = "root:root:755" ] \
	|| fail "$ENGINE is not root-owned mode 0755"
[ "$(stat -c '%U:%G:%a' "$POLICY")" = "root:root:755" ] \
	|| fail "$POLICY is not root-owned mode 0755"
[ "$(stat -c '%U:%G:%a' "$CONF")" = "root:$AG_GROUP:750" ] \
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
grep -q '^\[caddy-rate-local\]' "$POLICY_F2B" \
	|| fail "generated fail2ban policy missing a driven jail"
grep -q '127.0.0.0/8' "$POLICY_F2B" \
	|| fail "generated fail2ban policy missing the whitelist entry"
grep -q 'enabled = false' "$POLICY_F2B" \
	|| fail "generated fail2ban policy does not retire the old intel jails"
[ "$(sha256sum "$ENGINE" "$POLICY")" = "$binary_sum" ] \
	|| fail "sync/apply modified the installed executables"
executables="$(find "$STATE" -maxdepth 1 -type f -perm /111)"
[ -z "$executables" ] || fail "executable appeared in the abuseguard-writable state dir: $executables"
foreign="$(find "$STATE" -maxdepth 1 -type f ! -user abuseguard)"
[ -z "$foreign" ] || fail "state dir contains files not written by abuseguard: $foreign"
echo 'PASS: unprivileged sync cannot write executables or root-owned policy'

# --- boot restore: last-good snapshot, then normal apply ---------------------
snapshot_sum="$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")"
ip netns exec "$NS" nft delete table inet caddy_abuseguard_intel
mv -- "$STATE/intel.txt" "$TMP/intel.saved"
systemctl start "$POLICY_UNIT" >/dev/null 2>&1 \
	&& fail "boot policy apply accepted a missing feed over a non-empty policy"
[ "$(unit_result "$POLICY_UNIT")" = exit-code ] \
	|| fail "missing-feed boot apply did not fail as a unit"
systemctl reset-failed "$POLICY_UNIT" >/dev/null 2>&1 || true
ip netns exec "$NS" nft list table inet caddy_abuseguard_intel >/dev/null 2>&1 \
	|| fail "missing-feed boot apply did not restore the last-good kernel snapshot"
set_out="$(ip netns exec "$NS" nft list set inet caddy_abuseguard_intel block4)"
for ip in 203.0.113.7 198.51.100.9 192.0.2.33; do
	grep -qF "$ip" <<<"$set_out" || fail "restored snapshot lost feed entry $ip"
done
[ "$(sha256sum "$CONF/intel.nft" "$CONF/intel-allow.nft" "$CONF/intel-applied.json")" = "$snapshot_sum" ] \
	|| fail "failed boot apply changed the last-good snapshots"
echo 'PASS: boot service restores the last-good snapshot when the feed is missing'

mv -- "$TMP/intel.saved" "$STATE/intel.txt"
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
done
[ "$(stat -c '%U:%G:%a' "$POLICY_F2B")" = "root:root:644" ] \
	|| fail "boot policy service wrote a non-root fail2ban policy"
[ "$(sha256sum "$ENGINE" "$POLICY")" = "$binary_sum" ] \
	|| fail "boot apply modified the installed executables"
echo 'PASS: boot policy service applies the validated feed after a cleared table'

echo 'policy service tests: pass'
