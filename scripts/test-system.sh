#!/usr/bin/env bash
# Integration checks for a disposable, privileged Debian/systemd container
# AFTER install.sh has run. Never run this against a real server installation.
set -euo pipefail
[ "${ABUSEGUARD_TEST_SYSTEM:-}" = 1 ] && [ -f /.dockerenv ] && [ "$(id -u)" = 0 ] \
	|| { echo 'requires ABUSEGUARD_TEST_SYSTEM=1 in a disposable root Docker container' >&2; exit 2; }
WORK="$(mktemp -d)"
NS=ag-test-peer
BAD=198.18.0.2
TRUSTED=198.18.0.3
INTEL=198.18.0.6
BAD6=2001:db8:123::2
SITE=/etc/caddy/sites/abuseguard-integration.caddy
test ! -e "$SITE"
cleanup() {
	[ -z "${ECHO_PID:-}" ] || kill "$ECHO_PID" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del ag-test-host 2>/dev/null || true
	rm -f -- "$SITE"
}
trap cleanup EXIT
fail() { echo "system test failed: $* (evidence: $WORK)" >&2; exit 1; }
systemctl stop caddy-abuseguard-sync.timer caddy-abuseguard-report.timer
fail2ban-client -t
[ -x /usr/local/libexec/caddy-abuseguard ] || fail 'engine missing'
systemctl is-enabled --quiet caddy-abuseguard-policy.service || fail 'policy boot restore not enabled'
policy_exec="$(systemctl show -p ExecStart caddy-abuseguard-policy.service)"
grep -q 'policy-apply' <<<"$policy_exec" \
	|| fail 'policy boot restore does not call the engine policy-apply subcommand'
[ ! -e /usr/local/libexec/caddy-abuseguard-policy ] || fail 'legacy policy helper was not removed'
for jail in caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd; do
	fail2ban-client status "$jail" >/dev/null || fail "jail not enabled: $jail"
done
nft list table inet caddy_abuseguard_intel >/dev/null || fail 'native intel table missing'
ip netns add "$NS"
ip link add ag-test-host type veth peer name ag-test-client
ip link set ag-test-client netns "$NS"
ip addr add 198.18.0.1/29 dev ag-test-host
ip -6 addr add 2001:db8:123::1/64 dev ag-test-host nodad
ip link set ag-test-host up
ip -n "$NS" link set lo up
ip -n "$NS" link set ag-test-client up
for ip in "$BAD" "$TRUSTED" "$INTEL"; do ip -n "$NS" addr add "$ip/29" dev ag-test-client; done
ip -n "$NS" -6 addr add "$BAD6/64" dev ag-test-client nodad
cat > "$SITE" <<'EOF'
http://198.18.0.1 {
	import abuseguard
	respond "integration ok"
}
EOF
systemctl reload caddy
python3 -u - > "$WORK/echo.log" 2>&1 <<'PY' &
import socket, threading
def serve(kind, port):
    sock = socket.socket(socket.AF_INET6, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(('::', port))
    if kind == socket.SOCK_STREAM:
        sock.listen()
        while True:
            client, _ = sock.accept()
            client.close()
    else:
        while True:
            data, peer = sock.recvfrom(64)
            sock.sendto(data, peer)
threading.Thread(target=serve, args=(socket.SOCK_STREAM, 8443), daemon=True).start()
serve(socket.SOCK_DGRAM, 443)
PY
ECHO_PID=$!
sleep 1
cat > "$WORK/probe.py" <<'PY'
import socket, sys
source, destination, expected = sys.argv[1:]
for kind, port in [(socket.SOCK_STREAM, 22), (socket.SOCK_STREAM, 8443), (socket.SOCK_DGRAM, 443)]:
    family = socket.AF_INET6 if ':' in source else socket.AF_INET
    with socket.socket(family, kind) as sock:
        sock.bind((source, 0))
        sock.settimeout(1)
        try:
            sock.connect((destination, port))
            if kind == socket.SOCK_DGRAM:
                sock.send(b'probe')
                assert sock.recv(64) == b'probe'
            reachable = True
        except (OSError, AssertionError):
            reachable = False
        assert reachable == (expected == 'allow'), (source, kind, port, expected, reachable)
PY
probe() { ip netns exec "$NS" python3 "$WORK/probe.py" "$1" "${3:-198.18.0.1}" "$2"; }
has_ban() {
	local out
	out="$(fail2ban-client get "$1" banip 2>/dev/null)" || return 1
	case " $out " in *" $2 "*) return 0 ;; esac
	return 1
}
wait_ban() {
	for _ in {1..50}; do has_ban "$1" "$2" && return 0; sleep 0.2; done
	fail "no ban in $1 for $2"
}
ssh_failure() {
	printf '%s ag-test sshd[12345]: Failed password for invalid user agtest from %s port 55000 ssh2\n' "$(date '+%b %e %H:%M:%S')" "$1" >> /var/log/auth.log
}
probe "$BAD" allow
probe "$BAD6" allow 2001:db8:123::1
for _ in {1..5}; do
	ip netns exec "$NS" curl -fsS --interface "$BAD" --max-time 2 http://198.18.0.1/.env >/dev/null || true
done
wait_ban caddy-probe-h1 "$BAD"
probe "$BAD" drop
fail2ban-client set sshd banip "$BAD" >/dev/null
fail2ban-client set caddy-probe-h1 unbanip "$BAD" >/dev/null
probe "$BAD" drop
fail2ban-client unban "$BAD" >/dev/null
probe "$BAD" allow
echo 'PASS: Web detection blocks SSH, other TCP ports and UDP; independent bans survive partial unban'

retries="$(fail2ban-client get sshd maxretry)"
for ((i=0; i<retries; i++)); do ssh_failure "$BAD"; done
wait_ban sshd "$BAD"
probe "$BAD" drop
if ip netns exec "$NS" curl -fsS --interface "$BAD" --max-time 2 http://198.18.0.1/ >/dev/null 2>&1; then fail 'SSH-banned IP still reaches Web'; fi
fail2ban-client unban "$BAD" >/dev/null
echo 'PASS: SSH authentication failures trigger the global ban'

# The disposable test feed is tiny; lower the configured bounds so intel-export
# accepts it (production keeps the 90k-120k bounds).
jq '.intel.min_entries = 1 | .intel.max_entries = 1000' /etc/caddy-abuseguard/config.json > "$WORK/config.json" \
	|| fail 'could not lower intel bounds'
install -m 0640 -o root -g abuseguard "$WORK/config.json" /etc/caddy-abuseguard/config.json
printf '%s\n%s\n' "$INTEL" "$TRUSTED" > /var/lib/caddy-abuseguard/intel.txt
chown abuseguard:abuseguard /var/lib/caddy-abuseguard/intel.txt
printf '%s\n' "$TRUSTED" >> /etc/caddy-abuseguard/whitelist
chown root:abuseguard /etc/caddy-abuseguard/whitelist
chmod 0640 /etc/caddy-abuseguard/whitelist
/usr/local/bin/ag --policy-apply >/dev/null || fail 'policy apply failed'
probe "$INTEL" drop
probe "$TRUSTED" allow
sshd_ips="$(fail2ban-client status sshd 2>/dev/null | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
case " $sshd_ips " in
	*" $INTEL "*)
		fail 'intel enforcement still used fail2ban' ;;
esac
echo 'PASS: native intel table drops feed sources; the allowlist exception lets a listed source through without fail2ban'

for ((i=0; i<retries+1; i++)); do ssh_failure "$TRUSTED"; done
for _ in {1..6}; do
	ip netns exec "$NS" curl -fsS --interface "$TRUSTED" --max-time 2 http://198.18.0.1/.env >/dev/null
done
sleep 2
for jail in caddy-rate-local caddy-probe-h1 sshd; do
	if has_ban "$jail" "$TRUSTED"; then fail "allowlisted IP banned by $jail"; fi
done
probe "$TRUSTED" allow
echo 'PASS: the same allowlist overrides Web/SSH behavior and intel hits'

fail2ban-client set caddy-rate-local banip "$BAD6" >/dev/null
probe "$BAD6" drop 2001:db8:123::1
fail2ban-client unban "$BAD6" >/dev/null
probe "$BAD6" allow 2001:db8:123::1
echo 'PASS: global source-IP blocking and unban also work for IPv6'
nft list ruleset > "$WORK/nft-ruleset.txt"
echo "system integration tests: pass (evidence: $WORK)"
