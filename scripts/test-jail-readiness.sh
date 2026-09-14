#!/usr/bin/env bash
# Use Fail2Ban's real configuration loader to reproduce a later SSH override.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
mkdir "$TMP/jail.d" "$TMP/filter.d"
cleanup() {
	rm -f -- "$TMP/fail2ban.conf"
	rm -f -- "$TMP/jail.conf"
	rm -f -- "$TMP/jail.d/zz-caddy-abuseguard-report.local"
	rm -f -- "$TMP/jail.d/zz-disable-sshd.local"
	rm -f -- "$TMP/filter.d/test.conf"
	rm -f -- "$TMP/auth.log"
	rm -f -- "$TMP/error"
	rmdir -- "$TMP/jail.d" "$TMP/filter.d" "$TMP"
}
trap cleanup EXIT
cp /etc/fail2ban/fail2ban.conf "$TMP/fail2ban.conf"
eval "$(awk '/^verify_fail2ban_jails\(\) \{/ {p=1} p {print} p && /^}$/ {exit}' "$ROOT/install.sh")"
die() { echo "$*" >&2; exit 1; }
fail2ban-client() { command fail2ban-client -c "$TMP" "$@"; }
cat > "$TMP/filter.d/test.conf" <<'EOF'
[Definition]
failregex = ^<HOST> rejected$
EOF
touch "$TMP/auth.log"
cat > "$TMP/jail.conf" <<EOF
[DEFAULT]
enabled = true
filter = test
logpath = $TMP/auth.log
backend = polling
action =
EOF
for jail in caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd sshd-intel; do
	printf '\n[%s]\n' "$jail" >> "$TMP/jail.conf"
done
printf '[sshd]\nenabled = true\n' > "$TMP/jail.d/zz-caddy-abuseguard-report.local"
printf '[sshd]\nenabled = false\n' > "$TMP/jail.d/zz-disable-sshd.local"
if (trap - EXIT; verify_fail2ban_jails config) 2> "$TMP/error"; then
	die 'later SSH disable override was accepted'
fi
grep -q '未启用 sshd' "$TMP/error"
printf '[sshd]\nenabled = true\n' > "$TMP/jail.d/zz-disable-sshd.local"
verify_fail2ban_jails config

# Service activation alone is not readiness; allow startup delay but fail if
# one required jail remains unavailable.
calls=0
sleep() { :; }
fail2ban-client() {
	[ "$1" = status ] || return 2
	calls=$((calls + 1))
	[ "$calls" -gt 6 ]
}
verify_fail2ban_jails running
[ "$calls" -eq 12 ]
fail2ban-client() { [ "$2" != sshd ]; }
if (trap - EXIT; verify_fail2ban_jails running) 2> "$TMP/error"; then
	die 'missing runtime SSH jail was accepted'
fi
grep -q 'sshd' "$TMP/error"
echo 'jail readiness tests: pass'
