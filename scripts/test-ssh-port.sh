#!/usr/bin/env bash
# SSH port switch keeps both ports; the old port is retired from the firewall menu.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
	rm -f -- "$TMP/panel.sh" "$TMP/sshd_config" "$TMP/report.local"
	rm -f -- "$TMP/listen" "$TMP/calls" "$TMP/fw.nft"
	rm -f -- "$TMP/dropin/99-abuseguard-port.conf" "$TMP/dropin/99-ssh-port.conf"
	rmdir -- "$TMP/dropin" 2>/dev/null || true
	rmdir -- "$TMP" 2>/dev/null || true
}
trap cleanup EXIT
awk '/^# The panel needs root/{exit} {print}' "$ROOT/abuseguard.sh" > "$TMP/panel.sh"
source "$TMP/panel.sh"

# Keep the real firewall close implementation for the retire-old-port tests.
eval "$(declare -f firewall_change_port | sed '1s/^firewall_change_port/real_firewall_change_port/')"

SSHD_MAIN="$TMP/sshd_config"
SSHD_DROPIN_DIR="$TMP/dropin"
SSHD_DROPIN="$SSHD_DROPIN_DIR/99-abuseguard-port.conf"
SSH_REPORT_JAIL="$TMP/report.local"
FIREWALL_FILE="$TMP/fw.nft"
mkdir "$SSHD_DROPIN_DIR"

fail() { echo "ssh port test failed: $*" >&2; exit 1; }

SOCKET_ACTIVE=0
RELOAD_FAIL=0
SSHD_T_FAIL=0
ss() {
	local filter="${!#}" port
	if [ "$filter" = -tlnp ] || [ "$filter" = -tln ]; then
		while IFS= read -r port; do
			printf 'LISTEN 0 128 0.0.0.0:%s users:(("sshd",pid=1))\n' "$port"
		done < "$TMP/listen"
		return 0
	fi
	case "$filter" in
		"sport = :"*) port="${filter#sport = :}" ;;
		*) return 0 ;;
	esac
	if grep -qxF "$port" "$TMP/listen"; then
		printf 'LISTEN 0 128 0.0.0.0:%s users:(("sshd",pid=1))\n' "$port"
		return 0
	fi
	return 1
}
# Port is multi-valued: sshd listens on every Port line, defaulting to 22.
sshd_ports() {
	{ grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_MAIN" 2>/dev/null
		grep -rhE --include='*.conf' '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_DROPIN_DIR" 2>/dev/null || true; } |
		awk '{ print "port", $2 }'
}
sshd() {
	local ports
	ports="$(sshd_ports)"
	case "$1" in
		-T) [ -n "$ports" ] && printf '%s\n' "$ports" || echo "port 22" ;;
		-t) [ "$SSHD_T_FAIL" = 0 ] ;;
		*) return 1 ;;
	esac
}
systemctl() {
	case "$1" in
		cat) return 0 ;;
		is-active) [ "$SOCKET_ACTIVE" = 1 ] ;;
		reload)
			printf 'reload\n' >> "$TMP/calls"
			[ "$RELOAD_FAIL" = 0 ] || return 1
			: > "$TMP/listen"
			sshd_ports | awk '{ print $2 }' | sort -u > "$TMP/listen"
			[ -s "$TMP/listen" ] || echo 22 > "$TMP/listen"
			return 0 ;;
		*) return 1 ;;
	esac
}
# Recorder used by act_ssh_port; keeps the saved firewall file in step.
firewall_change_port() {
	printf 'fw %s\n' "$*" >> "$TMP/calls"
	case "$1" in
		open) printf '%s %s\n' "$2" "$3" >> "$FIREWALL_FILE" ;;
		close) printf '%s\n' "$(grep -vxF "$2 $3" "$FIREWALL_FILE")" > "$FIREWALL_FILE" ;;
	esac
	return 0
}
firewall_check_conflicts() { return 0; }
firewall_ports() { cat "$FIREWALL_FILE"; }
firewall_save() { printf '%s\n' "$1" | grep . | sort -u > "$FIREWALL_FILE"; printf 'save\n' >> "$TMP/calls"; return 0; }
firewall_running() { return 0; }
fail2ban-client() { printf 'f2b %s\n' "$*" >> "$TMP/calls"; return 0; }
sleep() { :; }

reset_all() {
	printf '#Port 22\n' > "$SSHD_MAIN"
	rm -f -- "$SSHD_DROPIN" "$SSHD_DROPIN_DIR/99-ssh-port.conf"
	: > "$TMP/listen"
	printf '22\n' > "$TMP/listen"
	printf 'tcp 22\n' > "$FIREWALL_FILE"
	: > "$TMP/calls"
	printf '[sshd]\naction = caddy-abuseguard-queue[profile=ssh-bruteforce, transport=SSH, target_port=22, window="%%(findtime)s"]\n' > "$SSH_REPORT_JAIL"
	SSH_CONNECTION=''
	SOCKET_ACTIVE=0
	RELOAD_FAIL=0
	SSHD_T_FAIL=0
}
run_ssh_port() { printf '%b' "$1" | act_ssh_port; }
close_port() { real_firewall_change_port close tcp "$1"; }
called() { grep -qxF "$1" "$TMP/calls"; }
listening() { grep -qxF "$1" "$TMP/listen"; }
fw_open() { grep -qxF "tcp $1" "$FIREWALL_FILE"; }

# No Port directive: add the new port while keeping the default 22.
reset_all
run_ssh_port '2222\ny\n' >/dev/null || fail 'switch returned non-zero'
grep -qxF 'Port 22' "$SSHD_DROPIN" || fail 'old port not kept during the switch'
grep -qxF 'Port 2222' "$SSHD_DROPIN" || fail 'new port not added'
listening 22 && listening 2222 || fail 'both ports should listen after the switch'
called reload || fail 'sshd not reloaded'
called 'fw open tcp 2222' || fail 'new port not opened'
fw_open 22 || fail 'old port rule removed too early'
grep -qF 'target_port=2222' "$SSH_REPORT_JAIL" || fail 'report port not synced'

# Reconnecting on the new port, then closing the old one from the firewall menu:
# the old Port directive and its firewall rule both go away.
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 2222'
close_port 22 >/dev/null || fail 'closing the old port failed'
grep -qE '^[[:space:]]*Port[[:space:]]+22([[:space:]]|$)' "$SSHD_DROPIN" && fail 'old Port directive survived the close'
grep -qxF 'Port 2222' "$SSHD_DROPIN" || fail 'new Port lost while closing the old one'
listening 22 && fail 'old port still listening after close'
listening 2222 || fail 'new port stopped listening after close'
fw_open 22 && fail 'old firewall rule survived the close'
fw_open 2222 || fail 'new firewall rule lost while closing the old one'

# An existing single Port stays put during the switch; closing removes it in place.
reset_all
printf '# existing migration\nPort 22\n# keep me\n' > "$SSHD_MAIN"
run_ssh_port '2222\ny\n' >/dev/null || fail 'did not keep an existing Port during the switch'
grep -qxF 'Port 22' "$SSHD_MAIN" || fail 'existing Port removed too early'
grep -qxF 'Port 2222' "$SSHD_DROPIN" || fail 'new Port not added alongside'
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 2222'
close_port 22 >/dev/null || fail 'closing an existing Port failed'
grep -qE '^[[:space:]]*Port[[:space:]]+22([[:space:]]|$)' "$SSHD_MAIN" && fail 'old Port line survived the close'
grep -qxF '# keep me' "$SSHD_MAIN" || fail 'close dropped unrelated lines'
grep -qxF 'Port 2222' "$SSHD_DROPIN" || fail 'new Port lost during close'

# A single Port drop-in (a machine migrated earlier) works the same way.
reset_all
printf '# migrated\nPort 22\n' > "$SSHD_DROPIN_DIR/99-ssh-port.conf"
run_ssh_port '2222\ny\n' >/dev/null || fail 'did not switch from a migrated drop-in'
grep -qxF 'Port 22' "$SSHD_DROPIN_DIR/99-ssh-port.conf" || fail 'migrated Port removed too early'
grep -qxF 'Port 2222' "$SSHD_DROPIN" || fail 'new Port not added for a migrated drop-in'
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 2222'
close_port 22 >/dev/null || fail 'closing a migrated Port failed'
grep -qE '^[[:space:]]*Port[[:space:]]+22([[:space:]]|$)' "$SSHD_DROPIN_DIR/99-ssh-port.conf" && fail 'migrated old Port survived'
grep -qxF '# migrated' "$SSHD_DROPIN_DIR/99-ssh-port.conf" || fail 'migrated drop-in comment lost'

# The current session port cannot be closed from the firewall menu.
reset_all
run_ssh_port '2222\ny\n' >/dev/null || fail 'setup for the session-port guard failed'
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22'
if close_port 22 >/dev/null 2>&1; then fail 'closed the current session port'; fi
grep -qxF 'Port 22' "$SSHD_DROPIN" || fail 'session-port guard changed the config'
fw_open 22 || fail 'session-port guard changed the firewall'

# The only SSH port cannot be closed.
reset_all
if close_port 22 >/dev/null 2>&1; then fail 'closed the only SSH port'; fi
fw_open 22 || fail 'last-port guard changed the firewall'

# A listening port with no Port directive cannot be retired; the close is refused.
reset_all
printf 'Port 22\n' > "$SSHD_MAIN"
printf '2222\n' >> "$TMP/listen"
printf 'tcp 2222\n' >> "$FIREWALL_FILE"
if close_port 2222 >/dev/null 2>&1; then fail 'closed a port with no Port directive'; fi
fw_open 2222 || fail 'refused close still changed the firewall'
listening 2222 || fail 'refused close stopped the port'

# Removing the last configured Port is rolled back, even if another port listens.
reset_all
printf 'Port 22\n' > "$SSHD_MAIN"
printf '2222\n' >> "$TMP/listen"
printf 'tcp 2222\n' >> "$FIREWALL_FILE"
if close_port 22 >/dev/null 2>&1; then fail 'removed the last configured Port'; fi
grep -qxF 'Port 22' "$SSHD_MAIN" || fail 'last-Port rollback did not restore the config'
fw_open 22 || fail 'last-Port rollback changed the firewall'

# A missing drop-in directory is refused before writing anything.
reset_all
SSHD_DROPIN_DIR="$TMP/missing"
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted a missing drop-in directory'; fi
[ -e "$TMP/missing" ] && fail 'created the drop-in directory'
SSHD_DROPIN_DIR="$TMP/dropin"

# Duplicate Port directives cannot be switched safely.
reset_all
printf 'Port 22\nPort 22\n' > "$SSHD_MAIN"
before="$(cat "$SSHD_MAIN")"
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted duplicate Port directives'; fi
[ "$(cat "$SSHD_MAIN")" = "$before" ] || fail 'changed a duplicate-Port config'
[ -e "$SSHD_DROPIN" ] && fail 'wrote a drop-in despite duplicate Ports'

# Two different Port directives are refused before any change.
reset_all
printf 'Port 22\nPort 2200\n' > "$SSHD_MAIN"
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted multiple listening Ports'; fi

# A port already in use by another service is refused.
reset_all
printf '2222\n' >> "$TMP/listen"
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted a busy port'; fi
[ -e "$SSHD_DROPIN" ] && fail 'wrote a drop-in for a busy port'

# sshd -t failure rolls back before the firewall is touched.
reset_all
SSHD_T_FAIL=1
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted an invalid config'; fi
[ -e "$SSHD_DROPIN" ] && fail 'left the drop-in after sshd -t failure'
if called 'fw open tcp 2222'; then fail 'opened the port before config validation'; fi

# Reload failure restores the config and removes the opened port.
reset_all
RELOAD_FAIL=1
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted a reload failure'; fi
[ -e "$SSHD_DROPIN" ] && fail 'left the drop-in after reload rollback'
called 'fw close tcp 2222' || fail 'opened port was not rolled back'

# Socket activation ignores Port in sshd_config.
reset_all
SOCKET_ACTIVE=1
if run_ssh_port '2222\ny\n' >/dev/null 2>&1; then fail 'accepted ssh.socket activation'; fi

echo 'ssh port tests: pass'
