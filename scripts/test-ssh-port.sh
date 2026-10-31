#!/usr/bin/env bash
# Panel SSH port change: guards, ordering and rollback, with command doubles.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
	rm -f -- "$TMP/panel.sh" "$TMP/sshd_config" "$TMP/report.local"
	rm -f -- "$TMP/listen" "$TMP/calls" "$TMP/fw.nft"
	rm -f -- "$TMP/dropin/99-abuseguard-port.conf"
	rmdir -- "$TMP/dropin" 2>/dev/null || true
	rmdir -- "$TMP" 2>/dev/null || true
}
trap cleanup EXIT
awk '/^# The panel needs root/{exit} {print}' "$ROOT/abuseguard.sh" > "$TMP/panel.sh"
source "$TMP/panel.sh"

SSHD_MAIN="$TMP/sshd_config"
SSHD_DROPIN_DIR="$TMP/dropin"
SSHD_DROPIN="$SSHD_DROPIN_DIR/99-abuseguard-port.conf"
SSH_REPORT_JAIL="$TMP/report.local"
FIREWALL_FILE="$TMP/fw.nft"
mkdir "$SSHD_DROPIN_DIR"
: > "$FIREWALL_FILE"

fail() { echo "ssh port test failed: $*" >&2; exit 1; }

SOCKET_ACTIVE=0
RELOAD_FAIL=0
ss() {
	local filter="${!#}" port
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
sshd() {
	local ports
	ports="$({ grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_MAIN" "$SSHD_DROPIN" 2>/dev/null || true; } |
		awk '{ print "port", $2 }')"
	case "$1" in
		-T) [ -n "$ports" ] && printf '%s\n' "$ports" || echo "port 22" ;;
		-t) return 0 ;;
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
			local p
			p="$(awk '/^Port /{print $2}' "$SSHD_DROPIN" 2>/dev/null)"
			if [ -n "$p" ]; then
				: > "$TMP/listen"
				printf '%s\n' "$p" >> "$TMP/listen"
			fi
			return 0 ;;
		*) return 1 ;;
	esac
}
firewall_change_port() { printf 'fw %s\n' "$*" >> "$TMP/calls"; return 0; }
firewall_running() { return 0; }
fail2ban-client() { printf 'f2b %s\n' "$*" >> "$TMP/calls"; return 0; }
sleep() { :; }

reset_all() {
	printf '#Port 22\n' > "$SSHD_MAIN"
	rm -f -- "$SSHD_DROPIN" 2>/dev/null
	: > "$TMP/listen"
	printf '22\n' > "$TMP/listen"
	: > "$TMP/calls"
	printf '[sshd]\naction = caddy-abuseguard-queue[profile=ssh-bruteforce, transport=SSH, target_port=22, window="%%(findtime)s"]\n' > "$SSH_REPORT_JAIL"
	SOCKET_ACTIVE=0
	RELOAD_FAIL=0
}
run_ssh_port() { printf '%b' "$1" | act_ssh_port; }
called() { grep -qxF "$1" "$TMP/calls"; }

# Success while connected on the old port: switch, sync the report port, and
# keep the old port open so the current session cannot be cut off.
reset_all
SSH_CONNECTION='192.0.2.1 50000 192.0.2.2 22'
run_ssh_port '2222\nyes\n' >/dev/null || fail 'success path returned non-zero'
[ "$(cat "$SSHD_DROPIN")" = 'Port 2222' ] || fail 'drop-in not written'
called reload || fail 'sshd not reloaded'
called 'fw open tcp 2222' || fail 'new port not opened'
if called 'fw close tcp 22'; then fail 'closed the current session port'; fi
grep -qF 'target_port=2222' "$SSH_REPORT_JAIL" || fail 'report port not synced'

# The old port always stays allowed; closing it is a manual follow-up.
reset_all
SSH_CONNECTION=''
run_ssh_port '2222\nyes\n' >/dev/null || fail 'success path without session failed'
if called 'fw close tcp 22'; then fail 'old port was auto-closed'; fi

# An explicit Port elsewhere would make sshd listen on both ports.
reset_all
printf 'Port 22\n' > "$SSHD_MAIN"
if run_ssh_port '2222\nyes\n' >/dev/null 2>&1; then fail 'accepted an explicit Port'; fi
[ -f "$SSHD_DROPIN" ] && fail 'wrote a drop-in despite the conflict'
called 'fw open tcp 2222' && fail 'changed the firewall despite the conflict'

# A port already in use by another service is refused.
reset_all
printf '2222\n' >> "$TMP/listen"
if run_ssh_port '2222\nyes\n' >/dev/null 2>&1; then fail 'accepted a busy port'; fi
[ -f "$SSHD_DROPIN" ] && fail 'wrote a drop-in for a busy port'

# sshd -t failure rolls back before the firewall is touched.
reset_all
sshd() { case "$1" in -T) echo 'port 22' ;; -t) return 1 ;; esac; }
if run_ssh_port '2222\nyes\n' >/dev/null 2>&1; then fail 'accepted an invalid config'; fi
[ -f "$SSHD_DROPIN" ] && fail 'left the drop-in after sshd -t failure'
if called 'fw open tcp 2222'; then fail 'opened the port before config validation'; fi

# Reload failure restores the config and removes the opened port.
reset_all
sshd() {
	local ports
	ports="$({ grep -hE '^[[:space:]]*Port[[:space:]]+[0-9]+' "$SSHD_MAIN" "$SSHD_DROPIN" 2>/dev/null || true; } |
		awk '{ print "port", $2 }')"
	case "$1" in
		-T) [ -n "$ports" ] && printf '%s\n' "$ports" || echo "port 22" ;;
		-t) return 0 ;;
		*) return 1 ;;
	esac
}
RELOAD_FAIL=1
if run_ssh_port '2222\nyes\n' >/dev/null 2>&1; then fail 'accepted a reload failure'; fi
[ -f "$SSHD_DROPIN" ] && fail 'left the drop-in after reload rollback'
called 'fw close tcp 2222' || fail 'opened port was not rolled back'

# Socket activation ignores Port in sshd_config.
reset_all
SOCKET_ACTIVE=1
if run_ssh_port '2222\nyes\n' >/dev/null 2>&1; then fail 'accepted ssh.socket activation'; fi

echo 'ssh port tests: pass'
