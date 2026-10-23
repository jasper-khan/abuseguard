#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANEL="$ROOT/abuseguard.sh"
TMP="$(mktemp -d)"
PANEL_SOURCE="$TMP/panel-source.sh"
FIFO="$TMP/input"

cleanup() {
	rm -f -- "$FIFO"
	rm -f -- "$PANEL_SOURCE"
	rmdir -- "$TMP"
}
trap cleanup EXIT

grep -qx 'PANEL_REFRESH_SECONDS=10' "$PANEL"

# Source only the function definitions, shorten the production timeout, and
# keep stdin open without sending a choice. The menu must return for a redraw
# before the holder closes the pipe two seconds later.
awk '/^# The panel needs root/{exit} {print}' "$PANEL" |
	sed 's/^PANEL_REFRESH_SECONDS=10$/PANEL_REFRESH_SECONDS=0.1/' > "$PANEL_SOURCE"

result="$(
	timeout 1 bash --noprofile --norc -c '
		set -uo pipefail
		source "$1"
		header() { :; }
		panel_section() { :; }
		panel_option() { :; }
		panel_footer() { :; }
		mkfifo "$2"
		( exec 3>"$2"; sleep 2 ) &
		holder=$!
		menu < "$2" >/dev/null 2>&1
		kill "$holder" 2>/dev/null || true
		wait "$holder" 2>/dev/null || true
		printf "refreshed\n"
	' _ "$PANEL_SOURCE" "$FIFO"
)"

[ "$result" = refreshed ]

selected="$(
	bash --noprofile --norc -c '
		set -uo pipefail
		source "$1"
		header() { :; }
		panel_section() { :; }
		panel_option() { :; }
		panel_footer() { :; }
		act_status() { printf "selected\n"; }
		printf "1\n" | menu
	' _ "$PANEL_SOURCE"
)"
[ "${selected##*$'\n'}" = selected ]

# Exercise the public navigation paths with all actions replaced by doubles.
# In particular, visiting a category or returning must never run an action.
navigation="$(
	timeout 5 bash --noprofile --norc -s -- "$PANEL_SOURCE" <<'NAVIGATION'
set -euo pipefail
source "$1"
header() { :; }
panel_start() { :; }
panel_title() { :; }
panel_section() { :; }
panel_row() { :; }
panel_option() { :; }
panel_footer() { :; }
pause() { :; }
sites_lines() { :; }
cf_is_set() { return 1; }
reporting_state() { echo off; }
firewall_running() { return 0; }
firewall_ports() { :; }
firewall_check_conflicts() { :; }
systemctl() { :; }
nft() { if [ "$*" = '-a list ruleset' ]; then echo 'action:rules'; fi; }
act_status() { echo 'action:status'; }
act_cftoken() { echo 'action:cftoken'; }
firewall_change_port() { echo "action:port-$1"; }
act_banned() { echo 'action:banned'; }
act_ban() { echo 'action:ban'; }
act_unban() { echo 'action:unban'; }
act_whitelist() { echo 'action:whitelist'; }
firewall_apply() { echo 'action:apply'; }
act_sync() { echo 'action:sync'; }
act_flush() { echo 'action:flush'; }
act_key() { echo 'action:key'; }
act_toggle() { echo 'action:toggle'; }
act_logs() { echo 'action:logs'; }
act_update() { echo 'action:update'; }
act_uninstall() { echo 'action:uninstall'; }
printf '1\n' | menu
printf '2\n3\n0\n' | menu
printf '3\n1\n2\n3\n4\n5\n6\n7\n8\n0\n' | menu
printf '4\n1\n2\n3\n4\n0\n' | menu
printf '5\n1\n2\n3\n0\n' | menu
for category in 2 3 4 5; do
	printf '%s\n0\n' "$category" | menu
done
for screen in act_sites act_firewall act_intel act_system; do
	"$screen" </dev/null || true
done
NAVIGATION
)"
actions="$(printf '%s\n' "$navigation" | sed -n 's/^action://p')"
expected=$'status\ncftoken\nport-open\nport-close\nbanned\nban\nunban\nwhitelist\nrules\napply\nsync\nflush\nkey\ntoggle\nlogs\nupdate\nuninstall'
[ "$actions" = "$expected" ] || { printf 'unexpected menu actions:\n%s\n' "$actions" >&2; exit 1; }

# Keep framed rows aligned and preserve long Chinese text with ANSI colors.
bash --noprofile --norc -s -- "$PANEL_SOURCE" <<'LAYOUT'
set -euo pipefail
source "$1"
sample='中文对齐与长文本换行测试：TCP443,63052,33121；UDP443,58209；完整保留内容。'
rows="$(panel_row "${C_G}${sample}${C_0}" | sed $'s/\033\\[[0-9;]*m//g')"
while IFS= read -r row; do
	[ "$(printf '%s' "$row" | LC_ALL=C.UTF-8 wc -L)" -eq "$PANEL_WIDTH" ]
done <<< "$rows"
joined="$(printf '%s\n' "$rows" | sed 's/^│ //; s/ │$//; s/ *$//' | tr -d '\n')"
[ "$joined" = "$sample" ]
LAYOUT

echo "panel refresh, navigation and layout tests passed"
