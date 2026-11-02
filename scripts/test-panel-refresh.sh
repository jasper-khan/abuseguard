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

grep -qx 'PANEL_REFRESH_SECONDS=1800' "$PANEL"

# Source only the function definitions, shorten the production timeout, and
# keep stdin open without sending a choice. The menu must return for a redraw
# before the holder closes the pipe two seconds later.
awk '/^# The panel needs root/{exit} {print}' "$PANEL" |
	sed 's/^PANEL_REFRESH_SECONDS=1800$/PANEL_REFRESH_SECONDS=0.1/' > "$PANEL_SOURCE"

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
firewall_policy_load() { fw_ipv4_in=1; fw_ipv6_in=0; }
firewall_toggle_family() { echo "action:family-$1"; }
act_sync() { echo 'action:sync'; }
act_flush() { echo 'action:flush'; }
act_key() { echo 'action:key'; }
act_toggle() { echo 'action:toggle'; }
act_logs() { echo 'action:logs'; }
ssh_current_ports() { echo 22; }
ssh_auth_state() { echo on; }
root_password_login_ready() { return 0; }
act_ssh_port() { echo 'action:ssh-port'; }
act_ssh_auth() { echo "action:ssh-$1"; }
act_ssh_key_add() { echo 'action:ssh-key-add'; }
act_ssh_key_remove() { echo 'action:ssh-key-remove'; }
act_ssh_password() { echo 'action:ssh-password'; }
act_update() { echo 'action:update'; }
act_uninstall() { echo 'action:uninstall'; }
printf '1\n' | menu
printf '2\n3\n0\n' | menu
printf '3\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n0\n' | menu
printf '4\n1\n2\n3\n4\n5\n6\n0\n' | menu
printf '5\n1\n2\n3\n4\n0\n' | menu
printf '6\n1\n2\n3\n0\n' | menu
for category in 2 3 4 5 6; do
	printf '%s\n0\n' "$category" | menu
done
for screen in act_sites act_firewall act_ssh act_intel act_system; do
	"$screen" </dev/null || true
done
NAVIGATION
)"
actions="$(printf '%s\n' "$navigation" | sed -n 's/^action://p')"
expected=$'status\ncftoken\nport-open\nport-close\nfamily-ipv4\nfamily-ipv6\nbanned\nban\nunban\nwhitelist\nrules\napply\nssh-port\nssh-passwordauthentication\nssh-pubkeyauthentication\nssh-key-add\nssh-key-remove\nssh-password\nsync\nflush\nkey\ntoggle\nlogs\nupdate\nuninstall'
[ "$actions" = "$expected" ] || { printf 'unexpected menu actions:\n%s\n' "$actions" >&2; exit 1; }

# Preserve long Chinese text and align paired actions without box borders.
bash --noprofile --norc -s -- "$PANEL_SOURCE" <<'LAYOUT'
set -euo pipefail
source "$1"
sample='中文对齐与长文本换行测试：TCP443,63052,33121；UDP443,58209；完整保留内容。'
rows="$(panel_row "${C_G}${sample}${C_0}" | sed $'s/\033\\[[0-9;]*m//g')"
while IFS= read -r row; do
	[ "$(printf '%s' "$row" | LC_ALL=C.UTF-8 wc -L)" -le "$PANEL_WIDTH" ]
done <<< "$rows"
joined="$(printf '%s\n' "$rows" | sed 's/^  //' | tr -d '\n')"
[ "$joined" = "$sample" ]
pair="$(panel_pair 3 "IPv4 入站  ${C_G}已开启${C_0}" 4 "IPv6 入站  ${C_D}已关闭${C_0}" | sed $'s/\033\\[[0-9;]*m//g')"
[ "$(printf '%s\n' "$pair" | wc -l)" -eq 1 ]
[ "$(printf '%s' "${pair%%\[4\]*}" | LC_ALL=C.UTF-8 wc -L)" -eq 38 ]
[ "$(printf '%s' "$pair" | LC_ALL=C.UTF-8 wc -L)" -le "$PANEL_WIDTH" ]

metrics="$(panel_metric_row "当前封禁" "1,407" "情报库" "95,627" | sed $'s/\033\\[[0-9;]*m//g')"
[ "$(printf '%s\n' "$metrics" | wc -l)" -eq 1 ]
[ "$(printf '%s' "${metrics%%情报库*}" | LC_ALL=C.UTF-8 wc -L)" -eq 27 ]
[ "$(printf '%s' "$metrics" | LC_ALL=C.UTF-8 wc -L)" -le "$PANEL_WIDTH" ]
[ "$(thousands 1407)" = 1,407 ]
[ "$(thousands 95627)" = 95,627 ]

nav="$(panel_nav_row 1 "运行概览" 2 "站点与证书" 3 "防火墙" | sed $'s/\033\\[[0-9;]*m//g')"
[ "$(printf '%s\n' "$nav" | wc -l)" -eq 1 ]
[ "$(printf '%s' "${nav%%\[2\]*}" | LC_ALL=C.UTF-8 wc -L)" -eq 27 ]
[ "$(printf '%s' "${nav%%\[3\]*}" | LC_ALL=C.UTF-8 wc -L)" -eq 51 ]
[ "$(printf '%s' "$nav" | LC_ALL=C.UTF-8 wc -L)" -le "$PANEL_WIDTH" ]

# The home navigation lists the six category names only, three per row.
header() { :; }
panel_section() { :; }
panel_footer() { :; }
home="$(printf '0\n' | menu | sed $'s/\033\\[[0-9;]*m//g')"
[ "$(printf '%s\n' "$home" | wc -l)" -eq 2 ]
expected=$'[1] 运行概览 [2] 站点与证书 [3] 防火墙\n[4] SSH 与登录 [5] 情报与上报 [6] 系统维护'
[ "$(printf '%s\n' "$home" | sed -E 's/^ +//; s/ +/ /g')" = "$expected" ]
LAYOUT

echo "panel refresh, navigation and layout tests passed"
