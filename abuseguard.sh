#!/usr/bin/env bash
# AbuseGuard control panel.  Run:  sudo abuseguard
set -uo pipefail

CONF_DIR=/etc/caddy-abuseguard
CONFIG="$CONF_DIR/config.json"
WHITELIST="$CONF_DIR/whitelist"
KEYFILE="$CONF_DIR/abuseipdb-report.key"
ENGINE=/usr/local/libexec/caddy-abuseguard
CADDY_ENV=/etc/caddy/.env
STATE_DIR=/var/lib/caddy-abuseguard
INTEL="$STATE_DIR/intel.txt"
JAILS="caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2"
REPO_FILE="$CONF_DIR/repo"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-$( [ -f "$REPO_FILE" ] && cat "$REPO_FILE" || echo jasper-khan/abuseguard )}"

# GitHub download resiliency for the update/uninstall fetches (see install.sh).
#   ABUSEGUARD_MIRROR unset -> direct first, then auto proxy-chain fallback
#   ABUSEGUARD_MIRROR=cn    -> straight to the proxy chain
#   ABUSEGUARD_MIRROR=<p>/  -> force that one prefix
ABUSEGUARD_MIRROR="${ABUSEGUARD_MIRROR:-}"
AG_GH_MIRRORS="https://gh-proxy.com/ https://gh.ddlc.top/ https://ghproxy.net/ https://ghfast.top/"
AG_CURL="curl -fsSL --connect-timeout 10 --speed-limit 102400 --speed-time 10 --max-time 120"
gh_fetch() {  # URL OUTFILE
	local url="$1" out="$2" pfx
	case "$ABUSEGUARD_MIRROR" in
		""|0|off|no)
			$AG_CURL -o "$out" "$url" && return 0
			for pfx in $AG_GH_MIRRORS; do $AG_CURL -o "$out" "$pfx$url" && return 0; done
			return 1 ;;
		cn|1|yes|on)
			for pfx in $AG_GH_MIRRORS; do $AG_CURL -o "$out" "$pfx$url" && return 0; done
			return 1 ;;
		*) $AG_CURL -o "$out" "$ABUSEGUARD_MIRROR$url" ;;
	esac
}

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_B='\033[1;34m'; C_0='\033[0m'
pause() { echo; read -r -p "press Enter to continue..." _; }
svc_state() { systemctl is-active "$1" 2>/dev/null || echo inactive; }

count_banned() {
	local total=0 n
	for j in $JAILS; do
		n="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*\([0-9]*\).*/\1/p')"
		[ -n "$n" ] && total=$((total + n))
	done
	echo "$total"
}

reporting_state() {
	[ -f "$CONFIG" ] || { echo "?"; return; }
	[ "$(jq -r '.abuseipdb.enabled' "$CONFIG" 2>/dev/null)" = "true" ] && echo on || echo off
}

header() {
	clear 2>/dev/null || true
	local caddy f2b intel banned rep
	caddy="$(svc_state caddy)"; f2b="$(svc_state fail2ban)"
	intel="$( [ -f "$INTEL" ] && wc -l < "$INTEL" | tr -d ' ' || echo 0 )"
	banned="$(count_banned)"; rep="$(reporting_state)"
	echo -e "${C_B}=======================================================${C_0}"
	echo -e "               ${C_G}AbuseGuard${C_0}  control panel"
	echo -e "${C_B}=======================================================${C_0}"
	printf "  caddy: %b    fail2ban: %b\n" \
		"$( [ "$caddy" = active ] && echo "${C_G}active${C_0}" || echo "${C_R}${caddy}${C_0}" )" \
		"$( [ "$f2b" = active ] && echo "${C_G}active${C_0}" || echo "${C_R}${f2b}${C_0}" )"
	printf "  intel IPs: %s    banned now: %s    reporting: %b\n" \
		"$intel" "$banned" \
		"$( [ "$rep" = on ] && echo "${C_G}on${C_0}" || echo "${C_Y}off${C_0}" )"
	echo -e "${C_B}-------------------------------------------------------${C_0}"
}

act_status() {
	echo "== services =="
	for s in caddy fail2ban; do printf "  %-10s %s\n" "$s" "$(svc_state "$s")"; done
	echo; echo "== jails =="; fail2ban-client status 2>/dev/null | sed 's/^/  /'
	echo; echo "== timers =="; systemctl list-timers 'caddy-abuseguard-*' --no-pager 2>/dev/null | sed -n '1,6p'
	pause
}

act_banned() {
	for j in $JAILS; do
		echo "== $j =="
		fail2ban-client status "$j" 2>/dev/null \
			| sed -n '/Banned IP list/s/.*:[[:space:]]*//p' | tr ' ' '\n' | sed '/^$/d;s/^/  /'
	done
	pause
}

act_whitelist() {
	"${EDITOR:-nano}" "$WHITELIST"
	fail2ban-client reload >/dev/null 2>&1 || true
	echo "whitelist saved; fail2ban reloaded."
	pause
}

act_sync()  { runuser -u abuseguard -- "$ENGINE" sync-intel; pause; }
act_flush() { runuser -u abuseguard -- "$ENGINE" report send-auto; pause; }

act_key() {
	read -r -p "AbuseIPDB API key (blank = keep current): " k
	if [ -n "$k" ]; then
		printf '%s\n' "$k" > "$KEYFILE"; chown root:abuseguard "$KEYFILE"; chmod 0640 "$KEYFILE"
		echo "key saved."
	fi
	pause
}

act_cftoken() {
	read -r -p "Cloudflare API token (blank = keep current): " t
	if [ -n "$t" ]; then
		printf 'CF_API_TOKEN=%s\n' "$t" > "$CADDY_ENV"; chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
		systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
		echo "token saved; caddy reloaded."
	fi
	pause
}

act_toggle() {
	[ -f "$CONFIG" ] || { echo "no config"; pause; return; }
	local en newv tmp
	en="$(jq -r '.abuseipdb.enabled' "$CONFIG" 2>/dev/null)"
	[ "$en" = "true" ] && newv=false || newv=true
	tmp="$(mktemp)"
	if jq ".abuseipdb.enabled = $newv" "$CONFIG" > "$tmp"; then cat "$tmp" > "$CONFIG"; fi
	rm -f "$tmp"
	echo "AbuseIPDB reporting now: $newv"
	pause
}

act_logs() {
	echo "-- caddy (last 20) --";    journalctl -u caddy -n 20 --no-pager 2>/dev/null
	echo "-- fail2ban (last 20) --"; journalctl -u fail2ban -n 20 --no-pager 2>/dev/null
	pause
}

act_update() {
	echo "re-running installer from $ABUSEGUARD_REPO ..."
	local f=/tmp/abuseguard-install.sh
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/install.sh" "$f"; then
		ABUSEGUARD_MIRROR="$ABUSEGUARD_MIRROR" bash "$f" || echo "update failed."
		rm -f "$f"
	else
		echo "could not fetch install.sh (tried direct + mirrors)."
	fi
	pause
}

act_uninstall() {
	local f=/tmp/abuseguard-uninstall.sh
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/uninstall.sh" "$f"; then
		bash "$f"
		rm -f "$f"
	else
		echo "could not fetch uninstall.sh; run it from your local clone."
	fi
	pause
}

menu() {
	header
	cat <<'MENU'
   1) Status (services, jails, timers)
   2) List banned IPs (per jail)
   3) Edit whitelist
   4) Sync threat-intel now
   5) Flush report queue now
   6) Set AbuseIPDB API key
   7) Set Cloudflare API token
   8) Toggle AbuseIPDB reporting on/off
   9) View recent logs
  10) Update AbuseGuard (re-run installer)
  11) Uninstall
   0) Exit
MENU
	echo
	read -r -p "choice: " choice
	case "$choice" in
		1) act_status ;;
		2) act_banned ;;
		3) act_whitelist ;;
		4) act_sync ;;
		5) act_flush ;;
		6) act_key ;;
		7) act_cftoken ;;
		8) act_toggle ;;
		9) act_logs ;;
		10) act_update ;;
		11) act_uninstall ;;
		0) exit 0 ;;
		*) ;;
	esac
}

[ "$(id -u)" = "0" ] || { echo "run as root: sudo abuseguard"; exit 1; }
while true; do menu; done
