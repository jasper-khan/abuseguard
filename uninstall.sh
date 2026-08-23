#!/usr/bin/env bash
# AbuseGuard uninstaller for Debian/Ubuntu.
#
#   sudo ./uninstall.sh            # remove program files; keep config/whitelist/state
#   sudo ./uninstall.sh --purge    # also remove config, whitelist, state and logs
#   sudo ./uninstall.sh --dry-run  # print what would be removed, change nothing
#   add --yes to skip the confirmation prompt
#
set -euo pipefail

CONF_DIR=/etc/caddy-abuseguard
STATE_DIR=/var/lib/caddy-abuseguard
LOG_DIR=/var/log/caddy
ENGINE_BIN=/usr/local/libexec/caddy-abuseguard
PANEL_BIN=/usr/local/bin/abuseguard

PURGE=0; YES=0; DRY=0
for a in "$@"; do
	case "$a" in
		--purge) PURGE=1 ;;
		--yes|-y) YES=1 ;;
		--dry-run) DRY=1 ;;
		*) echo "unknown option: $a" >&2; exit 2 ;;
	esac
done

log() { printf '\033[1;32m[abuseguard]\033[0m %s\n' "$*"; }
run() { if [ "$DRY" = "1" ]; then echo "  would: $*"; else eval "$*"; fi; }

[ "$(id -u)" = "0" ] || { echo "run as root (sudo)" >&2; exit 1; }

log "stopping AbuseGuard timers/services"
for u in caddy-abuseguard-report.timer caddy-abuseguard-report.service \
         caddy-abuseguard-sync.timer caddy-abuseguard-sync.service; do
	run "systemctl disable --now $u >/dev/null 2>&1 || true"
done

log "removing unit files, engine, panel and fail2ban assets"
run "rm -f /etc/systemd/system/caddy-abuseguard-report.service"
run "rm -f /etc/systemd/system/caddy-abuseguard-report.timer"
run "rm -f /etc/systemd/system/caddy-abuseguard-sync.service"
run "rm -f /etc/systemd/system/caddy-abuseguard-sync.timer"
run "rm -f /etc/fail2ban/jail.d/caddy-abuseguard.local"
run "rm -f /etc/fail2ban/filter.d/caddy-abuseguard-any.conf"
run "rm -f /etc/fail2ban/filter.d/caddy-abuseguard-probe-h1.conf"
run "rm -f /etc/fail2ban/filter.d/caddy-abuseguard-probe-h2.conf"
run "rm -f /etc/fail2ban/action.d/caddy-abuseguard-queue.conf"
run "rm -f $ENGINE_BIN"
run "rm -f $PANEL_BIN"
run "rm -f /etc/caddy/abuseguard.caddy"
run "systemctl daemon-reload"
run "systemctl reload fail2ban >/dev/null 2>&1 || true"

log "left in place: the caddy binary + service, the caddy/abuseguard users, and existing nft bans."

if [ "$PURGE" = "1" ]; then
	if [ "$YES" != "1" ] && [ "$DRY" != "1" ]; then
		read -r -p "Purge $CONF_DIR, $STATE_DIR and $LOG_DIR? [y/N] " ans
		case "$ans" in y|Y|yes|YES) : ;; *) log "purge cancelled"; exit 0 ;; esac
	fi
	# guard against empty variables before any recursive removal
	[ -n "$CONF_DIR"  ] && run "rm -rf -- '$CONF_DIR'"
	[ -n "$STATE_DIR" ] && run "rm -rf -- '$STATE_DIR'"
	[ -n "$LOG_DIR"   ] && run "rm -rf -- '$LOG_DIR'"
	log "purged config, state and logs"
else
	log "kept $CONF_DIR, $STATE_DIR and $LOG_DIR (use --purge to remove them too)"
fi

log "done."
