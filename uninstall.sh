#!/usr/bin/env bash
# AbuseGuard uninstaller for Debian/Ubuntu.
#
# Two modes (chosen interactively, or via flags):
#   --conservative   remove AbuseGuard; KEEP Caddy + your reverse-proxy sites
#   --purge          thorough: also remove what AbuseGuard installed (Caddy /
#                    accounts / config), guided by the install manifest so
#                    anything that pre-existed the install is left untouched
#   --keep-sites | --drop-sites   managed sites: keep (de-protect) / delete
#   --yes            skip confirmation      --dry-run   print, change nothing
#
# Uninstall is symmetric to install: it reads /var/lib/caddy-abuseguard/
# install-manifest (written at install time) and only removes things AbuseGuard
# itself created. If the manifest is missing it falls back to the safest path
# (touch nothing that might be the user's: Caddy, accounts, config).
set -uo pipefail

CONF_DIR=/etc/caddy-abuseguard
STATE_DIR=/var/lib/caddy-abuseguard
LOG_DIR=/var/log/caddy
ENGINE_BIN=/usr/local/libexec/caddy-abuseguard
PANEL_BIN=/usr/local/bin/abuseguard
CADDY_BIN=/usr/local/bin/caddy
CADDY_ETC=/etc/caddy
CADDYFILE=/etc/caddy/Caddyfile
SNIPPET=/etc/caddy/abuseguard.caddy
SITES_DIR=/etc/caddy/sites
CADDY_ENV=/etc/caddy/.env
CADDY_LIB=/var/lib/caddy
MANIFEST="$STATE_DIR/install-manifest"

MODE=""; KEEP_SITES=""; YES=0; DRY=0
for a in "$@"; do case "$a" in
	--conservative) MODE=conservative ;;
	--purge|--all|--thorough) MODE=thorough ;;
	--keep-sites) KEEP_SITES=keep ;;
	--drop-sites) KEEP_SITES=drop ;;
	--yes|-y) YES=1 ;;
	--dry-run) DRY=1 ;;
	*) echo "unknown option: $a" >&2; exit 2 ;;
esac; done

log()  { printf '\033[1;32m[abuseguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[abuseguard]\033[0m %s\n' "$*" >&2; }
run()  { if [ "$DRY" = 1 ]; then echo "  would: $*"; else eval "$*"; fi; }
have_tty() { { exec 3</dev/tty; } 2>/dev/null; }

remove_file() {
	local path="$1"
	if [ "$DRY" = 1 ]; then
		echo "  would: rm -f -- $path"
	else
		rm -f -- "$path"
	fi
}

# Recursively clear only directories owned by this installer. Every entry is
# removed individually and each directory is removed only after it is empty.
remove_owned_tree() {
	local root="$1" path
	case "$root" in
		"$CONF_DIR"|"$STATE_DIR"|"$LOG_DIR"|"$SITES_DIR"|"$CADDY_LIB") : ;;
		*) warn "拒绝清理非 AbuseGuard 目录：$root"; return 1 ;;
	esac
	[ -e "$root" ] || return 0
	[ ! -L "$root" ] || { warn "拒绝清理符号链接：$root"; return 1; }
	if [ "$DRY" = 1 ]; then
		echo "  would: 逐项清空并删除 $root"
		return 0
	fi
	while IFS= read -r -d '' path; do
		if [ -d "$path" ] && [ ! -L "$path" ]; then
			rmdir -- "$path" || return 1
		else
			rm -f -- "$path" || return 1
		fi
	done < <(find "$root" -xdev -depth -mindepth 1 -print0)
	rmdir -- "$root"
}

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }

# --- read the install manifest (missing key/file => 1 = "pre-existing" = keep)
mval() {
	local v=""
	[ -f "$MANIFEST" ] && v="$(grep -E "^$1=" "$MANIFEST" 2>/dev/null | head -1 | cut -d= -f2)"
	echo "${v:-1}"
}
if [ -f "$MANIFEST" ]; then MANIFEST_OK=1; else MANIFEST_OK=0; fi
m_caddy_bin="$(mval caddy_bin_preexisting)"
m_caddy_svc="$(mval caddy_service_preexisting)"
m_caddy_user="$(mval caddy_user_preexisting)"
m_ag_user="$(mval abuseguard_user_preexisting)"
m_caddyfile="$(mval caddyfile_preexisting)"
m_caddy_etc="$(mval caddy_etc_preexisting)"
m_log_dir="$(mval log_dir_preexisting)"
m_caddy_lib="$(mval caddy_lib_preexisting)"

if [ "$MANIFEST_OK" = 0 ]; then
	warn "未找到安装清单，无法确认哪些是 AbuseGuard 安装的；为安全起见将不动 Caddy/账户/配置。"
fi

# --- count AbuseGuard-managed sites -----------------------------------------
site_count=0
if [ -d "$SITES_DIR" ]; then
	for f in "$SITES_DIR"/*.caddy; do
		[ -e "$f" ] || continue
		[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
		site_count=$((site_count + 1))
	done
fi

# --- choose mode -------------------------------------------------------------
if [ -z "$MODE" ]; then
	if [ "$YES" = 1 ] || ! have_tty; then
		MODE=conservative
	else
		echo "卸载模式："
		echo "  [1] 保守卸载：删 AbuseGuard，保留 Caddy 和你的反代站点"
		echo "  [2] 彻底卸载：连 AbuseGuard 安装的 Caddy/账户/配置一起删（按安装清单，不动你原有的）"
		echo "  [0] 取消"
		read -r -p "请选择: " a <&3; exec 3<&-
		case "$a" in 1) MODE=conservative ;; 2) MODE=thorough ;; *) echo "已取消"; exit 0 ;; esac
	fi
fi

# --- ask about AbuseGuard-managed sites (only if any exist) -----------------
if [ "$site_count" -gt 0 ] && [ -z "$KEEP_SITES" ]; then
	if [ "$YES" = 1 ] || ! have_tty; then
		KEEP_SITES=keep
	else
		echo "检测到 $site_count 个 AbuseGuard 管理的受保护站点："
		for f in "$SITES_DIR"/*.caddy; do
			[ -e "$f" ] || continue
			[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
			d="$(basename "$f" .caddy)"
			u="$(grep -oE 'reverse_proxy[[:space:]]+[^ ]+' "$f" 2>/dev/null | head -1 | awk '{print $2}')"
			echo "    $d → ${u:-?}"
		done
		echo "  [1] 保留反代，只去掉 AbuseGuard 防护（网站继续可访问）"
		echo "  [2] 连反代一起删除"
		read -r -p "请选择: " a <&3; exec 3<&-
		case "$a" in 2) KEEP_SITES=drop ;; *) KEEP_SITES=keep ;; esac
	fi
fi
[ -z "$KEEP_SITES" ] && KEEP_SITES=keep

# --- confirm -----------------------------------------------------------------
if [ "$YES" != 1 ] && [ "$DRY" != 1 ]; then
	echo
	echo "即将执行：$([ "$MODE" = thorough ] && echo '彻底卸载' || echo '保守卸载')；面板站点：$([ "$KEEP_SITES" = drop ] && echo '删除' || echo '保留反代')"
	if [ "$MODE" = thorough ]; then
		[ "$m_caddy_bin" = 0 ]  && echo "  · 将删除 Caddy 二进制（AbuseGuard 安装的）" || echo "  · 保留 Caddy 二进制（你原有的）"
		[ "$m_caddy_user" = 0 ] && echo "  · 将删除 caddy 账户" || echo "  · 保留 caddy 账户（你原有的）"
		echo "  · 将删除 AbuseGuard 的配置/状态目录"
		[ "$m_log_dir" = 0 ]  && echo "  · 将删除 $LOG_DIR（AbuseGuard 创建的）" || echo "  · 保留 $LOG_DIR（你原有的日志目录，只删 AbuseGuard 自己的日志文件）"
	fi
	c=n; have_tty && { read -r -p "确认继续? [y/N] " c <&3; exec 3<&-; }
	case "$c" in y|Y|yes|YES) : ;; *) echo "已取消"; exit 0 ;; esac
fi

# --- Caddyfile cleanup: strip AbuseGuard's own bits, keep the user's ---------
clean_caddyfile() {
	[ -f "$CADDYFILE" ] || return 0
	local drop_sites=0; [ "$KEEP_SITES" = drop ] && drop_sites=1
	if [ "$DRY" = 1 ]; then echo "  would: 清理 $CADDYFILE（摘除 import abuseguard / snippet$([ "$drop_sites" = 1 ] && echo ' / import sites') / 自检站点块）"; return 0; fi
	local tmp; tmp="$(mktemp)"
	awk -v drop_sites="$drop_sites" '
		/^[[:space:]]*http:\/\/127\.0\.0\.1:8080[[:space:]]*\{/ { insb=1; d=1; next }
		insb==1 { o=gsub(/\{/,"{"); c=gsub(/\}/,"}"); d+=o-c; if (d<=0) insb=0; next }
		/^[[:space:]]*import[[:space:]]+[^ ]*abuseguard\.caddy[[:space:]]*$/ { next }
		/^[[:space:]]*import[[:space:]]+[^ ]*\/sites\/\*\.caddy[[:space:]]*$/ { if (drop_sites) next; else { print; next } }
		/^[[:space:]]*import[[:space:]]+abuseguard[[:space:]]*$/ { next }
		{ print }
	' "$CADDYFILE" > "$tmp" && cat "$tmp" > "$CADDYFILE"
	remove_file "$tmp"
}

# strip `import abuseguard` from each managed site file, keeping the reverse proxy
clean_sites_keep() {
	[ -d "$SITES_DIR" ] || return 0
	local f
	for f in "$SITES_DIR"/*.caddy; do
		[ -e "$f" ] || continue
		[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
		if [ "$DRY" = 1 ]; then echo "  would: 从 $f 去掉 import abuseguard（保留反代）"; continue; fi
		sed -i '/^[[:space:]]*import[[:space:]]\+abuseguard[[:space:]]*$/d' "$f"
	done
}

# --- 1) stop + remove AbuseGuard's own components (both modes) ----------------
log "停止并移除 AbuseGuard 组件"
for u in caddy-abuseguard-report.timer caddy-abuseguard-report.service \
         caddy-abuseguard-sync.timer caddy-abuseguard-sync.service; do
	run "systemctl disable --now $u >/dev/null 2>&1 || true"
done
remove_file /etc/systemd/system/caddy-abuseguard-report.service
remove_file /etc/systemd/system/caddy-abuseguard-report.timer
remove_file /etc/systemd/system/caddy-abuseguard-sync.service
remove_file /etc/systemd/system/caddy-abuseguard-sync.timer
remove_file /etc/fail2ban/jail.d/caddy-abuseguard.local
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-any.conf
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-probe-h1.conf
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-probe-h2.conf
remove_file /etc/fail2ban/action.d/caddy-abuseguard-queue.conf
remove_file "$ENGINE_BIN"
remove_file "$PANEL_BIN"
remove_file "$SNIPPET"

# --- 2) sites + Caddyfile ----------------------------------------------------
if [ "$KEEP_SITES" = keep ]; then
	clean_sites_keep            # de-protect panel sites, keep the reverse proxy
else
	remove_owned_tree "$SITES_DIR" || exit 1
fi
clean_caddyfile                 # strip AbuseGuard's imports / self-test block

# --- 3) thorough: remove what AbuseGuard installed (per manifest) ------------
if [ "$MODE" = thorough ]; then
	if [ "$m_caddy_svc" = 0 ]; then
		run "systemctl disable --now caddy >/dev/null 2>&1 || true"
		remove_file /etc/systemd/system/caddy.service
	fi
	[ "$m_caddy_bin" = 0 ]  && remove_file "$CADDY_BIN"
	# only delete the Caddyfile if AbuseGuard created it (else we kept the user's, just cleaned)
	if [ "$m_caddyfile" = 0 ]; then
		remove_file "$CADDYFILE"
		remove_file "$CADDY_ETC/Caddyfile.pre-abuseguard"
	fi
	[ "$m_ag_user" = 0 ]    && run "userdel abuseguard >/dev/null 2>&1 || true"
	if [ "$m_caddy_user" = 0 ]; then
		run "userdel caddy >/dev/null 2>&1 || true"
		if [ "$m_caddy_lib" = 0 ]; then
			remove_owned_tree "$CADDY_LIB" || exit 1
		else
			log "已保留 /var/lib/caddy（你原有的 Caddy 数据/证书目录）"
		fi
	fi
	remove_owned_tree "$CONF_DIR" || exit 1
	remove_owned_tree "$STATE_DIR" || exit 1
	# Only remove the log dir if AbuseGuard created it. A pre-existing
	# /var/log/caddy is almost certainly the user's own Caddy logs (it is the
	# packaged default), so there we delete only our own log files.
	if [ "$m_log_dir" = 0 ]; then
		remove_owned_tree "$LOG_DIR" || exit 1
	else
		for f in "$LOG_DIR"/abuseguard-access*.json; do
			[ -e "$f" ] || continue
			remove_file "$f"
		done
		log "已保留你原有的 $LOG_DIR（仅删除 AbuseGuard 自己的日志文件）"
	fi
	# remove /etc/caddy only if AbuseGuard created it and it's now empty
	# Remove the files AbuseGuard itself created in /etc/caddy, so the dir can
	# actually be removed. Keep .env if it holds a token the user configured.
	if [ "$m_caddy_etc" = 0 ]; then
		if [ -f "$CADDY_ENV" ] && ! grep -qE '^CF_API_TOKEN=.+' "$CADDY_ENV" 2>/dev/null; then
			remove_file "$CADDY_ENV"
		elif [ -f "$CADDY_ENV" ]; then
			warn "保留 $CADDY_ENV（内含你设置的 CF_API_TOKEN）"
		fi
		[ -f "$SITES_DIR/_placeholder.caddy" ] && remove_file "$SITES_DIR/_placeholder.caddy"
		run "rmdir '$SITES_DIR' 2>/dev/null || true"
		if [ "$DRY" != 1 ]; then
			if rmdir "$CADDY_ETC" 2>/dev/null; then
				log "已删除 $CADDY_ETC"
			elif [ -d "$CADDY_ETC" ]; then
				warn "保留 $CADDY_ETC（非空，其中的文件不是 AbuseGuard 创建的）：$(ls -A "$CADDY_ETC" | tr '\n' ' ')"
			fi
		fi
	fi
	log "彻底卸载完成（按安装清单，只删了 AbuseGuard 安装的部分）。"
else
	log "保守卸载完成：已保留 Caddy、账户、配置；Caddyfile 中的 AbuseGuard 配置已摘除。"
fi

# --- 4) reload/validate ------------------------------------------------------
run "systemctl daemon-reload"
run "systemctl reload fail2ban >/dev/null 2>&1 || true"
if [ "$DRY" != 1 ] && [ -x "$CADDY_BIN" ] && [ -f "$CADDYFILE" ]; then
	if "$CADDY_BIN" validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1; then
		systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
		log "已重载 Caddy（清理后的配置校验通过）。"
	else
		warn "清理后的 Caddyfile 未通过校验，已保留原样，请手动检查 $CADDYFILE（原始备份见 $CADDY_ETC/Caddyfile.pre-abuseguard，若存在）。"
	fi
fi

# If a packaged Caddy unit exists, ours shadowed it and has now been removed;
# systemd needs a nudge and the service needs re-enabling.
if [ "$DRY" != 1 ] && [ -e /lib/systemd/system/caddy.service ]; then
	warn "系统仍有原生 Caddy 服务单元（/lib/systemd/system/caddy.service）。如需恢复你原有的 Caddy 服务，请执行：sudo systemctl enable --now caddy"
fi

log "done."
