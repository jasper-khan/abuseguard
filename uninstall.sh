#!/usr/bin/env bash
# AbuseGuard uninstaller for Debian/Ubuntu.
#
# Two modes (chosen interactively, or via flags):
#   --conservative   remove AbuseGuard; KEEP the reverse proxy + your sites
#   --purge          thorough: also remove what AbuseGuard installed (proxy /
#                    accounts / config), guided by the install manifest so
#                    anything that pre-existed the install is left untouched
#   --keep-sites | --drop-sites   managed sites: keep (de-protect) / delete
#   --yes            skip confirmation      --dry-run   print, change nothing
#
# Uninstall is symmetric to install: it reads /var/lib/caddy-abuseguard/
# install-manifest (written at install time) and only removes things AbuseGuard
# itself created. If the mode record or manifest is missing it falls back to
# the safest path (touch nothing that might be the user's: proxy, accounts,
# config, certificates).
set -uo pipefail

# Test hook parity with install.sh; production uses /etc/caddy-abuseguard.
CONF_DIR="${ABUSEGUARD_CONF_DIR:-/etc/caddy-abuseguard}"
STATE_DIR=/var/lib/caddy-abuseguard
LOG_DIR=/var/log/caddy
ENGINE_BIN=/usr/local/libexec/caddy-abuseguard
# Legacy Shell applier from releases before the Go policy-apply migration.
POLICY_BIN=/usr/local/libexec/caddy-abuseguard-policy
POLICY_F2B=/etc/fail2ban/jail.d/zzz-caddy-abuseguard-policy.local
PANEL_BIN=/usr/local/bin/ag
LEGACY_PANEL_BIN=/usr/local/bin/abuseguard
CADDY_BIN=/usr/local/bin/caddy
CADDY_ETC=/etc/caddy
CADDYFILE=/etc/caddy/Caddyfile
SNIPPET=/etc/caddy/abuseguard.caddy
SITES_DIR=/etc/caddy/sites
CADDY_ENV=/etc/caddy/.env
CADDY_LIB=/var/lib/caddy
MANIFEST="$STATE_DIR/install-manifest"

# Immutable proxy mode + root-trusted ownership metadata.
MODE_FILE="$CONF_DIR/web-server"
PACKAGE_RECORD="$CONF_DIR/package-ownership"
AG_NGINX_CF_CREDENTIALS="$CONF_DIR/cloudflare.ini"
NGINX_RUNTIME_PATH=/usr/local/libexec/abuseguard-nginx.sh
NGINX_DEPLOY_HOOK=/usr/local/libexec/abuseguard-nginx-deploy
NGINX_HTTP_CONF=/etc/nginx/conf.d/abuseguard.conf
NGINX_SELFTEST_CONF=/etc/nginx/conf.d/zz-abuseguard-selftest.conf
NGINX_CF_TRUST_INCLUDE=/etc/nginx/snippets/abuseguard-cloudflare.conf
NGINX_SITES_AVAILABLE=/etc/nginx/sites-available
NGINX_SITES_ENABLED=/etc/nginx/sites-enabled
NGINX_LOG_DIR=/var/log/nginx
NGINX_ACCESS_LOG="$NGINX_LOG_DIR/abuseguard-access.json"
NGINX_LOGROTATE=/etc/logrotate.d/abuseguard-nginx
NGINX_LETSENCRYPT_DIR=/etc/letsencrypt

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

validate_caddyfile() {
	local config="$1" cf_token=""
	[ ! -f "$CADDY_ENV" ] || cf_token="$(sed -n 's/^CF_API_TOKEN=//p' "$CADDY_ENV" | head -n 1)"
	CF_API_TOKEN="$cf_token" "$CADDY_BIN" validate --config "$config" --adapter caddyfile
}
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

# --- proxy mode (never sourced) ----------------------------------------------
proxy_mode_valid() { case "${1:-}" in caddy|nginx) return 0 ;; esac; return 1; }
read_mode_record() {
	local mode
	[ -e "$MODE_FILE" ] || [ -L "$MODE_FILE" ] || return 1
	[ -f "$MODE_FILE" ] && [ ! -L "$MODE_FILE" ] || return 2
	mode="$(cat -- "$MODE_FILE" 2>/dev/null)" || return 2
	proxy_mode_valid "$mode" || return 2
	if [ "$(stat -c %u -- "$MODE_FILE" 2>/dev/null)" != 0 ]; then return 2; fi
	printf '%s' "$mode"
}

mval() {
	local v=""
	[ -f "$MANIFEST" ] && v="$(grep -E "^$1=" "$MANIFEST" 2>/dev/null | head -1 | cut -d= -f2)"
	echo "${v:-1}"
}
if [ -f "$MANIFEST" ]; then MANIFEST_OK=1; else MANIFEST_OK=0; fi

PROXY_MODE=""
nginx_abuse_files_present() {
	local f
	if [ -e "$NGINX_HTTP_CONF" ] || [ -e "$NGINX_RUNTIME_PATH" ] || [ -e "$NGINX_DEPLOY_HOOK" ] \
		|| [ -e "$AG_NGINX_CF_CREDENTIALS" ] || [ -e "$NGINX_SELFTEST_CONF" ] || [ -e "$NGINX_CF_TRUST_INCLUDE" ]; then
		return 0
	fi
	for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		return 0
	done
	return 1
}
caddy_abuse_files_present() {
	[ -e "$SNIPPET" ] || [ -e "$CADDY_ETC/Caddyfile.pre-abuseguard" ] \
		|| [ -e /etc/systemd/system/caddy.service ]
}
if mode="$(read_mode_record)"; then
	PROXY_MODE="$mode"
else
	rc=$?
	mode_bad=0
	if [ "$rc" = 2 ]; then
		warn "代理模式记录 $MODE_FILE 缺失或无效；无法确认反向代理。"
		mode_bad=1
	fi
	if [ "$mode_bad" = 0 ] && nginx_abuse_files_present; then
		warn "检测到 AbuseGuard Nginx 文件，但模式记录不可用；按保守方式处理。"
	elif [ "$mode_bad" = 0 ] && [ "$MANIFEST_OK" = 1 ]; then
		mws="$(sed -n 's/^web_server=//p' "$MANIFEST" | head -n 1)"
		if [ "$mws" = nginx ]; then
			warn "安装清单记录 Nginx，但模式记录不可用；按保守方式处理。"
		elif caddy_abuse_files_present; then
			PROXY_MODE=caddy
		fi
	elif [ "$mode_bad" = 0 ] && caddy_abuse_files_present; then
		PROXY_MODE=caddy
	fi
fi
if [ -z "$PROXY_MODE" ]; then
	warn "无法确定已安装的反向代理；按保守卸载处理（保留代理/证书/配置，仅移除核心）。"
	MODE=conservative
	KEEP_SITES=keep
fi

if [ "$MANIFEST_OK" = 0 ]; then
	warn "未找到安装清单，无法确认哪些是 AbuseGuard 安装的；为安全起见将不动 Caddy/账户/配置。"
fi
m_caddy_bin="$(mval caddy_bin_preexisting)"
m_caddy_svc="$(mval caddy_service_preexisting)"
m_caddy_user="$(mval caddy_user_preexisting)"
m_ag_user="$(mval abuseguard_user_preexisting)"
m_caddyfile="$(mval caddyfile_preexisting)"
m_caddy_etc="$(mval caddy_etc_preexisting)"
m_log_dir="$(mval log_dir_preexisting)"
m_caddy_lib="$(mval caddy_lib_preexisting)"

# Root-trusted package ownership; missing/symlinked/unknown values stay
# conservative and never authorize package removal. Field value 0 means the
# package was absent before this install (ours to remove), 1 means pre-existing.
pkg_owner() {
	[ -f "$PACKAGE_RECORD" ] && [ ! -L "$PACKAGE_RECORD" ] || { echo unknown; return 0; }
	[ "$(stat -c %u -- "$PACKAGE_RECORD" 2>/dev/null)" = 0 ] || { echo unknown; return 0; }
	local v
	v="$(grep -E "^$1=" "$PACKAGE_RECORD" 2>/dev/null | head -1 | cut -d= -f2)"
	case "$v" in 0|1) echo "$v" ;; *) echo unknown ;; esac
}
m_nginx_pkg="$(pkg_owner nginx_preexisting)"
m_nginx_core_pkg="$(pkg_owner nginx_core_preexisting)"
m_nginx_common_pkg="$(pkg_owner nginx_common_preexisting)"
m_certbot_pkg="$(pkg_owner certbot_preexisting)"
m_certbot_cf_pkg="$(pkg_owner certbot_dns_cloudflare_preexisting)"

# Source the installed Nginx helper (if still present) for full-context
# validation/reload during file transactions. It is source-only by contract.
if [ "$PROXY_MODE" = nginx ] && [ -f "$NGINX_RUNTIME_PATH" ] && [ ! -L "$NGINX_RUNTIME_PATH" ]; then
	# shellcheck disable=SC1090
	. "$NGINX_RUNTIME_PATH" 2>/dev/null || warn "无法加载 Nginx 助手；将直接使用 nginx -t。"
fi

nginx_validate_live() {
	command -v nginx >/dev/null 2>&1 || return 0
	if [ -f /etc/nginx/nginx.conf ]; then
		nginx -t
	elif declare -F nginx_validate >/dev/null 2>&1; then
		nginx_validate
	else
		return 0
	fi
}
nginx_reload_live() {
	systemctl is-active --quiet nginx 2>/dev/null || return 0
	if declare -F nginx_reload >/dev/null 2>&1; then
		nginx_reload
	else
		systemctl reload nginx
	fi
}

# Back up, remove, validate and reload Nginx as one transaction. On any
# validation/reload failure every path is restored and the old config reloaded.
nginx_paths_remove() {
	local path backup manifest i=0 failed=0
	if [ "$DRY" = 1 ]; then
		for path in "$@"; do
			[ -e "$path" ] || [ -L "$path" ] || continue
			echo "  would: rm -rf -- $path"
		done
		return 0
	fi
	backup="$(mktemp -d)" || { warn "无法创建 Nginx 回滚目录。"; return 1; }
	manifest="$backup/manifest"
	: > "$manifest"
	for path in "$@"; do
		[ -e "$path" ] || [ -L "$path" ] || continue
		i=$((i + 1))
		cp -a -- "$path" "$backup/$i" || { warn "无法备份 $path。"; rm -rf -- "$backup"; return 1; }
		printf '%s\t%s\n' "$i" "$path" >> "$manifest"
	done
	if [ "$i" = 0 ]; then
		rm -rf -- "$backup"
		return 0
	fi
	for path in "$@"; do
		[ -e "$path" ] || [ -L "$path" ] || continue
		rm -rf -- "$path" || failed=1
	done
	if [ "$failed" = 0 ] && nginx_validate_live >/dev/null 2>&1 \
		&& nginx_reload_live >/dev/null 2>&1; then
		rm -rf -- "$backup"
		return 0
	fi
	warn "Nginx 配置变更校验/重载失败，正在回滚。"
	while IFS=$'\t' read -r i path; do
		[ -n "$path" ] || continue
		rm -rf -- "$path"
		cp -a -- "$backup/$i" "$path" || warn "无法恢复 $path。"
	done < "$manifest"
	nginx_reload_live >/dev/null 2>&1 || warn "回滚后 Nginx 重载失败；请手动检查：systemctl status nginx"
	rm -rf -- "$backup"
	return 1
}

# --- count AbuseGuard-managed sites -----------------------------------------
site_count=0
if [ "$PROXY_MODE" = nginx ]; then
	for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		site_count=$((site_count + 1))
	done
elif [ "$PROXY_MODE" = caddy ]; then
	if [ -d "$SITES_DIR" ]; then
		for f in "$SITES_DIR"/*.caddy; do
			[ -e "$f" ] || continue
			[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
			site_count=$((site_count + 1))
		done
	fi
fi

# --- choose mode -------------------------------------------------------------
if [ -z "$MODE" ]; then
	if [ "$YES" = 1 ] || ! have_tty; then
		MODE=conservative
	else
		echo "卸载模式："
		echo "  [1] 保守卸载：删 AbuseGuard，保留反向代理和你的站点"
		echo "  [2] 彻底卸载：连 AbuseGuard 安装的代理/账户/配置一起删（按安装清单，不动你原有的）"
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
		if [ "$PROXY_MODE" = nginx ]; then
			for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf; do
				[ -e "$f" ] || [ -L "$f" ] || continue
				d="$(basename "$f" .conf)"; d="${d#abuseguard-}"
				u="$(grep -oE 'proxy_pass[[:space:]]+http://[^;]+' "$f" 2>/dev/null | head -1 | awk '{print $2}')"
				echo "    $d → ${u:-?}"
			done
		else
			for f in "$SITES_DIR"/*.caddy; do
				[ -e "$f" ] || continue
				[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
				d="$(basename "$f" .caddy)"
				u="$(grep -oE 'reverse_proxy[[:space:]]+[^ ]+' "$f" 2>/dev/null | head -1 | awk '{print $2}')"
				echo "    $d → ${u:-?}"
			done
		fi
		echo "  [1] 保留反代，只去掉 AbuseGuard 防护（网站继续可访问）"
		echo "  [2] 连反代一起删除"
		read -r -p "请选择: " a <&3; exec 3<&-
		case "$a" in 2) KEEP_SITES=drop ;; *) KEEP_SITES=keep ;; esac
	fi
[ -z "$KEEP_SITES" ] && KEEP_SITES=keep
fi

# --- confirm -----------------------------------------------------------------
if [ "$YES" != 1 ] && [ "$DRY" != 1 ]; then
	echo
	echo "即将执行：$([ "$MODE" = thorough ] && echo '彻底卸载' || echo '保守卸载')；面板站点：$([ "$KEEP_SITES" = drop ] && echo '删除' || echo '保留反代')"
	if [ "$MODE" = thorough ] && [ "$PROXY_MODE" = caddy ]; then
		[ "$m_caddy_bin" = 0 ]  && echo "  · 将删除 Caddy 二进制（AbuseGuard 安装的）" || echo "  · 保留 Caddy 二进制（你原有的）"
		[ "$m_caddy_user" = 0 ] && echo "  · 将删除 caddy 账户" || echo "  · 保留 caddy 账户（你原有的）"
		echo "  · 将删除 AbuseGuard 的配置/状态目录"
		[ "$m_log_dir" = 0 ]  && echo "  · 将删除 $LOG_DIR（AbuseGuard 创建的）" || echo "  · 保留 $LOG_DIR（你原有的日志目录，只删 AbuseGuard 自己的日志文件）"
	elif [ "$MODE" = thorough ]; then
		echo "  · 保留 Nginx/Certbot 及其续期与站点配置（若保留站点）"
	fi
	c=n; have_tty && { read -r -p "确认继续? [y/N] " c <&3; exec 3<&-; }
	case "$c" in y|Y|yes|YES) : ;; *) echo "已取消"; exit 0 ;; esac
fi

# --- Caddyfile cleanup: strip AbuseGuard's own bits, keep the user's ---------
clean_caddyfile() {
	[ -f "$CADDYFILE" ] || return 0
	local drop_sites=0; [ "$KEEP_SITES" = drop ] && drop_sites=1
	local strip_snippet=0; [ "$MODE" = thorough ] && strip_snippet=1
	if [ "$DRY" = 1 ]; then echo "  would: 清理 $CADDYFILE（摘除 import abuseguard / snippet$([ "$drop_sites" = 1 ] && echo ' / import sites') / 自检站点块）"; return 0; fi
	local tmp; tmp="$(mktemp)"
	awk -v drop_sites="$drop_sites" -v strip_snippet="$strip_snippet" '
		/^[[:space:]]*http:\/\/127\.0\.0\.1:8080[[:space:]]*\{/ { insb=1; d=1; next }
		insb==1 { o=gsub(/\{/,"{"); c=gsub(/\}/,"}"); d+=o-c; if (d<=0) insb=0; next }
		strip_snippet == "1" && /^[[:space:]]*import[[:space:]]+[^ ]*abuseguard\.caddy[[:space:]]*$/ { next }
		/^[[:space:]]*import[[:space:]]+[^ ]*\/sites\/\*\.caddy[[:space:]]*$/ { if (drop_sites) next; else { print; next } }
		strip_snippet == "1" && /^[[:space:]]*import[[:space:]]+abuseguard[[:space:]]*$/ { next }
		{ print }
	' "$CADDYFILE" > "$tmp" && cat "$tmp" > "$CADDYFILE"
	remove_file "$tmp"
}
# strip `import abuseguard` from each managed site file (thorough mode only,
# where the snippet file is removed and site files would otherwise break).
clean_sites_keep() {
	[ -d "$SITES_DIR" ] || return 0
	local f
	for f in "$SITES_DIR"/*.caddy; do
		[ -e "$f" ] || continue
		[ "$(basename "$f")" = "_placeholder.caddy" ] && continue
		if [ "$DRY" = 1 ]; then echo "  would: 从 $f 去掉 import abuseguard（保留反代）"; continue; fi
		sed -i "/^[[:space:]]*import[[:space:]]\+abuseguard[[:space:]]*\$/d" "$f"
	done
}

# --- Nginx cleanup helpers ---------------------------------------------------
nginx_managed_domains() {
	local f base domain
	for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		base="$(basename "$f")"; domain="${base#abuseguard-}"; domain="${domain%.conf}"
		case "$domain" in ''|*[!a-z0-9.-]*) continue ;; esac
		printf '%s\n' "$domain"
	done
	if [ -d "$NGINX_LETSENCRYPT_DIR/renewal" ]; then
		for f in "$NGINX_LETSENCRYPT_DIR/renewal"/abuseguard-*.conf; do
			[ -e "$f" ] || continue
			base="$(basename "$f")"; domain="${base#abuseguard-}"; domain="${domain%.conf}"
			case "$domain" in ''|*[!a-z0-9.-]*) continue ;; esac
			printf '%s\n' "$domain"
		done
	fi
}

remove_managed_certificate() {
	local domain="$1" name="abuseguard-$1"
	case "$domain" in ''|*[!a-z0-9.-]*) warn "拒绝无效证书名：$name"; return 1 ;; esac
	if [ "$DRY" = 1 ]; then
		echo "  would: certbot delete --cert-name $name（或删除对应 lineage）"
		return 0
	fi
	if [ ! -e "$NGINX_LETSENCRYPT_DIR/live/$name" ] && [ ! -e "$NGINX_LETSENCRYPT_DIR/renewal/$name.conf" ]; then
		return 0
	fi
	if command -v certbot >/dev/null 2>&1; then
		certbot delete --cert-name "$name" --non-interactive >/dev/null 2>&1 && return 0
	fi
	rm -f -- "$NGINX_LETSENCRYPT_DIR/renewal/$name.conf"
	rm -rf -- "$NGINX_LETSENCRYPT_DIR/archive/$name" "$NGINX_LETSENCRYPT_DIR/live/$name"
}

nginx_has_unrelated_config() {
	local f base
	for f in "$NGINX_SITES_ENABLED"/*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		base="$(basename "$f")"
		case "$base" in abuseguard-*.conf) continue ;; esac
		return 0
	done
	for f in "$NGINX_SITES_AVAILABLE"/* "$NGINX_SITES_AVAILABLE"/.*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		base="$(basename "$f")"
		case "$base" in abuseguard-*.conf|default|.|..) continue ;; esac
		return 0
	done
	for f in /etc/nginx/conf.d/*; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		base="$(basename "$f")"
		case "$base" in abuseguard.conf|zz-abuseguard-selftest.conf) continue ;; esac
		return 0
	done
	# A user-added server block directly in nginx.conf also means the package
	# is still serving something outside AbuseGuard.
	if [ -f /etc/nginx/nginx.conf ] && grep -Eq '^[[:space:]]*server[[:space:]]*\{' /etc/nginx/nginx.conf 2>/dev/null; then
		return 0
	fi
	return 1
}

pkg_installed() {
	command -v dpkg-query >/dev/null 2>&1 || return 1
	[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]
}

remove_owned_packages() {
	[ "$MODE" = thorough ] || return 0
	[ "$KEEP_SITES" = drop ] || return 0
	[ "$PROXY_MODE" = nginx ] || return 0
	local -a nginx_pkgs=() certbot_pkgs=()
	if [ "$m_nginx_pkg" = 0 ] && pkg_installed nginx && ! nginx_has_unrelated_config; then
		nginx_pkgs+=(nginx)
		if [ "$m_nginx_core_pkg" = 0 ] && pkg_installed nginx-core; then nginx_pkgs+=(nginx-core); fi
		if [ "$m_nginx_common_pkg" = 0 ] && pkg_installed nginx-common; then nginx_pkgs+=(nginx-common); fi
		if [ "$DRY" = 1 ]; then
			echo "  would: systemctl disable --now nginx; apt-get remove -y ${nginx_pkgs[*]}"
		else
			systemctl disable --now nginx >/dev/null 2>&1 || true
			apt-get remove -y "${nginx_pkgs[@]}" >/dev/null 2>&1 \
				|| warn "无法移除本次安装的 Nginx 软件包；已保留。"
		fi
	else
		log "已保留 Nginx 软件包（非本次安装、仍被其他配置使用或归属未知）"
	fi
	local other_renewals=0 f
	if [ -d "$NGINX_LETSENCRYPT_DIR/renewal" ]; then
		for f in "$NGINX_LETSENCRYPT_DIR/renewal"/*.conf; do
			[ -e "$f" ] || continue
			case "$(basename "$f")" in abuseguard-*) continue ;; esac
			other_renewals=1
			break
		done
	fi
	if [ "$m_certbot_pkg" = 0 ] && pkg_installed certbot && [ "$other_renewals" = 0 ]; then
		certbot_pkgs+=(certbot)
		if [ "$m_certbot_cf_pkg" = 0 ] && pkg_installed python3-certbot-dns-cloudflare; then
			certbot_pkgs+=(python3-certbot-dns-cloudflare)
		fi
		if [ "$DRY" = 1 ]; then
			echo "  would: apt-get remove -y ${certbot_pkgs[*]}"
		else
			apt-get remove -y "${certbot_pkgs[@]}" >/dev/null 2>&1 \
				|| warn "无法移除本次安装的 Certbot 软件包；已保留。"
		fi
	else
		log "已保留 Certbot 软件包/续期定时器（非本次安装或被其他证书使用）"
	fi
}

# --- 1) stop + remove AbuseGuard's own components (both modes) ----------------
log "停止并移除 AbuseGuard 组件"
run "systemctl disable --now caddy-abuseguard-policy.service >/dev/null 2>&1 || true"
run "systemctl disable --now caddy-abuseguard-firewall.service >/dev/null 2>&1 || true"
# Best-effort deletes of our own tables; do not depend on a successful list
# (nft has crashed on large dumps, which would leave the table enforced).
run "nft delete table inet caddy_abuseguard_intel >/dev/null 2>&1 || true" || exit 1
run "nft delete table inet caddy_abuseguard >/dev/null 2>&1 || true" || exit 1
remove_file /etc/systemd/system/caddy-abuseguard-policy.service
remove_file /etc/systemd/system/caddy-abuseguard-firewall.service
for u in caddy-abuseguard-report.timer caddy-abuseguard-report.service \
         caddy-abuseguard-sync.timer caddy-abuseguard-sync.service; do
	run "systemctl disable --now $u >/dev/null 2>&1 || true"
done
remove_file /etc/systemd/system/caddy-abuseguard-report.service
remove_file /etc/systemd/system/caddy-abuseguard-report.timer
remove_file /etc/systemd/system/caddy-abuseguard-sync.service
remove_file /etc/systemd/system/caddy-abuseguard-sync.timer
remove_file /etc/fail2ban/jail.d/caddy-abuseguard.local
remove_file /etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local
remove_file "$POLICY_F2B"
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-any.conf
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-probe-h1.conf
remove_file /etc/fail2ban/filter.d/caddy-abuseguard-probe-h2.conf
remove_file /etc/fail2ban/action.d/caddy-abuseguard-queue.conf
remove_file /etc/fail2ban/action.d/caddy-abuseguard-drop.conf
remove_file "$POLICY_BIN"
remove_file "$ENGINE_BIN"
remove_file "$PANEL_BIN"
# Older releases installed the panel as `abuseguard`; clean up that leftover
# too, but only when the file really is our panel.
if [ -f "$LEGACY_PANEL_BIN" ] && head -n 2 "$LEGACY_PANEL_BIN" | grep -q 'AbuseGuard 控制面板'; then
	remove_file "$LEGACY_PANEL_BIN"
fi

# --- 2) backend-specific site cleanup ---------------------------------------
if [ "$PROXY_MODE" = caddy ]; then
	if [ "$MODE" = thorough ] && [ "$KEEP_SITES" = keep ]; then
		clean_sites_keep
	fi
	if [ "$KEEP_SITES" = drop ]; then
		remove_owned_tree "$SITES_DIR" || exit 1
	fi
	clean_caddyfile
elif [ "$PROXY_MODE" = nginx ]; then
	if [ "$KEEP_SITES" = keep ]; then
		# Sites and certificate material stay usable. Remove only the loopback
		# self-test that belongs to the core installation.
		log "保留 Nginx 站点、证书、CF 凭据、续期定时器与部署钩子"
		nginx_paths_remove "$NGINX_SELFTEST_CONF" \
			|| warn "移除 Nginx 自检站点失败；其余配置未改动。"
	else
		# Drop managed sites and the now-unused project HTTP config. Unrelated
		# Nginx sites/conf.d files, Certbot lineages and renewal configs stay.
		nginx_site_paths=()
		for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf; do
			[ -e "$f" ] || [ -L "$f" ] || continue
			d="$(basename "$f" .conf)"; d="${d#abuseguard-}"
			nginx_site_paths+=("$f" "$NGINX_SITES_ENABLED/abuseguard-$d.conf")
		done
		# Also catch a dangling enabled symlink whose site file is already gone.
		for f in "$NGINX_SITES_ENABLED"/abuseguard-*.conf; do
			[ -e "$f" ] || [ -L "$f" ] || continue
			nginx_site_paths+=("$f")
		done
		nginx_drop_domains="$(nginx_managed_domains | sort -u)"
		if ! nginx_paths_remove "${nginx_site_paths[@]}" "$NGINX_HTTP_CONF" "$NGINX_SELFTEST_CONF" \
			"$NGINX_CF_TRUST_INCLUDE" "$NGINX_LOGROTATE"; then
			warn "Nginx 站点删除未能安全完成；已回滚并保留原配置。"
			exit 1
		fi
		while IFS= read -r d; do
			[ -n "$d" ] || continue
			if [ "$DRY" = 1 ]; then
				echo "  would: 删除证书 $NGINX_LETSENCRYPT_DIR/live/abuseguard-$d（不吊销）"
			else
				remove_managed_certificate "$d" || warn "无法删除证书 lineage abuseguard-$d；已保留。"
				log "已删除站点证书 lineage：abuseguard-$d（未吊销）"
			fi
		done <<< "$nginx_drop_domains"
		remove_file "$AG_NGINX_CF_CREDENTIALS"
		remove_file "$NGINX_DEPLOY_HOOK"
		remove_file "$NGINX_ACCESS_LOG"
	fi
	# The runtime helper is part of the core, not the serving/renewal path.
	remove_file "$NGINX_RUNTIME_PATH"
fi

# --- 3) thorough: remove what AbuseGuard installed (per manifest) ------------
if [ "$MODE" = thorough ] && [ "$PROXY_MODE" = caddy ]; then
	if [ "$m_caddy_svc" = 0 ]; then
		run "systemctl disable --now caddy >/dev/null 2>&1 || true"
		remove_file /etc/systemd/system/caddy.service
	fi
	[ "$m_caddy_bin" = 0 ]  && remove_file "$CADDY_BIN"
	remove_file "$SNIPPET"
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
elif [ "$MODE" = thorough ] && [ "$PROXY_MODE" = nginx ]; then
	remove_owned_packages
	if [ "$KEEP_SITES" = keep ]; then
		# Keep the root-owned mode record, CF credentials and package ownership
		# so a reinstall keeps the same backend and renewal keeps working.
		[ -f "$MANIFEST" ] && remove_file "$MANIFEST"
		# STATE_DIR (feed/reports) is removed below. A retained root policy
		# snapshot would make the next policy-apply refuse the now-empty feed
		# as a non-first install, so drop enforcement state with the core.
		remove_file "$CONF_DIR/intel.nft"
		remove_file "$CONF_DIR/intel-applied.json"
		log "已保留 $CONF_DIR（模式记录、Cloudflare 凭据、软件包归属、配置/白名单）"
	else
		remove_owned_tree "$CONF_DIR" || exit 1
	fi
	remove_owned_tree "$STATE_DIR" || exit 1
	log "彻底卸载完成（Nginx 模式：仅删除本次安装且已不再使用的部分）。"
elif [ "$MODE" = thorough ]; then
	warn "代理状态不完整；按保守方式保留反向代理/配置/证书。"
	log "已移除 AbuseGuard 核心；代理与证书保持可用。"
else
	if [ -z "$PROXY_MODE" ]; then
		log "保守卸载完成：代理状态未知，已按保守方式保留反向代理、站点与证书。"
	elif [ "$PROXY_MODE" = caddy ]; then
		log "保守卸载完成：已保留 Caddy、账户、配置；Caddyfile 中的 AbuseGuard 配置已摘除。"
	else
		log "保守卸载完成：已保留 Nginx、站点、证书与续期；仅移除 AbuseGuard 核心。"
	fi
fi

# --- 4) reload/validate ------------------------------------------------------
run "systemctl daemon-reload"
run "systemctl reload fail2ban >/dev/null 2>&1 || true"
if [ "$PROXY_MODE" = caddy ] && [ "$DRY" != 1 ] && [ -x "$CADDY_BIN" ] && [ -f "$CADDYFILE" ]; then
	if validate_caddyfile "$CADDYFILE" >/dev/null 2>&1; then
		systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
		log "已重载 Caddy（清理后的配置校验通过）。"
	else
		warn "清理后的 Caddyfile 未通过校验，已保留原样，请手动检查 $CADDYFILE（原始备份见 $CADDY_ETC/Caddyfile.pre-abuseguard，若存在）。"
	fi
fi
# If a packaged Caddy unit exists, ours shadowed it and has now been removed;
# systemd needs a nudge and the service needs re-enabling.
if [ "$PROXY_MODE" = caddy ] && [ "$DRY" != 1 ] && [ -e /lib/systemd/system/caddy.service ]; then
	warn "系统仍有原生 Caddy 服务单元（/lib/systemd/system/caddy.service）。如需恢复你原有的 Caddy 服务，请执行：sudo systemctl enable --now caddy"
fi

log "done."
