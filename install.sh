#!/usr/bin/env bash
# AbuseGuard installer for Debian/Ubuntu (amd64/arm64).
#
# Installs the selected reverse proxy (Caddy, or distro Nginx + Certbot DNS),
# fail2ban jails that block abusive IPs with nftables, a threat-intel sync,
# an optional AbuseIPDB auto-reporter, and the `ag` control panel.
#
# Usage:
#   sudo ./install.sh                        # Caddy (default), prebuilt engine
#   sudo ./install.sh --proxy=nginx          # distro Nginx + Certbot DNS-01
#   sudo ./install.sh --from-source          # build the Go engine here (needs `go`)
#   sudo ./install.sh --proxy=nginx --from-source
#   sudo ABUSEGUARD_ENGINE_BIN=/path/engine ./install.sh
#
# The reverse proxy is chosen once on the first install and recorded in
# /etc/caddy-abuseguard/web-server. Later runs must not switch it.
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-jasper-khan/abuseguard}"

# All downloads come straight from GitHub; there is no built-in mirror or
# proxy chain. A user behind a blocked network sets the standard
# https_proxy/HTTPS_PROXY environment variables (curl honours them natively),
# and that proxy is then its own trust anchor.
# curl opts: give up on a dead host fast, abort if the transfer stalls under
# 100 KB/s for 10s (catches a stalled link), hard-cap at 120s for small files.
AG_CURL="curl -fsL --connect-timeout 10 --speed-limit 102400 --speed-time 10 --max-time 120"
# For large binaries (engine ~6MB, Caddy ~40MB): same stall detection, but NO
# total-time cap — a healthy but slow link (~300KB/s) must not be killed
# mid-download, which would fail the install outright.
AG_CURL_BIG="curl -fsL --connect-timeout 10 --speed-limit 102400 --speed-time 10"
# For the tiny SHA256SUMS.txt: no stall detection (a few hundred bytes never
# sustains 100KB/s anyway), a short hard cap, and retries. Verification is
# mandatory, so this fetch is made as robust as possible instead of optional.
AG_CURL_SUMS="curl -fsL --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 1"

# gh_fetch URL OUTFILE [CURL_CMD] -- download a URL to OUTFILE, direct only.
# The failure is returned to the caller, which aborts with a clear error.
gh_fetch() {
	local curl_cmd="${3:-$AG_CURL}"
	$curl_cmd -o "$2" "$1"
}

# Test hook: scripts/test-proxy-selection.sh sources this file with a private
# config root. Production always uses /etc/caddy-abuseguard.
CONF_DIR="${ABUSEGUARD_CONF_DIR:-/etc/caddy-abuseguard}"
STATE_DIR=/var/lib/caddy-abuseguard
REPORTS_DIR="$STATE_DIR/reports"
LOG_DIR=/var/log/caddy
LIBEXEC_DIR=/usr/local/libexec
ENGINE_BIN="$LIBEXEC_DIR/caddy-abuseguard"
# Legacy Shell applier left by releases before the Go policy-apply migration;
# removed only after the new engine+unit pair is proven usable.
POLICY_BIN="$LIBEXEC_DIR/caddy-abuseguard-policy"
POLICY_UNIT_DIR=/etc/systemd/system
PANEL_BIN=/usr/local/bin/ag
LEGACY_PANEL_BIN=/usr/local/bin/abuseguard
CADDY_BIN=/usr/local/bin/caddy
CADDY_SERVICE=/etc/systemd/system/caddy.service
CADDY_ETC=/etc/caddy
CADDY_ENV="$CADDY_ETC/.env"
CADDYFILE="$CADDY_ETC/Caddyfile"
SNIPPET="$CADDY_ETC/abuseguard.caddy"
SITES_DIR="$CADDY_ETC/sites"

# First-install proxy choice: root-owned immutable mode record.
MODE_FILE="$CONF_DIR/web-server"
NGINX_RUNTIME_PATH="$LIBEXEC_DIR/abuseguard-nginx.sh"
NGINX_DEPLOY_HOOK="$LIBEXEC_DIR/abuseguard-nginx-deploy"
NGINX_HTTP_CONF=/etc/nginx/conf.d/abuseguard.conf
NGINX_SELFTEST_CONF=/etc/nginx/conf.d/zz-abuseguard-selftest.conf
NGINX_CF_TRUST_INCLUDE=/etc/nginx/snippets/abuseguard-cloudflare.conf
NGINX_SITES_AVAILABLE=/etc/nginx/sites-available
NGINX_SITES_ENABLED=/etc/nginx/sites-enabled
NGINX_LOG_DIR=/var/log/nginx
NGINX_ACCESS_LOG="$NGINX_LOG_DIR/abuseguard-access.json"
NGINX_LOGROTATE=/etc/logrotate.d/abuseguard-nginx
NGINX_LETSENCRYPT_DIR=/etc/letsencrypt
AG_NGINX_CF_CREDENTIALS="$CONF_DIR/cloudflare.ini"
# Root-trusted package ownership (CONF_DIR is root-owned, not abuseguard-writable).
PACKAGE_RECORD="$CONF_DIR/package-ownership"
POLICY_RC=/usr/sbin/policy-rc.d
POLICY_RC_SAVED=/usr/sbin/policy-rc.d.abuseguard-saved

FROM_SOURCE=0
REQUESTED_PROXY=""
PROXY_MODE=""
PROXY_MODE_ORIGIN=""
RECORDED_MODE=""
FRESH_PROXY=""
POLICY_RC_ACTIVE=0

log()  { printf '\033[1;32m[abuseguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[abuseguard]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[abuseguard]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<'EOF'
用法：sudo ./install.sh [--from-source] [--proxy=caddy|nginx]

  --proxy=caddy   使用 Caddy（首次安装默认）
  --proxy=nginx   使用发行版 Nginx + Certbot Cloudflare DNS（首次安装）
  --from-source   本地编译 Go 引擎（可与 --proxy 以任意顺序组合）
EOF
}

die_usage() { printf '\033[1;31m[abuseguard]\033[0m %s\n' "$*" >&2; exit 2; }

set_requested_proxy() {
	local value="$1"
	case "$value" in
		caddy|nginx) : ;;
		*) die_usage "无效的 --proxy 值：'$value'（仅支持 caddy 或 nginx）。" ;;
	esac
	if [ -n "$REQUESTED_PROXY" ] && [ "$REQUESTED_PROXY" != "$value" ]; then
		die_usage "冲突的 --proxy 参数：$REQUESTED_PROXY / $value。"
	fi
	REQUESTED_PROXY="$value"
}

parse_install_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--from-source) FROM_SOURCE=1 ;;
			--proxy=*) set_requested_proxy "${1#--proxy=}" ;;
			--proxy)
				[ "$#" -ge 2 ] || die_usage "--proxy 需要 caddy 或 nginx。"
				set_requested_proxy "$2"
				shift ;;
			-h|--help) usage; exit 0 ;;
			--) shift; [ "$#" -eq 0 ] || die_usage "未知参数：$1" ;;
			*) die_usage "未知参数：$1" ;;
		esac
		shift
	done
}

proxy_mode_valid() {
	case "${1:-}" in caddy|nginx) return 0 ;; esac
	return 1
}

# Reads the immutable mode record. Never sources it; a tampered/corrupt record
# aborts before any host change. Missing record returns 1 for the caller.
# The mode is returned through RECORDED_MODE so die() runs in the caller's
# shell instead of a command-substitution subshell.
read_recorded_mode() {
	local mode bits
	[ -e "$MODE_FILE" ] || [ -L "$MODE_FILE" ] || return 1
	[ -f "$MODE_FILE" ] && [ ! -L "$MODE_FILE" ] \
		|| die "代理模式记录 $MODE_FILE 不是普通文件；安装已中止，未改动系统。"
	mode="$(cat -- "$MODE_FILE" 2>/dev/null)" \
		|| die "无法读取代理模式记录 $MODE_FILE；安装已中止，未改动系统。"
	proxy_mode_valid "$mode" \
		|| die "代理模式记录 $MODE_FILE 内容无效（只允许 caddy 或 nginx）；安装已中止，未改动系统。"
	if [ "$(id -u)" = 0 ]; then
		[ "$(stat -c %u -- "$MODE_FILE" 2>/dev/null)" = 0 ] \
			|| die "代理模式记录 $MODE_FILE 不是 root 所有；安装已中止，未改动系统。"
		bits="$(stat -c %a -- "$MODE_FILE" 2>/dev/null)" || bits=""
		# Reject group/other write (mask 022), not just a writable last digit.
		if [ -n "$bits" ] && [ "$((0$bits & 022))" -ne 0 ]; then
			die "代理模式记录 $MODE_FILE 可被非 root 修改；安装已中止，未改动系统。"
		fi
	fi
	RECORDED_MODE="$mode"
}

# Marker missing: old releases only ever installed Caddy. Anything that looks
# like an Nginx AbuseGuard install without a marker is ambiguous, not Caddy.
legacy_manifest_mode() {
	local manifest="$STATE_DIR/install-manifest" mode
	[ -f "$manifest" ] || return 1
	mode="$(sed -n 's/^web_server=//p' "$manifest" | head -n 1)"
	case "$mode" in
		"")  printf 'caddy' ;;
		caddy) printf 'caddy' ;;
		*) return 2 ;;
	esac
}

has_nginx_abuse_artifacts() {
	local f
	if [ -e "$NGINX_HTTP_CONF" ] || [ -e "$NGINX_RUNTIME_PATH" ] || [ -e "$NGINX_DEPLOY_HOOK" ] \
		|| [ -e "$AG_NGINX_CF_CREDENTIALS" ] || [ -e "$NGINX_SELFTEST_CONF" ] \
		|| [ -e "$NGINX_CF_TRUST_INCLUDE" ]; then
		return 0
	fi
	for f in "$NGINX_SITES_AVAILABLE"/abuseguard-*.conf "$NGINX_SITES_ENABLED"/abuseguard-*.conf; do
		[ -e "$f" ] || [ -L "$f" ] || continue
		return 0
	done
	return 1
}

has_caddy_abuse_artifacts() {
	[ -e "$SNIPPET" ] || [ -e "$CADDY_SERVICE" ] \
		|| [ -e "$CADDY_ETC/Caddyfile.pre-abuseguard" ]
}

choose_fresh_proxy() {
	local choice
	if [ -n "$REQUESTED_PROXY" ]; then
		FRESH_PROXY="$REQUESTED_PROXY"
		return 0
	fi
	if [ -n "${ABUSEGUARD_NONINTERACTIVE:-}" ] || ! { exec 3</dev/tty; } 2>/dev/null; then
		FRESH_PROXY=caddy
		return 0
	fi
	printf '  选择反向代理：[1] Caddy（默认，内置 Cloudflare DNS） [2] Nginx（发行版包 + Certbot）: ' >&2
	IFS= read -r choice <&3 || choice=""
	exec 3<&-
	case "$choice" in
		''|1|caddy|Caddy|CADDY) FRESH_PROXY=caddy ;;
		2|nginx|Nginx|NGINX) FRESH_PROXY=nginx ;;
		*) die_usage "无效的代理选择：'$choice'（请选择 1 或 2）。" ;;
	esac
}

# Must run before apt or any host mutation.
resolve_proxy_mode() {
	local legacy
	if read_recorded_mode; then
		PROXY_MODE="$RECORDED_MODE"
		PROXY_MODE_ORIGIN=recorded
		if [ -n "$REQUESTED_PROXY" ] && [ "$REQUESTED_PROXY" != "$RECORDED_MODE" ]; then
			die "此安装已固定使用 $RECORDED_MODE，不能用 --proxy=$REQUESTED_PROXY 切换反向代理。安装未改动系统。"
		fi
		return 0
	fi

	if [ "$UPDATE_MODE" = 1 ]; then
		if has_nginx_abuse_artifacts; then
			die "检测到现有 AbuseGuard Nginx 文件，但缺少模式记录 $MODE_FILE；状态不明确，拒绝继续。请手动核对后重试。安装未改动系统。"
		fi
		if ! legacy="$(legacy_manifest_mode)"; then
			die "安装清单记录的代理模式与 $MODE_FILE 不一致；拒绝猜测。请手动核对后重试。安装未改动系统。"
		fi
		PROXY_MODE="$legacy"
		PROXY_MODE_ORIGIN=legacy
		if [ -n "$REQUESTED_PROXY" ] && [ "$REQUESTED_PROXY" != "$legacy" ]; then
			die "旧版 AbuseGuard 安装使用 $legacy，不能用 --proxy=$REQUESTED_PROXY 切换。安装未改动系统。"
		fi
		log "未找到代理模式记录；按旧版 AbuseGuard+$legacy 安装继续"
		return 0
	fi

	choose_fresh_proxy
	if [ "$FRESH_PROXY" = caddy ] && has_nginx_abuse_artifacts; then
		die "检测到现有 AbuseGuard Nginx 文件但缺少模式记录；不能静默改用 Caddy。请手动核对，或以 --proxy=nginx 重试。安装未改动系统。"
	fi
	if [ "$FRESH_PROXY" = nginx ] && has_caddy_abuse_artifacts; then
		die "检测到现有 AbuseGuard Caddy 文件但缺少模式记录；不能静默改用 Nginx。请手动核对，或以 --proxy=caddy 重试。安装未改动系统。"
	fi
	PROXY_MODE="$FRESH_PROXY"
	PROXY_MODE_ORIGIN=fresh
}

pkg_installed() {
	command -v dpkg-query >/dev/null 2>&1 || return 1
	[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]
}

# 0 = installed, 1 = not installed, unknown = cannot tell.
pkg_state() {
	if ! command -v dpkg-query >/dev/null 2>&1; then
		printf 'unknown'
		return 0
	fi
	if pkg_installed "$1"; then
		printf '0'
	else
		printf '1'
	fi
}

# 1 = existed before this install (keep it), 0 = absent before (ours to remove).
pkg_preexisting() {
	case "$(pkg_state "$1")" in
		0) printf '1' ;;
		1) printf '0' ;;
		*) printf 'unknown' ;;
	esac
}

# Old certbot-dns-cloudflare releases only understand the Global API Key
# (email + key); `dns_cloudflare_api_token` is the only credential this
# installer writes. Importing the module proves nothing, so probe the
# installed package for the token key and refuse an unsupported plugin here
# instead of failing at issuance or silently falling back to a Global API Key.
certbot_cf_supports_api_token() {
	python3 - <<'PY' >/dev/null 2>&1
import pathlib
import sys

try:
    import certbot_dns_cloudflare as package
except Exception:
    sys.exit(1)
root = pathlib.Path(package.__file__).resolve().parent
for path in root.rglob("*.py"):
    try:
        if "dns_cloudflare_api_token" in path.read_text(encoding="utf-8", errors="ignore"):
            sys.exit(0)
    except OSError:
        continue
sys.exit(1)
PY
}

proxy_backend_present() {
	local mode="$1" unit=""
	case "$mode" in
		caddy)
			pkg_installed caddy && return 0
			command -v caddy >/dev/null 2>&1 && return 0
			[ -x /usr/local/bin/caddy ] && return 0
			unit=caddy.service ;;
		nginx)
			pkg_installed nginx && return 0
			pkg_installed nginx-core && return 0
			pkg_installed nginx-common && return 0
			command -v nginx >/dev/null 2>&1 && return 0
			[ -x /usr/sbin/nginx ] && return 0
			unit=nginx.service ;;
		*) return 1 ;;
	esac
	[ -e "/etc/systemd/system/$unit" ] || [ -e "/lib/systemd/system/$unit" ] \
		|| [ -e "/usr/lib/systemd/system/$unit" ]
}

# No co-installed reverse proxies: even an inactive opposite backend refuses.
preflight_exclusive_proxy() {
	local opposite
	if [ "$PROXY_MODE" = caddy ]; then opposite=nginx; else opposite=caddy; fi
	if proxy_backend_present "$opposite"; then
		die "检测到已安装的 $opposite（二进制/软件包/服务，即使未运行）。AbuseGuard 只使用一种反向代理；请先手动移除 $opposite 后重试。安装未改动系统。"
	fi
}

write_mode_record() {
	local tmp
	proxy_mode_valid "$PROXY_MODE" || die "内部错误：代理模式 '$PROXY_MODE' 无效；安装未完成。"
	[ -e "$MODE_FILE" ] && return 0
	install -d -m 0750 "$CONF_DIR" || die "无法创建 $CONF_DIR。"
	tmp="$(mktemp "$CONF_DIR/.web-server.XXXXXX")" || die "无法创建代理模式记录。"
	printf '%s\n' "$PROXY_MODE" > "$tmp" || { rm -f -- "$tmp"; die "无法写入代理模式记录。"; }
	chown root:root "$tmp" || { rm -f -- "$tmp"; die "无法设置代理模式记录所有者。"; }
	chmod 0644 "$tmp" || { rm -f -- "$tmp"; die "无法设置代理模式记录权限。"; }
	mv -f -- "$tmp" "$MODE_FILE" || { rm -f -- "$tmp"; die "无法保存代理模式记录。"; }
	log "已记录反向代理：$PROXY_MODE（$MODE_FILE，之后不可切换）"
}

record_package_ownership() {
	local tmp
	[ -f "$PACKAGE_RECORD" ] && return 0
	install -d -m 0750 "$CONF_DIR" || die "无法创建 $CONF_DIR。"
	tmp="$(mktemp "$CONF_DIR/.package-ownership.XXXXXX")" || die "无法创建软件包归属记录。"
	{
		printf 'version=1\n'
		printf 'nginx_preexisting=%s\n' "${PRE_NGINX_PKG:-unknown}"
		printf 'nginx_any_preexisting=%s\n' "${PRE_NGINX_ANY:-unknown}"
		printf 'nginx_core_preexisting=%s\n' "${PRE_NGINX_CORE_PKG:-unknown}"
		printf 'nginx_common_preexisting=%s\n' "${PRE_NGINX_COMMON_PKG:-unknown}"
		printf 'certbot_preexisting=%s\n' "${PRE_CERTBOT_PKG:-unknown}"
		printf 'certbot_dns_cloudflare_preexisting=%s\n' "${PRE_CERTBOT_CF_PKG:-unknown}"
	} > "$tmp" || { rm -f -- "$tmp"; die "无法写入软件包归属记录。"; }
	chown root:root "$tmp" || { rm -f -- "$tmp"; die "无法设置软件包归属记录所有者。"; }
	chmod 0640 "$tmp" || { rm -f -- "$tmp"; die "无法设置软件包归属记录权限。"; }
	mv -f -- "$tmp" "$PACKAGE_RECORD" || { rm -f -- "$tmp"; die "无法保存软件包归属记录。"; }
}

# Debian/Ubuntu package postinst starts nginx unless policy-rc.d says no. Block
# only nginx, chain any pre-existing policy, and restore it immediately after
# apt (and again from the EXIT trap if apt fails).
restore_proxy_autostart() {
	if [ "$POLICY_RC_ACTIVE" != 1 ] && [ ! -e "$POLICY_RC_SAVED" ]; then
		return 0
	fi
	if [ -e "$POLICY_RC_SAVED" ]; then
		mv -f -- "$POLICY_RC_SAVED" "$POLICY_RC" || warn "警告：无法恢复原有 $POLICY_RC。"
	else
		rm -f -- "$POLICY_RC" || warn "警告：无法移除临时 $POLICY_RC。"
	fi
	POLICY_RC_ACTIVE=0
}

inhibit_proxy_autostart() {
	if [ -e "$POLICY_RC_SAVED" ]; then
		mv -f -- "$POLICY_RC_SAVED" "$POLICY_RC"
	elif [ -f "$POLICY_RC" ] && grep -q 'AbuseGuard temporary policy' "$POLICY_RC" 2>/dev/null; then
		# A previous run died before restoring; drop our own stale wrapper.
		rm -f -- "$POLICY_RC"
	fi
	if [ -e "$POLICY_RC" ]; then
		mv -f -- "$POLICY_RC" "$POLICY_RC_SAVED" \
			|| die "无法暂存现有 $POLICY_RC；安装未改动系统。"
	fi
	# Mark active before writing, so a partial write is still restored by the
	# EXIT trap.
	POLICY_RC_ACTIVE=1
	if [ -e "$POLICY_RC_SAVED" ]; then
		cat > "$POLICY_RC" <<EOF || die "无法写入临时 $POLICY_RC。"
#!/bin/sh
# AbuseGuard temporary policy: block package-started nginx only.
if [ "\$1" = nginx ] || [ "\$1" = nginx.service ]; then exit 101; fi
exec $POLICY_RC_SAVED "\$@"
EOF
	else
		cat > "$POLICY_RC" <<'EOF' || die "无法写入临时 $POLICY_RC。"
#!/bin/sh
# AbuseGuard temporary policy: block package-started nginx only.
if [ "$1" = nginx ] || [ "$1" = nginx.service ]; then exit 101; fi
exit 0
EOF
	fi
	chmod 0755 "$POLICY_RC" || die "无法设置临时 $POLICY_RC 权限。"
}

# Resolve once before changing the host; bootstrap and assets share this tag.
# The redirect avoids requiring jq before dependencies have been installed.
latest_release_tag() {
	local url tag
	url="$(curl -fsSL --connect-timeout 10 --max-time 30 -o /dev/null -w '%{url_effective}' \
		"https://github.com/$ABUSEGUARD_REPO/releases/latest")" || return 1
	case "$url" in *"https://github.com/$ABUSEGUARD_REPO/releases/tag/"*) ;; *) return 1 ;; esac
	tag="${url##*/}"
	[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
	printf '%s' "$tag"
}

# detect_ssh_port -- print the TCP port sshd actually listens on. Prefer the
# live listener (covers custom and socket-activated ports), fall back to the
# effective sshd config. Prints nothing when neither source is usable.
detect_ssh_port() {
	local p=""
	p="$(ss -H -tlnp 2>/dev/null | awk '/sshd/ { n = split($4, a, ":"); print a[n] }' | sort -un | head -n 1)" || p=""
	if [ -z "$p" ]; then
		p="$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2; exit }')" || p=""
	fi
	case "$p" in ''|*[!0-9]*) return 1 ;; esac
	printf '%s' "$p"
}

verify_fail2ban_jails() {
	local mode="$1" jail dump missing attempt
	local jails="caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd"
	if [ "$mode" = config ]; then
		dump="$(fail2ban-client -d)" || die "无法读取 fail2ban 的有效配置。"
		for jail in $jails; do
			if ! grep -Fq "['add', '$jail', " <<< "$dump"; then
				die "fail2ban 有效配置未启用 $jail。请检查 /etc/fail2ban/jail.local 和 jail.d/*.local 中的 enabled 覆盖（后加载的文件优先），解决冲突后重新安装。"
			fi
		done
		return
	fi
	# systemd can report active before Fail2Ban finishes creating its jails.
	for attempt in {1..10}; do
		missing=""
		for jail in $jails; do
			fail2ban-client status "$jail" >/dev/null 2>&1 || missing="$missing $jail"
		done
		[ -n "$missing" ] || return 0
		sleep 1
	done
	die "fail2ban 已启动，但以下防护未运行：$missing。请检查 fail2ban 日志；安装未完成。"
}

# Legacy intel jails are retired. Capture their bans before the new jail files
# replace them, so the installer can re-ban each source after the new policy is
# live instead of silently dropping operator/feed bans.
legacy_intel_bans() {
	local jail status ips
	for jail in caddy-intel sshd-intel; do
		status="$(fail2ban-client status "$jail" 2>/dev/null)" || continue
		ips="$(printf '%s\n' "$status" | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
		[ -z "$ips" ] || printf '%s\n' "$ips" | tr ' ' '\n'
	done | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | sed '/^$/d' | awk '!seen[$0]++'
}

# --- fail2ban upgrade safety -------------------------------------------------
# The retired intel jails run the engine as ignorecommand. Replacing the engine
# while those jails are live would make them invoke the new CLI (which no longer
# has their subcommands) and ban every uncached visitor for 90 days. "idle" stops
# log detection/ignorecommand but keeps each jail's existing nft bans enforced;
# a full stop is only the fallback when idle is unavailable.
FAIL2BAN_PAUSED=0
FAIL2BAN_STOPPED=0
ENGINE_SWAPPED=0
ENGINE_BACKUP=""
UNIT_ROLLBACK_DIR=""
INSTALL_COMPLETE=0
STAGED_BIN=""
STAGED_RELEASE_BIN=""
F2B_ROLLBACK_DIR=""
PAUSE_JAILS="caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd sshd-intel"
PAUSED_JAILS_DONE=""
# Root-only test hook (scripts/test-native-policy.sh); production uses /etc.
F2B_ETC="${F2B_ETC:-/etc/fail2ban}"
POLICY_F2B="$F2B_ETC/jail.d/zzz-caddy-abuseguard-policy.local"

# Snapshot every fail2ban asset this installer overwrites, so a failure can
# restore the old engine+config and resume detection instead of leaving
# protection paused until the operator reruns the installer.
backup_f2b_assets() {
	local src rel
	F2B_ROLLBACK_DIR="$(mktemp -d)" || die "无法创建 fail2ban 回滚目录。"
	mkdir -p "$F2B_ROLLBACK_DIR/filter.d" "$F2B_ROLLBACK_DIR/action.d" "$F2B_ROLLBACK_DIR/jail.d" \
		|| die "无法创建 fail2ban 回滚目录。"
	: > "$F2B_ROLLBACK_DIR/manifest"
	for src in "$SRC_DIR"/assets/fail2ban/filter.d/*.conf; do
		rel="filter.d/$(basename "$src")"
		if [ -e "$F2B_ETC/$rel" ]; then
			cp -a -- "$F2B_ETC/$rel" "$F2B_ROLLBACK_DIR/$rel" || die "无法备份 $F2B_ETC/$rel。"
			printf 'present %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		else
			printf 'absent %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		fi
	done
	for src in "$SRC_DIR"/assets/fail2ban/action.d/*.conf; do
		rel="action.d/$(basename "$src")"
		if [ -e "$F2B_ETC/$rel" ]; then
			cp -a -- "$F2B_ETC/$rel" "$F2B_ROLLBACK_DIR/$rel" || die "无法备份 $F2B_ETC/$rel。"
			printf 'present %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		else
			printf 'absent %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		fi
	done
	for rel in jail.d/caddy-abuseguard.local jail.d/zz-caddy-abuseguard-report.local \
		jail.d/zzz-caddy-abuseguard-policy.local; do
		if [ -e "$F2B_ETC/$rel" ]; then
			cp -a -- "$F2B_ETC/$rel" "$F2B_ROLLBACK_DIR/$rel" || die "无法备份 $F2B_ETC/$rel。"
			printf 'present %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		else
			printf 'absent %s\n' "$rel" >> "$F2B_ROLLBACK_DIR/manifest"
		fi
	done
}

restore_f2b_assets() {
	local state rel failed=0
	[ -n "$F2B_ROLLBACK_DIR" ] && [ -f "$F2B_ROLLBACK_DIR/manifest" ] || return 0
	while IFS=' ' read -r state rel; do
		case "$state" in
			present) cp -a -- "$F2B_ROLLBACK_DIR/$rel" "$F2B_ETC/$rel" || failed=1 ;;
			absent) rm -f -- "$F2B_ETC/$rel" ;;
		esac
	done < "$F2B_ROLLBACK_DIR/manifest"
	[ "$failed" = 0 ] || warn "警告：无法完整恢复原 fail2ban 配置，请检查 /etc/fail2ban。"
}

pause_fail2ban_for_upgrade() {
	local jail failed=0
	fail2ban-client ping >/dev/null 2>&1 || return 0
	for jail in $PAUSE_JAILS; do
		fail2ban-client status "$jail" >/dev/null 2>&1 || continue
		if fail2ban-client set "$jail" idle on >/dev/null 2>&1; then
			PAUSED_JAILS_DONE="$PAUSED_JAILS_DONE $jail"
			log "已暂停 $jail 检测（现有封禁保持生效）"
		else
			warn "无法暂停 $jail 检测"
			failed=1
			break
		fi
	done
	if [ "$failed" = 1 ]; then
		log "idle 暂停失败，回退为停止 fail2ban（封禁规则短暂下掉，重启时由数据库恢复）"
		systemctl stop fail2ban \
			|| die "无法暂停或停止 fail2ban；为避免旧 jail 调用新引擎，安装已中止。"
		FAIL2BAN_STOPPED=1
	else
		FAIL2BAN_PAUSED=1
	fi
}

# The engine is still the old one on this path, so the old detection can resume.
resume_fail2ban_after_failure() {
	local jail
	for jail in $PAUSED_JAILS_DONE; do
		fail2ban-client set "$jail" idle off >/dev/null 2>&1 || true
	done
	if [ "$FAIL2BAN_PAUSED" = 1 ]; then
		warn "安装失败：已恢复旧 fail2ban 检测（旧引擎仍在使用）。"
	elif [ "$FAIL2BAN_STOPPED" = 1 ]; then
		systemctl start fail2ban >/dev/null 2>&1 || warn "警告：无法重新启动 fail2ban。"
		warn "安装失败：已恢复旧 fail2ban（旧引擎与旧配置仍在使用）。"
	elif [ -n "$PAUSED_JAILS_DONE" ]; then
		warn "安装失败：已恢复此前暂停的 fail2ban 检测（旧引擎仍在使用）。"
	fi
}

# Keep the previous engine beside the installed one until the new policy is
# proven usable, so a failure after the swap can restore the compatible pair
# instead of discarding recovery state.
restore_engine_backup() {
	[ -n "$ENGINE_BACKUP" ] || return 1
	mv -f -- "$ENGINE_BACKUP" "$ENGINE_BIN" || return 1
	ENGINE_BACKUP=""
	return 0
}

on_install_exit() {
	if declare -F restore_proxy_autostart >/dev/null 2>&1; then
		restore_proxy_autostart
	fi
	[ -z "$STAGED_BIN" ] || rm -f -- "$STAGED_BIN"
	[ -z "$STAGED_RELEASE_BIN" ] || rm -f -- "$STAGED_RELEASE_BIN"
	if [ "$INSTALL_COMPLETE" = 1 ]; then
		[ -z "$ENGINE_BACKUP" ] || rm -f -- "$ENGINE_BACKUP"
		[ -z "${UNIT_ROLLBACK_DIR:-}" ] || rm -rf -- "$UNIT_ROLLBACK_DIR"
		[ -z "$F2B_ROLLBACK_DIR" ] || rm -rf -- "$F2B_ROLLBACK_DIR"
		return 0
	fi
	if [ "$ENGINE_SWAPPED" = 0 ]; then
		restore_f2b_assets
		resume_fail2ban_after_failure
		[ -z "$ENGINE_BACKUP" ] || rm -f -- "$ENGINE_BACKUP"
		[ -z "${UNIT_ROLLBACK_DIR:-}" ] || rm -rf -- "$UNIT_ROLLBACK_DIR"
	elif restore_engine_backup; then
		# Restore the old units only after their engine is back: the new units
		# run policy-apply, which the old engine does not implement.
		if [ -n "${UNIT_ROLLBACK_DIR:-}" ] && [ -s "$UNIT_ROLLBACK_DIR/manifest" ]; then
			local state unit
			while IFS=' ' read -r state unit; do
				case "$state" in
					present) cp -a -- "$UNIT_ROLLBACK_DIR/$unit.present" "$POLICY_UNIT_DIR/$unit" \
						|| warn "警告：无法恢复旧策略服务单元 $unit。" ;;
					absent)
						systemctl disable "$unit" >/dev/null 2>&1 || true
						rm -f -- "$POLICY_UNIT_DIR/$unit" \
							|| warn "警告：无法移除新策略服务单元 $unit。" ;;
				esac
			done < "$UNIT_ROLLBACK_DIR/manifest"
			systemctl daemon-reload >/dev/null 2>&1 || warn "警告：systemd 未能重新加载恢复后的策略单元。"
		fi
		# Restore the old config only after its engine is back: old jails run the
		# engine as ignorecommand, which the new CLI no longer supports.
		restore_f2b_assets
		if systemctl restart fail2ban >/dev/null 2>&1; then
			warn "安装未完成：已恢复旧引擎、旧策略单元与旧 fail2ban 配置，检测已恢复；修复问题后请重新运行安装器。"
		else
			warn "安装未完成：已恢复旧引擎、旧策略单元与旧 fail2ban 配置，但 fail2ban 未能重新启动；请检查 journalctl -u fail2ban。"
		fi
	else
		# Fresh install (no previous engine) or unreadable backup: the new
		# engine+unit pair is compatible, so keep it and start detection.
		[ -z "$ENGINE_BACKUP" ] || warn "警告：旧引擎备份仍保留在 $ENGINE_BACKUP。"
		[ -z "${UNIT_ROLLBACK_DIR:-}" ] || rm -rf -- "$UNIT_ROLLBACK_DIR"
		if systemctl restart fail2ban >/dev/null 2>&1; then
			warn "安装未完成：已保留新 fail2ban 配置并恢复检测；修复问题后请重新运行安装器。"
		else
			warn "安装未完成：已保留新 fail2ban 配置，但 fail2ban 未能启动；请检查 journalctl -u fail2ban。"
		fi
	fi
	[ -z "$F2B_ROLLBACK_DIR" ] || rm -rf -- "$F2B_ROLLBACK_DIR"
	[ -z "${UNIT_ROLLBACK_DIR:-}" ] || rm -rf -- "$UNIT_ROLLBACK_DIR"
}

# Re-apply captured legacy bans to the retained non-reporting jail after the new
# fail2ban config is running. The pending file keeps them for a retry when an
# install fails before the migration completes.
migrate_legacy_bans() {
	local ip allow_rc failed=0
	[ -n "$LEGACY_BANS" ] || return 0
	log "正在把旧情报 jail 的封禁迁移到 caddy-rate-local（重新计时 90 天，不上报）"
	while IFS= read -r ip; do
		[ -n "$ip" ] || continue
		"$ENGINE_BIN" allowlist-validate --entry "$ip" >/dev/null 2>&1 \
			|| { warn "跳过无效的旧封禁：$ip"; continue; }
		allow_rc=0
		"$ENGINE_BIN" allowlist-check --ip "$ip" >/dev/null 2>&1 || allow_rc=$?
		case "$allow_rc" in
			0) log "白名单已覆盖旧封禁 $ip，跳过"; continue ;;
			1) ;;
			*) warn "无法检查白名单，跳过旧封禁 $ip"; failed=1; continue ;;
		esac
		if fail2ban-client set caddy-rate-local banip "$ip" >/dev/null 2>&1; then
			log "已迁移封禁：$ip"
		else
			warn "迁移封禁失败：$ip"
			failed=1
		fi
	done <<< "$LEGACY_BANS"
	if [ "$failed" = 0 ]; then
		rm -f -- "$CONF_DIR/legacy-intel-bans.pending"
	else
		warn "部分旧封禁未能迁移；保留 $CONF_DIR/legacy-intel-bans.pending 供下次安装重试。"
		return 1
	fi
}

validate_caddyfile() {
	local config="$1" cf_token=""
	[ ! -f "$CADDY_ENV" ] || cf_token="$(sed -n 's/^CF_API_TOKEN=//p' "$CADDY_ENV" | head -n 1)"
	CF_API_TOKEN="$cf_token" "$CADDY_BIN" validate --config "$config" --adapter caddyfile
}

# Source-tree runtime helper for this install. The helper installs itself
# (root-owned) through nginx_install_assets, together with only our HTTP-level
# snippets, selftest, logrotate entry and deploy hook.
setup_nginx_proxy() {
	local runtime="$SRC_DIR/assets/nginx/runtime.sh"
	[ -f "$runtime" ] || die "缺少 Nginx 运行时助手：$runtime"
	# shellcheck disable=SC1090
	. "$runtime" || die "无法加载 Nginx 运行时助手。"
	declare -F nginx_install_assets >/dev/null 2>&1 \
		|| die "Nginx 运行时助手缺少 nginx_install_assets。"
	declare -F nginx_validate >/dev/null 2>&1 \
		|| die "Nginx 运行时助手缺少 nginx_validate。"
	declare -F nginx_reload >/dev/null 2>&1 \
		|| die "Nginx 运行时助手缺少 nginx_reload。"
	nginx_install_assets "$SRC_DIR" \
		|| die "Nginx 配置/资源安装失败；安装未完成。"
	nginx_validate \
		|| die "Nginx 配置校验失败；安装未完成。"
	log "Nginx 配置与资源已就绪（$NGINX_HTTP_CONF）"
}

# Remove only a mktemp-created checkout, one entry at a time. Refuse symlinks
# and any path outside the exact temporary-directory shapes used by mktemp.
cleanup_temp_tree() {
	local root="$1" path
	case "$root" in
		/tmp/tmp.*|/var/tmp/tmp.*) : ;;
		*) warn "拒绝清理非临时目录：$root"; return 1 ;;
	esac
	[ -e "$root" ] || return 0
	[ ! -L "$root" ] || { warn "拒绝清理符号链接：$root"; return 1; }
	while IFS= read -r -d '' path; do
		if [ -d "$path" ] && [ ! -L "$path" ]; then
			rmdir -- "$path" || return 1
		else
			rm -f -- "$path" || return 1
		fi
	done < <(find "$root" -xdev -depth -mindepth 1 -print0)
	rmdir -- "$root"
}

if [ "${ABUSEGUARD_LIB_ONLY:-}" = 1 ] && [ "${BASH_SOURCE[0]}" != "$0" ]; then
	return 0
fi
parse_install_args "$@"
[ "$(id -u)" = "0" ] || die "请以 root 运行（sudo）。"

# Resolve the immutable proxy mode and reject an opposite proxy before apt or
# any other host change. An in-progress install keeps its marker, so a retry
# cannot switch backends.
UPDATE_MODE=0
if [ -f "$STATE_DIR/install-manifest" ] || [ -x "$PANEL_BIN" ] || [ -x "$LEGACY_PANEL_BIN" ]; then UPDATE_MODE=1; fi
if [ -n "${ABUSEGUARD_PROXY_CHOICE:-}" ]; then
	[ -n "$REQUESTED_PROXY" ] || set_requested_proxy "$ABUSEGUARD_PROXY_CHOICE"
	unset ABUSEGUARD_PROXY_CHOICE
fi
resolve_proxy_mode
preflight_exclusive_proxy
# Pass an interactive fresh choice through the release bootstrap unchanged.
export ABUSEGUARD_PROXY_CHOICE="$PROXY_MODE"

# --- self-bootstrap ----------------------------------------------------------
# Default installs, including those from a clone, use the latest published
# release. Only explicit source/preset-binary installs use the local checkout.
RELEASE_TAG="${ABUSEGUARD_RELEASE_TAG:-}"
unset ABUSEGUARD_RELEASE_TAG
fetch_release=0
if [ "$FROM_SOURCE" = 0 ] && [ -z "${ABUSEGUARD_ENGINE_BIN:-}" ] && [ -z "$RELEASE_TAG" ]; then
	RELEASE_TAG="$(latest_release_tag)" || die "无法确定最新 release，安装未开始。请检查网络后重试。"
	fetch_release=1
fi
if [ "$fetch_release" = 1 ] || [ ! -d "$SRC_DIR/engine" ] || [ ! -d "$SRC_DIR/assets" ]; then
	command -v tar >/dev/null 2>&1 || die "自举需要 tar 命令。"
	AG_REF="${ABUSEGUARD_REF:-main}"
	archive_ref="heads/$AG_REF"
	if [ -n "$RELEASE_TAG" ]; then AG_REF="$RELEASE_TAG"; archive_ref="tags/$RELEASE_TAG"; fi
	AG_TMP="$(mktemp -d)"
	trap 'cleanup_temp_tree "$AG_TMP" || true' EXIT
	log "正在获取仓库 $ABUSEGUARD_REPO@$AG_REF ..."
	gh_fetch "https://github.com/$ABUSEGUARD_REPO/archive/refs/$archive_ref.tar.gz" "$AG_TMP/repo.tar.gz" \
		|| die "自举下载失败（可设置 ABUSEGUARD_REPO / ABUSEGUARD_REF，或克隆仓库后运行 ./install.sh）。"
	tar -xzf "$AG_TMP/repo.tar.gz" -C "$AG_TMP" --strip-components=1 \
		|| die "自举解压失败。"
	rm -f "$AG_TMP/repo.tar.gz"
	# Never hand an nginx request to a release without nginx support.
	if [ "${PROXY_MODE:-caddy}" = nginx ] \
		&& { [ ! -f "$AG_TMP/assets/nginx/runtime.sh" ] || ! grep -q -- '--proxy' "$AG_TMP/install.sh"; }; then
		die "目标版本 $AG_REF 不支持 Nginx 安装（缺少运行时或 --proxy 处理）。请使用 --from-source 或改用 --proxy=caddy。安装未改动系统。"
	fi
	export ABUSEGUARD_REPO ABUSEGUARD_REF
	# Run (not exec) the unpacked installer so the EXIT trap above still fires
	# and cleans the temp checkout; propagate its exit code. The choice must
	# survive even when the user picked nginx interactively.
	ABUSEGUARD_RELEASE_TAG="$RELEASE_TAG" ABUSEGUARD_PROXY_CHOICE="${PROXY_MODE:-caddy}" \
		bash "$AG_TMP/install.sh" "$@"
	exit $?
fi
if [ "${PROXY_MODE:-caddy}" = nginx ] && [ ! -f "$SRC_DIR/assets/nginx/runtime.sh" ]; then
	die "当前源码缺少 assets/nginx/runtime.sh，无法安装 Nginx。请使用完整源码或改用 --proxy=caddy。安装未改动系统。"
fi

TARGET_VERSION="$(tr -d '[:space:]' < "$SRC_DIR/VERSION" 2>/dev/null || true)"
[ -n "$TARGET_VERSION" ] || TARGET_VERSION=dev
if [ -n "$RELEASE_TAG" ] && [ "$RELEASE_TAG" != "v$TARGET_VERSION" ]; then
	die "release 源码版本不匹配：$RELEASE_TAG / $TARGET_VERSION。"
fi

# --- OS + arch guard ---------------------------------------------------------
. /etc/os-release 2>/dev/null || die "无法读取 /etc/os-release。"
case " ${ID:-} ${ID_LIKE:-} " in
	*" debian "*|*" ubuntu "*) : ;;
	*) die "不支持的系统 '${PRETTY_NAME:-unknown}'。AbuseGuard 仅支持 Debian/Ubuntu。" ;;
esac
case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "不支持的架构 '$(uname -m)'。仅支持 amd64/arm64。" ;;
esac
log "目标系统：${PRETTY_NAME:-Debian/Ubuntu}（$ARCH）"

# --- proxy mode record + package ownership (before apt touches the host) -----
# A failed install keeps the mode record, so a retry cannot switch backends.
write_mode_record
if [ "$PROXY_MODE" = nginx ]; then
	PRE_NGINX_PKG="$(pkg_preexisting nginx)"
	PRE_NGINX_ANY=0
	if proxy_backend_present nginx; then PRE_NGINX_ANY=1; fi
	PRE_NGINX_CORE_PKG="$(pkg_preexisting nginx-core)"
	PRE_NGINX_COMMON_PKG="$(pkg_preexisting nginx-common)"
	PRE_CERTBOT_PKG="$(pkg_preexisting certbot)"
	PRE_CERTBOT_CF_PKG="$(pkg_preexisting python3-certbot-dns-cloudflare)"
	record_package_ownership
	# A retry after a partial apt run must keep using the original ownership,
	# not the now-installed package state.
	recorded_nginx_owner="$(sed -n 's/^nginx_preexisting=//p' "$PACKAGE_RECORD" 2>/dev/null | head -n 1)"
	case "$recorded_nginx_owner" in
		0|1) PRE_NGINX_PKG="$recorded_nginx_owner" ;;
	esac
	recorded_nginx_any="$(sed -n 's/^nginx_any_preexisting=//p' "$PACKAGE_RECORD" 2>/dev/null | head -n 1)"
	case "$recorded_nginx_any" in
		0|1) PRE_NGINX_ANY="$recorded_nginx_any" ;;
		"") PRE_NGINX_ANY="$PRE_NGINX_PKG" ;;
	esac
fi

# --- dependencies ------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
if [ "$PROXY_MODE" = caddy ]; then
	log "正在安装依赖（fail2ban、rsyslog、nftables、curl、jq、libcap2-bin）..."
	apt-get update -qq
	apt-get install -y -qq fail2ban rsyslog nftables curl jq ca-certificates libcap2-bin >/dev/null
else
	log "正在安装依赖（fail2ban、rsyslog、nftables、curl、jq、nginx、certbot、certbot-dns-cloudflare）..."
	apt-get update -qq
	for pkg in nginx certbot python3-certbot-dns-cloudflare; do
		apt-cache show "$pkg" >/dev/null 2>&1 \
			|| die "软件源中没有 $pkg；无法安装 Nginx 方案。安装未完成。"
	done
	trap on_install_exit EXIT
	inhibit_proxy_autostart
	apt-get install -y -qq fail2ban rsyslog nftables curl jq ca-certificates \
		nginx certbot python3-certbot-dns-cloudflare >/dev/null \
		|| die "Nginx/Certbot 依赖安装失败。"
	restore_proxy_autostart
	# The package may have enabled nginx before our config exists. Keep it from
	# starting an empty/default site on reboot until the install succeeds. This
	# applies to a fresh install or a retry before the manifest exists; an
	# update must not disable an already serving proxy.
	if [ "$PRE_NGINX_ANY" = 0 ] && [ "$UPDATE_MODE" = 0 ]; then
		systemctl disable nginx >/dev/null 2>&1 || true
	fi
	# Capability preflight: the distro build must provide what our managed
	# sites need, and the DNS authenticator must import before we touch config.
	command -v nginx >/dev/null 2>&1 || die "nginx 可执行文件不可用。"
	command -v certbot >/dev/null 2>&1 || die "certbot 可执行文件不可用。"
	nginx_build="$(nginx -V 2>&1 || true)"
	case "$nginx_build" in
		*--with-http_ssl_module*) : ;;
		*) die "发行版 Nginx 缺少 http_ssl_module，无法提供 HTTPS。" ;;
	esac
	case "$nginx_build" in
		*--with-http_v2_module*) : ;;
		*) die "发行版 Nginx 缺少 http_v2_module，无法提供 HTTP/2。" ;;
	esac
	python3 -c 'import certbot_dns_cloudflare' >/dev/null 2>&1 \
		|| die "certbot-dns-cloudflare 插件不可用。"
	certbot_cf_supports_api_token \
		|| die "当前 certbot-dns-cloudflare 插件不支持 Cloudflare API Token（旧版只支持 Global API Key）。请升级 python3-certbot-dns-cloudflare 后重试；AbuseGuard 不会回退到 Global API Key，安装未完成。"
	[ -f /etc/nginx/nginx.conf ] || die "缺少 /etc/nginx/nginx.conf。"
	# Only a package we just installed created the distro default site. Disable
	# it instead of exposing port 80; a pre-existing Nginx keeps its own sites.
	if [ "$PRE_NGINX_ANY" = 0 ] && [ "$UPDATE_MODE" = 0 ] \
		&& { [ -e /etc/nginx/sites-enabled/default ] || [ -L /etc/nginx/sites-enabled/default ]; }; then
		rm -f -- /etc/nginx/sites-enabled/default
		log "已禁用发行版默认 80 端口站点（/etc/nginx/sites-enabled/default）"
	fi
	nginx -t >/dev/null 2>&1 || die "发行版 Nginx 现有配置预检失败；请先修复后再安装。"
fi
systemctl enable --now rsyslog >/dev/null 2>&1 || die "rsyslog 启动失败（查看：journalctl -u rsyslog）。"
[ -e /var/log/auth.log ] || install -m 0640 -o root -g adm /dev/null /var/log/auth.log

# --- record pre-install state (for symmetric uninstall) ----------------------
# Snapshot what already exists BEFORE creating anything, so uninstall can tell
# "installed by AbuseGuard" (safe to remove) from "user already had it" (keep).
PRE_CADDY_BIN=0;  [ -e "$CADDY_BIN" ] && PRE_CADDY_BIN=1 || :
PRE_CADDY_SVC=0;  [ -e /etc/systemd/system/caddy.service ] && PRE_CADDY_SVC=1 || :
PRE_CADDY_USER=0; id caddy >/dev/null 2>&1 && PRE_CADDY_USER=1 || :
PRE_AG_USER=0;    id abuseguard >/dev/null 2>&1 && PRE_AG_USER=1 || :
PRE_CADDYFILE=0;  [ -e "$CADDYFILE" ] && PRE_CADDYFILE=1 || :
PRE_CADDY_ETC=0;  [ -e "$CADDY_ETC" ] && PRE_CADDY_ETC=1 || :
PRE_LOG_DIR=0;    [ -e "$LOG_DIR" ] && PRE_LOG_DIR=1 || :
PRE_CADDY_LIB=0;  [ -e /var/lib/caddy ] && PRE_CADDY_LIB=1 || :

# --- service accounts --------------------------------------------------------
if [ "$PROXY_MODE" = caddy ] && ! id caddy >/dev/null 2>&1; then
	log "创建系统用户 'caddy'"
	useradd --system --user-group --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
fi
if ! id abuseguard >/dev/null 2>&1; then
	log "创建系统用户 'abuseguard'"
	useradd --system --user-group --shell /usr/sbin/nologin abuseguard
fi

# --- directories -------------------------------------------------------------
install -d -m 0755 "$LIBEXEC_DIR"
if [ "$PROXY_MODE" = caddy ]; then
	install -d -m 0755 "$CADDY_ETC"
	install -d -m 0750 -o caddy -g caddy "$LOG_DIR"
fi
install -d -m 0750 -o root -g abuseguard "$CONF_DIR"
install -d -m 0750 -o abuseguard -g abuseguard "$STATE_DIR" "$REPORTS_DIR"

# Write the install manifest ONCE (first install); a re-run must not overwrite
# the original pre-install snapshot.
if [ ! -f "$STATE_DIR/install-manifest" ]; then
	cat > "$STATE_DIR/install-manifest" <<EOF
web_server=$PROXY_MODE
caddy_bin_preexisting=$PRE_CADDY_BIN
caddy_service_preexisting=$PRE_CADDY_SVC
caddy_user_preexisting=$PRE_CADDY_USER
abuseguard_user_preexisting=$PRE_AG_USER
caddyfile_preexisting=$PRE_CADDYFILE
caddy_etc_preexisting=$PRE_CADDY_ETC
log_dir_preexisting=$PRE_LOG_DIR
caddy_lib_preexisting=$PRE_CADDY_LIB
EOF
	chmod 0640 "$STATE_DIR/install-manifest"
	log "已记录安装清单（供卸载时对称回滚）"
fi

# --- capture legacy fail2ban state before the engine swap ---------------------
# The retired jails' bans must be read while the old config is live; per-jail
# native ignoreip is preserved by the applier on every apply. Old jails are
# made idle (not stopped) around the swap so existing bans stay enforced. The
# pending file makes the ban migration retryable after a failed install.
LEGACY_BANS=""
if [ -f "$CONF_DIR/legacy-intel-bans.pending" ]; then
	LEGACY_BANS="$(cat "$CONF_DIR/legacy-intel-bans.pending")"
fi
if fail2ban-client ping >/dev/null 2>&1; then
	LEGACY_BANS="$(printf '%s\n%s\n' "$LEGACY_BANS" "$(legacy_intel_bans || true)" \
		| sed '/^$/d' | awk '!seen[$0]++')"
else
	[ "$UPDATE_MODE" = 0 ] \
		|| warn "fail2ban 未运行：无法读取旧情报 jail 的封禁；已记录的封禁会在成功安装后迁移。"
fi
if [ -n "$LEGACY_BANS" ]; then
	printf '%s\n' "$LEGACY_BANS" > "$CONF_DIR/legacy-intel-bans.pending" \
		|| die "无法保存旧封禁清单。"
	chown root:root "$CONF_DIR/legacy-intel-bans.pending"
	chmod 0640 "$CONF_DIR/legacy-intel-bans.pending"
fi
trap on_install_exit EXIT
trap 'exit 130' INT TERM
# Snapshot every fail2ban file replaced below: a failure before the engine swap
# restores this set, then resumes the old detection instead of leaving it off.
backup_f2b_assets
# Install the new jail/filter/action files before the engine swap. They contain
# no ignorecommand, so a reboot or a failed install cannot make the old intel
# jails execute the new engine. The running fail2ban keeps its old in-memory
# config until the final restart; this only changes the on-disk config.
log "正在安装 fail2ban 的 filter / action / jail"
install -m 0644 "$SRC_DIR"/assets/fail2ban/filter.d/*.conf "$F2B_ETC/filter.d/"
install -m 0644 "$SRC_DIR"/assets/fail2ban/action.d/*.conf "$F2B_ETC/action.d/"
install -m 0644 "$SRC_DIR/assets/fail2ban/jail.d/caddy-abuseguard.local" "$F2B_ETC/jail.d/caddy-abuseguard.local"
install -m 0644 "$SRC_DIR/assets/fail2ban/jail.d/zz-caddy-abuseguard-report.local" "$F2B_ETC/jail.d/zz-caddy-abuseguard-report.local"
# Same jail IDs/filters/thresholds; only where the access log lives changes.
if [ "$PROXY_MODE" = nginx ]; then
	sed -i 's#/var/log/caddy/abuseguard-access.json#/var/log/nginx/abuseguard-access.json#g' \
		"$F2B_ETC/jail.d/caddy-abuseguard.local" \
		|| die "无法将 fail2ban jail 的日志路径切换到 Nginx。"
	grep -Eq '^[[:space:]]*logpath[[:space:]]*=[[:space:]]*/var/log/nginx/abuseguard-access\.json[[:space:]]*$' "$F2B_ETC/jail.d/caddy-abuseguard.local" \
		|| die "fail2ban jail 的 Nginx 日志路径未生效；安装未完成。"
fi
# Disable retired intel jails before the engine swap, even if a copy lives in
# jail.local: the first policy apply rewrites this file with the full generated
# ignoreip, but this early version already prevents old jails from ever running
# the new engine after a reboot.
if [ ! -f "$POLICY_F2B" ]; then
	printf '[caddy-intel]\nenabled = false\n\n[sshd-intel]\nenabled = false\n' \
		> "$POLICY_F2B"
	chmod 0644 "$POLICY_F2B"
fi
# Reports carry the port that was actually attacked, so keep the SSH jail in
# sync with the port sshd listens on instead of the hardcoded 22 default.
ssh_port="$(detect_ssh_port)" || ssh_port=""
if [ -n "$ssh_port" ]; then
	sed -i -E "s/(profile=ssh-bruteforce, transport=SSH, target_port=)[0-9]+/\1$ssh_port/" \
		"$F2B_ETC/jail.d/zz-caddy-abuseguard-report.local"
	log "SSH 上报端口已同步为 $ssh_port"
else
	warn "未能探测 SSH 端口，SSH 上报端口保持默认 22（可在 /etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local 手动修改）"
fi

# release_asset NAME -- URL of an asset from the selected release.
release_asset() {
	local route=latest/download
	[ -z "${RELEASE_TAG:-}" ] || route="download/$RELEASE_TAG"
	printf 'https://github.com/%s/releases/%s/%s' "$ABUSEGUARD_REPO" "$route" "$1"
}

# --- integrity: verify downloaded binaries against the release SHA256SUMS -----
# Every downloaded binary MUST match the release checksums. Verification is
# MANDATORY, not best-effort: if the checksums cannot be obtained we abort,
# rather than quietly installing something unverified. That is practical
# because the sums file is tiny and is fetched direct from GitHub, with
# retries.
SUMS_FILE=""
# sums_require -- fetch SHA256SUMS.txt once, on first actual need (so a
# --from-source / preset-binary install never fetches it at all). Aborts the
# install if it cannot be had; it never degrades to "skip verification".
sums_require() {
	if [ -n "$SUMS_FILE" ]; then return 0; fi
	local url; url="$(release_asset SHA256SUMS.txt)"
	local f; f="$(mktemp)"
	log "正在获取 SHA256SUMS（校验二进制用）..."
	if $AG_CURL_SUMS -o "$f" "$url" && [ -s "$f" ]; then
		SUMS_FILE="$f"
		trap 'rm -f "${SUMS_FILE:-}"; on_install_exit' EXIT
		return 0
	fi
	rm -f "$f"
	die "无法获取 SHA256SUMS.txt。为避免安装未经校验的二进制，安装已中止；请检查网络后重试，或用 --from-source 本地编译引擎。"
}
verify_sha256() {  # FILE BASENAME -- return failure unless the release checksum matches
	local file="$1" fn="$2" want got
	sums_require
	want="$(awk -v f="$fn" '$2==f || $2=="*"f {print $1; exit}' "$SUMS_FILE")"
	[ -n "$want" ] || { warn "SHA256SUMS.txt 里没有 $fn 的校验值，无法校验。"; return 1; }
	got="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
	[ "$got" = "$want" ] || { warn "$fn 校验失败（期望 $want，实际 ${got:-空}）——可能被镜像篡改或下载损坏。"; return 1; }
	log "已校验 $fn（sha256 ✓）"
}

# Stage a release binary beside its destination, then verify and probe it before
# an atomic rename. A failed download, checksum, or startup check leaves the
# currently installed binary untouched. The caller decides when to commit, so a
# long download can finish while fail2ban still runs the old engine.
stage_release_binary() {  # URL DEST BASENAME LABEL [EXPECTED_ENGINE_VERSION]
	local url="$1" dest="$2" fn="$3" label="$4" expected="${5:-}" tmp version_output
	sums_require
	tmp="$(mktemp "$(dirname "$dest")/.${fn}.tmp.XXXXXX")" \
		|| { warn "$label：无法创建临时下载文件。"; return 1; }
	if ! gh_fetch "$url" "$tmp" "$AG_CURL_BIG"; then
		rm -f -- "$tmp"
		warn "$label 下载失败。"
		return 1
	fi
	if ! verify_sha256 "$tmp" "$fn"; then
		rm -f -- "$tmp"
		return 1
	fi
	if ! chmod 0755 "$tmp" || ! version_output="$("$tmp" version 2>/dev/null)"; then
		rm -f -- "$tmp"
		warn "$label 启动检查失败，保留当前版本。"
		return 1
	fi
	if [ -n "$expected" ] && [ "$(awk 'NR == 1 { print $2 }' <<< "$version_output")" != "$expected" ]; then
		rm -f -- "$tmp"
		warn "$label 版本不匹配（需要 $expected），保留当前版本。"
		return 1
	fi
	STAGED_RELEASE_BIN="$tmp"
}
commit_staged_binary() {  # DEST LABEL
	if ! mv -f -- "$STAGED_BIN" "$1"; then
		rm -f -- "$STAGED_BIN"
		STAGED_BIN=""
		warn "$2 无法替换当前二进制。"
		return 1
	fi
	STAGED_BIN=""
}
install_release_binary() {  # URL DEST BASENAME LABEL [EXPECTED_ENGINE_VERSION]
	local staged
	stage_release_binary "$@" || return 1
	staged="$STAGED_RELEASE_BIN"
	STAGED_RELEASE_BIN=""
	if ! mv -f -- "$staged" "$2"; then
		rm -f -- "$staged"
		warn "$4 无法替换当前二进制。"
		return 1
	fi
}

# --- engine ------------------------------------------------------------------
# Download/compile/verify into a temp beside the destination; the atomic swap
# happens only after fail2ban is paused (commit_engine below).
stage_engine() {
	if [ -n "${ABUSEGUARD_ENGINE_BIN:-}" ]; then
		[ -f "$ABUSEGUARD_ENGINE_BIN" ] || die "找不到 ABUSEGUARD_ENGINE_BIN 指定的文件 '$ABUSEGUARD_ENGINE_BIN'。"
		log "从 ABUSEGUARD_ENGINE_BIN 安装引擎"
		STAGED_BIN="$(mktemp "$(dirname "$ENGINE_BIN")/.engine.tmp.XXXXXX")" \
			|| die "无法创建引擎临时文件。"
		install -m 0755 "$ABUSEGUARD_ENGINE_BIN" "$STAGED_BIN" \
			|| die "无法暂存 ABUSEGUARD_ENGINE_BIN。"
		return
	fi
	if [ "$FROM_SOURCE" = "1" ]; then
		command -v go >/dev/null 2>&1 || die "--from-source 需要 Go 工具链（请先安装 go）。"
		log "从源码编译引擎（$SRC_DIR/engine）"
		STAGED_BIN="$(mktemp "$(dirname "$ENGINE_BIN")/.engine.tmp.XXXXXX")" \
			|| die "无法创建引擎临时文件。"
		( cd "$SRC_DIR/engine" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$TARGET_VERSION" -o "$STAGED_BIN" . ) \
			|| die "引擎编译失败；未替换当前引擎。"
		chmod 0755 "$STAGED_BIN"
		return
	fi
	local fn="caddy-abuseguard-linux-$ARCH"
	local url; url="$(release_asset "$fn")"
	log "正在下载引擎（linux-$ARCH，自动选择线路，稍候）..."
	stage_release_binary "$url" "$ENGINE_BIN" "$fn" "引擎" "$TARGET_VERSION" \
		|| die "引擎下载、校验或启动检查失败。可用 --from-source 或设置 ABUSEGUARD_ENGINE_BIN。"
	STAGED_BIN="$STAGED_RELEASE_BIN"
	STAGED_RELEASE_BIN=""
}
commit_engine() {
	if [ -e "$ENGINE_BIN" ]; then
		ENGINE_BACKUP="$(mktemp "$(dirname "$ENGINE_BIN")/.engine.rollback.XXXXXX")" \
			|| die "无法创建旧引擎备份；安装未完成。"
		cp -a -- "$ENGINE_BIN" "$ENGINE_BACKUP" \
			|| die "无法备份当前引擎；安装未完成。"
	fi
	commit_staged_binary "$ENGINE_BIN" "引擎" \
		|| die "无法替换引擎二进制；安装未完成。"
	ENGINE_SWAPPED=1
}
stage_engine
INSTALLED_VERSION="$("$STAGED_BIN" version 2>/dev/null | awk 'NR == 1 { print $2 }' || true)"
[ "$INSTALLED_VERSION" = "$TARGET_VERSION" ] \
	|| die "引擎版本不匹配：需要 $TARGET_VERSION，实际 ${INSTALLED_VERSION:-未知}。"
log "引擎：$("$STAGED_BIN" version)"

# --- config, whitelist, key (only if absent) ---------------------------------
if [ ! -f "$CONF_DIR/config.json" ]; then
	install -m 0640 -o root -g abuseguard "$SRC_DIR/assets/config/config.json.template" "$CONF_DIR/config.json"
	log "已写入 $CONF_DIR/config.json"
else
	log "保留已有的 $CONF_DIR/config.json"
fi
if [ ! -f "$CONF_DIR/whitelist" ]; then
	install -m 0640 -o root -g abuseguard "$SRC_DIR/assets/whitelist.default" "$CONF_DIR/whitelist"
	log "已写入 $CONF_DIR/whitelist"
else
	log "保留已有的 $CONF_DIR/whitelist"
fi
if [ ! -f "$CONF_DIR/abuseipdb-report.key" ]; then
	install -m 0640 -o root -g abuseguard /dev/null "$CONF_DIR/abuseipdb-report.key"
	log "已创建空的 $CONF_DIR/abuseipdb-report.key（可在面板中设置 key）"
fi
printf '%s\n' "$ABUSEGUARD_REPO" > "$CONF_DIR/repo"; chmod 0644 "$CONF_DIR/repo"

# --- backend setup -----------------------------------------------------------
if [ "$PROXY_MODE" = caddy ]; then
# --- Caddy binary with the cloudflare DNS module -----------------------------
# Downloaded from our own GitHub release (built by CI with xcaddy), like the
# engine. caddyserver.com's custom build is not used.
need_caddy=1
if [ -x "$CADDY_BIN" ] && "$CADDY_BIN" list-modules 2>/dev/null | awk '$0=="dns.providers.cloudflare" { found=1 } END { exit !found }'; then
	need_caddy=0
fi
if [ "$need_caddy" = "1" ]; then
	caddy_fn="caddy-linux-$ARCH"
	log "正在下载带 cloudflare 模块的 Caddy（linux-$ARCH，自动选择线路，稍候）..."
	install_release_binary "$(release_asset "$caddy_fn")" "$CADDY_BIN" "$caddy_fn" "Caddy" \
		|| die "Caddy 下载、校验或启动检查失败。可预置一个带 cloudflare 模块的 caddy 到 $CADDY_BIN 后重试。"
else
	log "已有的 Caddy 已包含 cloudflare 模块"
fi
# checksums no longer needed; drop the temp + its EXIT trap (if we fetched one)
if [ -n "$SUMS_FILE" ]; then rm -f "$SUMS_FILE"; SUMS_FILE=""; trap on_install_exit EXIT; fi
setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" || warn "setcap 失败；Caddy 绑定 :80/:443 可能需要 root"

# --- Caddy snippet + env + systemd unit --------------------------------------
# Protected sites live here, one <domain>.caddy each. The
# placeholder keeps `import sites/*.caddy` matching at least one file (an empty
# glob would fail Caddyfile adaptation).
install -d -m 0755 "$SITES_DIR"
if [ ! -e "$SITES_DIR/_placeholder.caddy" ]; then
	cat > "$SITES_DIR/_placeholder.caddy" <<'PH'
# AbuseGuard 受保护站点目录。
# 每个站点一个 <域名>.caddy 文件，并在站点块中 import abuseguard。
PH
	chmod 0644 "$SITES_DIR/_placeholder.caddy"
fi
caddy_env_token="$(sed -n 's/^CF_API_TOKEN=//p' "$CADDY_ENV" 2>/dev/null | head -n 1 || true)"
if [ -z "$caddy_env_token" ]; then
	caddy_pid="$(systemctl show -p MainPID --value caddy 2>/dev/null || true)"
	if [[ "$caddy_pid" =~ ^[1-9][0-9]*$ ]] && [ -r "/proc/$caddy_pid/environ" ]; then
		caddy_env_token="$(tr '\0' '\n' < "/proc/$caddy_pid/environ" | sed -n 's/^CF_API_TOKEN=//p' | head -n 1)"
	fi
	if [ -n "$caddy_env_token" ]; then
		printf 'CF_API_TOKEN=%s\n' "$caddy_env_token" > "$CADDY_ENV"
		chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
		log "已将现有 Caddy 服务的 Cloudflare token 写入 $CADDY_ENV"
	fi
fi
if [ ! -f "$CADDY_ENV" ]; then
	printf 'CF_API_TOKEN=\n' > "$CADDY_ENV"; chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
	log "已创建 $CADDY_ENV（可在面板中设置 CF_API_TOKEN）"
fi
# If a packaged Caddy unit exists (/lib/systemd/system/caddy.service), ours in
# /etc/systemd/system takes precedence and shadows it. Say so, since uninstall
# removes ours and the packaged one then needs re-enabling.
if [ "$PRE_CADDY_SVC" = 0 ] && [ -e /lib/systemd/system/caddy.service ]; then
	warn "检测到系统已有 Caddy 服务单元（/lib/systemd/system/caddy.service）。AbuseGuard 的单元会覆盖它；卸载后如需恢复原服务，请执行：sudo systemctl enable --now caddy"
fi
install -m 0644 "$SRC_DIR/assets/systemd/caddy.service" /etc/systemd/system/caddy.service

# --- Caddyfile (only if absent) ----------------------------------------------
# If the user already had a Caddyfile, back it up once so uninstall can restore
# their exact original config.
if [ "$PRE_CADDYFILE" = 1 ] && [ ! -e "$CADDY_ETC/Caddyfile.pre-abuseguard" ]; then
	cp -a "$CADDYFILE" "$CADDY_ETC/Caddyfile.pre-abuseguard"
	log "已备份原 Caddyfile 到 $CADDY_ETC/Caddyfile.pre-abuseguard"
fi
caddy_migration_source="$CADDYFILE"
if [ ! -f "$CADDYFILE" ]; then
	log "正在获取 Cloudflare IP 段用于 trusted_proxies..."
	CF_V4="$(curl -fsSL --max-time 15 https://www.cloudflare.com/ips-v4 2>/dev/null || true)"
	CF_V6="$(curl -fsSL --max-time 15 https://www.cloudflare.com/ips-v6 2>/dev/null || true)"
	# `|| true`: under `set -euo pipefail` a no-match grep exits 1 and would abort
	# the whole install here — before the fallback below ever runs.
	CF_RANGES="$(printf '%s\n%s\n' "$CF_V4" "$CF_V6" | grep -E '[0-9a-fA-F:.]+/[0-9]+' | tr '\n' ' ' | sed 's/  */ /g; s/ *$//' || true)"
	# Live fetch failed (slow/blocked network)? Fall back to the bundled snapshot
	# so trusted_proxies is never loopback-only behind Cloudflare — which would
	# make Caddy treat every visitor as a CF edge IP and ban Cloudflare itself.
	if [ -z "$CF_RANGES" ] && [ -f "$SRC_DIR/assets/caddy/cloudflare-ips.fallback" ]; then
		CF_RANGES="$(grep -E '[0-9a-fA-F:.]+/[0-9]+' "$SRC_DIR/assets/caddy/cloudflare-ips.fallback" | tr '\n' ' ' | sed 's/  */ /g; s/ *$//' || true)"
		[ -n "$CF_RANGES" ] && warn "未能实时获取 Cloudflare IP 段，已使用内置快照（可能过期）。若你在 Cloudflare 之后，请务必核对 $CADDYFILE 的 trusted_proxies——配置错误会封禁 Cloudflare 自身、导致站点整体不可用。"
	fi
	[ -n "$CF_RANGES" ] || warn "无法获取 Cloudflare IP 段（实时与内置快照均失败）；仅信任回环。若在 Cloudflare 之后，请手动补上 trusted_proxies，否则可能自我封禁。"
	cat > "$CADDYFILE" <<EOF
# 由 AbuseGuard install.sh 生成，可自由编辑。
#
# 全局块信任你的边缘代理，使 client_ip 为真实访客 IP（用于检测/上报）。
{
	servers {
		protocols h1 h2
		trusted_proxies static 127.0.0.1/8 ::1 ${CF_RANGES}
		trusted_proxies_strict
	}
}

# 引入一次 AbuseGuard 的日志/探测片段。
import ${SNIPPET}

# AbuseGuard 受保护站点（每个域名一个文件）。
import ${SITES_DIR}/*.caddy

# 安装器创建的仅回环自检站点，可安全删除。
# 它在不暴露任何东西的情况下验证 日志 + fail2ban 链路是否正常。
http://127.0.0.1:8080 {
	bind 127.0.0.1
	import abuseguard
	respond "abuseguard test ok"
}

# 在 ${SITES_DIR}/<域名>.caddy 中添加受保护站点。
EOF
	log "已写入 $CADDYFILE"
else
	log "保留已有的 $CADDYFILE"
	caddy_migration_source="$(mktemp)"
	install -m 0644 "$CADDYFILE" "$caddy_migration_source"
	site_import="$SITES_DIR/*.caddy"
	# A pre-existing Caddyfile needs the named snippet before any protected
	# site can `import abuseguard`. Insert it before an existing sites import;
	# otherwise append it now and append the sites import immediately after.
	if ! awk -v snippet="$SNIPPET" '$1=="import" && $2==snippet { found=1 } END { exit !found }' "$caddy_migration_source"; then
		tmp="$(mktemp)"
		awk -v snippet="$SNIPPET" -v sites="$site_import" '
			!inserted && $1=="import" && $2==sites {
				print "# 引入一次 AbuseGuard 的日志/探测片段。"
				print "import " snippet
				print ""
				inserted=1
			}
			{ print }
			END {
				if (!inserted) {
					print ""
					print "# 引入一次 AbuseGuard 的日志/探测片段。"
					print "import " snippet
				}
			}
		' "$caddy_migration_source" > "$tmp" && cat "$tmp" > "$caddy_migration_source"
		rm -f "$tmp"
		log "已在现有 Caddyfile 中加入 import abuseguard.caddy"
	fi
	if ! awk -v sites="$site_import" '$1=="import" && $2==sites { found=1 } END { exit !found }' "$caddy_migration_source"; then
		printf '\n# AbuseGuard 受保护站点\nimport %s/*.caddy\n' "$SITES_DIR" >> "$caddy_migration_source"
		log "已在 Caddyfile 中加入 import sites/*.caddy"
	fi
fi

# Keep the canonical AbuseGuard Caddy layout warning-free after migrating old
# configs.  Caddy already forwards X-Forwarded-Host with this exact value.
normalize_caddy_file() {
	local file="$1"
	[ -f "$file" ] || return 0
	sed -i -E '/^[[:space:]]*header_up[[:space:]]+X-Forwarded-Host[[:space:]]+\{(host|http\.request\.host)\}[[:space:]]*$/d' "$file"
	"$CADDY_BIN" fmt --overwrite "$file" >/dev/null || { warn "无法格式化 Caddy 配置：$file"; return 1; }
}

# A conservative uninstall keeps managed site files but removes this import.
# Reinstalling must put those existing sites back under AbuseGuard protection.
ensure_site_protected() {
	local file="$1" tmp
	[ "$(basename "$file")" != "_placeholder.caddy" ] || return 0
	grep -qE '^[[:space:]]*import[[:space:]]+abuseguard[[:space:]]*$' "$file" && return 0
	tmp="$(mktemp)"
	if ! awk '
		!inserted && /^[[:space:]]*[^#].*\{[[:space:]]*(#.*)?$/ {
			print
			match($0, /^[[:space:]]*/)
			print substr($0, RSTART, RLENGTH) "\timport abuseguard"
			inserted=1
			next
		}
		{ print }
		END { if (!inserted) exit 1 }
	' "$file" > "$tmp"; then
		rm -f "$tmp"
		warn "无法为现有站点恢复 AbuseGuard 防护：$file"
		return 1
	fi
	install -m 0644 "$tmp" "$file"
	rm -f "$tmp"
	log "已恢复现有站点的 AbuseGuard 防护：$file"
}

# --- normalize sites into /etc/caddy/sites ----------------------------------
# Existing Caddy installs may keep ordinary reverse-proxy sites in the main
# Caddyfile, while old AbuseGuard releases wrote protection directives there.
# The canonical layout is one protected site per /etc/caddy/sites/<domain>.caddy,
# using the shared `import abuseguard` snippet.
#
# All normalization and migration work happens in a private candidate tree.
# The real Caddyfile and site files are changed only after the complete
# candidate validates, and are restored if the final installation step fails.
migration_abort() {
	local root="$1" source="$2" message="$3"
	cleanup_temp_tree "$root" || true
	[ "$source" = "$CADDYFILE" ] || rm -f -- "$source"
	die "$message"
}

migrate_caddy_sites() {
	local source="$1"
	local migrator="$SRC_DIR/scripts/migrate-caddy-sites.sh"
	local root candidate_etc candidate_source candidate_snippet candidate_sites out_root out_main out_sites domains
	local validation candidate_site domain target name backup_dir site_backup_dir had_main=0 snippet_existed=0 failed=0 count=0
	local -a site_candidates=() site_targets=() site_existed=()
	root="$(mktemp -d)"
	if [ ! -f "$migrator" ]; then
		migration_abort "$root" "$source" "缺少站点迁移器：$migrator"
	fi

	candidate_etc="$root/config"
	candidate_source="$candidate_etc/Caddyfile"
	candidate_snippet="$candidate_etc/abuseguard.caddy"
	candidate_sites="$candidate_etc/sites"
	out_root="$root/migrated"
	out_main="$out_root/Caddyfile"
	out_sites="$out_root/sites"
	domains="$out_root/domains"
	install -d -m 0700 "$candidate_etc" "$out_sites" || migration_abort "$root" "$source" "无法创建 Caddy 候选目录。"
	# Keep the candidate under the same /etc/caddy layout.  This preserves
	# relative imports such as `import ../common.conf` from a site file without
	# rewriting or interpreting arbitrary import paths.
	cp -aL -- "$CADDY_ETC/." "$candidate_etc/" || migration_abort "$root" "$source" "无法创建 Caddy 配置候选副本。"
	install -m 0644 "$source" "$candidate_source" || migration_abort "$root" "$source" "无法创建 Caddyfile 候选副本。"
	install -m 0644 "$SRC_DIR/assets/caddy/abuseguard.caddy" "$candidate_snippet" || migration_abort "$root" "$source" "无法创建 AbuseGuard 片段候选副本。"

	log "正在规范化 AbuseGuard Caddy 配置"
	if ! normalize_caddy_file "$candidate_source"; then
		migration_abort "$root" "$source" "无法格式化 Caddyfile 候选；原 Caddyfile 和站点文件未改动。"
	fi
	for candidate_site in "$candidate_sites"/*.caddy; do
		if ! ensure_site_protected "$candidate_site"; then
			migration_abort "$root" "$source" "无法恢复站点候选的 AbuseGuard 防护；原 Caddyfile 和站点文件未改动。"
		fi
		if ! normalize_caddy_file "$candidate_site"; then
			migration_abort "$root" "$source" "无法格式化站点候选；原 Caddyfile 和站点文件未改动。"
		fi
	done

	if ! bash "$migrator" "$candidate_source" "$out_main" "$out_sites" "$candidate_sites" > "$domains"; then
		migration_abort "$root" "$source" "Caddy 站点无法按 AbuseGuard 标准结构迁移；原 Caddyfile 和站点文件未改动。"
	fi
	if ! normalize_caddy_file "$out_main"; then
		migration_abort "$root" "$source" "无法格式化迁移后的 Caddyfile 候选；原 Caddyfile 和站点文件未改动。"
	fi
	for candidate_site in "$out_sites"/*.caddy; do
		if ! normalize_caddy_file "$candidate_site"; then
			migration_abort "$root" "$source" "无法格式化迁移后的站点候选；原 Caddyfile 和站点文件未改动。"
		fi
	done

	# Add generated sites to the candidate tree before validation, so the exact
	# tree that will be installed is what Caddy validates.
	while IFS= read -r domain; do
		[ -n "$domain" ] || continue
		target="$candidate_sites/$domain.caddy"
		if [ -e "$target" ] || [ -L "$target" ] || ! install -m 0644 "$out_sites/$domain.caddy" "$target"; then
			migration_abort "$root" "$source" "无法写入迁移后的候选站点文件；原 Caddyfile 和站点文件未改动。"
		fi
	done < "$domains"

	# Keep imports such as `common.conf` relative to /etc/caddy while replacing
	# only the canonical sites import with the candidate tree for validation.
	validation="$(mktemp "$CADDY_ETC/.Caddyfile.abuseguard-validate.XXXXXX")" || migration_abort "$root" "$source" "无法创建 Caddy 配置校验文件。"
	if ! awk -v snippet="$SNIPPET" -v staged_snippet="$candidate_snippet" \
		-v canonical="$SITES_DIR/*.caddy" -v staged="$candidate_sites/*.caddy" '
		$1 == "import" && $2 == snippet {
			print "import " staged_snippet
			snippet_replaced = 1
			next
		}
		$1 == "import" && ($2 == canonical || $2 == "sites/*.caddy" || $2 == "./sites/*.caddy") {
			print "import " staged
			sites_replaced = 1
			next
		}
		{ print }
		END {
			if (!sites_replaced) {
				print ""
				print "import " staged
			}
		}
	' "$out_main" > "$validation"; then
		rm -f -- "$validation"
		migration_abort "$root" "$source" "无法生成 Caddy 配置校验候选；原 Caddyfile 和站点文件未改动。"
	fi
	if ! validate_caddyfile "$validation" >/dev/null; then
		rm -f -- "$validation"
		migration_abort "$root" "$source" "迁移后的 Caddy 配置校验失败；原 Caddyfile 和站点文件未改动。"
	fi
	rm -f -- "$validation"

	# Back up every file that the commit may replace.  Non-Caddy files in the
	# sites directory are left in place and are never part of this transaction.
	backup_dir="$root/backup"
	local rollback_failed=0
	install -d -m 0700 "$backup_dir" || migration_abort "$root" "$source" "无法创建 Caddy 回滚备份。"
	site_backup_dir="$backup_dir/sites"
	install -d -m 0700 "$site_backup_dir" || migration_abort "$root" "$source" "无法创建站点回滚备份。"
	if [ -e "$SNIPPET" ] || [ -L "$SNIPPET" ]; then
		snippet_existed=1
		cp -a -- "$SNIPPET" "$backup_dir/abuseguard.caddy" || migration_abort "$root" "$source" "无法备份原 AbuseGuard 片段。"
	fi
	if [ -e "$CADDYFILE" ] || [ -L "$CADDYFILE" ]; then
		cp -a -- "$CADDYFILE" "$backup_dir/Caddyfile" || migration_abort "$root" "$source" "无法备份原 Caddyfile。"
		had_main=1
	fi
	while IFS= read -r -d '' candidate_site; do
		name="$(basename "$candidate_site")"
		target="$SITES_DIR/$name"
		site_candidates+=("$candidate_site")
		site_targets+=("$target")
		if [ -L "$target" ]; then
			migration_abort "$root" "$source" "站点文件是符号链接，无法安全提交迁移：$target"
		fi
		if [ -e "$target" ] || [ -L "$target" ]; then
			site_existed+=(1)
			cp -a -- "$target" "$site_backup_dir/$name" || migration_abort "$root" "$source" "无法备份原站点文件：$target"
		else
			site_existed+=(0)
		fi
	done < <(find "$candidate_sites" -maxdepth 1 -type f -name '*.caddy' -print0)

	if [ "$failed" = 0 ]; then
		if ! install -m 0644 "$candidate_snippet" "$SNIPPET"; then
			failed=1
		fi
	fi
	if [ "$failed" = 0 ]; then
		for ((i = 0; i < ${#site_candidates[@]}; i++)); do
			if ! install -m 0644 "${site_candidates[i]}" "${site_targets[i]}"; then
				failed=1
				break
			fi
		done
	fi
	if [ "$failed" = 0 ] && ! install -m 0644 "$out_main" "$CADDYFILE"; then
		failed=1
	fi

	if [ "$failed" != 0 ]; then
		# Restore the main file and every site touched above, including files
		# from a partially completed site loop.
		rm -f -- "$SNIPPET"
		rm -f -- "$CADDYFILE"
		if [ "$snippet_existed" = 1 ] && ! cp -a -- "$backup_dir/abuseguard.caddy" "$SNIPPET"; then rollback_failed=1; fi
		if [ "$had_main" = 1 ] && ! cp -a -- "$backup_dir/Caddyfile" "$CADDYFILE"; then rollback_failed=1; fi
		for ((i = 0; i < ${#site_targets[@]}; i++)); do
			rm -f -- "${site_targets[i]}"
			if [ "${site_existed[i]}" = 1 ]; then
				if ! cp -a -- "$site_backup_dir/$(basename "${site_targets[i]}")" "${site_targets[i]}"; then rollback_failed=1; fi
			fi
		done
		if [ "$rollback_failed" = 1 ]; then
			[ "$source" = "$CADDYFILE" ] || rm -f -- "$source"
			die "无法完整回滚迁移后的 Caddy 文件；回滚备份保留在 $root。"
		fi
		migration_abort "$root" "$source" "无法安装迁移后的 Caddy 文件；已回滚原 Caddyfile 和站点文件。"
	fi

	while IFS= read -r domain; do
		[ -n "$domain" ] || continue
		log "已迁移受保护站点：$SITES_DIR/$domain.caddy"
		count=$((count + 1))
	done < "$domains"
	[ "$count" = 0 ] || log "已按 AbuseGuard 标准结构迁移 $count 个站点"
	cleanup_temp_tree "$root" || true
	[ "$source" = "$CADDYFILE" ] || rm -f -- "$source"
}
migrate_caddy_sites "$caddy_migration_source"

# Root-side Caddy validation above may create the access log first.  Always
# repair its ownership/mode here without truncating an existing log.
[ -e "$LOG_DIR/abuseguard-access.json" ] || install -m 0640 -o caddy -g caddy /dev/null "$LOG_DIR/abuseguard-access.json"
chown caddy:caddy "$LOG_DIR/abuseguard-access.json"
chmod 0640 "$LOG_DIR/abuseguard-access.json"
else
	setup_nginx_proxy
fi

# Legacy bans and ignoreip were captured before the engine swap (see above).


# --- systemd timers + panel --------------------------------------------------
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.service" /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.timer"   /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.timer"     /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-firewall.service" /etc/systemd/system/
install -m 0755 "$SRC_DIR/abuseguard.sh" "$PANEL_BIN"
# Older releases installed the panel as `abuseguard`. Remove that stale copy
# so `ag` is the only shortcut, but only when the file really is our panel.
if [ -f "$LEGACY_PANEL_BIN" ] && head -n 2 "$LEGACY_PANEL_BIN" | grep -q 'AbuseGuard 控制面板'; then
	rm -f -- "$LEGACY_PANEL_BIN"
	log "已移除旧快捷命令 abuseguard（请改用 ag）"
fi

# --- optional interactive setup ----------------------------------------------
# Ask (y/N, default No) before prompting for each secret, so a plain Enter
# means "don't configure now". Reads from an explicitly-opened /dev/tty so it
# works under `bash <(curl ...)` and `curl | bash`; skips cleanly with no tty
# or when ABUSEGUARD_NONINTERACTIVE=1. Updates always preserve existing keys
# and skip these first-install questions.
if [ "$UPDATE_MODE" = 1 ]; then
	log "更新模式：保留现有 API 密钥，跳过密钥询问"
elif [ -z "${ABUSEGUARD_NONINTERACTIVE:-}" ] && { exec 3</dev/tty; } 2>/dev/null; then
	echo
	log "可选配置（以下两项都可稍后随时用 ag 面板设置）"
	printf '  现在设置 Cloudflare API token 吗？（用于自动签发 TLS 证书）[y/N] '
	IFS= read -r ans <&3 || ans=""
	case "$ans" in
		[yY]|[yY][eE][sS])
			printf '    请粘贴 Cloudflare API token（回车确认）: '
			IFS= read -r cf_token <&3 || cf_token=""
			if [ -n "$cf_token" ]; then
				if [ "$PROXY_MODE" = caddy ]; then
					printf 'CF_API_TOKEN=%s\n' "$cf_token" > "$CADDY_ENV"
					chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
				else
					nginx_save_token "$cf_token" \
						|| die "无法保存 Cloudflare token（$AG_NGINX_CF_CREDENTIALS）；安装未完成。"
				fi
				log "已保存 Cloudflare token"
			else
				log "未输入，跳过 Cloudflare token"
			fi ;;
		*) log "跳过 Cloudflare token" ;;
	esac
	printf '  现在设置 AbuseIPDB API key 吗？（用于自动上报恶意 IP）[y/N] '
	IFS= read -r ans <&3 || ans=""
	case "$ans" in
		[yY]|[yY][eE][sS])
			printf '    请粘贴 AbuseIPDB API key（回车确认）: '
			IFS= read -r -s aipdb_key <&3 || aipdb_key=""
			printf '\n'
			if [ -n "$aipdb_key" ]; then
				printf '%s\n' "$aipdb_key" > "$CONF_DIR/abuseipdb-report.key"
				chown root:abuseguard "$CONF_DIR/abuseipdb-report.key"; chmod 0640 "$CONF_DIR/abuseipdb-report.key"
				log "已保存 AbuseIPDB key"
			else
				log "未输入，跳过 AbuseIPDB key"
			fi ;;
		*) log "跳过 AbuseIPDB key（设置前不会上报）" ;;
	esac
	exec 3<&-
else
	log "非交互运行：跳过密钥询问（稍后用 ag 面板设置）"
fi

# --- validate + enable -------------------------------------------------------
if [ "$PROXY_MODE" = caddy ]; then
	log "正在校验 Caddyfile"
	validate_caddyfile "$CADDYFILE" >/dev/null || die "Caddyfile 校验失败。"
else
	log "正在校验 Nginx 配置"
	nginx_validate || die "Nginx 配置校验失败。"
fi
log "正在校验 fail2ban 配置"
fail2ban-client -t >/dev/null || die "fail2ban 配置校验失败。"
verify_fail2ban_jails config
# All long work (downloads/builds, jail files, prompts) is done while fail2ban
# keeps running. Pause it only for the binary swap, then restart below.
pause_fail2ban_for_upgrade
commit_engine
# The new policy and sync units run `policy-apply`, which only the new engine
# provides. Install and back them up only after the engine swap, so an ordinary
# failure restores a compatible engine+unit+helper triple.
UNIT_ROLLBACK_DIR="$(mktemp -d)" || die "无法创建策略服务回滚目录。"
: > "$UNIT_ROLLBACK_DIR/manifest"
for unit in caddy-abuseguard-policy.service caddy-abuseguard-sync.service; do
	if [ -e "$POLICY_UNIT_DIR/$unit" ]; then
		cp -a -- "$POLICY_UNIT_DIR/$unit" "$UNIT_ROLLBACK_DIR/$unit.present" \
			|| die "无法备份 $POLICY_UNIT_DIR/$unit。"
		printf 'present %s\n' "$unit" >> "$UNIT_ROLLBACK_DIR/manifest"
	else
		printf 'absent %s\n' "$unit" >> "$UNIT_ROLLBACK_DIR/manifest"
	fi
done
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-policy.service" "$POLICY_UNIT_DIR/caddy-abuseguard-policy.service" \
	|| die "无法安装策略服务单元。"
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.service" "$POLICY_UNIT_DIR/caddy-abuseguard-sync.service" \
	|| die "无法安装同步服务单元。"
log "引擎已更新；正在应用新策略"

systemctl daemon-reload
systemctl enable caddy-abuseguard-policy.service >/dev/null 2>&1 \
	|| die "无法启用开机策略恢复（caddy-abuseguard-policy.service）。"
log "正在启用 AbuseGuard 防火墙并设置开机恢复"
"$PANEL_BIN" --firewall-apply || die "防火墙接管失败，安装未完成。请检查上方错误后重试。"
log "正在应用原生白名单/情报策略"
"$ENGINE_BIN" policy-apply || die "原生白名单/情报策略应用失败，安装未完成。请检查上方错误后重试。"
log "正在启用并启动服务"
if [ "$PROXY_MODE" = caddy ]; then
	# Prefer a non-disruptive reload, but restart when the existing Caddy has
	# its admin API disabled and therefore cannot accept `caddy reload`.
	systemctl enable caddy >/dev/null 2>&1 || true
	systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy || die "caddy 启动失败（查看：journalctl -u caddy）"
else
	if systemctl is-active --quiet nginx; then
		nginx_reload || die "Nginx 重载失败（查看：journalctl -u nginx）；安装未完成。"
	else
		systemctl start nginx || die "nginx 启动失败（查看：journalctl -u nginx）"
	fi
	systemctl is-active --quiet nginx || die "nginx 未处于运行状态；安装未完成。"
	# Enable only after a successful start, so a failed install does not leave
	# an autostart policy behind.
	systemctl enable nginx >/dev/null 2>&1 || warn "警告：无法让 nginx 开机自启。"
fi
systemctl enable fail2ban >/dev/null 2>&1 || true
# A reload does not attach newly installed actions to already-running jails.
systemctl restart fail2ban || die "fail2ban 未能正常启动（查看：journalctl -u fail2ban）"
verify_fail2ban_jails running
migrate_legacy_bans || die "旧封禁迁移失败，安装未完成。"
# Re-run against the live daemon: writes/validates ignoreip, reloads if it
# changed, and clears bans that a newly allowlisted source still carries.
"$ENGINE_BIN" policy-apply || die "fail2ban 就绪后应用策略失败，安装未完成。"
# Only now is the cutover usable; before this point a failure restores the old
# engine+config. Reclaim the rollback copy without waiting for the EXIT trap
# (the interactive path execs the panel, which skips EXIT traps).
INSTALL_COMPLETE=1
[ -z "$ENGINE_BACKUP" ] || rm -f -- "$ENGINE_BACKUP"
ENGINE_BACKUP=""
[ -z "$UNIT_ROLLBACK_DIR" ] || rm -rf -- "$UNIT_ROLLBACK_DIR"
UNIT_ROLLBACK_DIR=""
[ -z "$F2B_ROLLBACK_DIR" ] || rm -rf -- "$F2B_ROLLBACK_DIR"
# Only now is the new unit live; drop the legacy helper an older release left
# behind. Keeping it during the swap preserves a bootable old engine+unit pair
# until a failure rollback is no longer possible.
if [ -e "$POLICY_BIN" ]; then
	rm -f -- "$POLICY_BIN" || warn "警告：无法移除旧策略助手 $POLICY_BIN。"
fi
systemctl enable --now caddy-abuseguard-report.timer caddy-abuseguard-sync.timer >/dev/null 2>&1 || true

log "AbuseGuard 安装完成。"
log "已启用 SSH 防护；Web、SSH 和手动封禁共用白名单，并按源 IP 拦截所有端口。"
log "原生白名单/情报策略已应用；外部修改白名单后运行：sudo ag --policy-apply"
if [ "$PROXY_MODE" = caddy ]; then
cat <<EOF

  文件位置：
    Caddyfile:    $CADDYFILE
    白名单:       $CONF_DIR/whitelist
    配置:         $CONF_DIR/config.json
    情报快照:     $CONF_DIR/intel.nft（开机恢复）
    访问日志:     $LOG_DIR/abuseguard-access.json

  在 $SITES_DIR/<域名>.caddy 中添加受保护站点（站点块内放
  'import abuseguard'），然后执行：sudo systemctl reload caddy || sudo systemctl restart caddy

安全提示：Caddy 本身不提供鉴权。凡是你对外暴露的站点，除非自行加鉴权，
否则都是公开的。安装器自带的自检站点只绑定 127.0.0.1。

EOF
else
	nginx_token_state="未设置（添加站点前请在 ag 中设置 Cloudflare token）"
	if nginx_token_is_set; then
		nginx_token_state="已设置（$AG_NGINX_CF_CREDENTIALS，root:root 0600）"
	fi
cat <<EOF

  文件位置：
    Nginx 主配置: $NGINX_HTTP_CONF
    受保护站点:   $NGINX_SITES_AVAILABLE/abuseguard-<域名>.conf
    白名单:       $CONF_DIR/whitelist
    配置:         $CONF_DIR/config.json
    情报快照:     $CONF_DIR/intel.nft（开机恢复）
    访问日志:     $NGINX_ACCESS_LOG
    Cloudflare:   $nginx_token_state

  在 ag 面板中添加受保护站点；证书通过 Cloudflare DNS-01 自动签发。
  手动重载：sudo systemctl reload nginx
  安装器自带的自检站点只绑定 127.0.0.1:8080，不开放 80 端口。

安全提示：Nginx 本身不提供鉴权。凡是你对外暴露的站点，除非自行加鉴权，
否则都是公开的。

EOF
fi

# On an interactive terminal, drop straight into the control panel; otherwise
# just leave the summary above and tell the user how to open it.
if [ "$UPDATE_MODE" = 0 ] && [ -z "${ABUSEGUARD_NONINTERACTIVE:-}" ] && { : </dev/tty; } 2>/dev/null; then
	echo
	log "即将进入控制面板（下次可随时运行：ag）..."
	sleep 1
	exec "$PANEL_BIN" </dev/tty
fi
echo
log "运行 ag 打开控制面板。"
