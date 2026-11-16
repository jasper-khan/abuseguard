#!/usr/bin/env bash
# AbuseGuard Nginx runtime helpers (nginx mode only).
#
# This file is a library: sourcing it only defines functions and default paths.
# It installs nothing, starts nothing and changes no configuration on import.
# The installer sources the source-tree copy; the panel/uninstaller may source
# the installed copy. Tests may override the globals below after sourcing to
# run against an isolated fixture (see local://nginx-runtime-notes.md).
#
# Managed paths:
#   /usr/local/libexec/abuseguard-nginx.sh
#   /etc/nginx/conf.d/abuseguard.conf
#   /etc/nginx/conf.d/zz-abuseguard-selftest.conf
#   /etc/nginx/snippets/abuseguard-cloudflare.conf
#   /etc/nginx/sites-available/abuseguard-<domain>.conf
#   /etc/nginx/sites-enabled/abuseguard-<domain>.conf   (symlink)
#   /var/log/nginx/abuseguard-access.json
#   /etc/logrotate.d/abuseguard-nginx
#   /usr/local/libexec/abuseguard-nginx-deploy
#   /etc/caddy-abuseguard/cloudflare.ini                 (root:root 0600)

: "${NGINX_ETC:=/etc/nginx}"
: "${NGINX_CONFD_DIR:=$NGINX_ETC/conf.d}"
: "${NGINX_SNIPPETS_DIR:=$NGINX_ETC/snippets}"
: "${NGINX_SITES_AVAILABLE:=$NGINX_ETC/sites-available}"
: "${NGINX_SITES_ENABLED:=$NGINX_ETC/sites-enabled}"
: "${NGINX_HTTP_CONF:=$NGINX_CONFD_DIR/abuseguard.conf}"
: "${NGINX_SELFTEST_CONF:=$NGINX_CONFD_DIR/zz-abuseguard-selftest.conf}"
: "${NGINX_CF_TRUST_INCLUDE:=$NGINX_SNIPPETS_DIR/abuseguard-cloudflare.conf}"
: "${NGINX_LOG_DIR:=/var/log/nginx}"
: "${NGINX_ACCESS_LOG:=$NGINX_LOG_DIR/abuseguard-access.json}"
: "${NGINX_LOGROTATE:=/etc/logrotate.d/abuseguard-nginx}"
: "${NGINX_LETSENCRYPT_DIR:=/etc/letsencrypt}"
: "${NGINX_LIBEXEC_DIR:=/usr/local/libexec}"
: "${NGINX_DEPLOY_HOOK:=$NGINX_LIBEXEC_DIR/abuseguard-nginx-deploy}"
: "${NGINX_RUNTIME_PATH:=$NGINX_LIBEXEC_DIR/abuseguard-nginx.sh}"
: "${AG_NGINX_CONF_DIR:=/etc/caddy-abuseguard}"
: "${AG_NGINX_CF_CREDENTIALS:=$AG_NGINX_CONF_DIR/cloudflare.ini}"
: "${NGINX_SELFTEST_PORT:=8080}"
: "${NGINX_BIN:=nginx}"
: "${NGINX_SYSTEMCTL:=systemctl}"
: "${CERTBOT_BIN:=certbot}"
: "${NGINX_CF_LIVE:=1}"
: "${NGINX_CF_CURL:=curl}"
: "${NGINX_CF_V4_URL:=https://www.cloudflare.com/ips-v4}"
: "${NGINX_CF_V6_URL:=https://www.cloudflare.com/ips-v6}"
: "${NGINX_CERTBOT_PROPAGATION_SECONDS:=30}"

_nginx_warn() { printf '\033[1;33m[abuseguard]\033[0m %s\n' "$*" >&2; }
_nginx_err()  { printf '\033[1;31m[abuseguard]\033[0m %s\n' "$*" >&2; }

# Atomically replace a root-owned config file. Temp names never match the
# include globs that Nginx loads (`*.conf` / `sites-enabled/*`).
_nginx_write_file() {
	local path="$1" mode="$2" dir tmp
	dir="$(dirname -- "$path")"
	[ -d "$dir" ] || { _nginx_err "目录不存在：$dir"; return 1; }
	tmp="$(mktemp "$dir/.abuseguard-write.XXXXXX")" || {
		_nginx_err "无法在 $dir 创建临时文件"
		return 1
	}
	if ! cat > "$tmp"; then
		rm -f -- "$tmp"
		_nginx_err "无法写入临时文件：$tmp"
		return 1
	fi
	if ! chmod "$mode" "$tmp" || ! mv -f -- "$tmp" "$path"; then
		rm -f -- "$tmp"
		_nginx_err "无法安装配置：$path"
		return 1
	fi
}

_nginx_copy_exec() {
	local src="$1" dest="$2" dir tmp
	dir="$(dirname -- "$dest")"
	tmp="$(mktemp "$dir/.abuseguard-write.XXXXXX")" || return 1
	if ! cp -f -- "$src" "$tmp" || ! chmod 0755 "$tmp" || ! mv -f -- "$tmp" "$dest"; then
		rm -f -- "$tmp"
		_nginx_err "无法安装程序：$dest"
		return 1
	fi
}

_nginx_domain_valid() {
	local d="$1"
	[ "${#d}" -ge 1 ] && [ "${#d}" -le 235 ] || return 1
	case "$d" in
		*[!a-z0-9.-]*|.*|*.|*..*) return 1 ;;
	esac
	printf '%s' "$d" | grep -qE '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
}

_nginx_upstream_valid() {
	local up="$1" host port label
	case "$up" in
		''|*[[:space:]]*|*[!A-Za-z0-9.:_-]*) return 1 ;;
	esac
	[ "${#up}" -le 253 ] || return 1
	case "$up" in *:*) ;; *) return 1 ;; esac
	host="${up%:*}"
	port="${up##*:}"
	case "$host" in ''|*:*|*[!A-Za-z0-9._-]*|.*|*.|*..*) return 1 ;; esac
	case "$port" in ''|*[!0-9]*) return 1 ;; esac
	[ "$port" -ge 1 ] 2>/dev/null && [ "$port" -le 65535 ] 2>/dev/null || return 1
	local IFS=.
	for label in $host; do
		[ "${#label}" -ge 1 ] && [ "${#label}" -le 63 ] || return 1
		case "$label" in -*|*-) return 1 ;; esac
	done
	return 0
}

_nginx_site_name() { printf 'abuseguard-%s' "$1"; }

_nginx_cert_exists() {
	local live="$NGINX_LETSENCRYPT_DIR/live/abuseguard-$1"
	[ -s "$live/fullchain.pem" ] && [ -s "$live/privkey.pem" ]
}

_nginx_site_upstream() {
	awk '
		/^[[:space:]]*proxy_pass[[:space:]]+http:\/\// {
			sub(/^[[:space:]]*proxy_pass[[:space:]]+http:\/\//, "")
			sub(/[;[:space:]].*$/, "")
			print
			exit
		}
	' "$1" 2>/dev/null
}

# --- public API ---------------------------------------------------------------

nginx_token_is_set() {
	local value
	[ -f "$AG_NGINX_CF_CREDENTIALS" ] && [ ! -L "$AG_NGINX_CF_CREDENTIALS" ] || return 1
	value="$(sed -n 's/^[[:space:]]*dns_cloudflare_api_token[[:space:]]*=[[:space:]]*//p' \
		"$AG_NGINX_CF_CREDENTIALS" 2>/dev/null | head -n 1)"
	[ -n "$value" ]
}

nginx_save_token() {
	local token="${1-}" dir tmp
	if [ -z "$token" ]; then
		_nginx_err "Cloudflare API Token 不能为空。"
		return 1
	fi
	case "$token" in
		*[[:cntrl:]]*|*[[:space:]]*)
			_nginx_err "Cloudflare API Token 含有空白或控制字符，未保存。"
			return 1
			;;
	esac
	[ "${#token}" -le 4096 ] || { _nginx_err "Cloudflare API Token 过长，未保存。"; return 1; }
	dir="$(dirname -- "$AG_NGINX_CF_CREDENTIALS")"
	install -d -m 0750 "$dir" || { _nginx_err "无法创建目录：$dir"; return 1; }
	tmp="$(umask 077; mktemp "$dir/.cloudflare.ini.XXXXXX")" || {
		_nginx_err "无法在 $dir 创建临时凭据文件"
		return 1
	}
	if ! printf 'dns_cloudflare_api_token = %s\n' "$token" > "$tmp"; then
		rm -f -- "$tmp"
		_nginx_err "无法写入 Cloudflare 凭据，未保存。"
		return 1
	fi
	if [ "$(id -u)" = 0 ]; then
		if ! chown root:root "$tmp"; then
			rm -f -- "$tmp"
			_nginx_err "无法将 Cloudflare 凭据设为 root:root，未保存。"
			return 1
		fi
	fi
	if ! chmod 0600 "$tmp" || ! mv -f -- "$tmp" "$AG_NGINX_CF_CREDENTIALS"; then
		rm -f -- "$tmp"
		_nginx_err "无法安装 Cloudflare 凭据，未保存。"
		return 1
	fi
	return 0
}

nginx_sites_lines() {
	local f name up
	for f in "$NGINX_SITES_ENABLED"/abuseguard-*.conf; do
		[ -e "$f" ] || continue
		name="${f##*/}"
		name="${name#abuseguard-}"
		name="${name%.conf}"
		_nginx_domain_valid "$name" || continue
		up="$(_nginx_site_upstream "$f")"
		printf '%s\t%s\n' "$name" "${up:-?}"
	done
}

nginx_validate() {
	local out
	if ! out="$("$NGINX_BIN" -t 2>&1)"; then
		_nginx_err "Nginx 配置校验失败（$NGINX_BIN -t）："
		printf '%s\n' "$out" >&2
		return 1
	fi
	return 0
}

# Reload Nginx and prove that a new worker generation actually took over.
# `systemctl reload` returns before the master's new workers bind; a failed
# bind (occupied port, unavailable address family) keeps the old workers and
# the old config while the unit still reports success. Success therefore
# requires a new worker PID (an old draining worker exiting must not count),
# and unobservable state is a failure; this never restarts the service. POSIX
# sh because nginx_install_assets embeds this function into the standalone
# deploy hook, which must keep working after a conservative uninstall removes
# this helper. $1 is the systemctl command.
_nginx_reload_confirmed() {
	_nginx_ctl="${1:-systemctl}"
	_nginx_master="$("$_nginx_ctl" show -p MainPID --value nginx 2>/dev/null || true)"
	case "$_nginx_master" in
	''|0|1|*[!0-9]*)
		printf 'cannot observe the running Nginx master (MainPID=%s)\n' "${_nginx_master:-unknown}" >&2
		return 1
		;;
	esac
	_nginx_before="$(pgrep -P "$_nginx_master" 2>/dev/null | sort -n | tr '\n' ' ' || true)"
	if [ -z "$_nginx_before" ]; then
		printf 'cannot observe Nginx workers under master PID %s\n' "$_nginx_master" >&2
		return 1
	fi
	if ! "$_nginx_ctl" reload nginx; then
		printf 'systemctl reload nginx failed\n' >&2
		return 1
	fi
	_nginx_active="$("$_nginx_ctl" is-active nginx 2>/dev/null || true)"
	if [ "$_nginx_active" != active ]; then
		printf 'nginx is not active after reload (state: %s)\n' "${_nginx_active:-unknown}" >&2
		return 1
	fi
	_nginx_i=0
	while [ "$_nginx_i" -lt 50 ]; do
		_nginx_after="$(pgrep -P "$_nginx_master" 2>/dev/null | sort -n | tr '\n' ' ' || true)"
		if [ -n "$_nginx_after" ]; then
			for _nginx_pid in $_nginx_after; do
				case " $_nginx_before " in
					*" $_nginx_pid "*) ;;
					*) return 0 ;;
				esac
			done
		fi
		_nginx_i=$((_nginx_i + 1))
		sleep 0.2
	done
	printf 'no new Nginx worker generation within 10s; the reload did not take effect\n' >&2
	return 1
}

nginx_reload() {
	local out
	if out="$(_nginx_reload_confirmed "$NGINX_SYSTEMCTL" 2>&1)"; then
		return 0
	fi
	_nginx_err "Nginx 重载未生效或无法确认：${out:-未知原因}。未自动重启服务。"
	return 1
}

# Validate the complete loaded configuration AND confirm the candidate file is
# actually part of what Nginx loaded, so a missing include cannot pass silently.
_nginx_candidate_loaded() {
	local domain="$1" enabled out
	enabled="$NGINX_SITES_ENABLED/$(_nginx_site_name "$domain").conf"
	if ! out="$("$NGINX_BIN" -T 2>&1)"; then
		_nginx_err "候选 Nginx 配置校验失败："
		printf '%s\n' "$out" >&2
		return 1
	fi
	case "$out" in
		*"configuration file $enabled:"*) return 0 ;;
	esac
	_nginx_err "候选站点未被 Nginx 加载（$enabled 不在 nginx -T 输出中）。请检查 $NGINX_ETC/nginx.conf 是否包含 sites-enabled。"
	return 1
}

_nginx_issue_cert() {
	local domain="$1" out
	if [ ! -x "$NGINX_DEPLOY_HOOK" ]; then
		_nginx_err "证书部署钩子缺失或不可执行：$NGINX_DEPLOY_HOOK。请重新运行安装器修复。"
		return 1
	fi
	out="$(mktemp "${TMPDIR:-/tmp}/abuseguard-certbot.XXXXXX")" || {
		_nginx_err "无法创建 Certbot 输出临时文件。"
		return 1
	}
	if ! "$CERTBOT_BIN" certonly \
		--cert-name "$(_nginx_site_name "$domain")" \
		--dns-cloudflare \
		--dns-cloudflare-credentials "$AG_NGINX_CF_CREDENTIALS" \
		--dns-cloudflare-propagation-seconds "$NGINX_CERTBOT_PROPAGATION_SECONDS" \
		-d "$domain" \
		--non-interactive --agree-tos --register-unsafely-without-email \
		--deploy-hook "$NGINX_DEPLOY_HOOK" >"$out" 2>&1; then
		_nginx_err "站点 $domain 的 Cloudflare DNS-01 证书签发失败。请检查 Token 的 Zone/DNS 编辑权限、域名是否在该 Cloudflare 账户下以及 DNS 生效情况。"
		if [ -s "$out" ]; then
			grep -iE 'error|failed|unauthorized|invalid|timed out|nxdomain|forbidden' "$out" 2>/dev/null \
				| tail -n 5 | sed 's/^/    /' >&2 || true
		fi
		rm -f -- "$out"
		return 1
	fi
	rm -f -- "$out"
	if ! _nginx_cert_exists "$domain"; then
		_nginx_err "Certbot 报告成功，但未找到 abuseguard-$domain 证书文件。"
		return 1
	fi
	return 0
}

nginx_add_site() {
	local domain upstream name available enabled tmp sni_re
	if [ "$#" -ne 2 ]; then
		_nginx_err "用法：nginx_add_site <域名> <主机或IP:端口>"
		return 2
	fi
	domain="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	upstream="$2"
	if ! _nginx_domain_valid "$domain"; then
		_nginx_err "域名格式无效（只接受字母、数字、点、连字符组成的域名）。"
		return 1
	fi
	if ! _nginx_upstream_valid "$upstream"; then
		_nginx_err "上游格式无效（只接受 host/IP:port，不支持 scheme、路径或通配符）。"
		return 1
	fi
	if ! nginx_token_is_set; then
		_nginx_err "尚未配置 Cloudflare API Token（$AG_NGINX_CF_CREDENTIALS）。Nginx 模式只使用 DNS-01，不会回退到 HTTP-01。"
		return 1
	fi
	if [ ! -x "$NGINX_DEPLOY_HOOK" ]; then
		_nginx_err "证书部署钩子缺失或不可执行：$NGINX_DEPLOY_HOOK。请重新运行安装器修复。"
		return 1
	fi
	name="$(_nginx_site_name "$domain")"
	available="$NGINX_SITES_AVAILABLE/$name.conf"
	enabled="$NGINX_SITES_ENABLED/$name.conf"
	if [ -e "$available" ] || [ -L "$available" ] || [ -e "$enabled" ] || [ -L "$enabled" ]; then
		_nginx_err "站点已存在：$domain"
		return 1
	fi
	install -d -m 0755 "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED" \
		"$NGINX_SNIPPETS_DIR" "$NGINX_LOG_DIR" || {
		_nginx_err "无法创建 Nginx 站点目录。"
		return 1
	}
	if [ ! -f "$NGINX_HTTP_CONF" ] || [ ! -f "$NGINX_CF_TRUST_INCLUDE" ]; then
		_nginx_err "Nginx 项目配置不完整（$NGINX_HTTP_CONF 或 $NGINX_CF_TRUST_INCLUDE 缺失）。请重新运行安装器修复后再添加站点。"
		return 1
	fi
	if ! _nginx_cert_exists "$domain"; then
		_nginx_issue_cert "$domain" || return 1
	fi
	tmp="$(mktemp "$NGINX_SITES_AVAILABLE/.$name.XXXXXX")" || {
		_nginx_err "无法在 $NGINX_SITES_AVAILABLE 创建临时文件。"
		return 1
	}
	if ! {
		printf 'server {\n'
		printf '    listen 443 ssl http2;\n'
		printf '    listen [::]:443 ssl http2;\n'
		printf '    server_name %s;\n' "$domain"
		printf '    ssl_certificate "%s/live/%s/fullchain.pem";\n' "$NGINX_LETSENCRYPT_DIR" "$name"
		printf '    ssl_certificate_key "%s/live/%s/privkey.pem";\n' "$NGINX_LETSENCRYPT_DIR" "$name"
		printf '    ssl_protocols TLSv1.2 TLSv1.3;\n'
		printf '    include "%s";\n' "$NGINX_CF_TRUST_INCLUDE"
		printf '    access_log "%s" abuseguard_json;\n' "$NGINX_ACCESS_LOG"
		printf '    client_max_body_size 0;\n'
		printf '    # Caddy returns 404 for a Host it does not serve; the first site\n'
		printf '    # becomes the default vhost, so reject unknown Hosts/SNI here\n'
		printf '    # instead of proxying them to this site upstream. RFC 6066 makes\n'
		printf '    # SNI case-insensitive while $ssl_server_name keeps client case.\n'
		printf '    if ($http_host = "") {\n'
		printf '        return 404;\n'
		printf '    }\n'
		printf '    if ($host != %s) {\n' "$domain"
		printf '        return 404;\n'
		printf '    }\n'
		sni_re="$(printf '%s' "$domain" | sed 's/\./\\./g')"
		printf '    if ($ssl_server_name !~* ^%s$) {\n' "$sni_re"
		printf '        return 404;\n'
		printf '    }\n'
		printf '    location / {\n'
		printf '        proxy_pass http://%s;\n' "$upstream"
		printf '        proxy_http_version 1.1;\n'
		printf '        # Caddy streams and keeps idle upgraded/slow responses open;\n'
		printf '        # Nginx defaults would buffer SSE and cut WS at 60 idle seconds.\n'
		printf '        proxy_buffering off;\n'
		printf '        proxy_read_timeout 1h;\n'
		printf '        proxy_set_header Upgrade $http_upgrade;\n'
		printf '        proxy_set_header Connection $abuseguard_connection_upgrade;\n'
		printf '        proxy_set_header Host $http_host;\n'
		printf '        proxy_set_header X-Real-IP $remote_addr;\n'
		printf '        proxy_set_header X-Forwarded-For $remote_addr;\n'
		printf '        proxy_set_header X-Forwarded-Proto $scheme;\n'
		printf '        proxy_set_header X-Forwarded-Host $http_host;\n'
		printf '    }\n'
		printf '}\n'
	} > "$tmp"; then
		rm -f -- "$tmp"
		_nginx_err "无法写入站点配置，未启用站点。"
		return 1
	fi
	if ! chmod 0644 "$tmp" || ! mv -f -- "$tmp" "$available"; then
		rm -f -- "$tmp" "$available"
		_nginx_err "无法安装站点配置，未启用站点。"
		return 1
	fi
	if ! ln -s -- "$available" "$enabled"; then
		rm -f -- "$available"
		_nginx_err "无法启用站点（symbolic link 创建失败），已回滚。"
		return 1
	fi
	if ! _nginx_candidate_loaded "$domain"; then
		rm -f -- "$enabled" "$available"
		_nginx_err "站点 $domain 未启用：完整配置校验失败，已回滚（证书材料保留）。"
		return 1
	fi
	if ! nginx_reload; then
		rm -f -- "$enabled" "$available"
		if nginx_validate; then
			nginx_reload >/dev/null 2>&1 || _nginx_err "回滚后 Nginx 仍未能重载旧配置，请检查服务状态。"
		else
			_nginx_err "回滚后现有 Nginx 配置未通过校验，请检查服务状态。"
		fi
		_nginx_err "站点 $domain 未启用：Nginx 重载失败，已回滚（证书材料保留）。"
		return 1
	fi
	printf '已添加站点 %s → %s（Nginx 已重载）\n' "$domain" "$upstream"
}

nginx_delete_site() {
	local domain name available enabled removed=0 restored=0
	if [ "$#" -ne 1 ]; then
		_nginx_err "用法：nginx_delete_site <域名>"
		return 2
	fi
	domain="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
	if ! _nginx_domain_valid "$domain"; then
		_nginx_err "域名格式无效（只接受字母、数字、点、连字符组成的域名）。"
		return 1
	fi
	name="$(_nginx_site_name "$domain")"
	available="$NGINX_SITES_AVAILABLE/$name.conf"
	enabled="$NGINX_SITES_ENABLED/$name.conf"
	if [ -e "$enabled" ] && [ ! -L "$enabled" ]; then
		_nginx_err "启用目录中的 $enabled 不是符号链接，拒绝自动删除（请人工检查）。"
		return 1
	fi
	if [ -L "$enabled" ]; then
		rm -f -- "$enabled" || { _nginx_err "无法停用站点：$enabled"; return 1; }
		removed=1
	fi
	if [ "$removed" = 0 ] && [ ! -e "$available" ] && [ ! -L "$available" ]; then
		_nginx_err "未找到受管站点：$domain"
		return 1
	fi
	if [ "$removed" = 1 ]; then
		if ! nginx_validate; then
			if [ -e "$available" ]; then
				if ln -s -- "$available" "$enabled"; then restored=1; fi
			fi
			if [ "$restored" = 1 ]; then
				_nginx_err "删除 $domain 失败：剩余配置校验未通过，已恢复启用状态。"
			else
				_nginx_err "删除 $domain 失败：剩余配置校验未通过，且未能恢复启用链接，请人工检查 $enabled。"
			fi
			return 1
		fi
		if ! nginx_reload; then
			if [ -e "$available" ]; then
				if ln -s -- "$available" "$enabled"; then restored=1; fi
			fi
			if [ "$restored" = 1 ]; then
				nginx_reload >/dev/null 2>&1 || _nginx_err "恢复 $domain 后 Nginx 未能重载，请检查服务状态。"
				_nginx_err "删除 $domain 失败：Nginx 重载失败，已恢复启用状态。"
			else
				_nginx_err "删除 $domain 失败：Nginx 重载失败，且未能恢复启用链接，请人工检查 $enabled。"
			fi
			return 1
		fi
	fi
	if [ -e "$available" ] || [ -L "$available" ]; then
		if ! rm -f -- "$available"; then
			_nginx_err "站点 $domain 已停用，但配置文件删除失败：$available"
			return 1
		fi
	fi
	printf '已删除站点 %s（证书 abuseguard-%s 保留，不会撤销或删除其他 lineage）\n' "$domain" "$domain"
}

nginx_certificate_status() {
	local domain upstream file end day status
	while IFS=$'\t' read -r domain upstream; do
		[ -n "$domain" ] || continue
		file="$NGINX_LETSENCRYPT_DIR/live/abuseguard-$domain/fullchain.pem"
		if ! _nginx_cert_exists "$domain" || ! command -v openssl >/dev/null 2>&1; then
			printf '%s\t\tmissing\n' "$domain"
			continue
		fi
		if ! openssl x509 -in "$file" -noout >/dev/null 2>&1; then
			printf '%s\t\tmissing\n' "$domain"
			continue
		fi
		if ! openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1; then
			status=expired
		elif ! openssl x509 -in "$file" -noout -checkend 2592000 >/dev/null 2>&1; then
			status=expiring
		else
			status=valid
		fi
		end="$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed -n 's/^notAfter=//p' || true)"
		day="$(date -u -d "$end" +%Y-%m-%d 2>/dev/null || true)"
		[ -n "$day" ] || day="$end"
		printf '%s\t%s\t%s\n' "$domain" "$day" "$status"
	done < <(nginx_sites_lines)
}

_nginx_cf_valid_cidr() {
	local cidr="$1"
	case "$cidr" in
		*/0|*[!0-9a-fA-F:./]*) return 1 ;;
	esac
	[ "${#cidr}" -le 49 ] || return 1
	case "$cidr" in
		*.*/*)
			printf '%s' "$cidr" | grep -qE '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[12]?[0-9])$'
			;;
		*:*/*)
			printf '%s' "$cidr" | grep -qE '^[0-9a-fA-F:]+/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$'
			;;
		*) return 1 ;;
	esac
}

_nginx_cf_filter() {
	local line clean
	while IFS= read -r line || [ -n "$line" ]; do
		line="${line%%#*}"
		line="${line%$'\r'}"
		clean="$(printf '%s' "$line" | tr -d '[:space:]')"
		[ -n "$clean" ] || continue
		_nginx_cf_valid_cidr "$clean" || continue
		printf '%s\n' "$clean"
	done | awk '!seen[$0]++ { print; if (++n >= 64) exit }'
}

_nginx_cf_ranges() {
	local fallback="$1" live=""
	if [ "$NGINX_CF_LIVE" = 1 ] && command -v "$NGINX_CF_CURL" >/dev/null 2>&1; then
		live="$("$NGINX_CF_CURL" -fsSL --connect-timeout 5 --max-time 8 "$NGINX_CF_V4_URL" 2>/dev/null || true)"
		live+=$'\n'"$("$NGINX_CF_CURL" -fsSL --connect-timeout 5 --max-time 8 "$NGINX_CF_V6_URL" 2>/dev/null || true)"
	fi
	live="$(printf '%s\n' "$live" | _nginx_cf_filter || true)"
	if [ -n "$live" ]; then
		printf '%s\n' "$live"
		return 0
	fi
	if [ -f "$fallback" ]; then
		live="$(_nginx_cf_filter < "$fallback" || true)"
		if [ -n "$live" ]; then
			_nginx_warn "未能实时获取 Cloudflare IP 段，已使用内置快照：$fallback"
			printf '%s\n' "$live"
			return 0
		fi
	fi
	_nginx_warn "未能获取有效的 Cloudflare IP 段；CF-Connecting-IP 将不被信任（不会信任任意来源）。请稍后重新运行安装器或人工核对 $NGINX_CF_TRUST_INCLUDE。"
	return 0
}

nginx_install_assets() {
	local src="${1-}" fallback ranges cidr
	if [ -z "$src" ] || [ ! -d "$src" ]; then
		_nginx_err "用法：nginx_install_assets <源码根目录>"
		return 2
	fi
	if [ ! -f "$src/assets/nginx/runtime.sh" ]; then
		_nginx_err "安装源缺少 assets/nginx/runtime.sh：$src"
		return 1
	fi
	install -d -m 0755 "$NGINX_CONFD_DIR" "$NGINX_SNIPPETS_DIR" \
		"$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED" \
		"$NGINX_LOG_DIR" "$NGINX_LIBEXEC_DIR" "$(dirname -- "$NGINX_LOGROTATE")" || {
		_nginx_err "无法创建 Nginx/日志目录。"
		return 1
	}

	_nginx_write_file "$NGINX_HTTP_CONF" 0644 <<'EOF' || return 1
# AbuseGuard HTTP-level config for Nginx (managed by AbuseGuard).
# Reinstalling rewrites this file; do not put unrelated config here.

map $http_upgrade $abuseguard_connection_upgrade {
    default upgrade;
    ''      close;
}

# Only these request paths are tagged as probes. Caddy matches its probe
# matcher case-insensitively, so this map must be case-insensitive too.
map $uri $abuseguard_probe {
    ~*^/(?:\.env|\.git|phpmyadmin|vendor/phpunit|cgi-bin)(?:/|$)  web-probe;
    default                                                     "";
}

# Privacy-trimmed JSON access log consumed by the unchanged fail2ban filters.
# No URI, query, headers, body, host or forwarded identity is logged.
log_format abuseguard_json escape=json
    '{"ts":$msec,"client_ip":"$remote_addr","proto":"$server_protocol",'
    '"caddy_abuseguard_site":"protected","caddy_abuseguard_probe":"$abuseguard_probe"}';
EOF

	fallback="$src/assets/caddy/cloudflare-ips.fallback"
	ranges="$(_nginx_cf_ranges "$fallback")"
	{
		printf '%s\n' "# AbuseGuard: trust CF-Connecting-IP only from validated Cloudflare edge ranges."
		printf '%s\n' "# Generated by nginx_install_assets; do not add arbitrary sources here."
		if [ -n "$ranges" ]; then
			while IFS= read -r cidr; do
				[ -n "$cidr" ] && printf 'set_real_ip_from %s;\n' "$cidr"
			done <<< "$ranges"
		else
			printf '%s\n' "# No valid ranges were available; real_ip_header is ignored without set_real_ip_from."
		fi
		printf 'real_ip_header CF-Connecting-IP;\n'
		printf 'real_ip_recursive off;\n'
	} | _nginx_write_file "$NGINX_CF_TRUST_INCLUDE" 0644 || return 1

	_nginx_write_file "$NGINX_SELFTEST_CONF" 0644 <<EOF || return 1
# AbuseGuard loopback-only selftest (managed). Not reachable publicly.
server {
    listen 127.0.0.1:$NGINX_SELFTEST_PORT;
    server_name _;
    access_log "$NGINX_ACCESS_LOG" abuseguard_json;
    location = / {
        default_type text/plain;
        return 200 "abuseguard test ok";
    }
    location / {
        return 404;
    }
}
EOF

	_nginx_write_file "$NGINX_LOGROTATE" 0644 <<EOF || return 1
# AbuseGuard managed log rotation for the privacy-trimmed Nginx access log.
$NGINX_ACCESS_LOG {
    daily
    rotate 7
    maxsize 100M
    missingok
    notifempty
    compress
    delaycompress
    create 0640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}
EOF

	declare -F _nginx_reload_confirmed >/dev/null 2>&1 || {
		_nginx_err "内部错误：重载确认函数未定义，拒绝生成部署钩子。"
		return 1
	}
	{
		printf '#!/bin/sh\n'
		printf '# AbuseGuard Certbot deploy hook (managed). Survives conservative\n'
		printf '# uninstall so renewals keep reloading a live Nginx; it never sources\n'
		printf '# the runtime helper. Only a validated, applied reload counts as success.\n'
		printf 'set -u\n'
		printf 'if ! nginx -t; then\n'
		printf '    echo "AbuseGuard: nginx config invalid after certificate deployment; not reloading." >&2\n'
		printf '    exit 1\n'
		printf 'fi\n'
		declare -f _nginx_reload_confirmed
		printf 'if ! _nginx_reload_confirmed systemctl; then\n'
		printf '    echo "AbuseGuard: nginx reload was not confirmed; the renewed certificate may not be loaded." >&2\n'
		printf '    exit 1\n'
		printf 'fi\n'
	} | _nginx_write_file "$NGINX_DEPLOY_HOOK" 0755 || return 1

	if [ ! -e "$NGINX_ACCESS_LOG" ]; then
		if ! install -m 0640 -o www-data -g adm /dev/null "$NGINX_ACCESS_LOG" 2>/dev/null; then
			install -m 0640 /dev/null "$NGINX_ACCESS_LOG" || {
				_nginx_err "无法创建访问日志：$NGINX_ACCESS_LOG"
				return 1
			}
		fi
	else
		chmod 0640 "$NGINX_ACCESS_LOG" 2>/dev/null || true
		if [ "$(id -u)" = 0 ]; then
			chown www-data:adm "$NGINX_ACCESS_LOG" 2>/dev/null || true
		fi
	fi

	_nginx_copy_exec "$src/assets/nginx/runtime.sh" "$NGINX_RUNTIME_PATH" || return 1
	return 0
}
