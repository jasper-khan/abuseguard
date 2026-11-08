#!/usr/bin/env bash
# AbuseGuard 控制面板。运行： ag
set -uo pipefail

CONF_DIR=/etc/caddy-abuseguard
CONFIG="$CONF_DIR/config.json"
WHITELIST="$CONF_DIR/whitelist"
KEYFILE="$CONF_DIR/abuseipdb-report.key"
ENGINE=/usr/local/libexec/caddy-abuseguard
CADDY=/usr/local/bin/caddy
CADDY_ENV=/etc/caddy/.env
CADDYFILE=/etc/caddy/Caddyfile
SITES_DIR=/etc/caddy/sites
STATE_DIR=/var/lib/caddy-abuseguard
INTEL="$STATE_DIR/intel.txt"
JAILS="caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd sshd-intel"
PANEL_REFRESH_SECONDS=1800
FIREWALL_FILE="$CONF_DIR/firewall.nft"
FIREWALL_SERVICE=caddy-abuseguard-firewall.service
SSHD_MAIN=/etc/ssh/sshd_config
SSHD_DROPIN_DIR=/etc/ssh/sshd_config.d
SSHD_DROPIN="$SSHD_DROPIN_DIR/99-abuseguard-port.conf"
SSHD_AUTH_DROPIN="$SSHD_DROPIN_DIR/00-abuseguard-auth.conf"
SSHD_AUTH_DROPIN_OLD="$SSHD_DROPIN_DIR/99-abuseguard-auth.conf"
SSH_ROOT_HOME=/root/.ssh
SSH_AUTH_KEYS="$SSH_ROOT_HOME/authorized_keys"
SSH_REPORT_JAIL=/etc/fail2ban/jail.d/zz-caddy-abuseguard-report.local
REPO_FILE="$CONF_DIR/repo"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-$( [ -f "$REPO_FILE" ] && cat "$REPO_FILE" || echo jasper-khan/abuseguard )}"

# GitHub download resiliency for the update/uninstall fetches (see install.sh).
#   ABUSEGUARD_MIRROR unset -> direct first, then auto proxy-chain fallback
#   ABUSEGUARD_MIRROR=cn    -> straight to the proxy chain
#   ABUSEGUARD_MIRROR=<p>/  -> force that one prefix
# The update/uninstall URLs carry ?v=<epoch> so a mirror cannot serve a
# stale cached script (GitHub ignores the query; mirrors key on full URL).
ABUSEGUARD_MIRROR="${ABUSEGUARD_MIRROR:-}"
AG_GH_MIRRORS="https://gh-proxy.com/ https://gh.ddlc.top/ https://ghproxy.net/ https://ghfast.top/"
AG_CURL="curl -fsL --connect-timeout 10 --speed-limit 102400 --speed-time 10 --max-time 120"
gh_fetch() {  # URL OUTFILE — direct then mirror chain, quietly
	local url="$1" out="$2" pfx
	case "$ABUSEGUARD_MIRROR" in
		""|0|off|no)
			$AG_CURL -o "$out" "$url" 2>/dev/null && return 0
			for pfx in $AG_GH_MIRRORS; do $AG_CURL -o "$out" "$pfx$url" 2>/dev/null && return 0; done
			return 1 ;;
		cn|1|yes|on)
			for pfx in $AG_GH_MIRRORS; do $AG_CURL -o "$out" "$pfx$url" 2>/dev/null && return 0; done
			return 1 ;;
		*) $AG_CURL -o "$out" "$ABUSEGUARD_MIRROR$url" 2>/dev/null ;;
	esac
}

validate_caddyfile() {
	local config="$1" cf_token=""
	[ ! -f "$CADDY_ENV" ] || cf_token="$(sed -n 's/^CF_API_TOKEN=//p' "$CADDY_ENV" | head -n 1)"
	CF_API_TOKEN="$cf_token" "$CADDY" validate --config "$config" --adapter caddyfile
}

# 普通配置变更优先 reload；reload 不可用时回退 restart，并把真实结果返回给调用方。
caddy_reload_or_restart() {
	systemctl reload caddy >/dev/null 2>&1 && return 0
	systemctl restart caddy >/dev/null 2>&1
}

# token 存在主进程环境里，必须重启并确认服务实际处于 active。
caddy_restart_active() {
	systemctl restart caddy >/dev/null 2>&1 || return 1
	[ "$(systemctl is-active caddy 2>/dev/null)" = active ]
}

# 辅助文字跟随终端默认前景色，避免固定亮灰色在浅色主题下难以辨认。
C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_B=$'\033[1;36m'; C_D=$'\033[22;39m'; C_H=$'\033[1m'; C_0=$'\033[0m'
PANEL_WIDTH=76
pause() { echo; read -r -p "按回车继续..." _; }
svc_state() { systemctl is-active "$1" 2>/dev/null || echo inactive; }

panel_sep() {
	local fill
	printf -v fill '%*s' "$((PANEL_WIDTH - 4))" ''
	printf '  %s\n' "${fill// /=}"
}

# 长文本按终端列宽换行：汉字和全角标点占两列，ANSI 颜色不占列。
panel_row() {
	local LC_ALL=C.UTF-8 text="$1" line='' color='' used=0 char size seq
	local limit=$((PANEL_WIDTH - 4)) sgr=$'\033''\[[0-9;]*m'
	while [ -n "$text" ]; do
		if [[ "$text" =~ ^($sgr) ]]; then
			seq="${BASH_REMATCH[1]}"; line+="$seq"; text="${text:${#seq}}"
			color="$seq"; [ "$seq" != "$C_0" ] || color=''
			continue
		fi
		char="${text:0:1}"; text="${text:1}"
		case "$char" in [㐀-鿿　-〿！-～]) size=2 ;; *) size=1 ;; esac
		if (( used + size > limit )) || [ "$char" = $'\n' ]; then
			printf '  %s%s\n' "$line" "$C_0"
			line="$color"; used=0
			[ "$char" != $'\n' ] || continue
		fi
		line+="$char"; used=$((used + size))
	done
	printf '  %s%s\n' "$line" "$C_0"
}

# 按显示列宽补齐单元格，汉字与全角标点占两列，ANSI 颜色不占列。
panel_width() {
	local LC_ALL=C.UTF-8 text="$1" width=0 char size seq
	local sgr=$'\033''\[[0-9;]*m'
	while [ -n "$text" ]; do
		if [[ "$text" =~ ^($sgr) ]]; then
			seq="${BASH_REMATCH[1]}"; text="${text:${#seq}}"; continue
		fi
		char="${text:0:1}"; text="${text:1}"
		case "$char" in [㐀-鿿　-〿！-～]) size=2 ;; *) size=1 ;; esac
		width=$((width + size))
	done
	printf '%s' "$width"
}

panel_pad() {
	local text="$1" target="$2" width pad
	width=$(panel_width "$text")
	width=$((target - width)); [ "$width" -gt 0 ] || width=0
	printf -v pad '%*s' "$width" ''
	printf '%s%s' "$text" "$pad"
}

thousands() {
	local n="$1" out=''
	case "$n" in '' | *[!0-9]*) printf '%s' "$n"; return ;; esac
	while [ "${#n}" -gt 3 ]; do
		out=",${n: -3}${out}"
		n="${n:0:${#n}-3}"
	done
	printf '%s%s' "$n" "$out"
}

panel_center() {
	local width pad
	width=$(panel_width "$1")
	pad=$(((PANEL_WIDTH - 4 - width) / 2)); [ "$pad" -gt 0 ] || pad=0
	printf -v pad '%*s' "$pad" ''
	printf '  %s%s\n' "$pad" "$1"
}

panel_start() {
	clear 2>/dev/null || true
	panel_sep
	panel_center "${C_H}$1${C_0}"
	panel_sep
}

panel_pause() {
	panel_sep
	read -r -p "  按回车返回..." _
}

panel_title() { panel_start "$1"; echo; }
panel_kv() { panel_row " $(panel_pad "$1" 8) : $2"; }
panel_option() { panel_row " $1. $2"; }
panel_pair() { panel_option "$1" "$2"; panel_option "$3" "$4"; }
panel_footer() { panel_option 0 "$1"; panel_sep; }

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

# 情报最后同步距今小时数（无 meta 或解析失败则回空）
intel_age_h() {
	local meta="$STATE_DIR/intel-last-sync.txt" gen ts now
	[ -f "$meta" ] || { echo ""; return; }
	gen="$(jq -r '.generated_at // empty' "$meta" 2>/dev/null)"
	[ -n "$gen" ] || { echo ""; return; }
	ts="$(date -d "$gen" +%s 2>/dev/null)" || { echo ""; return; }
	now="$(date +%s)"
	echo $(( (now - ts) / 3600 ))
}

header() {
	local caddy f2b intel banned rep age version ssh_ports sites
	local firewall_ok=0 issue_text='' protect_value report_value intel_note
	caddy="$(svc_state caddy)"; f2b="$(svc_state fail2ban)"
	intel="$( [ -f "$INTEL" ] && wc -l < "$INTEL" | tr -d ' ' || echo 0 )"
	banned="$(count_banned)"; rep="$(reporting_state)"
	ssh_ports="$(ssh_current_ports)"
	[ -n "$ssh_ports" ] || ssh_ports="?"
	ssh_ports="$(printf '%s' "$ssh_ports" | tr '\n' ' ')"
	ssh_ports="${ssh_ports% }"
	version="$("$ENGINE" version 2>/dev/null | awk 'NR == 1 { print $2 }')"
	[ -n "$version" ] || version="?"
	sites="$(sites_lines | wc -l | tr -d ' ')"
	if firewall_running; then firewall_ok=1; fi

	if [ "$caddy" != active ]; then issue_text='Caddy 未运行'; fi
	if [ "$f2b" != active ]; then
		[ -z "$issue_text" ] || issue_text+=' · '
		issue_text+='Fail2Ban 未运行'
	fi
	if [ "$firewall_ok" = 0 ]; then
		[ -z "$issue_text" ] || issue_text+=' · '
		issue_text+='防火墙未就绪'
	fi
	if [ -z "$issue_text" ]; then
		protect_value="${C_G}正常${C_0}（Caddy / Fail2Ban / 防火墙）"
	else
		protect_value="${C_R}异常${C_0}（${issue_text}）"
	fi

	if [ "$rep" = on ]; then
		if [ -s "$KEYFILE" ]; then report_value="${C_G}已开启${C_0}"
		else report_value="${C_Y}未配置 API Key${C_0}"
		fi
	else
		report_value='已关闭'
	fi
	age="$(intel_age_h)"
	if [ -z "$age" ]; then intel_note="${C_Y}尚未同步${C_0}"
	elif [ "$age" -gt 12 ]; then intel_note="${C_Y}${age} 小时前，建议检查${C_0}"
	else intel_note="${age} 小时前同步"
	fi

	panel_start "AbuseGuard 控制中心"
	panel_kv "防护状态" "$protect_value"
	panel_kv "封禁记录" "${C_H}$(thousands "$banned")${C_0}"
	panel_kv "情报库" "${C_H}$(thousands "$intel")${C_0} 条（${intel_note}）"
	panel_kv "自动上报" "$report_value"
	panel_kv "SSH 端口" "${C_H}${ssh_ports}${C_0}"
	panel_kv "保护站点" "${C_H}${sites}${C_0}"
	panel_kv "版本" "$version"
}

act_status() {
	local st n desc next d u
	panel_start "运行概览"
	panel_row " ${C_D}服务${C_0}"
	for s in caddy fail2ban; do
		if [ "$(svc_state "$s")" = active ]; then st="${C_G}运行中${C_0}"; else st="${C_R}未运行${C_0}"; fi
		panel_row " $(panel_pad "$s" 24)$st"
	done
	panel_sep
	panel_row " ${C_D}站点${C_0}"
	if [ -n "$(sites_lines)" ]; then
		while IFS=$'\t' read -r d u; do
			[ -n "$d" ] && panel_row " $(panel_pad "$d" 24)${C_D}→${C_0} $u"
		done < <(sites_lines)
	else
		panel_row " 暂无站点，可从首页「站点与证书」添加。"
	fi
	panel_sep
	panel_row " ${C_D}封禁${C_0}"
	for j in $JAILS; do
		n="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*\([0-9]*\).*/\1/p')"
		if [ -n "$n" ]; then
			printf -v st ' %-24s%7s' "$j" "$n"
			panel_row "$st"
		else
			panel_row " $(panel_pad "$j" 24)${C_D}未启用${C_0}"
		fi
	done
	panel_sep
	panel_row " ${C_D}定时${C_0}"
	for u in caddy-abuseguard-report.timer caddy-abuseguard-sync.timer; do
		case "$u" in *report*) desc="上报队列冲刷" ;; *sync*) desc="威胁情报同步" ;; esac
		if [ "$(systemctl is-active "$u" 2>/dev/null)" = active ]; then
			next="$(systemctl show "$u" -p NextElapseUSecRealtime --value 2>/dev/null)"
			case "$next" in ""|0|n/a) next="" ;; esac
			st=""
			[ -n "$next" ] && st="${C_D}（下次 $next）${C_0}"
			panel_row " $(panel_pad "$desc" 24)${C_G}已启用${C_0}$st"
		else
			panel_row " $(panel_pad "$desc" 24)${C_D}未启用${C_0}"
		fi
	done
	panel_pause
}

act_banned() {
	local ips
	for j in $JAILS; do
		echo "== $j =="
		ips="$(fail2ban-client status "$j" 2>/dev/null | sed -n '/Banned IP list/s/.*:[[:space:]]*//p' | tr ' ' '\n' | sed '/^$/d')"
		if [ -n "$ips" ]; then printf '%s\n' "$ips" | sed 's/^/  /'; else echo "  （无）"; fi
	done
	pause
}

act_unban() {
	local ip
	read -r -p "输入要解封的 IP（留空取消）: " ip
	ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
	[ -z "$ip" ] && return
	wl_valid "$ip" || { echo "  IP 格式无效。"; pause; return; }
	if fail2ban-client unban "$ip" >/dev/null 2>&1; then
		echo "  已解封 $ip（所有 jail）。"
	else
		echo "  解封失败，或该 IP 当前未被封禁。"
	fi
	pause
}

act_ban() {
	local ip allow_status
	read -r -p "输入要立即封禁的 IP（留空取消）: " ip
	ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
	[ -z "$ip" ] && return
	case "$ip" in */*) echo "  手动封禁仅支持单个 IPv4/IPv6 地址，不支持网段。"; pause; return ;; esac
	wl_valid "$ip" || { echo "  IP 格式无效。"; pause; return; }
	allow_status=0
	"$ENGINE" allowlist-check --ip "$ip" >/dev/null 2>&1 || allow_status=$?
	case "$allow_status" in
		0) echo "  该 IP 已在白名单中，不能封禁。"; pause; return ;;
		1) ;;
		*) echo "  无法可靠检查白名单，已取消封禁。"; pause; return ;;
	esac
	# 任一 AbuseGuard jail 都按源 IP 拦截所有端口和协议。
	# 用 caddy-intel：它只做防火墙 drop、不挂上报动作，手动封禁不会被自动上报到
	# AbuseIPDB（probe jail 带 queue 动作，手动封会误报一个管理员本地拉黑的 IP）。
	if fail2ban-client set caddy-intel banip "$ip" >/dev/null 2>&1; then
		echo "  已封禁 $ip。"
	else
		echo "  封禁失败（检查 jail 是否启用）。"
	fi
	pause
}

# 使用引擎的同一解析器严格校验 IPv4/IPv6（可带 /前缀）。
wl_valid() {
	"$ENGINE" allowlist-validate --entry "$1" >/dev/null 2>&1
}

# 候选文件与正式白名单同目录，校验和权限设置成功后再原子替换。
wl_candidate() {
	local tmp
	tmp="$(mktemp "$CONF_DIR/.whitelist.XXXXXX")" || return 1
	if ! cp -- "$WHITELIST" "$tmp"; then
		rm -f -- "$tmp"
		return 1
	fi
	printf '%s\n' "$tmp"
}

wl_commit() {
	local candidate="$1"
	"$ENGINE" allowlist-validate --file "$candidate" >/dev/null 2>&1 || return 1
	chown root:abuseguard "$candidate" || return 1
	chmod 0640 "$candidate" || return 1
	mv -f -- "$candidate" "$WHITELIST"
}

# 重载 fail2ban 并清 ignore 缓存，让白名单改动立即生效
wl_reload() { chown root:abuseguard "$WHITELIST" 2>/dev/null; chmod 0640 "$WHITELIST" 2>/dev/null; fail2ban-client reload >/dev/null 2>&1 || true; }

act_whitelist() {
	local -a items
	local line ip num target tmp c i
	while true; do
		panel_start "防火墙 / IP 白名单"
		panel_row " 白名单 IP 不会被封禁或上报，仍受端口规则限制。"
		items=()
		while IFS= read -r line; do
			line="${line%%#*}"; line="$(printf '%s' "$line" | tr -d '[:space:]')"
			[ -n "$line" ] && items+=("$line")
		done < "$WHITELIST"
		if [ "${#items[@]}" -eq 0 ]; then
			panel_row " （空）"
		else
			for line in "${items[@]}"; do panel_row " $line"; done
		fi
		panel_sep
		panel_option 1 "添加 IP 或网段（支持批量）"
		panel_option 2 "删除白名单条目"
		panel_option 3 "用编辑器打开"
		panel_footer "返回防火墙"
		read -r -p "  请输入选项 [0-3]（回车返回）: " c || return
		case "$c" in
			1)
				echo "  批量添加：每行一个，或用空格/逗号分隔多个；输入空行结束。"
				local added=0 skipped=0 tok; local -a added_ips=()
				tmp="$(wl_candidate)" || { echo "  无法创建白名单候选文件。"; sleep 1; continue; }
				while IFS= read -r ip; do
					[ -z "$ip" ] && break
					ip="${ip//,/ }"
					for tok in $ip; do
						if ! wl_valid "$tok"; then echo "    跳过(格式无效)：$tok"; skipped=$((skipped+1)); continue; fi
						if grep -qxF "$tok" "$tmp" 2>/dev/null; then echo "    跳过(已存在)：$tok"; skipped=$((skipped+1)); continue; fi
						printf '%s\n' "$tok" >> "$tmp"; added=$((added+1)); added_ips+=("$tok"); echo "    待添加：$tok"
					done
				done
				if [ "$added" -gt 0 ] && wl_commit "$tmp"; then
					tmp=""; wl_reload
					# reload 只影响未来判定；正被封的 IP 需显式解封才能立即放行
					for tok in "${added_ips[@]}"; do fail2ban-client unban "$tok" >/dev/null 2>&1; done
					echo "  完成：新增 $added，跳过 $skipped（加白的 IP 若在封禁中已一并解封）"
				else
					rm -f -- "$tmp"
					[ "$added" -eq 0 ] && echo "  完成：新增 0，跳过 $skipped" \
						|| echo "  候选白名单未通过完整校验，原文件保持不变。"
				fi
				sleep 1 ;;
			2)
				[ "${#items[@]}" -eq 0 ] && { echo "  没有可删除的条目"; sleep 1; continue; }
				i=1; for line in "${items[@]}"; do printf "  [%d] %s\n" "$i" "$line"; i=$((i+1)); done
				read -r -p "  输入要删除的编号: " num
				case "$num" in ''|*[!0-9]*) continue ;; esac
				if [ "$num" -lt 1 ] || [ "$num" -gt "${#items[@]}" ]; then echo "  编号超出范围"; sleep 1; continue; fi
				target="${items[$((num-1))]}"
				tmp="$(wl_candidate)" || { echo "  无法创建白名单候选文件。"; sleep 1; continue; }
				# 删掉“去注释去空格后 == target”的行，保留注释/空行/其它条目
				if awk -v t="$target" '{l=$0; sub(/#.*/,"",l); gsub(/[ \t]/,"",l); if (l!=t) print}' "$WHITELIST" > "$tmp" \
					&& wl_commit "$tmp"; then
					tmp=""; wl_reload; echo "  已删除：$target"
				else
					rm -f -- "$tmp"; echo "  候选白名单无效，原文件保持不变。"
				fi
				sleep 1 ;;
			3)
				tmp="$(wl_candidate)" || { echo "  无法创建白名单候选文件。"; sleep 1; continue; }
				if "${EDITOR:-nano}" "$tmp" && wl_commit "$tmp"; then
					tmp=""; wl_reload; echo "  白名单已保存。"
				else
					rm -f -- "$tmp"; echo "  白名单格式无效或编辑失败，原文件保持不变。"
				fi
				sleep 1 ;;
			''|0) wl_reload; return ;;
			*) echo "请输入 0–3 之间的菜单编号。"; pause ;;
		esac
	done
}

# ---- 本机防火墙（安装时启用，IP 自动封禁由 fail2ban 执行） ----
firewall_running() { nft list table inet caddy_abuseguard >/dev/null 2>&1; }

firewall_check_conflicts() {
	local conflicts
	# An accept here cannot override another base chain's drop. Ignore empty
	# accept chains, our own table and Fail2Ban; reject competing input rules.
	conflicts="$(nft -j list ruleset | jq -r '
		.nftables as $objects | $objects[] | .chain // empty |
		select(.hook == "input" and (.family == "inet" or .family == "ip" or .family == "ip6")) |
		select((.family != "inet" or .table != "caddy_abuseguard") and .table != "f2b-table") |
		. as $chain |
		select(.policy == "drop" or any($objects[];
			.rule.family == $chain.family and .rule.table == $chain.table and .rule.chain == $chain.name)) |
		"\(.family) \(.table) \(.name)"
	')" || { echo "无法读取现有防火墙规则，已停止接管。" >&2; return 1; }
	[ -z "$conflicts" ] || {
		echo "检测到其他本机入站规则，无法由 AbuseGuard 独立管理：" >&2
		printf '  %s\n' "$conflicts" >&2
		echo "请先迁移或停用对应的防火墙规则，再重新运行安装器。" >&2
		return 1
	}
}

firewall_ports() {
	[ -f "$FIREWALL_FILE" ] || return 0
	awk '
		$1 == "meta" && $2 == "nfproto" && $3 == "ipv4" && ($4 == "tcp" || $4 == "udp") && $5 == "dport" && $7 == "accept" { print $4, $6, "any"; next }
		($1 == "ip" || $1 == "ip6") && $2 == "saddr" && ($4 == "tcp" || $4 == "udp") && $5 == "dport" && $7 == "accept" { print $4, $6, $3; next }
		NF == 4 && ($1 == "tcp" || $1 == "udp") && $2 == "dport" && $4 == "accept" { print $1, $3, "any" }
	' "$FIREWALL_FILE"
}

# 该端口是否已有任意来源的规则。
firewall_has_port() {
	printf '%s\n' "$1" | grep -qE "^tcp[[:space:]]+$2([[:space:]]|$)"
}

# 同时保留当前监听、sshd 配置和本次 SSH 连接的端口，支持多个 SSH 端口。
firewall_ssh_ports() {
	local ports p
	ports="$(
		{
			ss -H -tlnp 2>/dev/null | awk '/sshd/ { n = split($4, a, ":"); print a[n] }'
			sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'
			[ -z "${SSH_CONNECTION:-}" ] || printf '%s\n' "${SSH_CONNECTION##* }"
		} | sort -un
	)"
	[ -n "$ports" ] || { echo "无法识别 SSH 端口，已取消变更。" >&2; return 1; }
	for p in $ports; do port_valid "$p" || return 1; done
	printf '%s\n' "$ports"
}

# 单一持久配置；在一个 nft 事务中只替换本项目的表，不清空整个 ruleset。
fw_ipv4_in=1
fw_ipv6_in=0

firewall_policy_load() {
	local line=""
	[ -f "$FIREWALL_FILE" ] && line="$(sed -n '1{/^# policy /p;}' "$FIREWALL_FILE")"
	fw_ipv4_in=1
	fw_ipv6_in=0
	case "$line" in *ipv4-in=0*) fw_ipv4_in=0 ;; esac
	case "$line" in *ipv6-in=1*) fw_ipv6_in=1 ;; esac
}

firewall_render() {
	local proto port source
	firewall_policy_load
	case "${1:-}" in
		ipv4) fw_ipv4_in="$2" ;;
		ipv6) fw_ipv6_in="$2" ;;
	esac
	printf '# policy ipv4-in=%s ipv6-in=%s\n' "$fw_ipv4_in" "$fw_ipv6_in"
	cat <<'NFT'
# Managed by ag. Change ports through the firewall menu.
add table inet caddy_abuseguard
delete table inet caddy_abuseguard
table inet caddy_abuseguard {
	chain input {
		type filter hook input priority filter; policy drop;
		iifname "lo" accept
		ct state established,related accept
		ct state invalid drop
		meta l4proto { icmp, ipv6-icmp } accept
		udp sport 67 udp dport 68 accept
		udp sport 547 udp dport 546 accept
NFT
	if [ "$fw_ipv4_in" = 0 ]; then printf '\t\tmeta nfproto ipv4 drop\n'; fi
	if [ "$fw_ipv6_in" = 0 ]; then printf '\t\tmeta nfproto ipv6 drop\n'; fi
	while read -r proto port source; do
		[ -n "$proto" ] || continue
		case "$proto" in tcp|udp) ;; *) return 1 ;; esac
		port_valid "$port" || return 1
		if [ -n "$source" ] && [ "$source" != any ]; then
			case "$source" in
				*:*) printf '\t\tip6 saddr %s %s dport %s accept\n' "$source" "$proto" "$port" ;;
				*) printf '\t\tip saddr %s %s dport %s accept\n' "$source" "$proto" "$port" ;;
			esac
		else
			printf '\t\t%s dport %s accept\n' "$proto" "$port"
		fi
	done
	printf '\t}\n}\n'
}

firewall_save() {
	local ports="$1" candidate active=0
	# Do not take over an existing same-named table without our saved config.
	if firewall_running; then
		[ -f "$FIREWALL_FILE" ] || { echo "同名防火墙表已存在但没有配置文件，未接管。" >&2; return 1; }
		active=1
	fi
	candidate="$(mktemp "$CONF_DIR/.firewall.XXXXXX")" || return 1
	if ! printf '%s\n' "$ports" | sort -u | firewall_render "${2:-}" "${3:-}" > "$candidate" \
		|| ! nft -c -f "$candidate"; then
		rm -f -- "$candidate"
		return 1
	fi
	if [ "$active" = 1 ] && ! nft -f "$candidate"; then
		rm -f -- "$candidate"
		return 1
	fi
	if ! mv -f -- "$candidate" "$FIREWALL_FILE"; then
		# If persistence fails after applying, restore the previous live rules.
		if [ "$active" = 1 ]; then
			nft -f "$FIREWALL_FILE" || echo "恢复旧防火墙规则失败，请检查当前规则。" >&2
		fi
		rm -f -- "$candidate"
		return 1
	fi
}

firewall_apply() {
	local ports ssh_ports p
	firewall_check_conflicts || return 1
	ssh_ports="$(firewall_ssh_ports)" || return 1
	if [ -f "$FIREWALL_FILE" ]; then
		ports="$(firewall_ports)" || return 1
	else
		ports=$'tcp 443 any\nudp 443 any'
	fi
	for p in $ssh_ports; do
		firewall_has_port "$ports" "$p" || ports+=$'\n'"tcp $p any"
	done
	firewall_save "$ports" || return 1
	systemctl start "$FIREWALL_SERVICE" || return 1
	if ! systemctl enable "$FIREWALL_SERVICE"; then
		echo "规则已生效，但设置开机恢复失败。" >&2
		return 1
	fi
	echo "AbuseGuard 防火墙已启用，开机自动恢复。开放端口："
	firewall_ports | sed 's/^/  /'
}

firewall_change_port() {
	local action="$1" proto="${2:-}" port="${3:-}" source="${4:-any}" skip_ssh="${5:-}"
	local interactive=0 ports ssh_ports p rules idx selected remaining pr po so ssh_retire_file="" ssh_retire_backup=""
	[ "$#" -eq 1 ] && interactive=1
	[ -f "$FIREWALL_FILE" ] || { echo "防火墙配置缺失，请选择重新应用规则或重新运行安装器。"; return 1; }
	firewall_check_conflicts || return 1

	if [ "$interactive" = 1 ] && [ "$action" = close ]; then
		rules="$(firewall_ports)" || return 1
		if [ -z "$rules" ]; then
			echo "没有可关闭的端口规则。"
			return 0
		fi
		panel_row " 编号  协议  端口  来源"
		idx=0
		while read -r pr po so; do
			idx=$((idx + 1))
			panel_row "$(printf ' [%d]  %-4s %-6s %s' "$idx" "$pr" "$po" "${so:-any}")"
		done <<< "$rules"
		read -r -p "  要关闭的规则编号（留空取消）: " selected || return 1
		[ -n "$selected" ] || return 0
		case "$selected" in *[!0-9]*) echo "编号无效。"; return 1 ;; esac
		selected=$((10#$selected))
		[ "$selected" -ge 1 ] && [ "$selected" -le "$idx" ] || { echo "编号无效。"; return 1; }
		selected="$(printf '%s\n' "$rules" | sed -n "${selected}p")"
		set -- $selected
		proto="$1"; port="$2"; source="${3:-any}"
	elif [ "$interactive" = 1 ]; then
		read -r -p "协议（tcp/udp，默认 tcp）: " proto || return 1
		proto="${proto:-tcp}"
	fi
	case "$proto" in tcp|udp) ;; *) echo "协议只能是 tcp 或 udp。"; return 1 ;; esac
	if [ "$interactive" = 1 ] && [ "$action" = open ]; then
		read -r -p "端口（1–65535，留空取消）: " port || return 1
		[ -n "$port" ] || return 0
		read -r -p "来源 IPv4/IPv6 或 CIDR（留空=所有来源）: " source || return 1
		source="${source:-any}"
	fi
	[ "${#port}" -le 5 ] && port_valid "$port" || { echo "端口格式无效。"; return 1; }
	port=$((10#$port))
	source="${source:-any}"
	case "$source" in *[[:space:]]*) echo "来源不能包含空白。"; return 1 ;; esac
	case "$source" in any) ;; *[!0-9a-fA-F.:/]*) echo "来源必须是 IPv4/IPv6 地址、CIDR 或留空。"; return 1 ;; esac

	if [ "$skip_ssh" != no-ssh ]; then
		ssh_ports="$(firewall_ssh_ports)" || return 1
	fi
	ports="$(firewall_ports)" || return 1
	if [ "$action" = close ] && ! printf '%s\n' "$ports" | grep -qxF "$proto $port $source"; then
		echo "规则不存在：$proto $port $source"
		return 1
	fi

	if [ "$action" = close ] && [ "$skip_ssh" != no-ssh ] && [ "$proto" = tcp ] && grep -qxF "$port" <<< "$ssh_ports"; then
		if [ -n "${SSH_CONNECTION:-}" ] && [ "${SSH_CONNECTION##* }" = "$port" ]; then
			echo "这是当前 SSH 会话端口，关闭会断开连接。"
			return 1
		fi
		remaining="$(printf '%s\n' "$ports" | grep -cE "^tcp[[:space:]]+$port([[:space:]]|$)")"
		if [ "$remaining" -le 1 ]; then
			if [ "$(grep -c . <<< "$ssh_ports")" -le 1 ]; then
				echo "这是唯一的 SSH 管理端口，不能在面板中关闭。"
				return 1
			fi
			if systemctl is-active --quiet ssh.socket 2>/dev/null; then
				echo "SSH 由 ssh.socket 激活，请在系统层面调整端口。"
				return 1
			fi
			if ! ssh_port_remove "$port"; then
				echo "无法从 sshd 配置中移除端口 $port，已取消关闭。"
				return 1
			fi
			if ! ssh_ports="$(firewall_ssh_ports)"; then
				ssh_restore_file "$ssh_retire_file" "$ssh_retire_backup"
				return 1
			fi
		fi
	fi

	ports="$(awk -v proto="$proto" -v port="$port" -v src="$source" '!($1 == proto && $2 == port && ($3 == src || ($3 == "" && src == "any")))' <<< "$ports")"
	[ "$action" = close ] || ports+=$'\n'"$proto $port $source"
	if [ "$skip_ssh" != no-ssh ]; then
		for p in $ssh_ports; do
			firewall_has_port "$ports" "$p" || ports+=$'\n'"tcp $p any"
		done
	fi
	if ! firewall_save "$ports"; then
		[ -z "$ssh_retire_backup" ] || ssh_restore_file "$ssh_retire_file" "$ssh_retire_backup"
		return 1
	fi
	if [ -n "$ssh_retire_backup" ] && ! rm -f -- "$ssh_retire_backup"; then
		echo "规则已生效，但无法删除 SSH 配置备份：$ssh_retire_backup" >&2
	fi
	if firewall_running; then
		echo "规则已保存并生效（已建立的连接继续保留）。"
	else
		echo "规则已保存；防火墙未运行，请选择重新应用规则。"
	fi
}

firewall_set_policy() {
	local fam="$1" value="$2" ports
	[ -f "$FIREWALL_FILE" ] || { echo "防火墙配置缺失，请先重新应用规则。"; return 1; }
	firewall_check_conflicts || return 1
	ports="$(firewall_ports)" || return 1
	firewall_save "$ports" "$fam" "$value"
}

firewall_toggle_family() {
	local fam="$1" now target warn answer srv
	firewall_policy_load
	if [ "$fam" = ipv4 ]; then now=$fw_ipv4_in; warn=IPv4; else now=$fw_ipv6_in; warn=IPv6; fi
	if [ "$now" = 1 ]; then target=0; else target=1; fi
	if [ "$target" = 0 ]; then
		echo " 关闭后，新的 $warn 入站连接将被丢弃。"
		if [ -n "${SSH_CONNECTION:-}" ]; then
			set -- $SSH_CONNECTION
			case "$3" in *:*) srv=IPv6 ;; *) srv=IPv4 ;; esac
			[ "$srv" = "$warn" ] && echo " 当前 SSH 会话是 $warn；断开后需要控制台恢复。"
		fi
		read -r -p " 输入 yes 继续: " answer || return 1
		[ "$answer" = yes ] || { echo " 已取消。"; return 1; }
	fi
	if firewall_set_policy "$fam" "$target"; then
		if [ "$target" = 1 ]; then echo " 已开启 $warn 入站。"; else echo " 已关闭 $warn 入站。"; fi
		firewall_running || echo " 防火墙未运行，重启或重新应用规则后生效。"
	else
		echo " 修改失败，规则保持不变。"
	fi
}

act_firewall() {
	local choice ports line warning state boot state4 state6
	nft list tables >/dev/null || { echo "无法访问 nftables。"; pause; return; }
	while true; do
		panel_start "防火墙"
		firewall_policy_load
		if firewall_running; then state="${C_G}运行中${C_0}"; else state="${C_Y}未就绪，请重新应用规则${C_0}"; fi
		if systemctl is-enabled --quiet "$FIREWALL_SERVICE"; then boot="已开启"; else boot="未开启"; fi
		panel_row " $(panel_pad "防火墙" 24)$state"
		panel_row " $(panel_pad "开机恢复" 24)$boot"
		panel_row " ${C_D}默认拒绝未放行的入站连接，保留已建立连接。${C_0}"
		ports="$(firewall_ports)"
		if [ -n "$ports" ]; then
			panel_row " ${C_D}协议    端口  来源${C_0}"
			while IFS= read -r line; do panel_row "$line"; done < <(printf '%s\n' "$ports" | awk '
				{ printf " %-5s %6s  %s\n", toupper($1), $2, ($3 != "" && $3 != "any" ? $3 : "所有来源") }
			')
		else panel_row " （配置缺失）"; fi
		warning="$(firewall_check_conflicts 2>&1)" || true
		if [ -n "$warning" ]; then
			while IFS= read -r line; do panel_row "${C_Y}$line${C_0}"; done <<< "$warning"
		fi
		panel_sep
		panel_pair 1 "开放端口" 2 "关闭端口"
		if [ "$fw_ipv4_in" = 1 ]; then state4="${C_G}已开启${C_0}"; else state4="${C_D}已关闭${C_0}"; fi
		if [ "$fw_ipv6_in" = 1 ]; then state6="${C_G}已开启${C_0}"; else state6="${C_D}已关闭${C_0}"; fi
		panel_pair 3 "IPv4 入站  $state4" 4 "IPv6 入站  $state6"
		panel_pair 5 "查看封禁列表" 6 "封禁 IP"
		panel_pair 7 "解封 IP" 8 "管理白名单"
		panel_pair 9 "查看全部规则" 10 "重新应用规则"
		echo
		panel_row " ${C_D}白名单仅豁免 IP 封禁，仍受端口规则限制。${C_0}"
		panel_row " ${C_D}云安全组及容器转发规则需在对应平台管理。${C_0}"
		panel_footer "返回首页"
		read -r -p "  请输入选项 [0-10]（回车返回）: " choice || return
		case "$choice" in
			1) panel_title "防火墙 / 开放端口"; firewall_change_port open || echo "未完成端口变更。"; pause ;;
			2) panel_title "防火墙 / 关闭端口"; firewall_change_port close || echo "未完成端口变更。"; pause ;;
			3) panel_title "防火墙 / IPv4 入站"; firewall_toggle_family ipv4; pause ;;
			4) panel_title "防火墙 / IPv6 入站"; firewall_toggle_family ipv6; pause ;;
			5) panel_title "防火墙 / 封禁列表"; act_banned ;;
			6) panel_title "防火墙 / 封禁 IP"; act_ban ;;
			7) panel_title "防火墙 / 解封 IP"; act_unban ;;
			8) act_whitelist ;;
			9) panel_title "防火墙 / 全部规则"; nft -a list ruleset; pause ;;
			10) panel_title "防火墙 / 重新应用规则"; firewall_apply || echo "应用失败，请检查上方错误。"; pause ;;
			''|0) return ;;
			*) echo "请输入 0–10 之间的菜单编号。"; pause ;;
		esac
	done
}

# ---- SSH 端口 ----
# 修改端口时新旧端口同时监听；确认新端口可登录后，再到防火墙管理关闭旧端口。
ssh_current_ports() {
	sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -un || true
}

# 列出声明 Port 的位置（可只匹配某个端口），格式：文件:行:内容。
ssh_port_sites() {
	local pat='^[[:space:]]*Port[[:space:]]+[0-9]+'
	[ -z "${1:-}" ] || pat='^[[:space:]]*Port[[:space:]]+'"$1"'([[:space:]]|$)'
	grep -HnE "$pat" "$SSHD_MAIN" 2>/dev/null
	grep -rnE --include='*.conf' "$pat" "$SSHD_DROPIN_DIR" 2>/dev/null || true
}

# 恢复某个 sshd 配置文件并重载（失败回滚）。
ssh_restore_file() {
	local file="$1" backup="$2"
	if [ -n "$backup" ]; then
		if ! mv -f -- "$backup" "$file"; then
			echo "无法恢复 SSH 配置，备份保留于 $backup。" >&2
			return 1
		fi
	else
		rm -f -- "$file" || return 1
	fi
	if ! sshd -t >/dev/null 2>&1 || ! systemctl reload ssh >/dev/null 2>&1; then
		echo "SSH 配置已恢复，但无法重载，请检查 ssh 服务。" >&2
		return 1
	fi
}

# 从 sshd 配置中移除某个端口；调用者保留备份直到防火墙提交成功。
ssh_port_remove() {
	local port="$1" sites files file backup
	sites="$(ssh_port_sites "$port")"
	files="$(printf '%s\n' "$sites" | grep . | cut -d: -f1 | sort -u)"
	[ -n "$files" ] || return 1
	[ "$(printf '%s\n' "$files" | grep -c .)" -eq 1 ] || return 1
	file="$files"
	backup="$(mktemp)" || return 1
	if ! cp -p -- "$file" "$backup"; then
		rm -f -- "$backup"
		return 1
	fi
	if ! sed -i -E "/^[[:space:]]*Port[[:space:]]+$port([[:space:]]|$)/d" "$file"; then
		ssh_restore_file "$file" "$backup"
		return 1
	fi
	if [ "$file" = "$SSHD_DROPIN" ] && ! grep -qE '^[[:space:]]*Port[[:space:]]+' "$file"; then
		rm -f -- "$file"
	fi
	if ! sshd -t; then
		ssh_restore_file "$file" "$backup"
		return 1
	fi
	if [ -z "$(ssh_current_ports)" ]; then
		ssh_restore_file "$file" "$backup"
		return 1
	fi
	if ! systemctl reload ssh 2>/dev/null; then
		ssh_restore_file "$file" "$backup"
		return 1
	fi
	if ss -H -tlnp "sport = :$port" 2>/dev/null | grep -q sshd; then
		ssh_restore_file "$file" "$backup"
		return 1
	fi
	# The caller keeps this backup until the firewall change is committed.
	ssh_retire_file="$file"
	ssh_retire_backup="$backup"
	return 0
}

# 加入新端口，旧端口继续监听；关闭旧端口由防火墙管理完成。
act_ssh_port() {
	local cur new answer port_sites port_count backup="" fw=0 now p old_sources="" target_sources="" added_sources="" src a
	systemctl cat ssh.service >/dev/null 2>&1 || { echo "未找到 ssh 服务，无法修改 SSH 端口。"; return 1; }
	if systemctl is-active --quiet ssh.socket 2>/dev/null; then
		echo "系统使用 ssh.socket 激活 SSH，面板不修改其端口；请先恢复 ssh.service 再试。"
		return 1
	fi
	command -v sshd >/dev/null 2>&1 || { echo "未找到 sshd，无法修改 SSH 端口。"; return 1; }
	[ -d "$SSHD_DROPIN_DIR" ] || { echo "系统没有 $SSHD_DROPIN_DIR，面板不修改 SSH 端口。"; return 1; }
	cur="$(ssh_current_ports)"
	[ -n "$cur" ] || { echo "无法读取当前 SSH 端口，已取消。"; return 1; }
	if [ "$(printf '%s\n' "$cur" | grep -c .)" -ne 1 ]; then
		echo "当前 SSH 监听多个端口（$(printf '%s' "$cur" | tr '\n' ' ')），请先在「防火墙」中关闭不需要的端口再切换。"
		return 1
	fi
	echo "当前 SSH 端口：$cur"
	port_sites="$(ssh_port_sites)"
	port_count="$(printf '%s\n' "$port_sites" | grep -c .)"
	if [ "$port_count" -gt 1 ]; then
		echo "检测到多个 Port 指令，面板无法安全切换（sshd 会同时监听多个端口）："
		printf '  %s\n' "$port_sites"
		echo "请先只保留一个 Port 指令后重试。"
		return 1
	fi
	read -r -p "  新的 SSH 端口（1-65535，留空取消）: " new || return 1
	[ -n "$new" ] || return 0
	[ "${#new}" -le 5 ] && port_valid "$new" || { echo "端口格式无效。"; return 1; }
	new=$((10#$new))
	printf '%s\n' "$cur" | grep -qxF "$new" && { echo "新端口与当前端口相同。"; return 1; }
	if ss -H -tln "sport = :$new" 2>/dev/null | grep -q .; then
		echo "端口 $new 已被其他服务监听，已取消。"
		return 1
	fi
	old_sources="$(firewall_ports | awk -v p="$cur" '$1 == "tcp" && $2 == p { print $3 }' | sort -u)"
	if printf '%s\n' "$old_sources" | grep -qxF any; then old_sources=any; fi
	[ -n "$old_sources" ] || old_sources=any
	target_sources="$(firewall_ports | awk -v p="$new" '$1 == "tcp" && $2 == p { print $3 }' | sort -u)"
	if [ "$old_sources" != any ]; then
		for src in $target_sources; do
			if ! printf '%s\n' "$old_sources" | grep -qxF "$src"; then
				echo "新端口已有不同来源的防火墙规则，请先在「防火墙」中调整。"
				return 1
			fi
		done
	fi
	echo "  ${C_R}新旧端口将同时监听；确认新端口可登录后到防火墙关闭旧端口。${C_0}"
	echo "  ${C_R}请先在云安全组放行 $new/tcp。${C_0}"
	read -r -p "  继续？[y/N]: " answer || return 1
	case "$answer" in y|Y) ;; *) echo "已取消。"; return 1 ;; esac

	if [ -f "$SSHD_DROPIN" ]; then
		backup="$(mktemp)" || return 1
		if ! cp -p -- "$SSHD_DROPIN" "$backup"; then
			rm -f -- "$backup"
			return 1
		fi
	fi
	# 已有的单个 Port 留在原文件；我们的 drop-in 只负责新端口。没有 Port 时，
	# 把当前端口也显式写出来，否则 sshd 只监听新端口。
	if [ "$port_count" = 1 ] && [ "${port_sites%%:*}" != "$SSHD_DROPIN" ]; then
		printf 'Port %s\n' "$new" > "$SSHD_DROPIN"
	else
		printf 'Port %s\nPort %s\n' "$cur" "$new" > "$SSHD_DROPIN"
	fi
	if ! sshd -t; then
		echo "sshd 配置校验失败，已回滚。"
		ssh_restore_file "$SSHD_DROPIN" "$backup"
		return 1
	fi
	now="$(ssh_current_ports)"
	if ! printf '%s\n' "$now" | grep -qxF "$cur" || ! printf '%s\n' "$now" | grep -qxF "$new"; then
		echo "sshd 未同时监听新旧端口，已回滚。"
		ssh_restore_file "$SSHD_DROPIN" "$backup"
		return 1
	fi
	if [ -f "$FIREWALL_FILE" ]; then
		for src in $old_sources; do
			if printf '%s\n' "$target_sources" | grep -qxF "$src"; then continue; fi
			if ! firewall_change_port open tcp "$new" "$src" >/dev/null; then
				echo "防火墙放行新端口失败，已回滚。"
				for a in $added_sources; do firewall_change_port close tcp "$new" "$a" no-ssh >/dev/null 2>&1; done
				ssh_restore_file "$SSHD_DROPIN" "$backup"
				return 1
			fi
			added_sources+=" $src"
		done
		fw=1
	elif firewall_running; then
		echo "防火墙正在运行但配置缺失，无法安全放行新端口，已取消。"
		ssh_restore_file "$SSHD_DROPIN" "$backup"
		return 1
	fi
	if ! systemctl reload ssh 2>/dev/null; then
		echo "sshd 重载失败，已回滚。"
		ssh_restore_file "$SSHD_DROPIN" "$backup"
		if [ "$fw" = 1 ]; then for a in $added_sources; do firewall_change_port close tcp "$new" "$a" no-ssh >/dev/null 2>&1; done; fi
		return 1
	fi
	for p in "$cur" "$new"; do
		for _ in {1..10}; do
			ss -H -tlnp "sport = :$p" 2>/dev/null | grep -q sshd && break
			sleep 1
		done
		if ! ss -H -tlnp "sport = :$p" 2>/dev/null | grep -q sshd; then
			echo "端口 $p 未在监听，已回滚。"
			ssh_restore_file "$SSHD_DROPIN" "$backup"
			if [ "$fw" = 1 ]; then for a in $added_sources; do firewall_change_port close tcp "$new" "$a" no-ssh >/dev/null 2>&1; done; fi
			return 1
		fi
	done
	if [ -n "$backup" ] && ! rm -f -- "$backup"; then
		echo "端口已切换，但无法删除 SSH 配置备份：$backup" >&2
	fi

	# 上报元数据切到最终端口；旧端口只是过渡期保留。
	if [ -f "$SSH_REPORT_JAIL" ]; then
		sed -i -E "s/(profile=ssh-bruteforce, transport=SSH, target_port=)[0-9]+/\1$new/" "$SSH_REPORT_JAIL"
		fail2ban-client reload >/dev/null 2>&1 || echo "fail2ban 重载失败，SSH 上报端口可能未生效。" >&2
	fi
	echo "新端口 $new 已开启，旧端口 $cur 仍监听。"
	echo "请用新端口重新登录确认，然后到「防火墙」关闭旧端口。"
}

# ---- SSH 登录方式 ----
# 认证开关写入独立 drop-in；关闭密码登录前必须确认 root 有可用公钥。
# 列出声明某认证指令的位置（可只匹配某指令），格式：文件:行:内容。
ssh_auth_sites() {
	local pat='^[[:space:]]*(PasswordAuthentication|PubkeyAuthentication)[[:space:]]+(yes|no)'
	[ -z "${1:-}" ] || pat='^[[:space:]]*'"$1"'[[:space:]]+(yes|no)'
	grep -HinE "$pat" "$SSHD_MAIN" 2>/dev/null || true
	grep -rinE --include='*.conf' "$pat" "$SSHD_DROPIN_DIR" 2>/dev/null || true
}

# 真正压得过面板 drop-in 的指令位置（这些才拒绝修改）。sshd 首值生效，Include
# 按文件名字典序展开；面板文件用 00- 排第一，主配置全局指令（Include 在主配置
# 开头）和排序靠后的 drop-in 都被面板压住，不构成冲突。要拒绝的只有三种：
#   1. 主配置没有 Include：drop-in 整体不生效
#   2. Match 块内的指令：对匹配的连接覆盖全局设置
#   3. 排序在面板文件之前的外部 drop-in
ssh_auth_conflicts() {
	local directive="$1" row file rest fline inc mline file_match name mine
	mine="${SSHD_AUTH_DROPIN##*/}"
	inc="$(grep -nE "^[[:space:]]*Include[[:space:]]+$SSHD_DROPIN_DIR" "$SSHD_MAIN" 2>/dev/null | head -n 1 | cut -d: -f1)" || true
	[ -n "$inc" ] || { echo "$SSHD_MAIN 缺少 Include $SSHD_DROPIN_DIR，面板配置不会生效"; return 0; }
	mline="$(grep -niE '^[[:space:]]*Match[[:space:]]' "$SSHD_MAIN" 2>/dev/null | head -n 1 | cut -d: -f1)" || true
	mline="${mline:-0}"
	while IFS= read -r row; do
		[ -n "$row" ] || continue
		file="${row%%:*}"
		rest="${row#*:}"
		fline="${rest%%:*}"
		if [ "$file" = "$SSHD_MAIN" ]; then
			if [ "$mline" -gt 0 ] && [ "$fline" -gt "$mline" ]; then
				echo "$row（Match 块内，会覆盖面板配置）"
			elif [ "$fline" -lt "$inc" ]; then
				echo "$row（在 Include 之前，先于面板生效）"
			fi
		else
			name="${file##*/}"
			file_match="$(grep -niE '^[[:space:]]*Match[[:space:]]' "$file" 2>/dev/null | head -n 1 | cut -d: -f1)" || true
			if [ -n "$file_match" ] && [ "$fline" -gt "$file_match" ]; then
				echo "$row（Match 块内，会覆盖面板配置）"
			elif [ "$name" != "$mine" ] && [ "$name" \< "$mine" ]; then
				echo "$row（drop-in 排序在面板之前）"
			fi
		fi
	done < <(ssh_auth_sites "$directive")
}

# 生效的认证开关（sshd -T 的输出是小写 on/off）。
ssh_auth_state() {
	local key="$1" line
	line="$(sshd -T 2>/dev/null | awk -v k="$key" '$1 == k && !found { print $2; found=1 }')" || line=""
	case "$line" in
		yes|on) echo on ;;
		no|off) echo off ;;
		*) echo unknown ;;
	esac
}

# 检查公钥内容和权限；无法运行 ssh-keygen 时不能认为公钥可用。
ssh_key_ready() {
	local file="${1:-$SSH_AUTH_KEYS}" m
	[ -f "$file" ] && [ -s "$file" ] || return 1
	command -v ssh-keygen >/dev/null 2>&1 || return 1
	# 只确认没有限制选项的公钥；ssh-keygen 自身也会把私钥识别为有效输入。
	awk '
		/^[[:space:]]*#/ { next }
		$1 ~ /^(ssh-|ecdsa-|sk-)/ && $2 ~ /^[A-Za-z0-9+\/=]+$/ { print $1, $2 }
	' "$file" | ssh-keygen -lf - >/dev/null 2>&1 || return 1
	m="$(stat -c %a "$SSH_ROOT_HOME" 2>/dev/null)" || return 1
	[ "$(( 8#$m & 022 ))" -eq 0 ] || return 1
	m="$(stat -c %a "$file" 2>/dev/null)" || return 1
	[ "$(( 8#$m & 022 ))" -eq 0 ] || return 1
}

# 根据当前 SSH 连接检查 root 的有效配置。无法确定来源时不假定备用方式可用。
ssh_root_config() {
	local client client_port local_ip local_port config
	read -r client client_port local_ip local_port <<< "${SSH_CONNECTION:-}"
	[ -n "$client" ] && [ -n "$client_port" ] && [ -n "$local_ip" ] && [ -n "$local_port" ] || return 1
	config="$(sshd -T -C "user=root,host=$client,addr=$client,laddr=$local_ip,lport=$local_port" 2>/dev/null)" || return 1
	# UseDNS=yes 时 host 是反向解析的名称，而非来源 IP，不能安全地猜测。
	[ "$(printf '%s\n' "$config" | awk '$1 == "usedns" { print $2; exit }')" = no ] || return 1
	printf '%s\n' "$config"
}

ssh_auth_allows_single() {
	local config="$1" method="$2" methods
	methods="$(printf '%s\n' "$config" | awk '$1 == "authenticationmethods" { for (i=2; i<=NF; i++) printf " %s", $i; exit }')"
	case "$methods " in *" any "*|*" $method "*) return 0 ;; *) return 1 ;; esac
}

# 这里只能确认配置允许独立使用密码，不能证明操作者知道密码。
root_password_login_ready() {
	local config root_login password_auth password_status
	config="$(ssh_root_config)" || return 1
	root_login="$(printf '%s\n' "$config" | awk 'tolower($1) == "permitrootlogin" { print tolower($2); exit }')"
	password_auth="$(printf '%s\n' "$config" | awk 'tolower($1) == "passwordauthentication" { print tolower($2); exit }')"
	[ "$root_login" = yes ] || return 1
	[ "$password_auth" = yes ] || return 1
	ssh_auth_allows_single "$config" password || return 1
	password_status="$(passwd -S root 2>/dev/null | awk '{ print $2; exit }')"
	case "$password_status" in P|PS) return 0 ;; *) return 1 ;; esac
}

root_key_login_ready() {
	local config root_login pubkey_auth files file
	config="$(ssh_root_config)" || return 1
	root_login="$(printf '%s\n' "$config" | awk '$1 == "permitrootlogin" { print $2; exit }')"
	pubkey_auth="$(printf '%s\n' "$config" | awk '$1 == "pubkeyauthentication" { print $2; exit }')"
	case "$root_login" in yes|prohibit-password|without-password) ;; *) return 1 ;; esac
	[ "$pubkey_auth" = yes ] || return 1
	ssh_auth_allows_single "$config" publickey || return 1
	files="$(printf '%s\n' "$config" | awk '$1 == "authorizedkeysfile" { for (i=2; i<=NF; i++) printf " %s", $i; exit }')"
	for file in $files; do
		case "$file" in .ssh/authorized_keys|/root/.ssh/authorized_keys|%h/.ssh/authorized_keys) return 0 ;; esac
	done
	return 1
}

# 写入认证开关；调用者负责备份、校验与重载。
ssh_auth_write() {
	local pw="$1" pk="$2" line=""
	[ -f "$SSHD_AUTH_DROPIN" ] && grep -vE '^[[:space:]]*(PasswordAuthentication|PubkeyAuthentication)[[:space:]]' "$SSHD_AUTH_DROPIN" > "$SSHD_AUTH_DROPIN.tmp"
	[ -n "$pw" ] && line="${line}PasswordAuthentication $pw"$'\n'
	[ -n "$pk" ] && line="${line}PubkeyAuthentication $pk"$'\n'
	printf '%s' "$line" >> "$SSHD_AUTH_DROPIN.tmp"
	mv -f -- "$SSHD_AUTH_DROPIN.tmp" "$SSHD_AUTH_DROPIN"
}

# 开关某个认证方式（password|pubkey -> on|off）。
act_ssh_auth() {
	local key="$1" directive="$2" label="$3" cur target answer conflicts backup ysn ypw ypk root_target
	[ -d "$SSHD_DROPIN_DIR" ] || { echo "系统没有 $SSHD_DROPIN_DIR，面板不修改 SSH 认证。"; return 1; }
	command -v sshd >/dev/null 2>&1 || { echo "未找到 sshd，无法修改 SSH 认证。"; return 1; }
	if systemctl is-active --quiet ssh.socket 2>/dev/null; then
		echo "系统使用 ssh.socket 激活 SSH，面板不修改其配置；请先恢复 ssh.service 再试。"
		return 1
	fi
	# 旧版本把面板 drop-in 放在 99-，升级后迁到 00-（排序第一，压过外部指令）。
	if [ -f "$SSHD_AUTH_DROPIN_OLD" ]; then
		if [ -f "$SSHD_AUTH_DROPIN" ]; then rm -f -- "$SSHD_AUTH_DROPIN_OLD"
		else mv -f -- "$SSHD_AUTH_DROPIN_OLD" "$SSHD_AUTH_DROPIN"; fi
	fi
	cur="$(ssh_auth_state "$key")"
	[ "$cur" != unknown ] || { echo "无法读取当前 SSH 认证状态，已取消。"; return 1; }
	target=off; [ "$cur" = off ] && target=on
	# 只拒绝真正压不过面板的指令（见 ssh_auth_conflicts）。
	conflicts="$(ssh_auth_conflicts "$directive")"
	if [ -n "$conflicts" ]; then
		echo "以下位置的 $directive 指令优先级高于面板配置，面板不修改："
		printf '  %s\n' "$conflicts"
		echo "请先移除对应指令后重试。"
		return 1
	fi
	if [ "$target" = off ]; then
		if [ "$directive" = PasswordAuthentication ]; then
			if [ "$(ssh_auth_state pubkeyauthentication)" != on ]; then
				echo "密钥登录未开启，关闭密码登录会锁死，已拒绝。"
				return 1
			fi
			if ! ssh_key_ready || ! root_key_login_ready; then
				echo "无法确认 root 可独立使用公钥登录，已拒绝关闭密码认证。"
				echo "请检查公钥、ssh-keygen、SSH 连接及 root 认证配置，并先用新连接验证。"
				return 1
			fi
		elif [ "$directive" = PubkeyAuthentication ] && ! root_password_login_ready; then
			echo "无法确认 root 可独立使用密码登录，已拒绝关闭密钥认证。"
			echo "请检查当前 SSH 连接、PermitRootLogin 和 AuthenticationMethods，并先用新连接验证。"
			return 1
		fi
		if [ "$directive" = PasswordAuthentication ]; then
			echo " 请保持当前会话，先用新连接验证 root 密钥登录。"
		else
			echo " 请保持当前会话，先用新连接验证 root 密码登录。"
		fi
		read -r -p " 确认备用登录已验证，输入 yes 继续: " answer || return 1
		[ "$answer" = yes ] || { echo " 已取消。"; return 1; }
	fi
	backup=""
	if [ -f "$SSHD_AUTH_DROPIN" ]; then
		backup="$(mktemp)" || return 1
		cp -p -- "$SSHD_AUTH_DROPIN" "$backup" || { rm -f -- "$backup"; return 1; }
	fi
	# 内部状态用 on/off，sshd 配置只认 yes/no。写入时带上另一开关的现值，
	# 因为 ssh_auth_write 会先滤掉两条旧指令，漏传就会丢行。
	ysn=no; [ "$target" = on ] && ysn=yes
	ypw=""; ypk=""
	[ "$(ssh_auth_state passwordauthentication)" = on ] && ypw=yes
	[ "$(ssh_auth_state passwordauthentication)" = off ] && ypw=no
	[ "$(ssh_auth_state pubkeyauthentication)" = on ] && ypk=yes
	[ "$(ssh_auth_state pubkeyauthentication)" = off ] && ypk=no
	if [ "$directive" = PasswordAuthentication ]; then ypw="$ysn"; else ypk="$ysn"; fi
	ssh_auth_write "$ypw" "$ypk"
	root_target=""
	if [ "$target" = off ]; then
		root_target="$(ssh_root_config | awk -v k="$key" '$1 == k { print $2 }')" || root_target=""
	fi
	if ! sshd -t >/dev/null 2>&1 \
		|| [ "$(ssh_auth_state "$key")" != "$target" ] \
		|| { [ "$target" = off ] && [ "$root_target" != no ]; } \
		|| ! systemctl reload ssh 2>/dev/null; then
		echo "修改失败，已回滚。"
		if [ -n "$backup" ]; then
			mv -f -- "$backup" "$SSHD_AUTH_DROPIN"
		else
			rm -f -- "$SSHD_AUTH_DROPIN"
		fi
		systemctl reload ssh 2>/dev/null
		return 1
	fi
	[ -z "$backup" ] || rm -f -- "$backup"
	if [ "$target" = on ]; then
		echo " 全局 $label 认证已开启。"
		if [ "$directive" = PasswordAuthentication ] && ! root_password_login_ready; then
			echo " 这是全局密码认证；root 密码登录可能仍受 SSH 策略限制或无法确认。"
		fi
	else
		echo " 全局 $label 认证已关闭。"
		if [ "$directive" = PasswordAuthentication ] && [ "$(ssh_auth_state kbdinteractiveauthentication)" = on ]; then
			echo " 键盘交互认证仍开启，可能仍允许密码，请检查 SSH 配置。"
		fi
	fi
}

# 添加公钥到 root 的 authorized_keys。
act_ssh_key_add() {
	local key tmp
	[ -d "$SSH_ROOT_HOME" ] || mkdir -m 700 -p "$SSH_ROOT_HOME" || { echo "无法创建 $SSH_ROOT_HOME。"; return 1; }
	read -r -p "  粘贴公钥（ssh-ed25519/ssh-rsa/...，留空取消）: " key || return 1
	[ -n "$key" ] || return 0
	local ktype kblob rest
	read -r ktype kblob rest <<< "$key"
	case "$ktype" in
		ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com|sk-ecdsa-sha2-nistp384@openssh.com|sk-ecdsa-sha2-nistp521@openssh.com) ;;
		*) echo "公钥格式无效。"; return 1 ;;
	esac
	case "$kblob" in ''|*[!A-Za-z0-9+/=]*) echo "公钥格式无效。"; return 1 ;; esac
	if ! command -v ssh-keygen >/dev/null 2>&1; then
		echo "未找到 ssh-keygen，无法验证公钥。"
		return 1
	fi
	tmp="$SSH_AUTH_KEYS.tmp"
	printf '%s\n' "$key" > "$tmp"
	if ! ssh-keygen -lf "$tmp" >/dev/null 2>&1; then
		rm -f -- "$tmp"
		echo "公钥格式无效。"
		return 1
	fi
	rm -f -- "$tmp"
	# 按类型+blob 去重，注释不同视为同一把钥匙。
	if awk -v t="$ktype" -v b="$kblob" 'NF { if ($1 == t && $2 == b) { found=1; exit } } END { exit found ? 0 : 1 }' "$SSH_AUTH_KEYS" 2>/dev/null; then
		echo "该公钥已存在。"
		return 0
	fi
	# 原子追加：先写临时文件再整体替换，失败不破坏原文件。
	tmp="$SSH_AUTH_KEYS.tmp"
	{
		if [ -f "$SSH_AUTH_KEYS" ]; then
			cat "$SSH_AUTH_KEYS"
			if [ -s "$SSH_AUTH_KEYS" ] && [ "$(tail -c 1 "$SSH_AUTH_KEYS" | tr -d '\n')" ]; then
				printf '\n'
			fi
		fi
		printf '%s\n' "$key"
	} > "$tmp" || { rm -f -- "$tmp"; return 1; }
	chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
	mv -f -- "$tmp" "$SSH_AUTH_KEYS" || { rm -f -- "$tmp"; return 1; }
	chmod 700 "$SSH_ROOT_HOME"
	echo "公钥已添加（第 $(grep -c . "$SSH_AUTH_KEYS") 条）。请保持当前会话，用新会话验证密钥可登录。"
}

# 从 root 的 authorized_keys 删除一条公钥。
act_ssh_key_remove() {
	local keys idx=0 n target tmp remain answer
	[ -f "$SSH_AUTH_KEYS" ] && [ -s "$SSH_AUTH_KEYS" ] || { echo "还没有公钥。"; return 1; }
	keys="$(grep . "$SSH_AUTH_KEYS")"
	echo
	while IFS= read -r line; do
		idx=$((idx + 1))
		printf ' [%d] %.60s\n' "$idx" "$line"
	done <<< "$keys"
	read -r -p "  要删除的编号（留空取消）: " n || return 1
	[ -n "$n" ] || return 0
	case "$n" in *[!0-9]*) echo "编号无效。"; return 1 ;; esac
	[ "$n" -ge 1 ] && [ "$n" -le "$idx" ] || { echo "编号无效。"; return 1; }
	target="$n"
	tmp="$SSH_AUTH_KEYS.tmp"
	remain=0
	awk -v t="$target" 'length($0) && ++i == t { next } { print }' "$SSH_AUTH_KEYS" > "$tmp" || { rm -f -- "$tmp"; return 1; }
	remain="$(awk 'NF{n++} END{print n+0}' "$tmp")"
	chmod 600 "$tmp" || { rm -f -- "$tmp"; return 1; }
	if ! ssh_key_ready "$tmp"; then
		if ! root_password_login_ready; then
			rm -f -- "$tmp"
			echo "删除后无法确认有有效公钥或可独立使用的 root 密码，已拒绝。"
			return 1
		fi
		echo "删除后将没有有效公钥。请保持当前会话，先用新连接验证 root 密码登录。"
		read -r -p " 输入 yes 继续: " answer || { rm -f -- "$tmp"; return 1; }
		[ "$answer" = yes ] || { rm -f -- "$tmp"; echo "已取消。"; return 1; }
	fi
	mv -f -- "$tmp" "$SSH_AUTH_KEYS" || { rm -f -- "$tmp"; return 1; }
	echo "已删除，剩余 $remain 条。"
}

# 修改 root 密码。
act_ssh_password() {
	local p1 p2
	echo " 将修改 root 的登录密码（仅当密码登录开启时可用于 SSH）。"
	read -r -s -p "  新密码: " p1 || return 1
	echo
	[ -n "$p1" ] || { echo "密码不能为空。"; return 1; }
	read -r -s -p "  再输入一次: " p2 || return 1
	echo
	[ "$p1" = "$p2" ] || { echo "两次输入不一致。"; return 1; }
	if printf 'root:%s\n' "$p1" | chpasswd >/dev/null 2>&1; then
		echo "root 密码已更新。"
	else
		echo "密码修改失败。"
		return 1
	fi
}

# SSH 管理入口：端口切换与登录方式管理。
act_ssh() {
	local choice ports pw pk pw_display pk_display
	while true; do
		panel_start "SSH 与登录"
		ports="$(ssh_current_ports)"
		[ -n "$ports" ] || ports="无法读取"
		panel_row " 监听端口 $(printf '%s' "$ports" | tr '\n' ' ')"
		pw="$(ssh_auth_state passwordauthentication)"
		pk="$(ssh_auth_state pubkeyauthentication)"
		case "$pw" in on) pw_display="${C_G}已开启${C_0}" ;; off) pw_display="${C_D}已关闭${C_0}" ;; *) pw_display="${C_Y}未知${C_0}" ;; esac
		case "$pk" in on) pk_display="${C_G}已开启${C_0}" ;; off) pk_display="${C_D}已关闭${C_0}" ;; *) pk_display="${C_Y}未知${C_0}" ;; esac
		panel_row " 全局密码认证 $pw_display   全局密钥认证 $pk_display"
		if [ "$pw" = on ] && ! root_password_login_ready; then
			panel_row " ${C_Y}root 能否独立使用密码：未确认（可能受 SSH 策略限制）${C_0}"
		fi
		if [ "$pw" = off ] && [ "$(ssh_auth_state kbdinteractiveauthentication)" = on ]; then
			panel_row " ${C_Y}键盘交互认证仍开启，可能仍允许密码${C_0}"
		fi
		panel_sep
		panel_option 1 "修改 SSH 端口"
		panel_option 2 "全局密码认证 开/关"
		panel_option 3 "全局密钥认证 开/关"
		panel_pair 4 "添加公钥" 5 "删除公钥"
		panel_option 6 "修改 root 密码"
		echo
		panel_row " ${C_D}新端口验证登录后，再到防火墙关闭旧端口。${C_0}"
		panel_row " ${C_D}关闭认证方式前，请确认备用登录方式可用。${C_0}"
		panel_footer "返回首页"
		read -r -p "  请输入选项 [0-6]（回车返回）: " choice || return
		case "$choice" in
			1) panel_title "SSH 与登录 / 端口"; act_ssh_port || echo "未完成端口修改。"; pause ;;
			2) panel_title "SSH 与登录 / 密码登录"; act_ssh_auth passwordauthentication PasswordAuthentication "密码登录" || echo "未完成修改。"; pause ;;
			3) panel_title "SSH 与登录 / 密钥登录"; act_ssh_auth pubkeyauthentication PubkeyAuthentication "密钥登录" || echo "未完成修改。"; pause ;;
			4) panel_title "SSH 与登录 / 添加公钥"; act_ssh_key_add; pause ;;
			5) panel_title "SSH 与登录 / 删除公钥"; act_ssh_key_remove; pause ;;
			6) panel_title "SSH 与登录 / 修改 root 密码"; act_ssh_password; pause ;;
			''|0) return ;;
			*) echo "请输入 0–6 之间的菜单编号。"; pause ;;
		esac
	done
}

# ---- 站点 / 反向代理管理 ----
# CF token 是否已设置（决定站点用 Cloudflare DNS 还是 Caddy 默认 HTTPS）
cf_is_set() { grep -qE '^CF_API_TOKEN=.+' "$CADDY_ENV" 2>/dev/null; }
# 域名校验（example.com、a.b.co）
domain_valid() { printf '%s' "$1" | grep -qiE '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$'; }
# 端口校验（1-65535）
port_valid() { case "$1" in ''|*[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
# host:port 校验
hostport_valid() { local h="${1%:*}" p="${1##*:}"; [ "$1" != "$h" ] && [ -n "$h" ] && port_valid "$p"; }
# 列出受保护站点：每行「域名<TAB>上游」
sites_lines() {
	local f base up
	for f in "$SITES_DIR"/*.caddy; do
		[ -e "$f" ] || continue
		base="$(basename "$f" .caddy)"; [ "$base" = "_placeholder" ] && continue
		up="$(grep -oE 'reverse_proxy[[:space:]]+[^ ]+' "$f" 2>/dev/null | head -1 | awk '{print $2}')"
		printf '%s\t%s\n' "$base" "${up:-?}"
	done
}

act_sites() {
	local choice dom t hp up tls f backup num target out d u
	local -a doms
	while true; do
		panel_start "站点与证书"
		doms=()
		while IFS=$'\t' read -r d u; do
			[ -n "$d" ] || continue
			doms+=("$d")
			panel_row " $d → $u"
		done < <(sites_lines)
		[ "${#doms[@]}" -eq 0 ] && panel_row " （暂无站点，选择 [1] 添加并启用防护）"
		if cf_is_set; then
			panel_row " 证书方式：Cloudflare DNS-01（已配置 API Token）"
		else
			panel_row " 证书方式：Caddy 自动 HTTPS（需 443/tcp 可直达）"
		fi
		panel_sep
		panel_option 1 "添加站点"
		panel_option 2 "删除站点"
		panel_option 3 "设置 Cloudflare API Token"
		panel_footer "返回首页"
		read -r -p "  请输入选项 [0-3]（回车返回）: " choice || return
		case "$choice" in
			1)
				panel_title "站点与证书 / 添加站点"
				read -r -p "  域名（如 example.com）: " dom
				dom="$(printf '%s' "$dom" | tr -d '[:space:]')"
				domain_valid "$dom" || { echo "  域名格式无效"; sleep 1; continue; }
				[ -e "$SITES_DIR/$dom.caddy" ] && { echo "  该域名已存在"; sleep 1; continue; }
				echo "  上游类型："
				echo "  [1] 本地 IP:端口（如 127.0.0.1:3000）"
				echo "  [2] 公网 IP:端口（如 203.0.113.10:8080）"
				read -r -p "  请选择: " t
				case "$t" in
					1) read -r -p "  本地 IP:端口: " hp; hp="$(printf '%s' "$hp" | tr -d '[:space:]')"
					   hostport_valid "$hp" || { echo "  IP:端口 格式无效"; sleep 1; continue; }
					   up="$hp" ;;
					2) read -r -p "  公网 IP:端口: " hp; hp="$(printf '%s' "$hp" | tr -d '[:space:]')"
					   hostport_valid "$hp" || { echo "  IP:端口 格式无效"; sleep 1; continue; }
					   up="$hp" ;;
					*) continue ;;
				esac
				if cf_is_set; then
					tls=$'\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t}\n'
				else
					tls=""
				fi
				f="$SITES_DIR/$dom.caddy"
				{
					printf '%s {\n' "$dom"
					printf '\timport abuseguard\n'
					[ -n "$tls" ] && printf '%s' "$tls"
					printf '\treverse_proxy %s\n}\n' "$up"
				} > "$f"
				chmod 0644 "$f"
				out="$(validate_caddyfile "$CADDYFILE" 2>&1)"
				if [ $? -ne 0 ]; then
					rm -f "$f"
					echo "  配置校验失败，已回滚。错误："
					printf '%s\n' "$out" | grep -iE 'error|invalid' | head -3 | sed 's/^/    /'
					sleep 2; continue
				fi
				if ! caddy_reload_or_restart; then
					if rm -f -- "$f"; then
						echo "  Caddy 应用失败，新站点配置已移除。"
						caddy_restart_active && echo "  Caddy 已恢复运行。" || echo "  Caddy 服务未恢复，请检查服务日志。" >&2
					else
						echo "  Caddy 应用失败，新站点配置移除失败：$f" >&2
					fi
					sleep 2; continue
				fi
				echo "  已添加 $dom → $up （caddy 已应用配置）"; sleep 1 ;;
			2)
				[ "${#doms[@]}" -eq 0 ] && { echo "  没有可删除的站点"; sleep 1; continue; }
				i=1; for d in "${doms[@]}"; do printf "  [%d] %s\n" "$i" "$d"; i=$((i+1)); done
				read -r -p "  输入要删除的编号: " num
				case "$num" in ''|*[!0-9]*) continue ;; esac
				if [ "$num" -lt 1 ] || [ "$num" -gt "${#doms[@]}" ]; then echo "  编号超出范围"; sleep 1; continue; fi
				target="${doms[$((num-1))]}"
				f="$SITES_DIR/$target.caddy"
				backup="$(mktemp "$SITES_DIR/.site-backup.XXXXXX")" || { echo "  无法备份站点配置，未删除。"; sleep 1; continue; }
				if ! mv -- "$f" "$backup"; then
					rm -f -- "$backup"
					echo "  无法备份站点配置，未删除。"
					sleep 1; continue
				fi
				if ! caddy_reload_or_restart; then
					if mv -f -- "$backup" "$f"; then
						echo "  Caddy 应用失败，已恢复原站点配置。"
						caddy_restart_active && echo "  Caddy 已恢复运行。" || echo "  Caddy 服务未恢复，请检查服务日志。" >&2
					else
						echo "  Caddy 应用失败，原站点配置恢复失败：$backup" >&2
					fi
					sleep 2; continue
				fi
				rm -f -- "$backup"
				echo "  已删除 $target （caddy 已应用配置）"; sleep 1 ;;
			3) panel_title "站点与证书 / Cloudflare API Token"; act_cftoken ;;
			''|0) return ;;
			*) echo "请输入 0–3 之间的菜单编号。"; pause ;;
		esac
	done
}

act_sync()  { runuser -u abuseguard -- "$ENGINE" sync-intel; pause; }
act_flush() { runuser -u abuseguard -- "$ENGINE" report send-auto; pause; }

act_key() {
	read -r -s -p "AbuseIPDB API key（留空=保持当前）: " k
	echo
	if [ -n "$k" ]; then
		printf '%s\n' "$k" > "$KEYFILE"; chown root:abuseguard "$KEYFILE"; chmod 0640 "$KEYFILE"
		echo "已保存 key。"
	fi
	pause
}

act_cftoken() {
	read -r -p "Cloudflare API token（留空=保持当前）: " t
	if [ -n "$t" ]; then
		local backup had_env=0 restore_rc=0 restart_attempted=0
		backup="$(mktemp)" || { echo "无法备份旧 token，未修改。" >&2; pause; return 1; }
		if [ -f "$CADDY_ENV" ]; then
			cp -p -- "$CADDY_ENV" "$backup" || { rm -f -- "$backup"; echo "无法备份旧 token，未修改。" >&2; pause; return 1; }
			had_env=1
		fi
		if printf 'CF_API_TOKEN=%s\n' "$t" > "$CADDY_ENV" \
			&& chown root:caddy "$CADDY_ENV" \
			&& chmod 0640 "$CADDY_ENV" \
			&& validate_caddyfile "$CADDYFILE" >/dev/null 2>&1 \
			&& { restart_attempted=1; caddy_restart_active; }; then
			rm -f -- "$backup"
			echo "已保存 token，caddy 已重启并生效。"
			pause
			return
		fi
		if [ "$had_env" -eq 1 ]; then
			cp -p -- "$backup" "$CADDY_ENV" || restore_rc=$?
		else
			rm -f -- "$CADDY_ENV" || restore_rc=$?
		fi
		if [ "$restore_rc" -eq 0 ]; then
			rm -f -- "$backup"
			echo "token 保存失败，已恢复旧 .env。" >&2
			if [ "$restart_attempted" = 1 ]; then
				caddy_restart_active && echo "Caddy 已恢复运行。" || echo "Caddy 服务未恢复，请检查服务日志。" >&2
			fi
		else
			echo "token 保存失败，旧 .env 恢复失败；备份保留于 $backup。" >&2
		fi
		pause
		return 1
	fi
	pause
}

act_toggle() {
	[ -f "$CONFIG" ] || { echo "没有配置文件"; pause; return; }
	local en newv tmp
	en="$(jq -r '.abuseipdb.enabled' "$CONFIG" 2>/dev/null)"
	[ "$en" = "true" ] && newv=false || newv=true
	tmp="$(mktemp)"
	if jq ".abuseipdb.enabled = $newv" "$CONFIG" > "$tmp"; then cat "$tmp" > "$CONFIG"; fi
	rm -f "$tmp"
	[ "$newv" = true ] && echo "AbuseIPDB 上报已开启" || echo "AbuseIPDB 上报已关闭"
	pause
}

act_logs() {
	echo "-- caddy（最近 20 条）--";    journalctl -u caddy -n 20 --no-pager 2>/dev/null
	echo "-- fail2ban（最近 20 条）--"; journalctl -u fail2ban -n 20 --no-pager 2>/dev/null
	pause
}

act_update() {
	echo "正在从 $ABUSEGUARD_REPO 重新运行安装器..."
	local f=/tmp/abuseguard-install.sh
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/install.sh?v=$(date +%s)" "$f"; then
		if ABUSEGUARD_REPO="$ABUSEGUARD_REPO" ABUSEGUARD_RELEASE_TAG= \
			ABUSEGUARD_MIRROR="$ABUSEGUARD_MIRROR" ABUSEGUARD_NONINTERACTIVE=1 bash "$f"; then
			rm -f "$f"
			echo "更新完成，正在重新加载控制面板..."
			exec /usr/local/bin/ag
		else
			rm -f "$f"
			echo "更新失败。"
		fi
	else
		echo "无法获取 install.sh（直连与镜像均失败）。"
	fi
	pause
}

act_uninstall() {
	local f=/tmp/abuseguard-uninstall.sh
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/uninstall.sh?v=$(date +%s)" "$f"; then
		bash "$f"
		rm -f "$f"
	else
		echo "无法获取 uninstall.sh；请从本地克隆运行。"
	fi
	pause
}

act_intel() {
	local choice
	while true; do
		panel_start "情报与上报"
		if [ "$(reporting_state)" = on ]; then
			if [ -s "$KEYFILE" ]; then panel_row " AbuseIPDB 自动上报：${C_G}已开启${C_0}"
			else panel_row " AbuseIPDB 自动上报：${C_Y}等待配置 API Key${C_0}"; fi
		else
			panel_row " AbuseIPDB 自动上报：${C_D}已关闭${C_0}"
		fi
		panel_sep
		panel_option 1 "立即同步威胁情报"
		panel_option 2 "立即发送上报队列"
		panel_option 3 "设置 AbuseIPDB API Key"
		panel_option 4 "开关自动上报"
		panel_footer "返回首页"
		read -r -p "  请输入选项 [0-4]（回车返回）: " choice || return
		case "$choice" in
			1) panel_title "情报与上报 / 同步情报"; act_sync ;;
			2) panel_title "情报与上报 / 发送上报队列"; act_flush ;;
			3) panel_title "情报与上报 / AbuseIPDB API Key"; act_key ;;
			4) panel_title "情报与上报 / 自动上报"; act_toggle ;;
			''|0) return ;;
			*) echo "请输入 0–4 之间的菜单编号。"; pause ;;
		esac
	done
}

act_system() {
	local choice
	while true; do
		panel_start "系统维护"
		panel_option 1 "查看最近日志"
		panel_option 2 "更新 AbuseGuard"
		panel_option 3 "${C_R}卸载 AbuseGuard${C_0}"
		panel_footer "返回首页"
		read -r -p "  请输入选项 [0-3]（回车返回）: " choice || return
		case "$choice" in
			1) panel_title "系统维护 / 最近日志"; act_logs ;;
			2) panel_title "系统维护 / 更新"; act_update ;;
			3) panel_title "系统维护 / 卸载"; act_uninstall ;;
			''|0) return ;;
			*) echo "请输入 0–3 之间的菜单编号。"; pause ;;
		esac
	done
}

menu() {
	local choice read_status
	header
	panel_sep
	panel_option 1 "运行概览"
	panel_option 2 "站点与证书"
	panel_option 3 "防火墙"
	panel_option 4 "SSH 与登录"
	panel_option 5 "情报与上报"
	panel_option 6 "系统维护"
	panel_footer "退出面板"
	read -r -t "$PANEL_REFRESH_SECONDS" -p "  请输入选项 [0-6]: " choice
	read_status=$?
	case "$read_status" in
		0) ;;
		1) exit 0 ;; # stdin closed
		142) return ;; # read timeout: redraw the header and current ban count
		*) exit "$read_status" ;;
	esac
	case "$choice" in
		1) act_status ;;
		2) act_sites ;;
		3) act_firewall ;;
		4) act_ssh ;;
		5) act_intel ;;
		6) act_system ;;
		0) exit 0 ;;
		*) echo "请输入 0–6 之间的菜单编号。"; pause ;;
	esac
}

# The panel needs root (reads /etc/caddy-abuseguard, drives fail2ban/systemctl).
# If launched as a normal user, transparently re-exec under sudo so plain
# `ag` opens the panel (prompting for a password only if sudo needs one).
if [ "$(id -u)" != "0" ]; then
	if command -v sudo >/dev/null 2>&1; then
		exec sudo -- "$0" "$@"
	fi
	echo "ag 需要 root 权限——请用 root 运行，或先安装 sudo。" >&2
	exit 1
fi
case "${1:-}" in
	--firewall-apply) firewall_apply; exit $? ;;
	--firewall-open)
		[ "$#" -eq 3 ] || { echo "用法：ag --firewall-open tcp|udp 端口" >&2; exit 2; }
		firewall_change_port open "$2" "$3"; exit $? ;;
	"") ;;
	*) echo "用法：ag [--firewall-apply | --firewall-open tcp|udp 端口]" >&2; exit 2 ;;
esac
while true; do menu; done
