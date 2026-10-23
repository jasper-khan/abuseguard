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
PANEL_REFRESH_SECONDS=10
FIREWALL_FILE="$CONF_DIR/firewall.nft"
FIREWALL_SERVICE=caddy-abuseguard-firewall.service
REPO_FILE="$CONF_DIR/repo"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-$( [ -f "$REPO_FILE" ] && cat "$REPO_FILE" || echo jasper-khan/abuseguard )}"

# GitHub download resiliency for the update/uninstall fetches (see install.sh).
#   ABUSEGUARD_MIRROR unset -> direct first, then auto proxy-chain fallback
#   ABUSEGUARD_MIRROR=cn    -> straight to the proxy chain
#   ABUSEGUARD_MIRROR=<p>/  -> force that one prefix
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

C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_B=$'\033[1;34m'; C_H=$'\033[1m'; C_0=$'\033[0m'
PANEL_WIDTH=76
pause() { echo; read -r -p "按回车继续..." _; }
svc_state() { systemctl is-active "$1" 2>/dev/null || echo inactive; }

panel_line() {
	local fill
	printf -v fill '%*s' "$((PANEL_WIDTH - 2))" ''
	printf '%s%s%s%s%s\n' "$C_B" "$1" "${fill// /─}" "$2" "$C_0"
}

# 固定宽度框线：汉字和全角标点占两列，ANSI 颜色不占列。
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
			printf '%s│%s %s%*s %s│%s\n' "$C_B" "$C_0" "$line" "$((limit - used))" '' "$C_B" "$C_0"
			line="$color"; used=0
			[ "$char" != $'\n' ] || continue
		fi
		line+="$char"; used=$((used + size))
	done
	printf '%s│%s %s%*s %s│%s\n' "$C_B" "$C_0" "$line" "$((limit - used))" '' "$C_B" "$C_0"
}

panel_start() {
	clear 2>/dev/null || true
	panel_line '╭' '╮'
	panel_row " ${C_B}AbuseGuard${C_0}  /  ${C_H}$1${C_0}"
}

panel_end() { panel_line '╰' '╯'; }
panel_title() { panel_start "$1"; panel_end; }
panel_section() { panel_line '├' '┤'; panel_row " ${C_H}$1${C_0}"; }

panel_option() {
	local width gap=''
	if [ -n "${3:-}" ]; then
		width="$(printf '%s' "$2" | LC_ALL=C.UTF-8 wc -L)"
		printf -v gap '%*s' "$((14 - width))" ''
	fi
	panel_row " ${C_B}[$1]${C_0} ${C_H}$2${C_0}${gap}${3:-}"
}

panel_pair() { panel_option "$1" "$2" "${C_B}[$3]${C_0} ${C_H}$4${C_0}"; }

panel_footer() {
	panel_line '├' '┤'
	panel_option 0 "$1" "${2:-}"
	panel_end
}

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
	local caddy f2b intel banned rep age fresh report_status version firewall_status
	caddy="$(svc_state caddy)"; f2b="$(svc_state fail2ban)"
	intel="$( [ -f "$INTEL" ] && wc -l < "$INTEL" | tr -d ' ' || echo 0 )"
	banned="$(count_banned)"; rep="$(reporting_state)"
	version="$("$ENGINE" version 2>/dev/null | awk 'NR == 1 { print $2 }')"
	[ -n "$version" ] || version="?"
	age="$(intel_age_h)"
	if [ -z "$age" ]; then fresh="（未同步）"
	elif [ "$age" -gt 12 ]; then fresh="$(printf '（最后同步 %b%sh 前，建议检查%b）' "$C_Y" "$age" "$C_0")"
	else fresh="（最后同步 ${age}h 前）"; fi
	if [ "$rep" = on ]; then
		[ -s "$KEYFILE" ] && report_status="${C_G}已开启${C_0}" || report_status="${C_Y}未配置 API Key${C_0}"
	else
		report_status="${C_Y}已关闭${C_0}"
	fi
	if firewall_running; then firewall_status="${C_G}运行中${C_0}"
	else firewall_status="${C_Y}未就绪${C_0}"; fi
	panel_start "控制中心 · v${version}"
	panel_section "运行状态"
	panel_row " Caddy $( [ "$caddy" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${caddy}${C_0}" )   Fail2Ban $( [ "$f2b" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${f2b}${C_0}" )"
	panel_row " 防火墙 ${firewall_status}   当前封禁 ${C_H}${banned}${C_0}   上报 ${report_status}"
	panel_row " 情报 IP ${C_H}${intel}${C_0}  ${fresh}"
}

act_status() {
	local st n desc next d u
	panel_start "运行概览"
	panel_section "服务状态"
	for s in caddy fail2ban; do
		st="$(svc_state "$s")"; [ "$st" = active ] && st="运行中"
		panel_row " $s  $st"
	done
	panel_section "受保护站点 · 域名 → 反代上游"
	if [ -n "$(sites_lines)" ]; then
		while IFS=$'\t' read -r d u; do [ -n "$d" ] && panel_row " $d → $u"; done < <(sites_lines)
	else
		panel_row " 暂无站点，可从首页「站点与证书」添加。"
	fi
	panel_section "防护任务 · 各 jail 当前封禁数"
	for j in $JAILS; do
		n="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*\([0-9]*\).*/\1/p')"
		[ -z "$n" ] && n="未启用"
		printf -v st ' %-20s%s' "$j" "$n"
		panel_row "$st"
	done
	panel_section "定时任务"
	for u in caddy-abuseguard-report.timer caddy-abuseguard-sync.timer; do
		case "$u" in *report*) desc="上报队列冲刷" ;; *sync*) desc="威胁情报同步" ;; esac
		if [ "$(systemctl is-active "$u" 2>/dev/null)" = active ]; then
			next="$(systemctl show "$u" -p NextElapseUSecRealtime --value 2>/dev/null)"
			case "$next" in ""|0|n/a) panel_row " $desc：已启用" ;; *) panel_row " $desc：已启用（下次 $next）" ;; esac
		else
			panel_row " $desc：未启用"
		fi
	done
	panel_end
	pause
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
		panel_start "防火墙管理 / IP 白名单"
		panel_section "当前白名单"
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
		panel_section "白名单操作"
		panel_option 1 "添加 IP 或网段（支持批量）"
		panel_option 2 "删除白名单条目"
		panel_option 3 "用编辑器打开"
		panel_footer "返回防火墙管理"
		read -r -p "  选择 [0-3] > " c || return
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
			0) wl_reload; return ;;
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
	awk 'NF == 4 && ($1 == "tcp" || $1 == "udp") && $2 == "dport" && $4 == "accept" { print $1, $3 }' "$FIREWALL_FILE"
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
firewall_render() {
	local proto port
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
	while read -r proto port; do
		[ -n "$proto" ] || continue
		case "$proto" in tcp|udp) ;; *) return 1 ;; esac
		port_valid "$port" || return 1
		printf '\t\t%s dport %s accept\n' "$proto" "$port"
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
	if ! printf '%s\n' "$ports" | sort -u | firewall_render > "$candidate" \
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
		ports=$'tcp 80\ntcp 443\nudp 443'
	fi
	for p in $ssh_ports; do ports+=$'\n'"tcp $p"; done
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
	local action="$1" proto="${2:-}" port="${3:-}" ports ssh_ports p
	[ -f "$FIREWALL_FILE" ] || { echo "防火墙配置缺失，请选择重新应用规则或重新运行安装器。"; return 1; }
	firewall_check_conflicts || return 1
	if [ "$#" -eq 1 ]; then
		read -r -p "协议（tcp/udp，默认 tcp）: " proto || return 1
		proto="${proto:-tcp}"
	fi
	case "$proto" in tcp|udp) ;; *) echo "协议只能是 tcp 或 udp。"; return 1 ;; esac
	if [ "$#" -eq 1 ]; then
		read -r -p "端口（1–65535，留空取消）: " port || return 1
		[ -n "$port" ] || return 0
	fi
	[ "${#port}" -le 5 ] && port_valid "$port" || { echo "端口格式无效。"; return 1; }
	port=$((10#$port))
	ssh_ports="$(firewall_ssh_ports)" || return 1
	if [ "$action" = close ] && [ "$proto" = tcp ] && grep -qxF "$port" <<< "$ssh_ports"; then
		echo "这是 SSH 管理端口，不能在面板中关闭。"
		return 1
	fi
	ports="$(firewall_ports)" || return 1
	ports="$(awk -v proto="$proto" -v port="$port" '!($1 == proto && $2 == port)' <<< "$ports")"
	[ "$action" != open ] || ports+=$'\n'"$proto $port"
	for p in $ssh_ports; do ports+=$'\n'"tcp $p"; done
	firewall_save "$ports" || return 1
	if firewall_running; then
		echo "规则已保存并生效（已建立的连接继续保留）。"
	else
		echo "规则已保存；防火墙未运行，请选择重新应用规则。"
	fi
}

act_firewall() {
	local choice ports line warning state boot
	nft list tables >/dev/null || { echo "无法访问 nftables。"; pause; return; }
	while true; do
		panel_start "防火墙管理"
		panel_section "当前策略"
		if firewall_running; then state="${C_G}运行中${C_0}"; else state="${C_Y}未就绪，请重新应用规则${C_0}"; fi
		if systemctl is-enabled --quiet "$FIREWALL_SERVICE"; then boot="已开启"; else boot="未开启"; fi
		panel_row " 防火墙 $state   开机恢复 $boot"
		panel_row " 仅开放下列入站端口，保留已建立连接。"
		ports="$(firewall_ports)"
		if [ -n "$ports" ]; then
			while IFS= read -r line; do panel_row "$line"; done < <(printf '%s\n' "$ports" | awk '
				$1 == "tcp" { tcp = tcp ts $2; ts = ", " }
				$1 == "udp" { udp = udp us $2; us = ", " }
				END { printf " TCP   %s\n UDP   %s\n", tcp ? tcp : "（无）", udp ? udp : "（无）" }
			')
		else panel_row " （配置缺失）"; fi
		warning="$(firewall_check_conflicts 2>&1)" || true
		if [ -n "$warning" ]; then
			while IFS= read -r line; do panel_row "${C_Y}$line${C_0}"; done <<< "$warning"
		fi
		panel_row " 云安全组及容器转发规则需在对应平台管理。"
		panel_section "端口放行"
		panel_pair 1 "开放端口" 2 "关闭端口"
		panel_section "IP 访问控制"
		panel_pair 3 "查看封禁列表" 4 "封禁 IP"
		panel_pair 5 "解封 IP" 6 "管理白名单"
		panel_section "规则维护"
		panel_pair 7 "查看全部规则" 8 "重新应用规则"
		panel_footer "返回首页"
		read -r -p "  选择 [0-8] > " choice || return
		case "$choice" in
			1) panel_title "防火墙管理 / 开放端口"; firewall_change_port open || echo "未完成端口变更。"; pause ;;
			2) panel_title "防火墙管理 / 关闭端口"; firewall_change_port close || echo "未完成端口变更。"; pause ;;
			3) panel_title "防火墙管理 / 封禁列表"; act_banned ;;
			4) panel_title "防火墙管理 / 封禁 IP"; act_ban ;;
			5) panel_title "防火墙管理 / 解封 IP"; act_unban ;;
			6) act_whitelist ;;
			7) panel_title "防火墙管理 / 全部规则"; nft -a list ruleset; pause ;;
			8) panel_title "防火墙管理 / 重新应用规则"; firewall_apply || echo "应用失败，请检查上方错误。"; pause ;;
			0) return ;;
			*) echo "请输入 0–8 之间的菜单编号。"; pause ;;
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
		panel_section "已保护的站点 · 域名 → 反代上游"
		doms=()
		while IFS=$'\t' read -r d u; do
			[ -n "$d" ] || continue
			doms+=("$d")
			panel_row " $d → $u"
		done < <(sites_lines)
		[ "${#doms[@]}" -eq 0 ] && panel_row " （暂无站点，选择 [1] 添加并启用防护）"
		if cf_is_set; then
			panel_row " 证书方式：Cloudflare DNS（已配置 CF token）"
		else
			panel_row " 证书方式：Caddy 自动 HTTPS（需 80/443 可直达）"
		fi
		panel_section "站点管理"
		panel_option 1 "添加站点"
		panel_option 2 "删除站点"
		panel_section "证书设置"
		panel_option 3 "设置 Cloudflare API Token"
		panel_footer "返回首页"
		read -r -p "  选择 [0-3] > " choice || return
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
					rm -f -- "$f"
					echo "  Caddy 应用失败，新站点配置已移除。"
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
					else
						echo "  Caddy 应用失败，原站点配置恢复失败：$backup" >&2
					fi
					sleep 2; continue
				fi
				rm -f -- "$backup"
				echo "  已删除 $target （caddy 已应用配置）"; sleep 1 ;;
			3) panel_title "站点与证书 / Cloudflare API Token"; act_cftoken ;;
			0) return ;;
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
		local backup had_env=0 restore_rc=0
		backup="$(mktemp)" || { echo "无法备份旧 token，未修改。" >&2; pause; return 1; }
		if [ -f "$CADDY_ENV" ]; then
			cp -p -- "$CADDY_ENV" "$backup" || { rm -f -- "$backup"; echo "无法备份旧 token，未修改。" >&2; pause; return 1; }
			had_env=1
		fi
		if printf 'CF_API_TOKEN=%s\n' "$t" > "$CADDY_ENV" \
			&& chown root:caddy "$CADDY_ENV" \
			&& chmod 0640 "$CADDY_ENV" \
			&& validate_caddyfile "$CADDYFILE" >/dev/null 2>&1 \
			&& caddy_restart_active; then
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
		rm -f -- "$backup"
		if [ "$restore_rc" -eq 0 ]; then
			echo "token 保存失败，已恢复旧 .env。" >&2
		else
			echo "token 保存失败，旧 .env 恢复失败。" >&2
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
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/install.sh" "$f"; then
		if ABUSEGUARD_MIRROR="$ABUSEGUARD_MIRROR" ABUSEGUARD_NONINTERACTIVE=1 bash "$f"; then
			rm -f "$f"
			echo "更新完成，正在重新加载控制面板..."
			exec /usr/local/bin/ag
			echo "无法重新加载控制面板，请退出后重新运行 ag。"
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
	if gh_fetch "https://raw.githubusercontent.com/$ABUSEGUARD_REPO/main/uninstall.sh" "$f"; then
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
		panel_start "威胁情报"
		panel_section "情报与上报状态"
		if [ "$(reporting_state)" = on ]; then
			if [ -s "$KEYFILE" ]; then panel_row " AbuseIPDB 自动上报：${C_G}已开启${C_0}"
			else panel_row " AbuseIPDB 自动上报：${C_Y}等待配置 API Key${C_0}"; fi
		else
			panel_row " AbuseIPDB 自动上报：${C_Y}已关闭${C_0}"
		fi
		panel_section "情报同步"
		panel_option 1 "立即同步威胁情报"
		panel_section "AbuseIPDB 上报"
		panel_option 2 "立即发送上报队列"
		panel_option 3 "设置 AbuseIPDB API Key"
		panel_option 4 "开关自动上报"
		panel_footer "返回首页"
		read -r -p "  选择 [0-4] > " choice || return
		case "$choice" in
			1) panel_title "威胁情报 / 同步情报"; act_sync ;;
			2) panel_title "威胁情报 / 发送上报队列"; act_flush ;;
			3) panel_title "威胁情报 / AbuseIPDB API Key"; act_key ;;
			4) panel_title "威胁情报 / 自动上报"; act_toggle ;;
			0) return ;;
			*) echo "请输入 0–4 之间的菜单编号。"; pause ;;
		esac
	done
}

act_system() {
	local choice
	while true; do
		panel_start "系统维护"
		panel_section "运行诊断"
		panel_option 1 "查看最近日志"
		panel_section "版本维护"
		panel_option 2 "更新 AbuseGuard"
		panel_section "卸载"
		panel_option 3 "${C_R}卸载 AbuseGuard${C_0}"
		panel_footer "返回首页"
		read -r -p "  选择 [0-3] > " choice || return
		case "$choice" in
			1) panel_title "系统维护 / 最近日志"; act_logs ;;
			2) panel_title "系统维护 / 更新"; act_update ;;
			3) panel_title "系统维护 / 卸载"; act_uninstall ;;
			0) return ;;
			*) echo "请输入 0–3 之间的菜单编号。"; pause ;;
		esac
	done
}

menu() {
	local choice read_status
	header
	panel_section "功能导航"
	panel_option 1 "运行概览" "服务状态 · 站点 · 防护任务"
	panel_option 2 "站点与证书" "站点管理 · Cloudflare 证书"
	panel_option 3 "防火墙管理" "端口 · IP 封禁/解封 · 白名单"
	panel_option 4 "威胁情报" "情报同步 · 上报 · API 设置"
	panel_option 5 "系统维护" "日志 · 更新 · 卸载"
	panel_footer "退出面板" "每 ${PANEL_REFRESH_SECONDS} 秒刷新状态"
	read -r -t "$PANEL_REFRESH_SECONDS" -p "  选择 [0-5] > " choice
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
		4) act_intel ;;
		5) act_system ;;
		0) exit 0 ;;
		*) echo "请输入 0–5 之间的菜单编号。"; pause ;;
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
