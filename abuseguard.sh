#!/usr/bin/env bash
# AbuseGuard 控制面板。运行： abuseguard
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
JAILS="caddy-intel caddy-rate-local caddy-probe-h1 caddy-probe-h2"
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

C_G='\033[1;32m'; C_Y='\033[1;33m'; C_R='\033[1;31m'; C_B='\033[1;34m'; C_0='\033[0m'
pause() { echo; read -r -p "按回车继续..." _; }
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
	clear 2>/dev/null || true
	local caddy f2b intel banned rep age fresh report_status version
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
		[ -s "$KEYFILE" ] && report_status="${C_G}开${C_0}" || report_status="${C_Y}未配置 API Key${C_0}"
	else
		report_status="${C_Y}关${C_0}"
	fi
	echo -e "${C_B}=======================================================${C_0}"
	echo -e "              ${C_G}AbuseGuard v${version}${C_0}  控制面板"
	echo -e "${C_B}=======================================================${C_0}"
	printf "  caddy: %b    fail2ban: %b\n" \
		"$( [ "$caddy" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${caddy}${C_0}" )" \
		"$( [ "$f2b" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${f2b}${C_0}" )"
	printf "  情报 IP: %s %b   当前封禁: %s   上报: %b\n" \
		"$intel" "$fresh" "$banned" \
		"$report_status"
	echo -e "${C_B}-------------------------------------------------------${C_0}"
}

act_status() {
	local st n desc next d u
	echo "服务状态："
	for s in caddy fail2ban; do
		st="$(svc_state "$s")"; [ "$st" = active ] && st="运行中"
		printf "  %-12s%s\n" "$s" "$st"
	done
	echo
	echo "受保护站点（域名 → 反代上游）："
	if [ -n "$(sites_lines)" ]; then
		while IFS=$'\t' read -r d u; do [ -n "$d" ] && printf "  %-28s → %s\n" "$d" "$u"; done < <(sites_lines)
	else
		echo "  （暂无，可用菜单「站点/反代管理」添加）"
	fi
	echo
	echo "封禁 jail（各自当前封禁数）："
	for j in $JAILS; do
		n="$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:[[:space:]]*\([0-9]*\).*/\1/p')"
		[ -z "$n" ] && n="未启用"
		printf "  %-20s%s\n" "$j" "$n"
	done
	echo
	echo "定时任务："
	for u in caddy-abuseguard-report.timer caddy-abuseguard-sync.timer; do
		case "$u" in *report*) desc="上报队列冲刷" ;; *sync*) desc="威胁情报同步" ;; esac
		if [ "$(systemctl is-active "$u" 2>/dev/null)" = active ]; then
			next="$(systemctl show "$u" -p NextElapseUSecRealtime --value 2>/dev/null)"
			case "$next" in ""|0|n/a) echo "  $desc：已启用" ;; *) echo "  $desc：已启用（下次 $next）" ;; esac
		else
			echo "  $desc：未启用"
		fi
	done
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
	local ip
	read -r -p "输入要立即封禁的 IP（留空取消）: " ip
	ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
	[ -z "$ip" ] && return
	wl_valid "$ip" || { echo "  IP 格式无效。"; pause; return; }
	# 各 jail 共用同一条 nftables 封禁（drop 80/443），封任一 jail 即全局生效。
	# 用 caddy-intel：它只做防火墙 drop、不挂上报动作，手动封禁不会被自动上报到
	# AbuseIPDB（probe jail 带 queue 动作，手动封会误报一个管理员本地拉黑的 IP）。
	if fail2ban-client set caddy-intel banip "$ip" >/dev/null 2>&1; then
		echo "  已封禁 $ip。"
	else
		echo "  封禁失败（检查 jail 是否启用）。"
	fi
	pause
}

# 校验 IPv4/IPv6（可带 /前缀），宽松匹配，挡住明显错误输入
wl_valid() {
	local x="$1"
	printf '%s' "$x" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' && return 0
	printf '%s' "$x" | grep -qiE '^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(/[0-9]{1,3})?$' && return 0
	return 1
}

# 重载 fail2ban 并清 ignore 缓存，让白名单改动立即生效
wl_reload() { chown root:abuseguard "$WHITELIST" 2>/dev/null; chmod 0640 "$WHITELIST" 2>/dev/null; fail2ban-client reload >/dev/null 2>&1 || true; }

act_whitelist() {
	local -a items
	local line ip num target tmp c i
	while true; do
		clear 2>/dev/null || true
		echo -e "${C_B}== 白名单（这些 IP 永不封禁、永不上报）==${C_0}"
		echo
		items=()
		while IFS= read -r line; do
			line="${line%%#*}"; line="$(printf '%s' "$line" | tr -d '[:space:]')"
			[ -n "$line" ] && items+=("$line")
		done < "$WHITELIST"
		if [ "${#items[@]}" -eq 0 ]; then
			echo "  （空）"
		else
			for line in "${items[@]}"; do echo "  $line"; done
		fi
		echo
		echo "  [1] 添加（可批量）"
		echo "  [2] 删除"
		echo "  [3] 用编辑器打开"
		echo "  [0] 返回"
		read -r -p "请选择: " c
		case "$c" in
			1)
				echo "  批量添加：每行一个，或用空格/逗号分隔多个；输入空行结束。"
				local added=0 skipped=0 tok; local -a added_ips=()
				while IFS= read -r ip; do
					[ -z "$ip" ] && break
					ip="${ip//,/ }"
					for tok in $ip; do
						if ! wl_valid "$tok"; then echo "    跳过(格式无效)：$tok"; skipped=$((skipped+1)); continue; fi
						if grep -qxF "$tok" "$WHITELIST" 2>/dev/null; then echo "    跳过(已存在)：$tok"; skipped=$((skipped+1)); continue; fi
						printf '%s\n' "$tok" >> "$WHITELIST"; added=$((added+1)); added_ips+=("$tok"); echo "    已加：$tok"
					done
				done
				[ "$added" -gt 0 ] && wl_reload
				# reload 只影响未来判定；正被封的 IP 需显式解封才能立即放行
				[ "$added" -gt 0 ] && for tok in "${added_ips[@]}"; do fail2ban-client unban "$tok" >/dev/null 2>&1; done
				echo "  完成：新增 $added，跳过 $skipped（加白的 IP 若在封禁中已一并解封）"; sleep 1 ;;
			2)
				[ "${#items[@]}" -eq 0 ] && { echo "  没有可删除的条目"; sleep 1; continue; }
				i=1; for line in "${items[@]}"; do printf "  [%d] %s\n" "$i" "$line"; i=$((i+1)); done
				read -r -p "  输入要删除的编号: " num
				case "$num" in ''|*[!0-9]*) continue ;; esac
				if [ "$num" -lt 1 ] || [ "$num" -gt "${#items[@]}" ]; then echo "  编号超出范围"; sleep 1; continue; fi
				target="${items[$((num-1))]}"
				tmp="$(mktemp)"
				# 删掉“去注释去空格后 == target”的行，保留注释/空行/其它条目
				awk -v t="$target" '{l=$0; sub(/#.*/,"",l); gsub(/[ \t]/,"",l); if (l!=t) print}' "$WHITELIST" > "$tmp" && cat "$tmp" > "$WHITELIST"
				rm -f "$tmp"; wl_reload
				echo "  已删除：$target"; sleep 1 ;;
			3)
				"${EDITOR:-nano}" "$WHITELIST"; wl_reload ;;
			0) wl_reload; return ;;
			*) ;;
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
	local choice dom t port hp up tls f num target out d u
	local -a doms
	while true; do
		clear 2>/dev/null || true
		echo -e "${C_B}== 站点 / 反向代理（每个站点自动启用 AbuseGuard 防护）==${C_0}"
		echo
		doms=()
		while IFS=$'\t' read -r d u; do
			[ -n "$d" ] || continue
			doms+=("$d")
			printf "  %-28s → %s\n" "$d" "$u"
		done < <(sites_lines)
		[ "${#doms[@]}" -eq 0 ] && echo "  （暂无站点）"
		echo
		if cf_is_set; then
			echo "  证书方式：Cloudflare DNS（已配置 CF token）"
		else
			echo "  证书方式：Caddy 自动 HTTPS（需 80/443 可直达；在面板设 CF token 可改用 DNS）"
		fi
		echo
		echo "  [1] 添加站点"
		echo "  [2] 删除站点"
		echo "  [0] 返回"
		read -r -p "请选择: " choice
		case "$choice" in
			1)
				read -r -p "  域名（如 example.com）: " dom
				dom="$(printf '%s' "$dom" | tr -d '[:space:]')"
				domain_valid "$dom" || { echo "  域名格式无效"; sleep 1; continue; }
				[ -e "$SITES_DIR/$dom.caddy" ] && { echo "  该域名已存在"; sleep 1; continue; }
				echo "  上游类型："
				echo "  [1] 本地端口（localhost:端口）"
				echo "  [2] 远程 IP:端口"
				read -r -p "  请选择: " t
				case "$t" in
					1) read -r -p "  本地端口: " port; port="$(printf '%s' "$port" | tr -d '[:space:]')"
					   port_valid "$port" || { echo "  端口无效"; sleep 1; continue; }
					   up="localhost:$port" ;;
					2) read -r -p "  远程 IP:端口（如 10.0.0.5:8080）: " hp; hp="$(printf '%s' "$hp" | tr -d '[:space:]')"
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
				out="$("$CADDY" validate --config "$CADDYFILE" --adapter caddyfile 2>&1)"
				if [ $? -ne 0 ]; then
					rm -f "$f"
					echo "  配置校验失败，已回滚。错误："
					printf '%s\n' "$out" | grep -iE 'error|invalid' | head -3 | sed 's/^/    /'
					sleep 2; continue
				fi
				systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
				echo "  已添加 $dom → $up （caddy 已重载）"; sleep 1 ;;
			2)
				[ "${#doms[@]}" -eq 0 ] && { echo "  没有可删除的站点"; sleep 1; continue; }
				i=1; for d in "${doms[@]}"; do printf "  [%d] %s\n" "$i" "$d"; i=$((i+1)); done
				read -r -p "  输入要删除的编号: " num
				case "$num" in ''|*[!0-9]*) continue ;; esac
				if [ "$num" -lt 1 ] || [ "$num" -gt "${#doms[@]}" ]; then echo "  编号超出范围"; sleep 1; continue; fi
				target="${doms[$((num-1))]}"
				rm -f "$SITES_DIR/$target.caddy"
				systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
				echo "  已删除 $target （caddy 已重载）"; sleep 1 ;;
			0) return ;;
			*) ;;
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
		printf 'CF_API_TOKEN=%s\n' "$t" > "$CADDY_ENV"; chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
		systemctl reload caddy >/dev/null 2>&1 || systemctl restart caddy >/dev/null 2>&1 || true
		echo "已保存 token，caddy 已重载。"
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
		ABUSEGUARD_MIRROR="$ABUSEGUARD_MIRROR" ABUSEGUARD_NONINTERACTIVE=1 bash "$f" || echo "更新失败。"
		rm -f "$f"
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

menu() {
	header
	cat <<'MENU'
   [1]  状态（服务、受保护站点、jail、定时器）
   [2]  站点/反代管理（加域名→自动 import abuseguard）
   [3]  查看被封禁的 IP（按 jail）
   [4]  解封指定 IP
   [5]  立即封禁指定 IP
   [6]  编辑白名单
   [7]  立即同步威胁情报
   [8]  立即冲刷上报队列
   [9]  设置 AbuseIPDB API key
  [10]  设置 Cloudflare API token
  [11]  开关 AbuseIPDB 上报
  [12]  查看最近日志
  [13]  更新 AbuseGuard（重新运行安装器）
  [14]  卸载
   [0]  退出
MENU
	echo
	read -r -p "请选择: " choice
	case "$choice" in
		1) act_status ;;
		2) act_sites ;;
		3) act_banned ;;
		4) act_unban ;;
		5) act_ban ;;
		6) act_whitelist ;;
		7) act_sync ;;
		8) act_flush ;;
		9) act_key ;;
		10) act_cftoken ;;
		11) act_toggle ;;
		12) act_logs ;;
		13) act_update ;;
		14) act_uninstall ;;
		0) exit 0 ;;
		*) ;;
	esac
}

# The panel needs root (reads /etc/caddy-abuseguard, drives fail2ban/systemctl).
# If launched as a normal user, transparently re-exec under sudo so plain
# `abuseguard` opens the panel (prompting for a password only if sudo needs one).
if [ "$(id -u)" != "0" ]; then
	if command -v sudo >/dev/null 2>&1; then
		exec sudo -- "$0" "$@"
	fi
	echo "abuseguard 需要 root 权限——请用 root 运行，或先安装 sudo。" >&2
	exit 1
fi
while true; do menu; done
