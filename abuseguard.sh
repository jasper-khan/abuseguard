#!/usr/bin/env bash
# AbuseGuard 控制面板。运行： abuseguard
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

header() {
	clear 2>/dev/null || true
	local caddy f2b intel banned rep
	caddy="$(svc_state caddy)"; f2b="$(svc_state fail2ban)"
	intel="$( [ -f "$INTEL" ] && wc -l < "$INTEL" | tr -d ' ' || echo 0 )"
	banned="$(count_banned)"; rep="$(reporting_state)"
	echo -e "${C_B}=======================================================${C_0}"
	echo -e "                 ${C_G}AbuseGuard${C_0}  控制面板"
	echo -e "${C_B}=======================================================${C_0}"
	printf "  caddy: %b    fail2ban: %b\n" \
		"$( [ "$caddy" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${caddy}${C_0}" )" \
		"$( [ "$f2b" = active ] && echo "${C_G}运行中${C_0}" || echo "${C_R}${f2b}${C_0}" )"
	printf "  情报 IP: %s    当前封禁: %s    上报: %b\n" \
		"$intel" "$banned" \
		"$( [ "$rep" = on ] && echo "${C_G}开${C_0}" || echo "${C_Y}关${C_0}" )"
	echo -e "${C_B}-------------------------------------------------------${C_0}"
}

act_status() {
	local st n desc next
	echo "服务状态："
	for s in caddy fail2ban; do
		st="$(svc_state "$s")"; [ "$st" = active ] && st="运行中"
		printf "  %-12s%s\n" "$s" "$st"
	done
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
			i=1; for line in "${items[@]}"; do printf "  %2d) %s\n" "$i" "$line"; i=$((i+1)); done
		fi
		echo
		echo "  a) 添加    d) 删除    e) 用编辑器打开    0) 返回"
		read -r -p "请选择: " c
		case "$c" in
			a|A)
				read -r -p "  输入要放行的 IP 或 CIDR（如 1.2.3.4 或 10.0.0.0/8）: " ip
				ip="$(printf '%s' "$ip" | tr -d '[:space:]')"
				[ -z "$ip" ] && continue
				if ! wl_valid "$ip"; then echo "  格式无效：$ip"; sleep 1; continue; fi
				if grep -qxF "$ip" "$WHITELIST" 2>/dev/null; then echo "  已存在：$ip"; sleep 1; continue; fi
				printf '%s\n' "$ip" >> "$WHITELIST"; wl_reload
				echo "  已添加：$ip"; sleep 1 ;;
			d|D)
				[ "${#items[@]}" -eq 0 ] && { echo "  没有可删除的条目"; sleep 1; continue; }
				read -r -p "  输入要删除的编号: " num
				case "$num" in ''|*[!0-9]*) continue ;; esac
				if [ "$num" -lt 1 ] || [ "$num" -gt "${#items[@]}" ]; then echo "  编号超出范围"; sleep 1; continue; fi
				target="${items[$((num-1))]}"
				tmp="$(mktemp)"
				# 删掉“去注释去空格后 == target”的行，保留注释/空行/其它条目
				awk -v t="$target" '{l=$0; sub(/#.*/,"",l); gsub(/[ \t]/,"",l); if (l!=t) print}' "$WHITELIST" > "$tmp" && cat "$tmp" > "$WHITELIST"
				rm -f "$tmp"; wl_reload
				echo "  已删除：$target"; sleep 1 ;;
			e|E)
				"${EDITOR:-nano}" "$WHITELIST"; wl_reload ;;
			0) wl_reload; return ;;
			*) ;;
		esac
	done
}

act_sync()  { runuser -u abuseguard -- "$ENGINE" sync-intel; pause; }
act_flush() { runuser -u abuseguard -- "$ENGINE" report send-auto; pause; }

act_key() {
	read -r -p "AbuseIPDB API key（留空=保持当前）: " k
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
		ABUSEGUARD_MIRROR="$ABUSEGUARD_MIRROR" bash "$f" || echo "更新失败。"
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
   1) 状态（服务、jail、定时器）
   2) 查看被封禁的 IP（按 jail）
   3) 编辑白名单
   4) 立即同步威胁情报
   5) 立即冲刷上报队列
   6) 设置 AbuseIPDB API key
   7) 设置 Cloudflare API token
   8) 开关 AbuseIPDB 上报
   9) 查看最近日志
  10) 更新 AbuseGuard（重新运行安装器）
  11) 卸载
   0) 退出
MENU
	echo
	read -r -p "请选择: " choice
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
