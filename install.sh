#!/usr/bin/env bash
# AbuseGuard installer for Debian/Ubuntu (amd64/arm64).
#
# Installs a hardened Caddy (with the caddy-dns/cloudflare DNS module),
# fail2ban jails that block abusive IPs with nftables, a threat-intel sync,
# an optional AbuseIPDB auto-reporter, and the `abuseguard` control panel.
#
# Usage:
#   sudo ./install.sh                 # download the prebuilt engine (GitHub release)
#   sudo ./install.sh --from-source   # build the Go engine here (needs `go`)
#   sudo ABUSEGUARD_ENGINE_BIN=/path/engine ./install.sh   # use a prebuilt engine
#
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ABUSEGUARD_REPO="${ABUSEGUARD_REPO:-jasper-khan/abuseguard}"

# GitHub download resiliency (matters mainly in mainland China, where direct
# github.com downloads are throttled or blocked). Default behaviour: try a
# direct download first (instant for overseas users), and only if it stalls
# fall back through a chain of public GitHub proxies until one delivers.
#   ABUSEGUARD_MIRROR unset      direct first, then auto proxy-chain fallback
#   ABUSEGUARD_MIRROR=cn         skip direct, go straight to the proxy chain
#                                (also switches the intel list to fastly.jsdelivr)
#   ABUSEGUARD_MIRROR=<prefix>/  force this one proxy prefix, no chain
ABUSEGUARD_MIRROR="${ABUSEGUARD_MIRROR:-}"
# Proxies that re-serve github.com URLs, fastest-first (benchmarked from CN).
AG_GH_MIRRORS="https://gh-proxy.com/ https://gh.ddlc.top/ https://ghproxy.net/ https://ghfast.top/"
# curl opts: give up on a dead host fast, abort if the transfer stalls under
# 100 KB/s for 10s (catches throttling), hard-cap at 120s.
AG_CURL="curl -fsSL --connect-timeout 10 --speed-limit 102400 --speed-time 10 --max-time 120"

# gh_fetch URL OUTFILE -- download a github.com URL to OUTFILE, resilient to
# CN throttling via bounded, stall-aborting attempts with proxy fallback.
gh_fetch() {
	local url="$1" out="$2" pfx
	case "$ABUSEGUARD_MIRROR" in
		""|0|off|no)
			$AG_CURL -o "$out" "$url" && return 0
			for pfx in $AG_GH_MIRRORS; do
				warn "直连下载卡住，改用镜像 ${pfx#https://}"
				$AG_CURL -o "$out" "$pfx$url" && return 0
			done
			return 1 ;;
		cn|1|yes|on)
			for pfx in $AG_GH_MIRRORS; do
				$AG_CURL -o "$out" "$pfx$url" && return 0
				warn "镜像 ${pfx#https://} 失败，尝试下一个"
			done
			return 1 ;;
		*)
			$AG_CURL -o "$out" "$ABUSEGUARD_MIRROR$url" ;;
	esac
}

CONF_DIR=/etc/caddy-abuseguard
STATE_DIR=/var/lib/caddy-abuseguard
REPORTS_DIR="$STATE_DIR/reports"
LOG_DIR=/var/log/caddy
LIBEXEC_DIR=/usr/local/libexec
ENGINE_BIN="$LIBEXEC_DIR/caddy-abuseguard"
PANEL_BIN=/usr/local/bin/abuseguard
CADDY_BIN=/usr/local/bin/caddy
CADDY_ETC=/etc/caddy
CADDY_ENV="$CADDY_ETC/.env"
CADDYFILE="$CADDY_ETC/Caddyfile"
SNIPPET="$CADDY_ETC/abuseguard.caddy"

FROM_SOURCE=0
[ "${1:-}" = "--from-source" ] && FROM_SOURCE=1

log()  { printf '\033[1;32m[abuseguard]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[abuseguard]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[abuseguard]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "请以 root 运行（sudo）。"

# --- self-bootstrap ----------------------------------------------------------
# When run detached from the repo (e.g. `curl ... install.sh | bash`), the
# asset/engine trees are missing next to this script. Fetch the repo tarball
# into a temp dir and re-exec from there so the one-command install works.
if [ ! -d "$SRC_DIR/engine" ] || [ ! -d "$SRC_DIR/assets" ]; then
	command -v tar >/dev/null 2>&1 || die "自举需要 tar 命令。"
	AG_REF="${ABUSEGUARD_REF:-main}"
	AG_TMP="$(mktemp -d)"
	trap 'rm -rf "$AG_TMP"' EXIT
	log "正在获取仓库 $ABUSEGUARD_REPO@$AG_REF ..."
	gh_fetch "https://github.com/$ABUSEGUARD_REPO/archive/refs/heads/$AG_REF.tar.gz" "$AG_TMP/repo.tar.gz" \
		|| die "自举下载失败（可设置 ABUSEGUARD_REPO / ABUSEGUARD_REF，或克隆仓库后运行 ./install.sh）。"
	tar -xzf "$AG_TMP/repo.tar.gz" -C "$AG_TMP" --strip-components=1 \
		|| die "自举解压失败。"
	rm -f "$AG_TMP/repo.tar.gz"
	export ABUSEGUARD_REPO ABUSEGUARD_REF
	# Run (not exec) the unpacked installer so the EXIT trap above still fires
	# and cleans the temp checkout; propagate its exit code.
	bash "$AG_TMP/install.sh" "$@"
	exit $?
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

# --- dependencies ------------------------------------------------------------
log "正在安装依赖（fail2ban、nftables、curl、jq、libcap2-bin）..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq fail2ban nftables curl jq ca-certificates libcap2-bin >/dev/null

# --- service accounts --------------------------------------------------------
if ! id caddy >/dev/null 2>&1; then
	log "创建系统用户 'caddy'"
	useradd --system --user-group --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy
fi
if ! id abuseguard >/dev/null 2>&1; then
	log "创建系统用户 'abuseguard'"
	useradd --system --user-group --shell /usr/sbin/nologin abuseguard
fi

# --- directories -------------------------------------------------------------
install -d -m 0755 "$LIBEXEC_DIR" "$CADDY_ETC"
install -d -m 0750 -o root -g abuseguard "$CONF_DIR"
install -d -m 0750 -o abuseguard -g abuseguard "$STATE_DIR" "$REPORTS_DIR"
install -d -m 0750 -o caddy -g caddy "$LOG_DIR"

# --- engine ------------------------------------------------------------------
install_engine() {
	if [ -n "${ABUSEGUARD_ENGINE_BIN:-}" ]; then
		[ -f "$ABUSEGUARD_ENGINE_BIN" ] || die "找不到 ABUSEGUARD_ENGINE_BIN 指定的文件 '$ABUSEGUARD_ENGINE_BIN'。"
		log "从 ABUSEGUARD_ENGINE_BIN 安装引擎"
		install -m 0755 "$ABUSEGUARD_ENGINE_BIN" "$ENGINE_BIN"
		return
	fi
	if [ "$FROM_SOURCE" = "1" ]; then
		command -v go >/dev/null 2>&1 || die "--from-source 需要 Go 工具链（请先安装 go）。"
		log "从源码编译引擎（$SRC_DIR/engine）"
		( cd "$SRC_DIR/engine" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$ENGINE_BIN" . )
		chmod 0755 "$ENGINE_BIN"
		return
	fi
	local url="https://github.com/$ABUSEGUARD_REPO/releases/latest/download/caddy-abuseguard-linux-$ARCH"
	log "正在下载引擎（linux-$ARCH）..."
	gh_fetch "$url" "$ENGINE_BIN" \
		|| die "引擎下载失败（直连与镜像都失败）。可用 --from-source 或设置 ABUSEGUARD_ENGINE_BIN。"
	chmod 0755 "$ENGINE_BIN"
}
install_engine
log "引擎：$("$ENGINE_BIN" version 2>/dev/null || echo 已安装)"

# --- config, whitelist, key (only if absent) ---------------------------------
if [ ! -f "$CONF_DIR/config.json" ]; then
	install -m 0640 -o root -g abuseguard "$SRC_DIR/assets/config/config.json.template" "$CONF_DIR/config.json"
	# In mirror mode, point the big intel blocklist at fastly.jsdelivr (the
	# commit_url stays on api.github.com, which is small and not proxied).
	if [ -n "$ABUSEGUARD_MIRROR" ] && command -v jq >/dev/null 2>&1; then
		tmp="$(mktemp)"
		jq '.intel.source_url = "https://fastly.jsdelivr.net/gh/borestad/blocklist-abuseipdb@{commit}/abuseipdb-s100-14d.ipv4"' \
			"$CONF_DIR/config.json" > "$tmp" && install -m 0640 -o root -g abuseguard "$tmp" "$CONF_DIR/config.json"
		rm -f "$tmp"
		log "镜像模式：情报源已切换到 fastly.jsdelivr"
	fi
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

# --- Caddy binary with the cloudflare DNS module -----------------------------
need_caddy=1
if [ -x "$CADDY_BIN" ] && "$CADDY_BIN" list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
	need_caddy=0
fi
if [ "$need_caddy" = "1" ]; then
	log "正在下载带 caddy-dns/cloudflare 的 Caddy（$ARCH）..."
	curl -fsSL -o "$CADDY_BIN" "https://caddyserver.com/api/download?os=linux&arch=$ARCH&p=github.com/caddy-dns/cloudflare" \
		|| die "Caddy 下载失败。"
	chmod 0755 "$CADDY_BIN"
else
	log "已有的 Caddy 已包含 cloudflare 模块"
fi
setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" || warn "setcap 失败；Caddy 绑定 :80/:443 可能需要 root"

# --- Caddy snippet + env + systemd unit --------------------------------------
install -m 0644 "$SRC_DIR/assets/caddy/abuseguard.caddy" "$SNIPPET"
if [ ! -f "$CADDY_ENV" ]; then
	printf 'CF_API_TOKEN=\n' > "$CADDY_ENV"; chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
	log "已创建 $CADDY_ENV（可在面板中设置 CF_API_TOKEN）"
fi
install -m 0644 "$SRC_DIR/assets/systemd/caddy.service" /etc/systemd/system/caddy.service

# --- Caddyfile (only if absent) ----------------------------------------------
if [ ! -f "$CADDYFILE" ]; then
	log "正在获取 Cloudflare IP 段用于 trusted_proxies..."
	CF_V4="$(curl -fsSL https://www.cloudflare.com/ips-v4 2>/dev/null || true)"
	CF_V6="$(curl -fsSL https://www.cloudflare.com/ips-v6 2>/dev/null || true)"
	CF_RANGES="$(printf '%s\n%s\n' "$CF_V4" "$CF_V6" | grep -E '[0-9a-fA-F:.]+/[0-9]+' | tr '\n' ' ' | sed 's/  */ /g; s/ *$//')"
	[ -n "$CF_RANGES" ] || warn "无法获取 Cloudflare IP 段；仅信任回环地址"
	cat > "$CADDYFILE" <<EOF
# 由 AbuseGuard install.sh 生成，可自由编辑。
#
# 全局块信任你的边缘代理，使 client_ip 为真实访客 IP。
{
	servers {
		trusted_proxies static 127.0.0.1/8 ::1 ${CF_RANGES}
		trusted_proxies_strict
	}
}

# 引入一次 AbuseGuard 的日志/探测片段。
import ${SNIPPET}

# 安装器创建的仅回环自检站点，可安全删除。
# 它在不暴露任何东西的情况下验证 日志 + fail2ban 链路是否正常。
http://127.0.0.1:8080 {
	bind 127.0.0.1
	import abuseguard
	respond "abuseguard test ok"
}

# --- 在下面添加你的真实站点，例如： ------------------------------------------
# example.com {
# 	import abuseguard
# 	tls {
# 		dns cloudflare {env.CF_API_TOKEN}
# 	}
# 	reverse_proxy localhost:3000
# }
EOF
	log "已写入 $CADDYFILE"
else
	log "保留已有的 $CADDYFILE（请自行加入 'import $SNIPPET' 和 'import abuseguard'）"
fi

# ensure the access log exists and is caddy-writable before fail2ban starts
[ -e "$LOG_DIR/abuseguard-access.json" ] || install -m 0640 -o caddy -g caddy /dev/null "$LOG_DIR/abuseguard-access.json"

# --- fail2ban assets ---------------------------------------------------------
log "正在安装 fail2ban 的 filter / action / jail"
install -m 0644 "$SRC_DIR"/assets/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/
install -m 0644 "$SRC_DIR"/assets/fail2ban/action.d/*.conf /etc/fail2ban/action.d/
install -m 0644 "$SRC_DIR/assets/fail2ban/jail.d/caddy-abuseguard.local" /etc/fail2ban/jail.d/caddy-abuseguard.local

# --- systemd timers + panel --------------------------------------------------
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.service" /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-report.timer"   /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.service"   /etc/systemd/system/
install -m 0644 "$SRC_DIR/assets/systemd/caddy-abuseguard-sync.timer"     /etc/systemd/system/
install -m 0755 "$SRC_DIR/abuseguard.sh" "$PANEL_BIN"

# --- optional interactive setup ----------------------------------------------
# Ask (y/N, default No) before prompting for each secret, so a plain Enter
# means "don't configure now". Reads from an explicitly-opened /dev/tty so it
# works under `bash <(curl ...)` and `curl | bash`; skips cleanly with no tty
# or when ABUSEGUARD_NONINTERACTIVE=1.
if [ -z "${ABUSEGUARD_NONINTERACTIVE:-}" ] && { exec 3</dev/tty; } 2>/dev/null; then
	echo
	log "可选配置（以下两项都可稍后随时用 abuseguard 面板设置）"
	printf '  现在设置 Cloudflare API token 吗？（用于自动签发 TLS 证书）[y/N] '
	IFS= read -r ans <&3 || ans=""
	case "$ans" in
		[yY]|[yY][eE][sS])
			printf '    请粘贴 Cloudflare API token（回车确认）: '
			IFS= read -r cf_token <&3 || cf_token=""
			if [ -n "$cf_token" ]; then
				printf 'CF_API_TOKEN=%s\n' "$cf_token" > "$CADDY_ENV"
				chown root:caddy "$CADDY_ENV"; chmod 0640 "$CADDY_ENV"
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
			IFS= read -r aipdb_key <&3 || aipdb_key=""
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
	log "非交互运行：跳过密钥询问（稍后用 abuseguard 面板设置）"
fi

# --- validate + enable -------------------------------------------------------
log "正在校验 Caddyfile"
"$CADDY_BIN" validate --config "$CADDYFILE" --adapter caddyfile >/dev/null || die "Caddyfile 校验失败。"

systemctl daemon-reload
log "正在启用并启动服务"
# reload-or-restart (not just enable --now) so a re-run reloads the freshly
# written Caddyfile / fail2ban jails even when the service is already running.
systemctl enable caddy >/dev/null 2>&1 || true
systemctl reload-or-restart caddy || die "caddy 启动失败（查看：journalctl -u caddy）"
systemctl enable fail2ban >/dev/null 2>&1 || true
systemctl reload-or-restart fail2ban || warn "fail2ban 未能正常启动（查看：journalctl -u fail2ban）"
systemctl enable --now caddy-abuseguard-report.timer caddy-abuseguard-sync.timer >/dev/null 2>&1 || true

log "AbuseGuard 安装完成。"
cat <<EOF

  ============================================================
    打开控制面板：  abuseguard
  ============================================================

  面板里可以：设置/修改 Cloudflare token（7）与 AbuseIPDB
  key（6）、查看封禁、同步情报、查看日志等。

  文件位置：
    Caddyfile:    $CADDYFILE
    白名单:       $CONF_DIR/whitelist
    配置:         $CONF_DIR/config.json
    访问日志:     $LOG_DIR/abuseguard-access.json

  在 $CADDYFILE 里添加你的站点（每个站点块内放
  'import abuseguard'），然后执行：sudo systemctl reload caddy

安全提示：Caddy 本身不提供鉴权。凡是你对外暴露的站点，除非自行加鉴权，
否则都是公开的。安装器自带的自检站点只绑定 127.0.0.1。
EOF
