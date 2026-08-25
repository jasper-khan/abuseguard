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
# 100 KB/s for 10s (catches throttling), hard-cap at 120s. No -S: curl stays
# quiet on failure so a slow/aborted direct attempt doesn't print scary errors.
AG_CURL="curl -fsL --connect-timeout 10 --speed-limit 102400 --speed-time 10 --max-time 120"
# For large binaries (engine ~6MB, Caddy ~40MB): same stall detection, but NO
# total-time cap — a healthy mirror at a moderate ~300KB/s must not be killed
# mid-download (40MB > 120s), which would churn the whole chain or fail outright.
AG_CURL_BIG="curl -fsL --connect-timeout 10 --speed-limit 102400 --speed-time 10"
# For the tiny SHA256SUMS.txt: no stall detection (a few hundred bytes never
# sustains 100KB/s anyway), a short hard cap, and retries. Verification is
# mandatory, so this fetch is made as robust as possible instead of optional.
AG_CURL_SUMS="curl -fsL --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 1"

# gh_fetch URL OUTFILE -- download a github.com URL to OUTFILE. Tries a direct
# download first, then a chain of mirrors, quietly (curl errors -> /dev/null),
# so the fallback is automatic and the user only sees the "downloading…" line.
gh_fetch() {
	local url="$1" out="$2" curl_cmd="${3:-$AG_CURL}" pfx
	case "$ABUSEGUARD_MIRROR" in
		""|0|off|no)
			$curl_cmd -o "$out" "$url" 2>/dev/null && return 0
			for pfx in $AG_GH_MIRRORS; do
				$curl_cmd -o "$out" "$pfx$url" 2>/dev/null && return 0
			done
			return 1 ;;
		cn|1|yes|on)
			for pfx in $AG_GH_MIRRORS; do
				$curl_cmd -o "$out" "$pfx$url" 2>/dev/null && return 0
			done
			return 1 ;;
		*)
			$curl_cmd -o "$out" "$ABUSEGUARD_MIRROR$url" 2>/dev/null ;;
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
SITES_DIR="$CADDY_ETC/sites"

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

# Write the install manifest ONCE (first install); a re-run must not overwrite
# the original pre-install snapshot.
if [ ! -f "$STATE_DIR/install-manifest" ]; then
	cat > "$STATE_DIR/install-manifest" <<EOF
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

# --- integrity: verify downloaded binaries against the release SHA256SUMS -----
# engine + Caddy come through third-party GitHub proxies, so every downloaded
# binary MUST match the release checksums. Verification is MANDATORY, not
# best-effort: if the checksums cannot be obtained we abort, rather than quietly
# installing something unverified. That is practical because the sums file is
# tiny, so it is fetched over every available route with retries: direct GitHub
# first (fine even on a throttled link), then the whole mirror chain.
# Honest limit: if you force ONE mirror for everything (ABUSEGUARD_MIRROR=<prefix>/),
# the sums travel that same path, so this guards against a passive/caching
# mirror, not an active tamperer on that single forced path.
SUMS_FILE=""
# sums_require -- fetch SHA256SUMS.txt once, on first actual need (so a
# --from-source / preset-binary install never fetches it at all). Aborts the
# install if it cannot be had; it never degrades to "skip verification".
sums_require() {
	if [ -n "$SUMS_FILE" ]; then return 0; fi
	local url="https://github.com/$ABUSEGUARD_REPO/releases/latest/download/SHA256SUMS.txt"
	local f; f="$(mktemp)"
	log "正在获取 SHA256SUMS（校验二进制用）..."
	if { $AG_CURL_SUMS -o "$f" "$url" 2>/dev/null || gh_fetch "$url" "$f" "$AG_CURL_SUMS"; } && [ -s "$f" ]; then
		SUMS_FILE="$f"
		trap 'rm -f "$SUMS_FILE"' EXIT
		return 0
	fi
	rm -f "$f"
	die "无法获取 SHA256SUMS.txt（直连与镜像均已重试）。为避免安装未经校验的二进制，安装已中止；请检查网络后重试，或用 --from-source 本地编译引擎。"
}
verify_sha256() {  # FILE BASENAME -- abort unless FILE matches the release checksum
	local file="$1" fn="$2" want got
	sums_require
	want="$(awk -v f="$fn" '$2==f || $2=="*"f {print $1; exit}' "$SUMS_FILE")"
	[ -n "$want" ] || die "SHA256SUMS.txt 里没有 $fn 的校验值，无法校验，安装已中止。"
	got="$(sha256sum "$file" 2>/dev/null | awk '{print $1}')"
	[ "$got" = "$want" ] || die "$fn 校验失败（期望 $want，实际 ${got:-空}）——可能被镜像篡改或下载损坏，已中止。"
	log "已校验 $fn（sha256 ✓）"
}

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
	local fn="caddy-abuseguard-linux-$ARCH"
	local url="https://github.com/$ABUSEGUARD_REPO/releases/latest/download/$fn"
	log "正在下载引擎（linux-$ARCH，自动选择线路，稍候）..."
	gh_fetch "$url" "$ENGINE_BIN" "$AG_CURL_BIG" \
		|| die "引擎下载失败（直连与镜像都失败）。可用 --from-source 或设置 ABUSEGUARD_ENGINE_BIN。"
	verify_sha256 "$ENGINE_BIN" "$fn"
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
# Downloaded from our own GitHub release (built by CI with xcaddy), so it gets
# the same direct-then-mirror fallback as the engine. caddyserver.com's custom
# build is not mirror-able (not github.com) and is throttled hard from CN.
need_caddy=1
if [ -x "$CADDY_BIN" ] && "$CADDY_BIN" list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
	need_caddy=0
fi
if [ "$need_caddy" = "1" ]; then
	caddy_fn="caddy-linux-$ARCH"
	log "正在下载带 cloudflare 模块的 Caddy（linux-$ARCH，自动选择线路，稍候）..."
	gh_fetch "https://github.com/$ABUSEGUARD_REPO/releases/latest/download/$caddy_fn" "$CADDY_BIN" "$AG_CURL_BIG" \
		|| die "Caddy 下载失败（直连与镜像都失败）。可预置一个带 cloudflare 模块的 caddy 到 $CADDY_BIN 后重试。"
	verify_sha256 "$CADDY_BIN" "$caddy_fn"
	chmod 0755 "$CADDY_BIN"
else
	log "已有的 Caddy 已包含 cloudflare 模块"
fi
# checksums no longer needed; drop the temp + its EXIT trap (if we fetched one)
if [ -n "$SUMS_FILE" ]; then rm -f "$SUMS_FILE"; SUMS_FILE=""; trap - EXIT; fi
setcap 'cap_net_bind_service=+ep' "$CADDY_BIN" || warn "setcap 失败；Caddy 绑定 :80/:443 可能需要 root"

# --- Caddy snippet + env + systemd unit --------------------------------------
install -m 0644 "$SRC_DIR/assets/caddy/abuseguard.caddy" "$SNIPPET"
# Panel-managed reverse-proxy sites live here, one <domain>.caddy each. The
# placeholder keeps `import sites/*.caddy` matching at least one file (an empty
# glob would fail Caddyfile adaptation).
install -d -m 0755 "$SITES_DIR"
if [ ! -e "$SITES_DIR/_placeholder.caddy" ]; then
	cat > "$SITES_DIR/_placeholder.caddy" <<'PH'
# AbuseGuard 站点目录：由面板（abuseguard → 站点/反代管理）自动管理。
# 每个反代站点一个 <域名>.caddy 文件；本占位文件请勿删除。
PH
	chmod 0644 "$SITES_DIR/_placeholder.caddy"
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
# 全局块信任你的边缘代理，使 client_ip 为真实访客 IP。
{
	servers {
		trusted_proxies static 127.0.0.1/8 ::1 ${CF_RANGES}
		trusted_proxies_strict
	}
}

# 引入一次 AbuseGuard 的日志/探测片段。
import ${SNIPPET}

# 由面板管理的反代站点（每个域名一个文件）。
import ${SITES_DIR}/*.caddy

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
	log "保留已有的 $CADDYFILE"
	if ! grep -q "$SITES_DIR" "$CADDYFILE" 2>/dev/null; then
		printf '\n# 由面板管理的反代站点\nimport %s/*.caddy\n' "$SITES_DIR" >> "$CADDYFILE"
		log "已在 Caddyfile 中加入 import sites/*.caddy"
	fi
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

# On an interactive terminal, drop straight into the control panel; otherwise
# just leave the summary above and tell the user how to open it.
if [ -z "${ABUSEGUARD_NONINTERACTIVE:-}" ] && { : </dev/tty; } 2>/dev/null; then
	echo
	log "即将进入控制面板（下次可随时运行：abuseguard）..."
	sleep 1
	exec "$PANEL_BIN" </dev/tty
fi
echo
log "运行 abuseguard 打开控制面板。"
