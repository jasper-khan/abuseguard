#!/usr/bin/env bash
# Focused, deterministic regression check for assets/nginx/runtime.sh.
#
# Runs entirely in a temp fixture: no real Nginx, Certbot, systemd, network,
# /etc changes or firewall actions. It covers the uncertain lifecycle edges:
# token privacy/permissions, managed-file rendering, full-config rollback,
# reload rollback, reuse of an existing lineage, and unrelated-site preservation.
#
# Usage: scripts/test-nginx-runtime-contract.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/abuseguard-nginx-test.XXXXXX")"
cleanup() {
	if [ -n "${MASTER_PID:-}" ]; then
		pkill -P "$MASTER_PID" 2>/dev/null || true
		kill "$MASTER_PID" 2>/dev/null || true
	fi
	rm -rf -- "$TMP"
}
trap cleanup EXIT INT TERM

ok()   { printf 'ok - %s\n' "$*"; }
fail() { printf 'FAIL - %s\n' "$*" >&2; exit 1; }
expect_fail() { "$@" >/dev/null 2>&1 && fail "unexpected success: $*" || true; }

BASE="$TMP/root"
mkdir -p "$BASE/etc/nginx/conf.d" "$BASE/etc/nginx/snippets" \
	"$BASE/etc/nginx/sites-available" "$BASE/etc/nginx/sites-enabled" \
	"$BASE/var/log/nginx" "$BASE/var/lib" "$BASE/usr/local/libexec" \
	"$BASE/etc/letsencrypt/live" "$BASE/etc/logrotate.d" \
	"$BASE/etc/caddy-abuseguard" "$BASE/bin"

cat > "$BASE/bin/nginx" <<'SH'
#!/usr/bin/env bash
set -e
[ "${FAKE_NGINX_CONFIG_OK:-1}" = 1 ] || { echo "nginx: invalid config" >&2; exit 1; }
case "${1:-}" in
	-t)
		echo "nginx: configuration file test is successful" >&2
		;;
	-T)
		for f in "${NGINX_SITES_ENABLED:?}"/*; do
			[ -e "$f" ] || continue
			if [ "${FAKE_NGINX_SKIP_NAME:-}" = "${f##*/}" ]; then continue; fi
			echo "# configuration file $f:"
		done
		echo "nginx: configuration file test is successful" >&2
		;;
	*)
		echo "unexpected fake nginx args: $*" >&2
		exit 1
		;;
esac
SH
chmod 0755 "$BASE/bin/nginx"

cat > "$BASE/bin/nginx-master" <<'SH'
#!/usr/bin/env bash
# Fixture stand-in for the Nginx master: two sleeping children. SIGHUP replaces
# them, which is the observable worker-generation change the runtime requires.
children=()
spawn() {
	[ "${#children[@]}" -eq 0 ] || kill "${children[@]}" 2>/dev/null || true
	sleep 300 & children=("$!")
	sleep 300 & children+=("$!")
}
trap spawn HUP
spawn
printf '%s\n' "$$" > "${FAKE_MASTER_PID_FILE:?}"
while :; do wait; done
SH
chmod 0755 "$BASE/bin/nginx-master"

cat > "$BASE/bin/systemctl" <<'SH'
#!/usr/bin/env bash
case "$*" in
	"show -p MainPID --value nginx")
		[ -s "${FAKE_MASTER_PID_FILE:?}" ] || exit 1
		cat "$FAKE_MASTER_PID_FILE"
		exit 0
		;;
	"is-active nginx") echo active; exit 0 ;;
	"reload nginx")
		[ "${FAKE_RELOAD_FAIL:-0}" = 1 ] && exit 1
		[ "${FAKE_RELOAD_NOOP:-0}" = 1 ] && exit 0
		if [ -n "${FAKE_RELOAD_NOOP_NAME:-}" ] \
			&& [ -e "${NGINX_SITES_ENABLED:?}/$FAKE_RELOAD_NOOP_NAME" ]; then
			exit 0
		fi
		if [ -e "${FAKE_RELOAD_DRAIN_FILE:-}" ]; then
			rm -f -- "$FAKE_RELOAD_DRAIN_FILE"
			kill "$(pgrep -P "$(cat "$FAKE_MASTER_PID_FILE")" | head -n 1)"
			exit 0
		fi
		kill -HUP "$(cat "$FAKE_MASTER_PID_FILE")"
		exit 0
		;;
esac
exit 1
SH
chmod 0755 "$BASE/bin/systemctl"

cat > "$BASE/bin/certbot" <<'SH'
#!/usr/bin/env bash
set -e
printf '%s\n' "$*" >> "${FAKE_CERTBOT_LOG:?}"
[ "${FAKE_CERTBOT_FAIL:-0}" = 1 ] && exit 1
certname=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		--cert-name) certname="$2"; shift 2 ;;
		*) shift ;;
	esac
done
[ -n "$certname" ] || exit 1
mkdir -p "${NGINX_LETSENCRYPT_DIR:?}/live/$certname"
printf 'cert\n' > "$NGINX_LETSENCRYPT_DIR/live/$certname/fullchain.pem"
printf 'key\n' > "$NGINX_LETSENCRYPT_DIR/live/$certname/privkey.pem"
SH
chmod 0755 "$BASE/bin/certbot"

source "$ROOT/assets/nginx/runtime.sh"

# Override every path/command used by the library (documented in
# local://nginx-runtime-notes.md). All writes stay under $BASE.
NGINX_ETC="$BASE/etc/nginx"
NGINX_CONFD_DIR="$NGINX_ETC/conf.d"
NGINX_SNIPPETS_DIR="$NGINX_ETC/snippets"
NGINX_SITES_AVAILABLE="$NGINX_ETC/sites-available"
NGINX_SITES_ENABLED="$NGINX_ETC/sites-enabled"
NGINX_HTTP_CONF="$NGINX_CONFD_DIR/abuseguard.conf"
NGINX_SELFTEST_CONF="$NGINX_CONFD_DIR/zz-abuseguard-selftest.conf"
NGINX_CF_TRUST_INCLUDE="$NGINX_SNIPPETS_DIR/abuseguard-cloudflare.conf"
NGINX_LOG_DIR="$BASE/var/log/nginx"
NGINX_ACCESS_LOG="$NGINX_LOG_DIR/abuseguard-access.json"
NGINX_LOGROTATE="$BASE/etc/logrotate.d/abuseguard-nginx"
NGINX_LETSENCRYPT_DIR="$BASE/etc/letsencrypt"
NGINX_LIBEXEC_DIR="$BASE/usr/local/libexec"
NGINX_DEPLOY_HOOK="$NGINX_LIBEXEC_DIR/abuseguard-nginx-deploy"
NGINX_RUNTIME_PATH="$NGINX_LIBEXEC_DIR/abuseguard-nginx.sh"
NGINX_BIN="$BASE/bin/nginx"
NGINX_SYSTEMCTL="$BASE/bin/systemctl"
CERTBOT_BIN="$BASE/bin/certbot"
NGINX_CF_LIVE=0
AG_NGINX_CONF_DIR="$BASE/etc/caddy-abuseguard"
AG_NGINX_CF_CREDENTIALS="$AG_NGINX_CONF_DIR/cloudflare.ini"
FAKE_CERTBOT_LOG="$TMP/certbot.args"
FAKE_NGINX_CONFIG_OK=1
FAKE_RELOAD_FAIL=0
FAKE_RELOAD_NOOP=0
FAKE_RELOAD_NOOP_NAME=""
FAKE_RELOAD_DRAIN_FILE="$TMP/reload-drain"
FAKE_NGINX_SKIP_NAME=""
FAKE_MASTER_PID_FILE="$TMP/nginx-master.pid"
export FAKE_CERTBOT_LOG FAKE_NGINX_CONFIG_OK FAKE_RELOAD_FAIL FAKE_RELOAD_NOOP \
	FAKE_RELOAD_NOOP_NAME FAKE_RELOAD_DRAIN_FILE FAKE_NGINX_SKIP_NAME \
	FAKE_MASTER_PID_FILE NGINX_SITES_ENABLED NGINX_LETSENCRYPT_DIR

"$BASE/bin/nginx-master" &
MASTER_PID=$!
for _ in $(seq 1 50); do
	[ -s "$FAKE_MASTER_PID_FILE" ] && break
	sleep 0.1
done
[ -s "$FAKE_MASTER_PID_FILE" ] || fail "fake nginx master did not start"
[ -n "$(pgrep -P "$MASTER_PID" 2>/dev/null)" ] || fail "fake nginx master has no workers"

if nginx_token_is_set; then fail "token reported as set before any write"; fi
ok "token starts unset"

# --- asset rendering --------------------------------------------------------
nginx_install_assets "$ROOT" || fail "install_assets failed"
for f in "$NGINX_HTTP_CONF" "$NGINX_CF_TRUST_INCLUDE" "$NGINX_SELFTEST_CONF" \
	"$NGINX_LOGROTATE" "$NGINX_DEPLOY_HOOK" "$NGINX_RUNTIME_PATH"; do
	[ -f "$f" ] || fail "install_assets did not create $f"
done
[ -x "$NGINX_DEPLOY_HOOK" ] || fail "deploy hook is not executable"
[ -x "$NGINX_RUNTIME_PATH" ] || fail "installed runtime is not executable"
grep -q 'log_format abuseguard_json escape=json' "$NGINX_HTTP_CONF" || fail "JSON log format missing"
grep -q 'caddy_abuseguard_site":"protected"' "$NGINX_HTTP_CONF" || fail "site tag missing"
grep -q 'caddy_abuseguard_probe' "$NGINX_HTTP_CONF" || fail "probe tag missing"
grep -q 'set_real_ip_from 173.245.48.0/20' "$NGINX_CF_TRUST_INCLUDE" || fail "fallback CF IPv4 range missing"
grep -q 'set_real_ip_from 2a06:98c0::/29' "$NGINX_CF_TRUST_INCLUDE" || fail "fallback CF IPv6 range missing"
grep -q 'set_real_ip_from 0.0.0.0/0' "$NGINX_CF_TRUST_INCLUDE" && fail "trust-all IPv4 range installed" || true
grep -q 'set_real_ip_from ::/0' "$NGINX_CF_TRUST_INCLUDE" && fail "trust-all IPv6 range installed" || true
grep -q 'listen 127.0.0.1:8080' "$NGINX_SELFTEST_CONF" || fail "selftest is not loopback-only"
grep -q 'listen 80' "$NGINX_SELFTEST_CONF" && fail "selftest listens on port 80" || true
grep -q 'dns_cloudflare_api_token' "$NGINX_HTTP_CONF" && fail "secret leaked into nginx conf" || true
filtered="$(printf '%s\n' '0.0.0.0/0' '::/0' '1.2.3.4/33' '1.2.3.4' \
	'evil;include /etc/passwd' '173.245.48.0/20' | _nginx_cf_filter)"
[ "$filtered" = '173.245.48.0/20' ] || fail "CF CIDR filter accepted unsafe input: $filtered"
ok "CF trust filter rejects trust-all and malformed/injection ranges"

# --- unrelated site preservation fixture -----------------------------------
printf 'server { listen 8443; }\n' > "$NGINX_SITES_AVAILABLE/other.conf"
ln -s "$NGINX_SITES_AVAILABLE/other.conf" "$NGINX_SITES_ENABLED/other.conf"

# --- token-missing add fails before cert/nginx work -------------------------
if nginx_add_site no-token.example 127.0.0.1:3000 >/dev/null 2>&1; then
	fail "add succeeded without a token"
fi
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-no-token.example.conf" ] || fail "file left without token"
[ ! -e "$FAKE_CERTBOT_LOG" ] || fail "certbot ran without a token"
ok "missing token fails before certificate or Nginx work"

# --- token handling ---------------------------------------------------------
expect_fail nginx_save_token $'bad\ntoken'
if [ -e "$AG_NGINX_CF_CREDENTIALS" ]; then fail "multiline token created a file"; fi
out="$(nginx_save_token 'cf-token_TEST-123' 2>&1)" || fail "save_token failed: $out"
case "$out" in *cf-token*) fail "save_token leaked the token to output" ;; esac
grep -qx 'dns_cloudflare_api_token = cf-token_TEST-123' "$AG_NGINX_CF_CREDENTIALS" \
	|| fail "credential format wrong"
case "$(ls -l "$AG_NGINX_CF_CREDENTIALS" | cut -c1-10)" in
	-rw-------) ;;
	*) fail "credential file is not 0600" ;;
esac
nginx_token_is_set || fail "token not reported as set"
ok "token is root-only and never echoed"

# --- validation rejects injection -----------------------------------------
expect_fail nginx_add_site 'evil.example;' 127.0.0.1:3000
expect_fail nginx_add_site evil2.example '127.0.0.1:3000;'
expect_fail nginx_add_site 'evil3.example' 'http://127.0.0.1:3000'
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-evil.example.conf" ] || fail "injected domain created a file"
ok "domain/upstream injection rejected"

# --- add site: cert, config, reload ---------------------------------------
out="$(nginx_add_site Example.COM 127.0.0.1:3000 2>&1)" || fail "add_site failed: $out"
AVAIL="$NGINX_SITES_AVAILABLE/abuseguard-example.com.conf"
ENABLED="$NGINX_SITES_ENABLED/abuseguard-example.com.conf"
[ -f "$AVAIL" ] || fail "managed site file missing"
[ -L "$ENABLED" ] || fail "managed site is not enabled by symlink"
grep -q 'server_name example.com;' "$AVAIL" || fail "domain not normalized into server_name"
grep -q 'listen 443 ssl http2;' "$AVAIL" || fail "TLS listener missing"
grep -q 'listen \[::\]:443 ssl http2;' "$AVAIL" || fail "IPv6 TLS listener missing"
grep -q 'proxy_pass http://127.0.0.1:3000;' "$AVAIL" || fail "upstream proxy_pass wrong"
grep -q 'client_max_body_size 0;' "$AVAIL" || fail "default upload limit not disabled"
grep -q 'if (\$http_host = "") {' "$AVAIL" || fail "missing Host rejection missing"
grep -q 'if (\$host != example.com) {' "$AVAIL" || fail "unknown Host rejection missing"
grep -Fq 'if ($ssl_server_name !~* ^example\.com$) {' "$AVAIL" || fail "case-insensitive SNI/Host mismatch rejection missing"
grep -q 'return 404;' "$AVAIL" || fail "unknown Host does not return 404"
grep -q 'proxy_set_header Host \$http_host;' "$AVAIL" || fail "Host is not forwarded with its original port"
grep -q 'proxy_set_header X-Forwarded-Host \$http_host;' "$AVAIL" || fail "X-Forwarded-Host is not Caddy-compatible"
grep -q 'proxy_set_header X-Forwarded-For \$remote_addr;' "$AVAIL" || fail "XFF is not overwritten with trusted client"
grep -q 'listen 80' "$AVAIL" && fail "managed site listens on port 80" || true
grep -q 'access_log .*combined' "$AVAIL" && fail "managed site has a second combined log" || true
grep -q -- '--dns-cloudflare' "$FAKE_CERTBOT_LOG" || fail "certbot did not use DNS-01"
grep -q -- '--cert-name abuseguard-example.com' "$FAKE_CERTBOT_LOG" || fail "cert name is not abuseguard-<domain>"
grep -q -- '--deploy-hook' "$FAKE_CERTBOT_LOG" || fail "renewal deploy hook not saved"
grep -qE -- '--nginx|--standalone|--webroot' "$FAKE_CERTBOT_LOG" && fail "HTTP-01 challenge mode used" || true
[ "$(nginx_sites_lines)" = $'example.com\t127.0.0.1:3000' ] || fail "sites_lines output wrong"
ok "site add issues DNS-01, validates, enables and reloads"

# duplicate add is refused and does not mint another cert
certs_before="$(wc -l < "$FAKE_CERTBOT_LOG")"
expect_fail nginx_add_site example.com 127.0.0.1:3001
[ "$(wc -l < "$FAKE_CERTBOT_LOG")" = "$certs_before" ] || fail "duplicate add invoked certbot"
ok "duplicate site add refused without certificate churn"

# --- candidate config rollback --------------------------------------------
FAKE_NGINX_CONFIG_OK=0
if nginx_add_site rollback.example 127.0.0.1:3001 >/dev/null 2>&1; then
	fail "add succeeded despite failed full-config validation"
fi
FAKE_NGINX_CONFIG_OK=1
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-rollback.example.conf" ] || fail "rollback left site file"
[ ! -L "$NGINX_SITES_ENABLED/abuseguard-rollback.example.conf" ] || fail "rollback left enabled symlink"
[ -f "$NGINX_LETSENCRYPT_DIR/live/abuseguard-rollback.example/fullchain.pem" ] \
	|| fail "rollback should retain issued cert material"
ok "failed full-config validation leaves no half-enabled site"

# --- candidate-not-loaded rollback ----------------------------------------
FAKE_NGINX_SKIP_NAME="abuseguard-notloaded.example.conf"
if nginx_add_site notloaded.example 127.0.0.1:3001 >/dev/null 2>&1; then
	fail "add succeeded though its site was not loaded by nginx -T"
fi
FAKE_NGINX_SKIP_NAME=""
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-notloaded.example.conf" ] || fail "unloaded candidate left site file"
[ ! -L "$NGINX_SITES_ENABLED/abuseguard-notloaded.example.conf" ] || fail "unloaded candidate left symlink"
ok "candidate missing from nginx -T is rolled back"

# --- reload rollback -------------------------------------------------------
FAKE_RELOAD_FAIL=1
if nginx_add_site reload.example 127.0.0.1:3001 >/dev/null 2>&1; then
	fail "add succeeded despite failed reload"
fi
FAKE_RELOAD_FAIL=0
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-reload.example.conf" ] || fail "reload rollback left site file"
[ ! -L "$NGINX_SITES_ENABLED/abuseguard-reload.example.conf" ] || fail "reload rollback left symlink"
ok "failed reload removes the new site and keeps prior config"

# --- false-success reload regression ---------------------------------------
# The unit reports success but the old workers keep serving (this is what a
# failed bind looks like). The add must fail and roll back instead of claiming
# an applied config. The rollback reload then succeeds because the candidate is
# gone, so this guard costs one bounded poll.
FAKE_RELOAD_NOOP_NAME="abuseguard-bindcollision.example.conf"
if out="$(nginx_add_site bindcollision.example 127.0.0.1:3002 2>&1)"; then
	fail "add claimed success although the reload never took effect: $out"
fi
FAKE_RELOAD_NOOP_NAME=""
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-bindcollision.example.conf" ] \
	|| fail "ineffective reload left the site file"
[ ! -L "$NGINX_SITES_ENABLED/abuseguard-bindcollision.example.conf" ] \
	|| fail "ineffective reload left the enabled symlink"
ok "reload rc 0 without worker turnover fails and rolls the site back"

# --- draining-worker reload regression -------------------------------------
# The reload command succeeds but merely kills one existing worker and starts
# none (the failed-bind aftermath while an old worker drains a request); the
# other worker, the master and `active` state remain. A removal-only change
# must not be accepted as a new generation.
touch "$FAKE_RELOAD_DRAIN_FILE"
if out="$(nginx_add_site drainonly.example 127.0.0.1:3002 2>&1)"; then
	fail "add claimed success although the reload only lost an old worker: $out"
fi
[ ! -e "$NGINX_SITES_AVAILABLE/abuseguard-drainonly.example.conf" ] \
	|| fail "removal-only reload left the site file"
[ ! -L "$NGINX_SITES_ENABLED/abuseguard-drainonly.example.conf" ] \
	|| fail "removal-only reload left the enabled symlink"
ok "reload rc 0 that only removes a draining worker fails and rolls back"

# --- standalone deploy hook keeps the same truthfulness --------------------
PATH="$BASE/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1 \
	|| fail "deploy hook failed on a healthy reload"
FAKE_RELOAD_NOOP=1
if PATH="$BASE/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1; then
	fail "deploy hook claimed success although the reload never took effect"
fi
FAKE_RELOAD_NOOP=0
touch "$FAKE_RELOAD_DRAIN_FILE"
if PATH="$BASE/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1; then
	fail "deploy hook claimed success although the reload only lost a draining worker"
fi
ok "deploy hook inherits the removal-only failure"
# Conservative uninstall removes the helper but keeps the hook; the hook must
# stay self-contained and keep this check.
rm -f -- "$NGINX_RUNTIME_PATH"
PATH="$BASE/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1 \
	|| fail "deploy hook depends on the removed runtime helper"
ok "deploy hook confirms reloads and stays standalone after uninstall"

# --- status output is local-only -------------------------------------------
out="$(nginx_certificate_status)" || fail "certificate status failed"
printf '%s\n' "$out" | grep -q $'^example.com\t\tmissing$' \
	|| fail "certificate status output wrong: $out"
ok "certificate status reports managed certs without network calls"

# --- delete keeps certs and unrelated sites --------------------------------
nginx_delete_site example.com >/dev/null || fail "delete_site failed"
[ ! -e "$AVAIL" ] || fail "delete left site file"
[ ! -L "$ENABLED" ] || fail "delete left enabled symlink"
[ -f "$NGINX_LETSENCRYPT_DIR/live/abuseguard-example.com/fullchain.pem" ] \
	|| fail "delete removed certificate material"
[ -L "$NGINX_SITES_ENABLED/other.conf" ] || fail "delete touched an unrelated site"
[ -z "$(nginx_sites_lines)" ] || fail "deleted site still listed"
expect_fail nginx_delete_site example.com
ok "delete disables/removes only the managed site and retains its certificate"

printf '\nAll Nginx runtime contract checks passed.\n'
