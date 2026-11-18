#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
FUNCTIONS="$TMP/functions.sh"
UNINSTALL_FUNCTIONS="$TMP/uninstall-functions.sh"
OLD_BIN="$TMP/old-bin"
OLD_EXPECTED="$TMP/old-expected"
BAD_BIN="$TMP/bad-bin"
BROKEN_BIN="$TMP/broken-bin"
GOOD_BIN="$TMP/good-bin"
SUMS_FILE="$TMP/SHA256SUMS.txt"
ENGINE_BUILD="$TMP/engine"
CADDY_MOCK="$TMP/caddy-mock"
CADDY_CONFIG="$TMP/Caddyfile"
CADDY_ENV_TEST="$TMP/caddy.env"
CADDY_ENV_EXPECTED="$TMP/caddy.env.expected"
TOKEN_CAPTURE="$TMP/token-capture"
SYSTEMCTL_LOG="$TMP/systemctl.log"
SITES_TEST="$TMP/sites"
SITE_EXPECTED="$TMP/site.expected"
CONF_TEST="$TMP/conf"
WHITELIST_EXPECTED="$TMP/whitelist-expected"
NGINX_RUNTIME_TEST="$TMP/nginx-runtime.sh"
NGINX_TOKEN_CAPTURE="$TMP/nginx-token"
NGINX_ADD_CAPTURE="$TMP/nginx-add"
NGINX_DELETE_CAPTURE="$TMP/nginx-delete"
NGINX_SITES_FIXTURE="$TMP/nginx-sites"
INVALID_CANDIDATE=""
VALID_CANDIDATE=""

cleanup() {
	[ -z "$INVALID_CANDIDATE" ] || rm -f -- "$INVALID_CANDIDATE"
	[ -z "$VALID_CANDIDATE" ] || rm -f -- "$VALID_CANDIDATE"
	rm -f -- "$FUNCTIONS"
	rm -f -- "$UNINSTALL_FUNCTIONS"
	rm -f -- "$OLD_BIN"
	rm -f -- "$OLD_EXPECTED"
	rm -f -- "$BAD_BIN"
	rm -f -- "$BROKEN_BIN"
	rm -f -- "$GOOD_BIN"
	rm -f -- "$SUMS_FILE"
	rm -f -- "$ENGINE_BUILD"
	rm -f -- "$CADDY_MOCK"
	rm -f -- "$CADDY_CONFIG"
	rm -f -- "$CADDY_ENV_TEST"
	rm -f -- "$CADDY_ENV_EXPECTED"
	rm -f -- "$TOKEN_CAPTURE"
	rm -f -- "$SYSTEMCTL_LOG"
	rm -f -- "$SITES_TEST/example.com.caddy"
	rm -f -- "$SITES_TEST/existing.example.com.caddy"
	rm -f -- "$SITE_EXPECTED"
	rmdir -- "$SITES_TEST" 2>/dev/null || true
	rm -f -- "$WHITELIST_EXPECTED"
	rm -f -- "$CONF_TEST/whitelist"
	rm -f -- "$CONF_TEST/web-server"
	rm -f -- "$NGINX_RUNTIME_TEST"
	rm -f -- "$NGINX_TOKEN_CAPTURE"
	rm -f -- "$NGINX_ADD_CAPTURE"
	rm -f -- "$NGINX_DELETE_CAPTURE"
	rm -f -- "$NGINX_SITES_FIXTURE"
	rmdir -- "$CONF_TEST" 2>/dev/null || true
	rmdir -- "$TMP/bootstrap" 2>/dev/null || true
	rmdir -- "$TMP"
}
trap cleanup EXIT

extract_function() {
	local name="$1" file="$2"
	awk -v signature="$name() {" '
		index($0, signature) == 1 { printing=1 }
		printing { print }
		printing && /^}$/ { exit }
	' "$file"
}

fail() {
	printf 'review-fix test failed: %s\n' "$*" >&2
	exit 1
}

# The generic installer helper must stage, verify, probe, and only then replace.
extract_function verify_sha256 "$ROOT/install.sh" > "$FUNCTIONS"
extract_function stage_release_binary "$ROOT/install.sh" >> "$FUNCTIONS"
extract_function commit_staged_binary "$ROOT/install.sh" >> "$FUNCTIONS"
extract_function install_release_binary "$ROOT/install.sh" >> "$FUNCTIONS"
extract_function latest_release_tag "$ROOT/install.sh" >> "$FUNCTIONS"
extract_function release_asset "$ROOT/install.sh" >> "$FUNCTIONS"
# shellcheck disable=SC1090
source "$FUNCTIONS"
log() { :; }
warn() { :; }
sums_require() { :; }
AG_CURL_BIG=:
gh_fetch() {
	cp -- "$DOWNLOAD_SOURCE" "$2"
	[ "${FETCH_RESULT:-0}" = 0 ]
}
write_sum() {
	sha256sum "$1" | awk -v name=test-name '{print $1 "  " name}' > "$SUMS_FILE"
}

# Resolve latest once, then use the same tag even if latest moves meanwhile.
ABUSEGUARD_REPO=jasper-khan/abuseguard
curl() { printf '%s' "$LATEST_URL"; return "${CURL_RESULT:-0}"; }
LATEST_URL="https://github.com/$ABUSEGUARD_REPO/releases/tag/v0.3.33"
RELEASE_TAG="$(latest_release_tag)" || fail "latest release was not resolved"
[ "$RELEASE_TAG" = v0.3.33 ] || fail "wrong release tag"
LATEST_URL="https://github.com/$ABUSEGUARD_REPO/releases/tag/v0.3.34"
[ "$(release_asset test-name)" = "https://github.com/$ABUSEGUARD_REPO/releases/download/v0.3.33/test-name" ] \
	|| fail "asset download followed a moving latest release"
LATEST_URL="https://github.com/$ABUSEGUARD_REPO/releases"
if latest_release_tag; then fail "missing release tag was accepted"; fi
CURL_RESULT=1
if latest_release_tag; then fail "failed latest lookup was accepted"; fi
CURL_RESULT=0
LATEST_URL="https://github.com/$ABUSEGUARD_REPO/releases/tag/not-a-tag"
if latest_release_tag; then fail "malformed release tag was accepted"; fi
unset -f curl

# Exercise the actual bootstrap with a local checkout present. It must still
# choose release source, and pass the selected tag into the child installer.
mkdir "$TMP/bootstrap"
(
	SRC_DIR="$ROOT"
	FROM_SOURCE=0
	unset ABUSEGUARD_RELEASE_TAG ABUSEGUARD_ENGINE_BIN
	latest_release_tag() { printf v0.3.33; }
	mktemp() { printf '%s\n' "$TMP/bootstrap"; }
	cleanup_temp_tree() { :; }
	gh_fetch() {
		case "$1" in "https://github.com/$ABUSEGUARD_REPO/archive/refs/tags/v0.3.33.tar.gz") return 0 ;; esac
		fail "bootstrap did not select the release archive"
	}
	tar() { :; }
	bash() {
		[ "$ABUSEGUARD_RELEASE_TAG" = v0.3.33 ] || fail "child installer lost the selected release"
		[ "$1" = "$TMP/bootstrap/install.sh" ] || fail "wrong child installer"
	}
	die() { fail "$*"; }
	source <(awk '/^RELEASE_TAG=/{printing=1} /^# --- OS /{exit} printing {print}' "$ROOT/install.sh")
	fail "default install used the local checkout"
) || fail "release bootstrap failed"
rmdir "$TMP/bootstrap"

printf '#!/usr/bin/env bash\nprintf "old\\n"\n' > "$OLD_BIN"
cp -- "$OLD_BIN" "$OLD_EXPECTED"
printf 'corrupt download\n' > "$BAD_BIN"
printf '#!/usr/bin/env bash\nexit 1\n' > "$BROKEN_BIN"
printf '#!/usr/bin/env bash\nprintf "new\\n"\n' > "$GOOD_BIN"
chmod 0755 "$OLD_BIN" "$BAD_BIN" "$BROKEN_BIN" "$GOOD_BIN"

DOWNLOAD_SOURCE="$BAD_BIN" FETCH_RESULT=1
if install_release_binary test-url "$OLD_BIN" test-name test-label; then
	fail "download failure was accepted"
fi
cmp "$OLD_EXPECTED" "$OLD_BIN" || fail "download failure replaced the old binary"

write_sum "$GOOD_BIN"
DOWNLOAD_SOURCE="$BAD_BIN" FETCH_RESULT=0
if install_release_binary test-url "$OLD_BIN" test-name test-label; then
	fail "checksum failure was accepted"
fi
cmp "$OLD_EXPECTED" "$OLD_BIN" || fail "checksum failure replaced the old binary"

write_sum "$BROKEN_BIN"
DOWNLOAD_SOURCE="$BROKEN_BIN"
if install_release_binary test-url "$OLD_BIN" test-name test-label; then
	fail "startup-check failure was accepted"
fi
cmp "$OLD_EXPECTED" "$OLD_BIN" || fail "startup-check failure replaced the old binary"

write_sum "$GOOD_BIN"
DOWNLOAD_SOURCE="$GOOD_BIN"
if install_release_binary test-url "$OLD_BIN" test-name test-label 0.3.33; then
	fail "wrong engine version was accepted"
fi
cmp "$OLD_EXPECTED" "$OLD_BIN" || fail "version mismatch replaced the old binary"
install_release_binary test-url "$OLD_BIN" test-name test-label \
	|| fail "valid binary was not installed"
[ "$("$OLD_BIN" version)" = new ] || fail "valid binary did not replace the old binary"
printf '#!/usr/bin/env bash\nprintf "abuseguard-engine 0.3.33\\n"\n' > "$GOOD_BIN"
write_sum "$GOOD_BIN"
install_release_binary test-url "$OLD_BIN" test-name test-label 0.3.33 \
	|| fail "matching engine version was rejected"
[ "$("$OLD_BIN" version)" = 'abuseguard-engine 0.3.33' ] || fail "matching engine was not installed"
find "$TMP" -maxdepth 1 -name '.*.tmp.*' -print -quit | grep -q . \
	&& fail "installer left a staged binary behind"

# The Caddy release download must not reuse the engine's staging slot: the
# engine is staged first, committed only after fail2ban is paused.
STAGED_BIN="$TMP/engine.staged"
printf 'staged engine\n' > "$STAGED_BIN"
write_sum "$GOOD_BIN"
DOWNLOAD_SOURCE="$GOOD_BIN"
install_release_binary test-url "$OLD_BIN" test-name test-label \
	|| fail "release install next to a staged engine failed"
[ "$STAGED_BIN" = "$TMP/engine.staged" ] && [ -f "$STAGED_BIN" ] \
	|| fail "release binary install clobbered the staged engine"
rm -f -- "$STAGED_BIN"
STAGED_BIN=""

# Build the real engine so panel validation is tested against its parser.
(cd "$ROOT/engine" && go build -o "$ENGINE_BUILD" .)

# The engine removed the enqueue --mode flag; fail2ban must not keep sending it.
if grep -q -- '--mode' "$ROOT/assets/fail2ban/action.d/caddy-abuseguard-queue.conf"; then
	fail "stale enqueue --mode flag remains in fail2ban action"
fi

for name in validate_caddyfile wl_valid wl_candidate wl_commit; do
	extract_function "$name" "$ROOT/abuseguard.sh" >> "$FUNCTIONS"
done
# shellcheck disable=SC1090
source "$FUNCTIONS"

printf '#!/usr/bin/env bash\nprintf "%%s" "${CF_API_TOKEN-}" > "$TOKEN_CAPTURE"\nprintf "validated\\n"\n[ "${CADDY_VALIDATE_RC:-0}" = 0 ]\n' > "$CADDY_MOCK"
chmod 0755 "$CADDY_MOCK"
printf '{}\n' > "$CADDY_CONFIG"
test_token='secret-test-token'
printf 'CF_API_TOKEN=%s\n' "$test_token" > "$CADDY_ENV_TEST"
export TOKEN_CAPTURE
unset CF_API_TOKEN || true
CADDY="$CADDY_MOCK"
CADDY_ENV="$CADDY_ENV_TEST"
validation_output="$(validate_caddyfile "$CADDY_CONFIG" 2>&1)"
[ "$(<"$TOKEN_CAPTURE")" = "$test_token" ] || fail "panel validation did not receive the .env token"
case "$validation_output" in *"$test_token"*) fail "panel validation leaked the token" ;; esac

extract_function validate_caddyfile "$ROOT/uninstall.sh" > "$UNINSTALL_FUNCTIONS"
unset -f validate_caddyfile
# shellcheck disable=SC1090
source "$UNINSTALL_FUNCTIONS"
CADDY_BIN="$CADDY_MOCK"
: > "$TOKEN_CAPTURE"
validation_output="$(validate_caddyfile "$CADDY_CONFIG" 2>&1)"
[ "$(<"$TOKEN_CAPTURE")" = "$test_token" ] || fail "uninstall validation did not receive the .env token"
case "$validation_output" in *"$test_token"*) fail "uninstall validation leaked the token" ;; esac

ENGINE="$ENGINE_BUILD"
for invalid in 999.1.2.3 192.0.2.1/33 2001:db8::/129; do
	if wl_valid "$invalid"; then fail "panel accepted invalid allowlist entry $invalid"; fi
done
for valid in 192.0.2.1 192.0.2.0/24 2001:db8::1 2001:db8::/32; do
	wl_valid "$valid" || fail "panel rejected valid allowlist entry $valid"
done

mkdir "$CONF_TEST"
CONF_DIR="$CONF_TEST"
WHITELIST="$CONF_TEST/whitelist"
printf '192.0.2.1\n' > "$WHITELIST"
cp -- "$WHITELIST" "$WHITELIST_EXPECTED"
chown() { :; }

INVALID_CANDIDATE="$(wl_candidate)"
printf '999.1.2.3\n' >> "$INVALID_CANDIDATE"
if wl_commit "$INVALID_CANDIDATE"; then fail "invalid candidate replaced the whitelist"; fi
cmp "$WHITELIST_EXPECTED" "$WHITELIST" || fail "invalid candidate changed the whitelist"
rm -f -- "$INVALID_CANDIDATE"
INVALID_CANDIDATE=""

VALID_CANDIDATE="$(wl_candidate)"
printf '2001:db8::/32\n' >> "$VALID_CANDIDATE"
wl_commit "$VALID_CANDIDATE" || fail "valid candidate was not committed"
VALID_CANDIDATE=""
printf '192.0.2.1\n2001:db8::/32\n' > "$WHITELIST_EXPECTED"
cmp "$WHITELIST_EXPECTED" "$WHITELIST" || fail "valid candidate was not atomically installed"

# Panel token and site changes must expose systemctl failures and roll back files.
for name in validate_caddyfile caddy_reload_or_restart caddy_restart_active \
	domain_valid port_valid hostport_valid cf_is_set sites_lines proxy_mode \
	nginx_runtime_load act_sites act_cftoken; do
	extract_function "$name" "$ROOT/abuseguard.sh" >> "$FUNCTIONS"
done
# shellcheck disable=SC1090
source "$FUNCTIONS"

mkdir "$SITES_TEST"
CADDY="$CADDY_MOCK"
CADDY_ENV="$CADDY_ENV_TEST"
CADDYFILE="$CADDY_CONFIG"
SITES_DIR="$SITES_TEST"
export CADDY_VALIDATE_RC=0
export TOKEN_CAPTURE

# Minimal source-only double of the installed nginx runtime script. The panel's
# obligation is routing plus real outcome propagation; the helper itself is
# covered by its own regression script.
cat > "$NGINX_RUNTIME_TEST" <<'RUNTIME'
nginx_token_is_set() { return "${TOKEN_SET_RC:-1}"; }
nginx_save_token() {
	printf '%s' "$1" > "$NGINX_TOKEN_CAPTURE"
	return "${TOKEN_SAVE_RC:-0}"
}
nginx_sites_lines() { cat "$NGINX_SITES_FIXTURE"; }
nginx_add_site() {
	printf '%s\t%s\n' "$1" "$2" > "$NGINX_ADD_CAPTURE"
	[ -z "${ADD_ERROR:-}" ] || printf '%s\n' "$ADD_ERROR"
	return "${ADD_RC:-0}"
}
nginx_delete_site() {
	printf '%s\n' "$1" > "$NGINX_DELETE_CAPTURE"
	[ -z "${DELETE_ERROR:-}" ] || printf '%s\n' "$DELETE_ERROR"
	return "${DELETE_RC:-0}"
}
nginx_certificate_status() { return 0; }
nginx_validate() { return 0; }
nginx_reload() { return 0; }
RUNTIME
WEB_SERVER_FILE="$CONF_TEST/web-server"
NGINX_RUNTIME="$NGINX_RUNTIME_TEST"
NGINX_RUNTIME_LOADED=0
rm -f -- "$WEB_SERVER_FILE"

SYSTEMCTL_RELOAD_RC=0
SYSTEMCTL_RESTART_RC=0
SYSTEMCTL_ACTIVE_RC=0
RESTORE_SUCCEEDS=0
systemctl() {
	printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
	# In recovery cases, the first restart fails and a second one can succeed
	# only after the original files are back in place.
	if [ "$RESTORE_SUCCEEDS" = 1 ] && [ "$(grep -c '^restart caddy$' "$SYSTEMCTL_LOG")" -ge 2 ]; then
		cmp -s "$CADDY_ENV_EXPECTED" "$CADDY_ENV_TEST" || return 1
		[ ! -e "$SITES_TEST/example.com.caddy" ] || return 1
		if [ -e "$SITE_EXPECTED" ]; then cmp -s "$SITE_EXPECTED" "$SITES_TEST/existing.example.com.caddy" || return 1; fi
		case "$*" in 'restart caddy') return 0 ;; 'is-active caddy') echo active; return 0 ;; esac
	fi
	case "$*" in
		"reload caddy") return "$SYSTEMCTL_RELOAD_RC" ;;
		"restart caddy") return "$SYSTEMCTL_RESTART_RC" ;;
		"is-active caddy")
			if [ "$SYSTEMCTL_ACTIVE_RC" -eq 0 ]; then echo active; else echo inactive; fi
			return "$SYSTEMCTL_ACTIVE_RC" ;;
		*) return 1 ;;
	esac
}
clear() { :; }
panel_start() { :; }
panel_title() { :; }
panel_section() { :; }
panel_sep() { :; }
panel_row() { :; }
panel_option() { :; }
panel_footer() { :; }
sleep() { :; }
pause() { :; }
C_B=""
C_0=""
C_Y=""
C_R=""

reset_caddy_env() {
	printf 'CF_API_TOKEN=old-token\nKEEP=yes\n' > "$CADDY_ENV_TEST"
	cp -- "$CADDY_ENV_TEST" "$CADDY_ENV_EXPECTED"
}

reset_caddy_env
CADDY_VALIDATE_RC=1
: > "$SYSTEMCTL_LOG"
if token_output="$(act_cftoken <<< 'new-token' 2>&1)"; then
	fail "token validation failure was accepted"
fi
cmp "$CADDY_ENV_EXPECTED" "$CADDY_ENV_TEST" || fail "token validation failure did not restore .env"
case "$token_output" in *"已保存 token"*) fail "token validation failure displayed success" ;; esac
grep -q '^restart caddy$' "$SYSTEMCTL_LOG" && fail "token validation failure restarted caddy"

reset_caddy_env
CADDY_VALIDATE_RC=0
SYSTEMCTL_RESTART_RC=1
RESTORE_SUCCEEDS=1
: > "$SYSTEMCTL_LOG"
if token_output="$(act_cftoken <<< 'new-token' 2>&1)"; then
	fail "token restart failure was accepted"
fi
cmp "$CADDY_ENV_EXPECTED" "$CADDY_ENV_TEST" || fail "token restart failure did not restore .env"
case "$token_output" in *"已保存 token"*) fail "token restart failure displayed success" ;; esac
grep -q '^restart caddy$' "$SYSTEMCTL_LOG" || fail "token update did not explicitly restart caddy"
grep -q '^reload caddy$' "$SYSTEMCTL_LOG" && fail "token update used reload"
[ "$(grep -c '^restart caddy$' "$SYSTEMCTL_LOG")" -eq 2 ] || fail "token rollback did not restart the old service"
case "$token_output" in *"Caddy 已恢复运行"*) ;; *) fail "token rollback did not confirm service recovery" ;; esac

reset_caddy_env
RESTORE_SUCCEEDS=0
SYSTEMCTL_RESTART_RC=0
SYSTEMCTL_ACTIVE_RC=1
: > "$SYSTEMCTL_LOG"
if token_output="$(act_cftoken <<< 'new-token' 2>&1)"; then
	fail "inactive caddy after token restart was accepted"
fi
cmp "$CADDY_ENV_EXPECTED" "$CADDY_ENV_TEST" || fail "inactive caddy did not restore .env"
case "$token_output" in *"已保存 token"*) fail "inactive caddy displayed token success" ;; esac
grep -q '^is-active caddy$' "$SYSTEMCTL_LOG" || fail "token update did not verify caddy active state"
case "$token_output" in *"Caddy 服务未恢复"*) ;; *) fail "failed service recovery was not reported" ;; esac

reset_caddy_env
SYSTEMCTL_ACTIVE_RC=0
: > "$SYSTEMCTL_LOG"
: > "$TOKEN_CAPTURE"
token_output="$(act_cftoken <<< 'new-token' 2>&1)" || fail "valid token update failed"
[ "$(<"$TOKEN_CAPTURE")" = new-token ] || fail "token update did not validate the new token"
grep -qxF 'CF_API_TOKEN=new-token' "$CADDY_ENV_TEST" || fail "token update did not save the new token"
case "$token_output" in *"已保存 token，caddy 已重启并生效。"*) ;; *) fail "token update did not report restart success" ;; esac
grep -q '^restart caddy$' "$SYSTEMCTL_LOG" || fail "token success did not restart caddy"
grep -q '^reload caddy$' "$SYSTEMCTL_LOG" && fail "token success used reload"

rm -f -- "$SITES_TEST/example.com.caddy"
SYSTEMCTL_RELOAD_RC=1
SYSTEMCTL_RESTART_RC=0
: > "$SYSTEMCTL_LOG"
site_output="$(printf '1\nexample.com\n1\n127.0.0.1:8080\n0\n' | act_sites 2>&1)" \
	|| fail "site update failed while restart fallback succeeded"
[ -f "$SITES_TEST/example.com.caddy" ] || fail "successful restart fallback did not keep the new site"
grep -q 'reverse_proxy 127\.0\.0\.1:8080' "$SITES_TEST/example.com.caddy" \
	|| fail "new site did not use the entered local upstream"
case "$site_output" in *"已添加 example.com"*) ;; *) fail "successful restart fallback did not report success" ;; esac
grep -q '^reload caddy$' "$SYSTEMCTL_LOG" || fail "site update did not try reload first"
grep -q '^restart caddy$' "$SYSTEMCTL_LOG" || fail "site update did not fall back to restart"

rm -f -- "$SITES_TEST/example.com.caddy"
SYSTEMCTL_RESTART_RC=1
RESTORE_SUCCEEDS=1
reset_caddy_env
: > "$SYSTEMCTL_LOG"
site_output="$(printf '1\nexample.com\n1\n127.0.0.1:8080\n0\n' | act_sites 2>&1)"
[ ! -e "$SITES_TEST/example.com.caddy" ] || fail "failed site add kept the new site"
case "$site_output" in *"已添加 example.com"*) fail "failed site add displayed success" ;; esac
case "$site_output" in *"新站点配置已移除"*) ;; *) fail "failed site add did not report rollback" ;; esac
[ "$(grep -c '^restart caddy$' "$SYSTEMCTL_LOG")" -eq 2 ] || fail "site add rollback did not restart the old service"
case "$site_output" in *"Caddy 已恢复运行"*) ;; *) fail "site add rollback did not recover the service" ;; esac

printf 'existing.example.com {\n\treverse_proxy localhost:8080\n}\n' > "$SITES_TEST/existing.example.com.caddy"
cp -- "$SITES_TEST/existing.example.com.caddy" "$SITE_EXPECTED"
SYSTEMCTL_RELOAD_RC=1
SYSTEMCTL_RESTART_RC=1
: > "$SYSTEMCTL_LOG"
site_output="$(printf '2\n1\n0\n' | act_sites 2>&1)"
cmp "$SITE_EXPECTED" "$SITES_TEST/existing.example.com.caddy" || fail "failed site delete did not restore the site"
case "$site_output" in *"已删除 existing.example.com"*) fail "failed site delete displayed success" ;; esac
case "$site_output" in *"已恢复原站点配置"*) ;; *) fail "failed site delete did not report rollback" ;; esac
[ "$(grep -c '^restart caddy$' "$SYSTEMCTL_LOG")" -eq 2 ] || fail "site delete rollback did not restart the old service"
case "$site_output" in *"Caddy 已恢复运行"*) ;; *) fail "site delete rollback did not recover the service" ;; esac

# Nginx installations route every site/token action through the installed
# runtime helper; a corrupt marker must stop instead of falling back to Caddy.
printf 'nginx\n' > "$WEB_SERVER_FILE"
printf 'shop.example.com\t127.0.0.1:3000\n' > "$NGINX_SITES_FIXTURE"
[ "$(proxy_mode)" = nginx ] || fail "nginx marker was not honoured"
[ "$(sites_lines)" = $'shop.example.com\t127.0.0.1:3000' ] || fail "nginx site list was not used"
TOKEN_SET_RC=0
cf_is_set || fail "nginx token presence was not read from the runtime helper"
TOKEN_SET_RC=1
if cf_is_set; then fail "missing nginx token was reported as configured"; fi

reset_caddy_env
cp -- "$CADDY_ENV_TEST" "$CADDY_ENV_EXPECTED"
: > "$NGINX_TOKEN_CAPTURE"
: > "$SYSTEMCTL_LOG"
TOKEN_SAVE_RC=0
token_output="$(act_cftoken <<< 'cf-test-token' 2>&1)" || fail "nginx token save failed"
[ "$(<"$NGINX_TOKEN_CAPTURE")" = cf-test-token ] || fail "nginx token was not handed to the runtime helper"
cmp -s "$CADDY_ENV_EXPECTED" "$CADDY_ENV_TEST" || fail "nginx token save touched the Caddy .env"
grep -q '^restart caddy$\|^reload caddy$' "$SYSTEMCTL_LOG" && fail "nginx token save restarted Caddy"
case "$token_output" in
	*"已保存 token"*"无需重启"*) ;;
	*) fail "nginx token save did not report the stored credential truthfully" ;;
esac

TOKEN_SAVE_RC=1
if token_output="$(act_cftoken <<< 'bad-token' 2>&1)"; then
	fail "nginx token save failure was accepted"
fi
case "$token_output" in *"已保存 token"*) fail "nginx token save failure displayed success" ;; esac

: > "$NGINX_ADD_CAPTURE"
ADD_RC=0; ADD_ERROR=''
site_output="$(printf '1\nexample.com\n1\n127.0.0.1:8080\n0\n' | act_sites 2>&1)" \
	|| fail "nginx site add failed"
[ "$(<"$NGINX_ADD_CAPTURE")" = $'example.com\t127.0.0.1:8080' ] \
	|| fail "nginx site add did not hand domain and upstream to the runtime helper"
case "$site_output" in
	*"已添加 example.com → 127.0.0.1:8080（nginx 已应用配置）"*) ;;
	*) fail "nginx site add did not report the applied config" ;;
esac
[ ! -e "$SITES_TEST/example.com.caddy" ] || fail "nginx site add wrote a Caddy site file"

ADD_RC=1; ADD_ERROR='证书签发失败：缺少 Cloudflare 凭据'
site_output="$(printf '1\nexample.com\n1\n127.0.0.1:8080\n0\n' | act_sites 2>&1)"
case "$site_output" in *"添加失败"*) ;; *) fail "nginx site add failure was not reported" ;; esac
case "$site_output" in *"证书签发失败"*) ;; *) fail "nginx site add diagnostic was hidden" ;; esac
case "$site_output" in *"已添加 example.com"*) fail "failed nginx site add displayed success" ;; esac

: > "$NGINX_DELETE_CAPTURE"
DELETE_RC=0; DELETE_ERROR='证书材料保留在 /etc/letsencrypt'
site_output="$(printf '2\n1\n0\n' | act_sites 2>&1)" || fail "nginx site delete failed"
[ "$(<"$NGINX_DELETE_CAPTURE")" = shop.example.com ] \
	|| fail "nginx site delete did not hand the managed domain to the runtime helper"
case "$site_output" in
	*"已删除 shop.example.com（nginx 已应用配置）"*) ;;
	*) fail "nginx site delete did not report the applied config" ;;
esac
case "$site_output" in *"证书材料保留"*) ;; *) fail "nginx site delete did not surface the retention note" ;; esac

DELETE_RC=1; DELETE_ERROR='候选配置校验失败，已回滚'
site_output="$(printf '2\n1\n0\n' | act_sites 2>&1)"
case "$site_output" in *"删除失败"*) ;; *) fail "nginx site delete failure was not reported" ;; esac
case "$site_output" in *"已删除 shop.example.com"*) fail "failed nginx site delete displayed success" ;; esac

# Corrupt state must stop instead of silently falling back to Caddy.
printf 'apache\n' > "$WEB_SERVER_FILE"
if proxy_mode >/dev/null; then fail "corrupt backend record was accepted"; fi
if sites_lines; then fail "corrupt backend record listed sites"; fi
if cf_is_set; then fail "corrupt backend record reported token state"; fi
: > "$NGINX_TOKEN_CAPTURE"
if token_output="$(act_cftoken <<< 'corrupt-token' 2>&1)"; then
	fail "corrupt backend record saved a token"
fi
[ ! -s "$NGINX_TOKEN_CAPTURE" ] || fail "corrupt backend record reached the nginx helper"
: > "$NGINX_ADD_CAPTURE"
if act_sites </dev/null >/dev/null 2>&1; then
	fail "corrupt backend record opened the site page"
fi
[ ! -s "$NGINX_ADD_CAPTURE" ] || fail "corrupt backend record reached the nginx helper"

rm -f -- "$WEB_SERVER_FILE"
[ "$(proxy_mode)" = caddy ] || fail "legacy installs without a backend record must stay on Caddy"

echo "review fix tests: pass"
