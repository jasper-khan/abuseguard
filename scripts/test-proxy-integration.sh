#!/usr/bin/env bash
# Consumer-level integration checks for the Nginx runtime helper.
#
#   bash scripts/test-proxy-integration.sh
#
# Everything runs against an isolated fixture: a private Nginx prefix, stub
# systemctl, stub certbot (it only creates a self-signed lineage fixture) and a
# temp copy of every path the runtime manages. Nothing touches /etc/nginx,
# /etc/letsencrypt, the live service or real certificates.
#
# Covered behaviour:
#   - asset install is idempotent and leaves unrelated config untouched
#   - token save is atomic, secret-free on stdout, 0600, and rejects bad input
#   - bad domain/upstream input writes nothing
#   - add/delete validates the complete loaded config, not a fragment
#   - candidate failure (bad existing site, failed reload) leaves no half site
#   - delete failure restores the enabled site; success retains certificates
#   - certbot is invoked DNS-01 only, with the deploy hook
#   - the deploy hook reloads only after a successful nginx -t
#   - certificate status reads local material only
#
# Requires: nginx, openssl. Run from any directory.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REAL_NGINX="${REAL_NGINX:-$(command -v nginx || true)}"
[ -n "$REAL_NGINX" ] || { echo 'test-proxy-integration: nginx binary not found' >&2; exit 2; }
command -v openssl >/dev/null 2>&1 || { echo 'test-proxy-integration: openssl not found' >&2; exit 2; }

TMP="$(mktemp -d)"
fail() { printf '\033[1;31m[proxy-integration]\033[0m %s (evidence: %s)\n' "$*" "$TMP" >&2; exit 1; }
ok()   { printf '\033[1;32m[proxy-integration]\033[0m %s\n' "$*"; }
cleanup() {
	if [ -n "${MASTER_PID:-}" ]; then
		pkill -P "$MASTER_PID" 2>/dev/null || true
		kill "$MASTER_PID" 2>/dev/null || true
	fi
	rm -rf -- "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/bin" "$TMP/nginx/conf.d" "$TMP/nginx/snippets" \
	"$TMP/nginx/sites-available" "$TMP/nginx/sites-enabled" "$TMP/nginx/tmp" \
	"$TMP/log" "$TMP/libexec" "$TMP/agconf" "$TMP/tls" "$TMP/letsencrypt"

cat > "$TMP/nginx/nginx.conf" <<EOF
worker_processes 1;
pid $TMP/nginx.pid;
error_log $TMP/error.log notice;
events { worker_connections 32; }
http {
    access_log $TMP/log/default-access.log;
    client_body_temp_path $TMP/nginx/tmp/body;
    proxy_temp_path $TMP/nginx/tmp/proxy;
    fastcgi_temp_path $TMP/nginx/tmp/fastcgi;
    uwsgi_temp_path $TMP/nginx/tmp/uwsgi;
    scgi_temp_path $TMP/nginx/tmp/scgi;
    include $TMP/nginx/conf.d/*.conf;
    include $TMP/nginx/sites-enabled/*;
}
EOF
cat > "$TMP/bin/nginx" <<EOF
#!/bin/sh
exec "$REAL_NGINX" -p "$TMP/nginx/" -c "$TMP/nginx/nginx.conf" "\$@"
EOF
cat > "$TMP/bin/nginx-master" <<'SH'
#!/usr/bin/env bash
# Fixture stand-in for the Nginx master: two sleeping children. SIGHUP replaces
# them, which is the observable worker-generation change the runtime requires.
# The real nginx binary is still used for every config validation (nginx -t).
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
cat > "$TMP/bin/systemctl" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/systemctl.calls"
case "\$*" in
    "show -p MainPID --value nginx")
        [ -s "$TMP/nginx-master.pid" ] || exit 1
        cat "$TMP/nginx-master.pid"
        exit 0
        ;;
    "is-active nginx") printf 'active\n'; exit 0 ;;
    "reload nginx")
        [ -e "$TMP/fail-reload" ] && exit 1
        kill -HUP "\$(cat "$TMP/nginx-master.pid")"
        exit 0
        ;;
esac
exit 1
EOF
chmod 0755 "$TMP/bin/nginx-master" "$TMP/bin/systemctl"
cat > "$TMP/bin/certbot" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/certbot.calls"
[ -e "$TMP/fail-certbot" ] && exit 1
name='' domain=''
while [ "\$#" -gt 0 ]; do
    case "\$1" in
        --cert-name) name="\$2"; shift 2 ;;
        -d) domain="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "\$name" ] || exit 1
live="$TMP/letsencrypt/live/\$name"
mkdir -p "\$live" "$TMP/letsencrypt/renewal" || exit 1
cp "$TMP/tls/fullchain.pem" "\$live/fullchain.pem" || exit 1
cp "$TMP/tls/privkey.pem" "\$live/privkey.pem" || exit 1
printf '# fixture lineage for %s\n' "\$domain" > "$TMP/letsencrypt/renewal/\$name.conf"
exit 0
EOF
chmod 0755 "$TMP/bin/nginx" "$TMP/bin/systemctl" "$TMP/bin/certbot"
openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
	-subj '/CN=example.test' -addext 'subjectAltName=DNS:example.test' \
	-keyout "$TMP/tls/privkey.pem" -out "$TMP/tls/fullchain.pem" >/dev/null 2>&1 \
	|| fail 'could not create the fixture certificate'

# shellcheck source=/dev/null
source "$REPO_ROOT/assets/nginx/runtime.sh"
NGINX_ETC="$TMP/nginx"
NGINX_CONFD_DIR="$TMP/nginx/conf.d"
NGINX_SNIPPETS_DIR="$TMP/nginx/snippets"
NGINX_SITES_AVAILABLE="$TMP/nginx/sites-available"
NGINX_SITES_ENABLED="$TMP/nginx/sites-enabled"
NGINX_HTTP_CONF="$TMP/nginx/conf.d/abuseguard.conf"
NGINX_SELFTEST_CONF="$TMP/nginx/conf.d/zz-abuseguard-selftest.conf"
NGINX_CF_TRUST_INCLUDE="$TMP/nginx/snippets/abuseguard-cloudflare.conf"
NGINX_LOG_DIR="$TMP/log"
NGINX_ACCESS_LOG="$TMP/log/abuseguard-access.json"
NGINX_LOGROTATE="$TMP/abuseguard-nginx.logrotate"
NGINX_LETSENCRYPT_DIR="$TMP/letsencrypt"
NGINX_LIBEXEC_DIR="$TMP/libexec"
NGINX_DEPLOY_HOOK="$TMP/libexec/abuseguard-nginx-deploy"
NGINX_RUNTIME_PATH="$TMP/libexec/abuseguard-nginx.sh"
AG_NGINX_CONF_DIR="$TMP/agconf"
AG_NGINX_CF_CREDENTIALS="$TMP/agconf/cloudflare.ini"
NGINX_SELFTEST_PORT=18081
NGINX_BIN="$TMP/bin/nginx"
NGINX_SYSTEMCTL="$TMP/bin/systemctl"
CERTBOT_BIN="$TMP/bin/certbot"
NGINX_CF_LIVE=0
NGINX_CERTBOT_PROPAGATION_SECONDS=0
PATH="$TMP/bin:$PATH"
export PATH
FAKE_MASTER_PID_FILE="$TMP/nginx-master.pid"
export FAKE_MASTER_PID_FILE

"$TMP/bin/nginx-master" &
MASTER_PID=$!
for _ in $(seq 1 50); do
	[ -s "$FAKE_MASTER_PID_FILE" ] && break
	sleep 0.1
done
[ -s "$FAKE_MASTER_PID_FILE" ] || fail 'fake nginx master did not start'
[ -n "$(pgrep -P "$MASTER_PID" 2>/dev/null)" ] || fail 'fake nginx master has no workers'

# Unrelated config that must survive every operation.
UNRELATED_SITE="$NGINX_SITES_AVAILABLE/other.test.conf"
UNRELATED_LINK="$NGINX_SITES_ENABLED/other.test.conf"
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    location / { return 200 "other"; }
}
EOF
ln -s -- "$UNRELATED_SITE" "$UNRELATED_LINK"
cat > "$NGINX_CONFD_DIR/zz-other.conf" <<'EOF'
# unrelated operator config
EOF
sums() { sha256sum "$UNRELATED_SITE" "$UNRELATED_LINK" "$NGINX_CONFD_DIR/zz-other.conf"; }
UNRELATED_BEFORE="$(sums)"

expect_fail() {
	local label="$1"
	shift
	if "$@" >"$TMP/last.log" 2>&1; then fail "$label unexpectedly succeeded"; fi
}
assert_file() { [ -e "$1" ] || fail "expected file missing: $1"; }
assert_no_file() { [ ! -e "$1" ] && [ ! -L "$1" ] || fail "unexpected file exists: $1"; }
assert_grep() { grep -Fq -- "$2" "$1" || fail "expected '$2' in $1"; }
assert_no_grep() { ! grep -Fq -- "$2" "$1" || fail "unexpected '$2' in $1"; }

nginx_install_assets "$REPO_ROOT" >/dev/null 2>&1 || fail 'nginx_install_assets failed'
assert_file "$NGINX_HTTP_CONF"
assert_file "$NGINX_CF_TRUST_INCLUDE"
assert_file "$NGINX_SELFTEST_CONF"
assert_file "$NGINX_LOGROTATE"
assert_file "$NGINX_DEPLOY_HOOK"
assert_file "$NGINX_RUNTIME_PATH"
assert_file "$NGINX_ACCESS_LOG"
assert_grep "$NGINX_CF_TRUST_INCLUDE" 'set_real_ip_from '
assert_no_grep "$NGINX_CF_TRUST_INCLUDE" '0.0.0.0/0'
assert_no_grep "$NGINX_CF_TRUST_INCLUDE" '::/0'
nginx_validate || fail 'the installed fixture config does not validate'
ok 'assets install into the isolated fixture and the config validates'

# Idempotent reinstall must not rewrite unrelated config or change managed files.
managed_before="$(sha256sum "$NGINX_HTTP_CONF" "$NGINX_CF_TRUST_INCLUDE" "$NGINX_SELFTEST_CONF" "$NGINX_LOGROTATE" "$NGINX_DEPLOY_HOOK")"
nginx_install_assets "$REPO_ROOT" >/dev/null 2>&1 || fail 'second nginx_install_assets failed'
[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'reinstall modified unrelated Nginx config'
[ "$(sha256sum "$NGINX_HTTP_CONF" "$NGINX_CF_TRUST_INCLUDE" "$NGINX_SELFTEST_CONF" "$NGINX_LOGROTATE" "$NGINX_DEPLOY_HOOK")" = "$managed_before" ] \
	|| fail 'reinstall changed managed config content'
ok 'asset install is idempotent and unrelated config is preserved'

# --- token contract ----------------------------------------------------------
expect_fail 'empty token' nginx_save_token ''
expect_fail 'token with whitespace' nginx_save_token 'bad token'
expect_fail 'token with control characters' nginx_save_token $'bad\ntoken'
assert_no_file "$AG_NGINX_CF_CREDENTIALS"
out="$(nginx_save_token 'fixture-token-123')" || fail 'valid token was rejected'
case "$out" in *fixture-token-123*) fail 'token leaked to stdout' ;; esac
assert_file "$AG_NGINX_CF_CREDENTIALS"
[ "$(stat -c '%a' "$AG_NGINX_CF_CREDENTIALS")" = 600 ] || fail 'credential file mode is not 0600'
if [ "$(id -u)" = 0 ]; then
	[ "$(stat -c '%U:%G' "$AG_NGINX_CF_CREDENTIALS")" = root:root ] || fail 'credential file is not root:root'
fi
[ "$(cat "$AG_NGINX_CF_CREDENTIALS")" = 'dns_cloudflare_api_token = fixture-token-123' ] \
	|| fail 'credential file content is not the expected authenticator format'
nginx_token_is_set || fail 'saved token is not detected'
ok 'token save is atomic, secret-free, 0600 and rejects unsafe input'

# --- input validation --------------------------------------------------------
for domain in 'bad domain' '*.example.test' 'example'; do
	expect_fail "invalid domain $domain" nginx_add_site "$domain" 127.0.0.1:3000
done
for up in 'http://127.0.0.1:3000' '127.0.0.1' '127.0.0.1:99999' '127.0.0.1:3000; include /etc/passwd'; do
	expect_fail "invalid upstream $up" nginx_add_site example.test "$up"
done
assert_no_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_no_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
ok 'invalid domain/upstream input writes nothing'

# --- full-config failure leaves no half-enabled site -------------------------
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    this_directive_does_not_exist;
}
EOF
expect_fail 'add with a broken existing site' nginx_add_site example.test 127.0.0.1:3000
assert_no_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_no_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
assert_file "$NGINX_LETSENCRYPT_DIR/live/abuseguard-example.test/fullchain.pem"
assert_grep "$TMP/certbot.calls" 'certonly'
assert_grep "$TMP/certbot.calls" '--cert-name abuseguard-example.test'
assert_grep "$TMP/certbot.calls" '--dns-cloudflare'
assert_grep "$TMP/certbot.calls" '--deploy-hook'
assert_no_grep "$TMP/certbot.calls" '--nginx'
assert_no_grep "$TMP/certbot.calls" '--standalone'
assert_no_grep "$TMP/certbot.calls" '--webroot'
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    location / { return 200 "other"; }
}
EOF
nginx_validate || fail 'fixture config did not recover after restoring the unrelated site'
ok 'candidate validation covers the complete config; certbot is DNS-01 only'

# --- reload failure rolls back an added site ---------------------------------
touch "$TMP/fail-reload"
expect_fail 'add with failed reload' nginx_add_site example.test 127.0.0.1:3000
rm -f "$TMP/fail-reload"
assert_no_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_no_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
assert_file "$NGINX_LETSENCRYPT_DIR/live/abuseguard-example.test/fullchain.pem"
nginx_validate || fail 'config invalid after a rolled-back add'
[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'rolled-back add touched unrelated config'
ok 'failed reload leaves no half-enabled site and keeps certificate material'

# --- successful add ----------------------------------------------------------
nginx_add_site Example.Test 127.0.0.1:3000 >/dev/null || fail 'valid site add failed'
assert_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
[ -L "$NGINX_SITES_ENABLED/abuseguard-example.test.conf" ] || fail 'enabled site is not a symlink'
nginx_validate || fail 'config invalid after a successful add'
nginx_sites_lines | grep -Fq $'example.test\t127.0.0.1:3000' || fail 'nginx_sites_lines does not report the site'
nginx_certificate_status | awk -F'\t' '
	$1 == "example.test" && $3 == "valid" && $2 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ { found = 1 }
	END { exit(found ? 0 : 1) }
' || fail 'nginx_certificate_status does not report a valid local certificate'
[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'add modified unrelated config'
expect_fail 'duplicate site add' nginx_add_site example.test 127.0.0.1:3000
ok 'add enables a complete site, reports it, and reuses certificate material'

# --- delete rollback and success --------------------------------------------
touch "$TMP/fail-reload"
expect_fail 'delete with failed reload' nginx_delete_site example.test
rm -f "$TMP/fail-reload"
assert_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
nginx_validate || fail 'config invalid after a rolled-back delete'
[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'rolled-back delete touched unrelated config'
ok 'failed delete restores the enabled site'

nginx_delete_site example.test >/dev/null || fail 'valid site delete failed'
assert_no_file "$NGINX_SITES_AVAILABLE/abuseguard-example.test.conf"
assert_no_file "$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
assert_file "$NGINX_LETSENCRYPT_DIR/live/abuseguard-example.test/fullchain.pem"
nginx_validate || fail 'config invalid after a successful delete'
expect_fail 'delete of a missing site' nginx_delete_site example.test
[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'delete modified unrelated config'
ok 'delete disables/removes only the managed site and keeps certificates'

# --- deploy hook -------------------------------------------------------------
: > "$TMP/systemctl.calls"
PATH="$TMP/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1 || fail 'deploy hook failed on a valid config'
assert_grep "$TMP/systemctl.calls" 'reload nginx'
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    broken_directive;
}
EOF
: > "$TMP/systemctl.calls"
if PATH="$TMP/bin:$PATH" "$NGINX_DEPLOY_HOOK" >/dev/null 2>&1; then
	fail 'deploy hook reloaded despite an invalid config'
fi
assert_no_grep "$TMP/systemctl.calls" 'reload nginx'
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    location / { return 200 "other"; }
}
EOF
ok 'deploy hook reloads only after a successful nginx -t'

# --- missing token blocks add without an ACME fallback ----------------------
mv "$AG_NGINX_CF_CREDENTIALS" "$AG_NGINX_CF_CREDENTIALS.off"
nginx_token_is_set && fail 'token reported present while missing'
calls_before="$(wc -l < "$TMP/certbot.calls")"
expect_fail 'add without a token' nginx_add_site second.test 127.0.0.1:3001
[ "$(wc -l < "$TMP/certbot.calls")" = "$calls_before" ] || fail 'certbot was invoked without a token'
assert_no_file "$NGINX_SITES_AVAILABLE/abuseguard-second.test.conf"
mv "$AG_NGINX_CF_CREDENTIALS.off" "$AG_NGINX_CF_CREDENTIALS"
nginx_token_is_set || fail 'restored token is not detected'
ok 'missing token fails before any certificate/nginx work'

# --- validate/reload surfaces -------------------------------------------------
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    broken_directive;
}
EOF
expect_fail 'nginx_validate on a broken config' nginx_validate
touch "$TMP/fail-reload"
expect_fail 'nginx_reload on a failed reload' nginx_reload
rm -f "$TMP/fail-reload"
cat > "$UNRELATED_SITE" <<'EOF'
server {
    listen 8443;
    server_name other.test;
    location / { return 200 "other"; }
}
EOF
nginx_validate || fail 'fixture config did not recover'
assert_no_grep "$TMP/systemctl.calls" 'restart'
ok 'validate fails loudly and reload never falls back to a restart'

[ "$(sums)" = "$UNRELATED_BEFORE" ] || fail 'unrelated config changed during the suite'
ok 'proxy integration suite passed'
printf '\033[1;33m[proxy-integration]\033[0m note: certificates are fixtures; live Cloudflare DNS-01 issuance is not exercised.\n'
