#!/usr/bin/env bash
# Consumer-behaviour checks for the first-install proxy mode/argument rules.
# Sources install.sh in library mode (no root check, apt or host changes) and
# exercises the mode resolver against private temp fixtures.
#
#   bash scripts/test-proxy-selection.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

fail() { echo "proxy-selection test failed: $*" >&2; exit 1; }

ABUSEGUARD_LIB_ONLY=1
ABUSEGUARD_CONF_DIR="$TMP/conf"
export ABUSEGUARD_LIB_ONLY ABUSEGUARD_CONF_DIR
# shellcheck disable=SC1090
. "$ROOT/install.sh" || fail "could not source install.sh"
unset ABUSEGUARD_LIB_ONLY

# Point every production path the resolver inspects at the fixture tree.
fixture_paths() {
	CONF_DIR="$TMP/conf"
	STATE_DIR="$TMP/state"
	MODE_FILE="$CONF_DIR/web-server"
	PACKAGE_RECORD="$CONF_DIR/package-ownership"
	POLICY_RC="$TMP/policy-rc.d"
	POLICY_RC_SAVED="$TMP/policy-rc.d.abuseguard-saved"
	AG_NGINX_CF_CREDENTIALS="$CONF_DIR/cloudflare.ini"
	NGINX_HTTP_CONF="$TMP/nginx/conf.d/abuseguard.conf"
	NGINX_SELFTEST_CONF="$TMP/nginx/conf.d/zz-abuseguard-selftest.conf"
	NGINX_CF_TRUST_INCLUDE="$TMP/nginx/snippets/abuseguard-cloudflare.conf"
	NGINX_RUNTIME_PATH="$TMP/libexec/abuseguard-nginx.sh"
	NGINX_DEPLOY_HOOK="$TMP/libexec/abuseguard-nginx-deploy"
	NGINX_SITES_AVAILABLE="$TMP/nginx/sites-available"
	NGINX_SITES_ENABLED="$TMP/nginx/sites-enabled"
	CADDY_BIN="$TMP/bin/caddy"
	CADDY_SERVICE="$TMP/systemd/caddy.service"
	CADDY_ETC="$TMP/caddy"
	CADDYFILE="$TMP/caddy/Caddyfile"
	SNIPPET="$TMP/caddy/abuseguard.caddy"
	PANEL_BIN="$TMP/bin/ag"
	UPDATE_MODE=0
	REQUESTED_PROXY=""
	FROM_SOURCE=0
	PROXY_MODE=""
	PROXY_MODE_ORIGIN=""
	mkdir -p "$CONF_DIR" "$STATE_DIR" "$TMP/nginx/conf.d" "$TMP/nginx/snippets" \
		"$TMP/nginx/sites-available" "$TMP/nginx/sites-enabled" "$TMP/libexec" "$TMP/bin"
}

reset_fixture() {
	rm -rf -- "$TMP"/*
	fixture_paths
}
reset_fixture

# --- argument parsing --------------------------------------------------------
(
	parse_install_args --from-source --proxy=nginx
	[ "$FROM_SOURCE" = 1 ] || exit 1
	[ "$REQUESTED_PROXY" = nginx ] || exit 2
) || fail "--from-source --proxy=nginx was not accepted"
(
	parse_install_args --proxy=nginx --from-source
	[ "$FROM_SOURCE" = 1 ] || exit 1
	[ "$REQUESTED_PROXY" = nginx ] || exit 2
) || fail "--proxy=nginx --from-source was not accepted"
(
	parse_install_args --proxy nginx --from-source
	[ "$FROM_SOURCE" = 1 ] || exit 1
	[ "$REQUESTED_PROXY" = nginx ] || exit 2
) || fail "--proxy nginx was not accepted"
(
	parse_install_args --proxy=nginx --proxy=nginx
	[ "$REQUESTED_PROXY" = nginx ] || exit 2
) || fail "repeating the same --proxy value should be accepted"

code=0
( reset_fixture; parse_install_args --bogus ) >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "unknown option should exit 2 (got $code)"

code=0
( reset_fixture; parse_install_args --proxy=bogus ) >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "invalid enum should exit 2 (got $code)"

code=0
( reset_fixture; parse_install_args --proxy=nginx --proxy=caddy ) >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "conflicting --proxy values should exit 2 (got $code)"

code=0
( reset_fixture; parse_install_args --proxy ) >/dev/null 2>&1 || code=$?
[ "$code" = 2 ] || fail "--proxy without value should exit 2 (got $code)"

# --- fresh install defaults and choice --------------------------------------
(
	reset_fixture
	ABUSEGUARD_NONINTERACTIVE=1 resolve_proxy_mode
	[ "$PROXY_MODE" = caddy ] || exit 1
) || fail "fresh noninteractive install should default to caddy"

(
	reset_fixture
	REQUESTED_PROXY=nginx
	resolve_proxy_mode
	[ "$PROXY_MODE" = nginx ] || exit 1
) || fail "fresh --proxy=nginx should select nginx"

(
	reset_fixture
	REQUESTED_PROXY=caddy
	resolve_proxy_mode
	[ "$PROXY_MODE" = caddy ] || exit 1
) || fail "fresh --proxy=caddy should select caddy"

# --- package ownership semantics --------------------------------------------
# 1 = existed before (keep on purge), 0 = absent before (installed by us).
(
	pkg_state() { printf '0'; }
	[ "$(pkg_preexisting nginx)" = 1 ]
) || fail "installed-before package must be marked preexisting"
(
	pkg_state() { printf '1'; }
	[ "$(pkg_preexisting nginx)" = 0 ]
) || fail "absent-before package must be marked as ours"
(
	pkg_state() { printf 'unknown'; }
	[ "$(pkg_preexisting nginx)" = unknown ]
) || fail "unknown package state must stay unknown"

# --- Cloudflare plugin capability (token, not just importable) --------------
# An old plugin that only knows the Global API Key must be refused: importing
# the module alone must never be accepted as API-token support.
mkdir -p "$TMP/cfplugin/certbot_dns_cloudflare"
: > "$TMP/cfplugin/certbot_dns_cloudflare/__init__.py"
cat > "$TMP/cfplugin/certbot_dns_cloudflare/dns_cloudflare.py" <<'PY'
class CredentialsConfiguration:
    def __init__(self, filename):
        raise RuntimeError("dns_cloudflare_email and dns_cloudflare_api_key are required")
PY
if ( PYTHONPATH="$TMP/cfplugin" certbot_cf_supports_api_token ); then
	fail "old Global-API-Key-only Cloudflare plugin was accepted"
fi
if python3 -c 'import certbot_dns_cloudflare' >/dev/null 2>&1; then
	certbot_cf_supports_api_token || fail "token-capable Cloudflare plugin was rejected"
fi

# --- immutable recorded mode ------------------------------------------------
(
	reset_fixture
	printf 'caddy\n' > "$MODE_FILE"
	chmod 0644 "$MODE_FILE"
	REQUESTED_PROXY=nginx
	resolve_proxy_mode
) >/dev/null 2>&1 && fail "switching a recorded caddy install to nginx must fail"
[ "$(cat "$MODE_FILE")" = caddy ] || fail "recorded mode must not change on a rejected switch"

(
	reset_fixture
	printf 'nginx\n' > "$MODE_FILE"
	chmod 0644 "$MODE_FILE"
	resolve_proxy_mode
	[ "$PROXY_MODE" = nginx ] || exit 1
) || fail "updates must reuse the recorded nginx mode without flags"

(
	reset_fixture
	printf 'nginx\n' > "$MODE_FILE"
	chmod 0644 "$MODE_FILE"
	REQUESTED_PROXY=nginx
	resolve_proxy_mode
	[ "$PROXY_MODE" = nginx ] || exit 1
) || fail "matching --proxy must be accepted"

(
	reset_fixture
	printf 'Caddy\n' > "$MODE_FILE"
	chmod 0644 "$MODE_FILE"
	resolve_proxy_mode
) >/dev/null 2>&1 && fail "corrupt mode record must abort"

(
	reset_fixture
	: > "$MODE_FILE"
	resolve_proxy_mode
) >/dev/null 2>&1 && fail "empty mode record must abort"

if [ "$(id -u)" = 0 ]; then
	(
		reset_fixture
		printf 'caddy\n' > "$MODE_FILE"
		chmod 0664 "$MODE_FILE"
		resolve_proxy_mode
	) >/dev/null 2>&1 && fail "group-writable mode record must abort"
fi

# --- upgrade without a mode record -------------------------------------------
(
	reset_fixture
	printf 'caddy_bin_preexisting=0\ncaddy_service_preexisting=0\n' > "$STATE_DIR/install-manifest"
	UPDATE_MODE=1
	resolve_proxy_mode
) >/dev/null 2>&1 && fail "manifest without a mode record must abort"

(
	reset_fixture
	printf 'web_server=nginx\n' > "$STATE_DIR/install-manifest"
	UPDATE_MODE=1
	resolve_proxy_mode
) >/dev/null 2>&1 && fail "manifest nginx without a mode record must be treated as ambiguous"

# --- failed first install keeps its selection -------------------------------
(
	reset_fixture
	REQUESTED_PROXY=nginx
	resolve_proxy_mode
	if [ "$(id -u)" = 0 ]; then
		write_mode_record
	else
		printf 'nginx\n' > "$MODE_FILE"
		chmod 0644 "$MODE_FILE"
	fi
	# Retry without flags must keep nginx even though UPDATE_MODE is still 0.
	REQUESTED_PROXY=""
	resolve_proxy_mode
	[ "$PROXY_MODE" = nginx ] || exit 1
) || fail "an in-progress first install must preserve its selection"

# --- nginx must never be started by apt ------------------------------------
# nginx-common's postinst starts the unit through deb-systemd-invoke, which
# passes the unit name (nginx.service) to policy-rc.d; nginx.postinst uses
# invoke-rc.d and passes nginx. Blocking only one of them leaves apt starting
# nginx with the distro default site on :80 during install.

# No previous policy: both names blocked, other units allowed, nothing left.
(
	reset_fixture
	POLICY_RC_ACTIVE=0
	inhibit_proxy_autostart || exit 1
	[ -x "$POLICY_RC" ] || exit 2
	"$POLICY_RC" nginx start; [ "$?" = 101 ] || exit 3
	"$POLICY_RC" nginx.service start; [ "$?" = 101 ] || exit 4
	"$POLICY_RC" rsyslog start || exit 5
	restore_proxy_autostart || exit 6
	[ ! -e "$POLICY_RC" ] || exit 7
) || fail "a temporary policy-rc.d must block nginx and nginx.service"

# Existing policy: our wrapper blocks both names and chains everything else;
# restore puts the original file back, proven by it receiving later calls.
(
	reset_fixture
	searched="$TMP/original-policy.calls"
	printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> %s\nexit 0\n' "$searched" > "$POLICY_RC"
	chmod 0755 "$POLICY_RC"
	POLICY_RC_ACTIVE=0
	inhibit_proxy_autostart || exit 1
	"$POLICY_RC" nginx.service start; [ "$?" = 101 ] || exit 2
	"$POLICY_RC" nginx start; [ "$?" = 101 ] || exit 3
	"$POLICY_RC" rsyslog start || exit 4
	[ "$(cat "$searched")" = "rsyslog start" ] || exit 5
	restore_proxy_autostart || exit 6
	"$POLICY_RC" cron start || exit 7
	[ "$(tail -n 1 "$searched")" = "cron start" ] || exit 8
) || fail "a chained policy-rc.d must block nginx and restore the original"

echo "proxy-selection test OK"
