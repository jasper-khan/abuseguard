#!/usr/bin/env bash
# Isolate manifest admission and uninstall choices without running an installer,
# touching real system paths, or requiring root to exercise fixtures.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
fail() { printf 'install inventory test failed: %s\n' "$*" >&2; exit 1; }
log() { :; }
warn() { :; }
die() { fail "$*"; }

sed -n '/^load_uninstall_inventory() {/,/^}$/p' "$ROOT/uninstall.sh" > "$TMP/load.sh"
# shellcheck disable=SC1091
source "$TMP/load.sh"

ENGINE_BIN="$TMP/engine"
MODE_FILE="$TMP/mode"
MANIFEST="$TMP/manifest"
PACKAGE_RECORD="$TMP/packages"
cat > "$ENGINE_BIN" <<'ENGINE'
#!/usr/bin/env bash
set -eu
[ "$#" = 5 ] && [ "$1" = install-inventory ] && [ "$2" = inspect ] || exit 2
printf '%s\n' "$INVENTORY_RESULT"
exit "${INVENTORY_STATUS:-0}"
ENGINE
chmod 0755 "$ENGINE_BIN"

export INVENTORY_RESULT='v1|nginx|verified|1|1|1|1|1|1|1|1|0|unknown|1|0|0'
load_uninstall_inventory
[ "$MANIFEST_OK:$PROXY_MODE:$m_nginx_pkg:$m_nginx_core_pkg:$m_nginx_common_pkg" = '1:nginx:0:unknown:1' ] \
	|| fail 'unexpected valid inventory fields'
[ "$m_certbot_pkg:$m_certbot_cf_pkg" = '0:0' ] || fail 'wrong Certbot ownership'

export INVENTORY_RESULT='v1|caddy|unknown|1|1|1|1|1|1|1|1|unknown|unknown|unknown|unknown|unknown'
load_uninstall_inventory
[ "$MANIFEST_OK:$PROXY_MODE:$m_caddy_bin" = '0:caddy:1' ] || fail 'legacy inventory should not authorize purge'

export INVENTORY_RESULT='v1|caddy|verified|0|0|0|0|0|0|0|0|unknown|unknown|unknown|unknown|unknown'
export INVENTORY_STATUS=2
load_uninstall_inventory
[ "$MANIFEST_OK:$PROXY_MODE:$m_caddy_bin" = '0::1' ] || fail 'failed helper authorized purge'

export INVENTORY_STATUS=0
INVENTORY_RESULT+='|$(echo never-evaluate)'
load_uninstall_inventory
[ "$MANIFEST_OK:$PROXY_MODE:$m_caddy_bin" = '0::1' ] || fail 'invalid inventory authorized purge'

# Exercise only the manifest writer, with stubbed ownership and temp directories.
sed -n '/^# Keep the first observation across retries/,/^# --- service accounts/{ /^# --- service accounts/!p; }' \
	"$ROOT/install.sh" > "$TMP/write.sh"
chown() { return 0; }
CONF_DIR="$TMP/conf"
mkdir -m 0700 "$CONF_DIR"
INSTALL_MANIFEST="$CONF_DIR/install-manifest"
UPDATE_MODE=0 PROXY_MODE=caddy
PRE_CADDY_BIN=0 PRE_CADDY_SVC=1 PRE_CADDY_USER=1 PRE_AG_USER=0
PRE_CADDYFILE=1 PRE_CADDY_ETC=1 PRE_LOG_DIR=0 PRE_CADDY_LIB=1
# shellcheck disable=SC1091
source "$TMP/write.sh"
grep -qx 'version=1' "$INSTALL_MANIFEST"
grep -qx 'caddy_bin_preexisting=0' "$INSTALL_MANIFEST"
[ "$(stat -c %a "$INSTALL_MANIFEST")" = 640 ] || fail 'manifest permissions changed'

UPDATE_MODE=1 PRE_CADDY_BIN=1
source "$TMP/write.sh"
grep -qx 'caddy_bin_preexisting=0' "$INSTALL_MANIFEST"
CONF_DIR="$TMP/legacy-conf"
mkdir -m 0700 "$CONF_DIR"
INSTALL_MANIFEST="$CONF_DIR/install-manifest"
source "$TMP/write.sh"
[ ! -e "$INSTALL_MANIFEST" ] || fail 'upgrade fabricated early ownership'

UPDATE_MODE=0
chmod 0770 "$CONF_DIR"
source "$TMP/write.sh"
[ ! -e "$INSTALL_MANIFEST" ] || fail 'untrusted directory authorized manifest creation'

printf 'install inventory tests: pass\n'
