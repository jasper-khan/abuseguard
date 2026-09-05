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
TOKEN_CAPTURE="$TMP/token-capture"
CONF_TEST="$TMP/conf"
WHITELIST_EXPECTED="$TMP/whitelist-expected"
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
	rm -f -- "$TOKEN_CAPTURE"
	rm -f -- "$WHITELIST_EXPECTED"
	rm -f -- "$CONF_TEST/whitelist"
	rmdir -- "$CONF_TEST" 2>/dev/null || true
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
extract_function install_release_binary "$ROOT/install.sh" >> "$FUNCTIONS"
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
install_release_binary test-url "$OLD_BIN" test-name test-label \
	|| fail "valid binary was not installed"
[ "$("$OLD_BIN" version)" = new ] || fail "valid binary did not replace the old binary"
find "$TMP" -maxdepth 1 -name '.*.tmp.*' -print -quit | grep -q . \
	&& fail "installer left a staged binary behind"
grep -q 'install_release_binary .*ENGINE_BIN' "$ROOT/install.sh" \
	|| fail "engine download does not use the atomic installer"
grep -q 'install_release_binary .*CADDY_BIN' "$ROOT/install.sh" \
	|| fail "Caddy download does not use the atomic installer"

# Build the real engine so panel validation is tested against its parser.
(cd "$ROOT/engine" && go build -o "$ENGINE_BUILD" .)

for name in validate_caddyfile wl_valid wl_candidate wl_commit; do
	extract_function "$name" "$ROOT/abuseguard.sh" >> "$FUNCTIONS"
done
# shellcheck disable=SC1090
source "$FUNCTIONS"

printf '#!/usr/bin/env bash\nprintf "%%s" "${CF_API_TOKEN-}" > "$TOKEN_CAPTURE"\nprintf "validated\\n"\n' > "$CADDY_MOCK"
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

echo "review fix tests: pass"
