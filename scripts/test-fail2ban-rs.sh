#!/usr/bin/env bash
# Consumer-behaviour checks for install.sh's fail2ban-rs staging, checksum
# verification, version skip, upgrade/migration rollback, and distro cleanup.
# Sources install.sh in library mode (no root check, apt, or host changes).
#
#   bash scripts/test-fail2ban-rs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

fail() { echo "fail2ban-rs test failed: $*" >&2; exit 1; }

ABUSEGUARD_LIB_ONLY=1
ABUSEGUARD_CONF_DIR="$TMP/conf"
export ABUSEGUARD_LIB_ONLY ABUSEGUARD_CONF_DIR
# shellcheck disable=SC1090
. "$ROOT/install.sh" || fail "could not source install.sh"
unset ABUSEGUARD_LIB_ONLY

log() { :; }
warn() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }

make_fake_archive() { # ROOT_NAME OUT_TAR [BROKEN_PROBE] [INSTALL_LOG]
	local root="$1" out="$2" broken="${3:-0}" inst_log="${4:-$TMP/inst.log}"
	local src="$TMP/build-$root-$broken"
	rm -rf -- "$src"
	mkdir -p "$src/$root/bin"
	for bin in fail2ban-server fail2ban-client fail2ban-regex; do
		if [ "$broken" = 1 ] && [ "$bin" = fail2ban-client ]; then
			printf '#!/usr/bin/env bash\nexit 1\n' > "$src/$root/bin/$bin"
		else
			printf '#!/usr/bin/env bash\nprintf "Fail2Ban %s\\n"\n' "$root" > "$src/$root/bin/$bin"
		fi
		chmod 0755 "$src/$root/bin/$bin"
	done
	cat > "$src/$root/install.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$*" >> "$inst_log"
if [ "\${1:-}" = --uninstall ]; then
	rm -f -- "\$F2B_BIN_DIR/fail2ban-server" "\$F2B_BIN_DIR/fail2ban-client" "\$F2B_BIN_DIR/fail2ban-regex" \
		"\$F2B_UNIT_DIR/fail2ban.service" "\$F2B_UNIT_DIR/fail2ban.socket" "\$F2B_RS_MARKER"
	exit 0
fi
mkdir -p "\$F2B_BIN_DIR" "\$F2B_UNIT_DIR" "\$F2B_RS_STATE_DIR" "\$F2B_ETC"
for b in fail2ban-server fail2ban-client fail2ban-regex; do
	printf '#!/usr/bin/env bash\necho new-%s\n' "$root" > "\$F2B_BIN_DIR/\$b"
	chmod 0755 "\$F2B_BIN_DIR/\$b"
done
printf '[Unit]\nDescription=new %s\n' "$root" > "\$F2B_UNIT_DIR/fail2ban.service"
printf '[Socket]\n' > "\$F2B_UNIT_DIR/fail2ban.socket"
printf '%s\n' "$root" > "\$F2B_RS_MARKER"
[ -f "\$F2B_ETC/fail2ban.conf" ] || printf '[DEFAULT]\n' > "\$F2B_ETC/fail2ban.conf"
[ -f "\$F2B_ETC/jail.conf" ] || printf '[DEFAULT]\n' > "\$F2B_ETC/jail.conf"
EOF
	chmod 0755 "$src/$root/install.sh"
	tar -czf "$out" -C "$src" "$root"
	sha256sum "$out" | awk -v fn="$(basename "$out")" '{print $1 "  " fn}' > "$out.sha256"
	rm -rf -- "$src"
}

reset_env() {
	rm -rf -- "$TMP/fs" "$TMP/calls"
	mkdir -p "$TMP/fs/bin" "$TMP/fs/units" "$TMP/fs/man/man1" "$TMP/fs/man/man5" \
		"$TMP/fs/state" "$TMP/fs/etc" "$TMP/fs/policy-units"
	export F2B_BIN_DIR="$TMP/fs/bin"
	export F2B_UNIT_DIR="$TMP/fs/units"
	export F2B_MAN_DIR="$TMP/fs/man"
	export F2B_RS_STATE_DIR="$TMP/fs/state"
	export F2B_RS_MARKER="$F2B_RS_STATE_DIR/installed"
	export F2B_ETC="$TMP/fs/etc"
	POLICY_UNIT_DIR="$TMP/fs/policy-units"
	ARCH=amd64
	FAIL2BAN_RS_NEEDS_INSTALL=0
	FAIL2BAN_RS_SWAPPED=0
	FAIL2BAN_RS_HAD_PREV=0
	FAIL2BAN_RS_HAD_DISTRO=0
	FAIL2BAN_RS_TARGET_NAME=""
	FAIL2BAN_RS_STAGE_DIR=""
	FAIL2BAN_RS_ARCHIVE=""
	FAIL2BAN_RS_INSTALLER=""
	FAIL2BAN_RS_STAGED_CLIENT=""
	FAIL2BAN_RS_ROLLBACK_DIR=""
	FAIL2BAN_STOPPED=0
	unset ABUSEGUARD_FAIL2BAN_ARCHIVE ABUSEGUARD_FAIL2BAN_VERSION || true
}

# --- 1) latest_fail2ban_rs_version parsing -----------------------------------
(
	FAIL2BAN_RS_REPO=jasper-khan/fail2ban-rs
	curl() { printf '%s' "$LATEST_URL"; return "${CURL_RC:-0}"; }
	LATEST_URL="https://github.com/jasper-khan/fail2ban-rs/releases/tag/v1.1.2"
	[ "$(latest_fail2ban_rs_version)" = "1.1.2" ] || exit 1
	LATEST_URL="https://github.com/jasper-khan/fail2ban-rs/releases/tag/not-semver"
	if latest_fail2ban_rs_version >/dev/null 2>&1; then exit 2; fi
	LATEST_URL="https://github.com/jasper-khan/fail2ban-rs/releases"
	if latest_fail2ban_rs_version >/dev/null 2>&1; then exit 3; fi
	CURL_RC=1
	if latest_fail2ban_rs_version >/dev/null 2>&1; then exit 4; fi
) || fail "latest_fail2ban_rs_version validation failed"

# --- 2) archive checksum, root validation, probe, and version skip -----------
GOOD_TAR="$TMP/fail2ban-rs-1.1.2-linux-amd64.tar.gz"
ARM_TAR="$TMP/fail2ban-rs-1.1.2-linux-arm64.tar.gz"
BROKEN_TAR="$TMP/fail2ban-rs-1.1.3-linux-amd64.tar.gz"
BADROOT_TAR="$TMP/badroot.tar.gz"
make_fake_archive "fail2ban-rs-1.1.2-linux-amd64" "$GOOD_TAR" 0 "$TMP/inst.log"
make_fake_archive "fail2ban-rs-1.1.2-linux-arm64" "$ARM_TAR" 0 "$TMP/inst.log"
make_fake_archive "fail2ban-rs-1.1.3-linux-amd64" "$BROKEN_TAR" 1 "$TMP/inst.log"

mkdir -p "$TMP/badroot-src/unexpected-dir"
printf 'x\n' > "$TMP/badroot-src/unexpected-dir/file"
tar -czf "$BADROOT_TAR" -C "$TMP/badroot-src" unexpected-dir
sha256sum "$BADROOT_TAR" | awk '{print $1 "  badroot.tar.gz"}' > "$BADROOT_TAR.sha256"
rm -rf -- "$TMP/badroot-src"

# Tampered checksum fails
(
	reset_env
	cp -- "$GOOD_TAR" "$TMP/tampered.tar.gz"
	printf '0000000000000000000000000000000000000000000000000000000000000000  tampered.tar.gz\n' \
		> "$TMP/tampered.tar.gz.sha256"
	if verify_fail2ban_rs_archive "$TMP/tampered.tar.gz" "$TMP/tampered.tar.gz.sha256" >/dev/null 2>&1; then
		exit 1
	fi
) || fail "tampered sha256 archive was accepted"

# Malformed checksum fails
(
	reset_env
	printf 'not-a-sha\n' > "$TMP/badsum.sha256"
	if verify_fail2ban_rs_archive "$GOOD_TAR" "$TMP/badsum.sha256" >/dev/null 2>&1; then
		exit 1
	fi
) || fail "malformed sha256 digest was accepted"

# Unexpected archive root fails
(
	reset_env
	if verify_fail2ban_rs_archive "$BADROOT_TAR" "$BADROOT_TAR.sha256" >/dev/null 2>&1; then
		exit 1
	fi
) || fail "unexpected archive root was accepted"

# Wrong arch local archive fails
(
	reset_env
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$ARM_TAR"
	if (stage_fail2ban_rs) >/dev/null 2>&1; then exit 1; fi
) || fail "wrong-arch local archive was accepted"

# Broken startup probe fails before commit
(
	reset_env
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$BROKEN_TAR"
	if (stage_fail2ban_rs) >/dev/null 2>&1; then exit 1; fi
) || fail "broken fail2ban-client probe was accepted"

# Valid download via latest version succeeds, and re-running after install skips download
(
	reset_env
	DL_COUNT=0
	latest_fail2ban_rs_version() { printf '1.1.2'; }
	gh_fetch() {
		DL_COUNT=$((DL_COUNT + 1))
		case "$1" in
			*.tar.gz) cp -- "$GOOD_TAR" "$2" ;;
			*.tar.gz.sha256) cp -- "$GOOD_TAR.sha256" "$2" ;;
			*) return 1 ;;
		esac
	}
	systemctl() { return 1; }
	stage_fail2ban_rs
	[ "$FAIL2BAN_RS_NEEDS_INSTALL" = 1 ] || exit 1
	[ "$DL_COUNT" = 2 ] || exit 2
	commit_fail2ban_rs
	[ "$FAIL2BAN_RS_SWAPPED" = 1 ] || exit 3
	[ "$(cat "$F2B_RS_MARKER")" = "fail2ban-rs-1.1.2-linux-amd64" ] || exit 4
	cleanup_fail2ban_rs_stage

	# Same target version now installed: stage_fail2ban_rs must skip download
	FAIL2BAN_RS_SWAPPED=0
	stage_fail2ban_rs
	[ "$FAIL2BAN_RS_NEEDS_INSTALL" = 0 ] || exit 5
	[ "$DL_COUNT" = 2 ] || exit 6
) || fail "download/install/skip-same-version flow failed"

# --- 3) upgrade rollback restores previous fail2ban-rs files -----------------
(
	reset_env
	: > "$TMP/inst.log"
	# Seed an existing 1.1.1 installation
	for b in fail2ban-server fail2ban-client fail2ban-regex; do
		printf '#!/usr/bin/env bash\necho old-1.1.1\n' > "$F2B_BIN_DIR/$b"
		chmod 0755 "$F2B_BIN_DIR/$b"
	done
	printf '[Unit]\nDescription=old 1.1.1\n' > "$F2B_UNIT_DIR/fail2ban.service"
	printf 'fail2ban-rs-1.1.1-linux-amd64\n' > "$F2B_RS_MARKER"
	printf '[DEFAULT]\n' > "$F2B_ETC/fail2ban.conf"
	printf '[DEFAULT]\n' > "$F2B_ETC/jail.conf"

	systemctl() {
		printf 'systemctl %s\n' "$*" >> "$TMP/calls"
		case "$1" in
			is-active) return 0 ;;
			stop|daemon-reload) return 0 ;;
			*) return 0 ;;
		esac
	}
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$GOOD_TAR"
	stage_fail2ban_rs
	[ "$FAIL2BAN_RS_NEEDS_INSTALL" = 1 ] || exit 1
	commit_fail2ban_rs
	[ "$FAIL2BAN_STOPPED" = 1 ] || exit 2
	[ "$(cat "$F2B_RS_MARKER")" = "fail2ban-rs-1.1.2-linux-amd64" ] || exit 3
	[ -f "$F2B_UNIT_DIR/fail2ban.socket" ] || exit 4

	# Simulate post-swap failure -> restore must bring 1.1.1 back and remove new socket
	restore_fail2ban_rs_install
	[ "$(cat "$F2B_RS_MARKER")" = "fail2ban-rs-1.1.1-linux-amd64" ] || exit 5
	grep -q 'old-1.1.1' "$F2B_BIN_DIR/fail2ban-client" || exit 6
	grep -q 'Description=old 1.1.1' "$F2B_UNIT_DIR/fail2ban.service" || exit 7
	[ ! -e "$F2B_UNIT_DIR/fail2ban.socket" ] || exit 8
	cleanup_fail2ban_rs_stage
	cleanup_fail2ban_rs_rollback
) || fail "upgrade rollback did not restore previous fail2ban-rs installation"

# --- 4) migration rollback from distro fail2ban uninstalls new /usr/local ----
(
	reset_env
	: > "$TMP/inst.log"
	FAIL2BAN_RS_HAD_DISTRO=1
	printf '[DEFAULT]\n' > "$F2B_ETC/fail2ban.conf"
	printf '[DEFAULT]\n' > "$F2B_ETC/jail.conf"
	systemctl() {
		printf 'systemctl %s\n' "$*" >> "$TMP/calls"
		return 0
	}
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$GOOD_TAR"
	stage_fail2ban_rs
	commit_fail2ban_rs
	[ -x "$F2B_BIN_DIR/fail2ban-server" ] || exit 1
	restore_fail2ban_rs_install
	[ ! -e "$F2B_BIN_DIR/fail2ban-server" ] || exit 2
	[ ! -e "$F2B_RS_MARKER" ] || exit 3
	grep -qx -- '--uninstall' "$TMP/inst.log" || exit 4
	cleanup_fail2ban_rs_stage
) || fail "distro migration rollback did not uninstall new fail2ban-rs files"

# --- 5) remove_distro_fail2ban_pkg unmasks, removes pkg, restarts & verifies -
(
	reset_env
	# A regular user override unit must NOT be removed by unmask_fail2ban_service
	printf '[Unit]\nDescription=custom\n' > "$POLICY_UNIT_DIR/fail2ban.service"
	unmask_fail2ban_service
	[ -f "$POLICY_UNIT_DIR/fail2ban.service" ] || exit 1
	rm -f -- "$POLICY_UNIT_DIR/fail2ban.service"

	pkg_installed() { [ "$1" = fail2ban ]; }
	apt-get() {
		printf 'apt-get %s\n' "$*" >> "$TMP/calls"
		# Simulate older deb-systemd-helper masking fail2ban.service on remove
		ln -s /dev/null "$POLICY_UNIT_DIR/fail2ban.service" 2>/dev/null || true
		return 0
	}
	systemctl() { printf 'systemctl %s\n' "$*" >> "$TMP/calls"; return 0; }
	verify_fail2ban_jails() { printf 'verify %s\n' "$*" >> "$TMP/calls"; return 0; }

	remove_distro_fail2ban_pkg
	[ ! -L "$POLICY_UNIT_DIR/fail2ban.service" ] || exit 2
	grep -qx 'apt-get remove -y -qq fail2ban' "$TMP/calls" || exit 3
	grep -qx 'systemctl daemon-reload' "$TMP/calls" || exit 4
	grep -qx 'systemctl disable --now fail2ban.socket' "$TMP/calls" || exit 5
	grep -qx 'systemctl reenable fail2ban.service' "$TMP/calls" || exit 6
	grep -qx 'systemctl restart fail2ban.service' "$TMP/calls" || exit 7
	grep -qx 'verify running' "$TMP/calls" || exit 8
) || fail "remove_distro_fail2ban_pkg sequence failed"

echo "fail2ban-rs tests: pass"
