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
	export F2B_LOGROTATE="$TMP/fs/logrotate.d/fail2ban"
	export F2B_PROC_ROOT="$TMP/fs/proc"
	POLICY_UNIT_DIR="$TMP/fs/policy-units"
	ARCH=amd64
	FAIL2BAN_RS_NEEDS_INSTALL=0
	FAIL2BAN_RS_SWAPPED=0
	FAIL2BAN_RS_TARGET_NAME=""
	FAIL2BAN_RS_STAGE_DIR=""
	FAIL2BAN_RS_ARCHIVE=""
	FAIL2BAN_RS_INSTALLER=""
	FAIL2BAN_RS_STAGED_CLIENT=""
	FAIL2BAN_RS_ROLLBACK_DIR=""
	F2B_DEB=""
	F2B_REMOVE_STARTED=0
	F2B_LOGROTATE_CREATED=0
	F2B_ENABLE_CHANGED=0
	F2B_UNITS_CHANGED=0
	FAIL2BAN_PAUSED=0
	FAIL2BAN_STOPPED=0
	FAIL2BAN_SOCKET_STOPPED=0
	PAUSED_JAILS_DONE=""
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
	[ ! -e "$F2B_UNIT_DIR/fail2ban.socket" ] || exit 4
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
	stage_distro_fail2ban_pkg() { return 0; }
	apt-get() {
		if [ "$1" = -s ]; then printf 'Remv fail2ban [1.1.0]\n'; return 0; fi
		printf 'apt-get %s\n' "$*" >> "$TMP/calls"
		# Simulate older deb-systemd-helper masking fail2ban.service on remove
		ln -s /dev/null "$POLICY_UNIT_DIR/fail2ban.service" 2>/dev/null || true
		return 0
	}
	systemctl() { printf 'systemctl %s\n' "$*" >> "$TMP/calls"; return 0; }
	verify_fail2ban_rs_daemon() { printf 'verify-daemon\n' >> "$TMP/calls"; return 0; }
	verify_fail2ban_jails() { printf 'verify %s\n' "$*" >> "$TMP/calls"; return 0; }

	remove_distro_fail2ban_pkg
	[ ! -L "$POLICY_UNIT_DIR/fail2ban.service" ] || exit 2
	grep -qx 'apt-get remove --no-auto-remove -y -qq fail2ban' "$TMP/calls" || exit 3
	grep -qx 'systemctl daemon-reload' "$TMP/calls" || exit 4
	grep -qx 'systemctl disable --now fail2ban.socket' "$TMP/calls" || exit 5
	grep -qx 'systemctl reenable fail2ban.service' "$TMP/calls" || exit 6
	grep -qx 'systemctl restart fail2ban.service' "$TMP/calls" || exit 7
	grep -qx 'verify-daemon' "$TMP/calls" || exit 8
	grep -qx 'verify running' "$TMP/calls" || exit 9
) || fail "remove_distro_fail2ban_pkg sequence failed"

# A missing rollback package or reverse dependency must prevent removal.
(
	reset_env
	pkg_installed() { return 0; }
	for scenario in missing-deb reverse-dependency; do
		apt-get() {
			if [ "$1" = -s ]; then
				echo "Remv fail2ban [1.1.0]"
				[ "$scenario" != reverse-dependency ] || echo "Remv dependent [1.0]"
			else
				touch "$TMP/unexpected-remove"
			fi
		}
		stage_distro_fail2ban_pkg() { [ "$scenario" != missing-deb ]; }
		remove_distro_fail2ban_pkg
		[ ! -e "$TMP/unexpected-remove" ] || exit 1
	done
) || fail "unable to safely roll back a package removal"

# A socket-activated installation returns to socket-only operation after rollback.
(
	reset_env
	systemctl() {
		case "$*" in
			"is-enabled fail2ban.socket") echo enabled ;;
			"is-enabled fail2ban.service") echo disabled; return 1 ;;
			"is-active --quiet fail2ban.socket") return 0 ;;
			"is-active --quiet fail2ban.service") [ -f "$TMP/new-service-active" ] ;;
			*) echo "$*" >> "$TMP/calls" ;;
		esac
	}
	snapshot_fail2ban_units
	touch "$TMP/new-service-active"
	restore_fail2ban_units
	grep -qx 'reenable fail2ban.socket' "$TMP/calls" || exit 1
	grep -qx 'disable fail2ban.service' "$TMP/calls" || exit 2
	grep -qx 'stop fail2ban.service' "$TMP/calls" || exit 3
	if grep -Eq '^(re)?start fail2ban.service$' "$TMP/calls"; then exit 4; fi
) || fail "socket-only startup state was not restored"

# --- 6) Debian host without fail2ban.socket: stop only active service --------
(
	reset_env
	: > "$TMP/calls"
	printf '[DEFAULT]\n' > "$F2B_ETC/fail2ban.conf"
	printf '[DEFAULT]\n' > "$F2B_ETC/jail.conf"
	# Simulate Debian: fail2ban.service is active, fail2ban.socket does NOT exist
	# (stopping a missing unit returns exit code 5 like real systemd).
	systemctl() {
		printf 'systemctl %s\n' "$*" >> "$TMP/calls"
		case "$*" in
			"is-active --quiet fail2ban.socket") return 4 ;;
			"is-active --quiet fail2ban.service") return 0 ;;
			"stop fail2ban.socket"*) return 5 ;;
			"stop fail2ban.service") return 0 ;;
			"start fail2ban.service") return 0 ;;
			*) return 0 ;;
		esac
	}
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$GOOD_TAR"
	stage_fail2ban_rs
	commit_fail2ban_rs
	[ "$FAIL2BAN_STOPPED" = 1 ] || exit 1
	[ "$FAIL2BAN_SOCKET_STOPPED" = 0 ] || exit 2
	grep -qx 'systemctl stop fail2ban.service' "$TMP/calls" || exit 3
	if grep -q 'systemctl stop fail2ban.socket' "$TMP/calls"; then exit 4; fi
	# If a subsequent step fails, resume must start fail2ban.service (not socket)
	resume_fail2ban_after_failure
	grep -qx 'systemctl start fail2ban.service' "$TMP/calls" || exit 5
	if grep -q 'systemctl start fail2ban.socket' "$TMP/calls"; then exit 6; fi
	cleanup_fail2ban_rs_stage
) || fail "Debian missing-socket stop/resume flow failed"

# --- 7) mid-write failure inside sub-installer still triggers rollback -------
(
	reset_env
	# Build an archive whose sub-installer writes marker + server, then dies!
	PARTIAL_TAR="$TMP/fail2ban-rs-1.1.4-linux-amd64.tar.gz"
	src="$TMP/build-partial"
	rm -rf -- "$src"
	mkdir -p "$src/fail2ban-rs-1.1.4-linux-amd64/bin"
	for bin in fail2ban-server fail2ban-client fail2ban-regex; do
		printf '#!/usr/bin/env bash\nprintf "Fail2Ban 1.1.4\\n"\n' > "$src/fail2ban-rs-1.1.4-linux-amd64/bin/$bin"
		chmod 0755 "$src/fail2ban-rs-1.1.4-linux-amd64/bin/$bin"
	done
	cat > "$src/fail2ban-rs-1.1.4-linux-amd64/install.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# Mimic fail2ban-rs writing installed marker + one binary before failing mid-way
printf 'fail2ban-rs-1.1.4-linux-amd64\n' > "$F2B_RS_MARKER"
printf '#!/usr/bin/env bash\necho partial-1.1.4\n' > "$F2B_BIN_DIR/fail2ban-server"
chmod 0755 "$F2B_BIN_DIR/fail2ban-server"
exit 1
EOF
	chmod 0755 "$src/fail2ban-rs-1.1.4-linux-amd64/install.sh"
	tar -czf "$PARTIAL_TAR" -C "$src" fail2ban-rs-1.1.4-linux-amd64
	sha256sum "$PARTIAL_TAR" | awk '{print $1 "  fail2ban-rs-1.1.4-linux-amd64.tar.gz"}' > "$PARTIAL_TAR.sha256"
	rm -rf -- "$src"

	# Seed previous 1.1.1 installation
	for b in fail2ban-server fail2ban-client fail2ban-regex; do
		printf '#!/usr/bin/env bash\necho old-1.1.1\n' > "$F2B_BIN_DIR/$b"
		chmod 0755 "$F2B_BIN_DIR/$b"
	done
	printf '[Unit]\nDescription=old 1.1.1\n' > "$F2B_UNIT_DIR/fail2ban.service"
	printf 'fail2ban-rs-1.1.1-linux-amd64\n' > "$F2B_RS_MARKER"
	printf '[DEFAULT]\n' > "$F2B_ETC/fail2ban.conf"
	printf '[DEFAULT]\n' > "$F2B_ETC/jail.conf"
	systemctl() { return 1; }

	ABUSEGUARD_FAIL2BAN_ARCHIVE="$PARTIAL_TAR"
	stage_fail2ban_rs
	# Drive the real die -> exit 1 -> EXIT trap -> on_install_exit rollback path!
	if (
		trap 'restore_fail2ban_rs_install; cleanup_fail2ban_rs_stage; cleanup_fail2ban_rs_rollback' EXIT
		commit_fail2ban_rs
	) >/dev/null 2>&1; then
		exit 1
	fi
	# Rollback in the EXIT trap must have restored 1.1.1 marker and server binary
	[ "$(cat "$F2B_RS_MARKER")" = "fail2ban-rs-1.1.1-linux-amd64" ] || exit 2
	grep -q 'old-1.1.1' "$F2B_BIN_DIR/fail2ban-server" || exit 3
	# Subsequent retry must NOT falsely see 1.1.4 as already installed
	FAIL2BAN_RS_SWAPPED=0
	stage_fail2ban_rs
	[ "$FAIL2BAN_RS_NEEDS_INSTALL" = 1 ] || exit 4
	cleanup_fail2ban_rs_stage
	cleanup_fail2ban_rs_rollback
) || fail "partial sub-installer write did not roll back cleanly"

# --- 8) verify_fail2ban_rs_daemon checks MainPID exe and unit/drop-ins -------
(
	reset_env
	printf '#!/usr/bin/env bash\nexit 0\n' > "$F2B_BIN_DIR/fail2ban-server"
	printf '#!/usr/bin/env bash\nexit 0\n' > "$TMP/fs/distro-fail2ban-server"
	chmod 0755 "$F2B_BIN_DIR/fail2ban-server" "$TMP/fs/distro-fail2ban-server"
	mkdir -p "$F2B_PROC_ROOT/4242" "$TMP/fs/custom-units"
	printf '[Service]\nExecStart=/usr/local/bin/fail2ban-server -xf start\n' > "$F2B_UNIT_DIR/fail2ban.service"
	printf '[Service]\nExecReload=/usr/bin/fail2ban-client reload\n' > "$TMP/fs/custom-units/bad-dropin.conf"
	printf '[Service]\n# ExecStart=/usr/bin/fail2ban-server -xf start\nTimeoutStopSec=30\n' > "$TMP/fs/custom-units/good-dropin.conf"

	MOCK_PID=4242
	MOCK_FRAG="$F2B_UNIT_DIR/fail2ban.service"
	MOCK_DROPINS=""
	MOCK_EXE=""
	set_mock_exe() {
		MOCK_EXE="$1"
		rm -f -- "$F2B_PROC_ROOT/4242/exe"
		ln -sf "$1" "$F2B_PROC_ROOT/4242/exe"
		# On Linux, ln -sf creates a real symlink so real readlink -f runs.
		# On Windows Git Bash without native symlinks, stub readlink for the mock proc exe.
		if [ ! -L "$F2B_PROC_ROOT/4242/exe" ]; then
			readlink() {
				if [ "${2:-}" = "$F2B_PROC_ROOT/4242/exe" ]; then
					command readlink -f "$MOCK_EXE"
				else
					command readlink "$@"
				fi
			}
		fi
	}
	systemctl() {
		case "$*" in
			"show -p MainPID --value fail2ban.service") printf '%s\n' "$MOCK_PID" ;;
			"cat --no-pager fail2ban.service")
				cat "$MOCK_FRAG" || return 1
				[ -z "$MOCK_DROPINS" ] || cat "$MOCK_DROPINS" ;;
			*) return 1 ;;
		esac
	}

	# Wrong exe (still running Python distro server) must be rejected
	set_mock_exe "$TMP/fs/distro-fail2ban-server"
	if (verify_fail2ban_rs_daemon) >/dev/null 2>&1; then exit 1; fi

	# Correct exe, but drop-in still points to /usr/bin/fail2ban-client must be rejected
	set_mock_exe "$F2B_BIN_DIR/fail2ban-server"
	MOCK_DROPINS="$TMP/fs/custom-units/bad-dropin.conf"
	if (verify_fail2ban_rs_daemon) >/dev/null 2>&1; then exit 2; fi

	# Correct exe + clean drop-in (with commented legacy line) must pass
	MOCK_DROPINS="$TMP/fs/custom-units/good-dropin.conf"
	verify_fail2ban_rs_daemon || exit 3
) || fail "verify_fail2ban_rs_daemon identity checks failed"

# --- 9) ensure_fail2ban_logrotate creates only when absent -------------------
(
	reset_env
	ensure_fail2ban_logrotate
	[ -f "$F2B_LOGROTATE" ] || exit 1
	grep -qF "$F2B_BIN_DIR/fail2ban-client flushlogs" "$F2B_LOGROTATE" || exit 2
	# Existing admin rule must not be overwritten
	printf '# custom admin logrotate\n' > "$F2B_LOGROTATE"
	ensure_fail2ban_logrotate
	grep -qx '# custom admin logrotate' "$F2B_LOGROTATE" || exit 3
) || fail "ensure_fail2ban_logrotate behaviour failed"

# --- 10) first-time AbuseGuard install failure still rolls back fail2ban-rs --
(
	reset_env
	: > "$TMP/calls"
	printf '[DEFAULT]\n' > "$F2B_ETC/fail2ban.conf"
	printf '[DEFAULT]\n' > "$F2B_ETC/jail.conf"
	systemctl() {
		printf 'systemctl %s\n' "$*" >> "$TMP/calls"
		case "$*" in
			"is-active --quiet fail2ban.socket") return 4 ;;
			"is-active --quiet fail2ban.service") return 0 ;;
			"disable fail2ban.service")
				# Must run before restore_fail2ban_rs_install deletes the unit file.
				[ -f "$F2B_UNIT_DIR/fail2ban.service" ] || return 9
				return 0 ;;
			*) return 0 ;;
		esac
	}
	ABUSEGUARD_FAIL2BAN_ARCHIVE="$GOOD_TAR"
	stage_fail2ban_rs
	commit_fail2ban_rs
	[ -x "$F2B_BIN_DIR/fail2ban-server" ] || exit 1
	# Simulate post-engine-swap failure on a first-time install (ENGINE_BACKUP="")
	INSTALL_COMPLETE=0
	ENGINE_SWAPPED=1
	ENGINE_BACKUP=""
	PANEL_SWAPPED=0
	STAGED_BIN=""
	STAGED_RELEASE_BIN=""
	UNIT_ROLLBACK_DIR=""
	F2B_ROLLBACK_DIR=""
	F2B_ENABLE_CHANGED=1
	ensure_fail2ban_logrotate
	mkdir "$TMP/deb"
	F2B_DEB="$TMP/deb/exact-version.deb"
	touch "$F2B_DEB"
	F2B_REMOVE_STARTED=1
	dpkg() { [ "$*" = "--force-confold -i $F2B_DEB" ] && touch "$TMP/reinstalled"; }
	on_install_exit
	[ -f "$TMP/reinstalled" ] && [ ! -e "$F2B_LOGROTATE" ] || exit 5
	[ ! -e "$F2B_BIN_DIR/fail2ban-server" ] || exit 2
	[ ! -e "$F2B_RS_MARKER" ] || exit 3
	grep -qx 'systemctl disable fail2ban.service' "$TMP/calls" || exit 6
	grep -Eq '^systemctl (re)?start fail2ban.service$' "$TMP/calls" || exit 4
) || fail "first-time install on_install_exit did not roll back fail2ban-rs"

# --- 11) else branch (keep new config on backup restore failure) keeps enable -
(
	reset_env
	: > "$TMP/calls"
	systemctl() {
		printf 'systemctl %s\n' "$*" >> "$TMP/calls"
		return 0
	}
	INSTALL_COMPLETE=0
	ENGINE_SWAPPED=1
	ENGINE_BACKUP="$TMP/nonexistent-engine-backup"
	ENGINE_BIN="$TMP/fs/bin/caddy-abuseguard"
	PANEL_SWAPPED=0
	STAGED_BIN=""
	STAGED_RELEASE_BIN=""
	UNIT_ROLLBACK_DIR=""
	F2B_ROLLBACK_DIR=""
	F2B_ENABLE_CHANGED=1
	F2B_UNITS_CHANGED=1
	ensure_fail2ban_logrotate
	on_install_exit 2>/dev/null
	if grep -qx 'systemctl disable fail2ban.service' "$TMP/calls"; then exit 1; fi
	grep -qx 'systemctl restart fail2ban' "$TMP/calls" || exit 2
	[ -f "$F2B_LOGROTATE" ] || exit 3
) || fail "on_install_exit else branch disabled fail2ban.service or removed logrotate"

# --- 12) panel PATH normalization and logtarget-aware log viewer -------------
(
	funcs="$TMP/panel-funcs.sh"
	: > "$funcs"
	for name in ensure_local_bin_path show_fail2ban_logs; do
		awk -v sig="$name() {" '
			index($0, sig) == 1 { p=1 }
			p { print }
			p && /^}$/ { exit }
		' "$ROOT/abuseguard.sh" >> "$funcs"
	done
	# shellcheck disable=SC1090
	source "$funcs"

	PATH="/tmp/mock:/usr/bin:/bin" ensure_local_bin_path
	# subshell check via explicit calls so PATH mutation is observed cleanly
	check_path() {
		local got
		got="$(PATH="$1"; ensure_local_bin_path; printf '%s' "$PATH")"
		[ "$got" = "$2" ] || { printf 'PATH(%s) -> %s (want %s)\n' "$1" "$got" "$2" >&2; exit 1; }
	}
	check_path "/tmp/mock:/usr/bin:/bin" "/tmp/mock:/usr/local/bin:/usr/bin:/bin"
	check_path "/usr/sbin:/usr/bin:/sbin:/bin" "/usr/sbin:/usr/local/bin:/usr/bin:/sbin:/bin"
	check_path "/usr/bin:/usr/local/bin:/bin" "/usr/local/bin:/usr/bin:/bin"
	check_path "/bin:/usr/bin" "/usr/local/bin:/bin:/usr/bin"
	check_path "/tmp/mock:/bin:/usr/bin" "/tmp/mock:/usr/local/bin:/bin:/usr/bin"
	check_path "/bin:/usr/local/bin:/usr/bin" "/usr/local/bin:/bin:/usr/bin"
	check_path "/tmp/mock:/usr/local/bin:/bin:/usr/bin" "/tmp/mock:/usr/local/bin:/bin:/usr/bin"
	check_path "/tmp/mock" "/tmp/mock:/usr/local/bin"
	check_path "" "/usr/local/bin"

	f2b_log="$TMP/fail2ban.log"
	printf '2026-11-25 12:00:00 fail2ban.actions: NOTICE [sshd] Ban 198.51.100.7\n' > "$f2b_log"
	journalctl() { printf 'journal:%s\n' "$*"; }

	# File logtarget -> reads the file, not journalctl
	fail2ban-client() { printf 'Current logging target is:\n`- %s\n' "$f2b_log"; }
	out="$(show_fail2ban_logs)"
	grep -q 'Ban 198.51.100.7' <<< "$out" || exit 2

	# SYSTEMD-JOURNAL logtarget -> reads journalctl even though file exists on disk
	fail2ban-client() { printf 'Current logging target is:\n`- SYSTEMD-JOURNAL\n'; }
	out="$(show_fail2ban_logs)"
	[ "$out" = 'journal:-u fail2ban -n 20 --no-pager' ] || exit 3

	# SYSLOG logtarget -> queries fail2ban unit (fail2ban-rs uses fail2ban.actions ident)
	fail2ban-client() { printf 'Current logging target is:\n`- SYSLOG\n'; }
	out="$(show_fail2ban_logs)"
	[ "$out" = 'journal:-u fail2ban -n 20 --no-pager' ] || exit 4

	# Unreachable daemon -> falls back to unit journal
	fail2ban-client() { return 1; }
	out="$(show_fail2ban_logs)"
	[ "$out" = 'journal:-u fail2ban -n 20 --no-pager' ] || exit 5
) || fail "panel PATH or logtarget log viewer checks failed"

# --- 13) queue action logs enqueue failures via logger and still exits 0 -----
(
	act_line="$(sed -n 's/^actionban = //p' "$ROOT/assets/fail2ban/action.d/caddy-abuseguard-queue.conf")"
	[ -n "$act_line" ] || exit 1
	mock_bin="$TMP/queue-bin"
	mkdir -p "$mock_bin"
	cat > "$mock_bin/logger" <<EOF
#!/usr/bin/env bash
printf '%s\n' "\$*" > "$TMP/logger.out"
EOF
	cat > "$mock_bin/stub-fail" <<'EOF'
#!/usr/bin/env bash
echo "[abuseguard] enqueue: disk full" >&2
exit 1
EOF
	cat > "$mock_bin/stub-ok" <<'EOF'
#!/usr/bin/env bash
echo "[abuseguard] enqueue: disabled" >&2
exit 0
EOF
	chmod 0755 "$mock_bin/logger" "$mock_bin/stub-fail" "$mock_bin/stub-ok"
	prefix="/usr/bin/setpriv --reuid=abuseguard --regid=abuseguard --init-groups -- /usr/local/libexec/caddy-abuseguard enqueue --ip <ip> --profile <profile> --failures <failures> --window <window> --transport <transport> --port <target_port>"
	case "$act_line" in *"$prefix"*) ;; *) exit 6 ;; esac
	cmd_fail="${act_line/"$prefix"/"$mock_bin/stub-fail"}"
	PATH="$mock_bin:$PATH" sh -c "$cmd_fail" || exit 2
	grep -q 'enqueue: disk full' "$TMP/logger.out" || exit 3

	: > "$TMP/logger.out"
	cmd_ok="${act_line/"$prefix"/"$mock_bin/stub-ok"}"
	PATH="$mock_bin:$PATH" sh -c "$cmd_ok" || exit 4
	[ ! -s "$TMP/logger.out" ] || exit 5
) || fail "queue action failure logging check failed"

echo "fail2ban-rs tests: pass"
