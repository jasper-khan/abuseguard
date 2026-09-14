#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATOR="$ROOT/scripts/migrate-caddy-sites.sh"
TMP="$(mktemp -d)"

cleanup_temp_tree() {
	local root="$1" path
	case "$root" in /tmp/tmp.*|/var/tmp/tmp.*) : ;; *) return 1 ;; esac
	while IFS= read -r -d "" path; do
		if [ -d "$path" ] && [ ! -L "$path" ]; then rmdir -- "$path"
		else rm -f -- "$path"
		fi
	done < <(find "$root" -xdev -depth -mindepth 1 -print0)
	rmdir -- "$root"
}
trap 'cleanup_temp_tree "$TMP"' EXIT

mkdir -p "$TMP/existing" "$TMP/output-sites"
printf '# placeholder\n' > "$TMP/existing/_placeholder.caddy"

cat > "$TMP/Caddyfile" <<'EOF'
{
	servers {
		trusted_proxies static 127.0.0.1/8
	}
}

(cf_tls) {
	tls {
		dns cloudflare {env.CF_API_TOKEN}
	}
}

admin.example.com {
	@allowed remote_ip 192.0.2.1
	handle @allowed {
		reverse_proxy 127.0.0.1:8080
	}
}

legacy.example.com {
	import cf_tls
	# These fixed markers let Fail2Ban classify protected traffic without
	# retaining the site's host name or the requested path in the access log.
	log_append caddy_abuseguard_site protected
	@caddy_abuseguard_probe path /.env /.git
	log_append @caddy_abuseguard_probe caddy_abuseguard_probe web-probe
	log caddy_abuseguard {
		output file /var/log/caddy/abuseguard-access.json {
			mode 0640
		}
		format filter {
			wrap json
		}
	}
	handle /sub/* {
		reverse_proxy 127.0.0.1:2096
	}
	handle {
		reverse_proxy 127.0.0.1:60022
	}
}

current.example.com {
	import abuseguard
	reverse_proxy 127.0.0.1:3000
}

http://127.0.0.1:8080 {
	bind 127.0.0.1
	import abuseguard
	respond "ok"
}

:8788 {
	reverse_proxy 127.0.0.1:8787
}

static.example.com {
	respond "not a reverse proxy"
}
EOF

bash "$MIGRATOR" "$TMP/Caddyfile" "$TMP/main.out" "$TMP/output-sites" "$TMP/existing" > "$TMP/domains"

diff -u <(printf 'admin.example.com\nlegacy.example.com\ncurrent.example.com\n') "$TMP/domains"
! grep -q '^admin\.example\.com {' "$TMP/main.out"
grep -q '^http://127\.0\.0\.1:8080 {' "$TMP/main.out"
grep -q '^:8788 {' "$TMP/main.out"
grep -q '^static\.example\.com {' "$TMP/main.out"
! grep -q '^legacy\.example\.com {' "$TMP/main.out"
! grep -q '^current\.example\.com {' "$TMP/main.out"

for domain in admin.example.com legacy.example.com current.example.com; do
	test -f "$TMP/output-sites/$domain.caddy"
	grep -q '^[[:space:]]*import abuseguard$' "$TMP/output-sites/$domain.caddy"
	! grep -q 'caddy_abuseguard_site' "$TMP/output-sites/$domain.caddy"
	! grep -q 'log caddy_abuseguard' "$TMP/output-sites/$domain.caddy"
done
grep -q '@allowed remote_ip 192\.0\.2\.1' "$TMP/output-sites/admin.example.com.caddy"
grep -q 'reverse_proxy 127\.0\.0\.1:8080' "$TMP/output-sites/admin.example.com.caddy"
grep -q 'reverse_proxy 127\.0\.0\.1:2096' "$TMP/output-sites/legacy.example.com.caddy"
grep -q 'reverse_proxy 127\.0\.0\.1:60022' "$TMP/output-sites/legacy.example.com.caddy"

mkdir -p "$TMP/second-sites"
bash "$MIGRATOR" "$TMP/main.out" "$TMP/main.second" "$TMP/second-sites" "$TMP/output-sites" > "$TMP/domains.second"
test ! -s "$TMP/domains.second"
cmp "$TMP/main.out" "$TMP/main.second"

cat > "$TMP/unsupported" <<'EOF'
one.example.com, two.example.com {
	import abuseguard
	reverse_proxy 127.0.0.1:8080
}
EOF
if bash "$MIGRATOR" "$TMP/unsupported" "$TMP/unsupported.out" "$TMP/unsupported-sites" "$TMP/existing" >/dev/null 2>&1; then
	echo "expected multi-domain migration to fail" >&2
	exit 1
fi

printf 'existing\n' > "$TMP/existing/conflict.example.com.caddy"
cat > "$TMP/conflict" <<'EOF'
conflict.example.com {
	import abuseguard
	reverse_proxy 127.0.0.1:8080
}
EOF
if bash "$MIGRATOR" "$TMP/conflict" "$TMP/conflict.out" "$TMP/conflict-sites" "$TMP/existing" >/dev/null 2>&1; then
	echo "expected existing target migration to fail" >&2
	exit 1
fi

# The installer must not modify existing Caddy files before the full candidate
# validates, and a failure while installing the final Caddyfile must restore
# every site file already touched by the commit loop.
FUNCTIONS="$TMP/install-migration-functions.sh"
extract_function() {
	local name="$1"
	awk -v signature="$name() {" '
		index($0, signature) == 1 { printing = 1 }
		printing { print }
		printing && /^}$/ { exit }
	' "$ROOT/install.sh"
}
for name in cleanup_temp_tree normalize_caddy_file ensure_site_protected migration_abort migrate_caddy_sites; do
	extract_function "$name" >> "$FUNCTIONS"
done

mkdir -p "$TMP/transaction/etc/sites"
cat > "$TMP/transaction/etc/Caddyfile" <<EOF
import $TMP/transaction/etc/abuseguard.caddy
import $TMP/transaction/etc/sites/*.caddy
EOF
cat > "$TMP/transaction/etc/sites/example.com.caddy" <<'EOF'
example.com {
	import ../common.conf
	reverse_proxy 127.0.0.1:8080
}
EOF
printf 'header X-Test "candidate-relative-import"\n' > "$TMP/transaction/etc/common.conf"
printf 'original snippet\n' > "$TMP/transaction/etc/abuseguard.caddy"
cat > "$TMP/caddy-mock" <<'EOF'
#!/usr/bin/env bash
[ "${1:-}" = fmt ]
EOF
chmod 0755 "$TMP/caddy-mock"
cp -- "$TMP/transaction/etc/Caddyfile" "$TMP/transaction/Caddyfile.original"
cp -- "$TMP/transaction/etc/sites/example.com.caddy" "$TMP/transaction/site.original"
cp -- "$TMP/transaction/etc/abuseguard.caddy" "$TMP/transaction/snippet.original"

run_migration() {
	local validation="$1" fail_target="${2:-}"
	VALIDATE_RESULT="$validation" FAIL_TARGET="$fail_target" \
	CADDYFILE="$TMP/transaction/etc/Caddyfile" \
	CADDY_ETC="$TMP/transaction/etc" \
		SITES_DIR="$TMP/transaction/etc/sites" \
		CADDY_BIN="$TMP/caddy-mock" \
		SRC_DIR="$ROOT" \
		SNIPPET="$TMP/transaction/etc/abuseguard.caddy" \
		bash --noprofile --norc -c '
		set -uo pipefail
		source "$1"
		log() { :; }
		warn() { :; }
		die() { exit 1; }
		validate_caddyfile() {
			local candidate_import
			[ "${VALIDATE_RESULT:-ok}" = ok ] || return 1
			! grep -Fq "import $SNIPPET" "$1"
			! grep -Fq "import $SITES_DIR" "$1"
			candidate_import="$(grep -E "^import .*/sites/\\*\\.caddy\$" "$1" | head -n1 | cut -d" " -f2)"
			[ -n "$candidate_import" ] && [ -f "${candidate_import%/*}/../common.conf" ]
		}
		install() {
			if [ "${1:-}" = -d ]; then
				shift
				while [ "${1:-}" = -m ]; do shift 2; done
				command mkdir -p "$@"
				return
			fi
			local target="${!#}"
			[ -z "${FAIL_TARGET:-}" ] || [ "$target" != "$FAIL_TARGET" ] || return 1
			command install "$@"
		}
		migrate_caddy_sites "$CADDYFILE"
	' _ "$FUNCTIONS"
}

if run_migration fail; then
	echo "expected candidate validation to fail" >&2
	exit 1
fi
cmp "$TMP/transaction/Caddyfile.original" "$TMP/transaction/etc/Caddyfile"
cmp "$TMP/transaction/site.original" "$TMP/transaction/etc/sites/example.com.caddy"
cmp "$TMP/transaction/snippet.original" "$TMP/transaction/etc/abuseguard.caddy"

run_migration ok
grep -q '^[[:space:]]*import abuseguard$' "$TMP/transaction/etc/sites/example.com.caddy"
cmp "$ROOT/assets/caddy/abuseguard.caddy" "$TMP/transaction/etc/abuseguard.caddy"

cp -- "$TMP/transaction/Caddyfile.original" "$TMP/transaction/etc/Caddyfile"
cp -- "$TMP/transaction/site.original" "$TMP/transaction/etc/sites/example.com.caddy"
cp -- "$TMP/transaction/snippet.original" "$TMP/transaction/etc/abuseguard.caddy"
if run_migration ok "$TMP/transaction/etc/Caddyfile"; then
	echo "expected final Caddyfile install to fail" >&2
	exit 1
fi
cmp "$TMP/transaction/Caddyfile.original" "$TMP/transaction/etc/Caddyfile"
cmp "$TMP/transaction/site.original" "$TMP/transaction/etc/sites/example.com.caddy"
cmp "$TMP/transaction/snippet.original" "$TMP/transaction/etc/abuseguard.caddy"

echo "site migration tests: pass"
