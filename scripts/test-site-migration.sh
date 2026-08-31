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
EOF

bash "$MIGRATOR" "$TMP/Caddyfile" "$TMP/main.out" "$TMP/output-sites" "$TMP/existing" > "$TMP/domains"

diff -u <(printf 'legacy.example.com\ncurrent.example.com\n') "$TMP/domains"
grep -q '^admin\.example\.com {' "$TMP/main.out"
grep -q '^http://127\.0\.0\.1:8080 {' "$TMP/main.out"
! grep -q '^legacy\.example\.com {' "$TMP/main.out"
! grep -q '^current\.example\.com {' "$TMP/main.out"

for domain in legacy.example.com current.example.com; do
	test -f "$TMP/output-sites/$domain.caddy"
	grep -q '^[[:space:]]*import abuseguard$' "$TMP/output-sites/$domain.caddy"
	! grep -q 'caddy_abuseguard_site' "$TMP/output-sites/$domain.caddy"
	! grep -q 'log caddy_abuseguard' "$TMP/output-sites/$domain.caddy"
done
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

echo "site migration tests: pass"
