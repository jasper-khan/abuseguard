#!/usr/bin/env bash
# Verify the Nginx -> privacy-trimmed JSON -> fail2ban-filter contract with
# real binaries.
#
#   sudo scripts/verify-nginx-log-contract.sh
#
# The Caddy verifier drives the real Caddy binary; this is its Nginx peer. It
# installs the project's real HTTP-level config and managed site into an
# isolated prefix, starts real Nginx inside a throwaway network namespace, and
# drives real TLS traffic (HTTP/1.1 and HTTP/2). It then runs the REAL fail2ban
# filter files over the produced log with fail2ban-regex and executes the real
# logrotate entry.
#
# Covered behaviour:
#   - generated site config loads with the shared snippet (nginx -t / nginx -T)
#   - trusted Cloudflare edge source: CF-Connecting-IP becomes client_ip
#   - untrusted source: the same spoofed header is ignored
#   - IPv6 trusted source works
#   - the log never contains URI, query, headers or body, and has no extra field
#   - h1 and h2 probes still match caddy-abuseguard-probe-h1/h2
#   - rotation recreates the log and Postfix-style reload reopens it
#
# Requires root (network namespace), nginx, fail2ban-regex, curl, openssl,
# python3 and logrotate. CI runs this on Ubuntu with real packages.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REAL_NGINX="${REAL_NGINX:-$(command -v nginx || true)}"
FILTER_DIR="$REPO_ROOT/assets/fail2ban/filter.d"
[ -n "$REAL_NGINX" ] || { echo 'verify-nginx-log-contract: nginx binary not found' >&2; exit 2; }
for cmd in fail2ban-regex curl openssl python3 logrotate jq ip; do
	command -v "$cmd" >/dev/null 2>&1 || { echo "verify-nginx-log-contract: missing $cmd" >&2; exit 2; }
done
[ "$(id -u)" = 0 ] || { echo 'verify-nginx-log-contract: run as root (uses a network namespace)' >&2; exit 2; }

TMP="$(mktemp -d)"
NS="ag-nginx-contract-$$"
fail() { printf '\033[1;31m[nginx-contract]\033[0m %s (evidence: %s)\n' "$*" "$TMP" >&2; exit 1; }
ok()   { printf '\033[1;32m[nginx-contract]\033[0m %s\n' "$*"; }

cleanup() {
	if [ -f "$TMP/nginx.pid" ] && [ -d "/var/run/netns/$NS" ]; then
		ip netns exec "$NS" "$TMP/bin/nginx" -s quit >/dev/null 2>&1 || true
	fi
	[ -z "${UPSTREAM_PID:-}" ] || kill "$UPSTREAM_PID" 2>/dev/null || true
	ip netns del "$NS" >/dev/null 2>&1 || true
	rm -rf -- "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/bin" "$TMP/nginx/conf.d" "$TMP/nginx/snippets" \
	"$TMP/nginx/sites-available" "$TMP/nginx/sites-enabled" \
	"$TMP/nginx/tmp" "$TMP/log" "$TMP/libexec" "$TMP/agconf" "$TMP/tls"

# --- isolated Nginx prefix ---------------------------------------------------
cat > "$TMP/nginx/nginx.conf" <<EOF
user root;
worker_processes 1;
pid $TMP/nginx.pid;
error_log $TMP/error.log notice;
events { worker_connections 128; }
http {
    access_log $TMP/default-access.log;
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
chmod 0755 "$TMP/bin/nginx"

# Scoped systemctl fixture: it only drives the real private Nginx master started
# below (MainPID from its pidfile) and never touches the host systemd.
cat > "$TMP/bin/systemctl" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/systemctl.calls"
case "\$*" in
    "show -p MainPID --value nginx")
        [ -s "$TMP/nginx.pid" ] || exit 1
        cat "$TMP/nginx.pid"
        exit 0
        ;;
    "is-active nginx") printf 'active\n'; exit 0 ;;
    "reload nginx")
        [ -e "$TMP/nginx.running" ] || exit 1
        ip netns exec "$NS" "$TMP/bin/nginx" -s reload
        exit \$?
        ;;
esac
exit 1
EOF
chmod 0755 "$TMP/bin/systemctl"

openssl req -x509 -newkey rsa:2048 -nodes -days 90 \
	-subj '/CN=example.test' -addext 'subjectAltName=DNS:example.test' \
	-keyout "$TMP/tls/privkey.pem" -out "$TMP/tls/fullchain.pem" >/dev/null 2>&1 \
	|| fail 'could not create the fixture TLS certificate'

cat > "$TMP/bin/certbot" <<EOF
#!/bin/sh
printf '%s\n' "\$*" >> "$TMP/certbot.calls"
name='' domain=''
while [ "\$#" -gt 0 ]; do
    case "\$1" in
        --cert-name) name="\$2"; shift 2 ;;
        -d) domain="\$2"; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "\$name" ] || exit 1
live="\$NGINX_LETSENCRYPT_DIR/live/\$name"
mkdir -p "\$live" "\$NGINX_LETSENCRYPT_DIR/renewal" || exit 1
cp "$TMP/tls/fullchain.pem" "\$live/fullchain.pem" || exit 1
cp "$TMP/tls/privkey.pem" "\$live/privkey.pem" || exit 1
printf '# fixture lineage for %s\n' "\$domain" > "\$NGINX_LETSENCRYPT_DIR/renewal/\$name.conf"
exit 0
EOF
chmod 0755 "$TMP/bin/certbot"

# --- install the real managed config into the fixture ------------------------
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
NGINX_LOGROTATE="$TMP/logrotate-abuseguard-nginx"
NGINX_LETSENCRYPT_DIR="$TMP/letsencrypt"
NGINX_LIBEXEC_DIR="$TMP/libexec"
NGINX_DEPLOY_HOOK="$TMP/libexec/abuseguard-nginx-deploy"
NGINX_RUNTIME_PATH="$TMP/libexec/abuseguard-nginx.sh"
AG_NGINX_CONF_DIR="$TMP/agconf"
AG_NGINX_CF_CREDENTIALS="$TMP/agconf/cloudflare.ini"
NGINX_SELFTEST_PORT=18080
NGINX_BIN="$TMP/bin/nginx"
NGINX_SYSTEMCTL="$TMP/bin/systemctl"
CERTBOT_BIN="$TMP/bin/certbot"
NGINX_CF_LIVE=0
NGINX_CERTBOT_PROPAGATION_SECONDS=0
PATH="$TMP/bin:$PATH"
export PATH NGINX_LETSENCRYPT_DIR

nginx_save_token 'contract-fixture-token' >/dev/null || fail 'nginx_save_token failed'
nginx_install_assets "$REPO_ROOT" >/dev/null 2>&1 || fail 'nginx_install_assets failed'
[ -f "$NGINX_CF_TRUST_INCLUDE" ] || fail 'Cloudflare trust include missing'

# --- pick concrete fixture addresses from the installed trust list ----------
read -r TRUSTED_SRC TRUSTED_DST TRUSTED6_SRC TRUSTED6_DST < <(
	python3 - "$NGINX_CF_TRUST_INCLUDE" <<'PY'
import ipaddress, sys
v4 = v6 = None
for line in open(sys.argv[1], encoding="utf-8"):
    parts = line.split()
    if len(parts) != 2 or parts[0] != "set_real_ip_from":
        continue
    net = ipaddress.ip_network(parts[1].rstrip(";"), strict=False)
    if net.version == 4 and v4 is None and net.num_addresses > 32:
        v4 = net
    if net.version == 6 and v6 is None and net.num_addresses > 32:
        v6 = net
if not v4 or not v6:
    sys.exit("no IPv4/IPv6 trusted ranges in the include")
print(v4.network_address + 16, v4.network_address + 1,
      v6.network_address + 16, v6.network_address + 1)
PY
) || fail 'could not derive trusted fixture addresses from the include'
[ -n "$TRUSTED_SRC" ] && [ -n "$TRUSTED6_SRC" ] || fail 'empty trusted fixture addresses'

# --- isolated network namespace ---------------------------------------------
ip netns add "$NS" || fail 'could not create a network namespace (need root + iproute2)'
ip -n "$NS" link set lo up
ip -n "$NS" addr add "$TRUSTED_DST/32" dev lo
ip -n "$NS" addr add "$TRUSTED_SRC/32" dev lo
ip -n "$NS" addr add 198.18.0.1/32 dev lo
ip -n "$NS" addr add 198.18.0.2/32 dev lo
ip -n "$NS" -6 addr add "$TRUSTED6_DST/128" dev lo nodad
ip -n "$NS" -6 addr add "$TRUSTED6_SRC/128" dev lo nodad

# Fixture upstream: records the headers Nginx actually forwards. No external
# service is contacted; this is the origin behind the managed site.
cat > "$TMP/upstream.py" <<'PY'
import http.server, json, sys, time
LOG = sys.argv[1]
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(dict(self.headers.items())) + '\n')
        if self.path == '/sse':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            chunk = b'data: first\n\n'
            self.wfile.write(b'%x\r\n%s\r\n' % (len(chunk), chunk))
            self.wfile.flush()
            time.sleep(3)
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
            return
        body = b'upstream ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = _handle
    do_POST = _handle
    def log_message(self, *args):
        pass
http.server.ThreadingHTTPServer(('127.0.0.1', 3000), Handler).serve_forever()
PY
ip netns exec "$NS" python3 -u "$TMP/upstream.py" "$TMP/upstream.jsonl" >/dev/null 2>&1 &
UPSTREAM_PID=$!
upstream_ready=0
for _ in $(seq 1 50); do
	if ip netns exec "$NS" curl -fsS --max-time 1 http://127.0.0.1:3000/ >/dev/null 2>&1; then
		upstream_ready=1
		break
	fi
	sleep 0.1
done
[ "$upstream_ready" = 1 ] || fail 'fixture upstream did not start'
: > "$TMP/upstream.jsonl"

# Start the real master before adding a site: add/delete reload an already
# running Nginx in production, and the helper now requires an observed worker
# generation. This makes the reload evidence below real, not a systemctl rc.
ip netns exec "$NS" "$NGINX_BIN" || fail 'Nginx did not start in the fixture namespace'
touch "$TMP/nginx.running"
selftest_ready=0
for _ in $(seq 1 50); do
	if ip netns exec "$NS" curl -fsS --max-time 1 \
		"http://127.0.0.1:$NGINX_SELFTEST_PORT/" >/dev/null 2>&1; then
		selftest_ready=1
		break
	fi
	sleep 0.1
done
[ "$selftest_ready" = 1 ] || fail 'Nginx loopback selftest did not start'

MASTER_PID="$(cat "$TMP/nginx.pid")"
workers_before="$(pgrep -P "$MASTER_PID" | sort -n | tr '\n' ' ')"
[ -n "$workers_before" ] || fail 'could not observe the initial Nginx workers'
nginx_add_site example.test 127.0.0.1:3000 >/dev/null \
	|| fail 'nginx_add_site failed in the fixture'
workers_after="$(pgrep -P "$MASTER_PID" | sort -n | tr '\n' ' ')"
[ -n "$workers_after" ] && [ "$workers_after" != "$workers_before" ] \
	|| fail 'nginx_add_site claimed success without a new worker generation'
SITE_LINK="$NGINX_SITES_ENABLED/abuseguard-example.test.conf"
[ -L "$SITE_LINK" ] || fail 'managed site was not enabled'
ok 'managed site generated and applied by a real worker turnover'

ready=0
for _ in $(seq 1 50); do
	code="$(ip netns exec "$NS" curl -sSk --max-time 1 --interface "$TRUSTED_SRC" \
		--resolve "example.test:443:$TRUSTED_DST" -o /dev/null -w '%{http_code}' \
		"https://example.test/" 2>/dev/null || true)"
	[ "$code" != 000 ] && { ready=1; break; }
	sleep 0.2
done
[ "$ready" = 1 ] || fail 'Nginx did not answer inside the fixture namespace'

# req SRC DST URLPATH [curl args...] -- prints "HTTP_VERSION HTTP_CODE"
req() {
	local src="$1" dst="$2" path="$3"
	shift 3
	ip netns exec "$NS" curl -sSk --max-time 5 \
		--interface "$src" --resolve "example.test:443:$dst" \
		-w '%{http_version} %{http_code}' -o /dev/null "$@" \
		"https://example.test$path"
}
req6() {
	local src="$1" dst="$2" path="$3"
	shift 3
	ip netns exec "$NS" curl -sSk --max-time 5 \
		--interface "$src" --resolve "example.test:443:[$dst]" \
		-w '%{http_version} %{http_code}' -o /dev/null "$@" \
		"https://example.test$path"
}

read -r v h1_code <<<"$(req "$TRUSTED_SRC" "$TRUSTED_DST" / \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.77')"
[ "$v" = 1.1 ] || fail "trusted h1 request used HTTP/$v"
read -r v h2_code <<<"$(req "$TRUSTED_SRC" "$TRUSTED_DST" /.env \
	--http2 -H 'CF-Connecting-IP: 203.0.113.77')"
[ "$v" = 2 ] || fail "trusted h2 request did not negotiate HTTP/2 (got $v, code $h2_code)"
read -r _ _ <<<"$(req "$TRUSTED_SRC" "$TRUSTED_DST" /.env \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.77')"
read -r _ _ <<<"$(req 198.18.0.2 198.18.0.1 / \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.66')"
read -r v _ <<<"$(req6 "$TRUSTED6_SRC" "$TRUSTED6_DST" /.env \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.88')"
[ "$v" = 1.1 ] || fail "IPv6 trusted request failed (HTTP/$v)"
read -r _ _ <<<"$(req "$TRUSTED_SRC" "$TRUSTED_DST" '/?token=QUERYSECRET' \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.79' \
	-H 'Authorization: Bearer HEADERSECRET' -H 'X-Private: PRIVATESECRET' \
	--data 'BODYSECRET=1')"

# Caddy's probe matcher is case-insensitive; the distinct client id makes the
# log assertion below specific to this single request.
read -r _ _ <<<"$(req "$TRUSTED_SRC" "$TRUSTED_DST" '/.ENV' \
	--http1.1 -H 'CF-Connecting-IP: 203.0.113.91')"

# TLS SNI is case-insensitive (RFC 6066) while $ssl_server_name keeps client
# case. Mixed case must reach the site; a wrong Host or missing SNI must still
# get the Caddy-compatible 404.
sni_status() { # $1 SNI ('' = none), $2 Host header
	local sni="$1" host="$2" out
	printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$host" \
		> "$TMP/request.txt"
	if [ -n "$sni" ]; then
		out="$(ip netns exec "$NS" sh -c \
			'openssl s_client -quiet -servername "$1" -connect "$2:443" < "$3"' \
			_ "$sni" "$TRUSTED_DST" "$TMP/request.txt" 2>/dev/null || true)"
	else
		out="$(ip netns exec "$NS" sh -c \
			'openssl s_client -quiet -connect "$1:443" < "$2"' \
			_ "$TRUSTED_DST" "$TMP/request.txt" 2>/dev/null || true)"
	fi
	printf '%s\n' "$out" | awk '$1 ~ /^HTTP\/1\.[01]$/ { print $2; exit }'
}
[ "$(sni_status Example.Test Example.Test)" = 200 ] \
	|| fail 'mixed-case SNI/Host request was not served'
[ "$(sni_status example.test other.test)" = 404 ] \
	|| fail 'wrong Host was not rejected with 404'
[ "$(sni_status '' example.test)" = 404 ] \
	|| fail 'missing SNI was not rejected with 404'

# SSE/long responses must stream the first chunk instead of waiting for the
# upstream to close (Nginx default proxy_buffering would hold it for 3s).
sse_body="$(ip netns exec "$NS" curl -sSk --max-time 2 \
	--interface "$TRUSTED_SRC" --resolve "example.test:443:$TRUSTED_DST" \
	-H 'CF-Connecting-IP: 203.0.113.77' "https://example.test/sse" 2>/dev/null || true)"
[ "$sse_body" = 'data: first' ] \
	|| fail "streamed first chunk was buffered (got '${sse_body:-<empty>}')"
ok 'mixed-case probe/SNI are accepted and SSE streams its first chunk'

# --- forwarded behaviour behind the trusted edge ---------------------------
: > "$TMP/upstream.jsonl"
req "$TRUSTED_SRC" "$TRUSTED_DST" / --http1.1 \
	-H 'CF-Connecting-IP: 203.0.113.77' -H 'Host: example.test:4443' >/dev/null
sleep 0.2
[ -s "$TMP/upstream.jsonl" ] || fail 'upstream did not receive the proxied request'
up_host="$(jq -sr '.[-1]["Host"] // empty' "$TMP/upstream.jsonl")"
[ "$up_host" = 'example.test:4443' ] \
	|| fail "upstream Host is '${up_host:-<missing>}', expected the original 'example.test:4443'"

: > "$TMP/upstream.jsonl"
req "$TRUSTED_SRC" "$TRUSTED_DST" / --http1.1 \
	-H 'CF-Connecting-IP: 203.0.113.77' \
	-H 'X-Forwarded-For: 198.51.100.9' -H 'X-Real-IP: 198.51.100.8' >/dev/null
sleep 0.2
up_xff="$(jq -sr '.[-1]["X-Forwarded-For"] // empty' "$TMP/upstream.jsonl")"
up_real="$(jq -sr '.[-1]["X-Real-IP"] // empty' "$TMP/upstream.jsonl")"
[ "$up_xff" = '203.0.113.77' ] \
	|| fail "upstream X-Forwarded-For is '${up_xff:-<missing>}', expected the trusted client only"
[ "$up_real" = '203.0.113.77' ] \
	|| fail "upstream X-Real-IP is '${up_real:-<missing>}', expected the trusted client only"

: > "$TMP/upstream.jsonl"
req "$TRUSTED_SRC" "$TRUSTED_DST" / --http1.1 \
	-H 'CF-Connecting-IP: 203.0.113.77' \
	-H 'Upgrade: websocket' -H 'Connection: Upgrade' >/dev/null
sleep 0.2
up_upgrade="$(jq -sr '.[-1]["Upgrade"] // empty' "$TMP/upstream.jsonl")"
up_conn="$(jq -sr '.[-1]["Connection"] // empty' "$TMP/upstream.jsonl")"
[ "$up_upgrade" = 'websocket' ] || fail "upstream lost the WebSocket Upgrade header (got '${up_upgrade:-<missing>}')"
case "$up_conn" in *[Uu]pgrade*) ;; *) fail "upstream lost the WebSocket Connection header (got '${up_conn:-<missing>}')" ;; esac

# An unknown SNI/Host must not fall through to the managed upstream. Caddy
# answers unmatched hosts itself; the Nginx default vhost must not proxy them.
: > "$TMP/upstream.jsonl"
unknown_code="$(ip netns exec "$NS" curl -sSk --max-time 5 \
	--interface "$TRUSTED_SRC" --resolve "unknown.test:443:$TRUSTED_DST" \
	-o /dev/null -w '%{http_code}' -H 'CF-Connecting-IP: 203.0.113.77' \
	"https://unknown.test/" 2>/dev/null || true)"
sleep 0.2
if [ -s "$TMP/upstream.jsonl" ]; then
	fail 'unknown Host/SNI reached the managed upstream instead of a safe rejection'
fi
case "$unknown_code" in
	2*) fail "unknown Host/SNI returned upstream success HTTP $unknown_code" ;;
esac

sleep 0.5

LOG="$NGINX_ACCESS_LOG"
[ -s "$LOG" ] || fail 'no access log was written'
ok 'real Nginx wrote the privacy-trimmed JSON log'

# --- privacy / field contract ----------------------------------------------
jq -s -e '
	length >= 6 and
	all(.[];
		(keys == ["caddy_abuseguard_probe","caddy_abuseguard_site","client_ip","proto","ts"])
		and (.ts | type == "number" and . > 1000000000)
		and (.caddy_abuseguard_site == "protected")
		and (.caddy_abuseguard_probe == "" or .caddy_abuseguard_probe == "web-probe"))
' "$LOG" >/dev/null || fail 'log schema is not the exact privacy-trimmed field set'
grep -q '"client_ip":"203.0.113.77"' "$LOG" \
	|| fail 'trusted CF-Connecting-IP was not used as client_ip'
grep -q '"client_ip":"203.0.113.88"' "$LOG" \
	|| fail 'trusted IPv6 CF-Connecting-IP was not used as client_ip'
grep -q '"client_ip":"198.18.0.2"' "$LOG" \
	|| fail 'untrusted source did not keep its real peer address'
if grep -q '203.0.113.66' "$LOG"; then
	fail 'untrusted CF-Connecting-IP spoof reached the log'
fi
for secret in QUERYSECRET HEADERSECRET PRIVATESECRET BODYSECRET '/.env'; do
	if grep -q -- "$secret" "$LOG"; then fail "privacy leak in access log: $secret"; fi
done
probes="$(jq -s '[.[] | select(.caddy_abuseguard_probe == "web-probe")] | length' "$LOG")"
[ "$probes" -ge 3 ] || fail "expected at least 3 tagged probes, got $probes"
jq -s -e 'any(.[]; .client_ip == "203.0.113.91" and .caddy_abuseguard_probe == "web-probe")' \
	"$LOG" >/dev/null || fail 'mixed-case probe path was not tagged web-probe'
ok 'trusted/untrusted header behaviour, IPv6 trust, and privacy fields hold'

# --- real fail2ban filters against the real log ----------------------------
check_filter() {
	local name="$1" min="$2" out n
	out="$(fail2ban-regex --datepattern '"ts":{EPOCH}' "$LOG" "$FILTER_DIR/$name" 2>&1)" \
		|| fail "fail2ban-regex failed for $name"
	n="$(printf '%s' "$out" | sed -n 's/^Success, the total number of match is \([0-9]*\).*/\1/p' | head -1)"
	[ -n "$n" ] || n="$(printf '%s\n' "$out" | awk '$1=="Lines:" {for (i=2;i<NF;i++) if ($i=="matched,") {print $(i-1); exit}}')"
	if [ -z "$n" ] || [ "$n" -lt "$min" ]; then
		printf '%s\n' "$out" | tail -25 >&2
		fail "$name matched ${n:-0} line(s), expected >= $min"
	fi
	ok "$name matched $n line(s)"
}
check_filter caddy-abuseguard-any.conf 3
check_filter caddy-abuseguard-probe-h1.conf 3
check_filter caddy-abuseguard-probe-h2.conf 1

# --- real logrotate entry + reopen -----------------------------------------
before_lines="$(wc -l < "$LOG")"
logrotate -f -s "$TMP/logrotate.state" "$NGINX_LOGROTATE" || fail 'logrotate entry failed'
[ -f "$LOG.1" ] || fail 'logrotate did not rotate the access log'
[ "$(wc -l < "$LOG.1")" -eq "$before_lines" ] || fail 'rotated log lost lines'
req "$TRUSTED_SRC" "$TRUSTED_DST" / --http1.1 -H 'CF-Connecting-IP: 203.0.113.77' >/dev/null
[ -s "$LOG" ] || fail 'Nginx did not reopen the access log after rotation'
grep -q '"client_ip":"203.0.113.77"' "$LOG" || fail 'post-rotation request was not logged'
ok 'logrotate entry rotated the real log and Nginx reopened it'

ok "Nginx -> JSON -> fail2ban contract holds"
printf '\033[1;33m[nginx-contract]\033[0m note: certificate issuance/renewal is fixture-based here; live Cloudflare DNS-01 is not exercised.\n'
