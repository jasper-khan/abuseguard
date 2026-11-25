#!/usr/bin/env bash
# Fetch, verify (SHA-256), and install fail2ban-rs from GitHub Releases.
# Used by CI and release gates so every contract/policy test runs against the
# same Rust drop-in that install.sh deploys.
set -euo pipefail

die() { printf '%s\n' "$*" >&2; exit 1; }

REPO="${ABUSEGUARD_FAIL2BAN_REPO:-jasper-khan/fail2ban-rs}"
VERSION="${ABUSEGUARD_FAIL2BAN_VERSION:-}"

case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) die "unsupported architecture: $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
	url="$(curl -fsSL --connect-timeout 10 --max-time 30 --retry 3 --retry-delay 2 \
		-o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")" \
		|| die "failed to resolve latest fail2ban-rs release"
	case "$url" in
		*"https://github.com/$REPO/releases/tag/"*) ;;
		*) die "unexpected release redirect URL: $url" ;;
	esac
	tag="${url##*/}"
	[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "unexpected fail2ban-rs tag: $tag"
	VERSION="${tag#v}"
else
	[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid ABUSEGUARD_FAIL2BAN_VERSION: $VERSION"
fi

NAME="fail2ban-rs-$VERSION-linux-$ARCH"
BASE_URL="https://github.com/$REPO/releases/download/v$VERSION/$NAME.tar.gz"
WORK="$(mktemp -d)"
cleanup() {
	rm -f -- \
		"$WORK/$NAME.tar.gz" \
		"$WORK/$NAME.tar.gz.sha256" \
		"$WORK/$NAME/install.sh"
	rmdir -- "$WORK/$NAME" "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

curl -fsSL --connect-timeout 10 --retry 3 --retry-delay 2 -o "$WORK/$NAME.tar.gz" "$BASE_URL" \
	|| die "failed to download $BASE_URL"
curl -fsSL --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 2 -o "$WORK/$NAME.tar.gz.sha256" "$BASE_URL.sha256" \
	|| die "failed to download $BASE_URL.sha256"

read -r digest _ < "$WORK/$NAME.tar.gz.sha256" || true
[[ "$digest" =~ ^[[:xdigit:]]{64}$ ]] || die "invalid fail2ban-rs sha256 digest"
printf '%s  %s\n' "$digest" "$WORK/$NAME.tar.gz" | sha256sum -c - >/dev/null \
	|| die "fail2ban-rs sha256 verification failed"

tar -xzf "$WORK/$NAME.tar.gz" -C "$WORK" "$NAME/install.sh" \
	|| die "fail2ban-rs archive missing $NAME/install.sh"
bash "$WORK/$NAME/install.sh" "$WORK/$NAME.tar.gz"

root="${DESTDIR:-}"
"$root/usr/local/bin/fail2ban-client" --version
"$root/usr/local/bin/fail2ban-regex" --version
