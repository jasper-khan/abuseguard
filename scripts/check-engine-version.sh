#!/usr/bin/env bash
# Verify that a built artifact boots and reports the version being packaged.
# Optional RUNNER and arguments go before BINARY (e.g. qemu-aarch64-static).
set -eu

if [ "$#" -lt 2 ]; then
	echo "usage: $0 VERSION_FILE BINARY [RUNNER [ARG ...]]" >&2
	exit 2
fi
version_file="$1" binary="$2"
shift 2
version="$(tr -d '[:space:]' < "$version_file")"
if [ -z "$version" ]; then
	echo "$version_file is empty" >&2
	exit 1
fi
if ! got="$("$@" "$binary" version)"; then
	echo "$binary failed its version command" >&2
	exit 1
fi
expected="abuseguard-engine $version"
if [ "$got" != "$expected" ]; then
	printf '%s reported %s; expected %s\n' "$binary" "${got:-<no output>}" "$expected" >&2
	exit 1
fi
printf '%s: %s\n' "$binary" "$got"
