#!/usr/bin/env bash
# Candidate-only Caddy site migration. The installer validates the complete
# candidate with Caddy before it changes the live configuration.
set -euo pipefail

case "$#:${1:-}" in
	3:--plan|4:*) ;;
	*)
		echo "usage: $0 INPUT OUTPUT_MAIN OUTPUT_SITES EXISTING_SITES | $0 --plan INPUT EXISTING_SITES" >&2
		exit 2 ;;
esac

ENGINE="${ABUSEGUARD_MIGRATION_ENGINE:-/usr/local/libexec/caddy-abuseguard}"
[ -x "$ENGINE" ] || { echo "migration engine is missing or not executable: $ENGINE" >&2; exit 2; }
exec "$ENGINE" migrate-caddy-sites "$@"
