#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PANEL="$ROOT/abuseguard.sh"
TMP="$(mktemp -d)"
PANEL_SOURCE="$TMP/panel-source.sh"
FIFO="$TMP/input"

cleanup() {
	rm -f -- "$FIFO"
	rm -f -- "$PANEL_SOURCE"
	rmdir -- "$TMP"
}
trap cleanup EXIT

grep -qx 'PANEL_REFRESH_SECONDS=10' "$PANEL"

# Source only the function definitions, shorten the production timeout, and
# keep stdin open without sending a choice. The menu must return for a redraw
# before the holder closes the pipe two seconds later.
awk '/^# The panel needs root/{exit} {print}' "$PANEL" |
	sed 's/^PANEL_REFRESH_SECONDS=10$/PANEL_REFRESH_SECONDS=0.1/' > "$PANEL_SOURCE"

result="$(
	timeout 1 bash --noprofile --norc -c '
		set -uo pipefail
		source "$1"
		header() { :; }
		cat() { command cat >/dev/null; }
		mkfifo "$2"
		( exec 3>"$2"; sleep 2 ) &
		holder=$!
		menu < "$2" >/dev/null 2>&1
		kill "$holder" 2>/dev/null || true
		wait "$holder" 2>/dev/null || true
		printf "refreshed\n"
	' _ "$PANEL_SOURCE" "$FIFO"
)"

[ "$result" = refreshed ]

selected="$(
	bash --noprofile --norc -c '
		set -uo pipefail
		source "$1"
		header() { :; }
		cat() { command cat >/dev/null; }
		act_status() { printf "selected\n"; }
		printf "1\n" | menu
	' _ "$PANEL_SOURCE"
)"
[ "${selected##*$'\n'}" = selected ]

echo "panel refresh test passed"
