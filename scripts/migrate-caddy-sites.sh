#!/usr/bin/env bash
# Normalize protected top-level Caddy site blocks into one file per domain.
#
# Usage:
#   migrate-caddy-sites.sh INPUT OUTPUT_MAIN OUTPUT_SITES EXISTING_SITES
#
# The script writes only to OUTPUT_MAIN / OUTPUT_SITES. The caller validates
# the combined Caddy configuration before installing the generated files.
set -euo pipefail

[ "$#" = 4 ] || {
	echo "usage: $0 INPUT OUTPUT_MAIN OUTPUT_SITES EXISTING_SITES" >&2
	exit 2
}

INPUT="$1"
OUTPUT_MAIN="$2"
OUTPUT_SITES="$3"
EXISTING_SITES="$4"

[ -f "$INPUT" ] || { echo "missing Caddyfile: $INPUT" >&2; exit 2; }
mkdir -p "$OUTPUT_SITES"

existing_names=""
if [ -d "$EXISTING_SITES" ]; then
	for f in "$EXISTING_SITES"/*.caddy; do
		[ -e "$f" ] || continue
		existing_names="${existing_names}$(basename "$f")
"
	done
fi

awk -v out_main="$OUTPUT_MAIN" -v out_sites="$OUTPUT_SITES" -v existing_names="$existing_names" '
function brace_delta(line, text, opens, closes) {
	text = line
	sub(/[[:space:]]*#.*/, "", text)
	opens = gsub(/\{/, "{", text)
	closes = gsub(/\}/, "}", text)
	return opens - closes
}

function header_name(line, value) {
	value = line
	sub(/[[:space:]]*#.*/, "", value)
	sub(/^[[:space:]]*/, "", value)
	sub(/[[:space:]]*\{[[:space:]]*$/, "", value)
	sub(/[[:space:]]*$/, "", value)
	return value
}

function is_domain(value) {
	return value ~ /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/
}

function is_protection_line(line) {
	return line ~ /^[[:space:]]*import[[:space:]]+(abuseguard|caddy_abuseguard_log)[[:space:]]*(#.*)?$/ ||
		line ~ /^[[:space:]]*log_append[[:space:]]+caddy_abuseguard_site[[:space:]]+protected[[:space:]]*(#.*)?$/ ||
		line ~ /^[[:space:]]*log[[:space:]]+caddy_abuseguard[[:space:]]*\{/
}

function keep_protected_block(header) {
	return header ~ /^http:\/\/127\.0\.0\.1(:[0-9]+)?$/ || header ~ /^\([^()]+\)$/
}

function write_original(    i) {
	for (i = 1; i <= block_count; i++) print block[i] >> out_main
}

function write_site(domain, path, i, line, skip_log, skip_depth) {
	path = out_sites "/" tolower(domain) ".caddy"
	print block[1] > path
	print "\timport abuseguard" >> path

	skip_log = 0
	skip_depth = 0
	for (i = 2; i <= block_count; i++) {
		line = block[i]
		if (skip_log) {
			skip_depth += brace_delta(line)
			if (skip_depth <= 0) skip_log = 0
			continue
		}
		if (line ~ /^[[:space:]]*#[[:space:]]*These fixed markers let Fail2Ban classify protected traffic without[[:space:]]*$/ ||
			line ~ /^[[:space:]]*#[[:space:]]*retaining the site.s host name or the requested path in the access log\.[[:space:]]*$/) continue
		if (line ~ /^[[:space:]]*import[[:space:]]+(abuseguard|caddy_abuseguard_log)[[:space:]]*(#.*)?$/) continue
		if (line ~ /^[[:space:]]*log_append[[:space:]]+caddy_abuseguard_site[[:space:]]+protected[[:space:]]*(#.*)?$/) continue
		if (line ~ /^[[:space:]]*@caddy_abuseguard_probe[[:space:]]+path([[:space:]]|$)/) continue
		if (line ~ /^[[:space:]]*log_append[[:space:]]+@caddy_abuseguard_probe[[:space:]]+caddy_abuseguard_probe[[:space:]]+web-probe[[:space:]]*(#.*)?$/) continue
		if (line ~ /^[[:space:]]*log[[:space:]]+caddy_abuseguard[[:space:]]*\{/) {
			skip_log = 1
			skip_depth = brace_delta(line)
			if (skip_depth <= 0) skip_log = 0
			continue
		}
		print line >> path
	}
	close(path)
	print tolower(domain)
}

function process_block(    i, protected, header, domain, filename) {
	protected = 0
	for (i = 1; i <= block_count; i++) {
		if (is_protection_line(block[i])) protected = 1
	}
	if (!protected) {
		write_original()
		return
	}

	header = header_name(block[1])
	if (keep_protected_block(header)) {
		write_original()
		return
	}
	if (!is_domain(header)) {
		print "cannot migrate protected non-single-domain block: " header > "/dev/stderr"
		had_error = 1
		return
	}

	domain = tolower(header)
	filename = domain ".caddy"
	if (existing[filename]) {
		print "cannot migrate protected site; target already exists: " filename > "/dev/stderr"
		had_error = 1
		return
	}
	write_site(domain)
}

BEGIN {
	count = split(existing_names, names, "\n")
	for (i = 1; i <= count; i++) if (names[i] != "") existing[names[i]] = 1
	printf "%s", "" > out_main
	close(out_main)
}

{
	line = $0
	if (!capturing) {
		delta = brace_delta(line)
		if (delta > 0) {
			capturing = 1
			block_count = 1
			block[block_count] = line
			block_depth = delta
		} else {
			print line >> out_main
		}
		next
	}

	block[++block_count] = line
	block_depth += brace_delta(line)
	if (block_depth <= 0) {
		process_block()
		delete block
		block_count = 0
		block_depth = 0
		capturing = 0
	}
}

END {
	if (capturing) {
		print "cannot migrate malformed Caddyfile: unclosed top-level block" > "/dev/stderr"
		had_error = 1
	}
	close(out_main)
	if (had_error) exit 3
}
' "$INPUT"
