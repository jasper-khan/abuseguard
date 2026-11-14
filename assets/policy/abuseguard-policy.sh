#!/usr/bin/env bash
# AbuseGuard root native-policy applier.
#
# The unprivileged engine validates the whitelist and intel file and emits
# canonical text; this helper is the only component that turns that text into
# kernel policy. It builds one nftables transaction for
# `inet caddy_abuseguard_intel`, persists root-owned boot snapshots under
# /etc/caddy-abuseguard, and regenerates fail2ban `ignoreip` for the AbuseGuard
# jails so a single apply keeps the kernel and fail2ban in sync.
#
# Entry points: install/update, `sudo ag --policy-apply`, panel whitelist/ban
# changes, boot restore, and the six-hour sync service.
#
# AG_* path overrides are a root-only test hook (scripts/test-native-policy.sh);
# production callers never set them.
set -uo pipefail

CONF_DIR="${AG_CONF_DIR:-/etc/caddy-abuseguard}"
STATE_DIR="${AG_STATE_DIR:-/var/lib/caddy-abuseguard}"
ENGINE="${AG_ENGINE:-/usr/local/libexec/caddy-abuseguard}"
F2B_JAIL_DIR="${AG_F2B_JAIL_DIR:-/etc/fail2ban/jail.d}"
CONFIG="$CONF_DIR/config.json"
WHITELIST="$CONF_DIR/whitelist"
INTEL_NFT="$CONF_DIR/intel.nft"
ALLOW_NFT="$CONF_DIR/intel-allow.nft"
APPLIED_JSON="$CONF_DIR/intel-applied.json"
F2B_POLICY="$F2B_JAIL_DIR/zzz-caddy-abuseguard-policy.local"
LOCK="$CONF_DIR/policy.lock"
TABLE=caddy_abuseguard_intel
# Only these jails are driven by the generated allowlist file. Other jails
# (e.g. an operator's own) keep their own ignoreip untouched.
JAILS="caddy-rate-local caddy-probe-h1 caddy-probe-h2 sshd"
umask 077

log() { printf '[abuseguard-policy] %s\n' "$*"; }
die() { printf '[abuseguard-policy] %s\n' "$*" >&2; exit 1; }

# install to a same-directory temp file, then rename: a crash never leaves a
# truncated policy snapshot or a half-written fail2ban config in place.
write_atomic() { # SRC DEST MODE
	local src="$1" dest="$2" mode="$3" tmp
	tmp="$(mktemp "$(dirname "$dest")/.$(basename "$dest").XXXXXX")" || return 1
	if ! install -m "$mode" -o root -g root -- "$src" "$tmp"; then
		rm -f -- "$tmp"
		return 1
	fi
	mv -f -- "$tmp" "$dest" || { rm -f -- "$tmp"; return 1; }
}

# --- helpers -----------------------------------------------------------------

emit_set_elements() { # FILE — comma-separated set elements, no trailing comma
	local file="$1" e n=0
	while IFS= read -r e; do
		[ -n "$e" ] || continue
		[ "$n" -eq 0 ] || printf ',\n'
		printf '\t\t\t%s' "$e"
		n=$((n + 1))
	done < "$file"
	[ "$n" -eq 0 ] || printf '\n'
}

validate_allowlist() {
	local e
	while IFS= read -r e; do
		[ -n "$e" ] || continue
		[ "${#e}" -le 64 ] || die "白名单导出条目过长：$e"
		case "$e" in
			*[!0-9A-Fa-f:./]*) die "白名单导出包含非法字符：$e" ;;
			*/*/*) die "白名单导出包含多余的分隔符：$e" ;;
		esac
	done < "$allow_file"
}

validate_intel() {
	awk -F. '
		NF != 4 { exit 1 }
		{ for (i = 1; i <= 4; i++) if ($i !~ /^[0-9][0-9]?[0-9]?$/ || $i + 0 > 255) exit 1 }
	' "$intel_file" || die "情报导出包含非法或越界条目。"
}

# Fail2ban's native per-jail ignoreip is preserved by reading the effective
# configuration with our generated file moved aside. The generated file loads
# last and replaces each jail's ignoreip, so repeating only that jail's own
# native entries keeps an admin's SSH-only exemption out of the Web jails and
# lets later edits/removals in the native config take effect on the next apply.
# Neither the generated file nor these entries ever feed the kernel allowlist.
F2B_MOVED=""
restore_f2b_policy() {
	[ -z "$F2B_MOVED" ] || {
		mv -f -- "$F2B_MOVED" "$F2B_POLICY" || log "警告：无法恢复 $F2B_POLICY。"
		F2B_MOVED=""
	}
}

capture_native_ignoreip() { # WORKDIR ALLOW_FILE
	local work="$1" allow="$2" dump="$1/f2b.dump" jail merged
	if [ -f "$F2B_POLICY" ]; then
		F2B_MOVED="$work/f2b.moved"
		mv -f -- "$F2B_POLICY" "$F2B_MOVED" || die "无法暂存 $F2B_POLICY；未更改任何策略。"
	fi
	if ! fail2ban-client -d > "$dump" 2>/dev/null || [ ! -s "$dump" ]; then
		restore_f2b_policy
		die "无法读取 fail2ban 当前配置；未更改任何策略。"
	fi
	restore_f2b_policy
	for jail in $JAILS; do
		merged="$work/ignoreip.$jail"
		{
			awk 'NF && $0 !~ /^[[:space:]]*#/' "$allow"
			awk -v jail="$jail" '
				index($0, "addignoreip") == 0 { next }
				{
					line = $0
					sub(/^\[/, "", line)
					gsub(/[][\047]/, "", line)
					gsub(/"/, "", line)
					n = split(line, f, /,[[:space:]]*/)
					if (f[1] != "set" || f[3] != "addignoreip" || f[2] != jail) next
					for (i = 4; i <= n; i++) if (f[i] != "") print f[i]
				}' "$dump"
		} | awk '!seen[$0]++' > "$merged"
		# One token per line: reject whitespace joins and interpolation tokens
		# before they can leave a half-applied kernel/fail2ban split.
		awk 'BEGIN { bad = 0 } $0 !~ /^[A-Za-z0-9:._\/-]+$/ { bad = 1 } END { exit bad }' "$merged" \
			|| die "$jail 的原生 ignoreip 含非法条目；未更改任何策略。"
	done
}

restore_snapshot() {
	[ -s "$INTEL_NFT" ] || return 1
	nft -c -f "$INTEL_NFT" >/dev/null 2>&1 || return 1
	nft -f "$INTEL_NFT" || return 1
}

# A bootstrap install creates an empty set/snapshot before the first sync; an
# empty export over that state is still valid. Only a previously non-empty
# policy must never be wiped by an empty/missing feed.
intel_policy_nonempty() {
	if [ -f "$INTEL_NFT" ] && grep -q 'elements = {' "$INTEL_NFT"; then
		return 0
	fi
	nft -n list set inet "$TABLE" block4 2>/dev/null \
		| grep -Eq '([0-9]{1,3}\.){3}[0-9]{1,3}' && return 0
	return 1
}

rollback_nft() {
	if [ "$had_intel" = 1 ]; then
		nft -f "$work/intel.prev" >/dev/null 2>&1 \
			|| log "警告：无法恢复上一次内核情报策略，请检查 nft list table inet $TABLE。"
	else
		nft delete table inet "$TABLE" >/dev/null 2>&1 \
			|| log "警告：无法删除新建的情报表 inet $TABLE。"
	fi
	if [ "$had_intel" = 1 ]; then
		write_atomic "$work/intel.prev" "$INTEL_NFT" 0640 || log "警告：无法恢复 $INTEL_NFT。"
	else
		rm -f -- "$INTEL_NFT"
	fi
	if [ "$had_allow" = 1 ]; then
		write_atomic "$work/allow.prev" "$ALLOW_NFT" 0640 || log "警告：无法恢复 $ALLOW_NFT。"
	else
		rm -f -- "$ALLOW_NFT"
	fi
	if [ "$had_applied" = 1 ]; then
		write_atomic "$work/applied.prev" "$APPLIED_JSON" 0640 || log "警告：无法恢复 $APPLIED_JSON。"
	else
		rm -f -- "$APPLIED_JSON"
	fi
}

# Remove behavioural bans that already cover a now-whitelisted address. The
# kernel allow set only affects the intel chain; fail2ban needs an explicit
# unban because existing bans live in its database independent of ignoreip.
clear_whitelisted_bans() {
	local jail ips ip rc
	for jail in $JAILS; do
		ips="$(fail2ban-client status "$jail" 2>/dev/null \
			| sed -n 's/.*Banned IP list:[[:space:]]*//p' | tr ' ' '\n' | sed '/^$/d')" || continue
		for ip in $ips; do
			rc=0
			"$ENGINE" allowlist-check --ip "$ip" >/dev/null 2>&1 || rc=$?
			[ "$rc" = 0 ] || continue
			fail2ban-client set "$jail" unbanip "$ip" >/dev/null 2>&1 \
				|| log "警告：无法解除 $jail 中已加白 IP $ip 的封禁。"
		done
	done
}

# --- guards and serialization ------------------------------------------------

[ "$(id -u)" = 0 ] || die "需要 root 权限"
command -v nft >/dev/null 2>&1 || die "未找到 nft"
[ -x "$ENGINE" ] || die "找不到引擎：$ENGINE"
[ -d "$CONF_DIR" ] || die "配置目录不存在：$CONF_DIR"

exec 9>>"$LOCK" || die "无法创建策略锁：$LOCK"
flock -w 60 9 || die "另一个策略操作仍在运行（等待锁超时）。"

case "${1:-apply}" in
	apply) ;;
	*) echo "用法：caddy-abuseguard-policy apply" >&2; exit 2 ;;
esac

work="$(mktemp -d "$CONF_DIR/.policy.XXXXXX")" || die "无法创建策略临时目录。"
trap 'restore_f2b_policy; rm -rf -- "$work"' EXIT
export ABUSEGUARD_CONFIG="$CONFIG"

# Boot starts with no kernel table: restore the root-owned last-good snapshot
# before any fail2ban read or fresh export, so a broken fail2ban config or feed
# cannot leave the feed policy missing.
if ! nft list table inet "$TABLE" >/dev/null 2>&1; then
	restore_snapshot || true
fi

# --- export + validate (never trust raw feed text as nft input) ---------------

allow_file="$work/allow.list"
intel_file="$work/intel.list"
"$ENGINE" allowlist-export --file "$WHITELIST" > "$allow_file" \
	|| die "白名单校验/导出失败；未更改任何策略。"
validate_allowlist

# Preserve admin-managed native ignoreip per jail before any kernel change.
# Reading the effective config here means later edits/removals propagate on the
# next apply instead of being frozen into a copied flat list.
capture_native_ignoreip "$work" "$allow_file"

"$ENGINE" intel-export > "$intel_file" \
	|| die "情报导出失败；保留上一次生效的策略（检查 $STATE_DIR/intel.txt）。"
validate_intel
intel_count="$(awk 'NF { n++ } END { print n+0 }' "$intel_file")"
allow_count="$(awk 'NF { n++ } END { print n+0 }' "$allow_file")"
if [ "$intel_count" -eq 0 ] && intel_policy_nonempty; then
	# Missing intel.txt after a non-empty policy existed is a failure, not a
	# request to wipe enforcement.
	die "情报导出为空；已有策略不会被空列表覆盖（首次安装允许空列表）。"
fi

# --- build one nft transaction ------------------------------------------------

intel_nft="$work/intel.nft"
allow_nft="$work/intel-allow.nft"
allow_rules="$work/allow.rules"
# One rule per entry keeps overlapping IPs/CIDRs valid on every supported nft
# version; each rule returns only from this dedicated chain, so the normal port
# firewall is still evaluated afterwards.
{
	while IFS= read -r e; do
		[ -n "$e" ] || continue
		case "$e" in
			*:*) printf '\t\tip6 saddr %s return\n' "$e" ;;
			*) printf '\t\tip saddr %s return\n' "$e" ;;
		esac
	done < "$allow_file"
} > "$allow_rules"

# intel.nft is the complete, self-contained transaction (table + allow rules +
# block set), so boot restore and rollback are a single atomic file load.
{
	printf '# Generated by caddy-abuseguard-policy at %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	printf 'add table inet %s\n' "$TABLE"
	printf 'delete table inet %s\n' "$TABLE"
	printf 'table inet %s {\n' "$TABLE"
	printf '\tset block4 {\n\t\ttype ipv4_addr\n'
	if [ -s "$intel_file" ]; then
		printf '\t\telements = {\n'
		emit_set_elements "$intel_file"
		printf '\t\t}\n'
	fi
	printf '\t}\n'
	printf '\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n'
	cat -- "$allow_rules"
	printf '\t\tip saddr @block4 drop\n\t}\n}\n'
} > "$intel_nft"

{
	printf '# Allowlist exceptions (one per line) at last apply; intel.nft is the applied snapshot.\n'
	cat -- "$allow_file"
} > "$allow_nft"

nft -c -f "$intel_nft" >/dev/null \
	|| die "内核策略校验失败；未更改任何策略。"

# Snapshot backups must exist before the kernel changes, so a failed persist
# can restore both the live table and the disk files.
had_intel=0; had_allow=0; had_applied=0
[ ! -f "$INTEL_NFT" ] || { cp -p -- "$INTEL_NFT" "$work/intel.prev" || die "无法备份 $INTEL_NFT。"; had_intel=1; }
[ ! -f "$ALLOW_NFT" ] || { cp -p -- "$ALLOW_NFT" "$work/allow.prev" || die "无法备份 $ALLOW_NFT。"; had_allow=1; }
[ ! -f "$APPLIED_JSON" ] || { cp -p -- "$APPLIED_JSON" "$work/applied.prev" || die "无法备份 $APPLIED_JSON。"; had_applied=1; }

nft -f "$intel_nft" \
	|| die "内核策略应用失败；旧策略保持不变。"

# --- persist root-owned snapshots (roll back the kernel on write failure) -----

printf '{"applied_at":"%s","intel_entries":%d,"whitelist_entries":%d,"source":"policy-apply"}\n' \
	"$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$intel_count" "$allow_count" > "$work/applied.json"
if ! write_atomic "$intel_nft" "$INTEL_NFT" 0640 \
	|| ! write_atomic "$allow_nft" "$ALLOW_NFT" 0640 \
	|| ! write_atomic "$work/applied.json" "$APPLIED_JSON" 0640; then
	rollback_nft
	die "无法保存情报策略快照；已恢复上一次内核策略。"
fi

# --- regenerate fail2ban ignoreip per jail ----------------------------------

f2b_file="$work/policy.local"
{
	printf '# Generated by caddy-abuseguard-policy. Do not edit.\n'
	printf '# Source: %s + each jail'"'"'s own native ignoreip. Apply: sudo ag --policy-apply\n' "$WHITELIST"
	for jail in $JAILS; do
		[ -s "$work/ignoreip.$jail" ] || continue
		printf '\n[%s]\n' "$jail"
		first=1
		while IFS= read -r e; do
			if [ "$first" = 1 ]; then
				printf 'ignoreip = %s\n' "$e"
				first=0
			else
				printf '           %s\n' "$e"
			fi
		done < "$work/ignoreip.$jail"
	done
	# Retired intel jails must not survive as live aliases, even if a copy of
	# the old definitions was left in jail.local by the operator.
	printf '\n[caddy-intel]\nenabled = false\n\n[sshd-intel]\nenabled = false\n'
} > "$f2b_file"

had_f2b=0
f2b_changed=1
if [ ! -d "$F2B_JAIL_DIR" ]; then
	f2b_changed=0
	log "警告：未找到 $F2B_JAIL_DIR；本次只应用内核策略，跳过 fail2ban ignoreip。"
elif [ -f "$F2B_POLICY" ]; then
	cp -p -- "$F2B_POLICY" "$work/f2b.prev" || die "无法备份 $F2B_POLICY。"
	had_f2b=1
	cmp -s "$f2b_file" "$F2B_POLICY" && f2b_changed=0
fi
if [ "$f2b_changed" = 1 ]; then
	if ! write_atomic "$f2b_file" "$F2B_POLICY" 0644; then
		rollback_nft
		die "无法写入 fail2ban ignoreip；已恢复上一次内核策略。"
	fi
fi

# --- reload fail2ban or roll back both sides ---------------------------------

f2b_active=0
fail2ban-client ping >/dev/null 2>&1 && f2b_active=1
if [ "$f2b_active" = 1 ]; then
	if [ "$f2b_changed" = 1 ] && ! fail2ban-client reload >/dev/null 2>&1; then
		if [ "$had_f2b" = 1 ]; then
			write_atomic "$work/f2b.prev" "$F2B_POLICY" 0644 || log "警告：无法恢复旧 ignoreip 文件。"
		else
			rm -f -- "$F2B_POLICY"
		fi
		fail2ban-client reload >/dev/null 2>&1 || log "警告：fail2ban 回滚重载失败，请手动检查。"
		rollback_nft
		die "fail2ban 重载失败；已回滚内核策略和 ignoreip。"
	fi
	clear_whitelisted_bans
else
	log "fail2ban 未运行；ignoreip 已更新，将在下次启动时生效。"
fi

log "策略已应用：$intel_count 条情报，$allow_count 条白名单。"
