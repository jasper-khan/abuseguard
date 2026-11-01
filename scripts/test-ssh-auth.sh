#!/usr/bin/env bash
# SSH 认证开关、root 公钥管理与 root 密码修改（防锁死行为为主）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() {
	rm -f -- "$TMP/panel.sh" "$TMP/sshd_config" "$TMP/calls"
	rm -f -- "$TMP/test-key" "$TMP/test-key.pub" "$TMP/second-key" "$TMP/second-key.pub"
	rm -f -- "$TMP/auth/00-abuseguard-auth.conf" "$TMP/auth/00-abuseguard-auth.conf.tmp"
	rm -f -- "$TMP/auth/99-abuseguard-auth.conf" "$TMP/auth/00-aaa-hardening.conf" "$TMP/auth/50-cloud-init.conf"
	rm -f -- "$TMP/root/.ssh/authorized_keys" "$TMP/root/.ssh/authorized_keys.tmp"
	rmdir -- "$TMP/auth" "$TMP/root/.ssh" "$TMP/root" 2>/dev/null || true
	rmdir -- "$TMP" 2>/dev/null || true
}
trap cleanup EXIT

awk '/^# The panel needs root/{exit} {print}' "$ROOT/abuseguard.sh" > "$TMP/panel.sh"
source "$TMP/panel.sh"

SSHD_MAIN="$TMP/sshd_config"
SSHD_DROPIN_DIR="$TMP/auth"
SSHD_AUTH_DROPIN="$SSHD_DROPIN_DIR/00-abuseguard-auth.conf"
SSHD_AUTH_DROPIN_OLD="$SSHD_DROPIN_DIR/99-abuseguard-auth.conf"
SSHD_DROPIN="$SSHD_DROPIN_DIR/99-abuseguard-port.conf"
SSH_ROOT_HOME="$TMP/root/.ssh"
SSH_AUTH_KEYS="$SSH_ROOT_HOME/authorized_keys"
mkdir -p "$SSHD_DROPIN_DIR" "$SSH_ROOT_HOME"
printf 'Include %s/*.conf\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/test-key" -C test >/dev/null
ssh-keygen -q -t ecdsa -b 256 -N '' -f "$TMP/second-key" -C test >/dev/null
valid_key="$(awk '{print $1, $2}' "$TMP/test-key.pub")"
second_key="$(awk '{print $1, $2}' "$TMP/second-key.pub")"

fail() { echo "ssh auth test failed: $*" >&2; exit 1; }

SOCKET_ACTIVE=0
RELOAD_FAIL=0
SSHD_T_FAIL=0
CHPASSWD_FAIL=0
ROOT_PERMIT_ROOT_LOGIN=yes
ROOT_AUTH_METHODS=any
ROOT_USE_DNS=no
ROOT_DENY_SOURCE=""
ROOT_PASSWORD_STATUS=P
SSHD_QUERY_FAIL=0
SSHD_EXTRA_OUTPUT=0
ROOT_KBD_AUTH=no
ROOT_AUTH_KEYS_FILE='.ssh/authorized_keys .ssh/authorized_keys2'
ROOT_REMOTE_PASSWORD=""
ROOT_REMOTE_PUBKEY=""
SSH_CONNECTION='203.0.113.23 45000 192.0.2.20 22'
perm_home=700
perm_keys=600
: > "$TMP/calls"

sshd_T() {
	# 模拟 sshd 首值生效：主配置有 Include 时，drop-in 按字典序先读，主配置在后；
	# 没有 Include 则 drop-in 不生效。每个关键字取第一条。
	local pw pk
	if grep -qE '^[[:space:]]*Include[[:space:]]' "$SSHD_MAIN" 2>/dev/null; then
		pw="$(grep -hsE '^[[:space:]]*PasswordAuthentication[[:space:]]+(yes|no)' "$SSHD_DROPIN_DIR"/*.conf 2>/dev/null | head -n 1 || true)"
		pk="$(grep -hsE '^[[:space:]]*PubkeyAuthentication[[:space:]]+(yes|no)' "$SSHD_DROPIN_DIR"/*.conf 2>/dev/null | head -n 1 || true)"
	else
		pw=""; pk=""
	fi
	pw="$({ [ -n "$pw" ] && printf '%s\n' "$pw" || true
		grep -hsE '^[[:space:]]*PasswordAuthentication[[:space:]]+(yes|no)' "$SSHD_MAIN" 2>/dev/null || true; } | awk 'NF{print $2; exit}')"
	pk="$({ [ -n "$pk" ] && printf '%s\n' "$pk" || true
		grep -hsE '^[[:space:]]*PubkeyAuthentication[[:space:]]+(yes|no)' "$SSHD_MAIN" 2>/dev/null || true; } | awk 'NF{print $2; exit}')"
	if [ "$MATCH_ROOT" = 1 ]; then
		pw="${ROOT_REMOTE_PASSWORD:-$pw}"
		pk="${ROOT_REMOTE_PUBKEY:-$pk}"
	fi
	printf 'passwordauthentication %s\n' "${pw:-yes}"
	printf 'pubkeyauthentication %s\n' "${pk:-yes}"
	printf 'permitrootlogin %s\n' "$ROOT_PERMIT_ROOT_LOGIN"
	printf 'authenticationmethods %s\n' "$ROOT_AUTH_METHODS"
	printf 'authorizedkeysfile %s\n' "$ROOT_AUTH_KEYS_FILE"
	printf 'kbdinteractiveauthentication %s\n' "$ROOT_KBD_AUTH"
	printf 'usedns %s\n' "$ROOT_USE_DNS"
	printf 'port 22\n'
	if [ "$SSHD_EXTRA_OUTPUT" = 1 ]; then
		awk 'BEGIN { for (i=0; i<10000; i++) print "unrelated setting" }'
	fi
	return 0
}
sshd() {
	local ROOT_PERMIT_ROOT_LOGIN="$ROOT_PERMIT_ROOT_LOGIN" MATCH_ROOT=0
	case "$1" in
		-T)
			[ "$SSHD_QUERY_FAIL" = 0 ] || return 1
			[ "${2:-}" != -C ] || MATCH_ROOT=1
			if [ -n "$ROOT_DENY_SOURCE" ] && [[ "${3:-}" == *",addr=$ROOT_DENY_SOURCE,"* ]]; then
				ROOT_PERMIT_ROOT_LOGIN=prohibit-password
			fi
			sshd_T ;;
		-t) [ "$SSHD_T_FAIL" = 0 ] ;;
		*) return 1 ;;
	esac
}
systemctl() {
	case "$1" in
		is-active) [ "$SOCKET_ACTIVE" = 1 ] ;;
		# 管道里的函数跑在子 shell，计数落盘而不是内存变量。
		reload) echo reload >> "$TMP/calls"; [ "$RELOAD_FAIL" = 0 ] ;;
		*) return 0 ;;
	esac
}
stat() {
	[ "${1:-}" = -c ] && [ "${2:-}" = %a ] || return 1
	case "$3" in
		"$SSH_ROOT_HOME") echo "$perm_home" ;;
		"$SSH_AUTH_KEYS"|"$SSH_AUTH_KEYS.tmp") echo "$perm_keys" ;;
		*) return 1 ;;
	esac
}
chpasswd() { printf 'chpasswd\n' >> "$TMP/calls"; [ "$CHPASSWD_FAIL" = 0 ]; }
passwd() { [ "$1" = -S ] && [ "$2" = root ] || return 1; printf 'root %s 01/01/2026 0 99999 7 -1\n' "$ROOT_PASSWORD_STATUS"; }
pause() { :; }

reset_all() {
	printf 'Include %s/*.conf\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"
	rm -f -- "$SSHD_AUTH_DROPIN" "$SSHD_AUTH_DROPIN.tmp" "$SSHD_AUTH_DROPIN_OLD"
	rm -f -- "$SSHD_DROPIN_DIR/00-aaa-hardening.conf" "$SSHD_DROPIN_DIR/50-cloud-init.conf"
	rm -f -- "$SSH_AUTH_KEYS" "$SSH_AUTH_KEYS.tmp"
	SOCKET_ACTIVE=0; RELOAD_FAIL=0; SSHD_T_FAIL=0; CHPASSWD_FAIL=0
	ROOT_PERMIT_ROOT_LOGIN=yes
	ROOT_AUTH_METHODS=any; ROOT_USE_DNS=no; ROOT_DENY_SOURCE=""
	ROOT_PASSWORD_STATUS=P; SSHD_QUERY_FAIL=0; SSHD_EXTRA_OUTPUT=0
	ROOT_KBD_AUTH=no; ROOT_AUTH_KEYS_FILE='.ssh/authorized_keys .ssh/authorized_keys2'
	ROOT_REMOTE_PASSWORD=""; ROOT_REMOTE_PUBKEY=""
	SSH_CONNECTION='203.0.113.23 45000 192.0.2.20 22'
	: > "$TMP/calls"
	perm_home=700; perm_keys=600
}

# 末尾缺少换行时，追加公钥必须另起一行。
reset_all
printf '# provisioned without newline' > "$SSH_AUTH_KEYS"
if printf '%s user@host\n' "$valid_key" | act_ssh_key_add; then
	:
else
	fail 'key add without trailing newline failed'
fi
grep -qxF '# provisioned without newline' "$SSH_AUTH_KEYS" || fail 'existing line was changed'
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" \
	|| fail 'key was merged with existing line'
[ "$(awk 'NF{n++} END{print n+0}' "$SSH_AUTH_KEYS")" -eq 2 ] \
	|| fail 'newline fix did not keep lines separate'
rm -f -- "$SSH_AUTH_KEYS" "$SSH_AUTH_KEYS.tmp"

# 无公钥时关闭密码登录必须被拒绝，且不产生任何写入。
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password off without keys was accepted'
fi
[ ! -e "$SSHD_AUTH_DROPIN" ] || fail 'dropin written on refusal'
nreload() { awk '$0=="reload"{n++} END{print n+0}' "$TMP/calls" 2>/dev/null; }
[ "$(nreload)" -eq 0 ] || fail 'reload attempted on refusal'

# 公钥格式校验：垃圾行、未知类型、blob 含非法字符、缺 blob 都要拒绝。
while IFS= read -r bad; do
	if printf '%s\n' "$bad" | act_ssh_key_add; then fail "bad key accepted: $bad"; fi
	[ ! -e "$SSH_AUTH_KEYS" ] || fail "bad key written: $bad"
done <<'BAD'
garbage
ssh-dss AAAAB3NzaC1 comment
ssh-ed25519 not-base64!!
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host
ssh-ed25519
BAD

# 合法公钥（含注释）写入；重复添加不追加。
if printf '%s user@host\n' "$valid_key" | act_ssh_key_add; then :; else fail 'valid key rejected'; fi
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" || fail 'key line missing'
[ "$(awk 'NF{n++} END{print n+0}' "$SSH_AUTH_KEYS")" -eq 1 ] || fail 'key file should hold one line'
out="$(printf '%s other@host\n' "$valid_key" | act_ssh_key_add)"
printf '%s\n' "$out" | grep -q '已存在' || fail 'duplicate key not noticed'
[ "$(awk 'NF{n++} END{print n+0}' "$SSH_AUTH_KEYS")" -eq 1 ] || fail 'duplicate key appended'
if printf '%s touch-key\n' "$second_key" | act_ssh_key_add; then :; else fail 'second key rejected'; fi
[ "$(awk 'NF{n++} END{print n+0}' "$SSH_AUTH_KEYS")" -eq 2 ] || fail 'second key not added'

# 权限不达标（组/其他人可写）时拒绝关闭密码登录。
perm_keys=666
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password off accepted with loose authorized_keys perms'
fi
perm_keys=600
perm_home=777
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password off accepted with loose .ssh perms'
fi
perm_home=700

# 主配置全局指令被面板 drop-in 压住（Include 在前、00- 排第一），照常开关不拒绝。
printf 'Include %s/*.conf\nPasswordAuthentication yes\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then :; else fail 'password off rejected despite dominated body directive'; fi
grep -qx 'PasswordAuthentication no' "$SSHD_AUTH_DROPIN" || fail 'dropin missing with body directive present'
[ "$(ssh_auth_state passwordauthentication)" = off ] || fail 'state should follow dropin over body'
# 重开回到 on，后续测试从这里继续。
if act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 </dev/null; then :; else fail 'password on after body test failed'; fi
: > "$TMP/calls"

# 有钥且无冲突：关闭成功，drop-in 与 sshd -T 一致。
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then :; else fail 'password off failed'; fi
grep -qx 'PasswordAuthentication no' "$SSHD_AUTH_DROPIN" || fail 'PasswordAuthentication no missing'
[ "$(nreload)" -eq 1 ] || fail "reload not called once ($(nreload))"
[ "$(ssh_auth_state passwordauthentication)" = off ] || fail 'state should be off'

# 密码关闭时，不能再关闭唯一剩余的密钥认证。
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then
	fail 'pubkey off accepted while password login off'
fi
[ "$(ssh_auth_state pubkeyauthentication)" = on ] || fail 'pubkey state changed on refusal'
[ "$(nreload)" -eq 1 ] || fail 'refusal reloaded ssh'

# 重新开启不需要确认。
if act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 </dev/null; then :; else fail 'password on failed'; fi
grep -qx 'PasswordAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'PasswordAuthentication yes missing'

# 密钥登录开关同样工作，且两条指令共存。
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then :; else fail 'pubkey off failed'; fi
grep -qx 'PasswordAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'password line lost on pubkey toggle'
grep -qx 'PubkeyAuthentication no' "$SSHD_AUTH_DROPIN" || fail 'PubkeyAuthentication no missing'
if act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录 </dev/null; then :; else fail 'pubkey on failed'; fi

# sshd -t 失败：回滚到原 drop-in；reload 只出现在回滚恢复时（恰好一次）。
SSHD_T_FAIL=1
: > "$TMP/calls"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'toggle succeeded despite sshd -t failure'
fi
grep -qx 'PasswordAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'rollback lost previous dropin'
grep -qx 'PubkeyAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'rollback lost pubkey line'
[ "$(nreload)" -eq 1 ] || fail "rollback reload count wrong ($(nreload))"
SSHD_T_FAIL=0

# reload 失败：同样回滚，两次 reload（失败那次 + 回滚恢复）。
RELOAD_FAIL=1
: > "$TMP/calls"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'toggle succeeded despite reload failure'
fi
grep -qx 'PasswordAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'rollback after reload failure lost dropin'
[ "$(nreload)" -eq 2 ] || fail "reload-failure reload count wrong ($(nreload))"
RELOAD_FAIL=0

# 密钥登录未开启时，关闭密码登录直接拒绝。
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then :; else fail 'pubkey off failed (guard test)'; fi
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password off accepted while pubkey login off'
fi
if act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录 </dev/null; then :; else fail 'pubkey on failed (guard test)'; fi

# ssh.socket 激活时全部拒绝。
SOCKET_ACTIVE=1
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password toggle accepted with ssh.socket'
fi
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then
	fail 'pubkey toggle accepted with ssh.socket'
fi
SOCKET_ACTIVE=0

# —— 真正压不过面板的指令仍要拒绝 ——

# 主配置 Match 块内的指令：按条件覆盖面板，拒绝。
cp -p "$SSHD_MAIN" "$TMP/sshd_config.keep"
printf 'Include %s/*.conf\nMatch User bot\n  PasswordAuthentication no\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'Match-block directive not refused'
fi
grep -qx 'PubkeyAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'dropin touched on Match refusal'

# 主配置缺少 Include：drop-in 不生效，拒绝。
printf 'PasswordAuthentication yes\n' > "$SSHD_MAIN"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'missing Include not refused'
fi

# 排序在面板文件之前的外部 drop-in：拒绝。
printf 'Include %s/*.conf\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"
printf 'PasswordAuthentication no\n' > "$SSHD_DROPIN_DIR/00-aaa-hardening.conf"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'earlier-sorting foreign dropin not refused'
fi
out="$(printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 2>&1)" || true
printf '%s\n' "$out" | grep -q '00-aaa-hardening.conf' || fail 'refusal does not name the conflicting file'
rm -f -- "$SSHD_DROPIN_DIR/00-aaa-hardening.conf"

# 排序靠后的 drop-in 内的 Match 指令仍会按连接覆盖全局值，大小写也不影响识别。
printf 'Match User root\n  passwordauthentication no\n' > "$SSHD_DROPIN_DIR/50-cloud-init.conf"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'Match-block directive in later dropin was not refused'
fi
rm -f -- "$SSHD_DROPIN_DIR/50-cloud-init.conf"

# 排序靠后的 drop-in（如 50-cloud-init.conf）被面板压住：不拒绝，照常关。
printf 'PasswordAuthentication no\n' > "$SSHD_DROPIN_DIR/50-cloud-init.conf"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then :; else fail 'password off rejected despite dominated 50- dropin'; fi
[ "$(ssh_auth_state passwordauthentication)" = off ] || fail 'state should follow our 00- over 50- dropin'
rm -f -- "$SSHD_DROPIN_DIR/50-cloud-init.conf"

# 旧版 99- 文件自动迁移到 00-：内容保留，旧名消失。
rm -f -- "$SSHD_AUTH_DROPIN"
printf 'PasswordAuthentication no\nPubkeyAuthentication yes\n' > "$SSHD_AUTH_DROPIN_OLD"
if act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 </dev/null; then :; else fail 'password on with migration failed'; fi
[ ! -e "$SSHD_AUTH_DROPIN_OLD" ] || fail 'old 99- dropin not migrated away'
[ -f "$SSHD_AUTH_DROPIN" ] || fail 'migrated 00- dropin missing'
grep -qx 'PasswordAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'migrated dropin lost password line'
grep -qx 'PubkeyAuthentication yes' "$SSHD_AUTH_DROPIN" || fail 'migrated dropin lost pubkey line'
rm -f -- "$SSHD_AUTH_DROPIN" "$TMP/sshd_config.keep"
printf 'Include %s/*.conf\n' "$SSHD_DROPIN_DIR" > "$SSHD_MAIN"

# 删除公钥：关密码时禁止删最后一把；正常删除按编号。
reset_all
if printf '%s user@host\n' "$valid_key" | act_ssh_key_add; then :; else fail 'key add for removal failed'; fi
ROOT_PERMIT_ROOT_LOGIN=prohibit-password
if printf '1\n' | act_ssh_key_remove; then
	fail 'deleting last key was accepted when root password login is unavailable'
fi
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" \
	|| fail 'last key was removed while root password login was unavailable'
ROOT_PERMIT_ROOT_LOGIN=yes
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then :; else fail 'password off for removal failed'; fi
if printf '1\n' | act_ssh_key_remove; then fail 'removing last key with password off was accepted'; fi
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" || fail 'last key was removed'
if act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 </dev/null; then :; else fail 'password on for removal failed'; fi
if printf '%s touch-key\n' "$second_key" | act_ssh_key_add; then :; else fail 'second key add failed'; fi
if printf '1\n' | act_ssh_key_remove; then :; else fail 'key removal failed'; fi
grep -qxF "$(printf '%s touch-key' "$second_key")" "$SSH_AUTH_KEYS" || fail 'wrong key kept'
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" && fail 'removed key still present'
if printf 'x\n' | act_ssh_key_remove; then fail 'non-numeric index accepted'; fi

# 已有文件中的注释、无效行和不存在的 ssh-keygen 不能冒充有效公钥。
reset_all
printf '# comment only\n' > "$SSH_AUTH_KEYS"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'comment-only key file allowed password shutdown'
fi
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample bad\n' > "$SSH_AUTH_KEYS"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'invalid existing key allowed password shutdown'
fi
cp "$TMP/test-key" "$SSH_AUTH_KEYS"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'private key file was mistaken for an authorized public key'
fi
printf 'from="192.0.2.1" %s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'restricted key was assumed usable from the current source'
fi
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
ssh-keygen() { return 127; }
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password shutdown accepted without working ssh-keygen'
fi
unset -f ssh-keygen
command() {
	if [ "${1:-}" = -v ] && [ "${2:-}" = ssh-keygen ]; then return 1; fi
	builtin command "$@"
}
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then
	fail 'password shutdown accepted when ssh-keygen is missing'
fi
unset -f command

# 注释不能冒充剩余公钥；删除其他行时保留原有空行和公钥。
reset_all
printf '%s user@host\n# keep\n' "$valid_key" > "$SSH_AUTH_KEYS"
ROOT_PERMIT_ROOT_LOGIN=prohibit-password
if printf '1\n' | act_ssh_key_remove; then
	fail 'removed the last valid key because a comment remained'
fi
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" || fail 'last valid key was removed'
printf '# comment\n\n%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
if printf '1\n' | act_ssh_key_remove; then :; else fail 'removing a comment with a valid key remaining failed'; fi
[ "$(wc -l < "$SSH_AUTH_KEYS")" -eq 2 ] || fail 'removing a comment did not preserve blank lines'
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" || fail 'remaining valid key was changed'

# MFA 不是独立备用方式；检查使用实际连接来源而不是 localhost。
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
ROOT_AUTH_METHODS='publickey,password'
if printf '1\n' | act_ssh_key_remove; then fail 'last key removed when password also requires that key'; fi
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then fail 'pubkey off accepted with mandatory MFA'; fi
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then fail 'password off accepted with mandatory MFA'; fi
ROOT_AUTH_METHODS=any
ROOT_AUTH_KEYS_FILE=/etc/ssh/authorized_keys/%u
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then fail 'password off accepted when sshd ignores the panel key file'; fi
ROOT_AUTH_KEYS_FILE='.ssh/authorized_keys .ssh/authorized_keys2'
ROOT_DENY_SOURCE=203.0.113.23
if root_password_login_ready; then fail 'root password policy used localhost instead of remote source'; fi
ROOT_DENY_SOURCE=""
ROOT_USE_DNS=yes
if root_password_login_ready; then fail 'UseDNS=yes was assumed safe without the resolved host'; fi
ROOT_USE_DNS=no
ROOT_PASSWORD_STATUS=L
if root_password_login_ready; then fail 'locked root password was assumed usable'; fi
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then fail 'pubkey off accepted with locked root password'; fi
ROOT_PASSWORD_STATUS=P
SSH_CONNECTION=""
if root_password_login_ready; then fail 'missing connection was assumed safe'; fi

# 如果当前连接的 Match 规则覆盖了面板，关闭必须回滚。
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
ROOT_REMOTE_PASSWORD=yes
if printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录; then fail 'password shutdown accepted despite effective root override'; fi
[ "$(ssh_auth_state passwordauthentication)" = on ] || fail 'password override was not rolled back'
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
ROOT_REMOTE_PUBKEY=yes
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then fail 'pubkey shutdown accepted despite effective root override'; fi
[ "$(ssh_auth_state pubkeyauthentication)" = on ] || fail 'pubkey override was not rolled back'

# 键盘交互可能另行允许密码，关闭全局密码认证后要明确提示。
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
ROOT_KBD_AUTH=yes
out="$(printf 'yes\n' | act_ssh_auth passwordauthentication PasswordAuthentication 密码登录)" || fail 'password off with keyboard interactive failed'
printf '%s\n' "$out" | grep -q '键盘交互认证仍开启' || fail 'keyboard-interactive password possibility was not explained'
out="$(printf '0\n' | act_ssh)"
printf '%s\n' "$out" | grep -q '键盘交互认证仍开启' || fail 'keyboard-interactive warning missing from menu'

# 密码认证开关不修改 root 策略；受限时明确说明，禁止关闭公钥。
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
printf 'PasswordAuthentication no\nPubkeyAuthentication yes\n' > "$SSHD_AUTH_DROPIN"
ROOT_PERMIT_ROOT_LOGIN=prohibit-password
out="$(act_ssh_auth passwordauthentication PasswordAuthentication 密码登录 </dev/null)" || fail 'password on failed with root restriction'
printf '%s\n' "$out" | grep -q 'root 密码登录可能仍受' || fail 'root password restriction was not explained'
if printf 'yes\n' | act_ssh_auth pubkeyauthentication PubkeyAuthentication 密钥登录; then
	fail 'pubkey off accepted when root password is prohibited'
fi

# 最后一把公钥只在 root 密码条件通过且用户确认后删除。
reset_all
printf '%s user@host\n' "$valid_key" > "$SSH_AUTH_KEYS"
if printf '1\nno\n' | act_ssh_key_remove; then fail 'last key deletion ignored cancellation'; fi
grep -qxF "$(printf '%s user@host' "$valid_key")" "$SSH_AUTH_KEYS" || fail 'cancelled deletion changed the key file'
if printf '1\nyes\n' | act_ssh_key_remove; then :; else fail 'confirmed deletion with password available failed'; fi
[ ! -s "$SSH_AUTH_KEYS" ] || fail 'confirmed last key deletion did not remove the key'

# root 密码修改：两次一致才调用 chpasswd，不一致或空密码不动。
if printf 'secret\nsecret\n' | act_ssh_password; then :; else fail 'password change failed'; fi
grep -q chpasswd "$TMP/calls" || fail 'chpasswd not called'
reset_all
if printf 'one\ntwo\n' | act_ssh_password; then fail 'mismatched password accepted'; fi
grep -q chpasswd "$TMP/calls" && fail 'chpasswd called on mismatch'
if printf '\n' | act_ssh_password; then fail 'empty password accepted'; fi

# 菜单：显示两种登录状态，无效编号提示，0 返回。
out="$(printf '0\n' | act_ssh)"
printf '%s\n' "$out" | grep '全局密码认证' >/dev/null || fail 'menu misses password state'
printf '%s\n' "$out" | grep '全局密钥认证' >/dev/null || fail 'menu misses pubkey state'
out9="$(printf '9\n0\n' | act_ssh)"
printf '%s\n' "$out9" | grep '请输入 0–6' >/dev/null || fail 'invalid menu choice not reported'
SSHD_QUERY_FAIL=1
out="$(printf '0\n' | act_ssh)"
printf '%s\n' "$out" | grep '未知' >/dev/null || fail 'unavailable sshd was displayed as disabled'
SSHD_QUERY_FAIL=0
SSHD_EXTRA_OUTPUT=1
[ "$(ssh_auth_state passwordauthentication)" = on ] || fail 'large sshd output was mistaken for a failed query'

echo "ssh auth tests passed"
