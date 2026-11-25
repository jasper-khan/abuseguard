// policy.rs — root-only native policy: nftables transaction + fail2ban ignoreip.
use crate::allow::{format_allowlist, load_allowlist, Allowlist};
use crate::config::load_config_at;
use crate::util::{logf, write_file_atomic};
use std::collections::BTreeMap;
use std::process::Command;
use time::OffsetDateTime;

pub const POLICY_TABLE: &str = "caddy_abuseguard_intel";
pub const POLICY_APPLIED_SRC: &str = "policy-apply";

// Only these jails get their ignoreip driven by the generated file. Other
// jails (including retired intel jails) keep their own configuration.
pub const POLICY_JAILS: [&str; 4] = [
    "caddy-rate-local",
    "caddy-probe-h1",
    "caddy-probe-h2",
    "sshd",
];

// ignoreipToken: ^[A-Za-z0-9:._/-]+$ without the regex crate.
fn valid_ignoreip_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'.' | b'_' | b'/' | b'-'))
}

// ipv4Element: ([0-9]{1,3}\.){3}[0-9]{1,3} without the regex crate.
fn contains_ipv4_pattern(out: &[u8]) -> bool {
    let b = out;
    'outer: for i in 0..b.len() {
        // try to match 4 groups of 1-3 digits separated by dots starting at i
        let mut pos = i;
        let mut count = 0;
        while count < 4 {
            let start = pos;
            while pos < b.len() && b[pos].is_ascii_digit() && pos - start < 3 {
                pos += 1;
            }
            if pos == start {
                continue 'outer;
            }
            count += 1;
            if count < 4 {
                if pos < b.len() && b[pos] == b'.' {
                    pos += 1;
                } else {
                    continue 'outer;
                }
            }
        }
        return true;
    }
    false
}

pub struct PolicyPaths {
    pub config_path: String,
    pub intel_nft: String,
    pub allow_nft: String,
    pub applied: String,
    pub f2b_dir: String,
    pub f2b_policy: String,
}

fn policy_env(key: &str, def: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => def.to_string(),
    }
}

fn policy_paths_for(conf_dir: &str) -> PolicyPaths {
    let join = |a: &str, b: &str| format!("{}/{}", a, b);
    let f2b_dir = policy_env("AG_F2B_JAIL_DIR", "/etc/fail2ban/jail.d");
    PolicyPaths {
        config_path: join(conf_dir, "config.json"),
        intel_nft: join(conf_dir, "intel.nft"),
        allow_nft: join(conf_dir, "intel-allow.nft"),
        applied: join(conf_dir, "intel-applied.json"),
        f2b_policy: join(&f2b_dir, "zzz-caddy-abuseguard-policy.local"),
        f2b_dir,
    }
}

fn look_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(name);
        if cand.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(md) = cand.metadata() {
                    if md.permissions().mode() & 0o111 == 0 {
                        continue;
                    }
                }
            }
            return Some(cand);
        }
    }
    None
}

// run_policy_apply is the root-only native-policy entry point. It is the only
// engine command that needs root: sync/report/enqueue remain unprivileged.
pub fn run_policy_apply(args: &[String]) {
    if !args.is_empty() {
        logf("policy-apply: unexpected arguments");
        std::process::exit(2);
    }
    if !cfg!(target_os = "linux") {
        logf("policy-apply: 仅支持 Linux。");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    if !rustix::process::geteuid().is_root() {
        logf("policy-apply: 需要 root 权限");
        std::process::exit(1);
    }
    if look_path("nft").is_none() {
        logf("policy-apply: 未找到 nft");
        std::process::exit(1);
    }
    let conf_dir = policy_env("AG_CONF_DIR", "/etc/caddy-abuseguard");
    if !std::path::Path::new(&conf_dir).is_dir() {
        logf(&format!("policy-apply: 配置目录不存在：{}", conf_dir));
        std::process::exit(1);
    }
    let lock = match crate::filelock::acquire_policy_lock(
        &format!("{}/policy.lock", conf_dir),
        std::time::Duration::from_secs(60),
    ) {
        Ok(l) => l,
        Err(e) => {
            logf(&format!("policy-apply: {}", e));
            std::process::exit(1);
        }
    };
    let result = apply_policy(&conf_dir);
    drop(lock);
    if let Err(e) = result {
        logf(&format!("policy-apply: {}", e));
        std::process::exit(1);
    }
}

struct PolicyDiskBackup {
    intel: Option<Vec<u8>>,
    allow: Option<Vec<u8>>,
    applied: Option<Vec<u8>>,
}

pub fn apply_policy(conf_dir: &str) -> Result<(), String> {
    let p = policy_paths_for(conf_dir);

    let work = mkdtemp_policy(conf_dir)?;
    let _cleanup = TempDirGuard(&work);

    // Boot starts with no kernel table: restore the root-owned last-good
    // snapshot before any config, whitelist, feed or fail2ban read can fail.
    if !nft_table_exists() {
        restore_policy_snapshot(&p.intel_nft);
    }

    let c = load_config_at(&p.config_path)
        .map_err(|e| format!("读取配置失败；未更改任何策略：{}", e))?;

    let allow_data = format_allowlist(&c.allowlist_file)
        .map_err(|e| format!("白名单校验/导出失败；未更改任何策略：{}", e))?;
    let allow = load_allowlist(&c.allowlist_file)
        .map_err(|e| format!("白名单校验/导出失败；未更改任何策略：{}", e))?;
    let allow_entries = non_empty_lines(&allow_data);

    // Preserve admin-managed native ignoreip per jail before the kernel change,
    // reading the effective config through a work-dir mirror that reproduces
    // ancestor dirs for relative includes without touching /etc/fail2ban.
    let merge = capture_native_ignoreip(&p.f2b_dir, &p.f2b_policy, &work, &allow_entries)?;

    let intel_data = crate::intel::format_intel(&c).map_err(|e| {
        format!(
            "情报导出失败；保留上一次生效的策略（检查 {}/intel.txt）：{}",
            c.paths.state_dir, e
        )
    })?;
    let intel_entries = non_empty_lines(&intel_data);
    if intel_entries.is_empty() && policy_has_elements(&p) {
        // Missing feed after a non-empty policy existed is a failure, not a
        // request to wipe enforcement.
        return Err("情报导出为空；已有策略不会被空列表覆盖（首次安装允许空列表）。".to_string());
    }

    let now = OffsetDateTime::now_utc();
    let intel_nft = render_intel_nft(&intel_entries, &allow_entries, now);
    let allow_nft = render_allow_nft(&allow_entries);
    let applied = render_applied(now, intel_entries.len(), allow_entries.len());

    let intel_path = format!("{}/intel.nft", work);
    if let Err(e) = (|| -> Result<(), String> {
        std::fs::write(&intel_path, &intel_nft).map_err(crate::util::io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&intel_path, std::fs::Permissions::from_mode(0o600))
                .map_err(crate::util::io_err)?;
        }
        Ok(())
    })() {
        return Err(format!("无法创建策略临时文件；未更改任何策略：{}", e));
    }
    if let Err(e) = nft_check_file(&intel_path) {
        return Err(format!("内核策略校验失败；未更改任何策略：{}", e));
    }

    // Back up both the live policy and the disk snapshots before changing the
    // kernel: a failed persist must restore what is actually enforced, not an
    // assumption that disk matches the running table.
    let had_live = capture_live_policy(&work)
        .map_err(|e| format!("无法备份当前内核策略；未更改任何策略：{}", e))?;
    let backup =
        backup_policy_files(&p).map_err(|e| format!("无法备份策略快照；未更改任何策略：{}", e))?;

    if let Err(e) = nft_apply_file(&intel_path) {
        return Err(format!("内核策略应用失败；旧策略保持不变：{}", e));
    }

    let persist = write_file_atomic(&p.intel_nft, &intel_nft, 0o640)
        .and_then(|()| write_file_atomic(&p.allow_nft, &allow_nft, 0o640))
        .and_then(|()| write_file_atomic(&p.applied, &applied, 0o640));
    if let Err(e) = persist {
        rollback_policy(&p, &work, had_live, &backup);
        return Err(format!("无法保存情报策略快照；已恢复上一次内核策略：{}", e));
    }

    let f2b_data = render_fail2ban_policy(&c.allowlist_file, &merge);
    let (f2b_changed, f2b_old, had_f2b) =
        match prepare_fail2ban_file(&p.f2b_dir, &p.f2b_policy, &f2b_data) {
            Err(e) => {
                rollback_policy(&p, &work, had_live, &backup);
                return Err(e);
            }
            Ok(v) => v,
        };
    if f2b_changed {
        if let Err(e) = write_file_atomic(&p.f2b_policy, &f2b_data, 0o644) {
            rollback_policy(&p, &work, had_live, &backup);
            return Err(format!(
                "无法写入 fail2ban ignoreip；已恢复上一次内核策略：{}",
                e
            ));
        }
    }

    if cmd_ok("fail2ban-client", &["ping"]) {
        if f2b_changed {
            if !cmd_ok("fail2ban-client", &["reload"]) {
                restore_fail2ban_file(&p.f2b_policy, f2b_old.as_deref(), had_f2b);
                if !cmd_ok("fail2ban-client", &["reload"]) {
                    logf("policy-apply: 警告：fail2ban 回滚重载失败，请手动检查。");
                }
                rollback_policy(&p, &work, had_live, &backup);
                return Err("fail2ban 重载失败；已回滚内核策略和 ignoreip。".to_string());
            }
        }
        clear_whitelisted_bans(&allow);
    } else {
        logf("policy-apply: fail2ban 未运行；ignoreip 已更新，将在下次启动时生效。");
    }

    logf(&format!(
        "策略已应用：{} 条情报，{} 条白名单。",
        intel_entries.len(),
        allow_entries.len()
    ));
    Ok(())
}

struct TempDirGuard<'a>(&'a str);
impl Drop for TempDirGuard<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}

fn mkdtemp_policy(conf_dir: &str) -> Result<String, String> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    for _ in 0..1000 {
        let cand = format!(
            "{}/.policy.{}-{}",
            conf_dir,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        match std::fs::create_dir(&cand) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&cand, std::fs::Permissions::from_mode(0o700));
                }
                return Ok(cand);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("无法创建策略临时目录：{}", e)),
        }
    }
    Err("无法创建策略临时目录".to_string())
}

// cmd_ok runs the command and returns whether it exited 0.
fn cmd_ok(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn cmd_output(prog: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(crate::util::io_err)?;
    if !out.status.success() {
        return Err(format!("exit status {}", out.status.code().unwrap_or(-1)));
    }
    Ok(out.stdout)
}

// Mirror every ancestor directory from `/` down to `real_target` inside
// `root_mirror` with sibling symlinks. Any read_dir or symlink error aborts
// the apply so a missing sibling cannot silently drop relative `[INCLUDES]`.
#[cfg(unix)]
fn mirror_ancestors(
    root_mirror: &std::path::Path,
    real_target: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::symlink;
    use std::path::{Component, PathBuf};

    let parts: Vec<std::ffi::OsString> = real_target
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            _ => None,
        })
        .collect();
    if parts.is_empty() {
        return Err(format!("无效的 fail2ban 配置目录：{}", real_target.display()));
    }

    let mut real_cur = PathBuf::from("/");
    let mut mir_cur = root_mirror.to_path_buf();
    std::fs::create_dir_all(&mir_cur).map_err(crate::util::io_err)?;
    for part in &parts {
        for entry in std::fs::read_dir(&real_cur).map_err(crate::util::io_err)? {
            let entry = entry.map_err(crate::util::io_err)?;
            let name = entry.file_name();
            if name == *part {
                continue;
            }
            let dst = mir_cur.join(&name);
            if dst.symlink_metadata().is_err() {
                symlink(real_cur.join(&name), &dst).map_err(crate::util::io_err)?;
            }
        }
        real_cur.push(part);
        mir_cur.push(part);
        if mir_cur
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            std::fs::remove_file(&mir_cur).map_err(crate::util::io_err)?;
        }
        std::fs::create_dir_all(&mir_cur).map_err(crate::util::io_err)?;
    }
    Ok(mir_cur)
}

// Build a read-only symlink mirror of the fail2ban config directory inside
// `work_dir` (already writable under ProtectSystem=strict), following the real
// canonical directory paths so symlinked `/etc/fail2ban` (or `jail.d`) resolves
// relative `[INCLUDES]` like `before = ../native.local` identically to the
// kernel without mutating live config.
#[cfg(unix)]
fn build_f2b_mirror(
    f2b_dir: &str,
    f2b_policy: &str,
    work_dir: &str,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::symlink;
    use std::path::Path;

    let jail_dir = Path::new(f2b_dir);
    let f2b_root = jail_dir
        .parent()
        .ok_or_else(|| format!("无效的 fail2ban 配置目录：{}", f2b_dir))?;
    let jail_d_name = jail_dir
        .file_name()
        .ok_or_else(|| format!("无效的 fail2ban 配置目录：{}", f2b_dir))?;
    let policy_name = Path::new(f2b_policy)
        .file_name()
        .ok_or_else(|| format!("无效的 fail2ban 策略路径：{}", f2b_policy))?;
    let real_root = std::fs::canonicalize(f2b_root).map_err(crate::util::io_err)?;
    let root_mirror = Path::new(work_dir).join("f2b-root");
    let mir_root = mirror_ancestors(&root_mirror, &real_root)?;

    for entry in std::fs::read_dir(&real_root).map_err(crate::util::io_err)? {
        let entry = entry.map_err(crate::util::io_err)?;
        let name = entry.file_name();
        if name.as_os_str() == jail_d_name {
            continue;
        }
        symlink(real_root.join(&name), mir_root.join(&name)).map_err(crate::util::io_err)?;
    }

    if jail_dir.is_dir() {
        let real_jail_dir = std::fs::canonicalize(jail_dir).map_err(crate::util::io_err)?;
        let expected_jail_dir = real_root.join(jail_d_name);
        let mirror_jail_d = if real_jail_dir == expected_jail_dir {
            let d = mir_root.join(jail_d_name);
            std::fs::create_dir_all(&d).map_err(crate::util::io_err)?;
            d
        } else {
            let d = mirror_ancestors(&root_mirror, &real_jail_dir)?;
            symlink(&d, mir_root.join(jail_d_name)).map_err(crate::util::io_err)?;
            d
        };
        for entry in std::fs::read_dir(&real_jail_dir).map_err(crate::util::io_err)? {
            let entry = entry.map_err(crate::util::io_err)?;
            let name = entry.file_name();
            if name.as_os_str() == policy_name {
                continue;
            }
            symlink(real_jail_dir.join(&name), mirror_jail_d.join(&name))
                .map_err(crate::util::io_err)?;
        }
    }
    Ok(mir_root)
}

#[cfg(not(unix))]
fn build_f2b_mirror(
    _f2b_dir: &str,
    _f2b_policy: &str,
    _work_dir: &str,
) -> Result<std::path::PathBuf, String> {
    Err("仅支持 Unix 平台".to_string())
}

// capture_native_ignoreip merges the whitelist with each jail's own effective
// ignoreip by dumping a temporary mirror config tree under `work_dir` that
// omits the generated policy file while preserving relative include bases.
fn capture_native_ignoreip(
    f2b_dir: &str,
    f2b_policy: &str,
    work_dir: &str,
    allow: &[String],
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mirror = match build_f2b_mirror(f2b_dir, f2b_policy, work_dir) {
        Ok(m) => m,
        Err(e) => return Err(format!("无法读取 fail2ban 当前配置；未更改任何策略：{}", e)),
    };
    let mirror_str = mirror.to_string_lossy();
    let dump = match cmd_output("fail2ban-client", &["-c", mirror_str.as_ref(), "-d"]) {
        Err(_) => return Err("无法读取 fail2ban 当前配置；未更改任何策略。".to_string()),
        Ok(d) if d.iter().all(|b| b.is_ascii_whitespace()) => {
            return Err("无法读取 fail2ban 当前配置；未更改任何策略。".to_string());
        }
        Ok(d) => d,
    };
    merge_native_ignoreip(&dump, allow)
}

// merge_native_ignoreip combines the whitelist with each driven jail's native
// addignoreip entries. The dump is a Python-repr-like list; strip its
// punctuation and parse strictly. Never execute or interpolate it.
pub fn merge_native_ignoreip(
    dump: &[u8],
    allow: &[String],
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let mut merged: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for jail in POLICY_JAILS {
        let mut entries: Vec<String> = Vec::with_capacity(allow.len());
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for e in allow {
            if seen.insert(e.as_str()) {
                entries.push(e.clone());
            }
        }
        merged.insert(jail.to_string(), entries);
    }
    for line in String::from_utf8_lossy(dump).split('\n') {
        if !line.contains("addignoreip") {
            continue;
        }
        let s = line.strip_prefix('[').unwrap_or(line);
        let s = s.replace(['[', ']', '\'', '"'], "");
        let raw_fields: Vec<&str> = s.split(',').collect();
        let fields: Vec<String> = raw_fields.iter().map(|f| f.trim().to_string()).collect();
        if fields.len() < 4 || fields[0] != "set" || fields[2] != "addignoreip" {
            continue;
        }
        let jail = &fields[1];
        let entries = match merged.get_mut(jail) {
            None => continue,
            Some(e) => e,
        };
        let mut seen: std::collections::HashSet<String> = entries.iter().cloned().collect();
        for token in &fields[3..] {
            if token.is_empty() {
                continue;
            }
            if !valid_ignoreip_token(token) {
                return Err(format!(
                    "{} 的原生 ignoreip 含非法条目；未更改任何策略。",
                    jail
                ));
            }
            if seen.insert(token.clone()) {
                entries.push(token.clone());
            }
        }
    }
    Ok(merged)
}

fn restore_fail2ban_file(path: &str, old: Option<&[u8]>, had: bool) {
    if had {
        if let Some(data) = old {
            if let Err(e) = write_file_atomic(path, data, 0o644) {
                logf(&format!(
                    "policy-apply: 警告：无法恢复旧 ignoreip 文件 {}。{}",
                    path, e
                ));
            }
        }
        return;
    }
    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            logf(&format!(
                "policy-apply: 警告：无法删除新 ignoreip 文件 {}。{}",
                path, e
            ));
        }
    }
}

// prepare_fail2ban_file reports whether the generated policy changed and the
// previous content needed for rollback. A missing jail.d keeps kernel policy
// only, matching the old applier.
fn prepare_fail2ban_file(
    dir: &str,
    path: &str,
    data: &[u8],
) -> Result<(bool, Option<Vec<u8>>, bool), String> {
    if !std::path::Path::new(dir).is_dir() {
        logf(&format!(
            "policy-apply: 警告：未找到 {}；本次只应用内核策略，跳过 fail2ban ignoreip。",
            dir
        ));
        return Ok((false, None, false));
    }
    match std::fs::read(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((true, None, false)),
        Err(e) => Err(format!("无法备份 {}：{}", path, e)),
        Ok(old) => Ok((old != data, Some(old), true)),
    }
}

fn clear_whitelisted_bans(allow: &Allowlist) {
    for jail in POLICY_JAILS {
        let out = match cmd_output("fail2ban-client", &["status", jail]) {
            Ok(o) => o,
            Err(_) => continue,
        };
        for line in String::from_utf8_lossy(&out).split('\n') {
            let idx = match line.find("Banned IP list:") {
                None => continue,
                Some(i) => i,
            };
            for ip in line[idx + "Banned IP list:".len()..].split_whitespace() {
                if !allow.contains(ip) {
                    continue;
                }
                if !cmd_ok("fail2ban-client", &["set", jail, "unbanip", ip]) {
                    logf(&format!(
                        "policy-apply: 警告：无法解除 {} 中已加白 IP {} 的封禁。",
                        jail, ip
                    ));
                }
            }
        }
    }
}

pub fn render_intel_nft(intel: &[String], allow: &[String], now: OffsetDateTime) -> Vec<u8> {
    let mut b = String::new();
    b.push_str(&format!(
        "# Generated by caddy-abuseguard-policy at {}\n",
        crate::report::stamp_format(now)
    ));
    b.push_str(&format!("add table inet {}\n", POLICY_TABLE));
    b.push_str(&format!("delete table inet {}\n", POLICY_TABLE));
    b.push_str(&format!("table inet {} {{\n", POLICY_TABLE));
    b.push_str("\tset block4 {\n\t\ttype ipv4_addr\n");
    if !intel.is_empty() {
        b.push_str("\t\telements = {\n");
        for (i, e) in intel.iter().enumerate() {
            if i > 0 {
                b.push_str(",\n");
            }
            b.push_str(&format!("\t\t\t{}", e));
        }
        b.push_str("\n\t\t}\n");
    }
    b.push_str("\t}\n\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n");
    // One rule per entry keeps overlapping IPs/CIDRs valid on every supported
    // nft version; each rule returns only from this dedicated chain.
    for e in allow {
        if e.contains(':') {
            b.push_str(&format!("\t\tip6 saddr {} return\n", e));
        } else {
            b.push_str(&format!("\t\tip saddr {} return\n", e));
        }
    }
    b.push_str("\t\tip saddr @block4 drop\n\t}\n}\n");
    b.into_bytes()
}

pub fn render_allow_nft(allow: &[String]) -> Vec<u8> {
    let mut b = String::new();
    b.push_str(
        "# Allowlist exceptions (one per line) at last apply; intel.nft is the applied snapshot.\n",
    );
    for e in allow {
        b.push_str(&format!("{}\n", e));
    }
    b.into_bytes()
}

#[derive(serde::Serialize)]
struct PolicyAppliedMeta {
    applied_at: String,
    intel_entries: usize,
    whitelist_entries: usize,
    source: &'static str,
}

pub fn render_applied(now: OffsetDateTime, intel: usize, whitelist: usize) -> Vec<u8> {
    let b = serde_json::to_vec(&PolicyAppliedMeta {
        applied_at: crate::report::stamp_format(now),
        intel_entries: intel,
        whitelist_entries: whitelist,
        source: POLICY_APPLIED_SRC,
    })
    .unwrap_or_default();
    let mut out = b;
    out.push(b'\n');
    out
}

pub fn render_fail2ban_policy(
    whitelist_path: &str,
    by_jail: &BTreeMap<String, Vec<String>>,
) -> Vec<u8> {
    let mut b = String::new();
    b.push_str("# Generated by caddy-abuseguard-policy. Do not edit.\n");
    b.push_str(&format!(
        "# Source: {} + each jail's own native ignoreip. Apply: sudo ag --policy-apply\n",
        whitelist_path
    ));
    for jail in POLICY_JAILS {
        let entries = match by_jail.get(jail) {
            None => continue,
            Some(e) => e,
        };
        if entries.is_empty() {
            continue;
        }
        b.push_str(&format!("\n[{}]\n", jail));
        for (i, e) in entries.iter().enumerate() {
            if i == 0 {
                b.push_str(&format!("ignoreip = {}\n", e));
            } else {
                b.push_str(&format!("           {}\n", e));
            }
        }
    }
    b.into_bytes()
}

pub fn non_empty_lines(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(data).split('\n') {
        if !line.is_empty() {
            out.push(line.to_string());
        }
    }
    out
}

// policy_has_elements reports whether a previously applied policy had feed
// entries, from the root snapshot or the live set.
fn policy_has_elements(p: &PolicyPaths) -> bool {
    if let Ok(data) = std::fs::read(&p.intel_nft) {
        if snapshot_has_elements(&data) {
            return true;
        }
    }
    match cmd_output(
        "nft",
        &["-n", "list", "set", "inet", POLICY_TABLE, "block4"],
    ) {
        Ok(out) => contains_ipv4_pattern(&out),
        Err(_) => false,
    }
}

pub fn snapshot_has_elements(data: &[u8]) -> bool {
    data.windows(b"elements = {".len())
        .any(|w| w == b"elements = {")
}

fn nft_table_exists() -> bool {
    cmd_ok("nft", &["list", "table", "inet", POLICY_TABLE])
}

fn restore_policy_snapshot(path: &str) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            logf(&format!(
                "policy: boot restore: reading snapshot {} failed: {}",
                path, e
            ));
            return;
        }
    };
    if data.is_empty() {
        logf(&format!(
            "policy: boot restore: snapshot {} is empty; kernel table left absent",
            path
        ));
        return;
    }
    if let Err(e) = nft_check_file(path) {
        logf(&format!(
            "policy: boot restore: snapshot {} failed validation: {}",
            path, e
        ));
        return;
    }
    if let Err(e) = nft_apply_file(path) {
        logf(&format!(
            "policy: boot restore: applying snapshot {} failed: {}",
            path, e
        ));
    }
}

// capture_live_policy dumps the live table so rollback restores what is
// actually enforced even if the disk snapshot is stale.
fn capture_live_policy(work: &str) -> Result<bool, String> {
    if !nft_table_exists() {
        return Ok(false);
    }
    let out = match cmd_output("nft", &["list", "table", "inet", POLICY_TABLE]) {
        Err(e) => return Err(e),
        Ok(o) => o,
    };
    if out.iter().all(|b| b.is_ascii_whitespace()) {
        return Err("nft 返回空的内核策略".to_string());
    }
    let live = render_live_policy(&out);
    let live_path = format!("{}/live.nft", work);
    if let Err(e) = std::fs::write(&live_path, &live).map_err(crate::util::io_err) {
        return Err(e);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&live_path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(true)
}

// render_live_policy wraps a kernel dump in the add/delete/table idiom so a
// rollback is a single atomic nft load, never a delete-then-load gap.
pub fn render_live_policy(dump: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(format!("add table inet {}\n", POLICY_TABLE).as_bytes());
    b.extend_from_slice(format!("delete table inet {}\n", POLICY_TABLE).as_bytes());
    b.extend_from_slice(dump);
    b
}

fn backup_policy_files(p: &PolicyPaths) -> Result<PolicyDiskBackup, String> {
    Ok(PolicyDiskBackup {
        intel: read_backup(&p.intel_nft)?,
        allow: read_backup(&p.allow_nft)?,
        applied: read_backup(&p.applied)?,
    })
}

fn read_backup(path: &str) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// rollback_policy restores the live kernel policy first, then the disk
// snapshots. Rollback errors are logged, never suppressed.
fn rollback_policy(p: &PolicyPaths, work: &str, had_live: bool, b: &PolicyDiskBackup) {
    if had_live {
        let live_path = format!("{}/live.nft", work);
        if let Err(e) = nft_apply_file(&live_path) {
            logf(&format!(
                "policy-apply: 警告：无法恢复上一次内核情报策略，请检查 nft list table inet {}：{}",
                POLICY_TABLE, e
            ));
        }
    } else if nft_table_exists() {
        if !cmd_ok("nft", &["delete", "table", "inet", POLICY_TABLE]) {
            logf(&format!(
                "policy-apply: 警告：无法删除新建的情报表 inet {}",
                POLICY_TABLE
            ));
        }
    }
    restore_disk_file(&p.intel_nft, &b.intel);
    restore_disk_file(&p.allow_nft, &b.allow);
    restore_disk_file(&p.applied, &b.applied);
}

fn restore_disk_file(path: &str, data: &Option<Vec<u8>>) {
    match data {
        Some(d) => {
            if let Err(e) = write_file_atomic(path, d, 0o640) {
                logf(&format!("policy-apply: 警告：无法恢复 {}：{}", path, e));
            }
        }
        None => {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    logf(&format!("policy-apply: 警告：无法删除 {}：{}", path, e));
                }
            }
        }
    }
}

fn nft_check_file(path: &str) -> Result<(), String> {
    let out = Command::new("nft")
        .args(["-c", "-f", path])
        .output()
        .map_err(crate::util::io_err)?;
    if !out.status.success() {
        return Err(format!(
            "exit status {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

fn nft_apply_file(path: &str) -> Result<(), String> {
    let out = Command::new("nft")
        .args(["-f", path])
        .output()
        .map_err(crate::util::io_err)?;
    if !out.status.success() {
        return Err(format!(
            "exit status {}: {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::fixed_time;

    // pinned fragments of the nft transaction; a raw feed or whitelist token
    // must never reach it.
    #[test]
    fn render_intel_nft_matches_contract() {
        use time::format_description::well_known::Rfc3339;
        let now: OffsetDateTime = OffsetDateTime::parse("2026-11-14T01:02:03Z", &Rfc3339).unwrap();
        let out = String::from_utf8(render_intel_nft(
            &["192.0.2.33".to_string(), "198.51.100.9".to_string()],
            &["127.0.0.0/8".to_string(), "2001:db8::/64".to_string()],
            now,
        ))
        .unwrap();
        for want in [
            "# Generated by caddy-abuseguard-policy at 2026-11-14T01:02:03Z\n",
            "add table inet caddy_abuseguard_intel\n",
            "delete table inet caddy_abuseguard_intel\n",
            "\t\telements = {\n\t\t\t192.0.2.33,\n\t\t\t198.51.100.9\n\t\t}\n",
            "\t\tip saddr 127.0.0.0/8 return\n",
            "\t\tip6 saddr 2001:db8::/64 return\n",
            "\t\tip saddr @block4 drop\n",
        ] {
            assert!(
                out.contains(want),
                "rendered transaction missing {:?}:\n{}",
                want,
                out
            );
        }
    }

    #[test]
    fn render_intel_nft_empty_feed() {
        let out = String::from_utf8(render_intel_nft(
            &[],
            &["192.0.2.1".to_string()],
            fixed_time(0),
        ))
        .unwrap();
        assert!(
            !out.contains("elements = {"),
            "empty feed must not emit an elements block:\n{}",
            out
        );
        assert!(
            out.contains("ip saddr @block4 drop"),
            "empty feed must still drop the set:\n{}",
            out
        );
    }

    #[test]
    fn merge_native_ignoreip_appends_per_jail() {
        let dump = br#"['set', 'sshd', 'addignoreip', '192.0.2.88']
['set', 'caddy-rate-local', 'addignoreip', '192.0.2.8', '192.0.2.9']
['set', 'unrelated', 'addignoreip', '192.0.2.66']
"#;
        let merged =
            merge_native_ignoreip(dump, &["192.0.2.1".to_string(), "192.0.2.8".to_string()])
                .unwrap();
        let sshd = &merged["sshd"];
        assert_eq!(sshd.len(), 3);
        assert_eq!(sshd[2], "192.0.2.88");
        let rate = &merged["caddy-rate-local"];
        assert_eq!(rate.len(), 3);
        assert_eq!(rate[2], "192.0.2.9");
        let h1 = &merged["caddy-probe-h1"];
        assert_eq!(
            h1.len(),
            2,
            "native sshd-only entry leaked into a Web jail: {:?}",
            h1
        );
        assert!(!h1.iter().any(|e| e == "192.0.2.88"));
    }

    #[test]
    fn merge_native_ignoreip_rejects_unsafe_token() {
        let dump = b"['set', 'sshd', 'addignoreip', '192.0.2.8 203.0.113.1']\n";
        assert!(
            merge_native_ignoreip(dump, &[]).is_err(),
            "whitespace-joined or interpolated token was accepted"
        );
    }

    #[test]
    fn render_fail2ban_policy_matches_contract() {
        let mut by_jail = BTreeMap::new();
        by_jail.insert("sshd".to_string(), vec!["192.0.2.8".to_string()]);
        by_jail.insert(
            "caddy-rate-local".to_string(),
            vec!["192.0.2.1".to_string(), "2001:db8::/64".to_string()],
        );
        let out = String::from_utf8(render_fail2ban_policy(
            "/etc/caddy-abuseguard/whitelist",
            &by_jail,
        ))
        .unwrap();
        for want in [
            "\n[sshd]\nignoreip = 192.0.2.8\n",
            "\n[caddy-rate-local]\nignoreip = 192.0.2.1\n           2001:db8::/64\n",
        ] {
            assert!(
                out.contains(want),
                "generated ignoreip missing {:?}:\n{}",
                want,
                out
            );
        }
        assert!(
            !out.contains("[caddy-probe-h1]"),
            "empty jail section was emitted:\n{}",
            out
        );
    }

    #[test]
    fn render_live_policy_is_atomic_rollback() {
        let dump = b"table inet caddy_abuseguard_intel {\n\tchain input {\n\t\tip saddr @block4 drop\n\t}\n}\n";
        let got = render_live_policy(dump);
        let want_prefix =
            b"add table inet caddy_abuseguard_intel\ndelete table inet caddy_abuseguard_intel\n"
                .to_vec();
        let want = [want_prefix, dump.to_vec()].concat();
        assert_eq!(
            got,
            want,
            "live rollback is not one add/delete/table transaction:\n{}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn render_applied_matches_snapshot_schema() {
        use time::format_description::well_known::Rfc3339;
        let now: OffsetDateTime = OffsetDateTime::parse("2026-11-14T01:02:03Z", &Rfc3339).unwrap();
        let got = String::from_utf8(render_applied(now, 7, 3)).unwrap();
        let want = "{\"applied_at\":\"2026-11-14T01:02:03Z\",\"intel_entries\":7,\"whitelist_entries\":3,\"source\":\"policy-apply\"}\n";
        assert_eq!(got, want);
    }

    // A missing feed is allowed only while no prior policy exists. The disk
    // snapshot is authoritative evidence of a previous non-empty policy.
    #[test]
    fn snapshot_has_elements_contract() {
        assert!(!snapshot_has_elements(b""), "empty data must not count");
        assert!(snapshot_has_elements(
            b"table inet caddy_abuseguard_intel {\n\tset block4 {\n\t\ttype ipv4_addr\n\t\telements = {\n\t\t\t192.0.2.1\n\t\t}\n\t}\n}\n"
        ));
        assert!(!snapshot_has_elements(
            b"table inet caddy_abuseguard_intel {\n\tset block4 {\n\t\ttype ipv4_addr\n\t}\n}\n"
        ));
    }

    #[test]
    fn ignoreip_token_parser_is_strict() {
        assert!(valid_ignoreip_token("1.2.3.4"));
        assert!(valid_ignoreip_token("2001:db8::/32"));
        assert!(valid_ignoreip_token("dnstls_host-1.exe"));
        assert!(
            !valid_ignoreip_token("192.0.2.8 203.0.113.1"),
            "space inside"
        );
        assert!(!valid_ignoreip_token("'a';touch /tmp/x"), "shell metachar");
        assert!(!valid_ignoreip_token(""), "empty");
    }

    #[test]
    fn ipv4_pattern_scan() {
        assert!(contains_ipv4_pattern(b"elements = { 192.0.2.1 }"));
        assert!(contains_ipv4_pattern(b"\t\t\t10.0.0.1\n"));
        assert!(!contains_ipv4_pattern(b"empty set"));
        // substring semantics like the Go regexp: a match may start mid-digit
        assert!(
            contains_ipv4_pattern(b"1234.1.1.1"),
            "matches '234.1.1.1' inside, like Go"
        );
    }

    #[cfg(unix)]
    #[test]
    fn f2b_mirror_excludes_generated_policy_and_preserves_relative_parent() {
        let dir = crate::testutil::TempDir::new("f2b-mirror");
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let etc_like = dir.join("etc-like");
        let f2b_root = etc_like.join("fail2ban");
        let jail_d = f2b_root.join("jail.d");
        std::fs::create_dir_all(&jail_d).unwrap();
        std::fs::write(dir.join("upper.local"), b"[sshd]\nignoreip = 192.0.2.66\n").unwrap();
        std::fs::write(
            etc_like.join("native.local"),
            b"[sshd]\nignoreip = 192.0.2.77\n",
        )
        .unwrap();
        std::fs::write(f2b_root.join("jail.conf"), b"[DEFAULT]\n").unwrap();
        std::fs::write(
            jail_d.join("custom.local"),
            b"[sshd]\nignoreip = 192.0.2.88\n",
        )
        .unwrap();
        let generated = jail_d.join("zzz-caddy-abuseguard-policy.local");
        std::fs::write(&generated, b"[sshd]\nignoreip = 192.0.2.1\n").unwrap();

        let mirror = build_f2b_mirror(
            jail_d.to_str().unwrap(),
            generated.to_str().unwrap(),
            work.to_str().unwrap(),
        )
        .unwrap();

        // Mirror stays strictly inside `work` (compatible with ProtectSystem=strict).
        assert!(mirror.starts_with(&work));
        // Live generated policy file must never be removed or modified.
        assert_eq!(
            std::fs::read(&generated).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.1\n"
        );
        // Ancestor mirroring preserves `../` and `../../` relative include targets.
        assert_eq!(
            std::fs::read(mirror.join("../native.local")).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.77\n"
        );
        assert_eq!(
            std::fs::read(mirror.join("../../upper.local")).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.66\n"
        );
        // Mirror exposes the rest of the config while omitting the generated file.
        assert_eq!(
            std::fs::read(mirror.join("jail.conf")).unwrap(),
            b"[DEFAULT]\n"
        );
        assert_eq!(
            std::fs::read(mirror.join("jail.d").join("custom.local")).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.88\n"
        );
        assert!(!mirror
            .join("jail.d")
            .join("zzz-caddy-abuseguard-policy.local")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn f2b_mirror_follows_symlinked_config_dir_for_relative_includes() {
        use std::os::unix::fs::symlink;

        let dir = crate::testutil::TempDir::new("f2b-symlink-mirror");
        let work = dir.join("work");
        let etc_like = dir.join("etc-like");
        let srv_cfg = dir.join("srv").join("config");
        let real_root = srv_cfg.join("fail2ban");
        let real_jail_d = real_root.join("jail.d");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&etc_like).unwrap();
        std::fs::create_dir_all(&real_jail_d).unwrap();
        std::fs::write(
            dir.join("srv").join("upper.local"),
            b"[caddy-rate-local]\nignoreip = 192.0.2.66\n",
        )
        .unwrap();
        std::fs::write(
            srv_cfg.join("native.local"),
            b"[sshd]\nignoreip = 192.0.2.77\n",
        )
        .unwrap();
        std::fs::write(real_root.join("jail.conf"), b"[DEFAULT]\n").unwrap();
        let generated = real_jail_d.join("zzz-caddy-abuseguard-policy.local");
        std::fs::write(&generated, b"[sshd]\nignoreip = 192.0.2.99\n").unwrap();

        // /etc/fail2ban -> /srv/config/fail2ban
        let link_root = etc_like.join("fail2ban");
        symlink(&real_root, &link_root).unwrap();
        let link_jail_d = link_root.join("jail.d");
        let link_policy = link_jail_d.join("zzz-caddy-abuseguard-policy.local");

        let mirror = build_f2b_mirror(
            link_jail_d.to_str().unwrap(),
            link_policy.to_str().unwrap(),
            work.to_str().unwrap(),
        )
        .unwrap();

        assert!(mirror.starts_with(&work));
        // `../native.local` must resolve against `/srv/config`, not `etc-like`.
        assert_eq!(
            std::fs::read(mirror.join("../native.local")).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.77\n"
        );
        assert_eq!(
            std::fs::read(mirror.join("../../upper.local")).unwrap(),
            b"[caddy-rate-local]\nignoreip = 192.0.2.66\n"
        );
        assert!(!mirror
            .join("jail.d")
            .join("zzz-caddy-abuseguard-policy.local")
            .exists());
        assert_eq!(
            std::fs::read(&generated).unwrap(),
            b"[sshd]\nignoreip = 192.0.2.99\n"
        );
    }
}
