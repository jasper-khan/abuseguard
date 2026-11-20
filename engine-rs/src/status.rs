// The panel's status snapshot: bounded, read-only probes and a versioned JSON
// shape. Null means unavailable; absence is only false after a successful read.
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const DEFAULT_STATE_DIR: &str = "/var/lib/caddy-abuseguard";
const CONFIG_LIMIT: usize = 256 * 1024;
const METADATA_LIMIT: usize = 64 * 1024;
const FEED_LIMIT: u64 = 8 * 1024 * 1024;
const JAILS: [&str; 4] = ["caddy-rate-local", "caddy-probe-h1", "caddy-probe-h2", "sshd"];

#[derive(Serialize)]
struct Snapshot<'a> {
    schema_version: u8,
    version: &'a str,
    backend: Option<&'static str>,
    services: Services,
    timers: Timers,
    firewall_table_present: Option<bool>,
    intel_table_present: Option<bool>,
    jails: BTreeMap<&'static str, Option<u64>>,
    banned_total: Option<u64>,
    reporting_enabled: Option<bool>,
    report_key_present: Option<bool>,
    intel: Intel,
}

#[derive(Serialize)]
struct Services {
    proxy: Option<&'static str>,
    fail2ban: Option<&'static str>,
}

#[derive(Serialize, Default)]
struct Unit {
    state: Option<&'static str>,
    next: Option<String>,
}

#[derive(Serialize)]
struct Timers {
    report: Unit,
    sync: Unit,
    certbot: Unit,
}

#[derive(Serialize)]
struct Intel {
    local_entries: Option<u64>,
    synced_age_hours: Option<u64>,
    applied_entries: Option<u64>,
    applied_age_hours: Option<u64>,
}

pub fn run(args: &[String], version: &str) {
    if !matches!(args, [flag] if flag == "--json") {
        crate::util::logf("usage: caddy-abuseguard status --json");
        std::process::exit(2);
    }
    let config_path = crate::config::config_path();
    let stats = collect(
        Path::new(&config_path),
        version,
        OffsetDateTime::now_utc(),
        &run_probe,
    );
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &stats).is_err() || stdout.write_all(b"\n").is_err() {
        crate::util::logf("status: could not write JSON");
        std::process::exit(1);
    }
}

fn collect<'a>(
    config_path: &Path,
    version: &'a str,
    now: OffsetDateTime,
    query: &(impl Fn(&str, &[&str]) -> Option<Vec<u8>> + Sync),
) -> Snapshot<'a> {
    let conf_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let backend = read_small(&conf_dir.join("web-server"), 128)
        .and_then(|b| match std::str::from_utf8(&b).ok()?.trim() {
            "caddy" => Some("caddy"),
            "nginx" => Some("nginx"),
            _ => None,
        });
    let config = read_json(config_path, CONFIG_LIMIT);
    let state_dir = config
        .as_ref()
        .and_then(|v| v["paths"]["state_dir"].as_str())
        .filter(|p| !p.is_empty())
        .unwrap_or(DEFAULT_STATE_DIR);
    let state = Path::new(state_dir);
    let applied = read_json(&conf_dir.join("intel-applied.json"), METADATA_LIMIT);
    let synced = read_json(&state.join("intel-last-sync.txt"), METADATA_LIMIT);
    let intel = Intel {
        local_entries: line_count(&state.join("intel.txt")),
        synced_age_hours: synced.as_ref().and_then(|v| age_hours(&v["generated_at"], now)),
        applied_entries: applied.as_ref().and_then(|v| v["intel_entries"].as_u64()),
        applied_age_hours: applied.as_ref().and_then(|v| age_hours(&v["applied_at"], now)),
    };
    let reporting = config.as_ref().map(|v| &v["abuseipdb"]);
    let reporting_enabled = reporting.and_then(|v| v["enabled"].as_bool());
    let report_key_present = reporting
        .and_then(|v| v["report_key_file"].as_str())
        .and_then(|p| key_present(Path::new(p)));

    // These fixed probes are independent. Parallel calls keep slow or unavailable
    // local daemons from multiplying the per-command timeout on panel refresh.
    let (services, timers, tables, jails) = std::thread::scope(|s| {
        let proxy = s.spawn(|| match backend {
            Some("caddy") => query_unit(query, "caddy.service", false).state,
            Some("nginx") => query_unit(query, "nginx.service", false).state,
            _ => None,
        });
        let fail2ban = s.spawn(|| query_unit(query, "fail2ban.service", false).state);
        let report = s.spawn(|| query_unit(query, "caddy-abuseguard-report.timer", true));
        let sync = s.spawn(|| query_unit(query, "caddy-abuseguard-sync.timer", true));
        let certbot = s.spawn(|| match backend {
            Some("nginx") => query_unit(query, "certbot.timer", true),
            _ => Unit::default(),
        });
        let table_probe =
            s.spawn(|| query("nft", &["-j", "list", "tables"]).and_then(|b| parse_tables(&b)));
        let jail_probes = JAILS.map(|jail| {
            s.spawn(move || query("fail2ban-client", &["status", jail]).and_then(|b| parse_banned(&b)))
        });
        let services = Services {
            proxy: proxy.join().unwrap_or_default(),
            fail2ban: fail2ban.join().unwrap_or_default(),
        };
        let timers = Timers {
            report: report.join().unwrap_or_default(),
            sync: sync.join().unwrap_or_default(),
            certbot: certbot.join().unwrap_or_default(),
        };
        let jails: BTreeMap<_, _> = JAILS
            .into_iter()
            .zip(jail_probes.into_iter().map(|p| p.join().unwrap_or_default()))
            .collect();
        (services, timers, table_probe.join().unwrap_or_default(), jails)
    });
    let banned_total = jails
        .values()
        .try_fold(0u64, |total, count| total.checked_add((*count)?));
    Snapshot {
        schema_version: 1,
        version,
        backend,
        services,
        timers,
        firewall_table_present: tables.map(|t| t.0),
        intel_table_present: tables.map(|t| t.1),
        jails,
        banned_total,
        reporting_enabled,
        report_key_present,
        intel,
    }
}

fn query_unit(
    query: &impl Fn(&str, &[&str]) -> Option<Vec<u8>>,
    unit: &str,
    timer: bool,
) -> Unit {
    let mut args = vec!["show", "--property=LoadState", "--property=ActiveState"];
    if timer {
        args.push("--property=NextElapseUSecRealtime");
    }
    args.extend(["--", unit]);
    query("systemctl", &args).map_or_else(Unit::default, |b| parse_unit(&b))
}

fn parse_unit(b: &[u8]) -> Unit {
    let Ok(s) = std::str::from_utf8(b) else {
        return Unit::default();
    };
    let property = |key| s.lines().filter_map(|line| line.strip_prefix(key)).next();
    if !matches!(property("LoadState="), Some("loaded" | "masked")) {
        return Unit::default();
    }
    let state = match property("ActiveState=") {
        Some("active") => Some("active"),
        Some("inactive") => Some("inactive"),
        Some("failed") => Some("failed"),
        Some("activating") => Some("activating"),
        Some("deactivating") => Some("deactivating"),
        Some("reloading") => Some("reloading"),
        Some("maintenance") => Some("maintenance"),
        Some("refreshing") => Some("refreshing"),
        _ => None,
    };
    let next = if state == Some("active") {
        property("NextElapseUSecRealtime=")
            .filter(|s| {
                !matches!(*s, "" | "0" | "n/a")
                    && s.len() <= 128
                    && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            })
            .map(str::to_string)
    } else {
        None
    };
    Unit { state, next }
}

fn parse_banned(b: &[u8]) -> Option<u64> {
    let mut lines = std::str::from_utf8(b).ok()?.lines().filter_map(|line| {
        line.trim_start_matches(|c: char| {
            matches!(c, '|' | '`' | '-' | '├' | '└' | '─' | '│') || c.is_whitespace()
        })
        .strip_prefix("Currently banned:")
    });
    let number = lines.next()?.trim();
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) || lines.next().is_some() {
        return None;
    }
    number.parse().ok()
}

fn parse_tables(b: &[u8]) -> Option<(bool, bool)> {
    let v: Value = serde_json::from_slice(b).ok()?;
    let rows = v["nftables"].as_array()?;
    let (mut firewall, mut intel) = (false, false);
    for row in rows {
        if row.get("metainfo").is_some() {
            continue;
        }
        let info = row.get("table")?;
        if info.get("family")?.as_str()? != "inet" {
            continue;
        }
        match info.get("name")?.as_str()? {
            "caddy_abuseguard" => firewall = true,
            "caddy_abuseguard_intel" => intel = true,
            _ => {}
        }
    }
    Some((firewall, intel))
}

fn age_hours(value: &Value, now: OffsetDateTime) -> Option<u64> {
    let at = OffsetDateTime::parse(value.as_str()?, &Rfc3339).ok()?;
    (at <= now).then_some((now - at).whole_hours() as u64)
}

// Do not block on service-owned state paths replaced with FIFOs, or read
// symlink targets when the panel is querying status with elevated privileges.
fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32);
    }
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a regular file"));
    }
    Ok(file)
}

fn read_small(path: &Path, limit: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    open_regular(path).ok()?.take(limit as u64 + 1).read_to_end(&mut buf).ok()?;
    (buf.len() <= limit).then_some(buf)
}

fn read_json(path: &Path, limit: usize) -> Option<Value> {
    serde_json::from_slice(&read_small(path, limit)?).ok()
}

fn key_present(path: &Path) -> Option<bool> {
    if path.as_os_str().is_empty() {
        return Some(false);
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.is_file() => Some(md.len() > 0),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
        _ => None,
    }
}

fn line_count(path: &Path) -> Option<u64> {
    let mut file = open_regular(path).ok()?.take(FEED_LIMIT + 1);
    let mut bytes = 0u64;
    let mut lines = 0u64;
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            return Some(lines);
        }
        bytes += n as u64;
        if bytes > FEED_LIMIT {
            return None;
        }
        lines += buf[..n].iter().filter(|b| **b == b'\n').count() as u64;
    }
}

fn run_probe(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    bounded_output(program, args, Duration::from_millis(1500))
}

#[cfg(not(target_os = "linux"))]
fn bounded_output(_program: &str, _args: &[&str], _timeout: Duration) -> Option<Vec<u8>> {
    None
}

#[cfg(target_os = "linux")]
fn bounded_output(program: &str, args: &[&str], timeout: Duration) -> Option<Vec<u8>> {
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    use rustix::process::{kill_process_group, Pid, Signal};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    const MAX_OUTPUT: usize = 256 * 1024;
    let start = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("SYSTEMD_COLORS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .process_group(0)
        .spawn()
        .ok()?;
    let mut reaped = false;
    let result = (|| {
        let mut stdout = child.stdout.take()?;
        fcntl_setfl(&stdout, fcntl_getfl(&stdout).ok()? | OFlags::NONBLOCK).ok()?;
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut eof = false;
        loop {
            if start.elapsed() >= timeout {
                return None;
            }
            if let Some(code) = child.try_wait().ok()? {
                reaped = true;
                if !code.success() {
                    return None;
                }
                if eof {
                    return Some(out);
                }
            }
            if !eof {
                match stdout.read(&mut buf) {
                    Ok(0) => eof = true,
                    Ok(n) if n <= MAX_OUTPUT - out.len() => {
                        out.extend_from_slice(&buf[..n]);
                        continue;
                    }
                    Ok(_) => return None,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return None,
                }
            }
            std::thread::sleep(Duration::from_millis(8));
        }
    })();
    if result.is_none() && !reaped {
        // Only the process group started for this query, never the service.
        // Never signal a PID after reaping it; the OS can reuse it.
        let _ = kill_process_group(Pid::from_child(&child), Signal::Kill);
        // Avoid a blocking wait on the status path, even on an unhealthy host.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use serde_json::json;

    #[test]
    fn parses_service_results_without_turning_unknown_into_inactive() {
        let info = parse_unit(b"ActiveState=active\nLoadState=loaded\nNextElapseUSecRealtime=Mon 2026-01-12 06:15:00 UTC\n");
        assert_eq!(info.state, Some("active"));
        assert_eq!(info.next.as_deref(), Some("Mon 2026-01-12 06:15:00 UTC"));
        assert_eq!(parse_unit(b"LoadState=loaded\nActiveState=failed\n").state, Some("failed"));
        assert_eq!(parse_unit(b"LoadState=not-found\nActiveState=inactive\n").state, None);
        assert_eq!(parse_unit(b"ActiveState=active\n").state, None);
        assert_eq!(parse_unit(b"LoadState=loaded\nActiveState=active\nNextElapseUSecRealtime=n/a\n").next, None);
        assert_eq!(parse_unit(b"LoadState=loaded\nActiveState=active\nNextElapseUSecRealtime=\x1b[31m\n").next, None);
    }

    #[test]
    fn parses_nft_table_presence_without_matching_other_families() {
        let both = br#"{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"caddy_abuseguard"}},{"table":{"family":"inet","name":"caddy_abuseguard_intel"}}]}"#;
        let other = br#"{"nftables":[{"table":{"family":"ip","name":"caddy_abuseguard"}},{"table":{"family":"inet","name":"other"}}]}"#;
        assert_eq!(parse_tables(both), Some((true, true)));
        assert_eq!(parse_tables(other), Some((false, false)));
        assert_eq!(parse_tables(br#"{"nftables":[]}"#), Some((false, false)));
        assert_eq!(parse_tables(br#"{}"#), None);
    }

    #[test]
    fn jail_count_requires_unambiguous_number() {
        assert_eq!(parse_banned(b"|  `- Currently banned:\t0\n"), Some(0));
        assert_eq!(parse_banned(b"   |- Currently banned:\t7\n"), Some(7));
        assert_eq!(parse_banned(b"   |- Currently banned:\t7 / 10\n"), None);
        assert_eq!(parse_banned(b"Currently banned: 1\nCurrently banned: 2\n"), None);
        assert_eq!(parse_banned(b"Total banned: 8"), None);
    }

    #[test]
    fn collects_typed_status_and_never_loads_or_serializes_key_content() {
        let dir = TempDir::new("status-fixture");
        let root = dir.path();
        let config = root.join("config.json");
        let key = root.join("report-secret-file");
        std::fs::write(&key, "test-report-secret").unwrap();
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({
                "paths": {"state_dir": root},
                "abuseipdb": {"enabled": true, "report_key_file": key},
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("web-server"), "nginx\n").unwrap();
        std::fs::write(root.join("intel.txt"), "192.0.2.1\n192.0.2.2\n").unwrap();
        std::fs::write(root.join("intel-last-sync.txt"), br#"{"generated_at":"2026-01-12T00:00:00Z"}"#).unwrap();
        std::fs::write(root.join("intel-applied.json"), br#"{"applied_at":"2026-01-12T01:30:00Z","intel_entries":1}"#).unwrap();
        let now = OffsetDateTime::parse("2026-01-12T03:00:00Z", &Rfc3339).unwrap();
        let query = |program: &str, args: &[&str]| match (program, args.last().copied()) {
            ("systemctl", Some("nginx.service" | "fail2ban.service")) =>
                Some(b"LoadState=loaded\nActiveState=active\n".to_vec()),
            ("systemctl", Some("certbot.timer")) =>
                Some(b"LoadState=loaded\nActiveState=inactive\n".to_vec()),
            ("nft", _) => Some(br#"{"nftables":[{"table":{"family":"inet","name":"caddy_abuseguard"}}]}"#.to_vec()),
            ("fail2ban-client", Some("caddy-probe-h2")) => None,
            ("fail2ban-client", _) => Some(b"Currently banned: 5\n".to_vec()),
            _ => None,
        };
        let snapshot = collect(&config, "0.7.1", now, &query);
        let value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["backend"], "nginx");
        assert_eq!(value["services"]["proxy"], "active");
        assert_eq!(value["timers"]["certbot"]["state"], "inactive");
        assert!(value["timers"]["report"]["state"].is_null());
        assert_eq!(value["firewall_table_present"], true);
        assert_eq!(value["intel_table_present"], false);
        assert_eq!(value["jails"]["sshd"], 5);
        assert!(value["jails"]["caddy-probe-h2"].is_null());
        assert!(value["banned_total"].is_null());
        assert_eq!(value["reporting_enabled"], true);
        assert_eq!(value["report_key_present"], true);
        assert_eq!(
            value["intel"],
            json!({"local_entries":2,"synced_age_hours":3,"applied_entries":1,"applied_age_hours":1})
        );
        assert!(!value.to_string().contains("report-secret"));

        let all_readable = |program: &str, args: &[&str]| {
            if program == "fail2ban-client" {
                Some(b"Currently banned: 5\n".to_vec())
            } else {
                query(program, args)
            }
        };
        assert_eq!(
            collect(&config, "0.7.1", now, &all_readable).banned_total,
            Some(20)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subprocess_probe_has_timeout_and_requires_success() {
        use std::time::Instant;

        assert_eq!(
            bounded_output("/bin/echo", &["fixture"], Duration::from_secs(1)),
            Some(b"fixture\n".to_vec())
        );
        assert_eq!(bounded_output("/bin/false", &[], Duration::from_secs(1)), None);
        let start = Instant::now();
        assert_eq!(bounded_output("/bin/sleep", &["10"], Duration::from_millis(30)), None);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
