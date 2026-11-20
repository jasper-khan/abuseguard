// report.rs — AbuseIPDB flush: dedupe, daily cap, checkpoint, send.
use crate::allow::load_allowlist;
use crate::config::{read_key_file, Config};
use crate::filelock::acquire_file_lock;
use crate::http::send_report;
use crate::queue::{
    processing_queue_path, read_queue_file, report_lock_path, rotate_queue, write_queue_file,
    QueueRead, ReportItem,
};
use crate::util::{logf, mkdir_mode, parse_duration_default, save_json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// format_utc_rfc3339 prints whole-second RFC3339 (Go Format(time.RFC3339)).
pub fn format_utc_rfc3339(t: OffsetDateTime) -> String {
    let t = trunc_to_second(t);
    t.format(&Rfc3339).unwrap_or_default()
}

fn trunc_to_second(t: OffsetDateTime) -> OffsetDateTime {
    let d = t.date();
    let tm = time::Time::from_hms(t.hour(), t.minute(), t.second()).unwrap_or(time::Time::MIDNIGHT);
    d.with_time(tm).assume_utc()
}

pub const DATE_FMT: &[time::format_description::FormatItem<'static>] =
    time::macros::format_description!("[year]-[month]-[day]");

// stamp_format prints "2006-01-02T15:04:05Z" (policy renders).
pub fn stamp_format(t: OffsetDateTime) -> String {
    trunc_to_second(t).format(&Rfc3339).unwrap_or_default()
}

pub type DedupeEntries = BTreeMap<String, String>;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct DedupeStore {
    // None mirrors Go's nil map (missing "entries" in a checkpoint).
    #[serde(default)]
    pub entries: Option<DedupeEntries>,
}

fn get_entries_mut(d: &mut DedupeStore) -> &mut DedupeEntries {
    d.entries.get_or_insert_with(BTreeMap::new)
}

pub fn dedupe_key(ip: &str) -> String {
    let sum = Sha256::digest(ip.as_bytes());
    hex::encode(sum)
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct DailyUsage {
    #[serde(default)]
    pub day: String,
    #[serde(default)]
    pub attempts: i64,
}

pub const REPORT_CHECKPOINT_VERSION: i64 = 1;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ReportCheckpoint {
    #[serde(default)]
    pub version: i64,
    // Go writes a nil slice as null after the last item in a batch is sent.
    #[serde(default, deserialize_with = "deserialize_remaining")]
    pub remaining: Vec<String>,
    #[serde(default)]
    pub dedupe: DedupeStore,
    #[serde(default)]
    pub daily: DailyUsage,
}

fn deserialize_remaining<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    Ok(Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default())
}

pub fn dedupe_path(c: &Config) -> String {
    format!("{}/.dedupe.json", c.paths.reports_dir)
}
pub fn daily_path(c: &Config) -> String {
    format!("{}/.daily-usage.json", c.paths.reports_dir)
}
pub fn checkpoint_path(c: &Config) -> String {
    format!("{}/.report-checkpoint.json", c.paths.reports_dir)
}

pub fn validate_dedupe(d: &mut DedupeStore) -> Result<(), String> {
    get_entries_mut(d);
    let mut bad = String::new();
    if let Some(entries) = &d.entries {
        for ts in entries.values() {
            if OffsetDateTime::parse(ts, &Rfc3339).is_err() && bad.is_empty() {
                bad = format!("invalid dedupe timestamp {:?}", ts);
            }
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(bad)
    }
}

pub fn validate_daily(u: &DailyUsage) -> Result<(), String> {
    if !u.day.is_empty() && time::Date::parse(&u.day, DATE_FMT).is_err() {
        return Err(format!("invalid daily usage day {:?}", u.day));
    }
    if u.attempts < 0 {
        return Err(format!("invalid daily usage attempts {}", u.attempts));
    }
    Ok(())
}

pub fn load_dedupe(c: &Config) -> Result<DedupeStore, String> {
    let mut d = DedupeStore::default();
    let b = match std::fs::read(dedupe_path(c)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let _ = get_entries_mut(&mut d);
            return Ok(d);
        }
        Err(e) => return Err(e.to_string()),
    };
    d = serde_json::from_slice(&b).map_err(|e| e.to_string())?;
    validate_dedupe(&mut d)?;
    Ok(d)
}

// load_daily takes the clock seam: resetDailyFor uses reportNow in Go.
pub fn load_daily(c: &Config, now: OffsetDateTime) -> Result<DailyUsage, String> {
    let mut u = DailyUsage::default();
    match std::fs::read(daily_path(c)) {
        Ok(b) => u = serde_json::from_slice(&b).map_err(|e| e.to_string())?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    validate_daily(&u)?;
    reset_daily_for(now, &mut u);
    Ok(u)
}

pub fn reset_daily_for(now: OffsetDateTime, u: &mut DailyUsage) {
    let today = trunc_to_second(now)
        .date()
        .format(DATE_FMT)
        .unwrap_or_default();
    if u.day != today {
        u.day = today;
        u.attempts = 0;
    }
}

// apply_checkpoint is idempotent. The checkpoint stays in place until the
// queue, dedupe state, and daily usage have all reached the same snapshot.
pub fn apply_checkpoint(c: &Config, checkpoint: &mut ReportCheckpoint) -> Result<(), String> {
    if checkpoint.version != REPORT_CHECKPOINT_VERSION {
        return Err(format!(
            "unsupported checkpoint version {}",
            checkpoint.version
        ));
    }
    if checkpoint.dedupe.entries.is_none() || checkpoint.daily.day.is_empty() {
        return Err("incomplete checkpoint state".to_string());
    }
    validate_dedupe(&mut checkpoint.dedupe)?;
    validate_daily(&checkpoint.daily)?;
    write_queue_file(&processing_queue_path(c), &checkpoint.remaining)
        .map_err(|e| format!("save queue batch: {}", e))?;
    save_json(&dedupe_path(c), &checkpoint.dedupe, 0o640)
        .map_err(|e| format!("save dedupe state: {}", e))?;
    save_json(&daily_path(c), &checkpoint.daily, 0o640)
        .map_err(|e| format!("save daily usage: {}", e))?;
    match std::fs::remove_file(checkpoint_path(c)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove checkpoint: {}", e)),
    }
}

pub fn persist_checkpoint(
    c: &Config,
    remaining: &[String],
    dedupe: &DedupeStore,
    daily: &DailyUsage,
) -> Result<(), String> {
    let mut checkpoint = ReportCheckpoint {
        version: REPORT_CHECKPOINT_VERSION,
        remaining: remaining.to_vec(),
        dedupe: dedupe.clone(),
        daily: daily.clone(),
    };
    save_json(&checkpoint_path(c), &checkpoint, 0o640)
        .map_err(|e| format!("save checkpoint: {}", e))?;
    apply_checkpoint(c, &mut checkpoint)
}

pub fn recover_checkpoint(c: &Config) -> Result<(), String> {
    let b = match std::fs::read(checkpoint_path(c)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let mut checkpoint: ReportCheckpoint =
        serde_json::from_slice(&b).map_err(|e| format!("decode checkpoint: {}", e))?;
    apply_checkpoint(c, &mut checkpoint)
}

// cmd_report_send_auto flushes the queue to AbuseIPDB with dedupe + daily cap.
// clock replaces Go's reportNow seam; production passes now_utc().
pub fn cmd_report_send_auto(c: &Config, clock: &dyn Fn() -> OffsetDateTime) -> i32 {
    if !c.abuseipdb.enabled {
        logf("report: reporting disabled; nothing sent");
        return 0;
    }
    let key = read_key_file(&c.abuseipdb.report_key_file);
    if key.is_empty() {
        logf("report: no API key configured; skipping (queue kept)");
        return 0;
    }
    if let Err(e) = mkdir_mode(&c.paths.reports_dir, 0o750) {
        logf(&format!("report: mkdir reports dir: {}", e));
        return 1;
    }
    let _report_lock = match acquire_file_lock(&report_lock_path(c)) {
        Ok(l) => l,
        Err(e) => {
            logf(&format!("report: lock reporter: {}", e));
            return 1;
        }
    };
    if let Err(e) = recover_checkpoint(c) {
        logf(&format!("report: recover confirmed progress: {}", e));
        return 1;
    }

    let batch = match rotate_queue(c) {
        Ok(b) => b,
        Err(e) => {
            logf(&format!("report: rotate queue: {}", e));
            return 1;
        }
    };
    let batch = match batch {
        None => return 0,
        Some(b) => b,
    };
    let qr = match read_queue_file(&batch) {
        Ok(qr) => qr,
        Err(e) => {
            logf(&format!("report: read queue: {}", e));
            return 1;
        }
    };
    let QueueRead {
        items,
        raw,
        malformed,
    } = qr;
    if items.is_empty() {
        if let Err(e) = write_queue_file(&batch, &[]) {
            logf(&format!("report: remove empty queue batch: {}", e));
            return 1;
        }
        if malformed > 0 {
            return 1;
        }
        return 0;
    }
    let allow = match load_allowlist(&c.allowlist_file) {
        Ok(a) => a,
        Err(e) => {
            logf(&format!("report: load allowlist: {}; nothing sent", e));
            return 1;
        }
    };
    let mut dedupe = match load_dedupe(c) {
        Ok(d) => d,
        Err(e) => {
            logf(&format!("report: load dedupe state: {}; nothing sent", e));
            return 1;
        }
    };
    let mut daily = match load_daily(c, clock()) {
        Ok(d) => d,
        Err(e) => {
            logf(&format!("report: load daily usage: {}; nothing sent", e));
            return 1;
        }
    };
    let window = parse_duration_default(&c.abuseipdb.dedupe_window, Duration::from_secs(15 * 60));
    let mut daily_cap = c.abuseipdb.daily_report_cap;
    if daily_cap <= 0 {
        daily_cap = 1000;
    }
    let mut remaining: Vec<String> = Vec::new();
    let (mut sent, mut skipped, mut deferred, mut dropped) = (0i64, 0i64, 0i64, 0i64);
    let mut had_error = malformed > 0;

    let mut abort: Option<i32> = None;
    for (idx, it) in items.iter().enumerate() {
        let item_now = clock();
        reset_daily_for(item_now, &mut daily);
        if !crate::queue::is_reportable_ip(&it.ip) {
            logf(&format!(
                "report: invalid or non-public IP {:?} discarded",
                it.ip
            ));
            dropped += 1;
            had_error = true;
            continue;
        }
        let (cats, comment) = match report_details(it) {
            Ok(cc) => cc,
            Err(e) => {
                logf(&format!(
                    "report: invalid queued item for {} discarded: {}",
                    it.ip, e
                ));
                dropped += 1;
                had_error = true;
                continue;
            }
        };
        if allow.contains(&it.ip) {
            skipped += 1;
            continue; // never report a whitelisted IP
        }
        let k = dedupe_key(&it.ip);
        let mut deferred_now = false;
        if let Some(entries) = &dedupe.entries {
            if let Some(ts) = entries.get(&k) {
                if let Ok(t) = OffsetDateTime::parse(ts, &Rfc3339) {
                    if (item_now - t) < window {
                        remaining.push(raw[idx].clone());
                        deferred += 1;
                        deferred_now = true;
                    }
                }
            }
        }
        if deferred_now {
            continue; // AbuseIPDB accepts the same IP again after the window
        }
        if daily.attempts >= daily_cap {
            remaining.extend_from_slice(&raw[idx..]);
            logf(&format!(
                "report: daily cap {} reached; {} item(s) requeued",
                daily_cap,
                raw[idx..].len()
            ));
            break;
        }
        let sent_result = send_report(
            &c.abuseipdb.report_url,
            &key,
            &it.ip,
            &cats,
            &comment,
            &it.ts,
        );
        let status = match sent_result {
            Ok(s) => s,
            Err(e) => {
                remaining.extend_from_slice(&raw[idx..]);
                logf(&format!(
                    "report: send failed for {}: {}; {} item(s) requeued",
                    it.ip,
                    e,
                    raw[idx..].len()
                ));
                had_error = true;
                break;
            }
        };
        if status == 400 || status == 422 {
            logf(&format!(
                "report: AbuseIPDB rejected {} with HTTP {}; record discarded",
                it.ip, status
            ));
            dropped += 1;
            had_error = true;
            continue;
        }
        if !(200..300).contains(&status) {
            remaining.extend_from_slice(&raw[idx..]);
            logf(&format!(
                "report: AbuseIPDB returned HTTP {} for {}; {} item(s) requeued",
                status,
                it.ip,
                raw[idx..].len()
            ));
            had_error = true;
            break;
        }
        let reported_at = clock();
        reset_daily_for(reported_at, &mut daily);
        get_entries_mut(&mut dedupe).insert(k, format_utc_rfc3339(reported_at));
        daily.attempts += 1;
        sent += 1;
        let mut checkpoint_remaining = Vec::with_capacity(remaining.len() + raw.len() - idx - 1);
        checkpoint_remaining.extend_from_slice(&remaining);
        checkpoint_remaining.extend_from_slice(&raw[idx + 1..]);
        if let Err(e) = persist_checkpoint(c, &checkpoint_remaining, &dedupe, &daily) {
            logf(&format!(
                "report: persist confirmed report for {}: {}",
                it.ip, e
            ));
            abort = Some(1);
            break;
        }
    }
    if let Some(rc) = abort {
        return rc;
    }

    // prune dedupe entries older than 48h
    let prune_now = clock();
    get_entries_mut(&mut dedupe).retain(|_, ts| {
        !(match OffsetDateTime::parse(ts, &Rfc3339) {
            Ok(t) => (prune_now - t) > Duration::from_secs(48 * 3600),
            Err(_) => false,
        })
    });

    if let Err(e) = write_queue_file(&batch, &remaining) {
        logf(&format!("report: save queue batch: {}", e));
        return 1;
    }
    if let Err(e) = save_json(&dedupe_path(c), &dedupe, 0o640) {
        logf(&format!("report: save dedupe state: {}", e));
        return 1;
    }
    if let Err(e) = save_json(&daily_path(c), &daily, 0o640) {
        logf(&format!("report: save daily usage: {}", e));
        return 1;
    }
    logf(&format!(
        "report: sent={} skipped={} deferred={} dropped={} requeued={} (daily={}/{})",
        sent,
        skipped,
        deferred,
        dropped,
        remaining.len(),
        daily.attempts,
        daily_cap
    ));
    if had_error {
        return 1;
    }
    0
}

pub fn report_window_label(raw: &str) -> Result<String, String> {
    let window = raw.trim();
    let d = match crate::util::go_duration_parse(window) {
        Ok(d) => Some(d),
        Err(_) => crate::util::go_duration_parse(&format!("{}s", window)).ok(),
    };
    let d = match d {
        Some(d) if !d.is_zero() => d,
        _ => return Err(format!("invalid detection window {:?}", raw)),
    };
    let units = [
        (Duration::from_secs(3600), "hour"),
        (Duration::from_secs(60), "minute"),
        (Duration::from_secs(1), "second"),
    ];
    for (unit, name) in &units {
        let d_ns = d.as_nanos();
        let u_ns = unit.as_nanos();
        if d_ns % u_ns == 0 {
            let n = d_ns / u_ns;
            let name = if n != 1 {
                format!("{}s", name)
            } else {
                name.to_string()
            };
            return Ok(format!("{} {}", n, name));
        }
    }
    Ok(crate::util::format_go_duration(d))
}

// report_details keeps each supported profile, category, and privacy-safe
// reason in one closed map. Categories and comments are never caller supplied.
pub fn report_details(it: &ReportItem) -> Result<(String, String), String> {
    if it.profile != "web-probe" && it.profile != "ssh-bruteforce" {
        return Err(format!("unsupported profile {:?}", it.profile));
    }
    if it.failures <= 0 {
        return Err(format!("invalid failure count {}", it.failures));
    }
    let window = report_window_label(&it.window)?;
    let transport = it.transport.trim().to_string();
    match it.profile.as_str() {
        "web-probe" => {
            let transport = match transport.as_str() {
                "HTTP/1.1" => transport.clone(),
                "HTTP/2" | "HTTP/2.0" => "HTTP/2".to_string(),
                _ => {
                    return Err(format!(
                        "unsupported transport {:?} for profile {:?}",
                        it.transport, it.profile
                    ))
                }
            };
            let comment = format!(
                "Repeated probing of common sensitive web application paths: {} requests within {} over {}.",
                it.failures, window, transport
            );
            Ok(("21".to_string(), comment))
        }
        "ssh-bruteforce" => {
            if transport != "SSH" {
                return Err(format!(
                    "unsupported transport {:?} for profile {:?}",
                    it.transport, it.profile
                ));
            }
            let comment = format!(
                "Repeated SSH authentication failures: {} failed attempts within {}.",
                it.failures, window
            );
            Ok(("18,22".to_string(), comment))
        }
        _ => Err(format!("unsupported profile {:?}", it.profile)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::queue::{
        cmd_enqueue, is_reportable_ip, processing_queue_path, queue_path, ReportItem,
    };
    use crate::testutil::{start_server, FixedClock, HttpResp, TempDir};
    use std::sync::Arc;

    struct Env {
        c: Config,
        key_file: std::path::PathBuf,
        allowlist_file: std::path::PathBuf,
        _dir: TempDir, // keeps the temp dir alive for the test's lifetime
    }

    fn new_env() -> Env {
        let dir = TempDir::new("report");
        let key_file = dir.join("key");
        let allowlist_file = dir.join("whitelist");
        std::fs::write(&key_file, b"test-key\n").unwrap();
        std::fs::write(&allowlist_file, b"").unwrap();
        let mut c = Config::default();
        c.allowlist_file = allowlist_file.to_string_lossy().to_string();
        c.paths.state_dir = dir.path().to_string_lossy().to_string();
        c.paths.reports_dir = dir.join("reports").to_string_lossy().to_string();
        c.abuseipdb.enabled = true;
        c.abuseipdb.report_key_file = key_file.to_string_lossy().to_string();
        c.abuseipdb.daily_report_cap = 1000;
        c.abuseipdb.dedupe_window = "15m".to_string();
        Env {
            c,
            key_file,
            allowlist_file,
            _dir: dir,
        }
    }

    fn valid_probe(ip: &str) -> ReportItem {
        ReportItem {
            ip: ip.to_string(),
            profile: "web-probe".to_string(),
            failures: 5,
            window: "10m".to_string(),
            transport: "HTTP/1.1".to_string(),
            ..ReportItem::default()
        }
    }

    fn valid_ssh(ip: &str) -> ReportItem {
        ReportItem {
            ip: ip.to_string(),
            profile: "ssh-bruteforce".to_string(),
            failures: 5,
            window: "600".to_string(),
            transport: "SSH".to_string(),
            ..ReportItem::default()
        }
    }

    fn real_now() -> impl Fn() -> OffsetDateTime {
        || now_utc()
    }

    fn path_exists(p: &str) -> bool {
        std::path::Path::new(p).exists()
    }

    #[test]
    fn enqueue_skips_when_reporting_unavailable() {
        // disabled
        let mut env = new_env();
        env.c.abuseipdb.enabled = false;
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        assert!(!path_exists(&queue_path(&env.c)));

        // missing key
        let env = new_env();
        std::fs::write(&env.key_file, b"").unwrap();
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        assert!(!path_exists(&queue_path(&env.c)));
    }

    #[test]
    fn enqueue_rejects_invalid_report_data() {
        let cases = vec![
            ReportItem {
                ip: "192.0.2.10".into(),
                profile: "web-rate".into(),
                failures: 120,
                window: "60s".into(),
                transport: "HTTP".into(),
                ..ReportItem::default()
            },
            valid_probe("not-an-ip"),
            valid_probe("10.0.0.1"),
        ];
        for item in cases {
            let env = new_env();
            assert!(
                cmd_enqueue(&env.c, item, &real_now()) != 0,
                "enqueue accepted invalid report data"
            );
            assert!(!path_exists(&queue_path(&env.c)));
        }
    }

    #[test]
    fn report_details_exact_output() {
        let cases = [
            (
                "HTTP/1.1 web probe",
                valid_probe("192.0.2.10"),
                "21",
                "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/1.1.",
            ),
            (
                "HTTP/2 web probe",
                ReportItem {
                    ip: "192.0.2.10".into(),
                    profile: "web-probe".into(),
                    failures: 5,
                    window: "10m".into(),
                    transport: "HTTP/2.0".into(),
                    ..ReportItem::default()
                },
                "21",
                "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/2.",
            ),
            (
                "SSH brute force",
                valid_ssh("192.0.2.10"),
                "18,22",
                "Repeated SSH authentication failures: 5 failed attempts within 10 minutes.",
            ),
        ];
        for (name, item, cats, comment) in cases {
            let (got_cats, got_comment) =
                report_details(&item).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert_eq!(got_cats, cats, "{}", name);
            assert_eq!(got_comment, comment, "{}", name);
            let lower = got_comment.to_lowercase();
            for private in [
                "abuseguard",
                "192.0.2.10",
                ".env",
                ".git",
                "phpmyadmin",
                "username",
                "host=",
                "uri=",
                "header=",
                "authorization",
                "cookie",
            ] {
                assert!(
                    !lower.contains(private),
                    "{}: comment contains {}",
                    name,
                    private
                );
            }
        }
    }

    #[test]
    fn report_details_rejects_invalid_evidence() {
        let cases = vec![
            (
                "unsupported profile",
                ReportItem {
                    profile: "web-rate".into(),
                    failures: 120,
                    window: "60s".into(),
                    transport: "HTTP/1.1".into(),
                    ..ReportItem::default()
                },
            ),
            (
                "zero failures",
                ReportItem {
                    profile: "web-probe".into(),
                    failures: 0,
                    window: "10m".into(),
                    transport: "HTTP/1.1".into(),
                    ..ReportItem::default()
                },
            ),
            (
                "zero window",
                ReportItem {
                    profile: "web-probe".into(),
                    failures: 5,
                    window: "0".into(),
                    transport: "HTTP/1.1".into(),
                    ..ReportItem::default()
                },
            ),
            (
                "invalid window",
                ReportItem {
                    profile: "web-probe".into(),
                    failures: 5,
                    window: "ten minutes".into(),
                    transport: "HTTP/1.1".into(),
                    ..ReportItem::default()
                },
            ),
            (
                "unsupported HTTP transport",
                ReportItem {
                    profile: "web-probe".into(),
                    failures: 5,
                    window: "10m".into(),
                    transport: "HTTP/3.0".into(),
                    ..ReportItem::default()
                },
            ),
            (
                "unsupported SSH transport",
                ReportItem {
                    profile: "ssh-bruteforce".into(),
                    failures: 5,
                    window: "600".into(),
                    transport: "HTTP/1.1".into(),
                    ..ReportItem::default()
                },
            ),
        ];
        for (name, item) in cases {
            assert!(
                report_details(&item).is_err(),
                "reportDetails accepted invalid evidence: {}",
                name
            );
        }
    }

    #[test]
    fn reporter_stops_when_allowlist_cannot_be_read() {
        let env = new_env();
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        std::fs::remove_file(&env.allowlist_file).unwrap();
        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();
        assert_ne!(cmd_report_send_auto(&c, &real_now()), 0);
        assert_eq!(server.count(), 0);
        assert!(path_exists(&processing_queue_path(&c)));
    }

    #[test]
    fn reporter_never_sends_whitelisted_ip() {
        let env = new_env();
        std::fs::write(&env.allowlist_file, b"192.0.2.10 # trusted\n").unwrap();
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();
        assert_eq!(cmd_report_send_auto(&c, &real_now()), 0);
        assert_eq!(server.count(), 0);
        assert!(!path_exists(&processing_queue_path(&c)));
    }

    #[test]
    fn reporter_stops_on_corrupt_state() {
        for name in ["dedupe", "daily"] {
            let env = new_env();
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
                0
            );
            let corrupt = match name {
                "dedupe" => dedupe_path(&env.c),
                _ => daily_path(&env.c),
            };
            std::fs::write(&corrupt, b"{").unwrap();
            let server = start_server(|_| HttpResp::ok());
            let mut c = env.c.clone();
            c.abuseipdb.report_url = server.url.clone();
            assert_ne!(cmd_report_send_auto(&c, &real_now()), 0, "{}", name);
            assert_eq!(server.count(), 0);
            assert!(path_exists(&processing_queue_path(&c)), "{}", name);
        }
    }

    #[test]
    fn reporter_returns_failure_when_state_cannot_be_saved() {
        for name in ["dedupe", "daily usage"] {
            let env = new_env();
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
                0
            );
            let state_path = match name {
                "dedupe" => dedupe_path(&env.c),
                _ => daily_path(&env.c),
            };
            let server = start_server(move |_| {
                let _ = std::fs::create_dir(&state_path); // fails the state save within the reporter
                HttpResp::ok()
            });
            let mut c = env.c.clone();
            c.abuseipdb.report_url = server.url.clone();
            assert_ne!(
                cmd_report_send_auto(&c, &real_now()),
                0,
                "reporter hid a state save failure ({})",
                name
            );
        }
    }

    #[test]
    fn reporter_drops_record_errors_and_continues() {
        for status in [400u16, 422] {
            let env = new_env();
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
                0
            );
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.11"), &real_now()),
                0
            );
            let server = start_server(move |r| {
                assert_eq!(r.form("categories"), "21");
                if r.n == 1 {
                    HttpResp::status(status)
                } else {
                    HttpResp::ok()
                }
            });
            let mut c = env.c.clone();
            c.abuseipdb.report_url = server.url.clone();
            assert_ne!(cmd_report_send_auto(&c, &real_now()), 0, "HTTP {}", status);
            assert_eq!(server.count(), 2, "HTTP {}", status);
            assert!(!path_exists(&processing_queue_path(&c)));
        }
    }

    #[test]
    fn reporter_requeues_retryable_errors() {
        for status in [401u16, 403, 429, 500] {
            let env = new_env();
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
                0
            );
            assert_eq!(
                cmd_enqueue(&env.c, valid_probe("192.0.2.11"), &real_now()),
                0
            );
            let server = start_server(move |_| HttpResp::status(status));
            let mut c = env.c.clone();
            c.abuseipdb.report_url = server.url.clone();
            assert_ne!(cmd_report_send_auto(&c, &real_now()), 0, "HTTP {}", status);
            assert_eq!(server.count(), 1, "HTTP {}", status);
            let qr = read_queue_file(&processing_queue_path(&c)).unwrap();
            assert_eq!(qr.malformed, 0, "HTTP {}", status);
            assert_eq!(qr.items.len(), 2, "HTTP {}", status);
        }
    }

    #[test]
    fn reporter_persists_confirmed_progress_before_next_request() {
        let env = new_env();
        let first_ip = "192.0.2.10";
        let second_ip = "192.0.2.11";
        for ip in [first_ip, second_ip] {
            assert_eq!(cmd_enqueue(&env.c, valid_probe(ip), &real_now()), 0);
        }

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let server = start_server(move |r| {
            if r.n == 1 {
                HttpResp::ok()
            } else {
                // Hold the second request, then kill the connection: the
                // reporter must not treat the uncertain response as confirmed.
                let mut resp = HttpResp::ok();
                resp.wait = release_rx.lock().unwrap().take();
                resp.abort = true;
                resp
            }
        });
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();

        let c2 = c.clone();
        let t = std::thread::spawn(move || cmd_report_send_auto(&c2, &real_now()));

        // wait for the second request to be accepted (captured at accept time)
        loop {
            if server.count() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let qr = read_queue_file(&processing_queue_path(&c)).unwrap();
        assert_eq!(qr.malformed, 0);
        assert_eq!(qr.items.len(), 1);
        assert_eq!(qr.items[0].ip, second_ip);
        let dedupe = load_dedupe(&c).unwrap();
        assert!(dedupe.entries.unwrap().contains_key(&dedupe_key(first_ip)));
        let daily = load_daily(&c, now_utc()).unwrap();
        assert_eq!(daily.attempts, 1);

        drop(release_tx); // release the parked handler -> connection aborts

        let rc = t.join().unwrap();
        assert_ne!(rc, 0, "reporter hid the uncertain second response");

        let retry_server = start_server(|_| HttpResp::ok());
        let mut c3 = c.clone();
        c3.abuseipdb.report_url = retry_server.url.clone();
        assert_eq!(cmd_report_send_auto(&c3, &real_now()), 0);
        let retried: Vec<String> = retry_server
            .requests()
            .iter()
            .map(|r| r.form("ip"))
            .collect();
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0], second_ip);
    }

    #[test]
    fn reporter_recovers_checkpoint_before_sending() {
        let env = new_env();
        let first_ip = "192.0.2.10";
        let second_ip = "192.0.2.11";
        for ip in [first_ip, second_ip] {
            assert_eq!(cmd_enqueue(&env.c, valid_probe(ip), &real_now()), 0);
        }
        let batch = crate::queue::rotate_queue(&env.c).unwrap().unwrap();
        let qr = read_queue_file(&batch).unwrap();
        assert_eq!(qr.malformed, 0);
        assert_eq!(qr.raw.len(), 2);
        let now = now_utc();
        let mut dedupe = DedupeStore::default();
        let _ = get_entries_mut(&mut dedupe);
        dedupe
            .entries
            .as_mut()
            .unwrap()
            .insert(dedupe_key(first_ip), format_utc_rfc3339(now));
        let checkpoint = ReportCheckpoint {
            version: REPORT_CHECKPOINT_VERSION,
            remaining: vec![qr.raw[1].clone()],
            dedupe,
            daily: DailyUsage {
                day: format_utc_day(now),
                attempts: 1,
            },
        };
        save_json(&checkpoint_path(&env.c), &checkpoint, 0o640).unwrap();

        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();
        assert_eq!(cmd_report_send_auto(&c, &real_now()), 0);
        let reported: Vec<String> = server.requests().iter().map(|r| r.form("ip")).collect();
        assert_eq!(reported.len(), 1);
        assert_eq!(reported[0], second_ip);
        assert!(!path_exists(&checkpoint_path(&c)));
        let daily = load_daily(&c, now_utc()).unwrap();
        assert_eq!(daily.attempts, 2);
    }

    #[test]
    fn reporter_recovers_go_checkpoint_after_last_confirmed_report() {
        let env = new_env();
        let now = OffsetDateTime::parse("2026-11-14T10:00:00Z", &Rfc3339).unwrap();
        let clock = || now;
        let first_ip = "192.0.2.10";
        let second_ip = "192.0.2.11";
        assert_eq!(cmd_enqueue(&env.c, valid_probe(first_ip), &clock), 0);
        assert!(crate::queue::rotate_queue(&env.c).unwrap().is_some());
        assert_eq!(cmd_enqueue(&env.c, valid_probe(second_ip), &clock), 0);

        // Match Go's reportCheckpoint encoding when its remaining slice is nil:
        // the POST succeeded and the checkpoint was written, but it has not
        // yet been applied to the old processing queue.
        let checkpoint = serde_json::json!({
            "version": 1,
            "remaining": null,
            "dedupe": { "entries": { (dedupe_key(first_ip)): "2026-11-14T10:00:00Z" } },
            "daily": { "day": "2026-11-14", "attempts": 1 }
        });
        save_json(&checkpoint_path(&env.c), &checkpoint, 0o640).unwrap();

        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();
        assert_eq!(cmd_report_send_auto(&c, &clock), 0);
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].form("ip"), second_ip);
        assert!(!path_exists(&checkpoint_path(&c)));
        assert!(!path_exists(&processing_queue_path(&c)));
        assert_eq!(load_daily(&c, now).unwrap().attempts, 2);
        assert!(load_dedupe(&c)
            .unwrap()
            .entries
            .unwrap()
            .contains_key(&dedupe_key(first_ip)));
    }

    #[test]
    fn checkpoint_remaining_defaults_without_loosening_array_validation() {
        for checkpoint in [r#"{}"#, r#"{"remaining":null}"#, r#"{"remaining":[]}"#] {
            let checkpoint: ReportCheckpoint = serde_json::from_str(checkpoint).unwrap();
            assert!(checkpoint.remaining.is_empty());
            // Go's json.Unmarshal also accepts the empty array Rust emits.
            let serialized = serde_json::to_value(&checkpoint).unwrap();
            assert_eq!(serialized["remaining"], serde_json::json!([]));
        }
        let checkpoint: ReportCheckpoint = serde_json::from_str(r#"{"remaining":["line"]}"#).unwrap();
        assert_eq!(checkpoint.remaining, ["line"]);
        for checkpoint in [r#"{"remaining":"line"}"#, r#"{"remaining":[42]}"#] {
            assert!(serde_json::from_str::<ReportCheckpoint>(checkpoint).is_err());
        }
    }

    fn format_utc_day(t: OffsetDateTime) -> String {
        trunc_to_second(t)
            .date()
            .format(DATE_FMT)
            .unwrap_or_default()
    }

    #[test]
    fn reporter_stops_on_invalid_checkpoint() {
        let env = new_env();
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        std::fs::write(checkpoint_path(&env.c), b"{\"version\":1}").unwrap();
        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();

        assert_ne!(cmd_report_send_auto(&c, &real_now()), 0);
        assert_eq!(server.count(), 0);
        let qr = read_queue_file(&queue_path(&c)).unwrap();
        assert_eq!(qr.malformed, 0);
        assert_eq!(qr.items.len(), 1);
        assert!(
            path_exists(&checkpoint_path(&c)),
            "invalid checkpoint was not retained"
        );
    }

    #[test]
    fn reporter_defers_second_profile_for_same_ip() {
        let env = new_env();
        let ip = "192.0.2.10";
        assert_eq!(cmd_enqueue(&env.c, valid_probe(ip), &real_now()), 0);
        assert_eq!(cmd_enqueue(&env.c, valid_ssh(ip), &real_now()), 0);

        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();

        assert_eq!(cmd_report_send_auto(&c, &real_now()), 0);
        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].form("categories"), "21");
        assert_eq!(
            reqs[0].form("comment"),
            "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/1.1."
        );
        let qr = read_queue_file(&processing_queue_path(&c)).unwrap();
        assert_eq!(qr.malformed, 0);
        assert_eq!(qr.items.len(), 1);
        assert_eq!(qr.items[0].profile, "ssh-bruteforce");

        // expire the dedupe window: the SSH item is forwarded on the next run
        let mut dedupe = DedupeStore::default();
        let _ = get_entries_mut(&mut dedupe);
        dedupe.entries.as_mut().unwrap().insert(
            dedupe_key(ip),
            format_utc_rfc3339(now_utc() - time::Duration::minutes(16)),
        );
        save_json(&dedupe_path(&c), &dedupe, 0o640).unwrap();
        assert_eq!(cmd_report_send_auto(&c, &real_now()), 0);
        let reqs = server.requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[1].form("categories"), "18,22");
        assert_eq!(
            reqs[1].form("comment"),
            "Repeated SSH authentication failures: 5 failed attempts within 10 minutes."
        );
        assert!(!path_exists(&processing_queue_path(&c)));
    }

    #[test]
    fn reporter_uses_current_time_for_each_dedupe_decision() {
        let env = new_env();
        let first_ip = "192.0.2.10";
        let second_ip = "192.0.2.11";
        for ip in [first_ip, second_ip, first_ip] {
            assert_eq!(cmd_enqueue(&env.c, valid_probe(ip), &real_now()), 0);
        }

        let start_secs = 1767225600i64; // 2026-01-01T00:00:00Z
        let mut dedupe = DedupeStore::default();
        let _ = get_entries_mut(&mut dedupe);
        dedupe.entries.as_mut().unwrap().insert(
            dedupe_key(first_ip),
            format_utc_rfc3339(fixed_time_secs(start_secs - 30)),
        );
        save_json(&dedupe_path(&env.c), &dedupe, 0o640).unwrap();
        let mut c = env.c.clone();
        c.abuseipdb.dedupe_window = "1m".to_string();

        let clock = FixedClock::new(start_secs);
        let server = start_server({
            let clock = clock.clone();
            move |r| {
                if r.n == 1 {
                    // The first request is deliberately slow. Its success
                    // timestamp must advance, and the later duplicate must be
                    // checked against it.
                    clock.add(70);
                } else {
                    clock.add(1);
                }
                HttpResp::ok()
            }
        });
        c.abuseipdb.report_url = server.url.clone();

        let now_fn = clock.now_fn();
        assert_eq!(cmd_report_send_auto(&c, &now_fn), 0);
        let reported: Vec<String> = server.requests().iter().map(|r| r.form("ip")).collect();
        assert_eq!(reported, vec![second_ip.to_string(), first_ip.to_string()]);

        let dedupe = load_dedupe(&c).unwrap().entries.unwrap();
        assert_eq!(
            dedupe[&dedupe_key(second_ip)],
            format_utc_rfc3339(fixed_time_secs(start_secs + 70))
        );
        assert_eq!(
            dedupe[&dedupe_key(first_ip)],
            format_utc_rfc3339(fixed_time_secs(start_secs + 71))
        );
        let daily = load_daily(&c, fixed_time_secs(start_secs + 71)).unwrap();
        assert_eq!(daily.attempts, 2);
    }

    fn fixed_time_secs(unix: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(unix).expect("valid unix timestamp")
    }

    #[test]
    fn reporter_resets_daily_usage_after_utc_midnight() {
        let env = new_env();
        let ip = "192.0.2.10";
        assert_eq!(cmd_enqueue(&env.c, valid_probe(ip), &real_now()), 0);
        // 2026-01-01T23:59:59Z = 1767225600 (00:00:00) + 86399
        let start_secs = 1767311999i64;
        let daily = DailyUsage {
            day: "2026-01-01".to_string(),
            attempts: 1,
        };
        save_json(&daily_path(&env.c), &daily, 0o640).unwrap();

        let clock = FixedClock::new(start_secs);
        let server = start_server({
            let clock = clock.clone();
            move |_| {
                // The request starts on the old UTC day and succeeds after midnight.
                clock.add(2);
                HttpResp::ok()
            }
        });
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();
        c.abuseipdb.daily_report_cap = 2;

        let now_fn = clock.now_fn();
        assert_eq!(cmd_report_send_auto(&c, &now_fn), 0);
        let daily = load_daily(&c, fixed_time_secs(start_secs + 2)).unwrap();
        assert_eq!(daily.day, "2026-01-02");
        assert_eq!(daily.attempts, 1);
        let dedupe = load_dedupe(&c).unwrap().entries.unwrap();
        assert_eq!(
            dedupe[&dedupe_key(ip)],
            format_utc_rfc3339(fixed_time_secs(start_secs + 2))
        );
    }

    #[test]
    fn reporter_logs_and_drops_malformed_queue_line() {
        let env = new_env();
        assert_eq!(
            cmd_enqueue(&env.c, valid_probe("192.0.2.10"), &real_now()),
            0
        );
        let valid = std::fs::read(queue_path(&env.c)).unwrap();
        let mut data = b"not-json\n".to_vec();
        data.extend_from_slice(&valid);
        std::fs::write(queue_path(&env.c), data).unwrap();

        let server = start_server(|_| HttpResp::ok());
        let mut c = env.c.clone();
        c.abuseipdb.report_url = server.url.clone();

        assert_ne!(cmd_report_send_auto(&c, &real_now()), 0);
        assert_eq!(server.count(), 1);
        assert!(!path_exists(&processing_queue_path(&c)));
    }

    #[test]
    fn is_reportable_ip_matches_netip_semantics() {
        assert!(is_reportable_ip("192.0.2.1")); // doc range is reportable
        assert!(is_reportable_ip("2001:db8::1"));
        assert!(!is_reportable_ip("10.0.0.1"));
        assert!(!is_reportable_ip("192.168.1.1"));
        assert!(!is_reportable_ip("127.0.0.1"));
        assert!(!is_reportable_ip("not-an-ip"));
        assert!(!is_reportable_ip("255.255.255.255"));
        assert!(!is_reportable_ip("224.0.0.1"));
    }

    #[test]
    fn window_label_formats_like_go() {
        assert_eq!(report_window_label("10m").unwrap(), "10 minutes");
        assert_eq!(report_window_label("600").unwrap(), "10 minutes");
        assert_eq!(report_window_label("1h").unwrap(), "1 hour");
        assert_eq!(report_window_label("90s").unwrap(), "90 seconds");
        assert!(report_window_label("0").is_err());
        assert!(report_window_label("ten minutes").is_err());
    }
}
