// queue.rs — report queue: enqueue, rotate, read/write.
use crate::allow::canon_ip;
use crate::config::Config;
use crate::filelock::acquire_file_lock;
use crate::report::report_details;
use crate::util::{logf, mkdir_mode, open_append_mode};
use std::net::IpAddr;

#[derive(serde::Serialize, serde::Deserialize, Default, Debug, Clone)]
pub struct ReportItem {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub profile: String,
    #[serde(default)]
    pub failures: i64,
    #[serde(default)]
    pub window: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub port: i64,
    #[serde(default)]
    pub ts: String,
}

pub fn queue_path(c: &Config) -> String {
    format!("{}/queue.jsonl", c.paths.reports_dir)
}
pub fn processing_queue_path(c: &Config) -> String {
    format!("{}/queue.processing.jsonl", c.paths.reports_dir)
}
pub fn queue_lock_path(c: &Config) -> String {
    format!("{}/.queue.lock", c.paths.reports_dir)
}
pub fn report_lock_path(c: &Config) -> String {
    format!("{}/.report.lock", c.paths.reports_dir)
}

// is_reportable_ip mirrors netip.ParseAddr + IsGlobalUnicast + !IsPrivate.
// canonical: v4-mapped input is unmapped first (netip semantics for the
// checks; see allow.rs note), link-local is NOT excluded (Go parity).
pub fn is_reportable_ip(s: &str) -> bool {
    let ip = match canon_ip(s.trim()) {
        Some(ip) => ip,
        None => return false,
    };
    fn is_global_unicast(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let o = u32::from(*v4);
                // !unspecified !loopback !multicast !broadcast
                !(o == 0 || (o >> 24) == 127 || (o >> 28) == 0xE || o == 0xFFFF_FFFF)
            }
            IpAddr::V6(v6) => {
                let seg = u128::from(*v6);
                !(seg == 0
                    || seg == 1 // ::1 loopback
                    || (seg >> 120) == 0xFF) // ff00::/8 multicast
            }
        }
    }
    fn is_private(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4.is_private(), // 10/8, 172.16/12, 192.168/16
            IpAddr::V6(v6) => {
                // RFC 4193 fc00::/7
                (u128::from(*v6) >> 121) == 0b1111_110
            }
        }
    }
    is_global_unicast(&ip) && !is_private(&ip)
}

// cmd_enqueue appends one offender to the report queue (fail2ban action).
pub fn cmd_enqueue(c: &Config, it: ReportItem, get_now: &dyn Fn() -> time::OffsetDateTime) -> i32 {
    if !c.abuseipdb.enabled {
        logf("enqueue: reporting disabled; skipped");
        return 0;
    }
    if crate::config::read_key_file(&c.abuseipdb.report_key_file).is_empty() {
        logf("enqueue: no API key configured; skipped");
        return 0;
    }
    if !is_reportable_ip(&it.ip) {
        logf(&format!("enqueue: invalid or non-public IP {:?}", it.ip));
        return 1;
    }
    if let Err(e) = report_details(&it) {
        logf(&format!("enqueue: {}", e));
        return 1;
    }
    let mut it = it;
    if it.ts.is_empty() {
        it.ts = crate::report::format_utc_rfc3339(get_now());
    }
    if let Err(e) = mkdir_mode(&c.paths.reports_dir, 0o750) {
        logf(&format!("enqueue: mkdir reports dir: {}", e));
        return 1;
    }
    // encode cannot fail for this struct; Go's encode error branch is dead
    let mut line = serde_json::to_vec(&it).unwrap_or_default();
    line.push(b'\n');
    let _lock = match acquire_file_lock(&queue_lock_path(c)) {
        Ok(l) => l,
        Err(e) => {
            logf(&format!("enqueue: lock queue: {}", e));
            return 1;
        }
    };
    let mut f = match open_append_mode(&queue_path(c), 0o640) {
        Ok(f) => f,
        Err(e) => {
            logf(&format!("enqueue: open queue: {}", e));
            return 1;
        }
    };
    {
        use std::io::Write;
        if let Err(e) = f.write_all(&line).and_then(|()| f.flush()) {
            logf(&format!("enqueue: write queue: {}", e));
            return 1;
        }
    }
    0
}

// rotate_queue atomically detaches the current queue for one reporter. New
// enqueues immediately continue in a fresh queue.jsonl. A batch left by a
// crashed reporter is resumed before a new batch is rotated.
pub fn rotate_queue(c: &Config) -> Result<Option<String>, String> {
    let _lock = acquire_file_lock(&queue_lock_path(c))?;
    let processing = processing_queue_path(c);
    if std::path::Path::new(&processing).exists() {
        return Ok(Some(processing));
    }
    match std::fs::rename(queue_path(c), &processing) {
        Ok(()) => Ok(Some(processing)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub struct QueueRead {
    pub items: Vec<ReportItem>,
    pub raw: Vec<String>,
    pub malformed: usize,
}

// read_queue_file returns parsed items plus raw JSONL lines (index-aligned).
// Malformed lines are logged and discarded so they cannot block later records.
pub fn read_queue_file(path: &str) -> Result<QueueRead, String> {
    let b = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(QueueRead {
                items: Vec::new(),
                raw: Vec::new(),
                malformed: 0,
            })
        }
        Err(e) => return Err(e.to_string()),
    };
    let mut items = Vec::new();
    let mut raw = Vec::new();
    let mut malformed = 0usize;
    for (line_no, line) in String::from_utf8_lossy(&b).split('\n').enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<ReportItem>(line) {
            Ok(it) => {
                items.push(it);
                raw.push(line.to_string());
            }
            Err(e) => {
                malformed += 1;
                logf(&format!(
                    "report: malformed queue line {} discarded: {}",
                    line_no + 1,
                    e
                ));
            }
        }
    }
    Ok(QueueRead {
        items,
        raw,
        malformed,
    })
}

// write_queue_file replaces path with raw_lines (or removes it when empty).
pub fn write_queue_file(path: &str, raw_lines: &[String]) -> Result<(), String> {
    if raw_lines.is_empty() {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        };
    }
    let mut data = raw_lines.join("\n");
    data.push('\n');
    crate::util::write_file_atomic(path, data.as_bytes(), 0o640)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::report::now_utc;
    use crate::testutil::{start_server, HttpResp, TempDir};
    use std::sync::Arc;

    fn env() -> (Config, TempDir) {
        let dir = TempDir::new("queue");
        std::fs::write(dir.join("key"), b"test-key\n").unwrap();
        std::fs::write(dir.join("whitelist"), b"").unwrap();
        let mut c = Config::default();
        c.allowlist_file = dir.join("whitelist").to_string_lossy().to_string();
        c.paths.state_dir = dir.path().to_string_lossy().to_string();
        c.paths.reports_dir = dir.join("reports").to_string_lossy().to_string();
        c.abuseipdb.enabled = true;
        c.abuseipdb.report_key_file = dir.join("key").to_string_lossy().to_string();
        c.abuseipdb.daily_report_cap = 1000;
        c.abuseipdb.dedupe_window = "15m".to_string();
        (c, dir)
    }

    fn probe(ip: &str) -> ReportItem {
        ReportItem {
            ip: ip.to_string(),
            profile: "web-probe".to_string(),
            failures: 5,
            window: "10m".to_string(),
            transport: "HTTP/1.1".to_string(),
            ..ReportItem::default()
        }
    }

    // TestConcurrentEnqueueSurvivesReportFlush: enqueue during a blocked report
    // flush must land in the fresh queue, never in the processing batch.
    #[test]
    fn concurrent_enqueue_survives_report_flush() {
        let (c, _dir) = env();
        let now = || now_utc();
        assert_eq!(cmd_enqueue(&c, probe("192.0.2.1"), &now), 0);

        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(Some(release_rx)));
        let started = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let server = start_server(move |r| {
            let _ = r;
            // release the starter on the first request, park until released
            if let Some(tx) = started.lock().unwrap().take() {
                let _ = tx.send(());
            }
            let mut resp = HttpResp::ok();
            resp.wait = release_rx.lock().unwrap().take();
            resp
        });
        let mut c2 = c.clone();
        c2.abuseipdb.report_url = server.url.clone();

        let c3 = c2.clone();
        let report_done = Arc::new(std::sync::Mutex::new(None));
        let done2 = Arc::clone(&report_done);
        std::thread::spawn(move || {
            let rc = crate::report::cmd_report_send_auto(&c3, &now);
            *done2.lock().unwrap() = Some(rc);
        });

        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("report did not reach test endpoint");

        assert_eq!(cmd_enqueue(&c, probe("192.0.2.2"), &now), 0);
        drop(release_tx);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let done = report_done.lock().unwrap().is_some();
            if done || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let rc = report_done.lock().unwrap().take();
        assert_eq!(rc, Some(0), "report returned failure");

        let qr = read_queue_file(&queue_path(&c)).unwrap();
        assert_eq!(qr.malformed, 0);
        assert_eq!(qr.items.len(), 1);
        assert_eq!(qr.items[0].ip, "192.0.2.2");
        assert!(!std::path::Path::new(&processing_queue_path(&c)).exists());
    }
}
