// intel.rs — blocklist sync + canonical validation.
use crate::allow::canon_ip;
use crate::config::{read_key_file, Config};
use crate::http::http_get;
use crate::util::{logf, save_json, write_file_atomic};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read};
use std::net::Ipv4Addr;
use time::OffsetDateTime;

#[derive(serde::Serialize, Debug, Clone)]
pub struct IntelMeta {
    pub generated_at: String,
    pub source_commit: String,
    pub ipv4: i64,
    pub ipv6: i64,
    pub sha256: String,
}

pub fn intel_txt_path(c: &Config) -> String {
    format!("{}/intel.txt", c.paths.state_dir)
}
pub fn intel_meta_path(c: &Config) -> String {
    format!("{}/intel-last-sync.txt", c.paths.state_dir)
}

// format_intel returns canonical bare-IPv4 lines from intel.txt.
// The whole file is validated before returning so corrupt, empty, IPv6 or
// out-of-bounds stored data can never reach the kernel as a partial set. Only
// a missing file is treated as an empty list (root bootstraps before sync).
pub fn format_intel(c: &Config) -> Result<Vec<u8>, String> {
    const MAX_LINE_BYTES: u64 = 1024 * 1024;
    // The HTTP source is limited to 32 MiB; permit extra room for local files.
    const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

    let file = match std::fs::File::open(intel_txt_path(c)) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut reader = BufReader::new(file);
    let mut line_buf = Vec::new();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut entries = 0i64;
    let mut bytes = 0u64;
    loop {
        line_buf.clear();
        let n = reader
            .by_ref()
            .take(MAX_LINE_BYTES + 1)
            .read_until(b'\n', &mut line_buf)
            .map_err(crate::util::io_err)? as u64;
        if n == 0 {
            break;
        }
        if n > MAX_LINE_BYTES {
            return Err("intel entry exceeds maximum line length".to_string());
        }
        bytes += n;
        if bytes > MAX_FILE_BYTES {
            return Err("intel list exceeds maximum file size".to_string());
        }
        let line = line_buf.strip_suffix(b"\n").unwrap_or(&line_buf);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = std::str::from_utf8(line).map_err(crate::util::io_err)?;
        let ip = line
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("invalid intel entry {:?}", line))?;
        entries += 1;
        if c.intel.max_entries > 0 && entries > c.intel.max_entries {
            return Err(format!(
                "intel list has {} entries (> max {})",
                entries, c.intel.max_entries
            ));
        }
        if seen.insert(ip) {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
    }
    if entries == 0 {
        return Err("intel list is empty".to_string());
    }
    if entries < c.intel.min_entries {
        return Err(format!(
            "intel list has {} entries (< min {})",
            entries, c.intel.min_entries
        ));
    }
    Ok(out)
}

fn resolve_commit(c: &Config, token: &str) -> Result<String, String> {
    if !c.intel.source_url.contains("{commit}") || c.intel.commit_url.is_empty() {
        return Ok(String::new());
    }
    let body = http_get(&c.intel.commit_url, token)?;
    #[derive(serde::Deserialize)]
    struct ShaOnly {
        #[serde(default)]
        sha: String,
    }
    if let Ok(commits) = serde_json::from_slice::<Vec<ShaOnly>>(&body) {
        if let Some(first) = commits.first() {
            if !first.sha.is_empty() {
                return Ok(first.sha.clone());
            }
        }
    }
    if let Ok(one) = serde_json::from_slice::<ShaOnly>(&body) {
        if !one.sha.is_empty() {
            return Ok(one.sha);
        }
    }
    Err(format!(
        "could not parse commit sha from {}",
        c.intel.commit_url
    ))
}

// short mirrors short(): first 12 chars.
fn short(s: &str) -> String {
    if s.len() > 12 {
        s[..12].to_string()
    } else {
        s.to_string()
    }
}

// cmd_sync_intel refreshes intel.txt from the configured blocklist source.
pub fn cmd_sync_intel(c: &Config, get_now: &dyn Fn() -> OffsetDateTime) -> i32 {
    let token = read_key_file(&c.intel.token_file);
    let commit = match resolve_commit(c, &token) {
        Ok(cc) => cc,
        Err(e) => {
            logf(&format!(
                "sync-intel: resolve commit failed: {} (keeping existing list)",
                e
            ));
            return 0;
        }
    };
    let src = c.intel.source_url.replace("{commit}", &commit);
    let body = match http_get(&src, "") {
        Ok(b) => b,
        Err(e) => {
            logf(&format!(
                "sync-intel: download failed: {} (keeping existing list)",
                e
            ));
            return 0;
        }
    };
    let mut out = String::new();
    let mut count = 0i64;
    for line in String::from_utf8_lossy(&body).split('\n') {
        let mut line = line.strip_suffix('\r').unwrap_or(line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(i) = line.find(|ch| ch == ' ' || ch == '\t') {
            line = &line[..i]; // some lists append country/comment columns
        }
        // Store only the canonical dotted-quad form: the intel validators
        // reject anything else, so a non-canonical source spelling must never
        // block later native policy updates.
        let canonical = match canon_ip(line) {
            Some(std::net::IpAddr::V4(v4)) => Some(v4.to_string()),
            _ => None,
        };
        match canonical {
            Some(s) => {
                out.push_str(&s);
                out.push('\n');
                count += 1;
            }
            None => continue,
        }
    }
    if count < c.intel.min_entries {
        logf(&format!(
            "sync-intel: only {} entries (< min {}); keeping existing list",
            count, c.intel.min_entries
        ));
        return 0;
    }
    if c.intel.max_entries > 0 && count > c.intel.max_entries {
        logf(&format!(
            "sync-intel: {} entries (> max {}); refusing to load; keeping existing list",
            count, c.intel.max_entries
        ));
        return 0;
    }
    let sum = Sha256::digest(out.as_bytes());
    if let Err(e) = write_file_atomic(&intel_txt_path(c), out.as_bytes(), 0o640) {
        logf(&format!("sync-intel: write intel.txt failed: {}", e));
        return 1;
    }
    let meta = IntelMeta {
        generated_at: crate::report::format_utc_rfc3339(get_now()),
        source_commit: commit.clone(),
        ipv4: count,
        ipv6: 0,
        sha256: hex::encode(sum),
    };
    // parity: intel.go:206 ignores saveJSON's error here; rc stays 0.
    let _ = save_json(&intel_meta_path(c), &meta, 0o640);
    logf(&format!(
        "sync-intel: loaded {} IPv4 entries (commit {})",
        count,
        short(&commit)
    ));
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::report::now_utc;
    use crate::testutil::{start_server, HttpResp, TempDir};

    fn cfg_with_state(dir: &TempDir) -> Config {
        let mut c = Config::default();
        c.paths.state_dir = dir.path().to_string_lossy().to_string();
        c
    }

    fn write_intel(dir: &TempDir, data: &str) {
        std::fs::write(dir.join("intel.txt"), data).unwrap();
    }

    #[test]
    fn format_intel_exports_canonical_ipv4() {
        let dir = TempDir::new("intel-canonical");
        write_intel(&dir, "192.0.2.1\n198.51.100.2\n192.0.2.1\n");
        let mut c = cfg_with_state(&dir);
        c.intel.min_entries = 2;
        c.intel.max_entries = 10;
        let got = format_intel(&c).unwrap();
        assert_eq!(got, b"192.0.2.1\n198.51.100.2\n");
    }

    #[test]
    fn format_intel_preserves_crlf_and_unterminated_last_line() {
        let dir = TempDir::new("intel-line-endings");
        write_intel(&dir, "192.0.2.1\r\n198.51.100.2");
        assert_eq!(
            format_intel(&cfg_with_state(&dir)).unwrap(),
            b"192.0.2.1\n198.51.100.2\n"
        );
    }

    #[test]
    fn format_intel_missing_file_is_empty_success() {
        let dir = TempDir::new("intel-missing");
        let mut c = cfg_with_state(&dir);
        c.intel.min_entries = 90000;
        let got = format_intel(&c).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn format_intel_rejects_invalid_stored_data() {
        let cases = [
            ("empty file", "", 0i64, 0i64),
            ("blank line", "192.0.2.1\n\n198.51.100.2\n", 1, 10),
            ("ipv6", "2001:db8::1\n", 1, 10),
            ("ipv4-mapped ipv6", "::ffff:192.0.2.1\n", 1, 10),
            ("comment", "# list\n192.0.2.1\n", 1, 10),
            ("trailing field", "192.0.2.1 # cn\n", 1, 10),
            ("leading space", " 192.0.2.1\n", 1, 10),
            ("undersized", "192.0.2.1\n", 2, 10),
            ("oversized", "192.0.2.1\n198.51.100.2\n", 1, 1),
        ];
        for (name, data, min, max) in cases {
            let dir = TempDir::new("intel-invalid");
            write_intel(&dir, data);
            let mut c = cfg_with_state(&dir);
            c.intel.min_entries = min;
            c.intel.max_entries = max;
            assert!(
                format_intel(&c).is_err(),
                "invalid stored intel accepted: {}",
                name
            );
        }
    }

    #[test]
    fn sync_intel_does_not_send_token_to_source() {
        // commit API: token only over https — over plain http it must be absent.
        let api = start_server(|r| {
            assert_eq!(r.header("Authorization"), ""); // http: never attach
            HttpResp::body(r#"[{"sha":"abc123"}]"#)
        });
        let source = start_server(|r| {
            assert_eq!(r.header("Authorization"), "");
            HttpResp::body("::ffff:192.0.2.1\n192.0.2.2 # country column\n")
        });

        let dir = TempDir::new("intel-sync");
        let mut c = cfg_with_state(&dir);
        c.intel.commit_url = api.url.clone();
        c.intel.source_url = format!("{}/{{commit}}/list.txt", source.url);
        c.intel.min_entries = 1;
        c.intel.token_file = dir.join("token").to_string_lossy().to_string();
        std::fs::write(dir.join("token"), b"test-token").unwrap();

        let now = || now_utc();
        assert_eq!(cmd_sync_intel(&c, &now), 0);

        // commit API was consulted and {commit} was substituted
        let reqs = api.requests();
        assert_eq!(reqs.len(), 1);
        let src_reqs = source.requests();
        assert_eq!(src_reqs.len(), 1);
        assert_eq!(src_reqs[0].url, "/abc123/list.txt");

        // stored intel is canonical dotted-quad only
        let stored = std::fs::read(dir.join("intel.txt")).unwrap();
        assert_eq!(stored, b"192.0.2.1\n192.0.2.2\n");

        // meta records the count and source commit
        let meta = std::fs::read_to_string(dir.join("intel-last-sync.txt")).unwrap();
        assert!(meta.contains("\"source_commit\": \"abc123\""));
        assert!(meta.contains("\"ipv4\": 2"));
    }

    #[test]
    fn sync_intel_keeps_existing_list_when_download_fails() {
        let dir = TempDir::new("intel-download-fail");
        write_intel(&dir, "192.0.2.1\n");
        let mut c = cfg_with_state(&dir);
        let source = start_server(|_| HttpResp::status(404));
        c.intel.source_url = source.url.clone();
        c.intel.min_entries = 1;

        let now = || now_utc();
        assert_eq!(cmd_sync_intel(&c, &now), 0);
        let stored = std::fs::read(dir.join("intel.txt")).unwrap();
        assert_eq!(stored, b"192.0.2.1\n");
    }

    #[test]
    fn sync_intel_refuses_undersized_list() {
        let dir = TempDir::new("intel-small");
        let source = start_server(|_| HttpResp::body("192.0.2.1\n"));
        let mut c = cfg_with_state(&dir);
        c.intel.source_url = source.url.clone();
        c.intel.min_entries = 2;

        let now = || now_utc();
        assert_eq!(cmd_sync_intel(&c, &now), 0);
        assert!(
            !dir.join("intel.txt").exists(),
            "undersized list must not be stored"
        );
    }

    #[test]
    fn resolve_commit_parses_single_object_too() {
        // one-object commit API shape: {"sha":"..."} after a failed list parse
        let api = start_server(|_| HttpResp::body(r#"{"sha":"deadbeef"}"#));
        let dir = TempDir::new("commit-one");
        let mut c = cfg_with_state(&dir);
        c.intel.commit_url = api.url.clone();
        c.intel.source_url = "https://example.invalid/{commit}/list".to_string();

        let sha = resolve_commit(&c, "t").unwrap();
        assert_eq!(sha, "deadbeef");
    }
}
