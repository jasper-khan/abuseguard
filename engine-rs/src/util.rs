// util.rs — logging, atomic writes, JSON save, Go-style duration helpers.
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// logf writes to stderr (captured by journald for the units).
pub fn logf(msg: &str) {
    eprintln!("[abuseguard] {}", msg);
}

// fatalf logs and exits with code 1.
pub fn fatalf(msg: &str) -> ! {
    logf(msg);
    std::process::exit(1)
}

pub fn io_err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

// writeFileAtomic writes data to path via a temp file + rename in the same dir.
pub fn write_file_atomic(path: &str, data: &[u8], perm: u32) -> Result<(), String> {
    let p = Path::new(path);
    let dir = p.parent().unwrap_or_else(|| Path::new("."));
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_path = dir.join(format!(".tmp-{}-{}", std::process::id(), n));
    let r = (|| -> Result<(), String> {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(io_err)?
        };
        #[cfg(not(unix))]
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(io_err)?;
        f.write_all(data).map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(perm)).map_err(io_err)?;
        }
        let _ = perm; // non-unix: permissions not modeled (Go mirrors POSIX perms only)
        drop(f);
        fs::rename(&tmp_path, p).map_err(io_err)
    })();
    if r.is_err() {
        let _ = fs::remove_file(&tmp_path); // Go removes the temp via defer on every path
    }
    r
}

// mkdir_all creates the reports dir; POSIX mode set only on unix (0750 etc.).
pub fn mkdir_mode(path: &str, mode: u32) -> Result<(), String> {
    fs::create_dir_all(path).map_err(io_err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_err)?;
    }
    let _ = mode;
    Ok(())
}

// save_json writes v as 2-space-indented JSON, atomically.
pub fn save_json<T: serde::Serialize>(path: &str, v: &T, perm: u32) -> Result<(), String> {
    let b = serde_json::to_vec_pretty(v).map_err(io_err)?;
    write_file_atomic(path, &b, perm)
}

// open_create_mode opens path with O_CREATE|O_WRONLY|O_APPEND semantics and
// a POSIX mode applied only at creation time.
pub fn open_append_mode(path: &str, mode: u32) -> Result<fs::File, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(mode)
            .open(path)
            .map_err(io_err)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .map_err(io_err)
    }
}

// go_duration_parse mirrors time.ParseDuration ("300ms", "1.5h", "2h45m", "0").
// shortcut: Go accepts negative durations; this engine's windows must be >0,
// so negatives are rejected here instead of modeled (parse would be def-only).
pub fn go_duration_parse(s: &str) -> Result<Duration, String> {
    let bad = || format!("time: invalid duration {:?}", s);
    let mut rest = s;
    let neg = rest.starts_with('-');
    if neg || rest.starts_with('+') {
        rest = &rest[1..];
    }
    if rest == "0" {
        return if neg { Err(bad()) } else { Ok(Duration::ZERO) };
    }
    if rest.is_empty() {
        return Err(bad());
    }
    let mut total: u128 = 0;
    while !rest.is_empty() {
        let nd = rest.len() - rest.trim_start_matches(|c: char| c.is_ascii_digit()).len();
        let int_part = &rest[..nd];
        rest = &rest[nd..];
        let mut frac_part = "";
        if let Some(r) = rest.strip_prefix('.') {
            let fd = r.len() - r.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            frac_part = &r[..fd];
            rest = &r[fd..];
        }
        if int_part.is_empty() && frac_part.is_empty() {
            return Err(bad());
        }
        let unit_ns: u128 = if rest.starts_with("ns") {
            rest = &rest[2..];
            1
        } else if rest.starts_with("us") {
            rest = &rest[2..];
            1_000
        } else if rest.starts_with("\u{00b5}s") || rest.starts_with("\u{03bc}s") {
            rest = &rest[3..]; // µs/μs: sign is 2 UTF-8 bytes + 's'
            1_000
        } else if rest.starts_with("ms") {
            rest = &rest[2..];
            1_000_000
        } else if rest.starts_with('s') {
            rest = &rest[1..];
            1_000_000_000
        } else if rest.starts_with('m') {
            rest = &rest[1..];
            60_000_000_000
        } else if rest.starts_with('h') {
            rest = &rest[1..];
            3_600_000_000_000
        } else {
            return Err(bad());
        };
        // value = int.frac scaled into nanoseconds, truncating toward zero.
        let mantissa: u128 = format!("{}{}", int_part, frac_part)
            .parse()
            .map_err(|_| bad())?;
        let scale: u128 = 10_u128
            .checked_pow(frac_part.len() as u32)
            .ok_or_else(bad)?;
        // Go rejects sub-nanosecond precision (e.g. "1.5ns").
        if unit_ns == 1 && mantissa % scale != 0 {
            return Err(bad());
        }
        let add = mantissa
            .checked_mul(unit_ns)
            .and_then(|v| Some(v / scale))
            .ok_or_else(bad)?;
        total = total.checked_add(add).ok_or_else(bad)?;
    }
    if neg {
        return Err(bad()); // see shortcut note above
    }
    // Go caps at ~292 years (int64 nanos)
    if total > i64::MAX as u128 {
        return Err(bad());
    }
    Ok(Duration::from_nanos(total as u64))
}

// parse_duration_default mirrors parseDurationDefault: "" or invalid -> default.
pub fn parse_duration_default(s: &str, def: Duration) -> Duration {
    if s.is_empty() {
        return def;
    }
    match go_duration_parse(s) {
        Ok(d) => d,
        Err(_) => def,
    }
}

// format_go_duration mirrors time.Duration.String().
pub fn format_go_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos == 0 {
        return "0s".to_string();
    }
    let mut out = String::new();
    if nanos < 1_000_000_000 {
        // sub-second: use ms/us/ns units
        let (val, unit) = if nanos % 1_000_000 == 0 {
            (
                nanos / 1_000_000,
                if nanos % 1_000_000_000 == 0 {
                    "ms"
                } else {
                    "ms"
                },
            )
        } else if nanos % 1_000 == 0 {
            (nanos / 1_000, "us")
        } else {
            (nanos, "ns")
        };
        return format!("{}{}", val, unit);
    }
    let h = nanos / 3_600_000_000_000;
    let m = (nanos % 3_600_000_000_000) / 60_000_000_000;
    let s = nanos % 60_000_000_000;
    if h > 0 {
        out.push_str(&format!("{}h", h));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{}m", m));
    }
    if s % 1_000_000_000 == 0 {
        out.push_str(&format!("{}s", s / 1_000_000_000));
    } else {
        let frac = format!("{:09}", s % 1_000_000_000);
        let frac = frac.trim_end_matches('0');
        out.push_str(&format!("{}.{}s", s / 1_000_000_000, frac));
    }
    out
}

// prefer_local_bin_path ensures /usr/local/bin precedes /usr/bin and /bin (on
// usrmerge Debian/Ubuntu /bin -> /usr/bin) without overriding earlier custom dirs.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn prefer_local_bin_path(raw: &str) -> String {
    let is_sys_bin = |d: &str| matches!(d, "/usr/bin" | "/bin");
    let entries: Vec<&str> = raw.split(':').filter(|s| !s.is_empty()).collect();
    let local_idx = entries.iter().position(|&d| d == "/usr/local/bin");
    let sys_idx = entries.iter().position(|&d| is_sys_bin(d));
    if let Some(l) = local_idx {
        if sys_idx.map_or(true, |s| l < s) {
            return raw.to_string();
        }
    }
    let mut out: Vec<&str> = Vec::with_capacity(entries.len() + 1);
    let mut inserted = false;
    for dir in entries {
        if dir == "/usr/local/bin" {
            continue;
        }
        if !inserted && is_sys_bin(dir) {
            out.push("/usr/local/bin");
            inserted = true;
        }
        out.push(dir);
    }
    if !inserted {
        out.push("/usr/local/bin");
    }
    out.join(":")
}

// Called at single-threaded process startup so fail2ban-client in /usr/local/bin
// is found even under stripped PATH (e.g. cron or custom sudo secure_path).
pub fn ensure_local_bin_in_path() {
    #[cfg(unix)]
    {
        let cur = std::env::var("PATH").unwrap_or_default();
        let next = prefer_local_bin_path(&cur);
        if next != cur {
            std::env::set_var("PATH", next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefer_local_bin_preserves_custom_prefix_and_beats_usr_bin() {
        assert_eq!(
            prefer_local_bin_path("/tmp/test-bin:/usr/bin:/bin"),
            "/tmp/test-bin:/usr/local/bin:/usr/bin:/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/usr/sbin:/usr/bin:/sbin:/bin"),
            "/usr/sbin:/usr/local/bin:/usr/bin:/sbin:/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/usr/bin:/usr/local/bin:/bin"),
            "/usr/local/bin:/usr/bin:/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/tmp/test-bin:/usr/local/bin:/usr/bin:/bin"),
            "/tmp/test-bin:/usr/local/bin:/usr/bin:/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/bin:/usr/bin"),
            "/usr/local/bin:/bin:/usr/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/tmp/test-bin:/bin:/usr/bin"),
            "/tmp/test-bin:/usr/local/bin:/bin:/usr/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/bin:/usr/local/bin:/usr/bin"),
            "/usr/local/bin:/bin:/usr/bin"
        );
        assert_eq!(
            prefer_local_bin_path("/tmp/test-bin"),
            "/tmp/test-bin:/usr/local/bin"
        );
        assert_eq!(prefer_local_bin_path(""), "/usr/local/bin");
    }

    #[test]
    fn parse_go_durations() {
        assert_eq!(go_duration_parse("0").unwrap(), Duration::ZERO);
        assert_eq!(go_duration_parse("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(go_duration_parse("600").is_err(), true); // no unit: Go rejects
        assert_eq!(
            go_duration_parse("1h30m").unwrap(),
            Duration::from_secs(5400)
        );
        assert_eq!(
            go_duration_parse("300ms").unwrap(),
            Duration::from_millis(300)
        );
        assert!(go_duration_parse("ten minutes").is_err());
        assert!(go_duration_parse("1.5h").unwrap() == Duration::from_secs(5400));
    }

    #[test]
    fn format_go_durations() {
        assert_eq!(format_go_duration(Duration::ZERO), "0s");
        assert_eq!(format_go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(format_go_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_go_duration(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(format_go_duration(Duration::from_secs(65)), "1m5s");
    }

    #[test]
    fn duration_default() {
        assert_eq!(
            parse_duration_default("", Duration::from_secs(900)),
            Duration::from_secs(900)
        );
        assert_eq!(
            parse_duration_default("bogus", Duration::from_secs(900)),
            Duration::from_secs(900)
        );
        assert_eq!(
            parse_duration_default("15m", Duration::from_secs(900)),
            Duration::from_secs(900)
        );
    }

    #[test]
    fn atomic_write_and_json() {
        let dir = std::env::temp_dir().join(format!("ag-util-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.txt");
        write_file_atomic(p.to_str().unwrap(), b"hello", 0o640).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
        write_file_atomic(p.to_str().unwrap(), b"world2", 0o640).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"world2");
        // no temp files left behind
        for e in fs::read_dir(&dir).unwrap() {
            assert!(!e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tmp-"));
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
