// http.rs — ureq-based HTTP helpers mirroring the Go engine's client behavior.
use std::io::Read;
use std::time::Duration;

// query_escape mirrors Go's url.QueryEscape (url.Values.Encode uses it).
// ASCII alphanumerics and -_.~ stay; space becomes '+'; the rest %XX.
pub fn query_escape(s: &str) -> String {
    let mut out = String::new();
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// encode_form mirrors url.Values.Encode: keys sorted alphabetically.
pub fn encode_form(pairs: &[(String, String)]) -> String {
    let mut sorted: Vec<&(String, String)> = pairs.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    sorted
        .iter()
        .map(|(k, v)| format!("{}={}", query_escape(k), query_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// form_unescape reverses query_escape ("+" -> space, %XX -> byte). Test twin
// of Go's r.Form.Get; the engine itself never reads form data.
#[cfg(test)]
pub fn form_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

// agent builds the shared agent: rustls + overall timeout, redirects off
// (both helpers follow redirects by hand for exact header policy parity).
fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build()
}

// http_get mirrors intel.go httpGet: uses the token only over https, follows
// up to 10 redirects by hand, and drops Authorization on any redirect that is
// not https-and-same-host. Body capped at 32 MiB (LimitReader parity).
pub fn http_get(url: &str, token: &str) -> Result<Vec<u8>, String> {
    let a = agent(Duration::from_secs(60));
    let use_token = !token.is_empty() && url_startswith_https(url);
    let original_host = url_host(url).to_string();
    let mut current = url.to_string();
    let mut remaining_hops = 10usize;
    loop {
        let orig_hop = remaining_hops == 10;
        let is_https = url_startswith_https(&current);
        let same_host = url_host(&current).eq_ignore_ascii_case(&original_host);
        let mut req = a.get(&current).set("User-Agent", "abuseguard-intel/1.0");
        let attach_token = use_token && is_https && (orig_hop || same_host);
        if attach_token {
            req = req.set("Authorization", &format!("Bearer {}", token));
        }
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                // 4xx/5xx: Go reads status after draining; errors on !=200.
                let _ = r;
                return Err(format!("GET {} -> HTTP {}", url, code));
            }
            Err(e) => return Err(e.to_string()),
        };
        let status = resp.status();
        if (300..400).contains(&status) {
            if remaining_hops == 0 {
                return Err("stopped after 10 redirects".to_string());
            }
            let loc = resp.header("Location").unwrap_or("").to_string();
            remaining_hops -= 1;
            current = resolve_location(&current, &loc)?;
            continue;
        }
        let mut body = Vec::new();
        resp.into_reader()
            .take(32 * 1024 * 1024u64)
            .read_to_end(&mut body)
            .map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!("GET {} -> HTTP {}", url, status));
        }
        return Ok(body);
    }
}

// send_report mirrors report.go sendReport: form POST with Key header.
// shortcut: no redirect follow — the AbuseIPDB report endpoint in
// production does not redirect; a 3xx lands in the requeue branch and is
// retried by the next timer run.
pub fn send_report(
    report_url: &str,
    key: &str,
    ip: &str,
    cats: &str,
    comment: &str,
    ts: &str,
) -> Result<u16, String> {
    let a = agent(Duration::from_secs(30));
    let mut form: Vec<(String, String)> = vec![
        ("ip".into(), ip.to_string()),
        ("categories".into(), cats.to_string()),
        ("comment".into(), comment.to_string()),
    ];
    if !ts.is_empty() {
        form.push(("timestamp".into(), ts.to_string()));
    }
    let body = encode_form(&form);
    let resp = a
        .post(report_url)
        .set("Key", key)
        .set("Accept", "application/json")
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&body);
    match resp {
        Ok(r) => {
            let status = r.status();
            drain_1mib(r);
            Ok(status)
        }
        Err(ureq::Error::Status(code, r)) => {
            // transport-level "errors" for 4xx/5xx carry the status we need.
            drain_1mib(r);
            Ok(code)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn drain_1mib(r: ureq::Response) {
    let mut sink = Vec::new();
    let _ = r.into_reader().take(1 << 20).read_to_end(&mut sink);
}

pub fn url_startswith_https(url: &str) -> bool {
    url.starts_with("https://")
}

pub fn url_host(url: &str) -> &str {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let end = rest.find('/').unwrap_or(rest.len());
    &rest[..end]
}

fn url_split(url: &str) -> (String, String, String) {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https".to_string(), r.to_string())
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http".to_string(), r.to_string())
    } else {
        return (String::new(), String::new(), url.to_string());
    };
    let end = rest.find('/').unwrap_or(rest.len());
    let (host, path) = rest.split_at(end);
    (scheme, host.to_string(), path.to_string())
}

// resolve_location handles absolute URLs, absolute paths, and simple relative
// paths. Deep RFC 3986 normalization is out of scope: list hosts emit
// absolute or root-relative Locations.
fn resolve_location(base: &str, loc: &str) -> Result<String, String> {
    if loc.starts_with("http://") || loc.starts_with("https://") {
        return Ok(loc.to_string());
    }
    let (scheme, host, path) = url_split(base);
    if scheme.is_empty() {
        return Err(format!("invalid redirect location {}", loc));
    }
    if loc.starts_with('/') {
        return Ok(format!("{}://{}{}", scheme, host, loc));
    }
    // relative: resolve against the base path's directory
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Ok(format!("{}://{}{}{}", scheme, host, dir, loc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{start_server, HttpResp};

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(query_escape("192.0.2.1"), "192.0.2.1");
        assert_eq!(
            query_escape("Repeated probing: 5 requests."),
            "Repeated+probing%3A+5+requests."
        );
        assert_eq!(query_escape("18,22"), "18%2C22");
    }

    #[test]
    fn encode_form_sorts_keys_like_go() {
        let form = encode_form(&[
            ("ip".into(), "192.0.2.1".into()),
            ("categories".into(), "21".into()),
            ("comment".into(), "hello world".into()),
        ]);
        assert_eq!(form, "categories=21&comment=hello+world&ip=192.0.2.1");
    }

    #[test]
    fn roundtrip_form_escape() {
        let esc = encode_form(&[("comment".into(), "a+b% c,d:e".into())]);
        let value = esc.strip_prefix("comment=").unwrap();
        assert_eq!(form_unescape(value), "a+b% c,d:e");
    }

    #[test]
    fn http_get_follows_absolute_redirect_and_returns_body() {
        let target = start_server(|_| HttpResp::body("ok"));
        let target_url = target.url.clone();
        let redirect = start_server(move |r| {
            assert!(r.header("Authorization").is_empty()); // http: token never attached
            HttpResp::redirect(&target_url)
        });
        let body = http_get(&redirect.url, "secret-token").unwrap();
        assert_eq!(body, b"ok");
        assert_eq!(target.count(), 1);
    }

    #[test]
    fn http_get_errors_on_http_status() {
        let srv = start_server(|_| HttpResp::status(404));
        let err = http_get(&srv.url, "").unwrap_err();
        assert!(err.contains("HTTP 404"), "err={}", err);
    }

    #[test]
    fn send_report_posts_form_with_key_header() {
        let srv = start_server(|_| HttpResp::ok());
        let status = send_report(
            &srv.url,
            "test-key",
            "192.0.2.1",
            "21",
            "Repeated probing of common sensitive web application paths: 5 requests within 10 minutes over HTTP/1.1.",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(status, 200);
        let reqs = srv.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].header("Key"), "test-key");
        assert_eq!(
            reqs[0].header("Content-Type"),
            "application/x-www-form-urlencoded"
        );
        assert_eq!(reqs[0].form("ip"), "192.0.2.1");
        assert_eq!(reqs[0].form("categories"), "21");
        assert_eq!(reqs[0].form("timestamp"), "2026-01-01T00:00:00Z");
        assert!(reqs[0]
            .form("comment")
            .starts_with("Repeated probing of common sensitive web application paths"));
    }

    #[test]
    fn send_report_surfaces_error_status() {
        let srv = start_server(|_| HttpResp::status(429));
        let status = send_report(&srv.url, "k", "192.0.2.1", "18,22", "c", "").unwrap();
        assert_eq!(status, 429);
    }
}
