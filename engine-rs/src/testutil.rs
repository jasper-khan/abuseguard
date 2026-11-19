// testutil.rs — #[cfg(test)]-only harness: tiny_http server, fixed clock, temp dir.
#![cfg(test)]

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

pub struct TempDir(std::path::PathBuf);
impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        static N: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "ag-test-{}-{}-{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&d).unwrap();
        TempDir(d)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}
impl std::ops::Deref for TempDir {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// FixedClock mirrors Go's reportNow override backed by an AtomicI64.
#[derive(Clone)]
pub struct FixedClock {
    pub secs: Arc<AtomicI64>,
}
impl FixedClock {
    pub fn new(secs: i64) -> FixedClock {
        FixedClock {
            secs: Arc::new(AtomicI64::new(secs)),
        }
    }
    pub fn add(&self, d: i64) {
        self.secs.fetch_add(d, Ordering::SeqCst);
    }
    pub fn now_fn(&self) -> impl Fn() -> OffsetDateTime + Send + Sync + 'static {
        let secs = Arc::clone(&self.secs);
        move || fixed_time(secs.load(Ordering::SeqCst))
    }
}

pub fn fixed_time(unix: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(unix).expect("valid unix timestamp")
}

// HttpReq is one captured request, number 1-based like the Go tests count calls.
#[derive(Debug, Clone)]
pub struct HttpReq {
    pub n: u64,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpReq {
    pub fn header(&self, name: &str) -> String {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }
    pub fn form(&self, field: &str) -> String {
        for pair in self.body.split('&') {
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => continue,
            };
            let k = crate::http::form_unescape(k);
            let v = crate::http::form_unescape(v);
            if k == field {
                return v;
            }
        }
        String::new()
    }
}

pub struct HttpResp {
    pub status: u16,
    pub location: Option<String>,
    pub body: String,
    /// drop the connection without responding (Go's http.ErrAbortHandler).
    pub abort: bool,
    /// park the handler until this channel closes (test synchronization).
    pub wait: Option<std::sync::mpsc::Receiver<()>>,
}

impl HttpResp {
    pub fn ok() -> HttpResp {
        HttpResp {
            status: 200,
            location: None,
            body: String::new(),
            abort: false,
            wait: None,
        }
    }
    pub fn status(s: u16) -> HttpResp {
        HttpResp {
            status: s,
            location: None,
            body: String::new(),
            abort: false,
            wait: None,
        }
    }
    pub fn redirect(loc: &str) -> HttpResp {
        HttpResp {
            status: 302,
            location: Some(loc.to_string()),
            body: String::new(),
            abort: false,
            wait: None,
        }
    }
    pub fn body(b: &str) -> HttpResp {
        HttpResp {
            status: 200,
            location: None,
            body: b.to_string(),
            abort: false,
            wait: None,
        }
    }
}

pub struct TestServer {
    pub url: String,
    _server: Arc<tiny_http::Server>,
    requests: Arc<Mutex<Vec<HttpReq>>>,
}

impl TestServer {
    pub fn requests(&self) -> Vec<HttpReq> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn count(&self) -> usize {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

// start_server launches a tiny_http server where each request is handled on
// its own thread by `handler(request) -> response`. Returns its URL.
pub fn start_server<F>(handler: F) -> TestServer
where
    F: Fn(HttpReq) -> HttpResp + Send + Sync + 'static,
{
    let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").unwrap());
    let url = format!(
        "http://{}",
        server
            .server_addr()
            .to_string()
            .replace('[', "")
            .replace(']', "")
    );
    let requests: Arc<Mutex<Vec<HttpReq>>> = Arc::new(Mutex::new(Vec::new()));
    let counter = Arc::new(AtomicU64::new(0));
    {
        let server = Arc::clone(&server);
        let requests = Arc::clone(&requests);
        let counter = Arc::clone(&counter);
        let handler = Arc::new(handler);
        std::thread::spawn(move || loop {
            let mut req = match server.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(_) => break,
            };
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let creq = HttpReq {
                n,
                url: req.url().to_string(),
                headers: req
                    .headers()
                    .iter()
                    .map(|h| {
                        (
                            h.field.as_str().as_str().to_string(),
                            h.value.as_str().to_string(),
                        )
                    })
                    .collect(),
                body,
            };
            requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(creq.clone());
            let handler = Arc::clone(&handler);
            std::thread::spawn(move || {
                let resp = handler(creq);
                if let Some(rx) = resp.wait {
                    let _ = rx.recv();
                }
                if resp.abort {
                    drop(req);
                    return;
                }
                let mut r =
                    tiny_http::Response::from_string(resp.body).with_status_code(resp.status);
                if let Some(loc) = resp.location {
                    r = r.with_header(
                        tiny_http::Header::from_bytes(&b"Location"[..], loc.as_bytes()).unwrap(),
                    );
                }
                let _ = req.respond(r);
            });
        });
    }
    TestServer {
        url,
        _server: server,
        requests,
    }
}
