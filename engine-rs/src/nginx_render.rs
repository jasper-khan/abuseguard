//! Pure renderer for project-owned Nginx site configs. Installation, certbot,
//! validating the complete Nginx config, reloading and rollback stay in Bash.

use std::io::{self, Write};

fn valid_domain(domain: &str) -> bool {
    if domain.len() > 235 {
        return false;
    }
    let Some((name, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    (2..=63).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_lowercase())
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn valid_upstream(upstream: &str) -> bool {
    if upstream.len() > 253 {
        return false;
    }
    let Some((host, port)) = upstream.rsplit_once(':') else {
        return false;
    };
    !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok_and(|p| p != 0)
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn valid_quoted_path(path: &str) -> bool {
    // Paths are Nginx quoted tokens, not shell code. Forbid delimiters,
    // escapes and variable expansion instead of trying to quote them twice.
    path.starts_with('/')
        && !path
            .chars()
            .any(|c| matches!(c, '"' | '\\' | '$') || c.is_control())
}

fn render_site(
    domain: &str,
    upstream: &str,
    letsencrypt: &str,
    trust_include: &str,
    access_log: &str,
) -> Result<String, &'static str> {
    if !valid_domain(domain) {
        return Err("invalid Nginx site domain");
    }
    if !valid_upstream(upstream) {
        return Err("invalid Nginx site upstream");
    }
    if ![letsencrypt, trust_include, access_log]
        .into_iter()
        .all(valid_quoted_path)
    {
        return Err("invalid Nginx site path");
    }
    let name = format!("abuseguard-{domain}");
    let sni = domain.replace('.', r"\.");
    Ok(format!(
        r#"server {{
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name {domain};
    ssl_certificate "{letsencrypt}/live/{name}/fullchain.pem";
    ssl_certificate_key "{letsencrypt}/live/{name}/privkey.pem";
    ssl_protocols TLSv1.2 TLSv1.3;
    include "{trust_include}";
    access_log "{access_log}" abuseguard_json;
    client_max_body_size 0;
    # Caddy returns 404 for a Host it does not serve; the first site
    # becomes the default vhost, so reject unknown Hosts/SNI here
    # instead of proxying them to this site upstream. RFC 6066 makes
    # SNI case-insensitive while $ssl_server_name keeps client case.
    if ($http_host = "") {{
        return 404;
    }}
    if ($host != {domain}) {{
        return 404;
    }}
    if ($ssl_server_name !~* ^{sni}$) {{
        return 404;
    }}
    location / {{
        proxy_pass http://{upstream};
        proxy_http_version 1.1;
        # Caddy streams and keeps idle upgraded/slow responses open;
        # Nginx defaults would buffer SSE and cut WS at 60 idle seconds.
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $abuseguard_connection_upgrade;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $http_host;
    }}
}}
"#
    ))
}

pub fn run(args: &[String]) {
    let result = match args {
        [mode] if mode == "supported" => Ok(Some("nginx-render-v1\n".to_string())),
        [mode, domain] if mode == "validate-domain" => valid_domain(domain)
            .then_some(None)
            .ok_or("invalid Nginx site domain"),
        [mode, upstream] if mode == "validate-upstream" => valid_upstream(upstream)
            .then_some(None)
            .ok_or("invalid Nginx site upstream"),
        [mode, domain, upstream, letsencrypt, trust_include, access_log] if mode == "site" => {
            render_site(domain, upstream, letsencrypt, trust_include, access_log).map(Some)
        }
        _ => {
            eprintln!(
                "usage: nginx-render supported | validate-domain DOMAIN | validate-upstream HOST:PORT | site DOMAIN HOST:PORT LETSENCRYPT_DIR TRUST_INCLUDE ACCESS_LOG"
            );
            std::process::exit(2);
        }
    };
    match result {
        Ok(None) => {}
        Ok(Some(data)) => {
            let mut stdout = io::stdout().lock();
            if stdout
                .write_all(data.as_bytes())
                .and_then(|()| stdout.flush())
                .is_err()
            {
                eprintln!("nginx-render: could not write output");
                std::process::exit(1);
            }
        }
        Err(message) => {
            eprintln!("nginx-render: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_the_shell_domain_contract() {
        for domain in ["a.co", "www.a-b.example", "0.example", "xn--d1acufc.example"] {
            assert!(valid_domain(domain), "{domain}");
        }
        for domain in [
            "", "localhost", "example.c", "EXAMPLE.com", "a..example", "-bad.example",
            "bad-.example", ".foo.com", "example.com.", "example.123", "a_b.example",
            "example.com\n", "example.com;",
        ] {
            assert!(!valid_domain(domain), "{domain:?}");
        }

        let label = "a".repeat(63);
        let partial = format!("{label}.{label}.{label}.{}", "b".repeat(39));
        assert_eq!(format!("{partial}.com").len(), 235);
        assert!(valid_domain(&format!("{partial}.com")));
        assert!(!valid_domain(&format!("{partial}.info")));
        assert!(!valid_domain(&format!("{label}a.example")));
        assert!(!valid_domain(&format!("a.{}a", "b".repeat(63))));
    }

    #[test]
    fn validates_the_shell_upstream_contract() {
        for upstream in ["127.0.0.1:3000", "localhost:1", "APP_service:65535", "app:00001"] {
            assert!(valid_upstream(upstream), "{upstream}");
        }
        for upstream in [
            "", "localhost", "https://localhost:5", "[::1]:443", "foo..bar:80", "-foo:80",
            "foo-:80", "foo:0", "foo:65536", "foo:9999999999999999999999", "foo:+80",
            "foo:80/path", "foo:80\n",
        ] {
            assert!(!valid_upstream(upstream), "{upstream:?}");
        }

        let label = "a".repeat(63);
        let host = format!("{label}.{label}.{label}.{}", "b".repeat(56));
        assert_eq!(format!("{host}:3000").len(), 253);
        assert!(valid_upstream(&format!("{host}:3000")));
        assert!(!valid_upstream(&format!("{host}:30000")));
        assert!(!valid_upstream(&format!("{label}a:3000")));
    }

    #[test]
    fn renders_managed_site_contract() {
        let rendered = render_site(
            "foo-bar.example.com",
            "127.0.0.1:3000",
            "/etc/letsencrypt fixture",
            "/etc/nginx/snippets/abuseguard-cloudflare.conf",
            "/var/log/nginx/abuseguard-access.json",
        )
        .unwrap();

        for expected in [
            "    listen 443 ssl http2;",
            "    listen [::]:443 ssl http2;",
            "    server_name foo-bar.example.com;",
            "    ssl_certificate \"/etc/letsencrypt fixture/live/abuseguard-foo-bar.example.com/fullchain.pem\";",
            "    ssl_certificate_key \"/etc/letsencrypt fixture/live/abuseguard-foo-bar.example.com/privkey.pem\";",
            "    include \"/etc/nginx/snippets/abuseguard-cloudflare.conf\";",
            "    access_log \"/var/log/nginx/abuseguard-access.json\" abuseguard_json;",
            "    if ($http_host = \"\") {",
            "    if ($host != foo-bar.example.com) {",
            r"    if ($ssl_server_name !~* ^foo-bar\.example\.com$) {",
            "        proxy_pass http://127.0.0.1:3000;",
            "        proxy_buffering off;",
            "        proxy_read_timeout 1h;",
            "        proxy_set_header Host $http_host;",
            "        proxy_set_header X-Forwarded-For $remote_addr;",
        ] {
            assert!(rendered.lines().any(|line| line == expected), "{expected}");
        }
        assert_eq!(rendered.matches("return 404;").count(), 3);
        assert!(rendered.ends_with("    }\n}\n"));
        assert!(!rendered.contains("listen 80"));
        assert!(!rendered.contains(" combined;"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_site_is_byte_identical_to_bootstrap_fallback() {
        let domain = "foo-bar.example.com";
        let upstream = "127.0.0.1:3000";
        let letsencrypt = "/etc/letsencrypt fixture";
        let trust_include = "/etc/nginx/snippets/abuseguard-cloudflare.conf";
        let access_log = "/var/log/nginx/abuseguard-access.json";
        let output = std::process::Command::new("bash")
            .env_remove("BASH_ENV")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                r#"set -e
source "$1"
NGINX_LETSENCRYPT_DIR="$4"
NGINX_CF_TRUST_INCLUDE="$5"
NGINX_ACCESS_LOG="$6"
_nginx_render_site_shell "$2" "$3""#,
                "nginx-render-parity",
            ])
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../assets/nginx/runtime.sh"),
            )
            .args([domain, upstream, letsencrypt, trust_include, access_log])
            .output()
            .expect("bash must be available for the Nginx runtime parity test");

        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(
            render_site(domain, upstream, letsencrypt, trust_include, access_log)
                .unwrap()
                .as_bytes(),
            output.stdout,
        );
    }

    #[test]
    fn renderer_rejects_invalid_quoted_paths_and_site_values() {
        let render = |domain, upstream, path| {
            render_site(domain, upstream, "/etc/letsencrypt", path, "/var/log/ag.log")
        };
        for path in ["relative.conf", "/file\"quote", "/escape\\path", "/$host", "/new\nline"] {
            assert!(render("foo.example", "localhost:80", path).is_err(), "{path:?}");
        }
        assert!(render("foo.example;", "localhost:80", "/ok").is_err());
        assert!(render("foo.example", "localhost:80;", "/ok").is_err());
    }
}
