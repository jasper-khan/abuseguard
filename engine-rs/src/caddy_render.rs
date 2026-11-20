// Render only files owned by the panel. Caddy remains the authority for
// validating the combined configuration, and the caller owns apply/rollback.
use std::net::{IpAddr, SocketAddr};

fn hostname(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    })
}

fn domain(value: &str) -> bool {
    value.rsplit_once('.').is_some_and(|(_, tld)| {
        hostname(value) && tld.len() >= 2 && tld.bytes().all(|c| c.is_ascii_alphabetic())
    })
}

fn upstream(value: &str) -> bool {
    if value.starts_with('[') {
        return value.parse::<SocketAddr>().is_ok_and(|addr| addr.is_ipv6() && addr.port() != 0);
    }
    value.rsplit_once(':').is_some_and(|(host, port)| {
        (host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4()) || hostname(host))
            && !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port != 0)
    })
}

fn render(site: &str, target: &str, tls: &str) -> Result<String, &'static str> {
    if !domain(site) {
        return Err("invalid Caddy site domain");
    }
    if !upstream(target) {
        return Err("invalid Caddy upstream (use host:port or [IPv6]:port)");
    }
    let tls_block = match tls {
        "auto" => "",
        "cloudflare" => "\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t}\n",
        _ => return Err("TLS must be auto or cloudflare"),
    };
    Ok(format!("{site} {{\n\timport abuseguard\n{tls_block}\treverse_proxy {target}\n}}\n"))
}

pub fn run(args: &[String]) {
    let [site, target, tls] = args else {
        eprintln!("usage: caddy-abuseguard caddy-render DOMAIN UPSTREAM auto|cloudflare");
        std::process::exit(2);
    };
    match render(site, target, tls) {
        Ok(config) => print!("{config}"),
        Err(error) => {
            eprintln!("caddy-render: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_panel_site_with_both_tls_modes() {
        assert_eq!(render("example.com", "127.0.0.1:3000", "auto").unwrap(),
            "example.com {\n\timport abuseguard\n\treverse_proxy 127.0.0.1:3000\n}\n");
        assert_eq!(render("example.com", "[2001:db8::1]:443", "cloudflare").unwrap(),
            "example.com {\n\timport abuseguard\n\ttls {\n\t\tdns cloudflare {env.CF_API_TOKEN}\n\t}\n\treverse_proxy [2001:db8::1]:443\n}\n");
    }

    #[test]
    fn rejects_invalid_domain_and_endpoints() {
        for value in ["localhost", "-test.example", "example..com"] {
            assert!(render(value, "localhost:80", "auto").is_err());
        }
        for value in ["localhost", "localhost:0", "localhost:65536", "2001:db8::1:443", "http://localhost:80"] {
            assert!(render("example.com", value, "auto").is_err());
        }
    }
}
