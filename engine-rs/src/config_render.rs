// Rendering only: this module never loads nftables or writes a policy file.
use std::fmt::Write as _;
use std::io::{self, BufRead, Write as _};
use std::net::IpAddr;

const FIREWALL_HEAD: &str = concat!(
    "# Managed by ag. Change ports through the firewall menu.\n",
    "add table inet caddy_abuseguard\n",
    "delete table inet caddy_abuseguard\n",
    "table inet caddy_abuseguard {\n",
    "\tchain input {\n",
    "\t\ttype filter hook input priority filter; policy drop;\n",
    "\t\tiifname \"lo\" accept\n",
    "\t\tct state established,related accept\n",
    "\t\tct state invalid drop\n",
    "\t\tmeta l4proto { icmp, ipv6-icmp } accept\n",
    "\t\tudp sport 67 udp dport 68 accept\n",
    "\t\tudp sport 547 udp dport 546 accept\n",
);

fn parse_switch(raw: &str) -> Option<bool> {
    match raw {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn source_family(source: &str) -> Option<&'static str> {
    let (raw_ip, prefix) = match source.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (source, None),
    };
    // Keep the parsed address family and preserve the spelling in output.
    // The panel matches the persisted source string when deleting a rule.
    let (family, max_prefix) = match raw_ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => ("ip", 32),
        IpAddr::V6(_) => ("ip6", 128),
    };
    if let Some(prefix) = prefix {
        if !prefix.bytes().all(|b| b.is_ascii_digit()) || prefix.parse::<u8>().ok()? > max_prefix {
            return None;
        }
    }
    Some(family)
}

fn render_firewall(ports: impl BufRead, ipv4_in: bool, ipv6_in: bool) -> Result<String, String> {
    let mut out = format!("# policy ipv4-in={} ipv6-in={}\n", u8::from(ipv4_in), u8::from(ipv6_in));
    out.push_str(FIREWALL_HEAD);
    if !ipv4_in {
        out.push_str("\t\tmeta nfproto ipv4 drop\n");
    }
    if !ipv6_in {
        out.push_str("\t\tmeta nfproto ipv6 drop\n");
    }
    for (index, line) in ports.lines().enumerate() {
        let line = line.map_err(|e| format!("cannot read firewall port row {}: {e}", index + 1))?;
        let mut fields = line.split_ascii_whitespace();
        let Some(proto) = fields.next() else { continue };
        let invalid = || format!("invalid firewall port row {}", index + 1);
        if !matches!(proto, "tcp" | "udp") {
            return Err(invalid());
        }
        let port = fields.next().ok_or_else(invalid)?;
        if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..=65535)) {
            return Err(invalid());
        }
        let source = fields.next().unwrap_or("any");
        if fields.next().is_some() {
            return Err(invalid());
        }
        if source == "any" {
            writeln!(out, "\t\t{proto} dport {port} accept").expect("writing to a String cannot fail");
        } else {
            let family = source_family(source).ok_or_else(invalid)?;
            writeln!(out, "\t\t{family} saddr {source} {proto} dport {port} accept")
                .expect("writing to a String cannot fail");
        }
    }
    out.push_str("\t}\n}\n");
    Ok(out)
}

pub fn run_firewall_render(args: &[String]) {
    let flags = match args {
        [ipv4, ipv6] => parse_switch(ipv4).zip(parse_switch(ipv6)),
        _ => None,
    };
    let Some((ipv4_in, ipv6_in)) = flags else {
        crate::util::logf("usage: caddy-abuseguard firewall-render <ipv4:0|1> <ipv6:0|1>");
        std::process::exit(2);
    };
    // Do not expose any candidate content unless the entire input validated.
    let out = render_firewall(io::stdin().lock(), ipv4_in, ipv6_in)
        .unwrap_or_else(|err| crate::util::fatalf(&format!("firewall-render: {err}")));
    if let Err(err) = io::stdout().lock().write_all(out.as_bytes()) {
        crate::util::fatalf(&format!("firewall-render: {err}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_same_transaction_and_source_spelling() {
        let ports = b"\ntcp 22\nudp 443 any\ntcp 8443 203.0.113.5/32\ntcp 8443 2001:0DB8:0::5\n";
        let rules = render_firewall(&ports[..], true, false).unwrap();
        let expected = concat!(
            "# policy ipv4-in=1 ipv6-in=0\n",
            "# Managed by ag. Change ports through the firewall menu.\n",
            "add table inet caddy_abuseguard\n",
            "delete table inet caddy_abuseguard\n",
            "table inet caddy_abuseguard {\n",
            "\tchain input {\n",
            "\t\ttype filter hook input priority filter; policy drop;\n",
            "\t\tiifname \"lo\" accept\n",
            "\t\tct state established,related accept\n",
            "\t\tct state invalid drop\n",
            "\t\tmeta l4proto { icmp, ipv6-icmp } accept\n",
            "\t\tudp sport 67 udp dport 68 accept\n",
            "\t\tudp sport 547 udp dport 546 accept\n",
            "\t\tmeta nfproto ipv6 drop\n",
            "\t\ttcp dport 22 accept\n",
            "\t\tudp dport 443 accept\n",
            "\t\tip saddr 203.0.113.5/32 tcp dport 8443 accept\n",
            "\t\tip6 saddr 2001:0DB8:0::5 tcp dport 8443 accept\n",
            "\t}\n}\n",
        );
        assert_eq!(rules, expected);
    }

    #[test]
    fn family_policy_does_not_reorder_the_port_rules() {
        let ports = b"udp 65535 2001:db8::/64\ntcp 1\n";
        let rules = render_firewall(&ports[..], false, true).unwrap();
        assert!(rules.starts_with("# policy ipv4-in=0 ipv6-in=1\n"));
        assert!(!rules.contains("nfproto ipv6 drop"));
        assert!(rules.ends_with(concat!(
            "\t\tmeta nfproto ipv4 drop\n",
            "\t\tip6 saddr 2001:db8::/64 udp dport 65535 accept\n",
            "\t\ttcp dport 1 accept\n",
            "\t}\n}\n",
        )));
    }

    #[test]
    fn rejects_invalid_port_rows_and_networks() {
        for row in [
            "icmp 22",
            "tcp",
            "tcp 0",
            "udp 65536",
            "tcp +22",
            "tcp 22 host.example",
            "tcp 22 192.0.2.1/33",
            "tcp 22 2001:db8::1/129",
            "tcp 22 2001:db8::1/+64",
            "tcp 22 192.0.2.1/",
            "tcp 22 any extra",
        ] {
            let ports = format!("tcp 443\n{row}\n");
            assert_eq!(
                render_firewall(ports.as_bytes(), true, false).unwrap_err(),
                "invalid firewall port row 2",
                "{row}",
            );
        }
    }
}
