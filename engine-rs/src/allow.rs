// allow.rs — allowlist parsing, canonical export, membership check.
// Like Go, fold IPv4-mapped IPv6 into IPv4 for comparison and display, but
// preserve native IPv6 addresses, including loopback and unspecified.
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct Cidr {
    ip: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (&self.ip, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let p = self.prefix as u32;
                if p == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - p).min(32);
                (u32::from(*n) & mask) == (u32::from(*a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let p = self.prefix as u16;
                if p == 0 {
                    return true;
                }
                let np = u128::from(*n);
                let ap = u128::from(*a);
                let mask = u128::MAX << (128 - p).min(128);
                (np & mask) == (ap & mask)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.prefix)
    }
}

// canon_ip parses and canonicalizes: IPv4-mapped IPv6 collapses to IPv4,
// mirroring net.ParseIP + To4-based Equals/String.
pub fn canon_ip(s: &str) -> Option<IpAddr> {
    match s.parse::<IpAddr>() {
        Err(_) => None,
        Ok(IpAddr::V6(v6)) => Some(v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4)),
        Ok(v4 @ IpAddr::V4(_)) => Some(v4),
    }
}

pub enum AllowEntry {
    Single(IpAddr),
    Net(Cidr),
}

pub fn parse_cidr(value: &str) -> Result<Cidr, String> {
    let (addr_s, prefix_s) = value
        .split_once('/')
        .ok_or_else(|| format!("invalid CIDR {:?}", value))?;
    let prefix: u32 = prefix_s
        .parse()
        .map_err(|_| format!("invalid CIDR {:?}", value))?;
    if addr_s.contains(':') {
        let v6: Ipv6Addr = addr_s
            .parse()
            .map_err(|_| format!("invalid CIDR {:?}", value))?;
        if prefix > 128 {
            return Err(format!("invalid CIDR {:?}", value));
        }
        let masked = mask_v6(v6, prefix as u16);
        // net.IPNet.String uses the masked network. Only prefixes covering
        // the entire mapped prefix can be represented as an IPv4 CIDR.
        if prefix >= 96 {
            if let Some(v4) = masked.to_ipv4_mapped() {
                return Ok(Cidr {
                    ip: IpAddr::V4(v4),
                    prefix: (prefix - 96) as u8,
                });
            }
        }
        Ok(Cidr {
            ip: IpAddr::V6(masked),
            prefix: prefix as u8,
        })
    } else {
        let v4: Ipv4Addr = addr_s
            .parse()
            .map_err(|_| format!("invalid CIDR {:?}", value))?;
        if prefix > 32 {
            return Err(format!("invalid CIDR {:?}", value));
        }
        Ok(Cidr {
            ip: IpAddr::V4(masked_v4(v4, prefix)),
            prefix: prefix as u8,
        })
    }
}

fn masked_v4(v4: Ipv4Addr, prefix: u32) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let mask = u32::MAX << (32 - prefix).min(32);
    Ipv4Addr::from(u32::from(v4) & mask)
}

fn mask_v6(v6: Ipv6Addr, prefix: u16) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let mask = u128::MAX << (128 - prefix).min(128);
    Ipv6Addr::from(u128::from(v6) & mask)
}

pub fn parse_allowlist_entry(value: &str) -> Result<AllowEntry, String> {
    if value.contains('/') {
        Ok(AllowEntry::Net(parse_cidr(value)?))
    } else {
        match canon_ip(value) {
            Some(ip) => Ok(AllowEntry::Single(ip)),
            None => Err(format!("invalid IP {:?}", value)),
        }
    }
}

pub struct Allowlist {
    ips: Vec<IpAddr>,
    nets: Vec<Cidr>,
}

// load_allowlist parses the whitelist file. Callers decide how to fail safe:
// the reporter stops without sending, while exports fail closed with no output.
pub fn load_allowlist(path: &str) -> Result<Allowlist, String> {
    let f = File::open(path).map_err(crate::util::io_err)?;
    let mut a = Allowlist {
        ips: Vec::new(),
        nets: Vec::new(),
    };
    let mut line_no = 0usize;
    for line in BufReader::new(f).lines() {
        let raw = line.map_err(crate::util::io_err)?;
        line_no += 1;
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // strip trailing inline comment / annotation
        if let Some(i) = line.find(|c| c == ' ' || c == '\t' || c == '#') {
            line = line[..i].trim();
        }
        if line.is_empty() {
            continue;
        }
        match parse_allowlist_entry(line) {
            Ok(AllowEntry::Net(n)) => a.nets.push(n),
            Ok(AllowEntry::Single(ip)) => a.ips.push(ip),
            Err(e) => return Err(format!("line {}: {}", line_no, e)),
        }
    }
    Ok(a)
}

// format_allowlist returns canonical one-entry-per-line output. The whole file
// is parsed first, so a bad entry can never yield a partial policy.
pub fn format_allowlist(path: &str) -> Result<Vec<u8>, String> {
    let allow = load_allowlist(path)?;
    let mut out = String::new();
    let mut seen = std::collections::HashSet::new();
    let mut write = |entry: &str| {
        if seen.insert(entry.to_string()) {
            out.push_str(entry);
            out.push('\n');
        }
    };
    for ip in &allow.ips {
        write(&ip.to_string());
    }
    for n in &allow.nets {
        write(&n.to_string());
    }
    Ok(out.into_bytes())
}

impl Allowlist {
    pub fn contains(&self, ip_str: &str) -> bool {
        let ip = match canon_ip(ip_str.trim()) {
            Some(ip) => ip,
            None => return false,
        };
        for x in &self.ips {
            if *x == ip {
                return true;
            }
        }
        for n in &self.nets {
            if n.contains(&ip) {
                return true;
            }
        }
        false
    }
}

// allowlist_check_code maps the allowlist-check contract to process exit codes:
// 0 covered, 1 not covered, 2 invalid input or unreadable/invalid allowlist.
pub fn allowlist_check_code(path: &str, raw_ip: &str) -> i32 {
    let entry = match parse_allowlist_entry(raw_ip.trim()) {
        Ok(e) => e,
        Err(_) => return 2,
    };
    let ip = match entry {
        AllowEntry::Single(ip) => ip,
        AllowEntry::Net(_) => return 2,
    };
    let allow = match load_allowlist(path) {
        Ok(a) => a,
        Err(_) => return 2,
    };
    if allow.contains(&ip.to_string()) {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &std::path::Path, data: &str) {
        std::fs::write(path, data).unwrap();
    }

    #[test]
    fn load_allowlist_rejects_invalid_entry() {
        for entry in ["not-an-ip", "999.1.2.3", "192.0.2.1/33", "2001:db8::/129"] {
            let dir = crate::testutil::TempDir::new("allow-reject");
            let path = dir.join("whitelist");
            write(&path, &format!("192.0.2.1\n{}\n", entry));
            assert!(
                load_allowlist(path.to_str().unwrap()).is_err(),
                "invalid allowlist entry was accepted: {}",
                entry
            );
        }
    }

    #[test]
    fn load_allowlist_parses_comments_and_cidrs() {
        let dir = crate::testutil::TempDir::new("allow-comments");
        let path = dir.join("whitelist");
        write(
            &path,
            "# trusted addresses\n192.0.2.1 # admin\n2001:db8::/32\n",
        );
        let allow = load_allowlist(path.to_str().unwrap()).unwrap();
        for ip in ["192.0.2.1", "2001:db8::1"] {
            assert!(allow.contains(ip), "allowlist does not contain {}", ip);
        }
    }

    #[test]
    fn format_allowlist_canonicalizes_without_narrowing() {
        let dir = crate::testutil::TempDir::new("allow-canonical");
        let path = dir.join("whitelist");
        let data = [
            "# trusted addresses",
            "192.0.2.1 # admin",
            "192.0.2.1",
            "::ffff:192.0.2.1",
            "::ffff:192.0.2.9",
            "::ffff:198.51.100.7",
            "198.51.100.5/24",
            "::ffff:203.0.113.77/120",
            "2001:db8::1/32",
        ]
        .join("\n")
            + "\n";
        write(&path, &data);

        let exported = format_allowlist(path.to_str().unwrap()).unwrap();
        let want =
            b"192.0.2.1\n192.0.2.9\n198.51.100.7\n198.51.100.0/24\n203.0.113.0/24\n2001:db8::/32\n";
        assert_eq!(exported, want);

        let round_path = dir.join("exported");
        write(&round_path, std::str::from_utf8(&exported).unwrap());
        let original = load_allowlist(path.to_str().unwrap()).unwrap();
        let round_trip = load_allowlist(round_path.to_str().unwrap()).unwrap();
        let cases: [(&str, bool); 12] = [
            ("192.0.2.1", true),
            ("::ffff:192.0.2.1", true),
            ("192.0.2.2", false),
            ("192.0.2.9", true),
            ("::ffff:192.0.2.9", true),
            ("198.51.100.7", true),
            ("::ffff:198.51.100.7", true),
            ("198.51.100.255", true),
            ("198.51.101.1", false),
            ("203.0.113.5", true),
            ("::ffff:203.0.113.5", true),
            ("2001:db8:1::1", true), // wait: 2001:db8::/32 covers 2001:db8:1::1
        ];
        for (ip, want) in cases {
            assert_eq!(original.contains(ip), want, "original Contains({})", ip);
            assert_eq!(
                round_trip.contains(ip),
                original.contains(ip),
                "exported Contains({}) changed",
                ip
            );
        }
        // and a miss outside every net
        assert!(!original.contains("2001:db9::1"));
    }

    #[test]
    fn format_allowlist_preserves_native_ipv6() {
        let dir = crate::testutil::TempDir::new("allow-native-ipv6");
        let path = dir.join("whitelist");
        let p = path.to_str().unwrap();
        // These are the shipped default whitelist entries.
        write(&path, "127.0.0.0/8\n::1\n");
        assert_eq!(format_allowlist(p).unwrap(), b"::1\n127.0.0.0/8\n");
        assert_eq!(allowlist_check_code(p, "::1"), 0);
        assert_eq!(allowlist_check_code(p, "0.0.0.1"), 1);
        assert_eq!(canon_ip("::"), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        write(&path, "::1/128\n::/0\n::ffff:192.0.2.1/95\n");
        assert_eq!(
            format_allowlist(p).unwrap(),
            b"::1/128\n::/0\n::fffe:0:0/95\n"
        );
        let allow = load_allowlist(p).unwrap();
        assert!(allow.contains("2001:db8::1"));
        assert!(!allow.contains("192.0.2.1"));
    }

    #[test]
    fn format_allowlist_rejects_invalid_without_output() {
        let dir = crate::testutil::TempDir::new("allow-invalid");
        let path = dir.join("whitelist");
        write(&path, "192.0.2.1\n999.1.2.3\n");
        assert!(format_allowlist(path.to_str().unwrap()).is_err());
        assert!(format_allowlist(dir.join("missing").to_str().unwrap()).is_err());
    }

    #[test]
    fn allowlist_check_exit_codes() {
        let dir = crate::testutil::TempDir::new("allow-codes");
        let path = dir.join("whitelist");
        write(&path, "192.0.2.1\n2001:db8::/32\n");
        let p = path.to_str().unwrap();
        let cases = [
            ("single IP hit", "192.0.2.1", 0),
            ("CIDR hit", "2001:db8::10", 0),
            ("IPv4 CIDR target rejected", "192.0.2.0/24", 2),
            ("IPv6 CIDR target rejected", "2001:db8:1::/48", 2),
            ("valid miss", "198.51.100.1", 1),
            ("non-overlapping CIDR rejected", "198.51.100.0/24", 2),
            ("invalid input rejected", "not-an-ip", 2),
        ];
        for (name, ip, want) in cases {
            assert_eq!(allowlist_check_code(p, ip), want, "{}", name);
        }
        let missing = crate::testutil::TempDir::new("allow-codes-missing");
        assert_eq!(
            allowlist_check_code(missing.join("whitelist").to_str().unwrap(), "198.51.100.1"),
            2
        );
        let invalid = crate::testutil::TempDir::new("allow-codes-bad");
        let bad = invalid.join("whitelist");
        write(&bad, "not-an-ip\n");
        assert_eq!(
            allowlist_check_code(bad.to_str().unwrap(), "198.51.100.1"),
            2
        );
    }
}
