// main.rs — CLI dispatch: enqueue | report send-auto | sync-intel |
// allowlist-validate | allowlist-check | policy-apply | panel commands | version.
mod allow;
mod caddy_render;
mod config;
mod config_render;
mod config_txn;
mod filelock;
mod http;
mod intel;
mod install_inventory;
mod nginx_render;
mod policy;
mod queue;
mod report;
mod site_migration;
mod ssh_admin;
mod status;
#[cfg(test)]
mod testutil;
mod util;

use report::now_utc;
use util::{fatalf, logf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }
    let sub = args[1].as_str();
    let rest: Vec<String> = args[2..].to_vec();
    match sub {
        "enqueue" => run_enqueue(&rest),
        "report" => {
            if rest.first().map(|s| s.as_str()) == Some("send-auto") {
                let c = must_config();
                std::process::exit(report::cmd_report_send_auto(&c, &now_utc));
            }
            fatalf("usage: caddy-abuseguard report send-auto");
        }
        "sync-intel" => {
            let c = must_config();
            std::process::exit(intel::cmd_sync_intel(&c, &now_utc));
        }
        "allowlist-validate" => run_allowlist_validate(&rest),
        "allowlist-check" => run_allowlist_check(&rest),
        "policy-apply" => policy::run_policy_apply(&rest),
        "migrate-caddy-sites" => site_migration::run(&rest),
        "config-transaction" => config_txn::run(&rest),
        "install-inventory" => install_inventory::run(&rest),
        "ssh-admin" => ssh_admin::run(&rest),
        "status" => status::run(&rest, VERSION),
        "firewall-render" => config_render::run_firewall_render(&rest),
        "nginx-render" => nginx_render::run(&rest),
        "caddy-render" => caddy_render::run(&rest),
        "version" | "-v" | "--version" => println!("abuseguard-engine {}", VERSION),
        _ => {
            usage();
            std::process::exit(2);
        }
    }
}

fn usage() {
    logf("subcommands: enqueue | report send-auto | sync-intel | allowlist-validate (--entry <IP/CIDR> | --file <path>) | allowlist-check --ip <IP> | policy-apply (root, Linux) | status --json | firewall-render | nginx-render | caddy-render | migrate-caddy-sites | config-transaction | install-inventory | ssh-admin | version");
}

fn must_config() -> config::Config {
    match config::load_config() {
        Ok(c) => c,
        Err(e) => fatalf(&format!("load config: {}", e)),
    }
}

// Flags wraps Go's flag.FlagSet for the small flag surface used here:
// (--x v) and (--x=v) / (-x v) and (-x=v) forms, string and int values.
// Once a non-flag argument appears, parsing stops and the rest are
// positionals — exactly flag.FlagSet.Parse's contract.
struct Flags {
    vals: std::collections::HashMap<String, String>,
    ints: std::collections::HashMap<String, i64>,
    positionals: Vec<String>,
}

fn parse_flags(spec: &[(&str, Option<i64>)], args: &[String]) -> Flags {
    let mut flags = Flags {
        vals: std::collections::HashMap::new(),
        ints: std::collections::HashMap::new(),
        positionals: Vec::new(),
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let lead = a
            .strip_prefix("--")
            .or_else(|| a.strip_prefix('-'))
            .map(|s| s.to_string());
        let lead = match lead {
            Some(l) => l,
            None => {
                flags.positionals.extend(args[i..].iter().cloned());
                break;
            }
        };
        let (name, inline_val) = match lead.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (lead, None),
        };
        let declared_int = match spec.iter().find(|(n, _)| *n == name) {
            Some((_, Some(_d))) => true,
            Some((_, None)) => false,
            None => go_flag_error(&a), // unknown flag: flag.ExitOnError
        };
        let value = match inline_val {
            Some(v) => v,
            None => {
                i += 1;
                if i >= args.len() {
                    go_flag_error(&a); // missing value: flag.ExitOnError
                }
                args[i].clone()
            }
        };
        if declared_int {
            match value.parse::<i64>() {
                Ok(n) => {
                    flags.ints.insert(name.clone(), n);
                }
                Err(_) => go_flag_error(&a), // bad int: flag.ExitOnError
            }
        }
        flags.vals.insert(name, value);
        i += 1;
    }
    flags
}

// go_flag_error mirrors flag.ExitOnError: message + exit 2.
fn go_flag_error(_bad: &str) -> ! {
    usage();
    std::process::exit(2);
}

fn run_enqueue(args: &[String]) {
    let flags = parse_flags(
        &[
            ("ip", None),
            ("profile", None),
            ("failures", Some(0)),
            ("window", None),
            ("transport", None),
            ("port", Some(443)),
        ],
        args,
    );
    let ip = flags.vals.get("ip").cloned().unwrap_or_default();
    if ip.is_empty() {
        fatalf("enqueue: --ip required");
    }
    let item = queue::ReportItem {
        ip,
        profile: flags.vals.get("profile").cloned().unwrap_or_default(),
        failures: flags.ints.get("failures").cloned().unwrap_or(0),
        window: flags.vals.get("window").cloned().unwrap_or_default(),
        transport: flags.vals.get("transport").cloned().unwrap_or_default(),
        port: flags.ints.get("port").cloned().unwrap_or(443),
        ts: String::new(),
    };
    let c = must_config();
    std::process::exit(queue::cmd_enqueue(&c, item, &now_utc));
}

fn run_allowlist_validate(args: &[String]) {
    let flags = parse_flags(&[("entry", None), ("file", None)], args);
    let entry = flags.vals.get("entry").cloned().unwrap_or_default();
    let path = flags.vals.get("file").cloned().unwrap_or_default();
    if entry.is_empty() == path.is_empty() {
        logf("allowlist-validate: specify exactly one of --entry or --file");
        std::process::exit(2);
    }
    let err = if !entry.is_empty() {
        allow::parse_allowlist_entry(&entry).err()
    } else {
        allow::load_allowlist(&path).err()
    };
    if let Some(e) = err {
        logf(&format!("allowlist-validate: {}", e));
        std::process::exit(1);
    }
}

// run_allowlist_check is used by the root control panel before a manual ban.
// Exit 0 means the IP is covered by the allowlist, 1 means it is not covered,
// and 2 means the input or allowlist could not be read reliably.
fn run_allowlist_check(args: &[String]) {
    let flags = parse_flags(&[("ip", None)], args);
    let ip = flags.vals.get("ip").cloned().unwrap_or_default();
    if ip.is_empty() || !flags.positionals.is_empty() {
        logf("allowlist-check: specify exactly one --ip <IP>");
        std::process::exit(2);
    }
    let c = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            logf(&format!("allowlist-check: load config: {}", e));
            std::process::exit(2);
        }
    };
    let code = allow::allowlist_check_code(&c.allowlist_file, &ip);
    if code == 2 {
        logf("allowlist-check: invalid IP or unreadable/invalid allowlist");
    }
    std::process::exit(code);
}
