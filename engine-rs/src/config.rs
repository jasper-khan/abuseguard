// config.rs — mirrors /etc/caddy-abuseguard/config.json.
use crate::util::io_err;
use std::fs;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/caddy-abuseguard/config.json";

#[derive(serde::Deserialize, Default, Debug, Clone)]
pub struct PathsCfg {
    #[serde(default)]
    pub state_dir: String,
    #[serde(default)]
    pub reports_dir: String,
}

#[derive(serde::Deserialize, Default, Debug, Clone)]
pub struct IntelCfg {
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub commit_url: String,
    #[serde(default)]
    pub token_file: String,
    #[serde(default)]
    pub min_entries: i64,
    #[serde(default)]
    pub max_entries: i64,
}

#[derive(serde::Deserialize, Default, Debug, Clone)]
pub struct AbuseCfg {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub report_url: String,
    #[serde(default)]
    pub report_key_file: String,
    #[serde(default)]
    pub daily_report_cap: i64,
    #[serde(default)]
    pub dedupe_window: String,
}

#[derive(serde::Deserialize, Default, Debug, Clone)]
pub struct Config {
    #[serde(default)]
    pub allowlist_file: String,
    #[serde(default)]
    pub paths: PathsCfg,
    #[serde(default)]
    pub intel: IntelCfg,
    #[serde(default)]
    pub abuseipdb: AbuseCfg,
}

pub fn config_path() -> String {
    match std::env::var("ABUSEGUARD_CONFIG") {
        Ok(p) if !p.is_empty() => p,
        _ => DEFAULT_CONFIG_PATH.to_string(),
    }
}

pub fn load_config() -> Result<Config, String> {
    load_config_at(&config_path())
}

pub fn load_config_at(path: &str) -> Result<Config, String> {
    let b = fs::read(path).map_err(io_err)?;
    let mut c: Config = serde_json::from_slice(&b).map_err(io_err)?;
    if c.paths.state_dir.is_empty() {
        c.paths.state_dir = "/var/lib/caddy-abuseguard".to_string();
    }
    if c.paths.reports_dir.is_empty() {
        c.paths.reports_dir = format!("{}/reports", c.paths.state_dir);
    }
    if c.allowlist_file.is_empty() {
        c.allowlist_file = "/etc/caddy-abuseguard/whitelist".to_string();
    }
    Ok(c)
}

// read_key_file returns the trimmed contents of a key file, or "" if missing/empty.
pub fn read_key_file(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    match fs::read(path) {
        Err(_) => String::new(),
        Ok(b) => String::from_utf8_lossy(&b).trim().to_string(),
    }
}
