// tui/backend.rs — Connects the TUI to status::collect_live and abuseguard.sh bridge commands.
use crate::status::{self, Snapshot};
use crate::tui::model::{HostInfo, LogsData, PanelData, PendingAction};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub fn collect_host_info() -> HostInfo {
    let os_raw = std::fs::read_to_string("/etc/os-release")
        .or_else(|_| std::fs::read_to_string("/usr/lib/os-release"))
        .unwrap_or_default();
    let deb_ver = std::fs::read_to_string("/etc/debian_version").unwrap_or_default();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| std::env::consts::OS.to_string());
    HostInfo {
        os: parse_os_label(&os_raw, &deb_ver),
        arch: std::env::consts::ARCH.to_string(),
        kernel,
    }
}

pub fn parse_os_label(os_release: &str, debian_version: &str) -> String {
    let mut id = String::new();
    let mut name = String::new();
    let mut pretty = String::new();
    let mut ver_id = String::new();
    let mut codename = String::new();

    for line in os_release.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match k.trim() {
            "ID" => id = val,
            "NAME" => name = val,
            "PRETTY_NAME" => pretty = val,
            "VERSION_ID" => ver_id = val,
            "VERSION_CODENAME" => codename = val,
            _ => {}
        }
    }

    let point = debian_version.lines().next().unwrap_or("").trim();
    if id == "debian"
        && !ver_id.is_empty()
        && ver_id.bytes().all(|b| b.is_ascii_digit())
        && !point.is_empty()
        && point.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        && point.split('.').next() == Some(ver_id.as_str())
    {
        let base = if name.is_empty() {
            "Debian GNU/Linux"
        } else {
            name.as_str()
        };
        return if codename.is_empty() {
            format!("{} {}", base, point)
        } else {
            format!("{} {} ({})", base, point, codename)
        };
    }

    if !pretty.is_empty() {
        return pretty;
    }
    let mut out = if name.is_empty() {
        "Linux".to_string()
    } else {
        name
    };
    if !ver_id.is_empty() {
        out.push(' ');
        out.push_str(&ver_id);
    }
    if !codename.is_empty() {
        out.push_str(&format!(" ({})", codename));
    }
    out
}

#[derive(Debug, Clone)]
pub struct ShellBackend {
    pub panel_script: PathBuf,
    pub version: &'static str,
}

impl ShellBackend {
    pub fn new(panel_script: PathBuf, version: &'static str) -> Self {
        Self {
            panel_script,
            version,
        }
    }

    pub fn load_all(&self) -> (Snapshot<'static>, Result<PanelData, String>) {
        let snapshot = status::collect_live(self.version);
        let panel = self.query_json::<PanelData>("panel");
        (snapshot, panel)
    }

    pub fn load_logs(&self) -> Result<LogsData, String> {
        self.query_json::<LogsData>("logs")
    }

    fn query_json<T: serde::de::DeserializeOwned>(&self, scope: &str) -> Result<T, String> {
        let out = Command::new("bash")
            .arg(&self.panel_script)
            .arg("--tui-data")
            .arg(scope)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("无法调用面板数据接口：{}", e))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            return Err(if err.is_empty() {
                format!("读取 {} 状态失败 (exit {})", scope, out.status)
            } else {
                err
            });
        }
        serde_json::from_slice(&out.stdout)
            .map_err(|e| format!("解析 {} 状态 JSON 失败：{}", scope, e))
    }

    pub fn run_action(&self, action: &PendingAction) -> (bool, String) {
        if matches!(action, PendingAction::ViewRuleset) {
            return self.run_raw(&["--tui-data", "ruleset"], None);
        }
        match action {
            PendingAction::SiteAdd { domain, upstream } => {
                self.run_raw(&["--tui-action", "site-add", domain, upstream], None)
            }
            PendingAction::SiteDel { domain } => {
                self.run_raw(&["--tui-action", "site-del", domain], None)
            }
            PendingAction::SetCfToken { token } => {
                self.run_raw(&["--tui-action", "cf-token"], Some(format!("{}\n", token)))
            }
            PendingAction::FwOpen {
                proto,
                port,
                source,
                note,
            } => self.run_raw(&["--tui-action", "fw-open", proto, port, source, note], None),
            PendingAction::FwClose {
                proto,
                port,
                source,
            } => self.run_raw(&["--tui-action", "fw-close", proto, port, source], None),
            PendingAction::FwFamily { family, enable } => self.run_raw(
                &[
                    "--tui-action",
                    "fw-family",
                    family,
                    if *enable { "1" } else { "0" },
                ],
                None,
            ),
            PendingAction::FwApply => self.run_raw(&["--tui-action", "fw-apply"], None),
            PendingAction::BanIp { ip } => self.run_raw(&["--tui-action", "ban-ip", ip], None),
            PendingAction::UnbanIp { ip } => self.run_raw(&["--tui-action", "unban-ip", ip], None),
            PendingAction::WhitelistAdd { entries } => self.run_raw(
                &["--tui-action", "wl-add"],
                Some(format!("{}\n", entries)),
            ),
            PendingAction::WhitelistDel { entry } => {
                self.run_raw(&["--tui-action", "wl-del", entry], None)
            }
            PendingAction::SshPort { port } => {
                self.run_raw(&["--tui-action", "ssh-port", port], None)
            }
            PendingAction::SshAuth {
                which,
                confirmed_yes,
            } => self.run_raw(
                &[
                    "--tui-action",
                    "ssh-auth",
                    which,
                    if *confirmed_yes { "yes" } else { "no" },
                ],
                None,
            ),
            PendingAction::SshKeyAdd { pubkey } => {
                self.run_raw(&["--tui-action", "ssh-key-add"], Some(format!("{}\n", pubkey)))
            }
            PendingAction::SshKeyDel {
                index,
                confirmed_yes,
            } => {
                let idx = index.to_string();
                self.run_raw(
                    &[
                        "--tui-action",
                        "ssh-key-del",
                        &idx,
                        if *confirmed_yes { "yes" } else { "no" },
                    ],
                    None,
                )
            }
            PendingAction::SshPassword { p1, p2 } => self.run_raw(
                &["--tui-action", "ssh-password"],
                Some(format!("{}\n{}\n", p1, p2)),
            ),
            PendingAction::SyncIntel => self.run_raw(&["--tui-action", "sync-intel"], None),
            PendingAction::FlushReport => self.run_raw(&["--tui-action", "flush-report"], None),
            PendingAction::SetAbuseKey { key } => {
                self.run_raw(&["--tui-action", "abuse-key"], Some(format!("{}\n", key)))
            }
            PendingAction::ToggleReport => self.run_raw(&["--tui-action", "toggle-report"], None),
            PendingAction::ViewRuleset
            | PendingAction::WhitelistEdit
            | PendingAction::Update
            | PendingAction::Uninstall => (false, "该操作需要交互终端执行。".to_string()),
        }
    }

    pub fn run_interactive(&self, action: &PendingAction) -> Result<bool, String> {
        let verb = match action {
            PendingAction::WhitelistEdit => "wl-edit",
            PendingAction::Update => "update",
            PendingAction::Uninstall => "uninstall",
            _ => return Err("不支持的交互操作".to_string()),
        };
        let status = Command::new("bash")
            .arg(&self.panel_script)
            .arg("--tui-action")
            .arg(verb)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("无法启动交互操作：{}", e))?;
        Ok(status.success())
    }

    fn run_raw(&self, args: &[&str], stdin_data: Option<String>) -> (bool, String) {
        let mut cmd = Command::new("bash");
        cmd.arg(&self.panel_script)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return (false, format!("执行失败：{}", e)),
        };
        if let Some(payload) = stdin_data {
            if let Some(mut sin) = child.stdin.take() {
                let _ = sin.write_all(payload.as_bytes());
            }
        }
        match child.wait_with_output() {
            Ok(out) => {
                let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
                let err = String::from_utf8_lossy(&out.stderr);
                if !err.trim().is_empty() {
                    if !combined.is_empty() && !combined.ends_with('\n') {
                        combined.push('\n');
                    }
                    combined.push_str(&err);
                }
                (out.status.success(), combined)
            }
            Err(e) => (false, format!("等待命令输出失败：{}", e)),
        }
    }
}
