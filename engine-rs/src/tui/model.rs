// tui/model.rs — Application state, data payloads, modal dialogs, and pure key reducer.
use crate::status::Snapshot;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsAction {
    SyncIntel,
    AddSite,
    DelSite(usize),
    SetCfToken,
    ToggleIpv4,
    ToggleIpv6,
    OpenPort,
    ClosePort(usize),
    GoBlocklist,
    UnbanSelected(usize),
    BanIpPrompt,
    UnbanIpPrompt,
    WlAddPrompt,
    WlDelSelected(usize),
    WlEdit,
    ViewRuleset,
    FwApply,
    ChangeSshPort,
    ToggleSshPassword,
    ToggleSshPubkey,
    ChangeRootPassword,
    AddSshKey,
    DelSshKey(usize),
    FlushReport,
    SetAbuseKey,
    ToggleReport,
    CycleLogFilter,
    ViewLogsModal,
    RefreshLogs,
    Update,
    Uninstall,
}

#[derive(Debug, Clone)]
pub enum SettingsRow {
    Blank,
    Section(String),
    TableHead {
        c1: String,
        c2: String,
        c3: String,
    },
    Info {
        label: String,
        value: String,
        tone: RowTone,
    },
    Pair {
        l_label: String,
        l_value: String,
        l_tone: RowTone,
        r_label: String,
        r_value: String,
        r_tone: RowTone,
    },
    Note {
        text: String,
        tone: RowTone,
    },
    Item {
        label: String,
        detail: String,
        value: String,
        tone: RowTone,
        action: SettingsAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowTone {
    Normal,
    Muted,
    Ok,
    Warn,
    Err,
}

#[derive(Debug, Clone, Default)]
pub struct HostInfo {
    pub os: String,
    pub arch: String,
    pub kernel: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview = 0,
    Sites = 1,
    Firewall = 2,
    Blocklist = 3,
    Ssh = 4,
    Intel = 5,
    System = 6,
}

#[cfg(test)]
impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Overview,
        Tab::Sites,
        Tab::Firewall,
        Tab::Blocklist,
        Tab::Ssh,
        Tab::Intel,
        Tab::System,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFilter {
    All,
    Proxy,
    Certbot,
    Fail2ban,
}

impl LogFilter {
    pub fn options(is_nginx: bool) -> &'static [LogFilter] {
        if is_nginx {
            &[
                LogFilter::All,
                LogFilter::Proxy,
                LogFilter::Certbot,
                LogFilter::Fail2ban,
            ]
        } else {
            &[LogFilter::All, LogFilter::Proxy, LogFilter::Fail2ban]
        }
    }

    pub fn next(self, is_nginx: bool) -> Self {
        let opts = Self::options(is_nginx);
        let idx = opts.iter().position(|&f| f == self).unwrap_or(0);
        opts[(idx + 1) % opts.len()]
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SiteItem {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub upstream: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CertItem {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub expiry: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PortRule {
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub note: String,
}

impl PortRule {
    pub fn display_note(&self, is_ssh: bool, fallback: &str) -> String {
        let custom = self.note.trim();
        if is_ssh {
            if custom.is_empty() {
                "当前 SSH".to_string()
            } else {
                format!("SSH · {}", custom)
            }
        } else if !custom.is_empty() {
            custom.to_string()
        } else if self.port == "443" && self.proto == "tcp" {
            "HTTPS".to_string()
        } else if self.port == "443" && self.proto == "udp" {
            "HTTP/3".to_string()
        } else if self.port == "80" && self.proto == "tcp" {
            "HTTP".to_string()
        } else {
            fallback.to_string()
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct FirewallData {
    #[serde(default)]
    pub nft_available: bool,
    #[serde(default)]
    pub running: bool,
    #[serde(default)]
    pub boot_enabled: bool,
    #[serde(default)]
    pub ipv4_in: bool,
    #[serde(default)]
    pub ipv6_in: bool,
    #[serde(default)]
    pub intel_running: bool,
    #[serde(default)]
    pub intel_entries: String,
    #[serde(default)]
    pub ports: Vec<PortRule>,
    #[serde(default)]
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct BannedItem {
    #[serde(default)]
    pub jail: String,
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SshKeyItem {
    #[serde(default)]
    pub index: usize,
    #[serde(default)]
    pub raw: String,
}

impl SshKeyItem {
    pub fn parts(&self) -> (&str, String, &str) {
        let mut iter = self.raw.split_whitespace();
        let kind = iter.next().unwrap_or("");
        let blob = iter.next().unwrap_or("");
        let comment = iter.next().unwrap_or("");
        let is_key = kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-");
        if !is_key {
            let trimmed = self.raw.trim();
            let short: String = trimmed.chars().take(48).collect();
            return ("注释/其它", short, "");
        }
        let short_blob = if blob.len() > 24 {
            format!("{}…{}", &blob[..14], &blob[blob.len() - 8..])
        } else {
            blob.to_string()
        };
        (kind, short_blob, comment)
    }

    pub fn is_valid_key_line(&self) -> bool {
        let mut iter = self.raw.split_whitespace();
        let Some(kind) = iter.next() else {
            return false;
        };
        let Some(blob) = iter.next() else {
            return false;
        };
        (kind.starts_with("ssh-") || kind.starts_with("ecdsa-") || kind.starts_with("sk-"))
            && !blob.is_empty()
            && blob
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SshData {
    #[serde(default)]
    pub ports: Vec<String>,
    #[serde(default)]
    pub password_auth: String,
    #[serde(default)]
    pub pubkey_auth: String,
    #[serde(default)]
    pub kbd_auth: String,
    #[serde(default)]
    pub root_pw_ready: bool,
    #[serde(default)]
    pub ssh_conn_family: String,
    #[serde(default)]
    pub keys: Vec<SshKeyItem>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PanelData {
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub backend_error: String,
    #[serde(default)]
    pub cf_token_set: Option<bool>,
    #[serde(default)]
    pub sites: Vec<SiteItem>,
    #[serde(default)]
    pub certs: Vec<CertItem>,
    #[serde(default)]
    pub firewall: FirewallData,
    #[serde(default)]
    pub banned: Vec<BannedItem>,
    #[serde(default)]
    pub whitelist: Vec<String>,
    #[serde(default)]
    pub ssh: SshData,
    #[serde(default)]
    pub repo: String,
    #[serde(default)]
    pub reporting_on: bool,
    #[serde(default)]
    pub report_key_set: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LogsData {
    #[serde(default)]
    pub proxy: Vec<String>,
    #[serde(default)]
    pub certbot: Vec<String>,
    #[serde(default)]
    pub fail2ban: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum FieldKind {
    Text { masked: bool },
    Toggle { options: Vec<&'static str>, idx: usize },
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub label: &'static str,
    pub placeholder: &'static str,
    pub value: String,
    pub kind: FieldKind,
}

impl FormField {
    pub fn text(label: &'static str, placeholder: &'static str) -> Self {
        Self {
            label,
            placeholder,
            value: String::new(),
            kind: FieldKind::Text { masked: false },
        }
    }

    pub fn secret(label: &'static str, placeholder: &'static str) -> Self {
        Self {
            label,
            placeholder,
            value: String::new(),
            kind: FieldKind::Text { masked: true },
        }
    }

    pub fn toggle(label: &'static str, options: Vec<&'static str>) -> Self {
        let initial = options.first().copied().unwrap_or("").to_string();
        Self {
            label,
            placeholder: "",
            value: initial,
            kind: FieldKind::Toggle { options, idx: 0 },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormSubmit {
    AddSite,
    SetCfToken,
    OpenPort,
    BanIp,
    UnbanIp,
    WhitelistAdd,
    ChangeSshPort,
    AddSshKey,
    ChangeRootPassword,
    SetAbuseKey,
}

#[derive(Debug, Clone)]
pub struct FormModal {
    pub title: String,
    pub hint: String,
    pub fields: Vec<FormField>,
    pub active: usize,
    pub error: Option<String>,
    pub submit: FormSubmit,
}

#[derive(Debug, Clone)]
pub struct ConfirmModal {
    pub title: String,
    pub lines: Vec<String>,
    pub danger: bool,
    pub require_yes: bool,
    pub typed: String,
    pub action: PendingAction,
}

#[derive(Debug, Clone)]
pub struct ViewerModal {
    pub title: String,
    pub lines: Vec<String>,
    pub scroll: usize,
}

#[derive(Debug, Clone)]
pub enum Modal {
    Form(FormModal),
    Confirm(ConfirmModal),
    Viewer(ViewerModal),
    Help,
}

#[derive(Debug, Clone)]
pub struct Toast {
    pub ok: bool,
    pub summary: String,
    pub full_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingAction {
    SiteAdd { domain: String, upstream: String },
    SiteDel { domain: String },
    SetCfToken { token: String },
    FwOpen {
        proto: String,
        port: String,
        source: String,
        note: String,
    },
    FwClose { proto: String, port: String, source: String },
    FwFamily { family: String, enable: bool },
    FwApply,
    BanIp { ip: String },
    UnbanIp { ip: String },
    WhitelistAdd { entries: String },
    WhitelistDel { entry: String },
    WhitelistEdit,
    SshPort { port: String },
    SshAuth { which: String, confirmed_yes: bool },
    SshKeyAdd { pubkey: String },
    SshKeyDel {
        index: usize,
        raw: String,
        confirmed_yes: bool,
    },
    SshPassword { p1: String, p2: String },
    SyncIntel,
    FlushReport,
    SetAbuseKey { key: String },
    ToggleReport,
    ViewRuleset,
    Update,
    Uninstall,
}

impl PendingAction {
    pub fn busy_label(&self) -> &'static str {
        match self {
            PendingAction::SiteAdd { .. } => "正在添加站点并校验/重载配置...",
            PendingAction::SiteDel { .. } => "正在删除站点并重载配置...",
            PendingAction::SetCfToken { .. } => "正在保存 Cloudflare API Token...",
            PendingAction::FwOpen { .. } => "正在开放端口并应用 nftables 规则...",
            PendingAction::FwClose { .. } => "正在关闭端口并应用 nftables 规则...",
            PendingAction::FwFamily { .. } => "正在更新入站协议族策略...",
            PendingAction::FwApply => "正在重新应用防火墙规则...",
            PendingAction::BanIp { .. } => "正在封禁 IP...",
            PendingAction::UnbanIp { .. } => "正在解封 IP...",
            PendingAction::WhitelistAdd { .. } => "正在写入白名单并同步内核策略...",
            PendingAction::WhitelistDel { .. } => "正在删除白名单并同步内核策略...",
            PendingAction::WhitelistEdit => "正在打开编辑器...",
            PendingAction::SshPort { .. } => "正在配置新 SSH 端口并校验监听...",
            PendingAction::SshAuth { .. } => "正在更新 SSH 认证策略并重载 sshd...",
            PendingAction::SshKeyAdd { .. } => "正在验证并添加 SSH 公钥...",
            PendingAction::SshKeyDel { .. } => "正在删除 SSH 公钥...",
            PendingAction::SshPassword { .. } => "正在更新 root 密码...",
            PendingAction::SyncIntel => "正在同步威胁情报并应用内核策略...",
            PendingAction::FlushReport => "正在发送 AbuseIPDB 上报队列...",
            PendingAction::SetAbuseKey { .. } => "正在保存 AbuseIPDB API Key...",
            PendingAction::ToggleReport => "正在切换自动上报开关...",
            PendingAction::ViewRuleset => "正在读取全部 nftables 规则...",
            PendingAction::Update => "正在启动更新...",
            PendingAction::Uninstall => "正在启动卸载...",
        }
    }

    pub fn is_interactive(&self) -> bool {
        matches!(
            self,
            PendingAction::WhitelistEdit | PendingAction::Update | PendingAction::Uninstall
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandEffect {
    None,
    Quit,
    RefreshAll,
    RefreshLogs,
    RunAction(PendingAction),
}

pub struct App {
    pub tab: Tab,
    pub home_idx: usize,
    pub settings_idx: usize,
    pub host: HostInfo,
    pub snapshot: Snapshot<'static>,
    pub panel: PanelData,
    pub logs: LogsData,
    pub logs_loaded: bool,
    pub last_refreshed: String,
    pub load_error: Option<String>,
    pub intel_last_output: Vec<String>,
    pub log_filter: LogFilter,

    pub modal: Option<Modal>,
    pub toast: Option<Toast>,
    pub busy: Option<String>,
    pub refreshing: Option<String>,
}

impl App {
    pub fn new(version: &'static str) -> Self {
        Self {
            tab: Tab::Overview,
            home_idx: 0,
            settings_idx: 0,
            host: HostInfo::default(),
            snapshot: Snapshot::empty(version),
            panel: PanelData::default(),
            logs: LogsData::default(),
            logs_loaded: false,
            last_refreshed: "--:--:--".to_string(),
            load_error: None,
            intel_last_output: Vec::new(),
            log_filter: LogFilter::All,
            modal: None,
            toast: None,
            busy: None,
            refreshing: None,
        }
    }

    pub fn is_nginx(&self) -> bool {
        self.effective_backend() == Some("nginx")
    }

    pub fn effective_backend(&self) -> Option<&str> {
        self.snapshot.backend.or_else(|| match self.panel.backend.as_str() {
            "caddy" => Some("caddy"),
            "nginx" => Some("nginx"),
            _ => None,
        })
    }

    pub fn backend_label(&self) -> &'static str {
        match self.effective_backend() {
            Some("nginx") => "Nginx",
            Some("caddy") => "Caddy",
            _ => "后端",
        }
    }

    pub fn health_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();
        let backend = self.effective_backend();
        let proxy_label = self.backend_label();
        if backend.is_none() {
            issues.push("后端状态未知".to_string());
        } else {
            match self.snapshot.services.proxy {
                Some("active") => {}
                Some(_) => issues.push(format!("{} 未运行", proxy_label)),
                None => issues.push(format!("{} 状态未知", proxy_label)),
            }
        }
        if !self.panel.backend_error.is_empty() {
            issues.push(self.panel.backend_error.clone());
        }
        match self.snapshot.services.fail2ban {
            Some("active") => {}
            Some(_) => issues.push("Fail2Ban 未运行".to_string()),
            None => issues.push("Fail2Ban 状态未知".to_string()),
        }
        match self.snapshot.firewall_table_present {
            Some(true) => {}
            Some(false) => issues.push("防火墙未就绪".to_string()),
            None => issues.push("防火墙状态未知".to_string()),
        }
        match self.snapshot.intel_table_present {
            Some(true) => {}
            Some(false) => issues.push("情报策略未应用".to_string()),
            None => issues.push("情报策略状态未知".to_string()),
        }
        if !self.panel.firewall.conflicts.is_empty() {
            issues.push("检测到其他 nftables 入站规则冲突".to_string());
        }
        issues
    }

    pub fn filtered_logs(&self) -> Vec<(&'static str, &str)> {
        let proxy_tag = if self.is_nginx() { "nginx" } else { "caddy" };
        let mut out = Vec::new();
        match self.log_filter {
            LogFilter::All => {
                for l in &self.logs.proxy {
                    out.push((proxy_tag, l.as_str()));
                }
                if self.is_nginx() {
                    for l in &self.logs.certbot {
                        out.push(("certbot", l.as_str()));
                    }
                }
                for l in &self.logs.fail2ban {
                    out.push(("fail2ban", l.as_str()));
                }
            }
            LogFilter::Proxy => {
                for l in &self.logs.proxy {
                    out.push((proxy_tag, l.as_str()));
                }
            }
            LogFilter::Certbot => {
                for l in &self.logs.certbot {
                    out.push(("certbot", l.as_str()));
                }
            }
            LogFilter::Fail2ban => {
                for l in &self.logs.fail2ban {
                    out.push(("fail2ban", l.as_str()));
                }
            }
        }
        out
    }

    pub fn clamp_selections(&mut self) {
        if !self.is_nginx() && self.log_filter == LogFilter::Certbot {
            self.log_filter = LogFilter::All;
        }
        let item_count = self
            .settings_rows()
            .iter()
            .filter(|r| matches!(r, SettingsRow::Item { .. }))
            .count();
        clamp_idx(&mut self.settings_idx, item_count);
    }

    pub fn apply_action_result(&mut self, action: &PendingAction, ok: bool, output: String) {
        let clean = strip_ansi(&output);
        let lines: Vec<String> = clean
            .lines()
            .map(|l| l.trim_end().to_string())
            .filter(|l| !l.trim().is_empty())
            .collect();

        if matches!(action, PendingAction::ViewRuleset) {
            if ok {
                let view_lines = if clean.is_empty() {
                    vec!["（规则集为空）".to_string()]
                } else {
                    clean.lines().map(str::to_string).collect()
                };
                self.modal = Some(Modal::Viewer(ViewerModal {
                    title: "防火墙 / 全部 nftables 规则".to_string(),
                    lines: view_lines,
                    scroll: 0,
                }));
            } else {
                self.toast = Some(Toast {
                    ok: false,
                    summary: lines
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "无法读取 nftables 规则。".to_string()),
                    full_output: clean,
                });
            }
            return;
        }

        if matches!(
            action,
            PendingAction::SyncIntel
                | PendingAction::FlushReport
                | PendingAction::SetAbuseKey { .. }
                | PendingAction::ToggleReport
        ) {
            self.intel_last_output = if lines.is_empty() {
                vec![if ok { "执行完成。".into() } else { "执行失败。".into() }]
            } else {
                lines.clone()
            };
        }

        let summary = if ok {
            lines
                .last()
                .cloned()
                .unwrap_or_else(|| "操作已完成。".to_string())
        } else {
            lines
                .first()
                .cloned()
                .unwrap_or_else(|| "操作失败，请按 o 查看详情。".to_string())
        };

        // Surface multi-line errors immediately so rollback/Certbot diagnostics are never hidden.
        if !ok && lines.len() > 1 {
            self.modal = Some(Modal::Viewer(ViewerModal {
                title: "执行失败 · 详细输出".to_string(),
                lines: lines.clone(),
                scroll: 0,
            }));
        }

        self.toast = Some(Toast {
            ok,
            summary,
            full_output: clean,
        });
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> CommandEffect {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return CommandEffect::Quit;
        }
        if self.busy.is_some() {
            return CommandEffect::None;
        }
        if self.modal.is_some() {
            return self.handle_modal_key(key);
        }
        self.handle_settings_key(key)
    }

    fn switch_tab(&mut self, next: Tab) -> CommandEffect {
        self.tab = next;
        self.settings_idx = 0;
        self.clamp_selections();
        if next == Tab::System && !self.logs_loaded {
            CommandEffect::RefreshLogs
        } else {
            CommandEffect::None
        }
    }

    pub fn settings_rows(&self) -> Vec<SettingsRow> {
        match self.tab {
            Tab::Overview => Vec::new(),
            Tab::Sites => self.settings_sites_rows(),
            Tab::Firewall => self.settings_firewall_rows(),
            Tab::Blocklist => self.settings_blocklist_rows(),
            Tab::Ssh => self.settings_ssh_rows(),
            Tab::Intel => self.settings_intel_rows(),
            Tab::System => self.settings_system_rows(),
        }
    }

    pub fn compact_next_timer(&self, next: Option<&str>) -> String {
        next.map(compact_next_time)
            .unwrap_or_else(|| "已启用".to_string())
    }

    fn settings_sites_rows(&self) -> Vec<SettingsRow> {
        let mut rows = vec![SettingsRow::Section("代理与证书".to_string())];
        if !self.panel.backend_error.is_empty() {
            rows.push(SettingsRow::Info {
                label: "代理后端".to_string(),
                value: self.panel.backend_error.clone(),
                tone: RowTone::Err,
            });
            rows.push(SettingsRow::Note {
                text: "请重新运行安装器修复；站点操作已停止。".to_string(),
                tone: RowTone::Muted,
            });
            return rows;
        }
        let (cert_txt, cert_tone) = if self.panel.cf_token_set == Some(true) {
            ("CF DNS-01（已配置）".to_string(), RowTone::Ok)
        } else if self.is_nginx() {
            ("CF DNS-01（未配置）".to_string(), RowTone::Warn)
        } else {
            ("Caddy 自动 HTTPS".to_string(), RowTone::Normal)
        };
        let proxy_txt = match self.snapshot.services.proxy {
            Some("active") => format!("{}（运行中）", self.backend_label()),
            Some(_) => format!("{}（未运行）", self.backend_label()),
            None => self.backend_label().to_string(),
        };
        let proxy_tone = match self.snapshot.services.proxy {
            Some("active") => RowTone::Ok,
            Some(_) => RowTone::Err,
            None => RowTone::Warn,
        };
        rows.push(SettingsRow::Pair {
            l_label: "代理后端".to_string(),
            l_value: proxy_txt,
            l_tone: proxy_tone,
            r_label: "证书模式".to_string(),
            r_value: cert_txt,
            r_tone: cert_tone,
        });

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section(format!(
            "受保护站点（{}）",
            self.panel.sites.len()
        )));
        if self.panel.sites.is_empty() {
            rows.push(SettingsRow::Note {
                text: "暂无站点。选中下方「+ 添加新站点」开始配置反向代理。".to_string(),
                tone: RowTone::Muted,
            });
        } else {
            rows.push(SettingsRow::TableHead {
                c1: "域名".to_string(),
                c2: "上游地址".to_string(),
                c3: "证书状态".to_string(),
            });
            for (i, s) in self.panel.sites.iter().enumerate() {
                let (cert_label, tone) = self.site_cert_plain(&s.domain);
                rows.push(SettingsRow::Item {
                    label: s.domain.clone(),
                    detail: s.upstream.clone(),
                    value: cert_label,
                    tone,
                    action: SettingsAction::DelSite(i),
                });
            }
        }
        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section("操作".to_string()));
        rows.push(SettingsRow::Item {
            label: "+ 添加新站点".to_string(),
            detail: String::new(),
            value: "配置域名与上游反向代理".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::AddSite,
        });
        rows.push(SettingsRow::Item {
            label: "Cloudflare API Token".to_string(),
            detail: String::new(),
            value: if self.panel.cf_token_set == Some(true) {
                "已配置".to_string()
            } else {
                "未配置".to_string()
            },
            tone: if self.panel.cf_token_set == Some(true) {
                RowTone::Ok
            } else {
                RowTone::Muted
            },
            action: SettingsAction::SetCfToken,
        });
        rows
    }

    fn settings_firewall_rows(&self) -> Vec<SettingsRow> {
        let (fw_txt, fw_tone) = if !self.panel.firewall.nft_available {
            ("无法访问 nftables", RowTone::Err)
        } else if self.panel.firewall.running {
            ("nftables 运行中", RowTone::Ok)
        } else {
            ("未就绪", RowTone::Warn)
        };
        let (boot_txt, boot_tone) = if self.panel.firewall.boot_enabled {
            ("已开启", RowTone::Ok)
        } else {
            ("未开启", RowTone::Err)
        };
        let (intel_txt, intel_tone) = if self.panel.firewall.intel_running {
            (
                self.panel
                    .firewall
                    .intel_entries
                    .parse::<u64>()
                    .ok()
                    .map(|n| format!("{} 条已生效", format_thousands(n)))
                    .unwrap_or_else(|| "运行中".to_string()),
                RowTone::Ok,
            )
        } else {
            ("未应用".to_string(), RowTone::Warn)
        };

        let mut rows = vec![
            SettingsRow::Section("防火墙状态".to_string()),
            SettingsRow::Pair {
                l_label: "引擎状态".to_string(),
                l_value: fw_txt.to_string(),
                l_tone: fw_tone,
                r_label: "开机恢复".to_string(),
                r_value: boot_txt.to_string(),
                r_tone: boot_tone,
            },
            SettingsRow::Pair {
                l_label: "情报内核".to_string(),
                l_value: intel_txt,
                l_tone: intel_tone,
                r_label: "默认策略".to_string(),
                r_value: "拒绝未放行入站".to_string(),
                r_tone: RowTone::Normal,
            },
        ];
        for c in &self.panel.firewall.conflicts {
            rows.push(SettingsRow::Note {
                text: format!("警告：{}", c),
                tone: RowTone::Warn,
            });
        }
        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section("入站协议族".to_string()));
        rows.push(SettingsRow::Item {
            label: "IPv4 入站".to_string(),
            detail: String::new(),
            value: if self.panel.firewall.ipv4_in {
                "已开启".to_string()
            } else {
                "已关闭".to_string()
            },
            tone: if self.panel.firewall.ipv4_in {
                RowTone::Ok
            } else {
                RowTone::Err
            },
            action: SettingsAction::ToggleIpv4,
        });
        rows.push(SettingsRow::Item {
            label: "IPv6 入站".to_string(),
            detail: String::new(),
            value: if self.panel.firewall.ipv6_in {
                "已开启".to_string()
            } else {
                "已关闭".to_string()
            },
            tone: if self.panel.firewall.ipv6_in {
                RowTone::Ok
            } else {
                RowTone::Muted
            },
            action: SettingsAction::ToggleIpv6,
        });

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section(format!(
            "开放端口（{}）",
            self.panel.firewall.ports.len()
        )));
        if self.panel.firewall.ports.is_empty() {
            rows.push(SettingsRow::Note {
                text: "暂无端口规则，请开放端口或重新应用规则。".to_string(),
                tone: RowTone::Muted,
            });
        } else {
            rows.push(SettingsRow::TableHead {
                c1: "协议与端口".to_string(),
                c2: "允许来源".to_string(),
                c3: "备注".to_string(),
            });
            for (i, p) in self.panel.firewall.ports.iter().enumerate() {
                let is_ssh =
                    p.proto == "tcp" && self.panel.ssh.ports.iter().any(|sp| sp == &p.port);
                let port_lbl = format!("{:<4} {}", p.proto.to_uppercase(), p.port);
                let src = if p.source.is_empty() || p.source == "any" {
                    "所有来源".to_string()
                } else {
                    p.source.clone()
                };
                let note = p.display_note(is_ssh, "");
                let tone = if is_ssh {
                    RowTone::Warn
                } else if !p.note.trim().is_empty() {
                    RowTone::Normal
                } else {
                    RowTone::Muted
                };
                rows.push(SettingsRow::Item {
                    label: port_lbl,
                    detail: src,
                    value: note,
                    tone,
                    action: SettingsAction::ClosePort(i),
                });
            }
        }
        rows.push(SettingsRow::Item {
            label: "+ 开放新端口".to_string(),
            detail: String::new(),
            value: "新增入站放行规则".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::OpenPort,
        });

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section("规则维护".to_string()));
        rows.push(SettingsRow::Item {
            label: "封禁 IP 与白名单管理".to_string(),
            detail: format!(
                "{} 条封禁 · {} 条白名单",
                self.panel.banned.len(),
                self.panel.whitelist.len()
            ),
            value: "按 3 直达 ->".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::GoBlocklist,
        });
        rows.push(SettingsRow::Item {
            label: "查看全部 nftables 规则".to_string(),
            detail: String::new(),
            value: "全屏浏览规则集".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::ViewRuleset,
        });
        rows.push(SettingsRow::Item {
            label: "重新应用防火墙规则".to_string(),
            detail: String::new(),
            value: "按配置重建入站规则".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::FwApply,
        });
        rows
    }

    fn settings_blocklist_rows(&self) -> Vec<SettingsRow> {
        let banned_total = self
            .snapshot
            .banned_total
            .map(format_thousands)
            .unwrap_or_else(|| "未知".to_string());
        let (f2b_txt, f2b_tone) = match self.snapshot.services.fail2ban {
            Some("active") => ("运行中", RowTone::Ok),
            Some(_) => ("未运行", RowTone::Err),
            None => ("未知", RowTone::Warn),
        };
        let mut rows = vec![
            SettingsRow::Section("封禁与白名单概览".to_string()),
            SettingsRow::Pair {
                l_label: "活跃行为封禁".to_string(),
                l_value: format!("{} 条（累计 {}）", self.panel.banned.len(), banned_total),
                l_tone: RowTone::Normal,
                r_label: "Fail2Ban".to_string(),
                r_value: f2b_txt.to_string(),
                r_tone: f2b_tone,
            },
            SettingsRow::Pair {
                l_label: "IP 白名单".to_string(),
                l_value: format!("{} 条", self.panel.whitelist.len()),
                l_tone: RowTone::Normal,
                r_label: "豁免范围".to_string(),
                r_value: "免封禁/上报（仍受端口限制）".to_string(),
                r_tone: RowTone::Muted,
            },
            SettingsRow::Blank,
            SettingsRow::Section(format!("封禁 IP 管理（{}）", self.panel.banned.len())),
            SettingsRow::Item {
                label: "+ 立即封禁 IP".to_string(),
                detail: String::new(),
                value: "支持单个 IPv4 / IPv6".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::BanIpPrompt,
            },
            SettingsRow::Item {
                label: "手动输入 IP 解封".to_string(),
                detail: String::new(),
                value: "从所有 Fail2Ban Jail 移除".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::UnbanIpPrompt,
            },
        ];
        if self.panel.banned.is_empty() {
            rows.push(SettingsRow::Note {
                text: "当前没有活跃行为封禁（威胁情报名单在内核独立拦截）。".to_string(),
                tone: RowTone::Muted,
            });
        } else {
            rows.push(SettingsRow::TableHead {
                c1: "封禁 IP（回车解封）".to_string(),
                c2: "触发规则（Jail）".to_string(),
                c3: String::new(),
            });
            for (i, b) in self.panel.banned.iter().enumerate() {
                rows.push(SettingsRow::Item {
                    label: b.ip.clone(),
                    detail: b.jail.clone(),
                    value: String::new(),
                    tone: RowTone::Normal,
                    action: SettingsAction::UnbanSelected(i),
                });
            }
        }

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section(format!(
            "IP 白名单管理（{}）",
            self.panel.whitelist.len()
        )));
        rows.push(SettingsRow::Item {
            label: "+ 添加 IP 或网段".to_string(),
            detail: String::new(),
            value: "支持逗号或空格批量添加".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::WlAddPrompt,
        });
        rows.push(SettingsRow::Item {
            label: "用外部编辑器打开白名单".to_string(),
            detail: String::new(),
            value: "保存后自动同步内核策略".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::WlEdit,
        });
        if self.panel.whitelist.is_empty() {
            rows.push(SettingsRow::Note {
                text: "白名单为空。".to_string(),
                tone: RowTone::Muted,
            });
        } else {
            for (i, entry) in self.panel.whitelist.iter().enumerate() {
                rows.push(SettingsRow::Item {
                    label: entry.clone(),
                    detail: String::new(),
                    value: "回车删除".to_string(),
                    tone: RowTone::Muted,
                    action: SettingsAction::WlDelSelected(i),
                });
            }
        }
        rows
    }

    fn settings_ssh_rows(&self) -> Vec<SettingsRow> {
        let port_str = if self.panel.ssh.ports.is_empty() {
            "无法读取".to_string()
        } else {
            self.panel.ssh.ports.join(", ")
        };
        let conn_str = if self.panel.ssh.ssh_conn_family.is_empty() {
            "本地会话".to_string()
        } else {
            self.panel.ssh.ssh_conn_family.clone()
        };
        let (pw_txt, pw_tone) = ssh_tone(&self.panel.ssh.password_auth);
        let (pk_txt, pk_tone) = ssh_tone(&self.panel.ssh.pubkey_auth);

        let mut rows = vec![
            SettingsRow::Section("当前状态".to_string()),
            SettingsRow::Pair {
                l_label: "监听端口".to_string(),
                l_value: port_str.clone(),
                l_tone: if self.panel.ssh.ports.len() > 1 {
                    RowTone::Warn
                } else {
                    RowTone::Normal
                },
                r_label: "当前连接".to_string(),
                r_value: conn_str,
                r_tone: RowTone::Normal,
            },
            SettingsRow::Pair {
                l_label: "密码认证".to_string(),
                l_value: pw_txt.to_string(),
                l_tone: pw_tone,
                r_label: "密钥认证".to_string(),
                r_value: pk_txt.to_string(),
                r_tone: pk_tone,
            },
        ];
        if self.panel.ssh.password_auth == "on" && !self.panel.ssh.root_pw_ready {
            rows.push(SettingsRow::Note {
                text: "提示：root 能否独立使用密码未确认（可能受 SSH 策略限制）。".to_string(),
                tone: RowTone::Warn,
            });
        }
        if self.panel.ssh.password_auth == "off" && self.panel.ssh.kbd_auth == "on" {
            rows.push(SettingsRow::Note {
                text: "提示：键盘交互认证仍开启，可能仍允许密码登录。".to_string(),
                tone: RowTone::Warn,
            });
        }

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section("端口与认证设置".to_string()));
        rows.push(SettingsRow::Item {
            label: "SSH 监听端口".to_string(),
            detail: String::new(),
            value: port_str,
            tone: if self.panel.ssh.ports.len() > 1 {
                RowTone::Warn
            } else {
                RowTone::Normal
            },
            action: SettingsAction::ChangeSshPort,
        });
        rows.push(SettingsRow::Item {
            label: "全局密码认证".to_string(),
            detail: String::new(),
            value: pw_txt.to_string(),
            tone: pw_tone,
            action: SettingsAction::ToggleSshPassword,
        });
        rows.push(SettingsRow::Item {
            label: "全局密钥认证".to_string(),
            detail: String::new(),
            value: pk_txt.to_string(),
            tone: pk_tone,
            action: SettingsAction::ToggleSshPubkey,
        });
        rows.push(SettingsRow::Item {
            label: "修改 root 登录密码".to_string(),
            detail: String::new(),
            value: "更新系统 root 密码".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::ChangeRootPassword,
        });

        rows.push(SettingsRow::Blank);
        rows.push(SettingsRow::Section(format!(
            "root 公钥（{}）",
            self.panel.ssh.keys.len()
        )));
        if self.panel.ssh.keys.is_empty() {
            rows.push(SettingsRow::Note {
                text: "尚未配置公钥。".to_string(),
                tone: RowTone::Muted,
            });
        } else {
            rows.push(SettingsRow::TableHead {
                c1: "序号与类型".to_string(),
                c2: "指纹与备注".to_string(),
                c3: String::new(),
            });
            for (i, item) in self.panel.ssh.keys.iter().enumerate() {
                let (kind, digest, comment) = item.parts();
                let detail = if comment.is_empty() {
                    digest
                } else {
                    format!("{}  {}", digest, comment)
                };
                rows.push(SettingsRow::Item {
                    label: format!("#{} {}", item.index, kind),
                    detail,
                    value: String::new(),
                    tone: RowTone::Normal,
                    action: SettingsAction::DelSshKey(i),
                });
            }
        }
        rows.push(SettingsRow::Item {
            label: "+ 添加 root 公钥".to_string(),
            detail: String::new(),
            value: "追加 SSH 认证公钥".to_string(),
            tone: RowTone::Muted,
            action: SettingsAction::AddSshKey,
        });
        rows
    }

    fn settings_intel_rows(&self) -> Vec<SettingsRow> {
        let local = self
            .snapshot
            .intel
            .local_entries
            .map(|n| match self.snapshot.intel.synced_age_hours {
                Some(h) => format!("{} 条（{}h 前）", format_thousands(n), h),
                None => format!("{} 条", format_thousands(n)),
            })
            .unwrap_or_else(|| "未知".to_string());
        let (applied, applied_tone) = match self.snapshot.intel_table_present {
            Some(true) => (
                self.snapshot
                    .intel
                    .applied_entries
                    .map(|n| format!("已应用 {} 条", format_thousands(n)))
                    .unwrap_or_else(|| "运行中".to_string()),
                RowTone::Ok,
            ),
            Some(false) => ("未应用".to_string(), RowTone::Warn),
            None => ("未知".to_string(), RowTone::Warn),
        };
        let (rep_txt, rep_tone) = if self.panel.reporting_on {
            if self.panel.report_key_set {
                ("已开启", RowTone::Ok)
            } else {
                ("等待配置 Key", RowTone::Warn)
            }
        } else {
            ("已关闭", RowTone::Muted)
        };
        let (key_txt, key_tone) = if self.panel.report_key_set {
            ("已配置", RowTone::Ok)
        } else {
            ("未配置", RowTone::Muted)
        };

        let mut rows = vec![
            SettingsRow::Section("情报与上报状态".to_string()),
            SettingsRow::Pair {
                l_label: "本地情报库".to_string(),
                l_value: local,
                l_tone: if self.snapshot.intel.synced_age_hours.is_some_and(|h| h > 12) {
                    RowTone::Warn
                } else {
                    RowTone::Normal
                },
                r_label: "内核策略表".to_string(),
                r_value: applied,
                r_tone: applied_tone,
            },
            SettingsRow::Pair {
                l_label: "自动上报".to_string(),
                l_value: rep_txt.to_string(),
                l_tone: rep_tone,
                r_label: "API Key".to_string(),
                r_value: key_txt.to_string(),
                r_tone: key_tone,
            },
            SettingsRow::Blank,
            SettingsRow::Section("操作与配置".to_string()),
            SettingsRow::Item {
                label: "立即同步威胁情报并应用内核".to_string(),
                detail: String::new(),
                value: "拉取最新情报库".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::SyncIntel,
            },
            SettingsRow::Item {
                label: "立即发送上报队列".to_string(),
                detail: String::new(),
                value: "冲刷待上报记录".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::FlushReport,
            },
            SettingsRow::Item {
                label: "AbuseIPDB API Key".to_string(),
                detail: String::new(),
                value: key_txt.to_string(),
                tone: key_tone,
                action: SettingsAction::SetAbuseKey,
            },
            SettingsRow::Item {
                label: "自动上报开关".to_string(),
                detail: String::new(),
                value: if self.panel.reporting_on {
                    "已开启".to_string()
                } else {
                    "已关闭".to_string()
                },
                tone: if self.panel.reporting_on {
                    RowTone::Ok
                } else {
                    RowTone::Muted
                },
                action: SettingsAction::ToggleReport,
            },
        ];

        rows.push(SettingsRow::Blank);
        if !self.intel_last_output.is_empty() {
            rows.push(SettingsRow::Section("最近输出".to_string()));
            for line in self.intel_last_output.iter().take(6) {
                rows.push(SettingsRow::Note {
                    text: line.clone(),
                    tone: RowTone::Muted,
                });
            }
        } else {
            let sync_c = timer_cell(
                "威胁情报同步",
                self.snapshot.timers.sync.state,
                self.snapshot.timers.sync.next.as_deref(),
            );
            let rep_c = timer_cell(
                "上报队列冲刷",
                self.snapshot.timers.report.state,
                self.snapshot.timers.report.next.as_deref(),
            );
            rows.push(SettingsRow::Section("定时计划".to_string()));
            rows.push(SettingsRow::Pair {
                l_label: sync_c.0,
                l_value: sync_c.1,
                l_tone: sync_c.2,
                r_label: rep_c.0,
                r_value: rep_c.1,
                r_tone: rep_c.2,
            });
        }
        rows
    }

    fn settings_system_rows(&self) -> Vec<SettingsRow> {
        let repo = if self.panel.repo.is_empty() {
            "jasper-khan/abuseguard"
        } else {
            self.panel.repo.as_str()
        };
        let filter_lbl = match self.log_filter {
            LogFilter::All => "全部",
            LogFilter::Proxy => self.backend_label(),
            LogFilter::Certbot => "Certbot",
            LogFilter::Fail2ban => "Fail2Ban",
        };
        let logs = self.filtered_logs();
        let log_count = logs.len();

        let mut rows = vec![
            SettingsRow::Section("版本与日志".to_string()),
            SettingsRow::Pair {
                l_label: "当前版本".to_string(),
                l_value: format!("v{}", self.snapshot.version),
                l_tone: RowTone::Normal,
                r_label: "代码仓库".to_string(),
                r_value: repo.to_string(),
                r_tone: RowTone::Muted,
            },
            SettingsRow::Pair {
                l_label: "日志来源".to_string(),
                l_value: filter_lbl.to_string(),
                l_tone: RowTone::Normal,
                r_label: "已载入条数".to_string(),
                r_value: format!("{} 条", log_count),
                r_tone: RowTone::Normal,
            },
            SettingsRow::Blank,
            SettingsRow::Section("操作与维护".to_string()),
            SettingsRow::Item {
                label: "日志来源".to_string(),
                detail: String::new(),
                value: filter_lbl.to_string(),
                tone: RowTone::Normal,
                action: SettingsAction::CycleLogFilter,
            },
            SettingsRow::Item {
                label: "全屏滚动查看日志".to_string(),
                detail: String::new(),
                value: format!("{} 条 ->", log_count),
                tone: RowTone::Muted,
                action: SettingsAction::ViewLogsModal,
            },
            SettingsRow::Item {
                label: "刷新日志".to_string(),
                detail: String::new(),
                value: "重新读取最新日志".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::RefreshLogs,
            },
            SettingsRow::Item {
                label: "更新 AbuseGuard".to_string(),
                detail: String::new(),
                value: "运行官方更新流程".to_string(),
                tone: RowTone::Muted,
                action: SettingsAction::Update,
            },
            SettingsRow::Item {
                label: "卸载 AbuseGuard".to_string(),
                detail: String::new(),
                value: "进入交互卸载流程".to_string(),
                tone: RowTone::Err,
                action: SettingsAction::Uninstall,
            },
        ];

        if !logs.is_empty() {
            rows.push(SettingsRow::Blank);
            rows.push(SettingsRow::Section("最近日志预览".to_string()));
            let start = logs.len().saturating_sub(10);
            for (src, line) in &logs[start..] {
                rows.push(SettingsRow::Note {
                    text: format!("[{}] {}", src, line),
                    tone: RowTone::Muted,
                });
            }
        }
        rows
    }

    pub fn settings_context_hint(&self) -> String {
        if self.tab == Tab::Overview {
            return match self.home_idx {
                0 => "管理受保护反向代理站点与 Cloudflare DNS-01 证书配置。".to_string(),
                1 => "开关 IPv4/IPv6 入站、开放与关闭端口、查看完整 nftables 规则集。".to_string(),
                2 => "查看并解封 Fail2Ban 封禁 IP，手动封禁或管理 IP 白名单。".to_string(),
                3 => "更换 SSH 监听端口、切换密码/密钥认证策略与管理 root 公钥。".to_string(),
                4 => "同步威胁情报内核黑名单、配置 AbuseIPDB API Key 与自动上报。".to_string(),
                5 => "筛选与全屏浏览代理/Fail2Ban 日志，执行 AbuseGuard 更新或卸载。".to_string(),
                6 => "立即拉取最新威胁情报名单并刷新内核 nftables 拦截表。".to_string(),
                7 => "重新采集全部服务状态、端口、封禁、站点与威胁情报统计。".to_string(),
                8 => "退出控制面板（需要旧版编号菜单可运行 ag --classic）。".to_string(),
                _ => String::new(),
            };
        }
        let action = self
            .settings_rows()
            .into_iter()
            .filter_map(|r| match r {
                SettingsRow::Item { action, .. } => Some(action),
                _ => None,
            })
            .nth(self.settings_idx);

        match action {
            Some(SettingsAction::SyncIntel) => "按 Enter 立即拉取最新威胁情报并更新内核 nftables 策略。".to_string(),
            Some(SettingsAction::AddSite) => "按 Enter 打开表单添加反向代理域名与上游地址，自动校验并重载。".to_string(),
            Some(SettingsAction::DelSite(_)) => "按 Enter 或 d 删除选中站点（先校验配置并自动重载代理服务）。".to_string(),
            Some(SettingsAction::SetCfToken) => "按 Enter 设置或更新 Cloudflare DNS-01 API Token。".to_string(),
            Some(SettingsAction::ToggleIpv4) => "按 Enter/Space 切换 IPv4 入站；关闭当前 SSH 所在协议族需输入 yes。".to_string(),
            Some(SettingsAction::ToggleIpv6) => "按 Enter/Space 切换 IPv6 入站；关闭当前 SSH 所在协议族需输入 yes。".to_string(),
            Some(SettingsAction::OpenPort) => "按 Enter 开放新入站端口（云安全组需在云平台同步放行）。".to_string(),
            Some(SettingsAction::ClosePort(_)) => "按 Enter 或 d 关闭选中端口；关闭唯一 SSH 端口前请确认备用端口可用。".to_string(),
            Some(SettingsAction::GoBlocklist) => "按 Enter 进入封禁 IP 与白名单管理页。".to_string(),
            Some(SettingsAction::UnbanSelected(_)) => "按 Enter 或 d 解封当前选中的 IP。".to_string(),
            Some(SettingsAction::BanIpPrompt) => "按 Enter 手动输入 IPv4/IPv6 地址立即封禁。".to_string(),
            Some(SettingsAction::UnbanIpPrompt) => "按 Enter 手动输入 IP 地址从全部 Jail 解封。".to_string(),
            Some(SettingsAction::WlAddPrompt) => "按 Enter 添加单个或批量 IP/CIDR 白名单条目。".to_string(),
            Some(SettingsAction::WlDelSelected(_)) => "按 Enter 或 d 从白名单移除该条目并同步内核策略。".to_string(),
            Some(SettingsAction::WlEdit) => "按 Enter 暂离面板并用系统默认编辑器直接编辑白名单文件。".to_string(),
            Some(SettingsAction::ViewRuleset) => "按 Enter 全屏查看当前生效的全部 nftables 规则集。".to_string(),
            Some(SettingsAction::FwApply) => "按 Enter 按现有配置重新生成并应用防火墙规则（保留已建立连接）。".to_string(),
            Some(SettingsAction::ChangeSshPort) => "按 Enter 新增 SSH 端口；验证新端口可登录后再到防火墙关闭旧端口。".to_string(),
            Some(SettingsAction::ToggleSshPassword) => "按 Enter/Space 切换全局密码认证（关闭最后一种可用方式时会被拦截）。".to_string(),
            Some(SettingsAction::ToggleSshPubkey) => "按 Enter/Space 切换全局密钥认证（关闭前请确认备用方式可登录）。".to_string(),
            Some(SettingsAction::ChangeRootPassword) => "按 Enter 更新系统 root 用户登录密码。".to_string(),
            Some(SettingsAction::AddSshKey) => "按 Enter 粘贴并追加一条新的 root SSH 公钥。".to_string(),
            Some(SettingsAction::DelSshKey(_)) => "按 Enter 或 d 删除选中公钥（删除最后一把公钥需输入 yes）。".to_string(),
            Some(SettingsAction::FlushReport) => "按 Enter 立即冲刷并发送当前待上报的 AbuseIPDB 队列。".to_string(),
            Some(SettingsAction::SetAbuseKey) => "按 Enter 设置或更换 AbuseIPDB API Key。".to_string(),
            Some(SettingsAction::ToggleReport) => "按 Enter/Space 开启或关闭恶意 IP 自动上报。".to_string(),
            Some(SettingsAction::CycleLogFilter) => "按 Enter/Space 轮换日志来源过滤条件。".to_string(),
            Some(SettingsAction::ViewLogsModal) => "按 Enter 打开全屏日志查看器（支持 ↑↓ / PgUpDn 滚动）。".to_string(),
            Some(SettingsAction::RefreshLogs) => "按 Enter 重新拉取最新代理与 Fail2Ban 日志。".to_string(),
            Some(SettingsAction::Update) => "按 Enter 启动 AbuseGuard 官方更新流程，完成后自动重启面板。".to_string(),
            Some(SettingsAction::Uninstall) => "高危操作：按 Enter 转交交互式卸载流程，请确认后再执行。".to_string(),
            None => "按 ← / Esc / 0 返回主面板。".to_string(),
        }
    }

    fn site_cert_plain(&self, domain: &str) -> (String, RowTone) {
        if self.is_nginx() {
            if let Some(cert) = self.panel.certs.iter().find(|c| c.domain == domain) {
                return match cert.status.as_str() {
                    "valid" => (format!("有效至 {}", cert.expiry), RowTone::Ok),
                    "expiring" => (format!("即将过期 {}", cert.expiry), RowTone::Warn),
                    "expired" => (format!("已过期 {}", cert.expiry), RowTone::Err),
                    "missing" => ("证书缺失".to_string(), RowTone::Err),
                    _ => (cert.expiry.clone(), RowTone::Muted),
                };
            }
            return ("无证书记录".to_string(), RowTone::Muted);
        }
        if self.panel.cf_token_set == Some(true) {
            ("CF DNS-01".to_string(), RowTone::Ok)
        } else {
            ("自动 HTTPS".to_string(), RowTone::Normal)
        }
    }

    fn handle_settings_key(&mut self, key: KeyEvent) -> CommandEffect {
        match key.code {
            KeyCode::Char('q') => return CommandEffect::Quit,
            KeyCode::Char('?') => {
                self.modal = Some(Modal::Help);
                return CommandEffect::None;
            }
            KeyCode::Char('o') => {
                if let Some(t) = &self.toast {
                    let lines: Vec<String> = if t.full_output.is_empty() {
                        vec![t.summary.clone()]
                    } else {
                        t.full_output.lines().map(str::to_string).collect()
                    };
                    self.modal = Some(Modal::Viewer(ViewerModal {
                        title: if t.ok { "操作输出" } else { "错误详情" }.to_string(),
                        lines,
                        scroll: 0,
                    }));
                }
                return CommandEffect::None;
            }
            KeyCode::Char('r') => {
                return if self.tab == Tab::System {
                    CommandEffect::RefreshLogs
                } else {
                    CommandEffect::RefreshAll
                };
            }
            KeyCode::Char('1') => return self.switch_tab(Tab::Sites),
            KeyCode::Char('2') => return self.switch_tab(Tab::Firewall),
            KeyCode::Char('3') => return self.switch_tab(Tab::Blocklist),
            KeyCode::Char('4') => return self.switch_tab(Tab::Ssh),
            KeyCode::Char('5') => return self.switch_tab(Tab::Intel),
            KeyCode::Char('6') => return self.switch_tab(Tab::System),
            _ => {}
        }

        if self.tab == Tab::Overview {
            match key.code {
                KeyCode::Char('0') => return CommandEffect::Quit,
                KeyCode::Char('7') | KeyCode::Char('s') => {
                    return CommandEffect::RunAction(PendingAction::SyncIntel);
                }
                KeyCode::Char('8') => return CommandEffect::RefreshAll,
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    move_down(&mut self.home_idx, 9);
                    CommandEffect::None
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    move_up(&mut self.home_idx, 9);
                    CommandEffect::None
                }
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => {
                    self.exec_home_item(self.home_idx)
                }
                KeyCode::Esc => {
                    self.toast = None;
                    CommandEffect::None
                }
                _ => CommandEffect::None,
            }
        } else {
            let items: Vec<SettingsAction> = self
                .settings_rows()
                .into_iter()
                .filter_map(|r| match r {
                    SettingsRow::Item { action, .. } => Some(action),
                    _ => None,
                })
                .collect();
            match key.code {
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Esc | KeyCode::Char('0') => {
                    self.tab = Tab::Overview;
                    self.settings_idx = 0;
                    CommandEffect::None
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                    move_down(&mut self.settings_idx, items.len());
                    CommandEffect::None
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                    move_up(&mut self.settings_idx, items.len());
                    CommandEffect::None
                }
                KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => {
                    if let Some(action) = items.get(self.settings_idx).cloned() {
                        self.exec_settings_action(action)
                    } else {
                        CommandEffect::None
                    }
                }
                KeyCode::Char('d') | KeyCode::Delete => {
                    if let Some(action) = items.get(self.settings_idx).cloned() {
                        if matches!(
                            action,
                            SettingsAction::DelSite(_)
                                | SettingsAction::ClosePort(_)
                                | SettingsAction::UnbanSelected(_)
                                | SettingsAction::WlDelSelected(_)
                                | SettingsAction::DelSshKey(_)
                        ) {
                            return self.exec_settings_action(action);
                        }
                    }
                    CommandEffect::None
                }
                _ => CommandEffect::None,
            }
        }
    }

    fn exec_home_item(&mut self, idx: usize) -> CommandEffect {
        match idx {
            0 => self.switch_tab(Tab::Sites),
            1 => self.switch_tab(Tab::Firewall),
            2 => self.switch_tab(Tab::Blocklist),
            3 => self.switch_tab(Tab::Ssh),
            4 => self.switch_tab(Tab::Intel),
            5 => self.switch_tab(Tab::System),
            6 => CommandEffect::RunAction(PendingAction::SyncIntel),
            7 => CommandEffect::RefreshAll,
            8 => CommandEffect::Quit,
            _ => CommandEffect::None,
        }
    }

    fn exec_settings_action(&mut self, action: SettingsAction) -> CommandEffect {
        match action {
            SettingsAction::SyncIntel => CommandEffect::RunAction(PendingAction::SyncIntel),
            SettingsAction::AddSite => {
                let hint = if self.is_nginx() && self.panel.cf_token_set != Some(true) {
                    "提示：Nginx 模式需先配置 Cloudflare API Token 才能签发 DNS-01 证书。"
                } else {
                    "支持本地 (127.0.0.1:3000) 或公网 (203.0.113.10:8080) 上游。"
                };
                self.modal = Some(Modal::Form(FormModal {
                    title: "添加受保护站点".to_string(),
                    hint: hint.to_string(),
                    fields: vec![
                        FormField::text("域名", "例如 example.com"),
                        FormField::text("上游 IP:端口", "例如 127.0.0.1:3000"),
                    ],
                    active: 0,
                    error: None,
                    submit: FormSubmit::AddSite,
                }));
                CommandEffect::None
            }
            SettingsAction::DelSite(idx) => {
                if let Some(site) = self.panel.sites.get(idx) {
                    let domain = site.domain.clone();
                    let note = if self.is_nginx() {
                        format!("删除后将停用 {} 并重载 Nginx（证书材料保留）。", domain)
                    } else {
                        format!("删除后将移除 {} 的 Caddy 配置并重载服务。", domain)
                    };
                    self.modal = Some(Modal::Confirm(ConfirmModal {
                        title: format!("删除站点：{}", domain),
                        lines: vec![format!("目标：{} -> {}", domain, site.upstream), note],
                        danger: true,
                        require_yes: false,
                        typed: String::new(),
                        action: PendingAction::SiteDel { domain },
                    }));
                }
                CommandEffect::None
            }
            SettingsAction::SetCfToken => {
                let hint = if self.is_nginx() {
                    "将写入 root 凭据文件（0600），签发/续期时验证，无需重启 Nginx。"
                } else {
                    "保存后将校验 Caddyfile 并重启 Caddy 生效。"
                };
                self.modal = Some(Modal::Form(FormModal {
                    title: "设置 Cloudflare API Token".to_string(),
                    hint: hint.to_string(),
                    fields: vec![FormField::secret("API Token", "粘贴 Cloudflare API Token")],
                    active: 0,
                    error: None,
                    submit: FormSubmit::SetCfToken,
                }));
                CommandEffect::None
            }
            SettingsAction::ToggleIpv4 => {
                self.open_family_toggle_modal("ipv4", !self.panel.firewall.ipv4_in);
                CommandEffect::None
            }
            SettingsAction::ToggleIpv6 => {
                self.open_family_toggle_modal("ipv6", !self.panel.firewall.ipv6_in);
                CommandEffect::None
            }
            SettingsAction::OpenPort => {
                self.open_port_modal();
                CommandEffect::None
            }
            SettingsAction::ClosePort(idx) => {
                if let Some(rule) = self.panel.firewall.ports.get(idx) {
                    let proto = rule.proto.clone();
                    let port = rule.port.clone();
                    let source = if rule.source.is_empty() {
                        "any".to_string()
                    } else {
                        rule.source.clone()
                    };
                    let src_disp = if source == "any" { "所有来源" } else { source.as_str() };
                    let mut lines = vec![format!(
                        "确认关闭端口规则：{} {} ({})",
                        proto.to_uppercase(),
                        port,
                        src_disp
                    )];
                    if !rule.note.trim().is_empty() {
                        lines.push(format!("备注：{}", rule.note.trim()));
                    }
                    if proto == "tcp" && self.panel.ssh.ports.iter().any(|p| p == &port) {
                        lines.push(
                            "注意：该端口属于当前 SSH 监听端口；若是过渡旧端口将同时从 sshd 配置移除，唯一或当前会话端口会被保护拒绝。"
                                .to_string(),
                        );
                    }
                    self.modal = Some(Modal::Confirm(ConfirmModal {
                        title: "关闭端口规则".to_string(),
                        lines,
                        danger: true,
                        require_yes: false,
                        typed: String::new(),
                        action: PendingAction::FwClose {
                            proto,
                            port,
                            source,
                        },
                    }));
                }
                CommandEffect::None
            }
            SettingsAction::GoBlocklist => self.switch_tab(Tab::Blocklist),
            SettingsAction::UnbanSelected(idx) => {
                if let Some(item) = self.panel.banned.get(idx) {
                    let ip = item.ip.clone();
                    self.modal = Some(Modal::Confirm(ConfirmModal {
                        title: format!("解封 IP：{}", ip),
                        lines: vec![
                            format!("将清除 {} 在所有 Fail2Ban jail 中的行为封禁（{}）。", ip, item.jail),
                            "若该 IP 仍在威胁情报名单上，内核仍会拦截；放行请加入白名单。".to_string(),
                        ],
                        danger: false,
                        require_yes: false,
                        typed: String::new(),
                        action: PendingAction::UnbanIp { ip },
                    }));
                }
                CommandEffect::None
            }
            SettingsAction::BanIpPrompt => {
                self.open_ban_modal();
                CommandEffect::None
            }
            SettingsAction::UnbanIpPrompt => {
                self.open_unban_modal();
                CommandEffect::None
            }
            SettingsAction::WlAddPrompt => {
                self.open_whitelist_add_modal();
                CommandEffect::None
            }
            SettingsAction::WlDelSelected(idx) => {
                if let Some(entry) = self.panel.whitelist.get(idx).cloned() {
                    self.modal = Some(Modal::Confirm(ConfirmModal {
                        title: "删除白名单条目".to_string(),
                        lines: vec![
                            format!("将从白名单删除：{}", entry),
                            "删除后将自动重新应用内核与 Fail2Ban 策略。".to_string(),
                        ],
                        danger: true,
                        require_yes: false,
                        typed: String::new(),
                        action: PendingAction::WhitelistDel { entry },
                    }));
                }
                CommandEffect::None
            }
            SettingsAction::WlEdit => CommandEffect::RunAction(PendingAction::WhitelistEdit),
            SettingsAction::ViewRuleset => CommandEffect::RunAction(PendingAction::ViewRuleset),
            SettingsAction::FwApply => {
                self.modal = Some(Modal::Confirm(ConfirmModal {
                    title: "重新应用防火墙规则".to_string(),
                    lines: vec![
                        "将校验并重新加载 nftables 防火墙表，并开启开机自动恢复。".to_string(),
                        "现有已建立的连接与已保存的端口规则都会保留。".to_string(),
                    ],
                    danger: false,
                    require_yes: false,
                    typed: String::new(),
                    action: PendingAction::FwApply,
                }));
                CommandEffect::None
            }
            SettingsAction::ChangeSshPort => {
                let cur = if self.panel.ssh.ports.is_empty() {
                    "未知".to_string()
                } else {
                    self.panel.ssh.ports.join(", ")
                };
                self.modal = Some(Modal::Form(FormModal {
                    title: "修改 SSH 端口".to_string(),
                    hint: format!("当前端口：{}。切换期间新旧端口同时监听。", cur),
                    fields: vec![FormField::text("新 SSH 端口", "1–65535，例如 2222")],
                    active: 0,
                    error: None,
                    submit: FormSubmit::ChangeSshPort,
                }));
                CommandEffect::None
            }
            SettingsAction::ToggleSshPassword => {
                self.open_ssh_auth_modal("password", "全局密码认证", &self.panel.ssh.password_auth.clone());
                CommandEffect::None
            }
            SettingsAction::ToggleSshPubkey => {
                self.open_ssh_auth_modal("pubkey", "全局密钥认证", &self.panel.ssh.pubkey_auth.clone());
                CommandEffect::None
            }
            SettingsAction::ChangeRootPassword => {
                self.modal = Some(Modal::Form(FormModal {
                    title: "修改 root 登录密码".to_string(),
                    hint: "仅当密码登录开启时可用于 SSH；输入已掩码隐藏。".to_string(),
                    fields: vec![
                        FormField::secret("新密码", "输入新 root 密码"),
                        FormField::secret("确认密码", "再次输入新密码"),
                    ],
                    active: 0,
                    error: None,
                    submit: FormSubmit::ChangeRootPassword,
                }));
                CommandEffect::None
            }
            SettingsAction::AddSshKey => {
                self.modal = Some(Modal::Form(FormModal {
                    title: "添加 root SSH 公钥".to_string(),
                    hint: "支持 ssh-ed25519 / ssh-rsa / ecdsa-* / sk-*。".to_string(),
                    fields: vec![FormField::text("公钥内容", "粘贴 ssh-ed25519 AAAA... user@host")],
                    active: 0,
                    error: None,
                    submit: FormSubmit::AddSshKey,
                }));
                CommandEffect::None
            }
            SettingsAction::DelSshKey(idx) => {
                if let Some(item) = self.panel.ssh.keys.get(idx).cloned() {
                    let valid_count = self
                        .panel
                        .ssh
                        .keys
                        .iter()
                        .filter(|k| k.is_valid_key_line())
                        .count();
                    let is_last_valid = item.is_valid_key_line() && valid_count <= 1;
                    let (kind, digest, comment) = item.parts();
                    let mut lines = vec![format!("目标：#{} {} {} {}", item.index, kind, digest, comment)];
                    if is_last_valid {
                        lines.push(
                            "高危警告：这是最后一把有效公钥！请先确认 root 密码可独立登录。"
                                .to_string(),
                        );
                    }
                    self.modal = Some(Modal::Confirm(ConfirmModal {
                        title: "删除 SSH 公钥".to_string(),
                        lines,
                        danger: true,
                        require_yes: is_last_valid,
                        typed: String::new(),
                        action: PendingAction::SshKeyDel {
                            index: item.index,
                            raw: item.raw,
                            confirmed_yes: is_last_valid,
                        },
                    }));
                }
                CommandEffect::None
            }
            SettingsAction::FlushReport => CommandEffect::RunAction(PendingAction::FlushReport),
            SettingsAction::SetAbuseKey => {
                self.open_abuse_key_modal();
                CommandEffect::None
            }
            SettingsAction::ToggleReport => CommandEffect::RunAction(PendingAction::ToggleReport),
            SettingsAction::CycleLogFilter => {
                self.log_filter = self.log_filter.next(self.is_nginx());
                CommandEffect::None
            }
            SettingsAction::ViewLogsModal => {
                let lines: Vec<String> = self
                    .filtered_logs()
                    .into_iter()
                    .map(|(src, l)| format!("[{}] {}", src, l))
                    .collect();
                let view_lines = if lines.is_empty() {
                    vec!["当前日志源暂无最近记录。".to_string()]
                } else {
                    lines
                };
                self.modal = Some(Modal::Viewer(ViewerModal {
                    title: "系统日志".to_string(),
                    scroll: view_lines.len(),
                    lines: view_lines,
                }));
                CommandEffect::None
            }
            SettingsAction::RefreshLogs => CommandEffect::RefreshLogs,
            SettingsAction::Update => {
                self.modal = Some(Modal::Confirm(ConfirmModal {
                    title: "更新 AbuseGuard".to_string(),
                    lines: vec![
                        format!("仓库：{}", self.panel.repo),
                        "将暂停界面，从 GitHub 最新 release 拉取安装器升级并自动重载面板。".to_string(),
                    ],
                    danger: false,
                    require_yes: false,
                    typed: String::new(),
                    action: PendingAction::Update,
                }));
                CommandEffect::None
            }
            SettingsAction::Uninstall => {
                self.modal = Some(Modal::Confirm(ConfirmModal {
                    title: "卸载 AbuseGuard".to_string(),
                    lines: vec![
                        "将暂停界面并进入交互式卸载流程。".to_string(),
                        "请输入 yes 确认继续。".to_string(),
                    ],
                    danger: true,
                    require_yes: true,
                    typed: String::new(),
                    action: PendingAction::Uninstall,
                }));
                CommandEffect::None
            }
        }
    }

    fn open_port_modal(&mut self) {
        self.modal = Some(Modal::Form(FormModal {
            title: "开放入站端口".to_string(),
            hint: "Tab/↑↓ 切字段，Space 切协议；来源与备注均可留空".to_string(),
            fields: vec![
                FormField::toggle("协议", vec!["tcp", "udp"]),
                FormField::text("端口", "1–65535，例如 8443"),
                FormField::text("来源 IP / CIDR", "留空 = 所有来源，如 203.0.113.0/24"),
                FormField::text("备注（可选）", "留空自动标记，如 代理节点 / 管理后台"),
            ],
            active: 1,
            error: None,
            submit: FormSubmit::OpenPort,
        }));
    }

    fn open_ban_modal(&mut self) {
        self.modal = Some(Modal::Form(FormModal {
            title: "立即封禁 IP".to_string(),
            hint: "仅支持单个 IPv4/IPv6 地址（不支持网段）；白名单 IP 会自动受保护。".to_string(),
            fields: vec![FormField::text("目标 IP", "例如 198.51.100.10")],
            active: 0,
            error: None,
            submit: FormSubmit::BanIp,
        }));
    }

    fn open_unban_modal(&mut self) {
        self.modal = Some(Modal::Form(FormModal {
            title: "解封 IP".to_string(),
            hint: "清除该 IP 在所有 Fail2Ban jail 中的定时行为封禁。".to_string(),
            fields: vec![FormField::text("目标 IP", "例如 198.51.100.10")],
            active: 0,
            error: None,
            submit: FormSubmit::UnbanIp,
        }));
    }

    fn open_whitelist_add_modal(&mut self) {
        self.modal = Some(Modal::Form(FormModal {
            title: "添加 IP 白名单（支持批量）".to_string(),
            hint: "多个 IP 或网段用空格或逗号分隔；白名单不豁免端口规则。".to_string(),
            fields: vec![FormField::text("IP / CIDR", "例如 192.0.2.1, 2001:db8::/32")],
            active: 0,
            error: None,
            submit: FormSubmit::WhitelistAdd,
        }));
    }

    fn open_family_toggle_modal(&mut self, family: &str, enable: bool) {
        let label = if family == "ipv4" { "IPv4" } else { "IPv6" };
        if enable {
            self.modal = Some(Modal::Confirm(ConfirmModal {
                title: format!("开启 {} 入站", label),
                lines: vec![format!("确认开启 {} 入站流量（按端口白名单放行）？", label)],
                danger: false,
                require_yes: false,
                typed: String::new(),
                action: PendingAction::FwFamily {
                    family: family.to_string(),
                    enable: true,
                },
            }));
        } else {
            let mut lines = vec![format!("关闭后，新的 {} 入站连接将被直接丢弃。", label)];
            if self.panel.ssh.ssh_conn_family == label {
                lines.push(format!(
                    "高危警告：当前 SSH 会话正在使用 {}！断开后需要云控制台恢复！",
                    label
                ));
            }
            self.modal = Some(Modal::Confirm(ConfirmModal {
                title: format!("关闭 {} 入站", label),
                lines,
                danger: true,
                require_yes: true,
                typed: String::new(),
                action: PendingAction::FwFamily {
                    family: family.to_string(),
                    enable: false,
                },
            }));
        }
    }

    fn open_ssh_auth_modal(&mut self, which: &str, label: &str, current: &str) {
        let turning_off = current == "on";
        if turning_off {
            let backup_tip = if which == "password" {
                "请保持当前会话，先用新连接验证 root 密钥登录，再输入 yes 确认关闭密码认证。"
            } else {
                "请保持当前会话，先用新连接验证 root 密码登录，再输入 yes 确认关闭密钥认证。"
            };
            self.modal = Some(Modal::Confirm(ConfirmModal {
                title: format!("关闭{}", label),
                lines: vec![
                    backup_tip.to_string(),
                    "底层仍会执行完整防锁死校验，不符合条件将自动拒绝或回滚。".to_string(),
                ],
                danger: true,
                require_yes: true,
                typed: String::new(),
                action: PendingAction::SshAuth {
                    which: which.to_string(),
                    confirmed_yes: true,
                },
            }));
        } else {
            self.modal = Some(Modal::Confirm(ConfirmModal {
                title: format!("开启{}", label),
                lines: vec![format!("确认开启{}并重载 sshd？", label)],
                danger: false,
                require_yes: false,
                typed: String::new(),
                action: PendingAction::SshAuth {
                    which: which.to_string(),
                    confirmed_yes: false,
                },
            }));
        }
    }

    fn open_abuse_key_modal(&mut self) {
        self.modal = Some(Modal::Form(FormModal {
            title: "设置 AbuseIPDB API Key".to_string(),
            hint: "将以 0640 权限保存至 /etc/caddy-abuseguard/abuseipdb-report.key。".to_string(),
            fields: vec![FormField::secret("API Key", "粘贴 AbuseIPDB API Key")],
            active: 0,
            error: None,
            submit: FormSubmit::SetAbuseKey,
        }));
    }

    fn handle_modal_key(&mut self, key: KeyEvent) -> CommandEffect {
        let modal = self.modal.take().unwrap();
        match modal {
            Modal::Help => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') | KeyCode::Enter => {}
                    _ => self.modal = Some(Modal::Help),
                }
                CommandEffect::None
            }
            Modal::Viewer(mut v) => {
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => return CommandEffect::None,
                    KeyCode::Down | KeyCode::Char('j') => {
                        v.scroll = v.scroll.saturating_add(1).min(v.lines.len());
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        v.scroll = v.scroll.saturating_sub(1);
                    }
                    KeyCode::PageDown => {
                        v.scroll = v.scroll.saturating_add(15).min(v.lines.len());
                    }
                    KeyCode::PageUp => {
                        v.scroll = v.scroll.saturating_sub(15);
                    }
                    KeyCode::Char('g') | KeyCode::Home => v.scroll = 0,
                    KeyCode::Char('G') | KeyCode::End => v.scroll = v.lines.len(),
                    _ => {}
                }
                self.modal = Some(Modal::Viewer(v));
                CommandEffect::None
            }
            Modal::Confirm(mut c) => match key.code {
                KeyCode::Esc => CommandEffect::None,
                KeyCode::Char('n') | KeyCode::Char('N') if !c.require_yes => CommandEffect::None,
                KeyCode::Char('y') | KeyCode::Char('Y') if !c.require_yes => {
                    CommandEffect::RunAction(c.action)
                }
                KeyCode::Enter => {
                    if !c.require_yes || c.typed.trim() == "yes" {
                        CommandEffect::RunAction(c.action)
                    } else {
                        self.modal = Some(Modal::Confirm(c));
                        CommandEffect::None
                    }
                }
                KeyCode::Backspace if c.require_yes => {
                    c.typed.pop();
                    self.modal = Some(Modal::Confirm(c));
                    CommandEffect::None
                }
                KeyCode::Char(ch) if c.require_yes && !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if c.typed.len() < 8 {
                        c.typed.push(ch);
                    }
                    self.modal = Some(Modal::Confirm(c));
                    CommandEffect::None
                }
                _ => {
                    self.modal = Some(Modal::Confirm(c));
                    CommandEffect::None
                }
            },
            Modal::Form(mut f) => match key.code {
                KeyCode::Esc => CommandEffect::None,
                KeyCode::Tab | KeyCode::Down => {
                    if !f.fields.is_empty() {
                        f.active = (f.active + 1) % f.fields.len();
                    }
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                KeyCode::BackTab | KeyCode::Up => {
                    if !f.fields.is_empty() {
                        f.active = (f.active + f.fields.len() - 1) % f.fields.len();
                    }
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                KeyCode::Enter => {
                    if f.active + 1 < f.fields.len() && !key.modifiers.contains(KeyModifiers::CONTROL)
                    {
                        f.active += 1;
                        self.modal = Some(Modal::Form(f));
                        return CommandEffect::None;
                    }
                    self.submit_form(f)
                }
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(field) = f.fields.get_mut(f.active) {
                        if matches!(field.kind, FieldKind::Text { .. }) {
                            field.value.clear();
                        }
                    }
                    f.error = None;
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
                    if f.fields
                        .get(f.active)
                        .is_some_and(|fld| matches!(fld.kind, FieldKind::Toggle { .. })) =>
                {
                    if let Some(field) = f.fields.get_mut(f.active) {
                        if let FieldKind::Toggle { options, idx } = &mut field.kind {
                            if !options.is_empty() {
                                *idx = if key.code == KeyCode::Left {
                                    (*idx + options.len() - 1) % options.len()
                                } else {
                                    (*idx + 1) % options.len()
                                };
                                field.value = options[*idx].to_string();
                            }
                        }
                    }
                    f.error = None;
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                KeyCode::Backspace => {
                    if let Some(field) = f.fields.get_mut(f.active) {
                        if matches!(field.kind, FieldKind::Text { .. }) {
                            field.value.pop();
                        }
                    }
                    f.error = None;
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                KeyCode::Char(ch) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if let Some(field) = f.fields.get_mut(f.active) {
                        if matches!(field.kind, FieldKind::Text { .. }) {
                            field.value.push(ch);
                        }
                    }
                    f.error = None;
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
                _ => {
                    self.modal = Some(Modal::Form(f));
                    CommandEffect::None
                }
            },
        }
    }

    fn submit_form(&mut self, mut form: FormModal) -> CommandEffect {
        let val = |i: usize| {
            form.fields
                .get(i)
                .map(|f| f.value.trim().to_string())
                .unwrap_or_default()
        };
        let raw_val = |i: usize| form.fields.get(i).map(|f| f.value.clone()).unwrap_or_default();

        match form.submit {
            FormSubmit::AddSite => {
                let domain = val(0);
                let upstream = val(1);
                if domain.is_empty() || upstream.is_empty() {
                    form.error = Some("请完整填写域名和上游地址。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::SiteAdd { domain, upstream })
            }
            FormSubmit::SetCfToken => {
                let token = val(0);
                if token.is_empty() {
                    form.error = Some("Cloudflare API Token 不能为空。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::SetCfToken { token })
            }
            FormSubmit::OpenPort => {
                let proto = val(0);
                let port = val(1);
                let source = val(2);
                let note = val(3);
                if !valid_port(&port) {
                    form.error = Some("端口必须是 1–65535 之间的数字。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                if note.chars().count() > 32 || note.chars().any(|c| c.is_control()) {
                    form.error = Some("备注最多 32 个字符，且不能包含换行或制表符。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::FwOpen {
                    proto,
                    port,
                    source: if source.is_empty() {
                        "any".to_string()
                    } else {
                        source
                    },
                    note,
                })
            }
            FormSubmit::BanIp => {
                let ip = val(0);
                if ip.is_empty() {
                    form.error = Some("请输入要封禁的 IP 地址。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::BanIp { ip })
            }
            FormSubmit::UnbanIp => {
                let ip = val(0);
                if ip.is_empty() {
                    form.error = Some("请输入要解封的 IP 地址。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::UnbanIp { ip })
            }
            FormSubmit::WhitelistAdd => {
                let entries = val(0);
                if entries.is_empty() {
                    form.error = Some("请输入至少一个 IP 或 CIDR 网段。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::WhitelistAdd { entries })
            }
            FormSubmit::ChangeSshPort => {
                let port = val(0);
                if !valid_port(&port) {
                    form.error = Some("端口必须是 1–65535 之间的数字。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                self.modal = Some(Modal::Confirm(ConfirmModal {
                    title: format!("确认新增 SSH 端口 :{}", port),
                    lines: vec![
                        "新旧端口将同时监听；确认新端口可登录后再到「防火墙」关闭旧端口。".to_string(),
                        format!("重要：请务必先在云安全组放行 {}/tcp！", port),
                    ],
                    danger: true,
                    require_yes: false,
                    typed: String::new(),
                    action: PendingAction::SshPort { port },
                }));
                CommandEffect::None
            }
            FormSubmit::AddSshKey => {
                let pubkey = val(0);
                if pubkey.is_empty() {
                    form.error = Some("公钥内容不能为空。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::SshKeyAdd { pubkey })
            }
            FormSubmit::ChangeRootPassword => {
                let p1 = raw_val(0);
                let p2 = raw_val(1);
                if p1.is_empty() {
                    form.error = Some("密码不能为空。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                if p1 != p2 {
                    form.error = Some("两次输入的密码不一致。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::SshPassword { p1, p2 })
            }
            FormSubmit::SetAbuseKey => {
                let key = val(0);
                if key.is_empty() {
                    form.error = Some("API Key 不能为空。".to_string());
                    self.modal = Some(Modal::Form(form));
                    return CommandEffect::None;
                }
                CommandEffect::RunAction(PendingAction::SetAbuseKey { key })
            }
        }
    }
}

pub fn format_thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn valid_port(s: &str) -> bool {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    matches!(s.parse::<u32>(), Ok(1..=65535))
}

fn clamp_idx(idx: &mut usize, len: usize) {
    if len == 0 {
        *idx = 0;
    } else if *idx >= len {
        *idx = len - 1;
    }
}

fn move_down(idx: &mut usize, len: usize) {
    if len > 0 {
        *idx = (*idx + 1) % len;
    }
}

fn move_up(idx: &mut usize, len: usize) {
    if len > 0 {
        *idx = (*idx + len - 1) % len;
    }
}

fn compact_next_time(next: &str) -> String {
    let tokens: Vec<&str> = next.split_whitespace().collect();
    for i in 0..tokens.len() {
        let d = tokens[i];
        let b = d.as_bytes();
        if b.len() == 10 && b[4] == b'-' && b[7] == b'-' {
            if let Some(t) = tokens.get(i + 1) {
                let tb = t.as_bytes();
                if tb.len() >= 5 && tb[2] == b':' {
                    let base = format!("{} {}", &d[5..10], &t[0..5]);
                    if let Some(tz) = tokens.get(i + 2) {
                        if tz.len() <= 5 && tz.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'-') {
                            return format!("{} {}", base, tz);
                        }
                    }
                    return base;
                }
            }
        }
    }
    next.trim().to_string()
}

fn timer_cell(name: &str, state: Option<&str>, next: Option<&str>) -> (String, String, RowTone) {
    let (val, tone) = match state {
        Some("active") => (
            match next {
                Some(n) => compact_next_time(n),
                None => "已启用".to_string(),
            },
            RowTone::Ok,
        ),
        Some("inactive" | "failed") => ("未启用".to_string(), RowTone::Muted),
        _ => ("未知".to_string(), RowTone::Warn),
    };
    (name.to_string(), val, tone)
}

fn ssh_tone(state: &str) -> (&'static str, RowTone) {
    match state {
        "on" => ("已开启", RowTone::Ok),
        "off" => ("已关闭", RowTone::Err),
        _ => ("未知", RowTone::Warn),
    }
}
