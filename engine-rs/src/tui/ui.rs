// tui/ui.rs — Full-width left-anchored horizontal-rule TUI (sing-box-yg density + arrow/hotkey controls).
use crate::tui::model::{
    format_thousands, App, ConfirmModal, FieldKind, FormModal, Modal, RowTone, SettingsRow, Tab,
    ViewerModal,
};
use ratatui::layout::{Alignment, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;
use unicode_width::UnicodeWidthStr;

const BRAND: Color = Color::Red;
const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const OK: Color = Color::Green;
const WARN: Color = Color::Yellow;
const ERR: Color = Color::Red;

const BANNER: [&str; 3] = [
    "▄▀▀▄ █▀▀▄ █  █ ▄▀▀▀ █▀▀▀   ▄▀▀▀ █  █ ▄▀▀▄ █▀▀▄ █▀▀▄",
    "█▀▀█ █▀▀▄ █  █  ▀▀▄ █▀▀    █ ▀█ █  █ █▀▀█ █▀▀▄ █  █",
    "▀  ▀ ▀▀▀  ▀▀▀▀ ▀▀▀  ▀▀▀▀   ▀▀▀▀ ▀▀▀▀ ▀  ▀ ▀  ▀ ▀▀▀ ",
];

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    if area.width < 52 || area.height < 14 {
        let msg = Paragraph::new(vec![
            Line::from(Span::styled(
                "ABUSEGUARD",
                Style::default().fg(BRAND).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!(
                "终端窗口过小（{}x{}），请至少调整至 80x24。",
                area.width, area.height
            )),
            Line::from(Span::styled("按 q 退出", Style::default().fg(MUTED))),
        ])
        .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    // Narrow, cohesive 60-col layout so split panes (~60-68 cols) have breathing room and never clip.
    let w = area.width.saturating_sub(2).min(60) as usize;
    let pad_x = ((area.width as usize).saturating_sub(w) / 2).min(4).max(1) as u16;
    let x = area.x + pad_x;
    let top_y = area.y + if area.height >= 34 { 1 } else { 0 };
    let avail_h = area.height.saturating_sub(top_y - area.y);

    if app.tab == Tab::Overview {
        render_home(frame, x, top_y, w, avail_h, app);
    } else {
        render_subpage(frame, x, top_y, w, avail_h, app);
    }

    if let Some(modal) = app.modal.clone() {
        match modal {
            Modal::Form(form) => render_form_modal(frame, area, &form),
            Modal::Confirm(confirm) => render_confirm_modal(frame, area, &confirm),
            Modal::Viewer(viewer) => render_viewer_modal(frame, area, &viewer),
            Modal::Help => render_help_modal(frame, area),
        }
    }
}

fn render_home(frame: &mut Frame, x: u16, y: u16, w: usize, h: u16, app: &App) {
    let has_status = app.busy.is_some()
        || app.refreshing.is_some()
        || app.toast.is_some()
        || app.load_error.is_some();
    let show_live_tables = h >= if has_status { 31 } else { 29 };
    let show_banner = w >= 55
        && h >= if show_live_tables {
            if has_status { 34 } else { 32 }
        } else {
            27
        };
    let max_table_rows = if h >= 37 {
        5usize
    } else if h >= 35 {
        4usize
    } else {
        3usize
    };

    let mut lines: Vec<Line> = Vec::with_capacity(38);

    if show_banner {
        let b_st = Style::default().fg(BRAND).add_modifier(Modifier::BOLD);
        let b_pad = " ".repeat(w.saturating_sub(51) / 2);
        for row in BANNER {
            lines.push(Line::from(Span::styled(format!("{}{}", b_pad, row), b_st)));
        }
    }

    lines.push(bold_rule(w));
    lines.push(render_home_header(w, app));
    lines.push(thin_rule(w));

    // Shared status values
    let ssh_ports = if app.panel.ssh.ports.is_empty() {
        "-".to_string()
    } else {
        app.panel.ssh.ports.join(",")
    };
    let (ssh_auth_lbl, ssh_tone) = match (
        app.panel.ssh.password_auth.as_str(),
        app.panel.ssh.pubkey_auth.as_str(),
    ) {
        ("off", "on") => ("仅密钥", RowTone::Ok),
        ("on", "on") => ("密码+密钥", RowTone::Warn),
        ("on", "off") => ("仅密码", RowTone::Warn),
        _ => ("未确认", RowTone::Muted),
    };
    let site_cert = if app.panel.cf_token_set == Some(true) {
        "CF DNS-01"
    } else if app.is_nginx() {
        "未配 Token"
    } else {
        "自动 HTTPS"
    };
    let in_lbl = match (app.panel.firewall.ipv4_in, app.panel.firewall.ipv6_in) {
        (true, true) => "v4+v6 开",
        (true, false) => "IPv4 开",
        (false, true) => "IPv6 开",
        (false, false) => "入站全关",
    };
    let intel_cnt = app
        .snapshot
        .intel
        .local_entries
        .map(|n| format!("{} 条", format_thousands(n)))
        .unwrap_or_else(|| "未知".to_string());
    let rep_short = match (
        app.snapshot.reporting_enabled,
        app.snapshot.report_key_present,
    ) {
        (Some(true), Some(true)) => "上报开",
        (Some(true), Some(false)) => "缺 Key",
        (Some(false), _) => "上报关",
        _ => "未知",
    };
    let sync_next = app.compact_next_timer(app.snapshot.timers.sync.next.as_deref());

    // 1. Live VPS & protection status FIRST (right below header)
    let os_str = if app.host.os.is_empty() {
        "Linux"
    } else {
        app.host.os.as_str()
    };
    let arch_str = if app.host.arch.is_empty() {
        std::env::consts::ARCH
    } else {
        app.host.arch.as_str()
    };
    let kernel_str = if app.host.kernel.is_empty() {
        "-"
    } else {
        app.host.kernel.as_str()
    };
    let (proxy_val, proxy_tone) = match app.snapshot.services.proxy {
        Some("active") => (format!("{} 运行中", app.backend_label()), RowTone::Ok),
        Some(_) => (format!("{} 未运行", app.backend_label()), RowTone::Err),
        None => (format!("{} 未知", app.backend_label()), RowTone::Warn),
    };
    let (f2b_val, f2b_tone) = match app.snapshot.services.fail2ban {
        Some("active") => ("运行中", RowTone::Ok),
        Some(_) => ("未运行", RowTone::Err),
        None => ("未知", RowTone::Warn),
    };
    let (fw_val, fw_tone) = if !app.panel.firewall.nft_available {
        ("nftables 不可用".to_string(), RowTone::Err)
    } else if !app.panel.firewall.conflicts.is_empty() {
        (format!("存在规则冲突 · {}", in_lbl), RowTone::Warn)
    } else if app.panel.firewall.running {
        if !app.panel.firewall.boot_enabled {
            (format!("nft(开机未开) · {}", in_lbl), RowTone::Warn)
        } else if !app.panel.firewall.ipv4_in && !app.panel.firewall.ipv6_in {
            (format!("nftables · {}", in_lbl), RowTone::Err)
        } else {
            (format!("nftables 运行中 · {}", in_lbl), RowTone::Ok)
        }
    } else {
        (format!("nftables 未就绪 · {}", in_lbl), RowTone::Warn)
    };
    let (rep_val, rep_tone) = match (
        app.snapshot.reporting_enabled,
        app.snapshot.report_key_present,
    ) {
        (Some(true), Some(true)) => ("已开启", RowTone::Ok),
        (Some(true), Some(false)) => ("缺 API Key", RowTone::Warn),
        (Some(false), _) => ("已关闭", RowTone::Muted),
        _ => ("未知", RowTone::Warn),
    };
    let banned_total = app
        .snapshot
        .banned_total
        .map(format_thousands)
        .unwrap_or_else(|| "-".to_string());
    let jn = |name: &str| -> Option<u64> { app.snapshot.jails.get(name).copied().flatten() };
    let j = |name: &str| -> String {
        jn(name)
            .map(format_thousands)
            .unwrap_or_else(|| "-".to_string())
    };
    let web_bans = match (
        jn("caddy-rate-local"),
        jn("caddy-probe-h1"),
        jn("caddy-probe-h2"),
    ) {
        (Some(a), Some(b), Some(c)) => format_thousands(a + b + c),
        _ => "-".to_string(),
    };
    let intel_detail = match (
        app.snapshot.intel.local_entries,
        app.snapshot.intel.synced_age_hours,
        app.snapshot.intel_table_present,
    ) {
        (_, _, Some(false)) => ("内核未应用".to_string(), RowTone::Warn),
        (Some(n), Some(hr), _) if hr > 12 => (
            format!("{} 条 ({}h 前，建议检查)", format_thousands(n), hr),
            RowTone::Warn,
        ),
        (Some(n), Some(hr), _) => (
            format!("{} 条 ({}h 前 · 内核生效)", format_thousands(n), hr),
            RowTone::Ok,
        ),
        (Some(n), None, _) => (format!("{} 条 (内核生效)", format_thousands(n)), RowTone::Ok),
        _ => ("未知".to_string(), RowTone::Warn),
    };

    lines.push(Line::from(Span::styled(
        "  主机与防护状态：",
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    let os_arch = format!("{} · {}", os_str, arch_str);
    let f2b_full = format!("Fail2Ban {}", f2b_val);
    let ssh_line = format!(
        "端口 {} · {} · 公钥 {} 把",
        ssh_ports,
        ssh_auth_lbl,
        app.panel.ssh.keys.len()
    );
    let ban_full = format!(
        "{} (sshd {} · rate {} · h1 {} · h2 {})",
        banned_total,
        j("sshd"),
        j("caddy-rate-local"),
        j("caddy-probe-h1"),
        j("caddy-probe-h2"),
    );
    let ban_compact = format!("{} (sshd {} · web {})", banned_total, j("sshd"), web_bans);
    let ban_val = if ban_full.width() <= w.saturating_sub(11) {
        ban_full.as_str()
    } else {
        ban_compact.as_str()
    };

    lines.push(status_row(w, "系统", &[(&os_arch, RowTone::Normal)]));
    lines.push(status_row(w, "内核", &[(kernel_str, RowTone::Normal)]));
    lines.push(status_row(
        w,
        "服务",
        &[(&proxy_val, proxy_tone), (&f2b_full, f2b_tone)],
    ));
    lines.push(status_row(w, "防火墙", &[(&fw_val, fw_tone)]));
    lines.push(status_row(
        w,
        "情报",
        &[(&intel_detail.0, intel_detail.1), (rep_val, rep_tone)],
    ));
    lines.push(status_row(w, "SSH", &[(&ssh_line, ssh_tone)]));
    lines.push(status_row(w, "封禁", &[(ban_val, RowTone::Normal)]));

    if show_live_tables {
        lines.push(thin_rule(w));
        lines.extend(render_home_live_overview(w, max_table_rows, app));
    }

    lines.push(bold_rule(w));

    // 2. Concise numbered vertical menu below status
    let menu_items: [(usize, &str, &str, String, Color); 9] = [
        (
            0,
            "1.",
            "站点与证书管理",
            format!("{} 个站点 · {}", app.panel.sites.len(), site_cert),
            OK,
        ),
        (
            1,
            "2.",
            "防火墙与端口",
            format!("{} 条端口 · {}", app.panel.firewall.ports.len(), in_lbl),
            OK,
        ),
        (
            2,
            "3.",
            "封禁 IP 与白名单",
            format!(
                "{} 封禁 · {} 白名单",
                app.panel.banned.len(),
                app.panel.whitelist.len()
            ),
            OK,
        ),
        (
            3,
            "4.",
            "SSH 与登录安全",
            format!("端口 {} · {}", ssh_ports, ssh_auth_lbl),
            OK,
        ),
        (
            4,
            "5.",
            "威胁情报与上报",
            format!("{} · {}", intel_cnt, rep_short),
            OK,
        ),
        (
            5,
            "6.",
            "日志与系统维护",
            format!("v{}", app.snapshot.version),
            OK,
        ),
        (
            6,
            "7.",
            "立即同步威胁情报",
            format!("下次 {}", sync_next),
            ACCENT,
        ),
        (7, "8.", "刷新全部运行状态", "r 刷新".to_string(), ACCENT),
        (8, "0.", "退出面板", "q 退出".to_string(), ERR),
    ];

    for (idx, num, title, right_meta, col) in &menu_items {
        if *idx == 6 {
            lines.push(thin_rule(w));
        }
        lines.push(home_menu_row(
            w,
            *idx == app.home_idx,
            num,
            title,
            right_meta,
            *col,
        ));
    }

    if has_status {
        lines.push(thin_rule(w));
        lines.push(status_message_line(w, app));
    }

    lines.push(bold_rule(w));
    lines.push(Line::from(Span::styled(
        truncate_cell(
            "  ↑↓ 选择  Enter 进入  1-8/0 直达  r 刷新  ? 帮助  q 退出",
            w,
        ),
        Style::default().fg(MUTED),
    )));

    let draw_h = lines.len().min(h as usize) as u16;
    let rect = Rect::new(x, y, w as u16, draw_h);
    frame.render_widget(Paragraph::new(lines), rect);
}

fn render_home_header(w: usize, app: &App) -> Line<'static> {
    let ver = format!("  AbuseGuard v{}", app.snapshot.version);
    let meta = format!(" · {}", app.backend_label());
    let issues = app.health_issues();
    let (status_txt, status_col) = if issues.is_empty() {
        ("防护正常".to_string(), OK)
    } else {
        (format!("需要检查({})", issues.len()), WARN)
    };
    let clock = format!(" {}  ", app.last_refreshed);
    let right_w = status_txt.width() + clock.width();
    let meta_fit = truncate_cell(&meta, w.saturating_sub(ver.width() + right_w + 2));
    let gap = w.saturating_sub(ver.width() + meta_fit.width() + right_w).max(1);
    Line::from(vec![
        Span::styled(ver, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(meta_fit),
        Span::raw(" ".repeat(gap)),
        Span::styled(
            status_txt,
            Style::default().fg(status_col).add_modifier(Modifier::BOLD),
        ),
        Span::raw(clock),
    ])
}

fn home_menu_row(
    w: usize,
    selected: bool,
    num: &str,
    title: &str,
    right_meta: &str,
    col: Color,
) -> Line<'static> {
    let inner_w = w.saturating_sub(2);
    let prefix = if selected { " > " } else { "   " };
    let title_col = 16usize;
    let title_padded = pad_cell(title, title_col);

    if selected {
        let mut s = format!("{}{:>2} {}", prefix, num, title_padded);
        let gap = inner_w.saturating_sub(s.width() + right_meta.width()).max(2);
        s.push_str(&" ".repeat(gap));
        s.push_str(right_meta);
        return Line::from(Span::styled(
            pad_cell(&s, w),
            Style::default().add_modifier(Modifier::REVERSED),
        ));
    }

    let used = prefix.width() + 3 + title_col;
    let gap = inner_w.saturating_sub(used + right_meta.width()).max(2);
    Line::from(vec![
        Span::raw(prefix.to_string()),
        Span::styled(
            format!("{:>2} ", num),
            Style::default().fg(col).add_modifier(Modifier::BOLD),
        ),
        Span::styled(title_padded, Style::default().fg(col)),
        Span::raw(" ".repeat(gap)),
        Span::styled(right_meta.to_string(), Style::default().fg(MUTED)),
    ])
}

fn status_row(w: usize, label: &str, parts: &[(&str, RowTone)]) -> Line<'static> {
    let mut spans = vec![
        Span::raw("  "),
        Span::styled(
            pad_cell(label, 8),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    let mut rem = w.saturating_sub(11);
    for (i, (txt, tone)) in parts.iter().enumerate() {
        if i > 0 {
            if rem <= 3 {
                break;
            }
            spans.push(Span::styled(" · ", Style::default().fg(MUTED)));
            rem -= 3;
        }
        let fit = truncate_cell(txt, rem);
        rem = rem.saturating_sub(fit.width());
        spans.push(Span::styled(fit, tone_style(*tone)));
    }
    Line::from(spans)
}

fn render_home_live_overview(w: usize, max_rows: usize, app: &App) -> Vec<Line<'static>> {
    let mut port_lines: Vec<(String, String, RowTone)> = Vec::new();
    if app.panel.firewall.ports.is_empty() {
        port_lines.push((
            "暂无端口规则（按 2 开放或重应用）".to_string(),
            String::new(),
            RowTone::Muted,
        ));
    } else {
        for p in app.panel.firewall.ports.iter().take(max_rows) {
            let is_ssh = p.proto == "tcp" && app.panel.ssh.ports.iter().any(|sp| sp == &p.port);
            let src = if p.source.is_empty() || p.source == "any" {
                "所有来源"
            } else {
                p.source.as_str()
            };
            let note = p.display_note(is_ssh, "已放行");
            port_lines.push((
                format!("{:<3} {:<4} {}", p.proto.to_uppercase(), p.port, src),
                note,
                if is_ssh { RowTone::Warn } else { RowTone::Ok },
            ));
        }
        if app.panel.firewall.ports.len() > max_rows {
            port_lines.push((
                format!(
                    "... 还有 {} 条端口（按 2 查看全部）",
                    app.panel.firewall.ports.len() - max_rows
                ),
                String::new(),
                RowTone::Muted,
            ));
        }
    }

    let mut out: Vec<Line> = Vec::new();
    out.push(Line::from(Span::styled(
        format!(
            "  开放端口 ({})  ·  受保护站点 ({})",
            app.panel.firewall.ports.len(),
            app.panel.sites.len()
        ),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    for (txt, tag, tone) in port_lines.iter().take(max_rows) {
        let mut spans = vec![Span::raw("  ")];
        spans.extend(live_cell_spans(txt, tag, *tone, w.saturating_sub(4)));
        out.push(Line::from(spans));
    }
    out
}

fn live_cell_spans(text: &str, tag: &str, tone: RowTone, cell_w: usize) -> Vec<Span<'static>> {
    if tag.is_empty() {
        return vec![Span::styled(truncate_cell(text, cell_w), tone_style(tone))];
    }
    let tag_fit = truncate_cell(tag, cell_w / 2);
    let avail_txt = cell_w.saturating_sub(2 + tag_fit.width() + 2);
    let fit = truncate_cell(text, avail_txt);
    let gap = cell_w.saturating_sub(2 + fit.width() + tag_fit.width()).max(2);
    vec![
        Span::styled("● ", Style::default().fg(dot_color(tone))),
        Span::raw(fit),
        Span::raw(" ".repeat(gap)),
        Span::styled(tag_fit, tone_style(tone)),
    ]
}

fn render_subpage(frame: &mut Frame, x: u16, y: u16, w: usize, h: u16, app: &App) {
    let title = match app.tab {
        Tab::Sites => "1. 站点与证书管理",
        Tab::Firewall => "2. 防火墙与端口",
        Tab::Blocklist => "3. 封禁 IP 与白名单",
        Tab::Ssh => "4. SSH 与登录安全",
        Tab::Intel => "5. 威胁情报与上报",
        Tab::System => "6. 日志与系统维护",
        Tab::Overview => "概览",
    };

    let rows = app.settings_rows();
    let inner_w = w.saturating_sub(4);
    let wide_pairs = inner_w >= 68;
    let label_col = 14usize;
    let (c1_w, c2_w) = if inner_w >= 86 {
        (28, 30)
    } else if inner_w >= 68 {
        (24, 24)
    } else {
        (19, 17)
    };

    let mut body: Vec<Line> = Vec::with_capacity(rows.len() + 2);
    let mut item_counter = 0usize;
    let mut selected_line: Option<usize> = None;

    for row in rows {
        match row {
            SettingsRow::Blank => body.push(Line::from("")),
            SettingsRow::Section(sec) => body.push(group_title(&sec)),
            SettingsRow::TableHead { c1, c2, c3 } => {
                let mut spans = vec![
                    Span::raw("    "),
                    Span::styled(pad_cell(&c1, c1_w), Style::default().fg(MUTED)),
                    Span::raw("  "),
                ];
                if c3.is_empty() {
                    spans.push(Span::styled(c2, Style::default().fg(MUTED)));
                } else {
                    let c3_w = c3.width();
                    let mid_w = inner_w
                        .saturating_sub(2 + c1_w + 2 + 2 + c3_w)
                        .max(c2_w.min(12));
                    spans.push(Span::styled(pad_cell(&c2, mid_w), Style::default().fg(MUTED)));
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(c3, Style::default().fg(MUTED)));
                }
                body.push(Line::from(spans));
            }
            SettingsRow::Info { label, value, tone } => {
                body.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(pad_cell(&label, label_col), Style::default().fg(MUTED)),
                    Span::raw("  "),
                    Span::styled(
                        truncate_cell(&value, inner_w.saturating_sub(label_col + 2)),
                        tone_style(tone),
                    ),
                ]));
            }
            SettingsRow::Pair {
                l_label,
                l_value,
                l_tone,
                r_label,
                r_value,
                r_tone,
            } => {
                if wide_pairs {
                    body.push(status_pair_line(
                        w, &l_label, &l_value, l_tone, &r_label, &r_value, r_tone,
                    ));
                } else {
                    body.push(status_single_line(w, &l_label, &l_value, l_tone));
                    body.push(status_single_line(w, &r_label, &r_value, r_tone));
                }
            }
            SettingsRow::Note { text, tone } => {
                body.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(truncate_cell(&text, inner_w), tone_style(tone)),
                ]));
            }
            SettingsRow::Item {
                label,
                detail,
                value,
                tone,
                ..
            } => {
                let is_sel = item_counter == app.settings_idx;
                if is_sel {
                    selected_line = Some(body.len());
                }
                item_counter += 1;

                let prefix = if is_sel { "> " } else { "  " };
                if is_sel {
                    let full = format_item_row(prefix, &label, &detail, &value, c1_w, c2_w, inner_w);
                    body.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(full, Style::default().add_modifier(Modifier::REVERSED)),
                    ]));
                } else {
                    body.push(render_item_spans(
                        prefix, &label, &detail, &value, tone, c1_w, c2_w, inner_w,
                    ));
                }
            }
        }
    }

    let chrome_h = 7usize;
    let max_body_h = (h as usize).saturating_sub(chrome_h).max(4);
    let total = body.len();
    let max_scroll = total.saturating_sub(max_body_h);
    let scroll = if max_scroll == 0 {
        0
    } else if let Some(sel) = selected_line {
        let keep_top = sel.saturating_sub(3);
        if sel + 2 < max_body_h {
            0
        } else {
            keep_top.min(max_scroll)
        }
    } else {
        0
    };
    let visible_body: Vec<Line> = body.into_iter().skip(scroll).take(max_body_h).collect();

    let scroll_hint = if max_scroll > 0 {
        match (scroll > 0, scroll < max_scroll) {
            (true, true) => Some("↑↓ 更多"),
            (false, true) => Some("↓ 下方还有内容"),
            (true, false) => Some("↑ 上方还有内容"),
            (false, false) => None,
        }
    } else {
        None
    };

    let mut lines: Vec<Line> = Vec::with_capacity(visible_body.len() + chrome_h);
    lines.push(bold_rule(w));
    lines.push(render_subpage_header(w, title, app));
    lines.push(thin_rule(w));
    lines.extend(visible_body);
    lines.push(thin_rule(w));
    lines.push(status_message_line(w, app));
    lines.push(bold_rule(w));
    lines.push(render_subpage_footer(w, scroll_hint));

    let draw_h = lines.len().min(h as usize) as u16;
    let rect = Rect::new(x, y, w as u16, draw_h);
    frame.render_widget(Paragraph::new(lines), rect);
}

fn render_subpage_header(w: usize, title: &str, app: &App) -> Line<'static> {
    let left = format!("  ◆ {}", title);
    let issues = app.health_issues();
    let (status_txt, status_col) = if issues.is_empty() {
        ("防护正常".to_string(), OK)
    } else {
        (format!("需要检查({})", issues.len()), WARN)
    };
    let back = "  0 / ← / Esc 返回主页  ";
    let gap = w
        .saturating_sub(left.width() + status_txt.width() + back.width())
        .max(1);
    Line::from(vec![
        Span::styled(
            left,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(gap)),
        Span::styled(status_txt, Style::default().fg(status_col)),
        Span::styled(back, Style::default().fg(MUTED)),
    ])
}

fn render_subpage_footer(w: usize, scroll_hint: Option<&str>) -> Line<'static> {
    let left_full = "  ↑↓ 选择   Enter/Space 执行   0/←/Esc 返回主页   1-6 切页   r 刷新   q 退出";
    let left_compact = "  ↑↓ 选择  Enter 执行  ←/Esc 主页  1-6 切页  r 刷新  q 退出";
    let right = scroll_hint.unwrap_or("");
    let need_r = if right.is_empty() { 0 } else { right.width() + 3 };
    let left = if left_full.width() + need_r <= w {
        left_full
    } else {
        left_compact
    };
    let left_fit = truncate_cell(left, w.saturating_sub(need_r));
    let mut spans = vec![Span::styled(left_fit.clone(), Style::default().fg(MUTED))];
    if !right.is_empty() {
        let gap = w.saturating_sub(left_fit.width() + right.width() + 2).max(1);
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(right.to_string(), Style::default().fg(ACCENT)));
    }
    Line::from(spans)
}

fn status_message_line(w: usize, app: &App) -> Line<'static> {
    let inner_w = w.saturating_sub(4);
    if let Some(msg) = app.busy.as_deref().or(app.refreshing.as_deref()) {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                truncate_cell(&format!("请稍候：{}", msg), inner_w),
                Style::default().fg(if app.busy.is_some() { WARN } else { MUTED }),
            ),
        ])
    } else if let Some(toast) = &app.toast {
        let col = if toast.ok { OK } else { ERR };
        let suffix = if toast.full_output.lines().count() > 1 {
            "  (按 o 查看完整输出)"
        } else {
            ""
        };
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                truncate_cell(&format!("{}{}", toast.summary, suffix), inner_w),
                Style::default().fg(col),
            ),
        ])
    } else if let Some(err) = &app.load_error {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                truncate_cell(&format!("状态加载异常：{} (按 r 重试)", err), inner_w),
                Style::default().fg(WARN),
            ),
        ])
    } else {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                truncate_cell(&app.settings_context_hint(), inner_w),
                Style::default().fg(MUTED),
            ),
        ])
    }
}

fn bold_rule(w: usize) -> Line<'static> {
    Line::from(Span::styled(
        "━".repeat(w),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

fn thin_rule(w: usize) -> Line<'static> {
    Line::from(Span::styled("─".repeat(w), Style::default().fg(MUTED)))
}

fn group_title(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("  ◆ {}", title),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

fn dot_color(tone: RowTone) -> Color {
    match tone {
        RowTone::Ok => OK,
        RowTone::Warn => WARN,
        RowTone::Err => ERR,
        RowTone::Muted => MUTED,
        RowTone::Normal => ACCENT,
    }
}

fn status_single_line(w: usize, label: &str, value: &str, tone: RowTone) -> Line<'static> {
    let max_v = w.saturating_sub(6 + label.width());
    Line::from(vec![
        Span::raw("  "),
        Span::styled("●", Style::default().fg(dot_color(tone))),
        Span::raw(" "),
        Span::styled(label.to_string(), Style::default().fg(MUTED)),
        Span::raw("  "),
        Span::styled(truncate_cell(value, max_v), tone_style(tone)),
    ])
}

fn status_pair_line(
    w: usize,
    l_label: &str,
    l_val: &str,
    l_tone: RowTone,
    r_label: &str,
    r_val: &str,
    r_tone: RowTone,
) -> Line<'static> {
    let inner_w = w.saturating_sub(4);
    let gutter = 4usize;
    let left_w = inner_w.saturating_sub(gutter) / 2;
    let right_w = inner_w.saturating_sub(gutter + left_w);

    let mut spans = vec![Span::raw("  ")];
    spans.extend(status_cell_spans(l_label, l_val, l_tone, left_w, true));
    spans.push(Span::raw(" ".repeat(gutter)));
    spans.extend(status_cell_spans(r_label, r_val, r_tone, right_w, false));
    Line::from(spans)
}

fn status_cell_spans(
    label: &str,
    value: &str,
    tone: RowTone,
    cell_w: usize,
    pad_right: bool,
) -> Vec<Span<'static>> {
    let prefix_w = 2 + label.width() + 2;
    let avail_v = cell_w.saturating_sub(prefix_w);
    let val_fit = truncate_cell(value, avail_v);
    let used = prefix_w + val_fit.width();
    let mut out = vec![
        Span::styled("●", Style::default().fg(dot_color(tone))),
        Span::raw(" "),
        Span::styled(label.to_string(), Style::default().fg(MUTED)),
        Span::raw("  "),
        Span::styled(val_fit, tone_style(tone)),
    ];
    if pad_right && used < cell_w {
        out.push(Span::raw(" ".repeat(cell_w - used)));
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn render_item_spans(
    prefix: &str,
    label: &str,
    detail: &str,
    value: &str,
    tone: RowTone,
    c1_w: usize,
    c2_w: usize,
    total_w: usize,
) -> Line<'static> {
    let mut spans = vec![Span::raw("  "), Span::raw(prefix.to_string())];
    if detail.is_empty() && value.is_empty() {
        spans.push(Span::styled(
            truncate_cell(label, total_w.saturating_sub(prefix.width())),
            tone_style(tone),
        ));
    } else if detail.is_empty() {
        let val_w = value.width();
        let avail_lbl = total_w.saturating_sub(prefix.width() + val_w + 2);
        let lbl = truncate_cell(label, avail_lbl);
        let gap = total_w
            .saturating_sub(prefix.width() + lbl.width() + val_w)
            .max(2);
        let lbl_st = if tone == RowTone::Err {
            Style::default().fg(ERR)
        } else {
            Style::default()
        };
        spans.push(Span::styled(lbl, lbl_st));
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(value.to_string(), tone_style(tone)));
    } else if value.is_empty() {
        let rest_w = total_w.saturating_sub(prefix.width() + c1_w + 2);
        spans.push(Span::styled(pad_cell(label, c1_w), tone_style(tone)));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            truncate_cell(detail, rest_w),
            Style::default().fg(MUTED),
        ));
    } else {
        let max_val_w = total_w.saturating_sub(prefix.width() + c1_w + 2 + c2_w.min(12) + 2);
        let val_fit = truncate_cell(value, max_val_w);
        let mid_w = total_w
            .saturating_sub(prefix.width() + c1_w + 2 + 2 + val_fit.width())
            .max(c2_w.min(12));
        spans.push(Span::raw(pad_cell(label, c1_w)));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            pad_cell(detail, mid_w),
            Style::default().fg(MUTED),
        ));
        spans.push(Span::raw("  "));
        spans.push(Span::styled(val_fit, tone_style(tone)));
    }
    Line::from(spans)
}

fn format_item_row(
    prefix: &str,
    label: &str,
    detail: &str,
    value: &str,
    c1_w: usize,
    c2_w: usize,
    total_w: usize,
) -> String {
    let mut s = String::from(prefix);
    if detail.is_empty() && value.is_empty() {
        s.push_str(label);
    } else if detail.is_empty() {
        let val_w = value.width();
        let avail_lbl = total_w.saturating_sub(prefix.width() + val_w + 2);
        let lbl = truncate_cell(label, avail_lbl);
        let gap = total_w
            .saturating_sub(prefix.width() + lbl.width() + val_w)
            .max(2);
        s.push_str(&lbl);
        s.push_str(&" ".repeat(gap));
        s.push_str(value);
    } else if value.is_empty() {
        let rest_w = total_w.saturating_sub(prefix.width() + c1_w + 2);
        s.push_str(&pad_cell(label, c1_w));
        s.push_str("  ");
        s.push_str(&truncate_cell(detail, rest_w));
    } else {
        let max_val_w = total_w.saturating_sub(prefix.width() + c1_w + 2 + c2_w.min(12) + 2);
        let val_fit = truncate_cell(value, max_val_w);
        let mid_w = total_w
            .saturating_sub(prefix.width() + c1_w + 2 + 2 + val_fit.width())
            .max(c2_w.min(12));
        s.push_str(&pad_cell(label, c1_w));
        s.push_str("  ");
        s.push_str(&pad_cell(detail, mid_w));
        s.push_str("  ");
        s.push_str(&val_fit);
    }
    pad_cell(&s, total_w)
}

fn render_form_modal(frame: &mut Frame, area: Rect, form: &FormModal) {
    let field_rows = form.fields.len() as u16 * 3;
    let err_h = if form.error.is_some() { 2 } else { 0 };
    let height = (field_rows + 6 + err_h)
        .min(area.height.saturating_sub(2))
        .max(10);
    let width = 64u16.min(area.width.saturating_sub(4)).max(44);
    let popup = centered_rect(area, width, height);

    clear_modal_margin(frame, area, popup);
    let outer = Block::default()
        .title(Span::styled(
            format!(" {} ", form.title),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(ACCENT));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let mut lines: Vec<Line> = vec![
        Line::from(Span::styled(
            truncate_cell(&format!(" {}", form.hint), inner.width as usize),
            Style::default().fg(MUTED),
        )),
        Line::from(""),
    ];

    for (idx, field) in form.fields.iter().enumerate() {
        let active = idx == form.active;
        let prefix = if active { "> " } else { "  " };
        lines.push(Line::from(Span::styled(
            format!("{}{}", prefix, field.label),
            if active {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED)
            },
        )));

        let val_line = match &field.kind {
            FieldKind::Toggle { options, idx: opt_i } => {
                let mut sp = vec![Span::raw("  ")];
                for (oi, opt) in options.iter().enumerate() {
                    if oi > 0 {
                        sp.push(Span::raw("   "));
                    }
                    let txt = format!(" {} ", opt.to_uppercase());
                    if oi == *opt_i {
                        sp.push(Span::styled(
                            txt,
                            Style::default().add_modifier(Modifier::REVERSED),
                        ));
                    } else {
                        sp.push(Span::styled(txt, Style::default().fg(MUTED)));
                    }
                }
                Line::from(sp)
            }
            FieldKind::Text { masked } => {
                if field.value.is_empty() {
                    if active {
                        Line::from(vec![
                            Span::raw("  "),
                            Span::styled("_", Style::default().add_modifier(Modifier::BOLD)),
                            Span::styled(
                                format!(" {}", field.placeholder),
                                Style::default().fg(MUTED),
                            ),
                        ])
                    } else {
                        Line::from(Span::styled(
                            format!("  {}", field.placeholder),
                            Style::default().fg(MUTED),
                        ))
                    }
                } else {
                    let disp = if *masked {
                        "*".repeat(field.value.chars().count())
                    } else {
                        field.value.clone()
                    };
                    let mut sp = vec![Span::raw(format!("  {}", disp))];
                    if active {
                        sp.push(Span::styled("_", Style::default().add_modifier(Modifier::BOLD)));
                    }
                    Line::from(sp)
                }
            }
        };
        lines.push(val_line);
        lines.push(Line::from(""));
    }

    if let Some(err) = &form.error {
        lines.push(Line::from(Span::styled(
            format!(" 错误：{}", err),
            Style::default().fg(ERR),
        )));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        " Enter 下一步/提交   Tab 切换   Ctrl+U 清空   Esc 取消",
        Style::default().fg(MUTED),
    )));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_confirm_modal(frame: &mut Frame, area: Rect, confirm: &ConfirmModal) {
    let extra = if confirm.require_yes { 3 } else { 1 };
    let height = (confirm.lines.len() as u16 * 2 + 5 + extra)
        .min(area.height.saturating_sub(2))
        .max(9);
    let width = 62u16.min(area.width.saturating_sub(4)).max(44);
    let popup = centered_rect(area, width, height);

    clear_modal_margin(frame, area, popup);
    let border_col = if confirm.danger { ERR } else { ACCENT };
    let block = Block::default()
        .title(Span::styled(
            format!(" {} ", confirm.title),
            Style::default()
                .fg(border_col)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(border_col));
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let mut lines: Vec<Line> = vec![Line::from("")];
    for (i, text) in confirm.lines.iter().enumerate() {
        let st = if confirm.danger && i > 0 {
            Style::default().fg(ERR)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(format!(" {}", text), st)));
    }
    lines.push(Line::from(""));

    if confirm.require_yes {
        let matched = confirm.typed.trim() == "yes";
        lines.push(Line::from(vec![
            Span::styled(" 输入 yes 后回车确认：", Style::default().fg(WARN)),
            Span::styled(
                format!("{}_", confirm.typed),
                Style::default()
                    .fg(if matched { OK } else { ERR })
                    .add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            " Enter 确认   Esc 取消",
            Style::default().fg(MUTED),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            " Enter / y 确认   Esc / n 取消",
            Style::default().fg(MUTED),
        )));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

fn render_viewer_modal(frame: &mut Frame, area: Rect, viewer: &ViewerModal) {
    let width = area.width.saturating_sub(6).max(44);
    let height = area.height.saturating_sub(4).max(10);
    let popup = centered_rect(area, width, height);

    clear_modal_margin(frame, area, popup);
    let view_h = height.saturating_sub(3) as usize;
    let total = viewer.lines.len();
    let max_scroll = total.saturating_sub(view_h);
    let scroll = viewer.scroll.min(max_scroll);

    let block = Block::default()
        .title(Span::styled(
            format!(
                " {} ({}/{})  ↑↓/PgUpDn 滚动  Esc 关闭 ",
                viewer.title,
                (scroll + view_h).min(total),
                total
            ),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(ACCENT));

    let lines: Vec<Line> = viewer
        .lines
        .iter()
        .skip(scroll)
        .take(view_h.max(1))
        .map(|l| Line::from(format!(" {}", l)))
        .collect();
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}

fn render_help_modal(frame: &mut Frame, area: Rect) {
    let width = 64u16.min(area.width.saturating_sub(4)).max(44);
    let height = 12u16.min(area.height.saturating_sub(2)).max(9);
    let popup = centered_rect(area, width, height);

    clear_modal_margin(frame, area, popup);
    let block = Block::default()
        .title(Span::styled(
            " 操作说明 (Esc 关闭) ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(ACCENT));

    let rows = [
        ("↑↓ / j k", "上下选择菜单项或配置项"),
        ("Enter / Space", "进入选中模块或执行/切换当前配置项"),
        ("1 - 6", "直达站点 / 防火墙 / 封禁白名单 / SSH / 情报 / 系统"),
        ("7 / 8", "主面板快速同步威胁情报 / 刷新全部状态"),
        ("0 / ← / Esc", "子页返回主面板（主面板按 0 或 q 退出）"),
        ("o / r", "查看上次完整输出 / 刷新当前页"),
        ("q", "退出面板（ag --classic 使用旧版编号菜单）"),
    ];
    let lines: Vec<Line> = rows
        .into_iter()
        .map(|(k, d)| {
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    format!("{:<14}", k),
                    Style::default().fg(OK).add_modifier(Modifier::BOLD),
                ),
                Span::styled(d, Style::default().fg(MUTED)),
            ])
        })
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
        popup,
    );
}

fn tone_style(tone: RowTone) -> Style {
    match tone {
        RowTone::Normal => Style::default(),
        RowTone::Muted => Style::default().fg(MUTED),
        RowTone::Ok => Style::default().fg(OK),
        RowTone::Warn => Style::default().fg(WARN),
        RowTone::Err => Style::default().fg(ERR),
    }
}

fn truncate_cell(text: &str, max_w: usize) -> String {
    if max_w == 0 {
        return String::new();
    }
    if text.width() <= max_w {
        return text.to_string();
    }
    let mut out = String::new();
    let mut cur = 0usize;
    for ch in text.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if cur + cw + 1 > max_w {
            out.push('…');
            break;
        }
        out.push(ch);
        cur += cw;
    }
    out
}

fn pad_cell(text: &str, target_w: usize) -> String {
    let w = text.width();
    if w > target_w {
        let mut out = truncate_cell(text, target_w);
        let ow = out.width();
        if ow < target_w {
            out.push_str(&" ".repeat(target_w - ow));
        }
        out
    } else {
        format!("{}{}", text, " ".repeat(target_w - w))
    }
}

fn clear_modal_margin(frame: &mut Frame, area: Rect, popup: Rect) {
    let x = popup.x.saturating_sub(1).max(area.x);
    let right = (popup.x + popup.width + 1).min(area.x + area.width);
    let halo = Rect::new(x, popup.y, right.saturating_sub(x), popup.height);
    frame.render_widget(Clear, halo);
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::{Intel, Services, Snapshot, Timers, Unit};
    use crate::tui::backend::parse_os_label;
    use crate::tui::model::{
        BannedItem, CertItem, CommandEffect, FirewallData, HostInfo, LogsData, Modal, PanelData,
        PendingAction, PortRule, SiteItem, SshData, SshKeyItem, Tab,
    };
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::collections::BTreeMap;

    fn sample_app(nginx: bool) -> App {
        let mut app = App::new("1.0.4");
        app.host = HostInfo {
            os: "Debian GNU/Linux 12.15 (bookworm)".to_string(),
            arch: "x86_64".to_string(),
            kernel: "6.1.0-56-cloud-amd64".to_string(),
        };
        let mut jails = BTreeMap::new();
        jails.insert("caddy-rate-local", Some(158));
        jails.insert("caddy-probe-h1", Some(12));
        jails.insert("caddy-probe-h2", Some(7));
        jails.insert("sshd", Some(1230));
        app.snapshot = Snapshot {
            schema_version: 1,
            version: "1.0.4",
            backend: Some(if nginx { "nginx" } else { "caddy" }),
            services: Services {
                proxy: Some("active"),
                fail2ban: Some("active"),
            },
            timers: Timers {
                report: Unit {
                    state: Some("active"),
                    next: Some("Fri 2026-11-27 10:00:00 UTC".to_string()),
                },
                sync: Unit {
                    state: Some("active"),
                    next: Some("Fri 2026-11-27 18:00:00 UTC".to_string()),
                },
                certbot: Unit {
                    state: if nginx { Some("active") } else { None },
                    next: if nginx {
                        Some("Sat 2026-11-28 03:15:00 UTC".to_string())
                    } else {
                        None
                    },
                },
            },
            firewall_table_present: Some(true),
            intel_table_present: Some(true),
            jails,
            banned_total: Some(1407),
            reporting_enabled: Some(true),
            report_key_present: Some(true),
            intel: Intel {
                local_entries: Some(134320),
                synced_age_hours: Some(5),
                applied_entries: Some(134320),
                applied_age_hours: Some(5),
            },
        };
        app.panel = PanelData {
            backend: if nginx { "nginx" } else { "caddy" }.to_string(),
            backend_error: String::new(),
            cf_token_set: Some(true),
            sites: vec![
                SiteItem {
                    domain: "app.example.com".to_string(),
                    upstream: "127.0.0.1:3000".to_string(),
                },
                SiteItem {
                    domain: "api.example.com".to_string(),
                    upstream: "127.0.0.1:8080".to_string(),
                },
            ],
            certs: if nginx {
                vec![
                    CertItem {
                        domain: "app.example.com".to_string(),
                        expiry: "2027-01-30".to_string(),
                        status: "valid".to_string(),
                    },
                    CertItem {
                        domain: "api.example.com".to_string(),
                        expiry: "2026-12-05".to_string(),
                        status: "expiring".to_string(),
                    },
                ]
            } else {
                vec![]
            },
            firewall: FirewallData {
                nft_available: true,
                running: true,
                boot_enabled: true,
                ipv4_in: true,
                ipv6_in: false,
                intel_running: true,
                intel_entries: "134320".to_string(),
                ports: vec![
                    PortRule {
                        proto: "tcp".to_string(),
                        port: "22".to_string(),
                        source: "203.0.113.0/24".to_string(),
                        note: String::new(),
                    },
                    PortRule {
                        proto: "tcp".to_string(),
                        port: "443".to_string(),
                        source: "any".to_string(),
                        note: String::new(),
                    },
                    PortRule {
                        proto: "udp".to_string(),
                        port: "443".to_string(),
                        source: "any".to_string(),
                        note: String::new(),
                    },
                ],
                conflicts: vec![],
            },
            banned: vec![
                BannedItem {
                    jail: "sshd".to_string(),
                    ip: "198.51.100.10".to_string(),
                },
                BannedItem {
                    jail: "caddy-probe-h1".to_string(),
                    ip: "198.51.100.25".to_string(),
                },
            ],
            whitelist: vec!["203.0.113.5".to_string(), "2001:db8::/32".to_string()],
            ssh: SshData {
                ports: vec!["22".to_string()],
                password_auth: "off".to_string(),
                pubkey_auth: "on".to_string(),
                kbd_auth: "no".to_string(),
                root_pw_ready: true,
                ssh_conn_family: "IPv4".to_string(),
                keys: vec![SshKeyItem {
                    index: 1,
                    raw: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataForRenderTest jasper@work"
                        .to_string(),
                }],
            },
            repo: "jasper-khan/abuseguard".to_string(),
            reporting_on: true,
            report_key_set: true,
        };
        app.logs = LogsData {
            proxy: vec!["Nov 26 20:20:01 caddy[101]: served request".to_string()],
            certbot: vec!["Nov 26 20:10:00 certbot[201]: no renewals due".to_string()],
            fail2ban: vec![
                "2026-11-26 20:21:00 fail2ban.actions [sshd] Ban 198.51.100.10".to_string(),
            ],
        };
        app.logs_loaded = true;
        app.last_refreshed = "09:27:52Z".to_string();
        app
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn render_to_string(app: &mut App, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, app)).unwrap();
        let buf = term.backend().buffer();
        let mut out = String::new();
        for y in 0..h {
            let mut x = 0u16;
            while x < w {
                let sym = buf[(x, y)].symbol();
                out.push_str(sym);
                let step = sym.width().max(1) as u16;
                x = x.saturating_add(step);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn parses_debian_point_release_and_systemd_timers() {
        let deb = "ID=debian\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n";
        assert_eq!(
            parse_os_label(deb, "12.15\n"),
            "Debian GNU/Linux 12.15 (bookworm)"
        );
        let ubu = "ID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.2 LTS\"\nVERSION_ID=\"24.04\"\n";
        assert_eq!(parse_os_label(ubu, "trixie/sid\n"), "Ubuntu 24.04.2 LTS");

        let app = sample_app(false);
        assert_eq!(
            app.compact_next_timer(Some("Fri 2026-11-27 18:00:00 UTC")),
            "11-27 18:00 UTC"
        );
        assert_eq!(
            app.compact_next_timer(Some("2026-11-27 00:00:00")),
            "11-27 00:00"
        );
    }

    #[test]
    fn renders_home_and_all_subpages_at_narrow_and_wide_sizes() {
        for nginx in [false, true] {
            let mut app = sample_app(nginx);
            for (w, h) in [(80, 24), (130, 36)] {
                for tab in Tab::ALL {
                    app.tab = tab;
                    app.settings_idx = 0;
                    let screen = render_to_string(&mut app, w, h);
                    assert!(screen.contains('━'));
                    assert!(!screen.contains('┌') && !screen.contains('│'));
                }
            }
            app.tab = Tab::Overview;
            for (w, h) in [(60, 34), (68, 34), (80, 24), (100, 32), (130, 36)] {
                let home = render_to_string(&mut app, w, h);
                assert!(home.contains("AbuseGuard v1.0.4") && home.contains("Debian GNU/Linux 12.15"));
                assert!(home.contains("主机与防护状态") && home.contains("q 退出"));
                assert!(!home.contains('…'), "unexpected truncation at {}x{}:\n{}", w, h, home);
                assert!(
                    home.find("主机与防护状态").unwrap() < home.find("1. 站点与证书管理").unwrap(),
                    "status block must appear before menu"
                );
                let val_col = |label: &str, val: &str| -> usize {
                    home.lines()
                        .find(|line| line.contains(label) && line.contains(val))
                        .and_then(|line| line.find(val).map(|idx| line[..idx].width()))
                        .unwrap_or_else(|| panic!("missing {}/{} at {}x{}:\n{}", label, val, w, h, home))
                };
                let vcol = val_col("系统", "Debian");
                assert_eq!(val_col("内核", "6.1.0"), vcol);
                assert_eq!(val_col("防火墙", "nftables"), vcol);
                assert_eq!(val_col("情报", "134,320"), vcol);
                assert_eq!(val_col("SSH", "端口"), vcol);
                assert_eq!(val_col("封禁", "1,407"), vcol);
                assert!(home.find("情报    ").unwrap() < home.find("SSH     ").unwrap());
                if h >= 32 {
                    assert!(home.contains("开放端口 (3)"));
                }
            }

            app.tab = Tab::Sites;
            let sites_screen = render_to_string(&mut app, 110, 30);
            assert!(sites_screen.contains("app.example.com"));
            if nginx {
                assert!(sites_screen.contains("2027-01-30"));
            } else {
                assert!(sites_screen.contains("CF DNS-01"));
            }

            app.tab = Tab::Firewall;
            app.settings_idx = 0;
            let narrow_fw = render_to_string(&mut app, 80, 24);
            assert!(narrow_fw.contains("IPv4") && narrow_fw.contains("IPv6"));
            assert!(narrow_fw.contains("↓ 下方还有内容"));
        }
    }

    #[test]
    fn navigates_home_menu_and_flat_subpages_with_arrows_and_hotkeys() {
        let mut app = sample_app(false);
        assert_eq!(app.tab, Tab::Overview);
        assert_eq!(app.home_idx, 0);

        // Down -> Firewall (idx 1), Enter opens Firewall
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.home_idx, 1);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.tab, Tab::Firewall);

        // Enter on IPv4 入站 opens yes-confirm modal
        app.handle_key(key(KeyCode::Enter));
        assert!(matches!(app.modal, Some(Modal::Confirm(ref c)) if c.require_yes));
        app.handle_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());

        // Move to "封禁 IP 与白名单管理" (idx 6) -> Enter jumps to Blocklist
        for _ in 0..6 {
            app.handle_key(key(KeyCode::Down));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.tab, Tab::Blocklist);

        // Esc returns straight to Home
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.tab, Tab::Overview);

        // Direct '7' triggers SyncIntel, '8' triggers RefreshAll, '0' quits
        assert_eq!(
            app.handle_key(key(KeyCode::Char('7'))),
            CommandEffect::RunAction(PendingAction::SyncIntel)
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('8'))),
            CommandEffect::RefreshAll
        );
        assert_eq!(app.handle_key(key(KeyCode::Char('0'))), CommandEffect::Quit);
    }

    #[test]
    fn disabling_active_ssh_family_and_last_key_require_typing_yes() {
        let mut app = sample_app(false);
        app.handle_key(key(KeyCode::Char('2'))); // Firewall
        app.handle_key(key(KeyCode::Enter)); // IPv4 入站
        let screen = render_to_string(&mut app, 100, 28);
        assert!(screen.contains("高危警告"));
        assert_eq!(app.handle_key(key(KeyCode::Enter)), CommandEffect::None);
        for c in ['y', 'e', 's'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            CommandEffect::RunAction(PendingAction::FwFamily {
                family: "ipv4".to_string(),
                enable: false
            })
        );

        app.handle_key(key(KeyCode::Char('4'))); // SSH
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.handle_key(key(KeyCode::Enter)), CommandEffect::None);
        for c in ['y', 'e', 's'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            CommandEffect::RunAction(PendingAction::SshKeyDel {
                index: 1,
                raw: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockKeyDataForRenderTest jasper@work"
                    .to_string(),
                confirmed_yes: true
            })
        );
    }

    #[test]
    fn open_port_form_validates_and_toggles_protocol() {
        let mut app = sample_app(false);
        app.handle_key(key(KeyCode::Char('2'))); // Firewall
        for _ in 0..5 {
            app.handle_key(key(KeyCode::Down));
        }
        app.handle_key(key(KeyCode::Enter));
        app.handle_key(key(KeyCode::Up));
        app.handle_key(key(KeyCode::Char(' '))); // tcp -> udp
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Char('0')));
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.handle_key(key(KeyCode::Enter)), CommandEffect::None);
        assert!(matches!(app.modal, Some(Modal::Form(ref f)) if f.error.is_some()));

        app.handle_key(key(KeyCode::Up));
        app.handle_key(key(KeyCode::Up));
        app.handle_key(key(KeyCode::Backspace));
        for c in ['8', '4', '4', '3'] {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter)); // -> source
        app.handle_key(key(KeyCode::Enter)); // -> note
        for c in "代理节点".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        let eff = app.handle_key(key(KeyCode::Enter));
        assert_eq!(
            eff,
            CommandEffect::RunAction(PendingAction::FwOpen {
                proto: "udp".to_string(),
                port: "8443".to_string(),
                source: "any".to_string(),
                note: "代理节点".to_string(),
            })
        );

        // Verify custom port note renders in firewall subpage and home overview
        app.panel.firewall.ports.push(PortRule {
            proto: "udp".to_string(),
            port: "8443".to_string(),
            source: "any".to_string(),
            note: "代理节点".to_string(),
        });
        let fw = render_to_string(&mut app, 68, 34);
        assert!(fw.contains("8443") && fw.contains("代理节点"));
    }

    #[test]
    fn switching_to_system_tab_triggers_lazy_log_load() {
        let mut app = sample_app(false);
        app.logs_loaded = false;
        assert_eq!(
            app.handle_key(key(KeyCode::Char('6'))),
            CommandEffect::RefreshLogs
        );
        assert_eq!(app.tab, Tab::System);
        app.refreshing = Some("正在读取最近日志...".to_string());
        app.handle_key(key(KeyCode::Char('?')));
        assert!(matches!(app.modal, Some(Modal::Help)));
        app.handle_key(key(KeyCode::Esc));
        assert!(app.modal.is_none());
        assert_eq!(app.handle_key(key(KeyCode::Char('q'))), CommandEffect::Quit);
    }
}
