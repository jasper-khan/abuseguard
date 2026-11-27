// tui/mod.rs — Full-screen Ratatui control panel entrypoint and event loop.
mod backend;
mod model;
mod ui;

use crate::status::Snapshot;
use crate::tui::backend::ShellBackend;
use crate::tui::model::{App, CommandEffect, LogsData, PanelData, PendingAction, Tab, Toast};
use crate::util::logf;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io::{self, IsTerminal, Stdout};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const REFRESH_INTERVAL: Duration = Duration::from_secs(1800);
const EXIT_REEXEC_PANEL: i32 = 75;

enum WorkerMsg {
    Refreshed {
        snapshot: Snapshot<'static>,
        panel: Result<PanelData, String>,
        clock: String,
    },
    LogsLoaded {
        logs: Result<LogsData, String>,
        clock: String,
    },
    ActionDone {
        action: PendingAction,
        ok: bool,
        output: String,
    },
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut term = Terminal::new(backend)?;
        term.clear()?;
        Ok(term)
    }

    fn leave() {
        let _ = disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        Self::leave();
    }
}

pub fn run(args: &[String], version: &'static str) {
    let mut panel_path = PathBuf::from("/usr/local/bin/ag");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--panel" => {
                i += 1;
                if i >= args.len() {
                    logf("usage: caddy-abuseguard tui [--panel <path>]");
                    std::process::exit(2);
                }
                panel_path = PathBuf::from(&args[i]);
            }
            _ => {
                logf("usage: caddy-abuseguard tui [--panel <path>]");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        logf("tui requires an interactive terminal");
        std::process::exit(2);
    }

    let orig_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        TerminalGuard::leave();
        orig_hook(info);
    }));

    let backend = ShellBackend::new(panel_path, version);
    let exit_code = match run_loop(backend, version) {
        Ok(code) => code,
        Err(e) => {
            TerminalGuard::leave();
            logf(&format!("tui error: {}", e));
            1
        }
    };
    std::process::exit(exit_code);
}

fn run_loop(backend: ShellBackend, version: &'static str) -> io::Result<i32> {
    let _guard = TerminalGuard;
    let mut terminal = TerminalGuard::enter()?;
    let mut app = App::new(version);
    app.host = backend::collect_host_info();
    let (tx, rx) = mpsc::channel::<WorkerMsg>();

    spawn_refresh(&backend, &tx);
    app.refreshing = Some("正在加载运行状态...".to_string());
    let mut last_auto_refresh = Instant::now();

    loop {
        while let Ok(msg) = rx.try_recv() {
            match msg {
                WorkerMsg::Refreshed {
                    snapshot,
                    panel,
                    clock,
                } => {
                    app.snapshot = snapshot;
                    app.last_refreshed = clock;
                    match panel {
                        Ok(data) => {
                            app.panel = data;
                            app.load_error = None;
                        }
                        Err(e) => {
                            app.load_error = Some(e);
                        }
                    }
                    app.refreshing = None;
                    app.clamp_selections();
                    last_auto_refresh = Instant::now();
                }
                WorkerMsg::LogsLoaded { logs, clock } => {
                    app.last_refreshed = clock;
                    match logs {
                        Ok(data) => {
                            app.logs = data;
                            app.logs_loaded = true;
                        }
                        Err(e) => {
                            app.toast = Some(Toast {
                                ok: false,
                                summary: e.clone(),
                                full_output: e,
                            });
                        }
                    }
                    app.refreshing = None;
                }
                WorkerMsg::ActionDone { action, ok, output } => {
                    let needs_refresh = !matches!(action, PendingAction::ViewRuleset);
                    app.apply_action_result(&action, ok, output);
                    app.busy = None;
                    if needs_refresh {
                        app.refreshing = Some("正在刷新状态...".to_string());
                        spawn_refresh(&backend, &tx);
                    }
                }
            }
        }

        if app.busy.is_none()
            && app.refreshing.is_none()
            && last_auto_refresh.elapsed() >= REFRESH_INTERVAL
        {
            app.refreshing = Some("正在自动刷新状态...".to_string());
            spawn_refresh(&backend, &tx);
            last_auto_refresh = Instant::now();
        }

        terminal.draw(|frame| ui::render(frame, &mut app))?;

        if event::poll(Duration::from_millis(90))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match app.handle_key(key) {
                    CommandEffect::None => {}
                    CommandEffect::Quit => return Ok(0),
                    CommandEffect::RefreshAll => {
                        if app.refreshing.is_none() {
                            app.refreshing = Some("正在刷新全部状态...".to_string());
                            spawn_refresh(&backend, &tx);
                        }
                    }
                    CommandEffect::RefreshLogs => {
                        if app.refreshing.is_none() {
                            app.refreshing = Some("正在读取最近日志...".to_string());
                            spawn_logs(&backend, &tx);
                        }
                    }
                    CommandEffect::RunAction(action) => {
                        if action.is_interactive() {
                            drop(terminal);
                            TerminalGuard::leave();
                            let res = backend.run_interactive(&action);
                            if matches!(action, PendingAction::Update) && matches!(res, Ok(true)) {
                                return Ok(EXIT_REEXEC_PANEL);
                            }
                            if matches!(action, PendingAction::Uninstall)
                                && !backend.panel_script.exists()
                            {
                                return Ok(0);
                            }
                            terminal = TerminalGuard::enter()?;
                            match res {
                                Ok(true) => {
                                    app.toast = Some(Toast {
                                        ok: true,
                                        summary: "交互操作已完成。".to_string(),
                                        full_output: String::new(),
                                    });
                                }
                                Ok(false) => {
                                    app.toast = Some(Toast {
                                        ok: false,
                                        summary: "交互操作未完成或已取消。".to_string(),
                                        full_output: String::new(),
                                    });
                                }
                                Err(e) => {
                                    app.toast = Some(Toast {
                                        ok: false,
                                        summary: e.clone(),
                                        full_output: e,
                                    });
                                }
                            }
                            app.refreshing = Some("正在刷新状态...".to_string());
                            spawn_refresh(&backend, &tx);
                            if app.tab == Tab::System {
                                spawn_logs(&backend, &tx);
                            }
                        } else {
                            app.busy = Some(action.busy_label().to_string());
                            spawn_action(&backend, action, &tx);
                        }
                    }
                }
            }
        }
    }
}

fn spawn_refresh(backend: &ShellBackend, tx: &mpsc::Sender<WorkerMsg>) {
    let b = backend.clone();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let (snapshot, panel) = b.load_all();
        let _ = tx.send(WorkerMsg::Refreshed {
            snapshot,
            panel,
            clock: now_hms(),
        });
    });
}

fn spawn_logs(backend: &ShellBackend, tx: &mpsc::Sender<WorkerMsg>) {
    let b = backend.clone();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let logs = b.load_logs();
        let _ = tx.send(WorkerMsg::LogsLoaded {
            logs,
            clock: now_hms(),
        });
    });
}

fn spawn_action(backend: &ShellBackend, action: PendingAction, tx: &mpsc::Sender<WorkerMsg>) {
    let b = backend.clone();
    let tx = tx.clone();
    std::thread::spawn(move || {
        let (ok, output) = b.run_action(&action);
        let _ = tx.send(WorkerMsg::ActionDone { action, ok, output });
    });
}

fn now_hms() -> String {
    let now = time::OffsetDateTime::now_utc();
    format!("{:02}:{:02}:{:02}Z", now.hour(), now.minute(), now.second())
}
