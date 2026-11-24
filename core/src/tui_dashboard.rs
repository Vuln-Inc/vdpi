use anyhow::Result;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding, Paragraph, RenderDirection, Sparkline};
use ratatui::{Frame, Terminal};
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io::{self, IsTerminal, Stdout};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::field::{Field, Visit};
use tracing::{info, Level};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;
use vdpi::config::{DesyncMode, RuntimeConfig};
use vdpi::desync::{EngineContext, EngineTelemetrySnapshot};

pub const MAX_LOG_ENTRIES: usize = 150;
pub const THROUGHPUT_WINDOW_SECS: usize = 60;
const TICK_INTERVAL: Duration = Duration::from_millis(250);
const NOTICE_TTL: Duration = Duration::from_secs(3);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const SIDE_BY_SIDE_MIN_WIDTH: u16 = 72;

pub type SharedLogRing = Arc<Mutex<VecDeque<LogEntry>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: Level,
    pub message: String,
}

pub fn new_log_ring() -> SharedLogRing {
    Arc::new(Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)))
}

pub fn push_log_entry(ring: &SharedLogRing, entry: LogEntry) {
    let mut guard = ring.lock().unwrap_or_else(|e| e.into_inner());
    while guard.len() >= MAX_LOG_ENTRIES {
        guard.pop_front();
    }
    guard.push_back(entry);
}

pub fn should_enable_dashboard(cfg: &RuntimeConfig, is_service: bool) -> bool {
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && !cfg.quiet
        && !cfg.debug
        && !is_service
        && std::env::var("TERM").as_deref() != Ok("dumb")
}

/// Lightweight tracing subscriber layer that routes `INFO`/`WARN`/`ERROR` events into
/// a capped ring buffer instead of printing raw text over the alternate screen.
/// When `passthrough_stderr` is set to `true` (e.g. headless fallback), events are
/// also emitted to stderr so logs are never silently dropped.
pub struct TuiLogLayer {
    logs: SharedLogRing,
    passthrough_stderr: Arc<AtomicBool>,
}

impl TuiLogLayer {
    pub fn new(logs: SharedLogRing, passthrough_stderr: Arc<AtomicBool>) -> Self {
        Self {
            logs,
            passthrough_stderr,
        }
    }
}

impl<S> Layer<S> for TuiLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        if !matches!(level, Level::ERROR | Level::WARN | Level::INFO) {
            return;
        }
        let mut visitor = LogFieldVisitor::default();
        event.record(&mut visitor);
        let message = visitor.into_message();
        if message.is_empty() {
            return;
        }
        let timestamp = format_wall_clock(SystemTime::now());
        if self.passthrough_stderr.load(Ordering::Relaxed) {
            let lvl = match level {
                Level::ERROR => "ERROR",
                Level::WARN => "WARN",
                _ => "INFO",
            };
            eprintln!("{timestamp}  {lvl} {message}");
        }
        push_log_entry(
            &self.logs,
            LogEntry {
                timestamp,
                level,
                message,
            },
        );
    }
}

#[derive(Default)]
struct LogFieldVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl LogFieldVisitor {
    fn into_message(self) -> String {
        let mut out = String::new();
        if let Some(msg) = self.message {
            out.push_str(&sanitize_single_line(&msg));
        }
        for field in self.fields {
            if !out.is_empty() {
                out.push_str("  ");
            }
            out.push_str(&sanitize_single_line(&field));
        }
        out
    }
}

impl Visit for LogFieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.fields.push(format!("{}={value}", field.name()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }
}

fn sanitize_single_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if ch == '\n' || ch == '\r' || ch == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else if !ch.is_control() {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

/// Fixed-size 480-byte ring storing the last 60 seconds of total throughput (bytes/sec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputRing {
    samples: [u64; THROUGHPUT_WINDOW_SECS],
}

impl Default for ThroughputRing {
    fn default() -> Self {
        Self::new()
    }
}

impl ThroughputRing {
    pub const fn new() -> Self {
        Self {
            samples: [0; THROUGHPUT_WINDOW_SECS],
        }
    }

    pub fn push(&mut self, bytes_per_sec: u64) {
        self.samples.rotate_left(1);
        self.samples[THROUGHPUT_WINDOW_SECS - 1] = bytes_per_sec;
    }

    pub fn samples(&self) -> &[u64; THROUGHPUT_WINDOW_SECS] {
        &self.samples
    }

    pub fn latest(&self) -> u64 {
        self.samples[THROUGHPUT_WINDOW_SECS - 1]
    }

    pub fn peak(&self) -> u64 {
        self.samples.iter().copied().max().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct DashboardInfo {
    pub primary_addr: SocketAddr,
    pub socks_addr: Option<SocketAddr>,
    pub mode: DesyncMode,
    pub enable_doh: bool,
    pub system_proxy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeStatus {
    Running,
    Pass { latency_ms: u128, detail: String },
    Fail { latency_ms: u128, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeRow {
    label: &'static str,
    host: &'static str,
    status: ProbeStatus,
}

#[derive(Debug, Clone)]
struct DiagnosticsState {
    run_id: u64,
    rows: [ProbeRow; 4],
}

impl DiagnosticsState {
    fn new_running(run_id: u64) -> Self {
        Self {
            run_id,
            rows: [
                ProbeRow {
                    label: "1.1.1.1 / DoH DNS Ring",
                    host: "one.one.one.one",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "discord.com",
                    host: "discord.com",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "gateway.discord.gg",
                    host: "gateway.discord.gg",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "www.roblox.com",
                    host: "www.roblox.com",
                    status: ProbeStatus::Running,
                },
            ],
        }
    }
}

const BORDER_SLATE: Color = Color::Rgb(58, 66, 78);
const TEXT_WHITE: Color = Color::Rgb(248, 250, 252);
const STEEL_MUTED: Color = Color::Rgb(148, 163, 184);
const STEEL_DIM: Color = Color::Rgb(100, 116, 139);
const EMERALD_ACTIVE: Color = Color::Rgb(62, 207, 142);
const AMBER_WARN: Color = Color::Rgb(245, 185, 90);
const RED_DANGER: Color = Color::Rgb(235, 96, 107);

#[derive(Debug, Clone, Copy)]
struct Palette {
    border_type: BorderType,
    border: Style,
    title: Style,
    text: Style,
    label: Style,
    dim: Style,
    emerald: Style,
    amber: Style,
    red: Style,
    key_hint: Style,
}

impl Palette {
    fn new(color: bool) -> Self {
        if !color {
            return Self {
                border_type: BorderType::Plain,
                border: Style::default(),
                title: Style::default().add_modifier(Modifier::BOLD),
                text: Style::default(),
                label: Style::default(),
                dim: Style::default().add_modifier(Modifier::DIM),
                emerald: Style::default().add_modifier(Modifier::BOLD),
                amber: Style::default().add_modifier(Modifier::BOLD),
                red: Style::default().add_modifier(Modifier::BOLD),
                key_hint: Style::default().add_modifier(Modifier::BOLD),
            };
        }

        Self {
            border_type: BorderType::Rounded,
            border: Style::default().fg(BORDER_SLATE),
            title: Style::default().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
            text: Style::default().fg(TEXT_WHITE),
            label: Style::default().fg(STEEL_MUTED),
            dim: Style::default().fg(STEEL_DIM),
            emerald: Style::default().fg(EMERALD_ACTIVE),
            amber: Style::default().fg(AMBER_WARN),
            red: Style::default().fg(RED_DANGER),
            key_hint: Style::default().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
        }
    }
}

struct DashboardState {
    info: DashboardInfo,
    palette: Palette,
    started_at: Instant,
    telemetry: EngineTelemetrySnapshot,
    rx_rate: u64,
    tx_rate: u64,
    prev_rx: u64,
    prev_tx: u64,
    last_rate_sample: Instant,
    throughput: ThroughputRing,
    logs: SharedLogRing,
    follow_logs: bool,
    log_scroll: usize,
    log_viewport_rows: usize,
    notice: Option<(String, Instant)>,
    diagnostics_open: bool,
    diagnostics: Arc<Mutex<DiagnosticsState>>,
    diag_tasks: JoinSet<()>,
    next_diag_run: u64,
}

impl DashboardState {
    fn new(info: DashboardInfo, logs: SharedLogRing, color: bool, now: Instant) -> Self {
        Self {
            info,
            palette: Palette::new(color),
            started_at: now,
            telemetry: EngineTelemetrySnapshot::default(),
            rx_rate: 0,
            tx_rate: 0,
            prev_rx: 0,
            prev_tx: 0,
            last_rate_sample: now,
            throughput: ThroughputRing::new(),
            logs,
            follow_logs: true,
            log_scroll: 0,
            log_viewport_rows: 1,
            notice: None,
            diagnostics_open: false,
            diagnostics: Arc::new(Mutex::new(DiagnosticsState::new_running(0))),
            diag_tasks: JoinSet::new(),
            next_diag_run: 0,
        }
    }

    fn update_telemetry(&mut self, snap: EngineTelemetrySnapshot, now: Instant) {
        self.telemetry = snap;
        let elapsed = now.saturating_duration_since(self.last_rate_sample);
        if elapsed >= Duration::from_secs(1) {
            let elapsed_ms = elapsed.as_millis().max(1) as u64;
            let drx = snap.bytes_rx.saturating_sub(self.prev_rx);
            let dtx = snap.bytes_tx.saturating_sub(self.prev_tx);
            self.rx_rate = drx.saturating_mul(1000) / elapsed_ms;
            self.tx_rate = dtx.saturating_mul(1000) / elapsed_ms;
            self.throughput
                .push(self.rx_rate.saturating_add(self.tx_rate));
            self.prev_rx = snap.bytes_rx;
            self.prev_tx = snap.bytes_tx;
            self.last_rate_sample = now;
        }
        if self.notice.as_ref().is_some_and(|(_, exp)| now >= *exp) {
            self.notice = None;
        }
    }

    fn set_notice(&mut self, message: impl Into<String>, now: Instant) {
        self.notice = Some((message.into(), now + NOTICE_TTL));
    }

    fn log_count(&self) -> usize {
        self.logs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    fn scroll_up(&mut self, lines: usize) {
        let total = self.log_count();
        let max_scroll = total.saturating_sub(self.log_viewport_rows.max(1));
        if max_scroll == 0 {
            self.follow_logs = true;
            self.log_scroll = 0;
            return;
        }
        let base = if self.follow_logs {
            max_scroll
        } else {
            self.log_scroll.min(max_scroll)
        };
        self.follow_logs = false;
        self.log_scroll = base.saturating_sub(lines);
    }

    fn scroll_down(&mut self, lines: usize) {
        if self.follow_logs {
            return;
        }
        let total = self.log_count();
        let max_scroll = total.saturating_sub(self.log_viewport_rows.max(1));
        let next = self.log_scroll.saturating_add(lines).min(max_scroll);
        if next >= max_scroll {
            self.follow_logs = true;
            self.log_scroll = max_scroll;
        } else {
            self.log_scroll = next;
        }
    }

    fn scroll_home(&mut self) {
        let total = self.log_count();
        let max_scroll = total.saturating_sub(self.log_viewport_rows.max(1));
        if max_scroll > 0 {
            self.follow_logs = false;
            self.log_scroll = 0;
        }
    }

    fn scroll_end(&mut self) {
        let total = self.log_count();
        let max_scroll = total.saturating_sub(self.log_viewport_rows.max(1));
        self.follow_logs = true;
        self.log_scroll = max_scroll;
    }

    fn abort_diagnostics_tasks(&mut self) {
        self.diag_tasks.abort_all();
        while self.diag_tasks.try_join_next().is_some() {}
    }

    fn begin_diagnostics_run(&mut self) -> (u64, [(usize, &'static str); 4]) {
        self.abort_diagnostics_tasks();
        self.next_diag_run = self.next_diag_run.wrapping_add(1).max(1);
        let run_id = self.next_diag_run;
        let fresh = DiagnosticsState::new_running(run_id);
        let targets = [
            (0, fresh.rows[0].host),
            (1, fresh.rows[1].host),
            (2, fresh.rows[2].host),
            (3, fresh.rows[3].host),
        ];
        *self.diagnostics.lock().unwrap_or_else(|e| e.into_inner()) = fresh;
        (run_id, targets)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAction {
    None,
    Redraw,
    ClearCache,
    RunDiagnostics,
    Quit,
}

fn handle_key_event(state: &mut DashboardState, key: KeyEvent) -> KeyAction {
    if key.kind == KeyEventKind::Release {
        return KeyAction::None;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return KeyAction::Quit;
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return KeyAction::None;
    }

    if state.diagnostics_open {
        if key.kind != KeyEventKind::Press {
            return KeyAction::None;
        }
        return match key.code {
            KeyCode::Esc | KeyCode::Char('d' | 'D') => {
                state.diagnostics_open = false;
                state.abort_diagnostics_tasks();
                KeyAction::Redraw
            }
            KeyCode::Char('r' | 'R') => KeyAction::RunDiagnostics,
            KeyCode::Char('q' | 'Q') => KeyAction::Quit,
            _ => KeyAction::None,
        };
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll_up(1);
            KeyAction::Redraw
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll_down(1);
            KeyAction::Redraw
        }
        KeyCode::PageUp => {
            let page = state.log_viewport_rows.max(1);
            state.scroll_up(page);
            KeyAction::Redraw
        }
        KeyCode::PageDown => {
            let page = state.log_viewport_rows.max(1);
            state.scroll_down(page);
            KeyAction::Redraw
        }
        KeyCode::Home => {
            state.scroll_home();
            KeyAction::Redraw
        }
        KeyCode::End => {
            state.scroll_end();
            KeyAction::Redraw
        }
        _ if key.kind != KeyEventKind::Press => KeyAction::None,
        KeyCode::Char('d' | 'D') => {
            state.diagnostics_open = true;
            KeyAction::RunDiagnostics
        }
        KeyCode::Char('c' | 'C') => KeyAction::ClearCache,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => KeyAction::Quit,
        _ => KeyAction::None,
    }
}

/// RAII guard that enters raw mode + alternate screen and guarantees clean terminal
/// restoration on normal exit, error return, or panic unwind.
struct DashboardGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl DashboardGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = execute!(stdout, Show, LeaveAlternateScreen);
            let _ = terminal::disable_raw_mode();
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(mut terminal) => {
                let _ = terminal.clear();
                Ok(Self { terminal })
            }
            Err(err) => {
                let mut out = io::stdout();
                let _ = execute!(out, Show, LeaveAlternateScreen);
                let _ = terminal::disable_raw_mode();
                Err(err)
            }
        }
    }
}

impl Drop for DashboardGuard {
    fn drop(&mut self) {
        let _ = execute!(self.terminal.backend_mut(), Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
    }
}

/// RAII guard for the background stdin event reader thread. Declared after
/// `DashboardGuard` so that on normal exit, error return, future cancellation,
/// or panic unwind the reader thread is always signaled to stop and joined
/// before raw mode is disabled.
struct EventReaderGuard {
    stop_reader: Arc<AtomicBool>,
    ev_rx: Option<mpsc::Receiver<Event>>,
    reader_handle: Option<std::thread::JoinHandle<()>>,
}

impl EventReaderGuard {
    fn spawn() -> Self {
        let stop_reader = Arc::new(AtomicBool::new(false));
        let reader_flag = Arc::clone(&stop_reader);
        let (ev_tx, ev_rx) = mpsc::channel::<Event>(32);

        let reader_handle = std::thread::spawn(move || {
            while !reader_flag.load(Ordering::Relaxed) {
                match event::poll(Duration::from_millis(50)) {
                    Ok(true) => match event::read() {
                        Ok(ev) => {
                            if ev_tx.blocking_send(ev).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    Ok(false) => {}
                    Err(_) => break,
                }
            }
        });

        Self {
            stop_reader,
            ev_rx: Some(ev_rx),
            reader_handle: Some(reader_handle),
        }
    }

    async fn recv(&mut self) -> Option<Event> {
        match self.ev_rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }
}

impl Drop for EventReaderGuard {
    fn drop(&mut self) {
        self.stop_reader.store(true, Ordering::Relaxed);
        self.ev_rx = None;
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
    }
}

fn spawn_diagnostics_probes(
    tasks: &mut JoinSet<()>,
    ctx: &EngineContext,
    diag_state: &Arc<Mutex<DiagnosticsState>>,
    run_id: u64,
    targets: [(usize, &'static str); 4],
) {
    for (idx, host) in targets {
        let dns = ctx.dns.clone();
        let diag = Arc::clone(diag_state);
        tasks.spawn(async move {
            let started = Instant::now();
            let result = tokio::time::timeout(PROBE_TIMEOUT, dns.resolve(host)).await;
            let latency_ms = started.elapsed().as_millis();
            let status = match result {
                Ok(Ok(ips)) => {
                    let detail = ips
                        .first()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "ok".to_string());
                    ProbeStatus::Pass { latency_ms, detail }
                }
                Ok(Err(err)) => ProbeStatus::Fail {
                    latency_ms,
                    reason: sanitize_single_line(&err.to_string()),
                },
                Err(_) => ProbeStatus::Fail {
                    latency_ms,
                    reason: "timed out".to_string(),
                },
            };

            let mut guard = diag.lock().unwrap_or_else(|e| e.into_inner());
            if guard.run_id == run_id {
                guard.rows[idx].status = status;
            }
        });
    }
}

/// Runs the interactive ratatui foreground dashboard at 4 Hz until the user quits
/// (`q`, `Esc`, `Ctrl-C`) or `external_shutdown` resolves. Restores the terminal via
/// RAII `DashboardGuard`, joins the stdin reader via `EventReaderGuard`, and signals
/// `shutdown_tx` on normal exit (leaving the server running on draw errors so the
/// caller can fall back to headless mode).
pub async fn run_dashboard<F>(
    info: DashboardInfo,
    ctx: EngineContext,
    logs: SharedLogRing,
    shutdown_tx: watch::Sender<bool>,
    external_shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut guard = DashboardGuard::enter()?;

    let now = Instant::now();
    let mut state = DashboardState::new(info, logs, color, now);
    state.update_telemetry(ctx.telemetry_snapshot(), now);

    let mut reader_guard = EventReaderGuard::spawn();

    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tokio::pin!(external_shutdown);

    let loop_result: io::Result<()> = loop {
        let now = Instant::now();
        state.update_telemetry(ctx.telemetry_snapshot(), now);
        if let Err(err) = guard
            .terminal
            .draw(|frame| render_dashboard(frame, &mut state))
        {
            break Err(err);
        }

        tokio::select! {
            biased;
            _ = &mut external_shutdown => {
                break Ok(());
            }
            maybe_ev = reader_guard.recv() => {
                match maybe_ev {
                    Some(Event::Key(key)) => {
                        match handle_key_event(&mut state, key) {
                            KeyAction::Quit => break Ok(()),
                            KeyAction::ClearCache => {
                                let clear_ctx = ctx.clone();
                                tokio::spawn(async move {
                                    clear_ctx.clear_adaptive_cache().await;
                                    clear_ctx.dns.clear_cache().await;
                                    info!("adaptive strategy and DNS caches cleared");
                                });
                                state.set_notice("Cache cleared", Instant::now());
                            }
                            KeyAction::RunDiagnostics => {
                                let (run_id, targets) = state.begin_diagnostics_run();
                                spawn_diagnostics_probes(
                                    &mut state.diag_tasks,
                                    &ctx,
                                    &state.diagnostics,
                                    run_id,
                                    targets,
                                );
                            }
                            KeyAction::Redraw | KeyAction::None => {}
                        }
                    }
                    // Resize and other events simply trigger the next redraw iteration.
                    Some(_) => {}
                    None => break Ok(()),
                }
            }
            _ = tick.tick() => {}
        }
    };

    state.abort_diagnostics_tasks();
    drop(reader_guard);
    drop(guard);

    loop_result?;
    let _ = shutdown_tx.send(true);
    Ok(())
}

fn render_dashboard(frame: &mut Frame<'_>, state: &mut DashboardState) {
    let area = frame.area();
    if area.width < 12 || area.height < 8 {
        let msg = Line::from(format!("vdpi v{}  (q quit)", env!("CARGO_PKG_VERSION")))
            .style(state.palette.title);
        frame.render_widget(Paragraph::new(msg), area);
        return;
    }

    let wide = area.width >= SIDE_BY_SIDE_MIN_WIDTH;
    if wide {
        let mid_height = if area.height >= 18 { 9 } else { 7 };
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(mid_height),
                Constraint::Min(4),
                Constraint::Length(1),
            ])
            .split(area);

        render_status_bar(frame, rows[0], state);

        let mid_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(rows[1]);
        render_stats_panel(frame, mid_cols[0], state);
        render_sparkline_panel(frame, mid_cols[1], state);

        render_activity_log(frame, rows[2], state);
        render_footer(frame, rows[3], state);
    } else {
        let (stats_h, spark_h) = if area.height >= 22 { (9, 5) } else { (7, 4) };
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(stats_h),
                Constraint::Length(spark_h),
                Constraint::Min(3),
                Constraint::Length(1),
            ])
            .split(area);

        render_status_bar(frame, rows[0], state);
        render_stats_panel(frame, rows[1], state);
        render_sparkline_panel(frame, rows[2], state);
        render_activity_log(frame, rows[3], state);
        render_footer(frame, rows[4], state);
    }

    if state.diagnostics_open {
        render_diagnostics_modal(frame, area, state);
    }
}

fn render_status_bar(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let p = state.palette;
    let block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let version = env!("CARGO_PKG_VERSION");
    let primary = state.info.primary_addr.to_string();
    let socks = state.info.socks_addr.map(|sa| sa.to_string());
    let mode = format_desync_mode(state.info.mode);
    let dns = if state.info.enable_doh { "DoH" } else { "UDP" };
    let uptime = format_uptime(state.started_at.elapsed());

    let w = inner.width as usize;
    let sep = Span::styled(" · ", p.dim);

    // "● vdpi v{version}" = 8 chars + version length.
    let head_len = 8 + version.len();
    let full_len = head_len
        + 3
        + "HTTP/SOCKS ".len()
        + primary.len()
        + socks
            .as_ref()
            .map_or(0, |s| 3 + "SOCKS/UDP ".len() + s.len())
        + 3
        + mode.len()
        + 3
        + dns.len()
        + 3
        + "Uptime ".len()
        + uptime.len();
    let med_len = head_len
        + 3
        + "HTTP ".len()
        + primary.len()
        + socks.as_ref().map_or(0, |s| 3 + "SOCKS ".len() + s.len())
        + 3
        + mode.len()
        + 3
        + dns.len()
        + 3
        + "Uptime ".len()
        + uptime.len();
    let compact_len = head_len
        + 3
        + primary.len()
        + socks.as_ref().map_or(0, |s| 3 + "SOCKS ".len() + s.len())
        + 3
        + mode.len()
        + 1
        + dns.len()
        + 3
        + uptime.len();

    let mut spans = vec![
        Span::styled("●", p.emerald),
        Span::raw(" "),
        Span::styled("vdpi", p.title),
        Span::raw(" "),
        Span::styled(format!("v{version}"), p.label),
    ];

    if w >= full_len {
        spans.push(sep.clone());
        spans.push(Span::styled("HTTP/SOCKS ", p.label));
        spans.push(Span::styled(primary, p.text));
        if let Some(sa) = socks {
            spans.push(sep.clone());
            spans.push(Span::styled("SOCKS/UDP ", p.label));
            spans.push(Span::styled(sa, p.text));
        }
        spans.push(sep.clone());
        spans.push(Span::styled(format!("{mode} · {dns}"), p.text));
        spans.push(sep);
        spans.push(Span::styled("Uptime ", p.label));
        spans.push(Span::styled(uptime, p.text));
    } else if w >= med_len {
        spans.push(sep.clone());
        spans.push(Span::styled("HTTP ", p.label));
        spans.push(Span::styled(primary, p.text));
        if let Some(sa) = socks {
            spans.push(sep.clone());
            spans.push(Span::styled("SOCKS ", p.label));
            spans.push(Span::styled(sa, p.text));
        }
        spans.push(sep.clone());
        spans.push(Span::styled(format!("{mode} · {dns}"), p.text));
        spans.push(sep);
        spans.push(Span::styled("Uptime ", p.label));
        spans.push(Span::styled(uptime, p.text));
    } else if w >= compact_len {
        spans.push(sep.clone());
        spans.push(Span::styled(primary, p.text));
        if let Some(sa) = socks {
            spans.push(sep.clone());
            spans.push(Span::styled("SOCKS ", p.label));
            spans.push(Span::styled(sa, p.text));
        }
        spans.push(sep.clone());
        spans.push(Span::styled(format!("{mode}/{dns}"), p.label));
        spans.push(sep);
        spans.push(Span::styled(uptime, p.text));
    } else {
        spans.push(sep.clone());
        spans.push(Span::styled(primary, p.text));
        spans.push(sep);
        spans.push(Span::styled(uptime, p.text));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn render_stats_panel(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let p = state.palette;
    let block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1))
        .title_top(
            Line::from(" Traffic & Engine ")
                .style(p.title)
                .left_aligned(),
        );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let snap = state.telemetry;
    let proxy_val = if state.info.system_proxy {
        "Active"
    } else {
        "Disabled"
    };
    let proxy_style = if state.info.system_proxy {
        p.emerald
    } else {
        p.label
    };
    let heal_style = if snap.auto_heal_escalations > 0 {
        p.amber
    } else {
        p.text
    };

    let rows = [
        (
            "Download",
            format!(
                "{} ({})",
                format_bytes(snap.bytes_rx),
                format_rate(state.rx_rate)
            ),
            p.text,
        ),
        (
            "Upload",
            format!(
                "{} ({})",
                format_bytes(snap.bytes_tx),
                format_rate(state.tx_rate)
            ),
            p.text,
        ),
        (
            "Connections",
            format!("{} / {}", snap.active_connections, snap.total_connections),
            p.text,
        ),
        ("TLS Handshakes", snap.tls_handshakes.to_string(), p.text),
        (
            "Auto-Heal",
            snap.auto_heal_escalations.to_string(),
            heal_style,
        ),
        ("Cached Hosts", snap.learned_hosts.to_string(), p.text),
        ("Proxy", proxy_val.to_string(), proxy_style),
    ];

    let width = inner.width as usize;
    let lines: Vec<Line<'_>> = rows
        .into_iter()
        .take(inner.height as usize)
        .map(|(label, value, val_style)| format_kv_line(label, &value, width, p.label, val_style))
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_sparkline_panel(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let p = state.palette;
    let cur = format_rate(state.throughput.latest());
    let peak = state.throughput.peak();
    let metrics_title = format!(" {cur} · peak {} ", format_rate(peak));

    let block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1))
        .title_top(
            Line::from(" Throughput · 60s ")
                .style(p.title)
                .left_aligned(),
        )
        .title_top(Line::from(metrics_title).style(p.label).right_aligned());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let sparkline = Sparkline::default()
        .data(state.throughput.samples().iter().rev().copied())
        .max(peak.max(1))
        .direction(RenderDirection::RightToLeft)
        .style(p.emerald);
    frame.render_widget(sparkline, inner);
}

fn render_activity_log(frame: &mut Frame<'_>, area: Rect, state: &mut DashboardState) {
    let p = state.palette;
    let inner_height = area.height.saturating_sub(2) as usize;
    state.log_viewport_rows = inner_height.max(1);
    let visible = inner_height;

    let (total, start, visible_entries) = {
        let guard = state.logs.lock().unwrap_or_else(|e| e.into_inner());
        let total = guard.len();
        let max_scroll = total.saturating_sub(state.log_viewport_rows);
        let start = if state.follow_logs {
            state.log_scroll = max_scroll;
            max_scroll
        } else {
            let clamped = state.log_scroll.min(max_scroll);
            state.log_scroll = clamped;
            clamped
        };
        let entries: Vec<LogEntry> = if visible == 0 {
            Vec::new()
        } else {
            guard.iter().skip(start).take(visible).cloned().collect()
        };
        (total, start, entries)
    };

    let status_badge = if !state.follow_logs && total > state.log_viewport_rows {
        let end_idx = (start + state.log_viewport_rows).min(total);
        Line::from(format!(" paused · {end_idx}/{total} "))
            .style(p.amber)
            .right_aligned()
    } else {
        Line::from(format!(" {total}/{MAX_LOG_ENTRIES} "))
            .style(p.dim)
            .right_aligned()
    };

    let block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1))
        .title_top(Line::from(" Activity Log ").style(p.title).left_aligned())
        .title_top(status_badge);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if visible_entries.is_empty() {
        let empty = Line::from(Span::styled("Waiting for engine activity...", p.dim));
        frame.render_widget(Paragraph::new(empty), inner);
        return;
    }

    let msg_budget = (inner.width as usize).saturating_sub(17);
    let lines: Vec<Line<'_>> = visible_entries
        .iter()
        .map(|entry| {
            let (lvl_text, lvl_style) = match entry.level {
                Level::ERROR => ("ERROR", p.red),
                Level::WARN => ("WARN ", p.amber),
                _ => ("INFO ", p.label),
            };
            let msg = truncate_chars(&entry.message, msg_budget);
            Line::from(vec![
                Span::styled(entry.timestamp.as_str(), p.dim),
                Span::raw("  "),
                Span::styled(lvl_text, lvl_style),
                Span::raw("  "),
                Span::styled(msg, p.text),
            ])
        })
        .collect();

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let p = state.palette;

    let (legend_area, notice_slot) = if let Some((notice, _)) = &state.notice {
        let notice_text = format!("{notice} ");
        let notice_width = (notice_text.chars().count() as u16).min(area.width / 2);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(notice_width)])
            .split(area);
        (cols[0], Some((cols[1], notice_text)))
    } else {
        (area, None)
    };

    let w = usize::from(legend_area.width);
    let legend = if w >= 57 {
        let sep = Span::styled("  ·  ", p.dim);
        Line::from(vec![
            Span::raw(" "),
            Span::styled("d", p.key_hint),
            Span::styled(" diagnostics", p.dim),
            sep.clone(),
            Span::styled("c", p.key_hint),
            Span::styled(" clear cache", p.dim),
            sep.clone(),
            Span::styled("↑↓", p.key_hint),
            Span::styled(" scroll", p.dim),
            sep,
            Span::styled("q", p.key_hint),
            Span::styled(" quit", p.dim),
        ])
    } else if w >= 38 {
        let sep = Span::styled(" · ", p.dim);
        Line::from(vec![
            Span::raw(" "),
            Span::styled("d", p.key_hint),
            Span::styled(" diag", p.dim),
            sep.clone(),
            Span::styled("c", p.key_hint),
            Span::styled(" cache", p.dim),
            sep.clone(),
            Span::styled("↑↓", p.key_hint),
            Span::styled(" scroll", p.dim),
            sep,
            Span::styled("q", p.key_hint),
            Span::styled(" quit", p.dim),
        ])
    } else if w >= 20 {
        let sep = Span::styled(" · ", p.dim);
        Line::from(vec![
            Span::raw(" "),
            Span::styled("d", p.key_hint),
            sep.clone(),
            Span::styled("c", p.key_hint),
            sep.clone(),
            Span::styled("↑↓", p.key_hint),
            sep,
            Span::styled("q", p.key_hint),
            Span::styled(" quit", p.dim),
        ])
    } else {
        Line::from(vec![
            Span::raw(" "),
            Span::styled("q", p.key_hint),
            Span::styled(" quit", p.dim),
        ])
    };

    frame.render_widget(Paragraph::new(legend), legend_area);
    if let Some((notice_area, notice_text)) = notice_slot {
        frame.render_widget(
            Paragraph::new(Line::from(notice_text).style(p.emerald).right_aligned()),
            notice_area,
        );
    }
}

fn render_diagnostics_modal(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let p = state.palette;
    let popup_w = area.width.saturating_sub(4).clamp(24, 68).min(area.width);
    let popup_h = 10u16
        .min(area.height.saturating_sub(2).max(5))
        .min(area.height);
    let popup = centered_rect(area, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1))
        .title_top(Line::from(" Diagnostics ").style(p.title).left_aligned())
        .title_top(
            Line::from(" r re-run · esc close ")
                .style(p.dim)
                .right_aligned(),
        );
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let snapshot = state
        .diagnostics
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    let mut lines = Vec::with_capacity(7);
    let show_detail = inner.width >= 52;
    let target_w = if inner.width >= 44 { 24 } else { 18 };

    if inner.height >= 6 {
        let header = if show_detail {
            format!(
                "{:<target_w$}  {:<10}  {:>7}  {}",
                "Target", "Status", "Latency", "Detail"
            )
        } else {
            format!(
                "{:<target_w$}  {:<10}  {:>7}",
                "Target", "Status", "Latency"
            )
        };
        lines.push(Line::from(Span::styled(
            truncate_chars(&header, inner.width as usize),
            p.dim,
        )));
    }

    let mut passed = 0usize;
    let mut failed = 0usize;

    for row in &snapshot.rows {
        let label = format!("{:<target_w$}", truncate_chars(row.label, target_w));
        let (status_text, status_style, latency_text, detail_text) = match &row.status {
            ProbeStatus::Running => (
                "Running...".to_string(),
                p.amber,
                "--".to_string(),
                String::new(),
            ),
            ProbeStatus::Pass { latency_ms, detail } => {
                passed += 1;
                (
                    "PASS".to_string(),
                    p.emerald,
                    format!("{latency_ms} ms"),
                    detail.clone(),
                )
            }
            ProbeStatus::Fail { latency_ms, reason } => {
                failed += 1;
                (
                    "FAIL".to_string(),
                    p.red,
                    format!("{latency_ms} ms"),
                    reason.clone(),
                )
            }
        };

        let mut spans = vec![
            Span::styled(label, p.text),
            Span::raw("  "),
            Span::styled(format!("{status_text:<10}"), status_style),
            Span::raw("  "),
            Span::styled(format!("{latency_text:>7}"), p.label),
        ];

        if show_detail && !detail_text.is_empty() {
            let used = target_w + 2 + 10 + 2 + 7 + 2;
            let rem = (inner.width as usize).saturating_sub(used);
            if rem > 0 {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(truncate_chars(&detail_text, rem), p.dim));
            }
        }

        lines.push(Line::from(spans));
    }

    if inner.height >= 7 {
        lines.push(Line::raw(""));
        let total = snapshot.rows.len();
        let done = passed + failed;
        let summary = if done < total {
            format!("Probing {done}/{total} targets via engine DNS...")
        } else if failed == 0 {
            format!("All {total}/{total} probes passed")
        } else {
            format!("{passed}/{total} passed · {failed} failed")
        };
        let summary_style = if done < total {
            p.dim
        } else if failed == 0 {
            p.emerald
        } else {
            p.amber
        };
        lines.push(Line::from(Span::styled(summary, summary_style)));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width, height)
}

fn format_kv_line<'a>(
    label: &'a str,
    value: &str,
    width: usize,
    label_style: Style,
    value_style: Style,
) -> Line<'a> {
    let label_len = label.chars().count();
    let max_val = width.saturating_sub(label_len + 1);
    let val = truncate_chars(value, max_val);
    let val_len = val.chars().count();
    let gap = width.saturating_sub(label_len + val_len).max(1);
    Line::from(vec![
        Span::styled(label, label_style),
        Span::raw(" ".repeat(gap)),
        Span::styled(val, value_style),
    ])
}

fn format_desync_mode(mode: DesyncMode) -> &'static str {
    match mode {
        DesyncMode::Combo => "Combo",
        DesyncMode::TlsRecord => "TLS Record",
        DesyncMode::Fragment => "Fragment",
        DesyncMode::Split => "Split",
    }
}

fn format_uptime(dur: Duration) -> String {
    let secs = dur.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn format_wall_clock(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let tod = secs % 86_400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    const TB: f64 = GB * 1024.0;

    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let b = bytes as f64;
    if b < MB {
        format!("{:.1} KB", b / KB)
    } else if b < GB {
        format!("{:.1} MB", b / MB)
    } else if b < TB {
        format!("{:.2} GB", b / GB)
    } else {
        format!("{:.2} TB", b / TB)
    }
}

fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    if max_chars == 1 {
        return text.chars().take(1).collect();
    }
    let mut out: String = text.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_info() -> DashboardInfo {
        DashboardInfo {
            primary_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            socks_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)),
            mode: DesyncMode::Combo,
            enable_doh: true,
            system_proxy: true,
        }
    }

    fn sample_state(color: bool) -> DashboardState {
        let logs = new_log_ring();
        push_log_entry(
            &logs,
            LogEntry {
                timestamp: "12:00:01".to_string(),
                level: Level::INFO,
                message: "vdpi proxy listening primary=127.0.0.1:8080".to_string(),
            },
        );
        push_log_entry(
            &logs,
            LogEntry {
                timestamp: "12:00:02".to_string(),
                level: Level::WARN,
                message: "primary port rotated to 127.0.0.1:8080".to_string(),
            },
        );

        let now = Instant::now();
        let mut state = DashboardState::new(sample_info(), logs, color, now);
        state.telemetry = EngineTelemetrySnapshot {
            active_connections: 4,
            total_connections: 42,
            bytes_tx: 2 * 1024 * 1024,
            bytes_rx: 15 * 1024 * 1024,
            tls_handshakes: 28,
            auto_heal_escalations: 2,
            learned_hosts: 7,
        };
        state.rx_rate = 128 * 1024;
        state.tx_rate = 16 * 1024;
        for v in [10_000, 45_000, 120_000, 90_000, 144_000] {
            state.throughput.push(v);
        }
        state
    }

    fn buffer_to_string(backend: &TestBackend) -> String {
        let buf = backend.buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn throughput_ring_rotates_60_samples_and_tracks_peak() {
        assert_eq!(std::mem::size_of::<ThroughputRing>(), 60 * 8);

        let mut ring = ThroughputRing::new();
        assert_eq!(ring.latest(), 0);
        assert_eq!(ring.peak(), 0);

        ring.push(500);
        ring.push(2_500);
        ring.push(1_000);
        assert_eq!(ring.latest(), 1_000);
        assert_eq!(ring.peak(), 2_500);
        assert_eq!(ring.samples()[57], 500);
        assert_eq!(ring.samples()[58], 2_500);
        assert_eq!(ring.samples()[59], 1_000);

        // Push 59 smaller values: 2_500 moves to index 0 and is still peak.
        for i in 1..=58 {
            ring.push(i * 10);
        }
        assert_eq!(ring.samples()[0], 2_500);
        assert_eq!(ring.peak(), 2_500);

        // One more push evicts 2_500 from the 60-second window.
        ring.push(777);
        assert_eq!(ring.latest(), 777);
        assert_eq!(ring.peak(), 1_000);

        // Push 1 more to evict 1_000 as well.
        ring.push(300);
        assert_eq!(ring.peak(), 777);
    }

    #[test]
    fn log_ring_evicts_oldest_entries_at_150_cap() {
        let ring = new_log_ring();
        for i in 0..200usize {
            push_log_entry(
                &ring,
                LogEntry {
                    timestamp: "00:00:00".to_string(),
                    level: Level::INFO,
                    message: format!("event-{i}"),
                },
            );
        }

        let guard = ring.lock().unwrap();
        assert_eq!(guard.len(), MAX_LOG_ENTRIES);
        assert_eq!(guard.front().unwrap().message, "event-50");
        assert_eq!(guard.back().unwrap().message, "event-199");
    }

    #[test]
    fn renders_dashboard_at_100x30_wide_layout() {
        let mut state = sample_state(true);
        state.set_notice("Cache cleared", Instant::now());

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains('╭'));
        assert!(screen.contains(&format!("vdpi v{}", env!("CARGO_PKG_VERSION"))));
        assert!(screen.contains("127.0.0.1:8080"));
        assert!(screen.contains("127.0.0.1:1080"));
        assert!(screen.contains("Combo · DoH"));
        assert!(screen.contains("Uptime"));
        assert!(screen.contains("Traffic & Engine"));
        assert!(screen.contains("Throughput · 60s"));
        assert!(screen.contains("Download"));
        assert!(screen.contains("Upload"));
        assert!(screen.contains("Connections"));
        assert!(screen.contains("4 / 42"));
        assert!(screen.contains("TLS Handshakes"));
        assert!(screen.contains("Auto-Heal"));
        assert!(screen.contains("Cached Hosts"));
        assert!(screen.contains("Active"));
        assert!(screen.contains("Activity Log"));
        assert!(screen.contains("vdpi proxy listening"));
        assert!(screen.contains("d diagnostics"));
        assert!(screen.contains("c clear cache"));
        assert!(screen.contains("q quit"));
        assert!(screen.contains("Cache cleared"));

        // Verify side-by-side panels share the same top border line.
        let same_row = screen
            .lines()
            .any(|line| line.contains("Traffic & Engine") && line.contains("Throughput · 60s"));
        assert!(same_row, "expected side-by-side middle panels at 100x30");
    }

    #[test]
    fn renders_dashboard_at_60x22_narrow_stacked_layout() {
        let mut state = sample_state(true);
        let backend = TestBackend::new(60, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("Traffic & Engine"));
        assert!(screen.contains("Throughput · 60s"));
        assert!(screen.contains("Activity Log"));
        assert!(screen.contains("q quit"));

        let traffic_row = screen
            .lines()
            .position(|line| line.contains("Traffic & Engine"))
            .unwrap();
        let spark_row = screen
            .lines()
            .position(|line| line.contains("Throughput · 60s"))
            .unwrap();
        assert!(
            spark_row > traffic_row,
            "expected stacked middle panels when width < 72"
        );
    }

    #[test]
    fn renders_no_color_monochrome_with_plain_borders() {
        let mut state = sample_state(false);
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains('┌'));
        assert!(screen.contains('└'));
        assert!(screen.contains('●'));
        assert!(!screen.contains('╭'));
        assert!(!screen.contains('╰'));

        let buf = terminal.backend().buffer();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let cell = &buf[(x, y)];
                assert_eq!(cell.fg, Color::Reset, "unexpected fg color at ({x},{y})");
                assert_eq!(cell.bg, Color::Reset, "unexpected bg color at ({x},{y})");
            }
        }
    }

    #[test]
    fn narrow_footer_tiers_keep_quit_visible_with_notice_and_polish_invariants() {
        // 60x22 with "Cache cleared" leaves 46 cols for legend -> compact tier.
        let mut state = sample_state(true);
        state.set_notice("Cache cleared", Instant::now());
        let backend = TestBackend::new(60, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("d diag · c cache · ↑↓ scroll · q quit"));
        assert!(screen.contains("Cache cleared"));

        // 42x22 with "Cache cleared" leaves 28 cols for legend -> minimal tier.
        let backend = TestBackend::new(42, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("d · c · ↑↓ · q quit"));
        assert!(screen.contains("Cache cleared"));

        // Compact status bar tier uses "SOCKS " label and split vdpi bold / version muted.
        let mut compact_state = sample_state(true);
        let backend = TestBackend::new(84, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut compact_state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("SOCKS 127.0.0.1:1080"));
        assert!(!screen.contains("UDP 127.0.0.1:1080"));
        let buf = terminal.backend().buffer();
        let status_row = 1u16;
        let vdpi_x = (0..buf.area.width.saturating_sub(1))
            .find(|&x| {
                buf[(x, status_row)].symbol() == "v" && buf[(x + 1, status_row)].symbol() == "d"
            })
            .expect("vdpi brand cell");
        assert_eq!(buf[(vdpi_x, status_row)].fg, TEXT_WHITE);
        assert!(buf[(vdpi_x, status_row)].modifier.contains(Modifier::BOLD));
        let ver_x = vdpi_x + 5;
        assert_eq!(buf[(ver_x, status_row)].symbol(), "v");
        assert_eq!(buf[(ver_x, status_row)].fg, STEEL_MUTED);
        assert!(!buf[(ver_x, status_row)].modifier.contains(Modifier::BOLD));

        // Mode formatting and ellipsis truncation match launcher/tui.rs.
        assert_eq!(format_desync_mode(DesyncMode::TlsRecord), "TLS Record");
        assert_eq!(truncate_chars("hello world", 6), "hello…");
        assert_eq!(truncate_chars("hello", 2), "h…");
        assert_eq!(truncate_chars("hello", 1), "h");
        assert_eq!(truncate_chars("hello", 0), "");
    }

    #[test]
    fn renders_diagnostics_modal_overlay() {
        let mut state = sample_state(true);
        state.diagnostics_open = true;
        {
            let mut diag = state.diagnostics.lock().unwrap();
            diag.run_id = 1;
            diag.rows[0].status = ProbeStatus::Pass {
                latency_ms: 19,
                detail: "1.1.1.1".to_string(),
            };
            diag.rows[1].status = ProbeStatus::Pass {
                latency_ms: 27,
                detail: "162.159.135.232".to_string(),
            };
            diag.rows[2].status = ProbeStatus::Running;
            diag.rows[3].status = ProbeStatus::Fail {
                latency_ms: 4000,
                reason: "timed out".to_string(),
            };
        }

        for (w, h) in [(100u16, 30u16), (60u16, 22u16)] {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &mut state))
                .unwrap();

            let screen = buffer_to_string(terminal.backend());
            assert!(screen.contains("Diagnostics"));
            assert!(screen.contains("r re-run"));
            assert!(screen.contains("esc close"));
            assert!(screen.contains("discord.com"));
            assert!(screen.contains("gateway.discord.gg"));
            assert!(screen.contains("www.roblox.com"));
            assert!(screen.contains("PASS"));
            assert!(screen.contains("FAIL"));
            assert!(screen.contains("Running..."));
            assert!(screen.contains("19 ms"));
        }
    }

    #[test]
    fn key_events_drive_modal_scroll_cache_and_quit() {
        let mut state = sample_state(true);
        for i in 0..30 {
            push_log_entry(
                &state.logs,
                LogEntry {
                    timestamp: "12:00:10".to_string(),
                    level: Level::INFO,
                    message: format!("line-{i}"),
                },
            );
        }
        state.log_viewport_rows = 5;

        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Release events are ignored.
        assert_eq!(
            handle_key_event(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('q'),
                    KeyModifiers::NONE,
                    KeyEventKind::Release
                ),
            ),
            KeyAction::None
        );

        // Open diagnostics modal -> Esc closes it without quitting; r re-runs; d closes it.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('d'))),
            KeyAction::RunDiagnostics
        );
        assert!(state.diagnostics_open);
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::RunDiagnostics
        );
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Esc)),
            KeyAction::Redraw
        );
        assert!(!state.diagnostics_open);

        // Scroll up pauses follow, End resumes follow.
        assert!(state.follow_logs);
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Up)),
            KeyAction::Redraw
        );
        assert!(!state.follow_logs);
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::End)),
            KeyAction::Redraw
        );
        assert!(state.follow_logs);

        // Cache clear & quit.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('c'))),
            KeyAction::ClearCache
        );
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Esc)),
            KeyAction::Quit
        );
        assert_eq!(
            handle_key_event(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            ),
            KeyAction::Quit
        );
    }

    #[test]
    fn stats_panel_shows_disabled_when_system_proxy_off() {
        let mut state = sample_state(true);
        state.info.system_proxy = false;

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("Disabled"));
        assert!(!screen.contains("--no-proxy"));
    }

    #[test]
    fn tui_log_layer_records_events_with_passthrough_flag() {
        use tracing_subscriber::layer::SubscriberExt;

        let logs = new_log_ring();
        let passthrough = Arc::new(AtomicBool::new(false));
        let subscriber = tracing_subscriber::registry().with(TuiLogLayer::new(
            Arc::clone(&logs),
            Arc::clone(&passthrough),
        ));

        tracing::subscriber::with_default(subscriber, || {
            info!("buffered only");
            passthrough.store(true, Ordering::Relaxed);
            tracing::warn!("fallback warning");
        });

        let guard = logs.lock().unwrap();
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[0].level, Level::INFO);
        assert_eq!(guard[0].message, "buffered only");
        assert_eq!(guard[1].level, Level::WARN);
        assert_eq!(guard[1].message, "fallback warning");
    }

    #[tokio::test]
    async fn diagnostics_join_set_aborts_on_rerun_and_modal_close() {
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }

        let mut state = sample_state(true);
        state.diagnostics_open = true;

        let aborted_rerun = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let flag = Arc::clone(&aborted_rerun);
        state.diag_tasks.spawn(async move {
            let _guard = DropFlag(flag);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let _ = state.begin_diagnostics_run();
        while state.diag_tasks.join_next().await.is_some() {}
        assert!(aborted_rerun.load(Ordering::Relaxed));

        let aborted_close = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let flag = Arc::clone(&aborted_close);
        state.diag_tasks.spawn(async move {
            let _guard = DropFlag(flag);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        assert_eq!(
            handle_key_event(&mut state, KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            KeyAction::Redraw
        );
        assert!(!state.diagnostics_open);
        while state.diag_tasks.join_next().await.is_some() {}
        assert!(aborted_close.load(Ordering::Relaxed));
    }
}
