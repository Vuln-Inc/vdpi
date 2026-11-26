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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tracing::field::{Field, Visit};
use tracing::{info, Level};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;
use vdpi::config::{DesyncMode, RuntimeConfig};
use vdpi::desync::{EngineContext, EngineTelemetrySnapshot};

pub const MAX_LOG_ENTRIES: usize = 150;
pub const MAX_LOG_MESSAGE_CHARS: usize = 512;
pub const THROUGHPUT_WINDOW_SECS: usize = 60;
const TICK_INTERVAL: Duration = Duration::from_millis(250);
const ATTACHED_POLL_INTERVAL: Duration = Duration::from_millis(500);
const NOTICE_TTL: Duration = Duration::from_secs(3);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const SIDE_BY_SIDE_MIN_WIDTH: u16 = 72;
const PROXY_CONNECT_MAX_HEADER_BYTES: usize = 2048;
const AUTO_HEAL_LOG_COOLDOWN: Duration = Duration::from_secs(5);
const LEARNED_HOSTS_LOG_COOLDOWN: Duration = Duration::from_secs(15);

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

pub fn push_log_entry(ring: &SharedLogRing, mut entry: LogEntry) {
    if entry.message.len() > MAX_LOG_MESSAGE_CHARS
        && entry.message.chars().count() > MAX_LOG_MESSAGE_CHARS
    {
        entry.message = truncate_chars(&entry.message, MAX_LOG_MESSAGE_CHARS);
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardEngine {
    Proxy {
        primary_addr: SocketAddr,
        socks_addr: Option<SocketAddr>,
        system_proxy: bool,
    },
    Tun {
        interface: String,
        physical_nic: Option<String>,
        vpn_conflict: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct DashboardInfo {
    pub engine: DashboardEngine,
    pub mode: DesyncMode,
    pub enable_doh: bool,
}

/// Live telemetry snapshot returned by a remote-attach probe callback for
/// [`run_attached_dashboard`]. Decoupled from `service.rs` so the dashboard
/// module compiles independently of health-client types.
#[derive(Debug, Clone)]
pub struct AttachedTelemetry {
    pub snap: EngineTelemetrySnapshot,
    pub engine: DashboardEngine,
    pub mode: DesyncMode,
    pub doh: bool,
    pub block_quic: bool,
    pub rss_kb: Option<u64>,
    pub isp_stage: Option<String>,
    pub version: Option<String>,
}

/// Live TUN metadata snapshot polled alongside engine telemetry so interface transitions,
/// uplink switches, and VPN conflicts refresh in real time.
#[derive(Debug, Clone, Default)]
pub struct TunLiveMeta {
    pub interface: Option<String>,
    pub physical_nic: Option<String>,
    pub vpn_conflict: Option<String>,
}

/// Optional live probe returning [`TunLiveMeta`] for TUN mode.
pub type TunMetaProbe = Arc<dyn Fn() -> TunLiveMeta + Send + Sync>;

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
    rate_initialized: bool,
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
    is_attached: bool,
    reconnecting: bool,
    rss_kb: Option<u64>,
    isp_stage: Option<String>,
    remote_version: Option<String>,
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
            rate_initialized: false,
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
            is_attached: false,
            reconnecting: false,
            rss_kb: None,
            isp_stage: None,
            remote_version: None,
        }
    }

    fn new_attached(
        info: DashboardInfo,
        initial_snap: EngineTelemetrySnapshot,
        initial_rss_kb: Option<u64>,
        initial_isp_stage: Option<String>,
        logs: SharedLogRing,
        color: bool,
        now: Instant,
    ) -> Self {
        let mut state = Self::new(info, logs, color, now);
        state.is_attached = true;
        state.rss_kb = initial_rss_kb;
        state.isp_stage = normalize_opt_string(initial_isp_stage);
        state.update_telemetry(initial_snap, now);
        state
    }

    fn update_telemetry(&mut self, snap: EngineTelemetrySnapshot, now: Instant) {
        self.telemetry = snap;
        if !self.rate_initialized {
            self.prev_rx = snap.bytes_rx;
            self.prev_tx = snap.bytes_tx;
            self.rx_rate = 0;
            self.tx_rate = 0;
            self.last_rate_sample = now;
            self.rate_initialized = true;
        } else if snap.bytes_rx < self.prev_rx || snap.bytes_tx < self.prev_tx {
            // Daemon restarted and byte counters reset to a lower value:
            // re-baseline cleanly without stalling or underflowing.
            if now.saturating_duration_since(self.last_rate_sample) >= Duration::from_secs(1) {
                self.throughput.push(0);
            }
            self.prev_rx = snap.bytes_rx;
            self.prev_tx = snap.bytes_tx;
            self.rx_rate = 0;
            self.tx_rate = 0;
            self.last_rate_sample = now;
        } else {
            let elapsed = now.saturating_duration_since(self.last_rate_sample);
            if elapsed >= Duration::from_secs(1) {
                let elapsed_ms = u128::from(elapsed.as_millis().max(1) as u64);
                let drx = u128::from(snap.bytes_rx.saturating_sub(self.prev_rx));
                let dtx = u128::from(snap.bytes_tx.saturating_sub(self.prev_tx));
                self.rx_rate = ((drx * 1000) / elapsed_ms).min(u128::from(u64::MAX)) as u64;
                self.tx_rate = ((dtx * 1000) / elapsed_ms).min(u128::from(u64::MAX)) as u64;
                self.throughput
                    .push(self.rx_rate.saturating_add(self.tx_rate));
                self.prev_rx = snap.bytes_rx;
                self.prev_tx = snap.bytes_tx;
                self.last_rate_sample = now;
            }
        }
        self.expire_notice(now);
    }

    fn apply_attached_sample(&mut self, sample: AttachedTelemetry, now: Instant) {
        let was_reconnecting = self.reconnecting;
        self.reconnecting = false;
        if was_reconnecting {
            // Re-baseline after an offline window so accumulated traffic during
            // disconnect never shows up as a fake catch-up spike.
            self.rate_initialized = false;
        }
        self.update_telemetry(sample.snap, now);
        self.info.engine = sample.engine;
        self.info.mode = sample.mode;
        self.info.enable_doh = sample.doh;
        self.rss_kb = sample.rss_kb;
        self.isp_stage = normalize_opt_string(sample.isp_stage);
        self.remote_version = normalize_opt_string(sample.version).and_then(|v| {
            let trimmed = v.trim_start_matches('v').trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
    }

    fn mark_reconnecting(&mut self, now: Instant) {
        self.reconnecting = true;
        self.tick_reconnecting(now);
    }

    fn tick_reconnecting(&mut self, now: Instant) {
        if self.reconnecting
            && now.saturating_duration_since(self.last_rate_sample) >= Duration::from_secs(1)
        {
            self.rx_rate = 0;
            self.tx_rate = 0;
            self.throughput.push(0);
            self.last_rate_sample = now;
        }
        self.expire_notice(now);
    }

    fn expire_notice(&mut self, now: Instant) {
        if self.notice.as_ref().is_some_and(|(_, exp)| now >= *exp) {
            self.notice = None;
        }
    }

    fn refresh_tun_meta(&mut self, meta: TunLiveMeta) {
        if let DashboardEngine::Tun {
            interface: ref mut iface_slot,
            physical_nic: ref mut nic_slot,
            vpn_conflict: ref mut vpn_slot,
        } = self.info.engine
        {
            if let Some(iface) = meta.interface {
                *iface_slot = iface;
            }
            *nic_slot = meta.physical_nic;
            *vpn_slot = meta.vpn_conflict;
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
    Refresh,
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
        KeyCode::Char('r' | 'R') if state.is_attached => KeyAction::Refresh,
        KeyCode::Char('c' | 'C') if !state.is_attached => KeyAction::ClearCache,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => KeyAction::Quit,
        _ => KeyAction::None,
    }
}

static TUI_PANIC_HOOK_ONCE: Once = Once::new();
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Installs a process-wide panic hook wrapper once that restores raw mode and
/// leaves the alternate screen before invoking the previous hook, so panic
/// messages are never erased by unwinding `Drop` guards.
pub(crate) fn install_tui_panic_hook() {
    TUI_PANIC_HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            prev(info);
        }));
    });
}

pub(crate) fn mark_tui_active(active: bool) {
    TUI_ACTIVE.store(active, Ordering::Release);
}

pub(crate) fn take_tui_active() -> bool {
    TUI_ACTIVE.swap(false, Ordering::AcqRel)
}

/// RAII guard that enters raw mode + alternate screen and guarantees clean terminal
/// restoration on normal exit, error return, or panic unwind.
struct DashboardGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl DashboardGuard {
    fn enter() -> io::Result<Self> {
        install_tui_panic_hook();
        terminal::enable_raw_mode()?;
        mark_tui_active(true);
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            if take_tui_active() {
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(mut terminal) => {
                let _ = terminal.clear();
                Ok(Self { terminal })
            }
            Err(err) => {
                if take_tui_active() {
                    let mut out = io::stdout();
                    let _ = execute!(out, LeaveAlternateScreen, Show);
                    let _ = terminal::disable_raw_mode();
                }
                Err(err)
            }
        }
    }
}

impl Drop for DashboardGuard {
    fn drop(&mut self) {
        if take_tui_active() {
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
            let _ = terminal::disable_raw_mode();
        }
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

struct TaskAbortGuard<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T> TaskAbortGuard<T> {
    fn new(handle: JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }
}

impl<T> Drop for TaskAbortGuard<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

fn normalize_opt_string(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = sanitize_single_line(&s);
        (!trimmed.is_empty()).then_some(trimmed)
    })
}

fn normalize_loopback_connect_addr(addr: SocketAddr) -> SocketAddr {
    let ip = addr.ip().to_canonical();
    let connect_ip = if ip.is_unspecified() {
        match ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    } else {
        ip
    };
    SocketAddr::new(connect_ip, addr.port())
}

fn format_engine_summary(engine: &DashboardEngine) -> String {
    match engine {
        DashboardEngine::Proxy {
            primary_addr,
            socks_addr,
            system_proxy,
        } => {
            let mut out = format!("proxy {primary_addr}");
            if let Some(sa) = socks_addr {
                out.push_str(&format!(" · socks {sa}"));
            }
            if !*system_proxy {
                out.push_str(" · manual proxy");
            }
            out
        }
        DashboardEngine::Tun {
            interface,
            physical_nic,
            ..
        } => match physical_nic
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(nic) => format!("TUN {interface} ({nic})"),
            None => format!("TUN {interface}"),
        },
    }
}

fn next_traffic_milestone_after(total_bytes: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;
    const STEPS: [u64; 6] = [10 * MB, 50 * MB, 100 * MB, 250 * MB, 500 * MB, GB];
    for step in STEPS {
        if total_bytes < step {
            return step;
        }
    }
    (total_bytes / GB).saturating_add(1).saturating_mul(GB)
}

struct AttachedActivityTracker {
    logs: SharedLogRing,
    last_block_quic: Option<bool>,
    last_auto_heal: u64,
    last_auto_heal_log: Option<Instant>,
    last_learned_hosts: usize,
    last_learned_hosts_log: Option<Instant>,
    next_traffic_milestone: u64,
}

impl AttachedActivityTracker {
    fn new(
        logs: SharedLogRing,
        initial_info: &DashboardInfo,
        initial_snap: EngineTelemetrySnapshot,
        initial_isp_stage: Option<&str>,
    ) -> Self {
        let total_bytes = initial_snap.bytes_rx.saturating_add(initial_snap.bytes_tx);
        let tracker = Self {
            logs,
            last_block_quic: None,
            last_auto_heal: initial_snap.auto_heal_escalations,
            last_auto_heal_log: None,
            last_learned_hosts: initial_snap.learned_hosts,
            last_learned_hosts_log: None,
            next_traffic_milestone: next_traffic_milestone_after(total_bytes),
        };

        let engine_summary = format_engine_summary(&initial_info.engine);
        let mode = format_desync_mode(initial_info.mode);
        let dns = if initial_info.enable_doh {
            "DoH"
        } else {
            "UDP"
        };
        let mut startup =
            format!("attached to live vdpi daemon · {engine_summary} · {mode} · {dns}");
        if let Some(stage) = initial_isp_stage.map(str::trim).filter(|s| !s.is_empty()) {
            startup.push_str(&format!(" · stage {stage}"));
        }
        tracker.push(Level::INFO, startup);

        if let DashboardEngine::Tun {
            vpn_conflict: Some(vpn),
            ..
        } = &initial_info.engine
        {
            let vpn = sanitize_single_line(vpn);
            if !vpn.is_empty() {
                tracker.push(Level::WARN, format!("VPN conflict active: {vpn}"));
            }
        }

        tracker
    }

    fn push(&self, level: Level, message: impl Into<String>) {
        push_log_entry(
            &self.logs,
            LogEntry {
                timestamp: format_wall_clock(SystemTime::now()),
                level,
                message: sanitize_single_line(&message.into()),
            },
        );
    }

    fn on_offline(&self, prev: &DashboardState) {
        if !prev.reconnecting {
            self.push(Level::WARN, "daemon unreachable; waiting to reconnect...");
        }
    }

    fn on_sample(&mut self, prev: &DashboardState, sample: &AttachedTelemetry, now: Instant) {
        let counters_reset = prev.rate_initialized
            && (sample.snap.bytes_rx < prev.prev_rx || sample.snap.bytes_tx < prev.prev_tx);
        let new_summary = format_engine_summary(&sample.engine);

        if prev.reconnecting {
            if counters_reset {
                self.push(
                    Level::INFO,
                    format!("reconnected to live vdpi daemon (restarted · {new_summary})"),
                );
            } else {
                self.push(
                    Level::INFO,
                    format!("reconnected to live vdpi daemon ({new_summary})"),
                );
            }
        } else if counters_reset {
            self.push(
                Level::WARN,
                "daemon telemetry counters reset (service restarted)",
            );
        }

        if counters_reset {
            self.last_auto_heal = sample.snap.auto_heal_escalations;
            self.last_auto_heal_log = None;
            self.last_learned_hosts = sample.snap.learned_hosts;
            self.last_learned_hosts_log = None;
            let total_bytes = sample.snap.bytes_rx.saturating_add(sample.snap.bytes_tx);
            self.next_traffic_milestone = next_traffic_milestone_after(total_bytes);
        }

        match (&prev.info.engine, &sample.engine) {
            (
                DashboardEngine::Tun {
                    interface: old_iface,
                    physical_nic: old_nic,
                    vpn_conflict: old_vpn,
                },
                DashboardEngine::Tun {
                    interface: new_iface,
                    physical_nic: new_nic,
                    vpn_conflict: new_vpn,
                },
            ) => {
                if old_iface != new_iface {
                    self.push(
                        Level::INFO,
                        format!("TUN interface changed: {old_iface} -> {new_iface}"),
                    );
                }
                let old_nic_norm = normalize_opt_string(old_nic.clone());
                let new_nic_norm = normalize_opt_string(new_nic.clone());
                if old_nic_norm != new_nic_norm {
                    self.push(
                        Level::INFO,
                        format!(
                            "TUN uplink changed: {} -> {}",
                            old_nic_norm.as_deref().unwrap_or("none"),
                            new_nic_norm.as_deref().unwrap_or("none")
                        ),
                    );
                }
                let old_vpn_norm = normalize_opt_string(old_vpn.clone());
                let new_vpn_norm = normalize_opt_string(new_vpn.clone());
                if old_vpn_norm != new_vpn_norm {
                    match (old_vpn_norm, new_vpn_norm) {
                        (None, Some(v)) => {
                            self.push(Level::WARN, format!("VPN conflict detected: {v}"));
                        }
                        (Some(old), None) => {
                            self.push(Level::INFO, format!("VPN conflict cleared (was {old})"));
                        }
                        (Some(old), Some(new)) => {
                            self.push(Level::WARN, format!("VPN conflict changed: {old} -> {new}"));
                        }
                        (None, None) => {}
                    }
                }
            }
            (
                DashboardEngine::Proxy {
                    primary_addr: old_p,
                    socks_addr: old_s,
                    system_proxy: old_sys,
                },
                DashboardEngine::Proxy {
                    primary_addr: new_p,
                    socks_addr: new_s,
                    system_proxy: new_sys,
                },
            ) => {
                if old_p != new_p || old_s != new_s || old_sys != new_sys {
                    self.push(
                        Level::INFO,
                        format!("proxy configuration updated: {new_summary}"),
                    );
                }
            }
            _ => {
                self.push(Level::INFO, format!("engine switched to {new_summary}"));
                if let DashboardEngine::Tun {
                    vpn_conflict: Some(vpn),
                    ..
                } = &sample.engine
                {
                    let vpn = sanitize_single_line(vpn);
                    if !vpn.is_empty() {
                        self.push(Level::WARN, format!("VPN conflict active: {vpn}"));
                    }
                }
            }
        }

        if prev.info.mode != sample.mode {
            self.push(
                Level::INFO,
                format!(
                    "desync mode changed: {} -> {}",
                    format_desync_mode(prev.info.mode),
                    format_desync_mode(sample.mode)
                ),
            );
        }

        if prev.info.enable_doh != sample.doh {
            let old_dns = if prev.info.enable_doh { "DoH" } else { "UDP" };
            let new_dns = if sample.doh { "DoH" } else { "UDP" };
            self.push(
                Level::INFO,
                format!("DNS transport changed: {old_dns} -> {new_dns}"),
            );
        }

        if let Some(prev_quic) = self.last_block_quic {
            if prev_quic != sample.block_quic {
                let state_str = if sample.block_quic {
                    "enabled"
                } else {
                    "disabled"
                };
                self.push(Level::INFO, format!("QUIC blocking {state_str}"));
            }
        }
        self.last_block_quic = Some(sample.block_quic);

        let new_stage = normalize_opt_string(sample.isp_stage.clone());
        if prev.isp_stage != new_stage {
            match (&prev.isp_stage, &new_stage) {
                (Some(old), Some(new)) => {
                    self.push(Level::INFO, format!("ISP stage changed: {old} -> {new}"));
                }
                (None, Some(new)) => {
                    self.push(Level::INFO, format!("ISP stage active: {new}"));
                }
                (Some(old), None) => {
                    self.push(Level::INFO, format!("ISP stage cleared (was {old})"));
                }
                (None, None) => {}
            }
        }

        if !counters_reset {
            if sample.snap.auto_heal_escalations > self.last_auto_heal
                && self
                    .last_auto_heal_log
                    .is_none_or(|t| now.saturating_duration_since(t) >= AUTO_HEAL_LOG_COOLDOWN)
            {
                let delta = sample.snap.auto_heal_escalations - self.last_auto_heal;
                self.push(
                    Level::WARN,
                    format!(
                        "auto-heal escalated (+{delta}, total {})",
                        sample.snap.auto_heal_escalations
                    ),
                );
                self.last_auto_heal = sample.snap.auto_heal_escalations;
                self.last_auto_heal_log = Some(now);
            }

            if sample.snap.learned_hosts > self.last_learned_hosts {
                let delta = sample.snap.learned_hosts - self.last_learned_hosts;
                if delta >= 5
                    || self.last_learned_hosts_log.is_none_or(|t| {
                        now.saturating_duration_since(t) >= LEARNED_HOSTS_LOG_COOLDOWN
                    })
                {
                    self.push(
                        Level::INFO,
                        format!(
                            "adaptive strategy cache grew (+{delta}, total {} hosts)",
                            sample.snap.learned_hosts
                        ),
                    );
                    self.last_learned_hosts = sample.snap.learned_hosts;
                    self.last_learned_hosts_log = Some(now);
                }
            }

            let total_bytes = sample.snap.bytes_rx.saturating_add(sample.snap.bytes_tx);
            if total_bytes >= self.next_traffic_milestone {
                self.push(
                    Level::INFO,
                    format!(
                        "traffic milestone: {} total ({} down / {} up, {} connections)",
                        format_bytes(total_bytes),
                        format_bytes(sample.snap.bytes_rx),
                        format_bytes(sample.snap.bytes_tx),
                        sample.snap.total_connections
                    ),
                );
                self.next_traffic_milestone = next_traffic_milestone_after(total_bytes);
            }
        }
    }
}

async fn probe_via_http_connect(proxy_addr: SocketAddr, host: &str) -> ProbeStatus {
    let started = Instant::now();
    let connect_addr = normalize_loopback_connect_addr(proxy_addr);
    let result = tokio::time::timeout(PROBE_TIMEOUT, async {
        let mut stream = TcpStream::connect(connect_addr).await?;
        let req = format!(
            "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        let mut buf = Vec::with_capacity(256);
        let mut chunk = [0u8; 256];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            let remaining = PROXY_CONNECT_MAX_HEADER_BYTES.saturating_sub(buf.len());
            let take = n.min(remaining);
            buf.extend_from_slice(&chunk[..take]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n")
                || buf.len() >= PROXY_CONNECT_MAX_HEADER_BYTES
            {
                break;
            }
        }
        let header = String::from_utf8_lossy(&buf);
        let status_line = header
            .lines()
            .next()
            .map(sanitize_single_line)
            .unwrap_or_default();
        Ok::<String, io::Error>(status_line)
    })
    .await;

    let latency_ms = started.elapsed().as_millis();
    match result {
        Ok(Ok(status_line)) => {
            let code = status_line.split_whitespace().nth(1);
            if status_line.starts_with("HTTP/1.") && code == Some("200") {
                ProbeStatus::Pass {
                    latency_ms,
                    detail: "CONNECT 200".to_string(),
                }
            } else if status_line.is_empty() {
                ProbeStatus::Fail {
                    latency_ms,
                    reason: "empty proxy response".to_string(),
                }
            } else {
                ProbeStatus::Fail {
                    latency_ms,
                    reason: status_line,
                }
            }
        }
        Ok(Err(err)) => ProbeStatus::Fail {
            latency_ms,
            reason: sanitize_single_line(&err.to_string()),
        },
        Err(_) => ProbeStatus::Fail {
            latency_ms,
            reason: "timed out".to_string(),
        },
    }
}

async fn probe_via_tun_direct(
    client: Option<Arc<reqwest::Client>>,
    enable_doh: bool,
    idx: usize,
    host: &'static str,
) -> ProbeStatus {
    let started = Instant::now();
    if idx == 0 && !enable_doh {
        let result =
            tokio::time::timeout(PROBE_TIMEOUT, tokio::net::lookup_host((host, 443))).await;
        let latency_ms = started.elapsed().as_millis();
        return match result {
            Ok(Ok(mut addrs)) => {
                let detail = addrs
                    .next()
                    .map(|sa| sa.ip().to_string())
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
    }

    let Some(client) = client else {
        return ProbeStatus::Fail {
            latency_ms: started.elapsed().as_millis(),
            reason: "HTTP client unavailable".to_string(),
        };
    };

    let result = tokio::time::timeout(PROBE_TIMEOUT, async move {
        if idx == 0 {
            let resp = client
                .get("https://1.1.1.1/dns-query?name=one.one.one.one&type=A")
                .header(reqwest::header::ACCEPT, "application/dns-json")
                .send()
                .await
                .map_err(|e| sanitize_single_line(&e.to_string()))?;
            let status = resp.status();
            if status.is_success() {
                Ok::<String, String>(format!("DoH HTTP {}", status.as_u16()))
            } else {
                Err(format!("DoH HTTP {}", status.as_u16()))
            }
        } else {
            let url = format!("https://{host}/");
            let resp = client
                .head(&url)
                .send()
                .await
                .map_err(|e| sanitize_single_line(&e.to_string()))?;
            Ok(format!("TLS HTTP {}", resp.status().as_u16()))
        }
    })
    .await;

    let latency_ms = started.elapsed().as_millis();
    match result {
        Ok(Ok(detail)) => ProbeStatus::Pass { latency_ms, detail },
        Ok(Err(reason)) => ProbeStatus::Fail {
            latency_ms,
            reason: sanitize_single_line(&reason),
        },
        Err(_) => ProbeStatus::Fail {
            latency_ms,
            reason: "timed out".to_string(),
        },
    }
}

fn spawn_attached_diagnostics_probes(
    tasks: &mut JoinSet<()>,
    engine: &DashboardEngine,
    enable_doh: bool,
    diag_state: &Arc<Mutex<DiagnosticsState>>,
    run_id: u64,
    targets: [(usize, &'static str); 4],
) {
    match engine {
        DashboardEngine::Proxy { primary_addr, .. } => {
            let proxy_addr = *primary_addr;
            for (idx, host) in targets {
                let diag = Arc::clone(diag_state);
                tasks.spawn(async move {
                    let status = probe_via_http_connect(proxy_addr, host).await;
                    let mut guard = diag.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.run_id == run_id {
                        guard.rows[idx].status = status;
                    }
                });
            }
        }
        DashboardEngine::Tun { .. } => {
            let shared_client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(PROBE_TIMEOUT)
                .build()
                .ok()
                .map(Arc::new);
            for (idx, host) in targets {
                let diag = Arc::clone(diag_state);
                let client = shared_client.clone();
                tasks.spawn(async move {
                    let status = probe_via_tun_direct(client, enable_doh, idx, host).await;
                    let mut guard = diag.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.run_id == run_id {
                        guard.rows[idx].status = status;
                    }
                });
            }
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
    run_dashboard_with_tun_meta(info, ctx, logs, shutdown_tx, external_shutdown, None).await
}

/// Variant of [`run_dashboard`] that also polls an optional [`TunMetaProbe`] on each tick
/// to keep TUN physical NIC and VPN conflict badges updated live.
pub async fn run_dashboard_with_tun_meta<F>(
    info: DashboardInfo,
    ctx: EngineContext,
    logs: SharedLogRing,
    shutdown_tx: watch::Sender<bool>,
    external_shutdown: F,
    tun_meta_probe: Option<TunMetaProbe>,
) -> Result<()>
where
    F: Future<Output = ()>,
{
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut guard = DashboardGuard::enter()?;

    let now = Instant::now();
    let mut state = DashboardState::new(info, logs, color, now);
    state.update_telemetry(ctx.telemetry_snapshot(), now);
    state.rss_kb = vdpi::health::read_self_rss_kb();
    state.isp_stage = Some(ctx.preferred_stage().label().to_string());
    let mut last_rss_sample = now;
    if let Some(ref probe) = tun_meta_probe {
        state.refresh_tun_meta(probe());
    }

    let mut reader_guard = EventReaderGuard::spawn();

    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tokio::pin!(external_shutdown);

    let loop_result: io::Result<()> = loop {
        while state.diag_tasks.try_join_next().is_some() {}
        let now = Instant::now();
        state.update_telemetry(ctx.telemetry_snapshot(), now);
        state.isp_stage = Some(ctx.preferred_stage().label().to_string());
        if now.saturating_duration_since(last_rss_sample) >= Duration::from_secs(1) {
            state.rss_kb = vdpi::health::read_self_rss_kb();
            last_rss_sample = now;
        }
        if let Some(ref probe) = tun_meta_probe {
            state.refresh_tun_meta(probe());
        }
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
                            KeyAction::Refresh | KeyAction::Redraw | KeyAction::None => {}
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

/// Runs the remote-attach live dashboard connected to an already-running background
/// `vdpi` service. Polls `probe_fn` on a background `spawn_blocking` timer every
/// 500 ms (or immediately on `[r]`) so keyboard input never stutters, synthesizes
/// non-spammy activity log entries for state transitions, and detaches cleanly on
/// `q`, `Esc`, `Ctrl-C`, or `external_shutdown` without stopping the daemon.
pub async fn run_attached_dashboard<P, F>(
    initial_info: DashboardInfo,
    initial_snap: EngineTelemetrySnapshot,
    initial_rss_kb: Option<u64>,
    initial_isp_stage: Option<String>,
    probe_fn: P,
    external_shutdown: F,
) -> Result<()>
where
    P: Fn() -> Option<AttachedTelemetry> + Send + Sync + 'static,
    F: Future<Output = ()>,
{
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let mut guard = DashboardGuard::enter()?;

    let now = Instant::now();
    let logs = new_log_ring();
    let mut tracker = AttachedActivityTracker::new(
        Arc::clone(&logs),
        &initial_info,
        initial_snap,
        initial_isp_stage.as_deref(),
    );
    let mut state = DashboardState::new_attached(
        initial_info,
        initial_snap,
        initial_rss_kb,
        initial_isp_stage,
        logs,
        color,
        now,
    );

    let probe_fn = Arc::new(probe_fn);
    let (refresh_tx, mut refresh_rx) = mpsc::channel::<()>(4);
    let (poll_tx, mut poll_rx) = mpsc::channel::<Option<AttachedTelemetry>>(4);
    let _poller_guard = TaskAbortGuard::new(tokio::spawn(async move {
        let mut poll_tick = tokio::time::interval(ATTACHED_POLL_INTERVAL);
        poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Consume immediate first tick; initial_snap is already rendered.
        poll_tick.tick().await;
        loop {
            tokio::select! {
                biased;
                maybe_req = refresh_rx.recv() => {
                    if maybe_req.is_none() {
                        break;
                    }
                    while refresh_rx.try_recv().is_ok() {}
                    poll_tick.reset();
                }
                _ = poll_tick.tick() => {}
            }
            let probe = Arc::clone(&probe_fn);
            let sample = tokio::task::spawn_blocking(move || probe())
                .await
                .ok()
                .flatten();
            if poll_tx.send(sample).await.is_err() {
                break;
            }
        }
    }));

    let mut reader_guard = EventReaderGuard::spawn();
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut manual_refresh_pending = false;

    tokio::pin!(external_shutdown);

    let loop_result: io::Result<()> = loop {
        while state.diag_tasks.try_join_next().is_some() {}
        let now = Instant::now();
        state.tick_reconnecting(now);

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
                            KeyAction::Refresh => {
                                manual_refresh_pending = true;
                                let _ = refresh_tx.try_send(());
                                state.set_notice("Refreshing...", Instant::now());
                            }
                            KeyAction::RunDiagnostics => {
                                let (run_id, targets) = state.begin_diagnostics_run();
                                spawn_attached_diagnostics_probes(
                                    &mut state.diag_tasks,
                                    &state.info.engine,
                                    state.info.enable_doh,
                                    &state.diagnostics,
                                    run_id,
                                    targets,
                                );
                            }
                            KeyAction::ClearCache | KeyAction::Redraw | KeyAction::None => {}
                        }
                    }
                    // Resize and other events simply trigger the next redraw iteration.
                    Some(_) => {}
                    None => break Ok(()),
                }
            }
            maybe_sample = poll_rx.recv() => {
                let sample_now = Instant::now();
                match maybe_sample {
                    Some(Some(sample)) => {
                        tracker.on_sample(&state, &sample, sample_now);
                        state.apply_attached_sample(sample, sample_now);
                        if manual_refresh_pending {
                            manual_refresh_pending = false;
                            state.set_notice("Refreshed", sample_now);
                        }
                    }
                    Some(None) => {
                        tracker.on_offline(&state);
                        state.mark_reconnecting(sample_now);
                        if manual_refresh_pending {
                            manual_refresh_pending = false;
                            state.set_notice("Daemon unreachable", sample_now);
                        }
                    }
                    None => {
                        tracker.on_offline(&state);
                        state.mark_reconnecting(sample_now);
                    }
                }
            }
            _ = tick.tick() => {}
        }
    };

    state.abort_diagnostics_tasks();
    drop(_poller_guard);
    drop(refresh_tx);
    drop(reader_guard);
    drop(guard);

    loop_result?;
    Ok(())
}

fn render_dashboard(frame: &mut Frame<'_>, state: &mut DashboardState) {
    let area = frame.area();
    if area.width < 12 || area.height < 8 {
        let quit_hint = if state.is_attached {
            "q back"
        } else {
            "q quit"
        };
        let version = state
            .remote_version
            .as_deref()
            .unwrap_or(env!("CARGO_PKG_VERSION"));
        let msg = Line::from(format!("vdpi v{version}  ({quit_hint})")).style(state.palette.title);
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

    let version = state
        .remote_version
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let mode = format_desync_mode(state.info.mode);
    let dns = if state.info.enable_doh { "DoH" } else { "UDP" };
    let uptime = format_uptime(state.started_at.elapsed());

    let w = inner.width as usize;
    let sep = Span::styled(" · ", p.dim);

    // "● vdpi v{version}" = 8 chars + version length.
    let head_len = 8 + version.chars().count();
    let dot_style = if state.is_attached && state.reconnecting {
        p.amber
    } else {
        p.emerald
    };

    let mut spans = vec![
        Span::styled("●", dot_style),
        Span::raw(" "),
        Span::styled("vdpi", p.title),
        Span::raw(" "),
        Span::styled(format!("v{version}"), p.label),
    ];

    if state.is_attached && state.reconnecting {
        const RECONNECTING: &str = "Reconnecting…";
        let reconnecting_len = RECONNECTING.chars().count();
        let engine_tag = match &state.info.engine {
            DashboardEngine::Proxy { primary_addr, .. } => primary_addr.to_string(),
            DashboardEngine::Tun { interface, .. } => format!("TUN {interface}"),
        };
        let engine_len = engine_tag.chars().count();

        let full_len =
            head_len + 3 + reconnecting_len + 3 + engine_len + 3 + "Uptime ".len() + uptime.len();
        let med_len = head_len + 3 + reconnecting_len + 3 + engine_len + 3 + uptime.len();
        let compact_len = head_len + 3 + reconnecting_len + 3 + uptime.len();
        let min_len = head_len + 3 + reconnecting_len;

        if w >= full_len {
            spans.push(sep.clone());
            spans.push(Span::styled(RECONNECTING, p.amber));
            spans.push(sep.clone());
            spans.push(Span::styled(engine_tag, p.label));
            spans.push(sep);
            spans.push(Span::styled("Uptime ", p.label));
            spans.push(Span::styled(uptime, p.text));
        } else if w >= med_len {
            spans.push(sep.clone());
            spans.push(Span::styled(RECONNECTING, p.amber));
            spans.push(sep.clone());
            spans.push(Span::styled(engine_tag, p.label));
            spans.push(sep);
            spans.push(Span::styled(uptime, p.text));
        } else if w >= compact_len {
            spans.push(sep.clone());
            spans.push(Span::styled(RECONNECTING, p.amber));
            spans.push(sep);
            spans.push(Span::styled(uptime, p.text));
        } else if w >= min_len {
            spans.push(sep);
            spans.push(Span::styled(RECONNECTING, p.amber));
        } else {
            let rem = w.saturating_sub(head_len + 3);
            if rem > 0 {
                spans.push(sep);
                spans.push(Span::styled(truncate_chars(RECONNECTING, rem), p.amber));
            }
        }

        frame.render_widget(Paragraph::new(Line::from(spans)), inner);
        return;
    }

    match &state.info.engine {
        DashboardEngine::Proxy {
            primary_addr,
            socks_addr,
            ..
        } => {
            let primary = primary_addr.to_string();
            let socks = socks_addr.map(|sa| sa.to_string());

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
        }
        DashboardEngine::Tun {
            interface,
            physical_nic,
            vpn_conflict,
        } => {
            let iface = interface.as_str();
            let nic = physical_nic
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty());
            let vpn_badge = vpn_conflict
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|provider| format!("[VPN: {provider}]"));

            let iface_chars = iface.chars().count();
            let nic_suffix = nic.map(|n| format!(" ({n})"));
            let nic_chars = nic_suffix.as_ref().map_or(0, |s| s.chars().count());
            let vpn_extra = vpn_badge.as_ref().map_or(0, |b| 3 + b.chars().count());

            let full_len = head_len
                + 3
                + "TUN ".len()
                + iface_chars
                + nic_chars
                + vpn_extra
                + 3
                + mode.len()
                + 3
                + dns.len()
                + 3
                + "Uptime ".len()
                + uptime.len();
            let med_len = head_len
                + 3
                + "TUN ".len()
                + iface_chars
                + nic_chars
                + vpn_extra
                + 3
                + mode.len()
                + 1
                + dns.len()
                + 3
                + uptime.len();
            let compact_len = head_len
                + 3
                + "TUN ".len()
                + iface_chars
                + vpn_extra
                + 3
                + mode.len()
                + 1
                + dns.len()
                + 3
                + uptime.len();

            if w >= full_len {
                spans.push(sep.clone());
                spans.push(Span::styled("TUN ", p.label));
                spans.push(Span::styled(iface.to_string(), p.text));
                if let Some(suffix) = nic_suffix {
                    spans.push(Span::styled(suffix, p.label));
                }
                if let Some(badge) = vpn_badge {
                    spans.push(sep.clone());
                    spans.push(Span::styled(badge, p.amber));
                }
                spans.push(sep.clone());
                spans.push(Span::styled(format!("{mode} · {dns}"), p.text));
                spans.push(sep);
                spans.push(Span::styled("Uptime ", p.label));
                spans.push(Span::styled(uptime, p.text));
            } else if w >= med_len {
                spans.push(sep.clone());
                spans.push(Span::styled("TUN ", p.label));
                spans.push(Span::styled(iface.to_string(), p.text));
                if let Some(suffix) = nic_suffix {
                    spans.push(Span::styled(suffix, p.label));
                }
                if let Some(badge) = vpn_badge {
                    spans.push(sep.clone());
                    spans.push(Span::styled(badge, p.amber));
                }
                spans.push(sep.clone());
                spans.push(Span::styled(format!("{mode}/{dns}"), p.label));
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            } else if w >= compact_len {
                spans.push(sep.clone());
                spans.push(Span::styled("TUN ", p.label));
                spans.push(Span::styled(iface.to_string(), p.text));
                if let Some(badge) = vpn_badge {
                    spans.push(sep.clone());
                    spans.push(Span::styled(badge, p.amber));
                }
                spans.push(sep.clone());
                spans.push(Span::styled(format!("{mode}/{dns}"), p.label));
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            } else {
                spans.push(sep.clone());
                spans.push(Span::styled("TUN ", p.label));
                spans.push(Span::styled(iface.to_string(), p.text));
                if let Some(full_badge) = vpn_badge {
                    let base_len = head_len + 3 + "TUN ".len() + iface_chars + 3 + uptime.len();
                    let full_with_badge = base_len + 3 + full_badge.chars().count();
                    let compact_with_badge = base_len + 3 + "[VPN]".len();
                    let chosen_badge = if w >= full_with_badge {
                        Some(full_badge)
                    } else if w >= compact_with_badge {
                        Some("[VPN]".to_string())
                    } else {
                        None
                    };
                    if let Some(badge_text) = chosen_badge {
                        spans.push(sep.clone());
                        spans.push(Span::styled(badge_text, p.amber));
                    }
                }
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            }
        }
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn render_stats_panel(frame: &mut Frame<'_>, area: Rect, state: &DashboardState) {
    let p = state.palette;
    let avail = area.width.saturating_sub(2) as usize;
    let left_title = " Traffic & Engine ";
    let left_len = left_title.chars().count();
    let rss_title = state.rss_kb.and_then(|kb| {
        let formatted = format_rss_kb(kb);
        let full_len = " RSS ".len() + formatted.len() + 1;
        if left_len + 1 + full_len <= avail {
            Some(Line::from(vec![
                Span::styled(" RSS ", p.label),
                Span::styled(formatted, p.text),
                Span::raw(" "),
            ]))
        } else {
            let compact_len = 1 + formatted.len() + 1;
            (left_len + 1 + compact_len <= avail).then(|| {
                Line::from(vec![
                    Span::raw(" "),
                    Span::styled(formatted, p.text),
                    Span::raw(" "),
                ])
            })
        }
    });

    let mut block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1))
        .title_top(Line::from(left_title).style(p.title).left_aligned());
    if let Some(rss) = rss_title {
        block = block.title_top(rss.right_aligned());
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    let snap = state.telemetry;
    let heal_style = if snap.auto_heal_escalations > 0 {
        p.amber
    } else {
        p.text
    };
    let download_val = format!(
        "{} ({})",
        format_bytes(snap.bytes_rx),
        format_rate(state.rx_rate)
    );
    let upload_val = format!(
        "{} ({})",
        format_bytes(snap.bytes_tx),
        format_rate(state.tx_rate)
    );

    let rows: [(&str, String, Style); 7] = match &state.info.engine {
        DashboardEngine::Proxy { system_proxy, .. } => {
            let proxy_val = if *system_proxy { "Active" } else { "Disabled" };
            let proxy_style = if *system_proxy { p.emerald } else { p.label };
            [
                ("Download", download_val, p.text),
                ("Upload", upload_val, p.text),
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
            ]
        }
        DashboardEngine::Tun {
            interface,
            physical_nic,
            vpn_conflict,
        } => {
            let iface_val = match physical_nic
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(nic) => format!("{interface} ({nic})"),
                None => interface.clone(),
            };
            let iface_style = if vpn_conflict
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty())
            {
                p.amber
            } else {
                p.emerald
            };
            [
                ("Download", download_val, p.text),
                ("Upload", upload_val, p.text),
                (
                    "TCP / UDP",
                    format!(
                        "{} active · {} UDP",
                        snap.active_connections, snap.udp_flows_active
                    ),
                    p.text,
                ),
                ("QUIC Blocked", snap.quic_blocked.to_string(), p.text),
                (
                    if state.info.enable_doh {
                        "DoH Queries"
                    } else {
                        "DNS Queries"
                    },
                    snap.dns_queries.to_string(),
                    p.text,
                ),
                (
                    "TLS / Heal",
                    format!("{} / {}", snap.tls_handshakes, snap.auto_heal_escalations),
                    heal_style,
                ),
                ("Interface", iface_val, iface_style),
            ]
        }
    };

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
    let peak_str = format_rate(peak);
    let avail = area.width.saturating_sub(2) as usize;

    let left_title = if avail >= 50 {
        Some(" Throughput · 60s ")
    } else if avail >= " Throughput ".len() {
        Some(" Throughput ")
    } else {
        None
    };
    let left_len = left_title.map_or(0, |t| t.chars().count());
    let min_gap = usize::from(left_len > 0);

    let right_title = {
        let full = format!(" {cur} · peak {peak_str} ");
        if left_len + min_gap + full.chars().count() <= avail {
            Some(full)
        } else {
            let short = format!(" {cur} · pk {peak_str} ");
            if left_len + min_gap + short.chars().count() <= avail {
                Some(short)
            } else {
                let cur_only = format!(" {cur} ");
                (left_len + min_gap + cur_only.chars().count() <= avail).then_some(cur_only)
            }
        }
    };

    let mut block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1));
    if let Some(left) = left_title {
        block = block.title_top(Line::from(left).style(p.title).left_aligned());
    }
    if let Some(right) = right_title {
        block = block.title_top(Line::from(right).style(p.label).right_aligned());
    }
    if let Some(stage) = state
        .isp_stage
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let full_len = " ISP Stage ".len() + stage.chars().count() + 1;
        let short_len = " Stage ".len() + stage.chars().count() + 1;
        let bottom = if full_len <= avail {
            Some(Line::from(vec![
                Span::styled(" ISP Stage ", p.label),
                Span::styled(stage.to_string(), p.text),
                Span::raw(" "),
            ]))
        } else if short_len <= avail {
            Some(Line::from(vec![
                Span::styled(" Stage ", p.label),
                Span::styled(stage.to_string(), p.text),
                Span::raw(" "),
            ]))
        } else if avail > " Stage ".len() + 2 {
            let budget = avail - " Stage ".len() - 1;
            Some(Line::from(vec![
                Span::styled(" Stage ", p.label),
                Span::styled(truncate_chars(stage, budget), p.text),
                Span::raw(" "),
            ]))
        } else {
            None
        };
        if let Some(line) = bottom {
            block = block.title_bottom(line.left_aligned());
        }
    }
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
    let legend = if state.is_attached {
        if w >= 47 {
            let sep = Span::styled(" · ", p.dim);
            Line::from(vec![
                Span::raw(" "),
                Span::styled("d", p.key_hint),
                Span::styled(" diagnostics", p.dim),
                sep.clone(),
                Span::styled("r", p.key_hint),
                Span::styled(" refresh", p.dim),
                sep.clone(),
                Span::styled("↑↓", p.key_hint),
                Span::styled(" scroll", p.dim),
                sep,
                Span::styled("q", p.key_hint),
                Span::styled(" back", p.dim),
            ])
        } else if w >= 40 {
            let sep = Span::styled(" · ", p.dim);
            Line::from(vec![
                Span::raw(" "),
                Span::styled("d", p.key_hint),
                Span::styled(" diag", p.dim),
                sep.clone(),
                Span::styled("r", p.key_hint),
                Span::styled(" refresh", p.dim),
                sep.clone(),
                Span::styled("↑↓", p.key_hint),
                Span::styled(" scroll", p.dim),
                sep,
                Span::styled("q", p.key_hint),
                Span::styled(" back", p.dim),
            ])
        } else if w >= 20 {
            let sep = Span::styled(" · ", p.dim);
            Line::from(vec![
                Span::raw(" "),
                Span::styled("d", p.key_hint),
                sep.clone(),
                Span::styled("r", p.key_hint),
                sep.clone(),
                Span::styled("↑↓", p.key_hint),
                sep,
                Span::styled("q", p.key_hint),
                Span::styled(" back", p.dim),
            ])
        } else {
            Line::from(vec![
                Span::raw(" "),
                Span::styled("q", p.key_hint),
                Span::styled(" back", p.dim),
            ])
        }
    } else if w >= 57 {
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
    let show_detail = inner.width >= 58;
    let fixed = 2 + 10 + 2 + 7;
    let target_w = if inner.width >= 58 {
        24
    } else {
        (inner.width as usize).saturating_sub(fixed).clamp(8, 18)
    };

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
            if state.is_attached {
                format!("Probing {done}/{total} targets via live daemon...")
            } else {
                format!("Probing {done}/{total} targets via engine DNS...")
            }
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
        lines.push(Line::from(Span::styled(
            truncate_chars(&summary, inner.width as usize),
            summary_style,
        )));
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

fn format_rss_kb(rss_kb: u64) -> String {
    if rss_kb < 1024 {
        format!("{rss_kb} KB")
    } else if rss_kb < 1024 * 1024 {
        let mb = rss_kb.saturating_add(512) / 1024;
        format!("{mb} MB")
    } else {
        format!("{:.1} GB", rss_kb as f64 / (1024.0 * 1024.0))
    }
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
            engine: DashboardEngine::Proxy {
                primary_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
                socks_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1080)),
                system_proxy: true,
            },
            mode: DesyncMode::Combo,
            enable_doh: true,
        }
    }

    fn sample_tun_info(vpn_conflict: Option<&str>) -> DashboardInfo {
        DashboardInfo {
            engine: DashboardEngine::Tun {
                interface: "vdpi0".to_string(),
                physical_nic: Some("Ethernet".to_string()),
                vpn_conflict: vpn_conflict.map(str::to_string),
            },
            mode: DesyncMode::Combo,
            enable_doh: true,
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
            udp_flows_active: 0,
            quic_blocked: 0,
            dns_queries: 0,
        };
        state.rx_rate = 128 * 1024;
        state.tx_rate = 16 * 1024;
        for v in [10_000, 45_000, 120_000, 90_000, 144_000] {
            state.throughput.push(v);
        }
        state
    }

    fn sample_tun_state(color: bool, vpn_conflict: Option<&str>) -> DashboardState {
        let logs = new_log_ring();
        push_log_entry(
            &logs,
            LogEntry {
                timestamp: "12:00:01".to_string(),
                level: Level::INFO,
                message: "desktop TUN engine active interface=vdpi0".to_string(),
            },
        );

        let now = Instant::now();
        let mut state = DashboardState::new(sample_tun_info(vpn_conflict), logs, color, now);
        state.update_telemetry(
            EngineTelemetrySnapshot {
                active_connections: 4,
                total_connections: 42,
                bytes_tx: 2 * 1024 * 1024,
                bytes_rx: 15 * 1024 * 1024,
                tls_handshakes: 28,
                auto_heal_escalations: 2,
                learned_hosts: 7,
                udp_flows_active: 12,
                quic_blocked: 7,
                dns_queries: 34,
            },
            now,
        );
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
        if let DashboardEngine::Proxy {
            ref mut system_proxy,
            ..
        } = state.info.engine
        {
            *system_proxy = false;
        }

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
    fn renders_tun_dashboard_at_100x30_wide_layout() {
        let mut state = sample_tun_state(true, Some("WireGuard"));
        state.set_notice("Cache cleared", Instant::now());

        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains('╭'));
        assert!(screen.contains(&format!("vdpi v{}", env!("CARGO_PKG_VERSION"))));
        assert!(screen.contains("TUN vdpi0 (Ethernet)"));
        assert!(screen.contains("[VPN: WireGuard]"));
        assert!(screen.contains("Combo · DoH"));
        assert!(screen.contains("Uptime"));
        assert!(screen.contains("Traffic & Engine"));
        assert!(screen.contains("Throughput · 60s"));
        assert!(screen.contains("Download"));
        assert!(screen.contains("Upload"));
        assert!(screen.contains("TCP / UDP"));
        assert!(screen.contains("4 active · 12 UDP"));
        assert!(screen.contains("QUIC Blocked"));
        assert!(screen.contains("DoH Queries"));
        assert!(screen.contains("34"));
        assert!(screen.contains("TLS / Heal"));
        assert!(screen.contains("28 / 2"));
        assert!(screen.contains("Interface"));
        assert!(screen.contains("vdpi0 (Ethernet)"));
        assert!(screen.contains("desktop TUN engine active"));
        assert!(screen.contains("Cache cleared"));

        // Verify amber VPN conflict badge color in status bar.
        let buf = terminal.backend().buffer();
        let status_row = 1u16;
        let vpn_x = (0..buf.area.width.saturating_sub(4))
            .find(|&x| {
                buf[(x, status_row)].symbol() == "["
                    && buf[(x + 1, status_row)].symbol() == "V"
                    && buf[(x + 2, status_row)].symbol() == "P"
                    && buf[(x + 3, status_row)].symbol() == "N"
            })
            .expect("amber VPN badge in TUN status bar");
        assert_eq!(buf[(vpn_x, status_row)].fg, AMBER_WARN);

        let same_row = screen
            .lines()
            .any(|line| line.contains("Traffic & Engine") && line.contains("Throughput · 60s"));
        assert!(same_row, "expected side-by-side middle panels at 100x30");
    }

    #[test]
    fn renders_tun_dashboard_at_80x24_layout() {
        // Without VPN conflict: full NIC label fits at 80x24.
        let mut clean_state = sample_tun_state(true, None);
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut clean_state))
            .unwrap();
        let clean_screen = buffer_to_string(terminal.backend());
        assert!(clean_screen.contains("TUN vdpi0 (Ethernet)"));
        assert!(clean_screen.contains("Combo · DoH"));
        assert!(!clean_screen.contains("[VPN"));
        assert!(clean_screen.contains("TCP / UDP"));
        assert!(clean_screen.contains("4 active · 12 UDP"));
        assert!(clean_screen.contains("QUIC Blocked"));
        assert!(clean_screen.contains("DoH Queries"));
        assert!(clean_screen.contains("TLS / Heal"));
        assert!(clean_screen.contains("Interface"));

        // With VPN conflict: compact tier keeps interface, amber VPN badge, and mode/DNS visible.
        let mut vpn_state = sample_tun_state(true, Some("WireGuard"));
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut vpn_state))
            .unwrap();
        let vpn_screen = buffer_to_string(terminal.backend());
        assert!(vpn_screen.contains("TUN vdpi0"));
        assert!(vpn_screen.contains("[VPN: WireGuard]"));
        assert!(vpn_screen.contains("Combo/DoH"));
    }

    #[test]
    fn renders_tun_dashboard_at_60x22_narrow_stacked_layout() {
        let mut state = sample_tun_state(true, Some("WireGuard"));
        let backend = TestBackend::new(60, 22);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();

        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("TUN vdpi0"));
        assert!(screen.contains("[VPN: WireGuard]"));
        assert!(screen.contains("Traffic & Engine"));
        assert!(screen.contains("Throughput · 60s"));
        assert!(screen.contains("TCP / UDP"));
        assert!(screen.contains("4 active · 12 UDP"));
        assert!(screen.contains("QUIC Blocked"));
        assert!(screen.contains("DoH Queries"));
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
    fn renders_tun_dashboard_no_color_monochrome() {
        let mut state = sample_tun_state(false, Some("WireGuard"));
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
        assert!(screen.contains("TUN vdpi0 (Ethernet)"));
        assert!(screen.contains("[VPN: WireGuard]"));
        assert!(screen.contains("4 active · 12 UDP"));

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

    #[test]
    fn renders_tun_status_bar_at_46x18_without_clipping_uptime() {
        let mut state = sample_tun_state(true, Some("WireGuard"));
        let before = format_uptime(state.started_at.elapsed());

        let backend = TestBackend::new(46, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let after = format_uptime(state.started_at.elapsed());
        let screen = buffer_to_string(terminal.backend());
        let status_line = screen.lines().nth(1).expect("status bar row");

        assert!(
            status_line.contains("TUN vdpi0"),
            "missing TUN interface in 46x18 status bar: {status_line}"
        );
        assert!(
            status_line.contains(&before) || status_line.contains(&after),
            "46x18 TUN status bar clipped uptime: {status_line}"
        );
        assert!(
            !status_line.contains("[VPN"),
            "46x18 TUN status bar must omit VPN badge rather than overflowing: {status_line}"
        );
        assert_eq!(terminal.backend().buffer()[(45, 1)].symbol(), "│");

        // At 50x18 (inner 46 cols), compact [VPN] fits alongside uptime without full badge overflow.
        let before_mid = format_uptime(state.started_at.elapsed());
        let mid_backend = TestBackend::new(50, 18);
        let mut mid_terminal = Terminal::new(mid_backend).unwrap();
        mid_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let after_mid = format_uptime(state.started_at.elapsed());
        let mid_screen = buffer_to_string(mid_terminal.backend());
        let mid_status = mid_screen.lines().nth(1).expect("50x18 status bar row");
        assert!(mid_status.contains("TUN vdpi0"));
        assert!(mid_status.contains("[VPN]"));
        assert!(!mid_status.contains("[VPN: WireGuard]"));
        assert!(mid_status.contains(&before_mid) || mid_status.contains(&after_mid));

        // When DoH is disabled, TUN stats panel labels the DNS row "DNS Queries".
        state.info.enable_doh = false;
        let wide_backend = TestBackend::new(100, 30);
        let mut wide_terminal = Terminal::new(wide_backend).unwrap();
        wide_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let wide_screen = buffer_to_string(wide_terminal.backend());
        assert!(wide_screen.contains("DNS Queries"));
        assert!(!wide_screen.contains("DoH Queries"));
    }

    #[test]
    fn renders_sparkline_without_title_collision_at_80x24_and_46x18() {
        let mut state = sample_state(true);

        // 80x24 with non-zero throughput (140.6 KB/s): shortens left & right titles with border gap.
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        let header_row = screen
            .lines()
            .find(|line| line.contains("Traffic & Engine"))
            .expect("80x24 middle panel border row");
        assert!(
            header_row.contains(" Throughput ─"),
            "80x24 sparkline left title must not collide with right title: {header_row}"
        );
        assert!(
            header_row.contains(" 140.6 KB/s · pk 140.6 KB/s "),
            "80x24 sparkline should use compact pk right title: {header_row}"
        );
        assert!(!header_row.contains("Throughput · 60s"));

        // Wider rate (1023.9 KB/s) degrades further to cur-only at 80x24 and pk at 46x18 without colliding.
        state.throughput.push(1_048_473);
        let wide_backend = TestBackend::new(80, 24);
        let mut wide_terminal = Terminal::new(wide_backend).unwrap();
        wide_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let wide_screen = buffer_to_string(wide_terminal.backend());
        let wide_row = wide_screen
            .lines()
            .find(|line| line.contains("Traffic & Engine"))
            .expect("80x24 high-rate border row");
        assert!(
            wide_row.contains(" Throughput ─"),
            "80x24 high-rate sparkline left title collided: {wide_row}"
        );
        assert!(
            wide_row.contains(" 1023.9 KB/s "),
            "80x24 high-rate sparkline should fall back to cur-only title: {wide_row}"
        );
        assert!(!wide_row.contains("pk "));

        let narrow_backend = TestBackend::new(46, 18);
        let mut narrow_terminal = Terminal::new(narrow_backend).unwrap();
        narrow_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let narrow_screen = buffer_to_string(narrow_terminal.backend());
        let narrow_row = narrow_screen
            .lines()
            .find(|line| line.contains(" Throughput "))
            .expect("46x18 sparkline border row");
        assert!(
            narrow_row.contains(" Throughput ─"),
            "46x18 sparkline left title collided: {narrow_row}"
        );
        assert!(
            narrow_row.contains(" 1023.9 KB/s · pk 1023.9 KB/s "),
            "46x18 sparkline should render compact pk title cleanly: {narrow_row}"
        );
    }

    #[test]
    fn renders_diagnostics_modal_cleanly_at_46x18_and_60x22() {
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

        // 46x18: latencies remain unclipped and Detail column is hidden.
        let backend_46 = TestBackend::new(46, 18);
        let mut term_46 = Terminal::new(backend_46).unwrap();
        term_46
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen_46 = buffer_to_string(term_46.backend());
        assert!(screen_46.contains("Diagnostics"));
        assert!(screen_46.contains("r re-run · esc close"));
        assert!(screen_46.contains("Target"));
        assert!(screen_46.contains("Status"));
        assert!(screen_46.contains("Latency"));
        assert!(!screen_46.contains("Detai"));
        assert!(screen_46.contains("19 ms"));
        assert!(screen_46.contains("27 ms"));
        assert!(screen_46.contains("4000 ms"));
        assert!(screen_46.contains("PASS"));
        assert!(screen_46.contains("FAIL"));
        assert!(screen_46.contains("Running..."));

        // 60x22: Detail column stays gated off so its header is never truncated to "Detai…".
        let backend_60 = TestBackend::new(60, 22);
        let mut term_60 = Terminal::new(backend_60).unwrap();
        term_60
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen_60 = buffer_to_string(term_60.backend());
        assert!(screen_60.contains("Target"));
        assert!(screen_60.contains("Status"));
        assert!(screen_60.contains("Latency"));
        assert!(
            !screen_60.contains("Detai"),
            "60x22 modal must not render truncated Detail header:\n{screen_60}"
        );
        assert!(screen_60.contains("discord.com"));
        assert!(screen_60.contains("gateway.discord.gg"));
        assert!(screen_60.contains("www.roblox.com"));
        assert!(screen_60.contains("19 ms"));
        assert!(screen_60.contains("4000 ms"));

        // 100x30: Detail column appears untruncated with IP detail.
        let backend_100 = TestBackend::new(100, 30);
        let mut term_100 = Terminal::new(backend_100).unwrap();
        term_100
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen_100 = buffer_to_string(term_100.backend());
        assert!(screen_100.contains("Detail"));
        assert!(screen_100.contains("162.159.135.232"));
    }

    #[test]
    fn log_ring_caps_entry_message_at_512_chars() {
        let ring = new_log_ring();
        push_log_entry(
            &ring,
            LogEntry {
                timestamp: "12:00:00".to_string(),
                level: Level::INFO,
                message: "x".repeat(1_000),
            },
        );
        let guard = ring.lock().unwrap();
        let stored = &guard.back().unwrap().message;
        assert_eq!(stored.chars().count(), MAX_LOG_MESSAGE_CHARS);
        assert!(stored.ends_with('…'));
    }

    fn sample_attached_state(color: bool, reconnecting: bool, tun_mode: bool) -> DashboardState {
        let now = Instant::now();
        let info = if tun_mode {
            sample_tun_info(Some("WireGuard"))
        } else {
            sample_info()
        };
        let initial_snap = EngineTelemetrySnapshot {
            active_connections: 6,
            total_connections: 120,
            bytes_tx: 8 * 1024 * 1024,
            bytes_rx: 42 * 1024 * 1024,
            tls_handshakes: 95,
            auto_heal_escalations: 1,
            learned_hosts: 14,
            udp_flows_active: 9,
            quic_blocked: 5,
            dns_queries: 64,
        };
        let logs = new_log_ring();
        let _tracker = AttachedActivityTracker::new(
            Arc::clone(&logs),
            &info,
            initial_snap,
            Some("ComboMultiRecord"),
        );
        let mut state = DashboardState::new_attached(
            info,
            initial_snap,
            Some(29 * 1024),
            Some("ComboMultiRecord".to_string()),
            logs,
            color,
            now,
        );
        state.remote_version = Some(env!("CARGO_PKG_VERSION").to_string());
        state.rx_rate = 256 * 1024;
        state.tx_rate = 32 * 1024;
        for v in [30_000, 80_000, 180_000, 288 * 1024] {
            state.throughput.push(v);
        }
        state.reconnecting = reconnecting;
        state
    }

    #[test]
    fn telemetry_rate_seeding_delta_and_counter_reset_recovery() {
        let t0 = Instant::now();
        let logs = new_log_ring();
        let initial = EngineTelemetrySnapshot {
            bytes_rx: 500_000_000,
            bytes_tx: 80_000_000,
            ..Default::default()
        };

        // Seeding on first snapshot must produce 0 initial spike even if elapsed >= 1s.
        let mut fresh = DashboardState::new(sample_info(), Arc::clone(&logs), true, t0);
        fresh.update_telemetry(initial, t0 + Duration::from_secs(5));
        assert_eq!(fresh.rx_rate, 0);
        assert_eq!(fresh.tx_rate, 0);
        assert_eq!(fresh.throughput.latest(), 0);
        assert_eq!(fresh.throughput.peak(), 0);

        // Attached constructor also seeds without spiking.
        let mut state = DashboardState::new_attached(
            sample_info(),
            initial,
            Some(29 * 1024),
            Some("ComboMultiRecord".to_string()),
            logs,
            true,
            t0,
        );
        assert_eq!(state.rx_rate, 0);
        assert_eq!(state.tx_rate, 0);
        assert_eq!(state.throughput.peak(), 0);

        // Subsequent 2s delta computes exact bytes/sec rates.
        let t1 = t0 + Duration::from_secs(2);
        let snap1 = EngineTelemetrySnapshot {
            bytes_rx: initial.bytes_rx + 200_000,
            bytes_tx: initial.bytes_tx + 40_000,
            ..Default::default()
        };
        state.update_telemetry(snap1, t1);
        assert_eq!(state.rx_rate, 100_000);
        assert_eq!(state.tx_rate, 20_000);
        assert_eq!(state.throughput.latest(), 120_000);

        // Daemon restart: counters drop below previous baseline -> clean zero reset, no underflow.
        let t2 = t1 + Duration::from_secs(1);
        let snap_reset = EngineTelemetrySnapshot {
            bytes_rx: 4_096,
            bytes_tx: 512,
            ..Default::default()
        };
        state.update_telemetry(snap_reset, t2);
        assert_eq!(state.rx_rate, 0);
        assert_eq!(state.tx_rate, 0);
        assert_eq!(state.prev_rx, 4_096);
        assert_eq!(state.prev_tx, 512);
        assert_eq!(state.throughput.latest(), 0);

        // Next 1s sample after reset recovers accurate rate immediately.
        let t3 = t2 + Duration::from_secs(1);
        let snap_recovered = EngineTelemetrySnapshot {
            bytes_rx: 4_096 + 20_000,
            bytes_tx: 512 + 4_000,
            ..Default::default()
        };
        state.update_telemetry(snap_recovered, t3);
        assert_eq!(state.rx_rate, 20_000);
        assert_eq!(state.tx_rate, 4_000);
        assert_eq!(state.throughput.latest(), 24_000);

        // Reconnect after offline window re-baselines instead of producing a fake catch-up spike.
        let t4 = t3 + Duration::from_secs(2);
        state.mark_reconnecting(t4);
        assert!(state.reconnecting);
        assert_eq!(state.rx_rate, 0);
        assert_eq!(state.tx_rate, 0);

        let t5 = t4 + Duration::from_secs(3);
        state.apply_attached_sample(
            AttachedTelemetry {
                snap: EngineTelemetrySnapshot {
                    bytes_rx: snap_recovered.bytes_rx + 5_000_000,
                    bytes_tx: snap_recovered.bytes_tx + 1_000_000,
                    ..Default::default()
                },
                engine: sample_info().engine,
                mode: DesyncMode::Combo,
                doh: true,
                block_quic: true,
                rss_kb: Some(30 * 1024),
                isp_stage: Some("OobSniDesync".to_string()),
                version: Some("0.5.5".to_string()),
            },
            t5,
        );
        assert!(!state.reconnecting);
        assert_eq!(state.rx_rate, 0);
        assert_eq!(state.tx_rate, 0);
        assert_eq!(state.rss_kb, Some(30 * 1024));
        assert_eq!(state.isp_stage.as_deref(), Some("OobSniDesync"));
    }

    #[test]
    fn renders_attached_dashboard_across_all_sizes_connected_and_reconnecting() {
        for (w, h) in [(100u16, 30u16), (80, 24), (60, 22), (46, 18)] {
            // Connected Proxy mode
            let mut connected = sample_attached_state(true, false, false);
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &mut connected))
                .unwrap();
            let screen = buffer_to_string(terminal.backend());
            let buf = terminal.backend().buffer();

            assert_eq!(
                buf[(w - 1, 1)].symbol(),
                "│",
                "status bar right border clipped at {w}x{h} (connected)"
            );
            assert!(
                screen.contains("RSS 29 MB"),
                "missing RSS 29 MB at {w}x{h}:\n{screen}"
            );
            assert!(
                screen.contains("ISP Stage ComboMultiRecord"),
                "missing ISP Stage at {w}x{h}:\n{screen}"
            );
            assert!(
                screen.contains("q back"),
                "missing 'q back' footer at {w}x{h}:\n{screen}"
            );
            assert!(
                !screen.contains("clear cache") && !screen.contains("q quit"),
                "attached footer leaked foreground hints at {w}x{h}:\n{screen}"
            );
            if w >= 60 {
                assert!(
                    screen.contains("d diagnostics · r refresh · ↑↓ scroll · q back"),
                    "expected full attached footer at {w}x{h}:\n{screen}"
                );
            } else {
                assert!(
                    screen.contains("d diag · r refresh · ↑↓ scroll · q back"),
                    "expected compact attached footer at {w}x{h}:\n{screen}"
                );
            }
            let dot_x = (0..w)
                .find(|&x| buf[(x, 1)].symbol() == "●")
                .expect("connected status dot");
            assert_eq!(buf[(dot_x, 1)].fg, EMERALD_ACTIVE);

            // Reconnecting Proxy mode
            let mut reconnecting = sample_attached_state(true, true, false);
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &mut reconnecting))
                .unwrap();
            let screen = buffer_to_string(terminal.backend());
            let buf = terminal.backend().buffer();

            assert_eq!(
                buf[(w - 1, 1)].symbol(),
                "│",
                "status bar right border clipped at {w}x{h} (reconnecting)"
            );
            assert!(
                screen.contains("Reconnecting…"),
                "missing Reconnecting… at {w}x{h}:\n{screen}"
            );
            assert!(screen.contains("RSS 29 MB"));
            assert!(screen.contains("ISP Stage ComboMultiRecord"));
            assert!(screen.contains("q back"));

            let dot_x = (0..w)
                .find(|&x| buf[(x, 1)].symbol() == "●")
                .expect("reconnecting status dot");
            assert_eq!(buf[(dot_x, 1)].fg, AMBER_WARN);
            let rec_x = (0..w.saturating_sub(3))
                .find(|&x| {
                    buf[(x, 1)].symbol() == "R"
                        && buf[(x + 1, 1)].symbol() == "e"
                        && buf[(x + 2, 1)].symbol() == "c"
                })
                .expect("Reconnecting… text in status bar");
            assert_eq!(buf[(rec_x, 1)].fg, AMBER_WARN);
        }

        // NO_COLOR verification for both connected and reconnecting (wide + compact).
        for reconnecting in [false, true] {
            for (w, h) in [(100u16, 30u16), (46, 18)] {
                let mut state = sample_attached_state(false, reconnecting, true);
                let backend = TestBackend::new(w, h);
                let mut terminal = Terminal::new(backend).unwrap();
                terminal
                    .draw(|frame| render_dashboard(frame, &mut state))
                    .unwrap();
                let screen = buffer_to_string(terminal.backend());
                assert!(screen.contains('┌'));
                assert!(!screen.contains('╭'));
                assert!(screen.contains("RSS 29 MB"));
                assert!(screen.contains("ISP Stage ComboMultiRecord"));
                assert!(screen.contains("q back"));
                if reconnecting {
                    assert!(screen.contains("Reconnecting…"));
                }

                let buf = terminal.backend().buffer();
                for y in 0..buf.area.height {
                    for x in 0..buf.area.width {
                        let cell = &buf[(x, y)];
                        assert_eq!(
                            cell.fg,
                            Color::Reset,
                            "unexpected fg color at ({x},{y}) in NO_COLOR attached mode"
                        );
                        assert_eq!(
                            cell.bg,
                            Color::Reset,
                            "unexpected bg color at ({x},{y}) in NO_COLOR attached mode"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn attached_key_handling_refresh_diagnostics_and_modal_esc() {
        let mut state = sample_attached_state(true, false, false);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // 'c' is ignored in attached mode (no remote cache-clear endpoint).
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('c'))),
            KeyAction::None
        );

        // 'r' triggers manual refresh when diagnostics modal is closed.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::Refresh
        );

        // 'd' opens diagnostics modal and runs probes.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('d'))),
            KeyAction::RunDiagnostics
        );
        assert!(state.diagnostics_open);

        // While modal is open, 'r' re-runs diagnostics and 'Esc' closes modal without quitting.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::RunDiagnostics
        );
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Esc)),
            KeyAction::Redraw
        );
        assert!(!state.diagnostics_open);

        // Once modal is closed, 'Esc', 'q', and Ctrl-C all detach/quit cleanly.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Esc)),
            KeyAction::Quit
        );
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('q'))),
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
    fn attached_activity_tracker_synthesizes_non_spammy_transitions() {
        let t0 = Instant::now();
        let logs = new_log_ring();
        let initial_info = sample_info();
        let initial_snap = EngineTelemetrySnapshot {
            bytes_rx: 1024,
            bytes_tx: 512,
            auto_heal_escalations: 1,
            learned_hosts: 2,
            ..Default::default()
        };
        let mut tracker = AttachedActivityTracker::new(
            Arc::clone(&logs),
            &initial_info,
            initial_snap,
            Some("ComboMultiRecord"),
        );
        let mut state = DashboardState::new_attached(
            initial_info,
            initial_snap,
            Some(29 * 1024),
            Some("ComboMultiRecord".to_string()),
            Arc::clone(&logs),
            true,
            t0,
        );

        // Startup log present.
        assert!(logs
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.message.contains("attached to live vdpi daemon")));

        // Offline warning fires only once while staying offline.
        tracker.on_offline(&state);
        state.mark_reconnecting(t0 + Duration::from_secs(1));
        tracker.on_offline(&state);
        let offline_count = logs
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.message.contains("daemon unreachable"))
            .count();
        assert_eq!(offline_count, 1);

        // Reconnect + mode/engine/ISP-stage/VPN-conflict transitions.
        let sample = AttachedTelemetry {
            snap: EngineTelemetrySnapshot {
                bytes_rx: 12 * 1024 * 1024,
                bytes_tx: 2 * 1024 * 1024,
                total_connections: 25,
                auto_heal_escalations: 3,
                learned_hosts: 8,
                ..Default::default()
            },
            engine: sample_tun_info(Some("WireGuard")).engine,
            mode: DesyncMode::TlsRecord,
            doh: false,
            block_quic: true,
            rss_kb: Some(31 * 1024),
            isp_stage: Some("OobSniDesync".to_string()),
            version: Some("0.5.5".to_string()),
        };
        let t1 = t0 + Duration::from_secs(2);
        tracker.on_sample(&state, &sample, t1);
        state.apply_attached_sample(sample, t1);

        let messages: Vec<String> = logs
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.message.clone())
            .collect();
        assert!(messages
            .iter()
            .any(|m| m.contains("reconnected to live vdpi daemon")));
        assert!(messages
            .iter()
            .any(|m| m.contains("engine switched to TUN vdpi0")));
        assert!(messages
            .iter()
            .any(|m| m.contains("VPN conflict active: WireGuard")));
        assert!(messages
            .iter()
            .any(|m| m.contains("desync mode changed: Combo -> TLS Record")));
        assert!(messages
            .iter()
            .any(|m| m.contains("DNS transport changed: DoH -> UDP")));
        assert!(messages
            .iter()
            .any(|m| m.contains("ISP stage changed: ComboMultiRecord -> OobSniDesync")));
        assert!(messages
            .iter()
            .any(|m| m.contains("auto-heal escalated (+2, total 3)")));
        assert!(messages.iter().any(|m| m.contains("traffic milestone:")));
    }

    #[tokio::test]
    async fn attached_http_connect_probe_passes_and_fails_cleanly() {
        assert_eq!(
            normalize_loopback_connect_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                8080
            )),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
        assert_eq!(
            normalize_loopback_connect_addr(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                8080
            )),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)
        );

        let ok_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = ok_listener.local_addr().unwrap();
        let ok_server = tokio::spawn(async move {
            let (mut sock, _) = ok_listener.accept().await.unwrap();
            let mut req_buf = [0u8; 512];
            let _ = sock.read(&mut req_buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await;
        });
        let pass = probe_via_http_connect(ok_addr, "discord.com").await;
        ok_server.await.unwrap();
        assert!(
            matches!(pass, ProbeStatus::Pass { ref detail, .. } if detail == "CONNECT 200"),
            "expected CONNECT 200 pass, got {pass:?}"
        );

        let fail_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fail_addr = fail_listener.local_addr().unwrap();
        let fail_server = tokio::spawn(async move {
            let (mut sock, _) = fail_listener.accept().await.unwrap();
            let mut req_buf = [0u8; 512];
            let _ = sock.read(&mut req_buf).await;
            let _ = sock
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        });
        let fail = probe_via_http_connect(fail_addr, "www.roblox.com").await;
        fail_server.await.unwrap();
        assert!(
            matches!(fail, ProbeStatus::Fail { ref reason, .. } if reason.contains("502 Bad Gateway")),
            "expected 502 fail, got {fail:?}"
        );
    }

    #[test]
    fn format_rss_kb_formats_kb_mb_and_gb_cleanly() {
        assert_eq!(format_rss_kb(512), "512 KB");
        assert_eq!(format_rss_kb(29 * 1024), "29 MB");
        assert_eq!(format_rss_kb(29 * 1024 + 511), "29 MB");
        assert_eq!(format_rss_kb(1_536 * 1024), "1.5 GB");
    }
}
