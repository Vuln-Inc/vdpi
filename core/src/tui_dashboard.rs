use anyhow::Result;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
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

fn is_interactive_tty() -> bool {
    let dumb = std::env::var_os("TERM").is_some_and(|v| v == "dumb");
    io::stdin().is_terminal() && io::stdout().is_terminal() && !dumb
}

pub fn should_enable_dashboard(cfg: &RuntimeConfig, is_service: bool) -> bool {
    is_interactive_tty() && !cfg.quiet && !cfg.debug && !is_service
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

#[derive(Clone)]
pub struct DashboardInfo {
    pub engine: DashboardEngine,
    pub mode: DesyncMode,
    pub enable_doh: bool,
    pub dns_addr: Option<String>,
}

impl fmt::Debug for DashboardInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_dns = self
            .dns_addr
            .as_deref()
            .map(vdpi_core::dns::redact_dns_for_display);
        f.debug_struct("DashboardInfo")
            .field("engine", &self.engine)
            .field("mode", &self.mode)
            .field("enable_doh", &self.enable_doh)
            .field("dns_addr", &redacted_dns)
            .finish()
    }
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
    pub dns_addr: Option<String>,
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
    label: String,
    host: &'static str,
    status: ProbeStatus,
}

#[derive(Debug, Clone)]
struct DiagnosticsState {
    run_id: u64,
    rows: [ProbeRow; 4],
}

impl DiagnosticsState {
    fn new_running(run_id: u64, dns_addr: Option<&str>, enable_doh: bool) -> Self {
        Self {
            run_id,
            rows: [
                ProbeRow {
                    label: diagnostics_dns_row_label(dns_addr, enable_doh),
                    host: "one.one.one.one",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "discord.com".to_string(),
                    host: "discord.com",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "gateway.discord.gg".to_string(),
                    host: "gateway.discord.gg",
                    status: ProbeStatus::Running,
                },
                ProbeRow {
                    label: "www.roblox.com".to_string(),
                    host: "www.roblox.com",
                    status: ProbeStatus::Running,
                },
            ],
        }
    }

    fn is_running(&self) -> bool {
        self.rows
            .iter()
            .any(|row| matches!(row.status, ProbeStatus::Running))
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
    color: bool,
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
                color: false,
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
            color: true,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoticeKind {
    Info,
    Warn,
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
    notice: Option<(String, NoticeKind, Instant)>,
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
        let initial_diag =
            DiagnosticsState::new_running(0, info.dns_addr.as_deref(), info.enable_doh);
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
            diagnostics: Arc::new(Mutex::new(initial_diag)),
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
            if self.is_attached {
                self.started_at = now;
            }
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
        let counters_reset = self.rate_initialized
            && (sample.snap.bytes_rx < self.prev_rx || sample.snap.bytes_tx < self.prev_tx);
        self.reconnecting = false;
        if counters_reset {
            self.started_at = now;
        }
        if was_reconnecting {
            // Re-baseline after an offline window so accumulated traffic during
            // disconnect never shows up as a fake catch-up spike.
            self.rate_initialized = false;
        }
        self.update_telemetry(sample.snap, now);
        self.info.engine = sample.engine;
        self.info.mode = sample.mode;
        self.info.enable_doh = sample.doh;
        self.info.dns_addr = normalize_opt_string(sample.dns_addr);
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
        if self.notice.as_ref().is_some_and(|(_, _, exp)| now >= *exp) {
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
        self.notice = Some((message.into(), NoticeKind::Info, now + NOTICE_TTL));
    }

    fn set_notice_warn(&mut self, message: impl Into<String>, now: Instant) {
        self.notice = Some((message.into(), NoticeKind::Warn, now + NOTICE_TTL));
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

    fn diagnostics_running(&self) -> bool {
        self.diagnostics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_running()
    }

    fn begin_diagnostics_run(&mut self) -> (u64, [(usize, &'static str); 4]) {
        self.abort_diagnostics_tasks();
        self.next_diag_run = self.next_diag_run.wrapping_add(1).max(1);
        let run_id = self.next_diag_run;
        let fresh =
            DiagnosticsState::new_running(run_id, self.info.dns_addr.as_deref(), self.info.enable_doh);
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
    DiagnosticsOffline,
    Quit,
}

fn handle_key_event(state: &mut DashboardState, key: KeyEvent) -> KeyAction {
    if key.kind == KeyEventKind::Release {
        return KeyAction::None;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return if key.kind == KeyEventKind::Press {
            KeyAction::Quit
        } else {
            KeyAction::None
        };
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
            KeyCode::Char('r' | 'R') => {
                if state.is_attached && state.reconnecting {
                    state.diagnostics_open = false;
                    state.abort_diagnostics_tasks();
                    KeyAction::DiagnosticsOffline
                } else if state.diagnostics_running() {
                    KeyAction::None
                } else {
                    KeyAction::RunDiagnostics
                }
            }
            KeyCode::Char('q' | 'Q') => KeyAction::Quit,
            _ => KeyAction::None,
        };
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k' | 'K') => {
            state.scroll_up(1);
            KeyAction::Redraw
        }
        KeyCode::Down | KeyCode::Char('j' | 'J') => {
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
            if state.is_attached && state.reconnecting {
                KeyAction::DiagnosticsOffline
            } else {
                state.diagnostics_open = true;
                KeyAction::RunDiagnostics
            }
        }
        KeyCode::Char('r' | 'R') if state.is_attached => KeyAction::Refresh,
        KeyCode::Char('c' | 'C') if !state.is_attached => KeyAction::ClearCache,
        KeyCode::Char('q' | 'Q') | KeyCode::Esc => KeyAction::Quit,
        _ => KeyAction::None,
    }
}

static TUI_PANIC_HOOK_ONCE: Once = Once::new();
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Installs a process-wide panic hook wrapper once that restores raw mode,
/// disables bracketed paste, and leaves the alternate screen before invoking
/// the previous hook, so panic messages are never erased by unwinding `Drop` guards.
pub(crate) fn install_tui_panic_hook() {
    TUI_PANIC_HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(
                    io::stdout(),
                    DisableBracketedPaste,
                    LeaveAlternateScreen,
                    Show
                );
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
            while !reader_flag.load(Ordering::Acquire) {
                match event::poll(Duration::from_millis(15)) {
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
        self.stop_reader.store(true, Ordering::Release);
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
        let (dns, _) =
            format_dashboard_dns_tag(initial_info.dns_addr.as_deref(), initial_info.enable_doh);
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

        let old_dns_addr = normalize_opt_string(prev.info.dns_addr.clone());
        let new_dns_addr = normalize_opt_string(sample.dns_addr.clone());
        let prev_effective_doh =
            effective_dashboard_doh(old_dns_addr.as_deref(), prev.info.enable_doh);
        let new_effective_doh = effective_dashboard_doh(new_dns_addr.as_deref(), sample.doh);

        if prev_effective_doh != new_effective_doh {
            let old_dns = if prev_effective_doh { "DoH" } else { "UDP" };
            let new_dns = if new_effective_doh { "DoH" } else { "UDP" };
            self.push(
                Level::INFO,
                format!("DNS transport changed: {old_dns} -> {new_dns}"),
            );
        }

        if old_dns_addr != new_dns_addr {
            let (old_tag, _) =
                format_dashboard_dns_tag(old_dns_addr.as_deref(), prev_effective_doh);
            let (new_tag, _) = format_dashboard_dns_tag(new_dns_addr.as_deref(), new_effective_doh);
            match (old_dns_addr.as_deref(), new_dns_addr.as_deref()) {
                (None, Some("1.1.1.1")) | (Some("1.1.1.1"), None) => {}
                (_, None) => {
                    self.push(
                        Level::INFO,
                        format!("DNS server reset to default ({new_tag})"),
                    );
                }
                (None, Some(_)) => {
                    self.push(Level::INFO, format!("DNS server set: {new_tag}"));
                }
                (Some(_), Some(_)) if old_tag != new_tag => {
                    self.push(
                        Level::INFO,
                        format!("DNS server changed: {old_tag} -> {new_tag}"),
                    );
                }
                (Some(_), Some(_)) => {
                    self.push(Level::INFO, format!("DNS server updated: {new_tag}"));
                }
            }
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

const DEFAULT_DOH_PROBE_URL: &str = "https://1.1.1.1/dns-query";

fn normalize_doh_probe_url(raw: &str) -> String {
    let rest = &raw[8..];
    match rest.find(['/', '?']) {
        None => format!("https://{rest}/dns-query"),
        Some(idx) => {
            let suffix = &rest[idx..];
            if suffix.starts_with('?') {
                format!("https://{}/dns-query{suffix}", &rest[..idx])
            } else if let Some(query) = suffix.strip_prefix("/?") {
                format!("https://{}/dns-query?{query}", &rest[..idx])
            } else {
                format!("https://{rest}")
            }
        }
    }
}

fn known_doh_ip_probe_url(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
        IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
    }
}

fn doh_url_is_redacted_host_only(url: &str) -> bool {
    let trimmed = url.trim();
    if !is_valid_doh_url(trimmed) {
        return false;
    }
    let rest = &trimmed[8..];
    match rest.find(['/', '?', '#']) {
        None => true,
        Some(idx) => &rest[idx..] == "/",
    }
}

fn doh_authority_match_key(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if !is_valid_doh_url(trimmed) {
        return None;
    }
    let redacted = vdpi_core::dns::redact_dns_for_display(trimmed);
    let host = extract_redacted_doh_host(&redacted);
    if host.is_empty() || host.eq_ignore_ascii_case("<redacted>") {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    let normalized = lower.strip_suffix(":443").unwrap_or(&lower);
    Some(normalized.to_string())
}

fn resolve_tun_doh_probe_url_with_candidates<S: AsRef<str>>(
    dns_addr: Option<&str>,
    configured_candidates: &[S],
) -> String {
    let Some(raw) = dns_addr.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_DOH_PROBE_URL.to_string();
    };
    if is_valid_doh_url(raw) {
        if doh_url_is_redacted_host_only(raw) {
            if let Some(target_key) = doh_authority_match_key(raw) {
                for candidate in configured_candidates {
                    let Ok(validated) =
                        vdpi_core::dns::validate_custom_dns_input(candidate.as_ref())
                    else {
                        continue;
                    };
                    if is_valid_doh_url(&validated)
                        && !doh_url_is_redacted_host_only(&validated)
                        && doh_authority_match_key(&validated).as_deref()
                            == Some(target_key.as_str())
                    {
                        return normalize_doh_probe_url(&validated);
                    }
                }
            }
        }
        return normalize_doh_probe_url(raw);
    }
    if let Some(ip) = parse_known_doh_ip(raw) {
        return known_doh_ip_probe_url(ip);
    }
    DEFAULT_DOH_PROBE_URL.to_string()
}

fn resolve_tun_doh_probe_url(dns_addr: Option<&str>) -> String {
    resolve_tun_doh_probe_url_with_candidates::<&str>(dns_addr, &[])
}

fn load_local_configured_doh_candidates() -> Vec<String> {
    let mut candidates = Vec::with_capacity(2);
    for (path, service_mode) in [
        (vdpi::config_file::system_config_path(), true),
        (vdpi::config_file::user_config_path(), false),
    ] {
        let Ok((_, file_cfg)) = vdpi::config_file::load_file_config(Some(&path), service_mode)
        else {
            continue;
        };
        let Some(dns) = file_cfg.dns_addr else {
            continue;
        };
        let Ok(validated) = vdpi_core::dns::validate_custom_dns_input(&dns) else {
            continue;
        };
        if is_valid_doh_url(&validated) && !candidates.contains(&validated) {
            candidates.push(validated);
        }
    }
    candidates
}

fn resolve_attached_tun_doh_probe_url(dns_addr: Option<&str>) -> String {
    let Some(raw) = dns_addr.map(str::trim).filter(|s| !s.is_empty()) else {
        return DEFAULT_DOH_PROBE_URL.to_string();
    };
    if is_valid_doh_url(raw) {
        if !doh_url_is_redacted_host_only(raw) {
            return normalize_doh_probe_url(raw);
        }
        let candidates = load_local_configured_doh_candidates();
        return resolve_tun_doh_probe_url_with_candidates(Some(raw), candidates.as_slice());
    }
    if let Some(ip) = parse_known_doh_ip(raw) {
        return known_doh_ip_probe_url(ip);
    }
    DEFAULT_DOH_PROBE_URL.to_string()
}

fn redact_url_in_probe_error(msg: &str, url: &str) -> String {
    let redacted_urls = vdpi_core::dns::redact_urls_in_text(msg);
    if !url.is_empty() && redacted_urls.contains(url) {
        let redacted = vdpi_core::dns::redact_dns_for_display(url);
        redacted_urls.replace(url, &redacted)
    } else {
        redacted_urls
    }
}

async fn probe_via_tun_direct(
    client: Option<Arc<reqwest::Client>>,
    enable_doh: bool,
    doh_probe_url: Option<String>,
    idx: usize,
    host: &'static str,
) -> ProbeStatus {
    let started = Instant::now();
    let effective_doh = effective_dashboard_doh(doh_probe_url.as_deref(), enable_doh);
    if idx == 0 && !effective_doh {
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
            let doh_url = resolve_tun_doh_probe_url(doh_probe_url.as_deref());
            let wire_query = vdpi_core::dns::encode_dns_query(host, 1)
                .map_err(|e| sanitize_single_line(&e.to_string()))?;
            let resp = client
                .post(&doh_url)
                .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                .header(reqwest::header::ACCEPT, "application/dns-message")
                .body(wire_query)
                .send()
                .await
                .map_err(|e| {
                    let msg = sanitize_single_line(&e.without_url().to_string());
                    redact_url_in_probe_error(&msg, &doh_url)
                })?;
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
    dns_addr: Option<String>,
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
            let effective_doh = effective_dashboard_doh(dns_addr.as_deref(), enable_doh);
            let doh_probe_url = if effective_doh {
                Some(resolve_attached_tun_doh_probe_url(dns_addr.as_deref()))
            } else {
                None
            };
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
                let probe_url = if idx == 0 {
                    doh_probe_url.clone()
                } else {
                    None
                };
                tasks.spawn(async move {
                    let status =
                        probe_via_tun_direct(client, effective_doh, probe_url, idx, host).await;
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
    // Consume immediate first tick; initial state was populated above.
    tick.tick().await;

    let mut dirty = true;
    tokio::pin!(external_shutdown);

    let loop_result: io::Result<()> = loop {
        if dirty {
            if let Err(err) = guard
                .terminal
                .draw(|frame| render_dashboard(frame, &mut state))
            {
                break Err(err);
            }
            dirty = false;
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
                                dirty = true;
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
                                dirty = true;
                            }
                            KeyAction::Redraw => {
                                dirty = true;
                            }
                            KeyAction::Refresh
                            | KeyAction::DiagnosticsOffline
                            | KeyAction::None => {}
                        }
                    }
                    Some(Event::Resize(..)) => {
                        dirty = true;
                    }
                    Some(_) => {}
                    None => break Ok(()),
                }
            }
            _ = tick.tick() => {
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
                dirty = true;
            }
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
    if !is_interactive_tty() {
        anyhow::bail!("live dashboard requires an interactive terminal (TTY)");
    }

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
    tick.tick().await;
    let mut manual_refresh_pending = false;
    let mut poller_alive = true;
    let mut dirty = true;

    tokio::pin!(external_shutdown);

    let loop_result: io::Result<()> = loop {
        if dirty {
            if let Err(err) = guard
                .terminal
                .draw(|frame| render_dashboard(frame, &mut state))
            {
                break Err(err);
            }
            dirty = false;
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
                                dirty = true;
                            }
                            KeyAction::RunDiagnostics => {
                                let (run_id, targets) = state.begin_diagnostics_run();
                                spawn_attached_diagnostics_probes(
                                    &mut state.diag_tasks,
                                    &state.info.engine,
                                    effective_dashboard_doh(
                                        state.info.dns_addr.as_deref(),
                                        state.info.enable_doh,
                                    ),
                                    state.info.dns_addr.clone(),
                                    &state.diagnostics,
                                    run_id,
                                    targets,
                                );
                                dirty = true;
                            }
                            KeyAction::DiagnosticsOffline => {
                                state.set_notice_warn("Daemon unreachable", Instant::now());
                                dirty = true;
                            }
                            KeyAction::Redraw => {
                                dirty = true;
                            }
                            KeyAction::ClearCache | KeyAction::None => {}
                        }
                    }
                    Some(Event::Resize(..)) => {
                        dirty = true;
                    }
                    Some(_) => {}
                    None => break Ok(()),
                }
            }
            maybe_sample = poll_rx.recv(), if poller_alive => {
                let sample_now = Instant::now();
                match maybe_sample {
                    Some(Some(sample)) => {
                        tracker.on_sample(&state, &sample, sample_now);
                        state.apply_attached_sample(sample, sample_now);
                        if manual_refresh_pending {
                            manual_refresh_pending = false;
                            state.set_notice("Refreshed", sample_now);
                        }
                        dirty = true;
                    }
                    Some(None) => {
                        tracker.on_offline(&state);
                        state.mark_reconnecting(sample_now);
                        if manual_refresh_pending {
                            manual_refresh_pending = false;
                            state.set_notice_warn("Daemon unreachable", sample_now);
                        }
                        dirty = true;
                    }
                    None => {
                        poller_alive = false;
                        tracker.on_offline(&state);
                        state.mark_reconnecting(sample_now);
                        if manual_refresh_pending {
                            manual_refresh_pending = false;
                            state.set_notice_warn("Daemon unreachable", sample_now);
                        }
                        dirty = true;
                    }
                }
            }
            _ = tick.tick() => {
                while state.diag_tasks.try_join_next().is_some() {}
                state.tick_reconnecting(Instant::now());
                dirty = true;
            }
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

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);
    let status_area = outer[0];
    let body_area = outer[1];
    let footer_area = outer[2];

    render_status_bar(frame, status_area, state);

    let wide = area.width >= SIDE_BY_SIDE_MIN_WIDTH;
    if wide {
        let bh = body_area.height;
        let mid_height = if bh >= 12 {
            9
        } else if bh >= 7 {
            bh.saturating_sub(3).min(9)
        } else {
            bh
        };
        let log_height = bh.saturating_sub(mid_height);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(mid_height),
                Constraint::Length(log_height),
            ])
            .split(body_area);

        let mid_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(rows[0]);
        render_stats_panel(frame, mid_cols[0], state, false);
        render_sparkline_panel(frame, mid_cols[1], state);

        if log_height > 0 {
            render_activity_log(frame, rows[1], state);
        }
    } else {
        let bh = body_area.height;
        let (stats_h, spark_h) = if bh >= 18 {
            (9u16, 5u16)
        } else if bh >= 16 {
            (9, 4)
        } else if bh == 15 {
            (9, 3)
        } else if bh == 14 {
            (9, 0)
        } else if bh >= 10 {
            (bh - 5, 0)
        } else if bh >= 7 {
            (bh - 3, 3)
        } else {
            (bh, 0)
        };
        let spark_h = if spark_h < 3 { 0 } else { spark_h };
        let log_h = bh.saturating_sub(stats_h.saturating_add(spark_h));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(stats_h),
                Constraint::Length(spark_h),
                Constraint::Length(log_h),
            ])
            .split(body_area);

        render_stats_panel(frame, rows[0], state, spark_h == 0);
        if spark_h >= 3 {
            render_sparkline_panel(frame, rows[1], state);
        }
        if log_h > 0 {
            render_activity_log(frame, rows[2], state);
        }
    }

    render_footer(frame, footer_area, state);

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
    let (dns_full, dns_short) =
        format_dashboard_dns_tag(state.info.dns_addr.as_deref(), state.info.enable_doh);
    let dns_full_len = dns_full.chars().count();
    let dns_short_len = dns_short.chars().count();
    let has_custom_dns_tag = dns_full != dns_short;
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
        let reconnecting_text = if p.color {
            "Reconnecting…"
        } else {
            "! Reconnecting…"
        };
        let reconnecting_len = reconnecting_text.chars().count();
        let engine_tag = match &state.info.engine {
            DashboardEngine::Proxy { primary_addr, .. } => primary_addr.to_string(),
            DashboardEngine::Tun { interface, .. } => format!("TUN {interface}"),
        };
        let engine_len = engine_tag.chars().count();

        // Hide live uptime while disconnected so it never ticks against an offline daemon.
        let with_engine_len = head_len + 3 + reconnecting_len + 3 + engine_len;
        let min_len = head_len + 3 + reconnecting_len;

        if w >= with_engine_len {
            spans.push(sep.clone());
            spans.push(Span::styled(reconnecting_text, p.amber));
            spans.push(sep);
            spans.push(Span::styled(engine_tag, p.label));
        } else if w >= min_len {
            spans.push(sep);
            spans.push(Span::styled(reconnecting_text, p.amber));
        } else {
            let rem = w.saturating_sub(head_len + 3);
            if rem > 0 {
                spans.push(sep);
                spans.push(Span::styled(
                    truncate_chars(reconnecting_text, rem),
                    p.amber,
                ));
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
                + dns_full_len
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
                + dns_full_len
                + 3
                + "Uptime ".len()
                + uptime.len();
            let compact_dns_len =
                head_len + 3 + primary.len() + 3 + mode.len() + 3 + dns_full_len + 3 + uptime.len();
            let compact_len = head_len
                + 3
                + primary.len()
                + socks.as_ref().map_or(0, |s| 3 + "SOCKS ".len() + s.len())
                + 3
                + mode.len()
                + 1
                + dns_short_len
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
                spans.push(Span::styled(format!("{mode} · {dns_full}"), p.text));
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
                spans.push(Span::styled(format!("{mode} · {dns_full}"), p.text));
                spans.push(sep);
                spans.push(Span::styled("Uptime ", p.label));
                spans.push(Span::styled(uptime, p.text));
            } else if has_custom_dns_tag && w >= compact_dns_len {
                spans.push(sep.clone());
                spans.push(Span::styled(primary, p.text));
                spans.push(sep.clone());
                spans.push(Span::styled(format!("{mode} · {dns_full}"), p.label));
                spans.push(sep);
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
                spans.push(Span::styled(format!("{mode}/{dns_short}"), p.label));
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            } else {
                let min_with_primary = head_len + 3 + primary.len() + 3 + uptime.len();
                if w >= min_with_primary {
                    spans.push(sep.clone());
                    spans.push(Span::styled(primary, p.text));
                    spans.push(sep);
                    spans.push(Span::styled(uptime, p.text));
                } else {
                    let rem = w.saturating_sub(head_len + 3 + 3 + uptime.len());
                    if rem > 0 {
                        spans.push(sep.clone());
                        spans.push(Span::styled(truncate_chars(&primary, rem), p.text));
                        spans.push(sep);
                        spans.push(Span::styled(uptime, p.text));
                    } else if w >= head_len + 3 + uptime.len() {
                        spans.push(sep);
                        spans.push(Span::styled(uptime, p.text));
                    }
                }
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
                .map(|provider| {
                    if p.color {
                        format!("[VPN: {provider}]")
                    } else {
                        format!("! [VPN: {provider}]")
                    }
                });

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
                + dns_full_len
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
                + dns_full_len
                + 3
                + uptime.len();
            let compact_dns_len = head_len
                + 3
                + "TUN ".len()
                + iface_chars
                + vpn_extra
                + 3
                + mode.len()
                + 1
                + dns_full_len
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
                + dns_short_len
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
                spans.push(Span::styled(format!("{mode} · {dns_full}"), p.text));
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
                spans.push(Span::styled(format!("{mode}/{dns_full}"), p.label));
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            } else if has_custom_dns_tag && w >= compact_dns_len {
                spans.push(sep.clone());
                spans.push(Span::styled("TUN ", p.label));
                spans.push(Span::styled(iface.to_string(), p.text));
                if let Some(badge) = vpn_badge {
                    spans.push(sep.clone());
                    spans.push(Span::styled(badge, p.amber));
                }
                spans.push(sep.clone());
                spans.push(Span::styled(format!("{mode}/{dns_full}"), p.label));
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
                spans.push(Span::styled(format!("{mode}/{dns_short}"), p.label));
                spans.push(sep);
                spans.push(Span::styled(uptime, p.text));
            } else {
                let base_len = head_len + 3 + "TUN ".len() + iface_chars + 3 + uptime.len();
                if w >= base_len {
                    spans.push(sep.clone());
                    spans.push(Span::styled("TUN ", p.label));
                    spans.push(Span::styled(iface.to_string(), p.text));
                    if let Some(full_badge) = vpn_badge {
                        let compact_badge = if p.color { "[VPN]" } else { "! [VPN]" };
                        let full_with_badge = base_len + 3 + full_badge.chars().count();
                        let compact_with_badge = base_len + 3 + compact_badge.len();
                        let chosen_badge = if w >= full_with_badge {
                            Some(full_badge)
                        } else if w >= compact_with_badge {
                            Some(compact_badge.to_string())
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
                } else {
                    let rem = w.saturating_sub(head_len + 3 + "TUN ".len() + 3 + uptime.len());
                    if rem > 0 {
                        spans.push(sep.clone());
                        spans.push(Span::styled("TUN ", p.label));
                        spans.push(Span::styled(truncate_chars(iface, rem), p.text));
                        spans.push(sep);
                        spans.push(Span::styled(uptime, p.text));
                    } else if w >= head_len + 3 + uptime.len() {
                        spans.push(sep);
                        spans.push(Span::styled(uptime, p.text));
                    }
                }
            }
        }
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), inner);
}

fn format_isp_stage_bottom_title(
    isp_stage: Option<&str>,
    avail: usize,
    p: Palette,
) -> Option<Line<'static>> {
    let stage = isp_stage.map(str::trim).filter(|s| !s.is_empty())?;
    let full_len = " ISP Stage ".len() + stage.chars().count() + 1;
    let short_len = " Stage ".len() + stage.chars().count() + 1;
    if full_len <= avail {
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
    }
}

fn render_stats_panel(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &DashboardState,
    show_isp_stage_bottom: bool,
) {
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
    if show_isp_stage_bottom {
        if let Some(line) = format_isp_stage_bottom_title(state.isp_stage.as_deref(), avail, p) {
            block = block.title_bottom(line.left_aligned());
        }
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
            let heal_val = if !p.color && snap.auto_heal_escalations > 0 {
                format!("! {}", snap.auto_heal_escalations)
            } else {
                snap.auto_heal_escalations.to_string()
            };
            [
                ("Download", download_val, p.text),
                ("Upload", upload_val, p.text),
                (
                    "Connections",
                    format!("{} / {}", snap.active_connections, snap.total_connections),
                    p.text,
                ),
                ("TLS Handshakes", snap.tls_handshakes.to_string(), p.text),
                ("Auto-Heal", heal_val, heal_style),
                ("Cached Hosts", snap.learned_hosts.to_string(), p.text),
                ("Proxy", proxy_val.to_string(), proxy_style),
            ]
        }
        DashboardEngine::Tun {
            interface,
            physical_nic,
            vpn_conflict,
        } => {
            let has_vpn_conflict = vpn_conflict
                .as_deref()
                .map(str::trim)
                .is_some_and(|s| !s.is_empty());
            let base_iface = match physical_nic
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(nic) => format!("{interface} ({nic})"),
                None => interface.clone(),
            };
            let iface_val = if !p.color && has_vpn_conflict {
                format!("! {base_iface}")
            } else {
                base_iface
            };
            let iface_style = if has_vpn_conflict {
                p.amber
            } else {
                p.emerald
            };
            let tls_heal_val = if !p.color && snap.auto_heal_escalations > 0 {
                format!("{} / ! {}", snap.tls_handshakes, snap.auto_heal_escalations)
            } else {
                format!("{} / {}", snap.tls_handshakes, snap.auto_heal_escalations)
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
                    if effective_dashboard_doh(
                        state.info.dns_addr.as_deref(),
                        state.info.enable_doh,
                    ) {
                        "DoH Queries"
                    } else {
                        "DNS Queries"
                    },
                    snap.dns_queries.to_string(),
                    p.text,
                ),
                ("TLS / Heal", tls_heal_val, heal_style),
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
    if area.height < 3 {
        return;
    }
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
    if let Some(line) = format_isp_stage_bottom_title(state.isp_stage.as_deref(), avail, p) {
        block = block.title_bottom(line.left_aligned());
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

    let avail = area.width.saturating_sub(2) as usize;
    let left_title = if avail >= " Activity Log ".len() {
        Some(" Activity Log ")
    } else if avail >= " Logs ".len() {
        Some(" Logs ")
    } else {
        None
    };
    let left_len = left_title.map_or(0, |t| t.chars().count());
    let min_gap = usize::from(left_len > 0);

    let status_badge = if !state.follow_logs && total > state.log_viewport_rows {
        let end_idx = (start + state.log_viewport_rows).min(total);
        let full = format!(" paused · {end_idx}/{total} ");
        let compact = format!(" {end_idx}/{total} ");
        if left_len + min_gap + full.chars().count() <= avail {
            Some(Line::from(full).style(p.amber).right_aligned())
        } else if left_len + min_gap + compact.chars().count() <= avail {
            Some(Line::from(compact).style(p.amber).right_aligned())
        } else {
            None
        }
    } else {
        let full = format!(" {total}/{MAX_LOG_ENTRIES} ");
        (left_len + min_gap + full.chars().count() <= avail)
            .then(|| Line::from(full).style(p.dim).right_aligned())
    };

    let mut block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1));
    if let Some(left) = left_title {
        block = block.title_top(Line::from(left).style(p.title).left_aligned());
    }
    if let Some(badge) = status_badge {
        block = block.title_top(badge);
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if inner.width == 0 || inner.height == 0 {
        return;
    }

    if visible_entries.is_empty() {
        let empty = Line::from(Span::styled(
            truncate_chars("Waiting for engine activity...", inner.width as usize),
            p.dim,
        ));
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

    let (legend_area, notice_slot) = if let Some((notice, kind, _)) = &state.notice {
        let raw_notice = if *kind == NoticeKind::Warn && !p.color && !notice.starts_with("! ") {
            format!("! {notice}")
        } else {
            notice.clone()
        };
        let desired_width = raw_notice.chars().count().saturating_add(1) as u16;
        let notice_width = desired_width.min(area.width / 2);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(notice_width)])
            .split(area);
        let avail = usize::from(cols[1].width);
        let display = if avail == 0 {
            String::new()
        } else if avail == 1 {
            truncate_chars(&raw_notice, 1)
        } else {
            format!("{} ", truncate_chars(&raw_notice, avail - 1))
        };
        (cols[0], Some((cols[1], display, *kind)))
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
    if let Some((notice_area, notice_text, kind)) = notice_slot {
        if !notice_text.is_empty() {
            let style = match kind {
                NoticeKind::Info => p.emerald,
                NoticeKind::Warn => p.amber,
            };
            frame.render_widget(
                Paragraph::new(Line::from(notice_text).style(style).right_aligned()),
                notice_area,
            );
        }
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

    let avail = popup.width.saturating_sub(2) as usize;
    let left_title = if avail >= " Diagnostics ".len() {
        Some(" Diagnostics ")
    } else if avail >= " Diag ".len() {
        Some(" Diag ")
    } else {
        None
    };
    let left_len = left_title.map_or(0, |t| t.chars().count());
    let min_gap = usize::from(left_len > 0);
    let running = state.diagnostics_running();
    let right_title = if running {
        [" esc close ", " esc "]
    } else {
        [" r re-run · esc close ", " r · esc "]
    }
    .into_iter()
    .find(|candidate| left_len + min_gap + candidate.chars().count() <= avail);

    let mut block = Block::bordered()
        .border_type(p.border_type)
        .border_style(p.border)
        .padding(Padding::horizontal(1));
    if let Some(left) = left_title {
        block = block.title_top(Line::from(left).style(p.title).left_aligned());
    }
    if let Some(right) = right_title {
        block = block.title_top(Line::from(right).style(p.dim).right_aligned());
    }
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
        let label = format!("{:<target_w$}", truncate_chars(&row.label, target_w));
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

const MAX_DASHBOARD_DNS_HOST_CHARS: usize = 24;

fn is_doh_url(addr: &str) -> bool {
    let trimmed = addr.trim();
    trimmed
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn is_valid_doh_url(addr: &str) -> bool {
    let trimmed = addr.trim();
    is_doh_url(trimmed) && vdpi_core::dns::is_effective_doh_target(trimmed, false)
}

fn parse_known_doh_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("://") {
        return None;
    }
    if !vdpi_core::dns::is_effective_doh_target(trimmed, true) {
        return None;
    }
    if trimmed.starts_with('[') || trimmed.ends_with(']') {
        trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
            .map(IpAddr::V6)
    } else {
        trimmed.parse::<IpAddr>().ok()
    }
}

fn known_doh_ip_provider_name(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [1, 1, 1, 1..=3] | [1, 0, 0, 1..=3] => Some("Cloudflare"),
            [8, 8, 8, 8] | [8, 8, 4, 4] => Some("Google"),
            [9, 9, 9, 9] | [149, 112, 112, 112] => Some("Quad9"),
            [94, 140, 14, 14 | 15 | 140 | 141] | [94, 140, 15, 15 | 16] => Some("AdGuard"),
            _ => None,
        },
        IpAddr::V6(v6) => match v6.segments() {
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 | 0x1001 | 0x1112 | 0x1002 | 0x1113 | 0x1003] => {
                Some("Cloudflare")
            }
            [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 | 0x8844] => Some("Google"),
            [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe | 0x0009] => Some("Quad9"),
            [0x2a10, 0x50c0, 0, 0, 0, 0, 0x0ad1 | 0x0ad2 | 0xbad1 | 0xbad2 | 0x0001 | 0x0002, 0x00ff] => {
                Some("AdGuard")
            }
            _ => None,
        },
    }
}

fn effective_dashboard_doh(dns_addr: Option<&str>, enable_doh: bool) -> bool {
    match dns_addr.map(str::trim).filter(|s| !s.is_empty()) {
        Some(addr) => vdpi_core::dns::is_effective_doh_target(addr, enable_doh),
        None => enable_doh,
    }
}

fn extract_redacted_doh_host(redacted: &str) -> &str {
    let trimmed = redacted.trim();
    let without_scheme = trimmed
        .get(..8)
        .filter(|prefix| prefix.eq_ignore_ascii_case("https://"))
        .map(|_| &trimmed[8..])
        .unwrap_or(trimmed);
    let authority = without_scheme
        .split(['/', '?', '#'])
        .next()
        .map(str::trim)
        .unwrap_or("");
    authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .trim()
}

fn diagnostics_dns_row_label(dns_addr: Option<&str>, enable_doh: bool) -> String {
    let trimmed = dns_addr.map(str::trim).filter(|s| !s.is_empty());
    if let Some(raw) = trimmed.filter(|s| is_valid_doh_url(s)) {
        let redacted = vdpi_core::dns::redact_dns_for_display(raw);
        let host = extract_redacted_doh_host(&redacted);
        if !host.is_empty() {
            return format!("{host} / DoH");
        }
    }
    if !effective_dashboard_doh(trimmed, enable_doh) {
        return "UDP DNS Resolution".to_string();
    }
    if let Some(ip) = trimmed.and_then(parse_known_doh_ip) {
        if let Some(provider) = known_doh_ip_provider_name(ip) {
            return format!("{provider} DoH ({ip})");
        }
        return format!("DoH DNS ({ip})");
    }
    "Cloudflare DoH (1.1.1.1)".to_string()
}

fn format_dashboard_dns_tag(dns_addr: Option<&str>, enable_doh: bool) -> (String, &'static str) {
    let trimmed = dns_addr.map(str::trim).filter(|s| !s.is_empty());
    let valid_doh_url = trimmed.is_some_and(is_valid_doh_url);
    let short = if effective_dashboard_doh(trimmed, enable_doh) {
        "DoH"
    } else {
        "UDP"
    };
    let Some(raw) = trimmed else {
        return (short.to_string(), short);
    };
    if raw == "1.1.1.1" {
        return (short.to_string(), short);
    }
    let redacted = vdpi_core::dns::redact_dns_for_display(raw);
    if valid_doh_url {
        let host = extract_redacted_doh_host(&redacted);
        let compact = truncate_chars(host, MAX_DASHBOARD_DNS_HOST_CHARS);
        if compact.is_empty() {
            return ("DoH".to_string(), "DoH");
        }
        return (format!("DoH ({compact})"), "DoH");
    }
    let compact = truncate_chars(&redacted, MAX_DASHBOARD_DNS_HOST_CHARS);
    if compact.is_empty() {
        return (short.to_string(), short);
    }
    (format!("{short} ({compact})"), short)
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
            dns_addr: None,
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
            dns_addr: None,
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
            assert!(
                !screen.contains("r re-run") && !screen.contains("r ·"),
                "running modal must hide dead re-run hint at {w}x{h}:\n{screen}"
            );
            assert!(screen.contains("esc close"));
            assert!(screen.contains("discord.com"));
            assert!(screen.contains("gateway.discord.gg"));
            assert!(screen.contains("www.roblox.com"));
            assert!(screen.contains("PASS"));
            assert!(screen.contains("FAIL"));
            assert!(screen.contains("Running..."));
            assert!(screen.contains("19 ms"));
        }

        // Once all probes complete, the modal top border advertises 'r re-run · esc close'.
        state.diagnostics.lock().unwrap().rows[2].status = ProbeStatus::Pass {
            latency_ms: 31,
            detail: "162.159.135.234".to_string(),
        };
        for (w, h) in [(100u16, 30u16), (60u16, 22u16)] {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| render_dashboard(frame, &mut state))
                .unwrap();

            let screen = buffer_to_string(terminal.backend());
            assert!(screen.contains("r re-run · esc close"));
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

        // Open diagnostics modal -> r is ignored while running; once done r re-runs; Esc closes it without quitting.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('d'))),
            KeyAction::RunDiagnostics
        );
        assert!(state.diagnostics_open);
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::None
        );
        for row in &mut state.diagnostics.lock().unwrap().rows {
            row.status = ProbeStatus::Pass {
                latency_ms: 10,
                detail: "ok".to_string(),
            };
        }
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

        // 46x18 (bh == 14) drops the sparkline instead of drawing a 2-row empty border seam
        // and gives those 2 rows to the Activity Log (3 visible log rows).
        let narrow_18_backend = TestBackend::new(46, 18);
        let mut narrow_18_terminal = Terminal::new(narrow_18_backend).unwrap();
        narrow_18_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let narrow_18_screen = buffer_to_string(narrow_18_terminal.backend());
        assert!(
            !narrow_18_screen.contains("Throughput"),
            "46x18 must omit empty sparkline border seam:\n{narrow_18_screen}"
        );
        assert_eq!(state.log_viewport_rows, 3);

        // 46x19 (bh == 15) gives the sparkline 3 rows (1 inner bar row) and renders compact pk title cleanly.
        let narrow_backend = TestBackend::new(46, 19);
        let mut narrow_terminal = Terminal::new(narrow_backend).unwrap();
        narrow_terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let narrow_screen = buffer_to_string(narrow_terminal.backend());
        let narrow_row = narrow_screen
            .lines()
            .find(|line| line.contains(" Throughput "))
            .expect("46x19 sparkline border row");
        assert!(
            narrow_row.contains(" Throughput ─"),
            "46x19 sparkline left title collided: {narrow_row}"
        );
        assert!(
            narrow_row.contains(" 1023.9 KB/s · pk 1023.9 KB/s "),
            "46x19 sparkline should render compact pk title cleanly: {narrow_row}"
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

        // 46x18: latencies remain unclipped, Detail column is hidden, and running modal hides 'r re-run'.
        let backend_46 = TestBackend::new(46, 18);
        let mut term_46 = Terminal::new(backend_46).unwrap();
        term_46
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen_46 = buffer_to_string(term_46.backend());
        assert!(screen_46.contains("Diagnostics"));
        assert!(screen_46.contains("esc close"));
        assert!(
            !screen_46.contains("r re-run") && !screen_46.contains("r ·"),
            "46x18 running modal must hide dead re-run hint:\n{screen_46}"
        );
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
                dns_addr: None,
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

        // While modal is open and probes are still running, 'r' is ignored.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::None
        );

        // Once all probes complete, 'r' re-runs diagnostics and 'Esc' closes modal without quitting.
        for row in &mut state.diagnostics.lock().unwrap().rows {
            row.status = ProbeStatus::Pass {
                latency_ms: 12,
                detail: "ok".to_string(),
            };
        }
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
            dns_addr: None,
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

    #[test]
    fn renders_long_custom_doh_urls_without_breaking_borders_from_46x18_to_80x24() {
        assert_eq!(
            format_dashboard_dns_tag(Some("1.1.1.1"), true),
            ("DoH".to_string(), "DoH")
        );
        assert_eq!(
            format_dashboard_dns_tag(Some("https://dns.nextdns.io/abc123/my-profile"), true),
            ("DoH (dns.nextdns.io)".to_string(), "DoH")
        );
        let ultra_long_doh =
            "https://very-long-custom-doh-resolver-subdomain.enterprise.example.com/abc123/my-profile?token=secret";
        let (ultra_full, ultra_short) = format_dashboard_dns_tag(Some(ultra_long_doh), true);
        assert_eq!(ultra_short, "DoH");
        assert!(ultra_full.starts_with("DoH ("));
        assert!(ultra_full.ends_with("…)"));
        assert!(!ultra_full.contains("abc123"));
        assert!(!ultra_full.contains("secret"));

        for doh_url in ["https://dns.nextdns.io/abc123/my-profile", ultra_long_doh] {
            for is_tun in [false, true] {
                for (w, h) in [(46u16, 18u16), (60, 22), (72, 24), (80, 24), (100, 30)] {
                    let mut state = if is_tun {
                        sample_tun_state(true, None)
                    } else {
                        sample_state(true)
                    };
                    state.info.dns_addr = Some(doh_url.to_string());
                    push_log_entry(
                        &state.logs,
                        LogEntry {
                            timestamp: "12:00:05".to_string(),
                            level: Level::INFO,
                            message: format!("upstream DoH configured: {doh_url}"),
                        },
                    );

                    let backend = TestBackend::new(w, h);
                    let mut terminal = Terminal::new(backend).unwrap();
                    terminal
                        .draw(|frame| render_dashboard(frame, &mut state))
                        .unwrap();

                    let buf = terminal.backend().buffer();
                    assert_eq!(
                        buf[(0, 0)].symbol(),
                        "╭",
                        "top-left border broken at {w}x{h} (tun={is_tun})"
                    );
                    assert_eq!(
                        buf[(w - 1, 0)].symbol(),
                        "╮",
                        "top-right border broken at {w}x{h} (tun={is_tun})"
                    );
                    assert_eq!(
                        buf[(0, 1)].symbol(),
                        "│",
                        "status bar left border broken at {w}x{h} (tun={is_tun})"
                    );
                    assert_eq!(
                        buf[(w - 1, 1)].symbol(),
                        "│",
                        "status bar right border clipped at {w}x{h} (tun={is_tun})"
                    );
                    assert_eq!(
                        buf[(0, 2)].symbol(),
                        "╰",
                        "status bar bottom-left border broken at {w}x{h} (tun={is_tun})"
                    );
                    assert_eq!(
                        buf[(w - 1, 2)].symbol(),
                        "╯",
                        "status bar bottom-right border broken at {w}x{h} (tun={is_tun})"
                    );

                    let status_line: String = (0..w).map(|x| buf[(x, 1)].symbol()).collect();
                    assert!(
                        !status_line.contains("/abc123/my-profile"),
                        "raw custom DoH path leaked into status bar at {w}x{h}: {status_line}"
                    );
                    if doh_url == "https://dns.nextdns.io/abc123/my-profile" && w >= 80 {
                        assert!(
                            status_line.contains("DoH (dns.nextdns.io)"),
                            "expected compact custom DoH host at {w}x{h} (tun={is_tun}): {status_line}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn attached_dns_clear_restart_uptime_warn_notice_and_offline_diagnostics() {
        let t0 = Instant::now();
        let logs = new_log_ring();
        let mut initial_info = sample_info();
        initial_info.dns_addr = Some("9.9.9.9".to_string());
        let initial_snap = EngineTelemetrySnapshot {
            bytes_rx: 100_000,
            bytes_tx: 50_000,
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
        assert_eq!(state.info.dns_addr.as_deref(), Some("9.9.9.9"));

        // Reconnecting hides uptime and blocks 'd' diagnostics with offline action.
        let t1 = t0 + Duration::from_secs(5);
        state.mark_reconnecting(t1);
        state.set_notice_warn("Daemon unreachable", t1);
        assert_eq!(
            handle_key_event(&mut state, KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE)),
            KeyAction::DiagnosticsOffline
        );
        assert!(!state.diagnostics_open);

        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        let status_line = screen.lines().nth(1).unwrap();
        assert!(status_line.contains("Reconnecting…"));
        assert!(
            !status_line.contains("Uptime") && !status_line.contains("00:"),
            "uptime must be hidden while reconnecting: {status_line}"
        );
        let buf = terminal.backend().buffer();
        let footer_y = 23u16;
        let warn_x = (0..80u16)
            .find(|&x| {
                buf[(x, footer_y)].symbol() == "D"
                    && x + 5 < 80
                    && buf[(x + 1, footer_y)].symbol() == "a"
                    && buf[(x + 2, footer_y)].symbol() == "e"
            })
            .expect("Daemon unreachable warn notice in footer");
        assert_eq!(buf[(warn_x, footer_y)].fg, AMBER_WARN);

        // Long warn notice truncates cleanly on narrow width without overflowing footer.
        state.set_notice_warn("Daemon unreachable on loopback health port", t1);
        let narrow_backend = TestBackend::new(36, 18);
        let mut narrow_term = Terminal::new(narrow_backend).unwrap();
        narrow_term
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let narrow_screen = buffer_to_string(narrow_term.backend());
        let narrow_footer = narrow_screen.lines().nth(17).unwrap();
        assert!(narrow_footer.contains("q back"));
        assert!(narrow_footer.contains('…'));

        // Reconnecting with counter reset resets started_at and clears custom dns_addr to None.
        let t2 = t1 + Duration::from_secs(10);
        let reset_sample = AttachedTelemetry {
            snap: EngineTelemetrySnapshot {
                bytes_rx: 1_024,
                bytes_tx: 512,
                ..Default::default()
            },
            engine: sample_info().engine,
            mode: DesyncMode::Combo,
            doh: true,
            dns_addr: None,
            block_quic: true,
            rss_kb: Some(20 * 1024),
            isp_stage: None,
            version: Some("0.5.6".to_string()),
        };
        tracker.on_sample(&state, &reset_sample, t2);
        state.apply_attached_sample(reset_sample, t2);
        assert_eq!(state.started_at, t2);
        assert_eq!(state.info.dns_addr, None);
        let messages: Vec<String> = logs
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.message.clone())
            .collect();
        assert!(
            messages
                .iter()
                .any(|m| m.contains("DNS server reset to default")),
            "expected DNS reset log entry, got: {messages:?}"
        );
    }

    #[test]
    fn small_terminals_preserve_footer_key_stats_and_avoid_title_collisions() {
        let mut state = sample_state(true);
        for i in 0..20 {
            push_log_entry(
                &state.logs,
                LogEntry {
                    timestamp: "12:00:05".to_string(),
                    level: Level::INFO,
                    message: format!("log-{i}"),
                },
            );
        }
        state.follow_logs = false;
        state.log_scroll = 0;

        // 60x20 shows all 7 stats rows, sparkline, activity log, and footer.
        let backend_60_20 = TestBackend::new(60, 20);
        let mut term_60_20 = Terminal::new(backend_60_20).unwrap();
        term_60_20
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen_60_20 = buffer_to_string(term_60_20.backend());
        assert!(screen_60_20.contains("Download"));
        assert!(screen_60_20.contains("Proxy"));
        assert!(screen_60_20.contains("Activity Log"));
        assert!(screen_60_20.lines().nth(19).unwrap().contains("q quit"));

        // Very short terminals still preserve footer and key stats rows without panicking.
        for (w, h) in [(46u16, 18u16), (46, 14), (46, 12), (28, 12), (80, 10)] {
            let backend = TestBackend::new(w, h);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|frame| render_dashboard(frame, &mut state))
                .unwrap();
            let screen = buffer_to_string(term.backend());
            let footer_line = screen.lines().nth(usize::from(h - 1)).unwrap();
            assert!(
                footer_line.contains("q quit"),
                "footer vanished at {w}x{h}:\n{screen}"
            );
            assert!(
                screen.contains("Download") && screen.contains("Upload"),
                "key stats rows vanished at {w}x{h}:\n{screen}"
            );
        }

        // Narrow diagnostics modal adapts top titles without colliding.
        state.diagnostics_open = true;
        for (w, h) in [(34u16, 16u16), (26, 14)] {
            let backend = TestBackend::new(w, h);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|frame| render_dashboard(frame, &mut state))
                .unwrap();
            let screen = buffer_to_string(term.backend());
            assert!(screen.contains("Diagnostics"));
        }
    }

    #[test]
    fn no_color_warning_markers_and_key_repeat_and_uppercase_scroll() {
        // Proxy NO_COLOR Auto-Heal > 0 marker
        let mut proxy_nc = sample_state(false);
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|frame| render_dashboard(frame, &mut proxy_nc))
            .unwrap();
        let screen = buffer_to_string(term.backend());
        assert!(screen.contains("! 2"), "expected NO_COLOR Auto-Heal ! marker:\n{screen}");

        // TUN NO_COLOR VPN conflict & TLS / Heal ! markers
        let mut tun_nc = sample_tun_state(false, Some("WireGuard"));
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|frame| render_dashboard(frame, &mut tun_nc))
            .unwrap();
        let screen = buffer_to_string(term.backend());
        assert!(screen.contains("! [VPN: WireGuard]"));
        assert!(screen.contains("28 / ! 2"));
        assert!(screen.contains("! vdpi0 (Ethernet)"));

        // Attached reconnecting NO_COLOR ! marker
        let mut rec_nc = sample_attached_state(false, true, false);
        let backend = TestBackend::new(60, 20);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|frame| render_dashboard(frame, &mut rec_nc))
            .unwrap();
        let screen = buffer_to_string(term.backend());
        assert!(screen.contains("! Reconnecting…"));

        // Ctrl+C Repeat ignored, Press quits; uppercase J/K scroll
        let mut key_state = sample_state(true);
        for i in 0..15 {
            push_log_entry(
                &key_state.logs,
                LogEntry {
                    timestamp: "12:00:00".to_string(),
                    level: Level::INFO,
                    message: format!("m-{i}"),
                },
            );
        }
        key_state.log_viewport_rows = 5;
        assert_eq!(
            handle_key_event(
                &mut key_state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('c'),
                    KeyModifiers::CONTROL,
                    KeyEventKind::Repeat,
                ),
            ),
            KeyAction::None
        );
        assert_eq!(
            handle_key_event(
                &mut key_state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('K'),
                    KeyModifiers::SHIFT,
                    KeyEventKind::Press,
                ),
            ),
            KeyAction::Redraw
        );
        assert!(!key_state.follow_logs);
        assert_eq!(
            handle_key_event(
                &mut key_state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('J'),
                    KeyModifiers::SHIFT,
                    KeyEventKind::Press,
                ),
            ),
            KeyAction::Redraw
        );
        assert!(key_state.follow_logs);
    }

    #[test]
    fn diagnostics_modal_ignores_r_mash_while_probes_running() {
        let mut state = sample_state(true);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let shift_r = KeyEvent::new_with_kind(
            KeyCode::Char('R'),
            KeyModifiers::SHIFT,
            KeyEventKind::Press,
        );

        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('d'))),
            KeyAction::RunDiagnostics
        );
        assert!(state.diagnostics_open);

        // All 4 rows running -> both 'r' and 'R' are ignored.
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::None
        );
        assert_eq!(handle_key_event(&mut state, shift_r), KeyAction::None);

        // Partial completion (3 done, 1 still running) -> still ignored.
        {
            let mut diag = state.diagnostics.lock().unwrap();
            diag.rows[0].status = ProbeStatus::Pass {
                latency_ms: 15,
                detail: "DoH HTTP 200".to_string(),
            };
            diag.rows[1].status = ProbeStatus::Pass {
                latency_ms: 21,
                detail: "ok".to_string(),
            };
            diag.rows[2].status = ProbeStatus::Fail {
                latency_ms: 4000,
                reason: "timed out".to_string(),
            };
            diag.rows[3].status = ProbeStatus::Running;
        }
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::None
        );
        assert_eq!(handle_key_event(&mut state, shift_r), KeyAction::None);

        // Once all 4 probes finish (even with failures), 'r' and 'R' trigger a re-run.
        {
            let mut diag = state.diagnostics.lock().unwrap();
            diag.rows[3].status = ProbeStatus::Fail {
                latency_ms: 3500,
                reason: "reset".to_string(),
            };
        }
        assert_eq!(
            handle_key_event(&mut state, press(KeyCode::Char('r'))),
            KeyAction::RunDiagnostics
        );
        assert_eq!(
            handle_key_event(&mut state, shift_r),
            KeyAction::RunDiagnostics
        );
    }

    #[test]
    fn custom_doh_redaction_effective_doh_and_diagnostics_probe_target() {
        let secret_doh = "https://user:secret@dns.nextdns.io/abc123/my-profile?token=xyz";
        let valid_custom_doh = "https://dns.nextdns.io/abc123/my-profile?token=secret";

        // Status bar tag redacts path and query for valid custom DoH URLs.
        assert_eq!(
            format_dashboard_dns_tag(Some(valid_custom_doh), false),
            ("DoH (dns.nextdns.io)".to_string(), "DoH")
        );
        assert_eq!(
            format_dashboard_dns_tag(Some("https://dns.quad9.net:8443/dns-query?k=v"), false),
            ("DoH (dns.quad9.net:8443)".to_string(), "DoH")
        );
        // Malformed https:// URLs (empty host, missing host, userinfo) must NOT be treated as DoH
        // and must never leak secrets.
        for malformed in ["https://", "https:///secret-token", secret_doh] {
            let (tag, short) = format_dashboard_dns_tag(Some(malformed), false);
            assert_eq!(short, "UDP", "malformed URL must not be DoH: {malformed}");
            assert!(
                tag.starts_with("UDP ("),
                "expected UDP tag for malformed URL {malformed}, got {tag:?}"
            );
            for leaked in ["user", "secret", "abc123", "my-profile", "token", "xyz"] {
                assert!(
                    !tag.contains(leaked),
                    "malformed URL tag leaked {leaked:?}: {tag:?}"
                );
            }
            assert_eq!(
                diagnostics_dns_row_label(Some(malformed), true),
                "UDP DNS Resolution",
                "malformed URL diagnostics row 0 must not claim DoH: {malformed}"
            );
        }

        // DashboardInfo Debug impl redacts userinfo/path/query.
        let mut info = sample_info();
        info.enable_doh = false;
        info.dns_addr = Some(secret_doh.to_string());
        let debug_out = format!("{info:?}");
        assert!(debug_out.contains("dns.nextdns.io"), "debug output: {debug_out}");
        for leaked in ["user", "secret", "abc123", "my-profile", "token", "xyz"] {
            assert!(
                !debug_out.contains(leaked),
                "DashboardInfo Debug leaked '{leaked}': {debug_out}"
            );
        }

        // Status bar rendering never leaks path or query for valid custom DoH URLs.
        let mut state = sample_state(true);
        state.info.enable_doh = false;
        state.info.dns_addr = Some(valid_custom_doh.to_string());
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let screen = buffer_to_string(terminal.backend());
        assert!(screen.contains("DoH (dns.nextdns.io)"));
        for leaked in ["user", "secret", "abc123", "my-profile", "token", "xyz"] {
            assert!(
                !screen.contains(leaked),
                "status bar leaked '{leaked}':\n{screen}"
            );
        }

        // AttachedActivityTracker treats https:// dns_addr as effective DoH=true (no bogus DoH -> UDP).
        let t0 = Instant::now();
        let logs = new_log_ring();
        let initial_info = sample_info();
        let initial_snap = EngineTelemetrySnapshot::default();
        let mut tracker = AttachedActivityTracker::new(
            Arc::clone(&logs),
            &initial_info,
            initial_snap,
            None,
        );
        let mut attached = DashboardState::new_attached(
            initial_info,
            initial_snap,
            None,
            None,
            Arc::clone(&logs),
            true,
            t0,
        );
        let custom_sample = AttachedTelemetry {
            snap: initial_snap,
            engine: sample_info().engine,
            mode: DesyncMode::Combo,
            doh: false,
            dns_addr: Some(valid_custom_doh.to_string()),
            block_quic: true,
            rss_kb: None,
            isp_stage: None,
            version: None,
        };
        let t1 = t0 + Duration::from_secs(1);
        tracker.on_sample(&attached, &custom_sample, t1);
        attached.apply_attached_sample(custom_sample, t1);

        let messages: Vec<String> = logs
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.message.clone())
            .collect();
        assert!(
            !messages
                .iter()
                .any(|m| m.contains("DNS transport changed: DoH -> UDP")),
            "unexpected bogus DoH -> UDP transition log: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|m| m.contains("DNS server set: DoH (dns.nextdns.io)")),
            "expected redacted custom DoH set log, got: {messages:?}"
        );
        assert!(
            !messages
                .iter()
                .any(|m| m.contains("abc123") || m.contains("secret")),
            "activity log leaked custom DoH path/query: {messages:?}"
        );

        // Diagnostics row 0 label shows active redacted custom DoH host, provider/IP label for
        // known public DoH IPs, UDP DNS Resolution when effective DoH is off (bare non-DoH IP,
        // malformed https://, or --no-doh), and Cloudflare DoH (1.1.1.1) by default.
        assert_eq!(
            diagnostics_dns_row_label(None, true),
            "Cloudflare DoH (1.1.1.1)"
        );
        assert_eq!(diagnostics_dns_row_label(None, false), "UDP DNS Resolution");
        assert_eq!(
            diagnostics_dns_row_label(Some("1.1.1.1"), true),
            "Cloudflare DoH (1.1.1.1)"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("1.1.1.1"), false),
            "UDP DNS Resolution"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("9.9.9.9"), true),
            "Quad9 DoH (9.9.9.9)"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("8.8.8.8"), true),
            "Google DoH (8.8.8.8)"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("94.140.14.14"), true),
            "AdGuard DoH (94.140.14.14)"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("2620:fe::fe"), true),
            "Quad9 DoH (2620:fe::fe)"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("9.9.9.9"), false),
            "UDP DNS Resolution"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("76.76.2.0"), true),
            "UDP DNS Resolution"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some("10.0.0.53"), true),
            "UDP DNS Resolution"
        );
        assert_eq!(
            diagnostics_dns_row_label(Some(valid_custom_doh), false),
            "dns.nextdns.io / DoH"
        );
        let _ = state.begin_diagnostics_run();
        state.diagnostics_open = true;
        let modal_backend = TestBackend::new(80, 24);
        let mut modal_term = Terminal::new(modal_backend).unwrap();
        modal_term
            .draw(|frame| render_dashboard(frame, &mut state))
            .unwrap();
        let modal_screen = buffer_to_string(modal_term.backend());
        assert!(
            modal_screen.contains("dns.nextdns.io / DoH"),
            "expected custom DoH host in diagnostics row 0:\n{modal_screen}"
        );
        assert!(!modal_screen.contains("abc123"));
        assert!(!modal_screen.contains("secret"));

        // TUN DoH probe URL resolution targets configured custom https:// DoH endpoint or
        // known public DoH IP (never hardcoding 1.1.1.1 for Quad9/Google/AdGuard), and ignores
        // malformed https:// URLs.
        assert_eq!(resolve_tun_doh_probe_url(None), "https://1.1.1.1/dns-query");
        assert_eq!(
            resolve_tun_doh_probe_url(Some("1.1.1.1")),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("9.9.9.9")),
            "https://9.9.9.9/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("8.8.8.8")),
            "https://8.8.8.8/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("94.140.14.14")),
            "https://94.140.14.14/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("2620:fe::fe")),
            "https://[2620:fe::fe]/dns-query"
        );
        assert_eq!(
            resolve_attached_tun_doh_probe_url(Some("9.9.9.9")),
            "https://9.9.9.9/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("https://")),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("https://dns.nextdns.io/abc123")),
            "https://dns.nextdns.io/abc123"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("https://dns.quad9.net")),
            "https://dns.quad9.net/dns-query"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("https://dns.example.com?p=1")),
            "https://dns.example.com/dns-query?p=1"
        );
        assert_eq!(
            resolve_tun_doh_probe_url(Some("https://dns.example.com/?p=1")),
            "https://dns.example.com/dns-query?p=1"
        );

        let redacted_err = redact_url_in_probe_error(
            &format!("error sending request for url ({valid_custom_doh}): timed out"),
            valid_custom_doh,
        );
        assert!(redacted_err.contains("dns.nextdns.io"));
        assert!(!redacted_err.contains("abc123"));
        assert!(!redacted_err.contains("secret"));
    }

    #[test]
    fn stacked_layout_at_46x18_displays_all_seven_stats_rows_without_clipping() {
        // Proxy mode at 46x18: all 7 stats rows visible alongside expanded Activity Log and footer,
        // without drawing an empty 2-row sparkline border seam.
        let mut proxy_state = sample_state(true);
        let backend = TestBackend::new(46, 18);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render_dashboard(frame, &mut proxy_state))
            .unwrap();
        let proxy_screen = buffer_to_string(terminal.backend());
        for expected in [
            "Download",
            "Upload",
            "Connections",
            "TLS Handshakes",
            "Auto-Heal",
            "Cached Hosts",
            "Proxy",
            "Activity Log",
            "q quit",
        ] {
            assert!(
                proxy_screen.contains(expected),
                "missing '{expected}' in 46x18 proxy layout:\n{proxy_screen}"
            );
        }
        assert!(
            !proxy_screen.contains("Throughput"),
            "46x18 proxy layout must not draw empty sparkline seam:\n{proxy_screen}"
        );
        assert_eq!(proxy_state.log_viewport_rows, 3);

        // TUN mode at 46x18 with custom https:// DoH URL & enable_doh=false: all 7 rows visible,
        // including DoH Queries (effective DoH) and Interface, with 3 Activity Log rows.
        let mut tun_state = sample_tun_state(true, None);
        tun_state.info.enable_doh = false;
        tun_state.info.dns_addr = Some("https://dns.nextdns.io/abc123".to_string());
        let tun_backend = TestBackend::new(46, 18);
        let mut tun_term = Terminal::new(tun_backend).unwrap();
        tun_term
            .draw(|frame| render_dashboard(frame, &mut tun_state))
            .unwrap();
        let tun_screen = buffer_to_string(tun_term.backend());
        for expected in [
            "Download",
            "Upload",
            "TCP / UDP",
            "QUIC Blocked",
            "DoH Queries",
            "TLS / Heal",
            "Interface",
            "Activity Log",
            "q quit",
        ] {
            assert!(
                tun_screen.contains(expected),
                "missing '{expected}' in 46x18 TUN layout:\n{tun_screen}"
            );
        }
        assert!(!tun_screen.contains("DNS Queries"));
        assert!(
            !tun_screen.contains("Throughput"),
            "46x18 TUN layout must not draw empty sparkline seam:\n{tun_screen}"
        );
        assert_eq!(tun_state.log_viewport_rows, 3);

        // At 46x19 (bh == 15), sparkline gets 3 rows (1 inner row) and renders alongside stats & log.
        let backend_19 = TestBackend::new(46, 19);
        let mut term_19 = Terminal::new(backend_19).unwrap();
        term_19
            .draw(|frame| render_dashboard(frame, &mut proxy_state))
            .unwrap();
        let screen_19 = buffer_to_string(term_19.backend());
        assert!(screen_19.contains("Throughput"));
        assert!(screen_19.contains("Proxy"));
        assert!(screen_19.contains("Activity Log"));
        assert_eq!(proxy_state.log_viewport_rows, 1);
    }

    #[test]
    fn round3_attached_tun_doh_config_lookup_error_redaction_modal_border_and_bare_ip_display() {
        // 1. Attached TUN DoH probe URL resolution recovers full path/query from matching local config
        //    when live /vdpi-health dns_addr is redacted to host-only, without cross-host matching.
        let candidates = vec![
            "https://dns.nextdns.io/abc123/my-profile".to_string(),
            "https://freedns.controld.com/p2".to_string(),
            "https://dns.quad9.net:8443/custom-path?k=v".to_string(),
            "https://[2606:4700:4700::1111]/custom-v6".to_string(),
        ];
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://freedns.controld.com"),
                candidates.as_slice(),
            ),
            "https://freedns.controld.com/p2"
        );
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://dns.nextdns.io"),
                candidates.as_slice(),
            ),
            "https://dns.nextdns.io/abc123/my-profile"
        );
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://FREEDNS.CONTROLD.COM"),
                &["https://freedns.controld.com/CaseToken"][..],
            ),
            "https://freedns.controld.com/CaseToken"
        );
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://dns.quad9.net:8443"),
                candidates.as_slice(),
            ),
            "https://dns.quad9.net:8443/custom-path?k=v"
        );
        // Port mismatch must NOT match.
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://dns.quad9.net"),
                candidates.as_slice(),
            ),
            "https://dns.quad9.net/dns-query"
        );
        // Different host must NOT match.
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://doh.mullvad.net"),
                candidates.as_slice(),
            ),
            "https://doh.mullvad.net/dns-query"
        );
        // IPv6 host matches.
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://[2606:4700:4700::1111]"),
                candidates.as_slice(),
            ),
            "https://[2606:4700:4700::1111]/custom-v6"
        );
        // Already-full live URL is kept intact instead of overwritten by config.
        assert_eq!(
            resolve_tun_doh_probe_url_with_candidates(
                Some("https://dns.nextdns.io/live-only"),
                candidates.as_slice(),
            ),
            "https://dns.nextdns.io/live-only"
        );
        // UI labels always stay host-only redacted.
        assert_eq!(
            diagnostics_dns_row_label(Some("https://freedns.controld.com"), false),
            "freedns.controld.com / DoH"
        );

        // 2. Diagnostics modal top border hides 'r re-run' / 'r ·' while running and restores when done.
        let mut diag_state = sample_state(true);
        let _ = diag_state.begin_diagnostics_run();
        diag_state.diagnostics_open = true;
        for (w, h, expected_hint) in [
            (80u16, 24u16, " esc close "),
            (46, 18, " esc close "),
            (29, 14, " esc "),
        ] {
            let backend = TestBackend::new(w, h);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|frame| render_dashboard(frame, &mut diag_state))
                .unwrap();
            let screen = buffer_to_string(term.backend());
            assert!(
                screen.contains(expected_hint),
                "expected '{expected_hint}' while running at {w}x{h}:\n{screen}"
            );
            assert!(
                !screen.contains("r re-run") && !screen.contains("r ·"),
                "running modal must not advertise dead re-run at {w}x{h}:\n{screen}"
            );
        }
        for row in &mut diag_state.diagnostics.lock().unwrap().rows {
            row.status = ProbeStatus::Pass {
                latency_ms: 14,
                detail: "ok".to_string(),
            };
        }
        for (w, h, expected_hint) in [
            (80u16, 24u16, " r re-run · esc close "),
            (46, 18, " r re-run · esc close "),
            (29, 14, " r · esc "),
        ] {
            let backend = TestBackend::new(w, h);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|frame| render_dashboard(frame, &mut diag_state))
                .unwrap();
            let screen = buffer_to_string(term.backend());
            assert!(
                screen.contains(expected_hint),
                "expected '{expected_hint}' once finished at {w}x{h}:\n{screen}"
            );
        }

        // 3. redact_url_in_probe_error uses redact_urls_in_text so case/port normalization never leaks tokens.
        let case_norm_err = redact_url_in_probe_error(
            "error sending request for url (https://dns.nextdns.io/abc123/profile?token=secret): timed out",
            "https://DNS.NEXTDNS.IO:443/abc123/profile?token=secret",
        );
        assert!(case_norm_err.contains("https://dns.nextdns.io"));
        for leaked in ["abc123", "profile", "token", "secret"] {
            assert!(
                !case_norm_err.contains(leaked),
                "probe error leaked '{leaked}': {case_norm_err}"
            );
        }
        let scheme_case_err = redact_url_in_probe_error(
            "connect failed to HTTPS://user:pw@freedns.controld.com/p2?k=v",
            "https://freedns.controld.com/p2?k=v",
        );
        assert!(scheme_case_err.contains("https://freedns.controld.com"));
        for leaked in ["user", "pw", "/p2", "k=v"] {
            assert!(
                !scheme_case_err.contains(leaked),
                "probe error leaked '{leaked}': {scheme_case_err}"
            );
        }

        // 4. Bare custom non-DoH IPs display as UDP (<ip>) and DNS Queries even when enable_doh=true.
        assert_eq!(
            format_dashboard_dns_tag(Some("76.76.2.0"), true),
            ("UDP (76.76.2.0)".to_string(), "UDP")
        );
        assert_eq!(
            format_dashboard_dns_tag(Some("10.0.0.53"), true),
            ("UDP (10.0.0.53)".to_string(), "UDP")
        );
        assert_eq!(
            format_dashboard_dns_tag(Some("9.9.9.9"), true),
            ("DoH (9.9.9.9)".to_string(), "DoH")
        );
        assert_eq!(
            format_dashboard_dns_tag(Some("9.9.9.9"), false),
            ("UDP (9.9.9.9)".to_string(), "UDP")
        );
        assert_eq!(
            format_dashboard_dns_tag(None, true),
            ("DoH".to_string(), "DoH")
        );

        let mut bare_ip_tun = sample_tun_state(true, None);
        bare_ip_tun.info.enable_doh = true;
        bare_ip_tun.info.dns_addr = Some("76.76.2.0".to_string());
        let bare_backend = TestBackend::new(100, 30);
        let mut bare_term = Terminal::new(bare_backend).unwrap();
        bare_term
            .draw(|frame| render_dashboard(frame, &mut bare_ip_tun))
            .unwrap();
        let bare_screen = buffer_to_string(bare_term.backend());
        assert!(
            bare_screen.contains("UDP (76.76.2.0)"),
            "expected UDP (76.76.2.0) in status bar:\n{bare_screen}"
        );
        assert!(
            !bare_screen.contains("DoH (76.76.2.0)"),
            "bare non-DoH IP must not be labeled DoH:\n{bare_screen}"
        );
        assert!(
            bare_screen.contains("DNS Queries") && !bare_screen.contains("DoH Queries"),
            "bare non-DoH IP must use DNS Queries label:\n{bare_screen}"
        );
        let _ = bare_ip_tun.begin_diagnostics_run();
        bare_ip_tun.diagnostics_open = true;
        let bare_modal_backend = TestBackend::new(80, 24);
        let mut bare_modal_term = Terminal::new(bare_modal_backend).unwrap();
        bare_modal_term
            .draw(|frame| render_dashboard(frame, &mut bare_ip_tun))
            .unwrap();
        let bare_modal_screen = buffer_to_string(bare_modal_term.backend());
        assert!(
            bare_modal_screen.contains("UDP DNS Resolution"),
            "bare non-DoH IP diagnostics row 0 must show UDP DNS Resolution:\n{bare_modal_screen}"
        );
        assert!(
            !bare_modal_screen.contains("1.1.1.1 / DoH DNS Ring")
                && !bare_modal_screen.contains("Cloudflare DoH"),
            "bare non-DoH IP diagnostics row 0 must not label Cloudflare DoH:\n{bare_modal_screen}"
        );

        // 5. Compact stacked heights with spark_h < 3 (46x18, 46x14) omit sparkline and expand Activity Log.
        let mut compact_state = sample_attached_state(true, false, false);
        for (w, h) in [(46u16, 18u16), (46, 14)] {
            let backend = TestBackend::new(w, h);
            let mut term = Terminal::new(backend).unwrap();
            term.draw(|frame| render_dashboard(frame, &mut compact_state))
                .unwrap();
            let screen = buffer_to_string(term.backend());
            assert!(
                !screen.contains("Throughput"),
                "{w}x{h} must omit sparkline instead of drawing empty border seam:\n{screen}"
            );
            assert!(
                screen.contains("ISP Stage ComboMultiRecord"),
                "{w}x{h} should preserve ISP Stage on stats panel bottom border:\n{screen}"
            );
            assert_eq!(compact_state.log_viewport_rows, 3);
        }
    }
}
