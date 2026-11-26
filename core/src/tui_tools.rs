//! Interactive `ratatui` screens for Software Update and Live Network Diagnostics.
//!
//! Shares the restrained cool slate / white / emerald / ice-blue / amber / red
//! visual identity, RAII terminal restoration, `NO_COLOR` compliance, and
//! responsive centered card layout used across `vdpi`.

use anyhow::{anyhow, bail, Context, Result};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use std::borrow::Cow;
use std::io::{self, IsTerminal, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use vdpi::config::{EngineMode, VpnCoexistence};
use vdpi::service::{ControlCenterStatus, ServiceState};
use vdpi::update::{compare_versions, VersionRelation};
use vdpi_core::config::RuntimeConfig;
use vdpi_core::dns::DnsResolver;

const MAX_CARD_WIDTH: u16 = 76;
const MAX_CARD_HEIGHT: u16 = 28;
const SPINNER_INTERVAL: Duration = Duration::from_millis(100);
const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const RULE: &str = "────────────────────────────────────────────────────────────────────────────";

const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest";
const RELEASE_API_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RELEASE_API_BYTES: usize = 2 * 1024 * 1024;
const DIAG_DNS_TIMEOUT: Duration = Duration::from_secs(6);
const DIAG_TLS_TIMEOUT: Duration = Duration::from_secs(8);

// Restrained cool slate / white / emerald / ice-blue / semantic amber & red palette
// matching `core/src/launcher/tui.rs` and `core/src/split_tunnel/tui.rs`.
const BORDER_SLATE: Color = Color::Rgb(58, 66, 78);
const DIVIDER_SLATE: Color = Color::Rgb(48, 55, 66);
const ACTIVE_BG: Color = Color::Rgb(28, 35, 45);
const EMERALD_ACTIVE: Color = Color::Rgb(62, 207, 142);
const ICE_BLUE: Color = Color::Rgb(110, 180, 255);
const STEEL_MUTED: Color = Color::Rgb(148, 163, 184);
const SLATE_DIM: Color = Color::Rgb(100, 116, 139);
const TEXT_WHITE: Color = Color::Rgb(248, 250, 252);
const TEXT_LIGHT: Color = Color::Rgb(203, 213, 225);
const AMBER_WARN: Color = Color::Rgb(245, 185, 90);
const RED_DANGER: Color = Color::Rgb(235, 96, 107);

static TOOLS_TUI_ACTIVE: AtomicBool = AtomicBool::new(false);
static TOOLS_PANIC_HOOK: Once = Once::new();

fn install_tools_panic_hook() {
    TOOLS_PANIC_HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if TOOLS_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let mut stdout = io::stdout();
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            prev(info);
        }));
    });
}

fn color_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
}

fn is_interactive_tty() -> bool {
    let dumb = std::env::var_os("TERM").is_some_and(|v| v == "dumb");
    io::stdin().is_terminal() && io::stdout().is_terminal() && !dumb
}

/// RAII terminal guard that enables raw mode + alternate screen and restores
/// cursor, screen, and raw mode cleanly on drop, error, or panic unwind.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        install_tools_panic_hook();
        terminal::enable_raw_mode()?;
        TOOLS_TUI_ACTIVE.store(true, Ordering::Release);
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            if TOOLS_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                if TOOLS_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                    let _ = terminal::disable_raw_mode();
                }
                return Err(err);
            }
        };
        let mut guard = Self { terminal };
        guard.terminal.clear()?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if TOOLS_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
            let _ = terminal::disable_raw_mode();
        }
    }
}

/// RAII guard for the background crossterm event polling thread.
/// Always declared after `TerminalGuard` so it stops and joins before raw mode exits.
struct EventReaderGuard {
    stop_flag: Arc<AtomicBool>,
    ev_rx: Option<mpsc::Receiver<Event>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl EventReaderGuard {
    fn spawn() -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop_flag);
        let (tx, rx) = mpsc::channel::<Event>(32);

        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match event::poll(Duration::from_millis(50)) {
                    Ok(true) => match event::read() {
                        Ok(ev) => {
                            if tx.blocking_send(ev).is_err() {
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
            stop_flag,
            ev_rx: Some(rx),
            handle: Some(handle),
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
        self.stop_flag.store(true, Ordering::Relaxed);
        self.ev_rx = None;
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Palette {
    border: Style,
    divider: Style,
    brand: Style,
    title: Style,
    label: Style,
    value: Style,
    value_muted: Style,
    emerald_bold: Style,
    ice_bold: Style,
    amber: Style,
    amber_bold: Style,
    red_bold: Style,
    section_title: Style,
    bullet_dot: Style,
    body_text: Style,
    hint: Style,
    action_bar: Style,
    action_key: Style,
    action_text: Style,
    scroll_thumb: Style,
    scroll_track: Style,
    footer_key: Style,
    footer_text: Style,
    warn_icon: &'static str,
}

impl Palette {
    const fn for_color(color: bool) -> Self {
        if color {
            Self {
                border: Style::new().fg(BORDER_SLATE),
                divider: Style::new().fg(DIVIDER_SLATE),
                brand: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                title: Style::new().fg(TEXT_LIGHT),
                label: Style::new().fg(SLATE_DIM),
                value: Style::new().fg(TEXT_WHITE),
                value_muted: Style::new().fg(STEEL_MUTED),
                emerald_bold: Style::new().fg(EMERALD_ACTIVE).add_modifier(Modifier::BOLD),
                ice_bold: Style::new().fg(ICE_BLUE).add_modifier(Modifier::BOLD),
                amber: Style::new().fg(AMBER_WARN),
                amber_bold: Style::new().fg(AMBER_WARN).add_modifier(Modifier::BOLD),
                red_bold: Style::new().fg(RED_DANGER).add_modifier(Modifier::BOLD),
                section_title: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                bullet_dot: Style::new().fg(ICE_BLUE),
                body_text: Style::new().fg(TEXT_LIGHT),
                hint: Style::new().fg(SLATE_DIM),
                action_bar: Style::new().bg(ACTIVE_BG),
                action_key: Style::new()
                    .fg(ICE_BLUE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                action_text: Style::new()
                    .fg(TEXT_WHITE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                scroll_thumb: Style::new().fg(STEEL_MUTED),
                scroll_track: Style::new().fg(DIVIDER_SLATE),
                footer_key: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                footer_text: Style::new().fg(SLATE_DIM),
                warn_icon: "▲",
            }
        } else {
            let plain = Style::new();
            let bold = Style::new().add_modifier(Modifier::BOLD);
            let dim = Style::new().add_modifier(Modifier::DIM);
            let rev = Style::new().add_modifier(Modifier::REVERSED);
            let bold_rev = Style::new()
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::REVERSED);
            Self {
                border: plain,
                divider: dim,
                brand: bold,
                title: plain,
                label: dim,
                value: plain,
                value_muted: dim,
                emerald_bold: bold,
                ice_bold: bold,
                amber: bold,
                amber_bold: bold,
                red_bold: bold,
                section_title: bold,
                bullet_dot: dim,
                body_text: plain,
                hint: dim,
                action_bar: rev,
                action_key: bold_rev,
                action_text: bold_rev,
                scroll_thumb: bold,
                scroll_track: dim,
                footer_key: bold,
                footer_text: dim,
                warn_icon: "!",
            }
        }
    }
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let [vertical] = Layout::vertical([Constraint::Length(height.min(area.height))])
        .flex(Flex::Center)
        .areas(area);
    let [centered] = Layout::horizontal([Constraint::Length(width.min(area.width))])
        .flex(Flex::Center)
        .areas(vertical);
    centered
}

fn render_divider(frame: &mut Frame<'_>, area: Rect, style: Style) {
    if area.is_empty() {
        return;
    }
    let cols = usize::from(area.width);
    let rule: Cow<'static, str> = if cols <= RULE.chars().count() {
        let end = RULE
            .char_indices()
            .nth(cols)
            .map_or(RULE.len(), |(idx, _)| idx);
        Cow::Borrowed(&RULE[..end])
    } else {
        Cow::Owned("─".repeat(cols))
    };
    frame.render_widget(Line::from(Span::styled(rule, style)), area);
}

/// Strips ANSI CSI escapes and collapses control characters / newlines into single spaces.
fn sanitize_single_line(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut last_space = true;

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        if ch.is_control() || ch.is_whitespace() {
            if !last_space {
                cleaned.push(' ');
                last_space = true;
            }
            continue;
        }
        cleaned.push(ch);
        last_space = false;
    }

    if cleaned.ends_with(' ') {
        cleaned.pop();
    }
    cleaned
}

fn truncate_text(text: &str, max_cols: usize) -> String {
    if max_cols == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_cols {
        return text.to_string();
    }
    if max_cols == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(max_cols - 1).collect();
    out.push('…');
    out
}

/// Wraps text strictly on whitespace boundaries so normal words are never split mid-word.
/// Only an indivisible token wider than `max_width` on its own line is chunked to fit.
fn wrap_words(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return Vec::new();
    }
    let clean = sanitize_single_line(text);
    if clean.is_empty() {
        return Vec::new();
    }

    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in clean.split_whitespace() {
        let word_len = word.chars().count();
        if current.is_empty() {
            if word_len <= max_width {
                current.push_str(word);
                current_len = word_len;
            } else {
                push_overlong_token(&mut lines, &mut current, &mut current_len, word, max_width);
            }
        } else if current_len + 1 + word_len <= max_width {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + word_len;
        } else {
            lines.push(std::mem::take(&mut current));
            current_len = 0;
            if word_len <= max_width {
                current.push_str(word);
                current_len = word_len;
            } else {
                push_overlong_token(&mut lines, &mut current, &mut current_len, word, max_width);
            }
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }

    lines
}

fn push_overlong_token(
    lines: &mut Vec<String>,
    current: &mut String,
    current_len: &mut usize,
    word: &str,
    max_width: usize,
) {
    let mut chunk = String::new();
    let mut chunk_len = 0usize;
    for ch in word.chars() {
        if chunk_len == max_width {
            lines.push(std::mem::take(&mut chunk));
            chunk_len = 0;
        }
        chunk.push(ch);
        chunk_len += 1;
    }
    if !chunk.is_empty() {
        *current = chunk;
        *current_len = chunk_len;
    }
}

/// Wraps a bullet or indented item while preserving clean alignment on continuation lines.
fn wrap_bullet(
    text: &str,
    max_width: usize,
    first_prefix: &str,
    cont_prefix: &str,
) -> Vec<(String, String)> {
    if max_width == 0 {
        return Vec::new();
    }
    let prefix_cols = first_prefix
        .chars()
        .count()
        .max(cont_prefix.chars().count());
    let inner_width = max_width.saturating_sub(prefix_cols);
    if inner_width == 0 {
        return vec![(String::new(), truncate_text(text, max_width))];
    }

    let wrapped = wrap_words(text, inner_width);
    wrapped
        .into_iter()
        .enumerate()
        .map(|(idx, line)| {
            let prefix = if idx == 0 { first_prefix } else { cont_prefix };
            (prefix.to_string(), line)
        })
        .collect()
}

fn render_header_bar(
    frame: &mut Frame<'_>,
    area: Rect,
    subtitle: &str,
    short_subtitle: &str,
    pill_text: &str,
    pill_style: Style,
    palette: Palette,
) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let brand = "vdpi";
    let pill_len = pill_text.chars().count();
    let full_left_len = brand.len() + subtitle.chars().count();
    let short_left_len = brand.len() + short_subtitle.chars().count();

    let line = if width >= full_left_len + 2 + pill_len {
        let gap = width - full_left_len - pill_len;
        Line::from(vec![
            Span::styled(brand, palette.brand),
            Span::styled(subtitle, palette.title),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill_text, pill_style),
        ])
    } else if width >= short_left_len + 2 + pill_len {
        let gap = width - short_left_len - pill_len;
        Line::from(vec![
            Span::styled(brand, palette.brand),
            Span::styled(short_subtitle, palette.title),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill_text, pill_style),
        ])
    } else if width >= pill_len + 6 {
        let left_budget = width - pill_len - 1;
        let combined = format!("{brand}{short_subtitle}");
        let left_text = truncate_text(&combined, left_budget);
        let left_len = left_text.chars().count();
        let gap = width.saturating_sub(left_len + pill_len);
        Line::from(vec![
            Span::styled(left_text, palette.brand),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill_text, pill_style),
        ])
    } else {
        let combined = format!("{brand}{short_subtitle}");
        Line::from(Span::styled(truncate_text(&combined, width), palette.brand))
    };

    frame.render_widget(line, area);
}

fn render_footer_hints(
    frame: &mut Frame<'_>,
    area: Rect,
    items: &[(&str, &str)],
    palette: Palette,
) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let sep = " · ";
    let sep_len = sep.chars().count();

    let mut spans: Vec<Span<'_>> = Vec::with_capacity(items.len() * 3);
    let mut used = 0usize;

    for (idx, &(key, desc)) in items.iter().enumerate() {
        let need_sep = idx > 0;
        let item_len = key.chars().count()
            + if desc.is_empty() {
                0
            } else {
                1 + desc.chars().count()
            };
        let extra = if need_sep { sep_len } else { 0 } + item_len;
        if used + extra > width {
            if idx == 0 {
                let text = if desc.is_empty() {
                    key.to_string()
                } else {
                    format!("{key} {desc}")
                };
                spans.push(Span::styled(
                    truncate_text(&text, width),
                    palette.footer_key,
                ));
            }
            break;
        }
        if need_sep {
            spans.push(Span::styled(sep, palette.footer_text));
            used += sep_len;
        }
        spans.push(Span::styled(key, palette.footer_key));
        if !desc.is_empty() {
            spans.push(Span::styled(format!(" {desc}"), palette.footer_text));
        }
        used += item_len;
    }

    frame.render_widget(Line::from(spans), area);
}

fn render_scrollbar(
    frame: &mut Frame<'_>,
    area: Rect,
    total_rows: usize,
    visible_rows: usize,
    scroll: usize,
    palette: Palette,
) {
    if area.is_empty() || total_rows <= visible_rows || visible_rows == 0 {
        return;
    }
    let track_h = usize::from(area.height);
    let thumb_h = ((visible_rows * track_h) / total_rows).clamp(1, track_h);
    let max_scroll = total_rows.saturating_sub(visible_rows);
    let max_thumb_pos = track_h.saturating_sub(thumb_h);
    let thumb_pos = (scroll.min(max_scroll) * max_thumb_pos + max_scroll / 2)
        .checked_div(max_scroll)
        .unwrap_or(0);

    for row_idx in 0..track_h {
        let is_thumb = row_idx >= thumb_pos && row_idx < thumb_pos + thumb_h;
        let (sym, style) = if is_thumb {
            ("┃", palette.scroll_thumb)
        } else {
            ("│", palette.scroll_track)
        };
        let y = area.y.saturating_add(row_idx as u16);
        frame.render_widget(
            Line::from(Span::styled(sym, style)),
            Rect::new(area.x, y, 1, 1),
        );
    }
}

// ============================================================================
// Screen 1: Interactive Software Updater TUI (`run_update_tui`)
// ============================================================================

#[derive(Debug, Deserialize)]
struct GitHubReleasePayload {
    tag_name: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReleaseNoteLine {
    Heading(String),
    Bullet(String),
    Paragraph(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReleaseCheckInfo {
    current_version: String,
    latest_tag: String,
    html_url: String,
    relation: VersionRelation,
    notes: Vec<ReleaseNoteLine>,
    source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdatePhase {
    Checking,
    UpToDate(ReleaseCheckInfo),
    Available(ReleaseCheckInfo),
    Unknown(ReleaseCheckInfo),
    Error(String),
}

#[derive(Debug, Clone)]
struct UpdateTuiState {
    current_version: String,
    phase: UpdatePhase,
    spinner_tick: usize,
    scroll: usize,
    last_viewport_rows: usize,
    last_total_rows: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UpdateKeyAction {
    Ignore,
    Redraw,
    Recheck,
    Install(ReleaseCheckInfo),
    Back,
}

impl UpdateTuiState {
    fn new_checking(current_version: impl Into<String>) -> Self {
        Self {
            current_version: format_version_bare(&current_version.into()),
            phase: UpdatePhase::Checking,
            spinner_tick: 0,
            scroll: 0,
            last_viewport_rows: 8,
            last_total_rows: 0,
        }
    }

    fn apply_check_result(&mut self, result: Result<ReleaseCheckInfo, String>) {
        self.scroll = 0;
        match result {
            Ok(info) => {
                self.current_version = info.current_version.clone();
                self.phase = match info.relation {
                    VersionRelation::Newer => UpdatePhase::Available(info),
                    VersionRelation::Same | VersionRelation::Older => UpdatePhase::UpToDate(info),
                    VersionRelation::Unknown => UpdatePhase::Unknown(info),
                };
            }
            Err(err) => {
                self.phase = UpdatePhase::Error(sanitize_single_line(&err));
            }
        }
    }

    fn spinner_glyph(&self) -> &'static str {
        SPINNER_FRAMES[self.spinner_tick % SPINNER_FRAMES.len()]
    }

    fn scroll_by(&mut self, delta: isize) -> bool {
        let max_scroll = self.last_total_rows.saturating_sub(self.last_viewport_rows);
        let next = if delta < 0 {
            self.scroll.saturating_sub(delta.unsigned_abs())
        } else {
            self.scroll.saturating_add(delta as usize).min(max_scroll)
        };
        if next != self.scroll {
            self.scroll = next;
            true
        } else {
            false
        }
    }

    fn scroll_to_top(&mut self) -> bool {
        if self.scroll != 0 {
            self.scroll = 0;
            true
        } else {
            false
        }
    }

    fn scroll_to_bottom(&mut self) -> bool {
        let max_scroll = self.last_total_rows.saturating_sub(self.last_viewport_rows);
        if self.scroll != max_scroll {
            self.scroll = max_scroll;
            true
        } else {
            false
        }
    }
}

fn format_version_bare(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
        .to_string()
}

fn format_version_v(raw: &str) -> String {
    let bare = format_version_bare(raw);
    if bare.is_empty() {
        "v0.0.0".to_string()
    } else {
        format!("v{bare}")
    }
}

fn strip_inline_markdown(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if i + 1 < chars.len()
            && ((chars[i] == '*' && chars[i + 1] == '*')
                || (chars[i] == '_' && chars[i + 1] == '_'))
        {
            i += 2;
            continue;
        }
        if chars[i] == '`' {
            i += 1;
            continue;
        }
        out.push(chars[i]);
        i += 1;
    }
    sanitize_single_line(&out)
}

fn parse_release_notes(body: Option<&str>) -> Vec<ReleaseNoteLine> {
    let Some(raw) = body else {
        return Vec::new();
    };

    let mut parsed: Vec<ReleaseNoteLine> = Vec::new();
    let mut in_html_comment = false;
    let mut in_code_fence = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("```") {
            in_code_fence = !in_code_fence;
            continue;
        }
        if in_code_fence {
            continue;
        }
        if trimmed.starts_with("<!--") {
            if !trimmed.contains("-->") {
                in_html_comment = true;
            }
            continue;
        }
        if in_html_comment {
            if trimmed.contains("-->") {
                in_html_comment = false;
            }
            continue;
        }
        if trimmed.chars().all(|c| matches!(c, '-' | '*' | '_' | ' ')) && trimmed.len() >= 3 {
            continue;
        }

        if let Some(rest) = trimmed
            .strip_prefix("### ")
            .or_else(|| trimmed.strip_prefix("## "))
            .or_else(|| trimmed.strip_prefix("# "))
        {
            let heading = strip_inline_markdown(rest);
            if !heading.is_empty() && !heading.eq_ignore_ascii_case("what's new") {
                parsed.push(ReleaseNoteLine::Heading(heading));
            }
            continue;
        }

        if let Some(rest) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
            .or_else(|| trimmed.strip_prefix("• "))
        {
            let bullet = strip_inline_markdown(rest);
            if !bullet.is_empty() {
                parsed.push(ReleaseNoteLine::Bullet(bullet));
            }
            continue;
        }

        let para = strip_inline_markdown(trimmed);
        if !para.is_empty() && !para.starts_with("Full Changelog:") {
            parsed.push(ReleaseNoteLine::Paragraph(para));
        }
    }

    parsed
}

async fn read_response_text_bounded(
    mut resp: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            bail!("{label} response exceeded {max_bytes}-byte limit");
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("failed reading {label} response body"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            bail!("{label} response exceeded {max_bytes}-byte limit");
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).with_context(|| format!("{label} response was not valid UTF-8"))
}

async fn fetch_latest_release() -> Result<ReleaseCheckInfo> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let user_agent = format!("vdpi/{}", env!("CARGO_PKG_VERSION"));
    let client = reqwest::Client::builder()
        .user_agent(&user_agent)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(RELEASE_API_TIMEOUT)
        .build()
        .context("failed to build HTTP client")?;

    let installed_handle = tokio::task::spawn_blocking(vdpi::service::detect_installed_info);

    let resp = client
        .get(GITHUB_LATEST_RELEASE_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("failed to contact GitHub Releases API")?;

    if !resp.status().is_success() {
        bail!(
            "GitHub Releases API returned HTTP {}",
            resp.status().as_u16()
        );
    }
    if resp.url().scheme() != "https" {
        bail!(
            "refusing non-HTTPS redirect from GitHub Releases API: {}",
            resp.url()
        );
    }

    let body_text =
        read_response_text_bounded(resp, MAX_RELEASE_API_BYTES, "GitHub Releases API").await?;
    let payload: GitHubReleasePayload =
        serde_json::from_str(&body_text).context("failed to parse GitHub Releases API response")?;

    let installed = installed_handle.await.ok().flatten();
    let baseline_raw = installed
        .as_ref()
        .and_then(|info| info.installed_version.as_deref())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let current_version = format_version_bare(baseline_raw);
    let relation = compare_versions(&payload.tag_name, baseline_raw);
    let notes = parse_release_notes(payload.body.as_deref());

    Ok(ReleaseCheckInfo {
        current_version,
        latest_tag: sanitize_single_line(&payload.tag_name),
        html_url: sanitize_single_line(&payload.html_url),
        relation,
        notes,
        source: "GitHub Releases".to_string(),
    })
}

fn handle_update_key(state: &mut UpdateTuiState, key: KeyEvent) -> UpdateKeyAction {
    if key.kind == KeyEventKind::Release {
        return UpdateKeyAction::Ignore;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return if key.kind == KeyEventKind::Press {
            UpdateKeyAction::Back
        } else {
            UpdateKeyAction::Ignore
        };
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return UpdateKeyAction::Ignore;
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k' | 'K') => {
            if state.scroll_by(-1) {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        KeyCode::Down | KeyCode::Char('j' | 'J') => {
            if state.scroll_by(1) {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        KeyCode::PageUp => {
            let step = (state.last_viewport_rows.saturating_sub(1)).max(1) as isize;
            if state.scroll_by(-step) {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        KeyCode::PageDown => {
            let step = (state.last_viewport_rows.saturating_sub(1)).max(1) as isize;
            if state.scroll_by(step) {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        KeyCode::Home => {
            if state.scroll_to_top() {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        KeyCode::End => {
            if state.scroll_to_bottom() {
                UpdateKeyAction::Redraw
            } else {
                UpdateKeyAction::Ignore
            }
        }
        _ if key.kind != KeyEventKind::Press => UpdateKeyAction::Ignore,
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => UpdateKeyAction::Back,
        KeyCode::Char('r' | 'R') => UpdateKeyAction::Recheck,
        KeyCode::Char('u' | 'U') => match &state.phase {
            UpdatePhase::Available(info) => UpdateKeyAction::Install(info.clone()),
            _ => UpdateKeyAction::Ignore,
        },
        KeyCode::Enter => match &state.phase {
            UpdatePhase::Available(info) => UpdateKeyAction::Install(info.clone()),
            UpdatePhase::UpToDate(_) | UpdatePhase::Unknown(_) | UpdatePhase::Error(_) => {
                UpdateKeyAction::Back
            }
            UpdatePhase::Checking => UpdateKeyAction::Ignore,
        },
        _ => UpdateKeyAction::Ignore,
    }
}

fn build_update_note_lines(
    notes: &[ReleaseNoteLine],
    width: usize,
    palette: Palette,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }
    if notes.is_empty() {
        return wrap_words("No release notes published for this release.", width)
            .into_iter()
            .map(|text| Line::from(Span::styled(text, palette.hint)))
            .collect();
    }

    let mut out: Vec<Line<'static>> = Vec::new();
    for item in notes {
        match item {
            ReleaseNoteLine::Heading(heading) => {
                if !out.is_empty() {
                    out.push(Line::default());
                }
                for text in wrap_words(heading, width) {
                    out.push(Line::from(Span::styled(text, palette.section_title)));
                }
            }
            ReleaseNoteLine::Bullet(bullet) => {
                for (idx, (prefix, text)) in wrap_bullet(bullet, width, "  • ", "    ")
                    .into_iter()
                    .enumerate()
                {
                    if idx == 0 && !prefix.is_empty() {
                        out.push(Line::from(vec![
                            Span::styled(prefix, palette.bullet_dot),
                            Span::styled(text, palette.body_text),
                        ]));
                    } else if !prefix.is_empty() {
                        out.push(Line::from(vec![
                            Span::raw(prefix),
                            Span::styled(text, palette.body_text),
                        ]));
                    } else {
                        out.push(Line::from(Span::styled(text, palette.body_text)));
                    }
                }
            }
            ReleaseNoteLine::Paragraph(para) => {
                for text in wrap_words(para, width) {
                    out.push(Line::from(Span::styled(text, palette.body_text)));
                }
            }
        }
    }

    out
}

fn render_update_minimal(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &UpdateTuiState,
    palette: Palette,
) {
    let text = match &state.phase {
        UpdatePhase::Checking => format!("{} vdpi Update", state.spinner_glyph()),
        UpdatePhase::UpToDate(_) => "vdpi Up to date".to_string(),
        UpdatePhase::Available(info) => format!("vdpi Update {}", info.latest_tag),
        UpdatePhase::Unknown(_) => "vdpi Update".to_string(),
        UpdatePhase::Error(_) => "vdpi Update failed".to_string(),
    };
    frame.render_widget(
        Line::from(Span::styled(
            truncate_text(&text, usize::from(area.width)),
            palette.brand,
        )),
        Rect::new(area.x, area.y, area.width, 1),
    );
}

fn render_meta_row(
    frame: &mut Frame<'_>,
    area: Rect,
    label: &str,
    value_spans: Vec<Span<'_>>,
    palette: Palette,
) {
    if area.is_empty() {
        return;
    }
    let padded_label = format!("{label:<10}");
    let mut spans = Vec::with_capacity(value_spans.len() + 1);
    spans.push(Span::styled(padded_label, palette.label));
    spans.extend(value_spans);
    frame.render_widget(Line::from(spans), area);
}

fn render_update_tui(frame: &mut Frame<'_>, state: &mut UpdateTuiState, color: bool) {
    let area = frame.area();
    if area.is_empty() {
        return;
    }

    let palette = Palette::for_color(color);
    if area.width < 16 || area.height < 8 {
        render_update_minimal(frame, area, state, palette);
        return;
    }

    let card_width = area.width.min(MAX_CARD_WIDTH);
    let preferred_height = match &state.phase {
        UpdatePhase::Checking => 13,
        UpdatePhase::Error(_) => 15,
        UpdatePhase::UpToDate(_) | UpdatePhase::Unknown(_) => 22,
        UpdatePhase::Available(_) => 24,
    };
    let card_height = area.height.min(preferred_height.min(MAX_CARD_HEIGHT));
    let card_area = centered_rect(area, card_width, card_height);
    let padding = if card_width >= 24 {
        Padding::horizontal(1)
    } else {
        Padding::ZERO
    };

    let block = Block::bordered()
        .border_type(if color {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(palette.border)
        .padding(padding);
    let inner = block.inner(card_area);
    frame.render_widget(block, card_area);

    if inner.is_empty() {
        return;
    }

    let width = usize::from(inner.width);
    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |ry: u16| Rect::new(inner.x, ry, inner.width, 1);

    // 1. Header with semantic status pill
    let (pill_text, pill_style) = match &state.phase {
        UpdatePhase::Checking => (
            format!("{} Checking…", state.spinner_glyph()),
            palette.ice_bold,
        ),
        UpdatePhase::UpToDate(_) => ("● Up to date".to_string(), palette.emerald_bold),
        UpdatePhase::Available(_) => (
            if width >= 46 {
                "▲ Update available".to_string()
            } else {
                "▲ Available".to_string()
            },
            palette.ice_bold,
        ),
        UpdatePhase::Unknown(_) => ("● Check complete".to_string(), palette.amber_bold),
        UpdatePhase::Error(_) => ("✕ Check failed".to_string(), palette.red_bold),
    };

    render_header_bar(
        frame,
        row(y),
        " · Software Update",
        " · Update",
        &pill_text,
        pill_style,
        palette,
    );
    y = y.saturating_add(1);

    let show_top_div = inner.height >= 10;
    let show_footer = inner.height >= 6;
    let show_bot_div = inner.height >= 9;

    if show_top_div && y < bottom {
        render_divider(frame, row(y), palette.divider);
        y = y.saturating_add(1);
    }

    let footer_reserve = u16::from(show_footer) + u16::from(show_bot_div);
    let content_bottom = bottom.saturating_sub(footer_reserve).max(y);

    // 2. Body by phase
    match state.phase.clone() {
        UpdatePhase::Checking => {
            state.last_viewport_rows = 0;
            state.last_total_rows = 0;

            if y < content_bottom {
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                let status_line = format!("{} Checking GitHub Releases…", state.spinner_glyph());
                frame.render_widget(
                    Line::from(Span::styled(
                        truncate_text(&status_line, width),
                        palette.ice_bold,
                    )),
                    row(y),
                );
                y = y.saturating_add(1);
            }
            if y.saturating_add(1) < content_bottom {
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                let cur = format_version_v(&state.current_version);
                render_meta_row(
                    frame,
                    row(y),
                    "Current",
                    vec![Span::styled(cur, palette.value)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Source",
                    vec![Span::styled("GitHub Releases", palette.value_muted)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y.saturating_add(1) < content_bottom {
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                for line in wrap_words("Press q or Esc to return to Control Center.", width) {
                    if y >= content_bottom {
                        break;
                    }
                    frame.render_widget(Line::from(Span::styled(line, palette.hint)), row(y));
                    y = y.saturating_add(1);
                }
            }
        }
        UpdatePhase::UpToDate(info) => {
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Current",
                    vec![Span::styled(
                        format_version_v(&info.current_version),
                        palette.value,
                    )],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Latest",
                    vec![Span::styled(info.latest_tag.clone(), palette.emerald_bold)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Source",
                    vec![Span::styled(info.source.clone(), palette.value_muted)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom && content_bottom.saturating_sub(y) >= 3 {
                render_divider(frame, row(y), palette.divider);
                y = y.saturating_add(1);
            }

            let notes_area = Rect::new(inner.x, y, inner.width, content_bottom.saturating_sub(y));
            render_whats_new_section(frame, notes_area, &info.notes, state, palette);
        }
        UpdatePhase::Available(info) => {
            // Reserve 1 row (plus optional blank spacer) at bottom of content for primary action bar
            let action_rows = if content_bottom.saturating_sub(y) >= 5 {
                2u16
            } else {
                1u16
            };
            let body_bottom = content_bottom.saturating_sub(action_rows).max(y);

            if y < body_bottom {
                let cur = format_version_v(&info.current_version);
                let transition_full = format!("Current {cur} -> Latest {}", info.latest_tag);
                if width >= transition_full.chars().count() {
                    frame.render_widget(
                        Line::from(vec![
                            Span::styled("Current ", palette.label),
                            Span::styled(cur, palette.value_muted),
                            Span::styled(" -> ", palette.hint),
                            Span::styled("Latest ", palette.label),
                            Span::styled(info.latest_tag.clone(), palette.ice_bold),
                        ]),
                        row(y),
                    );
                } else {
                    render_meta_row(
                        frame,
                        row(y),
                        "Version",
                        vec![
                            Span::styled(cur, palette.value_muted),
                            Span::styled(" -> ", palette.hint),
                            Span::styled(info.latest_tag.clone(), palette.ice_bold),
                        ],
                        palette,
                    );
                }
                y = y.saturating_add(1);
            }
            if y < body_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Source",
                    vec![Span::styled(info.source.clone(), palette.value_muted)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < body_bottom && body_bottom.saturating_sub(y) >= 3 {
                render_divider(frame, row(y), palette.divider);
                y = y.saturating_add(1);
            }

            let notes_area = Rect::new(inner.x, y, inner.width, body_bottom.saturating_sub(y));
            render_whats_new_section(frame, notes_area, &info.notes, state, palette);

            // Highlighted primary action bar: [u] Install vX.Y.Z
            if content_bottom > body_bottom {
                let action_y = content_bottom.saturating_sub(1);
                let action_rect = row(action_y);
                let label = format!("Install {}", info.latest_tag);
                let prefix = " ▸ ";
                let key = "[u] ";
                let content_len = prefix.chars().count() + key.len() + label.chars().count();
                let pad = width.saturating_sub(content_len);
                frame.render_widget(
                    Line::from(vec![
                        Span::styled(prefix, palette.action_key),
                        Span::styled(key, palette.action_key),
                        Span::styled(
                            truncate_text(&label, width.saturating_sub(7)),
                            palette.action_text,
                        ),
                        Span::styled(" ".repeat(pad), palette.action_bar),
                    ]),
                    action_rect,
                );
            }
        }
        UpdatePhase::Unknown(info) => {
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Current",
                    vec![Span::styled(
                        format_version_v(&info.current_version),
                        palette.value,
                    )],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Latest",
                    vec![Span::styled(info.latest_tag.clone(), palette.amber_bold)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                render_meta_row(
                    frame,
                    row(y),
                    "Source",
                    vec![Span::styled(info.source.clone(), palette.value_muted)],
                    palette,
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom && content_bottom.saturating_sub(y) >= 3 {
                render_divider(frame, row(y), palette.divider);
                y = y.saturating_add(1);
            }
            let notes_area = Rect::new(inner.x, y, inner.width, content_bottom.saturating_sub(y));
            render_whats_new_section(frame, notes_area, &info.notes, state, palette);
        }
        UpdatePhase::Error(err_msg) => {
            if y < content_bottom {
                frame.render_widget(
                    Line::from(vec![
                        Span::styled("✕ ", palette.red_bold),
                        Span::styled("Unable to check for updates", palette.red_bold),
                    ]),
                    row(y),
                );
                y = y.saturating_add(1);
            }
            if y < content_bottom {
                y = y.saturating_add(1);
            }

            let err_lines: Vec<Line<'static>> =
                wrap_words(&err_msg, width.saturating_sub(2).max(1))
                    .into_iter()
                    .map(|text| Line::from(Span::styled(text, palette.body_text)))
                    .collect();
            let avail_rows = usize::from(content_bottom.saturating_sub(y));
            let hint_reserve = usize::from(avail_rows >= 3);
            let viewport_rows = avail_rows.saturating_sub(hint_reserve);
            state.last_total_rows = err_lines.len();
            state.last_viewport_rows = viewport_rows;
            let max_scroll = state.last_total_rows.saturating_sub(viewport_rows);
            state.scroll = state.scroll.min(max_scroll);

            for (offset, line) in err_lines
                .into_iter()
                .skip(state.scroll)
                .take(viewport_rows)
                .enumerate()
            {
                let ry = y.saturating_add(offset as u16);
                frame.render_widget(line, Rect::new(inner.x, ry, inner.width, 1));
            }
            if hint_reserve > 0 {
                let hint_y = content_bottom.saturating_sub(1);
                frame.render_widget(
                    Line::from(Span::styled(
                        truncate_text("Check your network connection and press r to retry.", width),
                        palette.hint,
                    )),
                    row(hint_y),
                );
            }
        }
    }

    // 3. Bottom divider + footer
    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        let hints: Vec<(&str, &str)> = match &state.phase {
            UpdatePhase::Checking => vec![("q / esc", "cancel")],
            UpdatePhase::UpToDate(_) | UpdatePhase::Unknown(_) => {
                if width >= 44 {
                    vec![("r", "re-check"), ("↑↓", "scroll"), ("enter / q", "back")]
                } else {
                    vec![("r", "check"), ("↑↓", "scroll"), ("q", "back")]
                }
            }
            UpdatePhase::Available(_) => {
                if width >= 46 {
                    vec![
                        ("u", "install"),
                        ("r", "re-check"),
                        ("↑↓", "scroll"),
                        ("q", "back"),
                    ]
                } else {
                    vec![("u", "install"), ("r", "check"), ("q", "back")]
                }
            }
            UpdatePhase::Error(_) => vec![("r", "retry"), ("q", "back")],
        };
        render_footer_hints(frame, row(footer_y), &hints, palette);
    }
    if show_bot_div && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), palette.divider);
    }
}

fn render_whats_new_section(
    frame: &mut Frame<'_>,
    area: Rect,
    notes: &[ReleaseNoteLine],
    state: &mut UpdateTuiState,
    palette: Palette,
) {
    if area.is_empty() {
        state.last_viewport_rows = 0;
        state.last_total_rows = 0;
        return;
    }

    let mut y = area.y;
    let bottom = area.y.saturating_add(area.height);
    let width = usize::from(area.width);

    // Reserve 1 column on right for scrollbar if notes overflow
    let first_pass = build_update_note_lines(notes, width, palette);
    let body_rows_available = usize::from(area.height.saturating_sub(1));
    let needs_scrollbar = first_pass.len() > body_rows_available && width >= 12;
    let text_width = if needs_scrollbar {
        width.saturating_sub(2)
    } else {
        width
    };
    let lines = if needs_scrollbar {
        build_update_note_lines(notes, text_width, palette)
    } else {
        first_pass
    };

    state.last_total_rows = lines.len();
    state.last_viewport_rows = body_rows_available;
    let max_scroll = state.last_total_rows.saturating_sub(body_rows_available);
    state.scroll = state.scroll.min(max_scroll);

    // Section title row: "What's New" + optional scroll range indicator
    let title = "What's New";
    if needs_scrollbar && body_rows_available > 0 {
        let start = state.scroll + 1;
        let end = (state.scroll + body_rows_available).min(lines.len());
        let indicator = format!("{start}-{end}/{}", lines.len());
        let gap = width.saturating_sub(title.len() + indicator.len());
        if gap >= 2 {
            frame.render_widget(
                Line::from(vec![
                    Span::styled(title, palette.section_title),
                    Span::raw(" ".repeat(gap)),
                    Span::styled(indicator, palette.hint),
                ]),
                Rect::new(area.x, y, area.width, 1),
            );
        } else {
            frame.render_widget(
                Line::from(Span::styled(title, palette.section_title)),
                Rect::new(area.x, y, area.width, 1),
            );
        }
    } else {
        frame.render_widget(
            Line::from(Span::styled(title, palette.section_title)),
            Rect::new(area.x, y, area.width, 1),
        );
    }
    y = y.saturating_add(1);

    let list_height = bottom.saturating_sub(y);
    if list_height == 0 {
        return;
    }

    for (idx, line) in lines
        .into_iter()
        .skip(state.scroll)
        .take(usize::from(list_height))
        .enumerate()
    {
        let ry = y.saturating_add(idx as u16);
        frame.render_widget(line, Rect::new(area.x, ry, text_width as u16, 1));
    }

    if needs_scrollbar {
        let bar_area = Rect::new(
            area.x.saturating_add(area.width.saturating_sub(1)),
            y,
            1,
            list_height,
        );
        render_scrollbar(
            frame,
            bar_area,
            state.last_total_rows,
            usize::from(list_height),
            state.scroll,
            palette,
        );
    }
}

/// Interactive Software Updater TUI.
///
/// Immediately renders the updater card with a live Braille spinner while querying
/// GitHub Releases, displays cleanly wrapped release notes, and exits raw/alternate
/// screen cleanly before invoking `vdpi::update::run_update` so `sudo`/Touch ID/UAC
/// elevation prompts work seamlessly on the real terminal.
///
/// Returns `Ok(Some(notice))` when an install was attempted (success or failure),
/// or `Ok(None)` when the user returns to the Control Center without installing.
pub async fn run_update_tui(cfg: &RuntimeConfig) -> Result<Option<String>> {
    if !is_interactive_tty() {
        return match fetch_latest_release().await {
            Ok(info) if info.relation == VersionRelation::Newer => Ok(Some(format!(
                "Update available: {} -> {}. Run 'vdpi update' to install.",
                format_version_v(&info.current_version),
                info.latest_tag
            ))),
            Ok(info) => Ok(Some(format!(
                "vdpi is up to date ({}).",
                format_version_v(&info.current_version)
            ))),
            Err(err) => Ok(Some(format!(
                "Update check failed: {}",
                sanitize_single_line(&format!("{err:#}"))
            ))),
        };
    }

    let color = color_enabled();
    let mut state = UpdateTuiState::new_checking(env!("CARGO_PKG_VERSION"));

    let mut guard = TerminalGuard::enter().context("failed to initialize Software Update TUI")?;
    let mut ev_reader = EventReaderGuard::spawn();

    let (check_tx, mut check_rx) = mpsc::channel::<(u64, Result<ReleaseCheckInfo, String>)>(4);
    let mut active_check_id: u64 = 1;
    let mut check_task: Option<JoinHandle<()>> =
        Some(spawn_release_check(active_check_id, check_tx.clone()));

    let mut spinner = tokio::time::interval(SPINNER_INTERVAL);
    spinner.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let install_target: Option<ReleaseCheckInfo> = loop {
        guard
            .terminal
            .draw(|frame| render_update_tui(frame, &mut state, color))?;

        tokio::select! {
            maybe_ev = ev_reader.recv() => {
                let Some(ev) = maybe_ev else {
                    break None;
                };
                match ev {
                    Event::Resize(..) => {}
                    Event::Key(key) => match handle_update_key(&mut state, key) {
                        UpdateKeyAction::Ignore => {}
                        UpdateKeyAction::Redraw => {}
                        UpdateKeyAction::Recheck => {
                            if let Some(handle) = check_task.take() {
                                handle.abort();
                            }
                            active_check_id = active_check_id.saturating_add(1);
                            state.phase = UpdatePhase::Checking;
                            state.spinner_tick = 0;
                            state.scroll = 0;
                            check_task = Some(spawn_release_check(active_check_id, check_tx.clone()));
                        }
                        UpdateKeyAction::Install(info) => {
                            break Some(info);
                        }
                        UpdateKeyAction::Back => {
                            break None;
                        }
                    },
                    _ => {}
                }
            }
            maybe_res = check_rx.recv() => {
                if let Some((id, res)) = maybe_res {
                    if id == active_check_id {
                        check_task = None;
                        state.apply_check_result(res);
                    }
                }
            }
            _ = spinner.tick(), if matches!(state.phase, UpdatePhase::Checking) => {
                state.spinner_tick = state.spinner_tick.wrapping_add(1);
            }
        }
    };

    if let Some(handle) = check_task.take() {
        handle.abort();
    }

    // Always drop EventReaderGuard BEFORE TerminalGuard so the terminal is fully
    // restored for sudo/Touch ID/Windows UAC prompts or clean return to Control Center.
    drop(ev_reader);
    drop(guard);

    let Some(info) = install_target else {
        return Ok(None);
    };

    println!("\nUpdating vdpi to {}...", info.latest_tag);
    let _ = io::stdout().flush();

    match vdpi::update::run_update(false, false, cfg).await {
        Ok(()) => Ok(Some(format!("Updated vdpi to {}.", info.latest_tag))),
        Err(err) => Ok(Some(format!(
            "Update failed: {}",
            sanitize_single_line(&format!("{err:#}"))
        ))),
    }
}

fn spawn_release_check(
    check_id: u64,
    tx: mpsc::Sender<(u64, Result<ReleaseCheckInfo, String>)>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let res = fetch_latest_release()
            .await
            .map_err(|err| format!("{err:#}"));
        let _ = tx.send((check_id, res)).await;
    })
}

// ============================================================================
// Screen 2: Interactive Live Network Diagnostics TUI (`run_diagnostics_tui`)
// ============================================================================

const DIAG_CHECK_COUNT: usize = 5;
const DIAG_CHECK_NAMES: [&str; DIAG_CHECK_COUNT] = [
    "Service & Engine",
    "VPN & Split Tunnel",
    "Encrypted DNS (DoH)",
    "TLS Handshake (discord.com)",
    "TLS Handshake (roblox.com)",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum DiagStatus {
    Running,
    Pass {
        summary: String,
        detail: Option<String>,
        latency_ms: Option<u128>,
    },
    Warn {
        summary: String,
        detail: Option<String>,
        latency_ms: Option<u128>,
    },
    Fail {
        summary: String,
        detail: Option<String>,
        latency_ms: Option<u128>,
    },
}

impl DiagStatus {
    fn is_done(&self) -> bool {
        !matches!(self, Self::Running)
    }

    fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }

    fn is_warn(&self) -> bool {
        matches!(self, Self::Warn { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DiagCheckItem {
    name: &'static str,
    status: DiagStatus,
}

#[derive(Debug, Clone)]
struct DiagnosticsTuiState {
    items: [DiagCheckItem; DIAG_CHECK_COUNT],
    spinner_tick: usize,
    scroll: usize,
    last_viewport_rows: usize,
    last_total_rows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiagKeyAction {
    Ignore,
    Redraw,
    Rerun,
    Back,
}

impl DiagnosticsTuiState {
    fn new_running() -> Self {
        Self {
            items: std::array::from_fn(|idx| DiagCheckItem {
                name: DIAG_CHECK_NAMES[idx],
                status: DiagStatus::Running,
            }),
            spinner_tick: 0,
            scroll: 0,
            last_viewport_rows: 10,
            last_total_rows: 0,
        }
    }

    fn reset_running(&mut self) {
        for item in &mut self.items {
            item.status = DiagStatus::Running;
        }
        self.spinner_tick = 0;
        self.scroll = 0;
    }

    fn set_result(&mut self, idx: usize, status: DiagStatus) {
        if let Some(item) = self.items.get_mut(idx) {
            item.status = status;
        }
    }

    fn spinner_glyph(&self) -> &'static str {
        SPINNER_FRAMES[self.spinner_tick % SPINNER_FRAMES.len()]
    }

    fn done_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.status.is_done())
            .count()
    }

    fn pass_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.status.is_pass())
            .count()
    }

    fn attention_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.status.is_warn() || item.status.is_fail())
            .count()
    }

    fn has_failure(&self) -> bool {
        self.items.iter().any(|item| item.status.is_fail())
    }

    fn is_running(&self) -> bool {
        self.done_count() < DIAG_CHECK_COUNT
    }

    fn summary_string(&self) -> String {
        let done = self.done_count();
        let passed = self.pass_count();
        if done == DIAG_CHECK_COUNT && passed == DIAG_CHECK_COUNT {
            format!("Diagnostics passed ({passed}/{DIAG_CHECK_COUNT})")
        } else if done < DIAG_CHECK_COUNT {
            format!("Diagnostics cancelled ({done}/{DIAG_CHECK_COUNT} complete, {passed} passed)")
        } else {
            format!("Diagnostics complete ({passed}/{DIAG_CHECK_COUNT} passed)")
        }
    }

    fn scroll_by(&mut self, delta: isize) -> bool {
        let max_scroll = self.last_total_rows.saturating_sub(self.last_viewport_rows);
        let next = if delta < 0 {
            self.scroll.saturating_sub(delta.unsigned_abs())
        } else {
            self.scroll.saturating_add(delta as usize).min(max_scroll)
        };
        if next != self.scroll {
            self.scroll = next;
            true
        } else {
            false
        }
    }

    fn scroll_to_top(&mut self) -> bool {
        if self.scroll != 0 {
            self.scroll = 0;
            true
        } else {
            false
        }
    }

    fn scroll_to_bottom(&mut self) -> bool {
        let max_scroll = self.last_total_rows.saturating_sub(self.last_viewport_rows);
        if self.scroll != max_scroll {
            self.scroll = max_scroll;
            true
        } else {
            false
        }
    }
}

fn handle_diag_key(state: &mut DiagnosticsTuiState, key: KeyEvent) -> DiagKeyAction {
    if key.kind == KeyEventKind::Release {
        return DiagKeyAction::Ignore;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return if key.kind == KeyEventKind::Press {
            DiagKeyAction::Back
        } else {
            DiagKeyAction::Ignore
        };
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return DiagKeyAction::Ignore;
    }

    match key.code {
        KeyCode::Up | KeyCode::Char('k' | 'K') => {
            if state.scroll_by(-1) {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        KeyCode::Down | KeyCode::Char('j' | 'J') => {
            if state.scroll_by(1) {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        KeyCode::PageUp => {
            let step = (state.last_viewport_rows.saturating_sub(1)).max(1) as isize;
            if state.scroll_by(-step) {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        KeyCode::PageDown => {
            let step = (state.last_viewport_rows.saturating_sub(1)).max(1) as isize;
            if state.scroll_by(step) {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        KeyCode::Home => {
            if state.scroll_to_top() {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        KeyCode::End => {
            if state.scroll_to_bottom() {
                DiagKeyAction::Redraw
            } else {
                DiagKeyAction::Ignore
            }
        }
        _ if key.kind != KeyEventKind::Press => DiagKeyAction::Ignore,
        KeyCode::Char('r' | 'R') => DiagKeyAction::Rerun,
        KeyCode::Enter | KeyCode::Esc | KeyCode::Char('q' | 'Q') => DiagKeyAction::Back,
        _ => DiagKeyAction::Ignore,
    }
}

fn format_rss_mb(rss_kb: u64) -> String {
    let mb = (rss_kb as f64) / 1024.0;
    format!("{mb:.1} MB RSS")
}

fn evaluate_service_engine_check(status: &ControlCenterStatus) -> DiagStatus {
    if let Some(live) = status.live_engine.as_ref() {
        let mut parts: Vec<String> = Vec::new();
        let engine_label = match live.engine {
            EngineMode::Tun => {
                if let Some(iface) = live.tun_interface.as_deref().filter(|s| !s.is_empty()) {
                    format!("TUN active ({iface})")
                } else {
                    "TUN active".to_string()
                }
            }
            EngineMode::Proxy => {
                let ip = normalize_loopback_ip(live.addr).unwrap_or(live.addr);
                let addr = SocketAddr::new(ip, live.port);
                format!("Proxy active ({addr})")
            }
        };
        if let Some(ver) = live.version.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format_version_v(ver));
        }
        if let Some(rss) = live.rss_kb {
            parts.push(format_rss_mb(rss));
        }
        if let Some(mode) = live.mode.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("desync {mode}"));
        }
        let detail = if parts.is_empty() {
            None
        } else {
            Some(parts.join(" · "))
        };
        return DiagStatus::Pass {
            summary: engine_label,
            detail,
            latency_ms: None,
        };
    }

    match status.service_state {
        ServiceState::Running => {
            let eng = match status.configured_engine {
                EngineMode::Tun => "TUN",
                EngineMode::Proxy => "Proxy",
            };
            DiagStatus::Pass {
                summary: format!("{eng} service running"),
                detail: Some("Background service active (health endpoint idle)".to_string()),
                latency_ms: None,
            }
        }
        ServiceState::Stopped => DiagStatus::Warn {
            summary: "Service paused (standby)".to_string(),
            detail: Some(
                "Resume the service from Control Center to enable protection.".to_string(),
            ),
            latency_ms: None,
        },
        ServiceState::NotInstalled => DiagStatus::Warn {
            summary: "Service not installed (standby)".to_string(),
            detail: Some(
                "Checks run over your direct connection until vdpi is active.".to_string(),
            ),
            latency_ms: None,
        },
    }
}

fn evaluate_vpn_split_check(status: &ControlCenterStatus, cfg: &RuntimeConfig) -> DiagStatus {
    let split = if cfg.split_tunnel.mode == vdpi_core::config::SplitTunnelMode::All
        && cfg.split_tunnel.apps.is_empty()
    {
        vdpi::service::load_configured_split_tunnel()
    } else {
        cfg.split_tunnel.clone()
    };
    let split_label = split.summary_label();

    if cfg.vpn_coexistence == VpnCoexistence::Off {
        return DiagStatus::Pass {
            summary: format!("VPN check off · {split_label}"),
            detail: Some("VPN coexistence detection is disabled in configuration.".to_string()),
            latency_ms: None,
        };
    }

    if let Some(conflict) = status
        .vpn_conflict
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        DiagStatus::Warn {
            summary: format!("VPN conflict: {}", sanitize_single_line(conflict)),
            detail: Some(format!("Split tunnel: {split_label}")),
            latency_ms: None,
        }
    } else {
        DiagStatus::Pass {
            summary: format!("No VPN conflict · {split_label}"),
            detail: None,
            latency_ms: None,
        }
    }
}

fn normalize_loopback_ip(ip: IpAddr) -> Option<IpAddr> {
    let canonical = ip.to_canonical();
    match canonical {
        IpAddr::V4(v4) if v4.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        addr if addr.is_loopback() => Some(addr),
        _ => None,
    }
}

async fn run_doh_check(cfg: &RuntimeConfig) -> DiagStatus {
    let dns_addr = if cfg.dns_addr.trim().is_empty() {
        "1.1.1.1".to_string()
    } else {
        cfg.dns_addr.trim().to_string()
    };
    let transport = if cfg.enable_doh { "DoH" } else { "UDP" };
    let started = Instant::now();

    let resolver =
        match DnsResolver::new(&dns_addr, cfg.dns_port, cfg.enable_doh, cfg.dns_ipv4_only) {
            Ok(r) => r,
            Err(err) => {
                return DiagStatus::Fail {
                    summary: format!("Resolver init failed ({dns_addr})"),
                    detail: Some(sanitize_single_line(&format!("{err:#}"))),
                    latency_ms: Some(started.elapsed().as_millis()),
                };
            }
        };

    let outcome = tokio::time::timeout(DIAG_DNS_TIMEOUT, resolver.resolve("discord.com")).await;
    let latency_ms = started.elapsed().as_millis();

    match outcome {
        Ok(Ok(ips)) if !ips.is_empty() => {
            let first = ips[0].to_string();
            let noun = if ips.len() == 1 { "IP" } else { "IPs" };
            DiagStatus::Pass {
                summary: format!("discord.com resolved ({} {noun})", ips.len()),
                detail: Some(format!("{transport} via {dns_addr} · {first}")),
                latency_ms: Some(latency_ms),
            }
        }
        Ok(Ok(_)) => DiagStatus::Fail {
            summary: "No IP addresses returned".to_string(),
            detail: Some(format!("{transport} via {dns_addr}")),
            latency_ms: Some(latency_ms),
        },
        Ok(Err(err)) => DiagStatus::Fail {
            summary: format!("{transport} lookup failed"),
            detail: Some(sanitize_single_line(&format!("{err:#}"))),
            latency_ms: Some(latency_ms),
        },
        Err(_) => DiagStatus::Fail {
            summary: format!("{transport} lookup timed out"),
            detail: Some(format!(
                "No reply from {dns_addr} within {}s",
                DIAG_DNS_TIMEOUT.as_secs()
            )),
            latency_ms: Some(latency_ms),
        },
    }
}

#[derive(Debug, Clone)]
enum TlsProbePath {
    Proxy(SocketAddr),
    Tun,
    Direct,
}

async fn run_tls_handshake_check(host: &str, path: TlsProbePath) -> DiagStatus {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let started = Instant::now();

    let (client_res, path_desc) = match &path {
        TlsProbePath::Proxy(proxy_addr) => {
            let proxy_url = format!("http://{proxy_addr}");
            let res = reqwest::Proxy::https(&proxy_url)
                .map_err(|err| anyhow!("invalid local proxy URL: {err}"))
                .and_then(|proxy| {
                    reqwest::Client::builder()
                        .https_only(true)
                        .proxy(proxy)
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(DIAG_TLS_TIMEOUT)
                        .build()
                        .map_err(anyhow::Error::from)
                });
            (res, format!("Via local proxy {proxy_addr}"))
        }
        TlsProbePath::Tun => {
            let res = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(DIAG_TLS_TIMEOUT)
                .build()
                .map_err(anyhow::Error::from);
            (res, "Via active TUN engine".to_string())
        }
        TlsProbePath::Direct => {
            let res = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(DIAG_TLS_TIMEOUT)
                .build()
                .map_err(anyhow::Error::from);
            (res, "Direct TLS connection".to_string())
        }
    };

    let client = match client_res {
        Ok(c) => c,
        Err(err) => {
            return DiagStatus::Fail {
                summary: "TLS client unavailable".to_string(),
                detail: Some(sanitize_single_line(&format!("{err:#}"))),
                latency_ms: Some(started.elapsed().as_millis()),
            };
        }
    };

    let url = format!("https://{host}/");
    let outcome = tokio::time::timeout(DIAG_TLS_TIMEOUT, client.head(&url).send()).await;
    let latency_ms = started.elapsed().as_millis();

    match outcome {
        Ok(Ok(resp)) => DiagStatus::Pass {
            summary: format!("TLS verified (HTTP {})", resp.status().as_u16()),
            detail: Some(path_desc),
            latency_ms: Some(latency_ms),
        },
        Ok(Err(err)) => DiagStatus::Fail {
            summary: "TLS handshake failed".to_string(),
            detail: Some(sanitize_single_line(&err.to_string())),
            latency_ms: Some(latency_ms),
        },
        Err(_) => DiagStatus::Fail {
            summary: "TLS handshake timed out".to_string(),
            detail: Some(format!(
                "Timed out after {}s ({path_desc})",
                DIAG_TLS_TIMEOUT.as_secs()
            )),
            latency_ms: Some(latency_ms),
        },
    }
}

fn spawn_diagnostics_run(
    tasks: &mut JoinSet<()>,
    run_id: u64,
    cfg: RuntimeConfig,
    tx: mpsc::Sender<(u64, usize, DiagStatus)>,
) {
    // Check 3 (Encrypted DNS / DoH) runs immediately in parallel with service probe.
    {
        let cfg_dns = cfg.clone();
        let tx_dns = tx.clone();
        tasks.spawn(async move {
            let status = run_doh_check(&cfg_dns).await;
            let _ = tx_dns.send((run_id, 2, status)).await;
        });
    }

    // Check 1 & 2 probe Control Center status, then immediately launch Check 4 & 5
    // over the discovered path (active local Proxy vs TUN vs Direct).
    tasks.spawn(async move {
        let cfg_probe = cfg.clone();
        let cc_status = tokio::task::spawn_blocking(move || {
            vdpi::service::probe_control_center_status(&cfg_probe)
        })
        .await
        .unwrap_or(ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: cfg.engine,
            vpn_conflict: None,
        });

        let service_result = evaluate_service_engine_check(&cc_status);
        let _ = tx.send((run_id, 0, service_result)).await;

        let vpn_result = evaluate_vpn_split_check(&cc_status, &cfg);
        let _ = tx.send((run_id, 1, vpn_result)).await;

        let tls_path = match cc_status.live_engine.as_ref() {
            Some(live) if live.engine == EngineMode::Proxy => {
                if let Some(ip) = normalize_loopback_ip(live.addr) {
                    TlsProbePath::Proxy(SocketAddr::new(ip, live.port))
                } else {
                    TlsProbePath::Direct
                }
            }
            Some(live) if live.engine == EngineMode::Tun => TlsProbePath::Tun,
            _ => TlsProbePath::Direct,
        };

        let tx_discord = tx.clone();
        let path_discord = tls_path.clone();
        let discord_fut = async move {
            let status = run_tls_handshake_check("discord.com", path_discord).await;
            let _ = tx_discord.send((run_id, 3, status)).await;
        };

        let tx_roblox = tx;
        let path_roblox = tls_path;
        let roblox_fut = async move {
            let status = run_tls_handshake_check("roblox.com", path_roblox).await;
            let _ = tx_roblox.send((run_id, 4, status)).await;
        };

        tokio::join!(discord_fut, roblox_fut);
    });
}

fn build_diag_rows(
    state: &DiagnosticsTuiState,
    width: usize,
    palette: Palette,
) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }

    let mut lines: Vec<Line<'static>> = Vec::new();
    let spinner = state.spinner_glyph();

    for (idx, item) in state.items.iter().enumerate() {
        if idx > 0 {
            lines.push(Line::default());
        }

        let (icon, icon_style, latency_text) = match &item.status {
            DiagStatus::Running => (spinner, palette.ice_bold, None),
            DiagStatus::Pass { latency_ms, .. } => (
                "●",
                palette.emerald_bold,
                latency_ms.map(|ms| format!("{ms} ms")),
            ),
            DiagStatus::Warn { latency_ms, .. } => (
                palette.warn_icon,
                palette.amber_bold,
                latency_ms.map(|ms| format!("{ms} ms")),
            ),
            DiagStatus::Fail { latency_ms, .. } => (
                "✕",
                palette.red_bold,
                latency_ms.map(|ms| format!("{ms} ms")),
            ),
        };

        // Title line: "<icon> <Name>" left, optional "<ms>" right
        let prefix = format!("{icon} ");
        let prefix_len = prefix.chars().count();
        let right_text = latency_text.unwrap_or_default();
        let right_len = right_text.chars().count();
        let name_budget = if right_len > 0 && width > prefix_len + right_len + 2 {
            width - prefix_len - right_len - 1
        } else {
            width.saturating_sub(prefix_len)
        };
        let display_name = truncate_text(item.name, name_budget);
        let name_len = display_name.chars().count();

        if right_len > 0 && prefix_len + name_len + 1 + right_len <= width {
            let gap = width - prefix_len - name_len - right_len;
            lines.push(Line::from(vec![
                Span::styled(prefix, icon_style),
                Span::styled(display_name, palette.section_title),
                Span::raw(" ".repeat(gap)),
                Span::styled(right_text, palette.value_muted),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled(prefix, icon_style),
                Span::styled(display_name, palette.section_title),
            ]));
        }

        // Summary + detail lines strictly word-wrapped on whitespace boundaries
        match &item.status {
            DiagStatus::Running => {
                for (_, text) in wrap_bullet("Checking…", width, "  ", "  ") {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(text, palette.hint),
                    ]));
                }
            }
            DiagStatus::Pass {
                summary, detail, ..
            } => {
                for (_, text) in wrap_bullet(summary, width, "  ", "  ") {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(text, palette.body_text),
                    ]));
                }
                if let Some(detail) = detail.as_deref().filter(|s| !s.is_empty()) {
                    for (_, text) in wrap_bullet(detail, width, "  ", "  ") {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(text, palette.hint),
                        ]));
                    }
                }
            }
            DiagStatus::Warn {
                summary, detail, ..
            } => {
                for (_, text) in wrap_bullet(summary, width, "  ", "  ") {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(text, palette.amber),
                    ]));
                }
                if let Some(detail) = detail.as_deref().filter(|s| !s.is_empty()) {
                    for (_, text) in wrap_bullet(detail, width, "  ", "  ") {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(text, palette.hint),
                        ]));
                    }
                }
            }
            DiagStatus::Fail {
                summary, detail, ..
            } => {
                for (_, text) in wrap_bullet(summary, width, "  ", "  ") {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(text, palette.red_bold),
                    ]));
                }
                if let Some(detail) = detail.as_deref().filter(|s| !s.is_empty()) {
                    for (_, text) in wrap_bullet(detail, width, "  ", "  ") {
                        lines.push(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(text, palette.hint),
                        ]));
                    }
                }
            }
        }
    }

    lines
}

fn render_diag_minimal(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &DiagnosticsTuiState,
    palette: Palette,
) {
    let text = if state.is_running() {
        format!(
            "{} vdpi Diag ({}/{DIAG_CHECK_COUNT})",
            state.spinner_glyph(),
            state.done_count()
        )
    } else {
        format!("vdpi Diag ({}/{DIAG_CHECK_COUNT})", state.pass_count())
    };
    frame.render_widget(
        Line::from(Span::styled(
            truncate_text(&text, usize::from(area.width)),
            palette.brand,
        )),
        Rect::new(area.x, area.y, area.width, 1),
    );
}

fn render_diagnostics_tui(frame: &mut Frame<'_>, state: &mut DiagnosticsTuiState, color: bool) {
    let area = frame.area();
    if area.is_empty() {
        return;
    }

    let palette = Palette::for_color(color);
    if area.width < 16 || area.height < 8 {
        render_diag_minimal(frame, area, state, palette);
        return;
    }

    let card_width = area.width.min(MAX_CARD_WIDTH);
    let card_height = area.height.min(MAX_CARD_HEIGHT);
    let card_area = centered_rect(area, card_width, card_height);
    let padding = if card_width >= 24 {
        Padding::horizontal(1)
    } else {
        Padding::ZERO
    };

    let block = Block::bordered()
        .border_type(if color {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(palette.border)
        .padding(padding);
    let inner = block.inner(card_area);
    frame.render_widget(block, card_area);

    if inner.is_empty() {
        return;
    }

    let width = usize::from(inner.width);
    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |ry: u16| Rect::new(inner.x, ry, inner.width, 1);

    // 1. Header row with live progress / result summary pill
    let (pill_text, pill_style) = if state.is_running() {
        let done = state.done_count();
        let text = if width >= 54 {
            format!(
                "{} Running checks ({done}/{DIAG_CHECK_COUNT})…",
                state.spinner_glyph()
            )
        } else {
            format!("{} {done}/{DIAG_CHECK_COUNT}…", state.spinner_glyph())
        };
        (text, palette.ice_bold)
    } else {
        let attention = state.attention_count();
        if attention == 0 {
            let text = if width >= 46 {
                "● All checks passed".to_string()
            } else {
                "● All passed".to_string()
            };
            (text, palette.emerald_bold)
        } else {
            let (icon, style) = if state.has_failure() {
                ("✕", palette.red_bold)
            } else {
                (palette.warn_icon, palette.amber_bold)
            };
            let noun = if attention == 1 {
                "check needs"
            } else {
                "checks need"
            };
            let text = if width >= 56 {
                format!("{icon} {attention} {noun} attention")
            } else {
                format!("{icon} {attention} attention")
            };
            (text, style)
        }
    };

    render_header_bar(
        frame,
        row(y),
        " · Network Diagnostics",
        " · Diagnostics",
        &pill_text,
        pill_style,
        palette,
    );
    y = y.saturating_add(1);

    let show_top_div = inner.height >= 10;
    let show_footer = inner.height >= 6;
    let show_bot_div = inner.height >= 9;

    if show_top_div && y < bottom {
        render_divider(frame, row(y), palette.divider);
        y = y.saturating_add(1);
    }

    let footer_reserve = u16::from(show_footer) + u16::from(show_bot_div);
    let content_bottom = bottom.saturating_sub(footer_reserve).max(y);
    let viewport_h = usize::from(content_bottom.saturating_sub(y));

    // 2. Scrollable 5-check list
    let first_pass = build_diag_rows(state, width, palette);
    let needs_scrollbar = first_pass.len() > viewport_h && width >= 12;
    let text_width = if needs_scrollbar {
        width.saturating_sub(2)
    } else {
        width
    };
    let rows = if needs_scrollbar {
        build_diag_rows(state, text_width, palette)
    } else {
        first_pass
    };

    state.last_total_rows = rows.len();
    state.last_viewport_rows = viewport_h;
    let max_scroll = state.last_total_rows.saturating_sub(viewport_h);
    state.scroll = state.scroll.min(max_scroll);

    for (offset, line) in rows
        .into_iter()
        .skip(state.scroll)
        .take(viewport_h)
        .enumerate()
    {
        let ry = y.saturating_add(offset as u16);
        frame.render_widget(line, Rect::new(inner.x, ry, text_width as u16, 1));
    }

    if needs_scrollbar && viewport_h > 0 {
        let bar_area = Rect::new(
            inner.x.saturating_add(inner.width.saturating_sub(1)),
            y,
            1,
            viewport_h as u16,
        );
        render_scrollbar(
            frame,
            bar_area,
            state.last_total_rows,
            viewport_h,
            state.scroll,
            palette,
        );
    }

    // 3. Bottom divider + footer
    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        let hints: Vec<(&str, &str)> = if width >= 46 {
            vec![("r", "re-run"), ("↑↓", "scroll"), ("enter / q", "back")]
        } else {
            vec![("r", "re-run"), ("↑↓", "scroll"), ("q", "back")]
        };
        render_footer_hints(frame, row(footer_y), &hints, palette);
    }
    if show_bot_div && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), palette.divider);
    }
}

/// Interactive Live Network Diagnostics TUI.
///
/// Runs 5 concurrent live checks (Service & Engine, VPN & Split Tunnel, Encrypted
/// DNS / DoH, TLS Handshake to `discord.com`, and TLS Handshake to `roblox.com`)
/// with smooth 100ms spinners, live streaming results over `tokio::sync::mpsc`,
/// `r` to re-run, `↑`/`↓` scrolling, and `Enter`/`q`/`Esc`/`Ctrl-C` to return to
/// Control Center with a concise summary string.
pub async fn run_diagnostics_tui(cfg: RuntimeConfig) -> Result<String> {
    if !is_interactive_tty() {
        let mut state = DiagnosticsTuiState::new_running();
        let (tx, mut rx) = mpsc::channel::<(u64, usize, DiagStatus)>(16);
        let mut tasks = JoinSet::new();
        spawn_diagnostics_run(&mut tasks, 1, cfg, tx);
        while state.is_running() {
            match rx.recv().await {
                Some((1, idx, status)) => state.set_result(idx, status),
                Some(_) => {}
                None => break,
            }
        }
        tasks.abort_all();
        return Ok(state.summary_string());
    }

    let color = color_enabled();
    let mut state = DiagnosticsTuiState::new_running();

    let mut guard =
        TerminalGuard::enter().context("failed to initialize Network Diagnostics TUI")?;
    let mut ev_reader = EventReaderGuard::spawn();

    let (res_tx, mut res_rx) = mpsc::channel::<(u64, usize, DiagStatus)>(16);
    let mut tasks = JoinSet::new();
    let mut run_id: u64 = 1;
    spawn_diagnostics_run(&mut tasks, run_id, cfg.clone(), res_tx.clone());

    let mut spinner = tokio::time::interval(SPINNER_INTERVAL);
    spinner.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        while tasks.try_join_next().is_some() {}

        guard
            .terminal
            .draw(|frame| render_diagnostics_tui(frame, &mut state, color))?;

        tokio::select! {
            maybe_ev = ev_reader.recv() => {
                let Some(ev) = maybe_ev else {
                    break;
                };
                match ev {
                    Event::Resize(..) => {}
                    Event::Key(key) => match handle_diag_key(&mut state, key) {
                        DiagKeyAction::Ignore => {}
                        DiagKeyAction::Redraw => {}
                        DiagKeyAction::Rerun => {
                            tasks.abort_all();
                            while tasks.try_join_next().is_some() {}
                            run_id = run_id.saturating_add(1);
                            state.reset_running();
                            spawn_diagnostics_run(&mut tasks, run_id, cfg.clone(), res_tx.clone());
                        }
                        DiagKeyAction::Back => break,
                    },
                    _ => {}
                }
            }
            maybe_res = res_rx.recv() => {
                if let Some((id, idx, status)) = maybe_res {
                    if id == run_id {
                        state.set_result(idx, status);
                    }
                }
            }
            _ = spinner.tick(), if state.is_running() => {
                state.spinner_tick = state.spinner_tick.wrapping_add(1);
            }
        }
    }

    tasks.abort_all();
    drop(ev_reader);
    drop(guard);

    Ok(state.summary_string())
}

// ============================================================================
// Unit Tests (`ratatui::backend::TestBackend`)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn press_ctrl(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
    }

    fn key_with_kind(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
    }

    fn render_update_buf(
        state: &mut UpdateTuiState,
        width: u16,
        height: u16,
        color: bool,
    ) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render_update_tui(frame, state, color))
            .expect("draw update frame");
        terminal.backend().buffer().clone()
    }

    fn render_diag_buf(
        state: &mut DiagnosticsTuiState,
        width: u16,
        height: u16,
        color: bool,
    ) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render_diagnostics_tui(frame, state, color))
            .expect("draw diagnostics frame");
        terminal.backend().buffer().clone()
    }

    fn buffer_text(buf: &Buffer) -> String {
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    fn assert_no_rgb_colors(buf: &Buffer) {
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let cell = &buf[(x, y)];
                assert!(
                    !matches!(cell.fg, Color::Rgb(..)),
                    "NO_COLOR emitted RGB fg {:?} at ({x},{y})",
                    cell.fg
                );
                assert!(
                    !matches!(cell.bg, Color::Rgb(..)),
                    "NO_COLOR emitted RGB bg {:?} at ({x},{y})",
                    cell.bg
                );
            }
        }
    }

    fn assert_outer_card_borders(buf: &Buffer, color: bool) {
        let text = buffer_text(buf);
        let (tl, tr, bl, br) = if color {
            ('╭', '╮', '╰', '╯')
        } else {
            ('┌', '┐', '└', '┘')
        };
        assert!(
            text.contains(tl) && text.contains(tr) && text.contains(bl) && text.contains(br),
            "expected outer card borders {tl}{tr}{bl}{br} (color={color}):\n{text}"
        );
    }

    fn sample_long_release_notes() -> Vec<ReleaseNoteLine> {
        parse_release_notes(Some(
            "\
### Highlights
- **Linux** and macOS TUN engines now automatically recover DNS after sleep/wake cycles (verified across Ubuntu and Fedora).
- Interactive split-tunnel application picker with live fuzzy search and instant routing mode switching.
- Hardened SHA-256 verification and atomic binary replacement on Windows, macOS, and Linux.
- Improved DoH failover behavior when ISP middleboxes throttle primary Cloudflare endpoints.
- Added live network diagnostics panel with real TLS handshakes and millisecond latency readout.
- Reduced background daemon idle memory footprint by tightening smoltcp buffer pools.
",
        ))
    }

    fn sample_up_to_date_info() -> ReleaseCheckInfo {
        ReleaseCheckInfo {
            current_version: "0.5.6".to_string(),
            latest_tag: "v0.5.6".to_string(),
            html_url: "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.5.6".to_string(),
            relation: VersionRelation::Same,
            notes: sample_long_release_notes(),
            source: "GitHub Releases".to_string(),
        }
    }

    fn sample_available_info() -> ReleaseCheckInfo {
        ReleaseCheckInfo {
            current_version: "0.5.5".to_string(),
            latest_tag: "v0.5.6".to_string(),
            html_url: "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.5.6".to_string(),
            relation: VersionRelation::Newer,
            notes: sample_long_release_notes(),
            source: "GitHub Releases".to_string(),
        }
    }

    fn sample_all_pass_diag() -> DiagnosticsTuiState {
        let mut state = DiagnosticsTuiState::new_running();
        state.set_result(
            0,
            DiagStatus::Pass {
                summary: "TUN active (utun4)".to_string(),
                detail: Some("v0.5.6 · 18.4 MB RSS · desync combo".to_string()),
                latency_ms: None,
            },
        );
        state.set_result(
            1,
            DiagStatus::Pass {
                summary: "No VPN conflict · Include (2 apps)".to_string(),
                detail: None,
                latency_ms: None,
            },
        );
        state.set_result(
            2,
            DiagStatus::Pass {
                summary: "discord.com resolved (4 IPs)".to_string(),
                detail: Some("DoH via 1.1.1.1 · 162.159.135.232".to_string()),
                latency_ms: Some(28),
            },
        );
        state.set_result(
            3,
            DiagStatus::Pass {
                summary: "TLS verified (HTTP 200)".to_string(),
                detail: Some("Via active TUN engine".to_string()),
                latency_ms: Some(112),
            },
        );
        state.set_result(
            4,
            DiagStatus::Pass {
                summary: "TLS verified (HTTP 301)".to_string(),
                detail: Some("Via active TUN engine".to_string()),
                latency_ms: Some(94),
            },
        );
        state
    }

    fn sample_mixed_diag() -> DiagnosticsTuiState {
        let mut state = DiagnosticsTuiState::new_running();
        state.set_result(
            0,
            DiagStatus::Pass {
                summary: "Proxy active (127.0.0.1:8080)".to_string(),
                detail: Some("v0.5.6 · 14.2 MB RSS".to_string()),
                latency_ms: None,
            },
        );
        state.set_result(
            1,
            DiagStatus::Warn {
                summary: "VPN conflict: WireGuard (wg0)".to_string(),
                detail: Some("Split tunnel: Exclude (1 app)".to_string()),
                latency_ms: None,
            },
        );
        state.set_result(
            2,
            DiagStatus::Pass {
                summary: "discord.com resolved (2 IPs)".to_string(),
                detail: Some("DoH via 94.140.14.14 · 162.159.136.232".to_string()),
                latency_ms: Some(41),
            },
        );
        state.set_result(
            3,
            DiagStatus::Pass {
                summary: "TLS verified (HTTP 200)".to_string(),
                detail: Some("Via local proxy 127.0.0.1:8080".to_string()),
                latency_ms: Some(135),
            },
        );
        state.set_result(
            4,
            DiagStatus::Fail {
                summary: "TLS handshake failed".to_string(),
                detail: Some(
                    "Connection reset by peer during handshake (verified on Linux middlebox)"
                        .to_string(),
                ),
                latency_ms: Some(4012),
            },
        );
        state
    }

    #[test]
    fn word_wrapping_never_splits_normal_words_mid_word() {
        let input = "Linux and macOS TUN engines now automatically recover DNS after sleep/wake cycles (verified).";
        for width in [20, 26, 32, 40, 48] {
            let wrapped = wrap_words(input, width);
            assert!(!wrapped.is_empty());
            for line in &wrapped {
                assert!(
                    line.chars().count() <= width,
                    "line {line:?} exceeded width {width}"
                );
            }
            let rejoined = wrapped.join(" ");
            assert_eq!(rejoined, input, "wrapping altered words at width {width}");
            // Explicitly ensure words like "Linux" or "(verified)." are intact on single lines.
            assert!(
                wrapped.iter().any(|l| l.contains("Linux")),
                "word 'Linux' was split at width {width}: {wrapped:?}"
            );
            assert!(
                wrapped.iter().any(|l| l.contains("(verified).")),
                "token '(verified).' was split at width {width}: {wrapped:?}"
            );
        }

        let bullet = wrap_bullet(input, 36, "  • ", "    ");
        assert!(bullet.len() >= 3);
        assert_eq!(bullet[0].0, "  • ");
        assert_eq!(bullet[1].0, "    ");
        for (prefix, text) in &bullet {
            assert!(prefix.chars().count() + text.chars().count() <= 36);
        }
    }

    #[test]
    fn update_tui_renders_all_states_across_target_sizes_and_no_color() {
        let sizes = [(100, 30), (80, 24), (60, 22), (46, 18)];

        for &(w, h) in &sizes {
            for &color in &[true, false] {
                // 1. Checking / loading state
                let mut checking = UpdateTuiState::new_checking("0.5.6");
                checking.spinner_tick = 3;
                let buf = render_update_buf(&mut checking, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(text.contains("vdpi"), "missing brand at {w}x{h}:\n{text}");
                assert!(
                    text.contains("Checking"),
                    "missing checking status at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }

                // 2. Up to date with long wrapped release notes
                let mut up_to_date = UpdateTuiState::new_checking("0.5.6");
                up_to_date.apply_check_result(Ok(sample_up_to_date_info()));
                let buf = render_update_buf(&mut up_to_date, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("Up to date"),
                    "missing Up to date pill at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("v0.5.6"),
                    "missing version at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("What's New"),
                    "missing What's New section at {w}x{h}:\n{text}"
                );
                assert!(
                    !text.contains("Linu\n"),
                    "mid-word wrap detected at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }

                // 3. Update available with primary action bar & NO_COLOR REVERSED check
                let mut available = UpdateTuiState::new_checking("0.5.5");
                available.apply_check_result(Ok(sample_available_info()));
                let buf = render_update_buf(&mut available, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("[u] Install v0.5.6"),
                    "missing primary install action bar at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                    let mut saw_bold = false;
                    let mut saw_dim = false;
                    let mut saw_reversed = false;
                    for y in 0..buf.area.height {
                        for x in 0..buf.area.width {
                            let m = buf[(x, y)].modifier;
                            saw_bold |= m.contains(Modifier::BOLD);
                            saw_dim |= m.contains(Modifier::DIM);
                            saw_reversed |= m.contains(Modifier::REVERSED);
                        }
                    }
                    assert!(saw_bold, "NO_COLOR update available at {w}x{h} needs BOLD");
                    assert!(saw_dim, "NO_COLOR update available at {w}x{h} needs DIM");
                    assert!(
                        saw_reversed,
                        "NO_COLOR update available at {w}x{h} needs REVERSED on primary action"
                    );
                }

                // 4. Error state
                let mut errored = UpdateTuiState::new_checking("0.5.6");
                errored.apply_check_result(Err(
                    "GitHub Releases API returned HTTP 403 rate limit exceeded for unauthenticated requests"
                        .to_string(),
                ));
                let buf = render_update_buf(&mut errored, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("Check failed"),
                    "missing error pill at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("retry"),
                    "missing retry footer at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }
            }
        }
    }

    #[test]
    fn diagnostics_tui_renders_all_states_across_target_sizes_and_no_color() {
        let sizes = [(100, 30), (80, 24), (60, 22), (46, 18)];

        for &(w, h) in &sizes {
            for &color in &[true, false] {
                // 1. Running (partial progress 2/5)
                let mut running = DiagnosticsTuiState::new_running();
                running.spinner_tick = 2;
                running.set_result(
                    0,
                    DiagStatus::Pass {
                        summary: "TUN active (utun4)".to_string(),
                        detail: None,
                        latency_ms: None,
                    },
                );
                running.set_result(
                    1,
                    DiagStatus::Pass {
                        summary: "No VPN conflict · All apps".to_string(),
                        detail: None,
                        latency_ms: None,
                    },
                );
                let buf = render_diag_buf(&mut running, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("2/5"),
                    "missing live progress 2/5 at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("Service & Engine"),
                    "missing check 1 at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }

                // 2. All pass (5/5)
                let mut all_pass = sample_all_pass_diag();
                let buf = render_diag_buf(&mut all_pass, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("All checks passed") || text.contains("All passed"),
                    "missing all-passed pill at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("28 ms"),
                    "missing DNS latency at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }

                // 3. Mixed pass / warn / fail
                let mut mixed = sample_mixed_diag();
                let buf = render_diag_buf(&mut mixed, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("attention"),
                    "missing attention pill at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("WireGuard"),
                    "missing VPN warn summary at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }
            }
        }
    }

    #[test]
    fn tiny_terminal_sizes_render_without_panicking() {
        let mut update = UpdateTuiState::new_checking("0.5.6");
        let mut diag = sample_mixed_diag();
        for &(w, h) in &[(0, 0), (1, 1), (10, 4), (15, 7), (20, 8)] {
            for &color in &[true, false] {
                let _ = render_update_buf(&mut update, w, h, color);
                let _ = render_diag_buf(&mut diag, w, h, color);
            }
        }
    }

    #[test]
    fn update_key_handling_respects_release_cancel_install_and_scroll() {
        // Checking phase: q / Esc / Ctrl-C cancels immediately, Release ignored, Enter ignored
        let mut checking = UpdateTuiState::new_checking("0.5.6");
        assert_eq!(
            handle_update_key(
                &mut checking,
                key_with_kind(KeyCode::Char('q'), KeyEventKind::Release)
            ),
            UpdateKeyAction::Ignore
        );
        assert_eq!(
            handle_update_key(&mut checking, press(KeyCode::Enter)),
            UpdateKeyAction::Ignore
        );
        assert_eq!(
            handle_update_key(&mut checking, press(KeyCode::Char('q'))),
            UpdateKeyAction::Back
        );
        assert_eq!(
            handle_update_key(&mut checking, press(KeyCode::Esc)),
            UpdateKeyAction::Back
        );
        assert_eq!(
            handle_update_key(&mut checking, press_ctrl('c')),
            UpdateKeyAction::Back
        );

        // Up to date: Enter returns Back, u is ignored, r re-checks, arrows scroll
        let mut up_to_date = UpdateTuiState::new_checking("0.5.6");
        up_to_date.apply_check_result(Ok(sample_up_to_date_info()));
        let _ = render_update_buf(&mut up_to_date, 46, 18, true);
        assert_eq!(
            handle_update_key(&mut up_to_date, press(KeyCode::Char('u'))),
            UpdateKeyAction::Ignore
        );
        assert_eq!(
            handle_update_key(&mut up_to_date, press(KeyCode::Enter)),
            UpdateKeyAction::Back
        );
        assert_eq!(
            handle_update_key(&mut up_to_date, press(KeyCode::Char('r'))),
            UpdateKeyAction::Recheck
        );
        assert!(up_to_date.last_total_rows > up_to_date.last_viewport_rows);
        assert_eq!(
            handle_update_key(&mut up_to_date, press(KeyCode::Down)),
            UpdateKeyAction::Redraw
        );
        assert_eq!(up_to_date.scroll, 1);
        assert_eq!(
            handle_update_key(&mut up_to_date, press(KeyCode::Up)),
            UpdateKeyAction::Redraw
        );
        assert_eq!(up_to_date.scroll, 0);

        // Available: u and Enter both trigger Install
        let mut available = UpdateTuiState::new_checking("0.5.5");
        available.apply_check_result(Ok(sample_available_info()));
        assert!(matches!(
            handle_update_key(&mut available, press(KeyCode::Char('u'))),
            UpdateKeyAction::Install(ref info) if info.latest_tag == "v0.5.6"
        ));
        assert!(matches!(
            handle_update_key(&mut available, press(KeyCode::Enter)),
            UpdateKeyAction::Install(ref info) if info.latest_tag == "v0.5.6"
        ));
    }

    #[test]
    fn diagnostics_key_handling_and_summary_strings() {
        let state = sample_all_pass_diag();
        assert_eq!(state.summary_string(), "Diagnostics passed (5/5)");

        let mut mixed = sample_mixed_diag();
        assert_eq!(mixed.summary_string(), "Diagnostics complete (3/5 passed)");
        let _ = render_diag_buf(&mut mixed, 46, 18, true);
        assert!(mixed.last_total_rows > mixed.last_viewport_rows);

        // Windows ConPTY Release event ignored
        assert_eq!(
            handle_diag_key(
                &mut mixed,
                key_with_kind(KeyCode::Char('q'), KeyEventKind::Release)
            ),
            DiagKeyAction::Ignore
        );
        assert_eq!(
            handle_diag_key(&mut mixed, press(KeyCode::Down)),
            DiagKeyAction::Redraw
        );
        assert_eq!(mixed.scroll, 1);
        assert_eq!(
            handle_diag_key(&mut mixed, press(KeyCode::Home)),
            DiagKeyAction::Redraw
        );
        assert_eq!(mixed.scroll, 0);
        assert_eq!(
            handle_diag_key(&mut mixed, press(KeyCode::Char('r'))),
            DiagKeyAction::Rerun
        );
        assert_eq!(
            handle_diag_key(&mut mixed, press(KeyCode::Enter)),
            DiagKeyAction::Back
        );
        assert_eq!(
            handle_diag_key(&mut mixed, press_ctrl('c')),
            DiagKeyAction::Back
        );

        let running = DiagnosticsTuiState::new_running();
        assert_eq!(
            running.summary_string(),
            "Diagnostics cancelled (0/5 complete, 0 passed)"
        );
    }
}
