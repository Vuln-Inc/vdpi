use super::{
    build_menu_with_options, dns_preset_index, format_dns_label, is_custom_dns, shorten_custom_dns,
    Choice, LauncherMenu, MenuItem, StatusRow, StatusTone, CUSTOM_DNS_HINT, DNS_PRESETS,
};
use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Padding};
use ratatui::{Frame, Terminal};
use std::borrow::Cow;
use std::io;
use vdpi::server::REPOSITORY_URL;
use vdpi::service::{ControlCenterStatus, ServiceState};
use vdpi_core::config::{EngineMode, SplitTunnelConfig};

const MAX_CARD_WIDTH: u16 = 72;
const MAX_NOTICE_LINES: usize = 2;
const WINDOWS_TUN_TIP: &str = "Tip: Switch to TUN mode for Roblox & Discord voice.";
const VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const MAX_RULE_COLS: usize = 68;
const RULE: &str = "────────────────────────────────────────────────────────────────────";
const KEY_BADGES: [&str; 9] = [
    "[1]", "[2]", "[3]", "[4]", "[5]", "[6]", "[7]", "[8]", "[9]",
];
const RANGE_LABELS: [&str; 9] = ["1", "1-2", "1-3", "1-4", "1-5", "1-6", "1-7", "1-8", "1-9"];
const COMPACT_VPN_BADGE: &str = "[VPN]";
const DNS_PICKER_ITEM_COUNT: usize = DNS_PRESETS.len() + 1;
const MAX_CUSTOM_DNS_INPUT_CHARS: usize = 200;
const CUSTOM_DNS_PLACEHOLDER: &str = "IP or https:// DoH URL";
const CUSTOM_DNS_EDITOR_HINT: &str =
    "IPv4, IPv6, or https:// DoH URL (e.g. 76.76.2.0 or https://dns.nextdns.io/id)";
const UNINSTALL_CONFIRM_BODY: &str = "This stops the background service, removes installed files and PATH entries, and restores routes & proxies.";

// Restrained cool slate / white / emerald / ice-blue / semantic amber & red palette.
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

#[derive(Debug, Clone, Copy)]
struct Palette {
    border: Style,
    divider: Style,
    brand: Style,
    version: Style,
    repo: Style,
    status_label: Style,
    status_active: Style,
    status_accent: Style,
    status_warn: Style,
    status_neutral: Style,
    status_warn_dot: &'static str,
    danger_bold: Style,
    active_row: Style,
    active_marker: Style,
    active_badge: Style,
    active_title: Style,
    active_hint: Style,
    inactive_badge: Style,
    inactive_title: Style,
    inactive_hint: Style,
    input_bg: Style,
    footer_key: Style,
    footer_text: Style,
}

impl Palette {
    const fn for_color(color: bool) -> Self {
        if color {
            Self {
                border: Style::new().fg(BORDER_SLATE),
                divider: Style::new().fg(DIVIDER_SLATE),
                brand: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                version: Style::new().fg(STEEL_MUTED),
                repo: Style::new().fg(SLATE_DIM),
                status_label: Style::new().fg(SLATE_DIM),
                status_active: Style::new().fg(EMERALD_ACTIVE),
                status_accent: Style::new().fg(ICE_BLUE),
                status_warn: Style::new().fg(AMBER_WARN),
                status_neutral: Style::new().fg(STEEL_MUTED),
                status_warn_dot: "● ",
                danger_bold: Style::new().fg(RED_DANGER).add_modifier(Modifier::BOLD),
                active_row: Style::new().bg(ACTIVE_BG),
                active_marker: Style::new().fg(ICE_BLUE).add_modifier(Modifier::BOLD),
                active_badge: Style::new().fg(STEEL_MUTED),
                active_title: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                active_hint: Style::new().fg(STEEL_MUTED),
                inactive_badge: Style::new().fg(SLATE_DIM),
                inactive_title: Style::new().fg(TEXT_LIGHT),
                inactive_hint: Style::new().fg(SLATE_DIM),
                input_bg: Style::new().fg(TEXT_WHITE).bg(ACTIVE_BG),
                footer_key: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                footer_text: Style::new().fg(SLATE_DIM),
            }
        } else {
            let plain = Style::new();
            let bold = Style::new().add_modifier(Modifier::BOLD);
            let dim = Style::new().add_modifier(Modifier::DIM);
            let rev = Style::new().add_modifier(Modifier::REVERSED);
            Self {
                border: plain,
                divider: dim,
                brand: bold,
                version: dim,
                repo: dim,
                status_label: dim,
                status_active: bold,
                status_accent: bold,
                status_warn: bold,
                status_neutral: plain,
                status_warn_dot: "! ",
                danger_bold: bold,
                active_row: rev,
                active_marker: bold,
                active_badge: bold,
                active_title: bold,
                active_hint: dim,
                inactive_badge: dim,
                inactive_title: plain,
                inactive_hint: dim,
                input_bg: rev,
                footer_key: bold,
                footer_text: dim,
            }
        }
    }

    const fn status(self, tone: StatusTone) -> Style {
        match tone {
            StatusTone::Active => self.status_active,
            StatusTone::Accent => self.status_accent,
            StatusTone::Warning => self.status_warn,
            StatusTone::Neutral => self.status_neutral,
        }
    }

    const fn status_dot(self, tone: StatusTone) -> &'static str {
        match tone {
            StatusTone::Warning => self.status_warn_dot,
            StatusTone::Active | StatusTone::Accent | StatusTone::Neutral => "● ",
        }
    }
}

#[derive(Clone, Copy)]
struct RenderCtx {
    palette: Palette,
    inset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UiState {
    menu: LauncherMenu,
    selected: usize,
    confirming_uninstall: bool,
    selecting_dns: bool,
    dns_selected: usize,
    editing_custom_dns: bool,
    custom_dns_input: String,
    custom_dns_cursor: usize,
    custom_dns_error: Option<String>,
    configured_dns: String,
    split_tunnel: SplitTunnelConfig,
    show_tun_tip: bool,
}

fn should_show_tun_tip_for_platform(is_windows: bool, status: &ControlCenterStatus) -> bool {
    is_windows
        && status.installed.is_none()
        && status.service_state == ServiceState::NotInstalled
        && status
            .live_engine
            .as_ref()
            .map_or(status.configured_engine, |live| live.engine)
            == EngineMode::Proxy
}

impl UiState {
    #[cfg(test)]
    fn new(status: &ControlCenterStatus, notice: Option<&str>) -> Self {
        Self::new_with_dns(status, notice, DNS_PRESETS[0].addr)
    }

    #[allow(dead_code)]
    fn new_with_dns(
        status: &ControlCenterStatus,
        notice: Option<&str>,
        configured_dns: &str,
    ) -> Self {
        Self::new_with_options(
            status,
            notice,
            configured_dns,
            &SplitTunnelConfig::default(),
        )
    }

    fn new_with_options(
        status: &ControlCenterStatus,
        notice: Option<&str>,
        configured_dns: &str,
        split_tunnel: &SplitTunnelConfig,
    ) -> Self {
        let dns = configured_dns.trim();
        let dns = if dns.is_empty() {
            DNS_PRESETS[0].addr
        } else {
            dns
        };
        Self {
            menu: build_menu_with_options(status, notice, dns, split_tunnel),
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: dns_preset_index(dns),
            editing_custom_dns: false,
            custom_dns_input: String::new(),
            custom_dns_cursor: 0,
            custom_dns_error: None,
            configured_dns: dns.to_string(),
            split_tunnel: split_tunnel.clone(),
            show_tun_tip: should_show_tun_tip_for_platform(cfg!(target_os = "windows"), status),
        }
    }

    fn open_dns_picker(&mut self) {
        self.dns_selected = dns_preset_index(&self.configured_dns);
        self.selecting_dns = true;
        self.editing_custom_dns = false;
        self.custom_dns_input.clear();
        self.custom_dns_cursor = 0;
        self.custom_dns_error = None;
    }

    fn open_custom_dns_editor(&mut self) {
        self.dns_selected = DNS_PRESETS.len();
        self.editing_custom_dns = true;
        self.custom_dns_input = if is_custom_dns(&self.configured_dns) {
            self.configured_dns
                .trim()
                .chars()
                .take(MAX_CUSTOM_DNS_INPUT_CHARS)
                .collect()
        } else {
            String::new()
        };
        self.custom_dns_cursor = self.custom_dns_input.chars().count();
        self.custom_dns_error = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Density {
    Spacious,
    Cozy,
    CompactActiveHint,
    CompactDivided,
    CompactTight,
    CompactMinimal,
}

#[derive(Debug, Clone, Copy)]
struct LayoutPlan {
    density: Density,
    visible_status_rows: usize,
    show_tun_tip: bool,
    visible_notice_rows: usize,
    show_footer: bool,
    card_height: u16,
}

impl LayoutPlan {
    const fn show_all_hints(self) -> bool {
        matches!(self.density, Density::Spacious | Density::Cozy)
    }

    const fn show_active_hint(self) -> bool {
        matches!(self.density, Density::CompactActiveHint)
    }

    const fn item_gap(self) -> bool {
        matches!(self.density, Density::Spacious)
    }

    const fn breathing_gaps(self) -> bool {
        matches!(self.density, Density::Spacious)
    }

    const fn top_divider(self) -> bool {
        !matches!(self.density, Density::CompactMinimal)
    }

    const fn status_divider(self) -> bool {
        !matches!(self.density, Density::CompactMinimal)
            && (self.visible_status_rows > 0 || self.show_tun_tip || self.visible_notice_rows > 0)
    }

    const fn bottom_divider(self) -> bool {
        matches!(
            self.density,
            Density::Spacious
                | Density::Cozy
                | Density::CompactActiveHint
                | Density::CompactDivided
        )
    }

    fn compute(
        area_height: u16,
        item_count: usize,
        status_count: usize,
        notice_rows: usize,
        has_tip: bool,
    ) -> Self {
        let n = u16::try_from(item_count).unwrap_or(u16::MAX);
        let s = u16::try_from(status_count).unwrap_or(u16::MAX);
        let t = u16::from(has_tip);
        let m = u16::try_from(notice_rows).unwrap_or(u16::MAX);
        let status_div = u16::from(status_count > 0 || has_tip || notice_rows > 0);
        let status_block = s
            .saturating_add(t)
            .saturating_add(m)
            .saturating_add(status_div);

        // Tall terminals (>= 28 rows) can expand to show per-item hints for every entry.
        if area_height >= 28 {
            let spacious_items = if n == 0 {
                0
            } else {
                n.saturating_mul(2).saturating_add(n - 1)
            };
            // borders(2) + header(1) + top_div(1) + status_block + top_gap(1) + items + bot_gap(1) + bot_div(1) + footer(1)
            let spacious_h = 8u16
                .saturating_add(status_block)
                .saturating_add(spacious_items);
            if area_height >= spacious_h {
                return Self {
                    density: Density::Spacious,
                    visible_status_rows: status_count,
                    show_tun_tip: has_tip,
                    visible_notice_rows: notice_rows,
                    show_footer: true,
                    card_height: spacious_h,
                };
            }

            // borders(2) + header(1) + top_div(1) + status_block + items(2*n) + bot_div(1) + footer(1)
            let cozy_h = 6u16
                .saturating_add(status_block)
                .saturating_add(n.saturating_mul(2));
            if area_height >= cozy_h {
                return Self {
                    density: Density::Cozy,
                    visible_status_rows: status_count,
                    show_tun_tip: has_tip,
                    visible_notice_rows: notice_rows,
                    show_footer: true,
                    card_height: cozy_h,
                };
            }
        }

        // Compact 1-line items + 1-line hint right below the selected item: fits 80x24 and 46x18 cleanly.
        // borders(2) + header(1) + top_div(1) + status_block + items(n) + active_hint(0|1) + bot_div(1) + footer(1)
        let active_hint_h = 6u16
            .saturating_add(status_block)
            .saturating_add(n)
            .saturating_add(u16::from(n > 0));
        if area_height >= active_hint_h {
            return Self {
                density: Density::CompactActiveHint,
                visible_status_rows: status_count,
                show_tun_tip: has_tip,
                visible_notice_rows: notice_rows,
                show_footer: true,
                card_height: active_hint_h,
            };
        }

        // borders(2) + header(1) + top_div(1) + status_block + items(n) + bot_div(1) + footer(1)
        let compact_divided_h = 6u16.saturating_add(status_block).saturating_add(n);
        if area_height >= compact_divided_h {
            return Self {
                density: Density::CompactDivided,
                visible_status_rows: status_count,
                show_tun_tip: has_tip,
                visible_notice_rows: notice_rows,
                show_footer: true,
                card_height: compact_divided_h,
            };
        }

        // borders(2) + header(1) + top_div(1) + status_block + items(n) + footer(1)
        let compact_tight_h = 5u16.saturating_add(status_block).saturating_add(n);
        if area_height >= compact_tight_h {
            return Self {
                density: Density::CompactTight,
                visible_status_rows: status_count,
                show_tun_tip: has_tip,
                visible_notice_rows: notice_rows,
                show_footer: true,
                card_height: compact_tight_h,
            };
        }

        // borders(2) + header(1) + status(s) + tip(t) + notice(m) + items(n) + footer(1)
        let compact_minimal_h = 4u16
            .saturating_add(s)
            .saturating_add(t)
            .saturating_add(m)
            .saturating_add(n);
        if area_height >= compact_minimal_h {
            return Self {
                density: Density::CompactMinimal,
                visible_status_rows: status_count,
                show_tun_tip: has_tip,
                visible_notice_rows: notice_rows,
                show_footer: true,
                card_height: compact_minimal_h,
            };
        }

        // Short terminal fallback: guarantee header and visible selected item(s), scrolling if needed.
        let show_footer = area_height >= 5;
        let inner_height = area_height.saturating_sub(2);
        let remaining = inner_height
            .saturating_sub(1) // header
            .saturating_sub(u16::from(show_footer));
        let min_items = n.min(2);

        let (visible_status_rows, show_tun_tip, visible_notice_rows) = if remaining
            >= s.saturating_add(t)
                .saturating_add(m)
                .saturating_add(min_items)
        {
            (status_count, has_tip, notice_rows)
        } else if remaining >= s.saturating_add(m).saturating_add(min_items) {
            (status_count, false, notice_rows)
        } else if notice_rows > 1 && remaining >= s.saturating_add(1).saturating_add(min_items) {
            (status_count, false, 1)
        } else if remaining >= s.saturating_add(min_items) {
            (status_count, false, 0)
        } else if status_count > 0 && remaining >= 1u16.saturating_add(min_items) {
            (1, false, 0)
        } else {
            (0, false, 0)
        };

        Self {
            density: Density::CompactMinimal,
            visible_status_rows,
            show_tun_tip,
            visible_notice_rows,
            show_footer,
            card_height: area_height,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ConfirmLayoutPlan {
    show_top_divider: bool,
    show_status: bool,
    show_status_divider: bool,
    show_bottom_divider: bool,
    show_footer: bool,
    card_height: u16,
}

impl ConfirmLayoutPlan {
    fn compute(area_height: u16, status_count: usize, body_lines: usize) -> Self {
        let s = u16::try_from(status_count).unwrap_or(u16::MAX);
        let b = u16::try_from(body_lines).unwrap_or(u16::MAX);
        let has_status = status_count > 0;
        let status_block = if has_status { s.saturating_add(1) } else { 0 };
        // Tight confirm body: header(1) + wrapped body(b) + prompt(1).
        let tight_body = b.saturating_add(2);

        // Spacious: symmetric top(1) + mid(1) + mid(1) + bottom(1) gaps around confirm block.
        // borders(2) + header(1) + top_div(1) + status_block + (tight_body + 4) + bot_div(1) + footer(1)
        let spacious_h = 10u16
            .saturating_add(status_block)
            .saturating_add(tight_body);
        if area_height >= spacious_h {
            return Self {
                show_top_divider: true,
                show_status: has_status,
                show_status_divider: has_status,
                show_bottom_divider: true,
                show_footer: true,
                card_height: spacious_h,
            };
        }

        // Cozy: header(1) + mid_gap_1(1) + body(b) + mid_gap_2(1) + prompt(1).
        let cozy_h = 8u16.saturating_add(status_block).saturating_add(tight_body);
        if area_height >= cozy_h {
            return Self {
                show_top_divider: true,
                show_status: has_status,
                show_status_divider: has_status,
                show_bottom_divider: true,
                show_footer: true,
                card_height: cozy_h,
            };
        }

        // Compact + prompt gap: header(1) + body(b) + mid_gap_2(1) + prompt(1).
        let gap_h = 7u16.saturating_add(status_block).saturating_add(tight_body);
        if area_height >= gap_h {
            return Self {
                show_top_divider: true,
                show_status: has_status,
                show_status_divider: has_status,
                show_bottom_divider: true,
                show_footer: true,
                card_height: gap_h,
            };
        }

        // Compact divided with status.
        let divided_h = 6u16.saturating_add(status_block).saturating_add(tight_body);
        if area_height >= divided_h {
            return Self {
                show_top_divider: true,
                show_status: has_status,
                show_status_divider: has_status,
                show_bottom_divider: true,
                show_footer: true,
                card_height: divided_h,
            };
        }

        // Tight with status (drop bottom divider).
        let tight_status_h = 5u16.saturating_add(status_block).saturating_add(tight_body);
        if area_height >= tight_status_h {
            return Self {
                show_top_divider: true,
                show_status: has_status,
                show_status_divider: has_status,
                show_bottom_divider: false,
                show_footer: true,
                card_height: tight_status_h,
            };
        }

        // Without status rows, keep dividers + footer.
        let no_status_divided_h = 6u16.saturating_add(tight_body);
        if area_height >= no_status_divided_h {
            return Self {
                show_top_divider: true,
                show_status: false,
                show_status_divider: false,
                show_bottom_divider: true,
                show_footer: true,
                card_height: no_status_divided_h,
            };
        }

        // Without status rows, drop bottom divider.
        let no_status_tight_h = 5u16.saturating_add(tight_body);
        if area_height >= no_status_tight_h {
            return Self {
                show_top_divider: true,
                show_status: false,
                show_status_divider: false,
                show_bottom_divider: false,
                show_footer: true,
                card_height: no_status_tight_h,
            };
        }

        // Short terminal fallback.
        Self {
            show_top_divider: area_height >= 8,
            show_status: false,
            show_status_divider: false,
            show_bottom_divider: false,
            show_footer: area_height >= 7,
            card_height: area_height,
        }
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        crate::tui_dashboard::install_tui_panic_hook();
        terminal::enable_raw_mode()?;
        crate::tui_dashboard::mark_tui_active(true);
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, EnableBracketedPaste, Hide) {
            if crate::tui_dashboard::take_tui_active() {
                let _ = execute!(stdout, DisableBracketedPaste, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                if crate::tui_dashboard::take_tui_active() {
                    let _ = execute!(
                        io::stdout(),
                        DisableBracketedPaste,
                        LeaveAlternateScreen,
                        Show
                    );
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
        if crate::tui_dashboard::take_tui_active() {
            let _ = execute!(
                self.terminal.backend_mut(),
                DisableBracketedPaste,
                LeaveAlternateScreen,
                Show
            );
            let _ = terminal::disable_raw_mode();
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Redraw,
    Refresh,
    Finish(Choice),
    Ignore,
}

#[allow(dead_code)]
pub(super) fn choose<F>(
    color: bool,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    choose_with_options(
        color,
        initial_status,
        notice,
        configured_dns,
        &SplitTunnelConfig::default(),
        refresh,
    )
}

pub(super) fn choose_with_options<F>(
    color: bool,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut state = UiState::new_with_options(initial_status, notice, configured_dns, split_tunnel);
    if state.menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }
    let mut guard = TerminalGuard::enter()?;

    loop {
        guard.terminal.draw(|frame| render(frame, &state, color))?;
        loop {
            match event::read()? {
                Event::Resize(..) => break,
                Event::Paste(text) => {
                    if handle_paste(&mut state, &text) == Action::Redraw {
                        break;
                    }
                }
                Event::Key(key) => match handle_key(&mut state, key) {
                    Action::Redraw => break,
                    Action::Refresh => {
                        let latest = refresh();
                        apply_refresh(&mut state, &latest);
                        if state.menu.items.is_empty() {
                            return Ok(Choice::Cancel);
                        }
                        break;
                    }
                    Action::Finish(choice) => return Ok(choice),
                    Action::Ignore => {}
                },
                _ => {}
            }
        }
    }
}

fn apply_refresh(state: &mut UiState, latest: &ControlCenterStatus) {
    state.menu = build_menu_with_options(
        latest,
        Some("Status refreshed."),
        &state.configured_dns,
        &state.split_tunnel,
    );
    state.confirming_uninstall = false;
    state.selecting_dns = false;
    state.editing_custom_dns = false;
    state.custom_dns_input.clear();
    state.custom_dns_cursor = 0;
    state.custom_dns_error = None;
    state.show_tun_tip = should_show_tun_tip_for_platform(cfg!(target_os = "windows"), latest);
    if state.menu.items.is_empty() {
        state.selected = 0;
    } else {
        state.selected = state.selected.min(state.menu.items.len() - 1);
    }
}

fn is_altgr_char(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char(_))
        && (key.modifiers - KeyModifiers::SHIFT) == (KeyModifiers::CONTROL | KeyModifiers::ALT)
}

fn first_non_empty_pasted_line(pasted: &str) -> &str {
    pasted
        .split(['\r', '\n'])
        .map(str::trim)
        .find(|line| line.chars().any(|ch| !ch.is_control()))
        .unwrap_or("")
}

fn handle_paste(state: &mut UiState, pasted: &str) -> Action {
    if !(state.selecting_dns && state.editing_custom_dns) {
        return Action::Ignore;
    }
    let first_line = first_non_empty_pasted_line(pasted);
    let mut current_len = state.custom_dns_input.chars().count();
    let mut cursor = state.custom_dns_cursor.min(current_len);
    let mut byte_idx = char_to_byte_idx(&state.custom_dns_input, cursor);
    let mut changed = false;
    for ch in first_line.chars() {
        if ch.is_control() {
            continue;
        }
        if current_len >= MAX_CUSTOM_DNS_INPUT_CHARS {
            break;
        }
        state.custom_dns_input.insert(byte_idx, ch);
        byte_idx += ch.len_utf8();
        cursor += 1;
        current_len += 1;
        changed = true;
    }
    if changed {
        state.custom_dns_cursor = cursor;
        state.custom_dns_error = None;
        Action::Redraw
    } else {
        Action::Ignore
    }
}

fn handle_custom_dns_key(state: &mut UiState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if !state.custom_dns_input.is_empty() || state.custom_dns_error.is_some() {
            state.custom_dns_input.clear();
            state.custom_dns_cursor = 0;
            state.custom_dns_error = None;
            return Action::Redraw;
        }
        return Action::Ignore;
    }

    if !is_altgr_char(&key)
        && key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Ignore;
    }

    let char_len = state.custom_dns_input.chars().count();
    let cursor = state.custom_dns_cursor.min(char_len);

    match key.code {
        KeyCode::Left => {
            if cursor > 0 {
                state.custom_dns_cursor = cursor - 1;
                return Action::Redraw;
            }
            Action::Ignore
        }
        KeyCode::Right => {
            if cursor < char_len {
                state.custom_dns_cursor = cursor + 1;
                return Action::Redraw;
            }
            Action::Ignore
        }
        KeyCode::Home => {
            if cursor > 0 {
                state.custom_dns_cursor = 0;
                return Action::Redraw;
            }
            Action::Ignore
        }
        KeyCode::End => {
            if cursor < char_len {
                state.custom_dns_cursor = char_len;
                return Action::Redraw;
            }
            Action::Ignore
        }
        KeyCode::Backspace => {
            if cursor > 0 {
                let byte_idx = char_to_byte_idx(&state.custom_dns_input, cursor - 1);
                state.custom_dns_input.remove(byte_idx);
                state.custom_dns_cursor = cursor - 1;
                state.custom_dns_error = None;
                return Action::Redraw;
            }
            if state.custom_dns_error.is_some() {
                state.custom_dns_error = None;
                return Action::Redraw;
            }
            Action::Ignore
        }
        KeyCode::Delete => {
            if cursor < char_len {
                let byte_idx = char_to_byte_idx(&state.custom_dns_input, cursor);
                state.custom_dns_input.remove(byte_idx);
                state.custom_dns_cursor = cursor;
                state.custom_dns_error = None;
                return Action::Redraw;
            }
            if state.custom_dns_error.is_some() {
                state.custom_dns_error = None;
                return Action::Redraw;
            }
            Action::Ignore
        }
        _ if key.kind != KeyEventKind::Press => Action::Ignore,
        KeyCode::Esc => {
            state.editing_custom_dns = false;
            state.custom_dns_error = None;
            Action::Redraw
        }
        KeyCode::Enter => {
            match vdpi_core::dns::validate_custom_dns_input(&state.custom_dns_input) {
                Ok(normalized) => Action::Finish(Choice::SetDns(normalized)),
                Err(err) => {
                    state.custom_dns_error = Some(sanitize_inline(&err).into_owned());
                    Action::Redraw
                }
            }
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            if char_len < MAX_CUSTOM_DNS_INPUT_CHARS {
                let byte_idx = char_to_byte_idx(&state.custom_dns_input, cursor);
                state.custom_dns_input.insert(byte_idx, ch);
                state.custom_dns_cursor = cursor + 1;
                state.custom_dns_error = None;
                return Action::Redraw;
            }
            Action::Ignore
        }
        _ => Action::Ignore,
    }
}

fn handle_dns_picker_key(state: &mut UiState, key: KeyEvent) -> Action {
    let count = DNS_PICKER_ITEM_COUNT;
    if state.dns_selected >= count {
        state.dns_selected = count.saturating_sub(1);
    }
    match key.code {
        KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k' | 'K') => {
            state.dns_selected = (state.dns_selected + count - 1) % count;
            Action::Redraw
        }
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j' | 'J') => {
            state.dns_selected = (state.dns_selected + 1) % count;
            Action::Redraw
        }
        KeyCode::Home => {
            state.dns_selected = 0;
            Action::Redraw
        }
        KeyCode::End => {
            state.dns_selected = count - 1;
            Action::Redraw
        }
        _ if key.kind != KeyEventKind::Press => Action::Ignore,
        KeyCode::Enter => {
            if let Some(preset) = DNS_PRESETS.get(state.dns_selected) {
                Action::Finish(Choice::SetDns(preset.addr.to_string()))
            } else {
                state.open_custom_dns_editor();
                Action::Redraw
            }
        }
        KeyCode::Char(c @ '1'..='9') => {
            let index = usize::from(c as u8 - b'1');
            if let Some(preset) = DNS_PRESETS.get(index) {
                state.dns_selected = index;
                Action::Finish(Choice::SetDns(preset.addr.to_string()))
            } else if index == DNS_PRESETS.len() {
                state.open_custom_dns_editor();
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q' | 'Q' | 'b' | 'B') => {
            state.selecting_dns = false;
            state.editing_custom_dns = false;
            state.custom_dns_error = None;
            Action::Redraw
        }
        _ => Action::Ignore,
    }
}

fn handle_key(state: &mut UiState, key: KeyEvent) -> Action {
    if key.kind == KeyEventKind::Release {
        return Action::Ignore;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return if key.kind == KeyEventKind::Press {
            Action::Finish(Choice::Cancel)
        } else {
            Action::Ignore
        };
    }
    if state.selecting_dns && state.editing_custom_dns {
        return handle_custom_dns_key(state, key);
    }
    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Ignore;
    }

    if state.confirming_uninstall {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        return match key.code {
            KeyCode::Char('y' | 'Y') => Action::Finish(Choice::Uninstall),
            KeyCode::Char('n' | 'N' | 'q' | 'Q') | KeyCode::Esc => {
                state.confirming_uninstall = false;
                Action::Redraw
            }
            _ => Action::Ignore,
        };
    }

    if state.selecting_dns {
        return handle_dns_picker_key(state, key);
    }

    let count = state.menu.items.len();
    if count == 0 {
        return Action::Finish(Choice::Cancel);
    }
    if state.selected >= count {
        state.selected = count - 1;
    }

    match key.code {
        KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k' | 'K') => {
            state.selected = (state.selected + count - 1) % count;
        }
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j' | 'J') => {
            state.selected = (state.selected + 1) % count;
        }
        KeyCode::Home => state.selected = 0,
        KeyCode::End => state.selected = count - 1,
        _ if key.kind != KeyEventKind::Press => return Action::Ignore,
        KeyCode::Char('r' | 'R') => return Action::Refresh,
        KeyCode::Char('d' | 'D') => {
            state.open_dns_picker();
            return Action::Redraw;
        }
        KeyCode::Char('m' | 'M') => {
            if let Some((index, item)) = state
                .menu
                .items
                .iter()
                .enumerate()
                .find(|(_, item)| matches!(item.choice, Choice::SwitchEngine(_)))
            {
                state.selected = index;
                return Action::Finish(item.choice.clone());
            }
            return Action::Ignore;
        }
        KeyCode::Char('l' | 'L') => {
            if let Some((index, _)) = state
                .menu
                .items
                .iter()
                .enumerate()
                .find(|(_, item)| item.choice == Choice::Dashboard)
            {
                state.selected = index;
                return Action::Finish(Choice::Dashboard);
            }
            return Action::Ignore;
        }
        KeyCode::Char('s' | 'S') => {
            if let Some((index, _)) = state
                .menu
                .items
                .iter()
                .enumerate()
                .find(|(_, item)| item.choice == Choice::SplitTunnel)
            {
                state.selected = index;
                return Action::Finish(Choice::SplitTunnel);
            }
            return Action::Ignore;
        }
        KeyCode::Enter => {
            let choice = state.menu.items[state.selected].choice.clone();
            if choice == Choice::Uninstall {
                state.confirming_uninstall = true;
                return Action::Redraw;
            }
            if choice == Choice::SelectDns {
                state.open_dns_picker();
                return Action::Redraw;
            }
            return Action::Finish(choice);
        }
        KeyCode::Char(c @ '1'..='9') => {
            let index = usize::from(c as u8 - b'1');
            if let Some(item) = state.menu.items.get(index) {
                if item.choice == Choice::Uninstall {
                    state.selected = index;
                    state.confirming_uninstall = true;
                    return Action::Redraw;
                }
                if item.choice == Choice::SelectDns {
                    state.selected = index;
                    state.open_dns_picker();
                    return Action::Redraw;
                }
                return Action::Finish(item.choice.clone());
            }
            return Action::Ignore;
        }
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => return Action::Finish(Choice::Cancel),
        _ => return Action::Ignore,
    }
    Action::Redraw
}

fn repo_display() -> &'static str {
    REPOSITORY_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://")
}

fn sanitize_inline(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

fn char_display_width(ch: char) -> usize {
    let mut buf = [0u8; 4];
    let s: &str = ch.encode_utf8(&mut buf);
    Span::raw(s).width()
}

fn truncate_head(text: &str, max_cols: usize) -> Cow<'_, str> {
    if max_cols == 0 {
        return Cow::Borrowed("");
    }
    if Span::raw(text).width() <= max_cols {
        return Cow::Borrowed(text);
    }
    if max_cols == 1 {
        let last = text.chars().next_back().unwrap_or('…');
        return Cow::Owned(last.to_string());
    }
    let budget = max_cols - 1;
    let mut used = 0usize;
    let mut start_byte = text.len();
    for (idx, ch) in text.char_indices().rev() {
        let w = char_display_width(ch);
        if used.saturating_add(w) > budget {
            break;
        }
        used += w;
        start_byte = idx;
    }
    let mut out = String::with_capacity('…'.len_utf8() + (text.len() - start_byte));
    out.push('…');
    out.push_str(&text[start_byte..]);
    Cow::Owned(out)
}

fn char_to_byte_idx(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map_or(s.len(), |(byte_idx, _)| byte_idx)
}

fn truncate_tail_cols(text: &str, max_cols: usize) -> Cow<'_, str> {
    if max_cols == 0 {
        return Cow::Borrowed("");
    }
    if Span::raw(text).width() <= max_cols {
        return Cow::Borrowed(text);
    }
    if max_cols == 1 {
        let first = text
            .chars()
            .next()
            .filter(|&ch| char_display_width(ch) <= 1)
            .unwrap_or('…');
        return Cow::Owned(first.to_string());
    }
    let budget = max_cols - 1;
    let mut used = 0usize;
    let mut end_byte = 0usize;
    for (idx, ch) in text.char_indices() {
        let w = char_display_width(ch);
        if used.saturating_add(w) > budget {
            break;
        }
        used += w;
        end_byte = idx + ch.len_utf8();
    }
    let mut out = String::with_capacity(end_byte + '…'.len_utf8());
    out.push_str(&text[..end_byte]);
    out.push('…');
    Cow::Owned(out)
}

fn window_around_cursor(text: &str, cursor_char: usize, max_cols: usize) -> (String, String) {
    if max_cols == 0 {
        return (String::new(), String::new());
    }
    let split_byte = char_to_byte_idx(text, cursor_char);
    let before = &text[..split_byte];
    let after = &text[split_byte..];
    let before_w = Span::raw(before).width();
    let after_w = Span::raw(after).width();
    if before_w.saturating_add(after_w) <= max_cols {
        return (before.to_string(), after.to_string());
    }
    let target_after = after_w.min(max_cols.saturating_sub(before_w).max(max_cols / 3));
    let target_before = max_cols.saturating_sub(target_after);
    let vis_before = truncate_head(before, target_before).into_owned();
    let remaining_for_after = max_cols.saturating_sub(Span::raw(vis_before.as_str()).width());
    let vis_after = truncate_tail_cols(after, remaining_for_after).into_owned();
    (vis_before, vis_after)
}

fn truncate_text(text: &str, max_chars: usize) -> Cow<'_, str> {
    if max_chars == 0 {
        return Cow::Borrowed("");
    }
    if text.chars().count() <= max_chars {
        return Cow::Borrowed(text);
    }
    if max_chars == 1 {
        let end = text
            .char_indices()
            .nth(1)
            .map_or(text.len(), |(idx, _)| idx);
        return Cow::Borrowed(&text[..end]);
    }
    let mut out = String::with_capacity(max_chars + '…'.len_utf8());
    for ch in text.chars().take(max_chars - 1) {
        out.push(ch);
    }
    out.push('…');
    Cow::Owned(out)
}

fn wrap_words(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if current.is_empty() {
            if word_len <= max_width {
                current.push_str(word);
                current_len = word_len;
            } else {
                lines.push(truncate_text(word, max_width).into_owned());
            }
        } else if current_len + 1 + word_len <= max_width {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + word_len;
        } else {
            lines.push(std::mem::take(&mut current));
            if word_len <= max_width {
                current.push_str(word);
                current_len = word_len;
            } else {
                lines.push(truncate_text(word, max_width).into_owned());
                current_len = 0;
            }
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

fn key_badge(index: usize) -> Cow<'static, str> {
    KEY_BADGES.get(index).map_or_else(
        || Cow::Owned(format!("[{}]", index + 1)),
        |&badge| Cow::Borrowed(badge),
    )
}

fn range_label(count: usize) -> Cow<'static, str> {
    if count == 0 {
        return Cow::Borrowed("");
    }
    RANGE_LABELS.get(count - 1).map_or_else(
        || Cow::Owned(format!("1-{count}")),
        |&label| Cow::Borrowed(label),
    )
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    let [vertical] = Layout::vertical([Constraint::Length(h)])
        .flex(Flex::Center)
        .areas(area);
    let [centered] = Layout::horizontal([Constraint::Length(w)])
        .flex(Flex::Center)
        .areas(vertical);
    centered
}

fn render(frame: &mut Frame<'_>, state: &UiState, color: bool) {
    let area = frame.area();
    if area.is_empty() {
        return;
    }

    let palette = Palette::for_color(color);
    let menu = &state.menu;
    let selected = state.selected.min(menu.items.len().saturating_sub(1));

    if area.width < 14 || area.height < 5 {
        render_minimal(frame, area, state, selected, palette);
        return;
    }

    let card_width = area.width.min(MAX_CARD_WIDTH);
    let padding = if card_width >= 20 {
        Padding::horizontal(1)
    } else {
        Padding::ZERO
    };
    let inner_width = card_width
        .saturating_sub(2)
        .saturating_sub(padding.left.saturating_add(padding.right));
    let inset = inner_width >= 36;

    if state.confirming_uninstall {
        let body_indent_len = if inset { 3usize } else { 2usize };
        let right_margin = usize::from(inset);
        let wrap_width = usize::from(inner_width)
            .saturating_sub(body_indent_len + right_margin)
            .max(1);
        let body_lines = wrap_words(UNINSTALL_CONFIRM_BODY, wrap_width);
        let confirm_plan =
            ConfirmLayoutPlan::compute(area.height, menu.status_rows.len(), body_lines.len());
        let card_area = centered_rect(area, card_width, confirm_plan.card_height);
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

        let ctx = RenderCtx { palette, inset };
        let mut y = inner.y;
        let bottom = inner.y.saturating_add(inner.height);
        let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

        if y < bottom {
            render_header(frame, row(y), ctx);
            y = y.saturating_add(1);
        }

        if confirm_plan.show_top_divider && y < bottom {
            render_divider(frame, row(y), ctx);
            y = y.saturating_add(1);
        }

        if confirm_plan.show_status {
            for status_row in &menu.status_rows {
                if y < bottom {
                    render_status_row(frame, row(y), status_row, ctx);
                    y = y.saturating_add(1);
                }
            }
            if confirm_plan.show_status_divider && y < bottom {
                render_divider(frame, row(y), ctx);
                y = y.saturating_add(1);
            }
        }

        let footer_reserve =
            u16::from(confirm_plan.show_footer) + u16::from(confirm_plan.show_bottom_divider);
        let body_bottom = bottom.saturating_sub(footer_reserve).max(y);
        let body_area = Rect::new(inner.x, y, inner.width, body_bottom.saturating_sub(y));
        render_uninstall_confirm(frame, body_area, &body_lines, ctx);

        let mut footer_y = bottom;
        if confirm_plan.show_footer && footer_y > y {
            footer_y = footer_y.saturating_sub(1);
            render_confirm_footer(frame, row(footer_y), ctx);
        }
        if confirm_plan.show_bottom_divider && footer_y > y {
            footer_y = footer_y.saturating_sub(1);
            render_divider(frame, row(footer_y), ctx);
        }
        return;
    }

    if state.selecting_dns {
        render_dns_picker_card(
            frame, area, card_width, padding, inset, state, palette, color,
        );
        return;
    }

    let pad_len = usize::from(inset);
    let notice_budget = usize::from(inner_width).saturating_sub(pad_len + 2 + pad_len);
    let cleaned_notice = menu.notice.as_deref().map(clean_notice);
    let notice_is_warning = cleaned_notice
        .as_deref()
        .is_some_and(is_warning_notice);
    let notice_lines = cleaned_notice.as_deref().map_or_else(Vec::new, |text| {
        wrap_notice_lines(text, notice_budget, MAX_NOTICE_LINES)
    });

    let plan = LayoutPlan::compute(
        area.height,
        menu.items.len(),
        menu.status_rows.len(),
        notice_lines.len(),
        state.show_tun_tip,
    );
    let card_area = centered_rect(area, card_width, plan.card_height);

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

    let ctx = RenderCtx { palette, inset };

    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

    if y < bottom {
        render_header(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    if plan.top_divider() && y < bottom {
        render_divider(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    for status_row in menu.status_rows.iter().take(plan.visible_status_rows) {
        if y < bottom {
            render_status_row(frame, row(y), status_row, ctx);
            y = y.saturating_add(1);
        }
    }

    if plan.show_tun_tip && y < bottom {
        render_tun_tip(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    if plan.visible_notice_rows > 0 && y < bottom {
        let avail_rows = usize::from(bottom.saturating_sub(y)).min(plan.visible_notice_rows);
        let rendered_lines: Cow<'_, [String]> = if avail_rows < notice_lines.len() {
            Cow::Owned(cleaned_notice.as_deref().map_or_else(Vec::new, |text| {
                wrap_notice_lines(text, notice_budget, avail_rows)
            }))
        } else {
            Cow::Borrowed(notice_lines.as_slice())
        };
        let notice_height = u16::try_from(rendered_lines.len()).unwrap_or(0);
        if notice_height > 0 {
            render_notice(
                frame,
                Rect::new(inner.x, y, inner.width, notice_height),
                notice_is_warning,
                &rendered_lines,
                ctx,
            );
            y = y.saturating_add(notice_height);
        }
    }

    if plan.status_divider() && y < bottom {
        render_divider(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    if plan.breathing_gaps() && y < bottom {
        y = y.saturating_add(1);
    }

    let footer_reserve = u16::from(plan.show_footer)
        + u16::from(plan.bottom_divider())
        + u16::from(plan.breathing_gaps());
    let items_bottom = bottom.saturating_sub(footer_reserve).max(y);
    let items_area = Rect::new(inner.x, y, inner.width, items_bottom.saturating_sub(y));

    render_items(frame, items_area, menu, selected, plan, ctx);

    let mut footer_y = bottom;
    if plan.show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_footer(
            frame,
            row(footer_y),
            menu.items.len(),
            menu_has_dashboard(menu),
            menu_has_split_tunnel(menu),
            ctx,
        );
    }
    if plan.bottom_divider() && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), ctx);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let left_line = Line::from(vec![
        Span::raw(pad),
        Span::styled("vdpi", ctx.palette.brand),
        Span::raw(" "),
        Span::styled(VERSION_LABEL, ctx.palette.version),
    ]);

    let repo = repo_display();
    let left_len = pad.len() + "vdpi".len() + 1 + VERSION_LABEL.len();
    let right_len = repo.len() + pad.len();

    if left_len + right_len + 2 <= usize::from(area.width) {
        let left_w = u16::try_from(left_len).unwrap_or(u16::MAX);
        let right_w = u16::try_from(right_len).unwrap_or(u16::MAX);
        let [left_area, right_area] =
            Layout::horizontal([Constraint::Min(left_w), Constraint::Length(right_w)]).areas(area);
        frame.render_widget(left_line, left_area);
        let right_line =
            Line::from(vec![Span::styled(repo, ctx.palette.repo), Span::raw(pad)]).right_aligned();
        frame.render_widget(right_line, right_area);
    } else {
        frame.render_widget(left_line, area);
    }
}

fn render_divider(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let cols = usize::from(area.width).min(MAX_RULE_COLS);
    let byte_len = cols * '─'.len_utf8();
    let line = Line::styled(&RULE[..byte_len], ctx.palette.divider);
    frame.render_widget(line, area);
}

fn format_full_badge(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        Cow::Borrowed(trimmed)
    } else {
        Cow::Owned(format!("[{trimmed}]"))
    }
}

fn truncate_badge(full_badge: Cow<'_, str>, max_chars: usize) -> Cow<'_, str> {
    if full_badge.chars().count() <= max_chars {
        return full_badge;
    }
    let inner = full_badge
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&full_badge);
    let inner_budget = max_chars.saturating_sub(2);
    Cow::Owned(format!("[{}]", truncate_text(inner, inner_budget)))
}

fn render_status_row(frame: &mut Frame<'_>, area: Rect, row: &StatusRow, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let dot = ctx.palette.status_dot(row.tone);
    let tone_style = ctx.palette.status(row.tone);
    let label_width = 8usize;
    let prefix_cols = pad.len() + 2 + label_width + 2;
    let right_margin = pad.len();
    let width = usize::from(area.width);

    if width <= prefix_cols + 4 {
        let compact = format!("{}: {}", row.label, row.value);
        let budget = width.saturating_sub(pad.len() + 2 + right_margin);
        let text = truncate_text(&compact, budget);
        let line = Line::from(vec![
            Span::raw(pad),
            Span::styled(dot, tone_style),
            Span::styled(text, tone_style),
        ]);
        frame.render_widget(line, area);
        return;
    }

    let label = format!("{:<width$}", row.label, width = label_width);
    let budget = width.saturating_sub(prefix_cols + right_margin);
    let badge = row
        .badge
        .as_ref()
        .map(|(text, tone)| (text.trim(), *tone))
        .filter(|(b, _)| !b.is_empty());

    let badge_layout: Option<(Cow<'_, str>, Cow<'_, str>, StatusTone)> =
        badge.and_then(|(raw_badge, badge_tone)| {
            let full_badge = format_full_badge(raw_badge);
            let value_width = row.value.chars().count();
            let full_badge_width = full_badge.chars().count();

            if value_width
                .saturating_add(2)
                .saturating_add(full_badge_width)
                <= budget
            {
                Some((Cow::Borrowed(row.value.as_str()), full_badge, badge_tone))
            } else if budget >= 34 {
                let max_badge_w = budget
                    .saturating_sub(2 + value_width.min(budget.saturating_sub(16)))
                    .max(12);
                let badge_text = truncate_badge(full_badge, max_badge_w);
                let value_budget = budget.saturating_sub(2 + badge_text.chars().count());
                Some((
                    truncate_text(&row.value, value_budget),
                    badge_text,
                    badge_tone,
                ))
            } else if budget >= 18 {
                let is_vpn_badge = raw_badge
                    .trim_start_matches('[')
                    .get(..3)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("vpn"));
                let compact_badge = if is_vpn_badge {
                    Cow::Borrowed(COMPACT_VPN_BADGE)
                } else {
                    truncate_badge(full_badge, budget.saturating_sub(8).clamp(5, 10))
                };
                let value_budget = budget.saturating_sub(2 + compact_badge.chars().count());
                Some((
                    truncate_text(&row.value, value_budget),
                    compact_badge,
                    badge_tone,
                ))
            } else {
                None
            }
        });

    let line = if let Some((value, badge_text, badge_tone)) = badge_layout {
        let value_len = value.chars().count();
        let badge_len = badge_text.chars().count();
        let gap = budget.saturating_sub(value_len.saturating_add(badge_len));
        Line::from(vec![
            Span::raw(pad),
            Span::styled(dot, tone_style),
            Span::styled(label, ctx.palette.status_label),
            Span::raw("  "),
            Span::styled(value, tone_style),
            Span::raw(" ".repeat(gap)),
            Span::styled(badge_text, ctx.palette.status(badge_tone)),
        ])
    } else {
        let value = truncate_text(&row.value, budget);
        Line::from(vec![
            Span::raw(pad),
            Span::styled(dot, tone_style),
            Span::styled(label, ctx.palette.status_label),
            Span::raw("  "),
            Span::styled(value, tone_style),
        ])
    };
    frame.render_widget(line, area);
}

fn is_warning_notice(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "wintun.dll",
        "missing",
        "no running",
        "not found",
        "cancelled",
        "canceled",
        "warning",
        "cannot",
        "unable",
        "required",
        "extract",
        "only supported",
        "failed",
        "error",
        "issues",
        "already running",
    ]
    .into_iter()
    .any(|needle| lower.contains(needle))
}

fn clean_notice(notice: &str) -> Cow<'_, str> {
    let stripped = notice
        .strip_prefix("✓ ")
        .or_else(|| notice.strip_prefix("! "))
        .unwrap_or(notice);
    sanitize_inline(stripped)
}

fn wrap_notice_lines(cleaned: &str, max_width: usize, max_lines: usize) -> Vec<String> {
    if max_width == 0 || max_lines == 0 {
        return Vec::new();
    }
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    if max_lines == 1 {
        return vec![truncate_text(trimmed, max_width).into_owned()];
    }
    if trimmed.chars().count() <= max_width {
        return vec![trimmed.to_string()];
    }
    let mut wrapped = wrap_words(trimmed, max_width);
    if wrapped.len() <= max_lines {
        return wrapped;
    }
    let overflow = wrapped.split_off(max_lines - 1);
    let tail = overflow.join(" ");
    wrapped.push(truncate_text(&tail, max_width).into_owned());
    wrapped
}

fn render_tun_tip(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let budget = usize::from(area.width).saturating_sub(pad.len() + 2 + pad.len());
    if budget == 0 {
        return;
    }
    let tip = truncate_text(WINDOWS_TUN_TIP, budget);
    let line = if let Some(rest) = tip.strip_prefix("Tip: ") {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("· ", ctx.palette.status_accent),
            Span::styled("Tip: ", ctx.palette.status_accent),
            Span::styled(rest, ctx.palette.active_hint),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("· ", ctx.palette.status_accent),
            Span::styled(tip.as_ref(), ctx.palette.active_hint),
        ])
    };
    frame.render_widget(line, area);
}

fn render_notice(
    frame: &mut Frame<'_>,
    area: Rect,
    is_warning: bool,
    lines: &[String],
    ctx: RenderCtx,
) {
    if area.is_empty() || lines.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let (prefix, style) = if is_warning {
        ("! ", ctx.palette.status_warn)
    } else {
        ("✓ ", ctx.palette.status_active)
    };
    let max_rows = usize::from(area.height).min(lines.len());
    for (idx, text) in lines.iter().take(max_rows).enumerate() {
        let row_area = Rect::new(
            area.x,
            area.y.saturating_add(u16::try_from(idx).unwrap_or(0)),
            area.width,
            1,
        );
        let line = if idx == 0 {
            Line::from(vec![
                Span::raw(pad),
                Span::styled(prefix, style),
                Span::styled(text.as_str(), style),
            ])
        } else {
            Line::from(vec![
                Span::raw(pad),
                Span::raw("  "),
                Span::styled(text.as_str(), style),
            ])
        };
        frame.render_widget(line, row_area);
    }
}

fn render_uninstall_confirm(
    frame: &mut Frame<'_>,
    area: Rect,
    body_lines: &[String],
    ctx: RenderCtx,
) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let body_indent = if ctx.inset { "   " } else { "  " };
    let right_margin = pad.len();

    let needed_tight = 1 + body_lines.len() + 1;
    let avail = usize::from(area.height);
    let extra = avail.saturating_sub(needed_tight);
    let top_gap = usize::from(extra >= 3);
    let mid_gap_1 = usize::from(extra >= 2);
    let mid_gap_2 = usize::from(extra >= 1);

    let mut y = area.y.saturating_add(u16::try_from(top_gap).unwrap_or(0));
    let max_y = area.y.saturating_add(area.height);

    if y < max_y {
        let header_budget = usize::from(area.width).saturating_sub(pad.len() + 2 + right_margin);
        let header_text = truncate_text("Confirm uninstall", header_budget);
        let line = Line::from(vec![
            Span::raw(pad),
            Span::styled(ctx.palette.status_warn_dot, ctx.palette.danger_bold),
            Span::styled(header_text, ctx.palette.danger_bold),
        ]);
        frame.render_widget(line, Rect::new(area.x, y, area.width, 1));
        y = y.saturating_add(1);
    }

    y = y.saturating_add(u16::try_from(mid_gap_1).unwrap_or(0));

    let body_limit = max_y.saturating_sub(1);
    for text in body_lines {
        if y >= body_limit {
            break;
        }
        let line = Line::from(vec![
            Span::raw(body_indent),
            Span::styled(text.as_str(), ctx.palette.inactive_title),
        ]);
        frame.render_widget(line, Rect::new(area.x, y, area.width, 1));
        y = y.saturating_add(1);
    }

    if mid_gap_2 > 0 && y.saturating_add(1) < max_y {
        y = y.saturating_add(1);
    }

    if y < max_y {
        let prompt_area = Rect::new(area.x, y, area.width, 1);
        let width = usize::from(area.width);
        let full_prompt_cols = body_indent.len() + 41 + right_margin;
        let compact_prompt_cols = body_indent.len() + 30 + right_margin;
        let tiny_prompt_cols = pad.len() + 16 + right_margin;
        let line = if width >= full_prompt_cols {
            Line::from(vec![
                Span::raw(body_indent),
                Span::styled("[y]", ctx.palette.danger_bold),
                Span::raw(" "),
                Span::styled("Uninstall vdpi", ctx.palette.active_title),
                Span::styled("   ·   ", ctx.palette.footer_text),
                Span::styled("[n / Esc]", ctx.palette.footer_key),
                Span::raw(" "),
                Span::styled("Cancel", ctx.palette.inactive_title),
            ])
        } else if width >= compact_prompt_cols {
            Line::from(vec![
                Span::raw(body_indent),
                Span::styled("[y]", ctx.palette.danger_bold),
                Span::raw(" "),
                Span::styled("Uninstall", ctx.palette.active_title),
                Span::styled(" · ", ctx.palette.footer_text),
                Span::styled("[n/Esc]", ctx.palette.footer_key),
                Span::raw(" "),
                Span::styled("Cancel", ctx.palette.inactive_title),
            ])
        } else if width >= tiny_prompt_cols {
            Line::from(vec![
                Span::raw(pad),
                Span::styled("[y]", ctx.palette.danger_bold),
                Span::raw(" "),
                Span::styled("Yes", ctx.palette.active_title),
                Span::styled(" · ", ctx.palette.footer_text),
                Span::styled("[n]", ctx.palette.footer_key),
                Span::raw(" "),
                Span::styled("No", ctx.palette.inactive_title),
            ])
        } else {
            let short = truncate_text("[y]/[n]", width.saturating_sub(pad.len() + right_margin));
            Line::from(vec![
                Span::raw(pad),
                Span::styled(short, ctx.palette.danger_bold),
            ])
        };
        frame.render_widget(line, prompt_area);
    }
}

fn render_items(
    frame: &mut Frame<'_>,
    area: Rect,
    menu: &LauncherMenu,
    selected: usize,
    plan: LayoutPlan,
    ctx: RenderCtx,
) {
    if area.is_empty() || menu.items.is_empty() {
        return;
    }

    let show_all_hints = plan.show_all_hints();
    let show_active_hint = plan.show_active_hint();
    let item_gap = plan.item_gap();

    let visible_slots = if show_all_hints && item_gap {
        usize::from(area.height.saturating_add(1) / 3)
    } else if show_all_hints {
        usize::from(area.height / 2)
    } else if show_active_hint {
        usize::from(area.height.saturating_sub(1)).max(1)
    } else {
        usize::from(area.height)
    };
    if visible_slots == 0 {
        return;
    }

    let start_index = if selected < visible_slots {
        0
    } else {
        (selected + 1).saturating_sub(visible_slots)
    };

    let mut cursor_y = area.y;
    let max_y = area.y.saturating_add(area.height);

    for (index, item) in menu
        .items
        .iter()
        .enumerate()
        .skip(start_index)
        .take(visible_slots)
    {
        if cursor_y >= max_y {
            break;
        }
        let is_selected = index == selected;
        let title_area = Rect::new(area.x, cursor_y, area.width, 1);
        render_item_title(frame, title_area, index, item, is_selected, ctx);
        cursor_y = cursor_y.saturating_add(1);

        let should_render_hint = show_all_hints || (show_active_hint && is_selected);
        if should_render_hint && cursor_y < max_y {
            let hint_area = Rect::new(area.x, cursor_y, area.width, 1);
            render_item_hint(frame, hint_area, item, is_selected, ctx);
            cursor_y = cursor_y.saturating_add(1);
        }

        if item_gap {
            cursor_y = cursor_y.saturating_add(1);
        }
    }
}

fn render_item_title(
    frame: &mut Frame<'_>,
    area: Rect,
    index: usize,
    item: &MenuItem,
    is_selected: bool,
    ctx: RenderCtx,
) {
    let lead = if ctx.inset { " " } else { "" };
    let badge = key_badge(index);
    let prefix_cols = lead.len() + 2 + badge.len() + 1;
    let budget = usize::from(area.width).saturating_sub(prefix_cols + lead.len());
    let title = truncate_text(&item.title, budget);

    let line = if is_selected {
        Line::from(vec![
            Span::raw(lead),
            Span::styled("▸ ", ctx.palette.active_marker),
            Span::styled(badge, ctx.palette.active_badge),
            Span::raw(" "),
            Span::styled(title, ctx.palette.active_title),
        ])
        .style(ctx.palette.active_row)
    } else {
        let inactive_prefix = if ctx.inset { "   " } else { "  " };
        Line::from(vec![
            Span::raw(inactive_prefix),
            Span::styled(badge, ctx.palette.inactive_badge),
            Span::raw(" "),
            Span::styled(title, ctx.palette.inactive_title),
        ])
    };
    frame.render_widget(line, area);
}

fn render_item_hint(
    frame: &mut Frame<'_>,
    area: Rect,
    item: &MenuItem,
    is_selected: bool,
    ctx: RenderCtx,
) {
    let indent = if ctx.inset { "       " } else { "      " };
    let right_margin = usize::from(ctx.inset);
    let budget = usize::from(area.width).saturating_sub(indent.len() + right_margin);
    let hint = truncate_text(&item.hint, budget);
    let style = if is_selected {
        ctx.palette.active_hint
    } else {
        ctx.palette.inactive_hint
    };
    let line = Line::from(vec![Span::raw(indent), Span::styled(hint, style)]);
    frame.render_widget(line, area);
}

#[allow(clippy::too_many_arguments)]
fn render_custom_dns_editor_card(
    frame: &mut Frame<'_>,
    area: Rect,
    card_width: u16,
    padding: Padding,
    inset: bool,
    state: &UiState,
    palette: Palette,
    color: bool,
) {
    let inner_width = card_width
        .saturating_sub(2)
        .saturating_sub(padding.left.saturating_add(padding.right));
    let pad = if inset { " " } else { "" };
    let right_margin = usize::from(inset);
    let hint_wrap_width = usize::from(inner_width)
        .saturating_sub(pad.len() + right_margin)
        .max(1);
    let hint_lines = wrap_words(CUSTOM_DNS_EDITOR_HINT, hint_wrap_width);
    let hint_count = u16::try_from(hint_lines.len()).unwrap_or(2);
    let err_rows = u16::from(state.custom_dns_error.is_some());
    // borders(2) + header(1) + top_div(1) + title(1) + gap(1) + input(1) + hint(h) + err(0|1) + gap(1) + bot_div(1) + footer(1)
    let ideal_height = 10u16.saturating_add(hint_count).saturating_add(err_rows);
    let card_height = ideal_height.min(area.height).max(5);
    let card_area = centered_rect(area, card_width, card_height);
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

    let ctx = RenderCtx { palette, inset };
    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

    let show_footer = inner.height >= 5;
    let essential_rows = 3u16
        .saturating_add(err_rows)
        .saturating_add(u16::from(show_footer));
    let show_top_divider = inner.height >= essential_rows.saturating_add(1);
    let show_bot_divider = inner.height >= essential_rows.saturating_add(3);

    if y < bottom {
        render_header(frame, row(y), ctx);
        y = y.saturating_add(1);
    }
    if show_top_divider && y < bottom {
        render_divider(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    let footer_reserve = u16::from(show_footer) + u16::from(show_bot_divider);
    let body_bottom = bottom.saturating_sub(footer_reserve).max(y);
    let width = usize::from(inner.width);

    if y < body_bottom {
        let heading = if is_custom_dns(&state.configured_dns) {
            format!(
                "Choose DNS server · {}",
                format_dns_label(&state.configured_dns)
            )
        } else {
            "Choose DNS server · Custom DNS".to_string()
        };
        let budget = width.saturating_sub(pad.len() + 2 + right_margin);
        let title_line = Line::from(vec![
            Span::raw(pad),
            Span::styled("● ", palette.status_accent),
            Span::styled(truncate_text(&heading, budget), palette.active_title),
        ]);
        frame.render_widget(title_line, row(y));
        y = y.saturating_add(1);
    }

    // Breathing gap before input when vertical room permits.
    let needed_body = 1u16.saturating_add(hint_count).saturating_add(err_rows);
    if body_bottom.saturating_sub(y) > needed_body && y < body_bottom {
        y = y.saturating_add(1);
    }

    // Inline input row: `Custom DNS: <before>▏<after>` with cursor-centered horizontal scroll.
    if y < body_bottom {
        let prompt = "Custom DNS: ";
        let cursor = "▏";
        let prompt_cols = Span::raw(prompt).width();
        let cursor_cols = Span::raw(cursor).width();
        let bar_width = width.saturating_sub(pad.len() + right_margin);
        let sanitized = sanitize_inline(&state.custom_dns_input);
        let bg = palette.input_bg;
        let line = if bar_width > prompt_cols + cursor_cols {
            let input_budget = bar_width.saturating_sub(prompt_cols + cursor_cols);
            let (vis_before, vis_after) =
                window_around_cursor(&sanitized, state.custom_dns_cursor, input_budget);
            let used = prompt_cols
                + Span::raw(vis_before.as_str()).width()
                + cursor_cols
                + Span::raw(vis_after.as_str()).width();
            let fill = bar_width.saturating_sub(used);
            let mut spans = vec![
                Span::raw(pad),
                Span::styled(prompt, bg.patch(palette.active_marker)),
                Span::styled(vis_before, bg),
                Span::styled(cursor, bg.patch(palette.status_accent)),
            ];
            if !vis_after.is_empty() {
                spans.push(Span::styled(vis_after, bg));
            }
            if fill > 0 {
                spans.push(Span::styled(" ".repeat(fill), bg));
            }
            Line::from(spans)
        } else if bar_width >= cursor_cols {
            let input_budget = bar_width.saturating_sub(cursor_cols);
            let (vis_before, vis_after) =
                window_around_cursor(&sanitized, state.custom_dns_cursor, input_budget);
            let used = Span::raw(vis_before.as_str()).width()
                + cursor_cols
                + Span::raw(vis_after.as_str()).width();
            let fill = bar_width.saturating_sub(used);
            let mut spans = vec![
                Span::raw(pad),
                Span::styled(vis_before, bg),
                Span::styled(cursor, bg.patch(palette.status_accent)),
            ];
            if !vis_after.is_empty() {
                spans.push(Span::styled(vis_after, bg));
            }
            if fill > 0 {
                spans.push(Span::styled(" ".repeat(fill), bg));
            }
            Line::from(spans)
        } else {
            Line::from(vec![
                Span::raw(pad),
                Span::styled(
                    truncate_head(cursor, bar_width).into_owned(),
                    bg.patch(palette.active_marker),
                ),
            ])
        };
        frame.render_widget(line, row(y));
        y = y.saturating_add(1);
    }

    // Reserve 1 row for inline validation error when present.
    let hint_limit = if state.custom_dns_error.is_some() {
        body_bottom.saturating_sub(1).max(y)
    } else {
        body_bottom
    };
    for hint_line in &hint_lines {
        if y >= hint_limit {
            break;
        }
        let line = Line::from(vec![
            Span::raw(pad),
            Span::styled(hint_line.as_str(), palette.active_hint),
        ]);
        frame.render_widget(line, row(y));
        y = y.saturating_add(1);
    }

    if let Some(err) = state.custom_dns_error.as_deref() {
        if y < body_bottom {
            let err_prefix = if color { "● " } else { "! " };
            let err_budget =
                width.saturating_sub(pad.len() + err_prefix.chars().count() + right_margin);
            let msg = truncate_text(err, err_budget);
            let line = Line::from(vec![
                Span::raw(pad),
                Span::styled(err_prefix, palette.danger_bold),
                Span::styled(msg, palette.danger_bold),
            ]);
            frame.render_widget(line, row(y));
            y = y.saturating_add(1);
        }
    }

    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_custom_dns_footer(frame, row(footer_y), ctx);
    }
    if show_bot_divider && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), ctx);
    }
}

#[allow(clippy::too_many_arguments)]
fn render_dns_picker_card(
    frame: &mut Frame<'_>,
    area: Rect,
    card_width: u16,
    padding: Padding,
    inset: bool,
    state: &UiState,
    palette: Palette,
    color: bool,
) {
    if state.editing_custom_dns {
        render_custom_dns_editor_card(
            frame, area, card_width, padding, inset, state, palette, color,
        );
        return;
    }

    let item_count = u16::try_from(DNS_PICKER_ITEM_COUNT).unwrap_or(7);
    // borders(2) + header(1) + top_div(1) + title(1) + gap(1) + items(7) + gap(1) + hint(1) + bot_div(1) + footer(1)
    let ideal_height = 2 + 1 + 1 + 1 + 1 + item_count + 1 + 1 + 1 + 1;
    let card_height = ideal_height.min(area.height).max(5);
    let card_area = centered_rect(area, card_width, card_height);
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

    let ctx = RenderCtx { palette, inset };
    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

    if y < bottom {
        render_header(frame, row(y), ctx);
        y = y.saturating_add(1);
    }
    if y + 2 < bottom {
        render_divider(frame, row(y), ctx);
        y = y.saturating_add(1);
    }

    let show_footer = inner.height >= 5;
    let show_bot_divider = inner.height >= 11;
    let footer_reserve = u16::from(show_footer) + u16::from(show_bot_divider);
    let body_bottom = bottom.saturating_sub(footer_reserve).max(y);

    let pad = if inset { " " } else { "" };
    let width = usize::from(inner.width);
    let right_margin = usize::from(inset);
    let selected = state
        .dns_selected
        .min(DNS_PICKER_ITEM_COUNT.saturating_sub(1));

    if y < body_bottom {
        let current_label = format_dns_label(&state.configured_dns);
        let heading = format!("Choose DNS server · {current_label}");
        let budget = width.saturating_sub(pad.len() + 2 + right_margin);
        let title_line = Line::from(vec![
            Span::raw(pad),
            Span::styled("● ", palette.status_accent),
            Span::styled(truncate_text(&heading, budget), palette.active_title),
        ]);
        frame.render_widget(title_line, row(y));
        y = y.saturating_add(1);
    }

    let remaining_for_items = body_bottom.saturating_sub(y);
    if remaining_for_items >= item_count + 2 && y < body_bottom {
        y = y.saturating_add(1);
    }

    let show_hint = body_bottom.saturating_sub(y) > item_count;
    let list_bottom = if show_hint {
        body_bottom.saturating_sub(1)
    } else {
        body_bottom
    };
    let visible_slots = usize::from(list_bottom.saturating_sub(y)).max(1);
    let start_index = if selected < visible_slots {
        0
    } else {
        (selected + 1).saturating_sub(visible_slots)
    };
    let custom_active = is_custom_dns(&state.configured_dns);
    let prefix_cols = if inset { 3usize } else { 2usize };
    // Keep 19-col alignment when every preset (including [Active]) fits cleanly;
    // on compact widths like 46x18, switch to dynamic spacing so IPs never truncate.
    let align_columns = width >= prefix_cols + 4 + 33 + 9 + right_margin;

    for index in (start_index..DNS_PICKER_ITEM_COUNT).take(visible_slots) {
        if y >= list_bottom {
            break;
        }
        let is_selected = index == selected;
        let prefix = if is_selected {
            if inset {
                " ▸ "
            } else {
                "▸ "
            }
        } else if inset {
            "   "
        } else {
            "  "
        };
        let badge = key_badge(index);
        let title_style = if is_selected {
            palette.active_title
        } else {
            palette.inactive_title
        };
        let mut spans = vec![
            Span::styled(
                prefix,
                if is_selected {
                    palette.active_marker
                } else {
                    palette.inactive_title
                },
            ),
            Span::styled(
                badge.clone(),
                if is_selected {
                    palette.active_badge
                } else {
                    palette.inactive_badge
                },
            ),
            Span::raw(" "),
        ];

        if let Some(preset) = DNS_PRESETS.get(index) {
            let is_active = preset
                .addr
                .eq_ignore_ascii_case(state.configured_dns.trim());
            let active_tag = if is_active { " [Active]" } else { "" };
            let used = prefix_cols + badge.len() + 1 + active_tag.len() + right_margin;
            let budget = width.saturating_sub(used);
            let display_label =
                format_dns_preset_label(preset.name, preset.addr, budget, align_columns);
            spans.push(Span::styled(display_label, title_style));
            if is_active {
                spans.push(Span::styled(active_tag, palette.status_active));
            }
        } else {
            // [7] Custom DNS row
            let active_tag = if custom_active { " [Active]" } else { "" };
            let used = prefix_cols + badge.len() + 1 + active_tag.len() + right_margin;
            let budget = width.saturating_sub(used);
            if custom_active {
                if align_columns && budget >= 24 {
                    let val_budget = budget.saturating_sub(20);
                    let display_val = shorten_custom_dns(&state.configured_dns, val_budget);
                    let label = format!("{:<19} {display_val}", "Custom DNS");
                    spans.push(Span::styled(label, title_style));
                } else if budget >= 16 {
                    let val_budget = budget.saturating_sub(12);
                    let display_val = shorten_custom_dns(&state.configured_dns, val_budget);
                    let label = format!("Custom DNS  {display_val}");
                    spans.push(Span::styled(label, title_style));
                } else {
                    let label = truncate_text("Custom DNS", budget);
                    spans.push(Span::styled(label, title_style));
                }
                spans.push(Span::styled(active_tag, palette.status_active));
            } else {
                let muted_style = if is_selected {
                    palette.active_hint
                } else {
                    palette.inactive_hint
                };
                if align_columns && budget >= 20 + CUSTOM_DNS_PLACEHOLDER.len() {
                    let val_budget = budget.saturating_sub(20);
                    spans.push(Span::styled(format!("{:<19} ", "Custom DNS"), title_style));
                    spans.push(Span::styled(
                        truncate_text(CUSTOM_DNS_PLACEHOLDER, val_budget),
                        muted_style,
                    ));
                } else if budget >= 16 {
                    let val_budget = budget.saturating_sub(12);
                    spans.push(Span::styled("Custom DNS  ", title_style));
                    spans.push(Span::styled(
                        truncate_text(CUSTOM_DNS_PLACEHOLDER, val_budget),
                        muted_style,
                    ));
                } else {
                    spans.push(Span::styled(
                        truncate_text("Custom DNS", budget),
                        title_style,
                    ));
                }
            }
        }

        let line = if is_selected {
            Line::from(spans).style(palette.active_row)
        } else {
            Line::from(spans)
        };
        frame.render_widget(line, row(y));
        y = y.saturating_add(1);
    }

    if show_hint && y < body_bottom {
        let hint_y = body_bottom.saturating_sub(1);
        let indent = if inset { "       " } else { "      " };
        let budget = width.saturating_sub(indent.len() + right_margin);
        let raw_hint = DNS_PRESETS
            .get(selected)
            .map_or(CUSTOM_DNS_HINT, |preset| preset.hint);
        let hint = truncate_text(raw_hint, budget);
        let line = Line::from(vec![
            Span::raw(indent),
            Span::styled(hint, palette.active_hint),
        ]);
        frame.render_widget(line, row(hint_y));
    }

    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_dns_footer(frame, row(footer_y), ctx);
    }
    if show_bot_divider && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), ctx);
    }
}

fn format_dns_preset_label(name: &str, addr: &str, budget: usize, align_columns: bool) -> String {
    let name_len = name.chars().count();
    let addr_len = addr.chars().count();
    if align_columns && 20 + addr_len <= budget {
        return format!("{name:<19} {addr}");
    }
    if name_len + 2 + addr_len <= budget {
        return format!("{name}  {addr}");
    }
    if name_len + 1 + addr_len <= budget {
        return format!("{name} {addr}");
    }
    if budget >= addr_len + 5 {
        let name_budget = budget - addr_len - 1;
        return format!("{} {addr}", truncate_text(name, name_budget));
    }
    truncate_text(&format!("{name} {addr}"), budget).into_owned()
}

fn render_custom_dns_footer(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let key = ctx.palette.footer_key;
    let text = ctx.palette.footer_text;
    let width = usize::from(area.width);

    let line = if width >= pad.len() * 2 + 54 {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("type IP or URL · ", text),
            Span::styled("enter", key),
            Span::styled(" apply · ", text),
            Span::styled("ctrl+u", key),
            Span::styled(" clear · ", text),
            Span::styled("esc", key),
            Span::styled(" back", text),
        ])
    } else if width >= pad.len() * 2 + 37 {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("enter", key),
            Span::styled(" apply · ", text),
            Span::styled("ctrl+u", key),
            Span::styled(" clear · ", text),
            Span::styled("esc", key),
            Span::styled(" back", text),
        ])
    } else if width >= pad.len() * 2 + 22 {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("^u", key),
            Span::styled(" clear · ", text),
            Span::styled("esc", key),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    };
    frame.render_widget(line, area);
}

fn render_dns_footer(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let key = ctx.palette.footer_key;
    let text = ctx.palette.footer_text;
    let width = usize::from(area.width);
    let range = range_label(DNS_PICKER_ITEM_COUNT);

    let line = if width >= pad.len() * 2 + 40 + range.len() {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" move · ", text),
            Span::styled(range, key),
            Span::styled(" pick · ", text),
            Span::styled("enter", key),
            Span::styled(" apply · ", text),
            Span::styled("esc", key),
            Span::styled(" back", text),
        ])
    } else if width >= pad.len() * 2 + 19 + range.len() {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    };
    frame.render_widget(line, area);
}

fn render_confirm_footer(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let key = ctx.palette.footer_key;
    let text = ctx.palette.footer_text;
    let width = usize::from(area.width);

    let line = if width >= pad.len() * 2 + 30 {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("y", ctx.palette.danger_bold),
            Span::styled(" uninstall  ·  ", text),
            Span::styled("n / esc", key),
            Span::styled(" cancel", text),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("y", ctx.palette.danger_bold),
            Span::styled(" · ", text),
            Span::styled("n/esc", key),
        ])
    };
    frame.render_widget(line, area);
}

fn menu_has_dashboard(menu: &LauncherMenu) -> bool {
    menu.items
        .iter()
        .any(|item| item.choice == Choice::Dashboard)
}

fn menu_has_split_tunnel(menu: &LauncherMenu) -> bool {
    menu.items
        .iter()
        .any(|item| item.choice == Choice::SplitTunnel)
}

fn render_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    item_count: usize,
    has_dashboard: bool,
    has_split_tunnel: bool,
    ctx: RenderCtx,
) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let key = ctx.palette.footer_key;
    let text = ctx.palette.footer_text;

    if item_count == 0 {
        let line = Line::from(vec![
            Span::raw(pad),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ]);
        frame.render_widget(line, area);
        return;
    }

    let range = range_label(item_count);
    let width = usize::from(area.width);
    let full_live_split_cols = pad.len() * 2 + 61 + range.len();
    let full_live_cols = pad.len() * 2 + 63 + range.len();
    let full_split_cols = pad.len() * 2 + 59 + range.len();
    let full_cols = pad.len() * 2 + 62 + range.len();
    let medium_live_cols = pad.len() * 2 + 50 + range.len();
    let medium_split_cols = pad.len() * 2 + 51 + range.len();
    let medium_cols = pad.len() * 2 + 41 + range.len();
    let compact_medium_cols = pad.len() * 2 + 34 + range.len();
    let short_cols = pad.len() * 2 + 21 + range.len();

    let line = if has_dashboard && has_split_tunnel && width >= full_live_split_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("l", key),
            Span::styled(" live · ", text),
            Span::styled("d", key),
            Span::styled(" dns · ", text),
            Span::styled("s", key),
            Span::styled(" split · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if has_dashboard && !has_split_tunnel && width >= full_live_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" move · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("l", key),
            Span::styled(" live · ", text),
            Span::styled("d", key),
            Span::styled(" dns · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if !has_dashboard && has_split_tunnel && width >= full_split_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("d", key),
            Span::styled(" dns · ", text),
            Span::styled("s", key),
            Span::styled(" split · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if !has_dashboard && !has_split_tunnel && width >= full_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" move · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("d", key),
            Span::styled(" dns · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" ok · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if has_dashboard && width >= medium_live_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("l", key),
            Span::styled(" live · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if !has_dashboard && has_split_tunnel && width >= medium_split_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("s", key),
            Span::styled(" split · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if width >= medium_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" select · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if width >= compact_medium_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("r", key),
            Span::styled(" refresh · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
            Span::styled(" quit", text),
        ])
    } else if width >= short_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" · ", text),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("r", key),
            Span::styled(" · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("r", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
        ])
    };
    frame.render_widget(line, area);
}

fn render_minimal(
    frame: &mut Frame<'_>,
    area: Rect,
    state: &UiState,
    selected: usize,
    palette: Palette,
) {
    let header_area = Rect::new(area.x, area.y, area.width, 1);
    let header = Line::from(vec![
        Span::styled("vdpi", palette.brand),
        Span::raw(" "),
        Span::styled(VERSION_LABEL, palette.version),
    ]);
    frame.render_widget(header, header_area);

    let ctx = RenderCtx {
        palette,
        inset: false,
    };

    if state.confirming_uninstall {
        if area.height >= 2 {
            let prompt = truncate_text("Uninstall? [y/n]", usize::from(area.width));
            frame.render_widget(
                Line::styled(prompt, palette.danger_bold),
                Rect::new(area.x, area.y + 1, area.width, 1),
            );
        }
        return;
    }

    if state.selecting_dns {
        if area.height >= 2 {
            let text = if state.editing_custom_dns {
                let sanitized = sanitize_inline(&state.custom_dns_input);
                let budget = usize::from(area.width).saturating_sub(6);
                let (vis_before, vis_after) =
                    window_around_cursor(&sanitized, state.custom_dns_cursor, budget);
                let prompt = format!("DNS: {vis_before}▏{vis_after}");
                truncate_head(&prompt, usize::from(area.width)).into_owned()
            } else {
                let prompt = format!("Choose DNS [{}]", range_label(DNS_PICKER_ITEM_COUNT));
                truncate_text(&prompt, usize::from(area.width)).into_owned()
            };
            frame.render_widget(
                Line::styled(text, palette.active_title),
                Rect::new(area.x, area.y + 1, area.width, 1),
            );
        }
        return;
    }

    if let Some(item) = state.menu.items.get(selected).filter(|_| area.height >= 2) {
        let item_area = Rect::new(area.x, area.y + 1, area.width, 1);
        render_item_title(frame, item_area, selected, item, true, ctx);
    }

    if area.height >= 3 {
        let footer_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        render_footer(
            frame,
            footer_area,
            state.menu.items.len(),
            menu_has_dashboard(&state.menu),
            menu_has_split_tunnel(&state.menu),
            ctx,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use vdpi::service::{InstalledInfo, LiveEngineStatus};
    use vdpi::update::VersionRelation;

    fn sample_info(
        installed_version: Option<&str>,
        current_version: &'static str,
        relation: VersionRelation,
    ) -> InstalledInfo {
        InstalledInfo {
            binary_path: PathBuf::from("/usr/local/bin/vdpi"),
            installed_version: installed_version.map(str::to_string),
            current_version,
            relation,
            running_from_installed: relation == VersionRelation::Same,
        }
    }

    fn sample_live_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(4),
            total_connections: Some(90),
            learned_hosts: Some(12),
            isp_stage: Some("balanced".to_string()),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            dns_addr: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: Some(1_048_576),
            bytes_tx: Some(524_288),
            tls_handshakes: Some(42),
            auto_heal_escalations: Some(1),
        }
    }

    fn status_running_live() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    fn status_paused() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    fn status_not_installed() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    fn status_update_available() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.3.0"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    fn render_state(width: u16, height: u16, state: &UiState, color: bool) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render(frame, state, color))
            .expect("draw launcher frame");
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

    #[test]
    fn renders_running_with_live_engine_at_80x24() {
        let state = UiState::new(&status_running_live(), None);
        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);

        assert!(text.contains('╭') && text.contains('╰'));
        assert!(text.contains("vdpi") && text.contains(VERSION_LABEL));
        assert!(text.contains(repo_display()));
        assert!(text.contains("Service"));
        assert!(text.contains("Running · v0.5.0"));
        assert!(text.contains("Anti-DPI"));
        assert!(text.contains("Active · Combo · DoH on · QUIC blocked"));
        assert!(text.contains("Engine"));
        assert!(text.contains("Proxy · 127.0.0.1:8080"));

        for (idx, item) in state.menu.items.iter().enumerate() {
            assert!(
                text.contains(&format!("[{}]", idx + 1)),
                "missing badge {}:\n{text}",
                idx + 1
            );
            assert!(
                text.contains(&item.title),
                "missing item title '{}':\n{text}",
                item.title
            );
        }
        assert!(
            text.contains(&state.menu.items[0].hint),
            "missing selected item hint:\n{text}"
        );
        assert!(
            text.contains("↑↓ · 1-9 · l live · d dns · s split · r refresh · enter · q quit"),
            "missing full live+split footer:\n{text}"
        );
        assert!(buf
            .content()
            .iter()
            .any(|c| c.symbol() == "●" && c.fg == EMERALD_ACTIVE));
        assert!(buf.content().iter().any(|c| c.bg == ACTIVE_BG));
    }

    #[test]
    fn renders_paused_with_all_seven_items_and_notice_at_80x24() {
        let state = UiState::new(
            &status_paused(),
            Some("Service paused - system proxies restored."),
        );
        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);

        assert!(text.contains("Paused · v0.5.0 (temporarily stopped)"));
        assert!(text.contains("Offline · routes & proxies restored"));
        assert!(text.contains("✓ Service paused - system proxies restored."));
        assert_eq!(state.menu.items.len(), 9);
        assert!(state
            .menu
            .items
            .iter()
            .any(|item| matches!(item.choice, Choice::SwitchEngine(_))));
        for (idx, item) in state.menu.items.iter().enumerate() {
            assert!(
                text.contains(&format!("[{}]", idx + 1)),
                "missing badge {}:\n{text}",
                idx + 1
            );
            assert!(
                text.contains(&item.title),
                "missing item title '{}':\n{text}",
                item.title
            );
        }
        assert!(text.contains(&state.menu.items[0].hint));
        assert!(
            text.contains("↑↓ · 1-9 select · d dns · s split · r refresh · enter · q quit"),
            "missing full 1-9 footer:\n{text}"
        );
        assert!(buf
            .content()
            .iter()
            .any(|c| c.symbol() == "●" && c.fg == AMBER_WARN));

        // Failure notice renders amber warning icon.
        let warn_state = UiState::new(&status_paused(), Some("Pause failed: access denied"));
        let warn_buf = render_state(80, 24, &warn_state, true);
        let warn_text = buffer_text(&warn_buf);
        assert!(warn_text.contains("! Pause failed: access denied"));
        assert!(warn_buf
            .content()
            .iter()
            .any(|c| c.symbol() == "!" && c.fg == AMBER_WARN));
    }

    #[test]
    fn renders_not_installed_and_update_available_at_80x24() {
        let fresh = UiState::new(&status_not_installed(), None);
        let fresh_buf = render_state(80, 24, &fresh, true);
        let fresh_text = buffer_text(&fresh_buf);
        assert!(fresh_text.contains("Not installed"));
        assert!(fresh_text.contains("Offline · routes & proxies restored"));
        assert!(fresh_text.contains("Run directly"));
        assert!(fresh_text.contains("Install for automatic startup"));
        assert!(fresh_text.contains("Split tunneling · All apps"));
        assert!(fresh_text.contains("Run diagnostics"));
        assert!(fresh_text.contains("Quit"));
        assert!(
            fresh_text.contains("↑↓ · 1-7 select · d dns · s split · r refresh · enter · q quit")
        );

        let update = UiState::new(&status_update_available(), None);
        let update_buf = render_state(80, 24, &update, true);
        let update_text = buffer_text(&update_buf);
        assert!(update_text.contains("Running · v0.3.0 -> v0.5.0 update ready"));
        assert!(update_text.contains("Update installed vdpi (v0.3.0 -> v0.5.0)"));
        assert!(update_text.contains("Pause background service"));
        assert!(update_text.contains("Uninstall vdpi"));
        assert!(update_buf
            .content()
            .iter()
            .any(|c| c.symbol() == "●" && c.fg == ICE_BLUE));

        // Tall terminal (>= 28 rows) expands to display every item's hint.
        let tall_buf = render_state(80, 32, &fresh, true);
        let tall_text = buffer_text(&tall_buf);
        for item in &fresh.menu.items {
            let expected_hint = truncate_text(&item.hint, 60);
            assert!(
                tall_text.contains(expected_hint.as_ref()),
                "tall 80x32 missing hint '{}':\n{tall_text}",
                expected_hint
            );
        }
    }

    #[test]
    fn inline_uninstall_confirmation_flow_and_rendering() {
        let mut state = UiState::new(&status_running_live(), None);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Select Uninstall via its number key -> enters confirmation instead of finishing.
        let uninstall_idx = state
            .menu
            .items
            .iter()
            .position(|i| i.choice == Choice::Uninstall)
            .expect("running menu includes Uninstall");
        let uninstall_key = char::from_digit(
            u32::try_from(uninstall_idx + 1).expect("uninstall badge fits u32"),
            10,
        )
        .expect("uninstall shortcut is single digit");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(uninstall_key))),
            Action::Redraw
        );
        assert!(state.confirming_uninstall);
        assert_eq!(state.selected, uninstall_idx);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("● Confirm uninstall"),
            "missing confirm header:\n{text}"
        );
        assert!(
            text.contains("stops the background service")
                && text.contains("restores routes & proxies."),
            "missing confirm body:\n{text}"
        );
        assert!(
            text.contains("[y] Uninstall vdpi   ·   [n / Esc] Cancel"),
            "missing confirm prompt:\n{text}"
        );
        assert!(buf
            .content()
            .iter()
            .any(|c| c.symbol() == "●" && c.fg == RED_DANGER));

        // Narrow 46x18 renders confirmation cleanly as well, keeping [y] red and Cancel neutral.
        let narrow_buf = render_state(46, 18, &state, true);
        let narrow_text = buffer_text(&narrow_buf);
        assert!(narrow_text.contains("● Confirm uninstall"));
        assert!(narrow_text.contains("[y] Uninstall · [n/Esc] Cancel"));
        let prompt_y = narrow_text
            .lines()
            .position(|line| line.contains("[y] Uninstall · [n/Esc] Cancel"))
            .expect("narrow confirm prompt row");
        let y_col = (0..narrow_buf.area.width)
            .find(|&x| narrow_buf[(x, prompt_y as u16)].symbol() == "y")
            .expect("y key cell");
        let cancel_col = (0..narrow_buf.area.width)
            .find(|&x| narrow_buf[(x, prompt_y as u16)].symbol() == "C")
            .expect("Cancel cell");
        assert_eq!(narrow_buf[(y_col, prompt_y as u16)].fg, RED_DANGER);
        assert_eq!(narrow_buf[(cancel_col, prompt_y as u16)].fg, TEXT_LIGHT);

        // Tall 120x30 confirm card stays compact (sized from status + confirm body, not menu items).
        let tall_buf = render_state(120, 30, &state, true);
        let tall_text = buffer_text(&tall_buf);
        let top_border_y = tall_text
            .lines()
            .position(|line| line.contains('╭'))
            .expect("top border");
        let bot_border_y = tall_text
            .lines()
            .position(|line| line.contains('╰'))
            .expect("bottom border");
        let confirm_card_height = bot_border_y - top_border_y + 1;
        assert_eq!(
            confirm_card_height, 18,
            "confirm card should not inherit menu height on 120x30:\n{tall_text}"
        );

        // Repeat 'y' must be ignored so held keys cannot accidentally confirm.
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('y'),
                    KeyModifiers::NONE,
                    KeyEventKind::Repeat
                )
            ),
            Action::Ignore
        );
        assert!(state.confirming_uninstall);

        // 'n' cancels safely back to menu.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('n'))),
            Action::Redraw
        );
        assert!(!state.confirming_uninstall);

        // Re-enter via Enter on Uninstall item, then cancel with Esc.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state.confirming_uninstall);
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(!state.confirming_uninstall);

        // Re-enter and cancel with 'q'.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state.confirming_uninstall);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('q'))),
            Action::Redraw
        );
        assert!(!state.confirming_uninstall);

        // Re-enter and confirm with 'y' and 'Y'.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('y'))),
            Action::Finish(Choice::Uninstall)
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('Y'))),
            Action::Finish(Choice::Uninstall)
        );
    }

    #[test]
    fn live_refresh_hotkey_updates_menu_and_clamps_selection() {
        let mut state = UiState::new(&status_paused(), None);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Move to last item (index 8 of 9).
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.selected, 8);

        // Pressing 'r' or 'R' requests refresh.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('r'))),
            Action::Refresh
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('R'))),
            Action::Refresh
        );

        // Apply refresh to NotInstalled (7 items): selection clamps cleanly to 6 and notice updates.
        apply_refresh(&mut state, &status_not_installed());
        assert_eq!(state.selected, 6);
        assert_eq!(state.menu.notice.as_deref(), Some("Status refreshed."));
        assert!(!state.confirming_uninstall);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(text.contains("✓ Status refreshed."));
        assert!(text.contains("▸ [7] Quit"));
    }

    #[test]
    fn renders_narrow_46x18_and_no_color_cleanly() {
        let running = UiState::new(&status_running_live(), None);
        let buf = render_state(46, 18, &running, true);
        let text = buffer_text(&buf);
        assert!(text.contains("vdpi"));
        assert!(text.contains(repo_display()));
        assert!(text.contains("Service"));
        assert!(text.contains("Anti-DPI"));
        assert!(text.contains("r refresh"));
        for idx in 0..running.menu.items.len() {
            assert!(
                text.contains(&format!("[{}]", idx + 1)),
                "narrow 46x18 missing badge {}:\n{text}",
                idx + 1
            );
        }

        // Below the header fit threshold, the repo URL hides cleanly.
        let tighter_buf = render_state(36, 18, &running, true);
        let tighter_text = buffer_text(&tighter_buf);
        assert!(tighter_text.contains("vdpi"));
        assert!(!tighter_text.contains(repo_display()));

        // NO_COLOR across normal and confirm modes: plain border, zero RGB colors, REVERSED active row.
        for confirming in [false, true] {
            let mut state = UiState::new(&status_running_live(), Some("Status refreshed."));
            state.confirming_uninstall = confirming;
            let no_color = render_state(80, 24, &state, false);
            let no_color_text = buffer_text(&no_color);
            assert!(
                no_color_text.contains('┌')
                    && no_color_text.contains('└')
                    && !no_color_text.contains('╭'),
                "NO_COLOR confirming={confirming} must use plain border:\n{no_color_text}"
            );
            assert!(
                no_color
                    .content()
                    .iter()
                    .all(|c| c.fg == Color::Reset && c.bg == Color::Reset),
                "NO_COLOR confirming={confirming} must not emit RGB colors"
            );
            if !confirming {
                assert!(no_color
                    .content()
                    .iter()
                    .any(|c| c.modifier.contains(Modifier::REVERSED)));
            }
            assert!(
                no_color
                    .content()
                    .iter()
                    .any(|c| c.modifier.contains(Modifier::BOLD)),
                "NO_COLOR confirming={confirming} must apply BOLD hierarchy"
            );
            assert!(
                no_color
                    .content()
                    .iter()
                    .any(|c| c.modifier.contains(Modifier::DIM)),
                "NO_COLOR confirming={confirming} must apply DIM hierarchy"
            );
        }
    }

    #[test]
    fn renders_degenerate_and_scrolled_sizes_without_panicking() {
        let mut paused = UiState::new(&status_paused(), Some("Service paused."));
        let mut confirm = UiState::new(&status_running_live(), None);
        confirm.confirming_uninstall = true;
        let empty = UiState {
            menu: LauncherMenu {
                status_rows: Vec::new(),
                notice: None,
                items: Vec::new(),
            },
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: 0,
            editing_custom_dns: false,
            custom_dns_input: String::new(),
            custom_dns_cursor: 0,
            custom_dns_error: None,
            configured_dns: DNS_PRESETS[0].addr.to_string(),
            split_tunnel: SplitTunnelConfig::default(),
            show_tun_tip: false,
        };

        for state in [&paused, &confirm, &empty] {
            for (width, height) in [
                (46, 18),
                (28, 10),
                (20, 7),
                (14, 5),
                (12, 4),
                (8, 3),
                (4, 1),
                (0, 0),
            ] {
                for color in [true, false] {
                    let _ = render_state(width, height, state, color);
                }
            }
        }

        // Verify scrolled selection on a very short framed terminal keeps selected item visible.
        paused.selected = paused.menu.items.len() - 1;
        let buf = render_state(40, 6, &paused, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("▸ [9] Quit"),
            "expected scrolled item:\n{text}"
        );
    }

    #[test]
    fn keyboard_navigation_wraps_and_filters_event_kinds() {
        let mut state = UiState::new(&status_not_installed(), None);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        assert_eq!(handle_key(&mut state, press(KeyCode::Up)), Action::Redraw);
        assert_eq!(state.selected, 6);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('k'))),
            Action::Redraw
        );
        assert_eq!(state.selected, 5);
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)
            ),
            Action::Redraw
        );
        assert_eq!(state.selected, 4);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(state.selected, 0);
        assert_eq!(handle_key(&mut state, press(KeyCode::Down)), Action::Redraw);
        assert_eq!(state.selected, 1);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('j'))),
            Action::Redraw
        );
        assert_eq!(state.selected, 2);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected, 3);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected, 4);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected, 5);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected, 6);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected, 0);

        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            for code in [
                KeyCode::Enter,
                KeyCode::Char('1'),
                KeyCode::Char('r'),
                KeyCode::Esc,
                KeyCode::Char('q'),
            ] {
                assert_eq!(
                    handle_key(
                        &mut state,
                        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
                    ),
                    Action::Ignore
                );
            }
        }

        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('5'))),
            Action::Finish(Choice::SplitTunnel)
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('6'))),
            Action::Finish(Choice::Doctor)
        );
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
            ),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('1'), KeyModifiers::ALT)
            ),
            Action::Ignore
        );
    }

    #[test]
    fn truncate_text_wrap_words_and_rule_invariants() {
        assert_eq!(RULE.chars().count(), MAX_RULE_COLS);
        assert_eq!(RULE.len(), MAX_RULE_COLS * '─'.len_utf8());

        assert!(matches!(truncate_text("hello", 10), Cow::Borrowed("hello")));
        assert!(matches!(truncate_text("hello", 5), Cow::Borrowed("hello")));
        assert_eq!(truncate_text("hello world", 6), "hello…");
        assert_eq!(truncate_text("hello", 2), "h…");
        assert!(matches!(truncate_text("hello", 1), Cow::Borrowed("h")));
        assert!(matches!(truncate_text("hello", 0), Cow::Borrowed("")));

        assert_eq!(wrap_words("one two three", 7), vec!["one two", "three"]);
        assert!(wrap_words("hello", 0).is_empty());

        assert!(matches!(
            format_full_badge("[VPN: Mullvad]"),
            Cow::Borrowed("[VPN: Mullvad]")
        ));
        assert_eq!(format_full_badge("VPN: Mullvad"), "[VPN: Mullvad]");
    }

    fn tun_vpn_state() -> UiState {
        UiState {
            menu: LauncherMenu {
                status_rows: vec![
                    StatusRow {
                        label: "Service".to_string(),
                        value: "Running · v0.5.0".to_string(),
                        tone: StatusTone::Active,
                        badge: None,
                    },
                    StatusRow {
                        label: "Anti-DPI".to_string(),
                        value: "Active · Combo · DoH on · QUIC blocked".to_string(),
                        tone: StatusTone::Active,
                        badge: None,
                    },
                    StatusRow {
                        label: "Engine".to_string(),
                        value: "TUN · 4 active · 12 cached hosts".to_string(),
                        tone: StatusTone::Warning,
                        badge: Some(("[VPN: Mullvad]".to_string(), StatusTone::Warning)),
                    },
                ],
                notice: None,
                items: vec![
                    MenuItem {
                        choice: Choice::PauseService,
                        title: "Pause background service".to_string(),
                        hint: "Temporarily stops vdpi and restores routing.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::SwitchEngine(EngineMode::Proxy),
                        title: "Switch to Proxy mode".to_string(),
                        hint: "Use classic local HTTP/SOCKS5 proxy instead of TUN.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::Update,
                        title: "Check for updates online".to_string(),
                        hint: "Checks GitHub Releases and updates automatically.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::Doctor,
                        title: "Run diagnostics".to_string(),
                        hint: "Tests DNS ring and anti-DPI bypass connectivity.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::Uninstall,
                        title: "Uninstall vdpi".to_string(),
                        hint: "Stops service, removes files & PATH, restores routing.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::Cancel,
                        title: "Quit".to_string(),
                        hint: "Exit without changing anything.".to_string(),
                    },
                ],
            },
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: 0,
            editing_custom_dns: false,
            custom_dns_input: String::new(),
            custom_dns_cursor: 0,
            custom_dns_error: None,
            configured_dns: DNS_PRESETS[0].addr.to_string(),
            split_tunnel: SplitTunnelConfig::default(),
            show_tun_tip: false,
        }
    }

    fn rightmost_content_col(buf: &Buffer, y: u16) -> Option<u16> {
        (0..buf.area.width)
            .rev()
            .find(|&x| !matches!(buf[(x, y)].symbol(), " " | "│"))
    }

    #[test]
    fn renders_tun_with_vpn_badge_at_80x24() {
        let state = tun_vpn_state();
        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);

        assert!(text.contains("TUN · 4 active · 12 cached hosts"));
        assert!(text.contains("[VPN: Mullvad]"));
        assert!(
            text.contains("↑↓ move · 1-6 select · d dns · r refresh · enter ok · q quit"),
            "footer must remain uncluttered:\n{text}"
        );

        let header_y = u16::try_from(
            text.lines()
                .position(|line| line.contains(repo_display()))
                .expect("header row"),
        )
        .expect("header y fits u16");
        let engine_y = u16::try_from(
            text.lines()
                .position(|line| {
                    line.contains("Engine")
                        && line.contains("TUN · 4 active · 12 cached hosts")
                        && line.contains("[VPN: Mullvad]")
                })
                .expect("engine row with full VPN badge"),
        )
        .expect("engine y fits u16");

        let header_right = rightmost_content_col(&buf, header_y).expect("header right col");
        let badge_end = rightmost_content_col(&buf, engine_y).expect("badge right col");
        assert_eq!(
            badge_end, header_right,
            "VPN badge must align flush with right edge:\n{text}"
        );
        assert_eq!(buf[(badge_end, engine_y)].symbol(), "]");

        let badge_len = u16::try_from("[VPN: Mullvad]".len()).expect("badge len");
        let badge_start = badge_end + 1 - badge_len;
        assert_eq!(buf[(badge_start, engine_y)].symbol(), "[");
        for x in badge_start..=badge_end {
            assert_eq!(
                buf[(x, engine_y)].fg,
                AMBER_WARN,
                "badge cell at x={x} must be AMBER_WARN"
            );
        }
    }

    #[test]
    fn renders_tun_with_compact_vpn_badge_at_46x18_and_omits_when_too_narrow() {
        let state = tun_vpn_state();
        let buf = render_state(46, 18, &state, true);
        let text = buffer_text(&buf);

        assert!(
            text.contains("TUN · 4 active · 12 …"),
            "narrow 46x18 should truncate TUN value to budget - 7:\n{text}"
        );
        assert!(
            text.contains("[VPN]"),
            "narrow 46x18 should render compact [VPN] badge:\n{text}"
        );
        assert!(
            !text.contains("[VPN: Mullvad]"),
            "narrow 46x18 must not overflow with full badge:\n{text}"
        );

        let header_y = u16::try_from(
            text.lines()
                .position(|line| line.contains(repo_display()))
                .expect("narrow header row"),
        )
        .expect("header y fits u16");
        let engine_y = u16::try_from(
            text.lines()
                .position(|line| line.contains("Engine") && line.contains("[VPN]"))
                .expect("narrow engine row with compact VPN badge"),
        )
        .expect("engine y fits u16");

        assert_eq!(buf[(0, engine_y)].symbol(), "│");
        assert_eq!(buf[(45, engine_y)].symbol(), "│");
        let header_right = rightmost_content_col(&buf, header_y).expect("header right col");
        let badge_end = rightmost_content_col(&buf, engine_y).expect("compact badge end");
        assert_eq!(badge_end, header_right);

        let badge_len = u16::try_from(COMPACT_VPN_BADGE.len()).expect("compact len");
        let badge_start = badge_end + 1 - badge_len;
        assert_eq!(buf[(badge_start, engine_y)].symbol(), "[");
        assert_eq!(buf[(badge_end, engine_y)].symbol(), "]");
        for x in badge_start..=badge_end {
            assert_eq!(buf[(x, engine_y)].fg, AMBER_WARN);
        }

        // Below budget 18 (width 30 -> inner 26 -> budget 14): badge omits cleanly with intact border.
        let tiny_buf = render_state(30, 18, &state, true);
        let tiny_text = buffer_text(&tiny_buf);
        assert!(tiny_text.contains("Engine"));
        assert!(
            !tiny_text.contains("[VPN"),
            "budget < 18 must omit badge cleanly:\n{tiny_text}"
        );
        let tiny_engine_y = u16::try_from(
            tiny_text
                .lines()
                .position(|line| line.contains("Engine"))
                .expect("tiny engine row"),
        )
        .expect("tiny engine y fits u16");
        assert_eq!(tiny_buf[(29, tiny_engine_y)].symbol(), "│");

        // Degenerate sizes with VPN badge must never panic.
        for (w, h) in [(28, 10), (20, 7), (14, 5), (12, 4), (8, 3), (4, 1), (0, 0)] {
            for color in [true, false] {
                let _ = render_state(w, h, &state, color);
            }
        }
    }

    #[test]
    fn renders_tun_vpn_badge_and_warning_dot_under_no_color() {
        let state = tun_vpn_state();

        // 80x24 NO_COLOR: full badge bold, warning dot is "! ", Active rows remain "● ".
        let buf = render_state(80, 24, &state, false);
        let text = buffer_text(&buf);
        assert!(text.contains('┌') && text.contains('└') && !text.contains('╭'));
        assert!(buf
            .content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
        assert!(
            text.contains("● Service"),
            "Active row must keep bullet dot under NO_COLOR:\n{text}"
        );
        assert!(
            text.contains("● Anti-DPI"),
            "Active row must keep bullet dot under NO_COLOR:\n{text}"
        );
        assert!(
            text.contains("! Engine") && !text.contains("● Engine"),
            "Warning row must render '! ' indicator under NO_COLOR:\n{text}"
        );
        assert!(text.contains("[VPN: Mullvad]"));

        let engine_y = u16::try_from(
            text.lines()
                .position(|line| line.contains("! Engine") && line.contains("[VPN: Mullvad]"))
                .expect("NO_COLOR engine row"),
        )
        .expect("engine y fits u16");
        let bang_col = (0..buf.area.width)
            .find(|&x| buf[(x, engine_y)].symbol() == "!")
            .expect("warning bang cell");
        assert!(buf[(bang_col, engine_y)].modifier.contains(Modifier::BOLD));

        let badge_end = rightmost_content_col(&buf, engine_y).expect("NO_COLOR badge end");
        let badge_len = u16::try_from("[VPN: Mullvad]".len()).expect("badge len");
        let badge_start = badge_end + 1 - badge_len;
        for x in badge_start..=badge_end {
            assert!(
                buf[(x, engine_y)].modifier.contains(Modifier::BOLD),
                "NO_COLOR badge cell at x={x} must be BOLD"
            );
        }

        // 46x18 NO_COLOR: compact [VPN] badge bold and "! Engine" warning dot.
        let narrow_buf = render_state(46, 18, &state, false);
        let narrow_text = buffer_text(&narrow_buf);
        assert!(narrow_buf
            .content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
        assert!(narrow_text.contains("! Engine"));
        assert!(narrow_text.contains("[VPN]") && !narrow_text.contains("[VPN: Mullvad]"));
        let narrow_engine_y = u16::try_from(
            narrow_text
                .lines()
                .position(|line| line.contains("! Engine") && line.contains("[VPN]"))
                .expect("narrow NO_COLOR engine row"),
        )
        .expect("narrow engine y fits u16");
        let narrow_end = rightmost_content_col(&narrow_buf, narrow_engine_y).expect("end col");
        let compact_len = u16::try_from(COMPACT_VPN_BADGE.len()).expect("compact len");
        for x in (narrow_end + 1 - compact_len)..=narrow_end {
            assert!(narrow_buf[(x, narrow_engine_y)]
                .modifier
                .contains(Modifier::BOLD));
        }

        // Verify all 4 tones under NO_COLOR: Warning -> "! ", Active/Accent/Neutral -> "● ".
        let tones_state = UiState {
            menu: LauncherMenu {
                status_rows: vec![
                    StatusRow {
                        label: "Active".to_string(),
                        value: "ok".to_string(),
                        tone: StatusTone::Active,
                        badge: None,
                    },
                    StatusRow {
                        label: "Accent".to_string(),
                        value: "update".to_string(),
                        tone: StatusTone::Accent,
                        badge: None,
                    },
                    StatusRow {
                        label: "Warn".to_string(),
                        value: "conflict".to_string(),
                        tone: StatusTone::Warning,
                        badge: None,
                    },
                    StatusRow {
                        label: "Neutral".to_string(),
                        value: "idle".to_string(),
                        tone: StatusTone::Neutral,
                        badge: None,
                    },
                ],
                notice: None,
                items: vec![MenuItem {
                    choice: Choice::Cancel,
                    title: "Quit".to_string(),
                    hint: "Exit.".to_string(),
                }],
            },
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: 0,
            editing_custom_dns: false,
            custom_dns_input: String::new(),
            custom_dns_cursor: 0,
            custom_dns_error: None,
            configured_dns: DNS_PRESETS[0].addr.to_string(),
            split_tunnel: SplitTunnelConfig::default(),
            show_tun_tip: false,
        };
        let tones_text = buffer_text(&render_state(80, 24, &tones_state, false));
        assert!(tones_text.contains("● Active"));
        assert!(tones_text.contains("● Accent"));
        assert!(tones_text.contains("! Warn"));
        assert!(tones_text.contains("● Neutral"));
    }

    #[test]
    fn switch_engine_m_hotkey_triggers_only_when_available_and_not_confirming() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        let mut state = tun_vpn_state();
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('m'))),
            Action::Finish(Choice::SwitchEngine(EngineMode::Proxy))
        );
        assert_eq!(state.selected, 1);

        state.selected = 0;
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('M'))),
            Action::Finish(Choice::SwitchEngine(EngineMode::Proxy))
        );
        assert_eq!(state.selected, 1);

        // Repeat/Release and modified keys must be ignored.
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            for ch in ['m', 'M'] {
                assert_eq!(
                    handle_key(
                        &mut state,
                        KeyEvent::new_with_kind(KeyCode::Char(ch), KeyModifiers::NONE, kind)
                    ),
                    Action::Ignore
                );
            }
        }
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('m'), KeyModifiers::CONTROL)
            ),
            Action::Ignore
        );
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('m'), KeyModifiers::ALT)
            ),
            Action::Ignore
        );

        // Confirm mode must ignore 'm' and 'M'.
        state.confirming_uninstall = true;
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('m'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('M'))),
            Action::Ignore
        );

        // Menus without SwitchEngine ignore 'm' and 'M'.
        let mut no_switch = UiState {
            menu: LauncherMenu {
                status_rows: Vec::new(),
                notice: None,
                items: vec![
                    MenuItem {
                        choice: Choice::Run,
                        title: "Run directly".to_string(),
                        hint: "Active while this terminal is open.".to_string(),
                    },
                    MenuItem {
                        choice: Choice::Cancel,
                        title: "Quit".to_string(),
                        hint: "Exit.".to_string(),
                    },
                ],
            },
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: 0,
            editing_custom_dns: false,
            custom_dns_input: String::new(),
            custom_dns_cursor: 0,
            custom_dns_error: None,
            configured_dns: DNS_PRESETS[0].addr.to_string(),
            split_tunnel: SplitTunnelConfig::default(),
            show_tun_tip: false,
        };
        assert_eq!(
            handle_key(&mut no_switch, press(KeyCode::Char('m'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut no_switch, press(KeyCode::Char('M'))),
            Action::Ignore
        );
        assert_eq!(no_switch.selected, 0);
    }

    #[test]
    fn status_row_uses_badge_tone_and_truncates_vpn_badge_when_budget_at_least_34() {
        let mut state = tun_vpn_state();
        // Long provider badge with budget >= 34 truncates to [VPN: <trunc>…] instead of collapsing to [VPN].
        state.menu.status_rows[2].badge = Some((
            "VPN: ProtonVPN WireGuard Enterprise".to_string(),
            StatusTone::Warning,
        ));
        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        let engine_row = text
            .lines()
            .find(|line| line.contains("Engine"))
            .expect("engine row at 80x24");
        assert!(
            engine_row.contains("[VPN: Proton") && engine_row.contains("…]"),
            "80x24 long VPN badge should truncate with ellipsis before collapsing to [VPN]:\n{text}"
        );
        assert!(!engine_row.contains("[VPN]"));

        // Non-warning badge tone renders with palette.status(badge_tone) instead of hardcoded AMBER_WARN.
        state.menu.status_rows[0].badge = Some(("Update".to_string(), StatusTone::Accent));
        let accent_buf = render_state(80, 24, &state, true);
        let accent_text = buffer_text(&accent_buf);
        let service_y = u16::try_from(
            accent_text
                .lines()
                .position(|line| line.contains("Service") && line.contains("[Update]"))
                .expect("service row with Accent badge"),
        )
        .expect("service y fits u16");
        let badge_end = rightmost_content_col(&accent_buf, service_y).expect("accent badge end");
        let badge_len = u16::try_from("[Update]".len()).expect("accent badge len");
        let badge_start = badge_end + 1 - badge_len;
        for x in badge_start..=badge_end {
            assert_eq!(
                accent_buf[(x, service_y)].fg,
                ICE_BLUE,
                "Accent badge cell at x={x} must use ICE_BLUE"
            );
        }
    }

    #[test]
    fn dns_picker_opens_via_hotkey_navigates_renders_and_applies_choice() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut state = UiState::new_with_dns(&status_running_live(), None, "1.1.1.1");
        assert!(!state.selecting_dns);

        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert!(state.selecting_dns);
        assert_eq!(state.dns_selected, 0);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("Choose DNS server"),
            "header missing:\n{text}"
        );
        assert!(text.contains("Cloudflare"), "Cloudflare missing:\n{text}");
        assert!(text.contains("AdGuard"), "AdGuard missing:\n{text}");
        assert!(text.contains("94.140.14.14"), "AdGuard IP missing:\n{text}");
        assert!(
            text.contains("[7] Custom DNS"),
            "[7] Custom DNS missing:\n{text}"
        );
        assert!(
            text.contains("IP or https:// DoH URL"),
            "Custom DNS muted placeholder missing:\n{text}"
        );
        assert!(text.contains("[Active]"), "Active tag missing:\n{text}");
        assert!(
            text.contains("↑↓ move · 1-7 pick · enter apply · esc back"),
            "DNS list footer missing:\n{text}"
        );

        // Move down twice (Cloudflare -> Google -> AdGuard) and press Enter.
        assert_eq!(handle_key(&mut state, press(KeyCode::Down)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Down)), Action::Redraw);
        assert_eq!(state.dns_selected, 2);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("94.140.14.14".to_string()))
        );

        // Digit '5' directly picks Quad9.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('5'))),
            Action::Finish(Choice::SetDns("9.9.9.9".to_string()))
        );

        // Esc closes DNS picker back to main menu without exiting.
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(!state.selecting_dns);

        // Rendering DNS picker at compact sizes (46x18, 24x12, 80x24) must never panic.
        state.selecting_dns = true;
        for (w, h) in [(80, 24), (46, 18), (24, 12)] {
            let _ = render_state(w, h, &state, true);
            let _ = render_state(w, h, &state, false);
        }
    }

    #[test]
    fn custom_dns_picker_inline_input_validation_navigation_and_active_badge() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let type_str = |state: &mut UiState, s: &str| {
            for ch in s.chars() {
                assert_eq!(
                    handle_key(state, KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)),
                    Action::Redraw
                );
            }
        };

        // Start with built-in preset active -> [7] Custom DNS shows muted placeholder & hint.
        let mut state = UiState::new_with_dns(&status_running_live(), None, "1.1.1.1");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert!(state.selecting_dns && !state.editing_custom_dns);
        assert_eq!(state.dns_selected, 0);

        // Move to row 7 via End and inspect hint text.
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.dns_selected, 6);
        let list_buf = render_state(80, 24, &state, true);
        let list_text = buffer_text(&list_buf);
        assert!(
            list_text.contains("[7] Custom DNS")
                && list_text.contains("IP or https:// DoH URL")
                && list_text.contains(CUSTOM_DNS_HINT),
            "row 7 highlight & hint missing:\n{list_text}"
        );

        // Enter on row 7 opens empty custom DNS inline editor.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state.selecting_dns && state.editing_custom_dns);
        assert!(state.custom_dns_input.is_empty());

        let editor_buf = render_state(80, 24, &state, true);
        let editor_text = buffer_text(&editor_buf);
        assert!(
            editor_text.contains("Custom DNS: ▏"),
            "editor prompt missing:\n{editor_text}"
        );
        assert!(
            editor_text.contains("IPv4, IPv6, or https:// DoH URL"),
            "editor hint missing:\n{editor_text}"
        );
        assert!(
            editor_text.contains("type IP or URL · enter apply · ctrl+u clear · esc back"),
            "editor footer missing:\n{editor_text}"
        );
        // Verify ice-blue focus accent on prompt & cursor.
        let prompt_y = editor_text
            .lines()
            .position(|l| l.contains("Custom DNS: ▏"))
            .expect("prompt row") as u16;
        let cursor_x = (0..editor_buf.area.width)
            .find(|&x| editor_buf[(x, prompt_y)].symbol() == "▏")
            .expect("cursor cell");
        assert_eq!(editor_buf[(cursor_x, prompt_y)].fg, ICE_BLUE);

        // KeyEventKind::Release must be ignored in custom input mode (Windows ConPTY safety).
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new_with_kind(
                    KeyCode::Char('7'),
                    KeyModifiers::NONE,
                    KeyEventKind::Release
                )
            ),
            Action::Ignore
        );
        assert!(state.custom_dns_input.is_empty());

        // Esc exits custom input mode back to the 7-item DNS picker (does NOT close picker).
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(state.selecting_dns && !state.editing_custom_dns);
        assert_eq!(state.dns_selected, 6);

        // Digit '7' directly enters custom input mode.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('7'))),
            Action::Redraw
        );
        assert!(state.selecting_dns && state.editing_custom_dns);

        // Invalid input is rejected with an inline red error line, and typing clears it.
        type_str(&mut state, "not-a-valid-dns");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state.editing_custom_dns);
        assert!(state.custom_dns_error.is_some());
        let err_buf = render_state(80, 24, &state, true);
        let err_text = buffer_text(&err_buf);
        assert!(
            err_buf
                .content()
                .iter()
                .any(|c| c.symbol() == "●" && c.fg == RED_DANGER),
            "validation error should render in RED_DANGER:\n{err_text}"
        );

        // Ctrl+U clears input and error cleanly.
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            ),
            Action::Redraw
        );
        assert!(state.custom_dns_input.is_empty());
        assert!(state.custom_dns_error.is_none());

        // Typing a custom IPv4 + Backspace edit -> Enter validates and returns Choice::SetDns.
        type_str(&mut state, "76.76.2.09");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "76.76.2.0");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("76.76.2.0".to_string()))
        );

        // Typing a custom DoH URL -> Enter validates and returns normalized Choice::SetDns.
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            ),
            Action::Redraw
        );
        type_str(&mut state, "https://dns.nextdns.io/abc123");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("https://dns.nextdns.io/abc123".to_string()))
        );

        // Input is capped at 200 characters.
        state.custom_dns_input = "a".repeat(MAX_CUSTOM_DNS_INPUT_CHARS);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('z'))),
            Action::Ignore
        );
        assert_eq!(state.custom_dns_input.len(), MAX_CUSTOM_DNS_INPUT_CHARS);
    }

    #[test]
    fn custom_dns_active_badge_prefill_no_color_and_viewport_matrix() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Active custom IPv4 shows header `Custom (76.76.2.0)` and emerald `[Active]` on [7].
        let mut ip_state = UiState::new_with_dns(&status_running_live(), None, "76.76.2.0");
        assert_eq!(
            handle_key(&mut ip_state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(ip_state.dns_selected, 6);
        let ip_buf = render_state(80, 24, &ip_state, true);
        let ip_text = buffer_text(&ip_buf);
        assert!(
            ip_text.contains("Choose DNS server · Custom (76.76.2.0)"),
            "custom IP header missing:\n{ip_text}"
        );
        assert!(
            ip_text.contains("[7] Custom DNS")
                && ip_text.contains("76.76.2.0")
                && ip_text.contains("[Active]"),
            "custom IP row or [Active] missing:\n{ip_text}"
        );
        let row7_y = ip_text
            .lines()
            .position(|l| l.contains("[7] Custom DNS") && l.contains("[Active]"))
            .expect("row 7 with [Active]") as u16;
        let active_x = (0..ip_buf.area.width)
            .find(|&x| {
                ip_buf[(x, row7_y)].symbol() == "["
                    && x + 1 < ip_buf.area.width
                    && ip_buf[(x + 1, row7_y)].symbol() == "A"
            })
            .expect("[Active] start cell");
        assert_eq!(ip_buf[(active_x, row7_y)].fg, EMERALD_ACTIVE);

        // Active custom DoH URL redacts path/token in display and pre-fills full URL when editing.
        let mut doh_state = UiState::new_with_dns(
            &status_running_live(),
            None,
            "https://dns.nextdns.io/abc123",
        );
        assert_eq!(
            handle_key(&mut doh_state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(doh_state.dns_selected, 6);
        let doh_buf = render_state(80, 24, &doh_state, true);
        let doh_text = buffer_text(&doh_buf);
        assert!(
            doh_text.contains("Choose DNS server · Custom (dns.nextdns.io)"),
            "custom DoH header missing:\n{doh_text}"
        );
        assert!(
            doh_text.contains("[7] Custom DNS")
                && doh_text.contains("dns.nextdns.io")
                && !doh_text.contains("abc123")
                && doh_text.contains("[Active]"),
            "custom DoH row missing or leaked secret path:\n{doh_text}"
        );

        // Entering edit mode pre-fills the full active custom DoH URL.
        assert_eq!(
            handle_key(&mut doh_state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(doh_state.editing_custom_dns);
        assert_eq!(doh_state.custom_dns_input, "https://dns.nextdns.io/abc123");

        // NO_COLOR renders both 7-item list and custom editor (with error) with plain borders and zero RGB.
        doh_state.custom_dns_error = Some("Enter a valid IP or https:// URL".to_string());
        for editing in [false, true] {
            doh_state.editing_custom_dns = editing;
            for (w, h) in [(80, 24), (60, 24), (46, 18)] {
                let no_color = render_state(w, h, &doh_state, false);
                let nc_text = buffer_text(&no_color);
                assert!(
                    nc_text.contains('┌') && nc_text.contains('└') && !nc_text.contains('╭'),
                    "NO_COLOR editing={editing} {w}x{h} must use plain border:\n{nc_text}"
                );
                assert!(
                    no_color
                        .content()
                        .iter()
                        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset),
                    "NO_COLOR editing={editing} {w}x{h} must not emit RGB colors"
                );
                if editing {
                    assert!(
                        nc_text.contains("! Enter a valid IP")
                            || nc_text.contains("! Enter a valid"),
                        "NO_COLOR error prefix missing at {w}x{h}:\n{nc_text}"
                    );
                } else {
                    assert!(
                        nc_text.contains("[7] Custom DNS"),
                        "NO_COLOR list missing [7] at {w}x{h}:\n{nc_text}"
                    );
                }
                // Color rendering at 46x18..80x24 must keep intact borders without panicking.
                let color_buf = render_state(w, h, &doh_state, true);
                let color_text = buffer_text(&color_buf);
                assert!(color_text.contains('╭') && color_text.contains('╰'));
            }
            // Degenerate sizes must never panic.
            for (w, h) in [(24, 12), (14, 5), (8, 3), (0, 0)] {
                let _ = render_state(w, h, &doh_state, true);
                let _ = render_state(w, h, &doh_state, false);
            }
        }
    }

    #[test]
    fn live_dashboard_l_hotkey_and_footer_hint() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        let mut running = UiState::new(&status_running_live(), None);
        let dashboard_idx = running
            .menu
            .items
            .iter()
            .position(|item| item.choice == Choice::Dashboard)
            .expect("running live menu includes Dashboard");

        running.selected = running.menu.items.len() - 1;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('l'))),
            Action::Finish(Choice::Dashboard)
        );
        assert_eq!(running.selected, dashboard_idx);

        running.selected = running.menu.items.len() - 1;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('L'))),
            Action::Finish(Choice::Dashboard)
        );
        assert_eq!(running.selected, dashboard_idx);

        // Repeat/Release and modified keys must be ignored.
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            for ch in ['l', 'L'] {
                assert_eq!(
                    handle_key(
                        &mut running,
                        KeyEvent::new_with_kind(KeyCode::Char(ch), KeyModifiers::NONE, kind)
                    ),
                    Action::Ignore
                );
            }
        }
        assert_eq!(
            handle_key(
                &mut running,
                KeyEvent::new(KeyCode::Char('l'), KeyModifiers::CONTROL)
            ),
            Action::Ignore
        );
        assert_eq!(
            handle_key(
                &mut running,
                KeyEvent::new(KeyCode::Char('l'), KeyModifiers::ALT)
            ),
            Action::Ignore
        );

        // Confirm and DNS picker modes must ignore 'l' and 'L'.
        running.confirming_uninstall = true;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('l'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('L'))),
            Action::Ignore
        );
        running.confirming_uninstall = false;

        running.selecting_dns = true;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('l'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('L'))),
            Action::Ignore
        );
        running.selecting_dns = false;

        // Paused and offline/not-installed menus ignore 'l' and 'L' and omit 'l live' from footer.
        for offline_status in [status_paused(), status_not_installed()] {
            let mut offline = UiState::new(&offline_status, None);
            assert_eq!(
                handle_key(&mut offline, press(KeyCode::Char('l'))),
                Action::Ignore
            );
            assert_eq!(
                handle_key(&mut offline, press(KeyCode::Char('L'))),
                Action::Ignore
            );
            assert_eq!(offline.selected, 0);

            let offline_text = buffer_text(&render_state(80, 24, &offline, true));
            assert!(
                !offline_text.contains("l live"),
                "offline menu must not show 'l live' in footer:\n{offline_text}"
            );
        }

        // Full 80x24 (MAX_CARD_WIDTH = 72) footer fits 'l live' cleanly without overflowing.
        let full_buf = render_state(80, 24, &running, true);
        let full_text = buffer_text(&full_buf);
        let header_y = u16::try_from(
            full_text
                .lines()
                .position(|line| line.contains(repo_display()))
                .expect("header row"),
        )
        .expect("header y fits u16");
        let footer_y = u16::try_from(
            full_text
                .lines()
                .position(|line| line.contains("l live") && line.contains("q quit"))
                .expect("full live footer row"),
        )
        .expect("footer y fits u16");
        let header_right = rightmost_content_col(&full_buf, header_y).expect("header right col");
        let footer_right = rightmost_content_col(&full_buf, footer_y).expect("footer right col");
        assert!(
            footer_right <= header_right,
            "live footer must not overflow MAX_CARD_WIDTH right margin ({footer_right} > {header_right}):\n{full_text}"
        );
        let card_right_border = (0..full_buf.area.width)
            .rev()
            .find(|&x| full_buf[(x, footer_y)].symbol() == "│")
            .expect("footer right border");
        assert!(footer_right < card_right_border);

        // Medium 60x24 width keeps 'l live' without overflowing the card border.
        let med_buf = render_state(60, 24, &running, true);
        let med_text = buffer_text(&med_buf);
        assert!(
            med_text.contains("↑↓ · 1-9 select · l live · r refresh · enter · q quit"),
            "medium 60x24 footer should keep 'l live':\n{med_text}"
        );
        let med_footer_y = u16::try_from(
            med_text
                .lines()
                .position(|line| line.contains("l live"))
                .expect("medium footer row"),
        )
        .expect("medium footer y fits u16");
        assert_eq!(med_buf[(59, med_footer_y)].symbol(), "│");

        // Compact narrow 46x18 width gracefully drops 'l live' so nothing overflows.
        let narrow_buf = render_state(46, 18, &running, true);
        let narrow_text = buffer_text(&narrow_buf);
        assert!(
            !narrow_text.contains("l live"),
            "compact narrow 46x18 footer must drop 'l live':\n{narrow_text}"
        );
        assert!(narrow_text.contains("r refresh"));
        let narrow_footer_y = u16::try_from(
            narrow_text
                .lines()
                .position(|line| line.contains("r refresh"))
                .expect("narrow footer row"),
        )
        .expect("narrow footer y fits u16");
        assert_eq!(narrow_buf[(45, narrow_footer_y)].symbol(), "│");
    }

    #[test]
    fn split_tunnel_s_hotkey_summary_refresh_and_footer_fit() {
        use vdpi_core::config::SplitTunnelMode;

        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let split_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["discord.exe".to_string(), "steam.exe".to_string()],
        };

        let mut running =
            UiState::new_with_options(&status_running_live(), None, "1.1.1.1", &split_cfg);
        let split_idx = running
            .menu
            .items
            .iter()
            .position(|item| item.choice == Choice::SplitTunnel)
            .expect("running live menu includes SplitTunnel");
        assert_eq!(split_idx, 4);
        assert_eq!(
            running.menu.items[split_idx].title,
            "Split tunneling · Exclude (2 apps)"
        );

        running.selected = 0;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('s'))),
            Action::Finish(Choice::SplitTunnel)
        );
        assert_eq!(running.selected, split_idx);

        running.selected = 0;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('S'))),
            Action::Finish(Choice::SplitTunnel)
        );
        assert_eq!(running.selected, split_idx);

        // Repeat/Release and modified keys must be ignored.
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            for ch in ['s', 'S'] {
                assert_eq!(
                    handle_key(
                        &mut running,
                        KeyEvent::new_with_kind(KeyCode::Char(ch), KeyModifiers::NONE, kind)
                    ),
                    Action::Ignore
                );
            }
        }
        assert_eq!(
            handle_key(
                &mut running,
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
            ),
            Action::Ignore
        );
        assert_eq!(
            handle_key(
                &mut running,
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::ALT)
            ),
            Action::Ignore
        );

        // Confirm and DNS picker modes must ignore 's' and 'S'.
        running.confirming_uninstall = true;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('s'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('S'))),
            Action::Ignore
        );
        running.confirming_uninstall = false;

        running.selecting_dns = true;
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('s'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut running, press(KeyCode::Char('S'))),
            Action::Ignore
        );
        running.selecting_dns = false;

        // Refresh preserves split_tunnel summary label.
        apply_refresh(&mut running, &status_paused());
        assert!(running
            .menu
            .items
            .iter()
            .any(|item| item.title == "Split tunneling · Exclude (2 apps)"));

        // Menus without SplitTunnel ignore 's' and 'S' and omit 's split' from footer.
        let mut without_split = tun_vpn_state();
        assert_eq!(
            handle_key(&mut without_split, press(KeyCode::Char('s'))),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut without_split, press(KeyCode::Char('S'))),
            Action::Ignore
        );
        let without_text = buffer_text(&render_state(80, 24, &without_split, true));
        assert!(
            !without_text.contains("s split"),
            "menu without SplitTunnel must not show 's split':\n{without_text}"
        );

        // Full 80x24 footer for both live and offline menus fits 's split' within MAX_CARD_WIDTH.
        for status in [
            status_running_live(),
            status_paused(),
            status_not_installed(),
        ] {
            let state = UiState::new_with_options(&status, None, "1.1.1.1", &split_cfg);
            let buf = render_state(80, 24, &state, true);
            let text = buffer_text(&buf);
            assert!(
                text.contains("Split tunneling · Exclude (2 apps)"),
                "rendered menu missing split tunnel title:\n{text}"
            );
            let header_y = u16::try_from(
                text.lines()
                    .position(|line| line.contains(repo_display()))
                    .expect("header row"),
            )
            .expect("header y fits u16");
            let footer_y = u16::try_from(
                text.lines()
                    .position(|line| line.contains("s split") && line.contains("q quit"))
                    .expect("full split footer row"),
            )
            .expect("footer y fits u16");
            let header_right = rightmost_content_col(&buf, header_y).expect("header right col");
            let footer_right = rightmost_content_col(&buf, footer_y).expect("footer right col");
            assert!(
                footer_right <= header_right,
                "split footer must not overflow MAX_CARD_WIDTH right margin ({footer_right} > {header_right}):\n{text}"
            );
        }

        // Medium 60x24 offline menu keeps 's split' cleanly; narrow 46x18 drops it cleanly.
        let paused = UiState::new_with_options(&status_paused(), None, "1.1.1.1", &split_cfg);
        let med_buf = render_state(60, 24, &paused, true);
        let med_text = buffer_text(&med_buf);
        assert!(
            med_text.contains("↑↓ · 1-9 select · s split · r refresh · enter · q quit"),
            "medium 60x24 offline footer should keep 's split':\n{med_text}"
        );
        let narrow_buf = render_state(46, 18, &paused, true);
        let narrow_text = buffer_text(&narrow_buf);
        assert!(
            !narrow_text.contains("s split"),
            "narrow 46x18 footer must drop 's split':\n{narrow_text}"
        );
        assert!(narrow_text.contains("r refresh"));
    }

    #[test]
    fn round1_custom_dns_tail_scroll_altgr_paste_short_errors_and_badges() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // 1. Ctrl+C ignores Repeat (Press only) and uppercase J/K navigate cleanly.
        let mut nav = UiState::new(&status_not_installed(), None);
        assert_eq!(
            handle_key(
                &mut nav,
                KeyEvent::new_with_kind(
                    KeyCode::Char('c'),
                    KeyModifiers::CONTROL,
                    KeyEventKind::Repeat,
                ),
            ),
            Action::Ignore
        );
        assert_eq!(
            handle_key(&mut nav, press(KeyCode::Char('J'))),
            Action::Redraw
        );
        assert_eq!(nav.selected, 1);
        assert_eq!(
            handle_key(&mut nav, press(KeyCode::Char('K'))),
            Action::Redraw
        );
        assert_eq!(nav.selected, 0);

        // 2. DNS picker at 46x18 keeps full Cloudflare 1.1.1.1 [Active] without truncating IP.
        let mut dns = UiState::new_with_dns(&status_running_live(), None, "1.1.1.1");
        assert_eq!(
            handle_key(&mut dns, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut dns, press(KeyCode::Char('J'))),
            Action::Redraw
        );
        assert_eq!(dns.dns_selected, 1);
        assert_eq!(
            handle_key(&mut dns, press(KeyCode::Char('K'))),
            Action::Redraw
        );
        assert_eq!(dns.dns_selected, 0);
        let dns_46 = buffer_text(&render_state(46, 18, &dns, true));
        assert!(
            dns_46.contains("Cloudflare")
                && dns_46.contains("1.1.1.1")
                && dns_46.contains("[Active]"),
            "46x18 DNS picker must not truncate Cloudflare 1.1.1.1:\n{dns_46}"
        );

        // 3. Custom DNS AltGr ('[' / ']'), Paste (strips trailing CRLF), and tail-scroll cursor.
        assert_eq!(
            handle_key(&mut dns, press(KeyCode::Char('7'))),
            Action::Redraw
        );
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(
            handle_key(&mut dns, KeyEvent::new(KeyCode::Char('['), altgr)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut dns, KeyEvent::new(KeyCode::Char(']'), altgr)),
            Action::Redraw
        );
        assert_eq!(dns.custom_dns_input, "[]");
        assert_eq!(
            handle_key(
                &mut dns,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            ),
            Action::Redraw
        );
        let long_doh = "https://freedns.controld.com/p/abcdefghijklmnop1234567890/my-gaming-pc-tail";
        assert_eq!(
            handle_paste(&mut dns, &format!("{long_doh}\r\n")),
            Action::Redraw
        );
        assert_eq!(dns.custom_dns_input, long_doh);
        assert!(dns.editing_custom_dns);

        for (w, h) in [(80, 24), (60, 24), (46, 18)] {
            let buf = render_state(w, h, &dns, true);
            let text = buffer_text(&buf);
            assert!(
                text.contains("…") && text.contains("tail▏"),
                "long DoH URL must tail-scroll and keep cursor ▏ visible at {w}x{h}:\n{text}"
            );
        }

        // 4. Short terminals (height = 7..=10) keep custom_dns_error visible.
        dns.custom_dns_error = Some("Invalid DoH endpoint".to_string());
        for h in 7..=10 {
            let text = buffer_text(&render_state(60, h, &dns, true));
            assert!(
                text.contains("Invalid DoH endpoint"),
                "custom_dns_error dropped at 60x{h}:\n{text}"
            );
        }

        // 5. Non-VPN compact badge at narrow width truncates real badge instead of "[VPN]".
        let mut badge_state = tun_vpn_state();
        badge_state.menu.status_rows[2].badge =
            Some(("Update available".to_string(), StatusTone::Accent));
        let narrow_badge_text = buffer_text(&render_state(46, 18, &badge_state, true));
        assert!(
            !narrow_badge_text.contains("[VPN]"),
            "non-VPN badge must not turn into hardcoded [VPN]:\n{narrow_badge_text}"
        );
        assert!(
            narrow_badge_text.contains("[Update"),
            "non-VPN badge should truncate real badge text:\n{narrow_badge_text}"
        );
    }

    #[test]
    fn round2_warning_notice_classification_and_two_line_wrapping() {
        for warning in [
            "wintun.dll not found next to vdpi.exe - extract all files from the zip",
            "Missing wintun.dll driver file",
            "No running vdpi service detected.",
            "Binary not found in PATH",
            "Elevation cancelled by user (UAC prompt dismissed).",
            "Install canceled.",
            "Warning: active VPN detected",
            "Cannot reach GitHub Releases",
            "Unable to start background service",
            "Administrator privileges required",
            "Please extract all files before running",
            "TUN mode is only supported on desktop",
            "Pause failed: access denied",
            "Dashboard error: timeout",
            "Diagnostics found 2 issues",
            "vdpi is already running",
        ] {
            assert!(
                is_warning_notice(warning),
                "expected warning classification for: {warning}"
            );
        }

        for ok in [
            "Status refreshed.",
            "Service paused - system proxies restored.",
            "Service resumed - anti-DPI active.",
            "vdpi background service uninstalled.",
            "Switched to TUN mode.",
            "DNS updated to Cloudflare (1.1.1.1).",
        ] {
            assert!(
                !is_warning_notice(ok),
                "unexpected warning classification for: {ok}"
            );
        }

        // Missing wintun.dll & UAC cancellation notices render amber '!' and wrap cleanly across 2 rows.
        for notice in [
            "wintun.dll not found next to vdpi.exe - extract all files from the zip",
            "Administrator elevation cancelled (UAC prompt dismissed). Retry and click Yes to continue.",
        ] {
            let state = UiState::new(&status_paused(), Some(notice));
            let buf = render_state(80, 24, &state, true);
            let text = buffer_text(&buf);

            assert!(
                !text.contains("✓ "),
                "warning notice must not use green checkmark:\n{text}"
            );
            assert!(
                text.contains("! "),
                "warning notice must use '!' prefix:\n{text}"
            );
            assert!(
                buf.content()
                    .iter()
                    .any(|c| c.symbol() == "!" && c.fg == AMBER_WARN),
                "warning notice '!' must render in AMBER_WARN:\n{text}"
            );

            // Reconstruct wrapped notice text from buffer rows and verify zero mid-sentence truncation.
            let lines: Vec<&str> = text.lines().collect();
            let first_idx = lines
                .iter()
                .position(|line| line.contains("! "))
                .expect("first wrapped notice row");
            let combined = format!(
                "{} {}",
                lines[first_idx].trim().trim_matches('│').trim(),
                lines[first_idx + 1].trim().trim_matches('│').trim()
            );
            for word in notice.split_whitespace() {
                assert!(
                    combined.contains(word),
                    "wrapped 2-line notice lost word '{word}':\n{text}"
                );
            }
            assert!(
                !combined.contains('…'),
                "2-line notice should fit without ellipsis:\n{text}"
            );
            // All 9 paused menu items remain visible alongside the 2-line notice at 80x24.
            for idx in 1..=state.menu.items.len() {
                assert!(
                    text.contains(&format!("[{idx}]")),
                    "missing menu item [{idx}] with 2-line notice:\n{text}"
                );
            }
        }

        // Notices exceeding 2 lines cap at 2 rows with a trailing ellipsis on row 2.
        let huge = "wintun.dll verification failed: unexpected hash mismatch detected while checking the extracted release archive directory - please re-download and extract all files from the official release zip";
        let wrapped = wrap_notice_lines(huge, 64, MAX_NOTICE_LINES);
        assert_eq!(wrapped.len(), 2);
        assert!(wrapped[1].ends_with('…'));
        assert!(wrapped[0].chars().count() <= 64);
        assert!(wrapped[1].chars().count() <= 64);

        // Short terminal fallback degrades gracefully without panicking.
        let fallback_state = UiState::new(&status_paused(), Some(huge));
        for (w, h) in [(60, 14), (46, 18), (46, 12), (28, 10)] {
            let _ = render_state(w, h, &fallback_state, true);
            let _ = render_state(w, h, &fallback_state, false);
        }
    }

    #[test]
    fn round2_windows_first_run_tun_tip_visibility() {
        let not_installed_proxy = status_not_installed();
        let mut not_installed_tun = status_not_installed();
        not_installed_tun.configured_engine = EngineMode::Tun;

        assert!(should_show_tun_tip_for_platform(true, &not_installed_proxy));
        assert!(!should_show_tun_tip_for_platform(
            false,
            &not_installed_proxy
        ));
        assert!(!should_show_tun_tip_for_platform(true, &not_installed_tun));
        assert!(!should_show_tun_tip_for_platform(
            true,
            &status_running_live()
        ));
        assert!(!should_show_tun_tip_for_platform(true, &status_paused()));

        let mut state = UiState::new(&not_installed_proxy, None);
        assert_eq!(state.show_tun_tip, cfg!(target_os = "windows"));

        // Exercise rendering across platforms by explicitly enabling the Windows first-run tip.
        state.show_tun_tip = true;
        for color in [true, false] {
            let buf = render_state(80, 24, &state, color);
            let text = buffer_text(&buf);
            assert!(
                text.contains(WINDOWS_TUN_TIP),
                "80x24 color={color} must render Windows TUN tip:\n{text}"
            );
            let status_y = text
                .lines()
                .position(|line| line.contains("Anti-DPI"))
                .expect("Anti-DPI status row");
            let tip_y = text
                .lines()
                .position(|line| line.contains(WINDOWS_TUN_TIP))
                .expect("TUN tip row");
            assert_eq!(
                tip_y,
                status_y + 1,
                "TUN tip should appear directly below the status header:\n{text}"
            );
            if !color {
                assert!(buf
                    .content()
                    .iter()
                    .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
            }
        }

        // Compact 46x18 renders cleanly without overflowing the right border.
        let narrow_buf = render_state(46, 18, &state, true);
        let narrow_text = buffer_text(&narrow_buf);
        let tip_y = u16::try_from(
            narrow_text
                .lines()
                .position(|line| line.contains("Tip: Switch to TUN"))
                .expect("narrow tip row"),
        )
        .expect("tip y fits u16");
        assert_eq!(narrow_buf[(45, tip_y)].symbol(), "│");
    }

    #[test]
    fn round2_no_color_uninstall_header_and_custom_dns_input_bg() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // 1. Uninstall confirmation under NO_COLOR=1 uses ASCII '! ' prefix instead of '● '.
        let mut confirm_state = UiState::new(&status_running_live(), None);
        confirm_state.confirming_uninstall = true;
        let confirm_buf = render_state(80, 24, &confirm_state, false);
        let confirm_text = buffer_text(&confirm_buf);
        assert!(
            confirm_text.contains("! Confirm uninstall"),
            "NO_COLOR uninstall confirm must use '! ' prefix:\n{confirm_text}"
        );
        assert!(
            !confirm_text.contains("● Confirm uninstall"),
            "NO_COLOR uninstall confirm must not use filled bullet:\n{confirm_text}"
        );
        assert!(confirm_buf
            .content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
        let confirm_y = u16::try_from(
            confirm_text
                .lines()
                .position(|line| line.contains("! Confirm uninstall"))
                .expect("NO_COLOR confirm header row"),
        )
        .expect("confirm y fits u16");
        let bang_x = (0..confirm_buf.area.width)
            .find(|&x| confirm_buf[(x, confirm_y)].symbol() == "!")
            .expect("confirm bang cell");
        assert!(confirm_buf[(bang_x, confirm_y)]
            .modifier
            .contains(Modifier::BOLD));

        // 2. Custom DNS editor under NO_COLOR=1 styles input_bg (including cursor and bar fill) with REVERSED.
        let mut dns_state = UiState::new_with_dns(&status_running_live(), None, "76.76.2.0");
        assert_eq!(
            handle_key(&mut dns_state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut dns_state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(dns_state.editing_custom_dns);

        let nc_buf = render_state(80, 24, &dns_state, false);
        let nc_text = buffer_text(&nc_buf);
        assert!(nc_buf
            .content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
        let input_y = u16::try_from(
            nc_text
                .lines()
                .position(|line| line.contains("Custom DNS: 76.76.2.0▏"))
                .expect("NO_COLOR custom DNS input row"),
        )
        .expect("input y fits u16");
        let cursor_x = (0..nc_buf.area.width)
            .find(|&x| nc_buf[(x, input_y)].symbol() == "▏")
            .expect("NO_COLOR cursor cell");
        assert!(
            nc_buf[(cursor_x, input_y)]
                .modifier
                .contains(Modifier::REVERSED),
            "NO_COLOR custom DNS cursor must keep REVERSED input_bg"
        );
        assert!(
            nc_buf[(cursor_x - 1, input_y)]
                .modifier
                .contains(Modifier::REVERSED),
            "NO_COLOR custom DNS text must use REVERSED input_bg"
        );
        assert!(
            nc_buf[(cursor_x + 1, input_y)]
                .modifier
                .contains(Modifier::REVERSED),
            "NO_COLOR custom DNS fill must use REVERSED input_bg"
        );

        // 3. Narrow fallback cursor branch (width 15 -> bar_width 13 <= prompt+cursor) preserves input_bg.
        let narrow_color = render_state(15, 10, &dns_state, true);
        let narrow_color_text = buffer_text(&narrow_color);
        let nc_y = u16::try_from(
            narrow_color_text
                .lines()
                .position(|line| line.contains('▏'))
                .expect("narrow color cursor row"),
        )
        .expect("narrow color y fits u16");
        let nc_x = (0..narrow_color.area.width)
            .find(|&x| narrow_color[(x, nc_y)].symbol() == "▏")
            .expect("narrow color cursor cell");
        assert_eq!(narrow_color[(nc_x, nc_y)].fg, ICE_BLUE);
        assert_eq!(narrow_color[(nc_x, nc_y)].bg, ACTIVE_BG);

        let narrow_nc = render_state(15, 10, &dns_state, false);
        let narrow_nc_text = buffer_text(&narrow_nc);
        let nnc_y = u16::try_from(
            narrow_nc_text
                .lines()
                .position(|line| line.contains('▏'))
                .expect("narrow NO_COLOR cursor row"),
        )
        .expect("narrow NO_COLOR y fits u16");
        let nnc_x = (0..narrow_nc.area.width)
            .find(|&x| narrow_nc[(x, nnc_y)].symbol() == "▏")
            .expect("narrow NO_COLOR cursor cell");
        assert!(narrow_nc[(nnc_x, nnc_y)]
            .modifier
            .contains(Modifier::REVERSED));
        assert!(narrow_nc[(nnc_x, nnc_y)].modifier.contains(Modifier::BOLD));
        assert!(narrow_nc
            .content()
            .iter()
            .all(|c| c.fg == Color::Reset && c.bg == Color::Reset));
    }

    #[test]
    fn round2_custom_dns_inline_cursor_left_right_home_end_delete_editing() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let repeat = |code| KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Repeat);

        let mut state = UiState::new_with_dns(&status_running_live(), None, "1.1.1.1");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('7'))),
            Action::Redraw
        );

        // Paste a NextDNS URL with two typos: missing 'e' in nextdns and 'x' instead of 'c'.
        assert_eq!(
            handle_paste(&mut state, "https://dns.nxtdns.io/abx123"),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_cursor, 28);

        // Boundary no-ops at end of input.
        assert_eq!(handle_key(&mut state, press(KeyCode::Right)), Action::Ignore);
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Ignore
        );

        // Home moves cursor to 0; boundary no-ops at start of input.
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(state.custom_dns_cursor, 0);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Ignore);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Ignore
        );

        // Move right 13 positions (including Repeat events) and insert missing 'e'.
        for i in 0..13 {
            let ev = if i % 2 == 0 {
                press(KeyCode::Right)
            } else {
                repeat(KeyCode::Right)
            };
            assert_eq!(handle_key(&mut state, ev), Action::Redraw);
        }
        assert_eq!(state.custom_dns_cursor, 13);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('e'))),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/abx123");
        assert_eq!(state.custom_dns_cursor, 14);

        // Jump to End, move Left 4 times to 'x', Delete it, and insert 'c'.
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.custom_dns_cursor, 29);
        for _ in 0..4 {
            assert_eq!(
                handle_key(&mut state, repeat(KeyCode::Left)),
                Action::Redraw
            );
        }
        assert_eq!(state.custom_dns_cursor, 25);
        assert_eq!(
            handle_key(&mut state, repeat(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/ab123");
        assert_eq!(state.custom_dns_cursor, 25);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('c'))),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/abc123");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("https://dns.nextdns.io/abc123".to_string()))
        );

        // Inline paste inserts at cursor position.
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Right)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Backspace)), Action::Redraw);
        assert_eq!(handle_paste(&mut state, "h"), Action::Redraw);
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/abc123");

        // Long DoH URL keeps cursor visible at Home, middle, and End across 80x24 and 46x18.
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            ),
            Action::Redraw
        );
        let long_doh =
            "https://freedns.controld.com/p/abcdefghijklmnop1234567890/my-gaming-pc-tail";
        assert_eq!(handle_paste(&mut state, long_doh), Action::Redraw);

        for (w, h) in [(80, 24), (46, 18)] {
            // Home: cursor at start with trailing ellipsis.
            state.custom_dns_cursor = 0;
            let home_text = buffer_text(&render_state(w, h, &state, true));
            assert!(
                home_text.contains("▏https://") && home_text.contains('…'),
                "Home cursor rendering failed at {w}x{h}:\n{home_text}"
            );

            // Middle: cursor visible between leading and trailing ellipses.
            state.custom_dns_cursor = 38;
            let mid_text = buffer_text(&render_state(w, h, &state, true));
            let mid_row = mid_text
                .lines()
                .find(|line| line.contains('▏'))
                .expect("middle cursor row");
            assert_eq!(
                mid_row.matches('…').count(),
                2,
                "middle cursor should show both ellipses at {w}x{h}:\n{mid_text}"
            );

            // End: cursor at tail with leading ellipsis.
            state.custom_dns_cursor = long_doh.chars().count();
            let end_text = buffer_text(&render_state(w, h, &state, true));
            assert!(
                end_text.contains('…') && end_text.contains("tail▏"),
                "End cursor rendering failed at {w}x{h}:\n{end_text}"
            );
        }
    }

    #[test]
    fn round3_custom_dns_multiline_paste_takes_first_non_empty_line() {
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        let mut state = UiState::new_with_dns(&status_running_live(), None, "1.1.1.1");
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('d'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('7'))),
            Action::Redraw
        );

        // Simple two-line paste takes only line 1 instead of concatenating both lines.
        assert_eq!(
            handle_paste(&mut state, "1.1.1.1\n8.8.8.8"),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "1.1.1.1");
        assert_eq!(state.custom_dns_cursor, 7);

        // Clear and paste multiline clipboard with leading blank/control lines, whitespace, and CRLF.
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            ),
            Action::Redraw
        );
        state.custom_dns_error = Some("previous error".to_string());
        assert_eq!(
            handle_paste(
                &mut state,
                "\r\n   \n\x07\n  https://dns.nextdns.io/abc123  \r\nhttps://1.1.1.1/dns-query\n"
            ),
            Action::Redraw
        );
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/abc123");
        assert_eq!(state.custom_dns_cursor, 29);
        assert_eq!(state.custom_dns_error, None);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("https://dns.nextdns.io/abc123".to_string()))
        );

        // Blank/control-only multiline paste is ignored without modifying existing input.
        assert_eq!(
            handle_paste(&mut state, "\r\n   \n\t\x07\r\n"),
            Action::Ignore
        );
        assert_eq!(state.custom_dns_input, "https://dns.nextdns.io/abc123");
        assert_eq!(state.custom_dns_cursor, 29);
    }
}
