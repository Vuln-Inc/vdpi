use super::{
    build_menu_with_dns, dns_preset_index, format_dns_label, Choice, LauncherMenu, MenuItem,
    StatusRow, StatusTone, DNS_PRESETS,
};
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
use std::borrow::Cow;
use std::io;
use vdpi::server::REPOSITORY_URL;
use vdpi::service::ControlCenterStatus;

const MAX_CARD_WIDTH: u16 = 72;
const VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const MAX_RULE_COLS: usize = 68;
const RULE: &str = "────────────────────────────────────────────────────────────────────";
const KEY_BADGES: [&str; 9] = [
    "[1]", "[2]", "[3]", "[4]", "[5]", "[6]", "[7]", "[8]", "[9]",
];
const RANGE_LABELS: [&str; 9] = ["1", "1-2", "1-3", "1-4", "1-5", "1-6", "1-7", "1-8", "1-9"];
const COMPACT_VPN_BADGE: &str = "[VPN]";
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
                footer_key: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                footer_text: Style::new().fg(SLATE_DIM),
            }
        } else {
            let plain = Style::new();
            let bold = Style::new().add_modifier(Modifier::BOLD);
            let dim = Style::new().add_modifier(Modifier::DIM);
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
                active_row: Style::new().add_modifier(Modifier::REVERSED),
                active_marker: bold,
                active_badge: bold,
                active_title: bold,
                active_hint: dim,
                inactive_badge: dim,
                inactive_title: plain,
                inactive_hint: dim,
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
    configured_dns: String,
}

impl UiState {
    #[cfg(test)]
    fn new(status: &ControlCenterStatus, notice: Option<&str>) -> Self {
        Self::new_with_dns(status, notice, DNS_PRESETS[0].addr)
    }

    fn new_with_dns(
        status: &ControlCenterStatus,
        notice: Option<&str>,
        configured_dns: &str,
    ) -> Self {
        let dns = configured_dns.trim();
        let dns = if dns.is_empty() {
            DNS_PRESETS[0].addr
        } else {
            dns
        };
        Self {
            menu: build_menu_with_dns(status, notice, dns),
            selected: 0,
            confirming_uninstall: false,
            selecting_dns: false,
            dns_selected: dns_preset_index(dns),
            configured_dns: dns.to_string(),
        }
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
    show_notice: bool,
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
            && (self.visible_status_rows > 0 || self.show_notice)
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

    fn compute(area_height: u16, item_count: usize, status_count: usize, has_notice: bool) -> Self {
        let n = u16::try_from(item_count).unwrap_or(u16::MAX);
        let s = u16::try_from(status_count).unwrap_or(u16::MAX);
        let m = u16::from(has_notice);
        let status_div = u16::from(status_count > 0 || has_notice);
        let status_block = s.saturating_add(m).saturating_add(status_div);

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
                    show_notice: has_notice,
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
                    show_notice: has_notice,
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
                show_notice: has_notice,
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
                show_notice: has_notice,
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
                show_notice: has_notice,
                show_footer: true,
                card_height: compact_tight_h,
            };
        }

        // borders(2) + header(1) + status(s) + notice(m) + items(n) + footer(1)
        let compact_minimal_h = 4u16.saturating_add(s).saturating_add(m).saturating_add(n);
        if area_height >= compact_minimal_h {
            return Self {
                density: Density::CompactMinimal,
                visible_status_rows: status_count,
                show_notice: has_notice,
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

        let (visible_status_rows, show_notice) =
            if remaining >= s.saturating_add(m).saturating_add(min_items) {
                (status_count, has_notice)
            } else if remaining >= s.saturating_add(min_items) {
                (status_count, false)
            } else if status_count > 0 && remaining >= 1u16.saturating_add(min_items) {
                (1, false)
            } else {
                (0, false)
            };

        Self {
            density: Density::CompactMinimal,
            visible_status_rows,
            show_notice,
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
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            if crate::tui_dashboard::take_tui_active() {
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                if crate::tui_dashboard::take_tui_active() {
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
        if crate::tui_dashboard::take_tui_active() {
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
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

pub(super) fn choose<F>(
    color: bool,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut state = UiState::new_with_dns(initial_status, notice, configured_dns);
    if state.menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }
    let mut guard = TerminalGuard::enter()?;

    loop {
        guard.terminal.draw(|frame| render(frame, &state, color))?;
        loop {
            match event::read()? {
                Event::Resize(..) => break,
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
    state.menu = build_menu_with_dns(latest, Some("Status refreshed."), &state.configured_dns);
    state.confirming_uninstall = false;
    state.selecting_dns = false;
    if state.menu.items.is_empty() {
        state.selected = 0;
    } else {
        state.selected = state.selected.min(state.menu.items.len() - 1);
    }
}

fn handle_key(state: &mut UiState, key: KeyEvent) -> Action {
    if key.kind == KeyEventKind::Release {
        return Action::Ignore;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return Action::Finish(Choice::Cancel);
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
        let count = DNS_PRESETS.len();
        if state.dns_selected >= count {
            state.dns_selected = count.saturating_sub(1);
        }
        match key.code {
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                state.dns_selected = (state.dns_selected + count - 1) % count;
                return Action::Redraw;
            }
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
                state.dns_selected = (state.dns_selected + 1) % count;
                return Action::Redraw;
            }
            KeyCode::Home => {
                state.dns_selected = 0;
                return Action::Redraw;
            }
            KeyCode::End => {
                state.dns_selected = count - 1;
                return Action::Redraw;
            }
            _ if key.kind != KeyEventKind::Press => return Action::Ignore,
            KeyCode::Enter => {
                return Action::Finish(Choice::SetDns(DNS_PRESETS[state.dns_selected].addr));
            }
            KeyCode::Char(c @ '1'..='9') => {
                let index = usize::from(c as u8 - b'1');
                if let Some(preset) = DNS_PRESETS.get(index) {
                    state.dns_selected = index;
                    return Action::Finish(Choice::SetDns(preset.addr));
                }
                return Action::Ignore;
            }
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Char('q' | 'Q' | 'b' | 'B') => {
                state.selecting_dns = false;
                return Action::Redraw;
            }
            _ => return Action::Ignore,
        }
    }

    let count = state.menu.items.len();
    if count == 0 {
        return Action::Finish(Choice::Cancel);
    }
    if state.selected >= count {
        state.selected = count - 1;
    }

    match key.code {
        KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
            state.selected = (state.selected + count - 1) % count;
        }
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
            state.selected = (state.selected + 1) % count;
        }
        KeyCode::Home => state.selected = 0,
        KeyCode::End => state.selected = count - 1,
        _ if key.kind != KeyEventKind::Press => return Action::Ignore,
        KeyCode::Char('r' | 'R') => return Action::Refresh,
        KeyCode::Char('d' | 'D') => {
            state.dns_selected = dns_preset_index(&state.configured_dns);
            state.selecting_dns = true;
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
                return Action::Finish(item.choice);
            }
            return Action::Ignore;
        }
        KeyCode::Enter => {
            let choice = state.menu.items[state.selected].choice;
            if choice == Choice::Uninstall {
                state.confirming_uninstall = true;
                return Action::Redraw;
            }
            if choice == Choice::SelectDns {
                state.dns_selected = dns_preset_index(&state.configured_dns);
                state.selecting_dns = true;
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
                    state.dns_selected = dns_preset_index(&state.configured_dns);
                    state.selecting_dns = true;
                    return Action::Redraw;
                }
                return Action::Finish(item.choice);
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

    let plan = LayoutPlan::compute(
        area.height,
        menu.items.len(),
        menu.status_rows.len(),
        menu.notice.is_some(),
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

    if let Some(notice) = menu
        .notice
        .as_deref()
        .filter(|_| plan.show_notice && y < bottom)
    {
        render_notice(frame, row(y), notice, ctx);
        y = y.saturating_add(1);
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
        render_footer(frame, row(footer_y), menu.items.len(), ctx);
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
                Some((
                    truncate_text(&row.value, budget - 7),
                    Cow::Borrowed(COMPACT_VPN_BADGE),
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
    lower.contains("failed")
        || lower.contains("error")
        || lower.contains("issues")
        || lower.contains("already running")
}

fn render_notice(frame: &mut Frame<'_>, area: Rect, notice: &str, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let cleaned = notice
        .strip_prefix("✓ ")
        .or_else(|| notice.strip_prefix("! "))
        .unwrap_or(notice);
    let (prefix, style) = if is_warning_notice(cleaned) {
        ("! ", ctx.palette.status_warn)
    } else {
        ("✓ ", ctx.palette.status_active)
    };
    let budget = usize::from(area.width).saturating_sub(pad.len() + 2 + pad.len());
    let text = truncate_text(cleaned, budget);
    let line = Line::from(vec![
        Span::raw(pad),
        Span::styled(prefix, style),
        Span::styled(text, style),
    ]);
    frame.render_widget(line, area);
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
            Span::styled("● ", ctx.palette.danger_bold),
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
    let preset_count = u16::try_from(DNS_PRESETS.len()).unwrap_or(6);
    // borders(2) + header(1) + top_div(1) + title(1) + gap(1) + presets(6) + gap(1) + hint(1) + bot_div(1) + footer(1)
    let ideal_height = 2 + 1 + 1 + 1 + 1 + preset_count + 1 + 1 + 1 + 1;
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
    let selected = state.dns_selected.min(DNS_PRESETS.len().saturating_sub(1));

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

    let remaining_for_presets = body_bottom.saturating_sub(y);
    if remaining_for_presets >= preset_count + 2 && y < body_bottom {
        y = y.saturating_add(1);
    }

    let show_hint = body_bottom.saturating_sub(y) > preset_count;
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

    for (index, preset) in DNS_PRESETS
        .iter()
        .enumerate()
        .skip(start_index)
        .take(visible_slots)
    {
        if y >= list_bottom {
            break;
        }
        let is_selected = index == selected;
        let is_active = preset
            .addr
            .eq_ignore_ascii_case(state.configured_dns.trim());
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
        let active_tag = if is_active { " [Active]" } else { "" };
        let label = format!("{:<19} {}", preset.name, preset.addr);
        let used = prefix.len() + badge.len() + 1 + active_tag.len() + right_margin;
        let budget = width.saturating_sub(used);
        let display_label = truncate_text(&label, budget);

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
                badge,
                if is_selected {
                    palette.active_badge
                } else {
                    palette.inactive_badge
                },
            ),
            Span::raw(" "),
            Span::styled(
                display_label,
                if is_selected {
                    palette.active_title
                } else {
                    palette.inactive_title
                },
            ),
        ];
        if is_active {
            spans.push(Span::styled(active_tag, palette.status_active));
        }
        frame.render_widget(Line::from(spans), row(y));
        y = y.saturating_add(1);
    }

    if show_hint && y < body_bottom {
        let hint_y = body_bottom.saturating_sub(1);
        let indent = if inset { "       " } else { "      " };
        let budget = width.saturating_sub(indent.len() + right_margin);
        let hint = truncate_text(DNS_PRESETS[selected].hint, budget);
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

fn render_dns_footer(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let key = ctx.palette.footer_key;
    let text = ctx.palette.footer_text;
    let width = usize::from(area.width);
    let range = range_label(DNS_PRESETS.len());

    let line = if width >= pad.len() * 2 + 46 + range.len() {
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
    } else if width >= pad.len() * 2 + 24 + range.len() {
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

fn render_footer(frame: &mut Frame<'_>, area: Rect, item_count: usize, ctx: RenderCtx) {
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
    let full_cols = pad.len() * 2 + 62 + range.len();
    let medium_cols = pad.len() * 2 + 41 + range.len();
    let compact_medium_cols = pad.len() * 2 + 34 + range.len();
    let short_cols = pad.len() * 2 + 21 + range.len();

    let line = if width >= full_cols {
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

    if let Some(item) = state.menu.items.get(selected).filter(|_| area.height >= 2) {
        let item_area = Rect::new(area.x, area.y + 1, area.width, 1);
        render_item_title(frame, item_area, selected, item, true, ctx);
    }

    if area.height >= 3 {
        let footer_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        render_footer(frame, footer_area, state.menu.items.len(), ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use vdpi::service::{InstalledInfo, LiveEngineStatus, ServiceState};
    use vdpi::update::VersionRelation;
    use vdpi_core::config::EngineMode;

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
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
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
            text.contains("↑↓ move · 1-8 select · d dns · r refresh · enter ok · q quit"),
            "missing full footer:\n{text}"
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
            text.contains("↑↓ move · 1-9 select · d dns · r refresh · enter ok · q quit"),
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
        assert!(fresh_text.contains("Run diagnostics"));
        assert!(fresh_text.contains("Quit"));
        assert!(fresh_text.contains("↑↓ move · 1-6 select · d dns · r refresh · enter ok · q quit"));

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

        // Apply refresh to NotInstalled (6 items): selection clamps cleanly to 5 and notice updates.
        apply_refresh(&mut state, &status_not_installed());
        assert_eq!(state.selected, 5);
        assert_eq!(state.menu.notice.as_deref(), Some("Status refreshed."));
        assert!(!state.confirming_uninstall);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(text.contains("✓ Status refreshed."));
        assert!(text.contains("▸ [6] Quit"));
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
            configured_dns: DNS_PRESETS[0].addr.to_string(),
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
        assert_eq!(state.selected, 5);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('k'))),
            Action::Redraw
        );
        assert_eq!(state.selected, 4);
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)
            ),
            Action::Redraw
        );
        assert_eq!(state.selected, 3);
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
            configured_dns: DNS_PRESETS[0].addr.to_string(),
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
            configured_dns: DNS_PRESETS[0].addr.to_string(),
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
            configured_dns: DNS_PRESETS[0].addr.to_string(),
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
        assert!(text.contains("[Active]"), "Active tag missing:\n{text}");

        // Move down twice (Cloudflare -> Google -> AdGuard) and press Enter.
        assert_eq!(handle_key(&mut state, press(KeyCode::Down)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Down)), Action::Redraw);
        assert_eq!(state.dns_selected, 2);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Finish(Choice::SetDns("94.140.14.14"))
        );

        // Digit '5' directly picks Quad9.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('5'))),
            Action::Finish(Choice::SetDns("9.9.9.9"))
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
}
