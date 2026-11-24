use super::{build_menu, Choice, LauncherMenu, MenuItem, StatusRow, StatusTone};
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
const UNINSTALL_CONFIRM_BODY: &str = "This stops the background service, removes installed files and PATH entries, and restores system proxies.";

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
                danger_bold: Style::new().fg(RED_DANGER).add_modifier(Modifier::BOLD),
                active_row: Style::new().bg(ACTIVE_BG),
                active_marker: Style::new().fg(ICE_BLUE).add_modifier(Modifier::BOLD),
                active_badge: Style::new().fg(STEEL_MUTED),
                active_title: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                active_hint: Style::new().fg(STEEL_MUTED),
                inactive_badge: Style::new().fg(SLATE_DIM),
                inactive_title: Style::new().fg(TEXT_LIGHT),
                inactive_hint: Style::new().fg(SLATE_DIM),
                footer_key: Style::new().fg(STEEL_MUTED),
                footer_text: Style::new().fg(SLATE_DIM),
            }
        } else {
            let plain = Style::new();
            let bold = Style::new().add_modifier(Modifier::BOLD);
            Self {
                border: plain,
                divider: plain,
                brand: bold,
                version: plain,
                repo: plain,
                status_label: plain,
                status_active: plain,
                status_accent: plain,
                status_warn: plain,
                status_neutral: plain,
                danger_bold: bold,
                active_row: Style::new().add_modifier(Modifier::REVERSED),
                active_marker: bold,
                active_badge: plain,
                active_title: bold,
                active_hint: plain,
                inactive_badge: plain,
                inactive_title: plain,
                inactive_hint: plain,
                footer_key: plain,
                footer_text: plain,
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
}

impl UiState {
    fn new(status: &ControlCenterStatus, notice: Option<&str>) -> Self {
        Self {
            menu: build_menu(status, notice),
            selected: 0,
            confirming_uninstall: false,
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

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            let _ = execute!(stdout, Show, LeaveAlternateScreen);
            let _ = terminal::disable_raw_mode();
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
                let _ = terminal::disable_raw_mode();
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
        let _ = execute!(self.terminal.backend_mut(), Show, LeaveAlternateScreen);
        let _ = terminal::disable_raw_mode();
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
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut state = UiState::new(initial_status, notice);
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
    state.menu = build_menu(latest, Some("Status refreshed."));
    state.confirming_uninstall = false;
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
        KeyCode::Enter => {
            let choice = state.menu.items[state.selected].choice;
            if choice == Choice::Uninstall {
                state.confirming_uninstall = true;
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

    let plan = LayoutPlan::compute(
        area.height,
        menu.items.len(),
        menu.status_rows.len(),
        menu.notice.is_some(),
    );
    let card_width = area.width.min(MAX_CARD_WIDTH);
    let card_height = if state.confirming_uninstall {
        let target = plan.card_height.max(15);
        target.min(area.height)
    } else {
        plan.card_height
    };
    let card_area = centered_rect(area, card_width, card_height);

    let padding = if card_area.width >= 20 {
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

    let ctx = RenderCtx {
        palette,
        inset: inner.width >= 36,
    };

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

    if state.confirming_uninstall {
        let show_footer = inner.height >= 5;
        let show_bot_div = plan.bottom_divider() && inner.height >= 10;
        let footer_reserve = u16::from(show_footer) + u16::from(show_bot_div);
        let confirm_min_body = 5u16;
        let available_before_confirm = bottom.saturating_sub(y).saturating_sub(footer_reserve);
        let status_need = u16::try_from(menu.status_rows.len())
            .unwrap_or(u16::MAX)
            .saturating_add(1)
            .saturating_add(confirm_min_body);

        if available_before_confirm >= status_need {
            for status_row in &menu.status_rows {
                if y < bottom {
                    render_status_row(frame, row(y), status_row, ctx);
                    y = y.saturating_add(1);
                }
            }
            if !menu.status_rows.is_empty() && y < bottom {
                render_divider(frame, row(y), ctx);
                y = y.saturating_add(1);
            }
        }

        let body_bottom = bottom.saturating_sub(footer_reserve).max(y);
        let body_area = Rect::new(inner.x, y, inner.width, body_bottom.saturating_sub(y));
        render_uninstall_confirm(frame, body_area, ctx);

        let mut footer_y = bottom;
        if show_footer && footer_y > y {
            footer_y = footer_y.saturating_sub(1);
            render_confirm_footer(frame, row(footer_y), ctx);
        }
        if show_bot_div && footer_y > y {
            footer_y = footer_y.saturating_sub(1);
            render_divider(frame, row(footer_y), ctx);
        }
        return;
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

fn render_status_row(frame: &mut Frame<'_>, area: Rect, row: &StatusRow, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
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
            Span::styled("● ", tone_style),
            Span::styled(text, tone_style),
        ]);
        frame.render_widget(line, area);
        return;
    }

    let label = format!("{:<width$}", row.label, width = label_width);
    let budget = width.saturating_sub(prefix_cols + right_margin);
    let value = truncate_text(&row.value, budget);
    let line = Line::from(vec![
        Span::raw(pad),
        Span::styled("● ", tone_style),
        Span::styled(label, ctx.palette.status_label),
        Span::raw("  "),
        Span::styled(value, tone_style),
    ]);
    frame.render_widget(line, area);
}

fn is_warning_notice(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("failed") || lower.contains("error") || lower.contains("issues")
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

fn render_uninstall_confirm(frame: &mut Frame<'_>, area: Rect, ctx: RenderCtx) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let body_indent = if ctx.inset { "   " } else { "  " };
    let right_margin = pad.len();
    let wrap_width = usize::from(area.width).saturating_sub(body_indent.len() + right_margin);
    let body_lines = wrap_words(UNINSTALL_CONFIRM_BODY, wrap_width.max(1));

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
    for text in &body_lines {
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
        let full_prompt_cols = body_indent.len() + 41 + right_margin;
        let line = if usize::from(area.width) >= full_prompt_cols {
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
        } else {
            let short = truncate_text(
                "[y] Uninstall · [n/Esc] Cancel",
                usize::from(area.width).saturating_sub(pad.len() + right_margin),
            );
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
            Span::styled(" move  ·  ", text),
            Span::styled(range, key),
            Span::styled(" select  ·  ", text),
            Span::styled("r", key),
            Span::styled(" refresh  ·  ", text),
            Span::styled("enter", key),
            Span::styled(" confirm  ·  ", text),
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
            version: Some("0.4.1".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(4),
            total_connections: Some(90),
            learned_hosts: Some(12),
            isp_stage: Some("balanced".to_string()),
        }
    }

    fn status_running_live() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
        }
    }

    fn status_paused() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        }
    }

    fn status_not_installed() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
        }
    }

    fn status_update_available() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: Some(sample_info(Some("0.3.0"), "0.4.1", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
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
        assert!(text.contains("Running · v0.4.1"));
        assert!(text.contains("Anti-DPI"));
        assert!(text.contains("Active · Combo · DoH on · QUIC blocked"));
        assert!(text.contains("Engine"));
        assert!(text.contains("127.0.0.1:8080 · 4 active · 12 cached hosts"));

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
            text.contains("↑↓ move  ·  1-6 select  ·  r refresh  ·  enter confirm  ·  q quit"),
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

        assert!(text.contains("Paused · v0.4.1 (temporarily stopped)"));
        assert!(text.contains("Offline · system proxies restored"));
        assert!(text.contains("✓ Service paused - system proxies restored."));
        assert_eq!(state.menu.items.len(), 7);
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
            text.contains("↑↓ move  ·  1-7 select  ·  r refresh  ·  enter confirm  ·  q quit"),
            "missing full 1-7 footer:\n{text}"
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
        assert!(fresh_text.contains("Offline · system proxies restored"));
        assert!(fresh_text.contains("Run directly"));
        assert!(fresh_text.contains("Install for automatic startup"));
        assert!(fresh_text.contains("Run diagnostics"));
        assert!(fresh_text.contains("Quit"));
        assert!(fresh_text
            .contains("↑↓ move  ·  1-4 select  ·  r refresh  ·  enter confirm  ·  q quit"));

        let update = UiState::new(&status_update_available(), None);
        let update_buf = render_state(80, 24, &update, true);
        let update_text = buffer_text(&update_buf);
        assert!(update_text.contains("Running · v0.3.0 -> v0.4.1 update ready"));
        assert!(update_text.contains("Update installed vdpi (v0.3.0 -> v0.4.1)"));
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
            assert!(
                tall_text.contains(&item.hint),
                "tall 80x32 missing hint '{}':\n{tall_text}",
                item.hint
            );
        }
    }

    #[test]
    fn inline_uninstall_confirmation_flow_and_rendering() {
        let mut state = UiState::new(&status_running_live(), None);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Select Uninstall via number key '5' -> enters confirmation instead of finishing.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('5'))),
            Action::Redraw
        );
        assert!(state.confirming_uninstall);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("● Confirm uninstall"),
            "missing confirm header:\n{text}"
        );
        assert!(
            text.contains("stops the background service")
                && text.contains("restores system proxies."),
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

        // Narrow 46x18 renders confirmation cleanly as well.
        let narrow_buf = render_state(46, 18, &state, true);
        let narrow_text = buffer_text(&narrow_buf);
        assert!(narrow_text.contains("● Confirm uninstall"));
        assert!(narrow_text.contains("[y] Uninstall"));

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

        // Move to last item (index 6 of 7).
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.selected, 6);

        // Pressing 'r' or 'R' requests refresh.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('r'))),
            Action::Refresh
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('R'))),
            Action::Refresh
        );

        // Apply refresh to NotInstalled (4 items): selection clamps cleanly to 3 and notice updates.
        apply_refresh(&mut state, &status_not_installed());
        assert_eq!(state.selected, 3);
        assert_eq!(state.menu.notice.as_deref(), Some("Status refreshed."));
        assert!(!state.confirming_uninstall);

        let buf = render_state(80, 24, &state, true);
        let text = buffer_text(&buf);
        assert!(text.contains("✓ Status refreshed."));
        assert!(text.contains("▸ [4] Quit"));
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
        paused.selected = 6;
        let buf = render_state(40, 6, &paused, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("▸ [7] Quit"),
            "expected scrolled item:\n{text}"
        );
    }

    #[test]
    fn keyboard_navigation_wraps_and_filters_event_kinds() {
        let mut state = UiState::new(&status_not_installed(), None);
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        assert_eq!(handle_key(&mut state, press(KeyCode::Up)), Action::Redraw);
        assert_eq!(state.selected, 3);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('k'))),
            Action::Redraw
        );
        assert_eq!(state.selected, 2);
        assert_eq!(
            handle_key(
                &mut state,
                KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)
            ),
            Action::Redraw
        );
        assert_eq!(state.selected, 1);
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
            handle_key(&mut state, press(KeyCode::Char('3'))),
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
    }
}
