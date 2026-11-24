use super::{Choice, LauncherMenu, MenuItem};
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

const MAX_CARD_WIDTH: u16 = 66;
const VERSION_LABEL: &str = concat!("v", env!("CARGO_PKG_VERSION"));
const MAX_RULE_COLS: usize = 64;
const RULE: &str = "────────────────────────────────────────────────────────────────";
const KEY_BADGES: [&str; 9] = [
    "[1]", "[2]", "[3]", "[4]", "[5]", "[6]", "[7]", "[8]", "[9]",
];
const RANGE_LABELS: [&str; 9] = ["1", "1-2", "1-3", "1-4", "1-5", "1-6", "1-7", "1-8", "1-9"];

// Restrained cool slate / white / ice-blue / semantic amber palette.
const BORDER_SLATE: Color = Color::Rgb(58, 66, 78);
const DIVIDER_SLATE: Color = Color::Rgb(48, 55, 66);
const ACTIVE_BG: Color = Color::Rgb(28, 35, 45);
const ICE_BLUE: Color = Color::Rgb(110, 180, 255);
const STEEL_MUTED: Color = Color::Rgb(148, 163, 184);
const SLATE_DIM: Color = Color::Rgb(100, 116, 139);
const TEXT_WHITE: Color = Color::Rgb(248, 250, 252);
const TEXT_LIGHT: Color = Color::Rgb(203, 213, 225);
const AMBER_WARN: Color = Color::Rgb(245, 185, 90);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatusIntent {
    UpdateAvailable,
    UpToDate,
    Caution,
}

#[derive(Debug, Clone, Copy)]
struct Palette {
    border: Style,
    divider: Style,
    brand: Style,
    version: Style,
    repo: Style,
    status_update: Style,
    status_same: Style,
    status_warn: Style,
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
                status_update: Style::new().fg(ICE_BLUE),
                status_same: Style::new().fg(STEEL_MUTED),
                status_warn: Style::new().fg(AMBER_WARN),
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
                status_update: plain,
                status_same: plain,
                status_warn: plain,
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

    const fn status(self, intent: StatusIntent) -> Style {
        match intent {
            StatusIntent::UpdateAvailable => self.status_update,
            StatusIntent::UpToDate => self.status_same,
            StatusIntent::Caution => self.status_warn,
        }
    }
}

#[derive(Clone, Copy)]
struct RenderCtx {
    palette: Palette,
    inset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Density {
    Spacious,
    Cozy,
    CompactDivided,
    CompactTight,
    CompactMinimal,
}

#[derive(Debug, Clone, Copy)]
struct LayoutPlan {
    density: Density,
    show_status: bool,
    show_footer: bool,
    card_height: u16,
}

impl LayoutPlan {
    const fn show_hints(self) -> bool {
        matches!(self.density, Density::Spacious | Density::Cozy)
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

    const fn bottom_divider(self) -> bool {
        matches!(
            self.density,
            Density::Spacious | Density::Cozy | Density::CompactDivided
        )
    }

    fn compute(area_height: u16, item_count: usize, has_status: bool) -> Self {
        let n = u16::try_from(item_count).unwrap_or(u16::MAX);
        let status = u16::from(has_status);

        // borders(2) + header(1) + top_div(1) + status + top_gap(1) + items + bot_gap(1) + bot_div(1) + footer(1)
        let spacious_items = if n == 0 {
            0
        } else {
            n.saturating_mul(2).saturating_add(n - 1)
        };
        let spacious_h = 8u16.saturating_add(status).saturating_add(spacious_items);
        if area_height >= spacious_h {
            return Self {
                density: Density::Spacious,
                show_status: has_status,
                show_footer: true,
                card_height: spacious_h,
            };
        }

        // borders(2) + header(1) + top_div(1) + status + items(2*n) + bot_div(1) + footer(1)
        let cozy_h = 6u16
            .saturating_add(status)
            .saturating_add(n.saturating_mul(2));
        if area_height >= cozy_h {
            return Self {
                density: Density::Cozy,
                show_status: has_status,
                show_footer: true,
                card_height: cozy_h,
            };
        }

        // borders(2) + header(1) + top_div(1) + status + items(n) + bot_div(1) + footer(1)
        let compact_divided_h = 6u16.saturating_add(status).saturating_add(n);
        if area_height >= compact_divided_h {
            return Self {
                density: Density::CompactDivided,
                show_status: has_status,
                show_footer: true,
                card_height: compact_divided_h,
            };
        }

        // borders(2) + header(1) + top_div(1) + status + items(n) + footer(1)
        let compact_tight_h = 5u16.saturating_add(status).saturating_add(n);
        if area_height >= compact_tight_h {
            return Self {
                density: Density::CompactTight,
                show_status: has_status,
                show_footer: true,
                card_height: compact_tight_h,
            };
        }

        // borders(2) + header(1) + status + items(n) + footer(1), or clamped fallback
        let compact_minimal_h = 4u16.saturating_add(status).saturating_add(n);
        if area_height >= compact_minimal_h {
            return Self {
                density: Density::CompactMinimal,
                show_status: has_status,
                show_footer: true,
                card_height: compact_minimal_h,
            };
        }

        Self {
            density: Density::CompactMinimal,
            show_status: has_status && area_height >= 6,
            show_footer: area_height >= 5,
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
    Finish(Choice),
    Ignore,
}

pub(super) fn choose(color: bool, menu: &LauncherMenu) -> io::Result<Choice> {
    if menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }
    let mut guard = TerminalGuard::enter()?;
    let mut selected = 0usize;

    loop {
        guard
            .terminal
            .draw(|frame| render(frame, menu, selected, color))?;
        loop {
            match event::read()? {
                Event::Resize(..) => break,
                Event::Key(key) => match handle_key(&mut selected, key, menu) {
                    Action::Redraw => break,
                    Action::Finish(choice) => return Ok(choice),
                    Action::Ignore => {}
                },
                _ => {}
            }
        }
    }
}

fn handle_key(selected: &mut usize, key: KeyEvent, menu: &LauncherMenu) -> Action {
    let count = menu.items.len();
    if count == 0 {
        return Action::Finish(Choice::Cancel);
    }
    if *selected >= count {
        *selected = count - 1;
    }
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
    match key.code {
        KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
            *selected = (*selected + count - 1) % count;
        }
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
            *selected = (*selected + 1) % count;
        }
        KeyCode::Home => *selected = 0,
        KeyCode::End => *selected = count - 1,
        _ if key.kind != KeyEventKind::Press => return Action::Ignore,
        KeyCode::Enter => return Action::Finish(menu.items[*selected].choice),
        KeyCode::Char(c @ '1'..='9') => {
            let index = usize::from(c as u8 - b'1');
            if let Some(item) = menu.items.get(index) {
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

fn status_intent(menu: &LauncherMenu) -> StatusIntent {
    match menu.items.first().map(|item| item.choice) {
        Some(Choice::Update) => StatusIntent::UpToDate,
        Some(Choice::Install)
            if menu
                .status_line
                .as_deref()
                .is_some_and(|s| s.contains("->")) =>
        {
            StatusIntent::UpdateAvailable
        }
        Some(Choice::Run | Choice::Install) => StatusIntent::Caution,
        _ => StatusIntent::UpToDate,
    }
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

fn render(frame: &mut Frame<'_>, menu: &LauncherMenu, selected: usize, color: bool) {
    let area = frame.area();
    if area.is_empty() {
        return;
    }

    let palette = Palette::for_color(color);
    let selected = selected.min(menu.items.len().saturating_sub(1));

    if area.width < 14 || area.height < 5 {
        render_minimal(frame, area, menu, selected, palette);
        return;
    }

    let plan = LayoutPlan::compute(area.height, menu.items.len(), menu.status_line.is_some());
    let card_width = area.width.min(MAX_CARD_WIDTH);
    let card_area = centered_rect(area, card_width, plan.card_height);

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

    if let Some(status) = menu
        .status_line
        .as_deref()
        .filter(|_| plan.show_status && y < bottom)
    {
        render_status(frame, row(y), status, status_intent(menu), ctx);
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

fn render_status(
    frame: &mut Frame<'_>,
    area: Rect,
    status: &str,
    intent: StatusIntent,
    ctx: RenderCtx,
) {
    if area.is_empty() {
        return;
    }
    let pad = if ctx.inset { " " } else { "" };
    let prefix_cols = pad.len() + 2;
    let budget = usize::from(area.width).saturating_sub(prefix_cols + pad.len());
    let text = truncate_text(status, budget);
    let style = ctx.palette.status(intent);
    let line = Line::from(vec![
        Span::raw(pad),
        Span::styled("● ", style),
        Span::styled(text, style),
    ]);
    frame.render_widget(line, area);
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

    let show_hints = plan.show_hints();
    let item_gap = plan.item_gap();
    let visible_slots = match (show_hints, item_gap) {
        (true, true) => usize::from(area.height.saturating_add(1) / 3),
        (true, false) => usize::from(area.height / 2),
        (false, _) => usize::from(area.height),
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

        if show_hints && cursor_y < max_y {
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
    let indent = if ctx.inset { "   " } else { "  " };
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
    let full_cols = pad.len() + 48 + range.len();
    let medium_cols = pad.len() + 29 + range.len();
    let short_cols = pad.len() + 17 + range.len();

    let line = if width >= full_cols {
        Line::from(vec![
            Span::raw(pad),
            Span::styled("↑↓", key),
            Span::styled(" move  ·  ", text),
            Span::styled(range, key),
            Span::styled(" select  ·  ", text),
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
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("q", key),
        ])
    } else {
        Line::from(vec![
            Span::raw(pad),
            Span::styled(range, key),
            Span::styled(" · ", text),
            Span::styled("q", key),
        ])
    };
    frame.render_widget(line, area);
}

fn render_minimal(
    frame: &mut Frame<'_>,
    area: Rect,
    menu: &LauncherMenu,
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

    if let Some(item) = menu.items.get(selected).filter(|_| area.height >= 2) {
        let item_area = Rect::new(area.x, area.y + 1, area.width, 1);
        let ctx = RenderCtx {
            palette,
            inset: false,
        };
        render_item_title(frame, item_area, selected, item, true, ctx);
    }

    if area.height >= 3 {
        let footer_area = Rect::new(area.x, area.y + area.height - 1, area.width, 1);
        let ctx = RenderCtx {
            palette,
            inset: false,
        };
        render_footer(frame, footer_area, menu.items.len(), ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::super::build_menu;
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::path::PathBuf;
    use vdpi::service::InstalledInfo;
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

    fn render_to_buffer(
        width: u16,
        height: u16,
        menu: &LauncherMenu,
        selected: usize,
        color: bool,
    ) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render(frame, menu, selected, color))
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

    fn all_five_menus() -> [(&'static str, LauncherMenu); 5] {
        [
            ("fresh", build_menu(None)),
            (
                "newer",
                build_menu(Some(&sample_info(
                    Some("0.3.0"),
                    "0.4.0",
                    VersionRelation::Newer,
                ))),
            ),
            (
                "same",
                build_menu(Some(&sample_info(
                    Some("0.4.0"),
                    "0.4.0",
                    VersionRelation::Same,
                ))),
            ),
            (
                "older",
                build_menu(Some(&sample_info(
                    Some("0.5.0"),
                    "0.4.0",
                    VersionRelation::Older,
                ))),
            ),
            (
                "unknown",
                build_menu(Some(&sample_info(None, "0.4.0", VersionRelation::Unknown))),
            ),
        ]
    }

    #[test]
    fn renders_all_five_states_across_standard_narrow_and_tiny_sizes() {
        let menus = all_five_menus();
        let sizes = [(80u16, 24u16), (42, 16), (28, 10)];

        for (label, menu) in &menus {
            for &(width, height) in &sizes {
                for color in [true, false] {
                    let buf = render_to_buffer(width, height, menu, 0, color);
                    let text = buffer_text(&buf);

                    // Frame border type and color discipline.
                    if color {
                        assert!(
                            text.contains('╭') && text.contains('╰'),
                            "{label} {width}x{height} color=true missing rounded corners:\n{text}"
                        );
                        assert!(
                            buf.content().iter().any(|c| c.fg == BORDER_SLATE),
                            "{label} {width}x{height} missing slate border color"
                        );
                        assert!(
                            buf.content().iter().any(|c| c.bg == ACTIVE_BG),
                            "{label} {width}x{height} missing active highlight bg"
                        );
                    } else {
                        assert!(
                            text.contains('┌') && text.contains('└') && !text.contains('╭'),
                            "{label} {width}x{height} color=false should use plain border:\n{text}"
                        );
                        assert!(
                            buf.content()
                                .iter()
                                .all(|c| c.fg == Color::Reset && c.bg == Color::Reset),
                            "{label} {width}x{height} color=false must not emit RGB colors"
                        );
                        assert!(
                            buf.content()
                                .iter()
                                .any(|c| c.modifier.contains(Modifier::REVERSED)),
                            "{label} {width}x{height} color=false missing REVERSED active row"
                        );
                    }

                    // Header, divider, active marker, and all key badges always present.
                    assert!(
                        text.contains("vdpi") && text.contains(VERSION_LABEL),
                        "{label} {width}x{height} missing header:\n{text}"
                    );
                    assert!(
                        text.contains('─'),
                        "{label} {width}x{height} missing divider:\n{text}"
                    );
                    assert!(
                        text.contains('▸'),
                        "{label} {width}x{height} missing active marker:\n{text}"
                    );
                    for idx in 0..menu.items.len() {
                        let badge = format!("[{}]", idx + 1);
                        assert!(
                            text.contains(&badge),
                            "{label} {width}x{height} missing badge {badge}:\n{text}"
                        );
                    }

                    // Status pill present whenever menu.status_line is Some.
                    if let Some(status) = &menu.status_line {
                        assert!(
                            text.contains('●'),
                            "{label} {width}x{height} missing status dot:\n{text}"
                        );
                        if color {
                            let expected_fg = match status_intent(menu) {
                                StatusIntent::UpdateAvailable => ICE_BLUE,
                                StatusIntent::UpToDate => STEEL_MUTED,
                                StatusIntent::Caution => AMBER_WARN,
                            };
                            assert!(
                                buf.content()
                                    .iter()
                                    .any(|c| c.symbol() == "●" && c.fg == expected_fg),
                                "{label} {width}x{height} wrong status dot color"
                            );
                        }
                        if width == 80 {
                            assert!(
                                text.contains(status),
                                "{label} 80x24 truncated status:\n{text}"
                            );
                        }
                    } else {
                        assert!(
                            !text.contains('●'),
                            "{label} {width}x{height} unexpected status dot:\n{text}"
                        );
                    }

                    // Standard 80x24 shows full repo, full titles, full hints, and full footer.
                    if width == 80 && height == 24 {
                        assert!(text.contains(repo_display()));
                        for item in &menu.items {
                            assert!(
                                text.contains(&item.title),
                                "{label} 80x24 missing title '{}':\n{text}",
                                item.title
                            );
                            assert!(
                                text.contains(&item.hint),
                                "{label} 80x24 missing hint '{}':\n{text}",
                                item.hint
                            );
                        }
                        let expected_footer = format!(
                            "↑↓ move  ·  1-{} select  ·  enter confirm  ·  q quit",
                            menu.items.len()
                        );
                        assert!(
                            text.contains(&expected_footer),
                            "{label} 80x24 missing full footer '{expected_footer}':\n{text}"
                        );
                    }

                    // Narrow 42x16 omits repo cleanly while keeping hints and footer.
                    if width == 42 && height == 16 {
                        assert!(!text.contains(repo_display()));
                        assert!(text.contains("q quit"));
                    }

                    // Tiny 28x10 auto-compacts to single-line per item with short footer.
                    if width == 28 && height == 10 {
                        assert!(!text.contains(repo_display()));
                        assert!(text.contains("enter · q"));
                    }
                }
            }
        }
    }

    #[test]
    fn renders_degenerate_and_scrolled_sizes_without_panicking() {
        let same = build_menu(Some(&sample_info(
            Some("0.4.0"),
            "0.4.0",
            VersionRelation::Same,
        )));
        let empty = LauncherMenu {
            status_line: None,
            items: Vec::new(),
        };

        for menu in [&same, &empty] {
            for (width, height) in [(20, 7), (14, 5), (12, 4), (8, 3), (4, 1), (0, 0)] {
                for selected in [0, 2, 3, 99] {
                    for color in [true, false] {
                        let _ = render_to_buffer(width, height, menu, selected, color);
                    }
                }
            }
        }

        // Verify scrolled selection on a very short framed terminal keeps selected item visible.
        let buf = render_to_buffer(40, 6, &same, 3, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("▸ [4] Quit"),
            "expected scrolled item:\n{text}"
        );
    }

    #[test]
    fn keyboard_navigation_wraps_and_filters_confirmation_kinds() {
        let menu = build_menu(None);
        let mut selected = 0;
        let press = |code| KeyEvent::new(code, KeyModifiers::NONE);

        // Wrap upward with Up, k, BackTab.
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Up), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 2);
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Char('k')), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 1);
        assert_eq!(
            handle_key(
                &mut selected,
                KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
                &menu,
            ),
            Action::Redraw
        );
        assert_eq!(selected, 0);

        // Wrap downward with Down, j, Tab, and Repeat navigation.
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Down), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 1);
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Char('j')), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 2);
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Tab), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 0);
        assert_eq!(
            handle_key(
                &mut selected,
                KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Repeat),
                &menu,
            ),
            Action::Redraw
        );
        assert_eq!(selected, 1);

        // Home and End.
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::End), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 2);
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Home), &menu),
            Action::Redraw
        );
        assert_eq!(selected, 0);

        // Confirmations must ignore Repeat and Release.
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            for code in [
                KeyCode::Enter,
                KeyCode::Char('1'),
                KeyCode::Char('2'),
                KeyCode::Esc,
                KeyCode::Char('q'),
            ] {
                assert_eq!(
                    handle_key(
                        &mut selected,
                        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind),
                        &menu,
                    ),
                    Action::Ignore
                );
            }
        }

        // Release navigation is also ignored.
        assert_eq!(
            handle_key(
                &mut selected,
                KeyEvent::new_with_kind(KeyCode::Down, KeyModifiers::NONE, KeyEventKind::Release),
                &menu,
            ),
            Action::Ignore
        );
        assert_eq!(selected, 0);

        // Confirm, Escape, q/Q, Ctrl-C, and Alt-modified ignore.
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Enter), &menu),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Esc), &menu),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Char('q')), &menu),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(&mut selected, press(KeyCode::Char('Q')), &menu),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(
                &mut selected,
                KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
                &menu,
            ),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(
                &mut selected,
                KeyEvent::new(KeyCode::Char('1'), KeyModifiers::ALT),
                &menu,
            ),
            Action::Ignore
        );
    }

    #[test]
    fn dynamic_number_keys_match_all_version_states() {
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        let mut selected = 0;

        let fresh = build_menu(None);
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('1')), &fresh),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2')), &fresh),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('3')), &fresh),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('4')), &fresh),
            Action::Ignore
        );

        let newer = build_menu(Some(&sample_info(
            Some("0.3.0"),
            "0.4.0",
            VersionRelation::Newer,
        )));
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Enter), &newer),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('1')), &newer),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2')), &newer),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('3')), &newer),
            Action::Finish(Choice::Cancel)
        );

        let same = build_menu(Some(&sample_info(
            Some("0.4.0"),
            "0.4.0",
            VersionRelation::Same,
        )));
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('1')), &same),
            Action::Finish(Choice::Update)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2')), &same),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('3')), &same),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('4')), &same),
            Action::Finish(Choice::Cancel)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('5')), &same),
            Action::Ignore
        );

        let older = build_menu(Some(&sample_info(
            Some("0.5.0"),
            "0.4.0",
            VersionRelation::Older,
        )));
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('1')), &older),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2')), &older),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('3')), &older),
            Action::Finish(Choice::Cancel)
        );

        let unknown = build_menu(Some(&sample_info(None, "0.4.0", VersionRelation::Unknown)));
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('1')), &unknown),
            Action::Finish(Choice::Install)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2')), &unknown),
            Action::Finish(Choice::Run)
        );
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('3')), &unknown),
            Action::Finish(Choice::Cancel)
        );
    }

    #[test]
    fn status_intent_and_palette_match_version_relations() {
        let palette = Palette::for_color(true);
        let newer = build_menu(Some(&sample_info(
            Some("0.3.0"),
            "0.4.0",
            VersionRelation::Newer,
        )));
        let same = build_menu(Some(&sample_info(
            Some("0.4.0"),
            "0.4.0",
            VersionRelation::Same,
        )));
        let older = build_menu(Some(&sample_info(
            Some("0.5.0"),
            "0.4.0",
            VersionRelation::Older,
        )));
        let unknown = build_menu(Some(&sample_info(None, "0.4.0", VersionRelation::Unknown)));

        assert_eq!(status_intent(&newer), StatusIntent::UpdateAvailable);
        assert_eq!(palette.status(status_intent(&newer)).fg, Some(ICE_BLUE));

        assert_eq!(status_intent(&same), StatusIntent::UpToDate);
        assert_eq!(palette.status(status_intent(&same)).fg, Some(STEEL_MUTED));

        assert_eq!(status_intent(&older), StatusIntent::Caution);
        assert_eq!(palette.status(status_intent(&older)).fg, Some(AMBER_WARN));

        assert_eq!(status_intent(&unknown), StatusIntent::Caution);
        assert_eq!(palette.status(status_intent(&unknown)).fg, Some(AMBER_WARN));
    }

    #[test]
    fn truncate_text_and_rule_invariants() {
        assert_eq!(RULE.chars().count(), MAX_RULE_COLS);
        assert_eq!(RULE.len(), MAX_RULE_COLS * '─'.len_utf8());

        assert!(matches!(truncate_text("hello", 10), Cow::Borrowed("hello")));
        assert!(matches!(truncate_text("hello", 5), Cow::Borrowed("hello")));
        assert_eq!(truncate_text("hello world", 6), "hello…");
        assert_eq!(truncate_text("hello", 2), "h…");
        assert!(matches!(truncate_text("hello", 1), Cow::Borrowed("h")));
        assert!(matches!(truncate_text("hello", 0), Cow::Borrowed("")));
    }
}
