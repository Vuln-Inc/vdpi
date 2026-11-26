//! Interactive `ratatui` split-tunnel application picker with live fuzzy
//! search, routing mode selector, scrollable app list, and custom app modal.

use super::{
    canonical_exe_entry, discover_apps, filter_and_rank_apps, normalize_exe,
    popular_app_display_name, AppCategory, DiscoveredApp,
};
use anyhow::Result;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Padding};
use ratatui::{Frame, Terminal};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use vdpi_core::config::{SplitTunnelConfig, SplitTunnelMode};

const MAX_CARD_WIDTH: u16 = 76;
const MAX_CARD_HEIGHT: u16 = 28;
const MAX_CUSTOM_INPUT_CHARS: usize = 256;
const MAX_SEARCH_CHARS: usize = 128;
const RULE: &str = "────────────────────────────────────────────────────────────────────────────";

// Restrained cool slate / white / emerald / ice-blue / semantic amber & red palette
// matching `vdpi` Control Center (`core/src/launcher/tui.rs`).
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
    border_accent: Style,
    divider: Style,
    divider_accent: Style,
    brand: Style,
    title: Style,
    pill_selected: Style,
    pill_zero: Style,
    mode_active_bg: Style,
    mode_active_all: Style,
    mode_active_include: Style,
    mode_active_exclude: Style,
    mode_inactive: Style,
    mode_hint: Style,
    search_prompt_active: Style,
    search_cursor: Style,
    search_text: Style,
    search_slash: Style,
    search_placeholder: Style,
    search_count: Style,
    active_row: Style,
    active_marker: Style,
    check_on: Style,
    check_off: Style,
    name_active: Style,
    name_inactive: Style,
    exe_active: Style,
    exe_inactive: Style,
    badge_running: Style,
    badge_custom: Style,
    badge_installed: Style,
    scroll_thumb: Style,
    scroll_track: Style,
    modal_input_bg: Style,
    modal_error: Style,
    footer_key: Style,
    footer_text: Style,
}

impl Palette {
    const fn for_color(color: bool) -> Self {
        if color {
            Self {
                border: Style::new().fg(BORDER_SLATE),
                border_accent: Style::new().fg(ICE_BLUE),
                divider: Style::new().fg(DIVIDER_SLATE),
                divider_accent: Style::new().fg(ICE_BLUE),
                brand: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                title: Style::new().fg(TEXT_LIGHT),
                pill_selected: Style::new().fg(EMERALD_ACTIVE).add_modifier(Modifier::BOLD),
                pill_zero: Style::new().fg(ICE_BLUE),
                mode_active_bg: Style::new()
                    .fg(TEXT_WHITE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                mode_active_all: Style::new()
                    .fg(ICE_BLUE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                mode_active_include: Style::new()
                    .fg(EMERALD_ACTIVE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                mode_active_exclude: Style::new()
                    .fg(AMBER_WARN)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                mode_inactive: Style::new().fg(SLATE_DIM),
                mode_hint: Style::new().fg(STEEL_MUTED),
                search_prompt_active: Style::new().fg(ICE_BLUE).add_modifier(Modifier::BOLD),
                search_cursor: Style::new().fg(ICE_BLUE),
                search_text: Style::new().fg(TEXT_WHITE),
                search_slash: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                search_placeholder: Style::new().fg(SLATE_DIM),
                search_count: Style::new().fg(STEEL_MUTED),
                active_row: Style::new().bg(ACTIVE_BG),
                active_marker: Style::new()
                    .fg(ICE_BLUE)
                    .bg(ACTIVE_BG)
                    .add_modifier(Modifier::BOLD),
                check_on: Style::new().fg(EMERALD_ACTIVE).add_modifier(Modifier::BOLD),
                check_off: Style::new().fg(SLATE_DIM),
                name_active: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                name_inactive: Style::new().fg(TEXT_LIGHT),
                exe_active: Style::new().fg(STEEL_MUTED),
                exe_inactive: Style::new().fg(SLATE_DIM),
                badge_running: Style::new().fg(EMERALD_ACTIVE),
                badge_custom: Style::new().fg(AMBER_WARN),
                badge_installed: Style::new().fg(SLATE_DIM),
                scroll_thumb: Style::new().fg(STEEL_MUTED),
                scroll_track: Style::new().fg(DIVIDER_SLATE),
                modal_input_bg: Style::new().fg(TEXT_WHITE).bg(ACTIVE_BG),
                modal_error: Style::new().fg(RED_DANGER).add_modifier(Modifier::BOLD),
                footer_key: Style::new().fg(TEXT_WHITE).add_modifier(Modifier::BOLD),
                footer_text: Style::new().fg(SLATE_DIM),
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
                border_accent: bold,
                divider: dim,
                divider_accent: bold,
                brand: bold,
                title: plain,
                pill_selected: bold,
                pill_zero: dim,
                mode_active_bg: bold_rev,
                mode_active_all: bold_rev,
                mode_active_include: bold_rev,
                mode_active_exclude: bold_rev,
                mode_inactive: dim,
                mode_hint: dim,
                search_prompt_active: bold,
                search_cursor: bold,
                search_text: plain,
                search_slash: bold,
                search_placeholder: dim,
                search_count: dim,
                active_row: rev,
                active_marker: bold_rev,
                check_on: bold,
                check_off: dim,
                name_active: bold_rev,
                name_inactive: plain,
                exe_active: rev,
                exe_inactive: dim,
                badge_running: bold,
                badge_custom: bold,
                badge_installed: dim,
                scroll_thumb: bold,
                scroll_track: dim,
                modal_input_bg: bold,
                modal_error: bold,
                footer_key: bold,
                footer_text: dim,
            }
        }
    }

    const fn mode_dot_style(self, mode: SplitTunnelMode) -> Style {
        match mode {
            SplitTunnelMode::All => self.mode_active_all,
            SplitTunnelMode::Include => self.mode_active_include,
            SplitTunnelMode::Exclude => self.mode_active_exclude,
        }
    }
}

static PICKER_PANIC_HOOK_ONCE: Once = Once::new();
static PICKER_TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

fn install_picker_panic_hook() {
    PICKER_PANIC_HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            prev(info);
        }));
    });
}

/// RAII terminal guard that enables raw mode + alternate screen and restores
/// cursor, screen, and raw mode cleanly on drop, error, or panic unwind.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        install_picker_panic_hook();
        terminal::enable_raw_mode()?;
        PICKER_TUI_ACTIVE.store(true, Ordering::Release);
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, Hide) {
            if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(stdout, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
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
        if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen, Show);
            let _ = terminal::disable_raw_mode();
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AddModalState {
    input: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct PickerState {
    mode: SplitTunnelMode,
    all_apps: Vec<DiscoveredApp>,
    /// Map from `normalize_exe(exe)` to canonical display/config exe name.
    selected_entries: BTreeMap<String, String>,
    search_query: String,
    search_focused: bool,
    filtered_indices: Vec<usize>,
    cursor: usize,
    scroll_offset: usize,
    last_list_height: usize,
    add_modal: Option<AddModalState>,
}

impl PickerState {
    fn new(initial: SplitTunnelConfig, all_apps: Vec<DiscoveredApp>) -> Self {
        let mut selected_entries = BTreeMap::new();
        for raw in &initial.apps {
            let Some(canonical) = canonical_exe_entry(raw) else {
                continue;
            };
            let key = normalize_exe(&canonical);
            if key.is_empty() {
                continue;
            }
            let preferred = all_apps
                .iter()
                .find(|app| normalize_exe(&app.exe_name) == key)
                .map(|app| app.exe_name.clone())
                .unwrap_or(canonical);
            selected_entries.entry(key).or_insert(preferred);
        }

        let mut state = Self {
            mode: initial.mode,
            all_apps,
            selected_entries,
            search_query: String::new(),
            search_focused: false,
            filtered_indices: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            last_list_height: 10,
            add_modal: None,
        };
        state.refresh_filtered();
        state
    }

    fn selected_count(&self) -> usize {
        self.selected_entries.len()
    }

    fn is_selected(&self, app: &DiscoveredApp) -> bool {
        let key = normalize_exe(&app.exe_name);
        !key.is_empty() && self.selected_entries.contains_key(&key)
    }

    fn toggle_highlighted(&mut self) -> bool {
        let Some(&app_idx) = self.filtered_indices.get(self.cursor) else {
            return false;
        };
        let app = &self.all_apps[app_idx];
        let key = normalize_exe(&app.exe_name);
        if key.is_empty() {
            return false;
        }
        match self.selected_entries.entry(key) {
            Entry::Occupied(entry) => {
                entry.remove();
            }
            Entry::Vacant(entry) => {
                entry.insert(app.exe_name.clone());
            }
        }
        true
    }

    fn cycle_mode_forward(&mut self) {
        self.mode = match self.mode {
            SplitTunnelMode::All => SplitTunnelMode::Include,
            SplitTunnelMode::Include => SplitTunnelMode::Exclude,
            SplitTunnelMode::Exclude => SplitTunnelMode::All,
        };
    }

    fn cycle_mode_backward(&mut self) {
        self.mode = match self.mode {
            SplitTunnelMode::All => SplitTunnelMode::Exclude,
            SplitTunnelMode::Include => SplitTunnelMode::All,
            SplitTunnelMode::Exclude => SplitTunnelMode::Include,
        };
    }

    fn refresh_filtered(&mut self) {
        let base = self.all_apps.as_ptr() as usize;
        let stride = std::mem::size_of::<DiscoveredApp>();
        let ranked = filter_and_rank_apps(&self.all_apps, &self.search_query);
        self.filtered_indices = ranked
            .into_iter()
            .filter_map(|app| {
                let offset = (app as *const DiscoveredApp as usize)
                    .checked_sub(base)?
                    .checked_div(stride)?;
                (offset < self.all_apps.len()).then_some(offset)
            })
            .collect();
        self.sync_viewport(self.last_list_height);
    }

    fn sync_viewport(&mut self, visible_rows: usize) {
        let visible = visible_rows.max(1);
        self.last_list_height = visible;
        let total = self.filtered_indices.len();
        if total == 0 {
            self.cursor = 0;
            self.scroll_offset = 0;
            return;
        }
        if self.cursor >= total {
            self.cursor = total - 1;
        }
        if self.cursor < self.scroll_offset {
            self.scroll_offset = self.cursor;
        } else if self.cursor >= self.scroll_offset.saturating_add(visible) {
            self.scroll_offset = self.cursor + 1 - visible;
        }
        let max_offset = total.saturating_sub(visible);
        if self.scroll_offset > max_offset {
            self.scroll_offset = max_offset;
        }
    }

    fn move_cursor_up(&mut self, step: usize) {
        if self.filtered_indices.is_empty() {
            self.cursor = 0;
            self.scroll_offset = 0;
            return;
        }
        self.cursor = self.cursor.saturating_sub(step);
        self.sync_viewport(self.last_list_height);
    }

    fn move_cursor_down(&mut self, step: usize) {
        let len = self.filtered_indices.len();
        if len == 0 {
            self.cursor = 0;
            self.scroll_offset = 0;
            return;
        }
        self.cursor = self.cursor.saturating_add(step).min(len - 1);
        self.sync_viewport(self.last_list_height);
    }

    fn submit_custom_app(&mut self) {
        let Some(raw) = self.add_modal.as_ref().map(|m| m.input.clone()) else {
            return;
        };
        let Some(canonical) = canonical_exe_entry(&raw) else {
            if let Some(modal) = self.add_modal.as_mut() {
                modal.error = Some("Enter an executable name (e.g. discord.exe)".to_string());
            }
            return;
        };

        let key = normalize_exe(&canonical);
        if key.is_empty() {
            if let Some(modal) = self.add_modal.as_mut() {
                modal.error = Some("Enter a valid executable name".to_string());
            }
            return;
        }

        let target_idx = if let Some(existing_idx) = self
            .all_apps
            .iter()
            .position(|app| normalize_exe(&app.exe_name) == key)
        {
            let existing_exe = self.all_apps[existing_idx].exe_name.clone();
            self.selected_entries.insert(key, existing_exe);
            existing_idx
        } else {
            let display_name = popular_app_display_name(&canonical)
                .map(str::to_string)
                .unwrap_or_else(|| canonical.clone());
            self.all_apps.push(DiscoveredApp {
                display_name,
                exe_name: canonical.clone(),
                path: None,
                is_running: false,
                category: AppCategory::Custom,
            });
            self.selected_entries.insert(key, canonical);
            self.all_apps.len() - 1
        };

        self.add_modal = None;
        self.refresh_filtered();
        if let Some(pos) = self.filtered_indices.iter().position(|&i| i == target_idx) {
            self.cursor = pos;
            self.sync_viewport(self.last_list_height);
        } else if !self.search_query.is_empty() {
            // Clear an unrelated active search filter so the newly added app is visible.
            self.search_query.clear();
            self.refresh_filtered();
            if let Some(pos) = self.filtered_indices.iter().position(|&i| i == target_idx) {
                self.cursor = pos;
                self.sync_viewport(self.last_list_height);
            }
        }
    }

    fn build_config(&self) -> SplitTunnelConfig {
        SplitTunnelConfig {
            mode: self.mode,
            apps: self.selected_entries.values().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Redraw,
    Save,
    Cancel,
    Ignore,
}

/// Runs the interactive full-screen `ratatui` split-tunneling application picker.
///
/// Returns `Ok(Some(updated))` when the user confirms with `Enter`, or `Ok(None)`
/// when cancelled with `Esc`, `q`, or `Ctrl+C`.
pub fn run_split_tunnel_picker(initial: SplitTunnelConfig) -> Result<Option<SplitTunnelConfig>> {
    let color = std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
    let all_apps = discover_apps(&initial.apps);
    let mut state = PickerState::new(initial, all_apps);
    let mut guard = TerminalGuard::enter()?;

    loop {
        guard
            .terminal
            .draw(|frame| render(frame, &mut state, color))?;
        loop {
            match event::read()? {
                Event::Resize(..) => break,
                Event::Key(key) => match handle_key(&mut state, key) {
                    Action::Redraw => break,
                    Action::Save => return Ok(Some(state.build_config())),
                    Action::Cancel => return Ok(None),
                    Action::Ignore => {}
                },
                _ => {}
            }
        }
    }
}

fn handle_key(state: &mut PickerState, key: KeyEvent) -> Action {
    // Windows ConPTY emits Release events alongside Press; ignore all Releases.
    if key.kind == KeyEventKind::Release {
        return Action::Ignore;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        return if key.kind == KeyEventKind::Press {
            Action::Cancel
        } else {
            Action::Ignore
        };
    }

    if state.add_modal.is_some() {
        return handle_modal_key(state, key);
    }

    if state.search_focused {
        return handle_search_key(state, key);
    }

    handle_normal_key(state, key)
}

fn handle_modal_key(state: &mut PickerState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if let Some(modal) = state.add_modal.as_mut() {
            if !modal.input.is_empty() || modal.error.is_some() {
                modal.input.clear();
                modal.error = None;
                return Action::Redraw;
            }
        }
        return Action::Ignore;
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Ignore;
    }

    match key.code {
        KeyCode::Backspace => {
            if let Some(modal) = state.add_modal.as_mut() {
                if modal.input.pop().is_some() || modal.error.is_some() {
                    modal.error = None;
                    return Action::Redraw;
                }
            }
            Action::Ignore
        }
        _ if key.kind != KeyEventKind::Press => Action::Ignore,
        KeyCode::Esc => {
            state.add_modal = None;
            Action::Redraw
        }
        KeyCode::Enter => {
            state.submit_custom_app();
            Action::Redraw
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            if let Some(modal) = state.add_modal.as_mut() {
                if modal.input.chars().count() < MAX_CUSTOM_INPUT_CHARS {
                    modal.input.push(ch);
                    modal.error = None;
                    return Action::Redraw;
                }
            }
            Action::Ignore
        }
        _ => Action::Ignore,
    }
}

fn handle_search_key(state: &mut PickerState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if !state.search_query.is_empty() {
            state.search_query.clear();
            state.cursor = 0;
            state.scroll_offset = 0;
            state.refresh_filtered();
            return Action::Redraw;
        }
        return Action::Ignore;
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Ignore;
    }

    let page_step = state.last_list_height.saturating_sub(1).max(1);

    match key.code {
        // Navigation keys allow Repeat cleanly.
        KeyCode::Up => {
            state.move_cursor_up(1);
            Action::Redraw
        }
        KeyCode::Down => {
            state.move_cursor_down(1);
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.move_cursor_up(page_step);
            Action::Redraw
        }
        KeyCode::PageDown => {
            state.move_cursor_down(page_step);
            Action::Redraw
        }
        KeyCode::Backspace => {
            if state.search_query.pop().is_some() {
                state.cursor = 0;
                state.scroll_offset = 0;
                state.refresh_filtered();
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        // Non-navigation actions ignore Repeat (Windows ConPTY safety).
        _ if key.kind != KeyEventKind::Press => Action::Ignore,
        KeyCode::Tab => {
            if state.toggle_highlighted() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Enter | KeyCode::Esc => {
            state.search_focused = false;
            Action::Redraw
        }
        KeyCode::Char(ch) if !ch.is_control() => {
            if state.search_query.chars().count() < MAX_SEARCH_CHARS {
                state.search_query.push(ch);
                state.cursor = 0;
                state.scroll_offset = 0;
                state.refresh_filtered();
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        _ => Action::Ignore,
    }
}

fn handle_normal_key(state: &mut PickerState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if !state.search_query.is_empty() {
            state.search_query.clear();
            state.cursor = 0;
            state.scroll_offset = 0;
            state.refresh_filtered();
            return Action::Redraw;
        }
        return Action::Ignore;
    }

    if key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
    {
        return Action::Ignore;
    }

    let page_step = state.last_list_height.saturating_sub(1).max(1);

    match key.code {
        // Navigation keys allow Repeat smoothly.
        KeyCode::Up | KeyCode::Char('k') => {
            state.move_cursor_up(1);
            Action::Redraw
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.move_cursor_down(1);
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.move_cursor_up(page_step);
            Action::Redraw
        }
        KeyCode::PageDown => {
            state.move_cursor_down(page_step);
            Action::Redraw
        }
        KeyCode::Home => {
            state.cursor = 0;
            state.sync_viewport(state.last_list_height);
            Action::Redraw
        }
        KeyCode::End => {
            state.cursor = state.filtered_indices.len().saturating_sub(1);
            state.sync_viewport(state.last_list_height);
            Action::Redraw
        }
        // Strictly ignore Repeat on toggles, mode switches, modals, save/cancel.
        _ if key.kind != KeyEventKind::Press => Action::Ignore,
        KeyCode::Char(' ') => {
            if state.toggle_highlighted() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Tab => {
            state.cycle_mode_forward();
            Action::Redraw
        }
        KeyCode::BackTab => {
            state.cycle_mode_backward();
            Action::Redraw
        }
        KeyCode::Char('1') => {
            if state.mode != SplitTunnelMode::All {
                state.mode = SplitTunnelMode::All;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('2') => {
            if state.mode != SplitTunnelMode::Include {
                state.mode = SplitTunnelMode::Include;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('3') => {
            if state.mode != SplitTunnelMode::Exclude {
                state.mode = SplitTunnelMode::Exclude;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('/') => {
            state.search_focused = true;
            Action::Redraw
        }
        KeyCode::Char('a' | 'A') => {
            state.add_modal = Some(AddModalState::default());
            Action::Redraw
        }
        KeyCode::Char('x' | 'X') => {
            if !state.selected_entries.is_empty() {
                state.selected_entries.clear();
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Enter => Action::Save,
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => Action::Cancel,
        _ => Action::Ignore,
    }
}

fn sanitize_inline(text: &str) -> Cow<'_, str> {
    if !text.chars().any(char::is_control) {
        return Cow::Borrowed(text);
    }
    let cleaned: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    Cow::Owned(cleaned)
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

fn truncate_head(text: &str, max_chars: usize) -> Cow<'_, str> {
    if max_chars == 0 {
        return Cow::Borrowed("");
    }
    let total = text.chars().count();
    if total <= max_chars {
        return Cow::Borrowed(text);
    }
    if max_chars == 1 {
        let last = text.chars().next_back().unwrap_or('…');
        return Cow::Owned(last.to_string());
    }
    let skip = total - (max_chars - 1);
    let mut out = String::with_capacity(max_chars + '…'.len_utf8());
    out.push('…');
    for ch in text.chars().skip(skip) {
        out.push(ch);
    }
    Cow::Owned(out)
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

fn render(frame: &mut Frame<'_>, state: &mut PickerState, color: bool) {
    let area = frame.area();
    if area.is_empty() {
        return;
    }

    let palette = Palette::for_color(color);

    if area.width < 16 || area.height < 8 {
        render_minimal(frame, area, state, palette);
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

    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

    let show_top_div = inner.height >= 12;
    let show_mode_hint = inner.height >= 14;
    let show_mid_divs = inner.height >= 13;
    let show_footer = inner.height >= 7;
    let show_bot_div = inner.height >= 11;

    // 1. Header row
    if y < bottom {
        render_header(frame, row(y), state, palette);
        y = y.saturating_add(1);
    }

    if show_top_div && y < bottom {
        render_divider(frame, row(y), palette.divider);
        y = y.saturating_add(1);
    }

    // 2. Mode selector bar + optional contextual description
    if y < bottom {
        render_mode_bar(frame, row(y), state.mode, palette);
        y = y.saturating_add(1);
    }
    if show_mode_hint && y < bottom {
        render_mode_hint(frame, row(y), state, palette);
        y = y.saturating_add(1);
    }

    if show_mid_divs && y < bottom {
        let div_style = if state.search_focused {
            palette.divider_accent
        } else {
            palette.divider
        };
        render_divider(frame, row(y), div_style);
        y = y.saturating_add(1);
    }

    // 3. Live search bar
    if y < bottom {
        render_search_bar(frame, row(y), state, palette);
        y = y.saturating_add(1);
    }

    if show_mid_divs && y < bottom {
        let div_style = if state.search_focused {
            palette.divider_accent
        } else {
            palette.divider
        };
        render_divider(frame, row(y), div_style);
        y = y.saturating_add(1);
    }

    // 4. Footer reservation & scrollable app list
    let footer_reserve = u16::from(show_footer) + u16::from(show_bot_div);
    let list_bottom = bottom.saturating_sub(footer_reserve).max(y);
    let list_area = Rect::new(inner.x, y, inner.width, list_bottom.saturating_sub(y));
    render_app_list(frame, list_area, state, palette);

    // 5. Bottom divider + footer
    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_footer(frame, row(footer_y), state.search_focused, palette);
    }
    if show_bot_div && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_divider(frame, row(footer_y), palette.divider);
    }

    // 6. Add Custom App overlay modal
    if let Some(modal) = state.add_modal.as_ref() {
        render_add_modal(frame, card_area, modal, palette, color);
    }
}

fn render_minimal(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    let text = format!("vdpi Split ({} sel)", state.selected_count());
    let line = Line::from(Span::styled(
        truncate_text(&text, usize::from(area.width)),
        palette.brand,
    ));
    frame.render_widget(line, Rect::new(area.x, area.y, area.width, 1));
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

fn render_header(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let count = state.selected_count();
    let pill = format!("{count} selected");
    let pill_len = pill.chars().count();
    let pill_style = if count > 0 {
        palette.pill_selected
    } else {
        palette.pill_zero
    };

    const BRAND: &str = "vdpi";
    const SUBTITLE: &str = " Split Tunneling";
    let full_left_len = BRAND.len() + SUBTITLE.len();

    let line = if width >= full_left_len + 2 + pill_len {
        let gap = width - full_left_len - pill_len;
        Line::from(vec![
            Span::styled(BRAND, palette.brand),
            Span::styled(SUBTITLE, palette.title),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill, pill_style),
        ])
    } else if width >= pill_len + 6 {
        let left_budget = width - pill_len - 1;
        let left_text = truncate_text("vdpi Split Tunneling", left_budget);
        let left_len = left_text.chars().count();
        let gap = width.saturating_sub(left_len + pill_len);
        Line::from(vec![
            Span::styled(left_text, palette.brand),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill, pill_style),
        ])
    } else {
        Line::from(Span::styled(
            truncate_text("vdpi Split Tunneling", width),
            palette.brand,
        ))
    };

    frame.render_widget(line, area);
}

fn render_mode_bar(frame: &mut Frame<'_>, area: Rect, active: SplitTunnelMode, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);

    let (all_label, inc_label, exc_label, gap_str) = if width >= 66 {
        (
            "1 All apps",
            "2 Only selected (Include)",
            "3 Exclude selected",
            "  ",
        )
    } else if width >= 46 {
        ("1 All apps", "2 Only selected", "3 Exclude", "  ")
    } else {
        ("1 All", "2 Include", "3 Exclude", " ")
    };

    let modes = [
        (SplitTunnelMode::All, all_label),
        (SplitTunnelMode::Include, inc_label),
        (SplitTunnelMode::Exclude, exc_label),
    ];

    let mut spans: Vec<Span<'_>> = Vec::with_capacity(11);
    let mut used = 0usize;

    for (idx, (mode, label)) in modes.into_iter().enumerate() {
        if idx > 0 {
            let g_len = gap_str.len();
            if used + g_len > width {
                break;
            }
            spans.push(Span::raw(gap_str));
            used += g_len;
        }
        let is_active = mode == active;
        let prefix = if is_active { " ● " } else { " " };
        let suffix = " ";
        let pill_chars = prefix.chars().count() + label.chars().count() + suffix.len();
        let remaining = width.saturating_sub(used);
        if remaining == 0 {
            break;
        }

        if pill_chars <= remaining {
            if is_active {
                spans.push(Span::styled(prefix, palette.mode_dot_style(mode)));
                spans.push(Span::styled(label, palette.mode_active_bg));
                spans.push(Span::styled(suffix, palette.mode_active_bg));
            } else {
                spans.push(Span::styled(prefix, palette.mode_inactive));
                spans.push(Span::styled(label, palette.mode_inactive));
                spans.push(Span::styled(suffix, palette.mode_inactive));
            }
            used += pill_chars;
        } else {
            let full = format!("{prefix}{label}{suffix}");
            let clipped = truncate_text(&full, remaining).into_owned();
            let style = if is_active {
                palette.mode_active_bg
            } else {
                palette.mode_inactive
            };
            spans.push(Span::styled(clipped, style));
            break;
        }
    }

    frame.render_widget(Line::from(spans), area);
}

fn render_mode_hint(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let hint = match state.mode {
        SplitTunnelMode::All => "Every app is protected through DPI desync.",
        SplitTunnelMode::Include if state.selected_count() == 0 => {
            "DPI desync ONLY for checked apps (check at least one below)."
        }
        SplitTunnelMode::Include => "DPI desync applies ONLY to checked apps.",
        SplitTunnelMode::Exclude => "Checked apps bypass DPI desync; all others stay protected.",
    };
    let line = Line::from(Span::styled(
        truncate_text(hint, usize::from(area.width)),
        palette.mode_hint,
    ));
    frame.render_widget(line, area);
}

fn render_search_bar(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let filtered = state.filtered_indices.len();
    let total = state.all_apps.len();
    let count_badge = format!("{filtered} / {total} apps");
    let count_len = count_badge.chars().count();

    let line = if state.search_focused {
        let prompt = "Search: ";
        let cursor_glyph = "▏";
        let prompt_len = prompt.chars().count();
        let cursor_len = cursor_glyph.chars().count();

        let show_count = width >= prompt_len + cursor_len + count_len + 4;
        let query_budget = if show_count {
            width.saturating_sub(prompt_len + cursor_len + count_len + 2)
        } else {
            width.saturating_sub(prompt_len + cursor_len)
        };
        let sanitized = sanitize_inline(&state.search_query);
        let visible_query = truncate_head(&sanitized, query_budget).into_owned();
        let query_len = visible_query.chars().count();

        let mut spans = vec![
            Span::styled(prompt, palette.search_prompt_active),
            Span::styled(visible_query, palette.search_text),
            Span::styled(cursor_glyph, palette.search_cursor),
        ];
        if show_count {
            let left_used = prompt_len + query_len + cursor_len;
            let gap = width.saturating_sub(left_used + count_len);
            spans.push(Span::raw(" ".repeat(gap)));
            spans.push(Span::styled(count_badge, palette.search_count));
        }
        Line::from(spans)
    } else if state.search_query.is_empty() {
        let full_left = "/ search";
        let sep = " · ";
        let full_len = full_left.chars().count() + sep.chars().count() + count_len;
        if width >= full_len {
            Line::from(vec![
                Span::styled("/", palette.search_slash),
                Span::styled(" search", palette.search_placeholder),
                Span::styled(sep, palette.search_placeholder),
                Span::styled(count_badge, palette.search_count),
            ])
        } else {
            let compact = format!("/ search · {filtered}/{total}");
            Line::from(Span::styled(
                truncate_text(&compact, width).into_owned(),
                palette.search_placeholder,
            ))
        }
    } else {
        let sanitized = sanitize_inline(&state.search_query);
        let sep = " · ";
        let prefix_len = 2usize; // "/ "
        let suffix_len = sep.chars().count() + count_len;
        if width > prefix_len + suffix_len + 2 {
            let q_budget = width - prefix_len - suffix_len;
            let shown_q = truncate_text(&sanitized, q_budget).into_owned();
            Line::from(vec![
                Span::styled("/ ", palette.search_prompt_active),
                Span::styled(shown_q, palette.search_text),
                Span::styled(sep, palette.search_placeholder),
                Span::styled(count_badge, palette.search_count),
            ])
        } else {
            let compact = format!("/ {sanitized} · {filtered}/{total}");
            Line::from(Span::styled(
                truncate_text(&compact, width).into_owned(),
                palette.search_text,
            ))
        }
    };

    frame.render_widget(line, area);
}

fn render_app_list(frame: &mut Frame<'_>, area: Rect, state: &mut PickerState, palette: Palette) {
    if area.is_empty() {
        return;
    }

    let visible_rows = usize::from(area.height);
    state.sync_viewport(visible_rows);

    let total_filtered = state.filtered_indices.len();
    if total_filtered == 0 {
        let msg = if state.search_query.is_empty() {
            "No apps found. Press 'a' to add a custom executable.".to_string()
        } else {
            let sanitized_q = sanitize_inline(&state.search_query);
            let q = truncate_text(
                &sanitized_q,
                usize::from(area.width).saturating_sub(28).max(4),
            );
            format!("No matches for \"{q}\". Press 'a' to add custom.")
        };
        let line = Line::from(Span::styled(
            truncate_text(&msg, usize::from(area.width)).into_owned(),
            palette.search_placeholder,
        ));
        let msg_y = area
            .y
            .saturating_add(area.height / 2)
            .min(area.bottom() - 1);
        frame.render_widget(line, Rect::new(area.x, msg_y, area.width, 1));
        return;
    }

    let width = usize::from(area.width);
    let needs_scrollbar = total_filtered > visible_rows && width >= 20;
    let content_width = if needs_scrollbar {
        width.saturating_sub(2)
    } else {
        width
    };

    // Scrollbar thumb range in [0, visible_rows).
    let (thumb_start, thumb_end) = if needs_scrollbar {
        let thumb_len = ((visible_rows * visible_rows) / total_filtered)
            .max(1)
            .min(visible_rows);
        let max_scroll = total_filtered.saturating_sub(visible_rows).max(1);
        let max_thumb_pos = visible_rows.saturating_sub(thumb_len);
        let start = (state.scroll_offset * max_thumb_pos + max_scroll / 2) / max_scroll;
        (start, (start + thumb_len).min(visible_rows))
    } else {
        (0, 0)
    };

    for row_idx in 0..visible_rows {
        let list_idx = state.scroll_offset + row_idx;
        let row_rect = Rect::new(area.x, area.y + row_idx as u16, area.width, 1);
        let Some(&app_idx) = state.filtered_indices.get(list_idx) else {
            break;
        };
        let app = &state.all_apps[app_idx];
        let is_cursor = list_idx == state.cursor;
        let is_checked = state.is_selected(app);

        let row_bg = if is_cursor {
            palette.active_row
        } else {
            Style::new()
        };

        let marker = if is_cursor { "▸ " } else { "  " };
        let marker_style = if is_cursor {
            palette.active_marker
        } else {
            row_bg
        };

        let checkbox = if is_checked { "[x]" } else { "[ ]" };
        let check_style = if is_checked {
            palette.check_on.patch(row_bg)
        } else {
            palette.check_off.patch(row_bg)
        };

        let (badge_text, badge_base_style) = if content_width >= 34 {
            if app.is_running {
                ("● Running", palette.badge_running)
            } else if app.category == AppCategory::Custom {
                ("Custom", palette.badge_custom)
            } else {
                ("Installed", palette.badge_installed)
            }
        } else if content_width >= 26 {
            if app.is_running {
                ("● Run", palette.badge_running)
            } else if app.category == AppCategory::Custom {
                ("Custom", palette.badge_custom)
            } else {
                ("Inst", palette.badge_installed)
            }
        } else {
            ("", palette.badge_installed)
        };
        let badge_len = badge_text.chars().count();
        let badge_reserve = if badge_len > 0 { badge_len + 1 } else { 0 };

        // Fixed prefix: marker(2) + checkbox(3) + space(1) = 6 cols.
        let prefix_len = 6usize;
        let mid_budget = content_width.saturating_sub(prefix_len + badge_reserve);

        let clean_name = sanitize_inline(&app.display_name);
        let clean_exe = sanitize_inline(&app.exe_name);
        let show_exe = !clean_exe.eq_ignore_ascii_case(&clean_name) && mid_budget >= 18;

        let (shown_name, shown_exe) = if show_exe {
            let name_len = clean_name.chars().count();
            let exe_len = clean_exe.chars().count();
            if name_len + 2 + exe_len <= mid_budget {
                (clean_name.into_owned(), Some(clean_exe.into_owned()))
            } else {
                let name_cap = ((mid_budget * 3) / 5).max(10).min(mid_budget - 6);
                let trunc_name = truncate_text(&clean_name, name_cap).into_owned();
                let used_name = trunc_name.chars().count();
                let exe_cap = mid_budget.saturating_sub(used_name + 1);
                if exe_cap >= 4 {
                    (
                        trunc_name,
                        Some(truncate_text(&clean_exe, exe_cap).into_owned()),
                    )
                } else {
                    (truncate_text(&clean_name, mid_budget).into_owned(), None)
                }
            }
        } else {
            (truncate_text(&clean_name, mid_budget).into_owned(), None)
        };

        let name_style = if is_cursor {
            palette.name_active
        } else {
            palette.name_inactive
        };
        let exe_style = if is_cursor {
            palette.exe_active.patch(row_bg)
        } else {
            palette.exe_inactive
        };
        let badge_style = badge_base_style.patch(row_bg);

        let mut spans: Vec<Span<'_>> = Vec::with_capacity(9);
        spans.push(Span::styled(marker, marker_style));
        spans.push(Span::styled(checkbox, check_style));
        spans.push(Span::styled(" ", row_bg));

        let mut mid_used = shown_name.chars().count();
        spans.push(Span::styled(shown_name, name_style));

        if let Some(exe) = shown_exe {
            let exe_gap = if mid_used + 2 + exe.chars().count() <= mid_budget {
                "  "
            } else {
                " "
            };
            mid_used += exe_gap.len() + exe.chars().count();
            spans.push(Span::styled(exe_gap, row_bg));
            spans.push(Span::styled(exe, exe_style));
        }

        let filler = content_width.saturating_sub(prefix_len + mid_used + badge_len);
        if filler > 0 {
            spans.push(Span::styled(" ".repeat(filler), row_bg));
        }
        if badge_len > 0 {
            spans.push(Span::styled(badge_text, badge_style));
        }

        if needs_scrollbar {
            spans.push(Span::raw(" "));
            if row_idx >= thumb_start && row_idx < thumb_end {
                spans.push(Span::styled("┃", palette.scroll_thumb));
            } else {
                spans.push(Span::styled("│", palette.scroll_track));
            }
        }

        frame.render_widget(Line::from(spans), row_rect);
    }
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, search_focused: bool, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let key = palette.footer_key;
    let text = palette.footer_text;

    let line = if search_focused {
        if width >= 66 {
            Line::from(vec![
                Span::styled("type to filter · ", text),
                Span::styled("↑↓", key),
                Span::styled(" move · ", text),
                Span::styled("tab", key),
                Span::styled(" toggle · ", text),
                Span::styled("enter/esc", key),
                Span::styled(" done · ", text),
                Span::styled("^u", key),
                Span::styled(" clear", text),
            ])
        } else if width >= 50 {
            Line::from(vec![
                Span::styled("↑↓", key),
                Span::styled(" move · ", text),
                Span::styled("tab", key),
                Span::styled(" toggle · ", text),
                Span::styled("enter/esc", key),
                Span::styled(" done · ", text),
                Span::styled("^u", key),
                Span::styled(" clear", text),
            ])
        } else if width >= 36 {
            Line::from(vec![
                Span::styled("↑↓", key),
                Span::styled(" · ", text),
                Span::styled("tab", key),
                Span::styled(" toggle · ", text),
                Span::styled("esc", key),
                Span::styled(" done · ", text),
                Span::styled("^u", key),
                Span::styled(" clear", text),
            ])
        } else {
            Line::from(vec![
                Span::styled("tab", key),
                Span::styled(" toggle · ", text),
                Span::styled("esc", key),
                Span::styled(" done", text),
            ])
        }
    } else if width >= 70 {
        Line::from(vec![
            Span::styled("space", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" search · ", text),
            Span::styled("tab", key),
            Span::styled(" mode · ", text),
            Span::styled("a", key),
            Span::styled(" add · ", text),
            Span::styled("x", key),
            Span::styled(" clear · ", text),
            Span::styled("enter", key),
            Span::styled(" save · ", text),
            Span::styled("esc", key),
        ])
    } else if width >= 54 {
        Line::from(vec![
            Span::styled("space", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" find · ", text),
            Span::styled("tab", key),
            Span::styled(" mode · ", text),
            Span::styled("a", key),
            Span::styled(" add · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    } else if width >= 38 {
        Line::from(vec![
            Span::styled("spc", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" · ", text),
            Span::styled("tab", key),
            Span::styled(" · ", text),
            Span::styled("a", key),
            Span::styled(" · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    } else {
        Line::from(vec![
            Span::styled("spc", key),
            Span::styled(" · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    };

    frame.render_widget(line, area);
}

fn render_add_modal(
    frame: &mut Frame<'_>,
    parent: Rect,
    modal: &AddModalState,
    palette: Palette,
    color: bool,
) {
    let modal_w = parent
        .width
        .saturating_sub(4)
        .clamp(24, 54)
        .min(parent.width);
    let modal_h = if modal.error.is_some() { 9 } else { 8 }.min(parent.height);
    if modal_w < 14 || modal_h < 5 {
        return;
    }

    let modal_area = centered_rect(parent, modal_w, modal_h);
    frame.render_widget(Clear, modal_area);

    let block = Block::bordered()
        .border_type(if color {
            BorderType::Rounded
        } else {
            BorderType::Plain
        })
        .border_style(palette.border_accent)
        .title(Span::styled(" Add custom app ", palette.brand))
        .padding(if modal_w >= 24 {
            Padding::horizontal(1)
        } else {
            Padding::ZERO
        });
    let inner = block.inner(modal_area);
    frame.render_widget(block, modal_area);

    if inner.is_empty() {
        return;
    }

    let width = usize::from(inner.width);
    let mut y = inner.y;
    let bottom = inner.y.saturating_add(inner.height);
    let row = |row_y: u16| Rect::new(inner.x, row_y, inner.width, 1);

    // Hint line
    if y < bottom {
        let prompt = "e.g. discord.exe or firefox";
        frame.render_widget(
            Line::from(Span::styled(
                truncate_text(prompt, width),
                palette.mode_hint,
            )),
            row(y),
        );
        y = y.saturating_add(1);
    }

    // Breathing gap when space allows
    let reserve_after_input = 1u16 + u16::from(modal.error.is_some()) + 1;
    if y + reserve_after_input < bottom {
        y = y.saturating_add(1);
    }

    // Input box row
    if y < bottom {
        let prefix = " > ";
        let cursor_glyph = "▏";
        let prefix_len = prefix.chars().count();
        let cursor_len = cursor_glyph.chars().count();
        let input_budget = width.saturating_sub(prefix_len + cursor_len + 1);
        let sanitized = sanitize_inline(&modal.input);
        let visible_input = truncate_head(&sanitized, input_budget).into_owned();
        let used = prefix_len + visible_input.chars().count() + cursor_len;
        let pad = width.saturating_sub(used);

        let bg = palette.modal_input_bg;
        let line = Line::from(vec![
            Span::styled(prefix, palette.search_prompt_active.patch(bg)),
            Span::styled(visible_input, bg),
            Span::styled(cursor_glyph, palette.search_cursor.patch(bg)),
            Span::styled(" ".repeat(pad), bg),
        ]);
        frame.render_widget(line, row(y));
        y = y.saturating_add(1);
    }

    // Inline error line
    if let Some(err) = modal.error.as_deref() {
        if y + 1 < bottom {
            let err_prefix = if color { "● " } else { "! " };
            let msg = truncate_text(err, width.saturating_sub(err_prefix.chars().count()));
            let line = Line::from(vec![
                Span::styled(err_prefix, palette.modal_error),
                Span::styled(msg, palette.modal_error),
            ]);
            frame.render_widget(line, row(y));
        }
    }

    // Footer at bottom of modal
    if bottom > inner.y {
        let footer_y = bottom - 1;
        let line = if width >= 28 {
            Line::from(vec![
                Span::styled("enter", palette.footer_key),
                Span::styled(" add · ", palette.footer_text),
                Span::styled("^u", palette.footer_key),
                Span::styled(" clear · ", palette.footer_text),
                Span::styled("esc", palette.footer_key),
                Span::styled(" cancel", palette.footer_text),
            ])
        } else {
            Line::from(vec![
                Span::styled("enter", palette.footer_key),
                Span::styled(" add · ", palette.footer_text),
                Span::styled("esc", palette.footer_key),
                Span::styled(" cancel", palette.footer_text),
            ])
        };
        frame.render_widget(line, row(footer_y));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn sample_apps() -> Vec<DiscoveredApp> {
        vec![
            DiscoveredApp {
                display_name: "Discord".to_string(),
                exe_name: "Discord.exe".to_string(),
                path: Some(r"C:\Users\demo\AppData\Local\Discord\Discord.exe".to_string()),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Google Chrome".to_string(),
                exe_name: "chrome.exe".to_string(),
                path: Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string()),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Mozilla Firefox".to_string(),
                exe_name: "firefox.exe".to_string(),
                path: Some(r"C:\Program Files\Mozilla Firefox\firefox.exe".to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "Steam".to_string(),
                exe_name: "steam.exe".to_string(),
                path: Some(r"C:\Program Files (x86)\Steam\steam.exe".to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "Roblox".to_string(),
                exe_name: "RobloxPlayerBeta.exe".to_string(),
                path: None,
                is_running: false,
                category: AppCategory::Installed,
            },
            DiscoveredApp {
                display_name: "my-custom-tool.exe".to_string(),
                exe_name: "my-custom-tool.exe".to_string(),
                path: None,
                is_running: false,
                category: AppCategory::Custom,
            },
        ]
    }

    fn many_apps(count: usize) -> Vec<DiscoveredApp> {
        let mut apps = sample_apps();
        for idx in 0..count {
            apps.push(DiscoveredApp {
                display_name: format!("Extra Utility App {idx:02}"),
                exe_name: format!("extra_util_{idx:02}.exe"),
                path: None,
                is_running: false,
                category: AppCategory::Installed,
            });
        }
        apps
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn press_ctrl(ch: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
    }

    fn key_with_kind(code: KeyCode, kind: KeyEventKind) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, kind)
    }

    fn render_to_buffer(state: &mut PickerState, width: u16, height: u16, color: bool) -> Buffer {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal
            .draw(|frame| render(frame, state, color))
            .expect("draw frame");
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
            "expected outer borders {tl}{tr}{bl}{br} (color={color}):\n{text}"
        );
    }

    #[test]
    fn renders_cleanly_across_target_sizes_and_modes() {
        let initial = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["Discord.exe".to_string(), "my-custom-tool.exe".to_string()],
        };

        for &(w, h) in &[(100, 30), (80, 24), (60, 22), (46, 18)] {
            for &color in &[true, false] {
                // 1. Main view
                let mut state = PickerState::new(initial.clone(), many_apps(25));
                let buf = render_to_buffer(&mut state, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("vdpi"),
                    "missing header brand at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("2 selected"),
                    "missing selection pill at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("Discord"),
                    "missing Discord row at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("[x]") && text.contains("[ ]"),
                    "missing checked/unchecked boxes at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("● Running"),
                    "missing Running badge at {w}x{h}:\n{text}"
                );
                if w >= 80 {
                    assert!(
                        text.contains("1 All apps")
                            && text.contains("2 Only selected (Include)")
                            && text.contains("3 Exclude selected"),
                        "missing full mode labels at {w}x{h}:\n{text}"
                    );
                    assert!(
                        text.contains("Installed"),
                        "missing Installed badge at {w}x{h}:\n{text}"
                    );
                }
                // Verify Custom badge renders cleanly when visible in the list.
                let mut custom_state = PickerState::new(initial.clone(), sample_apps());
                let custom_buf = render_to_buffer(&mut custom_state, w, h, color);
                assert_outer_card_borders(&custom_buf, color);
                let custom_text = buffer_text(&custom_buf);
                assert!(
                    custom_text.contains("Custom"),
                    "missing Custom badge at {w}x{h}:\n{custom_text}"
                );
                if !color {
                    assert_no_rgb_colors(&custom_buf);
                }
                if !color {
                    assert_no_rgb_colors(&buf);
                    let mut saw_bold = false;
                    let mut saw_dim = false;
                    let mut saw_reversed = false;
                    for y in 0..h {
                        for x in 0..w {
                            let mods = buf[(x, y)].modifier;
                            saw_bold |= mods.contains(Modifier::BOLD);
                            saw_dim |= mods.contains(Modifier::DIM);
                            saw_reversed |= mods.contains(Modifier::REVERSED);
                        }
                    }
                    assert!(saw_bold, "NO_COLOR main view at {w}x{h} needs BOLD");
                    assert!(saw_dim, "NO_COLOR main view at {w}x{h} needs DIM");
                    assert!(saw_reversed, "NO_COLOR main view at {w}x{h} needs REVERSED");
                }

                // 2. Active search mode
                let mut search_state = PickerState::new(initial.clone(), many_apps(25));
                assert_eq!(
                    handle_key(&mut search_state, press(KeyCode::Char('/'))),
                    Action::Redraw
                );
                for ch in "chr".chars() {
                    assert_eq!(
                        handle_key(&mut search_state, press(KeyCode::Char(ch))),
                        Action::Redraw
                    );
                }
                let buf = render_to_buffer(&mut search_state, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("Search: chr▏"),
                    "missing live search bar at {w}x{h}:\n{text}"
                );
                assert!(
                    text.contains("Google Chrome"),
                    "missing filtered match at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }

                // 3. Add Custom App modal (including validation error state)
                let mut modal_state = PickerState::new(initial.clone(), sample_apps());
                assert_eq!(
                    handle_key(&mut modal_state, press(KeyCode::Char('a'))),
                    Action::Redraw
                );
                assert_eq!(
                    handle_key(&mut modal_state, press(KeyCode::Enter)),
                    Action::Redraw
                );
                let buf = render_to_buffer(&mut modal_state, w, h, color);
                assert_outer_card_borders(&buf, color);
                let text = buffer_text(&buf);
                assert!(
                    text.contains("Add custom app"),
                    "missing modal title at {w}x{h}:\n{text}"
                );
                if !color {
                    assert_no_rgb_colors(&buf);
                }
            }
        }
    }

    #[test]
    fn renders_degenerate_tiny_sizes_without_panicking() {
        let initial = SplitTunnelConfig::default();
        for &(w, h) in &[(0, 0), (1, 1), (10, 4), (16, 8), (24, 10), (35, 12)] {
            let mut state = PickerState::new(initial.clone(), sample_apps());
            let _ = render_to_buffer(&mut state, w, h, true);
            state.add_modal = Some(AddModalState {
                input: "very_long_executable_name_that_exceeds_small_widths.exe".to_string(),
                error: Some("Invalid entry".to_string()),
            });
            let _ = render_to_buffer(&mut state, w, h, false);
        }
    }

    #[test]
    fn live_search_filtering_navigation_and_tab_toggle() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        assert_eq!(state.filtered_indices.len(), 6);

        // Focus search via '/'
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('/'))),
            Action::Redraw
        );
        assert!(state.search_focused);

        // Typing with a space ("google chrome") works in search mode without toggling.
        for ch in "google chrome".chars() {
            assert_eq!(
                handle_key(&mut state, press(KeyCode::Char(ch))),
                Action::Redraw
            );
        }
        assert_eq!(state.search_query, "google chrome");
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(
            state.all_apps[state.filtered_indices[0]].exe_name,
            "chrome.exe"
        );

        // Tab toggles highlighted match while searching.
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.selected_count(), 1);
        assert!(state.selected_entries.contains_key("chrome"));

        // Ctrl+U clears query while staying focused.
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Redraw);
        assert!(state.search_query.is_empty());
        assert!(state.search_focused);
        assert_eq!(state.filtered_indices.len(), 6);

        // Type "fire" then Backspace -> "fir", Up/Down navigate results, Enter exits focus keeping filter.
        for ch in "fire".chars() {
            handle_key(&mut state, press(KeyCode::Char(ch)));
        }
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fir");
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(
            state.all_apps[state.filtered_indices[0]].exe_name,
            "firefox.exe"
        );

        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(!state.search_focused);
        assert_eq!(state.search_query, "fir");
        assert_eq!(state.filtered_indices.len(), 1);

        // Focus search again and press Esc: exits focus while keeping filter.
        handle_key(&mut state, press(KeyCode::Char('/')));
        assert!(state.search_focused);
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(!state.search_focused);
        assert_eq!(state.search_query, "fir");
    }

    #[test]
    fn checkbox_toggle_clear_mode_cycling_save_and_cancel() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        assert_eq!(state.mode, SplitTunnelMode::All);
        assert_eq!(state.selected_count(), 0);

        // Space toggles Discord (cursor 0), j moves to Chrome, Space toggles Chrome.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(state.selected_count(), 1);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('j'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(state.selected_count(), 2);

        // Tab cycles All -> Include -> Exclude -> All; BackTab reverses.
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.mode, SplitTunnelMode::Include);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.mode, SplitTunnelMode::Exclude);
        assert_eq!(handle_key(&mut state, press(KeyCode::Tab)), Action::Redraw);
        assert_eq!(state.mode, SplitTunnelMode::All);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::BackTab)),
            Action::Redraw
        );
        assert_eq!(state.mode, SplitTunnelMode::Exclude);

        // Direct number hotkeys 1/2/3.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('1'))),
            Action::Redraw
        );
        assert_eq!(state.mode, SplitTunnelMode::All);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('2'))),
            Action::Redraw
        );
        assert_eq!(state.mode, SplitTunnelMode::Include);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('3'))),
            Action::Redraw
        );
        assert_eq!(state.mode, SplitTunnelMode::Exclude);

        // Enter saves with deduped selected config.
        assert_eq!(handle_key(&mut state, press(KeyCode::Enter)), Action::Save);
        let saved = state.build_config();
        assert_eq!(saved.mode, SplitTunnelMode::Exclude);
        assert_eq!(
            saved.apps,
            vec!["chrome.exe".to_string(), "Discord.exe".to_string()]
        );

        // 'x' clears all selected apps.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('x'))),
            Action::Redraw
        );
        assert_eq!(state.selected_count(), 0);

        // Esc, q, and Ctrl+C cancel cleanly.
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Cancel);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('q'))),
            Action::Cancel
        );
        assert_eq!(handle_key(&mut state, press_ctrl('c')), Action::Cancel);
    }

    #[test]
    fn custom_app_modal_adds_dedupes_validates_and_cancels() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        let initial_len = state.all_apps.len();

        // Open modal via 'a', cancel via Esc.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('a'))),
            Action::Redraw
        );
        assert!(state.add_modal.is_some());
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(state.add_modal.is_none());

        // Open modal, submit empty -> validation error, stays open.
        handle_key(&mut state, press(KeyCode::Char('a')));
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state
            .add_modal
            .as_ref()
            .and_then(|m| m.error.as_ref())
            .is_some());

        // Type a Windows path to a new executable and submit -> extracts filename, adds Custom, checks [x].
        for ch in r#""C:\Games\Valorant\VALORANT-Win64-Shipping.exe""#.chars() {
            handle_key(&mut state, press(KeyCode::Char(ch)));
        }
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Enter)),
            Action::Redraw
        );
        assert!(state.add_modal.is_none());
        assert_eq!(state.all_apps.len(), initial_len + 1);
        assert!(state
            .selected_entries
            .contains_key("valorant-win64-shipping"));

        // Adding an already-existing app ("discord.exe") dedupes instead of duplicating, and checks [x].
        let len_before = state.all_apps.len();
        handle_key(&mut state, press(KeyCode::Char('a')));
        for ch in "discord.exe".chars() {
            handle_key(&mut state, press(KeyCode::Char(ch)));
        }
        handle_key(&mut state, press(KeyCode::Enter));
        assert!(state.add_modal.is_none());
        assert_eq!(state.all_apps.len(), len_before);
        assert!(state.selected_entries.contains_key("discord"));
    }

    #[test]
    fn windows_conpty_release_and_non_nav_repeat_are_ignored() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());

        // Release on Space/Tab/Enter must be ignored.
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Char(' '), KeyEventKind::Release)
            ),
            Action::Ignore
        );
        assert_eq!(state.selected_count(), 0);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Tab, KeyEventKind::Release)
            ),
            Action::Ignore
        );
        assert_eq!(state.mode, SplitTunnelMode::All);

        // Repeat on Space/Tab/Enter/x/a must be ignored so checkboxes never double-toggle.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(state.selected_count(), 1);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Char(' '), KeyEventKind::Repeat)
            ),
            Action::Ignore
        );
        assert_eq!(state.selected_count(), 1);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Tab, KeyEventKind::Repeat)
            ),
            Action::Ignore
        );
        assert_eq!(state.mode, SplitTunnelMode::All);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Enter, KeyEventKind::Repeat)
            ),
            Action::Ignore
        );
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Char('x'), KeyEventKind::Repeat)
            ),
            Action::Ignore
        );
        assert_eq!(state.selected_count(), 1);

        // Repeat on Down/Up navigation MUST still work smoothly.
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Down, KeyEventKind::Repeat)
            ),
            Action::Redraw
        );
        assert_eq!(state.cursor, 1);
    }

    #[test]
    fn scroll_offset_clamps_cleanly_on_paging_resize_and_filter_change() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), many_apps(40));
        let _ = render_to_buffer(&mut state, 80, 24, true);
        let visible = state.last_list_height;
        assert!(visible >= 8);

        // Jump to bottom via End, verify cursor is inside viewport.
        handle_key(&mut state, press(KeyCode::End));
        assert_eq!(state.cursor, state.filtered_indices.len() - 1);
        assert!(state.cursor >= state.scroll_offset);
        assert!(state.cursor < state.scroll_offset + state.last_list_height);

        // Shrink terminal to 46x18 -> scroll_offset adjusts without panic and keeps cursor visible.
        let _ = render_to_buffer(&mut state, 46, 18, true);
        assert!(state.cursor >= state.scroll_offset);
        assert!(state.cursor < state.scroll_offset + state.last_list_height);

        // PageUp moves up cleanly.
        let before = state.cursor;
        handle_key(&mut state, press(KeyCode::PageUp));
        assert!(state.cursor < before);

        // Filter down to 1 item -> scroll_offset resets cleanly to 0.
        handle_key(&mut state, press(KeyCode::Char('/')));
        for ch in "discord".chars() {
            handle_key(&mut state, press(KeyCode::Char(ch)));
        }
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(state.cursor, 0);
        assert_eq!(state.scroll_offset, 0);
        let _ = render_to_buffer(&mut state, 46, 18, true);
    }
}
