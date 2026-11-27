//! Interactive `ratatui` split-tunnel application picker with live fuzzy
//! search, routing mode selector, scrollable app list, and custom app modal.

use super::{
    canonical_exe_entry, discover_apps, filter_and_rank_apps, normalize_exe,
    popular_app_display_name, AppCategory, DiscoveredApp,
};
use crate::config_file::MAX_SPLIT_TUNNEL_APPS;
use crate::i18n::{self, tr, Lang};
use anyhow::Result;
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
use ratatui::widgets::{Block, BorderType, Clear, Padding};
use ratatui::{Frame, Terminal};
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use vdpi_core::config::{SplitTunnelConfig, SplitTunnelMode};

const MAX_CARD_WIDTH: u16 = 76;
const MAX_CARD_HEIGHT: u16 = 28;
const MAX_CUSTOM_INPUT_CHARS: usize = 1024;
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
    notice_warn: Style,
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
                notice_warn: Style::new().fg(AMBER_WARN).add_modifier(Modifier::BOLD),
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
                modal_input_bg: rev,
                modal_error: bold,
                notice_warn: bold,
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
                let _ = execute!(io::stdout(), DisableBracketedPaste, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            prev(info);
        }));
    });
}

/// RAII terminal guard that enables raw mode + alternate screen + bracketed paste
/// and restores cursor, paste mode, screen, and raw mode cleanly on drop, error,
/// or panic unwind.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        install_picker_panic_hook();
        terminal::enable_raw_mode()?;
        PICKER_TUI_ACTIVE.store(true, Ordering::Release);
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen, EnableBracketedPaste, Hide) {
            if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
                let _ = execute!(stdout, DisableBracketedPaste, LeaveAlternateScreen, Show);
                let _ = terminal::disable_raw_mode();
            }
            return Err(err);
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = match Terminal::new(backend) {
            Ok(terminal) => terminal,
            Err(err) => {
                if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
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
        if PICKER_TUI_ACTIVE.swap(false, Ordering::AcqRel) {
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AddModalState {
    input: String,
    /// Cursor position as a Unicode scalar (`char`) index in `0..=input.chars().count()`.
    cursor: usize,
    error: Option<String>,
}

impl AddModalState {
    fn char_count(&self) -> usize {
        self.input.chars().count()
    }

    fn clamped_cursor(&self) -> usize {
        self.cursor.min(self.char_count())
    }

    fn byte_index_at_char(&self, char_idx: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_idx)
            .map_or(self.input.len(), |(byte_idx, _)| byte_idx)
    }

    fn insert_char(&mut self, ch: char) -> bool {
        let len = self.char_count();
        if len >= MAX_CUSTOM_INPUT_CHARS {
            return false;
        }
        let cursor = self.cursor.min(len);
        let byte_idx = self.byte_index_at_char(cursor);
        self.input.insert(byte_idx, ch);
        self.cursor = cursor + 1;
        self.error = None;
        true
    }

    fn insert_str_capped(&mut self, text: &str) -> bool {
        let mut len = self.char_count();
        let mut cursor = self.cursor.min(len);
        let mut byte_idx = self.byte_index_at_char(cursor);
        let mut changed = false;
        for ch in text.chars() {
            if ch.is_control() {
                continue;
            }
            if len >= MAX_CUSTOM_INPUT_CHARS {
                break;
            }
            self.input.insert(byte_idx, ch);
            byte_idx += ch.len_utf8();
            cursor += 1;
            len += 1;
            changed = true;
        }
        if changed {
            self.cursor = cursor;
            self.error = None;
        }
        changed
    }

    fn backspace(&mut self) -> bool {
        let cursor = self.clamped_cursor();
        if cursor > 0 {
            let start = self.byte_index_at_char(cursor - 1);
            let end = self.byte_index_at_char(cursor);
            self.input.drain(start..end);
            self.cursor = cursor - 1;
            self.error = None;
            true
        } else if self.error.is_some() {
            self.error = None;
            true
        } else {
            false
        }
    }

    fn delete(&mut self) -> bool {
        let len = self.char_count();
        let cursor = self.cursor.min(len);
        if cursor < len {
            let start = self.byte_index_at_char(cursor);
            let end = self.byte_index_at_char(cursor + 1);
            self.input.drain(start..end);
            self.cursor = cursor;
            self.error = None;
            true
        } else if self.error.is_some() {
            self.error = None;
            true
        } else {
            false
        }
    }

    fn move_left(&mut self) -> bool {
        let cursor = self.clamped_cursor();
        if cursor > 0 {
            self.cursor = cursor - 1;
            true
        } else {
            false
        }
    }

    fn move_right(&mut self) -> bool {
        let len = self.char_count();
        let cursor = self.cursor.min(len);
        if cursor < len {
            self.cursor = cursor + 1;
            true
        } else {
            false
        }
    }

    fn move_home(&mut self) -> bool {
        let cursor = self.clamped_cursor();
        if cursor != 0 {
            self.cursor = 0;
            true
        } else {
            false
        }
    }

    fn move_end(&mut self) -> bool {
        let len = self.char_count();
        if self.cursor != len {
            self.cursor = len;
            true
        } else {
            false
        }
    }

    fn clear(&mut self) -> bool {
        if !self.input.is_empty() || self.cursor != 0 || self.error.is_some() {
            self.input.clear();
            self.cursor = 0;
            self.error = None;
            true
        } else {
            false
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoticeKind {
    EmptyIncludeConfirm,
    AllModeConfirm,
    DiscardConfirm,
}

impl NoticeKind {
    fn default_text(self) -> &'static str {
        match self {
            Self::EmptyIncludeConfirm => tr(
                "Empty Include protects no apps - press s/Enter again to save",
                "Boş Dahil Et hiçbir uygulamayı korumaz - kaydetmek için tekrar s/Enter",
            ),
            Self::AllModeConfirm => tr(
                "All mode ignores checked apps (2/3) - press s/Enter again to save",
                "Tümü modu seçili uygulamaları yok sayar (2/3) - tekrar s/Enter ile kaydet",
            ),
            Self::DiscardConfirm => tr(
                "Unsaved changes - Esc again to discard, or s/Enter to save",
                "Kaydedilmemiş değişiklikler - vazgeçmek için tekrar Esc, kaydetmek için s/Enter",
            ),
        }
    }

    fn text_for_budget(self, budget: usize) -> &'static str {
        let variants: [&'static str; 3] = match self {
            Self::EmptyIncludeConfirm => [
                Self::EmptyIncludeConfirm.default_text(),
                tr(
                    "Empty Include protects none - s/Enter again to save",
                    "Boş Dahil Et korumaz - tekrar s/Enter ile kaydet",
                ),
                tr(
                    "Empty Include (none) - s/Enter to save",
                    "Boş Dahil Et - kaydetmek için s/Enter",
                ),
            ],
            Self::AllModeConfirm => [
                Self::AllModeConfirm.default_text(),
                tr(
                    "All mode ignores checked - s/Enter again to save",
                    "Tümü seçilileri yok sayar - tekrar s/Enter ile kaydet",
                ),
                tr(
                    "All ignores checked - s/Enter to save",
                    "Tümü yok sayar - s/Enter ile kaydet",
                ),
            ],
            Self::DiscardConfirm => [
                Self::DiscardConfirm.default_text(),
                tr(
                    "Unsaved - Esc again to discard, s/Enter to save",
                    "Kaydedilmedi - Esc ile vazgeç, s/Enter ile kaydet",
                ),
                tr(
                    "Unsaved: Esc discard, s/Enter to save",
                    "Kaydedilmedi: Esc vazgeç, s/Enter kaydet",
                ),
            ],
        };
        variants
            .into_iter()
            .find(|text| display_width(text) <= budget)
            .unwrap_or(variants[2])
    }
}

#[derive(Debug, Clone)]
struct PickerState {
    initial_mode: SplitTunnelMode,
    initial_selected_keys: BTreeSet<String>,
    mode: SplitTunnelMode,
    all_apps: Vec<DiscoveredApp>,
    /// Map from `normalize_exe(exe)` to canonical display/config exe name.
    selected_entries: BTreeMap<String, String>,
    search_query: String,
    /// Cursor position in `search_query` as a Unicode scalar (`char`) index in
    /// `0..=search_query.chars().count()`.
    search_cursor: usize,
    search_focused: bool,
    only_selected: bool,
    filtered_indices: Vec<usize>,
    cursor: usize,
    scroll_offset: usize,
    last_list_height: usize,
    add_modal: Option<AddModalState>,
    notice: Option<String>,
    notice_kind: Option<NoticeKind>,
    pending_discard_confirm: bool,
    pending_save_confirm: bool,
}

impl PickerState {
    fn new(initial: SplitTunnelConfig, all_apps: Vec<DiscoveredApp>) -> Self {
        let mut selected_entries = BTreeMap::new();
        for raw in &initial.apps {
            if selected_entries.len() >= MAX_SPLIT_TUNNEL_APPS {
                break;
            }
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
        let initial_selected_keys: BTreeSet<String> = selected_entries.keys().cloned().collect();

        let mut state = Self {
            initial_mode: initial.mode,
            initial_selected_keys,
            mode: initial.mode,
            all_apps,
            selected_entries,
            search_query: String::new(),
            search_cursor: 0,
            search_focused: false,
            only_selected: false,
            filtered_indices: Vec::new(),
            cursor: 0,
            scroll_offset: 0,
            last_list_height: 10,
            add_modal: None,
            notice: None,
            notice_kind: None,
            pending_discard_confirm: false,
            pending_save_confirm: false,
        };
        state.refresh_filtered();
        state
    }

    fn is_dirty(&self) -> bool {
        self.mode != self.initial_mode
            || self.selected_entries.len() != self.initial_selected_keys.len()
            || self
                .selected_entries
                .keys()
                .any(|key| !self.initial_selected_keys.contains(key))
    }

    fn clear_confirmations(&mut self) {
        self.pending_discard_confirm = false;
        self.pending_save_confirm = false;
        self.notice_kind = None;
        self.notice = None;
    }

    fn set_confirm_notice(&mut self, kind: NoticeKind) {
        self.notice_kind = Some(kind);
        self.notice = Some(kind.default_text().to_string());
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
        let exe_name = self.all_apps[app_idx].exe_name.clone();
        let key = normalize_exe(&exe_name);
        if key.is_empty() {
            return false;
        }
        self.clear_confirmations();
        let can_insert = self.selected_entries.len() < MAX_SPLIT_TUNNEL_APPS;
        match self.selected_entries.entry(key) {
            Entry::Occupied(entry) => {
                entry.remove();
            }
            Entry::Vacant(entry) => {
                if !can_insert {
                    self.notice_kind = None;
                    self.notice = Some(match i18n::active_lang() {
                        Lang::En => format!(
                            "Maximum {MAX_SPLIT_TUNNEL_APPS} apps reached - uncheck one first"
                        ),
                        Lang::Tr => format!(
                            "En fazla {MAX_SPLIT_TUNNEL_APPS} uygulama seçilebilir - önce birinin işaretini kaldırın"
                        ),
                    });
                    return true;
                }
                entry.insert(exe_name);
            }
        }
        if self.only_selected {
            self.refresh_filtered();
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
            .filter(|&idx| !self.only_selected || self.is_selected(&self.all_apps[idx]))
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

    fn search_char_count(&self) -> usize {
        self.search_query.chars().count()
    }

    fn clamped_search_cursor(&self) -> usize {
        self.search_cursor.min(self.search_char_count())
    }

    fn search_byte_index_at_char(&self, char_idx: usize) -> usize {
        self.search_query
            .char_indices()
            .nth(char_idx)
            .map_or(self.search_query.len(), |(byte_idx, _)| byte_idx)
    }

    fn search_insert_char(&mut self, ch: char) -> bool {
        let len = self.search_char_count();
        if len >= MAX_SEARCH_CHARS {
            return false;
        }
        let cursor = self.search_cursor.min(len);
        let byte_idx = self.search_byte_index_at_char(cursor);
        self.search_query.insert(byte_idx, ch);
        self.search_cursor = cursor + 1;
        self.clear_confirmations();
        self.cursor = 0;
        self.scroll_offset = 0;
        self.refresh_filtered();
        true
    }

    fn search_insert_str_capped(&mut self, text: &str) -> bool {
        let mut len = self.search_char_count();
        let mut cursor = self.search_cursor.min(len);
        let mut byte_idx = self.search_byte_index_at_char(cursor);
        let mut changed = false;
        for ch in text.chars() {
            if ch.is_control() {
                continue;
            }
            if len >= MAX_SEARCH_CHARS {
                break;
            }
            self.search_query.insert(byte_idx, ch);
            byte_idx += ch.len_utf8();
            cursor += 1;
            len += 1;
            changed = true;
        }
        if changed {
            self.search_cursor = cursor;
            self.clear_confirmations();
            self.cursor = 0;
            self.scroll_offset = 0;
            self.refresh_filtered();
        }
        changed
    }

    fn search_backspace(&mut self) -> bool {
        let cursor = self.clamped_search_cursor();
        if cursor > 0 {
            let start = self.search_byte_index_at_char(cursor - 1);
            let end = self.search_byte_index_at_char(cursor);
            self.search_query.drain(start..end);
            self.search_cursor = cursor - 1;
            self.clear_confirmations();
            self.cursor = 0;
            self.scroll_offset = 0;
            self.refresh_filtered();
            true
        } else {
            false
        }
    }

    fn search_delete(&mut self) -> bool {
        let len = self.search_char_count();
        let cursor = self.search_cursor.min(len);
        if cursor < len {
            let start = self.search_byte_index_at_char(cursor);
            let end = self.search_byte_index_at_char(cursor + 1);
            self.search_query.drain(start..end);
            self.search_cursor = cursor;
            self.clear_confirmations();
            self.cursor = 0;
            self.scroll_offset = 0;
            self.refresh_filtered();
            true
        } else {
            false
        }
    }

    fn search_move_left(&mut self) -> bool {
        let cursor = self.clamped_search_cursor();
        if cursor > 0 {
            self.search_cursor = cursor - 1;
            true
        } else {
            false
        }
    }

    fn search_move_right(&mut self) -> bool {
        let len = self.search_char_count();
        let cursor = self.search_cursor.min(len);
        if cursor < len {
            self.search_cursor = cursor + 1;
            true
        } else {
            false
        }
    }

    fn search_move_home(&mut self) -> bool {
        let cursor = self.clamped_search_cursor();
        if cursor != 0 {
            self.search_cursor = 0;
            true
        } else {
            false
        }
    }

    fn search_move_end(&mut self) -> bool {
        let len = self.search_char_count();
        if self.search_cursor != len {
            self.search_cursor = len;
            true
        } else {
            false
        }
    }

    fn search_clear(&mut self) -> bool {
        if !self.search_query.is_empty() || self.search_cursor != 0 {
            let was_non_empty = !self.search_query.is_empty();
            self.search_query.clear();
            self.search_cursor = 0;
            if was_non_empty {
                self.clear_confirmations();
                self.cursor = 0;
                self.scroll_offset = 0;
                self.refresh_filtered();
            }
            true
        } else {
            false
        }
    }

    fn submit_custom_app(&mut self) {
        let Some(raw) = self.add_modal.as_ref().map(|m| m.input.clone()) else {
            return;
        };
        let Some(canonical) = canonical_exe_entry(&raw) else {
            if let Some(modal) = self.add_modal.as_mut() {
                modal.error = Some(
                    tr(
                        "Enter an executable name (e.g. discord.exe)",
                        "Bir uygulama dosya adı girin (örn. discord.exe)",
                    )
                    .to_string(),
                );
            }
            return;
        };

        let key = normalize_exe(&canonical);
        if key.is_empty() {
            if let Some(modal) = self.add_modal.as_mut() {
                modal.error = Some(
                    tr(
                        "Enter a valid executable name",
                        "Geçerli bir uygulama dosya adı girin",
                    )
                    .to_string(),
                );
            }
            return;
        }

        if !self.selected_entries.contains_key(&key)
            && self.selected_entries.len() >= MAX_SPLIT_TUNNEL_APPS
        {
            if let Some(modal) = self.add_modal.as_mut() {
                modal.error = Some(match i18n::active_lang() {
                    Lang::En => {
                        format!("Maximum {MAX_SPLIT_TUNNEL_APPS} apps reached - uncheck one first")
                    }
                    Lang::Tr => format!(
                        "En fazla {MAX_SPLIT_TUNNEL_APPS} uygulama seçilebilir - önce birinin işaretini kaldırın"
                    ),
                });
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

        self.clear_confirmations();
        self.add_modal = None;
        self.refresh_filtered();
        if let Some(pos) = self.filtered_indices.iter().position(|&i| i == target_idx) {
            self.cursor = pos;
            self.sync_viewport(self.last_list_height);
        } else if !self.search_query.is_empty() {
            // Clear an unrelated active search filter so the newly added app is visible.
            self.search_query.clear();
            self.search_cursor = 0;
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
/// Returns `Ok(Some(updated))` when the user confirms with `Enter`/`s`, or `Ok(None)`
/// when cancelled with `Esc`, `q`, or `Ctrl+C`.
pub fn run_split_tunnel_picker(initial: SplitTunnelConfig) -> Result<Option<SplitTunnelConfig>> {
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || std::env::var("TERM").as_deref() == Ok("dumb")
    {
        anyhow::bail!(
            "interactive split-tunnel picker requires a TTY; use 'vdpi split status|list|mode|add|remove'"
        );
    }

    i18n::init_from_config();

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
                Event::Paste(text) => {
                    if handle_paste(&mut state, &text) == Action::Redraw {
                        break;
                    }
                }
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

fn handle_paste(state: &mut PickerState, pasted: &str) -> Action {
    let first_line = first_non_empty_pasted_line(pasted);
    if let Some(modal) = state.add_modal.as_mut() {
        if modal.insert_str_capped(first_line) {
            return Action::Redraw;
        }
        return Action::Ignore;
    }

    if state.search_focused && state.search_insert_str_capped(first_line) {
        return Action::Redraw;
    }

    Action::Ignore
}

fn handle_key(state: &mut PickerState, key: KeyEvent) -> Action {
    // Windows ConPTY emits Release events alongside Press; ignore all Releases.
    if key.kind == KeyEventKind::Release {
        return Action::Ignore;
    }

    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('c' | 'C'))
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
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if state.add_modal.as_mut().is_some_and(AddModalState::clear) {
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

    match key.code {
        // Navigation and deletion keys allow Repeat cleanly.
        KeyCode::Backspace => {
            if state
                .add_modal
                .as_mut()
                .is_some_and(AddModalState::backspace)
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Delete => {
            if state.add_modal.as_mut().is_some_and(AddModalState::delete) {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Left => {
            if state
                .add_modal
                .as_mut()
                .is_some_and(AddModalState::move_left)
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Right => {
            if state
                .add_modal
                .as_mut()
                .is_some_and(AddModalState::move_right)
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Home => {
            if state
                .add_modal
                .as_mut()
                .is_some_and(AddModalState::move_home)
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::End => {
            if state
                .add_modal
                .as_mut()
                .is_some_and(AddModalState::move_end)
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
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
            if state
                .add_modal
                .as_mut()
                .is_some_and(|modal| modal.insert_char(ch))
            {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        _ => Action::Ignore,
    }
}

fn handle_search_key(state: &mut PickerState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if state.search_clear() {
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

    let page_step = state.last_list_height.saturating_sub(1).max(1);

    match key.code {
        // Navigation and deletion keys allow Repeat cleanly.
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
            if state.search_backspace() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Delete => {
            if state.search_delete() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Left => {
            if state.search_move_left() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Right => {
            if state.search_move_right() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Home => {
            if state.search_move_home() {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::End => {
            if state.search_move_end() {
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
            if state.search_insert_char(ch) {
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        _ => Action::Ignore,
    }
}

fn try_save(state: &mut PickerState) -> Action {
    state.pending_discard_confirm = false;
    if state.mode == SplitTunnelMode::Include && state.selected_count() == 0 {
        if state.pending_save_confirm {
            state.clear_confirmations();
            return Action::Save;
        }
        state.pending_save_confirm = true;
        state.set_confirm_notice(NoticeKind::EmptyIncludeConfirm);
        return Action::Redraw;
    }
    if state.mode == SplitTunnelMode::All && state.selected_count() > 0 {
        if state.pending_save_confirm {
            state.clear_confirmations();
            return Action::Save;
        }
        state.pending_save_confirm = true;
        state.set_confirm_notice(NoticeKind::AllModeConfirm);
        return Action::Redraw;
    }
    state.clear_confirmations();
    Action::Save
}

fn handle_normal_key(state: &mut PickerState, key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
        && matches!(key.code, KeyCode::Char('u' | 'U'))
    {
        if key.kind != KeyEventKind::Press {
            return Action::Ignore;
        }
        if state.search_clear() {
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
        KeyCode::Up | KeyCode::Char('k' | 'K') => {
            state.clear_confirmations();
            state.move_cursor_up(1);
            Action::Redraw
        }
        KeyCode::Down | KeyCode::Char('j' | 'J') => {
            state.clear_confirmations();
            state.move_cursor_down(1);
            Action::Redraw
        }
        KeyCode::PageUp => {
            state.clear_confirmations();
            state.move_cursor_up(page_step);
            Action::Redraw
        }
        KeyCode::PageDown => {
            state.clear_confirmations();
            state.move_cursor_down(page_step);
            Action::Redraw
        }
        KeyCode::Home => {
            state.clear_confirmations();
            state.cursor = 0;
            state.sync_viewport(state.last_list_height);
            Action::Redraw
        }
        KeyCode::End => {
            state.clear_confirmations();
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
            state.clear_confirmations();
            state.cycle_mode_forward();
            Action::Redraw
        }
        KeyCode::BackTab => {
            state.clear_confirmations();
            state.cycle_mode_backward();
            Action::Redraw
        }
        KeyCode::Char('1') => {
            if state.mode != SplitTunnelMode::All {
                state.clear_confirmations();
                state.mode = SplitTunnelMode::All;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('2') => {
            if state.mode != SplitTunnelMode::Include {
                state.clear_confirmations();
                state.mode = SplitTunnelMode::Include;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('3') => {
            if state.mode != SplitTunnelMode::Exclude {
                state.clear_confirmations();
                state.mode = SplitTunnelMode::Exclude;
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Char('f' | 'F') => {
            state.clear_confirmations();
            state.only_selected = !state.only_selected;
            state.cursor = 0;
            state.scroll_offset = 0;
            state.refresh_filtered();
            Action::Redraw
        }
        KeyCode::Char('/') => {
            state.clear_confirmations();
            state.search_focused = true;
            state.search_cursor = state.search_char_count();
            Action::Redraw
        }
        KeyCode::Char('a' | 'A') => {
            state.clear_confirmations();
            state.add_modal = Some(AddModalState::default());
            Action::Redraw
        }
        KeyCode::Char('x' | 'X') => {
            if !state.selected_entries.is_empty() {
                state.clear_confirmations();
                state.selected_entries.clear();
                if state.only_selected {
                    state.cursor = 0;
                    state.scroll_offset = 0;
                    state.refresh_filtered();
                }
                Action::Redraw
            } else {
                Action::Ignore
            }
        }
        KeyCode::Enter | KeyCode::Char('s' | 'S') => try_save(state),
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => {
            if state.is_dirty() && !state.pending_discard_confirm {
                state.pending_save_confirm = false;
                state.pending_discard_confirm = true;
                state.set_confirm_notice(NoticeKind::DiscardConfirm);
                Action::Redraw
            } else {
                Action::Cancel
            }
        }
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

fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}

fn char_display_width(ch: char) -> usize {
    let mut buf = [0u8; 4];
    let s: &str = ch.encode_utf8(&mut buf);
    Span::raw(s).width()
}

fn truncate_text(text: &str, max_cols: usize) -> Cow<'_, str> {
    if max_cols == 0 {
        return Cow::Borrowed("");
    }
    if display_width(text) <= max_cols {
        return Cow::Borrowed(text);
    }
    if max_cols == 1 {
        let mut end_byte = 0usize;
        let mut used = 0usize;
        for (idx, ch) in text.char_indices() {
            let w = char_display_width(ch);
            if used.saturating_add(w) > 1 {
                break;
            }
            used += w;
            end_byte = idx + ch.len_utf8();
        }
        return if end_byte > 0 {
            Cow::Borrowed(&text[..end_byte])
        } else {
            Cow::Borrowed("…")
        };
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

fn truncate_head(text: &str, max_cols: usize) -> Cow<'_, str> {
    if max_cols == 0 {
        return Cow::Borrowed("");
    }
    if display_width(text) <= max_cols {
        return Cow::Borrowed(text);
    }
    if max_cols == 1 {
        let mut start_byte = text.len();
        let mut used = 0usize;
        for (idx, ch) in text.char_indices().rev() {
            let w = char_display_width(ch);
            if used.saturating_add(w) > 1 {
                break;
            }
            used += w;
            start_byte = idx;
        }
        return if start_byte < text.len() {
            Cow::Borrowed(&text[start_byte..])
        } else {
            Cow::Borrowed("…")
        };
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

fn window_around_cursor<'a>(
    text: &'a str,
    cursor_char: usize,
    max_cols: usize,
) -> (Cow<'a, str>, Cow<'a, str>) {
    if max_cols == 0 {
        return (Cow::Borrowed(""), Cow::Borrowed(""));
    }
    let split_byte = text
        .char_indices()
        .nth(cursor_char)
        .map_or(text.len(), |(idx, _)| idx);
    let before = &text[..split_byte];
    let after = &text[split_byte..];

    let before_w = display_width(before);
    let after_w = display_width(after);
    if before_w.saturating_add(after_w) <= max_cols {
        return (Cow::Borrowed(before), Cow::Borrowed(after));
    }

    let after_reserve = if after.is_empty() {
        0
    } else {
        after_w.min((max_cols / 3).max(1)).min(max_cols)
    };
    let before_budget = max_cols.saturating_sub(after_reserve);
    let visible_before = truncate_head(before, before_budget);
    let used_before = display_width(&visible_before);
    let after_budget = max_cols.saturating_sub(used_before);
    let visible_after = truncate_text(after, after_budget);
    (visible_before, visible_after)
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

    // 4. Footer, optional notice, & scrollable app list
    let has_notice = state.notice.is_some();
    let show_bot_div = show_bot_div && (!has_notice || inner.height >= 12);
    let footer_reserve =
        u16::from(show_footer) + u16::from(has_notice) + u16::from(show_bot_div);
    let list_bottom = bottom.saturating_sub(footer_reserve).max(y);
    let list_area = Rect::new(inner.x, y, inner.width, list_bottom.saturating_sub(y));
    render_app_list(frame, list_area, state, palette);

    // 5. Bottom divider, optional inline warning notice, + footer
    let mut footer_y = bottom;
    if show_footer && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_footer(
            frame,
            row(footer_y),
            state.search_focused,
            state.only_selected,
            palette,
        );
    }
    if state.notice.is_some() && footer_y > y {
        footer_y = footer_y.saturating_sub(1);
        render_notice(frame, row(footer_y), state, palette);
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

fn render_notice(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    if area.is_empty() {
        return;
    }
    let Some(raw_notice) = state.notice.as_deref() else {
        return;
    };
    let prefix = "! ";
    let budget = usize::from(area.width).saturating_sub(display_width(prefix));
    let chosen = state
        .notice_kind
        .map_or(raw_notice, |kind| kind.text_for_budget(budget));
    let msg = truncate_text(&sanitize_inline(chosen), budget).into_owned();
    let line = Line::from(vec![
        Span::styled(prefix, palette.notice_warn),
        Span::styled(msg, palette.notice_warn),
    ]);
    frame.render_widget(line, area);
}

fn render_minimal(frame: &mut Frame<'_>, area: Rect, state: &PickerState, palette: Palette) {
    let width = usize::from(area.width);
    let text = match i18n::active_lang() {
        Lang::En => format!("vdpi Split ({} sel)", state.selected_count()),
        Lang::Tr => format!("vdpi Böl ({} seç)", state.selected_count()),
    };
    let line = Line::from(Span::styled(truncate_text(&text, width), palette.brand));
    frame.render_widget(line, Rect::new(area.x, area.y, area.width, 1));

    if area.height >= 2 {
        let detail_row = Rect::new(area.x, area.y + 1, area.width, 1);
        if let Some(modal) = state.add_modal.as_ref() {
            let sanitized = sanitize_inline(&modal.input);
            let cursor_char = modal.clamped_cursor();
            let split_byte = sanitized
                .char_indices()
                .nth(cursor_char)
                .map_or(sanitized.len(), |(idx, _)| idx);
            let add_prefix = tr("Add: ", "Ekle: ");
            let prompt = format!(
                "{add_prefix}{}▏{}",
                &sanitized[..split_byte],
                &sanitized[split_byte..]
            );
            let prompt_cursor = add_prefix.chars().count() + cursor_char + 1;
            let (before, after) = window_around_cursor(&prompt, prompt_cursor, width);
            let visible = format!("{before}{after}");
            frame.render_widget(
                Line::from(Span::styled(visible, palette.search_text)),
                detail_row,
            );
            if area.height >= 3 {
                if let Some(err) = modal.error.as_deref() {
                    frame.render_widget(
                        Line::from(Span::styled(
                            truncate_text(err, width),
                            palette.modal_error,
                        )),
                        Rect::new(area.x, area.y + 2, area.width, 1),
                    );
                }
            }
        } else if state.search_focused {
            let sanitized = sanitize_inline(&state.search_query);
            let cursor_char = state.clamped_search_cursor();
            let split_byte = sanitized
                .char_indices()
                .nth(cursor_char)
                .map_or(sanitized.len(), |(idx, _)| idx);
            let prompt = format!("/{}▏{}", &sanitized[..split_byte], &sanitized[split_byte..]);
            let prompt_cursor = 1 + cursor_char + 1;
            let (before, after) = window_around_cursor(&prompt, prompt_cursor, width);
            let visible = format!("{before}{after}");
            frame.render_widget(
                Line::from(Span::styled(visible, palette.search_text)),
                detail_row,
            );
        } else if !state.search_query.is_empty() {
            let prompt = format!("/{}", sanitize_inline(&state.search_query));
            frame.render_widget(
                Line::from(Span::styled(
                    truncate_head(&prompt, width).into_owned(),
                    palette.search_text,
                )),
                detail_row,
            );
        } else if let Some(raw_notice) = state.notice.as_deref() {
            let chosen = state
                .notice_kind
                .map_or(raw_notice, |kind| kind.text_for_budget(width));
            frame.render_widget(
                Line::from(Span::styled(
                    truncate_text(&sanitize_inline(chosen), width).into_owned(),
                    palette.notice_warn,
                )),
                detail_row,
            );
        }
    }
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
    let pill = match (i18n::active_lang(), state.only_selected) {
        (Lang::En, true) => format!("{count} selected [filter]"),
        (Lang::En, false) => format!("{count} selected"),
        (Lang::Tr, true) => format!("{count} seçili [filtre]"),
        (Lang::Tr, false) => format!("{count} seçili"),
    };
    let pill_len = display_width(&pill);
    let pill_style = if state.only_selected || count > 0 {
        palette.pill_selected
    } else {
        palette.pill_zero
    };

    const BRAND: &str = "vdpi";
    let subtitle = tr(" Split Tunneling", " Bölünmüş Tünelleme");
    let full_title = tr("vdpi Split Tunneling", "vdpi Bölünmüş Tünelleme");
    let full_left_len = display_width(BRAND) + display_width(subtitle);

    let line = if width >= full_left_len + 2 + pill_len {
        let gap = width - full_left_len - pill_len;
        Line::from(vec![
            Span::styled(BRAND, palette.brand),
            Span::styled(subtitle, palette.title),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill, pill_style),
        ])
    } else if width >= pill_len + 6 {
        let left_budget = width - pill_len - 1;
        let left_text = truncate_text(full_title, left_budget);
        let left_len = display_width(&left_text);
        let gap = width.saturating_sub(left_len + pill_len);
        Line::from(vec![
            Span::styled(left_text, palette.brand),
            Span::raw(" ".repeat(gap)),
            Span::styled(pill, pill_style),
        ])
    } else {
        Line::from(Span::styled(
            truncate_text(full_title, width),
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

    let (all_label, inc_label, exc_label, gap_str) = match i18n::active_lang() {
        Lang::En => {
            if width >= 66 {
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
            }
        }
        Lang::Tr => {
            if width >= 66 {
                (
                    "1 Tüm uygulamalar",
                    "2 Yalnızca seçililer",
                    "3 Seçilileri hariç tut",
                    "  ",
                )
            } else if width >= 46 {
                ("1 Tümü", "2 Yalnızca seçililer", "3 Hariç tut", "  ")
            } else {
                ("1 Tümü", "2 Dahil", "3 Hariç", " ")
            }
        }
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
        let pill_chars = display_width(prefix) + display_width(label) + suffix.len();
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
        SplitTunnelMode::All if state.selected_count() > 0 => tr(
            "All mode protects every app (checked apps ignored; press 2 or 3).",
            "Tümü modu her uygulamayı korur (seçililer yok sayılır; 2 veya 3'e basın).",
        ),
        SplitTunnelMode::All => tr(
            "Every app is protected through DPI desync.",
            "Tüm uygulamalar DPI desync ile korunur.",
        ),
        SplitTunnelMode::Include if state.selected_count() == 0 => tr(
            "Empty Include protects no apps (check apps below to enable).",
            "Boş Dahil Et hiçbir uygulamayı korumaz (etkinleştirmek için aşağıdan seçin).",
        ),
        SplitTunnelMode::Include => tr(
            "DPI desync applies ONLY to checked apps.",
            "DPI desync YALNIZCA işaretli uygulamalara uygulanır.",
        ),
        SplitTunnelMode::Exclude => tr(
            "Checked apps bypass DPI desync; all others stay protected.",
            "İşaretli uygulamalar DPI desync'i atlar; diğerleri korunur.",
        ),
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
    let count_badge = match (i18n::active_lang(), state.only_selected) {
        (Lang::En, true) => format!("{filtered} / {total} (selected)"),
        (Lang::En, false) => format!("{filtered} / {total} apps"),
        (Lang::Tr, true) => format!("{filtered} / {total} (seçili)"),
        (Lang::Tr, false) => format!("{filtered} / {total} uygulama"),
    };
    let count_len = display_width(&count_badge);

    let line = if state.search_focused {
        let prompt = tr("Search: ", "Ara: ");
        let cursor_glyph = "▏";
        let prompt_len = display_width(prompt);
        let cursor_len = display_width(cursor_glyph);

        let show_count = width >= prompt_len + cursor_len + count_len + 4;
        let query_budget = if show_count {
            width.saturating_sub(prompt_len + cursor_len + count_len + 2)
        } else {
            width.saturating_sub(prompt_len + cursor_len)
        };
        let sanitized = sanitize_inline(&state.search_query);
        let (visible_before, visible_after) =
            window_around_cursor(&sanitized, state.clamped_search_cursor(), query_budget);
        let query_len = display_width(&visible_before) + display_width(&visible_after);

        let mut spans = vec![
            Span::styled(prompt, palette.search_prompt_active),
            Span::styled(visible_before.into_owned(), palette.search_text),
            Span::styled(cursor_glyph, palette.search_cursor),
            Span::styled(visible_after.into_owned(), palette.search_text),
        ];
        if show_count {
            let left_used = prompt_len + query_len + cursor_len;
            let gap = width.saturating_sub(left_used + count_len);
            spans.push(Span::raw(" ".repeat(gap)));
            spans.push(Span::styled(count_badge, palette.search_count));
        }
        Line::from(spans)
    } else if state.search_query.is_empty() {
        let search_word = tr(" search", " ara");
        let full_left = tr("/ search", "/ ara");
        let sep = " · ";
        let full_len = display_width(full_left) + display_width(sep) + count_len;
        if width >= full_len {
            Line::from(vec![
                Span::styled("/", palette.search_slash),
                Span::styled(search_word, palette.search_placeholder),
                Span::styled(sep, palette.search_placeholder),
                Span::styled(count_badge, palette.search_count),
            ])
        } else {
            let compact = format!("{full_left} · {filtered}/{total}");
            Line::from(Span::styled(
                truncate_text(&compact, width).into_owned(),
                palette.search_placeholder,
            ))
        }
    } else {
        let sanitized = sanitize_inline(&state.search_query);
        let sep = " · ";
        let prefix_len = 2usize; // "/ "
        let suffix_len = display_width(sep) + count_len;
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
            if state.only_selected {
                tr(
                    "No selected apps. Press 'f' to show all apps.",
                    "Seçili uygulama yok. Tümünü görmek için 'f' tuşuna basın.",
                )
                .to_string()
            } else {
                tr(
                    "No apps found. Press 'a' to add a custom executable.",
                    "Uygulama bulunamadı. Özel uygulama eklemek için 'a' tuşuna basın.",
                )
                .to_string()
            }
        } else {
            let sanitized_q = sanitize_inline(&state.search_query);
            let suffix = if state.search_focused {
                tr(
                    "Press Esc then 'a' to add custom.",
                    "Özel eklemek için Esc sonra 'a' basın.",
                )
            } else if state.only_selected {
                tr(
                    "Press 'f' for all apps or 'a' to add.",
                    "Tümü için 'f', eklemek için 'a' basın.",
                )
            } else {
                tr("Press 'a' to add custom.", "Özel eklemek için 'a' basın.")
            };
            let overhead = 18 + display_width(suffix);
            let q = truncate_text(
                &sanitized_q,
                usize::from(area.width).saturating_sub(overhead).max(4),
            );
            match i18n::active_lang() {
                Lang::En => format!("No matches for \"{q}\". {suffix}"),
                Lang::Tr => format!("\"{q}\" için eşleşme yok. {suffix}"),
            }
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
                (tr("● Running", "● Çalışıyor"), palette.badge_running)
            } else if app.category == AppCategory::Custom {
                (tr("Custom", "Özel"), palette.badge_custom)
            } else {
                (tr("Installed", "Kurulu"), palette.badge_installed)
            }
        } else if content_width >= 26 {
            if app.is_running {
                (tr("● Run", "● Açık"), palette.badge_running)
            } else if app.category == AppCategory::Custom {
                (tr("Custom", "Özel"), palette.badge_custom)
            } else {
                (tr("Inst", "Krl"), palette.badge_installed)
            }
        } else {
            ("", palette.badge_installed)
        };
        let badge_len = display_width(badge_text);
        let badge_reserve = if badge_len > 0 { badge_len + 1 } else { 0 };

        // Fixed prefix: marker(2) + checkbox(3) + space(1) = 6 cols.
        let prefix_len = 6usize;
        let mid_budget = content_width.saturating_sub(prefix_len + badge_reserve);

        let clean_name = sanitize_inline(&app.display_name);
        let clean_exe = sanitize_inline(&app.exe_name);
        let show_exe = !clean_exe.eq_ignore_ascii_case(&clean_name) && mid_budget >= 18;

        let (shown_name, shown_exe) = if show_exe {
            let name_len = display_width(&clean_name);
            let exe_len = display_width(&clean_exe);
            if name_len + 2 + exe_len <= mid_budget {
                (clean_name.into_owned(), Some(clean_exe.into_owned()))
            } else {
                let name_cap = ((mid_budget * 3) / 5).max(10).min(mid_budget - 6);
                let trunc_name = truncate_text(&clean_name, name_cap).into_owned();
                let used_name = display_width(&trunc_name);
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
            palette.name_active.patch(row_bg)
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

        let mut mid_used = display_width(&shown_name);
        spans.push(Span::styled(shown_name, name_style));

        if let Some(exe) = shown_exe {
            let exe_width = display_width(&exe);
            let exe_gap = if mid_used + 2 + exe_width <= mid_budget {
                "  "
            } else {
                " "
            };
            mid_used += exe_gap.len() + exe_width;
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

fn render_footer(
    frame: &mut Frame<'_>,
    area: Rect,
    search_focused: bool,
    only_selected: bool,
    palette: Palette,
) {
    if area.is_empty() {
        return;
    }
    let width = usize::from(area.width);
    let key = palette.footer_key;
    let text = palette.footer_text;
    let is_tr = i18n::active_lang() == Lang::Tr;
    let filter_label = match (is_tr, only_selected) {
        (false, true) => " all · ",
        (false, false) => " sel · ",
        (true, true) => " tüm · ",
        (true, false) => " seç · ",
    };

    let line = if search_focused {
        if is_tr {
            if width >= 66 {
                Line::from(vec![
                    Span::styled("filtrele · ", text),
                    Span::styled("↑↓", key),
                    Span::styled(" gez · ", text),
                    Span::styled("tab", key),
                    Span::styled(" seç · ", text),
                    Span::styled("enter/esc", key),
                    Span::styled(" bitti · ", text),
                    Span::styled("^u", key),
                    Span::styled(" temizle", text),
                ])
            } else if width >= 50 {
                Line::from(vec![
                    Span::styled("↑↓", key),
                    Span::styled(" gez · ", text),
                    Span::styled("tab", key),
                    Span::styled(" seç · ", text),
                    Span::styled("enter/esc", key),
                    Span::styled(" bitti · ", text),
                    Span::styled("^u", key),
                    Span::styled(" temizle", text),
                ])
            } else if width >= 37 {
                Line::from(vec![
                    Span::styled("↑↓", key),
                    Span::styled(" · ", text),
                    Span::styled("tab", key),
                    Span::styled(" seç · ", text),
                    Span::styled("esc", key),
                    Span::styled(" bitti · ", text),
                    Span::styled("^u", key),
                    Span::styled(" temizle", text),
                ])
            } else {
                Line::from(vec![
                    Span::styled("tab", key),
                    Span::styled(" seç · ", text),
                    Span::styled("esc", key),
                    Span::styled(" bitti", text),
                ])
            }
        } else if width >= 66 {
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
        } else if width >= 37 {
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
    } else if is_tr {
        if width >= 71 {
            Line::from(vec![
                Span::styled("space", key),
                Span::styled(" seç · ", text),
                Span::styled("/", key),
                Span::styled(" · ", text),
                Span::styled("f", key),
                Span::styled(filter_label, text),
                Span::styled("tab", key),
                Span::styled(" mod · ", text),
                Span::styled("a", key),
                Span::styled(" ekle · ", text),
                Span::styled("x", key),
                Span::styled(" sil · ", text),
                Span::styled("enter", key),
                Span::styled(" kaydet · ", text),
                Span::styled("esc", key),
            ])
        } else if width >= 56 {
            Line::from(vec![
                Span::styled("spc", key),
                Span::styled(" seç · ", text),
                Span::styled("/", key),
                Span::styled(" ara · ", text),
                Span::styled("f", key),
                Span::styled(filter_label, text),
                Span::styled("tab", key),
                Span::styled(" mod · ", text),
                Span::styled("a", key),
                Span::styled(" · ", text),
                Span::styled("enter", key),
                Span::styled(" · ", text),
                Span::styled("esc", key),
            ])
        } else if width >= 42 {
            Line::from(vec![
                Span::styled("spc", key),
                Span::styled(" seç · ", text),
                Span::styled("/", key),
                Span::styled(" · ", text),
                Span::styled("f", key),
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
        }
    } else if width >= 71 {
        Line::from(vec![
            Span::styled("space", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" · ", text),
            Span::styled("f", key),
            Span::styled(filter_label, text),
            Span::styled("tab", key),
            Span::styled(" mode · ", text),
            Span::styled("a", key),
            Span::styled(" add · ", text),
            Span::styled("x", key),
            Span::styled(" clr · ", text),
            Span::styled("enter", key),
            Span::styled(" save · ", text),
            Span::styled("esc", key),
        ])
    } else if width >= 56 {
        Line::from(vec![
            Span::styled("spc", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" find · ", text),
            Span::styled("f", key),
            Span::styled(filter_label, text),
            Span::styled("tab", key),
            Span::styled(" mode · ", text),
            Span::styled("a", key),
            Span::styled(" · ", text),
            Span::styled("enter", key),
            Span::styled(" · ", text),
            Span::styled("esc", key),
        ])
    } else if width >= 42 {
        Line::from(vec![
            Span::styled("spc", key),
            Span::styled(" toggle · ", text),
            Span::styled("/", key),
            Span::styled(" · ", text),
            Span::styled("f", key),
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
        .title(Span::styled(
            tr(" Add custom app ", " Özel uygulama ekle "),
            palette.brand,
        ))
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
        let prompt = tr("e.g. discord.exe or firefox", "örn. discord.exe veya firefox");
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
        let prefix_w = display_width(prefix);
        let cursor_w = display_width(cursor_glyph);
        let input_budget = width.saturating_sub(prefix_w + cursor_w + 1);
        let sanitized = sanitize_inline(&modal.input);
        let (visible_before, visible_after) =
            window_around_cursor(&sanitized, modal.clamped_cursor(), input_budget);
        let used = prefix_w
            + display_width(&visible_before)
            + cursor_w
            + display_width(&visible_after);
        let pad = width.saturating_sub(used);

        let bg = palette.modal_input_bg;
        let line = Line::from(vec![
            Span::styled(prefix, bg.patch(palette.search_prompt_active)),
            Span::styled(visible_before.into_owned(), bg),
            Span::styled(cursor_glyph, bg.patch(palette.search_cursor)),
            Span::styled(visible_after.into_owned(), bg),
            Span::styled(" ".repeat(pad), bg),
        ]);
        frame.render_widget(line, row(y));
        y = y.saturating_add(1);
    }

    // Inline error line
    if let Some(err) = modal.error.as_deref() {
        if y + 1 < bottom {
            let err_prefix = if color { "● " } else { "! " };
            let msg = truncate_text(err, width.saturating_sub(display_width(err_prefix)));
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
        let is_tr = i18n::active_lang() == Lang::Tr;
        let add_lbl = tr(" add · ", " ekle · ");
        let clear_lbl = tr(" clear · ", " temizle · ");
        let cancel_lbl = tr(" cancel", " iptal");
        let full_w = if is_tr { 35 } else { 33 };
        let med_w = if is_tr { 24 } else { 22 };
        let line = if width >= full_w {
            Line::from(vec![
                Span::styled("enter", palette.footer_key),
                Span::styled(add_lbl, palette.footer_text),
                Span::styled("^u", palette.footer_key),
                Span::styled(clear_lbl, palette.footer_text),
                Span::styled("esc", palette.footer_key),
                Span::styled(cancel_lbl, palette.footer_text),
            ])
        } else if width >= med_w {
            Line::from(vec![
                Span::styled("enter", palette.footer_key),
                Span::styled(add_lbl, palette.footer_text),
                Span::styled("esc", palette.footer_key),
                Span::styled(cancel_lbl, palette.footer_text),
            ])
        } else {
            Line::from(vec![
                Span::styled("enter", palette.footer_key),
                Span::styled(" · ", palette.footer_text),
                Span::styled("esc", palette.footer_key),
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
            state.search_focused = true;
            state.search_query =
                "very_long_search_query_exceeding_tiny_terminal_widths".to_string();
            state.search_cursor = 18;
            let _ = render_to_buffer(&mut state, w, h, true);
            state.search_focused = false;
            state.add_modal = Some(AddModalState {
                input: "very_long_executable_name_that_exceeds_small_widths.exe".to_string(),
                cursor: 20,
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
        assert_eq!(state.search_cursor, 13);
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
        assert_eq!(state.search_cursor, 0);
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
        assert_eq!(state.search_cursor, 3);
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

        // Dirty Esc warns once, then discards on second Esc; Ctrl+C cancels immediately.
        assert!(state.is_dirty());
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert_eq!(
            state.notice.as_deref(),
            Some("Unsaved changes - Esc again to discard, or s/Enter to save")
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Cancel);

        // Clean state cancels immediately on Esc and q.
        let mut clean = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        assert!(!clean.is_dirty());
        assert_eq!(handle_key(&mut clean, press(KeyCode::Esc)), Action::Cancel);
        assert_eq!(
            handle_key(&mut clean, press(KeyCode::Char('q'))),
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

    #[test]
    fn round1_cursor_bg_altgr_paste_filter_guards_and_layout() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());

        // 1. Cursor row has ACTIVE_BG on app name (no dark background hole).
        let buf = render_to_buffer(&mut state, 80, 24, true);
        let text = buffer_text(&buf);
        let cursor_y = text
            .lines()
            .position(|l| l.contains("▸") && l.contains("Discord"))
            .expect("cursor row with Discord") as u16;
        let name_x = (0..buf.area.width)
            .find(|&x| buf[(x, cursor_y)].symbol() == "D")
            .expect("Discord 'D' cell");
        assert_eq!(buf[(name_x, cursor_y)].bg, ACTIVE_BG);

        // 2. Uppercase J / K navigate cleanly.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('J'))),
            Action::Redraw
        );
        assert_eq!(state.cursor, 1);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('K'))),
            Action::Redraw
        );
        assert_eq!(state.cursor, 0);

        // 3. AltGr (CONTROL | ALT) and Event::Paste work in modal and search.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('a'))),
            Action::Redraw
        );
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(
            handle_key(&mut state, KeyEvent::new(KeyCode::Char('\\'), altgr)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, KeyEvent::new(KeyCode::Char('@'), altgr)),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, r"\@");
        assert_eq!(handle_paste(&mut state, "game.exe\r\n"), Action::Redraw);
        assert_eq!(state.add_modal.as_ref().unwrap().input, r"\@game.exe");
        // NO_COLOR modal input uses Modifier::REVERSED.
        let nc_modal = render_to_buffer(&mut state, 80, 24, false);
        assert_no_rgb_colors(&nc_modal);
        let nc_modal_text = buffer_text(&nc_modal);
        let modal_y = nc_modal_text
            .lines()
            .position(|l| l.contains(r"\@game.exe"))
            .expect("modal input row") as u16;
        let input_x = (0..nc_modal.area.width)
            .find(|&x| nc_modal[(x, modal_y)].symbol() == "@")
            .expect("modal input char");
        assert!(nc_modal[(input_x, modal_y)]
            .modifier
            .contains(Modifier::REVERSED));
        // Minimal view renders active modal input.
        let min_modal = buffer_text(&render_to_buffer(&mut state, 14, 5, true));
        assert!(min_modal.contains("game.exe"));
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);

        // Search AltGr + Paste + empty-search focused hint + minimal search display.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('/'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, KeyEvent::new(KeyCode::Char('@'), altgr)),
            Action::Redraw
        );
        assert_eq!(handle_paste(&mut state, "nomatch\n"), Action::Redraw);
        assert_eq!(state.search_query, "@nomatch");
        let empty_search = buffer_text(&render_to_buffer(&mut state, 80, 24, true));
        assert!(empty_search.contains("Press Esc then 'a' to add custom."));
        let min_search = buffer_text(&render_to_buffer(&mut state, 14, 5, true));
        assert!(min_search.contains("nomatch"));
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);

        // 4. [f] selected-only filter toggles cleanly with header indicator.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('f'))),
            Action::Redraw
        );
        assert!(state.only_selected);
        assert_eq!(state.filtered_indices.len(), 1);
        let filtered_text = buffer_text(&render_to_buffer(&mut state, 80, 24, true));
        assert!(filtered_text.contains("1 selected [filter]"));
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('F'))),
            Action::Redraw
        );
        assert!(!state.only_selected);
        assert_eq!(state.filtered_indices.len(), 6);

        // 5. Mode warnings on save: All mode with checked apps warns on first Enter/s, saves on second.
        assert_eq!(state.mode, SplitTunnelMode::All);
        assert_eq!(state.selected_count(), 1);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('s'))),
            Action::Redraw
        );
        assert!(state
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("All mode ignores checked apps")));
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('s'))),
            Action::Save
        );

        // Include mode with 0 checked apps warns on first Enter, saves on second.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('x'))),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('2'))),
            Action::Redraw
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::Enter)), Action::Redraw);
        assert!(state
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("Empty Include protects no apps")));
        assert_eq!(handle_key(&mut state, press(KeyCode::Enter)), Action::Save);

        // 6. MAX_SPLIT_TUNNEL_APPS (256) cap produces inline notice on toggle & modal error on add.
        let mut big_apps = Vec::with_capacity(MAX_SPLIT_TUNNEL_APPS + 2);
        let mut preselected = Vec::with_capacity(MAX_SPLIT_TUNNEL_APPS);
        for i in 0..(MAX_SPLIT_TUNNEL_APPS + 2) {
            let exe = format!("cap_app_{i:03}.exe");
            if i < MAX_SPLIT_TUNNEL_APPS {
                preselected.push(exe.clone());
            }
            big_apps.push(DiscoveredApp {
                display_name: format!("Cap App {i:03}"),
                exe_name: exe,
                path: None,
                is_running: false,
                category: AppCategory::Installed,
            });
        }
        let mut cap_state = PickerState::new(
            SplitTunnelConfig {
                mode: SplitTunnelMode::Exclude,
                apps: preselected,
            },
            big_apps,
        );
        assert_eq!(cap_state.selected_count(), MAX_SPLIT_TUNNEL_APPS);
        cap_state.cursor = MAX_SPLIT_TUNNEL_APPS;
        assert_eq!(
            handle_key(&mut cap_state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(cap_state.selected_count(), MAX_SPLIT_TUNNEL_APPS);
        assert!(cap_state
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("Maximum 256 apps reached")));

        handle_key(&mut cap_state, press(KeyCode::Char('a')));
        assert_eq!(handle_paste(&mut cap_state, "overflow.exe"), Action::Redraw);
        handle_key(&mut cap_state, press(KeyCode::Enter));
        assert!(cap_state
            .add_modal
            .as_ref()
            .and_then(|m| m.error.as_deref())
            .is_some_and(|e| e.contains("Maximum 256 apps reached")));
    }

    #[test]
    fn confirmation_notices_never_truncate_at_76_60_and_46_cols() {
        for kind in [
            NoticeKind::EmptyIncludeConfirm,
            NoticeKind::AllModeConfirm,
            NoticeKind::DiscardConfirm,
        ] {
            assert!(
                display_width(kind.default_text()) <= 70,
                "default notice exceeds 70 cols: {:?}",
                kind.default_text()
            );
        }

        for &(w, h) in &[(76, 24), (60, 22), (46, 18)] {
            // 1. Empty Include confirmation notice
            let mut empty_inc = PickerState::new(
                SplitTunnelConfig {
                    mode: SplitTunnelMode::Include,
                    apps: Vec::new(),
                },
                sample_apps(),
            );
            assert_eq!(
                handle_key(&mut empty_inc, press(KeyCode::Char('s'))),
                Action::Redraw
            );
            let buf = render_to_buffer(&mut empty_inc, w, h, true);
            let text = buffer_text(&buf);
            let notice_line = text
                .lines()
                .find(|l| l.contains("! "))
                .unwrap_or_else(|| panic!("missing Empty-Include notice at {w}x{h}:\n{text}"));
            assert!(
                !notice_line.contains('…'),
                "Empty-Include notice truncated at {w}x{h}: {notice_line:?}"
            );
            assert!(
                notice_line.contains("to save"),
                "Empty-Include notice lost 'to save' at {w}x{h}: {notice_line:?}"
            );

            // 2. All mode with checked apps confirmation notice
            let mut all_mode = PickerState::new(
                SplitTunnelConfig {
                    mode: SplitTunnelMode::All,
                    apps: vec!["Discord.exe".to_string()],
                },
                sample_apps(),
            );
            assert_eq!(
                handle_key(&mut all_mode, press(KeyCode::Enter)),
                Action::Redraw
            );
            let buf = render_to_buffer(&mut all_mode, w, h, true);
            let text = buffer_text(&buf);
            let notice_line = text
                .lines()
                .find(|l| l.contains("! "))
                .unwrap_or_else(|| panic!("missing All-mode notice at {w}x{h}:\n{text}"));
            assert!(
                !notice_line.contains('…'),
                "All-mode notice truncated at {w}x{h}: {notice_line:?}"
            );
            assert!(
                notice_line.contains("to save"),
                "All-mode notice lost 'to save' at {w}x{h}: {notice_line:?}"
            );

            // 3. Esc unsaved changes confirmation notice
            let mut dirty = PickerState::new(SplitTunnelConfig::default(), sample_apps());
            assert_eq!(
                handle_key(&mut dirty, press(KeyCode::Char(' '))),
                Action::Redraw
            );
            assert_eq!(handle_key(&mut dirty, press(KeyCode::Esc)), Action::Redraw);
            let buf = render_to_buffer(&mut dirty, w, h, true);
            let text = buffer_text(&buf);
            let notice_line = text
                .lines()
                .find(|l| l.contains("! "))
                .unwrap_or_else(|| panic!("missing Esc-unsaved notice at {w}x{h}:\n{text}"));
            assert!(
                !notice_line.contains('…'),
                "Esc-unsaved notice truncated at {w}x{h}: {notice_line:?}"
            );
            assert!(
                notice_line.contains("discard"),
                "Esc-unsaved notice lost 'discard' at {w}x{h}: {notice_line:?}"
            );
            assert!(
                notice_line.contains("to save"),
                "Esc-unsaved notice lost 'to save' at {w}x{h}: {notice_line:?}"
            );
        }
    }

    #[test]
    fn modal_ice_blue_style_multiline_paste_and_cursor_navigation() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('a'))),
            Action::Redraw
        );

        // 1. Multiline paste takes ONLY the first non-empty line (never concatenates later lines).
        assert_eq!(
            handle_paste(&mut state, "\r\n   \n  alpha.exe  \r\nbeta.exe\ngamma.exe"),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "alpha.exe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 9);

        // 2. render_add_modal preserves ICE_BLUE fg over ACTIVE_BG on both '>' prompt and '▏' cursor.
        let buf = render_to_buffer(&mut state, 80, 24, true);
        let text = buffer_text(&buf);
        let modal_y = text
            .lines()
            .position(|l| l.contains("> alpha.exe▏"))
            .expect("modal input row with prompt and cursor") as u16;
        let prompt_x = (0..buf.area.width)
            .find(|&x| buf[(x, modal_y)].symbol() == ">")
            .expect("modal '>' prompt cell");
        let cursor_x = (0..buf.area.width)
            .find(|&x| buf[(x, modal_y)].symbol() == "▏")
            .expect("modal '▏' cursor cell");
        assert_eq!(buf[(prompt_x, modal_y)].fg, ICE_BLUE);
        assert_eq!(buf[(prompt_x, modal_y)].bg, ACTIVE_BG);
        assert_eq!(buf[(cursor_x, modal_y)].fg, ICE_BLUE);
        assert_eq!(buf[(cursor_x, modal_y)].bg, ACTIVE_BG);

        // 3. Cursor Left, Right, Home, End, Delete, Backspace, and mid-string insertion/paste.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Ignore
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Ignore
        );

        // Move left 4 times (including Repeat): "alpha|.exe" (cursor 5).
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Left, KeyEventKind::Repeat)
            ),
            Action::Redraw
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 5);

        // Insert '2' at cursor -> "alpha2.exe" (cursor 6), verify rendered cursor sits mid-string.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('2'))),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "alpha2.exe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 6);
        let mid_text = buffer_text(&render_to_buffer(&mut state, 80, 24, true));
        assert!(
            mid_text.contains("> alpha2▏.exe"),
            "expected mid-string cursor render:\n{mid_text}"
        );

        // Delete removes '.' at cursor -> "alpha2exe" (cursor stays 6).
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "alpha2exe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 6);

        // Right moves past 'e' -> cursor 7; Backspace removes 'e' -> "alpha2xe" (cursor 6).
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 7);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "alpha2xe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 6);

        // Home jumps to 0; Home/Left at 0 are no-ops; Delete removes 'a' -> "lpha2xe".
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 0);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Ignore);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "lpha2xe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 0);

        // Paste at cursor 0 inserts at start; End jumps to end.
        assert_eq!(
            handle_paste(&mut state, "my_\nignored_second_line"),
            Action::Redraw
        );
        assert_eq!(state.add_modal.as_ref().unwrap().input, "my_lpha2xe");
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 3);
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 10);

        // 4. Wide Unicode / CJK editing and horizontal windowing never panic and keep cursor visible.
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Redraw);
        assert_eq!(state.add_modal.as_ref().unwrap().cursor, 0);
        assert_eq!(
            handle_paste(&mut state, "日本語テストアプリゲーム名前長いパス.exe\nsecond"),
            Action::Redraw
        );
        assert_eq!(
            state.add_modal.as_ref().unwrap().input,
            "日本語テストアプリゲーム名前長いパス.exe"
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(
            state.add_modal.as_ref().unwrap().input,
            "日語テストアプリゲーム名前長いパス.exe"
        );
        let cjk_buf = render_to_buffer(&mut state, 46, 18, true);
        let cjk_text = buffer_text(&cjk_buf);
        assert!(
            cjk_text.contains("日 ▏語") && cjk_text.contains('…'),
            "expected visible cursor and ellipsis on wide CJK modal render:\n{cjk_text}"
        );
    }

    #[test]
    fn empty_include_mode_hint_matches_fail_closed_behavior() {
        let mut state = PickerState::new(
            SplitTunnelConfig {
                mode: SplitTunnelMode::Include,
                apps: Vec::new(),
            },
            sample_apps(),
        );

        let buf = render_to_buffer(&mut state, 80, 24, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("Empty Include protects no apps (check apps below to enable)."),
            "expected fail-closed empty Include hint:\n{text}"
        );
        assert!(
            !text.contains("falls back"),
            "contradictory fallback wording must not appear:\n{text}"
        );

        // Saving empty Include warns with matching fail-closed confirmation notice.
        assert_eq!(handle_key(&mut state, press(KeyCode::Enter)), Action::Redraw);
        assert!(state
            .notice
            .as_deref()
            .is_some_and(|n| n.contains("Empty Include protects no apps")));

        // Checking an app updates the mode hint cleanly.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char(' '))),
            Action::Redraw
        );
        assert_eq!(state.selected_count(), 1);
        let checked_text = buffer_text(&render_to_buffer(&mut state, 80, 24, true));
        assert!(
            checked_text.contains("DPI desync applies ONLY to checked apps."),
            "expected active Include hint once an app is checked:\n{checked_text}"
        );
    }

    #[test]
    fn search_bar_cursor_navigation_editing_paste_and_windowing() {
        let mut state = PickerState::new(SplitTunnelConfig::default(), sample_apps());
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('/'))),
            Action::Redraw
        );
        assert!(state.search_focused);
        assert_eq!(state.search_cursor, 0);

        // Empty search boundary no-ops.
        for code in [
            KeyCode::Left,
            KeyCode::Right,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::Backspace,
            KeyCode::Delete,
        ] {
            assert_eq!(handle_key(&mut state, press(code)), Action::Ignore);
        }
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Ignore);

        // Type "firez" -> cursor 5; Right/End/Delete at end are no-ops.
        for ch in "firez".chars() {
            assert_eq!(
                handle_key(&mut state, press(KeyCode::Char(ch))),
                Action::Redraw
            );
        }
        assert_eq!(state.search_query, "firez");
        assert_eq!(state.search_cursor, 5);
        assert!(state.filtered_indices.is_empty());
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Ignore
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Ignore
        );

        // Left moves to 4 ("fire|z"), Delete removes 'z' -> "fire" (cursor 4, matches Firefox).
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(state.search_cursor, 4);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fire");
        assert_eq!(state.search_cursor, 4);
        assert_eq!(state.filtered_indices.len(), 1);
        assert_eq!(
            state.all_apps[state.filtered_indices[0]].exe_name,
            "firefox.exe"
        );

        // Move Left twice (including Repeat): "fi|re" (cursor 2), verify rendered mid-string cursor.
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Left, KeyEventKind::Repeat)
            ),
            Action::Redraw
        );
        assert_eq!(state.search_cursor, 2);

        let buf = render_to_buffer(&mut state, 80, 24, true);
        let text = buffer_text(&buf);
        let search_y = text
            .lines()
            .position(|l| l.contains("Search: fi▏re"))
            .unwrap_or_else(|| panic!("expected mid-string search cursor:\n{text}")) as u16;
        let cursor_x = (0..buf.area.width)
            .find(|&x| buf[(x, search_y)].symbol() == "▏")
            .expect("search '▏' cursor cell");
        assert_eq!(buf[(cursor_x, search_y)].fg, ICE_BLUE);

        let nc_buf = render_to_buffer(&mut state, 80, 24, false);
        assert_no_rgb_colors(&nc_buf);
        assert!(buffer_text(&nc_buf).contains("Search: fi▏re"));

        // Mid-string char insert ('z') -> "fizre" (cursor 3); Backspace removes 'z' -> "fire" (cursor 2).
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('z'))),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fizre");
        assert_eq!(state.search_cursor, 3);
        assert!(state.filtered_indices.is_empty());
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fire");
        assert_eq!(state.search_cursor, 2);
        assert_eq!(state.filtered_indices.len(), 1);

        // Right (Press + Repeat) walks to end; Home jumps to 0; End jumps back to 4.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Right, KeyEventKind::Repeat)
            ),
            Action::Redraw
        );
        assert_eq!(state.search_cursor, 4);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(state.search_cursor, 0);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Ignore);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Ignore);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Ignore
        );
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Redraw);
        assert_eq!(state.search_cursor, 4);
        assert_eq!(handle_key(&mut state, press(KeyCode::End)), Action::Ignore);

        // Mid-string multiline paste inserts only first non-empty line at search_cursor.
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(state.search_cursor, 2);
        assert_eq!(
            handle_paste(&mut state, "\r\n  xx  \r\nignored_second_line"),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fixxre");
        assert_eq!(state.search_cursor, 4);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Backspace)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(
                &mut state,
                key_with_kind(KeyCode::Backspace, KeyEventKind::Repeat)
            ),
            Action::Redraw
        );
        assert_eq!(state.search_query, "fire");
        assert_eq!(state.search_cursor, 2);
        assert_eq!(state.filtered_indices.len(), 1);

        // Re-focusing '/' puts cursor at end; Ctrl+U from normal mode clears query and resets cursor.
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert!(!state.search_focused);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('/'))),
            Action::Redraw
        );
        assert!(state.search_focused);
        assert_eq!(state.search_cursor, 4);
        assert_eq!(handle_key(&mut state, press(KeyCode::Esc)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Redraw);
        assert!(state.search_query.is_empty());
        assert_eq!(state.search_cursor, 0);

        // Ctrl+U while focused with mid-string cursor clears query and resets cursor to 0.
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Char('/'))),
            Action::Redraw
        );
        assert_eq!(handle_paste(&mut state, "chrome"), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(handle_key(&mut state, press(KeyCode::Left)), Action::Redraw);
        assert_eq!(state.search_cursor, 4);
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Redraw);
        assert!(state.search_query.is_empty());
        assert_eq!(state.search_cursor, 0);
        assert!(state.search_focused);
        assert_eq!(handle_key(&mut state, press_ctrl('u')), Action::Ignore);

        // Wide Unicode / CJK cursor editing and horizontal windowing in main & minimal views.
        assert_eq!(
            handle_paste(&mut state, "日本語テストアプリゲーム名前長いパス\nsecond"),
            Action::Redraw
        );
        assert_eq!(state.search_query, "日本語テストアプリゲーム名前長いパス");
        assert_eq!(state.search_cursor, 18);
        assert_eq!(handle_key(&mut state, press(KeyCode::Home)), Action::Redraw);
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Right)),
            Action::Redraw
        );
        assert_eq!(
            handle_key(&mut state, press(KeyCode::Delete)),
            Action::Redraw
        );
        assert_eq!(state.search_query, "日語テストアプリゲーム名前長いパス");
        assert_eq!(state.search_cursor, 1);

        let cjk_buf = render_to_buffer(&mut state, 46, 18, true);
        let cjk_text = buffer_text(&cjk_buf);
        assert!(
            cjk_text.contains("Search: 日 ▏語")
                && cjk_text.contains('…')
                && cjk_text.contains("0 / 6 apps"),
            "expected visible cursor, ellipsis, and count badge on wide CJK search render:\n{cjk_text}"
        );

        let min_buf = render_to_buffer(&mut state, 14, 5, true);
        let min_text = buffer_text(&min_buf);
        assert!(
            min_text.contains("/日 ▏語") && min_text.contains('…'),
            "expected visible cursor and ellipsis on wide CJK minimal search render:\n{min_text}"
        );
    }

    #[test]
    fn renders_split_tunnel_picker_and_add_modal_in_turkish() {
        let _guard = i18n::push_thread_lang(Some(Lang::Tr));
        let mut state = PickerState::new(
            SplitTunnelConfig {
                mode: SplitTunnelMode::Exclude,
                apps: vec!["discord.exe".to_string()],
            },
            sample_apps(),
        );
        let buf = render_to_buffer(&mut state, 80, 24, true);
        let text = buffer_text(&buf);
        assert!(
            text.contains("vdpi Bölünmüş Tünelleme"),
            "missing TR header:\n{text}"
        );
        assert!(text.contains("1 seçili"), "missing TR count pill:\n{text}");
        assert!(
            text.contains("1 Tüm uygulamalar")
                && text.contains("2 Yalnızca seçililer")
                && text.contains("3 Seçilileri hariç tut"),
            "missing TR mode tabs:\n{text}"
        );
        assert!(text.contains("/ ara"), "missing TR search placeholder:\n{text}");
        assert!(text.contains("uygulama"), "missing TR app count:\n{text}");
        assert!(
            text.contains("● Çalışıyor") && text.contains("Kurulu"),
            "missing TR badges:\n{text}"
        );
        assert!(
            text.contains("enter kaydet"),
            "missing TR footer:\n{text}"
        );

        // Open custom add modal in Turkish.
        state.add_modal = Some(AddModalState::default());
        let modal_buf = render_to_buffer(&mut state, 80, 24, true);
        let modal_text = buffer_text(&modal_buf);
        assert!(
            modal_text.contains("Özel uygulama ekle"),
            "missing TR add modal title:\n{modal_text}"
        );
        assert!(
            modal_text.contains("örn. discord.exe veya firefox"),
            "missing TR add modal hint:\n{modal_text}"
        );
        assert!(
            modal_text.contains("enter ekle") && modal_text.contains("esc iptal"),
            "missing TR add modal footer:\n{modal_text}"
        );
    }
}
