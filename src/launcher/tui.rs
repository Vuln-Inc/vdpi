use super::Choice;
use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::style::{
    Attribute, Color, Print, ResetColor, SetAttribute, SetBackgroundColor, SetForegroundColor,
};
use crossterm::terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::{execute, queue};
use std::io::{self, Stdout, Write};

const ACTIONS: [(Choice, &str, &str); 3] = [
    (
        Choice::Run,
        "Run directly",
        "Active while this terminal is open.",
    ),
    (
        Choice::Install,
        "Install for automatic startup",
        "Runs in the background after you close it.",
    ),
    (Choice::Cancel, "Quit", "Exit without changing anything."),
];

// Slate background, cool white, muted steel, and a pale blue active route.
const PANEL: Color = Color::AnsiValue(235);
const ACTIVE: Color = Color::AnsiValue(24);
const TEXT: Color = Color::AnsiValue(255);
const MUTED: Color = Color::AnsiValue(249);
const ROUTE: Color = Color::AnsiValue(117);

pub(super) fn choose(color: bool) -> io::Result<Choice> {
    let mut screen = Screen::open()?;
    let mut selected = 0;
    loop {
        let (width, height) = terminal::size()?;
        draw(&mut screen.output, width, height, selected, color)?;
        loop {
            match event::read()? {
                Event::Resize(..) => break,
                Event::Key(key) => match handle_key(&mut selected, key) {
                    Action::Redraw => break,
                    Action::Finish(choice) => return Ok(choice),
                    Action::Ignore => {}
                },
                _ => {}
            }
        }
    }
}

struct Screen {
    output: Stdout,
}

impl Screen {
    fn open() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        let mut screen = Self {
            output: io::stdout(),
        };
        execute!(screen.output, EnterAlternateScreen, Hide)?;
        Ok(screen)
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(
            self.output,
            ResetColor,
            SetAttribute(Attribute::Reset),
            Show,
            LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Redraw,
    Finish(Choice),
    Ignore,
}

fn handle_key(selected: &mut usize, key: KeyEvent) -> Action {
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
            *selected = (*selected + ACTIONS.len() - 1) % ACTIONS.len()
        }
        KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
            *selected = (*selected + 1) % ACTIONS.len()
        }
        KeyCode::Home => *selected = 0,
        KeyCode::End => *selected = ACTIONS.len() - 1,
        _ if key.kind != KeyEventKind::Press => return Action::Ignore,
        KeyCode::Enter => return Action::Finish(ACTIONS[*selected].0),
        KeyCode::Char('1') => return Action::Finish(Choice::Run),
        KeyCode::Char('2') => return Action::Finish(Choice::Install),
        KeyCode::Esc | KeyCode::Char('q' | 'Q') => return Action::Finish(Choice::Cancel),
        _ => return Action::Ignore,
    }
    Action::Redraw
}

struct Frame<'a, W> {
    output: &'a mut W,
    color: bool,
    width: u16,
    height: u16,
}

impl<W: Write> Frame<'_, W> {
    fn line(
        &mut self,
        x: u16,
        y: u16,
        text: &str,
        fg: Color,
        bg: Color,
        bold: bool,
    ) -> io::Result<()> {
        if x >= self.width || y >= self.height {
            return Ok(());
        }
        // All launcher copy uses single-column characters. Leave the last column free
        // so writing into the bottom row never scrolls the screen.
        let clipped: String = text.chars().take(usize::from(self.width - x)).collect();
        queue!(self.output, MoveTo(x, y), SetAttribute(Attribute::Reset))?;
        if self.color {
            queue!(self.output, SetForegroundColor(fg), SetBackgroundColor(bg))?;
        }
        if bold {
            queue!(self.output, SetAttribute(Attribute::Bold))?;
        }
        queue!(self.output, Print(clipped))
    }
}

fn draw(
    output: &mut impl Write,
    width: u16,
    height: u16,
    selected: usize,
    color: bool,
) -> io::Result<()> {
    queue!(
        output,
        ResetColor,
        SetAttribute(Attribute::Reset),
        Clear(ClearType::All)
    )?;
    let width = width.saturating_sub(1);
    let mut frame = Frame {
        output,
        color,
        width,
        height,
    };
    if width >= 74 && height >= 20 {
        draw_panel(&mut frame, selected)?;
    } else {
        draw_compact(&mut frame, selected)?;
    }
    queue!(frame.output, ResetColor, SetAttribute(Attribute::Reset))?;
    frame.output.flush()
}

fn draw_panel(frame: &mut Frame<'_, impl Write>, selected: usize) -> io::Result<()> {
    let width = frame.width.min(90);
    let x = (frame.width - width) / 2;
    let y = (frame.height - 20) / 2;
    let padding = " ".repeat(usize::from(width));
    let rule = "-".repeat(usize::from(width - 6));
    for row in 0..20 {
        frame.line(x, y + row, &padding, TEXT, PANEL, false)?;
    }
    frame.line(x + 3, y + 2, "v d p i   /   startup", ROUTE, PANEL, true)?;
    let version = concat!("v", env!("CARGO_PKG_VERSION"));
    frame.line(
        x + width - 3 - version.len() as u16,
        y + 2,
        version,
        MUTED,
        PANEL,
        false,
    )?;
    frame.line(x + 3, y + 4, &rule, MUTED, PANEL, false)?;

    let menu_width = width - 27;
    for (index, (_, title, note)) in ACTIONS.iter().enumerate() {
        let row = y + 6 + index as u16 * 3;
        let focused = index == selected;
        let bg = if focused { ACTIVE } else { PANEL };
        let marker = if focused { ">" } else { " " };
        let label = format!(" {marker}  {title}");
        frame.line(
            x + 2,
            row,
            &format!("{label:<n$}", n = usize::from(menu_width - 3)),
            TEXT,
            bg,
            focused,
        )?;
        frame.line(x + 7, row + 1, note, MUTED, PANEL, false)?;
    }

    let route = x + width - 24;
    let (last, caption) = match ACTIONS[selected].0 {
        Choice::Run => ("Current session", "Remembers this choice"),
        Choice::Install => ("Background service", "Starts automatically"),
        _ => ("No proxy started", "No settings changed"),
    };
    frame.line(route, y + 6, "Local route", ROUTE, PANEL, true)?;
    frame.line(route, y + 8, "o  Your apps", TEXT, PANEL, false)?;
    frame.line(route, y + 9, "|", MUTED, PANEL, false)?;
    frame.line(
        route,
        y + 10,
        if selected == 2 { "x  vdpi" } else { "o  vdpi" },
        ROUTE,
        PANEL,
        true,
    )?;
    frame.line(route, y + 11, "|", MUTED, PANEL, false)?;
    frame.line(route, y + 12, &format!("o  {last}"), TEXT, PANEL, false)?;
    frame.line(route, y + 14, caption, MUTED, PANEL, false)?;
    frame.line(x + 3, y + 16, &rule, MUTED, PANEL, false)?;
    frame.line(
        x + 3,
        y + 18,
        "Up/Down  Move     Enter  Select     Esc  Quit",
        MUTED,
        PANEL,
        false,
    )
}

fn draw_compact(frame: &mut Frame<'_, impl Write>, selected: usize) -> io::Result<()> {
    if frame.height < 7 || frame.width < 22 {
        return frame.line(0, 0, "1 Run  2 Install  Q Quit", ROUTE, PANEL, true);
    }
    frame.line(
        1,
        0,
        concat!("vdpi / startup  v", env!("CARGO_PKG_VERSION")),
        ROUTE,
        PANEL,
        true,
    )?;
    let roomy = frame.height >= 12 && frame.width >= 40;
    let step = if roomy { 3 } else { 1 };
    for (index, (_, title, note)) in ACTIONS.iter().enumerate() {
        let y = 2 + index as u16 * step;
        let focused = index == selected;
        let marker = if focused { ">" } else { " " };
        frame.line(
            1,
            y,
            &format!("{marker} {title}"),
            TEXT,
            if focused { ACTIVE } else { PANEL },
            focused,
        )?;
        if roomy {
            frame.line(3, y + 1, note, MUTED, PANEL, false)?;
        }
    }
    frame.line(
        1,
        frame.height - 1,
        "Enter Select  Esc Quit  1/2 Run/Install",
        MUTED,
        PANEL,
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyboard_wraps_and_ignores_held_or_released_confirmation() {
        let mut selected = 0;
        let key = |code| KeyEvent::new(code, KeyModifiers::NONE);
        assert_eq!(handle_key(&mut selected, key(KeyCode::Up)), Action::Redraw);
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Enter)),
            Action::Finish(Choice::Cancel)
        );
        for kind in [KeyEventKind::Repeat, KeyEventKind::Release] {
            assert_eq!(
                handle_key(
                    &mut selected,
                    KeyEvent::new_with_kind(KeyCode::Char('2'), KeyModifiers::NONE, kind)
                ),
                Action::Ignore
            );
        }
        assert_eq!(
            handle_key(&mut selected, key(KeyCode::Char('2'))),
            Action::Finish(Choice::Install)
        );
    }
}
