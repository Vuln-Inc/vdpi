use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

#[cfg(windows)]
mod windows;

const TITLE: &str = "Run or install vdpi";
const RUN_HINT: &str = "Keep vdpi open to use it. This choice is remembered.";
const INSTALL_HINT: &str = "Install vdpi to start automatically in the background.";
const RUN_NOTICE: &str =
    "vdpi is running without installation. Run `vdpi install` to enable automatic startup.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Run,
    Unattended,
    Install,
    Cancel,
}

pub fn choose(explicit: bool) -> Result<Choice> {
    let state = preference_path();
    if !explicit && state.as_deref().is_some_and(Path::is_file) {
        return Ok(Choice::Run);
    }

    let terminal = io::stdin().is_terminal() && io::stderr().is_terminal();
    #[cfg(windows)]
    let desktop_first = windows::has_own_console();
    #[cfg(not(windows))]
    let desktop_first = false;

    let selected = if terminal && !desktop_first {
        console_choice()?
    } else if let Some(choice) = desktop_choice(explicit || desktop_first)? {
        choice
    } else if terminal {
        console_choice()?
    } else if explicit {
        anyhow::bail!("no interactive launcher available; use `vdpi start` or `vdpi install`");
    } else {
        // Noninteractive bare invocations retain the existing foreground behavior.
        return Ok(Choice::Unattended);
    };

    if selected == Choice::Run {
        if let Err(e) = state
            .context("could not locate the per-user launcher directory")
            .and_then(|p| remember_run(&p))
        {
            eprintln!("vdpi could not save your choice: {e:#}");
        }
    }
    Ok(selected)
}

pub fn print_run_notice() {
    let (amber, reset) = if use_color() {
        ("\x1b[33m", "\x1b[0m")
    } else {
        ("", "")
    };
    eprintln!("  {amber}Run directly{reset}  |  {RUN_NOTICE}");
}

pub fn install_finished(result: &Result<()>) {
    if let Ok(()) = result {
        clear_preference();
    }
    #[cfg(windows)]
    if windows::has_own_console() {
        windows::install_finished(result);
    }
}

pub fn clear_preference() {
    if let Some(path) = preference_path() {
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != io::ErrorKind::NotFound {
                eprintln!("vdpi could not clear the previous run-only choice: {e}");
            }
        }
    }
}

fn preference_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let base = env::var_os("LOCALAPPDATA")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = vdpi::service::home_dir()
        .ok()
        .map(|p| p.join("Library/Application Support"));
    #[cfg(not(any(windows, target_os = "macos")))]
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| vdpi::service::home_dir().ok().map(|p| p.join(".config")));
    base.map(|p| p.join("vdpi").join("run-directly"))
}

fn remember_run(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("launcher preference has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    // An empty marker is sufficient; create_new publishes it atomically.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_file() => Ok(()),
        Err(e) => Err(e).with_context(|| format!("saving {}", path.display())),
    }
}

fn use_color() -> bool {
    io::stderr().is_terminal()
        && env::var_os("NO_COLOR").is_none()
        && env::var("TERM").as_deref() != Ok("dumb")
        && enable_terminal_color()
}

#[cfg(windows)]
fn enable_terminal_color() -> bool {
    windows::enable_terminal_color()
}

#[cfg(not(windows))]
fn enable_terminal_color() -> bool {
    true
}

fn console_choice() -> Result<Choice> {
    let color = use_color();
    read_choice(io::stdin().lock(), io::stderr().lock(), color).context("reading launcher choice")
}

fn read_choice(mut input: impl BufRead, mut output: impl Write, color: bool) -> io::Result<Choice> {
    let (teal, dim, reset) = if color {
        ("\x1b[1;36m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "")
    };
    writeln!(
        output,
        "\n  {teal}vdpi{reset}  {dim}v{}{reset}",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(
        output,
        "  {dim}--------------------------------------------{reset}\n"
    )?;
    writeln!(output, "  {teal}1{reset}  Run directly\n     {RUN_HINT}\n")?;
    writeln!(
        output,
        "  {teal}2{reset}  Install for automatic startup\n     {INSTALL_HINT}\n"
    )?;
    writeln!(output, "  {teal}q{reset}  Quit\n")?;
    let mut answer = String::new();
    loop {
        write!(output, "  Choose [1 / 2 / q]: ")?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(Choice::Cancel);
        }
        match answer.trim() {
            "1" => return Ok(Choice::Run),
            "2" => return Ok(Choice::Install),
            "q" | "Q" => return Ok(Choice::Cancel),
            _ => writeln!(output, "  Enter 1 to run, 2 to install, or q to quit.")?,
        }
    }
}

#[cfg(windows)]
fn desktop_choice(allowed: bool) -> Result<Option<Choice>> {
    Ok(if allowed {
        windows::desktop_choice()
    } else {
        None
    })
}

#[cfg(target_os = "macos")]
fn desktop_choice(_: bool) -> Result<Option<Choice>> {
    if env::var_os("SSH_CONNECTION").is_some() || env::var_os("CI").is_some() {
        return Ok(None);
    }
    let script = format!(
        "button returned of (display alert \"{TITLE}\" message \"{RUN_HINT}\\n{INSTALL_HINT}\" buttons {{\"Cancel\", \"Run directly\", \"Install\"}} default button \"Run directly\" cancel button \"Cancel\")"
    );
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()?;
    Ok(if output.status.success() {
        match String::from_utf8_lossy(&output.stdout).trim() {
            "Run directly" => Some(Choice::Run),
            "Install" => Some(Choice::Install),
            _ => None,
        }
    } else if String::from_utf8_lossy(&output.stderr).contains("(-128)") {
        Some(Choice::Cancel)
    } else {
        None
    })
}

#[cfg(target_os = "linux")]
fn desktop_choice(_: bool) -> Result<Option<Choice>> {
    if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
        return Ok(None);
    }
    let text = format!("{RUN_HINT}\n{INSTALL_HINT}");
    let output = match std::process::Command::new("zenity")
        .args([
            "--question",
            "--title",
            TITLE,
            "--text",
            &text,
            "--ok-label=Run directly",
            "--cancel-label=Cancel",
            "--extra-button=Install",
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("opening the desktop launcher"),
    };
    Ok(
        if String::from_utf8_lossy(&output.stdout).trim() == "Install" {
            Some(Choice::Install)
        } else if output.status.success() {
            Some(Choice::Run)
        } else if output.status.code() == Some(1) {
            Some(Choice::Cancel)
        } else {
            None
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_reprompts_on_invalid_input_and_eof_cancels() {
        let mut output = Vec::new();
        assert_eq!(
            read_choice(&b"\nno\n2\n"[..], &mut output, false).unwrap(),
            Choice::Install
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Run directly"));
        assert!(output.contains("Enter 1 to run"));
        assert!(!output.contains('\x1b'));
        assert_eq!(
            read_choice(&b""[..], Vec::new(), false).unwrap(),
            Choice::Cancel
        );
    }

    #[test]
    fn run_preference_survives_reopening_and_repeat_saves() {
        let dir = env::temp_dir().join(format!("vdpi-launcher-test-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("vdpi").join("run-directly");
        let result = (|| {
            remember_run(&marker)?;
            remember_run(&marker)?;
            Ok::<_, anyhow::Error>(marker.is_file())
        })();
        fs::remove_dir_all(dir).unwrap();
        assert!(result.unwrap());
    }
}
