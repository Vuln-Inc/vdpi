use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

mod tui;

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

    let selected = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        if env::var("TERM").as_deref() == Ok("dumb") {
            read_choice(io::stdin().lock(), io::stderr().lock())?
        } else {
            tui::choose(env::var_os("NO_COLOR").is_none())
                .context("running the terminal launcher")?
        }
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
    eprintln!("  Run directly  |  {RUN_NOTICE}");
}

pub fn install_finished(result: &Result<()>) {
    if let Ok(()) = result {
        clear_preference();
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        match result {
            Ok(()) => eprintln!("\n  vdpi is installed and starts automatically."),
            Err(error) => eprintln!("\n  Installation did not finish: {error:#}"),
        }
        eprintln!("  Press Enter to close this window.");
        let _ = io::stdin().read_line(&mut String::new());
    }
}

#[cfg(windows)]
fn has_own_console() -> bool {
    let mut processes = [0; 2];
    // The array is writable for two process IDs for the duration of the call.
    unsafe {
        windows_sys::Win32::System::Console::GetConsoleProcessList(processes.as_mut_ptr(), 2) == 1
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

fn read_choice(mut input: impl BufRead, mut output: impl Write) -> io::Result<Choice> {
    writeln!(output, "\n  vdpi v{}\n", env!("CARGO_PKG_VERSION"))?;
    writeln!(output, "  1  Run directly\n     {RUN_HINT}\n")?;
    writeln!(
        output,
        "  2  Install for automatic startup\n     {INSTALL_HINT}\n"
    )?;
    writeln!(output, "  q  Quit\n")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_reprompts_on_invalid_input_and_eof_cancels() {
        let mut output = Vec::new();
        assert_eq!(
            read_choice(&b"\nno\n2\n"[..], &mut output).unwrap(),
            Choice::Install
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Run directly"));
        assert!(output.contains("Enter 1 to run"));
        assert!(!output.contains('\x1b'));
        assert_eq!(read_choice(&b""[..], Vec::new()).unwrap(), Choice::Cancel);
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
