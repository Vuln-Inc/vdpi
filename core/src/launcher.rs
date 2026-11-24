use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use vdpi::server::REPOSITORY_URL;
use vdpi::service::InstalledInfo;
use vdpi::update::VersionRelation;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tui;

const RUN_NOTICE: &str =
    "vdpi is running without installation. Run `vdpi install` to enable automatic startup.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Run,
    Unattended,
    Install,
    Update,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MenuItem {
    pub choice: Choice,
    pub title: String,
    pub hint: String,
}

impl MenuItem {
    fn new(choice: Choice, title: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            choice,
            title: title.into(),
            hint: hint.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LauncherMenu {
    pub status_line: Option<String>,
    pub items: Vec<MenuItem>,
}

pub(super) fn build_menu(installed: Option<&InstalledInfo>) -> LauncherMenu {
    match installed {
        None => LauncherMenu {
            status_line: None,
            items: vec![
                MenuItem::new(
                    Choice::Run,
                    "Run directly",
                    "Active while this terminal is open.",
                ),
                MenuItem::new(
                    Choice::Install,
                    "Install for automatic startup",
                    "Runs in the background after you close it.",
                ),
                MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything."),
            ],
        },
        Some(info) => match info.relation {
            VersionRelation::Newer => {
                let old = info.installed_version.as_deref().unwrap_or("unknown");
                let new = info.current_version;
                LauncherMenu {
                    status_line: Some(format!("Installed: v{old}  ->  This binary: v{new}")),
                    items: vec![
                        MenuItem::new(
                            Choice::Install,
                            format!("Update installed vdpi (v{old} -> v{new})"),
                            "Replaces the installed service and restarts cleanly.",
                        ),
                        MenuItem::new(
                            Choice::Run,
                            "Run directly without updating",
                            "Active while this terminal is open.",
                        ),
                        MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything."),
                    ],
                }
            }
            VersionRelation::Same => {
                let ver = info.current_version;
                LauncherMenu {
                    status_line: Some(format!("Installed: v{ver} (already installed)")),
                    items: vec![
                        MenuItem::new(
                            Choice::Update,
                            "Check for updates online",
                            "Checks GitHub Releases and updates automatically.",
                        ),
                        MenuItem::new(
                            Choice::Install,
                            "Reinstall / repair service",
                            "Rewrites the background service and restarts it.",
                        ),
                        MenuItem::new(
                            Choice::Run,
                            "Run directly",
                            "Active while this terminal is open.",
                        ),
                        MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything."),
                    ],
                }
            }
            VersionRelation::Older => {
                let inst = info.installed_version.as_deref().unwrap_or("newer");
                let cur = info.current_version;
                LauncherMenu {
                    status_line: Some(format!("Installed: v{inst} (newer than this v{cur})")),
                    items: vec![
                        MenuItem::new(
                            Choice::Run,
                            "Run directly",
                            format!("Keep installed v{inst} untouched."),
                        ),
                        MenuItem::new(
                            Choice::Install,
                            format!("Downgrade installed vdpi (v{inst} -> v{cur})"),
                            format!("Replaces installed v{inst} with this older v{cur} binary."),
                        ),
                        MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything."),
                    ],
                }
            }
            VersionRelation::Unknown => {
                let cur = info.current_version;
                LauncherMenu {
                    status_line: Some("Installed vdpi detected (version unreadable)".to_string()),
                    items: vec![
                        MenuItem::new(
                            Choice::Install,
                            format!("Update / repair installed vdpi (to v{cur})"),
                            "Replaces the installed service and restarts cleanly.",
                        ),
                        MenuItem::new(
                            Choice::Run,
                            "Run directly",
                            "Active while this terminal is open.",
                        ),
                        MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything."),
                    ],
                }
            }
        },
    }
}

fn should_auto_run(
    explicit: bool,
    marker_path: Option<&Path>,
    installed: Option<&InstalledInfo>,
) -> bool {
    !explicit
        && marker_path.is_some_and(Path::is_file)
        && !matches!(installed.map(|i| i.relation), Some(VersionRelation::Newer))
}

pub fn choose(explicit: bool, installed: Option<&InstalledInfo>) -> Result<Choice> {
    let state = preference_path();
    if should_auto_run(explicit, state.as_deref(), installed) {
        return Ok(Choice::Run);
    }

    let menu = build_menu(installed);
    let selected = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if env::var("TERM").as_deref() == Ok("dumb") {
                read_choice(io::stdin().lock(), io::stderr().lock(), &menu)?
            } else {
                tui::choose(env::var_os("NO_COLOR").is_none(), &menu)
                    .context("running the terminal launcher")?
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            read_choice(io::stdin().lock(), io::stderr().lock(), &menu)?
        }
    } else if explicit {
        anyhow::bail!("no interactive launcher available; use `vdpi start` or `vdpi install`");
    } else {
        // Noninteractive bare invocations retain the existing foreground behavior.
        return Ok(Choice::Unattended);
    };

    if selected == Choice::Run {
        if let Err(e) = state
            .context("could not locate the vdpi executable directory")
            .and_then(|p| remember_run(&p))
        {
            eprintln!("vdpi could not save your choice: {e:#}");
        }
    }
    Ok(selected)
}

pub fn print_run_notice() {
    eprintln!("  Run directly  |  {RUN_NOTICE}");
    eprintln!("  GitHub        |  {REPOSITORY_URL}");
}

pub fn install_finished(result: &Result<()>, installed_before: Option<&InstalledInfo>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(not(windows))]
    let _ = installed_before;
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        match result {
            Ok(()) => {
                eprintln!("\n  {}", install_success_message(installed_before));
                eprintln!("  GitHub: {REPOSITORY_URL}");
            }
            Err(error) => eprintln!("\n  Installation did not finish: {error:#}"),
        }
        eprintln!("  Press Enter to close this window.");
        let _ = io::stdin().read_line(&mut String::new());
    }
}

#[cfg(any(windows, test))]
fn install_success_message(installed_before: Option<&InstalledInfo>) -> String {
    match installed_before {
        Some(info) if info.relation == VersionRelation::Newer => {
            format!("vdpi updated to v{} and restarted.", info.current_version)
        }
        _ => "vdpi is installed and starts automatically.".to_string(),
    }
}

pub fn update_finished(result: &Result<()>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        match result {
            Ok(()) => {
                eprintln!("\n  Update completed.");
                eprintln!("  GitHub: {REPOSITORY_URL}");
            }
            Err(error) => eprintln!("\n  Update did not finish: {error:#}"),
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
    Some(env::current_exe().ok()?.parent()?.join("run-directly"))
}

fn remember_run(path: &Path) -> Result<()> {
    // An empty marker is sufficient; create_new publishes it atomically.
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_file() => Ok(()),
        Err(e) => Err(e).with_context(|| format!("saving {}", path.display())),
    }
}

fn read_choice(
    mut input: impl BufRead,
    mut output: impl Write,
    menu: &LauncherMenu,
) -> io::Result<Choice> {
    if menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }
    writeln!(
        output,
        "\n  vdpi v{}  |  {REPOSITORY_URL}",
        env!("CARGO_PKG_VERSION")
    )?;
    if let Some(status) = &menu.status_line {
        writeln!(output, "  {status}")?;
    }
    writeln!(output)?;

    for (index, item) in menu.items.iter().enumerate() {
        writeln!(
            output,
            "  {}  {}\n     {}\n",
            index + 1,
            item.title,
            item.hint
        )?;
    }

    let count = menu.items.len();
    let choices: Vec<String> = (1..=count)
        .map(|n| n.to_string())
        .chain(std::iter::once("q".to_string()))
        .collect();
    let prompt_choices = choices.join(" / ");

    let mut answer = String::new();
    loop {
        write!(output, "  Choose [{prompt_choices}]: ")?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(Choice::Cancel);
        }
        let trimmed = answer.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            return Ok(Choice::Cancel);
        }
        if let Some(item) = trimmed
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| menu.items.get(i))
        {
            return Ok(item.choice);
        }
        writeln!(output, "  Enter a number from 1 to {count}, or q to quit.")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn build_menu_fresh_install() {
        let menu = build_menu(None);
        assert_eq!(menu.status_line, None);
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].choice, Choice::Run);
        assert_eq!(menu.items[0].title, "Run directly");
        assert_eq!(menu.items[0].hint, "Active while this terminal is open.");
        assert_eq!(menu.items[1].choice, Choice::Install);
        assert_eq!(menu.items[1].title, "Install for automatic startup");
        assert_eq!(
            menu.items[1].hint,
            "Runs in the background after you close it."
        );
        assert_eq!(menu.items[2].choice, Choice::Cancel);
        assert_eq!(menu.items[2].title, "Quit");
        assert_eq!(menu.items[2].hint, "Exit without changing anything.");
    }

    #[test]
    fn build_menu_newer_defaults_to_update() {
        let info = sample_info(Some("0.3.0"), "0.4.0", VersionRelation::Newer);
        let menu = build_menu(Some(&info));
        assert_eq!(
            menu.status_line.as_deref(),
            Some("Installed: v0.3.0  ->  This binary: v0.4.0")
        );
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].choice, Choice::Install);
        assert_eq!(
            menu.items[0].title,
            "Update installed vdpi (v0.3.0 -> v0.4.0)"
        );
        assert_eq!(
            menu.items[0].hint,
            "Replaces the installed service and restarts cleanly."
        );
        assert_eq!(menu.items[1].choice, Choice::Run);
        assert_eq!(menu.items[1].title, "Run directly without updating");
        assert_eq!(menu.items[2].choice, Choice::Cancel);

        let fallback = sample_info(None, "0.4.0", VersionRelation::Newer);
        let fallback_menu = build_menu(Some(&fallback));
        assert_eq!(
            fallback_menu.status_line.as_deref(),
            Some("Installed: vunknown  ->  This binary: v0.4.0")
        );
    }

    #[test]
    fn build_menu_same_offers_online_update_and_repair() {
        let info = sample_info(Some("0.4.0"), "0.4.0", VersionRelation::Same);
        let menu = build_menu(Some(&info));
        assert_eq!(
            menu.status_line.as_deref(),
            Some("Installed: v0.4.0 (already installed)")
        );
        assert_eq!(menu.items.len(), 4);
        assert_eq!(menu.items[0].choice, Choice::Update);
        assert_eq!(menu.items[0].title, "Check for updates online");
        assert_eq!(
            menu.items[0].hint,
            "Checks GitHub Releases and updates automatically."
        );
        assert_eq!(menu.items[1].choice, Choice::Install);
        assert_eq!(menu.items[1].title, "Reinstall / repair service");
        assert_eq!(
            menu.items[1].hint,
            "Rewrites the background service and restarts it."
        );
        assert_eq!(menu.items[2].choice, Choice::Run);
        assert_eq!(menu.items[2].title, "Run directly");
        assert_eq!(menu.items[3].choice, Choice::Cancel);
    }

    #[test]
    fn build_menu_older_defaults_to_run_with_downgrade_option() {
        let info = sample_info(Some("0.5.0"), "0.4.0", VersionRelation::Older);
        let menu = build_menu(Some(&info));
        assert_eq!(
            menu.status_line.as_deref(),
            Some("Installed: v0.5.0 (newer than this v0.4.0)")
        );
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].choice, Choice::Run);
        assert_eq!(menu.items[0].title, "Run directly");
        assert_eq!(menu.items[0].hint, "Keep installed v0.5.0 untouched.");
        assert_eq!(menu.items[1].choice, Choice::Install);
        assert_eq!(
            menu.items[1].title,
            "Downgrade installed vdpi (v0.5.0 -> v0.4.0)"
        );
        assert_eq!(
            menu.items[1].hint,
            "Replaces installed v0.5.0 with this older v0.4.0 binary."
        );
        assert_eq!(menu.items[2].choice, Choice::Cancel);

        let fallback = sample_info(None, "0.4.0", VersionRelation::Older);
        let fallback_menu = build_menu(Some(&fallback));
        assert_eq!(
            fallback_menu.status_line.as_deref(),
            Some("Installed: vnewer (newer than this v0.4.0)")
        );
    }

    #[test]
    fn build_menu_unknown_offers_repair() {
        let info = sample_info(None, "0.4.0", VersionRelation::Unknown);
        let menu = build_menu(Some(&info));
        assert_eq!(
            menu.status_line.as_deref(),
            Some("Installed vdpi detected (version unreadable)")
        );
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].choice, Choice::Install);
        assert_eq!(
            menu.items[0].title,
            "Update / repair installed vdpi (to v0.4.0)"
        );
        assert_eq!(
            menu.items[0].hint,
            "Replaces the installed service and restarts cleanly."
        );
        assert_eq!(menu.items[1].choice, Choice::Run);
        assert_eq!(menu.items[1].title, "Run directly");
        assert_eq!(menu.items[2].choice, Choice::Cancel);
    }

    #[test]
    fn console_reprompts_on_invalid_input_renders_status_and_handles_dynamic_menus() {
        let fresh = build_menu(None);
        let mut output = Vec::new();
        assert_eq!(
            read_choice(&b"\nno\n0\n9\n2\n"[..], &mut output, &fresh).unwrap(),
            Choice::Install
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Run directly"));
        assert!(output.contains("Install for automatic startup"));
        assert!(output.contains("Enter a number from 1 to 3, or q to quit."));
        assert!(output.contains("Choose [1 / 2 / 3 / q]: "));
        assert!(output.contains(REPOSITORY_URL));
        assert!(!output.contains('\x1b'));
        assert_eq!(
            read_choice(&b""[..], Vec::new(), &fresh).unwrap(),
            Choice::Cancel
        );

        let newer_info = sample_info(Some("0.3.0"), "0.4.0", VersionRelation::Newer);
        let newer = build_menu(Some(&newer_info));
        let mut newer_out = Vec::new();
        assert_eq!(
            read_choice(&b"1\n"[..], &mut newer_out, &newer).unwrap(),
            Choice::Install
        );
        let newer_out = String::from_utf8(newer_out).unwrap();
        assert!(newer_out.contains("Installed: v0.3.0  ->  This binary: v0.4.0"));
        assert!(newer_out.contains("Update installed vdpi (v0.3.0 -> v0.4.0)"));
        assert!(!newer_out.contains('\x1b'));

        let same_info = sample_info(Some("0.4.0"), "0.4.0", VersionRelation::Same);
        let same = build_menu(Some(&same_info));
        let mut same_out = Vec::new();
        assert_eq!(
            read_choice(&b"1\n"[..], &mut same_out, &same).unwrap(),
            Choice::Update
        );
        let same_out = String::from_utf8(same_out).unwrap();
        assert!(same_out.contains("Installed: v0.4.0 (already installed)"));
        assert!(same_out.contains("Choose [1 / 2 / 3 / 4 / q]: "));
        assert_eq!(
            read_choice(&b"2\n"[..], Vec::new(), &same).unwrap(),
            Choice::Install
        );
        assert_eq!(
            read_choice(&b"3\n"[..], Vec::new(), &same).unwrap(),
            Choice::Run
        );
        assert_eq!(
            read_choice(&b"4\n"[..], Vec::new(), &same).unwrap(),
            Choice::Cancel
        );
        assert_eq!(
            read_choice(&b"Q\n"[..], Vec::new(), &same).unwrap(),
            Choice::Cancel
        );
    }

    #[test]
    fn auto_run_marker_bypasses_for_newer_binary_and_explicit_launcher() {
        let dir =
            env::temp_dir().join(format!("vdpi-launcher-autorun-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("run-directly");
        remember_run(&marker).unwrap();

        let newer = sample_info(Some("0.3.0"), "0.4.0", VersionRelation::Newer);
        let same = sample_info(Some("0.4.0"), "0.4.0", VersionRelation::Same);
        let older = sample_info(Some("0.5.0"), "0.4.0", VersionRelation::Older);
        let unknown = sample_info(None, "0.4.0", VersionRelation::Unknown);

        assert!(should_auto_run(false, Some(&marker), None));
        assert!(should_auto_run(false, Some(&marker), Some(&same)));
        assert!(should_auto_run(false, Some(&marker), Some(&older)));
        assert!(should_auto_run(false, Some(&marker), Some(&unknown)));
        assert!(!should_auto_run(false, Some(&marker), Some(&newer)));
        assert!(!should_auto_run(true, Some(&marker), None));
        assert!(!should_auto_run(false, None, None));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_success_message_distinguishes_update_from_fresh_install() {
        let newer = sample_info(Some("0.3.0"), "0.4.0", VersionRelation::Newer);
        let same = sample_info(Some("0.4.0"), "0.4.0", VersionRelation::Same);
        let older = sample_info(Some("0.5.0"), "0.4.0", VersionRelation::Older);
        let unknown = sample_info(None, "0.4.0", VersionRelation::Unknown);

        assert_eq!(
            install_success_message(Some(&newer)),
            "vdpi updated to v0.4.0 and restarted."
        );
        assert_eq!(
            install_success_message(None),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&same)),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&older)),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&unknown)),
            "vdpi is installed and starts automatically."
        );
    }

    #[test]
    fn run_preference_survives_reopening_and_repeat_saves() {
        let dir = env::temp_dir().join(format!("vdpi-launcher-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("run-directly");
        let result = (|| {
            remember_run(&marker)?;
            remember_run(&marker)?;
            Ok::<_, anyhow::Error>(marker.is_file())
        })();
        fs::remove_dir_all(dir).unwrap();
        assert!(result.unwrap());
    }
}
