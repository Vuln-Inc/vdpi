use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use vdpi::server::REPOSITORY_URL;
use vdpi::service::{ControlCenterStatus, InstalledInfo, LiveEngineStatus, ServiceState};
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
    PauseService,
    ResumeService,
    Doctor,
    Uninstall,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub(super) enum StatusTone {
    Active,  // emerald (service running / DPI active)
    Accent,  // ice-blue (update available)
    Warning, // amber (service paused / downgrade / unreadable)
    Neutral, // muted steel (not installed / offline)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatusRow {
    pub label: String,
    pub value: String,
    #[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
    pub tone: StatusTone,
}

impl StatusRow {
    fn new(label: impl Into<String>, value: impl Into<String>, tone: StatusTone) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            tone,
        }
    }
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
    pub status_rows: Vec<StatusRow>,
    pub notice: Option<String>,
    pub items: Vec<MenuItem>,
}

fn format_mode_label(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("combo") {
        "Combo"
    } else if trimmed.eq_ignore_ascii_case("tls-record") || trimmed.eq_ignore_ascii_case("tlsrec") {
        "TLS Record"
    } else if trimmed.eq_ignore_ascii_case("fragment") || trimmed.eq_ignore_ascii_case("chunk") {
        "Fragment"
    } else if trimmed.eq_ignore_ascii_case("split") {
        "Split"
    } else {
        trimmed
    }
}

fn build_service_status_row(status: &ControlCenterStatus) -> StatusRow {
    match (status.service_state, status.installed.as_ref()) {
        (ServiceState::NotInstalled, None) => {
            StatusRow::new("Service", "Not installed", StatusTone::Neutral)
        }
        (ServiceState::NotInstalled, Some(info)) => {
            let value = match info.installed_version.as_deref() {
                Some(ver) => format!("Installed v{ver} (service not registered)"),
                None => "Installed (version unreadable, service not registered)".to_string(),
            };
            StatusRow::new("Service", value, StatusTone::Warning)
        }
        (ServiceState::Running, Some(info)) => match info.relation {
            VersionRelation::Newer => {
                let old = info.installed_version.as_deref().unwrap_or("unknown");
                let new = info.current_version;
                StatusRow::new(
                    "Service",
                    format!("Running · v{old} -> v{new} update ready"),
                    StatusTone::Accent,
                )
            }
            VersionRelation::Same => StatusRow::new(
                "Service",
                format!("Running · v{}", info.current_version),
                StatusTone::Active,
            ),
            VersionRelation::Older => {
                let inst = info.installed_version.as_deref().unwrap_or("newer");
                let cur = info.current_version;
                StatusRow::new(
                    "Service",
                    format!("Running · v{inst} (newer than this v{cur})"),
                    StatusTone::Warning,
                )
            }
            VersionRelation::Unknown => StatusRow::new(
                "Service",
                "Running · version unreadable",
                StatusTone::Warning,
            ),
        },
        (ServiceState::Running, None) => {
            let value = match status
                .live_engine
                .as_ref()
                .and_then(|live| live.version.as_deref())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                Some(ver) => format!("Running · v{}", ver.trim_start_matches(['v', 'V'])),
                None => "Running".to_string(),
            };
            StatusRow::new("Service", value, StatusTone::Active)
        }
        (ServiceState::Stopped, Some(info)) => match info.relation {
            VersionRelation::Newer => {
                let old = info.installed_version.as_deref().unwrap_or("unknown");
                let new = info.current_version;
                StatusRow::new(
                    "Service",
                    format!("Paused · v{old} -> v{new} update ready"),
                    StatusTone::Accent,
                )
            }
            VersionRelation::Same => StatusRow::new(
                "Service",
                format!("Paused · v{} (temporarily stopped)", info.current_version),
                StatusTone::Warning,
            ),
            VersionRelation::Older => {
                let inst = info.installed_version.as_deref().unwrap_or("newer");
                let cur = info.current_version;
                StatusRow::new(
                    "Service",
                    format!("Paused · v{inst} (newer than this v{cur})"),
                    StatusTone::Warning,
                )
            }
            VersionRelation::Unknown => StatusRow::new(
                "Service",
                "Paused · version unreadable (temporarily stopped)",
                StatusTone::Warning,
            ),
        },
        (ServiceState::Stopped, None) => StatusRow::new(
            "Service",
            "Paused (temporarily stopped)",
            StatusTone::Warning,
        ),
    }
}

fn build_anti_dpi_row(live: &LiveEngineStatus) -> StatusRow {
    let mut parts: Vec<String> = Vec::new();
    if let Some(mode) = live
        .mode
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        parts.push(format_mode_label(mode).to_string());
    }
    if let Some(doh) = live.doh {
        let label = if doh { "DoH on" } else { "DoH off" };
        parts.push(label.to_string());
    }
    if let Some(block_quic) = live.block_quic {
        let label = if block_quic {
            "QUIC blocked"
        } else {
            "QUIC allowed"
        };
        parts.push(label.to_string());
    }

    let value = if parts.is_empty() {
        format!("Active · {}:{}", live.addr, live.port)
    } else {
        format!("Active · {}", parts.join(" · "))
    };
    StatusRow::new("Anti-DPI", value, StatusTone::Active)
}

fn build_engine_row(live: &LiveEngineStatus) -> StatusRow {
    let mut parts = vec![format!("{}:{}", live.addr, live.port)];
    if let Some(active) = live.active_connections {
        parts.push(format!("{active} active"));
    }
    if let Some(hosts) = live.learned_hosts {
        let label = if hosts == 1 {
            "cached host"
        } else {
            "cached hosts"
        };
        parts.push(format!("{hosts} {label}"));
    }
    StatusRow::new("Engine", parts.join(" · "), StatusTone::Neutral)
}

fn build_status_rows(status: &ControlCenterStatus) -> Vec<StatusRow> {
    let mut rows = Vec::with_capacity(3);
    rows.push(build_service_status_row(status));

    if let Some(live) = status.live_engine.as_ref() {
        rows.push(build_anti_dpi_row(live));
        rows.push(build_engine_row(live));
    } else if status.service_state == ServiceState::Running {
        rows.push(StatusRow::new(
            "Anti-DPI",
            "Starting or listening on custom port",
            StatusTone::Warning,
        ));
    } else {
        rows.push(StatusRow::new(
            "Anti-DPI",
            "Offline · system proxies restored",
            StatusTone::Neutral,
        ));
    }

    rows
}

fn pause_or_resume_item(service_state: ServiceState) -> Option<MenuItem> {
    match service_state {
        ServiceState::Running => Some(MenuItem::new(
            Choice::PauseService,
            "Pause background service",
            "Temporarily stops vdpi and restores system proxies.",
        )),
        ServiceState::Stopped => Some(MenuItem::new(
            Choice::ResumeService,
            "Resume background service",
            "Starts the installed service and re-enables proxies.",
        )),
        ServiceState::NotInstalled => None,
    }
}

fn uninstall_item() -> MenuItem {
    MenuItem::new(
        Choice::Uninstall,
        "Uninstall vdpi",
        "Stops service, removes files & PATH, restores proxies.",
    )
}

fn quit_item() -> MenuItem {
    MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything.")
}

fn build_same_version_items(service_state: ServiceState) -> Vec<MenuItem> {
    match service_state {
        ServiceState::Running => vec![
            MenuItem::new(
                Choice::PauseService,
                "Pause background service",
                "Temporarily stops vdpi and restores system proxies.",
            ),
            MenuItem::new(
                Choice::Update,
                "Check for updates online",
                "Checks GitHub Releases and updates automatically.",
            ),
            MenuItem::new(
                Choice::Doctor,
                "Run diagnostics",
                "Tests DNS ring and anti-DPI bypass connectivity.",
            ),
            MenuItem::new(
                Choice::Install,
                "Reinstall / repair service",
                "Rewrites the background service and restarts it.",
            ),
            uninstall_item(),
            quit_item(),
        ],
        ServiceState::Stopped => vec![
            MenuItem::new(
                Choice::ResumeService,
                "Resume background service",
                "Starts the installed service and re-enables proxies.",
            ),
            MenuItem::new(
                Choice::Run,
                "Run directly (this session)",
                "Active while this terminal is open.",
            ),
            MenuItem::new(
                Choice::Update,
                "Check for updates online",
                "Checks GitHub Releases and updates automatically.",
            ),
            MenuItem::new(
                Choice::Doctor,
                "Run diagnostics",
                "Tests DNS ring and anti-DPI bypass connectivity.",
            ),
            MenuItem::new(
                Choice::Install,
                "Reinstall / repair service",
                "Rewrites the background service and restarts it.",
            ),
            uninstall_item(),
            quit_item(),
        ],
        ServiceState::NotInstalled => vec![
            MenuItem::new(
                Choice::Install,
                "Reinstall / repair service",
                "Rewrites the background service and restarts it.",
            ),
            MenuItem::new(
                Choice::Run,
                "Run directly (this session)",
                "Active while this terminal is open.",
            ),
            MenuItem::new(
                Choice::Update,
                "Check for updates online",
                "Checks GitHub Releases and updates automatically.",
            ),
            MenuItem::new(
                Choice::Doctor,
                "Run diagnostics",
                "Tests DNS ring and anti-DPI bypass connectivity.",
            ),
            uninstall_item(),
            quit_item(),
        ],
    }
}

pub(super) fn build_menu(status: &ControlCenterStatus, notice: Option<&str>) -> LauncherMenu {
    let status_rows = build_status_rows(status);
    let notice = notice
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let items = match (status.installed.as_ref(), status.service_state) {
        (None, ServiceState::NotInstalled) => vec![
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
            MenuItem::new(
                Choice::Doctor,
                "Run diagnostics",
                "Tests DNS ring and anti-DPI bypass connectivity.",
            ),
            quit_item(),
        ],
        (None, service_state) => build_same_version_items(service_state),
        (Some(info), service_state) => match info.relation {
            VersionRelation::Newer => {
                let old = info.installed_version.as_deref().unwrap_or("unknown");
                let new = info.current_version;
                let mut items = Vec::with_capacity(5);
                items.push(MenuItem::new(
                    Choice::Install,
                    format!("Update installed vdpi (v{old} -> v{new})"),
                    "Replaces the installed service and restarts cleanly.",
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly without updating",
                    "Active while this terminal is open.",
                ));
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
            VersionRelation::Same => build_same_version_items(service_state),
            VersionRelation::Older => {
                let inst = info.installed_version.as_deref().unwrap_or("newer");
                let cur = info.current_version;
                let mut items = Vec::with_capacity(5);
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly",
                    format!("Keep installed v{inst} untouched."),
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(MenuItem::new(
                    Choice::Install,
                    format!("Downgrade installed vdpi (v{inst} -> v{cur})"),
                    format!("Replaces installed v{inst} with this older v{cur} binary."),
                ));
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
            VersionRelation::Unknown => {
                let cur = info.current_version;
                let mut items = Vec::with_capacity(5);
                items.push(MenuItem::new(
                    Choice::Install,
                    format!("Update / repair installed vdpi (to v{cur})"),
                    "Replaces the installed service and restarts cleanly.",
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly",
                    "Active while this terminal is open.",
                ));
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
        },
    };

    LauncherMenu {
        status_rows,
        notice,
        items,
    }
}

fn should_auto_run(
    explicit: bool,
    marker_path: Option<&Path>,
    status: &ControlCenterStatus,
) -> bool {
    !explicit
        && marker_path.is_some_and(Path::is_file)
        && status.installed.is_none()
        && status.service_state == ServiceState::NotInstalled
}

pub fn choose<F>(
    explicit: bool,
    status: &ControlCenterStatus,
    notice: Option<&str>,
    refresh: F,
) -> Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let state = preference_path();
    if should_auto_run(explicit, state.as_deref(), status) {
        return Ok(Choice::Run);
    }

    let selected = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if env::var("TERM").as_deref() == Ok("dumb") {
                read_choice(
                    io::stdin().lock(),
                    io::stderr().lock(),
                    status,
                    notice,
                    refresh,
                )?
            } else {
                tui::choose(env::var_os("NO_COLOR").is_none(), status, notice, refresh)
                    .context("running the terminal launcher")?
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            read_choice(
                io::stdin().lock(),
                io::stderr().lock(),
                status,
                notice,
                refresh,
            )?
        }
    } else if explicit {
        anyhow::bail!("no interactive launcher available; use `vdpi start` or `vdpi install`");
    } else {
        // Noninteractive bare invocations retain the existing foreground behavior.
        return Ok(Choice::Unattended);
    };

    if selected == Choice::Run
        && status.installed.is_none()
        && status.service_state == ServiceState::NotInstalled
    {
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

pub fn uninstall_finished(result: &Result<()>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        match result {
            Ok(()) => {
                eprintln!("\n  vdpi has been uninstalled and system proxies restored.");
                eprintln!("  GitHub: {REPOSITORY_URL}");
            }
            Err(error) => eprintln!("\n  Uninstall did not finish: {error:#}"),
        }
        eprintln!("  Press Enter to close this window.");
        let _ = io::stdin().read_line(&mut String::new());
    }
}

pub fn wait_for_continue_if_interactive() {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        eprintln!("\n  Press Enter to return to vdpi Control Center...");
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

fn print_console_menu(output: &mut impl Write, menu: &LauncherMenu) -> io::Result<()> {
    writeln!(
        output,
        "\n  vdpi v{}  |  {REPOSITORY_URL}",
        env!("CARGO_PKG_VERSION")
    )?;
    for row in &menu.status_rows {
        writeln!(output, "  {:<8}  {}", row.label, row.value)?;
    }
    if let Some(notice) = &menu.notice {
        writeln!(output, "  Notice    {notice}")?;
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
    Ok(())
}

fn read_choice<F>(
    mut input: impl BufRead,
    mut output: impl Write,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut menu = build_menu(initial_status, notice);
    if menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }

    print_console_menu(&mut output, &menu)?;

    let mut answer = String::new();
    loop {
        let count = menu.items.len();
        let choices: Vec<String> = (1..=count)
            .map(|n| n.to_string())
            .chain(["r".to_string(), "q".to_string()])
            .collect();
        let prompt_choices = choices.join(" / ");

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
        if trimmed.eq_ignore_ascii_case("r") {
            let latest = refresh();
            menu = build_menu(&latest, Some("Status refreshed."));
            if menu.items.is_empty() {
                return Ok(Choice::Cancel);
            }
            print_console_menu(&mut output, &menu)?;
            continue;
        }
        if let Some(item) = trimmed
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| menu.items.get(i))
        {
            if item.choice == Choice::Uninstall {
                write!(
                    output,
                    "  Confirm uninstall? This stops the service, removes files & PATH, and restores proxies. [y/N]: "
                )?;
                output.flush()?;
                answer.clear();
                if input.read_line(&mut answer)? == 0 {
                    return Ok(Choice::Cancel);
                }
                let confirm = answer.trim();
                if confirm.eq_ignore_ascii_case("y") || confirm.eq_ignore_ascii_case("yes") {
                    return Ok(Choice::Uninstall);
                }
                writeln!(output, "  Uninstall canceled.")?;
                continue;
            }
            return Ok(item.choice);
        }
        writeln!(
            output,
            "  Enter a number from 1 to {count}, r to refresh, or q to quit."
        )?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
            active_connections: Some(3),
            total_connections: Some(42),
            learned_hosts: Some(7),
            isp_stage: Some("balanced".to_string()),
        }
    }

    fn sample_minimal_live_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: None,
            version: Some("0.3.2".to_string()),
            mode: None,
            doh: None,
            block_quic: None,
            active_connections: None,
            total_connections: None,
            learned_hosts: None,
            isp_stage: None,
        }
    }

    fn fresh_status() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
        }
    }

    #[test]
    fn build_menu_fresh_install() {
        let menu = build_menu(&fresh_status(), None);
        assert_eq!(menu.notice, None);
        assert_eq!(menu.status_rows.len(), 2);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Not installed", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new(
                "Anti-DPI",
                "Offline · system proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(menu.items.len(), 4);
        assert_eq!(menu.items[0].choice, Choice::Run);
        assert_eq!(menu.items[0].title, "Run directly");
        assert_eq!(menu.items[1].choice, Choice::Install);
        assert_eq!(menu.items[1].title, "Install for automatic startup");
        assert_eq!(menu.items[2].choice, Choice::Doctor);
        assert_eq!(menu.items[2].title, "Run diagnostics");
        assert_eq!(menu.items[3].choice, Choice::Cancel);
        assert_eq!(menu.items[3].title, "Quit");
    }

    #[test]
    fn build_menu_running_with_live_engine_and_minimal_fallback() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
        };
        let menu = build_menu(&status, Some("Service resumed - anti-DPI active."));
        assert_eq!(
            menu.notice.as_deref(),
            Some("Service resumed - anti-DPI active.")
        );
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Running · v0.4.1", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Engine",
                "127.0.0.1:8080 · 3 active · 7 cached hosts",
                StatusTone::Neutral
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::PauseService,
                Choice::Update,
                Choice::Doctor,
                Choice::Install,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let minimal_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_minimal_live_engine()),
        };
        let minimal_menu = build_menu(&minimal_status, None);
        assert_eq!(
            minimal_menu.status_rows[1],
            StatusRow::new("Anti-DPI", "Active · 127.0.0.1:8080", StatusTone::Active)
        );
        assert_eq!(
            minimal_menu.status_rows[2],
            StatusRow::new("Engine", "127.0.0.1:8080", StatusTone::Neutral)
        );

        let custom_port_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
        };
        let custom_menu = build_menu(&custom_port_status, None);
        assert_eq!(custom_menu.status_rows.len(), 2);
        assert_eq!(
            custom_menu.status_rows[1],
            StatusRow::new(
                "Anti-DPI",
                "Starting or listening on custom port",
                StatusTone::Warning
            )
        );
    }

    #[test]
    fn build_menu_paused_same_version() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let menu = build_menu(&status, None);
        assert_eq!(menu.status_rows.len(), 2);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.4.1 (temporarily stopped)",
                StatusTone::Warning
            )
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new(
                "Anti-DPI",
                "Offline · system proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::ResumeService,
                Choice::Run,
                Choice::Update,
                Choice::Doctor,
                Choice::Install,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );
    }

    #[test]
    fn build_menu_newer_older_unknown_and_unregistered_binary() {
        let newer_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.3.0"), "0.4.1", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
        };
        let menu = build_menu(&newer_running, None);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Running · v0.3.0 -> v0.4.1 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::Install,
                Choice::PauseService,
                Choice::Run,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let newer_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.3.0"), "0.4.1", VersionRelation::Newer)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let stopped_menu = build_menu(&newer_stopped, None);
        assert_eq!(
            stopped_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.3.0 -> v0.4.1 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(stopped_menu.items[1].choice, Choice::ResumeService);

        let older = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.4.1", VersionRelation::Older)),
            service_state: ServiceState::Running,
            live_engine: None,
        };
        let older_menu = build_menu(&older, None);
        assert_eq!(older_menu.status_rows[0].tone, StatusTone::Warning);
        assert_eq!(
            older_menu
                .items
                .iter()
                .map(|i| i.choice)
                .collect::<Vec<_>>(),
            vec![
                Choice::Run,
                Choice::PauseService,
                Choice::Install,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let unknown = ControlCenterStatus {
            installed: Some(sample_info(None, "0.4.1", VersionRelation::Unknown)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let unknown_menu = build_menu(&unknown, None);
        assert_eq!(unknown_menu.status_rows[0].tone, StatusTone::Warning);
        assert_eq!(
            unknown_menu
                .items
                .iter()
                .map(|i| i.choice)
                .collect::<Vec<_>>(),
            vec![
                Choice::Install,
                Choice::ResumeService,
                Choice::Run,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let unregistered = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
        };
        let unreg_menu = build_menu(&unregistered, None);
        assert_eq!(
            unreg_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Installed v0.4.1 (service not registered)",
                StatusTone::Warning
            )
        );
    }

    #[test]
    fn console_handles_refresh_uninstall_confirm_and_reprompts() {
        let fresh = fresh_status();
        let mut output = Vec::new();
        assert_eq!(
            read_choice(
                &b"\nno\n0\n9\n2\n"[..],
                &mut output,
                &fresh,
                None,
                fresh_status
            )
            .unwrap(),
            Choice::Install
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Run directly"));
        assert!(output.contains("Install for automatic startup"));
        assert!(output.contains("Run diagnostics"));
        assert!(output.contains("Enter a number from 1 to 4, r to refresh, or q to quit."));
        assert!(output.contains("Choose [1 / 2 / 3 / 4 / r / q]: "));
        assert!(output.contains(REPOSITORY_URL));
        assert!(!output.contains('\x1b'));

        // Refresh transitions from Running -> Stopped and allows selecting ResumeService.
        let running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_engine()),
        };
        let paused = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let mut refresh_out = Vec::new();
        assert_eq!(
            read_choice(&b"r\n1\n"[..], &mut refresh_out, &running, None, || {
                paused.clone()
            })
            .unwrap(),
            Choice::ResumeService
        );
        let refresh_out = String::from_utf8(refresh_out).unwrap();
        assert!(refresh_out.contains("Status refreshed."));
        assert!(refresh_out.contains("Resume background service"));

        // Uninstall requires explicit confirmation: 'n' returns to menu, 'y' confirms.
        let mut confirm_out = Vec::new();
        assert_eq!(
            read_choice(
                &b"5\nn\n5\ny\n"[..],
                &mut confirm_out,
                &running,
                None,
                || { running.clone() }
            )
            .unwrap(),
            Choice::Uninstall
        );
        let confirm_out = String::from_utf8(confirm_out).unwrap();
        assert!(confirm_out.contains("Confirm uninstall?"));
        assert!(confirm_out.contains("Uninstall canceled."));

        // EOF cancels cleanly.
        assert_eq!(
            read_choice(&b""[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::Cancel
        );
    }

    #[test]
    fn auto_run_marker_only_applies_when_not_installed_and_not_explicit() {
        let dir =
            env::temp_dir().join(format!("vdpi-launcher-autorun-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("run-directly");
        remember_run(&marker).unwrap();

        let fresh = fresh_status();
        let installed_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
        };
        let installed_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let service_without_bin = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::Stopped,
            live_engine: None,
        };
        let bin_without_service = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
        };

        assert!(should_auto_run(false, Some(&marker), &fresh));
        assert!(!should_auto_run(true, Some(&marker), &fresh));
        assert!(!should_auto_run(false, None, &fresh));
        assert!(!should_auto_run(false, Some(&marker), &installed_running));
        assert!(!should_auto_run(false, Some(&marker), &installed_stopped));
        assert!(!should_auto_run(false, Some(&marker), &service_without_bin));
        assert!(!should_auto_run(false, Some(&marker), &bin_without_service));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_success_message_distinguishes_update_from_fresh_install() {
        let newer = sample_info(Some("0.3.0"), "0.4.1", VersionRelation::Newer);
        let same = sample_info(Some("0.4.1"), "0.4.1", VersionRelation::Same);
        let older = sample_info(Some("0.5.0"), "0.4.1", VersionRelation::Older);
        let unknown = sample_info(None, "0.4.1", VersionRelation::Unknown);

        assert_eq!(
            install_success_message(Some(&newer)),
            "vdpi updated to v0.4.1 and restarted."
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
    fn format_mode_label_maps_known_modes_and_preserves_unknown() {
        assert_eq!(format_mode_label("combo"), "Combo");
        assert_eq!(format_mode_label(" COMBO "), "Combo");
        assert_eq!(format_mode_label("tls-record"), "TLS Record");
        assert_eq!(format_mode_label("tlsrec"), "TLS Record");
        assert_eq!(format_mode_label("fragment"), "Fragment");
        assert_eq!(format_mode_label("chunk"), "Fragment");
        assert_eq!(format_mode_label("split"), "Split");
        assert_eq!(format_mode_label("custom-mode"), "custom-mode");
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
