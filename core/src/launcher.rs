use anyhow::{Context, Result};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use vdpi::config::EngineMode;
use vdpi::server::REPOSITORY_URL;
use vdpi::service::{ControlCenterStatus, InstalledInfo, LiveEngineStatus, ServiceState};
use vdpi::update::VersionRelation;
use vdpi_core::config::SplitTunnelConfig;

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
    SwitchEngine(EngineMode),
    SelectDns,
    SetDns(&'static str),
    SplitTunnel,
    Dashboard,
    Doctor,
    Uninstall,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsPreset {
    pub name: &'static str,
    pub addr: &'static str,
    pub hint: &'static str,
}

pub const DNS_PRESETS: [DnsPreset; 6] = [
    DnsPreset {
        name: "Cloudflare",
        addr: "1.1.1.1",
        hint: "Fast, privacy-focused public DNS (default).",
    },
    DnsPreset {
        name: "Google",
        addr: "8.8.8.8",
        hint: "Global low-latency public DNS.",
    },
    DnsPreset {
        name: "AdGuard",
        addr: "94.140.14.14",
        hint: "Blocks ads, trackers, and phishing domains.",
    },
    DnsPreset {
        name: "AdGuard Unfiltered",
        addr: "94.140.14.140",
        hint: "Privacy-focused DNS without ad filtering.",
    },
    DnsPreset {
        name: "Quad9",
        addr: "9.9.9.9",
        hint: "Blocks known malware and phishing domains.",
    },
    DnsPreset {
        name: "Cloudflare Family",
        addr: "1.1.1.3",
        hint: "Blocks malware and adult content.",
    },
];

pub fn format_dns_label(addr: &str) -> String {
    let trimmed = addr.trim();
    if let Some(preset) = DNS_PRESETS
        .iter()
        .find(|p| p.addr.eq_ignore_ascii_case(trimmed))
    {
        format!("{} ({})", preset.name, preset.addr)
    } else if trimmed.is_empty() {
        format!("{} ({})", DNS_PRESETS[0].name, DNS_PRESETS[0].addr)
    } else {
        format!("Custom ({trimmed})")
    }
}

pub(super) fn dns_preset_index(addr: &str) -> usize {
    let trimmed = addr.trim();
    DNS_PRESETS
        .iter()
        .position(|p| p.addr.eq_ignore_ascii_case(trimmed))
        .unwrap_or(0)
}

fn dns_server_item(current_dns: &str) -> MenuItem {
    MenuItem::new(
        Choice::SelectDns,
        format!("Choose DNS server · {}", format_dns_label(current_dns)),
        "Pick Cloudflare, Google, AdGuard, Quad9, or Family DoH.",
    )
}

fn split_tunnel_item(split: &SplitTunnelConfig) -> MenuItem {
    MenuItem::new(
        Choice::SplitTunnel,
        format!("Split tunneling · {}", split.summary_label()),
        "Choose which apps use or bypass anti-DPI (with live search).",
    )
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
    pub badge: Option<(String, StatusTone)>,
}

impl StatusRow {
    fn new(label: impl Into<String>, value: impl Into<String>, tone: StatusTone) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            tone,
            badge: None,
        }
    }

    fn with_badge(mut self, badge: Option<(String, StatusTone)>) -> Self {
        self.badge = badge;
        self
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

const fn engine_label(engine: EngineMode) -> &'static str {
    match engine {
        EngineMode::Tun => "TUN",
        EngineMode::Proxy => "Proxy",
    }
}

fn format_rss_mb(rss_kb: Option<u64>) -> Option<String> {
    let kb = rss_kb.filter(|&kb| kb > 0)?;
    let mb = (kb.saturating_add(512) / 1024).max(1);
    Some(format!("{mb} MB"))
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
        if live.engine == EngineMode::Tun {
            "Active".to_string()
        } else {
            format!("Active · {}", SocketAddr::new(live.addr, live.port))
        }
    } else {
        format!("Active · {}", parts.join(" · "))
    };
    StatusRow::new("Anti-DPI", value, StatusTone::Active)
}

fn build_engine_row(status: &ControlCenterStatus) -> StatusRow {
    let badge = status
        .live_engine
        .as_ref()
        .and_then(|l| l.vpn_conflict.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            status
                .vpn_conflict
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
        })
        .map(|v| (format!("VPN: {v}"), StatusTone::Warning));

    if let Some(live) = status.live_engine.as_ref() {
        let value = match live.engine {
            EngineMode::Tun => {
                let mut parts = vec!["TUN".to_string()];
                if let Some(iface) = live
                    .tun_interface
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    parts.push(iface.to_string());
                }
                if let Some(nic) = live
                    .physical_nic
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    parts.push(nic.to_string());
                }
                if let Some(rss) = format_rss_mb(live.rss_kb) {
                    let current_len: usize = parts.iter().map(|p| p.chars().count()).sum::<usize>()
                        + parts.len().saturating_sub(1) * 3;
                    let max_len = if badge.is_some() { 38 } else { 48 };
                    if current_len + 3 + rss.len() <= max_len {
                        parts.push(rss);
                    }
                }
                parts.join(" · ")
            }
            EngineMode::Proxy => format!("Proxy · {}", SocketAddr::new(live.addr, live.port)),
        };

        return StatusRow::new("Engine", value, StatusTone::Active).with_badge(badge);
    }

    let label = engine_label(status.configured_engine);
    let state_suffix = match status.service_state {
        ServiceState::Stopped => "paused",
        ServiceState::Running | ServiceState::NotInstalled => "selected",
    };
    StatusRow::new(
        "Engine",
        format!("{label} ({state_suffix})"),
        StatusTone::Neutral,
    )
    .with_badge(badge)
}

fn build_status_rows(status: &ControlCenterStatus) -> Vec<StatusRow> {
    let anti_dpi_row = if let Some(live) = status.live_engine.as_ref() {
        build_anti_dpi_row(live)
    } else if status.service_state == ServiceState::Running {
        StatusRow::new(
            "Anti-DPI",
            "Starting or listening on custom port",
            StatusTone::Warning,
        )
    } else {
        StatusRow::new(
            "Anti-DPI",
            "Offline · routes & proxies restored",
            StatusTone::Neutral,
        )
    };

    vec![
        build_service_status_row(status),
        build_engine_row(status),
        anti_dpi_row,
    ]
}

fn pause_or_resume_item(service_state: ServiceState) -> Option<MenuItem> {
    match service_state {
        ServiceState::Running => Some(MenuItem::new(
            Choice::PauseService,
            "Pause background service",
            "Temporarily stops vdpi and restores routes & proxies.",
        )),
        ServiceState::Stopped => Some(MenuItem::new(
            Choice::ResumeService,
            "Resume background service",
            "Starts the service and re-enables routes & proxies.",
        )),
        ServiceState::NotInstalled => None,
    }
}

fn uninstall_item() -> MenuItem {
    MenuItem::new(
        Choice::Uninstall,
        "Uninstall vdpi",
        "Stops service, removes files & PATH, restores routes & proxies.",
    )
}

fn active_or_configured_engine(status: &ControlCenterStatus) -> EngineMode {
    status
        .live_engine
        .as_ref()
        .map_or(status.configured_engine, |live| live.engine)
}

fn switch_engine_item(current: EngineMode) -> MenuItem {
    match current {
        EngineMode::Proxy => MenuItem::new(
            Choice::SwitchEngine(EngineMode::Tun),
            "Switch to TUN mode",
            "Transparent system-wide anti-DPI via vdpi0 - no proxy setup or browser restarts.",
        ),
        EngineMode::Tun => MenuItem::new(
            Choice::SwitchEngine(EngineMode::Proxy),
            "Switch to Proxy mode",
            "Classic local HTTP/SOCKS5 proxy - lightweight, no virtual adapter, VPN-friendly.",
        ),
    }
}

fn dashboard_item() -> MenuItem {
    MenuItem::new(
        Choice::Dashboard,
        "Open live dashboard",
        "Real-time throughput, connections, ISP stage & diagnostics.",
    )
}

fn quit_item() -> MenuItem {
    MenuItem::new(Choice::Cancel, "Quit", "Exit without changing anything.")
}

fn build_same_version_items(
    service_state: ServiceState,
    current_engine: EngineMode,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    has_live_engine: bool,
) -> Vec<MenuItem> {
    match service_state {
        ServiceState::Running => {
            let mut items = Vec::with_capacity(if has_live_engine { 9 } else { 8 });
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.extend([
                MenuItem::new(
                    Choice::PauseService,
                    "Pause background service",
                    "Temporarily stops vdpi and restores routes & proxies.",
                ),
                switch_engine_item(current_engine),
                dns_server_item(configured_dns),
                split_tunnel_item(split_tunnel),
                MenuItem::new(
                    Choice::Doctor,
                    "Run diagnostics",
                    "Tests DNS ring and anti-DPI bypass connectivity.",
                ),
                MenuItem::new(
                    Choice::Update,
                    "Check for updates online",
                    "Checks GitHub Releases and updates automatically.",
                ),
                uninstall_item(),
                quit_item(),
            ]);
            items
        }
        ServiceState::Stopped => {
            let mut items = Vec::with_capacity(9);
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.push(MenuItem::new(
                Choice::ResumeService,
                "Resume background service",
                "Starts the service and re-enables routes & proxies.",
            ));
            items.push(switch_engine_item(current_engine));
            items.push(dns_server_item(configured_dns));
            items.push(split_tunnel_item(split_tunnel));
            if !has_live_engine {
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly (this session)",
                    "Active while this terminal is open.",
                ));
            }
            items.extend([
                MenuItem::new(
                    Choice::Doctor,
                    "Run diagnostics",
                    "Tests DNS ring and anti-DPI bypass connectivity.",
                ),
                MenuItem::new(
                    Choice::Update,
                    "Check for updates online",
                    "Checks GitHub Releases and updates automatically.",
                ),
                uninstall_item(),
                quit_item(),
            ]);
            items
        }
        ServiceState::NotInstalled => {
            let mut items = Vec::with_capacity(9);
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.push(MenuItem::new(
                Choice::Install,
                "Reinstall / repair service",
                "Rewrites the background service and restarts it.",
            ));
            items.push(switch_engine_item(current_engine));
            items.push(dns_server_item(configured_dns));
            items.push(split_tunnel_item(split_tunnel));
            if !has_live_engine {
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly (this session)",
                    "Active while this terminal is open.",
                ));
            }
            items.extend([
                MenuItem::new(
                    Choice::Doctor,
                    "Run diagnostics",
                    "Tests DNS ring and anti-DPI bypass connectivity.",
                ),
                MenuItem::new(
                    Choice::Update,
                    "Check for updates online",
                    "Checks GitHub Releases and updates automatically.",
                ),
                uninstall_item(),
                quit_item(),
            ]);
            items
        }
    }
}

#[cfg(test)]
pub(super) fn build_menu(status: &ControlCenterStatus, notice: Option<&str>) -> LauncherMenu {
    build_menu_with_dns(status, notice, DNS_PRESETS[0].addr)
}

#[allow(dead_code)]
pub(super) fn build_menu_with_dns(
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
) -> LauncherMenu {
    build_menu_with_options(
        status,
        notice,
        configured_dns,
        &SplitTunnelConfig::default(),
    )
}

pub(super) fn build_menu_with_options(
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
) -> LauncherMenu {
    let status_rows = build_status_rows(status);
    let notice = notice
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let current_engine = active_or_configured_engine(status);
    let has_live_engine = status.live_engine.is_some();

    let items = match (status.installed.as_ref(), status.service_state) {
        (None, ServiceState::NotInstalled) => {
            let mut items = Vec::with_capacity(if has_live_engine { 8 } else { 7 });
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.extend([
                MenuItem::new(
                    Choice::Run,
                    "Run directly",
                    "Active while this terminal is open.",
                ),
                switch_engine_item(current_engine),
                MenuItem::new(
                    Choice::Install,
                    "Install for automatic startup",
                    "Runs in the background after you close it.",
                ),
                dns_server_item(configured_dns),
                split_tunnel_item(split_tunnel),
                MenuItem::new(
                    Choice::Doctor,
                    "Run diagnostics",
                    "Tests DNS ring and anti-DPI bypass connectivity.",
                ),
                quit_item(),
            ]);
            items
        }
        (None, service_state) => build_same_version_items(
            service_state,
            current_engine,
            configured_dns,
            split_tunnel,
            has_live_engine,
        ),
        (Some(info), service_state) => match info.relation {
            VersionRelation::Newer => {
                let old = info.installed_version.as_deref().unwrap_or("unknown");
                let new = info.current_version;
                let mut items = Vec::with_capacity(9);
                items.push(MenuItem::new(
                    Choice::Install,
                    format!("Update installed vdpi (v{old} -> v{new})"),
                    "Replaces the installed service and restarts cleanly.",
                ));
                if has_live_engine {
                    items.push(dashboard_item());
                }
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly without updating",
                    "Active while this terminal is open.",
                ));
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
            VersionRelation::Same => build_same_version_items(
                service_state,
                current_engine,
                configured_dns,
                split_tunnel,
                has_live_engine,
            ),
            VersionRelation::Older => {
                let inst = info.installed_version.as_deref().unwrap_or("newer");
                let cur = info.current_version;
                let mut items = Vec::with_capacity(9);
                if has_live_engine {
                    items.push(dashboard_item());
                }
                items.push(MenuItem::new(
                    Choice::Run,
                    "Run directly",
                    format!("Keep installed v{inst} untouched."),
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
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
                let mut items = Vec::with_capacity(9);
                if has_live_engine {
                    items.push(dashboard_item());
                }
                items.push(MenuItem::new(
                    Choice::Install,
                    format!("Update / repair installed vdpi (to v{cur})"),
                    "Replaces the installed service and restarts cleanly.",
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
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

#[allow(dead_code)]
pub fn choose<F>(
    explicit: bool,
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    refresh: F,
) -> Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    choose_with_options(
        explicit,
        status,
        notice,
        configured_dns,
        &SplitTunnelConfig::default(),
        refresh,
    )
}

pub fn choose_with_options<F>(
    explicit: bool,
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    mut refresh: F,
) -> Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let state = preference_path();
    if should_auto_run(explicit, state.as_deref(), status) {
        return Ok(Choice::Run);
    }

    let mut latest_status = status.clone();
    let selected = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        let mut tracked_refresh = || {
            let refreshed = refresh();
            latest_status = refreshed.clone();
            refreshed
        };
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if env::var("TERM").as_deref() == Ok("dumb") {
                read_choice_with_options(
                    io::stdin().lock(),
                    io::stderr().lock(),
                    status,
                    notice,
                    configured_dns,
                    split_tunnel,
                    &mut tracked_refresh,
                )?
            } else {
                let color = env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
                match tui::choose_with_options(
                    color,
                    status,
                    notice,
                    configured_dns,
                    split_tunnel,
                    &mut tracked_refresh,
                ) {
                    Ok(choice) => choice,
                    Err(_) => read_choice_with_options(
                        io::stdin().lock(),
                        io::stderr().lock(),
                        status,
                        notice,
                        configured_dns,
                        split_tunnel,
                        &mut tracked_refresh,
                    )
                    .context("running the terminal launcher")?,
                }
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            read_choice_with_options(
                io::stdin().lock(),
                io::stderr().lock(),
                status,
                notice,
                configured_dns,
                split_tunnel,
                &mut tracked_refresh,
            )?
        }
    } else if explicit {
        anyhow::bail!("no interactive launcher available; use `vdpi start` or `vdpi install`");
    } else {
        // Noninteractive bare invocations retain the existing foreground behavior.
        return Ok(Choice::Unattended);
    };

    if selected == Choice::Run
        && latest_status.installed.is_none()
        && latest_status.service_state == ServiceState::NotInstalled
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
                eprintln!("\n  vdpi has been uninstalled and routes & proxies restored.");
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
        if let Some((badge, _)) = &row.badge {
            writeln!(output, "  {:<8}  {}  [{badge}]", row.label, row.value)?;
        } else {
            writeln!(output, "  {:<8}  {}", row.label, row.value)?;
        }
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

#[cfg(test)]
fn read_choice<F>(
    input: impl BufRead,
    output: impl Write,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    read_choice_with_options(
        input,
        output,
        initial_status,
        notice,
        DNS_PRESETS[0].addr,
        &SplitTunnelConfig::default(),
        refresh,
    )
}

fn read_dns_choice(
    input: &mut impl BufRead,
    output: &mut impl Write,
    configured_dns: &str,
) -> io::Result<Option<&'static str>> {
    writeln!(
        output,
        "\n  Choose DNS server (current: {})",
        format_dns_label(configured_dns)
    )?;
    for (idx, preset) in DNS_PRESETS.iter().enumerate() {
        let active = if preset.addr.eq_ignore_ascii_case(configured_dns.trim()) {
            " [active]"
        } else {
            ""
        };
        writeln!(
            output,
            "  {}  {:<18} {:<15} {}{active}",
            idx + 1,
            preset.name,
            preset.addr,
            preset.hint
        )?;
    }
    let mut answer = String::new();
    loop {
        write!(output, "  Choose DNS [1-{} / b back]: ", DNS_PRESETS.len())?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(None);
        }
        let trimmed = answer.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("b")
            || trimmed.eq_ignore_ascii_case("q")
        {
            return Ok(None);
        }
        if let Some(preset) = trimmed
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| DNS_PRESETS.get(i))
        {
            return Ok(Some(preset.addr));
        }
        writeln!(
            output,
            "  Enter a number from 1 to {}, or b to go back.",
            DNS_PRESETS.len()
        )?;
    }
}

fn read_choice_with_options<F>(
    mut input: impl BufRead,
    mut output: impl Write,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut menu = build_menu_with_options(initial_status, notice, configured_dns, split_tunnel);
    if menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }

    print_console_menu(&mut output, &menu)?;

    let mut answer = String::new();
    loop {
        let count = menu.items.len();
        let choices: Vec<String> = (1..=count)
            .map(|n| n.to_string())
            .chain([
                "d".to_string(),
                "s".to_string(),
                "r".to_string(),
                "q".to_string(),
            ])
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
            menu = build_menu_with_options(
                &latest,
                Some("Status refreshed."),
                configured_dns,
                split_tunnel,
            );
            if menu.items.is_empty() {
                return Ok(Choice::Cancel);
            }
            print_console_menu(&mut output, &menu)?;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("m") {
            if let Some(item) = menu
                .items
                .iter()
                .find(|item| matches!(item.choice, Choice::SwitchEngine(_)))
            {
                return Ok(item.choice);
            }
        }
        if trimmed.eq_ignore_ascii_case("s")
            && menu
                .items
                .iter()
                .any(|item| item.choice == Choice::SplitTunnel)
        {
            return Ok(Choice::SplitTunnel);
        }
        if trimmed.eq_ignore_ascii_case("d") {
            if let Some(addr) = read_dns_choice(&mut input, &mut output, configured_dns)? {
                return Ok(Choice::SetDns(addr));
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
            if item.choice == Choice::SelectDns {
                if let Some(addr) = read_dns_choice(&mut input, &mut output, configured_dns)? {
                    return Ok(Choice::SetDns(addr));
                }
                print_console_menu(&mut output, &menu)?;
                continue;
            }
            if item.choice == Choice::Uninstall {
                write!(
                    output,
                    "  Confirm uninstall? This stops the service, removes files & PATH, and restores routes & proxies. [y/N]: "
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

    fn sample_live_proxy_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(3),
            total_connections: Some(42),
            learned_hosts: Some(7),
            isp_stage: Some("balanced".to_string()),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: Some(14_336),
            bytes_rx: Some(1_048_576),
            bytes_tx: Some(262_144),
            tls_handshakes: Some(28),
            auto_heal_escalations: Some(1),
        }
    }

    fn sample_live_tun_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 18089,
            socks_port: None,
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(5),
            total_connections: Some(120),
            learned_hosts: Some(9),
            isp_stage: Some("balanced".to_string()),
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            udp_flows_active: Some(12),
            quic_blocked: Some(42),
            dns_queries: Some(89),
            rss_kb: Some(16_384),
            bytes_rx: Some(4_194_304),
            bytes_tx: Some(524_288),
            tls_handshakes: Some(64),
            auto_heal_escalations: Some(2),
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
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        }
    }

    fn fresh_status() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    #[test]
    fn build_menu_fresh_install() {
        let menu = build_menu(&fresh_status(), None);
        assert_eq!(menu.notice, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Not installed", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Offline · routes & proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(menu.items.len(), 7);
        assert_eq!(menu.items[0].choice, Choice::Run);
        assert_eq!(menu.items[0].title, "Run directly");
        assert_eq!(menu.items[1].choice, Choice::SwitchEngine(EngineMode::Tun));
        assert_eq!(menu.items[1].title, "Switch to TUN mode");
        assert_eq!(
            menu.items[1].hint,
            "Transparent system-wide anti-DPI via vdpi0 - no proxy setup or browser restarts."
        );
        assert_eq!(menu.items[2].choice, Choice::Install);
        assert_eq!(menu.items[2].title, "Install for automatic startup");
        assert_eq!(menu.items[3].choice, Choice::SelectDns);
        assert!(menu.items[3].title.contains("Cloudflare (1.1.1.1)"));
        assert_eq!(menu.items[4].choice, Choice::SplitTunnel);
        assert_eq!(menu.items[4].title, "Split tunneling · All apps");
        assert_eq!(
            menu.items[4].hint,
            "Choose which apps use or bypass anti-DPI (with live search)."
        );
        assert_eq!(menu.items[5].choice, Choice::Doctor);
        assert_eq!(menu.items[5].title, "Run diagnostics");
        assert_eq!(menu.items[6].choice, Choice::Cancel);
        assert_eq!(menu.items[6].title, "Quit");

        let mut fresh_tun = fresh_status();
        fresh_tun.configured_engine = EngineMode::Tun;
        let tun_menu = build_menu(&fresh_tun, None);
        assert_eq!(
            tun_menu.status_rows[1],
            StatusRow::new("Engine", "TUN (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            tun_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );
        assert_eq!(tun_menu.items[1].title, "Switch to Proxy mode");
        assert_eq!(
            tun_menu.items[1].hint,
            "Classic local HTTP/SOCKS5 proxy - lightweight, no virtual adapter, VPN-friendly."
        );
    }

    #[test]
    fn build_menu_running_proxy_mode_and_minimal_fallback() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, Some("Service resumed - anti-DPI active."));
        assert_eq!(
            menu.notice.as_deref(),
            Some("Service resumed - anti-DPI active.")
        );
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Running · v0.5.0", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::Dashboard,
                Choice::PauseService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Doctor,
                Choice::Update,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let mut proxy_with_vpn = sample_live_proxy_engine();
        proxy_with_vpn.vpn_conflict = Some("WireGuard".to_string());
        let vpn_proxy_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(proxy_with_vpn),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let vpn_proxy_menu = build_menu(&vpn_proxy_status, None);
        assert_eq!(
            vpn_proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
                .with_badge(Some(("VPN: WireGuard".to_string(), StatusTone::Warning)))
        );

        let minimal_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_minimal_live_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let minimal_menu = build_menu(&minimal_status, None);
        assert_eq!(
            minimal_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
        );
        assert_eq!(
            minimal_menu.status_rows[2],
            StatusRow::new("Anti-DPI", "Active · 127.0.0.1:8080", StatusTone::Active)
        );

        let custom_port_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let custom_menu = build_menu(&custom_port_status, None);
        assert_eq!(custom_menu.status_rows.len(), 3);
        assert_eq!(
            custom_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            custom_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Starting or listening on custom port",
                StatusTone::Warning
            )
        );
    }

    #[test]
    fn build_menu_running_tun_mode_and_vpn_badge() {
        let tun_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let tun_menu = build_menu(&tun_status, None);
        assert_eq!(tun_menu.status_rows.len(), 3);
        assert_eq!(
            tun_menu.status_rows[0],
            StatusRow::new("Service", "Running · v0.5.0", StatusTone::Active)
        );
        assert_eq!(
            tun_menu.status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Ethernet · 16 MB",
                StatusTone::Active
            )
        );
        assert_eq!(
            tun_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        assert_eq!(tun_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(
            tun_menu.items[2],
            MenuItem::new(
                Choice::SwitchEngine(EngineMode::Proxy),
                "Switch to Proxy mode",
                "Classic local HTTP/SOCKS5 proxy - lightweight, no virtual adapter, VPN-friendly.",
            )
        );

        // TUN without RSS reports interface + uplink cleanly.
        let mut no_rss_tun = sample_live_tun_engine();
        no_rss_tun.rss_kb = None;
        let no_rss_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(no_rss_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            build_menu(&no_rss_status, None).status_rows[1],
            StatusRow::new("Engine", "TUN · vdpi0 · Ethernet", StatusTone::Active)
        );

        // TUN + VPN conflict attaches a warning badge.
        let mut vpn_tun = sample_live_tun_engine();
        vpn_tun.vpn_conflict = Some("Mullvad".to_string());
        let vpn_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(vpn_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let vpn_menu = build_menu(&vpn_status, None);
        assert_eq!(
            vpn_menu.status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Ethernet · 16 MB",
                StatusTone::Active
            )
            .with_badge(Some(("VPN: Mullvad".to_string(), StatusTone::Warning)))
        );

        // Very long physical NIC name omits RSS so the status row stays compact.
        let mut long_nic_tun = sample_live_tun_engine();
        long_nic_tun.physical_nic = Some("Realtek PCIe GbE Family Controller".to_string());
        let long_nic_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(long_nic_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            build_menu(&long_nic_status, None).status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Realtek PCIe GbE Family Controller",
                StatusTone::Active
            )
        );
    }

    #[test]
    fn build_menu_paused_same_version() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.5.0 (temporarily stopped)",
                StatusTone::Warning
            )
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "TUN (paused)", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Offline · routes & proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::ResumeService,
                Choice::SwitchEngine(EngineMode::Proxy),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Run,
                Choice::Doctor,
                Choice::Update,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let paused_proxy = ControlCenterStatus {
            configured_engine: EngineMode::Proxy,
            ..status
        };
        let proxy_menu = build_menu(&paused_proxy, None);
        assert_eq!(
            proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (paused)", StatusTone::Neutral)
        );
        assert_eq!(
            proxy_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Tun)
        );
    }

    #[test]
    fn build_menu_newer_older_unknown_and_unregistered_binary() {
        let newer_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&newer_running, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Running · v0.4.2 -> v0.5.0 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(
            menu.items.iter().map(|i| i.choice).collect::<Vec<_>>(),
            vec![
                Choice::Install,
                Choice::Dashboard,
                Choice::PauseService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Run,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let newer_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let stopped_menu = build_menu(&newer_stopped, None);
        assert_eq!(
            stopped_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.4.2 -> v0.5.0 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(stopped_menu.items[1].choice, Choice::ResumeService);
        assert_eq!(
            stopped_menu.items[2].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );

        let older = ControlCenterStatus {
            installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
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
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Install,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let unknown = ControlCenterStatus {
            installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
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
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Run,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let unregistered = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let unreg_menu = build_menu(&unregistered, None);
        assert_eq!(
            unreg_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Installed v0.5.0 (service not registered)",
                StatusTone::Warning
            )
        );
        assert_eq!(
            unreg_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );
    }

    #[test]
    fn console_handles_refresh_badge_switch_engine_uninstall_confirm_and_reprompts() {
        let fresh = fresh_status();
        let mut output = Vec::new();
        assert_eq!(
            read_choice(
                &b"\nno\n0\n9\n3\n"[..],
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
        assert!(output.contains("Switch to TUN mode"));
        assert!(output.contains("Install for automatic startup"));
        assert!(output.contains("Split tunneling · All apps"));
        assert!(output.contains("Run diagnostics"));
        assert!(output.contains("Enter a number from 1 to 7, r to refresh, or q to quit."));
        assert!(output.contains("Choose [1 / 2 / 3 / 4 / 5 / 6 / 7 / d / s / r / q]: "));
        assert!(output.contains(REPOSITORY_URL));
        assert!(!output.contains('\x1b'));

        // Console 's' / 'S' shortcut selects SplitTunnel directly.
        assert_eq!(
            read_choice(&b"s\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SplitTunnel
        );
        assert_eq!(
            read_choice(&b"S\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SplitTunnel
        );

        // Console 'd' shortcut opens DNS preset picker and selects AdGuard on '3'.
        let mut dns_out = Vec::new();
        assert_eq!(
            read_choice(&b"d\n3\n"[..], &mut dns_out, &fresh, None, fresh_status).unwrap(),
            Choice::SetDns("94.140.14.14")
        );
        let dns_out = String::from_utf8(dns_out).unwrap();
        assert!(dns_out.contains("AdGuard"));
        assert!(dns_out.contains("94.140.14.14"));

        // Console renders inline [VPN: Mullvad] badge, returns Dashboard on slot 1 and SwitchEngine on slot 3.
        let mut tun_with_vpn = sample_live_tun_engine();
        tun_with_vpn.vpn_conflict = Some("Mullvad".to_string());
        let running_tun = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(tun_with_vpn),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            read_choice(&b"1\n"[..], Vec::new(), &running_tun, None, || {
                running_tun.clone()
            })
            .unwrap(),
            Choice::Dashboard
        );
        let mut tun_out = Vec::new();
        assert_eq!(
            read_choice(&b"3\n"[..], &mut tun_out, &running_tun, None, || {
                running_tun.clone()
            })
            .unwrap(),
            Choice::SwitchEngine(EngineMode::Proxy)
        );
        let tun_out = String::from_utf8(tun_out).unwrap();
        assert!(tun_out.contains("Engine    TUN · vdpi0 · Ethernet · 16 MB  [VPN: Mullvad]"));
        assert!(tun_out.contains("Open live dashboard"));
        assert!(tun_out.contains("Switch to Proxy mode"));

        // Shortcut 'm' also triggers SwitchEngine in console fallback.
        assert_eq!(
            read_choice(&b"m\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SwitchEngine(EngineMode::Tun)
        );

        // Refresh transitions from Running -> Stopped and allows selecting ResumeService.
        let running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let paused = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
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
                &b"8\nn\n8\ny\n"[..],
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
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let installed_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let service_without_bin = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let bin_without_service = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
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
        let newer = sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer);
        let same = sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same);
        let older = sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older);
        let unknown = sample_info(None, "0.5.0", VersionRelation::Unknown);

        assert_eq!(
            install_success_message(Some(&newer)),
            "vdpi updated to v0.5.0 and restarted."
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

    #[test]
    fn ipv6_live_engine_address_uses_brackets() {
        let mut live = sample_minimal_live_engine();
        live.addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        live.port = 8080;
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(live),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, None);
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · [::1]:8080", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new("Anti-DPI", "Active · [::1]:8080", StatusTone::Active)
        );
    }

    #[test]
    fn vpn_conflict_badge_visible_across_non_live_and_proxy_states_and_hints_mention_routes() {
        // NotInstalled with top-level status.vpn_conflict shows badge.
        let mut fresh_vpn = fresh_status();
        fresh_vpn.vpn_conflict = Some("Mullvad".to_string());
        let fresh_menu = build_menu(&fresh_vpn, None);
        assert_eq!(
            fresh_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
                .with_badge(Some(("VPN: Mullvad".to_string(), StatusTone::Warning)))
        );

        // Paused service with top-level status.vpn_conflict shows badge and updated hints.
        let paused_vpn = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: Some("WireGuard".to_string()),
        };
        let paused_menu = build_menu(&paused_vpn, None);
        assert_eq!(
            paused_menu.status_rows[1],
            StatusRow::new("Engine", "TUN (paused)", StatusTone::Neutral)
                .with_badge(Some(("VPN: WireGuard".to_string(), StatusTone::Warning)))
        );
        assert!(paused_menu.items[0].hint.contains("routes & proxies"));
        let uninstall_item = paused_menu
            .items
            .iter()
            .find(|item| item.choice == Choice::Uninstall)
            .expect("uninstall item");
        assert!(uninstall_item.hint.contains("routes & proxies"));

        // Live proxy with live.vpn_conflict = None falls back to status.vpn_conflict.
        let proxy_fallback = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: Some("ProtonVPN".to_string()),
        };
        let proxy_menu = build_menu(&proxy_fallback, None);
        assert_eq!(
            proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
                .with_badge(Some(("VPN: ProtonVPN".to_string(), StatusTone::Warning)))
        );
        assert_eq!(proxy_menu.items[1].choice, Choice::PauseService);
        assert!(proxy_menu.items[1].hint.contains("routes & proxies"));

        // Live vpn_conflict takes precedence over top-level status.vpn_conflict.
        let mut live_override = sample_live_tun_engine();
        live_override.vpn_conflict = Some("Tailscale".to_string());
        let override_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(live_override),
            configured_engine: EngineMode::Tun,
            vpn_conflict: Some("Mullvad".to_string()),
        };
        assert_eq!(
            build_menu(&override_status, None).status_rows[1].badge,
            Some(("VPN: Tailscale".to_string(), StatusTone::Warning))
        );
    }

    #[test]
    fn dashboard_item_present_when_live_engine_active_and_within_nine_slots() {
        let same_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let same_menu = build_menu(&same_running, None);
        assert_eq!(same_menu.items.len(), 9);
        assert_eq!(
            same_menu.items[0],
            MenuItem::new(
                Choice::Dashboard,
                "Open live dashboard",
                "Real-time throughput, connections, ISP stage & diagnostics.",
            )
        );

        let newer_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let newer_menu = build_menu(&newer_running, None);
        assert!(newer_menu.items.len() <= 9);
        assert_eq!(newer_menu.items[0].choice, Choice::Install);
        assert_eq!(newer_menu.items[1].choice, Choice::Dashboard);

        let older_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let older_menu = build_menu(&older_running, None);
        assert!(older_menu.items.len() <= 9);
        assert_eq!(older_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(older_menu.items[1].choice, Choice::Run);

        let unknown_running = ControlCenterStatus {
            installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let unknown_menu = build_menu(&unknown_running, None);
        assert!(unknown_menu.items.len() <= 9);
        assert_eq!(unknown_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(unknown_menu.items[1].choice, Choice::Install);

        let running_daemon_no_install = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let daemon_menu = build_menu(&running_daemon_no_install, None);
        assert_eq!(daemon_menu.items.len(), 9);
        assert_eq!(daemon_menu.items[0].choice, Choice::Dashboard);

        let standalone_live_not_installed = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let standalone_menu = build_menu(&standalone_live_not_installed, None);
        assert_eq!(standalone_menu.items.len(), 8);
        assert_eq!(standalone_menu.items[0].choice, Choice::Dashboard);

        let stopped_with_live = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let stopped_live_menu = build_menu(&stopped_with_live, None);
        assert_eq!(stopped_live_menu.items.len(), 9);
        assert_eq!(stopped_live_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(stopped_live_menu.items[1].choice, Choice::ResumeService);
    }

    #[test]
    fn dashboard_item_absent_when_offline_or_paused() {
        let cases = [
            fresh_status(),
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Tun,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::Running,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
                service_state: ServiceState::Running,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::NotInstalled,
                live_engine: None,
                configured_engine: EngineMode::Tun,
                vpn_conflict: None,
            },
        ];

        for status in &cases {
            let menu = build_menu(status, None);
            assert!(menu.items.len() <= 9);
            assert!(
                !menu
                    .items
                    .iter()
                    .any(|item| item.choice == Choice::Dashboard),
                "Choice::Dashboard should be absent when live_engine is None"
            );
        }
    }

    #[test]
    fn split_tunnel_item_present_with_summary_and_within_nine_slots_in_all_branches() {
        use vdpi_core::config::SplitTunnelMode;

        let exclude_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["discord.exe".to_string(), "steam.exe".to_string()],
        };
        let include_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["chrome.exe".to_string()],
        };

        let all_item = split_tunnel_item(&SplitTunnelConfig::default());
        assert_eq!(all_item.choice, Choice::SplitTunnel);
        assert_eq!(all_item.title, "Split tunneling · All apps");
        assert_eq!(
            all_item.hint,
            "Choose which apps use or bypass anti-DPI (with live search)."
        );

        let exclude_item = split_tunnel_item(&exclude_cfg);
        assert_eq!(exclude_item.title, "Split tunneling · Exclude (2 apps)");

        let include_item = split_tunnel_item(&include_cfg);
        assert_eq!(include_item.title, "Split tunneling · Include (1 app)");

        let states = [
            ServiceState::NotInstalled,
            ServiceState::Running,
            ServiceState::Stopped,
        ];
        let installs = [
            None,
            Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
        ];
        let lives = [None, Some(sample_live_proxy_engine())];

        for service_state in states {
            for installed in &installs {
                for live_engine in &lives {
                    let status = ControlCenterStatus {
                        installed: installed.clone(),
                        service_state,
                        live_engine: live_engine.clone(),
                        configured_engine: EngineMode::Proxy,
                        vpn_conflict: None,
                    };
                    let menu =
                        build_menu_with_options(&status, None, DNS_PRESETS[0].addr, &exclude_cfg);
                    assert!(
                        menu.items.len() <= 9,
                        "branch ({installed:?}, {service_state:?}, live={}) exceeded 9 items: {}",
                        live_engine.is_some(),
                        menu.items.len()
                    );
                    let split = menu
                        .items
                        .iter()
                        .find(|item| item.choice == Choice::SplitTunnel)
                        .expect("every menu branch must include Choice::SplitTunnel");
                    assert_eq!(split.title, "Split tunneling · Exclude (2 apps)");
                }
            }
        }
    }
}
