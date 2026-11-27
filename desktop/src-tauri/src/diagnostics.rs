use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
use vdpi_core::config::{RuntimeConfig, VpnCoexistence};
use vdpi_core::dns::{
    effective_enable_doh, is_effective_doh_target, redact_dns_for_display, redact_urls_in_text,
    DnsResolver,
};

#[cfg(any(target_os = "windows", test))]
use crate::models::{LiveTelemetryDto, WintunStatusDto};
use crate::models::{
    CliVersionRelationDto, DesktopStatusSnapshotDto, DiagStatusDto, DiagnosticCheckItemDto,
    DiagnosticsReportDto, EngineModeDto, ServiceStateDto, SplitTunnelModeDto,
};

const DIAG_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_PROBE_REQWEST_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_PROBE_OUTER_TIMEOUT: Duration = Duration::from_secs(6);
const DEFAULT_DNS_ADDR: &str = "1.1.1.1";
const DNS_PROBE_HOST: &str = "discord.com";
const DISCORD_GATEWAY_URL: &str = "https://discord.com/api/v10/gateway";
const DISCORD_GATEWAY_TARGET: &str = "discord.com/api/v10/gateway";
const ROBLOX_CLIENT_SETTINGS_URL: &str =
    "https://clientsettings.roblox.com/v2/client-version/WindowsPlayer";
const ROBLOX_CLIENT_SETTINGS_TARGET: &str =
    "clientsettings.roblox.com/v2/client-version/WindowsPlayer";
const HIGH_RSS_WARN_KB: u64 = 256 * 1024;
const DIAGNOSTICS_USER_AGENT: &str = concat!("vdpi-desktop/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq)]
enum HttpProbePath {
    Proxy(SocketAddr),
    Tun,
    Direct,
}

impl HttpProbePath {
    fn description(&self) -> String {
        match self {
            Self::Proxy(addr) => format!("Via local proxy {addr}"),
            Self::Tun => "Via active TUN engine".to_string(),
            Self::Direct => {
                "Direct (vdpi not running - anti-DPI bypass not tested)".to_string()
            }
        }
    }

    fn is_direct(&self) -> bool {
        matches!(self, Self::Direct)
    }
}

/// Runs fast, real, non-destructive desktop diagnostic checks concurrently with
/// strict 5-second timeouts and produces a strictly redacted report.
pub async fn run_desktop_diagnostics(status: &DesktopStatusSnapshotDto) -> DiagnosticsReportDto {
    let config_path = status.config_path.clone();
    let service_mode = status.service_state != ServiceStateDto::NotInstalled;
    let cfg = tokio::time::timeout(
        DIAG_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            load_runtime_config_from_path(&config_path, service_mode)
        }),
    )
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or_default();

    let probe_path = resolve_http_probe_path(status);

    let (vpn_check, dns_check, discord_check, roblox_check) = tokio::join!(
        run_vpn_coexistence_check(status, cfg.vpn_coexistence),
        run_dns_check(&cfg),
        run_http_reachability_check(
            "discord_gateway",
            "Discord Web & Gateway",
            DISCORD_GATEWAY_URL,
            DISCORD_GATEWAY_TARGET,
            &probe_path,
        ),
        run_http_reachability_check(
            "roblox_clientsettings",
            "Roblox ClientSettings",
            ROBLOX_CLIENT_SETTINGS_URL,
            ROBLOX_CLIENT_SETTINGS_TARGET,
            &probe_path,
        ),
    );

    let checks = vec![
        vpn_check,
        #[cfg(target_os = "windows")]
        evaluate_wintun_check(
            &status.wintun,
            status.configured_engine,
            status.live.as_ref(),
        ),
        dns_check,
        discord_check,
        roblox_check,
        evaluate_service_hygiene_check(status),
    ];

    build_diagnostics_report(status, now_epoch_ms(), checks)
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

fn load_runtime_config_from_path(config_path: &str, service_mode: bool) -> RuntimeConfig {
    let mut runtime = RuntimeConfig::default();
    let trimmed = config_path.trim();
    let explicit = Path::new(trimmed);
    let loaded = if !trimmed.is_empty() && explicit.exists() {
        vdpi::config_file::load_file_config_or_default(Some(explicit), service_mode)
    } else {
        vdpi::config_file::load_file_config_or_default(None, service_mode)
    };
    if let Ok((_, file_cfg)) = loaded {
        file_cfg.apply_to_runtime(&mut runtime);
    }
    runtime
}

/// Strips ANSI CSI escapes and collapses control characters / newlines into single spaces.
fn sanitize_single_line(raw: &str) -> String {
    let mut cleaned = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let mut last_space = true;

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            if chars.peek() == Some(&'[') {
                let _ = chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        if ch.is_control() || ch.is_whitespace() {
            if !last_space {
                cleaned.push(' ');
                last_space = true;
            }
            continue;
        }
        cleaned.push(ch);
        last_space = false;
    }

    if cleaned.ends_with(' ') {
        cleaned.pop();
    }
    cleaned
}

fn format_version_bare(raw: &str) -> String {
    let trimmed = raw.trim();
    trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed)
        .to_string()
}

fn format_version_v(raw: &str) -> String {
    let bare = format_version_bare(raw);
    if bare.is_empty() {
        "v0.0.0".to_string()
    } else {
        format!("v{bare}")
    }
}

fn format_rss_label(rss_kb: u64) -> String {
    if rss_kb < 1024 {
        format!("{rss_kb} KB RSS")
    } else {
        let mb = (rss_kb as f64) / 1024.0;
        format!("{mb:.1} MB RSS")
    }
}

fn engine_label(engine: EngineModeDto) -> &'static str {
    match engine {
        EngineModeDto::Tun => "TUN",
        EngineModeDto::Proxy => "Proxy",
    }
}

fn service_state_label(state: ServiceStateDto) -> &'static str {
    match state {
        ServiceStateDto::Running => "Running",
        ServiceStateDto::Stopped => "Stopped",
        ServiceStateDto::NotInstalled => "Not installed",
    }
}

fn vpn_coexistence_label(mode: VpnCoexistence) -> &'static str {
    match mode {
        VpnCoexistence::AutoYield => "Auto-Yield",
        VpnCoexistence::Warn => "Warn",
        VpnCoexistence::Off => "Off",
    }
}

fn format_split_tunnel_summary(status: &DesktopStatusSnapshotDto) -> String {
    let noun = if status.split_tunnel_count == 1 {
        "app"
    } else {
        "apps"
    };
    match status.split_tunnel_mode {
        SplitTunnelModeDto::All => "All apps".to_string(),
        SplitTunnelModeDto::Exclude => format!("Exclude ({} {noun})", status.split_tunnel_count),
        SplitTunnelModeDto::Include => format!("Include ({} {noun})", status.split_tunnel_count),
    }
}

fn normalize_loopback_ip(ip: IpAddr) -> Option<IpAddr> {
    let canonical = ip.to_canonical();
    match canonical {
        IpAddr::V4(v4) if v4.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        addr if addr.is_loopback() => Some(addr),
        _ => None,
    }
}

fn parse_loopback_proxy_addr(raw_addr: &str, port: u16) -> Option<SocketAddr> {
    if port == 0 {
        return None;
    }
    let trimmed = raw_addr.trim();
    if trimmed.eq_ignore_ascii_case("localhost") {
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    let ip: IpAddr = trimmed.parse().ok()?;
    let normalized = normalize_loopback_ip(ip)?;
    Some(SocketAddr::new(normalized, port))
}

fn resolve_http_probe_path(status: &DesktopStatusSnapshotDto) -> HttpProbePath {
    match status.live.as_ref().filter(|live| live.running) {
        Some(live) if live.engine == EngineModeDto::Proxy => {
            if let Some(proxy_addr) = parse_loopback_proxy_addr(&live.addr, live.port) {
                HttpProbePath::Proxy(proxy_addr)
            } else {
                HttpProbePath::Direct
            }
        }
        Some(live) if live.engine == EngineModeDto::Tun => HttpProbePath::Tun,
        _ => HttpProbePath::Direct,
    }
}

// ============================================================================
// Check 1: VPN Coexistence
// ============================================================================

async fn run_vpn_coexistence_check(
    status: &DesktopStatusSnapshotDto,
    coexistence: VpnCoexistence,
) -> DiagnosticCheckItemDto {
    let started = Instant::now();
    let self_tun_name = status
        .live
        .as_ref()
        .and_then(|live| live.tun_interface.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let probe = tokio::time::timeout(
        DIAG_TIMEOUT,
        tokio::task::spawn_blocking(move || detect_active_vpn(self_tun_name.as_deref())),
    )
    .await;

    let latency_ms = Some(elapsed_ms(started));
    let split_label = format_split_tunnel_summary(status);

    match probe {
        Ok(Ok(scope)) => evaluate_vpn_scope(&scope, coexistence, &split_label, latency_ms),
        Ok(Err(err)) => DiagnosticCheckItemDto {
            id: "vpn_coexistence".to_string(),
            name: "VPN Coexistence".to_string(),
            target: "Routing table & adapters".to_string(),
            status: DiagStatusDto::Warn,
            latency_ms,
            summary: "VPN detection task failed".to_string(),
            detail: Some(sanitize_single_line(&redact_urls_in_text(&err.to_string()))),
        },
        Err(_) => DiagnosticCheckItemDto {
            id: "vpn_coexistence".to_string(),
            name: "VPN Coexistence".to_string(),
            target: "Routing table & adapters".to_string(),
            status: DiagStatusDto::Warn,
            latency_ms,
            summary: "VPN detection timed out".to_string(),
            detail: Some(format!(
                "Adapter & route probe did not complete within {}s",
                DIAG_TIMEOUT.as_secs()
            )),
        },
    }
}

fn evaluate_vpn_scope(
    scope: &VpnScope,
    coexistence: VpnCoexistence,
    split_label: &str,
    latency_ms: Option<u64>,
) -> DiagnosticCheckItemDto {
    let mode_label = vpn_coexistence_label(coexistence);

    if coexistence == VpnCoexistence::Off {
        match scope {
            VpnScope::FullTunnel {
                provider,
                iface,
                kill_switch,
            } => {
                let mut desc = if iface.trim().is_empty() {
                    sanitize_single_line(provider)
                } else {
                    format!(
                        "{} ({})",
                        sanitize_single_line(provider),
                        sanitize_single_line(iface)
                    )
                };
                if *kill_switch {
                    desc.push_str(" [kill-switch]");
                }
                return DiagnosticCheckItemDto {
                    id: "vpn_coexistence".to_string(),
                    name: "VPN Coexistence".to_string(),
                    target: "Routing table & adapters".to_string(),
                    status: DiagStatusDto::Warn,
                    latency_ms,
                    summary: format!("Full-tunnel VPN active while coexistence is off: {desc}"),
                    detail: Some(format!(
                        "VPN coexistence detection is disabled in configuration - active full-tunnel VPN may conflict with vdpi · Split tunnel: {split_label}"
                    )),
                };
            }
            VpnScope::SplitOverlay { providers } => {
                return DiagnosticCheckItemDto {
                    id: "vpn_coexistence".to_string(),
                    name: "VPN Coexistence".to_string(),
                    target: "Routing table & adapters".to_string(),
                    status: DiagStatusDto::Pass,
                    latency_ms,
                    summary: format!("VPN check off · {split_label}"),
                    detail: Some(format!(
                        "VPN coexistence detection is disabled (split overlay: {}).",
                        sanitize_single_line(&providers.join(", "))
                    )),
                };
            }
            VpnScope::None => {
                return DiagnosticCheckItemDto {
                    id: "vpn_coexistence".to_string(),
                    name: "VPN Coexistence".to_string(),
                    target: "Routing table & adapters".to_string(),
                    status: DiagStatusDto::Pass,
                    latency_ms,
                    summary: format!("VPN check off · {split_label}"),
                    detail: Some(
                        "VPN coexistence detection is disabled in configuration.".to_string(),
                    ),
                };
            }
        }
    }

    match scope {
        VpnScope::FullTunnel {
            provider,
            iface,
            kill_switch,
        } => {
            let mut desc = if iface.trim().is_empty() {
                sanitize_single_line(provider)
            } else {
                format!(
                    "{} ({})",
                    sanitize_single_line(provider),
                    sanitize_single_line(iface)
                )
            };
            if *kill_switch {
                desc.push_str(" [kill-switch]");
            }
            DiagnosticCheckItemDto {
                id: "vpn_coexistence".to_string(),
                name: "VPN Coexistence".to_string(),
                target: "Routing table & adapters".to_string(),
                status: DiagStatusDto::Warn,
                latency_ms,
                summary: format!("Full-tunnel VPN conflict: {desc}"),
                detail: Some(format!(
                    "Coexistence: {mode_label} · Split tunnel: {split_label}"
                )),
            }
        }
        VpnScope::SplitOverlay { providers } => {
            let list = sanitize_single_line(&providers.join(", "));
            DiagnosticCheckItemDto {
                id: "vpn_coexistence".to_string(),
                name: "VPN Coexistence".to_string(),
                target: "Routing table & adapters".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms,
                summary: format!("Split-tunnel overlay ({list}) · {split_label}"),
                detail: Some(format!(
                    "Overlay does not own the global default route · Coexistence: {mode_label}"
                )),
            }
        }
        VpnScope::None => DiagnosticCheckItemDto {
            id: "vpn_coexistence".to_string(),
            name: "VPN Coexistence".to_string(),
            target: "Routing table & adapters".to_string(),
            status: DiagStatusDto::Pass,
            latency_ms,
            summary: format!("No VPN conflict · {split_label}"),
            detail: Some(format!("Coexistence: {mode_label}")),
        },
    }
}

// ============================================================================
// Check 2: Wintun Driver (Windows only)
// ============================================================================

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_check(
    wintun: &WintunStatusDto,
    configured_engine: EngineModeDto,
    live: Option<&LiveTelemetryDto>,
) -> DiagnosticCheckItemDto {
    let tun_needed = wintun.required
        || configured_engine == EngineModeDto::Tun
        || live.is_some_and(|l| l.running && l.engine == EngineModeDto::Tun);
    let cleaned_msg = wintun
        .message
        .as_deref()
        .map(|m| sanitize_single_line(&redact_urls_in_text(m)))
        .filter(|s| !s.is_empty());

    if wintun.ready {
        let tun_active = live.is_some_and(|l| l.running && l.engine == EngineModeDto::Tun);
        let runtime_note = if tun_active {
            None
        } else if live.is_some_and(|l| l.running) {
            Some("Proxy mode active - TUN adapter load not tested".to_string())
        } else {
            Some("Service not running - driver load and adapter creation not tested".to_string())
        };

        let summary = if tun_active {
            format!(
                "wintun.dll v{} SHA-256 verified (TUN active)",
                vdpi::platform::windows_tun::WINTUN_VERSION
            )
        } else {
            format!(
                "wintun.dll v{} SHA-256 verified on disk",
                vdpi::platform::windows_tun::WINTUN_VERSION
            )
        };

        let detail = match (cleaned_msg, runtime_note) {
            (Some(msg), Some(note)) => Some(format!("{msg} · {note}")),
            (Some(msg), None) => Some(msg),
            (None, Some(note)) => Some(note),
            (None, None) => None,
        };

        return DiagnosticCheckItemDto {
            id: "wintun_driver".to_string(),
            name: "Wintun Driver (wintun.dll)".to_string(),
            target: "wintun.dll".to_string(),
            status: DiagStatusDto::Pass,
            latency_ms: None,
            summary,
            detail,
        };
    }

    let hash_mismatch = cleaned_msg.as_deref().is_some_and(|msg| {
        let lower = msg.to_ascii_lowercase();
        lower.contains("sha-256") || lower.contains("hash") || lower.contains("mismatch")
    });

    let detail = cleaned_msg.or_else(|| {
        Some("Extract all files from the release archive (keep wintun.dll beside vdpi.exe).".to_string())
    });

    if tun_needed {
        DiagnosticCheckItemDto {
            id: "wintun_driver".to_string(),
            name: "Wintun Driver (wintun.dll)".to_string(),
            target: "wintun.dll".to_string(),
            status: DiagStatusDto::Fail,
            latency_ms: None,
            summary: if hash_mismatch {
                "wintun.dll corrupted or mismatched (required for TUN)".to_string()
            } else {
                "wintun.dll missing or invalid (required for TUN)".to_string()
            },
            detail,
        }
    } else {
        DiagnosticCheckItemDto {
            id: "wintun_driver".to_string(),
            name: "Wintun Driver (wintun.dll)".to_string(),
            target: "wintun.dll".to_string(),
            status: DiagStatusDto::Warn,
            latency_ms: None,
            summary: if hash_mismatch {
                "wintun.dll corrupted or mismatched (Proxy ok; needed for TUN)".to_string()
            } else {
                "wintun.dll missing or invalid (Proxy ok; needed for TUN)".to_string()
            },
            detail,
        }
    }
}

// ============================================================================
// Check 3: Active DNS / DoH Resolution
// ============================================================================

fn doh_check_target(cfg: &RuntimeConfig) -> (String, String, &'static str, bool) {
    let dns_addr = if cfg.dns_addr.trim().is_empty() {
        DEFAULT_DNS_ADDR.to_string()
    } else {
        cfg.dns_addr.trim().to_string()
    };
    let dns_display = sanitize_single_line(&redact_dns_for_display(&dns_addr));
    let effective_doh = effective_enable_doh(&dns_addr, cfg.enable_doh);
    let transport = if is_effective_doh_target(&dns_addr, cfg.enable_doh) {
        "DoH"
    } else {
        "UDP"
    };
    (dns_addr, dns_display, transport, effective_doh)
}

fn diag_dns_check_name(cfg: &RuntimeConfig) -> &'static str {
    let (_, _, transport, _) = doh_check_target(cfg);
    if transport == "DoH" {
        "Encrypted DNS (DoH)"
    } else {
        "DNS Resolution (UDP)"
    }
}

fn sanitize_dns_error_detail(raw_err: &str, dns_addr: &str, dns_display: &str) -> String {
    let direct_redacted = if !dns_addr.is_empty() && dns_addr != dns_display {
        raw_err.replace(dns_addr, dns_display)
    } else {
        raw_err.to_string()
    };
    let url_redacted = redact_urls_in_text(&direct_redacted);
    sanitize_single_line(&url_redacted)
}

fn format_dns_init_error(
    check_name: &str,
    dns_addr: &str,
    dns_display: &str,
    raw_err: &str,
    latency_ms: u64,
) -> DiagnosticCheckItemDto {
    DiagnosticCheckItemDto {
        id: "dns_resolution".to_string(),
        name: check_name.to_string(),
        target: dns_display.to_string(),
        status: DiagStatusDto::Fail,
        latency_ms: Some(latency_ms),
        summary: format!("Resolver init failed ({dns_display})"),
        detail: Some(sanitize_dns_error_detail(raw_err, dns_addr, dns_display)),
    }
}

fn evaluate_dns_outcome(
    check_name: &str,
    dns_addr: &str,
    dns_display: &str,
    transport: &str,
    outcome: Result<Result<Vec<IpAddr>, String>, ()>,
    latency_ms: u64,
) -> DiagnosticCheckItemDto {
    match outcome {
        Ok(Ok(ips)) if !ips.is_empty() => {
            let first = ips[0].to_string();
            let noun = if ips.len() == 1 { "IP" } else { "IPs" };
            DiagnosticCheckItemDto {
                id: "dns_resolution".to_string(),
                name: check_name.to_string(),
                target: dns_display.to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: Some(latency_ms),
                summary: format!("{DNS_PROBE_HOST} resolved ({} {noun})", ips.len()),
                detail: Some(format!("{transport} via {dns_display} · {first}")),
            }
        }
        Ok(Ok(_)) => DiagnosticCheckItemDto {
            id: "dns_resolution".to_string(),
            name: check_name.to_string(),
            target: dns_display.to_string(),
            status: DiagStatusDto::Fail,
            latency_ms: Some(latency_ms),
            summary: "No IP addresses returned".to_string(),
            detail: Some(format!("{transport} via {dns_display}")),
        },
        Ok(Err(err)) => DiagnosticCheckItemDto {
            id: "dns_resolution".to_string(),
            name: check_name.to_string(),
            target: dns_display.to_string(),
            status: DiagStatusDto::Fail,
            latency_ms: Some(latency_ms),
            summary: format!("{transport} lookup failed"),
            detail: Some(sanitize_dns_error_detail(&err, dns_addr, dns_display)),
        },
        Err(()) => DiagnosticCheckItemDto {
            id: "dns_resolution".to_string(),
            name: check_name.to_string(),
            target: dns_display.to_string(),
            status: DiagStatusDto::Fail,
            latency_ms: Some(latency_ms),
            summary: format!("{transport} lookup timed out"),
            detail: Some(format!(
                "No reply from {dns_display} within {}s",
                DIAG_TIMEOUT.as_secs()
            )),
        },
    }
}

async fn run_dns_check(cfg: &RuntimeConfig) -> DiagnosticCheckItemDto {
    let check_name = diag_dns_check_name(cfg);
    let (dns_addr, dns_display, transport, effective_doh) = doh_check_target(cfg);
    let started = Instant::now();

    let resolver =
        match DnsResolver::new(&dns_addr, cfg.dns_port, effective_doh, cfg.dns_ipv4_only) {
            Ok(r) => r,
            Err(err) => {
                return format_dns_init_error(
                    check_name,
                    &dns_addr,
                    &dns_display,
                    &format!("{err:#}"),
                    elapsed_ms(started),
                );
            }
        };

    let outcome = tokio::time::timeout(DIAG_TIMEOUT, resolver.resolve(DNS_PROBE_HOST))
        .await
        .map(|res| res.map_err(|err| format!("{err:#}")))
        .map_err(|_| ());

    evaluate_dns_outcome(
        check_name,
        &dns_addr,
        &dns_display,
        transport,
        outcome,
        elapsed_ms(started),
    )
}

// ============================================================================
// Checks 4 & 5: Discord Gateway & Roblox ClientSettings Reachability
// ============================================================================

fn build_http_probe_client(path: &HttpProbePath) -> Result<reqwest::Client, String> {
    let builder = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(HTTP_PROBE_REQWEST_TIMEOUT)
        .timeout(HTTP_PROBE_REQWEST_TIMEOUT)
        .user_agent(DIAGNOSTICS_USER_AGENT);

    let builder = match path {
        HttpProbePath::Proxy(proxy_addr) => {
            let proxy_url = format!("http://{proxy_addr}");
            let proxy = reqwest::Proxy::https(&proxy_url)
                .map_err(|err| format!("invalid local proxy URL: {err}"))?;
            builder.proxy(proxy)
        }
        HttpProbePath::Tun | HttpProbePath::Direct => builder.no_proxy(),
    };

    builder.build().map_err(|err| err.to_string())
}

enum HttpProbeOutcome {
    Response(u16),
    TimedOut,
    Failed(String),
}

fn evaluate_http_probe_outcome(
    id: &str,
    name: &str,
    display_target: &str,
    path: &HttpProbePath,
    outcome: HttpProbeOutcome,
    latency_ms: Option<u64>,
) -> DiagnosticCheckItemDto {
    let path_desc = path.description();

    match outcome {
        HttpProbeOutcome::Response(code) if (200..300).contains(&code) => {
            if path.is_direct() {
                DiagnosticCheckItemDto {
                    id: id.to_string(),
                    name: name.to_string(),
                    target: display_target.to_string(),
                    status: DiagStatusDto::Warn,
                    latency_ms,
                    summary: format!("Reachable directly (HTTP {code}) - bypass not tested"),
                    detail: Some(path_desc),
                }
            } else {
                DiagnosticCheckItemDto {
                    id: id.to_string(),
                    name: name.to_string(),
                    target: display_target.to_string(),
                    status: DiagStatusDto::Pass,
                    latency_ms,
                    summary: format!("Reachable (HTTP {code})"),
                    detail: Some(path_desc),
                }
            }
        }
        HttpProbeOutcome::Response(code) if (300..400).contains(&code) => {
            DiagnosticCheckItemDto {
                id: id.to_string(),
                name: name.to_string(),
                target: display_target.to_string(),
                status: DiagStatusDto::Warn,
                latency_ms,
                summary: format!("Unexpected redirect (HTTP {code}, possible captive portal)"),
                detail: Some(path_desc),
            }
        }
        HttpProbeOutcome::Response(code) => DiagnosticCheckItemDto {
            id: id.to_string(),
            name: name.to_string(),
            target: display_target.to_string(),
            status: DiagStatusDto::Warn,
            latency_ms,
            summary: format!("TLS verified, unexpected HTTP {code}"),
            detail: Some(path_desc),
        },
        HttpProbeOutcome::Failed(err) => DiagnosticCheckItemDto {
            id: id.to_string(),
            name: name.to_string(),
            target: display_target.to_string(),
            status: DiagStatusDto::Fail,
            latency_ms,
            summary: "Reachability check failed".to_string(),
            detail: Some(format!(
                "{path_desc} · {}",
                sanitize_single_line(&redact_urls_in_text(&err))
            )),
        },
        HttpProbeOutcome::TimedOut => DiagnosticCheckItemDto {
            id: id.to_string(),
            name: name.to_string(),
            target: display_target.to_string(),
            status: DiagStatusDto::Fail,
            latency_ms,
            summary: format!("Timed out after {}s", HTTP_PROBE_REQWEST_TIMEOUT.as_secs()),
            detail: Some(path_desc),
        },
    }
}

async fn run_http_reachability_check(
    id: &str,
    name: &str,
    url: &str,
    display_target: &str,
    path: &HttpProbePath,
) -> DiagnosticCheckItemDto {
    let started = Instant::now();

    let client = match build_http_probe_client(path) {
        Ok(c) => c,
        Err(err) => {
            return DiagnosticCheckItemDto {
                id: id.to_string(),
                name: name.to_string(),
                target: display_target.to_string(),
                status: DiagStatusDto::Fail,
                latency_ms: Some(elapsed_ms(started)),
                summary: "HTTPS client unavailable".to_string(),
                detail: Some(sanitize_single_line(&redact_urls_in_text(&err))),
            };
        }
    };

    let outcome = tokio::time::timeout(HTTP_PROBE_OUTER_TIMEOUT, client.get(url).send()).await;
    let latency = Some(elapsed_ms(started));

    let probe_outcome = match outcome {
        Ok(Ok(resp)) => HttpProbeOutcome::Response(resp.status().as_u16()),
        Ok(Err(err)) if err.is_timeout() => HttpProbeOutcome::TimedOut,
        Ok(Err(err)) => HttpProbeOutcome::Failed(err.to_string()),
        Err(_) => HttpProbeOutcome::TimedOut,
    };

    evaluate_http_probe_outcome(id, name, display_target, path, probe_outcome, latency)
}

// ============================================================================
// Check 6: Service & Runtime Hygiene
// ============================================================================

fn evaluate_service_hygiene_check(status: &DesktopStatusSnapshotDto) -> DiagnosticCheckItemDto {
    let target = format!("{} service", engine_label(status.configured_engine));
    let config_warning = status
        .config_warning
        .as_deref()
        .map(|w| sanitize_single_line(&redact_urls_in_text(w)))
        .filter(|s| !s.is_empty());

    if let Some(live) = status.live.as_ref().filter(|l| l.running) {
        let active_label = match live.engine {
            EngineModeDto::Tun => {
                if let Some(iface) = live
                    .tun_interface
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    format!("TUN active ({})", sanitize_single_line(iface))
                } else {
                    "TUN active".to_string()
                }
            }
            EngineModeDto::Proxy => {
                if let Some(sock) = parse_loopback_proxy_addr(&live.addr, live.port) {
                    format!("Proxy active ({sock})")
                } else {
                    format!(
                        "Proxy active ({}:{})",
                        sanitize_single_line(&live.addr),
                        live.port
                    )
                }
            }
        };

        let mut parts: Vec<String> = Vec::new();
        if let Some(ver) = live
            .version
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            parts.push(format_version_v(ver));
        }
        if let Some(rss) = live.rss_kb {
            parts.push(format_rss_label(rss));
        }
        if let Some(mode) = live
            .mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            parts.push(format!("desync {}", sanitize_single_line(mode)));
        }

        let engine_mismatch = live.engine != status.configured_engine;
        let version_mismatch = match (
            status
                .installed_version
                .as_deref()
                .map(format_version_bare)
                .filter(|s| !s.is_empty()),
            live.version
                .as_deref()
                .map(format_version_bare)
                .filter(|s| !s.is_empty()),
        ) {
            (Some(inst), Some(running)) => inst != running,
            _ => false,
        };
        let orphaned_live = status.service_state != ServiceStateDto::Running;
        let high_rss = live.rss_kb.filter(|&kb| kb >= HIGH_RSS_WARN_KB);

        let mut warnings: Vec<String> = Vec::new();

        if engine_mismatch {
            warnings.push(format!(
                "Engine mismatch: configured {}, live {}",
                engine_label(status.configured_engine),
                engine_label(live.engine)
            ));
            parts.push("restart service to apply configured engine".to_string());
        }

        if version_mismatch {
            let inst = format_version_v(status.installed_version.as_deref().unwrap_or_default());
            let running = format_version_v(live.version.as_deref().unwrap_or_default());
            warnings.push(format!(
                "Version mismatch: installed {inst}, live {running}"
            ));
            parts.push("restart service to load installed version".to_string());
        }

        if orphaned_live {
            let state_label = service_state_label(status.service_state);
            warnings.push(format!(
                "Orphaned live process (service {})",
                state_label.to_ascii_lowercase()
            ));
            parts.push(format!(
                "live engine running while service state is {state_label}"
            ));
        }

        if let Some(rss_kb) = high_rss {
            warnings.push(format!("elevated memory ({})", format_rss_label(rss_kb)));
            parts.push("RSS exceeds 256 MB threshold".to_string());
        }

        if let Some(warn) = config_warning {
            warnings.push("config warning".to_string());
            parts.push(format!("Config warning: {warn}"));
        }

        if status.cli_version_relation == CliVersionRelationDto::RepairNeeded {
            if warnings.is_empty() {
                return DiagnosticCheckItemDto {
                    id: "service_hygiene".to_string(),
                    name: "Service & Runtime Hygiene".to_string(),
                    target,
                    status: DiagStatusDto::Warn,
                    latency_ms: None,
                    summary: "Background service needs repair".to_string(),
                    detail: Some(
                        "Installed CLI binary could not be verified on disk while the service is registered. Open Installation and run Repair / Reinstall."
                            .to_string(),
                    ),
                };
            }
            warnings.push("Background service needs repair".to_string());
            parts.push(
                "Installed CLI binary could not be verified on disk while the service is registered. Open Installation and run Repair / Reinstall."
                    .to_string(),
            );
        }

        if !warnings.is_empty() {
            let summary = if warnings.len() == 1 && !engine_mismatch && !version_mismatch {
                format!("{active_label} · {}", warnings[0])
            } else {
                warnings.join(" · ")
            };
            return DiagnosticCheckItemDto {
                id: "service_hygiene".to_string(),
                name: "Service & Runtime Hygiene".to_string(),
                target,
                status: DiagStatusDto::Warn,
                latency_ms: None,
                summary,
                detail: Some(parts.join(" · ")),
            };
        }

        return DiagnosticCheckItemDto {
            id: "service_hygiene".to_string(),
            name: "Service & Runtime Hygiene".to_string(),
            target,
            status: DiagStatusDto::Pass,
            latency_ms: None,
            summary: active_label,
            detail: if parts.is_empty() {
                None
            } else {
                Some(parts.join(" · "))
            },
        };
    }

    let vpn_conflict = status
        .vpn_conflict
        .as_deref()
        .map(|v| sanitize_single_line(&redact_urls_in_text(v)))
        .filter(|s| !s.is_empty());

    let (check_status, summary, base_detail) = match status.service_state {
        ServiceStateDto::Running | ServiceStateDto::Stopped
            if status.cli_version_relation == CliVersionRelationDto::RepairNeeded =>
        {
            (
                DiagStatusDto::Warn,
                "Background service needs repair".to_string(),
                "Installed CLI binary could not be verified on disk while the service is registered. Open Installation and run Repair / Reinstall."
                    .to_string(),
            )
        }
        ServiceStateDto::Running if status.live.is_none() && vpn_conflict.is_some() => {
            let vpn = vpn_conflict.unwrap();
            (
                DiagStatusDto::Warn,
                format!(
                    "{} service running (protection paused - VPN conflict: {vpn})",
                    engine_label(status.configured_engine)
                ),
                format!(
                    "Background service is running, but protection is yielded while active VPN ({vpn}) is connected."
                ),
            )
        }
        ServiceStateDto::Running => (
            DiagStatusDto::Warn,
            format!(
                "{} service running (live telemetry unavailable)",
                engine_label(status.configured_engine)
            ),
            "Background service reports Running, but the health endpoint returned no active engine."
                .to_string(),
        ),
        ServiceStateDto::Stopped => (
            DiagStatusDto::Warn,
            "Service stopped (standby)".to_string(),
            format!(
                "Configured engine: {}. Start vdpi to enable protection.",
                engine_label(status.configured_engine)
            ),
        ),
        ServiceStateDto::NotInstalled if !status.can_install_from_bundle => (
            DiagStatusDto::Fail,
            "Service not installed · Bundled vdpi CLI missing".to_string(),
            "The bundled vdpi CLI engine binary was not found in the application directory. Reinstall vdpi Desktop, extract all files from the archive, or check antivirus quarantine before installing the service."
                .to_string(),
        ),
        ServiceStateDto::NotInstalled => (
            DiagStatusDto::Warn,
            "Service not installed (standby)".to_string(),
            "Checks ran over your direct connection until the vdpi service is installed and active."
                .to_string(),
        ),
    };

    let detail = match config_warning {
        Some(warn) => format!("{base_detail} · Config warning: {warn}"),
        None => base_detail,
    };

    DiagnosticCheckItemDto {
        id: "service_hygiene".to_string(),
        name: "Service & Runtime Hygiene".to_string(),
        target,
        status: check_status,
        latency_ms: None,
        summary,
        detail: Some(detail),
    }
}

// ============================================================================
// Report Assembly & Guaranteed URL Redaction
// ============================================================================

fn sanitize_check_item(mut item: DiagnosticCheckItemDto) -> DiagnosticCheckItemDto {
    item.name = sanitize_single_line(&redact_urls_in_text(&item.name));
    item.target = sanitize_single_line(&redact_urls_in_text(&item.target));
    item.summary = sanitize_single_line(&redact_urls_in_text(&item.summary));
    item.detail = item
        .detail
        .map(|d| sanitize_single_line(&redact_urls_in_text(&d)))
        .filter(|d| !d.is_empty());
    item
}

fn status_badge(status: DiagStatusDto) -> &'static str {
    match status {
        DiagStatusDto::Pass => "PASS",
        DiagStatusDto::Warn => "WARN",
        DiagStatusDto::Fail => "FAIL",
        DiagStatusDto::Running => "RUN",
        DiagStatusDto::Idle => "IDLE",
    }
}

/// Converts Unix epoch milliseconds to an ISO-8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
/// using Howard Hinnant's pure-integer `civil_from_days` conversion.
fn format_utc_iso8601(epoch_ms: u64) -> String {
    let total_secs = epoch_ms / 1_000;
    let secs_of_day = (total_secs % 86_400) as u32;
    let days_since_epoch = (total_secs / 86_400) as i64;

    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = if m <= 2 { y + 1 } else { y };

    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn is_path_prefix_boundary(prev: Option<char>) -> bool {
    match prev {
        None => true,
        Some(ch) => !(ch.is_alphanumeric() || matches!(ch, '_' | '-' | '\\' | '.')),
    }
}

fn is_username_hard_stop_char(ch: char) -> bool {
    ch.is_control()
        || (ch.is_whitespace() && ch != ' ')
        || matches!(
            ch,
            '"' | '('
                | ')'
                | '['
                | ']'
                | '<'
                | '>'
                | ','
                | ';'
                | ':'
                | '|'
                | '?'
                | '*'
                | '·'
                | '\u{2014}'
        )
}

fn is_apostrophe_stop(prev_before_prefix: Option<char>, after_prefix: &str, idx: usize) -> bool {
    match after_prefix[idx + 1..].chars().next() {
        None => true,
        Some(c) if c.is_whitespace() || is_username_hard_stop_char(c) => true,
        Some('/' | '\\') => prev_before_prefix == Some('\''),
        Some(_) => false,
    }
}

fn match_home_prefix(s: &str) -> Option<(usize, char)> {
    let (unc_len, tail) = if let Some(stripped) = s.strip_prefix(r"\\?\") {
        (4usize, stripped)
    } else {
        (0usize, s)
    };

    // Windows: `<Drive>:\Users\` or `<Drive>:/Users/` (case-insensitive).
    let bytes = tail.as_bytes();
    if bytes.len() >= 9
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
        && tail
            .get(3..8)
            .is_some_and(|seg| seg.eq_ignore_ascii_case("users"))
        && (bytes[8] == b'\\' || bytes[8] == b'/')
    {
        return Some((unc_len + 9, bytes[8] as char));
    }

    if unc_len > 0 {
        return None;
    }

    // macOS: `/Users/`
    if s.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("/Users/")) {
        return Some((7, '/'));
    }

    // Linux: `/home/`
    if s.starts_with("/home/") {
        return Some((6, '/'));
    }

    None
}

/// Scrubs Windows (`C:\Users\<user>...`), macOS (`/Users/<user>...`), and Linux
/// (`/home/<user>...`) home directory prefixes to `[USER_HOME]...`, including
/// multi-word OS usernames containing spaces when followed by a matching path
/// separator and usernames containing apostrophes (e.g. `O'Connor`).
fn scrub_user_home_paths(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while cursor < input.len() {
        let prev_char = input[..cursor].chars().next_back();
        let rest = &input[cursor..];

        let matched_prefix = if is_path_prefix_boundary(prev_char) {
            match_home_prefix(rest)
        } else {
            None
        };

        if let Some((prefix_len, expected_sep)) = matched_prefix {
            let after_prefix = &rest[prefix_len..];
            let mut first_stop = after_prefix.len();
            for (idx, ch) in after_prefix.char_indices() {
                if ch == '/'
                    || ch == '\\'
                    || ch == ' '
                    || is_username_hard_stop_char(ch)
                    || (ch == '\'' && is_apostrophe_stop(prev_char, after_prefix, idx))
                {
                    first_stop = idx;
                    break;
                }
            }

            let mut user_end = first_stop;
            if first_stop > 0 && after_prefix[first_stop..].starts_with(' ') {
                for (rel_idx, ch) in after_prefix[first_stop..].char_indices() {
                    let abs_idx = first_stop + rel_idx;
                    if ch == expected_sep {
                        let candidate = &after_prefix[..abs_idx];
                        if !candidate.ends_with(' ') && !candidate.contains("  ") {
                            user_end = abs_idx;
                        }
                        break;
                    }
                    if ch == '/'
                        || ch == '\\'
                        || is_username_hard_stop_char(ch)
                        || (ch == '\'' && is_apostrophe_stop(prev_char, after_prefix, abs_idx))
                    {
                        break;
                    }
                }
            }

            let followed_by_sep = after_prefix[user_end..]
                .chars()
                .next()
                .is_some_and(|c| c == expected_sep);
            if !followed_by_sep {
                while user_end > 0 && after_prefix.as_bytes()[user_end - 1] == b'.' {
                    user_end -= 1;
                }
            }

            if user_end > 0 {
                out.push_str("[USER_HOME]");
                cursor += prefix_len + user_end;
                continue;
            }
        }

        let ch = rest.chars().next().unwrap();
        out.push(ch);
        cursor += ch.len_utf8();
    }

    out
}

fn is_cgnat_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    a == 100 && (64..=127).contains(&b)
}

fn is_redacted_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || is_cgnat_ipv4(ip)
}

fn parse_ipv4_prefix_len(s: &str) -> Option<(usize, Ipv4Addr)> {
    let bytes = s.as_bytes();
    let mut pos = 0usize;

    for octet_idx in 0..4 {
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() && (pos - start) < 3 {
            pos += 1;
        }
        if pos == start {
            return None;
        }
        if octet_idx < 3 {
            if pos >= bytes.len() || bytes[pos] != b'.' {
                return None;
            }
            pos += 1;
        }
    }

    if let Some(&next) = bytes.get(pos) {
        if next.is_ascii_alphanumeric() || next == b'_' {
            return None;
        }
        if next == b'.' && bytes.get(pos + 1).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }

    let ip: Ipv4Addr = s[..pos].parse().ok()?;
    Some((pos, ip))
}

/// Redacts private RFC1918 (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`),
/// link-local (`169.254.x.x`), and CGNAT/Tailscale (`100.64.0.0/10`) IPv4
/// addresses to `[LAN_IP]` while preserving public resolver IPs (`1.1.1.1`,
/// `9.9.9.9`, `8.8.8.8`, `94.140.14.14`, etc.) and loopback (`127.0.0.1`).
fn redact_private_ipv4_addresses(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while cursor < input.len() {
        let prev_char = input[..cursor].chars().next_back();
        let rest = &input[cursor..];
        let at_boundary = match prev_char {
            None => true,
            Some(ch) => !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_'),
        };

        if at_boundary && rest.as_bytes()[0].is_ascii_digit() {
            if let Some((len, ip)) = parse_ipv4_prefix_len(rest) {
                if is_redacted_ipv4(ip) {
                    out.push_str("[LAN_IP]");
                    cursor += len;
                    continue;
                }
            }
        }

        let ch = rest.chars().next().unwrap();
        out.push(ch);
        cursor += ch.len_utf8();
    }

    out
}

fn is_redacted_ipv6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    // Unique Local Addresses (ULA): fc00::/7 (covers both fc00::/8 and fd00::/8)
    let is_ula = (seg0 & 0xfe00) == 0xfc00;
    // Unicast Link-Local: fe80::/10 (fe80:: through febf::)
    let is_link_local = (seg0 & 0xffc0) == 0xfe80;
    // IPv4-mapped IPv6 addresses (`::ffff:c0a8:0105`, `::ffff:6440:0001`, `::ffff:192.168.1.5`)
    let is_redacted_mapped_v4 = ip.to_ipv4_mapped().is_some_and(is_redacted_ipv4);
    is_ula || is_link_local || is_redacted_mapped_v4
}

fn is_preceding_colon_in_ipv6_context(before_colon: &str) -> bool {
    let Some(last) = before_colon.chars().next_back() else {
        return false;
    };
    if last == ':' {
        return true;
    }
    if !last.is_ascii_hexdigit() {
        return false;
    }
    let prefix = before_colon.trim_end_matches(|c: char| c.is_ascii_alphanumeric() || c == '_');
    let word = &before_colon[prefix.len()..];
    !word.is_empty() && word.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_ipv6_prefix_len(s: &str) -> Option<(usize, Ipv6Addr)> {
    let bytes = s.as_bytes();
    let mut end = 0usize;
    let mut colon_count = 0usize;

    while end < bytes.len() {
        let b = bytes[end];
        if b.is_ascii_hexdigit() || b == b'.' {
            end += 1;
        } else if b == b':' {
            colon_count += 1;
            end += 1;
        } else {
            break;
        }
    }

    if colon_count < 2 || end < 2 {
        return None;
    }

    if let Some(&next) = bytes.get(end) {
        if next.is_ascii_alphanumeric() || next == b'_' {
            return None;
        }
    }

    let mut candidate_end = end;
    loop {
        if candidate_end < 2 {
            return None;
        }
        if let Ok(ip) = s[..candidate_end].parse::<Ipv6Addr>() {
            return Some((candidate_end, ip));
        }
        let last = bytes[candidate_end - 1];
        if last == b'.'
            || (last == b':' && !(candidate_end >= 2 && bytes[candidate_end - 2] == b':'))
        {
            candidate_end -= 1;
        } else {
            return None;
        }
    }
}

/// Redacts private Unique Local (`fc00::/7`, including `fd00::/8`),
/// link-local (`fe80::/10`, including optional `%zone` suffixes), and
/// IPv4-mapped private/link-local/CGNAT (`::ffff:...`) IPv6 addresses to
/// `[LAN_IPV6]` while preserving public IPv6 resolvers (`2606:4700:...`,
/// `2001:4860:...`, `2620:fe::...`, `2a10:50c0::...`) and loopback (`::1`).
fn redact_private_ipv6_addresses(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while cursor < input.len() {
        let prev_char = input[..cursor].chars().next_back();
        let rest = &input[cursor..];
        let at_boundary = match prev_char {
            None => true,
            Some(':') => !is_preceding_colon_in_ipv6_context(&input[..cursor - 1]),
            Some(ch) => !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_'),
        };

        if at_boundary && (rest.as_bytes()[0].is_ascii_hexdigit() || rest.as_bytes()[0] == b':') {
            if let Some((len, ip)) = parse_ipv6_prefix_len(rest) {
                if is_redacted_ipv6(ip) {
                    let mut total_len = len;
                    if rest.as_bytes().get(len) == Some(&b'%') {
                        let zone_tail = &rest[len + 1..];
                        let mut zone_len = 0usize;
                        for (idx, b) in zone_tail.bytes().enumerate() {
                            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
                                zone_len = idx + 1;
                            } else {
                                break;
                            }
                        }
                        while zone_len > 0 && zone_tail.as_bytes()[zone_len - 1] == b'.' {
                            zone_len -= 1;
                        }
                        if zone_len > 0 {
                            total_len += 1 + zone_len;
                        }
                    }
                    out.push_str("[LAN_IPV6]");
                    cursor += total_len;
                    continue;
                }
                out.push_str(&rest[..len]);
                cursor += len;
                continue;
            }
        }

        let ch = rest.chars().next().unwrap();
        out.push(ch);
        cursor += ch.len_utf8();
    }

    out
}

fn redact_report_line(line: &str) -> String {
    let urls_redacted = redact_urls_in_text(line);
    let paths_scrubbed = scrub_user_home_paths(&urls_redacted);
    let ipv6_redacted = redact_private_ipv6_addresses(&paths_scrubbed);
    redact_private_ipv4_addresses(&ipv6_redacted)
}

fn format_redacted_report(
    status: &DesktopStatusSnapshotDto,
    ran_at_ms: u64,
    checks: &[DiagnosticCheckItemDto],
) -> String {
    let total = checks.len();
    let passed = checks
        .iter()
        .filter(|c| c.status == DiagStatusDto::Pass)
        .count();
    let warned = checks
        .iter()
        .filter(|c| c.status == DiagStatusDto::Warn)
        .count();
    let failed = checks
        .iter()
        .filter(|c| c.status == DiagStatusDto::Fail)
        .count();

    let mut lines: Vec<String> = Vec::with_capacity(checks.len() * 2 + 14);
    lines.push("# vdpi Desktop Diagnostics".to_string());
    lines.push(format!(
        "- App Version: {}",
        format_version_v(&status.app_version)
    ));
    lines.push(format!(
        "- Platform: {}",
        sanitize_single_line(&status.platform)
    ));

    let service_line = match status
        .installed_version
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(ver) => format!(
            "- Service: {} ({})",
            service_state_label(status.service_state),
            format_version_v(ver)
        ),
        None => format!("- Service: {}", service_state_label(status.service_state)),
    };
    lines.push(service_line);

    let engine_line = match status.live.as_ref().filter(|l| l.running) {
        Some(live) => {
            let rss_part = live
                .rss_kb
                .map(|kb| format!(" · {}", format_rss_label(kb)))
                .unwrap_or_default();
            format!(
                "- Engine: {} configured / {} live{rss_part}",
                engine_label(status.configured_engine),
                engine_label(live.engine)
            )
        }
        None => format!(
            "- Engine: {} configured (standby)",
            engine_label(status.configured_engine)
        ),
    };
    lines.push(engine_line);

    lines.push(format!(
        "- Split Tunnel: {}",
        format_split_tunnel_summary(status)
    ));

    if let Some(live) = status.live.as_ref().filter(|l| l.running) {
        let dns_target = sanitize_single_line(&redact_dns_for_display(&live.dns_display));
        let dns_mode = if live.doh_enabled { "DoH" } else { "UDP" };
        if dns_target.is_empty() {
            lines.push(format!("- Live DNS: {dns_mode}"));
        } else {
            lines.push(format!("- Live DNS: {dns_target} ({dns_mode})"));
        }
        let quic_state = if live.block_quic {
            "Enabled"
        } else {
            "Disabled"
        };
        lines.push(format!("- QUIC Block: {quic_state}"));
        let isp_stage = live
            .isp_stage
            .as_deref()
            .map(sanitize_single_line)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "None".to_string());
        lines.push(format!("- ISP Stage: {isp_stage}"));
    }

    if let Some(warn) = status
        .config_warning
        .as_deref()
        .map(sanitize_single_line)
        .filter(|s| !s.is_empty())
    {
        lines.push(format!("- Config Warning: {warn}"));
    }

    lines.push(format!("- Ran At: {}", format_utc_iso8601(ran_at_ms)));
    lines.push(format!(
        "- Result: {passed}/{total} passed ({warned} warn, {failed} fail)"
    ));
    lines.push(String::new());
    lines.push("## Checks".to_string());

    for check in checks {
        let badge = status_badge(check.status);
        let latency_suffix = check
            .latency_ms
            .map(|ms| format!(" ({ms} ms)"))
            .unwrap_or_default();
        let target_part = if check.target.trim().is_empty() {
            String::new()
        } else {
            format!(" [{}]", sanitize_single_line(&check.target))
        };
        lines.push(format!(
            "- [{badge}] {}{target_part}: {}{latency_suffix}",
            sanitize_single_line(&check.name),
            sanitize_single_line(&check.summary),
        ));
        if let Some(detail) = check
            .detail
            .as_deref()
            .map(sanitize_single_line)
            .filter(|s| !s.is_empty())
        {
            lines.push(format!("  Detail: {detail}"));
        }
    }

    // Guarantee every single output line runs through URL redaction, user home
    // path scrubbing, and private/CGNAT/link-local IPv4 & IPv6 redaction so no
    // DoH profile token, query secret, fragment, userinfo, home username, or
    // LAN/Tailscale IP leaks.
    lines
        .into_iter()
        .flat_map(|line| {
            line.split('\n')
                .map(redact_report_line)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_diagnostics_report(
    status: &DesktopStatusSnapshotDto,
    ran_at_ms: u64,
    checks: Vec<DiagnosticCheckItemDto>,
) -> DiagnosticsReportDto {
    let sanitized_checks: Vec<DiagnosticCheckItemDto> =
        checks.into_iter().map(sanitize_check_item).collect();
    let total_count = sanitized_checks.len();
    let passed_count = sanitized_checks
        .iter()
        .filter(|c| c.status == DiagStatusDto::Pass)
        .count();
    let all_passed = total_count > 0 && passed_count == total_count;
    let redacted_text = format_redacted_report(status, ran_at_ms, &sanitized_checks);

    DiagnosticsReportDto {
        ran_at_ms,
        all_passed,
        passed_count,
        total_count,
        checks: sanitized_checks,
        redacted_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_live_telemetry(engine: EngineModeDto) -> LiveTelemetryDto {
        LiveTelemetryDto {
            running: true,
            engine,
            addr: "127.0.0.1".to_string(),
            port: 8080,
            socks_port: Some(1080),
            tun_interface: (engine == EngineModeDto::Tun).then(|| "vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            version: Some("0.6.0".to_string()),
            mode: Some("combo".to_string()),
            doh_enabled: true,
            dns_display: "https://dns.nextdns.io".to_string(),
            block_quic: true,
            active_connections: 4,
            total_connections: 42,
            learned_hosts: 8,
            isp_stage: Some("stage1".to_string()),
            udp_flows_active: 2,
            quic_blocked: 5,
            dns_queries: 19,
            rss_kb: Some(18_432),
            bytes_rx: 102_400,
            bytes_tx: 51_200,
            rx_rate_bps: 1024,
            tx_rate_bps: 512,
            tls_handshakes: 14,
            auto_heal_escalations: 0,
        }
    }

    fn sample_status(engine: EngineModeDto, live: Option<LiveTelemetryDto>) -> DesktopStatusSnapshotDto {
        DesktopStatusSnapshotDto {
            snapshot_seq: 1,
            app_version: "0.6.0".to_string(),
            platform: "windows".to_string(),
            service_state: if live.is_some() {
                ServiceStateDto::Running
            } else {
                ServiceStateDto::Stopped
            },
            installed_version: Some("0.6.0".to_string()),
            configured_engine: engine,
            live,
            vpn_conflict: None,
            wintun: WintunStatusDto {
                required: engine == EngineModeDto::Tun,
                ready: true,
                message: Some("C:\\Program Files\\vdpi\\wintun.dll".to_string()),
            },
            split_tunnel_mode: SplitTunnelModeDto::Exclude,
            split_tunnel_count: 2,
            config_path: String::new(),
            logs_dir: String::new(),
            tray_supported: true,
            config_warning: None,
            bundled_engine_version: Some("0.6.0".to_string()),
            cli_version_relation: crate::models::CliVersionRelationDto::UpToDate,
            can_install_from_bundle: true,
            live_version_stale: false,
            pending_operation: None,
            running_from_readonly_dmg: false,
        }
    }

    #[test]
    fn dns_check_title_and_redaction_match_vdpi_rules() {
        let nextdns_cfg = RuntimeConfig {
            dns_addr: "https://dns.nextdns.io/a1b2c3secret".to_string(),
            enable_doh: false, // explicit https:// URL still uses DoH
            ..RuntimeConfig::default()
        };
        let (addr, display, transport, eff_doh) = doh_check_target(&nextdns_cfg);
        assert_eq!(addr, "https://dns.nextdns.io/a1b2c3secret");
        assert_eq!(display, "https://dns.nextdns.io");
        assert_eq!(transport, "DoH");
        assert!(eff_doh);
        assert_eq!(diag_dns_check_name(&nextdns_cfg), "Encrypted DNS (DoH)");

        let pass = evaluate_dns_outcome(
            diag_dns_check_name(&nextdns_cfg),
            &addr,
            &display,
            transport,
            Ok(Ok(vec![IpAddr::V4(Ipv4Addr::new(162, 159, 135, 232))])),
            22,
        );
        assert_eq!(pass.status, DiagStatusDto::Pass);
        assert_eq!(pass.name, "Encrypted DNS (DoH)");
        assert_eq!(pass.target, "https://dns.nextdns.io");
        assert!(!pass.target.contains("a1b2c3secret"));
        assert!(!pass.summary.contains("a1b2c3secret"));
        assert_eq!(
            pass.detail.as_deref(),
            Some("DoH via https://dns.nextdns.io · 162.159.135.232")
        );

        let err_item = evaluate_dns_outcome(
            diag_dns_check_name(&nextdns_cfg),
            &addr,
            &display,
            transport,
            Ok(Err(
                "POST https://dns.nextdns.io/a1b2c3secret?device=workstation#top failed: reset"
                    .to_string(),
            )),
            31,
        );
        assert_eq!(err_item.status, DiagStatusDto::Fail);
        let detail = err_item.detail.as_deref().unwrap_or("");
        assert!(detail.contains("https://dns.nextdns.io"));
        for secret in ["a1b2c3secret", "device", "workstation", "#top"] {
            assert!(!detail.contains(secret), "leaked {secret:?} in {detail:?}");
        }

        let init_err = format_dns_init_error(
            diag_dns_check_name(&nextdns_cfg),
            &addr,
            &display,
            "failed to build client for https://DNS.NEXTDNS.IO:443/a1b2c3secret?tok=1",
            9,
        );
        assert_eq!(init_err.status, DiagStatusDto::Fail);
        assert_eq!(init_err.summary, "Resolver init failed (https://dns.nextdns.io)");
        let init_detail = init_err.detail.as_deref().unwrap_or("");
        assert!(init_detail.contains("https://dns.nextdns.io"));
        assert!(!init_detail.contains("a1b2c3secret"));
        assert!(!init_detail.contains("tok=1"));

        let timed_out = evaluate_dns_outcome(
            diag_dns_check_name(&nextdns_cfg),
            &addr,
            &display,
            transport,
            Err(()),
            5000,
        );
        assert_eq!(timed_out.status, DiagStatusDto::Fail);
        assert_eq!(timed_out.summary, "DoH lookup timed out");
        assert_eq!(
            timed_out.detail.as_deref(),
            Some("No reply from https://dns.nextdns.io within 5s")
        );

        // Bare custom non-DoH IP uses UDP title even when enable_doh = true.
        let custom_udp_cfg = RuntimeConfig {
            dns_addr: "76.76.2.0".to_string(),
            enable_doh: true,
            ..RuntimeConfig::default()
        };
        assert_eq!(diag_dns_check_name(&custom_udp_cfg), "DNS Resolution (UDP)");

        // Known public DoH IP switches title based on enable_doh.
        let quad9_doh = RuntimeConfig {
            dns_addr: "9.9.9.9".to_string(),
            enable_doh: true,
            ..RuntimeConfig::default()
        };
        assert_eq!(diag_dns_check_name(&quad9_doh), "Encrypted DNS (DoH)");

        let quad9_udp = RuntimeConfig {
            dns_addr: "9.9.9.9".to_string(),
            enable_doh: false,
            ..RuntimeConfig::default()
        };
        assert_eq!(diag_dns_check_name(&quad9_udp), "DNS Resolution (UDP)");

        // Direct dns_addr replacement runs BEFORE redact_urls_in_text so delimiter
        // characters inside a configured URL never let trailing segments escape.
        let delim_addr = "https://dns.nextdns.io/abc(secretToken)";
        let delim_display = "https://dns.nextdns.io";
        let delim_detail = sanitize_dns_error_detail(
            "POST https://dns.nextdns.io/abc(secretToken)?dev=laptop failed",
            delim_addr,
            delim_display,
        );
        assert!(delim_detail.contains("https://dns.nextdns.io"));
        assert!(!delim_detail.contains("secretToken"));
        assert!(!delim_detail.contains("dev=laptop"));

        // Malformed https:// URL falls back to UDP title and never leaks secrets.
        let bad_cfg = RuntimeConfig {
            dns_addr: "https://user:superpass@freedns.controld.com/p2secret?k=v#frag".to_string(),
            enable_doh: true,
            ..RuntimeConfig::default()
        };
        let (_, bad_display, bad_transport, _) = doh_check_target(&bad_cfg);
        assert_eq!(bad_transport, "UDP");
        assert_eq!(diag_dns_check_name(&bad_cfg), "DNS Resolution (UDP)");
        for secret in ["user", "superpass", "p2secret", "k=v", "frag"] {
            assert!(!bad_display.contains(secret));
        }
    }

    #[test]
    fn http_probe_path_respects_active_proxy_tun_and_direct() {
        let proxy_live = sample_live_telemetry(EngineModeDto::Proxy);
        let proxy_status = sample_status(EngineModeDto::Proxy, Some(proxy_live));
        assert_eq!(
            resolve_http_probe_path(&proxy_status),
            HttpProbePath::Proxy(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080))
        );

        let mut wildcard_proxy = sample_live_telemetry(EngineModeDto::Proxy);
        wildcard_proxy.addr = "0.0.0.0".to_string();
        wildcard_proxy.port = 18080;
        let wildcard_status = sample_status(EngineModeDto::Proxy, Some(wildcard_proxy));
        assert_eq!(
            resolve_http_probe_path(&wildcard_status),
            HttpProbePath::Proxy(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18080))
        );

        let tun_status = sample_status(
            EngineModeDto::Tun,
            Some(sample_live_telemetry(EngineModeDto::Tun)),
        );
        assert_eq!(resolve_http_probe_path(&tun_status), HttpProbePath::Tun);

        let standby_status = sample_status(EngineModeDto::Proxy, None);
        assert_eq!(
            resolve_http_probe_path(&standby_status),
            HttpProbePath::Direct
        );
        assert_eq!(
            HttpProbePath::Direct.description(),
            "Direct (vdpi not running - anti-DPI bypass not tested)"
        );
    }

    #[test]
    fn http_probe_outcome_warns_on_direct_and_redirects_and_uses_deterministic_timeout() {
        // Stopped/uninstalled direct HTTP 200 must report Warn (never misleading green Pass).
        let direct_ok = evaluate_http_probe_outcome(
            "discord_gateway",
            "Discord Web & Gateway",
            DISCORD_GATEWAY_TARGET,
            &HttpProbePath::Direct,
            HttpProbeOutcome::Response(200),
            Some(44),
        );
        assert_eq!(direct_ok.status, DiagStatusDto::Warn);
        assert_eq!(
            direct_ok.detail.as_deref(),
            Some("Direct (vdpi not running - anti-DPI bypass not tested)")
        );

        // Active TUN and Proxy HTTP 2xx report Pass.
        let tun_ok = evaluate_http_probe_outcome(
            "discord_gateway",
            "Discord Web & Gateway",
            DISCORD_GATEWAY_TARGET,
            &HttpProbePath::Tun,
            HttpProbeOutcome::Response(200),
            Some(35),
        );
        assert_eq!(tun_ok.status, DiagStatusDto::Pass);
        assert_eq!(tun_ok.summary, "Reachable (HTTP 200)");
        assert_eq!(tun_ok.detail.as_deref(), Some("Via active TUN engine"));

        let proxy_ok = evaluate_http_probe_outcome(
            "roblox_clientsettings",
            "Roblox ClientSettings",
            ROBLOX_CLIENT_SETTINGS_TARGET,
            &HttpProbePath::Proxy(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)),
            HttpProbeOutcome::Response(204),
            Some(29),
        );
        assert_eq!(proxy_ok.status, DiagStatusDto::Pass);

        // 3xx captive-portal / ISP redirects must NEVER be treated as Pass.
        let tun_redirect = evaluate_http_probe_outcome(
            "discord_gateway",
            "Discord Web & Gateway",
            DISCORD_GATEWAY_TARGET,
            &HttpProbePath::Tun,
            HttpProbeOutcome::Response(302),
            Some(18),
        );
        assert_eq!(tun_redirect.status, DiagStatusDto::Warn);
        assert!(tun_redirect.summary.contains("302"));

        // Timeout always produces deterministic "Timed out after 5s" matching the 5s reqwest budget.
        let timed_out = evaluate_http_probe_outcome(
            "discord_gateway",
            "Discord Web & Gateway",
            DISCORD_GATEWAY_TARGET,
            &HttpProbePath::Tun,
            HttpProbeOutcome::TimedOut,
            Some(5_010),
        );
        assert_eq!(timed_out.status, DiagStatusDto::Fail);
        assert_eq!(timed_out.summary, "Timed out after 5s");
        assert_eq!(HTTP_PROBE_REQWEST_TIMEOUT, Duration::from_secs(5));
        assert_eq!(HTTP_PROBE_OUTER_TIMEOUT, Duration::from_secs(6));
        assert!(HTTP_PROBE_REQWEST_TIMEOUT < HTTP_PROBE_OUTER_TIMEOUT);
    }

    #[test]
    fn vpn_wintun_and_service_hygiene_checks_evaluate_expected_states() {
        let full_vpn = evaluate_vpn_scope(
            &VpnScope::FullTunnel {
                provider: "Mullvad".to_string(),
                iface: "Mullvad".to_string(),
                kill_switch: true,
            },
            VpnCoexistence::AutoYield,
            "Exclude (2 apps)",
            Some(4),
        );
        assert_eq!(full_vpn.status, DiagStatusDto::Warn);
        assert!(full_vpn.summary.contains("Mullvad"));
        assert!(full_vpn.summary.contains("[kill-switch]"));

        // Full-tunnel VPN with coexistence Off must still return Warn (never Pass).
        let full_vpn_off = evaluate_vpn_scope(
            &VpnScope::FullTunnel {
                provider: "ProtonVPN".to_string(),
                iface: "ProtonVPN".to_string(),
                kill_switch: false,
            },
            VpnCoexistence::Off,
            "All apps",
            Some(2),
        );
        assert_eq!(full_vpn_off.status, DiagStatusDto::Warn);
        assert!(full_vpn_off.summary.contains("ProtonVPN"));

        let no_vpn_off = evaluate_vpn_scope(
            &VpnScope::None,
            VpnCoexistence::Off,
            "All apps",
            Some(1),
        );
        assert_eq!(no_vpn_off.status, DiagStatusDto::Pass);

        let overlay = evaluate_vpn_scope(
            &VpnScope::SplitOverlay {
                providers: vec!["Tailscale".to_string()],
            },
            VpnCoexistence::AutoYield,
            "All apps",
            Some(3),
        );
        assert_eq!(overlay.status, DiagStatusDto::Pass);
        assert!(overlay.summary.contains("Tailscale"));

        // Wintun ready while service stopped honestly states disk SHA-256 verified,
        // without claiming driver/adapter load was tested.
        let ready_stopped_wintun = evaluate_wintun_check(
            &WintunStatusDto {
                required: true,
                ready: true,
                message: Some("C:\\Program Files\\vdpi\\wintun.dll".to_string()),
            },
            EngineModeDto::Tun,
            None,
        );
        assert_eq!(ready_stopped_wintun.status, DiagStatusDto::Pass);
        assert!(ready_stopped_wintun.summary.contains("SHA-256 verified on disk"));
        assert!(ready_stopped_wintun
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("not tested"));

        let live_tun = sample_live_telemetry(EngineModeDto::Tun);
        let ready_active_wintun = evaluate_wintun_check(
            &WintunStatusDto {
                required: true,
                ready: true,
                message: Some("C:\\Program Files\\vdpi\\wintun.dll".to_string()),
            },
            EngineModeDto::Tun,
            Some(&live_tun),
        );
        assert_eq!(ready_active_wintun.status, DiagStatusDto::Pass);
        assert!(ready_active_wintun.summary.contains("TUN active"));

        let missing_wintun_tun = evaluate_wintun_check(
            &WintunStatusDto {
                required: true,
                ready: false,
                message: Some("SHA-256 hash mismatch on wintun.dll".to_string()),
            },
            EngineModeDto::Tun,
            None,
        );
        assert_eq!(missing_wintun_tun.status, DiagStatusDto::Fail);
        assert!(missing_wintun_tun.summary.contains("corrupted or mismatched"));

        let missing_wintun_proxy = evaluate_wintun_check(
            &WintunStatusDto {
                required: false,
                ready: false,
                message: None,
            },
            EngineModeDto::Proxy,
            None,
        );
        assert_eq!(missing_wintun_proxy.status, DiagStatusDto::Warn);

        let healthy_status = sample_status(
            EngineModeDto::Tun,
            Some(sample_live_telemetry(EngineModeDto::Tun)),
        );
        let healthy_service = evaluate_service_hygiene_check(&healthy_status);
        assert_eq!(healthy_service.status, DiagStatusDto::Pass);
        assert!(healthy_service.summary.contains("TUN active (vdpi0)"));
        assert!(healthy_service
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("18.0 MB RSS"));

        let mut mismatched_status = sample_status(
            EngineModeDto::Tun,
            Some(sample_live_telemetry(EngineModeDto::Proxy)),
        );
        let mismatch_check = evaluate_service_hygiene_check(&mismatched_status);
        assert_eq!(mismatch_check.status, DiagStatusDto::Warn);
        assert!(mismatch_check.summary.contains("Engine mismatch"));

        // Concurrent warnings (engine mismatch + version mismatch + orphaned live
        // process while stopped + high RSS + config warning) must ALL be collected.
        mismatched_status.installed_version = Some("0.7.0".to_string());
        mismatched_status.service_state = ServiceStateDto::Stopped;
        mismatched_status.config_warning =
            Some("Failed to parse config.toml; using defaults".to_string());
        if let Some(live) = mismatched_status.live.as_mut() {
            live.rss_kb = Some(300 * 1024);
        }
        let multi_warn = evaluate_service_hygiene_check(&mismatched_status);
        assert_eq!(multi_warn.status, DiagStatusDto::Warn);
        assert!(multi_warn.summary.contains("Engine mismatch"));
        assert!(multi_warn.summary.contains("Version mismatch"));
        assert!(multi_warn.summary.contains("Orphaned live process"));
        assert!(multi_warn.summary.contains("elevated memory"));
        assert!(multi_warn.summary.contains("config warning"));
        let multi_detail = multi_warn.detail.as_deref().unwrap_or("");
        assert!(multi_detail.contains("restart service to apply configured engine"));
        assert!(multi_detail.contains("restart service to load installed version"));
        assert!(multi_detail.contains("live engine running while service state is Stopped"));
        assert!(multi_detail.contains("RSS exceeds 256 MB threshold"));
        assert!(multi_detail.contains("Failed to parse config.toml; using defaults"));

        // High RSS alone also warns.
        let mut high_rss_only = sample_status(
            EngineModeDto::Proxy,
            Some(sample_live_telemetry(EngineModeDto::Proxy)),
        );
        if let Some(live) = high_rss_only.live.as_mut() {
            live.rss_kb = Some(300 * 1024);
        }
        let high_rss_check = evaluate_service_hygiene_check(&high_rss_only);
        assert_eq!(high_rss_check.status, DiagStatusDto::Warn);
        assert!(high_rss_check.summary.contains("elevated memory"));

        // Stopped service with config_warning emits visible Warn detail.
        let mut stopped_warn_status = sample_status(EngineModeDto::Tun, None);
        stopped_warn_status.config_warning = Some("Invalid TOML syntax in config.toml".to_string());
        let stopped_warn = evaluate_service_hygiene_check(&stopped_warn_status);
        assert_eq!(stopped_warn.status, DiagStatusDto::Warn);
        assert!(stopped_warn
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("Invalid TOML syntax in config.toml"));

        // Running service with live = None and active vpn_conflict surfaces paused/yielded
        // VPN conflict guidance instead of generic "live telemetry unavailable".
        let mut vpn_yielded_status = sample_status(EngineModeDto::Tun, None);
        vpn_yielded_status.service_state = ServiceStateDto::Running;
        vpn_yielded_status.vpn_conflict = Some("Mullvad (Mullvad)".to_string());
        let vpn_yielded = evaluate_service_hygiene_check(&vpn_yielded_status);
        assert_eq!(vpn_yielded.status, DiagStatusDto::Warn);
        assert!(vpn_yielded.summary.contains("protection paused"));
        assert!(vpn_yielded.summary.contains("Mullvad (Mullvad)"));
        assert!(!vpn_yielded.summary.contains("live telemetry unavailable"));
        assert!(vpn_yielded
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("yielded"));

        // Running service with live = None and no vpn_conflict still reports unavailable telemetry.
        let mut running_no_live = sample_status(EngineModeDto::Tun, None);
        running_no_live.service_state = ServiceStateDto::Running;
        let no_live_check = evaluate_service_hygiene_check(&running_no_live);
        assert_eq!(no_live_check.status, DiagStatusDto::Warn);
        assert!(no_live_check.summary.contains("live telemetry unavailable"));

        // NotInstalled with missing bundled sidecar flags a Fail check.
        let mut missing_bundle = sample_status(EngineModeDto::Tun, None);
        missing_bundle.service_state = ServiceStateDto::NotInstalled;
        missing_bundle.can_install_from_bundle = false;
        missing_bundle.bundled_engine_version = None;
        missing_bundle.cli_version_relation = CliVersionRelationDto::BundledMissing;
        let missing_bundle_check = evaluate_service_hygiene_check(&missing_bundle);
        assert_eq!(missing_bundle_check.status, DiagStatusDto::Fail);
        assert!(missing_bundle_check.summary.contains("Bundled vdpi CLI missing"));

        // Running service with live telemetry but RepairNeeded (unreadable/missing disk binary)
        // must WARN instead of falsely reporting Pass.
        let mut repair_running = sample_status(
            EngineModeDto::Tun,
            Some(sample_live_telemetry(EngineModeDto::Tun)),
        );
        repair_running.installed_version = None;
        repair_running.cli_version_relation = CliVersionRelationDto::RepairNeeded;
        let repair_running_check = evaluate_service_hygiene_check(&repair_running);
        assert_eq!(repair_running_check.status, DiagStatusDto::Warn);
        assert_eq!(
            repair_running_check.summary,
            "Background service needs repair"
        );
        assert_eq!(
            repair_running_check.detail.as_deref(),
            Some(
                "Installed CLI binary could not be verified on disk while the service is registered. Open Installation and run Repair / Reinstall."
            )
        );

        // Concurrent warning alongside RepairNeeded preserves both warnings.
        let mut repair_with_cfg_warn = repair_running.clone();
        repair_with_cfg_warn.config_warning = Some("Invalid TOML syntax".to_string());
        let repair_cfg_check = evaluate_service_hygiene_check(&repair_with_cfg_warn);
        assert_eq!(repair_cfg_check.status, DiagStatusDto::Warn);
        assert!(repair_cfg_check
            .summary
            .contains("Background service needs repair"));
        assert!(repair_cfg_check.summary.contains("config warning"));

        // Stopped service with RepairNeeded also surfaces repair guidance.
        let mut repair_stopped = sample_status(EngineModeDto::Tun, None);
        repair_stopped.installed_version = None;
        repair_stopped.cli_version_relation = CliVersionRelationDto::RepairNeeded;
        let repair_stopped_check = evaluate_service_hygiene_check(&repair_stopped);
        assert_eq!(repair_stopped_check.status, DiagStatusDto::Warn);
        assert_eq!(
            repair_stopped_check.summary,
            "Background service needs repair"
        );
    }

    #[test]
    fn report_formatting_and_strict_url_token_redaction_never_leak_secrets() {
        let status = sample_status(
            EngineModeDto::Tun,
            Some(sample_live_telemetry(EngineModeDto::Tun)),
        );

        let checks = vec![
            DiagnosticCheckItemDto {
                id: "vpn_coexistence".to_string(),
                name: "VPN Coexistence".to_string(),
                target: "Routing table & adapters".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: Some(3),
                summary: "No VPN conflict · Exclude (2 apps)".to_string(),
                detail: Some("Coexistence: Auto-Yield".to_string()),
            },
            DiagnosticCheckItemDto {
                id: "dns_resolution".to_string(),
                name: "Encrypted DNS (DoH)".to_string(),
                target: "https://dns.nextdns.io/secretProfile99?token=leakme#frag".to_string(),
                status: DiagStatusDto::Fail,
                latency_ms: Some(45),
                summary: "DoH lookup failed for https://user:pw@freedns.controld.com/p2secret?dev=pc"
                    .to_string(),
                detail: Some(
                    "upstream error at https://[2606:4700:4700::1111]:8443/dns-query?key=topsecret#anchor and http://admin:hunter2@192.168.1.5/api?auth=xyz"
                        .to_string(),
                ),
            },
            DiagnosticCheckItemDto {
                id: "discord_gateway".to_string(),
                name: "Discord Web & Gateway".to_string(),
                target: DISCORD_GATEWAY_TARGET.to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: Some(82),
                summary: "Reachable (HTTP 200)".to_string(),
                detail: Some("Via active TUN engine".to_string()),
            },
        ];

        let report = build_diagnostics_report(&status, 1_730_000_000_000, checks);

        assert_eq!(report.ran_at_ms, 1_730_000_000_000);
        assert_eq!(report.total_count, 3);
        assert_eq!(report.passed_count, 2);
        assert!(!report.all_passed);

        // Verify structured check fields are themselves URL-scrubbed.
        let dns_item = &report.checks[1];
        assert_eq!(dns_item.target, "https://dns.nextdns.io");
        assert!(dns_item.summary.contains("https://freedns.controld.com"));
        assert!(dns_item
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("https://[2606:4700:4700::1111]:8443"));
        assert!(dns_item
            .detail
            .as_deref()
            .unwrap_or("")
            .contains("http://192.168.1.5"));

        // Verify crisp markdown report header, live telemetry summary, ISO-8601 UTC timestamp,
        // LAN IP redaction, and check entries.
        let text = &report.redacted_text;
        assert!(text.starts_with("# vdpi Desktop Diagnostics\n"));
        assert!(text.contains("- App Version: v0.6.0"));
        assert!(text.contains("- Platform: windows"));
        assert!(text.contains("- Service: Running (v0.6.0)"));
        assert!(text.contains("- Engine: TUN configured / TUN live · 18.0 MB RSS"));
        assert!(text.contains("- Split Tunnel: Exclude (2 apps)"));
        assert!(text.contains("- Live DNS: https://dns.nextdns.io (DoH)"));
        assert!(text.contains("- QUIC Block: Enabled"));
        assert!(text.contains("- ISP Stage: stage1"));
        assert!(text.contains("- Ran At: 2024-10-27T03:33:20Z"));
        assert!(text.contains("- Result: 2/3 passed (0 warn, 1 fail)"));
        assert!(text.contains("## Checks"));
        assert!(text.contains("- [PASS] VPN Coexistence [Routing table & adapters]: No VPN conflict · Exclude (2 apps) (3 ms)"));
        assert!(text.contains("- [FAIL] Encrypted DNS (DoH) [https://dns.nextdns.io]:"));
        assert!(text.contains("http://[LAN_IP]"));
        assert!(!text.contains("192.168.1.5"));
        assert!(text.contains("- [PASS] Discord Web & Gateway [discord.com/api/v10/gateway]: Reachable (HTTP 200) (82 ms)"));

        // Strict leak check across every single line of `redacted_text` and all checks.
        let secrets = [
            "secretProfile99",
            "leakme",
            "#frag",
            "user:pw",
            "p2secret",
            "dev=pc",
            "topsecret",
            "#anchor",
            "dns-query",
            "admin",
            "hunter2",
            "auth=xyz",
        ];
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "redacted_text leaked secret {secret:?}:\n{text}"
            );
            for item in &report.checks {
                assert!(
                    !item.target.contains(secret)
                        && !item.summary.contains(secret)
                        && !item.detail.as_deref().unwrap_or("").contains(secret),
                    "check item {} leaked secret {secret:?}: {item:?}",
                    item.id
                );
            }
        }
    }

    #[test]
    fn utc_iso8601_conversion_handles_epoch_leap_days_and_recent_dates() {
        assert_eq!(format_utc_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_utc_iso8601(951_827_696_000),
            "2000-02-29T12:34:56Z"
        );
        assert_eq!(
            format_utc_iso8601(1_709_164_800_000),
            "2024-02-29T00:00:00Z"
        );
        assert_eq!(
            format_utc_iso8601(1_730_000_000_000),
            "2024-10-27T03:33:20Z"
        );
    }

    #[test]
    fn format_redacted_report_scrubs_home_paths_and_lan_ips_while_keeping_public_resolvers() {
        let mut status = sample_status(EngineModeDto::Proxy, None);
        status.config_warning = Some(
            r"Could not read C:\Users\Alice\AppData\Roaming\vdpi\config.toml via 10.20.30.40"
                .to_string(),
        );

        let checks = vec![
            DiagnosticCheckItemDto {
                id: "wintun_driver".to_string(),
                name: "Wintun Driver (wintun.dll)".to_string(),
                target: "wintun.dll".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: None,
                summary: "wintun.dll verified".to_string(),
                detail: Some(
                    r"paths: C:\Users\Alice\Downloads\wintun.dll, D:/users/Bob/wintun.dll, \\?\C:\Users\Eve\vdpi.exe, /Users/carol/Library/Logs/vdpi.log, /home/dave/.config/vdpi/config.toml, C:\Program Files\vdpi\wintun.dll"
                        .to_string(),
                ),
            },
            DiagnosticCheckItemDto {
                id: "dns_resolution".to_string(),
                name: "DNS Resolution (UDP)".to_string(),
                target: "1.1.1.1".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: Some(12),
                summary: "Resolvers checked: 1.1.1.1, 9.9.9.9, 8.8.8.8, 94.140.14.14, 172.15.0.1, 172.32.0.1, 127.0.0.1".to_string(),
                detail: Some(
                    "LAN peers: 10.0.0.1, 172.16.5.9, 172.31.255.254, 192.168.1.5:53, 192.168.0.1."
                        .to_string(),
                ),
            },
        ];

        let text = format_redacted_report(&status, 1_730_000_000_000, &checks);

        // ISO-8601 UTC timestamp present.
        assert!(text.contains("- Ran At: 2024-10-27T03:33:20Z"));

        // Home directory usernames scrubbed across Windows, macOS, and Linux formats.
        assert!(text.contains(r"[USER_HOME]\AppData\Roaming\vdpi\config.toml"));
        assert!(text.contains(r"[USER_HOME]\Downloads\wintun.dll"));
        assert!(text.contains("[USER_HOME]/wintun.dll"));
        assert!(text.contains(r"[USER_HOME]\vdpi.exe"));
        assert!(text.contains("[USER_HOME]/Library/Logs/vdpi.log"));
        assert!(text.contains("[USER_HOME]/.config/vdpi/config.toml"));
        assert!(text.contains(r"C:\Program Files\vdpi\wintun.dll"));
        for leaked_user in ["Alice", "Bob", "Eve", "carol", "dave"] {
            assert!(
                !text.contains(leaked_user),
                "leaked username {leaked_user:?} in:\n{text}"
            );
        }

        // Private RFC1918 LAN IPs scrubbed to [LAN_IP].
        assert!(text.contains("[LAN_IP]:53"));
        assert!(text.contains("[LAN_IP]."));
        for lan_ip in [
            "10.20.30.40",
            "10.0.0.1",
            "172.16.5.9",
            "172.31.255.254",
            "192.168.1.5",
            "192.168.0.1",
        ] {
            assert!(
                !text.contains(lan_ip),
                "leaked LAN IP {lan_ip:?} in:\n{text}"
            );
        }

        // Public resolver IPs and loopback remain intact.
        for public_ip in [
            "1.1.1.1",
            "9.9.9.9",
            "8.8.8.8",
            "94.140.14.14",
            "172.15.0.1",
            "172.32.0.1",
            "127.0.0.1",
        ] {
            assert!(
                text.contains(public_ip),
                "public/loopback IP {public_ip:?} was unexpectedly redacted:\n{text}"
            );
        }
    }

    #[test]
    fn format_redacted_report_redacts_every_line_even_on_raw_multiline_input() {
        let status = sample_status(EngineModeDto::Proxy, None);
        let raw_checks = vec![DiagnosticCheckItemDto {
            id: "dns_resolution".to_string(),
            name: "Encrypted DNS (DoH)".to_string(),
            target: "https://dns.nextdns.io/rawTokenA".to_string(),
            status: DiagStatusDto::Pass,
            latency_ms: Some(15),
            summary: "Resolved via https://dns.nextdns.io/rawTokenB".to_string(),
            detail: Some("line1 https://freedns.controld.com/rawTokenC\nline2 https://dns.quad9.net/rawTokenD?q=secret".to_string()),
        }];

        let text = format_redacted_report(&status, 42, &raw_checks);
        for secret in ["rawTokenA", "rawTokenB", "rawTokenC", "rawTokenD", "q=secret"] {
            assert!(
                !text.contains(secret),
                "format_redacted_report leaked {secret:?}:\n{text}"
            );
        }
        assert!(text.contains("https://dns.nextdns.io"));
        assert!(text.contains("https://freedns.controld.com"));
        assert!(text.contains("https://dns.quad9.net"));
    }

    #[test]
    fn scrub_user_home_paths_handles_multi_word_usernames_without_over_scrubbing() {
        assert_eq!(
            scrub_user_home_paths(r"C:\Users\John Doe\AppData\Roaming\vdpi\config.toml"),
            r"[USER_HOME]\AppData\Roaming\vdpi\config.toml"
        );
        assert_eq!(
            scrub_user_home_paths(r"\\?\C:\Users\Mary Jane Watson\vdpi.exe"),
            r"[USER_HOME]\vdpi.exe"
        );
        assert_eq!(
            scrub_user_home_paths("D:/users/Jane Smith/wintun.dll"),
            "[USER_HOME]/wintun.dll"
        );
        assert_eq!(
            scrub_user_home_paths("/Users/John Doe/Library/Logs/vdpi.log"),
            "[USER_HOME]/Library/Logs/vdpi.log"
        );
        assert_eq!(
            scrub_user_home_paths("/home/John Doe/.config/vdpi/config.toml"),
            "[USER_HOME]/.config/vdpi/config.toml"
        );
        assert_eq!(
            scrub_user_home_paths(r#"open "C:\Users\John Doe\AppData\vdpi.toml" failed"#),
            r#"open "[USER_HOME]\AppData\vdpi.toml" failed"#
        );

        // When no path separator follows the username, do not swallow subsequent prose or paths.
        assert_eq!(
            scrub_user_home_paths("Home is /home/alice and /var/log/vdpi.log"),
            "Home is [USER_HOME] and /var/log/vdpi.log"
        );
        assert_eq!(
            scrub_user_home_paths(r"Home dir C:\Users\Alice · /var/log/foo"),
            "Home dir [USER_HOME] · /var/log/foo"
        );
        assert_eq!(
            scrub_user_home_paths(r"Home is C:\Users\Alice."),
            "Home is [USER_HOME]."
        );

        // Apostrophes inside usernames must not truncate early, while closing
        // single quotes remain intact.
        assert_eq!(
            scrub_user_home_paths(r"C:\Users\O'Connor\AppData\vdpi.toml"),
            r"[USER_HOME]\AppData\vdpi.toml"
        );
        assert_eq!(
            scrub_user_home_paths(r"C:\Users\John O'Connor\AppData\vdpi.toml"),
            r"[USER_HOME]\AppData\vdpi.toml"
        );
        assert_eq!(
            scrub_user_home_paths(r"open 'C:\Users\O'Connor\AppData\vdpi.toml' failed"),
            r"open '[USER_HOME]\AppData\vdpi.toml' failed"
        );
        assert_eq!(
            scrub_user_home_paths(r"open 'C:\Users\Alice' failed"),
            r"open '[USER_HOME]' failed"
        );

        // Mismatched path separators must never let a Windows `\` path swallow
        // trailing prose containing `/` (or vice versa).
        assert_eq!(
            scrub_user_home_paths(r"C:\Users\Alice via HTTP/2"),
            "[USER_HOME] via HTTP/2"
        );
        assert_eq!(
            scrub_user_home_paths(r"/home/alice via C:\Windows"),
            r"[USER_HOME] via C:\Windows"
        );
    }

    #[test]
    fn redact_private_ipv6_handles_unspaced_key_value_and_ipv4_mapped_hex() {
        assert_eq!(
            redact_private_ipv6_addresses("peer:fe80::1 dns:fd00::53 src:fd7a:115c:a1e0::1"),
            "peer:[LAN_IPV6] dns:[LAN_IPV6] src:[LAN_IPV6]"
        );
        assert_eq!(
            redact_private_ipv6_addresses("peer:2606:4700:4700::1111 2606:4700:fe80::99"),
            "peer:2606:4700:4700::1111 2606:4700:fe80::99"
        );
        assert_eq!(
            redact_private_ipv6_addresses("mapped: ::ffff:c0a8:0105, ::ffff:6440:0001, ::ffff:192.168.1.5"),
            "mapped: [LAN_IPV6], [LAN_IPV6], [LAN_IPV6]"
        );
        assert_eq!(
            redact_private_ipv6_addresses("peer:::ffff:c0a8:0105"),
            "peer:[LAN_IPV6]"
        );
        assert_eq!(
            redact_private_ipv6_addresses("public mapped: ::ffff:0101:0101, ::ffff:1.1.1.1, ::1"),
            "public mapped: ::ffff:0101:0101, ::ffff:1.1.1.1, ::1"
        );
    }

    #[test]
    fn format_redacted_report_redacts_cgnat_ipv4_and_private_ipv6_while_preserving_public_resolvers()
    {
        let mut status = sample_status(EngineModeDto::Tun, None);
        status.config_warning = Some(
            r"Could not read C:\Users\John Doe\AppData\Roaming\vdpi\config.toml via 100.100.100.100 or fd7a:115c:a1e0::1"
                .to_string(),
        );

        let checks = vec![
            DiagnosticCheckItemDto {
                id: "wintun_driver".to_string(),
                name: "Wintun Driver (wintun.dll)".to_string(),
                target: "wintun.dll".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: None,
                summary: "wintun.dll verified".to_string(),
                detail: Some(
                    "macOS path: /Users/John Doe/Library/Logs/vdpi.log · Tailscale peers: 100.64.0.1, 100.127.255.254, public 100.63.255.255, 100.128.0.1"
                        .to_string(),
                ),
            },
            DiagnosticCheckItemDto {
                id: "dns_resolution".to_string(),
                name: "Encrypted DNS (DoH)".to_string(),
                target: "https://[2606:4700:4700::1111]:443".to_string(),
                status: DiagStatusDto::Pass,
                latency_ms: Some(14),
                summary: "Public IPv6 resolvers: 2606:4700:4700::1111, 2001:4860:4860::8888, 2620:fe::fe, 2a10:50c0::ad1:ff, 2606:4700:fe80::99, ::1"
                    .to_string(),
                detail: Some(
                    "Private IPv6: fc00::1, fd00::53, fd7a:115c:a1e0::dead:beef, fe80::1%eth0, febf::1234, [fd12:3456:789a::1]:53."
                        .to_string(),
                ),
            },
        ];

        let text = format_redacted_report(&status, 1_730_000_000_000, &checks);

        // Multi-word usernames scrubbed.
        assert!(text.contains(r"[USER_HOME]\AppData\Roaming\vdpi\config.toml"));
        assert!(text.contains("[USER_HOME]/Library/Logs/vdpi.log"));
        assert!(!text.contains("John Doe"));

        // CGNAT / Tailscale IPv4 (`100.64.0.0/10`) scrubbed to `[LAN_IP]`.
        for cgnat in ["100.64.0.1", "100.100.100.100", "100.127.255.254"] {
            assert!(
                !text.contains(cgnat),
                "leaked CGNAT/Tailscale IPv4 {cgnat:?} in:\n{text}"
            );
        }
        assert!(text.contains("[LAN_IP]"));

        // Non-CGNAT boundary IPv4 addresses preserved.
        for non_cgnat in ["100.63.255.255", "100.128.0.1"] {
            assert!(
                text.contains(non_cgnat),
                "public IPv4 {non_cgnat:?} was unexpectedly redacted:\n{text}"
            );
        }

        // Private ULA (`fc00::/7`, `fd00::/8`) and link-local (`fe80::/10` + zone) IPv6 scrubbed to `[LAN_IPV6]`.
        assert!(text.contains("[LAN_IPV6]"));
        for priv_v6 in [
            "fc00::1",
            "fd00::53",
            "fd7a:115c:a1e0::1",
            "fd7a:115c:a1e0::dead:beef",
            "fe80::1",
            "%eth0",
            "febf::1234",
            "fd12:3456:789a::1",
        ] {
            assert!(
                !text.contains(priv_v6),
                "leaked private/link-local IPv6 {priv_v6:?} in:\n{text}"
            );
        }

        // Public IPv6 resolvers and loopback preserved intact.
        for public_v6 in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2620:fe::fe",
            "2a10:50c0::ad1:ff",
            "2606:4700:fe80::99",
            "::1",
        ] {
            assert!(
                text.contains(public_v6),
                "public/loopback IPv6 {public_v6:?} was unexpectedly redacted:\n{text}"
            );
        }
    }
}
