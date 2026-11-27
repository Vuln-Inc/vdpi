use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;
use vdpi::config_file::{self, FileConfig};
use vdpi::health::DEFAULT_TUN_HEALTH_PORT;
use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
use vdpi::service::{self, LiveEngineStatus, RuntimeState, ServiceState};
use vdpi_core::config::{EngineMode, RuntimeConfig, VpnCoexistence};
use vdpi_core::dns;

use crate::models::{
    DesktopSettingsPayloadDto, DesktopStatusSnapshotDto, GuiPreferencesDto, LiveTelemetryDto,
    WintunStatusDto,
};
use crate::state::{
    engine_mode_to_dto, service_state_to_dto, split_tunnel_mode_to_dto, vpn_coexistence_to_dto,
    BinaryFileMetadata, DesktopAppState, StaticProbeEntry,
};

#[cfg(any(target_os = "windows", test))]
const WINTUN_MISSING_MESSAGE: &str = "wintun.dll is missing — reinstall vdpi Desktop, extract all files from the zip, or check Windows Defender quarantine.";

#[cfg(any(target_os = "windows", test))]
const WINTUN_HASH_MISMATCH_MESSAGE: &str = "wintun.dll failed SHA-256 hash verification (file may be corrupted or tampered) — reinstall vdpi Desktop or replace wintun.dll from an official release.";

const LIVE_PROBE_BUDGET: Duration = Duration::from_millis(500);

/// Returns the normalized desktop platform tag (`"windows"`, `"macos"`, or `"linux"`).
pub fn current_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "linux"
    }
}

/// Probes whether a SHA-256-verified `wintun.dll` is present on disk using
/// purely read-only filesystem checks (never materializing embedded DLLs,
/// touching the network, or querying OS service managers).
///
/// - On non-Windows platforms, Wintun is not required and always reports ready.
/// - On Windows, inspects existing candidate files directly via
///   [`vdpi::platform::windows_tun::verify_wintun_dll_sha256`] and distinguishes
///   missing files from SHA-256 hash verification failures.
pub fn probe_wintun_status(configured_engine: EngineMode) -> WintunStatusDto {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = configured_engine;
        WintunStatusDto {
            required: false,
            ready: true,
            message: None,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = collect_windows_wintun_candidates();
        match vdpi::platform::windows_tun::expected_wintun_dll_sha256() {
            Ok(expected_sha256) => evaluate_wintun_candidates_with_sha256(
                configured_engine,
                &candidates,
                expected_sha256,
            ),
            Err(_) => WintunStatusDto {
                required: configured_engine == EngineMode::Tun,
                ready: false,
                message: Some(WINTUN_MISSING_MESSAGE.to_string()),
            },
        }
    }
}

fn probe_wintun_status_cached(
    state: &DesktopAppState,
    configured_engine: EngineMode,
) -> WintunStatusDto {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state, configured_engine);
        WintunStatusDto {
            required: false,
            ready: true,
            message: None,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let candidates = collect_windows_wintun_candidates();
        match vdpi::platform::windows_tun::expected_wintun_dll_sha256() {
            Ok(expected_sha256) => evaluate_wintun_candidates_cached_with(
                state,
                configured_engine,
                &candidates,
                |path| {
                    vdpi::platform::windows_tun::verify_wintun_dll_sha256(path, expected_sha256)
                        .is_ok()
                },
            ),
            Err(_) => WintunStatusDto {
                required: configured_engine == EngineMode::Tun,
                ready: false,
                message: Some(WINTUN_MISSING_MESSAGE.to_string()),
            },
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn push_unique_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.contains(&path) {
        candidates.push(path);
    }
}

#[cfg(target_os = "windows")]
fn is_unc_or_device_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    let bytes = raw.as_bytes();
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let rb = rest.as_bytes();
        if rb.len() >= 4
            && rest[..3].eq_ignore_ascii_case("UNC")
            && matches!(rb[3], b'\\' | b'/')
        {
            return true;
        }
        let is_drive = rb.len() >= 3
            && rb[0].is_ascii_alphabetic()
            && rb[1] == b':'
            && matches!(rb[2], b'\\' | b'/');
        return !is_drive;
    }
    if raw.starts_with(r"\\.\") || raw.starts_with("//./") {
        return true;
    }
    bytes.len() >= 2 && matches!(bytes[0], b'\\' | b'/') && matches!(bytes[1], b'\\' | b'/')
}

#[cfg(target_os = "windows")]
fn env_non_empty_local_path(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var_os(name).filter(|v| !v.is_empty())?);
    if is_unc_or_device_path(&path) {
        return None;
    }
    Some(path)
}

#[cfg(target_os = "windows")]
fn collect_windows_wintun_candidates() -> Vec<PathBuf> {
    let installed_bin = service::installed_binary_path().ok();
    let current_exe = std::env::current_exe().ok();
    let mut candidates =
        collect_wintun_candidates(installed_bin.as_deref(), current_exe.as_deref());

    if let Some(pf) = env_non_empty_local_path("ProgramFiles") {
        push_unique_candidate(&mut candidates, pf.join("vdpi").join("bin").join("wintun.dll"));
    }

    let runtime_dll = format!("wintun-{}.dll", vdpi::platform::windows_tun::WINTUN_VERSION);
    for env_var in ["ProgramData", "LOCALAPPDATA"] {
        if let Some(root) = env_non_empty_local_path(env_var) {
            push_unique_candidate(
                &mut candidates,
                root.join("vdpi").join("runtime").join(&runtime_dll),
            );
        }
    }

    let tmp = std::env::temp_dir();
    if !tmp.as_os_str().is_empty() && !is_unc_or_device_path(&tmp) {
        push_unique_candidate(&mut candidates, tmp.join("vdpi-runtime").join(&runtime_dll));
    }

    candidates
}

#[cfg(any(target_os = "windows", test))]
fn collect_wintun_candidates_for_exe(candidates: &mut Vec<PathBuf>, exe_path: &Path) {
    let canonical = std::fs::canonicalize(exe_path).ok();
    for candidate in
        vdpi::platform::windows_tun::resolve_wintun_dll_candidates(exe_path, canonical.as_deref())
    {
        let resources_candidate = candidate
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(|dir| dir.join("resources").join("wintun.dll"));
        push_unique_candidate(candidates, candidate);
        if let Some(res_path) = resources_candidate {
            push_unique_candidate(candidates, res_path);
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn collect_wintun_candidates(
    installed_bin: Option<&Path>,
    current_exe: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(installed) = installed_bin {
        collect_wintun_candidates_for_exe(&mut candidates, installed);
    }
    if let Some(exe) = current_exe {
        collect_wintun_candidates_for_exe(&mut candidates, exe);
    }
    candidates
}

#[cfg(any(target_os = "windows", test))]
fn snapshot_existing_wintun_metadata(candidates: &[PathBuf]) -> Vec<BinaryFileMetadata> {
    candidates
        .iter()
        .filter_map(|path| BinaryFileMetadata::from_regular_file(path))
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_metadata_with<FVerify>(
    required: bool,
    existing_files: &[BinaryFileMetadata],
    verify_sha256: FVerify,
) -> WintunStatusDto
where
    FVerify: Fn(&Path) -> bool,
{
    if existing_files.is_empty() {
        return WintunStatusDto {
            required,
            ready: false,
            message: Some(WINTUN_MISSING_MESSAGE.to_string()),
        };
    }

    let ready = existing_files
        .iter()
        .any(|file| file.len > 0 && verify_sha256(&file.path));
    let message = if ready {
        None
    } else {
        Some(WINTUN_HASH_MISMATCH_MESSAGE.to_string())
    };
    WintunStatusDto {
        required,
        ready,
        message,
    }
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_candidates_with_sha256(
    configured_engine: EngineMode,
    candidates: &[PathBuf],
    expected_sha256: &str,
) -> WintunStatusDto {
    let required = configured_engine == EngineMode::Tun;
    let existing_files = snapshot_existing_wintun_metadata(candidates);
    evaluate_wintun_metadata_with(required, &existing_files, |path| {
        vdpi::platform::windows_tun::verify_wintun_dll_sha256(path, expected_sha256).is_ok()
    })
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_candidates_cached_with<FVerify>(
    state: &DesktopAppState,
    configured_engine: EngineMode,
    candidates: &[PathBuf],
    verify_sha256: FVerify,
) -> WintunStatusDto
where
    FVerify: Fn(&Path) -> bool,
{
    let required = configured_engine == EngineMode::Tun;
    let existing_files = snapshot_existing_wintun_metadata(candidates);

    if let Some(cached) = state.cached_wintun_status(&existing_files, required) {
        return cached;
    }

    let result = evaluate_wintun_metadata_with(required, &existing_files, verify_sha256);
    state.set_cached_wintun_status(existing_files, result.clone());
    result
}

fn is_system_service_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        service::systemd_system_unit_path().exists()
    }
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::query_windows_service_status().installed
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

fn system_service_installed_from_service_state(service_state: ServiceState) -> bool {
    #[cfg(target_os = "windows")]
    {
        service_state != ServiceState::NotInstalled
    }
    #[cfg(target_os = "macos")]
    {
        let _ = service_state;
        service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        let _ = service_state;
        service::systemd_system_unit_path().exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = service_state;
        false
    }
}

fn default_engine_for_service_mode(system_service_installed: bool) -> EngineMode {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if system_service_installed {
        return EngineMode::Tun;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = system_service_installed;
    RuntimeConfig::default().engine
}

struct EffectiveFileConfigLoad {
    path: PathBuf,
    config: FileConfig,
    warning: Option<String>,
}

fn redact_config_error(err: &anyhow::Error) -> String {
    dns::redact_urls_in_text(&format!("{err:#}"))
}

fn format_config_parse_warning(path: &Path, redacted_error: &str, fallback_desc: &str) -> String {
    format!(
        "Failed to parse {}: {redacted_error} ({fallback_desc})",
        path.display()
    )
}

fn load_effective_file_config_from_paths(
    system_service_installed: bool,
    sys_path: &Path,
    user_path: &Path,
) -> EffectiveFileConfigLoad {
    if system_service_installed {
        return match config_file::load_file_config_or_default(Some(sys_path), true) {
            Ok((_, cfg)) => EffectiveFileConfigLoad {
                path: sys_path.to_path_buf(),
                config: cfg,
                warning: None,
            },
            Err(err) => {
                let redacted = redact_config_error(&err);
                warn!(
                    path = %sys_path.display(),
                    error = %redacted,
                    "failed to load system config.toml; falling back to defaults"
                );
                EffectiveFileConfigLoad {
                    path: sys_path.to_path_buf(),
                    config: FileConfig::default(),
                    warning: Some(format_config_parse_warning(
                        sys_path,
                        &redacted,
                        "using default settings",
                    )),
                }
            }
        };
    }

    let mut user_warning = None;
    match config_file::load_file_config_or_default(Some(user_path), false) {
        Ok((Some(path), cfg)) => {
            return EffectiveFileConfigLoad {
                path,
                config: cfg,
                warning: None,
            };
        }
        Ok((None, _)) => {}
        Err(err) => {
            let redacted = redact_config_error(&err);
            warn!(
                path = %user_path.display(),
                error = %redacted,
                "failed to load user config.toml; checking system config fallback"
            );
            user_warning = Some(format_config_parse_warning(
                user_path,
                &redacted,
                "using fallback settings",
            ));
        }
    }

    match config_file::load_file_config_or_default(Some(sys_path), true) {
        Ok((Some(path), cfg)) => EffectiveFileConfigLoad {
            path,
            config: cfg,
            warning: user_warning,
        },
        Ok((None, _)) => EffectiveFileConfigLoad {
            path: user_path.to_path_buf(),
            config: FileConfig::default(),
            warning: user_warning,
        },
        Err(err) => {
            let redacted = redact_config_error(&err);
            warn!(
                path = %sys_path.display(),
                error = %redacted,
                "failed to load fallback system config.toml; falling back to defaults"
            );
            let warning = user_warning.or_else(|| {
                Some(format_config_parse_warning(
                    sys_path,
                    &redacted,
                    "using default settings",
                ))
            });
            EffectiveFileConfigLoad {
                path: user_path.to_path_buf(),
                config: FileConfig::default(),
                warning,
            }
        }
    }
}

/// Returns the active `config.toml` path for the current installation state.
pub fn active_config_path() -> PathBuf {
    let sys_path = config_file::system_config_path();
    if is_system_service_installed() {
        return sys_path;
    }
    let user_path = config_file::user_config_path();
    if user_path.is_file() {
        user_path
    } else if sys_path.is_file() {
        sys_path
    } else {
        user_path
    }
}

fn default_user_logs_dir() -> PathBuf {
    service::vdpi_root_dir()
        .map(|root| root.join("logs"))
        .unwrap_or_else(|_| {
            config_file::user_config_path()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|dir| dir.join("logs"))
                .unwrap_or_else(|| PathBuf::from("logs"))
        })
}

fn resolve_logs_dir_for_platform(
    platform: &str,
    system_service_installed: bool,
    default_user_logs: PathBuf,
    linux_system_candidates: &[PathBuf],
) -> PathBuf {
    if system_service_installed {
        match platform {
            "macos" => return PathBuf::from("/var/log"),
            "linux" => {
                for candidate in linux_system_candidates {
                    if candidate.is_dir() {
                        return candidate.clone();
                    }
                }
                return default_user_logs;
            }
            _ => {}
        }
    }
    default_user_logs
}

fn default_logs_dir_for_service_mode(system_service_installed: bool) -> PathBuf {
    let user_logs = default_user_logs_dir();
    let linux_candidates = [
        PathBuf::from("/var/log/vdpi"),
        user_logs.clone(),
        PathBuf::from("/var/log"),
    ];
    resolve_logs_dir_for_platform(
        current_platform(),
        system_service_installed,
        user_logs,
        &linux_candidates,
    )
}

/// Returns the default directory where `vdpi` stores service/runtime logs.
///
/// On macOS LaunchDaemon mode this returns `/var/log`; on Linux systemd
/// system-service mode it returns the first existing logs directory among
/// `/var/log/vdpi`, `~/.vdpi/logs`, and `/var/log`; otherwise `~/.vdpi/logs`
/// (or `%ProgramFiles%\vdpi\logs` on Windows).
pub fn default_logs_dir() -> PathBuf {
    default_logs_dir_for_service_mode(is_system_service_installed())
}

fn is_custom_doh_url(dns_addr: &str) -> bool {
    dns::validate_custom_dns_input(dns_addr)
        .is_ok_and(|normalized| normalized.starts_with("https://"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FastProbeCandidate {
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
}

fn probe_connect_ip(addr: IpAddr) -> Option<IpAddr> {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ip if ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn build_fast_probe_candidates(
    cfg: &RuntimeConfig,
    states: &[RuntimeState],
) -> Vec<FastProbeCandidate> {
    let cfg_connect_ip = probe_connect_ip(cfg.addr);
    let primary_socks = states
        .iter()
        .find(|s| {
            s.port == cfg.port
                && (s.addr == cfg.addr
                    || cfg_connect_ip.is_some_and(|ip| probe_connect_ip(s.addr) == Some(ip)))
        })
        .map_or(cfg.socks_port, |s| s.socks_port);

    let mut seen: Vec<(IpAddr, u16)> = Vec::new();
    let mut out = Vec::new();

    for (addr, port, socks_port) in states
        .iter()
        .map(|s| (s.addr, s.port, s.socks_port))
        .chain(std::iter::once((cfg.addr, cfg.port, primary_socks)))
        .chain(std::iter::once((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DEFAULT_TUN_HEALTH_PORT,
            None,
        )))
    {
        if port == 0 {
            continue;
        }
        let Some(connect_ip) = probe_connect_ip(addr) else {
            continue;
        };
        if seen.contains(&(connect_ip, port)) {
            continue;
        }
        seen.push((connect_ip, port));
        out.push(FastProbeCandidate {
            addr,
            port,
            socks_port,
        });
    }

    out
}

fn probe_live_engine_fast(cfg: &RuntimeConfig) -> Option<LiveEngineStatus> {
    let states = service::read_runtime_states();
    let deadline = Instant::now() + LIVE_PROBE_BUDGET;

    for candidate in build_fast_probe_candidates(cfg, &states) {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(status) = service::probe_live_engine(
            candidate.addr,
            candidate.port,
            candidate.socks_port.unwrap_or(0),
        ) {
            return Some(status);
        }
    }

    None
}

fn format_vpn_scope_conflict(scope: &VpnScope) -> Option<String> {
    match scope {
        VpnScope::FullTunnel {
            provider,
            iface,
            kill_switch,
        } => {
            let mut desc = if iface.trim().is_empty() {
                provider.clone()
            } else {
                format!("{provider} ({iface})")
            };
            if *kill_switch {
                desc.push_str(" [kill-switch]");
            }
            Some(desc)
        }
        VpnScope::None | VpnScope::SplitOverlay { .. } => None,
    }
}

fn detect_vpn_conflict_summary(self_tun_name: Option<&str>) -> Option<String> {
    let scope = detect_active_vpn(self_tun_name);
    format_vpn_scope_conflict(&scope)
}

fn compute_fallback_dns(file_cfg: &FileConfig, fallback: &str) -> String {
    let fallback_normalized =
        dns::validate_custom_dns_input(fallback).unwrap_or_else(|_| fallback.to_string());
    file_cfg
        .dns_addr
        .as_deref()
        .and_then(|raw| dns::validate_custom_dns_input(raw).ok())
        .unwrap_or(fallback_normalized)
}

fn locate_installed_binary_path() -> Option<PathBuf> {
    let installed = service::installed_binary_path().ok().filter(|p| p.is_file());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let sys_bin = PathBuf::from(service::UNIX_SYSTEM_BIN_PATH);
        #[cfg(target_os = "macos")]
        let has_system_daemon = service::launch_daemon_plist_path().exists();
        #[cfg(target_os = "linux")]
        let has_system_daemon = service::systemd_system_unit_path().exists();

        if has_system_daemon && sys_bin.is_file() {
            Some(sys_bin)
        } else {
            installed.or_else(|| sys_bin.is_file().then_some(sys_bin))
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        installed
    }
}

fn resolve_installed_version_with<FLocate, FProbe>(
    state: &DesktopAppState,
    locate_binary: FLocate,
    probe_version: FProbe,
) -> Option<String>
where
    FLocate: FnOnce() -> Option<PathBuf>,
    FProbe: FnOnce(&Path) -> Option<String>,
{
    let Some(binary_path) = locate_binary() else {
        state.clear_cached_installed_version();
        return None;
    };

    let Some(metadata) = BinaryFileMetadata::from_path(&binary_path) else {
        state.clear_cached_installed_version();
        return None;
    };

    if let Some(cached) = state.cached_installed_version(&metadata) {
        return cached;
    }

    let version = probe_version(&binary_path);
    if version.is_some() {
        state.set_cached_installed_version(metadata, version.clone());
    } else {
        state.clear_cached_installed_version();
    }
    version
}

fn resolve_installed_version_cached(state: &DesktopAppState) -> Option<String> {
    resolve_installed_version_with(state, locate_installed_binary_path, |_| {
        service::detect_installed_info().and_then(|info| info.installed_version)
    })
}

fn collect_static_probe_entry(
    state: &DesktopAppState,
    default_cfg: &RuntimeConfig,
    live_status: Option<&LiveEngineStatus>,
    now: Instant,
) -> StaticProbeEntry {
    let service_state = service::detect_service_state();
    let system_service_installed = system_service_installed_from_service_state(service_state);
    let sys_path = config_file::system_config_path();
    let user_path = config_file::user_config_path();
    let loaded =
        load_effective_file_config_from_paths(system_service_installed, &sys_path, &user_path);

    let default_engine = default_engine_for_service_mode(system_service_installed);
    let mut runtime = RuntimeConfig {
        engine: default_engine,
        ..default_cfg.clone()
    };
    loaded.config.apply_to_runtime(&mut runtime);

    let configured_engine = runtime.engine;
    let fallback_dns = compute_fallback_dns(&loaded.config, &default_cfg.dns_addr);
    let installed_version = resolve_installed_version_cached(state);
    let wintun = probe_wintun_status_cached(state, configured_engine);
    let tray_supported = crate::tray::is_tray_host_available();
    let logs_dir = default_logs_dir_for_service_mode(system_service_installed)
        .display()
        .to_string();

    let vpn_conflict = if runtime.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_status
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_status.and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    StaticProbeEntry {
        installed_version,
        wintun,
        config_path: loaded.path.display().to_string(),
        logs_dir,
        tray_supported,
        split_tunnel_mode: split_tunnel_mode_to_dto(runtime.split_tunnel.mode),
        split_tunnel_count: runtime.split_tunnel.apps.len(),
        config_warning: loaded.warning,
        configured_engine: engine_mode_to_dto(configured_engine),
        service_state: service_state_to_dto(service_state),
        vpn_conflict,
        fallback_dns,
        cached_at: now,
    }
}

fn map_live_telemetry(
    live: LiveEngineStatus,
    fallback_dns: &str,
    default_cfg: &RuntimeConfig,
    rx_rate_bps: u64,
    tx_rate_bps: u64,
) -> LiveTelemetryDto {
    let fallback = fallback_dns.trim();
    let raw_dns = live
        .dns_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(if fallback.is_empty() {
            default_cfg.dns_addr.as_str()
        } else {
            fallback
        });
    let raw_doh = live.doh.unwrap_or(default_cfg.enable_doh);
    let dns_display = dns::redact_dns_for_display(raw_dns);
    let doh_enabled = dns::is_effective_doh_target(raw_dns, raw_doh);

    LiveTelemetryDto {
        running: true,
        engine: engine_mode_to_dto(live.engine),
        addr: live.addr.to_string(),
        port: live.port,
        socks_port: live.socks_port,
        tun_interface: live.tun_interface,
        physical_nic: live.physical_nic,
        vpn_conflict: live.vpn_conflict,
        version: live.version,
        mode: live.mode,
        doh_enabled,
        dns_display,
        block_quic: live.block_quic.unwrap_or(default_cfg.block_quic),
        active_connections: live.active_connections.unwrap_or(0),
        total_connections: live.total_connections.unwrap_or(0),
        learned_hosts: live.learned_hosts.unwrap_or(0),
        isp_stage: live.isp_stage,
        udp_flows_active: live.udp_flows_active.unwrap_or(0),
        quic_blocked: live.quic_blocked.unwrap_or(0),
        dns_queries: live.dns_queries.unwrap_or(0),
        rss_kb: live.rss_kb,
        bytes_rx: live.bytes_rx.unwrap_or(0),
        bytes_tx: live.bytes_tx.unwrap_or(0),
        rx_rate_bps,
        tx_rate_bps,
        tls_handshakes: live.tls_handshakes.unwrap_or(0),
        auto_heal_escalations: live.auto_heal_escalations.unwrap_or(0),
    }
}

fn collect_status_snapshot_with<FNow, FLive, FStatic>(
    state: &DesktopAppState,
    mut force_full_refresh: bool,
    now_fn: FNow,
    probe_live: FLive,
    probe_static: FStatic,
) -> Arc<DesktopStatusSnapshotDto>
where
    FNow: Fn() -> Instant,
    FLive: FnOnce(&RuntimeConfig) -> Option<LiveEngineStatus>,
    FStatic: FnOnce(&RuntimeConfig, Option<&LiveEngineStatus>, Instant) -> StaticProbeEntry,
{
    let _snapshot_guard = state
        .snapshot_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let default_cfg = RuntimeConfig::default();
    let live_status = probe_live(&default_cfg);
    let sampled_at = now_fn();

    let prev_live_present = state.last_snapshot().map(|s| s.live.is_some());
    if prev_live_present.is_some_and(|was_live| was_live != live_status.is_some()) {
        force_full_refresh = true;
    }

    let static_entry = if force_full_refresh {
        let fresh = probe_static(&default_cfg, live_status.as_ref(), sampled_at);
        state.set_static_probe_cache(fresh.clone());
        fresh
    } else if let Some(cached) = state.cached_static_probes(sampled_at) {
        cached
    } else {
        let fresh = probe_static(&default_cfg, live_status.as_ref(), sampled_at);
        state.set_static_probe_cache(fresh.clone());
        fresh
    };

    let live = match live_status {
        Some(live_status) => {
            let bytes_rx = live_status.bytes_rx.unwrap_or(0);
            let bytes_tx = live_status.bytes_tx.unwrap_or(0);
            let (rx_rate_bps, tx_rate_bps) =
                state.sample_rates(bytes_rx, bytes_tx, sampled_at);
            Some(map_live_telemetry(
                live_status,
                &static_entry.fallback_dns,
                &default_cfg,
                rx_rate_bps,
                tx_rate_bps,
            ))
        }
        None => {
            state.reset_rates();
            None
        }
    };

    let vpn_conflict = live
        .as_ref()
        .and_then(|l| l.vpn_conflict.clone())
        .or_else(|| static_entry.vpn_conflict.clone());

    let snapshot = Arc::new(DesktopStatusSnapshotDto {
        snapshot_seq: state.next_snapshot_seq(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: current_platform().to_string(),
        service_state: static_entry.service_state,
        installed_version: static_entry.installed_version,
        configured_engine: static_entry.configured_engine,
        live,
        vpn_conflict,
        wintun: static_entry.wintun,
        split_tunnel_mode: static_entry.split_tunnel_mode,
        split_tunnel_count: static_entry.split_tunnel_count,
        config_path: static_entry.config_path,
        logs_dir: static_entry.logs_dir,
        tray_supported: static_entry.tray_supported,
        config_warning: static_entry.config_warning,
    });

    state.set_last_snapshot(Arc::clone(&snapshot));
    snapshot
}

/// Probes live loopback daemon telemetry and combines it with TTL-cached
/// installation, background service, Wintun, tray-host, and split-tunnel state
/// into an immutable `Arc<DesktopStatusSnapshotDto>`.
///
/// Acquires `state.snapshot_lock` so concurrent polls never race `RateTracker`.
/// Regular ticks (`force_full_refresh == false`) reuse `state.static_probe_cache`
/// within its 45-second TTL and run only the fast loopback `/vdpi-health` probe,
/// escalating immediately to a full refresh whenever live daemon presence flips
/// (`Some -> None` or `None -> Some`).
pub fn collect_status_snapshot(
    state: &DesktopAppState,
    force_full_refresh: bool,
) -> Arc<DesktopStatusSnapshotDto> {
    collect_status_snapshot_with(
        state,
        force_full_refresh,
        Instant::now,
        probe_live_engine_fast,
        |default_cfg, live_status, now| {
            collect_static_probe_entry(state, default_cfg, live_status, now)
        },
    )
}

fn build_settings_payload_from_config(
    file_cfg: &FileConfig,
    default_engine: EngineMode,
    prefs: GuiPreferencesDto,
) -> DesktopSettingsPayloadDto {
    let mut runtime = RuntimeConfig {
        engine: default_engine,
        ..RuntimeConfig::default()
    };
    file_cfg.apply_to_runtime(&mut runtime);

    let dns_addr = runtime.dns_addr.clone();
    let dns_display = dns::redact_dns_for_display(&dns_addr);
    let dns_is_custom_url = is_custom_doh_url(&dns_addr);
    let doh_enabled = runtime.enable_doh;
    let effective_doh = dns::is_effective_doh_target(&dns_addr, doh_enabled);

    DesktopSettingsPayloadDto {
        engine: engine_mode_to_dto(runtime.engine),
        dns_addr,
        dns_display,
        dns_is_custom_url,
        doh_enabled,
        effective_doh,
        block_quic: runtime.block_quic,
        tun_ipv6: runtime.tun_ipv6,
        ipv4_only: runtime.dns_ipv4_only,
        vpn_coexistence: vpn_coexistence_to_dto(runtime.vpn_coexistence),
        bypass_domains: runtime.bypass_domains,
        include_domains: runtime.patterns,
        split_tunnel_mode: split_tunnel_mode_to_dto(runtime.split_tunnel.mode),
        split_tunnel_apps: runtime.split_tunnel.apps,
        gui: prefs,
    }
}

/// Loads the effective `FileConfig` cleanly and maps it alongside the provided
/// `GuiPreferencesDto` into a `DesktopSettingsPayloadDto`, redacting any secret
/// path/query/userinfo tokens from `dns_display`.
pub fn build_settings_payload(prefs: GuiPreferencesDto) -> DesktopSettingsPayloadDto {
    let system_installed = is_system_service_installed();
    let sys_path = config_file::system_config_path();
    let user_path = config_file::user_config_path();
    let loaded = load_effective_file_config_from_paths(system_installed, &sys_path, &user_path);
    let default_engine = default_engine_for_service_mode(system_installed);
    build_settings_payload_from_config(&loaded.config, default_engine, prefs)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use vdpi_core::config::{SplitTunnelMode, VpnCoexistence};

    use super::*;
    use crate::models::{
        EngineModeDto, LanguagePreferenceDto, ServiceStateDto, SplitTunnelModeDto,
        ThemePreferenceDto, VpnCoexistenceDto,
    };
    use crate::state::STATIC_PROBE_CACHE_TTL;

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let pid = std::process::id();
            let ts_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("vdpi-status-test-{label}-{pid}-{ts_nanos}-{seq}"));
            fs::create_dir_all(&path).expect("create test temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_live_status(dns_addr: Option<&str>, doh: Option<bool>) -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            version: Some("0.6.0".to_string()),
            mode: Some("combo".to_string()),
            doh,
            dns_addr: dns_addr.map(str::to_string),
            block_quic: Some(true),
            active_connections: Some(7),
            total_connections: Some(123),
            learned_hosts: Some(14),
            isp_stage: Some("Stage 1".to_string()),
            udp_flows_active: Some(3),
            quic_blocked: Some(9),
            dns_queries: Some(42),
            rss_kb: Some(18_432),
            bytes_rx: Some(10_000),
            bytes_tx: Some(20_000),
            tls_handshakes: Some(55),
            auto_heal_escalations: Some(1),
        }
    }

    fn sample_static_entry(
        cached_at: Instant,
        tray_supported: bool,
        config_warning: Option<String>,
    ) -> StaticProbeEntry {
        StaticProbeEntry {
            installed_version: Some("0.6.0".to_string()),
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            config_path: "/etc/vdpi/config.toml".to_string(),
            logs_dir: "/var/log".to_string(),
            tray_supported,
            split_tunnel_mode: SplitTunnelModeDto::Exclude,
            split_tunnel_count: 2,
            config_warning,
            configured_engine: EngineModeDto::Tun,
            service_state: ServiceStateDto::Running,
            vpn_conflict: None,
            fallback_dns: "1.1.1.1".to_string(),
            cached_at,
        }
    }

    #[test]
    fn current_platform_returns_expected_target_tag() {
        let tag = current_platform();
        assert!(matches!(tag, "windows" | "macos" | "linux"));

        #[cfg(target_os = "windows")]
        assert_eq!(tag, "windows");
        #[cfg(target_os = "macos")]
        assert_eq!(tag, "macos");
        #[cfg(target_os = "linux")]
        assert_eq!(tag, "linux");
    }

    #[test]
    fn live_telemetry_redacts_doh_secrets_and_computes_effective_doh() {
        let default_cfg = RuntimeConfig::default();
        let custom_url = "https://dns.nextdns.io/abc123secret?device=gaming-rig";
        let dto = map_live_telemetry(
            sample_live_status(Some(custom_url), Some(false)),
            "1.1.1.1",
            &default_cfg,
            4_096,
            2_048,
        );
        assert!(dto.running);
        assert_eq!(dto.engine, EngineModeDto::Tun);
        assert_eq!(dto.dns_display, "https://dns.nextdns.io");
        assert!(!dto.dns_display.contains("abc123secret"));
        assert!(!dto.dns_display.contains("gaming-rig"));
        assert!(dto.doh_enabled);
        assert_eq!(dto.rx_rate_bps, 4_096);
        assert_eq!(dto.tx_rate_bps, 2_048);

        let ipv6_url = "https://[2606:4700:4700::1111]:8443/profile-secret?tok=99";
        let ipv6_dto = map_live_telemetry(
            sample_live_status(Some(ipv6_url), Some(false)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(ipv6_dto.dns_display, "https://[2606:4700:4700::1111]:8443");
        assert!(!ipv6_dto.dns_display.contains("profile-secret"));
        assert!(!ipv6_dto.dns_display.contains("tok=99"));
        assert!(ipv6_dto.doh_enabled);

        let userinfo_url = "https://alice:topsecret@dns.example.com/private-path";
        let userinfo_dto = map_live_telemetry(
            sample_live_status(Some(userinfo_url), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(userinfo_dto.dns_display, "https://dns.example.com");
        assert!(!userinfo_dto.dns_display.contains("alice"));
        assert!(!userinfo_dto.dns_display.contains("topsecret"));
        assert!(!userinfo_dto.dns_display.contains("private-path"));

        // Known public DoH IP respects doh flag.
        let cf_on = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(cf_on.dns_display, "1.1.1.1");
        assert!(cf_on.doh_enabled);

        let cf_off = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(false)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(cf_off.dns_display, "1.1.1.1");
        assert!(!cf_off.doh_enabled);

        // Bare custom UDP-first IP must NOT be mislabeled as effective DoH.
        let udp_custom = map_live_telemetry(
            sample_live_status(Some("76.76.2.0"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(udp_custom.dns_display, "76.76.2.0");
        assert!(!udp_custom.doh_enabled);

        // Missing/empty live dns_addr falls back cleanly and redacts the fallback.
        let fallback_dto = map_live_telemetry(
            sample_live_status(Some("   "), Some(false)),
            "https://dns.nextdns.io/fallback-secret",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(fallback_dto.dns_display, "https://dns.nextdns.io");
        assert!(!fallback_dto.dns_display.contains("fallback-secret"));
        assert!(fallback_dto.doh_enabled);

        // Empty live dns_addr and empty fallback_dns reuse default_cfg.dns_addr.
        let default_dns_dto = map_live_telemetry(
            sample_live_status(None, None),
            "   ",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(default_dns_dto.dns_display, default_cfg.dns_addr);
        assert_eq!(
            default_dns_dto.doh_enabled,
            dns::is_effective_doh_target(&default_cfg.dns_addr, default_cfg.enable_doh)
        );
    }

    #[test]
    fn live_telemetry_integrates_with_state_rate_tracker() {
        let state = DesktopAppState::default();
        let default_cfg = RuntimeConfig::default();
        let t0 = Instant::now();

        let (rx0, tx0) = state.sample_rates(10_000, 20_000, t0);
        let snap0 = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            rx0,
            tx0,
        );
        assert_eq!((snap0.rx_rate_bps, snap0.tx_rate_bps), (0, 0));

        let (rx1, tx1) = state.sample_rates(18_000, 36_000, t0 + Duration::from_secs(2));
        let mut status1 = sample_live_status(Some("1.1.1.1"), Some(true));
        status1.bytes_rx = Some(18_000);
        status1.bytes_tx = Some(36_000);
        let snap1 = map_live_telemetry(status1, "1.1.1.1", &default_cfg, rx1, tx1);
        assert_eq!((snap1.rx_rate_bps, snap1.tx_rate_bps), (4_000, 8_000));
    }

    #[test]
    fn settings_payload_maps_defaults_cleanly() {
        let prefs = GuiPreferencesDto {
            theme: ThemePreferenceDto::Dark,
            language: LanguagePreferenceDto::System,
            keep_in_tray_on_close: true,
            minimize_to_tray: false,
            start_minimized_to_tray: true,
            show_taskbar_icon_when_minimized: false,
        };

        let payload = build_settings_payload_from_config(
            &FileConfig::default(),
            EngineMode::Proxy,
            prefs.clone(),
        );

        assert_eq!(payload.engine, EngineModeDto::Proxy);
        assert_eq!(payload.dns_addr, "1.1.1.1");
        assert_eq!(payload.dns_display, "1.1.1.1");
        assert!(!payload.dns_is_custom_url);
        assert!(payload.doh_enabled);
        assert!(payload.effective_doh);
        assert!(payload.block_quic);
        assert!(!payload.tun_ipv6);
        assert!(!payload.ipv4_only);
        assert_eq!(payload.vpn_coexistence, VpnCoexistenceDto::AutoYield);
        assert!(payload.bypass_domains.is_empty());
        assert!(payload.include_domains.is_empty());
        assert_eq!(payload.split_tunnel_mode, SplitTunnelModeDto::All);
        assert!(payload.split_tunnel_apps.is_empty());
        assert_eq!(payload.gui, prefs);
    }

    #[test]
    fn settings_payload_maps_overrides_and_never_leaks_doh_secret_in_display() {
        let file_cfg = FileConfig {
            engine: Some(EngineMode::Tun),
            dns_addr: Some("https://dns.nextdns.io/super-secret-id?device=desktop".to_string()),
            doh: Some(false),
            block_quic: Some(false),
            tun_ipv6: Some(true),
            ipv4_only: Some(true),
            vpn_coexistence: Some(VpnCoexistence::Warn),
            bypass_domains: Some(vec!["bank.example".to_string(), "corp.local".to_string()]),
            include_domains: Some(vec!["discord.com".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec![
                r"C:\Games\Discord.exe".to_string(),
                "STEAM.EXE".to_string(),
                "discord".to_string(),
            ]),
            ..FileConfig::default()
        };

        let prefs = GuiPreferencesDto::default();
        let payload =
            build_settings_payload_from_config(&file_cfg, EngineMode::Proxy, prefs.clone());

        assert_eq!(payload.engine, EngineModeDto::Tun);
        assert_eq!(
            payload.dns_addr,
            "https://dns.nextdns.io/super-secret-id?device=desktop"
        );
        assert_eq!(payload.dns_display, "https://dns.nextdns.io");
        assert!(!payload.dns_display.contains("super-secret-id"));
        assert!(!payload.dns_display.contains("device=desktop"));
        assert!(payload.dns_is_custom_url);
        assert!(!payload.doh_enabled);
        assert!(payload.effective_doh);
        assert!(!payload.block_quic);
        assert!(payload.tun_ipv6);
        assert!(payload.ipv4_only);
        assert_eq!(payload.vpn_coexistence, VpnCoexistenceDto::Warn);
        assert_eq!(payload.bypass_domains, vec!["bank.example", "corp.local"]);
        assert_eq!(payload.include_domains, vec!["discord.com"]);
        assert_eq!(payload.split_tunnel_mode, SplitTunnelModeDto::Exclude);
        assert_eq!(payload.split_tunnel_apps, vec!["Discord.exe", "STEAM.EXE"]);
        assert_eq!(payload.gui, prefs);
    }

    #[test]
    fn settings_payload_distinguishes_custom_udp_ip_from_effective_doh() {
        let file_cfg = FileConfig {
            dns_addr: Some("76.76.2.0".to_string()),
            doh: Some(true),
            ..FileConfig::default()
        };

        let payload = build_settings_payload_from_config(
            &file_cfg,
            EngineMode::Proxy,
            GuiPreferencesDto::default(),
        );

        assert_eq!(payload.dns_addr, "76.76.2.0");
        assert_eq!(payload.dns_display, "76.76.2.0");
        assert!(!payload.dns_is_custom_url);
        assert!(payload.doh_enabled);
        assert!(!payload.effective_doh);
    }

    #[test]
    fn is_custom_doh_url_requires_validated_https_url() {
        assert!(is_custom_doh_url("https://dns.nextdns.io/abc123?device=pc"));
        assert!(is_custom_doh_url("HTTPS://dns.quad9.net/dns-query"));
        assert!(is_custom_doh_url(
            "  https://[2606:4700:4700::1111]:8443/dns-query  "
        ));

        // Non-https schemes, malformed URLs, loopback hosts, userinfo, and bare IPs must be false.
        assert!(!is_custom_doh_url("http://dns.nextdns.io/abc123"));
        assert!(!is_custom_doh_url("ftp://dns.example.com/dns-query"));
        assert!(!is_custom_doh_url("foo://bar"));
        assert!(!is_custom_doh_url("https://"));
        assert!(!is_custom_doh_url(
            "https://alice:secret@dns.example.com/dns-query"
        ));
        assert!(!is_custom_doh_url("https://dns.example.com/dns-query#frag"));
        assert!(!is_custom_doh_url("https://0.0.0.0/dns-query"));
        assert!(is_custom_doh_url("https://127.0.0.1/dns-query"));
        assert!(!is_custom_doh_url("1.1.1.1"));
        assert!(!is_custom_doh_url("2606:4700:4700::1111"));
        assert!(!is_custom_doh_url(""));
        assert!(!is_custom_doh_url("   "));

        // Non-https dns_addr in FileConfig must never be flagged as a custom DoH URL.
        let invalid_scheme_cfg = FileConfig {
            dns_addr: Some("http://dns.example.com/secret-token".to_string()),
            ..FileConfig::default()
        };
        let payload = build_settings_payload_from_config(
            &invalid_scheme_cfg,
            EngineMode::Proxy,
            GuiPreferencesDto::default(),
        );
        assert!(!payload.dns_is_custom_url);
        assert!(!payload.dns_display.contains("secret-token"));
    }

    #[test]
    fn effective_file_config_loader_respects_service_mode_and_corrupt_fallback() {
        let dir = TestDir::new("config-precedence");
        let sys_path = dir.path().join("system.toml");
        let user_path = dir.path().join("user.toml");

        fs::write(&sys_path, "engine = \"tun\"\ndns_addr = \"9.9.9.9\"\n")
            .expect("write system config");
        fs::write(&user_path, "engine = \"proxy\"\ndns_addr = \"8.8.8.8\"\n")
            .expect("write user config");

        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.path, sys_path);
        assert_eq!(loaded.config.engine, Some(EngineMode::Tun));
        assert_eq!(loaded.config.dns_addr.as_deref(), Some("9.9.9.9"));
        assert!(loaded.warning.is_none());

        let loaded = load_effective_file_config_from_paths(false, &sys_path, &user_path);
        assert_eq!(loaded.path, user_path);
        assert_eq!(loaded.config.engine, Some(EngineMode::Proxy));
        assert_eq!(loaded.config.dns_addr.as_deref(), Some("8.8.8.8"));
        assert!(loaded.warning.is_none());

        // Corrupt system config in service mode must fall back cleanly to defaults,
        // surface a warning, and never read the user-writable config file.
        fs::write(&sys_path, "not valid = [toml").expect("write corrupt system config");
        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.path, sys_path);
        assert_eq!(loaded.config, FileConfig::default());
        assert!(loaded.warning.is_some());

        // Missing user config falls back to defaults without a warning when system config is absent.
        let missing_sys = dir.path().join("missing-sys.toml");
        let missing_user = dir.path().join("missing-user.toml");
        let loaded = load_effective_file_config_from_paths(false, &missing_sys, &missing_user);
        assert_eq!(loaded.path, missing_user);
        assert_eq!(loaded.config, FileConfig::default());
        assert!(loaded.warning.is_none());
    }

    #[test]
    fn config_parse_warning_redacts_embedded_urls() {
        let dir = TestDir::new("config-redact");
        let sys_path = dir.path().join("system.toml");
        let user_path = dir.path().join("user.toml");

        // Trigger a parse error whose message echoes the raw value containing a secret URL.
        fs::write(
            &sys_path,
            "engine = \"https://alice:topsecret@dns.nextdns.io/secret-profile?device=gaming-rig\"\n",
        )
        .expect("write invalid config with secret url");

        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.config, FileConfig::default());
        let warning = loaded
            .warning
            .expect("corrupt config must emit config_warning");
        assert!(warning.contains("https://dns.nextdns.io"));
        assert!(!warning.contains("alice"));
        assert!(!warning.contains("topsecret"));
        assert!(!warning.contains("secret-profile"));
        assert!(!warning.contains("gaming-rig"));

        let err = anyhow::anyhow!(
            "invalid endpoint https://user:pass@doh.example.com/private?tok=42 and http://1.2.3.4/leak"
        );
        let redacted = redact_config_error(&err);
        assert!(redacted.contains("https://doh.example.com"));
        assert!(redacted.contains("http://1.2.3.4"));
        assert!(!redacted.contains("user:pass"));
        assert!(!redacted.contains("private"));
        assert!(!redacted.contains("tok=42"));
        assert!(!redacted.contains("leak"));
    }

    #[test]
    fn wintun_candidate_evaluation_checks_real_sha256_and_friendly_message() {
        let dir = TestDir::new("wintun");
        let empty_dll = dir.path().join("empty-wintun.dll");
        let corrupted_dll = dir.path().join("corrupted-wintun.dll");
        let valid_dll = dir.path().join("wintun.dll");
        let missing_dll = dir.path().join("missing-wintun.dll");

        let valid_bytes = b"MZ-verified-wintun-test-payload";
        let expected_sha256 = vdpi::update::sha256_hex(valid_bytes);

        fs::write(&empty_dll, b"").expect("write empty dll");
        fs::write(&corrupted_dll, b"MZ-tampered-or-corrupted-dll").expect("write corrupted dll");
        fs::write(&valid_dll, valid_bytes).expect("write valid dll");

        // Missing file reports missing message (not SHA-256 hash mismatch).
        let missing_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            std::slice::from_ref(&missing_dll),
            &expected_sha256,
        );
        assert!(missing_tun.required);
        assert!(!missing_tun.ready);
        assert_eq!(
            missing_tun.message.as_deref(),
            Some(WINTUN_MISSING_MESSAGE)
        );
        let missing_lower = missing_tun
            .message
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(!missing_lower.contains("sha-256"));
        assert!(!missing_lower.contains("hash"));
        assert!(!missing_lower.contains("mismatch"));

        // Existing empty or non-empty corrupted DLL (wrong SHA-256) reports hash
        // verification failure so diagnostics routes to the hash-mismatch branch.
        let invalid_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            &[missing_dll.clone(), empty_dll.clone(), corrupted_dll.clone()],
            &expected_sha256,
        );
        assert!(invalid_tun.required);
        assert!(!invalid_tun.ready);
        assert_eq!(
            invalid_tun.message.as_deref(),
            Some(WINTUN_HASH_MISMATCH_MESSAGE)
        );
        let mismatch_lower = invalid_tun
            .message
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(mismatch_lower.contains("sha-256"));
        assert!(mismatch_lower.contains("hash"));

        let invalid_proxy = evaluate_wintun_candidates_with_sha256(
            EngineMode::Proxy,
            std::slice::from_ref(&corrupted_dll),
            &expected_sha256,
        );
        assert!(!invalid_proxy.required);
        assert!(!invalid_proxy.ready);
        assert_eq!(
            invalid_proxy.message.as_deref(),
            Some(WINTUN_HASH_MISMATCH_MESSAGE)
        );

        // SHA-256 verified DLL in any candidate slot reports ready with no warning message.
        let ready_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            &[missing_dll, empty_dll, corrupted_dll, valid_dll],
            &expected_sha256,
        );
        assert!(ready_tun.required);
        assert!(ready_tun.ready);
        assert!(ready_tun.message.is_none());
    }

    #[test]
    fn binary_metadata_cache_skips_reprobe_and_rehash_until_file_changes_or_invalidated() {
        let dir = TestDir::new("binary-meta-cache");
        let fake_bin = dir.path().join("vdpi.exe");
        let wintun_dll = dir.path().join("wintun.dll");

        let valid_bytes = b"MZ-verified-wintun-cached-payload";
        let expected_sha256 = vdpi::update::sha256_hex(valid_bytes);
        fs::write(&fake_bin, b"vdpi-v0.6.0-binary").expect("write fake binary");
        fs::write(&wintun_dll, valid_bytes).expect("write valid dll");

        let state = DesktopAppState::default();
        let version_probes = AtomicUsize::new(0);
        let wintun_hashes = AtomicUsize::new(0);

        // First installed_version probe runs once and caches under (path, len, mtime).
        let v1 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.0".to_string())
            },
        );
        assert_eq!(v1.as_deref(), Some("0.6.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 1);

        // Second probe on unchanged binary skips spawning completely.
        let v2 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.1".to_string())
            },
        );
        assert_eq!(v2.as_deref(), Some("0.6.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 1);

        // Replacing the binary (different length) triggers a fresh probe.
        fs::write(&fake_bin, b"vdpi-v0.7.0-upgraded-binary-payload")
            .expect("rewrite upgraded binary");
        let v3 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(v3.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 2);

        // First Wintun verification hashes once and caches.
        let candidates = [wintun_dll.clone()];
        let w1 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(w1.required && w1.ready && w1.message.is_none());
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 1);

        // Second Wintun check on unchanged file skips hashing and adapts `required` to Proxy.
        let w2 =
            evaluate_wintun_candidates_cached_with(&state, EngineMode::Proxy, &candidates, |p| {
                wintun_hashes.fetch_add(1, Ordering::SeqCst);
                vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
            });
        assert!(!w2.required && w2.ready && w2.message.is_none());
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 1);

        // Tampering with wintun.dll (new length) invalidates the cache and reports hash failure.
        fs::write(&wintun_dll, b"tampered-bytes").expect("tamper wintun dll");
        let w3 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(w3.required && !w3.ready);
        assert_eq!(w3.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 2);

        // Repeated check on unchanged tampered file hits cache without re-hashing.
        let w4 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert_eq!(w4.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 2);

        // Explicit `invalidate_static_cache()` forces both version and Wintun re-probes.
        state.invalidate_static_cache();
        let v4 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(v4.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 3);

        let w5 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert_eq!(w5.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 3);

        // Deleting wintun.dll reports missing without hashing.
        fs::remove_file(&wintun_dll).expect("remove wintun dll");
        let w6 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(!w6.ready);
        assert_eq!(w6.message.as_deref(), Some(WINTUN_MISSING_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 3);

        // Transient `None` version probe must NOT poison BinaryMetadataCache;
        // subsequent probes on the same unchanged file retry and cache `Some`.
        state.invalidate_static_cache();
        let transient_fail = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                None
            },
        );
        assert!(transient_fail.is_none());
        assert_eq!(version_probes.load(Ordering::SeqCst), 4);

        let recovered = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(recovered.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 5);

        let cached_after_recovery = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.8.0".to_string())
            },
        );
        assert_eq!(cached_after_recovery.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn wintun_candidate_collection_covers_installed_sibling_and_resources_dirs() {
        let dir = TestDir::new("wintun-candidates");
        let installed_dir = dir.path().join("installed");
        let app_dir = dir.path().join("app");
        fs::create_dir_all(&installed_dir).expect("create installed dir");
        fs::create_dir_all(&app_dir).expect("create app dir");

        let installed_bin = installed_dir.join("vdpi.exe");
        let desktop_exe = app_dir.join("vdpi-desktop.exe");

        let candidates = collect_wintun_candidates(Some(&installed_bin), Some(&desktop_exe));
        assert!(candidates.contains(&installed_dir.join("wintun.dll")));
        assert!(candidates.contains(&installed_dir.join("resources").join("wintun.dll")));
        assert!(candidates.contains(&app_dir.join("wintun.dll")));
        assert!(candidates.contains(&app_dir.join("resources").join("wintun.dll")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn probe_wintun_status_on_non_windows_is_always_ready_and_not_required() {
        for mode in [EngineMode::Tun, EngineMode::Proxy] {
            let status = probe_wintun_status(mode);
            assert!(!status.required);
            assert!(status.ready);
            assert!(status.message.is_none());
        }
    }

    #[test]
    fn resolve_logs_dir_handles_macos_linux_system_service_and_user_modes() {
        let dir = TestDir::new("logs-dir");
        let user_logs = dir.path().join("home").join(".vdpi").join("logs");
        let sys_vdpi_logs = dir.path().join("var-log-vdpi");
        let sys_var_log = dir.path().join("var-log");

        // macOS LaunchDaemon mode always resolves to /var/log; LaunchAgent uses ~/.vdpi/logs.
        assert_eq!(
            resolve_logs_dir_for_platform("macos", true, user_logs.clone(), &[]),
            PathBuf::from("/var/log")
        );
        assert_eq!(
            resolve_logs_dir_for_platform("macos", false, user_logs.clone(), &[]),
            user_logs
        );

        // Linux system service prefers first existing logs directory; falls back to user logs.
        let candidates = [
            sys_vdpi_logs.clone(),
            user_logs.clone(),
            sys_var_log.clone(),
        ];
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            user_logs
        );

        fs::create_dir_all(&sys_var_log).expect("create var-log");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            sys_var_log
        );

        fs::create_dir_all(&user_logs).expect("create user logs");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            user_logs
        );

        fs::create_dir_all(&sys_vdpi_logs).expect("create var-log-vdpi");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            sys_vdpi_logs
        );

        // Linux non-system-service always returns user logs.
        assert_eq!(
            resolve_logs_dir_for_platform("linux", false, user_logs.clone(), &candidates),
            user_logs
        );

        // Windows always returns its default logs directory.
        assert_eq!(
            resolve_logs_dir_for_platform("windows", true, user_logs.clone(), &candidates),
            user_logs
        );
    }

    #[test]
    fn fast_probe_candidates_prioritize_runtime_states_and_deduplicate() {
        let cfg = RuntimeConfig::default();
        let states = vec![
            RuntimeState {
                pid: 100,
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 19000,
                socks_port: Some(19001),
                engine: EngineMode::Tun,
                tun_interface: Some("vdpi0".to_string()),
                env_activated_at: None,
            },
            RuntimeState {
                pid: 101,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 19000,
                socks_port: None,
                engine: EngineMode::Tun,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 102,
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
                port: 19002,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 103,
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                port: 0,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
        ];

        let candidates = build_fast_probe_candidates(&cfg, &states);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].port, 19000);
        assert_eq!(candidates[0].socks_port, Some(19001));
        assert_eq!(candidates[1].port, cfg.port);
        assert_eq!(candidates[2].port, DEFAULT_TUN_HEALTH_PORT);
    }

    #[test]
    fn collect_status_snapshot_reuses_static_cache_and_honors_force_refresh_and_ttl() {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let t0 = Instant::now();

        // Tick 1 (cold cache): invokes static probe once and establishes rate baseline.
        let s1 = collect_status_snapshot_with(
            &state,
            false,
            || t0,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, false, Some("parsed with warning".to_string()))
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(s1.snapshot_seq, 1);
        assert!(!s1.tray_supported);
        assert_eq!(s1.config_warning.as_deref(), Some("parsed with warning"));
        assert_eq!(s1.live.as_ref().expect("live").rx_rate_bps, 0);

        // Tick 2 (+2s, force_full_refresh = false): reuses StaticProbeCache (0 extra static probes).
        let t1 = t0 + Duration::from_secs(2);
        let s2 = collect_status_snapshot_with(
            &state,
            false,
            || t1,
            |_| {
                let mut live = sample_live_status(Some("1.1.1.1"), Some(true));
                live.bytes_rx = Some(18_000);
                live.bytes_tx = Some(36_000);
                Some(live)
            },
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(s2.snapshot_seq, 2);
        assert!(!s2.tray_supported);
        assert_eq!(s2.live.as_ref().expect("live").rx_rate_bps, 4_000);
        assert_eq!(s2.live.as_ref().expect("live").tx_rate_bps, 8_000);

        // Tick 3 (+4s, force_full_refresh = true): bypasses fresh cache and refreshes static probes.
        let t2 = t0 + Duration::from_secs(4);
        let s3 = collect_status_snapshot_with(
            &state,
            true,
            || t2,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert_eq!(s3.snapshot_seq, 3);
        assert!(s3.tray_supported);
        assert!(s3.config_warning.is_none());
        assert!(s3.live.is_none());

        // Tick 4 (after 45s TTL expires, same offline presence): triggers a fresh
        // static probe automatically purely due to TTL expiration.
        let t3 = t2 + STATIC_PROBE_CACHE_TTL + Duration::from_secs(1);
        let s4 = collect_status_snapshot_with(
            &state,
            false,
            || t3,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 3);
        assert_eq!(s4.snapshot_seq, 4);
        assert!(s4.live.is_none());

        // Tick 5 (+2s, daemon comes back online): live presence flip (None -> Some)
        // triggers an immediate static refresh and re-baselines rate tracker at 0 B/s.
        let t4 = t3 + Duration::from_secs(2);
        let s5 = collect_status_snapshot_with(
            &state,
            false,
            || t4,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 4);
        assert_eq!(s5.snapshot_seq, 5);
        assert_eq!(s5.live.as_ref().expect("live").rx_rate_bps, 0);
        assert_eq!(state.last_snapshot().expect("last snapshot").snapshot_seq, 5);
    }

    #[test]
    fn collect_status_snapshot_forces_full_refresh_on_live_presence_flip_and_uses_cached_fallback_dns(
    ) {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let t0 = Instant::now();

        // Tick 1: cold cache populates cached `fallback_dns`; live telemetry with
        // missing `dns_addr` uses cached `fallback_dns` without reading config.toml.
        let s1 = collect_status_snapshot_with(
            &state,
            false,
            || t0,
            |_| Some(sample_live_status(None, Some(false))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.config_path = "/nonexistent/must-not-be-read/config.toml".to_string();
                entry.fallback_dns = "https://dns.nextdns.io/secret-cached-profile".to_string();
                entry.service_state = ServiceStateDto::Running;
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        let live1 = s1.live.as_ref().expect("live telemetry");
        assert_eq!(live1.dns_display, "https://dns.nextdns.io");
        assert!(!live1.dns_display.contains("secret-cached-profile"));
        assert!(live1.doh_enabled);

        // Tick 2 (+1.5s, still live, force_full_refresh = false): cache hit (no static probe).
        let t1 = t0 + Duration::from_millis(1_500);
        let s2 = collect_status_snapshot_with(
            &state,
            false,
            || t1,
            |_| Some(sample_live_status(Some("   "), Some(false))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        let live2 = s2.live.as_ref().expect("live telemetry");
        assert_eq!(live2.dns_display, "https://dns.nextdns.io");
        assert!(live2.doh_enabled);

        // Tick 3 (+3s, external daemon stopped / VPN yielded: Some -> None):
        // immediately forces full refresh instead of waiting for 45s TTL.
        let t2 = t0 + Duration::from_secs(3);
        let s3 = collect_status_snapshot_with(
            &state,
            false,
            || t2,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.service_state = ServiceStateDto::Stopped;
                entry.vpn_conflict = Some("Mullvad".to_string());
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert!(s3.live.is_none());
        assert_eq!(s3.service_state, ServiceStateDto::Stopped);
        assert_eq!(s3.vpn_conflict.as_deref(), Some("Mullvad"));

        // Tick 4 (+4.5s, still offline: None -> None): reuses cache (no static probe).
        let t3 = t0 + Duration::from_millis(4_500);
        let s4 = collect_status_snapshot_with(
            &state,
            false,
            || t3,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert_eq!(s4.service_state, ServiceStateDto::Stopped);

        // Tick 5 (+6s, external daemon started: None -> Some):
        // immediately forces full refresh instead of waiting for 45s TTL.
        let t4 = t0 + Duration::from_secs(6);
        let s5 = collect_status_snapshot_with(
            &state,
            false,
            || t4,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.service_state = ServiceStateDto::Running;
                entry.vpn_conflict = None;
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 3);
        assert!(s5.live.is_some());
        assert_eq!(s5.service_state, ServiceStateDto::Running);
        assert!(s5.vpn_conflict.is_none());
    }

    #[test]
    fn collect_status_snapshot_serializes_concurrent_polls_via_snapshot_lock() {
        let state = Arc::new(DesktopAppState::default());
        let threads = 6usize;
        let barrier = Arc::new(Barrier::new(threads));
        let static_calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let state_clone = Arc::clone(&state);
            let barrier_clone = Arc::clone(&barrier);
            let static_calls_clone = Arc::clone(&static_calls);
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
                collect_status_snapshot_with(
                    &state_clone,
                    false,
                    Instant::now,
                    |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
                    |_, _, now| {
                        static_calls_clone.fetch_add(1, Ordering::SeqCst);
                        sample_static_entry(now, true, None)
                    },
                )
                .snapshot_seq
            }));
        }

        let mut seqs: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().expect("join snapshot thread"))
            .collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (1..=threads as u64).collect::<Vec<_>>());
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.last_snapshot().expect("cached snapshot").snapshot_seq,
            threads as u64
        );
    }
}
