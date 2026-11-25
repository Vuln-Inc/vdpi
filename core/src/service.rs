use crate::config::{DesyncMode, EngineMode, RuntimeConfig, VpnCoexistence};
use crate::config_file;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
use crate::config_file::{FileConfig, CONFIG_SCHEMA_VERSION};
use crate::desync::EngineContext;
use crate::health::DEFAULT_TUN_HEALTH_PORT;
use crate::platform::vpn::{detect_active_vpn, VpnScope};
use crate::platform::{clear_all_system_proxies, platform_name, print_platform_proxy_status};
use crate::update::{compare_versions, parse_semver, VersionRelation};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use anyhow::Context;
use anyhow::{bail, Result};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const LAUNCH_AGENT_LABEL: &str = "com.vdpi";
pub const LAUNCH_DAEMON_LABEL: &str = "com.vdpi.daemon";
pub const LAUNCH_DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/com.vdpi.daemon.plist";
pub const SYSTEMD_UNIT_NAME: &str = "vdpi.service";
pub const SYSTEMD_SYSTEM_UNIT_PATH: &str = "/etc/systemd/system/vdpi.service";
pub const UNIX_SYSTEM_BIN_PATH: &str = "/usr/local/bin/vdpi";
pub const WINDOWS_SERVICE_NAME: &str = "vdpi";
pub const WINDOWS_LEGACY_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Persisted active listener metadata written when `vdpi` starts so `vdpi status`
/// and `vdpi doctor` always discover rotated ports automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeState {
    pub pid: u32,
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub engine: EngineMode,
    #[serde(default)]
    pub tun_interface: Option<String>,
    #[serde(default)]
    pub env_activated_at: Option<u64>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn runtime_state_write_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if crate::platform::windows::is_running_as_service() {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            return Some(base.join("vdpi").join("state.json"));
        }
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            return Some(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if is_unix_root() {
            return Some(PathBuf::from("/run/vdpi/state.json"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if is_unix_root() {
            return Some(PathBuf::from(
                "/Library/Application Support/vdpi/state.json",
            ));
        }
    }
    vdpi_root_dir().ok().map(|r| r.join("state.json"))
}

fn runtime_state_read_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "windows")]
    {
        let pd = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        paths.push(pd.join("vdpi").join("state.json"));
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            paths.push(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        paths.push(PathBuf::from("/run/vdpi/state.json"));
    }
    #[cfg(target_os = "macos")]
    {
        paths.push(PathBuf::from(
            "/Library/Application Support/vdpi/state.json",
        ));
    }
    if let Ok(root) = vdpi_root_dir() {
        let p = root.join("state.json");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

pub fn write_runtime_state(primary_addr: SocketAddr, socks_addr: Option<SocketAddr>) {
    write_runtime_state_with_meta(
        primary_addr,
        socks_addr,
        EngineMode::Proxy,
        None,
        Some(unix_now_secs()),
    );
}

pub fn write_runtime_state_with_meta(
    primary_addr: SocketAddr,
    socks_addr: Option<SocketAddr>,
    engine: EngineMode,
    tun_interface: Option<String>,
    env_activated_at: Option<u64>,
) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    if let Some(parent) = path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if is_unix_root() {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
        }
    }
    let state = RuntimeState {
        pid: std::process::id(),
        addr: primary_addr.ip(),
        port: primary_addr.port(),
        socks_port: socks_addr.map(|a| a.port()),
        engine,
        tun_interface,
        env_activated_at,
    };
    let Ok(json) = serde_json::to_string(&state) else {
        return;
    };
    let tmp = path.with_extension("json.tmp");
    if fs::write(&tmp, json).is_ok() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
        }
        let _ = fs::remove_file(&path);
        let _ = fs::rename(&tmp, &path);
    }
}

pub fn clear_runtime_state(expected_pid: u32) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
            if state.pid == expected_pid {
                let _ = fs::remove_file(&path);
            }
        }
    }
}

pub fn read_runtime_states() -> Vec<RuntimeState> {
    let mut states = Vec::new();
    for path in runtime_state_read_paths() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
                if !states.contains(&state) {
                    states.push(state);
                }
            }
        }
    }
    states
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn parse_nonzero_sudo_uid(raw: Option<&std::ffi::OsStr>) -> Option<u32> {
    raw?.to_str()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&uid| uid != 0)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixTargetUser {
    uid: u32,
    gid: u32,
    #[cfg(target_os = "linux")]
    username: Option<String>,
    home_dir: PathBuf,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_user_by_uid(uid: u32) -> Option<UnixTargetUser> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd` and `buf` are valid writable buffers for `getpwuid_r`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwuid_r` succeeded with a non-null `result` pointing to `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    #[cfg(target_os = "linux")]
    let username = if pwd.pw_name.is_null() {
        None
    } else {
        // SAFETY: `pw_name` is a valid NUL-terminated C string inside `buf`.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        (!name.is_empty()).then_some(name)
    };
    Some(UnixTargetUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        #[cfg(target_os = "linux")]
        username,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_user_by_name(name: &str) -> Option<UnixTargetUser> {
    use std::ffi::{CStr, CString, OsStr};
    use std::os::unix::ffi::OsStrExt;

    let c_name = CString::new(name).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `c_name` is NUL-terminated; `pwd` and `buf` are valid writable buffers.
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwnam_r` succeeded with a non-null `result` pointing to `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    #[cfg(target_os = "linux")]
    let username = if pwd.pw_name.is_null() {
        Some(name.to_string())
    } else {
        // SAFETY: `pw_name` is a valid NUL-terminated C string inside `buf`.
        let resolved = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        (!resolved.is_empty()).then_some(resolved)
    };
    Some(UnixTargetUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        #[cfg(target_os = "linux")]
        username,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

/// Resolves the invoking non-root user when running under `sudo` (`geteuid() == 0`),
/// querying `libc::getpwuid_r` / `libc::getpwnam_r` so service management and uninstall
/// target the real user's `gui/<sudo_uid>`, home directory, and `config.toml` instead
/// of `/root` / `gui/0`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_sudo_invoking_user() -> Option<UnixTargetUser> {
    if !is_unix_root() {
        return None;
    }
    if let Some(sudo_uid) = parse_nonzero_sudo_uid(std::env::var_os("SUDO_UID").as_deref()) {
        if let Some(user) = lookup_unix_user_by_uid(sudo_uid) {
            return Some(user);
        }
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            let gid =
                parse_nonzero_sudo_uid(std::env::var_os("SUDO_GID").as_deref()).unwrap_or(sudo_uid);
            #[cfg(target_os = "linux")]
            let username = std::env::var("SUDO_USER")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "root");
            return Some(UnixTargetUser {
                uid: sudo_uid,
                gid,
                #[cfg(target_os = "linux")]
                username,
                home_dir: PathBuf::from(home),
            });
        }
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let trimmed = sudo_user.trim();
        if !trimmed.is_empty() && trimmed != "root" {
            if let Some(user) = lookup_unix_user_by_name(trimmed).filter(|u| u.uid != 0) {
                return Some(user);
            }
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn chown_to_sudo_user(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(sudo_user) = resolve_sudo_invoking_user() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path string.
    unsafe {
        let _ = libc::chown(c_path.as_ptr(), sudo_user.uid, sudo_user.gid);
    }
}

fn resolved_user_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(sudo_user) = resolve_sudo_invoking_user() {
            return sudo_user.home_dir.join(".vdpi").join("config.toml");
        }
        config_file::user_config_path()
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(sudo_user) = resolve_sudo_invoking_user() {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.starts_with(&sudo_user.home_dir))
            {
                return xdg.join("vdpi").join("config.toml");
            }
            return sudo_user
                .home_dir
                .join(".config")
                .join("vdpi")
                .join("config.toml");
        }
        config_file::user_config_path()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        config_file::user_config_path()
    }
}

pub fn home_dir() -> Result<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        return Ok(sudo_user.home_dir);
    }
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(h));
    }
    if let Some(up) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(up));
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(user) = lookup_unix_user_by_uid(unsafe { libc::getuid() }) {
        return Ok(user.home_dir);
    }
    bail!("neither HOME nor USERPROFILE environment variable is set")
}

pub fn vdpi_root_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            return Ok(PathBuf::from(program_files).join("vdpi"));
        }
        Ok(PathBuf::from(r"C:\Program Files").join("vdpi"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(home_dir()?.join(".vdpi"))
    }
}

pub fn installed_binary_path() -> Result<PathBuf> {
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    Ok(vdpi_root_dir()?.join("bin").join(bin_name))
}

/// Snapshot of an existing `vdpi` installation discovered on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledInfo {
    pub binary_path: PathBuf,
    pub installed_version: Option<String>,
    pub current_version: &'static str,
    pub relation: VersionRelation,
    pub running_from_installed: bool,
}

/// Detects whether `vdpi` is installed in its standard service location and
/// probes the installed binary's version offline without network requests.
pub fn detect_installed_info() -> Option<InstalledInfo> {
    let installed = installed_binary_path().ok().filter(|p| p.is_file());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let binary_path = installed.or_else(|| {
        let sys_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
        sys_bin.is_file().then_some(sys_bin)
    })?;
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let binary_path = installed?;

    let running_from_installed = std::env::current_exe().ok().is_some_and(|current_exe| {
        match (
            fs::canonicalize(&current_exe),
            fs::canonicalize(&binary_path),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => current_exe == binary_path,
        }
    });

    let current_version = env!("CARGO_PKG_VERSION");

    let (installed_version, relation) = if running_from_installed {
        (Some(current_version.to_string()), VersionRelation::Same)
    } else {
        let installed = probe_binary_version(&binary_path);
        let rel = installed.as_deref().map_or(VersionRelation::Unknown, |v| {
            compare_versions(current_version, v)
        });
        (installed, rel)
    };

    Some(InstalledInfo {
        binary_path,
        installed_version,
        current_version,
        relation,
        running_from_installed,
    })
}

/// Registration and runtime status of the OS background service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    NotInstalled,
}

/// Live telemetry parsed from the local daemon `/vdpi-health` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEngineStatus {
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub engine: EngineMode,
    pub tun_interface: Option<String>,
    pub physical_nic: Option<String>,
    pub vpn_conflict: Option<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
    pub doh: Option<bool>,
    pub block_quic: Option<bool>,
    pub active_connections: Option<usize>,
    pub total_connections: Option<u64>,
    pub learned_hosts: Option<usize>,
    pub isp_stage: Option<String>,
    pub udp_flows_active: Option<u64>,
    pub quic_blocked: Option<u64>,
    pub dns_queries: Option<u64>,
    pub rss_kb: Option<u64>,
}

/// Combined local snapshot for the interactive Control Center.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCenterStatus {
    pub installed: Option<InstalledInfo>,
    pub service_state: ServiceState,
    pub live_engine: Option<LiveEngineStatus>,
    pub configured_engine: EngineMode,
    pub vpn_conflict: Option<String>,
}

fn load_configured_engine(fallback: EngineMode) -> EngineMode {
    #[cfg(target_os = "macos")]
    if launch_daemon_plist_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.engine)
            .unwrap_or(EngineMode::Tun);
    }

    #[cfg(target_os = "linux")]
    if systemd_system_unit_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.engine)
            .unwrap_or(EngineMode::Tun);
    }

    #[cfg(target_os = "windows")]
    if crate::platform::windows_service::query_windows_service_status().installed {
        let sys_path = config_file::system_config_path();
        if let Some(engine) = config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.engine)
        {
            return engine;
        }
    }

    let user_path = resolved_user_config_path();
    if let Some(engine) = config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    let sys_path = config_file::system_config_path();
    if let Some(engine) = config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    fallback
}

/// Loads the currently configured upstream DNS server address from the active
/// `config.toml` (system config when a system service is installed, otherwise
/// user config with fallback to system config and runtime default).
pub fn load_configured_dns(fallback: &str) -> String {
    #[cfg(target_os = "macos")]
    if launch_daemon_plist_path().exists() {
        let sys_path = config_file::system_config_path();
        if let Some(dns) = config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.dns_addr)
            .filter(|s| !s.trim().is_empty())
        {
            return dns;
        }
    }

    #[cfg(target_os = "linux")]
    if systemd_system_unit_path().exists() {
        let sys_path = config_file::system_config_path();
        if let Some(dns) = config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.dns_addr)
            .filter(|s| !s.trim().is_empty())
        {
            return dns;
        }
    }

    #[cfg(target_os = "windows")]
    if crate::platform::windows_service::query_windows_service_status().installed {
        let sys_path = config_file::system_config_path();
        if let Some(dns) = config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.dns_addr)
            .filter(|s| !s.trim().is_empty())
        {
            return dns;
        }
    }

    let user_path = resolved_user_config_path();
    if let Some(dns) = config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.dns_addr)
        .filter(|s| !s.trim().is_empty())
    {
        return dns;
    }
    let sys_path = config_file::system_config_path();
    if let Some(dns) = config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.dns_addr)
        .filter(|s| !s.trim().is_empty())
    {
        return dns;
    }
    fallback.to_string()
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

fn format_rss_label(rss_kb: u64) -> String {
    if rss_kb >= 1024 {
        let mb = (rss_kb.saturating_add(512) / 1024).max(1);
        format!("{mb} MB RSS")
    } else {
        format!("{rss_kb} KB RSS")
    }
}

/// Detects whether the background `vdpi` service is installed and currently running.
pub fn detect_service_state() -> ServiceState {
    #[cfg(target_os = "windows")]
    {
        let svc = crate::platform::windows_service::query_windows_service_status();
        if !svc.installed {
            ServiceState::NotInstalled
        } else if matches!(svc.state, "RUNNING" | "START_PENDING") {
            ServiceState::Running
        } else {
            ServiceState::Stopped
        }
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        if !daemon_exists && !agent_exists {
            return ServiceState::NotInstalled;
        }
        if daemon_exists {
            let target = format!("system/{LAUNCH_DAEMON_LABEL}");
            if launchctl_service_running(&target) {
                return ServiceState::Running;
            }
        }
        if agent_exists {
            let uid = current_uid();
            let target = format!("gui/{uid}/{LAUNCH_AGENT_LABEL}");
            if launchctl_service_running(&target) {
                return ServiceState::Running;
            }
        }
        ServiceState::Stopped
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        if !system_exists && !user_exists {
            return ServiceState::NotInstalled;
        }
        if system_exists && systemd_unit_active(false) {
            return ServiceState::Running;
        }
        if user_exists && systemd_unit_active(true) {
            return ServiceState::Running;
        }
        ServiceState::Stopped
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        ServiceState::NotInstalled
    }
}

/// Parses a `/vdpi-health` JSON payload into a structured [`LiveEngineStatus`].
pub fn parse_health_json(
    body: &str,
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
) -> Option<LiveEngineStatus> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let obj = value.as_object()?;

    let status = obj.get("status").and_then(serde_json::Value::as_str);
    let service = obj.get("service").and_then(serde_json::Value::as_str);
    if !matches!((status, service), (Some("ok") | None, Some("vdpi"))) {
        return None;
    }

    let engine = match obj.get("engine").and_then(serde_json::Value::as_str) {
        Some(raw) if raw.trim().eq_ignore_ascii_case("tun") => EngineMode::Tun,
        _ => EngineMode::Proxy,
    };

    let non_empty_str = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    Some(LiveEngineStatus {
        addr,
        port,
        socks_port,
        engine,
        tun_interface: non_empty_str("tun_interface"),
        physical_nic: non_empty_str("physical_nic"),
        vpn_conflict: non_empty_str("vpn_conflict"),
        version: obj
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        mode: obj
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        doh: obj.get("doh").and_then(serde_json::Value::as_bool),
        block_quic: obj.get("block_quic").and_then(serde_json::Value::as_bool),
        active_connections: obj
            .get("active_connections")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| usize::try_from(v).ok()),
        total_connections: obj
            .get("total_connections")
            .and_then(serde_json::Value::as_u64),
        learned_hosts: obj
            .get("learned_hosts")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| usize::try_from(v).ok()),
        isp_stage: obj
            .get("isp_stage")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        udp_flows_active: obj
            .get("udp_flows_active")
            .and_then(serde_json::Value::as_u64),
        quic_blocked: obj.get("quic_blocked").and_then(serde_json::Value::as_u64),
        dns_queries: obj.get("dns_queries").and_then(serde_json::Value::as_u64),
        rss_kb: obj.get("rss_kb").and_then(serde_json::Value::as_u64),
    })
}

const MAX_HEALTH_RESPONSE_BYTES: usize = 8 * 1024;
const CONTROL_CENTER_PROBE_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeCandidate {
    addr: IpAddr,
    connect_ip: IpAddr,
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

fn build_probe_candidates(cfg: &RuntimeConfig, states: &[RuntimeState]) -> Vec<ProbeCandidate> {
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

    for (addr, port, socks_port) in std::iter::once((cfg.addr, cfg.port, primary_socks))
        .chain(states.iter().map(|s| (s.addr, s.port, s.socks_port)))
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
        out.push(ProbeCandidate {
            addr,
            connect_ip,
            port,
            socks_port,
        });
    }

    out
}

fn probe_local_health(
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
    deadline: Instant,
) -> Option<LiveEngineStatus> {
    const PROBE_CONNECT_CAP: Duration = Duration::from_millis(200);
    const HEALTH_REQUEST: &[u8] =
        b"GET /vdpi-health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if port == 0 {
        return None;
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }

    let connect_ip = probe_connect_ip(addr)?;
    let sock = SocketAddr::new(connect_ip, port);

    let connect_timeout = remaining.min(PROBE_CONNECT_CAP);
    let mut stream = TcpStream::connect_timeout(&sock, connect_timeout).ok()?;

    let write_remaining = deadline.saturating_duration_since(Instant::now());
    if write_remaining.is_zero() {
        return None;
    }
    let _ = stream.set_write_timeout(Some(write_remaining));

    stream.write_all(HEALTH_REQUEST).ok()?;
    let _ = stream.flush();

    let mut raw = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    while raw.len() < MAX_HEALTH_RESPONSE_BYTES {
        let read_remaining = deadline.saturating_duration_since(Instant::now());
        if read_remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(read_remaining));
        let to_read = buf.len().min(MAX_HEALTH_RESPONSE_BYTES - raw.len());
        match stream.read(&mut buf[..to_read]) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if raw.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(&raw);
    let status_line = text.lines().next()?;
    let status_rest = status_line
        .strip_prefix("HTTP/1.1 200")
        .or_else(|| status_line.strip_prefix("HTTP/1.0 200"))?;
    if !status_rest.is_empty() && !status_rest.starts_with(' ') {
        return None;
    }
    let (_, body) = text.split_once("\r\n\r\n")?;

    parse_health_json(body, addr, port, socks_port)
}

/// Performs a fast, synchronous, local-only status probe of installation, background
/// service registration, and live loopback daemon health (zero internet calls, zero
/// async runtime spawn).
pub fn probe_control_center_status(cfg: &RuntimeConfig) -> ControlCenterStatus {
    let installed = detect_installed_info();
    let service_state = detect_service_state();
    let configured_engine = load_configured_engine(cfg.engine);
    let states = read_runtime_states();

    let deadline = Instant::now() + CONTROL_CENTER_PROBE_BUDGET;
    let mut live_engine = None;

    for candidate in build_probe_candidates(cfg, &states) {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(status) = probe_local_health(
            candidate.addr,
            candidate.port,
            candidate.socks_port,
            deadline,
        ) {
            live_engine = Some(status);
            break;
        }
    }

    let vpn_conflict = if cfg.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_engine
            .as_ref()
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_engine
                        .as_ref()
                        .and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    ControlCenterStatus {
        installed,
        service_state,
        live_engine,
        configured_engine,
        vpn_conflict,
    }
}

/// Extracts and normalizes a semantic version (`X.Y.Z`) from `vdpi --version` stdout.
pub fn parse_version_from_cli_output(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().find(|line| !line.trim().is_empty())?;
    first_line.split_whitespace().find_map(|token| {
        let (major, minor, patch) =
            parse_semver(token).or_else(|| token.strip_prefix('v').and_then(parse_semver))?;
        Some(format!("{major}.{minor}.{patch}"))
    })
}

fn probe_binary_version(path: &Path) -> Option<String> {
    const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const MAX_PROBE_STDOUT_BYTES: usize = 4 * 1024;

    let mut cmd = Command::new(path);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take()?;

    let reader_handle = std::thread::spawn(move || {
        let mut pipe = stdout_pipe;
        let mut retained = Vec::new();
        let mut scratch = [0u8; 1024];
        loop {
            match pipe.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    if retained.len() < MAX_PROBE_STDOUT_BYTES {
                        let keep = (MAX_PROBE_STDOUT_BYTES - retained.len()).min(n);
                        retained.extend_from_slice(&scratch[..keep]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        retained
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let raw_stdout = reader_handle.join().ok()?;
    let status = status?;
    if !status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&raw_stdout);
    parse_version_from_cli_output(&stdout)
}

pub fn launch_agent_plist_path() -> Result<PathBuf> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
}

pub fn launch_daemon_plist_path() -> PathBuf {
    PathBuf::from(LAUNCH_DAEMON_PLIST_PATH)
}

pub fn systemd_user_unit_path() -> Result<PathBuf> {
    let home = home_dir().unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let sudo_invoker = resolve_sudo_invoking_user().is_some();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let sudo_invoker = false;

    let config_base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| !sudo_invoker || p.starts_with(&home))
        .unwrap_or_else(|| home.join(".config"));
    Ok(config_base
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME))
}

pub fn systemd_system_unit_path() -> PathBuf {
    PathBuf::from(SYSTEMD_SYSTEM_UNIT_PATH)
}

pub fn build_windows_service_bin_path(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut args = vec!["--service".to_string()];
    args.extend(build_service_cli_args(cfg));
    args.push("--quiet".to_string());
    let quoted_args: Vec<String> = args.into_iter().map(|a| quote_windows_arg(&a)).collect();
    format!("\"{}\" {}", bin_path.display(), quoted_args.join(" "))
}

pub(crate) fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            c => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn build_service_cli_args(cfg: &RuntimeConfig) -> Vec<String> {
    let mut args = vec![match cfg.engine {
        EngineMode::Tun => "--tun".to_string(),
        EngineMode::Proxy => "--proxy".to_string(),
    }];
    args.extend([
        "--bind".to_string(),
        cfg.addr.to_string(),
        "--port".to_string(),
        cfg.port.to_string(),
        "--chunk-size".to_string(),
        cfg.chunk_size.to_string(),
    ]);

    if let Some(sp) = cfg.socks_port {
        args.push("--socks-port".to_string());
        args.push(sp.to_string());
    } else {
        args.push("--socks-port".to_string());
        args.push("0".to_string());
    }

    if !cfg.enable_doh {
        args.push("--no-doh".to_string());
    }

    if cfg.mode != DesyncMode::Combo {
        let mode_str = match cfg.mode {
            DesyncMode::Combo => "combo",
            DesyncMode::TlsRecord => "tls-record",
            DesyncMode::Fragment => "fragment",
            DesyncMode::Split => "split",
        };
        args.push("--mode".to_string());
        args.push(mode_str.to_string());
    }

    if cfg.dns_addr != "1.1.1.1" {
        args.push("--dns".to_string());
        args.push(cfg.dns_addr.clone());
    }
    if cfg.dns_port != 53 {
        args.push("--dns-port".to_string());
        args.push(cfg.dns_port.to_string());
    }
    if cfg.dns_ipv4_only {
        args.push("--ipv4-only".to_string());
    }
    if cfg.connect_timeout != std::time::Duration::from_secs(8) {
        args.push("--timeout".to_string());
        args.push(cfg.connect_timeout.as_millis().to_string());
    }
    if !cfg.system_proxy {
        args.push("--no-system-proxy".to_string());
    } else {
        if !cfg.socks_system_proxy && cfg.socks_port.is_some() {
            args.push("--no-socks-proxy".to_string());
        }
        if !cfg.env_proxy {
            args.push("--no-env-proxy".to_string());
        }
    }
    if !cfg.block_quic {
        args.push("--allow-quic".to_string());
    }
    if cfg.tun_ipv6 {
        args.push("--tun-ipv6".to_string());
    }
    if cfg.vpn_coexistence != VpnCoexistence::AutoYield {
        args.push("--vpn-coexistence".to_string());
        args.push(cfg.vpn_coexistence.as_str().to_string());
    }
    for pattern in &cfg.patterns {
        args.push("--include".to_string());
        args.push(pattern.clone());
    }
    for domain in &cfg.bypass_domains {
        args.push("--bypass".to_string());
        args.push(domain.clone());
    }
    if cfg.debug {
        args.push("--debug".to_string());
    }

    args
}

pub fn generate_launch_agent_plist(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut proxy_cfg = cfg.clone();
    proxy_cfg.engine = EngineMode::Proxy;

    let log_dir = vdpi_root_dir()
        .map(|r| r.join("logs"))
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    let out_log = log_dir.join("vdpi.out.log");
    let err_log = log_dir.join("vdpi.err.log");

    let mut args = vec![bin_path.display().to_string()];
    args.extend(build_service_cli_args(&proxy_cfg));

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"#,
        label = LAUNCH_AGENT_LABEL,
        args_xml = args_xml,
        out_log = xml_escape(&out_log.display().to_string()),
        err_log = xml_escape(&err_log.display().to_string()),
    )
}

/// Generates a root-owned macOS `LaunchDaemon` plist for transparent `EngineMode::Tun`.
pub fn generate_launch_daemon_plist(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut tun_cfg = cfg.clone();
    tun_cfg.engine = EngineMode::Tun;

    let mut args = vec![bin_path.display().to_string()];
    args.extend(build_service_cli_args(&tun_cfg));
    args.push("--quiet".to_string());

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/vdpi.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/vdpi.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCH_DAEMON_LABEL,
        args_xml = args_xml,
    )
}

fn quote_systemd_arg(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\0' => {}
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn generate_systemd_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut proxy_cfg = cfg.clone();
    proxy_cfg.engine = EngineMode::Proxy;

    let bin_str = bin_path.display().to_string();
    let mut exec_parts = vec![quote_systemd_arg(&bin_str)];
    for arg in build_service_cli_args(&proxy_cfg) {
        exec_parts.push(quote_systemd_arg(&arg));
    }
    let exec_start = exec_parts.join(" ");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Local Proxy Engine\n\
After=network-online.target\n\
Wants=network-online.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
KillMode=mixed\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    )
}

/// Generates a root-owned Linux `systemd` system service unit for transparent
/// `EngineMode::Tun` with full root capabilities and automatic `ExecStopPost` TUN cleanup.
pub fn generate_systemd_system_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut tun_cfg = cfg.clone();
    tun_cfg.engine = EngineMode::Tun;

    let bin_str = bin_path.display().to_string();
    let quoted_bin = quote_systemd_arg(&bin_str);
    let mut exec_parts = vec![quoted_bin.clone()];
    for arg in build_service_cli_args(&tun_cfg) {
        exec_parts.push(quote_systemd_arg(&arg));
    }
    exec_parts.push(quote_systemd_arg("--quiet"));
    let exec_start = exec_parts.join(" ");
    let exec_stop_post = format!("+{quoted_bin} --internal-linux-tun-cleanup");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Transparent TUN Engine\n\
After=network-online.target systemd-resolved.service NetworkManager.service\n\
Wants=network-online.target\n\
StartLimitIntervalSec=60\n\
StartLimitBurst=5\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
ExecStopPost={exec_stop_post}\n\
KillMode=mixed\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn file_config_from_runtime(cfg: &RuntimeConfig) -> FileConfig {
    FileConfig {
        schema_version: Some(CONFIG_SCHEMA_VERSION),
        engine: Some(cfg.engine),
        mode: Some(cfg.mode),
        doh: Some(cfg.enable_doh),
        block_quic: Some(cfg.block_quic),
        dns_addr: Some(cfg.dns_addr.clone()),
        bypass_domains: (!cfg.bypass_domains.is_empty()).then(|| cfg.bypass_domains.clone()),
        include_domains: (!cfg.patterns.is_empty()).then(|| cfg.patterns.clone()),
        vpn_coexistence: Some(cfg.vpn_coexistence),
        tun_ipv6: Some(cfg.tun_ipv6),
        chunk_size: Some(cfg.chunk_size),
        bind: Some(cfg.addr),
        port: Some(cfg.port),
        socks_port: Some(cfg.socks_port.unwrap_or(0)),
        dns_port: Some(cfg.dns_port),
        ipv4_only: Some(cfg.dns_ipv4_only),
        timeout_ms: u64::try_from(cfg.connect_timeout.as_millis()).ok(),
        system_proxy: Some(cfg.system_proxy),
        socks_system_proxy: Some(cfg.socks_system_proxy),
        env_proxy: Some(cfg.env_proxy),
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn apply_file_config_to_runtime(base: &RuntimeConfig, file_cfg: &FileConfig) -> RuntimeConfig {
    let mut out = base.clone();
    if let Some(engine) = file_cfg.engine {
        out.engine = engine;
    }
    if let Some(mode) = file_cfg.mode {
        out.mode = mode;
    }
    if let Some(doh) = file_cfg.doh {
        out.enable_doh = doh;
    }
    if let Some(block_quic) = file_cfg.block_quic {
        out.block_quic = block_quic;
    }
    if let Some(ref dns_addr) = file_cfg.dns_addr {
        out.dns_addr.clone_from(dns_addr);
    }
    if let Some(ref bypass) = file_cfg.bypass_domains {
        out.bypass_domains.clone_from(bypass);
    }
    if let Some(ref include) = file_cfg.include_domains {
        out.patterns.clone_from(include);
    }
    if let Some(vpn_coexistence) = file_cfg.vpn_coexistence {
        out.vpn_coexistence = vpn_coexistence;
    }
    if let Some(tun_ipv6) = file_cfg.tun_ipv6 {
        out.tun_ipv6 = tun_ipv6;
    }
    if let Some(chunk_size) = file_cfg.chunk_size {
        out.chunk_size = chunk_size.max(1);
    }
    if let Some(bind) = file_cfg.bind {
        out.addr = bind;
    }
    if let Some(port) = file_cfg.port {
        out.port = port;
    }
    if let Some(socks_port) = file_cfg.socks_port {
        out.socks_port = if socks_port == 0 || socks_port == out.port {
            None
        } else {
            Some(socks_port)
        };
    }
    if let Some(dns_port) = file_cfg.dns_port {
        out.dns_port = dns_port;
    }
    if let Some(ipv4_only) = file_cfg.ipv4_only {
        out.dns_ipv4_only = ipv4_only;
    }
    if let Some(timeout_ms) = file_cfg.timeout_ms {
        out.connect_timeout = if timeout_ms == 0 {
            Duration::from_millis(8000)
        } else {
            Duration::from_millis(timeout_ms)
        };
    }
    if let Some(system_proxy) = file_cfg.system_proxy {
        out.system_proxy = system_proxy;
    }
    if let Some(socks_system_proxy) = file_cfg.socks_system_proxy {
        out.socks_system_proxy = out.system_proxy && socks_system_proxy && out.socks_port.is_some();
    }
    if let Some(env_proxy) = file_cfg.env_proxy {
        out.env_proxy = out.system_proxy && env_proxy;
    }
    if out.socks_port == Some(out.port) {
        out.socks_port = None;
    }
    if !out.system_proxy {
        out.socks_system_proxy = false;
        out.env_proxy = false;
    }
    if out.socks_port.is_none() {
        out.socks_system_proxy = false;
    }
    out
}

#[cfg(any(target_os = "windows", test))]
fn split_windows_cmdline(cmdline: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    let chars: Vec<char> = cmdline.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            let mut backslashes = 0usize;
            while i < chars.len() && chars[i] == '\\' {
                backslashes += 1;
                i += 1;
            }
            if i < chars.len() && chars[i] == '"' {
                for _ in 0..(backslashes / 2) {
                    current.push('\\');
                }
                if backslashes % 2 == 1 {
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
                has_token = true;
                i += 1;
            } else {
                for _ in 0..backslashes {
                    current.push('\\');
                }
                has_token = true;
            }
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            has_token = true;
            i += 1;
            continue;
        }
        if !in_quotes && ch.is_ascii_whitespace() {
            if has_token {
                args.push(std::mem::take(&mut current));
                has_token = false;
            }
            i += 1;
            continue;
        }
        current.push(ch);
        has_token = true;
        i += 1;
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Migrates a legacy v0.4.x Windows service `binPath` command line into a v0.5.0
/// [`FileConfig`] with `engine = Some(EngineMode::Proxy)` so `--upgrade` preserves
/// existing proxy behavior and custom flags without disruption.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn migrate_legacy_service_cmdline_to_file_config(cmdline: &str) -> FileConfig {
    let mut cfg = FileConfig {
        schema_version: Some(CONFIG_SCHEMA_VERSION),
        engine: Some(EngineMode::Proxy),
        ..Default::default()
    };

    let tokens = split_windows_cmdline(cmdline);
    let mut bypass = Vec::new();
    let mut include = Vec::new();

    // Skip argv[0] (executable path).
    let mut i = 1usize;
    while i < tokens.len() {
        let flag = tokens[i].as_str();
        let next = tokens.get(i + 1).map(String::as_str);
        match flag {
            "--bind" | "--addr" => {
                if let Some(ip) = next.and_then(|v| v.parse::<IpAddr>().ok()) {
                    cfg.bind = Some(ip);
                    i += 2;
                    continue;
                }
            }
            "--port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--socks-port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.socks_port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--chunk-size" | "--window-size" => {
                if let Some(sz) = next.and_then(|v| v.parse::<usize>().ok()) {
                    cfg.chunk_size = Some(sz.max(1));
                    i += 2;
                    continue;
                }
            }
            "--mode" | "--strategy" => {
                if let Some(raw) = next {
                    let parsed = match raw.to_ascii_lowercase().as_str() {
                        "combo" => Some(DesyncMode::Combo),
                        "tls-record" | "tlsrec" => Some(DesyncMode::TlsRecord),
                        "fragment" | "chunk" => Some(DesyncMode::Fragment),
                        "split" => Some(DesyncMode::Split),
                        _ => None,
                    };
                    if let Some(mode) = parsed {
                        cfg.mode = Some(mode);
                        i += 2;
                        continue;
                    }
                }
            }
            "--dns" | "--dns-addr" => {
                if let Some(dns) = next {
                    cfg.dns_addr = Some(dns.to_string());
                    i += 2;
                    continue;
                }
            }
            "--dns-port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.dns_port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--timeout" => {
                if let Some(ms) = next.and_then(|v| v.parse::<u64>().ok()) {
                    cfg.timeout_ms = Some(ms);
                    i += 2;
                    continue;
                }
            }
            "--include" | "--pattern" => {
                if let Some(pat) = next {
                    include.push(pat.to_string());
                    i += 2;
                    continue;
                }
            }
            "--bypass" => {
                if let Some(dom) = next {
                    bypass.push(dom.to_string());
                    i += 2;
                    continue;
                }
            }
            "--no-doh" => cfg.doh = Some(false),
            "--ipv4-only" | "--dns-ipv4-only" => cfg.ipv4_only = Some(true),
            "--no-system-proxy" => cfg.system_proxy = Some(false),
            "--no-socks-proxy" | "--no-socks-system-proxy" => cfg.socks_system_proxy = Some(false),
            "--no-env-proxy" | "--no-launchd-env" => cfg.env_proxy = Some(false),
            "--allow-quic" | "--no-block-quic" => cfg.block_quic = Some(false),
            "--tun" => cfg.engine = Some(EngineMode::Tun),
            "--proxy" => cfg.engine = Some(EngineMode::Proxy),
            "--tun-ipv6" => cfg.tun_ipv6 = Some(true),
            "--vpn-coexistence" => {
                if let Some(raw) = next {
                    let parsed = match raw.to_ascii_lowercase().as_str() {
                        "auto-yield" => Some(VpnCoexistence::AutoYield),
                        "warn" => Some(VpnCoexistence::Warn),
                        "off" => Some(VpnCoexistence::Off),
                        _ => None,
                    };
                    if let Some(mode) = parsed {
                        cfg.vpn_coexistence = Some(mode);
                        i += 2;
                        continue;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if !bypass.is_empty() {
        cfg.bypass_domains = Some(bypass);
    }
    if !include.is_empty() {
        cfg.include_domains = Some(include);
    }
    cfg
}

/// Installs the `vdpi` binary into the service directory and registers automatic
/// background startup for the active operating system (macOS LaunchAgent/LaunchDaemon,
/// native Windows Service under SCM, or Linux systemd unit).
pub fn install_service(cfg: &RuntimeConfig) -> Result<()> {
    install_service_with_options(cfg, false)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
pub fn install_service_with_options(_cfg: &RuntimeConfig, _upgrade: bool) -> Result<()> {
    bail!(
        "service installation is not supported on {}",
        platform_name()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn copy_binary_atomically(current_exe: &Path, target_bin: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let bin_dir = target_bin
        .parent()
        .context("failed to determine target binary directory")?;
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;

    let same_binary = match (fs::canonicalize(current_exe), fs::canonicalize(target_bin)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_bin,
    };
    if same_binary {
        return Ok(());
    }

    let tmp_bin = bin_dir.join(format!(".vdpi.tmp.{}", std::process::id()));
    if let Err(err) = fs::copy(current_exe, &tmp_bin)
        .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))
    {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err);
    }

    if let Err(err) = fs::set_permissions(&tmp_bin, fs::Permissions::from_mode(0o755)) {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err).with_context(|| format!("failed to chmod 0755 {}", tmp_bin.display()));
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("/usr/bin/codesign")
            .args(["-fs", "-"])
            .arg(&tmp_bin)
            .output();
    }
    if let Err(err) = fs::rename(&tmp_bin, target_bin) {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                target_bin.display(),
                tmp_bin.display()
            )
        });
    }

    Ok(())
}

#[cfg(target_os = "windows")]
struct ReplacedFileBackup {
    target: PathBuf,
    backup: PathBuf,
}

#[cfg(target_os = "windows")]
impl ReplacedFileBackup {
    fn commit(self) {
        let _ = fs::remove_file(&self.backup);
    }

    fn rollback(self) {
        if self.target.exists() && fs::remove_file(&self.target).is_err() {
            let displaced = self
                .target
                .with_extension(format!("failed.{}", std::process::id()));
            let _ = fs::rename(&self.target, &displaced);
            let _ = fs::remove_file(&displaced);
        }
        let _ = fs::rename(&self.backup, &self.target);
    }
}

#[cfg(target_os = "windows")]
fn copy_binary_atomically_with_backup(
    current_exe: &Path,
    target_bin: &Path,
    retain_backup: bool,
) -> Result<Option<ReplacedFileBackup>> {
    let bin_dir = target_bin
        .parent()
        .context("failed to determine target binary directory")?;
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;

    let same_binary = match (fs::canonicalize(current_exe), fs::canonicalize(target_bin)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_bin,
    };
    if same_binary {
        return Ok(None);
    }

    let pid = std::process::id();
    let tmp_bin = bin_dir.join(format!("vdpi.tmp.{pid}.exe"));
    if let Err(err) = fs::copy(current_exe, &tmp_bin)
        .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))
    {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err);
    }

    let backup_path = if target_bin.exists() {
        let preferred = bin_dir.join("vdpi.old.exe");
        let backup = if preferred.exists() && fs::remove_file(&preferred).is_err() {
            bin_dir.join(format!("vdpi.old.{pid}.exe"))
        } else {
            preferred
        };
        if let Err(err) = fs::rename(target_bin, &backup) {
            let _ = fs::remove_file(&tmp_bin);
            return Err(err).with_context(|| {
                format!(
                    "failed to move existing binary {} aside to {}",
                    target_bin.display(),
                    backup.display()
                )
            });
        }
        Some(backup)
    } else {
        None
    };

    if let Err(err) = fs::rename(&tmp_bin, target_bin) {
        let _ = fs::remove_file(tmp_bin);
        if let Some(backup) = backup_path {
            let _ = fs::rename(backup, target_bin);
        }
        return Err(err)
            .with_context(|| format!("failed to install new binary to {}", target_bin.display()));
    }

    match backup_path {
        Some(backup) if retain_backup => Ok(Some(ReplacedFileBackup {
            target: target_bin.to_path_buf(),
            backup,
        })),
        Some(backup) => {
            let _ = fs::remove_file(backup);
            Ok(None)
        }
        None => Ok(None),
    }
}

#[cfg(target_os = "windows")]
fn copy_verified_sibling_wintun(bin_dir: &Path) -> Result<bool> {
    let (copied, _) = copy_verified_sibling_wintun_with_backup(bin_dir, false)?;
    Ok(copied)
}

#[cfg(target_os = "windows")]
fn copy_verified_sibling_wintun_with_backup(
    bin_dir: &Path,
    retain_backup: bool,
) -> Result<(bool, Option<ReplacedFileBackup>)> {
    let src_wintun = match crate::platform::windows_tun::find_verified_wintun_dll() {
        Ok(path) => path,
        Err(err) => {
            // Distinguish genuinely absent wintun.dll (allowed for Proxy installs) from
            // a present DLL that failed SHA-256 verification (always fatal).
            let any_candidate_present = std::env::current_exe().ok().is_some_and(|exe| {
                let canonical = fs::canonicalize(&exe).ok();
                crate::platform::windows_tun::resolve_wintun_dll_candidates(
                    &exe,
                    canonical.as_deref(),
                )
                .into_iter()
                .any(|cand| cand.is_file())
            });
            if any_candidate_present {
                return Err(err);
            }
            return Ok((false, None));
        }
    };

    let target_wintun = bin_dir.join("wintun.dll");
    let same_file = match (
        fs::canonicalize(&src_wintun),
        fs::canonicalize(&target_wintun),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => src_wintun == target_wintun,
    };

    let retained_backup = if !same_file {
        let pid = std::process::id();
        let staged = bin_dir.join(format!("wintun.tmp.{pid}.dll"));
        if let Err(err) = fs::copy(&src_wintun, &staged).with_context(|| {
            format!(
                "failed to copy {} to {}",
                src_wintun.display(),
                staged.display()
            )
        }) {
            let _ = fs::remove_file(&staged);
            return Err(err);
        }

        let backup_path = if target_wintun.exists() {
            let preferred = bin_dir.join("wintun.old.dll");
            let backup = if preferred.exists() && fs::remove_file(&preferred).is_err() {
                bin_dir.join(format!("wintun.old.{pid}.dll"))
            } else {
                preferred
            };
            if let Err(err) = fs::rename(&target_wintun, &backup) {
                let _ = fs::remove_file(&staged);
                return Err(err).with_context(|| {
                    format!(
                        "failed to move existing {} aside to {}",
                        target_wintun.display(),
                        backup.display()
                    )
                });
            }
            Some(backup)
        } else {
            None
        };

        if let Err(err) = fs::rename(&staged, &target_wintun) {
            let _ = fs::remove_file(staged);
            if let Some(backup) = backup_path {
                let _ = fs::rename(backup, &target_wintun);
            }
            return Err(err).with_context(|| {
                format!(
                    "failed to install wintun.dll to {}",
                    target_wintun.display()
                )
            });
        }

        match backup_path {
            Some(backup) if retain_backup => Some(ReplacedFileBackup {
                target: target_wintun,
                backup,
            }),
            Some(backup) => {
                let _ = fs::remove_file(backup);
                None
            }
            None => None,
        }
    } else {
        None
    };

    if let Some(src_dir) = src_wintun.parent() {
        let src_license = src_dir.join("WINTUN-LICENSE.txt");
        if src_license.is_file() {
            let _ = fs::copy(&src_license, bin_dir.join("WINTUN-LICENSE.txt"));
        }
    }

    Ok((!same_file, retained_backup))
}

#[cfg(target_os = "windows")]
fn print_windows_stale_browser_hint(cfg: &RuntimeConfig) {
    if cfg.engine != EngineMode::Proxy || !cfg.system_proxy || !cfg.env_proxy {
        return;
    }
    let stale = crate::platform::windows::detect_stale_browsers(unix_now_secs().saturating_add(1));
    if !stale.is_empty() {
        println!(
            "Hint             : restart open browser(s) ({}) once to pick up proxy env, or run 'vdpi engine tun'.",
            stale.join(", ")
        );
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub fn install_service_with_options(cfg: &RuntimeConfig, upgrade: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            is_elevated, query_windows_service_status, relaunch_elevated_and_wait,
        };

        if !is_elevated() {
            println!("Requesting Administrator privileges to install the vdpi Windows service...");
            let mut args = vec!["install".to_string()];
            if upgrade {
                args.push("--upgrade".to_string());
            } else {
                // `build_service_cli_args` always emits explicit `--proxy` / `--tun`
                // so system `config.toml` cannot flip caller intent across UAC.
                args.extend(build_service_cli_args(cfg));
            }
            relaunch_elevated_and_wait(&args)?;
            notify_wininet_refresh();
            broadcast_environment_change();
            println!("Installed and started Windows service: {WINDOWS_SERVICE_NAME} (AUTO_START)");
            if !upgrade {
                print_windows_stale_browser_hint(cfg);
            }
            return Ok(());
        }

        let prev_svc = query_windows_service_status();
        let config_path = config_file::system_config_path();

        // Stop existing Windows service and any legacy vdpi.exe processes before replacing the binary.
        if upgrade {
            let _ = crate::platform::windows_service::stop_windows_service_for_upgrade()?;
        } else {
            let _ = crate::platform::windows_service::stop_windows_service_if_running()?;
        }
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();

        let effective_cfg = if upgrade {
            if config_path.is_file() {
                match config_file::load_file_config(Some(&config_path), true) {
                    Ok((_, file_cfg)) => apply_file_config_to_runtime(cfg, &file_cfg),
                    Err(_) => cfg.clone(),
                }
            } else {
                let migrated = prev_svc
                    .binary_path
                    .as_deref()
                    .map(migrate_legacy_service_cmdline_to_file_config)
                    .unwrap_or_else(|| {
                        let mut fc = file_config_from_runtime(cfg);
                        fc.engine = Some(EngineMode::Proxy);
                        fc
                    });
                config_file::save_file_config_atomic(&config_path, &migrated)?;
                apply_file_config_to_runtime(cfg, &migrated)
            }
        } else {
            let file_cfg = file_config_from_runtime(cfg);
            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
            cfg.clone()
        };

        let vdpi_root = vdpi_root_dir()?;
        let bin_dir = vdpi_root.join("bin");
        let log_dir = vdpi_root.join("logs");
        fs::create_dir_all(&bin_dir)
            .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;

        let current_exe =
            std::env::current_exe().context("failed to determine current executable")?;
        let target_bin = installed_binary_path()?;
        let bin_backup = copy_binary_atomically_with_backup(&current_exe, &target_bin, upgrade)?;
        let (wintun_copied, wintun_backup) =
            match copy_verified_sibling_wintun_with_backup(&bin_dir, upgrade) {
                Ok(res) => res,
                Err(err) => {
                    if let Some(backup) = bin_backup {
                        backup.rollback();
                    }
                    return Err(err);
                }
            };

        if let Err(err) = install_windows_native_service(&target_bin, &effective_cfg) {
            if let Some(backup) = wintun_backup {
                backup.rollback();
            }
            if let Some(backup) = bin_backup {
                backup.rollback();
            }
            return Err(err);
        }

        if let Some(backup) = wintun_backup {
            backup.commit();
        }
        if let Some(backup) = bin_backup {
            backup.commit();
        }

        if wintun_copied {
            println!(
                "Installed Wintun : {}",
                bin_dir.join("wintun.dll").display()
            );
        }
        if !upgrade {
            print_windows_stale_browser_hint(&effective_cfg);
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let current_exe =
            std::env::current_exe().context("failed to determine current executable")?;

        let effective_cfg = if upgrade {
            #[cfg(target_os = "macos")]
            let has_system_daemon = launch_daemon_plist_path().exists();
            #[cfg(target_os = "linux")]
            let has_system_daemon = systemd_system_unit_path().exists();
            let preferred_path = if has_system_daemon {
                config_file::system_config_path()
            } else {
                resolved_user_config_path()
            };
            match config_file::load_file_config(Some(&preferred_path), has_system_daemon) {
                Ok((Some(_), file_cfg)) => apply_file_config_to_runtime(cfg, &file_cfg),
                _ => cfg.clone(),
            }
        } else {
            cfg.clone()
        };

        if effective_cfg.engine == EngineMode::Tun {
            if !is_unix_root() {
                let mut sudo_args = build_service_cli_args(&effective_cfg);
                sudo_args.push("install".to_string());
                if upgrade {
                    sudo_args.push("--upgrade".to_string());
                }
                return relaunch_unix_sudo_and_wait(&sudo_args, "install vdpi in TUN mode");
            }
            let sys_config_path = config_file::system_config_path();
            if !upgrade || !sys_config_path.is_file() {
                let file_cfg = file_config_from_runtime(&effective_cfg);
                config_file::save_file_config_atomic(&sys_config_path, &file_cfg)?;
            }
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            copy_binary_atomically(&current_exe, &target_bin)?;

            #[cfg(target_os = "macos")]
            install_macos_launch_daemon(&target_bin, &effective_cfg)?;

            #[cfg(target_os = "linux")]
            install_linux_systemd_system_service(&target_bin, &effective_cfg)?;

            return Ok(());
        }

        let user_config_path = resolved_user_config_path();
        if !upgrade || !user_config_path.is_file() {
            let file_cfg = file_config_from_runtime(&effective_cfg);
            config_file::save_file_config_atomic(&user_config_path, &file_cfg)?;
            if let Some(parent) = user_config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&user_config_path);
        }

        let vdpi_root = vdpi_root_dir()?;
        let bin_dir = vdpi_root.join("bin");
        let log_dir = vdpi_root.join("logs");
        fs::create_dir_all(&bin_dir)
            .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;

        let target_bin = installed_binary_path()?;
        copy_binary_atomically(&current_exe, &target_bin)?;
        chown_to_sudo_user(&vdpi_root);
        chown_to_sudo_user(&bin_dir);
        chown_to_sudo_user(&log_dir);
        chown_to_sudo_user(&target_bin);

        #[cfg(target_os = "macos")]
        install_macos_launch_agent(&target_bin, &effective_cfg)?;

        #[cfg(target_os = "linux")]
        install_linux_systemd_service(&target_bin, &effective_cfg)?;

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn wait_launchctl_unloaded(service_target: &str) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while launchctl_service_loaded(service_target) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn remove_macos_launch_agent_if_present() {
    let Ok(plist_path) = launch_agent_plist_path() else {
        return;
    };
    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &service_target])
        .stdin(Stdio::null())
        .output();
    if plist_path.exists() {
        let plist_str = plist_path.display().to_string();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &domain_target, &plist_str])
            .stdin(Stdio::null())
            .output();
        let _ = Command::new("/bin/launchctl")
            .args(["unload", &plist_str])
            .stdin(Stdio::null())
            .output();
        let _ = fs::remove_file(&plist_path);
    }
    wait_launchctl_unloaded(&service_target);
}

#[cfg(target_os = "macos")]
fn remove_macos_launch_daemon_if_present() -> Result<bool> {
    let plist_path = launch_daemon_plist_path();
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    if !plist_path.exists() && !launchctl_service_loaded(&service_target) {
        return Ok(false);
    }
    if !is_unix_root() {
        bail!(
            "removing the root LaunchDaemon ({}) requires root privileges; run with sudo.",
            plist_path.display()
        );
    }
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &service_target])
        .stdin(Stdio::null())
        .output();
    if plist_path.exists() {
        let plist_str = plist_path.display().to_string();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", "system", &plist_str])
            .stdin(Stdio::null())
            .output();
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
    }
    wait_launchctl_unloaded(&service_target);
    Ok(true)
}

#[cfg(target_os = "macos")]
fn start_macos_launch_daemon(plist_path: &Path) -> Result<()> {
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    let plist_str = plist_path.display().to_string();

    let _ = Command::new("/bin/launchctl")
        .args(["enable", &service_target])
        .stdin(Stdio::null())
        .output();

    let boot = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", &plist_str])
        .stdin(Stdio::null())
        .output()
        .context("failed to execute '/bin/launchctl bootstrap'")?;
    if !boot.status.success() && !launchctl_service_loaded(&service_target) {
        let detail = String::from_utf8_lossy(&boot.stderr).trim().to_string();
        if detail.is_empty() {
            bail!(
                "failed to start LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                boot.status
            );
        }
        bail!("failed to start LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
    }

    // `RunAtLoad=true` starts the daemon automatically after `bootstrap`; wait briefly
    // before issuing a non-destructive `kickstart` so we do not SIGKILL it mid-utun startup.
    let deadline = Instant::now() + Duration::from_millis(1500);
    while !launchctl_service_running(&service_target) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !launchctl_service_running(&service_target) {
        let kick = Command::new("/bin/launchctl")
            .args(["kickstart", &service_target])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl kickstart'")?;
        if !kick.status.success() && !launchctl_service_running(&service_target) {
            let detail = String::from_utf8_lossy(&kick.stderr).trim().to_string();
            if detail.is_empty() {
                bail!(
                    "failed to kickstart LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                    kick.status
                );
            }
            bail!("failed to kickstart LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launch_daemon(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    // Mutual exclusion: unload any user LaunchAgent and clear system proxies before starting TUN.
    remove_macos_launch_agent_if_present();
    let _ = clear_all_system_proxies();

    let plist_path = launch_daemon_plist_path();
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    let plist_str = plist_path.display().to_string();

    if plist_path.exists() || launchctl_service_loaded(&service_target) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", "system", &plist_str])
            .stdin(Stdio::null())
            .output();
        wait_launchctl_unloaded(&service_target);
    }

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let plist_xml = generate_launch_daemon_plist(target_bin, cfg);
    fs::write(&plist_path, plist_xml)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
    }

    start_macos_launch_daemon(&plist_path)?;

    println!("Installed binary : {}", target_bin.display());
    println!("Loaded daemon    : {} (TUN)", plist_path.display());
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launch_agent(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    // Mutual exclusion: remove system LaunchDaemon if previously installed in TUN mode.
    let _ = remove_macos_launch_daemon_if_present()?;

    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
    let plist_path = launch_agent_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let plist_str = plist_path.display().to_string();
    if plist_path.exists() || launchctl_service_loaded(&service_target) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &domain_target, &plist_str])
            .stdin(Stdio::null())
            .output();
        wait_launchctl_unloaded(&service_target);
    }

    let plist_xml = generate_launch_agent_plist(target_bin, cfg);
    fs::write(&plist_path, plist_xml)?;
    chown_to_sudo_user(&plist_path);

    let boot = Command::new("/bin/launchctl")
        .args(["bootstrap", &domain_target, &plist_str])
        .output()?;
    if !boot.status.success() && !launchctl_service_loaded(&service_target) {
        let fallback = Command::new("/bin/launchctl")
            .args(["load", "-w", &plist_str])
            .output()?;
        if !fallback.status.success() {
            bail!(
                "failed to load LaunchAgent {}: {}",
                plist_path.display(),
                String::from_utf8_lossy(&fallback.stderr).trim()
            );
        }
    }

    let _ = Command::new("/bin/launchctl")
        .args(["kickstart", "-k", &service_target])
        .output();

    let path_updated = ensure_unix_shell_path();

    println!("Installed binary : {}", target_bin.display());
    println!("Loaded service   : {}", plist_path.display());
    if path_updated {
        println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_user_systemctl_command() -> Command {
    let mut cmd = Command::new("systemctl");
    cmd.arg("--user");
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        use std::os::unix::process::CommandExt;
        let runtime_dir = format!("/run/user/{}", sudo_user.uid);
        let dbus_addr = format!("unix:path={runtime_dir}/bus");
        cmd.uid(sudo_user.uid)
            .gid(sudo_user.gid)
            .env("HOME", &sudo_user.home_dir)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr);
        if let Some(ref name) = sudo_user.username {
            cmd.env("USER", name).env("LOGNAME", name);
        }
    }
    cmd
}

#[cfg(target_os = "linux")]
fn remove_linux_user_unit_if_present() {
    let _ = linux_user_systemctl_command()
        .args(["disable", "--now", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .output();
    if let Some(unit_path) = systemd_user_unit_path().ok().filter(|p| p.exists()) {
        let _ = fs::remove_file(unit_path);
        let _ = linux_user_systemctl_command()
            .args(["daemon-reload"])
            .stdin(Stdio::null())
            .output();
    }
}

#[cfg(target_os = "linux")]
fn remove_linux_system_unit_if_present() -> Result<bool> {
    let unit_path = systemd_system_unit_path();
    if !unit_path.exists() {
        return Ok(false);
    }
    if !is_unix_root() {
        bail!(
            "removing the system systemd unit ({}) requires root privileges; run with sudo.",
            unit_path.display()
        );
    }
    let _ = Command::new("systemctl")
        .args(["disable", "--now", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .output();
    fs::remove_file(&unit_path)
        .with_context(|| format!("failed to remove {}", unit_path.display()))?;
    let _ = Command::new("systemctl")
        .args(["daemon-reload"])
        .stdin(Stdio::null())
        .output();
    Ok(true)
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_system_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    // Mutual exclusion: stop/remove user Proxy unit and clear desktop proxies before starting TUN.
    remove_linux_user_unit_if_present();
    let _ = clear_all_system_proxies();

    let unit_path = systemd_system_unit_path();
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let unit_text = generate_systemd_system_unit(target_bin, cfg);
    fs::write(&unit_path, unit_text)
        .with_context(|| format!("failed to write {}", unit_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&unit_path, fs::Permissions::from_mode(0o644));
    }

    let _ = Command::new("systemctl")
        .args(["daemon-reload"])
        .stdin(Stdio::null())
        .output();
    let enable = Command::new("systemctl")
        .args(["enable", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .output();

    let mut systemd_note = enable
        .ok()
        .filter(|out| !out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stderr).trim().to_string());

    if systemd_note.is_none() {
        let restart = Command::new("systemctl")
            .args(["restart", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output();
        if let Some(out) = restart.ok().filter(|out| !out.status.success()) {
            systemd_note = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }

    if let Some(reason) = systemd_note {
        println!(
            "Note: systemd system daemon not active ({reason}). Wrote unit file to {}",
            unit_path.display()
        );
    }

    println!("Installed binary : {}", target_bin.display());
    println!("Systemd unit     : {} (TUN)", unit_path.display());
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    // Mutual exclusion: remove root system TUN unit if previously installed.
    let _ = remove_linux_system_unit_if_present()?;

    if let Ok(home) = home_dir() {
        let local_bin = home.join(".local").join("bin");
        if fs::create_dir_all(&local_bin).is_ok() {
            let link_path = local_bin.join("vdpi");
            let _ = fs::remove_file(&link_path);
            let _ = std::os::unix::fs::symlink(target_bin, &link_path);
            chown_to_sudo_user(&local_bin);
        }
    }

    let unit_path = systemd_user_unit_path()?;
    if let Some(parent) = unit_path.parent() {
        fs::create_dir_all(parent)?;
        chown_to_sudo_user(parent);
    }

    let unit_text = generate_systemd_unit(target_bin, cfg);
    fs::write(&unit_path, unit_text)?;
    chown_to_sudo_user(&unit_path);

    let _ = linux_user_systemctl_command()
        .args(["daemon-reload"])
        .output();
    let enable = linux_user_systemctl_command()
        .args(["enable", SYSTEMD_UNIT_NAME])
        .output();

    let mut systemd_note = enable
        .ok()
        .filter(|out| !out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stderr).trim().to_string());

    if systemd_note.is_none() {
        let restart = linux_user_systemctl_command()
            .args(["restart", SYSTEMD_UNIT_NAME])
            .output();
        if let Some(out) = restart.ok().filter(|out| !out.status.success()) {
            systemd_note = Some(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
    }

    if let Some(reason) = systemd_note {
        println!(
            "Note: systemd user session not active ({reason}). Wrote unit file to {}",
            unit_path.display()
        );
    }

    let path_updated = ensure_unix_shell_path();

    println!("Installed binary : {}", target_bin.display());
    println!("Systemd unit     : {}", unit_path.display());
    if path_updated {
        println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const UNIX_SHELL_PATH_EXPORT: &str = r#"export PATH="$HOME/.vdpi/bin:$PATH""#;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn strip_unix_shell_path_line(content: &str) -> Option<String> {
    let mut removed = false;
    let mut kept = Vec::new();
    for line in content.lines() {
        if line == UNIX_SHELL_PATH_EXPORT {
            removed = true;
        } else {
            kept.push(line);
        }
    }
    if !removed {
        return None;
    }
    let mut next = kept.join("\n");
    if !next.is_empty() && content.ends_with('\n') {
        next.push('\n');
    }
    Some(next)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_unix_shell_path() -> bool {
    let Ok(home) = home_dir() else {
        return false;
    };
    let mut updated = false;
    for rc_name in [".zshrc", ".bashrc", ".profile"] {
        let rc_path = home.join(rc_name);
        if !rc_path.is_file() {
            continue;
        }
        let Ok(content) = fs::read_to_string(&rc_path) else {
            continue;
        };
        if content.contains(".vdpi/bin") {
            continue;
        }
        let mut next = content;
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(UNIX_SHELL_PATH_EXPORT);
        next.push('\n');
        if fs::write(&rc_path, next).is_ok() {
            updated = true;
        }
    }
    updated
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_unix_shell_path() -> bool {
    let Ok(home) = home_dir() else {
        return false;
    };
    let mut updated = false;
    for rc_name in [".zshrc", ".bashrc", ".profile"] {
        let rc_path = home.join(rc_name);
        if !rc_path.is_file() {
            continue;
        }
        let Ok(content) = fs::read_to_string(&rc_path) else {
            continue;
        };
        let Some(next) = strip_unix_shell_path_line(&content) else {
            continue;
        };
        if fs::write(&rc_path, next).is_ok() {
            updated = true;
        }
    }
    updated
}

#[cfg(target_os = "windows")]
fn install_windows_native_service(target_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    use crate::platform::windows::{
        add_dir_to_windows_system_path, broadcast_environment_change, notify_wininet_refresh,
    };
    use crate::platform::windows_service::install_or_update_windows_service;

    let bin_path_cmd = build_windows_service_bin_path(target_bin, cfg);
    install_or_update_windows_service(&bin_path_cmd)?;

    let legacy_bin = legacy_windows_root_dir().map(|r| r.join("bin"));
    let path_added = target_bin
        .parent()
        .and_then(|bin_dir| add_dir_to_windows_system_path(bin_dir, legacy_bin.as_deref()).ok())
        .unwrap_or(false);

    // Refresh WinINET and environment directly in the interactive caller's session as well.
    notify_wininet_refresh();
    broadcast_environment_change();

    println!("Installed binary : {}", target_bin.display());
    println!("Windows service  : {WINDOWS_SERVICE_NAME} (AUTO_START, RUNNING)");
    if path_added {
        if let Some(bin_dir) = target_bin.parent() {
            println!("System PATH      : added {}", bin_dir.display());
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn legacy_windows_root_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("vdpi"))
}

#[cfg(target_os = "windows")]
fn cleanup_legacy_windows_startup() {
    use crate::platform::windows::run_reg;

    let _ = run_reg(&["delete", WINDOWS_LEGACY_RUN_KEY, "/v", "vdpi", "/f"]);
    if let Some(legacy_root) = legacy_windows_root_dir() {
        let legacy_vbs = legacy_root.join("bin").join("vdpi-autostart.vbs");
        let _ = fs::remove_file(legacy_vbs);
    }
}

#[cfg(target_os = "windows")]
fn stop_windows_foreground_daemons() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let my_pid = std::process::id();
    // Stop published daemon PIDs only; the unelevated installer is waiting for our exit.
    for state in read_runtime_states() {
        if state.pid != my_pid {
            let _ = Command::new("taskkill")
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "/F",
                    "/PID",
                    &state.pid.to_string(),
                    "/FI",
                    "IMAGENAME eq vdpi.exe",
                ])
                .output();
        }
    }
}

#[cfg(target_os = "windows")]
fn schedule_delayed_windows_dir_cleanup(vdpi_root: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let Some(root_str) = vdpi_root.to_str() else {
        return;
    };
    if root_str.is_empty()
        || root_str.contains(['"', '&', '|', '%', '^', '<', '>', '\r', '\n', '\0'])
    {
        return;
    }

    let cleanup_cmd = format!(
        "for /L %i in (1,1,12) do (rmdir /S /Q \"{root_str}\" 2>nul & if not exist \"{root_str}\" (exit /b 0) else (ping -n 2 127.0.0.1 >nul))"
    );
    let _ = Command::new("cmd.exe")
        .current_dir(std::env::temp_dir())
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .raw_arg("/C")
        .raw_arg(cleanup_cmd)
        .spawn();
}

#[cfg(target_os = "windows")]
fn cleanup_windows_install_files(purge: bool) {
    use crate::platform::windows::remove_dir_from_windows_path;

    // Release any directory handle held on `C:\Program Files\vdpi\bin` via CWD.
    let _ = std::env::set_current_dir(std::env::temp_dir());

    let Ok(vdpi_root) = vdpi_root_dir() else {
        return;
    };
    let bin_dir = vdpi_root.join("bin");
    let legacy_root = legacy_windows_root_dir();
    let legacy_bin = legacy_root.as_ref().map(|r| r.join("bin"));
    let user_cfg = config_file::user_config_path();

    remove_dir_from_windows_path(&bin_dir, legacy_bin.as_deref());

    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(&p).ok());

    if let Some(legacy) = legacy_root.as_deref().filter(|p| p.exists()) {
        if purge {
            let running_from_legacy = current_exe
                .as_ref()
                .zip(fs::canonicalize(legacy).ok())
                .is_some_and(|(exe, root)| exe.starts_with(root));
            if running_from_legacy || fs::remove_dir_all(legacy).is_err() {
                let _ = fs::remove_dir_all(legacy.join("logs"));
                schedule_delayed_windows_dir_cleanup(legacy);
            }
        } else {
            // Preserve `%LOCALAPPDATA%\vdpi\config.toml` and its parent directory when
            // uninstall runs without `--purge`; remove only bin/, logs/, and state.json.
            let _ = fs::remove_dir_all(legacy.join("logs"));
            let _ = fs::remove_file(legacy.join("state.json"));
            let legacy_bin_dir = legacy.join("bin");
            if legacy_bin_dir.exists() {
                let running_from_legacy_bin = current_exe
                    .as_ref()
                    .zip(fs::canonicalize(&legacy_bin_dir).ok())
                    .is_some_and(|(exe, root)| exe.starts_with(root));
                if running_from_legacy_bin || fs::remove_dir_all(&legacy_bin_dir).is_err() {
                    schedule_delayed_windows_dir_cleanup(&legacy_bin_dir);
                }
            }
        }
    }

    let pd_dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("vdpi");
    if pd_dir.exists() {
        if purge {
            let _ = fs::remove_dir_all(&pd_dir);
        } else {
            let _ = fs::remove_file(pd_dir.join("state.json"));
        }
    }

    if purge {
        if user_cfg.is_file() {
            let _ = fs::remove_file(&user_cfg);
        }
        if let Some(parent) = user_cfg.parent() {
            let _ = fs::remove_dir(parent);
        }
    }

    if vdpi_root.exists() {
        let contains_user_cfg = user_cfg.starts_with(&vdpi_root);
        if purge || !contains_user_cfg {
            let running_from_root = current_exe
                .as_ref()
                .zip(fs::canonicalize(&vdpi_root).ok())
                .is_some_and(|(exe, root)| exe.starts_with(root));
            if running_from_root || fs::remove_dir_all(&vdpi_root).is_err() {
                let _ = fs::remove_dir_all(vdpi_root.join("logs"));
                schedule_delayed_windows_dir_cleanup(&vdpi_root);
            }
        } else {
            let _ = fs::remove_dir_all(vdpi_root.join("logs"));
            let _ = fs::remove_file(vdpi_root.join("state.json"));
            if bin_dir.exists() {
                let running_from_bin = current_exe
                    .as_ref()
                    .zip(fs::canonicalize(&bin_dir).ok())
                    .is_some_and(|(exe, root)| exe.starts_with(root));
                if running_from_bin || fs::remove_dir_all(&bin_dir).is_err() {
                    schedule_delayed_windows_dir_cleanup(&bin_dir);
                }
            }
        }
    }
}

/// Persists `target` (`EngineMode::Tun` or `EngineMode::Proxy`) to the canonical
/// `config.toml`, cleanly transitions any installed background service between TUN
/// and Proxy modes, and restarts the service if it was running.
pub fn switch_service_engine(target: EngineMode, cfg: &RuntimeConfig) -> Result<()> {
    switch_service_engine_impl(target, cfg, true)
}

/// Quiet variant of [`switch_service_engine`] for interactive TUI callers.
pub fn switch_service_engine_quiet(target: EngineMode, cfg: &RuntimeConfig) -> Result<()> {
    switch_service_engine_impl(target, cfg, false)
}

fn switch_service_engine_impl(
    target: EngineMode,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait,
            stop_windows_service_if_running,
        };
        use crate::platform::windows_tun::{
            find_verified_wintun_dll, verify_wintun_dll_sha256, WINTUN_DLL_AMD64_SHA256,
            WINTUN_VERSION,
        };

        let svc = query_windows_service_status();
        if svc.installed && !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to switch the vdpi Windows service to {} mode...",
                    target.as_str()
                );
            }
            relaunch_elevated_and_wait(&["engine".to_string(), target.as_str().to_string()])?;
            notify_wininet_refresh();
            broadcast_environment_change();
            if verbose {
                println!(
                    "Switched vdpi Windows service engine to {}.",
                    target.as_str()
                );
            }
            return Ok(());
        }

        let config_path = if svc.installed || is_elevated() {
            config_file::system_config_path()
        } else {
            config_file::user_config_path()
        };

        let mut file_cfg = config_file::load_file_config(Some(&config_path), svc.installed)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);

        if svc.installed {
            let target_bin = installed_binary_path()
                .ok()
                .filter(|p| p.is_file())
                .or_else(|| std::env::current_exe().ok())
                .context("failed to determine vdpi binary path for service switch")?;
            let bin_dir = target_bin
                .parent()
                .map(Path::to_path_buf)
                .context("failed to determine vdpi service binary directory")?;
            let target_wintun = bin_dir.join("wintun.dll");

            if target == EngineMode::Tun {
                if let Err(sibling_err) = find_verified_wintun_dll() {
                    if !target_wintun.is_file() {
                        bail!(
                            "cannot switch Windows service to TUN mode: {} is missing ({sibling_err}). \
                             Place the verified amd64 wintun.dll (v{WINTUN_VERSION}) in {} or reinstall vdpi.",
                            target_wintun.display(),
                            bin_dir.display()
                        );
                    }
                    verify_wintun_dll_sha256(&target_wintun, WINTUN_DLL_AMD64_SHA256).with_context(
                        || {
                            format!(
                                "cannot switch Windows service to TUN mode: {} failed SHA-256 verification; \
                                 replace it with the verified amd64 wintun.dll (v{WINTUN_VERSION}) or reinstall vdpi",
                                target_wintun.display()
                            )
                        },
                    )?;
                }
            }

            let was_running = matches!(svc.state, "RUNNING" | "START_PENDING");
            let _ = stop_windows_service_if_running()?;
            stop_windows_foreground_daemons();

            if target == EngineMode::Tun {
                let _ = copy_verified_sibling_wintun(&bin_dir)?;
                if !target_wintun.is_file() {
                    bail!(
                        "cannot switch Windows service to TUN mode: {} is missing. \
                         Place the verified amd64 wintun.dll (v{WINTUN_VERSION}) in {} or reinstall vdpi.",
                        target_wintun.display(),
                        bin_dir.display()
                    );
                }
                verify_wintun_dll_sha256(&target_wintun, WINTUN_DLL_AMD64_SHA256).with_context(
                    || {
                        format!(
                            "cannot switch Windows service to TUN mode: {} failed SHA-256 verification; \
                             replace it with the verified amd64 wintun.dll (v{WINTUN_VERSION}) or reinstall vdpi",
                            target_wintun.display()
                        )
                    },
                )?;
                clear_all_system_proxies()?;
            }

            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let bin_path_cmd = build_windows_service_bin_path(&target_bin, &target_cfg);
            install_or_update_windows_service_with_start(&bin_path_cmd, was_running)?;
            notify_wininet_refresh();
            broadcast_environment_change();
        } else {
            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        let service_installed = daemon_exists || agent_exists;
        let was_running = detect_service_state() == ServiceState::Running;

        if service_installed && (target == EngineMode::Tun || daemon_exists) && !is_unix_root() {
            let args = vec!["engine".to_string(), target.as_str().to_string()];
            let action = format!(
                "switch the macOS background service to {} mode",
                target.as_str()
            );
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if target == EngineMode::Tun && (service_installed || is_unix_root()) {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg =
            config_file::load_file_config(Some(&config_path), target == EngineMode::Tun)
                .ok()
                .and_then(|(found, fc)| found.map(|_| fc))
                .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if target == EngineMode::Proxy {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        if service_installed {
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let current_exe =
                std::env::current_exe().context("failed to determine current executable")?;

            match target {
                EngineMode::Tun => {
                    remove_macos_launch_agent_if_present();
                    let _ = clear_all_system_proxies();
                    let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    let plist_path = launch_daemon_plist_path();
                    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
                    let plist_str = plist_path.display().to_string();
                    if plist_path.exists() || launchctl_service_loaded(&service_target) {
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", &service_target])
                            .stdin(Stdio::null())
                            .output();
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", "system", &plist_str])
                            .stdin(Stdio::null())
                            .output();
                        wait_launchctl_unloaded(&service_target);
                    }
                    if let Some(parent) = plist_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(
                        &plist_path,
                        generate_launch_daemon_plist(&target_bin, &target_cfg),
                    )?;
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
                    }
                    if was_running {
                        start_macos_launch_daemon(&plist_path)?;
                    }
                }
                EngineMode::Proxy => {
                    let _ = remove_macos_launch_daemon_if_present()?;
                    let target_bin = installed_binary_path()?;
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    chown_to_sudo_user(&target_bin);
                    if let Some(bin_dir) = target_bin.parent() {
                        chown_to_sudo_user(bin_dir);
                        if let Some(root) = bin_dir.parent() {
                            chown_to_sudo_user(root);
                        }
                    }
                    let plist_path = launch_agent_plist_path()?;
                    if let Some(parent) = plist_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let uid = current_uid();
                    let domain_target = format!("gui/{uid}");
                    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
                    let plist_str = plist_path.display().to_string();
                    if plist_path.exists() || launchctl_service_loaded(&service_target) {
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", &service_target])
                            .stdin(Stdio::null())
                            .output();
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", &domain_target, &plist_str])
                            .stdin(Stdio::null())
                            .output();
                        wait_launchctl_unloaded(&service_target);
                    }
                    fs::write(
                        &plist_path,
                        generate_launch_agent_plist(&target_bin, &target_cfg),
                    )?;
                    chown_to_sudo_user(&plist_path);
                    if was_running {
                        let boot = Command::new("/bin/launchctl")
                            .args(["bootstrap", &domain_target, &plist_str])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute '/bin/launchctl bootstrap'")?;
                        if !boot.status.success() && !launchctl_service_loaded(&service_target) {
                            let detail = String::from_utf8_lossy(&boot.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                                    boot.status
                                );
                            }
                            bail!("failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
                        }
                        let kick = Command::new("/bin/launchctl")
                            .args(["kickstart", "-k", &service_target])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute '/bin/launchctl kickstart'")?;
                        if !kick.status.success() && !launchctl_service_running(&service_target) {
                            let detail = String::from_utf8_lossy(&kick.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to kickstart LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                                    kick.status
                                );
                            }
                            bail!(
                                "failed to kickstart LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}"
                            );
                        }
                    }
                }
            }
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        let service_installed = system_exists || user_exists;
        let was_running = detect_service_state() == ServiceState::Running;

        if service_installed && (target == EngineMode::Tun || system_exists) && !is_unix_root() {
            let args = vec!["engine".to_string(), target.as_str().to_string()];
            let action = format!(
                "switch the Linux background service to {} mode",
                target.as_str()
            );
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if target == EngineMode::Tun && (service_installed || is_unix_root()) {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg =
            config_file::load_file_config(Some(&config_path), target == EngineMode::Tun)
                .ok()
                .and_then(|(found, fc)| found.map(|_| fc))
                .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if target == EngineMode::Proxy {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        if service_installed {
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let current_exe =
                std::env::current_exe().context("failed to determine current executable")?;

            match target {
                EngineMode::Tun => {
                    remove_linux_user_unit_if_present();
                    let _ = clear_all_system_proxies();
                    let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    let unit_path = systemd_system_unit_path();
                    if let Some(parent) = unit_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(
                        &unit_path,
                        generate_systemd_system_unit(&target_bin, &target_cfg),
                    )?;
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&unit_path, fs::Permissions::from_mode(0o644));
                    }
                    let _ = Command::new("systemctl")
                        .args(["daemon-reload"])
                        .stdin(Stdio::null())
                        .output();
                    let _ = Command::new("systemctl")
                        .args(["enable", SYSTEMD_UNIT_NAME])
                        .stdin(Stdio::null())
                        .output();
                    if was_running {
                        let out = Command::new("systemctl")
                            .args(["restart", SYSTEMD_UNIT_NAME])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute 'systemctl restart'")?;
                        if !out.status.success() {
                            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                                    out.status
                                );
                            }
                            bail!(
                                "failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}"
                            );
                        }
                    }
                }
                EngineMode::Proxy => {
                    let _ = remove_linux_system_unit_if_present()?;
                    let target_bin = installed_binary_path()?;
                    if !target_bin.is_file() {
                        copy_binary_atomically(&current_exe, &target_bin)?;
                        chown_to_sudo_user(&target_bin);
                        if let Some(bin_dir) = target_bin.parent() {
                            chown_to_sudo_user(bin_dir);
                            if let Some(root) = bin_dir.parent() {
                                chown_to_sudo_user(root);
                            }
                        }
                    }
                    let unit_path = systemd_user_unit_path()?;
                    if let Some(parent) = unit_path.parent() {
                        fs::create_dir_all(parent)?;
                        chown_to_sudo_user(parent);
                    }
                    fs::write(&unit_path, generate_systemd_unit(&target_bin, &target_cfg))?;
                    chown_to_sudo_user(&unit_path);
                    let _ = linux_user_systemctl_command()
                        .args(["daemon-reload"])
                        .stdin(Stdio::null())
                        .output();
                    let _ = linux_user_systemctl_command()
                        .args(["enable", SYSTEMD_UNIT_NAME])
                        .stdin(Stdio::null())
                        .output();
                    if was_running {
                        let out = linux_user_systemctl_command()
                            .args(["restart", SYSTEMD_UNIT_NAME])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute 'systemctl --user restart'")?;
                        if !out.status.success() {
                            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                                    out.status
                                );
                            }
                            bail!(
                                "failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}"
                            );
                        }
                    }
                }
            }
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (target, cfg, verbose);
        bail!("engine switching is not supported on {}", platform_name());
    }
}

/// Updates the configured upstream DNS server in `config.toml` and restarts any
/// running background service so the new resolver takes effect immediately.
pub fn set_service_dns(dns_addr: &str, cfg: &RuntimeConfig) -> Result<()> {
    set_service_dns_impl(dns_addr, cfg, true)
}

/// Silent variant of [`set_service_dns`] for the interactive Control Center TUI.
pub fn set_service_dns_quiet(dns_addr: &str, cfg: &RuntimeConfig) -> Result<()> {
    set_service_dns_impl(dns_addr, cfg, false)
}

fn set_service_dns_impl(dns_addr: &str, cfg: &RuntimeConfig, verbose: bool) -> Result<()> {
    let trimmed = dns_addr.trim();
    let mut validator = config_file::FileConfig::default();
    config_file::set_config_key(&mut validator, "dns_addr", trimmed)?;
    let validated = validator.dns_addr.unwrap_or_else(|| trimmed.to_string());

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait,
        };

        let svc = query_windows_service_status();
        if svc.installed && !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to update the vdpi Windows service DNS server to {validated}..."
                );
            }
            relaunch_elevated_and_wait(&["dns".to_string(), validated.clone()])?;
            if verbose {
                println!("Updated vdpi Windows service DNS server to {validated}.");
            }
            return Ok(());
        }

        let config_path = if svc.installed || is_elevated() {
            config_file::system_config_path()
        } else {
            config_file::user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), svc.installed)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;

        if svc.installed {
            let was_running = matches!(svc.state, "RUNNING" | "START_PENDING");
            let target_bin = installed_binary_path()
                .ok()
                .filter(|p| p.is_file())
                .or_else(|| std::env::current_exe().ok())
                .context("failed to determine vdpi binary path for DNS update")?;
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let bin_path_cmd = build_windows_service_bin_path(&target_bin, &target_cfg);
            install_or_update_windows_service_with_start(&bin_path_cmd, was_running)?;
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {validated} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        if daemon_exists && !is_unix_root() {
            let args = vec!["dns".to_string(), validated.clone()];
            let action = format!("update the macOS background service DNS server to {validated}");
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if daemon_exists {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), daemon_exists)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if !daemon_exists {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
        if daemon_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let plist_path = launch_daemon_plist_path();
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", "system", &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            fs::write(
                &plist_path,
                generate_launch_daemon_plist(&target_bin, &target_cfg),
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
            }
            if was_running {
                start_macos_launch_daemon(&plist_path)?;
            }
        } else if agent_exists {
            let target_bin = installed_binary_path()?;
            let plist_path = launch_agent_plist_path()?;
            let domain = launchctl_gui_domain();
            let service_target = format!("{domain}/{LAUNCH_AGENT_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &domain, &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            fs::write(
                &plist_path,
                generate_launchd_plist(&target_bin, &target_cfg),
            )?;
            if was_running {
                let boot = Command::new("/bin/launchctl")
                    .args(["bootstrap", &domain, &plist_str])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute '/bin/launchctl bootstrap'")?;
                if !boot.status.success() && !launchctl_service_loaded(&service_target) {
                    let detail = String::from_utf8_lossy(&boot.stderr).trim().to_string();
                    bail!("failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
                }
                let _ = Command::new("/bin/launchctl")
                    .args(["kickstart", "-k", &service_target])
                    .stdin(Stdio::null())
                    .output();
            }
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {validated} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        if system_exists && !is_unix_root() {
            let args = vec!["dns".to_string(), validated.clone()];
            let action = format!("update the Linux background service DNS server to {validated}");
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if system_exists {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), system_exists)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if !system_exists {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
        if system_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let unit_path = systemd_system_unit_path();
            fs::write(
                &unit_path,
                generate_systemd_system_unit(&target_bin, &target_cfg),
            )?;
            let _ = Command::new("systemctl")
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = Command::new("systemctl")
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
            }
        } else if user_exists {
            let target_bin = installed_binary_path()?;
            let unit_path = systemd_user_unit_path()?;
            fs::write(&unit_path, generate_systemd_unit(&target_bin, &target_cfg))?;
            let _ = linux_user_systemctl_command()
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = linux_user_systemctl_command()
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl --user restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
            }
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {validated} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (validated, cfg, verbose);
        bail!("DNS configuration is not supported on {}", platform_name());
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn cleanup_unix_root_dir(root: &Path, user_cfg: &Path, purge: bool) {
    if !root.exists() {
        return;
    }
    if purge {
        let _ = fs::remove_dir_all(root);
        return;
    }
    let _ = fs::remove_dir_all(root.join("bin"));
    let _ = fs::remove_dir_all(root.join("logs"));
    let _ = fs::remove_file(root.join("state.json"));
    let _ = fs::remove_file(root.join("proxy-lease.lock"));
    if !user_cfg.starts_with(root) {
        let _ = fs::remove_dir(root);
    }
}

/// Stops the background service, removes startup registration, cleans installed files,
/// and restores system proxy state (including removing persisted `config.toml`).
pub fn uninstall_service() -> Result<()> {
    uninstall_service_with_options(true)
}

/// Stops the background service (both system TUN and user Proxy units if present), removes
/// startup registration, cleans installed files, restores system proxy state, and removes
/// `config.toml` when `purge` is `true`.
pub fn uninstall_service_with_options(purge: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let daemon_present = launch_daemon_plist_path().exists()
            || launchctl_service_loaded(&format!("system/{LAUNCH_DAEMON_LABEL}"))
            || fs::symlink_metadata(UNIX_SYSTEM_BIN_PATH).is_ok();
        if daemon_present && !is_unix_root() {
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            return relaunch_unix_sudo_and_wait(&args, "uninstall the vdpi TUN background service");
        }
        if remove_macos_launch_daemon_if_present()? {
            println!(
                "Removed LaunchDaemon: {}",
                launch_daemon_plist_path().display()
            );
        }
        let sys_bin = Path::new(UNIX_SYSTEM_BIN_PATH);
        if fs::symlink_metadata(sys_bin).is_ok() {
            match fs::remove_file(sys_bin) {
                Ok(()) => println!("Removed system binary: {}", sys_bin.display()),
                Err(err) => eprintln!(
                    "Warning: could not remove {} ({err}); run with sudo if needed.",
                    sys_bin.display()
                ),
            }
        }

        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        let plist_path = launch_agent_plist_path()?;

        // Always attempt service-target bootout even when the plist file is already missing.
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();

        if plist_path.exists() {
            let plist_str = plist_path.display().to_string();
            let _ = Command::new("/bin/launchctl")
                .args(["bootout", &domain_target, &plist_str])
                .stdin(Stdio::null())
                .output();
            let _ = Command::new("/bin/launchctl")
                .args(["unload", &plist_str])
                .stdin(Stdio::null())
                .output();
            fs::remove_file(&plist_path)?;
            println!("Removed LaunchAgent: {}", plist_path.display());
        } else {
            println!("LaunchAgent {} is not installed", plist_path.display());
        }

        wait_launchctl_unloaded(&service_target);

        if remove_unix_shell_path() {
            println!("Removed ~/.vdpi/bin from shell PATH profile.");
        }
        let _ = fs::remove_file("/Library/Application Support/vdpi/state.json");
        let user_cfg = resolved_user_config_path();
        if let Ok(root) = vdpi_root_dir() {
            cleanup_unix_root_dir(&root, &user_cfg, purge);
        }
        if purge {
            let sys_cfg = config_file::system_config_path();
            if sys_cfg.is_file() {
                let _ = fs::remove_file(&sys_cfg);
                if let Some(parent) = sys_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            if user_cfg.is_file() {
                let _ = fs::remove_file(&user_cfg);
                if let Some(parent) = user_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            let _ = fs::remove_file("/var/log/vdpi.out.log");
            let _ = fs::remove_file("/var/log/vdpi.err.log");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let system_present = systemd_system_unit_path().exists()
            || fs::symlink_metadata(UNIX_SYSTEM_BIN_PATH).is_ok();
        if system_present && !is_unix_root() {
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            return relaunch_unix_sudo_and_wait(&args, "uninstall the vdpi TUN background service");
        }
        if remove_linux_system_unit_if_present()? {
            println!(
                "Removed systemd system unit: {}",
                systemd_system_unit_path().display()
            );
        }
        let sys_bin = Path::new(UNIX_SYSTEM_BIN_PATH);
        if fs::symlink_metadata(sys_bin).is_ok() {
            match fs::remove_file(sys_bin) {
                Ok(()) => println!("Removed system binary: {}", sys_bin.display()),
                Err(err) => eprintln!(
                    "Warning: could not remove {} ({err}); run with sudo if needed.",
                    sys_bin.display()
                ),
            }
        }

        let unit_path = systemd_user_unit_path()?;
        let _ = linux_user_systemctl_command()
            .args(["disable", "--now", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output();
        if unit_path.exists() {
            fs::remove_file(&unit_path)?;
            let _ = linux_user_systemctl_command()
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            println!("Removed systemd user unit: {}", unit_path.display());
        } else {
            println!("Systemd unit {} is not installed", unit_path.display());
        }
        if let Ok(home) = home_dir() {
            let link_path = home.join(".local").join("bin").join("vdpi");
            if fs::symlink_metadata(&link_path).is_ok_and(|meta| meta.is_symlink()) {
                let _ = fs::remove_file(&link_path);
            }
        }
        if remove_unix_shell_path() {
            println!("Removed ~/.vdpi/bin from shell PATH profile.");
        }
        let _ = fs::remove_file("/run/vdpi/state.json");
        let user_cfg = resolved_user_config_path();
        if let Ok(root) = vdpi_root_dir() {
            cleanup_unix_root_dir(&root, &user_cfg, purge);
        }
        if purge {
            let _ = fs::remove_dir_all("/run/vdpi");
            let sys_cfg = config_file::system_config_path();
            if sys_cfg.is_file() {
                let _ = fs::remove_file(&sys_cfg);
                if let Some(parent) = sys_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            if user_cfg.is_file() {
                let _ = fs::remove_file(&user_cfg);
                if let Some(parent) = user_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{is_elevated, relaunch_elevated_and_wait};

        if !is_elevated() {
            println!(
                "Requesting Administrator privileges to uninstall the vdpi Windows service..."
            );
            let _ = std::env::set_current_dir(std::env::temp_dir());
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            relaunch_elevated_and_wait(&args)?;
            clear_all_system_proxies()?;
            println!(
                "Removed Windows service '{WINDOWS_SERVICE_NAME}' and restored {} system proxy settings.",
                platform_name()
            );
            return Ok(());
        }

        let removed = crate::platform::windows_service::uninstall_windows_service()?;
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();
        if removed {
            println!("Stopped and removed Windows service: {WINDOWS_SERVICE_NAME}");
        } else {
            println!("Windows service '{WINDOWS_SERVICE_NAME}' is not installed.");
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = purge;

    clear_all_system_proxies()?;

    #[cfg(target_os = "windows")]
    cleanup_windows_install_files(purge);

    println!("Restored {} system proxy settings.", platform_name());
    Ok(())
}

/// Temporarily stops the background `vdpi` service and restores system proxies without
/// uninstalling installed files, PATH entries, or service registration.
pub fn pause_service() -> Result<()> {
    pause_service_impl(true)
}

/// Quiet variant of [`pause_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn pause_service_quiet() -> Result<()> {
    pause_service_impl(false)
}

fn pause_service_impl(verbose: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{
            is_elevated, query_windows_service_status, relaunch_elevated_and_wait,
            stop_windows_service_if_running,
        };

        if !query_windows_service_status().installed {
            bail!("vdpi Windows service is not installed.");
        }

        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to pause the vdpi Windows service..."
                );
            }
            relaunch_elevated_and_wait(&["pause".to_string()])?;
            clear_all_system_proxies()?;
            return Ok(());
        }

        let _ = stop_windows_service_if_running()?;
        stop_windows_foreground_daemons();
        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused Windows service '{WINDOWS_SERVICE_NAME}' and restored Windows system proxies."
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["pause".to_string()],
                    "pause the vdpi TUN background service",
                );
            }
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            let plist_str = daemon_path.display().to_string();
            let mut out = Command::new("/bin/launchctl")
                .args(["bootout", &service_target])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl bootout'")?;
            if !out.status.success() && launchctl_service_loaded(&service_target) {
                out = Command::new("/bin/launchctl")
                    .args(["bootout", "system", &plist_str])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute '/bin/launchctl bootout'")?;
            }
            wait_launchctl_unloaded(&service_target);
            if detect_service_state() == ServiceState::Running {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to pause LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to pause LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
            }
            if verbose {
                println!(
                    "Paused LaunchDaemon '{LAUNCH_DAEMON_LABEL}' and restored macOS TUN routing/DNS."
                );
            }
            return Ok(());
        }

        let plist_path = launch_agent_plist_path()?;
        if !plist_path.exists() {
            bail!(
                "vdpi LaunchAgent is not installed ({}).",
                plist_path.display()
            );
        }
        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        let plist_str = plist_path.display().to_string();

        let mut out = Command::new("/bin/launchctl")
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl bootout'")?;

        if !out.status.success() && launchctl_service_loaded(&service_target) {
            out = Command::new("/bin/launchctl")
                .args(["bootout", &domain_target, &plist_str])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl bootout'")?;
        }

        // Wait for launchd asynchronous bootout teardown so the exiting daemon
        // does not race with clear_all_system_proxies().
        wait_launchctl_unloaded(&service_target);

        if detect_service_state() == ServiceState::Running {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to pause LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to pause LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
        }

        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused LaunchAgent '{LAUNCH_AGENT_LABEL}' and restored {} system proxy settings.",
                platform_name()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_unit = systemd_system_unit_path();
        if system_unit.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["pause".to_string()],
                    "pause the vdpi TUN background service",
                );
            }
            let out = Command::new("systemctl")
                .args(["stop", SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute 'systemctl stop'")?;
            let not_loaded_and_stopped =
                out.status.code() == Some(5) && detect_service_state() != ServiceState::Running;
            if !out.status.success() && !not_loaded_and_stopped {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to pause systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to pause systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
            }
            if verbose {
                println!(
                    "Paused systemd system unit '{SYSTEMD_UNIT_NAME}' and restored Linux TUN routing/DNS."
                );
            }
            return Ok(());
        }

        let unit_path = systemd_user_unit_path()?;
        if !unit_path.exists() {
            bail!(
                "vdpi systemd user unit is not installed ({}).",
                unit_path.display()
            );
        }
        let out = linux_user_systemctl_command()
            .args(["stop", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute 'systemctl --user stop'")?;
        let not_loaded_and_stopped =
            out.status.code() == Some(5) && detect_service_state() != ServiceState::Running;
        if !out.status.success() && !not_loaded_and_stopped {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to pause systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to pause systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
        }
        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused systemd user unit '{SYSTEMD_UNIT_NAME}' and restored {} system proxy settings.",
                platform_name()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = verbose;
        bail!(
            "pausing background service is not supported on {}",
            platform_name()
        );
    }
}

/// Starts or restarts a previously installed/paused background `vdpi` service.
pub fn resume_service() -> Result<()> {
    resume_service_impl(true)
}

/// Quiet variant of [`resume_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn resume_service_quiet() -> Result<()> {
    resume_service_impl(false)
}

fn resume_service_impl(verbose: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            is_elevated, query_windows_service_status, relaunch_elevated_and_wait,
            start_windows_service,
        };

        if !query_windows_service_status().installed {
            bail!("vdpi Windows service is not installed. Run 'vdpi install' first.");
        }

        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to resume the vdpi Windows service..."
                );
            }
            relaunch_elevated_and_wait(&["resume".to_string()])?;
            notify_wininet_refresh();
            broadcast_environment_change();
            return Ok(());
        }

        if !start_windows_service()? {
            bail!("vdpi Windows service is not installed. Run 'vdpi install' first.");
        }
        notify_wininet_refresh();
        broadcast_environment_change();
        if verbose {
            println!(
                "Resumed Windows service '{WINDOWS_SERVICE_NAME}' (anti-DPI protection active)."
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["resume".to_string()],
                    "resume the vdpi TUN background service",
                );
            }
            start_macos_launch_daemon(&daemon_path)?;
            if verbose {
                println!(
                    "Resumed LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (TUN anti-DPI protection active)."
                );
            }
            return Ok(());
        }

        let plist_path = launch_agent_plist_path()?;
        if !plist_path.exists() {
            bail!(
                "vdpi LaunchAgent is not installed ({}). Run 'vdpi install' first.",
                plist_path.display()
            );
        }
        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        let plist_str = plist_path.display().to_string();

        let _ = Command::new("/bin/launchctl")
            .args(["enable", &service_target])
            .stdin(Stdio::null())
            .output();

        let boot = Command::new("/bin/launchctl")
            .args(["bootstrap", &domain_target, &plist_str])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl bootstrap'")?;

        if boot.status.success() {
            // `RunAtLoad=true` already spawns the agent; avoid racing a second
            // instance with `kickstart -k` (which collides on proxy-lease.lock).
            let deadline = Instant::now() + Duration::from_millis(1500);
            while detect_service_state() != ServiceState::Running && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if detect_service_state() != ServiceState::Running {
                let kick = Command::new("/bin/launchctl")
                    .args(["kickstart", &service_target])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute '/bin/launchctl kickstart'")?;
                if !kick.status.success() && detect_service_state() != ServiceState::Running {
                    let kick_err = String::from_utf8_lossy(&kick.stderr);
                    let detail = kick_err.trim();
                    if detail.is_empty() {
                        bail!(
                            "failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                            kick.status
                        );
                    }
                    bail!("failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
                }
            }
        } else if launchctl_service_loaded(&service_target) {
            let kick = Command::new("/bin/launchctl")
                .args(["kickstart", "-k", &service_target])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl kickstart'")?;
            if !kick.status.success() {
                let kick_err = String::from_utf8_lossy(&kick.stderr);
                let detail = kick_err.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                        kick.status
                    );
                }
                bail!("failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
            }
        } else {
            let boot_err = String::from_utf8_lossy(&boot.stderr);
            let detail = boot_err.trim();
            if detail.is_empty() {
                bail!(
                    "failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}': bootstrap failed (exit status: {})",
                    boot.status
                );
            }
            bail!("failed to resume LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
        }

        if verbose {
            println!("Resumed LaunchAgent '{LAUNCH_AGENT_LABEL}' (anti-DPI protection active).");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_unit = systemd_system_unit_path();
        if system_unit.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["resume".to_string()],
                    "resume the vdpi TUN background service",
                );
            }
            let _ = Command::new("systemctl")
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            let out = Command::new("systemctl")
                .args(["start", SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute 'systemctl start'")?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to resume systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to resume systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
            }
            if verbose {
                println!(
                    "Resumed systemd system unit '{SYSTEMD_UNIT_NAME}' (TUN anti-DPI protection active)."
                );
            }
            return Ok(());
        }

        let unit_path = systemd_user_unit_path()?;
        if !unit_path.exists() {
            bail!(
                "vdpi systemd user unit is not installed ({}). Run 'vdpi install' first.",
                unit_path.display()
            );
        }
        let _ = linux_user_systemctl_command()
            .args(["daemon-reload"])
            .stdin(Stdio::null())
            .output();
        let out = linux_user_systemctl_command()
            .args(["start", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute 'systemctl --user start'")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to resume systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to resume systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
        }

        // Briefly confirm the unit did not immediately crash into `failed` state.
        let deadline = Instant::now() + Duration::from_millis(400);
        loop {
            if let Ok(state_out) = linux_user_systemctl_command()
                .args(["is-active", SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
            {
                let state = String::from_utf8_lossy(&state_out.stdout);
                if state.trim() == "failed" {
                    bail!(
                        "systemd user unit '{SYSTEMD_UNIT_NAME}' entered failed state immediately after start"
                    );
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if verbose {
            println!(
                "Resumed systemd user unit '{SYSTEMD_UNIT_NAME}' (anti-DPI protection active)."
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = verbose;
        bail!(
            "resuming background service is not supported on {}",
            platform_name()
        );
    }
}

async fn read_capped_health_body(mut resp: reqwest::Response) -> Option<String> {
    let mut buf = Vec::with_capacity(512);
    while buf.len() < MAX_HEALTH_RESPONSE_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_HEALTH_RESPONSE_BYTES - buf.len();
                let take = chunk.len().min(remaining);
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

async fn discover_live_daemon(
    client: &Client,
    cfg: &RuntimeConfig,
) -> (IpAddr, u16, Option<u16>, Option<String>) {
    let states = read_runtime_states();

    for candidate in build_probe_candidates(cfg, &states) {
        let socket = SocketAddr::new(candidate.connect_ip, candidate.port);
        let url = format!("http://{socket}/vdpi-health");
        let Ok(resp) = client.get(url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Some(text) = read_capped_health_body(resp).await else {
            continue;
        };
        if parse_health_json(&text, candidate.addr, candidate.port, candidate.socks_port).is_some()
        {
            return (
                candidate.addr,
                candidate.port,
                candidate.socks_port,
                Some(text),
            );
        }
    }

    (cfg.addr, cfg.port, cfg.socks_port, None)
}

fn format_tun_engine_summary(live: &LiveEngineStatus) -> String {
    let mut base = match (live.tun_interface.as_deref(), live.physical_nic.as_deref()) {
        (Some(iface), Some(nic)) => format!("{iface} via {nic}"),
        (Some(iface), None) => iface.to_string(),
        (None, Some(nic)) => format!("via {nic}"),
        (None, None) => "active".to_string(),
    };
    if let Some(rss_kb) = live.rss_kb {
        base.push_str(" · ");
        base.push_str(&format_rss_label(rss_kb));
    }
    base
}

fn format_proxy_engine_summary(live: &LiveEngineStatus) -> String {
    let mut base = format!("{}:{}", live.addr, live.port);
    if let Some(rss_kb) = live.rss_kb {
        base.push_str(" · ");
        base.push_str(&format_rss_label(rss_kb));
    }
    base
}

/// Prints a comprehensive status overview of `vdpi`, startup service registration, and OS proxies.
pub async fn print_status(cfg: &RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;

    let (active_addr, active_port, active_socks_port, health_body) =
        discover_live_daemon(&client, cfg).await;

    let live_status = health_body
        .as_deref()
        .and_then(|text| parse_health_json(text, active_addr, active_port, active_socks_port));

    let configured_engine = load_configured_engine(cfg.engine);
    let vpn_conflict = if cfg.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_status
            .as_ref()
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_status
                        .as_ref()
                        .and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    println!("=== vdpi status ({}) ===", platform_name());

    if let Some(ref live) = live_status {
        match live.engine {
            EngineMode::Tun => {
                println!(
                    "Engine (TUN)              : {}",
                    format_tun_engine_summary(live)
                );
                println!(
                    "Health Endpoint           : {}:{} -> RUNNING",
                    active_addr, active_port
                );
            }
            EngineMode::Proxy => {
                let daemon_state = match health_body.as_deref() {
                    Some(text) => format!("RUNNING ({})", text.trim()),
                    None => "NOT RESPONDING".to_string(),
                };
                let socks_state = if let Some(sp) = active_socks_port {
                    if let Some(connect_ip) = probe_connect_ip(active_addr) {
                        match tokio::time::timeout(
                            Duration::from_secs(1),
                            tokio::net::TcpStream::connect((connect_ip, sp)),
                        )
                        .await
                        {
                            Ok(Ok(_)) => format!("LISTENING ({}:{})", active_addr, sp),
                            _ => format!("CLOSED ({}:{})", active_addr, sp),
                        }
                    } else {
                        format!("UNREACHABLE ({}:{})", active_addr, sp)
                    }
                } else {
                    "DISABLED (available via primary port auto-detect)".to_string()
                };
                println!(
                    "Engine (Proxy)            : {}",
                    format_proxy_engine_summary(live)
                );
                println!(
                    "Primary HTTP/CONNECT/Auto : {}:{} -> {}",
                    active_addr, active_port, daemon_state
                );
                println!("Dedicated SOCKS5 (TCP/UDP): {}", socks_state);
            }
        }
    } else {
        let engine_tag = match configured_engine {
            EngineMode::Tun => "TUN",
            EngineMode::Proxy => "Proxy",
        };
        println!("Engine ({engine_tag})             : NOT RESPONDING");
        if configured_engine == EngineMode::Proxy {
            println!(
                "Primary HTTP/CONNECT/Auto : {}:{} -> NOT RESPONDING",
                active_addr, active_port
            );
            let socks_state = if let Some(sp) = active_socks_port {
                format!("CLOSED ({}:{})", active_addr, sp)
            } else {
                "DISABLED (available via primary port auto-detect)".to_string()
            };
            println!("Dedicated SOCKS5 (TCP/UDP): {}", socks_state);
        }
    }

    if let Some(ref conflict) = vpn_conflict {
        println!("VPN Conflict              : {conflict}");
    }

    if let Some(ref live) = live_status {
        let mut engine_parts = Vec::new();
        if let Some(mode) = live.mode.as_deref() {
            engine_parts.push(format!("mode={mode}"));
        }
        if let Some(doh) = live.doh {
            engine_parts.push(format!("DoH={}", if doh { "on" } else { "off" }));
        }
        if let Some(block_quic) = live.block_quic {
            engine_parts.push(format!(
                "QUIC={}",
                if block_quic { "blocked" } else { "allowed" }
            ));
        }
        if let Some(stage) = live.isp_stage.as_deref() {
            engine_parts.push(format!("ISP stage={stage}"));
        }
        if !engine_parts.is_empty() {
            println!("Anti-DPI Engine           : {}", engine_parts.join(", "));
        }

        let mut telemetry_parts = Vec::new();
        match (live.active_connections, live.total_connections) {
            (Some(active), Some(total)) => {
                telemetry_parts.push(format!("{active} active / {total} total connections"));
            }
            (Some(active), None) => {
                telemetry_parts.push(format!("{active} active connections"));
            }
            (None, Some(total)) => {
                telemetry_parts.push(format!("{total} total connections"));
            }
            (None, None) => {}
        }
        if let Some(hosts) = live.learned_hosts {
            telemetry_parts.push(format!("{hosts} cached hosts"));
        }
        if let Some(udp) = live.udp_flows_active {
            telemetry_parts.push(format!("{udp} UDP flows"));
        }
        if let Some(quic) = live.quic_blocked {
            telemetry_parts.push(format!("{quic} QUIC blocked"));
        }
        if let Some(dns) = live.dns_queries {
            telemetry_parts.push(format!("{dns} DNS queries"));
        }
        if let Some(rss_kb) = live.rss_kb {
            telemetry_parts.push(format_rss_label(rss_kb));
        }
        if !telemetry_parts.is_empty() {
            println!("Live Telemetry            : {}", telemetry_parts.join(", "));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            let daemon_state =
                if launchctl_service_running(&format!("system/{LAUNCH_DAEMON_LABEL}")) {
                    "running"
                } else {
                    "paused"
                };
            println!(
                "LaunchDaemon plist (TUN)  : {} ({daemon_state})",
                daemon_path.display()
            );
        }
        let plist_path = launch_agent_plist_path()?;
        let agent_state = if !plist_path.exists() {
            "not installed"
        } else if launchctl_service_running(&format!("gui/{}/{LAUNCH_AGENT_LABEL}", current_uid()))
        {
            "running"
        } else {
            "paused"
        };
        println!(
            "LaunchAgent plist         : {} ({agent_state})",
            plist_path.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let sys_unit = systemd_system_unit_path();
        if sys_unit.exists() {
            let sys_state = if systemd_unit_active(false) {
                "running"
            } else {
                "paused"
            };
            println!(
                "systemd system unit (TUN) : {} ({sys_state})",
                sys_unit.display()
            );
        }
        let unit_path = systemd_user_unit_path()?;
        let user_state = if !unit_path.exists() {
            "not installed"
        } else if systemd_unit_active(true) {
            "running"
        } else {
            "paused"
        };
        println!(
            "systemd user unit         : {} ({user_state})",
            unit_path.display()
        );
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;
        use crate::platform::windows_service::query_windows_service_status;

        let svc = query_windows_service_status();
        if svc.installed {
            let pid_suffix = svc.pid.map(|p| format!(", PID {p}")).unwrap_or_default();
            println!(
                "Windows Service ({WINDOWS_SERVICE_NAME})    : {} ({}{})",
                svc.state, svc.start_type, pid_suffix
            );
            if let Some(bin) = svc.binary_path {
                println!("Service Command           : {bin}");
            }
        } else {
            println!("Windows Service ({WINDOWS_SERVICE_NAME})    : NOT INSTALLED");
        }

        if let Some(legacy) = query_reg_sz(WINDOWS_LEGACY_RUN_KEY, "vdpi") {
            println!("Legacy Startup (HKCU Run) : {legacy} (run 'vdpi install' to migrate)");
        }
    }

    print_platform_proxy_status();
    Ok(())
}

async fn query_live_health_snapshot(
    client: &Client,
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
) -> Option<LiveEngineStatus> {
    let connect_ip = probe_connect_ip(addr)?;
    let url = format!("http://{}/vdpi-health", SocketAddr::new(connect_ip, port));
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = read_capped_health_body(resp).await?;
    parse_health_json(&text, addr, port, socks_port)
}

async fn run_tun_udp_dns_check() -> Result<(Vec<IpAddr>, u128)> {
    let query = crate::dns::encode_dns_query("discord.com", 1)?;
    let t0 = Instant::now();
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)))
        .await?;
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await??;
    let (ips, _) = crate::dns::decode_dns_response(&buf[..n], 1)?;
    if ips.is_empty() {
        bail!("UDP DNS response for discord.com contained no A records");
    }
    Ok((ips, t0.elapsed().as_millis()))
}

async fn send_quic_initial_probe() -> Result<()> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let mut pkt = vec![0u8; 1200];
    // RFC 9000 QUIC v1 Initial long header (0xc0 | version=0x00000001 | dcid_len=8 | scid_len=0)
    pkt[0] = 0xc0;
    pkt[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt[5] = 8;
    pkt[6..14].copy_from_slice(b"vdpiprob");
    pkt[14] = 0;
    sock.send_to(&pkt, SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)))
        .await?;
    Ok(())
}

fn check_proxy_drift_for_live_daemon(active_addr: IpAddr, active_port: u16) -> Option<String> {
    let expected_server = format!("{active_addr}:{active_port}");
    let expected_url = format!("http://{expected_server}");

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;

        let inet_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let enabled_raw = query_reg_sz(inet_key, "ProxyEnable").unwrap_or_default();
        let enabled = enabled_raw == "0x1" || enabled_raw == "1";
        let server = query_reg_sz(inet_key, "ProxyServer").unwrap_or_default();
        if enabled && !server.is_empty() && !server.eq_ignore_ascii_case(&expected_server) {
            return Some(format!(
                "WinINET ProxyServer points to '{server}' instead of '{expected_server}'"
            ));
        }

        if let Some(env_https) = query_reg_sz(r"HKCU\Environment", "HTTPS_PROXY") {
            let trimmed = env_https.trim();
            let lower = trimmed.to_ascii_lowercase();
            if (lower.starts_with("http://127.0.0.1:") || lower.starts_with("http://[::1]:"))
                && !trimmed.eq_ignore_ascii_case(&expected_url)
            {
                return Some(format!(
                    "HKCU\\Environment HTTPS_PROXY points to '{trimmed}' instead of '{expected_url}'"
                ));
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(env_https) = crate::platform::macos::read_launchd_env("HTTPS_PROXY") {
            let trimmed = env_https.trim();
            let lower = trimmed.to_ascii_lowercase();
            if (lower.starts_with("http://127.0.0.1:") || lower.starts_with("http://[::1]:"))
                && !trimmed.eq_ignore_ascii_case(&expected_url)
            {
                return Some(format!(
                    "launchd HTTPS_PROXY points to '{trimmed}' instead of '{expected_url}'"
                ));
            }
        }
        if let Ok(statuses) = crate::platform::macos::inspect_service_proxies() {
            for st in statuses {
                if st.secure_enabled
                    && matches!(st.secure_server.as_str(), "127.0.0.1" | "::1")
                    && st.secure_port != active_port.to_string()
                {
                    return Some(format!(
                        "macOS service '{}' HTTPS proxy points to {}:{} instead of {}",
                        st.service, st.secure_server, st.secure_port, expected_server
                    ));
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(out) = linux_user_systemctl_command()
            .args(["show-environment"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if let Some(val) = text.lines().find_map(|l| l.strip_prefix("HTTPS_PROXY=")) {
                    let trimmed = val.trim();
                    let lower = trimmed.to_ascii_lowercase();
                    if (lower.starts_with("http://127.0.0.1:")
                        || lower.starts_with("http://[::1]:"))
                        && !trimmed.eq_ignore_ascii_case(&expected_url)
                    {
                        return Some(format!(
                            "systemd user HTTPS_PROXY points to '{trimmed}' instead of '{expected_url}'"
                        ));
                    }
                }
            }
        }
        let _ = expected_server;
        None
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (expected_server, expected_url);
        None
    }
}

fn detect_stale_browsers_for_env(since_unix_secs: u64) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::detect_stale_browsers(since_unix_secs)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = since_unix_secs;
        Vec::new()
    }
}

/// Runs live end-to-end connectivity checks through `vdpi` (adapting automatically to
/// live TUN vs Proxy daemons, or spawning an ephemeral in-process engine when no daemon
/// is running) against Discord and Roblox endpoints.
pub async fn run_doctor(cfg: RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let direct_check = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(800))
        .build()?;

    let (active_addr, active_port, active_socks_port, live_health) =
        discover_live_daemon(&direct_check, &cfg).await;

    let live_status = live_health
        .as_deref()
        .and_then(|text| parse_health_json(text, active_addr, active_port, active_socks_port));

    // Always run VPN conflict check first (unless vpn_coexistence=off).
    println!("=== VPN Conflict Check ===");
    if cfg.vpn_coexistence == VpnCoexistence::Off {
        println!("  [PASS] VPN Conflict             -> disabled (vpn_coexistence=off)");
    } else {
        let self_tun = live_status
            .as_ref()
            .and_then(|live| live.tun_interface.as_deref());
        match detect_active_vpn(self_tun) {
            VpnScope::None => {
                println!("  [PASS] VPN Conflict             -> none detected");
            }
            VpnScope::SplitOverlay { providers } => {
                println!(
                    "  [PASS] VPN Conflict             -> split-tunnel overlay only ({})",
                    providers.join(", ")
                );
            }
            VpnScope::FullTunnel {
                provider,
                iface,
                kill_switch,
            } => {
                let ks = if kill_switch { " [kill-switch]" } else { "" };
                println!(
                    "  [WARN] VPN Conflict             -> full-tunnel VPN active: {provider} ({iface}){ks}"
                );
            }
        }
    }
    println!();

    #[cfg(target_os = "windows")]
    {
        println!("=== Windows TUN Preflight (Wintun) ===");
        match crate::platform::windows_tun::find_verified_wintun_dll() {
            Ok(path) => {
                println!(
                    "  [PASS] {:24} -> verified ({})",
                    "Wintun DLL",
                    path.display()
                );
            }
            Err(err) => {
                println!("  [WARN] {:24} -> {err}", "Wintun DLL");
            }
        }
        println!();
    }

    let roblox_settings_url = if cfg!(target_os = "windows") {
        "https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer"
    } else {
        "https://clientsettingscdn.roblox.com/v2/client-version/MacPlayer"
    };

    // Branch A: Live TUN daemon checks (direct non-proxied HTTPS + UDP DNS + QUIC drop counter).
    if let Some(live) = live_status
        .as_ref()
        .filter(|live| live.engine == EngineMode::Tun)
    {
        println!(
            "Testing against running vdpi TUN daemon ({})...\n",
            format_tun_engine_summary(live)
        );

        let direct_client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(8))
            .build()?;

        let tun_targets = [
            ("Roblox ClientSettings", roblox_settings_url),
            ("Discord Web", "https://discord.com"),
            ("Discord Gateway", "https://gateway.discord.gg"),
            ("Roblox Web", "https://www.roblox.com"),
        ];

        let mut passed = 0usize;
        println!("=== Direct HTTPS via TUN Checks ===");
        for (label, url) in tun_targets {
            let t0 = Instant::now();
            match direct_client.get(url).send().await {
                Ok(resp) => {
                    let ms = t0.elapsed().as_millis();
                    println!(
                        "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                        label,
                        resp.status().as_u16(),
                        ms
                    );
                    passed += 1;
                }
                Err(e) => {
                    println!("  [FAIL] {:24} -> {}", label, e);
                }
            }
        }

        println!("\n=== TUN UDP DNS & QUIC Checks ===");
        let dns_ok = match run_tun_udp_dns_check().await {
            Ok((ips, ms)) => {
                println!(
                    "  [PASS] {:24} -> resolved {} IP(s) ({:4} ms)",
                    "UDP DNS (discord.com)",
                    ips.len(),
                    ms
                );
                true
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", "UDP DNS (discord.com)", e);
                false
            }
        };

        let block_quic = live.block_quic.unwrap_or(true);
        if !block_quic {
            println!(
                "  [PASS] {:24} -> QUIC blocking disabled (--allow-quic)",
                "QUIC Drop Counter"
            );
        } else {
            let quic_before = live.quic_blocked.unwrap_or(0);
            if let Err(e) = send_quic_initial_probe().await {
                println!(
                    "  [WARN] {:24} -> failed to send QUIC probe: {}",
                    "QUIC Drop Counter", e
                );
            } else {
                tokio::time::sleep(Duration::from_millis(150)).await;
                let quic_after = query_live_health_snapshot(
                    &direct_check,
                    active_addr,
                    active_port,
                    active_socks_port,
                )
                .await
                .and_then(|snap| snap.quic_blocked)
                .unwrap_or(quic_before);
                if quic_after > quic_before {
                    println!(
                        "  [PASS] {:24} -> incremented ({quic_before} -> {quic_after})",
                        "QUIC Drop Counter"
                    );
                } else {
                    println!(
                        "  [WARN] {:24} -> counter unchanged ({quic_before} -> {quic_after})",
                        "QUIC Drop Counter"
                    );
                }
            }
        }

        if passed != tun_targets.len() || !dns_ok {
            bail!(
                "doctor detected TUN failures ({}/{} HTTPS passed, udp_dns_ok={})",
                passed,
                tun_targets.len(),
                dns_ok
            );
        }

        println!("\nAll TUN direct HTTPS, UDP DNS, and QUIC checks passed.");
        return Ok(());
    }

    // Branch B: Live Proxy daemon (or ephemeral in-process proxy engine).
    let testing_live_proxy = live_health.is_some();
    let (http_proxy_addr, socks_proxy_addr, _guard_tx) = if testing_live_proxy {
        let connect_ip = probe_connect_ip(active_addr).unwrap_or(active_addr);
        let hp = SocketAddr::new(connect_ip, active_port);
        let sp = SocketAddr::new(connect_ip, active_socks_port.unwrap_or(active_port));
        println!("Testing against running vdpi daemon at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, None)
    } else {
        let mut ephemeral_cfg = cfg.clone();
        ephemeral_cfg.port = 0;
        ephemeral_cfg.socks_port = Some(0);
        ephemeral_cfg.system_proxy = false;
        let ctx = EngineContext::new(ephemeral_cfg)?;
        let bound = crate::server::bind_listeners(&ctx)?;
        let hp_ip = probe_connect_ip(bound.primary_addr.ip()).unwrap_or(bound.primary_addr.ip());
        let hp = SocketAddr::new(hp_ip, bound.primary_addr.port());
        let sp = bound.socks_addr.map_or(hp, |a| {
            SocketAddr::new(probe_connect_ip(a.ip()).unwrap_or(a.ip()), a.port())
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = crate::server::serve_until_shutdown(bound, ctx, rx).await;
        });
        println!("Testing with ephemeral in-process vdpi engine at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, Some(tx))
    };

    let http_client = Client::builder()
        .proxy(Proxy::all(format!("http://{http_proxy_addr}"))?)
        .timeout(Duration::from_secs(8))
        .build()?;

    let discord_updater_url = if cfg!(target_os = "windows") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"
    } else if cfg!(target_os = "linux") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=linux&arch=x64"
    } else if cfg!(target_arch = "aarch64") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=arm64"
    } else {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=x64"
    };

    let targets = [
        ("Discord Web", "https://discord.com"),
        ("Discord Updater", discord_updater_url),
        ("Discord Gateway", "https://gateway.discord.gg"),
        ("Discord CDN", "https://cdn.discordapp.com"),
        ("Discord Voice Latency", "https://latency.discord.media"),
        ("Roblox Web", "https://www.roblox.com"),
        ("Roblox ClientSettings", roblox_settings_url),
        ("Roblox APIs", "https://apis.roblox.com"),
        ("Roblox Auth", "https://auth.roblox.com"),
        ("Roblox GameJoin", "https://gamejoin.roblox.com"),
        ("Roblox Telemetry", "https://ecsv2.roblox.com"),
    ];

    let mut passed = 0usize;
    println!("=== HTTP/HTTPS CONNECT Tunnel Checks ===");
    for (label, url) in targets {
        let t0 = Instant::now();
        match http_client.get(url).send().await {
            Ok(resp) => {
                let ms = t0.elapsed().as_millis();
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    ms
                );
                passed += 1;
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
            }
        }
    }

    println!("\n=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===");
    let socks_client = Client::builder()
        .proxy(Proxy::all(format!("socks5h://{socks_proxy_addr}"))?)
        .timeout(Duration::from_secs(8))
        .build()?;

    let mut socks_ok = true;
    for (label, url) in [
        ("SOCKS5 Discord", "https://discord.com"),
        ("SOCKS5 Discord Gateway", "https://gateway.discord.gg"),
        ("SOCKS5 Roblox Web", "https://www.roblox.com"),
        ("SOCKS5 Roblox APIs", "https://apis.roblox.com"),
    ] {
        let t0 = Instant::now();
        match socks_client.get(url).send().await {
            Ok(resp) => {
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    t0.elapsed().as_millis()
                );
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
                socks_ok = false;
            }
        }
    }

    if testing_live_proxy {
        println!("\n=== Proxy Session & Browser Checks ===");
        let env_activated_at = read_runtime_states()
            .into_iter()
            .find(|s| s.port == active_port)
            .and_then(|s| s.env_activated_at);
        if !cfg.system_proxy || !cfg.env_proxy {
            println!(
                "  [PASS] {:24} -> skipped (env proxy disabled)",
                "Stale Browsers"
            );
        } else if let Some(activated_at) = env_activated_at {
            let stale_browsers = detect_stale_browsers_for_env(activated_at);
            if stale_browsers.is_empty() {
                println!("  [PASS] {:24} -> none detected", "Stale Browsers");
            } else {
                println!(
                    "  [WARN] {:24} -> {} started before proxy env activation (restart browser or run 'vdpi engine tun')",
                    "Stale Browsers",
                    stale_browsers.join(", ")
                );
            }
        } else {
            println!(
                "  [PASS] {:24} -> skipped (proxy env not activated)",
                "Stale Browsers"
            );
        }

        if let Some(drift) = check_proxy_drift_for_live_daemon(active_addr, active_port) {
            println!("  [WARN] {:24} -> {drift}", "System Proxy Drift");
        } else {
            println!(
                "  [PASS] {:24} -> aligned with {active_addr}:{active_port}",
                "System Proxy Drift"
            );
        }
    }

    if passed != targets.len() || !socks_ok {
        bail!(
            "doctor detected failures ({}/{} HTTP passed, socks5_ok={})",
            passed,
            targets.len(),
            socks_ok
        );
    }

    println!("\nAll Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn launchctl_service_running(service_target: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", service_target])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.trim() == "state = running")
        })
}

#[cfg(target_os = "macos")]
fn launchctl_service_loaded(service_target: &str) -> bool {
    Command::new("/bin/launchctl")
        .args(["print", service_target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(target_os = "linux")]
fn systemd_unit_active(user: bool) -> bool {
    let mut cmd = if user {
        linux_user_systemctl_command()
    } else {
        Command::new("systemctl")
    };
    cmd.args(["is-active", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            output.status.success() || stdout.trim() == "active"
        })
}

#[cfg(target_os = "macos")]
fn current_uid() -> u32 {
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        return sudo_user.uid;
    }
    unsafe { libc::getuid() }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn is_unix_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn relaunch_unix_sudo_and_wait(args: &[String], action_description: &str) -> Result<()> {
    use std::io::IsTerminal;

    let cmd_hint = args.join(" ");
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("Root required - run: sudo vdpi {cmd_hint}");
    }

    let exe = std::env::current_exe().context("failed to determine current executable")?;
    let sudo_bin = ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or("sudo");

    println!("\nAdministrator privileges required to {action_description}.");
    println!("Enter your password (or Touch ID) if prompted by sudo...");

    let status = Command::new(sudo_bin)
        .arg("--")
        .arg(exe)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Root required - run: sudo vdpi {cmd_hint}"))?;

    if !status.success() {
        let code = status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        bail!("sudo canceled or failed (exit {code}) - try: sudo vdpi {cmd_hint}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;

    #[test]
    fn generates_valid_service_manifests_for_all_platforms() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--chunk-size", "10"]).unwrap();
        let cfg = cli.into_runtime_config();

        let plist = generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &cfg);
        assert!(plist.contains("<string>com.vdpi</string>"));
        assert!(plist.contains("<string>--proxy</string>"));
        assert!(!plist.contains("<string>--tun</string>"));
        assert!(plist.contains("<string>--chunk-size</string>"));
        assert!(plist.contains("<string>10</string>"));
        assert!(plist.contains("<string>--socks-port</string>"));
        assert!(plist.contains("<string>1080</string>"));

        let unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &cfg);
        assert!(unit.contains("ExecStart=\"/home/test/.vdpi/bin/vdpi\" \"--proxy\""));
        assert!(!unit.contains("\"--tun\""));
        assert!(unit.contains("LimitNOFILE=65536"));

        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.starts_with(r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --proxy "#));
        assert!(win_bin.contains("--bind 127.0.0.1"));
        assert!(win_bin.contains("--port 8080"));
        assert!(win_bin.contains("--chunk-size 10"));
        assert!(win_bin.contains("--socks-port 1080"));
        assert!(win_bin.contains("--quiet"));

        // Passing a TUN config to proxy-only generators must still force --proxy.
        let mut tun_cfg = cfg;
        tun_cfg.engine = EngineMode::Tun;
        let forced_plist =
            generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &tun_cfg);
        assert!(forced_plist.contains("<string>--proxy</string>"));
        assert!(!forced_plist.contains("<string>--tun</string>"));

        let forced_unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &tun_cfg);
        assert!(forced_unit.contains("\"--proxy\""));
        assert!(!forced_unit.contains("\"--tun\""));
    }

    #[test]
    fn preserves_custom_flags_in_windows_service_bin_path() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--mode",
            "tls-record",
            "--dns",
            "8.8.8.8",
            "--bypass",
            "*.example.com",
            "--no-env-proxy",
        ])
        .unwrap();
        let cfg = cli.into_runtime_config();
        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.contains("--service"));
        assert!(win_bin.contains("--mode tls-record"));
        assert!(win_bin.contains("--dns 8.8.8.8"));
        assert!(win_bin.contains("--bypass *.example.com"));
        assert!(win_bin.contains("--no-env-proxy"));
    }

    #[test]
    fn parses_version_from_cli_output() {
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.3\n").as_deref(),
            Some("0.3.3")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.4\r\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi v1.2.3\n").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            parse_version_from_cli_output("0.3.4\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(parse_version_from_cli_output(""), None);
        assert_eq!(parse_version_from_cli_output("   \r\n"), None);
        assert_eq!(parse_version_from_cli_output("garbage output\n"), None);
        assert_eq!(parse_version_from_cli_output("vdpi not-a-version\n"), None);
    }

    #[test]
    fn quotes_windows_args_with_backslashes_and_quotes() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg(""), r#""""#);
        assert_eq!(quote_windows_arg("a b"), r#""a b""#);
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\vdpi\"),
            r#""C:\Program Files\vdpi\\""#
        );
        assert_eq!(quote_windows_arg(r#"a\\""#), r#""a\\\\\"""#);
    }

    #[test]
    fn escapes_systemd_unit_execstart_arguments() {
        let mut cli = CliArgs::parse_from_iter(["vdpi"]).unwrap();
        cli.bypass_domains = vec![
            "evil\nExecStartPost=/bin/sh".to_string(),
            r#"100%"a\b$HOME"#.to_string(),
        ];
        let cfg = cli.into_runtime_config();
        let unit = generate_systemd_unit(Path::new("/home/u%1/$bin/my \"dir\"\\vdpi"), &cfg);

        assert!(!unit.contains("\nExecStartPost="));
        assert!(unit.contains(r#"ExecStart="/home/u%%1/$$bin/my \"dir\"\\vdpi""#));
        assert!(unit.contains(r#""100%%\"a\\b$$HOME""#));
    }

    #[test]
    fn parses_enriched_v0_4_2_health_json() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.4.2",
            "mode": "combo",
            "doh": true,
            "block_quic": true,
            "active_connections": 7,
            "total_connections": 420,
            "learned_hosts": 19,
            "isp_stage": "stage-1"
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, 8080, Some(1080))
            .expect("enriched health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: 8080,
                socks_port: Some(1080),
                engine: EngineMode::Proxy,
                tun_interface: None,
                physical_nic: None,
                vpn_conflict: None,
                version: Some("0.4.2".to_string()),
                mode: Some("combo".to_string()),
                doh: Some(true),
                block_quic: Some(true),
                active_connections: Some(7),
                total_connections: Some(420),
                learned_hosts: Some(19),
                isp_stage: Some("stage-1".to_string()),
                udp_flows_active: None,
                quic_blocked: None,
                dns_queries: None,
                rss_kb: None,
            }
        );
    }

    #[test]
    fn parses_legacy_minimal_v0_4_0_health_json() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let legacy = "{\"status\":\"ok\",\"service\":\"vdpi\",\"version\":\"0.4.0\"}\n";
        let parsed = parse_health_json(legacy, addr, 8080, None)
            .expect("legacy minimal health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: 8080,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                physical_nic: None,
                vpn_conflict: None,
                version: Some("0.4.0".to_string()),
                mode: None,
                doh: None,
                block_quic: None,
                active_connections: None,
                total_connections: None,
                learned_hosts: None,
                isp_stage: None,
                udp_flows_active: None,
                quic_blocked: None,
                dns_queries: None,
                rss_kb: None,
            }
        );

        let service_only = r#"{"service":"vdpi"}"#;
        let parsed_service_only = parse_health_json(service_only, addr, 8080, Some(1080))
            .expect("service=vdpi payload without status should parse");
        assert_eq!(parsed_service_only.engine, EngineMode::Proxy);
        assert_eq!(parsed_service_only.version, None);
        assert_eq!(parsed_service_only.socks_port, Some(1080));
    }

    #[test]
    fn parses_v0_5_0_tun_health_json() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.5.0",
            "mode": "combo",
            "doh": true,
            "block_quic": true,
            "active_connections": 12,
            "total_connections": 900,
            "learned_hosts": 24,
            "isp_stage": "stage-2",
            "engine": "tun",
            "tun_interface": "vdpi0",
            "physical_nic": "Ethernet",
            "vpn_conflict": "Mullvad (wg0)",
            "udp_flows_active": 18,
            "quic_blocked": 55,
            "dns_queries": 310,
            "rss_kb": 16384
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, DEFAULT_TUN_HEALTH_PORT, None)
            .expect("v0.5.0 TUN health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: DEFAULT_TUN_HEALTH_PORT,
                socks_port: None,
                engine: EngineMode::Tun,
                tun_interface: Some("vdpi0".to_string()),
                physical_nic: Some("Ethernet".to_string()),
                vpn_conflict: Some("Mullvad (wg0)".to_string()),
                version: Some("0.5.0".to_string()),
                mode: Some("combo".to_string()),
                doh: Some(true),
                block_quic: Some(true),
                active_connections: Some(12),
                total_connections: Some(900),
                learned_hosts: Some(24),
                isp_stage: Some("stage-2".to_string()),
                udp_flows_active: Some(18),
                quic_blocked: Some(55),
                dns_queries: Some(310),
                rss_kb: Some(16384),
            }
        );
        assert_eq!(
            format_tun_engine_summary(&parsed),
            "vdpi0 via Ethernet · 16 MB RSS"
        );
    }

    #[test]
    fn parses_v0_5_0_proxy_health_json_and_ignores_blank_optional_strings() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.5.0",
            "engine": "proxy",
            "tun_interface": null,
            "physical_nic": "",
            "vpn_conflict": "   ",
            "udp_flows_active": 0,
            "quic_blocked": 3,
            "dns_queries": 44,
            "rss_kb": 9216
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, 8080, Some(1080))
            .expect("v0.5.0 Proxy health payload should parse");
        assert_eq!(parsed.engine, EngineMode::Proxy);
        assert_eq!(parsed.tun_interface, None);
        assert_eq!(parsed.physical_nic, None);
        assert_eq!(parsed.vpn_conflict, None);
        assert_eq!(parsed.udp_flows_active, Some(0));
        assert_eq!(parsed.quic_blocked, Some(3));
        assert_eq!(parsed.dns_queries, Some(44));
        assert_eq!(parsed.rss_kb, Some(9216));
    }

    #[test]
    fn runtime_state_deserializes_legacy_v0_4_json_with_defaults() {
        let legacy = r#"{"pid":1234,"addr":"127.0.0.1","port":8080,"socks_port":1080}"#;
        let parsed: RuntimeState =
            serde_json::from_str(legacy).expect("legacy RuntimeState JSON should deserialize");
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.socks_port, Some(1080));
        assert_eq!(parsed.engine, EngineMode::Proxy);
        assert_eq!(parsed.tun_interface, None);
        assert_eq!(parsed.env_activated_at, None);
    }

    #[test]
    fn generates_valid_tun_system_service_manifests() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--tun", "--tun-ipv6"]).unwrap();
        let cfg = cli.into_runtime_config();

        let daemon_plist = generate_launch_daemon_plist(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
        assert!(daemon_plist.contains("<string>com.vdpi.daemon</string>"));
        assert!(daemon_plist.contains("<string>/usr/local/bin/vdpi</string>"));
        assert!(daemon_plist.contains("<string>--tun</string>"));
        assert!(daemon_plist.contains("<string>--tun-ipv6</string>"));
        assert!(daemon_plist.contains("<key>AbandonProcessGroup</key>\n    <true/>"));

        let sys_unit = generate_systemd_system_unit(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
        assert!(sys_unit.contains(
            "After=network-online.target systemd-resolved.service NetworkManager.service"
        ));
        assert!(sys_unit.contains("StartLimitIntervalSec=60"));
        assert!(sys_unit.contains("StartLimitBurst=5"));
        assert!(sys_unit.contains("ExecStart=\"/usr/local/bin/vdpi\" \"--tun\""));
        assert!(!sys_unit.contains("AmbientCapabilities="));
        assert!(!sys_unit.contains("CapabilityBoundingSet="));
        assert!(
            sys_unit.contains("ExecStopPost=+\"/usr/local/bin/vdpi\" --internal-linux-tun-cleanup")
        );
        assert!(sys_unit.contains("WantedBy=multi-user.target"));

        let custom_sys_unit =
            generate_systemd_system_unit(Path::new("/opt/my $vdpi/bin/vdpi"), &cfg);
        assert!(custom_sys_unit
            .contains("ExecStopPost=+\"/opt/my $$vdpi/bin/vdpi\" --internal-linux-tun-cleanup"));
    }

    #[test]
    fn migrates_legacy_v0_4_windows_service_cmdline_to_proxy_file_config() {
        let legacy_cmd = r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --bind 127.0.0.1 --port 8088 --chunk-size 6 --socks-port 1088 --mode tls-record --dns 8.8.8.8 --bypass *.example.com --no-env-proxy --allow-quic --quiet"#;
        let migrated = migrate_legacy_service_cmdline_to_file_config(legacy_cmd);
        assert_eq!(migrated.schema_version, Some(CONFIG_SCHEMA_VERSION));
        assert_eq!(migrated.engine, Some(EngineMode::Proxy));
        assert_eq!(migrated.bind, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(migrated.port, Some(8088));
        assert_eq!(migrated.chunk_size, Some(6));
        assert_eq!(migrated.socks_port, Some(1088));
        assert_eq!(migrated.mode, Some(DesyncMode::TlsRecord));
        assert_eq!(migrated.dns_addr.as_deref(), Some("8.8.8.8"));
        assert_eq!(
            migrated.bypass_domains,
            Some(vec!["*.example.com".to_string()])
        );
        assert_eq!(migrated.env_proxy, Some(false));
        assert_eq!(migrated.block_quic, Some(false));
    }

    #[test]
    fn formats_vpn_conflict_and_rss_labels_cleanly() {
        assert_eq!(format_vpn_scope_conflict(&VpnScope::None), None);
        assert_eq!(
            format_vpn_scope_conflict(&VpnScope::SplitOverlay {
                providers: vec!["Tailscale".to_string()],
            }),
            None
        );
        assert_eq!(
            format_vpn_scope_conflict(&VpnScope::FullTunnel {
                provider: "Mullvad".to_string(),
                iface: "wg0".to_string(),
                kill_switch: true,
            })
            .as_deref(),
            Some("Mullvad (wg0) [kill-switch]")
        );
        assert_eq!(format_rss_label(16384), "16 MB RSS");
        assert_eq!(format_rss_label(512), "512 KB RSS");
    }

    #[test]
    fn rejects_invalid_health_json() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(parse_health_json("", addr, 8080, None), None);
        assert_eq!(parse_health_json("   \r\n", addr, 8080, None), None);
        assert_eq!(
            parse_health_json("<html>200 OK</html>", addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok""#, addr, 8080, None),
            None
        );
        assert_eq!(parse_health_json(r#"["ok"]"#, addr, 8080, None), None);
        assert_eq!(
            parse_health_json(r#"{"hello":"world"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok","service":"other"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"error","service":"vdpi"}"#, addr, 8080, None),
            None
        );
    }

    #[test]
    fn probe_connect_ip_normalizes_wildcards_and_rejects_remote() {
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1))),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0))),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808
            ))),
            None
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None
        );
    }

    #[test]
    fn build_probe_candidates_deduplicates_canonical_endpoints() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        cfg.addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        cfg.port = 8080;
        cfg.socks_port = Some(1080);

        let states = vec![
            RuntimeState {
                pid: 1,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8080,
                socks_port: Some(1081),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 2,
                addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)),
                port: 8080,
                socks_port: Some(1082),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 3,
                addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 8081,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 4,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8081,
                socks_port: Some(1085),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
        ];

        let candidates = build_probe_candidates(&cfg, &states);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[0].port, 8080);
        assert_eq!(candidates[0].socks_port, Some(1081));
        assert_eq!(candidates[1].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[1].port, 8081);
        assert_eq!(candidates[1].socks_port, Some(1085));
        assert_eq!(candidates[2].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[2].port, DEFAULT_TUN_HEALTH_PORT);
        assert_eq!(candidates[2].socks_port, None);

        // Deduplicates DEFAULT_TUN_HEALTH_PORT when already present in RuntimeState.
        let mut with_tun = states;
        with_tun.push(RuntimeState {
            pid: 5,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_TUN_HEALTH_PORT,
            socks_port: None,
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            env_activated_at: None,
        });
        let deduped = build_probe_candidates(&cfg, &with_tun);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[2].port, DEFAULT_TUN_HEALTH_PORT);
    }

    #[test]
    fn strips_exact_unix_shell_path_export_line() {
        let content = format!("export FOO=1\n{UNIX_SHELL_PATH_EXPORT}\nexport BAR=2\n");
        assert_eq!(
            strip_unix_shell_path_line(&content).as_deref(),
            Some("export FOO=1\nexport BAR=2\n")
        );

        let only_export = format!("{UNIX_SHELL_PATH_EXPORT}\n");
        assert_eq!(
            strip_unix_shell_path_line(&only_export).as_deref(),
            Some("")
        );

        let custom = format!("{UNIX_SHELL_PATH_EXPORT} # custom\n");
        assert_eq!(strip_unix_shell_path_line(&custom), None);
        assert_eq!(strip_unix_shell_path_line("export FOO=1\n"), None);
    }

    #[test]
    fn probe_local_health_accepts_200_and_rejects_non_200() {
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();

        let body = r#"{"status":"ok","service":"vdpi","version":"0.4.2","mode":"combo","doh":true,"block_quic":true,"active_connections":3,"total_connections":42,"learned_hosts":5,"isp_stage":"stage-1"}"#;
        let responses = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
            format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
        ];

        let server = std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept probe connection");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut req_buf = [0u8; 512];
                let _ = stream.read(&mut req_buf);
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP response");
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Write);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let ok_11 = probe_local_health(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Some(1080), deadline)
            .expect("HTTP/1.1 200 response should succeed");
        assert_eq!(ok_11.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(ok_11.port, port);
        assert_eq!(ok_11.socks_port, Some(1080));
        assert_eq!(ok_11.version.as_deref(), Some("0.4.2"));
        assert_eq!(ok_11.mode.as_deref(), Some("combo"));
        assert_eq!(ok_11.doh, Some(true));
        assert_eq!(ok_11.block_quic, Some(true));
        assert_eq!(ok_11.active_connections, Some(3));
        assert_eq!(ok_11.total_connections, Some(42));
        assert_eq!(ok_11.learned_hosts, Some(5));
        assert_eq!(ok_11.isp_stage.as_deref(), Some("stage-1"));

        let ok_10_wildcard =
            probe_local_health(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, None, deadline)
                .expect("HTTP/1.0 200 via 0.0.0.0 wildcard should normalize to 127.0.0.1");
        assert_eq!(ok_10_wildcard.version.as_deref(), Some("0.4.2"));

        let rejected_404 =
            probe_local_health(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Some(1080), deadline);
        assert_eq!(rejected_404, None);

        server.join().expect("server thread should finish cleanly");
    }

    #[test]
    fn apply_file_config_to_runtime_enforces_invariants_unconditionally() {
        let base = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        assert_eq!(base.socks_port, Some(1080));
        assert!(base.system_proxy);
        assert!(base.socks_system_proxy);
        assert!(base.env_proxy);

        // Port colliding with existing socks_port must clear socks_port and socks_system_proxy.
        let collided = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                port: Some(1080),
                ..Default::default()
            },
        );
        assert_eq!(collided.port, 1080);
        assert_eq!(collided.socks_port, None);
        assert!(!collided.socks_system_proxy);

        // Disabling system_proxy must clear socks_system_proxy and env_proxy even if omitted.
        let no_sys = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                system_proxy: Some(false),
                ..Default::default()
            },
        );
        assert!(!no_sys.system_proxy);
        assert!(!no_sys.socks_system_proxy);
        assert!(!no_sys.env_proxy);

        // Disabling socks_port must clear socks_system_proxy even if omitted.
        let no_socks = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                socks_port: Some(0),
                ..Default::default()
            },
        );
        assert_eq!(no_socks.socks_port, None);
        assert!(!no_socks.socks_system_proxy);
    }

    #[test]
    fn cleanup_unix_root_dir_preserves_user_config_without_purge() {
        let unique = format!(
            "vdpi-cleanup-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let bin_dir = root.join("bin");
        let logs_dir = root.join("logs");
        let state_file = root.join("state.json");
        let user_cfg = root.join("config.toml");

        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::create_dir_all(&logs_dir).expect("create logs dir");
        fs::write(bin_dir.join("vdpi"), b"bin").expect("write fake bin");
        fs::write(logs_dir.join("vdpi.out.log"), b"log").expect("write fake log");
        fs::write(&state_file, b"{}").expect("write fake state");
        fs::write(&user_cfg, b"engine = \"proxy\"\n").expect("write fake config");

        cleanup_unix_root_dir(&root, &user_cfg, false);
        assert!(!bin_dir.exists());
        assert!(!logs_dir.exists());
        assert!(!state_file.exists());
        assert!(user_cfg.is_file());
        assert!(root.is_dir());

        cleanup_unix_root_dir(&root, &user_cfg, true);
        assert!(!user_cfg.exists());
        assert!(!root.exists());
    }

    #[test]
    fn parse_nonzero_sudo_uid_rejects_zero_and_invalid_values() {
        use std::ffi::OsStr;

        assert_eq!(parse_nonzero_sudo_uid(None), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new(""))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("0"))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("not-a-uid"))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("501"))), Some(501));
        assert_eq!(
            parse_nonzero_sudo_uid(Some(OsStr::new(" 1000 "))),
            Some(1000)
        );
    }
}
