use crate::bypass::build_no_proxy_value_with_includes;
use anyhow::{bail, Context, Result};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

pub const PAC_PATH: &str = "/vdpi.pac";

const TRUSTED_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/run/current-system/sw/bin",
];

const SANITIZED_SYSTEM_PATH: &str =
    "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/run/current-system/sw/bin";

fn normalize_proxy_addr(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

fn format_proxy_url(addr: IpAddr, port: u16) -> String {
    match normalize_proxy_addr(addr) {
        IpAddr::V4(v4) => format!("http://{v4}:{port}"),
        IpAddr::V6(v6) => format!("http://[{v6}]:{port}"),
    }
}

pub fn format_pac_url(addr: IpAddr, port: u16) -> String {
    format!("{}{PAC_PATH}", format_proxy_url(addr, port))
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn is_loopback_authority(authority: &str) -> bool {
    let authority = authority.trim();
    if authority.is_empty() {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return false;
        };
        if !after.is_empty() {
            let Some(port) = after.strip_prefix(':') else {
                return false;
            };
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        return host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    }
    let host = match authority.split_once(':') {
        Some((h, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            h
        }
        None => authority,
    };
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub fn is_vdpi_pac_url(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, path_and_query)) = rest.split_once('/') else {
        return false;
    };
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    path == "vdpi.pac" && is_loopback_authority(authority)
}

fn is_loopback_kde_proxy_value(val: &str) -> bool {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return false;
    }
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let host_and_opt_port = without_scheme
        .split([' ', '\t', '/'])
        .next()
        .unwrap_or("")
        .trim();
    if host_and_opt_port.is_empty() {
        return false;
    }
    is_loopback_authority(host_and_opt_port) || is_loopback_host(host_and_opt_port)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    uid: u32,
    gid: u32,
    name: String,
    home: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SudoUserContext {
    uid: u32,
    gid: u32,
    username: Option<String>,
    home: PathBuf,
    xdg_config_home: PathBuf,
    xdg_runtime_dir: PathBuf,
    dbus_session_bus_address: String,
}

#[derive(Default)]
struct ElevationEnv {
    sudo_uid: Option<String>,
    sudo_gid: Option<String>,
    sudo_user: Option<String>,
    pkexec_uid: Option<String>,
    doas_user: Option<String>,
    home: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    dbus_session_bus_address: Option<String>,
}

/// # Safety
/// `pwd` must have been initialized by a successful `getpwuid_r` / `getpwnam_r` call whose
/// backing buffer is still alive.
unsafe fn passwd_entry_from_raw(pwd: &libc::passwd) -> Option<PasswdEntry> {
    if pwd.pw_dir.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: Caller guarantees `pw_dir` and `pw_name` are valid NUL-terminated C strings.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    let name_bytes = unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes();
    if dir_bytes.is_empty() || name_bytes.is_empty() {
        return None;
    }
    let home = PathBuf::from(OsStr::from_bytes(dir_bytes));
    let name = std::str::from_utf8(name_bytes).ok()?.to_owned();
    Some(PasswdEntry {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        name,
        home,
    })
}

fn lookup_passwd_by_uid(uid: u32) -> Option<PasswdEntry> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16_384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`, `buf`, and `result` are valid pointers with matching buffer length.
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
    // SAFETY: `getpwuid_r` succeeded and populated `pwd` with valid NUL-terminated pointers into `buf`.
    let pwd = unsafe { pwd.assume_init() };
    // SAFETY: `buf` is still alive while extracting `PasswdEntry`.
    unsafe { passwd_entry_from_raw(&pwd) }
}

fn lookup_passwd_by_name(name: &str) -> Option<PasswdEntry> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.contains('/') {
        return None;
    }
    let c_name = CString::new(trimmed).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16_384];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `c_name`, `pwd`, `buf`, and `result` are valid pointers with matching buffer length.
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
    // SAFETY: `getpwnam_r` succeeded and populated `pwd` with valid NUL-terminated pointers into `buf`.
    let pwd = unsafe { pwd.assume_init() };
    // SAFETY: `buf` is still alive while extracting `PasswdEntry`.
    unsafe { passwd_entry_from_raw(&pwd) }
}

fn is_valid_dbus_session_address(addr: &str, uid: u32) -> bool {
    let trimmed = addr.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
        return false;
    }
    let mut any_entry = false;
    for entry in trimmed.split(';') {
        let Some(rest) = entry.strip_prefix("unix:") else {
            return false;
        };
        if rest.is_empty() {
            return false;
        }
        let mut has_transport_target = false;
        for part in rest.split(',') {
            if let Some(path) = part.strip_prefix("path=") {
                if path.is_empty() || !path.starts_with('/') {
                    return false;
                }
                if path == "/root" || path.starts_with("/root/") {
                    return false;
                }
                if let Some(after_run_user) = path.strip_prefix("/run/user/") {
                    let expected_prefix = format!("{uid}/");
                    if !after_run_user.starts_with(&expected_prefix) {
                        return false;
                    }
                }
                has_transport_target = true;
            } else if let Some(abs) = part.strip_prefix("abstract=") {
                if abs.is_empty() {
                    return false;
                }
                has_transport_target = true;
            } else if let Some(dir) = part.strip_prefix("dir=") {
                if dir.is_empty() || !dir.starts_with('/') {
                    return false;
                }
                if dir == "/root" || dir.starts_with("/root/") {
                    return false;
                }
                has_transport_target = true;
            } else if part == "runtime=yes" {
                has_transport_target = true;
            }
        }
        if !has_transport_target {
            return false;
        }
        any_entry = true;
    }
    any_entry
}

fn sanitize_username(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|u| !u.is_empty() && !u.contains('/') && !u.contains('\0') && *u != "root")
        .map(str::to_owned)
}

fn parse_non_root_id(raw: Option<&str>) -> Option<u32> {
    raw.and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&id| id > 0)
}

fn build_sudo_user_context(
    uid: u32,
    gid: u32,
    username: Option<String>,
    home: PathBuf,
    inherited_xdg_config: Option<&Path>,
    inherited_dbus_address: Option<&str>,
) -> SudoUserContext {
    let xdg_config_home = inherited_xdg_config
        .filter(|dir| {
            !dir.as_os_str().is_empty()
                && !home.as_os_str().is_empty()
                && dir.starts_with(&home)
                && !dir
                    .components()
                    .any(|comp| matches!(comp, Component::ParentDir))
        })
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".config"));
    let xdg_runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    let dbus_session_bus_address = inherited_dbus_address
        .map(str::trim)
        .filter(|addr| is_valid_dbus_session_address(addr, uid))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("unix:path=/run/user/{uid}/bus"));
    let username = sanitize_username(username.as_deref());
    SudoUserContext {
        uid,
        gid,
        username,
        home,
        xdg_config_home,
        xdg_runtime_dir,
        dbus_session_bus_address,
    }
}

fn resolve_sudo_user_context_from(
    env: &ElevationEnv,
    lookup_uid: impl Fn(u32) -> Option<PasswdEntry>,
    lookup_name: impl Fn(&str) -> Option<PasswdEntry>,
) -> Option<SudoUserContext> {
    let sudo_gid = env
        .sudo_gid
        .as_deref()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let sudo_user = sanitize_username(env.sudo_user.as_deref());
    let fallback_home = env.home.as_deref().filter(|h| {
        !h.as_os_str().is_empty()
            && h.is_absolute()
            && *h != Path::new("/root")
            && !h
                .components()
                .any(|comp| matches!(comp, Component::ParentDir))
    });

    // 1. SUDO_UID
    if let Some(uid) = parse_non_root_id(env.sudo_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = sudo_gid
            .or_else(|| entry.as_ref().map(|e| e.gid))
            .unwrap_or(uid);
        let username = entry
            .as_ref()
            .map(|e| e.name.clone())
            .or_else(|| sudo_user.clone());
        let home = entry
            .map(|e| e.home)
            .or_else(|| sudo_user.as_deref().map(|u| PathBuf::from("/home").join(u)))
            .or_else(|| fallback_home.map(Path::to_path_buf))?;
        return Some(build_sudo_user_context(
            uid,
            gid,
            username,
            home,
            env.xdg_config_home.as_deref(),
            env.dbus_session_bus_address.as_deref(),
        ));
    }

    // 2. SUDO_USER (via getpwnam_r)
    if let Some(ref user) = sudo_user {
        if let Some(entry) = lookup_name(user).filter(|e| e.uid > 0) {
            let gid = sudo_gid.unwrap_or(entry.gid);
            return Some(build_sudo_user_context(
                entry.uid,
                gid,
                Some(entry.name),
                entry.home,
                env.xdg_config_home.as_deref(),
                env.dbus_session_bus_address.as_deref(),
            ));
        }
    }

    // 3. PKEXEC_UID
    if let Some(uid) = parse_non_root_id(env.pkexec_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = entry.as_ref().map(|e| e.gid).unwrap_or(uid);
        let username = entry.as_ref().map(|e| e.name.clone());
        let home = entry
            .map(|e| e.home)
            .or_else(|| fallback_home.map(Path::to_path_buf))?;
        return Some(build_sudo_user_context(
            uid,
            gid,
            username,
            home,
            env.xdg_config_home.as_deref(),
            env.dbus_session_bus_address.as_deref(),
        ));
    }

    // 4. DOAS_USER (via getpwnam_r)
    if let Some(doas_user) = sanitize_username(env.doas_user.as_deref()) {
        if let Some(entry) = lookup_name(&doas_user).filter(|e| e.uid > 0) {
            return Some(build_sudo_user_context(
                entry.uid,
                entry.gid,
                Some(entry.name),
                entry.home,
                env.xdg_config_home.as_deref(),
                env.dbus_session_bus_address.as_deref(),
            ));
        }
    }

    None
}

fn resolve_sudo_user_context() -> Option<SudoUserContext> {
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let env = ElevationEnv {
        sudo_uid: std::env::var("SUDO_UID").ok(),
        sudo_gid: std::env::var("SUDO_GID").ok(),
        sudo_user: std::env::var("SUDO_USER").ok(),
        pkexec_uid: std::env::var("PKEXEC_UID").ok(),
        doas_user: std::env::var("DOAS_USER").ok(),
        home: std::env::var_os("HOME").map(PathBuf::from),
        xdg_config_home: std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        dbus_session_bus_address: std::env::var("DBUS_SESSION_BUS_ADDRESS").ok(),
    };
    resolve_sudo_user_context_from(&env, lookup_passwd_by_uid, lookup_passwd_by_name)
}

fn resolve_trusted_bin_in(bin: &str, dirs: &[&Path]) -> Option<PathBuf> {
    if bin.is_empty() || bin.contains('\0') || bin.contains('/') {
        return None;
    }
    for dir in dirs {
        let candidate = dir.join(bin);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn resolve_trusted_bin(bin: &str) -> Option<PathBuf> {
    let dirs: Vec<&Path> = TRUSTED_BIN_DIRS.iter().map(Path::new).collect();
    resolve_trusted_bin_in(bin, &dirs)
}

fn build_user_command(program: &Path, sudo_ctx: Option<&SudoUserContext>) -> Command {
    let mut cmd = Command::new(program);
    if let Some(ctx) = sudo_ctx {
        cmd.env("PATH", SANITIZED_SYSTEM_PATH)
            .env("HOME", &ctx.home)
            .env("XDG_CONFIG_HOME", &ctx.xdg_config_home)
            .env("XDG_RUNTIME_DIR", &ctx.xdg_runtime_dir)
            .env("DBUS_SESSION_BUS_ADDRESS", &ctx.dbus_session_bus_address);
        if let Some(ref user) = ctx.username {
            cmd.env("USER", user).env("LOGNAME", user);
        } else {
            cmd.env_remove("USER").env_remove("LOGNAME");
        }
        let uid = ctx.uid;
        let gid = ctx.gid;
        // SAFETY: `setgroups`, `setgid`, and `setuid` run in the forked child before `exec`
        // while euid is still 0 so `setgroups` retains CAP_SETGID. Using `CommandExt::uid`
        // would drop UID before `pre_exec` runs and cause `setgroups` to fail with EPERM.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setgid(gid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    cmd
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
enum SavedKdeNoProxy {
    /// `NoProxyFor` was absent or empty before activation; delete on restore.
    Unset,
    /// `NoProxyFor` had a pre-existing value before activation; restore verbatim.
    Value(String),
}

impl SavedKdeNoProxy {
    fn from_raw(raw: &str) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            Self::Unset
        } else {
            Self::Value(trimmed.to_string())
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct GnomeProxySnapshot {
    mode: Option<String>,
    autoconfig_url: Option<String>,
    ignore_hosts: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KdeProxySnapshot {
    proxy_type: Option<String>,
    proxy_config_script: Option<String>,
    no_proxy_for: Option<SavedKdeNoProxy>,
}

fn sanitize_gnome_restore_targets<'a>(
    saved_mode: Option<&'a str>,
    saved_autoconfig_url: Option<&'a str>,
) -> (&'a str, &'a str) {
    let raw_url = saved_autoconfig_url.map(|u| u.trim().trim_matches('\''));
    let url_was_vdpi = raw_url.is_some_and(is_vdpi_pac_url);
    let restore_url = if url_was_vdpi {
        ""
    } else {
        raw_url.unwrap_or("")
    };
    let raw_mode = saved_mode
        .map(|m| m.trim().trim_matches('\''))
        .filter(|m| matches!(*m, "none" | "manual" | "auto"));
    let restore_mode = match raw_mode {
        Some("auto") if url_was_vdpi => "none",
        Some(m) => m,
        None => "none",
    };
    (restore_mode, restore_url)
}

fn sanitize_kde_restore_targets<'a>(
    saved_proxy_type: Option<&'a str>,
    saved_pac_script: Option<&'a str>,
) -> (&'a str, Option<&'a str>) {
    let raw_script = saved_pac_script.map(str::trim);
    let script_was_vdpi = raw_script.is_some_and(is_vdpi_pac_url);
    let restore_script = if script_was_vdpi {
        None
    } else {
        raw_script.filter(|s| !s.is_empty())
    };
    let raw_type = saved_proxy_type
        .map(str::trim)
        .filter(|t| matches!(*t, "0" | "1" | "2" | "3" | "4"));
    let restore_type = match raw_type {
        Some("2") if script_was_vdpi => "0",
        Some(t) => t,
        None => "0",
    };
    (restore_type, restore_script)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SavedLinuxProxyState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gnome_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gnome_autoconfig_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gnome_ignore_hosts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kde_proxy_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kde_proxy_config_script: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kde_no_proxy_for: Option<SavedKdeNoProxy>,
}

impl SavedLinuxProxyState {
    fn is_empty(&self) -> bool {
        self.gnome_mode.is_none()
            && self.gnome_autoconfig_url.is_none()
            && self.gnome_ignore_hosts.is_none()
            && self.kde_proxy_type.is_none()
            && self.kde_proxy_config_script.is_none()
            && self.kde_no_proxy_for.is_none()
    }

    fn record_gnome_if_absent(&mut self, snap: &GnomeProxySnapshot) {
        if self.gnome_mode.is_none() {
            if let Some(ref mode) = snap.mode {
                self.gnome_mode = Some(mode.clone());
            }
        }
        if self.gnome_autoconfig_url.is_none() {
            if let Some(ref url) = snap.autoconfig_url {
                self.gnome_autoconfig_url = Some(url.clone());
            }
        }
        if self.gnome_ignore_hosts.is_none() {
            if let Some(ref orig) = snap.ignore_hosts {
                self.gnome_ignore_hosts = Some(orig.clone());
            }
        }
    }

    fn record_kde_if_absent(&mut self, snap: &KdeProxySnapshot) {
        if self.kde_proxy_type.is_none() {
            if let Some(ref ptype) = snap.proxy_type {
                self.kde_proxy_type = Some(ptype.clone());
            }
        }
        if self.kde_proxy_config_script.is_none() {
            if let Some(ref script) = snap.proxy_config_script {
                self.kde_proxy_config_script = Some(script.clone());
            }
        }
        if self.kde_no_proxy_for.is_none() {
            if let Some(ref no_proxy) = snap.no_proxy_for {
                self.kde_no_proxy_for = Some(no_proxy.clone());
            }
        }
    }

    fn save_to_path(&self, path: &Path, sudo_ctx: Option<&SudoUserContext>) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialize Linux proxy state")?;
        write_state_file_atomic(path, &json, sudo_ctx)
    }

    fn load_from_path(path: &Path, sudo_ctx: Option<&SudoUserContext>) -> Result<Option<Self>> {
        if let Some(ctx) = sudo_ctx {
            ensure_no_symlink_under_home(path, &ctx.home)?;
        }
        let mut opts = OpenOptions::new();
        opts.read(true);
        if sudo_ctx.is_some() {
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match opts.open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        };
        let mut raw = String::new();
        file.read_to_string(&mut raw)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let state = serde_json::from_str(&raw).with_context(|| {
            format!(
                "failed to deserialize Linux proxy state from {}",
                path.display()
            )
        })?;
        Ok(Some(state))
    }
}

fn linux_proxy_state_path(sudo_ctx: Option<&SudoUserContext>) -> PathBuf {
    if let Some(ctx) = sudo_ctx {
        return ctx.home.join(".vdpi").join("linux-proxy-state.json");
    }
    crate::service::vdpi_root_dir()
        .map(|root| root.join("linux-proxy-state.json"))
        .unwrap_or_else(|_| PathBuf::from("/etc/vdpi/linux-proxy-state.json"))
}

/// Refuses to traverse, create, open, or chown through any symlink or `..`
/// component located beneath `home_dir` (checking every intermediate directory
/// and the target component itself).
fn ensure_no_symlink_under_home(path: &Path, home_dir: &Path) -> Result<()> {
    if home_dir.as_os_str().is_empty() {
        return Ok(());
    }
    let Ok(rel) = path.strip_prefix(home_dir) else {
        return Ok(());
    };
    let mut normal_parts = Vec::new();
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => normal_parts.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                bail!(
                    "refusing to traverse parent component '..' under user home '{}' while running as root",
                    home_dir.display()
                );
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "unexpected absolute path component under user home '{}'",
                    home_dir.display()
                );
            }
        }
    }

    let last_idx = normal_parts.len().saturating_sub(1);
    let mut cur = home_dir.to_path_buf();
    for (idx, part) in normal_parts.into_iter().enumerate() {
        cur.push(part);
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "refusing to write through symlink '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(meta) if idx < last_idx && !meta.file_type().is_dir() => {
                bail!(
                    "refusing to traverse non-directory '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect path {}", cur.display()));
            }
        }
    }
    Ok(())
}

fn is_valid_sudo_chown_target(path: &Path, ctx: &SudoUserContext) -> bool {
    if ctx.home.as_os_str().is_empty()
        || !ctx.home.is_absolute()
        || ctx.home == Path::new("/")
        || path == ctx.home
        || !path.starts_with(&ctx.home)
    {
        return false;
    }
    ensure_no_symlink_under_home(path, &ctx.home).is_ok()
}

fn chown_to_sudo_ctx(path: &Path, sudo_ctx: Option<&SudoUserContext>) {
    let Some(ctx) = sudo_ctx else {
        return;
    };
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    if !is_valid_sudo_chown_target(path, ctx) {
        return;
    }
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path string; `lchown` never follows symlinks.
    let _ = unsafe { libc::lchown(c_path.as_ptr(), ctx.uid, ctx.gid) };
}

fn write_state_file_atomic(
    path: &Path,
    contents: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> Result<()> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(ctx) = sudo_ctx {
        ensure_no_symlink_under_home(path, &ctx.home)?;
    }

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let missing_under_home: Vec<PathBuf> = if let Some(ctx) = sudo_ctx {
            if parent.starts_with(&ctx.home) {
                let mut missing = Vec::new();
                let mut cur = parent.to_path_buf();
                while cur != ctx.home && cur.starts_with(&ctx.home) {
                    if std::fs::symlink_metadata(&cur).is_err() {
                        missing.push(cur.clone());
                    }
                    let Some(p) = cur.parent() else {
                        break;
                    };
                    cur = p.to_path_buf();
                }
                missing.reverse();
                missing
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;

        if let Some(ctx) = sudo_ctx {
            ensure_no_symlink_under_home(path, &ctx.home)?;
            for created in &missing_under_home {
                chown_to_sudo_ctx(created, sudo_ctx);
            }
            if parent != ctx.home {
                chown_to_sudo_ctx(parent, sudo_ctx);
            }
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("linux-proxy-state.json");
    let pid = std::process::id();
    let mut created = None;
    for _ in 0..16 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.{pid}.{seq}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create temporary state {}", candidate.display())
                });
            }
        }
    }
    let (tmp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary state file in {}",
            parent.display()
        )
    })?;
    if let Err(err) = file
        .write_all(contents.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err)
            .with_context(|| format!("failed to write temporary state {}", tmp_path.display()));
    }
    drop(file);
    chown_to_sudo_ctx(&tmp_path, sudo_ctx);

    if let Some(ctx) = sudo_ctx {
        if let Err(err) = ensure_no_symlink_under_home(path, &ctx.home) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(err);
        }
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} from {}",
                path.display(),
                tmp_path.display()
            )
        });
    }
    Ok(())
}

fn remove_state_file(path: &Path, sudo_ctx: Option<&SudoUserContext>) {
    if let Some(ctx) = sudo_ctx {
        if let Err(err) = ensure_no_symlink_under_home(path, &ctx.home) {
            warn!(
                path = %path.display(),
                error = %err,
                "refusing to remove Linux proxy state file through symlink or traversal"
            );
            return;
        }
        if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            warn!(
                path = %path.display(),
                "refusing to remove symlinked Linux proxy state file"
            );
            return;
        }
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to remove Linux proxy state file"
            );
        }
    }
}

fn load_include_domains_from_paths(paths: &[&Path]) -> Vec<String> {
    for path in paths {
        if let Some(domains) = crate::config_file::load_file_config(Some(path), false)
            .ok()
            .and_then(|(_, cfg)| cfg.include_domains)
        {
            return domains;
        }
    }
    Vec::new()
}

fn load_effective_include_domains(sudo_ctx: Option<&SudoUserContext>) -> Vec<String> {
    let user_path = sudo_ctx
        .map(|ctx| ctx.xdg_config_home.join("vdpi").join("config.toml"))
        .unwrap_or_else(crate::config_file::user_config_path);
    let sys_path = crate::config_file::system_config_path();
    load_include_domains_from_paths(&[&user_path, &sys_path])
}

fn normalize_include_domains<'a>(domains: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut normalized = Vec::new();
    for raw in domains {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && !normalized.iter().any(|existing: &String| existing == trimmed) {
            normalized.push(trimmed.to_string());
        }
    }
    normalized
}

fn resolve_include_domains(
    cli_includes: &[String],
    load_config: impl FnOnce() -> Vec<String>,
) -> Vec<String> {
    let cli = normalize_include_domains(cli_includes.iter().map(String::as_str));
    if !cli.is_empty() {
        return cli;
    }
    let config_includes = load_config();
    normalize_include_domains(config_includes.iter().map(String::as_str))
}

#[derive(Debug, Clone)]
pub struct LinuxProxySession {
    addr: IpAddr,
    http_port: u16,
    pac_url: String,
    socks_port: Option<u16>,
    socks_configured: bool,
    gnome_configured: bool,
    kde_bin: Option<PathBuf>,
    systemd_env_configured: bool,
    no_proxy_csv: String,
    applied_gnome_ignore_hosts: Option<String>,
    applied_kde_no_proxy_for: Option<String>,
    saved_gnome_mode: Option<String>,
    saved_gnome_autoconfig_url: Option<String>,
    saved_gnome_ignore_hosts: Option<String>,
    saved_kde_proxy_type: Option<String>,
    saved_kde_proxy_config_script: Option<String>,
    saved_kde_no_proxy_for: Option<SavedKdeNoProxy>,
    sudo_ctx: Option<SudoUserContext>,
}

impl LinuxProxySession {
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        Self::activate_with_options(
            addr,
            http_port,
            socks_port,
            enable_socks_system_proxy,
            enable_env_proxy,
            extra_bypass,
            &[],
        )
    }

    pub fn activate_with_options(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
        include_domains: &[String],
    ) -> Result<Self> {
        let sudo_ctx = resolve_sudo_user_context();
        let ctx_ref = sudo_ctx.as_ref();
        let pac_url = format_pac_url(addr, http_port);
        let socks_configured = enable_socks_system_proxy && socks_port.is_some();
        let effective_includes =
            resolve_include_domains(include_domains, || load_effective_include_domains(ctx_ref));
        let no_proxy_csv = build_no_proxy_value_with_includes(extra_bypass, &effective_includes);

        if enable_socks_system_proxy {
            debug!(
                socks_port = ?socks_port,
                "ignoring fail-closed SOCKS5 desktop proxy on Linux in favor of fail-open PAC"
            );
        }

        let state_path = linux_proxy_state_path(ctx_ref);
        let had_existing_state = state_path.exists();
        let mut saved_state = SavedLinuxProxyState::load_from_path(&state_path, ctx_ref)
            .unwrap_or_else(|e| {
                warn!(
                    path = %state_path.display(),
                    error = %e,
                    "failed to load previous Linux proxy state"
                );
                None
            })
            .unwrap_or_default();

        // Snapshot existing GNOME mode, autoconfig-url, and ignore-hosts before activation
        // so pre-existing corporate/user proxy settings are preserved and restored.
        let mut gnome_snapshot: Option<GnomeProxySnapshot> = None;
        let gsettings_bin = resolve_trusted_bin("gsettings").filter(|gs| {
            gnome_snapshot = snapshot_gnome_proxy_with_bin(gs, ctx_ref);
            gnome_snapshot.is_some()
        });
        if let Some(ref snap) = gnome_snapshot {
            saved_state.record_gnome_if_absent(snap);
        }
        let merged_gnome_ignore = gnome_snapshot
            .as_ref()
            .and_then(|snap| snap.ignore_hosts.as_deref())
            .map(|existing| {
                merge_gsettings_ignore_hosts(Some(existing), extra_bypass, &effective_includes)
            });

        // Snapshot existing KDE ProxyType, Proxy Config Script, and NoProxyFor before activation
        // so pre-existing corporate/user proxy settings are preserved and restored.
        let kde_writer = detect_kde_writer(ctx_ref);
        let kde_snapshot = kde_writer.as_deref().and_then(|kbin| {
            kde_reader_for_writer(kbin)
                .as_deref()
                .map(|r| snapshot_kde_proxy_with_reader(r, ctx_ref))
        });
        if let Some(ref snap) = kde_snapshot {
            saved_state.record_kde_if_absent(snap);
        }
        let merged_kde_no_proxy = kde_snapshot
            .as_ref()
            .and_then(|snap| snap.no_proxy_for.as_ref())
            .map(|existing| match existing {
                SavedKdeNoProxy::Value(val) => merge_kde_no_proxy_for(Some(val), &no_proxy_csv),
                SavedKdeNoProxy::Unset => merge_kde_no_proxy_for(Some(""), &no_proxy_csv),
            });

        if !saved_state.is_empty() {
            if let Err(e) = saved_state.save_to_path(&state_path, ctx_ref) {
                warn!(
                    path = %state_path.display(),
                    error = %e,
                    "failed to persist Linux proxy state snapshot"
                );
            }
        }

        let gnome_configured = gsettings_bin.as_deref().is_some_and(|gs| {
            configure_gnome_proxy_with_bin(
                gs,
                &pac_url,
                merged_gnome_ignore.as_deref(),
                gnome_snapshot.as_ref().and_then(|s| s.mode.as_deref()),
                gnome_snapshot
                    .as_ref()
                    .and_then(|s| s.autoconfig_url.as_deref()),
                gnome_snapshot
                    .as_ref()
                    .and_then(|s| s.ignore_hosts.as_deref()),
                ctx_ref,
            )
        });

        let kde_bin = kde_writer.filter(|kbin| {
            configure_kde_proxy(
                kbin,
                &pac_url,
                merged_kde_no_proxy.as_deref(),
                kde_snapshot
                    .as_ref()
                    .and_then(|s| s.proxy_config_script.as_deref()),
                kde_snapshot.as_ref().and_then(|s| s.no_proxy_for.as_ref()),
                ctx_ref,
            )
        });

        if !had_existing_state {
            let gnome_had_snapshot = saved_state.gnome_mode.is_some()
                || saved_state.gnome_autoconfig_url.is_some()
                || saved_state.gnome_ignore_hosts.is_some();
            let kde_had_snapshot = saved_state.kde_proxy_type.is_some()
                || saved_state.kde_proxy_config_script.is_some()
                || saved_state.kde_no_proxy_for.is_some();
            if !gnome_configured {
                saved_state.gnome_mode = None;
                saved_state.gnome_autoconfig_url = None;
                saved_state.gnome_ignore_hosts = None;
            }
            if kde_bin.is_none() {
                saved_state.kde_proxy_type = None;
                saved_state.kde_proxy_config_script = None;
                saved_state.kde_no_proxy_for = None;
            }
            if saved_state.is_empty() {
                remove_state_file(&state_path, ctx_ref);
            } else if (!gnome_configured && gnome_had_snapshot)
                || (kde_bin.is_none() && kde_had_snapshot)
            {
                let _ = saved_state.save_to_path(&state_path, ctx_ref);
            }
        }

        let applied_gnome_ignore_hosts = if gnome_configured {
            merged_gnome_ignore
        } else {
            None
        };
        let applied_kde_no_proxy_for = if kde_bin.is_some() {
            merged_kde_no_proxy
        } else {
            None
        };
        let saved_gnome_mode = if gnome_configured {
            saved_state.gnome_mode.clone()
        } else {
            None
        };
        let saved_gnome_autoconfig_url = if gnome_configured {
            saved_state.gnome_autoconfig_url.clone()
        } else {
            None
        };
        let saved_gnome_ignore_hosts = if gnome_configured {
            saved_state.gnome_ignore_hosts.clone()
        } else {
            None
        };
        let saved_kde_proxy_type = if kde_bin.is_some() {
            saved_state.kde_proxy_type.clone()
        } else {
            None
        };
        let saved_kde_proxy_config_script = if kde_bin.is_some() {
            saved_state.kde_proxy_config_script.clone()
        } else {
            None
        };
        let saved_kde_no_proxy_for = if kde_bin.is_some() {
            saved_state.kde_no_proxy_for.clone()
        } else {
            None
        };

        let systemd_env_configured = if enable_env_proxy {
            let proxy_url = format_proxy_url(addr, http_port);
            set_systemd_user_env(&proxy_url, &no_proxy_csv, ctx_ref)
        } else {
            false
        };

        info!(
            gnome = gnome_configured,
            kde = kde_bin.is_some(),
            systemd_env = systemd_env_configured,
            pac_url = %pac_url,
            "configured Linux fail-open PAC desktop proxy integration"
        );

        Ok(Self {
            addr,
            http_port,
            pac_url,
            socks_port,
            socks_configured,
            gnome_configured,
            kde_bin,
            systemd_env_configured,
            no_proxy_csv,
            applied_gnome_ignore_hosts,
            applied_kde_no_proxy_for,
            saved_gnome_mode,
            saved_gnome_autoconfig_url,
            saved_gnome_ignore_hosts,
            saved_kde_proxy_type,
            saved_kde_proxy_config_script,
            saved_kde_no_proxy_for,
            sudo_ctx,
        })
    }

    pub fn summary(&self) -> String {
        let mut backends = Vec::new();
        if self.gnome_configured {
            backends.push("GNOME gsettings PAC");
        }
        if self.kde_bin.is_some() {
            backends.push("KDE kioslaverc PAC");
        }
        if self.systemd_env_configured {
            backends.push("systemd user env");
        }
        if backends.is_empty() {
            "listening (export HTTP_PROXY / HTTPS_PROXY manually on headless Linux)".to_string()
        } else {
            format!("active ({}; {})", backends.join(" + "), self.pac_url)
        }
    }

    pub fn reconcile(&self) {
        if crate::platform::vpn::detect_active_vpn(None).is_full_tunnel() {
            debug!("full-tunnel VPN active; skipping Linux proxy reconciliation");
            return;
        }

        let ctx_ref = self.sudo_ctx.as_ref();

        if self.gnome_configured {
            if let Some(gsettings) = resolve_trusted_bin("gsettings") {
                let _ = reconcile_gnome_with_bin(
                    &gsettings,
                    &self.pac_url,
                    self.applied_gnome_ignore_hosts.as_deref(),
                    self.saved_gnome_mode.as_deref(),
                    self.saved_gnome_autoconfig_url.as_deref(),
                    self.saved_gnome_ignore_hosts.as_deref(),
                    ctx_ref,
                );
            }
        }
        if let Some(ref kbin) = self.kde_bin {
            let reader = kde_reader_for_writer(kbin);
            let _ = reconcile_kde_with_bins(
                kbin,
                reader.as_deref(),
                &self.pac_url,
                self.applied_kde_no_proxy_for.as_deref(),
                self.saved_kde_proxy_config_script.as_deref(),
                self.saved_kde_no_proxy_for.as_ref(),
                ctx_ref,
            );
        }
        if self.systemd_env_configured {
            let proxy_url = format_proxy_url(self.addr, self.http_port);
            let _ = set_systemd_user_env(&proxy_url, &self.no_proxy_csv, ctx_ref);
        }
    }

    pub fn deactivate(&self) {
        self.deactivate_scoped();
        debug!("restored Linux desktop proxy settings");
    }

    pub(super) fn deactivate_foreground(&self) {
        self.deactivate_scoped();
    }

    fn deactivate_scoped(&self) {
        let ctx_ref = self.sudo_ctx.as_ref();
        let state_path = linux_proxy_state_path(ctx_ref);
        let disk_state = SavedLinuxProxyState::load_from_path(&state_path, ctx_ref)
            .ok()
            .flatten();

        if self.gnome_configured {
            if let Some(gsettings) = resolve_trusted_bin("gsettings") {
                let saved_mode = self.saved_gnome_mode.as_deref().or_else(|| {
                    disk_state.as_ref().and_then(|s| s.gnome_mode.as_deref())
                });
                let saved_autoconfig = self.saved_gnome_autoconfig_url.as_deref().or_else(|| {
                    disk_state
                        .as_ref()
                        .and_then(|s| s.gnome_autoconfig_url.as_deref())
                });
                let saved_ignore = self.saved_gnome_ignore_hosts.as_deref().or_else(|| {
                    disk_state
                        .as_ref()
                        .and_then(|s| s.gnome_ignore_hosts.as_deref())
                });
                deactivate_gnome_with_bin(
                    &gsettings,
                    self.addr,
                    self.http_port,
                    &self.pac_url,
                    self.socks_configured,
                    self.socks_port,
                    self.applied_gnome_ignore_hosts.as_deref(),
                    saved_mode,
                    saved_autoconfig,
                    saved_ignore,
                    ctx_ref,
                );
            }
        }
        if let Some(writer) = &self.kde_bin {
            let reader = kde_reader_for_writer(writer);
            let dbus_send = resolve_trusted_bin("dbus-send");
            let saved_proxy_type = self.saved_kde_proxy_type.as_deref().or_else(|| {
                disk_state
                    .as_ref()
                    .and_then(|s| s.kde_proxy_type.as_deref())
            });
            let saved_pac_script = self.saved_kde_proxy_config_script.as_deref().or_else(|| {
                disk_state
                    .as_ref()
                    .and_then(|s| s.kde_proxy_config_script.as_deref())
            });
            let saved_no_proxy = self.saved_kde_no_proxy_for.as_ref().or_else(|| {
                disk_state
                    .as_ref()
                    .and_then(|s| s.kde_no_proxy_for.as_ref())
            });
            deactivate_kde_with_bins(
                writer,
                reader.as_deref(),
                dbus_send.as_deref(),
                self.addr,
                self.http_port,
                &self.pac_url,
                self.socks_configured,
                self.socks_port,
                self.applied_kde_no_proxy_for.as_deref(),
                saved_proxy_type,
                saved_pac_script,
                saved_no_proxy,
                ctx_ref,
            );
        }
        if self.systemd_env_configured {
            if let Some(systemctl) = resolve_trusted_bin("systemctl") {
                let expected = format_proxy_url(self.addr, self.http_port);
                let owned = build_user_command(&systemctl, ctx_ref)
                    .args(["--user", "show-environment"])
                    .output()
                    .ok()
                    .filter(|out| out.status.success())
                    .is_some_and(|out| {
                        let text = String::from_utf8_lossy(&out.stdout);
                        systemd_env_matches_proxy(&text, &expected)
                    });
                if owned {
                    let _ = build_user_command(&systemctl, ctx_ref)
                        .args([
                            "--user",
                            "unset-environment",
                            "HTTP_PROXY",
                            "HTTPS_PROXY",
                            "http_proxy",
                            "https_proxy",
                            "NO_PROXY",
                            "no_proxy",
                        ])
                        .output();
                }
            }
        }
        if self.gnome_configured || self.kde_bin.is_some() {
            remove_state_file(&state_path, ctx_ref);
        }
    }
}

fn should_clear_gnome_pac(autoconfig_url: Option<&str>) -> bool {
    autoconfig_url
        .map(|val| val.trim_matches('\''))
        .is_some_and(is_vdpi_pac_url)
}

fn should_reset_gnome_mode(
    autoconfig_url: Option<&str>,
    mode: Option<&str>,
    cleared_manual: bool,
) -> bool {
    let clean_mode = mode.map(|m| m.trim_matches('\''));
    if should_clear_gnome_pac(autoconfig_url) && matches!(clean_mode, Some("auto") | None) {
        return true;
    }
    cleared_manual && clean_mode == Some("manual")
}

fn should_clear_kde_pac(pac_script: Option<&str>) -> bool {
    pac_script.is_some_and(is_vdpi_pac_url)
}

fn should_reset_kde_proxy_type(
    pac_script: Option<&str>,
    proxy_type: Option<&str>,
    cleared_manual: bool,
) -> bool {
    let ptype = proxy_type.map(str::trim);
    if should_clear_kde_pac(pac_script) && matches!(ptype, Some("2") | None) {
        return true;
    }
    cleared_manual && ptype == Some("1")
}

fn should_reset_kde_proxy_type_scoped(
    pac_owned: bool,
    manual_owned: bool,
    proxy_type: Option<&str>,
) -> bool {
    let ptype = proxy_type.map(str::trim);
    if pac_owned && ptype == Some("2") {
        return true;
    }
    manual_owned && ptype == Some("1")
}

fn should_reconcile_gnome(
    mode: Option<&str>,
    autoconfig_url: Option<&str>,
    expected_pac_url: &str,
) -> bool {
    let Some(clean_mode) = mode.map(|v| v.trim().trim_matches('\'')) else {
        return false;
    };
    let Some(clean_url) = autoconfig_url.map(|v| v.trim().trim_matches('\'')) else {
        return false;
    };
    if !matches!(clean_mode, "none" | "auto") {
        return false;
    }
    // GNOME `mode == 'auto'` with an empty `autoconfig-url` represents corporate WPAD
    // auto-discovery (equivalent to KDE `ProxyType=3`); never overwrite it.
    if clean_mode == "auto" && clean_url.is_empty() {
        return false;
    }
    if !clean_url.is_empty() && !is_vdpi_pac_url(clean_url) {
        return false;
    }
    !(clean_mode == "auto" && clean_url.eq_ignore_ascii_case(expected_pac_url))
}

fn should_reconcile_kde(
    proxy_type: Option<&str>,
    pac_script: Option<&str>,
    expected_pac_url: &str,
) -> bool {
    let Some(clean_type) = proxy_type.map(str::trim) else {
        return false;
    };
    let Some(clean_script) = pac_script.map(str::trim) else {
        return false;
    };
    if !matches!(clean_type, "" | "0" | "2") {
        return false;
    }
    if !clean_script.is_empty() && !is_vdpi_pac_url(clean_script) {
        return false;
    }
    !(clean_type == "2" && clean_script.eq_ignore_ascii_case(expected_pac_url))
}

#[allow(clippy::too_many_arguments)]
fn reconcile_gnome_with_bin(
    gsettings: &Path,
    pac_url: &str,
    applied_ignore_hosts: Option<&str>,
    saved_mode: Option<&str>,
    saved_autoconfig_url: Option<&str>,
    saved_ignore_hosts: Option<&str>,
    ctx_ref: Option<&SudoUserContext>,
) -> bool {
    let mode = gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "mode", ctx_ref);
    let autoconfig =
        gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "autoconfig-url", ctx_ref);
    if !should_reconcile_gnome(mode.as_deref(), autoconfig.as_deref(), pac_url) {
        debug!(
            mode = ?mode,
            autoconfig_url = ?autoconfig,
            "skipping GNOME proxy reconciliation (already configured or user/corporate proxy active)"
        );
        return false;
    }
    configure_gnome_proxy_with_bin(
        gsettings,
        pac_url,
        applied_ignore_hosts,
        saved_mode,
        saved_autoconfig_url,
        saved_ignore_hosts,
        ctx_ref,
    )
}

#[allow(clippy::too_many_arguments)]
fn reconcile_kde_with_bins(
    writer: &Path,
    reader: Option<&Path>,
    pac_url: &str,
    applied_no_proxy_for: Option<&str>,
    saved_pac_script: Option<&str>,
    saved_no_proxy_for: Option<&SavedKdeNoProxy>,
    ctx_ref: Option<&SudoUserContext>,
) -> bool {
    let proxy_type = reader.and_then(|r| kde_read_proxy_key(r, "ProxyType", ctx_ref));
    let pac_script = reader.and_then(|r| kde_read_proxy_key(r, "Proxy Config Script", ctx_ref));
    if !should_reconcile_kde(proxy_type.as_deref(), pac_script.as_deref(), pac_url) {
        debug!(
            proxy_type = ?proxy_type,
            pac_script = ?pac_script,
            "skipping KDE proxy reconciliation (already configured or user/corporate proxy active)"
        );
        return false;
    }
    configure_kde_proxy(
        writer,
        pac_url,
        applied_no_proxy_for,
        saved_pac_script,
        saved_no_proxy_for,
        ctx_ref,
    )
}

#[allow(clippy::too_many_arguments)]
fn deactivate_gnome_with_bin(
    gsettings: &Path,
    addr: IpAddr,
    http_port: u16,
    pac_url: &str,
    socks_configured: bool,
    socks_port: Option<u16>,
    applied_ignore_hosts: Option<&str>,
    saved_mode: Option<&str>,
    saved_autoconfig_url: Option<&str>,
    saved_ignore_hosts: Option<&str>,
    ctx_ref: Option<&SudoUserContext>,
) {
    let addr_str = normalize_proxy_addr(addr).to_string();
    let raw_addr_str = addr.to_string();
    let mode = gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "mode", ctx_ref);
    let autoconfig =
        gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "autoconfig-url", ctx_ref);
    let pac_owned = autoconfig.as_deref().is_some_and(|val| {
        let clean = val.trim_matches('\'');
        clean.eq_ignore_ascii_case(pac_url) || is_vdpi_pac_url(clean)
    });

    let http_owned = [
        "org.gnome.system.proxy.http",
        "org.gnome.system.proxy.https",
    ]
    .into_iter()
    .any(|schema| {
        gsettings_get_with_bin(gsettings, schema, "host", ctx_ref).is_some_and(|host| {
            let h = host.trim_matches('\'');
            h == addr_str || h == raw_addr_str
        }) && gsettings_get_with_bin(gsettings, schema, "port", ctx_ref)
            .is_some_and(|port| port.parse::<u16>() == Ok(http_port))
    });
    let socks_owned = socks_configured
        && socks_port.is_some_and(|sp| {
            gsettings_get_with_bin(gsettings, "org.gnome.system.proxy.socks", "host", ctx_ref)
                .is_some_and(|host| {
                    let h = host.trim_matches('\'');
                    h == addr_str || h == raw_addr_str
                })
                && gsettings_get_with_bin(
                    gsettings,
                    "org.gnome.system.proxy.socks",
                    "port",
                    ctx_ref,
                )
                .is_some_and(|port| port.parse::<u16>() == Ok(sp))
        });

    let (restore_mode, restore_url) =
        sanitize_gnome_restore_targets(saved_mode, saved_autoconfig_url);

    if pac_owned {
        let _ = gsettings_set_with_bin(
            gsettings,
            "org.gnome.system.proxy",
            "autoconfig-url",
            restore_url,
            ctx_ref,
        );
        if mode.as_deref() == Some("'auto'") {
            let _ = gsettings_set_with_bin(
                gsettings,
                "org.gnome.system.proxy",
                "mode",
                restore_mode,
                ctx_ref,
            );
        }
    } else if (http_owned || socks_owned) && mode.as_deref() == Some("'manual'") {
        let _ = gsettings_set_with_bin(
            gsettings,
            "org.gnome.system.proxy",
            "mode",
            restore_mode,
            ctx_ref,
        );
    }
    let _ = clear_stale_gnome_manual_keys_with_bin(gsettings, ctx_ref);

    if let Some(orig_ignore) = saved_ignore_hosts {
        let current_ignore =
            gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "ignore-hosts", ctx_ref);
        let should_restore = match (current_ignore.as_deref(), applied_ignore_hosts) {
            (Some(curr), Some(applied)) => gsettings_string_array_eq(curr, applied),
            (None, _) | (Some(_), None) => pac_owned || http_owned || socks_owned,
        };
        if should_restore {
            let _ = gsettings_set_with_bin(
                gsettings,
                "org.gnome.system.proxy",
                "ignore-hosts",
                normalize_gsettings_ignore_hosts_for_restore(orig_ignore),
                ctx_ref,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn deactivate_kde_with_bins(
    writer: &Path,
    reader: Option<&Path>,
    dbus_send: Option<&Path>,
    addr: IpAddr,
    http_port: u16,
    pac_url: &str,
    socks_configured: bool,
    socks_port: Option<u16>,
    applied_no_proxy_csv: Option<&str>,
    saved_proxy_type: Option<&str>,
    saved_pac_script: Option<&str>,
    saved_no_proxy: Option<&SavedKdeNoProxy>,
    ctx_ref: Option<&SudoUserContext>,
) {
    let pac_owned = reader
        .and_then(|r| kde_read_proxy_key(r, "Proxy Config Script", ctx_ref))
        .is_some_and(|val| val.eq_ignore_ascii_case(pac_url) || is_vdpi_pac_url(&val));
    let proxy_type = reader.and_then(|r| kde_read_proxy_key(r, "ProxyType", ctx_ref));
    let expected_http = format!("http://{} {}", addr, http_port);
    let http_owned = reader.is_some_and(|r| {
        ["httpProxy", "httpsProxy"].into_iter().any(|key| {
            kde_read_proxy_key(r, key, ctx_ref).is_some_and(|val| val == expected_http)
        })
    });
    let socks_owned = socks_configured
        && socks_port.is_some_and(|sp| {
            let expected_socks = format!("socks://{} {sp}", addr);
            reader
                .and_then(|r| kde_read_proxy_key(r, "socksProxy", ctx_ref))
                .is_some_and(|val| val == expected_socks)
        });
    let manual_owned = http_owned || socks_owned;
    let reset_type =
        should_reset_kde_proxy_type_scoped(pac_owned, manual_owned, proxy_type.as_deref());
    let (restore_type, restore_script) =
        sanitize_kde_restore_targets(saved_proxy_type, saved_pac_script);

    let mut changed = false;
    if pac_owned || manual_owned {
        if pac_owned {
            let _ = match restore_script {
                Some(orig) => kde_write_proxy_key(writer, "Proxy Config Script", orig, ctx_ref),
                None => kde_delete_proxy_key(writer, "Proxy Config Script", ctx_ref),
            };
            changed = true;
        }
        if reset_type {
            let _ = kde_write_proxy_key(writer, "ProxyType", restore_type, ctx_ref);
            changed = true;
        }
        if clear_stale_kde_manual_keys_with_reader(writer, reader, ctx_ref) {
            changed = true;
        }
    }

    if let Some(orig_no_proxy) = saved_no_proxy {
        let current_no_proxy = reader.and_then(|r| kde_read_proxy_key(r, "NoProxyFor", ctx_ref));
        let should_restore = match (current_no_proxy.as_deref(), applied_no_proxy_csv) {
            (Some(curr), Some(applied)) => csv_list_eq(curr, applied),
            (None, _) | (Some(_), None) => pac_owned || manual_owned,
        };
        if should_restore && restore_kde_no_proxy_for(writer, orig_no_proxy, ctx_ref) {
            changed = true;
        }
    }

    if changed {
        if let Some(dbus_bin) = dbus_send {
            notify_kde_reload_with_bin(dbus_bin, ctx_ref);
        }
    }
}

fn clear_gnome_proxies_with_bin(
    gsettings: &Path,
    saved_mode: Option<&str>,
    saved_autoconfig_url: Option<&str>,
    saved_ignore_hosts: Option<&str>,
    ctx_ref: Option<&SudoUserContext>,
) {
    let autoconfig = gsettings_get_with_bin(
        gsettings,
        "org.gnome.system.proxy",
        "autoconfig-url",
        ctx_ref,
    );
    let mode = gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "mode", ctx_ref);
    let should_clear_pac = should_clear_gnome_pac(autoconfig.as_deref());
    let cleared_manual = clear_stale_gnome_manual_keys_with_bin(gsettings, ctx_ref);
    let (restore_mode, restore_url) =
        sanitize_gnome_restore_targets(saved_mode, saved_autoconfig_url);
    if should_clear_pac {
        let _ = gsettings_set_with_bin(
            gsettings,
            "org.gnome.system.proxy",
            "autoconfig-url",
            restore_url,
            ctx_ref,
        );
    }
    if should_reset_gnome_mode(autoconfig.as_deref(), mode.as_deref(), cleared_manual) {
        let _ = gsettings_set_with_bin(
            gsettings,
            "org.gnome.system.proxy",
            "mode",
            restore_mode,
            ctx_ref,
        );
    }
    if should_clear_pac || cleared_manual {
        if let Some(orig_ignore) = saved_ignore_hosts {
            let _ = gsettings_set_with_bin(
                gsettings,
                "org.gnome.system.proxy",
                "ignore-hosts",
                normalize_gsettings_ignore_hosts_for_restore(orig_ignore),
                ctx_ref,
            );
        }
    }
}

fn clear_kde_proxies_with_bins(
    writer: &Path,
    reader: Option<&Path>,
    dbus_send: Option<&Path>,
    saved_proxy_type: Option<&str>,
    saved_pac_script: Option<&str>,
    saved_no_proxy: Option<&SavedKdeNoProxy>,
    ctx_ref: Option<&SudoUserContext>,
) {
    let pac_script = reader.and_then(|r| kde_read_proxy_key(r, "Proxy Config Script", ctx_ref));
    let proxy_type = reader.and_then(|r| kde_read_proxy_key(r, "ProxyType", ctx_ref));
    let should_clear_pac = should_clear_kde_pac(pac_script.as_deref());
    let cleared_manual = clear_stale_kde_manual_keys_with_reader(writer, reader, ctx_ref);
    let should_reset_type = should_reset_kde_proxy_type(
        pac_script.as_deref(),
        proxy_type.as_deref(),
        cleared_manual,
    );
    let (restore_type, restore_script) =
        sanitize_kde_restore_targets(saved_proxy_type, saved_pac_script);
    if should_clear_pac {
        let _ = match restore_script {
            Some(orig) => kde_write_proxy_key(writer, "Proxy Config Script", orig, ctx_ref),
            None => kde_delete_proxy_key(writer, "Proxy Config Script", ctx_ref),
        };
    }
    if should_reset_type {
        let _ = kde_write_proxy_key(writer, "ProxyType", restore_type, ctx_ref);
    }
    let restored_no_proxy = if should_clear_pac || cleared_manual {
        saved_no_proxy
            .is_some_and(|orig| restore_kde_no_proxy_for(writer, orig, ctx_ref))
    } else {
        false
    };
    if should_clear_pac || cleared_manual || should_reset_type || restored_no_proxy {
        if let Some(dbus_bin) = dbus_send {
            notify_kde_reload_with_bin(dbus_bin, ctx_ref);
        }
    }
}

pub fn clear_all_linux_proxies() -> Result<()> {
    let sudo_ctx = resolve_sudo_user_context();
    let ctx_ref = sudo_ctx.as_ref();
    let state_path = linux_proxy_state_path(ctx_ref);
    let saved_state = SavedLinuxProxyState::load_from_path(&state_path, ctx_ref)
        .ok()
        .flatten()
        .unwrap_or_default();

    if let Some(gsettings) = resolve_trusted_bin("gsettings") {
        clear_gnome_proxies_with_bin(
            &gsettings,
            saved_state.gnome_mode.as_deref(),
            saved_state.gnome_autoconfig_url.as_deref(),
            saved_state.gnome_ignore_hosts.as_deref(),
            ctx_ref,
        );
    }
    if let Some(kbin) = detect_kde_writer_for_cleanup(ctx_ref) {
        let reader = kde_reader_for_writer(&kbin);
        let dbus_send = resolve_trusted_bin("dbus-send");
        clear_kde_proxies_with_bins(
            &kbin,
            reader.as_deref(),
            dbus_send.as_deref(),
            saved_state.kde_proxy_type.as_deref(),
            saved_state.kde_proxy_config_script.as_deref(),
            saved_state.kde_no_proxy_for.as_ref(),
            ctx_ref,
        );
    }
    if let Some(systemctl) = resolve_trusted_bin("systemctl") {
        let should_unset = build_user_command(&systemctl, ctx_ref)
            .args(["--user", "show-environment"])
            .output()
            .ok()
            .filter(|out| out.status.success())
            .is_some_and(|out| {
                let text = String::from_utf8_lossy(&out.stdout);
                systemd_env_has_loopback_proxy(&text)
            });
        if should_unset {
            let _ = build_user_command(&systemctl, ctx_ref)
                .args([
                    "--user",
                    "unset-environment",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "http_proxy",
                    "https_proxy",
                    "NO_PROXY",
                    "no_proxy",
                ])
                .output();
        }
    }
    remove_state_file(&state_path, ctx_ref);
    Ok(())
}

pub fn print_linux_proxy_status() {
    let sudo_ctx = resolve_sudo_user_context();
    let ctx_ref = sudo_ctx.as_ref();

    println!("\n=== Linux Desktop Proxy Integration ===");
    if let Some(gsettings) = resolve_trusted_bin("gsettings") {
        let mode = gsettings_get_with_bin(&gsettings, "org.gnome.system.proxy", "mode", ctx_ref)
            .unwrap_or_else(|| "<unavailable>".into());
        let autoconfig = gsettings_get_with_bin(
            &gsettings,
            "org.gnome.system.proxy",
            "autoconfig-url",
            ctx_ref,
        )
        .unwrap_or_else(|| "<unset>".into());
        println!("GNOME proxy mode          : {mode}");
        println!("GNOME autoconfig-url      : {autoconfig}");
    }
    if let Some(reader) = detect_kde_reader_for_status(ctx_ref) {
        let proxy_type = kde_read_proxy_key(&reader, "ProxyType", ctx_ref)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "<unset>".into());
        let pac_script = kde_read_proxy_key(&reader, "Proxy Config Script", ctx_ref)
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "<unset>".into());
        println!("KDE kioslaverc ProxyType  : {proxy_type}");
        println!("KDE kioslaverc PAC script : {pac_script}");
    }
    if let Some(systemctl) = resolve_trusted_bin("systemctl") {
        let env_out = build_user_command(&systemctl, ctx_ref)
            .args(["--user", "show-environment"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let https_val = env_out
            .lines()
            .find_map(|l| l.strip_prefix("HTTPS_PROXY="))
            .unwrap_or("<unset>");
        println!("systemd user HTTPS_PROXY  : {https_val}");
    }
}

fn gsettings_get_with_bin(
    gsettings: &Path,
    schema: &str,
    key: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> Option<String> {
    build_user_command(gsettings, sudo_ctx)
        .args(["get", schema, key])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn gsettings_set_with_bin(
    gsettings: &Path,
    schema: &str,
    key: &str,
    val: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    build_user_command(gsettings, sudo_ctx)
        .args(["set", schema, key, val])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn snapshot_gnome_proxy_with_bin(
    gsettings: &Path,
    sudo_ctx: Option<&SudoUserContext>,
) -> Option<GnomeProxySnapshot> {
    let raw_mode = gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "mode", sudo_ctx)?;
    let raw_autoconfig = gsettings_get_with_bin(
        gsettings,
        "org.gnome.system.proxy",
        "autoconfig-url",
        sudo_ctx,
    );
    let ignore_hosts =
        gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "ignore-hosts", sudo_ctx);
    let (sanitized_mode, sanitized_url) =
        sanitize_gnome_restore_targets(Some(&raw_mode), raw_autoconfig.as_deref());
    Some(GnomeProxySnapshot {
        mode: Some(sanitized_mode.to_string()),
        autoconfig_url: Some(sanitized_url.to_string()),
        ignore_hosts,
    })
}

fn clear_stale_gnome_manual_keys_with_bin(
    gsettings: &Path,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    let mut cleared = false;
    for schema in [
        "org.gnome.system.proxy.http",
        "org.gnome.system.proxy.https",
        "org.gnome.system.proxy.socks",
    ] {
        let host = gsettings_get_with_bin(gsettings, schema, "host", sudo_ctx);
        let is_loopback = host
            .as_deref()
            .map(|h| h.trim_matches('\''))
            .is_some_and(is_loopback_host);
        if is_loopback {
            let _ = gsettings_set_with_bin(gsettings, schema, "host", "", sudo_ctx);
            let _ = gsettings_set_with_bin(gsettings, schema, "port", "0", sudo_ctx);
            if schema == "org.gnome.system.proxy.http" {
                let _ = gsettings_set_with_bin(gsettings, schema, "enabled", "false", sudo_ctx);
            }
            cleared = true;
        } else if schema == "org.gnome.system.proxy.http"
            && host
                .as_deref()
                .is_some_and(|h| h.trim_matches('\'').is_empty())
            && gsettings_get_with_bin(gsettings, schema, "enabled", sudo_ctx).as_deref()
                == Some("true")
        {
            let _ = gsettings_set_with_bin(gsettings, schema, "enabled", "false", sudo_ctx);
            cleared = true;
        }
    }
    cleared
}

#[allow(clippy::too_many_arguments)]
fn configure_gnome_proxy_with_bin(
    gsettings: &Path,
    pac_url: &str,
    ignore_hosts: Option<&str>,
    rollback_mode: Option<&str>,
    rollback_autoconfig_url: Option<&str>,
    rollback_ignore_hosts: Option<&str>,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    if gsettings_get_with_bin(gsettings, "org.gnome.system.proxy", "mode", sudo_ctx).is_none() {
        return false;
    }

    let _ = clear_stale_gnome_manual_keys_with_bin(gsettings, sudo_ctx);

    let ignore_updated = ignore_hosts.is_some_and(|hosts| {
        gsettings_set_with_bin(
            gsettings,
            "org.gnome.system.proxy",
            "ignore-hosts",
            hosts,
            sudo_ctx,
        )
    });
    let url_ok = gsettings_set_with_bin(
        gsettings,
        "org.gnome.system.proxy",
        "autoconfig-url",
        pac_url,
        sudo_ctx,
    );
    let mode_ok = if url_ok {
        gsettings_set_with_bin(gsettings, "org.gnome.system.proxy", "mode", "auto", sudo_ctx)
    } else {
        false
    };

    if !(url_ok && mode_ok) {
        let (restore_mode, restore_url) =
            sanitize_gnome_restore_targets(rollback_mode, rollback_autoconfig_url);
        if url_ok && !mode_ok {
            let _ = gsettings_set_with_bin(
                gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                restore_url,
                sudo_ctx,
            );
            if rollback_mode.is_some() {
                let _ = gsettings_set_with_bin(
                    gsettings,
                    "org.gnome.system.proxy",
                    "mode",
                    restore_mode,
                    sudo_ctx,
                );
            }
        }
        if ignore_updated {
            if let Some(orig) = rollback_ignore_hosts {
                let _ = gsettings_set_with_bin(
                    gsettings,
                    "org.gnome.system.proxy",
                    "ignore-hosts",
                    normalize_gsettings_ignore_hosts_for_restore(orig),
                    sudo_ctx,
                );
            }
        }
        return false;
    }

    true
}

fn find_kde_writer_bin() -> Option<PathBuf> {
    for candidate in ["kwriteconfig6", "kwriteconfig5"] {
        if let Some(path) = resolve_trusted_bin(candidate) {
            return Some(path);
        }
    }
    None
}

fn find_kde_reader_bin() -> Option<PathBuf> {
    for candidate in ["kreadconfig6", "kreadconfig5"] {
        if let Some(path) = resolve_trusted_bin(candidate) {
            return Some(path);
        }
    }
    None
}

fn kde_reader_for_writer(writer: &Path) -> Option<PathBuf> {
    let file_name = writer.file_name()?.to_str()?;
    let reader_name = match file_name {
        "kwriteconfig6" => "kreadconfig6",
        "kwriteconfig5" => "kreadconfig5",
        _ => return None,
    };
    if let Some(parent) = writer.parent() {
        let sibling = parent.join(reader_name);
        if is_executable_file(&sibling) {
            return Some(sibling);
        }
    }
    resolve_trusted_bin(reader_name)
}

fn should_detect_kde(xdg_current_desktop: Option<&str>, has_kioslaverc: bool) -> bool {
    let desktop = xdg_current_desktop
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if desktop.contains("kde") || desktop.contains("plasma") {
        return true;
    }
    desktop.is_empty() && has_kioslaverc
}

fn detect_kde_writer(sudo_ctx: Option<&SudoUserContext>) -> Option<PathBuf> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").ok();
    let has_kioslaverc = kioslaverc_exists(sudo_ctx);
    if !should_detect_kde(desktop.as_deref(), has_kioslaverc) {
        return None;
    }
    find_kde_writer_bin()
}

fn kioslaverc_exists_in(xdg_config_home: Option<&Path>, home: Option<&Path>) -> bool {
    let xdg_exists = xdg_config_home
        .filter(|dir| !dir.as_os_str().is_empty())
        .is_some_and(|dir| dir.join("kioslaverc").exists());
    if xdg_exists {
        return true;
    }
    home.filter(|h| !h.as_os_str().is_empty())
        .is_some_and(|h| h.join(".config").join("kioslaverc").exists())
}

fn kioslaverc_exists(sudo_ctx: Option<&SudoUserContext>) -> bool {
    if let Some(ctx) = sudo_ctx {
        return kioslaverc_exists_in(Some(&ctx.xdg_config_home), Some(&ctx.home));
    }
    let xdg = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    kioslaverc_exists_in(xdg.as_deref(), home.as_deref())
}

fn detect_kde_writer_for_cleanup(sudo_ctx: Option<&SudoUserContext>) -> Option<PathBuf> {
    if let Some(kbin) = detect_kde_writer(sudo_ctx) {
        return Some(kbin);
    }
    if kioslaverc_exists(sudo_ctx) {
        find_kde_writer_bin()
    } else {
        None
    }
}

fn detect_kde_reader_for_status(sudo_ctx: Option<&SudoUserContext>) -> Option<PathBuf> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if desktop.contains("kde") || desktop.contains("plasma") || kioslaverc_exists(sudo_ctx) {
        find_kde_reader_bin()
    } else {
        None
    }
}

fn kde_read_proxy_key(
    reader: &Path,
    key: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> Option<String> {
    build_user_command(reader, sudo_ctx)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
        ])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn kde_write_proxy_key(
    writer: &Path,
    key: &str,
    val: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    build_user_command(writer, sudo_ctx)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
            val,
        ])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn kde_delete_proxy_key(
    writer: &Path,
    key: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    build_user_command(writer, sudo_ctx)
        .args([
            "--file",
            "kioslaverc",
            "--group",
            "Proxy Settings",
            "--key",
            key,
            "--delete",
        ])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn clear_stale_kde_manual_keys_with_reader(
    writer: &Path,
    reader: Option<&Path>,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    let Some(reader) = reader else {
        return false;
    };
    let mut cleared = false;
    for key in ["httpProxy", "httpsProxy", "socksProxy"] {
        let should_delete = kde_read_proxy_key(reader, key, sudo_ctx)
            .is_some_and(|val| is_loopback_kde_proxy_value(&val));
        if should_delete && kde_delete_proxy_key(writer, key, sudo_ctx) {
            cleared = true;
        }
    }
    cleared
}

fn clear_stale_kde_manual_keys(writer: &Path, sudo_ctx: Option<&SudoUserContext>) -> bool {
    let reader = kde_reader_for_writer(writer);
    clear_stale_kde_manual_keys_with_reader(writer, reader.as_deref(), sudo_ctx)
}

fn restore_kde_no_proxy_for(
    writer: &Path,
    saved: &SavedKdeNoProxy,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    match saved {
        SavedKdeNoProxy::Value(orig) => kde_write_proxy_key(writer, "NoProxyFor", orig, sudo_ctx),
        SavedKdeNoProxy::Unset => kde_delete_proxy_key(writer, "NoProxyFor", sudo_ctx),
    }
}

fn snapshot_kde_proxy_with_reader(
    reader: &Path,
    sudo_ctx: Option<&SudoUserContext>,
) -> KdeProxySnapshot {
    let raw_proxy_type = kde_read_proxy_key(reader, "ProxyType", sudo_ctx);
    let raw_pac_script = kde_read_proxy_key(reader, "Proxy Config Script", sudo_ctx);
    let raw_no_proxy = kde_read_proxy_key(reader, "NoProxyFor", sudo_ctx);
    let (proxy_type, proxy_config_script) =
        if raw_proxy_type.is_some() || raw_pac_script.is_some() {
            let (sanitized_type, sanitized_script) = sanitize_kde_restore_targets(
                raw_proxy_type.as_deref(),
                raw_pac_script.as_deref(),
            );
            (
                Some(sanitized_type.to_string()),
                Some(sanitized_script.unwrap_or("").to_string()),
            )
        } else {
            (None, None)
        };
    KdeProxySnapshot {
        proxy_type,
        proxy_config_script,
        no_proxy_for: raw_no_proxy.as_deref().map(SavedKdeNoProxy::from_raw),
    }
}

fn configure_kde_proxy(
    kbin: &Path,
    pac_url: &str,
    no_proxy_csv: Option<&str>,
    rollback_pac_script: Option<&str>,
    rollback_no_proxy: Option<&SavedKdeNoProxy>,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    let _ = clear_stale_kde_manual_keys(kbin, sudo_ctx);
    let (no_proxy_ok, no_proxy_updated) = match no_proxy_csv {
        Some(csv) => {
            let ok = kde_write_proxy_key(kbin, "NoProxyFor", csv, sudo_ctx);
            (ok, ok)
        }
        None => (true, false),
    };
    let url_ok = if no_proxy_ok {
        kde_write_proxy_key(kbin, "Proxy Config Script", pac_url, sudo_ctx)
    } else {
        false
    };
    let type_ok = if url_ok {
        kde_write_proxy_key(kbin, "ProxyType", "2", sudo_ctx)
    } else {
        false
    };
    if !(no_proxy_ok && url_ok && type_ok) {
        warn!(
            kde_bin = %kbin.display(),
            no_proxy_ok,
            url_ok,
            type_ok,
            "failed to configure KDE kioslaverc PAC proxy"
        );
        if url_ok && !type_ok {
            let (_, restore_script) = sanitize_kde_restore_targets(None, rollback_pac_script);
            let _ = match restore_script {
                Some(orig) => kde_write_proxy_key(kbin, "Proxy Config Script", orig, sudo_ctx),
                None => kde_delete_proxy_key(kbin, "Proxy Config Script", sudo_ctx),
            };
        }
        if no_proxy_updated {
            if let Some(orig) = rollback_no_proxy {
                let _ = restore_kde_no_proxy_for(kbin, orig, sudo_ctx);
            }
        }
        return false;
    }
    notify_kde_reload(sudo_ctx);
    true
}

fn notify_kde_reload_with_bin(dbus_send: &Path, sudo_ctx: Option<&SudoUserContext>) {
    // Emit both KF6 (Plasma 6) and KF5 (Plasma 5) KIO reload signals.
    for signal in [
        "org.kde.KIO.Scheduler.reparseWorkerConfiguration",
        "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
    ] {
        let _ = build_user_command(dbus_send, sudo_ctx)
            .args(["--type=signal", "/KIO/Scheduler", signal, "string:"])
            .output();
    }
}

fn notify_kde_reload(sudo_ctx: Option<&SudoUserContext>) {
    if let Some(dbus_send) = resolve_trusted_bin("dbus-send") {
        notify_kde_reload_with_bin(&dbus_send, sudo_ctx);
    }
}

fn set_systemd_user_env(
    proxy_url: &str,
    no_proxy: &str,
    sudo_ctx: Option<&SudoUserContext>,
) -> bool {
    let Some(systemctl) = resolve_trusted_bin("systemctl") else {
        return false;
    };
    let res = build_user_command(&systemctl, sudo_ctx)
        .args([
            "--user",
            "set-environment",
            &format!("HTTP_PROXY={proxy_url}"),
            &format!("HTTPS_PROXY={proxy_url}"),
            &format!("http_proxy={proxy_url}"),
            &format!("https_proxy={proxy_url}"),
            &format!("NO_PROXY={no_proxy}"),
            &format!("no_proxy={no_proxy}"),
        ])
        .output();
    let _ = build_user_command(&systemctl, sudo_ctx)
        .args(["--user", "unset-environment", "ALL_PROXY", "all_proxy"])
        .output();
    matches!(res, Ok(o) if o.status.success())
}

fn systemd_env_matches_proxy(env_output: &str, expected_proxy_url: &str) -> bool {
    env_output.lines().any(|line| {
        ["HTTP_PROXY=", "HTTPS_PROXY=", "http_proxy=", "https_proxy="]
            .into_iter()
            .any(|prefix| line.strip_prefix(prefix) == Some(expected_proxy_url))
    })
}

fn systemd_env_has_loopback_proxy(env_output: &str) -> bool {
    env_output.lines().any(|line| {
        [
            "HTTP_PROXY=",
            "HTTPS_PROXY=",
            "http_proxy=",
            "https_proxy=",
            "ALL_PROXY=",
            "all_proxy=",
        ]
        .into_iter()
        .any(|prefix| {
            line.strip_prefix(prefix)
                .is_some_and(is_loopback_kde_proxy_value)
        })
    })
}

const GNOME_BASELINE_IGNORE_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.0/8",
    "0.0.0.0",
    "::1",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
    ".localhost",
    ".localdomain",
    ".local",
    ".lan",
    ".internal",
    ".home.arpa",
    ".ts.net",
    "captive.apple.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
    "msftncsi.com",
    "dns.msftncsi.com",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "connectivity-check.ubuntu.com",
    "ping.archlinux.org",
    "neverssl.com",
    ".gov.tr",
    ".isbank.com.tr",
];

fn parse_gsettings_string_array(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let without_type = trimmed
        .strip_prefix("@as")
        .map(str::trim)
        .unwrap_or(trimmed);
    let inner = without_type
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
        .unwrap_or("");
    if inner.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() || ch == ',' {
            chars.next();
            continue;
        }
        if ch == '\'' || ch == '"' {
            let quote = ch;
            chars.next();
            let mut val = String::new();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        val.push(escaped);
                    }
                } else if c == quote {
                    break;
                } else {
                    val.push(c);
                }
            }
            let cleaned = val.trim();
            if !cleaned.is_empty() {
                out.push(cleaned.to_string());
            }
        } else {
            let mut val = String::new();
            while let Some(&c) = chars.peek() {
                if c == ',' {
                    break;
                }
                val.push(c);
                chars.next();
            }
            let cleaned = val.trim();
            if !cleaned.is_empty() {
                out.push(cleaned.to_string());
            }
        }
    }
    out
}

fn gsettings_string_array_eq(a: &str, b: &str) -> bool {
    let parsed_a = parse_gsettings_string_array(a);
    let parsed_b = parse_gsettings_string_array(b);
    parsed_a.len() == parsed_b.len()
        && parsed_a
            .iter()
            .zip(parsed_b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn normalize_gsettings_ignore_hosts_for_restore(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        "@as []"
    } else {
        trimmed
    }
}

fn is_local_or_ip_gnome_baseline(entry: &str) -> bool {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.contains('/') || trimmed.contains(':') {
        return true;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return true;
    }
    if trimmed
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'*')
    {
        return true;
    }
    let base = trimmed
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    matches!(
        base.as_str(),
        "localhost" | "localdomain" | "local" | "lan" | "internal" | "home.arpa" | "ts.net"
    ) || base.ends_with(".localhost")
        || base.ends_with(".localdomain")
        || base.ends_with(".local")
        || base.ends_with(".lan")
        || base.ends_with(".internal")
        || base.ends_with(".home.arpa")
        || base.ends_with(".ts.net")
}

fn gnome_baseline_wildcard_to_regex(pattern: &str) -> Option<String> {
    let p = pattern.trim().to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.").or_else(|| p.strip_prefix('.')) {
        let suffix = suffix.trim_end_matches('.');
        if suffix.is_empty() {
            return None;
        }
        let escaped = regex::escape(suffix);
        Some(format!(r"^(?:.+\.)?{escaped}$"))
    } else {
        let p = p.trim_end_matches('.');
        if p.is_empty() {
            return None;
        }
        if p.contains('*') {
            let mut out = String::from("^");
            for (i, part) in p.split('*').enumerate() {
                if i > 0 {
                    out.push_str(".*");
                }
                out.push_str(&regex::escape(part));
            }
            out.push('$');
            Some(out)
        } else {
            let escaped = regex::escape(p);
            Some(format!(r"^(?:.+\.)?{escaped}$"))
        }
    }
}

fn extract_include_domain_candidates(pattern: &str) -> Vec<String> {
    let trimmed = pattern.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Vec::new();
    }

    let unescaped = trimmed.replace(r"\.", ".").replace(r"\-", "-");
    let mut candidates = Vec::new();
    for segment in unescaped.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        // Ignore prefix fragments such as `gov.tr.` in `gov\.tr\.(example|test)\.com$`.
        if segment.is_empty() || segment.ends_with('.') {
            continue;
        }
        let cleaned = segment.trim_start_matches('.').trim_matches('-');
        if cleaned.contains('.') {
            candidates.push(cleaned.to_ascii_lowercase());
        }
    }
    candidates
}

fn gnome_baseline_overridden_by_includes(
    baseline: &str,
    include_regexes: &[Regex],
    include_candidates: &[String],
) -> bool {
    if include_regexes.is_empty() && include_candidates.is_empty() {
        return false;
    }
    if is_local_or_ip_gnome_baseline(baseline) {
        return false;
    }

    let cleaned = baseline.trim().trim_start_matches('*');
    let base = cleaned.trim_start_matches('.').to_ascii_lowercase();
    if base.is_empty() {
        return false;
    }

    let sample_subdomain = format!("a.{base}");
    if include_regexes
        .iter()
        .any(|re| re.is_match(&base) || re.is_match(cleaned) || re.is_match(&sample_subdomain))
    {
        return true;
    }

    if include_candidates.is_empty() {
        return false;
    }
    let Some(expr) = gnome_baseline_wildcard_to_regex(baseline) else {
        return false;
    };
    let Ok(pat_re) = Regex::new(&expr) else {
        return false;
    };
    include_candidates.iter().any(|cand| pat_re.is_match(cand))
}

fn format_gsettings_ignore_hosts(
    existing: &[String],
    extra: &[String],
    include_domains: &[String],
) -> String {
    let mut include_regexes = Vec::new();
    let mut include_candidates = Vec::new();
    for raw in include_domains {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(re) = RegexBuilder::new(trimmed).case_insensitive(true).build() {
            include_regexes.push(re);
        }
        include_candidates.extend(extract_include_domain_candidates(trimmed));
    }

    let mut items: Vec<String> = Vec::new();
    let mut push_unique = |val: &str| {
        let clean = val.trim();
        if !clean.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            items.push(clean.to_string());
        }
    };

    for entry in existing {
        push_unique(entry);
    }
    for baseline in GNOME_BASELINE_IGNORE_HOSTS {
        if gnome_baseline_overridden_by_includes(baseline, &include_regexes, &include_candidates) {
            continue;
        }
        push_unique(baseline);
    }
    for entry in extra {
        let clean = entry.trim().trim_start_matches('*');
        push_unique(clean);
    }

    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("'{}'", s.replace('\\', "\\\\").replace('\'', "")))
        .collect();
    format!("[{}]", quoted.join(", "))
}

fn merge_gsettings_ignore_hosts(
    existing_raw: Option<&str>,
    extra: &[String],
    include_domains: &[String],
) -> String {
    let existing = existing_raw
        .map(parse_gsettings_string_array)
        .unwrap_or_default();
    format_gsettings_ignore_hosts(&existing, extra, include_domains)
}

#[cfg(test)]
fn build_gsettings_ignore_hosts(extra: &[String]) -> String {
    format_gsettings_ignore_hosts(&[], extra, &[])
}

fn merge_kde_no_proxy_for(existing: Option<&str>, vdpi_no_proxy_csv: &str) -> String {
    let mut items: Vec<String> = Vec::new();
    let mut push_unique = |val: &str| {
        let clean = val.trim();
        if !clean.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            items.push(clean.to_string());
        }
    };

    if let Some(raw) = existing {
        for entry in raw.split(',') {
            push_unique(entry);
        }
    }
    for entry in vdpi_no_proxy_csv.split(',') {
        push_unique(entry);
    }

    items.join(",")
}

fn csv_list_eq(a: &str, b: &str) -> bool {
    fn parse(s: &str) -> Vec<&str> {
        s.split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .collect()
    }
    let items_a = parse(a);
    let items_b = parse(b);
    items_a.len() == items_b.len()
        && items_a
            .iter()
            .zip(items_b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111) != 0)
}

fn command_exists_in_path(bin: &str, path_var: Option<&std::ffi::OsStr>) -> bool {
    if bin.is_empty() || bin.contains('\0') {
        return false;
    }
    if bin.contains('/') {
        return is_executable_file(Path::new(bin));
    }
    let Some(path_var) = path_var else {
        return false;
    };
    std::env::split_paths(path_var)
        .filter(|dir| !dir.as_os_str().is_empty())
        .any(|dir| is_executable_file(&dir.join(bin)))
}

pub fn command_exists(bin: &str) -> bool {
    let path_var = std::env::var_os("PATH");
    command_exists_in_path(bin, path_var.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn detects_kioslaverc_in_home_or_xdg_config_home() {
        let root =
            std::env::temp_dir().join(format!("vdpi-kioslaverc-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let home_dir = root.join("home");
        let home_cfg = home_dir.join(".config");
        fs::create_dir_all(&home_cfg).unwrap();

        assert!(!kioslaverc_exists_in(None, Some(&home_dir)));

        fs::write(
            home_cfg.join("kioslaverc"),
            "[Proxy Settings]\nProxyType=1\n",
        )
        .unwrap();
        assert!(kioslaverc_exists_in(None, Some(&home_dir)));

        let xdg_dir = root.join("xdg");
        fs::create_dir_all(&xdg_dir).unwrap();
        assert!(!kioslaverc_exists_in(Some(&xdg_dir), None));

        fs::write(
            xdg_dir.join("kioslaverc"),
            "[Proxy Settings]\nProxyType=1\n",
        )
        .unwrap();
        assert!(kioslaverc_exists_in(Some(&xdg_dir), None));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pure_rust_command_exists_scans_path_without_shell() {
        let root =
            std::env::temp_dir().join(format!("vdpi-cmd-exists-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();

        let exec_file = bin_dir.join("mytool");
        fs::write(&exec_file, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&exec_file, fs::Permissions::from_mode(0o755)).unwrap();

        let non_exec = bin_dir.join("readme");
        fs::write(&non_exec, "not executable").unwrap();
        fs::set_permissions(&non_exec, fs::Permissions::from_mode(0o644)).unwrap();

        let dir_as_bin = bin_dir.join("subdir");
        fs::create_dir_all(&dir_as_bin).unwrap();
        fs::set_permissions(&dir_as_bin, fs::Permissions::from_mode(0o755)).unwrap();

        let path_env = OsString::from(bin_dir.as_os_str());
        assert!(command_exists_in_path("mytool", Some(&path_env)));
        assert!(command_exists_in_path(
            exec_file.to_str().unwrap(),
            Some(&path_env)
        ));
        assert!(!command_exists_in_path("readme", Some(&path_env)));
        assert!(!command_exists_in_path("subdir", Some(&path_env)));
        assert!(!command_exists_in_path("missing", Some(&path_env)));
        assert!(!command_exists_in_path("", Some(&path_env)));
        assert!(!command_exists_in_path("mytool; echo pwn", Some(&path_env)));
        assert!(!command_exists_in_path("mytool", None));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn build_gsettings_ignore_hosts_escapes_backslashes_and_strips_quotes() {
        let result = build_gsettings_ignore_hosts(&[
            "foo\\bar".to_string(),
            "baz\\".to_string(),
            "qux'evil".to_string(),
        ]);
        assert!(result.contains("'foo\\\\bar'"));
        assert!(result.contains("'baz\\\\'"));
        assert!(result.contains("'quxevil'"));
        for expected in [
            "'localhost'",
            "'127.0.0.0/8'",
            "'0.0.0.0'",
            "'::1'",
            "'100.64.0.0/10'",
            "'fc00::/7'",
            "'fe80::/10'",
            "'.localhost'",
            "'.localdomain'",
            "'.local'",
            "'.lan'",
            "'.internal'",
            "'.home.arpa'",
            "'.ts.net'",
        ] {
            assert!(
                result.contains(expected),
                "expected {expected} in gsettings ignore-hosts: {result}"
            );
        }
    }

    #[test]
    fn formats_and_recognizes_linux_pac_urls_and_loopback_kde_values() {
        assert_eq!(
            format_pac_url(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            "http://127.0.0.1:8080/vdpi.pac"
        );
        assert_eq!(
            format_pac_url(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18080),
            "http://127.0.0.1:18080/vdpi.pac"
        );
        assert_eq!(
            format_pac_url(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080),
            "http://[::1]:8080/vdpi.pac"
        );
        assert!(is_vdpi_pac_url("http://127.0.0.1:8080/vdpi.pac"));
        assert!(is_vdpi_pac_url("http://[::1]:8080/vdpi.pac"));
        assert!(!is_vdpi_pac_url("https://corp.example/wpad.dat"));

        assert!(is_loopback_kde_proxy_value("http://127.0.0.1 8080"));
        assert!(is_loopback_kde_proxy_value("socks://[::1] 1080"));
        assert!(!is_loopback_kde_proxy_value("http://10.0.0.5 3128"));
    }

    #[test]
    fn builds_sudo_user_context_with_expected_xdg_and_dbus_env() {
        let ctx = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            PathBuf::from("/home/alice"),
            None,
            None,
        );
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(ctx.username.as_deref(), Some("alice"));
        assert_eq!(ctx.home, PathBuf::from("/home/alice"));
        assert_eq!(ctx.xdg_config_home, PathBuf::from("/home/alice/.config"));
        assert_eq!(ctx.xdg_runtime_dir, PathBuf::from("/run/user/1000"));
        assert_eq!(
            ctx.dbus_session_bus_address,
            "unix:path=/run/user/1000/bus"
        );

        let custom = build_sudo_user_context(
            1001,
            1002,
            Some("bob".to_string()),
            PathBuf::from("/home/bob"),
            Some(Path::new("/home/bob/.myconfig")),
            Some("unix:path=/tmp/dbus-bob-session,guid=1234"),
        );
        assert_eq!(custom.xdg_config_home, PathBuf::from("/home/bob/.myconfig"));
        assert_eq!(
            custom.dbus_session_bus_address,
            "unix:path=/tmp/dbus-bob-session,guid=1234"
        );

        let root_xdg = build_sudo_user_context(
            1001,
            1002,
            Some("root".to_string()),
            PathBuf::from("/home/bob"),
            Some(Path::new("/root/.config")),
            Some("unix:path=/run/user/0/bus"),
        );
        assert_eq!(root_xdg.username, None);
        assert_eq!(root_xdg.xdg_config_home, PathBuf::from("/home/bob/.config"));
        assert_eq!(
            root_xdg.dbus_session_bus_address,
            "unix:path=/run/user/1001/bus"
        );
    }

    #[test]
    fn resolves_sudo_pkexec_and_doas_user_contexts_and_command_env() {
        let alice = PasswdEntry {
            uid: 1000,
            gid: 1000,
            name: "alice".to_string(),
            home: PathBuf::from("/home/alice"),
        };
        let bob = PasswdEntry {
            uid: 1001,
            gid: 1002,
            name: "bob".to_string(),
            home: PathBuf::from("/home/bob"),
        };
        let root_entry = PasswdEntry {
            uid: 0,
            gid: 0,
            name: "root".to_string(),
            home: PathBuf::from("/root"),
        };

        let lookup_uid = |uid: u32| match uid {
            1000 => Some(alice.clone()),
            1001 => Some(bob.clone()),
            0 => Some(root_entry.clone()),
            _ => None,
        };
        let lookup_name = |name: &str| match name {
            "alice" => Some(alice.clone()),
            "bob" => Some(bob.clone()),
            "root" => Some(root_entry.clone()),
            _ => None,
        };

        // SUDO_USER fallback (when SUDO_UID is absent) resolves via getpwnam_r
        let sudo_user_env = ElevationEnv {
            sudo_user: Some("alice".to_string()),
            dbus_session_bus_address: Some("unix:abstract=/tmp/dbus-alice".to_string()),
            ..Default::default()
        };
        let sudo_ctx =
            resolve_sudo_user_context_from(&sudo_user_env, &lookup_uid, &lookup_name).unwrap();
        assert_eq!(sudo_ctx.uid, 1000);
        assert_eq!(sudo_ctx.gid, 1000);
        assert_eq!(sudo_ctx.username.as_deref(), Some("alice"));
        assert_eq!(
            sudo_ctx.dbus_session_bus_address,
            "unix:abstract=/tmp/dbus-alice"
        );

        // PKEXEC_UID resolves user and rejects mismatched /run/user/0 bus
        let pkexec_env = ElevationEnv {
            pkexec_uid: Some("1001".to_string()),
            dbus_session_bus_address: Some("unix:path=/run/user/0/bus".to_string()),
            ..Default::default()
        };
        let pkexec_ctx =
            resolve_sudo_user_context_from(&pkexec_env, &lookup_uid, &lookup_name).unwrap();
        assert_eq!(pkexec_ctx.uid, 1001);
        assert_eq!(pkexec_ctx.gid, 1002);
        assert_eq!(pkexec_ctx.username.as_deref(), Some("bob"));
        assert_eq!(
            pkexec_ctx.dbus_session_bus_address,
            "unix:path=/run/user/1001/bus"
        );

        // DOAS_USER resolves via getpwnam_r
        let doas_env = ElevationEnv {
            doas_user: Some("bob".to_string()),
            ..Default::default()
        };
        let doas_ctx =
            resolve_sudo_user_context_from(&doas_env, &lookup_uid, &lookup_name).unwrap();
        assert_eq!(doas_ctx.uid, 1001);
        assert_eq!(doas_ctx.gid, 1002);
        assert_eq!(doas_ctx.username.as_deref(), Some("bob"));

        // Root DOAS_USER is ignored
        let root_doas = ElevationEnv {
            doas_user: Some("root".to_string()),
            ..Default::default()
        };
        assert!(resolve_sudo_user_context_from(&root_doas, &lookup_uid, &lookup_name).is_none());

        // build_user_command uses absolute path and sets USER, LOGNAME, sanitized PATH, XDG, DBUS
        let cmd = build_user_command(Path::new("/usr/bin/gsettings"), Some(&sudo_ctx));
        assert_eq!(cmd.get_program(), OsStr::new("/usr/bin/gsettings"));
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|val| val.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(envs.contains(&("USER".into(), Some("alice".into()))));
        assert!(envs.contains(&("LOGNAME".into(), Some("alice".into()))));
        assert!(envs.contains(&("HOME".into(), Some("/home/alice".into()))));
        assert!(envs.contains(&("XDG_CONFIG_HOME".into(), Some("/home/alice/.config".into()))));
        assert!(envs.contains(&("XDG_RUNTIME_DIR".into(), Some("/run/user/1000".into()))));
        assert!(envs.contains(&(
            "DBUS_SESSION_BUS_ADDRESS".into(),
            Some("unix:abstract=/tmp/dbus-alice".into())
        )));
        assert!(envs.contains(&("PATH".into(), Some(SANITIZED_SYSTEM_PATH.into()))));
    }

    #[test]
    fn preserves_non_vdpi_pac_for_sudo_and_regular_users_during_cleanup() {
        // Decision logic: non-vdpi corporate PAC must never reset GNOME mode or KDE ProxyType
        assert!(!should_clear_gnome_pac(Some("'https://corp.example/wpad.dat'")));
        assert!(!should_reset_gnome_mode(
            Some("'https://corp.example/wpad.dat'"),
            Some("'auto'"),
            false
        ));
        // Empty autoconfig-url (WPAD or manual corporate proxy) must not reset mode
        assert!(!should_clear_gnome_pac(Some("''")));
        assert!(!should_reset_gnome_mode(Some("''"), Some("'auto'"), false));
        assert!(!should_reset_gnome_mode(Some("''"), Some("'manual'"), false));
        assert!(!should_reset_gnome_mode(None, Some("'manual'"), false));
        // vdpi-owned PAC clears autoconfig-url and resets mode when auto
        assert!(should_clear_gnome_pac(Some("'http://127.0.0.1:8080/vdpi.pac'")));
        assert!(should_reset_gnome_mode(
            Some("'http://127.0.0.1:8080/vdpi.pac'"),
            Some("'auto'"),
            false
        ));
        // Leftover vdpi PAC when user switched to corporate manual proxy must not clobber manual mode
        assert!(!should_reset_gnome_mode(
            Some("'http://127.0.0.1:8080/vdpi.pac'"),
            Some("'manual'"),
            false
        ));
        // Cleared stale loopback manual proxy resets manual mode
        assert!(should_reset_gnome_mode(Some("''"), Some("'manual'"), true));

        // KDE equivalents
        assert!(!should_clear_kde_pac(Some("https://corp.example/proxy.pac")));
        assert!(!should_reset_kde_proxy_type(
            Some("https://corp.example/proxy.pac"),
            Some("2"),
            false
        ));
        assert!(!should_clear_kde_pac(Some("")));
        assert!(!should_reset_kde_proxy_type(Some(""), Some("1"), false));
        assert!(!should_reset_kde_proxy_type(None, Some("3"), false));
        assert!(should_clear_kde_pac(Some("http://127.0.0.1:8080/vdpi.pac")));
        assert!(should_reset_kde_proxy_type(
            Some("http://127.0.0.1:8080/vdpi.pac"),
            Some("2"),
            false
        ));
        assert!(should_reset_kde_proxy_type(Some(""), Some("1"), true));

        // systemd user env loopback ownership check preserves corporate proxies
        assert!(!systemd_env_has_loopback_proxy(
            "HTTP_PROXY=http://proxy.corp.example:3128\nHTTPS_PROXY=http://proxy.corp.example:3128\n"
        ));
        assert!(systemd_env_has_loopback_proxy(
            "HTTPS_PROXY=http://127.0.0.1:8080\n"
        ));

        // Sudo user context preserves user's kioslaverc path & env without clobbering corporate PAC
        let sudo_ctx = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            PathBuf::from("/home/alice"),
            None,
            Some("unix:path=/run/user/1000/bus"),
        );
        let sudo_gsettings = build_user_command(Path::new("/usr/bin/gsettings"), Some(&sudo_ctx));
        assert_eq!(sudo_gsettings.get_program(), OsStr::new("/usr/bin/gsettings"));

        // End-to-end check with fake gsettings & KDE scripts
        let root = std::env::temp_dir().join(format!(
            "vdpi-clear-preserve-pac-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let corp_log = root.join("corp-gnome.log");
        let corp_gsettings = root.join("gsettings-corp");
        fs::write(
            &corp_gsettings,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"get\" ]; then\n  case \"$2:$3\" in\n    org.gnome.system.proxy:autoconfig-url) echo \"'https://corp.example/wpad.dat'\" ;;\n    org.gnome.system.proxy:mode) echo \"'auto'\" ;;\n    *) echo \"''\" ;;\n  esac\n  exit 0\nfi\necho \"$@\" >> \"{}\"\nexit 0\n",
                corp_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&corp_gsettings, fs::Permissions::from_mode(0o755)).unwrap();

        clear_gnome_proxies_with_bin(&corp_gsettings, None, None, None, None);
        assert!(
            !corp_log.exists(),
            "corporate GNOME PAC must not be modified by cleanup"
        );

        let vdpi_log = root.join("vdpi-gnome.log");
        let vdpi_gsettings = root.join("gsettings-vdpi");
        fs::write(
            &vdpi_gsettings,
            format!(
                "#!/bin/sh\nif [ \"$1\" = \"get\" ]; then\n  case \"$2:$3\" in\n    org.gnome.system.proxy:autoconfig-url) echo \"'http://127.0.0.1:8080/vdpi.pac'\" ;;\n    org.gnome.system.proxy:mode) echo \"'auto'\" ;;\n    *) echo \"''\" ;;\n  esac\n  exit 0\nfi\necho \"$@\" >> \"{}\"\nexit 0\n",
                vdpi_log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&vdpi_gsettings, fs::Permissions::from_mode(0o755)).unwrap();

        clear_gnome_proxies_with_bin(&vdpi_gsettings, None, None, None, None);
        let vdpi_calls = fs::read_to_string(&vdpi_log).unwrap();
        assert!(vdpi_calls.contains("set org.gnome.system.proxy autoconfig-url"));
        assert!(vdpi_calls.contains("set org.gnome.system.proxy mode none"));

        // KDE corporate PAC preservation + vdpi PAC cleanup
        let kde_corp_dir = root.join("kde-corp");
        fs::create_dir_all(&kde_corp_dir).unwrap();
        let kde_corp_log = kde_corp_dir.join("write.log");
        let kde_corp_reader = kde_corp_dir.join("kreadconfig6");
        let kde_corp_writer = kde_corp_dir.join("kwriteconfig6");
        fs::write(
            &kde_corp_reader,
            "#!/bin/sh\ncase \"$6\" in\n  \"Proxy Config Script\") echo \"https://corp.example/proxy.pac\" ;;\n  \"ProxyType\") echo \"2\" ;;\n  *) echo \"\" ;;\nesac\nexit 0\n",
        )
        .unwrap();
        fs::write(
            &kde_corp_writer,
            format!("#!/bin/sh\necho \"$@\" >> \"{}\"\nexit 0\n", kde_corp_log.display()),
        )
        .unwrap();
        fs::set_permissions(&kde_corp_reader, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&kde_corp_writer, fs::Permissions::from_mode(0o755)).unwrap();

        clear_kde_proxies_with_bins(
            &kde_corp_writer,
            Some(&kde_corp_reader),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(
            !kde_corp_log.exists(),
            "corporate KDE PAC must not be modified by cleanup"
        );

        let kde_vdpi_dir = root.join("kde-vdpi");
        fs::create_dir_all(&kde_vdpi_dir).unwrap();
        let kde_vdpi_log = kde_vdpi_dir.join("write.log");
        let kde_vdpi_reader = kde_vdpi_dir.join("kreadconfig6");
        let kde_vdpi_writer = kde_vdpi_dir.join("kwriteconfig6");
        fs::write(
            &kde_vdpi_reader,
            "#!/bin/sh\ncase \"$6\" in\n  \"Proxy Config Script\") echo \"http://127.0.0.1:8080/vdpi.pac\" ;;\n  \"ProxyType\") echo \"2\" ;;\n  *) echo \"\" ;;\nesac\nexit 0\n",
        )
        .unwrap();
        fs::write(
            &kde_vdpi_writer,
            format!("#!/bin/sh\necho \"$@\" >> \"{}\"\nexit 0\n", kde_vdpi_log.display()),
        )
        .unwrap();
        fs::set_permissions(&kde_vdpi_reader, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&kde_vdpi_writer, fs::Permissions::from_mode(0o755)).unwrap();

        clear_kde_proxies_with_bins(
            &kde_vdpi_writer,
            Some(&kde_vdpi_reader),
            None,
            None,
            None,
            None,
            None,
        );
        let kde_vdpi_calls = fs::read_to_string(&kde_vdpi_log).unwrap();
        assert!(kde_vdpi_calls.contains("--key Proxy Config Script --delete"));
        assert!(kde_vdpi_calls.contains("--key ProxyType 0"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn detects_kde_when_desktop_unset_and_propagates_kde_write_failures() {
        assert!(should_detect_kde(Some("KDE"), false));
        assert!(should_detect_kde(Some("plasma"), false));
        assert!(should_detect_kde(None, true));
        assert!(should_detect_kde(Some(""), true));
        assert!(!should_detect_kde(None, false));
        assert!(!should_detect_kde(Some("ubuntu:GNOME"), true));

        let root = std::env::temp_dir().join(format!(
            "vdpi-kde-fail-and-trusted-bin-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let trusted_dir = root.join("trusted");
        fs::create_dir_all(&trusted_dir).unwrap();

        let failing_writer = trusted_dir.join("kwriteconfig6");
        fs::write(&failing_writer, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&failing_writer, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!configure_kde_proxy(
            &failing_writer,
            "http://127.0.0.1:8080/vdpi.pac",
            Some("localhost"),
            None,
            None,
            None
        ));

        let resolved = resolve_trusted_bin_in("kwriteconfig6", &[trusted_dir.as_path()]);
        assert_eq!(resolved.as_deref(), Some(failing_writer.as_path()));
        assert!(resolve_trusted_bin_in("../kwriteconfig6", &[trusted_dir.as_path()]).is_none());
        assert!(resolve_trusted_bin_in("missing-bin", &[trusted_dir.as_path()]).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn systemd_env_ownership_matches_exact_proxy_url() {
        let env = "PATH=/usr/bin\nHTTP_PROXY=http://127.0.0.1:8080\nNO_PROXY=localhost\n";
        assert!(systemd_env_matches_proxy(env, "http://127.0.0.1:8080"));
        assert!(!systemd_env_matches_proxy(env, "http://127.0.0.1:9090"));
    }

    #[test]
    fn build_gsettings_ignore_hosts_includes_captive_portal_domains_and_merges_existing() {
        let baseline = build_gsettings_ignore_hosts(&[]);
        for probe in [
            "'192.0.0.0/24'",
            "'captive.apple.com'",
            "'www.msftconnecttest.com'",
            "'msftconnecttest.com'",
            "'ipv6.msftconnecttest.com'",
            "'www.msftncsi.com'",
            "'msftncsi.com'",
            "'dns.msftncsi.com'",
            "'detectportal.firefox.com'",
            "'connectivitycheck.gstatic.com'",
            "'connectivitycheck.android.com'",
            "'clients3.google.com'",
            "'nmcheck.gnome.org'",
            "'networkcheck.kde.org'",
            "'connectivity-check.ubuntu.com'",
            "'ping.archlinux.org'",
            "'neverssl.com'",
        ] {
            assert!(
                baseline.contains(probe),
                "expected captive portal probe {probe} in gsettings ignore-hosts: {baseline}"
            );
        }

        let merged = merge_gsettings_ignore_hosts(
            Some("['localhost', 'corp.internal', '*.mycorp.local']"),
            &["*.extra.example".to_string()],
            &[],
        );
        let parsed = parse_gsettings_string_array(&merged);
        assert!(parsed.iter().any(|x| x == "corp.internal"));
        assert!(parsed.iter().any(|x| x == "*.mycorp.local"));
        assert!(parsed.iter().any(|x| x == ".extra.example"));
        assert!(parsed.iter().any(|x| x == "nmcheck.gnome.org"));
        assert_eq!(
            parsed
                .iter()
                .filter(|x| x.eq_ignore_ascii_case("localhost"))
                .count(),
            1,
            "duplicate localhost should be deduplicated"
        );

        assert!(parse_gsettings_string_array("@as []").is_empty());
        assert!(parse_gsettings_string_array("[]").is_empty());
        assert_eq!(normalize_gsettings_ignore_hosts_for_restore("[]"), "@as []");
        assert_eq!(
            normalize_gsettings_ignore_hosts_for_restore("@as []"),
            "@as []"
        );

        let merged_kde = merge_kde_no_proxy_for(
            Some("corp.internal, 10.99.0.0/16, localhost"),
            "localhost,127.0.0.1,.gov.tr,networkcheck.kde.org",
        );
        let kde_entries: Vec<&str> = merged_kde.split(',').collect();
        assert!(kde_entries.contains(&"corp.internal"));
        assert!(kde_entries.contains(&"10.99.0.0/16"));
        assert!(kde_entries.contains(&".gov.tr"));
        assert!(kde_entries.contains(&"networkcheck.kde.org"));
        assert_eq!(
            kde_entries
                .iter()
                .filter(|x| x.eq_ignore_ascii_case("localhost"))
                .count(),
            1
        );
    }

    #[test]
    fn no_proxy_with_loaded_config_include_domains_overrides_org_tr() {
        let root = std::env::temp_dir().join(format!(
            "vdpi-linux-include-no-proxy-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let missing_path = root.join("missing.toml");
        let cfg_path = root.join("config.toml");
        fs::write(&cfg_path, "include_domains = [\"\\\\.org\\\\.tr$\"]\n").unwrap();

        let includes =
            load_include_domains_from_paths(&[missing_path.as_path(), cfg_path.as_path()]);
        assert_eq!(includes, vec![r"\.org\.tr$".to_string()]);

        let no_proxy = build_no_proxy_value_with_includes(&[], &includes);
        let entries: Vec<&str> = no_proxy.split(',').collect();
        assert!(
            !entries.iter().any(|e| e.eq_ignore_ascii_case(".org.tr")),
            "--include for .org.tr must override .org.tr in Linux NO_PROXY: {no_proxy}"
        );
        assert!(entries.contains(&"localhost"));
        assert!(entries.contains(&"127.0.0.1"));
        assert!(entries.contains(&".gov.tr"));
        assert!(entries.contains(&"captive.apple.com"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gnome_activation_and_deactivation_preserve_and_restore_ignore_hosts() {
        let root = std::env::temp_dir().join(format!(
            "vdpi-gnome-bypass-preserve-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();

        let orig_ignore = "['localhost', 'corp.internal', '10.99.0.0/16']";
        fs::write(state_dir.join("org.gnome.system.proxy.mode"), "'none'\n").unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.autoconfig-url"),
            "''\n",
        )
        .unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.ignore-hosts"),
            format!("{orig_ignore}\n"),
        )
        .unwrap();

        let fake_gsettings = root.join("gsettings");
        fs::write(
            &fake_gsettings,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\ncmd=\"$1\"\nschema=\"$2\"\nkey=\"$3\"\nfile=\"$state_dir/$schema.$key\"\nif [ \"$cmd\" = \"get\" ]; then\n  if [ -f \"$file\" ]; then\n    cat \"$file\"\n  else\n    echo \"''\"\n  fi\n  exit 0\nfi\nif [ \"$cmd\" = \"set\" ]; then\n  val=\"$4\"\n  if [ \"$key\" = \"ignore-hosts\" ] || [ \"$key\" = \"port\" ] || [ \"$key\" = \"enabled\" ]; then\n    printf '%s\\n' \"$val\" > \"$file\"\n  else\n    printf \"'%s'\\n\" \"$val\" > \"$file\"\n  fi\n  exit 0\nfi\nexit 1\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_gsettings, fs::Permissions::from_mode(0o755)).unwrap();

        let pac_url = "http://127.0.0.1:8080/vdpi.pac";
        let snapshot =
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .unwrap();
        assert_eq!(snapshot, orig_ignore);

        let merged = merge_gsettings_ignore_hosts(Some(&snapshot), &[], &[]);
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            pac_url,
            Some(&merged),
            Some("none"),
            Some(""),
            Some(&snapshot),
            None
        ));

        let active_ignore =
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .unwrap();
        assert!(active_ignore.contains("'corp.internal'"));
        assert!(active_ignore.contains("'10.99.0.0/16'"));
        assert!(active_ignore.contains("'nmcheck.gnome.org'"));
        assert!(active_ignore.contains("'captive.apple.com'"));
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'auto'")
        );

        deactivate_gnome_with_bin(
            &fake_gsettings,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            pac_url,
            false,
            None,
            Some(&merged),
            Some("none"),
            Some(""),
            Some(&snapshot),
            None,
        );

        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .as_deref(),
            Some(orig_ignore)
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'none'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("''")
        );

        // User edits ignore-hosts while vdpi is running -> deactivate must not clobber user's edit.
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            pac_url,
            Some(&merged),
            Some("none"),
            Some(""),
            Some(&snapshot),
            None
        ));
        let user_edited = "['localhost', 'new-corp.example']";
        assert!(gsettings_set_with_bin(
            &fake_gsettings,
            "org.gnome.system.proxy",
            "ignore-hosts",
            user_edited,
            None
        ));
        deactivate_gnome_with_bin(
            &fake_gsettings,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            pac_url,
            false,
            None,
            Some(&merged),
            Some("none"),
            Some(""),
            Some(&snapshot),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .as_deref(),
            Some(user_edited)
        );

        // Crash-recovery path: persisted SavedLinuxProxyState restores ignore-hosts via clear_gnome_proxies_with_bin.
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            pac_url,
            Some(&merged),
            Some("none"),
            Some(""),
            Some(&snapshot),
            None
        ));
        let state_file = root.join("linux-proxy-state.json");
        let saved = SavedLinuxProxyState {
            gnome_ignore_hosts: Some(orig_ignore.to_string()),
            ..Default::default()
        };
        saved.save_to_path(&state_file, None).unwrap();
        let reloaded = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_gnome_proxies_with_bin(
            &fake_gsettings,
            reloaded.gnome_mode.as_deref(),
            reloaded.gnome_autoconfig_url.as_deref(),
            reloaded.gnome_ignore_hosts.as_deref(),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .as_deref(),
            Some(orig_ignore)
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'none'")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn kde_bypass_preservation_and_proxy_type_1_corporate_manual_safety() {
        // Pure decision logic for scoped KDE ProxyType reset
        assert!(should_reset_kde_proxy_type_scoped(true, false, Some("2")));
        assert!(!should_reset_kde_proxy_type_scoped(true, false, Some("1")));
        assert!(!should_reset_kde_proxy_type_scoped(true, false, Some("3")));
        assert!(!should_reset_kde_proxy_type_scoped(true, false, Some("0")));
        assert!(!should_reset_kde_proxy_type_scoped(true, false, None));
        assert!(should_reset_kde_proxy_type_scoped(false, true, Some("1")));
        assert!(!should_reset_kde_proxy_type_scoped(false, false, Some("2")));

        let root = std::env::temp_dir().join(format!(
            "vdpi-kde-bypass-and-ptype1-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let reader = bin_dir.join("kreadconfig6");
        let writer = bin_dir.join("kwriteconfig6");
        fs::write(
            &reader,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ -f \"$state_dir/$k\" ]; then\n  cat \"$state_dir/$k\"\nelse\n  echo \"\"\nfi\nexit 0\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::write(
            &writer,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ \"$7\" = \"--delete\" ]; then\n  rm -f \"$state_dir/$k\"\nelse\n  printf '%s\\n' \"$7\" > \"$state_dir/$k\"\nfi\nexit 0\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&writer, fs::Permissions::from_mode(0o755)).unwrap();

        let pac_url = "http://127.0.0.1:8080/vdpi.pac";
        let vdpi_no_proxy = build_no_proxy_value_with_includes(&[], &[]);

        // Scenario A: Pre-existing KDE NoProxyFor is merged on activate and restored on deactivate.
        let orig_no_proxy = "corp.internal,10.99.0.0/16";
        assert!(kde_write_proxy_key(&writer, "ProxyType", "0", None));
        assert!(kde_write_proxy_key(
            &writer,
            "NoProxyFor",
            orig_no_proxy,
            None
        ));

        let existing = kde_read_proxy_key(&reader, "NoProxyFor", None).unwrap();
        let snap = SavedKdeNoProxy::from_raw(&existing);
        assert_eq!(snap, SavedKdeNoProxy::Value(orig_no_proxy.to_string()));
        let merged = merge_kde_no_proxy_for(Some(&existing), &vdpi_no_proxy);

        assert!(configure_kde_proxy(
            &writer,
            pac_url,
            Some(&merged),
            None,
            Some(&snap),
            None
        ));
        let active_no_proxy = kde_read_proxy_key(&reader, "NoProxyFor", None).unwrap();
        assert!(active_no_proxy.contains("corp.internal"));
        assert!(active_no_proxy.contains("10.99.0.0/16"));
        assert!(active_no_proxy.contains("networkcheck.kde.org"));
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("2")
        );

        deactivate_kde_with_bins(
            &writer,
            Some(&reader),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            pac_url,
            false,
            None,
            Some(&merged),
            Some("0"),
            Some(""),
            Some(&snap),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("0")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some("")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "NoProxyFor", None).as_deref(),
            Some(orig_no_proxy)
        );

        // Scenario B: Unset KDE NoProxyFor is deleted on restore.
        assert!(kde_delete_proxy_key(&writer, "NoProxyFor", None));
        let empty_existing = kde_read_proxy_key(&reader, "NoProxyFor", None).unwrap();
        let unset_snap = SavedKdeNoProxy::from_raw(&empty_existing);
        assert_eq!(unset_snap, SavedKdeNoProxy::Unset);
        let merged_from_empty = merge_kde_no_proxy_for(Some(&empty_existing), &vdpi_no_proxy);
        assert!(configure_kde_proxy(
            &writer,
            pac_url,
            Some(&merged_from_empty),
            None,
            Some(&unset_snap),
            None
        ));
        assert!(!kde_read_proxy_key(&reader, "NoProxyFor", None)
            .unwrap()
            .is_empty());
        deactivate_kde_with_bins(
            &writer,
            Some(&reader),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            pac_url,
            false,
            None,
            Some(&merged_from_empty),
            Some("0"),
            Some(""),
            Some(&unset_snap),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "NoProxyFor", None).as_deref(),
            Some("")
        );

        // Scenario C: User switches to manual corporate proxy (ProxyType=1) while vdpi is running;
        // deactivate_scoped must preserve ProxyType=1 and corporate httpProxy/httpsProxy!
        assert!(kde_write_proxy_key(
            &writer,
            "NoProxyFor",
            orig_no_proxy,
            None
        ));
        assert!(configure_kde_proxy(
            &writer,
            pac_url,
            Some(&merged),
            None,
            Some(&snap),
            None
        ));
        assert!(kde_write_proxy_key(&writer, "ProxyType", "1", None));
        assert!(kde_write_proxy_key(
            &writer,
            "httpProxy",
            "http://proxy.corp.example 3128",
            None
        ));
        assert!(kde_write_proxy_key(
            &writer,
            "httpsProxy",
            "http://proxy.corp.example 3128",
            None
        ));

        deactivate_kde_with_bins(
            &writer,
            Some(&reader),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            pac_url,
            false,
            None,
            Some(&merged),
            Some("0"),
            Some(""),
            Some(&snap),
            None,
        );

        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("1"),
            "KDE ProxyType=1 corporate manual proxy must never be reset to 0"
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "httpProxy", None).as_deref(),
            Some("http://proxy.corp.example 3128")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "httpsProxy", None).as_deref(),
            Some("http://proxy.corp.example 3128")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some("")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "NoProxyFor", None).as_deref(),
            Some(orig_no_proxy)
        );

        // Scenario D: Crash recovery via persisted SavedLinuxProxyState restores KDE NoProxyFor.
        assert!(kde_delete_proxy_key(&writer, "httpProxy", None));
        assert!(kde_delete_proxy_key(&writer, "httpsProxy", None));
        assert!(configure_kde_proxy(
            &writer,
            pac_url,
            Some(&merged),
            None,
            Some(&snap),
            None
        ));
        let state_file = root.join("linux-proxy-state.json");
        let saved = SavedLinuxProxyState {
            kde_no_proxy_for: Some(snap.clone()),
            ..Default::default()
        };
        saved.save_to_path(&state_file, None).unwrap();
        let reloaded = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_kde_proxies_with_bins(
            &writer,
            Some(&reader),
            None,
            reloaded.kde_proxy_type.as_deref(),
            reloaded.kde_proxy_config_script.as_deref(),
            reloaded.kde_no_proxy_for.as_ref(),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("0")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some("")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "NoProxyFor", None).as_deref(),
            Some(orig_no_proxy)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corporate_gnome_pac_and_manual_proxy_snapshot_and_restore() {
        // Sanitization never saves a stale vdpi PAC as a restore target
        assert_eq!(
            sanitize_gnome_restore_targets(
                Some("'auto'"),
                Some("'http://127.0.0.1:8080/vdpi.pac'")
            ),
            ("none", "")
        );
        assert_eq!(
            sanitize_gnome_restore_targets(
                Some("'manual'"),
                Some("'http://127.0.0.1:8080/vdpi.pac'")
            ),
            ("manual", "")
        );
        assert_eq!(
            sanitize_gnome_restore_targets(
                Some("'auto'"),
                Some("'https://corp.example/wpad.dat'")
            ),
            ("auto", "https://corp.example/wpad.dat")
        );

        let root = std::env::temp_dir().join(format!(
            "vdpi-corp-gnome-restore-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        fs::create_dir_all(&state_dir).unwrap();

        let fake_gsettings = root.join("gsettings");
        fs::write(
            &fake_gsettings,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\ncmd=\"$1\"\nschema=\"$2\"\nkey=\"$3\"\nfile=\"$state_dir/$schema.$key\"\nif [ \"$cmd\" = \"get\" ]; then\n  if [ -f \"$file\" ]; then\n    cat \"$file\"\n  else\n    echo \"''\"\n  fi\n  exit 0\nfi\nif [ \"$cmd\" = \"set\" ]; then\n  val=\"$4\"\n  if [ \"$key\" = \"ignore-hosts\" ] || [ \"$key\" = \"port\" ] || [ \"$key\" = \"enabled\" ]; then\n    printf '%s\\n' \"$val\" > \"$file\"\n  else\n    printf \"'%s'\\n\" \"$val\" > \"$file\"\n  fi\n  exit 0\nfi\nexit 1\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_gsettings, fs::Permissions::from_mode(0o755)).unwrap();

        let vdpi_pac = "http://127.0.0.1:8080/vdpi.pac";
        let corp_pac = "https://corp.example/wpad.dat";
        let orig_ignore = "['localhost', 'corp.internal']";

        // Scenario 1: Pre-existing corporate GNOME PAC -> snapshot -> activate -> deactivate + crash recovery
        fs::write(state_dir.join("org.gnome.system.proxy.mode"), "'auto'\n").unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.autoconfig-url"),
            format!("'{corp_pac}'\n"),
        )
        .unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.ignore-hosts"),
            format!("{orig_ignore}\n"),
        )
        .unwrap();

        let snap = snapshot_gnome_proxy_with_bin(&fake_gsettings, None).unwrap();
        assert_eq!(snap.mode.as_deref(), Some("auto"));
        assert_eq!(snap.autoconfig_url.as_deref(), Some(corp_pac));
        assert_eq!(snap.ignore_hosts.as_deref(), Some(orig_ignore));

        let mut saved_state = SavedLinuxProxyState::default();
        saved_state.record_gnome_if_absent(&snap);
        let state_file = root.join("linux-proxy-state.json");
        saved_state.save_to_path(&state_file, None).unwrap();

        let merged = merge_gsettings_ignore_hosts(snap.ignore_hosts.as_deref(), &[], &[]);
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            vdpi_pac,
            Some(&merged),
            snap.mode.as_deref(),
            snap.autoconfig_url.as_deref(),
            snap.ignore_hosts.as_deref(),
            None,
        ));
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("'http://127.0.0.1:8080/vdpi.pac'")
        );

        deactivate_gnome_with_bin(
            &fake_gsettings,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            vdpi_pac,
            false,
            None,
            Some(&merged),
            saved_state.gnome_mode.as_deref(),
            saved_state.gnome_autoconfig_url.as_deref(),
            saved_state.gnome_ignore_hosts.as_deref(),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'auto'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("'https://corp.example/wpad.dat'")
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "ignore-hosts", None)
                .as_deref(),
            Some(orig_ignore)
        );

        // Crash recovery restores corporate GNOME PAC from persisted SavedLinuxProxyState
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            vdpi_pac,
            Some(&merged),
            snap.mode.as_deref(),
            snap.autoconfig_url.as_deref(),
            snap.ignore_hosts.as_deref(),
            None,
        ));
        let reloaded = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_gnome_proxies_with_bin(
            &fake_gsettings,
            reloaded.gnome_mode.as_deref(),
            reloaded.gnome_autoconfig_url.as_deref(),
            reloaded.gnome_ignore_hosts.as_deref(),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'auto'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("'https://corp.example/wpad.dat'")
        );

        // Scenario 2: Pre-existing corporate GNOME manual proxy -> snapshot -> activate -> deactivate + crash recovery
        fs::write(state_dir.join("org.gnome.system.proxy.mode"), "'manual'\n").unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.autoconfig-url"),
            "''\n",
        )
        .unwrap();
        fs::write(
            state_dir.join("org.gnome.system.proxy.http.host"),
            "'proxy.corp.example'\n",
        )
        .unwrap();
        fs::write(state_dir.join("org.gnome.system.proxy.http.port"), "3128\n").unwrap();

        let manual_snap = snapshot_gnome_proxy_with_bin(&fake_gsettings, None).unwrap();
        assert_eq!(manual_snap.mode.as_deref(), Some("manual"));
        assert_eq!(manual_snap.autoconfig_url.as_deref(), Some(""));

        let mut manual_state = SavedLinuxProxyState::default();
        manual_state.record_gnome_if_absent(&manual_snap);
        manual_state.save_to_path(&state_file, None).unwrap();

        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            vdpi_pac,
            Some(&merged),
            manual_snap.mode.as_deref(),
            manual_snap.autoconfig_url.as_deref(),
            manual_snap.ignore_hosts.as_deref(),
            None,
        ));
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy.http", "host", None)
                .as_deref(),
            Some("'proxy.corp.example'"),
            "corporate manual host must not be cleared on activation"
        );

        deactivate_gnome_with_bin(
            &fake_gsettings,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            vdpi_pac,
            false,
            None,
            Some(&merged),
            manual_state.gnome_mode.as_deref(),
            manual_state.gnome_autoconfig_url.as_deref(),
            manual_state.gnome_ignore_hosts.as_deref(),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'manual'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("''")
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy.http", "host", None)
                .as_deref(),
            Some("'proxy.corp.example'")
        );

        // Crash recovery restores corporate GNOME manual proxy
        assert!(configure_gnome_proxy_with_bin(
            &fake_gsettings,
            vdpi_pac,
            Some(&merged),
            manual_snap.mode.as_deref(),
            manual_snap.autoconfig_url.as_deref(),
            manual_snap.ignore_hosts.as_deref(),
            None,
        ));
        let reloaded_manual = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_gnome_proxies_with_bin(
            &fake_gsettings,
            reloaded_manual.gnome_mode.as_deref(),
            reloaded_manual.gnome_autoconfig_url.as_deref(),
            reloaded_manual.gnome_ignore_hosts.as_deref(),
            None,
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'manual'")
        );
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy.http", "host", None)
                .as_deref(),
            Some("'proxy.corp.example'")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn corporate_kde_pac_and_manual_proxy_snapshot_and_restore() {
        // Sanitization never saves a stale vdpi PAC as a restore target
        assert_eq!(
            sanitize_kde_restore_targets(Some("2"), Some("http://127.0.0.1:8080/vdpi.pac")),
            ("0", None)
        );
        assert_eq!(
            sanitize_kde_restore_targets(Some("1"), Some("http://127.0.0.1:8080/vdpi.pac")),
            ("1", None)
        );
        assert_eq!(
            sanitize_kde_restore_targets(Some("2"), Some("https://corp.example/proxy.pac")),
            ("2", Some("https://corp.example/proxy.pac"))
        );

        let root = std::env::temp_dir().join(format!(
            "vdpi-corp-kde-restore-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let state_dir = root.join("state");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&state_dir).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let reader = bin_dir.join("kreadconfig6");
        let writer = bin_dir.join("kwriteconfig6");
        fs::write(
            &reader,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ -f \"$state_dir/$k\" ]; then\n  cat \"$state_dir/$k\"\nelse\n  echo \"\"\nfi\nexit 0\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::write(
            &writer,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ \"$7\" = \"--delete\" ]; then\n  rm -f \"$state_dir/$k\"\nelse\n  printf '%s\\n' \"$7\" > \"$state_dir/$k\"\nfi\nexit 0\n",
                state_dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&writer, fs::Permissions::from_mode(0o755)).unwrap();

        let vdpi_pac = "http://127.0.0.1:8080/vdpi.pac";
        let corp_pac = "https://corp.example/proxy.pac";
        let orig_no_proxy = "corp.internal,10.99.0.0/16";
        let vdpi_no_proxy = build_no_proxy_value_with_includes(&[], &[]);
        let merged = merge_kde_no_proxy_for(Some(orig_no_proxy), &vdpi_no_proxy);
        let state_file = root.join("linux-proxy-state.json");

        // Scenario 1: Pre-existing corporate KDE PAC -> snapshot -> activate -> deactivate + crash recovery
        assert!(kde_write_proxy_key(&writer, "ProxyType", "2", None));
        assert!(kde_write_proxy_key(
            &writer,
            "Proxy Config Script",
            corp_pac,
            None
        ));
        assert!(kde_write_proxy_key(
            &writer,
            "NoProxyFor",
            orig_no_proxy,
            None
        ));

        let snap = snapshot_kde_proxy_with_reader(&reader, None);
        assert_eq!(snap.proxy_type.as_deref(), Some("2"));
        assert_eq!(snap.proxy_config_script.as_deref(), Some(corp_pac));
        assert_eq!(
            snap.no_proxy_for,
            Some(SavedKdeNoProxy::Value(orig_no_proxy.to_string()))
        );

        let mut saved_state = SavedLinuxProxyState::default();
        saved_state.record_kde_if_absent(&snap);
        saved_state.save_to_path(&state_file, None).unwrap();

        assert!(configure_kde_proxy(
            &writer,
            vdpi_pac,
            Some(&merged),
            snap.proxy_config_script.as_deref(),
            snap.no_proxy_for.as_ref(),
            None,
        ));
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some(vdpi_pac)
        );

        deactivate_kde_with_bins(
            &writer,
            Some(&reader),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            vdpi_pac,
            false,
            None,
            Some(&merged),
            saved_state.kde_proxy_type.as_deref(),
            saved_state.kde_proxy_config_script.as_deref(),
            saved_state.kde_no_proxy_for.as_ref(),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("2")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some(corp_pac)
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "NoProxyFor", None).as_deref(),
            Some(orig_no_proxy)
        );

        // Crash recovery restores corporate KDE PAC
        assert!(configure_kde_proxy(
            &writer,
            vdpi_pac,
            Some(&merged),
            snap.proxy_config_script.as_deref(),
            snap.no_proxy_for.as_ref(),
            None,
        ));
        let reloaded = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_kde_proxies_with_bins(
            &writer,
            Some(&reader),
            None,
            reloaded.kde_proxy_type.as_deref(),
            reloaded.kde_proxy_config_script.as_deref(),
            reloaded.kde_no_proxy_for.as_ref(),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("2")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some(corp_pac)
        );

        // Scenario 2: Pre-existing corporate KDE manual proxy -> snapshot -> activate -> deactivate + crash recovery
        assert!(kde_write_proxy_key(&writer, "ProxyType", "1", None));
        assert!(kde_delete_proxy_key(&writer, "Proxy Config Script", None));
        assert!(kde_write_proxy_key(
            &writer,
            "httpProxy",
            "http://proxy.corp.example 3128",
            None
        ));
        assert!(kde_write_proxy_key(
            &writer,
            "httpsProxy",
            "http://proxy.corp.example 3128",
            None
        ));

        let manual_snap = snapshot_kde_proxy_with_reader(&reader, None);
        assert_eq!(manual_snap.proxy_type.as_deref(), Some("1"));
        assert_eq!(manual_snap.proxy_config_script.as_deref(), Some(""));

        let mut manual_state = SavedLinuxProxyState::default();
        manual_state.record_kde_if_absent(&manual_snap);
        manual_state.save_to_path(&state_file, None).unwrap();

        assert!(configure_kde_proxy(
            &writer,
            vdpi_pac,
            Some(&merged),
            manual_snap.proxy_config_script.as_deref(),
            manual_snap.no_proxy_for.as_ref(),
            None,
        ));
        assert_eq!(
            kde_read_proxy_key(&reader, "httpProxy", None).as_deref(),
            Some("http://proxy.corp.example 3128")
        );

        deactivate_kde_with_bins(
            &writer,
            Some(&reader),
            None,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8080,
            vdpi_pac,
            false,
            None,
            Some(&merged),
            manual_state.kde_proxy_type.as_deref(),
            manual_state.kde_proxy_config_script.as_deref(),
            manual_state.kde_no_proxy_for.as_ref(),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("1")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some("")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "httpProxy", None).as_deref(),
            Some("http://proxy.corp.example 3128")
        );

        // Crash recovery restores corporate KDE manual proxy
        assert!(configure_kde_proxy(
            &writer,
            vdpi_pac,
            Some(&merged),
            manual_snap.proxy_config_script.as_deref(),
            manual_snap.no_proxy_for.as_ref(),
            None,
        ));
        let reloaded_manual = SavedLinuxProxyState::load_from_path(&state_file, None)
            .unwrap()
            .unwrap();
        clear_kde_proxies_with_bins(
            &writer,
            Some(&reader),
            None,
            reloaded_manual.kde_proxy_type.as_deref(),
            reloaded_manual.kde_proxy_config_script.as_deref(),
            reloaded_manual.kde_no_proxy_for.as_ref(),
            None,
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("1")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "httpProxy", None).as_deref(),
            Some("http://proxy.corp.example 3128")
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn reconcile_refuses_to_clobber_mid_session_corporate_proxy_switches() {
        let pac_url = "http://127.0.0.1:8080/vdpi.pac";

        // Pure decision logic: GNOME
        assert!(!should_reconcile_gnome(
            Some("'auto'"),
            Some("'http://127.0.0.1:8080/vdpi.pac'"),
            pac_url
        ));
        assert!(!should_reconcile_gnome(
            Some("'manual'"),
            Some("''"),
            pac_url
        ));
        assert!(!should_reconcile_gnome(
            Some("'manual'"),
            Some("'http://127.0.0.1:8080/vdpi.pac'"),
            pac_url
        ));
        assert!(!should_reconcile_gnome(
            Some("'auto'"),
            Some("'https://corp.example/wpad.dat'"),
            pac_url
        ));
        assert!(!should_reconcile_gnome(Some("'auto'"), Some("''"), pac_url));
        assert!(!should_reconcile_gnome(Some("'auto'"), Some(""), pac_url));
        assert!(!should_reconcile_gnome(
            Some("'none'"),
            Some("'https://corp.example/wpad.dat'"),
            pac_url
        ));
        assert!(!should_reconcile_gnome(None, Some("''"), pac_url));
        assert!(!should_reconcile_gnome(Some("'none'"), None, pac_url));
        assert!(should_reconcile_gnome(Some("'none'"), Some("''"), pac_url));
        assert!(should_reconcile_gnome(
            Some("'none'"),
            Some("'http://127.0.0.1:8080/vdpi.pac'"),
            pac_url
        ));
        assert!(should_reconcile_gnome(
            Some("'auto'"),
            Some("'http://127.0.0.1:9999/vdpi.pac'"),
            pac_url
        ));

        // Pure decision logic: KDE
        assert!(!should_reconcile_kde(Some("2"), Some(pac_url), pac_url));
        assert!(!should_reconcile_kde(Some("1"), Some(""), pac_url));
        assert!(!should_reconcile_kde(Some("1"), Some(pac_url), pac_url));
        assert!(!should_reconcile_kde(Some("3"), Some(""), pac_url));
        assert!(!should_reconcile_kde(Some("4"), Some(""), pac_url));
        assert!(!should_reconcile_kde(
            Some("2"),
            Some("https://corp.example/proxy.pac"),
            pac_url
        ));
        assert!(!should_reconcile_kde(
            Some("0"),
            Some("https://corp.example/proxy.pac"),
            pac_url
        ));
        assert!(!should_reconcile_kde(None, Some(""), pac_url));
        assert!(!should_reconcile_kde(Some("0"), None, pac_url));
        assert!(should_reconcile_kde(Some("0"), Some(""), pac_url));
        assert!(should_reconcile_kde(Some(""), Some(""), pac_url));
        assert!(should_reconcile_kde(Some("0"), Some(pac_url), pac_url));
        assert!(should_reconcile_kde(
            Some("2"),
            Some("http://127.0.0.1:9999/vdpi.pac"),
            pac_url
        ));

        // End-to-end with fake gsettings & KDE binaries
        let root = std::env::temp_dir().join(format!(
            "vdpi-reconcile-non-clobber-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let gnome_dir = root.join("gnome");
        let kde_state = root.join("kde-state");
        let kde_bin = root.join("kde-bin");
        fs::create_dir_all(&gnome_dir).unwrap();
        fs::create_dir_all(&kde_state).unwrap();
        fs::create_dir_all(&kde_bin).unwrap();

        let fake_gsettings = root.join("gsettings");
        fs::write(
            &fake_gsettings,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\ncmd=\"$1\"\nschema=\"$2\"\nkey=\"$3\"\nfile=\"$state_dir/$schema.$key\"\nif [ \"$cmd\" = \"get\" ]; then\n  if [ -f \"$file\" ]; then\n    cat \"$file\"\n  else\n    echo \"''\"\n  fi\n  exit 0\nfi\nif [ \"$cmd\" = \"set\" ]; then\n  val=\"$4\"\n  if [ \"$key\" = \"ignore-hosts\" ] || [ \"$key\" = \"port\" ] || [ \"$key\" = \"enabled\" ]; then\n    printf '%s\\n' \"$val\" > \"$file\"\n  else\n    printf \"'%s'\\n\" \"$val\" > \"$file\"\n  fi\n  exit 0\nfi\nexit 1\n",
                gnome_dir.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fake_gsettings, fs::Permissions::from_mode(0o755)).unwrap();

        // GNOME switched to manual -> reconcile must NOT overwrite
        fs::write(gnome_dir.join("org.gnome.system.proxy.mode"), "'manual'\n").unwrap();
        fs::write(
            gnome_dir.join("org.gnome.system.proxy.autoconfig-url"),
            format!("'{pac_url}'\n"),
        )
        .unwrap();
        assert!(!reconcile_gnome_with_bin(
            &fake_gsettings,
            pac_url,
            None,
            Some("none"),
            Some(""),
            None,
            None
        ));
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'manual'")
        );

        // GNOME switched to corporate PAC -> reconcile must NOT overwrite
        fs::write(gnome_dir.join("org.gnome.system.proxy.mode"), "'auto'\n").unwrap();
        fs::write(
            gnome_dir.join("org.gnome.system.proxy.autoconfig-url"),
            "'https://corp.example/wpad.dat'\n",
        )
        .unwrap();
        assert!(!reconcile_gnome_with_bin(
            &fake_gsettings,
            pac_url,
            None,
            Some("none"),
            Some(""),
            None,
            None
        ));
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("'https://corp.example/wpad.dat'")
        );

        // GNOME switched to corporate WPAD auto-discovery (mode='auto', empty autoconfig-url)
        // -> reconcile must NOT overwrite (matches KDE ProxyType=3)
        fs::write(gnome_dir.join("org.gnome.system.proxy.mode"), "'auto'\n").unwrap();
        fs::write(
            gnome_dir.join("org.gnome.system.proxy.autoconfig-url"),
            "''\n",
        )
        .unwrap();
        assert!(!reconcile_gnome_with_bin(
            &fake_gsettings,
            pac_url,
            None,
            Some("none"),
            Some(""),
            None,
            None
        ));
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'auto'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("''")
        );

        // GNOME dropped to none -> reconcile re-applies vdpi PAC
        fs::write(gnome_dir.join("org.gnome.system.proxy.mode"), "'none'\n").unwrap();
        fs::write(
            gnome_dir.join("org.gnome.system.proxy.autoconfig-url"),
            "''\n",
        )
        .unwrap();
        assert!(reconcile_gnome_with_bin(
            &fake_gsettings,
            pac_url,
            None,
            Some("none"),
            Some(""),
            None,
            None
        ));
        assert_eq!(
            gsettings_get_with_bin(&fake_gsettings, "org.gnome.system.proxy", "mode", None)
                .as_deref(),
            Some("'auto'")
        );
        assert_eq!(
            gsettings_get_with_bin(
                &fake_gsettings,
                "org.gnome.system.proxy",
                "autoconfig-url",
                None
            )
            .as_deref(),
            Some("'http://127.0.0.1:8080/vdpi.pac'")
        );

        // KDE fake binaries
        let reader = kde_bin.join("kreadconfig6");
        let writer = kde_bin.join("kwriteconfig6");
        fs::write(
            &reader,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ -f \"$state_dir/$k\" ]; then\n  cat \"$state_dir/$k\"\nelse\n  echo \"\"\nfi\nexit 0\n",
                kde_state.display()
            ),
        )
        .unwrap();
        fs::write(
            &writer,
            format!(
                "#!/bin/sh\nstate_dir=\"{}\"\nk=$(printf '%s' \"$6\" | tr ' ' '_')\nif [ \"$7\" = \"--delete\" ]; then\n  rm -f \"$state_dir/$k\"\nelse\n  printf '%s\\n' \"$7\" > \"$state_dir/$k\"\nfi\nexit 0\n",
                kde_state.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&writer, fs::Permissions::from_mode(0o755)).unwrap();

        // KDE switched to ProxyType=1 (manual) -> reconcile must NOT overwrite
        assert!(kde_write_proxy_key(&writer, "ProxyType", "1", None));
        assert!(kde_write_proxy_key(
            &writer,
            "Proxy Config Script",
            pac_url,
            None
        ));
        assert!(!reconcile_kde_with_bins(
            &writer,
            Some(&reader),
            pac_url,
            None,
            None,
            None,
            None
        ));
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("1")
        );

        // KDE switched to corporate PAC script -> reconcile must NOT overwrite
        assert!(kde_write_proxy_key(&writer, "ProxyType", "2", None));
        assert!(kde_write_proxy_key(
            &writer,
            "Proxy Config Script",
            "https://corp.example/proxy.pac",
            None
        ));
        assert!(!reconcile_kde_with_bins(
            &writer,
            Some(&reader),
            pac_url,
            None,
            None,
            None,
            None
        ));
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some("https://corp.example/proxy.pac")
        );

        // KDE reset to ProxyType=0 -> reconcile re-applies vdpi PAC
        assert!(kde_write_proxy_key(&writer, "ProxyType", "0", None));
        assert!(kde_delete_proxy_key(&writer, "Proxy Config Script", None));
        assert!(reconcile_kde_with_bins(
            &writer,
            Some(&reader),
            pac_url,
            None,
            None,
            None,
            None
        ));
        assert_eq!(
            kde_read_proxy_key(&reader, "ProxyType", None).as_deref(),
            Some("2")
        );
        assert_eq!(
            kde_read_proxy_key(&reader, "Proxy Config Script", None).as_deref(),
            Some(pac_url)
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cli_include_domains_override_config_for_no_proxy_kde_and_gnome() {
        // Non-empty CLI --include overrides config include_domains (no stale config unioning).
        let mut config_loaded = false;
        let cli_override = resolve_include_domains(
            &[
                r" \.gov\.tr$ ".to_string(),
                r"\.gov\.tr$".to_string(),
                "www.isbank.com.tr".to_string(),
                "   ".to_string(),
            ],
            || {
                config_loaded = true;
                vec![r"\.org\.tr$".to_string()]
            },
        );
        assert!(
            !config_loaded,
            "non-empty CLI include_domains must override without loading config defaults"
        );
        assert_eq!(
            cli_override,
            vec![r"\.gov\.tr$".to_string(), "www.isbank.com.tr".to_string()]
        );

        // Empty or whitespace-only CLI include_domains falls back to config include_domains.
        let fallback = resolve_include_domains(&["  ".to_string()], || {
            vec![
                r" \.org\.tr$ ".to_string(),
                r"\.org\.tr$".to_string(),
                "".to_string(),
            ]
        });
        assert_eq!(fallback, vec![r"\.org\.tr$".to_string()]);

        // NO_PROXY and KDE NoProxyFor honor CLI override without unioning stale config .org.tr.
        let no_proxy = build_no_proxy_value_with_includes(&[], &cli_override);
        let entries: Vec<&str> = no_proxy.split(',').collect();
        assert!(
            !entries.iter().any(|e| e.eq_ignore_ascii_case(".gov.tr")),
            "CLI --include must override .gov.tr in NO_PROXY: {no_proxy}"
        );
        assert!(
            !entries
                .iter()
                .any(|e| e.eq_ignore_ascii_case(".isbank.com.tr")),
            "CLI --include must override .isbank.com.tr in NO_PROXY: {no_proxy}"
        );
        assert!(
            entries.iter().any(|e| e.eq_ignore_ascii_case(".org.tr")),
            "stale config .org.tr must remain bypassed when CLI --include overrides: {no_proxy}"
        );

        let kde_no_proxy = merge_kde_no_proxy_for(Some("corp.internal"), &no_proxy);
        let kde_entries: Vec<&str> = kde_no_proxy.split(',').collect();
        assert!(kde_entries.contains(&"corp.internal"));
        assert!(!kde_entries.iter().any(|e| e.eq_ignore_ascii_case(".gov.tr")));
        assert!(!kde_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(".isbank.com.tr")));
        assert!(kde_entries.iter().any(|e| e.eq_ignore_ascii_case(".org.tr")));

        // GNOME ignore-hosts filters GNOME_BASELINE_IGNORE_HOSTS against effective_includes.
        let gnome_merged = merge_gsettings_ignore_hosts(
            Some("['localhost', 'corp.internal']"),
            &["blocked.gov.tr".to_string()],
            &cli_override,
        );
        let gnome_entries = parse_gsettings_string_array(&gnome_merged);
        assert!(
            !gnome_entries.iter().any(|e| e.eq_ignore_ascii_case(".gov.tr")),
            "CLI --include must override .gov.tr in GNOME ignore-hosts: {gnome_merged}"
        );
        assert!(
            !gnome_entries
                .iter()
                .any(|e| e.eq_ignore_ascii_case(".isbank.com.tr")),
            "CLI --include must override .isbank.com.tr in GNOME ignore-hosts: {gnome_merged}"
        );
        assert!(gnome_entries.iter().any(|e| e == "corp.internal"));
        assert!(gnome_entries.iter().any(|e| e == "blocked.gov.tr"));
        assert!(gnome_entries.iter().any(|e| e == "localhost"));
        assert!(gnome_entries.iter().any(|e| e == "192.0.0.0/24"));
        assert!(gnome_entries.iter().any(|e| e == ".ts.net"));

        // Broad --include must still preserve all local namespaces and IP/CIDR entries in GNOME.
        let gnome_broad = merge_gsettings_ignore_hosts(
            Some("@as []"),
            &[],
            &[r"localhost$".to_string(), r".*".to_string()],
        );
        let broad_entries = parse_gsettings_string_array(&gnome_broad);
        for local in [
            "localhost",
            "127.0.0.0/8",
            "0.0.0.0",
            "::1",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "172.16.0.0/12",
            "192.0.0.0/24",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "fc00::/7",
            "fe80::/10",
            ".localhost",
            ".localdomain",
            ".local",
            ".lan",
            ".internal",
            ".home.arpa",
            ".ts.net",
        ] {
            assert!(
                broad_entries.iter().any(|e| e.eq_ignore_ascii_case(local)),
                "expected local/IP entry `{local}` to remain in GNOME ignore-hosts: {gnome_broad}"
            );
        }
        assert!(!broad_entries.iter().any(|e| e.eq_ignore_ascii_case(".gov.tr")));
        assert!(!broad_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(".isbank.com.tr")));
        assert!(!broad_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case("neverssl.com")));

        // False-positive guard: unrelated regex groups/prefixes must not strip .gov.tr.
        let gnome_unrelated = merge_gsettings_ignore_hosts(
            None,
            &[],
            &[
                r"(gov|discord)\.example\.com$".to_string(),
                r"gov\.tr\.(example|test)\.com$".to_string(),
            ],
        );
        let unrelated_entries = parse_gsettings_string_array(&gnome_unrelated);
        assert!(unrelated_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(".gov.tr")));
        assert!(unrelated_entries
            .iter()
            .any(|e| e.eq_ignore_ascii_case(".isbank.com.tr")));
    }

    #[test]
    fn write_state_file_atomic_rejects_symlinks_and_parent_traversal_under_sudo_home() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "vdpi-linux-state-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside_dir = base.join("outside");
        fs::create_dir_all(&fake_home).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let sudo_ctx = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            fake_home.clone(),
            None,
            None,
        );

        // Normal directory under invoking user's home succeeds and can be updated atomically.
        let real_state = fake_home.join(".vdpi").join("linux-proxy-state.json");
        assert!(ensure_no_symlink_under_home(&real_state, &fake_home).is_ok());
        write_state_file_atomic(&real_state, "{\"v\":1}", Some(&sudo_ctx)).unwrap();
        assert_eq!(fs::read_to_string(&real_state).unwrap(), "{\"v\":1}");
        write_state_file_atomic(&real_state, "{\"v\":2}", Some(&sudo_ctx)).unwrap();
        assert_eq!(fs::read_to_string(&real_state).unwrap(), "{\"v\":2}");

        // Intermediate symlink under user's home is rejected (both direct and nested).
        let link_subdir = fake_home.join(".vdpi-link");
        symlink(&outside_dir, &link_subdir).unwrap();
        let through_link = link_subdir.join("linux-proxy-state.json");
        assert!(ensure_no_symlink_under_home(&through_link, &fake_home).is_err());
        assert!(write_state_file_atomic(&through_link, "{}", Some(&sudo_ctx)).is_err());
        assert!(!outside_dir.join("linux-proxy-state.json").exists());

        let nested_through_link = link_subdir.join("nested").join("linux-proxy-state.json");
        assert!(ensure_no_symlink_under_home(&nested_through_link, &fake_home).is_err());
        assert!(write_state_file_atomic(&nested_through_link, "{}", Some(&sudo_ctx)).is_err());

        // Symlink at the target state file itself is rejected.
        let victim_file = outside_dir.join("victim.json");
        let target_link = fake_home.join(".vdpi").join("target-link.json");
        symlink(&victim_file, &target_link).unwrap();
        assert!(ensure_no_symlink_under_home(&target_link, &fake_home).is_err());
        assert!(write_state_file_atomic(&target_link, "{}", Some(&sudo_ctx)).is_err());
        assert!(!victim_file.exists());

        // Parent traversal `..` under user's home (even after a non-existent segment) is rejected.
        let dotdot_direct = fake_home.join("..").join("outside").join("escaped.json");
        assert!(ensure_no_symlink_under_home(&dotdot_direct, &fake_home).is_err());
        assert!(write_state_file_atomic(&dotdot_direct, "{}", Some(&sudo_ctx)).is_err());
        assert!(!outside_dir.join("escaped.json").exists());

        let dotdot_after_missing = fake_home
            .join("missing")
            .join("..")
            .join("..")
            .join("outside")
            .join("escaped2.json");
        assert!(ensure_no_symlink_under_home(&dotdot_after_missing, &fake_home).is_err());
        assert!(write_state_file_atomic(&dotdot_after_missing, "{}", Some(&sudo_ctx)).is_err());
        assert!(!outside_dir.join("escaped2.json").exists());

        // Paths outside user's home are unaffected by the home-subtree symlink guard.
        assert!(
            ensure_no_symlink_under_home(&outside_dir.join("linux-proxy-state.json"), &fake_home)
                .is_ok()
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn chown_to_sudo_ctx_enforces_home_allowlist_and_xdg_rejects_parent_dir() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "vdpi-linux-chown-allowlist-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let sibling_home = base.join("home2");
        let outside_dir = base.join("outside");
        fs::create_dir_all(fake_home.join(".vdpi")).unwrap();
        fs::create_dir_all(&sibling_home).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let state_file = fake_home.join(".vdpi").join("linux-proxy-state.json");
        let outside_file = outside_dir.join("system.conf");
        let sibling_file = sibling_home.join("file.json");
        fs::write(&state_file, "{}").unwrap();
        fs::write(&outside_file, "secret").unwrap();
        fs::write(&sibling_file, "{}").unwrap();

        let link_dir = fake_home.join(".vdpi-link");
        symlink(&outside_dir, &link_dir).unwrap();
        let file_link = fake_home.join(".vdpi").join("file-link.json");
        symlink(&outside_file, &file_link).unwrap();

        let xdg_traversal = fake_home.join("..").join("outside");
        let sudo_ctx = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            fake_home.clone(),
            Some(&xdg_traversal),
            None,
        );
        assert_eq!(
            sudo_ctx.xdg_config_home,
            fake_home.join(".config"),
            "XDG_CONFIG_HOME containing '..' must be rejected under sudo"
        );

        let nested_xdg_traversal = fake_home
            .join(".config")
            .join("..")
            .join("..")
            .join("outside");
        let sudo_ctx_nested = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            fake_home.clone(),
            Some(&nested_xdg_traversal),
            None,
        );
        assert_eq!(sudo_ctx_nested.xdg_config_home, fake_home.join(".config"));

        // Strict home allowlist + symlink/traversal checks for chown_to_sudo_ctx.
        assert!(is_valid_sudo_chown_target(&state_file, &sudo_ctx));
        assert!(!is_valid_sudo_chown_target(&fake_home, &sudo_ctx));
        assert!(!is_valid_sudo_chown_target(&outside_file, &sudo_ctx));
        assert!(!is_valid_sudo_chown_target(&sibling_file, &sudo_ctx));
        assert!(!is_valid_sudo_chown_target(
            &fake_home.join("..").join("outside").join("system.conf"),
            &sudo_ctx
        ));
        assert!(!is_valid_sudo_chown_target(
            &link_dir.join("system.conf"),
            &sudo_ctx
        ));
        assert!(!is_valid_sudo_chown_target(&file_link, &sudo_ctx));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn load_from_path_and_remove_state_file_reject_symlinks_under_sudo_home() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "vdpi-linux-load-remove-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside_dir = base.join("outside");
        fs::create_dir_all(&fake_home).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let sudo_ctx = build_sudo_user_context(
            1000,
            1000,
            Some("alice".to_string()),
            fake_home.clone(),
            None,
            None,
        );

        // Normal state file under user's home loads and removes cleanly.
        let real_state = fake_home.join(".vdpi").join("linux-proxy-state.json");
        let expected = SavedLinuxProxyState {
            gnome_mode: Some("none".to_string()),
            ..Default::default()
        };
        expected.save_to_path(&real_state, Some(&sudo_ctx)).unwrap();
        assert_eq!(
            SavedLinuxProxyState::load_from_path(&real_state, Some(&sudo_ctx)).unwrap(),
            Some(expected)
        );
        remove_state_file(&real_state, Some(&sudo_ctx));
        assert!(!real_state.exists());

        // Victim file outside user's home must never be read or deleted via symlinks or '..'.
        let victim_file = outside_dir.join("victim.json");
        fs::write(&victim_file, r#"{"gnome_mode":"manual"}"#).unwrap();

        let link_subdir = fake_home.join(".vdpi-link");
        symlink(&outside_dir, &link_subdir).unwrap();
        let through_link = link_subdir.join("victim.json");
        assert!(SavedLinuxProxyState::load_from_path(&through_link, Some(&sudo_ctx)).is_err());
        remove_state_file(&through_link, Some(&sudo_ctx));
        assert!(victim_file.exists());

        let target_link = fake_home.join(".vdpi").join("target-link.json");
        symlink(&victim_file, &target_link).unwrap();
        assert!(SavedLinuxProxyState::load_from_path(&target_link, Some(&sudo_ctx)).is_err());
        remove_state_file(&target_link, Some(&sudo_ctx));
        assert!(fs::symlink_metadata(&target_link).is_ok());
        assert!(victim_file.exists());

        // Direct symlink outside home is also rejected by O_NOFOLLOW / symlink guard.
        let outside_link = outside_dir.join("outside-link.json");
        symlink(&victim_file, &outside_link).unwrap();
        assert!(SavedLinuxProxyState::load_from_path(&outside_link, Some(&sudo_ctx)).is_err());
        remove_state_file(&outside_link, Some(&sudo_ctx));
        assert!(fs::symlink_metadata(&outside_link).is_ok());
        assert!(victim_file.exists());

        // Parent traversal '..' under user's home is rejected on both load and remove.
        let dotdot = fake_home.join("..").join("outside").join("victim.json");
        assert!(SavedLinuxProxyState::load_from_path(&dotdot, Some(&sudo_ctx)).is_err());
        remove_state_file(&dotdot, Some(&sudo_ctx));
        assert!(victim_file.exists());

        let _ = fs::remove_dir_all(&base);
    }
}
