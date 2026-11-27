use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};
use vdpi_core::bypass::filter_pac_default_bypass_domains;
use vdpi_core::config::VpnCoexistence;

pub const PAC_PATH: &str = "/vdpi.pac";

const ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

const DEFAULT_MACOS_BYPASS_DOMAINS: &[&str] = &["*.local", "169.254/16"];

#[derive(Debug, Clone, Default)]
pub struct UnixProxyResetOutcome {
    pub proxy_changed: bool,
    pub env_changed: bool,
    pub skipped_privileges: bool,
    pub errors: Vec<String>,
}

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

fn is_loopback_server(server: &str) -> bool {
    let trimmed = server.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
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

fn is_loopback_proxy_env_value(val: &str) -> bool {
    let trimmed = val.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let authority = without_scheme
        .split_once('/')
        .map_or(without_scheme, |(auth, _)| auth);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, auth)| auth);
    is_loopback_authority(authority)
}

fn is_vdpi_owned_proxy_env_value(val: &str, expected_proxy_url: &str) -> bool {
    let val = val.trim().trim_end_matches('/');
    let expected = expected_proxy_url.trim().trim_end_matches('/');
    if val.eq_ignore_ascii_case(expected) {
        return true;
    }
    let expected_authority = expected
        .split_once("://")
        .map_or(expected, |(_, rest)| rest);
    let val_authority = val.split_once("://").map_or(val, |(_, rest)| rest);
    !expected_authority.is_empty() && val_authority.eq_ignore_ascii_case(expected_authority)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoProxyState {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualProxyState {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub port: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedServiceProxyState {
    pub service: String,
    #[serde(default)]
    pub autoproxy: AutoProxyState,
    #[serde(default)]
    pub webproxy: ManualProxyState,
    #[serde(default)]
    pub securewebproxy: ManualProxyState,
    #[serde(default)]
    pub socksfirewallproxy: ManualProxyState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypass_domains: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedMacosProxyState {
    #[serde(default)]
    pub services: Vec<SavedServiceProxyState>,
}

impl SavedMacosProxyState {
    pub fn find_service(&self, service: &str) -> Option<&SavedServiceProxyState> {
        self.services.iter().find(|s| s.service == service)
    }

    pub fn upsert_if_absent(&mut self, snapshot: SavedServiceProxyState) -> bool {
        if self.services.iter().any(|s| s.service == snapshot.service) {
            return false;
        }
        self.services.push(snapshot);
        true
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).context("failed to serialize macOS proxy state")?;
        write_file_atomic(path, &json)
    }

    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        #[cfg(unix)]
        {
            let elevated_user = resolve_elevated_user();
            load_from_path_with_home_guard(
                path,
                elevated_user.as_ref().and_then(|u| u.home_dir.as_deref()),
            )
        }
        #[cfg(not(unix))]
        {
            match fs::read_to_string(path) {
                Ok(raw) => {
                    let state = serde_json::from_str(&raw).with_context(|| {
                        format!(
                            "failed to deserialize macOS proxy state from {}",
                            path.display()
                        )
                    })?;
                    Ok(Some(state))
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
            }
        }
    }
}

#[cfg(unix)]
fn load_from_path_with_home_guard(
    path: &Path,
    home_dir: Option<&Path>,
) -> Result<Option<SavedMacosProxyState>> {
    if let Some(home_dir) = home_dir {
        ensure_no_intermediate_symlink_under_home(path, home_dir)?;
    }
    let raw = if home_dir.is_some() {
        use std::fs::OpenOptions;
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt;

        match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(mut file) => {
                let mut buf = String::new();
                file.read_to_string(&mut buf)
                    .with_context(|| format!("failed to read {}", path.display()))?;
                buf
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        }
    } else {
        match fs::read_to_string(path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| format!("failed to read {}", path.display()));
            }
        }
    };
    let state = serde_json::from_str(&raw).with_context(|| {
        format!(
            "failed to deserialize macOS proxy state from {}",
            path.display()
        )
    })?;
    Ok(Some(state))
}

fn macos_proxy_state_path() -> PathBuf {
    crate::service::vdpi_root_dir()
        .map(|root| root.join("macos-proxy-state.json"))
        .unwrap_or_else(|_| {
            PathBuf::from("/Library/Application Support/vdpi/macos-proxy-state.json")
        })
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct ElevationEnv {
    sudo_uid: Option<String>,
    sudo_gid: Option<String>,
    sudo_user: Option<String>,
    pkexec_uid: Option<String>,
    doas_user: Option<String>,
    real_uid: Option<libc::uid_t>,
    home: Option<PathBuf>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home_dir: PathBuf,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElevatedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home_dir: Option<PathBuf>,
}

#[cfg(unix)]
fn parse_nonzero_uid(raw: Option<&str>) -> Option<libc::uid_t> {
    raw.and_then(|s| s.trim().parse::<libc::uid_t>().ok())
        .filter(|&uid| uid != 0)
}

#[cfg(unix)]
fn parse_gid(raw: Option<&str>) -> Option<libc::gid_t> {
    raw.and_then(|s| s.trim().parse::<libc::gid_t>().ok())
}

#[cfg(unix)]
fn sanitize_elevated_username(raw: Option<&str>) -> Option<&str> {
    let trimmed = raw?.trim();
    if trimmed.is_empty()
        || trimmed == "root"
        || trimmed.contains('/')
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed)
}

#[cfg(unix)]
fn lookup_passwd_by_uid(uid: libc::uid_t) -> Option<PasswdEntry> {
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
    Some(PasswdEntry {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(unix)]
fn lookup_passwd_by_name(name: &str) -> Option<PasswdEntry> {
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
    Some(PasswdEntry {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(unix)]
fn resolve_elevated_user_from(
    env: &ElevationEnv,
    lookup_uid: impl Fn(libc::uid_t) -> Option<PasswdEntry>,
    lookup_name: impl Fn(&str) -> Option<PasswdEntry>,
) -> Option<ElevatedUser> {
    let sudo_gid = parse_gid(env.sudo_gid.as_deref());
    let fallback_home = env
        .home
        .as_deref()
        .filter(|h| {
            !h.as_os_str().is_empty() && *h != Path::new("/root") && *h != Path::new("/var/root")
        })
        .map(Path::to_path_buf);

    // 1. SUDO_UID (+ optional SUDO_GID)
    if let Some(uid) = parse_nonzero_uid(env.sudo_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = sudo_gid
            .or_else(|| entry.as_ref().map(|e| e.gid))
            .unwrap_or(libc::gid_t::MAX);
        let home_dir = entry.map(|e| e.home_dir).or(fallback_home);
        return Some(ElevatedUser { uid, gid, home_dir });
    }

    // 2. SUDO_USER (via getpwnam_r)
    if let Some(sudo_user) = sanitize_elevated_username(env.sudo_user.as_deref()) {
        if let Some(entry) = lookup_name(sudo_user).filter(|e| e.uid != 0) {
            let gid = sudo_gid.unwrap_or(entry.gid);
            return Some(ElevatedUser {
                uid: entry.uid,
                gid,
                home_dir: Some(entry.home_dir),
            });
        }
    }

    // 3. PKEXEC_UID
    if let Some(uid) = parse_nonzero_uid(env.pkexec_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = entry.as_ref().map(|e| e.gid).unwrap_or(libc::gid_t::MAX);
        let home_dir = entry.map(|e| e.home_dir).or(fallback_home);
        return Some(ElevatedUser { uid, gid, home_dir });
    }

    // 4. DOAS_USER (via getpwnam_r)
    if let Some(doas_user) = sanitize_elevated_username(env.doas_user.as_deref()) {
        if let Some(entry) = lookup_name(doas_user).filter(|e| e.uid != 0) {
            return Some(ElevatedUser {
                uid: entry.uid,
                gid: entry.gid,
                home_dir: Some(entry.home_dir),
            });
        }
    }

    // 5. Real UID fallback (e.g. macOS `osascript ... with administrator privileges`
    // where `geteuid() == 0` and SUDO_*/PKEXEC_*/DOAS_* are absent, while `getuid() != 0`).
    if let Some(uid) = env.real_uid.filter(|&uid| uid != 0) {
        let entry = lookup_uid(uid);
        let gid = entry.as_ref().map(|e| e.gid).unwrap_or(libc::gid_t::MAX);
        let home_dir = entry.map(|e| e.home_dir).or(fallback_home);
        return Some(ElevatedUser { uid, gid, home_dir });
    }

    None
}

#[cfg(unix)]
fn resolve_elevated_user() -> Option<ElevatedUser> {
    // SAFETY: `geteuid(2)` and `getuid(2)` are always safe to call and never fail.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let ruid = unsafe { libc::getuid() };
    let env = ElevationEnv {
        sudo_uid: std::env::var("SUDO_UID").ok(),
        sudo_gid: std::env::var("SUDO_GID").ok(),
        sudo_user: std::env::var("SUDO_USER").ok(),
        pkexec_uid: std::env::var("PKEXEC_UID").ok(),
        doas_user: std::env::var("DOAS_USER").ok(),
        real_uid: (ruid != 0).then_some(ruid),
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    resolve_elevated_user_from(&env, lookup_passwd_by_uid, lookup_passwd_by_name)
}

#[cfg(unix)]
fn resolve_console_desktop_user() -> Option<ElevatedUser> {
    use std::os::unix::fs::MetadataExt;

    let uid = fs::metadata("/dev/console").ok()?.uid();
    if uid == 0 {
        return None;
    }
    let entry = lookup_passwd_by_uid(uid);
    let gid = entry.as_ref().map(|e| e.gid).unwrap_or(libc::gid_t::MAX);
    let home_dir = entry.map(|e| e.home_dir);
    Some(ElevatedUser { uid, gid, home_dir })
}

#[cfg(unix)]
fn resolve_target_desktop_user() -> Option<ElevatedUser> {
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return resolve_elevated_user().or_else(resolve_console_desktop_user);
    }
    let entry = lookup_passwd_by_uid(euid);
    let gid = entry.as_ref().map(|e| e.gid).unwrap_or_else(|| {
        // SAFETY: `getegid(2)` is always safe to call and never fails.
        unsafe { libc::getegid() }
    });
    let home_dir = entry
        .map(|e| e.home_dir)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from));
    Some(ElevatedUser {
        uid: euid,
        gid,
        home_dir,
    })
}

#[cfg(unix)]
fn should_chown_state_path(path: &Path, home_dir: Option<&Path>) -> bool {
    let Some(home_dir) = home_dir.filter(|h| {
        !h.as_os_str().is_empty()
            && h.is_absolute()
            && *h != Path::new("/")
            && !h
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
    }) else {
        return false;
    };
    if path == home_dir || !path.starts_with(home_dir) {
        return false;
    }
    !path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

#[cfg(unix)]
fn lchown_to_elevated_user(path: &Path, user: &ElevatedUser) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path string; `lchown` never follows symlinks.
    let _ = unsafe { libc::lchown(c_path.as_ptr(), user.uid, user.gid) };
}

#[cfg(unix)]
fn ensure_no_intermediate_symlink_under_home(path: &Path, home_dir: &Path) -> Result<()> {
    let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    let Ok(rel) = parent.strip_prefix(home_dir) else {
        return Ok(());
    };
    let mut cur = home_dir.to_path_buf();
    for comp in rel.components() {
        match comp {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(part) => cur.push(part),
            std::path::Component::ParentDir => {
                anyhow::bail!(
                    "refusing to traverse parent component '..' under user home '{}' while running as root",
                    home_dir.display()
                );
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                anyhow::bail!(
                    "unexpected absolute path component under user home '{}'",
                    home_dir.display()
                );
            }
        }
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                anyhow::bail!(
                    "refusing to access path through intermediate symlink '{}' under user home while running as root",
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

fn write_file_atomic(path: &Path, contents: &str) -> Result<()> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    let elevated_user = resolve_elevated_user();

    #[cfg(unix)]
    if let Some(home_dir) = elevated_user.as_ref().and_then(|u| u.home_dir.as_deref()) {
        ensure_no_intermediate_symlink_under_home(path, home_dir)?;
    }

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        #[cfg(unix)]
        let missing_under_home: Vec<PathBuf> = if let Some(home_dir) = elevated_user
            .as_ref()
            .and_then(|u| u.home_dir.as_deref())
            .filter(|&home_dir| should_chown_state_path(path, Some(home_dir)))
        {
            let mut missing = Vec::new();
            let mut cur = parent.to_path_buf();
            while cur != home_dir && cur.starts_with(home_dir) {
                if fs::symlink_metadata(&cur).is_err() {
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
        };

        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;

        #[cfg(unix)]
        if let Some(home_dir) = elevated_user.as_ref().and_then(|u| u.home_dir.as_deref()) {
            ensure_no_intermediate_symlink_under_home(path, home_dir)?;
        }

        #[cfg(unix)]
        if let Some(ref user) = elevated_user {
            let home_dir = user.home_dir.as_deref();
            if should_chown_state_path(path, home_dir) {
                for created in &missing_under_home {
                    if should_chown_state_path(created, home_dir) {
                        lchown_to_elevated_user(created, user);
                    }
                }
                if should_chown_state_path(parent, home_dir) {
                    lchown_to_elevated_user(parent, user);
                }
            }
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("macos-proxy-state.json");

    #[cfg(unix)]
    let tmp_path = {
        use std::fs::OpenOptions;
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
            .and_then(|()| file.set_permissions(fs::Permissions::from_mode(0o600)))
            .with_context(|| format!("failed to write temporary state {}", tmp_path.display()))
        {
            drop(file);
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        drop(file);
        if let Some(ref user) = elevated_user {
            if should_chown_state_path(&tmp_path, user.home_dir.as_deref()) {
                lchown_to_elevated_user(&tmp_path, user);
            }
        }
        tmp_path
    };

    #[cfg(not(unix))]
    let tmp_path = {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp_path = parent.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));
        fs::write(&tmp_path, contents)
            .with_context(|| format!("failed to write temporary state {}", tmp_path.display()))?;
        tmp_path
    };

    #[cfg(unix)]
    if let Some(home_dir) = elevated_user.as_ref().and_then(|u| u.home_dir.as_deref()) {
        ensure_no_intermediate_symlink_under_home(path, home_dir)?;
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
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

#[cfg(unix)]
fn remove_state_file_with_home_guard(path: &Path, home_dir: Option<&Path>) -> bool {
    if let Some(home_dir) = home_dir {
        if let Err(err) = ensure_no_intermediate_symlink_under_home(path, home_dir) {
            warn!(
                path = %path.display(),
                error = %err,
                "refusing to remove macOS proxy state file through unsafe path"
            );
            return false;
        }
    }
    match fs::remove_file(path) {
        Ok(()) => true,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => {
            warn!(path = %path.display(), error = %err, "failed to remove macOS proxy state file");
            false
        }
    }
}

fn remove_state_file(path: &Path) {
    #[cfg(unix)]
    {
        let elevated_user = resolve_elevated_user();
        let _ = remove_state_file_with_home_guard(
            path,
            elevated_user.as_ref().and_then(|u| u.home_dir.as_deref()),
        );
    }
    #[cfg(not(unix))]
    {
        if let Err(err) = fs::remove_file(path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(path = %path.display(), error = %err, "failed to remove macOS proxy state file");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkServiceProxyStatus {
    pub service: String,
    pub auto_proxy_enabled: bool,
    pub auto_proxy_url: String,
    pub web_enabled: bool,
    pub web_server: String,
    pub web_port: String,
    pub secure_enabled: bool,
    pub secure_server: String,
    pub secure_port: String,
    pub socks_enabled: bool,
    pub socks_server: String,
    pub socks_port: String,
}

impl NetworkServiceProxyStatus {
    #[cfg(test)]
    fn to_saved_state(&self) -> SavedServiceProxyState {
        self.to_saved_state_with_bypass(None)
    }

    fn to_saved_state_with_bypass(
        &self,
        bypass_domains: Option<Vec<String>>,
    ) -> SavedServiceProxyState {
        let autoproxy = if is_vdpi_pac_url(&self.auto_proxy_url) {
            AutoProxyState::default()
        } else {
            AutoProxyState {
                url: self.auto_proxy_url.clone(),
                enabled: self.auto_proxy_enabled,
            }
        };

        let sanitize_manual = |enabled: bool, server: &str, port: &str| {
            if is_loopback_server(server) {
                ManualProxyState::default()
            } else {
                ManualProxyState {
                    enabled,
                    server: server.to_string(),
                    port: port.to_string(),
                }
            }
        };

        SavedServiceProxyState {
            service: self.service.clone(),
            autoproxy,
            webproxy: sanitize_manual(self.web_enabled, &self.web_server, &self.web_port),
            securewebproxy: sanitize_manual(
                self.secure_enabled,
                &self.secure_server,
                &self.secure_port,
            ),
            socksfirewallproxy: sanitize_manual(
                self.socks_enabled,
                &self.socks_server,
                &self.socks_port,
            ),
            bypass_domains,
        }
    }
}

fn should_skip_proxy_for_vpn(mode: VpnCoexistence) -> bool {
    mode == VpnCoexistence::AutoYield
}

fn load_effective_vpn_coexistence() -> VpnCoexistence {
    let user_path = crate::service::vdpi_root_dir()
        .map(|root| root.join("config.toml"))
        .unwrap_or_else(|_| crate::config_file::user_config_path());
    if let Some(mode) = crate::config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, cfg)| cfg.vpn_coexistence)
    {
        return mode;
    }
    let sys_path = crate::config_file::system_config_path();
    if let Some(mode) = crate::config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, cfg)| cfg.vpn_coexistence)
    {
        return mode;
    }
    VpnCoexistence::default()
}

fn load_effective_include_domains() -> Vec<String> {
    let user_path = crate::service::vdpi_root_dir()
        .map(|root| root.join("config.toml"))
        .unwrap_or_else(|_| crate::config_file::user_config_path());
    if let Some(domains) = crate::config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, cfg)| cfg.include_domains)
    {
        return domains;
    }
    let sys_path = crate::config_file::system_config_path();
    if let Some(domains) = crate::config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, cfg)| cfg.include_domains)
    {
        return domains;
    }
    Vec::new()
}

#[derive(Debug, Clone)]
pub struct MacosProxySession {
    pac_url: String,
    services: Vec<String>,
    saved_state: SavedMacosProxyState,
    extra_bypass: Vec<String>,
    include_domains: Vec<String>,
    activated: bool,
    skipped_for_vpn: bool,
    vpn_coexistence: VpnCoexistence,
}

impl MacosProxySession {
    /// Applies macOS fail-open AutoProxyURL (PAC) settings via `networksetup` across active
    /// physical/Wi-Fi network services, disables legacy fail-closed loopback HTTP/HTTPS/SOCKS
    /// proxies and `launchctl` env vars, and snapshots previous per-service proxy state so
    /// even `kill -9` or crash fails open cleanly to `DIRECT`. Skips overriding proxy settings
    /// while a full-tunnel VPN is active only when `vpn_coexistence` is `AutoYield`.
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_launchd_env: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        Self::activate_with_vpn_coexistence(
            addr,
            http_port,
            socks_port,
            enable_socks_system_proxy,
            enable_launchd_env,
            extra_bypass,
            load_effective_vpn_coexistence(),
        )
    }

    pub fn activate_with_vpn_coexistence(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_launchd_env: bool,
        extra_bypass: &[String],
        vpn_coexistence: VpnCoexistence,
    ) -> Result<Self> {
        let include_domains = load_effective_include_domains();
        Self::activate_with_options(
            addr,
            http_port,
            socks_port,
            enable_socks_system_proxy,
            enable_launchd_env,
            extra_bypass,
            &include_domains,
            vpn_coexistence,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn activate_with_options(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
        include_domains: &[String],
        vpn_coexistence: VpnCoexistence,
    ) -> Result<Self> {
        let pac_url = format_pac_url(addr, http_port);
        let services = list_configurable_network_services().unwrap_or_default();

        if enable_socks_system_proxy {
            debug!(
                socks_port = ?socks_port,
                "ignoring fail-closed SOCKS5 system proxy on macOS in favor of fail-open PAC"
            );
        }
        if enable_env_proxy {
            debug!(
                "skipping fail-closed launchd HTTP_PROXY/HTTPS_PROXY persistence on macOS; cleaning stale loopback env vars"
            );
        }

        if should_skip_proxy_for_vpn(vpn_coexistence) && is_vpn_default_route_active() {
            info!(
                services = ?services,
                pac_url = %pac_url,
                http_port = http_port,
                socks_port = ?socks_port,
                "full-tunnel VPN active; skipping macOS system proxy activation"
            );
            return Ok(Self {
                pac_url,
                services: Vec::new(),
                saved_state: SavedMacosProxyState::default(),
                extra_bypass: extra_bypass.to_vec(),
                include_domains: include_domains.to_vec(),
                activated: false,
                skipped_for_vpn: true,
                vpn_coexistence,
            });
        } else if vpn_coexistence == VpnCoexistence::Warn && is_vpn_default_route_active() {
            warn!(
                services = ?services,
                pac_url = %pac_url,
                "full-tunnel VPN active (vpn_coexistence=warn); activating macOS system proxy anyway"
            );
        }

        let state_path = macos_proxy_state_path();
        let had_existing_state = state_path.exists();
        let mut saved_state = SavedMacosProxyState::load_from_path(&state_path)
            .unwrap_or_else(|e| {
                warn!(path = %state_path.display(), error = %e, "failed to load previous macOS proxy state");
                None
            })
            .unwrap_or_default();

        let mut snapshots = Vec::with_capacity(services.len());
        for svc in &services {
            let status = inspect_single_service_proxy(svc);
            let existing_bypass = match get_proxy_bypass_domains(svc) {
                Ok(domains) => Some(domains),
                Err(e) => {
                    warn!(
                        service = %svc,
                        error = %e,
                        "failed to read existing proxy bypass domains; skipping bypass domain snapshot and update"
                    );
                    None
                }
            };
            saved_state.upsert_if_absent(status.to_saved_state_with_bypass(existing_bypass.clone()));
            snapshots.push((status, existing_bypass));
        }

        if !saved_state.services.is_empty() {
            if let Err(e) = saved_state.save_to_path(&state_path) {
                warn!(path = %state_path.display(), error = %e, "failed to persist macOS proxy state snapshot");
            }
        }

        let mut configured_services = Vec::with_capacity(snapshots.len());
        for (st, existing_bypass) in &snapshots {
            let svc = st.service.as_str();
            let mut bypass_updated = false;
            if let Some(existing) = existing_bypass {
                let merged_svc = merge_service_bypass_domains_with_include(
                    existing,
                    extra_bypass,
                    include_domains,
                );
                match set_proxy_bypass_domains(svc, &merged_svc) {
                    Ok(()) => bypass_updated = true,
                    Err(e) => {
                        warn!(service = %svc, error = %e, "failed to update proxy bypass domains");
                    }
                }
            }

            disable_loopback_manual_proxies(st);

            match run_networksetup(&["-setautoproxyurl", svc, &pac_url])
                .and_then(|_| run_networksetup(&["-setautoproxystate", svc, "on"]))
            {
                Ok(_) => {
                    // Disable pre-existing manual HTTP/HTTPS/SOCKS proxies (already snapshotted
                    // into `saved_state` for restore on exit) so they do not override or run
                    // simultaneously alongside vdpi's AutoProxyURL.
                    disable_non_loopback_manual_proxies(st);
                    configured_services.push(svc.to_string());
                }
                Err(e) => {
                    warn!(service = %svc, error = %e, "failed to enable fail-open AutoProxyURL (PAC)");
                    if bypass_updated {
                        if let Some(original) = existing_bypass.as_deref() {
                            if let Err(restore_err) = set_proxy_bypass_domains(svc, original) {
                                warn!(
                                    service = %svc,
                                    error = %restore_err,
                                    "failed to roll back proxy bypass domains after PAC activation failure"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Never persist fail-closed launchctl HTTP_PROXY/HTTPS_PROXY; clean up stale loopback vars
        // left behind by older vdpi versions.
        unset_stale_loopback_launchd_proxy_env();

        if configured_services.is_empty() {
            if !had_existing_state {
                remove_state_file(&state_path);
            }
            warn!(
                services = ?services,
                pac_url = %pac_url,
                "macOS system proxy activation did not succeed on any network service (check administrator privileges or active network interfaces)"
            );
            anyhow::bail!(
                "macOS system proxy activation did not succeed on any network service (attempted: {:?}; check administrator privileges or active network interfaces)",
                services
            );
        }

        info!(
            services = ?configured_services,
            pac_url = %pac_url,
            http_port = http_port,
            socks_port = ?socks_port,
            "configured macOS fail-open PAC system proxy"
        );

        Ok(Self {
            pac_url,
            services: configured_services,
            saved_state,
            extra_bypass: extra_bypass.to_vec(),
            include_domains: include_domains.to_vec(),
            activated: true,
            skipped_for_vpn: false,
            vpn_coexistence,
        })
    }

    pub fn with_vpn_coexistence(mut self, mode: VpnCoexistence) -> Self {
        self.vpn_coexistence = mode;
        self
    }

    pub fn summary(&self) -> String {
        if !self.activated {
            if self.skipped_for_vpn {
                return "standby (full-tunnel VPN active; macOS system proxy skipped)".to_string();
            }
            return "inactive (macOS system proxy could not be applied to any network service)"
                .to_string();
        }
        format!(
            "active (macOS fail-open PAC {} on [{}])",
            self.pac_url,
            self.services.join(", ")
        )
    }

    /// Periodically verifies that sleep/wake cycles or VPN disconnects have not wiped
    /// fail-open PAC proxy settings on physical interfaces, and keeps legacy fail-closed
    /// loopback proxies off. Refuses to clobber mid-session user/MDM switches to a
    /// corporate PAC URL or manual corporate HTTP/HTTPS/SOCKS proxy. For newly attached
    /// interfaces, persists the pre-mutation state snapshot before applying baseline bypass
    /// domains and PAC. Avoids touching settings while a full-tunnel VPN is active when
    /// `vpn_coexistence` is `AutoYield`.
    pub fn reconcile(&self) {
        if should_skip_proxy_for_vpn(self.vpn_coexistence) && is_vpn_default_route_active() {
            debug!("full-tunnel VPN active; skipping macOS proxy reconciliation");
            return;
        }

        let state_path = macos_proxy_state_path();
        if let Ok(statuses) = inspect_service_proxies() {
            self.reconcile_services_with(
                &state_path,
                &statuses,
                get_proxy_bypass_domains,
                set_proxy_bypass_domains,
                run_networksetup,
            );
        }

        unset_stale_loopback_launchd_proxy_env();
    }

    fn reconcile_services_with(
        &self,
        state_path: &Path,
        statuses: &[NetworkServiceProxyStatus],
        mut get_bypass: impl FnMut(&str) -> Result<Vec<String>>,
        mut set_bypass: impl FnMut(&str, &[String]) -> Result<()>,
        mut run_cmd: impl FnMut(&[&str]) -> Result<String>,
    ) {
        let mut disk_state = SavedMacosProxyState::load_from_path(state_path)
            .ok()
            .flatten()
            .unwrap_or_else(|| self.saved_state.clone());

        for st in statuses {
            match classify_service_reconcile(st, &self.pac_url) {
                ServiceReconcileDecision::SkipExternalProxy => {
                    debug!(
                        service = %st.service,
                        auto_proxy_enabled = st.auto_proxy_enabled,
                        auto_proxy_url = %st.auto_proxy_url,
                        web_enabled = st.web_enabled,
                        secure_enabled = st.secure_enabled,
                        socks_enabled = st.socks_enabled,
                        "skipping macOS proxy reconciliation to preserve active corporate/external proxy"
                    );
                    continue;
                }
                ServiceReconcileDecision::AlreadyAligned => {
                    disable_loopback_manual_proxies_with(st, &mut run_cmd);
                    continue;
                }
                ServiceReconcileDecision::ApplyVdpiPac => {}
            }

            let is_new_service = disk_state.find_service(&st.service).is_none();
            let mut existing_bypass: Option<Vec<String>> = None;
            if is_new_service {
                existing_bypass = match get_bypass(&st.service) {
                    Ok(domains) => Some(domains),
                    Err(e) => {
                        warn!(
                            service = %st.service,
                            error = %e,
                            "failed to read existing proxy bypass domains for newly attached interface; skipping bypass domain snapshot and update"
                        );
                        None
                    }
                };
                let mut updated_state = disk_state.clone();
                updated_state
                    .upsert_if_absent(st.to_saved_state_with_bypass(existing_bypass.clone()));
                if let Err(e) = updated_state.save_to_path(state_path) {
                    warn!(
                        service = %st.service,
                        path = %state_path.display(),
                        error = %e,
                        "failed to persist macOS proxy state snapshot before mutating newly attached interface; skipping interface"
                    );
                    continue;
                }
                disk_state = updated_state;
            }

            let mut bypass_updated = false;
            if is_new_service {
                if let Some(existing) = existing_bypass.as_deref() {
                    let merged_svc = merge_service_bypass_domains_with_include(
                        existing,
                        &self.extra_bypass,
                        &self.include_domains,
                    );
                    match set_bypass(&st.service, &merged_svc) {
                        Ok(()) => bypass_updated = true,
                        Err(e) => {
                            warn!(
                                service = %st.service,
                                error = %e,
                                "failed to update proxy bypass domains for newly attached interface"
                            );
                        }
                    }
                }
            }

            disable_loopback_manual_proxies_with(st, &mut run_cmd);

            let pac_result = match run_cmd(&["-setautoproxyurl", &st.service, &self.pac_url]) {
                Ok(_) => run_cmd(&["-setautoproxystate", &st.service, "on"]),
                Err(e) => Err(e),
            };
            if let Err(e) = pac_result {
                warn!(
                    service = %st.service,
                    error = %e,
                    "failed to reconcile fail-open AutoProxyURL (PAC)"
                );
                if bypass_updated {
                    if let Some(original) = existing_bypass.as_deref() {
                        if let Err(restore_err) = set_bypass(&st.service, original) {
                            warn!(
                                service = %st.service,
                                error = %restore_err,
                                "failed to roll back proxy bypass domains after reconcile PAC failure"
                            );
                        }
                    }
                }
            }
        }
    }

    fn deactivate_owned_proxies(&self) {
        let state_path = macos_proxy_state_path();
        let mut saved_state = SavedMacosProxyState::load_from_path(&state_path)
            .ok()
            .flatten()
            .unwrap_or_else(|| self.saved_state.clone());
        for entry in &self.saved_state.services {
            saved_state.upsert_if_absent(entry.clone());
        }

        let mut services = list_configurable_network_services().unwrap_or_default();
        for svc in &self.services {
            if !services.iter().any(|s| s == svc) {
                services.push(svc.clone());
            }
        }
        for entry in &saved_state.services {
            if !services.iter().any(|s| s == &entry.service) {
                services.push(entry.service.clone());
            }
        }

        for svc in &services {
            restore_service_proxy_state(svc, saved_state.find_service(svc), Some(&self.pac_url));
        }

        unset_stale_loopback_launchd_proxy_env();
        remove_state_file(&state_path);
    }

    /// Cleanly restores pre-existing AutoProxyURL state (or disables vdpi PAC) across all active
    /// managed services and clears any legacy loopback manual proxies or `launchd` env vars.
    pub fn deactivate(&self) {
        self.deactivate_owned_proxies();
        debug!("restored macOS system proxy state");
    }

    pub(super) fn deactivate_foreground(&self) {
        self.deactivate_owned_proxies();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceReconcileDecision {
    AlreadyAligned,
    SkipExternalProxy,
    ApplyVdpiPac,
}

fn is_owned_vdpi_pac_url(url: &str, expected_pac_url: Option<&str>) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    is_vdpi_pac_url(trimmed)
        || expected_pac_url
            .map(str::trim)
            .is_some_and(|expected| !expected.is_empty() && trimmed.eq_ignore_ascii_case(expected))
}

fn has_active_non_loopback_manual_proxy(st: &NetworkServiceProxyStatus) -> bool {
    (st.web_enabled && !st.web_server.trim().is_empty() && !is_loopback_server(&st.web_server))
        || (st.secure_enabled
            && !st.secure_server.trim().is_empty()
            && !is_loopback_server(&st.secure_server))
        || (st.socks_enabled
            && !st.socks_server.trim().is_empty()
            && !is_loopback_server(&st.socks_server))
}

fn classify_service_reconcile(
    st: &NetworkServiceProxyStatus,
    expected_pac_url: &str,
) -> ServiceReconcileDecision {
    let current_pac = st.auto_proxy_url.trim();
    if !current_pac.is_empty() && !is_owned_vdpi_pac_url(current_pac, Some(expected_pac_url)) {
        return ServiceReconcileDecision::SkipExternalProxy;
    }
    if has_active_non_loopback_manual_proxy(st) {
        return ServiceReconcileDecision::SkipExternalProxy;
    }
    if st.auto_proxy_enabled && current_pac.eq_ignore_ascii_case(expected_pac_url.trim()) {
        return ServiceReconcileDecision::AlreadyAligned;
    }
    ServiceReconcileDecision::ApplyVdpiPac
}

fn disable_loopback_manual_proxies(st: &NetworkServiceProxyStatus) {
    disable_loopback_manual_proxies_with(st, run_networksetup);
}

fn disable_loopback_manual_proxies_with(
    st: &NetworkServiceProxyStatus,
    mut run_cmd: impl FnMut(&[&str]) -> Result<String>,
) {
    if st.web_enabled && is_loopback_server(&st.web_server) {
        if let Err(e) = run_cmd(&["-setwebproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback HTTP web proxy");
        }
    }
    if st.secure_enabled && is_loopback_server(&st.secure_server) {
        if let Err(e) = run_cmd(&["-setsecurewebproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback HTTPS secure web proxy");
        }
    }
    if st.socks_enabled && is_loopback_server(&st.socks_server) {
        if let Err(e) = run_cmd(&["-setsocksfirewallproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback SOCKS5 firewall proxy");
        }
    }
}

fn non_loopback_manual_proxy_disable_args(st: &NetworkServiceProxyStatus) -> Vec<[&str; 3]> {
    let mut cmds = Vec::new();
    if st.web_enabled && !is_loopback_server(&st.web_server) {
        cmds.push(["-setwebproxystate", st.service.as_str(), "off"]);
    }
    if st.secure_enabled && !is_loopback_server(&st.secure_server) {
        cmds.push(["-setsecurewebproxystate", st.service.as_str(), "off"]);
    }
    if st.socks_enabled && !is_loopback_server(&st.socks_server) {
        cmds.push(["-setsocksfirewallproxystate", st.service.as_str(), "off"]);
    }
    cmds
}

fn disable_non_loopback_manual_proxies(st: &NetworkServiceProxyStatus) {
    for args in non_loopback_manual_proxy_disable_args(st) {
        if let Err(e) = run_networksetup(&args) {
            warn!(
                service = %st.service,
                flag = args[0],
                error = %e,
                "failed to disable pre-existing manual proxy while PAC is active"
            );
        }
    }
}

fn restore_service_proxy_state(
    svc: &str,
    saved: Option<&SavedServiceProxyState>,
    expected_pac_url: Option<&str>,
) {
    let st = inspect_single_service_proxy(svc);
    restore_service_proxy_state_with(
        svc,
        &st,
        saved,
        expected_pac_url,
        run_networksetup,
        set_proxy_bypass_domains,
    );
}

fn restore_service_proxy_state_with(
    svc: &str,
    st: &NetworkServiceProxyStatus,
    saved: Option<&SavedServiceProxyState>,
    expected_pac_url: Option<&str>,
    mut run_cmd: impl FnMut(&[&str]) -> Result<String>,
    mut set_bypass: impl FnMut(&str, &[String]) -> Result<()>,
) {
    // 1. Restore previous AutoProxyURL state, or clear & disable vdpi's PAC if none existed before.
    let current_pac_owned = is_owned_vdpi_pac_url(&st.auto_proxy_url, expected_pac_url);
    let current_is_vdpi_or_empty = st.auto_proxy_url.trim().is_empty() || current_pac_owned;
    if let Some(prev) = saved.filter(|s| {
        !s.autoproxy.url.trim().is_empty()
            && !is_owned_vdpi_pac_url(&s.autoproxy.url, expected_pac_url)
    }) {
        if current_is_vdpi_or_empty {
            let _ = run_cmd(&["-setautoproxyurl", svc, &prev.autoproxy.url]);
            let state_arg = if prev.autoproxy.enabled { "on" } else { "off" };
            let _ = run_cmd(&["-setautoproxystate", svc, state_arg]);
        }
    } else if current_pac_owned {
        let _ = run_cmd(&["-setautoproxyurl", svc, ""]);
        let _ = run_cmd(&["-setautoproxystate", svc, "off"]);
    }

    // 2. Clean up any legacy 127.0.0.1 / ::1 fail-closed manual proxies.
    disable_loopback_manual_proxies_with(st, &mut run_cmd);

    // 3. Restore any saved non-loopback manual proxies if they were previously enabled.
    if let Some(prev) = saved {
        restore_manual_proxy_if_needed_with(
            svc,
            &prev.webproxy,
            st.web_enabled && !is_loopback_server(&st.web_server),
            "-setwebproxy",
            "-setwebproxystate",
            &mut run_cmd,
        );
        restore_manual_proxy_if_needed_with(
            svc,
            &prev.securewebproxy,
            st.secure_enabled && !is_loopback_server(&st.secure_server),
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
            &mut run_cmd,
        );
        restore_manual_proxy_if_needed_with(
            svc,
            &prev.socksfirewallproxy,
            st.socks_enabled && !is_loopback_server(&st.socks_server),
            "-setsocksfirewallproxy",
            "-setsocksfirewallproxystate",
            &mut run_cmd,
        );

        // 4. Restore original proxy bypass domains if snapshotted before activation and no
        //    external proxy was enabled mid-session.
        let external_proxy_active =
            !current_is_vdpi_or_empty || has_active_non_loopback_manual_proxy(st);
        if !external_proxy_active {
            if let Some(original_bypass) = prev.bypass_domains.as_deref() {
                if let Err(e) = set_bypass(svc, original_bypass) {
                    warn!(service = %svc, error = %e, "failed to restore proxy bypass domains");
                }
            }
        }
    }
}

fn restore_manual_proxy_if_needed_with(
    svc: &str,
    saved: &ManualProxyState,
    currently_active_non_loopback: bool,
    set_cmd: &str,
    state_cmd: &str,
    mut run_cmd: impl FnMut(&[&str]) -> Result<String>,
) {
    if currently_active_non_loopback
        || !saved.enabled
        || saved.server.trim().is_empty()
        || saved.port.trim().is_empty()
        || saved.port.trim() == "0"
        || is_loopback_server(&saved.server)
    {
        return;
    }
    let _ = run_cmd(&[set_cmd, svc, &saved.server, &saved.port]);
    let _ = run_cmd(&[state_cmd, svc, "on"]);
}

fn is_vpn_default_route_active() -> bool {
    crate::platform::vpn::detect_active_vpn(None).is_full_tunnel()
}

/// Restores saved macOS proxy state (or disables vdpi `/vdpi.pac` AutoProxyURL when none existed
/// before), cleans up any legacy loopback HTTP/HTTPS/SOCKS5 proxies across configurable network
/// services, and unsets stale loopback `launchctl` proxy environment variables.
pub fn clear_all_macos_proxies() -> Result<()> {
    let state_path = macos_proxy_state_path();
    let saved_state = SavedMacosProxyState::load_from_path(&state_path)
        .ok()
        .flatten()
        .unwrap_or_default();

    let mut services = list_configurable_network_services()?;
    for entry in &saved_state.services {
        if !services.iter().any(|s| s == &entry.service) {
            services.push(entry.service.clone());
        }
    }

    for svc in &services {
        restore_service_proxy_state(svc, saved_state.find_service(svc), None);
    }

    unset_stale_loopback_launchd_proxy_env();
    remove_state_file(&state_path);
    Ok(())
}

fn bypass_domains_match_default(domains: &[String]) -> bool {
    domains.len() == DEFAULT_MACOS_BYPASS_DOMAINS.len()
        && domains
            .iter()
            .zip(DEFAULT_MACOS_BYPASS_DOMAINS.iter())
            .all(|(actual, expected)| actual.trim().eq_ignore_ascii_case(expected))
}

fn service_proxy_needs_reset(st: &NetworkServiceProxyStatus, bypass: Option<&[String]>) -> bool {
    st.auto_proxy_enabled
        || !st.auto_proxy_url.trim().is_empty()
        || st.web_enabled
        || st.secure_enabled
        || st.socks_enabled
        || bypass.is_some_and(|domains| !bypass_domains_match_default(domains))
}

fn is_macos_privilege_error(err_text: &str) -> bool {
    let lower = err_text.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("not permitted")
        || lower.contains("not authorized")
        || lower.contains("authorization")
        || lower.contains("administrator")
        || lower.contains("requires root")
        || lower.contains("must be root")
        || lower.contains("privileges")
        || lower.contains("-60005")
        || lower.contains("-60006")
        || lower.contains("-60007")
        || lower.contains("-60008")
}

fn is_unrecognized_network_service_error(err_text: &str) -> bool {
    err_text
        .to_ascii_lowercase()
        .contains("is not a recognized network service")
}

fn collect_macos_proxy_state_paths(target_user: Option<&ElevatedUser>, is_root: bool) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::with_capacity(4);
    let mut push_unique = |p: PathBuf| {
        if !p.as_os_str().is_empty() && !paths.iter().any(|existing| existing == &p) {
            paths.push(p);
        }
    };
    if let Some(home) = target_user.and_then(|u| u.home_dir.as_deref()) {
        push_unique(home.join(".vdpi").join("macos-proxy-state.json"));
    }
    push_unique(macos_proxy_state_path());
    push_unique(PathBuf::from(
        "/Library/Application Support/vdpi/macos-proxy-state.json",
    ));
    if is_root {
        push_unique(PathBuf::from("/var/root/.vdpi/macos-proxy-state.json"));
    }
    paths
}

fn read_launchd_env_for_uid(uid: Option<libc::uid_t>, key: &str) -> Option<String> {
    let mut cmd = Command::new("/bin/launchctl");
    if let Some(u) = uid {
        cmd.args(["asuser", &u.to_string(), "/bin/launchctl", "getenv", key]);
    } else {
        cmd.args(["getenv", key]);
    }
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

fn unset_launchd_env_for_uid(uid: Option<libc::uid_t>, errors: &mut Vec<String>) -> bool {
    let mut changed = false;
    for key in ENV_KEYS {
        let was_set = read_launchd_env_for_uid(uid, key).is_some();
        let mut cmd = Command::new("/bin/launchctl");
        if let Some(u) = uid {
            cmd.args(["asuser", &u.to_string(), "/bin/launchctl", "unsetenv", key]);
        } else {
            cmd.args(["unsetenv", key]);
        }
        match cmd.output() {
            Ok(out) if out.status.success() => {
                if was_set {
                    changed = true;
                }
            }
            Ok(out) => {
                if was_set {
                    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    errors.push(format!(
                        "launchctl unsetenv {key} exited {}: {stderr}",
                        out.status
                    ));
                }
            }
            Err(err) => {
                if was_set {
                    errors.push(format!("failed to execute launchctl unsetenv {key}: {err}"));
                }
            }
        }
    }
    changed
}

fn remove_macos_proxy_state_file_guarded(
    path: &Path,
    home_guard: Option<&Path>,
    is_root: bool,
    outcome: &mut UnixProxyResetOutcome,
) {
    if let Some(home_dir) = home_guard {
        if let Err(err) = ensure_no_intermediate_symlink_under_home(path, home_dir) {
            warn!(
                path = %path.display(),
                error = %err,
                "refusing to remove macOS proxy state file through unsafe path"
            );
            return;
        }
        if fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            warn!(
                path = %path.display(),
                "refusing to remove symlinked macOS proxy state file under user home"
            );
            return;
        }
    }
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) if !is_root && err.kind() == std::io::ErrorKind::PermissionDenied => {
            outcome.skipped_privileges = true;
        }
        Err(err) => {
            outcome.errors.push(format!(
                "failed to remove {}: {err}",
                path.display()
            ));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reset_single_macos_service_with(
    svc: &str,
    from_saved_state_only: bool,
    is_root: bool,
    status: &NetworkServiceProxyStatus,
    bypass_res: Result<Vec<String>>,
    outcome: &mut UnixProxyResetOutcome,
    mut run_cmd: impl FnMut(&[&str]) -> Result<String>,
) -> bool {
    if from_saved_state_only {
        if let Err(ref err) = bypass_res {
            if is_unrecognized_network_service_error(&format!("{err:#}")) {
                return false;
            }
        }
    }
    let bypass = bypass_res.ok();
    let needs_reset = service_proxy_needs_reset(status, bypass.as_deref());
    if !needs_reset && bypass.is_some() {
        return false;
    }

    let reset_cmds: [&[&str]; 6] = [
        &["-setautoproxyurl", svc, ""],
        &["-setautoproxystate", svc, "off"],
        &["-setwebproxystate", svc, "off"],
        &["-setsecurewebproxystate", svc, "off"],
        &["-setsocksfirewallproxystate", svc, "off"],
        &[
            "-setproxybypassdomains",
            svc,
            DEFAULT_MACOS_BYPASS_DOMAINS[0],
            DEFAULT_MACOS_BYPASS_DOMAINS[1],
        ],
    ];

    let mut any_succeeded = false;
    for args in reset_cmds {
        match run_cmd(args) {
            Ok(_) => {
                any_succeeded = true;
            }
            Err(err) => {
                let msg = format!("{err:#}");
                if from_saved_state_only && is_unrecognized_network_service_error(&msg) {
                    return false;
                }
                if !is_root && is_macos_privilege_error(&msg) {
                    outcome.skipped_privileges = true;
                    return true;
                }
                outcome
                    .errors
                    .push(format!("networksetup {} failed: {msg}", args.join(" ")));
            }
        }
    }

    if any_succeeded && (needs_reset || bypass.is_none()) {
        outcome.proxy_changed = true;
    }
    false
}

/// Resets macOS network service proxies, proxy bypass domains, launchd proxy environment
/// variables, and saved proxy state files back to clean factory defaults.
pub fn reset_macos_proxies_to_defaults() -> UnixProxyResetOutcome {
    let mut outcome = UnixProxyResetOutcome::default();
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    let is_root = unsafe { libc::geteuid() == 0 };
    let target_user = resolve_target_desktop_user();
    let user_home = target_user.as_ref().and_then(|u| u.home_dir.as_deref());
    let state_paths = collect_macos_proxy_state_paths(target_user.as_ref(), is_root);

    let live_services: Vec<String> = match list_configurable_network_services() {
        Ok(svcs) => svcs,
        Err(err) => {
            let msg = format!("{err:#}");
            if !is_root && is_macos_privilege_error(&msg) {
                outcome.skipped_privileges = true;
            } else {
                outcome.errors.push(msg);
            }
            Vec::new()
        }
    };

    let mut services: Vec<(String, bool)> = live_services
        .into_iter()
        .map(|svc| (svc, false))
        .collect();

    for path in &state_paths {
        let guard_home = if is_root {
            user_home.filter(|home| path.starts_with(home))
        } else {
            None
        };
        if let Ok(Some(saved)) = load_from_path_with_home_guard(path, guard_home) {
            for entry in saved.services {
                if !entry.service.trim().is_empty()
                    && !services
                        .iter()
                        .any(|(existing, _)| existing == &entry.service)
                {
                    services.push((entry.service, true));
                }
            }
        }
    }

    for (svc, from_saved_state_only) in &services {
        let status = inspect_single_service_proxy(svc);
        let bypass_res = get_proxy_bypass_domains(svc);
        if reset_single_macos_service_with(
            svc,
            *from_saved_state_only,
            is_root,
            &status,
            bypass_res,
            &mut outcome,
            run_networksetup,
        ) {
            break;
        }
    }

    if is_root {
        if let Some(uid) = target_user.as_ref().map(|u| u.uid).filter(|&uid| uid != 0) {
            outcome.env_changed |= unset_launchd_env_for_uid(Some(uid), &mut outcome.errors);
        }
    }
    outcome.env_changed |= unset_launchd_env_for_uid(None, &mut outcome.errors);

    for path in &state_paths {
        let guard_home = user_home.filter(|home| path.starts_with(home));
        remove_macos_proxy_state_file_guarded(path, guard_home, is_root, &mut outcome);
    }

    outcome
}

pub fn print_macos_proxy_status() {
    println!(
        "launchd HTTPS_PROXY       : {}",
        read_launchd_env("HTTPS_PROXY").unwrap_or_else(|| "<unset>".into())
    );
    println!(
        "launchd NO_PROXY          : {}",
        read_launchd_env("NO_PROXY").unwrap_or_else(|| "<unset>".into())
    );

    if let Ok(services) = inspect_service_proxies() {
        println!("\n=== macOS Network Services ===");
        for s in services {
            println!(
                "- {}:\n    PAC   : {} ({})\n    HTTP  : {} ({}:{})\n    HTTPS : {} ({}:{})\n    SOCKS5: {} ({}:{})",
                s.service,
                if s.auto_proxy_enabled { "ON" } else { "OFF" },
                if s.auto_proxy_url.is_empty() {
                    "<unset>"
                } else {
                    s.auto_proxy_url.as_str()
                },
                if s.web_enabled { "ON" } else { "OFF" },
                s.web_server,
                s.web_port,
                if s.secure_enabled { "ON" } else { "OFF" },
                s.secure_server,
                s.secure_port,
                if s.socks_enabled { "ON" } else { "OFF" },
                s.socks_server,
                s.socks_port,
            );
        }
    }
}

/// Lists enabled primary macOS network services (e.g. `Wi-Fi`, `USB 10/100/1000 LAN`, `Ethernet`),
/// skipping virtual VPN/bridge tunnels.
pub fn list_configurable_network_services() -> Result<Vec<String>> {
    let out = run_networksetup(&["-listallnetworkservices"])?;
    Ok(parse_network_services_output(&out))
}

pub fn parse_network_services_output(output: &str) -> Vec<String> {
    let mut services = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("An asterisk") || trimmed.starts_with('*') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("vpn")
            || lower.contains("wireguard")
            || lower.contains("warp")
            || lower.contains("tailscale")
            || lower.contains("zerotier")
            || lower == "thunderbolt bridge"
        {
            continue;
        }
        services.push(trimmed.to_string());
    }
    services
}

pub fn get_proxy_bypass_domains(service: &str) -> Result<Vec<String>> {
    let out = run_networksetup(&["-getproxybypassdomains", service])?;
    let mut domains = Vec::new();
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("There aren't any") {
            continue;
        }
        domains.push(trimmed.to_string());
    }
    Ok(domains)
}

const BASELINE_BYPASS_DOMAINS: &[&str] = &[
    "localhost",
    "*.localhost",
    "*.localdomain",
    "127.0.0.1",
    "127.0.0.0/8",
    "0.0.0.0",
    "::1",
    "fc00::/7",
    "fe80::/10",
    "*.local",
    "*.lan",
    "*.internal",
    "*.home.arpa",
    "*.ts.net",
    "169.254/16",
    "192.168.*",
    "10.*",
    "172.16.0.0/12",
    "100.64.0.0/10",
    "192.0.0.0/24",
    "captive.apple.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "detectportal.firefox.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "msftncsi.com",
    "www.msftncsi.com",
    "dns.msftncsi.com",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "connectivity-check.ubuntu.com",
    "neverssl.com",
    "*.gov.tr",
    "*.org.tr",
    "*.osym.gov.tr",
    "*.bkm.com.tr",
    "paratika.com.tr",
    "*.halkbank.com.tr",
    "*.isbank.com.tr",
    "*.turktelekom.com.tr",
    "*.pttavm.com",
];

fn is_local_or_ip_baseline(entry: &str) -> bool {
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

#[cfg(test)]
fn merge_service_bypass_domains(existing: &[String], extra: &[String]) -> Vec<String> {
    merge_service_bypass_domains_with_include(existing, extra, &[])
}

fn merge_service_bypass_domains_with_include(
    existing: &[String],
    extra: &[String],
    include_domains: &[String],
) -> Vec<String> {
    let filterable_baselines: Vec<&str> = BASELINE_BYPASS_DOMAINS
        .iter()
        .copied()
        .filter(|baseline| !is_local_or_ip_baseline(baseline))
        .collect();
    let kept_non_local = filter_pac_default_bypass_domains(&filterable_baselines, include_domains);

    let mut out: Vec<String> = Vec::new();
    let mut push_unique = |val: &str| {
        let clean = val.trim();
        if !clean.is_empty() && !out.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            out.push(clean.to_string());
        }
    };

    for item in existing {
        push_unique(item);
    }
    for baseline in BASELINE_BYPASS_DOMAINS {
        if !is_local_or_ip_baseline(baseline) && !kept_non_local.contains(&baseline) {
            continue;
        }
        push_unique(baseline);
    }
    for item in extra {
        push_unique(item);
    }
    out
}

fn build_set_proxy_bypass_domains_args<'a>(
    service: &'a str,
    domains: &'a [String],
) -> Vec<&'a str> {
    let mut args = Vec::with_capacity(2 + domains.len().max(1));
    args.push("-setproxybypassdomains");
    args.push(service);
    for d in domains {
        let trimmed = d.trim();
        if !trimmed.is_empty() {
            args.push(trimmed);
        }
    }
    if args.len() == 2 {
        args.push("Empty");
    }
    args
}

fn set_proxy_bypass_domains(service: &str, domains: &[String]) -> Result<()> {
    let args = build_set_proxy_bypass_domains_args(service, domains);
    run_networksetup(&args).map(|_| ())
}

fn build_launchctl_args_for_user(
    is_root: bool,
    sudo_uid_env: Option<&str>,
    args: &[&str],
) -> Vec<String> {
    if is_root {
        if let Some(uid) = sudo_uid_env
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .filter(|&uid| uid != 0)
        {
            let mut full = Vec::with_capacity(3 + args.len());
            full.push("asuser".to_string());
            full.push(uid.to_string());
            full.push("/bin/launchctl".to_string());
            full.extend(args.iter().map(|a| (*a).to_string()));
            return full;
        }
    }
    args.iter().map(|a| (*a).to_string()).collect()
}

fn launchctl_command(args: &[&str]) -> Command {
    #[cfg(unix)]
    let (is_root, elevated_uid) = {
        // SAFETY: `geteuid(2)` is always safe to call and never fails.
        let root = unsafe { libc::geteuid() == 0 };
        let uid = if root {
            resolve_elevated_user().map(|u| u.uid.to_string())
        } else {
            None
        };
        (root, uid)
    };
    #[cfg(not(unix))]
    let (is_root, elevated_uid): (bool, Option<String>) = (false, None);

    let full_args = build_launchctl_args_for_user(is_root, elevated_uid.as_deref(), args);
    let mut cmd = Command::new("/bin/launchctl");
    cmd.args(full_args);
    cmd
}

pub fn set_launchd_proxy_env(proxy_url: &str, no_proxy: &str) {
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        let _ = launchctl_command(&["setenv", key, proxy_url]).output();
    }
    for key in ["NO_PROXY", "no_proxy"] {
        let _ = launchctl_command(&["setenv", key, no_proxy]).output();
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        if read_launchd_env(key)
            .is_some_and(|current| is_vdpi_owned_proxy_env_value(&current, proxy_url))
        {
            let _ = launchctl_command(&["unsetenv", key]).output();
        }
    }
}

fn unset_stale_loopback_launchd_proxy_env() {
    let mut unset_http_any = false;
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        if read_launchd_env(key).is_some_and(|current| is_loopback_proxy_env_value(&current)) {
            unset_http_any = true;
            let _ = launchctl_command(&["unsetenv", key]).output();
        }
    }
    if unset_http_any {
        for key in ["NO_PROXY", "no_proxy"] {
            let _ = launchctl_command(&["unsetenv", key]).output();
        }
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        if read_launchd_env(key).is_some_and(|current| is_loopback_proxy_env_value(&current)) {
            let _ = launchctl_command(&["unsetenv", key]).output();
        }
    }
}

pub fn unset_launchd_proxy_env() {
    for key in ENV_KEYS {
        let _ = launchctl_command(&["unsetenv", key]).output();
    }
}

pub fn read_launchd_env(key: &str) -> Option<String> {
    let out = launchctl_command(&["getenv", key]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

fn inspect_single_service_proxy(svc: &str) -> NetworkServiceProxyStatus {
    let auto_raw = run_networksetup(&["-getautoproxyurl", svc]).unwrap_or_default();
    let web = run_networksetup(&["-getwebproxy", svc]).unwrap_or_default();
    let sec = run_networksetup(&["-getsecurewebproxy", svc]).unwrap_or_default();
    let socks = run_networksetup(&["-getsocksfirewallproxy", svc]).unwrap_or_default();

    let autoproxy = parse_autoproxy_url_output(&auto_raw);
    let (web_enabled, web_server, web_port) = parse_proxy_kv(&web);
    let (secure_enabled, secure_server, secure_port) = parse_proxy_kv(&sec);
    let (socks_enabled, socks_server, socks_port) = parse_proxy_kv(&socks);

    NetworkServiceProxyStatus {
        service: svc.to_string(),
        auto_proxy_enabled: autoproxy.enabled,
        auto_proxy_url: autoproxy.url,
        web_enabled,
        web_server,
        web_port,
        secure_enabled,
        secure_server,
        secure_port,
        socks_enabled,
        socks_server,
        socks_port,
    }
}

pub fn inspect_service_proxies() -> Result<Vec<NetworkServiceProxyStatus>> {
    let services = list_configurable_network_services()?;
    Ok(services
        .iter()
        .map(|svc| inspect_single_service_proxy(svc))
        .collect())
}

pub fn parse_autoproxy_url_output(text: &str) -> AutoProxyState {
    let mut url = String::new();
    let mut enabled = false;
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("url") {
                if !val.is_empty() && !val.eq_ignore_ascii_case("(null)") {
                    url = val.to_string();
                } else {
                    url.clear();
                }
            } else if key.eq_ignore_ascii_case("enabled") {
                enabled = val.eq_ignore_ascii_case("yes");
            }
        }
    }
    AutoProxyState { url, enabled }
}

fn parse_proxy_kv(text: &str) -> (bool, String, String) {
    let mut enabled = false;
    let mut server = String::new();
    let mut port = String::new();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "Enabled" => enabled = val.eq_ignore_ascii_case("yes"),
                "Server" => server = val.to_string(),
                "Port" => port = val.to_string(),
                _ => {}
            }
        }
    }
    (enabled, server, port)
}

fn run_networksetup(args: &[&str]) -> Result<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .with_context(|| format!("failed to execute networksetup {args:?}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "networksetup {:?} exited {}: {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_vpn_and_bridge_interfaces_from_networksetup_output() {
        let sample = "\
An asterisk (*) denotes that a network service is disabled.
USB 10/100/1000 LAN
Thunderbolt Bridge
Wi-Fi
iPhone USB
ProtonVPN
*Disabled Ethernet
";
        let parsed = parse_network_services_output(sample);
        assert_eq!(parsed, vec!["USB 10/100/1000 LAN", "Wi-Fi", "iPhone USB"]);
    }

    #[test]
    fn merges_bypass_domains_without_losing_user_entries() {
        let existing = vec![" *.gov.tr".into(), "custom.internal.tr".into()];
        let merged = merge_service_bypass_domains(&existing, &["extra.example.com".into()]);
        assert!(merged.contains(&"*.gov.tr".to_string()));
        assert!(merged.contains(&"custom.internal.tr".to_string()));
        assert!(merged.contains(&"extra.example.com".to_string()));
        for expected in [
            "172.16.0.0/12",
            "::1",
            "100.64.0.0/10",
            "*.localhost",
            "*.localdomain",
            "127.0.0.0/8",
            "0.0.0.0",
            "fc00::/7",
            "fe80::/10",
            "captive.apple.com",
            "www.msftconnecttest.com",
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
            "clients3.google.com",
            "msftncsi.com",
            "www.msftncsi.com",
            "dns.msftncsi.com",
            "neverssl.com",
            "*.lan",
            "*.internal",
            "*.home.arpa",
            "*.ts.net",
            "*.org.tr",
            "*.osym.gov.tr",
            "*.bkm.com.tr",
            "*.halkbank.com.tr",
            "*.isbank.com.tr",
            "*.turktelekom.com.tr",
            "*.pttavm.com",
        ] {
            assert!(
                merged.contains(&expected.to_string()),
                "expected {expected} in merged bypass domains"
            );
        }
        assert!(!merged.contains(&"*org.tr".to_string()));
        assert!(!merged.contains(&"*halkbank.com.tr".to_string()));
        assert!(!merged.contains(&"*isbank.com.tr".to_string()));
    }

    #[test]
    fn filters_org_tr_baseline_when_include_domains_is_non_empty() {
        let existing = vec!["*.local".to_string()];

        let with_empty = merge_service_bypass_domains_with_include(&existing, &[], &[]);
        assert!(with_empty.contains(&"*.org.tr".to_string()));

        let with_blank = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &["  ".to_string(), "".to_string()],
        );
        assert!(with_blank.contains(&"*.org.tr".to_string()));

        let include_domains = vec!["example.org.tr".to_string()];
        let filtered = merge_service_bypass_domains_with_include(&existing, &[], &include_domains);
        assert!(!filtered.contains(&"*.org.tr".to_string()));
        assert!(filtered.contains(&"*.gov.tr".to_string()));
        assert!(filtered.contains(&"connectivitycheck.gstatic.com".to_string()));
        assert!(filtered.contains(&"neverssl.com".to_string()));

        let explicit_extra = merge_service_bypass_domains_with_include(
            &existing,
            &["*.org.tr".to_string()],
            &include_domains,
        );
        assert!(explicit_extra.contains(&"*.org.tr".to_string()));

        let preserved_existing = merge_service_bypass_domains_with_include(
            &["*.org.tr".to_string()],
            &[],
            &include_domains,
        );
        assert!(preserved_existing.contains(&"*.org.tr".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn write_file_atomic_replaces_destination_symlink_without_modifying_target() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-atomic-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let target = base.join("target.txt");
        fs::write(&target, "original-secret").unwrap();

        let dest_link = base.join("state.json");
        symlink(&target, &dest_link).unwrap();

        write_file_atomic(&dest_link, "{\"services\":[]}").unwrap();

        assert_eq!(fs::read_to_string(&target).unwrap(), "original-secret");
        assert!(!fs::symlink_metadata(&dest_link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_to_string(&dest_link).unwrap(), "{\"services\":[]}");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn builds_set_proxy_bypass_domains_args_including_empty_reset() {
        let non_empty = vec!["*.local".to_string(), "169.254/16".to_string()];
        assert_eq!(
            build_set_proxy_bypass_domains_args("Wi-Fi", &non_empty),
            vec!["-setproxybypassdomains", "Wi-Fi", "*.local", "169.254/16"]
        );

        let empty: Vec<String> = Vec::new();
        assert_eq!(
            build_set_proxy_bypass_domains_args("Wi-Fi", &empty),
            vec!["-setproxybypassdomains", "Wi-Fi", "Empty"]
        );

        let whitespace_only = vec!["  ".to_string(), "".to_string()];
        assert_eq!(
            build_set_proxy_bypass_domains_args("Ethernet", &whitespace_only),
            vec!["-setproxybypassdomains", "Ethernet", "Empty"]
        );
    }

    #[test]
    fn builds_launchctl_asuser_args_when_root_with_sudo_uid() {
        assert_eq!(
            build_launchctl_args_for_user(true, Some("501"), &["getenv", "HTTPS_PROXY"]),
            vec![
                "asuser",
                "501",
                "/bin/launchctl",
                "getenv",
                "HTTPS_PROXY"
            ]
        );
        assert_eq!(
            build_launchctl_args_for_user(
                true,
                Some(" 502\n"),
                &["setenv", "HTTP_PROXY", "http://127.0.0.1:8080"]
            ),
            vec![
                "asuser",
                "502",
                "/bin/launchctl",
                "setenv",
                "HTTP_PROXY",
                "http://127.0.0.1:8080"
            ]
        );
        assert_eq!(
            build_launchctl_args_for_user(true, Some("0"), &["unsetenv", "HTTP_PROXY"]),
            vec!["unsetenv", "HTTP_PROXY"]
        );
        assert_eq!(
            build_launchctl_args_for_user(true, None, &["getenv", "NO_PROXY"]),
            vec!["getenv", "NO_PROXY"]
        );
        assert_eq!(
            build_launchctl_args_for_user(true, Some("not-a-uid"), &["getenv", "NO_PROXY"]),
            vec!["getenv", "NO_PROXY"]
        );
        assert_eq!(
            build_launchctl_args_for_user(false, Some("501"), &["getenv", "HTTPS_PROXY"]),
            vec!["getenv", "HTTPS_PROXY"]
        );
    }

    #[test]
    fn only_auto_yield_skips_proxy_for_full_tunnel_vpn() {
        assert!(should_skip_proxy_for_vpn(VpnCoexistence::AutoYield));
        assert!(!should_skip_proxy_for_vpn(VpnCoexistence::Warn));
        assert!(!should_skip_proxy_for_vpn(VpnCoexistence::Off));
    }

    #[test]
    fn normalizes_unspecified_bind_ips_and_brackets_ipv6_urls() {
        assert_eq!(
            normalize_proxy_addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            normalize_proxy_addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            format_proxy_url(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
            "http://127.0.0.1:8080"
        );
        assert_eq!(
            format_proxy_url(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080),
            "http://[::1]:8080"
        );
        assert_eq!(
            format_proxy_url(IpAddr::V6(Ipv6Addr::LOCALHOST), 9090),
            "http://[::1]:9090"
        );
    }

    #[test]
    fn formats_and_recognizes_pac_urls() {
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
        assert_eq!(
            format_pac_url(IpAddr::V6(Ipv6Addr::LOCALHOST), 9090),
            "http://[::1]:9090/vdpi.pac"
        );

        assert!(is_vdpi_pac_url("http://127.0.0.1:8080/vdpi.pac"));
        assert!(is_vdpi_pac_url("HTTP://127.0.0.1:18080/VDPI.PAC?v=1"));
        assert!(is_vdpi_pac_url("http://[::1]:8080/vdpi.pac"));
        assert!(is_vdpi_pac_url("http://localhost:8080/vdpi.pac"));
        assert!(!is_vdpi_pac_url("http://10.0.0.1:8080/vdpi.pac"));
        assert!(!is_vdpi_pac_url("https://proxy.corp.example/wpad.dat"));
        assert!(!is_vdpi_pac_url("http://127.0.0.1:8080/other.pac"));
        assert!(!is_vdpi_pac_url("(null)"));
        assert!(!is_vdpi_pac_url(""));
    }

    #[test]
    fn parses_getautoproxyurl_output() {
        let enabled = "URL: http://127.0.0.1:8080/vdpi.pac\nEnabled: Yes\n";
        assert_eq!(
            parse_autoproxy_url_output(enabled),
            AutoProxyState {
                url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
                enabled: true,
            }
        );

        let unset = "URL: (null)\nEnabled: No\n";
        assert_eq!(
            parse_autoproxy_url_output(unset),
            AutoProxyState {
                url: String::new(),
                enabled: false,
            }
        );

        let disabled_with_corp_url =
            "URL: https://proxy.corp.example:8443/wpad.dat\r\nEnabled: No\r\n";
        assert_eq!(
            parse_autoproxy_url_output(disabled_with_corp_url),
            AutoProxyState {
                url: "https://proxy.corp.example:8443/wpad.dat".to_string(),
                enabled: false,
            }
        );

        let blank_url = "URL:\nEnabled: No\n";
        assert_eq!(
            parse_autoproxy_url_output(blank_url),
            AutoProxyState {
                url: String::new(),
                enabled: false,
            }
        );
    }

    #[test]
    fn saved_proxy_state_deserializes_legacy_json_and_roundtrips() {
        let legacy_json = r#"{
            "services": [
                {
                    "service": "Wi-Fi",
                    "webproxy": { "enabled": true, "server": "10.0.0.5", "port": "3128" },
                    "securewebproxy": { "enabled": false, "server": "", "port": "0" },
                    "socksfirewallproxy": { "enabled": false, "server": "", "port": "0" }
                }
            ]
        }"#;
        let decoded: SavedMacosProxyState = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(decoded.services.len(), 1);
        let wifi = decoded.find_service("Wi-Fi").unwrap();
        assert_eq!(wifi.autoproxy, AutoProxyState::default());
        assert!(wifi.webproxy.enabled);
        assert_eq!(wifi.webproxy.server, "10.0.0.5");
        assert_eq!(wifi.webproxy.port, "3128");
        assert_eq!(wifi.bypass_domains, None);

        let empty_decoded: SavedMacosProxyState = serde_json::from_str("{}").unwrap();
        assert!(empty_decoded.services.is_empty());

        let mut state = SavedMacosProxyState::default();
        assert!(state.upsert_if_absent(SavedServiceProxyState {
            service: "Wi-Fi".to_string(),
            autoproxy: AutoProxyState {
                url: "https://proxy.corp.example/proxy.pac".to_string(),
                enabled: true,
            },
            webproxy: ManualProxyState::default(),
            securewebproxy: ManualProxyState::default(),
            socksfirewallproxy: ManualProxyState::default(),
            bypass_domains: Some(vec!["*.local".to_string(), "169.254/16".to_string()]),
        }));
        assert!(state.upsert_if_absent(SavedServiceProxyState {
            service: "Ethernet".to_string(),
            bypass_domains: Some(Vec::new()),
            ..Default::default()
        }));
        assert!(!state.upsert_if_absent(SavedServiceProxyState {
            service: "Wi-Fi".to_string(),
            autoproxy: AutoProxyState::default(),
            ..Default::default()
        }));

        let tmp_path = std::env::temp_dir().join(format!(
            "vdpi-macos-proxy-state-test-{}.json",
            std::process::id()
        ));
        state.save_to_path(&tmp_path).unwrap();
        let loaded = SavedMacosProxyState::load_from_path(&tmp_path)
            .unwrap()
            .unwrap();
        assert_eq!(loaded, state);
        assert_eq!(
            loaded.find_service("Wi-Fi").unwrap().bypass_domains,
            Some(vec!["*.local".to_string(), "169.254/16".to_string()])
        );
        assert_eq!(
            loaded.find_service("Ethernet").unwrap().bypass_domains,
            Some(Vec::new())
        );
        remove_state_file(&tmp_path);
        assert!(SavedMacosProxyState::load_from_path(&tmp_path)
            .unwrap()
            .is_none());
    }

    #[test]
    fn to_saved_state_sanitizes_vdpi_owned_entries_and_preserves_external_ones() {
        let stale_vdpi = NetworkServiceProxyStatus {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: true,
            auto_proxy_url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
            web_enabled: true,
            web_server: "127.0.0.1".to_string(),
            web_port: "8080".to_string(),
            secure_enabled: true,
            secure_server: "::1".to_string(),
            secure_port: "8080".to_string(),
            socks_enabled: true,
            socks_server: "127.0.0.1".to_string(),
            socks_port: "1080".to_string(),
        };
        let saved = stale_vdpi.to_saved_state();
        assert_eq!(saved.autoproxy, AutoProxyState::default());
        assert_eq!(saved.webproxy, ManualProxyState::default());
        assert_eq!(saved.securewebproxy, ManualProxyState::default());
        assert_eq!(saved.socksfirewallproxy, ManualProxyState::default());

        let corp = NetworkServiceProxyStatus {
            service: "Ethernet".to_string(),
            auto_proxy_enabled: true,
            auto_proxy_url: "https://corp.example/wpad.dat".to_string(),
            web_enabled: false,
            web_server: String::new(),
            web_port: "0".to_string(),
            secure_enabled: true,
            secure_server: "10.0.0.5".to_string(),
            secure_port: "3128".to_string(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: "0".to_string(),
        };
        let saved_corp = corp.to_saved_state();
        assert_eq!(
            saved_corp.autoproxy,
            AutoProxyState {
                url: "https://corp.example/wpad.dat".to_string(),
                enabled: true,
            }
        );
        assert_eq!(
            saved_corp.securewebproxy,
            ManualProxyState {
                enabled: true,
                server: "10.0.0.5".to_string(),
                port: "3128".to_string(),
            }
        );
    }

    #[test]
    fn reflects_standby_when_proxy_activation_skipped_for_vpn() {
        let session = MacosProxySession {
            pac_url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
            services: vec!["Wi-Fi".to_string()],
            saved_state: SavedMacosProxyState::default(),
            extra_bypass: Vec::new(),
            include_domains: Vec::new(),
            activated: false,
            skipped_for_vpn: true,
            vpn_coexistence: VpnCoexistence::AutoYield,
        };
        assert!(session.summary().starts_with("standby"));

        let failed = MacosProxySession {
            skipped_for_vpn: false,
            ..session.clone()
        };
        assert!(failed.summary().starts_with("inactive"));

        let active = MacosProxySession {
            activated: true,
            skipped_for_vpn: false,
            ..session
        };
        assert!(active.summary().contains("http://127.0.0.1:8080/vdpi.pac"));
        assert!(active.summary().contains("Wi-Fi"));
    }

    #[test]
    fn matches_loopback_servers_and_env_values() {
        assert!(is_loopback_server("127.0.0.1"));
        assert!(is_loopback_server("::1"));
        assert!(is_loopback_server("[::1]"));
        assert!(is_loopback_server("localhost"));
        assert!(!is_loopback_server("10.0.0.1"));
        assert!(!is_loopback_server(""));

        assert!(is_loopback_proxy_env_value("http://127.0.0.1:8080"));
        assert!(is_loopback_proxy_env_value("socks5h://[::1]:1080/"));
        assert!(is_loopback_proxy_env_value("127.0.0.1:8080"));
        assert!(is_loopback_proxy_env_value("http://localhost:8080"));
        assert!(!is_loopback_proxy_env_value("http://10.0.0.1:8080"));
        assert!(!is_loopback_proxy_env_value(
            "http://proxy.corp.example:3128"
        ));

        assert!(is_vdpi_owned_proxy_env_value(
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_proxy_env_value(
            "socks5h://[::1]:8080/",
            "http://[::1]:8080"
        ));
        assert!(!is_vdpi_owned_proxy_env_value(
            "socks5://127.0.0.1:9050",
            "http://127.0.0.1:8080"
        ));
    }

    #[test]
    fn baseline_bypass_domains_includes_all_15_captive_portals_and_rfc6890_prefix() {
        let merged = merge_service_bypass_domains(&[], &[]);
        let expected_captive_portals = [
            "captive.apple.com",
            "www.msftconnecttest.com",
            "msftconnecttest.com",
            "ipv6.msftconnecttest.com",
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "clients3.google.com",
            "msftncsi.com",
            "www.msftncsi.com",
            "dns.msftncsi.com",
            "nmcheck.gnome.org",
            "networkcheck.kde.org",
            "connectivity-check.ubuntu.com",
            "neverssl.com",
        ];
        assert_eq!(expected_captive_portals.len(), 15);
        for portal in expected_captive_portals {
            assert!(
                BASELINE_BYPASS_DOMAINS.contains(&portal),
                "expected captive portal {portal} in BASELINE_BYPASS_DOMAINS"
            );
            assert!(
                merged.contains(&portal.to_string()),
                "expected captive portal {portal} in merged bypass domains"
            );
        }
        assert!(BASELINE_BYPASS_DOMAINS.contains(&"192.0.0.0/24"));
        assert!(merged.contains(&"192.0.0.0/24".to_string()));
    }

    #[test]
    fn pattern_matched_include_domains_filters_only_matching_baselines() {
        let existing = vec!["*.local".to_string()];

        // Unrelated --include discord.com MUST keep *.org.tr, *.gov.tr, and all other baselines.
        let discord_only =
            merge_service_bypass_domains_with_include(&existing, &[], &["discord.com".to_string()]);
        assert!(discord_only.contains(&"*.org.tr".to_string()));
        assert!(discord_only.contains(&"*.gov.tr".to_string()));
        assert!(discord_only.contains(&"*.osym.gov.tr".to_string()));
        assert!(discord_only.contains(&"paratika.com.tr".to_string()));

        // Regex --include '\.org\.tr$' removes ONLY *.org.tr.
        let org_tr_regex = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &[r"\.org\.tr$".to_string()],
        );
        assert!(!org_tr_regex.contains(&"*.org.tr".to_string()));
        assert!(org_tr_regex.contains(&"*.gov.tr".to_string()));
        assert!(org_tr_regex.contains(&"*.osym.gov.tr".to_string()));
        assert!(org_tr_regex.contains(&"*.bkm.com.tr".to_string()));
        assert!(org_tr_regex.contains(&"captive.apple.com".to_string()));

        // Specific host regex --include 'example\.gov\.tr' removes ONLY *.gov.tr,
        // keeping *.org.tr and *.osym.gov.tr intact.
        let example_gov_tr = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &[r"example\.gov\.tr".to_string()],
        );
        assert!(!example_gov_tr.contains(&"*.gov.tr".to_string()));
        assert!(example_gov_tr.contains(&"*.org.tr".to_string()));
        assert!(example_gov_tr.contains(&"*.osym.gov.tr".to_string()));
        assert!(example_gov_tr.contains(&"*.halkbank.com.tr".to_string()));

        // Broad regex --include '.*' still never strips local/private/CIDR/IP-wildcard entries.
        let wildcard_all =
            merge_service_bypass_domains_with_include(&[], &[], &[".*".to_string()]);
        for protected in [
            "localhost",
            "*.localhost",
            "*.localdomain",
            "127.0.0.1",
            "127.0.0.0/8",
            "0.0.0.0",
            "::1",
            "fc00::/7",
            "fe80::/10",
            "*.local",
            "*.lan",
            "*.internal",
            "*.home.arpa",
            "*.ts.net",
            "169.254/16",
            "192.168.*",
            "10.*",
            "172.16.0.0/12",
            "100.64.0.0/10",
            "192.0.0.0/24",
        ] {
            assert!(
                wildcard_all.contains(&protected.to_string()),
                "local/private baseline {protected} must never be stripped by --include"
            );
        }
        assert!(!wildcard_all.contains(&"*.org.tr".to_string()));
        assert!(!wildcard_all.contains(&"*.gov.tr".to_string()));

        // Invalid regex in --include does not panic and leaves unrelated baselines intact.
        let invalid_regex = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &["[unclosed-group".to_string()],
        );
        assert!(invalid_regex.contains(&"*.org.tr".to_string()));
        assert!(invalid_regex.contains(&"*.gov.tr".to_string()));
    }

    #[test]
    fn computes_disable_args_for_preexisting_non_loopback_manual_proxies() {
        let corp = NetworkServiceProxyStatus {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: String::new(),
            web_enabled: true,
            web_server: "10.0.0.5".to_string(),
            web_port: "3128".to_string(),
            secure_enabled: true,
            secure_server: "proxy.corp.example".to_string(),
            secure_port: "8443".to_string(),
            socks_enabled: true,
            socks_server: "127.0.0.1".to_string(),
            socks_port: "1080".to_string(),
        };
        assert_eq!(
            non_loopback_manual_proxy_disable_args(&corp),
            vec![
                ["-setwebproxystate", "Wi-Fi", "off"],
                ["-setsecurewebproxystate", "Wi-Fi", "off"],
            ]
        );

        let socks_corp = NetworkServiceProxyStatus {
            socks_server: "10.0.0.9".to_string(),
            web_enabled: false,
            secure_enabled: false,
            ..corp
        };
        assert_eq!(
            non_loopback_manual_proxy_disable_args(&socks_corp),
            vec![["-setsocksfirewallproxystate", "Wi-Fi", "off"]]
        );
    }

    #[cfg(unix)]
    #[test]
    fn guards_library_chown_resolves_elevation_env_and_rejects_intermediate_home_symlinks() {
        use std::os::unix::fs::symlink;

        let alice_home = Path::new("/Users/alice");
        assert!(!should_chown_state_path(
            Path::new("/Library/Application Support/vdpi/macos-proxy-state.json"),
            Some(alice_home),
        ));
        assert!(!should_chown_state_path(
            Path::new("/Library/Application Support/vdpi/.macos-proxy-state.json.1.0.tmp"),
            Some(alice_home),
        ));
        assert!(should_chown_state_path(
            Path::new("/Users/alice/.vdpi/macos-proxy-state.json"),
            Some(alice_home),
        ));

        let lookup_uid = |uid: libc::uid_t| -> Option<PasswdEntry> {
            match uid {
                501 => Some(PasswdEntry {
                    uid: 501,
                    gid: 20,
                    home_dir: PathBuf::from("/Users/alice"),
                }),
                502 => Some(PasswdEntry {
                    uid: 502,
                    gid: 20,
                    home_dir: PathBuf::from("/Users/bob"),
                }),
                _ => None,
            }
        };
        let lookup_name = |name: &str| -> Option<PasswdEntry> {
            match name {
                "alice" => Some(PasswdEntry {
                    uid: 501,
                    gid: 20,
                    home_dir: PathBuf::from("/Users/alice"),
                }),
                "carol" => Some(PasswdEntry {
                    uid: 503,
                    gid: 20,
                    home_dir: PathBuf::from("/Users/carol"),
                }),
                _ => None,
            }
        };

        // SUDO_UID + SUDO_GID
        let sudo_env = ElevationEnv {
            sudo_uid: Some("501".to_string()),
            sudo_gid: Some("80".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&sudo_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 501,
                gid: 80,
                home_dir: Some(PathBuf::from("/Users/alice")),
            })
        );

        // PKEXEC_UID
        let pkexec_env = ElevationEnv {
            pkexec_uid: Some("502".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&pkexec_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 502,
                gid: 20,
                home_dir: Some(PathBuf::from("/Users/bob")),
            })
        );

        // DOAS_USER
        let doas_env = ElevationEnv {
            doas_user: Some("carol".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&doas_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 503,
                gid: 20,
                home_dir: Some(PathBuf::from("/Users/carol")),
            })
        );

        // Real UID fallback (osascript with administrator privileges)
        let osascript_env = ElevationEnv {
            real_uid: Some(501),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&osascript_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 501,
                gid: 20,
                home_dir: Some(PathBuf::from("/Users/alice")),
            })
        );

        // Reject root / invalid elevation vars
        let root_env = ElevationEnv {
            sudo_uid: Some("0".to_string()),
            pkexec_uid: Some("0".to_string()),
            doas_user: Some("root".to_string()),
            real_uid: Some(0),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&root_env, lookup_uid, lookup_name),
            None
        );

        // Intermediate symlink check under user home
        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-intermediate-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside_dir = base.join("outside");
        fs::create_dir_all(&fake_home).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let real_subdir = fake_home.join(".vdpi-real");
        fs::create_dir_all(&real_subdir).unwrap();
        assert!(
            ensure_no_intermediate_symlink_under_home(
                &real_subdir.join("macos-proxy-state.json"),
                &fake_home,
            )
            .is_ok()
        );

        let link_subdir = fake_home.join(".vdpi-link");
        symlink(&outside_dir, &link_subdir).unwrap();
        assert!(
            ensure_no_intermediate_symlink_under_home(
                &link_subdir.join("macos-proxy-state.json"),
                &fake_home,
            )
            .is_err()
        );
        assert!(
            ensure_no_intermediate_symlink_under_home(
                &link_subdir.join("nested").join("macos-proxy-state.json"),
                &fake_home,
            )
            .is_err()
        );
        assert!(
            ensure_no_intermediate_symlink_under_home(
                &fake_home.join("..").join("outside").join("state.json"),
                &fake_home,
            )
            .is_err()
        );
        assert!(
            ensure_no_intermediate_symlink_under_home(
                &outside_dir.join("macos-proxy-state.json"),
                &fake_home,
            )
            .is_ok()
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn should_chown_state_path_requires_home_dir_allowlist() {
        let alice_home = Path::new("/Users/alice");

        // Paths strictly under the elevated user's home directory are allowed.
        assert!(should_chown_state_path(
            Path::new("/Users/alice/.vdpi/macos-proxy-state.json"),
            Some(alice_home),
        ));
        assert!(should_chown_state_path(
            Path::new("/Users/alice/.vdpi/.macos-proxy-state.json.1.0.tmp"),
            Some(alice_home),
        ));
        assert!(should_chown_state_path(
            Path::new("/Users/alice/macos-proxy-state.json"),
            Some(alice_home),
        ));

        // Paths outside home_dir (not only /Library) must be denied.
        for outside in [
            "/Library/Application Support/vdpi/macos-proxy-state.json",
            "/etc/vdpi/macos-proxy-state.json",
            "/tmp/macos-proxy-state.json",
            "/var/root/.vdpi/macos-proxy-state.json",
            "/Users/bob/.vdpi/macos-proxy-state.json",
            "/Users/alice2/.vdpi/macos-proxy-state.json",
            "/Users/alice",
            "/Users/alice/../bob/.vdpi/macos-proxy-state.json",
        ] {
            assert!(
                !should_chown_state_path(Path::new(outside), Some(alice_home)),
                "expected should_chown_state_path to deny {outside}"
            );
        }

        // Missing, empty, root, or relative home_dir must never allow chown.
        let candidate = Path::new("/Users/alice/.vdpi/macos-proxy-state.json");
        assert!(!should_chown_state_path(candidate, None));
        assert!(!should_chown_state_path(candidate, Some(Path::new(""))));
        assert!(!should_chown_state_path(candidate, Some(Path::new("/"))));
        assert!(!should_chown_state_path(
            candidate,
            Some(Path::new("Users/alice")),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn load_and_remove_state_file_reject_intermediate_symlinks_under_home() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-load-remove-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside_dir = base.join("outside");
        let real_subdir = fake_home.join(".vdpi-real");
        fs::create_dir_all(&real_subdir).unwrap();
        fs::create_dir_all(&outside_dir).unwrap();

        let outside_state = outside_dir.join("macos-proxy-state.json");
        fs::write(&outside_state, "{\"services\":[]}").unwrap();

        let link_subdir = fake_home.join(".vdpi-link");
        symlink(&outside_dir, &link_subdir).unwrap();
        let via_link = link_subdir.join("macos-proxy-state.json");

        assert!(load_from_path_with_home_guard(&via_link, Some(&fake_home)).is_err());
        assert!(!remove_state_file_with_home_guard(&via_link, Some(&fake_home)));
        assert!(
            outside_state.exists(),
            "outside file must not be unlinked through intermediate home symlink"
        );

        let direct_file_link = real_subdir.join("state-link.json");
        symlink(&outside_state, &direct_file_link).unwrap();
        assert!(load_from_path_with_home_guard(&direct_file_link, Some(&fake_home)).is_err());

        let real_state = real_subdir.join("macos-proxy-state.json");
        fs::write(&real_state, "{\"services\":[]}").unwrap();
        assert_eq!(
            load_from_path_with_home_guard(&real_state, Some(&fake_home)).unwrap(),
            Some(SavedMacosProxyState::default())
        );
        assert!(remove_state_file_with_home_guard(&real_state, Some(&fake_home)));
        assert!(!real_state.exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reconcile_refuses_to_clobber_mid_session_corporate_pac_and_manual_proxies() {
        let pac_url = "http://127.0.0.1:8080/vdpi.pac";
        let base_status = |service: &str| NetworkServiceProxyStatus {
            service: service.to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: String::new(),
            web_enabled: false,
            web_server: String::new(),
            web_port: "0".to_string(),
            secure_enabled: false,
            secure_server: String::new(),
            secure_port: "0".to_string(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: "0".to_string(),
        };

        // Pure decision tests
        let aligned = NetworkServiceProxyStatus {
            auto_proxy_enabled: true,
            auto_proxy_url: pac_url.to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&aligned, pac_url),
            ServiceReconcileDecision::AlreadyAligned
        );

        let corp_pac_on = NetworkServiceProxyStatus {
            auto_proxy_enabled: true,
            auto_proxy_url: "https://corp.example/wpad.dat".to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&corp_pac_on, pac_url),
            ServiceReconcileDecision::SkipExternalProxy
        );

        let corp_pac_off = NetworkServiceProxyStatus {
            auto_proxy_enabled: false,
            auto_proxy_url: "https://corp.example/wpad.dat".to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&corp_pac_off, pac_url),
            ServiceReconcileDecision::SkipExternalProxy
        );

        let corp_http = NetworkServiceProxyStatus {
            auto_proxy_enabled: true,
            auto_proxy_url: pac_url.to_string(),
            web_enabled: true,
            web_server: "10.0.0.5".to_string(),
            web_port: "3128".to_string(),
            ..base_status("Ethernet")
        };
        assert_eq!(
            classify_service_reconcile(&corp_http, pac_url),
            ServiceReconcileDecision::SkipExternalProxy
        );

        let corp_https = NetworkServiceProxyStatus {
            secure_enabled: true,
            secure_server: "proxy.corp.example".to_string(),
            secure_port: "8443".to_string(),
            ..base_status("Thunderbolt")
        };
        assert_eq!(
            classify_service_reconcile(&corp_https, pac_url),
            ServiceReconcileDecision::SkipExternalProxy
        );

        let corp_socks = NetworkServiceProxyStatus {
            socks_enabled: true,
            socks_server: "10.0.0.9".to_string(),
            socks_port: "1080".to_string(),
            ..base_status("USB LAN")
        };
        assert_eq!(
            classify_service_reconcile(&corp_socks, pac_url),
            ServiceReconcileDecision::SkipExternalProxy
        );

        // Disabled leftover corporate proxy + wiped PAC must still reconcile cleanly.
        let wiped_with_disabled_corp = NetworkServiceProxyStatus {
            web_enabled: false,
            web_server: "10.0.0.5".to_string(),
            web_port: "3128".to_string(),
            ..base_status("Wiped")
        };
        assert_eq!(
            classify_service_reconcile(&wiped_with_disabled_corp, pac_url),
            ServiceReconcileDecision::ApplyVdpiPac
        );

        let toggled_off_vdpi_pac = NetworkServiceProxyStatus {
            auto_proxy_enabled: false,
            auto_proxy_url: pac_url.to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&toggled_off_vdpi_pac, pac_url),
            ServiceReconcileDecision::ApplyVdpiPac
        );

        let stale_vdpi_port = NetworkServiceProxyStatus {
            auto_proxy_enabled: true,
            auto_proxy_url: "http://127.0.0.1:9999/vdpi.pac".to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&stale_vdpi_port, pac_url),
            ServiceReconcileDecision::ApplyVdpiPac
        );

        let loopback_manual_only = NetworkServiceProxyStatus {
            web_enabled: true,
            web_server: "127.0.0.1".to_string(),
            web_port: "8080".to_string(),
            ..base_status("Wi-Fi")
        };
        assert_eq!(
            classify_service_reconcile(&loopback_manual_only, pac_url),
            ServiceReconcileDecision::ApplyVdpiPac
        );

        // End-to-end reconcile_services_with verifies corporate interfaces are untouched.
        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-reconcile-non-clobber-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("macos-proxy-state.json");

        let mut initial_state = SavedMacosProxyState::default();
        for svc in ["Wi-Fi", "Ethernet", "Thunderbolt", "USB LAN", "Aligned", "Wiped"] {
            initial_state.upsert_if_absent(SavedServiceProxyState {
                service: svc.to_string(),
                ..Default::default()
            });
        }
        initial_state.save_to_path(&state_path).unwrap();

        let session = MacosProxySession {
            pac_url: pac_url.to_string(),
            services: vec!["Wi-Fi".to_string(), "Wiped".to_string()],
            saved_state: initial_state,
            extra_bypass: Vec::new(),
            include_domains: Vec::new(),
            activated: true,
            skipped_for_vpn: false,
            vpn_coexistence: VpnCoexistence::AutoYield,
        };

        let aligned_with_loopback = NetworkServiceProxyStatus {
            auto_proxy_enabled: true,
            auto_proxy_url: pac_url.to_string(),
            web_enabled: true,
            web_server: "127.0.0.1".to_string(),
            web_port: "8080".to_string(),
            ..base_status("Aligned")
        };
        let statuses = vec![
            corp_pac_on,
            corp_http,
            corp_https,
            corp_socks,
            aligned_with_loopback,
            wiped_with_disabled_corp,
        ];

        let mut bypass_writes: Vec<String> = Vec::new();
        let mut cmds: Vec<Vec<String>> = Vec::new();
        session.reconcile_services_with(
            &state_path,
            &statuses,
            |_svc| Ok(Vec::new()),
            |svc, _domains| {
                bypass_writes.push(svc.to_string());
                Ok(())
            },
            |args| {
                cmds.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
        );

        assert!(bypass_writes.is_empty());
        assert_eq!(
            cmds,
            vec![
                vec!["-setwebproxystate", "Aligned", "off"],
                vec!["-setautoproxyurl", "Wiped", pac_url],
                vec!["-setautoproxystate", "Wiped", "on"],
            ]
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reconcile_persists_state_before_mutating_and_merges_baseline_bypass_for_new_interface() {
        let pac_url = "http://127.0.0.1:8080/vdpi.pac";
        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-reconcile-new-iface-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let state_path = base.join("macos-proxy-state.json");

        let mut initial_state = SavedMacosProxyState::default();
        initial_state.upsert_if_absent(SavedServiceProxyState {
            service: "Wi-Fi".to_string(),
            bypass_domains: Some(vec!["*.local".to_string()]),
            ..Default::default()
        });
        initial_state.save_to_path(&state_path).unwrap();

        let session = MacosProxySession {
            pac_url: pac_url.to_string(),
            services: vec!["Wi-Fi".to_string()],
            saved_state: initial_state,
            extra_bypass: vec!["corp.local".to_string()],
            include_domains: vec!["example.org.tr".to_string()],
            activated: true,
            skipped_for_vpn: false,
            vpn_coexistence: VpnCoexistence::AutoYield,
        };

        let new_usb = NetworkServiceProxyStatus {
            service: "USB 10/100/1000 LAN".to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: String::new(),
            web_enabled: false,
            web_server: String::new(),
            web_port: "0".to_string(),
            secure_enabled: false,
            secure_server: String::new(),
            secure_port: "0".to_string(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: "0".to_string(),
        };
        let failing_tb = NetworkServiceProxyStatus {
            service: "Thunderbolt Ethernet".to_string(),
            ..new_usb.clone()
        };

        let mut persisted_before_bypass = false;
        let mut persisted_before_cmd = false;
        let mut bypass_calls: Vec<(String, Vec<String>)> = Vec::new();
        let mut cmd_calls: Vec<Vec<String>> = Vec::new();

        session.reconcile_services_with(
            &state_path,
            &[new_usb, failing_tb],
            |svc| match svc {
                "USB 10/100/1000 LAN" => Ok(vec!["custom.lan".to_string()]),
                "Thunderbolt Ethernet" => Ok(vec!["tb.local".to_string()]),
                _ => Ok(Vec::new()),
            },
            |svc, domains| {
                if svc == "USB 10/100/1000 LAN" {
                    let on_disk = SavedMacosProxyState::load_from_path(&state_path)
                        .unwrap()
                        .unwrap();
                    let saved = on_disk.find_service("USB 10/100/1000 LAN").unwrap();
                    assert_eq!(saved.bypass_domains, Some(vec!["custom.lan".to_string()]));
                    persisted_before_bypass = true;
                }
                bypass_calls.push((svc.to_string(), domains.to_vec()));
                Ok(())
            },
            |args| {
                if args.get(1) == Some(&"USB 10/100/1000 LAN") {
                    let on_disk = SavedMacosProxyState::load_from_path(&state_path)
                        .unwrap()
                        .unwrap();
                    assert!(on_disk.find_service("USB 10/100/1000 LAN").is_some());
                    persisted_before_cmd = true;
                }
                cmd_calls.push(args.iter().map(|s| (*s).to_string()).collect());
                if args.get(1) == Some(&"Thunderbolt Ethernet") {
                    anyhow::bail!("simulated networksetup failure");
                }
                Ok(String::new())
            },
        );

        assert!(persisted_before_bypass);
        assert!(persisted_before_cmd);

        // USB 10/100/1000 LAN received merged BASELINE_BYPASS_DOMAINS + existing + extra_bypass,
        // respecting include_domains (so *.org.tr is excluded).
        let (usb_svc, usb_merged) = &bypass_calls[0];
        assert_eq!(usb_svc, "USB 10/100/1000 LAN");
        assert!(usb_merged.contains(&"custom.lan".to_string()));
        assert!(usb_merged.contains(&"corp.local".to_string()));
        assert!(usb_merged.contains(&"localhost".to_string()));
        assert!(usb_merged.contains(&"captive.apple.com".to_string()));
        assert!(usb_merged.contains(&"*.gov.tr".to_string()));
        assert!(usb_merged.contains(&"192.0.0.0/24".to_string()));
        assert!(!usb_merged.contains(&"*.org.tr".to_string()));

        // Thunderbolt Ethernet rolled back its bypass domains when PAC activation failed.
        assert_eq!(bypass_calls.len(), 3);
        assert_eq!(bypass_calls[1].0, "Thunderbolt Ethernet");
        assert!(bypass_calls[1].1.contains(&"captive.apple.com".to_string()));
        assert_eq!(
            bypass_calls[2],
            (
                "Thunderbolt Ethernet".to_string(),
                vec!["tb.local".to_string()]
            )
        );

        assert_eq!(
            cmd_calls,
            vec![
                vec!["-setautoproxyurl", "USB 10/100/1000 LAN", pac_url],
                vec!["-setautoproxystate", "USB 10/100/1000 LAN", "on"],
                vec!["-setautoproxyurl", "Thunderbolt Ethernet", pac_url],
            ]
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn macos_proxy_reset_helpers_classify_defaults_privileges_and_guard_symlinks() {
        use std::os::unix::fs::symlink;

        assert!(bypass_domains_match_default(&[
            "*.local".to_string(),
            "169.254/16".to_string()
        ]));
        assert!(!bypass_domains_match_default(&[
            "*.local".to_string(),
            "169.254/16".to_string(),
            "localhost".to_string()
        ]));
        assert!(!bypass_domains_match_default(&[]));

        let clean = NetworkServiceProxyStatus {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: String::new(),
            web_enabled: false,
            web_server: String::new(),
            web_port: String::new(),
            secure_enabled: false,
            secure_server: String::new(),
            secure_port: String::new(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: String::new(),
        };
        let default_bypass = vec!["*.local".to_string(), "169.254/16".to_string()];
        assert!(!service_proxy_needs_reset(&clean, Some(&default_bypass)));

        let mut dirty = clean.clone();
        dirty.auto_proxy_url = "http://127.0.0.1:8080/vdpi.pac".to_string();
        assert!(service_proxy_needs_reset(&dirty, Some(&default_bypass)));
        assert!(service_proxy_needs_reset(
            &clean,
            Some(&["localhost".to_string()])
        ));

        assert!(is_macos_privilege_error("Error: (-60005) Authorization failed"));
        assert!(is_macos_privilege_error("Operation not permitted"));
        assert!(!is_macos_privilege_error("Wi-Fi is not a recognized network service"));

        let user = ElevatedUser {
            uid: 501,
            gid: 20,
            home_dir: Some(PathBuf::from("/Users/alice")),
        };
        let root_paths = collect_macos_proxy_state_paths(Some(&user), true);
        assert!(root_paths.contains(&PathBuf::from("/Users/alice/.vdpi/macos-proxy-state.json")));
        assert!(root_paths.contains(&PathBuf::from(
            "/Library/Application Support/vdpi/macos-proxy-state.json"
        )));
        assert!(root_paths.contains(&PathBuf::from("/var/root/.vdpi/macos-proxy-state.json")));

        let non_root_paths = collect_macos_proxy_state_paths(Some(&user), false);
        assert!(non_root_paths.contains(&PathBuf::from("/Users/alice/.vdpi/macos-proxy-state.json")));
        assert!(non_root_paths.contains(&PathBuf::from(
            "/Library/Application Support/vdpi/macos-proxy-state.json"
        )));
        assert!(!non_root_paths.contains(&PathBuf::from("/var/root/.vdpi/macos-proxy-state.json")));

        let base = std::env::temp_dir().join(format!(
            "vdpi-macos-reset-symlink-guard-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside = base.join("outside");
        fs::create_dir_all(fake_home.join(".vdpi")).unwrap();
        fs::create_dir_all(&outside).unwrap();

        let real_state = fake_home.join(".vdpi").join("macos-proxy-state.json");
        fs::write(&real_state, "{}").unwrap();
        let mut outcome = UnixProxyResetOutcome::default();
        remove_macos_proxy_state_file_guarded(&real_state, Some(&fake_home), true, &mut outcome);
        assert!(!real_state.exists());
        assert!(outcome.errors.is_empty());

        let victim = outside.join("victim.json");
        fs::write(&victim, "{}").unwrap();
        let sym_state = fake_home.join(".vdpi").join("macos-proxy-state.json");
        symlink(&victim, &sym_state).unwrap();
        remove_macos_proxy_state_file_guarded(&sym_state, Some(&fake_home), true, &mut outcome);
        assert!(fs::symlink_metadata(&sym_state).is_ok());
        assert!(victim.exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn reset_single_service_skips_clean_and_ignores_stale_saved_unrecognized_service() {
        let clean = NetworkServiceProxyStatus {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: String::new(),
            web_enabled: false,
            web_server: String::new(),
            web_port: String::new(),
            secure_enabled: false,
            secure_server: String::new(),
            secure_port: String::new(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: String::new(),
        };
        let default_bypass = vec!["*.local".to_string(), "169.254/16".to_string()];

        // Clean service with default bypass domains is skipped with zero networksetup calls.
        let mut outcome = UnixProxyResetOutcome::default();
        let mut calls: Vec<Vec<String>> = Vec::new();
        let priv_hit = reset_single_macos_service_with(
            "Wi-Fi",
            false,
            false,
            &clean,
            Ok(default_bypass.clone()),
            &mut outcome,
            |args| {
                calls.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
        );
        assert!(!priv_hit);
        assert!(calls.is_empty());
        assert!(!outcome.proxy_changed);
        assert!(!outcome.skipped_privileges);
        assert!(outcome.errors.is_empty());

        // Saved-state-only stale service returning "is not a recognized network service" is ignored.
        let mut stale_outcome = UnixProxyResetOutcome::default();
        let mut stale_calls: Vec<Vec<String>> = Vec::new();
        let priv_hit = reset_single_macos_service_with(
            "USB 10/100/1000 LAN",
            true,
            false,
            &clean,
            Err(anyhow::anyhow!(
                "USB 10/100/1000 LAN is not a recognized network service."
            )),
            &mut stale_outcome,
            |args| {
                stale_calls.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
        );
        assert!(!priv_hit);
        assert!(stale_calls.is_empty());
        assert!(!stale_outcome.proxy_changed);
        assert!(stale_outcome.errors.is_empty());

        // Also ignored if get_proxy_bypass_domains errored generically and run_cmd reports unrecognized.
        let mut stale_cmd_outcome = UnixProxyResetOutcome::default();
        let priv_hit = reset_single_macos_service_with(
            "USB 10/100/1000 LAN",
            true,
            false,
            &clean,
            Err(anyhow::anyhow!("transient failure")),
            &mut stale_cmd_outcome,
            |_args| {
                Err(anyhow::anyhow!(
                    "USB 10/100/1000 LAN is not a recognized network service."
                ))
            },
        );
        assert!(!priv_hit);
        assert!(!stale_cmd_outcome.proxy_changed);
        assert!(stale_cmd_outcome.errors.is_empty());
    }

    #[test]
    fn restore_service_clears_pac_url_preserves_mid_session_external_bypass_and_supports_non_loopback() {
        let base_status = NetworkServiceProxyStatus {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: true,
            auto_proxy_url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
            web_enabled: false,
            web_server: String::new(),
            web_port: String::new(),
            secure_enabled: false,
            secure_server: String::new(),
            secure_port: String::new(),
            socks_enabled: false,
            socks_server: String::new(),
            socks_port: String::new(),
        };
        let saved_clean = SavedServiceProxyState {
            service: "Wi-Fi".to_string(),
            autoproxy: AutoProxyState::default(),
            webproxy: ManualProxyState::default(),
            securewebproxy: ManualProxyState::default(),
            socksfirewallproxy: ManualProxyState::default(),
            bypass_domains: Some(vec!["*.local".to_string(), "169.254/16".to_string()]),
        };

        // 1. Clearing vdpi PAC with no prior corporate PAC clears AutoProxyURL then disables state,
        //    and restores bypass_domains.
        let mut cmds: Vec<Vec<String>> = Vec::new();
        let mut restored_bypass: Vec<Vec<String>> = Vec::new();
        restore_service_proxy_state_with(
            "Wi-Fi",
            &base_status,
            Some(&saved_clean),
            Some("http://127.0.0.1:8080/vdpi.pac"),
            |args| {
                cmds.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
            |_svc, domains| {
                restored_bypass.push(domains.to_vec());
                Ok(())
            },
        );
        assert_eq!(
            cmds,
            vec![
                vec!["-setautoproxyurl", "Wi-Fi", ""],
                vec!["-setautoproxystate", "Wi-Fi", "off"],
            ]
        );
        assert_eq!(
            restored_bypass,
            vec![vec!["*.local".to_string(), "169.254/16".to_string()]]
        );

        // 2. Non-loopback --addr PAC URL is recognized via expected_pac_url and cleared cleanly.
        let mut non_loopback = base_status.clone();
        non_loopback.auto_proxy_url = "http://192.168.1.50:8080/vdpi.pac".to_string();
        assert_eq!(
            classify_service_reconcile(&non_loopback, "http://192.168.1.50:8080/vdpi.pac"),
            ServiceReconcileDecision::AlreadyAligned
        );
        let mut non_loopback_cmds: Vec<Vec<String>> = Vec::new();
        let mut non_loopback_bypass: Vec<Vec<String>> = Vec::new();
        restore_service_proxy_state_with(
            "Wi-Fi",
            &non_loopback,
            Some(&saved_clean),
            Some("http://192.168.1.50:8080/vdpi.pac"),
            |args| {
                non_loopback_cmds.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
            |_svc, domains| {
                non_loopback_bypass.push(domains.to_vec());
                Ok(())
            },
        );
        assert_eq!(
            non_loopback_cmds,
            vec![
                vec!["-setautoproxyurl", "Wi-Fi", ""],
                vec!["-setautoproxystate", "Wi-Fi", "off"],
            ]
        );
        assert_eq!(non_loopback_bypass.len(), 1);

        // 3. Mid-session corporate PAC enabled -> skip clearing PAC and skip restoring bypass_domains.
        let mut corp_pac = base_status.clone();
        corp_pac.auto_proxy_url = "https://corp.example/wpad.dat".to_string();
        let mut corp_cmds: Vec<Vec<String>> = Vec::new();
        let mut corp_bypass: Vec<Vec<String>> = Vec::new();
        restore_service_proxy_state_with(
            "Wi-Fi",
            &corp_pac,
            Some(&saved_clean),
            Some("http://127.0.0.1:8080/vdpi.pac"),
            |args| {
                corp_cmds.push(args.iter().map(|s| (*s).to_string()).collect());
                Ok(String::new())
            },
            |_svc, domains| {
                corp_bypass.push(domains.to_vec());
                Ok(())
            },
        );
        assert!(corp_cmds.is_empty());
        assert!(corp_bypass.is_empty());

        // 4. Mid-session corporate manual proxy enabled -> skip restoring bypass_domains.
        let mut corp_manual = base_status.clone();
        corp_manual.web_enabled = true;
        corp_manual.web_server = "proxy.corp.example".to_string();
        corp_manual.web_port = "3128".to_string();
        let mut manual_bypass: Vec<Vec<String>> = Vec::new();
        restore_service_proxy_state_with(
            "Wi-Fi",
            &corp_manual,
            Some(&saved_clean),
            Some("http://127.0.0.1:8080/vdpi.pac"),
            |_args| Ok(String::new()),
            |_svc, domains| {
                manual_bypass.push(domains.to_vec());
                Ok(())
            },
        );
        assert!(manual_bypass.is_empty());
    }

    #[test]
    fn wildcard_include_domains_override_matching_macos_baselines() {
        let existing = vec!["*.local".to_string()];
        let org_tr_wildcard = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &["*.org.tr".to_string()],
        );
        assert!(!org_tr_wildcard.contains(&"*.org.tr".to_string()));
        assert!(org_tr_wildcard.contains(&"*.gov.tr".to_string()));
        assert!(org_tr_wildcard.contains(&"localhost".to_string()));
        assert!(org_tr_wildcard.contains(&"192.168.*".to_string()));

        let dot_gov_tr = merge_service_bypass_domains_with_include(
            &existing,
            &[],
            &[".gov.tr".to_string()],
        );
        assert!(!dot_gov_tr.contains(&"*.gov.tr".to_string()));
        assert!(!dot_gov_tr.contains(&"*.osym.gov.tr".to_string()));
        assert!(dot_gov_tr.contains(&"*.org.tr".to_string()));
    }
}
