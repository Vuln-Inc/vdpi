use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use vdpi_core::config::VpnCoexistence;
use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, FILETIME, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub mod foreground;

pub const VDPI_PAC_PATH: &str = "/vdpi.pac";
pub const WINDOWS_PROXY_STATE_FILENAME: &str = "windows-proxy-state.json";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INTERNET_SETTINGS_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const USER_ENV_SUBKEY: &str = "Environment";
const SYSTEM_ENV_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;

const HWND_BROADCAST: *mut c_void = 0xffffusize as *mut c_void;
const WM_SETTINGCHANGE: u32 = 0x001A;
const SMTO_ABORTIFHUNG: u32 = 0x0002;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const FILE_SHARE_READ: u32 = 0x0000_0001;
const FILE_SHARE_WRITE: u32 = 0x0000_0002;
const FILE_SHARE_DELETE: u32 = 0x0000_0004;
const OPEN_EXISTING: u32 = 3;

const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

const ERROR_SUCCESS: u32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_ALREADY_EXISTS: i32 = 183;

const SDDL_REVISION_1: u32 = 1;
const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

/// Protected DACL for `C:\ProgramData\vdpi`:
/// - `P`: blocks inherited `ProgramData` ACEs that otherwise allow standard users to create files/junctions
/// - `SY` (`NT AUTHORITY\SYSTEM`): Full Control (`FA`), inherited by child dirs/files (`OICI`)
/// - `BA` (`BUILTIN\Administrators`): Full Control (`FA`), inherited by child dirs/files (`OICI`)
/// - `BU` (`BUILTIN\Users`): Read & Execute / traverse (`FRFX`), inherited by child dirs/files (`OICI`)
const PROGRAMDATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

static RUNNING_AS_SERVICE: AtomicBool = AtomicBool::new(false);
static STATE_SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
#[allow(dead_code)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
#[allow(dead_code)]
struct ByHandleFileInformation {
    dw_file_attributes: u32,
    ft_creation_time: FILETIME,
    ft_last_access_time: FILETIME,
    ft_last_write_time: FILETIME,
    dw_volume_serial_number: u32,
    n_file_size_high: u32,
    n_file_size_low: u32,
    n_number_of_links: u32,
    n_file_index_high: u32,
    n_file_index_low: u32,
}

pub fn set_running_as_service(active: bool) {
    RUNNING_AS_SERVICE.store(active, Ordering::SeqCst);
}

pub fn is_running_as_service() -> bool {
    RUNNING_AS_SERVICE.load(Ordering::SeqCst)
}

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
    fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
    fn CreateDirectoryW(
        lp_path_name: *const u16,
        lp_security_attributes: *mut c_void,
    ) -> i32;
    fn CreateFileW(
        lp_file_name: *const u16,
        dw_desired_access: u32,
        dw_share_mode: u32,
        lp_security_attributes: *mut c_void,
        dw_creation_disposition: u32,
        dw_flags_and_attributes: u32,
        h_template_file: HANDLE,
    ) -> HANDLE;
    fn GetFileInformationByHandle(
        h_file: HANDLE,
        lp_file_information: *mut ByHandleFileInformation,
    ) -> i32;
    fn MoveFileExW(
        lp_existing_file_name: *const u16,
        lp_new_file_name: *const u16,
        dw_flags: u32,
    ) -> i32;
    fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        p_security_descriptor: *mut c_void,
        lpb_dacl_present: *mut i32,
        p_dacl: *mut *mut c_void,
        lpb_dacl_defaulted: *mut i32,
    ) -> i32;
    fn SetSecurityInfo(
        handle: HANDLE,
        object_type: u32,
        security_info: u32,
        psid_owner: *mut c_void,
        psid_group: *mut c_void,
        p_dacl: *mut c_void,
        p_sacl: *mut c_void,
    ) -> u32;
}

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        h_internet: *mut c_void,
        dw_option: u32,
        lp_buffer: *mut c_void,
        dw_buffer_length: u32,
    ) -> i32;
}

#[link(name = "user32")]
extern "system" {
    fn SendMessageTimeoutW(
        h_wnd: *mut c_void,
        msg: u32,
        w_param: usize,
        l_param: isize,
        fu_flags: u32,
        u_timeout: u32,
        lpdw_result: *mut usize,
    ) -> isize;
}

fn windows_system32_dir() -> PathBuf {
    let mut buf = vec![0u16; 260];
    loop {
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            break;
        }
        if (len as usize) < buf.len() {
            let dir = String::from_utf16_lossy(&buf[..len as usize]);
            if !dir.trim().is_empty() {
                return PathBuf::from(dir);
            }
            break;
        }
        buf.resize(len as usize + 1, 0);
    }
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .filter(|v| !v.is_empty())
        .map(|root| PathBuf::from(root).join("System32"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"))
}

fn system32_exe(name: &str) -> PathBuf {
    static SYSTEM32_DIR: OnceLock<PathBuf> = OnceLock::new();
    SYSTEM32_DIR.get_or_init(windows_system32_dir).join(name)
}

/// Best-effort call to `DnsFlushResolverCache()` in `dnsapi.dll` (loaded strictly from System32).
pub fn flush_dns_resolver_cache() {
    type DnsFlushResolverCacheFn = unsafe extern "system" fn() -> i32;
    struct ModuleGuard(HMODULE);
    impl Drop for ModuleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = FreeLibrary(self.0);
                }
            }
        }
    }

    let dnsapi_w: Vec<u16> = "dnsapi.dll\0".encode_utf16().collect();
    let hmod = unsafe {
        LoadLibraryExW(
            dnsapi_w.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if hmod.is_null() {
        debug!("could not load dnsapi.dll to flush DNS resolver cache");
        return;
    }
    let _guard = ModuleGuard(hmod);
    if let Some(proc) =
        unsafe { GetProcAddress(hmod, c"DnsFlushResolverCache".as_ptr().cast::<u8>()) }
    {
        let flush_fn: DnsFlushResolverCacheFn = unsafe { std::mem::transmute_copy(&proc) };
        let ok = unsafe { flush_fn() };
        debug!(ok = (ok != 0), "invoked DnsFlushResolverCache()");
    }
}

fn is_vdpi_owned_wininet_endpoint(endpoint: &str) -> bool {
    let port = endpoint
        .strip_prefix("127.0.0.1:")
        .or_else(|| endpoint.strip_prefix("[::1]:"))
        .or_else(|| endpoint.strip_prefix("localhost:"));
    port.is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

pub fn is_vdpi_owned_wininet_server(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if is_vdpi_owned_wininet_endpoint(&lower) {
        return true;
    }
    let mut matched = false;
    for raw_entry in lower.split(';') {
        let entry = raw_entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((scheme, endpoint)) = entry.split_once('=') else {
            return false;
        };
        let scheme = scheme.trim();
        let endpoint = endpoint.trim();
        if !matches!(scheme, "http" | "https") || !is_vdpi_owned_wininet_endpoint(endpoint) {
            return false;
        }
        matched = true;
    }
    matched
}

pub fn is_vdpi_owned_winhttp_proxy(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_vdpi_owned_proxy_env(trimmed) {
        return true;
    }
    trimmed.split([';', ' ', '\t']).any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        let val = entry.split_once('=').map_or(entry, |(_, v)| v.trim());
        is_vdpi_owned_proxy_env(val)
    })
}

pub fn build_windows_pac_url(addr: IpAddr, port: u16) -> String {
    let connect_ip = normalize_client_proxy_ip(addr);
    let authority = SocketAddr::new(connect_ip, port);
    format!("http://{authority}{VDPI_PAC_PATH}")
}

pub fn is_vdpi_owned_pac_url(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, path)) = rest.split_once('/') else {
        return false;
    };
    if authority.is_empty() || authority.contains(char::is_whitespace) {
        return false;
    }
    let path_without_query = path.split(['?', '#']).next().unwrap_or("");
    if path_without_query != "vdpi.pac" {
        return false;
    }
    let Some((host, port_str)) = authority.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && !port_str.is_empty() && port_str.bytes().all(|b| b.is_ascii_digit())
}

fn normalize_client_proxy_ip(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

/// Snapshot of a single Registry hive's prior WinINET settings captured before `vdpi`
/// enables its fail-open PAC `AutoConfigURL`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedWininetHiveState {
    #[serde(default)]
    pub proxy_enable: bool,
    #[serde(default)]
    pub proxy_server: Option<String>,
    #[serde(default)]
    pub proxy_override: Option<String>,
    #[serde(default)]
    pub auto_config_url: Option<String>,
}

/// Persisted WinINET proxy snapshots keyed by Registry hive root (e.g. `HKCU`, `HKU\S-1-5-21-...`).
///
/// Uses `#[serde(default)]` on every field so older single-hive `state.json` / proxy-state files
/// lacking `auto_config_url` or `hives` remain backwards-compatible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedWindowsProxyState {
    #[serde(default)]
    pub proxy_enable: bool,
    #[serde(default)]
    pub proxy_server: Option<String>,
    #[serde(default)]
    pub proxy_override: Option<String>,
    #[serde(default)]
    pub auto_config_url: Option<String>,
    #[serde(default)]
    pub hives: BTreeMap<String, SavedWininetHiveState>,
}

impl SavedWindowsProxyState {
    pub fn state_for_root(&self, root: &str) -> Option<SavedWininetHiveState> {
        if let Some((_, entry)) = self
            .hives
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(root))
        {
            return Some(entry.clone());
        }
        if self.hives.is_empty()
            && root.eq_ignore_ascii_case("HKCU")
            && (self.proxy_enable
                || self.proxy_server.is_some()
                || self.proxy_override.is_some()
                || self.auto_config_url.is_some())
        {
            return Some(SavedWininetHiveState {
                proxy_enable: self.proxy_enable,
                proxy_server: self.proxy_server.clone(),
                proxy_override: self.proxy_override.clone(),
                auto_config_url: self.auto_config_url.clone(),
            });
        }
        None
    }

    fn record_hive_if_absent(&mut self, root: &str, raw: SavedWininetHiveState) -> bool {
        if self.hives.keys().any(|k| k.eq_ignore_ascii_case(root)) {
            return false;
        }
        let sanitized = sanitize_captured_wininet_state(raw);
        if root.eq_ignore_ascii_case("HKCU") {
            self.proxy_enable = sanitized.proxy_enable;
            self.proxy_server = sanitized.proxy_server.clone();
            self.proxy_override = sanitized.proxy_override.clone();
            self.auto_config_url = sanitized.auto_config_url.clone();
        }
        self.hives.insert(root.to_string(), sanitized);
        true
    }

    fn merge_missing_from(&mut self, other: &SavedWindowsProxyState) -> bool {
        let mut added = false;
        for (root, state) in &other.hives {
            if self.record_hive_if_absent(root, state.clone()) {
                added = true;
            }
        }
        if other.hives.is_empty() {
            if let Some(hkcu) = other.state_for_root("HKCU") {
                if self.record_hive_if_absent("HKCU", hkcu) {
                    added = true;
                }
            }
        }
        added
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CurrentWininetState {
    proxy_enable: bool,
    proxy_server: String,
    auto_config_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AutoConfigAction {
    Keep,
    Delete,
    Set(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManualProxyAction {
    Keep,
    Disable,
    Restore {
        server: String,
        override_list: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WininetRestorePlan {
    auto_config: AutoConfigAction,
    manual_proxy: ManualProxyAction,
}

fn sanitize_captured_wininet_state(raw: SavedWininetHiveState) -> SavedWininetHiveState {
    let auto_config_url = raw
        .auto_config_url
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty() && !is_vdpi_owned_pac_url(u));

    let vdpi_manual = raw
        .proxy_server
        .as_deref()
        .is_some_and(is_vdpi_owned_wininet_server);

    let (proxy_enable, proxy_server, proxy_override) = if vdpi_manual {
        (false, None, None)
    } else {
        (
            raw.proxy_enable,
            raw.proxy_server
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            raw.proxy_override
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        )
    };

    SavedWininetHiveState {
        proxy_enable,
        proxy_server,
        proxy_override,
        auto_config_url,
    }
}

fn plan_wininet_restore(
    current: &CurrentWininetState,
    prior: Option<&SavedWininetHiveState>,
) -> WininetRestorePlan {
    let valid_prior_pac = prior
        .and_then(|p| p.auto_config_url.as_deref())
        .map(str::trim)
        .filter(|u| !u.is_empty() && !is_vdpi_owned_pac_url(u))
        .map(ToString::to_string);

    let current_pac = current
        .auto_config_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());

    let auto_config = match current_pac {
        Some(curr) if is_vdpi_owned_pac_url(curr) => match valid_prior_pac {
            Some(prev) => AutoConfigAction::Set(prev),
            None => AutoConfigAction::Delete,
        },
        None => match valid_prior_pac {
            Some(prev) => AutoConfigAction::Set(prev),
            None => AutoConfigAction::Keep,
        },
        Some(_) => AutoConfigAction::Keep,
    };

    let valid_prior_manual = prior.and_then(|p| {
        if !p.proxy_enable {
            return None;
        }
        let server = p.proxy_server.as_deref()?.trim();
        if server.is_empty() || is_vdpi_owned_wininet_server(server) {
            return None;
        }
        let override_list = p
            .proxy_override
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);
        Some((server.to_string(), override_list))
    });

    let manual_proxy =
        if current.proxy_enable && is_vdpi_owned_wininet_server(&current.proxy_server) {
            match valid_prior_manual {
                Some((server, override_list)) => ManualProxyAction::Restore {
                    server,
                    override_list,
                },
                None => ManualProxyAction::Disable,
            }
        } else if !current.proxy_enable {
            match valid_prior_manual {
                Some((server, override_list)) => ManualProxyAction::Restore {
                    server,
                    override_list,
                },
                None => ManualProxyAction::Keep,
            }
        } else {
            ManualProxyAction::Keep
        };

    WininetRestorePlan {
        auto_config,
        manual_proxy,
    }
}

fn programdata_vdpi_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("vdpi")
}

fn encode_wide_nul(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn is_reparse_point_attrs(attrs: u32) -> bool {
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

fn path_attributes_no_follow(path: &Path) -> std::io::Result<Option<u32>> {
    let wide = encode_wide_nul(path);
    // SAFETY: `wide` is valid NUL-terminated UTF-16 for the synchronous `GetFileAttributesW` call.
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs != INVALID_FILE_ATTRIBUTES {
        return Ok(Some(attrs));
    }
    let err = std::io::Error::last_os_error();
    if matches!(
        err.raw_os_error(),
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
    ) || err.kind() == ErrorKind::NotFound
    {
        return Ok(None);
    }
    Err(err)
}

fn reject_reparse_point(path: &Path) -> Result<()> {
    if let Some(attrs) = path_attributes_no_follow(path)
        .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
    {
        if is_reparse_point_attrs(attrs) {
            anyhow::bail!("refusing to access NTFS reparse point: {}", path.display());
        }
    }
    Ok(())
}

fn reject_reparse_point_or_dir(path: &Path) -> Result<()> {
    if let Some(attrs) = path_attributes_no_follow(path)
        .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
    {
        if is_reparse_point_attrs(attrs) {
            anyhow::bail!("refusing to access NTFS reparse point: {}", path.display());
        }
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            anyhow::bail!(
                "refusing to treat directory as state file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

struct LocalAllocGuard(*mut c_void);

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(self.0);
            }
        }
    }
}

struct ParsedHardenedSd {
    sd: LocalAllocGuard,
    dacl: *mut c_void,
}

impl ParsedHardenedSd {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        let mut sd_size: u32 = 0;
        // SAFETY: `sddl_w` is NUL-terminated UTF-16; `sd` and `sd_size` are valid out-pointers.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut sd_size,
            )
        };
        if ok == 0 || sd.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(err).context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
        }
        let guard = LocalAllocGuard(sd);

        let mut dacl_present: i32 = 0;
        let mut dacl_defaulted: i32 = 0;
        let mut dacl: *mut c_void = std::ptr::null_mut();
        // SAFETY: `guard.0` is a valid security descriptor allocated above.
        let dacl_ok = unsafe {
            GetSecurityDescriptorDacl(
                guard.0,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        };
        if dacl_ok == 0 || dacl_present == 0 || dacl.is_null() {
            let err = std::io::Error::last_os_error();
            return Err(err).context("GetSecurityDescriptorDacl failed to extract hardened DACL");
        }

        Ok(Self { sd: guard, dacl })
    }

    fn as_sd_ptr(&self) -> *mut c_void {
        self.sd.0
    }

    fn as_dacl_ptr(&self) -> *mut c_void {
        self.dacl
    }
}

fn create_dir_with_hardened_dacl(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        if !parent.exists() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create ancestor directory {}", parent.display())
            })?;
        }
    }

    let parsed_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_SDDL)?;
    let mut sa = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: parsed_sd.as_sd_ptr(),
        b_inherit_handle: 0,
    };
    let dir_w = encode_wide_nul(dir);
    // SAFETY: `dir_w` is NUL-terminated UTF-16 and `sa` borrows `parsed_sd` for the
    // synchronous `CreateDirectoryW` call.
    let ok =
        unsafe { CreateDirectoryW(dir_w.as_ptr(), (&mut sa as *mut SecurityAttributes).cast()) };
    if ok != 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
        return Ok(());
    }
    Err(err).with_context(|| format!("failed to create hardened directory {}", dir.display()))
}

fn apply_hardened_dir_dacl(dir: &Path) -> Result<()> {
    reject_reparse_point(dir)?;

    let parsed_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_SDDL)?;
    let dir_w = encode_wide_nul(dir);
    // Open the directory handle itself without following reparse points so the attribute
    // check and `SetSecurityInfo` target the exact same kernel object (no TOCTOU).
    // SAFETY: `dir_w` is valid NUL-terminated UTF-16; returned handle is owned by `HandleGuard`.
    let raw_handle = unsafe {
        CreateFileW(
            dir_w.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw_handle.is_null() || raw_handle == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        return Err(err).with_context(|| {
            format!(
                "failed to open directory {} for DACL hardening",
                dir.display()
            )
        });
    }
    let _guard = HandleGuard(raw_handle);

    // SAFETY: `info` is a plain C struct initialized before calling `GetFileInformationByHandle`.
    let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
    let info_ok = unsafe { GetFileInformationByHandle(raw_handle, &mut info) };
    if info_ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(err).with_context(|| {
            format!(
                "GetFileInformationByHandle failed for directory {}",
                dir.display()
            )
        });
    }
    if is_reparse_point_attrs(info.dw_file_attributes) {
        anyhow::bail!(
            "refusing to apply DACL to NTFS reparse point directory: {}",
            dir.display()
        );
    }
    if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        anyhow::bail!(
            "refusing to apply directory DACL to non-directory path: {}",
            dir.display()
        );
    }

    // SAFETY: `raw_handle` is a valid directory handle owned by `_guard`, and
    // `parsed_sd` keeps the DACL pointer alive for the synchronous `SetSecurityInfo` call.
    let status = unsafe {
        SetSecurityInfo(
            raw_handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            parsed_sd.as_dacl_ptr(),
            std::ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .with_context(|| format!("SetSecurityInfo failed to harden DACL on {}", dir.display()));
    }
    Ok(())
}

fn ensure_safe_state_dir(dir: &Path, harden_dacl: bool) -> Result<()> {
    match path_attributes_no_follow(dir)
        .with_context(|| format!("failed to inspect state directory {}", dir.display()))?
    {
        Some(attrs) => {
            if is_reparse_point_attrs(attrs) {
                anyhow::bail!(
                    "refusing to use NTFS reparse point as state directory: {}",
                    dir.display()
                );
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                anyhow::bail!(
                    "state directory path exists and is not a directory: {}",
                    dir.display()
                );
            }
        }
        None => {
            if harden_dacl {
                create_dir_with_hardened_dacl(dir)?;
            } else {
                fs::create_dir_all(dir).with_context(|| {
                    format!("failed to create state directory {}", dir.display())
                })?;
            }
            let attrs = path_attributes_no_follow(dir)
                .with_context(|| format!("failed to verify state directory {}", dir.display()))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "state directory disappeared after creation: {}",
                        dir.display()
                    )
                })?;
            if is_reparse_point_attrs(attrs) {
                anyhow::bail!(
                    "refusing to use NTFS reparse point as state directory: {}",
                    dir.display()
                );
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                anyhow::bail!(
                    "state directory path is not a directory after creation: {}",
                    dir.display()
                );
            }
        }
    }

    if harden_dacl {
        apply_hardened_dir_dacl(dir)?;
    }

    Ok(())
}

fn atomic_replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    const RETRY_DELAYS_MS: [u64; 5] = [10, 25, 50, 100, 200];

    let src_w = encode_wide_nul(src);
    let dst_w = encode_wide_nul(dst);

    for delay_ms in RETRY_DELAYS_MS.iter().copied().chain(std::iter::once(0)) {
        // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 buffers that
        // remain alive for the entire synchronous `MoveFileExW` call.
        let ok = unsafe {
            MoveFileExW(
                src_w.as_ptr(),
                dst_w.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        let retryable = matches!(
            err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        );
        if retryable && delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
            continue;
        }
        return Err(err);
    }

    Err(std::io::Error::last_os_error())
}

fn windows_proxy_state_write_path() -> Option<(PathBuf, bool)> {
    if is_running_as_service() {
        return Some((
            programdata_vdpi_dir().join(WINDOWS_PROXY_STATE_FILENAME),
            true,
        ));
    }
    if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        return Some((
            PathBuf::from(local_appdata)
                .join("vdpi")
                .join(WINDOWS_PROXY_STATE_FILENAME),
            false,
        ));
    }
    std::env::var_os("USERPROFILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .map(|home| {
            (
                home.join(".vdpi").join(WINDOWS_PROXY_STATE_FILENAME),
                false,
            )
        })
}

fn windows_proxy_state_read_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    paths.push(programdata_vdpi_dir().join(WINDOWS_PROXY_STATE_FILENAME));
    if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(local_appdata)
            .join("vdpi")
            .join(WINDOWS_PROXY_STATE_FILENAME);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if let Some(home) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        let p = PathBuf::from(home)
            .join(".vdpi")
            .join(WINDOWS_PROXY_STATE_FILENAME);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

fn read_windows_proxy_state_from_path(path: &Path) -> Option<SavedWindowsProxyState> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        match path_attributes_no_follow(parent) {
            Ok(Some(attrs)) if is_reparse_point_attrs(attrs) => {
                warn!(
                    path = %parent.display(),
                    "refusing to read Windows proxy state from NTFS reparse point directory"
                );
                return None;
            }
            Ok(Some(attrs)) if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 => {
                warn!(
                    path = %parent.display(),
                    "Windows proxy state parent path is not a directory"
                );
                return None;
            }
            Ok(None) => return None,
            Ok(Some(_)) => {}
            Err(err) => {
                warn!(
                    path = %parent.display(),
                    error = %err,
                    "failed to inspect Windows proxy state directory attributes"
                );
                return None;
            }
        }
    }

    match path_attributes_no_follow(path) {
        Ok(Some(attrs)) if is_reparse_point_attrs(attrs) => {
            warn!(
                path = %path.display(),
                "refusing to read Windows proxy state from NTFS reparse point file"
            );
            return None;
        }
        Ok(Some(attrs)) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => {
            warn!(
                path = %path.display(),
                "refusing to read Windows proxy state because target is a directory"
            );
            return None;
        }
        Ok(None) => return None,
        Ok(Some(_)) => {}
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to inspect Windows proxy state file attributes"
            );
            return None;
        }
    }

    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return None,
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to open Windows proxy state file"
            );
            return None;
        }
    };

    let meta = match file.metadata() {
        Ok(m) => m,
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to read metadata for Windows proxy state file"
            );
            return None;
        }
    };
    if is_reparse_point_attrs(meta.file_attributes()) || !meta.is_file() {
        warn!(
            path = %path.display(),
            "refusing to read Windows proxy state: opened handle is a reparse point or non-file"
        );
        return None;
    }

    let mut raw = String::new();
    if let Err(err) = file.read_to_string(&mut raw) {
        warn!(
            path = %path.display(),
            error = %err,
            "failed to read Windows proxy state file contents"
        );
        return None;
    }

    match serde_json::from_str::<SavedWindowsProxyState>(&raw) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "ignoring corrupt Windows proxy state JSON"
            );
            None
        }
    }
}

fn load_saved_windows_proxy_state() -> SavedWindowsProxyState {
    let mut merged = SavedWindowsProxyState::default();
    for path in windows_proxy_state_read_paths() {
        if let Some(parsed) = read_windows_proxy_state_from_path(&path) {
            let _ = merged.merge_missing_from(&parsed);
        }
    }
    merged
}

fn save_windows_proxy_state_to_path(
    path: &Path,
    state: &SavedWindowsProxyState,
    harden_parent_dacl: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("state file path has no parent directory: {}", path.display())
        })?;
    ensure_safe_state_dir(parent, harden_parent_dacl)?;
    reject_reparse_point_or_dir(path)?;

    let json = serde_json::to_string(state).context("failed to serialize Windows proxy state")?;
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|n| !n.is_empty())
        .unwrap_or(WINDOWS_PROXY_STATE_FILENAME);
    let pid = std::process::id();
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut created = None;
    for _ in 0..16 {
        let seq = STATE_SAVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{ts_nanos}.{seq}"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create unique temporary state file {}",
                        candidate.display()
                    )
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

    let write_res = (|| -> Result<()> {
        file.write_all(json.as_bytes()).with_context(|| {
            format!(
                "failed to write temporary state file {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!("failed to sync temporary state file {}", tmp_path.display())
        })?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    // Re-check both parent directory and destination file right before atomic replacement.
    if let Err(err) = reject_reparse_point(parent).and_then(|()| reject_reparse_point_or_dir(path))
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = atomic_replace_file(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                tmp_path.display()
            )
        });
    }

    Ok(())
}

fn save_windows_proxy_state(state: &SavedWindowsProxyState) {
    let Some((path, harden_parent_dacl)) = windows_proxy_state_write_path() else {
        return;
    };
    if let Err(err) = save_windows_proxy_state_to_path(&path, state, harden_parent_dacl) {
        warn!(
            path = %path.display(),
            error = %err,
            "failed to atomically persist Windows proxy state"
        );
    }
}

fn remove_windows_proxy_state_at_path(path: &Path) -> bool {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        match path_attributes_no_follow(parent) {
            Ok(Some(attrs)) if is_reparse_point_attrs(attrs) => {
                warn!(
                    path = %parent.display(),
                    "refusing to remove Windows proxy state inside NTFS reparse point directory"
                );
                return false;
            }
            Ok(Some(attrs)) if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 => return false,
            Ok(None) | Err(_) => return false,
            Ok(Some(_)) => {}
        }
    }

    match path_attributes_no_follow(path) {
        Ok(Some(attrs)) if is_reparse_point_attrs(attrs) => {
            warn!(
                path = %path.display(),
                "refusing to remove NTFS reparse point at Windows proxy state path"
            );
            return false;
        }
        Ok(Some(attrs)) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => return false,
        Ok(None) | Err(_) => return false,
        Ok(Some(_)) => {}
    }

    fs::remove_file(path).is_ok()
}

fn remove_saved_windows_proxy_state_files() {
    for path in windows_proxy_state_read_paths() {
        let _ = remove_windows_proxy_state_at_path(&path);
    }
}

#[derive(Debug, Clone)]
pub struct WindowsProxySession {
    addr: IpAddr,
    http_port: u16,
    vpn_coexistence: VpnCoexistence,
    saved_state: Arc<Mutex<SavedWindowsProxyState>>,
}

fn should_skip_reconcile_for_vpn(mode: VpnCoexistence) -> bool {
    mode == VpnCoexistence::AutoYield
}

impl WindowsProxySession {
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        _socks_port: Option<u16>,
        _enable_socks_system_proxy: bool,
        _enable_env_proxy: bool,
        _extra_bypass: &[String],
    ) -> Result<Self> {
        let client_ip = normalize_client_proxy_ip(addr);
        let pac_url = build_windows_pac_url(client_ip, http_port);
        let service_mode = is_running_as_service();
        let roots = target_proxy_roots();

        // Preserve any already-saved pre-vdpi state across crash/restart so Defender kills
        // or abrupt restarts never overwrite the user's original proxy configuration.
        let mut saved_state = load_saved_windows_proxy_state();
        for root in &roots {
            let inet_key = internet_settings_key(root);
            let _ = saved_state.record_hive_if_absent(root, capture_wininet_state(&inet_key));
        }
        save_windows_proxy_state(&saved_state);

        let mut env_cleaned = false;
        for root in &roots {
            let inet_key = internet_settings_key(root);
            if let Err(e) = apply_wininet_pac_proxy(&inet_key, &pac_url) {
                if service_mode {
                    warn!(hive = %root, error = %e, "failed to apply WinINET fail-open PAC proxy to user hive");
                } else {
                    return Err(e);
                }
            }

            // Never write persistent HKCU\Environment HTTP_PROXY/HTTPS_PROXY/NO_PROXY because
            // Registry env vars cannot fail open if vdpi.exe is killed or quarantined. Clean up
            // any stale vdpi-owned env vars left over from older versions so upgrades auto-heal.
            let env_key = user_env_key(root);
            if unset_windows_user_env(&env_key) {
                env_cleaned = true;
            }
        }

        // Auto-heal any legacy fail-closed WinHTTP manual proxy left by older vdpi versions.
        reset_winhttp_proxy_if_vdpi();

        notify_wininet_refresh();
        if env_cleaned {
            broadcast_environment_change();
        }

        info!(
            pac_url = %pac_url,
            service_mode,
            hives = roots.len(),
            "configured Windows WinINET fail-open PAC system proxy"
        );

        Ok(Self {
            addr: client_ip,
            http_port,
            vpn_coexistence: VpnCoexistence::AutoYield,
            saved_state: Arc::new(Mutex::new(saved_state)),
        })
    }

    /// Creates a standby session when a full-tunnel VPN is already active at startup,
    /// deferring WinINET proxy activation until `reconcile()` runs after VPN recovery.
    pub fn new_standby(addr: IpAddr, http_port: u16, vpn_coexistence: VpnCoexistence) -> Self {
        Self {
            addr: normalize_client_proxy_ip(addr),
            http_port,
            vpn_coexistence,
            saved_state: Arc::new(Mutex::new(load_saved_windows_proxy_state())),
        }
    }

    pub fn with_vpn_coexistence(mut self, mode: VpnCoexistence) -> Self {
        self.vpn_coexistence = mode;
        self
    }

    pub fn summary(&self) -> String {
        if is_running_as_service() {
            "active (Windows Service -> WinINET Fail-Open PAC AutoConfigURL)".to_string()
        } else {
            "active (Windows WinINET Fail-Open PAC AutoConfigURL)".to_string()
        }
    }

    fn snapshot_saved_state(&self) -> SavedWindowsProxyState {
        self.saved_state
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    fn record_reconciled_state(&self, updated: &SavedWindowsProxyState) -> bool {
        let mut guard = self
            .saved_state
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        guard.merge_missing_from(updated)
    }

    pub fn reconcile(&self) {
        if should_skip_reconcile_for_vpn(self.vpn_coexistence)
            && crate::platform::vpn::detect_active_vpn(None).is_full_tunnel()
        {
            debug!("full-tunnel VPN active; skipping Windows proxy reconciliation");
            return;
        }

        let expected_pac_url = build_windows_pac_url(self.addr, self.http_port);
        let roots = target_proxy_roots();
        let mut saved_state = load_saved_windows_proxy_state();
        let in_memory = self.snapshot_saved_state();
        let _ = saved_state.merge_missing_from(&in_memory);
        let _ = self.record_reconciled_state(&saved_state);
        let mut wininet_changed = false;
        let mut env_changed = false;

        for root in &roots {
            let inet_key = internet_settings_key(root);
            let current = query_current_wininet_state(&inet_key);
            let pac_aligned = current
                .auto_config_url
                .as_deref()
                .is_some_and(|u| u.trim().eq_ignore_ascii_case(&expected_pac_url));
            if !pac_aligned || current.proxy_enable {
                if saved_state.record_hive_if_absent(root, capture_wininet_state(&inet_key)) {
                    let _ = self.record_reconciled_state(&saved_state);
                    let snapshot = self.snapshot_saved_state();
                    save_windows_proxy_state(&snapshot);
                }
                if let Err(e) = apply_wininet_pac_proxy(&inet_key, &expected_pac_url) {
                    warn!(hive = %root, error = %e, "failed to reconcile Windows fail-open PAC proxy settings");
                } else {
                    wininet_changed = true;
                }
            }

            let env_key = user_env_key(root);
            if unset_windows_user_env(&env_key) {
                env_changed = true;
            }
        }

        if wininet_changed {
            notify_wininet_refresh();
        }
        if env_changed {
            broadcast_environment_change();
        }
    }

    /// Temporarily yields WinINET proxy settings for an active full-tunnel VPN while
    /// preserving `windows-proxy-state.json` on disk until final stop/uninstall.
    pub fn yield_for_vpn(&self) {
        let snapshot = self.snapshot_saved_state();
        let _ = clear_all_windows_proxies_with_fallback(Some(&snapshot), false);
        debug!("temporarily yielded Windows WinINET proxy state for VPN");
    }

    pub fn deactivate(&self) {
        let snapshot = self.snapshot_saved_state();
        let _ = clear_all_windows_proxies_with_fallback(Some(&snapshot), true);
        debug!("restored Windows WinINET proxy state");
    }
}

pub fn clear_all_windows_proxies() -> Result<()> {
    clear_all_windows_proxies_with_fallback(None, true)
}

fn clear_all_windows_proxies_with_fallback(
    fallback_saved: Option<&SavedWindowsProxyState>,
    remove_state_files: bool,
) -> Result<()> {
    let mut saved = load_saved_windows_proxy_state();
    if let Some(fb) = fallback_saved {
        saved.merge_missing_from(fb);
    }

    let mut wininet_changed = false;
    let mut env_changed = false;
    for root in all_cleanup_roots() {
        let inet_key = internet_settings_key(&root);
        let current = query_current_wininet_state(&inet_key);
        let prior = saved.state_for_root(&root);
        let plan = plan_wininet_restore(&current, prior.as_ref());
        if execute_wininet_restore_plan(&inet_key, &plan) {
            wininet_changed = true;
        }
        let env_key = user_env_key(&root);
        if unset_windows_user_env(&env_key) {
            env_changed = true;
        }
    }
    reset_winhttp_proxy_if_vdpi();
    if remove_state_files {
        remove_saved_windows_proxy_state_files();
    }
    if wininet_changed {
        notify_wininet_refresh();
    }
    if env_changed {
        broadcast_environment_change();
    }
    Ok(())
}

fn execute_wininet_restore_plan(inet_key: &str, plan: &WininetRestorePlan) -> bool {
    let mut changed = false;

    match &plan.auto_config {
        AutoConfigAction::Keep => {}
        AutoConfigAction::Delete => {
            if run_reg(&["delete", inet_key, "/v", "AutoConfigURL", "/f"]).is_ok() {
                changed = true;
            }
        }
        AutoConfigAction::Set(prev_url) => {
            if run_reg(&[
                "add",
                inet_key,
                "/v",
                "AutoConfigURL",
                "/t",
                "REG_SZ",
                "/d",
                prev_url,
                "/f",
            ])
            .is_ok()
            {
                changed = true;
            }
        }
    }

    match &plan.manual_proxy {
        ManualProxyAction::Keep => {}
        ManualProxyAction::Disable => {
            if run_reg(&[
                "add",
                inet_key,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .is_ok()
            {
                changed = true;
            }
        }
        ManualProxyAction::Restore {
            server,
            override_list,
        } => {
            let mut restored = run_reg(&[
                "add",
                inet_key,
                "/v",
                "ProxyServer",
                "/t",
                "REG_SZ",
                "/d",
                server,
                "/f",
            ])
            .is_ok();
            if let Some(ov) = override_list {
                let _ = run_reg(&[
                    "add",
                    inet_key,
                    "/v",
                    "ProxyOverride",
                    "/t",
                    "REG_SZ",
                    "/d",
                    ov,
                    "/f",
                ]);
            }
            if run_reg(&[
                "add",
                inet_key,
                "/v",
                "ProxyEnable",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .is_ok()
            {
                restored = true;
            }
            if restored {
                changed = true;
            }
        }
    }

    changed
}

fn query_winhttp_proxy_server() -> Option<String> {
    let out = Command::new(system32_exe("netsh.exe"))
        .creation_flags(CREATE_NO_WINDOW)
        .args(["winhttp", "show", "proxy"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_winhttp_proxy_server(&text)
}

fn parse_winhttp_proxy_server(text: &str) -> Option<String> {
    let mut fallback_value: Option<String> = None;
    for line in text.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        let val_trimmed = val.trim();
        if val_trimmed.is_empty() || val_trimmed.eq_ignore_ascii_case("(none)") {
            continue;
        }
        if key_lower.contains("bypass") {
            continue;
        }
        if key_lower.starts_with("proxy server") {
            return Some(val_trimmed.to_string());
        }
        if fallback_value.is_none() && !key_lower.contains("winhttp") {
            fallback_value = Some(val_trimmed.to_string());
        }
    }
    fallback_value
}

fn reset_winhttp_proxy_if_vdpi() {
    if query_winhttp_proxy_server()
        .as_deref()
        .is_some_and(is_vdpi_owned_winhttp_proxy)
    {
        let _ = Command::new(system32_exe("netsh.exe"))
            .creation_flags(CREATE_NO_WINDOW)
            .args(["winhttp", "reset", "proxy"])
            .output();
    }
}

pub fn print_windows_proxy_status() {
    let inet_key = internet_settings_key("HKCU");
    let env_key = user_env_key("HKCU");
    let current = query_current_wininet_state(&inet_key);
    let override_val = query_reg_sz(&inet_key, "ProxyOverride").unwrap_or_else(|| "<unset>".into());
    let https_env = query_reg_sz(&env_key, "HTTPS_PROXY").unwrap_or_else(|| "<unset>".into());
    let auto_config_url = current
        .auto_config_url
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("<unset>");

    println!("\n=== Windows System Proxy (WinINET) ===");
    println!("AutoConfigURL (PAC)       : {auto_config_url}");
    println!(
        "ProxyEnable               : {}",
        if current.proxy_enable {
            "ON (1)"
        } else {
            "OFF (0)"
        }
    );
    println!(
        "ProxyServer               : {}",
        if current.proxy_server.is_empty() {
            "<unset>"
        } else {
            &current.proxy_server
        }
    );
    println!("ProxyOverride             : {override_val}");
    println!("User Env HTTPS_PROXY      : {https_env}");
    println!(
        "WinHTTP Proxy             : {}",
        query_winhttp_proxy_server().unwrap_or_else(|| "direct (no proxy)".into())
    );
}

pub fn enumerate_interactive_hku_roots() -> Vec<String> {
    let Ok(out) = Command::new(system32_exe("reg.exe"))
        .creation_flags(CREATE_NO_WINDOW)
        .args(["query", "HKU"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut roots = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(sid) = trimmed
            .strip_prefix(r"HKEY_USERS\")
            .or_else(|| trimmed.strip_prefix(r"HKU\"))
        else {
            continue;
        };
        if sid.contains('\\') {
            continue;
        }
        let is_user_sid = sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-");
        let is_classes = sid.to_ascii_lowercase().ends_with("_classes");
        if is_user_sid && !is_classes {
            roots.push(format!(r"HKU\{sid}"));
        }
    }
    roots
}

fn target_proxy_roots() -> Vec<String> {
    if is_running_as_service() {
        enumerate_interactive_hku_roots()
    } else {
        vec!["HKCU".to_string()]
    }
}

fn all_cleanup_roots() -> Vec<String> {
    if is_running_as_service() {
        enumerate_interactive_hku_roots()
    } else {
        let mut roots = enumerate_interactive_hku_roots();
        if !roots.iter().any(|r| r.eq_ignore_ascii_case("HKCU")) {
            roots.push("HKCU".to_string());
        }
        roots
    }
}

fn internet_settings_key(root: &str) -> String {
    format!(r"{root}\{INTERNET_SETTINGS_SUBKEY}")
}

fn user_env_key(root: &str) -> String {
    format!(r"{root}\{USER_ENV_SUBKEY}")
}

fn apply_wininet_pac_proxy(inet_key: &str, pac_url: &str) -> Result<()> {
    run_reg(&[
        "add",
        inet_key,
        "/v",
        "AutoConfigURL",
        "/t",
        "REG_SZ",
        "/d",
        pac_url,
        "/f",
    ])?;
    // Explicitly disable manual ProxyEnable so Windows evaluates the fail-open PAC
    // (`PROXY 127.0.0.1:<port>; DIRECT`) and automatically falls back to DIRECT if vdpi exits.
    run_reg(&[
        "add",
        inet_key,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f",
    ])?;
    Ok(())
}

fn is_loopback_host_str(host: &str) -> bool {
    let trimmed = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn is_loopback_authority_str(authority: &str) -> bool {
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
        return host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
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
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

fn is_vdpi_owned_proxy_env(val: &str) -> bool {
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
        .map_or(authority, |(_, auth)| auth)
        .trim();
    if authority.is_empty() {
        return false;
    }
    let first_token = authority
        .split([' ', '\t'])
        .next()
        .unwrap_or("")
        .trim();
    is_loopback_authority_str(first_token) || is_loopback_host_str(first_token)
}

fn unset_windows_user_env(env_key: &str) -> bool {
    let mut owned = false;
    for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
        if query_reg_sz(env_key, key)
            .as_deref()
            .is_some_and(is_vdpi_owned_proxy_env)
        {
            owned = true;
            let _ = run_reg(&["delete", env_key, "/v", key, "/f"]);
        }
    }
    if owned {
        let _ = run_reg(&["delete", env_key, "/v", "NO_PROXY", "/f"]);
    }
    if query_reg_sz(env_key, "ALL_PROXY")
        .as_deref()
        .is_some_and(is_vdpi_owned_proxy_env)
    {
        owned = true;
        let _ = run_reg(&["delete", env_key, "/v", "ALL_PROXY", "/f"]);
    }
    owned
}

fn query_current_wininet_state(inet_key: &str) -> CurrentWininetState {
    let enabled_raw = query_reg_sz(inet_key, "ProxyEnable").unwrap_or_default();
    let proxy_enable = enabled_raw == "0x1" || enabled_raw == "1";
    let proxy_server = query_reg_sz(inet_key, "ProxyServer").unwrap_or_default();
    let auto_config_url = query_reg_sz(inet_key, "AutoConfigURL");
    CurrentWininetState {
        proxy_enable,
        proxy_server,
        auto_config_url,
    }
}

fn capture_wininet_state(inet_key: &str) -> SavedWininetHiveState {
    let current = query_current_wininet_state(inet_key);
    let proxy_override = query_reg_sz(inet_key, "ProxyOverride");
    SavedWininetHiveState {
        proxy_enable: current.proxy_enable,
        proxy_server: (!current.proxy_server.trim().is_empty()).then_some(current.proxy_server),
        proxy_override,
        auto_config_url: current.auto_config_url,
    }
}

pub fn query_reg_sz(key: &str, value_name: &str) -> Option<String> {
    let out = Command::new(system32_exe("reg.exe"))
        .creation_flags(CREATE_NO_WINDOW)
        .args(["query", key, "/v", value_name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() >= 3 && tokens[0].eq_ignore_ascii_case(value_name) {
            let after_name = &trimmed[tokens[0].len()..];
            let idx = after_name.find(tokens[1])? + tokens[1].len();
            let val = after_name[idx..].trim();
            return Some(val.to_string());
        }
    }
    None
}

pub fn run_reg(args: &[&str]) -> Result<String> {
    let out = Command::new(system32_exe("reg.exe"))
        .creation_flags(CREATE_NO_WINDOW)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute reg.exe {args:?}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "reg.exe {:?} exited {}: {}",
            args,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn notify_wininet_refresh() {
    unsafe {
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            std::ptr::null_mut(),
            0,
        );
        let _ = InternetSetOptionW(
            std::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            std::ptr::null_mut(),
            0,
        );
    }
}

pub fn broadcast_environment_change() {
    let wide: Vec<u16> = "Environment\0".encode_utf16().collect();
    let mut result: usize = 0;
    unsafe {
        let _ = SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            wide.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            500,
            &mut result,
        );
    }
}

/// Adds `dir` to the Windows System `Path` (`REG_EXPAND_SZ`) and removes any legacy directory
/// from the current user's `Path` so `vdpi` resolves cleanly from any terminal.
pub fn add_dir_to_windows_system_path(dir: &Path, legacy_dir: Option<&Path>) -> Result<bool> {
    let target = dir.display().to_string();
    let target_norm = target.trim_end_matches('\\');

    let current = query_reg_sz(SYSTEM_ENV_KEY, "Path").unwrap_or_default();
    let mut parts: Vec<String> = current
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    let already_present = parts
        .iter()
        .any(|p| p.trim_end_matches('\\').eq_ignore_ascii_case(target_norm));

    let mut changed = false;
    if !already_present {
        parts.push(target_norm.to_string());
        let new_path = parts.join(";");
        run_reg(&[
            "add",
            SYSTEM_ENV_KEY,
            "/v",
            "Path",
            "/t",
            "REG_EXPAND_SZ",
            "/d",
            &new_path,
            "/f",
        ])?;
        changed = true;
    }

    if let Some(legacy) = legacy_dir {
        if remove_from_env_path_key(&user_env_key("HKCU"), &[legacy]) {
            changed = true;
        }
    }

    if changed {
        broadcast_environment_change();
    }
    Ok(!already_present)
}

/// Removes `dir` (and optional `legacy_dir`) from System `Path` and interactive User `Path` entries.
pub fn remove_dir_from_windows_path(dir: &Path, legacy_dir: Option<&Path>) {
    let mut targets = vec![dir];
    if let Some(legacy) = legacy_dir {
        targets.push(legacy);
    }

    let mut changed = remove_from_env_path_key(SYSTEM_ENV_KEY, &targets);
    for root in all_cleanup_roots() {
        if remove_from_env_path_key(&user_env_key(&root), &targets) {
            changed = true;
        }
    }

    if changed {
        broadcast_environment_change();
    }
}

fn remove_from_env_path_key(env_key: &str, dirs: &[&Path]) -> bool {
    let Some(current) = query_reg_sz(env_key, "Path") else {
        return false;
    };

    let targets: Vec<String> = dirs
        .iter()
        .map(|d| d.display().to_string().trim_end_matches('\\').to_string())
        .collect();

    let parts: Vec<&str> = current
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();

    let filtered: Vec<&str> = parts
        .iter()
        .copied()
        .filter(|p| {
            let norm = p.trim_end_matches('\\');
            !targets.iter().any(|t| norm.eq_ignore_ascii_case(t))
        })
        .collect();

    if filtered.len() == parts.len() {
        return false;
    }

    let new_path = filtered.join(";");
    let reg_type = if env_key == SYSTEM_ENV_KEY || new_path.contains('%') {
        "REG_EXPAND_SZ"
    } else {
        "REG_SZ"
    };

    run_reg(&[
        "add", env_key, "/v", "Path", "/t", reg_type, "/d", &new_path, "/f",
    ])
    .is_ok()
}

pub fn build_windows_proxy_override(extra: &[String]) -> String {
    let mut entries: Vec<String> = vec![
        "localhost".into(),
        "*.localhost".into(),
        "127.0.0.1".into(),
        "127.*".into(),
        "[::1]".into(),
        "::1".into(),
        "0.0.0.0".into(),
        "10.*".into(),
    ];
    for octet in 16..=31 {
        entries.push(format!("172.{octet}.*"));
    }
    entries.push("192.168.*".into());
    entries.push("169.254.*".into());
    for octet in 64..=127 {
        entries.push(format!("100.{octet}.*"));
    }
    entries.extend(
        [
            "*.local",
            "*.lan",
            "*.internal",
            "*.home.arpa",
            "*.ts.net",
            "*.gov.tr",
            "*.bel.tr",
            "*.org.tr",
            "*.osym.gov.tr",
            "*.bkm.com.tr",
            "paratika.com.tr",
            "*.halkbank.com.tr",
            "*.isbank.com.tr",
            "*.akbank.com",
            "*.akbank.com.tr",
            "*.garantibbva.com.tr",
            "*.ziraatbank.com.tr",
            "*.yapikredi.com.tr",
            "*.vakifbank.com.tr",
            "*.turktelekom.com.tr",
            "*.pttavm.com",
        ]
        .into_iter()
        .map(String::from),
    );
    for item in extra {
        let clean = item.trim();
        if !clean.is_empty() && !entries.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            entries.push(clean.to_string());
        }
    }
    entries.push("<local>".into());
    entries.join(";")
}

const STALE_BROWSER_EXES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "opera.exe",
    "vivaldi.exe",
];

const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;
const FILETIME_TICKS_PER_SEC: u64 = 10_000_000;

struct HandleGuard(HANDLE);

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn canonical_stale_browser_name(exe_name: &str) -> Option<&'static str> {
    STALE_BROWSER_EXES
        .iter()
        .copied()
        .find(|candidate| exe_name.eq_ignore_ascii_case(candidate))
}

fn filetime_to_unix_secs(ft: FILETIME) -> Option<u64> {
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    (ticks / FILETIME_TICKS_PER_SEC).checked_sub(WINDOWS_TO_UNIX_EPOCH_SECS)
}

/// Detects allowlisted desktop browser processes started before `since_unix_secs`
/// so proxy-mode users can be advised to restart browsers that cached pre-proxy settings.
///
/// Uses only `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` +
/// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetProcessTimes`, and NEVER opens
/// handles to games, anti-cheat drivers, or any non-browser process.
pub fn detect_stale_browsers(since_unix_secs: u64) -> Vec<String> {
    let raw_snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw_snapshot.is_null() || raw_snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let _snapshot = HandleGuard(raw_snapshot);

    // SAFETY: `PROCESSENTRY32W` is a plain C struct; `dwSize` is initialized before FFI use.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(raw_snapshot, &mut entry) } == 0 {
        return Vec::new();
    }

    let mut stale: Vec<&'static str> = Vec::new();
    loop {
        let exe_len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let exe_name = String::from_utf16_lossy(&entry.szExeFile[..exe_len]);

        if let Some(browser) =
            canonical_stale_browser_name(&exe_name).filter(|b| !stale.contains(b))
        {
            let proc_handle =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID) };
            if !proc_handle.is_null() && proc_handle != INVALID_HANDLE_VALUE {
                let _proc_guard = HandleGuard(proc_handle);
                let mut creation = FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                };
                let mut exit = FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                };
                let mut kernel = FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                };
                let mut user = FILETIME {
                    dwLowDateTime: 0,
                    dwHighDateTime: 0,
                };
                let ok = unsafe {
                    GetProcessTimes(
                        proc_handle,
                        &mut creation,
                        &mut exit,
                        &mut kernel,
                        &mut user,
                    )
                };
                if ok != 0
                    && filetime_to_unix_secs(creation)
                        .is_some_and(|created| created < since_unix_secs)
                {
                    stale.push(browser);
                    if stale.len() == STALE_BROWSER_EXES.len() {
                        break;
                    }
                }
            }
        }

        if unsafe { Process32NextW(raw_snapshot, &mut entry) } == 0 {
            break;
        }
    }

    stale.sort_unstable();
    stale.into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_env_ownership_matches_only_vdpi_loopback_urls() {
        assert!(is_vdpi_owned_proxy_env("http://127.0.0.1:8080"));
        assert!(is_vdpi_owned_proxy_env("HTTP://127.0.0.1:18080"));
        assert!(is_vdpi_owned_proxy_env(" http://[::1]:8080 "));
        assert!(is_vdpi_owned_proxy_env("socks5://127.0.0.1:1080"));
        assert!(is_vdpi_owned_proxy_env("socks5h://127.0.0.1:1080"));
        assert!(is_vdpi_owned_proxy_env("socks5://[::1]:1080"));
        assert!(is_vdpi_owned_proxy_env("socks5h://[::1]:1080/"));
        assert!(is_vdpi_owned_proxy_env("http://localhost:8080"));
        assert!(is_vdpi_owned_proxy_env("socks5://localhost:1080"));
        assert!(is_vdpi_owned_proxy_env("SOCKS5H://LOCALHOST:1080"));
        assert!(is_vdpi_owned_proxy_env("127.0.0.1:8080"));
        assert!(is_vdpi_owned_proxy_env("[::1]:8080"));
        assert!(is_vdpi_owned_proxy_env("localhost:8080"));
        assert!(!is_vdpi_owned_proxy_env("http://proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_proxy_env("socks5://proxy.corp.local:1080"));
        assert!(!is_vdpi_owned_proxy_env("socks5h://10.0.0.1:1080"));
        assert!(!is_vdpi_owned_proxy_env("http://localhost.corp.local:8080"));
        assert!(!is_vdpi_owned_proxy_env(""));
    }

    #[test]
    fn wininet_server_ownership_matches_only_vdpi_loopback() {
        assert!(is_vdpi_owned_wininet_server("127.0.0.1:8080"));
        assert!(is_vdpi_owned_wininet_server(" 127.0.0.1:18080 "));
        assert!(is_vdpi_owned_wininet_server("[::1]:8080"));
        assert!(is_vdpi_owned_wininet_server(" [::1]:18080 "));
        assert!(is_vdpi_owned_wininet_server("localhost:8080"));
        assert!(is_vdpi_owned_wininet_server(" LOCALHOST:8080 "));
        assert!(is_vdpi_owned_wininet_server("LocalHost:18080"));
        assert!(is_vdpi_owned_wininet_server("http=localhost:8080"));
        assert!(is_vdpi_owned_wininet_server("https=localhost:8080"));
        assert!(is_vdpi_owned_wininet_server(
            "HTTP=LOCALHOST:8080;HTTPS=LOCALHOST:8080"
        ));
        assert!(is_vdpi_owned_wininet_server(
            "http=127.0.0.1:8080;https=127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_wininet_server(
            "http=[::1]:8080;https=[::1]:8080"
        ));
        assert!(!is_vdpi_owned_wininet_server("proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_wininet_server("localhost.corp.local:8080"));
        assert!(!is_vdpi_owned_wininet_server(
            "http=localhost.corp.local:8080"
        ));
        assert!(!is_vdpi_owned_wininet_server(
            "http=proxy.corp.local:3128;https=localhost:8080"
        ));
        assert!(!is_vdpi_owned_wininet_server("localhost:"));
        assert!(!is_vdpi_owned_wininet_server("::1:8080"));
        assert!(!is_vdpi_owned_wininet_server("http://127.0.0.1:8080"));
        assert!(!is_vdpi_owned_wininet_server("http://localhost:8080"));
        assert!(!is_vdpi_owned_wininet_server(""));
    }

    #[test]
    fn winhttp_proxy_ownership_matches_loopback_and_scheme_prefixed_entries() {
        assert!(is_vdpi_owned_winhttp_proxy("127.0.0.1:8080"));
        assert!(is_vdpi_owned_winhttp_proxy(" 127.0.0.1:18080 "));
        assert!(is_vdpi_owned_winhttp_proxy("[::1]:8080"));
        assert!(is_vdpi_owned_winhttp_proxy("localhost:8080"));
        assert!(is_vdpi_owned_winhttp_proxy("http://127.0.0.1:8080"));
        assert!(is_vdpi_owned_winhttp_proxy(
            "http=127.0.0.1:8080;https=127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_winhttp_proxy("http=localhost:8080"));
        assert!(is_vdpi_owned_winhttp_proxy("http=[::1]:8080"));
        assert!(is_vdpi_owned_winhttp_proxy(
            "http=10.0.0.1:8080;https=127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_winhttp_proxy(
            "http=10.0.0.1:8080 https=127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_winhttp_proxy("socks=127.0.0.1:1080"));
        assert!(!is_vdpi_owned_winhttp_proxy("proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_winhttp_proxy(
            "http=10.0.0.1:8080;https=10.0.0.2:8443"
        ));
        assert!(!is_vdpi_owned_winhttp_proxy(
            "http=10.0.0.1:8080 https=10.0.0.2:8443"
        ));
        assert!(!is_vdpi_owned_winhttp_proxy("http=localhost.corp.local:8080"));
        assert!(!is_vdpi_owned_winhttp_proxy("::1:8080"));
        assert!(!is_vdpi_owned_winhttp_proxy(""));
    }

    #[test]
    fn normalizes_unspecified_and_ipv6_client_proxy_endpoints() {
        assert_eq!(
            SocketAddr::new(
                normalize_client_proxy_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                8080
            )
            .to_string(),
            "127.0.0.1:8080"
        );
        assert_eq!(
            SocketAddr::new(
                normalize_client_proxy_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
                8080
            )
            .to_string(),
            "[::1]:8080"
        );
        assert_eq!(
            SocketAddr::new(
                normalize_client_proxy_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                18080
            )
            .to_string(),
            "[::1]:18080"
        );
    }

    #[test]
    fn parses_winhttp_proxy_server_without_clobbering_external_proxies() {
        let direct =
            "Current WinHTTP proxy settings:\r\n\r\n    Direct access (no proxy server).\r\n";
        assert_eq!(parse_winhttp_proxy_server(direct), None);

        let vdpi = "Current WinHTTP proxy settings:\r\n\r\n    Proxy Server(s) :  127.0.0.1:8080\r\n    Bypass List     :  localhost;127.0.0.1;<local>\r\n";
        assert_eq!(
            parse_winhttp_proxy_server(vdpi).as_deref(),
            Some("127.0.0.1:8080")
        );

        let host_only = "Current WinHTTP proxy settings:\r\n\r\n    Proxy Server(s) :  proxy.corp.local\r\n    Bypass List     :  (none)\r\n";
        assert_eq!(
            parse_winhttp_proxy_server(host_only).as_deref(),
            Some("proxy.corp.local")
        );

        let multi = "Current WinHTTP proxy settings:\r\n\r\n    Proxy Server(s) :  http=10.0.0.1:8080 https=10.0.0.2:8443\r\n    Bypass List     :  *.corp.local;127.0.0.1:8080\r\n";
        assert_eq!(
            parse_winhttp_proxy_server(multi).as_deref(),
            Some("http=10.0.0.1:8080 https=10.0.0.2:8443")
        );

        let bypass_only = "Current WinHTTP proxy settings:\r\n\r\n    Proxy Server(s) :  (none)\r\n    Bypass List     :  127.0.0.1:8080\r\n";
        assert_eq!(parse_winhttp_proxy_server(bypass_only), None);
    }

    #[test]
    fn browser_allowlist_matches_only_known_browsers() {
        for exe in [
            "chrome.exe",
            "CHROME.EXE",
            "msedge.exe",
            "brave.exe",
            "firefox.exe",
            "opera.exe",
            "vivaldi.exe",
        ] {
            assert!(canonical_stale_browser_name(exe).is_some());
        }
        for non_browser in [
            "VALORANT-Win64-Shipping.exe",
            "vgc.exe",
            "EasyAntiCheat.exe",
            "explorer.exe",
            "vdpi.exe",
        ] {
            assert_eq!(canonical_stale_browser_name(non_browser), None);
        }
    }

    #[test]
    fn converts_windows_filetime_to_unix_seconds() {
        let unix_epoch_ticks = WINDOWS_TO_UNIX_EPOCH_SECS * FILETIME_TICKS_PER_SEC;
        let epoch_ft = FILETIME {
            dwLowDateTime: unix_epoch_ticks as u32,
            dwHighDateTime: (unix_epoch_ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_secs(epoch_ft), Some(0));

        let pre_epoch = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        assert_eq!(filetime_to_unix_secs(pre_epoch), None);

        let sample_unix = 1_767_225_600u64; // 2026-01-01T00:00:00Z
        let sample_ticks = (sample_unix + WINDOWS_TO_UNIX_EPOCH_SECS) * FILETIME_TICKS_PER_SEC;
        let sample_ft = FILETIME {
            dwLowDateTime: sample_ticks as u32,
            dwHighDateTime: (sample_ticks >> 32) as u32,
        };
        assert_eq!(filetime_to_unix_secs(sample_ft), Some(sample_unix));
    }

    #[test]
    fn detect_stale_browsers_returns_empty_for_zero_epoch_threshold() {
        assert!(detect_stale_browsers(0).is_empty());
    }

    #[test]
    fn builds_fail_open_pac_urls_for_ipv4_ipv6_and_unspecified() {
        assert_eq!(
            build_windows_pac_url(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            "http://127.0.0.1:8080/vdpi.pac"
        );
        assert_eq!(
            build_windows_pac_url(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 18080),
            "http://127.0.0.1:18080/vdpi.pac"
        );
        assert_eq!(
            build_windows_pac_url(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 8080),
            "http://[::1]:8080/vdpi.pac"
        );
        assert_eq!(
            build_windows_pac_url(IpAddr::V6(Ipv6Addr::LOCALHOST), 9090),
            "http://[::1]:9090/vdpi.pac"
        );
        assert_eq!(
            build_windows_pac_url(IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()), 8080),
            "http://127.0.0.1:8080/vdpi.pac"
        );
    }

    #[test]
    fn pac_url_ownership_matches_only_vdpi_pac_endpoints() {
        assert!(is_vdpi_owned_pac_url("http://127.0.0.1:8080/vdpi.pac"));
        assert!(is_vdpi_owned_pac_url("HTTP://127.0.0.1:18080/VDPI.PAC"));
        assert!(is_vdpi_owned_pac_url(" http://[::1]:8080/vdpi.pac "));
        assert!(is_vdpi_owned_pac_url("http://127.0.0.1:8080/vdpi.pac?v=1"));
        assert!(is_vdpi_owned_pac_url("http://192.168.1.5:8080/vdpi.pac"));
        assert!(!is_vdpi_owned_pac_url("http://pac.corp.local/proxy.pac"));
        assert!(!is_vdpi_owned_pac_url("http://127.0.0.1:8080/other.pac"));
        assert!(!is_vdpi_owned_pac_url("https://127.0.0.1:8080/vdpi.pac"));
        assert!(!is_vdpi_owned_pac_url("http://127.0.0.1/vdpi.pac"));
        assert!(!is_vdpi_owned_pac_url(""));
    }

    #[test]
    fn saved_proxy_state_deserializes_legacy_json_without_auto_config_url() {
        let legacy_json = r#"{
            "proxy_enable": true,
            "proxy_server": "corp.proxy.local:3128",
            "proxy_override": "localhost;<local>"
        }"#;
        let parsed: SavedWindowsProxyState =
            serde_json::from_str(legacy_json).expect("legacy state JSON must deserialize");
        assert!(parsed.proxy_enable);
        assert_eq!(
            parsed.proxy_server.as_deref(),
            Some("corp.proxy.local:3128")
        );
        assert_eq!(parsed.proxy_override.as_deref(), Some("localhost;<local>"));
        assert_eq!(parsed.auto_config_url, None);
        assert!(parsed.hives.is_empty());

        let hkcu = parsed
            .state_for_root("HKCU")
            .expect("legacy flat state should map to HKCU");
        assert!(hkcu.proxy_enable);
        assert_eq!(hkcu.proxy_server.as_deref(), Some("corp.proxy.local:3128"));
        assert_eq!(hkcu.auto_config_url, None);

        // Empty JSON object should also deserialize cleanly via #[serde(default)].
        let empty: SavedWindowsProxyState =
            serde_json::from_str("{}").expect("empty JSON must deserialize");
        assert_eq!(empty, SavedWindowsProxyState::default());
        assert_eq!(empty.state_for_root("HKCU"), None);
    }

    #[test]
    fn saved_proxy_state_round_trips_auto_config_url_and_sanitizes_vdpi_entries() {
        let mut saved = SavedWindowsProxyState::default();
        saved.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: Some("127.0.0.1:8080".into()),
                proxy_override: Some("localhost;<local>".into()),
                auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            },
        );
        // Second capture for the same root must not overwrite the original snapshot.
        saved.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
        );
        // A hive that only had stale vdpi values sanitizes to empty prior state.
        saved.record_hive_if_absent(
            r"HKU\S-1-5-21-999",
            SavedWininetHiveState {
                proxy_enable: true,
                proxy_server: Some("127.0.0.1:8080".into()),
                proxy_override: Some("<local>".into()),
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
        );

        let json = serde_json::to_string(&saved).expect("serialize saved state");
        let round_trip: SavedWindowsProxyState =
            serde_json::from_str(&json).expect("deserialize saved state");
        assert_eq!(round_trip, saved);

        let hkcu = round_trip.state_for_root("hkcu").expect("HKCU present");
        assert!(!hkcu.proxy_enable);
        assert_eq!(hkcu.proxy_server, None);
        assert_eq!(
            hkcu.auto_config_url.as_deref(),
            Some("http://pac.corp.local/proxy.pac")
        );

        let sid = round_trip
            .state_for_root(r"HKU\S-1-5-21-999")
            .expect("SID present");
        assert_eq!(sid, SavedWininetHiveState::default());
    }

    #[test]
    fn restore_plan_cleans_stale_pac_and_legacy_manual_proxy_or_restores_prior() {
        // 1. No prior state: deletes vdpi AutoConfigURL and disables legacy vdpi ProxyEnable=1.
        let plan = plan_wininet_restore(
            &CurrentWininetState {
                proxy_enable: true,
                proxy_server: "127.0.0.1:8080".into(),
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
            None,
        );
        assert_eq!(plan.auto_config, AutoConfigAction::Delete);
        assert_eq!(plan.manual_proxy, ManualProxyAction::Disable);

        // 2. Prior corporate PAC exists: restores corporate PAC instead of deleting.
        let prior_pac = SavedWininetHiveState {
            proxy_enable: false,
            proxy_server: None,
            proxy_override: None,
            auto_config_url: Some("http://pac.corp.local/wpad.dat".into()),
        };
        let plan = plan_wininet_restore(
            &CurrentWininetState {
                proxy_enable: false,
                proxy_server: String::new(),
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
            Some(&prior_pac),
        );
        assert_eq!(
            plan.auto_config,
            AutoConfigAction::Set("http://pac.corp.local/wpad.dat".into())
        );
        assert_eq!(plan.manual_proxy, ManualProxyAction::Keep);

        // 3. Prior state erroneously contains a vdpi PAC URL: always deletes AutoConfigURL.
        let poisoned_prior = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("127.0.0.1:8080".into()),
            proxy_override: None,
            auto_config_url: Some("http://127.0.0.1:18080/vdpi.pac".into()),
        };
        let plan = plan_wininet_restore(
            &CurrentWininetState {
                proxy_enable: true,
                proxy_server: "[::1]:8080".into(),
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
            Some(&poisoned_prior),
        );
        assert_eq!(plan.auto_config, AutoConfigAction::Delete);
        assert_eq!(plan.manual_proxy, ManualProxyAction::Disable);

        // 4. Prior corporate manual proxy exists: deletes vdpi PAC and restores corporate manual proxy.
        let prior_manual = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("proxy.corp.local:3128".into()),
            proxy_override: Some("*.corp.local;<local>".into()),
            auto_config_url: None,
        };
        let plan = plan_wininet_restore(
            &CurrentWininetState {
                proxy_enable: false,
                proxy_server: String::new(),
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
            Some(&prior_manual),
        );
        assert_eq!(plan.auto_config, AutoConfigAction::Delete);
        assert_eq!(
            plan.manual_proxy,
            ManualProxyAction::Restore {
                server: "proxy.corp.local:3128".into(),
                override_list: Some("*.corp.local;<local>".into()),
            }
        );

        // 5. Unrelated external proxy & PAC are never clobbered.
        let plan = plan_wininet_restore(
            &CurrentWininetState {
                proxy_enable: true,
                proxy_server: "proxy.corp.local:3128".into(),
                auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            },
            None,
        );
        assert_eq!(plan.auto_config, AutoConfigAction::Keep);
        assert_eq!(plan.manual_proxy, ManualProxyAction::Keep);
    }

    #[test]
    fn windows_proxy_override_covers_private_cgnat_loopback_and_local_domains() {
        let raw = build_windows_proxy_override(&[
            "custom.example.com".to_string(),
            "LOCALHOST".to_string(),
        ]);
        let parts: Vec<&str> = raw.split(';').collect();
        for required in [
            "localhost",
            "*.localhost",
            "127.0.0.1",
            "127.*",
            "[::1]",
            "::1",
            "0.0.0.0",
            "10.*",
            "172.16.*",
            "172.24.*",
            "172.31.*",
            "192.168.*",
            "169.254.*",
            "100.64.*",
            "100.100.*",
            "100.127.*",
            "*.local",
            "*.lan",
            "*.internal",
            "*.home.arpa",
            "*.ts.net",
            "custom.example.com",
            "<local>",
        ] {
            assert!(parts.contains(&required), "missing override entry: {required}");
        }
        assert_eq!(
            parts
                .iter()
                .filter(|p| p.eq_ignore_ascii_case("localhost"))
                .count(),
            1
        );
    }

    #[test]
    fn system32_exes_and_vpn_reconcile_policy_behave_as_expected() {
        let reg = system32_exe("reg.exe");
        let netsh = system32_exe("netsh.exe");
        assert!(reg.is_absolute());
        assert!(netsh.is_absolute());
        assert_eq!(
            reg.file_name().and_then(|s| s.to_str()),
            Some("reg.exe")
        );
        assert_eq!(
            netsh.file_name().and_then(|s| s.to_str()),
            Some("netsh.exe")
        );

        assert!(should_skip_reconcile_for_vpn(VpnCoexistence::AutoYield));
        assert!(!should_skip_reconcile_for_vpn(VpnCoexistence::Warn));
        assert!(!should_skip_reconcile_for_vpn(VpnCoexistence::Off));
    }

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);
            let pid = std::process::id();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("vdpi-win-test-{label}-{pid}-{nanos}-{seq}"));
            fs::create_dir_all(&path).expect("create test temp dir");
            Self(path)
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_state_save_writes_overwrites_and_leaves_no_temp_files() {
        let root = TestTempDir::new("atomic-save");
        let state_dir = root.0.join("vdpi");
        let state_path = state_dir.join(WINDOWS_PROXY_STATE_FILENAME);

        let mut first = SavedWindowsProxyState::default();
        assert!(first.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            },
        ));
        save_windows_proxy_state_to_path(&state_path, &first, false)
            .expect("initial atomic state save must succeed");
        assert_eq!(read_windows_proxy_state_from_path(&state_path), Some(first.clone()));

        let mut second = first;
        assert!(second.record_hive_if_absent(
            r"HKU\S-1-5-21-1001",
            SavedWininetHiveState {
                proxy_enable: true,
                proxy_server: Some("proxy.corp.local:3128".into()),
                proxy_override: Some("localhost;<local>".into()),
                auto_config_url: None,
            },
        ));
        save_windows_proxy_state_to_path(&state_path, &second, false)
            .expect("atomic overwrite via MoveFileExW must succeed");
        assert_eq!(read_windows_proxy_state_from_path(&state_path), Some(second));

        let mut entries: Vec<String> = fs::read_dir(&state_dir)
            .expect("read state dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(entries, vec![WINDOWS_PROXY_STATE_FILENAME.to_string()]);

        assert!(remove_windows_proxy_state_at_path(&state_path));
        assert!(!state_path.exists());
        assert!(!remove_windows_proxy_state_at_path(&state_path));
    }

    #[test]
    fn reparse_point_detection_rejects_junctions_symlinks_and_directories() {
        assert!(is_reparse_point_attrs(FILE_ATTRIBUTE_REPARSE_POINT));
        assert!(is_reparse_point_attrs(
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(!is_reparse_point_attrs(FILE_ATTRIBUTE_DIRECTORY));
        assert!(!is_reparse_point_attrs(INVALID_FILE_ATTRIBUTES));

        let root = TestTempDir::new("reparse");
        let target_dir = root.0.join("target");
        fs::create_dir_all(&target_dir).expect("create target dir");
        let target_state = target_dir.join(WINDOWS_PROXY_STATE_FILENAME);

        let mut sentinel = SavedWindowsProxyState::default();
        sentinel.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://pac.corp.local/sentinel.pac".into()),
            },
        );
        save_windows_proxy_state_to_path(&target_state, &sentinel, false)
            .expect("save sentinel state");

        let mut attacker = SavedWindowsProxyState::default();
        attacker.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: true,
                proxy_server: Some("evil.proxy.invalid:8080".into()),
                proxy_override: None,
                auto_config_url: None,
            },
        );

        let junction_dir = root.0.join("vdpi-junction");
        let status = Command::new(system32_exe("cmd.exe"))
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                OsStr::new("/C"),
                OsStr::new("mklink"),
                OsStr::new("/J"),
                junction_dir.as_os_str(),
                target_dir.as_os_str(),
            ])
            .status()
            .expect("spawn cmd.exe mklink /J");
        assert!(
            status.success(),
            "mklink /J must create NTFS directory junction"
        );

        let junction_state = junction_dir.join(WINDOWS_PROXY_STATE_FILENAME);
        assert!(reject_reparse_point(&junction_dir).is_err());
        assert_eq!(read_windows_proxy_state_from_path(&junction_state), None);
        assert!(save_windows_proxy_state_to_path(&junction_state, &attacker, false).is_err());
        assert!(apply_hardened_dir_dacl(&junction_dir).is_err());
        assert!(!remove_windows_proxy_state_at_path(&junction_state));
        assert_eq!(
            read_windows_proxy_state_from_path(&target_state),
            Some(sentinel.clone())
        );

        let dir_as_file = root.0.join("dir-as-state");
        fs::create_dir_all(&dir_as_file).expect("create dir-as-state");
        assert!(reject_reparse_point_or_dir(&dir_as_file).is_err());
        assert!(save_windows_proxy_state_to_path(&dir_as_file, &attacker, false).is_err());
        assert_eq!(read_windows_proxy_state_from_path(&dir_as_file), None);

        let symlink_dir = root.0.join("symlink-parent");
        fs::create_dir_all(&symlink_dir).expect("create symlink parent");
        let symlink_state = symlink_dir.join(WINDOWS_PROXY_STATE_FILENAME);
        if std::os::windows::fs::symlink_file(&target_state, &symlink_state).is_ok() {
            assert!(reject_reparse_point(&symlink_state).is_err());
            assert_eq!(read_windows_proxy_state_from_path(&symlink_state), None);
            assert!(save_windows_proxy_state_to_path(&symlink_state, &attacker, false).is_err());
            assert!(!remove_windows_proxy_state_at_path(&symlink_state));
            assert_eq!(
                read_windows_proxy_state_from_path(&target_state),
                Some(sentinel)
            );
        }

        let _ = fs::remove_dir(&junction_dir);
    }

    #[test]
    fn hardened_programdata_sddl_parses_to_valid_protected_dacl() {
        assert!(PROGRAMDATA_DIR_SDDL.starts_with("D:P"));
        assert!(PROGRAMDATA_DIR_SDDL.contains("(A;OICI;FA;;;SY)"));
        assert!(PROGRAMDATA_DIR_SDDL.contains("(A;OICI;FA;;;BA)"));
        assert!(PROGRAMDATA_DIR_SDDL.contains("(A;OICI;FRFX;;;BU)"));

        let parsed = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_SDDL)
            .expect("PROGRAMDATA_DIR_SDDL must parse via advapi32");
        assert!(!parsed.as_sd_ptr().is_null());
        assert!(!parsed.as_dacl_ptr().is_null());
    }

    #[test]
    fn reconcile_updates_shared_in_memory_saved_state_across_session_clones() {
        let session = WindowsProxySession {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: 8080,
            vpn_coexistence: VpnCoexistence::AutoYield,
            saved_state: Arc::new(Mutex::new(SavedWindowsProxyState::default())),
        };
        let watchdog = session.clone();

        let mut newly_logged_in = SavedWindowsProxyState::default();
        assert!(newly_logged_in.record_hive_if_absent(
            r"HKU\S-1-5-21-555",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://pac.corp.local/user.pac".into()),
            },
        ));
        assert!(watchdog.record_reconciled_state(&newly_logged_in));

        let restored_snapshot = session.snapshot_saved_state();
        let captured = restored_snapshot
            .state_for_root(r"HKU\S-1-5-21-555")
            .expect("original session handle must observe hives captured during reconcile");
        assert_eq!(
            captured.auto_config_url.as_deref(),
            Some("http://pac.corp.local/user.pac")
        );

        let mut vdpi_overwrite = SavedWindowsProxyState::default();
        let _ = vdpi_overwrite.record_hive_if_absent(
            r"HKU\S-1-5-21-555",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            },
        );
        assert!(!watchdog.record_reconciled_state(&vdpi_overwrite));
        assert_eq!(
            session
                .snapshot_saved_state()
                .state_for_root(r"HKU\S-1-5-21-555")
                .and_then(|s| s.auto_config_url),
            Some("http://pac.corp.local/user.pac".into())
        );
    }
}
