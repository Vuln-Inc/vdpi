use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(test)]
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};
use vdpi_core::config::VpnCoexistence;
use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, FILETIME, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

pub mod foreground;

pub const VDPI_PAC_PATH: &str = "/vdpi.pac";
pub const WINDOWS_PROXY_STATE_FILENAME: &str = "windows-proxy-state.json";

#[cfg(test)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INTERNET_SETTINGS_SUBKEY: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const USER_ENV_SUBKEY: &str = "Environment";
const SYSTEM_ENV_SUBKEY: &str = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const SYSTEM_ENV_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const WINHTTP_CONNECTIONS_SUBKEY: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const WINHTTP_CONNECTIONS_WOW64_SUBKEY: &str =
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

const WININET_BLOB_VERSION_V60: u32 = 0x3C;
const WININET_BLOB_VERSION_V70: u32 = 0x46;
const WININET_FLAG_DIRECT: u32 = 0x01;
const WININET_FLAG_PROXY: u32 = 0x02;
const WININET_FLAG_AUTO_PROXY_URL: u32 = 0x04;
const WININET_CONNECTION_BLOB_VALUES: [&str; 2] =
    ["DefaultConnectionSettings", "SavedLegacySettings"];

const WINHTTP_ACCESS_TYPE_NO_PROXY: u32 = 1;
const WINHTTP_ACCESS_TYPE_NAMED_PROXY: u32 = 3;

const PROXY_ENV_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
const NO_PROXY_ENV_VARS: [&str; 2] = ["NO_PROXY", "no_proxy"];
const ALL_RESET_ENV_VARS: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];

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
    fn GlobalFree(h_mem: *mut c_void) -> *mut c_void;
}

#[cfg(test)]
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
}

#[repr(C)]
struct WinHttpProxyInfo {
    dw_access_type: u32,
    lpsz_proxy: *mut u16,
    lpsz_proxy_bypass: *mut u16,
}

struct WinHttpProxyInfoGuard(WinHttpProxyInfo);

impl Drop for WinHttpProxyInfoGuard {
    fn drop(&mut self) {
        // SAFETY: `lpsz_proxy` and `lpsz_proxy_bypass` were allocated by
        // `WinHttpGetDefaultProxyConfiguration` and must be freed via `GlobalFree`.
        unsafe {
            if !self.0.lpsz_proxy.is_null() {
                let _ = GlobalFree(self.0.lpsz_proxy.cast::<c_void>());
            }
            if !self.0.lpsz_proxy_bypass.is_null() {
                let _ = GlobalFree(self.0.lpsz_proxy_bypass.cast::<c_void>());
            }
        }
    }
}

#[link(name = "winhttp")]
extern "system" {
    fn WinHttpGetDefaultProxyConfiguration(p_proxy_info: *mut WinHttpProxyInfo) -> i32;
    fn WinHttpSetDefaultProxyConfiguration(p_proxy_info: *mut WinHttpProxyInfo) -> i32;
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

#[repr(C)]
struct KnownFolderGuid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

// FOLDERID_ProgramFiles = {905E63B6-C1BF-494E-B29C-65B732D3D21A}
const FOLDERID_PROGRAM_FILES: KnownFolderGuid = KnownFolderGuid {
    data1: 0x905e_63b6,
    data2: 0xc1bf,
    data3: 0x494e,
    data4: [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a],
};

// FOLDERID_ProgramData = {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}
const FOLDERID_PROGRAM_DATA: KnownFolderGuid = KnownFolderGuid {
    data1: 0x62ab_5d82,
    data2: 0xfdc1,
    data3: 0x4dc3,
    data4: [0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97],
};

#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(
        rfid: *const KnownFolderGuid,
        dw_flags: u32,
        h_token: *mut c_void,
        ppsz_path: *mut *mut u16,
    ) -> i32;
}

#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(pv: *mut c_void);
}

struct CoTaskMemGuard(*mut u16);

impl Drop for CoTaskMemGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by `SHGetKnownFolderPath` and must be freed via `CoTaskMemFree`.
            unsafe {
                CoTaskMemFree(self.0.cast::<c_void>());
            }
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
fn system32_exe(name: &str) -> PathBuf {
    static SYSTEM32_DIR: OnceLock<PathBuf> = OnceLock::new();
    SYSTEM32_DIR.get_or_init(windows_system32_dir).join(name)
}

/// # Safety
/// `ptr` must point to a valid NUL-terminated UTF-16 string.
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    String::from_utf16_lossy(slice)
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
    let trimmed = endpoint.trim().trim_end_matches('/');
    let stripped = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .unwrap_or(trimmed);
    let port = stripped
        .strip_prefix("127.0.0.1:")
        .or_else(|| stripped.strip_prefix("[::1]:"))
        .or_else(|| stripped.strip_prefix("localhost:"))
        .or_else(|| stripped.strip_prefix("0.0.0.0:"))
        .or_else(|| stripped.strip_prefix("[::]:"));
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
        if !matches!(scheme, "http" | "https" | "socks")
            || !is_vdpi_owned_wininet_endpoint(endpoint)
        {
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

fn is_valid_windows_known_folder_path_str(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.starts_with(r"\\")
        || trimmed.starts_with("//")
    {
        return false;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'\\' | b'/')
    {
        return false;
    }
    if trimmed[3..].trim_matches(['\\', '/']).is_empty() {
        return false;
    }
    !trimmed.split(['\\', '/']).any(|seg| seg == "..")
}

fn has_reparse_point_component(path: &Path) -> bool {
    let mut cur = PathBuf::new();
    let mut has_normal = false;
    for comp in path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                cur.push(comp.as_os_str());
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => return true,
            Component::Normal(part) => {
                has_normal = true;
                cur.push(part);
            }
        }
        match path_attributes_no_follow(&cur) {
            Ok(Some(attrs)) if is_reparse_point_attrs(attrs) => return true,
            Ok(Some(_)) | Ok(None) => {}
            Err(_) => return true,
        }
    }
    !has_normal
}

fn validate_known_folder_candidate(candidate: Option<PathBuf>, fallback: &'static str) -> PathBuf {
    if let Some(path) = candidate {
        if path
            .to_str()
            .is_some_and(is_valid_windows_known_folder_path_str)
            && !has_reparse_point_component(&path)
        {
            return path;
        }
        warn!(
            path = %path.display(),
            fallback,
            "SHGetKnownFolderPath returned an invalid or reparse-point path; falling back"
        );
    }
    let fallback_path = PathBuf::from(fallback);
    debug_assert!(is_valid_windows_known_folder_path_str(fallback));
    if has_reparse_point_component(&fallback_path) {
        warn!(
            path = %fallback_path.display(),
            "fallback Windows known folder path is an NTFS reparse point or inaccessible"
        );
    }
    fallback_path
}

fn resolve_known_folder_dir(folder_id: &KnownFolderGuid, fallback: &'static str) -> PathBuf {
    let mut raw_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: `folder_id` is a valid KNOWNFOLDERID GUID and `raw_ptr` is a valid out-pointer.
    let hr = unsafe { SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &mut raw_ptr) };
    let _guard = CoTaskMemGuard(raw_ptr);
    let candidate = if hr == 0 && !raw_ptr.is_null() {
        // SAFETY: `SHGetKnownFolderPath` succeeded and returned a NUL-terminated UTF-16 string
        // owned by `_guard` for the duration of this scope.
        let wide_slice = unsafe {
            let mut len = 0usize;
            while *raw_ptr.add(len) != 0 {
                len += 1;
            }
            std::slice::from_raw_parts(raw_ptr, len)
        };
        Some(PathBuf::from(OsString::from_wide(wide_slice)))
    } else {
        None
    };
    validate_known_folder_candidate(candidate, fallback)
}

/// Resolves the Windows `Program Files` directory via Win32 `SHGetKnownFolderPath`
/// (`FOLDERID_ProgramFiles`), validating local drive syntax and rejecting UNC paths,
/// `..` traversal, and NTFS reparse points. Falls back strictly to `C:\Program Files`.
pub fn known_program_files_dir() -> PathBuf {
    resolve_known_folder_dir(&FOLDERID_PROGRAM_FILES, r"C:\Program Files")
}

/// Resolves the Windows `ProgramData` directory via Win32 `SHGetKnownFolderPath`
/// (`FOLDERID_ProgramData`), validating local drive syntax and rejecting UNC paths,
/// `..` traversal, and NTFS reparse points. Falls back strictly to `C:\ProgramData`.
pub fn known_program_data_dir() -> PathBuf {
    resolve_known_folder_dir(&FOLDERID_PROGRAM_DATA, r"C:\ProgramData")
}

fn programdata_vdpi_dir() -> PathBuf {
    known_program_data_dir().join("vdpi")
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

#[derive(Debug, Clone, Default)]
pub struct WindowsProxyResetOutcome {
    pub wininet_changed: bool,
    pub env_changed: bool,
    pub winhttp_changed: bool,
    pub winhttp_skipped_privileges: bool,
    pub errors: Vec<String>,
}

pub fn reset_windows_proxies_to_defaults(elevated: bool) -> WindowsProxyResetOutcome {
    let mut outcome = WindowsProxyResetOutcome::default();

    let mut roots = vec!["HKCU".to_string()];
    if elevated {
        for sid_root in enumerate_interactive_hku_roots() {
            if !roots.iter().any(|r| r.eq_ignore_ascii_case(&sid_root)) {
                roots.push(sid_root);
            }
        }
        let default_root = r"HKU\.DEFAULT".to_string();
        if !roots.iter().any(|r| r.eq_ignore_ascii_case(&default_root)) {
            roots.push(default_root);
        }
    }

    for root in &roots {
        let inet_key = internet_settings_key(root);
        let was_enabled = query_reg_dword_native(&inet_key, "ProxyEnable").is_some_and(|v| v != 0);
        match set_reg_dword_existing_key(&inet_key, "ProxyEnable", 0) {
            Ok(true) if was_enabled => outcome.wininet_changed = true,
            Ok(_) => {}
            Err(err) => outcome
                .errors
                .push(format!("failed to disable ProxyEnable in {inet_key}: {err}")),
        }

        for value_name in ["AutoConfigURL", "ProxyServer", "ProxyOverride"] {
            match delete_reg_value_checked(&inet_key, value_name) {
                Ok(true) => outcome.wininet_changed = true,
                Ok(false) => {}
                Err(err) => outcome
                    .errors
                    .push(format!("failed to delete {inet_key}\\{value_name}: {err}")),
            }
        }

        let conn_key = format!(r"{inet_key}\Connections");
        for value_name in WININET_CONNECTION_BLOB_VALUES {
            match delete_reg_value_checked(&conn_key, value_name) {
                Ok(true) => outcome.wininet_changed = true,
                Ok(false) => {}
                Err(err) => outcome
                    .errors
                    .push(format!("failed to delete {conn_key}\\{value_name}: {err}")),
            }
        }

        let env_key = user_env_key(root);
        for env_name in ALL_RESET_ENV_VARS {
            match delete_reg_value_checked(&env_key, env_name) {
                Ok(true) => outcome.env_changed = true,
                Ok(false) => {}
                Err(err) => outcome
                    .errors
                    .push(format!("failed to delete {env_key}\\{env_name}: {err}")),
            }
        }
    }

    if elevated {
        // Delete proxy env vars from machine Environment only - never touch `Path`.
        for env_name in ALL_RESET_ENV_VARS {
            match delete_reg_value_checked(SYSTEM_ENV_KEY, env_name) {
                Ok(true) => outcome.env_changed = true,
                Ok(false) => {}
                Err(err) => outcome.errors.push(format!(
                    "failed to delete {SYSTEM_ENV_KEY}\\{env_name}: {err}"
                )),
            }
        }

        match reset_winhttp_proxy_unconditional() {
            Ok(changed) => outcome.winhttp_changed |= changed,
            Err(err) => outcome.errors.push(err),
        }
    } else if query_winhttp_proxy_server().is_some() {
        outcome.winhttp_skipped_privileges = true;
    }

    remove_saved_windows_proxy_state_files();
    notify_wininet_refresh();
    broadcast_environment_change();

    outcome
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
    if wininet_changed || !is_running_as_service() {
        notify_wininet_refresh();
    }
    if env_changed {
        broadcast_environment_change();
    }
    Ok(())
}

fn read_blob_u32_le(blob: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let bytes: [u8; 4] = blob.get(*pos..end)?.try_into().ok()?;
    *pos = end;
    Some(u32::from_le_bytes(bytes))
}

fn read_blob_len_prefixed<'a>(blob: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = usize::try_from(read_blob_u32_le(blob, pos)?).ok()?;
    let end = pos.checked_add(len)?;
    let data = blob.get(*pos..end)?;
    *pos = end;
    Some(data)
}

struct ParsedWininetBlob<'a> {
    version: u32,
    counter: u32,
    flags: u32,
    proxy_bytes: &'a [u8],
    bypass_bytes: &'a [u8],
    pac_bytes: &'a [u8],
    trailing: &'a [u8],
}

fn parse_wininet_connection_blob(blob: &[u8]) -> Option<ParsedWininetBlob<'_>> {
    let mut pos = 0usize;
    let version = read_blob_u32_le(blob, &mut pos)?;
    if version != WININET_BLOB_VERSION_V70 && version != WININET_BLOB_VERSION_V60 {
        return None;
    }
    let counter = read_blob_u32_le(blob, &mut pos)?;
    let flags = read_blob_u32_le(blob, &mut pos)?;
    let proxy_bytes = read_blob_len_prefixed(blob, &mut pos)?;
    let bypass_bytes = read_blob_len_prefixed(blob, &mut pos)?;
    let pac_bytes = read_blob_len_prefixed(blob, &mut pos)?;
    let trailing = blob.get(pos..)?;
    Some(ParsedWininetBlob {
        version,
        counter,
        flags,
        proxy_bytes,
        bypass_bytes,
        pac_bytes,
        trailing,
    })
}

fn encode_wininet_connection_blob(parsed: &ParsedWininetBlob<'_>) -> Option<Vec<u8>> {
    let proxy_len = u32::try_from(parsed.proxy_bytes.len()).ok()?;
    let bypass_len = u32::try_from(parsed.bypass_bytes.len()).ok()?;
    let pac_len = u32::try_from(parsed.pac_bytes.len()).ok()?;

    let mut out = Vec::with_capacity(
        24 + parsed.proxy_bytes.len()
            + parsed.bypass_bytes.len()
            + parsed.pac_bytes.len()
            + parsed.trailing.len(),
    );
    out.extend_from_slice(&parsed.version.to_le_bytes());
    out.extend_from_slice(&parsed.counter.to_le_bytes());
    out.extend_from_slice(&parsed.flags.to_le_bytes());
    out.extend_from_slice(&proxy_len.to_le_bytes());
    out.extend_from_slice(parsed.proxy_bytes);
    out.extend_from_slice(&bypass_len.to_le_bytes());
    out.extend_from_slice(parsed.bypass_bytes);
    out.extend_from_slice(&pac_len.to_le_bytes());
    out.extend_from_slice(parsed.pac_bytes);
    out.extend_from_slice(parsed.trailing);
    Some(out)
}

pub(crate) fn patch_wininet_connection_blob(
    blob: &[u8],
    clear_pac: bool,
    clear_manual: bool,
    set_pac_url: Option<&str>,
) -> Option<Vec<u8>> {
    let mut parsed = parse_wininet_connection_blob(blob)?;
    parsed.counter = parsed.counter.wrapping_add(1);

    if clear_manual {
        parsed.flags &= !WININET_FLAG_PROXY;
        parsed.proxy_bytes = &[];
        parsed.bypass_bytes = &[];
    }
    if clear_pac {
        parsed.flags &= !WININET_FLAG_AUTO_PROXY_URL;
        parsed.pac_bytes = &[];
        if (parsed.flags & (WININET_FLAG_PROXY | WININET_FLAG_AUTO_PROXY_URL)) == 0 {
            parsed.flags |= WININET_FLAG_DIRECT;
        }
    }
    if let Some(url) = set_pac_url {
        parsed.flags |= WININET_FLAG_AUTO_PROXY_URL | WININET_FLAG_DIRECT;
        parsed.flags &= !WININET_FLAG_PROXY;
        parsed.pac_bytes = url.as_bytes();
    }
    if clear_manual && (parsed.flags & (WININET_FLAG_PROXY | WININET_FLAG_AUTO_PROXY_URL)) == 0 {
        parsed.flags |= WININET_FLAG_DIRECT;
    }

    encode_wininet_connection_blob(&parsed)
}

fn patch_wininet_connection_blob_restore_manual(
    blob: &[u8],
    clear_pac: bool,
    set_pac_url: Option<&str>,
    server: &str,
    override_list: Option<&str>,
) -> Option<Vec<u8>> {
    let mut parsed = parse_wininet_connection_blob(blob)?;
    parsed.counter = parsed.counter.wrapping_add(1);
    parsed.flags |= WININET_FLAG_PROXY | WININET_FLAG_DIRECT;
    parsed.proxy_bytes = server.as_bytes();
    if let Some(ov) = override_list {
        parsed.bypass_bytes = ov.as_bytes();
    }
    if clear_pac {
        parsed.flags &= !WININET_FLAG_AUTO_PROXY_URL;
        parsed.pac_bytes = &[];
    }
    if let Some(url) = set_pac_url {
        parsed.flags |= WININET_FLAG_AUTO_PROXY_URL;
        parsed.pac_bytes = url.as_bytes();
    }
    encode_wininet_connection_blob(&parsed)
}

pub(crate) fn sync_wininet_connection_blobs(
    inet_key: &str,
    clear_pac: bool,
    clear_manual: bool,
    set_pac_url: Option<&str>,
    delete_if_malformed: bool,
) -> bool {
    let conn_key = format!(r"{inet_key}\Connections");
    let mut changed = false;
    for value_name in WININET_CONNECTION_BLOB_VALUES {
        let Some(blob) = query_reg_binary_native(&conn_key, value_name) else {
            continue;
        };
        match patch_wininet_connection_blob(&blob, clear_pac, clear_manual, set_pac_url) {
            Some(patched) => {
                if set_reg_binary_native(&conn_key, value_name, &patched).is_ok() {
                    changed = true;
                }
            }
            None => {
                if delete_if_malformed && delete_reg_value_native(&conn_key, value_name) {
                    changed = true;
                }
            }
        }
    }
    changed
}

pub(crate) fn sync_wininet_connection_blobs_restore_manual(
    inet_key: &str,
    clear_pac: bool,
    set_pac_url: Option<&str>,
    server: &str,
    override_list: Option<&str>,
) -> bool {
    let conn_key = format!(r"{inet_key}\Connections");
    let mut changed = false;
    for value_name in WININET_CONNECTION_BLOB_VALUES {
        let Some(blob) = query_reg_binary_native(&conn_key, value_name) else {
            continue;
        };
        let Some(patched) = patch_wininet_connection_blob_restore_manual(
            &blob,
            clear_pac,
            set_pac_url,
            server,
            override_list,
        ) else {
            continue;
        };
        if set_reg_binary_native(&conn_key, value_name, &patched).is_ok() {
            changed = true;
        }
    }
    changed
}

fn delete_vdpi_owned_manual_proxy_values(inet_key: &str) -> bool {
    let Some(server) = query_reg_sz_native(inet_key, "ProxyServer") else {
        return false;
    };
    if !is_vdpi_owned_wininet_server(&server) {
        return false;
    }
    let deleted_server = delete_reg_value_native(inet_key, "ProxyServer");
    let deleted_override = delete_reg_value_native(inet_key, "ProxyOverride");
    deleted_server || deleted_override
}

fn execute_wininet_restore_plan(inet_key: &str, plan: &WininetRestorePlan) -> bool {
    let mut changed = false;

    let (clear_pac, set_pac_url) = match &plan.auto_config {
        AutoConfigAction::Keep => (false, None),
        AutoConfigAction::Delete => {
            if delete_reg_value_native(inet_key, "AutoConfigURL") {
                changed = true;
            }
            (true, None)
        }
        AutoConfigAction::Set(prev_url) => {
            if set_reg_sz_native(inet_key, "AutoConfigURL", prev_url).is_ok() {
                changed = true;
            }
            (false, Some(prev_url.as_str()))
        }
    };

    match &plan.manual_proxy {
        ManualProxyAction::Keep => {
            let proxy_disabled =
                query_reg_dword_native(inet_key, "ProxyEnable").is_none_or(|v| v == 0);
            let cleared_stale_manual =
                proxy_disabled && delete_vdpi_owned_manual_proxy_values(inet_key);
            if cleared_stale_manual {
                changed = true;
            }
            if (clear_pac || set_pac_url.is_some() || cleared_stale_manual)
                && sync_wininet_connection_blobs(
                    inet_key,
                    clear_pac,
                    cleared_stale_manual,
                    set_pac_url,
                    clear_pac || cleared_stale_manual,
                )
            {
                changed = true;
            }
        }
        ManualProxyAction::Disable => {
            if set_reg_dword_native(inet_key, "ProxyEnable", 0).is_ok() {
                changed = true;
            }
            if delete_vdpi_owned_manual_proxy_values(inet_key) {
                changed = true;
            }
            if sync_wininet_connection_blobs(inet_key, clear_pac, true, set_pac_url, true) {
                changed = true;
            }
        }
        ManualProxyAction::Restore {
            server,
            override_list,
        } => {
            let mut restored = set_reg_sz_native(inet_key, "ProxyServer", server).is_ok();
            if let Some(ov) = override_list {
                let _ = set_reg_sz_native(inet_key, "ProxyOverride", ov);
            }
            if set_reg_dword_native(inet_key, "ProxyEnable", 1).is_ok() {
                restored = true;
            }
            if sync_wininet_connection_blobs_restore_manual(
                inet_key,
                clear_pac,
                set_pac_url,
                server,
                override_list.as_deref(),
            ) {
                restored = true;
            }
            if restored {
                changed = true;
            }
        }
    }

    changed
}

pub fn query_winhttp_proxy_server() -> Option<String> {
    let mut guard = WinHttpProxyInfoGuard(WinHttpProxyInfo {
        dw_access_type: 0,
        lpsz_proxy: std::ptr::null_mut(),
        lpsz_proxy_bypass: std::ptr::null_mut(),
    });
    // SAFETY: `guard.0` is initialized and any allocated buffers are freed on drop via `GlobalFree`.
    let ok = unsafe { WinHttpGetDefaultProxyConfiguration(&mut guard.0) };
    if ok == 0 {
        return None;
    }
    if guard.0.dw_access_type != WINHTTP_ACCESS_TYPE_NAMED_PROXY || guard.0.lpsz_proxy.is_null() {
        return None;
    }
    // SAFETY: `lpsz_proxy` is a non-null NUL-terminated UTF-16 string returned by WinHTTP.
    let proxy = unsafe { wide_ptr_to_string(guard.0.lpsz_proxy) };
    let trimmed = proxy.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn has_non_direct_winhttp_proxy() -> bool {
    let mut guard = WinHttpProxyInfoGuard(WinHttpProxyInfo {
        dw_access_type: 0,
        lpsz_proxy: std::ptr::null_mut(),
        lpsz_proxy_bypass: std::ptr::null_mut(),
    });
    // SAFETY: `guard.0` is initialized and any allocated buffers are freed on drop via `GlobalFree`.
    let ok = unsafe { WinHttpGetDefaultProxyConfiguration(&mut guard.0) };
    if ok == 0 {
        return false;
    }
    let has_proxy = !guard.0.lpsz_proxy.is_null()
        && !unsafe { wide_ptr_to_string(guard.0.lpsz_proxy) }
            .trim()
            .is_empty();
    let has_bypass = !guard.0.lpsz_proxy_bypass.is_null()
        && !unsafe { wide_ptr_to_string(guard.0.lpsz_proxy_bypass) }
            .trim()
            .is_empty();
    guard.0.dw_access_type != WINHTTP_ACCESS_TYPE_NO_PROXY || has_proxy || has_bypass
}

fn reset_winhttp_32bit_wow64() -> Result<bool, String> {
    use windows_sys::Win32::System::Registry::KEY_WOW64_32KEY;

    let mut deleted = delete_reg_value_checked_with_sam(
        RegHive::LocalMachine,
        WINHTTP_CONNECTIONS_SUBKEY,
        "WinHttpSettings",
        KEY_WOW64_32KEY,
    )
    .map_err(|e| format!("failed to reset 32-bit WOW64 WinHTTP settings: {e}"))?;

    if !deleted {
        deleted = delete_reg_value_checked_with_sam(
            RegHive::LocalMachine,
            WINHTTP_CONNECTIONS_WOW64_SUBKEY,
            "WinHttpSettings",
            KEY_WOW64_32KEY,
        )
        .map_err(|e| format!("failed to reset WOW6432Node WinHTTP settings: {e}"))?;
    }

    Ok(deleted)
}

pub fn reset_winhttp_proxy_unconditional() -> Result<bool, String> {
    let had_64bit_proxy = has_non_direct_winhttp_proxy();
    let mut info = WinHttpProxyInfo {
        dw_access_type: WINHTTP_ACCESS_TYPE_NO_PROXY,
        lpsz_proxy: std::ptr::null_mut(),
        lpsz_proxy_bypass: std::ptr::null_mut(),
    };
    // SAFETY: `info` is a valid `WINHTTP_PROXY_INFO` requesting direct (no proxy) access.
    let ok = unsafe { WinHttpSetDefaultProxyConfiguration(&mut info) };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("WinHttpSetDefaultProxyConfiguration failed: {err}"));
    }
    let wow64_changed = reset_winhttp_32bit_wow64()?;
    Ok(had_64bit_proxy || wow64_changed)
}

#[cfg(test)]
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
        if let Err(err) = reset_winhttp_proxy_unconditional() {
            debug!(error = %err, "failed to reset vdpi-owned WinHTTP proxy");
        }
    }
}

pub fn print_windows_proxy_status() {
    let inet_key = internet_settings_key("HKCU");
    let env_key = user_env_key("HKCU");
    let current = query_current_wininet_state(&inet_key);
    let override_val =
        query_reg_sz_native(&inet_key, "ProxyOverride").unwrap_or_else(|| "<unset>".into());
    let https_env = query_reg_sz_native(&env_key, "HTTPS_PROXY").unwrap_or_else(|| "<unset>".into());
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
    use windows_sys::Win32::Foundation::{
        ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS as WIN32_ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{RegEnumKeyExW, HKEY_USERS};

    let mut roots = Vec::new();
    let mut index: u32 = 0;
    let mut buf_cap: usize = 260;

    loop {
        let mut name_buf = vec![0u16; buf_cap];
        let mut name_len = name_buf.len() as u32;
        // SAFETY: `HKEY_USERS` is a predefined root handle and `name_buf` holds `name_len` UTF-16 units.
        let rc = unsafe {
            RegEnumKeyExW(
                HKEY_USERS,
                index,
                name_buf.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        match rc {
            WIN32_ERROR_SUCCESS => {
                let sid = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                let is_user_sid = sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-");
                let is_classes = sid.to_ascii_lowercase().ends_with("_classes");
                if is_user_sid && !is_classes {
                    roots.push(format!(r"HKU\{sid}"));
                }
                index = index.saturating_add(1);
            }
            ERROR_MORE_DATA => {
                if buf_cap >= 4096 {
                    index = index.saturating_add(1);
                } else {
                    buf_cap *= 2;
                }
            }
            ERROR_NO_MORE_ITEMS => break,
            other => {
                debug!(error = other, index, "RegEnumKeyExW(HKEY_USERS) stopped");
                break;
            }
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

pub(crate) fn internet_settings_key(root: &str) -> String {
    format!(r"{root}\{INTERNET_SETTINGS_SUBKEY}")
}

fn user_env_key(root: &str) -> String {
    format!(r"{root}\{USER_ENV_SUBKEY}")
}

fn apply_wininet_pac_proxy(inet_key: &str, pac_url: &str) -> Result<()> {
    set_reg_sz_native(inet_key, "AutoConfigURL", pac_url)?;
    // Explicitly disable manual ProxyEnable so Windows evaluates the fail-open PAC
    // (`PROXY 127.0.0.1:<port>; DIRECT`) and automatically falls back to DIRECT if vdpi exits.
    set_reg_dword_native(inet_key, "ProxyEnable", 0)?;
    let cleared_vdpi_manual = delete_vdpi_owned_manual_proxy_values(inet_key);
    let _ = sync_wininet_connection_blobs(
        inet_key,
        false,
        cleared_vdpi_manual,
        Some(pac_url),
        false,
    );
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

pub(crate) fn is_vdpi_owned_no_proxy_env(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    let has_cgnat_or_ula = (lower.contains("100.64.0.0/10") || lower.contains("100.64.*"))
        && (lower.contains("fc00::/7")
            || lower.contains("fe80::/10")
            || lower.contains("home.arpa")
            || lower.contains(".ts.net"));
    let has_tr_markers = lower.contains("paratika.com.tr")
        || (lower.contains(".gov.tr") && lower.contains(".bel.tr") && lower.contains(".ts.net"));
    has_cgnat_or_ula || has_tr_markers
}

fn unset_windows_user_env(env_key: &str) -> bool {
    let mut proxy_matched = false;
    let mut changed = false;
    for key in PROXY_ENV_VARS {
        if query_reg_sz_native(env_key, key)
            .as_deref()
            .is_some_and(is_vdpi_owned_proxy_env)
        {
            proxy_matched = true;
            if delete_reg_value_native(env_key, key) {
                changed = true;
            }
        }
    }
    for key in NO_PROXY_ENV_VARS {
        let should_delete = proxy_matched
            || query_reg_sz_native(env_key, key)
                .as_deref()
                .is_some_and(is_vdpi_owned_no_proxy_env);
        if should_delete && delete_reg_value_native(env_key, key) {
            changed = true;
        }
    }
    changed
}

fn query_current_wininet_state(inet_key: &str) -> CurrentWininetState {
    let proxy_enable = query_reg_dword_native(inet_key, "ProxyEnable").is_some_and(|v| v != 0);
    let proxy_server = query_reg_sz_native(inet_key, "ProxyServer").unwrap_or_default();
    let auto_config_url = query_reg_sz_native(inet_key, "AutoConfigURL");
    CurrentWininetState {
        proxy_enable,
        proxy_server,
        auto_config_url,
    }
}

fn capture_wininet_state(inet_key: &str) -> SavedWininetHiveState {
    let current = query_current_wininet_state(inet_key);
    let proxy_override = query_reg_sz_native(inet_key, "ProxyOverride");
    SavedWininetHiveState {
        proxy_enable: current.proxy_enable,
        proxy_server: (!current.proxy_server.trim().is_empty()).then_some(current.proxy_server),
        proxy_override,
        auto_config_url: current.auto_config_url,
    }
}

fn encode_wide_str_nul(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn query_reg_value_raw(key: &str, value_name: &str) -> Option<(u32, Vec<u8>)> {
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS as WIN32_ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_QUERY_VALUE, REG_VALUE_TYPE,
    };

    let (hive, subkey) = split_reg_key_path(key).ok()?;
    let wide_subkey = encode_wide_str_nul(subkey);
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc != WIN32_ERROR_SUCCESS {
        return None;
    }
    let guard = RegKeyGuard(raw_hkey);

    let wide_name = encode_wide_str_nul(value_name);
    let mut reg_type: REG_VALUE_TYPE = 0;
    let mut cb_data: u32 = 0;

    for _ in 0..8 {
        // SAFETY: `guard.0` is an open registry key and `wide_name` is NUL-terminated UTF-16.
        let size_rc = unsafe {
            RegQueryValueExW(
                guard.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        if size_rc != WIN32_ERROR_SUCCESS {
            return None;
        }
        if cb_data == 0 {
            return Some((reg_type, Vec::new()));
        }

        let mut data = vec![0u8; cb_data as usize];
        // SAFETY: `data` has capacity/length `cb_data` bytes.
        let read_rc = unsafe {
            RegQueryValueExW(
                guard.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                data.as_mut_ptr(),
                &mut cb_data,
            )
        };
        match read_rc {
            WIN32_ERROR_SUCCESS => {
                data.truncate(cb_data as usize);
                return Some((reg_type, data));
            }
            ERROR_MORE_DATA => continue,
            _ => return None,
        }
    }
    None
}

pub fn query_reg_sz_native(key: &str, value_name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};

    let (reg_type, data) = query_reg_value_raw(key, value_name)?;
    match reg_type {
        REG_SZ | REG_EXPAND_SZ => decode_reg_utf16_bytes(&data).ok(),
        REG_DWORD => {
            let bytes: [u8; 4] = data.as_slice().try_into().ok()?;
            Some(u32::from_le_bytes(bytes).to_string())
        }
        _ => None,
    }
}

pub fn query_reg_sz(key: &str, value_name: &str) -> Option<String> {
    query_reg_sz_native(key, value_name)
}

fn query_reg_dword_native(key: &str, value_name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};

    let (reg_type, data) = query_reg_value_raw(key, value_name)?;
    match reg_type {
        REG_DWORD => {
            let bytes: [u8; 4] = data.as_slice().try_into().ok()?;
            Some(u32::from_le_bytes(bytes))
        }
        REG_SZ | REG_EXPAND_SZ => {
            let text = decode_reg_utf16_bytes(&data).ok()?;
            let trimmed = text.trim();
            if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u32::from_str_radix(hex, 16).ok()
            } else {
                trimmed.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

fn query_reg_binary_native(key: &str, value_name: &str) -> Option<Vec<u8>> {
    use windows_sys::Win32::System::Registry::REG_BINARY;

    let (reg_type, data) = query_reg_value_raw(key, value_name)?;
    (reg_type == REG_BINARY).then_some(data)
}

fn set_reg_sz_native(key: &str, value_name: &str, value: &str) -> Result<()> {
    let (hive, subkey) = split_reg_key_path(key)?;
    set_reg_string_value(hive, subkey, value_name, value, RegStringKind::Sz)
}

fn set_reg_dword_native(key: &str, value_name: &str, value: u32) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS as WIN32_ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, HKEY, KEY_SET_VALUE, REG_DWORD,
    };

    let (hive, subkey) = split_reg_key_path(key)?;
    let hive_label = hive.label();
    let wide_subkey = encode_wide_str_nul(subkey);
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegOpenKeyExW({hive_label}\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}"
        );
    }
    let guard = RegKeyGuard(raw_hkey);

    let wide_name = encode_wide_str_nul(value_name);
    let bytes = value.to_le_bytes();
    // SAFETY: `guard.0` is an open registry handle with `KEY_SET_VALUE`, and `bytes` is 4 bytes.
    let set_rc = unsafe {
        RegSetValueExW(
            guard.0,
            wide_name.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if set_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegSetValueExW({hive_label}\\{subkey}\\{value_name}) failed with Win32 error {set_rc}"
        );
    }
    Ok(())
}

fn set_reg_dword_existing_key(key: &str, value_name: &str, value: u32) -> Result<bool> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND as WIN32_ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND as WIN32_ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS as WIN32_ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, HKEY, KEY_SET_VALUE, REG_DWORD,
    };

    let (hive, subkey) = split_reg_key_path(key)?;
    let hive_label = hive.label();
    let wide_subkey = encode_wide_str_nul(subkey);
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc == WIN32_ERROR_FILE_NOT_FOUND || open_rc == WIN32_ERROR_PATH_NOT_FOUND {
        return Ok(false);
    }
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegOpenKeyExW({hive_label}\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}"
        );
    }
    let guard = RegKeyGuard(raw_hkey);

    let wide_name = encode_wide_str_nul(value_name);
    let bytes = value.to_le_bytes();
    // SAFETY: `guard.0` is an open registry handle with `KEY_SET_VALUE`, and `bytes` is 4 bytes.
    let set_rc = unsafe {
        RegSetValueExW(
            guard.0,
            wide_name.as_ptr(),
            0,
            REG_DWORD,
            bytes.as_ptr(),
            bytes.len() as u32,
        )
    };
    if set_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegSetValueExW({hive_label}\\{subkey}\\{value_name}) failed with Win32 error {set_rc}"
        );
    }
    Ok(true)
}

fn set_reg_binary_native(key: &str, value_name: &str, data: &[u8]) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS as WIN32_ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, HKEY, KEY_SET_VALUE, REG_BINARY,
    };

    let (hive, subkey) = split_reg_key_path(key)?;
    let hive_label = hive.label();
    let wide_subkey = encode_wide_str_nul(subkey);
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegOpenKeyExW({hive_label}\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}"
        );
    }
    let guard = RegKeyGuard(raw_hkey);

    let wide_name = encode_wide_str_nul(value_name);
    let cb_data = u32::try_from(data.len()).with_context(|| {
        format!("registry binary value {hive_label}\\{subkey}\\{value_name} exceeds u32 byte length")
    })?;
    // SAFETY: `guard.0` is an open registry handle with `KEY_SET_VALUE`, and `data` has `cb_data` bytes.
    let set_rc = unsafe {
        RegSetValueExW(
            guard.0,
            wide_name.as_ptr(),
            0,
            REG_BINARY,
            data.as_ptr(),
            cb_data,
        )
    };
    if set_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegSetValueExW({hive_label}\\{subkey}\\{value_name}) failed with Win32 error {set_rc}"
        );
    }
    Ok(())
}

fn delete_reg_value_checked_with_sam(
    hive: RegHive,
    subkey: &str,
    value_name: &str,
    extra_sam: u32,
) -> Result<bool> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND as WIN32_ERROR_FILE_NOT_FOUND,
        ERROR_PATH_NOT_FOUND as WIN32_ERROR_PATH_NOT_FOUND,
        ERROR_SUCCESS as WIN32_ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegDeleteValueW, RegOpenKeyExW, HKEY, KEY_SET_VALUE,
    };

    let hive_label = hive.label();
    let wide_subkey = encode_wide_str_nul(subkey);
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_SET_VALUE | extra_sam,
            &mut raw_hkey,
        )
    };
    if open_rc == WIN32_ERROR_FILE_NOT_FOUND || open_rc == WIN32_ERROR_PATH_NOT_FOUND {
        return Ok(false);
    }
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegOpenKeyExW({hive_label}\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}"
        );
    }
    let guard = RegKeyGuard(raw_hkey);

    let wide_name = encode_wide_str_nul(value_name);
    // SAFETY: `guard.0` is an open registry handle with `KEY_SET_VALUE` and `wide_name` is NUL-terminated.
    let del_rc = unsafe { RegDeleteValueW(guard.0, wide_name.as_ptr()) };
    match del_rc {
        WIN32_ERROR_SUCCESS => Ok(true),
        WIN32_ERROR_FILE_NOT_FOUND | WIN32_ERROR_PATH_NOT_FOUND => Ok(false),
        other => anyhow::bail!(
            "RegDeleteValueW({hive_label}\\{subkey}\\{value_name}) failed with Win32 error {other}"
        ),
    }
}

fn delete_reg_value_checked(key: &str, value_name: &str) -> Result<bool> {
    let (hive, subkey) = split_reg_key_path(key)?;
    delete_reg_value_checked_with_sam(hive, subkey, value_name, 0)
}

pub fn delete_reg_value_native(key: &str, value_name: &str) -> bool {
    delete_reg_value_checked(key, value_name).unwrap_or(false)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegStringKind {
    Sz,
    ExpandSz,
}

impl RegStringKind {
    fn from_win32(reg_type: u32) -> Option<Self> {
        use windows_sys::Win32::System::Registry::{REG_EXPAND_SZ, REG_SZ};
        match reg_type {
            REG_SZ => Some(Self::Sz),
            REG_EXPAND_SZ => Some(Self::ExpandSz),
            _ => None,
        }
    }

    fn to_win32(self) -> u32 {
        use windows_sys::Win32::System::Registry::{REG_EXPAND_SZ, REG_SZ};
        match self {
            Self::Sz => REG_SZ,
            Self::ExpandSz => REG_EXPAND_SZ,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegHive {
    LocalMachine,
    CurrentUser,
    Users,
}

impl RegHive {
    fn as_hkey(self) -> windows_sys::Win32::System::Registry::HKEY {
        use windows_sys::Win32::System::Registry::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS,
        };
        match self {
            Self::LocalMachine => HKEY_LOCAL_MACHINE,
            Self::CurrentUser => HKEY_CURRENT_USER,
            Self::Users => HKEY_USERS,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::LocalMachine => "HKLM",
            Self::CurrentUser => "HKCU",
            Self::Users => "HKU",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegQueryOutcome {
    Value { value: String, kind: RegStringKind },
    NotFound,
}

struct RegKeyGuard(windows_sys::Win32::System::Registry::HKEY);

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was opened by `RegOpenKeyExW` and is closed once on drop.
            unsafe {
                let _ = windows_sys::Win32::System::Registry::RegCloseKey(self.0);
            }
        }
    }
}

fn split_reg_key_path(full_key: &str) -> Result<(RegHive, &str)> {
    let trimmed = full_key.trim().trim_matches('\\');
    let Some((root, subkey)) = trimmed.split_once('\\') else {
        anyhow::bail!("registry key path missing subkey: {full_key}");
    };
    let subkey = subkey.trim_matches('\\');
    if subkey.is_empty() {
        anyhow::bail!("registry key path has empty subkey: {full_key}");
    }
    let hive = if root.eq_ignore_ascii_case("HKLM") || root.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE")
    {
        RegHive::LocalMachine
    } else if root.eq_ignore_ascii_case("HKCU") || root.eq_ignore_ascii_case("HKEY_CURRENT_USER") {
        RegHive::CurrentUser
    } else if root.eq_ignore_ascii_case("HKU") || root.eq_ignore_ascii_case("HKEY_USERS") {
        RegHive::Users
    } else {
        anyhow::bail!("unsupported registry hive '{root}' in key path: {full_key}");
    };
    Ok((hive, subkey))
}

fn decode_reg_utf16_bytes(bytes: &[u8]) -> Result<String> {
    let (chunks, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        anyhow::bail!("registry string value has odd byte length ({})", bytes.len());
    }
    let mut wide: Vec<u16> = chunks
        .iter()
        .map(|&chunk| u16::from_le_bytes(chunk))
        .collect();
    if let Some(pos) = wide.iter().position(|&c| c == 0) {
        wide.truncate(pos);
    }
    Ok(String::from_utf16_lossy(&wide))
}

fn encode_reg_utf16_bytes(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((value.len() + 1) * 2);
    for unit in value.encode_utf16().chain(std::iter::once(0)) {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// Queries a `REG_SZ` / `REG_EXPAND_SZ` value under `<hive>\<subkey>` using native Win32 Advapi32,
/// preserving the original registry string type (`REG_SZ` vs `REG_EXPAND_SZ`) and distinguishing
/// an absent value (`RegQueryOutcome::NotFound`) from real query errors (such as access denied,
/// key open failure, odd UTF-16 byte length, or unexpected value type).
fn query_reg_string_checked(
    hive: RegHive,
    subkey: &str,
    value_name: &str,
) -> Result<RegQueryOutcome> {
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND as WIN32_ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA,
        ERROR_SUCCESS as WIN32_ERROR_SUCCESS,
    };
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_QUERY_VALUE, REG_VALUE_TYPE,
    };

    let hive_label = hive.label();
    let wide_subkey: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!("RegOpenKeyExW({hive_label}\\{subkey}) failed with Win32 error {open_rc}");
    }
    let key = RegKeyGuard(raw_hkey);

    let wide_name: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut reg_type: REG_VALUE_TYPE = 0;
    let mut cb_data: u32 = 0;

    for _ in 0..8 {
        // SAFETY: `key.0` is a valid open registry handle and `wide_name` is NUL-terminated.
        let size_rc = unsafe {
            RegQueryValueExW(
                key.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                std::ptr::null_mut(),
                &mut cb_data,
            )
        };
        if size_rc == WIN32_ERROR_FILE_NOT_FOUND {
            return Ok(RegQueryOutcome::NotFound);
        }
        if size_rc != WIN32_ERROR_SUCCESS {
            anyhow::bail!(
                "RegQueryValueExW({hive_label}\\{subkey}\\{value_name}) size query failed with Win32 error {size_rc}"
            );
        }
        let Some(kind) = RegStringKind::from_win32(reg_type) else {
            anyhow::bail!(
                "unexpected registry type {reg_type} for {hive_label}\\{subkey}\\{value_name}"
            );
        };
        if cb_data == 0 {
            return Ok(RegQueryOutcome::Value {
                value: String::new(),
                kind,
            });
        }

        let mut data = vec![0u8; cb_data as usize];
        // SAFETY: `data` has capacity/length `cb_data` bytes.
        let read_rc = unsafe {
            RegQueryValueExW(
                key.0,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                data.as_mut_ptr(),
                &mut cb_data,
            )
        };
        match read_rc {
            WIN32_ERROR_FILE_NOT_FOUND => return Ok(RegQueryOutcome::NotFound),
            ERROR_MORE_DATA => continue,
            WIN32_ERROR_SUCCESS => {
                let Some(kind) = RegStringKind::from_win32(reg_type) else {
                    anyhow::bail!(
                        "unexpected registry type {reg_type} for {hive_label}\\{subkey}\\{value_name}"
                    );
                };
                data.truncate(cb_data as usize);
                let value = decode_reg_utf16_bytes(&data)?;
                return Ok(RegQueryOutcome::Value { value, kind });
            }
            other => {
                anyhow::bail!(
                    "RegQueryValueExW({hive_label}\\{subkey}\\{value_name}) read failed with Win32 error {other}"
                );
            }
        }
    }

    anyhow::bail!(
        "RegQueryValueExW({hive_label}\\{subkey}\\{value_name}) kept returning ERROR_MORE_DATA"
    )
}

/// Writes a UTF-16LE `REG_SZ` / `REG_EXPAND_SZ` value under `<hive>\<subkey>` using native
/// Win32 Advapi32 (`RegOpenKeyExW` + `RegSetValueExW`) so non-ASCII paths are never corrupted
/// through `reg.exe` code-page translation.
fn set_reg_string_value(
    hive: RegHive,
    subkey: &str,
    value_name: &str,
    value: &str,
    kind: RegStringKind,
) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS as WIN32_ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, HKEY, KEY_SET_VALUE,
    };

    let hive_label = hive.label();
    let wide_subkey: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let mut raw_hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `wide_subkey` is NUL-terminated UTF-16 and `raw_hkey` is a valid out-pointer.
    let open_rc = unsafe {
        RegOpenKeyExW(
            hive.as_hkey(),
            wide_subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut raw_hkey,
        )
    };
    if open_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegOpenKeyExW({hive_label}\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}"
        );
    }
    let key = RegKeyGuard(raw_hkey);

    let wide_name: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let bytes = encode_reg_utf16_bytes(value);
    let cb_data = u32::try_from(bytes.len()).with_context(|| {
        format!(
            "registry string value {hive_label}\\{subkey}\\{value_name} exceeds u32 byte length"
        )
    })?;

    // SAFETY: `key.0` is an open registry handle with `KEY_SET_VALUE`, `wide_name` is
    // NUL-terminated UTF-16, and `bytes` is a NUL-terminated UTF-16LE buffer of length `cb_data`.
    let set_rc = unsafe {
        RegSetValueExW(
            key.0,
            wide_name.as_ptr(),
            0,
            kind.to_win32(),
            bytes.as_ptr(),
            cb_data,
        )
    };
    if set_rc != WIN32_ERROR_SUCCESS {
        anyhow::bail!(
            "RegSetValueExW({hive_label}\\{subkey}\\{value_name}) failed with Win32 error {set_rc}"
        );
    }
    Ok(())
}

fn add_dir_to_windows_system_path_with<FQuery, FWrite>(
    dir: &Path,
    query_path: FQuery,
    mut write_path: FWrite,
) -> Result<bool>
where
    FQuery: FnOnce() -> Result<RegQueryOutcome>,
    FWrite: FnMut(&str, RegStringKind) -> Result<()>,
{
    let target = dir.display().to_string();
    let target_norm = target.trim().trim_end_matches('\\');
    if target_norm.is_empty() {
        anyhow::bail!("refusing to add an empty directory to Windows System Path");
    }

    let (current, existing_kind) = match query_path()
        .context("refusing to modify Windows System Path because querying existing Path failed")?
    {
        RegQueryOutcome::Value { value, kind } => (value, kind),
        RegQueryOutcome::NotFound => (String::new(), RegStringKind::ExpandSz),
    };

    let mut parts: Vec<String> = current
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .collect();

    let already_present = parts
        .iter()
        .any(|p| p.trim_end_matches('\\').eq_ignore_ascii_case(target_norm));

    if !already_present {
        parts.push(target_norm.to_string());
        let new_path = parts.join(";");
        // Defensive sanity guard: never allow a write that would shorten an existing non-empty Path.
        if !current.is_empty() && new_path.len() < current.len() {
            anyhow::bail!(
                "refusing to overwrite Windows System Path: computed Path ({} bytes) is shorter than existing Path ({} bytes)",
                new_path.len(),
                current.len()
            );
        }
        let write_kind = if existing_kind == RegStringKind::ExpandSz || new_path.contains('%') {
            RegStringKind::ExpandSz
        } else {
            RegStringKind::Sz
        };
        write_path(&new_path, write_kind)?;
    }

    Ok(!already_present)
}

/// Adds `dir` to the Windows System `Path` (`REG_EXPAND_SZ` / preserved `REG_SZ`) using native
/// UTF-16 Advapi32 registry calls, and removes any legacy directory from the current user's `Path`
/// so `vdpi` resolves cleanly from any terminal.
pub fn add_dir_to_windows_system_path(dir: &Path, legacy_dir: Option<&Path>) -> Result<bool> {
    let added = add_dir_to_windows_system_path_with(
        dir,
        || query_reg_string_checked(RegHive::LocalMachine, SYSTEM_ENV_SUBKEY, "Path"),
        |new_path, kind| {
            set_reg_string_value(
                RegHive::LocalMachine,
                SYSTEM_ENV_SUBKEY,
                "Path",
                new_path,
                kind,
            )
        },
    )?;

    let mut changed = added;
    if let Some(legacy) = legacy_dir {
        if remove_from_env_path_key(&user_env_key("HKCU"), &[legacy]) {
            changed = true;
        }
    }

    if changed {
        broadcast_environment_change();
    }
    Ok(added)
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

fn remove_from_env_path_key_with<FQuery, FWrite>(
    dirs: &[&Path],
    query_path: FQuery,
    mut write_path: FWrite,
) -> Result<bool>
where
    FQuery: FnOnce() -> Result<RegQueryOutcome>,
    FWrite: FnMut(&str, RegStringKind) -> Result<()>,
{
    let targets: Vec<String> = dirs
        .iter()
        .map(|d| {
            d.display()
                .to_string()
                .trim()
                .trim_end_matches('\\')
                .to_string()
        })
        .filter(|t| !t.is_empty())
        .collect();
    if targets.is_empty() {
        return Ok(false);
    }

    let (current, existing_kind) = match query_path()? {
        RegQueryOutcome::Value { value, kind } => (value, kind),
        RegQueryOutcome::NotFound => return Ok(false),
    };

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
        return Ok(false);
    }

    let new_path = filtered.join(";");
    let write_kind = if existing_kind == RegStringKind::ExpandSz || new_path.contains('%') {
        RegStringKind::ExpandSz
    } else {
        RegStringKind::Sz
    };

    write_path(&new_path, write_kind)?;
    Ok(true)
}

fn remove_from_env_path_key(env_key: &str, dirs: &[&Path]) -> bool {
    let Ok((hive, subkey)) = split_reg_key_path(env_key) else {
        warn!(
            key = %env_key,
            "refusing to modify unsupported Windows Path registry key"
        );
        return false;
    };

    match remove_from_env_path_key_with(
        dirs,
        || query_reg_string_checked(hive, subkey, "Path"),
        |new_path, kind| set_reg_string_value(hive, subkey, "Path", new_path, kind),
    ) {
        Ok(changed) => changed,
        Err(err) => {
            warn!(
                key = %env_key,
                error = %err,
                "aborting Windows Path removal due to registry error"
            );
            false
        }
    }
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

#[cfg(test)]
const STALE_BROWSER_EXES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "firefox.exe",
    "opera.exe",
    "vivaldi.exe",
];

#[cfg(test)]
const WINDOWS_TO_UNIX_EPOCH_SECS: u64 = 11_644_473_600;
#[cfg(test)]
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

#[cfg(test)]
fn canonical_stale_browser_name(exe_name: &str) -> Option<&'static str> {
    STALE_BROWSER_EXES
        .iter()
        .copied()
        .find(|candidate| exe_name.eq_ignore_ascii_case(candidate))
}

#[cfg(test)]
fn filetime_to_unix_secs(ft: FILETIME) -> Option<u64> {
    let ticks = (u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime);
    (ticks / FILETIME_TICKS_PER_SEC).checked_sub(WINDOWS_TO_UNIX_EPOCH_SECS)
}

/// Kept as a no-op returning an empty list: scanning running desktop browsers with
/// `OpenProcess` triggers Windows Defender behavioral heuristics and anti-cheat telemetry,
/// while WinINET fail-open PAC refresh updates active sessions without process inspection.
pub fn detect_stale_browsers(_since_unix_secs: u64) -> Vec<String> {
    Vec::new()
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
        assert!(is_vdpi_owned_wininet_server("0.0.0.0:8080"));
        assert!(is_vdpi_owned_wininet_server("[::]:8080"));
        assert!(is_vdpi_owned_wininet_server("http://127.0.0.1:8080"));
        assert!(is_vdpi_owned_wininet_server("https://127.0.0.1:8443"));
        assert!(is_vdpi_owned_wininet_server("http://localhost:8080"));
        assert!(is_vdpi_owned_wininet_server("https://[::1]:8080/"));
        assert!(is_vdpi_owned_wininet_server("http://0.0.0.0:8080"));
        assert!(is_vdpi_owned_wininet_server("https://[::]:8443"));
        assert!(is_vdpi_owned_wininet_server("http=localhost:8080"));
        assert!(is_vdpi_owned_wininet_server("https=localhost:8080"));
        assert!(is_vdpi_owned_wininet_server("socks=127.0.0.1:1080"));
        assert!(is_vdpi_owned_wininet_server("SOCKS=localhost:1080"));
        assert!(is_vdpi_owned_wininet_server(
            "HTTP=LOCALHOST:8080;HTTPS=LOCALHOST:8080;SOCKS=127.0.0.1:1080"
        ));
        assert!(is_vdpi_owned_wininet_server(
            "http=127.0.0.1:8080;https=127.0.0.1:8080"
        ));
        assert!(is_vdpi_owned_wininet_server(
            "http=[::1]:8080;https=[::1]:8080"
        ));
        assert!(is_vdpi_owned_wininet_server(
            "http=0.0.0.0:8080;https=[::]:8443"
        ));
        assert!(!is_vdpi_owned_wininet_server("proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_wininet_server("localhost.corp.local:8080"));
        assert!(!is_vdpi_owned_wininet_server(
            "http=localhost.corp.local:8080"
        ));
        assert!(!is_vdpi_owned_wininet_server(
            "http=proxy.corp.local:3128;https=localhost:8080"
        ));
        assert!(!is_vdpi_owned_wininet_server("socks=proxy.corp.local:1080"));
        assert!(!is_vdpi_owned_wininet_server("http://proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_wininet_server(
            "https://proxy.corp.local:3128"
        ));
        assert!(!is_vdpi_owned_wininet_server("localhost:"));
        assert!(!is_vdpi_owned_wininet_server("0.0.0.0:"));
        assert!(!is_vdpi_owned_wininet_server("[::]:"));
        assert!(!is_vdpi_owned_wininet_server("::1:8080"));
        assert!(!is_vdpi_owned_wininet_server(""));
    }

    fn build_test_wininet_blob(
        version: u32,
        counter: u32,
        flags: u32,
        proxy: &[u8],
        bypass: &[u8],
        pac: &[u8],
        trailing: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&version.to_le_bytes());
        out.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&(proxy.len() as u32).to_le_bytes());
        out.extend_from_slice(proxy);
        out.extend_from_slice(&(bypass.len() as u32).to_le_bytes());
        out.extend_from_slice(bypass);
        out.extend_from_slice(&(pac.len() as u32).to_le_bytes());
        out.extend_from_slice(pac);
        out.extend_from_slice(trailing);
        out
    }

    #[test]
    fn patch_wininet_connection_blob_handles_set_pac_clear_pac_clear_manual_and_malformed() {
        let trailing = [0xAAu8; 32];

        // 1. Set PAC URL on a v0x46 blob that had manual proxy enabled (0x01 | 0x02):
        //    sets 0x04, clears 0x02, preserves 0x01 and trailing bytes, increments counter.
        let initial = build_test_wininet_blob(
            WININET_BLOB_VERSION_V70,
            7,
            WININET_FLAG_DIRECT | WININET_FLAG_PROXY,
            b"proxy.corp.local:3128",
            b"*.corp.local;<local>",
            b"",
            &trailing,
        );
        let with_pac = patch_wininet_connection_blob(
            &initial,
            false,
            false,
            Some("http://127.0.0.1:8080/vdpi.pac"),
        )
        .expect("valid v0x46 blob should patch for PAC");
        let parsed = parse_wininet_connection_blob(&with_pac).expect("patched blob parses");
        assert_eq!(parsed.version, WININET_BLOB_VERSION_V70);
        assert_eq!(parsed.counter, 8);
        assert_eq!(parsed.flags, WININET_FLAG_DIRECT | WININET_FLAG_AUTO_PROXY_URL);
        assert_eq!(parsed.proxy_bytes, b"proxy.corp.local:3128");
        assert_eq!(parsed.bypass_bytes, b"*.corp.local;<local>");
        assert_eq!(parsed.pac_bytes, b"http://127.0.0.1:8080/vdpi.pac");
        assert_eq!(parsed.trailing, &trailing);

        // 2. Clear PAC URL on a blob with AUTO_PROXY_URL | AUTO_DETECT (0x04 | 0x08):
        //    clears 0x04, empties pac_bytes, ensures 0x01 (DIRECT) is set, preserves 0x08.
        let pac_and_wpad = build_test_wininet_blob(
            WININET_BLOB_VERSION_V70,
            12,
            WININET_FLAG_AUTO_PROXY_URL | 0x08,
            b"",
            b"",
            b"http://127.0.0.1:8080/vdpi.pac",
            &trailing,
        );
        let cleared_pac = patch_wininet_connection_blob(&pac_and_wpad, true, false, None)
            .expect("clear PAC should succeed");
        let parsed_clear = parse_wininet_connection_blob(&cleared_pac).expect("parsed");
        assert_eq!(parsed_clear.counter, 13);
        assert_eq!(parsed_clear.flags, WININET_FLAG_DIRECT | 0x08);
        assert!(parsed_clear.pac_bytes.is_empty());
        assert_eq!(parsed_clear.trailing, &trailing);

        // 3. Clear manual proxy on a v0x3C blob with wrapping counter (u32::MAX -> 0):
        //    clears 0x02, empties proxy_bytes and bypass_bytes, sets 0x01, preserves version 0x3C.
        let legacy_manual = build_test_wininet_blob(
            WININET_BLOB_VERSION_V60,
            u32::MAX,
            WININET_FLAG_PROXY,
            b"127.0.0.1:8080",
            b"localhost;<local>",
            b"",
            &trailing[..8],
        );
        let cleared_manual = patch_wininet_connection_blob(&legacy_manual, false, true, None)
            .expect("clear manual should succeed");
        let parsed_manual = parse_wininet_connection_blob(&cleared_manual).expect("parsed");
        assert_eq!(parsed_manual.version, WININET_BLOB_VERSION_V60);
        assert_eq!(parsed_manual.counter, 0);
        assert_eq!(parsed_manual.flags, WININET_FLAG_DIRECT);
        assert!(parsed_manual.proxy_bytes.is_empty());
        assert!(parsed_manual.bypass_bytes.is_empty());
        assert_eq!(parsed_manual.trailing, &trailing[..8]);

        // 4. Malformed blobs return None safely without panicking.
        assert!(patch_wininet_connection_blob(&[], true, true, None).is_none());
        assert!(patch_wininet_connection_blob(&[0x46, 0, 0, 0, 1, 0, 0, 0], true, false, None)
            .is_none());
        let bad_version = build_test_wininet_blob(0x99, 1, 1, b"", b"", b"", &[]);
        assert!(patch_wininet_connection_blob(&bad_version, true, false, None).is_none());
        let mut overflow_len = Vec::new();
        overflow_len.extend_from_slice(&WININET_BLOB_VERSION_V70.to_le_bytes());
        overflow_len.extend_from_slice(&1u32.to_le_bytes());
        overflow_len.extend_from_slice(&WININET_FLAG_PROXY.to_le_bytes());
        overflow_len.extend_from_slice(&u32::MAX.to_le_bytes());
        overflow_len.extend_from_slice(&[0u8; 16]);
        assert!(patch_wininet_connection_blob(&overflow_len, true, true, None).is_none());
        let mut truncated_pac = build_test_wininet_blob(
            WININET_BLOB_VERSION_V70,
            1,
            WININET_FLAG_AUTO_PROXY_URL,
            b"",
            b"",
            b"http://127.0.0.1:8080/vdpi.pac",
            &[],
        );
        truncated_pac.truncate(truncated_pac.len() - 5);
        assert!(patch_wininet_connection_blob(&truncated_pac, true, false, None).is_none());
    }

    #[test]
    fn no_proxy_ownership_detects_vdpi_baseline_markers_only() {
        assert!(is_vdpi_owned_no_proxy_env(
            "localhost,127.0.0.1,100.64.0.0/10,fc00::/7,fe80::/10,.home.arpa"
        ));
        assert!(is_vdpi_owned_no_proxy_env(
            "localhost;100.64.*;*.ts.net;paratika.com.tr"
        ));
        assert!(!is_vdpi_owned_no_proxy_env("localhost,127.0.0.1,.corp.local"));
        assert!(!is_vdpi_owned_no_proxy_env(""));
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

    #[test]
    fn add_dir_to_windows_system_path_aborts_on_query_error_without_overwriting() {
        let mut wrote = false;
        let res = add_dir_to_windows_system_path_with(
            Path::new(r"C:\Program Files\vdpi\bin"),
            || Err(anyhow::anyhow!("simulated Win32 ERROR_ACCESS_DENIED (5)")),
            |_, _| {
                wrote = true;
                Ok(())
            },
        );
        assert!(
            res.is_err(),
            "query failure must abort System Path update rather than wiping Path"
        );
        assert!(
            !wrote,
            "write callback must never be invoked when querying System Path fails"
        );
    }

    #[test]
    fn add_dir_to_windows_system_path_appends_handles_not_found_and_guards_truncation() {
        // Existing REG_EXPAND_SZ Path: appends cleanly and preserves REG_EXPAND_SZ.
        let mut written = None;
        let added = add_dir_to_windows_system_path_with(
            Path::new(r"C:\Program Files\vdpi\bin\"),
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Windows\System32;C:\Windows".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |new_path, kind| {
                written = Some((new_path.to_string(), kind));
                Ok(())
            },
        )
        .expect("append to existing Path");
        assert!(added);
        assert_eq!(
            written,
            Some((
                r"C:\Windows\System32;C:\Windows;C:\Program Files\vdpi\bin".to_string(),
                RegStringKind::ExpandSz,
            ))
        );

        // Existing REG_SZ Path without '%': preserves REG_SZ and non-ASCII entries.
        let mut written_sz = None;
        let added_sz = add_dir_to_windows_system_path_with(
            Path::new(r"C:\Program Files\vdpi\bin"),
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Kullanıcılar\Ömer\Araçlar".into(),
                    kind: RegStringKind::Sz,
                })
            },
            |new_path, kind| {
                written_sz = Some((new_path.to_string(), kind));
                Ok(())
            },
        )
        .expect("append to existing REG_SZ Path");
        assert!(added_sz);
        assert_eq!(
            written_sz,
            Some((
                r"C:\Kullanıcılar\Ömer\Araçlar;C:\Program Files\vdpi\bin".to_string(),
                RegStringKind::Sz,
            ))
        );

        // Already present (case-insensitive): no-op without writing.
        let mut wrote_duplicate = false;
        let added_dup = add_dir_to_windows_system_path_with(
            Path::new(r"c:\program files\vdpi\bin"),
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Windows\System32;C:\Program Files\vdpi\bin".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |_, _| {
                wrote_duplicate = true;
                Ok(())
            },
        )
        .expect("duplicate Path check");
        assert!(!added_dup);
        assert!(!wrote_duplicate);

        // Genuinely absent Path value (NotFound): initializes with target directory as REG_EXPAND_SZ.
        let mut written_new = None;
        let added_new = add_dir_to_windows_system_path_with(
            Path::new(r"C:\Program Files\vdpi\bin"),
            || Ok(RegQueryOutcome::NotFound),
            |new_path, kind| {
                written_new = Some((new_path.to_string(), kind));
                Ok(())
            },
        )
        .expect("initialize absent Path");
        assert!(added_new);
        assert_eq!(
            written_new,
            Some((
                r"C:\Program Files\vdpi\bin".to_string(),
                RegStringKind::ExpandSz,
            ))
        );

        // Defensive sanity guard: refuse to write if computed Path is shorter than existing Path.
        let mut wrote_short = false;
        let short_res = add_dir_to_windows_system_path_with(
            Path::new(r"C:\a"),
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Windows;;;;;;;;;;;;;;;;;;;;".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |_, _| {
                wrote_short = true;
                Ok(())
            },
        );
        assert!(
            short_res.is_err(),
            "sanity guard must refuse to write a Path shorter than existing Path"
        );
        assert!(!wrote_short);
    }

    #[test]
    fn add_dir_to_windows_system_path_rejects_empty_dir_and_propagates_write_errors() {
        for empty in [Path::new(""), Path::new("   "), Path::new(r"\\\")] {
            let mut queried = false;
            let mut wrote = false;
            let res = add_dir_to_windows_system_path_with(
                empty,
                || {
                    queried = true;
                    Ok(RegQueryOutcome::NotFound)
                },
                |_, _| {
                    wrote = true;
                    Ok(())
                },
            );
            assert!(
                res.is_err(),
                "empty/whitespace/slash-only target dir {empty:?} must be rejected"
            );
            assert!(
                !queried,
                "query callback must not run for invalid empty dir {empty:?}"
            );
            assert!(
                !wrote,
                "write callback must not run for invalid empty dir {empty:?}"
            );
        }

        let write_err = add_dir_to_windows_system_path_with(
            Path::new(r"C:\Program Files\vdpi\bin"),
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Windows\System32".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |_, _| Err(anyhow::anyhow!("simulated RegSetValueExW access denied")),
        );
        assert!(
            write_err.is_err(),
            "write callback failure must propagate as Err"
        );
    }

    #[test]
    fn decode_reg_utf16_bytes_handles_odd_bytes_interior_and_trailing_nul_and_non_ascii() {
        // Odd byte length is rejected.
        assert!(decode_reg_utf16_bytes(&[0x41]).is_err());
        assert!(decode_reg_utf16_bytes(&[0x41, 0x00, 0x42]).is_err());

        // Empty buffer decodes to empty string.
        assert_eq!(decode_reg_utf16_bytes(&[]).expect("empty buffer"), "");

        // Trailing NULs (single and multiple) are stripped.
        let trailing_nul: Vec<u8> = "C:\\Windows"
            .encode_utf16()
            .chain([0u16, 0u16])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            decode_reg_utf16_bytes(&trailing_nul).expect("trailing NUL"),
            r"C:\Windows"
        );

        // Interior NUL truncates at the FIRST 0 code unit so trailing garbage never leaks through.
        let interior_nul: Vec<u8> = "C:\\Windows"
            .encode_utf16()
            .chain([0u16])
            .chain("GARBAGE\\TRAILING".encode_utf16())
            .chain([0u16])
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(
            decode_reg_utf16_bytes(&interior_nul).expect("interior NUL truncation"),
            r"C:\Windows"
        );

        // Non-ASCII UTF-16LE (Turkish, CJK, and astral surrogate pair) round-trips losslessly.
        let non_ascii = r"C:\Kullanıcılar\Ömer\İstanbul;D:\日本語\ツール;E:\🚀\bin";
        let encoded = encode_reg_utf16_bytes(non_ascii);
        assert_eq!(encoded.len(), (non_ascii.encode_utf16().count() + 1) * 2);
        assert_eq!(&encoded[encoded.len() - 2..], &[0, 0]);
        assert_eq!(
            decode_reg_utf16_bytes(&encoded).expect("non-ASCII UTF-16LE"),
            non_ascii
        );
    }

    #[test]
    fn split_reg_key_path_supports_hklm_hkcu_and_hku_sid_keys() {
        assert_eq!(
            split_reg_key_path(SYSTEM_ENV_KEY).expect("HKLM system env key"),
            (RegHive::LocalMachine, SYSTEM_ENV_SUBKEY)
        );
        assert_eq!(
            split_reg_key_path(r"HKEY_LOCAL_MACHINE\SYSTEM\Test").expect("HKEY_LOCAL_MACHINE"),
            (RegHive::LocalMachine, r"SYSTEM\Test")
        );
        assert_eq!(
            split_reg_key_path(r"HKCU\Environment").expect("HKCU env key"),
            (RegHive::CurrentUser, "Environment")
        );
        assert_eq!(
            split_reg_key_path(r"HKEY_CURRENT_USER\Environment").expect("HKEY_CURRENT_USER"),
            (RegHive::CurrentUser, "Environment")
        );
        assert_eq!(
            split_reg_key_path(r"HKU\S-1-5-21-123456-1001\Environment").expect("HKU SID env key"),
            (RegHive::Users, r"S-1-5-21-123456-1001\Environment")
        );
        assert_eq!(
            split_reg_key_path(r"HKEY_USERS\S-1-5-21-123456-1001\Environment")
                .expect("HKEY_USERS SID env key"),
            (RegHive::Users, r"S-1-5-21-123456-1001\Environment")
        );
        assert!(split_reg_key_path("HKCU").is_err());
        assert!(split_reg_key_path(r"HKCU\").is_err());
        assert!(split_reg_key_path(r"HKCR\Environment").is_err());
    }

    #[test]
    fn remove_from_env_path_key_with_handles_case_backslash_expand_sz_and_absent() {
        // Case-insensitive removal with trailing backslash, preserving REG_EXPAND_SZ even
        // when the remaining Path contains no '%' characters, and preserving non-ASCII entries.
        let mut written = None;
        let removed = remove_from_env_path_key_with(
            &[Path::new(r"C:\Program Files\VDPI\Bin\")],
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Kullanıcılar\Ömer\bin;c:\program files\vdpi\bin\;D:\Tools".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |new_path, kind| {
                written = Some((new_path.to_string(), kind));
                Ok(())
            },
        )
        .expect("case-insensitive removal with trailing backslash");
        assert!(removed);
        assert_eq!(
            written,
            Some((
                r"C:\Kullanıcılar\Ömer\bin;D:\Tools".to_string(),
                RegStringKind::ExpandSz,
            ))
        );

        // Preserves REG_SZ when original was REG_SZ and remaining Path has no '%'.
        let mut written_sz = None;
        let removed_sz = remove_from_env_path_key_with(
            &[Path::new(r"C:\vdpi\bin")],
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Tools;C:\VDPI\BIN\".into(),
                    kind: RegStringKind::Sz,
                })
            },
            |new_path, kind| {
                written_sz = Some((new_path.to_string(), kind));
                Ok(())
            },
        )
        .expect("removal preserving REG_SZ");
        assert!(removed_sz);
        assert_eq!(written_sz, Some((r"C:\Tools".to_string(), RegStringKind::Sz)));

        // No-op when target directory is absent from Path.
        let mut wrote_absent = false;
        let removed_absent = remove_from_env_path_key_with(
            &[Path::new(r"C:\Program Files\vdpi\bin")],
            || {
                Ok(RegQueryOutcome::Value {
                    value: r"C:\Windows\System32;C:\Windows".into(),
                    kind: RegStringKind::ExpandSz,
                })
            },
            |_, _| {
                wrote_absent = true;
                Ok(())
            },
        )
        .expect("no-op when dir absent");
        assert!(!removed_absent);
        assert!(!wrote_absent);

        // No-op when Path registry value does not exist.
        let mut wrote_not_found = false;
        let removed_not_found = remove_from_env_path_key_with(
            &[Path::new(r"C:\Program Files\vdpi\bin")],
            || Ok(RegQueryOutcome::NotFound),
            |_, _| {
                wrote_not_found = true;
                Ok(())
            },
        )
        .expect("no-op when Path value NotFound");
        assert!(!removed_not_found);
        assert!(!wrote_not_found);

        // Query error aborts without writing.
        let mut wrote_on_err = false;
        let err_res = remove_from_env_path_key_with(
            &[Path::new(r"C:\Program Files\vdpi\bin")],
            || Err(anyhow::anyhow!("simulated RegQueryValueExW access denied")),
            |_, _| {
                wrote_on_err = true;
                Ok(())
            },
        );
        assert!(err_res.is_err());
        assert!(!wrote_on_err);
    }

    #[test]
    fn known_folder_path_validation_accepts_local_drives_and_rejects_unc_traversal_and_reparse() {
        for valid in [
            r"C:\Program Files",
            r"D:\ProgramData",
            "E:/ProgramData",
            r"c:\Program Files",
        ] {
            assert!(
                is_valid_windows_known_folder_path_str(valid),
                "expected valid local known folder path: {valid:?}"
            );
        }

        for invalid in [
            "",
            "   ",
            r"\\attacker\share",
            "//attacker/share",
            r"\\?\C:\ProgramData",
            r"\\.\C:\ProgramData",
            r"C:\ProgramData\..\Windows",
            "C:/ProgramData/../Windows",
            "ProgramData",
            "C:",
            "C:ProgramData",
            r"C:\",
            "C:\\Program\0Data",
        ] {
            assert!(
                !is_valid_windows_known_folder_path_str(invalid),
                "expected invalid known folder path to be rejected: {invalid:?}"
            );
        }

        let root = TestTempDir::new("known-folder-reparse");
        let target_dir = root.0.join("target");
        fs::create_dir_all(&target_dir).expect("create target dir");

        let junction_dir = root.0.join("junction");
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

        assert!(has_reparse_point_component(&junction_dir));
        assert!(!has_reparse_point_component(&target_dir));
        assert_eq!(
            validate_known_folder_candidate(Some(junction_dir), r"C:\ProgramData"),
            PathBuf::from(r"C:\ProgramData")
        );
        assert_eq!(
            validate_known_folder_candidate(
                Some(PathBuf::from(r"\\attacker\ProgramData")),
                r"C:\ProgramData"
            ),
            PathBuf::from(r"C:\ProgramData")
        );
        assert_eq!(
            validate_known_folder_candidate(None, r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files")
        );
        assert_eq!(
            validate_known_folder_candidate(Some(target_dir.clone()), r"C:\ProgramData"),
            target_dir
        );
    }

    #[test]
    fn known_program_files_and_program_data_dirs_resolve_valid_local_non_reparse_paths() {
        let pf = known_program_files_dir();
        let pd = known_program_data_dir();

        for (label, dir) in [("ProgramFiles", &pf), ("ProgramData", &pd)] {
            let text = dir
                .to_str()
                .unwrap_or_else(|| panic!("{label} path must be valid UTF-8: {dir:?}"));
            assert!(
                is_valid_windows_known_folder_path_str(text),
                "{label} path must be a validated local drive path: {text:?}"
            );
            assert!(dir.is_absolute(), "{label} path must be absolute: {dir:?}");
            assert!(
                dir.is_dir(),
                "{label} resolved directory must exist: {dir:?}"
            );
            assert!(
                !has_reparse_point_component(dir),
                "{label} resolved directory must not be or traverse a reparse point: {dir:?}"
            );
        }

        assert_eq!(programdata_vdpi_dir(), pd.join("vdpi"));
    }
}
