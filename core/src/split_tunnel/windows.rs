//! Windows desktop application discovery and socket-to-process resolution
//! for per-application split tunneling.
//!
//! - **Running processes**: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` +
//!   `Process32FirstW`/`Process32NextW`, enriched with full image paths via
//!   `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW`.
//! - **Installed apps**: Windows Registry `Uninstall` hives (HKLM 64-bit, HKLM
//!   WOW6432Node, HKCU) plus well-known `%LOCALAPPDATA%` / `%APPDATA%` /
//!   `%ProgramFiles%` installation layouts (Discord, Roblox, Telegram, Spotify,
//!   browsers, game launchers, etc.).
//! - **Socket-to-process lookup**: `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`)
//!   and `GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`) for both `AF_INET` and
//!   `AF_INET6`, with bounded `ERROR_INSUFFICIENT_BUFFER` retries and zero handle leaks.

use super::{AppCategory, DiscoveredApp};
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_CURRENT_USER,
    HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD, REG_EXPAND_SZ, REG_SZ, REG_VALUE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Maximum retries when `GetExtendedTcpTable`/`GetExtendedUdpTable` grows between
/// size-query and data-fetch calls (`ERROR_INSUFFICIENT_BUFFER`).
const MAX_TABLE_RETRIES: usize = 3;

/// Extra byte headroom added on table buffer allocations to avoid resize races.
const TABLE_BUFFER_HEADROOM: usize = 4096;

/// Upper bound on Registry Uninstall subkeys enumerated per hive.
const MAX_UNINSTALL_SUBKEYS: u32 = 4096;

/// Upper bound on versioned subdirectories scanned for `%LOCALAPPDATA%` apps.
const MAX_VERSION_SUBDIRS: usize = 64;

/// Windows OS internals, background hosts, and vdpi binaries excluded from app discovery.
const NOISE_PROCESSES: &[&str] = &[
    "applicationframehost.exe",
    "audiodg.exe",
    "backgroundtaskhost.exe",
    "compattelrunner.exe",
    "conhost.exe",
    "consent.exe",
    "crashpad_handler.exe",
    "csrss.exe",
    "ctfmon.exe",
    "dashost.exe",
    "dllhost.exe",
    "dwm.exe",
    "explorer.exe",
    "fontdrvhost.exe",
    "gamebar.exe",
    "gamebarftserver.exe",
    "gamebarpresencewriter.exe",
    "googleupdate.exe",
    "idle",
    "lockapp.exe",
    "logonui.exe",
    "lsaiso.exe",
    "lsass.exe",
    "memory compression",
    "microsoftedgeupdate.exe",
    "mpdefendercoreservice.exe",
    "msedgewebview2.exe",
    "msiexec.exe",
    "msmpeng.exe",
    "musnotifyicon.exe",
    "nissrv.exe",
    "openconsole.exe",
    "phoneexperiencehost.exe",
    "registry",
    "runtimebroker.exe",
    "searchapp.exe",
    "searchfilterhost.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "secure system",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "services.exe",
    "sgrmbroker.exe",
    "shellexperiencehost.exe",
    "sihclient.exe",
    "sihost.exe",
    "smartscreen.exe",
    "smss.exe",
    "spoolsv.exe",
    "sppsvc.exe",
    "startmenuexperiencehost.exe",
    "svchost.exe",
    "system",
    "system idle process",
    "taskhostw.exe",
    "textinputhost.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "uhssvc.exe",
    "usocoreworker.exe",
    "vdpi-service.exe",
    "vdpi.exe",
    "vssvc.exe",
    "waasmedicagent.exe",
    "werfault.exe",
    "wermgr.exe",
    "widgets.exe",
    "widgetservice.exe",
    "wininit.exe",
    "winlogon.exe",
    "wmiprvse.exe",
    "wuauclt.exe",
    "wudfhost.exe",
];

/// Anti-cheat service executables that we avoid opening process handles against
/// during passive app discovery.
const ANTICHEAT_PROCESSES: &[&str] = &[
    "bedaisy.exe",
    "beservice.exe",
    "easyanticheat.exe",
    "easyanticheat_eos.exe",
    "vgc.exe",
    "vgtray.exe",
];

/// Generic installer/uninstaller/updater executables ignored when parsing Registry
/// `Uninstall` entries.
const INSTALLER_EXES: &[&str] = &[
    "crashhandler.exe",
    "crashpad_handler.exe",
    "elevate.exe",
    "helper.exe",
    "install.exe",
    "installer.exe",
    "maintenancetool.exe",
    "msiexec.exe",
    "setup.exe",
    "squirrel.exe",
    "unins000.exe",
    "unins001.exe",
    "uninst.exe",
    "uninstall.exe",
    "update.exe",
    "updater.exe",
];

/// Substrings in Registry `DisplayName` identifying OS runtimes/updates rather than apps.
const NOISE_DISPLAY_NAME_TOKENS: &[&str] = &[
    ".net desktop runtime",
    ".net host",
    ".net runtime",
    ".net sdk",
    "hotfix for ",
    "microsoft edge webview2",
    "microsoft visual c++",
    "redistributable",
    "security update for ",
    "update for ",
    "windows app runtime",
    "windows sdk",
    "windows software development kit",
];

/// RAII wrapper for Win32 `HANDLE` values ensuring `CloseHandle` is always called.
struct HandleGuard(HANDLE);

impl HandleGuard {
    fn new(handle: HANDLE) -> Option<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Self(handle))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is a valid, owned Win32 handle obtained from
            // `CreateToolhelp32Snapshot` or `OpenProcess` and closed exactly once here.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// RAII wrapper for Win32 `HKEY` handles ensuring `RegCloseKey` is always called.
struct RegKeyGuard(HKEY);

impl RegKeyGuard {
    fn open(root: HKEY, subkey: &str) -> Option<Self> {
        let wide = encode_wide_nul(subkey);
        let mut hkey: HKEY = std::ptr::null_mut();
        // SAFETY: `root` is a valid predefined or open HKEY, `wide` is NUL-terminated
        // UTF-16, and `hkey` is a valid aligned out-pointer.
        let status = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_READ, &mut hkey) };
        if status == ERROR_SUCCESS && !hkey.is_null() {
            Some(Self(hkey))
        } else {
            None
        }
    }

    fn raw(&self) -> HKEY {
        self.0
    }
}

impl Drop for RegKeyGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was successfully opened via `RegOpenKeyExW` and is
            // closed exactly once on drop.
            unsafe {
                let _ = RegCloseKey(self.0);
            }
        }
    }
}

fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn decode_wide_nul(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

fn is_noise_process_name(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    if lower.is_empty()
        || lower.starts_with('[')
        || lower.ends_with(']')
        || matches!(
            lower.as_str(),
            "aggregatorhost.exe"
                | "gamingservices.exe"
                | "gamingservicesnet.exe"
                | "gameinputrawinputproxy.exe"
                | "gameinputredistservice.exe"
                | "crossdeviceservice.exe"
                | "amdfendrsr.exe"
                | "amdppkgsvc.exe"
                | "hapticservice.exe"
                | "discordsystemhelper.exe"
        )
    {
        return true;
    }
    NOISE_PROCESSES.contains(&lower.as_str())
}

fn is_anticheat_process_name(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    ANTICHEAT_PROCESSES.contains(&lower.as_str())
}

fn is_windows_system_path(path: &str) -> bool {
    let normalized = path.trim().replace('/', "\\").to_ascii_lowercase();
    let windir = std::env::var("WINDIR")
        .or_else(|_| std::env::var("SystemRoot"))
        .unwrap_or_else(|_| r"C:\Windows".to_string())
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();

    const SYSTEM_SUBDIRS: &[&str] = &[
        r"\system32\",
        r"\syswow64\",
        r"\systemapps\",
        r"\winsxs\",
        r"\servicing\",
        r"\immersivecontrolpanel\",
    ];

    SYSTEM_SUBDIRS
        .iter()
        .any(|sub| normalized.starts_with(&format!("{windir}{sub}")))
}

fn is_installer_or_noise_exe(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    if lower.is_empty() || !lower.ends_with(".exe") {
        return true;
    }
    if NOISE_PROCESSES.contains(&lower.as_str()) || INSTALLER_EXES.contains(&lower.as_str()) {
        return true;
    }
    lower.starts_with("unins") || lower.contains("uninstall")
}

fn is_noise_display_name(display_name: &str) -> bool {
    let lower = display_name.trim().to_ascii_lowercase();
    lower.is_empty()
        || NOISE_DISPLAY_NAME_TOKENS
            .iter()
            .any(|token| lower.contains(token))
}

fn default_display_name(exe_name: &str) -> String {
    if let Some(pop) = super::popular_app_display_name(exe_name) {
        return pop.to_string();
    }
    let trimmed = exe_name.trim();
    if trimmed.len() > 4 && trimmed[trimmed.len() - 4..].eq_ignore_ascii_case(".exe") {
        trimmed[..trimmed.len() - 4].to_string()
    } else {
        trimmed.to_string()
    }
}

fn query_process_image_path(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // SAFETY: `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` is read-only
    // metadata access; returned handle is immediately wrapped in `HandleGuard`.
    let guard =
        HandleGuard::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;

    for &capacity in &[1024usize, 4096usize, 32768usize] {
        let mut buf = vec![0u16; capacity];
        let mut len = buf.len() as u32;
        // SAFETY: `guard.raw()` is a valid process handle, `buf` is writable for `len`
        // `u16` elements, and `len` is initialized to the buffer capacity in characters.
        let ok = unsafe {
            QueryFullProcessImageNameW(guard.raw(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
        };
        if ok != 0 {
            let actual = (len as usize).min(buf.len());
            let path = String::from_utf16_lossy(&buf[..actual]);
            let trimmed = path.trim();
            return if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        // SAFETY: `GetLastError` reads the calling thread's last Win32 error code.
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            break;
        }
    }
    None
}

fn toolhelp_exe_name_for_pid(target_pid: u32) -> Option<String> {
    if target_pid == 0 {
        return None;
    }
    // SAFETY: `CreateToolhelp32Snapshot` returns a snapshot handle or `INVALID_HANDLE_VALUE`,
    // wrapped in `HandleGuard` so it is always closed.
    let snapshot = HandleGuard::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;

    // SAFETY: `PROCESSENTRY32W` is a plain C struct; `dwSize` is set before calling Win32.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: `snapshot.raw()` is valid and `entry` has `dwSize` properly initialized.
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) } == 0 {
        return None;
    }

    loop {
        if entry.th32ProcessID == target_pid {
            let name = decode_wide_nul(&entry.szExeFile);
            let trimmed = name.trim();
            return if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        // SAFETY: `snapshot.raw()` is valid and `entry` remains initialized.
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
            break;
        }
    }
    None
}

/// Resolves a Windows process ID to its executable filename (e.g. `"Discord.exe"`).
fn pid_to_exe_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if let Some(full_path) = query_process_image_path(pid) {
        if let Some(file_name) = Path::new(&full_path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::trim)
            .filter(|n| !n.is_empty())
        {
            return Some(file_name.to_string());
        }
    }
    // Fallback for elevated/protected processes where `OpenProcess` returns ACCESS_DENIED.
    toolhelp_exe_name_for_pid(pid)
}

fn discover_running_processes() -> Vec<DiscoveredApp> {
    // SAFETY: `CreateToolhelp32Snapshot` returns a snapshot handle wrapped in `HandleGuard`.
    let Some(snapshot) =
        HandleGuard::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })
    else {
        return Vec::new();
    };

    // SAFETY: `PROCESSENTRY32W` is a plain C struct; `dwSize` is initialized before FFI use.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    // SAFETY: `snapshot.raw()` is a valid snapshot handle and `entry.dwSize` is set.
    if unsafe { Process32FirstW(snapshot.raw(), &mut entry) } == 0 {
        return Vec::new();
    }

    // Deduplicate by lowercase exe name first so multi-process apps (Chrome, Discord,
    // Electron) only trigger a single `QueryFullProcessImageNameW` call.
    let mut by_exe: HashMap<String, (String, u32)> = HashMap::new();
    loop {
        let exe_name = decode_wide_nul(&entry.szExeFile);
        let trimmed = exe_name.trim();
        if !trimmed.is_empty() && !is_noise_process_name(trimmed) {
            let key = trimmed.to_ascii_lowercase();
            by_exe
                .entry(key)
                .or_insert_with(|| (trimmed.to_string(), entry.th32ProcessID));
        }

        // SAFETY: `snapshot.raw()` is valid and `entry` remains initialized.
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
            break;
        }
    }

    let mut apps = Vec::with_capacity(by_exe.len());
    for (exe_name, pid) in by_exe.into_values() {
        let path = if is_anticheat_process_name(&exe_name) {
            None
        } else {
            query_process_image_path(pid)
        };

        if let Some(ref full_path) = path {
            if is_windows_system_path(full_path) && !super::is_popular_app(&exe_name) {
                continue;
            }
        }

        let display_name = default_display_name(&exe_name);
        apps.push(DiscoveredApp {
            display_name,
            exe_name,
            path,
            is_running: true,
            category: AppCategory::Running,
        });
    }

    apps
}

fn read_reg_string(hkey: HKEY, value_name: &str) -> Option<String> {
    let wide_name = encode_wide_nul(value_name);
    let mut reg_type: REG_VALUE_TYPE = 0;
    let mut buf = vec![0u16; 260];
    let mut cb_data = (buf.len() * std::mem::size_of::<u16>()) as u32;

    // SAFETY: `hkey` is an open registry key handle, `wide_name` is NUL-terminated UTF-16,
    // and `buf` is a valid writable buffer of `cb_data` bytes.
    let mut status = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut reg_type,
            buf.as_mut_ptr().cast::<u8>(),
            &mut cb_data,
        )
    };

    if status == ERROR_MORE_DATA && cb_data > 0 && cb_data <= 65_536 {
        let needed_u16 = (cb_data as usize).div_ceil(std::mem::size_of::<u16>());
        buf.resize(needed_u16, 0);
        cb_data = (buf.len() * std::mem::size_of::<u16>()) as u32;
        // SAFETY: `buf` has been resized to cover `cb_data` bytes.
        status = unsafe {
            RegQueryValueExW(
                hkey,
                wide_name.as_ptr(),
                std::ptr::null(),
                &mut reg_type,
                buf.as_mut_ptr().cast::<u8>(),
                &mut cb_data,
            )
        };
    }

    if status != ERROR_SUCCESS || (reg_type != REG_SZ && reg_type != REG_EXPAND_SZ) {
        return None;
    }

    let u16_count = ((cb_data as usize) / std::mem::size_of::<u16>()).min(buf.len());
    let text = decode_wide_nul(&buf[..u16_count]);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn read_reg_dword(hkey: HKEY, value_name: &str) -> Option<u32> {
    let wide_name = encode_wide_nul(value_name);
    let mut reg_type: REG_VALUE_TYPE = 0;
    let mut value: u32 = 0;
    let mut cb_data = std::mem::size_of::<u32>() as u32;

    // SAFETY: `hkey` is an open registry key handle, `wide_name` is NUL-terminated UTF-16,
    // and `&mut value` is a valid 4-byte writable buffer.
    let status = unsafe {
        RegQueryValueExW(
            hkey,
            wide_name.as_ptr(),
            std::ptr::null(),
            &mut reg_type,
            (&mut value as *mut u32).cast::<u8>(),
            &mut cb_data,
        )
    };

    if status == ERROR_SUCCESS
        && reg_type == REG_DWORD
        && cb_data == std::mem::size_of::<u32>() as u32
    {
        Some(value)
    } else {
        None
    }
}

fn expand_common_env_vars(raw: &str) -> String {
    if !raw.contains('%') {
        return raw.to_string();
    }
    let mut out = raw.to_string();
    const VARS: &[&str] = &[
        "LOCALAPPDATA",
        "APPDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PROGRAMDATA",
        "USERPROFILE",
        "WINDIR",
        "SYSTEMROOT",
    ];
    for var in VARS {
        let needle = format!("%{var}%");
        if let Some(pos) = out.to_ascii_lowercase().find(&needle.to_ascii_lowercase()) {
            if let Ok(val) = std::env::var(var) {
                out.replace_range(pos..pos + needle.len(), &val);
            }
        }
    }
    out
}

/// Cleans a Windows Registry `DisplayIcon` string (stripping quotes and `,0` / `,-101`
/// icon resource indices) and returns `(exe_name, full_path)` if it refers to a
/// non-installer `.exe` file.
fn parse_display_icon_exe(raw: &str) -> Option<(String, String)> {
    let mut cleaned = raw.trim();
    if cleaned.is_empty() {
        return None;
    }

    // Handle `"C:\Path\App.exe",0` or `"C:\Path\App.exe,0"`.
    if let Some(rest) = cleaned.strip_prefix('"') {
        if let Some(close_idx) = rest.find('"') {
            let after_quote = rest[close_idx + 1..].trim();
            if after_quote.is_empty() || after_quote.starts_with(',') {
                cleaned = rest[..close_idx].trim();
            }
        }
    }

    // Strip trailing icon index `,0`, `,1`, `,-101` without breaking paths containing commas.
    if let Some((before_comma, after_comma)) = cleaned.rsplit_once(',') {
        let idx_str = after_comma.trim();
        if !idx_str.is_empty() && idx_str.parse::<i32>().is_ok() {
            cleaned = before_comma.trim();
        }
    }

    cleaned = cleaned.trim_matches('"').trim();
    if cleaned.is_empty() {
        return None;
    }

    let expanded = expand_common_env_vars(cleaned);
    let path = Path::new(&expanded);
    let file_name = path.file_name()?.to_str()?.trim();
    if is_installer_or_noise_exe(file_name) || is_windows_system_path(&expanded) {
        return None;
    }

    Some((file_name.to_string(), expanded))
}

fn find_exe_in_install_location(install_dir: &str, display_name: &str) -> Option<(String, String)> {
    let expanded = expand_common_env_vars(install_dir.trim().trim_matches('"'));
    let dir = Path::new(&expanded);
    if !dir.is_dir() || is_windows_system_path(&expanded) {
        return None;
    }

    let entries = std::fs::read_dir(dir).ok()?;
    let display_lower = display_name.trim().to_ascii_lowercase();
    let mut candidates: Vec<(String, String)> = Vec::new();

    for entry in entries.take(64).flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_installer_or_noise_exe(name) {
            continue;
        }
        let stem = name[..name.len() - 4].to_ascii_lowercase();
        let full = path.to_string_lossy().into_owned();
        if !stem.is_empty()
            && (display_lower == stem
                || display_lower.contains(&stem)
                || super::is_popular_app(name))
        {
            return Some((name.to_string(), full));
        }
        candidates.push((name.to_string(), full));
    }

    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
    }
}

fn discover_registry_uninstall_apps() -> Vec<DiscoveredApp> {
    const ROOTS: &[(HKEY, &str)] = &[
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (
            HKEY_CURRENT_USER,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
    ];

    let mut apps = Vec::new();
    let mut name_buf = vec![0u16; 260];

    for &(hive, subkey_path) in ROOTS {
        let Some(parent) = RegKeyGuard::open(hive, subkey_path) else {
            continue;
        };

        for index in 0..MAX_UNINSTALL_SUBKEYS {
            let mut name_len = name_buf.len() as u32;
            // SAFETY: `parent.raw()` is a valid open HKEY and `name_buf` has capacity `name_len`.
            let status = unsafe {
                RegEnumKeyExW(
                    parent.raw(),
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };

            if status == ERROR_NO_MORE_ITEMS {
                break;
            }
            if status != ERROR_SUCCESS {
                continue;
            }

            let subkey_name =
                String::from_utf16_lossy(&name_buf[..(name_len as usize).min(name_buf.len())]);
            let Some(subkey) = RegKeyGuard::open(parent.raw(), &subkey_name) else {
                continue;
            };

            if read_reg_dword(subkey.raw(), "SystemComponent") == Some(1) {
                continue;
            }

            let Some(display_name) = read_reg_string(subkey.raw(), "DisplayName") else {
                continue;
            };
            if is_noise_display_name(&display_name) {
                continue;
            }

            let resolved = read_reg_string(subkey.raw(), "DisplayIcon")
                .and_then(|icon| parse_display_icon_exe(&icon))
                .or_else(|| {
                    read_reg_string(subkey.raw(), "InstallLocation")
                        .and_then(|loc| find_exe_in_install_location(&loc, &display_name))
                });

            let Some((exe_name, exe_path)) = resolved else {
                continue;
            };

            let category = if super::is_popular_app(&exe_name) {
                AppCategory::Popular
            } else {
                AppCategory::Installed
            };

            apps.push(DiscoveredApp {
                display_name,
                exe_name,
                path: Some(exe_path),
                is_running: false,
                category,
            });
        }
    }

    apps
}

fn find_latest_versioned_exe(base_dir: &Path, dir_prefix: &str, exe_name: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(base_dir).ok()?;
    let prefix_lower = dir_prefix.to_ascii_lowercase();
    let mut matches: Vec<(String, PathBuf)> = Vec::new();

    for entry in entries.take(MAX_VERSION_SUBDIRS).flatten() {
        let dir_path = entry.path();
        if !dir_path.is_dir() {
            continue;
        }
        let Some(folder_name) = dir_path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !prefix_lower.is_empty() && !folder_name.to_ascii_lowercase().starts_with(&prefix_lower)
        {
            continue;
        }
        let candidate = dir_path.join(exe_name);
        if candidate.is_file() {
            matches.push((folder_name.to_ascii_lowercase(), candidate));
        }
    }

    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches.pop().map(|(_, path)| path)
}

fn probe_well_known_app(
    apps: &mut Vec<DiscoveredApp>,
    display_name: &str,
    exe_name: &str,
    candidate_path: PathBuf,
) {
    if !candidate_path.is_file() {
        return;
    }
    let category = if super::is_popular_app(exe_name) {
        AppCategory::Popular
    } else {
        AppCategory::Installed
    };
    apps.push(DiscoveredApp {
        display_name: display_name.to_string(),
        exe_name: exe_name.to_string(),
        path: Some(candidate_path.to_string_lossy().into_owned()),
        is_running: false,
        category,
    });
}

fn discover_well_known_apps() -> Vec<DiscoveredApp> {
    let mut apps = Vec::new();

    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let app_data = std::env::var_os("APPDATA").map(PathBuf::from);
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let program_files_x86 = std::env::var_os("ProgramFiles(x86)").map(PathBuf::from);

    if let Some(ref local) = local_app_data {
        // Squirrel / versioned `%LOCALAPPDATA%` apps (Discord, Roblox, Slack).
        for (display, folder, prefix, exe) in [
            ("Discord", "Discord", "app-", "Discord.exe"),
            ("Discord PTB", "DiscordPTB", "app-", "DiscordPTB.exe"),
            (
                "Discord Canary",
                "DiscordCanary",
                "app-",
                "DiscordCanary.exe",
            ),
            ("Roblox", r"Roblox\Versions", "", "RobloxPlayerBeta.exe"),
            ("Slack", "slack", "app-", "slack.exe"),
        ] {
            if let Some(path) = find_latest_versioned_exe(&local.join(folder), prefix, exe) {
                probe_well_known_app(&mut apps, display, exe, path);
            }
        }

        // Direct `%LOCALAPPDATA%` user-scope installs.
        for (display, rel, exe) in [
            (
                "Visual Studio Code",
                r"Programs\Microsoft VS Code\Code.exe",
                "Code.exe",
            ),
            (
                "Google Chrome",
                r"Google\Chrome\Application\chrome.exe",
                "chrome.exe",
            ),
            (
                "Brave Browser",
                r"BraveSoftware\Brave-Browser\Application\brave.exe",
                "brave.exe",
            ),
            ("Opera", r"Programs\Opera\opera.exe", "opera.exe"),
            ("Opera GX", r"Programs\Opera GX\opera.exe", "opera.exe"),
            ("Vivaldi", r"Vivaldi\Application\vivaldi.exe", "vivaldi.exe"),
            (
                "Signal",
                r"Programs\signal-desktop\Signal.exe",
                "Signal.exe",
            ),
            (
                "Spotify",
                r"Microsoft\WindowsApps\Spotify.exe",
                "Spotify.exe",
            ),
        ] {
            probe_well_known_app(&mut apps, display, exe, local.join(rel));
        }
    }

    if let Some(ref roaming) = app_data {
        for (display, rel, exe) in [
            ("Telegram", r"Telegram Desktop\Telegram.exe", "Telegram.exe"),
            ("Spotify", r"Spotify\Spotify.exe", "Spotify.exe"),
            ("Zoom", r"Zoom\bin\Zoom.exe", "Zoom.exe"),
        ] {
            probe_well_known_app(&mut apps, display, exe, roaming.join(rel));
        }
    }

    if let Some(ref pf) = program_files {
        for (display, rel, exe) in [
            (
                "Google Chrome",
                r"Google\Chrome\Application\chrome.exe",
                "chrome.exe",
            ),
            (
                "Brave Browser",
                r"BraveSoftware\Brave-Browser\Application\brave.exe",
                "brave.exe",
            ),
            (
                "Mozilla Firefox",
                r"Mozilla Firefox\firefox.exe",
                "firefox.exe",
            ),
            (
                "Microsoft Edge",
                r"Microsoft\Edge\Application\msedge.exe",
                "msedge.exe",
            ),
            ("Steam", r"Steam\steam.exe", "steam.exe"),
            ("OBS Studio", r"obs-studio\bin\64bit\obs64.exe", "obs64.exe"),
            ("VLC Media Player", r"VideoLAN\VLC\vlc.exe", "vlc.exe"),
            (
                "qBittorrent",
                r"qBittorrent\qbittorrent.exe",
                "qbittorrent.exe",
            ),
            (
                "Visual Studio Code",
                r"Microsoft VS Code\Code.exe",
                "Code.exe",
            ),
            (
                "EA App",
                r"Electronic Arts\EA Desktop\EA Desktop\EADesktop.exe",
                "EADesktop.exe",
            ),
        ] {
            probe_well_known_app(&mut apps, display, exe, pf.join(rel));
        }
    }

    if let Some(ref pf86) = program_files_x86 {
        for (display, rel, exe) in [
            (
                "Google Chrome",
                r"Google\Chrome\Application\chrome.exe",
                "chrome.exe",
            ),
            (
                "Mozilla Firefox",
                r"Mozilla Firefox\firefox.exe",
                "firefox.exe",
            ),
            (
                "Microsoft Edge",
                r"Microsoft\Edge\Application\msedge.exe",
                "msedge.exe",
            ),
            ("Steam", r"Steam\steam.exe", "steam.exe"),
            (
                "Epic Games Launcher",
                r"Epic Games\Launcher\Portal\Binaries\Win64\EpicGamesLauncher.exe",
                "EpicGamesLauncher.exe",
            ),
            ("Battle.net", r"Battle.net\Battle.net.exe", "Battle.net.exe"),
            (
                "Minecraft Launcher",
                r"Minecraft Launcher\MinecraftLauncher.exe",
                "MinecraftLauncher.exe",
            ),
            ("VLC Media Player", r"VideoLAN\VLC\vlc.exe", "vlc.exe"),
        ] {
            probe_well_known_app(&mut apps, display, exe, pf86.join(rel));
        }
    }

    probe_well_known_app(
        &mut apps,
        "Riot Client",
        "RiotClientServices.exe",
        PathBuf::from(r"C:\Riot Games\Riot Client\RiotClientServices.exe"),
    );

    apps
}

/// Discovers running user applications and installed desktop applications on Windows.
pub(super) fn discover_platform_apps() -> Vec<DiscoveredApp> {
    let mut apps = discover_running_processes();
    apps.extend(discover_registry_uninstall_apps());
    apps.extend(discover_well_known_apps());
    apps
}

/// Fetches a variable-length IP Helper table (`GetExtendedTcpTable` or
/// `GetExtendedUdpTable`) into an 8-byte aligned buffer, retrying up to
/// [`MAX_TABLE_RETRIES`] times on `ERROR_INSUFFICIENT_BUFFER`.
fn fetch_iphlpapi_table<F>(mut fetch_fn: F) -> Option<(Vec<u64>, usize)>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
{
    let mut size: u32 = 0;
    let first = fetch_fn(std::ptr::null_mut(), &mut size);
    if first != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return None;
    }

    for _ in 0..MAX_TABLE_RETRIES {
        let alloc_bytes = (size as usize).saturating_add(TABLE_BUFFER_HEADROOM);
        let word_len = alloc_bytes.div_ceil(std::mem::size_of::<u64>()).max(1);
        let mut buf = vec![0u64; word_len];
        let mut buf_size = (buf.len() * std::mem::size_of::<u64>()) as u32;

        let status = fetch_fn(buf.as_mut_ptr().cast::<c_void>(), &mut buf_size);
        if status == NO_ERROR {
            let valid_bytes = (buf_size as usize).min(buf.len() * std::mem::size_of::<u64>());
            return Some((buf, valid_bytes));
        }
        if status == ERROR_INSUFFICIENT_BUFFER && buf_size > 0 {
            size = buf_size;
            continue;
        }
        return None;
    }

    None
}

fn lookup_tcp_v4_pid(target_ip: Ipv4Addr, local_port: u16) -> Option<u32> {
    let (buf, valid_bytes) = fetch_iphlpapi_table(|ptr, size_ptr| {
        // SAFETY: `ptr` is either null (size query) or an 8-byte aligned writable
        // buffer of `*size_ptr` bytes; `size_ptr` is a valid aligned `*mut u32`.
        unsafe {
            GetExtendedTcpTable(
                ptr,
                size_ptr,
                0,
                u32::from(AF_INET),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;

    let header_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    if valid_bytes < header_offset {
        return None;
    }

    let table_ptr = buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    // SAFETY: `buf` is 8-byte aligned (`align_of::<MIB_TCPTABLE_OWNER_PID>() == 4`)
    // and `valid_bytes >= header_offset >= size_of::<u32>()`, so reading `dwNumEntries`
    // is aligned and in-bounds.
    let declared_count = unsafe { (*table_ptr).dwNumEntries as usize };
    let max_rows = (valid_bytes - header_offset) / std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let count = declared_count.min(max_rows);

    // SAFETY: `rows_ptr` points to `count` initialized `MIB_TCPROW_OWNER_PID` entries
    // within `buf`, verified against `valid_bytes`, without creating an intermediate
    // reference to `[MIB_TCPROW_OWNER_PID; 1]`.
    let rows = unsafe {
        let rows_ptr = std::ptr::addr_of!((*table_ptr).table).cast::<MIB_TCPROW_OWNER_PID>();
        std::slice::from_raw_parts(rows_ptr, count)
    };

    let mut wildcard_pid: Option<u32> = None;
    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
        if row_ip == target_ip {
            return Some(row.dwOwningPid);
        }
        if row_ip.is_unspecified() && wildcard_pid.is_none() {
            wildcard_pid = Some(row.dwOwningPid);
        }
    }

    wildcard_pid
}

fn lookup_tcp_v6_pid(target_ip: Ipv6Addr, local_port: u16) -> Option<u32> {
    let (buf, valid_bytes) = fetch_iphlpapi_table(|ptr, size_ptr| {
        // SAFETY: `ptr` is either null (size query) or an 8-byte aligned writable
        // buffer of `*size_ptr` bytes; `size_ptr` is a valid aligned `*mut u32`.
        unsafe {
            GetExtendedTcpTable(
                ptr,
                size_ptr,
                0,
                u32::from(AF_INET6),
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        }
    })?;

    let header_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    if valid_bytes < header_offset {
        return None;
    }

    let table_ptr = buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    // SAFETY: `buf` is 8-byte aligned and `valid_bytes >= header_offset`, so reading
    // `dwNumEntries` is aligned and in-bounds.
    let declared_count = unsafe { (*table_ptr).dwNumEntries as usize };
    let max_rows = (valid_bytes - header_offset) / std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    let count = declared_count.min(max_rows);

    // SAFETY: `rows_ptr` points to `count` initialized `MIB_TCP6ROW_OWNER_PID` entries
    // within `buf`, verified against `valid_bytes`.
    let rows = unsafe {
        let rows_ptr = std::ptr::addr_of!((*table_ptr).table).cast::<MIB_TCP6ROW_OWNER_PID>();
        std::slice::from_raw_parts(rows_ptr, count)
    };

    let mut wildcard_pid: Option<u32> = None;
    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv6Addr::from(row.ucLocalAddr);
        if row_ip == target_ip {
            return Some(row.dwOwningPid);
        }
        if row_ip.is_unspecified() && wildcard_pid.is_none() {
            wildcard_pid = Some(row.dwOwningPid);
        }
    }

    wildcard_pid
}

fn lookup_udp_v4_pid(target_ip: Ipv4Addr, local_port: u16) -> Option<u32> {
    let (buf, valid_bytes) = fetch_iphlpapi_table(|ptr, size_ptr| {
        // SAFETY: `ptr` is either null (size query) or an 8-byte aligned writable
        // buffer of `*size_ptr` bytes; `size_ptr` is a valid aligned `*mut u32`.
        unsafe { GetExtendedUdpTable(ptr, size_ptr, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0) }
    })?;

    let header_offset = std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table);
    if valid_bytes < header_offset {
        return None;
    }

    let table_ptr = buf.as_ptr().cast::<MIB_UDPTABLE_OWNER_PID>();
    // SAFETY: `buf` is 8-byte aligned and `valid_bytes >= header_offset`, so reading
    // `dwNumEntries` is aligned and in-bounds.
    let declared_count = unsafe { (*table_ptr).dwNumEntries as usize };
    let max_rows = (valid_bytes - header_offset) / std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
    let count = declared_count.min(max_rows);

    // SAFETY: `rows_ptr` points to `count` initialized `MIB_UDPROW_OWNER_PID` entries
    // within `buf`, verified against `valid_bytes`.
    let rows = unsafe {
        let rows_ptr = std::ptr::addr_of!((*table_ptr).table).cast::<MIB_UDPROW_OWNER_PID>();
        std::slice::from_raw_parts(rows_ptr, count)
    };

    let mut wildcard_pid: Option<u32> = None;
    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
        if row_ip == target_ip {
            return Some(row.dwOwningPid);
        }
        if row_ip.is_unspecified() && wildcard_pid.is_none() {
            wildcard_pid = Some(row.dwOwningPid);
        }
    }

    wildcard_pid
}

fn lookup_udp_v6_pid(target_ip: Ipv6Addr, local_port: u16) -> Option<u32> {
    let (buf, valid_bytes) = fetch_iphlpapi_table(|ptr, size_ptr| {
        // SAFETY: `ptr` is either null (size query) or an 8-byte aligned writable
        // buffer of `*size_ptr` bytes; `size_ptr` is a valid aligned `*mut u32`.
        unsafe {
            GetExtendedUdpTable(
                ptr,
                size_ptr,
                0,
                u32::from(AF_INET6),
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    })?;

    let header_offset = std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table);
    if valid_bytes < header_offset {
        return None;
    }

    let table_ptr = buf.as_ptr().cast::<MIB_UDP6TABLE_OWNER_PID>();
    // SAFETY: `buf` is 8-byte aligned and `valid_bytes >= header_offset`, so reading
    // `dwNumEntries` is aligned and in-bounds.
    let declared_count = unsafe { (*table_ptr).dwNumEntries as usize };
    let max_rows = (valid_bytes - header_offset) / std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
    let count = declared_count.min(max_rows);

    // SAFETY: `rows_ptr` points to `count` initialized `MIB_UDP6ROW_OWNER_PID` entries
    // within `buf`, verified against `valid_bytes`.
    let rows = unsafe {
        let rows_ptr = std::ptr::addr_of!((*table_ptr).table).cast::<MIB_UDP6ROW_OWNER_PID>();
        std::slice::from_raw_parts(rows_ptr, count)
    };

    let mut wildcard_pid: Option<u32> = None;
    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv6Addr::from(row.ucLocalAddr);
        if row_ip == target_ip {
            return Some(row.dwOwningPid);
        }
        if row_ip.is_unspecified() && wildcard_pid.is_none() {
            wildcard_pid = Some(row.dwOwningPid);
        }
    }

    wildcard_pid
}

/// Resolves a local TCP or UDP endpoint `(local_ip, local_port, is_udp)` to the
/// owning process executable filename (e.g. `"chrome.exe"`).
pub(super) fn lookup_local_port_process(
    local_ip: IpAddr,
    local_port: u16,
    is_udp: bool,
) -> Option<String> {
    if local_port == 0 {
        return None;
    }

    let canonical = local_ip.to_canonical();
    let pid = match (canonical, is_udp) {
        (IpAddr::V4(v4), false) => lookup_tcp_v4_pid(v4, local_port)
            .or_else(|| lookup_tcp_v6_pid(v4.to_ipv6_mapped(), local_port)),
        (IpAddr::V6(v6), false) => lookup_tcp_v6_pid(v6, local_port),
        (IpAddr::V4(v4), true) => lookup_udp_v4_pid(v4, local_port)
            .or_else(|| lookup_udp_v6_pid(v4.to_ipv6_mapped(), local_port)),
        (IpAddr::V6(v6), true) => lookup_udp_v6_pid(v6, local_port),
    }?;

    pid_to_exe_name(pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    fn current_test_exe_name() -> String {
        std::env::current_exe()
            .expect("current_exe")
            .file_name()
            .expect("exe filename")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn discover_platform_apps_returns_apps_without_panicking() {
        let apps = discover_platform_apps();
        assert!(
            !apps.is_empty(),
            "expected Windows discovery to return running or installed apps"
        );
        for app in &apps {
            assert!(!app.exe_name.trim().is_empty());
            assert!(!app.display_name.trim().is_empty());
            let lower = app.exe_name.to_ascii_lowercase();
            assert_ne!(lower, "svchost.exe");
            assert_ne!(lower, "csrss.exe");
            assert_ne!(lower, "vdpi.exe");
        }
    }

    #[test]
    fn lookup_local_port_process_resolves_live_tcp_listener_and_stream() {
        let expected_exe = current_test_exe_name();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind tcp listener");
        let listen_addr = listener.local_addr().expect("listener local_addr");

        let resolved_listener =
            lookup_local_port_process(listen_addr.ip(), listen_addr.port(), false)
                .expect("should resolve bound TcpListener to current process");
        assert!(
            resolved_listener.eq_ignore_ascii_case(&expected_exe),
            "expected '{expected_exe}', got '{resolved_listener}'"
        );

        let client = TcpStream::connect(listen_addr).expect("connect tcp stream");
        let (_accepted, _) = listener.accept().expect("accept tcp stream");
        let client_addr = client.local_addr().expect("client local_addr");

        let resolved_stream =
            lookup_local_port_process(client_addr.ip(), client_addr.port(), false)
                .expect("should resolve connected TcpStream to current process");
        assert!(
            resolved_stream.eq_ignore_ascii_case(&expected_exe),
            "expected '{expected_exe}', got '{resolved_stream}'"
        );
    }

    #[test]
    fn lookup_local_port_process_resolves_live_udp_socket() {
        let expected_exe = current_test_exe_name();

        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind udp socket");
        let addr = socket.local_addr().expect("udp local_addr");

        let resolved = lookup_local_port_process(addr.ip(), addr.port(), true)
            .expect("should resolve bound UdpSocket to current process");
        assert!(
            resolved.eq_ignore_ascii_case(&expected_exe),
            "expected '{expected_exe}', got '{resolved}'"
        );
    }

    #[test]
    fn lookup_local_port_process_resolves_ipv6_tcp_listener() {
        let expected_exe = current_test_exe_name();

        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return;
        };
        let listen_addr = listener.local_addr().expect("v6 listener local_addr");

        let resolved = lookup_local_port_process(listen_addr.ip(), listen_addr.port(), false)
            .expect("should resolve IPv6 TcpListener to current process");
        assert!(
            resolved.eq_ignore_ascii_case(&expected_exe),
            "expected '{expected_exe}', got '{resolved}'"
        );
    }

    #[test]
    fn parse_display_icon_exe_cleans_quotes_indices_and_filters_uninstallers() {
        assert_eq!(
            parse_display_icon_exe(r#""C:\Program Files\Google\Chrome\Application\chrome.exe",0"#),
            Some((
                "chrome.exe".to_string(),
                r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string()
            ))
        );
        assert_eq!(
            parse_display_icon_exe(r#""C:\Apps\My, App\cool.exe,-101""#),
            Some((
                "cool.exe".to_string(),
                r"C:\Apps\My, App\cool.exe".to_string()
            ))
        );
        assert_eq!(parse_display_icon_exe(r"C:\Apps\Foo\app.ico,0"), None);
        assert_eq!(parse_display_icon_exe(r"C:\Apps\Foo\unins000.exe"), None);
        assert_eq!(
            parse_display_icon_exe(r"C:\Windows\System32\msiexec.exe,0"),
            None
        );
    }

    #[test]
    fn noise_process_filter_blocks_os_internals_and_keeps_user_apps() {
        for noise in [
            "svchost.exe",
            "CSRSS.EXE",
            "RuntimeBroker.exe",
            "vdpi.exe",
            "Memory Compression",
            "Registry",
        ] {
            assert!(
                is_noise_process_name(noise),
                "expected '{noise}' to be filtered"
            );
        }

        for real_app in [
            "Discord.exe",
            "chrome.exe",
            "RobloxPlayerBeta.exe",
            "steam.exe",
            "Code.exe",
            "Spotify.exe",
        ] {
            assert!(
                !is_noise_process_name(real_app),
                "expected '{real_app}' to be kept"
            );
        }
    }
}
