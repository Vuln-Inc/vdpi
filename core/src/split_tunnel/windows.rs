//! Windows desktop application discovery and socket-to-process resolution
//! for per-application split tunneling.
//!
//! - **Running processes**: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` +
//!   `Process32FirstW`/`Process32NextW`, enriched solely from known catalog and
//!   Windows Registry / well-known install metadata (zero `OpenProcess` calls).
//! - **Installed apps**: Windows Registry `Uninstall` hives (HKLM 64-bit, HKLM
//!   WOW6432Node, HKCU) plus well-known `%LOCALAPPDATA%` / `%APPDATA%` /
//!   `%ProgramFiles%` / `%ProgramData%\Riot Games\RiotClientInstalls.json`
//!   installation layouts (Discord, Roblox, Riot Games, Telegram, Spotify,
//!   browsers, game launchers, etc.).
//! - **Socket-to-process lookup**: `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`)
//!   and `GetExtendedUdpTable` (`UDP_TABLE_OWNER_PID`) for both `AF_INET` and
//!   `AF_INET6`, with bounded `ERROR_INSUFFICIENT_BUFFER` retries and zero handle leaks.

use super::{AppCategory, DiscoveredApp};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    HANDLE, INVALID_HANDLE_VALUE, NO_ERROR,
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

/// Maximum retries when `GetExtendedTcpTable`/`GetExtendedUdpTable` grows between
/// calls (`ERROR_INSUFFICIENT_BUFFER`).
const MAX_TABLE_RETRIES: usize = 3;

/// Initial size (32 KiB) of each persistent IP Helper table buffer so common
/// `GetExtendedTcpTable`/`GetExtendedUdpTable` calls complete in one syscall
/// without a null size probe or per-flow allocation.
const INITIAL_TABLE_BUFFER_BYTES: usize = 32 * 1024;

/// Extra byte headroom added on table buffer growth to avoid resize races.
const TABLE_BUFFER_HEADROOM: usize = 4096;

/// Time-to-live for cached `GetExtendedTcpTable`/`GetExtendedUdpTable` owner-PID
/// snapshots shared across connection bursts.
const IP_TABLE_SNAPSHOT_TTL: Duration = Duration::from_millis(50);

/// Upper bound on Registry Uninstall subkeys enumerated per hive.
const MAX_UNINSTALL_SUBKEYS: u32 = 4096;

/// Upper bound on versioned subdirectories scanned for `%LOCALAPPDATA%` apps.
const MAX_VERSION_SUBDIRS: usize = 64;

/// Time-to-live for the cached `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` PID map
/// used by `pid_to_exe_name` to resolve socket owners without opening process handles.
const PID_SNAPSHOT_TTL: Duration = Duration::from_millis(2500);

/// Minimum cooldown between `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` refreshes
/// on missing/exited PIDs so unknown PIDs cannot thrash the kernel snapshot API.
const PID_SNAPSHOT_MISS_REFRESH_COOLDOWN: Duration = Duration::from_millis(300);

/// Windows OS internals, background hosts, CLI tools, peripheral helpers,
/// game overlays, and vdpi binaries excluded from app discovery.
const NOISE_PROCESSES: &[&str] = &[
    "aggregatorhost.exe",
    "amdfendrsr.exe",
    "amdppkgsvc.exe",
    "appactions.exe",
    "applicationframehost.exe",
    "audiodg.exe",
    "backgroundtaskhost.exe",
    "bash.exe",
    "cc_engine_x64.exe",
    "cefsharp.browsersubprocess.exe",
    "chxsmartscreen.exe",
    "cmd.exe",
    "compattelrunner.exe",
    "conhost.exe",
    "consent.exe",
    "crashpad_handler.exe",
    "crossdeviceresume.exe",
    "crossdeviceservice.exe",
    "cscript.exe",
    "csrss.exe",
    "ctfmon.exe",
    "cut.exe",
    "cygpath.exe",
    "dashost.exe",
    "discord_clips.exe",
    "discordsystemhelper.exe",
    "dllhost.exe",
    "dwm.exe",
    "epicwebhelper.exe",
    "explorer.exe",
    "fontdrvhost.exe",
    "gamebar.exe",
    "gamebarftserver.exe",
    "gamebarpresencewriter.exe",
    "gameinputrawinputproxy.exe",
    "gameinputredistservice.exe",
    "gameoverlayui.exe",
    "gamingservices.exe",
    "gamingservicesnet.exe",
    "git-credential-manager.exe",
    "git.exe",
    "googleupdate.exe",
    "hapticservice.exe",
    "idle",
    "instupd.exe",
    "ledkeeper2.exe",
    "lockapp.exe",
    "logonui.exe",
    "lsaiso.exe",
    "lsass.exe",
    "memory compression",
    "microsoftedgeupdate.exe",
    "microsoftstartfeedprovider.exe",
    "mintty.exe",
    "mktemp.exe",
    "mpdefendercoreservice.exe",
    "msedgewebview2.exe",
    "msi.centralserver.exe",
    "msi.terminalserver.exe",
    "msiexec.exe",
    "msmpeng.exe",
    "musnotifyicon.exe",
    "nativedialog.exe",
    "nissrv.exe",
    "npfinstall.exe",
    "nvcontainer.exe",
    "nvdisplay.container.exe",
    "nvsphelper64.exe",
    "nvtelemetrycontainer.exe",
    "oalinst.exe",
    "openconsole.exe",
    "phoneexperiencehost.exe",
    "powershell.exe",
    "pwsh.exe",
    "qtwebengineprocess.exe",
    "registry",
    "regsvr32.exe",
    "rtlupd64.exe",
    "rundll32.exe",
    "runtimebroker.exe",
    "searchapp.exe",
    "searchfilterhost.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "searchprotocolhost.exe",
    "secure system",
    "securityhealthservice.exe",
    "securityhealthsystray.exe",
    "sed.exe",
    "sentry-crash.exe",
    "services.exe",
    "sgrmbroker.exe",
    "sh.exe",
    "shellexperiencehost.exe",
    "sihclient.exe",
    "sihost.exe",
    "smartscreen.exe",
    "smss.exe",
    "spoolsv.exe",
    "sppsvc.exe",
    "ssh-agent.exe",
    "startmenuexperiencehost.exe",
    "steamwebhelper.exe",
    "svchost.exe",
    "system",
    "system idle process",
    "tail.exe",
    "taskhostw.exe",
    "textinputhost.exe",
    "tiworker.exe",
    "trustedinstaller.exe",
    "uhssvc.exe",
    "unrealcefsubprocess.exe",
    "useroobebroker.exe",
    "usocoreworker.exe",
    "vctip.exe",
    "vdpi-service.exe",
    "vdpi.exe",
    "vmware-authd.exe",
    "vmware-usbarbitrator64.exe",
    "vssvc.exe",
    "waasmedicagent.exe",
    "wc.exe",
    "werfault.exe",
    "wermgr.exe",
    "widgetboard.exe",
    "widgets.exe",
    "widgetservice.exe",
    "wininit.exe",
    "winlogon.exe",
    "wmiprvse.exe",
    "wscript.exe",
    "wstoastnotification.exe",
    "wuauclt.exe",
    "wudfhost.exe",
];

/// Anti-cheat and anti-cheat-protected executables that must never be probed
/// with `OpenProcess` (maintained as a defense-in-depth denylist alongside
/// Toolhelp32-only process discovery and PID resolution).
const ANTICHEAT_PROCESSES: &[&str] = &[
    "bedaisy.exe",
    "beservice.exe",
    "eaanticheat.gameservice.exe",
    "eaanticheat.gameservicelauncher.exe",
    "easyanticheat.exe",
    "easyanticheat_eos.exe",
    "faceitclient.exe",
    "faceitservice.exe",
    "league of legends.exe",
    "riotclientservices.exe",
    "robloxplayerbeta.exe",
    "valorant-win64-shipping.exe",
    "valorant.exe",
    "vgc.exe",
    "vgtray.exe",
];

/// Background/kernel anti-cheat service executables hidden from selectable
/// `[running]` discovery clutter (still resolved safely if configured manually).
const ANTICHEAT_SERVICE_PROCESSES: &[&str] = &[
    "bedaisy.exe",
    "beservice.exe",
    "eaanticheat.gameservice.exe",
    "eaanticheat.gameservicelauncher.exe",
    "easyanticheat.exe",
    "easyanticheat_eos.exe",
    "faceitservice.exe",
    "vgc.exe",
    "vgtray.exe",
];

/// Generic installer/uninstaller/updater/helper executables ignored when parsing
/// Registry `Uninstall` entries or discovering running apps.
const INSTALLER_EXES: &[&str] = &[
    "crashhandler.exe",
    "crashpad_handler.exe",
    "crashreportclient.exe",
    "elevate.exe",
    "elevatedinstaller.exe",
    "errorreport.exe",
    "ffmpeg.exe",
    "helper.exe",
    "install.exe",
    "installer.exe",
    "instupd.exe",
    "maintenancetool.exe",
    "msiexec.exe",
    "nativedialog.exe",
    "npfinstall.exe",
    "oalinst.exe",
    "rtlupd64.exe",
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
    "windows desktop runtime",
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
            // `CreateToolhelp32Snapshot` and closed exactly once here.
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

/// Unicode-aware lowercase helper folding Turkish `İ` (`i\u{0307}` -> `i`) and
/// dotless `ı` (`\u{0131}` -> `i`) for reliable Windows install stem matching.
fn fold_unicode_lower(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.to_lowercase().chars() {
        match ch {
            '\u{0307}' => {}
            '\u{0131}' => out.push('i'),
            other => out.push(other),
        }
    }
    out
}

/// Real user applications whose executable names contain generic clutter tokens
/// (such as `service`) and must remain allowlisted before pattern-based filtering.
const CLUTTER_EXEMPT_EXES: &[&str] = &["riotclientservices.exe"];

/// Returns `true` for noisy background services, updaters, crash handlers,
/// peripheral helpers, and Python installer binaries excluded from both
/// `[running]` and `[installed]` discovery lists.
fn is_clutter_exe_pattern(lower: &str) -> bool {
    if CLUTTER_EXEMPT_EXES
        .iter()
        .any(|exempt| lower.eq_ignore_ascii_case(exempt))
        || super::is_popular_app(lower)
    {
        return false;
    }
    let stem = lower.strip_suffix(".exe").unwrap_or(lower);
    if stem.is_empty() {
        return true;
    }
    stem.contains("crashhandler")
        || stem.contains("crashpad")
        || stem.contains("crashreport")
        || stem.ends_with("-crash")
        || stem.ends_with("_crash")
        || stem.contains("updater")
        || stem.ends_with("update")
        || stem.ends_with("autoupdate")
        || stem.contains("service")
        || stem.contains("svc")
        || stem.starts_with("rz")
        || stem.starts_with("lghub_")
        || stem.starts_with("python-3.")
        || stem.starts_with("python-2.")
}

fn is_noise_process_name(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    if lower.is_empty() || lower.starts_with('[') || lower.ends_with(']') {
        return true;
    }
    NOISE_PROCESSES.contains(&lower.as_str())
        || INSTALLER_EXES.contains(&lower.as_str())
        || is_clutter_exe_pattern(&lower)
}

fn is_anticheat_process_name(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    ANTICHEAT_PROCESSES.contains(&lower.as_str())
}

fn is_anticheat_service_process_name(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    ANTICHEAT_SERVICE_PROCESSES.contains(&lower.as_str())
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

/// Checks via filesystem metadata alone (zero `OpenProcess` calls) whether
/// `exe_name` matches a built-in Windows System32/SysWOW64 binary.
fn is_windows_system_binary(exe_name: &str) -> bool {
    let trimmed = exe_name.trim();
    if trimmed.is_empty()
        || trimmed.contains(['\\', '/'])
        || super::is_popular_app(trimmed)
        || is_anticheat_process_name(trimmed)
    {
        return false;
    }
    let windir = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windir.join("System32").join(trimmed).is_file()
        || windir.join("SysWOW64").join(trimmed).is_file()
}

fn is_installer_or_noise_exe(exe_name: &str) -> bool {
    let lower = exe_name.trim().to_ascii_lowercase();
    if lower.is_empty() || !lower.ends_with(".exe") {
        return true;
    }
    if NOISE_PROCESSES.contains(&lower.as_str())
        || INSTALLER_EXES.contains(&lower.as_str())
        || ANTICHEAT_SERVICE_PROCESSES.contains(&lower.as_str())
        || is_clutter_exe_pattern(&lower)
    {
        return true;
    }
    let stem = &lower[..lower.len() - 4];
    stem.starts_with("unins")
        || stem.starts_with("dpinst")
        || stem.contains("uninstall")
        || stem.contains("installer")
        || stem.contains("setup")
        || stem.contains("runtime")
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

fn default_display_name_with_path(exe_name: &str, path: Option<&str>) -> String {
    if exe_name.trim().eq_ignore_ascii_case("opera.exe")
        && path.is_some_and(|p| p.to_ascii_lowercase().contains("opera gx"))
    {
        return "Opera GX".to_string();
    }
    default_display_name(exe_name)
}

struct PidSnapshotCache {
    map: HashMap<u32, String>,
    captured_at: Instant,
}

struct PidSnapshotStore {
    cache: Mutex<Option<PidSnapshotCache>>,
    refresh_lock: Mutex<()>,
}

impl PidSnapshotStore {
    fn new() -> Self {
        Self {
            cache: Mutex::new(None),
            refresh_lock: Mutex::new(()),
        }
    }

    fn try_cached(
        &self,
        pid: u32,
        ttl: Duration,
        miss_cooldown: Duration,
    ) -> Option<Option<String>> {
        let now = Instant::now();
        let guard = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cached = guard.as_ref()?;
        let age = now.saturating_duration_since(cached.captured_at);
        if age < ttl {
            if let Some(name) = cached.map.get(&pid) {
                return Some(Some(name.clone()));
            }
            if age < miss_cooldown {
                return Some(None);
            }
        }
        None
    }

    fn resolve_with<F>(
        &self,
        pid: u32,
        ttl: Duration,
        miss_cooldown: Duration,
        mut capture_fn: F,
    ) -> Option<String>
    where
        F: FnMut() -> Option<HashMap<u32, String>>,
    {
        if pid == 0 {
            return None;
        }

        if let Some(hit) = self.try_cached(pid, ttl, miss_cooldown) {
            return hit;
        }

        let _refresh_guard = self
            .refresh_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        if let Some(hit) = self.try_cached(pid, ttl, miss_cooldown) {
            return hit;
        }

        let captured_at = Instant::now();
        let fresh = capture_fn()?;
        let found = fresh.get(&pid).cloned();
        {
            let mut guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = Some(PidSnapshotCache {
                map: fresh,
                captured_at,
            });
        }
        found
    }
}

static PID_SNAPSHOT_CACHE: OnceLock<PidSnapshotStore> = OnceLock::new();

fn capture_toolhelp_pid_map() -> Option<HashMap<u32, String>> {
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

    let mut map = HashMap::with_capacity(256);
    loop {
        if entry.th32ProcessID != 0 {
            let name = decode_wide_nul(&entry.szExeFile);
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                map.insert(entry.th32ProcessID, trimmed.to_string());
            }
        }
        // SAFETY: `snapshot.raw()` is valid and `entry` remains initialized.
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
            break;
        }
    }
    Some(map)
}

/// Resolves a Windows process ID to its executable filename (e.g. `"Discord.exe"`).
///
/// Uses a cached `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` PID map
/// (2500ms positive TTL) with singleflight refresh serialization, pre-capture
/// timestamping, and a 300ms minimum refresh cooldown for missing/exited PIDs.
/// Never calls `OpenProcess` on any PID — if a PID is absent from a fresh
/// snapshot (e.g. already exited or kernel-hidden anti-cheat process), returns `None`.
fn pid_to_exe_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }

    PID_SNAPSHOT_CACHE
        .get_or_init(PidSnapshotStore::new)
        .resolve_with(
            pid,
            PID_SNAPSHOT_TTL,
            PID_SNAPSHOT_MISS_REFRESH_COOLDOWN,
            capture_toolhelp_pid_map,
        )
}

fn discover_running_processes(
    static_metadata: &HashMap<String, (String, Option<String>)>,
) -> Vec<DiscoveredApp> {
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

    // Deduplicate by lowercase exe name strictly from Toolhelp32 `szExeFile`
    // (never calling `OpenProcess` on running processes).
    let mut by_exe: HashMap<String, String> = HashMap::new();
    loop {
        let exe_name = decode_wide_nul(&entry.szExeFile);
        let trimmed = exe_name.trim();
        if !trimmed.is_empty()
            && !is_noise_process_name(trimmed)
            && !is_anticheat_service_process_name(trimmed)
        {
            let key = trimmed.to_ascii_lowercase();
            by_exe.entry(key).or_insert_with(|| trimmed.to_string());
        }

        // SAFETY: `snapshot.raw()` is valid and `entry` remains initialized.
        if unsafe { Process32NextW(snapshot.raw(), &mut entry) } == 0 {
            break;
        }
    }

    let mut apps = Vec::with_capacity(by_exe.len());
    for (key, exe_name) in by_exe {
        if is_windows_system_binary(&exe_name) {
            continue;
        }

        let (display_name, path) =
            if let Some((meta_display, meta_path)) = static_metadata.get(&key) {
                let resolved_display = if super::is_popular_app(&exe_name) {
                    if exe_name.eq_ignore_ascii_case("opera.exe")
                        && (meta_display.to_ascii_lowercase().contains("opera gx")
                            || meta_path
                                .as_deref()
                                .is_some_and(|p| p.to_ascii_lowercase().contains("opera gx")))
                    {
                        meta_display.clone()
                    } else {
                        default_display_name_with_path(&exe_name, meta_path.as_deref())
                    }
                } else if !meta_display.trim().is_empty() {
                    meta_display.clone()
                } else {
                    default_display_name_with_path(&exe_name, meta_path.as_deref())
                };
                (resolved_display, meta_path.clone())
            } else {
                (default_display_name(&exe_name), None)
            };

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
    let display_lower = fold_unicode_lower(display_name.trim());
    let is_roblox_studio = display_lower.contains("roblox studio");
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
        let stem = fold_unicode_lower(&name[..name.len() - 4]);
        let full = path.to_string_lossy().into_owned();
        if is_roblox_studio && name.eq_ignore_ascii_case("RobloxStudioBeta.exe") {
            return Some((name.to_string(), full));
        }
        if !stem.is_empty()
            && (display_lower == stem
                || display_lower.contains(&stem)
                || super::is_popular_app(name))
        {
            return Some((name.to_string(), full));
        }
        candidates.push((name.to_string(), full));
    }

    if is_roblox_studio {
        return None;
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

            let display_name = if exe_name.eq_ignore_ascii_case("opera.exe")
                && (display_name.to_ascii_lowercase().contains("opera gx")
                    || exe_path.to_ascii_lowercase().contains("opera gx"))
            {
                "Opera GX".to_string()
            } else {
                display_name
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
            (
                "Roblox Studio",
                r"Roblox\Versions",
                "",
                "RobloxStudioBeta.exe",
            ),
            ("Slack", "slack", "app-", "slack.exe"),
        ] {
            if let Some(path) = find_latest_versioned_exe(&local.join(folder), prefix, exe) {
                probe_well_known_app(&mut apps, display, exe, path);
            }
        }

        // Direct `%LOCALAPPDATA%` user-scope installs.
        for (display, rel, exe) in [
            ("Bloxstrap", r"Bloxstrap\Bloxstrap.exe", "Bloxstrap.exe"),
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

        // Opera and Opera GX share the `opera.exe` binary name on Windows; label
        // distinctly so Opera GX is never silently collapsed under plain "Opera".
        let opera_path = local.join(r"Programs\Opera\opera.exe");
        let opera_gx_path = local.join(r"Programs\Opera GX\opera.exe");
        match (opera_path.is_file(), opera_gx_path.is_file()) {
            (true, true) => {
                probe_well_known_app(&mut apps, "Opera / Opera GX", "opera.exe", opera_path);
            }
            (true, false) => {
                probe_well_known_app(&mut apps, "Opera", "opera.exe", opera_path);
            }
            (false, true) => {
                probe_well_known_app(&mut apps, "Opera GX", "opera.exe", opera_gx_path);
            }
            (false, false) => {}
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

    apps.extend(discover_riot_apps());

    apps
}

#[derive(Debug, Default, PartialEq, Eq)]
struct RiotInstallLocations {
    riot_client_exes: Vec<PathBuf>,
    game_roots: Vec<PathBuf>,
}

fn normalize_windows_json_path(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim().trim_matches('"').trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.replace('/', "\\");
    let stripped = if normalized.len() > 3 {
        normalized.trim_end_matches('\\')
    } else {
        normalized.as_str()
    };
    if stripped.is_empty() {
        None
    } else {
        Some(PathBuf::from(stripped))
    }
}

fn push_unique_path(list: &mut Vec<PathBuf>, seen: &mut HashSet<String>, path: PathBuf) {
    let key = path.to_string_lossy().to_ascii_lowercase();
    if seen.insert(key) {
        list.push(path);
    }
}

/// Parses Riot's `RiotClientInstalls.json` manifest (usually under
/// `%ProgramData%\Riot Games\RiotClientInstalls.json`) to locate Riot Client,
/// Valorant, and League of Legends installations on any drive (`C:\`, `D:\`, `E:\`, ...).
fn parse_riot_client_installs_json(json_str: &str) -> RiotInstallLocations {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return RiotInstallLocations::default();
    };
    let Some(obj) = value.as_object() else {
        return RiotInstallLocations::default();
    };

    let mut out = RiotInstallLocations::default();
    let mut seen_clients: HashSet<String> = HashSet::new();
    let mut seen_games: HashSet<String> = HashSet::new();

    for key in ["rc_live", "rc_default", "rc_beta"] {
        if let Some(raw) = obj.get(key).and_then(|v| v.as_str()) {
            if let Some(path) = normalize_windows_json_path(raw) {
                push_unique_path(&mut out.riot_client_exes, &mut seen_clients, path);
            }
        }
    }

    if let Some(patchlines) = obj.get("patchlines").and_then(|v| v.as_object()) {
        for val in patchlines.values() {
            if let Some(raw) = val.as_str() {
                if let Some(path) = normalize_windows_json_path(raw) {
                    push_unique_path(&mut out.riot_client_exes, &mut seen_clients, path);
                }
            }
        }
    }

    if let Some(associated) = obj.get("associated_client").and_then(|v| v.as_object()) {
        for (game_root_raw, rc_exe_raw) in associated {
            if let Some(game_root) = normalize_windows_json_path(game_root_raw) {
                push_unique_path(&mut out.game_roots, &mut seen_games, game_root);
            }
            if let Some(rc_path) = rc_exe_raw.as_str().and_then(normalize_windows_json_path) {
                push_unique_path(&mut out.riot_client_exes, &mut seen_clients, rc_path);
            }
        }
    }

    out
}

fn probe_first_existing_app(
    apps: &mut Vec<DiscoveredApp>,
    display_name: &str,
    exe_name: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> bool {
    for candidate in candidates {
        if candidate.is_file() {
            probe_well_known_app(apps, display_name, exe_name, candidate);
            return true;
        }
    }
    false
}

fn discover_riot_apps_from_locations(
    locations: &RiotInstallLocations,
    include_default_fallback: bool,
) -> Vec<DiscoveredApp> {
    let mut apps = Vec::new();
    let mut found_riot_client = false;
    let mut found_valorant = false;
    let mut found_league = false;

    if probe_first_existing_app(
        &mut apps,
        "Riot Client",
        "RiotClientServices.exe",
        locations.riot_client_exes.iter().cloned(),
    ) {
        found_riot_client = true;
    }

    for root in &locations.game_roots {
        if !found_valorant {
            let valorant_candidates = [
                root.join(r"ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe"),
                root.join(r"live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe"),
            ];
            if probe_first_existing_app(
                &mut apps,
                "Valorant",
                "VALORANT-Win64-Shipping.exe",
                valorant_candidates,
            ) {
                found_valorant = true;
            }
        }

        if !found_league {
            let league_client = root.join("LeagueClient.exe");
            if league_client.is_file() {
                probe_well_known_app(
                    &mut apps,
                    "League of Legends",
                    "LeagueClient.exe",
                    league_client,
                );
                found_league = true;
            } else {
                let league_game = root.join(r"Game\League of Legends.exe");
                if league_game.is_file() {
                    probe_well_known_app(
                        &mut apps,
                        "League of Legends",
                        "League of Legends.exe",
                        league_game,
                    );
                    found_league = true;
                }
            }
        }
    }

    for rc_exe in &locations.riot_client_exes {
        let Some(riot_games_dir) = rc_exe.parent().and_then(|p| p.parent()) else {
            continue;
        };
        if !found_valorant {
            let valorant = riot_games_dir
                .join(r"VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe");
            if valorant.is_file() {
                probe_well_known_app(
                    &mut apps,
                    "Valorant",
                    "VALORANT-Win64-Shipping.exe",
                    valorant,
                );
                found_valorant = true;
            }
        }
        if !found_league {
            let league = riot_games_dir.join(r"League of Legends\LeagueClient.exe");
            if league.is_file() {
                probe_well_known_app(&mut apps, "League of Legends", "LeagueClient.exe", league);
                found_league = true;
            }
        }
    }

    if include_default_fallback {
        if !found_riot_client {
            probe_well_known_app(
                &mut apps,
                "Riot Client",
                "RiotClientServices.exe",
                PathBuf::from(r"C:\Riot Games\Riot Client\RiotClientServices.exe"),
            );
        }
        if !found_valorant {
            probe_well_known_app(
                &mut apps,
                "Valorant",
                "VALORANT-Win64-Shipping.exe",
                PathBuf::from(
                    r"C:\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe",
                ),
            );
        }
        if !found_league {
            probe_well_known_app(
                &mut apps,
                "League of Legends",
                "LeagueClient.exe",
                PathBuf::from(r"C:\Riot Games\League of Legends\LeagueClient.exe"),
            );
        }
    }

    apps
}

fn discover_riot_apps() -> Vec<DiscoveredApp> {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let manifest_path = program_data.join(r"Riot Games\RiotClientInstalls.json");
    let locations = std::fs::metadata(&manifest_path)
        .ok()
        .filter(|m| m.is_file() && m.len() <= 1_048_576)
        .and_then(|_| std::fs::read_to_string(&manifest_path).ok())
        .map(|raw| parse_riot_client_installs_json(&raw))
        .unwrap_or_default();
    discover_riot_apps_from_locations(&locations, true)
}

fn canonical_riot_companion_target(exe_name: &str) -> Option<(&'static str, &'static str)> {
    match exe_name.trim().to_ascii_lowercase().as_str() {
        "riotclientservices.exe" | "riotclientux.exe" | "riotclientuxrender.exe" => {
            Some(("Riot Client", "RiotClientServices.exe"))
        }
        "valorant-win64-shipping.exe" | "valorant.exe" => {
            Some(("Valorant", "VALORANT-Win64-Shipping.exe"))
        }
        "leagueclient.exe"
        | "leagueclientux.exe"
        | "leagueclientuxrender.exe"
        | "league of legends.exe" => Some(("League of Legends", "LeagueClient.exe")),
        _ => None,
    }
}

/// Collapses Riot Client (`RiotClientServices` / `RiotClientUx`), Valorant
/// (`VALORANT-Win64-Shipping` / `VALORANT`), and League of Legends
/// (`LeagueClient` / `LeagueClientUx` / `League of Legends`) companion processes
/// into a single canonical row while preserving `is_running` state and the primary
/// executable path (runtime split tunneling already expands companion binaries via
/// `companion_executables_for`).
fn deduplicate_riot_companion_apps(apps: Vec<DiscoveredApp>) -> Vec<DiscoveredApp> {
    let mut out: Vec<DiscoveredApp> = Vec::with_capacity(apps.len());
    let mut canonical_indices: HashMap<&'static str, usize> = HashMap::new();

    for mut app in apps {
        let Some((canonical_display, canonical_exe)) =
            canonical_riot_companion_target(&app.exe_name)
        else {
            out.push(app);
            continue;
        };

        let is_primary_exe = app.exe_name.trim().eq_ignore_ascii_case(canonical_exe);
        let incoming_path = if is_primary_exe {
            app.path.take().filter(|p| !p.trim().is_empty())
        } else {
            None
        };

        if let Some(&idx) = canonical_indices.get(canonical_exe) {
            let existing = &mut out[idx];
            existing.is_running |= app.is_running;
            if existing.is_running {
                existing.category = AppCategory::Running;
            } else if app.category < existing.category {
                existing.category = app.category;
            }
            if existing.path.is_none() && incoming_path.is_some() {
                existing.path = incoming_path;
            }
        } else {
            let category = if app.is_running {
                AppCategory::Running
            } else {
                AppCategory::Popular
            };
            let idx = out.len();
            canonical_indices.insert(canonical_exe, idx);
            out.push(DiscoveredApp {
                display_name: canonical_display.to_string(),
                exe_name: canonical_exe.to_string(),
                path: incoming_path,
                is_running: app.is_running,
                category,
            });
        }
    }

    out
}

/// Discovers running user applications and installed desktop applications on Windows.
pub(super) fn discover_platform_apps() -> Vec<DiscoveredApp> {
    let registry_apps = discover_registry_uninstall_apps();
    let well_known_apps = discover_well_known_apps();

    // Build static exe -> (display_name, path) metadata from registry & well-known
    // installs so running processes resolve display names and paths strictly from
    // Toolhelp32 `szExeFile` + static metadata without ever calling `OpenProcess`.
    let mut static_metadata: HashMap<String, (String, Option<String>)> = HashMap::new();
    for app in well_known_apps.iter().chain(registry_apps.iter()) {
        let key = app.exe_name.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        static_metadata
            .entry(key)
            .or_insert_with(|| (app.display_name.clone(), app.path.clone()));
    }

    let mut apps = discover_running_processes(&static_metadata);
    apps.extend(registry_apps);
    apps.extend(well_known_apps);
    deduplicate_riot_companion_apps(apps)
}

/// Fetches a variable-length IP Helper table (`GetExtendedTcpTable` or
/// `GetExtendedUdpTable`) into a persistent, 8-byte aligned buffer starting at
/// [`INITIAL_TABLE_BUFFER_BYTES`] (32 KiB) without a null size probe, growing
/// and retrying up to [`MAX_TABLE_RETRIES`] times on `ERROR_INSUFFICIENT_BUFFER`.
fn fetch_iphlpapi_table_into<F>(buf: &mut Vec<u64>, mut fetch_fn: F) -> Option<usize>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
{
    let min_words = INITIAL_TABLE_BUFFER_BYTES
        .div_ceil(std::mem::size_of::<u64>())
        .max(1);
    if buf.len() < min_words {
        buf.resize(min_words, 0);
    }

    for _ in 0..=MAX_TABLE_RETRIES {
        let buf_bytes = buf.len().saturating_mul(std::mem::size_of::<u64>());
        let Ok(mut buf_size) = u32::try_from(buf_bytes) else {
            return None;
        };
        buf[0] = 0;

        let status = fetch_fn(buf.as_mut_ptr().cast::<c_void>(), &mut buf_size);
        if status == NO_ERROR {
            let valid_bytes = (buf_size as usize).min(buf_bytes);
            return Some(valid_bytes);
        }
        if status == ERROR_INSUFFICIENT_BUFFER && buf_size > 0 {
            let alloc_bytes = (buf_size as usize).saturating_add(TABLE_BUFFER_HEADROOM);
            let needed_words = alloc_bytes
                .div_ceil(std::mem::size_of::<u64>())
                .max(min_words);
            if needed_words > buf.len() {
                buf.resize(needed_words, 0);
            } else {
                let extra_words = TABLE_BUFFER_HEADROOM
                    .div_ceil(std::mem::size_of::<u64>())
                    .max(1);
                buf.resize(buf.len().saturating_add(extra_words), 0);
            }
            continue;
        }
        return None;
    }

    None
}

struct CachedIpTable {
    buf: Vec<u64>,
    valid_bytes: usize,
    captured_at: Option<Instant>,
    generation: u64,
}

enum IpTableProbe<T> {
    Hit(T),
    DefinitiveMiss,
    NeedsRefresh(u64),
}

struct IpTableCache {
    snapshot: Mutex<CachedIpTable>,
    refresh: Mutex<Vec<u64>>,
}

impl IpTableCache {
    fn new() -> Self {
        Self {
            snapshot: Mutex::new(CachedIpTable {
                buf: Vec::new(),
                valid_bytes: 0,
                captured_at: None,
                generation: 0,
            }),
            refresh: Mutex::new(Vec::new()),
        }
    }

    fn try_lookup_fresh<F, T>(&self, ttl: Duration, mut scan_fn: F) -> Option<T>
    where
        F: FnMut(&[u64], usize) -> Option<T>,
    {
        let now = Instant::now();
        let guard = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let captured_at = guard.captured_at?;
        if now.saturating_duration_since(captured_at) < ttl {
            scan_fn(&guard.buf, guard.valid_bytes)
        } else {
            None
        }
    }

    fn probe_snapshot<F, T>(
        &self,
        ttl: Duration,
        request_started_at: Instant,
        seen_generation: Option<u64>,
        scan_fn: &mut F,
    ) -> IpTableProbe<T>
    where
        F: FnMut(&[u64], usize) -> Option<T>,
    {
        let now = Instant::now();
        let guard = self
            .snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current_gen = guard.generation;
        let Some(captured_at) = guard.captured_at else {
            return IpTableProbe::NeedsRefresh(current_gen);
        };
        if now.saturating_duration_since(captured_at) >= ttl {
            return IpTableProbe::NeedsRefresh(current_gen);
        }
        if let Some(found) = scan_fn(&guard.buf, guard.valid_bytes) {
            return IpTableProbe::Hit(found);
        }
        if seen_generation.is_some_and(|seen| current_gen != seen)
            && captured_at >= request_started_at
        {
            IpTableProbe::DefinitiveMiss
        } else {
            IpTableProbe::NeedsRefresh(current_gen)
        }
    }

    fn lookup_with<Fetch, Scan, T>(
        &self,
        ttl: Duration,
        fetch_fn: Fetch,
        mut scan_fn: Scan,
    ) -> Option<T>
    where
        Fetch: FnMut(*mut c_void, *mut u32) -> u32,
        Scan: FnMut(&[u64], usize) -> Option<T>,
    {
        let request_started_at = Instant::now();
        let seen_gen = match self.probe_snapshot(ttl, request_started_at, None, &mut scan_fn) {
            IpTableProbe::Hit(val) => return Some(val),
            IpTableProbe::DefinitiveMiss => return None,
            IpTableProbe::NeedsRefresh(generation) => generation,
        };

        let mut scratch = self
            .refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        match self.probe_snapshot(ttl, request_started_at, Some(seen_gen), &mut scan_fn) {
            IpTableProbe::Hit(val) => return Some(val),
            IpTableProbe::DefinitiveMiss => return None,
            IpTableProbe::NeedsRefresh(_) => {}
        }

        let captured_at = Instant::now();
        let valid_bytes = fetch_iphlpapi_table_into(&mut scratch, fetch_fn)?;
        let found = scan_fn(&scratch, valid_bytes);

        {
            let mut snap = self
                .snapshot
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::swap(&mut snap.buf, &mut *scratch);
            snap.valid_bytes = valid_bytes;
            snap.captured_at = Some(captured_at);
            snap.generation = snap.generation.wrapping_add(1);
        }

        found
    }
}

static TCP_V4_TABLE_CACHE: OnceLock<IpTableCache> = OnceLock::new();
static TCP_V6_TABLE_CACHE: OnceLock<IpTableCache> = OnceLock::new();
static UDP_V4_TABLE_CACHE: OnceLock<IpTableCache> = OnceLock::new();
static UDP_V6_TABLE_CACHE: OnceLock<IpTableCache> = OnceLock::new();

/// Returns `true` for active TCP connection states (`SYN_SENT`..=`LAST_ACK`,
/// i.e. `dwState` in `3..=10`), distinguishing live connections from
/// `CLOSED (1)`, `LISTEN (2)`, `TIME_WAIT (11)`, and `DELETE_TCB (12)`.
fn is_active_tcp_state(dw_state: u32) -> bool {
    (3..=10).contains(&dw_state)
}

/// Priority score for TCP table row selection: active connection states (`3..=10`)
/// always outrank `LISTEN (2)`, which outranks `TIME_WAIT (11)` / `CLOSED (1)`,
/// and exact local IP matches outrank unspecified wildcard (`0.0.0.0` / `::`) rows
/// within the same activity tier.
fn tcp_row_priority(is_exact_ip: bool, dw_state: u32) -> u8 {
    match (is_exact_ip, dw_state) {
        (true, 3..=10) => 6,
        (false, 3..=10) => 5,
        (true, 2) => 4,
        (true, _) => 3,
        (false, 2) => 2,
        (false, _) => 1,
    }
}

fn select_tcp_v4_pid(
    rows: &[MIB_TCPROW_OWNER_PID],
    target_ip: Ipv4Addr,
    local_port: u16,
) -> Option<u32> {
    let mut best_prio: u8 = 0;
    let mut best_pid: Option<u32> = None;

    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes());
        let is_exact = row_ip == target_ip;
        if !is_exact && !row_ip.is_unspecified() {
            continue;
        }
        if is_exact && is_active_tcp_state(row.dwState) {
            return Some(row.dwOwningPid);
        }
        let prio = tcp_row_priority(is_exact, row.dwState);
        if prio > best_prio {
            best_prio = prio;
            best_pid = Some(row.dwOwningPid);
        }
    }

    best_pid
}

fn scan_tcp_v4_table(
    buf: &[u64],
    valid_bytes: usize,
    target_ip: Ipv4Addr,
    local_port: u16,
) -> Option<u32> {
    let valid_bytes = valid_bytes.min(buf.len().saturating_mul(std::mem::size_of::<u64>()));
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

    select_tcp_v4_pid(rows, target_ip, local_port)
}

fn lookup_tcp_v4_pid(target_ip: Ipv4Addr, local_port: u16) -> Option<u32> {
    TCP_V4_TABLE_CACHE
        .get_or_init(IpTableCache::new)
        .lookup_with(
            IP_TABLE_SNAPSHOT_TTL,
            |ptr, size_ptr| {
                // SAFETY: `ptr` is an 8-byte aligned writable buffer of `*size_ptr`
                // bytes; `size_ptr` is a valid aligned `*mut u32`.
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
            },
            |buf, valid_bytes| scan_tcp_v4_table(buf, valid_bytes, target_ip, local_port),
        )
}

fn select_tcp_v6_pid(
    rows: &[MIB_TCP6ROW_OWNER_PID],
    target_ip: Ipv6Addr,
    local_port: u16,
) -> Option<u32> {
    let mut best_prio: u8 = 0;
    let mut best_pid: Option<u32> = None;

    for row in rows {
        let row_port = u16::from_be(row.dwLocalPort as u16);
        if row_port != local_port || row.dwOwningPid == 0 {
            continue;
        }
        let row_ip = Ipv6Addr::from(row.ucLocalAddr);
        let is_exact = row_ip == target_ip;
        if !is_exact && !row_ip.is_unspecified() {
            continue;
        }
        if is_exact && is_active_tcp_state(row.dwState) {
            return Some(row.dwOwningPid);
        }
        let prio = tcp_row_priority(is_exact, row.dwState);
        if prio > best_prio {
            best_prio = prio;
            best_pid = Some(row.dwOwningPid);
        }
    }

    best_pid
}

fn scan_tcp_v6_table(
    buf: &[u64],
    valid_bytes: usize,
    target_ip: Ipv6Addr,
    local_port: u16,
) -> Option<u32> {
    let valid_bytes = valid_bytes.min(buf.len().saturating_mul(std::mem::size_of::<u64>()));
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

    select_tcp_v6_pid(rows, target_ip, local_port)
}

fn lookup_tcp_v6_pid(target_ip: Ipv6Addr, local_port: u16) -> Option<u32> {
    TCP_V6_TABLE_CACHE
        .get_or_init(IpTableCache::new)
        .lookup_with(
            IP_TABLE_SNAPSHOT_TTL,
            |ptr, size_ptr| {
                // SAFETY: `ptr` is an 8-byte aligned writable buffer of `*size_ptr`
                // bytes; `size_ptr` is a valid aligned `*mut u32`.
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
            },
            |buf, valid_bytes| scan_tcp_v6_table(buf, valid_bytes, target_ip, local_port),
        )
}

fn scan_udp_v4_table(
    buf: &[u64],
    valid_bytes: usize,
    target_ip: Ipv4Addr,
    local_port: u16,
) -> Option<u32> {
    let valid_bytes = valid_bytes.min(buf.len().saturating_mul(std::mem::size_of::<u64>()));
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

fn lookup_udp_v4_pid(target_ip: Ipv4Addr, local_port: u16) -> Option<u32> {
    UDP_V4_TABLE_CACHE
        .get_or_init(IpTableCache::new)
        .lookup_with(
            IP_TABLE_SNAPSHOT_TTL,
            |ptr, size_ptr| {
                // SAFETY: `ptr` is an 8-byte aligned writable buffer of `*size_ptr`
                // bytes; `size_ptr` is a valid aligned `*mut u32`.
                unsafe { GetExtendedUdpTable(ptr, size_ptr, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0) }
            },
            |buf, valid_bytes| scan_udp_v4_table(buf, valid_bytes, target_ip, local_port),
        )
}

fn scan_udp_v6_table(
    buf: &[u64],
    valid_bytes: usize,
    target_ip: Ipv6Addr,
    local_port: u16,
) -> Option<u32> {
    let valid_bytes = valid_bytes.min(buf.len().saturating_mul(std::mem::size_of::<u64>()));
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

fn lookup_udp_v6_pid(target_ip: Ipv6Addr, local_port: u16) -> Option<u32> {
    UDP_V6_TABLE_CACHE
        .get_or_init(IpTableCache::new)
        .lookup_with(
            IP_TABLE_SNAPSHOT_TTL,
            |ptr, size_ptr| {
                // SAFETY: `ptr` is an 8-byte aligned writable buffer of `*size_ptr`
                // bytes; `size_ptr` is a valid aligned `*mut u32`.
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
            },
            |buf, valid_bytes| scan_udp_v6_table(buf, valid_bytes, target_ip, local_port),
        )
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
        (IpAddr::V4(v4), false) => {
            let mapped = v4.to_ipv6_mapped();
            TCP_V4_TABLE_CACHE
                .get()
                .and_then(|cache| {
                    cache.try_lookup_fresh(IP_TABLE_SNAPSHOT_TTL, |buf, len| {
                        scan_tcp_v4_table(buf, len, v4, local_port)
                    })
                })
                .or_else(|| {
                    TCP_V6_TABLE_CACHE.get().and_then(|cache| {
                        cache.try_lookup_fresh(IP_TABLE_SNAPSHOT_TTL, |buf, len| {
                            scan_tcp_v6_table(buf, len, mapped, local_port)
                        })
                    })
                })
                .or_else(|| lookup_tcp_v4_pid(v4, local_port))
                .or_else(|| lookup_tcp_v6_pid(mapped, local_port))
        }
        (IpAddr::V6(v6), false) => lookup_tcp_v6_pid(v6, local_port),
        (IpAddr::V4(v4), true) => {
            let mapped = v4.to_ipv6_mapped();
            UDP_V4_TABLE_CACHE
                .get()
                .and_then(|cache| {
                    cache.try_lookup_fresh(IP_TABLE_SNAPSHOT_TTL, |buf, len| {
                        scan_udp_v4_table(buf, len, v4, local_port)
                    })
                })
                .or_else(|| {
                    UDP_V6_TABLE_CACHE.get().and_then(|cache| {
                        cache.try_lookup_fresh(IP_TABLE_SNAPSHOT_TTL, |buf, len| {
                            scan_udp_v6_table(buf, len, mapped, local_port)
                        })
                    })
                })
                .or_else(|| lookup_udp_v4_pid(v4, local_port))
                .or_else(|| lookup_udp_v6_pid(mapped, local_port))
        }
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

    #[test]
    fn installer_noise_and_anticheat_filters_match_expected_binaries() {
        for noise in [
            "MyAppInstaller.exe",
            "vcredist_setup_x64.exe",
            "dpinst64.exe",
            "DotNetRuntimeHelper.exe",
            "ffmpeg.exe",
            "errorreport.exe",
            "unins000.exe",
        ] {
            assert!(
                is_installer_or_noise_exe(noise),
                "expected '{noise}' to be filtered as installer/noise"
            );
        }

        for keep in [
            "Discord.exe",
            "Bloxstrap.exe",
            "VALORANT-Win64-Shipping.exe",
            "opera.exe",
        ] {
            assert!(
                !is_installer_or_noise_exe(keep),
                "expected '{keep}' to pass installer/noise filter"
            );
        }

        assert!(is_noise_display_name(
            "Microsoft Windows Desktop Runtime - 8.0.10 (x64)"
        ));

        for ac in [
            "vgc.exe",
            "vgtray.exe",
            "bedaisy.exe",
            "beservice.exe",
            "faceitclient.exe",
            "faceitservice.exe",
            "eaanticheat.gameservice.exe",
            "eaanticheat.gameservicelauncher.exe",
            "easyanticheat.exe",
            "easyanticheat_eos.exe",
            "VALORANT-Win64-Shipping.exe",
            "VALORANT.exe",
            "RiotClientServices.exe",
            "League of Legends.exe",
            "RobloxPlayerBeta.exe",
        ] {
            assert!(
                is_anticheat_process_name(ac),
                "expected '{ac}' in ANTICHEAT_PROCESSES"
            );
        }

        assert!(is_anticheat_service_process_name("vgc.exe"));
        assert!(is_anticheat_service_process_name("bedaisy.exe"));
        assert!(is_anticheat_service_process_name(
            "eaanticheat.gameservicelauncher.exe"
        ));
        assert!(!is_anticheat_service_process_name(
            "VALORANT-Win64-Shipping.exe"
        ));
        assert!(!is_anticheat_service_process_name("RobloxPlayerBeta.exe"));

        assert_eq!(
            default_display_name_with_path(
                "opera.exe",
                Some(r"C:\Users\alice\AppData\Local\Programs\Opera GX\opera.exe"),
            ),
            "Opera GX"
        );
        assert_eq!(
            default_display_name_with_path(
                "opera.exe",
                Some(r"C:\Users\alice\AppData\Local\Programs\Opera\opera.exe"),
            ),
            "Opera"
        );
    }

    #[test]
    fn clutter_filters_block_noisy_services_updaters_cli_and_roblox_nativedialog() {
        for clutter in [
            "crashhandler.exe",
            "crashhandler64.exe",
            "DiscordCrashHandler.exe",
            "updater.exe",
            "SteamUpdater.exe",
            "opera_autoupdate.exe",
            "foo_service.exe",
            "RazerAppEngine_service.exe",
            "RzSynapse.exe",
            "RzChromaStreamServer.exe",
            "nvcontainer.exe",
            "NVDisplay.Container.exe",
            "lghub_agent.exe",
            "lghub_updater.exe",
            "lghub_system_tray.exe",
            "bash.exe",
            "sh.exe",
            "wc.exe",
            "git.exe",
            "npfinstall.exe",
            "oalinst.exe",
            "instupd.exe",
            "rtlupd64.exe",
            "python-3.12.4-amd64.exe",
            "python-3.14.0.exe",
            "NativeDialog.exe",
        ] {
            assert!(
                is_noise_process_name(clutter),
                "expected '{clutter}' to be filtered from [running]"
            );
            assert!(
                is_installer_or_noise_exe(clutter),
                "expected '{clutter}' to be filtered from [installed]"
            );
        }

        for keep in [
            "RiotClientServices.exe",
            "LeagueClient.exe",
            "VALORANT-Win64-Shipping.exe",
            "Discord.exe",
            "RobloxPlayerBeta.exe",
            "RobloxStudioBeta.exe",
            "lghub.exe",
            "python.exe",
        ] {
            assert!(
                !is_noise_process_name(keep),
                "expected '{keep}' to remain visible in [running]"
            );
            assert!(
                !is_installer_or_noise_exe(keep),
                "expected '{keep}' to remain visible in [installed]"
            );
        }

        // Roblox Studio must never map to NativeDialog.exe via DisplayIcon or InstallLocation.
        assert_eq!(
            parse_display_icon_exe(r"C:\Users\alice\AppData\Local\Roblox\Versions\v1\NativeDialog.exe,0"),
            None
        );

        let base = std::env::temp_dir().join(format!(
            "vdpi_test_roblox_studio_{}",
            std::process::id()
        ));
        let only_dialog_dir = base.join("only_dialog");
        let with_studio_dir = base.join("with_studio");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&only_dialog_dir).expect("create only_dialog dir");
        std::fs::create_dir_all(&with_studio_dir).expect("create with_studio dir");
        std::fs::write(only_dialog_dir.join("NativeDialog.exe"), b"").expect("write dialog");
        std::fs::write(with_studio_dir.join("NativeDialog.exe"), b"").expect("write dialog");
        std::fs::write(with_studio_dir.join("RobloxStudioBeta.exe"), b"").expect("write studio");

        assert_eq!(
            find_exe_in_install_location(
                &only_dialog_dir.to_string_lossy(),
                "Roblox Studio for Alice",
            ),
            None
        );
        let resolved_studio = find_exe_in_install_location(
            &with_studio_dir.to_string_lossy(),
            "Roblox Studio for Alice",
        )
        .expect("should resolve RobloxStudioBeta.exe");
        assert_eq!(resolved_studio.0, "RobloxStudioBeta.exe");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn riot_client_installs_json_parses_non_c_drives_and_discovers_games() {
        let sample_json = r#"{
            "associated_client": {
                "D:/Riot Games/VALORANT/live/": "D:/Riot Games/Riot Client/RiotClientServices.exe",
                "E:\\Games\\Riot Games\\League of Legends\\": "D:/Riot Games/Riot Client/RiotClientServices.exe"
            },
            "patchlines": {
                "KeystoneFoundationLiveWin": "D:/Riot Games/Riot Client/RiotClientServices.exe"
            },
            "rc_default": "D:/Riot Games/Riot Client/RiotClientServices.exe",
            "rc_live": "D:/Riot Games/Riot Client/RiotClientServices.exe"
        }"#;

        let parsed = parse_riot_client_installs_json(sample_json);
        assert_eq!(
            parsed.riot_client_exes,
            vec![PathBuf::from(
                r"D:\Riot Games\Riot Client\RiotClientServices.exe"
            )]
        );
        assert!(parsed
            .game_roots
            .contains(&PathBuf::from(r"D:\Riot Games\VALORANT\live")));
        assert!(parsed
            .game_roots
            .contains(&PathBuf::from(r"E:\Games\Riot Games\League of Legends")));

        // Malformed or non-object JSON degrades cleanly without panicking.
        assert_eq!(
            parse_riot_client_installs_json("not valid json"),
            RiotInstallLocations::default()
        );
        assert_eq!(
            parse_riot_client_installs_json("[]"),
            RiotInstallLocations::default()
        );

        // End-to-end discovery against a temporary directory tree simulating a non-C: Riot install.
        let root = std::env::temp_dir().join(format!(
            "vdpi_test_riot_installs_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let rc_exe = root.join(r"Riot Client\RiotClientServices.exe");
        let val_root = root.join(r"VALORANT\live");
        let val_exe = val_root.join(r"ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe");
        let lol_root = root.join(r"League of Legends");
        let lol_exe = lol_root.join("LeagueClient.exe");

        for file in [&rc_exe, &val_exe, &lol_exe] {
            std::fs::create_dir_all(file.parent().expect("parent")).expect("create riot dir");
            std::fs::write(file, b"").expect("write dummy riot exe");
        }

        let rc_json = rc_exe.to_string_lossy().replace('\\', "/");
        let val_json = format!("{}/", val_root.to_string_lossy().replace('\\', "/"));
        let lol_json = format!("{}/", lol_root.to_string_lossy().replace('\\', "/"));
        let mut associated = serde_json::Map::new();
        associated.insert(val_json, serde_json::Value::String(rc_json.clone()));
        associated.insert(lol_json, serde_json::Value::String(rc_json.clone()));
        let mut root_obj = serde_json::Map::new();
        root_obj.insert("rc_live".to_string(), serde_json::Value::String(rc_json));
        root_obj.insert(
            "associated_client".to_string(),
            serde_json::Value::Object(associated),
        );
        let manifest = serde_json::Value::Object(root_obj).to_string();

        let locs = parse_riot_client_installs_json(&manifest);
        let discovered = discover_riot_apps_from_locations(&locs, false);
        assert_eq!(discovered.len(), 3);
        assert!(discovered.iter().any(|a| {
            a.display_name == "Riot Client"
                && a.exe_name == "RiotClientServices.exe"
                && a.path.as_deref() == Some(rc_exe.to_string_lossy().as_ref())
                && a.category == AppCategory::Popular
        }));
        assert!(discovered.iter().any(|a| {
            a.display_name == "Valorant"
                && a.exe_name == "VALORANT-Win64-Shipping.exe"
                && a.path.as_deref() == Some(val_exe.to_string_lossy().as_ref())
                && a.category == AppCategory::Popular
        }));
        assert!(discovered.iter().any(|a| {
            a.display_name == "League of Legends"
                && a.exe_name == "LeagueClient.exe"
                && a.path.as_deref() == Some(lol_exe.to_string_lossy().as_ref())
                && a.category == AppCategory::Popular
        }));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn install_location_matching_uses_unicode_turkish_folding() {
        assert_eq!(fold_unicode_lower("İstanbul"), "istanbul");
        assert_eq!(fold_unicode_lower("DİSCORD"), "discord");
        assert_eq!(fold_unicode_lower("Yazılım"), "yazilim");
        assert_eq!(fold_unicode_lower("YAZILIM"), "yazilim");

        let root = std::env::temp_dir().join(format!(
            "vdpi_test_unicode_stem_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create unicode test dir");
        std::fs::write(root.join("istanbul.exe"), b"").expect("write istanbul.exe");
        std::fs::write(root.join("YAZILIM.exe"), b"").expect("write YAZILIM.exe");
        std::fs::write(root.join("unrelated.exe"), b"").expect("write unrelated.exe");

        let dir_str = root.to_string_lossy().into_owned();
        let matched_istanbul = find_exe_in_install_location(&dir_str, "İstanbul App")
            .expect("should match Turkish dotted İ");
        assert_eq!(matched_istanbul.0, "istanbul.exe");

        let matched_yazilim = find_exe_in_install_location(&dir_str, "Yazılım")
            .expect("should match Turkish dotless ı");
        assert_eq!(matched_yazilim.0, "YAZILIM.exe");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn deduplicate_riot_companion_apps_collapses_duplicate_ux_rows() {
        let apps = vec![
            DiscoveredApp {
                display_name: "Riot Client".to_string(),
                exe_name: "RiotClientUx.exe".to_string(),
                path: Some(r"D:\Riot Games\Riot Client\UX\RiotClientUx.exe".to_string()),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Riot Client".to_string(),
                exe_name: "RiotClientServices.exe".to_string(),
                path: Some(r"D:\Riot Games\Riot Client\RiotClientServices.exe".to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "LeagueClient.exe".to_string(),
                path: Some(r"D:\Riot Games\League of Legends\LeagueClient.exe".to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "LeagueClientUx.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Discord".to_string(),
                exe_name: "Discord.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
        ];

        let deduped = deduplicate_riot_companion_apps(apps);
        assert_eq!(deduped.len(), 3);

        let riot = deduped
            .iter()
            .find(|a| a.exe_name == "RiotClientServices.exe")
            .expect("single canonical Riot Client row");
        assert_eq!(riot.display_name, "Riot Client");
        assert!(riot.is_running);
        assert_eq!(riot.category, AppCategory::Running);
        assert_eq!(
            riot.path.as_deref(),
            Some(r"D:\Riot Games\Riot Client\RiotClientServices.exe")
        );

        let league = deduped
            .iter()
            .find(|a| a.exe_name == "LeagueClient.exe")
            .expect("single canonical League of Legends row");
        assert_eq!(league.display_name, "League of Legends");
        assert!(league.is_running);
        assert_eq!(league.category, AppCategory::Running);
        assert_eq!(
            league.path.as_deref(),
            Some(r"D:\Riot Games\League of Legends\LeagueClient.exe")
        );
    }

    #[test]
    fn round3_clutter_filters_block_suffixed_services_shell_hosts_and_keep_riot_client() {
        for clutter in [
            // Suffixed / embedded service and svc background helpers
            "RtkAudUService64.exe",
            "GameManagerService3.exe",
            "nvfvsdksvc_x64.exe",
            "BlueStacksServices.exe",
            "Corsair Device Control Service.exe",
            "Corsair Device Control Service (64-bit).exe",
            // Crash helpers, MSYS coreutils, game overlays, Windows shell hosts, vendor daemons
            "sentry-crash.exe",
            "cut.exe",
            "sed.exe",
            "tail.exe",
            "mktemp.exe",
            "UserOOBEBroker.exe",
            "CrossDeviceResume.exe",
            "ChxSmartScreen.exe",
            "MicrosoftStartFeedProvider.exe",
            "WidgetBoard.exe",
            "WSToastNotification.exe",
            "AppActions.exe",
            "vmware-authd.exe",
            "vmware-usbarbitrator64.exe",
            "MSI.CentralServer.exe",
            "MSI.TerminalServer.exe",
            "LEDKeeper2.exe",
            "CC_Engine_x64.exe",
            "vctip.exe",
            "GameOverlayUI.exe",
            "discord_clips.exe",
        ] {
            assert!(
                is_noise_process_name(clutter),
                "expected '{clutter}' to be filtered from [running]"
            );
            assert!(
                is_installer_or_noise_exe(clutter),
                "expected '{clutter}' to be filtered from [installed]"
            );
        }

        // RiotClientServices.exe contains `service` and must stay explicitly allowlisted.
        for preserved in [
            "RiotClientServices.exe",
            "riotclientservices.exe",
            "VALORANT-Win64-Shipping.exe",
            "LeagueClient.exe",
            "Discord.exe",
            "steam.exe",
        ] {
            assert!(
                !is_clutter_exe_pattern(&preserved.to_ascii_lowercase()),
                "expected '{preserved}' to bypass clutter pattern filter"
            );
            assert!(
                !is_noise_process_name(preserved),
                "expected '{preserved}' to stay visible in [running]"
            );
            assert!(
                !is_installer_or_noise_exe(preserved),
                "expected '{preserved}' to stay visible in [installed]"
            );
        }
    }

    #[test]
    fn deduplicate_riot_companion_apps_collapses_valorant_and_league_game_exes() {
        let valorant_path =
            r"D:\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe";
        let league_path = r"D:\Riot Games\League of Legends\LeagueClient.exe";

        let apps = vec![
            DiscoveredApp {
                display_name: "Valorant".to_string(),
                exe_name: "VALORANT.exe".to_string(),
                path: Some(r"D:\Riot Games\VALORANT\live\VALORANT.exe".to_string()),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Valorant".to_string(),
                exe_name: "VALORANT-Win64-Shipping.exe".to_string(),
                path: Some(valorant_path.to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "League of Legends.exe".to_string(),
                path: Some(
                    r"D:\Riot Games\League of Legends\Game\League of Legends.exe".to_string(),
                ),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "LeagueClient.exe".to_string(),
                path: Some(league_path.to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "LeagueClientUxRender.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Discord".to_string(),
                exe_name: "Discord.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
        ];

        let deduped = deduplicate_riot_companion_apps(apps);
        assert_eq!(deduped.len(), 3);

        let valorant = deduped
            .iter()
            .find(|a| a.exe_name == "VALORANT-Win64-Shipping.exe")
            .expect("single canonical Valorant row");
        assert_eq!(valorant.display_name, "Valorant");
        assert!(valorant.is_running);
        assert_eq!(valorant.category, AppCategory::Running);
        assert_eq!(valorant.path.as_deref(), Some(valorant_path));

        let league = deduped
            .iter()
            .find(|a| a.exe_name == "LeagueClient.exe")
            .expect("single canonical League of Legends row");
        assert_eq!(league.display_name, "League of Legends");
        assert!(league.is_running);
        assert_eq!(league.category, AppCategory::Running);
        assert_eq!(league.path.as_deref(), Some(league_path));

        // Reverse order (installed primary exe first, active game process second) collapses identically.
        let reverse_apps = vec![
            DiscoveredApp {
                display_name: "Valorant".to_string(),
                exe_name: "VALORANT-Win64-Shipping.exe".to_string(),
                path: Some(valorant_path.to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "Valorant".to_string(),
                exe_name: "VALORANT.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "LeagueClient.exe".to_string(),
                path: Some(league_path.to_string()),
                is_running: false,
                category: AppCategory::Popular,
            },
            DiscoveredApp {
                display_name: "League of Legends".to_string(),
                exe_name: "League of Legends.exe".to_string(),
                path: None,
                is_running: true,
                category: AppCategory::Running,
            },
        ];

        let reverse_deduped = deduplicate_riot_companion_apps(reverse_apps);
        assert_eq!(reverse_deduped.len(), 2);
        assert!(reverse_deduped.iter().any(|a| {
            a.exe_name == "VALORANT-Win64-Shipping.exe"
                && a.display_name == "Valorant"
                && a.is_running
                && a.category == AppCategory::Running
                && a.path.as_deref() == Some(valorant_path)
        }));
        assert!(reverse_deduped.iter().any(|a| {
            a.exe_name == "LeagueClient.exe"
                && a.display_name == "League of Legends"
                && a.is_running
                && a.category == AppCategory::Running
                && a.path.as_deref() == Some(league_path)
        }));
    }

    fn make_tcp_v4_row(ip: Ipv4Addr, port: u16, state: u32, pid: u32) -> MIB_TCPROW_OWNER_PID {
        MIB_TCPROW_OWNER_PID {
            dwState: state,
            dwLocalAddr: u32::from_ne_bytes(ip.octets()),
            dwLocalPort: u32::from(port.to_be()),
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: pid,
        }
    }

    fn make_tcp_v6_row(ip: Ipv6Addr, port: u16, state: u32, pid: u32) -> MIB_TCP6ROW_OWNER_PID {
        MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: ip.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: u32::from(port.to_be()),
            ucRemoteAddr: [0; 16],
            dwRemoteScopeId: 0,
            dwRemotePort: 0,
            dwState: state,
            dwOwningPid: pid,
        }
    }

    fn write_tcp_v4_table(
        ptr: *mut c_void,
        size_ptr: *mut u32,
        rows: &[MIB_TCPROW_OWNER_PID],
    ) -> u32 {
        let header_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
        let needed = header_offset + std::mem::size_of_val(rows);
        let avail = unsafe { *size_ptr } as usize;
        if ptr.is_null() || avail < needed {
            unsafe {
                *size_ptr = needed as u32;
            }
            return ERROR_INSUFFICIENT_BUFFER;
        }
        unsafe {
            let table_ptr = ptr.cast::<MIB_TCPTABLE_OWNER_PID>();
            (*table_ptr).dwNumEntries = rows.len() as u32;
            let dst = std::ptr::addr_of_mut!((*table_ptr).table).cast::<MIB_TCPROW_OWNER_PID>();
            std::ptr::copy_nonoverlapping(rows.as_ptr(), dst, rows.len());
            *size_ptr = needed as u32;
        }
        NO_ERROR
    }

    #[test]
    fn pid_snapshot_store_singleflight_cooldown_and_pre_capture_timestamp() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        assert_eq!(PID_SNAPSHOT_TTL, Duration::from_millis(2500));
        assert_eq!(
            PID_SNAPSHOT_MISS_REFRESH_COOLDOWN,
            Duration::from_millis(300)
        );

        // PID 0 short-circuits without invoking snapshot capture.
        let store = Arc::new(PidSnapshotStore::new());
        let zero_calls = Arc::new(AtomicUsize::new(0));
        let zc = Arc::clone(&zero_calls);
        assert_eq!(
            store.resolve_with(0, PID_SNAPSHOT_TTL, PID_SNAPSHOT_MISS_REFRESH_COOLDOWN, || {
                zc.fetch_add(1, Ordering::SeqCst);
                Some(HashMap::new())
            }),
            None
        );
        assert_eq!(zero_calls.load(Ordering::SeqCst), 0);

        // Concurrent burst on cold store shares one snapshot capture (singleflight).
        let burst_calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let s = Arc::clone(&store);
            let c = Arc::clone(&burst_calls);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                s.resolve_with(
                    42,
                    Duration::from_secs(5),
                    Duration::from_millis(300),
                    || {
                        c.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(25));
                        let mut map = HashMap::new();
                        map.insert(42, "discord.exe".to_string());
                        Some(map)
                    },
                )
            }));
        }
        for handle in handles {
            assert_eq!(
                handle.join().expect("thread join").as_deref(),
                Some("discord.exe")
            );
        }
        assert_eq!(burst_calls.load(Ordering::SeqCst), 1);

        // Missing/exited PIDs respect the minimum refresh cooldown instead of thrashing,
        // while still discovering newly spawned PIDs once the cooldown elapses.
        let cooldown_store = PidSnapshotStore::new();
        let cooldown_calls = AtomicUsize::new(0);
        let capture_map = || {
            let n = cooldown_calls.fetch_add(1, Ordering::SeqCst) + 1;
            let mut map = HashMap::new();
            map.insert(42, "discord.exe".to_string());
            if n >= 2 {
                map.insert(777, "chrome.exe".to_string());
            }
            Some(map)
        };
        let ttl = Duration::from_millis(600);
        let cooldown = Duration::from_millis(90);

        for _ in 0..5 {
            assert_eq!(
                cooldown_store.resolve_with(99999, ttl, cooldown, &capture_map),
                None
            );
        }
        assert_eq!(cooldown_calls.load(Ordering::SeqCst), 1);

        thread::sleep(Duration::from_millis(110));
        // Known PID still served from warm cache (< 600ms TTL).
        assert_eq!(
            cooldown_store
                .resolve_with(42, ttl, cooldown, &capture_map)
                .as_deref(),
            Some("discord.exe")
        );
        assert_eq!(cooldown_calls.load(Ordering::SeqCst), 1);
        // Newly spawned PID triggers one refresh after cooldown elapses.
        assert_eq!(
            cooldown_store
                .resolve_with(777, ttl, cooldown, &capture_map)
                .as_deref(),
            Some("chrome.exe")
        );
        assert_eq!(cooldown_calls.load(Ordering::SeqCst), 2);

        // `captured_at` is stamped BEFORE calling `capture_fn`: a 45ms capture with a
        // 60ms TTL must expire after sleeping 25ms (45 + 25 = 70ms >= 60ms).
        let stamp_store = PidSnapshotStore::new();
        let stamp_calls = AtomicUsize::new(0);
        let slow_capture = || {
            stamp_calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(45));
            let mut map = HashMap::new();
            map.insert(10, "app.exe".to_string());
            Some(map)
        };
        assert_eq!(
            stamp_store
                .resolve_with(
                    10,
                    Duration::from_millis(60),
                    Duration::from_millis(60),
                    &slow_capture
                )
                .as_deref(),
            Some("app.exe")
        );
        assert_eq!(stamp_calls.load(Ordering::SeqCst), 1);

        thread::sleep(Duration::from_millis(25));
        assert_eq!(
            stamp_store
                .resolve_with(
                    10,
                    Duration::from_millis(60),
                    Duration::from_millis(60),
                    &slow_capture
                )
                .as_deref(),
            Some("app.exe")
        );
        assert_eq!(stamp_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn fetch_iphlpapi_table_into_reuses_32kib_buffer_without_null_probe_and_grows() {
        assert_eq!(INITIAL_TABLE_BUFFER_BYTES, 32 * 1024);
        assert_eq!(IP_TABLE_SNAPSHOT_TTL, Duration::from_millis(50));

        let rows = [make_tcp_v4_row(Ipv4Addr::LOCALHOST, 5555, 5, 1234)];
        let mut buf: Vec<u64> = Vec::new();
        let mut calls = 0usize;

        let len1 = fetch_iphlpapi_table_into(&mut buf, |ptr, size_ptr| {
            calls += 1;
            assert!(!ptr.is_null(), "must not null-probe before fetching");
            let avail = unsafe { *size_ptr } as usize;
            assert!(avail >= INITIAL_TABLE_BUFFER_BYTES);
            write_tcp_v4_table(ptr, size_ptr, &rows)
        })
        .expect("initial fetch should succeed in one call");
        assert_eq!(calls, 1);
        assert_eq!(
            scan_tcp_v4_table(&buf, len1, Ipv4Addr::LOCALHOST, 5555),
            Some(1234)
        );

        let ptr_before = buf.as_ptr();
        let cap_before = buf.capacity();
        let len2 = fetch_iphlpapi_table_into(&mut buf, |ptr, size_ptr| {
            calls += 1;
            assert!(!ptr.is_null());
            write_tcp_v4_table(ptr, size_ptr, &rows)
        })
        .expect("reused buffer fetch should succeed");
        assert_eq!(calls, 2);
        assert_eq!(buf.as_ptr(), ptr_before);
        assert_eq!(buf.capacity(), cap_before);
        assert_eq!(
            scan_tcp_v4_table(&buf, len2, Ipv4Addr::LOCALHOST, 5555),
            Some(1234)
        );

        // Oversized table triggers growth + retry, then subsequent calls reuse the grown buffer.
        let required_bytes: usize = 48 * 1024;
        let len3 = fetch_iphlpapi_table_into(&mut buf, |ptr, size_ptr| {
            calls += 1;
            let avail = unsafe { *size_ptr } as usize;
            if avail < required_bytes {
                unsafe {
                    *size_ptr = required_bytes as u32;
                }
                ERROR_INSUFFICIENT_BUFFER
            } else {
                assert!(avail >= required_bytes + TABLE_BUFFER_HEADROOM);
                write_tcp_v4_table(ptr, size_ptr, &rows)
            }
        })
        .expect("grown buffer fetch should succeed");
        assert_eq!(calls, 4);
        assert_eq!(
            scan_tcp_v4_table(&buf, len3, Ipv4Addr::LOCALHOST, 5555),
            Some(1234)
        );

        let grown_cap = buf.capacity();
        let _ = fetch_iphlpapi_table_into(&mut buf, |ptr, size_ptr| {
            calls += 1;
            let avail = unsafe { *size_ptr } as usize;
            assert!(avail >= required_bytes + TABLE_BUFFER_HEADROOM);
            write_tcp_v4_table(ptr, size_ptr, &rows)
        })
        .expect("subsequent fetch should reuse grown buffer in one call");
        assert_eq!(calls, 5);
        assert_eq!(buf.capacity(), grown_cap);
    }

    #[test]
    fn ip_table_cache_singleflight_burst_and_ttl_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;

        let cache = Arc::new(IpTableCache::new());
        let rows = Arc::new(Mutex::new(
            (0..8u16)
                .map(|i| make_tcp_v4_row(Ipv4Addr::LOCALHOST, 50001 + i, 5, 101 + u32::from(i)))
                .collect::<Vec<_>>(),
        ));
        let fetch_calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(8));
        let ttl = Duration::from_millis(80);

        let mut handles = Vec::with_capacity(8);
        for i in 0..8u16 {
            let c = Arc::clone(&cache);
            let r = Arc::clone(&rows);
            let f = Arc::clone(&fetch_calls);
            let b = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                b.wait();
                let pid = c.lookup_with(
                    ttl,
                    |ptr, size_ptr| {
                        f.fetch_add(1, Ordering::SeqCst);
                        thread::sleep(Duration::from_millis(20));
                        let table = r.lock().unwrap();
                        write_tcp_v4_table(ptr, size_ptr, &table)
                    },
                    |buf, valid_bytes| {
                        scan_tcp_v4_table(buf, valid_bytes, Ipv4Addr::LOCALHOST, 50001 + i)
                    },
                );
                (i, pid)
            }));
        }

        for handle in handles {
            let (i, pid) = handle.join().expect("thread join");
            assert_eq!(pid, Some(101 + u32::from(i)));
        }
        assert_eq!(fetch_calls.load(Ordering::SeqCst), 1);

        // Subsequent lookup within TTL hits cached table without dumping again.
        let warm = cache.lookup_with(
            ttl,
            |ptr, size_ptr| {
                fetch_calls.fetch_add(1, Ordering::SeqCst);
                let table = rows.lock().unwrap();
                write_tcp_v4_table(ptr, size_ptr, &table)
            },
            |buf, valid_bytes| scan_tcp_v4_table(buf, valid_bytes, Ipv4Addr::LOCALHOST, 50003),
        );
        assert_eq!(warm, Some(103));
        assert_eq!(fetch_calls.load(Ordering::SeqCst), 1);

        // Brand-new socket created after snapshot refreshes on miss and resolves immediately.
        rows.lock()
            .unwrap()
            .push(make_tcp_v4_row(Ipv4Addr::LOCALHOST, 50099, 5, 999));
        let fresh = cache.lookup_with(
            ttl,
            |ptr, size_ptr| {
                fetch_calls.fetch_add(1, Ordering::SeqCst);
                let table = rows.lock().unwrap();
                write_tcp_v4_table(ptr, size_ptr, &table)
            },
            |buf, valid_bytes| scan_tcp_v4_table(buf, valid_bytes, Ipv4Addr::LOCALHOST, 50099),
        );
        assert_eq!(fresh, Some(999));
        assert_eq!(fetch_calls.load(Ordering::SeqCst), 2);

        // After TTL expires, even an already-known port triggers a fresh dump.
        thread::sleep(Duration::from_millis(100));
        let expired = cache.lookup_with(
            ttl,
            |ptr, size_ptr| {
                fetch_calls.fetch_add(1, Ordering::SeqCst);
                let table = rows.lock().unwrap();
                write_tcp_v4_table(ptr, size_ptr, &table)
            },
            |buf, valid_bytes| scan_tcp_v4_table(buf, valid_bytes, Ipv4Addr::LOCALHOST, 50001),
        );
        assert_eq!(expired, Some(101));
        assert_eq!(fetch_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn tcp_row_selection_prefers_active_states_over_listen_time_wait_and_closed() {
        let ip4 = Ipv4Addr::new(192, 168, 1, 10);
        let ip6 = Ipv6Addr::LOCALHOST;

        // Stale TIME_WAIT (11), CLOSED (1), and LISTEN (2) rows before an active state
        // must never shadow live connections (dwState in 3..=10).
        for active_state in 3..=10u32 {
            let v4_rows = [
                make_tcp_v4_row(ip4, 44321, 11, 111),           // TIME_WAIT
                make_tcp_v4_row(ip4, 44321, 1, 222),            // CLOSED
                make_tcp_v4_row(ip4, 44321, 2, 333),            // LISTEN
                make_tcp_v4_row(ip4, 44321, active_state, 444), // active
            ];
            assert_eq!(
                select_tcp_v4_pid(&v4_rows, ip4, 44321),
                Some(444),
                "IPv4 active state {active_state} must beat TIME_WAIT/CLOSED/LISTEN"
            );

            let v6_rows = [
                make_tcp_v6_row(ip6, 44321, 11, 111),
                make_tcp_v6_row(ip6, 44321, 1, 222),
                make_tcp_v6_row(ip6, 44321, 2, 333),
                make_tcp_v6_row(ip6, 44321, active_state, 444),
            ];
            assert_eq!(
                select_tcp_v6_pid(&v6_rows, ip6, 44321),
                Some(444),
                "IPv6 active state {active_state} must beat TIME_WAIT/CLOSED/LISTEN"
            );
        }

        // Without an active row, LISTEN beats TIME_WAIT and exact IP beats wildcard.
        let v4_inactive = [
            make_tcp_v4_row(Ipv4Addr::UNSPECIFIED, 8080, 2, 10),
            make_tcp_v4_row(ip4, 8080, 11, 20),
            make_tcp_v4_row(ip4, 8080, 2, 30),
        ];
        assert_eq!(select_tcp_v4_pid(&v4_inactive, ip4, 8080), Some(30));

        let v6_inactive = [
            make_tcp_v6_row(Ipv6Addr::UNSPECIFIED, 8080, 2, 10),
            make_tcp_v6_row(ip6, 8080, 11, 20),
            make_tcp_v6_row(ip6, 8080, 2, 30),
        ];
        assert_eq!(select_tcp_v6_pid(&v6_inactive, ip6, 8080), Some(30));

        // Standalone TIME_WAIT / wildcard LISTEN still resolve as fallback, and PID 0 is ignored.
        let v4_fallback = [
            make_tcp_v4_row(ip4, 9000, 5, 0),
            make_tcp_v4_row(ip4, 9000, 11, 77),
        ];
        assert_eq!(select_tcp_v4_pid(&v4_fallback, ip4, 9000), Some(77));

        let v6_wildcard = [make_tcp_v6_row(Ipv6Addr::UNSPECIFIED, 9001, 2, 88)];
        assert_eq!(select_tcp_v6_pid(&v6_wildcard, ip6, 9001), Some(88));
    }
}
