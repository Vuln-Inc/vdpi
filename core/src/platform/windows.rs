use crate::bypass::build_no_proxy_value;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};
use vdpi_core::config::VpnCoexistence;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub mod foreground;

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

static RUNNING_AS_SERVICE: AtomicBool = AtomicBool::new(false);

pub fn set_running_as_service(active: bool) {
    RUNNING_AS_SERVICE.store(active, Ordering::SeqCst);
}

pub fn is_running_as_service() -> bool {
    RUNNING_AS_SERVICE.load(Ordering::SeqCst)
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

pub fn is_vdpi_owned_wininet_server(s: &str) -> bool {
    let lower = s.trim().to_ascii_lowercase();
    lower.starts_with("127.0.0.1:") || lower.starts_with("[::1]:")
}

fn normalize_client_proxy_ip(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

#[derive(Debug, Clone)]
pub struct WindowsProxySession {
    addr: IpAddr,
    http_port: u16,
    proxy_override: String,
    env_configured: bool,
    no_proxy_csv: String,
    vpn_coexistence: VpnCoexistence,
}

impl WindowsProxySession {
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        _socks_port: Option<u16>,
        _enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        let client_ip = normalize_client_proxy_ip(addr);
        let server_val = SocketAddr::new(client_ip, http_port).to_string();
        let proxy_override = build_windows_proxy_override(extra_bypass);
        let no_proxy_csv = build_no_proxy_value(extra_bypass);
        let service_mode = is_running_as_service();
        let roots = target_proxy_roots();

        for root in &roots {
            let inet_key = internet_settings_key(root);
            if let Err(e) = apply_wininet_proxy(&inet_key, &server_val, &proxy_override) {
                if service_mode {
                    warn!(hive = %root, error = %e, "failed to apply WinINET proxy to user hive");
                } else {
                    return Err(e);
                }
            }

            if enable_env_proxy {
                let env_key = user_env_key(root);
                let proxy_url = format!("http://{server_val}");
                set_windows_user_env(&env_key, &proxy_url, &no_proxy_csv);
            }
        }

        if service_mode {
            apply_winhttp_proxy_if_safe(&server_val, &proxy_override);
        }

        notify_wininet_refresh();
        if enable_env_proxy {
            broadcast_environment_change();
        }

        info!(
            proxy = %server_val,
            env_proxy = enable_env_proxy,
            service_mode,
            hives = roots.len(),
            "configured Windows WinINET system proxy"
        );

        Ok(Self {
            addr: client_ip,
            http_port,
            proxy_override,
            env_configured: enable_env_proxy,
            no_proxy_csv,
            vpn_coexistence: VpnCoexistence::AutoYield,
        })
    }

    pub fn with_vpn_coexistence(mut self, mode: VpnCoexistence) -> Self {
        self.vpn_coexistence = mode;
        self
    }

    pub fn summary(&self) -> String {
        if is_running_as_service() {
            if self.env_configured {
                "active (Windows Service -> WinINET Registry + User Environment)".to_string()
            } else {
                "active (Windows Service -> WinINET Registry)".to_string()
            }
        } else if self.env_configured {
            "active (Windows WinINET Registry + User Environment)".to_string()
        } else {
            "active (Windows WinINET Registry)".to_string()
        }
    }

    pub fn reconcile(&self) {
        if self.vpn_coexistence != VpnCoexistence::Off
            && crate::platform::vpn::detect_active_vpn(None).is_full_tunnel()
        {
            debug!("full-tunnel VPN active; skipping Windows proxy reconciliation");
            return;
        }

        let expected_server =
            SocketAddr::new(normalize_client_proxy_ip(self.addr), self.http_port).to_string();
        let expected_url = format!("http://{expected_server}");
        let roots = target_proxy_roots();
        let mut wininet_changed = false;
        let mut env_changed = false;

        for root in &roots {
            let inet_key = internet_settings_key(root);
            let (enabled, current_server) = query_wininet_state(&inet_key);
            if !enabled || !current_server.eq_ignore_ascii_case(&expected_server) {
                if let Err(e) =
                    apply_wininet_proxy(&inet_key, &expected_server, &self.proxy_override)
                {
                    warn!(hive = %root, error = %e, "failed to reconcile Windows proxy settings");
                } else {
                    wininet_changed = true;
                }
            }

            if self.env_configured {
                let env_key = user_env_key(root);
                if query_reg_sz(&env_key, "HTTP_PROXY").as_deref() != Some(expected_url.as_str())
                    || query_reg_sz(&env_key, "HTTPS_PROXY").as_deref()
                        != Some(expected_url.as_str())
                {
                    set_windows_user_env(&env_key, &expected_url, &self.no_proxy_csv);
                    env_changed = true;
                }
            }
        }

        if is_running_as_service() {
            apply_winhttp_proxy_if_safe(&expected_server, &self.proxy_override);
        }
        if wininet_changed {
            notify_wininet_refresh();
        }
        if env_changed {
            broadcast_environment_change();
        }
    }

    pub fn deactivate(&self) {
        let _ = clear_all_windows_proxies();
        debug!("restored Windows WinINET proxy state");
    }
}

pub fn clear_all_windows_proxies() -> Result<()> {
    let mut wininet_changed = false;
    let mut env_changed = false;
    for root in all_cleanup_roots() {
        let inet_key = internet_settings_key(&root);
        let (enabled, server) = query_wininet_state(&inet_key);
        if enabled
            && is_vdpi_owned_wininet_server(&server)
            && run_reg(&[
                "add",
                &inet_key,
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
            wininet_changed = true;
        }
        let env_key = user_env_key(&root);
        if unset_windows_user_env(&env_key) {
            env_changed = true;
        }
    }
    reset_winhttp_proxy_if_vdpi();
    if wininet_changed {
        notify_wininet_refresh();
    }
    if env_changed {
        broadcast_environment_change();
    }
    Ok(())
}

fn query_winhttp_proxy_server() -> Option<String> {
    let out = Command::new("netsh")
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

fn apply_winhttp_proxy_if_safe(server: &str, bypass_list: &str) {
    // Only configure WinHTTP when no unrelated external proxy is already set.
    if let Some(current) = query_winhttp_proxy_server() {
        if current.eq_ignore_ascii_case(server) {
            return;
        }
        if !is_vdpi_owned_wininet_server(&current) {
            return;
        }
    }
    let proxy_arg = format!("proxy-server={server}");
    let bypass_arg = format!("bypass-list={bypass_list}");
    let _ = Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["winhttp", "set", "proxy", &proxy_arg, &bypass_arg])
        .output();
}

fn reset_winhttp_proxy_if_vdpi() {
    if query_winhttp_proxy_server()
        .as_deref()
        .is_some_and(is_vdpi_owned_wininet_server)
    {
        let _ = Command::new("netsh")
            .creation_flags(CREATE_NO_WINDOW)
            .args(["winhttp", "reset", "proxy"])
            .output();
    }
}

pub fn print_windows_proxy_status() {
    let inet_key = internet_settings_key("HKCU");
    let env_key = user_env_key("HKCU");
    let (enabled, server) = query_wininet_state(&inet_key);
    let override_val = query_reg_sz(&inet_key, "ProxyOverride").unwrap_or_else(|| "<unset>".into());
    let https_env = query_reg_sz(&env_key, "HTTPS_PROXY").unwrap_or_else(|| "<unset>".into());

    println!("\n=== Windows System Proxy (WinINET) ===");
    println!(
        "ProxyEnable               : {}",
        if enabled { "ON (1)" } else { "OFF (0)" }
    );
    println!(
        "ProxyServer               : {}",
        if server.is_empty() {
            "<unset>"
        } else {
            &server
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
    let Ok(out) = Command::new("reg")
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
        let mut roots = vec!["HKCU".to_string()];
        for hku in enumerate_interactive_hku_roots() {
            if !roots.iter().any(|r| r.eq_ignore_ascii_case(&hku)) {
                roots.push(hku);
            }
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

fn apply_wininet_proxy(inet_key: &str, server: &str, proxy_override: &str) -> Result<()> {
    run_reg(&[
        "add",
        inet_key,
        "/v",
        "ProxyServer",
        "/t",
        "REG_SZ",
        "/d",
        server,
        "/f",
    ])?;
    run_reg(&[
        "add",
        inet_key,
        "/v",
        "ProxyOverride",
        "/t",
        "REG_SZ",
        "/d",
        proxy_override,
        "/f",
    ])?;
    run_reg(&[
        "add",
        inet_key,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "1",
        "/f",
    ])?;
    Ok(())
}

fn set_windows_user_env(env_key: &str, proxy_url: &str, no_proxy: &str) {
    for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
        let _ = run_reg(&[
            "add", env_key, "/v", key, "/t", "REG_SZ", "/d", proxy_url, "/f",
        ]);
    }
    let _ = run_reg(&[
        "add", env_key, "/v", "NO_PROXY", "/t", "REG_SZ", "/d", no_proxy, "/f",
    ]);
    if query_reg_sz(env_key, "ALL_PROXY")
        .as_deref()
        .is_some_and(is_vdpi_owned_proxy_env)
    {
        let _ = run_reg(&["delete", env_key, "/v", "ALL_PROXY", "/f"]);
    }
}

fn is_vdpi_owned_proxy_env(val: &str) -> bool {
    let lower = val.trim().to_ascii_lowercase();
    lower.starts_with("http://127.0.0.1:") || lower.starts_with("http://[::1]:")
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

fn query_wininet_state(inet_key: &str) -> (bool, String) {
    let enabled_raw = query_reg_sz(inet_key, "ProxyEnable").unwrap_or_default();
    let enabled = enabled_raw == "0x1" || enabled_raw == "1";
    let server = query_reg_sz(inet_key, "ProxyServer").unwrap_or_default();
    (enabled, server)
}

pub fn query_reg_sz(key: &str, value_name: &str) -> Option<String> {
    let out = Command::new("reg")
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
    let out = Command::new("reg")
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

fn build_windows_proxy_override(extra: &[String]) -> String {
    let mut entries: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "10.*".into(),
        "172.16.*".into(),
        "192.168.*".into(),
        "169.254.*".into(),
        "*.local".into(),
        "*.lan".into(),
        "*.gov.tr".into(),
        "*.bel.tr".into(),
        "*.org.tr".into(),
        "*.osym.gov.tr".into(),
        "*.bkm.com.tr".into(),
        "paratika.com.tr".into(),
        "*.halkbank.com.tr".into(),
        "*.isbank.com.tr".into(),
        "*.akbank.com".into(),
        "*.akbank.com.tr".into(),
        "*.garantibbva.com.tr".into(),
        "*.ziraatbank.com.tr".into(),
        "*.yapikredi.com.tr".into(),
        "*.vakifbank.com.tr".into(),
        "*.turktelekom.com.tr".into(),
        "*.pttavm.com".into(),
    ];
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
        assert!(!is_vdpi_owned_proxy_env("http://proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_proxy_env("socks5://127.0.0.1:1080"));
        assert!(!is_vdpi_owned_proxy_env(""));
    }

    #[test]
    fn wininet_server_ownership_matches_only_vdpi_loopback() {
        assert!(is_vdpi_owned_wininet_server("127.0.0.1:8080"));
        assert!(is_vdpi_owned_wininet_server(" 127.0.0.1:18080 "));
        assert!(is_vdpi_owned_wininet_server("[::1]:8080"));
        assert!(is_vdpi_owned_wininet_server(" [::1]:18080 "));
        assert!(!is_vdpi_owned_wininet_server("proxy.corp.local:3128"));
        assert!(!is_vdpi_owned_wininet_server("::1:8080"));
        assert!(!is_vdpi_owned_wininet_server("http://127.0.0.1:8080"));
        assert!(!is_vdpi_owned_wininet_server(""));
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
}
