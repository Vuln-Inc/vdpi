use crate::bypass::build_no_proxy_value;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

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

#[derive(Debug, Clone)]
pub struct WindowsProxySession {
    addr: IpAddr,
    http_port: u16,
    proxy_override: String,
    env_configured: bool,
    no_proxy_csv: String,
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
        let server_val = format!("{addr}:{http_port}");
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
            addr,
            http_port,
            proxy_override,
            env_configured: enable_env_proxy,
            no_proxy_csv,
        })
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
        let expected_server = format!("{}:{}", self.addr, self.http_port);
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
                if query_reg_sz(&env_key, "HTTPS_PROXY").as_deref() != Some(expected_url.as_str()) {
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
    for root in all_cleanup_roots() {
        let inet_key = internet_settings_key(&root);
        let _ = run_reg(&[
            "add",
            &inet_key,
            "/v",
            "ProxyEnable",
            "/t",
            "REG_DWORD",
            "/d",
            "0",
            "/f",
        ]);
        let env_key = user_env_key(&root);
        unset_windows_user_env(&env_key);
    }
    reset_winhttp_proxy_if_vdpi();
    notify_wininet_refresh();
    broadcast_environment_change();
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
    for line in text.lines() {
        if let Some((_, val)) = line.split_once(':') {
            let trimmed = val.trim();
            if trimmed.contains(':') && !trimmed.contains(' ') {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn apply_winhttp_proxy_if_safe(server: &str, bypass_list: &str) {
    // Only configure WinHTTP when no unrelated external proxy is already set.
    if let Some(current) = query_winhttp_proxy_server() {
        if current.eq_ignore_ascii_case(server) {
            return;
        }
        if !current.starts_with("127.0.0.1:") && !current.starts_with("[::1]:") {
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
    if let Some(current) = query_winhttp_proxy_server() {
        if current.starts_with("127.0.0.1:") || current.starts_with("[::1]:") {
            let _ = Command::new("netsh")
                .creation_flags(CREATE_NO_WINDOW)
                .args(["winhttp", "reset", "proxy"])
                .output();
        }
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
    let _ = run_reg(&["delete", env_key, "/v", "ALL_PROXY", "/f"]);
}

fn unset_windows_user_env(env_key: &str) {
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"] {
        let _ = run_reg(&["delete", env_key, "/v", key, "/f"]);
    }
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
