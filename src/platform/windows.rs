use crate::bypass::build_no_proxy_value;
use anyhow::{Context, Result};
use std::ffi::c_void;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{debug, info, warn};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const USER_ENV_KEY: &str = r"HKCU\Environment";

const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(
        h_internet: *mut c_void,
        dw_option: u32,
        lp_buffer: *mut c_void,
        dw_buffer_length: u32,
    ) -> i32;
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

        apply_wininet_proxy(&server_val, &proxy_override)?;

        if enable_env_proxy {
            let proxy_url = format!("http://{server_val}");
            set_windows_user_env(&proxy_url, &no_proxy_csv);
        }

        notify_wininet_refresh();

        info!(
            proxy = %server_val,
            env_proxy = enable_env_proxy,
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
        if self.env_configured {
            "active (Windows WinINET Registry + User Environment)".to_string()
        } else {
            "active (Windows WinINET Registry)".to_string()
        }
    }

    pub fn reconcile(&self) {
        let expected_server = format!("{}:{}", self.addr, self.http_port);
        let (enabled, current_server) = query_wininet_state();
        if !enabled || !current_server.eq_ignore_ascii_case(&expected_server) {
            if let Err(e) = apply_wininet_proxy(&expected_server, &self.proxy_override) {
                warn!(error = %e, "failed to reconcile Windows proxy settings");
            } else {
                notify_wininet_refresh();
            }
        }

        if self.env_configured {
            let expected_url = format!("http://{expected_server}");
            if query_reg_sz(USER_ENV_KEY, "HTTPS_PROXY").as_deref() != Some(expected_url.as_str()) {
                set_windows_user_env(&expected_url, &self.no_proxy_csv);
            }
        }
    }

    pub fn deactivate(&self) {
        let _ = clear_all_windows_proxies();
        debug!("restored Windows WinINET proxy state");
    }
}

pub fn clear_all_windows_proxies() -> Result<()> {
    let _ = run_reg(&[
        "add",
        INTERNET_SETTINGS_KEY,
        "/v",
        "ProxyEnable",
        "/t",
        "REG_DWORD",
        "/d",
        "0",
        "/f",
    ]);
    unset_windows_user_env();
    notify_wininet_refresh();
    Ok(())
}

pub fn print_windows_proxy_status() {
    let (enabled, server) = query_wininet_state();
    let override_val =
        query_reg_sz(INTERNET_SETTINGS_KEY, "ProxyOverride").unwrap_or_else(|| "<unset>".into());
    let https_env = query_reg_sz(USER_ENV_KEY, "HTTPS_PROXY").unwrap_or_else(|| "<unset>".into());

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
}

fn apply_wininet_proxy(server: &str, proxy_override: &str) -> Result<()> {
    run_reg(&[
        "add",
        INTERNET_SETTINGS_KEY,
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
        INTERNET_SETTINGS_KEY,
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
        INTERNET_SETTINGS_KEY,
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

fn set_windows_user_env(proxy_url: &str, no_proxy: &str) {
    for key in ["HTTP_PROXY", "HTTPS_PROXY"] {
        let _ = run_reg(&[
            "add",
            USER_ENV_KEY,
            "/v",
            key,
            "/t",
            "REG_SZ",
            "/d",
            proxy_url,
            "/f",
        ]);
    }
    let _ = run_reg(&[
        "add",
        USER_ENV_KEY,
        "/v",
        "NO_PROXY",
        "/t",
        "REG_SZ",
        "/d",
        no_proxy,
        "/f",
    ]);
    let _ = run_reg(&["delete", USER_ENV_KEY, "/v", "ALL_PROXY", "/f"]);
}

fn unset_windows_user_env() {
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"] {
        let _ = run_reg(&["delete", USER_ENV_KEY, "/v", key, "/f"]);
    }
}

fn query_wininet_state() -> (bool, String) {
    let enabled_raw = query_reg_sz(INTERNET_SETTINGS_KEY, "ProxyEnable").unwrap_or_default();
    let enabled = enabled_raw == "0x1" || enabled_raw == "1";
    let server = query_reg_sz(INTERNET_SETTINGS_KEY, "ProxyServer").unwrap_or_default();
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
        if trimmed
            .to_ascii_lowercase()
            .starts_with(&value_name.to_ascii_lowercase())
        {
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            if tokens.len() >= 3 {
                let idx = trimmed.find(tokens[1])? + tokens[1].len();
                let val = trimmed[idx..].trim();
                let _ = parts;
                return Some(val.to_string());
            }
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

fn notify_wininet_refresh() {
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
