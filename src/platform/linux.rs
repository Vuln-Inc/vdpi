use crate::bypass::build_no_proxy_value;
use anyhow::Result;
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, info};

#[derive(Debug, Clone)]
pub struct LinuxProxySession {
    addr: IpAddr,
    http_port: u16,
    socks_port: Option<u16>,
    socks_configured: bool,
    gnome_configured: bool,
    kde_bin: Option<String>,
    systemd_env_configured: bool,
    no_proxy_csv: String,
    gsettings_ignore: String,
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
        let addr_str = addr.to_string();
        let port_str = http_port.to_string();
        let socks_configured = enable_socks_system_proxy && socks_port.is_some();
        let no_proxy_csv = build_no_proxy_value(extra_bypass);
        let gsettings_ignore = build_gsettings_ignore_hosts(extra_bypass);

        let gnome_configured = configure_gnome_proxy(
            &addr_str,
            &port_str,
            if socks_configured { socks_port } else { None },
            &gsettings_ignore,
        );

        let kde_bin = detect_kde_writer();
        if let Some(ref kbin) = kde_bin {
            configure_kde_proxy(
                kbin,
                &addr_str,
                http_port,
                if socks_configured { socks_port } else { None },
                &no_proxy_csv,
            );
        }

        let systemd_env_configured = if enable_env_proxy {
            let proxy_url = format!("http://{addr_str}:{http_port}");
            set_systemd_user_env(&proxy_url, &no_proxy_csv)
        } else {
            false
        };

        info!(
            gnome = gnome_configured,
            kde = kde_bin.is_some(),
            systemd_env = systemd_env_configured,
            "configured Linux desktop proxy integration"
        );

        Ok(Self {
            addr,
            http_port,
            socks_port,
            socks_configured,
            gnome_configured,
            kde_bin,
            systemd_env_configured,
            no_proxy_csv,
            gsettings_ignore,
        })
    }

    pub fn summary(&self) -> String {
        let mut backends = Vec::new();
        if self.gnome_configured {
            backends.push("GNOME gsettings");
        }
        if self.kde_bin.is_some() {
            backends.push("KDE kioslaverc");
        }
        if self.systemd_env_configured {
            backends.push("systemd user env");
        }
        if backends.is_empty() {
            "listening (export HTTP_PROXY / HTTPS_PROXY manually on headless Linux)".to_string()
        } else {
            format!("active ({})", backends.join(" + "))
        }
    }

    pub fn reconcile(&self) {
        if self.gnome_configured {
            if let Ok(out) = Command::new("gsettings")
                .args(["get", "org.gnome.system.proxy", "mode"])
                .output()
            {
                let mode = String::from_utf8_lossy(&out.stdout);
                if !mode.contains("manual") {
                    let _ = configure_gnome_proxy(
                        &self.addr.to_string(),
                        &self.http_port.to_string(),
                        if self.socks_configured {
                            self.socks_port
                        } else {
                            None
                        },
                        &self.gsettings_ignore,
                    );
                }
            }
        }
        if self.systemd_env_configured {
            let proxy_url = format!("http://{}:{}", self.addr, self.http_port);
            let _ = set_systemd_user_env(&proxy_url, &self.no_proxy_csv);
        }
    }

    pub fn deactivate(&self) {
        let _ = clear_all_linux_proxies();
        debug!("restored Linux desktop proxy settings");
    }
}

pub fn clear_all_linux_proxies() -> Result<()> {
    if command_exists("gsettings") {
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy", "mode", "none"])
            .output();
    }
    if let Some(kbin) = detect_kde_writer() {
        let _ = Command::new(&kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "ProxyType",
                "0",
            ])
            .output();
        notify_kde_reload();
    }
    if command_exists("systemctl") {
        let _ = Command::new("systemctl")
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
    Ok(())
}

pub fn print_linux_proxy_status() {
    println!("\n=== Linux Desktop Proxy Integration ===");
    if command_exists("gsettings") {
        let mode = Command::new("gsettings")
            .args(["get", "org.gnome.system.proxy", "mode"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "<unavailable>".into());
        println!("GNOME proxy mode          : {mode}");
    }
    if command_exists("systemctl") {
        let env_out = Command::new("systemctl")
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

fn configure_gnome_proxy(
    addr: &str,
    http_port: &str,
    socks_port: Option<u16>,
    ignore_hosts: &str,
) -> bool {
    if !command_exists("gsettings") {
        return false;
    }
    let probe = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .output();
    if !matches!(probe, Ok(ref o) if o.status.success()) {
        return false;
    }

    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "host", addr])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "port", http_port])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.http", "enabled", "true"])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "host", addr])
        .output();
    let _ = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy.https", "port", http_port])
        .output();

    if let Some(sp) = socks_port {
        let sp_str = sp.to_string();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "host", addr])
            .output();
        let _ = Command::new("gsettings")
            .args(["set", "org.gnome.system.proxy.socks", "port", &sp_str])
            .output();
    }

    let _ = Command::new("gsettings")
        .args([
            "set",
            "org.gnome.system.proxy",
            "ignore-hosts",
            ignore_hosts,
        ])
        .output();
    let res = Command::new("gsettings")
        .args(["set", "org.gnome.system.proxy", "mode", "manual"])
        .output();

    matches!(res, Ok(o) if o.status.success())
}

fn detect_kde_writer() -> Option<String> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !desktop.contains("kde") && !desktop.contains("plasma") {
        return None;
    }
    for candidate in ["kwriteconfig6", "kwriteconfig5"] {
        if command_exists(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn configure_kde_proxy(
    kbin: &str,
    addr: &str,
    http_port: u16,
    socks_port: Option<u16>,
    no_proxy_csv: &str,
) {
    let http_val = format!("http://{addr} {http_port}");
    for (k, v) in [
        ("ProxyType", "1"),
        ("httpProxy", http_val.as_str()),
        ("httpsProxy", http_val.as_str()),
        ("NoProxyFor", no_proxy_csv),
    ] {
        let _ = Command::new(kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                k,
                v,
            ])
            .output();
    }
    if let Some(sp) = socks_port {
        let socks_val = format!("socks://{addr} {sp}");
        let _ = Command::new(kbin)
            .args([
                "--file",
                "kioslaverc",
                "--group",
                "Proxy Settings",
                "--key",
                "socksProxy",
                &socks_val,
            ])
            .output();
    }
    notify_kde_reload();
}

fn notify_kde_reload() {
    if command_exists("dbus-send") {
        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ])
            .output();
    }
}

fn set_systemd_user_env(proxy_url: &str, no_proxy: &str) -> bool {
    if !command_exists("systemctl") {
        return false;
    }
    let res = Command::new("systemctl")
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
    let _ = Command::new("systemctl")
        .args(["--user", "unset-environment", "ALL_PROXY", "all_proxy"])
        .output();
    matches!(res, Ok(o) if o.status.success())
}

fn build_gsettings_ignore_hosts(extra: &[String]) -> String {
    let mut items: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.0/8".into(),
        "::1".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        ".local".into(),
        ".gov.tr".into(),
        ".isbank.com.tr".into(),
    ];
    for entry in extra {
        let clean = entry.trim().trim_start_matches('*');
        if !clean.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(clean)) {
            items.push(clean.to_string());
        }
    }
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("'{}'", s.replace('\'', "")))
        .collect();
    format!("[{}]", quoted.join(", "))
}

pub fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
