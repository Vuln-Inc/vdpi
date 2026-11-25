use crate::bypass::build_no_proxy_value;
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::{debug, info, warn};

const ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

fn normalize_proxy_addr(addr: IpAddr) -> IpAddr {
    match addr {
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

fn proxy_server_matches(current_server: &str, expected_addr: IpAddr) -> bool {
    let trimmed = current_server
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    trimmed
        .parse::<IpAddr>()
        .is_ok_and(|parsed| parsed == expected_addr)
        || trimmed == expected_addr.to_string()
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

#[derive(Debug, Clone)]
pub struct NetworkServiceProxyStatus {
    pub service: String,
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

#[derive(Debug, Clone)]
pub struct MacosProxySession {
    addr: IpAddr,
    http_port: u16,
    socks_port: Option<u16>,
    services: Vec<String>,
    socks_configured: bool,
    launchd_configured: bool,
    activated: bool,
    no_proxy_csv: String,
}

impl MacosProxySession {
    /// Applies macOS system proxy settings (`networksetup`) and optional `launchctl setenv`
    /// proxy variables across active physical/Wi-Fi network services. Skips overriding
    /// proxy settings while a full-tunnel VPN is active.
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_launchd_env: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        let addr = normalize_proxy_addr(addr);
        let services = list_configurable_network_services().unwrap_or_default();
        let socks_configured = enable_socks_system_proxy && socks_port.is_some();

        if is_vpn_default_route_active() {
            let no_proxy_csv = build_no_proxy_value(extra_bypass);
            info!(
                services = ?services,
                http_port = http_port,
                socks_port = ?socks_port,
                launchd_env = enable_launchd_env,
                "full-tunnel VPN active; skipping macOS system proxy activation"
            );
            return Ok(Self {
                addr,
                http_port,
                socks_port,
                services,
                socks_configured,
                launchd_configured: enable_launchd_env,
                activated: false,
                no_proxy_csv,
            });
        }

        let addr_str = addr.to_string();
        let port_str = http_port.to_string();

        let mut merged_bypass_all = extra_bypass.to_vec();

        for svc in &services {
            match get_proxy_bypass_domains(svc) {
                Ok(existing) => {
                    for d in &existing {
                        if !merged_bypass_all.iter().any(|x| x.eq_ignore_ascii_case(d)) {
                            merged_bypass_all.push(d.clone());
                        }
                    }
                    let merged_svc = merge_service_bypass_domains(&existing, extra_bypass);
                    if let Err(e) = set_proxy_bypass_domains(svc, &merged_svc) {
                        warn!(service = %svc, error = %e, "failed to update proxy bypass domains");
                    }
                }
                Err(e) => {
                    warn!(
                        service = %svc,
                        error = %e,
                        "failed to read existing proxy bypass domains; skipping bypass domain update"
                    );
                }
            }

            if let Err(e) = run_networksetup(&["-setwebproxy", svc, &addr_str, &port_str])
                .and_then(|_| run_networksetup(&["-setwebproxystate", svc, "on"]))
            {
                warn!(service = %svc, error = %e, "failed to enable HTTP web proxy");
            }

            if let Err(e) = run_networksetup(&["-setsecurewebproxy", svc, &addr_str, &port_str])
                .and_then(|_| run_networksetup(&["-setsecurewebproxystate", svc, "on"]))
            {
                warn!(service = %svc, error = %e, "failed to enable HTTPS secure web proxy");
            }

            if let (true, Some(sp)) = (socks_configured, socks_port) {
                let sp_str = sp.to_string();
                if let Err(e) =
                    run_networksetup(&["-setsocksfirewallproxy", svc, &addr_str, &sp_str])
                        .and_then(|_| run_networksetup(&["-setsocksfirewallproxystate", svc, "on"]))
                {
                    warn!(service = %svc, error = %e, "failed to enable SOCKS5 firewall proxy");
                }
            }
        }

        let no_proxy_csv = build_no_proxy_value(&merged_bypass_all);
        if enable_launchd_env {
            let proxy_url = format_proxy_url(addr, http_port);
            set_launchd_proxy_env(&proxy_url, &no_proxy_csv);
        }

        info!(
            services = ?services,
            http_port = http_port,
            socks_port = ?socks_port,
            launchd_env = enable_launchd_env,
            "configured macOS system proxies"
        );

        Ok(Self {
            addr,
            http_port,
            socks_port,
            services,
            socks_configured,
            launchd_configured: enable_launchd_env,
            activated: true,
            no_proxy_csv,
        })
    }

    pub fn summary(&self) -> String {
        if !self.activated {
            return "standby (full-tunnel VPN active; macOS system proxy skipped)".to_string();
        }
        if self.launchd_configured {
            format!(
                "active (macOS networksetup [{}] + launchd session env)",
                self.services.join(", ")
            )
        } else {
            format!("active (macOS networksetup [{}])", self.services.join(", "))
        }
    }

    /// Periodically verifies that sleep/wake cycles or VPN disconnects have not wiped
    /// proxy settings on physical interfaces. Avoids touching settings while a full-tunnel VPN
    /// is active.
    pub fn reconcile(&self) {
        if is_vpn_default_route_active() {
            debug!("full-tunnel VPN active; skipping macOS proxy reconciliation");
            return;
        }

        let addr_str = self.addr.to_string();
        let port_str = self.http_port.to_string();

        if let Ok(statuses) = inspect_service_proxies() {
            for st in statuses {
                if !st.web_enabled
                    || !proxy_server_matches(&st.web_server, self.addr)
                    || st.web_port != port_str
                {
                    let _ = run_networksetup(&["-setwebproxy", &st.service, &addr_str, &port_str]);
                    let _ = run_networksetup(&["-setwebproxystate", &st.service, "on"]);
                }
                if !st.secure_enabled
                    || !proxy_server_matches(&st.secure_server, self.addr)
                    || st.secure_port != port_str
                {
                    let _ = run_networksetup(&[
                        "-setsecurewebproxy",
                        &st.service,
                        &addr_str,
                        &port_str,
                    ]);
                    let _ = run_networksetup(&["-setsecurewebproxystate", &st.service, "on"]);
                }
                if let (true, Some(sp)) = (self.socks_configured, self.socks_port) {
                    let sp_str = sp.to_string();
                    if !st.socks_enabled
                        || !proxy_server_matches(&st.socks_server, self.addr)
                        || st.socks_port != sp_str
                    {
                        let _ = run_networksetup(&[
                            "-setsocksfirewallproxy",
                            &st.service,
                            &addr_str,
                            &sp_str,
                        ]);
                        let _ =
                            run_networksetup(&["-setsocksfirewallproxystate", &st.service, "on"]);
                    }
                }
            }
        }

        if self.launchd_configured {
            let expected_url = format_proxy_url(self.addr, self.http_port);
            if read_launchd_env("HTTPS_PROXY").as_deref() != Some(expected_url.as_str()) {
                set_launchd_proxy_env(&expected_url, &self.no_proxy_csv);
            }
        }
    }

    fn deactivate_owned_proxies(&self) {
        let mut services = list_configurable_network_services().unwrap_or_default();
        for svc in &self.services {
            if !services.iter().any(|s| s == svc) {
                services.push(svc.clone());
            }
        }

        let http = self.http_port.to_string();
        let socks = self.socks_port.map(|p| p.to_string());

        for svc in &services {
            let st = inspect_single_service_proxy(svc);
            if st.web_enabled
                && proxy_server_matches(&st.web_server, self.addr)
                && st.web_port == http
            {
                let _ = run_networksetup(&["-setwebproxystate", &st.service, "off"]);
            }
            if st.secure_enabled
                && proxy_server_matches(&st.secure_server, self.addr)
                && st.secure_port == http
            {
                let _ = run_networksetup(&["-setsecurewebproxystate", &st.service, "off"]);
            }
            if self.socks_configured
                && st.socks_enabled
                && proxy_server_matches(&st.socks_server, self.addr)
                && socks.as_deref() == Some(st.socks_port.as_str())
            {
                let _ = run_networksetup(&["-setsocksfirewallproxystate", &st.service, "off"]);
            }
        }

        if self.launchd_configured {
            let expected_url = format_proxy_url(self.addr, self.http_port);
            let expected_socks_url = self.socks_port.map(|p| format_proxy_url(self.addr, p));
            unset_launchd_proxy_env_if_owned(&expected_url, expected_socks_url.as_deref());
        }
    }

    /// Cleanly disables vdpi-owned proxy states on all active managed services (including
    /// adapters plugged in after startup) and removes vdpi-owned `launchd` proxy env vars.
    pub fn deactivate(&self) {
        self.deactivate_owned_proxies();
        debug!("restored macOS system proxy state");
    }

    pub(super) fn deactivate_foreground(&self) {
        self.deactivate_owned_proxies();
    }
}

fn is_vpn_default_route_active() -> bool {
    crate::platform::vpn::detect_active_vpn(None).is_full_tunnel()
}

/// Explicitly disables HTTP, HTTPS, and SOCKS5 proxies across all configurable macOS network
/// services and clears `launchctl` proxy environment variables.
pub fn clear_all_macos_proxies() -> Result<()> {
    let services = list_configurable_network_services()?;
    for svc in &services {
        let _ = run_networksetup(&["-setwebproxystate", svc, "off"]);
        let _ = run_networksetup(&["-setsecurewebproxystate", svc, "off"]);
        let _ = run_networksetup(&["-setsocksfirewallproxystate", svc, "off"]);
    }
    unset_launchd_proxy_env();
    Ok(())
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
                "- {}:\n    HTTP  : {} ({}:{})\n    HTTPS : {} ({}:{})\n    SOCKS5: {} ({}:{})",
                s.service,
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
            || lower == "iphone usb"
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

fn merge_service_bypass_domains(existing: &[String], extra: &[String]) -> Vec<String> {
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
    for baseline in [
        "localhost",
        "127.0.0.1",
        "*.local",
        "169.254/16",
        "192.168.*",
        "10.*",
        "*.gov.tr",
        "*.org.tr",
        "*.osym.gov.tr",
        "*.bkm.com.tr",
        "paratika.com.tr",
        "*.halkbank.com.tr",
        "*.isbank.com.tr",
        "*.turktelekom.com.tr",
        "*.pttavm.com",
    ] {
        push_unique(baseline);
    }
    for item in extra {
        push_unique(item);
    }
    out
}

fn set_proxy_bypass_domains(service: &str, domains: &[String]) -> Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    let mut args: Vec<&str> = Vec::with_capacity(2 + domains.len());
    args.push("-setproxybypassdomains");
    args.push(service);
    for d in domains {
        args.push(d.as_str());
    }
    run_networksetup(&args).map(|_| ())
}

pub fn set_launchd_proxy_env(proxy_url: &str, no_proxy: &str) {
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        let _ = Command::new("/bin/launchctl")
            .args(["setenv", key, proxy_url])
            .output();
    }
    for key in ["NO_PROXY", "no_proxy"] {
        let _ = Command::new("/bin/launchctl")
            .args(["setenv", key, no_proxy])
            .output();
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        if read_launchd_env(key)
            .is_some_and(|current| is_vdpi_owned_proxy_env_value(&current, proxy_url))
        {
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
}

fn unset_launchd_proxy_env_if_owned(expected_url: &str, expected_socks_url: Option<&str>) {
    let mut owned_any = false;
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        if read_launchd_env(key)
            .is_some_and(|current| is_vdpi_owned_proxy_env_value(&current, expected_url))
        {
            owned_any = true;
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
    if owned_any {
        for key in ["NO_PROXY", "no_proxy"] {
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        if read_launchd_env(key).is_some_and(|current| {
            is_vdpi_owned_proxy_env_value(&current, expected_url)
                || expected_socks_url
                    .is_some_and(|socks| is_vdpi_owned_proxy_env_value(&current, socks))
        }) {
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
}

pub fn unset_launchd_proxy_env() {
    for key in ENV_KEYS {
        let _ = Command::new("/bin/launchctl")
            .args(["unsetenv", key])
            .output();
    }
}

pub fn read_launchd_env(key: &str) -> Option<String> {
    let out = Command::new("/bin/launchctl")
        .args(["getenv", key])
        .output()
        .ok()?;
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
    let web = run_networksetup(&["-getwebproxy", svc]).unwrap_or_default();
    let sec = run_networksetup(&["-getsecurewebproxy", svc]).unwrap_or_default();
    let socks = run_networksetup(&["-getsocksfirewallproxy", svc]).unwrap_or_default();

    let (web_enabled, web_server, web_port) = parse_proxy_kv(&web);
    let (secure_enabled, secure_server, secure_port) = parse_proxy_kv(&sec);
    let (socks_enabled, socks_server, socks_port) = parse_proxy_kv(&socks);

    NetworkServiceProxyStatus {
        service: svc.to_string(),
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
        assert_eq!(parsed, vec!["USB 10/100/1000 LAN", "Wi-Fi"]);
    }

    #[test]
    fn merges_bypass_domains_without_losing_user_entries() {
        let existing = vec![" *.gov.tr".into(), "custom.internal.tr".into()];
        let merged = merge_service_bypass_domains(&existing, &["extra.example.com".into()]);
        assert!(merged.contains(&"*.gov.tr".to_string()));
        assert!(merged.contains(&"custom.internal.tr".to_string()));
        assert!(merged.contains(&"extra.example.com".to_string()));
        for expected in [
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
    fn reflects_standby_when_proxy_activation_skipped_for_vpn() {
        let session = MacosProxySession {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: 8080,
            socks_port: None,
            services: vec!["Wi-Fi".to_string()],
            socks_configured: false,
            launchd_configured: true,
            activated: false,
            no_proxy_csv: String::new(),
        };
        assert!(session.summary().starts_with("standby"));
    }

    #[test]
    fn matches_owned_proxy_servers_and_env_values() {
        assert!(proxy_server_matches(
            "127.0.0.1",
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
        assert!(proxy_server_matches("::1", IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(proxy_server_matches(
            "[::1]",
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        ));
        assert!(!proxy_server_matches(
            "10.0.0.1",
            IpAddr::V4(Ipv4Addr::LOCALHOST)
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
}
