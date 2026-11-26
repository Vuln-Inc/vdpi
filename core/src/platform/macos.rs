use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

pub const PAC_PATH: &str = "/vdpi.pac";

const ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
];

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

fn macos_proxy_state_path() -> PathBuf {
    crate::service::vdpi_root_dir()
        .map(|root| root.join("macos-proxy-state.json"))
        .unwrap_or_else(|_| {
            PathBuf::from("/Library/Application Support/vdpi/macos-proxy-state.json")
        })
}

fn write_file_atomic(path: &Path, contents: &str) -> Result<()> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("macos-proxy-state.json");
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{file_name}.{}.{seq}.tmp", std::process::id()));

    fs::write(&tmp_path, contents)
        .with_context(|| format!("failed to write temporary state {}", tmp_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
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

fn remove_state_file(path: &Path) {
    if let Err(err) = fs::remove_file(path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            warn!(path = %path.display(), error = %err, "failed to remove macOS proxy state file");
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
    fn to_saved_state(&self) -> SavedServiceProxyState {
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
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacosProxySession {
    pac_url: String,
    services: Vec<String>,
    saved_state: SavedMacosProxyState,
    activated: bool,
}

impl MacosProxySession {
    /// Applies macOS fail-open AutoProxyURL (PAC) settings via `networksetup` across active
    /// physical/Wi-Fi network services, disables legacy fail-closed loopback HTTP/HTTPS/SOCKS
    /// proxies and `launchctl` env vars, and snapshots previous per-service proxy state so
    /// even `kill -9` or crash fails open cleanly to `DIRECT`. Skips overriding proxy settings
    /// while a full-tunnel VPN is active.
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_launchd_env: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        let pac_url = format_pac_url(addr, http_port);
        let services = list_configurable_network_services().unwrap_or_default();

        if enable_socks_system_proxy {
            debug!(
                socks_port = ?socks_port,
                "ignoring fail-closed SOCKS5 system proxy on macOS in favor of fail-open PAC"
            );
        }
        if enable_launchd_env {
            debug!(
                "skipping fail-closed launchd HTTP_PROXY/HTTPS_PROXY persistence on macOS; cleaning stale loopback env vars"
            );
        }

        if is_vpn_default_route_active() {
            info!(
                services = ?services,
                pac_url = %pac_url,
                http_port = http_port,
                socks_port = ?socks_port,
                "full-tunnel VPN active; skipping macOS system proxy activation"
            );
            return Ok(Self {
                pac_url,
                services,
                saved_state: SavedMacosProxyState::default(),
                activated: false,
            });
        }

        let state_path = macos_proxy_state_path();
        let mut saved_state = SavedMacosProxyState::load_from_path(&state_path)
            .unwrap_or_else(|e| {
                warn!(path = %state_path.display(), error = %e, "failed to load previous macOS proxy state");
                None
            })
            .unwrap_or_default();

        let mut snapshots = Vec::with_capacity(services.len());
        for svc in &services {
            let status = inspect_single_service_proxy(svc);
            saved_state.upsert_if_absent(status.to_saved_state());
            snapshots.push(status);
        }

        if !saved_state.services.is_empty() {
            if let Err(e) = saved_state.save_to_path(&state_path) {
                warn!(path = %state_path.display(), error = %e, "failed to persist macOS proxy state snapshot");
            }
        }

        for st in &snapshots {
            let svc = st.service.as_str();
            match get_proxy_bypass_domains(svc) {
                Ok(existing) => {
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

            disable_loopback_manual_proxies(st);

            if let Err(e) = run_networksetup(&["-setautoproxyurl", svc, &pac_url])
                .and_then(|_| run_networksetup(&["-setautoproxystate", svc, "on"]))
            {
                warn!(service = %svc, error = %e, "failed to enable fail-open AutoProxyURL (PAC)");
            }
        }

        // Never persist fail-closed launchctl HTTP_PROXY/HTTPS_PROXY; clean up stale loopback vars
        // left behind by older vdpi versions.
        unset_stale_loopback_launchd_proxy_env();

        info!(
            services = ?services,
            pac_url = %pac_url,
            http_port = http_port,
            socks_port = ?socks_port,
            "configured macOS fail-open PAC system proxy"
        );

        Ok(Self {
            pac_url,
            services,
            saved_state,
            activated: true,
        })
    }

    pub fn summary(&self) -> String {
        if !self.activated {
            return "standby (full-tunnel VPN active; macOS system proxy skipped)".to_string();
        }
        format!(
            "active (macOS fail-open PAC {} on [{}])",
            self.pac_url,
            self.services.join(", ")
        )
    }

    /// Periodically verifies that sleep/wake cycles or VPN disconnects have not wiped
    /// fail-open PAC proxy settings on physical interfaces, and keeps legacy fail-closed
    /// loopback proxies off. Avoids touching settings while a full-tunnel VPN is active.
    pub fn reconcile(&self) {
        if is_vpn_default_route_active() {
            debug!("full-tunnel VPN active; skipping macOS proxy reconciliation");
            return;
        }

        let state_path = macos_proxy_state_path();
        let mut disk_state = SavedMacosProxyState::load_from_path(&state_path)
            .ok()
            .flatten()
            .unwrap_or_else(|| self.saved_state.clone());
        let mut state_dirty = false;

        if let Ok(statuses) = inspect_service_proxies() {
            for st in statuses {
                if disk_state.upsert_if_absent(st.to_saved_state()) {
                    state_dirty = true;
                }
                disable_loopback_manual_proxies(&st);
                if !st.auto_proxy_enabled || !st.auto_proxy_url.eq_ignore_ascii_case(&self.pac_url)
                {
                    let _ = run_networksetup(&["-setautoproxyurl", &st.service, &self.pac_url]);
                    let _ = run_networksetup(&["-setautoproxystate", &st.service, "on"]);
                }
            }
        }

        if state_dirty {
            if let Err(e) = disk_state.save_to_path(&state_path) {
                warn!(path = %state_path.display(), error = %e, "failed to update macOS proxy state snapshot");
            }
        }

        unset_stale_loopback_launchd_proxy_env();
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
            restore_service_proxy_state(svc, saved_state.find_service(svc));
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

fn disable_loopback_manual_proxies(st: &NetworkServiceProxyStatus) {
    if st.web_enabled && is_loopback_server(&st.web_server) {
        if let Err(e) = run_networksetup(&["-setwebproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback HTTP web proxy");
        }
    }
    if st.secure_enabled && is_loopback_server(&st.secure_server) {
        if let Err(e) = run_networksetup(&["-setsecurewebproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback HTTPS secure web proxy");
        }
    }
    if st.socks_enabled && is_loopback_server(&st.socks_server) {
        if let Err(e) = run_networksetup(&["-setsocksfirewallproxystate", &st.service, "off"]) {
            warn!(service = %st.service, error = %e, "failed to disable legacy loopback SOCKS5 firewall proxy");
        }
    }
}

fn restore_service_proxy_state(svc: &str, saved: Option<&SavedServiceProxyState>) {
    let st = inspect_single_service_proxy(svc);

    // 1. Restore previous AutoProxyURL state, or turn off vdpi's PAC if none existed before.
    let current_is_vdpi_or_empty =
        st.auto_proxy_url.is_empty() || is_vdpi_pac_url(&st.auto_proxy_url);
    if let Some(prev) =
        saved.filter(|s| !s.autoproxy.url.trim().is_empty() && !is_vdpi_pac_url(&s.autoproxy.url))
    {
        if current_is_vdpi_or_empty {
            let _ = run_networksetup(&["-setautoproxyurl", svc, &prev.autoproxy.url]);
            let state_arg = if prev.autoproxy.enabled { "on" } else { "off" };
            let _ = run_networksetup(&["-setautoproxystate", svc, state_arg]);
        }
    } else if st.auto_proxy_enabled && is_vdpi_pac_url(&st.auto_proxy_url) {
        let _ = run_networksetup(&["-setautoproxystate", svc, "off"]);
    }

    // 2. Clean up any legacy 127.0.0.1 / ::1 fail-closed manual proxies.
    disable_loopback_manual_proxies(&st);

    // 3. Restore any saved non-loopback manual proxies if they were previously enabled.
    if let Some(prev) = saved {
        restore_manual_proxy_if_needed(
            svc,
            &prev.webproxy,
            st.web_enabled && !is_loopback_server(&st.web_server),
            "-setwebproxy",
            "-setwebproxystate",
        );
        restore_manual_proxy_if_needed(
            svc,
            &prev.securewebproxy,
            st.secure_enabled && !is_loopback_server(&st.secure_server),
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
        );
        restore_manual_proxy_if_needed(
            svc,
            &prev.socksfirewallproxy,
            st.socks_enabled && !is_loopback_server(&st.socks_server),
            "-setsocksfirewallproxy",
            "-setsocksfirewallproxystate",
        );
    }
}

fn restore_manual_proxy_if_needed(
    svc: &str,
    saved: &ManualProxyState,
    currently_active_non_loopback: bool,
    set_cmd: &str,
    state_cmd: &str,
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
    let _ = run_networksetup(&[set_cmd, svc, &saved.server, &saved.port]);
    let _ = run_networksetup(&[state_cmd, svc, "on"]);
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
        restore_service_proxy_state(svc, saved_state.find_service(svc));
    }

    unset_stale_loopback_launchd_proxy_env();
    remove_state_file(&state_path);
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

fn unset_stale_loopback_launchd_proxy_env() {
    let mut unset_http_any = false;
    for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        if read_launchd_env(key).is_some_and(|current| is_loopback_proxy_env_value(&current)) {
            unset_http_any = true;
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
    if unset_http_any {
        for key in ["NO_PROXY", "no_proxy"] {
            let _ = Command::new("/bin/launchctl")
                .args(["unsetenv", key])
                .output();
        }
    }
    for key in ["ALL_PROXY", "all_proxy"] {
        if read_launchd_env(key).is_some_and(|current| is_loopback_proxy_env_value(&current)) {
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
            activated: false,
        };
        assert!(session.summary().starts_with("standby"));

        let active = MacosProxySession {
            activated: true,
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
}
