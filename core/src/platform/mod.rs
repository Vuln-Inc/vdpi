use anyhow::Result;
use std::net::IpAddr;
use vdpi_core::config::VpnCoexistence;

#[cfg(target_os = "linux")]
pub mod linux;
pub mod linux_tun;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod macos_tun;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod unix_foreground;
pub mod vpn;
pub mod vpn_guard;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod windows_service;
pub mod windows_tun;

/// Cross-platform system proxy session handle that configures OS-level HTTP/HTTPS/SOCKS5
/// settings on startup, reconciles across network changes, and cleanly restores state on exit.
#[derive(Debug, Clone)]
pub struct SystemProxySession {
    #[cfg(target_os = "macos")]
    inner: macos::MacosProxySession,
    #[cfg(target_os = "windows")]
    inner: windows::WindowsProxySession,
    #[cfg(target_os = "linux")]
    inner: linux::LinuxProxySession,
}

impl SystemProxySession {
    pub fn activate(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
    ) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let inner = macos::MacosProxySession::activate(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
            )?;
            Ok(Self { inner })
        }

        #[cfg(target_os = "windows")]
        {
            let inner = windows::WindowsProxySession::activate(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
            )?;
            Ok(Self { inner })
        }

        #[cfg(target_os = "linux")]
        {
            let inner = linux::LinuxProxySession::activate(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
            )?;
            Ok(Self { inner })
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = (
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
            );
            Ok(Self {})
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn activate_with_options(
        addr: IpAddr,
        http_port: u16,
        socks_port: Option<u16>,
        enable_socks_system_proxy: bool,
        enable_env_proxy: bool,
        extra_bypass: &[String],
        include_domains: &[String],
        vpn_coexistence: VpnCoexistence,
    ) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let inner = macos::MacosProxySession::activate_with_options(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
                include_domains,
                vpn_coexistence,
            )?;
            Ok(Self { inner })
        }

        #[cfg(target_os = "windows")]
        {
            let _ = include_domains;
            let inner = windows::WindowsProxySession::activate(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
            )
            .map(|s| s.with_vpn_coexistence(vpn_coexistence))?;
            Ok(Self { inner })
        }

        #[cfg(target_os = "linux")]
        {
            let _ = vpn_coexistence;
            let inner = linux::LinuxProxySession::activate_with_options(
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
                include_domains,
            )?;
            Ok(Self { inner })
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            let _ = (
                addr,
                http_port,
                socks_port,
                enable_socks_system_proxy,
                enable_env_proxy,
                extra_bypass,
                include_domains,
                vpn_coexistence,
            );
            Ok(Self {})
        }
    }

    pub fn with_vpn_coexistence(self, mode: VpnCoexistence) -> Self {
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            Self {
                inner: self.inner.with_vpn_coexistence(mode),
            }
        }
        #[cfg(not(any(target_os = "windows", target_os = "macos")))]
        {
            let _ = mode;
            self
        }
    }

    pub fn reconcile(&self) {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        self.inner.reconcile();
    }

    pub fn deactivate(&self) {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        self.inner.deactivate();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn deactivate_foreground(&self) {
        self.inner.deactivate_foreground();
    }

    pub fn summary(&self) -> String {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        {
            self.inner.summary()
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
        {
            "manual proxy mode".to_string()
        }
    }
}

pub fn clear_all_system_proxies() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::clear_all_macos_proxies()
    }
    #[cfg(target_os = "windows")]
    {
        windows::clear_all_windows_proxies()
    }
    #[cfg(target_os = "linux")]
    {
        linux::clear_all_linux_proxies()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}

pub fn print_platform_proxy_status() {
    #[cfg(target_os = "macos")]
    macos::print_macos_proxy_status();
    #[cfg(target_os = "windows")]
    windows::print_windows_proxy_status();
    #[cfg(target_os = "linux")]
    linux::print_linux_proxy_status();
}

pub fn platform_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macOS"
    }
    #[cfg(target_os = "windows")]
    {
        "Windows"
    }
    #[cfg(target_os = "linux")]
    {
        "Linux"
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        std::env::consts::OS
    }
}
