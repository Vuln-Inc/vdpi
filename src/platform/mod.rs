use anyhow::Result;
use std::net::IpAddr;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

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

    pub fn reconcile(&self) {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        self.inner.reconcile();
    }

    pub fn deactivate(&self) {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
        self.inner.deactivate();
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
