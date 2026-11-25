use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// Strategy used by `vdpi` to desynchronize Deep Packet Inspection on outbound handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum DesyncMode {
    /// Split TLS ClientHello into two RFC-compliant TLS records at the SNI midpoint AND
    /// transmit the first record in `chunk_size`-byte TCP segments with TCP_NODELAY.
    #[cfg_attr(feature = "cli", value(name = "combo"))]
    Combo,
    /// Split TLS ClientHello into two RFC-compliant TLS records at the SNI midpoint.
    #[cfg_attr(feature = "cli", value(name = "tls-record", alias = "tlsrec"))]
    TlsRecord,
    /// Fragment the entire TLS ClientHello into `chunk_size`-byte TCP segments.
    #[cfg_attr(feature = "cli", value(name = "fragment", alias = "chunk"))]
    Fragment,
    /// Transmit the first `chunk_size` bytes in an initial TCP segment and the rest immediately after.
    #[cfg_attr(feature = "cli", value(name = "split"))]
    Split,
}

/// Active desktop transport mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum EngineMode {
    /// Classic local HTTP/SOCKS5 proxy + OS system proxy (no virtual adapter required).
    #[default]
    #[cfg_attr(feature = "cli", value(name = "proxy"))]
    Proxy,
    /// Transparent system-wide virtual TUN adapter (Wintun / utun / /dev/net/tun).
    #[cfg_attr(feature = "cli", value(name = "tun"))]
    Tun,
}

impl EngineMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Tun => "tun",
        }
    }
}

/// How `vdpi` reacts when an active full-tunnel third-party VPN (e.g. Mullvad, WireGuard) is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum VpnCoexistence {
    /// Immediately yield TUN / suspend conflicting proxy rules while a full-tunnel VPN is active,
    /// and recover automatically after the VPN disconnects.
    #[default]
    #[cfg_attr(feature = "cli", value(name = "auto-yield"))]
    AutoYield,
    /// Surface a warning badge in status/TUI without tearing down automatically.
    #[cfg_attr(feature = "cli", value(name = "warn"))]
    Warn,
    /// Disable VPN conflict detection.
    #[cfg_attr(feature = "cli", value(name = "off"))]
    Off,
}

impl VpnCoexistence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoYield => "auto-yield",
            Self::Warn => "warn",
            Self::Off => "off",
        }
    }
}

/// Validated runtime configuration shared across desktop proxy, desktop TUN, Android, and iOS.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub engine: EngineMode,
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub dns_addr: String,
    pub dns_port: u16,
    pub dns_ipv4_only: bool,
    pub enable_doh: bool,
    /// Disables OS `lookup_host` fallback, mDNS `.local` OS resolution, and hostname-based DoH
    /// endpoints even when `outbound_binder` is `None` (e.g. iOS NEPacketTunnelProvider where
    /// NECP auto-excludes extension sockets, avoiding per-query HTTP/1.1 TLS while preventing
    /// `mDNSResponder` -> `utun` recursion loops).
    pub disable_system_dns_fallback: bool,
    pub chunk_size: usize,
    pub mode: DesyncMode,
    pub patterns: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub system_proxy: bool,
    pub socks_system_proxy: bool,
    pub env_proxy: bool,
    pub block_quic: bool,
    pub connect_timeout: Duration,
    pub vpn_coexistence: VpnCoexistence,
    pub tun_ipv6: bool,
    pub debug: bool,
    pub quiet: bool,
    pub windows_service: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            engine: EngineMode::Proxy,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            dns_addr: "1.1.1.1".to_string(),
            dns_port: 53,
            dns_ipv4_only: false,
            enable_doh: true,
            disable_system_dns_fallback: false,
            chunk_size: 10,
            mode: DesyncMode::Combo,
            patterns: Vec::new(),
            bypass_domains: Vec::new(),
            system_proxy: true,
            socks_system_proxy: true,
            env_proxy: true,
            block_quic: true,
            connect_timeout: Duration::from_millis(8000),
            vpn_coexistence: VpnCoexistence::AutoYield,
            tun_ipv6: false,
            debug: false,
            quiet: false,
            windows_service: false,
        }
    }
}
