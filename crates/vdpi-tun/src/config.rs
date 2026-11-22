use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use vdpi::config::{DesyncMode, RuntimeConfig};

pub const MIN_MTU: usize = 1280;
pub const MAX_MTU: usize = 9000;

/// Resource-budget tuning profile for the userspace TUN stack.
///
/// Android runs inside a normal app process with generous heap headroom (`Standard`),
/// while iOS `NEPacketTunnelProvider` extensions are terminated by Jetsam above ~50 MB RSS
/// (`LowMemory`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunProfile {
    pub stack_buffer_size: usize,
    pub tcp_buffer_size: usize,
    pub udp_buffer_size: usize,
    pub tcp_recv_buffer_size: u32,
    pub tcp_send_buffer_size: u32,
    pub max_tcp_sessions: usize,
    pub max_udp_flows: usize,
    pub max_dns_inflight: usize,
    pub max_reverse_dns_entries: usize,
    pub channel_capacity: usize,
    pub udp_reply_capacity: usize,
}

impl TunProfile {
    pub const STANDARD: Self = Self {
        stack_buffer_size: 512,
        tcp_buffer_size: 256,
        udp_buffer_size: 256,
        tcp_recv_buffer_size: 64 * 1024,
        tcp_send_buffer_size: 64 * 1024,
        max_tcp_sessions: 192,
        max_udp_flows: 256,
        max_dns_inflight: 96,
        max_reverse_dns_entries: 2048,
        channel_capacity: 512,
        udp_reply_capacity: 512,
    };

    /// Tuned for iOS `NEPacketTunnelProvider` (~50 MB hard Jetsam memory ceiling).
    pub const LOW_MEMORY: Self = Self {
        stack_buffer_size: 128,
        tcp_buffer_size: 96,
        udp_buffer_size: 96,
        tcp_recv_buffer_size: 24 * 1024,
        tcp_send_buffer_size: 24 * 1024,
        max_tcp_sessions: 80,
        max_udp_flows: 112,
        max_dns_inflight: 48,
        max_reverse_dns_entries: 512,
        channel_capacity: 128,
        udp_reply_capacity: 128,
    };
}

impl Default for TunProfile {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// JSON-serializable runtime settings passed from Android or iOS apps into the Rust TUN engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TunnelConfig {
    pub mode: DesyncMode,
    pub chunk_size: usize,
    pub dns_addr: String,
    pub enable_doh: bool,
    pub ipv4_only: bool,
    pub block_quic: bool,
    pub timeout_ms: u64,
    pub mtu: usize,
    pub bypass_domains: Vec<String>,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            mode: DesyncMode::Combo,
            chunk_size: 10,
            dns_addr: "1.1.1.1".to_string(),
            enable_doh: true,
            ipv4_only: false,
            block_quic: true,
            timeout_ms: 8000,
            mtu: 1400,
            bypass_domains: Vec::new(),
        }
    }
}

impl TunnelConfig {
    pub fn from_json_str(raw: &str) -> Result<Self, serde_json::Error> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(raw)
    }

    pub fn clamped_mtu(&self) -> usize {
        self.mtu.clamp(MIN_MTU, MAX_MTU)
    }

    pub fn into_runtime_config(self) -> RuntimeConfig {
        let timeout_ms = if self.timeout_ms == 0 {
            8000
        } else {
            self.timeout_ms.clamp(1500, 30_000)
        };

        RuntimeConfig {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            socks_port: None,
            dns_addr: if self.dns_addr.trim().is_empty() {
                "1.1.1.1".to_string()
            } else {
                self.dns_addr
            },
            dns_port: 53,
            dns_ipv4_only: self.ipv4_only,
            enable_doh: self.enable_doh,
            chunk_size: self.chunk_size.clamp(1, 64),
            mode: self.mode,
            patterns: Vec::new(),
            bypass_domains: self.bypass_domains,
            system_proxy: false,
            socks_system_proxy: false,
            env_proxy: false,
            block_quic: self.block_quic,
            connect_timeout: Duration::from_millis(timeout_ms),
            debug: false,
            quiet: true,
            windows_service: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_empty_or_partial_json_with_safe_defaults() {
        let empty = TunnelConfig::from_json_str("").unwrap();
        assert_eq!(empty, TunnelConfig::default());

        let partial = TunnelConfig::from_json_str(
            r#"{"mode":"tls-record","chunk_size":4,"dns_addr":"9.9.9.9","block_quic":false}"#,
        )
        .unwrap();
        assert_eq!(partial.mode, DesyncMode::TlsRecord);
        assert_eq!(partial.chunk_size, 4);
        assert_eq!(partial.dns_addr, "9.9.9.9");
        assert!(!partial.block_quic);
        assert!(partial.enable_doh);
        assert_eq!(partial.mtu, 1400);
    }

    #[test]
    fn clamps_runtime_config_and_mtu_bounds() {
        let raw = TunnelConfig {
            chunk_size: 0,
            timeout_ms: 100,
            mtu: usize::MAX,
            dns_addr: "   ".into(),
            ..Default::default()
        };
        assert_eq!(raw.clamped_mtu(), MAX_MTU);
        let low = TunnelConfig {
            mtu: 64,
            ..Default::default()
        };
        assert_eq!(low.clamped_mtu(), MIN_MTU);

        let cfg = raw.into_runtime_config();

        assert_eq!(cfg.chunk_size, 1);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(1500));
        assert_eq!(cfg.dns_addr, "1.1.1.1");
        assert!(!cfg.system_proxy);
    }

    #[test]
    fn low_memory_profile_stays_strictly_bounded_for_ios_jetsam() {
        let low = TunProfile::LOW_MEMORY;
        let std = TunProfile::STANDARD;
        assert!(low.tcp_recv_buffer_size < std.tcp_recv_buffer_size);
        assert!(low.max_tcp_sessions < std.max_tcp_sessions);
        assert!(low.max_udp_flows < std.max_udp_flows);
        // Worst-case concurrent smoltcp TCP buffer footprint stays well below 10 MB.
        let max_tcp_mem = low.max_tcp_sessions
            * (low.tcp_recv_buffer_size as usize + low.tcp_send_buffer_size as usize);
        assert!(max_tcp_mem <= 6 * 1024 * 1024);
    }
}
