use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use vdpi_core::config::{DesyncMode, RuntimeConfig};

pub const MIN_MTU: usize = 1280;
pub const DEFAULT_MTU: usize = 1400;
pub const DESKTOP_MTU: usize = 16384;
pub const MAX_MTU: usize = 65535;

/// Resource-budget tuning profile for the userspace TUN stack.
///
/// Desktop hosts run with high-throughput buffers (`DESKTOP`), Android runs inside a normal app
/// process with moderate heap headroom (`STANDARD`), while iOS `NEPacketTunnelProvider`
/// extensions are terminated by Jetsam above ~50 MB RSS (`LOW_MEMORY`).
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
    pub tcp_relay_buf_size: usize,
    pub packet_pool_size: usize,
    pub batch_size: usize,
    pub udp_socket_buf_bytes: usize,
    pub emit_quic_icmp_reject: bool,
}

impl TunProfile {
    /// Tuned for gigabit desktop virtual TUN adapters (Wintun / utun / `/dev/net/tun`):
    /// 512 KiB smoltcp TCP buffers (enabling RFC 7323 TCP Window Scaling), 2048-deep queues,
    /// 128 KiB TCP relay buffers, and 128-packet I/O bursts paired with `DESKTOP_MTU = 16384`.
    pub const DESKTOP: Self = Self {
        stack_buffer_size: 2048,
        tcp_buffer_size: 512,
        udp_buffer_size: 512,
        tcp_recv_buffer_size: 512 * 1024,
        tcp_send_buffer_size: 512 * 1024,
        max_tcp_sessions: 128,
        max_udp_flows: 256,
        max_dns_inflight: 128,
        max_reverse_dns_entries: 4096,
        channel_capacity: 2048,
        udp_reply_capacity: 2048,
        tcp_relay_buf_size: 128 * 1024,
        packet_pool_size: 512,
        batch_size: 128,
        udp_socket_buf_bytes: 128 * 1024,
        emit_quic_icmp_reject: true,
    };

    pub const STANDARD: Self = Self {
        stack_buffer_size: 512,
        tcp_buffer_size: 256,
        udp_buffer_size: 256,
        tcp_recv_buffer_size: 64 * 1024,
        tcp_send_buffer_size: 64 * 1024,
        max_tcp_sessions: 128,
        max_udp_flows: 128,
        max_dns_inflight: 96,
        max_reverse_dns_entries: 2048,
        channel_capacity: 512,
        udp_reply_capacity: 512,
        tcp_relay_buf_size: 32 * 1024,
        packet_pool_size: 256,
        batch_size: 32,
        udp_socket_buf_bytes: 128 * 1024,
        emit_quic_icmp_reject: false,
    };

    /// Tuned for iOS `NEPacketTunnelProvider` (~50 MB hard Jetsam memory ceiling and 256 RLIMIT_NOFILE).
    pub const LOW_MEMORY: Self = Self {
        stack_buffer_size: 96,
        tcp_buffer_size: 64,
        udp_buffer_size: 64,
        tcp_recv_buffer_size: 16 * 1024,
        tcp_send_buffer_size: 16 * 1024,
        max_tcp_sessions: 48,
        max_udp_flows: 64,
        max_dns_inflight: 24,
        max_reverse_dns_entries: 512,
        channel_capacity: 96,
        udp_reply_capacity: 96,
        tcp_relay_buf_size: 16 * 1024,
        packet_pool_size: 128,
        batch_size: 16,
        udp_socket_buf_bytes: 0,
        emit_quic_icmp_reject: false,
    };
}

impl Default for TunProfile {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// JSON-serializable runtime settings passed from desktop, Android, or iOS apps into the Rust TUN engine.
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
    #[serde(default)]
    pub cache_path: Option<String>,
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
            mtu: DEFAULT_MTU,
            bypass_domains: Vec::new(),
            cache_path: None,
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
            ..RuntimeConfig::default()
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
        assert_eq!(partial.mtu, DEFAULT_MTU);
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
        assert_eq!(MAX_MTU, 65535);
        let desktop = TunnelConfig {
            mtu: DESKTOP_MTU,
            ..Default::default()
        };
        assert_eq!(desktop.clamped_mtu(), DESKTOP_MTU);
        assert_eq!(DESKTOP_MTU, 16384);
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
        assert!(!cfg.tun_ipv6);
    }

    #[test]
    fn parses_cache_path_option_with_and_without_field() {
        let without = TunnelConfig::from_json_str(r#"{"dns_addr":"8.8.8.8"}"#).unwrap();
        assert_eq!(without.cache_path, None);

        let with_path = TunnelConfig::from_json_str(
            r#"{"dns_addr":"1.1.1.1","cache_path":"/data/user/0/com.vulninc.vdpi/cache/adaptive-cache.json"}"#,
        )
        .unwrap();
        assert_eq!(
            with_path.cache_path.as_deref(),
            Some("/data/user/0/com.vulninc.vdpi/cache/adaptive-cache.json")
        );

        let with_null = TunnelConfig::from_json_str(r#"{"cache_path":null}"#).unwrap();
        assert_eq!(with_null.cache_path, None);
    }

    #[test]
    fn low_memory_profile_stays_strictly_bounded_for_ios_jetsam() {
        let low = TunProfile::LOW_MEMORY;
        let std = TunProfile::STANDARD;
        assert!(low.tcp_recv_buffer_size < std.tcp_recv_buffer_size);
        assert!(low.max_tcp_sessions < std.max_tcp_sessions);
        assert!(low.max_udp_flows < std.max_udp_flows);
        assert!(low.tcp_relay_buf_size < std.tcp_relay_buf_size);
        assert!(low.packet_pool_size < std.packet_pool_size);
        assert!(low.batch_size < std.batch_size);
        assert_eq!(low.udp_socket_buf_bytes, 0);
        assert!(!low.emit_quic_icmp_reject);
        assert!(!std.emit_quic_icmp_reject);
        // Worst-case concurrent smoltcp TCP buffer footprint stays <= 6 MiB for iOS Jetsam.
        let max_tcp_mem = low.max_tcp_sessions
            * (low.tcp_recv_buffer_size as usize + low.tcp_send_buffer_size as usize);
        assert!(max_tcp_mem <= 6 * 1024 * 1024);
    }

    #[test]
    fn desktop_profile_scales_above_standard_with_valid_bounds() {
        let desk = TunProfile::DESKTOP;
        let std = TunProfile::STANDARD;

        assert!(desk.stack_buffer_size > std.stack_buffer_size);
        assert_eq!(desk.stack_buffer_size, 2048);
        assert!(desk.tcp_buffer_size > std.tcp_buffer_size);
        assert!(desk.udp_buffer_size > std.udp_buffer_size);
        assert_eq!(desk.tcp_recv_buffer_size, 512 * 1024);
        assert_eq!(desk.tcp_send_buffer_size, 512 * 1024);
        assert_eq!(desk.max_tcp_sessions, 128);
        assert_eq!(std.max_tcp_sessions, 128);
        assert_eq!(desk.max_udp_flows, 256);
        assert_eq!(std.max_udp_flows, 128);
        assert!(desk.max_udp_flows > std.max_udp_flows);
        assert!(desk.max_dns_inflight > std.max_dns_inflight);
        assert!(desk.max_reverse_dns_entries > std.max_reverse_dns_entries);
        assert_eq!(desk.channel_capacity, 2048);
        assert_eq!(desk.udp_reply_capacity, 2048);
        assert!(desk.channel_capacity > std.channel_capacity);
        assert!(desk.udp_reply_capacity > std.udp_reply_capacity);
        assert_eq!(desk.tcp_relay_buf_size, 128 * 1024);
        assert_eq!(desk.packet_pool_size, 512);
        assert!(desk.packet_pool_size > std.packet_pool_size);
        assert_eq!(desk.batch_size, 128);
        assert!(desk.batch_size > std.batch_size);
        assert_eq!(desk.udp_socket_buf_bytes, 128 * 1024);
        assert_eq!(std.udp_socket_buf_bytes, 128 * 1024);
        assert!(desk.emit_quic_icmp_reject);

        // Worst-case desktop smoltcp TCP buffer footprint: 128 sessions * (512 KiB + 512 KiB) = 128 MiB.
        let max_tcp_mem = desk.max_tcp_sessions
            * (desk.tcp_recv_buffer_size as usize + desk.tcp_send_buffer_size as usize);
        assert_eq!(max_tcp_mem, 128 * 1024 * 1024);
        // Android STANDARD FD budget stays well under the 1024 FD ceiling.
        assert!(std.max_tcp_sessions + std.max_udp_flows <= 256);

        assert_eq!(DEFAULT_MTU, 1400);
        assert_eq!(DESKTOP_MTU, 16384);
        assert_eq!(MAX_MTU, 65535);
    }
}
