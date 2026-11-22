use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use vdpi::config::{DesyncMode, RuntimeConfig};

/// JSON-serializable runtime settings passed from the Android app into the Rust TUN engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AndroidConfig {
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

impl Default for AndroidConfig {
    fn default() -> Self {
        Self {
            mode: DesyncMode::Combo,
            chunk_size: 10,
            dns_addr: "1.1.1.1".to_string(),
            enable_doh: true,
            ipv4_only: false,
            block_quic: true,
            timeout_ms: 8000,
            mtu: 1500,
            bypass_domains: Vec::new(),
        }
    }
}

impl AndroidConfig {
    pub fn from_json_str(raw: &str) -> Result<Self, serde_json::Error> {
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }
        serde_json::from_str(raw)
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
        let empty = AndroidConfig::from_json_str("").unwrap();
        assert_eq!(empty, AndroidConfig::default());

        let partial = AndroidConfig::from_json_str(
            r#"{"mode":"tls-record","chunk_size":4,"dns_addr":"9.9.9.9","block_quic":false}"#,
        )
        .unwrap();
        assert_eq!(partial.mode, DesyncMode::TlsRecord);
        assert_eq!(partial.chunk_size, 4);
        assert_eq!(partial.dns_addr, "9.9.9.9");
        assert!(!partial.block_quic);
        assert!(partial.enable_doh);
        assert_eq!(partial.mtu, 1500);
    }

    #[test]
    fn clamps_runtime_config_bounds() {
        let cfg = AndroidConfig {
            chunk_size: 0,
            timeout_ms: 100,
            dns_addr: "   ".into(),
            ..Default::default()
        }
        .into_runtime_config();

        assert_eq!(cfg.chunk_size, 1);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(1500));
        assert_eq!(cfg.dns_addr, "1.1.1.1");
        assert!(!cfg.system_proxy);
    }
}
