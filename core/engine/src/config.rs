use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
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

/// Per-application split-tunnel routing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[serde(rename_all = "kebab-case")]
pub enum SplitTunnelMode {
    /// Route all applications through DPI desync.
    #[default]
    #[cfg_attr(feature = "cli", value(name = "all"))]
    All,
    /// Bypass DPI desync for the listed applications; desync everything else.
    #[cfg_attr(feature = "cli", value(name = "exclude"))]
    Exclude,
    /// Only desync the listed applications; bypass everything else.
    #[cfg_attr(feature = "cli", value(name = "include"))]
    Include,
}

impl SplitTunnelMode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Exclude => "exclude",
            Self::Include => "include",
        }
    }
}

impl FromStr for SplitTunnelMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "exclude" => Ok(Self::Exclude),
            "include" => Ok(Self::Include),
            other => Err(format!(
                "invalid split tunnel mode '{other}' (expected all, exclude, or include)"
            )),
        }
    }
}

impl fmt::Display for SplitTunnelMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Normalize an application executable path or name for split-tunnel matching.
///
/// Trims whitespace, takes the filename component after any `/` or `\`, lowercases it,
/// and strips a trailing `.exe` suffix so `"C:\\Users\\x\\Discord.exe"`, `"discord.exe"`,
/// and `"Discord"` all normalize to `"discord"`.
pub fn normalize_split_app_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let file_name = trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed).trim();
    let lowered = file_name.to_lowercase();
    lowered
        .strip_suffix(".exe")
        .unwrap_or(&lowered)
        .trim()
        .to_string()
}

/// Per-application split-tunnel configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SplitTunnelConfig {
    pub mode: SplitTunnelMode,
    pub apps: Vec<String>,
}

impl SplitTunnelConfig {
    pub fn is_active(&self) -> bool {
        self.mode != SplitTunnelMode::All
    }

    /// Returns `true` when traffic for `exe_name` should bypass DPI desync.
    ///
    /// Behavior by mode:
    /// - `All`: always returns `false` (all apps use desync).
    /// - `Exclude`: returns `true` only when `exe_name` normalizes to a non-empty name
    ///   matching an entry in `self.apps`.
    /// - `Include`: when `self.apps` has no non-empty entries, returns `false` so an empty
    ///   include list never accidentally disables desync for all traffic. Otherwise, returns
    ///   `false` for matching apps and `true` for non-matching or unidentified (`None` / empty)
    ///   apps (strict include semantics).
    pub fn should_bypass_app(&self, exe_name: Option<&str>) -> bool {
        match self.mode {
            SplitTunnelMode::All => false,
            SplitTunnelMode::Exclude => exe_name
                .map(normalize_split_app_name)
                .filter(|n| !n.is_empty())
                .is_some_and(|n| self.apps.iter().any(|a| normalize_split_app_name(a) == n)),
            SplitTunnelMode::Include => {
                let has_targets = self
                    .apps
                    .iter()
                    .any(|a| !normalize_split_app_name(a).is_empty());
                if !has_targets {
                    return false;
                }
                match exe_name
                    .map(normalize_split_app_name)
                    .filter(|n| !n.is_empty())
                {
                    Some(n) => !self.apps.iter().any(|a| normalize_split_app_name(a) == n),
                    None => true,
                }
            }
        }
    }

    pub fn summary_label(&self) -> String {
        let count = self.apps.len();
        let noun = if count == 1 { "app" } else { "apps" };
        match self.mode {
            SplitTunnelMode::All => "All apps".to_string(),
            SplitTunnelMode::Exclude => format!("Exclude ({count} {noun})"),
            SplitTunnelMode::Include => format!("Include ({count} {noun})"),
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
    pub split_tunnel: SplitTunnelConfig,
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
            split_tunnel: SplitTunnelConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_tunnel_mode_str_roundtrip() {
        assert_eq!(SplitTunnelMode::default(), SplitTunnelMode::All);
        assert_eq!(SplitTunnelMode::All.as_str(), "all");
        assert_eq!(SplitTunnelMode::Exclude.as_str(), "exclude");
        assert_eq!(SplitTunnelMode::Include.as_str(), "include");

        assert_eq!(SplitTunnelMode::All.to_string(), "all");
        assert_eq!(SplitTunnelMode::Exclude.to_string(), "exclude");
        assert_eq!(SplitTunnelMode::Include.to_string(), "include");

        assert_eq!("all".parse::<SplitTunnelMode>(), Ok(SplitTunnelMode::All));
        assert_eq!("ALL".parse::<SplitTunnelMode>(), Ok(SplitTunnelMode::All));
        assert_eq!(
            "  ExClUdE  ".parse::<SplitTunnelMode>(),
            Ok(SplitTunnelMode::Exclude)
        );
        assert_eq!(
            "Include".parse::<SplitTunnelMode>(),
            Ok(SplitTunnelMode::Include)
        );
        assert!("unknown".parse::<SplitTunnelMode>().is_err());
    }

    #[test]
    fn normalize_app_name_handles_paths_case_and_exe_suffix() {
        assert_eq!(
            normalize_split_app_name(r"C:\Users\x\Discord.exe"),
            "discord"
        );
        assert_eq!(normalize_split_app_name("discord.exe"), "discord");
        assert_eq!(normalize_split_app_name("Discord"), "discord");
        assert_eq!(normalize_split_app_name("  STEAM.EXE  "), "steam");
        assert_eq!(
            normalize_split_app_name("/Applications/Discord.app/Contents/MacOS/Discord"),
            "discord"
        );
        assert_eq!(normalize_split_app_name("/usr/bin/Firefox.exe"), "firefox");
        assert_eq!(normalize_split_app_name("com.discord"), "com.discord");
        assert_eq!(normalize_split_app_name("my.app.exe"), "my.app");
        assert_eq!(normalize_split_app_name("my.exe.bak"), "my.exe.bak");
        assert_eq!(normalize_split_app_name(""), "");
        assert_eq!(normalize_split_app_name("   "), "");
        assert_eq!(normalize_split_app_name(".exe"), "");
        assert_eq!(normalize_split_app_name(r"C:\trailing\"), "");
    }

    #[test]
    fn split_tunnel_all_never_bypasses() {
        let cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::All,
            apps: vec!["discord.exe".to_string()],
        };
        assert!(!cfg.is_active());
        assert!(!cfg.should_bypass_app(Some("Discord.exe")));
        assert!(!cfg.should_bypass_app(Some("chrome.exe")));
        assert!(!cfg.should_bypass_app(None));
    }

    #[test]
    fn split_tunnel_exclude_bypasses_only_matching_apps() {
        let cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec![r"C:\Users\x\Discord.exe".to_string(), "Steam".to_string()],
        };
        assert!(cfg.is_active());
        assert!(cfg.should_bypass_app(Some("discord")));
        assert!(cfg.should_bypass_app(Some("DISCORD.EXE")));
        assert!(cfg.should_bypass_app(Some(r"D:\Games\steam.exe")));
        assert!(cfg.should_bypass_app(Some("/usr/local/bin/Steam")));
        assert!(!cfg.should_bypass_app(Some("chrome.exe")));
        assert!(!cfg.should_bypass_app(Some("")));
        assert!(!cfg.should_bypass_app(Some("   ")));
        assert!(!cfg.should_bypass_app(None));
    }

    #[test]
    fn split_tunnel_include_desyncs_only_matching_apps() {
        let cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["Discord.exe".to_string(), "/usr/bin/Firefox".to_string()],
        };
        assert!(cfg.is_active());
        assert!(!cfg.should_bypass_app(Some(r"C:\Users\x\discord.exe")));
        assert!(!cfg.should_bypass_app(Some("DISCORD")));
        assert!(!cfg.should_bypass_app(Some("firefox.exe")));
        assert!(cfg.should_bypass_app(Some("chrome.exe")));
        assert!(cfg.should_bypass_app(Some("")));
        assert!(cfg.should_bypass_app(None));
    }

    #[test]
    fn split_tunnel_include_empty_list_does_not_bypass_everything() {
        let empty = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: Vec::new(),
        };
        assert!(empty.is_active());
        assert!(!empty.should_bypass_app(Some("chrome.exe")));
        assert!(!empty.should_bypass_app(None));

        let blank_only = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["  ".to_string(), ".exe".to_string()],
        };
        assert!(!blank_only.should_bypass_app(Some("chrome.exe")));
        assert!(!blank_only.should_bypass_app(None));
    }

    #[test]
    fn split_tunnel_summary_label_formats_counts() {
        let all = SplitTunnelConfig::default();
        assert_eq!(all.summary_label(), "All apps");

        let exclude_zero = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: Vec::new(),
        };
        assert_eq!(exclude_zero.summary_label(), "Exclude (0 apps)");

        let exclude_three = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(exclude_three.summary_label(), "Exclude (3 apps)");

        let include_one = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["discord".into()],
        };
        assert_eq!(include_one.summary_label(), "Include (1 app)");

        let include_two = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["discord".into(), "firefox".into()],
        };
        assert_eq!(include_two.summary_label(), "Include (2 apps)");
    }

    #[test]
    fn runtime_config_default_initializes_split_tunnel() {
        let cfg = RuntimeConfig::default();
        assert_eq!(cfg.split_tunnel, SplitTunnelConfig::default());
        assert_eq!(cfg.split_tunnel.mode, SplitTunnelMode::All);
        assert!(cfg.split_tunnel.apps.is_empty());
        assert!(!cfg.split_tunnel.is_active());
    }
}
