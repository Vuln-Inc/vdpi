use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::net::IpAddr;
use std::time::Duration;

/// Strategy used by `vdpi` to desynchronize Deep Packet Inspection on outbound handshakes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DesyncMode {
    /// Split TLS ClientHello into two RFC-compliant TLS records at the SNI midpoint AND
    /// transmit the first record in `chunk_size`-byte TCP segments with TCP_NODELAY.
    #[value(name = "combo")]
    Combo,
    /// Split TLS ClientHello into two RFC-compliant TLS records at the SNI midpoint.
    #[value(name = "tls-record", alias = "tlsrec")]
    TlsRecord,
    /// Fragment the entire TLS ClientHello into `chunk_size`-byte TCP segments.
    #[value(name = "fragment", alias = "chunk")]
    Fragment,
    /// Transmit the first `chunk_size` bytes in an initial TCP segment and the rest immediately after.
    #[value(name = "split")]
    Split,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Start the vdpi engine in the foreground without opening the launcher
    #[command(visible_alias = "run")]
    Start,
    /// Open the run or install chooser, even if a preference was saved
    Launcher,
    /// Install vdpi and enable automatic background startup (Windows Service / LaunchAgent / systemd)
    Install,
    /// Stop vdpi, remove startup registration, and restore system proxy settings
    Uninstall,
    /// Temporarily stop the installed background service and restore system proxies
    #[command(visible_alias = "stop")]
    Pause,
    /// Start a paused background service and re-enable anti-DPI protection
    Resume,
    /// Display live daemon health, ports, system proxy state, and session environment
    Status,
    /// Run live end-to-end DPI bypass diagnostics (HTTP CONNECT + SOCKS5h + DoH)
    Doctor,
    /// Check GitHub Releases for a newer vdpi version and update in place
    Update {
        /// Only check whether a newer release is available without installing
        #[arg(long, default_value_t = false, conflicts_with = "force")]
        check: bool,
        /// Reinstall the latest release even if the current version matches
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

#[derive(Debug, Clone, Parser)]
#[command(
    name = "vdpi",
    version,
    author = "Vuln-Inc",
    about = "Zero-hassle, high-performance anti-DPI engine for macOS, Windows, and Linux"
)]
pub struct CliArgs {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Local address to bind listeners on
    #[arg(
        short = 'b',
        long = "bind",
        alias = "addr",
        default_value = "127.0.0.1",
        global = true
    )]
    pub bind: IpAddr,

    /// Primary proxy port (auto-detects HTTP/1.1, HTTPS CONNECT, SOCKS5, and SOCKS4a)
    #[arg(short = 'p', long = "port", default_value_t = 8080, global = true)]
    pub port: u16,

    /// Dedicated SOCKS5 (TCP CONNECT + UDP ASSOCIATE) port; set to 0 to disable dedicated listener
    #[arg(
        short = 's',
        long = "socks-port",
        default_value_t = 1080,
        global = true
    )]
    pub socks_port: u16,

    /// DPI desynchronization mode
    #[arg(
        short = 'm',
        long = "mode",
        alias = "strategy",
        value_enum,
        default_value_t = DesyncMode::Combo,
        global = true
    )]
    pub mode: DesyncMode,

    /// Segment size (in bytes) for fragmented TLS ClientHello packets
    #[arg(
        short = 'c',
        long = "chunk-size",
        alias = "window-size",
        default_value_t = 10,
        global = true
    )]
    pub chunk_size: usize,

    /// Primary upstream DNS / DoH server address or URL
    #[arg(
        long = "dns",
        alias = "dns-addr",
        default_value = "1.1.1.1",
        global = true
    )]
    pub dns_addr: String,

    /// Port for plain UDP DNS queries when DoH is disabled
    #[arg(long = "dns-port", default_value_t = 53, global = true)]
    pub dns_port: u16,

    /// Resolve IPv4 (A) records only
    #[arg(
        short = '4',
        long = "ipv4-only",
        alias = "dns-ipv4-only",
        default_value_t = false,
        global = true
    )]
    pub ipv4_only: bool,

    /// Enable RFC 8484 DNS-over-HTTPS (enabled by default; pass `--no-doh` to disable)
    #[arg(
        long = "enable-doh",
        default_value_t = true,
        hide = true,
        global = true
    )]
    pub enable_doh: bool,

    /// Disable DNS-over-HTTPS and use plain UDP / OS DNS resolution
    #[arg(long = "no-doh", default_value_t = false, global = true)]
    pub no_doh: bool,

    /// Apply DPI desynchronization only to hostnames matching this regex (repeatable)
    #[arg(long = "include", alias = "pattern", global = true)]
    pub include_patterns: Vec<String>,

    /// Additional domains or wildcards to bypass DPI fragmentation (repeatable)
    #[arg(long = "bypass", global = true)]
    pub bypass_domains: Vec<String>,

    /// Automatically configure OS system proxy settings while running
    #[arg(
        long = "system-proxy",
        default_value_t = true,
        hide = true,
        global = true
    )]
    pub system_proxy: bool,

    /// Do not modify OS system proxy settings
    #[arg(long = "no-system-proxy", default_value_t = false, global = true)]
    pub no_system_proxy: bool,

    /// Configure OS SOCKS5 system proxy alongside HTTP/HTTPS when supported
    #[arg(
        long = "socks-system-proxy",
        default_value_t = true,
        hide = true,
        global = true
    )]
    pub socks_system_proxy: bool,

    /// Do not configure OS SOCKS5 system proxy (keeps SOCKS5 listener running)
    #[arg(
        long = "no-socks-proxy",
        alias = "no-socks-system-proxy",
        default_value_t = false,
        global = true
    )]
    pub no_socks_proxy: bool,

    /// Export HTTP_PROXY/HTTPS_PROXY/NO_PROXY to user session environment for desktop apps
    #[arg(
        long = "env-proxy",
        alias = "launchd-env",
        default_value_t = true,
        hide = true,
        global = true
    )]
    pub env_proxy: bool,

    /// Do not export proxy variables into the user session environment
    #[arg(
        long = "no-env-proxy",
        alias = "no-launchd-env",
        default_value_t = false,
        global = true
    )]
    pub no_env_proxy: bool,

    /// Allow QUIC (UDP/443) packets over SOCKS5 UDP relay instead of forcing TCP TLS fallback
    #[arg(
        long = "allow-quic",
        alias = "no-block-quic",
        default_value_t = false,
        global = true
    )]
    pub allow_quic: bool,

    /// Outbound TCP connection timeout in milliseconds (0 uses default 8000ms)
    #[arg(short = 't', long = "timeout", default_value_t = 0, global = true)]
    pub timeout_ms: u64,

    /// Enable verbose debug logging
    #[arg(short = 'd', long = "debug", default_value_t = false, global = true)]
    pub debug: bool,

    /// Suppress startup banner and informational output
    #[arg(
        short = 'q',
        long = "quiet",
        alias = "silent",
        default_value_t = false,
        global = true
    )]
    pub quiet: bool,

    /// Run under the Windows Service Control Manager (internal)
    #[arg(long = "service", hide = true, default_value_t = false, global = true)]
    pub service: bool,
}

/// Validated runtime configuration derived from [`CliArgs`].
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub dns_addr: String,
    pub dns_port: u16,
    pub dns_ipv4_only: bool,
    pub enable_doh: bool,
    pub chunk_size: usize,
    pub mode: DesyncMode,
    pub patterns: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub system_proxy: bool,
    pub socks_system_proxy: bool,
    pub env_proxy: bool,
    pub block_quic: bool,
    pub connect_timeout: Duration,
    pub debug: bool,
    pub quiet: bool,
    pub windows_service: bool,
}

impl CliArgs {
    pub fn parse_from_iter<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        Self::try_parse_from(args)
    }

    pub fn into_runtime_config(self) -> RuntimeConfig {
        let system_proxy = self.system_proxy && !self.no_system_proxy;
        let enable_doh = self.enable_doh && !self.no_doh;
        let socks_port = if self.socks_port == 0 || self.socks_port == self.port {
            None
        } else {
            Some(self.socks_port)
        };
        let socks_system_proxy =
            system_proxy && self.socks_system_proxy && !self.no_socks_proxy && socks_port.is_some();
        let env_proxy = system_proxy && self.env_proxy && !self.no_env_proxy;
        let block_quic = !self.allow_quic;
        let connect_timeout = if self.timeout_ms == 0 {
            Duration::from_millis(8000)
        } else {
            Duration::from_millis(self.timeout_ms)
        };

        RuntimeConfig {
            addr: self.bind,
            port: self.port,
            socks_port,
            dns_addr: self.dns_addr,
            dns_port: self.dns_port,
            dns_ipv4_only: self.ipv4_only,
            enable_doh,
            chunk_size: self.chunk_size.max(1),
            mode: self.mode,
            patterns: self.include_patterns,
            bypass_domains: self.bypass_domains,
            system_proxy,
            socks_system_proxy,
            env_proxy,
            block_quic,
            connect_timeout,
            debug: self.debug,
            quiet: self.quiet,
            windows_service: self.service,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cli_flags_and_builds_runtime_config() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--chunk-size",
            "10",
            "--port",
            "8080",
            "--no-system-proxy",
        ])
        .expect("valid CLI flags");

        let cfg = cli.into_runtime_config();
        assert!(cfg.enable_doh);
        assert_eq!(cfg.chunk_size, 10);
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.socks_port, Some(1080));
        assert!(!cfg.system_proxy);
        assert!(!cfg.env_proxy);
        assert!(!cfg.socks_system_proxy);
    }

    #[test]
    fn parses_subcommands_and_desync_modes() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--mode",
            "tls-record",
            "--chunk-size",
            "6",
            "doctor",
        ])
        .expect("valid subcommand");

        assert!(matches!(cli.command, Some(Command::Doctor)));
        let cfg = cli.into_runtime_config();
        assert_eq!(cfg.mode, DesyncMode::TlsRecord);
        assert_eq!(cfg.chunk_size, 6);
        assert!(!cfg.windows_service);
    }

    #[test]
    fn parses_windows_service_flag() {
        let cli =
            CliArgs::parse_from_iter(["vdpi", "--service", "--quiet"]).expect("valid service flag");
        let cfg = cli.into_runtime_config();
        assert!(cfg.windows_service);
        assert!(cfg.quiet);
    }

    #[test]
    fn parses_update_subcommand_defaults() {
        let cli = CliArgs::parse_from_iter(["vdpi", "update"]).expect("valid update subcommand");
        assert!(matches!(
            cli.command,
            Some(Command::Update {
                check: false,
                force: false,
            })
        ));
    }

    #[test]
    fn parses_update_check_flag() {
        let cli = CliArgs::parse_from_iter(["vdpi", "update", "--check"])
            .expect("valid update --check subcommand");
        assert!(matches!(
            cli.command,
            Some(Command::Update {
                check: true,
                force: false,
            })
        ));
    }

    #[test]
    fn parses_update_force_flag() {
        let cli = CliArgs::parse_from_iter(["vdpi", "update", "--force"])
            .expect("valid update --force subcommand");
        assert!(matches!(
            cli.command,
            Some(Command::Update {
                check: false,
                force: true,
            })
        ));
    }

    #[test]
    fn rejects_conflicting_update_check_and_force_flags() {
        let err = CliArgs::parse_from_iter(["vdpi", "update", "--check", "--force"])
            .expect_err("--check and --force must conflict");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_pause_subcommand_and_stop_alias() {
        let pause = CliArgs::parse_from_iter(["vdpi", "pause"]).expect("valid pause subcommand");
        assert!(matches!(pause.command, Some(Command::Pause)));

        let stop = CliArgs::parse_from_iter(["vdpi", "stop"]).expect("valid stop alias");
        assert!(matches!(stop.command, Some(Command::Pause)));
    }

    #[test]
    fn parses_resume_subcommand() {
        let resume = CliArgs::parse_from_iter(["vdpi", "resume"]).expect("valid resume subcommand");
        assert!(matches!(resume.command, Some(Command::Resume)));
    }
}
