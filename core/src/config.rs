use crate::config_file::{sanitize_split_tunnel_apps, FileConfig};
use clap::{Parser, Subcommand};
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

pub use vdpi_core::config::{
    DesyncMode, EngineMode, RuntimeConfig, SplitTunnelConfig, SplitTunnelMode, VpnCoexistence,
};

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum Command {
    /// Start the vdpi engine in the foreground without opening the Control Center
    #[command(visible_alias = "run")]
    Start,
    /// Open the interactive Control Center TUI, even if a preference was saved
    Launcher,
    /// Install vdpi and enable automatic background startup (Windows Service / LaunchAgent / systemd)
    Install {
        /// Internal flag used during in-place upgrades to preserve existing service state
        #[arg(long, hide = true, default_value_t = false)]
        upgrade: bool,
    },
    /// Stop vdpi, remove startup registration, and restore system proxy settings
    Uninstall {
        /// Also remove persisted configuration, logs, and adaptive cache files
        #[arg(long, default_value_t = false)]
        purge: bool,
    },
    /// Temporarily stop the installed background service and restore system proxies
    #[command(visible_alias = "stop")]
    Pause,
    /// Start a paused background service and re-enable anti-DPI protection
    Resume,
    /// Display or switch the active desktop engine mode (`tun` or `proxy`)
    Engine {
        /// Target engine mode (`tun` or `proxy`); omit to print the active engine
        #[arg(id = "engine_mode", value_name = "ENGINE", value_enum)]
        mode: Option<EngineMode>,
    },
    /// Display or change the upstream DNS server address (e.g. `1.1.1.1`, `94.140.14.14`)
    Dns {
        /// Target DNS server IP or DoH URL; omit to print the configured DNS server
        #[arg(value_name = "SERVER")]
        addr: Option<String>,
    },
    /// Open the real-time live dashboard attached to the running vdpi service
    #[command(visible_alias = "dash")]
    Dashboard,
    /// Configure per-app split tunneling (opens interactive app picker when no subcommand given)
    #[command(visible_alias = "apps", alias = "split-tunnel")]
    Split {
        #[command(subcommand)]
        action: Option<SplitCommand>,
    },
    /// Inspect, validate, or modify persisted `config.toml` settings
    Config {
        #[command(subcommand)]
        action: Option<ConfigCommand>,
    },
    /// Display service state, live Anti-DPI engine telemetry, ports, and system proxy status
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

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration
    Show {
        /// Emit configuration as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Print the resolved `config.toml` path
    Path,
    /// Print a single configuration key value from `config.toml`
    Get {
        /// Configuration key name to read
        key: String,
    },
    /// Set a configuration key in `config.toml`
    Set {
        /// Configuration key name
        key: String,
        /// New value for the configuration key
        value: String,
    },
    /// Remove a configuration key from `config.toml`
    Unset {
        /// Configuration key name to remove
        key: String,
    },
    /// Parse and validate `config.toml`
    Validate,
    /// Reset `config.toml` back to built-in defaults
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq, Subcommand)]
pub enum SplitCommand {
    /// Print the current split-tunneling mode and configured applications
    Status,
    /// Discover and list installed and running applications, optionally filtered by query
    List {
        /// Optional fuzzy search filter query
        #[arg(short = 'f', long, alias = "filter")]
        query: Option<String>,
    },
    /// Set the split-tunneling mode (`all`, `exclude`, or `include`)
    Mode {
        /// Target split-tunneling mode (`all`, `exclude`, or `include`)
        #[arg(id = "split_tunnel_mode", value_name = "MODE", value_enum)]
        mode: SplitTunnelMode,
    },
    /// Add one or more applications to the split-tunnel list
    Add {
        /// Executable names or paths to add
        #[arg(required = true, value_name = "APP")]
        apps: Vec<String>,
    },
    /// Remove one or more applications from the split-tunnel list
    Remove {
        /// Executable names or paths to remove
        #[arg(required = true, value_name = "APP")]
        apps: Vec<String>,
    },
    /// Clear the configured application list and reset split-tunnel mode to `all`
    Clear,
    /// Atomically apply split-tunnel mode and app list (used for elevated saves)
    #[command(
        hide = true,
        arg = clap::Arg::new("mode")
            .long("__vdpi-desync-mode-shadow")
            .value_parser(clap::value_parser!(DesyncMode))
            .hide(true)
    )]
    Apply {
        /// Target split-tunneling mode (`all`, `exclude`, or `include`)
        #[arg(
            long = "mode",
            id = "split_apply_mode",
            value_name = "MODE",
            value_enum
        )]
        mode: SplitTunnelMode,
        /// Application executable names to set (repeatable)
        #[arg(long = "app", value_name = "APP")]
        apps: Vec<String>,
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

    /// Run in transparent system-wide virtual TUN mode (Wintun / utun / /dev/net/tun)
    #[arg(
        long = "tun",
        default_value_t = false,
        conflicts_with = "proxy",
        global = true
    )]
    pub tun: bool,

    /// Run in local HTTP/HTTPS/SOCKS5 proxy mode with OS system proxy integration
    #[arg(
        long = "proxy",
        default_value_t = false,
        conflicts_with = "tun",
        global = true
    )]
    pub proxy: bool,

    /// Path to an alternate `config.toml` file
    #[arg(long = "config", global = true)]
    pub config_path: Option<PathBuf>,

    /// Behavior when an active full-tunnel third-party VPN is detected
    #[arg(long = "vpn-coexistence", value_enum, global = true)]
    pub vpn_coexistence: Option<VpnCoexistence>,

    /// Enable IPv6 routing inside the desktop TUN adapter
    #[arg(
        long = "tun-ipv6",
        default_value_t = false,
        conflicts_with = "no_tun_ipv6",
        global = true
    )]
    pub tun_ipv6: bool,

    /// Disable IPv6 routing inside the desktop TUN adapter
    #[arg(
        long = "no-tun-ipv6",
        default_value_t = false,
        conflicts_with = "tun_ipv6",
        global = true
    )]
    pub no_tun_ipv6: bool,

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
        conflicts_with = "no_ipv4_only",
        global = true
    )]
    pub ipv4_only: bool,

    /// Allow both IPv4 (A) and IPv6 (AAAA) DNS resolution
    #[arg(
        long = "no-ipv4-only",
        alias = "no-dns-ipv4-only",
        default_value_t = false,
        conflicts_with = "ipv4_only",
        global = true
    )]
    pub no_ipv4_only: bool,

    /// Enable RFC 8484 DNS-over-HTTPS (enabled by default; pass `--no-doh` to disable)
    #[arg(
        long = "enable-doh",
        default_value_t = true,
        hide = true,
        conflicts_with = "no_doh",
        global = true
    )]
    pub enable_doh: bool,

    /// Disable DNS-over-HTTPS and use plain UDP / OS DNS resolution
    #[arg(
        long = "no-doh",
        default_value_t = false,
        conflicts_with = "enable_doh",
        global = true
    )]
    pub no_doh: bool,

    /// Apply DPI desynchronization only to hostnames matching this regex (repeatable)
    #[arg(long = "include", alias = "pattern", global = true)]
    pub include_patterns: Vec<String>,

    /// Additional domains or wildcards to bypass DPI fragmentation (repeatable)
    #[arg(long = "bypass", global = true)]
    pub bypass_domains: Vec<String>,

    /// Per-application split-tunnel routing mode (`all`, `exclude`, or `include`)
    #[arg(long, value_enum, global = true)]
    pub split_mode: Option<vdpi_core::config::SplitTunnelMode>,

    /// Application executable name or path for split-tunnel routing (repeatable)
    #[arg(long = "split-app", value_name = "APP", global = true)]
    pub split_apps: Vec<String>,

    /// Automatically configure OS system proxy settings while running
    #[arg(
        long = "system-proxy",
        default_value_t = true,
        hide = true,
        conflicts_with = "no_system_proxy",
        global = true
    )]
    pub system_proxy: bool,

    /// Do not modify OS system proxy settings
    #[arg(
        long = "no-system-proxy",
        default_value_t = false,
        conflicts_with = "system_proxy",
        global = true
    )]
    pub no_system_proxy: bool,

    /// Configure OS SOCKS5 system proxy alongside HTTP/HTTPS when supported
    #[arg(
        long = "socks-system-proxy",
        default_value_t = true,
        hide = true,
        conflicts_with = "no_socks_proxy",
        global = true
    )]
    pub socks_system_proxy: bool,

    /// Do not configure OS SOCKS5 system proxy (keeps SOCKS5 listener running)
    #[arg(
        long = "no-socks-proxy",
        alias = "no-socks-system-proxy",
        default_value_t = false,
        conflicts_with = "socks_system_proxy",
        global = true
    )]
    pub no_socks_proxy: bool,

    /// Export HTTP_PROXY/HTTPS_PROXY/NO_PROXY to user session environment for desktop apps
    #[arg(
        long = "env-proxy",
        alias = "launchd-env",
        default_value_t = true,
        hide = true,
        conflicts_with = "no_env_proxy",
        global = true
    )]
    pub env_proxy: bool,

    /// Do not export proxy variables into the user session environment
    #[arg(
        long = "no-env-proxy",
        alias = "no-launchd-env",
        default_value_t = false,
        conflicts_with = "env_proxy",
        global = true
    )]
    pub no_env_proxy: bool,

    /// Allow QUIC (UDP/443) packets over SOCKS5 UDP relay instead of forcing TCP TLS fallback
    #[arg(
        long = "allow-quic",
        alias = "no-block-quic",
        default_value_t = false,
        conflicts_with = "block_quic",
        global = true
    )]
    pub allow_quic: bool,

    /// Block QUIC (UDP/443) packets to force TCP TLS fallback (enabled by default; pass `--allow-quic` to allow)
    #[arg(
        long = "block-quic",
        default_value_t = false,
        conflicts_with = "allow_quic",
        global = true
    )]
    pub block_quic: bool,

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

    /// Run Linux TUN crash-cleanup helper (internal)
    #[arg(
        long = "internal-linux-tun-cleanup",
        hide = true,
        default_value_t = false
    )]
    pub internal_linux_tun_cleanup: bool,

    /// Run macOS TUN crash-guard helper (internal)
    #[arg(
        long = "internal-macos-tun-guard",
        hide = true,
        default_value_t = false
    )]
    pub internal_macos_tun_guard: bool,
}

#[derive(Debug, Default)]
struct ExplicitFlags {
    bind: bool,
    port: bool,
    socks_port: bool,
    mode: bool,
    chunk_size: bool,
    dns_addr: bool,
    dns_port: bool,
    ipv4_only: bool,
    no_ipv4_only: bool,
    enable_doh: bool,
    no_doh: bool,
    include_patterns: bool,
    bypass_domains: bool,
    split_apps: bool,
    system_proxy: bool,
    no_system_proxy: bool,
    socks_system_proxy: bool,
    no_socks_proxy: bool,
    env_proxy: bool,
    no_env_proxy: bool,
    allow_quic: bool,
    block_quic: bool,
    timeout_ms: bool,
    tun: bool,
    proxy: bool,
    tun_ipv6: bool,
    no_tun_ipv6: bool,
}

impl ExplicitFlags {
    fn from_args(args: &[String]) -> Self {
        let mut flags = Self::default();
        let mut skip_next = false;

        for raw in args {
            let arg = raw.as_str();
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg == "--" {
                break;
            }

            if let Some(long) = arg.strip_prefix("--") {
                let (name, has_eq) = match long.split_once('=') {
                    Some((name, _)) => (name, true),
                    None => (long, false),
                };
                match name {
                    "bind" | "addr" => {
                        flags.bind = true;
                        skip_next = !has_eq;
                    }
                    "port" => {
                        flags.port = true;
                        skip_next = !has_eq;
                    }
                    "socks-port" => {
                        flags.socks_port = true;
                        skip_next = !has_eq;
                    }
                    "mode" | "strategy" => {
                        flags.mode = true;
                        skip_next = !has_eq;
                    }
                    "chunk-size" | "window-size" => {
                        flags.chunk_size = true;
                        skip_next = !has_eq;
                    }
                    "dns" | "dns-addr" => {
                        flags.dns_addr = true;
                        skip_next = !has_eq;
                    }
                    "dns-port" => {
                        flags.dns_port = true;
                        skip_next = !has_eq;
                    }
                    "ipv4-only" | "dns-ipv4-only" => flags.ipv4_only = true,
                    "no-ipv4-only" | "no-dns-ipv4-only" => flags.no_ipv4_only = true,
                    "enable-doh" => flags.enable_doh = true,
                    "no-doh" => flags.no_doh = true,
                    "include" | "pattern" => {
                        flags.include_patterns = true;
                        skip_next = !has_eq;
                    }
                    "bypass" => {
                        flags.bypass_domains = true;
                        skip_next = !has_eq;
                    }
                    "split-app" => {
                        flags.split_apps = true;
                        skip_next = !has_eq;
                    }
                    "system-proxy" => flags.system_proxy = true,
                    "no-system-proxy" => flags.no_system_proxy = true,
                    "socks-system-proxy" => flags.socks_system_proxy = true,
                    "no-socks-proxy" | "no-socks-system-proxy" => flags.no_socks_proxy = true,
                    "env-proxy" | "launchd-env" => flags.env_proxy = true,
                    "no-env-proxy" | "no-launchd-env" => flags.no_env_proxy = true,
                    "allow-quic" | "no-block-quic" => flags.allow_quic = true,
                    "block-quic" => flags.block_quic = true,
                    "timeout" => {
                        flags.timeout_ms = true;
                        skip_next = !has_eq;
                    }
                    "tun" => flags.tun = true,
                    "proxy" => flags.proxy = true,
                    "tun-ipv6" => flags.tun_ipv6 = true,
                    "no-tun-ipv6" => flags.no_tun_ipv6 = true,
                    "config" | "vpn-coexistence" | "split-mode" => {
                        skip_next = !has_eq;
                    }
                    _ => {}
                }
            } else if let Some(short_cluster) = arg.strip_prefix('-') {
                if short_cluster.is_empty() {
                    continue;
                }
                let mut chars = short_cluster.chars().peekable();
                while let Some(ch) = chars.next() {
                    match ch {
                        'b' => {
                            flags.bind = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        'p' => {
                            flags.port = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        's' => {
                            flags.socks_port = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        'm' => {
                            flags.mode = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        'c' => {
                            flags.chunk_size = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        't' => {
                            flags.timeout_ms = true;
                            if chars.peek().is_none() {
                                skip_next = true;
                            }
                            break;
                        }
                        '4' => flags.ipv4_only = true,
                        'd' | 'q' => {}
                        _ => break,
                    }
                }
            }
        }

        flags
    }
}

impl CliArgs {
    pub fn parse_from_iter<I, T>(args: I) -> Result<Self, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let args_vec: Vec<OsString> = args.into_iter().map(Into::into).collect();
        let raw_args: Vec<String> = args_vec
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let parsed = Self::try_parse_from(args_vec)?;
        let explicit = ExplicitFlags::from_args(&raw_args);

        let conflicts = [
            (parsed.tun && parsed.proxy, "--tun", "--proxy"),
            (
                explicit.enable_doh && explicit.no_doh,
                "--enable-doh",
                "--no-doh",
            ),
            (
                explicit.system_proxy && explicit.no_system_proxy,
                "--system-proxy",
                "--no-system-proxy",
            ),
            (
                explicit.socks_system_proxy && explicit.no_socks_proxy,
                "--socks-system-proxy",
                "--no-socks-proxy",
            ),
            (
                explicit.env_proxy && explicit.no_env_proxy,
                "--env-proxy",
                "--no-env-proxy",
            ),
            (
                (parsed.ipv4_only || explicit.ipv4_only)
                    && (parsed.no_ipv4_only || explicit.no_ipv4_only),
                "--ipv4-only",
                "--no-ipv4-only",
            ),
            (
                (parsed.tun_ipv6 || explicit.tun_ipv6)
                    && (parsed.no_tun_ipv6 || explicit.no_tun_ipv6),
                "--tun-ipv6",
                "--no-tun-ipv6",
            ),
            (
                (parsed.allow_quic || explicit.allow_quic)
                    && (parsed.block_quic || explicit.block_quic),
                "--allow-quic",
                "--block-quic",
            ),
        ];

        for (conflicted, left, right) in conflicts {
            if conflicted {
                return Err(<Self as clap::CommandFactory>::command().error(
                    clap::error::ErrorKind::ArgumentConflict,
                    format!("the argument '{left}' cannot be used with '{right}'"),
                ));
            }
        }

        Ok(parsed)
    }

    pub fn into_runtime_config(self) -> RuntimeConfig {
        self.resolve_runtime_config(&FileConfig::default(), &[])
    }

    /// Resolves effective runtime settings with strict precedence:
    /// `CLI flags > config.toml > built-in defaults`.
    pub fn resolve_runtime_config(
        self,
        file_cfg: &FileConfig,
        explicit_args: &[String],
    ) -> RuntimeConfig {
        let explicit = ExplicitFlags::from_args(explicit_args);

        let engine = if self.tun || explicit.tun {
            EngineMode::Tun
        } else if self.proxy || explicit.proxy {
            EngineMode::Proxy
        } else {
            file_cfg.engine.unwrap_or(EngineMode::Proxy)
        };

        let addr = if explicit.bind {
            self.bind
        } else {
            file_cfg.bind.unwrap_or(self.bind)
        };

        let port = if explicit.port {
            self.port
        } else {
            file_cfg.port.unwrap_or(self.port)
        };

        let raw_socks_port = if explicit.socks_port {
            self.socks_port
        } else {
            file_cfg.socks_port.unwrap_or(self.socks_port)
        };
        let socks_port = if raw_socks_port == 0 || raw_socks_port == port {
            None
        } else {
            Some(raw_socks_port)
        };

        let dns_addr = if explicit.dns_addr {
            self.dns_addr
        } else {
            file_cfg
                .dns_addr
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(self.dns_addr)
        };

        let dns_port = if explicit.dns_port {
            self.dns_port
        } else {
            file_cfg.dns_port.unwrap_or(self.dns_port)
        };

        let dns_ipv4_only = if self.no_ipv4_only || explicit.no_ipv4_only {
            false
        } else if explicit.ipv4_only || self.ipv4_only {
            true
        } else {
            file_cfg.ipv4_only.unwrap_or(false)
        };

        let enable_doh = if self.no_doh || explicit.no_doh {
            false
        } else if explicit.enable_doh {
            self.enable_doh
        } else {
            file_cfg.doh.unwrap_or(self.enable_doh)
        };

        let chunk_size = if explicit.chunk_size {
            self.chunk_size
        } else {
            file_cfg.chunk_size.unwrap_or(self.chunk_size)
        }
        .max(1);

        let mode = if explicit.mode {
            self.mode
        } else {
            file_cfg.mode.unwrap_or(self.mode)
        };

        let patterns = if explicit.include_patterns || !self.include_patterns.is_empty() {
            self.include_patterns
        } else {
            file_cfg.include_domains.clone().unwrap_or_default()
        };

        let bypass_domains = if explicit.bypass_domains || !self.bypass_domains.is_empty() {
            self.bypass_domains
        } else {
            file_cfg.bypass_domains.clone().unwrap_or_default()
        };

        let split_tunnel_mode = self
            .split_mode
            .or(file_cfg.split_tunnel_mode)
            .unwrap_or_default();

        let split_tunnel_apps = if explicit.split_apps || !self.split_apps.is_empty() {
            sanitize_split_tunnel_apps(&self.split_apps)
        } else {
            file_cfg
                .split_tunnel_apps
                .as_deref()
                .map(sanitize_split_tunnel_apps)
                .unwrap_or_default()
        };

        let split_tunnel = SplitTunnelConfig {
            mode: split_tunnel_mode,
            apps: split_tunnel_apps,
        };

        let system_proxy = if self.no_system_proxy || explicit.no_system_proxy {
            false
        } else if explicit.system_proxy {
            self.system_proxy
        } else {
            file_cfg.system_proxy.unwrap_or(self.system_proxy)
        };

        let socks_system_proxy_pref = if self.no_socks_proxy || explicit.no_socks_proxy {
            false
        } else if explicit.socks_system_proxy {
            self.socks_system_proxy
        } else {
            file_cfg
                .socks_system_proxy
                .unwrap_or(self.socks_system_proxy)
        };
        let socks_system_proxy = system_proxy && socks_system_proxy_pref && socks_port.is_some();

        let env_proxy_pref = if self.no_env_proxy || explicit.no_env_proxy {
            false
        } else if explicit.env_proxy {
            self.env_proxy
        } else {
            file_cfg.env_proxy.unwrap_or(self.env_proxy)
        };
        let env_proxy = system_proxy && env_proxy_pref;

        let block_quic = if self.allow_quic || explicit.allow_quic {
            false
        } else if self.block_quic || explicit.block_quic {
            true
        } else {
            file_cfg.block_quic.unwrap_or(true)
        };

        let raw_timeout_ms = if explicit.timeout_ms {
            self.timeout_ms
        } else {
            file_cfg.timeout_ms.unwrap_or(self.timeout_ms)
        };
        let connect_timeout = if raw_timeout_ms == 0 {
            Duration::from_millis(8000)
        } else {
            Duration::from_millis(raw_timeout_ms)
        };

        let vpn_coexistence = self
            .vpn_coexistence
            .or(file_cfg.vpn_coexistence)
            .unwrap_or_default();

        let tun_ipv6 = if self.no_tun_ipv6 || explicit.no_tun_ipv6 {
            false
        } else if explicit.tun_ipv6 || self.tun_ipv6 {
            true
        } else {
            file_cfg.tun_ipv6.unwrap_or(false)
        };

        RuntimeConfig {
            engine,
            addr,
            port,
            socks_port,
            dns_addr,
            dns_port,
            dns_ipv4_only,
            enable_doh,
            disable_system_dns_fallback: false,
            chunk_size,
            mode,
            patterns,
            bypass_domains,
            split_tunnel,
            system_proxy,
            socks_system_proxy,
            env_proxy,
            block_quic,
            connect_timeout,
            vpn_coexistence,
            tun_ipv6,
            debug: self.debug,
            quiet: self.quiet,
            windows_service: self.service,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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

    #[test]
    fn parses_tun_and_proxy_engine_flags() {
        let default_cfg = CliArgs::parse_from_iter(["vdpi"])
            .expect("valid default args")
            .into_runtime_config();
        assert_eq!(default_cfg.engine, EngineMode::Proxy);

        let tun_cli = CliArgs::parse_from_iter(["vdpi", "start", "--tun"]).expect("valid --tun");
        assert!(tun_cli.tun);
        assert!(!tun_cli.proxy);
        assert!(matches!(tun_cli.command, Some(Command::Start)));
        assert_eq!(tun_cli.into_runtime_config().engine, EngineMode::Tun);

        let proxy_cli = CliArgs::parse_from_iter(["vdpi", "--proxy"]).expect("valid --proxy");
        assert!(proxy_cli.proxy);
        assert!(!proxy_cli.tun);
        assert_eq!(proxy_cli.into_runtime_config().engine, EngineMode::Proxy);
    }

    #[test]
    fn rejects_conflicting_tun_and_proxy_flags() {
        let err = CliArgs::parse_from_iter(["vdpi", "--tun", "--proxy"])
            .expect_err("--tun and --proxy must conflict");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);

        let sub_err = CliArgs::parse_from_iter(["vdpi", "--tun", "start", "--proxy"])
            .expect_err("--tun and --proxy across subcommand must conflict");
        assert_eq!(sub_err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn parses_engine_subcommand() {
        let show = CliArgs::parse_from_iter(["vdpi", "engine"]).expect("valid engine subcommand");
        assert_eq!(show.command, Some(Command::Engine { mode: None }));

        let to_tun = CliArgs::parse_from_iter(["vdpi", "engine", "tun"]).expect("valid engine tun");
        assert_eq!(
            to_tun.command,
            Some(Command::Engine {
                mode: Some(EngineMode::Tun)
            })
        );

        let to_proxy =
            CliArgs::parse_from_iter(["vdpi", "engine", "proxy"]).expect("valid engine proxy");
        assert_eq!(
            to_proxy.command,
            Some(Command::Engine {
                mode: Some(EngineMode::Proxy)
            })
        );
    }

    #[test]
    fn parses_install_and_uninstall_flags() {
        let install = CliArgs::parse_from_iter(["vdpi", "install"]).expect("valid install");
        assert_eq!(install.command, Some(Command::Install { upgrade: false }));

        let install_upgrade = CliArgs::parse_from_iter(["vdpi", "install", "--upgrade"])
            .expect("valid install --upgrade");
        assert_eq!(
            install_upgrade.command,
            Some(Command::Install { upgrade: true })
        );

        let uninstall = CliArgs::parse_from_iter(["vdpi", "uninstall"]).expect("valid uninstall");
        assert_eq!(uninstall.command, Some(Command::Uninstall { purge: false }));

        let uninstall_purge = CliArgs::parse_from_iter(["vdpi", "uninstall", "--purge"])
            .expect("valid uninstall --purge");
        assert_eq!(
            uninstall_purge.command,
            Some(Command::Uninstall { purge: true })
        );
    }

    #[test]
    fn parses_config_subcommands() {
        let bare = CliArgs::parse_from_iter(["vdpi", "config"]).expect("valid config");
        assert_eq!(bare.command, Some(Command::Config { action: None }));

        let show = CliArgs::parse_from_iter(["vdpi", "config", "show"]).expect("valid config show");
        assert_eq!(
            show.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Show { json: false })
            })
        );

        let show_json = CliArgs::parse_from_iter(["vdpi", "config", "show", "--json"])
            .expect("valid config show --json");
        assert_eq!(
            show_json.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Show { json: true })
            })
        );

        let path = CliArgs::parse_from_iter(["vdpi", "config", "path"]).expect("valid config path");
        assert_eq!(
            path.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Path)
            })
        );

        let get = CliArgs::parse_from_iter(["vdpi", "config", "get", "engine"])
            .expect("valid config get");
        assert_eq!(
            get.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Get {
                    key: "engine".to_string(),
                })
            })
        );

        let set = CliArgs::parse_from_iter(["vdpi", "config", "set", "engine", "tun"])
            .expect("valid config set");
        assert_eq!(
            set.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Set {
                    key: "engine".to_string(),
                    value: "tun".to_string(),
                })
            })
        );

        let unset = CliArgs::parse_from_iter(["vdpi", "config", "unset", "port"])
            .expect("valid config unset");
        assert_eq!(
            unset.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Unset {
                    key: "port".to_string(),
                })
            })
        );

        let validate =
            CliArgs::parse_from_iter(["vdpi", "config", "validate"]).expect("valid validate");
        assert_eq!(
            validate.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Validate)
            })
        );

        let reset = CliArgs::parse_from_iter(["vdpi", "config", "reset"]).expect("valid reset");
        assert_eq!(
            reset.command,
            Some(Command::Config {
                action: Some(ConfigCommand::Reset)
            })
        );
    }

    #[test]
    fn parses_global_config_vpn_and_internal_flags() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--config",
            "/etc/vdpi/custom.toml",
            "--vpn-coexistence",
            "warn",
            "--tun-ipv6",
            "--internal-linux-tun-cleanup",
            "--internal-macos-tun-guard",
        ])
        .expect("valid global and internal flags");

        assert_eq!(
            cli.config_path,
            Some(PathBuf::from("/etc/vdpi/custom.toml"))
        );
        assert_eq!(cli.vpn_coexistence, Some(VpnCoexistence::Warn));
        assert!(cli.tun_ipv6);
        assert!(cli.internal_linux_tun_cleanup);
        assert!(cli.internal_macos_tun_guard);

        let cfg = cli.into_runtime_config();
        assert_eq!(cfg.vpn_coexistence, VpnCoexistence::Warn);
        assert!(cfg.tun_ipv6);
    }

    #[test]
    fn resolve_runtime_config_preserves_file_config_when_cli_flags_omitted() {
        let file_cfg = FileConfig {
            schema_version: Some(1),
            engine: Some(EngineMode::Tun),
            mode: Some(DesyncMode::Fragment),
            doh: Some(false),
            block_quic: Some(false),
            dns_addr: Some("9.9.9.9".to_string()),
            bypass_domains: Some(vec!["*.corp.internal".to_string()]),
            include_domains: Some(vec!["^discord\\.com$".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec!["discord.exe".to_string()]),
            vpn_coexistence: Some(VpnCoexistence::Warn),
            tun_ipv6: Some(true),
            chunk_size: Some(4),
            bind: Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            port: Some(9090),
            socks_port: Some(1090),
            dns_port: Some(5353),
            ipv4_only: Some(true),
            timeout_ms: Some(4500),
            system_proxy: Some(false),
            socks_system_proxy: Some(false),
            env_proxy: Some(false),
        };

        let argv = vec!["vdpi".to_string(), "start".to_string()];
        let cli = CliArgs::parse_from_iter(&argv).expect("valid bare start");
        let cfg = cli.resolve_runtime_config(&file_cfg, &argv);

        assert_eq!(cfg.engine, EngineMode::Tun);
        assert_eq!(cfg.mode, DesyncMode::Fragment);
        assert!(!cfg.enable_doh);
        assert!(!cfg.block_quic);
        assert_eq!(cfg.dns_addr, "9.9.9.9");
        assert_eq!(cfg.bypass_domains, vec!["*.corp.internal".to_string()]);
        assert_eq!(cfg.patterns, vec!["^discord\\.com$".to_string()]);
        assert_eq!(cfg.split_tunnel.mode, SplitTunnelMode::Exclude);
        assert_eq!(cfg.split_tunnel.apps, vec!["discord.exe".to_string()]);
        assert_eq!(cfg.vpn_coexistence, VpnCoexistence::Warn);
        assert!(cfg.tun_ipv6);
        assert_eq!(cfg.chunk_size, 4);
        assert_eq!(cfg.addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(cfg.port, 9090);
        assert_eq!(cfg.socks_port, Some(1090));
        assert_eq!(cfg.dns_port, 5353);
        assert!(cfg.dns_ipv4_only);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(4500));
        assert!(!cfg.system_proxy);
        assert!(!cfg.socks_system_proxy);
        assert!(!cfg.env_proxy);
    }

    #[test]
    fn resolve_runtime_config_lets_explicit_cli_override_file_config() {
        let file_cfg = FileConfig {
            engine: Some(EngineMode::Tun),
            mode: Some(DesyncMode::Fragment),
            doh: Some(true),
            block_quic: Some(true),
            dns_addr: Some("9.9.9.9".to_string()),
            bypass_domains: Some(vec!["file.example.com".to_string()]),
            include_domains: Some(vec!["^file\\.example\\.com$".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec!["discord.exe".to_string()]),
            vpn_coexistence: Some(VpnCoexistence::Warn),
            tun_ipv6: Some(false),
            chunk_size: Some(4),
            port: Some(9090),
            socks_port: Some(1090),
            ..FileConfig::default()
        };

        let argv: Vec<String> = [
            "vdpi",
            "start",
            "--proxy",
            "--port=7777",
            "-m",
            "split",
            "--dns",
            "8.8.8.8",
            "--no-doh",
            "--allow-quic",
            "--bypass",
            "cli.example.com",
            "--include",
            "^cli\\.example\\.com$",
            "--split-mode",
            "include",
            "--split-app",
            "chrome.exe",
            "--split-app",
            "firefox.exe",
            "--vpn-coexistence",
            "off",
            "--tun-ipv6",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();

        let cli = CliArgs::parse_from_iter(&argv).expect("valid override args");
        let cfg = cli.resolve_runtime_config(&file_cfg, &argv);

        // Explicit CLI flags override config.toml
        assert_eq!(cfg.engine, EngineMode::Proxy);
        assert_eq!(cfg.port, 7777);
        assert_eq!(cfg.mode, DesyncMode::Split);
        assert_eq!(cfg.dns_addr, "8.8.8.8");
        assert!(!cfg.enable_doh);
        assert!(!cfg.block_quic);
        assert_eq!(cfg.bypass_domains, vec!["cli.example.com".to_string()]);
        assert_eq!(cfg.patterns, vec!["^cli\\.example\\.com$".to_string()]);
        assert_eq!(cfg.split_tunnel.mode, SplitTunnelMode::Include);
        assert_eq!(
            cfg.split_tunnel.apps,
            vec!["chrome.exe".to_string(), "firefox.exe".to_string()]
        );
        assert_eq!(cfg.vpn_coexistence, VpnCoexistence::Off);
        assert!(cfg.tun_ipv6);

        // Omitted CLI flags still fall back to config.toml
        assert_eq!(cfg.chunk_size, 4);
        assert_eq!(cfg.socks_port, Some(1090));
    }

    #[test]
    fn resolve_runtime_config_falls_back_to_defaults_when_file_config_empty() {
        let argv = vec!["vdpi".to_string()];
        let cli = CliArgs::parse_from_iter(&argv).expect("valid default args");
        let cfg = cli.resolve_runtime_config(&FileConfig::default(), &argv);

        assert_eq!(cfg.engine, EngineMode::Proxy);
        assert_eq!(cfg.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.socks_port, Some(1080));
        assert_eq!(cfg.dns_addr, "1.1.1.1");
        assert_eq!(cfg.dns_port, 53);
        assert!(!cfg.dns_ipv4_only);
        assert!(cfg.enable_doh);
        assert_eq!(cfg.chunk_size, 10);
        assert_eq!(cfg.mode, DesyncMode::Combo);
        assert!(cfg.patterns.is_empty());
        assert!(cfg.bypass_domains.is_empty());
        assert_eq!(cfg.split_tunnel, SplitTunnelConfig::default());
        assert!(cfg.system_proxy);
        assert!(cfg.socks_system_proxy);
        assert!(cfg.env_proxy);
        assert!(cfg.block_quic);
        assert_eq!(cfg.connect_timeout, Duration::from_millis(8000));
        assert_eq!(cfg.vpn_coexistence, VpnCoexistence::AutoYield);
        assert!(!cfg.tun_ipv6);
    }

    #[test]
    fn resolve_runtime_config_boolean_precedence_parity() {
        let file_cfg = FileConfig {
            doh: Some(false),
            block_quic: Some(false),
            tun_ipv6: Some(true),
            ipv4_only: Some(true),
            system_proxy: Some(false),
            socks_system_proxy: Some(false),
            env_proxy: Some(false),
            ..FileConfig::default()
        };

        let argv: Vec<String> = [
            "vdpi",
            "start",
            "--enable-doh",
            "--block-quic",
            "--no-tun-ipv6",
            "--no-ipv4-only",
            "--system-proxy",
            "--socks-system-proxy",
            "--env-proxy",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();

        let cli = CliArgs::parse_from_iter(&argv).expect("valid boolean override flags");
        let cfg = cli.resolve_runtime_config(&file_cfg, &argv);

        assert!(cfg.enable_doh);
        assert!(cfg.block_quic);
        assert!(!cfg.tun_ipv6);
        assert!(!cfg.dns_ipv4_only);
        assert!(cfg.system_proxy);
        assert!(cfg.socks_system_proxy);
        assert!(cfg.env_proxy);
    }

    #[test]
    fn rejects_conflicting_boolean_flag_pairs() {
        let pairs = [
            ("--no-doh", "--enable-doh"),
            ("--no-system-proxy", "--system-proxy"),
            ("--no-socks-system-proxy", "--socks-system-proxy"),
            ("--no-socks-proxy", "--socks-system-proxy"),
            ("--no-env-proxy", "--env-proxy"),
            ("--no-ipv4-only", "--ipv4-only"),
            ("--no-ipv4-only", "-4"),
            ("--no-tun-ipv6", "--tun-ipv6"),
            ("--allow-quic", "--block-quic"),
        ];

        for (left, right) in pairs {
            let direct = CliArgs::parse_from_iter(["vdpi", left, right])
                .expect_err("paired boolean flags must conflict");
            assert_eq!(
                direct.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "expected ArgumentConflict for {left} + {right}"
            );

            let across_sub = CliArgs::parse_from_iter(["vdpi", left, "start", right])
                .expect_err("paired boolean flags across subcommand must conflict");
            assert_eq!(
                across_sub.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "expected ArgumentConflict for {left} start {right}"
            );
        }
    }

    #[test]
    fn resolve_runtime_config_overlays_split_tunnel_cli_flags() {
        let file_cfg = FileConfig {
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec![
                " Discord.exe ".to_string(),
                "discord".to_string(),
                "steam.exe".to_string(),
            ]),
            ..FileConfig::default()
        };

        // CLI --split-mode only overlays mode; file apps remain (sanitized).
        let mode_only_argv: Vec<String> = ["vdpi", "start", "--split-mode=include"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mode_only_cli =
            CliArgs::parse_from_iter(&mode_only_argv).expect("valid --split-mode override");
        let mode_only_cfg = mode_only_cli.resolve_runtime_config(&file_cfg, &mode_only_argv);
        assert_eq!(mode_only_cfg.split_tunnel.mode, SplitTunnelMode::Include);
        assert_eq!(
            mode_only_cfg.split_tunnel.apps,
            vec!["Discord.exe".to_string(), "steam.exe".to_string()]
        );

        // CLI --split-app only overlays apps (sanitized & deduped); file mode remains.
        let apps_only_argv: Vec<String> = [
            "vdpi",
            "start",
            "--split-app",
            " Chrome.exe ",
            "--split-app=chrome",
            "--split-app",
            "firefox.exe",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let apps_only_cli =
            CliArgs::parse_from_iter(&apps_only_argv).expect("valid --split-app override");
        let apps_only_cfg = apps_only_cli.resolve_runtime_config(&file_cfg, &apps_only_argv);
        assert_eq!(apps_only_cfg.split_tunnel.mode, SplitTunnelMode::Exclude);
        assert_eq!(
            apps_only_cfg.split_tunnel.apps,
            vec!["Chrome.exe".to_string(), "firefox.exe".to_string()]
        );
    }

    #[test]
    fn parses_dashboard_and_split_subcommands_and_aliases() {
        let dash = CliArgs::parse_from_iter(["vdpi", "dashboard"]).unwrap();
        assert_eq!(dash.command, Some(Command::Dashboard));
        let dash_alias = CliArgs::parse_from_iter(["vdpi", "dash"]).unwrap();
        assert_eq!(dash_alias.command, Some(Command::Dashboard));

        let split_bare = CliArgs::parse_from_iter(["vdpi", "split"]).unwrap();
        assert_eq!(split_bare.command, Some(Command::Split { action: None }));
        let apps_alias = CliArgs::parse_from_iter(["vdpi", "apps"]).unwrap();
        assert_eq!(apps_alias.command, Some(Command::Split { action: None }));
        let split_tunnel_alias = CliArgs::parse_from_iter(["vdpi", "split-tunnel"]).unwrap();
        assert_eq!(
            split_tunnel_alias.command,
            Some(Command::Split { action: None })
        );

        let status = CliArgs::parse_from_iter(["vdpi", "split", "status"]).unwrap();
        assert_eq!(
            status.command,
            Some(Command::Split {
                action: Some(SplitCommand::Status)
            })
        );

        let list = CliArgs::parse_from_iter(["vdpi", "split", "list", "--query", "disc"]).unwrap();
        assert_eq!(
            list.command,
            Some(Command::Split {
                action: Some(SplitCommand::List {
                    query: Some("disc".to_string())
                })
            })
        );
        let list_short = CliArgs::parse_from_iter(["vdpi", "split", "list", "-f", "disc"]).unwrap();
        assert_eq!(
            list_short.command,
            Some(Command::Split {
                action: Some(SplitCommand::List {
                    query: Some("disc".to_string())
                })
            })
        );

        let mode = CliArgs::parse_from_iter(["vdpi", "split", "mode", "exclude"]).unwrap();
        assert_eq!(
            mode.command,
            Some(Command::Split {
                action: Some(SplitCommand::Mode {
                    mode: SplitTunnelMode::Exclude
                })
            })
        );

        let add =
            CliArgs::parse_from_iter(["vdpi", "apps", "add", "discord.exe", "steam.exe"]).unwrap();
        assert_eq!(
            add.command,
            Some(Command::Split {
                action: Some(SplitCommand::Add {
                    apps: vec!["discord.exe".to_string(), "steam.exe".to_string()]
                })
            })
        );

        let remove = CliArgs::parse_from_iter(["vdpi", "split", "remove", "discord.exe"]).unwrap();
        assert_eq!(
            remove.command,
            Some(Command::Split {
                action: Some(SplitCommand::Remove {
                    apps: vec!["discord.exe".to_string()]
                })
            })
        );

        let clear = CliArgs::parse_from_iter(["vdpi", "split", "clear"]).unwrap();
        assert_eq!(
            clear.command,
            Some(Command::Split {
                action: Some(SplitCommand::Clear)
            })
        );
    }

    #[test]
    fn parses_split_apply_subcommand() {
        <CliArgs as clap::CommandFactory>::command().debug_assert();

        let apply = CliArgs::parse_from_iter([
            "vdpi",
            "split",
            "apply",
            "--mode",
            "include",
            "--app",
            "discord.exe",
            "--app",
            "chrome.exe",
        ])
        .expect("valid split apply command");
        assert_eq!(
            apply.command,
            Some(Command::Split {
                action: Some(SplitCommand::Apply {
                    mode: SplitTunnelMode::Include,
                    apps: vec!["discord.exe".to_string(), "chrome.exe".to_string()],
                })
            })
        );

        let apply_empty = CliArgs::parse_from_iter(["vdpi", "split", "apply", "--mode", "all"])
            .expect("valid split apply command with no apps");
        assert_eq!(
            apply_empty.command,
            Some(Command::Split {
                action: Some(SplitCommand::Apply {
                    mode: SplitTunnelMode::All,
                    apps: Vec::new(),
                })
            })
        );
    }
}
