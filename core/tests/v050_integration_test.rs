use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use vdpi::binder::{windows_ipv4_unicast_if_value, windows_ipv6_unicast_if_value};
use vdpi::bypass::{BypassClass, BypassPolicy, IpNet};
use vdpi::config::{CliArgs, DesyncMode, EngineMode, RuntimeConfig, VpnCoexistence};
use vdpi::config_file::{
    load_file_config, parse_config_toml, render_config_toml, set_config_key, unset_config_key,
    FileConfig, CONFIG_SCHEMA_VERSION,
};
use vdpi::desync::{EngineContext, LearnedStrategy};
use vdpi::health::{render_health_json, HealthRuntimeMeta};
use vdpi::platform::vpn::{classify_vpn_adapter_name, is_excluded_non_vpn_adapter, VpnScope};
use vdpi::platform::vpn_guard::{GuardAction, GuardState, VpnGuard, DEFAULT_RECOVERY_DEBOUNCE};
use vdpi::platform::windows_tun::{
    ipv4_in_cidr, is_routed_public_ipv4, EXCLUDED_IPV4_CIDRS, PUBLIC_IPV4_COMPLEMENT_CIDRS,
    VDPI_TUN_DNS_V4,
};
use vdpi::service::parse_health_json;

fn parse_ip(raw: &str) -> IpAddr {
    raw.parse().expect("valid test IP address")
}

fn cidr_range(net: Ipv4Addr, prefix: u8) -> (u32, u32) {
    let mask = if prefix == 0 {
        0u32
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    let start = u32::from(net) & mask;
    let end = start | !mask;
    (start, end)
}

fn cidrs_overlap(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
    let (a_start, a_end) = cidr_range(a.0, a.1);
    let (b_start, b_end) = cidr_range(b.0, b.1);
    a_start <= b_end && b_start <= a_end
}

fn cidr_address_count(prefix: u8) -> u64 {
    1u64 << (32 - u32::from(prefix))
}

#[test]
fn config_toml_roundtrip_and_cli_precedence() {
    // 1. Parse comments, literal/escaped strings, multiline arrays, and unknown keys.
    let raw_toml = "\u{FEFF}\
# v0.5.0 integration test configuration
schema_version = 1 # inline comment
engine = 'tun' # literal string
mode = \"tls-record\"
doh = false # disable DoH in file
block_quic = false
dns_addr = \"9.9.9.9\"
bypass_domains = [
  # multiline array with comments and trailing comma
  \"*.corp.example\",
  'internal.bank.example',
]
include_domains = [
  \"^discord\\\\.com$\",
  \"^www\\\\.roblox\\\\.com$\",
]
vpn_coexistence = \"warn\"
tun_ipv6 = true
chunk_size = 6
bind = \"127.0.0.1\"
port = 8888
socks_port = 1088
dns_port = 5353
ipv4_only = true
timeout_ms = 6_500
system_proxy = false
socks_system_proxy = false
env_proxy = false
# Unknown forward-compatible keys must be silently ignored.
future_flag = true
future_timeout = 42
future_label = \"v0.6.0-preview\"
future_list = [
  \"alpha\",
  123,
  false,
]
";

    let parsed = parse_config_toml(raw_toml).expect("valid config.toml should parse");
    assert_eq!(parsed.schema_version, Some(CONFIG_SCHEMA_VERSION));
    assert_eq!(parsed.engine, Some(EngineMode::Tun));
    assert_eq!(parsed.mode, Some(DesyncMode::TlsRecord));
    assert_eq!(parsed.doh, Some(false));
    assert_eq!(parsed.block_quic, Some(false));
    assert_eq!(parsed.dns_addr.as_deref(), Some("9.9.9.9"));
    assert_eq!(
        parsed.bypass_domains,
        Some(vec![
            "*.corp.example".to_string(),
            "internal.bank.example".to_string(),
        ])
    );
    assert_eq!(
        parsed.include_domains,
        Some(vec![
            r"^discord\.com$".to_string(),
            r"^www\.roblox\.com$".to_string(),
        ])
    );
    assert_eq!(parsed.vpn_coexistence, Some(VpnCoexistence::Warn));
    assert_eq!(parsed.tun_ipv6, Some(true));
    assert_eq!(parsed.chunk_size, Some(6));
    assert_eq!(parsed.bind, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(parsed.port, Some(8888));
    assert_eq!(parsed.socks_port, Some(1088));
    assert_eq!(parsed.dns_port, Some(5353));
    assert_eq!(parsed.ipv4_only, Some(true));
    assert_eq!(parsed.timeout_ms, Some(6500));
    assert_eq!(parsed.system_proxy, Some(false));
    assert_eq!(parsed.socks_system_proxy, Some(false));
    assert_eq!(parsed.env_proxy, Some(false));

    // 2. Canonical render -> parse roundtrip preserves all known keys identically.
    let rendered = render_config_toml(&parsed);
    let reparsed = parse_config_toml(&rendered).expect("rendered TOML should roundtrip");
    assert_eq!(reparsed, parsed);

    // 3. set_config_key / unset_config_key support snake_case, kebab-case, and validation.
    let mut mutated = FileConfig::default();
    set_config_key(&mut mutated, "engine", "tun").expect("set engine");
    set_config_key(&mut mutated, "vpn-coexistence", "off").expect("set vpn-coexistence");
    set_config_key(&mut mutated, "block-quic", "false").expect("set block-quic");
    set_config_key(&mut mutated, "bypass_domains", "a.example, b.example")
        .expect("set bypass_domains");
    set_config_key(&mut mutated, "bind", "::1").expect("set bind IPv6");
    set_config_key(&mut mutated, "port", "9091").expect("set port");
    assert_eq!(mutated.engine, Some(EngineMode::Tun));
    assert_eq!(mutated.vpn_coexistence, Some(VpnCoexistence::Off));
    assert_eq!(mutated.block_quic, Some(false));
    assert_eq!(
        mutated.bypass_domains,
        Some(vec!["a.example".to_string(), "b.example".to_string()])
    );
    assert_eq!(mutated.bind, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert_eq!(mutated.port, Some(9091));
    assert!(set_config_key(&mut mutated, "unknown_option", "1").is_err());
    assert!(set_config_key(&mut mutated, "engine", "wireguard").is_err());

    for key in [
        "engine",
        "vpn-coexistence",
        "block-quic",
        "bypass_domains",
        "bind",
        "port",
    ] {
        unset_config_key(&mut mutated, key).expect("unset configured key");
    }
    assert_eq!(mutated, FileConfig::default());
    assert!(unset_config_key(&mut mutated, "nonexistent").is_err());

    // 4. Precedence: defaults when FileConfig is empty and no CLI flags are given.
    let bare_argv = ["vdpi".to_string(), "start".to_string()];
    let default_cfg = CliArgs::parse_from_iter(&bare_argv)
        .expect("valid bare start")
        .resolve_runtime_config(&FileConfig::default(), &bare_argv);
    assert_eq!(default_cfg.engine, EngineMode::Proxy);
    assert_eq!(default_cfg.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(default_cfg.port, 8080);
    assert_eq!(default_cfg.socks_port, Some(1080));
    assert_eq!(default_cfg.mode, DesyncMode::Combo);
    assert_eq!(default_cfg.chunk_size, 10);
    assert_eq!(default_cfg.dns_addr, "1.1.1.1");
    assert_eq!(default_cfg.dns_port, 53);
    assert!(default_cfg.enable_doh);
    assert!(default_cfg.block_quic);
    assert_eq!(default_cfg.connect_timeout, Duration::from_millis(8000));
    assert_eq!(default_cfg.vpn_coexistence, VpnCoexistence::AutoYield);
    assert!(!default_cfg.tun_ipv6);

    // 5. Precedence: config.toml overrides built-in defaults when CLI flags are omitted.
    let from_file = CliArgs::parse_from_iter(&bare_argv)
        .expect("valid bare start")
        .resolve_runtime_config(&parsed, &bare_argv);
    assert_eq!(from_file.engine, EngineMode::Tun);
    assert_eq!(from_file.mode, DesyncMode::TlsRecord);
    assert!(!from_file.enable_doh);
    assert!(!from_file.block_quic);
    assert_eq!(from_file.dns_addr, "9.9.9.9");
    assert_eq!(from_file.port, 8888);
    assert_eq!(from_file.socks_port, Some(1088));
    assert_eq!(from_file.chunk_size, 6);
    assert_eq!(from_file.vpn_coexistence, VpnCoexistence::Warn);
    assert!(from_file.tun_ipv6);
    assert_eq!(from_file.connect_timeout, Duration::from_millis(6500));

    // 6. Precedence: explicit CLI flags override config.toml while omitted flags inherit file values.
    let cli_override_argv = [
        "vdpi",
        "start",
        "--proxy",
        "--port=9191",
        "--mode",
        "split",
        "--dns",
        "1.0.0.1",
        "--vpn-coexistence",
        "off",
        "--bypass",
        "cli-only.example",
    ]
    .map(str::to_string);
    let merged = CliArgs::parse_from_iter(&cli_override_argv)
        .expect("valid override args")
        .resolve_runtime_config(&parsed, &cli_override_argv);
    assert_eq!(merged.engine, EngineMode::Proxy);
    assert_eq!(merged.port, 9191);
    assert_eq!(merged.mode, DesyncMode::Split);
    assert_eq!(merged.dns_addr, "1.0.0.1");
    assert_eq!(merged.vpn_coexistence, VpnCoexistence::Off);
    assert_eq!(merged.bypass_domains, ["cli-only.example"]);
    // Omitted flags still come from config.toml.
    assert_eq!(merged.socks_port, Some(1088));
    assert_eq!(merged.chunk_size, 6);
    assert!(!merged.enable_doh);
    assert!(!merged.block_quic);
    assert!(merged.tun_ipv6);
    assert_eq!(merged.connect_timeout, Duration::from_millis(6500));

    // 7. Explicit CLI boolean overrides (`--block-quic`, `--no-tun-ipv6`) win over config.toml.
    let cli_bool_override_argv =
        ["vdpi", "start", "--block-quic", "--no-tun-ipv6"].map(str::to_string);
    let bool_merged = CliArgs::parse_from_iter(&cli_bool_override_argv)
        .expect("valid --block-quic / --no-tun-ipv6 args")
        .resolve_runtime_config(&parsed, &cli_bool_override_argv);
    assert!(bool_merged.block_quic);
    assert!(!bool_merged.tun_ipv6);
    assert_eq!(bool_merged.engine, EngineMode::Tun);
    assert!(!bool_merged.enable_doh);
}

#[test]
fn explicit_missing_config_path_returns_error() {
    let missing = std::env::temp_dir().join(format!(
        "vdpi-nonexistent-config-{}.toml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);
    let cli = CliArgs::parse_from_iter([
        "vdpi",
        "--config",
        missing
            .to_str()
            .expect("temp config path should be valid UTF-8"),
        "start",
    ])
    .expect("CLI should parse explicit --config path");
    let explicit = cli.config_path.as_deref().expect("config_path populated");
    let err = load_file_config(Some(explicit), false)
        .expect_err("explicit --config pointing to a missing file must fail");
    let msg = format!("{err:#}");
    assert!(
        !msg.is_empty(),
        "missing explicit --config error message must be non-empty"
    );
}

#[test]
fn vpn_guard_full_lifecycle_transitions() {
    // 1. Adapter name classification and non-VPN exclusions.
    assert_eq!(
        classify_vpn_adapter_name("Mullvad", "WireGuard Tunnel"),
        Some("Mullvad")
    );
    assert_eq!(
        classify_vpn_adapter_name("wg0", "WireGuard Tunnel"),
        Some("WireGuard")
    );
    assert_eq!(
        classify_vpn_adapter_name("Tailscale", "Tailscale Tunnel"),
        Some("Tailscale")
    );
    assert_eq!(
        classify_vpn_adapter_name("NordLynx", "NordVPN Tunnel"),
        Some("NordVPN")
    );
    assert_eq!(
        classify_vpn_adapter_name("ProtonVPN", "ProtonVPN WireGuard"),
        Some("ProtonVPN")
    );
    assert_eq!(
        classify_vpn_adapter_name("CloudflareWARP", "Cloudflare WARP"),
        Some("Cloudflare WARP")
    );
    assert_eq!(
        classify_vpn_adapter_name("tun0", "TAP-Windows Adapter V9"),
        Some("OpenVPN")
    );

    for (name, desc) in [
        ("vdpi0", "vdpi Tunnel"),
        ("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter"),
        ("docker0", "Docker Bridge"),
        ("vmnet8", "VMware Virtual Ethernet Adapter"),
        ("lo0", "Software Loopback Interface 1"),
        ("Ethernet", "Intel(R) Ethernet Controller I225-V"),
    ] {
        assert_eq!(
            classify_vpn_adapter_name(name, desc),
            None,
            "adapter ({name}, {desc}) must not be classified as third-party VPN"
        );
    }
    assert!(is_excluded_non_vpn_adapter("vdpi0", "vdpi Tunnel"));
    assert!(is_excluded_non_vpn_adapter("vEthernet (WSL)", "Hyper-V"));

    // 2. AutoYield lifecycle: SplitOverlay never yields; Mullvad/WireGuard yield at 0ms;
    //    3s debounced recovery resumes at exact boundary; flapping cancels recovery.
    let t0 = Instant::now();
    let mut guard = VpnGuard::new(VpnCoexistence::AutoYield);
    assert_eq!(guard.policy(), VpnCoexistence::AutoYield);
    assert_eq!(guard.recovery_debounce(), DEFAULT_RECOVERY_DEBOUNCE);
    assert_eq!(guard.recovery_debounce(), Duration::from_secs(3));
    assert_eq!(guard.state(), &GuardState::Active);
    assert!(!guard.is_yielded());

    let tailscale_mesh = VpnScope::SplitOverlay {
        providers: vec!["Tailscale".to_string()],
    };
    assert_eq!(guard.evaluate(&tailscale_mesh, t0), GuardAction::None);
    assert_eq!(guard.state(), &GuardState::Active);
    assert!(!guard.is_yielded());
    assert_eq!(guard.active_conflict_label(&tailscale_mesh), None);

    // Full-tunnel Mullvad triggers 0ms immediate yield.
    let mullvad = VpnScope::FullTunnel {
        provider: "Mullvad".to_string(),
        iface: "Mullvad".to_string(),
        kill_switch: true,
    };
    let t_yield = t0 + Duration::from_secs(1);
    assert_eq!(
        guard.evaluate(&mullvad, t_yield),
        GuardAction::YieldTun {
            provider: "Mullvad".to_string(),
        }
    );
    assert_eq!(
        guard.state(),
        &GuardState::YieldedStandby {
            provider: "Mullvad".to_string(),
            since: t_yield,
        }
    );
    assert!(guard.is_yielded());
    assert_eq!(
        guard.active_conflict_label(&mullvad).as_deref(),
        Some("Mullvad (yielded)")
    );

    // Switching directly to WireGuard while yielded updates provider without re-yielding.
    let wireguard = VpnScope::FullTunnel {
        provider: "WireGuard".to_string(),
        iface: "wg0".to_string(),
        kill_switch: false,
    };
    assert_eq!(
        guard.evaluate(&wireguard, t_yield + Duration::from_millis(500)),
        GuardAction::None
    );
    assert_eq!(
        guard.state(),
        &GuardState::YieldedStandby {
            provider: "WireGuard".to_string(),
            since: t_yield,
        }
    );

    // Disconnect enters Recovering; must remain yielded until full 3s elapses.
    let t_clear = t_yield + Duration::from_secs(2);
    assert_eq!(guard.evaluate(&VpnScope::None, t_clear), GuardAction::None);
    assert_eq!(guard.state(), &GuardState::Recovering { since: t_clear });
    assert!(guard.is_yielded());
    assert_eq!(
        guard.active_conflict_label(&VpnScope::None).as_deref(),
        Some("recovering")
    );
    assert_eq!(
        guard.evaluate(&VpnScope::None, t_clear + Duration::from_millis(2999)),
        GuardAction::None
    );
    assert_eq!(guard.state(), &GuardState::Recovering { since: t_clear });

    // Brief VPN reconnect before 3s cancels recovery immediately.
    let t_flap = t_clear + Duration::from_millis(2999);
    assert_eq!(
        guard.evaluate(&wireguard, t_flap),
        GuardAction::YieldTun {
            provider: "WireGuard".to_string(),
        }
    );
    assert_eq!(
        guard.state(),
        &GuardState::YieldedStandby {
            provider: "WireGuard".to_string(),
            since: t_flap,
        }
    );

    // Returning to SplitOverlay (e.g. Tailscale mesh without exit node) starts a fresh 3s debounce.
    let t_clear2 = t_flap + Duration::from_secs(1);
    assert_eq!(guard.evaluate(&tailscale_mesh, t_clear2), GuardAction::None);
    assert_eq!(guard.state(), &GuardState::Recovering { since: t_clear2 });
    assert_eq!(
        guard.evaluate(&tailscale_mesh, t_clear2 + Duration::from_millis(2999)),
        GuardAction::None
    );
    assert_eq!(
        guard.evaluate(&tailscale_mesh, t_clear2 + Duration::from_secs(3)),
        GuardAction::ResumeTun
    );
    assert_eq!(guard.state(), &GuardState::Active);
    assert!(!guard.is_yielded());
    assert_eq!(guard.active_conflict_label(&tailscale_mesh), None);

    // 3. Warn mode never yields and reports warning label on FullTunnel only.
    let mut warn_guard = VpnGuard::new(VpnCoexistence::Warn);
    assert_eq!(warn_guard.evaluate(&tailscale_mesh, t0), GuardAction::None);
    assert_eq!(warn_guard.active_conflict_label(&tailscale_mesh), None);
    assert_eq!(
        warn_guard.evaluate(&mullvad, t0 + Duration::from_secs(1)),
        GuardAction::WarnOnly {
            provider: "Mullvad".to_string(),
        }
    );
    assert_eq!(warn_guard.state(), &GuardState::Active);
    assert!(!warn_guard.is_yielded());
    assert_eq!(
        warn_guard.active_conflict_label(&mullvad).as_deref(),
        Some("Mullvad (warn)")
    );

    // 4. Off mode suppresses all actions and labels while staying Active.
    let mut off_guard = VpnGuard::new(VpnCoexistence::Off);
    for (offset, scope) in (0u64..).zip([&VpnScope::None, &tailscale_mesh, &mullvad, &wireguard]) {
        assert_eq!(
            off_guard.evaluate(scope, t0 + Duration::from_secs(offset)),
            GuardAction::None
        );
        assert_eq!(off_guard.state(), &GuardState::Active);
        assert!(!off_guard.is_yielded());
        assert_eq!(off_guard.active_conflict_label(scope), None);
    }
}

#[test]
fn windows_tun_51_cidr_complement_invariants() {
    assert_eq!(PUBLIC_IPV4_COMPLEMENT_CIDRS.len(), 51);

    // 0. Every complement and excluded CIDR must have a valid prefix and canonical zero host bits.
    for &(net, prefix) in PUBLIC_IPV4_COMPLEMENT_CIDRS
        .iter()
        .chain(EXCLUDED_IPV4_CIDRS.iter())
    {
        assert!(prefix <= 32, "CIDR {net}/{prefix} must have prefix <= 32");
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - u32::from(prefix))
        };
        assert_eq!(
            u32::from(net) & !mask,
            0,
            "CIDR {net}/{prefix} must have canonical zero host bits"
        );
    }

    // 1. Pairwise disjointness across all public complement CIDRs.
    for (idx, &a) in PUBLIC_IPV4_COMPLEMENT_CIDRS.iter().enumerate() {
        for &b in &PUBLIC_IPV4_COMPLEMENT_CIDRS[idx + 1..] {
            assert!(
                !cidrs_overlap(a, b),
                "public CIDRs {}/{} and {}/{} must not overlap",
                a.0,
                a.1,
                b.0,
                b.1
            );
        }
    }

    // 2. Zero overlap between public complement CIDRs and excluded non-public CIDRs.
    for &pub_cidr in PUBLIC_IPV4_COMPLEMENT_CIDRS {
        for &ex_cidr in EXCLUDED_IPV4_CIDRS {
            assert!(
                !cidrs_overlap(pub_cidr, ex_cidr),
                "public CIDR {}/{} must not overlap excluded CIDR {}/{}",
                pub_cidr.0,
                pub_cidr.1,
                ex_cidr.0,
                ex_cidr.1
            );
        }
    }

    // 3. Exact 2^32 partition proof: |public| + |excluded| == 4,294,967,296.
    let public_count: u64 = PUBLIC_IPV4_COMPLEMENT_CIDRS
        .iter()
        .map(|&(_, prefix)| cidr_address_count(prefix))
        .sum();
    let excluded_count: u64 = EXCLUDED_IPV4_CIDRS
        .iter()
        .map(|&(_, prefix)| cidr_address_count(prefix))
        .sum();
    assert_eq!(public_count + excluded_count, 1u64 << 32);

    // 4. Required public IPs (and boundary public IPs) are covered by exactly one complement CIDR.
    let public_ips = [
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(128, 116, 5, 33),
        Ipv4Addr::new(162, 159, 135, 232),
        Ipv4Addr::new(1, 0, 0, 0),
        Ipv4Addr::new(9, 255, 255, 255),
        Ipv4Addr::new(11, 0, 0, 0),
        Ipv4Addr::new(100, 63, 255, 255),
        Ipv4Addr::new(100, 128, 0, 0),
        Ipv4Addr::new(126, 255, 255, 255),
        Ipv4Addr::new(169, 253, 255, 255),
        Ipv4Addr::new(169, 255, 0, 0),
        Ipv4Addr::new(172, 15, 255, 255),
        Ipv4Addr::new(172, 32, 0, 0),
        Ipv4Addr::new(192, 167, 255, 255),
        Ipv4Addr::new(192, 169, 0, 0),
        Ipv4Addr::new(223, 255, 255, 255),
    ];
    for ip in public_ips {
        assert!(
            is_routed_public_ipv4(ip),
            "expected public IP {ip} to be routed via Wintun complement"
        );
        let matching_cidrs = PUBLIC_IPV4_COMPLEMENT_CIDRS
            .iter()
            .filter(|&&(net, prefix)| ipv4_in_cidr(ip, net, prefix))
            .count();
        assert_eq!(
            matching_cidrs, 1,
            "public IP {ip} must match exactly one complement CIDR"
        );
    }

    // 5. All RFC1918, CGNAT, loopback, link-local, multicast, "this network", and reserved IPs are excluded.
    let excluded_ips = [
        // 0.0.0.0/8 ("this network")
        Ipv4Addr::new(0, 0, 0, 0),
        Ipv4Addr::new(0, 255, 255, 255),
        // RFC 1918 private
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 255, 255, 254),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 31, 255, 254),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 255, 254),
        // RFC 6598 CGNAT / Tailscale
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 100, 100, 100),
        Ipv4Addr::new(100, 127, 255, 254),
        // Loopback
        Ipv4Addr::new(127, 0, 0, 1),
        Ipv4Addr::new(127, 255, 255, 254),
        // Link-local / APIPA
        Ipv4Addr::new(169, 254, 0, 1),
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(169, 254, 255, 254),
        // Multicast (mDNS, SSDP, etc.)
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(224, 0, 0, 251),
        Ipv4Addr::new(239, 255, 255, 250),
        // Reserved + limited broadcast
        Ipv4Addr::new(240, 0, 0, 0),
        Ipv4Addr::new(240, 0, 0, 1),
        Ipv4Addr::new(255, 255, 255, 255),
    ];
    for ip in excluded_ips {
        assert!(
            !is_routed_public_ipv4(ip),
            "expected non-public/special IP {ip} to be excluded from Wintun complement"
        );
    }

    // 6. VDPI_TUN_DNS_V4 (198.18.0.2) is routed into TUN while bypassed from desync.
    assert_eq!(VDPI_TUN_DNS_V4, Ipv4Addr::new(198, 18, 0, 2));
    assert!(
        is_routed_public_ipv4(VDPI_TUN_DNS_V4),
        "VDPI_TUN_DNS_V4 ({VDPI_TUN_DNS_V4}) must be routed into TUN"
    );
    let default_policy = BypassPolicy::new(&[], &[]).expect("default bypass policy");
    assert!(BypassPolicy::is_non_public_ip(IpAddr::V4(VDPI_TUN_DNS_V4)));
    assert_eq!(
        default_policy.classify(None, Some(IpAddr::V4(VDPI_TUN_DNS_V4))),
        BypassClass::LocalLan
    );
    assert!(!default_policy.should_desync(None, Some(IpAddr::V4(VDPI_TUN_DNS_V4))));
}

#[test]
fn bypass_policy_v050_cidrs_and_sensitive_domains() {
    // 1. Custom CIDR bypass (IPv4, IPv6, IPv4-mapped IPv6, bare IP, and invalid CIDR ignored).
    let policy = BypassPolicy::new(
        &[
            "203.0.113.0/24".to_string(),
            "2001:db8::/32".to_string(),
            "198.51.100.7".to_string(),
            "not-a-cidr/99".to_string(),
        ],
        &[],
    )
    .expect("valid v0.5.0 bypass policy");

    assert_eq!(
        policy.classify(Some("203.0.113.42"), None),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(Some("discord.com"), Some(parse_ip("203.0.113.200"))),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(None, Some(parse_ip("::ffff:203.0.113.10"))),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(Some("203.0.114.1"), None),
        BypassClass::DesyncEligible
    );
    assert_eq!(
        policy.classify(Some("[2001:db8::abcd]"), None),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(Some("discord.com"), Some(parse_ip("2001:db8:1234::1"))),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(None, Some(parse_ip("2001:db9::1"))),
        BypassClass::DesyncEligible
    );
    assert_eq!(
        policy.classify(Some("198.51.100.7"), None),
        BypassClass::SensitiveDirect
    );
    assert_eq!(
        policy.classify(Some("198.51.100.8"), None),
        BypassClass::DesyncEligible
    );
    assert!(IpNet::parse("10.0.0.0/8")
        .expect("valid v4 CIDR")
        .contains(parse_ip("10.1.2.3")));
    assert!(IpNet::parse("203.0.113.0/33").is_none());
    assert!(IpNet::parse("2001:db8::/129").is_none());

    // 2. Non-public IP detection covers multicast, benchmark, reserved, IETF, CGNAT, and IPv6 special ranges.
    for non_public in [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.1.1",
        "100.64.0.1",
        "192.0.0.1",
        "198.18.0.1",
        "198.19.255.255",
        "224.0.0.1",
        "224.0.0.251",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fc00::1",
        "fd7a:115c:a1e0::1",
        "fe80::1",
        "ff02::1",
        "::ffff:224.0.0.251",
        "::ffff:198.18.0.1",
    ] {
        assert!(
            BypassPolicy::is_non_public_ip(parse_ip(non_public)),
            "expected {non_public} to be classified as non-public"
        );
    }
    for public in [
        "1.1.1.1",
        "8.8.8.8",
        "162.159.135.232",
        "198.17.255.255",
        "198.20.0.0",
        "223.255.255.255",
        "2606:4700:4700::1111",
    ] {
        assert!(
            !BypassPolicy::is_non_public_ip(parse_ip(public)),
            "expected {public} to be classified as public"
        );
    }

    // 3. Turkish banks & government domains -> SensitiveDirect.
    for host in [
        "edevlet.gov.tr",
        "giris.edevlet.gov.tr",
        "turkiye.gov.tr",
        "ais.osym.gov.tr",
        "www.isbank.com.tr",
        "www.garantibbva.com.tr",
        "www.ziraatbank.com.tr",
        "www.enpara.com",
        "www.qnbfinansbank.com",
        "www.ing.com.tr",
        "www.teb.com.tr",
        "www.kuveytturk.com.tr",
        "www.albaraka.com.tr",
        "www.odeabank.com.tr",
        "api.iyzico.com",
        "www.paytr.com",
        "bkm.com.tr",
    ] {
        assert_eq!(
            policy.classify(Some(host), None),
            BypassClass::SensitiveDirect,
            "expected SensitiveDirect for {host}"
        );
        assert!(policy.is_bypassed(Some(host), None));
        assert!(!policy.should_desync(Some(host), None));
    }

    // 4. Tailscale *.ts.net -> LocalLan.
    assert_eq!(
        policy.classify(Some("workstation.tailnet123.ts.net"), None),
        BypassClass::LocalLan
    );
    assert_eq!(policy.classify(Some("ts.net"), None), BypassClass::LocalLan);
    assert!(!policy.should_desync(Some("workstation.tailnet123.ts.net"), None));

    // 5. Riot / Valorant -> SensitiveDirect.
    for host in [
        "riotgames.com",
        "auth.riotgames.com",
        "valorant.dyn.riotcdn.net",
        "playvalorant.com",
        "eu.playvalorant.com",
    ] {
        assert_eq!(
            policy.classify(Some(host), None),
            BypassClass::SensitiveDirect,
            "expected SensitiveDirect for {host}"
        );
        assert!(!policy.should_desync(Some(host), None));
    }

    // 6. Regular public targets remain DesyncEligible (and no wildcard suffix false positives).
    for host in [
        "discord.com",
        "gateway.discord.gg",
        "www.roblox.com",
        "notorg.tr",
        "fake-isbank.com.tr",
        "myts.net",
    ] {
        assert_eq!(
            policy.classify(Some(host), None),
            BypassClass::DesyncEligible,
            "expected DesyncEligible for {host}"
        );
        assert!(policy.should_desync(Some(host), None));
    }
}

#[tokio::test]
async fn health_v050_tun_and_proxy_json_contract() {
    let cfg = RuntimeConfig {
        engine: EngineMode::Tun,
        mode: DesyncMode::Combo,
        enable_doh: true,
        block_quic: true,
        ..Default::default()
    };
    let ctx = EngineContext::new(cfg).expect("create test engine context");
    ctx.telemetry.active_connections.store(5, Ordering::Relaxed);
    ctx.telemetry
        .total_connections
        .store(128, Ordering::Relaxed);
    ctx.telemetry.learned_hosts.store(9, Ordering::Relaxed);
    ctx.preferred_isp_stage
        .store(LearnedStrategy::MultiRecordOob as u8, Ordering::Relaxed);
    ctx.set_udp_flows_active(14);
    ctx.inc_quic_blocked();
    let resolved = ctx
        .dns
        .resolve("localhost")
        .await
        .expect("localhost resolution should succeed");
    assert!(!resolved.is_empty());

    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);

    // 1. TUN mode render -> parse_health_json contract with live non-zero counters.
    let tun_meta = HealthRuntimeMeta {
        engine: EngineMode::Tun,
        tun_interface: Some("vdpi0".to_string()),
        physical_nic: Some("Ethernet".to_string()),
        vpn_conflict: Some("Mullvad (yielded)".to_string()),
    };
    let tun_json = render_health_json(&ctx, &tun_meta);
    let tun_status = parse_health_json(&tun_json, loopback, 18089, None)
        .expect("rendered TUN /vdpi-health JSON must parse cleanly");
    assert_eq!(tun_status.addr, loopback);
    assert_eq!(tun_status.port, 18089);
    assert_eq!(tun_status.socks_port, None);
    assert_eq!(tun_status.engine, EngineMode::Tun);
    assert_eq!(tun_status.tun_interface.as_deref(), Some("vdpi0"));
    assert_eq!(tun_status.physical_nic.as_deref(), Some("Ethernet"));
    assert_eq!(
        tun_status.vpn_conflict.as_deref(),
        Some("Mullvad (yielded)")
    );
    assert_eq!(
        tun_status.version.as_deref(),
        Some(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(tun_status.mode.as_deref(), Some("combo"));
    assert_eq!(tun_status.doh, Some(true));
    assert_eq!(tun_status.block_quic, Some(true));
    assert_eq!(tun_status.active_connections, Some(5));
    assert_eq!(tun_status.total_connections, Some(128));
    assert_eq!(tun_status.learned_hosts, Some(9));
    assert_eq!(tun_status.isp_stage.as_deref(), Some("MultiRecordOob"));
    assert_eq!(tun_status.udp_flows_active, Some(14));
    assert_eq!(tun_status.quic_blocked, Some(1));
    assert!(
        tun_status.dns_queries >= Some(1),
        "expected dns_queries >= 1, got {:?}",
        tun_status.dns_queries
    );
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    assert!(
        tun_status.rss_kb.is_some_and(|kb| kb > 0),
        "expected positive rss_kb on desktop OS, got {:?}",
        tun_status.rss_kb
    );

    // 2. Non-zero TUN telemetry counters roundtrip via parse_health_json.
    let tun_live_body = r#"{
        "status": "ok",
        "service": "vdpi",
        "version": "0.5.0",
        "engine": "tun",
        "tun_interface": "vdpi0",
        "physical_nic": "Wi-Fi",
        "vpn_conflict": "WireGuard (yielded)",
        "mode": "combo",
        "doh": true,
        "block_quic": true,
        "active_connections": 12,
        "total_connections": 340,
        "learned_hosts": 15,
        "isp_stage": "OobSniDesync",
        "udp_flows_active": 14,
        "quic_blocked": 7,
        "dns_queries": 42,
        "rss_kb": 18432
    }"#;
    let tun_live = parse_health_json(tun_live_body, loopback, 18089, None)
        .expect("live TUN JSON payload should parse");
    assert_eq!(tun_live.engine, EngineMode::Tun);
    assert_eq!(tun_live.tun_interface.as_deref(), Some("vdpi0"));
    assert_eq!(tun_live.physical_nic.as_deref(), Some("Wi-Fi"));
    assert_eq!(
        tun_live.vpn_conflict.as_deref(),
        Some("WireGuard (yielded)")
    );
    assert_eq!(tun_live.udp_flows_active, Some(14));
    assert_eq!(tun_live.quic_blocked, Some(7));
    assert_eq!(tun_live.dns_queries, Some(42));
    assert_eq!(tun_live.rss_kb, Some(18432));

    // 3. Proxy mode render -> parse_health_json contract.
    let proxy_meta = HealthRuntimeMeta {
        engine: EngineMode::Proxy,
        ..Default::default()
    };
    let proxy_json = render_health_json(&ctx, &proxy_meta);
    let proxy_status = parse_health_json(&proxy_json, loopback, 8080, Some(1080))
        .expect("rendered Proxy /vdpi-health JSON must parse cleanly");
    assert_eq!(proxy_status.addr, loopback);
    assert_eq!(proxy_status.port, 8080);
    assert_eq!(proxy_status.socks_port, Some(1080));
    assert_eq!(proxy_status.engine, EngineMode::Proxy);
    assert_eq!(proxy_status.tun_interface, None);
    assert_eq!(proxy_status.physical_nic, None);
    assert_eq!(proxy_status.vpn_conflict, None);
    assert_eq!(proxy_status.active_connections, Some(5));
    assert_eq!(proxy_status.total_connections, Some(128));
    assert_eq!(proxy_status.learned_hosts, Some(9));
    assert_eq!(proxy_status.udp_flows_active, Some(14));
    assert_eq!(proxy_status.quic_blocked, Some(1));
    assert!(
        proxy_status.dns_queries >= Some(1),
        "expected dns_queries >= 1, got {:?}",
        proxy_status.dns_queries
    );
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    assert!(
        proxy_status.rss_kb.is_some_and(|kb| kb > 0),
        "expected positive rss_kb on desktop OS, got {:?}",
        proxy_status.rss_kb
    );

    // 4. Windows IP_UNICAST_IF (network byte order) vs IPV6_UNICAST_IF (host byte order).
    assert_eq!(windows_ipv4_unicast_if_value(12), 12u32.to_be());
    assert_eq!(
        windows_ipv4_unicast_if_value(0x0102_0304),
        0x0102_0304u32.to_be()
    );
    assert_eq!(
        windows_ipv4_unicast_if_value(1).to_ne_bytes(),
        1u32.to_be_bytes()
    );
    assert_eq!(windows_ipv6_unicast_if_value(12), 12u32);
    assert_eq!(windows_ipv6_unicast_if_value(0x0102_0304), 0x0102_0304u32);
}
