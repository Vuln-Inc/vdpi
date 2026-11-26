use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use vdpi::config::{CliArgs, Command, ConfigCommand, DesyncMode, EngineMode, RuntimeConfig};
use vdpi::desync::{EngineContext, LearnedStrategy};
use vdpi::health::{serve_health_until_shutdown, HealthMetaFn, HealthRuntimeMeta};
use vdpi::service::{
    parse_health_json, ControlCenterStatus, InstalledInfo, LiveEngineStatus, ServiceState,
};
use vdpi::update::VersionRelation;

#[test]
fn parses_pause_stop_and_resume_subcommands() {
    let pause = CliArgs::try_parse_from(["vdpi", "pause"]).expect("valid pause subcommand");
    assert!(matches!(pause.command, Some(Command::Pause)));

    let stop = CliArgs::try_parse_from(["vdpi", "stop"]).expect("valid stop alias");
    assert!(matches!(stop.command, Some(Command::Pause)));

    let resume = CliArgs::try_parse_from(["vdpi", "resume"]).expect("valid resume subcommand");
    assert!(matches!(resume.command, Some(Command::Resume)));
}

#[test]
fn parses_v050_engine_and_config_subcommands() {
    let engine_show = CliArgs::try_parse_from(["vdpi", "engine"]).expect("valid engine show");
    assert_eq!(engine_show.command, Some(Command::Engine { mode: None }));

    let engine_tun = CliArgs::try_parse_from(["vdpi", "engine", "tun"]).expect("valid engine tun");
    assert_eq!(
        engine_tun.command,
        Some(Command::Engine {
            mode: Some(EngineMode::Tun),
        })
    );

    let engine_proxy =
        CliArgs::try_parse_from(["vdpi", "engine", "proxy"]).expect("valid engine proxy");
    assert_eq!(
        engine_proxy.command,
        Some(Command::Engine {
            mode: Some(EngineMode::Proxy),
        })
    );

    let config_set = CliArgs::try_parse_from(["vdpi", "config", "set", "engine", "tun"])
        .expect("valid config set engine tun");
    assert_eq!(
        config_set.command,
        Some(Command::Config {
            action: Some(ConfigCommand::Set {
                key: "engine".to_string(),
                value: "tun".to_string(),
            }),
        })
    );

    let config_show_json = CliArgs::try_parse_from(["vdpi", "config", "show", "--json"])
        .expect("valid config show --json");
    assert_eq!(
        config_show_json.command,
        Some(Command::Config {
            action: Some(ConfigCommand::Show { json: true }),
        })
    );

    let install_upgrade =
        CliArgs::try_parse_from(["vdpi", "install", "--upgrade"]).expect("valid install --upgrade");
    assert_eq!(
        install_upgrade.command,
        Some(Command::Install { upgrade: true })
    );

    let uninstall_purge =
        CliArgs::try_parse_from(["vdpi", "uninstall", "--purge"]).expect("valid uninstall --purge");
    assert_eq!(
        uninstall_purge.command,
        Some(Command::Uninstall { purge: true })
    );
}

#[test]
fn parse_health_json_extracts_enriched_and_legacy_payloads() {
    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let enriched_body = r#"{
        "status": "ok",
        "service": "vdpi",
        "version": "0.4.1",
        "mode": "combo",
        "doh": true,
        "block_quic": true,
        "active_connections": 7,
        "total_connections": 142,
        "learned_hosts": 19,
        "isp_stage": "MultiRecordOob"
    }"#;

    let enriched = parse_health_json(enriched_body, addr, 8080, Some(1080))
        .expect("enriched /vdpi-health payload should parse");
    assert_eq!(enriched.addr, addr);
    assert_eq!(enriched.port, 8080);
    assert_eq!(enriched.socks_port, Some(1080));
    assert_eq!(enriched.version.as_deref(), Some("0.4.1"));
    assert_eq!(enriched.mode.as_deref(), Some("combo"));
    assert_eq!(enriched.doh, Some(true));
    assert_eq!(enriched.block_quic, Some(true));
    assert_eq!(enriched.active_connections, Some(7));
    assert_eq!(enriched.total_connections, Some(142));
    assert_eq!(enriched.learned_hosts, Some(19));
    assert_eq!(enriched.isp_stage.as_deref(), Some("MultiRecordOob"));

    let legacy_body = r#"{"status":"ok","service":"vdpi","version":"0.4.0"}"#;
    let legacy = parse_health_json(legacy_body, addr, 8080, None)
        .expect("minimal legacy /vdpi-health payload should parse");
    assert_eq!(legacy.addr, addr);
    assert_eq!(legacy.port, 8080);
    assert_eq!(legacy.socks_port, None);
    assert_eq!(legacy.engine, EngineMode::Proxy);
    assert_eq!(legacy.tun_interface, None);
    assert_eq!(legacy.physical_nic, None);
    assert_eq!(legacy.vpn_conflict, None);
    assert_eq!(legacy.version.as_deref(), Some("0.4.0"));
    assert_eq!(legacy.mode, None);
    assert_eq!(legacy.doh, None);
    assert_eq!(legacy.block_quic, None);
    assert_eq!(legacy.active_connections, None);
    assert_eq!(legacy.total_connections, None);
    assert_eq!(legacy.learned_hosts, None);
    assert_eq!(legacy.isp_stage, None);
    assert_eq!(legacy.udp_flows_active, None);
    assert_eq!(legacy.quic_blocked, None);
    assert_eq!(legacy.dns_queries, None);
    assert_eq!(legacy.rss_kb, None);

    // Malformed payloads, non-ok statuses, and foreign services must be rejected cleanly.
    let rejected_payloads = [
        "",
        "not json",
        "{unclosed",
        "[]",
        r#"{"status":"error","service":"vdpi","version":"0.4.1"}"#,
        r#"{"status":"degraded","service":"vdpi","version":"0.4.1"}"#,
        r#"{"status":"starting","service":"other"}"#,
        r#"{"status":"ok","service":"other-app"}"#,
        r#"{"version":"0.4.1"}"#,
    ];
    for payload in rejected_payloads {
        assert_eq!(
            parse_health_json(payload, addr, 8080, Some(1080)),
            None,
            "expected None for rejected health payload: {payload:?}"
        );
    }

    // Malformed optional fields must degrade to None while keeping a valid vdpi status.
    let degraded_body = r#"{
        "status": "ok",
        "service": "vdpi",
        "version": "0.4.2",
        "engine": 999,
        "tun_interface": "",
        "physical_nic": "   ",
        "vpn_conflict": false,
        "mode": 123,
        "doh": "true",
        "block_quic": 1,
        "active_connections": -1,
        "total_connections": "many",
        "learned_hosts": -5,
        "isp_stage": false,
        "udp_flows_active": -2,
        "quic_blocked": "none",
        "dns_queries": -1,
        "rss_kb": "16MB"
    }"#;
    let degraded = parse_health_json(degraded_body, addr, 8080, Some(1080))
        .expect("valid vdpi status with malformed optional fields should gracefully degrade");
    assert_eq!(degraded.addr, addr);
    assert_eq!(degraded.port, 8080);
    assert_eq!(degraded.socks_port, Some(1080));
    assert_eq!(degraded.engine, EngineMode::Proxy);
    assert_eq!(degraded.tun_interface, None);
    assert_eq!(degraded.physical_nic, None);
    assert_eq!(degraded.vpn_conflict, None);
    assert_eq!(degraded.version.as_deref(), Some("0.4.2"));
    assert_eq!(degraded.mode, None);
    assert_eq!(degraded.doh, None);
    assert_eq!(degraded.block_quic, None);
    assert_eq!(degraded.active_connections, None);
    assert_eq!(degraded.total_connections, None);
    assert_eq!(degraded.learned_hosts, None);
    assert_eq!(degraded.isp_stage, None);
    assert_eq!(degraded.udp_flows_active, None);
    assert_eq!(degraded.quic_blocked, None);
    assert_eq!(degraded.dns_queries, None);
    assert_eq!(degraded.rss_kb, None);
}

#[test]
fn control_center_status_struct_sanity() {
    let running = ServiceState::Running;
    let stopped = ServiceState::Stopped;
    let not_installed = ServiceState::NotInstalled;

    assert_ne!(running, stopped);
    assert_ne!(running, not_installed);
    assert_ne!(stopped, not_installed);

    let not_installed_status = ControlCenterStatus {
        installed: None,
        service_state: ServiceState::NotInstalled,
        live_engine: None,
        configured_engine: EngineMode::Proxy,
        vpn_conflict: None,
    };
    assert_eq!(not_installed_status.service_state, not_installed);
    assert!(not_installed_status.installed.is_none());
    assert!(not_installed_status.live_engine.is_none());
    assert_eq!(not_installed_status.configured_engine, EngineMode::Proxy);
    assert_eq!(not_installed_status.vpn_conflict, None);

    let stopped_status = ControlCenterStatus {
        installed: Some(InstalledInfo {
            binary_path: PathBuf::from("/usr/local/bin/vdpi"),
            installed_version: Some("0.5.0".to_string()),
            current_version: "0.5.0",
            relation: VersionRelation::Same,
            running_from_installed: false,
        }),
        service_state: ServiceState::Stopped,
        live_engine: None,
        configured_engine: EngineMode::Tun,
        vpn_conflict: None,
    };
    assert_eq!(stopped_status.service_state, stopped);
    assert!(stopped_status.installed.is_some());
    assert!(stopped_status.live_engine.is_none());
    assert_eq!(stopped_status.configured_engine, EngineMode::Tun);
    assert_ne!(stopped_status, not_installed_status);

    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let live = LiveEngineStatus {
        addr,
        port: 18089,
        socks_port: None,
        engine: EngineMode::Tun,
        tun_interface: Some("vdpi0".to_string()),
        physical_nic: Some("Ethernet".to_string()),
        vpn_conflict: Some("Mullvad (yielded)".to_string()),
        version: Some("0.5.0".to_string()),
        mode: Some("combo".to_string()),
        doh: Some(true),
        block_quic: Some(true),
        active_connections: Some(3),
        total_connections: Some(25),
        learned_hosts: Some(4),
        isp_stage: Some("ComboMultiRecord".to_string()),
        udp_flows_active: Some(2),
        quic_blocked: Some(5),
        dns_queries: Some(19),
        rss_kb: Some(18432),
        bytes_rx: Some(4096),
        bytes_tx: Some(2048),
        tls_handshakes: Some(7),
        auto_heal_escalations: Some(1),
    };

    let running_status = ControlCenterStatus {
        installed: stopped_status.installed.clone(),
        service_state: ServiceState::Running,
        live_engine: Some(live.clone()),
        configured_engine: EngineMode::Tun,
        vpn_conflict: Some("Mullvad (yielded)".to_string()),
    };
    assert_eq!(running_status.service_state, running);
    assert_eq!(running_status.live_engine, Some(live));
    assert_eq!(running_status.configured_engine, EngineMode::Tun);
    assert_eq!(
        running_status.vpn_conflict.as_deref(),
        Some("Mullvad (yielded)")
    );
    assert_ne!(running_status, stopped_status);

    let cloned = running_status.clone();
    assert_eq!(cloned, running_status);
}

#[tokio::test]
async fn live_http_vdpi_health_endpoint_roundtrips_through_parse_health_json() {
    let cfg = RuntimeConfig {
        engine: EngineMode::Tun,
        mode: DesyncMode::Combo,
        enable_doh: true,
        block_quic: true,
        ..Default::default()
    };
    let ctx = EngineContext::new(cfg).expect("create test engine context");
    ctx.telemetry.active_connections.store(4, Ordering::Relaxed);
    ctx.telemetry.total_connections.store(89, Ordering::Relaxed);
    ctx.telemetry.learned_hosts.store(6, Ordering::Relaxed);
    ctx.preferred_isp_stage
        .store(LearnedStrategy::OobSniDesync as u8, Ordering::Relaxed);
    ctx.set_udp_flows_active(11);
    ctx.inc_quic_blocked();
    let resolved = ctx
        .dns
        .resolve("localhost")
        .await
        .expect("localhost resolution should succeed");
    assert!(!resolved.is_empty());

    let std_listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral loopback health port");
    let health_addr = std_listener
        .local_addr()
        .expect("read bound health listener address");

    let meta_fn: HealthMetaFn = Arc::new(|| HealthRuntimeMeta {
        engine: EngineMode::Tun,
        tun_interface: Some("vdpi0".to_string()),
        physical_nic: Some("Ethernet".to_string()),
        vpn_conflict: Some("Mullvad (yielded)".to_string()),
    });

    let (stop_tx, stop_rx) = watch::channel(false);
    let server_task = tokio::spawn(serve_health_until_shutdown(
        std_listener,
        ctx,
        meta_fn,
        stop_rx,
    ));

    let timeout = Duration::from_secs(5);
    let mut client = tokio::time::timeout(timeout, TcpStream::connect(health_addr))
        .await
        .expect("timed out connecting to /vdpi-health")
        .expect("connect to /vdpi-health");
    tokio::time::timeout(
        timeout,
        client.write_all(
            b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        ),
    )
    .await
    .expect("timed out writing /vdpi-health request")
    .expect("write /vdpi-health request");

    let mut raw_resp = Vec::new();
    tokio::time::timeout(timeout, client.read_to_end(&mut raw_resp))
        .await
        .expect("timed out reading /vdpi-health response")
        .expect("read /vdpi-health response");

    let _ = stop_tx.send(true);
    tokio::time::timeout(timeout, server_task)
        .await
        .expect("timed out stopping health server")
        .expect("health server task panicked");

    let resp_text = String::from_utf8(raw_resp).expect("valid UTF-8 HTTP response");
    let (headers, body) = resp_text
        .split_once("\r\n\r\n")
        .expect("HTTP response should contain header/body separator");
    assert!(
        headers.starts_with("HTTP/1.1 200 OK"),
        "expected HTTP 200 OK, got headers: {headers}"
    );

    let parsed = parse_health_json(body, health_addr.ip(), health_addr.port(), None)
        .expect("live /vdpi-health JSON body must parse cleanly");
    assert_eq!(parsed.addr, health_addr.ip());
    assert_eq!(parsed.port, health_addr.port());
    assert_eq!(parsed.socks_port, None);
    assert_eq!(parsed.engine, EngineMode::Tun);
    assert_eq!(parsed.tun_interface.as_deref(), Some("vdpi0"));
    assert_eq!(parsed.physical_nic.as_deref(), Some("Ethernet"));
    assert_eq!(parsed.vpn_conflict.as_deref(), Some("Mullvad (yielded)"));
    assert_eq!(parsed.version.as_deref(), Some(env!("CARGO_PKG_VERSION")));
    assert_eq!(parsed.mode.as_deref(), Some("combo"));
    assert_eq!(parsed.doh, Some(true));
    assert_eq!(parsed.block_quic, Some(true));
    assert_eq!(parsed.active_connections, Some(4));
    assert_eq!(parsed.total_connections, Some(89));
    assert_eq!(parsed.learned_hosts, Some(6));
    assert_eq!(parsed.isp_stage.as_deref(), Some("OobSniDesync"));
    assert_eq!(parsed.udp_flows_active, Some(11));
    assert_eq!(parsed.quic_blocked, Some(1));
    assert!(
        parsed.dns_queries >= Some(1),
        "expected dns_queries >= 1, got {:?}",
        parsed.dns_queries
    );
}
