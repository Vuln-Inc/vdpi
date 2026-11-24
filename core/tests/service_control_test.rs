use clap::Parser;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use vdpi::config::{CliArgs, Command};
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
    assert_eq!(legacy.version.as_deref(), Some("0.4.0"));
    assert_eq!(legacy.mode, None);
    assert_eq!(legacy.doh, None);
    assert_eq!(legacy.block_quic, None);
    assert_eq!(legacy.active_connections, None);
    assert_eq!(legacy.total_connections, None);
    assert_eq!(legacy.learned_hosts, None);
    assert_eq!(legacy.isp_stage, None);

    // Malformed payloads and non-ok statuses must be rejected cleanly.
    let rejected_payloads = [
        "",
        "not json",
        "{unclosed",
        "[]",
        r#"{"status":"error","service":"vdpi","version":"0.4.1"}"#,
        r#"{"status":"degraded","service":"vdpi","version":"0.4.1"}"#,
        r#"{"status":"starting","service":"other"}"#,
        r#"{"version":"0.4.1"}"#,
    ];
    for payload in rejected_payloads {
        assert_eq!(
            parse_health_json(payload, addr, 8080, Some(1080)),
            None,
            "expected None for rejected health payload: {payload:?}"
        );
    }
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
    };
    assert_eq!(not_installed_status.service_state, not_installed);
    assert!(not_installed_status.installed.is_none());
    assert!(not_installed_status.live_engine.is_none());

    let stopped_status = ControlCenterStatus {
        installed: Some(InstalledInfo {
            binary_path: PathBuf::from("/usr/local/bin/vdpi"),
            installed_version: Some("0.4.1".to_string()),
            current_version: "0.4.1",
            relation: VersionRelation::Same,
            running_from_installed: false,
        }),
        service_state: ServiceState::Stopped,
        live_engine: None,
    };
    assert_eq!(stopped_status.service_state, stopped);
    assert!(stopped_status.installed.is_some());
    assert!(stopped_status.live_engine.is_none());
    assert_ne!(stopped_status, not_installed_status);

    let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let live = LiveEngineStatus {
        addr,
        port: 8080,
        socks_port: Some(1080),
        version: Some("0.4.1".to_string()),
        mode: Some("combo".to_string()),
        doh: Some(true),
        block_quic: Some(true),
        active_connections: Some(3),
        total_connections: Some(25),
        learned_hosts: Some(4),
        isp_stage: Some("ComboMultiRecord".to_string()),
    };

    let running_status = ControlCenterStatus {
        installed: stopped_status.installed.clone(),
        service_state: ServiceState::Running,
        live_engine: Some(live.clone()),
    };
    assert_eq!(running_status.service_state, running);
    assert_eq!(running_status.live_engine, Some(live));
    assert_ne!(running_status, stopped_status);

    let cloned = running_status.clone();
    assert_eq!(cloned, running_status);
}
