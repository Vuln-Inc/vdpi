pub mod config;
pub mod doctor;
pub mod events;
#[cfg(target_os = "android")]
pub mod jni_bridge;
pub mod tun_engine;

use crate::config::AndroidConfig;
use crate::doctor::run_doctor;
use crate::events::{EngineEvent, EventRing};
use crate::tun_engine::TunStats;
#[cfg(unix)]
use anyhow::Context;
use anyhow::{anyhow, Result};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use vdpi::desync::EngineContext;

#[derive(Debug, Clone, Serialize)]
pub struct TelemetrySnapshot {
    pub running: bool,
    pub uptime_secs: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub tls_handshakes: u64,
    pub auto_heal_escalations: u64,
    pub dns_queries: u64,
    pub quic_blocked: u64,
    pub udp_flows_active: u64,
    pub learned_hosts: usize,
    pub stage_number: u8,
    pub stage_label: String,
    pub dns_addr: String,
    pub doh_enabled: bool,
    pub events: Vec<EngineEvent>,
}

struct ActiveTunnel {
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    task: JoinHandle<()>,
}

struct TunnelManager {
    runtime: Runtime,
    /// Serializes start/stop lifecycle transitions without blocking telemetry reads.
    lifecycle_lock: Mutex<()>,
    active: Mutex<Option<ActiveTunnel>>,
    events: Arc<EventRing>,
}

static MANAGER: OnceLock<std::result::Result<TunnelManager, String>> = OnceLock::new();

fn manager() -> Result<&'static TunnelManager> {
    let init = MANAGER.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("vdpi-android")
            .enable_all()
            .build()
            .map(|runtime| TunnelManager {
                runtime,
                lifecycle_lock: Mutex::new(()),
                active: Mutex::new(None),
                events: Arc::new(EventRing::new()),
            })
            .map_err(|e| format!("failed to initialize tokio runtime: {e}"))
    });
    match init {
        Ok(mgr) => Ok(mgr),
        Err(msg) => Err(anyhow!("{msg}")),
    }
}

pub fn engine_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn stop_active_locked(mgr: &TunnelManager) {
    let active = mgr.active.lock().ok().and_then(|mut g| g.take());
    if let Some(tunnel) = active {
        let _ = tunnel.shutdown_tx.send(true);
        let mut handle = tunnel.task;
        // Wait boundedly for graceful teardown so `OwnedFd` closes before returning.
        let finished = mgr.runtime.block_on(async {
            tokio::time::timeout(Duration::from_millis(1500), &mut handle)
                .await
                .is_ok()
        });
        if !finished {
            handle.abort();
        }
        mgr.events.push("info", "tunnel", "disconnect completed");
    }
}

/// Starts the Android TUN engine on `owned_fd`, closing any prior session cleanly first.
/// Registers `owned_fd` with Tokio synchronously so invalid fds fail immediately and never leak.
#[cfg(unix)]
pub fn start_tunnel(owned_fd: std::os::unix::io::OwnedFd, cfg: AndroidConfig) -> Result<()> {
    let mgr = manager()?;
    let _lifecycle = mgr
        .lifecycle_lock
        .lock()
        .map_err(|_| anyhow!("tunnel lifecycle lock poisoned"))?;

    stop_active_locked(mgr);

    let mtu = cfg.clamped_mtu();
    let mode_label = format!("{:?}", cfg.mode);
    let dns_label = cfg.dns_addr.clone();
    let doh_enabled = cfg.enable_doh;

    let ctx = EngineContext::new(cfg.into_runtime_config())?;
    let async_fd = {
        let _enter = mgr.runtime.enter();
        tun_engine::register_tun_fd(owned_fd).context("failed to register Android TUN fd")?
    };

    let tun_stats = Arc::new(TunStats::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    mgr.events.push(
        "info",
        "tunnel",
        format!(
            "engine started (mode={mode_label}, dns={dns_label}, doh={doh_enabled}, mtu={mtu})"
        ),
    );

    let task_ctx = ctx.clone();
    let task_stats = Arc::clone(&tun_stats);
    let task_events = Arc::clone(&mgr.events);

    let task = mgr.runtime.spawn(async move {
        if let Err(e) = tun_engine::run_registered_tun_fd(
            async_fd,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            shutdown_rx,
        )
        .await
        {
            task_events.push("error", "tunnel", format!("tunnel exited: {e:#}"));
        } else {
            task_events.push("info", "tunnel", "tunnel stopped cleanly");
        }
    });

    if let Ok(mut guard) = mgr.active.lock() {
        *guard = Some(ActiveTunnel {
            ctx,
            tun_stats,
            started_at: Instant::now(),
            shutdown_tx,
            task,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn start_tunnel(_tun_fd: i32, _cfg: AndroidConfig) -> Result<()> {
    anyhow::bail!("raw TUN fd attachment requires Unix/Android")
}

pub fn stop_tunnel() {
    let Ok(mgr) = manager() else {
        return;
    };
    let Ok(_lifecycle) = mgr.lifecycle_lock.lock() else {
        return;
    };
    stop_active_locked(mgr);
}

pub fn clear_engine_cache() {
    let Ok(mgr) = manager() else {
        return;
    };
    let ctx = mgr
        .active
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|t| t.ctx.clone()));
    if let Some(ctx) = ctx {
        mgr.runtime.block_on(async move {
            ctx.clear_adaptive_cache().await;
            ctx.dns.clear_cache().await;
        });
    }
    mgr.events
        .push("info", "cache", "cleared adaptive TLS and DNS caches");
}

pub fn snapshot_json() -> String {
    let Ok(mgr) = manager() else {
        return r#"{"running":false}"#.to_string();
    };
    let events = mgr.events.snapshot();
    let snapshot = {
        let guard = mgr.active.lock().ok();
        if let Some(Some(tunnel)) = guard.as_deref() {
            let core = tunnel.ctx.telemetry_snapshot();
            let stage = tunnel.ctx.preferred_stage();
            let running = !tunnel.task.is_finished();
            TelemetrySnapshot {
                running,
                uptime_secs: if running {
                    tunnel.started_at.elapsed().as_secs()
                } else {
                    0
                },
                active_connections: core.active_connections,
                total_connections: core.total_connections,
                bytes_tx: core.bytes_tx,
                bytes_rx: core.bytes_rx,
                tls_handshakes: core.tls_handshakes,
                auto_heal_escalations: core.auto_heal_escalations,
                dns_queries: tunnel.ctx.dns.query_count(),
                quic_blocked: tunnel.tun_stats.quic_blocked.load(Ordering::Relaxed),
                udp_flows_active: tunnel.tun_stats.udp_flows_active.load(Ordering::Relaxed),
                learned_hosts: core.learned_hosts,
                stage_number: stage.stage_number(),
                stage_label: stage.label().to_string(),
                dns_addr: tunnel.ctx.config.dns_addr.clone(),
                doh_enabled: tunnel.ctx.config.enable_doh,
                events,
            }
        } else {
            TelemetrySnapshot {
                running: false,
                uptime_secs: 0,
                active_connections: 0,
                total_connections: 0,
                bytes_tx: 0,
                bytes_rx: 0,
                tls_handshakes: 0,
                auto_heal_escalations: 0,
                dns_queries: 0,
                quic_blocked: 0,
                udp_flows_active: 0,
                learned_hosts: 0,
                stage_number: 1,
                stage_label: "ComboMultiRecord".to_string(),
                dns_addr: "1.1.1.1".to_string(),
                doh_enabled: true,
                events,
            }
        }
    };

    serde_json::to_string(&snapshot).unwrap_or_else(|_| "{}".to_string())
}

pub fn run_doctor_json(config_json: &str) -> String {
    let cfg = AndroidConfig::from_json_str(config_json).unwrap_or_default();
    let Ok(mgr) = manager() else {
        return r#"{"ok":false,"checks":[]}"#.to_string();
    };
    mgr.events
        .push("info", "doctor", "running live connectivity diagnostics");
    let report = mgr.runtime.block_on(run_doctor(&cfg));
    let passed = report.checks.iter().filter(|c| c.passed).count();
    mgr.events.push(
        if report.ok { "info" } else { "warn" },
        "doctor",
        format!(
            "diagnostics finished ({passed}/{} passed)",
            report.checks.len()
        ),
    );
    serde_json::to_string(&report).unwrap_or_else(|_| r#"{"ok":false,"checks":[]}"#.to_string())
}
