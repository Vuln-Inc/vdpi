#[cfg(target_os = "android")]
pub mod jni_bridge;

pub use vdpi_tun::config::TunnelConfig as AndroidConfig;
pub use vdpi_tun::TelemetrySnapshot;

#[cfg(unix)]
use anyhow::Context;
use anyhow::{anyhow, Result};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use vdpi::desync::EngineContext;
#[cfg(unix)]
use vdpi_tun::config::TunProfile;
use vdpi_tun::doctor::run_doctor;
use vdpi_tun::events::EventRing;
use vdpi_tun::pipeline::TunStats;

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
            let _ = mgr.runtime.block_on(tokio::time::timeout(
                Duration::from_millis(500),
                vdpi_tun::flush_engine_cache(&tunnel.ctx),
            ));
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

    let ctx = mgr.runtime.block_on(vdpi_tun::build_engine_context(cfg))?;
    let async_fd = {
        let _enter = mgr.runtime.enter();
        vdpi_tun::fd::register_tun_fd(owned_fd).context("failed to register Android TUN fd")?
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
        if let Err(e) = vdpi_tun::fd::run_registered_tun_fd(
            async_fd,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            TunProfile::STANDARD,
            shutdown_rx,
        )
        .await
        {
            task_events.push("error", "tunnel", format!("tunnel exited: {e:#}"));
        } else {
            task_events.push("info", "tunnel", "tunnel stopped cleanly");
        }
    });

    let mut guard = mgr.active.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(ActiveTunnel {
        ctx,
        tun_stats,
        started_at: Instant::now(),
        shutdown_tx,
        task,
    });
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
    let _lifecycle = mgr.lifecycle_lock.lock().unwrap_or_else(|e| e.into_inner());
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
            let running = !tunnel.task.is_finished();
            TelemetrySnapshot::from_live(
                &tunnel.ctx,
                &tunnel.tun_stats,
                tunnel.started_at,
                running,
                events,
            )
        } else {
            TelemetrySnapshot::idle(events)
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
