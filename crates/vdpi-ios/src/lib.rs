pub mod ffi;

pub use vdpi_tun::config::TunnelConfig as IosConfig;
pub use vdpi_tun::TelemetrySnapshot;

use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use vdpi::desync::EngineContext;
use vdpi_tun::config::TunProfile;
use vdpi_tun::doctor::run_doctor;
use vdpi_tun::events::EventRing;
use vdpi_tun::pipeline::{run_tun_pipeline, TunStats};

/// C callback signature invoked when the Rust TUN engine produces an outbound IP packet.
pub type WritePacketFn =
    unsafe extern "C" fn(data: *const u8, len: usize, family: u8, user_ctx: *mut c_void);

#[derive(Clone, Copy)]
pub struct PacketCallback {
    pub func: WritePacketFn,
    pub user_ctx: *mut c_void,
}

// SAFETY: The caller (`PacketTunnelProvider`) guarantees `func` and `user_ctx` are thread-safe
// until `stop_tunnel()` returns, and `stop_tunnel()` joins/aborts the writer task before returning.
unsafe impl Send for PacketCallback {}
unsafe impl Sync for PacketCallback {}

impl PacketCallback {
    unsafe fn invoke(&self, pkt: &[u8], family: u8) {
        (self.func)(pkt.as_ptr(), pkt.len(), family, self.user_ctx);
    }
}

struct ActiveIosTunnel {
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    pipeline_task: JoinHandle<()>,
    writer_task: JoinHandle<()>,
}

struct IosTunnelManager {
    runtime: Runtime,
    /// Serializes start/stop transitions without blocking packet pushes or telemetry reads.
    lifecycle_lock: Mutex<()>,
    inbound_tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    active: Mutex<Option<ActiveIosTunnel>>,
    events: Arc<EventRing>,
}

static MANAGER: OnceLock<std::result::Result<IosTunnelManager, String>> = OnceLock::new();

#[cfg(unix)]
fn ignore_sigpipe_once() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    });
}

fn manager() -> Result<&'static IosTunnelManager> {
    #[cfg(unix)]
    ignore_sigpipe_once();

    let init = MANAGER.get_or_init(|| {
        // 2 worker threads keep memory overhead minimal inside iOS's 50 MB Jetsam ceiling.
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vdpi-ios")
            .enable_all()
            .build()
            .map(|runtime| IosTunnelManager {
                runtime,
                lifecycle_lock: Mutex::new(()),
                inbound_tx: Mutex::new(None),
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

async fn join_or_abort(mut handle: JoinHandle<()>, budget: Duration) {
    if tokio::time::timeout(budget, &mut handle).await.is_err() {
        handle.abort();
        let _ = handle.await;
    }
}

fn stop_active_locked(mgr: &IosTunnelManager) {
    // Drop the inbound sender immediately so no further packets enter the pipeline.
    *mgr.inbound_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;

    let active = mgr
        .active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    if let Some(tunnel) = active {
        let _ = tunnel.shutdown_tx.send(true);
        let pipeline_task = tunnel.pipeline_task;
        let writer_task = tunnel.writer_task;

        // Await both tasks concurrently with bounded timeout and abort-on-timeout without
        // ever double-polling a completed JoinHandle.
        mgr.runtime.block_on(async {
            tokio::join!(
                join_or_abort(pipeline_task, Duration::from_millis(1200)),
                join_or_abort(writer_task, Duration::from_millis(1200)),
            );
        });

        mgr.events.push("info", "tunnel", "disconnect completed");
    }
}

/// Starts the iOS userspace TUN engine using `TunProfile::LOW_MEMORY`.
pub fn start_tunnel(cfg: IosConfig, callback: PacketCallback) -> Result<()> {
    let mgr = manager()?;
    let _lifecycle = mgr
        .lifecycle_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    // Validate configuration and build EngineContext BEFORE stopping any active tunnel
    // so invalid config never tears down a healthy session.
    let profile = TunProfile::LOW_MEMORY;
    let mtu = cfg.clamped_mtu();
    let mode_label = format!("{:?}", cfg.mode);
    let dns_label = cfg.dns_addr.clone();
    let doh_enabled = cfg.enable_doh;
    let ctx = EngineContext::new(cfg.into_runtime_config())?;

    stop_active_locked(mgr);
    let tun_stats = Arc::new(TunStats::default());
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    mgr.events.push(
        "info",
        "tunnel",
        format!(
            "iOS engine started (mode={mode_label}, dns={dns_label}, doh={doh_enabled}, mtu={mtu}, profile=low-memory)"
        ),
    );

    let mut writer_stop = shutdown_rx.clone();
    let writer_task = mgr.runtime.spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = writer_stop.wait_for(|s| *s) => break,
                maybe_pkt = outbound_rx.recv() => {
                    let Some(pkt) = maybe_pkt else { break; };
                    if pkt.is_empty() {
                        continue;
                    }
                    let family = pkt[0] >> 4;
                    if family != 4 && family != 6 {
                        continue;
                    }
                    // SAFETY: `callback` remains valid until `stop_active_locked` joins this task.
                    unsafe {
                        callback.invoke(&pkt, family);
                    }
                }
            }
        }
    });

    let task_ctx = ctx.clone();
    let task_stats = Arc::clone(&tun_stats);
    let task_events = Arc::clone(&mgr.events);
    let pipeline_task = mgr.runtime.spawn(async move {
        if let Err(e) = run_tun_pipeline(
            inbound_rx,
            outbound_tx,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            profile,
            shutdown_rx,
        )
        .await
        {
            task_events.push("error", "tunnel", format!("tunnel exited: {e:#}"));
        } else {
            task_events.push("info", "tunnel", "tunnel stopped cleanly");
        }
    });

    *mgr.inbound_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(inbound_tx);
    *mgr.active.lock().unwrap_or_else(|e| e.into_inner()) = Some(ActiveIosTunnel {
        ctx,
        tun_stats,
        started_at: Instant::now(),
        shutdown_tx,
        pipeline_task,
        writer_task,
    });

    Ok(())
}

/// Non-blocking packet injection called from `NEPacketTunnelFlow.readPackets`.
pub fn push_packet(packet: &[u8]) -> bool {
    if !(20..=65535).contains(&packet.len()) {
        return false;
    }
    let Ok(mgr) = manager() else {
        return false;
    };
    let sender = mgr
        .inbound_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned();
    let Some(tx) = sender else {
        return false;
    };
    tx.try_send(packet.to_vec()).is_ok()
}

pub fn stop_tunnel() {
    let Ok(mgr) = manager() else {
        return;
    };
    let _lifecycle = mgr
        .lifecycle_lock
        .lock()
        .unwrap_or_else(|e| e.into_inner());
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
            let running = !tunnel.pipeline_task.is_finished() && !tunnel.writer_task.is_finished();
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
    let cfg = IosConfig::from_json_str(config_json).unwrap_or_default();
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
