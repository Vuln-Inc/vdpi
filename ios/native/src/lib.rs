pub mod ffi;

pub use vdpi_tun::config::TunnelConfig as IosConfig;
pub use vdpi_tun::TelemetrySnapshot;

#[cfg(unix)]
use anyhow::Context;
use anyhow::{anyhow, Result};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use vdpi_core::desync::EngineContext;
use vdpi_tun::config::TunProfile;
use vdpi_tun::doctor::run_doctor;
use vdpi_tun::events::EventRing;
use vdpi_tun::pipeline::{run_tun_pipeline_with_route_watch, TunStats};

/// Hard iOS TUN MTU cap matching `TunnelNetworkSettingsBuilder` (4064 bytes).
const IOS_MAX_MTU: usize = 4064;
/// Minimum channel depth for the `NEPacketTunnelFlow` bridge so bursty batches never drop TCP ACKs.
const PACKET_FLOW_MIN_CHANNEL_CAP: usize = 512;
/// Maximum packets drained per single batched outbound callback invocation.
const OUTBOUND_BATCH_MAX: usize = 64;
/// Stack size for the dedicated OS packet writer thread (`vdpi-ios-tx`).
const WRITER_THREAD_STACK_BYTES: usize = 512 * 1024;

/// C callback signature invoked when the Rust TUN engine produces a single outbound IP packet.
pub type WritePacketFn =
    unsafe extern "C" fn(data: *const u8, len: usize, family: u8, user_ctx: *mut c_void);

/// C-ABI descriptor for a single IP packet inside an outbound batch callback.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VdpiPacketSlice {
    pub data: *const u8,
    pub len: usize,
    pub family: u8,
}

/// C callback signature invoked on a dedicated OS writer thread with a batch of outbound IP packets.
pub type WritePacketsBatchFn =
    unsafe extern "C" fn(packets: *const VdpiPacketSlice, count: usize, user_ctx: *mut c_void);

#[derive(Clone, Copy)]
pub struct PacketCallback {
    pub func: WritePacketFn,
    pub user_ctx: *mut c_void,
}

// SAFETY: The caller (`PacketTunnelProvider`) guarantees `func` and `user_ctx` are thread-safe
// until `stop_tunnel()` returns, and `stop_tunnel()` joins the writer thread before returning.
unsafe impl Send for PacketCallback {}
unsafe impl Sync for PacketCallback {}

impl PacketCallback {
    unsafe fn invoke(&self, pkt: &[u8], family: u8) {
        (self.func)(pkt.as_ptr(), pkt.len(), family, self.user_ctx);
    }
}

#[derive(Clone, Copy)]
pub struct BatchedPacketCallback {
    pub func: WritePacketsBatchFn,
    pub user_ctx: *mut c_void,
}

// SAFETY: The caller (`PacketTunnelProvider`) guarantees `func` and `user_ctx` are thread-safe
// until `stop_tunnel()` returns, and `stop_tunnel()` joins the writer thread before returning.
unsafe impl Send for BatchedPacketCallback {}
unsafe impl Sync for BatchedPacketCallback {}

impl BatchedPacketCallback {
    unsafe fn invoke(&self, slices: &[VdpiPacketSlice]) {
        if !slices.is_empty() {
            (self.func)(slices.as_ptr(), slices.len(), self.user_ctx);
        }
    }
}

#[derive(Clone, Copy)]
enum PacketWriterCallback {
    Single(PacketCallback),
    Batched(BatchedPacketCallback),
}

struct PacketFlowWriter {
    stop_flag: Arc<AtomicBool>,
    wake_tx: mpsc::WeakSender<Vec<u8>>,
    handle: std::thread::JoinHandle<()>,
}

struct ActiveIosTunnel {
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    route_tx: watch::Sender<u64>,
    pipeline_task: JoinHandle<()>,
    writer: Option<PacketFlowWriter>,
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
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn manager() -> Result<&'static IosTunnelManager> {
    let init = MANAGER.get_or_init(|| {
        #[cfg(unix)]
        ignore_sigpipe_once();

        // 3 worker threads, capped blocking pool, and 1 MiB worker stacks keep VM/RSS
        // bounded inside iOS's 50 MB Jetsam ceiling while preventing stack overflow.
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(3)
            .max_blocking_threads(12)
            .thread_stack_size(1024 * 1024)
            .thread_keep_alive(Duration::from_secs(5))
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

fn valid_ip_family(pkt: &[u8]) -> Option<u8> {
    let family = *pkt.first()? >> 4;
    if family == 4 || family == 6 {
        Some(family)
    } else {
        None
    }
}

fn spawn_packet_writer_thread(
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    callback: PacketWriterCallback,
) -> Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("vdpi-ios-tx".into())
        .stack_size(WRITER_THREAD_STACK_BYTES)
        .spawn(move || match callback {
            PacketWriterCallback::Single(cb) => {
                while !stop_flag.load(Ordering::Acquire) {
                    let Some(pkt) = outbound_rx.blocking_recv() else {
                        break;
                    };
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let Some(family) = valid_ip_family(&pkt) else {
                        continue;
                    };
                    // SAFETY: `cb` remains valid until `stop_active_locked` joins this thread.
                    unsafe {
                        cb.invoke(&pkt, family);
                    }
                }
            }
            PacketWriterCallback::Batched(cb) => {
                let mut batch_bufs: Vec<Vec<u8>> = Vec::with_capacity(OUTBOUND_BATCH_MAX);
                let mut batch_slices: Vec<VdpiPacketSlice> = Vec::with_capacity(OUTBOUND_BATCH_MAX);
                while !stop_flag.load(Ordering::Acquire) {
                    let Some(first) = outbound_rx.blocking_recv() else {
                        break;
                    };
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    batch_bufs.clear();
                    batch_slices.clear();

                    if valid_ip_family(&first).is_some() {
                        batch_bufs.push(first);
                    }

                    // Drain up to 64 ready packets per single Obj-C `writePackets` batch call.
                    while batch_bufs.len() < OUTBOUND_BATCH_MAX {
                        if stop_flag.load(Ordering::Acquire) {
                            break;
                        }
                        match outbound_rx.try_recv() {
                            Ok(pkt) => {
                                if valid_ip_family(&pkt).is_some() {
                                    batch_bufs.push(pkt);
                                }
                            }
                            Err(
                                mpsc::error::TryRecvError::Empty
                                | mpsc::error::TryRecvError::Disconnected,
                            ) => break,
                        }
                    }

                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    if batch_bufs.is_empty() {
                        continue;
                    }

                    for pkt in &batch_bufs {
                        batch_slices.push(VdpiPacketSlice {
                            data: pkt.as_ptr(),
                            len: pkt.len(),
                            family: pkt[0] >> 4,
                        });
                    }

                    // SAFETY: Every `VdpiPacketSlice::data` points into `batch_bufs`, which stays
                    // immutable and alive during `cb.invoke`, and `cb` remains valid until
                    // `stop_active_locked` joins this thread.
                    unsafe {
                        cb.invoke(&batch_slices);
                    }
                }
            }
        })
        .map_err(|e| anyhow!("failed to spawn iOS outbound writer thread: {e}"))
}

async fn join_or_abort(mut handle: JoinHandle<()>, budget: Duration) -> bool {
    if tokio::time::timeout(budget, &mut handle).await.is_err() {
        handle.abort();
        // Bound post-abort await so `stop_tunnel` can never hang holding `lifecycle_lock`.
        let _ = tokio::time::timeout(Duration::from_millis(500), &mut handle).await;
        return false;
    }
    true
}

fn stop_active_locked(mgr: &IosTunnelManager) {
    // Drop the inbound sender immediately so no further packets enter the pipeline.
    *mgr.inbound_tx.lock().unwrap_or_else(|e| e.into_inner()) = None;

    let active = mgr.active.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(tunnel) = active {
        if let Some(writer) = &tunnel.writer {
            writer.stop_flag.store(true, Ordering::Release);
            if let Some(tx) = writer.wake_tx.upgrade() {
                let _ = tx.try_send(Vec::new());
            }
        }
        let _ = tunnel.shutdown_tx.send(true);

        let pipeline_finished = mgr.runtime.block_on(join_or_abort(
            tunnel.pipeline_task,
            Duration::from_millis(1200),
        ));

        if let Some(writer) = tunnel.writer {
            // Re-wake in case the outbound channel was full before pipeline teardown drained it.
            if let Some(tx) = writer.wake_tx.upgrade() {
                let _ = tx.try_send(Vec::new());
            }
            let _ = writer.handle.join();
        }

        if !pipeline_finished {
            let _ = mgr.runtime.block_on(tokio::time::timeout(
                Duration::from_millis(500),
                vdpi_tun::flush_engine_cache(&tunnel.ctx),
            ));
        }

        mgr.events.push("info", "tunnel", "disconnect completed");
    }
}

fn start_packet_flow_tunnel(cfg: IosConfig, callback: PacketWriterCallback) -> Result<()> {
    let mgr = manager()?;
    let _lifecycle = mgr.lifecycle_lock.lock().unwrap_or_else(|e| e.into_inner());

    // Validate configuration and build EngineContext BEFORE stopping any active tunnel
    // so invalid config never tears down a healthy session.
    let profile = TunProfile::LOW_MEMORY;
    let mtu = cfg.clamped_mtu().min(IOS_MAX_MTU);
    let mode_label = format!("{:?}", cfg.mode);
    let dns_label = cfg.dns_addr.clone();
    let doh_enabled = cfg.enable_doh;
    let ctx = mgr.runtime.block_on(vdpi_tun::build_engine_context(cfg))?;

    stop_active_locked(mgr);

    let tun_stats = Arc::new(TunStats::default());
    let chan_cap = profile.channel_capacity.max(PACKET_FLOW_MIN_CHANNEL_CAP);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(chan_cap);
    let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(chan_cap);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (route_tx, route_rx) = watch::channel(0u64);

    let writer_stop = Arc::new(AtomicBool::new(false));
    let wake_tx = outbound_tx.downgrade();
    let writer_handle =
        spawn_packet_writer_thread(outbound_rx, Arc::clone(&writer_stop), callback)?;

    let path_label = match callback {
        PacketWriterCallback::Single(_) => "packetflow-legacy",
        PacketWriterCallback::Batched(_) => "packetflow-batched",
    };
    mgr.events.push(
        "info",
        "tunnel",
        format!(
            "iOS engine started (path={path_label}, mode={mode_label}, dns={dns_label}, doh={doh_enabled}, mtu={mtu}, profile=low-memory)"
        ),
    );

    let task_ctx = ctx.clone();
    let task_stats = Arc::clone(&tun_stats);
    let task_events = Arc::clone(&mgr.events);
    let pipeline_task = mgr.runtime.spawn(async move {
        if let Err(e) = run_tun_pipeline_with_route_watch(
            inbound_rx,
            outbound_tx,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            profile,
            shutdown_rx,
            Some(route_rx),
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
        route_tx,
        pipeline_task,
        writer: Some(PacketFlowWriter {
            stop_flag: writer_stop,
            wake_tx,
            handle: writer_handle,
        }),
    });

    Ok(())
}

/// Starts the iOS userspace TUN engine using `TunProfile::LOW_MEMORY` with single-packet callbacks
/// on a dedicated OS writer thread (`vdpi-ios-tx`).
pub fn start_tunnel(cfg: IosConfig, callback: PacketCallback) -> Result<()> {
    start_packet_flow_tunnel(cfg, PacketWriterCallback::Single(callback))
}

/// Starts the iOS userspace TUN engine using `TunProfile::LOW_MEMORY` with batched outbound
/// delivery (up to 64 packets per callback) on a dedicated OS writer thread (`vdpi-ios-tx`).
pub fn start_tunnel_batched(cfg: IosConfig, callback: BatchedPacketCallback) -> Result<()> {
    start_packet_flow_tunnel(cfg, PacketWriterCallback::Batched(callback))
}

/// Primary high-speed path: takes ownership of a `dup()`'d `utun` file descriptor, sets
/// `O_NONBLOCK`, registers `AsyncFd<OwnedFd>`, and runs the TUN pipeline directly without
/// Swift `[Data]` bridging overhead.
#[cfg(unix)]
pub fn start_tunnel_fd(owned_fd: std::os::unix::io::OwnedFd, cfg: IosConfig) -> Result<()> {
    let mgr = manager()?;
    let _lifecycle = mgr.lifecycle_lock.lock().unwrap_or_else(|e| e.into_inner());

    // Validate configuration and build EngineContext BEFORE stopping any active tunnel
    // so invalid config never tears down a healthy session.
    let profile = TunProfile::LOW_MEMORY;
    let mtu = cfg.clamped_mtu().min(IOS_MAX_MTU);
    let mode_label = format!("{:?}", cfg.mode);
    let dns_label = cfg.dns_addr.clone();
    let doh_enabled = cfg.enable_doh;
    let ctx = mgr.runtime.block_on(vdpi_tun::build_engine_context(cfg))?;

    // Set O_NONBLOCK and register with Tokio before tearing down an existing healthy tunnel.
    let async_fd = {
        let _enter = mgr.runtime.enter();
        vdpi_tun::fd::register_tun_fd(owned_fd).context("failed to register iOS utun fd")?
    };

    stop_active_locked(mgr);

    let tun_stats = Arc::new(TunStats::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (route_tx, route_rx) = watch::channel(0u64);

    mgr.events.push(
        "info",
        "tunnel",
        format!(
            "iOS engine started (path=utun-fd, mode={mode_label}, dns={dns_label}, doh={doh_enabled}, mtu={mtu}, profile=low-memory)"
        ),
    );

    let task_ctx = ctx.clone();
    let task_stats = Arc::clone(&tun_stats);
    let task_events = Arc::clone(&mgr.events);
    let pipeline_task = mgr.runtime.spawn(async move {
        if let Err(e) = vdpi_tun::fd::run_registered_tun_fd_with_route_watch(
            async_fd,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            profile,
            shutdown_rx,
            Some(route_rx),
        )
        .await
        {
            task_events.push("error", "tunnel", format!("tunnel exited: {e:#}"));
        } else {
            task_events.push("info", "tunnel", "tunnel stopped cleanly");
        }
    });

    *mgr.active.lock().unwrap_or_else(|e| e.into_inner()) = Some(ActiveIosTunnel {
        ctx,
        tun_stats,
        started_at: Instant::now(),
        shutdown_tx,
        route_tx,
        pipeline_task,
        writer: None,
    });

    Ok(())
}

#[cfg(not(unix))]
pub fn start_tunnel_fd(_tun_fd: i32, _cfg: IosConfig) -> Result<()> {
    anyhow::bail!("direct utun fd attachment requires Unix/iOS")
}

/// Non-blocking single-packet injection called from `NEPacketTunnelFlow.readPackets`.
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
    let Ok(permit) = tx.try_reserve() else {
        return false;
    };
    permit.send(packet.to_vec());
    true
}

/// Non-blocking batched packet injection locking `inbound_tx` once per `readPackets` batch.
/// Returns the number of packets accepted into the inbound channel (`< total` signals backpressure).
pub fn push_packets<'a, I>(packets: I) -> usize
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let Ok(mgr) = manager() else {
        return 0;
    };
    let sender = mgr
        .inbound_tx
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .cloned();
    let Some(tx) = sender else {
        return 0;
    };
    let mut accepted = 0usize;
    for packet in packets {
        if !(20..=65535).contains(&packet.len()) {
            continue;
        }
        match tx.try_reserve() {
            Ok(permit) => {
                permit.send(packet.to_vec());
                accepted += 1;
            }
            Err(_) => break,
        }
    }
    accepted
}

/// Signals an uplink or route change (Wi-Fi <-> Cellular handoff or wake) to immediately
/// drain and rebind stale UDP Cone-NAT sockets and clear stale DNS caches without wiping
/// learned adaptive TLS strategies.
pub fn notify_route_change() {
    let Ok(mgr) = manager() else {
        return;
    };
    let target = mgr
        .active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|t| (t.ctx.clone(), t.route_tx.clone()));
    if let Some((ctx, route_tx)) = target {
        let mut generation = 0u64;
        route_tx.send_modify(|g| {
            *g = g.wrapping_add(1);
            generation = *g;
        });
        mgr.runtime.block_on(async move {
            ctx.dns.clear_cache().await;
        });
        mgr.events.push(
            "info",
            "tunnel",
            format!(
                "route change notified (gen={generation}): rebinding UDP flows and cleared DNS cache"
            ),
        );
    }
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
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|t| t.ctx.clone());
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
        let guard = mgr.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(tunnel) = guard.as_ref() {
            let writer_running = tunnel
                .writer
                .as_ref()
                .is_none_or(|w| !w.handle.is_finished());
            let running = !tunnel.pipeline_task.is_finished() && writer_running;
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
