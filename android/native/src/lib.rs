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
use vdpi_core::binder::OutboundBinder;
use vdpi_core::desync::EngineContext;
#[cfg(unix)]
use vdpi_tun::config::TunProfile;
use vdpi_tun::doctor::run_doctor;
use vdpi_tun::events::EventRing;
use vdpi_tun::pipeline::TunStats;

#[cfg(target_os = "android")]
mod android_protect {
    use crate::{start_tunnel_with_binder, AndroidConfig};
    use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
    use jni::sys::{jint, jstring};
    use jni::{JNIEnv, JavaVM};
    use std::fmt;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::io::{FromRawFd, OwnedFd};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;
    use vdpi_core::binder::OutboundBinder;

    const MAX_CONFIG_JSON_BYTES: usize = 256 * 1024;

    /// Android [`OutboundBinder`] backed by a [`JavaVM`] and a [`GlobalRef`] to `VpnService`.
    /// Invokes `VpnService.protect(fd)` before `connect()`/`bind()` on every outbound TCP/UDP
    /// socket so traffic bypasses the TUN device even under Always-On VPN + Lockdown mode.
    pub struct AndroidProtectBinder {
        vm: JavaVM,
        vpn_service: GlobalRef,
    }

    impl fmt::Debug for AndroidProtectBinder {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("AndroidProtectBinder")
                .field("vpn_service", &"<GlobalRef(VpnService)>")
                .finish()
        }
    }

    impl AndroidProtectBinder {
        pub fn new(env: &JNIEnv, vpn_service: &JObject) -> jni::errors::Result<Self> {
            let vm = env.get_java_vm()?;
            let vpn_service = env.new_global_ref(vpn_service)?;
            Ok(Self { vm, vpn_service })
        }
    }

    impl OutboundBinder for AndroidProtectBinder {
        fn bind_socket(&self, sock: socket2::SockRef<'_>, _is_ipv4: bool) -> io::Result<()> {
            let fd: jint = sock.as_raw_fd();
            let mut env = self
                .vm
                .attach_current_thread_as_daemon()
                .map_err(|e| io::Error::other(format!("JNI attach_current_thread failed: {e}")))?;
            let protected = env
                .with_local_frame::<_, bool, jni::errors::Error>(8, |env| {
                    let res = env.call_method(
                        &self.vpn_service,
                        "protect",
                        "(I)Z",
                        &[JValue::Int(fd)],
                    );
                    match res {
                        Ok(val) => val.z(),
                        Err(err) => {
                            if env.exception_check().unwrap_or(false) {
                                let _ = env.exception_clear();
                            }
                            Err(err)
                        }
                    }
                })
                .map_err(|e| io::Error::other(format!("VpnService.protect({fd}) JNI error: {e}")))?;

            if protected {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("VpnService.protect({fd}) returned false"),
                ))
            }
        }
    }

    fn safe_jstring(env: &mut JNIEnv, value: &str) -> jstring {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        match env.new_string(value) {
            Ok(s) => s.into_raw(),
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                std::ptr::null_mut()
            }
        }
    }

    fn read_jstring_safe(env: &mut JNIEnv, input: &JString) -> Result<String, &'static str> {
        if input.is_null() {
            return Err("config JSON string is null");
        }
        match env.get_string(input) {
            Ok(s) => {
                if s.to_bytes().len() > MAX_CONFIG_JSON_BYTES {
                    return Err("config JSON exceeds 256 KiB limit");
                }
                let owned: String = s.into();
                if owned.len() > MAX_CONFIG_JSON_BYTES {
                    return Err("config JSON exceeds 256 KiB limit");
                }
                Ok(owned)
            }
            Err(_) => {
                if env.exception_check().unwrap_or(false) {
                    let _ = env.exception_clear();
                }
                Err("failed to read JNI config JSON string")
            }
        }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_vulninc_vdpi_engine_NativeEngine_nativeStartWithProtector(
        mut env: JNIEnv,
        _class: JClass,
        tun_fd: jint,
        config_json: JString,
        vpn_service: JObject,
    ) -> jstring {
        // Adopt TUN fd ownership immediately before any fallible JNI call so every
        // early error return or panic automatically closes the detached fd via Drop.
        let owned_fd = if tun_fd > 2 {
            // SAFETY: `tun_fd` is greater than stdio fds (0, 1, 2) and exclusively detached by
            // Android's `ParcelFileDescriptor.detachFd()` for transfer into native ownership.
            Some(unsafe { OwnedFd::from_raw_fd(tun_fd) })
        } else {
            None
        };

        let result = catch_unwind(AssertUnwindSafe(|| {
            let Some(fd) = owned_fd else {
                return format!("invalid TUN file descriptor: {tun_fd}");
            };
            let raw_cfg = match read_jstring_safe(&mut env, &config_json) {
                Ok(s) => s,
                Err(msg) => return msg.to_string(),
            };
            let cfg = match AndroidConfig::from_json_str(&raw_cfg) {
                Ok(c) => c,
                Err(e) => return format!("invalid config JSON: {e}"),
            };
            let binder: Option<Arc<dyn OutboundBinder>> = if vpn_service.is_null() {
                None
            } else {
                match AndroidProtectBinder::new(&env, &vpn_service) {
                    Ok(b) => Some(Arc::new(b)),
                    Err(e) => {
                        if env.exception_check().unwrap_or(false) {
                            let _ = env.exception_clear();
                        }
                        return format!("failed to bind VpnService protector: {e}");
                    }
                }
            };
            match start_tunnel_with_binder(fd, cfg, binder) {
                Ok(()) => String::new(),
                Err(e) => format!("{e:#}"),
            }
        }));

        let msg = match result {
            Ok(m) => m,
            Err(_) => "native engine panicked during start".to_string(),
        };
        safe_jstring(&mut env, &msg)
    }
}

#[cfg(target_os = "android")]
pub use android_protect::AndroidProtectBinder;

struct ActiveTunnel {
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    started_at: Instant,
    shutdown_tx: watch::Sender<bool>,
    route_tx: watch::Sender<u64>,
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

#[cfg(unix)]
fn ignore_sigpipe_once() {
    // POSIX SIGPIPE = 13 and SIG_IGN = 1 on Linux/Android/Darwin Unix ABIs.
    // Bound via extern "C" so vdpi-android stays free of an extra libc dependency.
    const SIGPIPE: std::ffi::c_int = 13;
    const SIG_IGN: usize = 1;
    extern "C" {
        fn signal(sig: std::ffi::c_int, handler: usize) -> usize;
    }
    // SAFETY: Setting SIGPIPE disposition to SIG_IGN is async-signal-safe and ensures
    // writes to peer-closed sockets return EPIPE instead of aborting the process.
    unsafe {
        signal(SIGPIPE, SIG_IGN);
    }
}

fn manager() -> Result<&'static TunnelManager> {
    let init = MANAGER.get_or_init(|| {
        #[cfg(unix)]
        ignore_sigpipe_once();

        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .max_blocking_threads(16)
            .thread_keep_alive(Duration::from_secs(30))
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
    let active = mgr.active.lock().unwrap_or_else(|e| e.into_inner()).take();
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
            mgr.runtime.block_on(async {
                let _ = tokio::time::timeout(Duration::from_millis(500), &mut handle).await;
                let _ = tokio::time::timeout(
                    Duration::from_millis(500),
                    vdpi_tun::flush_engine_cache(&tunnel.ctx),
                )
                .await;
            });
        }
        mgr.events.push("info", "tunnel", "disconnect completed");
    }
}

/// Starts the Android TUN engine on `owned_fd`, closing any prior session cleanly first.
/// Registers `owned_fd` with Tokio synchronously so invalid fds fail immediately and never leak.
#[cfg(unix)]
pub fn start_tunnel(owned_fd: std::os::unix::io::OwnedFd, cfg: AndroidConfig) -> Result<()> {
    start_tunnel_with_binder(owned_fd, cfg, None)
}

/// Starts the Android TUN engine on `owned_fd` with an optional [`OutboundBinder`] (such as
/// `AndroidProtectBinder` backed by `VpnService.protect(fd)`), closing any prior session cleanly first.
#[cfg(unix)]
pub fn start_tunnel_with_binder(
    owned_fd: std::os::unix::io::OwnedFd,
    cfg: AndroidConfig,
    binder: Option<Arc<dyn OutboundBinder>>,
) -> Result<()> {
    let mgr = manager()?;
    let _lifecycle = mgr.lifecycle_lock.lock().unwrap_or_else(|e| e.into_inner());

    let mtu = cfg.clamped_mtu();
    let mode_label = format!("{:?}", cfg.mode);
    let dns_label = vdpi_core::dns::redact_dns_for_display(&cfg.dns_addr);
    let doh_enabled = vdpi_core::dns::is_effective_doh_target(&cfg.dns_addr, cfg.enable_doh);
    let protected = binder.is_some();

    // Tear down any previous tunnel BEFORE loading `adaptive-cache.json` so the old session
    // flushes newly learned strategies and never overwrites the new session's cache.
    stop_active_locked(mgr);

    let ctx = mgr
        .runtime
        .block_on(vdpi_tun::build_engine_context_with_binder(cfg, binder))?;

    let async_fd = {
        let _enter = mgr.runtime.enter();
        vdpi_tun::fd::register_tun_fd(owned_fd).context("failed to register Android TUN fd")?
    };

    let tun_stats = Arc::new(TunStats::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (route_tx, route_rx) = watch::channel(0u64);

    mgr.events.push(
        "info",
        "tunnel",
        format!(
            "engine started (mode={mode_label}, dns={dns_label}, doh={doh_enabled}, mtu={mtu}, protect={protected})"
        ),
    );

    let task_ctx = ctx.clone();
    let task_stats = Arc::clone(&tun_stats);
    let task_events = Arc::clone(&mgr.events);

    let task = mgr.runtime.spawn(async move {
        if let Err(e) = vdpi_tun::fd::run_registered_tun_fd_with_route_watch(
            async_fd,
            task_ctx,
            task_stats,
            Arc::clone(&task_events),
            mtu,
            TunProfile::STANDARD,
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

    let mut guard = mgr.active.lock().unwrap_or_else(|e| e.into_inner());
    *guard = Some(ActiveTunnel {
        ctx,
        tun_stats,
        started_at: Instant::now(),
        shutdown_tx,
        route_tx,
        task,
    });
    Ok(())
}

#[cfg(not(unix))]
pub fn start_tunnel(tun_fd: i32, cfg: AndroidConfig) -> Result<()> {
    start_tunnel_with_binder(tun_fd, cfg, None)
}

#[cfg(not(unix))]
pub fn start_tunnel_with_binder(
    _tun_fd: i32,
    _cfg: AndroidConfig,
    _binder: Option<Arc<dyn OutboundBinder>>,
) -> Result<()> {
    anyhow::bail!("raw TUN fd attachment requires Unix/Android")
}

/// Signals an uplink or route change (Wi-Fi <-> Cellular handoff) to immediately drain and
/// rebind stale UDP Cone-NAT sockets and clear stale DNS caches without wiping learned
/// adaptive TLS strategies.
pub fn notify_route_change() {
    let Ok(mgr) = manager() else {
        return;
    };
    let route_tx = mgr
        .active
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|t| t.route_tx.clone());
    if let Some(route_tx) = route_tx {
        let mut generation = 0u64;
        route_tx.send_modify(|g| {
            *g = g.wrapping_add(1);
            generation = *g;
        });
        mgr.events.push(
            "info",
            "tunnel",
            format!(
                "route change notified (gen={generation}): rebinding UDP flows and clearing DNS cache"
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
