use crate::binder::{DynamicOutboundBinder, OutboundBinder, OutboundTarget};
use crate::config::{EngineMode, RuntimeConfig, VpnCoexistence};
use crate::desync::EngineContext;
use crate::dns::DnsResolver;
use crate::health::{
    bind_loopback_health_listener, serve_health_until_shutdown, HealthMetaFn, HealthRuntimeMeta,
    DEFAULT_TUN_HEALTH_PORT,
};
use crate::platform::vpn::{detect_active_vpn, VpnScope};
use crate::platform::vpn_guard::{GuardAction, VpnGuard};
use crate::platform::windows::{
    clear_all_windows_proxies, flush_dns_resolver_cache, notify_wininet_refresh,
    set_running_as_service, WindowsProxySession,
};
use crate::platform::windows_tun::{
    cleanup_orphan_wintun_adapter, find_verified_wintun_dll, WindowsTunSession, VDPI_TUN_NAME,
};
use crate::server::{bind_listeners, serve_until_shutdown};
use crate::service::{clear_runtime_state, write_runtime_state_with_meta};
use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use vdpi_tun::config::{TunProfile, DESKTOP_MTU};
use vdpi_tun::events::EventRing;
use vdpi_tun::pipeline::{run_tun_pipeline_with_app_bypass, TunStats};
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

pub const SERVICE_NAME: &str = "vdpi";
pub const SERVICE_DISPLAY_NAME: &str = "vdpi Anti-DPI Service";
pub const SERVICE_DESCRIPTION: &str =
    "Zero-hassle, high-performance anti-DPI local proxy engine (HTTP/HTTPS/SOCKS5 + DoH).";
pub const SERVICE_CONTROL_UPGRADE_STOP: u32 = 128;

const SERVICE_DEPENDENCIES: &str = "Tcpip\0Nsi\0Dnscache\0\0";

type ScHandle = *mut c_void;
type ServiceStatusHandle = *mut c_void;
type Bool = i32;
type Dword = u32;

const SC_MANAGER_CONNECT: Dword = 0x0001;
const SC_MANAGER_ALL_ACCESS: Dword = 0x000F_003F;

const SERVICE_QUERY_CONFIG: Dword = 0x0001;
const SERVICE_QUERY_STATUS: Dword = 0x0004;
const SERVICE_START: Dword = 0x0010;
const SERVICE_STOP: Dword = 0x0020;
const SERVICE_USER_DEFINED_CONTROL: Dword = 0x0100;
const DELETE: Dword = 0x0001_0000;
const SERVICE_ALL_ACCESS: Dword = 0x000F_01FF;

const SERVICE_WIN32_OWN_PROCESS: Dword = 0x0000_0010;
const SERVICE_AUTO_START: Dword = 0x0000_0002;
const SERVICE_DEMAND_START: Dword = 0x0000_0003;
const SERVICE_DISABLED: Dword = 0x0000_0004;
const SERVICE_ERROR_NORMAL: Dword = 0x0000_0001;

const SERVICE_STOPPED: Dword = 0x0000_0001;
const SERVICE_START_PENDING: Dword = 0x0000_0002;
const SERVICE_STOP_PENDING: Dword = 0x0000_0003;
const SERVICE_RUNNING: Dword = 0x0000_0004;
const SERVICE_CONTINUE_PENDING: Dword = 0x0000_0005;
const SERVICE_PAUSE_PENDING: Dword = 0x0000_0006;
const SERVICE_PAUSED: Dword = 0x0000_0007;

const SERVICE_ACCEPT_STOP: Dword = 0x0000_0001;
const SERVICE_ACCEPT_SHUTDOWN: Dword = 0x0000_0004;
const SERVICE_ACCEPT_POWEREVENT: Dword = 0x0000_0040;
const SERVICE_ACCEPT_SESSIONCHANGE: Dword = 0x0000_0080;
const SERVICE_ACCEPTED_CONTROLS: Dword = SERVICE_ACCEPT_STOP
    | SERVICE_ACCEPT_SHUTDOWN
    | SERVICE_ACCEPT_POWEREVENT
    | SERVICE_ACCEPT_SESSIONCHANGE;

const SERVICE_CONTROL_STOP: Dword = 0x0000_0001;
const SERVICE_CONTROL_INTERROGATE: Dword = 0x0000_0004;
const SERVICE_CONTROL_SHUTDOWN: Dword = 0x0000_0005;
const SERVICE_CONTROL_POWEREVENT: Dword = 0x0000_000D;
const SERVICE_CONTROL_SESSIONCHANGE: Dword = 0x0000_000E;

const PBT_APMRESUMESUSPEND: Dword = 0x0000_0007;
const PBT_APMRESUMEAUTOMATIC: Dword = 0x0000_0012;
const DEVICE_NOTIFY_CALLBACK: Dword = 0x0000_0002;

const WTS_SESSION_LOGON: Dword = 0x0000_0005;
const WTS_SESSION_UNLOCK: Dword = 0x0000_0008;

const SERVICE_CONFIG_DESCRIPTION: Dword = 1;
const SERVICE_CONFIG_FAILURE_ACTIONS: Dword = 2;
const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: Dword = 3;
const SC_ACTION_RESTART: Dword = 1;
const SC_STATUS_PROCESS_INFO: Dword = 0;

const NO_ERROR: Dword = 0;
const ERROR_ACCESS_DENIED: Dword = 5;
const ERROR_CALL_NOT_IMPLEMENTED: Dword = 120;
const ERROR_INVALID_SERVICE_CONTROL: Dword = 1052;
const ERROR_SERVICE_ALREADY_RUNNING: Dword = 1056;
const ERROR_SERVICE_DOES_NOT_EXIST: Dword = 1060;
const ERROR_SERVICE_CANNOT_ACCEPT_CTRL: Dword = 1061;
const ERROR_SERVICE_NOT_ACTIVE: Dword = 1062;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: Dword = 1063;
const ERROR_SERVICE_MARKED_FOR_DELETE: Dword = 1072;
const ERROR_CANCELLED: Dword = 1223;
const STATUS_CONTROL_C_EXIT: Dword = 0xC000_013A;
const DBG_TERMINATE_PROCESS: Dword = 0x4001_0004;

const SEE_MASK_NOCLOSEPROCESS: Dword = 0x0000_0040;
const SW_SHOWNORMAL: i32 = 1;
const INFINITE: Dword = 0xFFFF_FFFF;
const WAIT_OBJECT_0: Dword = 0;

#[repr(C)]
struct ShellExecuteInfoW {
    cb_size: Dword,
    f_mask: Dword,
    hwnd: *mut c_void,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: *mut c_void,
    lp_id_list: *mut c_void,
    lp_class: *const u16,
    hkey_class: *mut c_void,
    dw_hot_key: Dword,
    h_icon_or_monitor: *mut c_void,
    h_process: *mut c_void,
}

#[repr(C)]
struct ServiceTableEntryW {
    lp_service_name: *const u16,
    lp_service_proc: Option<unsafe extern "system" fn(Dword, *mut *mut u16)>,
}

#[repr(C)]
struct ServiceStatus {
    dw_service_type: Dword,
    dw_current_state: Dword,
    dw_controls_accepted: Dword,
    dw_win32_exit_code: Dword,
    dw_service_specific_exit_code: Dword,
    dw_check_point: Dword,
    dw_wait_hint: Dword,
}

#[repr(C)]
#[allow(dead_code)]
struct ServiceStatusProcess {
    dw_service_type: Dword,
    dw_current_state: Dword,
    dw_controls_accepted: Dword,
    dw_win32_exit_code: Dword,
    dw_service_specific_exit_code: Dword,
    dw_check_point: Dword,
    dw_wait_hint: Dword,
    dw_process_id: Dword,
    dw_service_flags: Dword,
}

#[repr(C)]
struct ServiceDescriptionW {
    lp_description: *mut u16,
}

#[repr(C)]
struct ScAction {
    action_type: Dword,
    delay: Dword,
}

#[repr(C)]
struct ServiceFailureActionsW {
    dw_reset_period: Dword,
    lp_reboot_msg: *mut u16,
    lp_command: *mut u16,
    c_actions: Dword,
    lpsa_actions: *mut ScAction,
}

#[repr(C)]
struct ServiceDelayedAutoStartInfo {
    f_delayed_autostart: Bool,
}

#[repr(C)]
#[allow(dead_code)]
struct QueryServiceConfigW {
    dw_service_type: Dword,
    dw_start_type: Dword,
    dw_error_control: Dword,
    lp_binary_path_name: *mut u16,
    lp_load_order_group: *mut u16,
    dw_tag_id: Dword,
    lp_dependencies: *mut u16,
    lp_service_start_name: *mut u16,
    lp_display_name: *mut u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> Dword;
    fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: Dword) -> Dword;
    fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut Dword) -> Bool;
    fn CloseHandle(h_object: *mut c_void) -> Bool;
}

#[link(name = "shell32")]
extern "system" {
    fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> Bool;
}

#[link(name = "advapi32")]
extern "system" {
    fn StartServiceCtrlDispatcherW(lp_service_start_table: *const ServiceTableEntryW) -> Bool;
    fn RegisterServiceCtrlHandlerExW(
        lp_service_name: *const u16,
        lp_handler_proc: unsafe extern "system" fn(Dword, Dword, *mut c_void, *mut c_void) -> Dword,
        lp_context: *mut c_void,
    ) -> ServiceStatusHandle;
    fn SetServiceStatus(
        h_service_status: ServiceStatusHandle,
        lp_service_status: *const ServiceStatus,
    ) -> Bool;
    fn OpenSCManagerW(
        lp_machine_name: *const u16,
        lp_database_name: *const u16,
        dw_desired_access: Dword,
    ) -> ScHandle;
    fn CloseServiceHandle(h_sc_object: ScHandle) -> Bool;
    fn OpenServiceW(
        h_sc_manager: ScHandle,
        lp_service_name: *const u16,
        dw_desired_access: Dword,
    ) -> ScHandle;
    fn CreateServiceW(
        h_sc_manager: ScHandle,
        lp_service_name: *const u16,
        lp_display_name: *const u16,
        dw_desired_access: Dword,
        dw_service_type: Dword,
        dw_start_type: Dword,
        dw_error_control: Dword,
        lp_binary_path_name: *const u16,
        lp_load_order_group: *const u16,
        lpdw_tag_id: *mut Dword,
        lp_dependencies: *const u16,
        lp_service_start_name: *const u16,
        lp_password: *const u16,
    ) -> ScHandle;
    fn ChangeServiceConfigW(
        h_service: ScHandle,
        dw_service_type: Dword,
        dw_start_type: Dword,
        dw_error_control: Dword,
        lp_binary_path_name: *const u16,
        lp_load_order_group: *const u16,
        lpdw_tag_id: *mut Dword,
        lp_dependencies: *const u16,
        lp_service_start_name: *const u16,
        lp_password: *const u16,
        lp_display_name: *const u16,
    ) -> Bool;
    fn ChangeServiceConfig2W(
        h_service: ScHandle,
        dw_info_level: Dword,
        lp_info: *const c_void,
    ) -> Bool;
    fn StartServiceW(
        h_service: ScHandle,
        dw_num_service_args: Dword,
        lp_service_arg_vectors: *const *const u16,
    ) -> Bool;
    fn ControlService(
        h_service: ScHandle,
        dw_control: Dword,
        lp_service_status: *mut ServiceStatus,
    ) -> Bool;
    fn DeleteService(h_service: ScHandle) -> Bool;
    fn QueryServiceStatusEx(
        h_service: ScHandle,
        info_level: Dword,
        lp_buffer: *mut u8,
        cb_buf_size: Dword,
        pcb_bytes_needed: *mut Dword,
    ) -> Bool;
    fn QueryServiceConfigW(
        h_service: ScHandle,
        lp_service_config: *mut u8,
        cb_buf_size: Dword,
        pcb_bytes_needed: *mut Dword,
    ) -> Bool;
}

struct ScmHandle(ScHandle);

impl Drop for ScmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopReason {
    Stop,
    Shutdown,
    Upgrade,
}

fn should_deactivate_proxy_on_stop(reason: StopReason) -> bool {
    matches!(reason, StopReason::Stop)
}

fn should_fallback_upgrade_control(win32_err: Dword) -> bool {
    win32_err == ERROR_INVALID_SERVICE_CONTROL || win32_err == ERROR_CALL_NOT_IMPLEMENTED
}

const RECONCILE_EVENT_SESSION_LOGON: u32 = 1 << 0;
const RECONCILE_EVENT_SESSION_UNLOCK: u32 = 1 << 1;
const RECONCILE_EVENT_POWER_RESUME: u32 = 1 << 2;

struct ControlChannels {
    stop_tx: watch::Sender<Option<StopReason>>,
    reconcile_tx: watch::Sender<u64>,
    reconcile_events: Arc<AtomicU32>,
}

static SERVICE_CONFIG: OnceLock<Mutex<Option<RuntimeConfig>>> = OnceLock::new();
static SERVICE_ERROR: OnceLock<Mutex<Option<String>>> = OnceLock::new();
static CONTROL_CHANNELS: OnceLock<Mutex<Option<ControlChannels>>> = OnceLock::new();
static SERVICE_STATUS_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[derive(Debug, Clone)]
pub struct WindowsServiceInfo {
    pub installed: bool,
    pub state: &'static str,
    pub start_type: &'static str,
    pub pid: Option<u32>,
    pub binary_path: Option<String>,
}

/// Returns `true` if the current process has Administrator privileges to manage Windows services.
pub fn is_elevated() -> bool {
    let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if raw.is_null() {
        false
    } else {
        unsafe {
            let _ = CloseServiceHandle(raw);
        }
        true
    }
}

fn classify_elevated_child_exit(exit_code: Dword) -> Result<()> {
    match exit_code {
        0 | STATUS_CONTROL_C_EXIT | DBG_TERMINATE_PROCESS => Ok(()),
        code if code >= 0x10000 => bail!(
            "elevated vdpi command failed (exit code {code} / 0x{code:08X}); \
             re-run from an elevated Administrator terminal to see full error output"
        ),
        code => bail!(
            "elevated vdpi command failed (exit code {code}); \
             re-run from an elevated Administrator terminal to see full error output"
        ),
    }
}

/// Relaunches the current `vdpi.exe` with explicit CLI arguments under UAC elevation (`runas`)
/// and waits for the elevated process to finish.
pub fn relaunch_elevated_and_wait(args: &[String]) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "Administrator privileges are required, and UAC elevation cannot be prompted in a \
             non-interactive or piped session (e.g. CI/SSH). Re-run from an elevated \
             Administrator terminal."
        );
    }

    let current_exe = crate::update::strip_windows_verbatim_prefix(
        &std::env::current_exe().context("failed to determine current executable")?,
    );
    let params: String = args
        .iter()
        .map(|arg| crate::service::quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");

    let temp_dir = crate::update::strip_windows_verbatim_prefix(&std::env::temp_dir());
    let verb_wide = to_wide_null("runas");
    let file_wide = to_wide_null(&current_exe.display().to_string());
    let params_wide = to_wide_null(&params);
    let dir_wide = to_wide_null(&temp_dir.display().to_string());

    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as Dword,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: ptr::null_mut(),
        lp_verb: verb_wide.as_ptr(),
        lp_file: file_wide.as_ptr(),
        lp_parameters: if params.is_empty() {
            ptr::null()
        } else {
            params_wide.as_ptr()
        },
        lp_directory: dir_wide.as_ptr(),
        n_show: SW_SHOWNORMAL,
        h_inst_app: ptr::null_mut(),
        lp_id_list: ptr::null_mut(),
        lp_class: ptr::null(),
        hkey_class: ptr::null_mut(),
        dw_hot_key: 0,
        h_icon_or_monitor: ptr::null_mut(),
        h_process: ptr::null_mut(),
    };

    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            bail!(
                "UAC elevation was cancelled. Administrator privileges are required for Windows TUN mode and '{SERVICE_NAME}' service management."
            );
        }
        bail!("ShellExecuteExW(runas) failed with Win32 error {err}");
    }

    if info.h_process.is_null() {
        bail!("ShellExecuteExW(runas) succeeded without returning an elevated process handle");
    }

    let mut exit_code: Dword = 0;
    let wait_res = unsafe { WaitForSingleObject(info.h_process, INFINITE) };
    let wait_err = if wait_res != WAIT_OBJECT_0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };

    let exit_code_err = if wait_err.is_none() {
        let got_exit = unsafe { GetExitCodeProcess(info.h_process, &mut exit_code) };
        if got_exit == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        }
    } else {
        None
    };

    unsafe {
        let _ = CloseHandle(info.h_process);
    }

    if let Some(err) = wait_err {
        bail!(
            "WaitForSingleObject for elevated vdpi command failed (result {wait_res}, Win32 error {err})"
        );
    }
    if let Some(err) = exit_code_err {
        bail!("GetExitCodeProcess for elevated vdpi command failed with Win32 error {err}");
    }

    classify_elevated_child_exit(exit_code)
}

/// Connects the current process to the Windows Service Control Manager (SCM) and blocks
/// until the service stops.
pub fn run_windows_service(cfg: RuntimeConfig) -> Result<()> {
    {
        let lock = SERVICE_CONFIG.get_or_init(|| Mutex::new(None));
        let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(cfg);
    }

    let name_wide = to_wide_null(SERVICE_NAME);
    let table = [
        ServiceTableEntryW {
            lp_service_name: name_wide.as_ptr(),
            lp_service_proc: Some(service_main),
        },
        ServiceTableEntryW {
            lp_service_name: ptr::null(),
            lp_service_proc: None,
        },
    ];

    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            bail!(
                "--service can only be launched by the Windows Service Control Manager. \
                 Run 'vdpi start' for interactive mode or 'vdpi install' to install the service."
            );
        }
        bail!("StartServiceCtrlDispatcherW failed with Win32 error {err}");
    }

    if let Some(lock) = SERVICE_ERROR.get() {
        if let Some(msg) = lock.lock().unwrap_or_else(|e| e.into_inner()).take() {
            bail!("{msg}");
        }
    }

    Ok(())
}

unsafe extern "system" fn service_main(_argc: Dword, _argv: *mut *mut u16) {
    set_running_as_service(true);

    let name_wide = to_wide_null(SERVICE_NAME);
    let handle =
        RegisterServiceCtrlHandlerExW(name_wide.as_ptr(), service_control_handler, ptr::null_mut());
    if handle.is_null() {
        return;
    }
    SERVICE_STATUS_HANDLE.store(handle, Ordering::SeqCst);

    report_service_status(handle, SERVICE_START_PENDING, 0, NO_ERROR, 1, 5000);

    let cfg = SERVICE_CONFIG
        .get()
        .and_then(|m| m.lock().unwrap_or_else(|e| e.into_inner()).take());

    let run_result = match cfg {
        Some(cfg) => run_service_runtime(handle, cfg),
        None => Err(anyhow::anyhow!("missing runtime configuration for service")),
    };

    if let Some(lock) = CONTROL_CHANNELS.get() {
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    match run_result {
        Ok(()) => {
            report_service_status(handle, SERVICE_STOPPED, 0, NO_ERROR, 0, 0);
        }
        Err(err) => {
            error!(error = %err, "vdpi Windows service terminated with error");
            let lock = SERVICE_ERROR.get_or_init(|| Mutex::new(None));
            *lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(err.to_string());
            report_service_status(handle, SERVICE_STOPPED, 0, 1, 0, 0);
        }
    }
}

enum TunRunOutcome {
    Stopped,
    FallbackToProxy(anyhow::Error),
}

struct TunSlot {
    session: Option<WindowsTunSession>,
    pipeline_stop_tx: Option<watch::Sender<bool>>,
    pipeline_task: Option<tokio::task::JoinHandle<Result<()>>>,
    route_rx: Option<watch::Receiver<u64>>,
}

impl TunSlot {
    fn empty() -> Self {
        Self {
            session: None,
            pipeline_stop_tx: None,
            pipeline_task: None,
            route_rx: None,
        }
    }

    fn is_running(&self) -> bool {
        self.session.is_some()
    }

    fn iface_name(&self) -> Option<String> {
        self.session.as_ref().map(|s| s.iface_name().to_string())
    }

    fn physical_nic_name(&self) -> Option<String> {
        self.session.as_ref().and_then(|s| s.physical_nic_name())
    }

    fn force_reconcile_uplink(&self) {
        if let Some(ref session) = self.session {
            session.force_reconcile_uplink();
        }
    }

    fn is_ipv6_active(&self) -> bool {
        self.session.as_ref().is_some_and(|s| s.is_ipv6_active())
    }

    async fn start(
        &mut self,
        binder: &Arc<DynamicOutboundBinder>,
        tun_ipv6: bool,
        explicit_dns_ipv4_only: bool,
        ctx: &EngineContext,
        tun_stats: &Arc<TunStats>,
        events: &Arc<EventRing>,
    ) -> Result<()> {
        if self.session.is_some() {
            return Ok(());
        }
        let start_binder = Arc::clone(binder);
        let (session, inbound_rx, outbound_tx, route_rx) =
            tokio::task::spawn_blocking(move || WindowsTunSession::start(start_binder, tun_ipv6))
                .await
                .context("Windows TUN startup task panicked")??;

        // Sync live DNS IPv4-only filtering with explicit `--ipv4-only` config and the
        // actual active TUN IPv6 state:
        // - Explicit `--ipv4-only` is always honored (`explicit_dns_ipv4_only == true`)
        // - IPv4-only / dual-stack with !tun_ipv6 -> ipv6_active=false -> ipv4_only=true (prevents Happy Eyeballs AAAA leak)
        // - IPv6-only uplink (auto-enabled IPv6 TUN) or tun_ipv6=true on dual-stack -> ipv6_active=true -> ipv4_only=false
        ctx.dns.set_ipv4_only(effective_tun_dns_ipv4_only(
            explicit_dns_ipv4_only,
            session.is_ipv6_active(),
        ));

        let app_bypass = crate::split_tunnel::build_tun_app_bypass_hook(&ctx.config.split_tunnel);
        let (pipeline_stop_tx, pipeline_stop_rx) = watch::channel(false);
        let pipeline_task = tokio::spawn(run_tun_pipeline_with_app_bypass(
            inbound_rx,
            outbound_tx,
            ctx.clone(),
            Arc::clone(tun_stats),
            Arc::clone(events),
            DESKTOP_MTU,
            TunProfile::DESKTOP,
            pipeline_stop_rx,
            Some(route_rx.clone()),
            app_bypass,
        ));

        self.session = Some(session);
        self.pipeline_stop_tx = Some(pipeline_stop_tx);
        self.pipeline_task = Some(pipeline_task);
        self.route_rx = Some(route_rx);
        let _ = tokio::task::spawn_blocking(notify_wininet_refresh).await;
        Ok(())
    }

    async fn stop(&mut self) {
        self.route_rx = None;
        if let Some(tx) = self.pipeline_stop_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(mut task) = self.pipeline_task.take() {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = tokio::time::timeout(Duration::from_millis(500), task).await;
            }
        }
        if let Some(session) = self.session.take() {
            let _ = tokio::task::spawn_blocking(move || drop(session)).await;
        }
    }
}

fn windows_service_cache_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("vdpi").join("adaptive-cache.json")
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sync_tun_telemetry(ctx: &EngineContext, tun_stats: &TunStats) {
    ctx.set_udp_flows_active(tun_stats.udp_flows_active.load(Ordering::Relaxed));
    let quic = tun_stats.quic_blocked.load(Ordering::Relaxed);
    ctx.telemetry
        .quic_blocked
        .fetch_max(quic, Ordering::Relaxed);
}

fn is_transient_offline_tun_error(err: &anyhow::Error) -> bool {
    format!("{err:#}")
        .to_ascii_lowercase()
        .contains("no active physical network uplink")
}

fn effective_tun_dns_ipv4_only(explicit_dns_ipv4_only: bool, tun_ipv6_active: bool) -> bool {
    explicit_dns_ipv4_only || !tun_ipv6_active
}

async fn sync_tun_dns_ipv4_only_if_changed<F, Fut>(
    dns: &DnsResolver,
    tun_running: bool,
    explicit_dns_ipv4_only: bool,
    tun_ipv6_active: bool,
    flush_os_cache: F,
) -> bool
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if !tun_running {
        return false;
    }
    let next = effective_tun_dns_ipv4_only(explicit_dns_ipv4_only, tun_ipv6_active);
    let prev = dns.is_ipv4_only();
    if prev == next {
        return false;
    }
    dns.set_ipv4_only(next);
    dns.clear_cache().await;
    flush_os_cache().await;
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunStartErrorLogAction {
    LogOfflineStandby,
    SuppressOfflineStandby,
    LogRetryableError,
}

fn classify_tun_start_error_log(
    offline_standby_logged: &mut bool,
    err: &anyhow::Error,
) -> TunStartErrorLogAction {
    if is_transient_offline_tun_error(err) {
        if *offline_standby_logged {
            TunStartErrorLogAction::SuppressOfflineStandby
        } else {
            *offline_standby_logged = true;
            TunStartErrorLogAction::LogOfflineStandby
        }
    } else {
        *offline_standby_logged = false;
        TunStartErrorLogAction::LogRetryableError
    }
}

fn redact_dns_addr_for_health(raw: &str) -> Option<String> {
    let redacted = vdpi_core::dns::redact_dns_for_display(raw);
    (!redacted.is_empty()).then_some(redacted)
}

struct TunSupervisor {
    binder: Arc<DynamicOutboundBinder>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    tun_ipv6: bool,
    explicit_dns_ipv4_only: bool,
    health_addr: SocketAddr,
    vpn_guard: VpnGuard,
    health_meta: Arc<Mutex<HealthRuntimeMeta>>,
    last_scope: VpnScope,
    last_start_attempt: Option<Instant>,
    last_warned_provider: Option<String>,
    offline_standby_logged: bool,
}

impl TunSupervisor {
    async fn reconcile(&mut self, slot: &mut TunSlot) {
        sync_tun_telemetry(&self.ctx, &self.tun_stats);
        let scope = if self.vpn_guard.policy() == VpnCoexistence::Off {
            VpnScope::None
        } else {
            tokio::task::spawn_blocking(|| detect_active_vpn(Some(VDPI_TUN_NAME)))
                .await
                .unwrap_or(VpnScope::None)
        };
        let now = Instant::now();
        let action = self.vpn_guard.evaluate(&scope, now);
        self.last_scope = scope;

        match action {
            GuardAction::YieldTun { provider } => {
                self.last_warned_provider = None;
                self.offline_standby_logged = false;
                warn!(
                    provider = %provider,
                    "full-tunnel VPN detected; yielding Windows TUN session"
                );
                slot.stop().await;
                self.ctx.dns.clear_cache().await;
                self.sync_runtime_state(slot);
            }
            GuardAction::ResumeTun => {
                self.last_warned_provider = None;
                info!("full-tunnel VPN cleared after cooldown; resuming Windows TUN session");
                self.ctx.dns.clear_cache().await;
                self.try_start_slot(slot, now).await;
            }
            GuardAction::WarnOnly { provider } => {
                if self.last_warned_provider.as_deref() != Some(provider.as_str()) {
                    warn!(
                        provider = %provider,
                        "full-tunnel VPN detected (vpn_coexistence=warn); keeping Windows TUN active"
                    );
                    self.last_warned_provider = Some(provider);
                }
            }
            GuardAction::None => {
                if !self.last_scope.is_full_tunnel() {
                    self.last_warned_provider = None;
                }
                if !self.vpn_guard.is_yielded() && !slot.is_running() {
                    let retry_due = self.last_start_attempt.is_none_or(|prev| {
                        now.saturating_duration_since(prev) >= Duration::from_secs(5)
                    });
                    if retry_due {
                        self.try_start_slot(slot, now).await;
                    }
                }
            }
        }

        self.sync_health_meta(slot);
    }

    async fn try_start_slot(&mut self, slot: &mut TunSlot, now: Instant) {
        self.last_start_attempt = Some(now);
        match slot
            .start(
                &self.binder,
                self.tun_ipv6,
                self.explicit_dns_ipv4_only,
                &self.ctx,
                &self.tun_stats,
                &self.events,
            )
            .await
        {
            Ok(()) => {
                if self.offline_standby_logged {
                    info!("physical network uplink restored; Windows TUN session is active");
                    self.offline_standby_logged = false;
                }
                self.sync_runtime_state(slot);
            }
            Err(err) => match classify_tun_start_error_log(&mut self.offline_standby_logged, &err) {
                TunStartErrorLogAction::LogOfflineStandby => {
                    warn!(
                        error = %err,
                        "no active physical network uplink; holding Windows TUN in standby and polling for connectivity"
                    );
                }
                TunStartErrorLogAction::SuppressOfflineStandby => {}
                TunStartErrorLogAction::LogRetryableError => {
                    warn!(
                        error = %err,
                        "failed to start or resume Windows TUN session; will retry"
                    );
                }
            },
        }
    }

    async fn sync_dns_ipv4_only(&self, slot: &TunSlot) {
        let tun_ipv6_active = slot.is_ipv6_active();
        if sync_tun_dns_ipv4_only_if_changed(
            &self.ctx.dns,
            slot.is_running(),
            self.explicit_dns_ipv4_only,
            tun_ipv6_active,
            || async {
                let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
            },
        )
        .await
        {
            debug!(
                ipv4_only = self.ctx.dns.is_ipv4_only(),
                tun_ipv6_active,
                "re-synced Windows TUN service DNS IPv4-only filtering after route change"
            );
        }
    }

    fn sync_runtime_state(&self, slot: &TunSlot) {
        write_runtime_state_with_meta(
            self.health_addr,
            None,
            EngineMode::Tun,
            slot.iface_name(),
            None,
        );
    }

    fn sync_health_meta(&self, slot: &TunSlot) {
        if let Ok(mut meta) = self.health_meta.lock() {
            meta.engine = EngineMode::Tun;
            meta.tun_interface = slot.iface_name();
            meta.physical_nic = slot.physical_nic_name();
            meta.vpn_conflict = self.vpn_guard.active_conflict_label(&self.last_scope);
        }
    }
}

const SERVICE_MAX_BLOCKING_THREADS: usize = 16;
const TUN_RECONCILE_ACTIVE_INTERVAL: Duration = Duration::from_secs(3);
const TUN_RECONCILE_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const PROXY_VPN_POLL_ACTIVE_INTERVAL: Duration = Duration::from_secs(3);
const PROXY_VPN_POLL_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const PROXY_RECONCILE_INTERVAL: Duration = Duration::from_secs(15);

fn service_tokio_worker_threads() -> usize {
    std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4))
}

fn tun_reconcile_interval(tun_running: bool, vpn_yielded: bool) -> Duration {
    if tun_running && !vpn_yielded {
        TUN_RECONCILE_ACTIVE_INTERVAL
    } else {
        TUN_RECONCILE_RECOVERY_INTERVAL
    }
}

fn proxy_vpn_poll_interval(vpn_yielded: bool) -> Duration {
    if vpn_yielded {
        PROXY_VPN_POLL_RECOVERY_INTERVAL
    } else {
        PROXY_VPN_POLL_ACTIVE_INTERVAL
    }
}

fn should_reapply_yielded_proxy_cleanup(vpn_yielded: bool, forced_reconcile: bool) -> bool {
    vpn_yielded && forced_reconcile
}

fn normalize_tun_service_config(mut cfg: RuntimeConfig) -> RuntimeConfig {
    // When IPv6 TUN routing is disabled, force IPv4-only DNS answers so browsers
    // (Happy Eyeballs) on dual-stack ISPs do not leak AAAA connections past vdpi0.
    // Once WindowsTunSession::start succeeds, TunSlot::start syncs the live resolver
    // with `explicit_dns_ipv4_only || !session.is_ipv6_active()` so explicit `--ipv4-only`
    // is preserved while IPv6-only uplinks that auto-enable IPv6 TUN still receive AAAA records.
    if !cfg.tun_ipv6 {
        cfg.dns_ipv4_only = true;
    }
    cfg
}

fn run_service_runtime(handle: ServiceStatusHandle, cfg: RuntimeConfig) -> Result<()> {
    let (stop_tx, stop_rx) = watch::channel::<Option<StopReason>>(None);
    let (reconcile_tx, reconcile_rx) = watch::channel::<u64>(0);
    let reconcile_events = Arc::new(AtomicU32::new(0));

    {
        let lock = CONTROL_CHANNELS.get_or_init(|| Mutex::new(None));
        *lock.lock().unwrap_or_else(|e| e.into_inner()) = Some(ControlChannels {
            stop_tx,
            reconcile_tx,
            reconcile_events: Arc::clone(&reconcile_events),
        });
    }

    // Cap worker and blocking threads so gigabit TUN bursts never wake 16+ workers
    // competing with real-time Windows audio engines (VoiceMeeter/WASAPI/ASIO).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(service_tokio_worker_threads())
        .max_blocking_threads(SERVICE_MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
        .context("failed to initialize Tokio runtime for Windows service")?;

    // Register Modern Standby (S0ix) suspend/resume notifications alongside
    // SERVICE_ACCEPT_POWEREVENT so modern laptops also fire reconcile_events on wake.
    let power_notify_guard = SuspendResumeNotificationGuard::register();

    let result = rt.block_on(async move {
        if cfg.engine == EngineMode::Tun {
            match find_verified_wintun_dll() {
                Ok(_) => {
                    match run_tun_service_runtime(
                        handle,
                        cfg.clone(),
                        stop_rx.clone(),
                        reconcile_rx.clone(),
                        Arc::clone(&reconcile_events),
                    )
                    .await?
                    {
                        TunRunOutcome::Stopped => return Ok(()),
                        TunRunOutcome::FallbackToProxy(err) => {
                            error!(
                                error = %err,
                                "Windows TUN session failed to initialize; falling back to proxy engine mode"
                            );
                        }
                    }
                }
                Err(err) => {
                    error!(
                        error = %err,
                        "wintun.dll is missing or invalid; falling back to proxy engine mode"
                    );
                }
            }

            let mut fallback_cfg = cfg;
            fallback_cfg.engine = EngineMode::Proxy;
            return run_proxy_service_runtime(
                handle,
                fallback_cfg,
                stop_rx,
                reconcile_rx,
                reconcile_events,
            )
            .await;
        }

        run_proxy_service_runtime(handle, cfg, stop_rx, reconcile_rx, reconcile_events).await
    });

    drop(power_notify_guard);
    result
}

async fn run_tun_service_runtime(
    handle: ServiceStatusHandle,
    cfg: RuntimeConfig,
    mut stop_rx: watch::Receiver<Option<StopReason>>,
    mut reconcile_rx: watch::Receiver<u64>,
    reconcile_events: Arc<AtomicU32>,
) -> Result<TunRunOutcome> {
    let explicit_dns_ipv4_only = cfg.dns_ipv4_only;
    let cfg = normalize_tun_service_config(cfg);
    let binder = DynamicOutboundBinder::new(OutboundTarget {
        fail_closed: true,
        ..OutboundTarget::default()
    });
    let binder_trait: Arc<dyn OutboundBinder> = binder.clone();
    let ctx = EngineContext::new_with_binder(cfg.clone(), Some(binder_trait))?;
    ctx.attach_cache_file(windows_service_cache_path()).await;
    let tun_stats = Arc::new(TunStats::default());
    let events = Arc::new(EventRing::new());

    let mut vpn_guard = VpnGuard::new(cfg.vpn_coexistence);
    let initial_scope = if vpn_guard.policy() == VpnCoexistence::Off {
        VpnScope::None
    } else {
        tokio::task::spawn_blocking(|| detect_active_vpn(Some(VDPI_TUN_NAME)))
            .await
            .unwrap_or(VpnScope::None)
    };
    let initial_action = vpn_guard.evaluate(&initial_scope, Instant::now());
    let mut last_warned_provider = None;
    match initial_action {
        GuardAction::YieldTun { ref provider } => {
            warn!(
                provider = %provider,
                "full-tunnel VPN active at startup; holding Windows TUN in standby"
            );
        }
        GuardAction::WarnOnly { ref provider } => {
            warn!(
                provider = %provider,
                "full-tunnel VPN active at startup (vpn_coexistence=warn); keeping Windows TUN active"
            );
            last_warned_provider = Some(provider.clone());
        }
        GuardAction::ResumeTun | GuardAction::None => {}
    }

    let mut slot = TunSlot::empty();
    let mut last_start_attempt = None;
    let mut offline_standby_logged = false;
    if !vpn_guard.is_yielded() {
        last_start_attempt = Some(Instant::now());
        if let Err(err) = slot
            .start(
                &binder,
                cfg.tun_ipv6,
                explicit_dns_ipv4_only,
                &ctx,
                &tun_stats,
                &events,
            )
            .await
        {
            slot.stop().await;
            if is_transient_offline_tun_error(&err) {
                let _ = tokio::task::spawn_blocking(cleanup_orphan_wintun_adapter).await;
                warn!(
                    error = %err,
                    "no active physical network uplink at startup; holding Windows TUN in standby and polling for connectivity"
                );
                offline_standby_logged = true;
            } else {
                return Ok(TunRunOutcome::FallbackToProxy(err));
            }
        }
    } else {
        // Clean up any orphaned vdpi0 adapter left from a prior crash so it cannot
        // blackhole traffic while TUN is held in VPN standby.
        let _ = tokio::task::spawn_blocking(cleanup_orphan_wintun_adapter).await;
    }

    // Clear any leftover WinINET/WinHTTP/user-env proxy settings once when running in TUN mode.
    let _ = tokio::task::spawn_blocking(clear_all_windows_proxies).await;

    let health_meta = Arc::new(Mutex::new(HealthRuntimeMeta {
        engine: EngineMode::Tun,
        tun_interface: slot.iface_name(),
        physical_nic: slot.physical_nic_name(),
        vpn_conflict: vpn_guard.active_conflict_label(&initial_scope),
        dns_addr: redact_dns_addr_for_health(&cfg.dns_addr),
    }));

    let health_listener = match bind_loopback_health_listener(DEFAULT_TUN_HEALTH_PORT) {
        Ok(listener) => listener,
        Err(err) => {
            slot.stop().await;
            return Err(err);
        }
    };
    let health_addr = match health_listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => {
            slot.stop().await;
            return Err(err).context("failed to determine loopback TUN health listener address");
        }
    };
    write_runtime_state_with_meta(health_addr, None, EngineMode::Tun, slot.iface_name(), None);

    let (health_shutdown_tx, health_shutdown_rx) = watch::channel(false);
    let meta_state = Arc::clone(&health_meta);
    let meta_binder = Arc::clone(&binder);
    let meta_ctx = ctx.clone();
    let meta_tun_stats = Arc::clone(&tun_stats);
    let meta_fn: HealthMetaFn = Arc::new(move || {
        sync_tun_telemetry(&meta_ctx, &meta_tun_stats);
        let mut meta = meta_state
            .lock()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone());
        if meta.tun_interface.is_some() {
            meta.physical_nic = meta_binder.physical_nic_name().or(meta.physical_nic);
        }
        meta
    });
    let health_task = tokio::spawn(serve_health_until_shutdown(
        health_listener,
        ctx.clone(),
        meta_fn,
        health_shutdown_rx,
    ));

    report_service_status(
        handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPTED_CONTROLS,
        NO_ERROR,
        0,
        0,
    );

    info!(
        health = %health_addr,
        tun_active = slot.is_running(),
        vpn_coexistence = cfg.vpn_coexistence.as_str(),
        "vdpi Windows service is running in TUN mode"
    );

    let mut supervisor = TunSupervisor {
        binder,
        ctx,
        tun_stats,
        events,
        tun_ipv6: cfg.tun_ipv6,
        explicit_dns_ipv4_only,
        health_addr,
        vpn_guard,
        health_meta,
        last_scope: initial_scope,
        last_start_attempt,
        last_warned_provider,
        offline_standby_logged,
    };

    let mut reconcile_open = true;

    let reason = loop {
        if let Some(r) = *stop_rx.borrow() {
            break r;
        }
        let poll_interval =
            tun_reconcile_interval(slot.is_running(), supervisor.vpn_guard.is_yielded());
        tokio::select! {
            biased;
            changed = stop_rx.changed() => {
                if changed.is_err() {
                    break StopReason::Stop;
                }
                if let Some(r) = *stop_rx.borrow() {
                    break r;
                }
            }
            pipeline_res = async {
                match slot.pipeline_task.as_mut() {
                    Some(task) => task.await,
                    None => std::future::pending().await,
                }
            } => {
                slot.pipeline_task = None;
                warn!(
                    result = ?pipeline_res,
                    "Windows TUN pipeline exited unexpectedly; tearing down adapter for recovery"
                );
                slot.stop().await;
                supervisor.last_start_attempt = Some(Instant::now());
                supervisor.sync_runtime_state(&slot);
                supervisor.sync_health_meta(&slot);
            }
            changed = async {
                match slot.route_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_ok() {
                    // Sync DNS IPv4-only filtering before reconcile (which runs blocking
                    // VPN detection) so queries during the transition never hit stale
                    // ipv4_only=true and cache synthetic NODATA in Windows Dnscache.
                    supervisor.sync_dns_ipv4_only(&slot).await;
                    supervisor.reconcile(&mut slot).await;
                } else {
                    slot.route_rx = None;
                }
            }
            changed = async {
                if reconcile_open {
                    reconcile_rx.changed().await
                } else {
                    std::future::pending().await
                }
            } => {
                if changed.is_ok() {
                    let event_flags = reconcile_events.swap(0, Ordering::SeqCst);
                    let is_power_resume = (event_flags & RECONCILE_EVENT_POWER_RESUME) != 0;
                    let is_session_unlock = (event_flags & RECONCILE_EVENT_SESSION_UNLOCK) != 0;
                    if is_power_resume || is_session_unlock {
                        supervisor.ctx.dns.clear_cache().await;
                    }
                    if is_power_resume {
                        supervisor.last_start_attempt = None;
                    }
                    let was_running = slot.is_running();
                    supervisor.reconcile(&mut slot).await;
                    if is_power_resume && was_running && slot.is_running() {
                        slot.force_reconcile_uplink();
                        let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
                    }
                } else {
                    reconcile_open = false;
                }
            }
            _ = tokio::time::sleep(poll_interval) => {
                supervisor.reconcile(&mut slot).await;
            }
        }
    };

    info!(
        ?reason,
        "stopping Windows TUN service and tearing down adapter"
    );
    report_service_status(handle, SERVICE_STOP_PENDING, 0, NO_ERROR, 2, 5000);
    let _ = health_shutdown_tx.send(true);
    clear_runtime_state(std::process::id());
    // Always tear down WindowsTunSession cleanly on Stop, Shutdown, and Upgrade.
    slot.stop().await;
    sync_tun_telemetry(&supervisor.ctx, &supervisor.tun_stats);
    if let Err(err) = supervisor.ctx.flush_persisted_cache().await {
        warn!(error = %err, "failed to flush adaptive cache on Windows TUN service shutdown");
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), health_task).await;

    Ok(TunRunOutcome::Stopped)
}

async fn run_proxy_service_runtime(
    handle: ServiceStatusHandle,
    cfg: RuntimeConfig,
    mut stop_rx: watch::Receiver<Option<StopReason>>,
    mut reconcile_rx: watch::Receiver<u64>,
    reconcile_events: Arc<AtomicU32>,
) -> Result<()> {
    // Clean up any orphaned vdpi0 Wintun adapter left behind by a prior TUN run or crash
    // (covers direct Proxy mode startup, missing wintun.dll fallback, and TUN init fallback).
    let _ = tokio::task::spawn_blocking(cleanup_orphan_wintun_adapter).await;

    let ctx = EngineContext::new(cfg.clone())?;
    ctx.attach_cache_file(windows_service_cache_path()).await;
    let bound = bind_listeners(&ctx)?;

    let primary_addr = bound.primary_addr;
    let socks_addr = bound.socks_addr;

    let mut vpn_guard = VpnGuard::new(cfg.vpn_coexistence);
    let mut last_warned_provider: Option<String> = None;
    let initial_scope = if cfg.system_proxy && vpn_guard.policy() != VpnCoexistence::Off {
        tokio::task::spawn_blocking(|| detect_active_vpn(None))
            .await
            .unwrap_or(VpnScope::None)
    } else {
        VpnScope::None
    };
    if cfg.system_proxy {
        match vpn_guard.evaluate(&initial_scope, Instant::now()) {
            GuardAction::YieldTun { ref provider } => {
                warn!(
                    provider = %provider,
                    "full-tunnel VPN active at startup; holding Windows system proxy in standby"
                );
            }
            GuardAction::WarnOnly { ref provider } => {
                warn!(
                    provider = %provider,
                    "full-tunnel VPN active at startup (vpn_coexistence=warn); keeping Windows system proxy active"
                );
                last_warned_provider = Some(provider.clone());
            }
            GuardAction::ResumeTun | GuardAction::None => {}
        }
    }

    let proxy_session = if cfg.system_proxy {
        if vpn_guard.is_yielded() {
            let standby = WindowsProxySession::new_standby(
                primary_addr.ip(),
                primary_addr.port(),
                cfg.vpn_coexistence,
            );
            // Clear any leftover vdpi AutoConfigURL/proxy settings preserved across
            // reboot or upgrade while a full-tunnel VPN is already connected, without
            // removing saved user proxy state on disk.
            let yield_session = standby.clone();
            let _ = tokio::task::spawn_blocking(move || {
                yield_session.yield_for_vpn();
                flush_dns_resolver_cache();
            })
            .await;
            Some(standby)
        } else {
            Some(
                WindowsProxySession::activate(
                    primary_addr.ip(),
                    primary_addr.port(),
                    socks_addr.map(|a| a.port()),
                    cfg.socks_system_proxy,
                    cfg.env_proxy,
                    &cfg.bypass_domains,
                )?
                .with_vpn_coexistence(cfg.vpn_coexistence),
            )
        }
    } else {
        None
    };

    let env_activated_at = (cfg.system_proxy && cfg.env_proxy).then(unix_now_secs);
    write_runtime_state_with_meta(
        primary_addr,
        socks_addr,
        EngineMode::Proxy,
        None,
        env_activated_at,
    );

    report_service_status(
        handle,
        SERVICE_RUNNING,
        SERVICE_ACCEPTED_CONTROLS,
        NO_ERROR,
        0,
        0,
    );

    info!(
        primary = %primary_addr,
        socks = ?socks_addr,
        proxy_yielded = vpn_guard.is_yielded(),
        "vdpi Windows service is running"
    );

    let (server_shutdown_tx, server_shutdown_rx) = watch::channel(false);

    let watchdog_session = proxy_session.clone();
    let watchdog_ctx = ctx.clone();
    let mut watchdog_shutdown = server_shutdown_rx.clone();
    let watchdog = tokio::spawn(async move {
        let mut reconcile_open = true;
        let mut last_proxy_reconcile = Instant::now();
        loop {
            let poll_interval = proxy_vpn_poll_interval(vpn_guard.is_yielded());
            let mut forced_reconcile = false;
            let mut power_or_unlock = false;
            tokio::select! {
                biased;
                _ = watchdog_shutdown.changed() => {
                    if *watchdog_shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                changed = async {
                    if reconcile_open {
                        reconcile_rx.changed().await
                    } else {
                        std::future::pending().await
                    }
                } => {
                    if changed.is_err() {
                        reconcile_open = false;
                        continue;
                    }
                    let event_flags = reconcile_events.swap(0, Ordering::SeqCst);
                    let is_power_resume = (event_flags & RECONCILE_EVENT_POWER_RESUME) != 0;
                    let is_session_unlock = (event_flags & RECONCILE_EVENT_SESSION_UNLOCK) != 0;
                    power_or_unlock = is_power_resume || is_session_unlock;
                    forced_reconcile = true;
                }
                _ = async {
                    if watchdog_session.is_some() {
                        tokio::time::sleep(poll_interval).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }

            let Some(ref session) = watchdog_session else {
                if power_or_unlock {
                    watchdog_ctx.dns.clear_cache().await;
                    let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
                }
                continue;
            };

            if power_or_unlock {
                watchdog_ctx.dns.clear_cache().await;
            }

            if vpn_guard.policy() == VpnCoexistence::Off {
                if forced_reconcile || last_proxy_reconcile.elapsed() >= PROXY_RECONCILE_INTERVAL {
                    let s = session.clone();
                    let _ = tokio::task::spawn_blocking(move || s.reconcile()).await;
                    last_proxy_reconcile = Instant::now();
                }
                if power_or_unlock {
                    let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
                }
                continue;
            }

            let scope = tokio::task::spawn_blocking(|| detect_active_vpn(None))
                .await
                .unwrap_or(VpnScope::None);
            let mut dns_flushed = false;
            match vpn_guard.evaluate(&scope, Instant::now()) {
                GuardAction::YieldTun { provider } => {
                    last_warned_provider = None;
                    warn!(
                        provider = %provider,
                        "full-tunnel VPN detected; yielding Windows system proxy"
                    );
                    let s = session.clone();
                    let _ = tokio::task::spawn_blocking(move || s.yield_for_vpn()).await;
                    watchdog_ctx.dns.clear_cache().await;
                    let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
                    dns_flushed = true;
                }
                GuardAction::ResumeTun => {
                    last_warned_provider = None;
                    info!(
                        "full-tunnel VPN cleared after cooldown; restoring Windows system proxy"
                    );
                    watchdog_ctx.dns.clear_cache().await;
                    let s = session.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        s.reconcile();
                        flush_dns_resolver_cache();
                    })
                    .await;
                    last_proxy_reconcile = Instant::now();
                    dns_flushed = true;
                }
                GuardAction::WarnOnly { provider } => {
                    if last_warned_provider.as_deref() != Some(provider.as_str()) {
                        warn!(
                            provider = %provider,
                            "full-tunnel VPN detected (vpn_coexistence=warn); keeping Windows system proxy active"
                        );
                        last_warned_provider = Some(provider);
                    }
                    if forced_reconcile
                        || last_proxy_reconcile.elapsed() >= PROXY_RECONCILE_INTERVAL
                    {
                        let s = session.clone();
                        let _ = tokio::task::spawn_blocking(move || s.reconcile()).await;
                        last_proxy_reconcile = Instant::now();
                    }
                }
                GuardAction::None => {
                    if !scope.is_full_tunnel() {
                        last_warned_provider = None;
                    }
                    if should_reapply_yielded_proxy_cleanup(
                        vpn_guard.is_yielded(),
                        forced_reconcile,
                    ) {
                        // A forced reconcile (e.g. WTS_SESSION_LOGON after boot-before-logon)
                        // may have just loaded an interactive user hive that still holds a
                        // stale shutdown AutoConfigURL; re-yield and flush DNS immediately.
                        let s = session.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            s.yield_for_vpn();
                            flush_dns_resolver_cache();
                        })
                        .await;
                        dns_flushed = true;
                    } else if !vpn_guard.is_yielded()
                        && (forced_reconcile
                            || last_proxy_reconcile.elapsed() >= PROXY_RECONCILE_INTERVAL)
                    {
                        let s = session.clone();
                        let _ = tokio::task::spawn_blocking(move || s.reconcile()).await;
                        last_proxy_reconcile = Instant::now();
                    }
                }
            }
            if power_or_unlock && !dns_flushed {
                let _ = tokio::task::spawn_blocking(flush_dns_resolver_cache).await;
            }
        }
    });

    let shutdown_ctx = ctx.clone();
    let server_task = tokio::spawn(serve_until_shutdown(bound, ctx, server_shutdown_rx));

    let reason = loop {
        if let Some(r) = *stop_rx.borrow() {
            break r;
        }
        if stop_rx.changed().await.is_err() {
            break StopReason::Stop;
        }
    };

    report_service_status(handle, SERVICE_STOP_PENDING, 0, NO_ERROR, 2, 5000);
    let _ = server_shutdown_tx.send(true);
    let _ = watchdog.await;
    clear_runtime_state(std::process::id());

    if should_deactivate_proxy_on_stop(reason) {
        if let Some(session) = proxy_session {
            let _ = tokio::task::spawn_blocking(move || session.deactivate()).await;
        }
    } else {
        info!(
            ?reason,
            "preserving Windows proxy settings across stop/upgrade"
        );
    }

    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
    if let Err(err) = shutdown_ctx.flush_persisted_cache().await {
        warn!(error = %err, "failed to flush adaptive cache on Windows proxy service shutdown");
    }
    Ok(())
}

fn should_trigger_power_resume_reconcile(event_type: Dword) -> bool {
    event_type == PBT_APMRESUMEAUTOMATIC || event_type == PBT_APMRESUMESUSPEND
}

#[repr(C)]
struct DeviceNotifySubscribeParameters {
    callback: unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> u32,
    context: *mut c_void,
}

type PowerRegisterSuspendResumeNotificationFn = unsafe extern "system" fn(
    flags: Dword,
    recipient: *mut c_void,
    registration_handle: *mut *mut c_void,
) -> Dword;

type PowerUnregisterSuspendResumeNotificationFn =
    unsafe extern "system" fn(registration_handle: *mut c_void) -> Dword;

unsafe extern "system" fn power_suspend_resume_callback(
    _context: *mut c_void,
    event_type: Dword,
    _setting: *mut c_void,
) -> u32 {
    if should_trigger_power_resume_reconcile(event_type) {
        trigger_reconcile(RECONCILE_EVENT_POWER_RESUME);
    }
    NO_ERROR
}

struct SuspendResumeNotificationGuard {
    hmod: HMODULE,
    reg_handle: *mut c_void,
    unregister_fn: PowerUnregisterSuspendResumeNotificationFn,
}

// Safety: `HMODULE` and `HPOWERNOTIFY` are process-global Win32 handles that can be
// unregistered and freed safely when the service runtime stops.
unsafe impl Send for SuspendResumeNotificationGuard {}

impl SuspendResumeNotificationGuard {
    fn register() -> Option<Self> {
        let dll_wide = to_wide_null("powrprof.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                dll_wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if hmod.is_null() {
            warn!("could not load powrprof.dll for Modern Standby wake notifications");
            return None;
        }

        let register_proc = unsafe {
            GetProcAddress(
                hmod,
                c"PowerRegisterSuspendResumeNotification"
                    .as_ptr()
                    .cast::<u8>(),
            )
        };
        let unregister_proc = unsafe {
            GetProcAddress(
                hmod,
                c"PowerUnregisterSuspendResumeNotification"
                    .as_ptr()
                    .cast::<u8>(),
            )
        };
        let (Some(register_proc), Some(unregister_proc)) = (register_proc, unregister_proc) else {
            warn!(
                "powrprof.dll missing PowerRegisterSuspendResumeNotification exports; \
                 relying on SERVICE_ACCEPT_POWEREVENT only"
            );
            unsafe {
                let _ = FreeLibrary(hmod);
            }
            return None;
        };

        let register_fn: PowerRegisterSuspendResumeNotificationFn =
            unsafe { std::mem::transmute_copy(&register_proc) };
        let unregister_fn: PowerUnregisterSuspendResumeNotificationFn =
            unsafe { std::mem::transmute_copy(&unregister_proc) };

        let mut params = DeviceNotifySubscribeParameters {
            callback: power_suspend_resume_callback,
            context: ptr::null_mut(),
        };
        let mut reg_handle: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            register_fn(
                DEVICE_NOTIFY_CALLBACK,
                (&mut params as *mut DeviceNotifySubscribeParameters).cast::<c_void>(),
                &mut reg_handle,
            )
        };
        if rc != NO_ERROR || reg_handle.is_null() {
            warn!(
                error = rc,
                "PowerRegisterSuspendResumeNotification failed; relying on SERVICE_ACCEPT_POWEREVENT only"
            );
            unsafe {
                let _ = FreeLibrary(hmod);
            }
            return None;
        }

        info!("registered Modern Standby (S0ix) power suspend/resume notification");
        Some(Self {
            hmod,
            reg_handle,
            unregister_fn,
        })
    }
}

impl Drop for SuspendResumeNotificationGuard {
    fn drop(&mut self) {
        let mut unregistered = true;
        if !self.reg_handle.is_null() {
            let rc = unsafe { (self.unregister_fn)(self.reg_handle) };
            if rc != NO_ERROR {
                warn!(
                    error = rc,
                    "PowerUnregisterSuspendResumeNotification failed"
                );
                unregistered = false;
            }
            self.reg_handle = ptr::null_mut();
        }
        if unregistered && !self.hmod.is_null() {
            unsafe {
                let _ = FreeLibrary(self.hmod);
            }
            self.hmod = ptr::null_mut();
        }
    }
}

fn trigger_reconcile(event_bits: u32) {
    if let Some(lock) = CONTROL_CHANNELS.get() {
        if let Some(ref ch) = *lock.lock().unwrap_or_else(|e| e.into_inner()) {
            ch.reconcile_events.fetch_or(event_bits, Ordering::SeqCst);
            ch.reconcile_tx.send_modify(|n| *n = n.wrapping_add(1));
        }
    }
}

unsafe extern "system" fn service_control_handler(
    control: Dword,
    event_type: Dword,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> Dword {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_UPGRADE_STOP => {
            let handle = SERVICE_STATUS_HANDLE.load(Ordering::SeqCst);
            if !handle.is_null() {
                report_service_status(handle, SERVICE_STOP_PENDING, 0, NO_ERROR, 1, 5000);
            }
            let reason = match control {
                SERVICE_CONTROL_SHUTDOWN => StopReason::Shutdown,
                SERVICE_CONTROL_UPGRADE_STOP => StopReason::Upgrade,
                _ => StopReason::Stop,
            };
            if let Some(lock) = CONTROL_CHANNELS.get() {
                if let Some(ref ch) = *lock.lock().unwrap_or_else(|e| e.into_inner()) {
                    let _ = ch.stop_tx.send(Some(reason));
                }
            }
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event_type == WTS_SESSION_LOGON {
                trigger_reconcile(RECONCILE_EVENT_SESSION_LOGON);
            } else if event_type == WTS_SESSION_UNLOCK {
                trigger_reconcile(RECONCILE_EVENT_SESSION_UNLOCK);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_POWEREVENT => {
            if should_trigger_power_resume_reconcile(event_type) {
                trigger_reconcile(RECONCILE_EVENT_POWER_RESUME);
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

fn report_service_status(
    handle: ServiceStatusHandle,
    current_state: Dword,
    controls_accepted: Dword,
    win32_exit_code: Dword,
    check_point: Dword,
    wait_hint: Dword,
) {
    let status = ServiceStatus {
        dw_service_type: SERVICE_WIN32_OWN_PROCESS,
        dw_current_state: current_state,
        dw_controls_accepted: controls_accepted,
        dw_win32_exit_code: win32_exit_code,
        dw_service_specific_exit_code: 0,
        dw_check_point: check_point,
        dw_wait_hint: wait_hint,
    };
    unsafe {
        let _ = SetServiceStatus(handle, &status);
    }
}

/// Stops the `vdpi` Windows service if it is currently installed and running.
/// Returns `Ok(true)` if the service existed, `Ok(false)` if not installed.
pub fn stop_windows_service_if_running() -> Result<bool> {
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name_wide = to_wide_null(SERVICE_NAME);
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            name_wide.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS,
        )
    };
    if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        if err == ERROR_ACCESS_DENIED {
            bail!(
                "Administrator privileges are required to stop the '{SERVICE_NAME}' Windows service. \
                 Please accept the UAC prompt or run from an elevated Administrator terminal."
            );
        }
        bail!("OpenServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
    }
    let svc = ScmHandle(raw);
    stop_service_handle(svc.0)?;
    thread::sleep(Duration::from_millis(150));
    Ok(true)
}

/// Stops the `vdpi` Windows service for an in-place upgrade using custom control code
/// `SERVICE_CONTROL_UPGRADE_STOP (128)` so proxy-mode user environment variables stay
/// intact across `vdpi update`, falling back to `SERVICE_CONTROL_STOP` if an older
/// v0.4.x service rejects custom control 128 (`ERROR_INVALID_SERVICE_CONTROL` /
/// `ERROR_CALL_NOT_IMPLEMENTED`).
/// Returns `Ok(true)` if the service existed, `Ok(false)` if not installed.
pub fn stop_windows_service_for_upgrade() -> Result<bool> {
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name_wide = to_wide_null(SERVICE_NAME);
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            name_wide.as_ptr(),
            SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | SERVICE_QUERY_STATUS,
        )
    };
    if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        if err == ERROR_ACCESS_DENIED {
            bail!(
                "Administrator privileges are required to stop the '{SERVICE_NAME}' Windows service. \
                 Please accept the UAC prompt or run from an elevated Administrator terminal."
            );
        }
        bail!("OpenServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
    }
    let svc = ScmHandle(raw);
    stop_service_handle_with_mode(svc.0, true)?;
    thread::sleep(Duration::from_millis(150));
    Ok(true)
}

/// Starts the `vdpi` Windows service if it is currently installed and waits until it is `RUNNING`.
/// Returns `Ok(true)` if the service exists and is running, `Ok(false)` if not installed.
pub fn start_windows_service() -> Result<bool> {
    let scm = open_scm(SC_MANAGER_CONNECT)?;
    let name_wide = to_wide_null(SERVICE_NAME);
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            name_wide.as_ptr(),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )
    };
    if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        if err == ERROR_ACCESS_DENIED {
            bail!(
                "Administrator privileges are required to start the '{SERVICE_NAME}' Windows service. \
                 Please accept the UAC prompt or run from an elevated Administrator terminal."
            );
        }
        bail!("OpenServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
    }
    let svc = ScmHandle(raw);

    let current = query_service_status_process(svc.0)?;
    if current.dw_current_state == SERVICE_RUNNING {
        return Ok(true);
    }
    if current.dw_current_state == SERVICE_START_PENDING {
        wait_for_service_running(svc.0, Duration::from_secs(10))?;
        return Ok(true);
    }
    if current.dw_current_state == SERVICE_STOP_PENDING {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(100));
            let state = query_service_status_process(svc.0)?.dw_current_state;
            if state == SERVICE_RUNNING {
                return Ok(true);
            }
            if state == SERVICE_START_PENDING {
                wait_for_service_running(svc.0, Duration::from_secs(10))?;
                return Ok(true);
            }
            if state != SERVICE_STOP_PENDING {
                break;
            }
        }
    }

    let started = unsafe { StartServiceW(svc.0, 0, ptr::null()) };
    if started == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_ALREADY_RUNNING {
            bail!("StartServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
        }
    }

    wait_for_service_running(svc.0, Duration::from_secs(10))?;
    Ok(true)
}

/// Installs or updates the `vdpi` Windows service with `AUTO_START` (non-delayed),
/// `Tcpip`/`Nsi`/`Dnscache` dependencies, automatic crash recovery, and starts it immediately.
pub fn install_or_update_windows_service(bin_path_cmd: &str) -> Result<()> {
    install_or_update_windows_service_with_start(bin_path_cmd, true)
}

/// Installs or updates the `vdpi` Windows service with `AUTO_START` (non-delayed),
/// `Tcpip`/`Nsi`/`Dnscache` dependencies, and automatic crash recovery, starting it
/// only when `start_service` is `true`.
pub(crate) fn install_or_update_windows_service_with_start(
    bin_path_cmd: &str,
    start_service: bool,
) -> Result<()> {
    let scm = open_scm(SC_MANAGER_ALL_ACCESS)?;
    let name_wide = to_wide_null(SERVICE_NAME);
    let display_wide = to_wide_null(SERVICE_DISPLAY_NAME);
    let bin_wide = to_wide_null(bin_path_cmd);
    let deps_wide: Vec<u16> = SERVICE_DEPENDENCIES.encode_utf16().collect();

    let svc = {
        let existing = unsafe { OpenServiceW(scm.0, name_wide.as_ptr(), SERVICE_ALL_ACCESS) };
        if !existing.is_null() {
            let guard = ScmHandle(existing);
            stop_service_handle(guard.0)?;
            let changed = unsafe {
                ChangeServiceConfigW(
                    guard.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    bin_wide.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    deps_wide.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    display_wide.as_ptr(),
                )
            };
            if changed == 0 {
                let err = unsafe { GetLastError() };
                if err == ERROR_SERVICE_MARKED_FOR_DELETE {
                    drop(guard);
                    create_service_with_retry(
                        scm.0,
                        &name_wide,
                        &display_wide,
                        &bin_wide,
                        &deps_wide,
                    )?
                } else {
                    bail!("ChangeServiceConfigW failed with Win32 error {err}");
                }
            } else {
                guard
            }
        } else {
            let err = unsafe { GetLastError() };
            if err != ERROR_SERVICE_DOES_NOT_EXIST {
                bail!("OpenServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
            }
            create_service_with_retry(scm.0, &name_wide, &display_wide, &bin_wide, &deps_wide)?
        }
    };

    configure_service_metadata(svc.0);

    if start_service {
        let started = unsafe { StartServiceW(svc.0, 0, ptr::null()) };
        if started == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_SERVICE_ALREADY_RUNNING {
                bail!("StartServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
            }
        }

        wait_for_service_running(svc.0, Duration::from_secs(10))?;
    }
    Ok(())
}

/// Stops and removes the `vdpi` Windows service. Returns `Ok(true)` if a service was removed.
pub fn uninstall_windows_service() -> Result<bool> {
    let scm = open_scm(SC_MANAGER_ALL_ACCESS)?;
    let name_wide = to_wide_null(SERVICE_NAME);
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            name_wide.as_ptr(),
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
        )
    };
    if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(false);
        }
        bail!("OpenServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
    }
    let svc = ScmHandle(raw);

    stop_service_handle(svc.0)?;

    let deleted = unsafe { DeleteService(svc.0) };
    if deleted == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SERVICE_MARKED_FOR_DELETE {
            bail!("DeleteService('{SERVICE_NAME}') failed with Win32 error {err}");
        }
    }

    drop(svc);
    thread::sleep(Duration::from_millis(150));
    Ok(true)
}

/// Queries the status and configuration of the `vdpi` Windows service without requiring Admin rights.
pub fn query_windows_service_status() -> WindowsServiceInfo {
    let not_installed = WindowsServiceInfo {
        installed: false,
        state: "NOT INSTALLED",
        start_type: "N/A",
        pid: None,
        binary_path: None,
    };

    let Ok(scm) = open_scm(SC_MANAGER_CONNECT) else {
        return not_installed;
    };
    let name_wide = to_wide_null(SERVICE_NAME);
    let raw = unsafe {
        OpenServiceW(
            scm.0,
            name_wide.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        )
    };
    let (svc, can_query_config) = if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err != ERROR_ACCESS_DENIED {
            return not_installed;
        }
        let status_only = unsafe { OpenServiceW(scm.0, name_wide.as_ptr(), SERVICE_QUERY_STATUS) };
        if status_only.is_null() {
            let fallback_err = unsafe { GetLastError() };
            if fallback_err == ERROR_ACCESS_DENIED {
                return WindowsServiceInfo {
                    installed: true,
                    state: "UNKNOWN",
                    start_type: "UNKNOWN",
                    pid: None,
                    binary_path: None,
                };
            }
            return not_installed;
        }
        (ScmHandle(status_only), false)
    } else {
        (ScmHandle(raw), true)
    };

    let (state, pid) = match query_service_status_process(svc.0) {
        Ok(ssp) => (
            service_state_label(ssp.dw_current_state),
            if ssp.dw_process_id != 0 {
                Some(ssp.dw_process_id)
            } else {
                None
            },
        ),
        Err(_) => ("UNKNOWN", None),
    };

    let (start_type, binary_path) = if can_query_config {
        query_service_config(svc.0).unwrap_or(("UNKNOWN", None))
    } else {
        ("UNKNOWN", None)
    };

    WindowsServiceInfo {
        installed: true,
        state,
        start_type,
        pid,
        binary_path,
    }
}

fn open_scm(access: Dword) -> Result<ScmHandle> {
    let raw = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if raw.is_null() {
        let err = unsafe { GetLastError() };
        if err == ERROR_ACCESS_DENIED {
            bail!(
                "Administrator privileges are required to manage the '{SERVICE_NAME}' Windows service. \
                 Please accept the UAC prompt or open an elevated Administrator terminal."
            );
        }
        bail!("OpenSCManagerW failed with Win32 error {err}");
    }
    Ok(ScmHandle(raw))
}

fn create_service_with_retry(
    scm: ScHandle,
    name_wide: &[u16],
    display_wide: &[u16],
    bin_wide: &[u16],
    deps_wide: &[u16],
) -> Result<ScmHandle> {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let created = unsafe {
            CreateServiceW(
                scm,
                name_wide.as_ptr(),
                display_wide.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                bin_wide.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                deps_wide.as_ptr(),
                ptr::null(),
                ptr::null(),
            )
        };
        if !created.is_null() {
            return Ok(ScmHandle(created));
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_SERVICE_MARKED_FOR_DELETE && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        if err == ERROR_SERVICE_MARKED_FOR_DELETE {
            bail!(
                "Windows service '{SERVICE_NAME}' is marked for deletion. \
                 Close Services.msc or Task Manager and run install again."
            );
        }
        bail!("CreateServiceW('{SERVICE_NAME}') failed with Win32 error {err}");
    }
}

fn configure_service_metadata(svc: ScHandle) {
    let mut desc_wide = to_wide_null(SERVICE_DESCRIPTION);
    let desc = ServiceDescriptionW {
        lp_description: desc_wide.as_mut_ptr(),
    };
    unsafe {
        let _ = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_DESCRIPTION,
            (&desc as *const ServiceDescriptionW).cast::<c_void>(),
        );
    }

    let delayed = ServiceDelayedAutoStartInfo {
        f_delayed_autostart: 0,
    };
    unsafe {
        let _ = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            (&delayed as *const ServiceDelayedAutoStartInfo).cast::<c_void>(),
        );
    }

    let mut actions = [
        ScAction {
            action_type: SC_ACTION_RESTART,
            delay: 1000,
        },
        ScAction {
            action_type: SC_ACTION_RESTART,
            delay: 2000,
        },
        ScAction {
            action_type: SC_ACTION_RESTART,
            delay: 5000,
        },
    ];
    let failure = ServiceFailureActionsW {
        dw_reset_period: 86_400,
        lp_reboot_msg: ptr::null_mut(),
        lp_command: ptr::null_mut(),
        c_actions: actions.len() as Dword,
        lpsa_actions: actions.as_mut_ptr(),
    };
    unsafe {
        let _ = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&failure as *const ServiceFailureActionsW).cast::<c_void>(),
        );
    }
}

fn zero_service_status() -> ServiceStatus {
    ServiceStatus {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
    }
}

fn stop_service_handle(svc: ScHandle) -> Result<()> {
    stop_service_handle_with_mode(svc, false)
}

fn stop_service_handle_with_mode(svc: ScHandle, prefer_upgrade_control: bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stop_sent = false;
    let mut use_upgrade_control = prefer_upgrade_control;

    loop {
        let ssp = query_service_status_process(svc)?;
        if ssp.dw_current_state == SERVICE_STOPPED {
            return Ok(());
        }

        if !stop_sent
            && ssp.dw_current_state != SERVICE_START_PENDING
            && ssp.dw_current_state != SERVICE_STOP_PENDING
        {
            if use_upgrade_control {
                let mut status = zero_service_status();
                let ok = unsafe { ControlService(svc, SERVICE_CONTROL_UPGRADE_STOP, &mut status) };
                if ok != 0 {
                    if status.dw_current_state == SERVICE_STOPPED {
                        return Ok(());
                    }
                    stop_sent = true;
                } else {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_SERVICE_NOT_ACTIVE {
                        return Ok(());
                    }
                    if should_fallback_upgrade_control(err) {
                        use_upgrade_control = false;
                    } else if err != ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
                        bail!("ControlService(UPGRADE_STOP) failed with Win32 error {err}");
                    }
                }
            }

            if !stop_sent && !use_upgrade_control {
                let mut status = zero_service_status();
                let ok = unsafe { ControlService(svc, SERVICE_CONTROL_STOP, &mut status) };
                if ok != 0 {
                    if status.dw_current_state == SERVICE_STOPPED {
                        return Ok(());
                    }
                    stop_sent = true;
                } else {
                    let err = unsafe { GetLastError() };
                    if err == ERROR_SERVICE_NOT_ACTIVE {
                        return Ok(());
                    }
                    if err != ERROR_SERVICE_CANNOT_ACCEPT_CTRL {
                        bail!("ControlService(STOP) failed with Win32 error {err}");
                    }
                }
            }
        }

        if Instant::now() >= deadline {
            bail!("timed out waiting for Windows service '{SERVICE_NAME}' to stop");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_service_running(svc: ScHandle, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let ssp = query_service_status_process(svc)?;
        match ssp.dw_current_state {
            SERVICE_RUNNING => return Ok(()),
            SERVICE_STOPPED => {
                bail!(
                    "Windows service '{SERVICE_NAME}' stopped immediately after start (exit code {})",
                    ssp.dw_win32_exit_code
                );
            }
            _ => {
                if Instant::now() >= deadline {
                    bail!(
                        "timed out waiting for Windows service '{SERVICE_NAME}' to enter RUNNING state (current: {})",
                        service_state_label(ssp.dw_current_state)
                    );
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn query_service_status_process(svc: ScHandle) -> Result<ServiceStatusProcess> {
    let mut ssp = ServiceStatusProcess {
        dw_service_type: 0,
        dw_current_state: 0,
        dw_controls_accepted: 0,
        dw_win32_exit_code: 0,
        dw_service_specific_exit_code: 0,
        dw_check_point: 0,
        dw_wait_hint: 0,
        dw_process_id: 0,
        dw_service_flags: 0,
    };
    let mut bytes_needed: Dword = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            svc,
            SC_STATUS_PROCESS_INFO,
            (&mut ssp as *mut ServiceStatusProcess).cast::<u8>(),
            std::mem::size_of::<ServiceStatusProcess>() as Dword,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        bail!("QueryServiceStatusEx failed with Win32 error {err}");
    }
    Ok(ssp)
}

fn query_service_config(svc: ScHandle) -> Option<(&'static str, Option<String>)> {
    let mut bytes_needed: Dword = 0;
    unsafe {
        let _ = QueryServiceConfigW(svc, ptr::null_mut(), 0, &mut bytes_needed);
    }
    if bytes_needed == 0 {
        return None;
    }

    let word_len = (bytes_needed as usize).div_ceil(std::mem::size_of::<u64>());
    let mut aligned_buf = vec![0u64; word_len];
    let ok = unsafe {
        QueryServiceConfigW(
            svc,
            aligned_buf.as_mut_ptr().cast::<u8>(),
            (aligned_buf.len() * std::mem::size_of::<u64>()) as Dword,
            &mut bytes_needed,
        )
    };
    if ok == 0 {
        return None;
    }

    let cfg = unsafe { &*(aligned_buf.as_ptr().cast::<QueryServiceConfigW>()) };
    let start_type = match cfg.dw_start_type {
        SERVICE_AUTO_START => "AUTO_START",
        SERVICE_DEMAND_START => "DEMAND_START",
        SERVICE_DISABLED => "DISABLED",
        _ => "OTHER",
    };
    let bin_path = unsafe { wide_ptr_to_string(cfg.lp_binary_path_name) };
    Some((start_type, bin_path))
}

fn service_state_label(state: Dword) -> &'static str {
    match state {
        SERVICE_STOPPED => "STOPPED",
        SERVICE_START_PENDING => "START_PENDING",
        SERVICE_STOP_PENDING => "STOP_PENDING",
        SERVICE_RUNNING => "RUNNING",
        SERVICE_CONTINUE_PENDING => "CONTINUE_PENDING",
        SERVICE_PAUSE_PENDING => "PAUSE_PENDING",
        SERVICE_PAUSED => "PAUSED",
        _ => "UNKNOWN",
    }
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

unsafe fn wide_ptr_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    Some(String::from_utf16_lossy(slice))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_control_constants_and_dependencies_match_win32_spec() {
        assert_eq!(SERVICE_CONTROL_UPGRADE_STOP, 128);
        assert_eq!(SERVICE_CONTROL_POWEREVENT, 0x0000_000D);
        assert_eq!(SERVICE_ACCEPT_POWEREVENT, 0x0000_0040);
        assert_eq!(PBT_APMRESUMESUSPEND, 0x0007);
        assert_eq!(PBT_APMRESUMEAUTOMATIC, 0x0012);
        assert_ne!(SERVICE_ACCEPTED_CONTROLS & SERVICE_ACCEPT_STOP, 0);
        assert_ne!(SERVICE_ACCEPTED_CONTROLS & SERVICE_ACCEPT_SHUTDOWN, 0);
        assert_ne!(SERVICE_ACCEPTED_CONTROLS & SERVICE_ACCEPT_SESSIONCHANGE, 0);
        assert_ne!(SERVICE_ACCEPTED_CONTROLS & SERVICE_ACCEPT_POWEREVENT, 0);

        assert_eq!(SERVICE_DEPENDENCIES, "Tcpip\0Nsi\0Dnscache\0\0");
        let deps_wide: Vec<u16> = SERVICE_DEPENDENCIES.encode_utf16().collect();
        assert!(deps_wide.ends_with(&[0, 0]));
    }

    #[test]
    fn proxy_stop_deactivation_and_upgrade_fallback_rules() {
        assert!(should_deactivate_proxy_on_stop(StopReason::Stop));
        assert!(!should_deactivate_proxy_on_stop(StopReason::Shutdown));
        assert!(!should_deactivate_proxy_on_stop(StopReason::Upgrade));

        assert!(should_fallback_upgrade_control(
            ERROR_INVALID_SERVICE_CONTROL
        ));
        assert!(should_fallback_upgrade_control(ERROR_CALL_NOT_IMPLEMENTED));
        assert!(!should_fallback_upgrade_control(ERROR_ACCESS_DENIED));
        assert!(!should_fallback_upgrade_control(
            ERROR_SERVICE_CANNOT_ACCEPT_CTRL
        ));
    }

    #[test]
    fn windows_service_cache_path_lives_under_vdpi_adaptive_cache_json() {
        let path = windows_service_cache_path();
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("adaptive-cache.json")
        );
        assert_eq!(
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str()),
            Some("vdpi")
        );
    }

    #[test]
    fn service_runtime_thread_caps_and_reconcile_intervals_are_bounded() {
        let workers = service_tokio_worker_threads();
        assert!((2..=4).contains(&workers));
        assert_eq!(SERVICE_MAX_BLOCKING_THREADS, 16);

        assert_eq!(tun_reconcile_interval(true, false), Duration::from_secs(3));
        assert_eq!(tun_reconcile_interval(true, true), Duration::from_secs(1));
        assert_eq!(tun_reconcile_interval(false, false), Duration::from_secs(1));
        assert_eq!(tun_reconcile_interval(false, true), Duration::from_secs(1));

        assert_eq!(proxy_vpn_poll_interval(false), Duration::from_secs(3));
        assert_eq!(proxy_vpn_poll_interval(true), Duration::from_secs(1));
    }

    #[test]
    fn transient_offline_tun_errors_and_health_dns_redaction_behave_as_expected() {
        let offline = anyhow::anyhow!(
            "no active physical network uplink detected; connect to Wi-Fi or Ethernet and retry"
        );
        assert!(is_transient_offline_tun_error(&offline));
        let fatal = anyhow::anyhow!("WintunCreateAdapter failed with access denied");
        assert!(!is_transient_offline_tun_error(&fatal));

        assert_eq!(redact_dns_addr_for_health("   "), None);
        assert_eq!(
            redact_dns_addr_for_health("1.1.1.1").as_deref(),
            Some("1.1.1.1")
        );
        assert_eq!(
            redact_dns_addr_for_health("https://dns.nextdns.io/abc123/my-device").as_deref(),
            Some("https://dns.nextdns.io")
        );
        assert_eq!(
            redact_dns_addr_for_health("HTTPS://user:secret@dns.example.com:8443/token?k=v")
                .as_deref(),
            Some("https://dns.example.com:8443")
        );
    }

    #[test]
    fn elevated_child_exit_treats_user_close_as_ok_and_formats_failures() {
        assert_eq!(STATUS_CONTROL_C_EXIT, 0xC000_013A);
        assert_eq!(DBG_TERMINATE_PROCESS, 0x4001_0004);

        assert!(classify_elevated_child_exit(0).is_ok());
        assert!(classify_elevated_child_exit(STATUS_CONTROL_C_EXIT).is_ok());
        assert!(classify_elevated_child_exit(DBG_TERMINATE_PROCESS).is_ok());

        let err_small = classify_elevated_child_exit(1).unwrap_err().to_string();
        assert!(err_small.contains("exit code 1"));
        assert!(err_small.contains("Administrator terminal"));

        let err_ntstatus = classify_elevated_child_exit(0xC000_0135)
            .unwrap_err()
            .to_string();
        assert!(err_ntstatus.contains("0xC0000135"));
        assert!(err_ntstatus.contains("Administrator terminal"));
    }

    #[test]
    fn tun_service_config_and_modern_standby_power_helpers_match_spec() {
        let cfg_v4 = normalize_tun_service_config(RuntimeConfig {
            tun_ipv6: false,
            dns_ipv4_only: false,
            ..RuntimeConfig::default()
        });
        assert!(cfg_v4.dns_ipv4_only);

        let cfg_v6 = normalize_tun_service_config(RuntimeConfig {
            tun_ipv6: true,
            dns_ipv4_only: false,
            ..RuntimeConfig::default()
        });
        assert!(!cfg_v6.dns_ipv4_only);

        assert_eq!(DEVICE_NOTIFY_CALLBACK, 2);
        assert!(should_trigger_power_resume_reconcile(
            PBT_APMRESUMEAUTOMATIC
        ));
        assert!(should_trigger_power_resume_reconcile(PBT_APMRESUMESUSPEND));
        assert!(!should_trigger_power_resume_reconcile(0x0004));
        assert!(!should_trigger_power_resume_reconcile(0));
    }

    #[test]
    fn yielded_proxy_reapplies_cleanup_only_on_forced_reconcile() {
        assert!(should_reapply_yielded_proxy_cleanup(true, true));
        assert!(!should_reapply_yielded_proxy_cleanup(true, false));
        assert!(!should_reapply_yielded_proxy_cleanup(false, true));
        assert!(!should_reapply_yielded_proxy_cleanup(false, false));
    }

    #[test]
    fn effective_tun_dns_ipv4_only_preserves_explicit_flag_and_tracks_ipv6() {
        // Explicit `--ipv4-only` is never overridden even when IPv6 TUN is active.
        assert!(effective_tun_dns_ipv4_only(true, true));
        assert!(effective_tun_dns_ipv4_only(true, false));
        // Without explicit `--ipv4-only`, follow `!is_ipv6_active()`.
        assert!(effective_tun_dns_ipv4_only(false, false));
        assert!(!effective_tun_dns_ipv4_only(false, true));
    }

    #[tokio::test]
    async fn sync_tun_dns_ipv4_only_clears_and_flushes_only_on_change() {
        let ctx = EngineContext::new(RuntimeConfig {
            tun_ipv6: false,
            dns_ipv4_only: true,
            ..RuntimeConfig::default()
        })
        .expect("EngineContext::new should succeed for default config");
        assert!(ctx.dns.is_ipv4_only());

        // Stopped TUN slot must not mutate DNS filtering or flush OS cache.
        let flushes = Arc::new(AtomicU32::new(0));
        let flushes_clone = Arc::clone(&flushes);
        let changed = sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            false,
            false,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 0);

        // No-op when effective ipv4_only matches current state (true -> true).
        let flushes_clone = Arc::clone(&flushes);
        let changed = sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            false,
            false,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 0);

        // Transition true -> false (e.g. IPv4-only Wi-Fi to IPv6-only cellular):
        // must flip ipv4_only BEFORE flushing Windows Dnscache.
        let flushes_clone = Arc::clone(&flushes);
        let ipv4_only_seen_at_flush = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let ipv4_only_seen_clone = Arc::clone(&ipv4_only_seen_at_flush);
        let dns_ref = &ctx.dns;
        let changed = sync_tun_dns_ipv4_only_if_changed(
            dns_ref,
            true,
            false,
            true,
            move || async move {
                ipv4_only_seen_clone.store(dns_ref.is_ipv4_only(), Ordering::SeqCst);
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(changed);
        assert!(!ctx.dns.is_ipv4_only());
        assert!(!ipv4_only_seen_at_flush.load(Ordering::SeqCst));
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        // Repeated route notification with the same IPv6 state must not re-flush.
        let flushes_clone = Arc::clone(&flushes);
        let changed = sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            false,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(!ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 1);

        // Transition false -> true (e.g. IPv6-only back to IPv4-only / dual-stack with !tun_ipv6):
        // must flip back to ipv4_only=true before flushing OS cache again.
        let flushes_clone = Arc::clone(&flushes);
        let ipv4_only_seen_at_flush = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ipv4_only_seen_clone = Arc::clone(&ipv4_only_seen_at_flush);
        let dns_ref = &ctx.dns;
        let changed = sync_tun_dns_ipv4_only_if_changed(
            dns_ref,
            true,
            false,
            false,
            move || async move {
                ipv4_only_seen_clone.store(dns_ref.is_ipv4_only(), Ordering::SeqCst);
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(changed);
        assert!(ctx.dns.is_ipv4_only());
        assert!(ipv4_only_seen_at_flush.load(Ordering::SeqCst));
        assert_eq!(flushes.load(Ordering::SeqCst), 2);

        // Explicit --ipv4-only stays true even when IPv6 TUN is active; no flush.
        let flushes_clone = Arc::clone(&flushes);
        let changed = sync_tun_dns_ipv4_only_if_changed(
            &ctx.dns,
            true,
            true,
            true,
            move || async move {
                flushes_clone.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
        assert!(!changed);
        assert!(ctx.dns.is_ipv4_only());
        assert_eq!(flushes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn offline_standby_log_deduplicates_repeated_uplink_errors() {
        let offline = anyhow::anyhow!(
            "no active physical network uplink detected; connect to Wi-Fi or Ethernet and retry"
        );
        let other = anyhow::anyhow!("WintunCreateAdapter failed with access denied");
        let mut logged = false;

        assert_eq!(
            classify_tun_start_error_log(&mut logged, &offline),
            TunStartErrorLogAction::LogOfflineStandby
        );
        assert!(logged);

        assert_eq!(
            classify_tun_start_error_log(&mut logged, &offline),
            TunStartErrorLogAction::SuppressOfflineStandby
        );
        assert!(logged);

        assert_eq!(
            classify_tun_start_error_log(&mut logged, &other),
            TunStartErrorLogAction::LogRetryableError
        );
        assert!(!logged);

        assert_eq!(
            classify_tun_start_error_log(&mut logged, &offline),
            TunStartErrorLogAction::LogOfflineStandby
        );
        assert!(logged);
    }
}
