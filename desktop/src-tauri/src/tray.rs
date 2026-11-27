#[cfg(any(target_os = "linux", test))]
use std::io::Read;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread::ThreadId;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use tauri::image::Image;
use tauri::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};
use tracing::{debug, error, warn};

use crate::models::{DesktopStatusSnapshotDto, EngineModeDto, GuiPreferencesDto, ServiceStateDto};
use crate::state::DesktopAppState;

/// Stable Tauri identifier for the vdpi system tray / menu bar icon.
pub const TRAY_ID: &str = "vdpi-tray";

/// Label of the primary desktop window declared in `tauri.conf.json`.
pub const MAIN_WINDOW_LABEL: &str = "main";

/// Tray context menu item identifiers.
pub const MENU_SHOW_ID: &str = "tray-show";
pub const MENU_STATUS_ID: &str = "tray-status";
pub const MENU_TOGGLE_PROTECTION_ID: &str = "tray-toggle-protection";
pub const MENU_QUIT_ID: &str = "tray-quit";

const ICON_PROTECTED_BYTES: &[u8] = include_bytes!("../icons/tray-protected.png");
const ICON_WARNING_BYTES: &[u8] = include_bytes!("../icons/tray-warning.png");
const ICON_PAUSED_BYTES: &[u8] = include_bytes!("../icons/tray-paused.png");

const RESTORE_GUARD_WINDOW: Duration = Duration::from_millis(350);
const TRAY_SYNC_TIMEOUT: Duration = Duration::from_secs(10);

static ICON_PROTECTED: OnceLock<Option<Image<'static>>> = OnceLock::new();
static ICON_WARNING: OnceLock<Option<Image<'static>>> = OnceLock::new();
static ICON_PAUSED: OnceLock<Option<Image<'static>>> = OnceLock::new();

static MENU_EVENT_HANDLER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Thread ID of the Tauri main event loop thread so OS tray mutations run
/// directly when already on the main thread and dispatch via
/// `app.run_on_main_thread` otherwise (avoiding cross-thread OS locks).
static MAIN_THREAD_ID: OnceLock<ThreadId> = OnceLock::new();

/// Pure in-memory runtime state for tray visuals and menu handles.
/// Never held across Tauri/OS calls.
static TRAY_STATE: Mutex<TrayRuntimeState> = Mutex::new(TrayRuntimeState::new());

#[cfg(target_os = "linux")]
const LINUX_TRAY_PROBE_TIMEOUT: Duration = Duration::from_millis(1_000);
#[cfg(target_os = "linux")]
const LINUX_TRAY_CACHE_TTL: Duration = Duration::from_secs(10);
#[cfg(any(target_os = "linux", test))]
const LINUX_TRAY_PROBE_MAX_STDOUT_BYTES: u64 = 4096;
#[cfg(any(target_os = "linux", test))]
const LINUX_PROBE_STRIPPED_ENV_VARS: [&str; 10] = [
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "LD_AUDIT",
    "APPDIR",
    "APPIMAGE",
    "GTK_PATH",
    "GIO_EXTRA_MODULES",
    "GIO_MODULE_DIR",
    "GDK_PIXBUF_MODULE_FILE",
    "GTK_IM_MODULE_FILE",
];
#[cfg(any(target_os = "linux", test))]
const LINUX_BUSCTL_PATHS: [&str; 2] = ["/usr/bin/busctl", "/bin/busctl"];
#[cfg(any(target_os = "linux", test))]
const LINUX_GDBUS_PATHS: [&str; 2] = ["/usr/bin/gdbus", "/bin/gdbus"];
#[cfg(any(target_os = "linux", test))]
const LINUX_DBUS_SEND_PATHS: [&str; 2] = ["/usr/bin/dbus-send", "/bin/dbus-send"];
#[cfg(target_os = "linux")]
static LINUX_TRAY_HOST_CACHE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

/// Records the calling thread as the Tauri main event loop thread.
///
/// Must be called once at the top of `tauri::Builder::setup` so off-thread
/// callers always dispatch OS tray mutations via `app.run_on_main_thread`.
pub fn record_main_thread() {
    let _ = MAIN_THREAD_ID.set(std::thread::current().id());
}

fn is_on_main_thread() -> bool {
    MAIN_THREAD_ID
        .get()
        .is_some_and(|id| *id == std::thread::current().id())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrayIconKind {
    Protected,
    Warning,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectionToggleAction {
    Pause,
    Resume,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrayVisualSpec {
    icon: TrayIconKind,
    status_label: &'static str,
    toggle_label: &'static str,
    toggle_enabled: bool,
    toggle_action: ProtectionToggleAction,
    tooltip: &'static str,
}

impl TrayVisualSpec {
    const fn checking() -> Self {
        Self {
            icon: TrayIconKind::Paused,
            status_label: "Status: Checking...",
            toggle_label: "Pause Protection",
            toggle_enabled: false,
            toggle_action: ProtectionToggleAction::Pause,
            tooltip: "vdpi - Checking status...",
        }
    }

    #[cfg(test)]
    fn from_option(status: Option<&DesktopStatusSnapshotDto>) -> Self {
        match status {
            Some(snapshot) => Self::from_snapshot(snapshot),
            None => Self::checking(),
        }
    }

    fn from_snapshot(status: &DesktopStatusSnapshotDto) -> Self {
        let is_live_running = status.live.as_ref().is_some_and(|live| live.running);
        let is_running = status.service_state == ServiceStateDto::Running || is_live_running;

        let active_engine = status
            .live
            .as_ref()
            .filter(|live| live.running)
            .map(|live| live.engine)
            .unwrap_or(status.configured_engine);

        let has_vpn_conflict = status
            .vpn_conflict
            .as_deref()
            .is_some_and(|msg| !msg.trim().is_empty())
            || status
                .live
                .as_ref()
                .and_then(|live| live.vpn_conflict.as_deref())
                .is_some_and(|msg| !msg.trim().is_empty());

        let has_wintun_issue = status.wintun.required && !status.wintun.ready;

        if is_running {
            if has_vpn_conflict {
                let (status_label, tooltip) = match active_engine {
                    EngineModeDto::Tun => (
                        "Status: VPN Conflict (TUN)",
                        "vdpi - VPN conflict detected (TUN)",
                    ),
                    EngineModeDto::Proxy => (
                        "Status: VPN Conflict (Proxy)",
                        "vdpi - VPN conflict detected (Proxy)",
                    ),
                };
                return Self {
                    icon: TrayIconKind::Warning,
                    status_label,
                    toggle_label: "Pause Protection",
                    toggle_enabled: true,
                    toggle_action: ProtectionToggleAction::Pause,
                    tooltip,
                };
            }

            if has_wintun_issue && active_engine == EngineModeDto::Tun {
                return Self {
                    icon: TrayIconKind::Warning,
                    status_label: "Status: Wintun Required (TUN)",
                    toggle_label: "Pause Protection",
                    toggle_enabled: true,
                    toggle_action: ProtectionToggleAction::Pause,
                    tooltip: "vdpi - Wintun driver required (TUN)",
                };
            }

            if !is_live_running {
                let (status_label, tooltip) = match active_engine {
                    EngineModeDto::Tun => (
                        "Status: Degraded (TUN)",
                        "vdpi - Service starting or degraded (TUN)",
                    ),
                    EngineModeDto::Proxy => (
                        "Status: Degraded (Proxy)",
                        "vdpi - Service starting or degraded (Proxy)",
                    ),
                };
                return Self {
                    icon: TrayIconKind::Warning,
                    status_label,
                    toggle_label: "Pause Protection",
                    toggle_enabled: true,
                    toggle_action: ProtectionToggleAction::Pause,
                    tooltip,
                };
            }

            let (status_label, tooltip) = match active_engine {
                EngineModeDto::Tun => ("Status: Protected (TUN)", "vdpi - Protected (TUN)"),
                EngineModeDto::Proxy => ("Status: Protected (Proxy)", "vdpi - Protected (Proxy)"),
            };
            return Self {
                icon: TrayIconKind::Protected,
                status_label,
                toggle_label: "Pause Protection",
                toggle_enabled: true,
                toggle_action: ProtectionToggleAction::Pause,
                tooltip,
            };
        }

        match status.service_state {
            ServiceStateDto::NotInstalled => Self {
                icon: TrayIconKind::Paused,
                status_label: "Status: Not Installed",
                toggle_label: "Resume Protection",
                toggle_enabled: false,
                toggle_action: ProtectionToggleAction::Resume,
                tooltip: "vdpi - Service not installed",
            },
            ServiceStateDto::Stopped | ServiceStateDto::Running => {
                if has_vpn_conflict {
                    Self {
                        icon: TrayIconKind::Warning,
                        status_label: "Status: Paused (VPN Active)",
                        toggle_label: "Resume Protection",
                        toggle_enabled: true,
                        toggle_action: ProtectionToggleAction::Resume,
                        tooltip: "vdpi - Paused while VPN is active",
                    }
                } else {
                    Self {
                        icon: TrayIconKind::Paused,
                        status_label: "Status: Paused",
                        toggle_label: "Resume Protection",
                        toggle_enabled: true,
                        toggle_action: ProtectionToggleAction::Resume,
                        tooltip: "vdpi - Protection paused",
                    }
                }
            }
        }
    }

    const fn with_toggle_busy(mut self, busy: bool) -> Self {
        if busy {
            self.toggle_label = if !self.toggle_enabled {
                "Updating Protection..."
            } else {
                match self.toggle_action {
                    ProtectionToggleAction::Pause => "Pausing Protection...",
                    ProtectionToggleAction::Resume => "Resuming Protection...",
                }
            };
            self.toggle_enabled = false;
        }
        self
    }
}

/// Tracks each OS tray visual property independently so partial OS failures
/// never mark failed fields as committed and are retried on subsequent updates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AppliedTrayVisual {
    icon: Option<TrayIconKind>,
    tooltip: Option<&'static str>,
    status_label: Option<&'static str>,
    toggle_label: Option<&'static str>,
    toggle_enabled: Option<bool>,
}

impl AppliedTrayVisual {
    const fn empty() -> Self {
        Self {
            icon: None,
            tooltip: None,
            status_label: None,
            toggle_label: None,
            toggle_enabled: None,
        }
    }

    const fn from_build(spec: TrayVisualSpec, has_icon: bool) -> Self {
        Self {
            icon: if has_icon { Some(spec.icon) } else { None },
            tooltip: Some(spec.tooltip),
            status_label: Some(spec.status_label),
            toggle_label: Some(spec.toggle_label),
            toggle_enabled: Some(spec.toggle_enabled),
        }
    }

    fn matches(&self, spec: TrayVisualSpec) -> bool {
        self.icon == Some(spec.icon)
            && self.tooltip == Some(spec.tooltip)
            && self.status_label == Some(spec.status_label)
            && self.toggle_label == Some(spec.toggle_label)
            && self.toggle_enabled == Some(spec.toggle_enabled)
    }
}

struct TrayRuntimeState {
    status_item: Option<MenuItem<Wry>>,
    toggle_item: Option<MenuItem<Wry>>,
    base_visual: Option<TrayVisualSpec>,
    last_visual: AppliedTrayVisual,
    last_snapshot_seq: u64,
    tray_generation: u64,
    toggle_busy: bool,
}

impl TrayRuntimeState {
    const fn new() -> Self {
        Self {
            status_item: None,
            toggle_item: None,
            base_visual: None,
            last_visual: AppliedTrayVisual::empty(),
            last_snapshot_seq: 0,
            tray_generation: 0,
            toggle_busy: false,
        }
    }

    fn accept_snapshot(&mut self, snapshot_seq: u64, base_spec: TrayVisualSpec) -> bool {
        if snapshot_seq > 0 && snapshot_seq < self.last_snapshot_seq {
            return false;
        }
        if snapshot_seq > self.last_snapshot_seq {
            self.last_snapshot_seq = snapshot_seq;
        }
        self.base_visual = Some(base_spec);
        true
    }

    fn should_dispatch_snapshot(&mut self, snapshot_seq: u64, base_spec: TrayVisualSpec) -> bool {
        if !self.accept_snapshot(snapshot_seq, base_spec) {
            return false;
        }
        !self
            .last_visual
            .matches(base_spec.with_toggle_busy(self.toggle_busy))
    }

    fn try_claim_toggle_busy(&mut self) -> bool {
        if self.toggle_busy {
            return false;
        }
        self.toggle_busy = true;
        true
    }
}

trait TrayVisualSink {
    fn set_icon(&mut self, kind: TrayIconKind) -> bool;
    fn set_tooltip(&mut self, tooltip: &'static str) -> bool;
    fn set_status_label(&mut self, label: &'static str) -> bool;
    fn set_toggle_label(&mut self, label: &'static str) -> bool;
    fn set_toggle_enabled(&mut self, enabled: bool) -> bool;
}

struct TauriTraySink<'a> {
    tray: &'a TrayIcon<Wry>,
    status_item: Option<&'a MenuItem<Wry>>,
    toggle_item: Option<&'a MenuItem<Wry>>,
}

impl TrayVisualSink for TauriTraySink<'_> {
    fn set_icon(&mut self, kind: TrayIconKind) -> bool {
        let Some(icon) = cached_tray_icon(kind) else {
            return false;
        };
        match self.tray.set_icon(Some(icon)) {
            Ok(()) => true,
            Err(err) => {
                warn!(error = %err, "failed to update tray icon");
                false
            }
        }
    }

    fn set_tooltip(&mut self, tooltip: &'static str) -> bool {
        match self.tray.set_tooltip(Some(tooltip)) {
            Ok(()) => true,
            Err(err) => {
                debug!(error = %err, "failed to update tray tooltip");
                false
            }
        }
    }

    fn set_status_label(&mut self, label: &'static str) -> bool {
        let Some(item) = self.status_item else {
            return false;
        };
        match item.set_text(label) {
            Ok(()) => true,
            Err(err) => {
                warn!(error = %err, "failed to update tray status menu label");
                false
            }
        }
    }

    fn set_toggle_label(&mut self, label: &'static str) -> bool {
        let Some(item) = self.toggle_item else {
            return false;
        };
        match item.set_text(label) {
            Ok(()) => true,
            Err(err) => {
                warn!(error = %err, "failed to update tray protection toggle label");
                false
            }
        }
    }

    fn set_toggle_enabled(&mut self, enabled: bool) -> bool {
        let Some(item) = self.toggle_item else {
            return false;
        };
        match item.set_enabled(enabled) {
            Ok(()) => true,
            Err(err) => {
                warn!(error = %err, "failed to update tray protection toggle enabled state");
                false
            }
        }
    }
}

fn sync_visual_fields<S: TrayVisualSink>(
    committed: &mut AppliedTrayVisual,
    spec: TrayVisualSpec,
    sink: &mut S,
) {
    if committed.matches(spec) {
        return;
    }

    if committed.icon != Some(spec.icon) && sink.set_icon(spec.icon) {
        committed.icon = Some(spec.icon);
    }

    if committed.tooltip != Some(spec.tooltip) && sink.set_tooltip(spec.tooltip) {
        committed.tooltip = Some(spec.tooltip);
    }

    if committed.status_label != Some(spec.status_label) && sink.set_status_label(spec.status_label)
    {
        committed.status_label = Some(spec.status_label);
    }

    if committed.toggle_label != Some(spec.toggle_label) && sink.set_toggle_label(spec.toggle_label)
    {
        committed.toggle_label = Some(spec.toggle_label);
    }

    if committed.toggle_enabled != Some(spec.toggle_enabled)
        && sink.set_toggle_enabled(spec.toggle_enabled)
    {
        committed.toggle_enabled = Some(spec.toggle_enabled);
    }
}

fn cached_tray_icon(kind: TrayIconKind) -> Option<Image<'static>> {
    let (cell, bytes, name) = match kind {
        TrayIconKind::Protected => (&ICON_PROTECTED, ICON_PROTECTED_BYTES, "tray-protected.png"),
        TrayIconKind::Warning => (&ICON_WARNING, ICON_WARNING_BYTES, "tray-warning.png"),
        TrayIconKind::Paused => (&ICON_PAUSED, ICON_PAUSED_BYTES, "tray-paused.png"),
    };

    let decoded = cell.get_or_init(|| match Image::from_bytes(bytes) {
        Ok(image) => Some(image),
        Err(err) => {
            error!(
                icon = name,
                error = %err,
                "failed to decode embedded tray icon PNG"
            );
            None
        }
    });

    decoded
        .as_ref()
        .map(|image| Image::new(image.rgba(), image.width(), image.height()))
}

#[cfg(any(target_os = "linux", test))]
fn is_valid_fixed_probe_binary(path: &Path) -> bool {
    path.is_absolute()
        && std::fs::symlink_metadata(path).is_ok_and(|meta| {
            let file_type = meta.file_type();
            file_type.is_file() && !file_type.is_symlink()
        })
}

#[cfg(any(target_os = "linux", test))]
fn resolve_fixed_probe_binary<'a>(candidates: &'a [&'a str]) -> Option<&'a Path> {
    candidates
        .iter()
        .map(|candidate| Path::new(*candidate))
        .find(|path| is_valid_fixed_probe_binary(path))
}

#[cfg(any(target_os = "linux", test))]
fn read_bounded_stdout<R: Read>(reader: R, max_bytes: u64) -> String {
    let mut buf = Vec::new();
    let _ = reader.take(max_bytes).read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(any(target_os = "linux", test))]
fn parse_dbus_bool_output(stdout: &str) -> Option<bool> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handles `busctl` ("b true"), `gdbus` ("(true,)"), and
    // `dbus-send --print-reply=literal` ("boolean true").
    for token in trimmed.split(|c: char| c.is_ascii_whitespace() || matches!(c, '(' | ')' | ',')) {
        match token {
            "true" => return Some(true),
            "false" => return Some(false),
            _ => {}
        }
    }

    None
}

#[cfg(target_os = "linux")]
enum ProbeOutcome {
    Available(bool),
    TimedOut,
    Unavailable,
}

#[cfg(target_os = "linux")]
fn run_dbus_probe(program: &Path, args: &[&str], timeout: Duration) -> ProbeOutcome {
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for var in LINUX_PROBE_STRIPPED_ENV_VARS {
        cmd.env_remove(var);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(_) => return ProbeOutcome::Unavailable,
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return ProbeOutcome::Unavailable;
                }
                let stdout = child
                    .stdout
                    .take()
                    .map(|pipe| read_bounded_stdout(pipe, LINUX_TRAY_PROBE_MAX_STDOUT_BYTES))
                    .unwrap_or_default();
                return match parse_dbus_bool_output(&stdout) {
                    Some(has_owner) => ProbeOutcome::Available(has_owner),
                    None => ProbeOutcome::Unavailable,
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return ProbeOutcome::TimedOut;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return ProbeOutcome::Unavailable;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn probe_linux_status_notifier_watcher() -> bool {
    const PROBES: [(&[&str], &[&str]); 3] = [
        (
            &LINUX_BUSCTL_PATHS,
            &[
                "--user",
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "NameHasOwner",
                "s",
                "org.kde.StatusNotifierWatcher",
            ],
        ),
        (
            &LINUX_GDBUS_PATHS,
            &[
                "call",
                "--session",
                "--timeout",
                "1",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.NameHasOwner",
                "org.kde.StatusNotifierWatcher",
            ],
        ),
        (
            &LINUX_DBUS_SEND_PATHS,
            &[
                "--session",
                "--print-reply=literal",
                "--reply-timeout=1000",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                "string:org.kde.StatusNotifierWatcher",
            ],
        ),
    ];

    for (candidates, args) in PROBES {
        let Some(program) = resolve_fixed_probe_binary(candidates) else {
            continue;
        };
        match run_dbus_probe(program, args, LINUX_TRAY_PROBE_TIMEOUT) {
            ProbeOutcome::Available(has_owner) => return has_owner,
            ProbeOutcome::TimedOut => {
                warn!(
                    program = %program.display(),
                    "timed out probing org.kde.StatusNotifierWatcher on session D-Bus"
                );
                return false;
            }
            ProbeOutcome::Unavailable => continue,
        }
    }

    debug!(
        "could not query org.kde.StatusNotifierWatcher via busctl/gdbus/dbus-send; assuming tray host unavailable"
    );
    false
}

/// Returns `true` when the desktop environment provides a system tray host.
///
/// Always `true` on Windows and macOS. On Linux, probes the session D-Bus with
/// a bounded timeout to verify `org.kde.StatusNotifierWatcher` has an owner so
/// GNOME sessions without an AppIndicator extension are honestly detected.
#[cfg(target_os = "linux")]
pub fn is_tray_host_available() -> bool {
    {
        let cache = LINUX_TRAY_HOST_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((checked_at, available)) = *cache {
            if checked_at.elapsed() < LINUX_TRAY_CACHE_TTL {
                return available;
            }
        }
    }

    let available = probe_linux_status_notifier_watcher();
    let mut cache = LINUX_TRAY_HOST_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *cache = Some((Instant::now(), available));
    available
}

/// Non-blocking check returning the last cached Linux tray host availability
/// without spawning D-Bus probe subprocesses (safe to call on the GTK main
/// thread). Returns `false` if no probe has completed yet.
#[cfg(target_os = "linux")]
pub fn is_tray_host_available_cached() -> bool {
    let cache = LINUX_TRAY_HOST_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    matches!(*cache, Some((_, true)))
}

/// Returns `true` when the desktop environment provides a system tray host.
#[cfg(not(target_os = "linux"))]
pub fn is_tray_host_available() -> bool {
    true
}

/// Non-blocking check returning whether the desktop environment provides a
/// system tray host (always `true` on Windows and macOS).
#[cfg(not(target_os = "linux"))]
pub fn is_tray_host_available_cached() -> bool {
    true
}

/// Returns `true` when any user GUI preference requires a system tray / menu bar icon.
pub const fn tray_enabled(prefs: &GuiPreferencesDto) -> bool {
    prefs.keep_in_tray_on_close || prefs.minimize_to_tray || prefs.start_minimized_to_tray
}

/// Creates, synchronizes, or cleanly hides/removes the native system tray icon
/// based on the user's GUI tray preferences and latest engine status snapshot.
///
/// All OS tray icon and menu mutations execute on the Tauri main thread without
/// holding any cross-thread lock across OS calls so `RunEvent::Exit` and
/// `WindowEvent::CloseRequested` can never AB-BA deadlock against worker threads.
pub fn setup_or_sync_tray(
    app: &AppHandle,
    prefs: &GuiPreferencesDto,
    status: Option<&DesktopStatusSnapshotDto>,
) -> tauri::Result<()> {
    let enabled = tray_enabled(prefs);
    let host_available = if enabled {
        is_tray_host_available()
    } else {
        false
    };
    let incoming =
        status.map(|snapshot| (snapshot.snapshot_seq, TrayVisualSpec::from_snapshot(snapshot)));

    if is_on_main_thread() {
        return setup_or_sync_tray_on_main_thread(app, enabled, host_available, incoming);
    }

    let (tx, rx) = mpsc::sync_channel::<tauri::Result<()>>(1);
    let app_handle = app.clone();
    app.run_on_main_thread(move || {
        record_main_thread();
        let result =
            setup_or_sync_tray_on_main_thread(&app_handle, enabled, host_available, incoming);
        let _ = tx.send(result);
    })?;

    match rx.recv_timeout(TRAY_SYNC_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(tauri::Error::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for main thread to synchronize system tray",
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(tauri::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "main thread exited before synchronizing system tray",
        ))),
    }
}

fn setup_or_sync_tray_on_main_thread(
    app: &AppHandle,
    enabled: bool,
    host_available: bool,
    incoming: Option<(u64, TrayVisualSpec)>,
) -> tauri::Result<()> {
    if !enabled || !host_available {
        if enabled {
            debug!("system tray host is unavailable; skipping tray icon creation");
        }
        remove_tray_cleanly_on_main_thread(app);
        if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
            if !window.is_visible().unwrap_or(true) {
                show_main_window(app);
            }
        }
        return Ok(());
    }

    let effective = {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let base = match incoming {
            Some((seq, spec)) => {
                if guard.accept_snapshot(seq, spec) {
                    spec
                } else {
                    *guard.base_visual.get_or_insert(spec)
                }
            }
            None => *guard.base_visual.get_or_insert_with(TrayVisualSpec::checking),
        };
        base.with_toggle_busy(guard.toggle_busy)
    };

    if let Some(existing) = app.tray_by_id(TRAY_ID) {
        if let Err(err) = existing.set_visible(true) {
            warn!(error = %err, "failed to make existing tray icon visible");
        }
        apply_current_tray_visuals_on_main_thread(app);
        return Ok(());
    }

    let show_item = MenuItem::with_id(app, MENU_SHOW_ID, "Show vdpi", true, None::<&str>)?;
    let sep_top = PredefinedMenuItem::separator(app)?;
    let status_item = MenuItem::with_id(
        app,
        MENU_STATUS_ID,
        effective.status_label,
        false,
        None::<&str>,
    )?;
    let toggle_item = MenuItem::with_id(
        app,
        MENU_TOGGLE_PROTECTION_ID,
        effective.toggle_label,
        effective.toggle_enabled,
        None::<&str>,
    )?;
    let sep_bottom = PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItem::with_id(app, MENU_QUIT_ID, "Quit vdpi GUI", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &show_item,
            &sep_top,
            &status_item,
            &toggle_item,
            &sep_bottom,
            &quit_item,
        ],
    )?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip(effective.tooltip)
        .show_menu_on_left_click(cfg!(target_os = "macos"))
        .on_tray_icon_event(|tray, event| {
            record_main_thread();
            if !cfg!(target_os = "macos") {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    show_main_window(tray.app_handle());
                }
            }
        });

    let has_icon = if let Some(icon) = cached_tray_icon(effective.icon) {
        builder = builder.icon(icon);
        true
    } else {
        false
    };

    let attach_menu_handler = MENU_EVENT_HANDLER_REGISTERED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if attach_menu_handler {
        builder = builder.on_menu_event(handle_tray_menu_event);
    }

    let build_result = builder.build(app);
    if build_result.is_err() && attach_menu_handler {
        MENU_EVENT_HANDLER_REGISTERED.store(false, Ordering::SeqCst);
    }
    let _tray = build_result?;

    // Store handles for in-place menu updates (required on Linux where replacing
    // an attached tray menu is unsupported) and avoid dropping previous handles
    // while holding the mutex.
    let (old_status, old_toggle) = {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.tray_generation = guard.tray_generation.wrapping_add(1);
        let prev_status = guard.status_item.replace(status_item);
        let prev_toggle = guard.toggle_item.replace(toggle_item);
        guard.last_visual = AppliedTrayVisual::from_build(effective, has_icon);
        (prev_status, prev_toggle)
    };
    drop(old_status);
    drop(old_toggle);

    // Reconcile if a newer snapshot or toggle_busy transition updated TRAY_STATE
    // while the tray icon was being constructed.
    apply_current_tray_visuals_on_main_thread(app);
    Ok(())
}

/// Swaps the embedded tray icon PNG, tooltip text, and status/toggle menu labels
/// when the visual state changes, enforcing monotonic `snapshot_seq` ordering
/// and dispatching OS mutations onto the main thread.
pub fn update_tray_visuals(app: &AppHandle, status: &DesktopStatusSnapshotDto) {
    let base_spec = TrayVisualSpec::from_snapshot(status);
    {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !guard.should_dispatch_snapshot(status.snapshot_seq, base_spec) {
            return;
        }
    }

    if app.tray_by_id(TRAY_ID).is_none() {
        return;
    }

    dispatch_apply_tray_visuals(app);
}

/// Atomically claims the tray protection toggle busy state if idle.
///
/// Returns `true` when this caller transitioned `toggle_busy` from `false` to
/// `true` and scheduled the busy visual update, or `false` when a toggle action
/// is already in flight.
pub fn try_claim_tray_toggle_busy(app: &AppHandle) -> bool {
    let claimed = {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.try_claim_toggle_busy()
    };

    if claimed && app.tray_by_id(TRAY_ID).is_some() {
        dispatch_apply_tray_visuals(app);
    }

    claimed
}

/// Disables and relabels the tray protection toggle menu item while a
/// pause/resume operation is in flight, or restores it once the operation ends.
pub fn set_tray_toggle_busy(app: &AppHandle, busy: bool) {
    {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.toggle_busy = busy;
    }

    if app.tray_by_id(TRAY_ID).is_none() {
        return;
    }

    dispatch_apply_tray_visuals(app);
}

fn dispatch_apply_tray_visuals(app: &AppHandle) {
    if is_on_main_thread() {
        apply_current_tray_visuals_on_main_thread(app);
        return;
    }

    let app_handle = app.clone();
    if let Err(err) = app.run_on_main_thread(move || {
        record_main_thread();
        apply_current_tray_visuals_on_main_thread(&app_handle);
    }) {
        debug!(
            error = %err,
            "failed to dispatch tray visual update to main thread"
        );
    }
}

fn apply_current_tray_visuals_on_main_thread(app: &AppHandle) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };

    let (base_spec, toggle_busy, mut committed, status_item, toggle_item, generation) = {
        let guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            guard.base_visual,
            guard.toggle_busy,
            guard.last_visual,
            guard.status_item.clone(),
            guard.toggle_item.clone(),
            guard.tray_generation,
        )
    };

    let base = base_spec.unwrap_or_else(|| {
        app.try_state::<DesktopAppState>()
            .and_then(|state| state.last_snapshot())
            .map(|snapshot| TrayVisualSpec::from_snapshot(&snapshot))
            .unwrap_or_else(TrayVisualSpec::checking)
    });
    let spec = base.with_toggle_busy(toggle_busy);

    if committed.matches(spec) {
        drop(status_item);
        drop(toggle_item);
        return;
    }

    let mut sink = TauriTraySink {
        tray: &tray,
        status_item: status_item.as_ref(),
        toggle_item: toggle_item.as_ref(),
    };
    sync_visual_fields(&mut committed, spec, &mut sink);

    {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.tray_generation == generation {
            guard.last_visual = committed;
        }
    }

    drop(status_item);
    drop(toggle_item);
}

fn remove_tray_cleanly_on_main_thread(app: &AppHandle) {
    if let Some(tray) = app.remove_tray_by_id(TRAY_ID) {
        if let Err(err) = tray.set_visible(false) {
            debug!(error = %err, "failed to hide tray icon prior to removal");
        }
        drop(tray);
    }

    let (old_status, old_toggle) = {
        let mut guard = TRAY_STATE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.tray_generation = guard.tray_generation.wrapping_add(1);
        guard.base_visual = None;
        guard.last_visual = AppliedTrayVisual::empty();
        (guard.status_item.take(), guard.toggle_item.take())
    };
    drop(old_status);
    drop(old_toggle);
}

/// Cleanly hides and removes the native system tray icon and clears cached
/// menu handles so no ghost tray icon lingers after exit or disable.
pub fn remove_tray_cleanly(app: &AppHandle) {
    if is_on_main_thread() {
        remove_tray_cleanly_on_main_thread(app);
        return;
    }

    let app_handle = app.clone();
    if let Err(err) = app.run_on_main_thread(move || {
        record_main_thread();
        remove_tray_cleanly_on_main_thread(&app_handle);
    }) {
        debug!(
            error = %err,
            "failed to dispatch tray removal to main thread"
        );
    }
}

fn handle_tray_menu_event(app: &AppHandle, event: MenuEvent) {
    record_main_thread();
    match event.id().as_ref() {
        MENU_SHOW_ID => {
            show_main_window(app);
        }
        MENU_TOGGLE_PROTECTION_ID => {
            if app
                .try_state::<DesktopAppState>()
                .is_some_and(|state| state.is_quitting())
            {
                return;
            }
            if !try_claim_tray_toggle_busy(app) {
                debug!("ignoring tray protection toggle click while action is already in flight");
                return;
            }
            let busy_guard = crate::commands::TrayToggleBusyGuard::adopt(app);
            tauri::async_runtime::spawn(crate::commands::handle_tray_toggle_protection(
                app.clone(),
                busy_guard,
            ));
        }
        MENU_QUIT_ID => {
            if let Some(state) = app.try_state::<DesktopAppState>() {
                state.set_quitting(true);
            }
            crate::wake_status_poller(app);
            remove_tray_cleanly(app);
            app.exit(0);
        }
        _ => {}
    }
}

/// Restores, returns to the taskbar/Dock, shows, and focuses the `main` window.
pub fn show_main_window(app: &AppHandle) {
    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        warn!(label = MAIN_WINDOW_LABEL, "main webview window not found");
        return;
    };

    if let Some(state) = app.try_state::<DesktopAppState>() {
        state.mark_restoring_for(RESTORE_GUARD_WINDOW);
    }

    #[cfg(target_os = "macos")]
    {
        let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
        let _ = app.show();
    }

    if let Err(err) = window.set_skip_taskbar(false) {
        debug!(
            error = %err,
            "failed to restore taskbar visibility for main window"
        );
    }
    if let Err(err) = window.unminimize() {
        debug!(error = %err, "failed to unminimize main window");
    }
    if let Err(err) = window.show() {
        warn!(error = %err, "failed to show main window");
    }
    if let Err(err) = window.set_focus() {
        debug!(error = %err, "failed to focus main window");
    }

    crate::wake_status_poller_for_visible(app);
}

/// Hides or minimizes the `main` window into the tray.
///
/// When `skip_taskbar` is `true`, the window is removed from the taskbar/Dock
/// and hidden completely, but only if a live system tray icon exists. When
/// `skip_taskbar` is `false`, the taskbar/Dock entry is kept visible while the
/// window is minimized.
pub fn hide_main_window_to_tray(app: &AppHandle, skip_taskbar: bool) {
    if skip_taskbar && app.tray_by_id(TRAY_ID).is_none() {
        warn!("refusing to hide main window with skip_taskbar=true while no tray icon exists");
        return;
    }

    let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) else {
        warn!(label = MAIN_WINDOW_LABEL, "main webview window not found");
        return;
    };

    if let Err(err) = window.set_skip_taskbar(skip_taskbar) {
        debug!(
            skip_taskbar,
            error = %err,
            "failed to update taskbar visibility for main window"
        );
    }

    if skip_taskbar {
        if let Err(err) = window.hide() {
            warn!(error = %err, "failed to hide main window to tray");
        }
        #[cfg(target_os = "macos")]
        {
            let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
        }
    } else if let Err(err) = window.minimize() {
        warn!(error = %err, "failed to minimize main window");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{LiveTelemetryDto, SplitTunnelModeDto, WintunStatusDto};

    #[derive(Default)]
    struct MockTrayVisualSink {
        fail_icon: bool,
        fail_tooltip: bool,
        fail_status_label: bool,
        fail_toggle_label: bool,
        fail_toggle_enabled: bool,
        icon_calls: usize,
        tooltip_calls: usize,
        status_label_calls: usize,
        toggle_label_calls: usize,
        toggle_enabled_calls: usize,
    }

    impl TrayVisualSink for MockTrayVisualSink {
        fn set_icon(&mut self, _kind: TrayIconKind) -> bool {
            self.icon_calls += 1;
            !self.fail_icon
        }

        fn set_tooltip(&mut self, _tooltip: &'static str) -> bool {
            self.tooltip_calls += 1;
            !self.fail_tooltip
        }

        fn set_status_label(&mut self, _label: &'static str) -> bool {
            self.status_label_calls += 1;
            !self.fail_status_label
        }

        fn set_toggle_label(&mut self, _label: &'static str) -> bool {
            self.toggle_label_calls += 1;
            !self.fail_toggle_label
        }

        fn set_toggle_enabled(&mut self, _enabled: bool) -> bool {
            self.toggle_enabled_calls += 1;
            !self.fail_toggle_enabled
        }
    }

    fn sample_live(engine: EngineModeDto, vpn_conflict: Option<&str>) -> LiveTelemetryDto {
        LiveTelemetryDto {
            running: true,
            engine,
            addr: "127.0.0.1".to_string(),
            port: 10808,
            socks_port: Some(10809),
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: vpn_conflict.map(str::to_string),
            version: Some("0.6.0".to_string()),
            mode: Some("auto".to_string()),
            doh_enabled: true,
            dns_display: "1.1.1.1".to_string(),
            block_quic: true,
            active_connections: 4,
            total_connections: 100,
            learned_hosts: 12,
            isp_stage: None,
            udp_flows_active: 0,
            quic_blocked: 3,
            dns_queries: 50,
            rss_kb: Some(12_000),
            bytes_rx: 1024,
            bytes_tx: 512,
            rx_rate_bps: 128,
            tx_rate_bps: 64,
            tls_handshakes: 20,
            auto_heal_escalations: 0,
        }
    }

    fn sample_snapshot(
        service_state: ServiceStateDto,
        configured_engine: EngineModeDto,
        live: Option<LiveTelemetryDto>,
    ) -> DesktopStatusSnapshotDto {
        DesktopStatusSnapshotDto {
            snapshot_seq: 1,
            app_version: "0.6.0".to_string(),
            platform: "windows".to_string(),
            service_state,
            installed_version: Some("0.6.0".to_string()),
            configured_engine,
            live,
            vpn_conflict: None,
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            split_tunnel_mode: SplitTunnelModeDto::All,
            split_tunnel_count: 0,
            config_path: "C:/vdpi/config.toml".to_string(),
            logs_dir: "C:/vdpi/logs".to_string(),
            tray_supported: true,
            config_warning: None,
        }
    }

    #[test]
    fn tray_enabled_matches_gui_preferences() {
        let mut prefs = GuiPreferencesDto::default();
        assert!(!tray_enabled(&prefs));

        prefs.keep_in_tray_on_close = true;
        assert!(tray_enabled(&prefs));

        prefs = GuiPreferencesDto {
            minimize_to_tray: true,
            ..GuiPreferencesDto::default()
        };
        assert!(tray_enabled(&prefs));

        prefs = GuiPreferencesDto {
            start_minimized_to_tray: true,
            ..GuiPreferencesDto::default()
        };
        assert!(tray_enabled(&prefs));
    }

    #[test]
    fn embedded_tray_icons_decode_once_and_borrow_statically() {
        for kind in [
            TrayIconKind::Protected,
            TrayIconKind::Warning,
            TrayIconKind::Paused,
        ] {
            let first = cached_tray_icon(kind).expect("embedded tray PNG must decode");
            let second = cached_tray_icon(kind).expect("cached tray PNG must remain available");

            assert!(first.width() > 0);
            assert!(first.height() > 0);
            assert_eq!(
                first.rgba().len(),
                (first.width() as usize) * (first.height() as usize) * 4
            );
            assert_eq!(first.rgba().as_ptr(), second.rgba().as_ptr());
        }
    }

    #[test]
    fn visual_spec_maps_protected_warning_and_paused_states() {
        let checking = TrayVisualSpec::from_option(None);
        assert_eq!(checking.icon, TrayIconKind::Paused);
        assert_eq!(checking.status_label, "Status: Checking...");
        assert!(!checking.toggle_enabled);

        let tun_protected = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));
        assert_eq!(tun_protected.icon, TrayIconKind::Protected);
        assert_eq!(tun_protected.status_label, "Status: Protected (TUN)");
        assert_eq!(tun_protected.toggle_label, "Pause Protection");
        assert!(tun_protected.toggle_enabled);
        assert_eq!(tun_protected.toggle_action, ProtectionToggleAction::Pause);

        let proxy_protected = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Proxy, None)),
        ));
        assert_eq!(proxy_protected.icon, TrayIconKind::Protected);
        assert_eq!(proxy_protected.status_label, "Status: Protected (Proxy)");

        let mut vpn_conflict_snap = sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, Some("WireGuard"))),
        );
        let vpn_warning = TrayVisualSpec::from_snapshot(&vpn_conflict_snap);
        assert_eq!(vpn_warning.icon, TrayIconKind::Warning);
        assert_eq!(vpn_warning.status_label, "Status: VPN Conflict (TUN)");

        vpn_conflict_snap.live = None;
        vpn_conflict_snap.service_state = ServiceStateDto::Stopped;
        vpn_conflict_snap.vpn_conflict = Some("WireGuard".to_string());
        let paused_vpn = TrayVisualSpec::from_snapshot(&vpn_conflict_snap);
        assert_eq!(paused_vpn.icon, TrayIconKind::Warning);
        assert_eq!(paused_vpn.status_label, "Status: Paused (VPN Active)");
        assert_eq!(paused_vpn.toggle_label, "Resume Protection");
        assert!(paused_vpn.toggle_enabled);
        assert_eq!(paused_vpn.toggle_action, ProtectionToggleAction::Resume);

        let mut wintun_missing = sample_snapshot(ServiceStateDto::Running, EngineModeDto::Tun, None);
        wintun_missing.wintun.ready = false;
        let wintun_spec = TrayVisualSpec::from_snapshot(&wintun_missing);
        assert_eq!(wintun_spec.icon, TrayIconKind::Warning);
        assert_eq!(wintun_spec.status_label, "Status: Wintun Required (TUN)");

        let degraded = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Proxy,
            None,
        ));
        assert_eq!(degraded.icon, TrayIconKind::Warning);
        assert_eq!(degraded.status_label, "Status: Degraded (Proxy)");

        let paused = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Stopped,
            EngineModeDto::Tun,
            None,
        ));
        assert_eq!(paused.icon, TrayIconKind::Paused);
        assert_eq!(paused.status_label, "Status: Paused");
        assert_eq!(paused.toggle_label, "Resume Protection");
        assert!(paused.toggle_enabled);

        let not_installed = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::NotInstalled,
            EngineModeDto::Tun,
            None,
        ));
        assert_eq!(not_installed.icon, TrayIconKind::Paused);
        assert_eq!(not_installed.status_label, "Status: Not Installed");
        assert_eq!(not_installed.toggle_label, "Resume Protection");
        assert!(!not_installed.toggle_enabled);
    }

    #[test]
    fn visual_spec_with_toggle_busy_disables_and_relabels_cleanly() {
        let protected = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));
        assert_eq!(protected.with_toggle_busy(false), protected);
        let busy_pause = protected.with_toggle_busy(true);
        assert_eq!(busy_pause.toggle_label, "Pausing Protection...");
        assert!(!busy_pause.toggle_enabled);
        assert_eq!(busy_pause.icon, protected.icon);
        assert_eq!(busy_pause.status_label, protected.status_label);
        assert_eq!(busy_pause.tooltip, protected.tooltip);

        let paused = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Stopped,
            EngineModeDto::Tun,
            None,
        ));
        let busy_resume = paused.with_toggle_busy(true);
        assert_eq!(busy_resume.toggle_label, "Resuming Protection...");
        assert!(!busy_resume.toggle_enabled);

        let checking_busy = TrayVisualSpec::checking().with_toggle_busy(true);
        assert_eq!(checking_busy.toggle_label, "Updating Protection...");
        assert!(!checking_busy.toggle_enabled);
    }

    #[test]
    fn sync_visual_fields_commits_only_successful_os_updates_and_retries_failures() {
        let spec = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));

        let mut committed = AppliedTrayVisual::empty();
        let mut sink = MockTrayVisualSink {
            fail_icon: true,
            fail_toggle_enabled: true,
            ..MockTrayVisualSink::default()
        };

        sync_visual_fields(&mut committed, spec, &mut sink);
        assert_eq!(committed.icon, None);
        assert_eq!(committed.tooltip, Some(spec.tooltip));
        assert_eq!(committed.status_label, Some(spec.status_label));
        assert_eq!(committed.toggle_label, Some(spec.toggle_label));
        assert_eq!(committed.toggle_enabled, None);
        assert!(!committed.matches(spec));
        assert_eq!(sink.icon_calls, 1);
        assert_eq!(sink.tooltip_calls, 1);
        assert_eq!(sink.status_label_calls, 1);
        assert_eq!(sink.toggle_label_calls, 1);
        assert_eq!(sink.toggle_enabled_calls, 1);

        // Retry after transient OS failure resolves: only previously failed fields run.
        sink.fail_icon = false;
        sink.fail_toggle_enabled = false;
        sync_visual_fields(&mut committed, spec, &mut sink);
        assert!(committed.matches(spec));
        assert_eq!(sink.icon_calls, 2);
        assert_eq!(sink.tooltip_calls, 1);
        assert_eq!(sink.status_label_calls, 1);
        assert_eq!(sink.toggle_label_calls, 1);
        assert_eq!(sink.toggle_enabled_calls, 2);

        // Fully matched spec performs zero OS calls.
        sync_visual_fields(&mut committed, spec, &mut sink);
        assert_eq!(sink.icon_calls, 2);
        assert_eq!(sink.tooltip_calls, 1);
        assert_eq!(sink.status_label_calls, 1);
        assert_eq!(sink.toggle_label_calls, 1);
        assert_eq!(sink.toggle_enabled_calls, 2);
    }

    #[test]
    fn sync_visual_fields_busy_toggle_only_touches_toggle_item() {
        let base = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));
        let mut committed = AppliedTrayVisual::from_build(base, true);
        let mut sink = MockTrayVisualSink::default();

        sync_visual_fields(&mut committed, base.with_toggle_busy(true), &mut sink);
        assert_eq!(sink.icon_calls, 0);
        assert_eq!(sink.tooltip_calls, 0);
        assert_eq!(sink.status_label_calls, 0);
        assert_eq!(sink.toggle_label_calls, 1);
        assert_eq!(sink.toggle_enabled_calls, 1);
        assert_eq!(committed.toggle_label, Some("Pausing Protection..."));
        assert_eq!(committed.toggle_enabled, Some(false));

        sync_visual_fields(&mut committed, base.with_toggle_busy(false), &mut sink);
        assert_eq!(sink.icon_calls, 0);
        assert_eq!(sink.tooltip_calls, 0);
        assert_eq!(sink.status_label_calls, 0);
        assert_eq!(sink.toggle_label_calls, 2);
        assert_eq!(sink.toggle_enabled_calls, 2);
        assert_eq!(committed.toggle_label, Some("Pause Protection"));
        assert_eq!(committed.toggle_enabled, Some(true));
    }

    #[test]
    fn runtime_state_enforces_monotonic_snapshot_seq() {
        let mut state = TrayRuntimeState::new();
        let protected = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));
        let paused = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Stopped,
            EngineModeDto::Tun,
            None,
        ));
        let degraded = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Proxy,
            None,
        ));

        assert!(state.accept_snapshot(5, protected));
        assert_eq!(state.last_snapshot_seq, 5);
        assert_eq!(state.base_visual, Some(protected));

        // Strictly older non-zero sequence must be ignored.
        assert!(!state.accept_snapshot(4, paused));
        assert_eq!(state.last_snapshot_seq, 5);
        assert_eq!(state.base_visual, Some(protected));

        // Equal sequence is accepted so transient OS failures can retry.
        assert!(state.accept_snapshot(5, protected));
        assert_eq!(state.last_snapshot_seq, 5);

        // Strictly newer sequence advances high-water mark and replaces visual.
        assert!(state.accept_snapshot(6, paused));
        assert_eq!(state.last_snapshot_seq, 6);
        assert_eq!(state.base_visual, Some(paused));

        // Unsequenced (0) snapshots are allowed without lowering high-water mark.
        assert!(state.accept_snapshot(0, degraded));
        assert_eq!(state.last_snapshot_seq, 6);
        assert_eq!(state.base_visual, Some(degraded));
    }

    #[test]
    fn runtime_state_short_circuits_steady_state_visual_dispatch() {
        let mut state = TrayRuntimeState::new();
        let protected = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Running,
            EngineModeDto::Tun,
            Some(sample_live(EngineModeDto::Tun, None)),
        ));
        let paused = TrayVisualSpec::from_snapshot(&sample_snapshot(
            ServiceStateDto::Stopped,
            EngineModeDto::Tun,
            None,
        ));

        // Initial snapshot with uncommitted OS visuals must dispatch.
        assert!(state.should_dispatch_snapshot(1, protected));
        assert_eq!(state.last_snapshot_seq, 1);

        // Once committed, identical steady-state ticks advance seq without dispatching.
        state.last_visual = AppliedTrayVisual::from_build(protected, true);
        assert!(!state.should_dispatch_snapshot(2, protected));
        assert_eq!(state.last_snapshot_seq, 2);

        // Stale sequence is still rejected without dispatching.
        assert!(!state.should_dispatch_snapshot(1, paused));
        assert_eq!(state.last_snapshot_seq, 2);

        // Partial OS failure (uncommitted icon) forces retry on next tick.
        state.last_visual.icon = None;
        assert!(state.should_dispatch_snapshot(3, protected));
        assert_eq!(state.last_snapshot_seq, 3);

        // Toggle-busy visuals are also short-circuited when already committed.
        state.toggle_busy = true;
        state.last_visual = AppliedTrayVisual::from_build(protected.with_toggle_busy(true), true);
        assert!(!state.should_dispatch_snapshot(4, protected));
        assert_eq!(state.last_snapshot_seq, 4);

        // Underlying state change during toggle_busy still dispatches.
        assert!(state.should_dispatch_snapshot(5, paused));
        assert_eq!(state.last_snapshot_seq, 5);
    }

    #[test]
    fn runtime_state_try_claim_toggle_busy_is_atomic_single_claim() {
        let mut state = TrayRuntimeState::new();
        assert!(!state.toggle_busy);

        assert!(state.try_claim_toggle_busy());
        assert!(state.toggle_busy);

        // Subsequent concurrent/rapid claims fail while busy.
        assert!(!state.try_claim_toggle_busy());
        assert!(state.toggle_busy);

        // Once released, the next claim succeeds.
        state.toggle_busy = false;
        assert!(state.try_claim_toggle_busy());
        assert!(state.toggle_busy);
    }

    #[test]
    fn parse_dbus_bool_output_handles_busctl_gdbus_and_dbus_send() {
        assert_eq!(parse_dbus_bool_output("b true\n"), Some(true));
        assert_eq!(parse_dbus_bool_output("b false\n"), Some(false));
        assert_eq!(parse_dbus_bool_output("(true,)\n"), Some(true));
        assert_eq!(parse_dbus_bool_output("(false,)\n"), Some(false));
        assert_eq!(parse_dbus_bool_output("   boolean true\n"), Some(true));
        assert_eq!(parse_dbus_bool_output("   boolean false\n"), Some(false));
        assert_eq!(parse_dbus_bool_output(""), None);
        assert_eq!(
            parse_dbus_bool_output("Error org.freedesktop.DBus.Error.ServiceUnknown"),
            None
        );
    }

    #[test]
    fn read_bounded_stdout_caps_at_4kib_and_handles_utf8_boundaries() {
        assert_eq!(
            read_bounded_stdout(std::io::Cursor::new(b"b true\n"), LINUX_TRAY_PROBE_MAX_STDOUT_BYTES),
            "b true\n"
        );

        let oversized = vec![b'a'; (LINUX_TRAY_PROBE_MAX_STDOUT_BYTES as usize) + 2048];
        let bounded = read_bounded_stdout(
            std::io::Cursor::new(oversized),
            LINUX_TRAY_PROBE_MAX_STDOUT_BYTES,
        );
        assert_eq!(bounded.len(), LINUX_TRAY_PROBE_MAX_STDOUT_BYTES as usize);

        // Multi-byte UTF-8 sequence straddling the 4096-byte cutoff is handled lossily without error.
        let mut straddling = vec![b'x'; (LINUX_TRAY_PROBE_MAX_STDOUT_BYTES as usize) - 1];
        straddling.extend_from_slice("é".as_bytes());
        let output = read_bounded_stdout(
            std::io::Cursor::new(straddling),
            LINUX_TRAY_PROBE_MAX_STDOUT_BYTES,
        );
        assert!(output.starts_with("xxxx"));
        assert!(output.ends_with('\u{FFFD}'));
    }

    #[test]
    fn linux_probe_paths_and_stripped_env_vars_are_hardened() {
        for candidates in [
            &LINUX_BUSCTL_PATHS[..],
            &LINUX_GDBUS_PATHS[..],
            &LINUX_DBUS_SEND_PATHS[..],
        ] {
            assert!(!candidates.is_empty());
            for path in candidates {
                assert!(
                    path.starts_with("/usr/bin/") || path.starts_with("/bin/"),
                    "probe path must be fixed under /usr/bin or /bin: {path}"
                );
            }
        }

        let required_vars = [
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_AUDIT",
            "APPDIR",
            "APPIMAGE",
            "GTK_PATH",
            "GIO_EXTRA_MODULES",
            "GIO_MODULE_DIR",
            "GDK_PIXBUF_MODULE_FILE",
            "GTK_IM_MODULE_FILE",
        ];
        assert_eq!(LINUX_PROBE_STRIPPED_ENV_VARS.len(), required_vars.len());
        for required in required_vars {
            assert!(
                LINUX_PROBE_STRIPPED_ENV_VARS.contains(&required),
                "missing stripped env var: {required}"
            );
        }
    }

    #[test]
    fn resolve_fixed_probe_binary_accepts_only_absolute_regular_non_symlinks() {
        let base_dir = std::env::temp_dir().join(format!(
            "vdpi-tray-probe-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base_dir);
        std::fs::create_dir_all(&base_dir).expect("create temp dir");

        let regular_file = base_dir.join("busctl");
        std::fs::write(&regular_file, b"stub").expect("write stub file");
        let missing_file = base_dir.join("missing");

        let base_dir_str = base_dir.to_string_lossy().into_owned();
        let regular_str = regular_file.to_string_lossy().into_owned();
        let missing_str = missing_file.to_string_lossy().into_owned();

        // Rejects relative paths, directories, and nonexistent paths.
        assert_eq!(resolve_fixed_probe_binary(&["busctl"]), None);
        assert_eq!(resolve_fixed_probe_binary(&[base_dir_str.as_str()]), None);
        assert_eq!(resolve_fixed_probe_binary(&[missing_str.as_str()]), None);

        // Skips invalid candidates and returns the first valid absolute regular file.
        assert_eq!(
            resolve_fixed_probe_binary(&[
                "busctl",
                missing_str.as_str(),
                base_dir_str.as_str(),
                regular_str.as_str(),
            ]),
            Some(regular_file.as_path())
        );

        #[cfg(unix)]
        {
            let link_path = base_dir.join("busctl-link");
            std::os::unix::fs::symlink(&regular_file, &link_path).expect("create symlink");
            let link_str = link_path.to_string_lossy().into_owned();
            assert_eq!(resolve_fixed_probe_binary(&[link_str.as_str()]), None);
            assert_eq!(
                resolve_fixed_probe_binary(&[link_str.as_str(), regular_str.as_str()]),
                Some(regular_file.as_path())
            );
        }

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn is_tray_host_available_returns_true_on_windows_and_macos() {
        assert!(is_tray_host_available());
        assert!(is_tray_host_available_cached());
    }
}
