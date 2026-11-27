pub mod actions;
pub mod commands;
pub mod diagnostics;
pub mod models;
pub mod preferences;
pub mod sidecar;
pub mod split;
pub mod state;
pub mod status;
pub mod tray;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::Notify;
use tracing::{debug, error, warn};
use tracing_subscriber::EnvFilter;

use crate::models::GuiPreferencesDto;
use crate::state::DesktopAppState;

/// Event channel carrying live [`models::DesktopStatusSnapshotDto`] updates to the webview.
pub const STATUS_EVENT_NAME: &str = "vdpi://status";

/// Event channel carrying [`models::ActionResultDto`] updates from native tray actions.
pub const TRAY_ACTION_RESULT_EVENT: &str = "vdpi://tray-action-result";

const VISIBLE_POLL_INTERVAL: Duration = Duration::from_millis(1500);
const HIDDEN_TRAY_POLL_INTERVAL: Duration = Duration::from_secs(15);
const MIN_WAKE_INTERVAL: Duration = Duration::from_millis(500);
const STALE_POLL_THRESHOLD: Duration = Duration::from_secs(3);
#[cfg(any(target_os = "macos", test))]
const MACOS_MINIMIZE_CHECK_DELAY: Duration = Duration::from_millis(380);
#[cfg(target_os = "macos")]
static MACOS_MINIMIZE_CHECK_PENDING: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "macos", test))]
struct AtomicFlagGuard<'a> {
    flag: &'a AtomicBool,
}

#[cfg(any(target_os = "macos", test))]
impl<'a> AtomicFlagGuard<'a> {
    fn try_acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self { flag })
    }
}

#[cfg(any(target_os = "macos", test))]
impl Drop for AtomicFlagGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

#[cfg(any(target_os = "macos", test))]
const fn should_schedule_macos_delayed_minimize_check(
    minimize_to_tray: bool,
    is_minimized: bool,
    is_restoring: bool,
    is_quitting: bool,
) -> bool {
    minimize_to_tray && !is_minimized && !is_restoring && !is_quitting
}

#[cfg(target_os = "macos")]
fn schedule_macos_delayed_minimize_check(app: &AppHandle, wake: &StatusPollerWake) {
    let Some(pending_guard) = AtomicFlagGuard::try_acquire(&MACOS_MINIMIZE_CHECK_PENDING) else {
        return;
    };

    let app_handle = app.clone();
    let wake_clone = wake.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(MACOS_MINIMIZE_CHECK_DELAY).await;
        if app_handle
            .try_state::<DesktopAppState>()
            .is_some_and(|state| state.is_quitting())
        {
            return;
        }

        let app_for_main = app_handle.clone();
        if let Err(err) = app_handle.run_on_main_thread(move || {
            drop(pending_guard);
            if app_for_main
                .try_state::<DesktopAppState>()
                .is_some_and(|state| state.is_quitting() || state.is_restoring())
            {
                return;
            }
            if let Some(main_window) = app_for_main.get_window(tray::MAIN_WINDOW_LABEL) {
                handle_minimize_to_tray_if_minimized(&main_window, &wake_clone);
            }
        }) {
            debug!(
                error = %err,
                "failed to dispatch delayed macOS minimize check to main thread"
            );
        }
    });
}

/// Managed state wrapping the shared wake handle and window visibility/staleness
/// tracking for the background status poller.
#[derive(Clone)]
pub(crate) struct StatusPollerWake {
    notify: Arc<Notify>,
    window_hidden: Arc<AtomicBool>,
    last_activity: Arc<Mutex<Option<Instant>>>,
}

impl StatusPollerWake {
    fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            window_hidden: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(Mutex::new(None)),
        }
    }

    fn mark_window_hidden(&self) {
        self.window_hidden.store(true, Ordering::SeqCst);
    }

    fn record_poll(&self, now: Instant) {
        let mut guard = self
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(now);
    }

    fn wake_now(&self) {
        {
            let mut guard = self
                .last_activity
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = Some(Instant::now());
        }
        self.notify.notify_one();
    }

    fn wake_for_visible(&self) {
        self.window_hidden.store(false, Ordering::SeqCst);
        self.wake_now();
    }

    fn wake_if_hidden_or_stale(&self) {
        let was_hidden = self.window_hidden.swap(false, Ordering::SeqCst);
        let now = Instant::now();
        let mut guard = self
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let is_stale = match *guard {
            None => true,
            Some(prev) => now.saturating_duration_since(prev) >= STALE_POLL_THRESHOLD,
        };
        if was_hidden || is_stale {
            *guard = Some(now);
            drop(guard);
            self.notify.notify_one();
        }
    }
}

pub(crate) fn wake_status_poller(app: &AppHandle) {
    if let Some(wake) = app.try_state::<StatusPollerWake>() {
        wake.wake_now();
    }
}

pub(crate) fn wake_status_poller_for_visible(app: &AppHandle) {
    if let Some(wake) = app.try_state::<StatusPollerWake>() {
        wake.wake_for_visible();
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

pub(crate) fn is_main_window_actively_visible(app: &AppHandle) -> bool {
    let Some(window) = app.get_webview_window(tray::MAIN_WINDOW_LABEL) else {
        return false;
    };
    if !window.is_visible().unwrap_or(false) {
        return false;
    }
    !window.is_minimized().unwrap_or(false)
}

/// Checks whether the main window is currently minimized and, if so, marks it
/// hidden for poller wake tracking and enforces the minimize-to-tray policy
/// (removing a stale tray icon if the OS tray host disappeared mid-session).
fn handle_minimize_to_tray_if_minimized(window: &tauri::Window, wake: &StatusPollerWake) -> bool {
    let app = window.app_handle();
    if app
        .try_state::<DesktopAppState>()
        .is_some_and(|state| state.is_restoring())
    {
        return false;
    }

    if !window.is_minimized().unwrap_or(false) {
        return false;
    }

    wake.mark_window_hidden();

    let prefs = app
        .try_state::<DesktopAppState>()
        .map(|state| state.preferences())
        .unwrap_or_default();

    if prefs.minimize_to_tray && app.tray_by_id(tray::TRAY_ID).is_some() {
        if !tray::is_tray_host_available_cached() {
            warn!(
                "system tray host became unavailable mid-session; removing stale tray icon instead of hiding minimized window"
            );
            tray::remove_tray_cleanly(app);
            if let Err(err) = window.set_skip_taskbar(false) {
                debug!(
                    error = %err,
                    "failed to keep taskbar icon visible after tray host disappeared"
                );
            }
            return true;
        }

        let skip_taskbar = !prefs.show_taskbar_icon_when_minimized;
        if skip_taskbar {
            tray::hide_main_window_to_tray(app, true);
        } else if let Err(err) = window.set_skip_taskbar(false) {
            debug!(
                error = %err,
                "failed to keep taskbar icon visible while minimized"
            );
        }
    }

    true
}

fn spawn_status_poller(app: AppHandle, wake: StatusPollerWake) {
    tauri::async_runtime::spawn(async move {
        let mut last_poll: Option<Instant> = None;

        while let Some(state) = app.try_state::<DesktopAppState>() {
            if state.is_quitting() {
                break;
            }

            let tray_active = app.tray_by_id(tray::TRAY_ID).is_some();
            let visible = is_main_window_actively_visible(&app);
            if !visible {
                wake.mark_window_hidden();
            }
            if !visible && !tray_active {
                wake.notify.notified().await;
                if let Some(prev) = last_poll {
                    let elapsed = prev.elapsed();
                    if elapsed < MIN_WAKE_INTERVAL {
                        tokio::time::sleep(MIN_WAKE_INTERVAL - elapsed).await;
                    }
                }
                continue;
            }

            let app_clone = app.clone();
            let snapshot_result = tokio::task::spawn_blocking(move || {
                app_clone
                    .try_state::<DesktopAppState>()
                    .map(|state| status::collect_status_snapshot(&state, false))
            })
            .await;
            let now = Instant::now();
            last_poll = Some(now);
            wake.record_poll(now);

            match snapshot_result {
                Ok(Some(snapshot)) => {
                    tray::update_tray_visuals(&app, &snapshot);
                    if is_main_window_actively_visible(&app) {
                        if let Err(err) =
                            app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &snapshot)
                        {
                            debug!(error = %err, "failed to emit vdpi://status event");
                        }
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    warn!(
                        error = %err,
                        "background status poll worker panicked or was cancelled"
                    );
                }
            }

            let quitting_after = match app.try_state::<DesktopAppState>() {
                Some(state) => state.is_quitting(),
                None => break,
            };
            if quitting_after {
                break;
            }

            let tray_active_after = app.tray_by_id(tray::TRAY_ID).is_some();
            let visible_after = is_main_window_actively_visible(&app);
            if !visible_after {
                wake.mark_window_hidden();
            }
            if !visible_after && !tray_active_after {
                wake.notify.notified().await;
                let elapsed = now.elapsed();
                if elapsed < MIN_WAKE_INTERVAL {
                    tokio::time::sleep(MIN_WAKE_INTERVAL - elapsed).await;
                }
                continue;
            }

            let interval = if visible_after {
                VISIBLE_POLL_INTERVAL
            } else {
                HIDDEN_TRAY_POLL_INTERVAL
            };

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = wake.notify.notified() => {
                    let elapsed = now.elapsed();
                    if elapsed < MIN_WAKE_INTERVAL {
                        tokio::time::sleep(MIN_WAKE_INTERVAL - elapsed).await;
                    }
                }
            }
        }
    });
}

pub fn run() {
    init_tracing();

    let status_wake = StatusPollerWake::new();
    let setup_wake = status_wake.clone();
    let window_wake = status_wake.clone();

    let build_result = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            tray::show_main_window(app);
        }))
        .setup(move |app| {
            tray::record_main_thread();

            if let Ok(resource_dir) = app.path().resource_dir() {
                sidecar::set_resource_dir(resource_dir);
            }
            sidecar::sweep_stale_temp_files();

            let prefs = preferences::load_gui_preferences();

            app.manage(DesktopAppState::new(prefs.clone()));
            app.manage(setup_wake.clone());

            let app_handle = app.handle().clone();
            if let Err(err) = tray::setup_or_sync_tray(&app_handle, &prefs, None) {
                warn!(error = %err, "failed to initialize system tray during setup");
            }

            let has_tray = app_handle.tray_by_id(tray::TRAY_ID).is_some();
            if prefs.start_minimized_to_tray && has_tray {
                setup_wake.mark_window_hidden();
                if prefs.show_taskbar_icon_when_minimized {
                    if let Some(window) = app_handle.get_webview_window(tray::MAIN_WINDOW_LABEL) {
                        if let Err(err) = window.set_skip_taskbar(false) {
                            debug!(
                                error = %err,
                                "failed to keep taskbar icon visible on minimized startup"
                            );
                        }
                        if let Err(err) = window.minimize() {
                            warn!(error = %err, "failed to minimize main window on startup");
                        }
                    }
                } else {
                    tray::hide_main_window_to_tray(&app_handle, true);
                }
            } else {
                tray::show_main_window(&app_handle);
            }

            spawn_status_poller(app_handle, setup_wake);
            Ok(())
        })
        .on_window_event(move |window, event| {
            if window.label() != tray::MAIN_WINDOW_LABEL {
                return;
            }

            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    let app = window.app_handle();
                    let (is_quitting, prefs) = match app.try_state::<DesktopAppState>() {
                        Some(state) => (state.is_quitting(), state.preferences()),
                        None => (false, GuiPreferencesDto::default()),
                    };

                    let can_hide_to_tray = if !is_quitting
                        && prefs.keep_in_tray_on_close
                        && app.tray_by_id(tray::TRAY_ID).is_some()
                    {
                        if tray::is_tray_host_available_cached() {
                            true
                        } else {
                            warn!(
                                "system tray host became unavailable mid-session; removing stale tray icon instead of hiding window"
                            );
                            tray::remove_tray_cleanly(app);
                            false
                        }
                    } else {
                        false
                    };

                    if can_hide_to_tray {
                        api.prevent_close();
                        window_wake.mark_window_hidden();
                        tray::hide_main_window_to_tray(app, true);
                    } else {
                        if let Some(state) = app.try_state::<DesktopAppState>() {
                            state.set_quitting(true);
                        }
                        wake_status_poller(app);
                        sidecar::sweep_stale_temp_files();
                        tray::remove_tray_cleanly(app);
                        app.exit(0);
                    }
                }
                WindowEvent::Resized(_) => {
                    let app = window.app_handle();
                    if app
                        .try_state::<DesktopAppState>()
                        .is_some_and(|state| state.is_restoring())
                    {
                        return;
                    }

                    if handle_minimize_to_tray_if_minimized(window, &window_wake) {
                        return;
                    }

                    if window.is_visible().unwrap_or(false) {
                        window_wake.wake_if_hidden_or_stale();
                    }
                }
                WindowEvent::Focused(false) => {
                    if !handle_minimize_to_tray_if_minimized(window, &window_wake) {
                        if !window.is_visible().unwrap_or(false) {
                            window_wake.mark_window_hidden();
                        }

                        #[cfg(target_os = "macos")]
                        {
                            let app = window.app_handle();
                            if let Some(state) = app.try_state::<DesktopAppState>() {
                                let prefs = state.preferences();
                                if should_schedule_macos_delayed_minimize_check(
                                    prefs.minimize_to_tray,
                                    window.is_minimized().unwrap_or(false),
                                    state.is_restoring(),
                                    state.is_quitting(),
                                ) {
                                    schedule_macos_delayed_minimize_check(app, &window_wake);
                                }
                            }
                        }
                    }
                }
                WindowEvent::Focused(true) => {
                    window_wake.wake_if_hidden_or_stale();
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_status,
            commands::get_settings,
            commands::save_gui_preferences,
            commands::toggle_protection,
            commands::switch_engine,
            commands::save_dns_rules,
            commands::get_split_tunnel,
            commands::save_split_tunnel,
            commands::run_diagnostics,
            commands::install_service,
            commands::uninstall_service,
            commands::check_updates,
            commands::open_app_folder,
            commands::open_external_url,
            commands::quit_app,
        ])
        .build(tauri::generate_context!());

    match build_result {
        Ok(app) => {
            app.run(|app_handle, event| match event {
                RunEvent::Exit => {
                    if let Some(state) = app_handle.try_state::<DesktopAppState>() {
                        state.set_quitting(true);
                    }
                    wake_status_poller(app_handle);
                    sidecar::sweep_stale_temp_files();
                    tray::remove_tray_cleanly(app_handle);
                }
                #[cfg(target_os = "macos")]
                RunEvent::Reopen { .. } => {
                    tray::show_main_window(app_handle);
                }
                _ => {}
            });
        }
        Err(err) => {
            error!(error = %err, "failed to build vdpi desktop application");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_poller_wake_for_visible_clears_hidden_flag() {
        let wake = StatusPollerWake::new();
        wake.mark_window_hidden();
        assert!(wake.window_hidden.load(Ordering::SeqCst));

        wake.wake_for_visible();
        assert!(!wake.window_hidden.load(Ordering::SeqCst));
        assert!(wake
            .last_activity
            .lock()
            .expect("lock last_activity")
            .is_some());
    }

    #[test]
    fn macos_delayed_minimize_check_predicate_and_single_flight_guard() {
        assert_eq!(MACOS_MINIMIZE_CHECK_DELAY, Duration::from_millis(380));

        assert!(should_schedule_macos_delayed_minimize_check(
            true, false, false, false
        ));
        assert!(!should_schedule_macos_delayed_minimize_check(
            false, false, false, false
        ));
        assert!(!should_schedule_macos_delayed_minimize_check(
            true, true, false, false
        ));
        assert!(!should_schedule_macos_delayed_minimize_check(
            true, false, true, false
        ));
        assert!(!should_schedule_macos_delayed_minimize_check(
            true, false, false, true
        ));

        let pending = AtomicBool::new(false);
        let guard = AtomicFlagGuard::try_acquire(&pending).expect("first acquire succeeds");
        assert!(pending.load(Ordering::SeqCst));
        assert!(
            AtomicFlagGuard::try_acquire(&pending).is_none(),
            "concurrent acquire must coalesce into a single scheduled check"
        );
        drop(guard);
        assert!(!pending.load(Ordering::SeqCst));
        assert!(AtomicFlagGuard::try_acquire(&pending).is_some());
    }
}
