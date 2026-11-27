use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};
use tracing::{debug, warn};

use crate::models::{
    ActionErrorCodeDto, ActionResultDto, AppIconRequestDto, DesktopSettingsPayloadDto,
    DesktopStatusSnapshotDto, DiagnosticsReportDto, DnsConfigUpdateDto, EngineModeDto,
    GuiPreferencesDto, ServiceOperationDto, ServiceStateDto, SplitTunnelPayloadDto,
    SplitTunnelSaveRequestDto, UpdateCheckPayloadDto,
};
use crate::state::DesktopAppState;
use crate::{
    actions, app_icons, diagnostics, preferences, sidecar, split, status, tray, STATUS_EVENT_NAME,
    TRAY_ACTION_RESULT_EVENT,
};

const READINESS_WAIT_MAX: Duration = Duration::from_millis(2500);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// RAII guard ensuring `DesktopAppState::active_operation` is always cleared on
/// exit/panic and immediately emitting a lightweight pending-operation snapshot.
struct ServiceOperationGuard {
    app: AppHandle,
}

impl ServiceOperationGuard {
    fn set(app: &AppHandle, op: ServiceOperationDto) -> Self {
        if let Some(state) = app.try_state::<DesktopAppState>() {
            state.set_active_operation(Some(op));
            if let Some(last) = state.last_snapshot() {
                let mut pending = (*last).clone();
                pending.snapshot_seq = state.next_snapshot_seq();
                pending.pending_operation = Some(op);
                let pending_arc = std::sync::Arc::new(pending);
                state.set_last_snapshot(std::sync::Arc::clone(&pending_arc));
                if crate::is_main_window_actively_visible(app) {
                    if let Err(err) =
                        app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &*pending_arc)
                    {
                        debug!(error = %err, "failed to emit pending vdpi://status event");
                    }
                }
            }
        }
        Self { app: app.clone() }
    }
}

impl Drop for ServiceOperationGuard {
    fn drop(&mut self) {
        if let Some(state) = self.app.try_state::<DesktopAppState>() {
            state.set_active_operation(None);
        }
    }
}

fn shutting_down_result() -> ActionResultDto {
    ActionResultDto {
        ok: false,
        message: "Application is shutting down.".to_string(),
        needs_restart: None,
        cancelled: None,
        code: Some(ActionErrorCodeDto::ShuttingDown),
        snapshot: None,
    }
}

fn busy_result(active_op: Option<ServiceOperationDto>) -> ActionResultDto {
    let message = match active_op {
        Some(ServiceOperationDto::Installing) => {
            "Service installation is already in progress.".to_string()
        }
        Some(ServiceOperationDto::Upgrading) => {
            "Service upgrade is already in progress.".to_string()
        }
        Some(ServiceOperationDto::Repairing) => {
            "Service repair is already in progress.".to_string()
        }
        Some(ServiceOperationDto::Uninstalling) => {
            "Service uninstall is already in progress.".to_string()
        }
        Some(ServiceOperationDto::Resuming | ServiceOperationDto::Pausing) => {
            "A protection toggle is already in progress.".to_string()
        }
        Some(ServiceOperationDto::SwitchingEngine) => {
            "An engine switch is already in progress.".to_string()
        }
        Some(ServiceOperationDto::SavingConfig) => {
            "Configuration changes are currently being applied.".to_string()
        }
        None => "Another service action is already in progress.".to_string(),
    };
    ActionResultDto {
        ok: false,
        message,
        needs_restart: None,
        cancelled: None,
        code: Some(ActionErrorCodeDto::Busy),
        snapshot: None,
    }
}

/// RAII guard ensuring tray toggle busy state is always cleared even if the
/// async task is cancelled or panics.
pub struct TrayToggleBusyGuard {
    app: AppHandle,
}

impl TrayToggleBusyGuard {
    /// Adopts a `toggle_busy` claim already acquired via
    /// [`tray::try_claim_tray_toggle_busy`] so the busy flag is cleared on drop
    /// without re-triggering the busy setter.
    pub(crate) fn adopt(app: &AppHandle) -> Self {
        Self { app: app.clone() }
    }

    fn try_claim(app: &AppHandle) -> Option<Self> {
        if tray::try_claim_tray_toggle_busy(app) {
            Some(Self { app: app.clone() })
        } else {
            None
        }
    }
}

impl Drop for TrayToggleBusyGuard {
    fn drop(&mut self) {
        tray::set_tray_toggle_busy(&self.app, false);
    }
}

#[cfg(target_os = "macos")]
const TRAY_SURFACE_NAME: &str = "menu bar";
#[cfg(not(target_os = "macos"))]
const TRAY_SURFACE_NAME: &str = "system tray";

fn format_tray_sync_error_for_surface(surface: &str, err: impl std::fmt::Display) -> String {
    format!("GUI preferences saved, but failed to synchronize {surface}: {err}")
}

fn format_tray_sync_error(err: impl std::fmt::Display) -> String {
    format_tray_sync_error_for_surface(TRAY_SURFACE_NAME, err)
}

/// Invalidates cached static probes, optionally waits up to 2.5 seconds for the
/// newly started daemon's health endpoint to become reachable, updates tray
/// visuals, pushes a fresh `vdpi://status` snapshot to the main webview window
/// while actively visible, and returns the fresh snapshot.
async fn refresh_and_broadcast_status_with_readiness(
    app: &AppHandle,
    wait_for_live: bool,
) -> Result<Box<DesktopStatusSnapshotDto>, String> {
    let deadline = Instant::now() + READINESS_WAIT_MAX;
    let mut attempt = 0usize;

    let snapshot = loop {
        let app_clone = app.clone();
        let invalidate = attempt == 0;
        let snap = tokio::task::spawn_blocking(move || {
            let state = app_clone.state::<DesktopAppState>();
            if invalidate {
                state.invalidate_static_cache();
            }
            status::collect_status_snapshot(&state, true)
        })
        .await
        .map_err(|err| format!("Failed to refresh status snapshot: {err}"))?;

        let ready = !wait_for_live
            || snap.live.is_some()
            || (snap.service_state == ServiceStateDto::Running && snap.vpn_conflict.is_some())
            || app
                .try_state::<DesktopAppState>()
                .is_some_and(|state| state.is_quitting());
        if ready {
            break snap;
        }

        let now = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(now) else {
            break snap;
        };
        if remaining.is_zero() {
            break snap;
        }
        attempt += 1;
        tokio::time::sleep(READINESS_POLL_INTERVAL.min(remaining)).await;
    };

    tray::update_tray_visuals(app, &snapshot);
    if crate::is_main_window_actively_visible(app) {
        if let Err(err) = app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &snapshot) {
            debug!(error = %err, "failed to emit vdpi://status event");
        }
    }

    Ok(Box::new((*snapshot).clone()))
}

fn resolve_toggle_target(app: &AppHandle, connect: Option<bool>) -> Result<bool, ActionResultDto> {
    let state = app.state::<DesktopAppState>();
    let snapshot = status::collect_status_snapshot(&state, true);
    if snapshot.service_state == ServiceStateDto::NotInstalled {
        return Err(ActionResultDto {
            ok: false,
            message: "Background service is not installed. Install the service from Installation or Settings first."
                .to_string(),
            needs_restart: None,
            cancelled: None,
            code: None,
            snapshot: Some(Box::new((*snapshot).clone())),
        });
    }

    let should_connect = match connect {
        Some(explicit) => explicit,
        None => {
            let is_active = snapshot.service_state == ServiceStateDto::Running
                || snapshot.live.as_ref().is_some_and(|live| live.running);
            !is_active
        }
    };
    Ok(should_connect)
}

/// Serialized handler invoked when the user toggles protection from the native
/// system tray menu. Takes ownership of the synchronously adopted busy guard,
/// tries to acquire `action_lock` (single-flight), runs the toggle action,
/// refreshes status while keeping the tray toggle busy, and emits
/// `vdpi://tray-action-result` to the main window so the UI can surface errors
/// or UAC/auth cancellations.
pub async fn handle_tray_toggle_protection(app: AppHandle, busy_guard: TrayToggleBusyGuard) {
    let Some(state) = app.try_state::<DesktopAppState>() else {
        return;
    };
    if state.is_quitting() {
        return;
    }

    let Ok(_guard) = state.action_lock.try_lock() else {
        let busy = busy_result(state.active_operation());
        drop(busy_guard);
        if let Err(err) = app.emit_to(tray::MAIN_WINDOW_LABEL, TRAY_ACTION_RESULT_EVENT, &busy) {
            debug!(error = %err, "failed to emit busy vdpi://tray-action-result event");
        }
        return;
    };
    if state.is_quitting() {
        return;
    }

    let app_for_target = app.clone();
    let target = tokio::task::spawn_blocking(move || resolve_toggle_target(&app_for_target, None))
        .await;

    let mut action_result = match target {
        Ok(Ok(should_connect)) => {
            let op_guard = ServiceOperationGuard::set(
                &app,
                if should_connect {
                    ServiceOperationDto::Resuming
                } else {
                    ServiceOperationDto::Pausing
                },
            );
            let mut result = match tokio::task::spawn_blocking(move || {
                actions::toggle_protection(should_connect)
            })
            .await
            {
                Ok(res) => res,
                Err(err) => {
                    warn!(error = %err, "tray protection toggle worker failed");
                    ActionResultDto {
                        ok: false,
                        message: format!("Failed to toggle protection: {err}"),
                        needs_restart: None,
                        cancelled: None,
                        code: None,
                        snapshot: None,
                    }
                }
            };
            drop(op_guard);
            let wait_for_live =
                should_connect && result.ok && result.needs_restart != Some(true);
            result.snapshot =
                refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
                    .await
                    .ok();
            result
        }
        Ok(Err(not_installed)) => not_installed,
        Err(err) => {
            warn!(error = %err, "tray protection toggle target worker failed");
            ActionResultDto {
                ok: false,
                message: format!("Failed to toggle protection: {err}"),
                needs_restart: None,
                cancelled: None,
                code: None,
                snapshot: None,
            }
        }
    };

    if action_result.snapshot.is_none() {
        action_result.snapshot = refresh_and_broadcast_status_with_readiness(&app, false)
            .await
            .ok();
    }
    drop(busy_guard);

    if !action_result.ok {
        warn!(
            message = %action_result.message,
            cancelled = action_result.cancelled.unwrap_or(false),
            "tray protection toggle did not succeed"
        );
    }

    if let Err(err) = app.emit_to(
        tray::MAIN_WINDOW_LABEL,
        TRAY_ACTION_RESULT_EVENT,
        &action_result,
    ) {
        debug!(error = %err, "failed to emit vdpi://tray-action-result event");
    }
}

#[tauri::command]
pub async fn get_status(
    app: AppHandle,
    force: Option<bool>,
) -> Result<DesktopStatusSnapshotDto, String> {
    let force_refresh = force.unwrap_or(false);
    let app_clone = app.clone();
    let snapshot = tokio::task::spawn_blocking(move || {
        let state = app_clone.state::<DesktopAppState>();
        status::collect_status_snapshot(&state, force_refresh)
    })
    .await
    .map_err(|err| format!("Failed to collect status snapshot: {err}"))?;

    tray::update_tray_visuals(&app, &snapshot);
    Ok((*snapshot).clone())
}

#[tauri::command]
pub async fn get_settings(app: AppHandle) -> Result<DesktopSettingsPayloadDto, String> {
    let prefs = app.state::<DesktopAppState>().preferences();
    tokio::task::spawn_blocking(move || status::build_settings_payload(prefs))
        .await
        .map_err(|err| format!("Failed to load desktop settings: {err}"))
}

#[tauri::command]
pub async fn save_gui_preferences(
    app: AppHandle,
    prefs: GuiPreferencesDto,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    let _guard = state.prefs_lock.lock().await;

    let prefs_to_save = prefs.clone();
    let save_result =
        tokio::task::spawn_blocking(move || preferences::save_gui_preferences(&prefs_to_save))
            .await
            .map_err(|err| format!("Failed to run GUI preferences save task: {err}"))?;

    if let Err(err) = save_result {
        return Ok(ActionResultDto {
            ok: false,
            message: format!("Failed to save GUI preferences: {err}"),
            needs_restart: None,
            cancelled: None,
            code: None,
            snapshot: None,
        });
    }

    state.set_preferences(prefs.clone());
    let snapshot = state.last_snapshot();
    let tray_language = prefs.language;

    let app_clone = app.clone();
    let prefs_for_tray = prefs;
    let tray_sync_result = tokio::task::spawn_blocking(move || {
        tray::setup_or_sync_tray(&app_clone, &prefs_for_tray, snapshot.as_deref())
    })
    .await;

    let tray_sync_err = match tray_sync_result {
        Ok(Ok(())) => None,
        Ok(Err(err)) => Some(err.to_string()),
        Err(err) => Some(err.to_string()),
    };

    if let Some(err) = tray_sync_err {
        warn!(
            error = %err,
            surface = TRAY_SURFACE_NAME,
            "failed to synchronize tray after saving GUI preferences"
        );
        crate::wake_status_poller(&app);
        return Ok(ActionResultDto {
            ok: false,
            message: format_tray_sync_error(err),
            needs_restart: None,
            cancelled: None,
            code: None,
            snapshot: None,
        });
    }

    tray::set_tray_language(&app, tray_language);
    crate::wake_status_poller(&app);

    Ok(ActionResultDto {
        ok: true,
        message: "GUI preferences saved.".to_string(),
        needs_restart: None,
        cancelled: None,
        code: None,
        snapshot: None,
    })
}

#[tauri::command]
pub async fn toggle_protection(
    app: AppHandle,
    connect: Option<bool>,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let Some(busy_guard) = TrayToggleBusyGuard::try_claim(&app) else {
        return Ok(busy_result(state.active_operation()));
    };

    let app_for_target = app.clone();
    let target = tokio::task::spawn_blocking(move || resolve_toggle_target(&app_for_target, connect))
        .await
        .map_err(|err| format!("Failed to resolve protection state: {err}"))?;

    let should_connect = match target {
        Ok(should_connect) => should_connect,
        Err(not_installed) => {
            drop(busy_guard);
            return Ok(not_installed);
        }
    };

    let op_guard = ServiceOperationGuard::set(
        &app,
        if should_connect {
            ServiceOperationDto::Resuming
        } else {
            ServiceOperationDto::Pausing
        },
    );

    let mut result = tokio::task::spawn_blocking(move || actions::toggle_protection(should_connect))
        .await
        .map_err(|err| format!("Failed to toggle protection: {err}"))?;

    drop(op_guard);
    let wait_for_live = should_connect && result.ok && result.needs_restart != Some(true);
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    drop(busy_guard);
    Ok(result)
}

#[tauri::command]
pub async fn switch_engine(
    app: AppHandle,
    engine: EngineModeDto,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::SwitchingEngine);
    let mut result = tokio::task::spawn_blocking(move || actions::switch_engine(engine))
        .await
        .map_err(|err| format!("Failed to switch engine: {err}"))?;

    drop(op_guard);
    let wait_for_live =
        result.ok && result.needs_restart != Some(true) && result.message.contains("restarted");
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn save_dns_rules(
    app: AppHandle,
    update: DnsConfigUpdateDto,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::SavingConfig);
    let mut result = tokio::task::spawn_blocking(move || actions::save_dns_and_rules(update))
        .await
        .map_err(|err| format!("Failed to save DNS and routing rules: {err}"))?;

    drop(op_guard);
    let wait_for_live =
        result.ok && result.needs_restart != Some(true) && result.message.contains("restarted");
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn get_split_tunnel() -> Result<SplitTunnelPayloadDto, String> {
    tokio::task::spawn_blocking(split::build_split_tunnel_payload)
        .await
        .map_err(|err| format!("Failed to load split-tunnel configuration: {err}"))
}

#[tauri::command]
pub async fn save_split_tunnel(
    app: AppHandle,
    request: SplitTunnelSaveRequestDto,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::SavingConfig);
    let mut result = tokio::task::spawn_blocking(move || split::save_split_tunnel_config(request))
        .await
        .map_err(|err| format!("Failed to save split-tunnel configuration: {err}"))?;

    drop(op_guard);
    let wait_for_live =
        result.ok && result.needs_restart != Some(true) && result.message.contains("restarted");
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn get_app_icons(
    apps: Vec<AppIconRequestDto>,
) -> Result<HashMap<String, String>, String> {
    tokio::task::spawn_blocking(move || app_icons::resolve_app_icons(&apps))
        .await
        .map_err(|err| format!("Failed to resolve application icons: {err}"))
}

#[tauri::command]
pub async fn run_diagnostics(app: AppHandle) -> Result<DiagnosticsReportDto, String> {
    let app_clone = app.clone();
    let snapshot = tokio::task::spawn_blocking(move || {
        let state = app_clone.state::<DesktopAppState>();
        status::collect_status_snapshot(&state, true)
    })
    .await
    .map_err(|err| format!("Failed to collect status snapshot for diagnostics: {err}"))?;

    tray::update_tray_visuals(&app, &snapshot);
    Ok(diagnostics::run_desktop_diagnostics(&snapshot).await)
}

#[tauri::command]
pub async fn install_service(
    app: AppHandle,
    engine: Option<EngineModeDto>,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::Installing);
    let mut result =
        tokio::task::spawn_blocking(move || actions::install_background_service(engine))
            .await
            .map_err(|err| format!("Failed to install background service: {err}"))?;

    drop(op_guard);
    let wait_for_live = result.ok && result.needs_restart != Some(true);
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn upgrade_service(app: AppHandle) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::Upgrading);
    let mut result = tokio::task::spawn_blocking(actions::upgrade_background_service)
        .await
        .map_err(|err| format!("Failed to upgrade background service: {err}"))?;

    drop(op_guard);
    let wait_for_live = result.ok
        && result.needs_restart != Some(true)
        && result.code != Some(ActionErrorCodeDto::AlreadyUpToDate);
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn repair_service(
    app: AppHandle,
    engine: Option<EngineModeDto>,
) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::Repairing);
    let mut result =
        tokio::task::spawn_blocking(move || actions::repair_background_service(engine))
            .await
            .map_err(|err| format!("Failed to repair background service: {err}"))?;

    drop(op_guard);
    let wait_for_live = result.ok && result.needs_restart != Some(true);
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, wait_for_live)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn uninstall_service(app: AppHandle) -> Result<ActionResultDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::set(&app, ServiceOperationDto::Uninstalling);
    let mut result = tokio::task::spawn_blocking(actions::uninstall_background_service)
        .await
        .map_err(|err| format!("Failed to uninstall background service: {err}"))?;

    drop(op_guard);
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, false)
        .await
        .ok();
    Ok(result)
}

#[tauri::command]
pub async fn check_updates() -> Result<UpdateCheckPayloadDto, String> {
    actions::check_for_updates().await
}

#[tauri::command]
pub async fn open_app_folder(
    kind: Option<String>,
    target: Option<String>,
) -> Result<ActionResultDto, String> {
    let selected = kind
        .or(target)
        .unwrap_or_else(|| "config".to_string())
        .trim()
        .to_ascii_lowercase();

    tokio::task::spawn_blocking(move || {
        let dir = match selected.as_str() {
            "config" | "" => {
                let cfg_path = status::active_config_path();
                cfg_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(PathBuf::from)
                    .unwrap_or(cfg_path)
            }
            "logs" => status::default_logs_dir(),
            "app" => match std::env::current_exe()
                .ok()
                .and_then(|p| {
                    p.parent()
                        .filter(|d| !d.as_os_str().is_empty())
                        .map(PathBuf::from)
                })
                .or_else(|| {
                    vdpi::service::installed_binary_path().ok().and_then(|p| {
                        p.parent()
                            .filter(|d| !d.as_os_str().is_empty())
                            .map(PathBuf::from)
                    })
                }) {
                Some(dir) => dir,
                None => {
                    return ActionResultDto {
                        ok: false,
                        message: "Could not locate application directory.".to_string(),
                        needs_restart: None,
                        cancelled: None,
                        code: None,
                        snapshot: None,
                    };
                }
            },
            _ => {
                return ActionResultDto {
                    ok: false,
                    message: "Unknown folder target. Expected 'config', 'logs', or 'app'."
                        .to_string(),
                    needs_restart: None,
                    cancelled: None,
                    code: None,
                    snapshot: None,
                };
            }
        };

        actions::open_directory_in_os(&dir)
    })
    .await
    .map_err(|err| format!("Failed to open application folder: {err}"))
}

#[tauri::command]
pub async fn open_external_url(url: String) -> ActionResultDto {
    tokio::task::spawn_blocking(move || actions::open_external_url(&url))
        .await
        .unwrap_or_else(|err| ActionResultDto {
            ok: false,
            message: format!("Failed to open external URL: {err}"),
            needs_restart: None,
            cancelled: None,
            code: None,
            snapshot: None,
        })
}

#[tauri::command]
pub fn quit_app(app: AppHandle) -> Result<(), String> {
    if let Some(state) = app.try_state::<DesktopAppState>() {
        state.set_quitting(true);
    }
    crate::wake_status_poller(&app);
    sidecar::sweep_stale_temp_files();
    tray::remove_tray_cleanly(&app);
    app.exit(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tray_sync_error_uses_platform_appropriate_surface_name() {
        assert_eq!(
            format_tray_sync_error_for_surface("menu bar", "timed out"),
            "GUI preferences saved, but failed to synchronize menu bar: timed out"
        );
        assert_eq!(
            format_tray_sync_error_for_surface("system tray", "timed out"),
            "GUI preferences saved, but failed to synchronize system tray: timed out"
        );

        #[cfg(target_os = "macos")]
        {
            assert_eq!(TRAY_SURFACE_NAME, "menu bar");
            assert_eq!(
                format_tray_sync_error("boom"),
                "GUI preferences saved, but failed to synchronize menu bar: boom"
            );
        }

        #[cfg(not(target_os = "macos"))]
        {
            assert_eq!(TRAY_SURFACE_NAME, "system tray");
            assert_eq!(
                format_tray_sync_error("boom"),
                "GUI preferences saved, but failed to synchronize system tray: boom"
            );
        }
    }
}
