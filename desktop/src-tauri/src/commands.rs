use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager, State};
use tracing::{debug, warn};
use vdpi_core::config::{RuntimeConfig, VpnCoexistence};

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

/// RAII guard ensuring `DesktopAppState::active_operation` is acquired
/// atomically after draining `snapshot_lock` and cleared on abnormal exit/panic
/// (emitting a cleared snapshot and waking the poller) unless disarmed on clean
/// handoff to [`refresh_and_broadcast_status_with_readiness`].
struct ServiceOperationGuard {
    app: AppHandle,
    armed: bool,
}

impl ServiceOperationGuard {
    async fn acquire(app: &AppHandle, op: ServiceOperationDto) -> Self {
        let app_clone = app.clone();
        let emitted_snapshot = tokio::task::spawn_blocking(move || {
            let state = app_clone.try_state::<DesktopAppState>()?;
            let _snapshot_guard = state
                .snapshot_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.set_active_operation(Some(op));
            state.last_snapshot().map(|last| {
                let mut pending = (*last).clone();
                pending.snapshot_seq = state.next_snapshot_seq();
                pending.pending_operation = Some(op);
                let pending_arc = std::sync::Arc::new(pending);
                state.set_last_snapshot(std::sync::Arc::clone(&pending_arc));
                pending_arc
            })
        })
        .await
        .ok()
        .flatten();

        if let Some(pending_arc) = emitted_snapshot {
            if crate::is_main_window_actively_visible(app) {
                if let Err(err) =
                    app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &*pending_arc)
                {
                    debug!(error = %err, "failed to emit pending vdpi://status event");
                }
            }
        }

        Self {
            app: app.clone(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ServiceOperationGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(state) = self.app.try_state::<DesktopAppState>() {
            let cleared_snapshot = {
                let _snapshot_guard = state
                    .snapshot_lock
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.set_active_operation(None);
                state.last_snapshot().map(|last| {
                    let mut cleared = (*last).clone();
                    cleared.snapshot_seq = state.next_snapshot_seq();
                    cleared.pending_operation = None;
                    let cleared_arc = std::sync::Arc::new(cleared);
                    state.set_last_snapshot(std::sync::Arc::clone(&cleared_arc));
                    cleared_arc
                })
            };
            if let Some(cleared_arc) = cleared_snapshot {
                if crate::is_main_window_actively_visible(&self.app) {
                    if let Err(err) = self.app.emit_to(
                        tray::MAIN_WINDOW_LABEL,
                        STATUS_EVENT_NAME,
                        &*cleared_arc,
                    ) {
                        debug!(
                            error = %err,
                            "failed to emit cleared pending vdpi://status event on abnormal drop"
                        );
                    }
                }
            }
        }
        crate::wake_status_poller(&self.app);
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

pub(crate) fn busy_result_for_operation(active_op: Option<ServiceOperationDto>) -> ActionResultDto {
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
        Some(ServiceOperationDto::ResettingNetwork) => {
            "Network reset is already in progress.".to_string()
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

/// RAII visual guard ensuring tray toggle busy indicator is always cleared even
/// if the async task is cancelled or panics. Mutual exclusion between tray and
/// UI actions is unified exclusively on `DesktopAppState::action_lock`.
pub struct TrayToggleBusyGuard {
    app: AppHandle,
}

impl TrayToggleBusyGuard {
    pub(crate) fn acquire(app: &AppHandle) -> Self {
        tray::set_tray_toggle_busy(app, true);
        Self { app: app.clone() }
    }
}

impl Drop for TrayToggleBusyGuard {
    fn drop(&mut self) {
        tray::set_tray_toggle_busy(&self.app, false);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadinessWait {
    None,
    Live,
    LiveFreshVersion,
    LiveEngine(EngineModeDto),
}

fn configured_vpn_coexistence(config_path: &str) -> VpnCoexistence {
    let trimmed = config_path.trim();
    if trimmed.is_empty() {
        return RuntimeConfig::default().vpn_coexistence;
    }
    match vdpi::config_file::load_file_config_or_default(Some(Path::new(trimmed)), false) {
        Ok((_, file_cfg)) => file_cfg
            .vpn_coexistence
            .unwrap_or_else(|| RuntimeConfig::default().vpn_coexistence),
        Err(_) => RuntimeConfig::default().vpn_coexistence,
    }
}

fn is_readiness_snapshot_ready(
    wait: ReadinessWait,
    snap: &DesktopStatusSnapshotDto,
    is_quitting: bool,
    vpn_auto_yield: bool,
) -> bool {
    if is_quitting {
        return true;
    }
    match wait {
        ReadinessWait::None => true,
        ReadinessWait::Live | ReadinessWait::LiveFreshVersion | ReadinessWait::LiveEngine(_) => {
            if matches!(
                snap.service_state,
                ServiceStateDto::NotInstalled | ServiceStateDto::Stopped
            ) {
                return true;
            }
            if snap.service_state == ServiceStateDto::Running
                && snap.vpn_conflict.is_some()
                && vpn_auto_yield
            {
                return true;
            }
            match wait {
                ReadinessWait::Live => snap.live.is_some(),
                ReadinessWait::LiveFreshVersion => snap.live.is_some() && !snap.live_version_stale,
                ReadinessWait::LiveEngine(target) => {
                    snap.live.as_ref().is_some_and(|live| live.engine == target)
                }
                ReadinessWait::None => true,
            }
        }
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

/// Invalidates cached static probes on the first readiness attempt, optionally
/// waits up to 2.5 seconds (polling fast live telemetry every 250ms) for the
/// restarted daemon to become reachable (and non-stale on upgrade/repair), keeps
/// `active_operation` suppression active until right before the final broadcast,
/// updates tray visuals, pushes the final `vdpi://status` snapshot, wakes the
/// background poller, and returns the final snapshot.
async fn refresh_and_broadcast_status_with_readiness(
    app: &AppHandle,
    mut op_guard: Option<ServiceOperationGuard>,
    wait: ReadinessWait,
) -> Result<Box<DesktopStatusSnapshotDto>, String> {
    let deadline = Instant::now() + READINESS_WAIT_MAX;
    let mut attempt = 0usize;

    let snapshot = loop {
        let app_clone = app.clone();
        let force_full_refresh = attempt == 0;
        let (snap, vpn_auto_yield) = tokio::task::spawn_blocking(move || {
            let state = app_clone.state::<DesktopAppState>();
            if force_full_refresh {
                state.invalidate_static_cache();
            }
            let snap = status::collect_status_snapshot_for_readiness(&state, force_full_refresh);
            let vpn_auto_yield = if wait != ReadinessWait::None && snap.vpn_conflict.is_some() {
                configured_vpn_coexistence(&snap.config_path) == VpnCoexistence::AutoYield
            } else {
                false
            };
            (snap, vpn_auto_yield)
        })
        .await
        .map_err(|err| format!("Failed to refresh status snapshot: {err}"))?;

        let is_quitting = app
            .try_state::<DesktopAppState>()
            .is_some_and(|state| state.is_quitting());
        if is_readiness_snapshot_ready(wait, &snap, is_quitting, vpn_auto_yield) {
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

    let final_snapshot = if let Some(mut guard) = op_guard.take() {
        let app_clone = app.clone();
        let base_snap = std::sync::Arc::clone(&snapshot);
        let cleared = tokio::task::spawn_blocking(move || {
            let state = app_clone.state::<DesktopAppState>();
            let _snapshot_guard = state
                .snapshot_lock
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.set_active_operation(None);
            let mut final_dto = (*base_snap).clone();
            final_dto.snapshot_seq = state.next_snapshot_seq();
            final_dto.pending_operation = None;
            let final_arc = std::sync::Arc::new(final_dto);
            state.set_last_snapshot(std::sync::Arc::clone(&final_arc));
            final_arc
        })
        .await
        .map_err(|err| format!("Failed to finalize status snapshot: {err}"));

        match cleared {
            Ok(final_arc) => {
                guard.disarm();
                final_arc
            }
            Err(err) => {
                // Keep `guard` armed so its Drop clears active_operation, emits, and wakes poller.
                drop(guard);
                return Err(err);
            }
        }
    } else {
        snapshot
    };

    tray::update_tray_visuals(app, &final_snapshot);
    if crate::is_main_window_actively_visible(app) {
        if let Err(err) =
            app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &final_snapshot)
        {
            debug!(error = %err, "failed to emit vdpi://status event");
        }
    }
    crate::wake_status_poller(app);

    Ok(Box::new((*final_snapshot).clone()))
}

fn resolve_toggle_target_from_snapshot(
    snapshot: &DesktopStatusSnapshotDto,
    connect: Option<bool>,
) -> Result<bool, ActionResultDto> {
    if snapshot.service_state == ServiceStateDto::NotInstalled {
        let can_pause_orphan_live = match connect {
            Some(false) => snapshot.live.is_some(),
            None => snapshot.live.as_ref().is_some_and(|live| live.running),
            Some(true) => false,
        };
        if can_pause_orphan_live {
            return Ok(false);
        }
        return Err(ActionResultDto {
            ok: false,
            message: "Background service is not installed. Install the service from Installation or Settings first."
                .to_string(),
            needs_restart: None,
            cancelled: None,
            code: None,
            snapshot: Some(Box::new(snapshot.clone())),
        });
    }

    if connect == Some(true)
        && snapshot.service_state == ServiceStateDto::Running
        && snapshot.live.is_none()
    {
        if let Some(vpn_name) = snapshot.vpn_conflict.as_deref() {
            let trimmed = vpn_name.trim();
            let message = if trimmed.is_empty() {
                "Protection is already running in standby while yielded to an active VPN. Disconnect the VPN or change VPN coexistence in Settings to resume.".to_string()
            } else {
                format!(
                    "Protection is already running in standby while yielded to active VPN ({trimmed}). Disconnect the VPN or change VPN coexistence in Settings to resume."
                )
            };
            return Err(ActionResultDto {
                ok: true,
                message,
                needs_restart: Some(false),
                cancelled: None,
                code: None,
                snapshot: Some(Box::new(snapshot.clone())),
            });
        }
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

fn resolve_toggle_target(app: &AppHandle, connect: Option<bool>) -> Result<bool, ActionResultDto> {
    let state = app.state::<DesktopAppState>();
    let snapshot = status::collect_status_snapshot(&state, true);
    resolve_toggle_target_from_snapshot(&snapshot, connect)
}

/// Serialized handler invoked when the user toggles protection from the native
/// system tray menu. Takes ownership of the `action_lock` guard acquired
/// synchronously on the tray click plus the visual `TrayToggleBusyGuard`, runs
/// the toggle action, refreshes status, and emits `vdpi://tray-action-result`.
pub async fn handle_tray_toggle_protection(
    app: AppHandle,
    _action_guard: tokio::sync::OwnedMutexGuard<()>,
    busy_guard: TrayToggleBusyGuard,
) {
    let Some(state) = app.try_state::<DesktopAppState>() else {
        drop(busy_guard);
        return;
    };
    if state.is_quitting() {
        drop(busy_guard);
        return;
    }

    let app_for_target = app.clone();
    let target = tokio::task::spawn_blocking(move || resolve_toggle_target(&app_for_target, None))
        .await;

    let mut action_result = match target {
        Ok(Ok(should_connect)) => {
            let op_guard = ServiceOperationGuard::acquire(
                &app,
                if should_connect {
                    ServiceOperationDto::Resuming
                } else {
                    ServiceOperationDto::Pausing
                },
            )
            .await;
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
            let wait = if should_connect && result.ok && result.needs_restart != Some(true) {
                ReadinessWait::Live
            } else {
                ReadinessWait::None
            };
            result.snapshot =
                refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        action_result.snapshot =
            refresh_and_broadcast_status_with_readiness(&app, None, ReadinessWait::None)
                .await
                .ok();
    }
    // Always release visual busy state before `_action_guard` drops.
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
        if force_refresh && !state.is_mutating_install_operation_active() {
            state.invalidate_static_cache();
        }
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
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let _guard = state.prefs_lock.lock().await;
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

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
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let busy_guard = TrayToggleBusyGuard::acquire(&app);

    let app_for_target = app.clone();
    let target = tokio::task::spawn_blocking(move || resolve_toggle_target(&app_for_target, connect))
        .await
        .map_err(|err| format!("Failed to resolve protection state: {err}"))?;

    let should_connect = match target {
        Ok(should_connect) => should_connect,
        Err(early_result) => {
            if let Some(ref snap) = early_result.snapshot {
                tray::update_tray_visuals(&app, snap.as_ref());
            }
            drop(busy_guard);
            return Ok(early_result);
        }
    };

    let op_guard = ServiceOperationGuard::acquire(
        &app,
        if should_connect {
            ServiceOperationDto::Resuming
        } else {
            ServiceOperationDto::Pausing
        },
    )
    .await;

    let mut result = tokio::task::spawn_blocking(move || actions::toggle_protection(should_connect))
        .await
        .map_err(|err| format!("Failed to toggle protection: {err}"))?;

    let wait = if should_connect && result.ok && result.needs_restart != Some(true) {
        ReadinessWait::Live
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::SwitchingEngine).await;
    let mut result = tokio::task::spawn_blocking(move || actions::switch_engine(engine))
        .await
        .map_err(|err| format!("Failed to switch engine: {err}"))?;

    let wait = if result.ok && result.needs_restart != Some(true) {
        ReadinessWait::LiveEngine(engine)
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::SavingConfig).await;
    let mut result = tokio::task::spawn_blocking(move || actions::save_dns_and_rules(update))
        .await
        .map_err(|err| format!("Failed to save DNS and routing rules: {err}"))?;

    let wait = if result.ok && result.needs_restart != Some(true) && result.message.contains("restarted")
    {
        ReadinessWait::Live
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::SavingConfig).await;
    let mut result = tokio::task::spawn_blocking(move || split::save_split_tunnel_config(request))
        .await
        .map_err(|err| format!("Failed to save split-tunnel configuration: {err}"))?;

    let wait = if result.ok && result.needs_restart != Some(true) && result.message.contains("restarted")
    {
        ReadinessWait::Live
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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

fn diagnostics_busy_error(active_op: Option<ServiceOperationDto>) -> Option<String> {
    active_op.map(|op| busy_result_for_operation(Some(op)).message)
}

#[tauri::command]
pub async fn run_diagnostics(app: AppHandle) -> Result<DiagnosticsReportDto, String> {
    let state = app.state::<DesktopAppState>();
    if state.is_quitting() {
        return Err("Application is shutting down.".to_string());
    }
    if let Some(busy_msg) = diagnostics_busy_error(state.active_operation()) {
        return Err(busy_msg);
    }

    let app_clone = app.clone();
    let snapshot = tokio::task::spawn_blocking(move || {
        let state = app_clone.state::<DesktopAppState>();
        if let Some(busy_msg) = diagnostics_busy_error(state.active_operation()) {
            return Err(busy_msg);
        }
        let snapshot = status::collect_status_snapshot(&state, true);
        if let Some(busy_msg) = diagnostics_busy_error(snapshot.pending_operation) {
            return Err(busy_msg);
        }
        Ok(snapshot)
    })
    .await
    .map_err(|err| format!("Failed to collect status snapshot for diagnostics: {err}"))??;

    tray::update_tray_visuals(&app, &snapshot);
    if crate::is_main_window_actively_visible(&app) {
        if let Err(err) = app.emit_to(tray::MAIN_WINDOW_LABEL, STATUS_EVENT_NAME, &*snapshot) {
            debug!(
                error = %err,
                "failed to emit fresh vdpi://status event during diagnostics"
            );
        }
    }
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::Installing).await;
    let mut result =
        tokio::task::spawn_blocking(move || actions::install_background_service(engine))
            .await
            .map_err(|err| format!("Failed to install background service: {err}"))?;

    let wait = if result.ok && result.needs_restart != Some(true) {
        ReadinessWait::Live
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::Upgrading).await;
    let mut result = tokio::task::spawn_blocking(actions::upgrade_background_service)
        .await
        .map_err(|err| format!("Failed to upgrade background service: {err}"))?;

    let wait = if result.ok
        && result.needs_restart != Some(true)
        && result.code != Some(ActionErrorCodeDto::AlreadyUpToDate)
    {
        ReadinessWait::LiveFreshVersion
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::Repairing).await;
    let mut result =
        tokio::task::spawn_blocking(move || actions::repair_background_service(engine))
            .await
            .map_err(|err| format!("Failed to repair background service: {err}"))?;

    let wait = if result.ok && result.needs_restart != Some(true) {
        ReadinessWait::LiveFreshVersion
    } else {
        ReadinessWait::None
    };
    result.snapshot = refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), wait)
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
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard = ServiceOperationGuard::acquire(&app, ServiceOperationDto::Uninstalling).await;
    let mut result = tokio::task::spawn_blocking(actions::uninstall_background_service)
        .await
        .map_err(|err| format!("Failed to uninstall background service: {err}"))?;

    result.snapshot =
        refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), ReadinessWait::None)
            .await
            .ok();
    Ok(result)
}

#[tauri::command]
pub async fn reset_network_settings(
    app: AppHandle,
    state: State<'_, DesktopAppState>,
) -> Result<ActionResultDto, String> {
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }
    let Ok(_guard) = state.action_lock.try_lock() else {
        return Ok(busy_result_for_operation(state.active_operation()));
    };
    if state.is_quitting() {
        return Ok(shutting_down_result());
    }

    let op_guard =
        ServiceOperationGuard::acquire(&app, ServiceOperationDto::ResettingNetwork).await;
    let mut result = match tokio::task::spawn_blocking(actions::reset_network_settings).await {
        Ok(res) => res,
        Err(err) => ActionResultDto::error(format!("Failed to reset network settings: {err}")),
    };

    result.snapshot =
        refresh_and_broadcast_status_with_readiness(&app, Some(op_guard), ReadinessWait::None)
            .await
            .ok();
    Ok(result)
}

#[tauri::command]
pub async fn check_updates(force: Option<bool>) -> Result<UpdateCheckPayloadDto, String> {
    actions::check_for_updates_with_force(force.unwrap_or(false)).await
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

    #[test]
    fn readiness_predicate_checks_fresh_version_not_installed_short_circuit_and_vpn_yield() {
        use crate::models::{
            CliVersionRelationDto, LiveTelemetryDto, SplitTunnelModeDto, WintunStatusDto,
        };

        let sample_live = LiveTelemetryDto {
            running: true,
            engine: EngineModeDto::Tun,
            addr: "127.0.0.1".to_string(),
            port: 8080,
            socks_port: None,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: None,
            vpn_conflict: None,
            version: Some("0.6.0".to_string()),
            mode: Some("auto".to_string()),
            doh_enabled: true,
            dns_display: "1.1.1.1".to_string(),
            block_quic: true,
            active_connections: 0,
            total_connections: 0,
            learned_hosts: 0,
            isp_stage: None,
            udp_flows_active: 0,
            quic_blocked: 0,
            dns_queries: 0,
            rss_kb: None,
            bytes_rx: 0,
            bytes_tx: 0,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            tls_handshakes: 0,
            auto_heal_escalations: 0,
        };

        let mut snap = DesktopStatusSnapshotDto {
            snapshot_seq: 1,
            app_version: "0.6.1".to_string(),
            platform: "windows".to_string(),
            service_state: ServiceStateDto::Running,
            installed_version: Some("0.6.1".to_string()),
            configured_engine: EngineModeDto::Tun,
            live: Some(sample_live),
            vpn_conflict: None,
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            split_tunnel_mode: SplitTunnelModeDto::All,
            split_tunnel_count: 0,
            config_path: String::new(),
            logs_dir: String::new(),
            tray_supported: true,
            config_warning: None,
            bundled_engine_version: Some("0.6.1".to_string()),
            cli_version_relation: CliVersionRelationDto::UpToDate,
            can_install_from_bundle: true,
            live_version_stale: true,
            pending_operation: Some(ServiceOperationDto::Upgrading),
            running_from_readonly_dmg: false,
        };

        // LiveFreshVersion keeps waiting while live daemon is still on old version.
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::None,
            &snap,
            false,
            true
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::Live,
            &snap,
            false,
            true
        ));
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            true
        ));
        // LiveEngine waits until live telemetry reports the exact target engine.
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Tun),
            &snap,
            false,
            true
        ));
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Proxy),
            &snap,
            false,
            true
        ));

        // Once live daemon reports the upgraded version, LiveFreshVersion exits ready.
        snap.live_version_stale = false;
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            true
        ));

        // Offline service keeps waiting until live telemetry appears...
        snap.live = None;
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::Live,
            &snap,
            false,
            true
        ));
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            true
        ));
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Tun),
            &snap,
            false,
            true
        ));
        // ...unless quitting, VPN-yielded while running in AutoYield mode, Stopped, or NotInstalled.
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            true,
            false
        ));
        snap.vpn_conflict = Some("WireGuard".to_string());
        // VPN conflict only short-circuits when vpn_coexistence is AutoYield (not Warn/Off).
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            false
        ));
        assert!(!is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Tun),
            &snap,
            false,
            false
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            true
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Tun),
            &snap,
            false,
            true
        ));
        snap.vpn_conflict = None;

        // Stopped service short-circuits immediately so stopped repair/upgrade/switch never stalls.
        snap.service_state = ServiceStateDto::Stopped;
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::Live,
            &snap,
            false,
            false
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            false
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Proxy),
            &snap,
            false,
            false
        ));

        snap.service_state = ServiceStateDto::NotInstalled;
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::Live,
            &snap,
            false,
            false
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveFreshVersion,
            &snap,
            false,
            false
        ));
        assert!(is_readiness_snapshot_ready(
            ReadinessWait::LiveEngine(EngineModeDto::Tun),
            &snap,
            false,
            false
        ));
    }

    #[test]
    fn toggle_target_allows_pausing_orphan_live_and_avoids_noop_resume_when_vpn_yielded() {
        use crate::models::{
            CliVersionRelationDto, LiveTelemetryDto, SplitTunnelModeDto, WintunStatusDto,
        };

        let sample_live = LiveTelemetryDto {
            running: true,
            engine: EngineModeDto::Proxy,
            addr: "127.0.0.1".to_string(),
            port: 8080,
            socks_port: Some(1080),
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            version: Some("0.6.3".to_string()),
            mode: Some("combo".to_string()),
            doh_enabled: true,
            dns_display: "1.1.1.1".to_string(),
            block_quic: true,
            active_connections: 0,
            total_connections: 0,
            learned_hosts: 0,
            isp_stage: None,
            udp_flows_active: 0,
            quic_blocked: 0,
            dns_queries: 0,
            rss_kb: None,
            bytes_rx: 0,
            bytes_tx: 0,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            tls_handshakes: 0,
            auto_heal_escalations: 0,
        };

        let mut snap = DesktopStatusSnapshotDto {
            snapshot_seq: 1,
            app_version: "0.6.3".to_string(),
            platform: "windows".to_string(),
            service_state: ServiceStateDto::NotInstalled,
            installed_version: None,
            configured_engine: EngineModeDto::Proxy,
            live: Some(sample_live),
            vpn_conflict: None,
            wintun: WintunStatusDto {
                required: false,
                ready: true,
                message: None,
            },
            split_tunnel_mode: SplitTunnelModeDto::All,
            split_tunnel_count: 0,
            config_path: String::new(),
            logs_dir: String::new(),
            tray_supported: true,
            config_warning: None,
            bundled_engine_version: Some("0.6.3".to_string()),
            cli_version_relation: CliVersionRelationDto::NotInstalled,
            can_install_from_bundle: true,
            live_version_stale: false,
            pending_operation: None,
            running_from_readonly_dmg: false,
        };

        // Orphan foreground daemon with NotInstalled service can be paused explicitly or via tray toggle.
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, Some(false)).ok(),
            Some(false)
        );
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, None).ok(),
            Some(false)
        );
        let err_connect = resolve_toggle_target_from_snapshot(&snap, Some(true))
            .expect_err("cannot resume uninstalled service");
        assert!(!err_connect.ok);
        assert!(err_connect.message.contains("not installed"));

        // NotInstalled with no live daemon rejects both pause and resume.
        snap.live = None;
        assert!(resolve_toggle_target_from_snapshot(&snap, Some(false)).is_err());
        assert!(resolve_toggle_target_from_snapshot(&snap, None).is_err());

        // Running service yielded to VPN with `connect == Some(true)` returns non-mutating explanation.
        snap.service_state = ServiceStateDto::Running;
        snap.vpn_conflict = Some("WireGuard (wg0)".to_string());
        let yielded = resolve_toggle_target_from_snapshot(&snap, Some(true))
            .expect_err("yielded VPN state must not run no-op elevated resume");
        assert!(yielded.ok);
        assert_eq!(yielded.needs_restart, Some(false));
        assert!(yielded.message.contains("WireGuard (wg0)"));
        assert!(yielded.message.contains("yielded"));
        assert!(yielded.snapshot.is_some());

        // Pausing a VPN-yielded running service still proceeds normally.
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, Some(false)).ok(),
            Some(false)
        );
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, None).ok(),
            Some(false)
        );

        // Stopped service toggles to connect.
        snap.service_state = ServiceStateDto::Stopped;
        snap.vpn_conflict = None;
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, None).ok(),
            Some(true)
        );
        assert_eq!(
            resolve_toggle_target_from_snapshot(&snap, Some(true)).ok(),
            Some(true)
        );
    }

    #[test]
    fn configured_vpn_coexistence_reads_config_file_and_defaults_to_auto_yield() {
        assert_eq!(configured_vpn_coexistence(""), VpnCoexistence::AutoYield);
        assert_eq!(configured_vpn_coexistence("   "), VpnCoexistence::AutoYield);

        let base = std::env::temp_dir().join(format!(
            "vdpi-commands-vpn-coexist-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&base);
        let warn_cfg = base.join("warn.toml");
        let off_cfg = base.join("off.toml");
        std::fs::write(&warn_cfg, "vpn_coexistence = \"warn\"\n").expect("write warn.toml");
        std::fs::write(&off_cfg, "vpn_coexistence = \"off\"\n").expect("write off.toml");

        assert_eq!(
            configured_vpn_coexistence(&warn_cfg.display().to_string()),
            VpnCoexistence::Warn
        );
        assert_eq!(
            configured_vpn_coexistence(&off_cfg.display().to_string()),
            VpnCoexistence::Off
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn diagnostics_busy_error_blocks_all_mutating_service_operations() {
        assert!(diagnostics_busy_error(None).is_none());
        for op in [
            ServiceOperationDto::Installing,
            ServiceOperationDto::Upgrading,
            ServiceOperationDto::Repairing,
            ServiceOperationDto::Uninstalling,
            ServiceOperationDto::ResettingNetwork,
            ServiceOperationDto::Resuming,
            ServiceOperationDto::Pausing,
            ServiceOperationDto::SwitchingEngine,
            ServiceOperationDto::SavingConfig,
        ] {
            let msg = diagnostics_busy_error(Some(op))
                .expect("any active service operation must block diagnostics");
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn busy_result_for_operation_sets_busy_code_for_all_operations() {
        for op in [
            None,
            Some(ServiceOperationDto::Installing),
            Some(ServiceOperationDto::Upgrading),
            Some(ServiceOperationDto::Repairing),
            Some(ServiceOperationDto::Uninstalling),
            Some(ServiceOperationDto::ResettingNetwork),
            Some(ServiceOperationDto::Resuming),
            Some(ServiceOperationDto::Pausing),
            Some(ServiceOperationDto::SwitchingEngine),
            Some(ServiceOperationDto::SavingConfig),
        ] {
            let res = busy_result_for_operation(op);
            assert!(!res.ok);
            assert_eq!(res.code, Some(ActionErrorCodeDto::Busy));
            assert!(!res.message.is_empty());
        }

        let net_reset = busy_result_for_operation(Some(ServiceOperationDto::ResettingNetwork));
        assert!(!net_reset.ok);
        assert_eq!(net_reset.code, Some(ActionErrorCodeDto::Busy));
        assert_eq!(net_reset.message, "Network reset is already in progress.");
    }
}
