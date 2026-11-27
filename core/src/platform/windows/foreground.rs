//! Keep the foreground fail-open PAC proxy lease tied to a detached process. Closing a
//! Windows console can terminate its processes without running any Rust cleanup.
use super::{
    broadcast_environment_change, build_windows_pac_url_with_nonce, clear_all_windows_proxies,
    ensure_safe_state_dir, internet_settings_key, is_reparse_point_attrs,
    is_vdpi_owned_no_proxy_env, is_vdpi_owned_pac_url, is_vdpi_owned_proxy_env,
    is_vdpi_owned_wininet_server, load_saved_windows_proxy_state, next_session_pac_nonce,
    notify_wininet_refresh, path_attributes_no_follow, read_windows_proxy_state_from_path,
    reject_reparse_point, reject_reparse_point_or_dir, remove_windows_proxy_state_at_path,
    reset_winhttp_proxy_if_vdpi, sanitize_captured_wininet_state, sync_wininet_connection_blobs,
    sync_wininet_connection_blobs_restore_manual, SavedWindowsProxyState, SavedWininetHiveState,
    ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_FLAG_OPEN_REPARSE_POINT, NO_PROXY_ENV_VARS, PROXY_ENV_VARS, WINDOWS_PROXY_STATE_FILENAME,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";
const READY: &str = "ready";
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
const GUARD_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
const GUARD_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(20);
static STATE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct Request {
    endpoint: SocketAddr,
    #[serde(default = "default_env_proxy")]
    env_proxy: bool,
    #[serde(default)]
    bypass: Vec<String>,
}

fn default_env_proxy() -> bool {
    true
}

pub struct ForegroundProxy(Child);

fn spawn_guard_process(exe: &Path) -> io::Result<Child> {
    let primary = Command::new(exe)
        .arg(GUARD_ARG)
        .creation_flags(DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    match primary {
        Ok(child) => Ok(child),
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Command::new(exe)
            .arg(GUARD_ARG)
            .creation_flags(DETACHED_PROCESS)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn(),
        Err(err) => Err(err),
    }
}

fn wait_child_bounded_with<S>(
    timeout: Duration,
    poll_interval: Duration,
    mut try_wait_fn: impl FnMut() -> io::Result<Option<S>>,
    mut sleep_fn: impl FnMut(Duration),
) -> io::Result<Option<S>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = try_wait_fn()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        sleep_fn(poll_interval.min(deadline.saturating_duration_since(now)));
    }
}

fn reap_failed_guard_child(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    match wait_child_bounded_with(
        timeout,
        GUARD_WAIT_POLL_INTERVAL,
        || child.try_wait(),
        std::thread::sleep,
    ) {
        Ok(Some(status)) => Some(status),
        Ok(None) | Err(_) => {
            let _ = child.kill();
            child.wait().ok()
        }
    }
}

fn format_guard_startup_failure(
    io_err: Option<&io::Error>,
    response: &str,
    exit_status: Option<ExitStatus>,
) -> anyhow::Error {
    let trimmed = response.trim();
    if !trimmed.is_empty() {
        return anyhow::anyhow!("Windows proxy could not start safely: {trimmed}");
    }
    match (exit_status, io_err) {
        (Some(status), Some(err)) => anyhow::anyhow!(
            "Windows proxy could not start safely: guard exited ({status}) while communicating ({err})"
        ),
        (Some(status), None) => anyhow::anyhow!(
            "Windows proxy could not start safely: guard exited ({status}) without reporting readiness"
        ),
        (None, Some(err)) => anyhow::anyhow!(
            "Windows proxy could not start safely: guard communication failed ({err})"
        ),
        (None, None) => anyhow::anyhow!(
            "Windows proxy could not start safely: guard closed stdout without reporting readiness"
        ),
    }
}

fn activate_with_child(mut child: Child, payload: &[u8]) -> Result<ForegroundProxy> {
    let write_err = {
        let pipe = child.stdin.as_mut().expect("guard stdin was piped");
        pipe.write_all(payload).and_then(|()| pipe.flush()).err()
    };

    if let Some(err) = write_err {
        drop(child.stdin.take());
        let mut response = String::new();
        if let Some(stdout) = child.stdout.take() {
            let _ = BufReader::new(stdout).read_line(&mut response);
        }
        let exit_status = reap_failed_guard_child(&mut child, GUARD_EXIT_TIMEOUT);
        return Err(format_guard_startup_failure(
            Some(&err),
            &response,
            exit_status,
        ));
    }

    let mut response = String::new();
    let read_res = BufReader::new(child.stdout.take().expect("guard stdout was piped"))
        .read_line(&mut response);
    if let Err(err) = read_res {
        drop(child.stdin.take());
        let exit_status = reap_failed_guard_child(&mut child, GUARD_EXIT_TIMEOUT);
        return Err(format_guard_startup_failure(
            Some(&err),
            &response,
            exit_status,
        ));
    }
    if response.trim() != READY {
        drop(child.stdin.take());
        let exit_status = reap_failed_guard_child(&mut child, GUARD_EXIT_TIMEOUT);
        return Err(format_guard_startup_failure(None, &response, exit_status));
    }
    Ok(ForegroundProxy(child))
}

impl ForegroundProxy {
    pub fn activate(endpoint: SocketAddr, env_proxy: bool, bypass: &[String]) -> Result<Self> {
        let exe = std::env::current_exe()?;
        let mut payload = serde_json::to_vec(&Request {
            endpoint,
            env_proxy,
            bypass: bypass.to_vec(),
        })?;
        payload.push(b'\n');
        let child =
            spawn_guard_process(&exe).context("starting the Windows proxy cleanup process")?;
        activate_with_child(child, &payload)
    }
}

#[allow(clippy::too_many_arguments)]
fn shutdown_guard_child_with<C>(
    ctx: &mut C,
    timeout: Duration,
    poll_interval: Duration,
    mut try_wait_fn: impl FnMut(&mut C) -> io::Result<Option<ExitStatus>>,
    mut kill_fn: impl FnMut(&mut C) -> io::Result<()>,
    mut wait_fn: impl FnMut(&mut C) -> io::Result<ExitStatus>,
    sleep_fn: impl FnMut(Duration),
    mut fallback_clear: impl FnMut(),
) {
    match wait_child_bounded_with(timeout, poll_interval, || try_wait_fn(ctx), sleep_fn) {
        Ok(Some(status)) if status.success() => {}
        Ok(Some(status)) => {
            tracing::warn!(?status, "Windows foreground proxy cleanup failed");
        }
        Ok(None) => {
            tracing::warn!(
                timeout_secs = timeout.as_secs(),
                "Windows foreground proxy cleanup timed out; killing guard and running fallback cleanup"
            );
            if let Err(err) = kill_fn(ctx) {
                tracing::warn!(error = %err, "failed to kill hung Windows foreground proxy guard");
            }
            let _ = wait_fn(ctx);
            fallback_clear();
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                "failed polling Windows foreground proxy cleanup process; killing guard and running fallback cleanup"
            );
            let _ = kill_fn(ctx);
            let _ = wait_fn(ctx);
            fallback_clear();
        }
    }
}

impl Drop for ForegroundProxy {
    fn drop(&mut self) {
        // The operating system closes this pipe on abrupt parent exit as well.
        drop(self.0.stdin.take());
        shutdown_guard_child_with(
            &mut self.0,
            GUARD_EXIT_TIMEOUT,
            GUARD_WAIT_POLL_INTERVAL,
            Child::try_wait,
            Child::kill,
            Child::wait,
            std::thread::sleep,
            || {
                if let Err(err) = clear_all_windows_proxies() {
                    tracing::warn!(
                        error = %err,
                        "fallback Windows proxy cleanup failed after guard timeout"
                    );
                }
            },
        );
    }
}

pub fn run_guard() -> Result<()> {
    let result = guard_inner();
    if let Err(e) = &result {
        // Strip embedded newlines so setup failures can be returned over one line.
        let _ = writeln!(
            io::stdout(),
            "{}",
            format!("{e:#}").replace(['\r', '\n'], " ")
        );
    }
    result
}

fn resolve_foreground_state_dir_from(
    local_appdata: Option<OsString>,
    userprofile: Option<OsString>,
) -> Result<PathBuf> {
    if let Some(base) = local_appdata.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(base).join("vdpi"));
    }
    if let Some(home) = userprofile.filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(home).join(".vdpi"));
    }
    bail!("LOCALAPPDATA and USERPROFILE are unavailable");
}

fn foreground_state_dir() -> Result<PathBuf> {
    resolve_foreground_state_dir_from(
        std::env::var_os("LOCALAPPDATA"),
        std::env::var_os("USERPROFILE"),
    )
}

fn acquire_proxy_lease_lock_with(
    lock_path: &Path,
    delays_ms: &[u64],
    sleep_fn: impl FnMut(Duration),
) -> Result<fs::File> {
    if let Some(parent) = lock_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        ensure_safe_state_dir(parent, false)?;
    }
    reject_reparse_point_or_dir(lock_path)?;
    let file = retry_on_transient_av_lock_with(
        delays_ms,
        || {
            if let Some(attrs) = path_attributes_no_follow(lock_path)? {
                if is_reparse_point_attrs(attrs) || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "refusing to open NTFS reparse point or directory as proxy lease lock: {}",
                            lock_path.display()
                        ),
                    ));
                }
            }
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(lock_path)
        },
        sleep_fn,
    )
    .context("acquiring the Windows proxy lease (another vdpi may already be running)")?;
    let meta = file
        .metadata()
        .with_context(|| format!("inspecting proxy lease lock metadata {}", lock_path.display()))?;
    if is_reparse_point_attrs(meta.file_attributes()) || !meta.is_file() {
        bail!(
            "refusing to use NTFS reparse point or non-file as proxy lease lock: {}",
            lock_path.display()
        );
    }
    Ok(file)
}

fn acquire_proxy_lease_lock(lock_path: &Path) -> Result<fs::File> {
    acquire_proxy_lease_lock_with(lock_path, &LEASE_LOCK_RETRY_DELAYS_MS, std::thread::sleep)
}

fn guard_inner() -> Result<()> {
    let mut input = io::stdin().lock();
    let mut request = String::new();
    input.read_line(&mut request)?;
    let request: Request = serde_json::from_str(&request).context("invalid proxy lease request")?;
    let dir = foreground_state_dir()?;
    ensure_safe_state_dir(&dir, false)?;
    let lease_lock = acquire_proxy_lease_lock(&dir.join("proxy-lease.lock"))?;

    let _ = (request.env_proxy, &request.bypass);
    let pac_nonce = next_session_pac_nonce();
    let pac_url =
        build_windows_pac_url_with_nonce(request.endpoint.ip(), request.endpoint.port(), &pac_nonce);
    let inet = Key::open(super::INTERNET_SETTINGS_SUBKEY)?;
    let prior_proxy_server = inet.read("ProxyServer")?.and_then(|v| v.as_string());
    let prior_proxy_override = inet.read("ProxyOverride")?.and_then(|v| v.as_string());
    let had_vdpi_manual = prior_proxy_server
        .as_deref()
        .is_some_and(is_vdpi_owned_wininet_server);
    // Use fail-open PAC (`AutoConfigURL` + `ProxyEnable=0`), matching `windows.rs` so an abrupt
    // termination or Defender quarantine never leaves a fail-closed proxy that bricks internet.
    let mut proxy = Settings::prepare(
        &inet,
        [
            ("AutoConfigURL", Some(Value::string(&pac_url))),
            ("ProxyEnable", Some(Value::dword(0))),
        ],
    )?;

    let had_stale_vdpi_pac = proxy
        .changes
        .iter()
        .find(|c| c.name == "AutoConfigURL")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_string)
        .as_deref()
        .is_some_and(|s| s.trim().eq_ignore_ascii_case(&pac_url) || is_vdpi_owned_pac_url(s));

    // Persist the sanitized pre-vdpi WinINET snapshot before mutating HKCU so even if
    // Defender quarantines vdpi.exe and kills both parent and guard simultaneously, a user's
    // original corporate PAC/manual proxy is preserved for subsequent restore.
    let state_path = dir.join(WINDOWS_PROXY_STATE_FILENAME);
    let captured_snapshot = snapshot_from_before(
        &proxy.changes,
        prior_proxy_server.as_deref(),
        prior_proxy_override.as_deref(),
    );
    let created_state_file = persist_proxy_state_if_absent(&state_path, captured_snapshot)?;

    normalize_stale_wininet_before(&mut proxy.changes, prior_proxy_server.as_deref(), &pac_url);
    let saved_prior = if !created_state_file {
        load_saved_hkcu_state_with_fallback(&state_path)
    } else if had_stale_vdpi_pac || had_vdpi_manual {
        load_saved_global_hkcu_state()
    } else {
        None
    };
    if let Some(saved_prior) = saved_prior {
        apply_saved_prior_wininet_before(
            &mut proxy.changes,
            &saved_prior,
            prior_proxy_server.as_deref(),
        );
    }

    // Delete any stale vdpi-owned manual ProxyServer/ProxyOverride even if ProxyEnable is already 0.
    if had_vdpi_manual {
        let _ = inet.write("ProxyServer", None);
        let _ = inet.write("ProxyOverride", None);
    }

    // Never write persistent HKCU\Environment HTTP_PROXY/HTTPS_PROXY/NO_PROXY because
    // Registry env vars cannot fail open if vdpi.exe is killed or quarantined. Clean up
    // any stale vdpi-owned env vars left over from older versions so upgrades auto-heal.
    if cleanup_stale_vdpi_user_env() {
        broadcast_environment_change();
    }
    // Auto-heal any legacy fail-closed WinHTTP manual proxy left by older vdpi versions.
    reset_winhttp_proxy_if_vdpi();

    let hkcu_inet_key = internet_settings_key("HKCU");
    with_proxy_lease(
        &mut proxy,
        Some((state_path.as_path(), created_state_file)),
        Some(lease_lock),
        || {
            let _ = sync_wininet_connection_blobs(
                &hkcu_inet_key,
                false,
                had_vdpi_manual,
                Some(&pac_url),
                false,
            );
        },
        || {
            if inet
                .read("ProxyServer")
                .ok()
                .flatten()
                .and_then(|v| v.as_string())
                .as_deref()
                .is_some_and(is_vdpi_owned_wininet_server)
            {
                let _ = inet.write("ProxyServer", None);
                let _ = inet.write("ProxyOverride", None);
            }
            let live_pac = inet
                .read("AutoConfigURL")
                .ok()
                .flatten()
                .and_then(|v| v.as_string())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !is_vdpi_owned_pac_url(s));
            let live_enable = inet
                .read("ProxyEnable")
                .ok()
                .flatten()
                .and_then(|v| v.as_dword())
                .is_some_and(|v| v != 0);
            let live_server = inet
                .read("ProxyServer")
                .ok()
                .flatten()
                .and_then(|v| v.as_string())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let live_override = inet
                .read("ProxyOverride")
                .ok()
                .flatten()
                .and_then(|v| v.as_string())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            if live_enable {
                if let Some(server) = live_server
                    .as_deref()
                    .filter(|s| !is_vdpi_owned_wininet_server(s))
                {
                    let _ = sync_wininet_connection_blobs_restore_manual(
                        &hkcu_inet_key,
                        live_pac.is_none(),
                        live_pac.as_deref(),
                        server,
                        live_override.as_deref(),
                    );
                    return;
                }
            }

            let clear_manual = had_vdpi_manual
                || live_server
                    .as_deref()
                    .is_none_or(is_vdpi_owned_wininet_server);
            let _ = sync_wininet_connection_blobs(
                &hkcu_inet_key,
                live_pac.is_none(),
                clear_manual,
                live_pac.as_deref(),
                live_pac.is_none(),
            );
        },
        notify_wininet_refresh,
        reset_winhttp_proxy_if_vdpi,
        || {
            let mut output = io::stdout().lock();
            writeln!(output, "{READY}")?;
            output.flush()?;
            drop(output);
            // Wait until the parent closes stdin (true EOF or broken pipe) before restoring the lease.
            let mut drain = [0u8; 64];
            loop {
                match input.read(&mut drain) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            Ok(())
        },
    )
}

fn cleanup_stale_vdpi_user_env() -> bool {
    let Ok(env_key) = Key::open(super::USER_ENV_SUBKEY) else {
        return false;
    };
    let mut proxy_matched = false;
    let mut cleaned = false;
    for name in PROXY_ENV_VARS {
        let is_vdpi = env_key
            .read(name)
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
            .as_deref()
            .is_some_and(is_vdpi_owned_proxy_env);
        if is_vdpi {
            proxy_matched = true;
            if env_key.write(name, None).is_ok() {
                cleaned = true;
            }
        }
    }
    for name in NO_PROXY_ENV_VARS {
        let current = env_key
            .read(name)
            .ok()
            .flatten()
            .and_then(|v| v.as_string());
        let should_delete = current.as_deref().is_some_and(|val| {
            proxy_matched || is_vdpi_owned_no_proxy_env(val)
        });
        if should_delete && env_key.write(name, None).is_ok() {
            cleaned = true;
        }
    }
    cleaned
}

fn normalize_stale_wininet_before(
    changes: &mut [Change],
    prior_proxy_server: Option<&str>,
    pac_url: &str,
) {
    if let Some(auto_config) = changes.iter_mut().find(|c| c.name == "AutoConfigURL") {
        let is_stale_pac = auto_config
            .before
            .as_ref()
            .and_then(Value::as_string)
            .as_deref()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case(pac_url) || is_vdpi_owned_pac_url(s));
        if is_stale_pac {
            auto_config.before = None;
        }
    }

    let before_enabled = changes
        .iter()
        .find(|c| c.name == "ProxyEnable")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_dword)
        .is_some_and(|v| v != 0);
    if before_enabled && prior_proxy_server.is_some_and(is_vdpi_owned_wininet_server) {
        if let Some(enable) = changes.iter_mut().find(|c| c.name == "ProxyEnable") {
            enable.before = Some(Value::dword(0));
        }
    }
}

fn snapshot_from_before(
    changes: &[Change],
    prior_proxy_server: Option<&str>,
    prior_proxy_override: Option<&str>,
) -> SavedWininetHiveState {
    let auto_config_url = changes
        .iter()
        .find(|c| c.name == "AutoConfigURL")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_string);
    let proxy_enable = changes
        .iter()
        .find(|c| c.name == "ProxyEnable")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_dword)
        .is_some_and(|v| v != 0);
    SavedWininetHiveState {
        proxy_enable,
        proxy_server: prior_proxy_server.map(ToString::to_string),
        proxy_override: prior_proxy_override.map(ToString::to_string),
        auto_config_url,
        auto_detect: None,
    }
}

fn is_empty_wininet_state(state: &SavedWininetHiveState) -> bool {
    !state.proxy_enable
        && state.proxy_server.is_none()
        && state.proxy_override.is_none()
        && state.auto_config_url.is_none()
        && state.auto_detect.is_none()
}

fn path_exists_no_follow(path: &Path) -> bool {
    matches!(path_attributes_no_follow(path), Ok(Some(_)))
}

const AV_LOCK_RETRY_DELAYS_MS: [u64; 5] = [10, 25, 50, 100, 200];
const LEASE_LOCK_RETRY_DELAYS_MS: [u64; 6] = [25, 50, 100, 200, 300, 500];

fn is_transient_av_lock_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
    )
}

fn retry_on_transient_av_lock_with<T>(
    delays_ms: &[u64],
    mut op: impl FnMut() -> io::Result<T>,
    mut sleep_fn: impl FnMut(Duration),
) -> io::Result<T> {
    for delay_ms in delays_ms.iter().copied().chain(std::iter::once(0)) {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_transient_av_lock_error(&err) && delay_ms > 0 => {
                sleep_fn(Duration::from_millis(delay_ms));
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("retry iterator always ends with a final 0ms attempt")
}

fn publish_proxy_state_if_absent_with(
    tmp_path: &Path,
    state_path: &Path,
    delays_ms: &[u64],
    hard_link_fn: impl FnMut() -> io::Result<()>,
    mut rename_fn: impl FnMut() -> io::Result<()>,
    mut sleep_fn: impl FnMut(Duration),
) -> Result<bool> {
    // Windows Defender real-time scanner can briefly hold newly written temp files right after
    // close/sync; retry transient sharing/access/lock errors (matching `windows.rs`) so
    // `ForegroundProxy::activate` does not abort spuriously.
    match retry_on_transient_av_lock_with(delays_ms, hard_link_fn, &mut sleep_fn) {
        Ok(()) => {
            let _ = fs::remove_file(tmp_path);
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(tmp_path);
            Ok(false)
        }
        Err(_) => {
            if let Err(err) = reject_reparse_point_or_dir(state_path) {
                let _ = fs::remove_file(tmp_path);
                return Err(err);
            }
            if path_exists_no_follow(state_path) {
                let _ = fs::remove_file(tmp_path);
                return Ok(false);
            }
            let rename_res = retry_on_transient_av_lock_with(
                delays_ms,
                || {
                    if let Some(attrs) = path_attributes_no_follow(state_path)? {
                        if is_reparse_point_attrs(attrs)
                            || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "refusing to overwrite NTFS reparse point or directory at {}",
                                    state_path.display()
                                ),
                            ));
                        }
                        return Err(io::Error::from(io::ErrorKind::AlreadyExists));
                    }
                    rename_fn()
                },
                &mut sleep_fn,
            );
            match rename_res {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(tmp_path);
                    Ok(false)
                }
                Err(rename_err) => {
                    let _ = fs::remove_file(tmp_path);
                    if reject_reparse_point_or_dir(state_path).is_ok()
                        && path_exists_no_follow(state_path)
                    {
                        return Ok(false);
                    }
                    Err(rename_err).with_context(|| {
                        format!(
                            "atomically persisting Windows proxy state to {}",
                            state_path.display()
                        )
                    })
                }
            }
        }
    }
}

fn persist_proxy_state_if_absent(
    state_path: &Path,
    raw_snapshot: SavedWininetHiveState,
) -> Result<bool> {
    let parent = state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_safe_state_dir(parent, false)?;
    reject_reparse_point_or_dir(state_path)?;
    if path_attributes_no_follow(state_path)
        .with_context(|| format!("inspecting Windows proxy state {}", state_path.display()))?
        .is_some()
    {
        return Ok(false);
    }

    let sanitized = sanitize_captured_wininet_state(raw_snapshot);
    if is_empty_wininet_state(&sanitized) {
        return Ok(false);
    }

    let mut state = SavedWindowsProxyState::default();
    state.record_hive_if_absent("HKCU", sanitized);
    let json = serde_json::to_string(&state).context("serializing Windows proxy state")?;

    let file_name = state_path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(WINDOWS_PROXY_STATE_FILENAME);
    let pid = std::process::id();
    let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{file_name}.tmp.{pid}.{seq}"));

    let write_res = (|| -> Result<()> {
        let mut tmp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&tmp_path)
            .with_context(|| format!("creating temporary proxy state {}", tmp_path.display()))?;
        tmp_file
            .write_all(json.as_bytes())
            .with_context(|| format!("writing temporary proxy state {}", tmp_path.display()))?;
        tmp_file
            .sync_all()
            .with_context(|| format!("syncing temporary proxy state {}", tmp_path.display()))?;
        Ok(())
    })();
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) =
        reject_reparse_point(parent).and_then(|()| reject_reparse_point_or_dir(state_path))
    {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    publish_proxy_state_if_absent_with(
        &tmp_path,
        state_path,
        &AV_LOCK_RETRY_DELAYS_MS,
        || fs::hard_link(&tmp_path, state_path),
        || fs::rename(&tmp_path, state_path),
        std::thread::sleep,
    )
}

fn load_saved_hkcu_state(state_path: &Path) -> Option<SavedWininetHiveState> {
    let parsed = read_windows_proxy_state_from_path(state_path)?;
    parsed
        .state_for_root("HKCU")
        .map(sanitize_captured_wininet_state)
}

fn load_saved_global_hkcu_state() -> Option<SavedWininetHiveState> {
    load_saved_windows_proxy_state()
        .state_for_root("HKCU")
        .map(sanitize_captured_wininet_state)
        .filter(|state| !is_empty_wininet_state(state))
}

fn load_saved_hkcu_state_with_fallback_using(
    state_path: &Path,
    load_global: impl FnOnce() -> SavedWindowsProxyState,
) -> Option<SavedWininetHiveState> {
    if let Some(local) =
        load_saved_hkcu_state(state_path).filter(|state| !is_empty_wininet_state(state))
    {
        return Some(local);
    }
    load_global()
        .state_for_root("HKCU")
        .map(sanitize_captured_wininet_state)
        .filter(|state| !is_empty_wininet_state(state))
}

fn load_saved_hkcu_state_with_fallback(state_path: &Path) -> Option<SavedWininetHiveState> {
    load_saved_hkcu_state_with_fallback_using(state_path, load_saved_windows_proxy_state)
}

fn apply_saved_prior_wininet_before(
    changes: &mut [Change],
    saved_prior: &SavedWininetHiveState,
    prior_proxy_server: Option<&str>,
) {
    if let Some(auto_config) = changes.iter_mut().find(|c| c.name == "AutoConfigURL") {
        if auto_config.before.is_none() {
            if let Some(prev_pac) = saved_prior
                .auto_config_url
                .as_deref()
                .map(str::trim)
                .filter(|u| !u.is_empty() && !is_vdpi_owned_pac_url(u))
            {
                auto_config.before = Some(Value::string(prev_pac));
            }
        }
    }

    let has_external_proxy_server = prior_proxy_server
        .map(str::trim)
        .is_some_and(|s| !s.is_empty() && !is_vdpi_owned_wininet_server(s));
    let saved_has_external_manual = saved_prior.proxy_enable
        && saved_prior
            .proxy_server
            .as_deref()
            .map(str::trim)
            .is_some_and(|s| !s.is_empty() && !is_vdpi_owned_wininet_server(s));
    if saved_has_external_manual && has_external_proxy_server {
        if let Some(enable) = changes.iter_mut().find(|c| c.name == "ProxyEnable") {
            let already_enabled = enable
                .before
                .as_ref()
                .and_then(Value::as_dword)
                .is_some_and(|v| v != 0);
            if !already_enabled {
                enable.before = Some(Value::dword(1));
            }
        }
    }
}

fn should_remove_state_file_on_cleanup(
    inet_restored_ok: bool,
    applied_all: bool,
    created_state_file: bool,
) -> bool {
    inet_restored_ok && (applied_all || created_state_file)
}

fn should_sync_blobs_for_live_auto_config(key: &Key) -> bool {
    match key.read("AutoConfigURL") {
        Ok(None) => true,
        Ok(Some(val)) => match val.as_string() {
            Some(url) => {
                let trimmed = url.trim();
                trimmed.is_empty() || is_vdpi_owned_pac_url(trimmed)
            }
            None => false,
        },
        Err(_) => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn with_proxy_lease<L>(
    proxy: &mut Settings<'_>,
    state_file: Option<(&Path, bool)>,
    mut lease_lock: Option<L>,
    sync_on_activate: impl Fn(),
    sync_on_restore: impl Fn(),
    refresh_inet: impl Fn(),
    reset_winhttp: impl Fn(),
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let outcome = (|| -> Result<()> {
        proxy.apply()?;
        sync_on_activate();
        refresh_inet();
        wait()
    })();
    let had_applied = proxy.applied > 0;
    let applied_all = proxy.applied == proxy.changes.len();
    let inet_restored = proxy.restore(Some("AutoConfigURL"));
    if !had_applied {
        drop(lease_lock.take());
        return outcome.and(inet_restored.map(|_| ()));
    }
    let restored_cleanly = matches!(inet_restored, Ok(true));
    if restored_cleanly || should_sync_blobs_for_live_auto_config(proxy.key) {
        sync_on_restore();
    }
    if let Some((path, created_state_file)) = state_file {
        if should_remove_state_file_on_cleanup(
            restored_cleanly,
            applied_all,
            created_state_file,
        ) {
            let _ = remove_windows_proxy_state_at_path(path);
        }
    }
    // Release the lease lock right after Registry, connection-blob, and state-file cleanup
    // so rapid VPN yield -> resume handoffs do not block on WinINET/WinHTTP refresh calls.
    drop(lease_lock.take());
    refresh_inet();
    reset_winhttp();
    outcome.and(inet_restored.map(|_| ()))
}

fn registry_values_match(name: &str, current: Option<&Value>, expected: Option<&Value>) -> bool {
    match (current, expected) {
        (None, None) => true,
        (Some(curr), Some(exp)) => {
            if let (Some(curr_s), Some(exp_s)) = (curr.as_string(), exp.as_string()) {
                let curr_trimmed = curr_s.trim();
                let exp_trimmed = exp_s.trim();
                if name.eq_ignore_ascii_case("AutoConfigURL") {
                    curr_trimmed.eq_ignore_ascii_case(exp_trimmed)
                } else {
                    curr_trimmed == exp_trimmed
                }
            } else if let (Some(curr_d), Some(exp_d)) = (curr.as_dword(), exp.as_dword()) {
                curr_d == exp_d
            } else {
                curr == exp
            }
        }
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Value {
    kind: u32,
    data: Vec<u8>,
}

impl Value {
    fn string(text: &str) -> Self {
        Self {
            kind: REG_SZ,
            data: wide(text).into_iter().flat_map(u16::to_le_bytes).collect(),
        }
    }

    fn dword(value: u32) -> Self {
        Self {
            kind: REG_DWORD,
            data: value.to_le_bytes().to_vec(),
        }
    }

    fn as_string(&self) -> Option<String> {
        if self.kind != REG_SZ && self.kind != REG_EXPAND_SZ {
            return None;
        }
        let (chunks, remainder) = self.data.as_chunks::<2>();
        if !remainder.is_empty() {
            return None;
        }
        let units: Vec<u16> = chunks.iter().map(|&c| u16::from_le_bytes(c)).collect();
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        Some(String::from_utf16_lossy(&units[..end]))
    }

    fn as_dword(&self) -> Option<u32> {
        if self.kind != REG_DWORD {
            return None;
        }
        let bytes: [u8; 4] = self.data.as_slice().try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }
}

struct Settings<'a> {
    key: &'a Key,
    changes: Vec<Change>,
    applied: usize,
}

struct Change {
    name: &'static str,
    before: Option<Value>,
    after: Option<Value>,
}

impl<'a> Settings<'a> {
    fn prepare(
        key: &'a Key,
        values: impl IntoIterator<Item = (&'static str, Option<Value>)>,
    ) -> Result<Self> {
        let changes = values
            .into_iter()
            .map(|(name, after)| {
                Ok(Change {
                    name,
                    before: key.read(name)?,
                    after,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            key,
            changes,
            applied: 0,
        })
    }

    fn apply(&mut self) -> Result<()> {
        for change in &self.changes {
            self.key.write(change.name, change.after.as_ref())?;
            self.applied += 1;
        }
        Ok(())
    }

    fn restore(&mut self, owner: Option<&str>) -> Result<bool> {
        if self.applied == 0 {
            return Ok(false);
        }
        let applied_count = self.applied;
        self.applied = 0;
        let mut failure = None;
        let applied = &self.changes[..applied_count];
        if let Some(owner) = applied.iter().find(|change| Some(change.name) == owner) {
            let current = self.key.read(owner.name)?;
            if !registry_values_match(owner.name, current.as_ref(), owner.after.as_ref()) {
                return Ok(false);
            }
        }
        for change in applied.iter().rev() {
            let result = (|| -> Result<()> {
                let current = self.key.read(change.name)?;
                if registry_values_match(change.name, current.as_ref(), change.after.as_ref()) {
                    self.key.write(change.name, change.before.as_ref())?;
                }
                Ok(())
            })();
            if let Err(e) = result {
                failure = Some(e);
            }
        }
        failure.map_or(Ok(true), Err)
    }
}

struct Key(HKEY);

impl Key {
    fn open(path: &str) -> Result<Self> {
        let mut key = null_mut();
        check(unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide(path).as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                &mut key,
            )
        })
        .with_context(|| format!("opening HKCU\\{path}"))?;
        Ok(Self(key))
    }

    fn read(&self, name: &str) -> Result<Option<Value>> {
        let name = wide(name);
        let mut len = 0;
        let mut kind = 0;
        loop {
            let code = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    null_mut(),
                    &mut len,
                )
            };
            if code == ERROR_FILE_NOT_FOUND {
                return Ok(None);
            }
            check(code)?;
            let mut data = vec![0; len as usize];
            let code = unsafe {
                RegQueryValueExW(
                    self.0,
                    name.as_ptr(),
                    null(),
                    &mut kind,
                    data.as_mut_ptr(),
                    &mut len,
                )
            };
            match code {
                ERROR_FILE_NOT_FOUND => return Ok(None),
                ERROR_MORE_DATA => continue,
                _ => check(code)?,
            }
            data.truncate(len as usize);
            return Ok(Some(Value { kind, data }));
        }
    }

    fn write(&self, name: &str, value: Option<&Value>) -> Result<()> {
        let wide_name = wide(name);
        let code = match value {
            Some(value) => unsafe {
                RegSetValueExW(
                    self.0,
                    wide_name.as_ptr(),
                    0,
                    value.kind,
                    value.data.as_ptr(),
                    value.data.len().try_into()?,
                )
            },
            None => match unsafe { RegDeleteValueW(self.0, wide_name.as_ptr()) } {
                ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
                code => code,
            },
        };
        check(code).with_context(|| format!("updating the Windows proxy setting {name}"))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn check(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32).into())
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::windows::process::ExitStatusExt;
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex};

    const ROLE: &str = "VDPI_TEST_PROXY_ROLE";
    const PATH: &str = "VDPI_TEST_PROXY_KEY";
    const TEST: &str =
        "platform::windows::foreground::tests::restores_proxy_after_parent_is_killed";

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("vdpi-fg-{label}-{}-{seq}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestRegKey(String);

    impl TestRegKey {
        fn create(subkey: &str) -> Self {
            use windows_sys::Win32::System::Registry::RegCreateKeyW;

            let mut hkey: HKEY = null_mut();
            let rc = unsafe { RegCreateKeyW(HKEY_CURRENT_USER, wide(subkey).as_ptr(), &mut hkey) };
            assert_eq!(rc, ERROR_SUCCESS, "RegCreateKeyW({subkey}) failed with {rc}");
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            Self(subkey.to_string())
        }
    }

    impl Drop for TestRegKey {
        fn drop(&mut self) {
            use windows_sys::Win32::System::Registry::RegDeleteTreeW;

            unsafe {
                let _ = RegDeleteTreeW(HKEY_CURRENT_USER, wide(&self.0).as_ptr());
            }
        }
    }

    #[test]
    fn restores_proxy_after_parent_is_killed() {
        let local_pac = Value::string("http://127.0.0.1:18080/vdpi.pac");
        let original_pac = Value::string("http://pac.corp.local/proxy.pac");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", TEST]).stdout(Stdio::null());

        match std::env::var(ROLE).as_deref() {
            Ok("parent") => {
                let mut guard = command
                    .env(ROLE, "guard")
                    .creation_flags(DETACHED_PROCESS)
                    .stdin(Stdio::piped())
                    .spawn()
                    .unwrap();
                // Hold the writer open until the test kills this intermediary.
                let pipe = guard.stdin.take();
                guard.wait().unwrap();
                drop(pipe);
            }
            Ok("guard") => {
                let key = Key::open(&std::env::var(PATH).unwrap()).unwrap();
                let mut changes = Settings::prepare(
                    &key,
                    [
                        ("AutoConfigURL", Some(local_pac)),
                        ("ProxyEnable", Some(Value::dword(0))),
                    ],
                )
                .unwrap();
                with_proxy_lease(
                    &mut changes,
                    None,
                    None::<()>,
                    || {},
                    || {},
                    || {},
                    || {},
                    || {
                        let _ = io::stdin().lock().fill_buf();
                        Ok(())
                    },
                )
                .unwrap();
            }
            _ => {
                let path = format!(r"Software\vdpi-proxy-test-{}", std::process::id());
                let _cleanup = TestRegKey::create(&path);
                let key = Key::open(&path).unwrap();
                key.write("AutoConfigURL", Some(&original_pac)).unwrap();
                key.write("ProxyEnable", Some(&Value::dword(1))).unwrap();
                let mut parent = command
                    .envs([(ROLE, "parent"), (PATH, path.as_str())])
                    .spawn()
                    .unwrap();
                let active = wait_until(|| {
                    key.read("AutoConfigURL").unwrap().as_ref() == Some(&local_pac)
                        && key.read("ProxyEnable").unwrap().as_ref() == Some(&Value::dword(0))
                });
                let _ = parent.kill();
                parent.wait().unwrap();
                assert!(
                    active,
                    "detached proxy guard never applied the test PAC settings"
                );
                assert!(
                    wait_until(|| {
                        key.read("AutoConfigURL").unwrap().as_ref() == Some(&original_pac)
                            && key.read("ProxyEnable").unwrap().as_ref() == Some(&Value::dword(1))
                    }),
                    "detached proxy guard did not restore AutoConfigURL/ProxyEnable after parent termination"
                );
            }
        }
    }

    fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        true
    }

    #[test]
    fn normalizes_stale_vdpi_before_state_without_clobbering_external_proxy() {
        let pac_url = "http://127.0.0.1:8080/vdpi.pac?v=session-1";

        let mut stale_pac_and_legacy_manual = vec![
            Change {
                name: "AutoConfigURL",
                before: Some(Value::string("http://[::1]:18080/vdpi.pac?v=old-nonce")),
                after: Some(Value::string(pac_url)),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(1)),
                after: Some(Value::dword(0)),
            },
        ];
        normalize_stale_wininet_before(
            &mut stale_pac_and_legacy_manual,
            Some("127.0.0.1:8080"),
            pac_url,
        );
        assert_eq!(stale_pac_and_legacy_manual[0].before, None);
        assert_eq!(
            stale_pac_and_legacy_manual[1].before,
            Some(Value::dword(0))
        );

        let mut external_pac_and_manual = vec![
            Change {
                name: "AutoConfigURL",
                before: Some(Value::string("http://pac.corp.local/proxy.pac")),
                after: Some(Value::string(pac_url)),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(1)),
                after: Some(Value::dword(0)),
            },
        ];
        normalize_stale_wininet_before(
            &mut external_pac_and_manual,
            Some("proxy.corp.local:3128"),
            pac_url,
        );
        assert_eq!(
            external_pac_and_manual[0].before,
            Some(Value::string("http://pac.corp.local/proxy.pac"))
        );
        assert_eq!(external_pac_and_manual[1].before, Some(Value::dword(1)));
    }

    #[test]
    fn persists_sanitized_proxy_state_atomically_only_if_absent() {
        let dir = TestDir::new("persist-state");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);

        let corp_snapshot = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some(" proxy.corp.local:3128 ".into()),
            proxy_override: Some(" *.corp.local;<local> ".into()),
            auto_config_url: Some(" http://pac.corp.local/proxy.pac ".into()),
            auto_detect: None,
        };
        let created = persist_proxy_state_if_absent(&state_path, corp_snapshot).unwrap();
        assert!(created);
        assert!(state_path.is_file());

        // Atomic write must not leave stray temporary files behind.
        let entries: Vec<String> = fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec![WINDOWS_PROXY_STATE_FILENAME.to_string()]);

        let parsed: SavedWindowsProxyState =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        let expected_corp = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("proxy.corp.local:3128".into()),
            proxy_override: Some("*.corp.local;<local>".into()),
            auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            auto_detect: None,
        };
        assert_eq!(parsed.state_for_root("HKCU"), Some(expected_corp.clone()));
        assert!(parsed.proxy_enable);
        assert_eq!(parsed.proxy_server.as_deref(), Some("proxy.corp.local:3128"));
        assert_eq!(parsed.proxy_override.as_deref(), Some("*.corp.local;<local>"));
        assert_eq!(
            parsed.auto_config_url.as_deref(),
            Some("http://pac.corp.local/proxy.pac")
        );

        // Second call when state file already exists (e.g. restart after abrupt Defender kill)
        // must NOT overwrite the original pre-vdpi snapshot.
        let stale_vdpi_snapshot = SavedWininetHiveState {
            proxy_enable: false,
            proxy_server: Some("127.0.0.1:8080".into()),
            proxy_override: None,
            auto_config_url: Some("http://127.0.0.1:8080/vdpi.pac".into()),
            auto_detect: None,
        };
        let second_created =
            persist_proxy_state_if_absent(&state_path, stale_vdpi_snapshot).unwrap();
        assert!(!second_created);
        assert_eq!(load_saved_hkcu_state(&state_path), Some(expected_corp));

        // Fresh capture that sanitizes to a completely empty snapshot must skip writing
        // `windows-proxy-state.json` to avoid unnecessary disk churn.
        let empty_dir = TestDir::new("skip-empty-state");
        let empty_path = empty_dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let poisoned = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("127.0.0.1:8080".into()),
            proxy_override: Some("localhost;<local>".into()),
            auto_config_url: Some("http://[::1]:18080/vdpi.pac?v=stale".into()),
            auto_detect: None,
        };
        assert!(!persist_proxy_state_if_absent(&empty_path, poisoned).unwrap());
        assert!(!empty_path.exists());
        assert!(
            !persist_proxy_state_if_absent(&empty_path, SavedWininetHiveState::default()).unwrap()
        );
        assert!(!empty_path.exists());

        // Mixed capture with corporate ProxyServer and poisoned vdpi PAC must strip the vdpi PAC
        // while still persisting the corporate fields.
        let mixed_dir = TestDir::new("sanitize-mixed-state");
        let mixed_path = mixed_dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let mixed = SavedWininetHiveState {
            proxy_enable: false,
            proxy_server: Some(" proxy.corp.local:3128 ".into()),
            proxy_override: Some(" *.corp.local ".into()),
            auto_config_url: Some("http://127.0.0.1:18080/vdpi.pac?v=stale".into()),
            auto_detect: None,
        };
        assert!(persist_proxy_state_if_absent(&mixed_path, mixed).unwrap());
        assert_eq!(
            load_saved_hkcu_state(&mixed_path),
            Some(SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: Some("proxy.corp.local:3128".into()),
                proxy_override: Some("*.corp.local".into()),
                auto_config_url: None,
                auto_detect: None,
            })
        );
    }

    #[test]
    fn hydrates_before_state_from_persisted_snapshot_after_abrupt_kill() {
        let dir = TestDir::new("hydrate-after-kill");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let pac_url = "http://127.0.0.1:8080/vdpi.pac";

        let original_corp = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("proxy.corp.local:3128".into()),
            proxy_override: Some("*.corp.local;<local>".into()),
            auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            auto_detect: None,
        };
        assert!(persist_proxy_state_if_absent(&state_path, original_corp).unwrap());
        let saved_prior = load_saved_hkcu_state(&state_path).unwrap();

        // Simulate restart when live HKCU still holds stale vdpi PAC + ProxyEnable=0.
        let mut restart_changes = vec![
            Change {
                name: "AutoConfigURL",
                before: Some(Value::string(pac_url)),
                after: Some(Value::string(pac_url)),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(0)),
                after: Some(Value::dword(0)),
            },
        ];
        normalize_stale_wininet_before(
            &mut restart_changes,
            Some("proxy.corp.local:3128"),
            pac_url,
        );
        apply_saved_prior_wininet_before(
            &mut restart_changes,
            &saved_prior,
            Some("proxy.corp.local:3128"),
        );
        assert_eq!(
            restart_changes[0].before,
            Some(Value::string("http://pac.corp.local/proxy.pac"))
        );
        assert_eq!(restart_changes[1].before, Some(Value::dword(1)));

        // If user manually switched to a newer external PAC while vdpi was down, preserve it;
        // and if ProxyServer is vdpi-owned or absent, do not force ProxyEnable=1.
        let mut newer_external = vec![
            Change {
                name: "AutoConfigURL",
                before: Some(Value::string("http://new.corp.local/new.pac")),
                after: Some(Value::string(pac_url)),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(0)),
                after: Some(Value::dword(0)),
            },
        ];
        apply_saved_prior_wininet_before(&mut newer_external, &saved_prior, Some("127.0.0.1:8080"));
        assert_eq!(
            newer_external[0].before,
            Some(Value::string("http://new.corp.local/new.pac"))
        );
        assert_eq!(newer_external[1].before, Some(Value::dword(0)));
    }

    #[test]
    fn with_proxy_lease_removes_state_file_and_runs_winhttp_cleanup_on_clean_restore() {
        let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let reg_path = format!(
            r"Software\vdpi-proxy-lease-test-{}-{seq}",
            std::process::id()
        );
        let _reg_cleanup = TestRegKey::create(&reg_path);

        let dir = TestDir::new("lease-cleanup");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let original_pac = Value::string("http://pac.corp.local/proxy.pac");
        let local_pac = Value::string("http://127.0.0.1:18080/vdpi.pac");

        let key = Key::open(&reg_path).unwrap();
        key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        key.write("ProxyEnable", Some(&Value::dword(1))).unwrap();
        key.write("ProxyServer", Some(&Value::string("proxy.corp.local:3128")))
            .unwrap();
        key.write("ProxyOverride", Some(&Value::string("*.corp.local;<local>")))
            .unwrap();

        let prior_server = key.read("ProxyServer").unwrap().and_then(|v| v.as_string());
        let prior_override = key
            .read("ProxyOverride")
            .unwrap()
            .and_then(|v| v.as_string());
        let mut settings = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac.clone())),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        let snapshot = snapshot_from_before(
            &settings.changes,
            prior_server.as_deref(),
            prior_override.as_deref(),
        );
        let created = persist_proxy_state_if_absent(&state_path, snapshot).unwrap();
        assert!(created);
        assert!(state_path.is_file());

        let activate_sync_count = AtomicUsize::new(0);
        let restore_sync_count = AtomicUsize::new(0);
        let refresh_count = AtomicUsize::new(0);
        let winhttp_reset_count = AtomicUsize::new(0);

        with_proxy_lease(
            &mut settings,
            Some((state_path.as_path(), created)),
            None::<()>,
            || {
                activate_sync_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                restore_sync_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                refresh_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                winhttp_reset_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                assert_eq!(key.read("AutoConfigURL")?.as_ref(), Some(&local_pac));
                assert_eq!(key.read("ProxyEnable")?.as_ref(), Some(&Value::dword(0)));
                assert!(state_path.is_file());
                assert_eq!(activate_sync_count.load(Ordering::SeqCst), 1);
                assert_eq!(restore_sync_count.load(Ordering::SeqCst), 0);
                assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
                assert_eq!(winhttp_reset_count.load(Ordering::SeqCst), 0);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(key.read("AutoConfigURL").unwrap().as_ref(), Some(&original_pac));
        assert_eq!(
            key.read("ProxyEnable").unwrap().as_ref(),
            Some(&Value::dword(1))
        );
        assert!(!state_path.exists());
        assert_eq!(activate_sync_count.load(Ordering::SeqCst), 1);
        assert_eq!(restore_sync_count.load(Ordering::SeqCst), 1);
        assert_eq!(refresh_count.load(Ordering::SeqCst), 2);
        assert_eq!(winhttp_reset_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_file_removal_policy_preserves_file_on_restore_failure_or_incomplete_recovery() {
        assert!(should_remove_state_file_on_cleanup(true, true, true));
        assert!(should_remove_state_file_on_cleanup(true, true, false));
        assert!(should_remove_state_file_on_cleanup(true, false, true));
        assert!(!should_remove_state_file_on_cleanup(true, false, false));
        assert!(!should_remove_state_file_on_cleanup(false, true, true));
        assert!(!should_remove_state_file_on_cleanup(false, true, false));
    }

    #[test]
    fn persist_proxy_state_retries_transient_av_locks_on_hard_link_and_rename() {
        // 1. `hard_link` retries ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
        //    with the [10, 25, 50, 100, 200] ms backoff schedule and succeeds once the lock clears.
        let dir = TestDir::new("av-retry-hard-link");
        let tmp_path = dir.0.join(".windows-proxy-state.json.tmp.1");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        fs::write(&tmp_path, b"{\"hkcu\":true}").unwrap();

        let mut link_attempts = 0usize;
        let mut rename_attempts = 0usize;
        let mut sleeps = Vec::new();
        let created = publish_proxy_state_if_absent_with(
            &tmp_path,
            &state_path,
            &AV_LOCK_RETRY_DELAYS_MS,
            || {
                link_attempts += 1;
                match link_attempts {
                    1 => Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED)),
                    2 => Err(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION)),
                    3 => Err(io::Error::from_raw_os_error(ERROR_LOCK_VIOLATION)),
                    _ => fs::hard_link(&tmp_path, &state_path),
                }
            },
            || {
                rename_attempts += 1;
                fs::rename(&tmp_path, &state_path)
            },
            |delay| sleeps.push(delay),
        )
        .unwrap();

        assert!(created);
        assert_eq!(link_attempts, 4);
        assert_eq!(rename_attempts, 0);
        assert_eq!(
            sleeps,
            vec![
                Duration::from_millis(10),
                Duration::from_millis(25),
                Duration::from_millis(50),
            ]
        );
        assert!(state_path.is_file());
        assert!(!tmp_path.exists());
        assert_eq!(
            fs::read_to_string(&state_path).unwrap(),
            "{\"hkcu\":true}"
        );

        // 2. Non-retryable `hard_link` error (e.g. filesystem without hard links) falls back to
        //    `rename` immediately without sleeping, and `rename` retries transient AV lock errors.
        let dir2 = TestDir::new("av-retry-rename");
        let tmp_path2 = dir2.0.join(".windows-proxy-state.json.tmp.2");
        let state_path2 = dir2.0.join(WINDOWS_PROXY_STATE_FILENAME);
        fs::write(&tmp_path2, b"{\"rename\":true}").unwrap();

        let mut link_attempts2 = 0usize;
        let mut rename_attempts2 = 0usize;
        let mut sleeps2 = Vec::new();
        let created2 = publish_proxy_state_if_absent_with(
            &tmp_path2,
            &state_path2,
            &AV_LOCK_RETRY_DELAYS_MS,
            || {
                link_attempts2 += 1;
                Err(io::Error::from(io::ErrorKind::Unsupported))
            },
            || {
                rename_attempts2 += 1;
                match rename_attempts2 {
                    1 => Err(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION)),
                    2 => Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED)),
                    3 => Err(io::Error::from_raw_os_error(ERROR_LOCK_VIOLATION)),
                    _ => fs::rename(&tmp_path2, &state_path2),
                }
            },
            |delay| sleeps2.push(delay),
        )
        .unwrap();

        assert!(created2);
        assert_eq!(link_attempts2, 1);
        assert_eq!(rename_attempts2, 4);
        assert_eq!(
            sleeps2,
            vec![
                Duration::from_millis(10),
                Duration::from_millis(25),
                Duration::from_millis(50),
            ]
        );
        assert!(state_path2.is_file());
        assert!(!tmp_path2.exists());
        assert_eq!(
            fs::read_to_string(&state_path2).unwrap(),
            "{\"rename\":true}"
        );

        // 3. Exhausting all retries sleeps the full [10, 25, 50, 100, 200] ms schedule, cleans up
        //    the temp file, and returns an error.
        let dir3 = TestDir::new("av-retry-exhausted");
        let tmp_path3 = dir3.0.join(".windows-proxy-state.json.tmp.3");
        let state_path3 = dir3.0.join(WINDOWS_PROXY_STATE_FILENAME);
        fs::write(&tmp_path3, b"{\"exhausted\":true}").unwrap();

        let mut rename_attempts3 = 0usize;
        let mut sleeps3 = Vec::new();
        let err3 = publish_proxy_state_if_absent_with(
            &tmp_path3,
            &state_path3,
            &AV_LOCK_RETRY_DELAYS_MS,
            || Err(io::Error::from(io::ErrorKind::Unsupported)),
            || {
                rename_attempts3 += 1;
                Err(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION))
            },
            |delay| sleeps3.push(delay),
        )
        .unwrap_err();

        assert!(err3
            .to_string()
            .contains("atomically persisting Windows proxy state"));
        assert_eq!(rename_attempts3, AV_LOCK_RETRY_DELAYS_MS.len() + 1);
        assert_eq!(
            sleeps3,
            AV_LOCK_RETRY_DELAYS_MS
                .iter()
                .copied()
                .map(Duration::from_millis)
                .collect::<Vec<_>>()
        );
        assert!(!tmp_path3.exists());
        assert!(!state_path3.exists());

        // 4. If `state_path` appears during a transient retry before `rename`, abort without
        //    clobbering the concurrently created state file and clean up `tmp_path`.
        let dir4 = TestDir::new("av-retry-concurrent-exists");
        let tmp_path4 = dir4.0.join(".windows-proxy-state.json.tmp.4");
        let state_path4 = dir4.0.join(WINDOWS_PROXY_STATE_FILENAME);
        fs::write(&tmp_path4, b"{\"new\":true}").unwrap();

        let mut rename_attempts4 = 0usize;
        let mut sleeps4 = Vec::new();
        let created4 = publish_proxy_state_if_absent_with(
            &tmp_path4,
            &state_path4,
            &AV_LOCK_RETRY_DELAYS_MS,
            || Err(io::Error::from(io::ErrorKind::Unsupported)),
            || {
                rename_attempts4 += 1;
                fs::write(&state_path4, b"{\"existing\":true}").unwrap();
                Err(io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION))
            },
            |delay| sleeps4.push(delay),
        )
        .unwrap();

        assert!(!created4);
        assert_eq!(rename_attempts4, 1);
        assert_eq!(sleeps4, vec![Duration::from_millis(10)]);
        assert!(!tmp_path4.exists());
        assert_eq!(
            fs::read_to_string(&state_path4).unwrap(),
            "{\"existing\":true}"
        );
    }

    #[test]
    fn resolves_foreground_state_dir_with_empty_localappdata_fallback() {
        let local = resolve_foreground_state_dir_from(
            Some(OsString::from(r"C:\Users\Alice\AppData\Local")),
            Some(OsString::from(r"C:\Users\Alice")),
        )
        .unwrap();
        assert_eq!(local, PathBuf::from(r"C:\Users\Alice\AppData\Local\vdpi"));

        let fallback_empty = resolve_foreground_state_dir_from(
            Some(OsString::from("")),
            Some(OsString::from(r"C:\Users\Alice")),
        )
        .unwrap();
        assert_eq!(fallback_empty, PathBuf::from(r"C:\Users\Alice\.vdpi"));

        let fallback_none =
            resolve_foreground_state_dir_from(None, Some(OsString::from(r"C:\Users\Alice")))
                .unwrap();
        assert_eq!(fallback_none, PathBuf::from(r"C:\Users\Alice\.vdpi"));

        assert!(resolve_foreground_state_dir_from(
            Some(OsString::from("")),
            Some(OsString::from("")),
        )
        .is_err());
        assert!(resolve_foreground_state_dir_from(None, None).is_err());
    }

    #[test]
    fn acquire_proxy_lease_lock_retries_transient_lock_and_rejects_directory() {
        let dir = TestDir::new("lease-lock-retry");
        let lock_path = dir.0.join("proxy-lease.lock");

        let holder = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .open(&lock_path)
            .unwrap();
        let mut holder = Some(holder);
        let mut sleeps = Vec::new();
        let acquired =
            acquire_proxy_lease_lock_with(&lock_path, &LEASE_LOCK_RETRY_DELAYS_MS, |delay| {
                sleeps.push(delay);
                if sleeps.len() == 2 {
                    drop(holder.take());
                }
            })
            .unwrap();
        drop(acquired);
        assert_eq!(
            sleeps,
            vec![Duration::from_millis(25), Duration::from_millis(50)]
        );
        assert_eq!(LEASE_LOCK_RETRY_DELAYS_MS, [25, 50, 100, 200, 300, 500]);

        let dir_lock = dir.0.join("dir-as-lock");
        fs::create_dir(&dir_lock).unwrap();
        let mut dir_sleeps = Vec::new();
        let err =
            acquire_proxy_lease_lock_with(&dir_lock, &LEASE_LOCK_RETRY_DELAYS_MS, |delay| {
                dir_sleeps.push(delay);
            })
            .unwrap_err();
        assert!(dir_sleeps.is_empty());
        assert!(err.to_string().contains("directory"));
    }

    #[test]
    fn settings_restore_skips_when_nothing_applied_and_matches_values_semantically() {
        let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let reg_path = format!(
            r"Software\vdpi-settings-restore-test-{}-{seq}",
            std::process::id()
        );
        let _reg_cleanup = TestRegKey::create(&reg_path);
        let key = Key::open(&reg_path).unwrap();

        let original_pac = Value::string("http://pac.corp.local/proxy.pac");
        let local_pac = Value::string("http://127.0.0.1:18080/vdpi.pac?v=abc");
        key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        key.write("ProxyEnable", Some(&Value::dword(1))).unwrap();

        // 1. `restore` when `applied == 0` must immediately return `Ok(false)` without touching registry.
        let mut unapplied = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac.clone())),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        assert!(!unapplied.restore(Some("AutoConfigURL")).unwrap());
        assert_eq!(unapplied.applied, 0);
        assert_eq!(key.read("AutoConfigURL").unwrap().as_ref(), Some(&original_pac));
        assert_eq!(
            key.read("ProxyEnable").unwrap().as_ref(),
            Some(&Value::dword(1))
        );

        // 2. Semantic match for `AutoConfigURL` handles REG_EXPAND_SZ, whitespace, ASCII case,
        //    and missing NUL terminator, restoring original values and resetting `applied = 0`.
        let mut semantic = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac.clone())),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        semantic.apply().unwrap();
        let expand_pac = Value {
            kind: REG_EXPAND_SZ,
            data: "  HTTP://127.0.0.1:18080/VDPI.PAC?V=ABC  "
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        };
        key.write("AutoConfigURL", Some(&expand_pac)).unwrap();
        assert!(semantic.restore(Some("AutoConfigURL")).unwrap());
        assert_eq!(semantic.applied, 0);
        assert_eq!(key.read("AutoConfigURL").unwrap().as_ref(), Some(&original_pac));
        assert_eq!(
            key.read("ProxyEnable").unwrap().as_ref(),
            Some(&Value::dword(1))
        );

        // 3. When an external owner takes over `AutoConfigURL`, `restore` returns `Ok(false)` and
        //    still resets `applied = 0`.
        let mut external = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac)),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        external.apply().unwrap();
        let external_pac = Value::string("http://vpn.corp.local/vpn.pac");
        key.write("AutoConfigURL", Some(&external_pac)).unwrap();
        assert!(!external.restore(Some("AutoConfigURL")).unwrap());
        assert_eq!(external.applied, 0);
        assert_eq!(key.read("AutoConfigURL").unwrap().as_ref(), Some(&external_pac));
    }

    #[test]
    fn with_proxy_lease_skips_cleanup_when_apply_writes_nothing() {
        let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let reg_path = format!(
            r"Software\vdpi-lease-noapply-test-{}-{seq}",
            std::process::id()
        );
        let _reg_cleanup = TestRegKey::create(&reg_path);
        let rw_key = Key::open(&reg_path).unwrap();
        let original_pac = Value::string("http://pac.corp.local/proxy.pac");
        rw_key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        rw_key.write("ProxyEnable", Some(&Value::dword(1))).unwrap();

        let dir = TestDir::new("lease-noapply");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let existing_corp = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("proxy.corp.local:3128".into()),
            proxy_override: None,
            auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            auto_detect: None,
        };
        assert!(persist_proxy_state_if_absent(&state_path, existing_corp).unwrap());

        // Open read-only handle so the first Registry write fails with ACCESS_DENIED (`applied == 0`).
        let mut ro_hkey: HKEY = null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                wide(&reg_path).as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut ro_hkey,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        let ro_key = Key(ro_hkey);

        let mut settings = Settings::prepare(
            &ro_key,
            [
                ("AutoConfigURL", Some(Value::string("http://127.0.0.1:18080/vdpi.pac?v=1"))),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();

        let activate_sync_count = AtomicUsize::new(0);
        let restore_sync_count = AtomicUsize::new(0);
        let refresh_count = AtomicUsize::new(0);
        let winhttp_reset_count = AtomicUsize::new(0);

        let res = with_proxy_lease(
            &mut settings,
            Some((state_path.as_path(), false)),
            None::<()>,
            || {
                activate_sync_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                restore_sync_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                refresh_count.fetch_add(1, Ordering::SeqCst);
            },
            || {
                winhttp_reset_count.fetch_add(1, Ordering::SeqCst);
            },
            || Ok(()),
        );
        assert!(res.is_err());
        assert_eq!(activate_sync_count.load(Ordering::SeqCst), 0);
        assert_eq!(restore_sync_count.load(Ordering::SeqCst), 0);
        assert_eq!(refresh_count.load(Ordering::SeqCst), 0);
        assert_eq!(winhttp_reset_count.load(Ordering::SeqCst), 0);
        assert!(state_path.is_file());
    }

    #[test]
    fn with_proxy_lease_preserves_state_file_on_skipped_restore_and_syncs_blobs_when_pac_missing_or_vdpi()
    {
        let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let reg_path = format!(
            r"Software\vdpi-lease-skip-test-{}-{seq}",
            std::process::id()
        );
        let _reg_cleanup = TestRegKey::create(&reg_path);
        let key = Key::open(&reg_path).unwrap();

        let dir = TestDir::new("lease-skip-restore");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let original_pac = Value::string("http://pac.corp.local/proxy.pac");
        let local_pac = Value::string("http://127.0.0.1:18080/vdpi.pac?v=1");
        let corp_snapshot = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("proxy.corp.local:3128".into()),
            proxy_override: None,
            auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            auto_detect: None,
        };
        assert!(persist_proxy_state_if_absent(&state_path, corp_snapshot).unwrap());

        // Case A: external PAC takes over -> restore skipped, state file preserved, blobs untouched.
        key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        key.write("ProxyEnable", Some(&Value::dword(1))).unwrap();
        let mut settings_a = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac.clone())),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        let restore_sync_a = AtomicUsize::new(0);
        let external_pac = Value::string("http://vpn.corp.local/vpn.pac");
        with_proxy_lease(
            &mut settings_a,
            Some((state_path.as_path(), true)),
            None::<()>,
            || {},
            || {
                restore_sync_a.fetch_add(1, Ordering::SeqCst);
            },
            || {},
            || {},
            || {
                key.write("AutoConfigURL", Some(&external_pac))?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(restore_sync_a.load(Ordering::SeqCst), 0);
        assert!(state_path.is_file());
        assert_eq!(key.read("AutoConfigURL").unwrap().as_ref(), Some(&external_pac));

        // Case B: AutoConfigURL deleted while running -> restore skipped, state file preserved,
        // but `sync_on_restore` still runs to scrub vdpi PAC from connection blobs.
        key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        let mut settings_b = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac.clone())),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        let restore_sync_b = AtomicUsize::new(0);
        with_proxy_lease(
            &mut settings_b,
            Some((state_path.as_path(), true)),
            None::<()>,
            || {},
            || {
                restore_sync_b.fetch_add(1, Ordering::SeqCst);
            },
            || {},
            || {},
            || {
                key.write("AutoConfigURL", None)?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(restore_sync_b.load(Ordering::SeqCst), 1);
        assert!(state_path.is_file());

        // Case C: AutoConfigURL changed to another vdpi-owned PAC -> restore skipped, state file
        // preserved, and `sync_on_restore` still runs for blob cleanup.
        key.write("AutoConfigURL", Some(&original_pac)).unwrap();
        let mut settings_c = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(local_pac)),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();
        let restore_sync_c = AtomicUsize::new(0);
        with_proxy_lease(
            &mut settings_c,
            Some((state_path.as_path(), true)),
            None::<()>,
            || {},
            || {
                restore_sync_c.fetch_add(1, Ordering::SeqCst);
            },
            || {},
            || {},
            || {
                key.write(
                    "AutoConfigURL",
                    Some(&Value::string("http://127.0.0.1:19090/vdpi.pac?v=other")),
                )?;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(restore_sync_c.load(Ordering::SeqCst), 1);
        assert!(state_path.is_file());
    }

    #[test]
    fn with_proxy_lease_releases_lock_before_refresh_and_winhttp_cleanup() {
        struct LockDropTracker {
            events: Arc<Mutex<Vec<&'static str>>>,
            state_path: PathBuf,
        }
        impl Drop for LockDropTracker {
            fn drop(&mut self) {
                assert!(
                    !self.state_path.exists(),
                    "state file must be removed before releasing proxy-lease.lock"
                );
                self.events.lock().unwrap().push("lock_dropped");
            }
        }

        let seq = STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let reg_path = format!(
            r"Software\vdpi-lease-order-test-{}-{seq}",
            std::process::id()
        );
        let _reg_cleanup = TestRegKey::create(&reg_path);
        let key = Key::open(&reg_path).unwrap();
        let dir = TestDir::new("lease-lock-order");
        let state_path = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let corp = SavedWininetHiveState {
            proxy_enable: false,
            proxy_server: None,
            proxy_override: None,
            auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
            auto_detect: None,
        };
        assert!(persist_proxy_state_if_absent(&state_path, corp).unwrap());

        let mut settings = Settings::prepare(
            &key,
            [
                ("AutoConfigURL", Some(Value::string("http://127.0.0.1:18080/vdpi.pac?v=2"))),
                ("ProxyEnable", Some(Value::dword(0))),
            ],
        )
        .unwrap();

        let events = Arc::new(Mutex::new(Vec::new()));
        let tracker = LockDropTracker {
            events: Arc::clone(&events),
            state_path: state_path.clone(),
        };
        with_proxy_lease(
            &mut settings,
            Some((state_path.as_path(), true)),
            Some(tracker),
            || events.lock().unwrap().push("activate_sync"),
            || events.lock().unwrap().push("restore_sync"),
            || events.lock().unwrap().push("refresh"),
            || events.lock().unwrap().push("winhttp"),
            || Ok(()),
        )
        .unwrap();

        assert_eq!(
            *events.lock().unwrap(),
            vec![
                "activate_sync",
                "refresh",
                "restore_sync",
                "lock_dropped",
                "refresh",
                "winhttp",
            ]
        );
    }

    #[test]
    fn shutdown_guard_child_bounded_timeout_kills_and_runs_fallback() {
        struct FakeGuard {
            polls: usize,
            exit_on_poll: Option<usize>,
            fail_try_wait: bool,
            killed: usize,
            waited: usize,
        }

        // 1. Clean exit within deadline does not kill or run fallback cleanup.
        let mut clean = FakeGuard {
            polls: 0,
            exit_on_poll: Some(2),
            fail_try_wait: false,
            killed: 0,
            waited: 0,
        };
        let mut fallback_clean = 0usize;
        shutdown_guard_child_with(
            &mut clean,
            Duration::from_millis(100),
            Duration::from_millis(5),
            |g| {
                g.polls += 1;
                if g.exit_on_poll == Some(g.polls) {
                    Ok(Some(ExitStatus::from_raw(0)))
                } else {
                    Ok(None)
                }
            },
            |g| {
                g.killed += 1;
                Ok(())
            },
            |g| {
                g.waited += 1;
                Ok(ExitStatus::from_raw(0))
            },
            |_| {},
            || fallback_clean += 1,
        );
        assert_eq!(clean.polls, 2);
        assert_eq!(clean.killed, 0);
        assert_eq!(clean.waited, 0);
        assert_eq!(fallback_clean, 0);

        // 2. Timeout kills hung guard, reaps via wait(), and invokes fallback proxy cleanup.
        let mut hung = FakeGuard {
            polls: 0,
            exit_on_poll: None,
            fail_try_wait: false,
            killed: 0,
            waited: 0,
        };
        let mut fallback_hung = 0usize;
        shutdown_guard_child_with(
            &mut hung,
            Duration::from_millis(30),
            Duration::from_millis(10),
            |g| {
                g.polls += 1;
                Ok(None)
            },
            |g| {
                g.killed += 1;
                Ok(())
            },
            |g| {
                g.waited += 1;
                Ok(ExitStatus::from_raw(1))
            },
            std::thread::sleep,
            || fallback_hung += 1,
        );
        assert!(hung.polls >= 1);
        assert_eq!(hung.killed, 1);
        assert_eq!(hung.waited, 1);
        assert_eq!(fallback_hung, 1);

        // 3. `try_wait` error also kills, waits, and invokes fallback proxy cleanup.
        let mut errored = FakeGuard {
            polls: 0,
            exit_on_poll: None,
            fail_try_wait: true,
            killed: 0,
            waited: 0,
        };
        let mut fallback_err = 0usize;
        shutdown_guard_child_with(
            &mut errored,
            Duration::from_millis(30),
            Duration::from_millis(10),
            |g| {
                g.polls += 1;
                if g.fail_try_wait {
                    Err(io::Error::other("poll failed"))
                } else {
                    Ok(None)
                }
            },
            |g| {
                g.killed += 1;
                Ok(())
            },
            |g| {
                g.waited += 1;
                Ok(ExitStatus::from_raw(1))
            },
            |_| {},
            || fallback_err += 1,
        );
        assert_eq!(errored.killed, 1);
        assert_eq!(errored.waited, 1);
        assert_eq!(fallback_err, 1);
    }

    #[test]
    fn format_guard_startup_failure_prefers_stdout_error_over_broken_pipe() {
        let pipe_err = io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe");
        let err = format_guard_startup_failure(
            Some(&pipe_err),
            "acquiring the Windows proxy lease (another vdpi may already be running)\n",
            Some(ExitStatus::from_raw(1)),
        );
        let msg = err.to_string();
        assert!(msg.contains("acquiring the Windows proxy lease"));
        assert!(!msg.contains("broken pipe"));

        let silent_err =
            format_guard_startup_failure(Some(&pipe_err), "   \n", Some(ExitStatus::from_raw(7)));
        let silent_msg = silent_err.to_string();
        assert!(silent_msg.contains("guard exited"));
        assert!(silent_msg.contains("broken pipe"));
    }

    #[test]
    fn hydrates_saved_prior_from_global_fallback_when_local_state_absent_or_empty() {
        let dir = TestDir::new("global-fallback");
        let missing_local = dir.0.join(WINDOWS_PROXY_STATE_FILENAME);

        let mut programdata_state = SavedWindowsProxyState::default();
        programdata_state.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: true,
                proxy_server: Some("proxy.corp.local:3128".into()),
                proxy_override: Some("*.corp.local".into()),
                auto_config_url: Some("http://pac.corp.local/proxy.pac".into()),
                auto_detect: None,
            },
        );

        let hydrated =
            load_saved_hkcu_state_with_fallback_using(&missing_local, || programdata_state.clone())
                .unwrap();
        assert_eq!(
            hydrated.auto_config_url.as_deref(),
            Some("http://pac.corp.local/proxy.pac")
        );
        assert!(hydrated.proxy_enable);
        assert_eq!(hydrated.proxy_server.as_deref(), Some("proxy.corp.local:3128"));

        // Empty local state file still falls back to ProgramData backup.
        let empty_local_json = serde_json::to_string(&SavedWindowsProxyState::default()).unwrap();
        fs::write(&missing_local, empty_local_json).unwrap();
        let hydrated_empty =
            load_saved_hkcu_state_with_fallback_using(&missing_local, || programdata_state.clone())
                .unwrap();
        assert_eq!(
            hydrated_empty.auto_config_url.as_deref(),
            Some("http://pac.corp.local/proxy.pac")
        );

        // Non-empty local state takes precedence over global fallback.
        let mut local_state = SavedWindowsProxyState::default();
        local_state.record_hive_if_absent(
            "HKCU",
            SavedWininetHiveState {
                proxy_enable: false,
                proxy_server: None,
                proxy_override: None,
                auto_config_url: Some("http://local.corp/custom.pac".into()),
                auto_detect: None,
            },
        );
        fs::write(
            &missing_local,
            serde_json::to_string(&local_state).unwrap(),
        )
        .unwrap();
        let hydrated_local =
            load_saved_hkcu_state_with_fallback_using(&missing_local, || programdata_state)
                .unwrap();
        assert_eq!(
            hydrated_local.auto_config_url.as_deref(),
            Some("http://local.corp/custom.pac")
        );
    }

    #[test]
    fn pac_url_with_session_nonce_is_vdpi_owned_and_unique_per_session() {
        let nonce_a = next_session_pac_nonce();
        let nonce_b = next_session_pac_nonce();
        assert!(!nonce_a.is_empty());
        assert_ne!(nonce_a, nonce_b);

        let url_a = build_windows_pac_url_with_nonce(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, &nonce_a);
        let url_b = build_windows_pac_url_with_nonce(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, &nonce_b);
        assert!(url_a.starts_with("http://127.0.0.1:8080/vdpi.pac?v="));
        assert!(url_b.starts_with("http://127.0.0.1:8080/vdpi.pac?v="));
        assert_ne!(url_a, url_b);
        assert!(is_vdpi_owned_pac_url(&url_a));
        assert!(is_vdpi_owned_pac_url(&url_b));
    }
}
