//! Keep the foreground fail-open PAC proxy lease tied to a detached process. Closing a
//! Windows console can terminate its processes without running any Rust cleanup.
use super::{
    broadcast_environment_change, build_windows_pac_url, is_vdpi_owned_pac_url,
    is_vdpi_owned_proxy_env, is_vdpi_owned_wininet_server, notify_wininet_refresh,
    reset_winhttp_proxy_if_vdpi, sanitize_captured_wininet_state, SavedWindowsProxyState,
    SavedWininetHiveState, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
    WINDOWS_PROXY_STATE_FILENAME,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";
const READY: &str = "ready";
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
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

impl ForegroundProxy {
    pub fn activate(endpoint: SocketAddr, env_proxy: bool, bypass: &[String]) -> Result<Self> {
        let exe = std::env::current_exe()?;
        let mut guard =
            Self(spawn_guard_process(&exe).context("starting the Windows proxy cleanup process")?);
        let pipe = guard.0.stdin.as_mut().expect("guard stdin was piped");
        serde_json::to_writer(
            &mut *pipe,
            &Request {
                endpoint,
                env_proxy,
                bypass: bypass.to_vec(),
            },
        )?;
        pipe.write_all(b"\n")?;
        let mut response = String::new();
        BufReader::new(guard.0.stdout.take().expect("guard stdout was piped"))
            .read_line(&mut response)?;
        if response.trim() != READY {
            bail!("Windows proxy could not start safely: {}", response.trim());
        }
        Ok(guard)
    }
}

impl Drop for ForegroundProxy {
    fn drop(&mut self) {
        // The operating system closes this pipe on abrupt parent exit as well.
        drop(self.0.stdin.take());
        match self.0.wait() {
            Ok(status) if status.success() => {}
            result => tracing::warn!(?result, "Windows foreground proxy cleanup failed"),
        }
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

fn guard_inner() -> Result<()> {
    let mut input = io::stdin().lock();
    let mut request = String::new();
    input.read_line(&mut request)?;
    let request: Request = serde_json::from_str(&request).context("invalid proxy lease request")?;
    let base = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is unavailable")?;
    let dir = PathBuf::from(base).join("vdpi");
    fs::create_dir_all(&dir)?;
    let _lease_lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(dir.join("proxy-lease.lock"))
        .context("acquiring the Windows proxy lease (another vdpi may already be running)")?;

    let _ = (request.env_proxy, &request.bypass);
    let pac_url = build_windows_pac_url(request.endpoint.ip(), request.endpoint.port());
    let inet = Key::open(super::INTERNET_SETTINGS_SUBKEY)?;
    let prior_proxy_server = inet.read("ProxyServer")?.and_then(|v| v.as_string());
    let prior_proxy_override = inet.read("ProxyOverride")?.and_then(|v| v.as_string());
    // Use fail-open PAC (`AutoConfigURL` + `ProxyEnable=0`), matching `windows.rs` so an abrupt
    // termination or Defender quarantine never leaves a fail-closed proxy that bricks internet.
    let mut proxy = Settings::prepare(
        &inet,
        [
            ("AutoConfigURL", Some(Value::string(&pac_url))),
            ("ProxyEnable", Some(Value::dword(0))),
        ],
    )?;

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
    if !created_state_file {
        if let Some(saved_prior) = load_saved_hkcu_state(&state_path) {
            apply_saved_prior_wininet_before(
                &mut proxy.changes,
                &saved_prior,
                prior_proxy_server.as_deref(),
            );
        }
    }

    // Never write persistent HKCU\Environment HTTP_PROXY/HTTPS_PROXY/NO_PROXY because
    // Registry env vars cannot fail open if vdpi.exe is killed or quarantined. Clean up
    // any stale vdpi-owned env vars left over from older versions so upgrades auto-heal.
    if cleanup_stale_vdpi_user_env() {
        broadcast_environment_change();
    }
    // Auto-heal any legacy fail-closed WinHTTP manual proxy left by older vdpi versions.
    reset_winhttp_proxy_if_vdpi();

    with_proxy_lease(
        &mut proxy,
        Some((state_path.as_path(), created_state_file)),
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
    let mut cleaned = false;
    for name in ["HTTP_PROXY", "HTTPS_PROXY"] {
        let is_vdpi = env_key
            .read(name)
            .ok()
            .flatten()
            .and_then(|v| v.as_string())
            .as_deref()
            .is_some_and(is_vdpi_owned_proxy_env);
        if is_vdpi && env_key.write(name, None).is_ok() {
            cleaned = true;
        }
    }
    if cleaned {
        let _ = env_key.write("NO_PROXY", None);
    }
    let all_is_vdpi = env_key
        .read("ALL_PROXY")
        .ok()
        .flatten()
        .and_then(|v| v.as_string())
        .as_deref()
        .is_some_and(is_vdpi_owned_proxy_env);
    if all_is_vdpi && env_key.write("ALL_PROXY", None).is_ok() {
        cleaned = true;
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
        == Some(1);
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
        == Some(1);
    SavedWininetHiveState {
        proxy_enable,
        proxy_server: prior_proxy_server.map(ToString::to_string),
        proxy_override: prior_proxy_override.map(ToString::to_string),
        auto_config_url,
    }
}

const AV_LOCK_RETRY_DELAYS_MS: [u64; 5] = [10, 25, 50, 100, 200];

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
            if state_path.exists() {
                let _ = fs::remove_file(tmp_path);
                return Ok(false);
            }
            let rename_res = retry_on_transient_av_lock_with(
                delays_ms,
                || {
                    if state_path.exists() {
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
                    if state_path.exists() {
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
    if state_path.exists() {
        return Ok(false);
    }

    let mut state = SavedWindowsProxyState::default();
    state.record_hive_if_absent("HKCU", raw_snapshot);
    let json = serde_json::to_string(&state).context("serializing Windows proxy state")?;

    let parent = state_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("creating proxy state directory {}", parent.display()))?;

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
    let raw = fs::read_to_string(state_path).ok()?;
    let parsed: SavedWindowsProxyState = serde_json::from_str(&raw).ok()?;
    parsed
        .state_for_root("HKCU")
        .map(sanitize_captured_wininet_state)
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
            let already_enabled = enable.before.as_ref().and_then(Value::as_dword) == Some(1);
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

fn with_proxy_lease(
    proxy: &mut Settings<'_>,
    state_file: Option<(&Path, bool)>,
    refresh_inet: impl Fn(),
    reset_winhttp: impl Fn(),
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let outcome = (|| -> Result<()> {
        proxy.apply()?;
        refresh_inet();
        wait()
    })();
    let applied_all = proxy.applied == proxy.changes.len();
    let inet_restored = proxy.restore(Some("AutoConfigURL"));
    refresh_inet();
    reset_winhttp();
    if let Some((path, created_state_file)) = state_file {
        if should_remove_state_file_on_cleanup(
            inet_restored.is_ok(),
            applied_all,
            created_state_file,
        ) {
            let _ = fs::remove_file(path);
        }
    }
    outcome.and(inet_restored)
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

    fn restore(&mut self, owner: Option<&str>) -> Result<()> {
        let mut failure = None;
        let applied = &self.changes[..self.applied];
        if let Some(owner) = applied.iter().find(|change| Some(change.name) == owner) {
            if self.key.read(owner.name)? != owner.after {
                return Ok(());
            }
        }
        for change in applied.iter().rev() {
            let result = (|| -> Result<()> {
                if self.key.read(change.name)? == change.after {
                    self.key.write(change.name, change.before.as_ref())?;
                }
                Ok(())
            })();
            if let Err(e) = result {
                failure = Some(e);
            }
        }
        self.applied = 0;
        failure.map_or(Ok(()), Err)
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
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

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
                let full = format!(r"HKCU\{path}");
                super::super::run_reg(&["add", &full, "/f"]).unwrap();
                struct TestKey(String);
                impl Drop for TestKey {
                    fn drop(&mut self) {
                        let _ = super::super::run_reg(&["delete", &self.0, "/f"]);
                    }
                }
                let _cleanup = TestKey(full);
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
        let pac_url = "http://127.0.0.1:8080/vdpi.pac";

        let mut stale_pac_and_legacy_manual = vec![
            Change {
                name: "AutoConfigURL",
                before: Some(Value::string("http://[::1]:18080/vdpi.pac")),
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
        };
        let second_created =
            persist_proxy_state_if_absent(&state_path, stale_vdpi_snapshot).unwrap();
        assert!(!second_created);
        assert_eq!(load_saved_hkcu_state(&state_path), Some(expected_corp));

        // Fresh capture containing vdpi-owned PAC and loopback manual proxy must be sanitized.
        let sanitized_dir = TestDir::new("sanitize-state");
        let sanitized_path = sanitized_dir.0.join(WINDOWS_PROXY_STATE_FILENAME);
        let poisoned = SavedWininetHiveState {
            proxy_enable: true,
            proxy_server: Some("127.0.0.1:8080".into()),
            proxy_override: Some("localhost;<local>".into()),
            auto_config_url: Some("http://[::1]:18080/vdpi.pac".into()),
        };
        assert!(persist_proxy_state_if_absent(&sanitized_path, poisoned).unwrap());
        assert_eq!(
            load_saved_hkcu_state(&sanitized_path),
            Some(SavedWininetHiveState::default())
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
        let reg_full = format!(r"HKCU\{reg_path}");
        super::super::run_reg(&["add", &reg_full, "/f"]).unwrap();
        struct TestKey(String);
        impl Drop for TestKey {
            fn drop(&mut self) {
                let _ = super::super::run_reg(&["delete", &self.0, "/f"]);
            }
        }
        let _reg_cleanup = TestKey(reg_full);

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

        let refresh_count = AtomicUsize::new(0);
        let winhttp_reset_count = AtomicUsize::new(0);

        with_proxy_lease(
            &mut settings,
            Some((state_path.as_path(), created)),
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
}
