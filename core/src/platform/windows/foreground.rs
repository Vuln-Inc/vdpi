//! Keep the foreground proxy settings tied to a detached process lease. Closing a
//! Windows console can terminate its processes without running any Rust cleanup.
use super::{
    broadcast_environment_change, build_windows_proxy_override, is_vdpi_owned_proxy_env,
    is_vdpi_owned_wininet_server, normalize_client_proxy_ip, notify_wininet_refresh,
};
use crate::bypass::build_no_proxy_value;
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
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_EXPAND_SZ, REG_SZ,
};

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";
const READY: &str = "ready";
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;

#[derive(Serialize, Deserialize)]
struct Request {
    endpoint: SocketAddr,
    #[serde(default = "default_env_proxy")]
    env_proxy: bool,
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

    let endpoint = SocketAddr::new(
        normalize_client_proxy_ip(request.endpoint.ip()),
        request.endpoint.port(),
    );
    let endpoint_str = endpoint.to_string();
    let inet = Key::open(super::INTERNET_SETTINGS_SUBKEY)?;
    let server = Value::string(&endpoint_str);
    let mut proxy = Settings::prepare(
        &inet,
        [
            ("ProxyServer", Some(server)),
            (
                "ProxyOverride",
                Some(Value::string(&build_windows_proxy_override(
                    &request.bypass,
                ))),
            ),
            ("ProxyEnable", Some(Value::dword(1))),
        ],
    )?;
    normalize_stale_wininet_before(&mut proxy.changes, &endpoint_str);

    // Also lease HKCU\Environment HTTP_PROXY/HTTPS_PROXY/NO_PROXY so libcurl-based
    // Windows desktop apps (such as RobloxPlayerBeta.exe) route through vdpi even in
    // foreground mode, and restore cleanly when the console exits or is killed.
    let env_key = if request.env_proxy {
        Key::open(super::USER_ENV_SUBKEY).ok()
    } else {
        None
    };
    let proxy_url = format!("http://{endpoint_str}");
    let no_proxy_csv = build_no_proxy_value(&request.bypass);
    let mut env_settings = match env_key.as_ref() {
        Some(key) => {
            let mut settings = Settings::prepare(
                key,
                [
                    ("HTTP_PROXY", Some(Value::string(&proxy_url))),
                    ("HTTPS_PROXY", Some(Value::string(&proxy_url))),
                    ("NO_PROXY", Some(Value::string(&no_proxy_csv))),
                ],
            )?;
            normalize_stale_env_before(&mut settings.changes, &proxy_url, &no_proxy_csv);
            Some(settings)
        }
        None => None,
    };

    with_proxy_lease_and_env(
        &mut proxy,
        env_settings.as_mut(),
        notify_wininet_refresh,
        broadcast_environment_change,
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

fn normalize_stale_wininet_before(changes: &mut [Change], endpoint: &str) {
    let before_server = changes
        .iter()
        .find(|c| c.name == "ProxyServer")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_string);
    let before_enabled = changes
        .iter()
        .find(|c| c.name == "ProxyEnable")
        .and_then(|c| c.before.as_ref())
        .and_then(Value::as_dword)
        == Some(1);

    let is_stale_vdpi = before_server.as_deref().is_some_and(|s| {
        s.trim().eq_ignore_ascii_case(endpoint)
            || (before_enabled && is_vdpi_owned_wininet_server(s))
    });
    if !is_stale_vdpi {
        return;
    }
    if let Some(enable) = changes.iter_mut().find(|c| c.name == "ProxyEnable") {
        enable.before = Some(Value::dword(0));
    }
}

fn normalize_stale_env_before(changes: &mut [Change], proxy_url: &str, no_proxy_csv: &str) {
    let mut had_vdpi_proxy = false;
    for change in changes.iter_mut() {
        if matches!(change.name, "HTTP_PROXY" | "HTTPS_PROXY") {
            let is_vdpi = change
                .before
                .as_ref()
                .and_then(Value::as_string)
                .as_deref()
                .is_some_and(|s| {
                    s.trim().eq_ignore_ascii_case(proxy_url) || is_vdpi_owned_proxy_env(s)
                });
            if is_vdpi {
                change.before = None;
                had_vdpi_proxy = true;
            }
        }
    }
    if let Some(no_proxy) = changes.iter_mut().find(|c| c.name == "NO_PROXY") {
        let is_vdpi_no_proxy = had_vdpi_proxy
            || no_proxy
                .before
                .as_ref()
                .and_then(Value::as_string)
                .as_deref()
                .is_some_and(|s| s.trim() == no_proxy_csv);
        if is_vdpi_no_proxy {
            no_proxy.before = None;
        }
    }
}

#[cfg(test)]
fn with_proxy_lease(
    proxy: &mut Settings<'_>,
    refresh: impl Fn(),
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    with_proxy_lease_and_env(proxy, None, refresh, || {}, wait)
}

fn with_proxy_lease_and_env(
    proxy: &mut Settings<'_>,
    mut env_settings: Option<&mut Settings<'_>>,
    refresh_inet: impl Fn(),
    refresh_env: impl Fn(),
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let outcome = (|| -> Result<()> {
        proxy.apply()?;
        refresh_inet();
        if let Some(env) = env_settings.as_deref_mut() {
            env.apply()?;
            refresh_env();
        }
        wait()
    })();
    let env_restored = match env_settings {
        Some(env) => {
            let res = env.restore(Some("HTTPS_PROXY"));
            refresh_env();
            res
        }
        None => Ok(()),
    };
    let inet_restored = proxy.restore(Some("ProxyServer"));
    refresh_inet();
    outcome.and(inet_restored).and(env_restored)
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
    use std::time::{Duration, Instant};

    const ROLE: &str = "VDPI_TEST_PROXY_ROLE";
    const PATH: &str = "VDPI_TEST_PROXY_KEY";
    const TEST: &str =
        "platform::windows::foreground::tests::restores_proxy_after_parent_is_killed";

    #[test]
    fn restores_proxy_after_parent_is_killed() {
        let local = Value::string("127.0.0.1:18080");
        let original = Value::string("previous-proxy.example:3128");
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
                        ("ProxyServer", Some(local)),
                        ("ProxyOverride", Some(Value::string("localhost"))),
                    ],
                )
                .unwrap();
                with_proxy_lease(
                    &mut changes,
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
                key.write("ProxyServer", Some(&original)).unwrap();
                let mut parent = command
                    .envs([(ROLE, "parent"), (PATH, path.as_str())])
                    .spawn()
                    .unwrap();
                let active = wait_until(|| key.read("ProxyOverride").unwrap().is_some());
                let _ = parent.kill();
                parent.wait().unwrap();
                assert!(
                    active,
                    "detached proxy guard never applied the test settings"
                );
                assert!(
                    wait_until(|| {
                        key.read("ProxyServer").unwrap().as_ref() == Some(&original)
                            && key.read("ProxyOverride").unwrap().is_none()
                    }),
                    "detached proxy guard did not restore the settings after parent termination"
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
        let mut stale_inet = vec![
            Change {
                name: "ProxyServer",
                before: Some(Value::string("127.0.0.1:8080")),
                after: Some(Value::string("127.0.0.1:8080")),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(1)),
                after: Some(Value::dword(1)),
            },
        ];
        normalize_stale_wininet_before(&mut stale_inet, "127.0.0.1:8080");
        assert_eq!(stale_inet[1].before, Some(Value::dword(0)));

        let mut stale_loopback_other_port = vec![
            Change {
                name: "ProxyServer",
                before: Some(Value::string("[::1]:18080")),
                after: Some(Value::string("127.0.0.1:8080")),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(1)),
                after: Some(Value::dword(1)),
            },
        ];
        normalize_stale_wininet_before(&mut stale_loopback_other_port, "127.0.0.1:8080");
        assert_eq!(stale_loopback_other_port[1].before, Some(Value::dword(0)));

        let mut external_inet = vec![
            Change {
                name: "ProxyServer",
                before: Some(Value::string("proxy.corp.local:3128")),
                after: Some(Value::string("127.0.0.1:8080")),
            },
            Change {
                name: "ProxyEnable",
                before: Some(Value::dword(1)),
                after: Some(Value::dword(1)),
            },
        ];
        normalize_stale_wininet_before(&mut external_inet, "127.0.0.1:8080");
        assert_eq!(external_inet[1].before, Some(Value::dword(1)));

        let mut stale_env = vec![
            Change {
                name: "HTTP_PROXY",
                before: Some(Value::string("http://127.0.0.1:8080")),
                after: Some(Value::string("http://127.0.0.1:8080")),
            },
            Change {
                name: "HTTPS_PROXY",
                before: Some(Value::string("http://[::1]:18080")),
                after: Some(Value::string("http://127.0.0.1:8080")),
            },
            Change {
                name: "NO_PROXY",
                before: Some(Value::string("localhost,127.0.0.1")),
                after: Some(Value::string("localhost,127.0.0.1")),
            },
        ];
        normalize_stale_env_before(
            &mut stale_env,
            "http://127.0.0.1:8080",
            "localhost,127.0.0.1",
        );
        assert!(stale_env.iter().all(|c| c.before.is_none()));

        let mut external_env = vec![
            Change {
                name: "HTTP_PROXY",
                before: Some(Value::string("http://proxy.corp.local:3128")),
                after: Some(Value::string("http://127.0.0.1:8080")),
            },
            Change {
                name: "HTTPS_PROXY",
                before: Some(Value::string("http://proxy.corp.local:3128")),
                after: Some(Value::string("http://127.0.0.1:8080")),
            },
            Change {
                name: "NO_PROXY",
                before: Some(Value::string("corp.internal")),
                after: Some(Value::string("localhost,127.0.0.1")),
            },
        ];
        normalize_stale_env_before(
            &mut external_env,
            "http://127.0.0.1:8080",
            "localhost,127.0.0.1",
        );
        assert!(external_env.iter().all(|c| c.before.is_some()));
    }
}
