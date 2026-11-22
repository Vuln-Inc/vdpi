//! Keep the foreground proxy settings tied to a detached process lease. Closing a
//! Windows console can terminate its processes without running any Rust cleanup.
use super::{build_windows_proxy_override, notify_wininet_refresh};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD, REG_SZ,
};

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";
const READY: &str = "ready";
const DETACHED_PROCESS: u32 = 0x00000008;

#[derive(Serialize, Deserialize)]
struct Request {
    endpoint: SocketAddr,
    bypass: Vec<String>,
}

pub struct ForegroundProxy(Child);

impl ForegroundProxy {
    pub fn activate(endpoint: SocketAddr, bypass: &[String]) -> Result<Self> {
        let mut guard = Self(
            Command::new(std::env::current_exe()?)
                .arg(GUARD_ARG)
                .creation_flags(DETACHED_PROCESS)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("starting the Windows proxy cleanup process")?,
        );
        let pipe = guard.0.stdin.as_mut().expect("guard stdin was piped");
        serde_json::to_writer(
            &mut *pipe,
            &Request {
                endpoint,
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

    let inet = Key::open(super::INTERNET_SETTINGS_SUBKEY)?;
    let server = Value::string(&request.endpoint.to_string());
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
            (
                "ProxyEnable",
                Some(Value {
                    kind: REG_DWORD,
                    data: 1u32.to_le_bytes().to_vec(),
                }),
            ),
        ],
    )?;
    with_proxy_lease(&mut proxy, notify_wininet_refresh, || {
        let mut output = io::stdout().lock();
        writeln!(output, "{READY}")?;
        output.flush()?;
        drop(output);
        // No further messages are necessary. Any return (EOF or broken pipe) restores the lease.
        let _ = input.fill_buf();
        Ok(())
    })
}

fn with_proxy_lease(
    proxy: &mut Settings<'_>,
    refresh: impl Fn(),
    wait: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let outcome = (|| -> Result<()> {
        proxy.apply()?;
        refresh();
        wait()
    })();
    let restored = proxy.restore(Some("ProxyServer"));
    refresh();
    outcome.and(restored)
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
}
