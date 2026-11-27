use super::SystemProxySession;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use vdpi_core::config::VpnCoexistence;

pub const GUARD_ARG: &str = "--internal-foreground-proxy-guard";

extern "C" {
    fn setsid() -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForegroundProxySpec {
    pub addr: SocketAddr,
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub bypass: Vec<String>,
    #[serde(default)]
    pub include_domains: Vec<String>,
    #[serde(default)]
    pub vpn_coexistence: VpnCoexistence,
}

pub struct ForegroundProxy {
    child: Child,
    pub summary: String,
}

impl ForegroundProxy {
    pub fn activate(addr: SocketAddr, socks_port: Option<u16>, bypass: &[String]) -> Result<Self> {
        Self::activate_spec(&ForegroundProxySpec {
            addr,
            socks_port,
            bypass: bypass.to_vec(),
            include_domains: Vec::new(),
            vpn_coexistence: VpnCoexistence::default(),
        })
    }

    pub fn activate_with_options(
        addr: SocketAddr,
        socks_port: Option<u16>,
        bypass: &[String],
        include_domains: &[String],
        vpn_coexistence: VpnCoexistence,
    ) -> Result<Self> {
        Self::activate_spec(&ForegroundProxySpec {
            addr,
            socks_port,
            bypass: bypass.to_vec(),
            include_domains: include_domains.to_vec(),
            vpn_coexistence,
        })
    }

    pub fn activate_spec(spec: &ForegroundProxySpec) -> Result<Self> {
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.arg(GUARD_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Detach before exec so a terminal hangup only reaches the proxy, not its lease keeper.
        unsafe {
            cmd.pre_exec(|| {
                if setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut guard = Self {
            child: cmd.spawn().context("starting proxy cleanup process")?,
            summary: String::new(),
        };
        let pipe = guard.child.stdin.as_mut().expect("guard stdin was piped");
        serde_json::to_writer(&mut *pipe, spec)?;
        pipe.write_all(b"\n")?;
        let mut response = String::new();
        BufReader::new(guard.child.stdout.take().expect("guard stdout was piped"))
            .read_line(&mut response)?;
        let Some(summary) = response.trim_end().strip_prefix("ready: ") else {
            bail!("system proxy could not start safely: {}", response.trim());
        };
        guard.summary = summary.to_owned();
        Ok(guard)
    }
}

impl Drop for ForegroundProxy {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        match self.child.wait() {
            Ok(status) if status.success() => {}
            result => tracing::warn!(?result, "foreground proxy cleanup failed"),
        }
    }
}

pub fn run_guard() -> Result<()> {
    // Ignore termination/hangup signals at guard startup so `launchctl bootout` or terminal
    // hangup cannot kill the cleanup guard before PAC/proxy restoration finishes on parent EOF.
    // SAFETY: `SIG_IGN` is a valid signal disposition for `SIGTERM`, `SIGINT`, and `SIGHUP`.
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let result = guard_inner();
    if let Err(e) = &result {
        let _ = writeln!(
            io::stdout(),
            "{}",
            format!("{e:#}").replace(['\r', '\n'], " ")
        );
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ElevatedUser {
    uid: libc::uid_t,
    gid: libc::gid_t,
    home_dir: Option<PathBuf>,
}

#[derive(Debug, Default)]
struct ElevationEnv {
    sudo_uid: Option<String>,
    sudo_gid: Option<String>,
    sudo_user: Option<String>,
    pkexec_uid: Option<String>,
    doas_user: Option<String>,
    home: Option<PathBuf>,
}

fn parse_nonzero_uid(raw: Option<&str>) -> Option<libc::uid_t> {
    raw.and_then(|s| s.trim().parse::<libc::uid_t>().ok())
        .filter(|&uid| uid != 0)
}

fn parse_nonzero_gid(raw: Option<&str>) -> Option<libc::gid_t> {
    raw.and_then(|s| s.trim().parse::<libc::gid_t>().ok())
        .filter(|&gid| gid != 0)
}

fn sanitize_username(raw: Option<&str>) -> Option<&str> {
    let trimmed = raw?.trim();
    if trimmed.is_empty()
        || trimmed == "root"
        || trimmed.contains('/')
        || trimmed.contains('\0')
    {
        return None;
    }
    Some(trimmed)
}

fn lookup_passwd_by_uid(uid: libc::uid_t) -> Option<ElevatedUser> {
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd` and `buf` are valid writable buffers for `getpwuid_r`.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwuid_r` succeeded with a non-null `result` pointing to `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    let home_dir = if pwd.pw_dir.is_null() {
        None
    } else {
        // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
        let bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
        (!bytes.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(bytes)))
    };
    Some(ElevatedUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir,
    })
}

fn lookup_passwd_by_name(name: &str) -> Option<ElevatedUser> {
    let c_name = CString::new(name).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
    let mut buf = vec![0u8; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `c_name` is NUL-terminated; `pwd` and `buf` are valid writable buffers.
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    // SAFETY: `getpwnam_r` succeeded with a non-null `result` pointing to `pwd`.
    let pwd = unsafe { pwd.assume_init() };
    let home_dir = if pwd.pw_dir.is_null() {
        None
    } else {
        // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
        let bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
        (!bytes.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(bytes)))
    };
    Some(ElevatedUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home_dir,
    })
}

fn resolve_elevated_user_from(
    env: &ElevationEnv,
    lookup_uid: impl Fn(libc::uid_t) -> Option<ElevatedUser>,
    lookup_name: impl Fn(&str) -> Option<ElevatedUser>,
) -> Option<ElevatedUser> {
    let fallback_home = env
        .home
        .as_deref()
        .filter(|p| !p.as_os_str().is_empty() && *p != Path::new("/root"))
        .map(Path::to_path_buf);

    let sudo_gid = parse_nonzero_gid(env.sudo_gid.as_deref());

    // 1. SUDO_UID
    if let Some(uid) = parse_nonzero_uid(env.sudo_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = sudo_gid
            .or_else(|| entry.as_ref().map(|e| e.gid))
            .unwrap_or(libc::gid_t::MAX);
        let home_dir = entry.and_then(|e| e.home_dir).or(fallback_home);
        return Some(ElevatedUser { uid, gid, home_dir });
    }

    // 2. SUDO_USER
    if let Some(user) = sanitize_username(env.sudo_user.as_deref()) {
        if let Some(entry) = lookup_name(user).filter(|e| e.uid != 0) {
            let gid = sudo_gid.unwrap_or(entry.gid);
            let home_dir = entry.home_dir.or(fallback_home);
            return Some(ElevatedUser {
                uid: entry.uid,
                gid,
                home_dir,
            });
        }
    }

    // 3. PKEXEC_UID
    if let Some(uid) = parse_nonzero_uid(env.pkexec_uid.as_deref()) {
        let entry = lookup_uid(uid);
        let gid = entry.as_ref().map(|e| e.gid).unwrap_or(libc::gid_t::MAX);
        let home_dir = entry.and_then(|e| e.home_dir).or(fallback_home);
        return Some(ElevatedUser { uid, gid, home_dir });
    }

    // 4. DOAS_USER
    if let Some(user) = sanitize_username(env.doas_user.as_deref()) {
        if let Some(entry) = lookup_name(user).filter(|e| e.uid != 0) {
            let home_dir = entry.home_dir.or(fallback_home);
            return Some(ElevatedUser {
                uid: entry.uid,
                gid: entry.gid,
                home_dir,
            });
        }
    }

    None
}

fn resolve_elevated_user() -> Option<ElevatedUser> {
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let env = ElevationEnv {
        sudo_uid: std::env::var("SUDO_UID").ok(),
        sudo_gid: std::env::var("SUDO_GID").ok(),
        sudo_user: std::env::var("SUDO_USER").ok(),
        pkexec_uid: std::env::var("PKEXEC_UID").ok(),
        doas_user: std::env::var("DOAS_USER").ok(),
        home: std::env::var_os("HOME").map(PathBuf::from),
    };
    resolve_elevated_user_from(&env, lookup_passwd_by_uid, lookup_passwd_by_name)
}

/// Refuses to traverse, create, open, or chown through any symlink located
/// beneath `user_home` (checking every intermediate parent directory and the
/// target component itself).
fn ensure_no_symlink_under_home(path: &Path, user_home: &Path) -> Result<()> {
    if !path.starts_with(user_home) {
        return Ok(());
    }
    let Ok(rel) = path.strip_prefix(user_home) else {
        return Ok(());
    };
    let components: Vec<Component<'_>> = rel.components().collect();
    let last_idx = components.len().saturating_sub(1);
    let mut cur = user_home.to_path_buf();
    for (idx, comp) in components.into_iter().enumerate() {
        match comp {
            Component::Normal(part) => cur.push(part),
            Component::CurDir => continue,
            _ => {
                bail!(
                    "refusing to traverse non-canonical path '{}' under user home while running as root",
                    path.display()
                );
            }
        }
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "refusing to traverse or modify symlink '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(meta) if idx < last_idx && !meta.file_type().is_dir() => {
                bail!(
                    "refusing to traverse non-directory '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect path {}", cur.display()));
            }
        }
    }
    Ok(())
}

fn lchown_path(path: &Path, uid: libc::uid_t, gid: libc::gid_t) {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path string; `lchown` never follows symlinks.
    let _ = unsafe { libc::lchown(c_path.as_ptr(), uid, gid) };
}

fn chown_to_sudo_user_if_root(path: &Path) {
    let Some(user) = resolve_elevated_user() else {
        return;
    };
    let check_home = user
        .home_dir
        .clone()
        .or_else(|| crate::service::home_dir().ok());
    if let Some(ref home) = check_home {
        if ensure_no_symlink_under_home(path, home).is_err() {
            return;
        }
    }
    lchown_path(path, user.uid, user.gid);
}

fn ensure_root_dir_safe(root: &Path, elevated: Option<&ElevatedUser>) -> Result<()> {
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        let check_home = elevated
            .and_then(|u| u.home_dir.clone())
            .or_else(|| crate::service::home_dir().ok());
        if let Some(ref home) = check_home {
            ensure_no_symlink_under_home(root, home)?;
            if root.starts_with(home) {
                let rel = root.strip_prefix(home).unwrap_or_else(|_| Path::new(""));
                let mut cur = home.to_path_buf();
                for comp in rel.components() {
                    match comp {
                        Component::Normal(part) => cur.push(part),
                        Component::CurDir => continue,
                        _ => {
                            bail!(
                                "refusing to create non-canonical path '{}' under user home while running as root",
                                root.display()
                            );
                        }
                    }
                    match fs::symlink_metadata(&cur) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            bail!(
                                "refusing to traverse symlink '{}' under user home while running as root",
                                cur.display()
                            );
                        }
                        Ok(meta) if !meta.file_type().is_dir() => {
                            bail!(
                                "refusing to use non-directory '{}' under user home while running as root",
                                cur.display()
                            );
                        }
                        Ok(meta) => {
                            if meta.uid() == 0 {
                                if let Some(user) = elevated {
                                    lchown_path(&cur, user.uid, user.gid);
                                }
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::NotFound => {
                            match fs::create_dir(&cur) {
                                Ok(()) => {}
                                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                                Err(e) => {
                                    return Err(e).with_context(|| {
                                        format!("failed to create directory {}", cur.display())
                                    });
                                }
                            }
                            let meta = fs::symlink_metadata(&cur).with_context(|| {
                                format!("failed to inspect directory {}", cur.display())
                            })?;
                            if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
                                bail!(
                                    "refusing to use symlink or non-directory '{}' under user home while running as root",
                                    cur.display()
                                );
                            }
                            if let Some(user) = elevated {
                                lchown_path(&cur, user.uid, user.gid);
                            }
                        }
                        Err(err) => {
                            return Err(err).with_context(|| {
                                format!("failed to inspect directory {}", cur.display())
                            });
                        }
                    }
                }
                return Ok(());
            }
        }
        if let Ok(meta) = fs::symlink_metadata(root) {
            if meta.file_type().is_symlink() {
                bail!(
                    "refusing to traverse symlink '{}' while running as root",
                    root.display()
                );
            }
        }
    }

    fs::create_dir_all(root)
        .with_context(|| format!("failed to create directory {}", root.display()))?;
    chown_to_sudo_user_if_root(root);
    Ok(())
}

fn open_lock_file_safe(root: &Path, elevated: Option<&ElevatedUser>) -> Result<File> {
    let lock_path = root.join("proxy-lease.lock");
    // SAFETY: `geteuid(2)` is always safe to call and never fails.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        let check_home = elevated
            .and_then(|u| u.home_dir.clone())
            .or_else(|| crate::service::home_dir().ok());
        if let Some(ref home) = check_home {
            ensure_no_symlink_under_home(&lock_path, home)?;
        }
        let root_meta = fs::symlink_metadata(root)
            .with_context(|| format!("failed to inspect directory {}", root.display()))?;
        if root_meta.file_type().is_symlink() || !root_meta.file_type().is_dir() {
            bail!(
                "refusing to open proxy lease inside symlink or non-directory '{}' while running as root",
                root.display()
            );
        }
    }

    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)?;

    let lock_meta = lock
        .metadata()
        .with_context(|| format!("failed to inspect {}", lock_path.display()))?;
    if !lock_meta.file_type().is_file() {
        bail!(
            "refusing to use non-regular proxy lease file '{}'",
            lock_path.display()
        );
    }

    if let Some(user) = elevated {
        if lock_meta.uid() == 0 {
            // SAFETY: `lock` is a valid open file descriptor; `fchown` operates on the open
            // inode directly without re-resolving path components.
            let _ = unsafe { libc::fchown(lock.as_raw_fd(), user.uid, user.gid) };
        }
    }

    Ok(lock)
}

fn guard_inner() -> Result<()> {
    let mut input = io::stdin().lock();
    let mut request = String::new();
    input.read_line(&mut request)?;
    let req: ForegroundProxySpec = serde_json::from_str(&request)?;
    let root = crate::service::vdpi_root_dir()?;
    let elevated = resolve_elevated_user();
    ensure_root_dir_safe(&root, elevated.as_ref())?;
    let lock = open_lock_file_safe(&root, elevated.as_ref())?;
    // LOCK_EX | LOCK_NB. The open file holds the lock until cleanup completes.
    if unsafe { flock(lock.as_raw_fd(), 2 | 4) } == -1 {
        return Err(io::Error::last_os_error())
            .context("acquiring the desktop proxy lease (another vdpi may already be running)");
    }

    let session = SystemProxySession::activate_with_options(
        req.addr.ip(),
        req.addr.port(),
        req.socks_port,
        req.socks_port.is_some(),
        false,
        &req.bypass,
        &req.include_domains,
        req.vpn_coexistence,
    )?;
    let result = (|| -> Result<()> {
        let mut output = io::stdout().lock();
        writeln!(
            output,
            "ready: {}",
            session.summary().replace(['\r', '\n'], " ")
        )?;
        output.flush()?;
        drop(output);
        let _ = input.fill_buf();
        Ok(())
    })();
    session.deactivate_foreground();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_test_dir(tag: &str) -> PathBuf {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "vdpi-unix-fg-{tag}-{}-{seq}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    #[test]
    fn foreground_proxy_spec_serde_round_trip_and_defaults() {
        let spec = ForegroundProxySpec {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            socks_port: Some(1080),
            bypass: vec!["localhost".to_string()],
            include_domains: vec!["example.com".to_string()],
            vpn_coexistence: VpnCoexistence::Warn,
        };
        let json = serde_json::to_string(&spec).expect("serialize ForegroundProxySpec");
        let parsed: ForegroundProxySpec =
            serde_json::from_str(&json).expect("deserialize ForegroundProxySpec");
        assert_eq!(parsed, spec);

        // Minimal legacy payload omits include_domains and vpn_coexistence.
        let minimal = r#"{"addr":"127.0.0.1:8080","socks_port":null,"bypass":[]}"#;
        let parsed_min: ForegroundProxySpec =
            serde_json::from_str(minimal).expect("deserialize minimal ForegroundProxySpec");
        assert!(parsed_min.include_domains.is_empty());
        assert_eq!(parsed_min.vpn_coexistence, VpnCoexistence::AutoYield);
    }

    #[test]
    fn resolve_elevated_user_supports_sudo_pkexec_and_doas() {
        let lookup_uid = |uid: libc::uid_t| match uid {
            1000 => Some(ElevatedUser {
                uid: 1000,
                gid: 1000,
                home_dir: Some(PathBuf::from("/home/alice")),
            }),
            1001 => Some(ElevatedUser {
                uid: 1001,
                gid: 100,
                home_dir: Some(PathBuf::from("/home/bob")),
            }),
            _ => None,
        };
        let lookup_name = |name: &str| match name {
            "alice" => Some(ElevatedUser {
                uid: 1000,
                gid: 1000,
                home_dir: Some(PathBuf::from("/home/alice")),
            }),
            "bob" => Some(ElevatedUser {
                uid: 1001,
                gid: 100,
                home_dir: Some(PathBuf::from("/home/bob")),
            }),
            "root" => Some(ElevatedUser {
                uid: 0,
                gid: 0,
                home_dir: Some(PathBuf::from("/root")),
            }),
            _ => None,
        };

        // PKEXEC_UID resolves uid/gid/home via passwd.
        let pkexec_env = ElevationEnv {
            pkexec_uid: Some("1001".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&pkexec_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 1001,
                gid: 100,
                home_dir: Some(PathBuf::from("/home/bob")),
            })
        );

        // PKEXEC_UID=0 is rejected.
        let pkexec_root = ElevationEnv {
            pkexec_uid: Some("0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&pkexec_root, lookup_uid, lookup_name),
            None
        );

        // DOAS_USER resolves via getpwnam_r.
        let doas_env = ElevationEnv {
            doas_user: Some("bob".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&doas_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 1001,
                gid: 100,
                home_dir: Some(PathBuf::from("/home/bob")),
            })
        );

        // DOAS_USER=root and path-like usernames are rejected.
        let doas_root = ElevationEnv {
            doas_user: Some("root".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&doas_root, lookup_uid, lookup_name),
            None
        );
        let doas_slash = ElevationEnv {
            doas_user: Some("../bob".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&doas_slash, lookup_uid, lookup_name),
            None
        );

        // SUDO_UID takes precedence over PKEXEC_UID and DOAS_USER.
        let mixed_env = ElevationEnv {
            sudo_uid: Some("1000".to_string()),
            sudo_gid: Some("1000".to_string()),
            pkexec_uid: Some("1001".to_string()),
            doas_user: Some("bob".to_string()),
            ..Default::default()
        };
        assert_eq!(
            resolve_elevated_user_from(&mixed_env, lookup_uid, lookup_name),
            Some(ElevatedUser {
                uid: 1000,
                gid: 1000,
                home_dir: Some(PathBuf::from("/home/alice")),
            })
        );
    }

    #[test]
    fn ensure_no_symlink_under_home_rejects_intermediate_and_target_symlinks() {
        let base = temp_test_dir("symlink");
        let home = base.join("home");
        let outside = base.join("outside");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&outside).unwrap();

        // Real nested directory passes.
        let real_root = home.join(".vdpi");
        fs::create_dir_all(&real_root).unwrap();
        let real_lock = real_root.join("proxy-lease.lock");
        assert!(ensure_no_symlink_under_home(&real_lock, &home).is_ok());

        // Intermediate symlink under user home is rejected.
        let sym_root = home.join("sym-vdpi");
        std::os::unix::fs::symlink(&outside, &sym_root).unwrap();
        let lock_through_sym = sym_root.join("proxy-lease.lock");
        assert!(ensure_no_symlink_under_home(&lock_through_sym, &home).is_err());

        // Deeper intermediate symlink under user home is rejected.
        let deep_lock = sym_root.join("nested").join("proxy-lease.lock");
        assert!(ensure_no_symlink_under_home(&deep_lock, &home).is_err());

        // Symlink at the final lock file path is rejected.
        let target_file = outside.join("target");
        fs::write(&target_file, b"").unwrap();
        let sym_lock = real_root.join("proxy-lease.lock");
        std::os::unix::fs::symlink(&target_file, &sym_lock).unwrap();
        assert!(ensure_no_symlink_under_home(&sym_lock, &home).is_err());

        // ParentDir traversal component is rejected.
        let traversal = home.join(".vdpi").join("..").join("outside");
        assert!(ensure_no_symlink_under_home(&traversal, &home).is_err());

        let _ = fs::remove_dir_all(&base);
    }
}
