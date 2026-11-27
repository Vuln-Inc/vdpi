use std::collections::hash_map::RandomState;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::hash::{BuildHasher, Hash, Hasher};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use vdpi::config_file::{render_config_toml, user_config_path, FileConfig};
use vdpi::service::installed_binary_path;
use vdpi::update::strip_windows_verbatim_prefix;
use vdpi_core::dns::redact_urls_in_text;

const MAX_CAPTURE_BYTES: usize = 256 * 1024;
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(25);
const KILL_WAIT_GRACE: Duration = Duration::from_millis(250);
const APPLY_CONFIG_TIMEOUT_SECS: u64 = 90;
const APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE: i32 = 2;

#[cfg(windows)]
const WINDOWS_RENAME_MAX_RETRIES: usize = 5;
#[cfg(windows)]
const WINDOWS_RENAME_RETRY_BACKOFF: Duration = Duration::from_millis(25);

#[cfg(any(target_os = "windows", test))]
const WIN32_ERROR_CANCELLED: u32 = 1223;
#[cfg(any(target_os = "windows", test))]
const MAX_NON_INFINITE_WAIT_MS: u64 = (u32::MAX as u64) - 1;

#[cfg(any(target_os = "macos", test))]
const MACOS_ELEVATION_PROMPT: &str =
    "vdpi Desktop needs administrator privileges to manage the background service.";

#[cfg(target_os = "linux")]
const PKEXEC_CANDIDATES: &[&str] = &["/usr/bin/pkexec", "/bin/pkexec"];

#[cfg(any(target_os = "linux", test))]
const LINUX_SCRUBBED_ENV_VARS: &[&str] = &[
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

static TEMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);
static RESOURCE_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Result of executing a `vdpi` CLI sidecar command (directly or elevated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarOutcome {
    /// Command completed with exit code 0; contains URL-redacted stdout (if captured).
    Ok(String),
    /// `vdpi config apply-file` saved the configuration atomically (exit code 2),
    /// but restarting the running background service failed or could not complete;
    /// contains URL-redacted detail (if captured).
    SavedNeedsRestart(String),
    /// User cancelled the OS elevation prompt (UAC, macOS authorization dialog, or Polkit).
    Cancelled,
    /// Command failed to launch, timed out, or exited non-zero; contains URL-redacted detail.
    Err(String),
}

#[derive(Debug, Clone)]
struct CapturedOutput {
    exit_code: Option<i32>,
    success: bool,
    stdout: String,
    stderr: String,
}

/// Records the Tauri application resource directory discovered during `lib.rs::setup()`
/// so sidecar binary resolution can locate packaged `vdpi` binaries (including Linux
/// `.deb`/`.rpm`/AppImage layouts where resources live under `/usr/lib/vdpi Desktop/`).
pub fn set_resource_dir(dir: PathBuf) {
    if !dir.as_os_str().is_empty() {
        let _ = RESOURCE_DIR.set(dir);
    }
}

#[cfg(windows)]
mod platform_fs {
    use std::fs::{File, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_LOCK_VIOLATION, ERROR_PATH_NOT_FOUND,
        ERROR_SHARING_VIOLATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };

    fn encode_wide_nul(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_not_found_error(err: &io::Error) -> bool {
        err.kind() == ErrorKind::NotFound
            || matches!(
                err.raw_os_error(),
                Some(code)
                    if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32
            )
    }

    fn is_reparse_point_attrs(attrs: u32) -> bool {
        attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }

    /// Queries Win32 `GetFileAttributesW` without following symlinks/reparse points on the
    /// final path component. Returns `Ok(None)` when the path does not exist.
    fn attributes_no_follow(path: &Path) -> io::Result<Option<u32>> {
        let wide = encode_wide_nul(path);
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer kept alive for the synchronous call.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs != INVALID_FILE_ATTRIBUTES {
            return Ok(Some(attrs));
        }
        let err = io::Error::last_os_error();
        if is_not_found_error(&err) {
            return Ok(None);
        }
        Err(err)
    }

    pub(super) fn path_exists_no_follow(path: &Path) -> Result<bool, String> {
        attributes_no_follow(path)
            .map(|attrs| attrs.is_some())
            .map_err(|err| format!("Failed to inspect attributes for {}: {err}", path.display()))
    }

    pub(super) fn reject_symlink_or_reparse(path: &Path) -> Result<(), String> {
        if let Some(attrs) = attributes_no_follow(path)
            .map_err(|err| format!("Failed to inspect attributes for {}: {err}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                return Err(format!(
                    "Refusing to access symlink/reparse point: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    pub(super) fn reject_target_symlink_or_dir(path: &Path) -> Result<(), String> {
        if let Some(attrs) = attributes_no_follow(path)
            .map_err(|err| format!("Failed to inspect attributes for {}: {err}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                return Err(format!(
                    "Refusing to access symlink/reparse point: {}",
                    path.display()
                ));
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                return Err(format!(
                    "Refusing to treat directory as temporary config file: {}",
                    path.display()
                ));
            }
        }
        Ok(())
    }

    pub(super) fn verify_dir_not_symlink(path: &Path) -> Result<bool, String> {
        match attributes_no_follow(path)
            .map_err(|err| format!("Failed to inspect directory {}: {err}", path.display()))?
        {
            None => Ok(false),
            Some(attrs) => {
                if is_reparse_point_attrs(attrs) {
                    return Err(format!(
                        "Refusing to use symlink/reparse point directory: {}",
                        path.display()
                    ));
                }
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    return Err(format!(
                        "Configuration directory path is not a directory: {}",
                        path.display()
                    ));
                }
                Ok(true)
            }
        }
    }

    pub(super) fn verify_opened_regular_file(file: &File, path: &Path) -> Result<(), String> {
        let meta = file
            .metadata()
            .map_err(|err| format!("Failed to inspect metadata for {}: {err}", path.display()))?;
        if is_reparse_point_attrs(meta.file_attributes()) || !meta.is_file() {
            return Err(format!(
                "Refusing to access non-regular file or reparse point: {}",
                path.display()
            ));
        }
        Ok(())
    }

    pub(super) fn configure_temp_open_options(opts: &mut OpenOptions) {
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    pub(super) fn is_retryable_rename_error(err: &io::Error) -> bool {
        if err.kind() == ErrorKind::PermissionDenied {
            return true;
        }
        matches!(
            err.raw_os_error(),
            Some(code)
                if code == ERROR_ACCESS_DENIED as i32
                    || code == ERROR_SHARING_VIOLATION as i32
                    || code == ERROR_LOCK_VIOLATION as i32
        )
    }
}

#[cfg(unix)]
mod platform_fs {
    use std::fs::{self, File, OpenOptions};
    use std::io::ErrorKind;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    pub(super) fn path_exists_no_follow(path: &Path) -> Result<bool, String> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(format!("Failed to inspect path {}: {err}", path.display())),
        }
    }

    pub(super) fn reject_symlink_or_reparse(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                Err(format!("Refusing to access symlink: {}", path.display()))
            }
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("Failed to inspect path {}: {err}", path.display())),
        }
    }

    pub(super) fn reject_target_symlink_or_dir(path: &Path) -> Result<(), String> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!("Refusing to access symlink: {}", path.display()));
                }
                if meta.is_dir() {
                    return Err(format!(
                        "Refusing to treat directory as temporary config file: {}",
                        path.display()
                    ));
                }
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("Failed to inspect path {}: {err}", path.display())),
        }
    }

    pub(super) fn verify_dir_not_symlink(path: &Path) -> Result<bool, String> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "Refusing to use symlink directory: {}",
                        path.display()
                    ));
                }
                if !meta.is_dir() {
                    return Err(format!(
                        "Configuration directory path is not a directory: {}",
                        path.display()
                    ));
                }
                Ok(true)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(format!(
                "Failed to inspect directory {}: {err}",
                path.display()
            )),
        }
    }

    pub(super) fn verify_opened_regular_file(file: &File, path: &Path) -> Result<(), String> {
        let meta = file
            .metadata()
            .map_err(|err| format!("Failed to inspect metadata for {}: {err}", path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            return Err(format!(
                "Refusing to access non-regular file or symlink: {}",
                path.display()
            ));
        }
        Ok(())
    }

    pub(super) fn configure_temp_open_options(opts: &mut OpenOptions) {
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
}

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_allowed_os_system_symlink_path(path: &Path, uid: u32, is_linux: bool) -> bool {
    if uid != 0 {
        return false;
    }
    let Some(raw) = path.to_str() else {
        return false;
    };
    if is_linux {
        matches!(raw, "/home" | "/usr/local" | "/var" | "/tmp" | "/etc")
    } else {
        matches!(raw, "/var" | "/tmp" | "/etc")
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_allowed_os_system_symlink(path: &Path, meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    is_allowed_os_system_symlink_path(path, meta.uid(), cfg!(target_os = "linux"))
}

/// Walks every path component from root/prefix down to the final component and
/// returns `false` if any component is `..`, missing, a symlink, or a Windows
/// reparse point (junction/symlink). Intermediate components must be directories.
///
/// Allows standard root-owned (`uid == 0`) OS compatibility symlinks as intermediate
/// directory components: `/var`, `/tmp`, `/etc` on macOS, and `/home`, `/usr/local`,
/// `/var`, `/tmp`, `/etc` on Linux (for ostree/immutable distros such as Fedora
/// Silverblue and Bazzite).
fn verify_all_path_components_no_symlink_or_reparse(path: &Path) -> bool {
    let clean = strip_windows_verbatim_prefix(path);
    let components: Vec<Component<'_>> = clean.components().collect();
    if components.is_empty() {
        return false;
    }

    let last_normal_idx = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));
    let mut current = PathBuf::new();

    for (idx, comp) in components.iter().enumerate() {
        match comp {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(comp.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => return false,
            Component::Normal(seg) => {
                current.push(seg);
                let Ok(meta) = fs::symlink_metadata(&current) else {
                    return false;
                };
                if is_symlink_or_reparse(&meta) {
                    #[cfg(any(target_os = "macos", target_os = "linux"))]
                    if Some(idx) != last_normal_idx
                        && is_allowed_os_system_symlink(&current, &meta)
                        && matches!(fs::metadata(&current), Ok(target) if target.is_dir())
                    {
                        continue;
                    }
                    return false;
                }
                if Some(idx) != last_normal_idx && !meta.is_dir() {
                    return false;
                }
            }
        }
    }

    last_normal_idx.is_some()
}

fn reject_parent_dir_traversal(path: &Path) -> Result<(), String> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "Refusing to access path containing parent directory traversal ('..'): {}",
            path.display()
        ));
    }
    Ok(())
}

fn push_abs_env_dir(roots: &mut Vec<PathBuf>, var: &str) {
    if let Some(val) = std::env::var_os(var) {
        if !val.is_empty() {
            let candidate = strip_windows_verbatim_prefix(&PathBuf::from(val));
            if candidate.is_absolute() {
                roots.push(candidate);
            }
        }
    }
}

fn user_home_and_config_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    #[cfg(windows)]
    {
        push_abs_env_dir(&mut roots, "USERPROFILE");
        push_abs_env_dir(&mut roots, "LOCALAPPDATA");
        push_abs_env_dir(&mut roots, "APPDATA");
        push_abs_env_dir(&mut roots, "ProgramData");
    }
    #[cfg(not(windows))]
    {
        push_abs_env_dir(&mut roots, "HOME");
        push_abs_env_dir(&mut roots, "XDG_CONFIG_HOME");
    }
    let tmp = strip_windows_verbatim_prefix(&std::env::temp_dir());
    if tmp.is_absolute() {
        roots.push(tmp.clone());
    }
    #[cfg(unix)]
    {
        if let Ok(canon_tmp) = fs::canonicalize(&tmp) {
            if canon_tmp.is_absolute() && !roots.contains(&canon_tmp) {
                roots.push(canon_tmp);
            }
        }
        let slash_tmp = PathBuf::from("/tmp");
        if !roots.contains(&slash_tmp) {
            roots.push(slash_tmp);
        }
    }
    roots
}

fn components_equal(a: Component<'_>, b: Component<'_>) -> bool {
    #[cfg(windows)]
    {
        match (a, b) {
            (Component::Prefix(pa), Component::Prefix(pb)) => pa
                .as_os_str()
                .to_string_lossy()
                .eq_ignore_ascii_case(&pb.as_os_str().to_string_lossy()),
            (Component::RootDir, Component::RootDir) => true,
            (Component::CurDir, Component::CurDir) => true,
            (Component::ParentDir, Component::ParentDir) => true,
            (Component::Normal(na), Component::Normal(nb)) => na
                .to_string_lossy()
                .eq_ignore_ascii_case(&nb.to_string_lossy()),
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

/// If `path` is inside (or equal to) `root`, returns `(matched_prefix, remaining_normal_segments)`
/// while preserving the original casing of `path`.
fn split_under_root(path: &Path, root: &Path) -> Option<(PathBuf, Vec<OsString>)> {
    let root_comps: Vec<Component<'_>> = root.components().collect();
    if root_comps.is_empty() {
        return None;
    }
    let path_comps: Vec<Component<'_>> = path.components().collect();
    if path_comps.len() < root_comps.len() {
        return None;
    }
    for (rc, pc) in root_comps.iter().zip(path_comps.iter()) {
        if !components_equal(*rc, *pc) {
            return None;
        }
    }
    let prefix: PathBuf = path_comps[..root_comps.len()].iter().copied().collect();
    let mut rest = Vec::new();
    for pc in &path_comps[root_comps.len()..] {
        if let Component::Normal(seg) = pc {
            rest.push((*seg).to_os_string());
        }
    }
    Some((prefix, rest))
}

fn is_filesystem_or_known_root(dir: &Path, roots: &[PathBuf]) -> bool {
    if dir == Path::new(".") || dir.parent().is_none() {
        return true;
    }
    roots
        .iter()
        .any(|root| matches!(split_under_root(dir, root), Some((_, rest)) if rest.is_empty()))
}

fn check_ancestors_under_roots(parent: &Path, roots: &[PathBuf]) -> Result<(), String> {
    let mut checked_any_root = false;
    for root in roots {
        if let Some((mut cur, rest)) = split_under_root(parent, root) {
            checked_any_root = true;
            if cur.parent().is_some() {
                platform_fs::reject_symlink_or_reparse(&cur)?;
            }
            for seg in rest {
                cur.push(seg);
                platform_fs::reject_symlink_or_reparse(&cur)?;
            }
        }
    }

    if !checked_any_root {
        let mut cur = PathBuf::new();
        for comp in parent.components() {
            match comp {
                Component::Prefix(p) => cur.push(p.as_os_str()),
                Component::RootDir => cur.push(comp.as_os_str()),
                Component::CurDir => continue,
                Component::ParentDir => {
                    return Err(format!(
                        "Refusing to access path containing parent directory traversal ('..'): {}",
                        parent.display()
                    ));
                }
                Component::Normal(seg) => {
                    cur.push(seg);
                    platform_fs::reject_symlink_or_reparse(&cur)?;
                }
            }
        }
    }

    Ok(())
}

/// Generates a 128-bit high-entropy token using `RandomState` combined with PID,
/// monotonic sequence number, timestamp, and thread ID.
fn unique_temp_token(pid: u32, seq: u64, ts_nanos: u128) -> String {
    let mut h1 = RandomState::new().build_hasher();
    pid.hash(&mut h1);
    seq.hash(&mut h1);
    ts_nanos.hash(&mut h1);
    thread::current().id().hash(&mut h1);
    let hi = h1.finish();

    let mut h2 = RandomState::new().build_hasher();
    hi.hash(&mut h2);
    seq.wrapping_add(0x9e37_79b9_7f4a_7c15).hash(&mut h2);
    let lo = h2.finish();

    format!("{pid}.{seq}.{hi:016x}{lo:016x}")
}

#[cfg(windows)]
fn rename_atomic(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut retries = 0;
    loop {
        match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(err)
                if retries < WINDOWS_RENAME_MAX_RETRIES
                    && platform_fs::is_retryable_rename_error(&err) =>
            {
                retries += 1;
                thread::sleep(WINDOWS_RENAME_RETRY_BACKOFF);
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(not(windows))]
fn rename_atomic(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

const fn expected_cli_binary_name() -> &'static str {
    if cfg!(windows) {
        "vdpi.exe"
    } else {
        "vdpi"
    }
}

/// Strictly validates that a filename refers to the real `vdpi` CLI binary
/// (`vdpi.exe` on Windows, `vdpi` on Unix) and NEVER `vdpi-desktop*`.
fn is_allowed_vdpi_cli_filename(name: &str, windows: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("vdpi-desktop") || lower.contains("vdpi-desktop") {
        return false;
    }
    if windows {
        lower == "vdpi.exe"
    } else {
        name == "vdpi"
    }
}

fn is_valid_vdpi_cli_candidate(path: &Path) -> bool {
    if path.as_os_str().is_empty() {
        return false;
    }
    let Some(raw) = path.to_str() else {
        return false;
    };
    if raw.contains('\0') {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    if !is_allowed_vdpi_cli_filename(file_name, cfg!(windows)) {
        return false;
    }

    // Walk every ancestor component (and the final file itself) to reject symlinks,
    // Windows NTFS junctions/reparse points, and `..` traversal components.
    if !verify_all_path_components_no_symlink_or_reparse(path) {
        return false;
    }

    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if is_symlink_or_reparse(&meta) || !meta.is_file() {
        return false;
    }

    if let Ok(canon) = fs::canonicalize(path) {
        let Some(canon_name) = canon.file_name().and_then(OsStr::to_str) else {
            return false;
        };
        if !is_allowed_vdpi_cli_filename(canon_name, cfg!(windows)) {
            return false;
        }
        if let Ok(current_exe) = std::env::current_exe().and_then(fs::canonicalize) {
            if canon == current_exe {
                return false;
            }
        }
    }

    true
}

#[cfg(any(unix, test))]
fn is_verified_unix_system_cli_metadata(
    file_uid: u32,
    file_mode: u32,
    parent_uid: u32,
    parent_mode: u32,
) -> bool {
    let file_ok = file_uid == 0 && (file_mode & 0o022) == 0 && (file_mode & 0o111) != 0;
    let parent_ok = parent_uid == 0 && (parent_mode & 0o022) == 0;
    file_ok && parent_ok
}

fn is_verified_system_cli_candidate(path: &Path) -> bool {
    if !is_valid_vdpi_cli_candidate(path) {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(meta) = fs::symlink_metadata(path) else {
            return false;
        };
        let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) else {
            return false;
        };
        let Ok(parent_meta) = fs::symlink_metadata(parent) else {
            return false;
        };
        // Both binary and parent directory must be owned by root (uid 0) and not
        // group- or world-writable; binary must also be executable.
        if !is_verified_unix_system_cli_metadata(
            meta.uid(),
            meta.mode(),
            parent_meta.uid(),
            parent_meta.mode(),
        ) {
            return false;
        }
    }

    true
}

fn push_unique_candidate(candidates: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
    }
}

#[cfg(any(target_os = "windows", test))]
fn is_local_drive_absolute(path: &Path) -> bool {
    let Some(raw) = path.to_str() else {
        return false;
    };
    let bytes = raw.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
}

#[cfg(any(target_os = "windows", test))]
fn has_windows_parent_traversal(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::ParentDir))
        || path
            .to_str()
            .is_some_and(|raw| raw.split(['\\', '/']).any(|seg| seg == ".."))
}

#[cfg(any(target_os = "windows", test))]
fn program_files_dir_from_system_drive(system_drive: &OsStr) -> Option<PathBuf> {
    let text = system_drive.to_str()?.trim();
    let bytes = text.as_bytes();
    let valid = (bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
        || (bytes.len() == 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'\\' | b'/'));
    if !valid {
        return None;
    }
    let drive = (bytes[0] as char).to_ascii_uppercase();
    Some(PathBuf::from(format!(r"{drive}:\Program Files")))
}

#[cfg(any(target_os = "windows", test))]
fn push_windows_program_files_cli_candidate(candidates: &mut Vec<PathBuf>, dir: PathBuf) {
    let pf = strip_windows_verbatim_prefix(&dir);
    if is_local_drive_absolute(&pf) && !has_windows_parent_traversal(&pf) {
        push_unique_candidate(candidates, pf.join("vdpi").join("bin").join("vdpi.exe"));
    }
}

#[cfg(target_os = "windows")]
fn query_windows_program_files_dir() -> Option<PathBuf> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramFiles, SHGetKnownFolderPath};

    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(pv: *const c_void);
    }

    struct CoTaskMemGuard(*mut u16);

    impl Drop for CoTaskMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `SHGetKnownFolderPath` via COM task allocator.
                unsafe {
                    CoTaskMemFree(self.0.cast());
                }
            }
        }
    }

    let mut raw_ptr: *mut u16 = std::ptr::null_mut();
    // SAFETY: `&FOLDERID_ProgramFiles` is a valid GUID pointer; `raw_ptr` is a valid out-pointer.
    let hr = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, 0, 0, &mut raw_ptr) };
    let _guard = CoTaskMemGuard(raw_ptr);
    if hr < 0 || raw_ptr.is_null() {
        return None;
    }

    let mut len = 0usize;
    // SAFETY: `SHGetKnownFolderPath` returns a NUL-terminated UTF-16 string on success.
    unsafe {
        while *raw_ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(raw_ptr, len);
        if slice.is_empty() {
            return None;
        }
        Some(PathBuf::from(OsString::from_wide(slice)))
    }
}

#[cfg(any(target_os = "windows", test))]
fn build_windows_system_cli_candidates_from(
    known_program_files: Option<PathBuf>,
    system_drive: Option<&OsStr>,
    program_files_env: Option<&OsStr>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // 1. OS Known Folder API (`SHGetKnownFolderPath(FOLDERID_ProgramFiles)`):
    //    HKLM-backed path immune to process environment variable tampering.
    if let Some(pf) = known_program_files.filter(|p| !p.as_os_str().is_empty()) {
        push_windows_program_files_cli_candidate(&mut candidates, pf);
    }

    // 2. `%SystemDrive%\Program Files\vdpi\bin\vdpi.exe` (strictly validated drive letter).
    if let Some(pf) = system_drive.and_then(program_files_dir_from_system_drive) {
        push_windows_program_files_cli_candidate(&mut candidates, pf);
    }

    // 3. Standard `C:\Program Files\vdpi\bin\vdpi.exe` ahead of mutable `%ProgramFiles%`.
    push_unique_candidate(
        &mut candidates,
        PathBuf::from(r"C:\Program Files")
            .join("vdpi")
            .join("bin")
            .join("vdpi.exe"),
    );

    // 4. Last-resort fallback to mutable `%ProgramFiles%` environment variable.
    if let Some(program_files) = program_files_env.filter(|v| !v.is_empty()) {
        push_windows_program_files_cli_candidate(&mut candidates, PathBuf::from(program_files));
    }

    candidates
}

fn build_system_cli_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        push_unique_candidate(
            &mut candidates,
            PathBuf::from(vdpi::service::UNIX_SYSTEM_BIN_PATH),
        );
    }

    #[cfg(target_os = "windows")]
    {
        for candidate in build_windows_system_cli_candidates_from(
            query_windows_program_files_dir(),
            std::env::var_os("SystemDrive").as_deref(),
            std::env::var_os("ProgramFiles").as_deref(),
        ) {
            push_unique_candidate(&mut candidates, candidate);
        }
    }

    candidates
}

#[cfg(any(target_os = "linux", test))]
fn current_exe_is_inside_appdir(current_exe: Option<&Path>, appdir: Option<&Path>) -> bool {
    let (Some(exe), Some(app_dir)) = (current_exe, appdir) else {
        return false;
    };
    if exe.as_os_str().is_empty()
        || app_dir.as_os_str().is_empty()
        || !exe.has_root()
        || !app_dir.has_root()
        || !app_dir.components().any(|c| matches!(c, Component::Normal(_)))
        || exe.components().any(|c| matches!(c, Component::ParentDir))
        || app_dir.components().any(|c| matches!(c, Component::ParentDir))
    {
        return false;
    }
    exe.starts_with(app_dir)
}

#[cfg(any(target_os = "linux", test))]
fn push_linux_packaged_candidates(
    candidates: &mut Vec<PathBuf>,
    current_exe: Option<&Path>,
    appdir: Option<&Path>,
    bin_name: &str,
) {
    let exe_dir = current_exe
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty());
    if let Some(prefix_dir) = exe_dir.and_then(Path::parent) {
        if !prefix_dir.as_os_str().is_empty() {
            // Tauri v2 Linux packages install resources under `/usr/lib/<productName>/`
            // (`vdpi Desktop`) and legacy/custom layouts under `/usr/lib/vdpi-desktop/`.
            push_unique_candidate(
                candidates,
                prefix_dir.join("lib").join("vdpi Desktop").join(bin_name),
            );
            push_unique_candidate(
                candidates,
                prefix_dir
                    .join("lib")
                    .join("vdpi Desktop")
                    .join("resources")
                    .join(bin_name),
            );
            push_unique_candidate(
                candidates,
                prefix_dir.join("lib").join("vdpi-desktop").join(bin_name),
            );
            push_unique_candidate(
                candidates,
                prefix_dir
                    .join("lib")
                    .join("vdpi-desktop")
                    .join("resources")
                    .join(bin_name),
            );
        }
    }

    // Only trust `$APPDIR` when `current_exe` actually resides inside `$APPDIR` so
    // an attacker cannot poison CLI resolution for a standard install via env vars.
    if current_exe_is_inside_appdir(current_exe, appdir) {
        if let Some(app_dir) = appdir.filter(|p| !p.as_os_str().is_empty()) {
            push_unique_candidate(
                candidates,
                app_dir
                    .join("usr")
                    .join("lib")
                    .join("vdpi Desktop")
                    .join(bin_name),
            );
            push_unique_candidate(
                candidates,
                app_dir
                    .join("usr")
                    .join("lib")
                    .join("vdpi Desktop")
                    .join("resources")
                    .join(bin_name),
            );
            push_unique_candidate(
                candidates,
                app_dir
                    .join("usr")
                    .join("lib")
                    .join("vdpi-desktop")
                    .join(bin_name),
            );
            push_unique_candidate(
                candidates,
                app_dir
                    .join("usr")
                    .join("lib")
                    .join("vdpi-desktop")
                    .join("resources")
                    .join(bin_name),
            );
        }
    }
}

fn build_cli_candidates_with(
    current_exe: Option<&Path>,
    resource_dir: Option<&Path>,
    appdir: Option<&Path>,
    installed_bin: Option<PathBuf>,
) -> Vec<PathBuf> {
    let bin_name = expected_cli_binary_name();
    let mut candidates = Vec::new();
    let exe_dir = current_exe
        .and_then(Path::parent)
        .filter(|p| !p.as_os_str().is_empty());

    if let Some(exe_dir) = exe_dir {
        // 1. Direct sibling next to `vdpi-desktop` executable.
        push_unique_candidate(&mut candidates, exe_dir.join(bin_name));
        // 2. Tauri `resources/` subdirectory (NSIS, portable, Linux, dev layouts).
        push_unique_candidate(&mut candidates, exe_dir.join("resources").join(bin_name));
    }

    // 3. Tauri runtime `resource_dir` registered via `set_resource_dir()` from `lib.rs::setup()`.
    if let Some(res_dir) = resource_dir.filter(|p| !p.as_os_str().is_empty()) {
        push_unique_candidate(&mut candidates, res_dir.join(bin_name));
        push_unique_candidate(&mut candidates, res_dir.join("resources").join(bin_name));
    }

    // 4. macOS `.app/Contents/MacOS/../Resources/` bundle layouts.
    #[cfg(target_os = "macos")]
    if let Some(contents_dir) = exe_dir.and_then(Path::parent) {
        push_unique_candidate(
            &mut candidates,
            contents_dir.join("Resources").join(bin_name),
        );
        push_unique_candidate(
            &mut candidates,
            contents_dir
                .join("Resources")
                .join("resources")
                .join(bin_name),
        );
    }

    // 5. Linux packaged resource directories (`/usr/lib/vdpi Desktop/`, `$APPDIR/usr/lib/vdpi Desktop/`
    //    when `current_exe` resides inside `$APPDIR`, `/usr/lib/vdpi-desktop/`).
    #[cfg(target_os = "linux")]
    push_linux_packaged_candidates(&mut candidates, current_exe, appdir, bin_name);
    #[cfg(not(target_os = "linux"))]
    let _ = appdir;

    // 6. Standard installed CLI binary path (`vdpi::service::installed_binary_path()`).
    if let Some(installed) = installed_bin {
        push_unique_candidate(&mut candidates, installed);
    }

    // 7. Standard Unix system-wide CLI binary path (`/usr/local/bin/vdpi`).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        push_unique_candidate(
            &mut candidates,
            PathBuf::from(vdpi::service::UNIX_SYSTEM_BIN_PATH),
        );
    }

    candidates
}

#[cfg(test)]
fn build_cli_candidates(
    current_exe: Option<&Path>,
    installed_bin: Option<PathBuf>,
) -> Vec<PathBuf> {
    build_cli_candidates_with(current_exe, None, None, installed_bin)
}

fn resolve_vdpi_cli_from_candidates(candidates: &[PathBuf]) -> Result<PathBuf, String> {
    for candidate in candidates {
        if is_valid_vdpi_cli_candidate(candidate) {
            return Ok(strip_windows_verbatim_prefix(candidate));
        }
    }
    Err(format!(
        "Could not locate the real `{}` CLI engine binary in the application directory, `resources/`, or the installed vdpi binary location.",
        expected_cli_binary_name()
    ))
}

fn resolve_vdpi_cli_for_elevation_with<FSystem>(
    prefer_system_binary: bool,
    system_candidates: &[PathBuf],
    bundled_candidates: &[PathBuf],
    mut is_verified_system: FSystem,
) -> Result<PathBuf, String>
where
    FSystem: FnMut(&Path) -> bool,
{
    if prefer_system_binary {
        for candidate in system_candidates {
            if is_verified_system(candidate) {
                return Ok(strip_windows_verbatim_prefix(candidate));
            }
        }
    }
    resolve_vdpi_cli_from_candidates(bundled_candidates)
}

/// Resolves the real `vdpi` CLI engine binary (`vdpi.exe` on Windows, `vdpi` on Unix).
///
/// Searches the sibling directory of `std::env::current_exe()`, the Tauri `resources/`
/// and registered `resource_dir` bundle directories, Linux/macOS packaged locations, and
/// `vdpi::service::installed_binary_path()` (plus the system Unix path on macOS/Linux).
/// Verifies every path component is free of symlinks/reparse points and NEVER falls back
/// to `vdpi-desktop`.
pub fn resolve_vdpi_cli_binary() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().ok();
    let resource_dir = RESOURCE_DIR.get().map(PathBuf::as_path);
    let appdir = std::env::var_os("APPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let installed = installed_binary_path().ok();
    let candidates = build_cli_candidates_with(
        current_exe.as_deref(),
        resource_dir,
        appdir.as_deref(),
        installed,
    );
    resolve_vdpi_cli_from_candidates(&candidates)
}

/// Resolves the real `vdpi` CLI engine binary for an elevated operation.
///
/// When `prefer_system_binary` is `true` (all non-`install` operations targeting an
/// already-installed system service), verified system-owned binary paths
/// (`/usr/local/bin/vdpi` on Unix, `%ProgramFiles%\vdpi\bin\vdpi.exe` on Windows) are
/// checked FIRST before falling back to bundled application paths. When `false`
/// (e.g. `install`), bundled application paths are preferred so the packaged CLI
/// installs or upgrades the system service. Every candidate undergoes a full ancestor
/// symlink/reparse-point walk.
pub fn resolve_vdpi_cli_binary_for_elevation(prefer_system_binary: bool) -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe().ok();
    let resource_dir = RESOURCE_DIR.get().map(PathBuf::as_path);
    let appdir = std::env::var_os("APPDIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let installed = installed_binary_path().ok();
    let system_candidates = build_system_cli_candidates();
    let bundled_candidates = build_cli_candidates_with(
        current_exe.as_deref(),
        resource_dir,
        appdir.as_deref(),
        installed,
    );
    resolve_vdpi_cli_for_elevation_with(
        prefer_system_binary,
        &system_candidates,
        &bundled_candidates,
        is_verified_system_cli_candidate,
    )
}

fn is_config_apply_file_args(args: &[&str]) -> bool {
    args.len() >= 2 && args[0] == "config" && args[1] == "apply-file"
}

fn should_prefer_system_binary_for_elevation(args: &[&str]) -> bool {
    !matches!(args.first().copied(), Some("install"))
}

#[cfg(any(target_os = "linux", test))]
fn scrub_linux_appimage_env(cmd: &mut Command) {
    for var in LINUX_SCRUBBED_ENV_VARS {
        cmd.env_remove(var);
    }
}

fn spawn_pipe_reader<R: Read + Send + 'static>(pipe: Option<R>) -> JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let Some(mut reader) = pipe else {
            return Vec::new();
        };
        let mut retained = Vec::new();
        let mut scratch = [0u8; 4096];
        loop {
            match reader.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    if retained.len() < MAX_CAPTURE_BYTES {
                        let keep = (MAX_CAPTURE_BYTES - retained.len()).min(n);
                        retained.extend_from_slice(&scratch[..keep]);
                    }
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        retained
    })
}

fn detach_child_reaper(
    mut child: Child,
    stdout_handle: JoinHandle<Vec<u8>>,
    stderr_handle: JoinHandle<Vec<u8>>,
) {
    let _ = thread::Builder::new()
        .name("vdpi-sidecar-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
        });
}

fn detach_pipe_reaper(stdout_handle: JoinHandle<Vec<u8>>, stderr_handle: JoinHandle<Vec<u8>>) {
    let _ = thread::Builder::new()
        .name("vdpi-sidecar-pipe-reaper".to_string())
        .spawn(move || {
            let _ = stdout_handle.join();
            let _ = stderr_handle.join();
        });
}

fn run_command_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<CapturedOutput, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }

    let mut child = cmd
        .spawn()
        .map_err(|err| redact_urls_in_text(&format!("Failed to launch vdpi CLI process: {err}")))?;

    let stdout_handle = spawn_pipe_reader(child.stdout.take());
    let stderr_handle = spawn_pipe_reader(child.stderr.take());

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    match child.kill() {
                        Ok(()) => {
                            let kill_deadline = Instant::now() + KILL_WAIT_GRACE;
                            let mut reaped = false;
                            loop {
                                match child.try_wait() {
                                    Ok(Some(_)) => {
                                        reaped = true;
                                        break;
                                    }
                                    Ok(None) if Instant::now() < kill_deadline => {
                                        thread::sleep(Duration::from_millis(10));
                                    }
                                    _ => break,
                                }
                            }
                            if reaped {
                                // Detach pipe joins so an orphaned grandchild keeping
                                // stdout/stderr open can never wedge the caller's lock.
                                detach_pipe_reaper(stdout_handle, stderr_handle);
                            } else {
                                detach_child_reaper(child, stdout_handle, stderr_handle);
                            }
                        }
                        Err(_) => {
                            // E.g. `PermissionDenied` when attempting to signal setuid `pkexec`
                            // on Linux. Hand `child` and pipe readers to a detached background
                            // reaper thread and return timeout immediately so `action_lock` is
                            // never wedged.
                            detach_child_reaper(child, stdout_handle, stderr_handle);
                        }
                    }
                    return Err(format!(
                        "vdpi command timed out after {}s.",
                        timeout.as_secs().max(1)
                    ));
                }
                let remaining = timeout.saturating_sub(elapsed);
                thread::sleep(CHILD_POLL_INTERVAL.min(remaining));
            }
            Err(err) => {
                let _ = child.kill();
                detach_child_reaper(child, stdout_handle, stderr_handle);
                return Err(redact_urls_in_text(&format!(
                    "Failed while waiting for vdpi process: {err}"
                )));
            }
        }
    };

    let stdout_bytes = stdout_handle.join().unwrap_or_default();
    let stderr_bytes = stderr_handle.join().unwrap_or_default();

    Ok(CapturedOutput {
        exit_code: status.code(),
        success: status.success(),
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
    })
}

fn format_non_zero_detail(label: &str, exit_code: Option<i32>, stdout: &str, stderr: &str) -> String {
    if !stderr.is_empty() {
        stderr.to_string()
    } else if !stdout.is_empty() {
        stdout.to_string()
    } else if let Some(code) = exit_code {
        format!("{label} exited with status code {code}.")
    } else {
        format!("{label} was terminated before completing.")
    }
}

fn classify_direct_outcome(
    output: &CapturedOutput,
    allow_saved_needs_restart: bool,
) -> SidecarOutcome {
    let stdout = redact_urls_in_text(output.stdout.trim());
    let stderr = redact_urls_in_text(output.stderr.trim());
    if output.success {
        SidecarOutcome::Ok(stdout)
    } else if allow_saved_needs_restart
        && output.exit_code == Some(APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE)
    {
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        SidecarOutcome::SavedNeedsRestart(detail)
    } else {
        SidecarOutcome::Err(format_non_zero_detail(
            "vdpi command",
            output.exit_code,
            &stdout,
            &stderr,
        ))
    }
}

fn build_resolved_vdpi_cli_command(bin: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(bin);
    #[cfg(target_os = "windows")]
    {
        // Never inherit a user-writable working directory (especially when already
        // running elevated) to prevent Windows DLL search-order hijacking.
        cmd.current_dir(win_elevate::windows_system32_dir());
    }
    #[cfg(target_os = "linux")]
    scrub_linux_appimage_env(&mut cmd);
    cmd.args(args);
    cmd
}

fn run_resolved_vdpi_cli(
    bin: &Path,
    args: &[&str],
    timeout_secs: u64,
    allow_saved_needs_restart: bool,
) -> SidecarOutcome {
    let mut cmd = build_resolved_vdpi_cli_command(bin, args);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    match run_command_with_timeout(&mut cmd, timeout) {
        Ok(output) => classify_direct_outcome(&output, allow_saved_needs_restart),
        Err(err) => SidecarOutcome::Err(redact_urls_in_text(&err)),
    }
}

/// Runs the resolved `vdpi` CLI binary directly without a console window on Windows,
/// scrubbing AppImage loader/GTK environment variables on Linux, enforcing a bounded
/// timeout, and redacting URLs from captured stdout/stderr.
pub fn run_vdpi_cli(args: &[&str], timeout_secs: u64) -> SidecarOutcome {
    if args.iter().any(|arg| arg.contains('\0')) {
        return SidecarOutcome::Err("vdpi arguments cannot contain NUL characters.".to_string());
    }

    let bin = match resolve_vdpi_cli_binary() {
        Ok(path) => path,
        Err(err) => return SidecarOutcome::Err(err),
    };

    let allow_saved_needs_restart = is_config_apply_file_args(args);
    run_resolved_vdpi_cli(&bin, args, timeout_secs, allow_saved_needs_restart)
}

#[cfg(any(target_os = "windows", test))]
fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .chars()
            .any(|c| matches!(c, ' ' | '\t' | '"' | '\n' | '\r' | '\x0b'))
    {
        return arg.to_string();
    }

    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            c => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

#[cfg(any(target_os = "windows", test))]
fn build_windows_parameters(args: &[&str]) -> Result<String, String> {
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err("Elevated vdpi arguments cannot contain NUL characters.".to_string());
    }
    Ok(args
        .iter()
        .map(|arg| quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" "))
}

#[cfg(any(target_os = "windows", test))]
fn bounded_timeout_ms(timeout_secs: u64) -> u32 {
    timeout_secs
        .max(1)
        .saturating_mul(1000)
        .min(MAX_NON_INFINITE_WAIT_MS) as u32
}

#[cfg(any(target_os = "windows", test))]
fn classify_windows_exit_code(exit_code: u32, allow_saved_needs_restart: bool) -> SidecarOutcome {
    match exit_code {
        0 => SidecarOutcome::Ok(String::new()),
        code if allow_saved_needs_restart
            && code == APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE as u32 =>
        {
            SidecarOutcome::SavedNeedsRestart(String::new())
        }
        WIN32_ERROR_CANCELLED => SidecarOutcome::Cancelled,
        code => SidecarOutcome::Err(format!(
            "Elevated vdpi command failed with exit code {code}."
        )),
    }
}

#[cfg(any(target_os = "windows", test))]
fn resolve_windows_system32_dir_from(
    api_system_dir: Option<PathBuf>,
    system_root: Option<&OsStr>,
    windir: Option<&OsStr>,
) -> PathBuf {
    if let Some(dir) = api_system_dir.filter(|p| !p.as_os_str().is_empty()) {
        return strip_windows_verbatim_prefix(&dir);
    }
    for candidate in [system_root, windir].into_iter().flatten() {
        if candidate.is_empty() {
            continue;
        }
        let path = strip_windows_verbatim_prefix(&PathBuf::from(candidate));
        if !path.components().any(|c| matches!(c, Component::ParentDir)) {
            return path.join("System32");
        }
    }
    PathBuf::from(r"C:\Windows\System32")
}

#[cfg(target_os = "windows")]
mod win_elevate {
    use std::ffi::{c_void, OsStr, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, BOOL, ERROR_CANCELLED, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use vdpi::update::strip_windows_verbatim_prefix;

    use super::{
        bounded_timeout_ms, build_windows_parameters, classify_windows_exit_code,
        resolve_windows_system32_dir_from, SidecarOutcome,
    };

    #[cfg_attr(target_arch = "x86", repr(C, packed(1)))]
    #[cfg_attr(not(target_arch = "x86"), repr(C))]
    struct ShellExecuteInfoW {
        cb_size: u32,
        f_mask: u32,
        hwnd: HANDLE,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: HANDLE,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: HANDLE,
        dw_hot_key: u32,
        h_icon_or_monitor: HANDLE,
        h_process: HANDLE,
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> BOOL;
    }

    struct ProcessHandleGuard(HANDLE);

    impl Drop for ProcessHandleGuard {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: `self.0` is an owned Win32 process handle returned by `ShellExecuteExW`.
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn encode_wide_nul(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn query_windows_system32_dir() -> Option<PathBuf> {
        let mut buf = vec![0u16; 260];
        // SAFETY: `buf` is a writable UTF-16 buffer of length `buf.len()`.
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if len == 0 {
            return None;
        }
        if len >= buf.len() {
            buf.resize(len + 1, 0);
            // SAFETY: resized `buf` is large enough for the returned path + NUL terminator.
            let len2 = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
            if len2 == 0 || len2 >= buf.len() {
                return None;
            }
            buf.truncate(len2);
        } else {
            buf.truncate(len);
        }
        Some(PathBuf::from(OsString::from_wide(&buf)))
    }

    pub(super) fn windows_system32_dir() -> PathBuf {
        resolve_windows_system32_dir_from(
            query_windows_system32_dir(),
            std::env::var_os("SystemRoot").as_deref(),
            std::env::var_os("WINDIR").as_deref(),
        )
    }

    pub(super) fn run_elevated(
        bin: &Path,
        args: &[&str],
        timeout_secs: u64,
        allow_saved_needs_restart: bool,
    ) -> SidecarOutcome {
        let params = match build_windows_parameters(args) {
            Ok(p) => p,
            Err(err) => return SidecarOutcome::Err(err),
        };

        let clean_bin = strip_windows_verbatim_prefix(bin);
        // Always set elevated working directory to `%SystemRoot%\System32` (never a
        // user-writable application or temp directory) to prevent DLL search-order hijacking.
        let work_dir = windows_system32_dir();

        let verb_wide = encode_wide_nul(OsStr::new("runas"));
        let file_wide = encode_wide_nul(clean_bin.as_os_str());
        let params_wide = encode_wide_nul(OsStr::new(&params));
        let dir_wide = encode_wide_nul(work_dir.as_os_str());

        let mut info = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            hwnd: 0,
            lp_verb: verb_wide.as_ptr(),
            lp_file: file_wide.as_ptr(),
            lp_parameters: if params.is_empty() {
                ptr::null()
            } else {
                params_wide.as_ptr()
            },
            lp_directory: dir_wide.as_ptr(),
            n_show: SW_HIDE,
            h_inst_app: 0,
            lp_id_list: ptr::null_mut(),
            lp_class: ptr::null(),
            hkey_class: 0,
            dw_hot_key: 0,
            h_icon_or_monitor: 0,
            h_process: 0,
        };

        // SAFETY: `info` and all NUL-terminated UTF-16 buffers outlive `ShellExecuteExW`.
        let ok = unsafe { ShellExecuteExW(&mut info) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_CANCELLED {
                return SidecarOutcome::Cancelled;
            }
            return SidecarOutcome::Err(format!(
                "Failed to launch elevated vdpi command (Win32 error {err})."
            ));
        }

        if info.h_process == 0 {
            return SidecarOutcome::Err(
                "Elevated vdpi launch did not return a process handle.".to_string(),
            );
        }

        let process = ProcessHandleGuard(info.h_process);
        let wait_ms = bounded_timeout_ms(timeout_secs);
        // SAFETY: `process.0` is a valid Win32 process handle; `wait_ms` is strictly bounded (< INFINITE).
        let wait_res = unsafe { WaitForSingleObject(process.0, wait_ms) };

        match wait_res {
            WAIT_OBJECT_0 => {
                let mut exit_code: u32 = 0;
                // SAFETY: `process.0` is valid and signaled; `exit_code` is a valid out-pointer.
                let got_exit = unsafe { GetExitCodeProcess(process.0, &mut exit_code) };
                if got_exit == 0 {
                    let err = unsafe { GetLastError() };
                    return SidecarOutcome::Err(format!(
                        "Failed to read elevated vdpi exit code (Win32 error {err})."
                    ));
                }
                classify_windows_exit_code(exit_code, allow_saved_needs_restart)
            }
            WAIT_TIMEOUT => {
                // Best-effort termination; may return ACCESS_DENIED from medium IL to elevated IL.
                unsafe {
                    let _ = TerminateProcess(process.0, 1);
                }
                SidecarOutcome::Err(format!(
                    "Elevated vdpi command timed out after {}s.",
                    timeout_secs.max(1)
                ))
            }
            other => {
                let err = unsafe { GetLastError() };
                SidecarOutcome::Err(format!(
                    "Waiting for elevated vdpi command failed (result {other}, Win32 error {err})."
                ))
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn shell_escape_posix_single_quote(arg: &str) -> Result<String, String> {
    if arg.contains('\0') {
        return Err("Shell arguments cannot contain NUL characters.".to_string());
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Ok(out)
}

#[cfg(any(target_os = "macos", test))]
fn build_posix_shell_command(bin: &Path, args: &[&str]) -> Result<String, String> {
    let bin_str = bin
        .to_str()
        .ok_or_else(|| "vdpi binary path is not valid UTF-8.".to_string())?;
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_escape_posix_single_quote(bin_str)?);
    for arg in args {
        parts.push(shell_escape_posix_single_quote(arg)?);
    }
    Ok(parts.join(" "))
}

#[cfg(any(target_os = "macos", test))]
fn escape_applescript_string(input: &str) -> Result<String, String> {
    if input.contains('\0') {
        return Err("AppleScript command cannot contain NUL characters.".to_string());
    }
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(any(target_os = "macos", test))]
fn build_osascript_elevation_script(bin: &Path, args: &[&str]) -> Result<String, String> {
    let shell_cmd = build_posix_shell_command(bin, args)?;
    let escaped = escape_applescript_string(&shell_cmd)?;
    Ok(format!(
        "do shell script \"{escaped}\" with prompt \"{MACOS_ELEVATION_PROMPT}\" with administrator privileges"
    ))
}

#[cfg(any(target_os = "macos", test))]
fn contains_standalone_token(haystack: &str, token: &str) -> bool {
    let bytes = haystack.as_bytes();
    let tok_len = token.len();
    let mut start = 0usize;
    while let Some(rel_idx) = haystack[start..].find(token) {
        let idx = start + rel_idx;
        let end = idx + tok_len;
        let left_ok = idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric();
        let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

#[cfg(any(target_os = "macos", test))]
fn osascript_stderr_has_exit_code(stderr: &str, code: i32) -> bool {
    let trimmed = stderr.trim_end();
    let suffix = format!("({code})");
    if !trimmed.ends_with(&suffix) {
        return false;
    }
    let prefix_len = trimmed.len() - suffix.len();
    prefix_len == 0 || trimmed.as_bytes()[prefix_len - 1].is_ascii_whitespace()
}

#[cfg(any(target_os = "macos", test))]
fn classify_osascript_outcome(
    output: &CapturedOutput,
    allow_saved_needs_restart: bool,
) -> SidecarOutcome {
    let stdout = redact_urls_in_text(output.stdout.trim());
    let stderr = redact_urls_in_text(output.stderr.trim());
    if output.success {
        return SidecarOutcome::Ok(stdout);
    }

    let lower_err = stderr.to_ascii_lowercase();
    if lower_err.contains("user canceled")
        || lower_err.contains("user cancelled")
        || contains_standalone_token(&stderr, "-128")
    {
        return SidecarOutcome::Cancelled;
    }

    if allow_saved_needs_restart
        && (output.exit_code == Some(APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE)
            || osascript_stderr_has_exit_code(&stderr, APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE))
    {
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return SidecarOutcome::SavedNeedsRestart(detail);
    }

    SidecarOutcome::Err(format_non_zero_detail(
        "Elevated vdpi command",
        output.exit_code,
        &stdout,
        &stderr,
    ))
}

#[cfg(any(target_os = "linux", test))]
fn is_appimage_fuse_path(path: &Path, appdir: Option<&Path>) -> bool {
    if let Some(app_dir) = appdir.filter(|p| !p.as_os_str().is_empty()) {
        if path.starts_with(app_dir) {
            return true;
        }
    }
    if let Some(raw) = path.to_str() {
        if raw.starts_with("/tmp/.mount_") {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "linux", all(unix, test)))]
struct StagedExecutableGuard {
    bin_path: Option<PathBuf>,
    exec_dir: Option<PathBuf>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl StagedExecutableGuard {
    fn path(&self) -> &Path {
        self.bin_path
            .as_deref()
            .expect("StagedExecutableGuard path accessed before initialization")
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl Drop for StagedExecutableGuard {
    fn drop(&mut self) {
        if let Some(ref bin) = self.bin_path {
            let _ = fs::remove_file(bin);
        }
        if let Some(ref dir) = self.exec_dir {
            let _ = fs::remove_dir(dir);
        }
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn stage_executable_copy_in(
    source_bin: &Path,
    base_dir: &Path,
    dir_prefix: &str,
) -> Result<StagedExecutableGuard, String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if !is_valid_vdpi_cli_candidate(source_bin) {
        return Err("Refusing to stage an invalid or symlinked vdpi binary.".to_string());
    }

    reject_parent_dir_traversal(base_dir)?;
    let roots = user_home_and_config_roots();
    check_ancestors_under_roots(base_dir, &roots)?;
    let is_root_base = is_filesystem_or_known_root(base_dir, &roots);
    let base_existed = if is_root_base {
        base_dir.is_dir()
    } else {
        platform_fs::verify_dir_not_symlink(base_dir)?
    };

    if !base_existed {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(base_dir).map_err(|err| {
            format!(
                "Failed to create runtime staging directory {}: {err}",
                base_dir.display()
            )
        })?;
        check_ancestors_under_roots(base_dir, &roots)?;
        if !is_root_base {
            if !platform_fs::verify_dir_not_symlink(base_dir)? {
                return Err(format!(
                    "Runtime staging directory disappeared after creation: {}",
                    base_dir.display()
                ));
            }
            fs::set_permissions(base_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
                format!(
                    "Failed to set 0700 permissions on runtime staging directory {}: {err}",
                    base_dir.display()
                )
            })?;
        }
    }

    let mut src_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source_bin)
        .map_err(|err| format!("Failed to open bundled vdpi binary for staging: {err}"))?;
    let src_meta = src_file
        .metadata()
        .map_err(|err| format!("Failed to inspect bundled vdpi binary metadata: {err}"))?;
    if src_meta.file_type().is_symlink() || !src_meta.is_file() || src_meta.len() == 0 {
        return Err("Bundled vdpi binary is not a valid non-empty regular file.".to_string());
    }
    let expected_len = src_meta.len();

    let pid = std::process::id();
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    for _ in 0..16 {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let token = unique_temp_token(pid, seq, ts_nanos);
        let exec_dir = base_dir.join(format!("{dir_prefix}{token}"));

        let mut dir_builder = fs::DirBuilder::new();
        dir_builder.mode(0o700);
        match dir_builder.create(&exec_dir) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "Failed to create exclusive staging directory {}: {err}",
                    exec_dir.display()
                ));
            }
        }

        let mut guard = StagedExecutableGuard {
            bin_path: None,
            exec_dir: Some(exec_dir.clone()),
        };

        if !platform_fs::verify_dir_not_symlink(&exec_dir)? {
            return Err(format!(
                "Exclusive staging directory disappeared after creation: {}",
                exec_dir.display()
            ));
        }
        fs::set_permissions(&exec_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!(
                "Failed to set 0700 permissions on staging directory {}: {err}",
                exec_dir.display()
            )
        })?;

        let staged_bin = exec_dir.join("vdpi");
        let mut dst_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staged_bin)
            .map_err(|err| {
                format!(
                    "Failed to create staged vdpi binary {}: {err}",
                    staged_bin.display()
                )
            })?;
        guard.bin_path = Some(staged_bin.clone());

        platform_fs::verify_opened_regular_file(&dst_file, &staged_bin)?;
        dst_file
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|err| {
                format!(
                    "Failed to set 0700 permissions on staged vdpi binary {}: {err}",
                    staged_bin.display()
                )
            })?;

        let copied = std::io::copy(&mut src_file, &mut dst_file).map_err(|err| {
            format!(
                "Failed to copy bundled vdpi binary to {}: {err}",
                staged_bin.display()
            )
        })?;
        if copied != expected_len {
            return Err(format!(
                "Staged vdpi binary size mismatch (expected {expected_len} bytes, copied {copied})."
            ));
        }
        dst_file.sync_all().map_err(|err| {
            format!(
                "Failed to flush staged vdpi binary {}: {err}",
                staged_bin.display()
            )
        })?;
        drop(dst_file);

        let staged_meta = fs::symlink_metadata(&staged_bin).map_err(|err| {
            format!(
                "Failed to verify staged vdpi binary {}: {err}",
                staged_bin.display()
            )
        })?;
        if staged_meta.file_type().is_symlink()
            || !staged_meta.is_file()
            || staged_meta.len() != expected_len
            || (staged_meta.permissions().mode() & 0o777) != 0o700
            || !is_valid_vdpi_cli_candidate(&staged_bin)
        {
            return Err("Staged vdpi binary failed integrity verification.".to_string());
        }

        return Ok(guard);
    }

    Err(format!(
        "Failed to allocate a unique staging directory in {}.",
        base_dir.display()
    ))
}

#[cfg(target_os = "linux")]
fn stage_appimage_binary_for_pkexec(
    source_bin: &Path,
    appdir: Option<&Path>,
) -> Result<StagedExecutableGuard, String> {
    if let Ok(root) = vdpi::service::vdpi_root_dir() {
        let runtime_dir = root.join("runtime");
        if !is_appimage_fuse_path(&runtime_dir, appdir) {
            if let Ok(guard) = stage_executable_copy_in(source_bin, &runtime_dir, "exec-") {
                return Ok(guard);
            }
        }
    }
    stage_executable_copy_in(source_bin, Path::new("/tmp"), "vdpi-exec-")
}

#[cfg(any(target_os = "linux", test))]
fn resolve_pkexec_from_candidates(candidates: &[PathBuf]) -> Result<PathBuf, String> {
    for candidate in candidates {
        if candidate.file_name().and_then(OsStr::to_str) != Some("pkexec") {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(candidate) else {
            continue;
        };
        if !meta.file_type().is_symlink() && meta.is_file() {
            return Ok(candidate.clone());
        }
    }
    Err("Polkit helper (`pkexec`) was not found at /usr/bin/pkexec or /bin/pkexec.".to_string())
}

#[cfg(any(target_os = "linux", test))]
fn classify_pkexec_outcome(
    output: &CapturedOutput,
    allow_saved_needs_restart: bool,
) -> SidecarOutcome {
    let stdout = redact_urls_in_text(output.stdout.trim());
    let stderr = redact_urls_in_text(output.stderr.trim());
    if output.success {
        return SidecarOutcome::Ok(stdout);
    }

    let lower_err = stderr.to_ascii_lowercase();
    if output.exit_code == Some(126)
        || (output.exit_code == Some(127)
            && (lower_err.contains("dismissed")
                || lower_err.contains("canceled")
                || lower_err.contains("cancelled")))
    {
        return SidecarOutcome::Cancelled;
    }

    if allow_saved_needs_restart
        && output.exit_code == Some(APPLY_FILE_SAVED_NEEDS_RESTART_EXIT_CODE)
    {
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return SidecarOutcome::SavedNeedsRestart(detail);
    }

    SidecarOutcome::Err(format_non_zero_detail(
        "Elevated vdpi command",
        output.exit_code,
        &stdout,
        &stderr,
    ))
}

/// Runs the resolved `vdpi` CLI binary with OS administrator/root privileges and a bounded timeout.
///
/// For non-`install` commands targeting an already-installed system service, verified system-owned
/// binaries (`/usr/local/bin/vdpi`, `%ProgramFiles%\vdpi\bin\vdpi.exe`) are resolved FIRST before
/// bundled paths.
///
/// - Windows: runs directly when already elevated; otherwise uses `ShellExecuteExW` (`runas`,
///   `SW_HIDE`, `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`, `lp_directory = %SystemRoot%\System32`)
///   and bounded `WaitForSingleObject`.
/// - macOS: runs directly when already root; otherwise prompts via `/usr/bin/osascript` with
///   a descriptive prompt and single-quoted POSIX shell escaping.
/// - Linux: runs directly when already root; otherwise elevates via `/usr/bin/pkexec` (or
///   `/bin/pkexec`), staging a verified `0o700` copy outside FUSE when running from an AppImage
///   and scrubbing AppImage loader/GTK environment variables.
pub fn run_vdpi_cli_elevated(args: &[&str], timeout_secs: u64) -> SidecarOutcome {
    if args.iter().any(|arg| arg.contains('\0')) {
        return SidecarOutcome::Err(
            "Elevated vdpi arguments cannot contain NUL characters.".to_string(),
        );
    }

    let allow_saved_needs_restart = is_config_apply_file_args(args);
    let prefer_system_binary = should_prefer_system_binary_for_elevation(args);

    #[cfg(target_os = "windows")]
    {
        let bin = match resolve_vdpi_cli_binary_for_elevation(prefer_system_binary) {
            Ok(path) => path,
            Err(err) => return SidecarOutcome::Err(err),
        };
        if vdpi::platform::windows_service::is_elevated() {
            return run_resolved_vdpi_cli(&bin, args, timeout_secs, allow_saved_needs_restart);
        }
        win_elevate::run_elevated(&bin, args, timeout_secs, allow_saved_needs_restart)
    }

    #[cfg(target_os = "macos")]
    {
        let bin = match resolve_vdpi_cli_binary_for_elevation(prefer_system_binary) {
            Ok(path) => path,
            Err(err) => return SidecarOutcome::Err(err),
        };
        if vdpi::service::is_unix_root() {
            return run_resolved_vdpi_cli(&bin, args, timeout_secs, allow_saved_needs_restart);
        }
        let script = match build_osascript_elevation_script(&bin, args) {
            Ok(s) => s,
            Err(err) => return SidecarOutcome::Err(err),
        };
        let mut cmd = Command::new("/usr/bin/osascript");
        cmd.arg("-e").arg(&script);
        let timeout = Duration::from_secs(timeout_secs.max(1));
        match run_command_with_timeout(&mut cmd, timeout) {
            Ok(output) => classify_osascript_outcome(&output, allow_saved_needs_restart),
            Err(err) => SidecarOutcome::Err(redact_urls_in_text(&err)),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let bin = match resolve_vdpi_cli_binary_for_elevation(prefer_system_binary) {
            Ok(path) => path,
            Err(err) => return SidecarOutcome::Err(err),
        };
        if vdpi::service::is_unix_root() {
            return run_resolved_vdpi_cli(&bin, args, timeout_secs, allow_saved_needs_restart);
        }

        let current_exe = std::env::current_exe().ok();
        let appdir = std::env::var_os("APPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|dir| {
                current_exe_is_inside_appdir(current_exe.as_deref(), Some(dir.as_path()))
            });
        let _staged_guard;
        let exec_bin = if !is_verified_system_cli_candidate(&bin)
            && is_appimage_fuse_path(&bin, appdir.as_deref())
        {
            let guard = match stage_appimage_binary_for_pkexec(&bin, appdir.as_deref()) {
                Ok(g) => g,
                Err(err) => return SidecarOutcome::Err(redact_urls_in_text(&err)),
            };
            let staged_path = guard.path().to_path_buf();
            _staged_guard = Some(guard);
            staged_path
        } else {
            _staged_guard = None;
            bin
        };

        let pkexec_candidates: Vec<PathBuf> =
            PKEXEC_CANDIDATES.iter().map(PathBuf::from).collect();
        let pkexec = match resolve_pkexec_from_candidates(&pkexec_candidates) {
            Ok(path) => path,
            Err(err) => return SidecarOutcome::Err(err),
        };
        let mut cmd = Command::new(&pkexec);
        scrub_linux_appimage_env(&mut cmd);
        cmd.arg(&exec_bin).args(args);
        let timeout = Duration::from_secs(timeout_secs.max(1));
        match run_command_with_timeout(&mut cmd, timeout) {
            Ok(output) => classify_pkexec_outcome(&output, allow_saved_needs_restart),
            Err(err) => SidecarOutcome::Err(redact_urls_in_text(&err)),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (allow_saved_needs_restart, prefer_system_binary);
        run_vdpi_cli(args, timeout_secs)
    }
}

struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("TempFileGuard path accessed after disarm")
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let _ = fs::remove_file(path);
        }
    }
}

fn resolve_user_config_dir_from(
    cfg_path: &Path,
    system_temp_dir: &Path,
) -> Result<PathBuf, String> {
    let Some(parent) = cfg_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Err(
            "Could not determine a private user configuration directory; refusing to fall back to a shared temp directory."
                .to_string(),
        );
    };
    if !parent.is_absolute() {
        return Err(
            "User configuration directory is not an absolute path; refusing to stage sensitive configuration."
                .to_string(),
        );
    }
    reject_parent_dir_traversal(parent)?;

    let clean_parent = strip_windows_verbatim_prefix(parent);
    let clean_temp = strip_windows_verbatim_prefix(system_temp_dir);
    if matches!(split_under_root(&clean_parent, &clean_temp), Some((_, rest)) if rest.is_empty()) {
        return Err(
            "Refusing to stage sensitive configuration in the shared system temp directory."
                .to_string(),
        );
    }

    #[cfg(unix)]
    if clean_parent == Path::new("/tmp")
        || clean_parent == Path::new("/var/tmp")
        || clean_parent == Path::new("/private/tmp")
    {
        return Err(
            "Refusing to stage sensitive configuration in a world-writable temp directory."
                .to_string(),
        );
    }

    Ok(clean_parent)
}

fn user_config_dir() -> Result<PathBuf, String> {
    let cfg_path = user_config_path();
    let temp_dir = std::env::temp_dir();
    resolve_user_config_dir_from(&cfg_path, &temp_dir)
}

fn is_stale_apply_temp_filename(name: &str) -> bool {
    name.starts_with(".vdpi-apply-") && (name.ends_with(".toml") || name.ends_with(".tmp"))
}

fn sweep_stale_temp_files_in(dir: &Path) -> usize {
    if reject_parent_dir_traversal(dir).is_err() {
        return 0;
    }
    let roots = user_home_and_config_roots();
    if check_ancestors_under_roots(dir, &roots).is_err() {
        return 0;
    }
    let is_root_dir = is_filesystem_or_known_root(dir, &roots);
    let exists = if is_root_dir {
        dir.is_dir()
    } else {
        matches!(platform_fs::verify_dir_not_symlink(dir), Ok(true))
    };
    if !exists {
        return 0;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if !is_stale_apply_temp_filename(name) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !is_symlink_or_reparse(&meta) && meta.is_file() && fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(any(target_os = "linux", all(unix, test)))]
fn sweep_stale_staged_exec_dirs_in(
    base_dir: &Path,
    dir_prefix: &str,
    required_uid: Option<u32>,
) -> usize {
    use std::os::unix::fs::MetadataExt;

    if reject_parent_dir_traversal(base_dir).is_err() {
        return 0;
    }
    let roots = user_home_and_config_roots();
    if check_ancestors_under_roots(base_dir, &roots).is_err() {
        return 0;
    }
    let is_root_dir = is_filesystem_or_known_root(base_dir, &roots);
    let exists = if is_root_dir {
        base_dir.is_dir()
    } else {
        matches!(platform_fs::verify_dir_not_symlink(base_dir), Ok(true))
    };
    if !exists {
        return 0;
    }
    let Ok(entries) = fs::read_dir(base_dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        if !name.starts_with(dir_prefix) {
            continue;
        }
        let dir_path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&dir_path) else {
            continue;
        };
        if is_symlink_or_reparse(&meta) || !meta.is_dir() {
            continue;
        }
        if let Some(expected_uid) = required_uid {
            if meta.uid() != expected_uid {
                continue;
            }
        }
        let staged_bin = dir_path.join("vdpi");
        if let Ok(bin_meta) = fs::symlink_metadata(&staged_bin) {
            let bin_owner_ok = match required_uid {
                Some(uid) => bin_meta.uid() == uid,
                None => true,
            };
            if !is_symlink_or_reparse(&bin_meta) && bin_meta.is_file() && bin_owner_ok {
                let _ = fs::remove_file(&staged_bin);
            }
        }
        if fs::remove_dir(&dir_path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(target_os = "linux")]
fn sweep_stale_linux_runtime_dirs() {
    // SAFETY: POSIX `geteuid(2)` is always safe to call and never fails.
    let current_uid: u32 = unsafe { libc::geteuid() };

    if let Ok(root) = vdpi::service::vdpi_root_dir() {
        let runtime_dir = root.join("runtime");
        let _ = sweep_stale_staged_exec_dirs_in(&runtime_dir, "exec-", Some(current_uid));
    }

    // Also sweep orphaned fallback staging dirs created under `/tmp/vdpi-exec-*`,
    // strictly restricted to directories owned by the current user.
    let _ = sweep_stale_staged_exec_dirs_in(Path::new("/tmp"), "vdpi-exec-", Some(current_uid));
}

/// Removes any orphaned `.vdpi-apply-*.toml` and `.vdpi-apply-*.tmp` temporary
/// config handoff files left behind in the user's configuration directory after
/// an unexpected crash or termination. Intended to be called on startup and exit.
pub fn sweep_stale_temp_files() {
    if let Ok(dir) = user_config_dir() {
        let _ = sweep_stale_temp_files_in(&dir);
    }
    #[cfg(target_os = "linux")]
    sweep_stale_linux_runtime_dirs();
}

fn write_atomic_owner_only_temp_file(dir: &Path, contents: &[u8]) -> Result<TempFileGuard, String> {
    reject_parent_dir_traversal(dir).map_err(|err| redact_urls_in_text(&err))?;

    let roots = user_home_and_config_roots();
    check_ancestors_under_roots(dir, &roots).map_err(|err| redact_urls_in_text(&err))?;

    let is_root_dir = is_filesystem_or_known_root(dir, &roots);
    let dir_existed = if is_root_dir {
        dir.is_dir()
    } else {
        platform_fs::verify_dir_not_symlink(dir).map_err(|err| redact_urls_in_text(&err))?
    };

    if !dir_existed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(dir).map_err(|err| {
                redact_urls_in_text(&format!(
                    "Failed to create configuration directory {}: {err}",
                    dir.display()
                ))
            })?;
            check_ancestors_under_roots(dir, &roots).map_err(|err| redact_urls_in_text(&err))?;
            if !is_root_dir {
                let exists_now = platform_fs::verify_dir_not_symlink(dir)
                    .map_err(|err| redact_urls_in_text(&err))?;
                if !exists_now {
                    return Err(redact_urls_in_text(&format!(
                        "Configuration directory disappeared after creation: {}",
                        dir.display()
                    )));
                }
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
                    redact_urls_in_text(&format!(
                        "Failed to set 0700 permissions on configuration directory {}: {err}",
                        dir.display()
                    ))
                })?;
            }
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(dir).map_err(|err| {
                redact_urls_in_text(&format!(
                    "Failed to create configuration directory {}: {err}",
                    dir.display()
                ))
            })?;
            check_ancestors_under_roots(dir, &roots).map_err(|err| redact_urls_in_text(&err))?;
            if !is_root_dir {
                let exists_now = platform_fs::verify_dir_not_symlink(dir)
                    .map_err(|err| redact_urls_in_text(&err))?;
                if !exists_now {
                    return Err(redact_urls_in_text(&format!(
                        "Configuration directory disappeared after creation: {}",
                        dir.display()
                    )));
                }
            }
        }
    }

    let pid = std::process::id();
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    for _ in 0..16 {
        let seq = TEMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let token = unique_temp_token(pid, seq, ts_nanos);
        let stage_path = dir.join(format!(".vdpi-apply-stage-{token}.tmp"));
        let final_path = dir.join(format!(".vdpi-apply-{token}.toml"));

        if platform_fs::path_exists_no_follow(&final_path)
            .map_err(|err| redact_urls_in_text(&err))?
        {
            continue;
        }

        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create_new(true);
        platform_fs::configure_temp_open_options(&mut open_opts);

        let mut file = match open_opts.open(&stage_path) {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(redact_urls_in_text(&format!(
                    "Failed to create temporary config file {}: {err}",
                    stage_path.display()
                )));
            }
        };

        let mut stage_guard = TempFileGuard::new(stage_path.clone());

        platform_fs::verify_opened_regular_file(&file, &stage_path)
            .map_err(|err| redact_urls_in_text(&err))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|err| {
                    redact_urls_in_text(&format!(
                        "Failed to set 0600 permissions on temporary config file {}: {err}",
                        stage_path.display()
                    ))
                })?;
        }

        file.write_all(contents).map_err(|err| {
            redact_urls_in_text(&format!(
                "Failed to write temporary config file {}: {err}",
                stage_path.display()
            ))
        })?;
        file.sync_all().map_err(|err| {
            redact_urls_in_text(&format!(
                "Failed to flush temporary config file {}: {err}",
                stage_path.display()
            ))
        })?;
        drop(file);

        // Re-verify ancestors, parent dir, and target path immediately before atomic rename.
        check_ancestors_under_roots(dir, &roots).map_err(|err| redact_urls_in_text(&err))?;
        if !is_root_dir {
            platform_fs::reject_symlink_or_reparse(dir)
                .map_err(|err| redact_urls_in_text(&err))?;
        }
        platform_fs::reject_target_symlink_or_dir(&final_path)
            .map_err(|err| redact_urls_in_text(&err))?;
        if platform_fs::path_exists_no_follow(&final_path)
            .map_err(|err| redact_urls_in_text(&err))?
        {
            continue;
        }

        rename_atomic(&stage_path, &final_path).map_err(|err| {
            redact_urls_in_text(&format!(
                "Failed to finalize temporary config file {}: {err}",
                final_path.display()
            ))
        })?;
        stage_guard.disarm();

        return Ok(TempFileGuard::new(final_path));
    }

    Err(format!(
        "Failed to allocate a unique temporary configuration file in {}.",
        dir.display()
    ))
}

fn apply_config_via_temp_file_in<F>(
    dir: &Path,
    cfg: &FileConfig,
    restart_service: bool,
    runner: F,
) -> SidecarOutcome
where
    F: FnOnce(&[&str], u64) -> SidecarOutcome,
{
    let rendered = render_config_toml(cfg);
    let temp_guard = match write_atomic_owner_only_temp_file(dir, rendered.as_bytes()) {
        Ok(guard) => guard,
        Err(err) => return SidecarOutcome::Err(err),
    };

    let clean_path = strip_windows_verbatim_prefix(temp_guard.path());
    let Some(path_str) = clean_path.to_str() else {
        return SidecarOutcome::Err(
            "Temporary configuration file path is not valid UTF-8.".to_string(),
        );
    };

    let mut args = Vec::with_capacity(4);
    args.push("config");
    args.push("apply-file");
    args.push(path_str);
    if restart_service {
        args.push("--restart");
    }

    let outcome = runner(&args, APPLY_CONFIG_TIMEOUT_SECS);
    drop(temp_guard);
    outcome
}

/// Renders `cfg` atomically to a unique owner-only (`0o600` on Unix) temporary file inside
/// the user's private `vdpi` config directory (never falling back to shared temp dirs and
/// never passing secret DoH URLs on argv), invokes `vdpi config apply-file <temp_path> [--restart]`
/// (elevated when `elevate` is true), and unconditionally removes the temporary file before returning.
pub fn apply_config_via_temp_file(
    cfg: &FileConfig,
    elevate: bool,
    restart_service: bool,
) -> SidecarOutcome {
    let dir = match user_config_dir() {
        Ok(dir) => dir,
        Err(err) => return SidecarOutcome::Err(redact_urls_in_text(&err)),
    };
    apply_config_via_temp_file_in(&dir, cfg, restart_service, |args, timeout_secs| {
        if elevate {
            run_vdpi_cli_elevated(args, timeout_secs)
        } else {
            run_vdpi_cli(args, timeout_secs)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use vdpi_core::config::{EngineMode, SplitTunnelMode};

    static TEST_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let pid = std::process::id();
            let ts_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let seq = TEST_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            #[cfg(unix)]
            let base =
                fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
            #[cfg(not(unix))]
            let base = strip_windows_verbatim_prefix(&std::env::temp_dir());

            let path = base.join(format!("vdpi-sidecar-test-{label}-{pid}-{ts_nanos}-{seq}"));
            fs::create_dir_all(&path).expect("create test temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(windows)]
    fn windows_cmd_exe() -> PathBuf {
        std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .filter(|v| !v.is_empty())
            .map(|root| PathBuf::from(root).join("System32").join("cmd.exe"))
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"))
    }

    #[test]
    fn binary_filename_filter_rejects_vdpi_desktop_and_non_cli_names() {
        // Windows rules
        assert!(is_allowed_vdpi_cli_filename("vdpi.exe", true));
        assert!(is_allowed_vdpi_cli_filename("VDPI.EXE", true));
        assert!(is_allowed_vdpi_cli_filename("Vdpi.Exe", true));
        for rejected in [
            "vdpi-desktop.exe",
            "VDPI-DESKTOP.EXE",
            "vdpi-desktop",
            "my-vdpi-desktop.exe",
            "vdpi",
            "vdpi.cmd",
            "vdpi.bat",
            "vdpi.exe.bak",
            "other.exe",
            "",
        ] {
            assert!(
                !is_allowed_vdpi_cli_filename(rejected, true),
                "Windows filter must reject {rejected:?}"
            );
        }

        // Unix rules
        assert!(is_allowed_vdpi_cli_filename("vdpi", false));
        for rejected in [
            "vdpi-desktop",
            "vdpi-desktop-bin",
            "VDPI",
            "vdpi.exe",
            "vdpi.sh",
            "vdpi-cli",
            "",
        ] {
            assert!(
                !is_allowed_vdpi_cli_filename(rejected, false),
                "Unix filter must reject {rejected:?}"
            );
        }
    }

    #[test]
    fn resolve_vdpi_cli_rejects_vdpi_desktop_directories_and_symlinks_including_ancestors() {
        let dir = TestDir::new("resolve");
        let bin_name = expected_cli_binary_name();
        let desktop_name = if cfg!(windows) {
            "vdpi-desktop.exe"
        } else {
            "vdpi-desktop"
        };

        let desktop_file = dir.path().join(desktop_name);
        fs::write(&desktop_file, b"gui binary").expect("write fake desktop exe");

        // Directory masquerading as vdpi binary must be rejected.
        let dir_as_bin = dir.path().join("dir-holder").join(bin_name);
        fs::create_dir_all(&dir_as_bin).expect("create fake bin dir");

        // Never falls back to vdpi-desktop or a directory.
        let err = resolve_vdpi_cli_from_candidates(&[
            desktop_file.clone(),
            dir_as_bin.clone(),
            dir.path().join("missing").join(bin_name),
        ])
        .expect_err("must reject vdpi-desktop and directory");
        assert!(err.contains(bin_name));

        // Real CLI binary in resources/ subdir is accepted when sibling is missing.
        let resources_bin = dir.path().join("resources").join(bin_name);
        fs::create_dir_all(resources_bin.parent().unwrap()).expect("create resources dir");
        fs::write(&resources_bin, b"real cli").expect("write real cli");

        let resolved = resolve_vdpi_cli_from_candidates(&[
            desktop_file.clone(),
            dir_as_bin,
            resources_bin.clone(),
        ])
        .expect("should resolve resources/ vdpi binary");
        assert_eq!(resolved, strip_windows_verbatim_prefix(&resources_bin));

        // Parent traversal component must be rejected even if it points to the real binary.
        let traversal = dir
            .path()
            .join("resources")
            .join("..")
            .join("resources")
            .join(bin_name);
        assert!(
            !is_valid_vdpi_cli_candidate(&traversal),
            "parent traversal candidate must be rejected"
        );

        // Symlink file AND symlink ancestor directory must both be rejected on Unix.
        #[cfg(unix)]
        {
            let symlink_dir = dir.path().join("sym");
            fs::create_dir_all(&symlink_dir).expect("create sym dir");
            let symlink_bin = symlink_dir.join(bin_name);
            std::os::unix::fs::symlink(&resources_bin, &symlink_bin).expect("create symlink");
            assert!(
                !is_valid_vdpi_cli_candidate(&symlink_bin),
                "symlink candidate must be rejected"
            );

            let ancestor_link = dir.path().join("ancestor-link");
            std::os::unix::fs::symlink(resources_bin.parent().unwrap(), &ancestor_link)
                .expect("create ancestor symlink");
            let through_ancestor = ancestor_link.join(bin_name);
            assert!(
                !is_valid_vdpi_cli_candidate(&through_ancestor),
                "candidate reached via symlink ancestor must be rejected"
            );

            let resolved_after_sym = resolve_vdpi_cli_from_candidates(&[
                symlink_bin,
                through_ancestor,
                resources_bin.clone(),
            ])
            .expect("must skip symlinks and resolve real binary");
            assert_eq!(resolved_after_sym, resources_bin);
        }

        // NTFS junction ancestor AND file symlink (when permitted) must be rejected on Windows.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let junction_dir = dir.path().join("junction-resources");
            let status = Command::new(windows_cmd_exe())
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .args([
                    OsStr::new("/C"),
                    OsStr::new("mklink"),
                    OsStr::new("/J"),
                    junction_dir.as_os_str(),
                    resources_bin.parent().unwrap().as_os_str(),
                ])
                .status()
                .expect("spawn mklink /J");
            assert!(status.success(), "mklink /J must create junction");

            let through_junction = junction_dir.join(bin_name);
            assert!(
                !is_valid_vdpi_cli_candidate(&through_junction),
                "candidate reached via NTFS junction ancestor must be rejected"
            );
            let _ = fs::remove_dir(&junction_dir);

            let symlink_dir = dir.path().join("sym");
            fs::create_dir_all(&symlink_dir).expect("create sym dir");
            let symlink_bin = symlink_dir.join(bin_name);
            if std::os::windows::fs::symlink_file(&resources_bin, &symlink_bin).is_ok() {
                assert!(
                    !is_valid_vdpi_cli_candidate(&symlink_bin),
                    "Windows symlink candidate must be rejected"
                );
            }
        }
    }

    #[test]
    fn build_cli_candidates_checks_sibling_resources_resource_dir_and_linux_layouts() {
        let dir = TestDir::new("candidates");
        let fake_exe = dir.path().join(if cfg!(windows) {
            "vdpi-desktop.exe"
        } else {
            "vdpi-desktop"
        });
        let installed = dir.path().join("installed").join(expected_cli_binary_name());
        let res_dir = dir.path().join("tauri-resources");

        let candidates = build_cli_candidates(Some(&fake_exe), Some(installed.clone()));
        assert_eq!(candidates[0], dir.path().join(expected_cli_binary_name()));
        assert_eq!(
            candidates[1],
            dir.path().join("resources").join(expected_cli_binary_name())
        );
        assert!(candidates.contains(&installed));
        assert!(
            candidates.iter().all(|c| {
                c.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|n| is_allowed_vdpi_cli_filename(n, cfg!(windows)))
            }),
            "candidate list must never include vdpi-desktop"
        );

        let with_res = build_cli_candidates_with(
            Some(&fake_exe),
            Some(&res_dir),
            None,
            Some(installed.clone()),
        );
        assert!(with_res.contains(&res_dir.join(expected_cli_binary_name())));

        // Verify all required Linux packaged candidate layouts (LIN-01) and that `$APPDIR`
        // is ignored unless `current_exe` actually resides inside `$APPDIR`.
        let mut system_install_candidates = Vec::new();
        let system_exe = Path::new("/usr/bin/vdpi-desktop");
        let forged_appdir = Path::new("/tmp/.mount_vdpiXYZ");
        push_linux_packaged_candidates(
            &mut system_install_candidates,
            Some(system_exe),
            Some(forged_appdir),
            "vdpi",
        );
        assert!(system_install_candidates.contains(&PathBuf::from("/usr/lib/vdpi Desktop/vdpi")));
        assert!(system_install_candidates.contains(&PathBuf::from("/usr/lib/vdpi-desktop/vdpi")));
        assert!(system_install_candidates.contains(&PathBuf::from(
            "/usr/lib/vdpi-desktop/resources/vdpi"
        )));
        assert!(
            !system_install_candidates.contains(&PathBuf::from(
                "/tmp/.mount_vdpiXYZ/usr/lib/vdpi Desktop/vdpi"
            )),
            "forged $APPDIR must be ignored when current_exe is outside $APPDIR"
        );

        let mut appimage_candidates = Vec::new();
        let appimage_exe = Path::new("/tmp/.mount_vdpiXYZ/AppRun");
        push_linux_packaged_candidates(
            &mut appimage_candidates,
            Some(appimage_exe),
            Some(forged_appdir),
            "vdpi",
        );
        assert!(appimage_candidates.contains(&PathBuf::from(
            "/tmp/.mount_vdpiXYZ/usr/lib/vdpi Desktop/vdpi"
        )));
        assert!(appimage_candidates.contains(&PathBuf::from(
            "/tmp/.mount_vdpiXYZ/usr/lib/vdpi-desktop/resources/vdpi"
        )));

        assert!(current_exe_is_inside_appdir(
            Some(Path::new("/tmp/.mount_vdpiXYZ/usr/bin/vdpi-desktop")),
            Some(Path::new("/tmp/.mount_vdpiXYZ")),
        ));
        assert!(!current_exe_is_inside_appdir(
            Some(Path::new("/tmp/.mount_vdpiXYZ_evil/usr/bin/vdpi-desktop")),
            Some(Path::new("/tmp/.mount_vdpiXYZ")),
        ));
        assert!(!current_exe_is_inside_appdir(
            Some(Path::new("/usr/bin/vdpi-desktop")),
            Some(Path::new("/")),
        ));
        assert!(!current_exe_is_inside_appdir(
            Some(Path::new("/tmp/.mount_vdpiXYZ/usr/bin/vdpi-desktop")),
            Some(Path::new("relative/appdir")),
        ));
        assert!(!current_exe_is_inside_appdir(
            Some(Path::new("/tmp/.mount_vdpiXYZ/usr/bin/vdpi-desktop")),
            Some(Path::new("/tmp/../tmp/.mount_vdpiXYZ")),
        ));
        assert!(!current_exe_is_inside_appdir(
            None,
            Some(Path::new("/tmp/.mount_vdpiXYZ")),
        ));
    }

    #[test]
    fn windows_system_cli_candidates_prefer_known_folder_and_system_drive_over_program_files_env() {
        let spoofed = OsStr::new(r"C:\Users\attacker\fake-pf");

        // SHGetKnownFolderPath + SystemDrive + C:\Program Files all precede mutable %ProgramFiles%.
        let candidates = build_windows_system_cli_candidates_from(
            Some(PathBuf::from(r"D:\Program Files")),
            Some(OsStr::new("E:")),
            Some(spoofed),
        );
        assert_eq!(
            candidates,
            vec![
                PathBuf::from(r"D:\Program Files")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
                PathBuf::from(r"E:\Program Files")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
                PathBuf::from(r"C:\Program Files")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
                PathBuf::from(r"C:\Users\attacker\fake-pf")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
            ]
        );

        // Deduplicates when Known Folder, SystemDrive, and C:\Program Files agree,
        // and still ranks C:\Program Files ahead of mutable %ProgramFiles%.
        let deduped = build_windows_system_cli_candidates_from(
            Some(PathBuf::from(r"C:\Program Files")),
            Some(OsStr::new(r"c:\")),
            Some(spoofed),
        );
        assert_eq!(
            deduped,
            vec![
                PathBuf::from(r"C:\Program Files")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
                PathBuf::from(r"C:\Users\attacker\fake-pf")
                    .join("vdpi")
                    .join("bin")
                    .join("vdpi.exe"),
            ]
        );

        // Invalid SystemDrive and traversal/UNC ProgramFiles values are rejected.
        let sanitized = build_windows_system_cli_candidates_from(
            None,
            Some(OsStr::new(r"C:\Users\attacker")),
            Some(OsStr::new(r"C:\Program Files\..\Evil")),
        );
        assert_eq!(
            sanitized,
            vec![PathBuf::from(r"C:\Program Files")
                .join("vdpi")
                .join("bin")
                .join("vdpi.exe")]
        );
        assert_eq!(program_files_dir_from_system_drive(OsStr::new("")), None);
        assert_eq!(program_files_dir_from_system_drive(OsStr::new("1:")), None);
        assert_eq!(
            program_files_dir_from_system_drive(OsStr::new(r"\\attacker\share")),
            None
        );
    }

    #[test]
    fn unix_system_cli_metadata_requires_root_owned_non_writable_file_and_parent() {
        assert!(is_verified_unix_system_cli_metadata(
            0, 0o100755, 0, 0o040755
        ));
        assert!(is_verified_unix_system_cli_metadata(
            0, 0o100500, 0, 0o040555
        ));
        // Non-root or group/world-writable parent directory must be rejected.
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100755, 501, 0o040755
        ));
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100755, 0, 0o040775
        ));
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100755, 0, 0o040777
        ));
        // Non-root, writable, or non-executable binary must be rejected.
        assert!(!is_verified_unix_system_cli_metadata(
            1000, 0o100755, 0, 0o040755
        ));
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100775, 0, 0o040755
        ));
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100757, 0, 0o040755
        ));
        assert!(!is_verified_unix_system_cli_metadata(
            0, 0o100644, 0, 0o040755
        ));
    }

    #[test]
    fn allowed_os_system_symlink_paths_support_linux_ostree_and_macos_root_only() {
        for path in ["/home", "/usr/local", "/var", "/tmp", "/etc"] {
            assert!(
                is_allowed_os_system_symlink_path(Path::new(path), 0, true),
                "Linux must allow root-owned OS/ostree link {path}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(path), 1000, true),
                "Linux must reject non-root link {path}"
            );
        }

        for path in ["/var", "/tmp", "/etc"] {
            assert!(
                is_allowed_os_system_symlink_path(Path::new(path), 0, false),
                "macOS must allow root-owned OS link {path}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(path), 501, false),
                "macOS must reject non-root link {path}"
            );
        }
        assert!(!is_allowed_os_system_symlink_path(
            Path::new("/home"),
            0,
            false
        ));
        assert!(!is_allowed_os_system_symlink_path(
            Path::new("/usr/local"),
            0,
            false
        ));

        for rejected in [
            "/opt",
            "/usr/local/bin",
            "/home/alice",
            "/var/log",
            "/tmp/vdpi",
            "/etc/vdpi",
        ] {
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(rejected), 0, true),
                "Linux must reject non-allowlisted link {rejected}"
            );
            assert!(
                !is_allowed_os_system_symlink_path(Path::new(rejected), 0, false),
                "macOS must reject non-allowlisted link {rejected}"
            );
        }
    }

    #[test]
    fn elevation_binary_ordering_prefers_verified_system_for_non_install_ops() {
        let dir = TestDir::new("elev-order");
        let bin_name = expected_cli_binary_name();

        let sys_bin = dir.path().join("system").join(bin_name);
        let bundled_bin = dir.path().join("bundled").join(bin_name);
        fs::create_dir_all(sys_bin.parent().unwrap()).expect("create sys dir");
        fs::create_dir_all(bundled_bin.parent().unwrap()).expect("create bundled dir");
        fs::write(&sys_bin, b"system cli").expect("write sys cli");
        fs::write(&bundled_bin, b"bundled cli").expect("write bundled cli");

        // Non-install ops prefer verified system binary FIRST.
        assert!(!should_prefer_system_binary_for_elevation(&[
            "install", "--tun"
        ]));
        assert!(should_prefer_system_binary_for_elevation(&["resume"]));
        assert!(should_prefer_system_binary_for_elevation(&["pause"]));
        assert!(should_prefer_system_binary_for_elevation(&["uninstall"]));
        assert!(should_prefer_system_binary_for_elevation(&[
            "engine", "tun"
        ]));
        assert!(should_prefer_system_binary_for_elevation(&[
            "config",
            "apply-file",
            "/tmp/x"
        ]));

        let chosen_sys = resolve_vdpi_cli_for_elevation_with(
            true,
            std::slice::from_ref(&sys_bin),
            std::slice::from_ref(&bundled_bin),
            is_valid_vdpi_cli_candidate,
        )
        .expect("should pick verified system binary");
        assert_eq!(chosen_sys, strip_windows_verbatim_prefix(&sys_bin));

        // If system binary fails verification, fall back to bundled binary.
        let fallback_bundled = resolve_vdpi_cli_for_elevation_with(
            true,
            std::slice::from_ref(&sys_bin),
            std::slice::from_ref(&bundled_bin),
            |_| false,
        )
        .expect("should fall back to bundled binary when system binary is unverified");
        assert_eq!(fallback_bundled, strip_windows_verbatim_prefix(&bundled_bin));

        // Install ops (`prefer_system_binary = false`) pick bundled binary FIRST.
        let chosen_bundled = resolve_vdpi_cli_for_elevation_with(
            false,
            std::slice::from_ref(&sys_bin),
            std::slice::from_ref(&bundled_bin),
            is_valid_vdpi_cli_candidate,
        )
        .expect("install op should pick bundled binary");
        assert_eq!(chosen_bundled, strip_windows_verbatim_prefix(&bundled_bin));
    }

    #[test]
    fn windows_arg_quoting_parameter_building_and_system32_dir() {
        assert_eq!(quote_windows_arg("config"), "config");
        assert_eq!(quote_windows_arg("--restart"), "--restart");
        assert_eq!(quote_windows_arg(""), "\"\"");
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\vdpi\config.toml"),
            r#""C:\Program Files\vdpi\config.toml""#
        );
        assert_eq!(
            quote_windows_arg(r"C:\dir with space\"),
            r#""C:\dir with space\\""#
        );
        assert_eq!(quote_windows_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);

        let params = build_windows_parameters(&[
            "config",
            "apply-file",
            r"C:\Users\My User\AppData\Local\vdpi\.vdpi-apply.toml",
            "--restart",
        ])
        .expect("build params");
        assert_eq!(
            params,
            r#"config apply-file "C:\Users\My User\AppData\Local\vdpi\.vdpi-apply.toml" --restart"#
        );

        let nul_err = build_windows_parameters(&["ok", "bad\0arg"])
            .expect_err("NUL byte in Windows args must be rejected");
        assert!(nul_err.contains("NUL"));

        // Elevated ShellExecuteExW lp_directory always resolves to System32, never user-writable dirs.
        assert_eq!(
            resolve_windows_system32_dir_from(
                Some(PathBuf::from(r"C:\Windows\System32")),
                Some(OsStr::new(r"D:\Win")),
                None
            ),
            PathBuf::from(r"C:\Windows\System32")
        );
        assert_eq!(
            resolve_windows_system32_dir_from(None, Some(OsStr::new(r"D:\Windows")), None),
            PathBuf::from(r"D:\Windows").join("System32")
        );
        assert_eq!(
            resolve_windows_system32_dir_from(None, None, Some(OsStr::new(r"E:\WINNT"))),
            PathBuf::from(r"E:\WINNT").join("System32")
        );
        assert_eq!(
            resolve_windows_system32_dir_from(None, None, None),
            PathBuf::from(r"C:\Windows\System32")
        );

        #[cfg(target_os = "windows")]
        {
            let cmd = build_resolved_vdpi_cli_command(
                Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"),
                &["resume"],
            );
            assert_eq!(
                cmd.get_current_dir(),
                Some(win_elevate::windows_system32_dir().as_path()),
                "direct/already-elevated Windows CLI invocation must pin CWD to System32"
            );
        }
    }

    #[test]
    fn posix_shell_and_applescript_escaping_and_prompt() {
        assert_eq!(
            shell_escape_posix_single_quote("simple").unwrap(),
            "'simple'"
        );
        assert_eq!(shell_escape_posix_single_quote("").unwrap(), "''");
        assert_eq!(
            shell_escape_posix_single_quote("it's").unwrap(),
            "'it'\\''s'"
        );
        assert_eq!(
            shell_escape_posix_single_quote("$(rm -rf /)").unwrap(),
            "'$(rm -rf /)'"
        );
        assert_eq!(
            shell_escape_posix_single_quote("`id`; uname -a").unwrap(),
            "'`id`; uname -a'"
        );
        assert!(shell_escape_posix_single_quote("bad\0arg").is_err());

        let script = build_osascript_elevation_script(
            Path::new("/Applications/vdpi Desktop.app/Contents/Resources/vdpi"),
            &[
                "config",
                "apply-file",
                "/Users/o'connor/dir \"1\"/$HOME/tmp.toml",
                "--restart",
            ],
        )
        .expect("build osascript");
        assert!(script.starts_with("do shell script \""));
        assert!(
            script.contains(
                "with prompt \"vdpi Desktop needs administrator privileges to manage the background service.\""
            ),
            "osascript must include descriptive macOS elevation prompt: {script}"
        );
        assert!(script.ends_with(" with administrator privileges"));
        // Single quote inside path is escaped as '\'' in POSIX, then backslash doubled for AppleScript.
        assert!(script.contains("o'\\\\''connor"));
        // Double quotes are escaped for AppleScript string literal.
        assert!(script.contains("\\\"1\\\""));
        // Dollar expansion remains inside single quotes so sh cannot expand it.
        assert!(script.contains("$HOME"));

        assert_eq!(
            escape_applescript_string("a\\b\"c\nd\re\tf").unwrap(),
            "a\\\\b\\\"c\\nd\\re\\tf"
        );
        assert!(escape_applescript_string("bad\0script").is_err());
    }

    #[test]
    fn direct_outcome_mapping_handles_saved_needs_restart_and_redacts_secret_urls() {
        let ok = classify_direct_outcome(
            &CapturedOutput {
                exit_code: Some(0),
                success: true,
                stdout: "Applied DNS https://alice:supersecret@dns.nextdns.io/abc123?key=xyz\n"
                    .to_string(),
                stderr: String::new(),
            },
            true,
        );
        match ok {
            SidecarOutcome::Ok(msg) => {
                assert!(msg.contains("https://dns.nextdns.io"));
                assert!(!msg.contains("supersecret"));
                assert!(!msg.contains("abc123"));
                assert!(!msg.contains("key=xyz"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        // Exit code 2 for `config apply-file` maps to SavedNeedsRestart with URL redaction.
        let saved_restart = classify_direct_outcome(
            &CapturedOutput {
                exit_code: Some(2),
                success: false,
                stdout: String::new(),
                stderr: "Saved https://u:pw@dns.example.com/secretpath, restart failed".to_string(),
            },
            true,
        );
        match saved_restart {
            SidecarOutcome::SavedNeedsRestart(msg) => {
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("secretpath"));
                assert!(!msg.contains("pw"));
            }
            other => panic!("expected SavedNeedsRestart, got {other:?}"),
        }

        // Exit code 2 for non-apply-file commands remains Err.
        let non_apply_exit2 = classify_direct_outcome(
            &CapturedOutput {
                exit_code: Some(2),
                success: false,
                stdout: String::new(),
                stderr: "invalid argument".to_string(),
            },
            false,
        );
        assert_eq!(
            non_apply_exit2,
            SidecarOutcome::Err("invalid argument".to_string())
        );

        let err = classify_direct_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: "ignored stdout".to_string(),
                stderr: "Failed probing https://user:pw@dns.example.com/private/token".to_string(),
            },
            false,
        );
        match err {
            SidecarOutcome::Err(msg) => {
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("private"));
                assert!(!msg.contains("token"));
                assert!(!msg.contains("pw"));
            }
            other => panic!("expected Err, got {other:?}"),
        }

        let empty_err = classify_direct_outcome(
            &CapturedOutput {
                exit_code: Some(42),
                success: false,
                stdout: "   ".to_string(),
                stderr: String::new(),
            },
            false,
        );
        assert_eq!(
            empty_err,
            SidecarOutcome::Err("vdpi command exited with status code 42.".to_string())
        );
    }

    #[test]
    fn windows_timeout_bound_and_exit_code_mapping() {
        assert_eq!(bounded_timeout_ms(0), 1_000);
        assert_eq!(bounded_timeout_ms(30), 30_000);
        assert_eq!(bounded_timeout_ms(u64::MAX), u32::MAX - 1);
        assert_ne!(
            bounded_timeout_ms(u64::MAX),
            u32::MAX,
            "timeout must NEVER equal Win32 INFINITE (0xFFFFFFFF)"
        );

        assert_eq!(
            classify_windows_exit_code(0, true),
            SidecarOutcome::Ok(String::new())
        );
        assert_eq!(
            classify_windows_exit_code(2, true),
            SidecarOutcome::SavedNeedsRestart(String::new())
        );
        assert_eq!(
            classify_windows_exit_code(2, false),
            SidecarOutcome::Err("Elevated vdpi command failed with exit code 2.".to_string())
        );
        assert_eq!(
            classify_windows_exit_code(WIN32_ERROR_CANCELLED, true),
            SidecarOutcome::Cancelled
        );
        assert_eq!(
            classify_windows_exit_code(5, true),
            SidecarOutcome::Err("Elevated vdpi command failed with exit code 5.".to_string())
        );
    }

    #[test]
    fn macos_osascript_outcome_mapping_handles_cancel_saved_needs_restart_and_redacts_errors() {
        let ok = classify_osascript_outcome(
            &CapturedOutput {
                exit_code: Some(0),
                success: true,
                stdout: "ok https://u:p@dns.nextdns.io/secret".to_string(),
                stderr: String::new(),
            },
            true,
        );
        match ok {
            SidecarOutcome::Ok(msg) => {
                assert!(msg.contains("https://dns.nextdns.io"));
                assert!(!msg.contains("secret"));
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        for cancel_stderr in [
            "36:84: execution error: User canceled. (-128)",
            "execution error: User cancelled.",
            "osascript failed with error -128",
        ] {
            let res = classify_osascript_outcome(
                &CapturedOutput {
                    exit_code: Some(1),
                    success: false,
                    stdout: String::new(),
                    stderr: cancel_stderr.to_string(),
                },
                true,
            );
            assert_eq!(
                res,
                SidecarOutcome::Cancelled,
                "expected Cancelled for {cancel_stderr:?}"
            );
        }

        // AppleScript `do shell script` reports shell exit code 2 via trailing ` (2)`.
        let saved_restart = classify_osascript_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: String::new(),
                stderr:
                    "36:142: execution error: Saved https://u:pw@dns.example.com/tok, restart failed (2)"
                        .to_string(),
            },
            true,
        );
        match saved_restart {
            SidecarOutcome::SavedNeedsRestart(msg) => {
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("tok"));
                assert!(!msg.contains("pw"));
            }
            other => panic!("expected SavedNeedsRestart, got {other:?}"),
        }

        // Trailing `(2)` is NOT SavedNeedsRestart for non-apply-file commands.
        let non_apply = classify_osascript_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "36:84: execution error: bad flag (2)".to_string(),
            },
            false,
        );
        assert!(matches!(non_apply, SidecarOutcome::Err(_)));

        // Embedded `(2)` with trailing `(1)` is NOT exit code 2.
        let embedded = classify_osascript_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "36:84: execution error: attempt (2) failed (1)".to_string(),
            },
            true,
        );
        assert!(matches!(embedded, SidecarOutcome::Err(_)));

        // `-1280` must NOT be misclassified as `-128` cancel.
        let non_cancel = classify_osascript_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "error -1280 talking to https://u:pw@dns.example.com/secretpath"
                    .to_string(),
            },
            true,
        );
        match non_cancel {
            SidecarOutcome::Err(msg) => {
                assert!(msg.contains("-1280"));
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("secretpath"));
                assert!(!msg.contains("pw"));
            }
            other => panic!("expected Err, got {other:?}"),
        }
    }

    #[test]
    fn linux_pkexec_outcome_mapping_env_scrubbing_and_appimage_detection() {
        assert_eq!(
            classify_pkexec_outcome(
                &CapturedOutput {
                    exit_code: Some(0),
                    success: true,
                    stdout: "applied".to_string(),
                    stderr: String::new(),
                },
                true
            ),
            SidecarOutcome::Ok("applied".to_string())
        );

        // Exit code 2 for `config apply-file` maps to SavedNeedsRestart.
        let saved_restart = classify_pkexec_outcome(
            &CapturedOutput {
                exit_code: Some(2),
                success: false,
                stdout: String::new(),
                stderr: "saved https://u:pw@dns.example.com/secret, restart failed".to_string(),
            },
            true,
        );
        match saved_restart {
            SidecarOutcome::SavedNeedsRestart(msg) => {
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("secret"));
                assert!(!msg.contains("pw"));
            }
            other => panic!("expected SavedNeedsRestart, got {other:?}"),
        }
        assert!(matches!(
            classify_pkexec_outcome(
                &CapturedOutput {
                    exit_code: Some(2),
                    success: false,
                    stdout: String::new(),
                    stderr: "usage error".to_string(),
                },
                false,
            ),
            SidecarOutcome::Err(_)
        ));

        // Exit 126 is always user dismissal in pkexec.
        assert_eq!(
            classify_pkexec_outcome(
                &CapturedOutput {
                    exit_code: Some(126),
                    success: false,
                    stdout: String::new(),
                    stderr: "Error executing command as another user: Not authorized".to_string(),
                },
                true
            ),
            SidecarOutcome::Cancelled
        );

        // Exit 127 with "dismissed" maps to Cancelled.
        assert_eq!(
            classify_pkexec_outcome(
                &CapturedOutput {
                    exit_code: Some(127),
                    success: false,
                    stdout: String::new(),
                    stderr: "Error executing command as another user: Request dismissed"
                        .to_string(),
                },
                true
            ),
            SidecarOutcome::Cancelled
        );

        // Exit 127 without dismissal (e.g. no polkit auth agent) maps to Err.
        let no_agent = classify_pkexec_outcome(
            &CapturedOutput {
                exit_code: Some(127),
                success: false,
                stdout: String::new(),
                stderr: "No authentication agent found".to_string(),
            },
            true,
        );
        assert!(matches!(no_agent, SidecarOutcome::Err(_)));

        // Non-cancel failure redacts URLs.
        let failed = classify_pkexec_outcome(
            &CapturedOutput {
                exit_code: Some(1),
                success: false,
                stdout: String::new(),
                stderr: "apply failed for https://u:pw@dns.example.com/tok123".to_string(),
            },
            true,
        );
        match failed {
            SidecarOutcome::Err(msg) => {
                assert!(msg.contains("https://dns.example.com"));
                assert!(!msg.contains("tok123"));
            }
            other => panic!("expected Err, got {other:?}"),
        }

        // pkexec candidate filtering
        let dir = TestDir::new("pkexec");
        let wrong_name = dir.path().join("sudo");
        fs::write(&wrong_name, b"nope").expect("write wrong helper");
        let pkexec_dir = dir.path().join("dir").join("pkexec");
        fs::create_dir_all(&pkexec_dir).expect("create dir named pkexec");
        let real_pkexec = dir.path().join("pkexec");
        fs::write(&real_pkexec, b"real").expect("write fake pkexec");

        let resolved =
            resolve_pkexec_from_candidates(&[wrong_name, pkexec_dir, real_pkexec.clone()])
                .expect("resolve valid pkexec");
        assert_eq!(resolved, real_pkexec);

        // AppImage FUSE path detection (LIN-03)
        assert!(is_appimage_fuse_path(
            Path::new("/tmp/.mount_vdpiAbCd/usr/lib/vdpi Desktop/vdpi"),
            None
        ));
        assert!(is_appimage_fuse_path(
            Path::new("/custom/mount/usr/lib/vdpi Desktop/vdpi"),
            Some(Path::new("/custom/mount"))
        ));
        assert!(!is_appimage_fuse_path(
            Path::new("/usr/local/bin/vdpi"),
            Some(Path::new("/tmp/.mount_vdpiAbCd"))
        ));
        assert!(!is_appimage_fuse_path(
            Path::new("/usr/lib/vdpi Desktop/vdpi"),
            None
        ));

        // Linux AppImage env scrubbing (LIN-07)
        let mut cmd = Command::new("vdpi");
        scrub_linux_appimage_env(&mut cmd);
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, v)| v.is_none())
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        for expected in LINUX_SCRUBBED_ENV_VARS {
            assert!(
                removed.iter().any(|k| k == expected),
                "expected env var {expected} to be scrubbed"
            );
        }
        assert!(!removed.iter().any(|k| k == "DISPLAY"));
        assert!(!removed.iter().any(|k| k == "DBUS_SESSION_BUS_ADDRESS"));
    }

    #[cfg(unix)]
    #[test]
    fn appimage_staging_creates_0700_copy_and_cleans_up_via_raii() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("stage-exec");
        let src_dir = dir.path().join("fuse-src");
        fs::create_dir_all(&src_dir).expect("create src dir");
        let src_bin = src_dir.join("vdpi");
        let payload = b"#!/bin/sh\necho staged\n";
        fs::write(&src_bin, payload).expect("write fake cli");

        let runtime_dir = dir.path().join("runtime");
        let staged_path;
        let exec_dir;
        {
            let guard = stage_executable_copy_in(&src_bin, &runtime_dir, "exec-")
                .expect("stage executable copy");
            staged_path = guard.path().to_path_buf();
            exec_dir = staged_path.parent().unwrap().to_path_buf();

            assert_eq!(staged_path.file_name(), Some(OsStr::new("vdpi")));
            assert_eq!(fs::read(&staged_path).expect("read staged"), payload);

            let runtime_mode = fs::metadata(&runtime_dir)
                .expect("stat runtime dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(runtime_mode, 0o700);

            let exec_dir_mode = fs::metadata(&exec_dir)
                .expect("stat exec dir")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(exec_dir_mode, 0o700);

            let bin_mode = fs::metadata(&staged_path)
                .expect("stat staged bin")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(bin_mode, 0o700);
        }

        assert!(
            !staged_path.exists(),
            "staged binary must be removed on RAII drop"
        );
        assert!(
            !exec_dir.exists(),
            "exclusive staging dir must be removed on RAII drop"
        );
    }

    #[test]
    fn run_command_with_timeout_returns_promptly_without_deadlock() {
        #[cfg(windows)]
        let mut cmd = {
            let mut c = Command::new(windows_cmd_exe());
            c.args(["/C", "ping -n 15 127.0.0.1 >nul"]);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = Command::new("/bin/sh");
            c.args(["-c", "sleep 15"]);
            c
        };

        let start = Instant::now();
        let err = run_command_with_timeout(&mut cmd, Duration::from_millis(120))
            .expect_err("long-running command must time out");
        assert!(err.contains("timed out"), "unexpected err: {err}");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "timeout must return promptly without waiting for child exit"
        );
    }

    #[test]
    fn user_config_dir_refuses_temp_dir_fallback_and_unsafe_paths() {
        let temp_dir = std::env::temp_dir();

        assert!(resolve_user_config_dir_from(Path::new("config.toml"), &temp_dir).is_err());
        assert!(resolve_user_config_dir_from(Path::new("relative/config.toml"), &temp_dir).is_err());
        assert!(
            resolve_user_config_dir_from(&temp_dir.join("config.toml"), &temp_dir).is_err(),
            "must refuse shared system temp_dir for secret config handoff"
        );

        #[cfg(unix)]
        {
            assert!(resolve_user_config_dir_from(Path::new("/tmp/config.toml"), &temp_dir).is_err());
            assert!(
                resolve_user_config_dir_from(Path::new("/var/tmp/config.toml"), &temp_dir).is_err()
            );
            assert!(resolve_user_config_dir_from(
                Path::new("/home/alice/../bob/.config/vdpi/config.toml"),
                &temp_dir
            )
            .is_err());
            assert_eq!(
                resolve_user_config_dir_from(
                    Path::new("/home/alice/.config/vdpi/config.toml"),
                    &temp_dir
                )
                .expect("valid user config dir"),
                PathBuf::from("/home/alice/.config/vdpi")
            );
        }

        #[cfg(windows)]
        {
            assert!(resolve_user_config_dir_from(
                Path::new(r"C:\Users\Alice\..\Bob\vdpi\config.toml"),
                &temp_dir
            )
            .is_err());
            assert_eq!(
                resolve_user_config_dir_from(
                    Path::new(r"C:\Users\Alice\AppData\Local\vdpi\config.toml"),
                    &temp_dir
                )
                .expect("valid windows user config dir"),
                PathBuf::from(r"C:\Users\Alice\AppData\Local\vdpi")
            );
        }
    }

    #[test]
    fn unique_temp_tokens_are_distinct_and_high_entropy() {
        let t1 = unique_temp_token(42, 1, 100);
        let t2 = unique_temp_token(42, 1, 100);
        assert_ne!(t1, t2);
        let parts: Vec<&str> = t1.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "42");
        assert_eq!(parts[1], "1");
        assert_eq!(parts[2].len(), 32);
        assert!(parts[2].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sweep_stale_temp_files_removes_only_orphaned_apply_temp_files() {
        let dir = TestDir::new("sweep");
        let stale_toml = dir.path().join(".vdpi-apply-123.0.deadbeef.toml");
        let stale_tmp = dir.path().join(".vdpi-apply-stage-123.0.deadbeef.tmp");
        let keep_config = dir.path().join("config.toml");
        let keep_prefs = dir.path().join("gui-prefs.json");
        let keep_subdir = dir.path().join(".vdpi-apply-dir.toml");

        fs::write(&stale_toml, b"secret").expect("write stale toml");
        fs::write(&stale_tmp, b"stage").expect("write stale tmp");
        fs::write(&keep_config, b"real config").expect("write real config");
        fs::write(&keep_prefs, b"{}").expect("write prefs");
        fs::create_dir_all(&keep_subdir).expect("create dir with matching name");

        let removed = sweep_stale_temp_files_in(dir.path());
        assert_eq!(removed, 2);
        assert!(!stale_toml.exists());
        assert!(!stale_tmp.exists());
        assert!(keep_config.is_file());
        assert!(keep_prefs.is_file());
        assert!(keep_subdir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn sweep_stale_staged_exec_dirs_removes_only_matching_owned_dirs() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("sweep-exec");
        let stale_one = dir.path().join("vdpi-exec-111");
        let stale_two = dir.path().join("vdpi-exec-222");
        let keep_other = dir.path().join("other-exec-333");
        let keep_file = dir.path().join("vdpi-exec-regular-file");
        let keep_link = dir.path().join("vdpi-exec-symlink");

        fs::create_dir_all(&stale_one).expect("create stale_one");
        fs::create_dir_all(&stale_two).expect("create stale_two");
        fs::create_dir_all(&keep_other).expect("create keep_other");
        fs::write(stale_one.join("vdpi"), b"bin1").expect("write bin1");
        fs::write(stale_two.join("vdpi"), b"bin2").expect("write bin2");
        fs::write(keep_other.join("vdpi"), b"other").expect("write other bin");
        fs::write(&keep_file, b"file").expect("write regular file");
        symlink(&keep_other, &keep_link).expect("create symlink dir");

        // SAFETY: POSIX `geteuid(2)` is always safe to call and never fails.
        let current_uid: u32 = unsafe { libc::geteuid() };
        let mismatched_uid = current_uid.wrapping_add(1);

        // Must never touch directories owned by another user.
        assert_eq!(
            sweep_stale_staged_exec_dirs_in(dir.path(), "vdpi-exec-", Some(mismatched_uid)),
            0
        );
        assert!(stale_one.is_dir());
        assert!(stale_two.is_dir());

        // Sweeps current-user-owned `vdpi-exec-*` staging dirs while preserving
        // non-matching dirs, regular files, and symlinks.
        assert_eq!(
            sweep_stale_staged_exec_dirs_in(dir.path(), "vdpi-exec-", Some(current_uid)),
            2
        );
        assert!(!stale_one.exists());
        assert!(!stale_two.exists());
        assert!(keep_other.join("vdpi").is_file());
        assert!(keep_file.is_file());
        assert!(fs::symlink_metadata(&keep_link)
            .expect("symlink must remain untouched")
            .file_type()
            .is_symlink());
    }

    #[test]
    fn apply_config_via_temp_file_writes_rendered_toml_never_leaks_argv_and_cleans_up() {
        let dir = TestDir::new("apply-config");
        let nested_dir = dir.path().join("private-cfg");
        let secret_doh = "https://alice:topsecret@dns.nextdns.io/mysecretprofile?token=xyz999";
        let cfg = FileConfig {
            schema_version: Some(1),
            engine: Some(EngineMode::Tun),
            doh: Some(true),
            block_quic: Some(true),
            dns_addr: Some(secret_doh.to_string()),
            bypass_domains: Some(vec!["example.com".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec!["discord".to_string()]),
            ..Default::default()
        };
        let expected_toml = render_config_toml(&cfg);

        // 1. Success path with `--restart`: verify argv, file contents, Unix 0700/0600 modes, and cleanup.
        let observed_temp_path = RefCell::new(None::<PathBuf>);
        let outcome =
            apply_config_via_temp_file_in(&nested_dir, &cfg, true, |args, timeout| {
                assert!(timeout > 0);
                assert_eq!(args.len(), 4);
                assert_eq!(args[0], "config");
                assert_eq!(args[1], "apply-file");
                assert_eq!(args[3], "--restart");

                for arg in args {
                    assert!(
                        !arg.contains("topsecret")
                            && !arg.contains("mysecretprofile")
                            && !arg.contains("xyz999")
                            && !arg.contains("dns.nextdns.io"),
                        "secret DoH URL must NEVER appear on argv: {arg}"
                    );
                }

                let tmp_path = PathBuf::from(args[2]);
                assert_eq!(tmp_path.parent(), Some(nested_dir.as_path()));
                assert!(tmp_path.is_file(), "temp file must exist while runner executes");

                let written = fs::read_to_string(&tmp_path).expect("read temp config toml");
                assert_eq!(written, expected_toml);

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let dir_mode = fs::metadata(&nested_dir)
                        .expect("stat newly created config dir")
                        .permissions()
                        .mode()
                        & 0o777;
                    assert_eq!(dir_mode, 0o700, "newly created config dir must be 0700");

                    let mode = fs::metadata(&tmp_path)
                        .expect("stat temp config file")
                        .permissions()
                        .mode()
                        & 0o777;
                    assert_eq!(mode, 0o600, "temp config file must be owner-only 0600");
                }

                *observed_temp_path.borrow_mut() = Some(tmp_path);
                SidecarOutcome::Ok("applied".to_string())
            });
        assert_eq!(outcome, SidecarOutcome::Ok("applied".to_string()));
        let first_tmp = observed_temp_path
            .borrow()
            .clone()
            .expect("recorded temp path");
        assert!(
            !first_tmp.exists(),
            "temp config file must be removed after Ok"
        );

        // 2. SavedNeedsRestart path: verify propagation and unconditional cleanup.
        let restart_tmp = RefCell::new(None::<PathBuf>);
        let restart_outcome =
            apply_config_via_temp_file_in(&nested_dir, &cfg, true, |args, _| {
                *restart_tmp.borrow_mut() = Some(PathBuf::from(args[2]));
                SidecarOutcome::SavedNeedsRestart("restart failed".to_string())
            });
        assert_eq!(
            restart_outcome,
            SidecarOutcome::SavedNeedsRestart("restart failed".to_string())
        );
        assert!(
            !restart_tmp.borrow().as_ref().unwrap().exists(),
            "temp config file must be removed after SavedNeedsRestart"
        );

        // 3. Cancelled path without `--restart`: verify no `--restart` flag and unconditional cleanup.
        let cancel_tmp = RefCell::new(None::<PathBuf>);
        let cancel_outcome =
            apply_config_via_temp_file_in(&nested_dir, &cfg, false, |args, _| {
                assert_eq!(args.len(), 3);
                assert_eq!(args[0], "config");
                assert_eq!(args[1], "apply-file");
                *cancel_tmp.borrow_mut() = Some(PathBuf::from(args[2]));
                SidecarOutcome::Cancelled
            });
        assert_eq!(cancel_outcome, SidecarOutcome::Cancelled);
        assert!(
            !cancel_tmp.borrow().as_ref().unwrap().exists(),
            "temp config file must be removed after Cancelled"
        );

        // 4. Error path: verify unconditional cleanup.
        let err_tmp = RefCell::new(None::<PathBuf>);
        let err_outcome = apply_config_via_temp_file_in(&nested_dir, &cfg, false, |args, _| {
            *err_tmp.borrow_mut() = Some(PathBuf::from(args[2]));
            SidecarOutcome::Err("apply failed".to_string())
        });
        assert_eq!(err_outcome, SidecarOutcome::Err("apply failed".to_string()));
        assert!(
            !err_tmp.borrow().as_ref().unwrap().exists(),
            "temp config file must be removed after Err"
        );

        // 5. Panic path: verify RAII guard still cleans up temp file during unwind.
        let panic_tmp = RefCell::new(None::<PathBuf>);
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            apply_config_via_temp_file_in(&nested_dir, &cfg, false, |args, _| {
                *panic_tmp.borrow_mut() = Some(PathBuf::from(args[2]));
                panic!("simulated runner panic");
            })
        }));
        assert!(panicked.is_err());
        assert!(
            !panic_tmp.borrow().as_ref().unwrap().exists(),
            "temp config file must be removed even on panic"
        );

        // 6. Symlink/junction/traversal parent dirs are rejected before writing secret config.
        let traversal_dir = nested_dir.join("..").join("private-cfg");
        assert!(write_atomic_owner_only_temp_file(&traversal_dir, b"secret").is_err());

        #[cfg(unix)]
        {
            let link_dir = dir.path().join("symlink-cfg");
            std::os::unix::fs::symlink(&nested_dir, &link_dir).expect("create symlink dir");
            assert!(write_atomic_owner_only_temp_file(&link_dir, b"secret").is_err());
            assert!(write_atomic_owner_only_temp_file(&link_dir.join("sub"), b"secret").is_err());
            assert!(
                check_ancestors_under_roots(&link_dir, std::slice::from_ref(&link_dir)).is_err()
            );
            assert!(check_ancestors_under_roots(
                &link_dir.join("sub"),
                std::slice::from_ref(&link_dir)
            )
            .is_err());
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let junction_dir = dir.path().join("junction-cfg");
            let status = Command::new(windows_cmd_exe())
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
                .args([
                    OsStr::new("/C"),
                    OsStr::new("mklink"),
                    OsStr::new("/J"),
                    junction_dir.as_os_str(),
                    nested_dir.as_os_str(),
                ])
                .status()
                .expect("spawn mklink /J");
            assert!(status.success(), "mklink /J must create junction");
            assert!(write_atomic_owner_only_temp_file(&junction_dir, b"secret").is_err());
            assert!(
                write_atomic_owner_only_temp_file(&junction_dir.join("sub"), b"secret").is_err()
            );
            assert!(
                check_ancestors_under_roots(&junction_dir, std::slice::from_ref(&junction_dir))
                    .is_err()
            );
            assert!(check_ancestors_under_roots(
                &junction_dir.join("sub"),
                std::slice::from_ref(&junction_dir)
            )
            .is_err());
            let _ = fs::remove_dir(&junction_dir);
        }

        // Directory must have zero leftover temp or staging files.
        let leftover: Vec<PathBuf> = fs::read_dir(&nested_dir)
            .expect("list test dir")
            .map(|e| e.expect("dir entry").path())
            .collect();
        assert!(
            leftover.is_empty(),
            "expected zero leftover temp files, found: {leftover:?}"
        );
    }
}
