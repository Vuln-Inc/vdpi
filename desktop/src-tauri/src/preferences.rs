use std::collections::hash_map::RandomState;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::hash::{BuildHasher, Hash, Hasher};
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use tracing::warn;

use crate::models::GuiPreferencesDto;

const GUI_PREFS_FILE_NAME: &str = "gui-prefs.json";
const MAX_GUI_PREFS_BYTES: usize = 256 * 1024;

#[cfg(windows)]
const WINDOWS_RENAME_MAX_RETRIES: usize = 5;
#[cfg(windows)]
const WINDOWS_RENAME_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(25);

static TMP_FILE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
mod platform_fs {
    use std::fs::{File, OpenOptions};
    use std::io::{self, ErrorKind};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use anyhow::{bail, Context, Result};
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

    pub(super) fn is_reparse_point_attrs(attrs: u32) -> bool {
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

    pub(super) fn reject_symlink_or_reparse(path: &Path) -> Result<()> {
        if let Some(attrs) = attributes_no_follow(path)
            .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                bail!(
                    "refusing to access symlink/reparse point: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    pub(super) fn reject_target_symlink_or_dir(path: &Path) -> Result<()> {
        if let Some(attrs) = attributes_no_follow(path)
            .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                bail!(
                    "refusing to access symlink/reparse point: {}",
                    path.display()
                );
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                bail!(
                    "refusing to treat directory as GUI preferences file: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    pub(super) fn verify_dir_not_symlink(path: &Path) -> Result<bool> {
        match attributes_no_follow(path)
            .with_context(|| format!("failed to inspect directory {}", path.display()))?
        {
            None => Ok(false),
            Some(attrs) => {
                if is_reparse_point_attrs(attrs) {
                    bail!(
                        "refusing to use symlink/reparse point directory: {}",
                        path.display()
                    );
                }
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    bail!(
                        "GUI preferences parent path is not a directory: {}",
                        path.display()
                    );
                }
                Ok(true)
            }
        }
    }

    /// Rejects symlinks/reparse points and directories BEFORE opening via `GetFileAttributesW`,
    /// opens with `FILE_FLAG_OPEN_REPARSE_POINT` to close TOCTOU races, and verifies the opened
    /// handle is a regular non-reparse file (`is_file()`).
    pub(super) fn open_regular_file_for_read(path: &Path) -> Result<Option<File>> {
        let Some(attrs) = attributes_no_follow(path)
            .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
        else {
            return Ok(None);
        };
        if is_reparse_point_attrs(attrs) {
            bail!(
                "refusing to read GUI preferences from symlink/reparse point: {}",
                path.display()
            );
        }
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            bail!(
                "refusing to read GUI preferences from directory: {}",
                path.display()
            );
        }

        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if is_not_found_error(&err) => return Ok(None),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to open GUI preferences {}", path.display()));
            }
        };

        verify_opened_regular_file(&file, path)?;
        Ok(Some(file))
    }

    pub(super) fn verify_opened_regular_file(file: &File, path: &Path) -> Result<()> {
        let meta = file
            .metadata()
            .with_context(|| format!("failed to inspect metadata for {}", path.display()))?;
        if is_reparse_point_attrs(meta.file_attributes()) || !meta.is_file() {
            bail!(
                "refusing to access non-regular file or reparse point: {}",
                path.display()
            );
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

    use anyhow::{bail, Context, Result};

    pub(super) fn reject_symlink_or_reparse(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("refusing to access symlink: {}", path.display());
            }
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => {
                Err(err).with_context(|| format!("failed to inspect path {}", path.display()))
            }
        }
    }

    pub(super) fn reject_target_symlink_or_dir(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!("refusing to access symlink: {}", path.display());
                }
                if meta.is_dir() {
                    bail!(
                        "refusing to treat directory as GUI preferences file: {}",
                        path.display()
                    );
                }
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => {
                Err(err).with_context(|| format!("failed to inspect path {}", path.display()))
            }
        }
    }

    pub(super) fn verify_dir_not_symlink(path: &Path) -> Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!("refusing to use symlink directory: {}", path.display());
                }
                if !meta.is_dir() {
                    bail!(
                        "GUI preferences parent path is not a directory: {}",
                        path.display()
                    );
                }
                Ok(true)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => {
                Err(err).with_context(|| format!("failed to inspect directory {}", path.display()))
            }
        }
    }

    /// Rejects symlinks and non-regular files BEFORE opening via `symlink_metadata`, opens with
    /// `O_NOFOLLOW | O_NONBLOCK` so a symlink or FIFO/device race can never follow a link or
    /// hang startup, and verifies `file.metadata().is_file()` on the opened descriptor before
    /// any bytes are read.
    pub(super) fn open_regular_file_for_read(path: &Path) -> Result<Option<File>> {
        match fs::symlink_metadata(path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!(
                        "refusing to read GUI preferences from symlink: {}",
                        path.display()
                    );
                }
                if !meta.file_type().is_file() {
                    bail!(
                        "refusing to read GUI preferences from non-regular file: {}",
                        path.display()
                    );
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect GUI preferences {}", path.display()));
            }
        }

        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to open GUI preferences {}", path.display()));
            }
        };

        verify_opened_regular_file(&file, path)?;
        Ok(Some(file))
    }

    pub(super) fn verify_opened_regular_file(file: &File, path: &Path) -> Result<()> {
        let meta = file
            .metadata()
            .with_context(|| format!("failed to inspect metadata for {}", path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!(
                "refusing to access non-regular file or symlink: {}",
                path.display()
            );
        }
        Ok(())
    }

    pub(super) fn configure_temp_open_options(opts: &mut OpenOptions) {
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
}

fn reject_parent_dir_traversal(path: &Path) -> Result<()> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!(
            "refusing to access GUI preferences path containing parent directory traversal ('..'): {}",
            path.display()
        );
    }
    Ok(())
}

fn push_abs_env_dir(roots: &mut Vec<PathBuf>, var: &str) {
    if let Some(val) = std::env::var_os(var) {
        if !val.is_empty() {
            let candidate = PathBuf::from(val);
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
    let tmp = std::env::temp_dir();
    if tmp.is_absolute() {
        roots.push(tmp);
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

fn check_ancestors_under_roots(parent: &Path, roots: &[PathBuf]) -> Result<()> {
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
                Component::Prefix(prefix) => cur.push(prefix.as_os_str()),
                Component::RootDir => cur.push(Component::RootDir.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    bail!(
                        "refusing to access GUI preferences path containing parent directory traversal ('..'): {}",
                        parent.display()
                    );
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

fn unique_temp_token(pid: u32, seq: u64, ts_nanos: u128) -> String {
    let mut h1 = RandomState::new().build_hasher();
    pid.hash(&mut h1);
    seq.hash(&mut h1);
    ts_nanos.hash(&mut h1);
    std::thread::current().id().hash(&mut h1);
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
                std::thread::sleep(WINDOWS_RENAME_RETRY_BACKOFF);
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(not(windows))]
fn rename_atomic(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

/// Returns the persistent GUI preferences file path (`gui-prefs.json`) stored
/// next to `vdpi::config_file::user_config_path()`.
pub fn gui_prefs_path() -> PathBuf {
    gui_prefs_path_from_config(&vdpi::config_file::user_config_path())
}

fn gui_prefs_path_from_config(config_path: &Path) -> PathBuf {
    match config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(GUI_PREFS_FILE_NAME),
        None => PathBuf::from(GUI_PREFS_FILE_NAME),
    }
}

/// Loads persisted GUI preferences from disk, falling back safely to defaults
/// if the file is missing, a symlink/reparse point, non-regular, unreadable,
/// oversized, or contains invalid JSON.
pub fn load_gui_preferences() -> GuiPreferencesDto {
    load_gui_preferences_from_path(&gui_prefs_path())
}

fn load_gui_preferences_from_path(path: &Path) -> GuiPreferencesDto {
    if let Err(err) = reject_parent_dir_traversal(path) {
        warn!(
            path = %path.display(),
            error = %err,
            "refusing to load GUI preferences from unsafe path; falling back to defaults"
        );
        return GuiPreferencesDto::default();
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let roots = user_home_and_config_roots();
    let parent_check = check_ancestors_under_roots(parent, &roots).and_then(|()| {
        if !is_filesystem_or_known_root(parent, &roots) {
            platform_fs::reject_symlink_or_reparse(parent)
        } else {
            Ok(())
        }
    });
    if let Err(err) = parent_check {
        warn!(
            path = %path.display(),
            error = %err,
            "refusing to load GUI preferences through symlink/reparse point ancestor; falling back to defaults"
        );
        return GuiPreferencesDto::default();
    }

    let file = match platform_fs::open_regular_file_for_read(path) {
        Ok(Some(file)) => file,
        Ok(None) => return GuiPreferencesDto::default(),
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "failed to safely open GUI preferences; falling back to defaults"
            );
            return GuiPreferencesDto::default();
        }
    };

    let mut buf = Vec::new();
    let max_read = (MAX_GUI_PREFS_BYTES as u64).saturating_add(1);
    if let Err(err) = file.take(max_read).read_to_end(&mut buf) {
        warn!(
            path = %path.display(),
            error = %err,
            "failed to read GUI preferences; falling back to defaults"
        );
        return GuiPreferencesDto::default();
    }

    if buf.len() > MAX_GUI_PREFS_BYTES {
        warn!(
            path = %path.display(),
            max_bytes = MAX_GUI_PREFS_BYTES,
            "GUI preferences file exceeds maximum allowed size; falling back to defaults"
        );
        return GuiPreferencesDto::default();
    }

    match serde_json::from_slice::<GuiPreferencesDto>(&buf) {
        Ok(prefs) => prefs,
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "invalid GUI preferences JSON; falling back to defaults"
            );
            GuiPreferencesDto::default()
        }
    }
}

/// Atomically persists GUI preferences to `gui-prefs.json` after verifying the
/// parent directory, ancestors under user home/config roots, and target path
/// are not symlinks/reparse points, using a unique sibling temporary file
/// (`0o600` mode on Unix, `0o700` on newly created parent dirs), `sync_all()`,
/// and atomic rename (with Windows AV-lock retry backoff).
pub fn save_gui_preferences(prefs: &GuiPreferencesDto) -> Result<()> {
    save_gui_preferences_to_path(&gui_prefs_path(), prefs)
}

fn save_gui_preferences_to_path(path: &Path, prefs: &GuiPreferencesDto) -> Result<()> {
    reject_parent_dir_traversal(path)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let roots = user_home_and_config_roots();

    check_ancestors_under_roots(parent, &roots)?;
    let is_root_parent = is_filesystem_or_known_root(parent, &roots);
    let parent_existed = if is_root_parent {
        parent.is_dir()
    } else {
        platform_fs::verify_dir_not_symlink(parent)?
    };
    platform_fs::reject_target_symlink_or_dir(path)?;

    if !parent_existed {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(parent).with_context(|| {
                format!(
                    "failed to create GUI preferences directory {}",
                    parent.display()
                )
            })?;
            check_ancestors_under_roots(parent, &roots)?;
            if !is_root_parent {
                let exists_now = platform_fs::verify_dir_not_symlink(parent)?;
                if !exists_now {
                    bail!(
                        "GUI preferences directory disappeared after creation: {}",
                        parent.display()
                    );
                }
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(
                    || {
                        format!(
                            "failed to set 0700 permissions on GUI preferences directory {}",
                            parent.display()
                        )
                    },
                )?;
            }
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create GUI preferences directory {}",
                    parent.display()
                )
            })?;
            check_ancestors_under_roots(parent, &roots)?;
            if !is_root_parent {
                let exists_now = platform_fs::verify_dir_not_symlink(parent)?;
                if !exists_now {
                    bail!(
                        "GUI preferences directory disappeared after creation: {}",
                        parent.display()
                    );
                }
            }
        }
    }

    let mut serialized = serde_json::to_string_pretty(prefs)
        .context("failed to serialize GUI preferences to JSON")?;
    serialized.push('\n');

    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(GUI_PREFS_FILE_NAME);
    let pid = std::process::id();
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut created = None;
    for _ in 0..16 {
        let seq = TMP_FILE_SEQ.fetch_add(1, Ordering::Relaxed);
        let token = unique_temp_token(pid, seq, ts_nanos);
        let candidate = parent.join(format!(".{file_name}.tmp.{token}"));

        let mut open_opts = OpenOptions::new();
        open_opts.write(true).create_new(true);
        platform_fs::configure_temp_open_options(&mut open_opts);

        match open_opts.open(&candidate) {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create temporary GUI preferences file {}",
                        candidate.display()
                    )
                });
            }
        }
    }

    let (tmp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary GUI preferences file in {}",
            parent.display()
        )
    })?;

    let write_res = (|| -> Result<()> {
        platform_fs::verify_opened_regular_file(&file, &tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .with_context(|| {
                    format!(
                        "failed to set 0600 permissions on temporary GUI preferences file {}",
                        tmp_path.display()
                    )
                })?;
        }
        file.write_all(serialized.as_bytes()).with_context(|| {
            format!(
                "failed to write temporary GUI preferences file {}",
                tmp_path.display()
            )
        })?;
        file.sync_all().with_context(|| {
            format!(
                "failed to sync temporary GUI preferences file {}",
                tmp_path.display()
            )
        })?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    let pre_rename_check = check_ancestors_under_roots(parent, &roots)
        .and_then(|()| {
            if !is_root_parent {
                platform_fs::reject_symlink_or_reparse(parent)
            } else {
                Ok(())
            }
        })
        .and_then(|()| platform_fs::reject_target_symlink_or_dir(path));
    if let Err(err) = pre_rename_check {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = rename_atomic(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                tmp_path.display()
            )
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{LanguagePreferenceDto, ThemePreferenceDto};

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
            let path = std::env::temp_dir()
                .join(format!("vdpi-gui-prefs-test-{label}-{pid}-{ts_nanos}-{seq}"));
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

    #[test]
    fn default_gui_preferences_match_expected_values() {
        let defaults = GuiPreferencesDto::default();
        assert_eq!(defaults.theme, ThemePreferenceDto::System);
        assert_eq!(defaults.language, LanguagePreferenceDto::System);
        assert!(!defaults.keep_in_tray_on_close);
        assert!(!defaults.minimize_to_tray);
        assert!(!defaults.start_minimized_to_tray);
        assert!(!defaults.show_taskbar_icon_when_minimized);
    }

    #[test]
    fn gui_prefs_path_is_sibling_of_user_config_path() {
        let user_cfg = vdpi::config_file::user_config_path();
        let prefs_path = gui_prefs_path();
        assert_eq!(prefs_path.file_name(), Some(OsStr::new(GUI_PREFS_FILE_NAME)));
        assert_eq!(prefs_path.parent(), user_cfg.parent());

        let nested = gui_prefs_path_from_config(&Path::new("vdpi-test").join("config.toml"));
        assert_eq!(nested, Path::new("vdpi-test").join(GUI_PREFS_FILE_NAME));

        let bare = gui_prefs_path_from_config(Path::new("config.toml"));
        assert_eq!(bare, PathBuf::from(GUI_PREFS_FILE_NAME));
    }

    #[test]
    fn load_missing_file_returns_defaults_without_creating_file() {
        let dir = TestDir::new("missing");
        let prefs_path = dir.path().join(GUI_PREFS_FILE_NAME);

        let loaded = load_gui_preferences_from_path(&prefs_path);
        assert_eq!(loaded, GuiPreferencesDto::default());
        assert!(!prefs_path.exists());
    }

    #[test]
    fn save_and_load_round_trip_and_overwrite() {
        let dir = TestDir::new("roundtrip");
        let prefs_path = dir.path().join("nested").join("vdpi").join(GUI_PREFS_FILE_NAME);

        let initial = GuiPreferencesDto {
            theme: ThemePreferenceDto::Dark,
            language: LanguagePreferenceDto::Tr,
            keep_in_tray_on_close: true,
            minimize_to_tray: true,
            start_minimized_to_tray: true,
            show_taskbar_icon_when_minimized: false,
        };
        save_gui_preferences_to_path(&prefs_path, &initial).expect("save initial prefs");

        let loaded = load_gui_preferences_from_path(&prefs_path);
        assert_eq!(loaded, initial);

        let raw = fs::read_to_string(&prefs_path).expect("read persisted JSON");
        let json: serde_json::Value = serde_json::from_str(&raw).expect("parse persisted JSON");
        assert_eq!(json["theme"], "dark");
        assert_eq!(json["language"], "tr");
        assert_eq!(json["keepInTrayOnClose"], true);
        assert_eq!(json["minimizeToTray"], true);
        assert_eq!(json["startMinimizedToTray"], true);
        assert_eq!(json["showTaskbarIconWhenMinimized"], false);

        let updated = GuiPreferencesDto {
            theme: ThemePreferenceDto::Light,
            language: LanguagePreferenceDto::En,
            keep_in_tray_on_close: false,
            minimize_to_tray: true,
            start_minimized_to_tray: false,
            show_taskbar_icon_when_minimized: true,
        };
        save_gui_preferences_to_path(&prefs_path, &updated).expect("overwrite prefs");

        let reloaded = load_gui_preferences_from_path(&prefs_path);
        assert_eq!(reloaded, updated);

        let entries: Vec<PathBuf> = fs::read_dir(prefs_path.parent().expect("parent dir"))
            .expect("list prefs dir")
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        assert_eq!(entries, vec![prefs_path]);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_0600_mode_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("unix-mode");
        let prefs_path = dir.path().join(GUI_PREFS_FILE_NAME);
        save_gui_preferences_to_path(&prefs_path, &GuiPreferencesDto::default())
            .expect("save prefs");

        let mode = fs::metadata(&prefs_path)
            .expect("stat prefs file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_0700_mode_on_newly_created_parent_dir_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new("unix-parent-mode");
        let parent_dir = dir.path().join("newly-created-parent");
        let prefs_path = parent_dir.join(GUI_PREFS_FILE_NAME);

        save_gui_preferences_to_path(&prefs_path, &GuiPreferencesDto::default())
            .expect("save prefs");

        let dir_mode = fs::metadata(&parent_dir)
            .expect("stat parent dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);

        let file_mode = fs::metadata(&prefs_path)
            .expect("stat prefs file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
    }

    #[test]
    fn load_corrupt_json_falls_back_to_defaults() {
        let dir = TestDir::new("corrupt");
        let prefs_path = dir.path().join(GUI_PREFS_FILE_NAME);

        let corrupt_payloads: &[&[u8]] = &[
            b"",
            b"   \n\t  ",
            b"{not valid json",
            b"{\"theme\": \"dark\"",
            b"[1, 2, 3]",
            b"\"just a string\"",
            b"{\"theme\": \"neon\"}",
            b"{\"minimizeToTray\": \"yes\"}",
            &[0xff, 0xfe, 0x00, 0x80],
        ];

        for payload in corrupt_payloads {
            fs::write(&prefs_path, payload).expect("write corrupt payload");
            let loaded = load_gui_preferences_from_path(&prefs_path);
            assert_eq!(loaded, GuiPreferencesDto::default());
        }
    }

    #[test]
    fn load_partial_json_fills_missing_fields_from_defaults() {
        let dir = TestDir::new("partial");
        let prefs_path = dir.path().join(GUI_PREFS_FILE_NAME);
        fs::write(&prefs_path, br#"{"theme":"dark","minimizeToTray":true}"#)
            .expect("write partial prefs");

        let loaded = load_gui_preferences_from_path(&prefs_path);
        assert_eq!(
            loaded,
            GuiPreferencesDto {
                theme: ThemePreferenceDto::Dark,
                language: LanguagePreferenceDto::System,
                keep_in_tray_on_close: false,
                minimize_to_tray: true,
                start_minimized_to_tray: false,
                show_taskbar_icon_when_minimized: false,
            }
        );
    }

    #[test]
    fn load_oversized_file_falls_back_to_defaults() {
        let dir = TestDir::new("oversized");
        let prefs_path = dir.path().join(GUI_PREFS_FILE_NAME);
        let oversized = format!(
            "{{\"theme\":\"dark\",\"padding\":\"{}\"}}",
            "a".repeat(MAX_GUI_PREFS_BYTES + 64)
        );
        fs::write(&prefs_path, oversized).expect("write oversized prefs");

        let loaded = load_gui_preferences_from_path(&prefs_path);
        assert_eq!(loaded, GuiPreferencesDto::default());
    }

    #[test]
    fn load_directory_path_falls_back_to_defaults() {
        let dir = TestDir::new("dir-as-file");
        let loaded = load_gui_preferences_from_path(dir.path());
        assert_eq!(loaded, GuiPreferencesDto::default());
    }

    #[test]
    fn parent_traversal_path_is_rejected_on_load_and_save() {
        let dir = TestDir::new("traversal");
        let nested = dir.path().join("sub");
        fs::create_dir_all(&nested).expect("create nested dir");
        let real_prefs = dir.path().join(GUI_PREFS_FILE_NAME);
        fs::write(&real_prefs, br#"{"theme":"dark"}"#).expect("write real prefs");

        let traversal_path = nested.join("..").join(GUI_PREFS_FILE_NAME);
        assert_eq!(
            load_gui_preferences_from_path(&traversal_path),
            GuiPreferencesDto::default()
        );
        assert!(
            save_gui_preferences_to_path(&traversal_path, &GuiPreferencesDto::default()).is_err()
        );
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

    #[cfg(unix)]
    #[test]
    fn load_and_save_reject_symlink_file_and_parent_on_unix() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("unix-symlink");
        let target_file = dir.path().join("real-target.json");
        fs::write(&target_file, br#"{"theme":"dark","minimizeToTray":true}"#)
            .expect("write target file");

        let link_file = dir.path().join(GUI_PREFS_FILE_NAME);
        symlink(&target_file, &link_file).expect("create file symlink");

        // Loading through a symlink must refuse and return defaults.
        assert_eq!(
            load_gui_preferences_from_path(&link_file),
            GuiPreferencesDto::default()
        );

        // Saving onto a symlink must fail and leave the target untouched.
        let new_prefs = GuiPreferencesDto {
            theme: ThemePreferenceDto::Light,
            ..GuiPreferencesDto::default()
        };
        assert!(save_gui_preferences_to_path(&link_file, &new_prefs).is_err());
        assert_eq!(
            fs::read_to_string(&target_file).expect("read target after rejected save"),
            r#"{"theme":"dark","minimizeToTray":true}"#
        );

        // Symlinked parent directory (direct and ancestor) must be rejected on load and save.
        let real_dir = dir.path().join("real-dir");
        fs::create_dir_all(&real_dir).expect("create real dir");
        fs::write(real_dir.join(GUI_PREFS_FILE_NAME), br#"{"theme":"dark"}"#)
            .expect("write prefs inside real dir");
        let link_dir = dir.path().join("link-dir");
        symlink(&real_dir, &link_dir).expect("create dir symlink");

        assert_eq!(
            load_gui_preferences_from_path(&link_dir.join(GUI_PREFS_FILE_NAME)),
            GuiPreferencesDto::default()
        );
        assert!(
            save_gui_preferences_to_path(&link_dir.join(GUI_PREFS_FILE_NAME), &new_prefs).is_err()
        );
        assert!(save_gui_preferences_to_path(
            &link_dir.join("nested").join(GUI_PREFS_FILE_NAME),
            &new_prefs
        )
        .is_err());
        assert!(!real_dir.join("nested").exists());

        // Matched root env dir itself and absolute paths outside known roots must be checked.
        assert!(check_ancestors_under_roots(&link_dir, std::slice::from_ref(&link_dir)).is_err());
        assert!(check_ancestors_under_roots(
            &link_dir.join("nested"),
            std::slice::from_ref(&link_dir)
        )
        .is_err());
        assert!(check_ancestors_under_roots(&link_dir.join("nested"), &[]).is_err());
        let canon_real = fs::canonicalize(&real_dir).expect("canonicalize real dir");
        assert!(check_ancestors_under_roots(&canon_real, &[]).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_fifo_and_symlink_to_fifo_without_blocking_on_unix() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("unix-fifo");
        let fifo_path = dir.path().join("prefs.fifo");
        let c_path = CString::new(fifo_path.as_os_str().as_bytes()).expect("CString fifo path");
        // SAFETY: `c_path` is a valid NUL-terminated path passed to POSIX `mkfifo`.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600 as libc::mode_t) };
        assert_eq!(rc, 0, "mkfifo should succeed");

        let link_to_fifo = dir.path().join(GUI_PREFS_FILE_NAME);
        symlink(&fifo_path, &link_to_fifo).expect("symlink to fifo");

        // Neither the FIFO nor a symlink to the FIFO may block startup.
        assert_eq!(
            load_gui_preferences_from_path(&fifo_path),
            GuiPreferencesDto::default()
        );
        assert_eq!(
            load_gui_preferences_from_path(&link_to_fifo),
            GuiPreferencesDto::default()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_reparse_point_and_retry_helpers_behave_as_expected() {
        use std::os::windows::process::CommandExt;
        use std::process::Command;
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
        };

        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        assert!(platform_fs::is_reparse_point_attrs(
            FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(platform_fs::is_reparse_point_attrs(
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        ));
        assert!(!platform_fs::is_reparse_point_attrs(
            FILE_ATTRIBUTE_DIRECTORY
        ));
        assert!(!platform_fs::is_reparse_point_attrs(
            INVALID_FILE_ATTRIBUTES
        ));

        assert!(platform_fs::is_retryable_rename_error(&std::io::Error::new(
            ErrorKind::PermissionDenied,
            "av lock"
        )));
        assert!(platform_fs::is_retryable_rename_error(
            &std::io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32)
        ));
        assert!(platform_fs::is_retryable_rename_error(
            &std::io::Error::from_raw_os_error(ERROR_LOCK_VIOLATION as i32)
        ));
        assert!(platform_fs::is_retryable_rename_error(
            &std::io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)
        ));
        assert!(!platform_fs::is_retryable_rename_error(&std::io::Error::new(
            ErrorKind::NotFound,
            "missing"
        )));

        let dir = TestDir::new("win-reparse");
        let real_dir = dir.path().join("real-dir");
        fs::create_dir_all(&real_dir).expect("create real dir");
        let real_prefs = real_dir.join(GUI_PREFS_FILE_NAME);
        fs::write(&real_prefs, br#"{"theme":"dark","minimizeToTray":true}"#)
            .expect("write real prefs");

        let cmd_exe = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .filter(|v| !v.is_empty())
            .map(|root| PathBuf::from(root).join("System32").join("cmd.exe"))
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
        let junction_dir = dir.path().join("junction-dir");
        let status = Command::new(cmd_exe)
            .creation_flags(CREATE_NO_WINDOW)
            .args([
                OsStr::new("/C"),
                OsStr::new("mklink"),
                OsStr::new("/J"),
                junction_dir.as_os_str(),
                real_dir.as_os_str(),
            ])
            .status()
            .expect("spawn cmd.exe mklink /J");
        assert!(status.success(), "mklink /J must create directory junction");

        // Loading and saving through an NTFS junction (direct or ancestor) must be rejected.
        assert_eq!(
            load_gui_preferences_from_path(&junction_dir.join(GUI_PREFS_FILE_NAME)),
            GuiPreferencesDto::default()
        );
        let new_prefs = GuiPreferencesDto {
            theme: ThemePreferenceDto::Light,
            ..GuiPreferencesDto::default()
        };
        assert!(
            save_gui_preferences_to_path(&junction_dir.join(GUI_PREFS_FILE_NAME), &new_prefs)
                .is_err()
        );
        assert!(save_gui_preferences_to_path(
            &junction_dir.join("nested").join(GUI_PREFS_FILE_NAME),
            &new_prefs
        )
        .is_err());
        assert!(!real_dir.join("nested").exists());

        // Matched root env dir itself and absolute paths outside known roots must be checked.
        assert!(
            check_ancestors_under_roots(&junction_dir, std::slice::from_ref(&junction_dir))
                .is_err()
        );
        assert!(check_ancestors_under_roots(
            &junction_dir.join("nested"),
            std::slice::from_ref(&junction_dir)
        )
        .is_err());
        assert!(check_ancestors_under_roots(&junction_dir.join("nested"), &[]).is_err());
        assert!(check_ancestors_under_roots(&real_dir, &[]).is_ok());

        // If the host allows unprivileged file symlinks (Developer Mode / elevated), verify
        // direct file symlink rejection as well.
        let file_symlink = dir.path().join("symlink-prefs.json");
        if std::os::windows::fs::symlink_file(&real_prefs, &file_symlink).is_ok() {
            assert_eq!(
                load_gui_preferences_from_path(&file_symlink),
                GuiPreferencesDto::default()
            );
            assert!(save_gui_preferences_to_path(&file_symlink, &new_prefs).is_err());
            let _ = fs::remove_file(&file_symlink);
        }

        let _ = fs::remove_dir(&junction_dir);
    }
}
