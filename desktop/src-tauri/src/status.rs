#[cfg(any(target_os = "windows", test))]
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(target_os = "windows", test))]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;
use vdpi::config_file::{self, FileConfig};
use vdpi::health::DEFAULT_TUN_HEALTH_PORT;
use vdpi::platform::vpn::{detect_active_vpn, VpnScope};
use vdpi::service::{self, LiveEngineStatus, RuntimeState, ServiceState};
use vdpi::update::{compare_versions, VersionRelation};
use vdpi_core::config::{EngineMode, RuntimeConfig, VpnCoexistence};
use vdpi_core::dns;

use crate::models::{
    CliVersionRelationDto, DesktopSettingsPayloadDto, DesktopStatusSnapshotDto, GuiPreferencesDto,
    LiveTelemetryDto, ServiceStateDto, WintunStatusDto,
};
use crate::state::{
    engine_mode_to_dto, service_state_to_dto, split_tunnel_mode_to_dto, vpn_coexistence_to_dto,
    BinaryFileMetadata, DesktopAppState, StaticProbeEntry,
};

#[cfg(any(target_os = "windows", test))]
const WINTUN_MISSING_MESSAGE: &str = "wintun.dll is missing - reinstall vdpi Desktop, extract all files from the zip, or check Windows Defender quarantine.";

#[cfg(any(target_os = "windows", test))]
const WINTUN_HASH_MISMATCH_MESSAGE: &str = "wintun.dll failed SHA-256 hash verification (file may be corrupted or tampered) - reinstall vdpi Desktop or replace wintun.dll from an official release.";

/// Detailed Windows Wintun preflight result distinguishing a missing DLL from
/// an existing DLL that failed SHA-256 verification.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WintunPreflightResult {
    Ready,
    Missing(String),
    Invalid(String),
}

const LIVE_PROBE_BUDGET: Duration = Duration::from_millis(500);

/// Returns the normalized desktop platform tag (`"windows"`, `"macos"`, or `"linux"`).
pub fn current_platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        "linux"
    }
}

/// Probes whether a SHA-256-verified `wintun.dll` is present on disk using
/// purely read-only filesystem checks (never materializing embedded DLLs,
/// touching the network, or querying OS service managers).
///
/// - On non-Windows platforms, Wintun is not required and always reports ready.
/// - On Windows, resolves Program Files / ProgramData via Known Folder APIs
///   (never mutable `%ProgramFiles%` or user `%TEMP%`/`%LOCALAPPDATA%`),
///   rejects ancestor NTFS junctions/reparse points before hashing, and fails
///   closed if a primary candidate exists on disk with a bad SHA-256.
pub fn probe_wintun_status(configured_engine: EngineMode) -> WintunStatusDto {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = configured_engine;
        WintunStatusDto {
            required: false,
            ready: true,
            message: None,
        }
    }

    #[cfg(target_os = "windows")]
    {
        let outcome = probe_wintun_preflight(false);
        wintun_outcome_to_status_dto(configured_engine == EngineMode::Tun, outcome)
    }
}

/// Runs a strict read-only Windows Wintun preflight returning [`WintunPreflightResult`]
/// so callers can distinguish missing DLLs (`WintunMissing`) from corrupted/tampered
/// DLLs (`WintunInvalid`). Never falls back to standard-user `%TEMP%`/`%LOCALAPPDATA%`.
#[cfg(target_os = "windows")]
pub(crate) fn probe_wintun_preflight(service_installed_runtime: bool) -> WintunPreflightResult {
    let Ok(expected_sha256) = vdpi::platform::windows_tun::expected_wintun_dll_sha256() else {
        return WintunPreflightResult::Missing(WINTUN_MISSING_MESSAGE.to_string());
    };
    let (primaries, candidates) = if service_installed_runtime {
        collect_windows_service_wintun_candidates()
    } else {
        collect_windows_bundle_wintun_candidates()
    };
    let existing_files = snapshot_existing_wintun_metadata(&candidates);
    evaluate_wintun_outcome_with(&primaries, &existing_files, |path| {
        vdpi::platform::windows_tun::verify_wintun_dll_sha256(path, expected_sha256).is_ok()
    })
}

fn probe_wintun_status_cached(
    state: &DesktopAppState,
    configured_engine: EngineMode,
    service_state: ServiceState,
) -> WintunStatusDto {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (state, configured_engine, service_state);
        WintunStatusDto {
            required: false,
            ready: true,
            message: None,
        }
    }

    #[cfg(target_os = "windows")]
    {
        match vdpi::platform::windows_tun::expected_wintun_dll_sha256() {
            Ok(expected_sha256) => {
                if service_state != ServiceState::NotInstalled {
                    let (primaries, candidates) = collect_windows_service_wintun_candidates();
                    evaluate_wintun_candidates_cached_with_primaries(
                        state,
                        configured_engine,
                        &primaries,
                        &candidates,
                        true,
                        |path| {
                            vdpi::platform::windows_tun::verify_wintun_dll_sha256(
                                path,
                                expected_sha256,
                            )
                            .is_ok()
                        },
                    )
                } else {
                    let (primaries, candidates) = collect_windows_bundle_wintun_candidates();
                    evaluate_wintun_candidates_cached_with_primaries(
                        state,
                        configured_engine,
                        &primaries,
                        &candidates,
                        false,
                        |path| {
                            vdpi::platform::windows_tun::verify_wintun_dll_sha256(
                                path,
                                expected_sha256,
                            )
                            .is_ok()
                        },
                    )
                }
            }
            Err(_) => WintunStatusDto {
                required: configured_engine == EngineMode::Tun,
                ready: false,
                message: Some(WINTUN_MISSING_MESSAGE.to_string()),
            },
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn push_unique_candidate(candidates: &mut Vec<PathBuf>, path: PathBuf) {
    if !candidates.contains(&path) {
        candidates.push(path);
    }
}

#[cfg(any(target_os = "windows", test))]
fn is_unc_or_device_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    let bytes = raw.as_bytes();
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let rb = rest.as_bytes();
        if rb.len() >= 4
            && rest[..3].eq_ignore_ascii_case("UNC")
            && matches!(rb[3], b'\\' | b'/')
        {
            return true;
        }
        let is_drive = rb.len() >= 3
            && rb[0].is_ascii_alphabetic()
            && rb[1] == b':'
            && matches!(rb[2], b'\\' | b'/');
        return !is_drive;
    }
    if raw.starts_with(r"\\.\") || raw.starts_with("//./") {
        return true;
    }
    bytes.len() >= 2 && matches!(bytes[0], b'\\' | b'/') && matches!(bytes[1], b'\\' | b'/')
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
fn program_dir_from_system_drive(system_drive: &OsStr, folder_name: &str) -> Option<PathBuf> {
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
    Some(PathBuf::from(format!(r"{drive}:\{folder_name}")))
}

#[cfg(target_os = "windows")]
fn query_windows_known_folder(folder_id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

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
    // SAFETY: `folder_id` is a valid GUID reference; `raw_ptr` is a valid out-pointer.
    let hr = unsafe { SHGetKnownFolderPath(folder_id, 0, 0, &mut raw_ptr) };
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
fn sanitize_known_windows_dir(dir: PathBuf) -> Option<PathBuf> {
    let clean = vdpi::update::strip_windows_verbatim_prefix(&dir);
    if clean.as_os_str().is_empty()
        || is_unc_or_device_path(&clean)
        || !is_local_drive_absolute(&clean)
        || clean.components().any(|c| matches!(c, Component::ParentDir))
    {
        return None;
    }
    Some(clean)
}

#[cfg(any(target_os = "windows", test))]
fn resolve_windows_program_files_dir_from(
    known_program_files: Option<PathBuf>,
    system_drive: Option<&OsStr>,
) -> PathBuf {
    if let Some(pf) = known_program_files.and_then(sanitize_known_windows_dir) {
        return pf;
    }
    if let Some(pf) = system_drive.and_then(|d| program_dir_from_system_drive(d, "Program Files")) {
        return pf;
    }
    PathBuf::from(r"C:\Program Files")
}

#[cfg(any(target_os = "windows", test))]
fn resolve_windows_program_data_dir_from(
    known_program_data: Option<PathBuf>,
    system_drive: Option<&OsStr>,
) -> PathBuf {
    if let Some(pd) = known_program_data.and_then(sanitize_known_windows_dir) {
        return pd;
    }
    if let Some(pd) = system_drive.and_then(|d| program_dir_from_system_drive(d, "ProgramData")) {
        return pd;
    }
    PathBuf::from(r"C:\ProgramData")
}

#[cfg(target_os = "windows")]
fn trusted_windows_program_files_dir() -> PathBuf {
    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles;
    resolve_windows_program_files_dir_from(
        query_windows_known_folder(&FOLDERID_ProgramFiles),
        std::env::var_os("SystemDrive").as_deref(),
    )
}

#[cfg(target_os = "windows")]
fn trusted_windows_program_data_dir() -> PathBuf {
    use windows_sys::Win32::UI::Shell::FOLDERID_ProgramData;
    resolve_windows_program_data_dir_from(
        query_windows_known_folder(&FOLDERID_ProgramData),
        std::env::var_os("SystemDrive").as_deref(),
    )
}

#[cfg(target_os = "windows")]
fn collect_windows_bundle_wintun_candidates() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut primaries = Vec::new();
    let mut candidates = Vec::new();

    if let Ok(bundled_cli) = crate::sidecar::resolve_bundled_vdpi_cli_binary() {
        collect_wintun_candidates_for_exe(&mut primaries, &bundled_cli);
    }

    if let Ok(current_exe) = std::env::current_exe() {
        collect_wintun_candidates_for_exe(&mut primaries, &current_exe);
    }

    if let Some(res_dir) =
        crate::sidecar::registered_resource_dir().filter(|dir| !is_unc_or_device_path(dir))
    {
        push_unique_candidate(&mut primaries, res_dir.join("wintun.dll"));
        push_unique_candidate(&mut primaries, res_dir.join("resources").join("wintun.dll"));
    }

    let pf = trusted_windows_program_files_dir();
    push_unique_candidate(
        &mut primaries,
        pf.join("vdpi").join("bin").join("wintun.dll"),
    );

    for path in &primaries {
        push_unique_candidate(&mut candidates, path.clone());
    }

    // Secondary system-only runtime cache (never standard-user %TEMP% or %LOCALAPPDATA%).
    let runtime_dll = format!("wintun-{}.dll", vdpi::platform::windows_tun::WINTUN_VERSION);
    let pd = trusted_windows_program_data_dir();
    push_unique_candidate(
        &mut candidates,
        pd.join("vdpi").join("runtime").join(runtime_dll),
    );

    (primaries, candidates)
}

#[cfg(any(target_os = "windows", test))]
fn collect_service_wintun_candidates(
    installed_bin: Option<&Path>,
    program_files: Option<&Path>,
    program_data: Option<&Path>,
    runtime_dll_name: &str,
) -> (Option<PathBuf>, Vec<PathBuf>) {
    let mut candidates = Vec::new();
    let mut primary_installed = None;

    if let Some(installed) = installed_bin {
        let canonical = std::fs::canonicalize(installed).ok();
        for candidate in vdpi::platform::windows_tun::resolve_wintun_dll_candidates(
            installed,
            canonical.as_deref(),
        ) {
            if primary_installed.is_none() {
                primary_installed = Some(candidate.clone());
            }
            push_unique_candidate(&mut candidates, candidate);
        }
    }

    if let Some(pf) = program_files.filter(|p| !p.as_os_str().is_empty()) {
        let pf_dll = pf.join("vdpi").join("bin").join("wintun.dll");
        if primary_installed.is_none() {
            primary_installed = Some(pf_dll.clone());
        }
        push_unique_candidate(&mut candidates, pf_dll);
    }

    if let Some(pd) = program_data.filter(|p| !p.as_os_str().is_empty()) {
        push_unique_candidate(
            &mut candidates,
            pd.join("vdpi").join("runtime").join(runtime_dll_name),
        );
    }

    (primary_installed, candidates)
}

#[cfg(target_os = "windows")]
fn collect_windows_service_wintun_candidates() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let program_files = trusted_windows_program_files_dir();
    let installed_bin = program_files.join("vdpi").join("bin").join("vdpi.exe");
    let program_data = trusted_windows_program_data_dir();
    let runtime_dll = format!("wintun-{}.dll", vdpi::platform::windows_tun::WINTUN_VERSION);
    let (primary_installed, candidates) = collect_service_wintun_candidates(
        Some(installed_bin.as_path()),
        Some(program_files.as_path()),
        Some(program_data.as_path()),
        &runtime_dll,
    );
    let primaries = primary_installed.into_iter().collect();
    (primaries, candidates)
}

#[cfg(any(target_os = "windows", test))]
fn collect_wintun_candidates_for_exe(candidates: &mut Vec<PathBuf>, exe_path: &Path) {
    let canonical = std::fs::canonicalize(exe_path).ok();
    for candidate in
        vdpi::platform::windows_tun::resolve_wintun_dll_candidates(exe_path, canonical.as_deref())
    {
        let resources_candidate = candidate
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .map(|dir| dir.join("resources").join("wintun.dll"));
        push_unique_candidate(candidates, candidate);
        if let Some(res_path) = resources_candidate {
            push_unique_candidate(candidates, res_path);
        }
    }
}

#[cfg(test)]
fn collect_wintun_candidates(
    installed_bin: Option<&Path>,
    current_exe: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(installed) = installed_bin {
        collect_wintun_candidates_for_exe(&mut candidates, installed);
    }
    if let Some(exe) = current_exe {
        collect_wintun_candidates_for_exe(&mut candidates, exe);
    }
    candidates
}

#[cfg(all(unix, test))]
fn is_allowed_unix_os_symlink(path: &Path, meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    if meta.uid() != 0 {
        return false;
    }
    matches!(
        path.to_str(),
        Some("/var" | "/tmp" | "/etc" | "/home" | "/usr/local")
    )
}

/// Walks every path component from root/prefix down to `path` and rejects
/// UNC/device paths, parent traversal (`..`), symlinks, and Windows NTFS
/// junctions/reparse points BEFORE opening or hashing `wintun.dll`.
#[cfg(any(target_os = "windows", test))]
fn verify_wintun_path_no_reparse_or_symlink(path: &Path) -> bool {
    let clean = vdpi::update::strip_windows_verbatim_prefix(path);
    #[cfg(windows)]
    if is_unc_or_device_path(&clean) {
        return false;
    }

    let components: Vec<Component<'_>> = clean.components().collect();
    let last_normal_idx = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));
    let Some(last_idx) = last_normal_idx else {
        return false;
    };

    let mut current = PathBuf::new();
    for (idx, comp) in components.iter().enumerate() {
        match comp {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(comp.as_os_str()),
            Component::CurDir => continue,
            Component::ParentDir => return false,
            Component::Normal(seg) => {
                current.push(seg);
                let Ok(meta) = std::fs::symlink_metadata(&current) else {
                    return false;
                };
                #[cfg(windows)]
                let is_link = {
                    use std::os::windows::fs::MetadataExt;
                    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
                    meta.file_type().is_symlink()
                        || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
                };
                #[cfg(not(windows))]
                let is_link = meta.file_type().is_symlink();

                if is_link {
                    #[cfg(all(unix, test))]
                    if idx != last_idx
                        && is_allowed_unix_os_symlink(&current, &meta)
                        && std::fs::metadata(&current).is_ok_and(|target| target.is_dir())
                    {
                        continue;
                    }
                    return false;
                }
                if idx != last_idx {
                    if !meta.is_dir() {
                        return false;
                    }
                } else if !meta.is_file() {
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(any(target_os = "windows", test))]
fn snapshot_existing_wintun_metadata(candidates: &[PathBuf]) -> Vec<BinaryFileMetadata> {
    candidates
        .iter()
        .filter(|path| verify_wintun_path_no_reparse_or_symlink(path))
        .filter_map(|path| BinaryFileMetadata::from_regular_file(path))
        .collect()
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_outcome_with<FVerify>(
    primary_paths: &[PathBuf],
    existing_files: &[BinaryFileMetadata],
    verify_sha256: FVerify,
) -> WintunPreflightResult
where
    FVerify: Fn(&Path) -> bool,
{
    if existing_files.is_empty() {
        return WintunPreflightResult::Missing(WINTUN_MISSING_MESSAGE.to_string());
    }

    // Fail closed on the first existing primary candidate in load-precedence order:
    // if a primary bundled/installed `wintun.dll` exists on disk but fails SHA-256
    // verification, never fall through to secondary locations.
    for primary_path in primary_paths {
        if let Some(primary_meta) = existing_files.iter().find(|f| f.path == *primary_path) {
            if primary_meta.len == 0 || !verify_sha256(&primary_meta.path) {
                return WintunPreflightResult::Invalid(WINTUN_HASH_MISMATCH_MESSAGE.to_string());
            }
            return WintunPreflightResult::Ready;
        }
    }

    if existing_files
        .iter()
        .any(|file| file.len > 0 && verify_sha256(&file.path))
    {
        WintunPreflightResult::Ready
    } else {
        WintunPreflightResult::Invalid(WINTUN_HASH_MISMATCH_MESSAGE.to_string())
    }
}

#[cfg(any(target_os = "windows", test))]
fn wintun_outcome_to_status_dto(
    required: bool,
    outcome: WintunPreflightResult,
) -> WintunStatusDto {
    match outcome {
        WintunPreflightResult::Ready => WintunStatusDto {
            required,
            ready: true,
            message: None,
        },
        WintunPreflightResult::Missing(msg) | WintunPreflightResult::Invalid(msg) => {
            WintunStatusDto {
                required,
                ready: false,
                message: Some(msg),
            }
        }
    }
}

#[cfg(test)]
fn evaluate_wintun_candidates_with_sha256(
    configured_engine: EngineMode,
    candidates: &[PathBuf],
    expected_sha256: &str,
) -> WintunStatusDto {
    let required = configured_engine == EngineMode::Tun;
    let existing_files = snapshot_existing_wintun_metadata(candidates);
    let outcome = evaluate_wintun_outcome_with(&[], &existing_files, |path| {
        vdpi::platform::windows_tun::verify_wintun_dll_sha256(path, expected_sha256).is_ok()
    });
    wintun_outcome_to_status_dto(required, outcome)
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_wintun_candidates_cached_with_primaries<FVerify>(
    state: &DesktopAppState,
    configured_engine: EngineMode,
    primary_paths: &[PathBuf],
    candidates: &[PathBuf],
    strict_primary: bool,
    verify_sha256: FVerify,
) -> WintunStatusDto
where
    FVerify: Fn(&Path) -> bool,
{
    let required = configured_engine == EngineMode::Tun;
    let existing_files = snapshot_existing_wintun_metadata(candidates);

    if let Some(cached) =
        state.cached_wintun_status_with_mode(&existing_files, required, strict_primary)
    {
        return cached;
    }

    let outcome = evaluate_wintun_outcome_with(primary_paths, &existing_files, verify_sha256);
    let result = wintun_outcome_to_status_dto(required, outcome);
    state.set_cached_wintun_status_with_mode(existing_files, result.clone(), strict_primary);
    result
}

#[cfg(test)]
fn evaluate_wintun_candidates_cached_with<FVerify>(
    state: &DesktopAppState,
    configured_engine: EngineMode,
    candidates: &[PathBuf],
    verify_sha256: FVerify,
) -> WintunStatusDto
where
    FVerify: Fn(&Path) -> bool,
{
    evaluate_wintun_candidates_cached_with_primaries(
        state,
        configured_engine,
        &[],
        candidates,
        false,
        verify_sha256,
    )
}

#[cfg(test)]
fn evaluate_service_wintun_candidates_cached_with<FVerify>(
    state: &DesktopAppState,
    configured_engine: EngineMode,
    primary_installed_path: Option<&Path>,
    candidates: &[PathBuf],
    verify_sha256: FVerify,
) -> WintunStatusDto
where
    FVerify: Fn(&Path) -> bool,
{
    let primaries: Vec<PathBuf> = primary_installed_path
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    evaluate_wintun_candidates_cached_with_primaries(
        state,
        configured_engine,
        &primaries,
        candidates,
        true,
        verify_sha256,
    )
}

fn is_system_service_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        service::systemd_system_unit_path().exists()
    }
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::query_windows_service_status().installed
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

fn system_service_installed_from_service_state(service_state: ServiceState) -> bool {
    #[cfg(target_os = "windows")]
    {
        service_state != ServiceState::NotInstalled
    }
    #[cfg(target_os = "macos")]
    {
        let _ = service_state;
        service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        let _ = service_state;
        service::systemd_system_unit_path().exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = service_state;
        false
    }
}

fn default_engine_for_service_mode(system_service_installed: bool) -> EngineMode {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if system_service_installed {
        return EngineMode::Tun;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = system_service_installed;
    RuntimeConfig::default().engine
}

struct EffectiveFileConfigLoad {
    path: PathBuf,
    config: FileConfig,
    warning: Option<String>,
}

fn redact_config_error(err: &anyhow::Error) -> String {
    dns::redact_urls_in_text(&format!("{err:#}"))
}

fn format_config_parse_warning(path: &Path, redacted_error: &str, fallback_desc: &str) -> String {
    format!(
        "Failed to parse {}: {redacted_error} ({fallback_desc})",
        path.display()
    )
}

fn load_effective_file_config_from_paths(
    system_service_installed: bool,
    sys_path: &Path,
    user_path: &Path,
) -> EffectiveFileConfigLoad {
    if system_service_installed {
        return match config_file::load_file_config_or_default(Some(sys_path), true) {
            Ok((_, cfg)) => EffectiveFileConfigLoad {
                path: sys_path.to_path_buf(),
                config: cfg,
                warning: None,
            },
            Err(err) => {
                let redacted = redact_config_error(&err);
                warn!(
                    path = %sys_path.display(),
                    error = %redacted,
                    "failed to load system config.toml; falling back to defaults"
                );
                EffectiveFileConfigLoad {
                    path: sys_path.to_path_buf(),
                    config: FileConfig::default(),
                    warning: Some(format_config_parse_warning(
                        sys_path,
                        &redacted,
                        "using default settings",
                    )),
                }
            }
        };
    }

    let mut user_warning = None;
    match config_file::load_file_config_or_default(Some(user_path), false) {
        Ok((Some(path), cfg)) => {
            return EffectiveFileConfigLoad {
                path,
                config: cfg,
                warning: None,
            };
        }
        Ok((None, _)) => {}
        Err(err) => {
            let redacted = redact_config_error(&err);
            warn!(
                path = %user_path.display(),
                error = %redacted,
                "failed to load user config.toml; checking system config fallback"
            );
            user_warning = Some(format_config_parse_warning(
                user_path,
                &redacted,
                "using fallback settings",
            ));
        }
    }

    match config_file::load_file_config_or_default(Some(sys_path), true) {
        Ok((Some(path), cfg)) => EffectiveFileConfigLoad {
            path,
            config: cfg,
            warning: user_warning,
        },
        Ok((None, _)) => EffectiveFileConfigLoad {
            path: user_path.to_path_buf(),
            config: FileConfig::default(),
            warning: user_warning,
        },
        Err(err) => {
            let redacted = redact_config_error(&err);
            warn!(
                path = %sys_path.display(),
                error = %redacted,
                "failed to load fallback system config.toml; falling back to defaults"
            );
            let warning = user_warning.or_else(|| {
                Some(format_config_parse_warning(
                    sys_path,
                    &redacted,
                    "using default settings",
                ))
            });
            EffectiveFileConfigLoad {
                path: user_path.to_path_buf(),
                config: FileConfig::default(),
                warning,
            }
        }
    }
}

/// Returns the active `config.toml` path for the current installation state.
pub fn active_config_path() -> PathBuf {
    let sys_path = config_file::system_config_path();
    if is_system_service_installed() {
        return sys_path;
    }
    let user_path = config_file::user_config_path();
    if user_path.is_file() {
        user_path
    } else if sys_path.is_file() {
        sys_path
    } else {
        user_path
    }
}

fn default_user_logs_dir() -> PathBuf {
    service::vdpi_root_dir()
        .map(|root| root.join("logs"))
        .unwrap_or_else(|_| {
            config_file::user_config_path()
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|dir| dir.join("logs"))
                .unwrap_or_else(|| PathBuf::from("logs"))
        })
}

fn resolve_logs_dir_for_platform(
    platform: &str,
    system_service_installed: bool,
    default_user_logs: PathBuf,
    linux_system_candidates: &[PathBuf],
) -> PathBuf {
    if system_service_installed {
        match platform {
            "macos" => return PathBuf::from("/var/log"),
            "linux" => {
                for candidate in linux_system_candidates {
                    if candidate.is_dir() {
                        return candidate.clone();
                    }
                }
                return default_user_logs;
            }
            _ => {}
        }
    }
    default_user_logs
}

fn default_logs_dir_for_service_mode(system_service_installed: bool) -> PathBuf {
    let user_logs = default_user_logs_dir();
    let linux_candidates = [
        PathBuf::from("/var/log/vdpi"),
        user_logs.clone(),
        PathBuf::from("/var/log"),
    ];
    resolve_logs_dir_for_platform(
        current_platform(),
        system_service_installed,
        user_logs,
        &linux_candidates,
    )
}

/// Returns the default directory where `vdpi` stores service/runtime logs.
///
/// On macOS LaunchDaemon mode this returns `/var/log`; on Linux systemd
/// system-service mode it returns the first existing logs directory among
/// `/var/log/vdpi`, `~/.vdpi/logs`, and `/var/log`; otherwise `~/.vdpi/logs`
/// (or `%ProgramFiles%\vdpi\logs` on Windows).
pub fn default_logs_dir() -> PathBuf {
    default_logs_dir_for_service_mode(is_system_service_installed())
}

fn is_custom_doh_url(dns_addr: &str) -> bool {
    dns::validate_custom_dns_input(dns_addr)
        .is_ok_and(|normalized| normalized.starts_with("https://"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FastProbeCandidate {
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
}

fn probe_connect_ip(addr: IpAddr) -> Option<IpAddr> {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        IpAddr::V6(v6) if v6.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ip if ip.is_loopback() => Some(ip),
        _ => None,
    }
}

fn build_fast_probe_candidates(
    cfg: &RuntimeConfig,
    states: &[RuntimeState],
) -> Vec<FastProbeCandidate> {
    let cfg_connect_ip = probe_connect_ip(cfg.addr);
    let primary_socks = states
        .iter()
        .find(|s| {
            s.port == cfg.port
                && (s.addr == cfg.addr
                    || cfg_connect_ip.is_some_and(|ip| probe_connect_ip(s.addr) == Some(ip)))
        })
        .map_or(cfg.socks_port, |s| s.socks_port);

    let mut seen: Vec<(IpAddr, u16)> = Vec::new();
    let mut out = Vec::new();

    for (addr, port, socks_port) in states
        .iter()
        .map(|s| (s.addr, s.port, s.socks_port))
        .chain(std::iter::once((cfg.addr, cfg.port, primary_socks)))
        .chain(std::iter::once((
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            DEFAULT_TUN_HEALTH_PORT,
            None,
        )))
    {
        if port == 0 {
            continue;
        }
        let Some(connect_ip) = probe_connect_ip(addr) else {
            continue;
        };
        if seen.contains(&(connect_ip, port)) {
            continue;
        }
        seen.push((connect_ip, port));
        out.push(FastProbeCandidate {
            addr,
            port,
            socks_port,
        });
    }

    out
}

fn probe_live_engine_fast(cfg: &RuntimeConfig) -> Option<LiveEngineStatus> {
    let states = service::read_runtime_states();
    let deadline = Instant::now() + LIVE_PROBE_BUDGET;

    for candidate in build_fast_probe_candidates(cfg, &states) {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(status) = service::probe_live_engine(
            candidate.addr,
            candidate.port,
            candidate.socks_port.unwrap_or(0),
        ) {
            return Some(status);
        }
    }

    None
}

fn format_vpn_scope_conflict(scope: &VpnScope) -> Option<String> {
    match scope {
        VpnScope::FullTunnel {
            provider,
            iface,
            kill_switch,
        } => {
            let mut desc = if iface.trim().is_empty() {
                provider.clone()
            } else {
                format!("{provider} ({iface})")
            };
            if *kill_switch {
                desc.push_str(" [kill-switch]");
            }
            Some(desc)
        }
        VpnScope::None | VpnScope::SplitOverlay { .. } => None,
    }
}

fn detect_vpn_conflict_summary(self_tun_name: Option<&str>) -> Option<String> {
    let scope = detect_active_vpn(self_tun_name);
    format_vpn_scope_conflict(&scope)
}

fn compute_fallback_dns(file_cfg: &FileConfig, fallback: &str) -> String {
    let fallback_normalized =
        dns::validate_custom_dns_input(fallback).unwrap_or_else(|_| fallback.to_string());
    file_cfg
        .dns_addr
        .as_deref()
        .and_then(|raw| dns::validate_custom_dns_input(raw).ok())
        .unwrap_or(fallback_normalized)
}

fn locate_installed_binary_path() -> Option<PathBuf> {
    let installed = service::installed_binary_path().ok().filter(|p| p.is_file());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let sys_bin = PathBuf::from(service::UNIX_SYSTEM_BIN_PATH);
        #[cfg(target_os = "macos")]
        let has_system_daemon = service::launch_daemon_plist_path().exists();
        #[cfg(target_os = "linux")]
        let has_system_daemon = service::systemd_system_unit_path().exists();

        if has_system_daemon && sys_bin.is_file() {
            Some(sys_bin)
        } else {
            installed.or_else(|| sys_bin.is_file().then_some(sys_bin))
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        installed
    }
}

fn resolve_installed_version_with<FLocate, FProbe>(
    state: &DesktopAppState,
    locate_binary: FLocate,
    probe_version: FProbe,
) -> Option<String>
where
    FLocate: FnOnce() -> Option<PathBuf>,
    FProbe: FnOnce(&Path) -> Option<String>,
{
    let Some(binary_path) = locate_binary() else {
        state.clear_cached_installed_version();
        return None;
    };

    let Some(metadata) = BinaryFileMetadata::from_path(&binary_path) else {
        state.clear_cached_installed_version();
        return None;
    };

    if let Some(cached) = state.cached_installed_version(&metadata) {
        return cached;
    }

    let version = probe_version(&binary_path);
    if version.is_some() {
        state.set_cached_installed_version(metadata, version.clone());
    } else {
        state.clear_cached_installed_version();
    }
    version
}

fn resolve_installed_version_cached(state: &DesktopAppState) -> Option<String> {
    resolve_installed_version_with(state, locate_installed_binary_path, |_| {
        service::detect_installed_info().and_then(|info| info.installed_version)
    })
}

/// Quickly probes the running local daemon's health endpoint (bounded by
/// [`LIVE_PROBE_BUDGET`]) and returns its reported version, if reachable.
pub(crate) fn probe_live_version_quick(cfg: &RuntimeConfig) -> Option<String> {
    probe_live_engine_fast(cfg)
        .and_then(|live| live.version)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Detailed outcome of probing a bundled `vdpi` CLI binary via `--version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BundledVersionProbe {
    Version(String),
    Unparseable,
    LaunchFailed(String),
}

/// Probes the semantic version of a resolved bundled `vdpi` CLI binary by
/// invoking `<bin> --version` directly, preserving classified AV/Win32 launch
/// errors from `SidecarOutcome::Err` instead of collapsing them to `None`.
pub(crate) fn probe_bundled_cli_version_detailed(path: &Path) -> BundledVersionProbe {
    match crate::sidecar::run_resolved_vdpi_cli(path, &["--version"], 3, false) {
        crate::sidecar::SidecarOutcome::Ok(stdout) => {
            match service::parse_version_from_cli_output(&stdout) {
                Some(ver) => BundledVersionProbe::Version(ver),
                None => BundledVersionProbe::Unparseable,
            }
        }
        crate::sidecar::SidecarOutcome::Err(err) => BundledVersionProbe::LaunchFailed(err),
        crate::sidecar::SidecarOutcome::SavedNeedsRestart(_)
        | crate::sidecar::SidecarOutcome::Cancelled => BundledVersionProbe::Unparseable,
    }
}

/// Probes the semantic version of a resolved bundled `vdpi` CLI binary by
/// invoking `<bin> --version` directly and parsing stdout via
/// [`vdpi::service::parse_version_from_cli_output`].
pub(crate) fn probe_bundled_cli_version(path: &Path) -> Option<String> {
    match probe_bundled_cli_version_detailed(path) {
        BundledVersionProbe::Version(ver) => Some(ver),
        BundledVersionProbe::Unparseable | BundledVersionProbe::LaunchFailed(_) => None,
    }
}

fn resolve_bundled_engine_with<FLocate, FProbe>(
    state: &DesktopAppState,
    locate_bundled: FLocate,
    probe_version: FProbe,
) -> (bool, Option<String>)
where
    FLocate: FnOnce() -> Option<PathBuf>,
    FProbe: FnOnce(&Path) -> Option<String>,
{
    let Some(binary_path) = locate_bundled() else {
        state.clear_cached_bundled_version();
        return (false, None);
    };

    let Some(metadata) = BinaryFileMetadata::from_path(&binary_path) else {
        state.clear_cached_bundled_version();
        return (false, None);
    };

    if let Some(cached) = state.cached_bundled_version(&metadata) {
        return (true, cached);
    }

    let version = probe_version(&binary_path);
    if version.is_some() {
        state.set_cached_bundled_version(metadata, version.clone());
    } else {
        state.clear_cached_bundled_version();
    }
    (true, version)
}

fn resolve_bundled_engine_cached(state: &DesktopAppState) -> (bool, Option<String>) {
    resolve_bundled_engine_with(
        state,
        || crate::sidecar::resolve_bundled_vdpi_cli_binary().ok(),
        probe_bundled_cli_version,
    )
}

#[cfg(target_os = "macos")]
fn is_path_on_readonly_mount(path: &Path) -> Option<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid NUL-terminated path and `stat` is a valid out-pointer.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), &mut stat) };
    if rc == 0 {
        Some((stat.f_flags & (libc::MNT_RDONLY as u32)) != 0)
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn is_macos_readonly_dmg_path_with(path: &Path, readonly_mount: Option<bool>) -> bool {
    let Some(raw) = path.to_str() else {
        return false;
    };
    if raw.contains("/AppTranslocation/") {
        return true;
    }
    if let Some(is_ro) = readonly_mount {
        return is_ro;
    }
    raw.starts_with("/Volumes/")
}

#[cfg(any(target_os = "macos", test))]
fn is_macos_readonly_dmg_path(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    let readonly_mount = is_path_on_readonly_mount(path);
    #[cfg(not(target_os = "macos"))]
    let readonly_mount = None;
    is_macos_readonly_dmg_path_with(path, readonly_mount)
}

fn detect_running_from_readonly_dmg() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::env::current_exe()
            .ok()
            .is_some_and(|exe| is_macos_readonly_dmg_path(&exe))
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn compute_cli_version_relation(
    service_state: ServiceStateDto,
    installed_version: Option<&str>,
    live_version: Option<&str>,
    bundled_engine_version: Option<&str>,
    can_install_from_bundle: bool,
) -> CliVersionRelationDto {
    if !can_install_from_bundle {
        return CliVersionRelationDto::BundledMissing;
    }
    if service_state == ServiceStateDto::NotInstalled {
        return CliVersionRelationDto::NotInstalled;
    }
    let Some(installed) = installed_version else {
        if service_state == ServiceStateDto::Running {
            if let (Some(live), Some(bundled)) = (live_version, bundled_engine_version) {
                if compare_versions(bundled, live) == VersionRelation::Older {
                    return CliVersionRelationDto::NewerInstalled;
                }
            }
        }
        return CliVersionRelationDto::RepairNeeded;
    };
    let Some(bundled) = bundled_engine_version else {
        return CliVersionRelationDto::Unknown;
    };
    match compare_versions(bundled, installed) {
        VersionRelation::Newer => CliVersionRelationDto::UpgradeAvailable,
        VersionRelation::Same => CliVersionRelationDto::UpToDate,
        VersionRelation::Older => CliVersionRelationDto::NewerInstalled,
        VersionRelation::Unknown => CliVersionRelationDto::Unknown,
    }
}

fn compute_live_version_stale(
    installed_version: Option<&str>,
    live_version: Option<&str>,
) -> bool {
    let (Some(installed), Some(live)) = (installed_version, live_version) else {
        return false;
    };
    let inst = installed.trim().trim_start_matches(['v', 'V']);
    let running = live.trim().trim_start_matches(['v', 'V']);
    if inst.is_empty() || running.is_empty() {
        return false;
    }
    match compare_versions(inst, running) {
        VersionRelation::Same => false,
        VersionRelation::Newer | VersionRelation::Older => true,
        VersionRelation::Unknown => inst != running,
    }
}

fn collect_static_probe_entry(
    state: &DesktopAppState,
    default_cfg: &RuntimeConfig,
    live_status: Option<&LiveEngineStatus>,
    now: Instant,
) -> StaticProbeEntry {
    let service_state = service::detect_service_state();
    let system_service_installed = system_service_installed_from_service_state(service_state);
    let sys_path = config_file::system_config_path();
    let user_path = config_file::user_config_path();
    let loaded =
        load_effective_file_config_from_paths(system_service_installed, &sys_path, &user_path);

    let default_engine = default_engine_for_service_mode(system_service_installed);
    let mut runtime = RuntimeConfig {
        engine: default_engine,
        ..default_cfg.clone()
    };
    loaded.config.apply_to_runtime(&mut runtime);

    let configured_engine = runtime.engine;
    let fallback_dns = compute_fallback_dns(&loaded.config, &default_cfg.dns_addr);
    let installed_version = resolve_installed_version_cached(state);
    let (can_install_from_bundle, bundled_engine_version) = resolve_bundled_engine_cached(state);
    let running_from_readonly_dmg = detect_running_from_readonly_dmg();
    let wintun = probe_wintun_status_cached(state, configured_engine, service_state);
    let tray_supported = crate::tray::is_tray_host_available();
    let logs_dir = default_logs_dir_for_service_mode(system_service_installed)
        .display()
        .to_string();

    let vpn_conflict = if runtime.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_status
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_status.and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    StaticProbeEntry {
        installed_version,
        bundled_engine_version,
        can_install_from_bundle,
        running_from_readonly_dmg,
        wintun,
        config_path: loaded.path.display().to_string(),
        logs_dir,
        tray_supported,
        split_tunnel_mode: split_tunnel_mode_to_dto(runtime.split_tunnel.mode),
        split_tunnel_count: runtime.split_tunnel.apps.len(),
        config_warning: loaded.warning,
        configured_engine: engine_mode_to_dto(configured_engine),
        service_state: service_state_to_dto(service_state),
        vpn_conflict,
        fallback_dns,
        cached_at: now,
    }
}

fn map_live_telemetry(
    live: LiveEngineStatus,
    fallback_dns: &str,
    default_cfg: &RuntimeConfig,
    rx_rate_bps: u64,
    tx_rate_bps: u64,
) -> LiveTelemetryDto {
    let fallback = fallback_dns.trim();
    let raw_dns = live
        .dns_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(if fallback.is_empty() {
            default_cfg.dns_addr.as_str()
        } else {
            fallback
        });
    let raw_doh = live.doh.unwrap_or(default_cfg.enable_doh);
    let dns_display = dns::redact_dns_for_display(raw_dns);
    let doh_enabled = dns::is_effective_doh_target(raw_dns, raw_doh);

    LiveTelemetryDto {
        running: true,
        engine: engine_mode_to_dto(live.engine),
        addr: live.addr.to_string(),
        port: live.port,
        socks_port: live.socks_port,
        tun_interface: live.tun_interface,
        physical_nic: live.physical_nic,
        vpn_conflict: live.vpn_conflict,
        version: live.version,
        mode: live.mode,
        doh_enabled,
        dns_display,
        block_quic: live.block_quic.unwrap_or(default_cfg.block_quic),
        active_connections: live.active_connections.unwrap_or(0),
        total_connections: live.total_connections.unwrap_or(0),
        learned_hosts: live.learned_hosts.unwrap_or(0),
        isp_stage: live.isp_stage,
        udp_flows_active: live.udp_flows_active.unwrap_or(0),
        quic_blocked: live.quic_blocked.unwrap_or(0),
        dns_queries: live.dns_queries.unwrap_or(0),
        rss_kb: live.rss_kb,
        bytes_rx: live.bytes_rx.unwrap_or(0),
        bytes_tx: live.bytes_tx.unwrap_or(0),
        rx_rate_bps,
        tx_rate_bps,
        tls_handshakes: live.tls_handshakes.unwrap_or(0),
        auto_heal_escalations: live.auto_heal_escalations.unwrap_or(0),
    }
}

fn collect_status_snapshot_inner<FNow, FLive, FStatic>(
    state: &DesktopAppState,
    mut force_full_refresh: bool,
    bypass_mutating_guard: bool,
    now_fn: FNow,
    probe_live: FLive,
    probe_static: FStatic,
) -> Arc<DesktopStatusSnapshotDto>
where
    FNow: Fn() -> Instant,
    FLive: FnOnce(&RuntimeConfig) -> Option<LiveEngineStatus>,
    FStatic: FnOnce(&RuntimeConfig, Option<&LiveEngineStatus>, Instant) -> StaticProbeEntry,
{
    let _snapshot_guard = state
        .snapshot_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Read `active_operation` ONCE atomically under `snapshot_lock` and enforce
    // the mutating-install short-circuit unconditionally (even on `force_full_refresh`)
    // for all external callers.
    let pending_operation = state.active_operation();
    let mutating_install = crate::state::is_mutating_install_operation(pending_operation);
    if !bypass_mutating_guard && mutating_install {
        if let Some(last) = state.last_snapshot() {
            let mut held = (*last).clone();
            held.snapshot_seq = state.next_snapshot_seq();
            held.pending_operation = pending_operation;
            let snapshot = Arc::new(held);
            state.set_last_snapshot(Arc::clone(&snapshot));
            return snapshot;
        }
    }

    let default_cfg = RuntimeConfig::default();
    let live_status = probe_live(&default_cfg);
    let sampled_at = now_fn();

    let prev_snap = state.last_snapshot();
    let prev_live_present = prev_snap.as_ref().map(|s| s.live.is_some());
    let prev_live_version = prev_snap
        .as_ref()
        .and_then(|s| s.live.as_ref())
        .and_then(|l| l.version.as_deref());
    let curr_live_version = live_status.as_ref().and_then(|l| l.version.as_deref());
    let live_presence_flipped =
        prev_live_present.is_some_and(|was_live| was_live != live_status.is_some());
    let live_version_changed = prev_snap.is_some() && prev_live_version != curr_live_version;
    if (!mutating_install || bypass_mutating_guard)
        && (live_presence_flipped || live_version_changed)
    {
        force_full_refresh = true;
    }

    let static_entry = if force_full_refresh {
        let fresh = probe_static(&default_cfg, live_status.as_ref(), sampled_at);
        state.set_static_probe_cache(fresh.clone());
        fresh
    } else if let Some(cached) = state.cached_static_probes(sampled_at) {
        cached
    } else {
        let fresh = probe_static(&default_cfg, live_status.as_ref(), sampled_at);
        state.set_static_probe_cache(fresh.clone());
        fresh
    };

    let live = match live_status {
        Some(live_status) => {
            let bytes_rx = live_status.bytes_rx.unwrap_or(0);
            let bytes_tx = live_status.bytes_tx.unwrap_or(0);
            let (rx_rate_bps, tx_rate_bps) =
                state.sample_rates(bytes_rx, bytes_tx, sampled_at);
            Some(map_live_telemetry(
                live_status,
                &static_entry.fallback_dns,
                &default_cfg,
                rx_rate_bps,
                tx_rate_bps,
            ))
        }
        None => {
            state.reset_rates();
            None
        }
    };

    let vpn_conflict = live
        .as_ref()
        .and_then(|l| l.vpn_conflict.clone())
        .or_else(|| static_entry.vpn_conflict.clone());

    let live_version = live.as_ref().and_then(|l| l.version.as_deref());
    let cli_version_relation = compute_cli_version_relation(
        static_entry.service_state,
        static_entry.installed_version.as_deref(),
        live_version,
        static_entry.bundled_engine_version.as_deref(),
        static_entry.can_install_from_bundle,
    );
    let live_version_stale = compute_live_version_stale(
        static_entry.installed_version.as_deref(),
        live_version,
    );

    let snapshot = Arc::new(DesktopStatusSnapshotDto {
        snapshot_seq: state.next_snapshot_seq(),
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: current_platform().to_string(),
        service_state: static_entry.service_state,
        installed_version: static_entry.installed_version,
        configured_engine: static_entry.configured_engine,
        live,
        vpn_conflict,
        wintun: static_entry.wintun,
        split_tunnel_mode: static_entry.split_tunnel_mode,
        split_tunnel_count: static_entry.split_tunnel_count,
        config_path: static_entry.config_path,
        logs_dir: static_entry.logs_dir,
        tray_supported: static_entry.tray_supported,
        config_warning: static_entry.config_warning,
        bundled_engine_version: static_entry.bundled_engine_version,
        cli_version_relation,
        can_install_from_bundle: static_entry.can_install_from_bundle,
        live_version_stale,
        pending_operation,
        running_from_readonly_dmg: static_entry.running_from_readonly_dmg,
    });

    state.set_last_snapshot(Arc::clone(&snapshot));
    snapshot
}

fn collect_status_snapshot_with<FNow, FLive, FStatic>(
    state: &DesktopAppState,
    force_full_refresh: bool,
    now_fn: FNow,
    probe_live: FLive,
    probe_static: FStatic,
) -> Arc<DesktopStatusSnapshotDto>
where
    FNow: Fn() -> Instant,
    FLive: FnOnce(&RuntimeConfig) -> Option<LiveEngineStatus>,
    FStatic: FnOnce(&RuntimeConfig, Option<&LiveEngineStatus>, Instant) -> StaticProbeEntry,
{
    collect_status_snapshot_inner(
        state,
        force_full_refresh,
        false,
        now_fn,
        probe_live,
        probe_static,
    )
}

/// Probes live loopback daemon telemetry and combines it with TTL-cached
/// installation, background service, Wintun, tray-host, and split-tunnel state
/// into an immutable `Arc<DesktopStatusSnapshotDto>`.
///
/// Acquires `state.snapshot_lock` so concurrent polls never race `RateTracker`.
/// Regular ticks (`force_full_refresh == false`) reuse `state.static_probe_cache`
/// within its 45-second TTL and run only the fast loopback `/vdpi-health` probe,
/// escalating immediately to a full refresh whenever live daemon presence flips
/// (`Some -> None` or `None -> Some`) or `live.version` changes.
pub fn collect_status_snapshot(
    state: &DesktopAppState,
    force_full_refresh: bool,
) -> Arc<DesktopStatusSnapshotDto> {
    collect_status_snapshot_with(
        state,
        force_full_refresh,
        Instant::now,
        probe_live_engine_fast,
        |default_cfg, live_status, now| {
            collect_static_probe_entry(state, default_cfg, live_status, now)
        },
    )
}

/// Internal readiness-polling snapshot collector used ONLY after a mutating
/// sidecar operation has finished while `active_operation` remains set to keep
/// background pollers and external `get_status` calls suppressed until final
/// broadcast.
pub(crate) fn collect_status_snapshot_for_readiness(
    state: &DesktopAppState,
    force_full_refresh: bool,
) -> Arc<DesktopStatusSnapshotDto> {
    collect_status_snapshot_inner(
        state,
        force_full_refresh,
        true,
        Instant::now,
        probe_live_engine_fast,
        |default_cfg, live_status, now| {
            collect_static_probe_entry(state, default_cfg, live_status, now)
        },
    )
}

fn build_settings_payload_from_config(
    file_cfg: &FileConfig,
    default_engine: EngineMode,
    prefs: GuiPreferencesDto,
) -> DesktopSettingsPayloadDto {
    let mut runtime = RuntimeConfig {
        engine: default_engine,
        ..RuntimeConfig::default()
    };
    file_cfg.apply_to_runtime(&mut runtime);

    let dns_addr = runtime.dns_addr.clone();
    let dns_display = dns::redact_dns_for_display(&dns_addr);
    let dns_is_custom_url = is_custom_doh_url(&dns_addr);
    let doh_enabled = runtime.enable_doh;
    let effective_doh = dns::is_effective_doh_target(&dns_addr, doh_enabled);

    DesktopSettingsPayloadDto {
        engine: engine_mode_to_dto(runtime.engine),
        dns_addr,
        dns_display,
        dns_is_custom_url,
        doh_enabled,
        effective_doh,
        block_quic: runtime.block_quic,
        tun_ipv6: runtime.tun_ipv6,
        ipv4_only: runtime.dns_ipv4_only,
        vpn_coexistence: vpn_coexistence_to_dto(runtime.vpn_coexistence),
        bypass_domains: runtime.bypass_domains,
        include_domains: runtime.patterns,
        split_tunnel_mode: split_tunnel_mode_to_dto(runtime.split_tunnel.mode),
        split_tunnel_apps: runtime.split_tunnel.apps,
        gui: prefs,
    }
}

/// Loads the effective `FileConfig` cleanly and maps it alongside the provided
/// `GuiPreferencesDto` into a `DesktopSettingsPayloadDto`, redacting any secret
/// path/query/userinfo tokens from `dns_display`.
pub fn build_settings_payload(prefs: GuiPreferencesDto) -> DesktopSettingsPayloadDto {
    let system_installed = is_system_service_installed();
    let sys_path = config_file::system_config_path();
    let user_path = config_file::user_config_path();
    let loaded = load_effective_file_config_from_paths(system_installed, &sys_path, &user_path);
    let default_engine = default_engine_for_service_mode(system_installed);
    build_settings_payload_from_config(&loaded.config, default_engine, prefs)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use vdpi_core::config::{SplitTunnelMode, VpnCoexistence};

    use super::*;
    use crate::models::{
        EngineModeDto, LanguagePreferenceDto, ServiceStateDto, SplitTunnelModeDto,
        ThemePreferenceDto, VpnCoexistenceDto,
    };
    use crate::state::STATIC_PROBE_CACHE_TTL;

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
                .join(format!("vdpi-status-test-{label}-{pid}-{ts_nanos}-{seq}"));
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

    fn sample_live_status(dns_addr: Option<&str>, doh: Option<bool>) -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            version: Some("0.6.0".to_string()),
            mode: Some("combo".to_string()),
            doh,
            dns_addr: dns_addr.map(str::to_string),
            block_quic: Some(true),
            active_connections: Some(7),
            total_connections: Some(123),
            learned_hosts: Some(14),
            isp_stage: Some("Stage 1".to_string()),
            udp_flows_active: Some(3),
            quic_blocked: Some(9),
            dns_queries: Some(42),
            rss_kb: Some(18_432),
            bytes_rx: Some(10_000),
            bytes_tx: Some(20_000),
            tls_handshakes: Some(55),
            auto_heal_escalations: Some(1),
        }
    }

    fn sample_static_entry(
        cached_at: Instant,
        tray_supported: bool,
        config_warning: Option<String>,
    ) -> StaticProbeEntry {
        StaticProbeEntry {
            installed_version: Some("0.6.0".to_string()),
            bundled_engine_version: Some("0.6.0".to_string()),
            can_install_from_bundle: true,
            running_from_readonly_dmg: false,
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            config_path: "/etc/vdpi/config.toml".to_string(),
            logs_dir: "/var/log".to_string(),
            tray_supported,
            split_tunnel_mode: SplitTunnelModeDto::Exclude,
            split_tunnel_count: 2,
            config_warning,
            configured_engine: EngineModeDto::Tun,
            service_state: ServiceStateDto::Running,
            vpn_conflict: None,
            fallback_dns: "1.1.1.1".to_string(),
            cached_at,
        }
    }

    #[test]
    fn current_platform_returns_expected_target_tag() {
        let tag = current_platform();
        assert!(matches!(tag, "windows" | "macos" | "linux"));

        #[cfg(target_os = "windows")]
        assert_eq!(tag, "windows");
        #[cfg(target_os = "macos")]
        assert_eq!(tag, "macos");
        #[cfg(target_os = "linux")]
        assert_eq!(tag, "linux");
    }

    #[test]
    fn live_telemetry_redacts_doh_secrets_and_computes_effective_doh() {
        let default_cfg = RuntimeConfig::default();
        let custom_url = "https://dns.nextdns.io/abc123secret?device=gaming-rig";
        let dto = map_live_telemetry(
            sample_live_status(Some(custom_url), Some(false)),
            "1.1.1.1",
            &default_cfg,
            4_096,
            2_048,
        );
        assert!(dto.running);
        assert_eq!(dto.engine, EngineModeDto::Tun);
        assert_eq!(dto.dns_display, "https://dns.nextdns.io");
        assert!(!dto.dns_display.contains("abc123secret"));
        assert!(!dto.dns_display.contains("gaming-rig"));
        assert!(dto.doh_enabled);
        assert_eq!(dto.rx_rate_bps, 4_096);
        assert_eq!(dto.tx_rate_bps, 2_048);

        let ipv6_url = "https://[2606:4700:4700::1111]:8443/profile-secret?tok=99";
        let ipv6_dto = map_live_telemetry(
            sample_live_status(Some(ipv6_url), Some(false)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(ipv6_dto.dns_display, "https://[2606:4700:4700::1111]:8443");
        assert!(!ipv6_dto.dns_display.contains("profile-secret"));
        assert!(!ipv6_dto.dns_display.contains("tok=99"));
        assert!(ipv6_dto.doh_enabled);

        let userinfo_url = "https://alice:topsecret@dns.example.com/private-path";
        let userinfo_dto = map_live_telemetry(
            sample_live_status(Some(userinfo_url), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(userinfo_dto.dns_display, "https://dns.example.com");
        assert!(!userinfo_dto.dns_display.contains("alice"));
        assert!(!userinfo_dto.dns_display.contains("topsecret"));
        assert!(!userinfo_dto.dns_display.contains("private-path"));

        // Known public DoH IP respects doh flag.
        let cf_on = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(cf_on.dns_display, "1.1.1.1");
        assert!(cf_on.doh_enabled);

        let cf_off = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(false)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(cf_off.dns_display, "1.1.1.1");
        assert!(!cf_off.doh_enabled);

        // Bare custom UDP-first IP must NOT be mislabeled as effective DoH.
        let udp_custom = map_live_telemetry(
            sample_live_status(Some("76.76.2.0"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(udp_custom.dns_display, "76.76.2.0");
        assert!(!udp_custom.doh_enabled);

        // Missing/empty live dns_addr falls back cleanly and redacts the fallback.
        let fallback_dto = map_live_telemetry(
            sample_live_status(Some("   "), Some(false)),
            "https://dns.nextdns.io/fallback-secret",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(fallback_dto.dns_display, "https://dns.nextdns.io");
        assert!(!fallback_dto.dns_display.contains("fallback-secret"));
        assert!(fallback_dto.doh_enabled);

        // Empty live dns_addr and empty fallback_dns reuse default_cfg.dns_addr.
        let default_dns_dto = map_live_telemetry(
            sample_live_status(None, None),
            "   ",
            &default_cfg,
            0,
            0,
        );
        assert_eq!(default_dns_dto.dns_display, default_cfg.dns_addr);
        assert_eq!(
            default_dns_dto.doh_enabled,
            dns::is_effective_doh_target(&default_cfg.dns_addr, default_cfg.enable_doh)
        );
    }

    #[test]
    fn live_telemetry_integrates_with_state_rate_tracker() {
        let state = DesktopAppState::default();
        let default_cfg = RuntimeConfig::default();
        let t0 = Instant::now();

        let (rx0, tx0) = state.sample_rates(10_000, 20_000, t0);
        let snap0 = map_live_telemetry(
            sample_live_status(Some("1.1.1.1"), Some(true)),
            "1.1.1.1",
            &default_cfg,
            rx0,
            tx0,
        );
        assert_eq!((snap0.rx_rate_bps, snap0.tx_rate_bps), (0, 0));

        let (rx1, tx1) = state.sample_rates(18_000, 36_000, t0 + Duration::from_secs(2));
        let mut status1 = sample_live_status(Some("1.1.1.1"), Some(true));
        status1.bytes_rx = Some(18_000);
        status1.bytes_tx = Some(36_000);
        let snap1 = map_live_telemetry(status1, "1.1.1.1", &default_cfg, rx1, tx1);
        assert_eq!((snap1.rx_rate_bps, snap1.tx_rate_bps), (4_000, 8_000));
    }

    #[test]
    fn settings_payload_maps_defaults_cleanly() {
        let prefs = GuiPreferencesDto {
            theme: ThemePreferenceDto::Dark,
            language: LanguagePreferenceDto::System,
            keep_in_tray_on_close: true,
            minimize_to_tray: false,
            start_minimized_to_tray: true,
            show_taskbar_icon_when_minimized: false,
        };

        let payload = build_settings_payload_from_config(
            &FileConfig::default(),
            EngineMode::Proxy,
            prefs.clone(),
        );

        assert_eq!(payload.engine, EngineModeDto::Proxy);
        assert_eq!(payload.dns_addr, "1.1.1.1");
        assert_eq!(payload.dns_display, "1.1.1.1");
        assert!(!payload.dns_is_custom_url);
        assert!(payload.doh_enabled);
        assert!(payload.effective_doh);
        assert!(payload.block_quic);
        assert!(!payload.tun_ipv6);
        assert!(!payload.ipv4_only);
        assert_eq!(payload.vpn_coexistence, VpnCoexistenceDto::AutoYield);
        assert!(payload.bypass_domains.is_empty());
        assert!(payload.include_domains.is_empty());
        assert_eq!(payload.split_tunnel_mode, SplitTunnelModeDto::All);
        assert!(payload.split_tunnel_apps.is_empty());
        assert_eq!(payload.gui, prefs);
    }

    #[test]
    fn settings_payload_maps_overrides_and_never_leaks_doh_secret_in_display() {
        let file_cfg = FileConfig {
            engine: Some(EngineMode::Tun),
            dns_addr: Some("https://dns.nextdns.io/super-secret-id?device=desktop".to_string()),
            doh: Some(false),
            block_quic: Some(false),
            tun_ipv6: Some(true),
            ipv4_only: Some(true),
            vpn_coexistence: Some(VpnCoexistence::Warn),
            bypass_domains: Some(vec!["bank.example".to_string(), "corp.local".to_string()]),
            include_domains: Some(vec!["discord.com".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec![
                r"C:\Games\Discord.exe".to_string(),
                "STEAM.EXE".to_string(),
                "discord".to_string(),
            ]),
            ..FileConfig::default()
        };

        let prefs = GuiPreferencesDto::default();
        let payload =
            build_settings_payload_from_config(&file_cfg, EngineMode::Proxy, prefs.clone());

        assert_eq!(payload.engine, EngineModeDto::Tun);
        assert_eq!(
            payload.dns_addr,
            "https://dns.nextdns.io/super-secret-id?device=desktop"
        );
        assert_eq!(payload.dns_display, "https://dns.nextdns.io");
        assert!(!payload.dns_display.contains("super-secret-id"));
        assert!(!payload.dns_display.contains("device=desktop"));
        assert!(payload.dns_is_custom_url);
        assert!(!payload.doh_enabled);
        assert!(payload.effective_doh);
        assert!(!payload.block_quic);
        assert!(payload.tun_ipv6);
        assert!(payload.ipv4_only);
        assert_eq!(payload.vpn_coexistence, VpnCoexistenceDto::Warn);
        assert_eq!(payload.bypass_domains, vec!["bank.example", "corp.local"]);
        assert_eq!(payload.include_domains, vec!["discord.com"]);
        assert_eq!(payload.split_tunnel_mode, SplitTunnelModeDto::Exclude);
        assert_eq!(payload.split_tunnel_apps, vec!["Discord.exe", "STEAM.EXE"]);
        assert_eq!(payload.gui, prefs);
    }

    #[test]
    fn settings_payload_distinguishes_custom_udp_ip_from_effective_doh() {
        let file_cfg = FileConfig {
            dns_addr: Some("76.76.2.0".to_string()),
            doh: Some(true),
            ..FileConfig::default()
        };

        let payload = build_settings_payload_from_config(
            &file_cfg,
            EngineMode::Proxy,
            GuiPreferencesDto::default(),
        );

        assert_eq!(payload.dns_addr, "76.76.2.0");
        assert_eq!(payload.dns_display, "76.76.2.0");
        assert!(!payload.dns_is_custom_url);
        assert!(payload.doh_enabled);
        assert!(!payload.effective_doh);
    }

    #[test]
    fn is_custom_doh_url_requires_validated_https_url() {
        assert!(is_custom_doh_url("https://dns.nextdns.io/abc123?device=pc"));
        assert!(is_custom_doh_url("HTTPS://dns.quad9.net/dns-query"));
        assert!(is_custom_doh_url(
            "  https://[2606:4700:4700::1111]:8443/dns-query  "
        ));

        // Non-https schemes, malformed URLs, loopback hosts, userinfo, and bare IPs must be false.
        assert!(!is_custom_doh_url("http://dns.nextdns.io/abc123"));
        assert!(!is_custom_doh_url("ftp://dns.example.com/dns-query"));
        assert!(!is_custom_doh_url("foo://bar"));
        assert!(!is_custom_doh_url("https://"));
        assert!(!is_custom_doh_url(
            "https://alice:secret@dns.example.com/dns-query"
        ));
        assert!(!is_custom_doh_url("https://dns.example.com/dns-query#frag"));
        assert!(!is_custom_doh_url("https://0.0.0.0/dns-query"));
        assert!(is_custom_doh_url("https://127.0.0.1/dns-query"));
        assert!(!is_custom_doh_url("1.1.1.1"));
        assert!(!is_custom_doh_url("2606:4700:4700::1111"));
        assert!(!is_custom_doh_url(""));
        assert!(!is_custom_doh_url("   "));

        // Non-https dns_addr in FileConfig must never be flagged as a custom DoH URL.
        let invalid_scheme_cfg = FileConfig {
            dns_addr: Some("http://dns.example.com/secret-token".to_string()),
            ..FileConfig::default()
        };
        let payload = build_settings_payload_from_config(
            &invalid_scheme_cfg,
            EngineMode::Proxy,
            GuiPreferencesDto::default(),
        );
        assert!(!payload.dns_is_custom_url);
        assert!(!payload.dns_display.contains("secret-token"));
    }

    #[test]
    fn effective_file_config_loader_respects_service_mode_and_corrupt_fallback() {
        let dir = TestDir::new("config-precedence");
        let sys_path = dir.path().join("system.toml");
        let user_path = dir.path().join("user.toml");

        fs::write(&sys_path, "engine = \"tun\"\ndns_addr = \"9.9.9.9\"\n")
            .expect("write system config");
        fs::write(&user_path, "engine = \"proxy\"\ndns_addr = \"8.8.8.8\"\n")
            .expect("write user config");

        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.path, sys_path);
        assert_eq!(loaded.config.engine, Some(EngineMode::Tun));
        assert_eq!(loaded.config.dns_addr.as_deref(), Some("9.9.9.9"));
        assert!(loaded.warning.is_none());

        let loaded = load_effective_file_config_from_paths(false, &sys_path, &user_path);
        assert_eq!(loaded.path, user_path);
        assert_eq!(loaded.config.engine, Some(EngineMode::Proxy));
        assert_eq!(loaded.config.dns_addr.as_deref(), Some("8.8.8.8"));
        assert!(loaded.warning.is_none());

        // Corrupt system config in service mode must fall back cleanly to defaults,
        // surface a warning, and never read the user-writable config file.
        fs::write(&sys_path, "not valid = [toml").expect("write corrupt system config");
        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.path, sys_path);
        assert_eq!(loaded.config, FileConfig::default());
        assert!(loaded.warning.is_some());

        // Missing user config falls back to defaults without a warning when system config is absent.
        let missing_sys = dir.path().join("missing-sys.toml");
        let missing_user = dir.path().join("missing-user.toml");
        let loaded = load_effective_file_config_from_paths(false, &missing_sys, &missing_user);
        assert_eq!(loaded.path, missing_user);
        assert_eq!(loaded.config, FileConfig::default());
        assert!(loaded.warning.is_none());
    }

    #[test]
    fn config_parse_warning_redacts_embedded_urls() {
        let dir = TestDir::new("config-redact");
        let sys_path = dir.path().join("system.toml");
        let user_path = dir.path().join("user.toml");

        // Trigger a parse error whose message echoes the raw value containing a secret URL.
        fs::write(
            &sys_path,
            "engine = \"https://alice:topsecret@dns.nextdns.io/secret-profile?device=gaming-rig\"\n",
        )
        .expect("write invalid config with secret url");

        let loaded = load_effective_file_config_from_paths(true, &sys_path, &user_path);
        assert_eq!(loaded.config, FileConfig::default());
        let warning = loaded
            .warning
            .expect("corrupt config must emit config_warning");
        assert!(warning.contains("https://dns.nextdns.io"));
        assert!(!warning.contains("alice"));
        assert!(!warning.contains("topsecret"));
        assert!(!warning.contains("secret-profile"));
        assert!(!warning.contains("gaming-rig"));

        let err = anyhow::anyhow!(
            "invalid endpoint https://user:pass@doh.example.com/private?tok=42 and http://1.2.3.4/leak"
        );
        let redacted = redact_config_error(&err);
        assert!(redacted.contains("https://doh.example.com"));
        assert!(redacted.contains("http://1.2.3.4"));
        assert!(!redacted.contains("user:pass"));
        assert!(!redacted.contains("private"));
        assert!(!redacted.contains("tok=42"));
        assert!(!redacted.contains("leak"));
    }

    #[test]
    fn wintun_candidate_evaluation_checks_real_sha256_and_friendly_message() {
        let dir = TestDir::new("wintun");
        let empty_dll = dir.path().join("empty-wintun.dll");
        let corrupted_dll = dir.path().join("corrupted-wintun.dll");
        let valid_dll = dir.path().join("wintun.dll");
        let missing_dll = dir.path().join("missing-wintun.dll");

        let valid_bytes = b"MZ-verified-wintun-test-payload";
        let expected_sha256 = vdpi::update::sha256_hex(valid_bytes);

        fs::write(&empty_dll, b"").expect("write empty dll");
        fs::write(&corrupted_dll, b"MZ-tampered-or-corrupted-dll").expect("write corrupted dll");
        fs::write(&valid_dll, valid_bytes).expect("write valid dll");

        // Missing file reports missing message (not SHA-256 hash mismatch).
        let missing_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            std::slice::from_ref(&missing_dll),
            &expected_sha256,
        );
        assert!(missing_tun.required);
        assert!(!missing_tun.ready);
        assert_eq!(
            missing_tun.message.as_deref(),
            Some(WINTUN_MISSING_MESSAGE)
        );
        let missing_lower = missing_tun
            .message
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(!missing_lower.contains("sha-256"));
        assert!(!missing_lower.contains("hash"));
        assert!(!missing_lower.contains("mismatch"));

        // Existing empty or non-empty corrupted DLL (wrong SHA-256) reports hash
        // verification failure so diagnostics routes to the hash-mismatch branch.
        let invalid_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            &[missing_dll.clone(), empty_dll.clone(), corrupted_dll.clone()],
            &expected_sha256,
        );
        assert!(invalid_tun.required);
        assert!(!invalid_tun.ready);
        assert_eq!(
            invalid_tun.message.as_deref(),
            Some(WINTUN_HASH_MISMATCH_MESSAGE)
        );
        let mismatch_lower = invalid_tun
            .message
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        assert!(mismatch_lower.contains("sha-256"));
        assert!(mismatch_lower.contains("hash"));

        let invalid_proxy = evaluate_wintun_candidates_with_sha256(
            EngineMode::Proxy,
            std::slice::from_ref(&corrupted_dll),
            &expected_sha256,
        );
        assert!(!invalid_proxy.required);
        assert!(!invalid_proxy.ready);
        assert_eq!(
            invalid_proxy.message.as_deref(),
            Some(WINTUN_HASH_MISMATCH_MESSAGE)
        );

        // SHA-256 verified DLL in any candidate slot reports ready with no warning message.
        let ready_tun = evaluate_wintun_candidates_with_sha256(
            EngineMode::Tun,
            &[missing_dll, empty_dll, corrupted_dll, valid_dll],
            &expected_sha256,
        );
        assert!(ready_tun.required);
        assert!(ready_tun.ready);
        assert!(ready_tun.message.is_none());
    }

    #[test]
    fn binary_metadata_cache_skips_reprobe_and_rehash_until_file_changes_or_invalidated() {
        let dir = TestDir::new("binary-meta-cache");
        let fake_bin = dir.path().join("vdpi.exe");
        let wintun_dll = dir.path().join("wintun.dll");

        let valid_bytes = b"MZ-verified-wintun-cached-payload";
        let expected_sha256 = vdpi::update::sha256_hex(valid_bytes);
        fs::write(&fake_bin, b"vdpi-v0.6.0-binary").expect("write fake binary");
        fs::write(&wintun_dll, valid_bytes).expect("write valid dll");

        let state = DesktopAppState::default();
        let version_probes = AtomicUsize::new(0);
        let wintun_hashes = AtomicUsize::new(0);

        // First installed_version probe runs once and caches under (path, len, mtime).
        let v1 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.0".to_string())
            },
        );
        assert_eq!(v1.as_deref(), Some("0.6.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 1);

        // Second probe on unchanged binary skips spawning completely.
        let v2 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.1".to_string())
            },
        );
        assert_eq!(v2.as_deref(), Some("0.6.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 1);

        // Replacing the binary (different length) triggers a fresh probe.
        fs::write(&fake_bin, b"vdpi-v0.7.0-upgraded-binary-payload")
            .expect("rewrite upgraded binary");
        let v3 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(v3.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 2);

        // First Wintun verification hashes once and caches.
        let candidates = [wintun_dll.clone()];
        let w1 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(w1.required && w1.ready && w1.message.is_none());
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 1);

        // Second Wintun check on unchanged file skips hashing and adapts `required` to Proxy.
        let w2 =
            evaluate_wintun_candidates_cached_with(&state, EngineMode::Proxy, &candidates, |p| {
                wintun_hashes.fetch_add(1, Ordering::SeqCst);
                vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
            });
        assert!(!w2.required && w2.ready && w2.message.is_none());
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 1);

        // Tampering with wintun.dll (new length) invalidates the cache and reports hash failure.
        fs::write(&wintun_dll, b"tampered-bytes").expect("tamper wintun dll");
        let w3 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(w3.required && !w3.ready);
        assert_eq!(w3.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 2);

        // Repeated check on unchanged tampered file hits cache without re-hashing.
        let w4 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert_eq!(w4.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 2);

        // Explicit `invalidate_static_cache()` forces both version and Wintun re-probes.
        state.invalidate_static_cache();
        let v4 = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(v4.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 3);

        let w5 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert_eq!(w5.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 3);

        // Deleting wintun.dll reports missing without hashing.
        fs::remove_file(&wintun_dll).expect("remove wintun dll");
        let w6 = evaluate_wintun_candidates_cached_with(&state, EngineMode::Tun, &candidates, |p| {
            wintun_hashes.fetch_add(1, Ordering::SeqCst);
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert!(!w6.ready);
        assert_eq!(w6.message.as_deref(), Some(WINTUN_MISSING_MESSAGE));
        assert_eq!(wintun_hashes.load(Ordering::SeqCst), 3);

        // Transient `None` version probe must NOT poison BinaryMetadataCache;
        // subsequent probes on the same unchanged file retry and cache `Some`.
        state.invalidate_static_cache();
        let transient_fail = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                None
            },
        );
        assert!(transient_fail.is_none());
        assert_eq!(version_probes.load(Ordering::SeqCst), 4);

        let recovered = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.7.0".to_string())
            },
        );
        assert_eq!(recovered.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 5);

        let cached_after_recovery = resolve_installed_version_with(
            &state,
            || Some(fake_bin.clone()),
            |_| {
                version_probes.fetch_add(1, Ordering::SeqCst);
                Some("0.8.0".to_string())
            },
        );
        assert_eq!(cached_after_recovery.as_deref(), Some("0.7.0"));
        assert_eq!(version_probes.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn wintun_candidate_collection_covers_installed_sibling_and_resources_dirs() {
        let dir = TestDir::new("wintun-candidates");
        let installed_dir = dir.path().join("installed");
        let app_dir = dir.path().join("app");
        fs::create_dir_all(&installed_dir).expect("create installed dir");
        fs::create_dir_all(&app_dir).expect("create app dir");

        let installed_bin = installed_dir.join("vdpi.exe");
        let desktop_exe = app_dir.join("vdpi-desktop.exe");

        let candidates = collect_wintun_candidates(Some(&installed_bin), Some(&desktop_exe));
        assert!(candidates.contains(&installed_dir.join("wintun.dll")));
        assert!(candidates.contains(&installed_dir.join("resources").join("wintun.dll")));
        assert!(candidates.contains(&app_dir.join("wintun.dll")));
        assert!(candidates.contains(&app_dir.join("resources").join("wintun.dll")));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn probe_wintun_status_on_non_windows_is_always_ready_and_not_required() {
        for mode in [EngineMode::Tun, EngineMode::Proxy] {
            let status = probe_wintun_status(mode);
            assert!(!status.required);
            assert!(status.ready);
            assert!(status.message.is_none());
        }
    }

    #[test]
    fn resolve_logs_dir_handles_macos_linux_system_service_and_user_modes() {
        let dir = TestDir::new("logs-dir");
        let user_logs = dir.path().join("home").join(".vdpi").join("logs");
        let sys_vdpi_logs = dir.path().join("var-log-vdpi");
        let sys_var_log = dir.path().join("var-log");

        // macOS LaunchDaemon mode always resolves to /var/log; LaunchAgent uses ~/.vdpi/logs.
        assert_eq!(
            resolve_logs_dir_for_platform("macos", true, user_logs.clone(), &[]),
            PathBuf::from("/var/log")
        );
        assert_eq!(
            resolve_logs_dir_for_platform("macos", false, user_logs.clone(), &[]),
            user_logs
        );

        // Linux system service prefers first existing logs directory; falls back to user logs.
        let candidates = [
            sys_vdpi_logs.clone(),
            user_logs.clone(),
            sys_var_log.clone(),
        ];
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            user_logs
        );

        fs::create_dir_all(&sys_var_log).expect("create var-log");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            sys_var_log
        );

        fs::create_dir_all(&user_logs).expect("create user logs");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            user_logs
        );

        fs::create_dir_all(&sys_vdpi_logs).expect("create var-log-vdpi");
        assert_eq!(
            resolve_logs_dir_for_platform("linux", true, user_logs.clone(), &candidates),
            sys_vdpi_logs
        );

        // Linux non-system-service always returns user logs.
        assert_eq!(
            resolve_logs_dir_for_platform("linux", false, user_logs.clone(), &candidates),
            user_logs
        );

        // Windows always returns its default logs directory.
        assert_eq!(
            resolve_logs_dir_for_platform("windows", true, user_logs.clone(), &candidates),
            user_logs
        );
    }

    #[test]
    fn fast_probe_candidates_prioritize_runtime_states_and_deduplicate() {
        let cfg = RuntimeConfig::default();
        let states = vec![
            RuntimeState {
                pid: 100,
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 19000,
                socks_port: Some(19001),
                engine: EngineMode::Tun,
                tun_interface: Some("vdpi0".to_string()),
                env_activated_at: None,
            },
            RuntimeState {
                pid: 101,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 19000,
                socks_port: None,
                engine: EngineMode::Tun,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 102,
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
                port: 19002,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 103,
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                port: 0,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
        ];

        let candidates = build_fast_probe_candidates(&cfg, &states);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].port, 19000);
        assert_eq!(candidates[0].socks_port, Some(19001));
        assert_eq!(candidates[1].port, cfg.port);
        assert_eq!(candidates[2].port, DEFAULT_TUN_HEALTH_PORT);
    }

    #[test]
    fn collect_status_snapshot_reuses_static_cache_and_honors_force_refresh_and_ttl() {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let t0 = Instant::now();

        // Tick 1 (cold cache): invokes static probe once and establishes rate baseline.
        let s1 = collect_status_snapshot_with(
            &state,
            false,
            || t0,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, false, Some("parsed with warning".to_string()))
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(s1.snapshot_seq, 1);
        assert!(!s1.tray_supported);
        assert_eq!(s1.config_warning.as_deref(), Some("parsed with warning"));
        assert_eq!(s1.live.as_ref().expect("live").rx_rate_bps, 0);

        // Tick 2 (+2s, force_full_refresh = false): reuses StaticProbeCache (0 extra static probes).
        let t1 = t0 + Duration::from_secs(2);
        let s2 = collect_status_snapshot_with(
            &state,
            false,
            || t1,
            |_| {
                let mut live = sample_live_status(Some("1.1.1.1"), Some(true));
                live.bytes_rx = Some(18_000);
                live.bytes_tx = Some(36_000);
                Some(live)
            },
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(s2.snapshot_seq, 2);
        assert!(!s2.tray_supported);
        assert_eq!(s2.live.as_ref().expect("live").rx_rate_bps, 4_000);
        assert_eq!(s2.live.as_ref().expect("live").tx_rate_bps, 8_000);

        // Tick 3 (+4s, force_full_refresh = true): bypasses fresh cache and refreshes static probes.
        let t2 = t0 + Duration::from_secs(4);
        let s3 = collect_status_snapshot_with(
            &state,
            true,
            || t2,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert_eq!(s3.snapshot_seq, 3);
        assert!(s3.tray_supported);
        assert!(s3.config_warning.is_none());
        assert!(s3.live.is_none());

        // Tick 4 (after 45s TTL expires, same offline presence): triggers a fresh
        // static probe automatically purely due to TTL expiration.
        let t3 = t2 + STATIC_PROBE_CACHE_TTL + Duration::from_secs(1);
        let s4 = collect_status_snapshot_with(
            &state,
            false,
            || t3,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 3);
        assert_eq!(s4.snapshot_seq, 4);
        assert!(s4.live.is_none());

        // Tick 5 (+2s, daemon comes back online): live presence flip (None -> Some)
        // triggers an immediate static refresh and re-baselines rate tracker at 0 B/s.
        let t4 = t3 + Duration::from_secs(2);
        let s5 = collect_status_snapshot_with(
            &state,
            false,
            || t4,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 4);
        assert_eq!(s5.snapshot_seq, 5);
        assert_eq!(s5.live.as_ref().expect("live").rx_rate_bps, 0);
        assert_eq!(state.last_snapshot().expect("last snapshot").snapshot_seq, 5);
    }

    #[test]
    fn collect_status_snapshot_forces_full_refresh_on_live_presence_flip_and_uses_cached_fallback_dns(
    ) {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let t0 = Instant::now();

        // Tick 1: cold cache populates cached `fallback_dns`; live telemetry with
        // missing `dns_addr` uses cached `fallback_dns` without reading config.toml.
        let s1 = collect_status_snapshot_with(
            &state,
            false,
            || t0,
            |_| Some(sample_live_status(None, Some(false))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.config_path = "/nonexistent/must-not-be-read/config.toml".to_string();
                entry.fallback_dns = "https://dns.nextdns.io/secret-cached-profile".to_string();
                entry.service_state = ServiceStateDto::Running;
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        let live1 = s1.live.as_ref().expect("live telemetry");
        assert_eq!(live1.dns_display, "https://dns.nextdns.io");
        assert!(!live1.dns_display.contains("secret-cached-profile"));
        assert!(live1.doh_enabled);

        // Tick 2 (+1.5s, still live, force_full_refresh = false): cache hit (no static probe).
        let t1 = t0 + Duration::from_millis(1_500);
        let s2 = collect_status_snapshot_with(
            &state,
            false,
            || t1,
            |_| Some(sample_live_status(Some("   "), Some(false))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        let live2 = s2.live.as_ref().expect("live telemetry");
        assert_eq!(live2.dns_display, "https://dns.nextdns.io");
        assert!(live2.doh_enabled);

        // Tick 3 (+3s, external daemon stopped / VPN yielded: Some -> None):
        // immediately forces full refresh instead of waiting for 45s TTL.
        let t2 = t0 + Duration::from_secs(3);
        let s3 = collect_status_snapshot_with(
            &state,
            false,
            || t2,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.service_state = ServiceStateDto::Stopped;
                entry.vpn_conflict = Some("Mullvad".to_string());
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert!(s3.live.is_none());
        assert_eq!(s3.service_state, ServiceStateDto::Stopped);
        assert_eq!(s3.vpn_conflict.as_deref(), Some("Mullvad"));

        // Tick 4 (+4.5s, still offline: None -> None): reuses cache (no static probe).
        let t3 = t0 + Duration::from_millis(4_500);
        let s4 = collect_status_snapshot_with(
            &state,
            false,
            || t3,
            |_| None,
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert_eq!(s4.service_state, ServiceStateDto::Stopped);

        // Tick 5 (+6s, external daemon started: None -> Some):
        // immediately forces full refresh instead of waiting for 45s TTL.
        let t4 = t0 + Duration::from_secs(6);
        let s5 = collect_status_snapshot_with(
            &state,
            false,
            || t4,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.service_state = ServiceStateDto::Running;
                entry.vpn_conflict = None;
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 3);
        assert!(s5.live.is_some());
        assert_eq!(s5.service_state, ServiceStateDto::Running);
        assert!(s5.vpn_conflict.is_none());
    }

    #[test]
    fn collect_status_snapshot_serializes_concurrent_polls_via_snapshot_lock() {
        let state = Arc::new(DesktopAppState::default());
        let threads = 6usize;
        let barrier = Arc::new(Barrier::new(threads));
        let static_calls = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let state_clone = Arc::clone(&state);
            let barrier_clone = Arc::clone(&barrier);
            let static_calls_clone = Arc::clone(&static_calls);
            handles.push(thread::spawn(move || {
                barrier_clone.wait();
                collect_status_snapshot_with(
                    &state_clone,
                    false,
                    Instant::now,
                    |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
                    |_, _, now| {
                        static_calls_clone.fetch_add(1, Ordering::SeqCst);
                        sample_static_entry(now, true, None)
                    },
                )
                .snapshot_seq
            }));
        }

        let mut seqs: Vec<u64> = handles
            .into_iter()
            .map(|h| h.join().expect("join snapshot thread"))
            .collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (1..=threads as u64).collect::<Vec<_>>());
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.last_snapshot().expect("cached snapshot").snapshot_seq,
            threads as u64
        );
    }

    #[test]
    fn cli_version_relation_live_staleness_and_macos_dmg_detection() {
        assert_eq!(
            compute_cli_version_relation(ServiceStateDto::NotInstalled, None, None, None, false),
            CliVersionRelationDto::BundledMissing
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                Some("0.6.0"),
                Some("0.6.0"),
                None,
                false
            ),
            CliVersionRelationDto::BundledMissing
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::NotInstalled,
                None,
                None,
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::NotInstalled
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Stopped,
                None,
                Some("0.7.0"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::RepairNeeded
        );
        // Running daemon newer than bundled with missing disk installed_version must
        // report NewerInstalled (never RepairNeeded) to avoid suggesting downgrade.
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                None,
                Some("0.7.0"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::NewerInstalled
        );
        // Running daemon older/same than bundled with missing disk binary still needs repair.
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                None,
                Some("0.6.1"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::RepairNeeded
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                None,
                Some("0.6.0"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::RepairNeeded
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                Some("0.6.0"),
                Some("0.6.0"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::UpgradeAvailable
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                Some("0.6.1"),
                Some("0.6.1"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::UpToDate
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                Some("0.7.0"),
                Some("0.7.0"),
                Some("0.6.1"),
                true
            ),
            CliVersionRelationDto::NewerInstalled
        );
        assert_eq!(
            compute_cli_version_relation(
                ServiceStateDto::Running,
                Some("0.6.1"),
                Some("0.6.1"),
                None,
                true
            ),
            CliVersionRelationDto::Unknown
        );

        assert!(!compute_live_version_stale(Some("0.6.1"), Some("v0.6.1")));
        assert!(compute_live_version_stale(Some("0.6.1"), Some("0.6.0")));
        assert!(!compute_live_version_stale(Some("0.6.1"), None));
        assert!(!compute_live_version_stale(None, Some("0.6.1")));

        assert!(is_macos_readonly_dmg_path(Path::new(
            "/Volumes/vdpi Desktop/vdpi Desktop.app/Contents/MacOS/vdpi-desktop"
        )));
        assert!(is_macos_readonly_dmg_path(Path::new(
            "/private/var/folders/ab/cd/T/AppTranslocation/1234/d/vdpi Desktop.app/Contents/MacOS/vdpi-desktop"
        )));
        assert!(!is_macos_readonly_dmg_path(Path::new(
            "/Applications/vdpi Desktop.app/Contents/MacOS/vdpi-desktop"
        )));

        // statfs MNT_RDONLY takes precedence over `/Volumes/` prefix, while
        // `/AppTranslocation/` is always treated as read-only.
        assert!(!is_macos_readonly_dmg_path_with(
            Path::new("/Volumes/ExternalSSD/Applications/vdpi Desktop.app/Contents/MacOS/vdpi-desktop"),
            Some(false)
        ));
        assert!(is_macos_readonly_dmg_path_with(
            Path::new("/Volumes/vdpi Desktop/vdpi Desktop.app/Contents/MacOS/vdpi-desktop"),
            Some(true)
        ));
        assert!(is_macos_readonly_dmg_path_with(
            Path::new("/private/var/folders/ab/cd/T/AppTranslocation/1234/d/vdpi Desktop.app"),
            Some(false)
        ));
        assert!(is_macos_readonly_dmg_path_with(
            Path::new("/Volumes/vdpi Desktop/vdpi Desktop.app"),
            None
        ));
        assert!(!is_macos_readonly_dmg_path_with(
            Path::new("/Applications/vdpi Desktop.app"),
            None
        ));
    }

    #[test]
    fn service_wintun_probe_fails_if_primary_installed_dll_has_bad_sha256() {
        let dir = TestDir::new("service-wintun-strict");
        let installed_dir = dir.path().join("ProgramFiles").join("vdpi").join("bin");
        let pd_dir = dir.path().join("ProgramData").join("vdpi").join("runtime");
        fs::create_dir_all(&installed_dir).expect("create installed dir");
        fs::create_dir_all(&pd_dir).expect("create ProgramData dir");

        let installed_bin = installed_dir.join("vdpi.exe");
        let primary_dll = installed_dir.join("wintun.dll");
        let fallback_dll = pd_dir.join("wintun-0.14.1.dll");
        let valid_bytes = b"MZ-valid-service-wintun";
        let expected_sha256 = vdpi::update::sha256_hex(valid_bytes);

        fs::write(&installed_bin, b"fake-exe").expect("write exe");
        fs::write(&primary_dll, b"corrupted-primary-wintun").expect("write bad primary dll");
        fs::write(&fallback_dll, valid_bytes).expect("write valid fallback dll");

        let pf_root = dir.path().join("ProgramFiles");
        let pd_root = dir.path().join("ProgramData");
        let (primary_path, candidates) = collect_service_wintun_candidates(
            Some(&installed_bin),
            Some(pf_root.as_path()),
            Some(pd_root.as_path()),
            "wintun-0.14.1.dll",
        );
        assert_eq!(primary_path.as_deref(), Some(primary_dll.as_path()));

        let state = DesktopAppState::default();
        let failed = evaluate_service_wintun_candidates_cached_with(
            &state,
            EngineMode::Tun,
            primary_path.as_deref(),
            &candidates,
            |p| vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok(),
        );
        assert!(!failed.ready, "bad primary installed wintun.dll must fail immediately");
        assert_eq!(failed.message.as_deref(), Some(WINTUN_HASH_MISMATCH_MESSAGE));

        // Direct outcome evaluation distinguishes Invalid vs Missing vs Ready.
        let existing = snapshot_existing_wintun_metadata(&candidates);
        let primaries = primary_path.clone().into_iter().collect::<Vec<_>>();
        let invalid_outcome = evaluate_wintun_outcome_with(&primaries, &existing, |p| {
            vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok()
        });
        assert_eq!(
            invalid_outcome,
            WintunPreflightResult::Invalid(WINTUN_HASH_MISMATCH_MESSAGE.to_string())
        );

        let missing_outcome = evaluate_wintun_outcome_with(&primaries, &[], |_| true);
        assert_eq!(
            missing_outcome,
            WintunPreflightResult::Missing(WINTUN_MISSING_MESSAGE.to_string())
        );

        // Replacing primary installed DLL with valid bytes succeeds after cache invalidation.
        fs::write(&primary_dll, valid_bytes).expect("write valid primary dll");
        state.invalidate_static_cache();
        let passed = evaluate_service_wintun_candidates_cached_with(
            &state,
            EngineMode::Tun,
            primary_path.as_deref(),
            &candidates,
            |p| vdpi::platform::windows_tun::verify_wintun_dll_sha256(p, &expected_sha256).is_ok(),
        );
        assert!(passed.ready);
        assert!(passed.message.is_none());
    }

    #[test]
    fn windows_known_folder_helpers_reject_unc_and_traversal_and_never_read_program_files_env() {
        assert_eq!(
            resolve_windows_program_files_dir_from(
                Some(PathBuf::from(r"\\?\D:\Program Files")),
                Some(OsStr::new("E:"))
            ),
            PathBuf::from(r"D:\Program Files")
        );
        // UNC / traversal KnownFolder values fall back cleanly to validated SystemDrive.
        assert_eq!(
            resolve_windows_program_files_dir_from(
                Some(PathBuf::from(r"\\attacker\share\Program Files")),
                Some(OsStr::new("D:"))
            ),
            PathBuf::from(r"D:\Program Files")
        );
        assert_eq!(
            resolve_windows_program_files_dir_from(
                Some(PathBuf::from(r"C:\Program Files\..\Evil")),
                None
            ),
            PathBuf::from(r"C:\Program Files")
        );
        assert_eq!(
            resolve_windows_program_data_dir_from(
                Some(PathBuf::from(r"D:\ProgramData")),
                Some(OsStr::new("E:"))
            ),
            PathBuf::from(r"D:\ProgramData")
        );
        assert_eq!(
            resolve_windows_program_data_dir_from(None, Some(OsStr::new("E:\\"))),
            PathBuf::from(r"E:\ProgramData")
        );
        assert_eq!(
            resolve_windows_program_data_dir_from(None, Some(OsStr::new("bad"))),
            PathBuf::from(r"C:\ProgramData")
        );
    }

    #[cfg(unix)]
    #[test]
    fn wintun_probe_rejects_ancestor_symlink_before_hashing() {
        use std::os::unix::fs::symlink;

        let dir = TestDir::new("wintun-symlink");
        let real_dir = dir.path().join("real");
        fs::create_dir_all(&real_dir).expect("create real dir");
        let real_dll = real_dir.join("wintun.dll");
        fs::write(&real_dll, b"MZ-valid").expect("write real dll");

        let link_dir = dir.path().join("junction-dir");
        symlink(&real_dir, &link_dir).expect("create ancestor symlink");
        let via_link = link_dir.join("wintun.dll");

        let leaf_link = dir.path().join("leaf-wintun.dll");
        symlink(&real_dll, &leaf_link).expect("create leaf symlink");

        assert!(verify_wintun_path_no_reparse_or_symlink(&real_dll));
        assert!(!verify_wintun_path_no_reparse_or_symlink(&via_link));
        assert!(!verify_wintun_path_no_reparse_or_symlink(&leaf_link));

        let hashes = AtomicUsize::new(0);
        let existing = snapshot_existing_wintun_metadata(&[via_link, leaf_link]);
        assert!(existing.is_empty());
        let outcome = evaluate_wintun_outcome_with(&[], &existing, |_| {
            hashes.fetch_add(1, Ordering::SeqCst);
            true
        });
        assert_eq!(
            outcome,
            WintunPreflightResult::Missing(WINTUN_MISSING_MESSAGE.to_string())
        );
        assert_eq!(hashes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resolve_bundled_engine_with_caches_by_metadata_handles_transient_none_and_missing() {
        let dir = TestDir::new("bundled-engine-cache");
        let bundled_bin = dir.path().join("vdpi");
        fs::write(&bundled_bin, b"bundled-cli-v0.6.1").expect("write bundled cli");

        let state = DesktopAppState::default();
        let probes = AtomicUsize::new(0);

        // Cold probe caches version under (path, len, mtime).
        let (present1, ver1) = resolve_bundled_engine_with(
            &state,
            || Some(bundled_bin.clone()),
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.1".to_string())
            },
        );
        assert!(present1);
        assert_eq!(ver1.as_deref(), Some("0.6.1"));
        assert_eq!(probes.load(Ordering::SeqCst), 1);

        // Unchanged file hits BinaryMetadataCache without re-probing.
        let (present2, ver2) = resolve_bundled_engine_with(
            &state,
            || Some(bundled_bin.clone()),
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                Some("9.9.9".to_string())
            },
        );
        assert!(present2);
        assert_eq!(ver2.as_deref(), Some("0.6.1"));
        assert_eq!(probes.load(Ordering::SeqCst), 1);

        // Changing file length invalidates metadata key and re-probes.
        fs::write(&bundled_bin, b"bundled-cli-v0.6.2-updated-payload")
            .expect("rewrite bundled cli");
        let (present3, ver3) = resolve_bundled_engine_with(
            &state,
            || Some(bundled_bin.clone()),
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.2".to_string())
            },
        );
        assert!(present3);
        assert_eq!(ver3.as_deref(), Some("0.6.2"));
        assert_eq!(probes.load(Ordering::SeqCst), 2);

        // Explicit cache invalidation forces re-probe; transient None must NOT poison cache.
        state.invalidate_static_cache();
        let (present_none, ver_none) = resolve_bundled_engine_with(
            &state,
            || Some(bundled_bin.clone()),
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                None
            },
        );
        assert!(present_none);
        assert!(ver_none.is_none());
        assert_eq!(probes.load(Ordering::SeqCst), 3);

        let (present_rec, ver_rec) = resolve_bundled_engine_with(
            &state,
            || Some(bundled_bin.clone()),
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.2".to_string())
            },
        );
        assert!(present_rec);
        assert_eq!(ver_rec.as_deref(), Some("0.6.2"));
        assert_eq!(probes.load(Ordering::SeqCst), 4);

        // Missing bundled binary returns (false, None) and clears cache.
        let (present_missing, ver_missing) = resolve_bundled_engine_with(
            &state,
            || None,
            |_| {
                probes.fetch_add(1, Ordering::SeqCst);
                Some("0.6.2".to_string())
            },
        );
        assert!(!present_missing);
        assert!(ver_missing.is_none());
        assert_eq!(probes.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn collect_status_snapshot_skips_probes_during_mutating_install_operation_even_when_forced() {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let live_calls = AtomicUsize::new(0);

        let initial = collect_status_snapshot_with(
            &state,
            true,
            Instant::now,
            |_| {
                live_calls.fetch_add(1, Ordering::SeqCst);
                None
            },
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(initial.pending_operation, None);
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(live_calls.load(Ordering::SeqCst), 1);

        state.set_active_operation(Some(crate::models::ServiceOperationDto::Upgrading));
        // Both force=false and force=true must unconditionally short-circuit during mutating install.
        for force in [false, true] {
            let held = collect_status_snapshot_with(
                &state,
                force,
                Instant::now,
                |_| {
                    live_calls.fetch_add(1, Ordering::SeqCst);
                    None
                },
                |_, _, now| {
                    static_calls.fetch_add(1, Ordering::SeqCst);
                    sample_static_entry(now, true, None)
                },
            );
            assert_eq!(
                held.pending_operation,
                Some(crate::models::ServiceOperationDto::Upgrading)
            );
            assert_eq!(static_calls.load(Ordering::SeqCst), 1);
            assert_eq!(live_calls.load(Ordering::SeqCst), 1);
            assert!(held.snapshot_seq > initial.snapshot_seq);
        }
    }

    #[test]
    fn collect_status_snapshot_forces_full_refresh_when_live_version_changes() {
        let state = DesktopAppState::default();
        let static_calls = AtomicUsize::new(0);
        let t0 = Instant::now();

        let s1 = collect_status_snapshot_with(
            &state,
            false,
            || t0,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);
        assert_eq!(s1.live.as_ref().and_then(|l| l.version.as_deref()), Some("0.6.0"));

        // Same live version within TTL reuses static cache.
        let t1 = t0 + Duration::from_secs(2);
        let _s2 = collect_status_snapshot_with(
            &state,
            false,
            || t1,
            |_| Some(sample_live_status(Some("1.1.1.1"), Some(true))),
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                sample_static_entry(now, true, None)
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 1);

        // Live daemon version changes while remaining online (Some -> Some):
        // must immediately escalate to full static refresh.
        let t2 = t0 + Duration::from_secs(4);
        let s3 = collect_status_snapshot_with(
            &state,
            false,
            || t2,
            |_| {
                let mut live = sample_live_status(Some("1.1.1.1"), Some(true));
                live.version = Some("0.6.1".to_string());
                Some(live)
            },
            |_, _, now| {
                static_calls.fetch_add(1, Ordering::SeqCst);
                let mut entry = sample_static_entry(now, true, None);
                entry.installed_version = Some("0.6.1".to_string());
                entry
            },
        );
        assert_eq!(static_calls.load(Ordering::SeqCst), 2);
        assert_eq!(s3.installed_version.as_deref(), Some("0.6.1"));
        assert!(!s3.live_version_stale);
    }
}
