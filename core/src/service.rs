use crate::config::{DesyncMode, EngineMode, RuntimeConfig, VpnCoexistence};
use crate::config_file;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
use crate::config_file::{FileConfig, CONFIG_SCHEMA_VERSION};
use crate::desync::EngineContext;
use crate::health::DEFAULT_TUN_HEALTH_PORT;
use crate::platform::vpn::{detect_active_vpn, VpnScope};
use crate::platform::{clear_all_system_proxies, platform_name, print_platform_proxy_status};
use crate::update::{compare_versions, parse_semver, VersionRelation};
use anyhow::{bail, Context, Result};
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const LAUNCH_AGENT_LABEL: &str = "com.vdpi";
pub const LAUNCH_DAEMON_LABEL: &str = "com.vdpi.daemon";
pub const LAUNCH_DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/com.vdpi.daemon.plist";
pub const MACOS_SYSTEM_CONFIG_PATH: &str = "/Library/Application Support/vdpi/config.toml";
pub const SYSTEMD_UNIT_NAME: &str = "vdpi.service";
pub const SYSTEMD_SYSTEM_UNIT_PATH: &str = "/etc/systemd/system/vdpi.service";
pub const LINUX_SYSTEM_CONFIG_PATH: &str = "/etc/vdpi/config.toml";
pub const UNIX_SYSTEM_BIN_PATH: &str = "/usr/local/bin/vdpi";
pub const WINDOWS_SERVICE_NAME: &str = "vdpi";
pub const WINDOWS_LEGACY_RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

/// Persisted active listener metadata written when `vdpi` starts so `vdpi status`
/// and `vdpi doctor` always discover rotated ports automatically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeState {
    pub pid: u32,
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    #[serde(default)]
    pub engine: EngineMode,
    #[serde(default)]
    pub tun_interface: Option<String>,
    #[serde(default)]
    pub env_activated_at: Option<u64>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn runtime_state_write_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if crate::platform::windows::is_running_as_service() {
            let base = std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
            return Some(base.join("vdpi").join("state.json"));
        }
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            return Some(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if is_unix_root() {
            return Some(PathBuf::from("/run/vdpi/state.json"));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if is_unix_root() {
            return Some(PathBuf::from(
                "/Library/Application Support/vdpi/state.json",
            ));
        }
    }
    vdpi_root_dir().ok().map(|r| r.join("state.json"))
}

fn runtime_state_read_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "windows")]
    {
        let pd = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        paths.push(pd.join("vdpi").join("state.json"));
        if let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") {
            paths.push(PathBuf::from(local_appdata).join("vdpi").join("state.json"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        paths.push(PathBuf::from("/run/vdpi/state.json"));
    }
    #[cfg(target_os = "macos")]
    {
        paths.push(PathBuf::from(
            "/Library/Application Support/vdpi/state.json",
        ));
    }
    if let Ok(root) = vdpi_root_dir() {
        let p = root.join("state.json");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}

pub fn write_runtime_state(primary_addr: SocketAddr, socks_addr: Option<SocketAddr>) {
    write_runtime_state_with_meta(
        primary_addr,
        socks_addr,
        EngineMode::Proxy,
        None,
        Some(unix_now_secs()),
    );
}

#[cfg(target_os = "windows")]
mod win_fs_hardening {
    use super::*;
    use std::ffi::{c_void, OsStr};
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, INVALID_HANDLE_VALUE};

    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    const ERROR_SUCCESS: u32 = 0;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    const ERROR_INVALID_OWNER: i32 = 1307;
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

    const SDDL_REVISION_1: u32 = 1;
    const SE_FILE_OBJECT: u32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    /// Owner + Protected DACL for `%ProgramData%\vdpi`: assigns `BUILTIN\Administrators` as
    /// owner (`O:BA`) so a non-admin pre-creator cannot retain implicit `WRITE_DAC` via
    /// ownership, blocks inherited ProgramData write ACEs, grants Full Control to SYSTEM
    /// and Administrators, and grants Read/Execute to Users.
    pub(super) const PROGRAMDATA_DIR_SDDL: &str =
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
    /// DACL-only fallback used solely when creating test directories as a non-admin user
    /// that lacks permission to assign `BUILTIN\Administrators` as owner.
    const PROGRAMDATA_DIR_DACL_ONLY_SDDL: &str =
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
    /// Owner + Protected DACL for pre-existing/written `%ProgramData%\vdpi\state.json` files.
    pub(super) const PROGRAMDATA_FILE_SDDL: &str =
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";

    static RUNTIME_STATE_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    #[repr(C)]
    #[allow(dead_code)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: FILETIME,
        ft_last_access_time: FILETIME,
        ft_last_write_time: FILETIME,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn CreateDirectoryW(
            lp_path_name: *const u16,
            lp_security_attributes: *mut c_void,
        ) -> i32;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: HANDLE,
        ) -> HANDLE;
        fn GetFileInformationByHandle(
            h_file: HANDLE,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_security_descriptor: *const u16,
            string_sd_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
        fn GetSecurityDescriptorOwner(
            p_security_descriptor: *mut c_void,
            p_owner: *mut *mut c_void,
            lpb_owner_defaulted: *mut i32,
        ) -> i32;
        fn GetSecurityDescriptorDacl(
            p_security_descriptor: *mut c_void,
            lpb_dacl_present: *mut i32,
            p_dacl: *mut *mut c_void,
            lpb_dacl_defaulted: *mut i32,
        ) -> i32;
        fn SetSecurityInfo(
            handle: HANDLE,
            object_type: u32,
            security_info: u32,
            psid_owner: *mut c_void,
            psid_group: *mut c_void,
            p_dacl: *mut c_void,
            p_sacl: *mut c_void,
        ) -> u32;
    }

    struct LocalAllocGuard(*mut c_void);

    impl Drop for LocalAllocGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
            }
        }
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    pub(super) struct ParsedHardenedSd {
        sd: LocalAllocGuard,
        owner: *mut c_void,
        dacl: *mut c_void,
    }

    impl ParsedHardenedSd {
        pub(super) fn from_sddl(sddl: &str) -> Result<Self> {
            let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sd: *mut c_void = std::ptr::null_mut();
            let mut sd_size: u32 = 0;
            // SAFETY: `sddl_w` is NUL-terminated UTF-16; `sd` and `sd_size` are valid out-pointers.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    &mut sd_size,
                )
            };
            if ok == 0 || sd.is_null() {
                let err = std::io::Error::last_os_error();
                return Err(err)
                    .context("ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
            }
            let guard = LocalAllocGuard(sd);

            let mut owner_defaulted: i32 = 0;
            let mut owner: *mut c_void = std::ptr::null_mut();
            // SAFETY: `guard.0` is a valid security descriptor allocated above.
            let owner_ok = unsafe {
                GetSecurityDescriptorOwner(guard.0, &mut owner, &mut owner_defaulted)
            };
            if owner_ok == 0 || (sddl.starts_with("O:") && owner.is_null()) {
                let err = std::io::Error::last_os_error();
                return Err(err).context("GetSecurityDescriptorOwner failed to extract owner SID");
            }

            let mut dacl_present: i32 = 0;
            let mut dacl_defaulted: i32 = 0;
            let mut dacl: *mut c_void = std::ptr::null_mut();
            // SAFETY: `guard.0` is a valid security descriptor allocated above.
            let dacl_ok = unsafe {
                GetSecurityDescriptorDacl(
                    guard.0,
                    &mut dacl_present,
                    &mut dacl,
                    &mut dacl_defaulted,
                )
            };
            if dacl_ok == 0 || dacl_present == 0 || dacl.is_null() {
                let err = std::io::Error::last_os_error();
                return Err(err).context("GetSecurityDescriptorDacl failed to extract DACL");
            }
            Ok(Self {
                sd: guard,
                owner,
                dacl,
            })
        }

        fn as_sd_ptr(&self) -> *mut c_void {
            self.sd.0
        }

        pub(super) fn as_owner_ptr(&self) -> *mut c_void {
            self.owner
        }

        pub(super) fn as_dacl_ptr(&self) -> *mut c_void {
            self.dacl
        }
    }

    fn encode_wide_nul(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn is_reparse_point_attrs(attrs: u32) -> bool {
        attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }

    pub(super) fn path_attributes_no_follow(path: &Path) -> std::io::Result<Option<u32>> {
        let wide = encode_wide_nul(path);
        // SAFETY: `wide` is valid NUL-terminated UTF-16 for `GetFileAttributesW`.
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs != INVALID_FILE_ATTRIBUTES {
            return Ok(Some(attrs));
        }
        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        ) || err.kind() == ErrorKind::NotFound
        {
            return Ok(None);
        }
        Err(err)
    }

    /// Returns `true` when `path` is an NTFS reparse point (or fails attribute inspection).
    pub(super) fn is_reparse_point(path: &Path) -> bool {
        match path_attributes_no_follow(path) {
            Ok(Some(attrs)) => is_reparse_point_attrs(attrs),
            Ok(None) => false,
            Err(_) => true,
        }
    }

    pub(super) fn reject_reparse_point(path: &Path) -> Result<()> {
        if let Some(attrs) = path_attributes_no_follow(path)
            .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                bail!("refusing to access NTFS reparse point: {}", path.display());
            }
        }
        Ok(())
    }

    fn reject_reparse_point_or_dir(path: &Path) -> Result<()> {
        if let Some(attrs) = path_attributes_no_follow(path)
            .with_context(|| format!("failed to inspect attributes for {}", path.display()))?
        {
            if is_reparse_point_attrs(attrs) {
                bail!("refusing to access NTFS reparse point: {}", path.display());
            }
            if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
                bail!(
                    "refusing to treat directory as state file: {}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    fn create_dir_with_hardened_dacl(dir: &Path) -> Result<()> {
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create ancestor directory {}", parent.display())
                })?;
            }
        }
        let dir_w = encode_wide_nul(dir);
        let parsed_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_SDDL)?;
        let mut sa = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: parsed_sd.as_sd_ptr(),
            b_inherit_handle: 0,
        };
        // SAFETY: `dir_w` is NUL-terminated UTF-16 and `sa` borrows `parsed_sd` synchronously.
        let ok = unsafe {
            CreateDirectoryW(dir_w.as_ptr(), (&mut sa as *mut SecurityAttributes).cast())
        };
        if ok != 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
            return Ok(());
        }
        if !crate::platform::windows_service::is_elevated()
            && matches!(
                err.raw_os_error(),
                Some(ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD)
            )
        {
            let fallback_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_DACL_ONLY_SDDL)?;
            let mut fallback_sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: fallback_sd.as_sd_ptr(),
                b_inherit_handle: 0,
            };
            // SAFETY: `dir_w` is NUL-terminated UTF-16 and `fallback_sa` borrows `fallback_sd`.
            let fallback_ok = unsafe {
                CreateDirectoryW(
                    dir_w.as_ptr(),
                    (&mut fallback_sa as *mut SecurityAttributes).cast(),
                )
            };
            if fallback_ok != 0 {
                return Ok(());
            }
            let fallback_err = std::io::Error::last_os_error();
            if fallback_err.raw_os_error() == Some(ERROR_ALREADY_EXISTS) {
                return Ok(());
            }
            return Err(fallback_err)
                .with_context(|| format!("failed to create hardened directory {}", dir.display()));
        }
        Err(err).with_context(|| format!("failed to create hardened directory {}", dir.display()))
    }

    fn open_handle_for_hardening(path: &Path, flags: u32) -> Result<Option<(HandleGuard, bool)>> {
        let path_w = encode_wide_nul(path);
        // SAFETY: `path_w` is valid NUL-terminated UTF-16; handle is owned by `HandleGuard`.
        let raw_handle = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                flags,
                std::ptr::null_mut(),
            )
        };
        if !raw_handle.is_null() && raw_handle != INVALID_HANDLE_VALUE {
            return Ok(Some((HandleGuard(raw_handle), true)));
        }
        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
        ) || err.kind() == ErrorKind::NotFound
        {
            return Ok(None);
        }
        if !crate::platform::windows_service::is_elevated()
            && matches!(
                err.raw_os_error(),
                Some(ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD)
            )
        {
            // Graceful fallback when running unelevated in unit tests without `WRITE_OWNER`.
            let fallback_handle = unsafe {
                CreateFileW(
                    path_w.as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    flags,
                    std::ptr::null_mut(),
                )
            };
            if !fallback_handle.is_null() && fallback_handle != INVALID_HANDLE_VALUE {
                return Ok(Some((HandleGuard(fallback_handle), false)));
            }
            let fallback_err = std::io::Error::last_os_error();
            if matches!(
                fallback_err.raw_os_error(),
                Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
            ) || fallback_err.kind() == ErrorKind::NotFound
            {
                return Ok(None);
            }
            return Err(fallback_err).with_context(|| {
                format!("failed to open {} for DACL hardening", path.display())
            });
        }
        Err(err).with_context(|| {
            format!(
                "failed to open {} for owner/DACL hardening",
                path.display()
            )
        })
    }

    fn apply_hardened_security_to_handle(
        raw_handle: HANDLE,
        path: &Path,
        parsed_sd: &ParsedHardenedSd,
        has_write_owner: bool,
    ) -> Result<()> {
        let owner_ptr = parsed_sd.as_owner_ptr();
        if has_write_owner && !owner_ptr.is_null() {
            // SAFETY: `raw_handle` is valid and `parsed_sd` keeps owner SID and DACL alive.
            let status = unsafe {
                SetSecurityInfo(
                    raw_handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    owner_ptr,
                    std::ptr::null_mut(),
                    parsed_sd.as_dacl_ptr(),
                    std::ptr::null_mut(),
                )
            };
            if status == ERROR_SUCCESS {
                return Ok(());
            }
            let allow_non_admin_fallback = !crate::platform::windows_service::is_elevated()
                && matches!(
                    status as i32,
                    ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD
                );
            if !allow_non_admin_fallback {
                return Err(std::io::Error::from_raw_os_error(status as i32)).with_context(|| {
                    format!(
                        "SetSecurityInfo failed to harden owner/DACL on {}",
                        path.display()
                    )
                });
            }
        }

        // SAFETY: `raw_handle` is valid and `parsed_sd` keeps the DACL pointer alive.
        let status = unsafe {
            SetSecurityInfo(
                raw_handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                parsed_sd.as_dacl_ptr(),
                std::ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32)).with_context(|| {
                format!(
                    "SetSecurityInfo failed to harden DACL on {}",
                    path.display()
                )
            });
        }
        Ok(())
    }

    fn apply_hardened_file_dacl(file: &Path) -> Result<()> {
        match path_attributes_no_follow(file)
            .with_context(|| format!("failed to inspect file attributes for {}", file.display()))?
        {
            None => return Ok(()),
            Some(attrs) if is_reparse_point_attrs(attrs) => {
                bail!(
                    "refusing to apply DACL to NTFS reparse point file: {}",
                    file.display()
                );
            }
            Some(attrs) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => {
                bail!(
                    "refusing to apply file DACL to directory path: {}",
                    file.display()
                );
            }
            Some(_) => {}
        }

        let parsed_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_FILE_SDDL)?;
        let Some((guard, has_write_owner)) = open_handle_for_hardening(
            file,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?
        else {
            return Ok(());
        };

        // SAFETY: `info` is a plain C struct initialized before `GetFileInformationByHandle`.
        let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
        let info_ok = unsafe { GetFileInformationByHandle(guard.0, &mut info) };
        if info_ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).with_context(|| {
                format!(
                    "GetFileInformationByHandle failed for file {}",
                    file.display()
                )
            });
        }
        if is_reparse_point_attrs(info.dw_file_attributes) {
            bail!(
                "refusing to apply DACL to NTFS reparse point file: {}",
                file.display()
            );
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            bail!(
                "refusing to apply file DACL to directory path: {}",
                file.display()
            );
        }

        apply_hardened_security_to_handle(guard.0, file, &parsed_sd, has_write_owner)
    }

    pub(super) fn apply_hardened_dir_dacl(dir: &Path) -> Result<()> {
        reject_reparse_point(dir)?;
        let parsed_sd = ParsedHardenedSd::from_sddl(PROGRAMDATA_DIR_SDDL)?;
        let Some((guard, has_write_owner)) = open_handle_for_hardening(
            dir,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?
        else {
            bail!(
                "directory {} disappeared before owner/DACL hardening",
                dir.display()
            );
        };

        // SAFETY: `info` is a plain C struct initialized before `GetFileInformationByHandle`.
        let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
        let info_ok = unsafe { GetFileInformationByHandle(guard.0, &mut info) };
        if info_ok == 0 {
            let err = std::io::Error::last_os_error();
            return Err(err).with_context(|| {
                format!(
                    "GetFileInformationByHandle failed for directory {}",
                    dir.display()
                )
            });
        }
        if is_reparse_point_attrs(info.dw_file_attributes) {
            bail!(
                "refusing to apply DACL to NTFS reparse point directory: {}",
                dir.display()
            );
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 {
            bail!(
                "refusing to apply directory DACL to non-directory path: {}",
                dir.display()
            );
        }

        apply_hardened_security_to_handle(guard.0, dir, &parsed_sd, has_write_owner)?;
        drop(guard);

        // Harden all pre-existing direct non-reparse child files (e.g. `state.json`,
        // `config.toml`, `proxy-state.json`) created before the directory was secured.
        let entries = fs::read_dir(dir).with_context(|| {
            format!(
                "failed to enumerate directory {} for child file hardening",
                dir.display()
            )
        })?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read directory entry in {} for child file hardening",
                    dir.display()
                )
            })?;
            let child = entry.path();
            match path_attributes_no_follow(&child).with_context(|| {
                format!("failed to inspect attributes for {}", child.display())
            })? {
                None => continue,
                Some(attrs)
                    if is_reparse_point_attrs(attrs)
                        || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 =>
                {
                    continue;
                }
                Some(_) => {
                    apply_hardened_file_dacl(&child)?;
                }
            }
        }
        Ok(())
    }

    fn ensure_safe_state_dir(dir: &Path, harden_dacl: bool) -> Result<()> {
        match path_attributes_no_follow(dir)
            .with_context(|| format!("failed to inspect state directory {}", dir.display()))?
        {
            Some(attrs) => {
                if is_reparse_point_attrs(attrs) {
                    bail!(
                        "refusing to use NTFS reparse point as state directory: {}",
                        dir.display()
                    );
                }
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    bail!(
                        "state directory path exists and is not a directory: {}",
                        dir.display()
                    );
                }
            }
            None => {
                if harden_dacl {
                    create_dir_with_hardened_dacl(dir)?;
                } else {
                    fs::create_dir_all(dir).with_context(|| {
                        format!("failed to create state directory {}", dir.display())
                    })?;
                }
                let attrs = path_attributes_no_follow(dir)
                    .with_context(|| format!("failed to verify state directory {}", dir.display()))?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "state directory disappeared after creation: {}",
                            dir.display()
                        )
                    })?;
                if is_reparse_point_attrs(attrs) {
                    bail!(
                        "refusing to use NTFS reparse point as state directory: {}",
                        dir.display()
                    );
                }
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    bail!(
                        "state directory path is not a directory after creation: {}",
                        dir.display()
                    );
                }
            }
        }
        if harden_dacl {
            apply_hardened_dir_dacl(dir)?;
        }
        Ok(())
    }

    fn atomic_replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
        const RETRY_DELAYS_MS: [u64; 5] = [10, 25, 50, 100, 200];

        let src_w = encode_wide_nul(src);
        let dst_w = encode_wide_nul(dst);

        for delay_ms in RETRY_DELAYS_MS.iter().copied().chain(std::iter::once(0)) {
            // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 buffers.
            let ok = unsafe {
                MoveFileExW(
                    src_w.as_ptr(),
                    dst_w.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            };
            if ok != 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            let retryable = matches!(
                err.raw_os_error(),
                Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
            );
            if retryable && delay_ms > 0 {
                std::thread::sleep(Duration::from_millis(delay_ms));
                continue;
            }
            return Err(err);
        }
        Err(std::io::Error::last_os_error())
    }

    pub(super) fn write_state_file_atomically(
        path: &Path,
        payload: &[u8],
        harden_parent_dacl: bool,
    ) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!("state file path has no parent directory: {}", path.display())
            })?;
        ensure_safe_state_dir(parent, harden_parent_dacl)?;
        reject_reparse_point_or_dir(path)?;

        let file_name = path
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|n| !n.is_empty())
            .unwrap_or("state.json");
        let pid = std::process::id();
        let ts_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        let mut created = None;
        for _ in 0..16 {
            let seq = RUNTIME_STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{ts_nanos}.{seq}"));
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&candidate)
            {
                Ok(file) => {
                    created = Some((candidate, file));
                    break;
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!(
                            "failed to create unique temporary state file {}",
                            candidate.display()
                        )
                    });
                }
            }
        }
        let (tmp_path, mut file) = created.ok_or_else(|| {
            anyhow::anyhow!(
                "failed to allocate unique temporary state file in {}",
                parent.display()
            )
        })?;

        let write_res = (|| -> Result<()> {
            file.write_all(payload)?;
            file.sync_all()?;
            Ok(())
        })();
        drop(file);

        if let Err(err) = write_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(err) =
            reject_reparse_point(parent).and_then(|()| reject_reparse_point_or_dir(path))
        {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(err) = atomic_replace_file(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err).with_context(|| {
                format!(
                    "failed to atomically replace {} with {}",
                    path.display(),
                    tmp_path.display()
                )
            });
        }
        if harden_parent_dacl {
            apply_hardened_file_dacl(path)?;
        }
        Ok(())
    }

    pub(super) fn safe_remove_file(path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if is_reparse_point(parent) {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "refusing to remove file inside NTFS reparse point directory: {}",
                        parent.display()
                    ),
                ));
            }
        }
        match path_attributes_no_follow(path)? {
            None => Ok(()),
            Some(attrs) if is_reparse_point_attrs(attrs) => Err(std::io::Error::new(
                ErrorKind::PermissionDenied,
                format!("refusing to remove NTFS reparse point: {}", path.display()),
            )),
            Some(_) => fs::remove_file(path),
        }
    }

    pub(super) fn safe_remove_dir_all(dir: &Path) -> std::io::Result<()> {
        match path_attributes_no_follow(dir)? {
            None => return Ok(()),
            Some(attrs) if is_reparse_point_attrs(attrs) => {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "refusing to recurse into NTFS reparse point directory: {}",
                        dir.display()
                    ),
                ));
            }
            Some(attrs) if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 => {
                return safe_remove_file(dir);
            }
            Some(_) => {}
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let child = entry.path();
            match path_attributes_no_follow(&child)? {
                None => continue,
                Some(attrs) if is_reparse_point_attrs(attrs) => {
                    return Err(std::io::Error::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "refusing to traverse or delete NTFS reparse point: {}",
                            child.display()
                        ),
                    ));
                }
                Some(attrs) if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 => {
                    safe_remove_dir_all(&child)?;
                }
                Some(_) => {
                    fs::remove_file(&child)?;
                }
            }
        }
        fs::remove_dir(dir)
    }

    fn fold_ascii_wide(u: u16) -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&u) {
            u + 32
        } else {
            u
        }
    }

    fn os_str_eq_ignore_ascii_case(a: &OsStr, b: &OsStr) -> bool {
        a.encode_wide()
            .map(fold_ascii_wide)
            .eq(b.encode_wide().map(fold_ascii_wide))
    }

    fn prefix_eq_ignore_ascii_case(a: &OsStr, b: &OsStr) -> bool {
        const VERBATIM: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
        let normalize = |s: &OsStr| -> Vec<u16> {
            let wide: Vec<u16> = s.encode_wide().collect();
            wide.strip_prefix(&VERBATIM)
                .unwrap_or(&wide)
                .iter()
                .copied()
                .map(fold_ascii_wide)
                .collect()
        };
        normalize(a) == normalize(b)
    }

    pub(super) fn is_path_under_dir_ascii_ci(dir: &Path, base: &Path) -> bool {
        use std::path::Component;

        if dir.components().any(|c| matches!(c, Component::ParentDir))
            || base.components().any(|c| matches!(c, Component::ParentDir))
        {
            return false;
        }
        let mut base_comps = base.components().peekable();
        if base_comps.peek().is_none() {
            return false;
        }
        let mut dir_comps = dir.components();
        for base_comp in base_comps {
            let Some(dir_comp) = dir_comps.next() else {
                return false;
            };
            let matched = match (dir_comp, base_comp) {
                (Component::RootDir, Component::RootDir) => true,
                (Component::CurDir, Component::CurDir) => true,
                (Component::Prefix(a), Component::Prefix(b)) => {
                    prefix_eq_ignore_ascii_case(a.as_os_str(), b.as_os_str())
                }
                (Component::Normal(a), Component::Normal(b)) => os_str_eq_ignore_ascii_case(a, b),
                _ => false,
            };
            if !matched {
                return false;
            }
        }
        true
    }

    pub(super) fn is_under_programdata_vdpi(dir: &Path) -> bool {
        let pd = std::env::var_os("ProgramData")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
            .join("vdpi");
        is_path_under_dir_ascii_ci(dir, &pd)
    }
}

#[cfg(unix)]
static UNIX_RUNTIME_STATE_TMP_SEQ: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(unix)]
fn write_unix_runtime_state_atomically(path: &Path, payload: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::Ordering;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    ensure_no_symlink_under_user_home(path)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("state file path has no parent directory: {}", path.display())
        })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create state directory {}", parent.display()))?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if is_unix_root() {
        let under_sudo_home = resolve_sudo_invoking_user()
            .is_some_and(|u| parent.starts_with(&u.home_dir));
        if !under_sudo_home {
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
        }
    }

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!(
                "refusing to replace symlink runtime state file: {}",
                path.display()
            );
        }
        if meta.is_dir() {
            bail!(
                "refusing to treat directory as runtime state file: {}",
                path.display()
            );
        }
    }

    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|n| !n.is_empty())
        .unwrap_or("state.json");
    let pid = std::process::id();
    let ts_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let mut created = None;
    for _ in 0..16 {
        let seq = UNIX_RUNTIME_STATE_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{ts_nanos}.{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create unique temporary runtime state file {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    let (tmp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary runtime state file in {}",
            parent.display()
        )
    })?;

    let write_res = (|| -> Result<()> {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set 0600 permissions on temporary runtime state fd {}",
                    tmp_path.display()
                )
            })?;
        file.write_all(payload)?;
        file.sync_all()?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Err(err) = ensure_no_symlink_under_user_home(path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
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

pub fn write_runtime_state_with_meta(
    primary_addr: SocketAddr,
    socks_addr: Option<SocketAddr>,
    engine: EngineMode,
    tun_interface: Option<String>,
    env_activated_at: Option<u64>,
) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    let state = RuntimeState {
        pid: std::process::id(),
        addr: primary_addr.ip(),
        port: primary_addr.port(),
        socks_port: socks_addr.map(|a| a.port()),
        engine,
        tun_interface,
        env_activated_at,
    };
    let Ok(json) = serde_json::to_string(&state) else {
        return;
    };

    #[cfg(target_os = "windows")]
    {
        let harden_parent_dacl = crate::platform::windows::is_running_as_service()
            || path
                .parent()
                .is_some_and(win_fs_hardening::is_under_programdata_vdpi);
        let _ = win_fs_hardening::write_state_file_atomically(
            &path,
            json.as_bytes(),
            harden_parent_dacl,
        );
    }

    #[cfg(unix)]
    {
        let _ = write_unix_runtime_state_atomically(&path, json.as_bytes());
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        if let Some(parent) = path.parent() {
            if fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        let tmp = path.with_extension("json.tmp");
        if fs::write(&tmp, json).is_ok() {
            let _ = fs::rename(&tmp, &path);
        }
    }
}

pub fn clear_runtime_state(expected_pid: u32) {
    let Some(path) = runtime_state_write_path() else {
        return;
    };
    #[cfg(target_os = "windows")]
    if path.parent().is_some_and(win_fs_hardening::is_reparse_point)
        || win_fs_hardening::is_reparse_point(&path)
    {
        return;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if ensure_no_symlink_under_user_home(&path).is_err() {
        return;
    }
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
            if state.pid == expected_pid {
                #[cfg(target_os = "windows")]
                let _ = win_fs_hardening::safe_remove_file(&path);
                #[cfg(not(target_os = "windows"))]
                let _ = fs::remove_file(&path);
            }
        }
    }
}

pub fn read_runtime_states() -> Vec<RuntimeState> {
    let mut states = Vec::new();
    for path in runtime_state_read_paths() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(state) = serde_json::from_str::<RuntimeState>(&raw) {
                if !states.contains(&state) {
                    states.push(state);
                }
            }
        }
    }
    states
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn parse_nonzero_sudo_uid(raw: Option<&std::ffi::OsStr>) -> Option<u32> {
    raw?.to_str()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|&uid| uid != 0)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixTargetUser {
    uid: u32,
    gid: u32,
    #[cfg(target_os = "linux")]
    username: Option<String>,
    home_dir: PathBuf,
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_user_by_uid(uid: u32) -> Option<UnixTargetUser> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt;

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
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    #[cfg(target_os = "linux")]
    let username = if pwd.pw_name.is_null() {
        None
    } else {
        // SAFETY: `pw_name` is a valid NUL-terminated C string inside `buf`.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        (!name.is_empty()).then_some(name)
    };
    Some(UnixTargetUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        #[cfg(target_os = "linux")]
        username,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn lookup_unix_user_by_name(name: &str) -> Option<UnixTargetUser> {
    use std::ffi::{CStr, CString, OsStr};
    use std::os::unix::ffi::OsStrExt;

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
    if pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` is a valid NUL-terminated C string inside `buf`.
    let dir_bytes = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    if dir_bytes.is_empty() {
        return None;
    }
    #[cfg(target_os = "linux")]
    let username = if pwd.pw_name.is_null() {
        Some(name.to_string())
    } else {
        // SAFETY: `pw_name` is a valid NUL-terminated C string inside `buf`.
        let resolved = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        (!resolved.is_empty()).then_some(resolved)
    };
    Some(UnixTargetUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        #[cfg(target_os = "linux")]
        username,
        home_dir: PathBuf::from(OsStr::from_bytes(dir_bytes)),
    })
}

/// Resolves the invoking non-root user when running as root under `sudo`, `pkexec`,
/// `doas`, or macOS `osascript ... with administrator privileges` (`geteuid() == 0`),
/// querying `libc::getpwuid_r` / `libc::getpwnam_r` so service management and uninstall
/// target the real user's session, home directory, and `config.toml` instead of
/// `/root` / `/var/root` / `gui/0`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_sudo_invoking_user() -> Option<UnixTargetUser> {
    if !is_unix_root() {
        return None;
    }
    let fallback_home = std::env::var_os("HOME")
        .filter(|v| {
            !v.is_empty()
                && Path::new(v) != Path::new("/root")
                && Path::new(v) != Path::new("/var/root")
        })
        .map(PathBuf::from);
    if let Some(sudo_uid) = parse_nonzero_sudo_uid(std::env::var_os("SUDO_UID").as_deref()) {
        if let Some(user) = lookup_unix_user_by_uid(sudo_uid) {
            return Some(user);
        }
        if let Some(home) = fallback_home.clone() {
            let gid =
                parse_nonzero_sudo_uid(std::env::var_os("SUDO_GID").as_deref()).unwrap_or(sudo_uid);
            #[cfg(target_os = "linux")]
            let username = std::env::var("SUDO_USER")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && s != "root" && !s.contains('/') && !s.contains('\0'));
            return Some(UnixTargetUser {
                uid: sudo_uid,
                gid,
                #[cfg(target_os = "linux")]
                username,
                home_dir: home,
            });
        }
    }
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        let trimmed = sudo_user.trim();
        if !trimmed.is_empty()
            && trimmed != "root"
            && !trimmed.contains('/')
            && !trimmed.contains('\0')
        {
            if let Some(user) = lookup_unix_user_by_name(trimmed).filter(|u| u.uid != 0) {
                return Some(user);
            }
        }
    }
    if let Some(pkexec_uid) = parse_nonzero_sudo_uid(std::env::var_os("PKEXEC_UID").as_deref()) {
        if let Some(user) = lookup_unix_user_by_uid(pkexec_uid) {
            return Some(user);
        }
        if let Some(home) = fallback_home.clone() {
            return Some(UnixTargetUser {
                uid: pkexec_uid,
                gid: pkexec_uid,
                #[cfg(target_os = "linux")]
                username: None,
                home_dir: home,
            });
        }
    }
    if let Ok(doas_user) = std::env::var("DOAS_USER") {
        let trimmed = doas_user.trim();
        if !trimmed.is_empty()
            && trimmed != "root"
            && !trimmed.contains('/')
            && !trimmed.contains('\0')
        {
            if let Some(user) = lookup_unix_user_by_name(trimmed).filter(|u| u.uid != 0) {
                return Some(user);
            }
        }
    }
    // Fallback for macOS `osascript ... with administrator privileges` (and setuid
    // elevation paths) where euid == 0 and SUDO_*/PKEXEC_*/DOAS_* are absent while
    // `getuid()` still identifies the invoking non-root user.
    // SAFETY: `getuid(2)` is always safe to call and never fails.
    let ruid = unsafe { libc::getuid() };
    if ruid != 0 {
        if let Some(user) = lookup_unix_user_by_uid(ruid) {
            return Some(user);
        }
        if let Some(home) = fallback_home {
            // SAFETY: `getgid(2)` is always safe to call and never fails.
            let rgid = unsafe { libc::getgid() };
            let gid = if rgid != 0 { rgid } else { ruid };
            return Some(UnixTargetUser {
                uid: ruid,
                gid,
                #[cfg(target_os = "linux")]
                username: None,
                home_dir: home,
            });
        }
    }
    None
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
static UNIX_SAFE_WRITE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn chown_to_sudo_user(path: &Path) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let Some(sudo_user) = resolve_sudo_invoking_user() else {
        return;
    };
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return;
    };
    // SAFETY: `c_path` is a valid NUL-terminated path string; `lchown` never follows symlinks.
    unsafe {
        let _ = libc::lchown(c_path.as_ptr(), sudo_user.uid, sudo_user.gid);
    }
}

/// Refuses to write into, delete through, or traverse any symlink located beneath
/// `base_dir` (e.g., the invoking non-root user's home directory while running as `root`).
#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn ensure_no_symlink_under_base(base_dir: &Path, path: &Path) -> Result<()> {
    use std::path::Component;

    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        bail!(
            "refusing to access path containing parent directory traversal ('..'): {}",
            path.display()
        );
    }
    if !path.starts_with(base_dir) {
        return Ok(());
    }
    let Ok(rel) = path.strip_prefix(base_dir) else {
        return Ok(());
    };
    if rel.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!(
            "refusing to access path containing parent directory traversal ('..'): {}",
            path.display()
        );
    }
    let mut cur = base_dir.to_path_buf();
    for comp in rel.components() {
        if matches!(comp, Component::ParentDir) {
            bail!(
                "refusing to access path containing parent directory traversal ('..'): {}",
                path.display()
            );
        }
        cur.push(comp);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "refusing to access through symlink '{}' under user home while running as root",
                    cur.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect path {}", cur.display()));
            }
        }
    }
    Ok(())
}

/// Refuses to write into, delete through, or traverse any symlink located beneath the
/// invoking non-root user's home directory while running as `root` under `sudo`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_no_symlink_under_user_home(path: &Path) -> Result<()> {
    let Some(sudo_user) = resolve_sudo_invoking_user() else {
        return Ok(());
    };
    ensure_no_symlink_under_base(&sudo_user.home_dir, path)
}

/// Creates `dir` (and missing parent directories) after verifying no symlink
/// exists along the user-home subpath when running under `sudo`, and `lchown`s
/// any newly created (or root-owned) directories beneath the invoking user's home.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn create_dir_all_for_unix_user(dir: &Path) -> Result<()> {
    ensure_no_symlink_under_user_home(dir)?;

    let missing_under_home: Vec<PathBuf> = if let Some(sudo_user) = resolve_sudo_invoking_user() {
        if dir.starts_with(&sudo_user.home_dir) {
            let mut missing = Vec::new();
            let mut cur = dir.to_path_buf();
            while cur != sudo_user.home_dir && cur.starts_with(&sudo_user.home_dir) {
                if fs::symlink_metadata(&cur).is_err() {
                    missing.push(cur.clone());
                }
                let Some(parent) = cur.parent() else {
                    break;
                };
                cur = parent.to_path_buf();
            }
            missing.reverse();
            missing
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    for created in &missing_under_home {
        chown_to_sudo_user(created);
    }
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        use std::os::unix::fs::MetadataExt;
        if dir.starts_with(&sudo_user.home_dir) && dir != sudo_user.home_dir {
            if let Ok(meta) = fs::symlink_metadata(dir) {
                if !meta.file_type().is_symlink() && meta.uid() == 0 {
                    chown_to_sudo_user(dir);
                }
            }
        }
    }
    Ok(())
}

/// Atomically writes `contents` to `path` beneath a user's home directory without
/// following symlinks, creating a unique temporary file with `O_CREAT | O_EXCL | O_NOFOLLOW`
/// and assigning ownership via `lchown` when running under `sudo`.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_unix_user_file_safely(path: &Path, contents: &[u8]) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::atomic::Ordering;

    ensure_no_symlink_under_user_home(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("failed to determine parent directory for user file")?;
    create_dir_all_for_unix_user(parent)?;

    let file_name = path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("vdpi.file");
    let pid = std::process::id();

    let mut created = None;
    for _ in 0..16 {
        let seq = UNIX_SAFE_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create temporary file {}", candidate.display())
                });
            }
        }
    }
    let (tmp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary file in {}",
            parent.display()
        )
    })?;

    if let Err(err) = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write temporary file {}", tmp_path.display()))
    {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    drop(file);

    chown_to_sudo_user(&tmp_path);
    if let Err(err) = fs::rename(&tmp_path, path) {
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

/// Returns `true` only when `path` is a root-owned, non-symlink, non-group/world-writable
/// regular executable outside any user `~/.vdpi` tree. Prevents `root` from executing
/// user-controlled binaries during version discovery.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_root_trusted_executable(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    if meta.uid() != 0 || (meta.mode() & 0o022) != 0 {
        return false;
    }
    if let Ok(user_root) = vdpi_root_dir() {
        if path.starts_with(&user_root) {
            return false;
        }
    }
    true
}

fn resolved_user_config_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(sudo_user) = resolve_sudo_invoking_user() {
            return sudo_user.home_dir.join(".vdpi").join("config.toml");
        }
        config_file::user_config_path()
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(sudo_user) = resolve_sudo_invoking_user() {
            if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| {
                    use std::path::Component;
                    !p.components().any(|c| matches!(c, Component::ParentDir))
                        && p.starts_with(&sudo_user.home_dir)
                        && p.strip_prefix(&sudo_user.home_dir).is_ok_and(|rel| {
                            !rel.components()
                                .any(|c| matches!(c, Component::ParentDir))
                        })
                })
            {
                return xdg.join("vdpi").join("config.toml");
            }
            return sudo_user
                .home_dir
                .join(".config")
                .join("vdpi")
                .join("config.toml");
        }
        config_file::user_config_path()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        config_file::user_config_path()
    }
}

pub fn home_dir() -> Result<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        return Ok(sudo_user.home_dir);
    }
    if let Some(h) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(h));
    }
    if let Some(up) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(up));
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if let Some(user) = lookup_unix_user_by_uid(unsafe { libc::getuid() }) {
        return Ok(user.home_dir);
    }
    bail!("neither HOME nor USERPROFILE environment variable is set")
}

pub fn vdpi_root_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            return Ok(PathBuf::from(program_files).join("vdpi"));
        }
        Ok(PathBuf::from(r"C:\Program Files").join("vdpi"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(home_dir()?.join(".vdpi"))
    }
}

pub fn installed_binary_path() -> Result<PathBuf> {
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    Ok(vdpi_root_dir()?.join("bin").join(bin_name))
}

/// Snapshot of an existing `vdpi` installation discovered on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledInfo {
    pub binary_path: PathBuf,
    pub installed_version: Option<String>,
    pub current_version: &'static str,
    pub relation: VersionRelation,
    pub running_from_installed: bool,
}

/// Detects whether `vdpi` is installed in its standard service location and
/// probes the installed binary's version offline without network requests.
pub fn detect_installed_info() -> Option<InstalledInfo> {
    let installed = installed_binary_path().ok().filter(|p| p.is_file());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let binary_path = {
        let sys_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
        #[cfg(target_os = "macos")]
        let has_system_daemon = launch_daemon_plist_path().exists();
        #[cfg(target_os = "linux")]
        let has_system_daemon = systemd_system_unit_path().exists();

        if has_system_daemon && sys_bin.is_file() {
            sys_bin
        } else {
            installed.or_else(|| sys_bin.is_file().then_some(sys_bin))?
        }
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let binary_path = installed?;

    let running_from_installed = std::env::current_exe().ok().is_some_and(|current_exe| {
        match (
            fs::canonicalize(&current_exe),
            fs::canonicalize(&binary_path),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => current_exe == binary_path,
        }
    });

    let current_version = env!("CARGO_PKG_VERSION");

    let (installed_version, relation) = if running_from_installed {
        (Some(current_version.to_string()), VersionRelation::Same)
    } else {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let allow_probe = !is_unix_root() || is_root_trusted_executable(&binary_path);
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let allow_probe = true;

        if !allow_probe {
            (None, VersionRelation::Unknown)
        } else {
            let installed = probe_binary_version(&binary_path);
            let rel = installed.as_deref().map_or(VersionRelation::Unknown, |v| {
                compare_versions(current_version, v)
            });
            (installed, rel)
        }
    };

    Some(InstalledInfo {
        binary_path,
        installed_version,
        current_version,
        relation,
        running_from_installed,
    })
}

/// Registration and runtime status of the OS background service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Running,
    Stopped,
    NotInstalled,
}

/// Live telemetry parsed from the local daemon `/vdpi-health` endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveEngineStatus {
    pub addr: IpAddr,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub engine: EngineMode,
    pub tun_interface: Option<String>,
    pub physical_nic: Option<String>,
    pub vpn_conflict: Option<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
    pub doh: Option<bool>,
    pub dns_addr: Option<String>,
    pub block_quic: Option<bool>,
    pub active_connections: Option<usize>,
    pub total_connections: Option<u64>,
    pub learned_hosts: Option<usize>,
    pub isp_stage: Option<String>,
    pub udp_flows_active: Option<u64>,
    pub quic_blocked: Option<u64>,
    pub dns_queries: Option<u64>,
    pub rss_kb: Option<u64>,
    pub bytes_rx: Option<u64>,
    pub bytes_tx: Option<u64>,
    pub tls_handshakes: Option<u64>,
    pub auto_heal_escalations: Option<u64>,
}

/// Combined local snapshot for the interactive Control Center.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCenterStatus {
    pub installed: Option<InstalledInfo>,
    pub service_state: ServiceState,
    pub live_engine: Option<LiveEngineStatus>,
    pub configured_engine: EngineMode,
    pub vpn_conflict: Option<String>,
}

#[cfg(any(target_os = "windows", test))]
fn resolve_configured_engine_from_paths(
    system_service_installed: bool,
    system_default_when_unset: EngineMode,
    sys_path: &Path,
    user_path: &Path,
    fallback: EngineMode,
) -> EngineMode {
    if system_service_installed {
        if let Ok((Some(_), file_cfg)) = config_file::load_file_config(Some(sys_path), true) {
            return file_cfg.engine.unwrap_or(system_default_when_unset);
        }
        return system_default_when_unset;
    }

    if let Some(engine) = config_file::load_file_config(Some(user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    if let Some(engine) = config_file::load_file_config(Some(sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    fallback
}

fn load_configured_engine(fallback: EngineMode) -> EngineMode {
    #[cfg(target_os = "macos")]
    if launch_daemon_plist_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.engine)
            .unwrap_or(EngineMode::Tun);
    }

    #[cfg(target_os = "linux")]
    if systemd_system_unit_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| file_cfg.engine)
            .unwrap_or(EngineMode::Tun);
    }

    #[cfg(target_os = "windows")]
    if crate::platform::windows_service::query_windows_service_status().installed {
        let sys_path = config_file::system_config_path();
        let user_path = resolved_user_config_path();
        return resolve_configured_engine_from_paths(true, fallback, &sys_path, &user_path, fallback);
    }

    let user_path = resolved_user_config_path();
    if let Some(engine) = config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    let sys_path = config_file::system_config_path();
    if let Some(engine) = config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
    {
        return engine;
    }
    fallback
}

fn resolve_configured_dns_from_paths(
    system_service_installed: bool,
    sys_path: &Path,
    user_path: &Path,
    fallback: &str,
) -> String {
    let fallback_normalized = vdpi_core::dns::validate_custom_dns_input(fallback)
        .unwrap_or_else(|_| fallback.to_string());

    if system_service_installed {
        if let Ok((Some(_), file_cfg)) = config_file::load_file_config(Some(sys_path), true) {
            return file_cfg
                .dns_addr
                .and_then(|s| vdpi_core::dns::validate_custom_dns_input(&s).ok())
                .unwrap_or(fallback_normalized);
        }
        return fallback_normalized;
    }

    if let Some(dns) = config_file::load_file_config(Some(user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.dns_addr)
        .and_then(|s| vdpi_core::dns::validate_custom_dns_input(&s).ok())
    {
        return dns;
    }
    if let Some(dns) = config_file::load_file_config(Some(sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.dns_addr)
        .and_then(|s| vdpi_core::dns::validate_custom_dns_input(&s).ok())
    {
        return dns;
    }
    fallback_normalized
}

/// Loads the currently configured upstream DNS server address from the active
/// `config.toml` (system config when a system service is installed, otherwise
/// user config with fallback to system config and runtime default).
pub fn load_configured_dns(fallback: &str) -> String {
    #[cfg(target_os = "macos")]
    let system_service_installed = launch_daemon_plist_path().exists();
    #[cfg(target_os = "linux")]
    let system_service_installed = systemd_system_unit_path().exists();
    #[cfg(target_os = "windows")]
    let system_service_installed =
        crate::platform::windows_service::query_windows_service_status().installed;
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let system_service_installed = false;

    let sys_path = config_file::system_config_path();
    let user_path = resolved_user_config_path();
    resolve_configured_dns_from_paths(system_service_installed, &sys_path, &user_path, fallback)
}

fn extract_split_tunnel_from_file_config(
    file_cfg: &config_file::FileConfig,
) -> Option<vdpi_core::config::SplitTunnelConfig> {
    if file_cfg.split_tunnel_mode.is_none() && file_cfg.split_tunnel_apps.is_none() {
        return None;
    }
    Some(vdpi_core::config::SplitTunnelConfig {
        mode: file_cfg.split_tunnel_mode.unwrap_or_default(),
        apps: file_cfg
            .split_tunnel_apps
            .as_deref()
            .map(config_file::sanitize_split_tunnel_apps)
            .unwrap_or_default(),
    })
}

/// Loads the currently configured per-application split-tunnel settings from
/// the active `config.toml` (system config when a system service is installed,
/// otherwise user config with fallback to system config and
/// [`vdpi_core::config::SplitTunnelConfig::default`]).
pub fn load_configured_split_tunnel() -> vdpi_core::config::SplitTunnelConfig {
    #[cfg(target_os = "macos")]
    if launch_daemon_plist_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| extract_split_tunnel_from_file_config(&file_cfg))
            .unwrap_or_default();
    }

    #[cfg(target_os = "linux")]
    if systemd_system_unit_path().exists() {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| extract_split_tunnel_from_file_config(&file_cfg))
            .unwrap_or_default();
    }

    #[cfg(target_os = "windows")]
    if crate::platform::windows_service::query_windows_service_status().installed {
        let sys_path = config_file::system_config_path();
        return config_file::load_file_config(Some(&sys_path), true)
            .ok()
            .and_then(|(_, file_cfg)| extract_split_tunnel_from_file_config(&file_cfg))
            .unwrap_or_default();
    }

    let user_path = resolved_user_config_path();
    if let Some(split_tunnel) = config_file::load_file_config(Some(&user_path), false)
        .ok()
        .and_then(|(_, file_cfg)| extract_split_tunnel_from_file_config(&file_cfg))
    {
        return split_tunnel;
    }
    let sys_path = config_file::system_config_path();
    if let Some(split_tunnel) = config_file::load_file_config(Some(&sys_path), true)
        .ok()
        .and_then(|(_, file_cfg)| extract_split_tunnel_from_file_config(&file_cfg))
    {
        return split_tunnel;
    }
    vdpi_core::config::SplitTunnelConfig::default()
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

fn format_rss_label(rss_kb: u64) -> String {
    if rss_kb >= 1024 {
        let mb = (rss_kb.saturating_add(512) / 1024).max(1);
        format!("{mb} MB RSS")
    } else {
        format!("{rss_kb} KB RSS")
    }
}

/// Detects whether the background `vdpi` service is installed and currently running.
pub fn detect_service_state() -> ServiceState {
    #[cfg(target_os = "windows")]
    {
        let svc = crate::platform::windows_service::query_windows_service_status();
        if !svc.installed {
            ServiceState::NotInstalled
        } else if matches!(svc.state, "RUNNING" | "START_PENDING") {
            ServiceState::Running
        } else {
            ServiceState::Stopped
        }
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        if !daemon_exists && !agent_exists {
            return ServiceState::NotInstalled;
        }
        if daemon_exists {
            let target = format!("system/{LAUNCH_DAEMON_LABEL}");
            if launchctl_service_running(&target) {
                return ServiceState::Running;
            }
        }
        if agent_exists {
            let uid = current_uid();
            let target = format!("gui/{uid}/{LAUNCH_AGENT_LABEL}");
            if launchctl_service_running(&target) {
                return ServiceState::Running;
            }
        }
        ServiceState::Stopped
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        if !system_exists && !user_exists {
            return ServiceState::NotInstalled;
        }
        if system_exists && systemd_unit_active(false) {
            return ServiceState::Running;
        }
        if user_exists && systemd_unit_active(true) {
            return ServiceState::Running;
        }
        ServiceState::Stopped
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        ServiceState::NotInstalled
    }
}

/// Parses a `/vdpi-health` JSON payload into a structured [`LiveEngineStatus`].
pub fn parse_health_json(
    body: &str,
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
) -> Option<LiveEngineStatus> {
    let value: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    let obj = value.as_object()?;

    let status = obj.get("status").and_then(serde_json::Value::as_str);
    let service = obj.get("service").and_then(serde_json::Value::as_str);
    if !matches!((status, service), (Some("ok") | None, Some("vdpi"))) {
        return None;
    }

    let engine = match obj.get("engine").and_then(serde_json::Value::as_str) {
        Some(raw) if raw.trim().eq_ignore_ascii_case("tun") => EngineMode::Tun,
        _ => EngineMode::Proxy,
    };

    let non_empty_str = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };

    Some(LiveEngineStatus {
        addr,
        port,
        socks_port,
        engine,
        tun_interface: non_empty_str("tun_interface"),
        physical_nic: non_empty_str("physical_nic"),
        vpn_conflict: non_empty_str("vpn_conflict"),
        version: obj
            .get("version")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        mode: obj
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        doh: obj.get("doh").and_then(serde_json::Value::as_bool),
        dns_addr: non_empty_str("dns_addr"),
        block_quic: obj.get("block_quic").and_then(serde_json::Value::as_bool),
        active_connections: obj
            .get("active_connections")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| usize::try_from(v).ok()),
        total_connections: obj
            .get("total_connections")
            .and_then(serde_json::Value::as_u64),
        learned_hosts: obj
            .get("learned_hosts")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| usize::try_from(v).ok()),
        isp_stage: obj
            .get("isp_stage")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        udp_flows_active: obj
            .get("udp_flows_active")
            .and_then(serde_json::Value::as_u64),
        quic_blocked: obj.get("quic_blocked").and_then(serde_json::Value::as_u64),
        dns_queries: obj.get("dns_queries").and_then(serde_json::Value::as_u64),
        rss_kb: obj.get("rss_kb").and_then(serde_json::Value::as_u64),
        bytes_rx: obj.get("bytes_rx").and_then(serde_json::Value::as_u64),
        bytes_tx: obj.get("bytes_tx").and_then(serde_json::Value::as_u64),
        tls_handshakes: obj
            .get("tls_handshakes")
            .and_then(serde_json::Value::as_u64),
        auto_heal_escalations: obj
            .get("auto_heal_escalations")
            .and_then(serde_json::Value::as_u64),
    })
}

const MAX_HEALTH_RESPONSE_BYTES: usize = 8 * 1024;
const CONTROL_CENTER_PROBE_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeCandidate {
    addr: IpAddr,
    connect_ip: IpAddr,
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

fn build_probe_candidates(cfg: &RuntimeConfig, states: &[RuntimeState]) -> Vec<ProbeCandidate> {
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

    for (addr, port, socks_port) in std::iter::once((cfg.addr, cfg.port, primary_socks))
        .chain(states.iter().map(|s| (s.addr, s.port, s.socks_port)))
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
        out.push(ProbeCandidate {
            addr,
            connect_ip,
            port,
            socks_port,
        });
    }

    out
}

fn probe_local_health(
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
    deadline: Instant,
) -> Option<LiveEngineStatus> {
    const PROBE_CONNECT_CAP: Duration = Duration::from_millis(200);
    const HEALTH_REQUEST: &[u8] =
        b"GET /vdpi-health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";

    if port == 0 {
        return None;
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }

    let connect_ip = probe_connect_ip(addr)?;
    let sock = SocketAddr::new(connect_ip, port);

    let connect_timeout = remaining.min(PROBE_CONNECT_CAP);
    let mut stream = TcpStream::connect_timeout(&sock, connect_timeout).ok()?;

    let write_remaining = deadline.saturating_duration_since(Instant::now());
    if write_remaining.is_zero() {
        return None;
    }
    let _ = stream.set_write_timeout(Some(write_remaining));

    stream.write_all(HEALTH_REQUEST).ok()?;
    let _ = stream.flush();

    let mut raw = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    while raw.len() < MAX_HEALTH_RESPONSE_BYTES {
        let read_remaining = deadline.saturating_duration_since(Instant::now());
        if read_remaining.is_zero() {
            break;
        }
        let _ = stream.set_read_timeout(Some(read_remaining));
        let to_read = buf.len().min(MAX_HEALTH_RESPONSE_BYTES - raw.len());
        match stream.read(&mut buf[..to_read]) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }

    if raw.is_empty() {
        return None;
    }

    let text = String::from_utf8_lossy(&raw);
    let status_line = text.lines().next()?;
    let status_rest = status_line
        .strip_prefix("HTTP/1.1 200")
        .or_else(|| status_line.strip_prefix("HTTP/1.0 200"))?;
    if !status_rest.is_empty() && !status_rest.starts_with(' ') {
        return None;
    }
    let (_, body) = text.split_once("\r\n\r\n")?;

    parse_health_json(body, addr, port, socks_port)
}

/// Performs a fast, synchronous, local-only `/vdpi-health` probe against the given
/// loopback bind address and port, returning parsed [`LiveEngineStatus`] telemetry.
///
/// A `socks_port` of `0` is treated as disabled (`None`).
pub fn probe_live_engine(bind: IpAddr, port: u16, socks_port: u16) -> Option<LiveEngineStatus> {
    let socks_port = (socks_port != 0).then_some(socks_port);
    let deadline = Instant::now() + CONTROL_CENTER_PROBE_BUDGET;
    probe_local_health(bind, port, socks_port, deadline)
}

/// Performs a fast, synchronous, local-only status probe of installation, background
/// service registration, and live loopback daemon health (zero internet calls, zero
/// async runtime spawn).
pub fn probe_control_center_status(cfg: &RuntimeConfig) -> ControlCenterStatus {
    let installed = detect_installed_info();
    let service_state = detect_service_state();
    let configured_engine = load_configured_engine(cfg.engine);
    let states = read_runtime_states();

    let deadline = Instant::now() + CONTROL_CENTER_PROBE_BUDGET;
    let mut live_engine = None;

    for candidate in build_probe_candidates(cfg, &states) {
        if Instant::now() >= deadline {
            break;
        }
        if let Some(status) = probe_local_health(
            candidate.addr,
            candidate.port,
            candidate.socks_port,
            deadline,
        ) {
            live_engine = Some(status);
            break;
        }
    }

    let vpn_conflict = if cfg.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_engine
            .as_ref()
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_engine
                        .as_ref()
                        .and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    ControlCenterStatus {
        installed,
        service_state,
        live_engine,
        configured_engine,
        vpn_conflict,
    }
}

/// Extracts and normalizes a semantic version (`X.Y.Z`) from `vdpi --version` stdout.
pub fn parse_version_from_cli_output(stdout: &str) -> Option<String> {
    let first_line = stdout.lines().find(|line| !line.trim().is_empty())?;
    first_line.split_whitespace().find_map(|token| {
        let (major, minor, patch) =
            parse_semver(token).or_else(|| token.strip_prefix('v').and_then(parse_semver))?;
        Some(format!("{major}.{minor}.{patch}"))
    })
}

/// Probes a `vdpi` binary at `path` by running `path --version` with a bounded timeout
/// and stdout cap, returning the normalized semantic version (`X.Y.Z`) if successful.
pub fn probe_binary_version(path: &Path) -> Option<String> {
    const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
    const POLL_INTERVAL: Duration = Duration::from_millis(25);
    const MAX_PROBE_STDOUT_BYTES: usize = 4 * 1024;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if is_unix_root() && !is_root_trusted_executable(path) {
        return None;
    }

    let mut cmd = Command::new(path);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = cmd.spawn().ok()?;
    let stdout_pipe = child.stdout.take()?;

    let reader_handle = std::thread::spawn(move || {
        let mut pipe = stdout_pipe;
        let mut retained = Vec::new();
        let mut scratch = [0u8; 1024];
        loop {
            match pipe.read(&mut scratch) {
                Ok(0) => break,
                Ok(n) => {
                    if retained.len() < MAX_PROBE_STDOUT_BYTES {
                        let keep = (MAX_PROBE_STDOUT_BYTES - retained.len()).min(n);
                        retained.extend_from_slice(&scratch[..keep]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        retained
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= PROBE_TIMEOUT {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let raw_stdout = reader_handle.join().ok()?;
    let status = status?;
    if !status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&raw_stdout);
    parse_version_from_cli_output(&stdout)
}

pub fn launch_agent_plist_path() -> Result<PathBuf> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LAUNCH_AGENT_LABEL}.plist")))
}

pub fn launch_daemon_plist_path() -> PathBuf {
    PathBuf::from(LAUNCH_DAEMON_PLIST_PATH)
}

pub fn systemd_user_unit_path() -> Result<PathBuf> {
    let home = home_dir().unwrap_or_else(|_| PathBuf::from("."));
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let sudo_invoker = resolve_sudo_invoking_user().is_some();
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let sudo_invoker = false;

    let config_base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| !sudo_invoker || p.starts_with(&home))
        .unwrap_or_else(|| home.join(".config"));
    Ok(config_base
        .join("systemd")
        .join("user")
        .join(SYSTEMD_UNIT_NAME))
}

pub fn systemd_system_unit_path() -> PathBuf {
    PathBuf::from(SYSTEMD_SYSTEM_UNIT_PATH)
}

pub fn build_windows_service_bin_path(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut args = vec!["--service".to_string()];
    args.extend(build_service_cli_args(cfg));
    args.push("--quiet".to_string());
    let quoted_args: Vec<String> = args.into_iter().map(|a| quote_windows_arg(&a)).collect();
    format!("\"{}\" {}", bin_path.display(), quoted_args.join(" "))
}

pub(crate) fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
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

pub fn build_service_cli_args(cfg: &RuntimeConfig) -> Vec<String> {
    let mut args = vec![match cfg.engine {
        EngineMode::Tun => "--tun".to_string(),
        EngineMode::Proxy => "--proxy".to_string(),
    }];
    args.extend([
        "--bind".to_string(),
        cfg.addr.to_string(),
        "--port".to_string(),
        cfg.port.to_string(),
        "--chunk-size".to_string(),
        cfg.chunk_size.to_string(),
    ]);

    if let Some(sp) = cfg.socks_port {
        args.push("--socks-port".to_string());
        args.push(sp.to_string());
    } else {
        args.push("--socks-port".to_string());
        args.push("0".to_string());
    }

    let normalized_dns = vdpi_core::dns::validate_custom_dns_input(&cfg.dns_addr)
        .unwrap_or_else(|_| cfg.dns_addr.trim().to_string());
    if !vdpi_core::dns::effective_enable_doh(&normalized_dns, cfg.enable_doh) {
        args.push("--no-doh".to_string());
    }

    if cfg.mode != DesyncMode::Combo {
        let mode_str = match cfg.mode {
            DesyncMode::Combo => "combo",
            DesyncMode::TlsRecord => "tls-record",
            DesyncMode::Fragment => "fragment",
            DesyncMode::Split => "split",
        };
        args.push("--mode".to_string());
        args.push(mode_str.to_string());
    }

    if !normalized_dns.is_empty() && normalized_dns != "1.1.1.1" {
        args.push("--dns".to_string());
        args.push(normalized_dns);
    }
    if cfg.dns_port != 53 {
        args.push("--dns-port".to_string());
        args.push(cfg.dns_port.to_string());
    }
    if cfg.dns_ipv4_only {
        args.push("--ipv4-only".to_string());
    }
    if cfg.connect_timeout != std::time::Duration::from_secs(8) {
        args.push("--timeout".to_string());
        args.push(cfg.connect_timeout.as_millis().to_string());
    }
    if !cfg.system_proxy {
        args.push("--no-system-proxy".to_string());
    } else {
        if !cfg.socks_system_proxy && cfg.socks_port.is_some() {
            args.push("--no-socks-proxy".to_string());
        }
        if !cfg.env_proxy {
            args.push("--no-env-proxy".to_string());
        }
    }
    if !cfg.block_quic {
        args.push("--allow-quic".to_string());
    }
    if cfg.tun_ipv6 {
        args.push("--tun-ipv6".to_string());
    }
    if cfg.vpn_coexistence != VpnCoexistence::AutoYield {
        args.push("--vpn-coexistence".to_string());
        args.push(cfg.vpn_coexistence.as_str().to_string());
    }
    for pattern in &cfg.patterns {
        args.push("--include".to_string());
        args.push(pattern.clone());
    }
    for domain in &cfg.bypass_domains {
        args.push("--bypass".to_string());
        args.push(domain.clone());
    }
    if cfg.split_tunnel.mode != vdpi_core::config::SplitTunnelMode::All {
        args.push("--split-mode".to_string());
        args.push(cfg.split_tunnel.mode.as_str().to_string());
    }
    for app in config_file::sanitize_split_tunnel_apps(&cfg.split_tunnel.apps) {
        if app.starts_with('-') {
            args.push(format!("--split-app={app}"));
        } else {
            args.push("--split-app".to_string());
            args.push(app);
        }
    }
    if cfg.debug {
        args.push("--debug".to_string());
    }

    args
}

pub fn generate_launch_agent_plist(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut proxy_cfg = cfg.clone();
    proxy_cfg.engine = EngineMode::Proxy;

    let log_dir = vdpi_root_dir()
        .map(|r| r.join("logs"))
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    let out_log = log_dir.join("vdpi.out.log");
    let err_log = log_dir.join("vdpi.err.log");

    let mut args = vec![bin_path.display().to_string()];
    args.extend(build_service_cli_args(&proxy_cfg));

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
</dict>
</plist>
"#,
        label = LAUNCH_AGENT_LABEL,
        args_xml = args_xml,
        out_log = xml_escape(&out_log.display().to_string()),
        err_log = xml_escape(&err_log.display().to_string()),
    )
}

/// Generates a root-owned macOS `LaunchDaemon` plist for transparent `EngineMode::Tun`.
pub fn generate_launch_daemon_plist(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut tun_cfg = cfg.clone();
    tun_cfg.engine = EngineMode::Tun;

    let mut args = vec![bin_path.display().to_string()];
    args.extend(build_service_cli_args(&tun_cfg));
    args.push("--config".to_string());
    args.push(MACOS_SYSTEM_CONFIG_PATH.to_string());
    args.push("--quiet".to_string());

    let args_xml: String = args
        .iter()
        .map(|a| format!("        <string>{}</string>", xml_escape(a)))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>ProcessType</key>
    <string>Interactive</string>
    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>65536</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/vdpi.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/vdpi.err.log</string>
</dict>
</plist>
"#,
        label = LAUNCH_DAEMON_LABEL,
        args_xml = args_xml,
    )
}

fn quote_systemd_arg(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\0' => {}
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn generate_systemd_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut proxy_cfg = cfg.clone();
    proxy_cfg.engine = EngineMode::Proxy;

    let bin_str = bin_path.display().to_string();
    let mut exec_parts = vec![quote_systemd_arg(&bin_str)];
    for arg in build_service_cli_args(&proxy_cfg) {
        exec_parts.push(quote_systemd_arg(&arg));
    }
    let exec_start = exec_parts.join(" ");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Local Proxy Engine\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
KillMode=mixed\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=default.target\n"
    )
}

/// Generates a root-owned Linux `systemd` system service unit for transparent
/// `EngineMode::Tun` with full root capabilities and automatic `ExecStopPost` TUN cleanup.
pub fn generate_systemd_system_unit(bin_path: &Path, cfg: &RuntimeConfig) -> String {
    let mut tun_cfg = cfg.clone();
    tun_cfg.engine = EngineMode::Tun;

    let bin_str = bin_path.display().to_string();
    let quoted_bin = quote_systemd_arg(&bin_str);
    let mut exec_parts = vec![quoted_bin.clone()];
    for arg in build_service_cli_args(&tun_cfg) {
        exec_parts.push(quote_systemd_arg(&arg));
    }
    exec_parts.push(quote_systemd_arg("--config"));
    exec_parts.push(quote_systemd_arg(LINUX_SYSTEM_CONFIG_PATH));
    exec_parts.push(quote_systemd_arg("--quiet"));
    let exec_start = exec_parts.join(" ");
    let exec_stop_post = format!("+{quoted_bin} --internal-linux-tun-cleanup");
    format!(
        "[Unit]\n\
Description=vdpi Anti-DPI Transparent TUN Engine\n\
After=network-online.target systemd-resolved.service NetworkManager.service\n\
Wants=network-online.target\n\
StartLimitIntervalSec=60\n\
StartLimitBurst=5\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exec_start}\n\
ExecStopPost={exec_stop_post}\n\
KillMode=mixed\n\
Restart=always\n\
RestartSec=2\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn file_config_from_runtime(cfg: &RuntimeConfig) -> FileConfig {
    let split_tunnel_apps = config_file::sanitize_split_tunnel_apps(&cfg.split_tunnel.apps);
    let normalized_dns = vdpi_core::dns::validate_custom_dns_input(&cfg.dns_addr)
        .unwrap_or_else(|_| cfg.dns_addr.trim().to_string());
    let effective_doh = vdpi_core::dns::effective_enable_doh(&normalized_dns, cfg.enable_doh);
    FileConfig {
        schema_version: Some(CONFIG_SCHEMA_VERSION),
        engine: Some(cfg.engine),
        mode: Some(cfg.mode),
        doh: Some(effective_doh),
        block_quic: Some(cfg.block_quic),
        dns_addr: Some(normalized_dns),
        bypass_domains: (!cfg.bypass_domains.is_empty()).then(|| cfg.bypass_domains.clone()),
        include_domains: (!cfg.patterns.is_empty()).then(|| cfg.patterns.clone()),
        split_tunnel_mode: cfg
            .split_tunnel
            .is_active()
            .then_some(cfg.split_tunnel.mode),
        split_tunnel_apps: (!split_tunnel_apps.is_empty()).then_some(split_tunnel_apps),
        vpn_coexistence: Some(cfg.vpn_coexistence),
        tun_ipv6: Some(cfg.tun_ipv6),
        chunk_size: Some(cfg.chunk_size),
        bind: Some(cfg.addr),
        port: Some(cfg.port),
        socks_port: Some(cfg.socks_port.unwrap_or(0)),
        dns_port: Some(cfg.dns_port),
        ipv4_only: Some(cfg.dns_ipv4_only),
        timeout_ms: u64::try_from(cfg.connect_timeout.as_millis()).ok(),
        system_proxy: Some(cfg.system_proxy),
        socks_system_proxy: Some(cfg.socks_system_proxy),
        env_proxy: Some(cfg.env_proxy),
        language: None,
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn apply_file_config_to_runtime(base: &RuntimeConfig, file_cfg: &FileConfig) -> RuntimeConfig {
    let mut out = base.clone();
    if let Some(engine) = file_cfg.engine {
        out.engine = engine;
    }
    if let Some(mode) = file_cfg.mode {
        out.mode = mode;
    }
    if let Some(doh) = file_cfg.doh {
        out.enable_doh = doh;
    }
    if let Some(block_quic) = file_cfg.block_quic {
        out.block_quic = block_quic;
    }
    if let Some(ref dns_addr) = file_cfg.dns_addr {
        if let Ok(validated) = vdpi_core::dns::validate_custom_dns_input(dns_addr) {
            out.dns_addr = validated;
        }
    }
    if let Some(ref bypass) = file_cfg.bypass_domains {
        out.bypass_domains.clone_from(bypass);
    }
    if let Some(ref include) = file_cfg.include_domains {
        out.patterns.clone_from(include);
    }
    if let Some(split_mode) = file_cfg.split_tunnel_mode {
        out.split_tunnel.mode = split_mode;
    }
    if let Some(ref split_apps) = file_cfg.split_tunnel_apps {
        out.split_tunnel.apps = config_file::sanitize_split_tunnel_apps(split_apps);
    }
    if let Some(vpn_coexistence) = file_cfg.vpn_coexistence {
        out.vpn_coexistence = vpn_coexistence;
    }
    if let Some(tun_ipv6) = file_cfg.tun_ipv6 {
        out.tun_ipv6 = tun_ipv6;
    }
    if let Some(chunk_size) = file_cfg.chunk_size {
        out.chunk_size = chunk_size.max(1);
    }
    if let Some(bind) = file_cfg.bind {
        out.addr = bind;
    }
    if let Some(port) = file_cfg.port {
        out.port = port;
    }
    if let Some(socks_port) = file_cfg.socks_port {
        out.socks_port = if socks_port == 0 || socks_port == out.port {
            None
        } else {
            Some(socks_port)
        };
    }
    if let Some(dns_port) = file_cfg.dns_port {
        out.dns_port = dns_port;
    }
    if let Some(ipv4_only) = file_cfg.ipv4_only {
        out.dns_ipv4_only = ipv4_only;
    }
    if let Some(timeout_ms) = file_cfg.timeout_ms {
        out.connect_timeout = if timeout_ms == 0 {
            Duration::from_millis(8000)
        } else {
            Duration::from_millis(timeout_ms)
        };
    }
    if let Some(system_proxy) = file_cfg.system_proxy {
        out.system_proxy = system_proxy;
    }
    if let Some(socks_system_proxy) = file_cfg.socks_system_proxy {
        out.socks_system_proxy = out.system_proxy && socks_system_proxy && out.socks_port.is_some();
    }
    if let Some(env_proxy) = file_cfg.env_proxy {
        out.env_proxy = out.system_proxy && env_proxy;
    }
    if out.socks_port == Some(out.port) {
        out.socks_port = None;
    }
    if !out.system_proxy {
        out.socks_system_proxy = false;
        out.env_proxy = false;
    }
    if out.socks_port.is_none() {
        out.socks_system_proxy = false;
    }
    out.enable_doh = vdpi_core::dns::effective_enable_doh(&out.dns_addr, out.enable_doh);
    out
}

#[cfg(any(target_os = "windows", test))]
fn split_windows_cmdline(cmdline: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    let chars: Vec<char> = cmdline.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let ch = chars[i];
        if ch == '\\' {
            let mut backslashes = 0usize;
            while i < chars.len() && chars[i] == '\\' {
                backslashes += 1;
                i += 1;
            }
            if i < chars.len() && chars[i] == '"' {
                for _ in 0..(backslashes / 2) {
                    current.push('\\');
                }
                if backslashes % 2 == 1 {
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
                has_token = true;
                i += 1;
            } else {
                for _ in 0..backslashes {
                    current.push('\\');
                }
                has_token = true;
            }
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            has_token = true;
            i += 1;
            continue;
        }
        if !in_quotes && ch.is_ascii_whitespace() {
            if has_token {
                args.push(std::mem::take(&mut current));
                has_token = false;
            }
            i += 1;
            continue;
        }
        current.push(ch);
        has_token = true;
        i += 1;
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Migrates a legacy v0.4.x Windows service `binPath` command line into a v0.5.0
/// [`FileConfig`] with `engine = Some(EngineMode::Proxy)` so `--upgrade` preserves
/// existing proxy behavior and custom flags without disruption.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn migrate_legacy_service_cmdline_to_file_config(cmdline: &str) -> FileConfig {
    let mut cfg = FileConfig {
        schema_version: Some(CONFIG_SCHEMA_VERSION),
        engine: Some(EngineMode::Proxy),
        ..Default::default()
    };

    let tokens = split_windows_cmdline(cmdline);
    let mut bypass = Vec::new();
    let mut include = Vec::new();
    let mut split_apps = Vec::new();

    // Skip argv[0] (executable path).
    let mut i = 1usize;
    while i < tokens.len() {
        let flag = tokens[i].as_str();
        let next = tokens.get(i + 1).map(String::as_str);
        if let Some(raw_mode) = flag.strip_prefix("--split-mode=") {
            if let Ok(parsed) = raw_mode.parse::<vdpi_core::config::SplitTunnelMode>() {
                cfg.split_tunnel_mode = Some(parsed);
            }
            i += 1;
            continue;
        }
        if let Some(raw_app) = flag.strip_prefix("--split-app=") {
            split_apps.push(raw_app.to_string());
            i += 1;
            continue;
        }
        match flag {
            "--bind" | "--addr" => {
                if let Some(ip) = next.and_then(|v| v.parse::<IpAddr>().ok()) {
                    cfg.bind = Some(ip);
                    i += 2;
                    continue;
                }
            }
            "--port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--socks-port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.socks_port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--chunk-size" | "--window-size" => {
                if let Some(sz) = next.and_then(|v| v.parse::<usize>().ok()) {
                    cfg.chunk_size = Some(sz.max(1));
                    i += 2;
                    continue;
                }
            }
            "--mode" | "--strategy" => {
                if let Some(raw) = next {
                    let parsed = match raw.to_ascii_lowercase().as_str() {
                        "combo" => Some(DesyncMode::Combo),
                        "tls-record" | "tlsrec" => Some(DesyncMode::TlsRecord),
                        "fragment" | "chunk" => Some(DesyncMode::Fragment),
                        "split" => Some(DesyncMode::Split),
                        _ => None,
                    };
                    if let Some(mode) = parsed {
                        cfg.mode = Some(mode);
                        i += 2;
                        continue;
                    }
                }
            }
            "--dns" | "--dns-addr" => {
                if let Some(dns) = next {
                    if let Ok(validated) = vdpi_core::dns::validate_custom_dns_input(dns) {
                        cfg.dns_addr = Some(validated);
                    }
                    i += 2;
                    continue;
                }
            }
            "--dns-port" => {
                if let Some(port) = next.and_then(|v| v.parse::<u16>().ok()) {
                    cfg.dns_port = Some(port);
                    i += 2;
                    continue;
                }
            }
            "--timeout" => {
                if let Some(ms) = next.and_then(|v| v.parse::<u64>().ok()) {
                    cfg.timeout_ms = Some(ms);
                    i += 2;
                    continue;
                }
            }
            "--include" | "--pattern" => {
                if let Some(pat) = next {
                    include.push(pat.to_string());
                    i += 2;
                    continue;
                }
            }
            "--bypass" => {
                if let Some(dom) = next {
                    bypass.push(dom.to_string());
                    i += 2;
                    continue;
                }
            }
            "--split-mode" => {
                if let Some(raw) = next {
                    if let Ok(parsed) = raw.parse::<vdpi_core::config::SplitTunnelMode>() {
                        cfg.split_tunnel_mode = Some(parsed);
                    }
                    i += 2;
                    continue;
                }
            }
            "--split-app" => {
                if let Some(app) = next {
                    split_apps.push(app.to_string());
                    i += 2;
                    continue;
                }
            }
            "--no-doh" => cfg.doh = Some(false),
            "--ipv4-only" | "--dns-ipv4-only" => cfg.ipv4_only = Some(true),
            "--no-system-proxy" => cfg.system_proxy = Some(false),
            "--no-socks-proxy" | "--no-socks-system-proxy" => cfg.socks_system_proxy = Some(false),
            "--no-env-proxy" | "--no-launchd-env" => cfg.env_proxy = Some(false),
            "--allow-quic" | "--no-block-quic" => cfg.block_quic = Some(false),
            "--tun" => cfg.engine = Some(EngineMode::Tun),
            "--proxy" => cfg.engine = Some(EngineMode::Proxy),
            "--tun-ipv6" => cfg.tun_ipv6 = Some(true),
            "--vpn-coexistence" => {
                if let Some(raw) = next {
                    let parsed = match raw.to_ascii_lowercase().as_str() {
                        "auto-yield" => Some(VpnCoexistence::AutoYield),
                        "warn" => Some(VpnCoexistence::Warn),
                        "off" => Some(VpnCoexistence::Off),
                        _ => None,
                    };
                    if let Some(mode) = parsed {
                        cfg.vpn_coexistence = Some(mode);
                        i += 2;
                        continue;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if !bypass.is_empty() {
        cfg.bypass_domains = Some(bypass);
    }
    if !include.is_empty() {
        cfg.include_domains = Some(include);
    }
    let sanitized_split = config_file::sanitize_split_tunnel_apps(&split_apps);
    if !sanitized_split.is_empty() {
        cfg.split_tunnel_apps = Some(sanitized_split);
    }
    if let (Some(ref dns), Some(doh)) = (&cfg.dns_addr, cfg.doh) {
        cfg.doh = Some(vdpi_core::dns::effective_enable_doh(dns, doh));
    }
    cfg
}

/// Installs the `vdpi` binary into the service directory and registers automatic
/// background startup for the active operating system (macOS LaunchAgent/LaunchDaemon,
/// native Windows Service under SCM, or Linux systemd unit).
pub fn install_service(cfg: &RuntimeConfig) -> Result<()> {
    install_service_with_options(cfg, false)
}

/// Quiet variant of [`install_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn install_service_quiet(cfg: &RuntimeConfig) -> Result<()> {
    install_service_with_options_impl(cfg, false, false)
}

pub fn install_service_with_options(cfg: &RuntimeConfig, upgrade: bool) -> Result<()> {
    install_service_with_options_impl(cfg, upgrade, true)
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn install_service_with_options_impl(
    _cfg: &RuntimeConfig,
    _upgrade: bool,
    _verbose: bool,
) -> Result<()> {
    bail!(
        "service installation is not supported on {}",
        platform_name()
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn copy_binary_atomically(current_exe: &Path, target_bin: &Path) -> Result<()> {
    use std::fs::{File, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::Ordering;

    ensure_no_symlink_under_user_home(target_bin)?;
    let bin_dir = target_bin
        .parent()
        .context("failed to determine target binary directory")?;
    create_dir_all_for_unix_user(bin_dir)
        .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;

    let same_binary = match (fs::canonicalize(current_exe), fs::canonicalize(target_bin)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_bin,
    };
    if same_binary {
        return Ok(());
    }

    let pid = std::process::id();
    let mut created = None;
    for _ in 0..16 {
        let seq = UNIX_SAFE_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = bin_dir.join(format!(".vdpi.tmp.{pid}.{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o755)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create temporary binary {}", candidate.display())
                });
            }
        }
    }
    let (tmp_bin, mut dst) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary binary in {}",
            bin_dir.display()
        )
    })?;

    let copy_res = (|| -> Result<()> {
        let mut src = File::open(current_exe)
            .with_context(|| format!("failed to open source executable {}", current_exe.display()))?;
        std::io::copy(&mut src, &mut dst)
            .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))?;
        dst.set_permissions(fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod 0755 {}", tmp_bin.display()))?;
        dst.sync_all()
            .with_context(|| format!("failed to sync {}", tmp_bin.display()))?;
        Ok(())
    })();
    drop(dst);
    if let Err(err) = copy_res {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err);
    }

    #[cfg(target_os = "macos")]
    {
        let already_valid = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&tmp_bin)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !already_valid {
            let output = match Command::new("/usr/bin/codesign")
                .args(["-fs", "-"])
                .arg(&tmp_bin)
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) => out,
                Err(err) => {
                    let _ = fs::remove_file(&tmp_bin);
                    return Err(err).with_context(|| {
                        format!("failed to execute /usr/bin/codesign for {}", tmp_bin.display())
                    });
                }
            };
            if !output.status.success() {
                let _ = fs::remove_file(&tmp_bin);
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                if detail.is_empty() {
                    bail!(
                        "failed to ad-hoc codesign {} (exit status: {})",
                        tmp_bin.display(),
                        output.status
                    );
                }
                bail!("failed to ad-hoc codesign {}: {detail}", tmp_bin.display());
            }
        }
    }

    if let Err(err) = fs::rename(&tmp_bin, target_bin) {
        let _ = fs::remove_file(&tmp_bin);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                target_bin.display(),
                tmp_bin.display()
            )
        });
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn is_retryable_windows_rename_error(err: &std::io::Error) -> bool {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    err.kind() == std::io::ErrorKind::PermissionDenied
        || matches!(
            err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
}

#[cfg(target_os = "windows")]
fn rename_with_windows_retry(from: &Path, to: &Path) -> std::io::Result<()> {
    // Up to 8 attempts with short exponential backoff (25ms..200ms) so transient
    // Windows Defender / antivirus real-time scans never fail install/upgrade.
    const BACKOFF_MS: [u64; 7] = [25, 40, 60, 90, 120, 160, 200];

    for delay_ms in BACKOFF_MS.into_iter().chain(std::iter::once(0)) {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(err) if delay_ms > 0 && is_retryable_windows_rename_error(&err) => {
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("retry loop always returns on final attempt")
}

#[cfg(target_os = "windows")]
struct ReplacedFileBackup {
    target: PathBuf,
    backup: PathBuf,
}

#[cfg(target_os = "windows")]
impl ReplacedFileBackup {
    fn commit(self) {
        let _ = fs::remove_file(self.backup);
    }

    fn rollback(self) {
        if self.target.exists() && fs::remove_file(&self.target).is_err() {
            let displaced = self
                .target
                .with_extension(format!("failed.{}", std::process::id()));
            let _ = rename_with_windows_retry(&self.target, &displaced);
            let _ = fs::remove_file(displaced);
        }
        let _ = rename_with_windows_retry(&self.backup, &self.target);
    }
}

#[cfg(target_os = "windows")]
fn copy_binary_atomically_with_backup(
    current_exe: &Path,
    target_bin: &Path,
    retain_backup: bool,
) -> Result<Option<ReplacedFileBackup>> {
    let bin_dir = target_bin
        .parent()
        .context("failed to determine target binary directory")?;
    fs::create_dir_all(bin_dir)
        .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;

    let same_binary = match (fs::canonicalize(current_exe), fs::canonicalize(target_bin)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_exe == target_bin,
    };
    if same_binary {
        return Ok(None);
    }

    let pid = std::process::id();
    let tmp_bin = bin_dir.join(format!("vdpi.tmp.{pid}.exe"));
    if let Err(err) = fs::copy(current_exe, &tmp_bin)
        .with_context(|| format!("failed to copy {:?} to {:?}", current_exe, tmp_bin))
    {
        let _ = fs::remove_file(tmp_bin);
        return Err(err);
    }

    let backup_path = if target_bin.exists() {
        let preferred = bin_dir.join("vdpi.old.exe");
        let backup = if preferred.exists() && fs::remove_file(&preferred).is_err() {
            bin_dir.join(format!("vdpi.old.{pid}.exe"))
        } else {
            preferred
        };
        if let Err(err) = rename_with_windows_retry(target_bin, &backup) {
            let _ = fs::remove_file(tmp_bin);
            return Err(err).with_context(|| {
                format!(
                    "failed to move existing binary {} aside to {}",
                    target_bin.display(),
                    backup.display()
                )
            });
        }
        Some(backup)
    } else {
        None
    };

    if let Err(err) = rename_with_windows_retry(&tmp_bin, target_bin) {
        let _ = fs::remove_file(tmp_bin);
        if let Some(backup) = backup_path {
            let _ = rename_with_windows_retry(&backup, target_bin);
        }
        return Err(err)
            .with_context(|| format!("failed to install new binary to {}", target_bin.display()));
    }

    match backup_path {
        Some(backup) if retain_backup => Ok(Some(ReplacedFileBackup {
            target: target_bin.to_path_buf(),
            backup,
        })),
        Some(backup) => {
            let _ = fs::remove_file(backup);
            Ok(None)
        }
        None => Ok(None),
    }
}

#[cfg(target_os = "windows")]
fn copy_verified_sibling_wintun(bin_dir: &Path) -> Result<bool> {
    let (copied, _) = copy_verified_sibling_wintun_with_backup(bin_dir, false)?;
    Ok(copied)
}

#[cfg(target_os = "windows")]
fn copy_verified_sibling_wintun_with_backup(
    bin_dir: &Path,
    retain_backup: bool,
) -> Result<(bool, Option<ReplacedFileBackup>)> {
    let Ok(current_exe) = std::env::current_exe() else {
        return Ok((false, None));
    };
    copy_verified_sibling_wintun_from_exe_with_backup(&current_exe, bin_dir, retain_backup)
}

#[cfg(target_os = "windows")]
fn preflight_windows_tun_wintun_with_exe(
    target_bin_dir: Option<&Path>,
    current_exe: Option<&Path>,
    expected_sha256: &str,
    action: &str,
) -> Result<PathBuf> {
    use crate::platform::windows_tun::{
        find_verified_wintun_dll, resolve_wintun_dll_candidates, verify_wintun_dll_sha256,
        WINTUN_VERSION,
    };

    if let Some(bin_dir) = target_bin_dir {
        let target_wintun = bin_dir.join("wintun.dll");
        win_fs_hardening::reject_reparse_point(&target_wintun)
            .with_context(|| format!("cannot {action}"))?;
        if target_wintun.is_file() {
            if let Err(err) = verify_wintun_dll_sha256(&target_wintun, expected_sha256) {
                if let Some(exe) = current_exe {
                    let canonical = fs::canonicalize(exe).ok();
                    if let Some(sibling) = resolve_wintun_dll_candidates(exe, canonical.as_deref())
                        .into_iter()
                        .find(|cand| {
                            !win_fs_hardening::is_reparse_point(cand)
                                && cand.is_file()
                                && verify_wintun_dll_sha256(cand, expected_sha256).is_ok()
                        })
                    {
                        return Ok(sibling);
                    }
                }
                return Err(err).with_context(|| {
                    format!(
                        "cannot {action}: {} (v{WINTUN_VERSION}) is corrupted or mismatched — \
                         extract all files from the zip (keep wintun.dll beside vdpi.exe)",
                        target_wintun.display()
                    )
                });
            }
        }
    }
    find_verified_wintun_dll().with_context(|| {
        format!(
            "cannot {action}: verified wintun.dll (v{WINTUN_VERSION}) is unavailable; \
             place the verified wintun.dll next to vdpi.exe or use Proxy mode"
        )
    })
}

#[cfg(target_os = "windows")]
fn preflight_windows_tun_wintun(target_bin_dir: Option<&Path>, action: &str) -> Result<PathBuf> {
    let expected_sha256 = crate::platform::windows_tun::expected_wintun_dll_sha256()?;
    let current_exe = std::env::current_exe().ok();
    preflight_windows_tun_wintun_with_exe(
        target_bin_dir,
        current_exe.as_deref(),
        expected_sha256,
        action,
    )
}

#[cfg(target_os = "windows")]
fn copy_verified_wintun_to_bin_dir_with_backup(
    src_wintun: &Path,
    bin_dir: &Path,
    retain_backup: bool,
) -> Result<(bool, Option<ReplacedFileBackup>)> {
    let expected_sha256 = crate::platform::windows_tun::expected_wintun_dll_sha256()?;
    crate::platform::windows_tun::verify_wintun_dll_sha256(src_wintun, expected_sha256)?;

    let target_wintun = bin_dir.join("wintun.dll");
    win_fs_hardening::reject_reparse_point(&target_wintun)?;
    let same_file = match (
        fs::canonicalize(src_wintun),
        fs::canonicalize(&target_wintun),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => src_wintun == target_wintun,
    };
    let already_verified = !same_file
        && target_wintun.is_file()
        && crate::platform::windows_tun::verify_wintun_dll_sha256(&target_wintun, expected_sha256)
            .is_ok();
    let skip_copy = same_file || already_verified;

    let retained_backup = if !skip_copy {
        let pid = std::process::id();
        let staged = bin_dir.join(format!("wintun.tmp.{pid}.dll"));
        if let Err(err) = fs::copy(src_wintun, &staged).with_context(|| {
            format!(
                "failed to copy {} to {}",
                src_wintun.display(),
                staged.display()
            )
        }) {
            let _ = fs::remove_file(staged);
            return Err(err);
        }

        let backup_path = if target_wintun.exists() {
            let preferred = bin_dir.join("wintun.old.dll");
            let backup = if preferred.exists() && fs::remove_file(&preferred).is_err() {
                bin_dir.join(format!("wintun.old.{pid}.dll"))
            } else {
                preferred
            };
            if let Err(err) = rename_with_windows_retry(&target_wintun, &backup) {
                let _ = fs::remove_file(staged);
                return Err(err).with_context(|| {
                    format!(
                        "failed to move existing {} aside to {}",
                        target_wintun.display(),
                        backup.display()
                    )
                });
            }
            Some(backup)
        } else {
            None
        };

        if let Err(err) = rename_with_windows_retry(&staged, &target_wintun) {
            let _ = fs::remove_file(staged);
            if let Some(backup) = backup_path {
                let _ = rename_with_windows_retry(&backup, &target_wintun);
            }
            return Err(err).with_context(|| {
                format!(
                    "failed to install wintun.dll to {}",
                    target_wintun.display()
                )
            });
        }

        match backup_path {
            Some(backup) if retain_backup => Some(ReplacedFileBackup {
                target: target_wintun,
                backup,
            }),
            Some(backup) => {
                let _ = fs::remove_file(backup);
                None
            }
            None => None,
        }
    } else {
        None
    };

    if let Some(src_dir) = src_wintun.parent() {
        let license_src = src_dir.join("WINTUN-LICENSE.txt");
        let license_dst = bin_dir.join("WINTUN-LICENSE.txt");
        let need_license = !skip_copy || !license_dst.is_file();
        if need_license
            && win_fs_hardening::reject_reparse_point(&license_src).is_ok()
            && license_src.is_file()
            && win_fs_hardening::reject_reparse_point(&license_dst).is_ok()
            && !same_file
            && license_src != license_dst
        {
            let _ = fs::copy(license_src, license_dst);
        }
    }

    Ok((!skip_copy, retained_backup))
}

#[cfg(target_os = "windows")]
fn copy_verified_sibling_wintun_from_exe_with_backup(
    current_exe: &Path,
    bin_dir: &Path,
    retain_backup: bool,
) -> Result<(bool, Option<ReplacedFileBackup>)> {
    let canonical = fs::canonicalize(current_exe).ok();
    let Some(src_wintun) = crate::platform::windows_tun::resolve_wintun_dll_candidates(
        current_exe,
        canonical.as_deref(),
    )
    .into_iter()
    .find(|cand| !win_fs_hardening::is_reparse_point(cand) && cand.is_file()) else {
        // No sibling wintun.dll next to current_exe; skip copying.
        return Ok((false, None));
    };
    copy_verified_wintun_to_bin_dir_with_backup(&src_wintun, bin_dir, retain_backup)
}

#[cfg(target_os = "windows")]
fn print_windows_stale_browser_hint(cfg: &RuntimeConfig) {
    if cfg.engine != EngineMode::Proxy || !cfg.system_proxy {
        return;
    }
    let stale = crate::platform::windows::detect_stale_browsers(unix_now_secs().saturating_add(1));
    if !stale.is_empty() {
        println!(
            "Hint             : open browser(s) ({}) pick up Windows PAC proxy automatically; for games or apps that ignore system proxy, run 'vdpi engine tun'.",
            stale.join(", ")
        );
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn build_unix_install_sudo_args(effective_cfg: &RuntimeConfig, upgrade: bool) -> Vec<String> {
    if upgrade {
        let mut args = vec!["install".to_string(), "--upgrade".to_string()];
        if effective_cfg.engine == EngineMode::Tun {
            args.push("--tun".to_string());
        }
        return args;
    }
    let mut args = build_service_cli_args(effective_cfg);
    args.push("install".to_string());
    args
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn install_service_with_options_impl(
    cfg: &RuntimeConfig,
    upgrade: bool,
    verbose: bool,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            is_elevated, query_windows_service_status, relaunch_elevated_and_wait,
        };

        let prev_svc = query_windows_service_status();
        let target_bin_dir = installed_binary_path()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        let preflight_tun = if upgrade {
            load_configured_engine(cfg.engine) == EngineMode::Tun
        } else {
            cfg.engine == EngineMode::Tun
        };
        // Preflight verified wintun.dll BEFORE triggering UAC so TUN installs fail
        // immediately with a clear error instead of silently downgrading to Proxy.
        if preflight_tun {
            let _ = preflight_windows_tun_wintun(
                target_bin_dir.as_deref(),
                "install the vdpi Windows service in TUN mode",
            )?;
        }

        // Windows SCM installation/upgrades (TUN or Proxy, fresh or existing service)
        // always require Administrator elevation.
        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to install the vdpi Windows service..."
                );
            }
            let mut args = vec!["install".to_string()];
            if upgrade {
                args.push("--upgrade".to_string());
            } else {
                // `build_service_cli_args` always emits explicit `--proxy` / `--tun`
                // so system `config.toml` cannot flip caller intent across UAC.
                args.extend(build_service_cli_args(cfg));
            }
            relaunch_elevated_and_wait(&args)?;
            notify_wininet_refresh();
            broadcast_environment_change();
            if verbose {
                println!(
                    "Installed and started Windows service: {WINDOWS_SERVICE_NAME} (AUTO_START)"
                );
                if !upgrade {
                    print_windows_stale_browser_hint(cfg);
                }
            }
            return Ok(());
        }

        let config_path = config_file::system_config_path();
        let vdpi_root = vdpi_root_dir()?;
        let bin_dir = vdpi_root.join("bin");
        let log_dir = vdpi_root.join("logs");

        let effective_cfg = if upgrade {
            if config_path.is_file() {
                match config_file::load_file_config(Some(&config_path), true) {
                    Ok((_, file_cfg)) => apply_file_config_to_runtime(cfg, &file_cfg),
                    Err(_) => cfg.clone(),
                }
            } else {
                let migrated = prev_svc
                    .binary_path
                    .as_deref()
                    .map(migrate_legacy_service_cmdline_to_file_config)
                    .unwrap_or_else(|| {
                        let mut fc = file_config_from_runtime(cfg);
                        fc.engine = Some(EngineMode::Proxy);
                        fc
                    });
                apply_file_config_to_runtime(cfg, &migrated)
            }
        } else {
            cfg.clone()
        };

        let verified_tun_wintun = if effective_cfg.engine == EngineMode::Tun {
            Some(preflight_windows_tun_wintun(
                Some(&bin_dir),
                "install the vdpi Windows service in TUN mode",
            )?)
        } else {
            None
        };

        // Stop existing Windows service and any legacy vdpi.exe processes before replacing the binary.
        let prev_was_running =
            prev_svc.installed && matches!(prev_svc.state, "RUNNING" | "START_PENDING");
        if upgrade {
            let _ = crate::platform::windows_service::stop_windows_service_for_upgrade()?;
        } else {
            let _ = crate::platform::windows_service::stop_windows_service_if_running()?;
        }
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();
        let _ = crate::platform::windows_tun::cleanup_orphan_wintun_adapter();

        if upgrade {
            if !config_path.is_file() {
                let migrated = prev_svc
                    .binary_path
                    .as_deref()
                    .map(migrate_legacy_service_cmdline_to_file_config)
                    .unwrap_or_else(|| {
                        let mut fc = file_config_from_runtime(cfg);
                        fc.engine = Some(EngineMode::Proxy);
                        fc
                    });
                config_file::save_file_config_atomic(&config_path, &migrated)?;
            }
        } else {
            let file_cfg = file_config_from_runtime(cfg);
            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        }

        fs::create_dir_all(&bin_dir)
            .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;
        fs::create_dir_all(&log_dir)
            .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;

        let current_exe =
            std::env::current_exe().context("failed to determine current executable")?;
        let target_bin = installed_binary_path()?;
        let bin_backup = copy_binary_atomically_with_backup(&current_exe, &target_bin, upgrade)?;
        let (wintun_copied, wintun_backup) =
            match copy_verified_sibling_wintun_with_backup(&bin_dir, upgrade) {
                Ok((false, None)) => {
                    if let Some(src_wintun) = verified_tun_wintun.as_deref() {
                        match copy_verified_wintun_to_bin_dir_with_backup(
                            src_wintun, &bin_dir, upgrade,
                        ) {
                            Ok(res) => res,
                            Err(err) => {
                                if let Some(backup) = bin_backup {
                                    backup.rollback();
                                }
                                if upgrade && prev_was_running {
                                    let _ =
                                        crate::platform::windows_service::start_windows_service();
                                }
                                return Err(err);
                            }
                        }
                    } else {
                        (false, None)
                    }
                }
                Ok(res) => res,
                Err(err) if effective_cfg.engine == EngineMode::Proxy => {
                    tracing::warn!(
                        error = %err,
                        "skipping sibling wintun.dll copy during Windows Proxy service install"
                    );
                    if verbose {
                        eprintln!(
                            "Warning: could not copy sibling wintun.dll ({err}); continuing Proxy service install."
                        );
                    }
                    (false, None)
                }
                Err(err) => {
                    if let Some(backup) = bin_backup {
                        backup.rollback();
                    }
                    if upgrade && prev_was_running {
                        let _ = crate::platform::windows_service::start_windows_service();
                    }
                    return Err(err);
                }
            };

        if let Err(err) = install_windows_native_service(&target_bin, &effective_cfg, verbose) {
            if let Some(backup) = wintun_backup {
                backup.rollback();
            }
            if let Some(backup) = bin_backup {
                backup.rollback();
            }
            if upgrade && prev_was_running {
                let _ = crate::platform::windows_service::start_windows_service();
            }
            return Err(err);
        }

        if let Some(backup) = wintun_backup {
            backup.commit();
        }
        if let Some(backup) = bin_backup {
            backup.commit();
        }

        if verbose {
            if wintun_copied {
                println!(
                    "Installed Wintun : {}",
                    bin_dir.join("wintun.dll").display()
                );
            }
            if !upgrade {
                print_windows_stale_browser_hint(&effective_cfg);
            }
        }
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let current_exe =
            std::env::current_exe().context("failed to determine current executable")?;

        #[cfg(target_os = "macos")]
        let has_system_daemon = launch_daemon_plist_path().exists()
            || launchctl_service_loaded(&format!("system/{LAUNCH_DAEMON_LABEL}"));
        #[cfg(target_os = "linux")]
        let has_system_daemon = systemd_system_unit_path().exists();
        let has_system_bin = Path::new(UNIX_SYSTEM_BIN_PATH).is_file();

        let effective_cfg = if upgrade {
            let preferred_path = if has_system_daemon {
                config_file::system_config_path()
            } else {
                resolved_user_config_path()
            };
            match config_file::load_file_config(Some(&preferred_path), has_system_daemon) {
                Ok((Some(_), file_cfg)) => {
                    let mut merged = apply_file_config_to_runtime(cfg, &file_cfg);
                    if has_system_daemon && file_cfg.engine.is_none() {
                        // A root system daemon (macOS LaunchDaemon / Linux systemd system unit)
                        // runs in TUN mode; preserve TUN when `config.toml` leaves `engine` unset.
                        merged.engine = EngineMode::Tun;
                    }
                    merged
                }
                _ => {
                    if has_system_daemon {
                        // A root system daemon is only installed for TUN mode; preserve
                        // TUN intent if the system config is unreadable prior to sudo.
                        let mut fallback = cfg.clone();
                        fallback.engine = EngineMode::Tun;
                        fallback
                    } else {
                        cfg.clone()
                    }
                }
            }
        } else {
            cfg.clone()
        };

        let needs_root = effective_cfg.engine == EngineMode::Tun
            || has_system_daemon
            || (upgrade && has_system_bin);
        if needs_root && !is_unix_root() {
            let sudo_args = build_unix_install_sudo_args(&effective_cfg, upgrade);
            let action = if upgrade {
                "update the vdpi background service"
            } else {
                "install the vdpi background service"
            };
            return relaunch_unix_sudo_and_wait(&sudo_args, action);
        }

        if effective_cfg.engine == EngineMode::Tun {
            let sys_config_path = config_file::system_config_path();
            if !upgrade || !sys_config_path.is_file() {
                let file_cfg = file_config_from_runtime(&effective_cfg);
                config_file::save_file_config_atomic(&sys_config_path, &file_cfg)?;
            }
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            copy_binary_atomically(&current_exe, &target_bin)?;

            #[cfg(target_os = "macos")]
            install_macos_launch_daemon(&target_bin, &effective_cfg, verbose)?;

            #[cfg(target_os = "linux")]
            install_linux_systemd_system_service(&target_bin, &effective_cfg, verbose)?;

            return Ok(());
        }

        let user_config_path = resolved_user_config_path();
        if !upgrade || !user_config_path.is_file() {
            ensure_no_symlink_under_user_home(&user_config_path)?;
            if let Some(parent) = user_config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
            let file_cfg = file_config_from_runtime(&effective_cfg);
            config_file::save_file_config_atomic(&user_config_path, &file_cfg)?;
            if let Some(parent) = user_config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&user_config_path);
        }

        let vdpi_root = vdpi_root_dir()?;
        let bin_dir = vdpi_root.join("bin");
        let log_dir = vdpi_root.join("logs");
        create_dir_all_for_unix_user(&bin_dir)
            .with_context(|| format!("failed to create service directory {}", bin_dir.display()))?;
        create_dir_all_for_unix_user(&log_dir)
            .with_context(|| format!("failed to create log directory {}", log_dir.display()))?;

        let target_bin = installed_binary_path()?;
        copy_binary_atomically(&current_exe, &target_bin)?;
        chown_to_sudo_user(&vdpi_root);
        chown_to_sudo_user(&bin_dir);
        chown_to_sudo_user(&log_dir);
        chown_to_sudo_user(&target_bin);

        if upgrade && has_system_bin && is_unix_root() {
            copy_binary_atomically(&current_exe, Path::new(UNIX_SYSTEM_BIN_PATH))?;
        }

        #[cfg(target_os = "macos")]
        install_macos_launch_agent(&target_bin, &effective_cfg, verbose)?;

        #[cfg(target_os = "linux")]
        install_linux_systemd_service(&target_bin, &effective_cfg, verbose)?;

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn macos_launch_agent_launchctl_command() -> Command {
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        let mut cmd = Command::new("/bin/launchctl");
        cmd.arg("asuser")
            .arg(sudo_user.uid.to_string())
            .arg("/bin/launchctl");
        return cmd;
    }
    Command::new("/bin/launchctl")
}

#[cfg(target_os = "macos")]
fn launchctl_command_for_target(service_target: &str) -> Command {
    if service_target.starts_with("gui/") {
        macos_launch_agent_launchctl_command()
    } else {
        Command::new("/bin/launchctl")
    }
}

#[cfg(target_os = "macos")]
fn wait_launchctl_unloaded(service_target: &str) {
    let deadline = Instant::now() + Duration::from_secs(4);
    while launchctl_service_loaded(service_target) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn start_macos_launch_agent(plist_path: &Path, allow_legacy_load_fallback: bool) -> Result<()> {
    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
    let plist_str = plist_path.display().to_string();

    let _ = macos_launch_agent_launchctl_command()
        .args(["enable", &service_target])
        .stdin(Stdio::null())
        .output();

    let boot = macos_launch_agent_launchctl_command()
        .args(["bootstrap", &domain_target, &plist_str])
        .stdin(Stdio::null())
        .output()
        .context("failed to execute '/bin/launchctl bootstrap'")?;

    if boot.status.success() {
        // `RunAtLoad=true` already spawns the agent; wait briefly before issuing
        // a non-destructive `kickstart` so we do not race `proxy-lease.lock`.
        let deadline = Instant::now() + Duration::from_millis(1500);
        while !launchctl_service_running(&service_target) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if !launchctl_service_running(&service_target) {
            let kick = macos_launch_agent_launchctl_command()
                .args(["kickstart", &service_target])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl kickstart'")?;
            if !kick.status.success() && !launchctl_service_running(&service_target) {
                let detail = String::from_utf8_lossy(&kick.stderr).trim().to_string();
                if detail.is_empty() {
                    bail!(
                        "failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                        kick.status
                    );
                }
                bail!("failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
            }
        }
        return Ok(());
    }

    if launchctl_service_loaded(&service_target) {
        let kick = macos_launch_agent_launchctl_command()
            .args(["kickstart", "-k", &service_target])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl kickstart'")?;
        if !kick.status.success() && !launchctl_service_running(&service_target) {
            let detail = String::from_utf8_lossy(&kick.stderr).trim().to_string();
            if detail.is_empty() {
                bail!(
                    "failed to kickstart LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                    kick.status
                );
            }
            bail!("failed to kickstart LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
        }
        return Ok(());
    }

    if allow_legacy_load_fallback {
        let fallback = macos_launch_agent_launchctl_command()
            .args(["load", "-w", &plist_str])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl load'")?;
        if fallback.status.success() {
            return Ok(());
        }
        bail!(
            "failed to load LaunchAgent {}: {}",
            plist_path.display(),
            String::from_utf8_lossy(&fallback.stderr).trim()
        );
    }

    let detail = String::from_utf8_lossy(&boot.stderr).trim().to_string();
    if detail.is_empty() {
        bail!(
            "failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}': bootstrap failed (exit status: {})",
            boot.status
        );
    }
    bail!("failed to start LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
}

#[cfg(target_os = "macos")]
fn remove_macos_launch_agent_if_present() {
    let Ok(plist_path) = launch_agent_plist_path() else {
        return;
    };
    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
    let _ = macos_launch_agent_launchctl_command()
        .args(["bootout", &service_target])
        .stdin(Stdio::null())
        .output();
    if ensure_no_symlink_under_user_home(&plist_path).is_ok() && plist_path.exists() {
        let plist_str = plist_path.display().to_string();
        let _ = macos_launch_agent_launchctl_command()
            .args(["bootout", &domain_target, &plist_str])
            .stdin(Stdio::null())
            .output();
        let _ = macos_launch_agent_launchctl_command()
            .args(["unload", &plist_str])
            .stdin(Stdio::null())
            .output();
        let _ = fs::remove_file(&plist_path);
    }
    wait_launchctl_unloaded(&service_target);
}

#[cfg(target_os = "macos")]
fn remove_macos_launch_daemon_if_present() -> Result<bool> {
    let plist_path = launch_daemon_plist_path();
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    if !plist_path.exists() && !launchctl_service_loaded(&service_target) {
        return Ok(false);
    }
    if !is_unix_root() {
        bail!(
            "removing the root LaunchDaemon ({}) requires root privileges; run with sudo.",
            plist_path.display()
        );
    }
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &service_target])
        .stdin(Stdio::null())
        .output();
    if plist_path.exists() {
        let plist_str = plist_path.display().to_string();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", "system", &plist_str])
            .stdin(Stdio::null())
            .output();
        fs::remove_file(&plist_path)
            .with_context(|| format!("failed to remove {}", plist_path.display()))?;
    }
    wait_launchctl_unloaded(&service_target);
    Ok(true)
}

#[cfg(target_os = "macos")]
fn start_macos_launch_daemon(plist_path: &Path) -> Result<()> {
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    let plist_str = plist_path.display().to_string();

    let _ = Command::new("/bin/launchctl")
        .args(["enable", &service_target])
        .stdin(Stdio::null())
        .output();

    let boot = Command::new("/bin/launchctl")
        .args(["bootstrap", "system", &plist_str])
        .stdin(Stdio::null())
        .output()
        .context("failed to execute '/bin/launchctl bootstrap'")?;
    if !boot.status.success() && !launchctl_service_loaded(&service_target) {
        let detail = String::from_utf8_lossy(&boot.stderr).trim().to_string();
        if detail.is_empty() {
            bail!(
                "failed to start LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                boot.status
            );
        }
        bail!("failed to start LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
    }

    // `RunAtLoad=true` starts the daemon automatically after `bootstrap`; wait briefly
    // before issuing a non-destructive `kickstart` so we do not SIGKILL it mid-utun startup.
    let deadline = Instant::now() + Duration::from_millis(1500);
    while !launchctl_service_running(&service_target) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if !launchctl_service_running(&service_target) {
        let kick = Command::new("/bin/launchctl")
            .args(["kickstart", &service_target])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl kickstart'")?;
        if !kick.status.success() && !launchctl_service_running(&service_target) {
            let detail = String::from_utf8_lossy(&kick.stderr).trim().to_string();
            if detail.is_empty() {
                bail!(
                    "failed to kickstart LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                    kick.status
                );
            }
            bail!("failed to kickstart LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launch_daemon(
    target_bin: &Path,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    // Mutual exclusion: unload any user LaunchAgent and clear system proxies before starting TUN.
    remove_macos_launch_agent_if_present();
    let _ = clear_all_system_proxies();

    let plist_path = launch_daemon_plist_path();
    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
    let plist_str = plist_path.display().to_string();

    if plist_path.exists() || launchctl_service_loaded(&service_target) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", "system", &plist_str])
            .stdin(Stdio::null())
            .output();
        wait_launchctl_unloaded(&service_target);
    }

    if let Some(parent) = plist_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let plist_xml = generate_launch_daemon_plist(target_bin, cfg);
    fs::write(&plist_path, plist_xml)
        .with_context(|| format!("failed to write {}", plist_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
    }

    start_macos_launch_daemon(&plist_path)?;

    if verbose {
        println!("Installed binary : {}", target_bin.display());
        println!("Loaded daemon    : {} (TUN)", plist_path.display());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_macos_launch_agent(target_bin: &Path, cfg: &RuntimeConfig, verbose: bool) -> Result<()> {
    // Mutual exclusion: remove system LaunchDaemon if previously installed in TUN mode.
    let _ = remove_macos_launch_daemon_if_present()?;

    let uid = current_uid();
    let domain_target = format!("gui/{uid}");
    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
    let plist_path = launch_agent_plist_path()?;
    if let Some(parent) = plist_path.parent() {
        create_dir_all_for_unix_user(parent)?;
    }

    let plist_str = plist_path.display().to_string();
    if plist_path.exists() || launchctl_service_loaded(&service_target) {
        let _ = macos_launch_agent_launchctl_command()
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();
        let _ = macos_launch_agent_launchctl_command()
            .args(["bootout", &domain_target, &plist_str])
            .stdin(Stdio::null())
            .output();
        wait_launchctl_unloaded(&service_target);
    }

    let plist_xml = generate_launch_agent_plist(target_bin, cfg);
    write_unix_user_file_safely(&plist_path, plist_xml.as_bytes())?;

    start_macos_launch_agent(&plist_path, true)?;

    let path_updated = ensure_unix_shell_path();

    if verbose {
        println!("Installed binary : {}", target_bin.display());
        println!("Loaded service   : {}", plist_path.display());
        if path_updated {
            println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_systemctl_bin() -> &'static str {
    for candidate in ["/usr/bin/systemctl", "/bin/systemctl"] {
        if Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "/usr/bin/systemctl"
}

#[cfg(target_os = "linux")]
fn configure_linux_user_command(
    cmd: &mut Command,
    sudo_user: &UnixTargetUser,
    set_xdg_config: bool,
) {
    use std::os::unix::process::CommandExt;

    let runtime_dir = format!("/run/user/{}", sudo_user.uid);
    let dbus_addr = format!("unix:path={runtime_dir}/bus");
    cmd.env("HOME", &sudo_user.home_dir)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .env("DBUS_SESSION_BUS_ADDRESS", &dbus_addr);
    if set_xdg_config {
        let xdg_config = sudo_user.home_dir.join(".config");
        cmd.env("XDG_CONFIG_HOME", &xdg_config);
    }
    if let Some(ref name) = sudo_user.username {
        cmd.env("USER", name).env("LOGNAME", name);
    } else {
        cmd.env_remove("USER").env_remove("LOGNAME");
    }
    let uid = sudo_user.uid;
    let gid = sudo_user.gid;
    // SAFETY: `setgroups`, `setgid`, and `setuid` run in the forked child before `exec`
    // while euid is still 0 so `setgroups` retains CAP_SETGID. Using `CommandExt::uid`
    // would drop UID before `pre_exec` runs and cause `setgroups` to fail with EPERM.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(target_os = "linux")]
fn linux_user_systemctl_command() -> Command {
    let mut cmd = Command::new(resolve_systemctl_bin());
    cmd.arg("--user");
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        configure_linux_user_command(&mut cmd, &sudo_user, false);
    }
    cmd
}

#[cfg(target_os = "linux")]
fn remove_linux_user_unit_if_present() {
    let _ = linux_user_systemctl_command()
        .args(["disable", "--now", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .output();
    if let Some(unit_path) = systemd_user_unit_path()
        .ok()
        .filter(|p| ensure_no_symlink_under_user_home(p).is_ok() && p.exists())
    {
        let _ = fs::remove_file(unit_path);
        let _ = linux_user_systemctl_command()
            .args(["daemon-reload"])
            .stdin(Stdio::null())
            .output();
    }
}

#[cfg(target_os = "linux")]
fn remove_linux_system_unit_if_present() -> Result<bool> {
    let unit_path = systemd_system_unit_path();
    if !unit_path.exists() {
        return Ok(false);
    }
    if !is_unix_root() {
        bail!(
            "removing the system systemd unit ({}) requires root privileges; run with sudo.",
            unit_path.display()
        );
    }
    let _ = Command::new(resolve_systemctl_bin())
        .args(["disable", "--now", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .output();
    fs::remove_file(&unit_path)
        .with_context(|| format!("failed to remove {}", unit_path.display()))?;
    let _ = Command::new(resolve_systemctl_bin())
        .args(["daemon-reload"])
        .stdin(Stdio::null())
        .output();
    Ok(true)
}

#[cfg(target_os = "linux")]
fn write_linux_system_unit_atomically(unit_path: &Path, contents: &str) -> Result<()> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::atomic::Ordering;

    let parent = unit_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .context("failed to determine parent directory for systemd system unit")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;

    let file_name = unit_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(SYSTEMD_UNIT_NAME);
    let pid = std::process::id();

    let mut created = None;
    for _ in 0..16 {
        let seq = UNIX_SAFE_WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{seq}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o644)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create temporary unit file {}", candidate.display())
                });
            }
        }
    }

    let (tmp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!(
            "failed to allocate unique temporary unit file in {}",
            parent.display()
        )
    })?;

    if let Err(err) = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write temporary unit file {}", tmp_path.display()))
    {
        drop(file);
        let _ = fs::remove_file(tmp_path);
        return Err(err);
    }
    drop(file);

    let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o644));
    if let Err(err) = fs::rename(&tmp_path, unit_path) {
        let _ = fs::remove_file(tmp_path);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically write systemd system unit {}",
                unit_path.display()
            )
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn format_systemctl_error(out: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("exit status {}", out.status)
}

#[cfg(target_os = "linux")]
fn run_systemctl_step(cmd: &mut Command, action_desc: &str, unit_path: &Path) -> Result<()> {
    let out = cmd.stdin(Stdio::null()).output().with_context(|| {
        format!(
            "wrote systemd unit to {}, but failed to execute '{action_desc}'",
            unit_path.display()
        )
    })?;
    if !out.status.success() {
        let detail = format_systemctl_error(&out);
        bail!(
            "wrote systemd unit to {}, but '{action_desc}' failed: {detail}",
            unit_path.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_system_service(
    target_bin: &Path,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    // Mutual exclusion: stop/remove user Proxy unit and clear desktop proxies before starting TUN.
    remove_linux_user_unit_if_present();
    let _ = clear_all_system_proxies();

    let unit_path = systemd_system_unit_path();
    let unit_text = generate_systemd_system_unit(target_bin, cfg);
    write_linux_system_unit_atomically(&unit_path, &unit_text)?;

    run_systemctl_step(
        Command::new(resolve_systemctl_bin()).args(["daemon-reload"]),
        "systemctl daemon-reload",
        &unit_path,
    )?;
    run_systemctl_step(
        Command::new(resolve_systemctl_bin()).args(["enable", SYSTEMD_UNIT_NAME]),
        &format!("systemctl enable {SYSTEMD_UNIT_NAME}"),
        &unit_path,
    )?;
    run_systemctl_step(
        Command::new(resolve_systemctl_bin()).args(["restart", SYSTEMD_UNIT_NAME]),
        &format!("systemctl restart {SYSTEMD_UNIT_NAME}"),
        &unit_path,
    )?;

    if verbose {
        println!("Installed binary : {}", target_bin.display());
        println!("Systemd unit     : {} (TUN)", unit_path.display());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_linux_systemd_service(
    target_bin: &Path,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    // Mutual exclusion: remove root system TUN unit if previously installed.
    let _ = remove_linux_system_unit_if_present()?;

    if let Ok(home) = home_dir() {
        let local_bin = home.join(".local").join("bin");
        if create_dir_all_for_unix_user(&local_bin).is_ok() {
            let link_path = local_bin.join("vdpi");
            let existing_is_symlink =
                fs::symlink_metadata(&link_path).is_ok_and(|meta| meta.file_type().is_symlink());
            if existing_is_symlink {
                let _ = fs::remove_file(&link_path);
            }
            if fs::symlink_metadata(&link_path).is_err()
                && std::os::unix::fs::symlink(target_bin, &link_path).is_ok()
            {
                chown_to_sudo_user(&link_path);
            }
        }
    }

    let unit_path = systemd_user_unit_path()?;
    if let Some(parent) = unit_path.parent() {
        create_dir_all_for_unix_user(parent)?;
    }

    let unit_text = generate_systemd_unit(target_bin, cfg);
    write_unix_user_file_safely(&unit_path, unit_text.as_bytes())?;

    run_systemctl_step(
        linux_user_systemctl_command().args(["daemon-reload"]),
        "systemctl --user daemon-reload",
        &unit_path,
    )?;
    run_systemctl_step(
        linux_user_systemctl_command().args(["enable", SYSTEMD_UNIT_NAME]),
        &format!("systemctl --user enable {SYSTEMD_UNIT_NAME}"),
        &unit_path,
    )?;
    run_systemctl_step(
        linux_user_systemctl_command().args(["restart", SYSTEMD_UNIT_NAME]),
        &format!("systemctl --user restart {SYSTEMD_UNIT_NAME}"),
        &unit_path,
    )?;

    let path_updated = ensure_unix_shell_path();

    if verbose {
        println!("Installed binary : {}", target_bin.display());
        println!("Systemd unit     : {}", unit_path.display());
        if path_updated {
            println!("Shell PATH       : added ~/.vdpi/bin (restart shell or source profile)");
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const UNIX_SHELL_PATH_EXPORT: &str = r#"export PATH="$HOME/.vdpi/bin:$PATH""#;

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn strip_unix_shell_path_line(content: &str) -> Option<String> {
    let mut removed = false;
    let mut kept = Vec::new();
    for line in content.lines() {
        if line == UNIX_SHELL_PATH_EXPORT {
            removed = true;
        } else {
            kept.push(line);
        }
    }
    if !removed {
        return None;
    }
    let mut next = kept.join("\n");
    if !next.is_empty() && content.ends_with('\n') {
        next.push('\n');
    }
    Some(next)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_non_symlink_user_file(path: &Path) -> Option<String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    if ensure_no_symlink_under_user_home(path).is_err() {
        return None;
    }
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    Some(buf)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_existing_non_symlink_user_file(path: &Path, content: &str) -> bool {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    if ensure_no_symlink_under_user_home(path).is_err() {
        return false;
    }
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return false;
    }
    let Ok(mut file) = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    else {
        return false;
    };
    file.write_all(content.as_bytes()).is_ok()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_unix_shell_path() -> bool {
    let Ok(home) = home_dir() else {
        return false;
    };
    let mut updated = false;
    for rc_name in [".zshrc", ".bashrc", ".profile"] {
        let rc_path = home.join(rc_name);
        let Some(content) = read_non_symlink_user_file(&rc_path) else {
            continue;
        };
        if content.contains(".vdpi/bin") {
            continue;
        }
        let mut next = content;
        if !next.ends_with('\n') {
            next.push('\n');
        }
        next.push_str(UNIX_SHELL_PATH_EXPORT);
        next.push('\n');
        if write_existing_non_symlink_user_file(&rc_path, &next) {
            updated = true;
        }
    }
    updated
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn remove_unix_shell_path() -> bool {
    let Ok(home) = home_dir() else {
        return false;
    };
    let mut updated = false;
    for rc_name in [".zshrc", ".bashrc", ".profile"] {
        let rc_path = home.join(rc_name);
        let Some(content) = read_non_symlink_user_file(&rc_path) else {
            continue;
        };
        let Some(next) = strip_unix_shell_path_line(&content) else {
            continue;
        };
        if write_existing_non_symlink_user_file(&rc_path, &next) {
            updated = true;
        }
    }
    updated
}

#[cfg(target_os = "windows")]
fn install_windows_native_service(
    target_bin: &Path,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    use crate::platform::windows::{
        add_dir_to_windows_system_path, broadcast_environment_change, notify_wininet_refresh,
    };
    use crate::platform::windows_service::install_or_update_windows_service;

    let bin_path_cmd = build_windows_service_bin_path(target_bin, cfg);
    install_or_update_windows_service(&bin_path_cmd)?;

    let legacy_bin = legacy_windows_root_dir().map(|r| r.join("bin"));
    let path_added = target_bin
        .parent()
        .and_then(|bin_dir| add_dir_to_windows_system_path(bin_dir, legacy_bin.as_deref()).ok())
        .unwrap_or(false);

    // Refresh WinINET and environment directly in the interactive caller's session as well.
    notify_wininet_refresh();
    broadcast_environment_change();

    if verbose {
        println!("Installed binary : {}", target_bin.display());
        println!("Windows service  : {WINDOWS_SERVICE_NAME} (AUTO_START, RUNNING)");
        if path_added {
            if let Some(bin_dir) = target_bin.parent() {
                println!("System PATH      : added {}", bin_dir.display());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn legacy_windows_root_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("vdpi"))
}

#[cfg(target_os = "windows")]
fn cleanup_legacy_windows_startup() {
    use crate::platform::windows::run_reg;

    let _ = run_reg(&["delete", WINDOWS_LEGACY_RUN_KEY, "/v", "vdpi", "/f"]);
    if let Some(legacy_root) = legacy_windows_root_dir() {
        if win_fs_hardening::is_reparse_point(&legacy_root) {
            return;
        }
        let legacy_bin = legacy_root.join("bin");
        if win_fs_hardening::is_reparse_point(&legacy_bin) {
            return;
        }
        let legacy_vbs = legacy_bin.join("vdpi-autostart.vbs");
        let _ = win_fs_hardening::safe_remove_file(&legacy_vbs);
    }
}

#[cfg(target_os = "windows")]
fn windows_system32_dir() -> Option<PathBuf> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
    }

    let mut buf = vec![0u16; 260];
    loop {
        // SAFETY: `buf` is writable with capacity `buf.len()` UTF-16 code units.
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            return None;
        }
        if (len as usize) < buf.len() {
            let dir = String::from_utf16_lossy(&buf[..len as usize]);
            let trimmed = dir.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
            return None;
        }
        buf.resize(len as usize + 1, 0);
    }
}

#[cfg(target_os = "windows")]
fn resolve_windows_system32_exe(exe_name: &str) -> Option<PathBuf> {
    let sys32 = windows_system32_dir()?;
    let candidate = sys32.join(exe_name);
    candidate.is_file().then_some(candidate)
}

#[cfg(target_os = "windows")]
fn stop_windows_foreground_daemons() {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let my_pid = std::process::id();
    let Some(taskkill) = resolve_windows_system32_exe("taskkill.exe") else {
        return;
    };
    // Stop published daemon PIDs only; the unelevated installer is waiting for our exit.
    for state in read_runtime_states() {
        if state.pid != my_pid {
            let _ = Command::new(&taskkill)
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "/F",
                    "/PID",
                    &state.pid.to_string(),
                    "/FI",
                    "IMAGENAME eq vdpi.exe",
                ])
                .output();
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn is_allowed_delayed_windows_cleanup_dir(candidate: &Path, program_files_vdpi: &Path) -> bool {
    use std::path::Component;

    if candidate.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let (Some(cand_raw), Some(root_raw)) = (candidate.to_str(), program_files_vdpi.to_str())
    else {
        return false;
    };
    if cand_raw.is_empty()
        || root_raw.is_empty()
        || cand_raw.contains(['"', '&', '|', '%', '^', '<', '>', '\r', '\n', '\0'])
    {
        return false;
    }
    let normalize = |s: &str| {
        s.replace('/', "\\")
            .trim_end_matches('\\')
            .to_ascii_lowercase()
    };
    let cand_norm = normalize(cand_raw);
    let root_norm = normalize(root_raw);
    if root_norm.is_empty() {
        return false;
    }
    cand_norm == root_norm || cand_norm == format!("{root_norm}\\bin")
}

#[cfg(target_os = "windows")]
fn schedule_delayed_windows_dir_cleanup(vdpi_root: &Path) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // Never allow elevated `cmd.exe rmdir /S /Q` against user-writable `%LOCALAPPDATA%`
    // or any path outside the admin-owned `Program Files\vdpi` install tree.
    let Ok(allowed_root) = vdpi_root_dir() else {
        return;
    };
    if !is_allowed_delayed_windows_cleanup_dir(vdpi_root, &allowed_root) {
        return;
    }
    if legacy_windows_root_dir().is_some_and(|legacy| {
        vdpi_root
            .to_str()
            .zip(legacy.to_str())
            .is_some_and(|(cand, leg)| {
                let c = cand.replace('/', "\\").to_ascii_lowercase();
                let l = leg
                    .replace('/', "\\")
                    .trim_end_matches('\\')
                    .to_ascii_lowercase();
                !l.is_empty() && (c == l || c.starts_with(&format!("{l}\\")))
            })
    }) {
        return;
    }
    if win_fs_hardening::is_reparse_point(&allowed_root)
        || win_fs_hardening::is_reparse_point(vdpi_root)
    {
        return;
    }

    let Some(root_str) = vdpi_root.to_str() else {
        return;
    };
    if root_str.is_empty()
        || root_str.contains(['"', '&', '|', '%', '^', '<', '>', '\r', '\n', '\0'])
    {
        return;
    }

    let Some(sys32_dir) = windows_system32_dir() else {
        return;
    };
    let (Some(cmd_exe), Some(ping_exe)) = (
        resolve_windows_system32_exe("cmd.exe"),
        resolve_windows_system32_exe("ping.exe"),
    ) else {
        return;
    };
    let Some(ping_str) = ping_exe.to_str() else {
        return;
    };
    if ping_str.is_empty()
        || ping_str.contains(['"', '&', '|', '%', '^', '<', '>', '\r', '\n', '\0'])
    {
        return;
    }

    let cleanup_cmd = format!(
        "for /L %i in (1,1,12) do (rmdir /S /Q \"{root_str}\" 2>nul & if not exist \"{root_str}\" (exit /b 0) else (\"{ping_str}\" -n 2 127.0.0.1 >nul))"
    );
    let _ = Command::new(cmd_exe)
        .current_dir(&sys32_dir)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .raw_arg("/C")
        .raw_arg(cleanup_cmd)
        .spawn();
}

#[cfg(target_os = "windows")]
fn cleanup_windows_install_files(purge: bool) {
    use crate::platform::windows::{remove_dir_from_windows_path, WINDOWS_PROXY_STATE_FILENAME};

    // Release any directory handle held on `C:\Program Files\vdpi\bin` via CWD.
    let _ = std::env::set_current_dir(std::env::temp_dir());

    let Ok(vdpi_root) = vdpi_root_dir() else {
        return;
    };
    let bin_dir = vdpi_root.join("bin");
    let legacy_root = legacy_windows_root_dir();
    let legacy_bin = legacy_root.as_ref().map(|r| r.join("bin"));
    let user_cfg = config_file::user_config_path();

    remove_dir_from_windows_path(&bin_dir, legacy_bin.as_deref());

    let current_exe = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(&p).ok());

    if let Some(legacy) = legacy_root.as_deref().filter(|p| p.exists()) {
        if !win_fs_hardening::is_reparse_point(legacy) {
            // Never schedule delayed `cmd.exe rmdir /S /Q` on user-writable `%LOCALAPPDATA%`
            // paths (junction-swap LPE risk); use synchronous reparse-safe removal only.
            if purge {
                let _ = win_fs_hardening::safe_remove_dir_all(&legacy.join("logs"));
                let _ = win_fs_hardening::safe_remove_dir_all(legacy);
            } else {
                // Preserve `%LOCALAPPDATA%\vdpi\config.toml` and its parent directory when
                // uninstall runs without `--purge`; remove only bin/, logs/, and state files.
                let _ = win_fs_hardening::safe_remove_dir_all(&legacy.join("logs"));
                let _ = win_fs_hardening::safe_remove_file(&legacy.join("state.json"));
                let _ = win_fs_hardening::safe_remove_file(
                    &legacy.join(WINDOWS_PROXY_STATE_FILENAME),
                );
                let legacy_bin_dir = legacy.join("bin");
                if legacy_bin_dir.exists() && !win_fs_hardening::is_reparse_point(&legacy_bin_dir) {
                    let _ = win_fs_hardening::safe_remove_dir_all(&legacy_bin_dir);
                }
            }
        }
    }

    let pd_dir = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("vdpi");
    if pd_dir.exists() && !win_fs_hardening::is_reparse_point(&pd_dir) {
        if purge {
            let _ = win_fs_hardening::safe_remove_dir_all(&pd_dir);
        } else {
            let _ = win_fs_hardening::safe_remove_file(&pd_dir.join("state.json"));
            let _ = win_fs_hardening::safe_remove_file(&pd_dir.join(WINDOWS_PROXY_STATE_FILENAME));
        }
    }

    if purge {
        if user_cfg.is_file() {
            let _ = win_fs_hardening::safe_remove_file(&user_cfg);
        }
        if let Some(parent) = user_cfg.parent() {
            if !win_fs_hardening::is_reparse_point(parent) {
                let _ = fs::remove_dir(parent);
            }
        }
    }

    if vdpi_root.exists() && !win_fs_hardening::is_reparse_point(&vdpi_root) {
        let contains_user_cfg = user_cfg.starts_with(&vdpi_root);
        if purge || !contains_user_cfg {
            let running_from_root = current_exe
                .as_ref()
                .zip(fs::canonicalize(&vdpi_root).ok())
                .is_some_and(|(exe, root)| exe.starts_with(root));
            if running_from_root {
                let _ = win_fs_hardening::safe_remove_dir_all(&vdpi_root.join("logs"));
                schedule_delayed_windows_dir_cleanup(&vdpi_root);
            } else if let Err(err) = win_fs_hardening::safe_remove_dir_all(&vdpi_root) {
                if !err.to_string().contains("reparse point") {
                    let _ = win_fs_hardening::safe_remove_dir_all(&vdpi_root.join("logs"));
                    schedule_delayed_windows_dir_cleanup(&vdpi_root);
                }
            }
        } else {
            let _ = win_fs_hardening::safe_remove_dir_all(&vdpi_root.join("logs"));
            let _ = win_fs_hardening::safe_remove_file(&vdpi_root.join("state.json"));
            let _ =
                win_fs_hardening::safe_remove_file(&vdpi_root.join(WINDOWS_PROXY_STATE_FILENAME));
            if bin_dir.exists() && !win_fs_hardening::is_reparse_point(&bin_dir) {
                let running_from_bin = current_exe
                    .as_ref()
                    .zip(fs::canonicalize(&bin_dir).ok())
                    .is_some_and(|(exe, root)| exe.starts_with(root));
                if running_from_bin {
                    schedule_delayed_windows_dir_cleanup(&bin_dir);
                } else if let Err(err) = win_fs_hardening::safe_remove_dir_all(&bin_dir) {
                    if !err.to_string().contains("reparse point") {
                        schedule_delayed_windows_dir_cleanup(&bin_dir);
                    }
                }
            }
        }
    }
}

/// Persists `target` (`EngineMode::Tun` or `EngineMode::Proxy`) to the canonical
/// `config.toml`, cleanly transitions any installed background service between TUN
/// and Proxy modes, and restarts the service if it was running.
pub fn switch_service_engine(target: EngineMode, cfg: &RuntimeConfig) -> Result<()> {
    switch_service_engine_impl(target, cfg, true)
}

/// Quiet variant of [`switch_service_engine`] for interactive TUI callers.
pub fn switch_service_engine_quiet(target: EngineMode, cfg: &RuntimeConfig) -> Result<()> {
    switch_service_engine_impl(target, cfg, false)
}

fn switch_service_engine_impl(
    target: EngineMode,
    cfg: &RuntimeConfig,
    verbose: bool,
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait,
            stop_windows_service_if_running,
        };
        use crate::platform::windows_tun::{
            expected_wintun_dll_sha256, verify_wintun_dll_sha256, WINTUN_VERSION,
        };

        let svc = query_windows_service_status();
        let preflight_bin_dir = svc.installed.then(|| {
            installed_binary_path()
                .ok()
                .and_then(|p| p.parent().map(Path::to_path_buf))
        }).flatten();
        let preflight_wintun = if target == EngineMode::Tun {
            Some(preflight_windows_tun_wintun(
                preflight_bin_dir.as_deref(),
                "switch Windows service to TUN mode",
            )?)
        } else {
            None
        };

        if svc.installed && !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to switch the vdpi Windows service to {} mode...",
                    target.as_str()
                );
            }
            relaunch_elevated_and_wait(&["engine".to_string(), target.as_str().to_string()])?;
            notify_wininet_refresh();
            broadcast_environment_change();
            if verbose {
                println!(
                    "Switched vdpi Windows service engine to {}.",
                    target.as_str()
                );
            }
            return Ok(());
        }

        let config_path = if svc.installed {
            config_file::system_config_path()
        } else {
            config_file::user_config_path()
        };

        let mut file_cfg = config_file::load_file_config(Some(&config_path), svc.installed)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);

        if svc.installed {
            let target_bin = installed_binary_path()
                .ok()
                .filter(|p| p.is_file())
                .or_else(|| std::env::current_exe().ok())
                .context("failed to determine vdpi binary path for service switch")?;
            let bin_dir = target_bin
                .parent()
                .map(Path::to_path_buf)
                .context("failed to determine vdpi service binary directory")?;
            let target_wintun = bin_dir.join("wintun.dll");

            let verified_wintun = if target == EngineMode::Tun {
                Some(match preflight_wintun {
                    Some(path) => path,
                    None => preflight_windows_tun_wintun(
                        Some(&bin_dir),
                        "switch Windows service to TUN mode",
                    )?,
                })
            } else {
                None
            };

            let was_running = matches!(svc.state, "RUNNING" | "START_PENDING");
            let _ = stop_windows_service_if_running()?;
            stop_windows_foreground_daemons();
            let _ = crate::platform::windows_tun::cleanup_orphan_wintun_adapter();

            if target == EngineMode::Tun {
                let copied = copy_verified_sibling_wintun(&bin_dir)?;
                let expected_sha256 = expected_wintun_dll_sha256()?;
                win_fs_hardening::reject_reparse_point(&target_wintun)
                    .context("cannot switch Windows service to TUN mode")?;
                let target_needs_replace = !target_wintun.is_file()
                    || verify_wintun_dll_sha256(&target_wintun, expected_sha256).is_err();
                if !copied && target_needs_replace {
                    if let Some(ref src_wintun) = verified_wintun {
                        let _ = copy_verified_wintun_to_bin_dir_with_backup(
                            src_wintun,
                            &bin_dir,
                            false,
                        )?;
                    }
                }
                win_fs_hardening::reject_reparse_point(&target_wintun)
                    .context("cannot switch Windows service to TUN mode")?;
                if target_wintun.is_file() {
                    verify_wintun_dll_sha256(&target_wintun, expected_sha256).with_context(
                        || {
                            format!(
                                "cannot switch Windows service to TUN mode: {} (v{WINTUN_VERSION}) is corrupted or mismatched — \
                                 extract all files from the zip (keep wintun.dll beside vdpi.exe)",
                                target_wintun.display()
                            )
                        },
                    )?;
                }
                clear_all_system_proxies()?;
            }

            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let bin_path_cmd = build_windows_service_bin_path(&target_bin, &target_cfg);
            install_or_update_windows_service_with_start(&bin_path_cmd, was_running)?;
            notify_wininet_refresh();
            broadcast_environment_change();
        } else {
            config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists()
            || launchctl_service_loaded(&format!("system/{LAUNCH_DAEMON_LABEL}"));
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        let service_installed = daemon_exists || agent_exists;
        let was_running = detect_service_state() == ServiceState::Running;

        if service_installed && (target == EngineMode::Tun || daemon_exists) && !is_unix_root() {
            let args = vec!["engine".to_string(), target.as_str().to_string()];
            let action = format!(
                "switch the macOS background service to {} mode",
                target.as_str()
            );
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if target == EngineMode::Tun && (service_installed || is_unix_root()) {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg =
            config_file::load_file_config(Some(&config_path), target == EngineMode::Tun)
                .ok()
                .and_then(|(found, fc)| found.map(|_| fc))
                .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);
        if target == EngineMode::Proxy {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if target == EngineMode::Proxy {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        if service_installed {
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let current_exe =
                std::env::current_exe().context("failed to determine current executable")?;

            match target {
                EngineMode::Tun => {
                    remove_macos_launch_agent_if_present();
                    let _ = clear_all_system_proxies();
                    let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    let plist_path = launch_daemon_plist_path();
                    let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
                    let plist_str = plist_path.display().to_string();
                    if plist_path.exists() || launchctl_service_loaded(&service_target) {
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", &service_target])
                            .stdin(Stdio::null())
                            .output();
                        let _ = Command::new("/bin/launchctl")
                            .args(["bootout", "system", &plist_str])
                            .stdin(Stdio::null())
                            .output();
                        wait_launchctl_unloaded(&service_target);
                    }
                    if let Some(parent) = plist_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(
                        &plist_path,
                        generate_launch_daemon_plist(&target_bin, &target_cfg),
                    )?;
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
                    }
                    if was_running {
                        start_macos_launch_daemon(&plist_path)?;
                    }
                }
                EngineMode::Proxy => {
                    let _ = remove_macos_launch_daemon_if_present()?;
                    let target_bin = installed_binary_path()?;
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    chown_to_sudo_user(&target_bin);
                    if let Some(bin_dir) = target_bin.parent() {
                        chown_to_sudo_user(bin_dir);
                        if let Some(root) = bin_dir.parent() {
                            chown_to_sudo_user(root);
                        }
                    }
                    let log_dir = vdpi_root_dir()?.join("logs");
                    create_dir_all_for_unix_user(&log_dir)?;
                    let plist_path = launch_agent_plist_path()?;
                    if let Some(parent) = plist_path.parent() {
                        create_dir_all_for_unix_user(parent)?;
                    }
                    let uid = current_uid();
                    let domain_target = format!("gui/{uid}");
                    let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
                    let plist_str = plist_path.display().to_string();
                    if plist_path.exists() || launchctl_service_loaded(&service_target) {
                        let _ = macos_launch_agent_launchctl_command()
                            .args(["bootout", &service_target])
                            .stdin(Stdio::null())
                            .output();
                        let _ = macos_launch_agent_launchctl_command()
                            .args(["bootout", &domain_target, &plist_str])
                            .stdin(Stdio::null())
                            .output();
                        wait_launchctl_unloaded(&service_target);
                    }
                    let plist_xml = generate_launch_agent_plist(&target_bin, &target_cfg);
                    write_unix_user_file_safely(&plist_path, plist_xml.as_bytes())?;
                    if was_running {
                        start_macos_launch_agent(&plist_path, false)?;
                    }
                }
            }
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        let service_installed = system_exists || user_exists;
        let was_running = detect_service_state() == ServiceState::Running;

        if service_installed && (target == EngineMode::Tun || system_exists) && !is_unix_root() {
            let args = vec!["engine".to_string(), target.as_str().to_string()];
            let action = format!(
                "switch the Linux background service to {} mode",
                target.as_str()
            );
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if target == EngineMode::Tun && (service_installed || is_unix_root()) {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg =
            config_file::load_file_config(Some(&config_path), target == EngineMode::Tun)
                .ok()
                .and_then(|(found, fc)| found.map(|_| fc))
                .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.engine = Some(target);
        if target == EngineMode::Proxy {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if target == EngineMode::Proxy {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        if service_installed {
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let current_exe =
                std::env::current_exe().context("failed to determine current executable")?;

            match target {
                EngineMode::Tun => {
                    remove_linux_user_unit_if_present();
                    let _ = clear_all_system_proxies();
                    let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    let unit_path = systemd_system_unit_path();
                    let unit_text = generate_systemd_system_unit(&target_bin, &target_cfg);
                    write_linux_system_unit_atomically(&unit_path, &unit_text)?;
                    let _ = Command::new(resolve_systemctl_bin())
                        .args(["daemon-reload"])
                        .stdin(Stdio::null())
                        .output();
                    let _ = Command::new(resolve_systemctl_bin())
                        .args(["enable", SYSTEMD_UNIT_NAME])
                        .stdin(Stdio::null())
                        .output();
                    if was_running {
                        let out = Command::new(resolve_systemctl_bin())
                            .args(["restart", SYSTEMD_UNIT_NAME])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute 'systemctl restart'")?;
                        if !out.status.success() {
                            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                                    out.status
                                );
                            }
                            bail!(
                                "failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}"
                            );
                        }
                    }
                }
                EngineMode::Proxy => {
                    let _ = remove_linux_system_unit_if_present()?;
                    let target_bin = installed_binary_path()?;
                    copy_binary_atomically(&current_exe, &target_bin)?;
                    chown_to_sudo_user(&target_bin);
                    if let Some(bin_dir) = target_bin.parent() {
                        chown_to_sudo_user(bin_dir);
                        if let Some(root) = bin_dir.parent() {
                            chown_to_sudo_user(root);
                        }
                    }
                    let log_dir = vdpi_root_dir()?.join("logs");
                    create_dir_all_for_unix_user(&log_dir)?;
                    let unit_path = systemd_user_unit_path()?;
                    if let Some(parent) = unit_path.parent() {
                        create_dir_all_for_unix_user(parent)?;
                    }
                    let unit_text = generate_systemd_unit(&target_bin, &target_cfg);
                    write_unix_user_file_safely(&unit_path, unit_text.as_bytes())?;
                    let _ = linux_user_systemctl_command()
                        .args(["daemon-reload"])
                        .stdin(Stdio::null())
                        .output();
                    let _ = linux_user_systemctl_command()
                        .args(["enable", SYSTEMD_UNIT_NAME])
                        .stdin(Stdio::null())
                        .output();
                    if was_running {
                        let out = linux_user_systemctl_command()
                            .args(["restart", SYSTEMD_UNIT_NAME])
                            .stdin(Stdio::null())
                            .output()
                            .context("failed to execute 'systemctl --user restart'")?;
                        if !out.status.success() {
                            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                            if detail.is_empty() {
                                bail!(
                                    "failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                                    out.status
                                );
                            }
                            bail!(
                                "failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}"
                            );
                        }
                    }
                }
            }
        }

        if verbose {
            println!(
                "Switched vdpi engine to {} (saved {}).",
                target.as_str(),
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (target, cfg, verbose);
        bail!("engine switching is not supported on {}", platform_name());
    }
}

/// Updates the configured upstream DNS server in `config.toml` and restarts any
/// running background service so the new resolver takes effect immediately.
pub fn set_service_dns(dns_addr: &str, cfg: &RuntimeConfig) -> Result<()> {
    set_service_dns_impl(dns_addr, cfg, true)
}

/// Silent variant of [`set_service_dns`] for the interactive Control Center TUI.
pub fn set_service_dns_quiet(dns_addr: &str, cfg: &RuntimeConfig) -> Result<()> {
    set_service_dns_impl(dns_addr, cfg, false)
}

fn set_service_dns_impl(dns_addr: &str, cfg: &RuntimeConfig, verbose: bool) -> Result<()> {
    let validated =
        vdpi_core::dns::validate_custom_dns_input(dns_addr).map_err(|msg| anyhow::anyhow!(msg))?;
    let redacted = vdpi_core::dns::redact_dns_for_display(&validated);

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait,
        };

        let svc = query_windows_service_status();
        if svc.installed && !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to update the vdpi Windows service DNS server to {redacted}..."
                );
            }
            relaunch_elevated_and_wait(&["dns".to_string(), validated.clone()])?;
            if verbose {
                println!("Updated vdpi Windows service DNS server to {redacted}.");
            }
            return Ok(());
        }

        let use_system = svc.installed;
        let config_path = if use_system {
            config_file::system_config_path()
        } else {
            config_file::user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), use_system)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        if validated
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        {
            file_cfg.doh = Some(true);
        }
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;

        if svc.installed {
            let was_running = matches!(svc.state, "RUNNING" | "START_PENDING");
            let target_bin = installed_binary_path()
                .ok()
                .filter(|p| p.is_file())
                .or_else(|| std::env::current_exe().ok())
                .context("failed to determine vdpi binary path for DNS update")?;
            let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
            let bin_path_cmd = build_windows_service_bin_path(&target_bin, &target_cfg);
            install_or_update_windows_service_with_start(&bin_path_cmd, was_running)?;
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {redacted} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        if daemon_exists && !is_unix_root() {
            let args = vec!["dns".to_string(), validated.clone()];
            let action = format!("update the macOS background service DNS server to {redacted}");
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if daemon_exists {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), daemon_exists)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        if validated
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        {
            file_cfg.doh = Some(true);
        }
        if !daemon_exists {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if !daemon_exists {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
        if daemon_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let plist_path = launch_daemon_plist_path();
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", "system", &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            fs::write(
                &plist_path,
                generate_launch_daemon_plist(&target_bin, &target_cfg),
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
            }
            if was_running {
                start_macos_launch_daemon(&plist_path)?;
            }
        } else if agent_exists {
            let target_bin = installed_binary_path()?;
            let plist_path = launch_agent_plist_path()?;
            let uid = current_uid();
            let domain = format!("gui/{uid}");
            let service_target = format!("{domain}/{LAUNCH_AGENT_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &domain, &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            let plist_xml = generate_launch_agent_plist(&target_bin, &target_cfg);
            write_unix_user_file_safely(&plist_path, plist_xml.as_bytes())?;
            if was_running {
                start_macos_launch_agent(&plist_path, false)?;
            }
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {redacted} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        if system_exists && !is_unix_root() {
            let args = vec!["dns".to_string(), validated.clone()];
            let action = format!("update the Linux background service DNS server to {redacted}");
            relaunch_unix_sudo_and_wait(&args, &action)?;
            return Ok(());
        }

        let config_path = if system_exists {
            config_file::system_config_path()
        } else {
            resolved_user_config_path()
        };
        let mut file_cfg = config_file::load_file_config(Some(&config_path), system_exists)
            .ok()
            .and_then(|(found, fc)| found.map(|_| fc))
            .unwrap_or_else(|| file_config_from_runtime(cfg));
        file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
        file_cfg.dns_addr = Some(validated.clone());
        if validated
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
        {
            file_cfg.doh = Some(true);
        }
        if !system_exists {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        config_file::save_file_config_atomic(&config_path, &file_cfg)?;
        if !system_exists {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(cfg, &file_cfg);
        if system_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let unit_path = systemd_system_unit_path();
            let unit_text = generate_systemd_system_unit(&target_bin, &target_cfg);
            write_linux_system_unit_atomically(&unit_path, &unit_text)?;
            let _ = Command::new(resolve_systemctl_bin())
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = Command::new(resolve_systemctl_bin())
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
            }
        } else if user_exists {
            let target_bin = installed_binary_path()?;
            let unit_path = systemd_user_unit_path()?;
            let unit_text = generate_systemd_unit(&target_bin, &target_cfg);
            write_unix_user_file_safely(&unit_path, unit_text.as_bytes())?;
            let _ = linux_user_systemctl_command()
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = linux_user_systemctl_command()
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl --user restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
            }
        }

        if verbose {
            println!(
                "Updated vdpi DNS server to {redacted} (saved {}).",
                config_path.display()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (validated, redacted, cfg, verbose);
        bail!("DNS configuration is not supported on {}", platform_name());
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn save_split_tunnel_to_config_path_with_result(
    config_path: &Path,
    service_mode: bool,
    cfg: &vdpi_core::config::SplitTunnelConfig,
) -> Result<FileConfig> {
    let (_, mut file_cfg) =
        config_file::load_file_config_or_default(Some(config_path), service_mode)?;
    file_cfg.schema_version = Some(CONFIG_SCHEMA_VERSION);
    file_cfg.split_tunnel_mode = Some(cfg.mode);
    file_cfg.split_tunnel_apps = Some(cfg.apps.clone());
    config_file::save_file_config_atomic(config_path, &file_cfg)?;
    Ok(file_cfg)
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
#[allow(dead_code)]
fn save_split_tunnel_to_config_path(
    config_path: &Path,
    service_mode: bool,
    cfg: &vdpi_core::config::SplitTunnelConfig,
) -> Result<()> {
    let _ = save_split_tunnel_to_config_path_with_result(config_path, service_mode, cfg)?;
    Ok(())
}

const SPLIT_APPS_FILE_PREFIX: &str = "__vdpi_split_apps_file__:";
#[cfg(any(target_os = "windows", test))]
const WINDOWS_SHELLEXECUTE_SAFE_ARGS_LIMIT: usize = 1200;
const MAX_SPLIT_APPS_TEMP_FILE_BYTES: u64 = 64 * 1024;
#[cfg(any(target_os = "windows", test))]
static SPLIT_APPS_TEMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(any(target_os = "windows", test))]
struct TempFileCleanupGuard(PathBuf);

#[cfg(any(target_os = "windows", test))]
impl Drop for TempFileCleanupGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn resolve_split_tunnel_apps_input(raw_apps: &[String]) -> Result<Vec<String>> {
    if raw_apps.len() == 1 {
        if let Some(raw_path) = raw_apps[0].strip_prefix(SPLIT_APPS_FILE_PREFIX) {
            let path = Path::new(raw_path);
            let file_name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("");
            if !file_name.starts_with("vdpi-split-apps-") || !file_name.ends_with(".txt") {
                bail!("invalid temporary split-tunnel app list path");
            }
            let meta = fs::symlink_metadata(path).with_context(|| {
                format!(
                    "failed to inspect temporary split-tunnel app list {}",
                    path.display()
                )
            })?;
            if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                bail!(
                    "temporary split-tunnel app list {} must be a regular non-symlink file",
                    path.display()
                );
            }
            if meta.len() > MAX_SPLIT_APPS_TEMP_FILE_BYTES {
                bail!(
                    "temporary split-tunnel app list {} exceeds maximum size ({} bytes)",
                    path.display(),
                    MAX_SPLIT_APPS_TEMP_FILE_BYTES
                );
            }
            let content = fs::read_to_string(path).with_context(|| {
                format!(
                    "failed to read temporary split-tunnel app list {}",
                    path.display()
                )
            })?;
            let parsed: Vec<String> = content
                .lines()
                .map(|line| line.trim_end_matches('\r').to_string())
                .filter(|line| !line.is_empty())
                .collect();
            return config_file::validate_split_tunnel_apps(&parsed);
        }
    }
    config_file::validate_split_tunnel_apps(raw_apps)
}

#[cfg(any(target_os = "windows", test))]
fn windows_shell_execute_params_len(args: &[String]) -> usize {
    args.iter()
        .map(|arg| quote_windows_arg(arg).len())
        .sum::<usize>()
        .saturating_add(args.len().saturating_sub(1))
}

#[cfg(any(target_os = "windows", test))]
fn build_windows_split_apply_args_with_temp(
    cfg: &vdpi_core::config::SplitTunnelConfig,
) -> Result<(Vec<String>, Option<TempFileCleanupGuard>)> {
    use std::fs::OpenOptions;
    use std::sync::atomic::Ordering;

    let inline_args = build_split_apply_args(cfg);
    if windows_shell_execute_params_len(&inline_args) <= WINDOWS_SHELLEXECUTE_SAFE_ARGS_LIMIT {
        return Ok((inline_args, None));
    }

    let temp_dir = std::env::temp_dir();
    let pid = std::process::id();
    let payload = cfg.apps.join("\n");

    let mut created = None;
    for _ in 0..16 {
        let seq = SPLIT_APPS_TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = temp_dir.join(format!("vdpi-split-apps-{pid}-{seq}.txt"));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        match opts.open(&candidate) {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to create temporary split-tunnel app list {}",
                        candidate.display()
                    )
                });
            }
        }
    }
    let (temp_path, mut file) = created.ok_or_else(|| {
        anyhow::anyhow!("failed to allocate unique temporary file for split-tunnel elevation")
    })?;

    if let Err(err) = file
        .write_all(payload.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| {
            format!(
                "failed to write temporary split-tunnel app list {}",
                temp_path.display()
            )
        })
    {
        drop(file);
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    drop(file);

    let args = vec![
        "split".to_string(),
        "apply".to_string(),
        "--mode".to_string(),
        cfg.mode.as_str().to_string(),
        "--app".to_string(),
        format!("{SPLIT_APPS_FILE_PREFIX}{}", temp_path.display()),
    ];
    Ok((args, Some(TempFileCleanupGuard(temp_path))))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn resolve_active_split_config_target(
    service_installed: bool,
    user_path: &Path,
    system_path: &Path,
) -> (PathBuf, bool) {
    let use_system = service_installed || (!user_path.is_file() && system_path.is_file());
    if use_system {
        (system_path.to_path_buf(), true)
    } else {
        (user_path.to_path_buf(), false)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
fn format_split_tunnel_saved_message(summary: &str, service_restarted: bool) -> String {
    if service_restarted {
        format!("Split tunneling saved: {summary} (service restarted)")
    } else {
        format!("Split tunneling saved: {summary}")
    }
}

/// Builds the `vdpi split apply --mode <mode> [--app <app>]...` CLI arguments
/// used when auto-elevating split-tunnel updates across `sudo` or Windows UAC.
pub fn build_split_apply_args(cfg: &vdpi_core::config::SplitTunnelConfig) -> Vec<String> {
    let mut args = vec![
        "split".to_string(),
        "apply".to_string(),
        "--mode".to_string(),
        cfg.mode.as_str().to_string(),
    ];
    for app in &cfg.apps {
        args.push("--app".to_string());
        args.push(app.clone());
    }
    args
}

/// Validates and saves per-application split-tunnel settings into the active
/// `config.toml` (preserving all other keys) and restarts the background `vdpi`
/// service when it is currently running.
pub fn set_service_split_tunnel(
    cfg: &vdpi_core::config::SplitTunnelConfig,
) -> anyhow::Result<String> {
    let validated_apps = resolve_split_tunnel_apps_input(&cfg.apps)?;
    let normalized = vdpi_core::config::SplitTunnelConfig {
        mode: cfg.mode,
        apps: validated_apps,
    };
    let summary = normalized.summary_label();

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait,
        };

        let svc = query_windows_service_status();
        let was_running = svc.installed && matches!(svc.state, "RUNNING" | "START_PENDING");
        let (config_path, use_system) = resolve_active_split_config_target(
            svc.installed,
            &config_file::user_config_path(),
            &config_file::system_config_path(),
        );

        if use_system && !is_elevated() {
            let (args, _temp_guard) = build_windows_split_apply_args_with_temp(&normalized)?;
            relaunch_elevated_and_wait(&args)?;
            if was_running {
                notify_wininet_refresh();
                broadcast_environment_change();
            }
            return Ok(format_split_tunnel_saved_message(&summary, was_running));
        }

        let file_cfg =
            save_split_tunnel_to_config_path_with_result(&config_path, use_system, &normalized)?;

        if svc.installed {
            let target_bin = installed_binary_path()
                .ok()
                .filter(|p| p.is_file())
                .or_else(|| std::env::current_exe().ok())
                .context("failed to determine vdpi binary path for split-tunnel update")?;
            let target_cfg = apply_file_config_to_runtime(&RuntimeConfig::default(), &file_cfg);
            let bin_path_cmd = build_windows_service_bin_path(&target_bin, &target_cfg);
            install_or_update_windows_service_with_start(&bin_path_cmd, was_running)?;
            if was_running {
                notify_wininet_refresh();
                broadcast_environment_change();
            }
            return Ok(format_split_tunnel_saved_message(&summary, was_running));
        }

        Ok(format_split_tunnel_saved_message(&summary, false))
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_exists = launch_daemon_plist_path().exists();
        let agent_exists = launch_agent_plist_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        let (config_path, use_system) = resolve_active_split_config_target(
            daemon_exists,
            &resolved_user_config_path(),
            &config_file::system_config_path(),
        );

        if use_system && !is_unix_root() {
            let args = build_split_apply_args(&normalized);
            relaunch_unix_sudo_and_wait(&args, "update split tunneling settings")?;
            return Ok(format_split_tunnel_saved_message(&summary, was_running));
        }

        if !use_system {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        let file_cfg =
            save_split_tunnel_to_config_path_with_result(&config_path, use_system, &normalized)?;
        if !use_system {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(&RuntimeConfig::default(), &file_cfg);
        if daemon_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let plist_path = launch_daemon_plist_path();
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", "system", &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            fs::write(
                &plist_path,
                generate_launch_daemon_plist(&target_bin, &target_cfg),
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&plist_path, fs::Permissions::from_mode(0o644));
            }
            if was_running {
                start_macos_launch_daemon(&plist_path)?;
                return Ok(format_split_tunnel_saved_message(&summary, true));
            }
        } else if agent_exists {
            let target_bin = installed_binary_path()?;
            let plist_path = launch_agent_plist_path()?;
            let uid = current_uid();
            let domain = format!("gui/{uid}");
            let service_target = format!("{domain}/{LAUNCH_AGENT_LABEL}");
            let plist_str = plist_path.display().to_string();
            if was_running || launchctl_service_loaded(&service_target) {
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &domain, &plist_str])
                    .stdin(Stdio::null())
                    .output();
                wait_launchctl_unloaded(&service_target);
            }
            let plist_xml = generate_launch_agent_plist(&target_bin, &target_cfg);
            write_unix_user_file_safely(&plist_path, plist_xml.as_bytes())?;
            if was_running {
                start_macos_launch_agent(&plist_path, false)?;
                return Ok(format_split_tunnel_saved_message(&summary, true));
            }
        }

        Ok(format_split_tunnel_saved_message(&summary, false))
    }

    #[cfg(target_os = "linux")]
    {
        let system_exists = systemd_system_unit_path().exists();
        let user_exists = systemd_user_unit_path().ok().is_some_and(|p| p.exists());
        let was_running = detect_service_state() == ServiceState::Running;

        let (config_path, use_system) = resolve_active_split_config_target(
            system_exists,
            &resolved_user_config_path(),
            &config_file::system_config_path(),
        );

        if use_system && !is_unix_root() {
            let args = build_split_apply_args(&normalized);
            relaunch_unix_sudo_and_wait(&args, "update split tunneling settings")?;
            return Ok(format_split_tunnel_saved_message(&summary, was_running));
        }

        if !use_system {
            ensure_no_symlink_under_user_home(&config_path)?;
            if let Some(parent) = config_path.parent() {
                create_dir_all_for_unix_user(parent)?;
            }
        }
        let file_cfg =
            save_split_tunnel_to_config_path_with_result(&config_path, use_system, &normalized)?;
        if !use_system {
            if let Some(parent) = config_path.parent() {
                chown_to_sudo_user(parent);
            }
            chown_to_sudo_user(&config_path);
        }

        let target_cfg = apply_file_config_to_runtime(&RuntimeConfig::default(), &file_cfg);
        if system_exists {
            let target_bin = PathBuf::from(UNIX_SYSTEM_BIN_PATH);
            let unit_path = systemd_system_unit_path();
            let unit_text = generate_systemd_system_unit(&target_bin, &target_cfg);
            write_linux_system_unit_atomically(&unit_path, &unit_text)?;
            let _ = Command::new(resolve_systemctl_bin())
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = Command::new(resolve_systemctl_bin())
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
                return Ok(format_split_tunnel_saved_message(&summary, true));
            }
        } else if user_exists {
            let target_bin = installed_binary_path()?;
            let unit_path = systemd_user_unit_path()?;
            let unit_text = generate_systemd_unit(&target_bin, &target_cfg);
            write_unix_user_file_safely(&unit_path, unit_text.as_bytes())?;
            let _ = linux_user_systemctl_command()
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            if was_running {
                let out = linux_user_systemctl_command()
                    .args(["restart", SYSTEMD_UNIT_NAME])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute 'systemctl --user restart'")?;
                if !out.status.success() {
                    let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                    bail!("failed to restart systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
                }
                return Ok(format_split_tunnel_saved_message(&summary, true));
            }
        }

        Ok(format_split_tunnel_saved_message(&summary, false))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (normalized, summary);
        bail!(
            "split tunneling configuration is not supported on {}",
            platform_name()
        );
    }
}

#[cfg(any(target_os = "linux", test))]
const LINUX_TUN_ARTIFACT_PATHS: &[&str] = &[
    "/sys/class/net/vdpi0",
    "/run/vdpi/tun-state.json",
    "/var/lib/vdpi/resolv.conf.orig",
    "/var/lib/vdpi/resolv-meta.json",
    "/run/NetworkManager/conf.d/99-vdpi-dns.conf",
];

#[cfg(any(target_os = "linux", test))]
fn has_linux_tun_artifacts_in(paths: &[&Path]) -> bool {
    paths
        .iter()
        .any(|p| p.exists() || fs::symlink_metadata(p).is_ok())
}

#[cfg(target_os = "linux")]
fn has_orphan_linux_tun_artifacts() -> bool {
    let refs: Vec<&Path> = LINUX_TUN_ARTIFACT_PATHS.iter().map(Path::new).collect();
    has_linux_tun_artifacts_in(&refs)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn cleanup_unix_root_dir_with_home(
    user_home: Option<&Path>,
    root: &Path,
    user_cfg: &Path,
    purge: bool,
) {
    let is_safe_target = |target: &Path| -> bool {
        if let Some(home) = user_home {
            if ensure_no_symlink_under_base(home, target).is_err() {
                return false;
            }
        }
        match fs::symlink_metadata(target) {
            Ok(meta) => !meta.file_type().is_symlink(),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => false,
        }
    };

    if !is_safe_target(root) || !root.exists() {
        return;
    }
    if purge {
        let _ = fs::remove_dir_all(root);
        return;
    }
    for subdir in [root.join("bin"), root.join("logs")] {
        if is_safe_target(&subdir) && subdir.exists() {
            let _ = fs::remove_dir_all(&subdir);
        }
    }
    for file in [root.join("state.json"), root.join("proxy-lease.lock")] {
        if is_safe_target(&file) && file.exists() {
            let _ = fs::remove_file(&file);
        }
    }
    if !user_cfg.starts_with(root) && is_safe_target(root) {
        let _ = fs::remove_dir(root);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn cleanup_unix_root_dir(root: &Path, user_cfg: &Path, purge: bool) {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        if ensure_no_symlink_under_user_home(root).is_err() {
            return;
        }
        let sudo_home = resolve_sudo_invoking_user().map(|u| u.home_dir);
        cleanup_unix_root_dir_with_home(sudo_home.as_deref(), root, user_cfg, purge);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        cleanup_unix_root_dir_with_home(None, root, user_cfg, purge);
    }
}

/// Stops the background service, removes startup registration, cleans installed files,
/// and restores system proxy state (including removing persisted `config.toml`).
pub fn uninstall_service() -> Result<()> {
    uninstall_service_with_options(true)
}

/// Quiet variant of [`uninstall_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn uninstall_service_quiet() -> Result<()> {
    uninstall_service_with_options_impl(true, false)
}

/// Stops the background service (both system TUN and user Proxy units if present), removes
/// startup registration, cleans installed files, restores system proxy state, and removes
/// `config.toml` when `purge` is `true`.
pub fn uninstall_service_with_options(purge: bool) -> Result<()> {
    uninstall_service_with_options_impl(purge, true)
}

fn uninstall_service_with_options_impl(purge: bool, verbose: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let daemon_present = launch_daemon_plist_path().exists()
            || launchctl_service_loaded(&format!("system/{LAUNCH_DAEMON_LABEL}"))
            || fs::symlink_metadata(UNIX_SYSTEM_BIN_PATH).is_ok()
            || (purge && config_file::system_config_path().exists());
        if daemon_present && !is_unix_root() {
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            return relaunch_unix_sudo_and_wait(&args, "uninstall the vdpi TUN background service");
        }
        if remove_macos_launch_daemon_if_present()? && verbose {
            println!(
                "Removed LaunchDaemon: {}",
                launch_daemon_plist_path().display()
            );
        }
        let sys_bin = Path::new(UNIX_SYSTEM_BIN_PATH);
        if fs::symlink_metadata(sys_bin).is_ok() {
            match fs::remove_file(sys_bin) {
                Ok(()) => {
                    if verbose {
                        println!("Removed system binary: {}", sys_bin.display());
                    }
                }
                Err(err) => {
                    if verbose {
                        eprintln!(
                            "Warning: could not remove {} ({err}); run with sudo if needed.",
                            sys_bin.display()
                        );
                    }
                }
            }
        }

        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        let plist_path = launch_agent_plist_path()?;

        // Always attempt service-target bootout even when the plist file is already missing.
        let _ = macos_launch_agent_launchctl_command()
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output();

        if fs::symlink_metadata(&plist_path).is_ok() || plist_path.exists() {
            ensure_no_symlink_under_user_home(&plist_path)?;
            if plist_path.exists() {
                let plist_str = plist_path.display().to_string();
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &domain_target, &plist_str])
                    .stdin(Stdio::null())
                    .output();
                let _ = macos_launch_agent_launchctl_command()
                    .args(["unload", &plist_str])
                    .stdin(Stdio::null())
                    .output();
                fs::remove_file(&plist_path)?;
                if verbose {
                    println!("Removed LaunchAgent: {}", plist_path.display());
                }
            }
        } else if verbose {
            println!("LaunchAgent {} is not installed", plist_path.display());
        }

        wait_launchctl_unloaded(&service_target);

        if remove_unix_shell_path() && verbose {
            println!("Removed ~/.vdpi/bin from shell PATH profile.");
        }
        // Restore system proxy settings while `~/.vdpi/macos-proxy-state.json` is still intact.
        clear_all_system_proxies()?;
        let _ = fs::remove_file("/Library/Application Support/vdpi/state.json");
        let user_cfg = resolved_user_config_path();
        if let Ok(root) = vdpi_root_dir() {
            cleanup_unix_root_dir(&root, &user_cfg, purge);
        }
        if purge {
            let sys_cfg = config_file::system_config_path();
            if sys_cfg.is_file() {
                let _ = fs::remove_file(&sys_cfg);
                if let Some(parent) = sys_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            if ensure_no_symlink_under_user_home(&user_cfg).is_ok() && user_cfg.is_file() {
                let _ = fs::remove_file(&user_cfg);
                if let Some(parent) = user_cfg.parent() {
                    if ensure_no_symlink_under_user_home(parent).is_ok() {
                        let _ = fs::remove_dir(parent);
                    }
                }
            }
            let _ = fs::remove_file("/var/log/vdpi.out.log");
            let _ = fs::remove_file("/var/log/vdpi.err.log");
        }
    }

    #[cfg(target_os = "linux")]
    {
        let system_present = systemd_system_unit_path().exists()
            || fs::symlink_metadata(UNIX_SYSTEM_BIN_PATH).is_ok()
            || has_orphan_linux_tun_artifacts()
            || (purge
                && (config_file::system_config_path().exists()
                    || Path::new("/var/lib/vdpi").exists()));
        if system_present && !is_unix_root() {
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            return relaunch_unix_sudo_and_wait(&args, "uninstall the vdpi TUN background service");
        }
        if remove_linux_system_unit_if_present()? && verbose {
            println!(
                "Removed systemd system unit: {}",
                systemd_system_unit_path().display()
            );
        }
        // Clean up any Linux TUN adapter, policy routes, and DNS state while `/var/lib/vdpi`
        // state files are still intact (before `uninstall --purge` deletes `/var/lib/vdpi`).
        if is_unix_root() {
            let _ = crate::platform::linux_tun::cleanup_linux_tun_state();
        }
        let sys_bin = Path::new(UNIX_SYSTEM_BIN_PATH);
        if fs::symlink_metadata(sys_bin).is_ok() {
            match fs::remove_file(sys_bin) {
                Ok(()) => {
                    if verbose {
                        println!("Removed system binary: {}", sys_bin.display());
                    }
                }
                Err(err) => {
                    if verbose {
                        eprintln!(
                            "Warning: could not remove {} ({err}); run with sudo if needed.",
                            sys_bin.display()
                        );
                    }
                }
            }
        }

        let unit_path = systemd_user_unit_path()?;
        let _ = linux_user_systemctl_command()
            .args(["disable", "--now", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output();
        if fs::symlink_metadata(&unit_path).is_ok() || unit_path.exists() {
            ensure_no_symlink_under_user_home(&unit_path)?;
            if unit_path.exists() {
                fs::remove_file(&unit_path)?;
                let _ = linux_user_systemctl_command()
                    .args(["daemon-reload"])
                    .stdin(Stdio::null())
                    .output();
                if verbose {
                    println!("Removed systemd user unit: {}", unit_path.display());
                }
            }
        } else if verbose {
            println!("Systemd unit {} is not installed", unit_path.display());
        }
        if let Ok(home) = home_dir() {
            let local_bin = home.join(".local").join("bin");
            if ensure_no_symlink_under_user_home(&local_bin).is_ok() {
                let link_path = local_bin.join("vdpi");
                if fs::symlink_metadata(&link_path).is_ok_and(|meta| meta.is_symlink()) {
                    let _ = fs::remove_file(&link_path);
                }
            }
        }
        if remove_unix_shell_path() && verbose {
            println!("Removed ~/.vdpi/bin from shell PATH profile.");
        }
        // Restore desktop/systemd proxy settings BEFORE `cleanup_unix_root_dir` / `--purge`
        // deletes `~/.vdpi/linux-proxy-state.json`.
        clear_all_system_proxies()?;
        let _ = fs::remove_file("/run/vdpi/state.json");
        let user_cfg = resolved_user_config_path();
        if let Ok(root) = vdpi_root_dir() {
            cleanup_unix_root_dir(&root, &user_cfg, purge);
        }
        if purge {
            let _ = fs::remove_dir_all("/run/vdpi");
            let _ = fs::remove_dir_all("/var/lib/vdpi");
            let sys_cfg = config_file::system_config_path();
            if sys_cfg.is_file() {
                let _ = fs::remove_file(&sys_cfg);
                if let Some(parent) = sys_cfg.parent() {
                    let _ = fs::remove_dir(parent);
                }
            }
            if ensure_no_symlink_under_user_home(&user_cfg).is_ok() && user_cfg.is_file() {
                let _ = fs::remove_file(&user_cfg);
                if let Some(parent) = user_cfg.parent() {
                    if ensure_no_symlink_under_user_home(parent).is_ok() {
                        let _ = fs::remove_dir(parent);
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{is_elevated, relaunch_elevated_and_wait};

        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to uninstall the vdpi Windows service..."
                );
            }
            let _ = std::env::set_current_dir(std::env::temp_dir());
            let mut args = vec!["uninstall".to_string()];
            if purge {
                args.push("--purge".to_string());
            }
            relaunch_elevated_and_wait(&args)?;
            clear_all_system_proxies()?;
            if verbose {
                println!(
                    "Removed Windows service '{WINDOWS_SERVICE_NAME}' and restored {} system proxy settings.",
                    platform_name()
                );
            }
            return Ok(());
        }

        let removed = crate::platform::windows_service::uninstall_windows_service()?;
        cleanup_legacy_windows_startup();
        stop_windows_foreground_daemons();
        let _ = crate::platform::windows_tun::cleanup_orphan_wintun_adapter();
        if verbose {
            if removed {
                println!("Stopped and removed Windows service: {WINDOWS_SERVICE_NAME}");
            } else {
                println!("Windows service '{WINDOWS_SERVICE_NAME}' is not installed.");
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = purge;

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    clear_all_system_proxies()?;

    #[cfg(target_os = "windows")]
    cleanup_windows_install_files(purge);

    if verbose {
        println!("Restored {} system proxy settings.", platform_name());
    }
    Ok(())
}

/// Temporarily stops the background `vdpi` service and restores system proxies without
/// uninstalling installed files, PATH entries, or service registration.
pub fn pause_service() -> Result<()> {
    pause_service_impl(true)
}

/// Quiet variant of [`pause_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn pause_service_quiet() -> Result<()> {
    pause_service_impl(false)
}

#[cfg(any(target_os = "windows", test))]
fn needs_windows_pause_elevation_without_service(
    orphan_tun: bool,
    loopback_winhttp: bool,
    is_elevated: bool,
) -> bool {
    !is_elevated && (orphan_tun || loopback_winhttp)
}

fn pause_service_impl(verbose: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows_service::{
            is_elevated, query_windows_service_status, relaunch_elevated_and_wait,
            stop_windows_service_if_running,
        };

        if !query_windows_service_status().installed {
            stop_windows_foreground_daemons();
            let orphan_tun = detect_orphan_windows_tun_adapter();
            let loopback_winhttp = !orphan_tun && detect_loopback_winhttp_proxy();
            if needs_windows_pause_elevation_without_service(
                orphan_tun,
                loopback_winhttp,
                is_elevated(),
            ) {
                if verbose {
                    if orphan_tun {
                        println!(
                            "Requesting Administrator privileges to remove orphaned Wintun adapter ({})...",
                            crate::platform::windows_tun::VDPI_TUN_NAME
                        );
                    } else {
                        println!(
                            "Requesting Administrator privileges to reset stale Windows WinHTTP proxy..."
                        );
                    }
                }
                if let Err(err) = relaunch_elevated_and_wait(&["pause".to_string()]) {
                    let _ = clear_all_system_proxies();
                    return Err(err);
                }
                clear_all_system_proxies()?;
                if verbose {
                    if orphan_tun && !detect_orphan_windows_tun_adapter() {
                        println!(
                            "No Windows service installed; cleaned up orphaned Wintun adapter ({}) and restored Windows system proxies.",
                            crate::platform::windows_tun::VDPI_TUN_NAME
                        );
                    } else if loopback_winhttp && !detect_loopback_winhttp_proxy() {
                        println!(
                            "No Windows service installed; reset stale Windows WinHTTP proxy and restored Windows system proxies."
                        );
                    } else {
                        println!(
                            "No Windows service installed; restored Windows system proxies and checked for orphaned adapters."
                        );
                    }
                }
                return Ok(());
            }
            let orphan_cleaned = crate::platform::windows_tun::cleanup_orphan_wintun_adapter();
            clear_all_system_proxies()?;
            if verbose {
                if orphan_cleaned {
                    println!(
                        "No Windows service installed; cleaned up orphaned Wintun adapter ({}) and restored Windows system proxies.",
                        crate::platform::windows_tun::VDPI_TUN_NAME
                    );
                } else {
                    println!(
                        "No Windows service installed; restored Windows system proxies and checked for orphaned adapters."
                    );
                }
            }
            return Ok(());
        }

        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to pause the vdpi Windows service..."
                );
            }
            if let Err(err) = relaunch_elevated_and_wait(&["pause".to_string()]) {
                let _ = clear_all_system_proxies();
                return Err(err);
            }
            clear_all_system_proxies()?;
            return Ok(());
        }

        let _ = stop_windows_service_if_running()?;
        stop_windows_foreground_daemons();
        let _ = crate::platform::windows_tun::cleanup_orphan_wintun_adapter();
        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused Windows service '{WINDOWS_SERVICE_NAME}' and restored Windows system proxies."
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["pause".to_string()],
                    "pause the vdpi TUN background service",
                );
            }
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            let plist_str = daemon_path.display().to_string();
            let mut out = Command::new("/bin/launchctl")
                .args(["bootout", &service_target])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl bootout'")?;
            if !out.status.success() && launchctl_service_loaded(&service_target) {
                out = Command::new("/bin/launchctl")
                    .args(["bootout", "system", &plist_str])
                    .stdin(Stdio::null())
                    .output()
                    .context("failed to execute '/bin/launchctl bootout'")?;
            }
            wait_launchctl_unloaded(&service_target);
            if detect_service_state() == ServiceState::Running {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to pause LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to pause LaunchDaemon '{LAUNCH_DAEMON_LABEL}': {detail}");
            }
            if verbose {
                println!(
                    "Paused LaunchDaemon '{LAUNCH_DAEMON_LABEL}' and restored macOS TUN routing/DNS."
                );
            }
            return Ok(());
        }

        let plist_path = launch_agent_plist_path()?;
        if !plist_path.exists() {
            bail!(
                "vdpi LaunchAgent is not installed ({}).",
                plist_path.display()
            );
        }
        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        let plist_str = plist_path.display().to_string();

        let mut out = macos_launch_agent_launchctl_command()
            .args(["bootout", &service_target])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute '/bin/launchctl bootout'")?;

        if !out.status.success() && launchctl_service_loaded(&service_target) {
            out = macos_launch_agent_launchctl_command()
                .args(["bootout", &domain_target, &plist_str])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute '/bin/launchctl bootout'")?;
        }

        // Wait for launchd asynchronous bootout teardown so the exiting daemon
        // does not race with clear_all_system_proxies().
        wait_launchctl_unloaded(&service_target);

        if detect_service_state() == ServiceState::Running {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to pause LaunchAgent '{LAUNCH_AGENT_LABEL}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to pause LaunchAgent '{LAUNCH_AGENT_LABEL}': {detail}");
        }

        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused LaunchAgent '{LAUNCH_AGENT_LABEL}' and restored {} system proxy settings.",
                platform_name()
            );
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_unit = systemd_system_unit_path();
        if system_unit.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["pause".to_string()],
                    "pause the vdpi TUN background service",
                );
            }
            let out = Command::new(resolve_systemctl_bin())
                .args(["stop", SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .output()
                .context("failed to execute 'systemctl stop'")?;
            let not_loaded_and_stopped =
                out.status.code() == Some(5) && detect_service_state() != ServiceState::Running;
            if !out.status.success() && !not_loaded_and_stopped {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to pause systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to pause systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
            }
            let _ = crate::platform::linux_tun::cleanup_linux_tun_state();
            if verbose {
                println!(
                    "Paused systemd system unit '{SYSTEMD_UNIT_NAME}' and restored Linux TUN routing/DNS."
                );
            }
            return Ok(());
        }

        let unit_path = systemd_user_unit_path()?;
        let has_orphan_tun = has_orphan_linux_tun_artifacts();
        if has_orphan_tun && !is_unix_root() {
            return relaunch_unix_sudo_and_wait(
                &["pause".to_string()],
                "clean up orphaned Linux TUN state",
            );
        }
        if !unit_path.exists() {
            if is_unix_root() && has_orphan_tun {
                let _ = crate::platform::linux_tun::cleanup_linux_tun_state();
                clear_all_system_proxies()?;
                if verbose {
                    println!(
                        "No systemd unit installed; cleaned up orphaned Linux TUN state and restored system proxies."
                    );
                }
                return Ok(());
            }
            bail!(
                "vdpi systemd user unit is not installed ({}).",
                unit_path.display()
            );
        }
        let out = linux_user_systemctl_command()
            .args(["stop", SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output()
            .context("failed to execute 'systemctl --user stop'")?;
        let not_loaded_and_stopped =
            out.status.code() == Some(5) && detect_service_state() != ServiceState::Running;
        if !out.status.success() && !not_loaded_and_stopped {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to pause systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to pause systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
        }
        if is_unix_root() {
            let _ = crate::platform::linux_tun::cleanup_linux_tun_state();
        }
        clear_all_system_proxies()?;
        if verbose {
            println!(
                "Paused systemd user unit '{SYSTEMD_UNIT_NAME}' and restored {} system proxy settings.",
                platform_name()
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = verbose;
        bail!(
            "pausing background service is not supported on {}",
            platform_name()
        );
    }
}

/// Starts or restarts a previously installed/paused background `vdpi` service.
pub fn resume_service() -> Result<()> {
    resume_service_impl(true)
}

/// Quiet variant of [`resume_service`] for interactive TUI callers that must not write
/// status lines to stdout.
pub fn resume_service_quiet() -> Result<()> {
    resume_service_impl(false)
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn load_resume_file_config(path: &Path, service_mode: bool) -> Result<Option<FileConfig>> {
    if !path.is_file() {
        return Ok(None);
    }
    let (loaded, file_cfg) = config_file::load_file_config(Some(path), service_mode)
        .with_context(|| {
            format!(
                "cannot resume vdpi service: failed to parse config file {}",
                path.display()
            )
        })?;
    Ok(loaded.map(|_| file_cfg))
}

#[cfg(any(target_os = "linux", test))]
fn linux_resume_systemctl_action(unit_changed: bool) -> &'static str {
    if unit_changed {
        "restart"
    } else {
        "start"
    }
}

fn resume_service_impl(verbose: bool) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::{broadcast_environment_change, notify_wininet_refresh};
        use crate::platform::windows_service::{
            install_or_update_windows_service_with_start, is_elevated,
            query_windows_service_status, relaunch_elevated_and_wait, start_windows_service,
        };

        let svc = query_windows_service_status();
        if !svc.installed {
            bail!("vdpi Windows service is not installed. Run 'vdpi install' first.");
        }

        let target_bin = installed_binary_path()
            .ok()
            .filter(|p| p.is_file())
            .or_else(|| std::env::current_exe().ok());
        let target_bin_dir = target_bin.as_deref().and_then(Path::parent);
        let fallback_engine = svc
            .binary_path
            .as_deref()
            .and_then(|cmd| migrate_legacy_service_cmdline_to_file_config(cmd).engine)
            .unwrap_or_default();
        let configured_engine = load_configured_engine(fallback_engine);

        // Preflight verified wintun.dll BEFORE triggering UAC so TUN resumes fail fast
        // with a clear error instead of prompting UAC and failing inside the elevated child.
        if configured_engine == EngineMode::Tun {
            let _ = preflight_windows_tun_wintun(
                target_bin_dir,
                "resume the vdpi Windows service in TUN mode",
            )?;
        }

        if !is_elevated() {
            if verbose {
                println!(
                    "Requesting Administrator privileges to resume the vdpi Windows service..."
                );
            }
            relaunch_elevated_and_wait(&["resume".to_string()])?;
            notify_wininet_refresh();
            broadcast_environment_change();
            return Ok(());
        }

        let sys_cfg_path = config_file::system_config_path();
        let mut updated_and_started = false;
        if let Some(file_cfg) = load_resume_file_config(&sys_cfg_path, true)? {
            let base_cfg = RuntimeConfig {
                engine: fallback_engine,
                ..RuntimeConfig::default()
            };
            let desired_cfg = apply_file_config_to_runtime(&base_cfg, &file_cfg);
            if desired_cfg.engine == EngineMode::Tun {
                let src_wintun = preflight_windows_tun_wintun(
                    target_bin_dir,
                    "resume the vdpi Windows service in TUN mode",
                )?;
                if let Some(bin_dir) = target_bin_dir {
                    let target_wintun = bin_dir.join("wintun.dll");
                    let needs_repair = !target_wintun.is_file()
                        || crate::platform::windows_tun::expected_wintun_dll_sha256()
                            .and_then(|sha| {
                                crate::platform::windows_tun::verify_wintun_dll_sha256(
                                    &target_wintun,
                                    sha,
                                )
                            })
                            .is_err();
                    if needs_repair {
                        let _ = copy_verified_wintun_to_bin_dir_with_backup(
                            &src_wintun,
                            bin_dir,
                            false,
                        )?;
                    }
                }
            }
            if let Some(bin) = target_bin.as_deref() {
                let desired_cmd = build_windows_service_bin_path(bin, &desired_cfg);
                let current_cmd = svc.binary_path.as_deref().map(str::trim).unwrap_or("");
                if current_cmd != desired_cmd {
                    install_or_update_windows_service_with_start(&desired_cmd, true)?;
                    updated_and_started = true;
                }
            }
        }

        if !updated_and_started && !start_windows_service()? {
            bail!("vdpi Windows service is not installed. Run 'vdpi install' first.");
        }
        notify_wininet_refresh();
        broadcast_environment_change();
        if verbose {
            println!(
                "Resumed Windows service '{WINDOWS_SERVICE_NAME}' (anti-DPI protection active)."
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["resume".to_string()],
                    "resume the vdpi TUN background service",
                );
            }
            let sys_cfg_path = config_file::system_config_path();
            let mut plist_changed = false;
            if let Some(file_cfg) = load_resume_file_config(&sys_cfg_path, true)? {
                let base_cfg = RuntimeConfig {
                    engine: EngineMode::Tun,
                    ..RuntimeConfig::default()
                };
                let mut desired_cfg = apply_file_config_to_runtime(&base_cfg, &file_cfg);
                desired_cfg.engine = EngineMode::Tun;
                let desired_plist =
                    generate_launch_daemon_plist(Path::new(UNIX_SYSTEM_BIN_PATH), &desired_cfg);
                if fs::read_to_string(&daemon_path).ok().as_deref() != Some(desired_plist.as_str())
                {
                    fs::write(&daemon_path, &desired_plist)?;
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&daemon_path, fs::Permissions::from_mode(0o644));
                    plist_changed = true;
                }
            }
            let service_target = format!("system/{LAUNCH_DAEMON_LABEL}");
            if plist_changed && launchctl_service_loaded(&service_target) {
                let plist_str = daemon_path.display().to_string();
                let _ = Command::new("/bin/launchctl")
                    .args(["bootout", &service_target])
                    .stdin(Stdio::null())
                    .output();
                if launchctl_service_loaded(&service_target) {
                    let _ = Command::new("/bin/launchctl")
                        .args(["bootout", "system", &plist_str])
                        .stdin(Stdio::null())
                        .output();
                }
                wait_launchctl_unloaded(&service_target);
            }
            start_macos_launch_daemon(&daemon_path)?;
            if verbose {
                println!(
                    "Resumed LaunchDaemon '{LAUNCH_DAEMON_LABEL}' (TUN anti-DPI protection active)."
                );
            }
            return Ok(());
        }

        let plist_path = launch_agent_plist_path()?;
        if !plist_path.exists() {
            bail!(
                "vdpi LaunchAgent is not installed ({}). Run 'vdpi install' first.",
                plist_path.display()
            );
        }
        let user_cfg_path = resolved_user_config_path();
        let mut plist_changed = false;
        if let Some(file_cfg) = load_resume_file_config(&user_cfg_path, false)? {
            if let Ok(target_bin) = installed_binary_path() {
                let base_cfg = RuntimeConfig {
                    engine: EngineMode::Proxy,
                    ..RuntimeConfig::default()
                };
                let mut desired_cfg = apply_file_config_to_runtime(&base_cfg, &file_cfg);
                desired_cfg.engine = EngineMode::Proxy;
                let desired_plist = generate_launch_agent_plist(&target_bin, &desired_cfg);
                if fs::read_to_string(&plist_path).ok().as_deref() != Some(desired_plist.as_str()) {
                    write_unix_user_file_safely(&plist_path, desired_plist.as_bytes())?;
                    plist_changed = true;
                }
            }
        }
        let uid = current_uid();
        let domain_target = format!("gui/{uid}");
        let service_target = format!("{domain_target}/{LAUNCH_AGENT_LABEL}");
        if plist_changed && launchctl_service_loaded(&service_target) {
            let plist_str = plist_path.display().to_string();
            let _ = macos_launch_agent_launchctl_command()
                .args(["bootout", &service_target])
                .stdin(Stdio::null())
                .output();
            if launchctl_service_loaded(&service_target) {
                let _ = macos_launch_agent_launchctl_command()
                    .args(["bootout", &domain_target, &plist_str])
                    .stdin(Stdio::null())
                    .output();
            }
            wait_launchctl_unloaded(&service_target);
        }
        start_macos_launch_agent(&plist_path, false)?;

        if verbose {
            println!("Resumed LaunchAgent '{LAUNCH_AGENT_LABEL}' (anti-DPI protection active).");
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    {
        let system_unit = systemd_system_unit_path();
        if system_unit.exists() {
            if !is_unix_root() {
                return relaunch_unix_sudo_and_wait(
                    &["resume".to_string()],
                    "resume the vdpi TUN background service",
                );
            }
            let sys_cfg_path = config_file::system_config_path();
            let mut unit_changed = false;
            if let Some(file_cfg) = load_resume_file_config(&sys_cfg_path, true)? {
                let base_cfg = RuntimeConfig {
                    engine: EngineMode::Tun,
                    ..RuntimeConfig::default()
                };
                let mut desired_cfg = apply_file_config_to_runtime(&base_cfg, &file_cfg);
                desired_cfg.engine = EngineMode::Tun;
                let desired_unit =
                    generate_systemd_system_unit(Path::new(UNIX_SYSTEM_BIN_PATH), &desired_cfg);
                if fs::read_to_string(&system_unit).ok().as_deref() != Some(desired_unit.as_str())
                {
                    write_linux_system_unit_atomically(&system_unit, &desired_unit)?;
                    unit_changed = true;
                }
            }
            let _ = Command::new(resolve_systemctl_bin())
                .args(["daemon-reload"])
                .stdin(Stdio::null())
                .output();
            let action = linux_resume_systemctl_action(unit_changed);
            let out = Command::new(resolve_systemctl_bin())
                .args([action, SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .output()
                .with_context(|| format!("failed to execute 'systemctl {action}'"))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = stderr.trim();
                if detail.is_empty() {
                    bail!(
                        "failed to resume systemd system unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                        out.status
                    );
                }
                bail!("failed to resume systemd system unit '{SYSTEMD_UNIT_NAME}': {detail}");
            }
            if verbose {
                println!(
                    "Resumed systemd system unit '{SYSTEMD_UNIT_NAME}' (TUN anti-DPI protection active)."
                );
            }
            return Ok(());
        }

        let unit_path = systemd_user_unit_path()?;
        if !unit_path.exists() {
            bail!(
                "vdpi systemd user unit is not installed ({}). Run 'vdpi install' first.",
                unit_path.display()
            );
        }
        let user_cfg_path = resolved_user_config_path();
        let mut unit_changed = false;
        if let Some(file_cfg) = load_resume_file_config(&user_cfg_path, false)? {
            if let Ok(target_bin) = installed_binary_path() {
                let base_cfg = RuntimeConfig {
                    engine: EngineMode::Proxy,
                    ..RuntimeConfig::default()
                };
                let mut desired_cfg = apply_file_config_to_runtime(&base_cfg, &file_cfg);
                desired_cfg.engine = EngineMode::Proxy;
                let desired_unit = generate_systemd_unit(&target_bin, &desired_cfg);
                if fs::read_to_string(&unit_path).ok().as_deref() != Some(desired_unit.as_str()) {
                    write_unix_user_file_safely(&unit_path, desired_unit.as_bytes())?;
                    unit_changed = true;
                }
            }
        }
        let _ = linux_user_systemctl_command()
            .args(["daemon-reload"])
            .stdin(Stdio::null())
            .output();
        let action = linux_resume_systemctl_action(unit_changed);
        let out = linux_user_systemctl_command()
            .args([action, SYSTEMD_UNIT_NAME])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("failed to execute 'systemctl --user {action}'"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr.trim();
            if detail.is_empty() {
                bail!(
                    "failed to resume systemd user unit '{SYSTEMD_UNIT_NAME}' (exit status: {})",
                    out.status
                );
            }
            bail!("failed to resume systemd user unit '{SYSTEMD_UNIT_NAME}': {detail}");
        }

        // Briefly confirm the unit did not immediately crash into `failed` state.
        let deadline = Instant::now() + Duration::from_millis(400);
        loop {
            if let Ok(state_out) = linux_user_systemctl_command()
                .args(["is-active", SYSTEMD_UNIT_NAME])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
            {
                let state = String::from_utf8_lossy(&state_out.stdout);
                if state.trim() == "failed" {
                    bail!(
                        "systemd user unit '{SYSTEMD_UNIT_NAME}' entered failed state immediately after start"
                    );
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if verbose {
            println!(
                "Resumed systemd user unit '{SYSTEMD_UNIT_NAME}' (anti-DPI protection active)."
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = verbose;
        bail!(
            "resuming background service is not supported on {}",
            platform_name()
        );
    }
}

async fn read_capped_health_body(mut resp: reqwest::Response) -> Option<String> {
    let mut buf = Vec::with_capacity(512);
    while buf.len() < MAX_HEALTH_RESPONSE_BYTES {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_HEALTH_RESPONSE_BYTES - buf.len();
                let take = chunk.len().min(remaining);
                buf.extend_from_slice(&chunk[..take]);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

async fn discover_live_daemon(
    client: &Client,
    cfg: &RuntimeConfig,
) -> (IpAddr, u16, Option<u16>, Option<String>) {
    let states = read_runtime_states();

    for candidate in build_probe_candidates(cfg, &states) {
        let socket = SocketAddr::new(candidate.connect_ip, candidate.port);
        let url = format!("http://{socket}/vdpi-health");
        let Ok(resp) = client.get(url).send().await else {
            continue;
        };
        if !resp.status().is_success() {
            continue;
        }
        let Some(text) = read_capped_health_body(resp).await else {
            continue;
        };
        if parse_health_json(&text, candidate.addr, candidate.port, candidate.socks_port).is_some()
        {
            return (
                candidate.addr,
                candidate.port,
                candidate.socks_port,
                Some(text),
            );
        }
    }

    (cfg.addr, cfg.port, cfg.socks_port, None)
}

fn format_tun_engine_summary(live: &LiveEngineStatus) -> String {
    let mut base = match (live.tun_interface.as_deref(), live.physical_nic.as_deref()) {
        (Some(iface), Some(nic)) => format!("{iface} via {nic}"),
        (Some(iface), None) => iface.to_string(),
        (None, Some(nic)) => format!("via {nic}"),
        (None, None) => "active".to_string(),
    };
    if let Some(rss_kb) = live.rss_kb {
        base.push_str(" · ");
        base.push_str(&format_rss_label(rss_kb));
    }
    base
}

fn format_proxy_engine_summary(live: &LiveEngineStatus) -> String {
    let mut base = format!("{}:{}", live.addr, live.port);
    if let Some(rss_kb) = live.rss_kb {
        base.push_str(" · ");
        base.push_str(&format_rss_label(rss_kb));
    }
    base
}

/// Prints a comprehensive status overview of `vdpi`, startup service registration, and OS proxies.
pub async fn print_status(cfg: &RuntimeConfig) -> Result<()> {
    print_status_with_options(cfg, false).await
}

fn redact_urls_in_text(text: &str) -> String {
    vdpi_core::dns::redact_urls_in_text(text)
}

#[cfg(any(target_os = "windows", test))]
fn format_service_command_for_display(command: &str) -> String {
    redact_urls_in_text(command)
}

fn effective_live_doh(live: &LiveEngineStatus, configured_dns: &str) -> Option<bool> {
    let active_dns = live.dns_addr.as_deref().unwrap_or(configured_dns);
    live.doh
        .map(|doh| vdpi_core::dns::is_effective_doh_target(active_dns, doh))
}

fn redact_health_body_for_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(obj) = value.as_object_mut() {
            if let Some(dns) = obj
                .get("dns_addr")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
            {
                obj.insert(
                    "dns_addr".to_string(),
                    serde_json::Value::String(vdpi_core::dns::redact_dns_for_display(&dns)),
                );
            }
            if let Ok(serialized) = serde_json::to_string(&value) {
                return serialized;
            }
        }
    }
    redact_urls_in_text(trimmed)
}

fn format_status_dns_line(configured_dns: &str, live_status: Option<&LiveEngineStatus>) -> String {
    if let Some(live) = live_status {
        let active_raw = live.dns_addr.as_deref().unwrap_or(configured_dns);
        let active_display = vdpi_core::dns::redact_dns_for_display(active_raw);
        format!("DNS Server                : {active_display}")
    } else {
        let configured_display = vdpi_core::dns::redact_dns_for_display(configured_dns);
        format!("DNS Server                : {configured_display} (configured)")
    }
}

fn build_status_json_payload(
    service_state: ServiceState,
    configured_engine: EngineMode,
    configured_dns: &str,
    vpn_conflict: Option<&str>,
    split_tunnel: &vdpi_core::config::SplitTunnelConfig,
    live_status: Option<&LiveEngineStatus>,
) -> serde_json::Value {
    let service_state_str = match service_state {
        ServiceState::Running => "running",
        ServiceState::Stopped => "stopped",
        ServiceState::NotInstalled => "not_installed",
    };
    let configured_dns_display = vdpi_core::dns::redact_dns_for_display(configured_dns);
    let active_dns_raw = live_status
        .and_then(|live| live.dns_addr.as_deref())
        .unwrap_or(configured_dns);
    let active_dns_display = vdpi_core::dns::redact_dns_for_display(active_dns_raw);
    let live_json = live_status.map(|live| {
        serde_json::json!({
            "addr": live.addr.to_string(),
            "port": live.port,
            "socks_port": live.socks_port,
            "engine": live.engine.as_str(),
            "tun_interface": live.tun_interface,
            "physical_nic": live.physical_nic,
            "vpn_conflict": live.vpn_conflict,
            "version": live.version,
            "mode": live.mode,
            "doh": effective_live_doh(live, configured_dns),
            "dns_addr": live.dns_addr.as_deref().map(vdpi_core::dns::redact_dns_for_display),
            "block_quic": live.block_quic,
            "active_connections": live.active_connections,
            "total_connections": live.total_connections,
            "learned_hosts": live.learned_hosts,
            "isp_stage": live.isp_stage,
            "udp_flows_active": live.udp_flows_active,
            "quic_blocked": live.quic_blocked,
            "dns_queries": live.dns_queries,
            "rss_kb": live.rss_kb,
            "bytes_rx": live.bytes_rx,
            "bytes_tx": live.bytes_tx,
            "tls_handshakes": live.tls_handshakes,
            "auto_heal_escalations": live.auto_heal_escalations,
        })
    });
    serde_json::json!({
        "platform": platform_name(),
        "version": env!("CARGO_PKG_VERSION"),
        "service_state": service_state_str,
        "running": live_status.is_some(),
        "configured_engine": configured_engine.as_str(),
        "configured_dns": configured_dns_display,
        "active_dns": active_dns_display,
        "vpn_conflict": vpn_conflict,
        "split_tunnel": {
            "mode": split_tunnel.mode.as_str(),
            "apps": split_tunnel.apps,
        },
        "live": live_json,
    })
}

fn resolve_status_configured_engine_and_dns(
    cfg: &RuntimeConfig,
    config_path: Option<&Path>,
) -> (EngineMode, String) {
    if config_path.is_some() {
        let normalized_dns = vdpi_core::dns::validate_custom_dns_input(&cfg.dns_addr)
            .unwrap_or_else(|_| cfg.dns_addr.clone());
        return (cfg.engine, normalized_dns);
    }
    (
        load_configured_engine(cfg.engine),
        load_configured_dns(&cfg.dns_addr),
    )
}

fn resolve_status_configured_split_tunnel(
    cfg: &RuntimeConfig,
    config_path: Option<&Path>,
) -> vdpi_core::config::SplitTunnelConfig {
    if config_path.is_some() {
        cfg.split_tunnel.clone()
    } else {
        load_configured_split_tunnel()
    }
}

/// Prints status in either human-readable text or structured JSON (`json = true`).
pub async fn print_status_with_options(cfg: &RuntimeConfig, json: bool) -> Result<()> {
    print_status_with_options_and_config(cfg, json, None).await
}

/// Prints status in either human-readable text or structured JSON (`json = true`),
/// honoring an explicit `--config` path when provided instead of probing default
/// system/user `config.toml` files.
pub async fn print_status_with_options_and_config(
    cfg: &RuntimeConfig,
    json: bool,
    config_path: Option<&Path>,
) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;

    let (active_addr, active_port, active_socks_port, health_body) =
        discover_live_daemon(&client, cfg).await;

    let live_status = health_body
        .as_deref()
        .and_then(|text| parse_health_json(text, active_addr, active_port, active_socks_port));

    let (configured_engine, configured_dns) =
        resolve_status_configured_engine_and_dns(cfg, config_path);
    let vpn_conflict = if cfg.vpn_coexistence == VpnCoexistence::Off {
        None
    } else {
        live_status
            .as_ref()
            .and_then(|live| live.vpn_conflict.clone())
            .or_else(|| {
                detect_vpn_conflict_summary(
                    live_status
                        .as_ref()
                        .and_then(|live| live.tun_interface.as_deref()),
                )
            })
    };

    if json {
        let split_tunnel = resolve_status_configured_split_tunnel(cfg, config_path);
        let payload = build_status_json_payload(
            detect_service_state(),
            configured_engine,
            &configured_dns,
            vpn_conflict.as_deref(),
            &split_tunnel,
            live_status.as_ref(),
        );
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    println!("=== vdpi status ({}) ===", platform_name());

    if let Some(ref live) = live_status {
        match live.engine {
            EngineMode::Tun => {
                println!(
                    "Engine (TUN)              : {}",
                    format_tun_engine_summary(live)
                );
                println!(
                    "Health Endpoint           : {}:{} -> RUNNING",
                    active_addr, active_port
                );
            }
            EngineMode::Proxy => {
                let daemon_state = match health_body.as_deref() {
                    Some(text) => format!("RUNNING ({})", redact_health_body_for_display(text)),
                    None => "NOT RESPONDING".to_string(),
                };
                let socks_state = if let Some(sp) = active_socks_port {
                    if let Some(connect_ip) = probe_connect_ip(active_addr) {
                        match tokio::time::timeout(
                            Duration::from_secs(1),
                            tokio::net::TcpStream::connect((connect_ip, sp)),
                        )
                        .await
                        {
                            Ok(Ok(_)) => format!("LISTENING ({}:{})", active_addr, sp),
                            _ => format!("CLOSED ({}:{})", active_addr, sp),
                        }
                    } else {
                        format!("UNREACHABLE ({}:{})", active_addr, sp)
                    }
                } else {
                    "DISABLED (available via primary port auto-detect)".to_string()
                };
                println!(
                    "Engine (Proxy)            : {}",
                    format_proxy_engine_summary(live)
                );
                println!(
                    "Primary HTTP/CONNECT/Auto : {}:{} -> {}",
                    active_addr, active_port, daemon_state
                );
                println!("Dedicated SOCKS5 (TCP/UDP): {}", socks_state);
            }
        }
    } else {
        let engine_tag = match configured_engine {
            EngineMode::Tun => "TUN",
            EngineMode::Proxy => "Proxy",
        };
        println!("Engine ({engine_tag})             : NOT RESPONDING");
        if configured_engine == EngineMode::Proxy {
            println!(
                "Primary HTTP/CONNECT/Auto : {}:{} -> NOT RESPONDING",
                active_addr, active_port
            );
            let socks_state = if let Some(sp) = active_socks_port {
                format!("CLOSED ({}:{})", active_addr, sp)
            } else {
                "DISABLED (available via primary port auto-detect)".to_string()
            };
            println!("Dedicated SOCKS5 (TCP/UDP): {}", socks_state);
        }
    }

    if let Some(ref conflict) = vpn_conflict {
        println!("VPN Conflict              : {conflict}");
    }

    println!(
        "{}",
        format_status_dns_line(&configured_dns, live_status.as_ref())
    );

    if let Some(ref live) = live_status {
        let mut engine_parts = Vec::new();
        if let Some(mode) = live.mode.as_deref() {
            engine_parts.push(format!("mode={mode}"));
        }
        if let Some(doh) = effective_live_doh(live, &configured_dns) {
            engine_parts.push(format!("DoH={}", if doh { "on" } else { "off" }));
        }
        if let Some(block_quic) = live.block_quic {
            engine_parts.push(format!(
                "QUIC={}",
                if block_quic { "blocked" } else { "allowed" }
            ));
        }
        if let Some(stage) = live.isp_stage.as_deref() {
            engine_parts.push(format!("ISP stage={stage}"));
        }
        if !engine_parts.is_empty() {
            println!("Anti-DPI Engine           : {}", engine_parts.join(", "));
        }

        let mut telemetry_parts = Vec::new();
        match (live.active_connections, live.total_connections) {
            (Some(active), Some(total)) => {
                telemetry_parts.push(format!("{active} active / {total} total connections"));
            }
            (Some(active), None) => {
                telemetry_parts.push(format!("{active} active connections"));
            }
            (None, Some(total)) => {
                telemetry_parts.push(format!("{total} total connections"));
            }
            (None, None) => {}
        }
        if let Some(hosts) = live.learned_hosts {
            telemetry_parts.push(format!("{hosts} cached hosts"));
        }
        if let Some(udp) = live.udp_flows_active {
            telemetry_parts.push(format!("{udp} UDP flows"));
        }
        if let Some(quic) = live.quic_blocked {
            telemetry_parts.push(format!("{quic} QUIC blocked"));
        }
        if let Some(dns) = live.dns_queries {
            telemetry_parts.push(format!("{dns} DNS queries"));
        }
        if let Some(rss_kb) = live.rss_kb {
            telemetry_parts.push(format_rss_label(rss_kb));
        }
        if !telemetry_parts.is_empty() {
            println!("Live Telemetry            : {}", telemetry_parts.join(", "));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let daemon_path = launch_daemon_plist_path();
        if daemon_path.exists() {
            let daemon_state =
                if launchctl_service_running(&format!("system/{LAUNCH_DAEMON_LABEL}")) {
                    "running"
                } else {
                    "paused"
                };
            println!(
                "LaunchDaemon plist (TUN)  : {} ({daemon_state})",
                daemon_path.display()
            );
        }
        let plist_path = launch_agent_plist_path()?;
        let agent_state = if !plist_path.exists() {
            "not installed"
        } else if launchctl_service_running(&format!("gui/{}/{LAUNCH_AGENT_LABEL}", current_uid()))
        {
            "running"
        } else {
            "paused"
        };
        println!(
            "LaunchAgent plist         : {} ({agent_state})",
            plist_path.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        let sys_unit = systemd_system_unit_path();
        if sys_unit.exists() {
            let sys_state = if systemd_unit_active(false) {
                "running"
            } else {
                "paused"
            };
            println!(
                "systemd system unit (TUN) : {} ({sys_state})",
                sys_unit.display()
            );
        }
        let unit_path = systemd_user_unit_path()?;
        let user_state = if !unit_path.exists() {
            "not installed"
        } else if systemd_unit_active(true) {
            "running"
        } else {
            "paused"
        };
        println!(
            "systemd user unit         : {} ({user_state})",
            unit_path.display()
        );
    }

    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;
        use crate::platform::windows_service::query_windows_service_status;

        let svc = query_windows_service_status();
        if svc.installed {
            let pid_suffix = svc.pid.map(|p| format!(", PID {p}")).unwrap_or_default();
            println!(
                "Windows Service ({WINDOWS_SERVICE_NAME})    : {} ({}{})",
                svc.state, svc.start_type, pid_suffix
            );
            if let Some(bin) = svc.binary_path {
                println!(
                    "Service Command           : {}",
                    format_service_command_for_display(&bin)
                );
            }
        } else {
            println!("Windows Service ({WINDOWS_SERVICE_NAME})    : NOT INSTALLED");
        }

        if let Some(legacy) = query_reg_sz(WINDOWS_LEGACY_RUN_KEY, "vdpi") {
            println!(
                "Legacy Startup (HKCU Run) : {} (run 'vdpi install' to migrate)",
                redact_urls_in_text(&legacy)
            );
        }
    }

    print_platform_proxy_status();
    Ok(())
}

async fn query_live_health_snapshot(
    client: &Client,
    addr: IpAddr,
    port: u16,
    socks_port: Option<u16>,
) -> Option<LiveEngineStatus> {
    let connect_ip = probe_connect_ip(addr)?;
    let url = format!("http://{}/vdpi-health", SocketAddr::new(connect_ip, port));
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = read_capped_health_body(resp).await?;
    parse_health_json(&text, addr, port, socks_port)
}

async fn run_tun_udp_dns_check(timeout: Duration) -> Result<(Vec<IpAddr>, u128)> {
    let query = crate::dns::encode_dns_query("discord.com", 1)?;
    let t0 = Instant::now();
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(&query, SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)))
        .await?;
    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await??;
    let (ips, _) = crate::dns::decode_dns_response(&buf[..n], 1)?;
    if ips.is_empty() {
        bail!("UDP DNS response for discord.com contained no A records");
    }
    Ok((ips, t0.elapsed().as_millis()))
}

async fn send_quic_initial_probe() -> Result<()> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let mut pkt = vec![0u8; 1200];
    // RFC 9000 QUIC v1 Initial long header (0xc0 | version=0x00000001 | dcid_len=8 | scid_len=0)
    pkt[0] = 0xc0;
    pkt[1..5].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    pkt[5] = 8;
    pkt[6..14].copy_from_slice(b"vdpiprob");
    pkt[14] = 0;
    sock.send_to(&pkt, SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 443)))
        .await?;
    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
#[allow(dead_code)]
fn normalize_proxy_connect_addr(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
#[allow(dead_code)]
fn format_expected_proxy_url(addr: IpAddr, port: u16) -> String {
    match normalize_proxy_connect_addr(addr) {
        IpAddr::V4(v4) => format!("http://{v4}:{port}"),
        IpAddr::V6(v6) => format!("http://[{v6}]:{port}"),
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
#[allow(dead_code)]
fn format_expected_pac_url(addr: IpAddr, port: u16) -> String {
    format!("{}/vdpi.pac", format_expected_proxy_url(addr, port))
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn is_loopback_host_str(host: &str) -> bool {
    let trimmed = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost")
        || trimmed
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn is_loopback_authority_str(authority: &str) -> bool {
    let authority = authority.trim();
    if authority.is_empty() {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after)) = rest.split_once(']') else {
            return false;
        };
        if !after.is_empty() {
            let Some(port) = after.strip_prefix(':') else {
                return false;
            };
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        return host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified());
    }
    let host = match authority.split_once(':') {
        Some((h, port)) => {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            h
        }
        None => authority,
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn is_loopback_proxy_env_val(raw: &str) -> bool {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return false;
    }
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let authority = without_scheme
        .split_once('/')
        .map_or(without_scheme, |(auth, _)| auth);
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, auth)| auth)
        .trim();
    if authority.is_empty() {
        return false;
    }
    let first_token = authority
        .split([' ', '\t'])
        .next()
        .unwrap_or("")
        .trim();
    is_loopback_authority_str(first_token) || is_loopback_host_str(first_token)
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn is_vdpi_pac_url_generic(url: &str) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://") else {
        return false;
    };
    let Some((authority, path_and_query)) = rest.split_once('/') else {
        return false;
    };
    let path = path_and_query.split(['?', '#']).next().unwrap_or("");
    path == "vdpi.pac" && is_loopback_authority_str(authority)
}

#[cfg(target_os = "windows")]
#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_windows_proxy_drift(
    active_addr: IpAddr,
    active_port: u16,
    proxy_enable: bool,
    proxy_server: &str,
    auto_config_url: Option<&str>,
    env_http_proxy: Option<&str>,
    env_https_proxy: Option<&str>,
) -> Option<String> {
    evaluate_windows_proxy_drift_full(
        active_addr,
        active_port,
        proxy_enable,
        proxy_server,
        auto_config_url,
        env_http_proxy,
        env_https_proxy,
        None,
    )
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn evaluate_windows_proxy_drift_full(
    active_addr: IpAddr,
    active_port: u16,
    proxy_enable: bool,
    proxy_server: &str,
    auto_config_url: Option<&str>,
    env_http_proxy: Option<&str>,
    env_https_proxy: Option<&str>,
    env_all_proxy: Option<&str>,
) -> Option<String> {
    use crate::platform::windows::{
        build_windows_pac_url, is_vdpi_owned_pac_url, is_vdpi_owned_wininet_server,
    };

    let expected_pac_url = build_windows_pac_url(active_addr, active_port);
    let auto_config_trimmed = auto_config_url.map(str::trim).filter(|s| !s.is_empty());
    let server_trimmed = proxy_server.trim();

    if let Some(pac) = auto_config_trimmed {
        if is_vdpi_owned_pac_url(pac) && !pac.eq_ignore_ascii_case(&expected_pac_url) {
            return Some(format!(
                "WinINET AutoConfigURL points to '{pac}' instead of '{expected_pac_url}'"
            ));
        }
    }

    if proxy_enable && !server_trimmed.is_empty() {
        if is_vdpi_owned_wininet_server(server_trimmed) {
            return Some(format!(
                "WinINET ProxyEnable=1 uses legacy fail-closed ProxyServer '{server_trimmed}' instead of fail-open PAC '{expected_pac_url}'"
            ));
        }
        return Some(format!(
            "WinINET ProxyServer points to '{server_trimmed}' instead of fail-open PAC '{expected_pac_url}'"
        ));
    }

    for (var_name, val) in [
        ("HTTP_PROXY", env_http_proxy),
        ("HTTPS_PROXY", env_https_proxy),
        ("ALL_PROXY", env_all_proxy),
    ] {
        if let Some(raw) = val {
            let trimmed = raw.trim();
            if is_loopback_proxy_env_val(trimmed) {
                return Some(format!(
                    "stale HKCU\\Environment {var_name}='{trimmed}' left from legacy proxy mode (cannot fail open; restart vdpi or run 'vdpi pause' to clear)"
                ));
            }
        }
    }

    None
}

#[cfg(any(target_os = "windows", test))]
fn is_loopback_winhttp_proxy(raw: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::is_vdpi_owned_winhttp_proxy(raw)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return false;
        }
        if is_loopback_proxy_env_val(trimmed) {
            return true;
        }
        trimmed.split([';', ' ', '\t']).any(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return false;
            }
            let val = entry.split_once('=').map_or(entry, |(_, v)| v.trim());
            is_loopback_proxy_env_val(val)
        })
    }
}

#[cfg(any(target_os = "windows", test))]
fn parse_winhttp_proxy_server_output(text: &str) -> Option<String> {
    let mut fallback_value: Option<String> = None;
    for line in text.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let key_lower = key.trim().to_ascii_lowercase();
        let val_trimmed = val.trim();
        if val_trimmed.is_empty() || val_trimmed.eq_ignore_ascii_case("(none)") {
            continue;
        }
        if key_lower.contains("bypass") {
            continue;
        }
        if key_lower.starts_with("proxy server") {
            return Some(val_trimmed.to_string());
        }
        if fallback_value.is_none() && !key_lower.contains("winhttp") {
            fallback_value = Some(val_trimmed.to_string());
        }
    }
    fallback_value
}

#[cfg(target_os = "windows")]
fn query_windows_winhttp_proxy_server() -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let netsh = resolve_windows_system32_exe("netsh.exe")?;
    let out = Command::new(netsh)
        .creation_flags(CREATE_NO_WINDOW)
        .args(["winhttp", "show", "proxy"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    parse_winhttp_proxy_server_output(&text)
}

#[cfg(target_os = "windows")]
fn detect_loopback_winhttp_proxy() -> bool {
    query_windows_winhttp_proxy_server()
        .as_deref()
        .is_some_and(is_loopback_winhttp_proxy)
}

#[cfg(any(target_os = "windows", test))]
#[cfg_attr(not(test), allow(dead_code))]
fn evaluate_windows_stale_proxy_when_stopped(
    proxy_enable: bool,
    proxy_server: &str,
    auto_config_url: Option<&str>,
    env_http_proxy: Option<&str>,
    env_https_proxy: Option<&str>,
) -> Option<String> {
    evaluate_windows_stale_proxy_when_stopped_full(
        proxy_enable,
        proxy_server,
        auto_config_url,
        env_http_proxy,
        env_https_proxy,
        None,
        None,
    )
}

#[cfg(any(target_os = "windows", test))]
fn evaluate_windows_stale_proxy_when_stopped_full(
    proxy_enable: bool,
    proxy_server: &str,
    auto_config_url: Option<&str>,
    env_http_proxy: Option<&str>,
    env_https_proxy: Option<&str>,
    env_all_proxy: Option<&str>,
    winhttp_proxy: Option<&str>,
) -> Option<String> {
    if let Some(pac) = auto_config_url.map(str::trim).filter(|s| !s.is_empty()) {
        if is_vdpi_pac_url_generic(pac) {
            return Some(format!(
                "stale WinINET AutoConfigURL '{pac}' remains active while no vdpi daemon is running (run 'vdpi pause' to clear)"
            ));
        }
    }

    let server_trimmed = proxy_server.trim();
    if proxy_enable && !server_trimmed.is_empty() && is_loopback_proxy_env_val(server_trimmed) {
        return Some(format!(
            "stale WinINET ProxyEnable=1 points to loopback '{server_trimmed}' while no vdpi daemon is running (run 'vdpi pause' to clear)"
        ));
    }

    for (var_name, val) in [
        ("HTTP_PROXY", env_http_proxy),
        ("HTTPS_PROXY", env_https_proxy),
        ("ALL_PROXY", env_all_proxy),
    ] {
        if let Some(raw) = val {
            let trimmed = raw.trim();
            if is_loopback_proxy_env_val(trimmed) {
                return Some(format!(
                    "stale HKCU\\Environment {var_name}='{trimmed}' points to loopback while no vdpi daemon is running (run 'vdpi pause' to clear)"
                ));
            }
        }
    }

    if let Some(wh) = winhttp_proxy.map(str::trim).filter(|s| !s.is_empty()) {
        if is_loopback_winhttp_proxy(wh) {
            return Some(format!(
                "stale WinHTTP proxy '{wh}' points to loopback while no vdpi daemon is running (run 'vdpi pause' to clear)"
            ));
        }
    }

    None
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Default)]
struct MacosProxyServiceSnapshot {
    service: String,
    auto_proxy_enabled: bool,
    auto_proxy_url: String,
    web_enabled: bool,
    web_server: String,
    web_port: String,
    secure_enabled: bool,
    secure_server: String,
    secure_port: String,
    socks_enabled: bool,
    socks_server: String,
    socks_port: String,
}

#[cfg(any(target_os = "macos", test))]
fn evaluate_macos_proxy_drift_snapshot(
    active_addr: IpAddr,
    active_port: u16,
    statuses: &[MacosProxyServiceSnapshot],
    env_vars: &[(&str, Option<&str>)],
) -> Option<String> {
    let expected_pac_url = format_expected_pac_url(active_addr, active_port);
    let mut any_pac_aligned = false;

    for st in statuses {
        let pac_trimmed = st.auto_proxy_url.trim();
        if st.auto_proxy_enabled && !pac_trimmed.is_empty() {
            if pac_trimmed.eq_ignore_ascii_case(&expected_pac_url) {
                any_pac_aligned = true;
            } else if is_vdpi_pac_url_generic(pac_trimmed) {
                return Some(format!(
                    "macOS service '{}' AutoProxyURL points to '{}' instead of '{}'",
                    st.service, pac_trimmed, expected_pac_url
                ));
            }
        }

        if st.web_enabled && is_loopback_host_str(&st.web_server) {
            return Some(format!(
                "macOS service '{}' HTTP proxy uses legacy fail-closed {}:{} instead of fail-open PAC '{}'",
                st.service, st.web_server, st.web_port, expected_pac_url
            ));
        }
        if st.secure_enabled && is_loopback_host_str(&st.secure_server) {
            return Some(format!(
                "macOS service '{}' HTTPS proxy uses legacy fail-closed {}:{} instead of fail-open PAC '{}'",
                st.service, st.secure_server, st.secure_port, expected_pac_url
            ));
        }
        if st.socks_enabled && is_loopback_host_str(&st.socks_server) {
            return Some(format!(
                "macOS service '{}' SOCKS proxy uses legacy fail-closed {}:{} instead of fail-open PAC '{}'",
                st.service, st.socks_server, st.socks_port, expected_pac_url
            ));
        }
    }

    for &(var_name, val) in env_vars {
        if let Some(raw) = val {
            let trimmed = raw.trim();
            if is_loopback_proxy_env_val(trimmed) {
                return Some(format!(
                    "stale launchd {var_name}='{trimmed}' left from legacy proxy mode (cannot fail open; restart vdpi or run 'vdpi pause' to clear)"
                ));
            }
        }
    }

    if !any_pac_aligned {
        return Some(format!(
            "macOS AutoProxyURL (PAC) is disabled or unset on all network services (expected '{expected_pac_url}')"
        ));
    }

    None
}

#[cfg(any(target_os = "macos", test))]
fn evaluate_macos_stale_proxy_when_stopped(
    statuses: &[MacosProxyServiceSnapshot],
    env_vars: &[(&str, Option<&str>)],
) -> Option<String> {
    for st in statuses {
        let pac_trimmed = st.auto_proxy_url.trim();
        if st.auto_proxy_enabled && is_vdpi_pac_url_generic(pac_trimmed) {
            return Some(format!(
                "stale macOS service '{}' AutoProxyURL '{}' remains enabled while no vdpi daemon is running (run 'vdpi pause' to clear)",
                st.service, pac_trimmed
            ));
        }
        if st.web_enabled && is_loopback_host_str(&st.web_server) {
            return Some(format!(
                "stale macOS service '{}' HTTP proxy {}:{} remains enabled while no vdpi daemon is running",
                st.service, st.web_server, st.web_port
            ));
        }
        if st.secure_enabled && is_loopback_host_str(&st.secure_server) {
            return Some(format!(
                "stale macOS service '{}' HTTPS proxy {}:{} remains enabled while no vdpi daemon is running",
                st.service, st.secure_server, st.secure_port
            ));
        }
        if st.socks_enabled && is_loopback_host_str(&st.socks_server) {
            return Some(format!(
                "stale macOS service '{}' SOCKS proxy {}:{} remains enabled while no vdpi daemon is running",
                st.service, st.socks_server, st.socks_port
            ));
        }
    }

    for &(var_name, val) in env_vars {
        if let Some(raw) = val {
            let trimmed = raw.trim();
            if is_loopback_proxy_env_val(trimmed) {
                return Some(format!(
                    "stale launchd {var_name}='{trimmed}' remains set while no vdpi daemon is running (run 'vdpi pause' to clear)"
                ));
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn macos_status_to_snapshot(
    st: &crate::platform::macos::NetworkServiceProxyStatus,
) -> MacosProxyServiceSnapshot {
    MacosProxyServiceSnapshot {
        service: st.service.clone(),
        auto_proxy_enabled: st.auto_proxy_enabled,
        auto_proxy_url: st.auto_proxy_url.clone(),
        web_enabled: st.web_enabled,
        web_server: st.web_server.clone(),
        web_port: st.web_port.clone(),
        secure_enabled: st.secure_enabled,
        secure_server: st.secure_server.clone(),
        secure_port: st.secure_port.clone(),
        socks_enabled: st.socks_enabled,
        socks_server: st.socks_server.clone(),
        socks_port: st.socks_port.clone(),
    }
}

#[cfg(target_os = "macos")]
fn evaluate_macos_proxy_drift(
    active_addr: IpAddr,
    active_port: u16,
    statuses: &[crate::platform::macos::NetworkServiceProxyStatus],
    env_vars: &[(&str, Option<&str>)],
) -> Option<String> {
    let snapshots: Vec<MacosProxyServiceSnapshot> =
        statuses.iter().map(macos_status_to_snapshot).collect();
    evaluate_macos_proxy_drift_snapshot(active_addr, active_port, &snapshots, env_vars)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Default)]
struct LinuxProxySnapshot {
    gnome_available: bool,
    gnome_mode: Option<String>,
    gnome_autoconfig_url: Option<String>,
    gnome_manual_hosts: Vec<(&'static str, String)>,
    kde_available: bool,
    kde_proxy_type: Option<String>,
    kde_pac_url: Option<String>,
    kde_manual_proxies: Vec<(&'static str, String)>,
    systemd_env: Vec<(String, String)>,
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_show_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

#[cfg(any(target_os = "linux", test))]
fn parse_kioslaverc_proxy_settings(
    content: &str,
) -> (Option<String>, Option<String>, Vec<(&'static str, String)>) {
    let mut in_proxy_section = false;
    let mut proxy_type = None;
    let mut pac_url = None;
    let mut manual = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_proxy_section = line == "[Proxy Settings]";
            continue;
        }
        if !in_proxy_section {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim().to_string();
        match key {
            "ProxyType" => proxy_type = Some(val),
            "Proxy Config Script" => pac_url = Some(val),
            "httpProxy" => manual.push(("httpProxy", val)),
            "httpsProxy" => manual.push(("httpsProxy", val)),
            "socksProxy" => manual.push(("socksProxy", val)),
            _ => {}
        }
    }

    (proxy_type, pac_url, manual)
}

#[cfg(any(target_os = "linux", test))]
fn evaluate_linux_proxy_drift(
    active_addr: IpAddr,
    active_port: u16,
    snapshot: &LinuxProxySnapshot,
) -> Option<String> {
    let expected_url = format_expected_proxy_url(active_addr, active_port);
    let expected_pac_url = format_expected_pac_url(active_addr, active_port);

    if snapshot.gnome_available {
        let mode = snapshot
            .gnome_mode
            .as_deref()
            .map(|s| s.trim().trim_matches('\'').trim())
            .unwrap_or("");
        let pac = snapshot
            .gnome_autoconfig_url
            .as_deref()
            .map(|s| s.trim().trim_matches('\'').trim())
            .unwrap_or("");
        match mode {
            "auto" => {
                if pac.is_empty() {
                    return Some(format!(
                        "GNOME proxy mode is 'auto' but autoconfig-url is unset (expected '{expected_pac_url}')"
                    ));
                }
                if !pac.eq_ignore_ascii_case(&expected_pac_url) {
                    return Some(format!(
                        "GNOME autoconfig-url points to '{pac}' instead of '{expected_pac_url}'"
                    ));
                }
            }
            "manual" => {
                for (proto, host) in &snapshot.gnome_manual_hosts {
                    let clean_host = host.trim().trim_matches('\'').trim();
                    if !clean_host.is_empty() && is_loopback_host_str(clean_host) {
                        return Some(format!(
                            "GNOME proxy uses legacy fail-closed manual {proto} host '{clean_host}' instead of fail-open PAC '{expected_pac_url}'"
                        ));
                    }
                }
                return Some(format!(
                    "GNOME proxy mode is 'manual' instead of fail-open PAC 'auto' ('{expected_pac_url}')"
                ));
            }
            other => {
                return Some(format!(
                    "GNOME proxy mode is '{other}' instead of 'auto' with PAC '{expected_pac_url}'"
                ));
            }
        }
    }

    if snapshot.kde_available {
        let proxy_type = snapshot.kde_proxy_type.as_deref().map(str::trim).unwrap_or("");
        let pac = snapshot.kde_pac_url.as_deref().map(str::trim).unwrap_or("");
        match proxy_type {
            "2" => {
                if pac.is_empty() {
                    return Some(format!(
                        "KDE kioslaverc ProxyType=2 (PAC) but 'Proxy Config Script' is unset (expected '{expected_pac_url}')"
                    ));
                }
                if !pac.eq_ignore_ascii_case(&expected_pac_url) {
                    return Some(format!(
                        "KDE kioslaverc 'Proxy Config Script' points to '{pac}' instead of '{expected_pac_url}'"
                    ));
                }
            }
            "1" => {
                for (key, val) in &snapshot.kde_manual_proxies {
                    let trimmed = val.trim();
                    if !trimmed.is_empty() && is_loopback_proxy_env_val(trimmed) {
                        return Some(format!(
                            "KDE kioslaverc uses legacy fail-closed manual {key}='{trimmed}' instead of fail-open PAC '{expected_pac_url}'"
                        ));
                    }
                }
                return Some(format!(
                    "KDE kioslaverc ProxyType=1 (manual) instead of ProxyType=2 with PAC '{expected_pac_url}'"
                ));
            }
            other => {
                return Some(format!(
                    "KDE kioslaverc ProxyType is '{other}' instead of '2' with PAC '{expected_pac_url}'"
                ));
            }
        }
    }

    for (key, val) in &snapshot.systemd_env {
        let trimmed = val.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(key.as_str(), "ALL_PROXY" | "all_proxy") {
            if is_loopback_proxy_env_val(trimmed) {
                return Some(format!(
                    "stale systemd user {key}='{trimmed}' left from legacy proxy mode"
                ));
            }
        } else if matches!(
            key.as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "http_proxy" | "https_proxy"
        ) && is_loopback_proxy_env_val(trimmed)
            && !trimmed
                .trim_end_matches('/')
                .eq_ignore_ascii_case(&expected_url)
        {
            return Some(format!(
                "systemd user {key} points to '{trimmed}' instead of '{expected_url}'"
            ));
        }
    }

    None
}

#[cfg(any(target_os = "linux", test))]
fn evaluate_linux_stale_proxy_when_stopped(snapshot: &LinuxProxySnapshot) -> Option<String> {
    if snapshot.gnome_available {
        let mode = snapshot
            .gnome_mode
            .as_deref()
            .map(|s| s.trim().trim_matches('\'').trim())
            .unwrap_or("");
        let pac = snapshot
            .gnome_autoconfig_url
            .as_deref()
            .map(|s| s.trim().trim_matches('\'').trim())
            .unwrap_or("");
        if mode == "auto" && is_vdpi_pac_url_generic(pac) {
            return Some(format!(
                "stale GNOME autoconfig-url '{pac}' remains active while no vdpi daemon is running (run 'vdpi pause' to clear)"
            ));
        }
        if mode == "manual" {
            for (proto, host) in &snapshot.gnome_manual_hosts {
                let clean_host = host.trim().trim_matches('\'').trim();
                if !clean_host.is_empty() && is_loopback_host_str(clean_host) {
                    return Some(format!(
                        "stale GNOME manual {proto} proxy '{clean_host}' remains active while no vdpi daemon is running"
                    ));
                }
            }
        }
    }

    if snapshot.kde_available {
        let proxy_type = snapshot.kde_proxy_type.as_deref().map(str::trim).unwrap_or("");
        let pac = snapshot.kde_pac_url.as_deref().map(str::trim).unwrap_or("");
        if proxy_type == "2" && is_vdpi_pac_url_generic(pac) {
            return Some(format!(
                "stale KDE kioslaverc 'Proxy Config Script' '{pac}' remains active while no vdpi daemon is running (run 'vdpi pause' to clear)"
            ));
        }
        if proxy_type == "1" {
            for (key, val) in &snapshot.kde_manual_proxies {
                let trimmed = val.trim();
                if !trimmed.is_empty() && is_loopback_proxy_env_val(trimmed) {
                    return Some(format!(
                        "stale KDE kioslaverc manual {key}='{trimmed}' remains active while no vdpi daemon is running"
                    ));
                }
            }
        }
    }

    for (key, val) in &snapshot.systemd_env {
        let trimmed = val.trim();
        if matches!(
            key.as_str(),
            "HTTP_PROXY" | "HTTPS_PROXY" | "http_proxy" | "https_proxy" | "ALL_PROXY" | "all_proxy"
        ) && is_loopback_proxy_env_val(trimmed)
        {
            return Some(format!(
                "stale systemd user {key}='{trimmed}' remains set while no vdpi daemon is running (run 'vdpi pause' to clear)"
            ));
        }
    }

    None
}

#[cfg(any(target_os = "linux", test))]
fn should_check_kde_proxy_drift(xdg_current_desktop: Option<&str>, has_kioslaverc: bool) -> bool {
    let desktop = xdg_current_desktop
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if desktop.contains("kde") || desktop.contains("plasma") {
        return true;
    }
    desktop.is_empty() && has_kioslaverc
}

#[cfg(target_os = "linux")]
fn linux_user_tool_command(candidates: &[&str]) -> Option<Command> {
    let bin = candidates.iter().copied().find(|p| Path::new(p).is_file())?;
    let mut cmd = Command::new(bin);
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        configure_linux_user_command(&mut cmd, &sudo_user, true);
    }
    Some(cmd)
}

#[cfg(target_os = "linux")]
fn collect_linux_proxy_snapshot() -> LinuxProxySnapshot {
    let mut snap = LinuxProxySnapshot::default();

    let gsettings_get = |schema: &str, key: &str| -> Option<String> {
        let mut cmd = linux_user_tool_command(&["/usr/bin/gsettings", "/bin/gsettings"])?;
        let out = cmd
            .args(["get", schema, key])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    if let Some(mode) = gsettings_get("org.gnome.system.proxy", "mode") {
        snap.gnome_available = true;
        let clean_mode = mode.trim().trim_matches('\'').to_string();
        snap.gnome_mode = Some(mode);
        snap.gnome_autoconfig_url = gsettings_get("org.gnome.system.proxy", "autoconfig-url");
        if clean_mode == "manual" {
            for (label, schema) in [
                ("http", "org.gnome.system.proxy.http"),
                ("https", "org.gnome.system.proxy.https"),
                ("socks", "org.gnome.system.proxy.socks"),
            ] {
                if let Some(host) = gsettings_get(schema, "host") {
                    snap.gnome_manual_hosts.push((label, host));
                }
            }
        }
    }

    let kioslaverc_path = home_dir().ok().map(|home| {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| resolve_sudo_invoking_user().is_none() || p.starts_with(&home))
            .unwrap_or_else(|| home.join(".config"))
            .join("kioslaverc")
    });
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").ok();
    let has_kioslaverc = kioslaverc_path.as_ref().is_some_and(|p| p.is_file());
    let kde_active = should_check_kde_proxy_drift(desktop.as_deref(), has_kioslaverc);

    if kde_active {
        let kde_read_key = |key: &str| -> Option<String> {
            let mut cmd = linux_user_tool_command(&[
                "/usr/bin/kreadconfig6",
                "/usr/bin/kreadconfig5",
                "/bin/kreadconfig6",
                "/bin/kreadconfig5",
            ])?;
            let out = cmd
                .args([
                    "--file",
                    "kioslaverc",
                    "--group",
                    "Proxy Settings",
                    "--key",
                    key,
                ])
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        };

        if let Some(proxy_type) = kde_read_key("ProxyType") {
            snap.kde_available = true;
            snap.kde_proxy_type = Some(proxy_type.clone());
            snap.kde_pac_url = kde_read_key("Proxy Config Script");
            if proxy_type.trim() == "1" {
                for key in ["httpProxy", "httpsProxy", "socksProxy"] {
                    if let Some(val) = kde_read_key(key) {
                        snap.kde_manual_proxies.push((key, val));
                    }
                }
            }
        } else if let Some(ref path) = kioslaverc_path {
            if let Ok(content) = fs::read_to_string(path) {
                snap.kde_available = true;
                let (pt, pac, manual) = parse_kioslaverc_proxy_settings(&content);
                snap.kde_proxy_type = pt;
                snap.kde_pac_url = pac;
                snap.kde_manual_proxies = manual;
            }
        }
    }

    if let Ok(out) = linux_user_systemctl_command()
        .args(["show-environment"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            snap.systemd_env = parse_systemd_show_env(&text);
        }
    }

    snap
}

fn check_proxy_drift_for_live_daemon(active_addr: IpAddr, active_port: u16) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;

        let inet_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let enabled_raw = query_reg_sz(inet_key, "ProxyEnable").unwrap_or_default();
        let enabled = enabled_raw == "0x1" || enabled_raw == "1";
        let server = query_reg_sz(inet_key, "ProxyServer").unwrap_or_default();
        let auto_config_url = query_reg_sz(inet_key, "AutoConfigURL");
        let env_http = query_reg_sz(r"HKCU\Environment", "HTTP_PROXY");
        let env_https = query_reg_sz(r"HKCU\Environment", "HTTPS_PROXY");
        let env_all = query_reg_sz(r"HKCU\Environment", "ALL_PROXY");

        evaluate_windows_proxy_drift_full(
            active_addr,
            active_port,
            enabled,
            &server,
            auto_config_url.as_deref(),
            env_http.as_deref(),
            env_https.as_deref(),
            env_all.as_deref(),
        )
    }

    #[cfg(target_os = "macos")]
    {
        let statuses = crate::platform::macos::inspect_service_proxies().unwrap_or_default();
        let env_http_upper = crate::platform::macos::read_launchd_env("HTTP_PROXY");
        let env_https_upper = crate::platform::macos::read_launchd_env("HTTPS_PROXY");
        let env_http_lower = crate::platform::macos::read_launchd_env("http_proxy");
        let env_https_lower = crate::platform::macos::read_launchd_env("https_proxy");
        let env_all_upper = crate::platform::macos::read_launchd_env("ALL_PROXY");
        let env_all_lower = crate::platform::macos::read_launchd_env("all_proxy");
        let env_vars = [
            ("HTTP_PROXY", env_http_upper.as_deref()),
            ("HTTPS_PROXY", env_https_upper.as_deref()),
            ("http_proxy", env_http_lower.as_deref()),
            ("https_proxy", env_https_lower.as_deref()),
            ("ALL_PROXY", env_all_upper.as_deref()),
            ("all_proxy", env_all_lower.as_deref()),
        ];
        evaluate_macos_proxy_drift(active_addr, active_port, &statuses, &env_vars)
    }

    #[cfg(target_os = "linux")]
    {
        let snap = collect_linux_proxy_snapshot();
        evaluate_linux_proxy_drift(active_addr, active_port, &snap)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (active_addr, active_port);
        None
    }
}

fn check_stale_proxy_when_no_daemon() -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        use crate::platform::windows::query_reg_sz;

        let inet_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        let enabled_raw = query_reg_sz(inet_key, "ProxyEnable").unwrap_or_default();
        let enabled = enabled_raw == "0x1" || enabled_raw == "1";
        let server = query_reg_sz(inet_key, "ProxyServer").unwrap_or_default();
        let auto_config_url = query_reg_sz(inet_key, "AutoConfigURL");
        let env_http = query_reg_sz(r"HKCU\Environment", "HTTP_PROXY");
        let env_https = query_reg_sz(r"HKCU\Environment", "HTTPS_PROXY");
        let env_all = query_reg_sz(r"HKCU\Environment", "ALL_PROXY");
        let winhttp_proxy = query_windows_winhttp_proxy_server();

        evaluate_windows_stale_proxy_when_stopped_full(
            enabled,
            &server,
            auto_config_url.as_deref(),
            env_http.as_deref(),
            env_https.as_deref(),
            env_all.as_deref(),
            winhttp_proxy.as_deref(),
        )
    }

    #[cfg(target_os = "macos")]
    {
        let statuses = crate::platform::macos::inspect_service_proxies().unwrap_or_default();
        let snapshots: Vec<MacosProxyServiceSnapshot> =
            statuses.iter().map(macos_status_to_snapshot).collect();
        let env_http_upper = crate::platform::macos::read_launchd_env("HTTP_PROXY");
        let env_https_upper = crate::platform::macos::read_launchd_env("HTTPS_PROXY");
        let env_http_lower = crate::platform::macos::read_launchd_env("http_proxy");
        let env_https_lower = crate::platform::macos::read_launchd_env("https_proxy");
        let env_all_upper = crate::platform::macos::read_launchd_env("ALL_PROXY");
        let env_all_lower = crate::platform::macos::read_launchd_env("all_proxy");
        let env_vars = [
            ("HTTP_PROXY", env_http_upper.as_deref()),
            ("HTTPS_PROXY", env_https_upper.as_deref()),
            ("http_proxy", env_http_lower.as_deref()),
            ("https_proxy", env_https_lower.as_deref()),
            ("ALL_PROXY", env_all_upper.as_deref()),
            ("all_proxy", env_all_lower.as_deref()),
        ];
        evaluate_macos_stale_proxy_when_stopped(&snapshots, &env_vars)
    }

    #[cfg(target_os = "linux")]
    {
        let snap = collect_linux_proxy_snapshot();
        evaluate_linux_stale_proxy_when_stopped(&snap)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

#[cfg(target_os = "windows")]
fn detect_orphan_windows_tun_adapter() -> bool {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
    };

    let mut raw_if_table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    // SAFETY: `GetIfTable2` populates `raw_if_table` on `NO_ERROR` and must be freed via `FreeMibTable`.
    let rc = unsafe { GetIfTable2(&mut raw_if_table) };
    if rc != NO_ERROR || raw_if_table.is_null() {
        return false;
    }

    let mut found = false;
    // SAFETY: `raw_if_table` is valid until `FreeMibTable`.
    unsafe {
        let count = (*raw_if_table).NumEntries as usize;
        if count > 0 {
            let first = std::ptr::addr_of!((*raw_if_table).Table).cast::<MIB_IF_ROW2>();
            let rows = std::slice::from_raw_parts(first, count);
            for row in rows {
                let nul = row
                    .Alias
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(row.Alias.len());
                let alias = String::from_utf16_lossy(&row.Alias[..nul]);
                if alias
                    .trim()
                    .eq_ignore_ascii_case(crate::platform::windows_tun::VDPI_TUN_NAME)
                {
                    found = true;
                    break;
                }
            }
        }
        FreeMibTable(raw_if_table.cast());
    }
    found
}

fn detect_orphan_tun_adapter() -> Option<&'static str> {
    #[cfg(target_os = "windows")]
    {
        detect_orphan_windows_tun_adapter().then_some(crate::platform::windows_tun::VDPI_TUN_NAME)
    }
    #[cfg(target_os = "linux")]
    {
        Path::new("/sys/class/net/vdpi0").exists().then_some("vdpi0")
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

fn detect_stale_browsers_for_env(since_unix_secs: u64) -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        crate::platform::windows::detect_stale_browsers(since_unix_secs)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = since_unix_secs;
        Vec::new()
    }
}

#[cfg(any(target_os = "windows", test))]
fn format_doctor_wintun_error(err: &str) -> String {
    let lower = err.to_ascii_lowercase();
    if lower.contains("sha-256")
        || lower.contains("sha256")
        || lower.contains("verification failed")
    {
        format!(
            "wintun.dll (v{}) is corrupted or mismatched (SHA-256 verification failed). Extract all files from the zip (keep wintun.dll beside vdpi.exe).",
            crate::platform::windows_tun::WINTUN_VERSION
        )
    } else if lower.contains("reparse point") || lower.contains("junction") {
        "wintun.dll path rejected (NTFS reparse point). Extract all files from the zip (keep wintun.dll beside vdpi.exe)."
            .to_string()
    } else {
        format!(
            "wintun.dll (v{}) not found. Extract all files from the zip (keep wintun.dll beside vdpi.exe).",
            crate::platform::windows_tun::WINTUN_VERSION
        )
    }
}

fn should_skip_live_proxy_drift_for_vpn(
    policy: VpnCoexistence,
    live_vpn_conflict: Option<&str>,
    active_vpn_scope: &VpnScope,
) -> bool {
    policy == VpnCoexistence::AutoYield
        && (live_vpn_conflict.is_some() || matches!(active_vpn_scope, VpnScope::FullTunnel { .. }))
}

/// Runs live end-to-end connectivity checks through `vdpi` (adapting automatically to
/// live TUN vs Proxy daemons, or spawning an ephemeral in-process engine when no daemon
/// is running) against Discord and Roblox endpoints.
pub async fn run_doctor(cfg: RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let direct_check = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(800))
        .build()?;

    let (active_addr, active_port, active_socks_port, live_health) =
        discover_live_daemon(&direct_check, &cfg).await;

    let live_status = live_health
        .as_deref()
        .and_then(|text| parse_health_json(text, active_addr, active_port, active_socks_port));

    // Always run VPN conflict check first (unless vpn_coexistence=off).
    println!("=== VPN Conflict Check ===");
    let active_vpn_scope = if cfg.vpn_coexistence == VpnCoexistence::Off {
        println!("  [PASS] VPN Conflict             -> disabled (vpn_coexistence=off)");
        VpnScope::None
    } else {
        let self_tun = live_status
            .as_ref()
            .and_then(|live| live.tun_interface.as_deref());
        let scope = detect_active_vpn(self_tun);
        match &scope {
            VpnScope::None => {
                println!("  [PASS] VPN Conflict             -> none detected");
            }
            VpnScope::SplitOverlay { providers } => {
                println!(
                    "  [PASS] VPN Conflict             -> split-tunnel overlay only ({})",
                    providers.join(", ")
                );
            }
            VpnScope::FullTunnel {
                provider,
                iface,
                kill_switch,
            } => {
                let ks = if *kill_switch { " [kill-switch]" } else { "" };
                println!(
                    "  [WARN] VPN Conflict             -> full-tunnel VPN active: {provider} ({iface}){ks}"
                );
            }
        }
        scope
    };
    println!();

    #[cfg(target_os = "windows")]
    {
        println!("=== Windows TUN Preflight (Wintun) ===");
        match crate::platform::windows_tun::find_verified_wintun_dll() {
            Ok(path) => {
                println!(
                    "  [PASS] {:24} -> verified ({})",
                    "Wintun DLL",
                    path.display()
                );
            }
            Err(err) => {
                println!(
                    "  [WARN] {:24} -> {}",
                    "Wintun DLL",
                    format_doctor_wintun_error(&err.to_string())
                );
            }
        }
        println!();
    }

    let roblox_settings_url = if cfg!(target_os = "windows") {
        "https://clientsettingscdn.roblox.com/v2/client-version/WindowsPlayer"
    } else {
        "https://clientsettingscdn.roblox.com/v2/client-version/MacPlayer"
    };

    // Branch A: Live TUN daemon checks (direct non-proxied HTTPS + UDP DNS + QUIC drop counter).
    if let Some(live) = live_status
        .as_ref()
        .filter(|live| live.engine == EngineMode::Tun)
    {
        println!(
            "Testing against running vdpi TUN daemon ({})...\n",
            format_tun_engine_summary(live)
        );

        let direct_client = Client::builder()
            .no_proxy()
            .timeout(cfg.connect_timeout)
            .build()?;

        let tun_targets = [
            ("Roblox ClientSettings", roblox_settings_url),
            ("Discord Web", "https://discord.com"),
            ("Discord Gateway", "https://gateway.discord.gg"),
            ("Roblox Web", "https://www.roblox.com"),
        ];

        let mut passed = 0usize;
        println!("=== Direct HTTPS via TUN Checks ===");
        for (label, url) in tun_targets {
            let t0 = Instant::now();
            match direct_client.get(url).send().await {
                Ok(resp) => {
                    let ms = t0.elapsed().as_millis();
                    println!(
                        "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                        label,
                        resp.status().as_u16(),
                        ms
                    );
                    passed += 1;
                }
                Err(e) => {
                    println!("  [FAIL] {:24} -> {}", label, e);
                }
            }
        }

        println!("\n=== TUN UDP DNS & QUIC Checks ===");
        let dns_ok = match run_tun_udp_dns_check(cfg.connect_timeout).await {
            Ok((ips, ms)) => {
                println!(
                    "  [PASS] {:24} -> resolved {} IP(s) ({:4} ms)",
                    "UDP DNS (discord.com)",
                    ips.len(),
                    ms
                );
                true
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", "UDP DNS (discord.com)", e);
                false
            }
        };

        let block_quic = live.block_quic.unwrap_or(true);
        if !block_quic {
            println!(
                "  [PASS] {:24} -> QUIC blocking disabled (--allow-quic)",
                "QUIC Drop Counter"
            );
        } else {
            let quic_before = live.quic_blocked.unwrap_or(0);
            if let Err(e) = send_quic_initial_probe().await {
                println!(
                    "  [WARN] {:24} -> failed to send QUIC probe: {}",
                    "QUIC Drop Counter", e
                );
            } else {
                tokio::time::sleep(Duration::from_millis(150)).await;
                let quic_after = query_live_health_snapshot(
                    &direct_check,
                    active_addr,
                    active_port,
                    active_socks_port,
                )
                .await
                .and_then(|snap| snap.quic_blocked)
                .unwrap_or(quic_before);
                if quic_after > quic_before {
                    println!(
                        "  [PASS] {:24} -> incremented ({quic_before} -> {quic_after})",
                        "QUIC Drop Counter"
                    );
                } else {
                    println!(
                        "  [WARN] {:24} -> counter unchanged ({quic_before} -> {quic_after})",
                        "QUIC Drop Counter"
                    );
                }
            }
        }

        if passed != tun_targets.len() || !dns_ok {
            bail!(
                "doctor detected TUN failures ({}/{} HTTPS passed, udp_dns_ok={})",
                passed,
                tun_targets.len(),
                dns_ok
            );
        }

        println!("\nAll TUN direct HTTPS, UDP DNS, and QUIC checks passed.");
        return Ok(());
    }

    // Branch B: Live Proxy daemon (or ephemeral in-process proxy engine).
    let testing_live_proxy = live_health.is_some();
    if !testing_live_proxy {
        // Run offline proxy & orphaned adapter hygiene checks BEFORE spawning the
        // ephemeral engine and running slow network probes so an orphaned `vdpi0` or
        // stale system proxy is flagged immediately instead of after probe timeouts.
        println!("=== System Proxy & Adapter Hygiene Checks ===");
        if let Some(drift) = check_stale_proxy_when_no_daemon() {
            println!("  [WARN] {:24} -> {drift}", "System Proxy Drift");
        } else {
            println!(
                "  [PASS] {:24} -> clean (no stale vdpi proxy active)",
                "System Proxy Drift"
            );
        }
        if let Some(orphan) = detect_orphan_tun_adapter() {
            println!(
                "  [WARN] {:24} -> orphaned interface '{orphan}' still present while no vdpi daemon is running (run 'vdpi pause' to clean up)",
                "Orphaned TUN Adapter"
            );
        } else {
            println!("  [PASS] {:24} -> none detected", "Orphaned TUN Adapter");
        }
        println!();
    }
    let (http_proxy_addr, socks_proxy_addr, _guard_tx) = if testing_live_proxy {
        let connect_ip = probe_connect_ip(active_addr).unwrap_or(active_addr);
        let hp = SocketAddr::new(connect_ip, active_port);
        let sp = SocketAddr::new(connect_ip, active_socks_port.unwrap_or(active_port));
        println!("Testing against running vdpi daemon at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, None)
    } else {
        let mut ephemeral_cfg = cfg.clone();
        ephemeral_cfg.port = 0;
        ephemeral_cfg.socks_port = Some(0);
        ephemeral_cfg.system_proxy = false;
        let ctx = EngineContext::new(ephemeral_cfg)?;
        let bound = crate::server::bind_listeners(&ctx)?;
        let hp_ip = probe_connect_ip(bound.primary_addr.ip()).unwrap_or(bound.primary_addr.ip());
        let hp = SocketAddr::new(hp_ip, bound.primary_addr.port());
        let sp = bound.socks_addr.map_or(hp, |a| {
            SocketAddr::new(probe_connect_ip(a.ip()).unwrap_or(a.ip()), a.port())
        });
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = crate::server::serve_until_shutdown(bound, ctx, rx).await;
        });
        println!("Testing with ephemeral in-process vdpi engine at {hp} (SOCKS5: {sp})...\n");
        (hp, sp, Some(tx))
    };

    let http_client = Client::builder()
        .proxy(Proxy::all(format!("http://{http_proxy_addr}"))?)
        .timeout(cfg.connect_timeout)
        .build()?;

    let discord_updater_url = if cfg!(target_os = "windows") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=win&arch=x64"
    } else if cfg!(target_os = "linux") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=linux&arch=x64"
    } else if cfg!(target_arch = "aarch64") {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=arm64"
    } else {
        "https://updates.discord.com/distributions/app/manifests/latest?channel=stable&platform=osx&arch=x64"
    };

    let targets = [
        ("Discord Web", "https://discord.com"),
        ("Discord Updater", discord_updater_url),
        ("Discord Gateway", "https://gateway.discord.gg"),
        ("Discord CDN", "https://cdn.discordapp.com"),
        ("Discord Voice Latency", "https://latency.discord.media"),
        ("Roblox Web", "https://www.roblox.com"),
        ("Roblox ClientSettings", roblox_settings_url),
        ("Roblox APIs", "https://apis.roblox.com"),
        ("Roblox Auth", "https://auth.roblox.com"),
        ("Roblox GameJoin", "https://gamejoin.roblox.com"),
        ("Roblox Telemetry", "https://ecsv2.roblox.com"),
    ];

    let mut passed = 0usize;
    println!("=== HTTP/HTTPS CONNECT Tunnel Checks ===");
    for (label, url) in targets {
        let t0 = Instant::now();
        match http_client.get(url).send().await {
            Ok(resp) => {
                let ms = t0.elapsed().as_millis();
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    ms
                );
                passed += 1;
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
            }
        }
    }

    println!("\n=== SOCKS5h (Remote DoH + TLS DPI Desync) Checks ===");
    let socks_client = Client::builder()
        .proxy(Proxy::all(format!("socks5h://{socks_proxy_addr}"))?)
        .timeout(cfg.connect_timeout)
        .build()?;

    let mut socks_ok = true;
    for (label, url) in [
        ("SOCKS5 Discord", "https://discord.com"),
        ("SOCKS5 Discord Gateway", "https://gateway.discord.gg"),
        ("SOCKS5 Roblox Web", "https://www.roblox.com"),
        ("SOCKS5 Roblox APIs", "https://apis.roblox.com"),
    ] {
        let t0 = Instant::now();
        match socks_client.get(url).send().await {
            Ok(resp) => {
                println!(
                    "  [PASS] {:24} -> HTTP {:3} ({:4} ms)",
                    label,
                    resp.status().as_u16(),
                    t0.elapsed().as_millis()
                );
            }
            Err(e) => {
                println!("  [FAIL] {:24} -> {}", label, e);
                socks_ok = false;
            }
        }
    }

    if testing_live_proxy {
        println!("\n=== Proxy Session & Browser Checks ===");
        let env_activated_at = read_runtime_states()
            .into_iter()
            .find(|s| s.port == active_port)
            .and_then(|s| s.env_activated_at);
        if !cfg.system_proxy || !cfg.env_proxy {
            println!(
                "  [PASS] {:24} -> skipped (env proxy disabled)",
                "Stale Browsers"
            );
        } else if let Some(activated_at) = env_activated_at {
            let stale_browsers = detect_stale_browsers_for_env(activated_at);
            if stale_browsers.is_empty() {
                println!("  [PASS] {:24} -> none detected", "Stale Browsers");
            } else {
                println!(
                    "  [WARN] {:24} -> {} started before proxy env activation (restart browser or run 'vdpi engine tun')",
                    "Stale Browsers",
                    stale_browsers.join(", ")
                );
            }
        } else {
            println!(
                "  [PASS] {:24} -> skipped (proxy env not activated)",
                "Stale Browsers"
            );
        }

        let live_vpn_conflict = live_status
            .as_ref()
            .and_then(|live| live.vpn_conflict.as_deref());
        if !cfg.system_proxy {
            println!(
                "  [PASS] {:24} -> skipped (--no-system-proxy)",
                "System Proxy Drift"
            );
        } else if should_skip_live_proxy_drift_for_vpn(
            cfg.vpn_coexistence,
            live_vpn_conflict,
            &active_vpn_scope,
        ) {
            let vpn_label = live_vpn_conflict
                .map(str::to_owned)
                .or_else(|| format_vpn_scope_conflict(&active_vpn_scope))
                .unwrap_or_else(|| "full-tunnel VPN".to_string());
            println!(
                "  [PASS] {:24} -> skipped (Proxy intentionally yielded to {vpn_label} under auto-yield)",
                "System Proxy Drift"
            );
        } else if let Some(drift) = check_proxy_drift_for_live_daemon(active_addr, active_port) {
            println!("  [WARN] {:24} -> {drift}", "System Proxy Drift");
        } else {
            println!(
                "  [PASS] {:24} -> aligned with {active_addr}:{active_port}",
                "System Proxy Drift"
            );
        }

        if let Some(orphan) = detect_orphan_tun_adapter() {
            println!(
                "  [WARN] {:24} -> orphaned interface '{orphan}' still present while Proxy daemon is running (run 'vdpi pause' to clean up)",
                "Orphaned TUN Adapter"
            );
        } else {
            println!("  [PASS] {:24} -> none detected", "Orphaned TUN Adapter");
        }
    }

    if passed != targets.len() || !socks_ok {
        bail!(
            "doctor detected failures ({}/{} HTTP passed, socks5_ok={})",
            passed,
            targets.len(),
            socks_ok
        );
    }

    println!("\nAll Discord & Roblox HTTP CONNECT and SOCKS5h checks passed.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn launchctl_service_running(service_target: &str) -> bool {
    launchctl_command_for_target(service_target)
        .args(["print", service_target])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.trim() == "state = running")
        })
}

#[cfg(target_os = "macos")]
fn launchctl_service_loaded(service_target: &str) -> bool {
    launchctl_command_for_target(service_target)
        .args(["print", service_target])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(target_os = "linux")]
fn systemd_unit_active(user: bool) -> bool {
    let mut cmd = if user {
        linux_user_systemctl_command()
    } else {
        Command::new(resolve_systemctl_bin())
    };
    cmd.args(["is-active", SYSTEMD_UNIT_NAME])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .is_ok_and(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout);
            output.status.success() || stdout.trim() == "active"
        })
}

#[cfg(target_os = "macos")]
fn current_uid() -> u32 {
    if let Some(sudo_user) = resolve_sudo_invoking_user() {
        return sudo_user.uid;
    }
    unsafe { libc::getuid() }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn is_unix_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

const SUDO_CARD_INDENT: &str = "  ";
const SUDO_CARD_INNER_WIDTH: usize = 60;
const SUDO_CARD_ACTION_WRAP_WIDTH: usize = 46;
const SUDO_CARD_TITLE: &str = "vdpi · Administrator Approval";

fn capitalize_first_char(text: &str) -> String {
    let trimmed = text.trim();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some(first) => {
            let mut out = String::with_capacity(trimmed.len());
            for ch in first.to_uppercase() {
                out.push(ch);
            }
            out.push_str(chars.as_str());
            out
        }
        None => String::new(),
    }
}

fn wrap_sudo_action_lines(action_description: &str, max_width: usize) -> Vec<String> {
    let normalized = capitalize_first_char(action_description);
    let source = if normalized.is_empty() {
        "Complete a privileged operation".to_string()
    } else {
        normalized
    };

    let limit = max_width.max(1);
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in source.split_whitespace() {
        let word_len = word.chars().count();
        if word_len > limit {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
                current_len = 0;
            }
            let mut chunk = String::new();
            let mut chunk_len = 0usize;
            for ch in word.chars() {
                if chunk_len == limit {
                    lines.push(std::mem::take(&mut chunk));
                    chunk_len = 0;
                }
                chunk.push(ch);
                chunk_len += 1;
            }
            if !chunk.is_empty() {
                current = chunk;
                current_len = chunk_len;
            }
            continue;
        }

        if current.is_empty() {
            current.push_str(word);
            current_len = word_len;
        } else if current_len + 1 + word_len <= limit {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + word_len;
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
            current_len = word_len;
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push("Complete a privileged operation".to_string());
    }
    lines
}

/// Formats a compact 62-column rounded-box Unix `sudo` approval card (64 columns
/// including its 2-space left margin so it never wraps on 80x24 terminals).
///
/// When `no_color` is `true`, no ANSI escape sequences are emitted.
pub fn format_unix_sudo_prompt_card(
    action_description: &str,
    is_macos: bool,
    no_color: bool,
) -> String {
    const BORDER: &str = "\x1b[38;2;74;85;104m";
    const TITLE: &str = "\x1b[1;38;2;241;245;249m";
    const LABEL: &str = "\x1b[38;2;148;163;184m";
    const VALUE: &str = "\x1b[38;2;226;232;240m";
    const HINT: &str = "\x1b[38;2;148;163;184m";
    const RESET: &str = "\x1b[0m";

    let (c_border, c_title, c_label, c_value, c_hint, c_reset) = if no_color {
        ("", "", "", "", "", "")
    } else {
        (BORDER, TITLE, LABEL, VALUE, HINT, RESET)
    };

    let hbar = "─".repeat(SUDO_CARD_INNER_WIDTH);
    let title_len = SUDO_CARD_TITLE.chars().count();
    let title_pad = " ".repeat(SUDO_CARD_INNER_WIDTH.saturating_sub(2 + title_len));

    let prompt_hint = if is_macos {
        "Enter your password (or Touch ID) below"
    } else {
        "Enter your sudo password below"
    };

    let redacted_action = redact_urls_in_text(action_description);
    let action_lines = wrap_sudo_action_lines(&redacted_action, SUDO_CARD_ACTION_WRAP_WIDTH);

    let mut out = String::new();
    out.push_str(&format!("{SUDO_CARD_INDENT}{c_border}╭{hbar}╮{c_reset}\n"));
    out.push_str(&format!(
        "{SUDO_CARD_INDENT}{c_border}│{c_reset}  {c_title}{SUDO_CARD_TITLE}{c_reset}{title_pad}{c_border}│{c_reset}\n"
    ));
    out.push_str(&format!("{SUDO_CARD_INDENT}{c_border}├{hbar}┤{c_reset}\n"));

    for (idx, line) in action_lines.iter().enumerate() {
        let label = if idx == 0 { "Action   " } else { "         " };
        let used = 2 + label.chars().count() + line.chars().count();
        let pad = " ".repeat(SUDO_CARD_INNER_WIDTH.saturating_sub(used));
        out.push_str(&format!(
            "{SUDO_CARD_INDENT}{c_border}│{c_reset}  {c_label}{label}{c_reset}{c_value}{line}{c_reset}{pad}{c_border}│{c_reset}\n"
        ));
    }

    let prompt_label = "Prompt   ";
    let prompt_used = 2 + prompt_label.chars().count() + prompt_hint.chars().count();
    let prompt_pad = " ".repeat(SUDO_CARD_INNER_WIDTH.saturating_sub(prompt_used));
    out.push_str(&format!(
        "{SUDO_CARD_INDENT}{c_border}│{c_reset}  {c_label}{prompt_label}{c_reset}{c_hint}{prompt_hint}{c_reset}{prompt_pad}{c_border}│{c_reset}\n"
    ));
    out.push_str(&format!("{SUDO_CARD_INDENT}{c_border}╰{hbar}╯{c_reset}\n"));
    out
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn relaunch_unix_sudo_and_wait(args: &[String], action_description: &str) -> Result<()> {
    use std::io::IsTerminal;

    let cmd_hint = redact_urls_in_text(&args.join(" "));
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("Root required - run: sudo vdpi {cmd_hint}");
    }

    let exe = std::env::current_exe().context("failed to determine current executable")?;
    let sudo_bin = ["/usr/bin/sudo", "/bin/sudo"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "trusted sudo binary not found at /usr/bin/sudo or /bin/sudo - run as root: sudo vdpi {cmd_hint}"
            )
        })?;

    let no_color = std::env::var_os("NO_COLOR").is_some();
    let card =
        format_unix_sudo_prompt_card(action_description, cfg!(target_os = "macos"), no_color);
    print!("\x1b[2J\x1b[H\n{card}\n");
    let _ = std::io::stdout().flush();

    let status = Command::new(sudo_bin)
        .args(["-p", "  Password: ", "--"])
        .arg(exe)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("Root required - run: sudo vdpi {cmd_hint}"))?;

    if !status.success() {
        let code = status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        bail!("sudo canceled or failed (exit {code}) - try: sudo vdpi {cmd_hint}");
    }

    print!("\x1b[2J\x1b[H");
    let _ = std::io::stdout().flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;

    #[test]
    fn generates_valid_service_manifests_for_all_platforms() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--chunk-size", "10"]).unwrap();
        let cfg = cli.into_runtime_config();

        let plist = generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &cfg);
        assert!(plist.contains("<string>com.vdpi</string>"));
        assert!(plist.contains("<string>--proxy</string>"));
        assert!(!plist.contains("<string>--tun</string>"));
        assert!(plist.contains("<string>--chunk-size</string>"));
        assert!(plist.contains("<string>10</string>"));
        assert!(plist.contains("<string>--socks-port</string>"));
        assert!(plist.contains("<string>1080</string>"));

        let unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &cfg);
        assert!(unit.contains("ExecStart=\"/home/test/.vdpi/bin/vdpi\" \"--proxy\""));
        assert!(!unit.contains("\"--tun\""));
        assert!(!unit.contains("network-online.target"));
        assert!(unit.contains("LimitNOFILE=65536"));

        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.starts_with(r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --proxy "#));
        assert!(win_bin.contains("--bind 127.0.0.1"));
        assert!(win_bin.contains("--port 8080"));
        assert!(win_bin.contains("--chunk-size 10"));
        assert!(win_bin.contains("--socks-port 1080"));
        assert!(win_bin.contains("--quiet"));

        // Passing a TUN config to proxy-only generators must still force --proxy.
        let mut tun_cfg = cfg;
        tun_cfg.engine = EngineMode::Tun;
        let forced_plist =
            generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &tun_cfg);
        assert!(forced_plist.contains("<string>--proxy</string>"));
        assert!(!forced_plist.contains("<string>--tun</string>"));

        let forced_unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &tun_cfg);
        assert!(forced_unit.contains("\"--proxy\""));
        assert!(!forced_unit.contains("\"--tun\""));
    }

    #[test]
    fn preserves_custom_flags_in_windows_service_bin_path() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--mode",
            "tls-record",
            "--dns",
            "8.8.8.8",
            "--bypass",
            "*.example.com",
            "--no-env-proxy",
        ])
        .unwrap();
        let cfg = cli.into_runtime_config();
        let win_bin =
            build_windows_service_bin_path(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"), &cfg);
        assert!(win_bin.contains("--service"));
        assert!(win_bin.contains("--mode tls-record"));
        assert!(win_bin.contains("--dns 8.8.8.8"));
        assert!(win_bin.contains("--bypass *.example.com"));
        assert!(win_bin.contains("--no-env-proxy"));
    }

    #[test]
    fn parses_version_from_cli_output() {
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.3\n").as_deref(),
            Some("0.3.3")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi 0.3.4\r\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(
            parse_version_from_cli_output("vdpi v1.2.3\n").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            parse_version_from_cli_output("0.3.4\n").as_deref(),
            Some("0.3.4")
        );
        assert_eq!(parse_version_from_cli_output(""), None);
        assert_eq!(parse_version_from_cli_output("   \r\n"), None);
        assert_eq!(parse_version_from_cli_output("garbage output\n"), None);
        assert_eq!(parse_version_from_cli_output("vdpi not-a-version\n"), None);
    }

    #[test]
    fn quotes_windows_args_with_backslashes_and_quotes() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg(""), r#""""#);
        assert_eq!(quote_windows_arg("a b"), r#""a b""#);
        assert_eq!(quote_windows_arg(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote_windows_arg(r#"a\"b"#), r#""a\\\"b""#);
        assert_eq!(
            quote_windows_arg(r"C:\Program Files\vdpi\"),
            r#""C:\Program Files\vdpi\\""#
        );
        assert_eq!(quote_windows_arg(r#"a\\""#), r#""a\\\\\"""#);
    }

    #[test]
    fn escapes_systemd_unit_execstart_arguments() {
        let mut cli = CliArgs::parse_from_iter(["vdpi"]).unwrap();
        cli.bypass_domains = vec![
            "evil\nExecStartPost=/bin/sh".to_string(),
            r#"100%"a\b$HOME"#.to_string(),
        ];
        let cfg = cli.into_runtime_config();
        let unit = generate_systemd_unit(Path::new("/home/u%1/$bin/my \"dir\"\\vdpi"), &cfg);

        assert!(!unit.contains("\nExecStartPost="));
        assert!(unit.contains(r#"ExecStart="/home/u%%1/$$bin/my \"dir\"\\vdpi""#));
        assert!(unit.contains(r#""100%%\"a\\b$$HOME""#));
    }

    #[test]
    fn parses_enriched_v0_4_2_health_json() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.4.2",
            "mode": "combo",
            "doh": true,
            "block_quic": true,
            "active_connections": 7,
            "total_connections": 420,
            "learned_hosts": 19,
            "isp_stage": "stage-1"
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, 8080, Some(1080))
            .expect("enriched health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: 8080,
                socks_port: Some(1080),
                engine: EngineMode::Proxy,
                tun_interface: None,
                physical_nic: None,
                vpn_conflict: None,
                version: Some("0.4.2".to_string()),
                mode: Some("combo".to_string()),
                doh: Some(true),
                dns_addr: None,
                block_quic: Some(true),
                active_connections: Some(7),
                total_connections: Some(420),
                learned_hosts: Some(19),
                isp_stage: Some("stage-1".to_string()),
                udp_flows_active: None,
                quic_blocked: None,
                dns_queries: None,
                rss_kb: None,
                bytes_rx: None,
                bytes_tx: None,
                tls_handshakes: None,
                auto_heal_escalations: None,
            }
        );
    }

    #[test]
    fn parses_legacy_minimal_v0_4_0_health_json() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let legacy = "{\"status\":\"ok\",\"service\":\"vdpi\",\"version\":\"0.4.0\"}\n";
        let parsed = parse_health_json(legacy, addr, 8080, None)
            .expect("legacy minimal health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: 8080,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                physical_nic: None,
                vpn_conflict: None,
                version: Some("0.4.0".to_string()),
                mode: None,
                doh: None,
                dns_addr: None,
                block_quic: None,
                active_connections: None,
                total_connections: None,
                learned_hosts: None,
                isp_stage: None,
                udp_flows_active: None,
                quic_blocked: None,
                dns_queries: None,
                rss_kb: None,
                bytes_rx: None,
                bytes_tx: None,
                tls_handshakes: None,
                auto_heal_escalations: None,
            }
        );

        let service_only = r#"{"service":"vdpi"}"#;
        let parsed_service_only = parse_health_json(service_only, addr, 8080, Some(1080))
            .expect("service=vdpi payload without status should parse");
        assert_eq!(parsed_service_only.engine, EngineMode::Proxy);
        assert_eq!(parsed_service_only.version, None);
        assert_eq!(parsed_service_only.socks_port, Some(1080));
    }

    #[test]
    fn parses_v0_5_0_tun_health_json() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.5.0",
            "mode": "combo",
            "doh": true,
            "dns_addr": "94.140.14.14",
            "block_quic": true,
            "active_connections": 12,
            "total_connections": 900,
            "learned_hosts": 24,
            "isp_stage": "stage-2",
            "engine": "tun",
            "tun_interface": "vdpi0",
            "physical_nic": "Ethernet",
            "vpn_conflict": "Mullvad (wg0)",
            "udp_flows_active": 18,
            "quic_blocked": 55,
            "dns_queries": 310,
            "rss_kb": 16384
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, DEFAULT_TUN_HEALTH_PORT, None)
            .expect("v0.5.0 TUN health payload should parse");

        assert_eq!(
            parsed,
            LiveEngineStatus {
                addr,
                port: DEFAULT_TUN_HEALTH_PORT,
                socks_port: None,
                engine: EngineMode::Tun,
                tun_interface: Some("vdpi0".to_string()),
                physical_nic: Some("Ethernet".to_string()),
                vpn_conflict: Some("Mullvad (wg0)".to_string()),
                version: Some("0.5.0".to_string()),
                mode: Some("combo".to_string()),
                doh: Some(true),
                dns_addr: Some("94.140.14.14".to_string()),
                block_quic: Some(true),
                active_connections: Some(12),
                total_connections: Some(900),
                learned_hosts: Some(24),
                isp_stage: Some("stage-2".to_string()),
                udp_flows_active: Some(18),
                quic_blocked: Some(55),
                dns_queries: Some(310),
                rss_kb: Some(16384),
                bytes_rx: None,
                bytes_tx: None,
                tls_handshakes: None,
                auto_heal_escalations: None,
            }
        );
        assert_eq!(
            format_tun_engine_summary(&parsed),
            "vdpi0 via Ethernet · 16 MB RSS"
        );
    }

    #[test]
    fn parses_v0_5_0_proxy_health_json_and_ignores_blank_optional_strings() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.5.0",
            "engine": "proxy",
            "tun_interface": null,
            "physical_nic": "",
            "vpn_conflict": "   ",
            "udp_flows_active": 0,
            "quic_blocked": 3,
            "dns_queries": 44,
            "rss_kb": 9216
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, 8080, Some(1080))
            .expect("v0.5.0 Proxy health payload should parse");
        assert_eq!(parsed.engine, EngineMode::Proxy);
        assert_eq!(parsed.tun_interface, None);
        assert_eq!(parsed.physical_nic, None);
        assert_eq!(parsed.vpn_conflict, None);
        assert_eq!(parsed.udp_flows_active, Some(0));
        assert_eq!(parsed.quic_blocked, Some(3));
        assert_eq!(parsed.dns_queries, Some(44));
        assert_eq!(parsed.rss_kb, Some(9216));
        assert_eq!(parsed.bytes_rx, None);
        assert_eq!(parsed.bytes_tx, None);
        assert_eq!(parsed.tls_handshakes, None);
        assert_eq!(parsed.auto_heal_escalations, None);
    }

    #[test]
    fn parses_live_traffic_and_auto_heal_telemetry_from_health_json() {
        let body = r#"{
            "status": "ok",
            "service": "vdpi",
            "version": "0.5.0",
            "engine": "proxy",
            "bytes_rx": 1048576,
            "bytes_tx": 262144,
            "tls_handshakes": 28,
            "auto_heal_escalations": 2
        }"#;
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let parsed = parse_health_json(body, addr, 8080, Some(1080))
            .expect("health payload with traffic and auto-heal telemetry should parse");
        assert_eq!(parsed.bytes_rx, Some(1_048_576));
        assert_eq!(parsed.bytes_tx, Some(262_144));
        assert_eq!(parsed.tls_handshakes, Some(28));
        assert_eq!(parsed.auto_heal_escalations, Some(2));

        let zeros = r#"{
            "status": "ok",
            "service": "vdpi",
            "bytes_rx": 0,
            "bytes_tx": 0,
            "tls_handshakes": 0,
            "auto_heal_escalations": 0
        }"#;
        let parsed_zeros = parse_health_json(zeros, addr, 8080, None)
            .expect("health payload with zeroed telemetry should parse");
        assert_eq!(parsed_zeros.bytes_rx, Some(0));
        assert_eq!(parsed_zeros.bytes_tx, Some(0));
        assert_eq!(parsed_zeros.tls_handshakes, Some(0));
        assert_eq!(parsed_zeros.auto_heal_escalations, Some(0));
    }

    #[test]
    fn runtime_state_deserializes_legacy_v0_4_json_with_defaults() {
        let legacy = r#"{"pid":1234,"addr":"127.0.0.1","port":8080,"socks_port":1080}"#;
        let parsed: RuntimeState =
            serde_json::from_str(legacy).expect("legacy RuntimeState JSON should deserialize");
        assert_eq!(parsed.pid, 1234);
        assert_eq!(parsed.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(parsed.port, 8080);
        assert_eq!(parsed.socks_port, Some(1080));
        assert_eq!(parsed.engine, EngineMode::Proxy);
        assert_eq!(parsed.tun_interface, None);
        assert_eq!(parsed.env_activated_at, None);
    }

    #[test]
    fn generates_valid_tun_system_service_manifests() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--tun", "--tun-ipv6"]).unwrap();
        let cfg = cli.into_runtime_config();

        let daemon_plist = generate_launch_daemon_plist(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
        assert!(daemon_plist.contains("<string>com.vdpi.daemon</string>"));
        assert!(daemon_plist.contains("<string>/usr/local/bin/vdpi</string>"));
        assert!(daemon_plist.contains("<string>--tun</string>"));
        assert!(daemon_plist.contains("<string>--tun-ipv6</string>"));
        assert!(daemon_plist.contains("<string>--config</string>"));
        assert!(daemon_plist.contains(&format!("<string>{MACOS_SYSTEM_CONFIG_PATH}</string>")));
        assert!(daemon_plist.contains("<key>AbandonProcessGroup</key>\n    <true/>"));

        let sys_unit = generate_systemd_system_unit(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
        assert!(sys_unit.contains(
            "After=network-online.target systemd-resolved.service NetworkManager.service"
        ));
        assert!(sys_unit.contains("StartLimitIntervalSec=60"));
        assert!(sys_unit.contains("StartLimitBurst=5"));
        assert!(sys_unit.contains("ExecStart=\"/usr/local/bin/vdpi\" \"--tun\""));
        assert!(sys_unit.contains(&format!("\"--config\" \"{LINUX_SYSTEM_CONFIG_PATH}\"")));
        assert!(!sys_unit.contains("AmbientCapabilities="));
        assert!(!sys_unit.contains("CapabilityBoundingSet="));
        assert!(
            sys_unit.contains("ExecStopPost=+\"/usr/local/bin/vdpi\" --internal-linux-tun-cleanup")
        );
        assert!(sys_unit.contains("WantedBy=multi-user.target"));

        let custom_sys_unit =
            generate_systemd_system_unit(Path::new("/opt/my $vdpi/bin/vdpi"), &cfg);
        assert!(custom_sys_unit
            .contains("ExecStopPost=+\"/opt/my $$vdpi/bin/vdpi\" --internal-linux-tun-cleanup"));
    }

    #[test]
    fn migrates_legacy_v0_4_windows_service_cmdline_to_proxy_file_config() {
        let legacy_cmd = r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --bind 127.0.0.1 --port 8088 --chunk-size 6 --socks-port 1088 --mode tls-record --dns 8.8.8.8 --bypass *.example.com --no-env-proxy --allow-quic --quiet"#;
        let migrated = migrate_legacy_service_cmdline_to_file_config(legacy_cmd);
        assert_eq!(migrated.schema_version, Some(CONFIG_SCHEMA_VERSION));
        assert_eq!(migrated.engine, Some(EngineMode::Proxy));
        assert_eq!(migrated.bind, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(migrated.port, Some(8088));
        assert_eq!(migrated.chunk_size, Some(6));
        assert_eq!(migrated.socks_port, Some(1088));
        assert_eq!(migrated.mode, Some(DesyncMode::TlsRecord));
        assert_eq!(migrated.dns_addr.as_deref(), Some("8.8.8.8"));
        assert_eq!(
            migrated.bypass_domains,
            Some(vec!["*.example.com".to_string()])
        );
        assert_eq!(migrated.env_proxy, Some(false));
        assert_eq!(migrated.block_quic, Some(false));
    }

    #[test]
    fn formats_vpn_conflict_and_rss_labels_cleanly() {
        assert_eq!(format_vpn_scope_conflict(&VpnScope::None), None);
        assert_eq!(
            format_vpn_scope_conflict(&VpnScope::SplitOverlay {
                providers: vec!["Tailscale".to_string()],
            }),
            None
        );
        assert_eq!(
            format_vpn_scope_conflict(&VpnScope::FullTunnel {
                provider: "Mullvad".to_string(),
                iface: "wg0".to_string(),
                kill_switch: true,
            })
            .as_deref(),
            Some("Mullvad (wg0) [kill-switch]")
        );
        assert_eq!(format_rss_label(16384), "16 MB RSS");
        assert_eq!(format_rss_label(512), "512 KB RSS");
    }

    #[test]
    fn rejects_invalid_health_json() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(parse_health_json("", addr, 8080, None), None);
        assert_eq!(parse_health_json("   \r\n", addr, 8080, None), None);
        assert_eq!(
            parse_health_json("<html>200 OK</html>", addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok""#, addr, 8080, None),
            None
        );
        assert_eq!(parse_health_json(r#"["ok"]"#, addr, 8080, None), None);
        assert_eq!(
            parse_health_json(r#"{"hello":"world"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"ok","service":"other"}"#, addr, 8080, None),
            None
        );
        assert_eq!(
            parse_health_json(r#"{"status":"error","service":"vdpi"}"#, addr, 8080, None),
            None
        );
    }

    #[test]
    fn probe_connect_ip_normalizes_wildcards_and_rejects_remote() {
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1))),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0))),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808
            ))),
            None
        );
        assert_eq!(
            probe_connect_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            None
        );
    }

    #[test]
    fn build_probe_candidates_deduplicates_canonical_endpoints() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        cfg.addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        cfg.port = 8080;
        cfg.socks_port = Some(1080);

        let states = vec![
            RuntimeState {
                pid: 1,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8080,
                socks_port: Some(1081),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 2,
                addr: IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)),
                port: 8080,
                socks_port: Some(1082),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 3,
                addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 8081,
                socks_port: None,
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
            RuntimeState {
                pid: 4,
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 8081,
                socks_port: Some(1085),
                engine: EngineMode::Proxy,
                tun_interface: None,
                env_activated_at: None,
            },
        ];

        let candidates = build_probe_candidates(&cfg, &states);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[0].port, 8080);
        assert_eq!(candidates[0].socks_port, Some(1081));
        assert_eq!(candidates[1].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[1].port, 8081);
        assert_eq!(candidates[1].socks_port, Some(1085));
        assert_eq!(candidates[2].connect_ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(candidates[2].port, DEFAULT_TUN_HEALTH_PORT);
        assert_eq!(candidates[2].socks_port, None);

        // Deduplicates DEFAULT_TUN_HEALTH_PORT when already present in RuntimeState.
        let mut with_tun = states;
        with_tun.push(RuntimeState {
            pid: 5,
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DEFAULT_TUN_HEALTH_PORT,
            socks_port: None,
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            env_activated_at: None,
        });
        let deduped = build_probe_candidates(&cfg, &with_tun);
        assert_eq!(deduped.len(), 3);
        assert_eq!(deduped[2].port, DEFAULT_TUN_HEALTH_PORT);
    }

    #[test]
    fn strips_exact_unix_shell_path_export_line() {
        let content = format!("export FOO=1\n{UNIX_SHELL_PATH_EXPORT}\nexport BAR=2\n");
        assert_eq!(
            strip_unix_shell_path_line(&content).as_deref(),
            Some("export FOO=1\nexport BAR=2\n")
        );

        let only_export = format!("{UNIX_SHELL_PATH_EXPORT}\n");
        assert_eq!(
            strip_unix_shell_path_line(&only_export).as_deref(),
            Some("")
        );

        let custom = format!("{UNIX_SHELL_PATH_EXPORT} # custom\n");
        assert_eq!(strip_unix_shell_path_line(&custom), None);
        assert_eq!(strip_unix_shell_path_line("export FOO=1\n"), None);
    }

    #[test]
    fn probe_local_health_accepts_200_and_rejects_non_200() {
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();

        let body = r#"{"status":"ok","service":"vdpi","version":"0.4.2","mode":"combo","doh":true,"block_quic":true,"active_connections":3,"total_connections":42,"learned_hosts":5,"isp_stage":"stage-1"}"#;
        let responses = [
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
            format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
            format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
            ),
        ];

        let server = std::thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("accept probe connection");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut req_buf = [0u8; 512];
                let _ = stream.read(&mut req_buf);
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP response");
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Write);
            }
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        let ok_11 = probe_local_health(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Some(1080), deadline)
            .expect("HTTP/1.1 200 response should succeed");
        assert_eq!(ok_11.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(ok_11.port, port);
        assert_eq!(ok_11.socks_port, Some(1080));
        assert_eq!(ok_11.version.as_deref(), Some("0.4.2"));
        assert_eq!(ok_11.mode.as_deref(), Some("combo"));
        assert_eq!(ok_11.doh, Some(true));
        assert_eq!(ok_11.block_quic, Some(true));
        assert_eq!(ok_11.active_connections, Some(3));
        assert_eq!(ok_11.total_connections, Some(42));
        assert_eq!(ok_11.learned_hosts, Some(5));
        assert_eq!(ok_11.isp_stage.as_deref(), Some("stage-1"));

        let ok_10_wildcard =
            probe_local_health(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port, None, deadline)
                .expect("HTTP/1.0 200 via 0.0.0.0 wildcard should normalize to 127.0.0.1");
        assert_eq!(ok_10_wildcard.version.as_deref(), Some("0.4.2"));

        let rejected_404 =
            probe_local_health(IpAddr::V4(Ipv4Addr::LOCALHOST), port, Some(1080), deadline);
        assert_eq!(rejected_404, None);

        server.join().expect("server thread should finish cleanly");
    }

    #[test]
    fn probe_live_engine_fetches_health_and_maps_socks_port() {
        use std::net::{Shutdown, TcpListener};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener addr").port();

        let body = r#"{"status":"ok","service":"vdpi","version":"0.5.0","engine":"proxy","bytes_rx":4096,"bytes_tx":1024,"tls_handshakes":11,"auto_heal_escalations":1}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
        );

        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept probe connection");
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut req_buf = [0u8; 512];
                let _ = stream.read(&mut req_buf);
                stream
                    .write_all(response.as_bytes())
                    .expect("write HTTP response");
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Write);
            }
        });

        let with_socks = probe_live_engine(IpAddr::V4(Ipv4Addr::LOCALHOST), port, 1080)
            .expect("probe_live_engine with socks_port should succeed");
        assert_eq!(with_socks.socks_port, Some(1080));
        assert_eq!(with_socks.bytes_rx, Some(4096));
        assert_eq!(with_socks.bytes_tx, Some(1024));
        assert_eq!(with_socks.tls_handshakes, Some(11));
        assert_eq!(with_socks.auto_heal_escalations, Some(1));

        let without_socks = probe_live_engine(IpAddr::V4(Ipv4Addr::LOCALHOST), port, 0)
            .expect("probe_live_engine with socks_port=0 should succeed");
        assert_eq!(without_socks.socks_port, None);
        assert_eq!(without_socks.bytes_rx, Some(4096));

        assert_eq!(
            probe_live_engine(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, 1080),
            None
        );
        assert_eq!(
            probe_live_engine(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), port, 1080),
            None
        );

        server.join().expect("server thread should finish cleanly");
    }

    #[test]
    fn apply_file_config_to_runtime_enforces_invariants_unconditionally() {
        let base = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        assert_eq!(base.socks_port, Some(1080));
        assert!(base.system_proxy);
        assert!(base.socks_system_proxy);
        assert!(base.env_proxy);

        // Port colliding with existing socks_port must clear socks_port and socks_system_proxy.
        let collided = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                port: Some(1080),
                ..Default::default()
            },
        );
        assert_eq!(collided.port, 1080);
        assert_eq!(collided.socks_port, None);
        assert!(!collided.socks_system_proxy);

        // Disabling system_proxy must clear socks_system_proxy and env_proxy even if omitted.
        let no_sys = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                system_proxy: Some(false),
                ..Default::default()
            },
        );
        assert!(!no_sys.system_proxy);
        assert!(!no_sys.socks_system_proxy);
        assert!(!no_sys.env_proxy);

        // Disabling socks_port must clear socks_system_proxy even if omitted.
        let no_socks = apply_file_config_to_runtime(
            &base,
            &FileConfig {
                socks_port: Some(0),
                ..Default::default()
            },
        );
        assert_eq!(no_socks.socks_port, None);
        assert!(!no_socks.socks_system_proxy);
    }

    #[test]
    fn cleanup_unix_root_dir_preserves_user_config_without_purge() {
        let unique = format!(
            "vdpi-cleanup-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let bin_dir = root.join("bin");
        let logs_dir = root.join("logs");
        let state_file = root.join("state.json");
        let user_cfg = root.join("config.toml");

        fs::create_dir_all(&bin_dir).expect("create bin dir");
        fs::create_dir_all(&logs_dir).expect("create logs dir");
        fs::write(bin_dir.join("vdpi"), b"bin").expect("write fake bin");
        fs::write(logs_dir.join("vdpi.out.log"), b"log").expect("write fake log");
        fs::write(&state_file, b"{}").expect("write fake state");
        fs::write(&user_cfg, b"engine = \"proxy\"\n").expect("write fake config");

        cleanup_unix_root_dir(&root, &user_cfg, false);
        assert!(!bin_dir.exists());
        assert!(!logs_dir.exists());
        assert!(!state_file.exists());
        assert!(user_cfg.is_file());
        assert!(root.is_dir());

        cleanup_unix_root_dir(&root, &user_cfg, true);
        assert!(!user_cfg.exists());
        assert!(!root.exists());
    }

    #[test]
    fn parse_nonzero_sudo_uid_rejects_zero_and_invalid_values() {
        use std::ffi::OsStr;

        assert_eq!(parse_nonzero_sudo_uid(None), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new(""))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("0"))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("not-a-uid"))), None);
        assert_eq!(parse_nonzero_sudo_uid(Some(OsStr::new("501"))), Some(501));
        assert_eq!(
            parse_nonzero_sudo_uid(Some(OsStr::new(" 1000 "))),
            Some(1000)
        );
    }

    #[test]
    fn file_config_roundtrip_preserves_split_tunnel_settings() {
        let mut base = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        let default_fc = file_config_from_runtime(&base);
        assert_eq!(default_fc.split_tunnel_mode, None);
        assert_eq!(default_fc.split_tunnel_apps, None);

        base.split_tunnel = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: vec!["Discord.exe".to_string(), "chrome".to_string()],
        };
        let fc = file_config_from_runtime(&base);
        assert_eq!(
            fc.split_tunnel_mode,
            Some(vdpi_core::config::SplitTunnelMode::Include)
        );
        assert_eq!(
            fc.split_tunnel_apps,
            Some(vec!["Discord.exe".to_string(), "chrome".to_string()])
        );

        let fresh = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        let applied = apply_file_config_to_runtime(&fresh, &fc);
        assert_eq!(applied.split_tunnel, base.split_tunnel);
    }

    #[test]
    fn save_split_tunnel_preserves_existing_keys_and_extracts_back() {
        let unique = format!(
            "vdpi-split-tunnel-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let cfg_path = root.join("config.toml");

        let initial = FileConfig {
            schema_version: Some(CONFIG_SCHEMA_VERSION),
            engine: Some(EngineMode::Tun),
            dns_addr: Some("94.140.14.14".to_string()),
            bypass_domains: Some(vec!["local.test".to_string()]),
            port: Some(9090),
            ..Default::default()
        };
        config_file::save_file_config_atomic(&cfg_path, &initial).expect("write initial config");

        let target = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["steam".to_string(), "discord".to_string()],
        };
        save_split_tunnel_to_config_path(&cfg_path, false, &target)
            .expect("save split tunnel config");

        let (_, reloaded) =
            config_file::load_file_config(Some(&cfg_path), false).expect("reload config");
        assert_eq!(reloaded.engine, Some(EngineMode::Tun));
        assert_eq!(reloaded.dns_addr.as_deref(), Some("94.140.14.14"));
        assert_eq!(
            reloaded.bypass_domains,
            Some(vec!["local.test".to_string()])
        );
        assert_eq!(reloaded.port, Some(9090));
        assert_eq!(
            extract_split_tunnel_from_file_config(&reloaded),
            Some(target)
        );

        let err = set_service_split_tunnel(&vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: vec!["bad\napp".to_string()],
        })
        .expect_err("control characters in app list must fail validation");
        assert!(err.to_string().contains("control characters"));

        let _ = fs::remove_dir_all(&root);
    }

    fn strip_ansi_escapes(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn sudo_prompt_card_respects_width_wrapping_and_no_color() {
        let long_action =
            "switch the macOS background service to tun mode and refresh split tunneling rules";
        let plain_macos = format_unix_sudo_prompt_card(long_action, true, true);
        assert!(
            !plain_macos.contains('\x1b'),
            "NO_COLOR card must not emit ANSI escapes"
        );
        assert!(plain_macos.contains("vdpi · Administrator Approval"));
        assert!(plain_macos.contains("Prompt   Enter your password (or Touch ID) below"));

        let lines: Vec<&str> = plain_macos.lines().collect();
        assert!(lines.len() >= 6, "long action should wrap across lines");
        for line in &lines {
            let width = line.chars().count();
            assert!(
                width <= 64,
                "sudo card line exceeded 64 cols ({width}): {line:?}"
            );
            assert_eq!(
                width, 64,
                "sudo card lines should stay aligned at 64 cols: {line:?}"
            );
        }

        // Verify word wrapping never breaks words mid-word and capitalizes the first letter.
        let wrapped = wrap_sudo_action_lines(long_action, SUDO_CARD_ACTION_WRAP_WIDTH);
        assert!(wrapped.len() >= 2);
        assert!(wrapped[0].starts_with("Switch "));
        for wline in &wrapped {
            assert!(
                wline.chars().count() <= SUDO_CARD_ACTION_WRAP_WIDTH,
                "wrapped action line exceeded 46 chars: {wline:?}"
            );
        }
        assert_eq!(
            wrapped.join(" "),
            "Switch the macOS background service to tun mode and refresh split tunneling rules"
        );

        // Verify colored macOS card uses the expected ANSI palette and strips identically to plain.
        let colored_macos = format_unix_sudo_prompt_card(long_action, true, false);
        assert!(colored_macos.contains("\x1b[38;2;74;85;104m"));
        assert!(colored_macos.contains("\x1b[1;38;2;241;245;249m"));
        assert!(colored_macos.contains("\x1b[38;2;148;163;184m"));
        assert_eq!(strip_ansi_escapes(&colored_macos), plain_macos);

        // Verify Linux prompt hint and empty action fallback.
        let plain_linux = format_unix_sudo_prompt_card("   ", false, true);
        assert!(!plain_linux.contains('\x1b'));
        assert!(plain_linux.contains("Prompt   Enter your sudo password below"));
        assert!(plain_linux.contains("Action   Complete a privileged operation"));
        for line in plain_linux.lines() {
            assert!(line.chars().count() <= 64);
        }
    }

    #[test]
    fn builds_split_apply_args_for_elevation() {
        let all_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::All,
            apps: vec![],
        };
        assert_eq!(
            build_split_apply_args(&all_cfg),
            vec!["split", "apply", "--mode", "all"]
        );

        let exclude_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["discord".to_string(), "steam".to_string()],
        };
        assert_eq!(
            build_split_apply_args(&exclude_cfg),
            vec!["split", "apply", "--mode", "exclude", "--app", "discord", "--app", "steam"]
        );

        let include_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: vec!["Google Chrome".to_string()],
        };
        assert_eq!(
            build_split_apply_args(&include_cfg),
            vec![
                "split",
                "apply",
                "--mode",
                "include",
                "--app",
                "Google Chrome"
            ]
        );
    }

    #[test]
    fn builds_unix_install_sudo_args_preserving_upgrade_and_engine() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();

        cfg.engine = EngineMode::Proxy;
        assert_eq!(
            build_unix_install_sudo_args(&cfg, true),
            vec!["install", "--upgrade"]
        );

        cfg.engine = EngineMode::Tun;
        assert_eq!(
            build_unix_install_sudo_args(&cfg, true),
            vec!["install", "--upgrade", "--tun"]
        );

        let fresh_tun = build_unix_install_sudo_args(&cfg, false);
        assert!(fresh_tun.iter().any(|a| a == "--tun"));
        assert_eq!(fresh_tun.last().map(String::as_str), Some("install"));

        cfg.engine = EngineMode::Proxy;
        let fresh_proxy = build_unix_install_sudo_args(&cfg, false);
        assert!(fresh_proxy.iter().any(|a| a == "--proxy"));
        assert_eq!(fresh_proxy.last().map(String::as_str), Some("install"));
    }

    #[test]
    fn custom_dns_ipv4_ipv6_and_doh_roundtrip_across_manifests_and_config() {
        let unique = format!(
            "vdpi-custom-dns-service-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        fs::create_dir_all(&root).expect("create temp dir");

        let valid_cases = [
            "76.76.2.0",
            "2606:4700:4700::1111",
            "https://dns.nextdns.io/abc123",
            "https://freedns.controld.com/p2",
            "https://dns.example.com:8443/dns-query",
        ];

        for (idx, dns) in valid_cases.iter().enumerate() {
            let mut cfg = CliArgs::parse_from_iter(["vdpi", "--tun", "--dns", dns])
                .expect("CLI should parse custom DNS in TUN mode")
                .into_runtime_config();
            assert_eq!(cfg.engine, EngineMode::Tun);
            assert_eq!(cfg.dns_addr, *dns);

            // CLI service args must emit `--dns <value>` verbatim.
            let cli_args = build_service_cli_args(&cfg);
            let dns_idx = cli_args
                .iter()
                .position(|a| a == "--dns")
                .expect("--dns flag missing");
            assert_eq!(cli_args.get(dns_idx + 1).map(String::as_str), Some(*dns));

            // Windows service binPath round-trip (TUN mode + custom DoH URL never parses as Ipv4Addr).
            let win_bin = build_windows_service_bin_path(
                Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"),
                &cfg,
            );
            assert!(
                win_bin.contains(&format!("--dns {dns}")),
                "Windows binPath missing custom DNS '{dns}': {win_bin}"
            );
            let migrated = migrate_legacy_service_cmdline_to_file_config(&win_bin);
            assert_eq!(migrated.engine, Some(EngineMode::Tun));
            assert_eq!(migrated.dns_addr.as_deref(), Some(*dns));

            // macOS LaunchDaemon and LaunchAgent plists.
            let daemon_plist = generate_launch_daemon_plist(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
            assert!(daemon_plist.contains("<string>--dns</string>"));
            assert!(daemon_plist.contains(&format!("<string>{}</string>", xml_escape(dns))));
            let agent_plist =
                generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &cfg);
            assert!(agent_plist.contains("<string>--dns</string>"));
            assert!(agent_plist.contains(&format!("<string>{}</string>", xml_escape(dns))));

            // Linux systemd system and user units.
            let sys_unit = generate_systemd_system_unit(Path::new(UNIX_SYSTEM_BIN_PATH), &cfg);
            assert!(sys_unit.contains(&format!("\"--dns\" {}", quote_systemd_arg(dns))));
            let user_unit = generate_systemd_unit(Path::new("/home/test/.vdpi/bin/vdpi"), &cfg);
            assert!(user_unit.contains(&format!("\"--dns\" {}", quote_systemd_arg(dns))));

            // FileConfig TOML persistence and runtime re-hydration round-trip.
            let file_cfg = file_config_from_runtime(&cfg);
            assert_eq!(file_cfg.dns_addr.as_deref(), Some(*dns));
            let cfg_path = root.join(format!("config-{idx}.toml"));
            config_file::save_file_config_atomic(&cfg_path, &file_cfg)
                .expect("save custom DNS config");
            let (_, reloaded) =
                config_file::load_file_config(Some(&cfg_path), true).expect("reload custom DNS");
            assert_eq!(reloaded.dns_addr.as_deref(), Some(*dns));

            let fresh = CliArgs::parse_from_iter(["vdpi"])
                .unwrap()
                .into_runtime_config();
            let applied = apply_file_config_to_runtime(&fresh, &reloaded);
            assert_eq!(applied.engine, EngineMode::Tun);
            assert_eq!(applied.dns_addr, *dns);

            // Proxy mode also preserves the exact custom DNS argument.
            cfg.engine = EngineMode::Proxy;
            let proxy_args = build_service_cli_args(&cfg);
            let proxy_dns_idx = proxy_args
                .iter()
                .position(|a| a == "--dns")
                .expect("proxy --dns flag missing");
            assert_eq!(
                proxy_args.get(proxy_dns_idx + 1).map(String::as_str),
                Some(*dns)
            );
        }

        // set_service_dns_quiet must reject invalid DNS strings up front before touching files/services.
        let base_cfg = CliArgs::parse_from_iter(["vdpi", "--tun"])
            .unwrap()
            .into_runtime_config();
        for bad in ["", "   ", "http://dns.nextdns.io/abc123", "not-a-dns"] {
            assert!(
                set_service_dns_quiet(bad, &base_cfg).is_err(),
                "set_service_dns_quiet should reject invalid DNS {bad:?}"
            );
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn sibling_wintun_copy_succeeds_without_loose_dll_and_rejects_tampered_sibling() {
        let unique = format!(
            "vdpi-wintun-sibling-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let src_dir = root.join("src");
        let dst_dir = root.join("dst");
        fs::create_dir_all(&src_dir).expect("create src dir");
        fs::create_dir_all(&dst_dir).expect("create dst dir");

        let fake_exe = src_dir.join("vdpi.exe");
        fs::write(&fake_exe, b"fake-exe").expect("write fake exe");

        // No loose wintun.dll next to current_exe: must succeed with (false, None) and never fail.
        let (copied, backup) =
            copy_verified_sibling_wintun_from_exe_with_backup(&fake_exe, &dst_dir, false)
                .expect("missing loose wintun.dll must never fail install");
        assert!(!copied);
        assert!(backup.is_none());
        assert!(!dst_dir.join("wintun.dll").exists());

        // Present but tampered sibling wintun.dll must fail SHA-256 verification.
        fs::write(src_dir.join("wintun.dll"), b"tampered-bytes").expect("write tampered dll");
        assert!(
            copy_verified_sibling_wintun_from_exe_with_backup(&fake_exe, &dst_dir, false).is_err(),
            "tampered loose sibling wintun.dll must be rejected"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn retryable_windows_rename_errors_cover_defender_sharing_and_access_locks() {
        assert!(is_retryable_windows_rename_error(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "permission denied",
        )));
        assert!(is_retryable_windows_rename_error(
            &std::io::Error::from_raw_os_error(5)
        ));
        assert!(is_retryable_windows_rename_error(
            &std::io::Error::from_raw_os_error(32)
        ));
        assert!(is_retryable_windows_rename_error(
            &std::io::Error::from_raw_os_error(33)
        ));
        assert!(!is_retryable_windows_rename_error(&std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        )));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_proxy_drift_recognizes_fail_open_pac_and_flags_stale_manual_or_env() {
        let lo4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // Healthy fail-open PAC (IPv4 localhost, 0.0.0.0 normalized, and IPv6 localhost).
        assert_eq!(
            evaluate_windows_proxy_drift(
                lo4,
                8080,
                false,
                "",
                Some("http://127.0.0.1:8080/vdpi.pac"),
                None,
                None,
            ),
            None
        );
        assert_eq!(
            evaluate_windows_proxy_drift(
                any4,
                18080,
                false,
                "127.0.0.1:8080",
                Some("http://127.0.0.1:18080/vdpi.pac"),
                None,
                None,
            ),
            None
        );
        assert_eq!(
            evaluate_windows_proxy_drift(
                lo6,
                8080,
                false,
                "",
                Some("http://[::1]:8080/vdpi.pac"),
                None,
                None,
            ),
            None
        );

        // Drifted AutoConfigURL pointing to a different vdpi port must warn.
        let pac_drift = evaluate_windows_proxy_drift(
            lo4,
            8080,
            false,
            "",
            Some("http://127.0.0.1:18080/vdpi.pac"),
            None,
            None,
        )
        .expect("drifted AutoConfigURL must be flagged");
        assert!(pac_drift.contains("AutoConfigURL"));
        assert!(pac_drift.contains("http://127.0.0.1:8080/vdpi.pac"));

        // Legacy fail-closed ProxyEnable=1 pointing at loopback must warn.
        let legacy_manual = evaluate_windows_proxy_drift(
            lo4,
            8080,
            true,
            "127.0.0.1:8080",
            Some("http://127.0.0.1:8080/vdpi.pac"),
            None,
            None,
        )
        .expect("legacy fail-closed ProxyEnable=1 must be flagged");
        assert!(legacy_manual.contains("fail-closed"));

        // Stale legacy HKCU\Environment HTTP_PROXY / HTTPS_PROXY must warn.
        let stale_env = evaluate_windows_proxy_drift(
            lo4,
            8080,
            false,
            "",
            Some("http://127.0.0.1:8080/vdpi.pac"),
            None,
            Some("http://127.0.0.1:8080"),
        )
        .expect("stale HKCU\\Environment HTTPS_PROXY must be flagged");
        assert!(stale_env.contains("HTTPS_PROXY"));

        let stale_http_env = evaluate_windows_proxy_drift(
            lo4,
            8080,
            false,
            "",
            Some("http://127.0.0.1:8080/vdpi.pac"),
            Some("http://[::1]:8080"),
            None,
        )
        .expect("stale HKCU\\Environment HTTP_PROXY must be flagged");
        assert!(stale_http_env.contains("HTTP_PROXY"));

        // Unrelated external env proxy and --no-system-proxy mode are left alone.
        assert_eq!(
            evaluate_windows_proxy_drift(
                lo4,
                8080,
                false,
                "",
                None,
                Some("http://proxy.corp.local:3128"),
                Some("http://proxy.corp.local:3128"),
            ),
            None
        );
    }

    #[test]
    fn build_service_cli_args_emits_split_tunnel_flags_and_avoids_contradictory_no_doh() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--tun"])
            .unwrap()
            .into_runtime_config();
        cfg.split_tunnel = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec![
                "discord".to_string(),
                "steam.exe".to_string(),
                "-weird-app".to_string(),
                "DISCORD".to_string(), // duplicate should be deduplicated
            ],
        };
        // Explicit DoH URL with enable_doh = false must NOT emit contradictory `--no-doh`.
        cfg.enable_doh = false;
        cfg.dns_addr = "https://dns.nextdns.io/abc123".to_string();

        let args = build_service_cli_args(&cfg);
        assert!(
            !args.iter().any(|a| a == "--no-doh"),
            "must never emit --no-doh alongside https:// DoH URL: {args:?}"
        );
        let dns_pos = args.iter().position(|a| a == "--dns").expect("--dns missing");
        assert_eq!(
            args.get(dns_pos + 1).map(String::as_str),
            Some("https://dns.nextdns.io/abc123")
        );
        let mode_pos = args
            .iter()
            .position(|a| a == "--split-mode")
            .expect("--split-mode missing");
        assert_eq!(args.get(mode_pos + 1).map(String::as_str), Some("exclude"));
        assert!(args.windows(2).any(|w| w == ["--split-app", "discord"]));
        assert!(args.windows(2).any(|w| w == ["--split-app", "steam.exe"]));
        assert!(args.iter().any(|a| a == "--split-app=-weird-app"));
        assert_eq!(
            args.iter()
                .filter(|a| *a == "--split-app" || a.starts_with("--split-app="))
                .count(),
            3
        );

        // FileConfig persistence & runtime re-hydration must also enforce effective DoH.
        let file_cfg = file_config_from_runtime(&cfg);
        assert_eq!(file_cfg.doh, Some(true));
        let mut conflicting_fc = file_cfg.clone();
        conflicting_fc.doh = Some(false);
        let fresh = CliArgs::parse_from_iter(["vdpi"])
            .unwrap()
            .into_runtime_config();
        let applied = apply_file_config_to_runtime(&fresh, &conflicting_fc);
        assert!(applied.enable_doh);

        // Plain IP DNS with enable_doh = false still emits --no-doh.
        let mut plain_cfg = CliArgs::parse_from_iter(["vdpi", "--dns", "8.8.8.8", "--no-doh"])
            .unwrap()
            .into_runtime_config();
        plain_cfg.enable_doh = false;
        let plain_args = build_service_cli_args(&plain_cfg);
        assert!(plain_args.iter().any(|a| a == "--no-doh"));
        assert!(!plain_args.iter().any(|a| a == "--split-mode"));
        assert!(!plain_args.iter().any(|a| a == "--split-app"));

        // LaunchAgent plist must include AbandonProcessGroup=true.
        let agent_plist =
            generate_launch_agent_plist(Path::new("/Users/test/.vdpi/bin/vdpi"), &cfg);
        assert!(agent_plist.contains("<key>AbandonProcessGroup</key>\n    <true/>"));
    }

    #[test]
    fn split_tunnel_large_app_list_uses_temp_file_and_active_config_resolution() {
        let small = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["discord".to_string(), "steam".to_string()],
        };
        let (small_args, small_guard) =
            build_windows_split_apply_args_with_temp(&small).expect("small split args");
        assert!(small_guard.is_none());
        assert_eq!(small_args, build_split_apply_args(&small));

        let large_apps: Vec<String> = (0..120)
            .map(|i| format!("com.example.longapplicationname.entry{i:03}.exe"))
            .collect();
        let large = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: large_apps.clone(),
        };
        let inline_len = windows_shell_execute_params_len(&build_split_apply_args(&large));
        assert!(inline_len > WINDOWS_SHELLEXECUTE_SAFE_ARGS_LIMIT);

        let (elevated_args, guard) =
            build_windows_split_apply_args_with_temp(&large).expect("large split args");
        let guard = guard.expect("large app list must spill to a temp file");
        let elevated_len = windows_shell_execute_params_len(&elevated_args);
        assert!(
            elevated_len <= WINDOWS_SHELLEXECUTE_SAFE_ARGS_LIMIT,
            "elevated args ({elevated_len} chars) must stay under safe ShellExecuteExW limit"
        );
        let temp_path = guard.0.clone();
        assert!(temp_path.is_file());

        let app_idx = elevated_args
            .iter()
            .position(|a| a == "--app")
            .expect("--app marker missing");
        let decoded = resolve_split_tunnel_apps_input(&[elevated_args[app_idx + 1].clone()])
            .expect("temp file app list should decode cleanly");
        assert_eq!(decoded, large_apps);

        drop(guard);
        assert!(
            !temp_path.exists(),
            "temp split-tunnel file must be cleaned up when guard drops"
        );

        // Active config target resolution: when no service is installed and only system config
        // exists, write to system config instead of creating a partial shadowing user config.
        let unique = format!(
            "vdpi-active-cfg-test-{}-{}",
            std::process::id(),
            unix_now_secs()
        );
        let root = std::env::temp_dir().join(unique);
        let user_cfg = root.join("user").join("config.toml");
        let sys_cfg = root.join("sys").join("config.toml");
        fs::create_dir_all(sys_cfg.parent().unwrap()).expect("create sys dir");
        fs::write(&sys_cfg, "engine = \"tun\"\n").expect("write sys config");

        let (chosen, use_sys) = resolve_active_split_config_target(false, &user_cfg, &sys_cfg);
        assert_eq!(chosen, sys_cfg);
        assert!(use_sys);

        fs::create_dir_all(user_cfg.parent().unwrap()).expect("create user dir");
        fs::write(&user_cfg, "engine = \"proxy\"\n").expect("write user config");
        let (chosen_user, use_sys_user) =
            resolve_active_split_config_target(false, &user_cfg, &sys_cfg);
        assert_eq!(chosen_user, user_cfg);
        assert!(!use_sys_user);

        let (chosen_svc, use_sys_svc) =
            resolve_active_split_config_target(true, &user_cfg, &sys_cfg);
        assert_eq!(chosen_svc, sys_cfg);
        assert!(use_sys_svc);

        assert_eq!(
            format_split_tunnel_saved_message("exclude (2 apps)", true),
            "Split tunneling saved: exclude (2 apps) (service restarted)"
        );
        assert_eq!(
            format_split_tunnel_saved_message("exclude (2 apps)", false),
            "Split tunneling saved: exclude (2 apps)"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn macos_proxy_drift_fails_when_pac_disabled_and_catches_lowercase_or_localhost_env() {
        let lo4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

        let aligned_wifi = MacosProxyServiceSnapshot {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: true,
            auto_proxy_url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
            ..Default::default()
        };
        assert_eq!(
            evaluate_macos_proxy_drift_snapshot(lo4, 8080, std::slice::from_ref(&aligned_wifi), &[]),
            None
        );
        assert_eq!(
            evaluate_macos_proxy_drift_snapshot(any4, 8080, std::slice::from_ref(&aligned_wifi), &[]),
            None
        );

        let aligned_v6 = MacosProxyServiceSnapshot {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: true,
            auto_proxy_url: "http://[::1]:8080/vdpi.pac".to_string(),
            ..Default::default()
        };
        assert_eq!(
            evaluate_macos_proxy_drift_snapshot(any6, 8080, &[aligned_v6], &[]),
            None
        );

        // PAC disabled/unset on all services must FAIL.
        let disabled_wifi = MacosProxyServiceSnapshot {
            service: "Wi-Fi".to_string(),
            auto_proxy_enabled: false,
            auto_proxy_url: "http://127.0.0.1:8080/vdpi.pac".to_string(),
            ..Default::default()
        };
        let disabled_err = evaluate_macos_proxy_drift_snapshot(lo4, 8080, &[disabled_wifi], &[])
            .expect("disabled PAC on all macOS services must fail drift check");
        assert!(disabled_err.contains("disabled or unset"));

        let empty_err = evaluate_macos_proxy_drift_snapshot(lo4, 8080, &[], &[])
            .expect("empty macOS service list must fail drift check");
        assert!(empty_err.contains("disabled or unset"));

        // Lowercase http_proxy / https_proxy / all_proxy and localhost must all be flagged.
        for (var_name, val) in [
            ("http_proxy", "http://127.0.0.1:8080"),
            ("https_proxy", "http://localhost:8080"),
            ("all_proxy", "socks5://localhost:1080"),
            ("ALL_PROXY", "socks5h://[::1]:1080"),
        ] {
            let err = evaluate_macos_proxy_drift_snapshot(
                lo4,
                8080,
                std::slice::from_ref(&aligned_wifi),
                &[(var_name, Some(val))],
            )
            .unwrap_or_else(|| panic!("expected {var_name}={val} to be flagged as drift"));
            assert!(err.contains(var_name));
        }

        // Stopped-daemon hygiene check flags stale PAC and stale lowercase env.
        let stale_pac = evaluate_macos_stale_proxy_when_stopped(&[aligned_wifi], &[])
            .expect("stale vdpi AutoProxyURL while stopped must be flagged");
        assert!(stale_pac.contains("AutoProxyURL"));

        let stale_env = evaluate_macos_stale_proxy_when_stopped(
            &[],
            &[("all_proxy", Some("socks5://localhost:1080"))],
        )
        .expect("stale launchd all_proxy while stopped must be flagged");
        assert!(stale_env.contains("all_proxy"));

        assert_eq!(evaluate_macos_stale_proxy_when_stopped(&[], &[]), None);
    }

    #[test]
    fn linux_proxy_drift_checks_gnome_kde_pac_and_normalizes_ipv6_wildcard() {
        let any4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let any6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

        // Healthy GNOME + KDE PAC + systemd env with 0.0.0.0 normalized to 127.0.0.1.
        let healthy_v4 = LinuxProxySnapshot {
            gnome_available: true,
            gnome_mode: Some("'auto'".to_string()),
            gnome_autoconfig_url: Some("'http://127.0.0.1:8080/vdpi.pac'".to_string()),
            kde_available: true,
            kde_proxy_type: Some("2".to_string()),
            kde_pac_url: Some("http://127.0.0.1:8080/vdpi.pac".to_string()),
            systemd_env: parse_systemd_show_env(
                "HTTP_PROXY=http://127.0.0.1:8080\nHTTPS_PROXY=http://127.0.0.1:8080\nhttps_proxy=http://127.0.0.1:8080\n",
            ),
            ..Default::default()
        };
        assert_eq!(evaluate_linux_proxy_drift(any4, 8080, &healthy_v4), None);

        // Healthy IPv6 wildcard `::` normalized to `[::1]`.
        let healthy_v6 = LinuxProxySnapshot {
            gnome_available: true,
            gnome_mode: Some("'auto'".to_string()),
            gnome_autoconfig_url: Some("'http://[::1]:9090/vdpi.pac'".to_string()),
            kde_available: true,
            kde_proxy_type: Some("2".to_string()),
            kde_pac_url: Some("http://[::1]:9090/vdpi.pac".to_string()),
            systemd_env: vec![("HTTPS_PROXY".to_string(), "http://[::1]:9090".to_string())],
            ..Default::default()
        };
        assert_eq!(evaluate_linux_proxy_drift(any6, 9090, &healthy_v6), None);

        // GNOME mode 'none' or drifted PAC URL must fail.
        let mut gnome_none = healthy_v4.clone();
        gnome_none.gnome_mode = Some("'none'".to_string());
        assert!(evaluate_linux_proxy_drift(any4, 8080, &gnome_none)
            .expect("GNOME mode=none must fail")
            .contains("GNOME proxy mode"));

        let mut gnome_drifted = healthy_v4.clone();
        gnome_drifted.gnome_autoconfig_url =
            Some("'http://127.0.0.1:18080/vdpi.pac'".to_string());
        assert!(evaluate_linux_proxy_drift(any4, 8080, &gnome_drifted)
            .expect("GNOME drifted PAC must fail")
            .contains("autoconfig-url"));

        // KDE ProxyType=0 or drifted PAC URL must fail.
        let mut kde_off = healthy_v4.clone();
        kde_off.kde_proxy_type = Some("0".to_string());
        assert!(evaluate_linux_proxy_drift(any4, 8080, &kde_off)
            .expect("KDE ProxyType=0 must fail")
            .contains("KDE kioslaverc ProxyType"));

        let mut kde_drifted = healthy_v4.clone();
        kde_drifted.kde_pac_url = Some("http://127.0.0.1:18080/vdpi.pac".to_string());
        assert!(evaluate_linux_proxy_drift(any4, 8080, &kde_drifted)
            .expect("KDE drifted PAC must fail")
            .contains("Proxy Config Script"));

        // systemd lowercase https_proxy drift and stale all_proxy must fail.
        let mut env_drift = healthy_v4.clone();
        env_drift.systemd_env = vec![("https_proxy".to_string(), "http://localhost:9999".to_string())];
        assert!(evaluate_linux_proxy_drift(any4, 8080, &env_drift)
            .expect("lowercase https_proxy drift must fail")
            .contains("https_proxy"));

        let mut env_all = healthy_v4.clone();
        env_all.systemd_env = vec![("all_proxy".to_string(), "socks5://127.0.0.1:1080".to_string())];
        assert!(evaluate_linux_proxy_drift(any4, 8080, &env_all)
            .expect("stale all_proxy must fail")
            .contains("all_proxy"));

        // kioslaverc INI parser sanity check.
        let ini = "[General]\nfoo=bar\n[Proxy Settings]\nProxyType=2\nProxy Config Script=http://127.0.0.1:8080/vdpi.pac\n";
        let (pt, pac, manual) = parse_kioslaverc_proxy_settings(ini);
        assert_eq!(pt.as_deref(), Some("2"));
        assert_eq!(pac.as_deref(), Some("http://127.0.0.1:8080/vdpi.pac"));
        assert!(manual.is_empty());

        // Stopped-daemon check flags stale GNOME/KDE PAC and systemd loopback env.
        assert!(evaluate_linux_stale_proxy_when_stopped(&healthy_v4).is_some());
        let clean = LinuxProxySnapshot {
            gnome_available: true,
            gnome_mode: Some("'none'".to_string()),
            kde_available: true,
            kde_proxy_type: Some("0".to_string()),
            ..Default::default()
        };
        assert_eq!(evaluate_linux_stale_proxy_when_stopped(&clean), None);
    }

    #[test]
    fn windows_stale_proxy_when_stopped_flags_vdpi_pac_and_loopback_env() {
        assert_eq!(
            evaluate_windows_stale_proxy_when_stopped(false, "", None, None, None),
            None
        );
        assert_eq!(
            evaluate_windows_stale_proxy_when_stopped(
                false,
                "",
                Some("https://proxy.corp.example/wpad.dat"),
                Some("http://proxy.corp.example:3128"),
                None,
            ),
            None
        );
        assert!(evaluate_windows_stale_proxy_when_stopped(
            false,
            "",
            Some("http://127.0.0.1:8080/vdpi.pac"),
            None,
            None,
        )
        .expect("stale vdpi PAC must be flagged when stopped")
        .contains("AutoConfigURL"));
        assert!(evaluate_windows_stale_proxy_when_stopped(
            true,
            "127.0.0.1:8080",
            None,
            None,
            None,
        )
        .expect("stale loopback ProxyEnable=1 must be flagged when stopped")
        .contains("ProxyEnable=1"));
        assert!(evaluate_windows_stale_proxy_when_stopped(
            false,
            "",
            None,
            Some("http://localhost:8080"),
            None,
        )
        .expect("stale localhost HTTP_PROXY must be flagged when stopped")
        .contains("HTTP_PROXY"));
    }

    #[test]
    fn status_output_redacts_doh_urls_in_text_json_and_health_body() {
        let configured_secret = "https://dns.nextdns.io/secret987654/my-laptop";
        let active_secret = "https://freedns.controld.com/privtoken42";
        let expected_configured = vdpi_core::dns::redact_dns_for_display(configured_secret);
        let expected_active = vdpi_core::dns::redact_dns_for_display(active_secret);

        let live = LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            dns_addr: Some(active_secret.to_string()),
            block_quic: Some(true),
            active_connections: Some(1),
            total_connections: Some(2),
            learned_hosts: Some(3),
            isp_stage: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        };

        let split = vdpi_core::config::SplitTunnelConfig::default();
        let json = build_status_json_payload(
            ServiceState::Running,
            EngineMode::Proxy,
            configured_secret,
            None,
            &split,
            Some(&live),
        );
        let serialized = serde_json::to_string(&json).expect("serialize status json");
        assert_eq!(
            json["configured_dns"].as_str(),
            Some(expected_configured.as_str())
        );
        assert_eq!(json["active_dns"].as_str(), Some(expected_active.as_str()));
        assert_eq!(
            json["live"]["dns_addr"].as_str(),
            Some(expected_active.as_str())
        );
        assert!(
            !serialized.contains("secret987654"),
            "status JSON must redact configured_dns token: {serialized}"
        );
        assert!(
            !serialized.contains("privtoken42"),
            "status JSON must redact active_dns token: {serialized}"
        );

        let live_line = format_status_dns_line(configured_secret, Some(&live));
        assert!(live_line.contains(&expected_active));
        assert!(!live_line.contains("privtoken42"));

        let offline_line = format_status_dns_line(configured_secret, None);
        assert!(offline_line.contains(&expected_configured));
        assert!(offline_line.contains("(configured)"));
        assert!(!offline_line.contains("secret987654"));

        let plain_line = format_status_dns_line("1.1.1.1", None);
        assert!(plain_line.contains("1.1.1.1"));

        let raw_health = format!(r#"{{"status":"ok","service":"vdpi","dns_addr":"{active_secret}"}}"#);
        let redacted_health = redact_health_body_for_display(&raw_health);
        assert!(!redacted_health.contains("privtoken42"));
        assert!(redacted_health.contains(&expected_active));
    }

    #[test]
    fn service_command_sudo_card_and_live_doh_redact_and_guard_doh_urls() {
        let secret_url = "https://dns.nextdns.io/secret987654/work-laptop?token=xyz";
        let raw_cmd = format!(
            r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --tun --dns {secret_url} --quiet"#
        );
        let redacted_cmd = format_service_command_for_display(&raw_cmd);
        assert!(redacted_cmd.contains("https://dns.nextdns.io"));
        assert!(!redacted_cmd.contains("secret987654"));
        assert!(!redacted_cmd.contains("work-laptop"));
        assert!(!redacted_cmd.contains("token=xyz"));
        assert!(redacted_cmd.contains("--service --tun --dns"));

        let quoted_cmd = format!(
            r#""C:\Program Files\vdpi\bin\vdpi.exe" --service --tun --dns "{secret_url}" --quiet"#
        );
        let redacted_quoted = format_service_command_for_display(&quoted_cmd);
        assert!(redacted_quoted.contains("\"https://dns.nextdns.io\""));
        assert!(!redacted_quoted.contains("secret987654"));

        // Sudo prompt card must also strip any embedded URL secret path/query.
        let card = format_unix_sudo_prompt_card(
            &format!("update the Linux background service DNS server to {secret_url}"),
            false,
            true,
        );
        assert!(card.contains("https://dns.nextdns.io"));
        assert!(!card.contains("secret987654"));
        assert!(!card.contains("token=xyz"));

        // Guard live.doh via effective_enable_doh even if a daemon reports doh=false with a DoH URL.
        let live = LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(false),
            dns_addr: Some("https://dns.nextdns.io/privtoken99".to_string()),
            block_quic: Some(true),
            active_connections: None,
            total_connections: None,
            learned_hosts: None,
            isp_stage: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        };
        assert_eq!(effective_live_doh(&live, "1.1.1.1"), Some(true));
        let split = vdpi_core::config::SplitTunnelConfig::default();
        let json = build_status_json_payload(
            ServiceState::Running,
            EngineMode::Proxy,
            "1.1.1.1",
            None,
            &split,
            Some(&live),
        );
        assert_eq!(json["live"]["doh"].as_bool(), Some(true));
        assert!(!serde_json::to_string(&json).unwrap().contains("privtoken99"));
    }

    #[test]
    fn gnome_with_kioslaverc_does_not_trigger_false_positive_kde_drift() {
        // Non-empty non-KDE XDG_CURRENT_DESKTOP must skip KDE even when kioslaverc exists.
        assert!(!should_check_kde_proxy_drift(Some("GNOME"), true));
        assert!(!should_check_kde_proxy_drift(Some("ubuntu:GNOME"), true));
        assert!(!should_check_kde_proxy_drift(Some("Hyprland"), true));
        // KDE/Plasma desktops and unset desktop with kioslaverc still check KDE.
        assert!(should_check_kde_proxy_drift(Some("KDE"), false));
        assert!(should_check_kde_proxy_drift(Some("plasma"), false));
        assert!(should_check_kde_proxy_drift(None, true));
        assert!(should_check_kde_proxy_drift(Some("  "), true));
        assert!(!should_check_kde_proxy_drift(None, false));

        // Simulate GNOME session where ~/.config/kioslaverc exists (ProxyType=0) from a KDE app:
        // collect_linux_proxy_snapshot skips KDE, so kde_available stays false and drift is None.
        let kde_active = should_check_kde_proxy_drift(Some("ubuntu:GNOME"), true);
        let snap = LinuxProxySnapshot {
            gnome_available: true,
            gnome_mode: Some("'auto'".to_string()),
            gnome_autoconfig_url: Some("'http://127.0.0.1:8080/vdpi.pac'".to_string()),
            kde_available: kde_active,
            kde_proxy_type: kde_active.then(|| "0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            evaluate_linux_proxy_drift(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080, &snap),
            None
        );
    }

    #[test]
    fn load_configured_dns_and_engine_do_not_fall_through_to_stale_user_config() {
        let base = std::env::temp_dir().join(format!(
            "vdpi-r3-non-fallthrough-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("create temp test dir");

        let sys_cfg = base.join("sys-config.toml");
        let user_cfg = base.join("user-config.toml");

        // System config exists with no `dns_addr` and no `engine`; stale user config sets both.
        fs::write(&sys_cfg, "schema_version = 1\nport = 8080\n").expect("write sys config");
        fs::write(
            &user_cfg,
            "schema_version = 1\nengine = \"tun\"\ndns_addr = \"8.8.8.8\"\n",
        )
        .expect("write user config");

        // With system service installed + system config present: must NOT fall through to user config.
        assert_eq!(
            resolve_configured_dns_from_paths(true, &sys_cfg, &user_cfg, "1.1.1.1"),
            "1.1.1.1"
        );
        assert_eq!(
            resolve_configured_engine_from_paths(
                true,
                EngineMode::Proxy,
                &sys_cfg,
                &user_cfg,
                EngineMode::Proxy,
            ),
            EngineMode::Proxy
        );

        // When system config explicitly sets dns_addr, use it.
        fs::write(
            &sys_cfg,
            "schema_version = 1\nengine = \"proxy\"\ndns_addr = \"9.9.9.9\"\n",
        )
        .expect("update sys config");
        assert_eq!(
            resolve_configured_dns_from_paths(true, &sys_cfg, &user_cfg, "1.1.1.1"),
            "9.9.9.9"
        );
        assert_eq!(
            resolve_configured_engine_from_paths(
                true,
                EngineMode::Tun,
                &sys_cfg,
                &user_cfg,
                EngineMode::Tun,
            ),
            EngineMode::Proxy
        );

        // With system service installed + system config missing: must STILL NOT fall through to user config.
        let missing_sys_cfg = base.join("missing-sys-config.toml");
        assert_eq!(
            resolve_configured_dns_from_paths(true, &missing_sys_cfg, &user_cfg, "1.1.1.1"),
            "1.1.1.1"
        );
        assert_eq!(
            resolve_configured_engine_from_paths(
                true,
                EngineMode::Proxy,
                &missing_sys_cfg,
                &user_cfg,
                EngineMode::Proxy,
            ),
            EngineMode::Proxy
        );

        // Without system service installed, user config takes precedence as before.
        assert_eq!(
            resolve_configured_dns_from_paths(false, &sys_cfg, &user_cfg, "1.1.1.1"),
            "8.8.8.8"
        );
        assert_eq!(
            resolve_configured_engine_from_paths(
                false,
                EngineMode::Proxy,
                &sys_cfg,
                &user_cfg,
                EngineMode::Proxy,
            ),
            EngineMode::Tun
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn doctor_windows_hygiene_wintun_copy_and_vpn_yield_drift() {
        // Stale ALL_PROXY and WinHTTP loopback proxies are caught when stopped.
        assert!(evaluate_windows_stale_proxy_when_stopped_full(
            false,
            "",
            None,
            None,
            None,
            Some("socks5://127.0.0.1:1080"),
            None,
        )
        .expect("stale ALL_PROXY must be flagged")
        .contains("ALL_PROXY"));

        assert!(evaluate_windows_stale_proxy_when_stopped_full(
            false,
            "",
            None,
            None,
            None,
            None,
            Some("http=127.0.0.1:8080;https=127.0.0.1:8080"),
        )
        .expect("stale WinHTTP proxy must be flagged")
        .contains("WinHTTP"));

        assert_eq!(
            parse_winhttp_proxy_server_output(
                "Current WinHTTP proxy settings:\n\n    Proxy Server(s) :  127.0.0.1:8080\n    Bypass List     :  <local>\n"
            ),
            Some("127.0.0.1:8080".to_string())
        );

        // Clean Wintun doctor copy must not leak internal cache paths.
        let raw_err = r"wintun.dll (v0.14.1) not found beside vdpi executable or runtime cache (checked: C:\ProgramData\vdpi\runtime\wintun-0.14.1.dll, C:\Users\u\AppData\Local\vdpi\runtime\wintun-0.14.1.dll)";
        let clean = format_doctor_wintun_error(raw_err);
        assert!(clean.contains("Extract all files from the zip (keep wintun.dll beside vdpi.exe)."));
        assert!(!clean.contains("ProgramData"));
        assert!(!clean.contains("AppData"));

        // Live proxy drift check is skipped when yielded to a full-tunnel VPN under auto-yield.
        let full_vpn = VpnScope::FullTunnel {
            provider: "WireGuard".to_string(),
            iface: "wg0".to_string(),
            kill_switch: false,
        };
        assert!(should_skip_live_proxy_drift_for_vpn(
            VpnCoexistence::AutoYield,
            Some("WireGuard (wg0)"),
            &VpnScope::None,
        ));
        assert!(should_skip_live_proxy_drift_for_vpn(
            VpnCoexistence::AutoYield,
            None,
            &full_vpn,
        ));
        assert!(!should_skip_live_proxy_drift_for_vpn(
            VpnCoexistence::Warn,
            Some("WireGuard (wg0)"),
            &full_vpn,
        ));
        assert!(!should_skip_live_proxy_drift_for_vpn(
            VpnCoexistence::Off,
            None,
            &full_vpn,
        ));
        assert!(!should_skip_live_proxy_drift_for_vpn(
            VpnCoexistence::AutoYield,
            None,
            &VpnScope::None,
        ));
    }

    #[test]
    fn round4_windows_delayed_cleanup_allowlist_and_pause_elevation_and_wintun_wording() {
        let pf_root = Path::new(r"C:\Program Files\vdpi");
        assert!(is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\Program Files\vdpi"),
            pf_root
        ));
        assert!(is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"c:\program files\vdpi\bin"),
            pf_root
        ));
        assert!(is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:/Program Files/vdpi/bin/"),
            pf_root
        ));
        // Never allow user-writable %LOCALAPPDATA%, parent traversals, or shell metacharacters.
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\Users\alice\AppData\Local\vdpi"),
            pf_root
        ));
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\Users\alice\AppData\Local\vdpi\bin"),
            pf_root
        ));
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\Program Files\vdpi\..\Windows"),
            pf_root
        ));
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\Program Files\vdpi\logs"),
            pf_root
        ));
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r"C:\ProgramData\vdpi"),
            pf_root
        ));
        assert!(!is_allowed_delayed_windows_cleanup_dir(
            Path::new(r#"C:\Program Files\vdpi&whoami"#),
            pf_root
        ));

        // Pause auto-elevation without service triggers on loopback WinHTTP or orphan TUN when unelevated.
        assert!(needs_windows_pause_elevation_without_service(
            false, true, false
        ));
        assert!(needs_windows_pause_elevation_without_service(
            true, false, false
        ));
        assert!(!needs_windows_pause_elevation_without_service(
            false, false, false
        ));
        assert!(!needs_windows_pause_elevation_without_service(
            true, true, true
        ));

        // Corrupted/mismatched wintun.dll doctor wording.
        let sha_err = format_doctor_wintun_error(
            r"wintun.dll SHA-256 verification failed for C:\Program Files\vdpi\bin\wintun.dll",
        );
        assert!(sha_err.contains("corrupted or mismatched"));
        assert!(!sha_err.contains("Program Files"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round4_windows_programdata_sddl_has_admin_owner_and_wintun_preflight_recovers_with_sibling()
    {
        assert!(win_fs_hardening::PROGRAMDATA_DIR_SDDL.starts_with("O:BAD:P"));
        assert!(win_fs_hardening::PROGRAMDATA_FILE_SDDL.starts_with("O:BAD:P"));

        let dir_sd = win_fs_hardening::ParsedHardenedSd::from_sddl(
            win_fs_hardening::PROGRAMDATA_DIR_SDDL,
        )
        .expect("parse hardened dir SDDL with O:BA");
        assert!(!dir_sd.as_owner_ptr().is_null());
        assert!(!dir_sd.as_dacl_ptr().is_null());

        let file_sd = win_fs_hardening::ParsedHardenedSd::from_sddl(
            win_fs_hardening::PROGRAMDATA_FILE_SDDL,
        )
        .expect("parse hardened file SDDL with O:BA");
        assert!(!file_sd.as_owner_ptr().is_null());
        assert!(!file_sd.as_dacl_ptr().is_null());

        // Corrupted installed wintun.dll must recover when a verified sibling exists next to current_exe.
        let base = std::env::temp_dir().join(format!(
            "vdpi-r4-wintun-preflight-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let installed_bin = base.join("installed");
        let fresh_bundle = base.join("fresh");
        let missing_bundle = base.join("missing");
        fs::create_dir_all(&installed_bin).expect("create installed dir");
        fs::create_dir_all(&fresh_bundle).expect("create fresh bundle dir");
        fs::create_dir_all(&missing_bundle).expect("create missing bundle dir");

        // SHA-256("abc") per FIPS 180-4.
        const ABC_SHA256: &str =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        fs::write(installed_bin.join("wintun.dll"), b"corrupted-bytes")
            .expect("write corrupted installed wintun");
        let fresh_exe = fresh_bundle.join("vdpi.exe");
        let fresh_wintun = fresh_bundle.join("wintun.dll");
        fs::write(&fresh_exe, b"exe").expect("write dummy exe");
        fs::write(&fresh_wintun, b"abc").expect("write valid sibling wintun");

        let recovered = preflight_windows_tun_wintun_with_exe(
            Some(&installed_bin),
            Some(&fresh_exe),
            ABC_SHA256,
            "reinstall vdpi in TUN mode",
        )
        .expect("valid sibling wintun.dll must break corrupted installed deadlock");
        assert_eq!(recovered, fresh_wintun);

        let no_sibling_exe = missing_bundle.join("vdpi.exe");
        fs::write(&no_sibling_exe, b"exe").expect("write dummy exe without sibling");
        let err = preflight_windows_tun_wintun_with_exe(
            Some(&installed_bin),
            Some(&no_sibling_exe),
            ABC_SHA256,
            "reinstall vdpi in TUN mode",
        )
        .expect_err("corrupted installed wintun with no valid sibling must fail");
        let err_msg = err.to_string();
        assert!(err_msg.contains(
            "corrupted or mismatched — extract all files from the zip (keep wintun.dll beside vdpi.exe)"
        ));
        assert!(!err_msg.contains("failed SHA-256 verification"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn round4_linux_tun_artifacts_doh_target_resume_errors_and_status_config_override() {
        // Real Linux TUN crash-recovery artifacts (no bogus /var/lib/vdpi/tun-state.json).
        for expected in [
            "/sys/class/net/vdpi0",
            "/run/vdpi/tun-state.json",
            "/var/lib/vdpi/resolv.conf.orig",
            "/var/lib/vdpi/resolv-meta.json",
            "/run/NetworkManager/conf.d/99-vdpi-dns.conf",
        ] {
            assert!(
                LINUX_TUN_ARTIFACT_PATHS.contains(&expected),
                "missing real Linux TUN artifact {expected}"
            );
        }
        assert!(!LINUX_TUN_ARTIFACT_PATHS.contains(&"/var/lib/vdpi/tun-state.json"));

        let base = std::env::temp_dir().join(format!(
            "vdpi-r4-polish-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).expect("create temp test dir");

        let a1 = base.join("tun-state.json");
        let a2 = base.join("99-vdpi-dns.conf");
        assert!(!has_linux_tun_artifacts_in(&[a1.as_path(), a2.as_path()]));
        fs::write(&a2, b"[main]\ndns=none\n").expect("write artifact");
        assert!(has_linux_tun_artifacts_in(&[a1.as_path(), a2.as_path()]));

        // effective_live_doh uses is_effective_doh_target: bare custom non-DoH IPs report false.
        let mut live = LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            dns_addr: Some("10.0.0.53".to_string()),
            block_quic: Some(true),
            active_connections: None,
            total_connections: None,
            learned_hosts: None,
            isp_stage: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        };
        assert_eq!(effective_live_doh(&live, "1.1.1.1"), Some(false));
        live.dns_addr = Some("1.1.1.1".to_string());
        assert_eq!(effective_live_doh(&live, "10.0.0.53"), Some(true));
        live.doh = Some(false);
        live.dns_addr = Some("https://dns.nextdns.io/privtoken99".to_string());
        assert_eq!(effective_live_doh(&live, "10.0.0.53"), Some(true));

        // redact_urls_in_text delegates cleanly to vdpi_core::dns::redact_urls_in_text.
        assert_eq!(
            redact_urls_in_text("using https://dns.nextdns.io/secret123/device?k=v."),
            "using https://dns.nextdns.io."
        );

        // Resume config loader surfaces invalid TOML errors instead of swallowing them.
        let bad_cfg = base.join("bad-config.toml");
        fs::write(&bad_cfg, "engine = [not valid toml\n").expect("write invalid config");
        assert!(load_resume_file_config(&bad_cfg, false).is_err());
        let missing_cfg = base.join("does-not-exist.toml");
        assert!(load_resume_file_config(&missing_cfg, false)
            .expect("missing config returns Ok(None)")
            .is_none());
        let good_cfg = base.join("good-config.toml");
        fs::write(&good_cfg, "schema_version = 1\nengine = \"tun\"\n")
            .expect("write valid config");
        assert_eq!(
            load_resume_file_config(&good_cfg, true)
                .expect("valid config loads")
                .and_then(|fc| fc.engine),
            Some(EngineMode::Tun)
        );
        assert_eq!(linux_resume_systemctl_action(true), "restart");
        assert_eq!(linux_resume_systemctl_action(false), "start");

        // Explicit --config status resolution honors cfg directly instead of probing default files.
        let custom_cfg = RuntimeConfig {
            engine: EngineMode::Tun,
            dns_addr: "76.76.2.0".to_string(),
            split_tunnel: vdpi_core::config::SplitTunnelConfig {
                mode: vdpi_core::config::SplitTunnelMode::Exclude,
                apps: vec!["discord".to_string()],
            },
            ..RuntimeConfig::default()
        };
        let explicit = Path::new("custom.toml");
        assert_eq!(
            resolve_status_configured_engine_and_dns(&custom_cfg, Some(explicit)),
            (EngineMode::Tun, "76.76.2.0".to_string())
        );
        assert_eq!(
            resolve_status_configured_split_tunnel(&custom_cfg, Some(explicit)),
            custom_cfg.split_tunnel
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[cfg(unix)]
    #[test]
    fn round4_unix_symlink_deletion_guard_and_atomic_0600_runtime_state() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let base = std::env::temp_dir().join(format!(
            "vdpi-r4-unix-hardening-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let fake_home = base.join("home");
        let outside = base.join("outside");
        fs::create_dir_all(&fake_home).expect("create fake home");
        fs::create_dir_all(&outside).expect("create outside dir");
        let sentinel = outside.join("keep.txt");
        fs::write(&sentinel, b"do-not-delete").expect("write sentinel");

        // Symlink at `~/.vdpi` pointing outside user home must be rejected by both guards.
        let symlinked_root = fake_home.join(".vdpi");
        symlink(&outside, &symlinked_root).expect("create symlink root");
        assert!(ensure_no_symlink_under_base(&fake_home, &symlinked_root).is_err());
        assert!(ensure_no_symlink_under_base(&fake_home, &symlinked_root.join("bin")).is_err());
        cleanup_unix_root_dir_with_home(
            Some(&fake_home),
            &symlinked_root,
            &symlinked_root.join("config.toml"),
            true,
        );
        assert!(
            sentinel.is_file(),
            "cleanup_unix_root_dir_with_home must never delete through symlinked root"
        );

        // Atomic Unix runtime state write creates 0o600 file and rejects symlink target.
        let state_dir = base.join("state");
        let state_path = state_dir.join("state.json");
        write_unix_runtime_state_atomically(&state_path, br#"{"pid":1}"#)
            .expect("write unix runtime state atomically");
        let mode = fs::symlink_metadata(&state_path)
            .expect("stat state.json")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            fs::read_to_string(&state_path).expect("read state.json"),
            r#"{"pid":1}"#
        );

        // Overwriting atomically works and leaves no temp files behind.
        write_unix_runtime_state_atomically(&state_path, br#"{"pid":2}"#)
            .expect("overwrite unix runtime state atomically");
        assert_eq!(
            fs::read_to_string(&state_path).expect("read updated state.json"),
            r#"{"pid":2}"#
        );
        let leftover_tmps = fs::read_dir(&state_dir)
            .expect("read state dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftover_tmps, 0);

        let symlink_state = state_dir.join("link-state.json");
        symlink(&sentinel, &symlink_state).expect("create symlink state");
        assert!(write_unix_runtime_state_atomically(&symlink_state, br#"{"pid":3}"#).is_err());
        assert_eq!(
            fs::read_to_string(&sentinel).expect("sentinel unchanged"),
            "do-not-delete"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn round5_ensure_no_symlink_rejects_parent_dir_traversal() {
        let base = std::env::temp_dir().join(format!(
            "vdpi-r5-parent-dir-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join(".vdpi")).expect("create temp base dir");

        // Any `..` (Component::ParentDir) must be rejected before starts_with / symlink_metadata.
        assert!(
            ensure_no_symlink_under_base(Path::new("/home/user"), Path::new("/home/user/../../etc"))
                .is_err()
        );
        assert!(ensure_no_symlink_under_base(
            Path::new("/home/user"),
            Path::new("/home/user/.vdpi/../.ssh/authorized_keys"),
        )
        .is_err());
        assert!(ensure_no_symlink_under_base(
            Path::new("/home/user"),
            Path::new("/other/../etc/passwd"),
        )
        .is_err());
        assert!(ensure_no_symlink_under_base(&base, &base.join("..").join("outside")).is_err());

        // Clean paths under base_dir without `..` or symlinks succeed.
        assert!(ensure_no_symlink_under_base(&base, &base.join(".vdpi").join("config.toml")).is_ok());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn round5_winhttp_space_separated_mixed_proxy_detection() {
        assert!(is_loopback_winhttp_proxy(
            "http=10.0.0.1:8080 https=127.0.0.1:8080"
        ));
        assert!(is_loopback_winhttp_proxy(
            "http=proxy.corp.local:3128 https=[::1]:8080"
        ));
        assert!(is_loopback_winhttp_proxy(
            "http=10.0.0.1:8080\thttps=localhost:8080"
        ));
        assert!(is_loopback_winhttp_proxy(
            "http=10.0.0.1:8080;https=127.0.0.1:8080"
        ));
        assert!(!is_loopback_winhttp_proxy(
            "http=10.0.0.1:8080 https=10.0.0.2:8443"
        ));
        assert!(!is_loopback_winhttp_proxy(
            "http=proxy.corp.local:3128;https=proxy2.corp.local:8443"
        ));
        assert!(!is_loopback_winhttp_proxy(""));

        assert!(evaluate_windows_stale_proxy_when_stopped_full(
            false,
            "",
            None,
            None,
            None,
            None,
            Some("http=10.0.0.1:8080 https=127.0.0.1:8080"),
        )
        .expect("space-separated mixed loopback WinHTTP proxy must be flagged")
        .contains("WinHTTP"));
        assert!(evaluate_windows_stale_proxy_when_stopped_full(
            false,
            "",
            None,
            None,
            None,
            None,
            Some("http=10.0.0.1:8080 https=10.0.0.2:8443"),
        )
        .is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn round5_windows_programdata_case_insensitive_and_child_hardening() {
        let pd = Path::new(r"C:\ProgramData\vdpi");
        assert!(win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"c:\programdata\vdpi"),
            pd
        ));
        assert!(win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"C:\PROGRAMDATA\VDPI\runtime"),
            pd
        ));
        assert!(win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"C:/ProgramData/vdpi/"),
            pd
        ));
        assert!(win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"\\?\c:\ProgramData\VDPI"),
            pd
        ));
        assert!(!win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"C:\ProgramData\vdpi2"),
            pd
        ));
        assert!(!win_fs_hardening::is_path_under_dir_ascii_ci(
            Path::new(r"C:\ProgramData\vdpi\..\Windows"),
            pd
        ));

        let base = std::env::temp_dir().join(format!(
            "vdpi-r5-win-dacl-children-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("sub")).expect("create test dir and subdir");
        fs::write(base.join("state.json"), b"{}").expect("write state.json");
        fs::write(base.join("config.toml"), b"schema_version = 1\n").expect("write config.toml");
        fs::write(base.join("proxy-state.json"), b"{}").expect("write proxy-state.json");

        win_fs_hardening::apply_hardened_dir_dacl(&base)
            .expect("apply_hardened_dir_dacl must harden all direct non-reparse child files");

        let _ = fs::remove_dir_all(&base);
    }
}
