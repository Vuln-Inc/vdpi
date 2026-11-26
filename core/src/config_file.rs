use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;
use vdpi_core::config::{
    normalize_split_app_name, DesyncMode, EngineMode, RuntimeConfig, SplitTunnelMode,
    VpnCoexistence,
};

/// Current `config.toml` schema version.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Maximum number of per-application split-tunnel entries persisted or applied.
pub const MAX_SPLIT_TUNNEL_APPS: usize = 256;

const MAX_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const MAX_ARRAY_DEPTH: usize = 8;

static ATOMIC_SAVE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Persistent user/system configuration loaded from `config.toml`.
///
/// Every field is optional so omitted entries fall back to built-in defaults
/// and CLI flags can layer cleanly on top.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub schema_version: Option<u32>,
    pub engine: Option<EngineMode>,
    pub mode: Option<DesyncMode>,
    pub doh: Option<bool>,
    pub block_quic: Option<bool>,
    pub dns_addr: Option<String>,
    pub bypass_domains: Option<Vec<String>>,
    pub include_domains: Option<Vec<String>>,
    pub split_tunnel_mode: Option<SplitTunnelMode>,
    pub split_tunnel_apps: Option<Vec<String>>,
    pub vpn_coexistence: Option<VpnCoexistence>,
    pub tun_ipv6: Option<bool>,
    pub chunk_size: Option<usize>,
    pub bind: Option<IpAddr>,
    pub port: Option<u16>,
    pub socks_port: Option<u16>,
    pub dns_port: Option<u16>,
    pub ipv4_only: Option<bool>,
    pub timeout_ms: Option<u64>,
    pub system_proxy: Option<bool>,
    pub socks_system_proxy: Option<bool>,
    pub env_proxy: Option<bool>,
}

impl FileConfig {
    /// Merges `overlay` on top of `self`, returning a new [`FileConfig`] where
    /// any `Some` field in `overlay` takes precedence over `self`.
    pub fn merge(&self, overlay: &FileConfig) -> FileConfig {
        FileConfig {
            schema_version: overlay.schema_version.or(self.schema_version),
            engine: overlay.engine.or(self.engine),
            mode: overlay.mode.or(self.mode),
            doh: overlay.doh.or(self.doh),
            block_quic: overlay.block_quic.or(self.block_quic),
            dns_addr: overlay.dns_addr.clone().or_else(|| self.dns_addr.clone()),
            bypass_domains: overlay
                .bypass_domains
                .clone()
                .or_else(|| self.bypass_domains.clone()),
            include_domains: overlay
                .include_domains
                .clone()
                .or_else(|| self.include_domains.clone()),
            split_tunnel_mode: overlay.split_tunnel_mode.or(self.split_tunnel_mode),
            split_tunnel_apps: overlay
                .split_tunnel_apps
                .clone()
                .or_else(|| self.split_tunnel_apps.clone()),
            vpn_coexistence: overlay.vpn_coexistence.or(self.vpn_coexistence),
            tun_ipv6: overlay.tun_ipv6.or(self.tun_ipv6),
            chunk_size: overlay.chunk_size.or(self.chunk_size),
            bind: overlay.bind.or(self.bind),
            port: overlay.port.or(self.port),
            socks_port: overlay.socks_port.or(self.socks_port),
            dns_port: overlay.dns_port.or(self.dns_port),
            ipv4_only: overlay.ipv4_only.or(self.ipv4_only),
            timeout_ms: overlay.timeout_ms.or(self.timeout_ms),
            system_proxy: overlay.system_proxy.or(self.system_proxy),
            socks_system_proxy: overlay.socks_system_proxy.or(self.socks_system_proxy),
            env_proxy: overlay.env_proxy.or(self.env_proxy),
        }
    }

    /// Applies every `Some` field from `self` onto `runtime`, leaving unset
    /// (`None`) fields untouched.
    pub fn apply_to_runtime(&self, runtime: &mut RuntimeConfig) {
        if let Some(engine) = self.engine {
            runtime.engine = engine;
        }
        if let Some(mode) = self.mode {
            runtime.mode = mode;
        }
        if let Some(doh) = self.doh {
            runtime.enable_doh = doh;
        }
        if let Some(block_quic) = self.block_quic {
            runtime.block_quic = block_quic;
        }
        if let Some(ref dns_addr) = self.dns_addr {
            if let Ok(validated) = vdpi_core::dns::validate_custom_dns_input(dns_addr) {
                runtime.dns_addr = validated;
            }
        }
        if let Some(ref domains) = self.bypass_domains {
            runtime.bypass_domains = domains.clone();
        }
        if let Some(ref domains) = self.include_domains {
            runtime.patterns = domains.clone();
        }
        if let Some(mode) = self.split_tunnel_mode {
            runtime.split_tunnel.mode = mode;
        }
        if let Some(ref apps) = self.split_tunnel_apps {
            runtime.split_tunnel.apps = sanitize_split_tunnel_apps(apps);
        }
        if let Some(coex) = self.vpn_coexistence {
            runtime.vpn_coexistence = coex;
        }
        if let Some(tun_ipv6) = self.tun_ipv6 {
            runtime.tun_ipv6 = tun_ipv6;
        }
        if let Some(chunk_size) = self.chunk_size {
            runtime.chunk_size = chunk_size.max(1);
        }
        if let Some(bind) = self.bind {
            runtime.addr = bind;
        }
        if let Some(port) = self.port {
            runtime.port = port;
            if runtime.socks_port == Some(port) {
                runtime.socks_port = None;
            }
        }
        if let Some(socks_port) = self.socks_port {
            runtime.socks_port = if socks_port == 0 || socks_port == runtime.port {
                None
            } else {
                Some(socks_port)
            };
        }
        if let Some(dns_port) = self.dns_port {
            runtime.dns_port = dns_port;
        }
        if let Some(ipv4_only) = self.ipv4_only {
            runtime.dns_ipv4_only = ipv4_only;
        }
        if let Some(timeout_ms) = self.timeout_ms {
            runtime.connect_timeout = if timeout_ms == 0 {
                Duration::from_millis(8000)
            } else {
                Duration::from_millis(timeout_ms)
            };
        }
        if let Some(system_proxy) = self.system_proxy {
            runtime.system_proxy = system_proxy;
        }
        if let Some(socks_system_proxy) = self.socks_system_proxy {
            runtime.socks_system_proxy =
                runtime.system_proxy && socks_system_proxy && runtime.socks_port.is_some();
        } else if self.system_proxy.is_some() || self.socks_port.is_some() || self.port.is_some() {
            runtime.socks_system_proxy =
                runtime.system_proxy && runtime.socks_system_proxy && runtime.socks_port.is_some();
        }
        if let Some(env_proxy) = self.env_proxy {
            runtime.env_proxy = runtime.system_proxy && env_proxy;
        } else if self.system_proxy.is_some() {
            runtime.env_proxy = runtime.system_proxy && runtime.env_proxy;
        }
    }
}

/// Returns the OS-standard machine-wide `config.toml` path.
pub fn system_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows_system_config_path(std::env::var_os("ProgramData").as_deref())
    }
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/Library/Application Support/vdpi/config.toml")
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        PathBuf::from("/etc/vdpi/config.toml")
    }
}

/// Returns the OS-standard per-user `config.toml` path.
pub fn user_config_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows_user_config_path(
            std::env::var_os("LOCALAPPDATA").as_deref(),
            std::env::var_os("USERPROFILE").as_deref(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        macos_user_config_path(std::env::var_os("HOME").as_deref())
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        linux_user_config_path(
            std::env::var_os("XDG_CONFIG_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )
    }
}

#[cfg(any(target_os = "windows", test))]
fn is_windows_abs(v: &OsStr) -> bool {
    let bytes = v.as_encoded_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || bytes.starts_with(br"\\")
        || bytes.starts_with(b"//")
}

#[cfg(any(not(target_os = "windows"), test))]
fn is_unix_abs(v: &OsStr) -> bool {
    v.as_encoded_bytes().starts_with(b"/")
}

#[cfg(any(target_os = "windows", test))]
fn windows_system_config_path(program_data: Option<&OsStr>) -> PathBuf {
    let base = program_data
        .filter(|v| is_windows_abs(v))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("vdpi").join("config.toml")
}

#[cfg(any(target_os = "windows", test))]
fn windows_user_config_path(
    local_appdata: Option<&OsStr>,
    user_profile: Option<&OsStr>,
) -> PathBuf {
    if let Some(dir) = local_appdata.filter(|v| is_windows_abs(v)) {
        return PathBuf::from(dir).join("vdpi").join("config.toml");
    }
    if let Some(profile) = user_profile.filter(|v| is_windows_abs(v)) {
        return PathBuf::from(profile)
            .join("AppData")
            .join("Local")
            .join("vdpi")
            .join("config.toml");
    }
    windows_system_config_path(None)
}

#[cfg(any(target_os = "macos", test))]
fn macos_user_config_path(home: Option<&OsStr>) -> PathBuf {
    if let Some(home) = home.filter(|v| is_unix_abs(v)) {
        return PathBuf::from(home).join(".vdpi").join("config.toml");
    }
    PathBuf::from("/Library/Application Support/vdpi/config.toml")
}

#[cfg(any(not(any(target_os = "windows", target_os = "macos")), test))]
fn linux_user_config_path(xdg_config_home: Option<&OsStr>, home: Option<&OsStr>) -> PathBuf {
    if let Some(xdg) = xdg_config_home.filter(|v| is_unix_abs(v)) {
        return PathBuf::from(xdg).join("vdpi").join("config.toml");
    }
    if let Some(home) = home.filter(|v| is_unix_abs(v)) {
        return PathBuf::from(home)
            .join(".config")
            .join("vdpi")
            .join("config.toml");
    }
    PathBuf::from("/etc/vdpi/config.toml")
}

fn candidate_config_paths(service_mode: bool) -> Vec<PathBuf> {
    if service_mode {
        // On Windows, `LocalSystem` services must only read the admin-protected
        // `%ProgramData%\vdpi\config.toml` path and never user-writable paths.
        #[cfg(target_os = "windows")]
        {
            vec![system_config_path()]
        }
        #[cfg(not(target_os = "windows"))]
        {
            vec![system_config_path(), user_config_path()]
        }
    } else {
        vec![user_config_path(), system_config_path()]
    }
}

/// Loads `FileConfig` from `explicit_path` or the OS-appropriate config path.
///
/// When `explicit_path` is `Some(path)`, returns an error if the requested file
/// does not exist rather than silently falling back to defaults.
/// In `service_mode` on Windows, only [`system_config_path`] is consulted when
/// `explicit_path` is `None` so `LocalSystem` never reads user-writable files.
/// Returns `(None, FileConfig::default())` when `explicit_path` is `None` and
/// no default config file exists.
pub fn load_file_config(
    explicit_path: Option<&Path>,
    service_mode: bool,
) -> Result<(Option<PathBuf>, FileConfig)> {
    if let Some(path) = explicit_path {
        let Some(contents) = read_bounded_config_file(path)? else {
            bail!("config file does not exist: {}", path.display());
        };
        let cfg = parse_config_toml(&contents)
            .with_context(|| format!("failed to parse config file {}", path.display()))?;
        return Ok((Some(path.to_path_buf()), cfg));
    }

    for path in candidate_config_paths(service_mode) {
        if let Some(contents) = read_bounded_config_file(&path)? {
            let cfg = parse_config_toml(&contents)
                .with_context(|| format!("failed to parse config file {}", path.display()))?;
            return Ok((Some(path), cfg));
        }
    }

    Ok((None, FileConfig::default()))
}

/// Loads `FileConfig` from `explicit_path` or the OS-appropriate config path,
/// returning `(None, FileConfig::default())` if the target file does not yet exist.
///
/// Intended for mutating commands such as `config set` and `config unset` that
/// may create a brand-new configuration file at `explicit_path`.
pub fn load_file_config_or_default(
    explicit_path: Option<&Path>,
    service_mode: bool,
) -> Result<(Option<PathBuf>, FileConfig)> {
    let candidates = match explicit_path {
        Some(path) => vec![path.to_path_buf()],
        None => candidate_config_paths(service_mode),
    };

    for path in candidates {
        if let Some(contents) = read_bounded_config_file(&path)? {
            let cfg = parse_config_toml(&contents)
                .with_context(|| format!("failed to parse config file {}", path.display()))?;
            return Ok((Some(path), cfg));
        }
    }

    Ok((None, FileConfig::default()))
}

fn read_bounded_config_file(path: &Path) -> Result<Option<String>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("failed to open config file {}", path.display()));
        }
    };

    let mut buf = Vec::new();
    file.take(MAX_CONFIG_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    if (buf.len() as u64) > MAX_CONFIG_FILE_BYTES {
        bail!(
            "config file {} exceeds maximum allowed size of {} bytes",
            path.display(),
            MAX_CONFIG_FILE_BYTES
        );
    }

    let text = String::from_utf8(buf)
        .with_context(|| format!("config file {} is not valid UTF-8", path.display()))?;
    Ok(Some(text))
}

/// Atomically persists `cfg` to `path` as canonical flat TOML.
///
/// Creates parent directories as needed, writes to a unique sibling
/// `.config.toml.tmp.<pid>.<seq>` file opened exclusively with `create_new`,
/// calls `sync_all()`, and atomically replaces the target via
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`
/// on Windows or `fs::rename` on Unix.
pub fn save_file_config_atomic(path: &Path, cfg: &FileConfig) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create config directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|n| !n.is_empty())
        .unwrap_or("config.toml");
    let pid = std::process::id();
    let rendered = render_config_toml(cfg);

    let mut created = None;
    for _ in 0..16 {
        let seq = ATOMIC_SAVE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".{file_name}.tmp.{pid}.{seq}"));
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
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

    let write_res = (|| -> Result<()> {
        file.write_all(rendered.as_bytes())
            .with_context(|| format!("failed to write temporary file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary file {}", tmp_path.display()))?;
        Ok(())
    })();
    drop(file);

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = atomic_replace(&tmp_path, path) {
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

#[cfg(windows)]
fn atomic_replace(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            lp_existing_file_name: *const u16,
            lp_new_file_name: *const u16,
            dw_flags: u32,
        ) -> i32;
    }

    let src_w: Vec<u16> = src
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let dst_w: Vec<u16> = dst
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `src_w` and `dst_w` are valid NUL-terminated UTF-16 buffers that
    // remain alive for the entire synchronous `MoveFileExW` call.
    let ok = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(windows))]
fn atomic_replace(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}

/// Sets a single configuration key on `cfg` from a string representation.
///
/// Accepts both `snake_case` and `kebab-case` key names. Array fields
/// (`bypass_domains`, `include_domains`, `split_tunnel_apps`) accept either a
/// TOML array literal (`["a.com", "b.com"]`) or a comma-separated list
/// (`a.com, b.com`).
pub fn set_config_key(cfg: &mut FileConfig, key: &str, value: &str) -> Result<()> {
    let normalized = normalize_key(key);
    let trimmed = value.trim();

    match normalized.as_str() {
        "schema_version" => {
            cfg.schema_version = Some(parse_uint_str::<u32>(trimmed, "schema_version", "u32")?);
        }
        "engine" => {
            cfg.engine = Some(parse_engine_mode(trimmed)?);
        }
        "mode" => {
            cfg.mode = Some(parse_desync_mode(trimmed)?);
        }
        "doh" => {
            cfg.doh = Some(parse_bool_str(trimmed, "doh")?);
        }
        "block_quic" => {
            cfg.block_quic = Some(parse_bool_str(trimmed, "block_quic")?);
        }
        "dns_addr" => {
            let validated = vdpi_core::dns::validate_custom_dns_input(trimmed).map_err(|msg| {
                anyhow::anyhow!("invalid value '{trimmed}' for 'dns_addr': {msg}")
            })?;
            cfg.dns_addr = Some(validated);
        }
        "bypass_domains" => {
            cfg.bypass_domains = Some(parse_string_list_arg(trimmed, "bypass_domains"));
        }
        "include_domains" => {
            cfg.include_domains = Some(parse_string_list_arg(trimmed, "include_domains"));
        }
        "split_tunnel_mode" => {
            cfg.split_tunnel_mode = Some(parse_split_tunnel_mode(trimmed)?);
        }
        "split_tunnel_apps" => {
            let raw = parse_string_list_arg(trimmed, "split_tunnel_apps");
            cfg.split_tunnel_apps = Some(validate_split_tunnel_apps(&raw)?);
        }
        "vpn_coexistence" => {
            cfg.vpn_coexistence = Some(parse_vpn_coexistence(trimmed)?);
        }
        "tun_ipv6" => {
            cfg.tun_ipv6 = Some(parse_bool_str(trimmed, "tun_ipv6")?);
        }
        "chunk_size" => {
            let chunk_size = parse_uint_str::<usize>(trimmed, "chunk_size", "usize")?;
            if chunk_size == 0 {
                bail!("value for 'chunk_size' must be at least 1");
            }
            cfg.chunk_size = Some(chunk_size);
        }
        "bind" => {
            let ip: IpAddr = trimmed
                .parse()
                .with_context(|| format!("invalid IP address '{trimmed}' for 'bind'"))?;
            cfg.bind = Some(ip);
        }
        "port" => {
            cfg.port = Some(parse_uint_str::<u16>(trimmed, "port", "u16")?);
        }
        "socks_port" => {
            cfg.socks_port = Some(parse_uint_str::<u16>(trimmed, "socks_port", "u16")?);
        }
        "dns_port" => {
            cfg.dns_port = Some(parse_uint_str::<u16>(trimmed, "dns_port", "u16")?);
        }
        "ipv4_only" => {
            cfg.ipv4_only = Some(parse_bool_str(trimmed, "ipv4_only")?);
        }
        "timeout_ms" => {
            cfg.timeout_ms = Some(parse_uint_str::<u64>(trimmed, "timeout_ms", "u64")?);
        }
        "system_proxy" => {
            cfg.system_proxy = Some(parse_bool_str(trimmed, "system_proxy")?);
        }
        "socks_system_proxy" => {
            cfg.socks_system_proxy = Some(parse_bool_str(trimmed, "socks_system_proxy")?);
        }
        "env_proxy" => {
            cfg.env_proxy = Some(parse_bool_str(trimmed, "env_proxy")?);
        }
        _ => bail!("unknown config key '{key}'"),
    }

    Ok(())
}

/// Reads a single configuration key from `cfg` formatted as a string,
/// returning `Ok(None)` when the key is valid but unset.
///
/// Accepts both `snake_case` and `kebab-case` key names.
pub fn get_config_key(cfg: &FileConfig, key: &str) -> Result<Option<String>> {
    let normalized = normalize_key(key);

    let value = match normalized.as_str() {
        "schema_version" => cfg.schema_version.map(|v| v.to_string()),
        "engine" => cfg.engine.map(|v| v.as_str().to_string()),
        "mode" => cfg.mode.map(|v| desync_mode_as_str(v).to_string()),
        "doh" => cfg.doh.map(|v| v.to_string()),
        "block_quic" => cfg.block_quic.map(|v| v.to_string()),
        "dns_addr" => cfg.dns_addr.clone(),
        "bypass_domains" => cfg
            .bypass_domains
            .as_deref()
            .map(format_string_array_inline),
        "include_domains" => cfg
            .include_domains
            .as_deref()
            .map(format_string_array_inline),
        "split_tunnel_mode" => cfg.split_tunnel_mode.map(|v| v.as_str().to_string()),
        "split_tunnel_apps" => cfg
            .split_tunnel_apps
            .as_deref()
            .map(format_string_array_inline),
        "vpn_coexistence" => cfg.vpn_coexistence.map(|v| v.as_str().to_string()),
        "tun_ipv6" => cfg.tun_ipv6.map(|v| v.to_string()),
        "chunk_size" => cfg.chunk_size.map(|v| v.to_string()),
        "bind" => cfg.bind.map(|v| v.to_string()),
        "port" => cfg.port.map(|v| v.to_string()),
        "socks_port" => cfg.socks_port.map(|v| v.to_string()),
        "dns_port" => cfg.dns_port.map(|v| v.to_string()),
        "ipv4_only" => cfg.ipv4_only.map(|v| v.to_string()),
        "timeout_ms" => cfg.timeout_ms.map(|v| v.to_string()),
        "system_proxy" => cfg.system_proxy.map(|v| v.to_string()),
        "socks_system_proxy" => cfg.socks_system_proxy.map(|v| v.to_string()),
        "env_proxy" => cfg.env_proxy.map(|v| v.to_string()),
        _ => bail!("unknown config key '{key}'"),
    };

    Ok(value)
}

/// Clears a single configuration key on `cfg` back to `None`.
pub fn unset_config_key(cfg: &mut FileConfig, key: &str) -> Result<()> {
    let normalized = normalize_key(key);

    match normalized.as_str() {
        "schema_version" => cfg.schema_version = None,
        "engine" => cfg.engine = None,
        "mode" => cfg.mode = None,
        "doh" => cfg.doh = None,
        "block_quic" => cfg.block_quic = None,
        "dns_addr" => cfg.dns_addr = None,
        "bypass_domains" => cfg.bypass_domains = None,
        "include_domains" => cfg.include_domains = None,
        "split_tunnel_mode" => cfg.split_tunnel_mode = None,
        "split_tunnel_apps" => cfg.split_tunnel_apps = None,
        "vpn_coexistence" => cfg.vpn_coexistence = None,
        "tun_ipv6" => cfg.tun_ipv6 = None,
        "chunk_size" => cfg.chunk_size = None,
        "bind" => cfg.bind = None,
        "port" => cfg.port = None,
        "socks_port" => cfg.socks_port = None,
        "dns_port" => cfg.dns_port = None,
        "ipv4_only" => cfg.ipv4_only = None,
        "timeout_ms" => cfg.timeout_ms = None,
        "system_proxy" => cfg.system_proxy = None,
        "socks_system_proxy" => cfg.socks_system_proxy = None,
        "env_proxy" => cfg.env_proxy = None,
        _ => bail!("unknown config key '{key}'"),
    }

    Ok(())
}

fn normalize_key(key: &str) -> String {
    key.trim().replace('-', "_")
}

fn parse_bool_str(value: &str, key: &str) -> Result<bool> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        bail!("invalid boolean '{value}' for '{key}' (expected 'true' or 'false')")
    }
}

fn parse_uint_str<T>(value: &str, key: &str, type_name: &str) -> Result<T>
where
    T: TryFrom<i128>,
{
    let Some(parsed) = parse_toml_int(value) else {
        bail!("invalid integer '{value}' for '{key}'");
    };
    T::try_from(parsed)
        .map_err(|_| anyhow::anyhow!("value {parsed} for '{key}' is out of range for {type_name}"))
}

fn try_parse_toml_string_array(value: &str, key: &str) -> Result<Vec<String>> {
    let mut parser = Parser::new(value);
    let arr = parser.parse_array(0)?;
    parser.expect_eol_or_eof()?;
    extract_string_array(arr, 1, key)
}

fn parse_string_list_arg(value: &str, key: &str) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }
    if value.starts_with('[') {
        if let Ok(items) = try_parse_toml_string_array(value, key) {
            return items;
        }
    }
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn format_string_array_inline(items: &[String]) -> String {
    let joined = items
        .iter()
        .map(|s| escape_toml_string(s))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{joined}]")
}

fn parse_engine_mode(value: &str) -> Result<EngineMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "proxy" => Ok(EngineMode::Proxy),
        "tun" => Ok(EngineMode::Tun),
        other => bail!("invalid value '{other}' for 'engine' (expected 'proxy' or 'tun')"),
    }
}

fn parse_desync_mode(value: &str) -> Result<DesyncMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "combo" => Ok(DesyncMode::Combo),
        "tls-record" | "tlsrec" => Ok(DesyncMode::TlsRecord),
        "fragment" | "chunk" => Ok(DesyncMode::Fragment),
        "split" => Ok(DesyncMode::Split),
        other => bail!(
            "invalid value '{other}' for 'mode' (expected 'combo', 'tls-record', 'fragment', or 'split')"
        ),
    }
}

fn parse_vpn_coexistence(value: &str) -> Result<VpnCoexistence> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto-yield" => Ok(VpnCoexistence::AutoYield),
        "warn" => Ok(VpnCoexistence::Warn),
        "off" => Ok(VpnCoexistence::Off),
        other => bail!(
            "invalid value '{other}' for 'vpn_coexistence' (expected 'auto-yield', 'warn', or 'off')"
        ),
    }
}

fn parse_split_tunnel_mode(value: &str) -> Result<SplitTunnelMode> {
    value.parse::<SplitTunnelMode>().map_err(|_| {
        let other = value.trim().to_ascii_lowercase();
        anyhow::anyhow!(
            "invalid value '{other}' for 'split_tunnel_mode' (expected 'all', 'exclude', or 'include')"
        )
    })
}

/// Validates and sanitizes per-application split-tunnel entries.
///
/// Rejects entries containing control characters or newlines, trims whitespace,
/// skips empty/blank entries, deduplicates case-insensitively by normalized
/// executable name (preserving first-seen order), and caps the list at
/// [`MAX_SPLIT_TUNNEL_APPS`].
pub fn validate_split_tunnel_apps(apps: &[String]) -> Result<Vec<String>> {
    if apps.iter().any(|raw| raw.chars().any(char::is_control)) {
        bail!("value for 'split_tunnel_apps' cannot contain control characters or newlines");
    }
    Ok(sanitize_split_tunnel_apps(apps))
}

/// Lossily sanitizes per-application split-tunnel entries for rendering/apply.
///
/// Drops entries containing control characters or newlines, trims whitespace,
/// skips empty/blank entries, deduplicates by normalized executable name
/// (preserving first-seen order), and caps the list at
/// [`MAX_SPLIT_TUNNEL_APPS`].
pub fn sanitize_split_tunnel_apps(apps: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(apps.len().min(MAX_SPLIT_TUNNEL_APPS));
    let mut seen = HashSet::with_capacity(apps.len().min(MAX_SPLIT_TUNNEL_APPS));

    for raw in apps {
        if raw.chars().any(char::is_control) {
            continue;
        }
        let trimmed = raw.trim();
        let key = normalize_split_app_name(trimmed);
        if trimmed.is_empty() || key.is_empty() {
            continue;
        }
        if !seen.insert(key) {
            continue;
        }
        if out.len() >= MAX_SPLIT_TUNNEL_APPS {
            warn!(
                limit = MAX_SPLIT_TUNNEL_APPS,
                "split_tunnel_apps exceeds maximum entries; truncating"
            );
            break;
        }
        out.push(trimmed.to_string());
    }

    out
}

const fn desync_mode_as_str(mode: DesyncMode) -> &'static str {
    match mode {
        DesyncMode::Combo => "combo",
        DesyncMode::TlsRecord => "tls-record",
        DesyncMode::Fragment => "fragment",
        DesyncMode::Split => "split",
    }
}

/// Renders `cfg` into canonical flat TOML format.
pub fn render_config_toml(cfg: &FileConfig) -> String {
    let mut out = String::new();
    out.push_str("# vdpi configuration\n");

    if let Some(v) = cfg.schema_version {
        let _ = writeln!(out, "schema_version = {v}");
    }
    if let Some(engine) = cfg.engine {
        let _ = writeln!(out, "engine = {}", escape_toml_string(engine.as_str()));
    }
    if let Some(mode) = cfg.mode {
        let _ = writeln!(
            out,
            "mode = {}",
            escape_toml_string(desync_mode_as_str(mode))
        );
    }
    if let Some(v) = cfg.doh {
        let _ = writeln!(out, "doh = {v}");
    }
    if let Some(v) = cfg.block_quic {
        let _ = writeln!(out, "block_quic = {v}");
    }
    if let Some(ref dns_addr) = cfg.dns_addr {
        let _ = writeln!(out, "dns_addr = {}", escape_toml_string(dns_addr));
    }
    if let Some(ref domains) = cfg.bypass_domains {
        write_string_array(&mut out, "bypass_domains", domains);
    }
    if let Some(ref domains) = cfg.include_domains {
        write_string_array(&mut out, "include_domains", domains);
    }
    if let Some(split_mode) = cfg.split_tunnel_mode {
        let _ = writeln!(
            out,
            "split_tunnel_mode = {}",
            escape_toml_string(split_mode.as_str())
        );
    }
    if let Some(ref apps) = cfg.split_tunnel_apps {
        let sanitized = sanitize_split_tunnel_apps(apps);
        write_string_array(&mut out, "split_tunnel_apps", &sanitized);
    }
    if let Some(coex) = cfg.vpn_coexistence {
        let _ = writeln!(
            out,
            "vpn_coexistence = {}",
            escape_toml_string(coex.as_str())
        );
    }
    if let Some(v) = cfg.tun_ipv6 {
        let _ = writeln!(out, "tun_ipv6 = {v}");
    }
    if let Some(v) = cfg.chunk_size {
        let _ = writeln!(out, "chunk_size = {v}");
    }
    if let Some(ip) = cfg.bind {
        let _ = writeln!(out, "bind = {}", escape_toml_string(&ip.to_string()));
    }
    if let Some(v) = cfg.port {
        let _ = writeln!(out, "port = {v}");
    }
    if let Some(v) = cfg.socks_port {
        let _ = writeln!(out, "socks_port = {v}");
    }
    if let Some(v) = cfg.dns_port {
        let _ = writeln!(out, "dns_port = {v}");
    }
    if let Some(v) = cfg.ipv4_only {
        let _ = writeln!(out, "ipv4_only = {v}");
    }
    if let Some(v) = cfg.timeout_ms {
        let _ = writeln!(out, "timeout_ms = {v}");
    }
    if let Some(v) = cfg.system_proxy {
        let _ = writeln!(out, "system_proxy = {v}");
    }
    if let Some(v) = cfg.socks_system_proxy {
        let _ = writeln!(out, "socks_system_proxy = {v}");
    }
    if let Some(v) = cfg.env_proxy {
        let _ = writeln!(out, "env_proxy = {v}");
    }

    out
}

fn write_string_array(out: &mut String, key: &str, items: &[String]) {
    match items.len() {
        0 => {
            let _ = writeln!(out, "{key} = []");
        }
        1 => {
            let _ = writeln!(out, "{key} = [{}]", escape_toml_string(&items[0]));
        }
        _ => {
            let _ = writeln!(out, "{key} = [");
            for item in items {
                let _ = writeln!(out, "  {},", escape_toml_string(item));
            }
            out.push_str("]\n");
        }
    }
}

fn escape_toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str(r#"\""#),
            '\x08' => out.push_str(r"\b"),
            '\x0c' => out.push_str(r"\f"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\x00'..='\x1f' | '\x7f' => {
                let _ = write!(out, "\\u{:04X}", ch as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TomlValue {
    Str(String),
    Bool(bool),
    Int(i128),
    Float,
    InlineTable,
    Array(Vec<TomlValue>),
}

/// Parses a flat `config.toml` document into [`FileConfig`].
///
/// Supports `#` comments (full-line and inline outside quotes), `"..."` basic
/// strings (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, `\uXXXX`, `\UXXXXXXXX`),
/// `'...'` literal strings, booleans, integers, floats, inline tables, and
/// single-line or multiline arrays with optional trailing commas.
/// Duplicate normalized keys are rejected with line numbers; unknown keys are
/// logged with `tracing::warn!` and ignored for forward and backward
/// compatibility.
pub fn parse_config_toml(input: &str) -> Result<FileConfig> {
    let mut parser = Parser::new(input);
    let mut cfg = FileConfig::default();
    let mut seen_keys = HashSet::new();

    loop {
        parser.skip_ws_and_comments_multiline();
        if parser.peek().is_none() {
            break;
        }

        let key_line = parser.line;
        let key = parser.parse_key()?;

        parser.skip_ws_inline();
        if parser.peek() != Some('=') {
            bail!("line {key_line}: expected '=' after key '{key}'");
        }
        parser.bump();
        parser.skip_ws_inline();

        if matches!(parser.peek(), None | Some('\n') | Some('\r') | Some('#')) {
            bail!("line {key_line}: missing value for key '{key}'");
        }

        let val_line = parser.line;
        let val = parser.parse_value(0)?;
        parser.expect_eol_or_eof()?;

        if !seen_keys.insert(normalize_key(&key)) {
            bail!("line {key_line}: duplicate config key '{key}'");
        }

        apply_parsed_entry(&mut cfg, &key, val, key_line, val_line)?;
    }

    Ok(cfg)
}

fn apply_parsed_entry(
    cfg: &mut FileConfig,
    key: &str,
    val: TomlValue,
    key_line: usize,
    val_line: usize,
) -> Result<()> {
    let normalized = normalize_key(key);
    match normalized.as_str() {
        "schema_version" => {
            cfg.schema_version = Some(extract_uint::<u32>(val, val_line, key, "u32")?);
        }
        "engine" => {
            let s = extract_string(val, val_line, key)?;
            cfg.engine =
                Some(parse_engine_mode(&s).map_err(|e| anyhow::anyhow!("line {val_line}: {e}"))?);
        }
        "mode" => {
            let s = extract_string(val, val_line, key)?;
            cfg.mode =
                Some(parse_desync_mode(&s).map_err(|e| anyhow::anyhow!("line {val_line}: {e}"))?);
        }
        "doh" => {
            cfg.doh = Some(extract_bool(val, val_line, key)?);
        }
        "block_quic" => {
            cfg.block_quic = Some(extract_bool(val, val_line, key)?);
        }
        "dns_addr" => {
            let s = extract_string(val, val_line, key)?;
            let validated = vdpi_core::dns::validate_custom_dns_input(&s)
                .map_err(|e| anyhow::anyhow!("line {val_line}: key 'dns_addr': {e}"))?;
            cfg.dns_addr = Some(validated);
        }
        "bypass_domains" => {
            let arr = extract_array(val, val_line, key)?;
            cfg.bypass_domains = Some(extract_string_array(arr, val_line, key)?);
        }
        "include_domains" => {
            let arr = extract_array(val, val_line, key)?;
            cfg.include_domains = Some(extract_string_array(arr, val_line, key)?);
        }
        "split_tunnel_mode" => {
            let s = extract_string(val, val_line, key)?;
            cfg.split_tunnel_mode = Some(
                parse_split_tunnel_mode(&s).map_err(|e| anyhow::anyhow!("line {val_line}: {e}"))?,
            );
        }
        "split_tunnel_apps" => {
            let arr = extract_array(val, val_line, key)?;
            let raw = extract_string_array(arr, val_line, key)?;
            cfg.split_tunnel_apps = Some(
                validate_split_tunnel_apps(&raw)
                    .map_err(|e| anyhow::anyhow!("line {val_line}: {e}"))?,
            );
        }
        "vpn_coexistence" => {
            let s = extract_string(val, val_line, key)?;
            cfg.vpn_coexistence = Some(
                parse_vpn_coexistence(&s).map_err(|e| anyhow::anyhow!("line {val_line}: {e}"))?,
            );
        }
        "tun_ipv6" => {
            cfg.tun_ipv6 = Some(extract_bool(val, val_line, key)?);
        }
        "chunk_size" => {
            let chunk_size = extract_uint::<usize>(val, val_line, key, "usize")?;
            if chunk_size == 0 {
                bail!("line {val_line}: key '{key}' must be at least 1");
            }
            cfg.chunk_size = Some(chunk_size);
        }
        "bind" => {
            let s = extract_string(val, val_line, key)?;
            let ip: IpAddr = s.trim().parse().map_err(|_| {
                anyhow::anyhow!("line {val_line}: invalid IP address '{s}' for 'bind'")
            })?;
            cfg.bind = Some(ip);
        }
        "port" => {
            cfg.port = Some(extract_uint::<u16>(val, val_line, key, "u16")?);
        }
        "socks_port" => {
            cfg.socks_port = Some(extract_uint::<u16>(val, val_line, key, "u16")?);
        }
        "dns_port" => {
            cfg.dns_port = Some(extract_uint::<u16>(val, val_line, key, "u16")?);
        }
        "ipv4_only" => {
            cfg.ipv4_only = Some(extract_bool(val, val_line, key)?);
        }
        "timeout_ms" => {
            cfg.timeout_ms = Some(extract_uint::<u64>(val, val_line, key, "u64")?);
        }
        "system_proxy" => {
            cfg.system_proxy = Some(extract_bool(val, val_line, key)?);
        }
        "socks_system_proxy" => {
            cfg.socks_system_proxy = Some(extract_bool(val, val_line, key)?);
        }
        "env_proxy" => {
            cfg.env_proxy = Some(extract_bool(val, val_line, key)?);
        }
        unknown => {
            warn!(
                line = key_line,
                key = unknown,
                "ignoring unknown config key"
            );
        }
    }

    Ok(())
}

fn extract_string(val: TomlValue, line: usize, key: &str) -> Result<String> {
    match val {
        TomlValue::Str(s) => Ok(s),
        _ => bail!("line {line}: key '{key}' expects a string"),
    }
}

fn extract_bool(val: TomlValue, line: usize, key: &str) -> Result<bool> {
    match val {
        TomlValue::Bool(b) => Ok(b),
        _ => bail!("line {line}: key '{key}' expects a boolean"),
    }
}

fn extract_uint<T>(val: TomlValue, line: usize, key: &str, type_name: &str) -> Result<T>
where
    T: TryFrom<i128>,
{
    let TomlValue::Int(n) = val else {
        bail!("line {line}: key '{key}' expects an integer");
    };
    T::try_from(n).map_err(|_| {
        anyhow::anyhow!("line {line}: value {n} for '{key}' is out of range for {type_name}")
    })
}

fn extract_array(val: TomlValue, line: usize, key: &str) -> Result<Vec<TomlValue>> {
    match val {
        TomlValue::Array(items) => Ok(items),
        _ => bail!("line {line}: key '{key}' expects an array of strings"),
    }
}

fn extract_string_array(items: Vec<TomlValue>, line: usize, key: &str) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            TomlValue::Str(s) => out.push(s),
            _ => bail!("line {line}: key '{key}' array elements must be strings"),
        }
    }
    Ok(out)
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        let src = input.strip_prefix('\u{FEFF}').unwrap_or(input);
        Self {
            src,
            pos: 0,
            line: 1,
        }
    }

    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
        }
        Some(ch)
    }

    fn skip_ws_inline(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    fn skip_comment_to_eol(&mut self) {
        if self.peek() == Some('#') {
            while let Some(ch) = self.peek() {
                if ch == '\n' {
                    break;
                }
                self.bump();
            }
        }
    }

    fn skip_ws_and_comments_multiline(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t' | '\r' | '\n') => {
                    self.bump();
                }
                Some('#') => {
                    self.skip_comment_to_eol();
                }
                _ => break,
            }
        }
    }

    fn expect_eol_or_eof(&mut self) -> Result<()> {
        self.skip_ws_inline();
        self.skip_comment_to_eol();
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            Some('\r') => {
                self.bump();
                if self.peek() == Some('\n') {
                    self.bump();
                }
                Ok(())
            }
            Some(_) => {
                let preview = self.rest().lines().next().unwrap_or("").trim();
                bail!(
                    "line {}: unexpected trailing input after value: {:?}",
                    self.line,
                    preview
                );
            }
        }
    }

    fn parse_key(&mut self) -> Result<String> {
        if self.peek() == Some('[') {
            bail!(
                "line {}: table sections are not supported in flat config.toml",
                self.line
            );
        }
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                self.bump();
            } else {
                break;
            }
        }
        let key = &self.src[start..self.pos];
        if key.is_empty() {
            let ch = self.peek().unwrap_or('\0');
            bail!("line {}: expected key, found '{}'", self.line, ch);
        }
        Ok(key.to_string())
    }

    fn parse_value(&mut self, depth: usize) -> Result<TomlValue> {
        match self.peek() {
            None | Some('\n' | '\r' | '#') => {
                bail!("line {}: expected value", self.line);
            }
            Some('"') => self.parse_basic_string().map(TomlValue::Str),
            Some('\'') => self.parse_literal_string().map(TomlValue::Str),
            Some('[') => self.parse_array(depth).map(TomlValue::Array),
            Some('{') => self
                .parse_inline_table(depth)
                .map(|()| TomlValue::InlineTable),
            Some(_) => self.parse_bare_value(),
        }
    }

    fn parse_basic_string(&mut self) -> Result<String> {
        let start_line = self.line;
        self.bump(); // opening '"'
        let mut out = String::new();

        loop {
            match self.bump() {
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('b') => out.push('\x08'),
                    Some('f') => out.push('\x0c'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('u') => {
                        let ch = self.parse_unicode_escape(4)?;
                        out.push(ch);
                    }
                    Some('U') => {
                        let ch = self.parse_unicode_escape(8)?;
                        out.push(ch);
                    }
                    Some('\n' | '\r') | None => {
                        bail!("line {start_line}: unterminated string literal");
                    }
                    Some(other) => {
                        bail!(
                            "line {}: unsupported escape sequence '\\{}'",
                            self.line,
                            other
                        );
                    }
                },
                Some('\n' | '\r') | None => {
                    bail!("line {start_line}: unterminated string literal");
                }
                Some(ch) => out.push(ch),
            }
        }
    }

    fn parse_unicode_escape(&mut self, digits: usize) -> Result<char> {
        let line = self.line;
        let mut hex = String::with_capacity(digits);
        for _ in 0..digits {
            match self.bump() {
                Some(ch) if ch.is_ascii_hexdigit() => hex.push(ch),
                Some(ch) => {
                    bail!("line {line}: invalid hex digit '{ch}' in unicode escape");
                }
                None => {
                    bail!("line {line}: truncated unicode escape in string literal");
                }
            }
        }
        let code = u32::from_str_radix(&hex, 16)
            .map_err(|_| anyhow::anyhow!("line {line}: invalid unicode escape '\\u{hex}'"))?;
        char::from_u32(code)
            .ok_or_else(|| anyhow::anyhow!("line {line}: invalid unicode scalar value 0x{hex}"))
    }

    fn parse_literal_string(&mut self) -> Result<String> {
        let start_line = self.line;
        self.bump(); // opening '\''
        let mut out = String::new();

        loop {
            match self.bump() {
                Some('\'') => return Ok(out),
                Some('\n' | '\r') | None => {
                    bail!("line {start_line}: unterminated literal string");
                }
                Some(ch) => out.push(ch),
            }
        }
    }

    fn parse_inline_table_key(&mut self) -> Result<()> {
        loop {
            match self.peek() {
                Some('"') => {
                    let _ = self.parse_basic_string()?;
                }
                Some('\'') => {
                    let _ = self.parse_literal_string()?;
                }
                _ => {
                    let _ = self.parse_key()?;
                }
            }
            self.skip_ws_inline();
            if self.peek() == Some('.') {
                self.bump();
                self.skip_ws_inline();
            } else {
                break;
            }
        }
        Ok(())
    }

    fn parse_inline_table(&mut self, depth: usize) -> Result<()> {
        if depth >= MAX_ARRAY_DEPTH {
            bail!(
                "line {}: inline table nesting exceeds maximum depth of {MAX_ARRAY_DEPTH}",
                self.line
            );
        }
        let start_line = self.line;
        self.bump(); // opening '{'

        loop {
            self.skip_ws_and_comments_multiline();
            match self.peek() {
                None => bail!("line {start_line}: unterminated inline table"),
                Some('}') => {
                    self.bump();
                    return Ok(());
                }
                Some(',') => bail!("line {}: unexpected ',' in inline table", self.line),
                Some(_) => {
                    self.parse_inline_table_key()?;
                    self.skip_ws_inline();
                    if self.peek() != Some('=') {
                        bail!("line {}: expected '=' in inline table", self.line);
                    }
                    self.bump();
                    self.skip_ws_inline();
                    let _ = self.parse_value(depth + 1)?;
                    self.skip_ws_and_comments_multiline();
                    match self.peek() {
                        Some(',') => {
                            self.bump();
                        }
                        Some('}') => {
                            self.bump();
                            return Ok(());
                        }
                        None => bail!("line {start_line}: unterminated inline table"),
                        Some(ch) => {
                            bail!(
                                "line {}: expected ',' or '}}' in inline table, found '{}'",
                                self.line,
                                ch
                            );
                        }
                    }
                }
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<Vec<TomlValue>> {
        if depth >= MAX_ARRAY_DEPTH {
            bail!(
                "line {}: array nesting exceeds maximum depth of {MAX_ARRAY_DEPTH}",
                self.line
            );
        }
        let start_line = self.line;
        self.bump(); // opening '['
        let mut items = Vec::new();

        loop {
            self.skip_ws_and_comments_multiline();
            match self.peek() {
                None => bail!("line {start_line}: unterminated array"),
                Some(']') => {
                    self.bump();
                    return Ok(items);
                }
                Some(',') => bail!("line {}: unexpected ',' in array", self.line),
                Some(_) => {
                    let val = self.parse_value(depth + 1)?;
                    items.push(val);
                    self.skip_ws_and_comments_multiline();
                    match self.peek() {
                        Some(',') => {
                            self.bump();
                        }
                        Some(']') => {
                            self.bump();
                            return Ok(items);
                        }
                        None => bail!("line {start_line}: unterminated array"),
                        Some(ch) => {
                            bail!(
                                "line {}: expected ',' or ']' in array, found '{}'",
                                self.line,
                                ch
                            );
                        }
                    }
                }
            }
        }
    }

    fn parse_bare_value(&mut self) -> Result<TomlValue> {
        let val_line = self.line;
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if matches!(ch, ' ' | '\t' | '\r' | '\n' | '#' | ',' | ']' | '}') {
                break;
            }
            self.bump();
        }
        let token = &self.src[start..self.pos];
        if token.is_empty() {
            let ch = self.peek().unwrap_or('\0');
            bail!("line {val_line}: unexpected character '{ch}' in value");
        }
        if token == "true" {
            Ok(TomlValue::Bool(true))
        } else if token == "false" {
            Ok(TomlValue::Bool(false))
        } else if let Some(n) = parse_toml_int(token) {
            Ok(TomlValue::Int(n))
        } else if is_toml_float(token) {
            Ok(TomlValue::Float)
        } else {
            bail!("line {val_line}: invalid value '{token}'");
        }
    }
}

fn is_valid_digit_seq(digits: &str, allow_leading_zero: bool) -> bool {
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') {
        return false;
    }
    if !allow_leading_zero && digits.starts_with('0') && digits.len() > 1 {
        return false;
    }
    let mut prev_underscore = false;
    for ch in digits.chars() {
        if ch == '_' {
            if prev_underscore {
                return false;
            }
            prev_underscore = true;
        } else if ch.is_ascii_digit() {
            prev_underscore = false;
        } else {
            return false;
        }
    }
    true
}

fn parse_toml_int(token: &str) -> Option<i128> {
    if token.is_empty() {
        return None;
    }
    let (sign, digits) = if let Some(rest) = token.strip_prefix('-') {
        ("-", rest)
    } else if let Some(rest) = token.strip_prefix('+') {
        ("", rest)
    } else {
        ("", token)
    };
    if !is_valid_digit_seq(digits, false) {
        return None;
    }

    let mut cleaned = String::with_capacity(sign.len() + digits.len());
    cleaned.push_str(sign);
    for ch in digits.chars() {
        if ch != '_' {
            cleaned.push(ch);
        }
    }

    cleaned.parse::<i128>().ok()
}

fn is_toml_float(token: &str) -> bool {
    if matches!(token, "inf" | "+inf" | "-inf" | "nan" | "+nan" | "-nan") {
        return true;
    }
    let unsigned = token
        .strip_prefix('-')
        .or_else(|| token.strip_prefix('+'))
        .unwrap_or(token);
    if unsigned.is_empty() {
        return false;
    }

    let (mantissa, has_exp) = match unsigned.find(['e', 'E']) {
        Some(idx) => {
            let exp_part = &unsigned[idx + 1..];
            let exp_digits = exp_part
                .strip_prefix('-')
                .or_else(|| exp_part.strip_prefix('+'))
                .unwrap_or(exp_part);
            if !is_valid_digit_seq(exp_digits, true) {
                return false;
            }
            (&unsigned[..idx], true)
        }
        None => (unsigned, false),
    };

    match mantissa.split_once('.') {
        Some((int_part, frac_part)) => {
            is_valid_digit_seq(int_part, false) && is_valid_digit_seq(frac_part, true)
        }
        None => has_exp && is_valid_digit_seq(mantissa, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let seq = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "vdpi-config-file-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create test temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn roundtrip_full_config() {
        let cfg = FileConfig {
            schema_version: Some(CONFIG_SCHEMA_VERSION),
            engine: Some(EngineMode::Tun),
            mode: Some(DesyncMode::TlsRecord),
            doh: Some(true),
            block_quic: Some(false),
            dns_addr: Some("https://1.1.1.1/dns-query".to_string()),
            bypass_domains: Some(vec![
                "example.com".to_string(),
                "corp.local".to_string(),
                r#"quote"and\slash"#.to_string(),
            ]),
            include_domains: Some(vec!["discord.com".to_string()]),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec![
                "discord.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
            ]),
            vpn_coexistence: Some(VpnCoexistence::Warn),
            tun_ipv6: Some(true),
            chunk_size: Some(12),
            bind: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: Some(8088),
            socks_port: Some(1088),
            dns_port: Some(5353),
            ipv4_only: Some(true),
            timeout_ms: Some(12_000),
            system_proxy: Some(false),
            socks_system_proxy: Some(false),
            env_proxy: Some(true),
        };

        let rendered = render_config_toml(&cfg);
        let parsed = parse_config_toml(&rendered).expect("rendered TOML must parse");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn roundtrip_default_and_empty_arrays() {
        let empty = FileConfig::default();
        let rendered = render_config_toml(&empty);
        assert_eq!(
            parse_config_toml(&rendered).expect("empty config parses"),
            empty
        );

        let with_empty_lists = FileConfig {
            bypass_domains: Some(Vec::new()),
            include_domains: Some(Vec::new()),
            ..Default::default()
        };
        let rendered_lists = render_config_toml(&with_empty_lists);
        assert_eq!(
            parse_config_toml(&rendered_lists).expect("empty arrays parse"),
            with_empty_lists
        );
    }

    #[test]
    fn parses_comments_escapes_literal_strings_and_multiline_arrays() {
        let input = "\u{FEFF}\
# Top-level comment
schema_version = 1 # inline comment
engine = 'tun' # literal string
mode = \"fragment\"
doh = true#attached comment
block_quic = false
dns_addr = \"https://dns.nextdns.io/abc123\"
bypass_domains = [
  # first entry
  \"alpha.example#not-a-comment\\t\\n\\\\\\\"ok\\\"\", # inline array comment
  'beta\\literal.example',
] # trailing array comment
include_domains = [\"one.example\", \"two.example\",]
vpn_coexistence = \"auto-yield\"
bind = \"::1\"
timeout_ms = 8_000
";

        let cfg = parse_config_toml(input).expect("complex TOML should parse");
        assert_eq!(cfg.schema_version, Some(1));
        assert_eq!(cfg.engine, Some(EngineMode::Tun));
        assert_eq!(cfg.mode, Some(DesyncMode::Fragment));
        assert_eq!(cfg.doh, Some(true));
        assert_eq!(cfg.block_quic, Some(false));
        assert_eq!(
            cfg.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/abc123")
        );
        assert_eq!(
            cfg.bypass_domains,
            Some(vec![
                "alpha.example#not-a-comment\t\n\\\"ok\"".to_string(),
                r"beta\literal.example".to_string(),
            ])
        );
        assert_eq!(
            cfg.include_domains,
            Some(vec!["one.example".to_string(), "two.example".to_string()])
        );
        assert_eq!(cfg.vpn_coexistence, Some(VpnCoexistence::AutoYield));
        assert_eq!(cfg.bind, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(cfg.timeout_ms, Some(8000));
    }

    #[test]
    fn ignores_unknown_keys_for_forward_compat() {
        let input = "\
schema_version = 2
future_string = \"hello\"
future_bool = true
future_int = 42
future_array = [
  1,
  \"two\",
  false,
]
engine = \"proxy\"
port = 9090
";

        let cfg = parse_config_toml(input).expect("unknown keys must be ignored");
        assert_eq!(cfg.schema_version, Some(2));
        assert_eq!(cfg.engine, Some(EngineMode::Proxy));
        assert_eq!(cfg.port, Some(9090));
    }

    #[test]
    fn rejects_invalid_syntax_and_values_with_line_numbers() {
        let cases = [
            ("port = 70000", "line 1:"),
            ("port = -5", "line 1:"),
            ("doh = \"true\"", "line 1:"),
            ("engine = \"wireguard\"", "line 1:"),
            ("mode = \"invalid-mode\"", "line 1:"),
            ("vpn_coexistence = \"always\"", "line 1:"),
            ("bind = \"not-an-ip\"", "line 1:"),
            ("dns_addr = \"unterminated", "line 1:"),
            ("dns_addr = 'unterminated", "line 1:"),
            ("dns_addr = \"bad\\qescape\"", "line 1:"),
            ("bypass_domains = [\"a\" \"b\"]", "line 1:"),
            ("bypass_domains = [,\"a\"]", "line 1:"),
            ("bypass_domains = [123]", "line 1:"),
            ("bypass_domains = [\"unclosed\"", "line 1:"),
            ("port = 8080 extra", "line 1:"),
            ("[section]\nport = 8080", "line 1:"),
            ("\nport", "line 2:"),
            ("\n\nport =", "line 3:"),
        ];

        for (input, expected_prefix) in cases {
            let Err(err) = parse_config_toml(input) else {
                panic!("input should fail to parse: {input:?}");
            };
            let msg = err.to_string();
            assert!(
                msg.contains(expected_prefix),
                "error '{msg}' for input {input:?} did not contain '{expected_prefix}'"
            );
        }
    }

    #[test]
    fn set_and_unset_config_keys() {
        let mut cfg = FileConfig::default();

        set_config_key(&mut cfg, "schema_version", "1").expect("set schema_version");
        set_config_key(&mut cfg, "engine", "tun").expect("set engine");
        set_config_key(&mut cfg, "mode", "split").expect("set mode");
        set_config_key(&mut cfg, "doh", "false").expect("set doh");
        set_config_key(&mut cfg, "block-quic", "true").expect("set block-quic");
        set_config_key(&mut cfg, "dns_addr", "9.9.9.9").expect("set dns_addr");
        set_config_key(&mut cfg, "bypass_domains", "a.com, b.com").expect("set bypass_domains");
        set_config_key(&mut cfg, "include_domains", "[\"c.com\", \"d.com\"]")
            .expect("set include_domains");
        set_config_key(&mut cfg, "split-tunnel-mode", "include").expect("set split_tunnel_mode");
        set_config_key(
            &mut cfg,
            "split-tunnel-apps",
            "discord.exe, robloxplayerbeta.exe",
        )
        .expect("set split_tunnel_apps");
        set_config_key(&mut cfg, "vpn-coexistence", "off").expect("set vpn_coexistence");
        set_config_key(&mut cfg, "tun_ipv6", "true").expect("set tun_ipv6");
        set_config_key(&mut cfg, "chunk_size", "16").expect("set chunk_size");
        set_config_key(&mut cfg, "bind", "127.0.0.1").expect("set bind");
        set_config_key(&mut cfg, "port", "8081").expect("set port");
        set_config_key(&mut cfg, "socks_port", "1081").expect("set socks_port");
        set_config_key(&mut cfg, "dns_port", "5353").expect("set dns_port");
        set_config_key(&mut cfg, "ipv4_only", "true").expect("set ipv4_only");
        set_config_key(&mut cfg, "timeout_ms", "5000").expect("set timeout_ms");
        set_config_key(&mut cfg, "system_proxy", "false").expect("set system_proxy");
        set_config_key(&mut cfg, "socks_system_proxy", "false").expect("set socks_system_proxy");
        set_config_key(&mut cfg, "env_proxy", "false").expect("set env_proxy");

        assert_eq!(cfg.schema_version, Some(1));
        assert_eq!(cfg.engine, Some(EngineMode::Tun));
        assert_eq!(cfg.mode, Some(DesyncMode::Split));
        assert_eq!(cfg.doh, Some(false));
        assert_eq!(cfg.block_quic, Some(true));
        assert_eq!(cfg.dns_addr.as_deref(), Some("9.9.9.9"));
        assert_eq!(
            cfg.bypass_domains,
            Some(vec!["a.com".to_string(), "b.com".to_string()])
        );
        assert_eq!(
            cfg.include_domains,
            Some(vec!["c.com".to_string(), "d.com".to_string()])
        );
        assert_eq!(cfg.split_tunnel_mode, Some(SplitTunnelMode::Include));
        assert_eq!(
            cfg.split_tunnel_apps,
            Some(vec![
                "discord.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
            ])
        );
        assert_eq!(cfg.vpn_coexistence, Some(VpnCoexistence::Off));
        assert_eq!(cfg.tun_ipv6, Some(true));
        assert_eq!(cfg.chunk_size, Some(16));
        assert_eq!(cfg.bind, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(cfg.port, Some(8081));
        assert_eq!(cfg.socks_port, Some(1081));
        assert_eq!(cfg.dns_port, Some(5353));
        assert_eq!(cfg.ipv4_only, Some(true));
        assert_eq!(cfg.timeout_ms, Some(5000));
        assert_eq!(cfg.system_proxy, Some(false));
        assert_eq!(cfg.socks_system_proxy, Some(false));
        assert_eq!(cfg.env_proxy, Some(false));

        assert!(set_config_key(&mut cfg, "unknown_key", "1").is_err());
        assert!(set_config_key(&mut cfg, "port", "99999").is_err());
        assert!(set_config_key(&mut cfg, "doh", "maybe").is_err());
        assert!(set_config_key(&mut cfg, "engine", "bogus").is_err());
        assert!(set_config_key(&mut cfg, "dns_addr", "   ").is_err());

        for key in [
            "schema_version",
            "engine",
            "mode",
            "doh",
            "block-quic",
            "dns_addr",
            "bypass_domains",
            "include_domains",
            "split_tunnel_mode",
            "split_tunnel_apps",
            "vpn_coexistence",
            "tun_ipv6",
            "chunk_size",
            "bind",
            "port",
            "socks_port",
            "dns_port",
            "ipv4_only",
            "timeout_ms",
            "system_proxy",
            "socks_system_proxy",
            "env_proxy",
        ] {
            unset_config_key(&mut cfg, key).expect("unset known key");
        }
        assert_eq!(cfg, FileConfig::default());
        assert!(unset_config_key(&mut cfg, "nonexistent").is_err());
    }

    #[test]
    fn atomic_save_creates_parents_and_replaces_cleanly() {
        let dir = TestTempDir::new("atomic");
        let path = dir.path().join("nested").join("dir").join("config.toml");

        assert!(
            load_file_config(Some(&path), false).is_err(),
            "missing explicit --config path must return an error"
        );
        let (missing_path, missing_cfg) = load_file_config_or_default(Some(&path), false)
            .expect("load_file_config_or_default returns default when missing");
        assert_eq!(missing_path, None);
        assert_eq!(missing_cfg, FileConfig::default());

        let first = FileConfig {
            schema_version: Some(1),
            engine: Some(EngineMode::Proxy),
            port: Some(8080),
            ..Default::default()
        };
        save_file_config_atomic(&path, &first).expect("initial atomic save");
        let (loaded_path, loaded_first) =
            load_file_config(Some(&path), false).expect("load saved config");
        assert_eq!(loaded_path.as_deref(), Some(path.as_path()));
        assert_eq!(loaded_first, first);

        let second = FileConfig {
            schema_version: Some(1),
            engine: Some(EngineMode::Tun),
            mode: Some(DesyncMode::Combo),
            bypass_domains: Some(vec!["local.test".to_string()]),
            ..Default::default()
        };
        save_file_config_atomic(&path, &second).expect("atomic overwrite");
        let (_, loaded_second) =
            load_file_config(Some(&path), false).expect("load overwritten config");
        assert_eq!(loaded_second, second);

        // Verify no stray `.config.toml.tmp.*` file remains alongside `config.toml`.
        let entries: Vec<String> = fs::read_dir(path.parent().expect("config parent"))
            .expect("read config dir")
            .map(|e| {
                e.expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(entries, vec!["config.toml".to_string()]);
    }

    #[test]
    fn rejects_duplicate_keys_with_line_numbers() {
        let dup_exact = "port = 8080\nport = 9090\n";
        let err = parse_config_toml(dup_exact).expect_err("duplicate key must fail");
        assert!(
            err.to_string().contains("line 2:"),
            "expected line 2 error, got: {err}"
        );

        let dup_kebab = "block_quic = true\n# comment\nblock-quic = false\n";
        let err_kebab =
            parse_config_toml(dup_kebab).expect_err("kebab/snake duplicate key must fail");
        assert!(
            err_kebab.to_string().contains("line 3:"),
            "expected line 3 error, got: {err_kebab}"
        );
    }

    #[test]
    fn missing_explicit_config_returns_error_while_or_default_succeeds() {
        let dir = TestTempDir::new("missing-explicit");
        let missing = dir.path().join("does-not-exist.toml");

        let err = load_file_config(Some(&missing), false)
            .expect_err("explicit missing config must return error");
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );

        let (found, cfg) = load_file_config_or_default(Some(&missing), false)
            .expect("load_file_config_or_default must succeed");
        assert_eq!(found, None);
        assert_eq!(cfg, FileConfig::default());
    }

    #[test]
    fn normalizes_kebab_case_keys_and_trims_dns_addr_in_toml() {
        let input = "\
schema-version = 1
block-quic = false
dns-addr = \"  9.9.9.9  \"
vpn-coexistence = \"warn\"
tun-ipv6 = true
chunk-size = 6
socks-port = 1088
dns-port = 5353
ipv4-only = true
timeout-ms = 4000
system-proxy = false
socks-system-proxy = false
env-proxy = false
bypass-domains = [\"example.org\"]
include-domains = [\"^test\\\\.org$\"]
";
        let cfg = parse_config_toml(input).expect("kebab-case keys should parse");
        assert_eq!(cfg.schema_version, Some(1));
        assert_eq!(cfg.block_quic, Some(false));
        assert_eq!(cfg.dns_addr.as_deref(), Some("9.9.9.9"));
        assert_eq!(cfg.vpn_coexistence, Some(VpnCoexistence::Warn));
        assert_eq!(cfg.tun_ipv6, Some(true));
        assert_eq!(cfg.chunk_size, Some(6));
        assert_eq!(cfg.socks_port, Some(1088));
        assert_eq!(cfg.dns_port, Some(5353));
        assert_eq!(cfg.ipv4_only, Some(true));
        assert_eq!(cfg.timeout_ms, Some(4000));
        assert_eq!(cfg.system_proxy, Some(false));
        assert_eq!(cfg.socks_system_proxy, Some(false));
        assert_eq!(cfg.env_proxy, Some(false));
        assert_eq!(cfg.bypass_domains, Some(vec!["example.org".to_string()]));
        assert_eq!(cfg.include_domains, Some(vec!["^test\\.org$".to_string()]));
    }

    #[test]
    fn rejects_leading_zero_ints_and_zero_chunk_size() {
        assert!(parse_config_toml("port = 08080").is_err());
        assert!(parse_config_toml("timeout_ms = -01").is_err());
        assert!(parse_config_toml("port = 0_1").is_err());
        assert!(parse_config_toml("chunk_size = 0").is_err());

        // Single zero remains valid for fields that allow 0 (e.g. socks_port = 0 disables it).
        let cfg = parse_config_toml("socks_port = 0\ntimeout_ms = 0").expect("0 is valid");
        assert_eq!(cfg.socks_port, Some(0));
        assert_eq!(cfg.timeout_ms, Some(0));

        let mut mut_cfg = FileConfig::default();
        assert!(set_config_key(&mut mut_cfg, "port", "08080").is_err());
        assert!(set_config_key(&mut mut_cfg, "chunk_size", "0").is_err());
        assert!(set_config_key(&mut mut_cfg, "chunk-size", "0").is_err());
    }

    #[test]
    fn ignores_unknown_float_and_inline_table_keys_for_forward_compat() {
        let input = "\
schema_version = 2
future_float = 1.5
future_sci = -2.5e-3
future_inf = inf
future_inline = { host = \"1.1.1.1\", weight = 0.75, nested = { enabled = true, list = [1, 2.5, {}] } }
future_empty_table = {}
future_array_mixed = [1.25, { k = \"v\" }, true]
port = 8081
";
        let cfg = parse_config_toml(input).expect("unknown float/inline table keys must skip");
        assert_eq!(cfg.schema_version, Some(2));
        assert_eq!(cfg.port, Some(8081));

        // Known integer keys must still reject floats and inline tables.
        assert!(parse_config_toml("port = 80.5").is_err());
        assert!(parse_config_toml("port = { value = 8080 }").is_err());
    }

    #[test]
    fn get_config_key_returns_formatted_values_and_errors_on_unknown() {
        let mut cfg = FileConfig::default();
        assert_eq!(get_config_key(&cfg, "engine").unwrap(), None);
        assert_eq!(get_config_key(&cfg, "block-quic").unwrap(), None);
        assert!(get_config_key(&cfg, "nonexistent").is_err());

        set_config_key(&mut cfg, "engine", "tun").unwrap();
        set_config_key(&mut cfg, "mode", "tls-record").unwrap();
        set_config_key(&mut cfg, "block_quic", "false").unwrap();
        set_config_key(&mut cfg, "port", "9090").unwrap();
        set_config_key(&mut cfg, "bypass_domains", "a.com, b.com").unwrap();
        set_config_key(&mut cfg, "vpn_coexistence", "warn").unwrap();

        assert_eq!(
            get_config_key(&cfg, "engine").unwrap().as_deref(),
            Some("tun")
        );
        assert_eq!(
            get_config_key(&cfg, "mode").unwrap().as_deref(),
            Some("tls-record")
        );
        assert_eq!(
            get_config_key(&cfg, "block-quic").unwrap().as_deref(),
            Some("false")
        );
        assert_eq!(
            get_config_key(&cfg, "port").unwrap().as_deref(),
            Some("9090")
        );
        assert_eq!(
            get_config_key(&cfg, "bypass-domains").unwrap().as_deref(),
            Some("[\"a.com\", \"b.com\"]")
        );
        assert_eq!(
            get_config_key(&cfg, "vpn-coexistence").unwrap().as_deref(),
            Some("warn")
        );
    }

    #[test]
    fn parse_string_list_arg_falls_back_on_regex_and_ipv6_bracket_values() {
        let mut cfg = FileConfig::default();

        set_config_key(&mut cfg, "include_domains", r"[a-z]+\.example\.com")
            .expect("regex starting with '[' must not fail");
        assert_eq!(
            cfg.include_domains,
            Some(vec![r"[a-z]+\.example\.com".to_string()])
        );

        set_config_key(&mut cfg, "bypass_domains", "[2001:db8::1], [::1]")
            .expect("IPv6 bracket values must fall back to comma list");
        assert_eq!(
            cfg.bypass_domains,
            Some(vec!["[2001:db8::1]".to_string(), "[::1]".to_string()])
        );

        // Valid TOML string arrays continue to parse as TOML arrays.
        set_config_key(&mut cfg, "bypass_domains", "[\"one.com\", \"two.com\"]")
            .expect("valid TOML array");
        assert_eq!(
            cfg.bypass_domains,
            Some(vec!["one.com".to_string(), "two.com".to_string()])
        );
    }

    #[test]
    fn escapes_and_roundtrips_control_chars_in_toml_strings() {
        let cfg = FileConfig {
            bypass_domains: Some(vec!["a\x00b\x08c\x0cd\x1be\x7ff".to_string()]),
            ..Default::default()
        };
        let rendered = render_config_toml(&cfg);
        assert!(rendered.contains(r"\u0000"));
        assert!(rendered.contains(r"\b"));
        assert!(rendered.contains(r"\f"));
        assert!(rendered.contains(r"\u001B"));
        assert!(rendered.contains(r"\u007F"));

        let parsed = parse_config_toml(&rendered).expect("escaped control chars must roundtrip");
        assert_eq!(parsed, cfg);
    }

    #[test]
    fn path_helpers_follow_os_conventions() {
        assert_eq!(
            windows_system_config_path(Some(OsStr::new(r"D:\ProgramData"))),
            PathBuf::from(r"D:\ProgramData")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            windows_system_config_path(None),
            PathBuf::from(r"C:\ProgramData")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            windows_user_config_path(Some(OsStr::new(r"C:\Users\alice\AppData\Local")), None),
            PathBuf::from(r"C:\Users\alice\AppData\Local")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            windows_user_config_path(None, None),
            PathBuf::from(r"C:\ProgramData")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            windows_user_config_path(Some(OsStr::new("relative")), None),
            PathBuf::from(r"C:\ProgramData")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            macos_user_config_path(Some(OsStr::new("/Users/alice"))),
            PathBuf::from("/Users/alice")
                .join(".vdpi")
                .join("config.toml")
        );
        assert_eq!(
            macos_user_config_path(None),
            PathBuf::from("/Library/Application Support/vdpi/config.toml")
        );
        assert_eq!(
            linux_user_config_path(
                Some(OsStr::new("/xdg/cfg")),
                Some(OsStr::new("/home/alice"))
            ),
            PathBuf::from("/xdg/cfg").join("vdpi").join("config.toml")
        );
        assert_eq!(
            linux_user_config_path(None, Some(OsStr::new("/home/alice"))),
            PathBuf::from("/home/alice")
                .join(".config")
                .join("vdpi")
                .join("config.toml")
        );
        assert_eq!(
            linux_user_config_path(None, None),
            PathBuf::from("/etc/vdpi/config.toml")
        );
        assert_eq!(
            linux_user_config_path(
                Some(OsStr::new("relative")),
                Some(OsStr::new("/home/alice"))
            ),
            PathBuf::from("/home/alice")
                .join(".config")
                .join("vdpi")
                .join("config.toml")
        );

        assert_eq!(
            system_config_path().file_name(),
            Some(OsStr::new("config.toml"))
        );
        assert_eq!(
            user_config_path().file_name(),
            Some(OsStr::new("config.toml"))
        );
        assert!(user_config_path().is_absolute());

        #[cfg(target_os = "windows")]
        {
            let service_paths = candidate_config_paths(true);
            assert_eq!(service_paths, vec![system_config_path()]);
        }
    }

    #[test]
    fn split_tunnel_toml_roundtrip_all_modes_and_empty_apps() {
        for mode in [
            SplitTunnelMode::All,
            SplitTunnelMode::Exclude,
            SplitTunnelMode::Include,
        ] {
            let cfg = FileConfig {
                split_tunnel_mode: Some(mode),
                split_tunnel_apps: Some(vec![
                    "discord.exe".to_string(),
                    "robloxplayerbeta.exe".to_string(),
                ]),
                ..Default::default()
            };
            let rendered = render_config_toml(&cfg);
            assert!(rendered.contains(&format!("split_tunnel_mode = \"{}\"", mode.as_str())));
            assert!(rendered.contains("split_tunnel_apps = ["));
            let parsed = parse_config_toml(&rendered).expect("split tunnel config roundtrips");
            assert_eq!(parsed, cfg);
        }

        let empty_apps = FileConfig {
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(Vec::new()),
            ..Default::default()
        };
        let rendered_empty = render_config_toml(&empty_apps);
        assert!(rendered_empty.contains("split_tunnel_apps = []"));
        assert_eq!(
            parse_config_toml(&rendered_empty).expect("empty split_tunnel_apps parses"),
            empty_apps
        );

        let kebab = "\
split-tunnel-mode = \"include\"
split-tunnel-apps = [\"discord.exe\", \"firefox\"]
";
        let parsed_kebab = parse_config_toml(kebab).expect("kebab split tunnel keys parse");
        assert_eq!(
            parsed_kebab.split_tunnel_mode,
            Some(SplitTunnelMode::Include)
        );
        assert_eq!(
            parsed_kebab.split_tunnel_apps,
            Some(vec!["discord.exe".to_string(), "firefox".to_string()])
        );
        assert_eq!(
            get_config_key(&parsed_kebab, "split-tunnel-mode")
                .unwrap()
                .as_deref(),
            Some("include")
        );
        assert_eq!(
            get_config_key(&parsed_kebab, "split-tunnel-apps")
                .unwrap()
                .as_deref(),
            Some("[\"discord.exe\", \"firefox\"]")
        );
    }

    #[test]
    fn split_tunnel_rejects_invalid_mode_and_control_chars() {
        let invalid_cases = [
            ("split_tunnel_mode = \"bypass\"", "line 1:"),
            ("split_tunnel_mode = \"only\"", "line 1:"),
            ("split_tunnel_mode = \"\"", "line 1:"),
            ("split_tunnel_mode = 123", "line 1:"),
            ("split_tunnel_apps = \"discord.exe\"", "line 1:"),
            ("split_tunnel_apps = [123]", "line 1:"),
            ("split_tunnel_apps = [\"discord.exe\\nwhoami\"]", "line 1:"),
            ("split_tunnel_apps = [\"discord.exe\\r\"]", "line 1:"),
            ("split_tunnel_apps = [\"bad\\u0000app.exe\"]", "line 1:"),
            ("split_tunnel_apps = [\"bad\\tapp.exe\"]", "line 1:"),
            ("\nsplit_tunnel_mode = \"invalid\"", "line 2:"),
        ];

        for (input, expected_prefix) in invalid_cases {
            let Err(err) = parse_config_toml(input) else {
                panic!("input should fail to parse: {input:?}");
            };
            let msg = err.to_string();
            assert!(
                msg.contains(expected_prefix),
                "error '{msg}' for input {input:?} did not contain '{expected_prefix}'"
            );
        }

        let mut cfg = FileConfig::default();
        assert!(set_config_key(&mut cfg, "split_tunnel_mode", "bogus").is_err());
        assert!(set_config_key(&mut cfg, "split_tunnel_apps", "discord.exe\nevil.exe").is_err());
        assert!(set_config_key(&mut cfg, "split_tunnel_apps", "[\"bad\\u001B.exe\"]").is_err());
    }

    #[test]
    fn split_tunnel_deduplicates_sanitizes_and_caps_apps_on_load_and_save() {
        let input = "\
split_tunnel_mode = \"exclude\"
split_tunnel_apps = [
  \"  Discord.exe  \",
  \"discord.exe\",
  \"discord\",
  \"\",
  \"   \",
  \".exe\",
  \"robloxplayerbeta.exe\",
  \"RobloxPlayerBeta\",
  \"steam.exe\",
]
";
        let parsed = parse_config_toml(input).expect("sanitized split_tunnel_apps parses");
        assert_eq!(
            parsed.split_tunnel_apps,
            Some(vec![
                "Discord.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
                "steam.exe".to_string(),
            ])
        );

        // Verify render_config_toml sanitizes dirty in-memory values (control chars, dupes, >256).
        let mut oversized: Vec<String> = (0..(MAX_SPLIT_TUNNEL_APPS + 20))
            .map(|i| format!("app-{i}.exe"))
            .collect();
        oversized.insert(0, "bad\nentry.exe".to_string());
        oversized.insert(2, "APP-0.EXE".to_string());
        oversized.insert(3, "   ".to_string());

        let dirty = FileConfig {
            split_tunnel_mode: Some(SplitTunnelMode::Include),
            split_tunnel_apps: Some(oversized),
            ..Default::default()
        };
        let rendered = render_config_toml(&dirty);
        assert!(!rendered.contains("bad"));
        let reparsed = parse_config_toml(&rendered).expect("rendered sanitized TOML parses");
        let reparsed_apps = reparsed
            .split_tunnel_apps
            .expect("split_tunnel_apps present");
        assert_eq!(reparsed_apps.len(), MAX_SPLIT_TUNNEL_APPS);
        assert_eq!(reparsed_apps[0], "app-0.exe");
        assert_eq!(
            reparsed_apps[MAX_SPLIT_TUNNEL_APPS - 1],
            format!("app-{}.exe", MAX_SPLIT_TUNNEL_APPS - 1)
        );

        // Verify parse_config_toml also gracefully caps lists exceeding MAX_SPLIT_TUNNEL_APPS.
        let mut big_toml = String::from("split_tunnel_apps = [\n");
        for i in 0..(MAX_SPLIT_TUNNEL_APPS + 15) {
            let _ = writeln!(big_toml, "  \"proc-{i}.exe\",");
        }
        big_toml.push_str("]\n");
        let capped = parse_config_toml(&big_toml).expect("oversized TOML array is capped");
        let capped_apps = capped.split_tunnel_apps.expect("apps present");
        assert_eq!(capped_apps.len(), MAX_SPLIT_TUNNEL_APPS);
        assert_eq!(capped_apps[0], "proc-0.exe");
        assert_eq!(
            capped_apps[MAX_SPLIT_TUNNEL_APPS - 1],
            format!("proc-{}.exe", MAX_SPLIT_TUNNEL_APPS - 1)
        );
    }

    #[test]
    fn file_config_merge_precedence() {
        let base = FileConfig {
            engine: Some(EngineMode::Proxy),
            port: Some(8080),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec!["discord.exe".to_string()]),
            ..Default::default()
        };
        let overlay = FileConfig {
            engine: Some(EngineMode::Tun),
            split_tunnel_mode: Some(SplitTunnelMode::Include),
            split_tunnel_apps: None,
            ..Default::default()
        };

        let merged = base.merge(&overlay);
        assert_eq!(merged.engine, Some(EngineMode::Tun));
        assert_eq!(merged.port, Some(8080));
        assert_eq!(merged.split_tunnel_mode, Some(SplitTunnelMode::Include));
        assert_eq!(
            merged.split_tunnel_apps,
            Some(vec!["discord.exe".to_string()])
        );

        // Explicit empty list in overlay overrides non-empty list in base.
        let clearing_overlay = FileConfig {
            split_tunnel_apps: Some(Vec::new()),
            ..Default::default()
        };
        let cleared = base.merge(&clearing_overlay);
        assert_eq!(cleared.split_tunnel_mode, Some(SplitTunnelMode::Exclude));
        assert_eq!(cleared.split_tunnel_apps, Some(Vec::new()));
    }

    #[test]
    fn file_config_apply_to_runtime_wires_split_tunnel() {
        let mut runtime = RuntimeConfig::default();
        assert_eq!(runtime.split_tunnel.mode, SplitTunnelMode::All);
        assert!(runtime.split_tunnel.apps.is_empty());

        let file_cfg = FileConfig {
            engine: Some(EngineMode::Tun),
            split_tunnel_mode: Some(SplitTunnelMode::Exclude),
            split_tunnel_apps: Some(vec![
                "  discord.exe ".to_string(),
                "DISCORD.EXE".to_string(),
                "bad\napp.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
            ]),
            ..Default::default()
        };
        file_cfg.apply_to_runtime(&mut runtime);

        assert_eq!(runtime.engine, EngineMode::Tun);
        assert_eq!(runtime.split_tunnel.mode, SplitTunnelMode::Exclude);
        assert_eq!(
            runtime.split_tunnel.apps,
            vec![
                "discord.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
            ]
        );

        // Unset fields in a subsequent FileConfig leave runtime split_tunnel untouched.
        let partial = FileConfig {
            port: Some(9090),
            ..Default::default()
        };
        partial.apply_to_runtime(&mut runtime);
        assert_eq!(runtime.port, 9090);
        assert_eq!(runtime.split_tunnel.mode, SplitTunnelMode::Exclude);
        assert_eq!(
            runtime.split_tunnel.apps,
            vec![
                "discord.exe".to_string(),
                "robloxplayerbeta.exe".to_string(),
            ]
        );
    }

    #[test]
    fn custom_dns_roundtrips_ipv4_ipv6_and_doh_urls_and_rejects_invalid() {
        let dir = TestTempDir::new("custom-dns");
        let valid_cases = [
            "76.76.2.0",
            "2606:4700:4700::1111",
            "https://dns.nextdns.io/abc123",
            "https://freedns.controld.com/p2",
            "https://dns.example.com:8443/dns-query",
        ];

        for (idx, dns) in valid_cases.iter().enumerate() {
            let mut cfg = FileConfig {
                schema_version: Some(CONFIG_SCHEMA_VERSION),
                engine: Some(EngineMode::Tun),
                ..Default::default()
            };
            set_config_key(&mut cfg, "dns_addr", dns)
                .unwrap_or_else(|e| panic!("set_config_key failed for valid DNS '{dns}': {e:#}"));
            assert_eq!(
                get_config_key(&cfg, "dns-addr").unwrap().as_deref(),
                Some(*dns)
            );

            let rendered = render_config_toml(&cfg);
            let parsed = parse_config_toml(&rendered)
                .unwrap_or_else(|e| panic!("parse_config_toml failed for '{dns}': {e:#}"));
            assert_eq!(parsed.dns_addr.as_deref(), Some(*dns));

            let path = dir.path().join(format!("config-{idx}.toml"));
            save_file_config_atomic(&path, &cfg).expect("atomic save custom DNS");
            let (_, reloaded) =
                load_file_config(Some(&path), false).expect("reload custom DNS config");
            assert_eq!(reloaded, cfg);

            let mut runtime = RuntimeConfig::default();
            reloaded.apply_to_runtime(&mut runtime);
            assert_eq!(runtime.engine, EngineMode::Tun);
            assert_eq!(runtime.dns_addr, *dns);
        }

        // Invalid custom DNS values must be rejected in both set_config_key and parse_config_toml.
        let invalid_cases = [
            "",
            "   ",
            "http://dns.nextdns.io/abc123",
            "not-a-valid-dns",
            "https://",
            "76.76.2.0\nwhoami",
        ];
        let mut cfg = FileConfig::default();
        for bad in invalid_cases {
            assert!(
                set_config_key(&mut cfg, "dns_addr", bad).is_err(),
                "set_config_key should reject invalid DNS {bad:?}"
            );
            let toml = format!("dns_addr = {}\n", escape_toml_string(bad));
            let err = parse_config_toml(&toml).expect_err(&format!(
                "parse_config_toml should reject invalid DNS {bad:?}"
            ));
            assert!(
                err.to_string().contains("line 1:"),
                "expected line 1 error for {bad:?}, got: {err}"
            );
        }
    }
}
