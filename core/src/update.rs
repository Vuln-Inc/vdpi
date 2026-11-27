use crate::config::RuntimeConfig;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::debug;

const GITHUB_LATEST_RELEASE_URL: &str =
    "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const API_TIMEOUT: Duration = Duration::from_secs(12);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_API_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SUMS_BODY_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const SHA256_READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_EXTRACT_SEARCH_DEPTH: usize = 3;
const GITHUB_API_HOST: &str = "api.github.com";
const GITHUB_RELEASE_DOWNLOAD_PATH_PREFIX: &str = "/Vuln-Inc/vdpi/releases/download/";
const MAX_REDIRECT_HOPS: usize = 5;
const ALLOWED_GITHUB_DOWNLOAD_HOSTS: &[&str] = &[
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "codeload.github.com",
];
#[cfg(any(target_os = "windows", test))]
const WINDOWS_OPTIONAL_ARCHIVE_MEMBERS: &[&str] = &["wintun.dll", "WINTUN-LICENSE.txt"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedirectTargetPolicy {
    GitHubApi,
    GitHubDownload,
}

fn is_allowed_github_download_host(host: &str) -> bool {
    ALLOWED_GITHUB_DOWNLOAD_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn validate_github_api_parsed_url(parsed: &reqwest::Url, label: &str) -> Result<()> {
    if parsed.scheme() != "https" {
        bail!("refusing non-HTTPS URL for {label}: {parsed}");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("refusing URL with embedded credentials for {label}: {parsed}");
    }
    if parsed.port_or_known_default() != Some(443) {
        bail!("refusing non-standard HTTPS port for {label}: {parsed}");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL for {label} is missing a host: {parsed}"))?;
    if !host.eq_ignore_ascii_case(GITHUB_API_HOST) {
        bail!(
            "refusing untrusted API host '{host}' for {label} (only {GITHUB_API_HOST} is allowed)"
        );
    }
    Ok(())
}

fn validate_github_download_parsed_url(parsed: &reqwest::Url, label: &str) -> Result<()> {
    if parsed.scheme() != "https" {
        bail!("refusing non-HTTPS download URL for {label}: {parsed}");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("refusing download URL with embedded credentials for {label}: {parsed}");
    }
    if parsed.port_or_known_default() != Some(443) {
        bail!("refusing non-standard HTTPS port for {label}: {parsed}");
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("download URL for {label} is missing a host: {parsed}"))?;
    if !is_allowed_github_download_host(host) {
        bail!(
            "refusing untrusted download host '{host}' for {label} (only GitHub release domains are allowed)"
        );
    }
    if host.eq_ignore_ascii_case("github.com") {
        let path = parsed.path();
        let lower_path = path.to_ascii_lowercase();
        if !path.starts_with(GITHUB_RELEASE_DOWNLOAD_PATH_PREFIX)
            || path.len() <= GITHUB_RELEASE_DOWNLOAD_PATH_PREFIX.len()
            || path.contains("..")
            || lower_path.contains("%2e")
            || lower_path.contains("%2f")
            || lower_path.contains("%5c")
            || path.contains('\\')
        {
            bail!(
                "refusing untrusted github.com download path '{path}' for {label} (must be under {GITHUB_RELEASE_DOWNLOAD_PATH_PREFIX})"
            );
        }
    }
    Ok(())
}

fn validate_github_download_url(raw_url: &str, label: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(raw_url)
        .with_context(|| format!("invalid download URL for {label}: {raw_url}"))?;
    validate_github_download_parsed_url(&parsed, label)
}

fn validate_redirect_hop(
    target: RedirectTargetPolicy,
    next_url: &reqwest::Url,
    previous_hops: usize,
) -> Result<()> {
    if previous_hops > MAX_REDIRECT_HOPS {
        bail!("too many redirects (exceeded {MAX_REDIRECT_HOPS}-hop limit)");
    }
    match target {
        RedirectTargetPolicy::GitHubApi => {
            validate_github_api_parsed_url(next_url, "GitHub Releases API redirect")
        }
        RedirectTargetPolicy::GitHubDownload => {
            validate_github_download_parsed_url(next_url, "release download redirect")
        }
    }
}

fn build_redirect_policy(target: RedirectTargetPolicy) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        match validate_redirect_hop(target, attempt.url(), attempt.previous().len()) {
            Ok(()) => attempt.follow(),
            Err(err) => attempt.error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                err.to_string(),
            )),
        }
    })
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Scoop,
    WinGet,
    Homebrew,
}

impl PackageManager {
    fn name(self) -> &'static str {
        match self {
            Self::Scoop => "Scoop",
            Self::WinGet => "WinGet",
            Self::Homebrew => "Homebrew",
        }
    }

    fn upgrade_command(self) -> &'static str {
        match self {
            Self::Scoop => "scoop update vdpi",
            Self::WinGet => "winget upgrade Vuln-Inc.vdpi",
            Self::Homebrew => "brew upgrade vdpi",
        }
    }
}

#[cfg(any(target_os = "windows", test))]
fn normalize_windows_match_path(path: &Path) -> String {
    strip_windows_verbatim_prefix(path)
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

#[cfg(any(target_os = "windows", test))]
fn path_is_under_scoop_root(normalized_exe: &str, root: &OsStr) -> bool {
    let root_str = root.to_string_lossy();
    let trimmed = root_str.trim();
    if trimmed.is_empty() {
        return false;
    }
    let norm_root = normalize_windows_match_path(Path::new(trimmed));
    let norm_root = norm_root.trim_end_matches('\\');
    if norm_root.is_empty() {
        return false;
    }
    let apps_prefix = format!("{norm_root}\\apps\\vdpi\\");
    let shim_path = format!("{norm_root}\\shims\\vdpi.exe");
    normalized_exe.starts_with(&apps_prefix) || normalized_exe == shim_path
}

#[cfg(any(target_os = "windows", test))]
fn detect_windows_package_manager_path_with_env(
    path: &Path,
    scoop_env: Option<&OsStr>,
    scoop_global_env: Option<&OsStr>,
) -> Option<PackageManager> {
    let normalized = normalize_windows_match_path(path);
    if normalized.contains("\\scoop\\apps\\vdpi\\")
        || normalized.ends_with("\\scoop\\shims\\vdpi.exe")
        || scoop_env.is_some_and(|root| path_is_under_scoop_root(&normalized, root))
        || scoop_global_env.is_some_and(|root| path_is_under_scoop_root(&normalized, root))
    {
        Some(PackageManager::Scoop)
    } else if normalized.contains("\\winget\\packages\\") {
        Some(PackageManager::WinGet)
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn path_is_under_homebrew_prefix(
    normalized_path: &str,
    prefix: &str,
    case_insensitive: bool,
) -> bool {
    let trimmed = prefix.trim();
    if !trimmed.starts_with('/') {
        return false;
    }
    let clean_prefix = trimmed.trim_end_matches('/');
    if clean_prefix.is_empty() {
        return false;
    }
    if case_insensitive {
        let lower_prefix = clean_prefix.to_ascii_lowercase();
        normalized_path.starts_with(&format!("{lower_prefix}/cellar/vdpi/"))
            || normalized_path.starts_with(&format!("{lower_prefix}/opt/vdpi/"))
    } else {
        normalized_path.starts_with(&format!("{clean_prefix}/Cellar/vdpi/"))
            || normalized_path.starts_with(&format!("{clean_prefix}/opt/vdpi/"))
    }
}

#[cfg(any(target_os = "macos", test))]
fn detect_macos_package_manager_path_with_env(
    path: &Path,
    homebrew_prefix: Option<&OsStr>,
) -> Option<PackageManager> {
    let normalized = path.to_string_lossy().to_ascii_lowercase();
    let custom_match = homebrew_prefix.is_some_and(|prefix| {
        let prefix_str = prefix.to_string_lossy();
        path_is_under_homebrew_prefix(&normalized, &prefix_str, true)
    });
    if path_is_under_homebrew_prefix(&normalized, "/opt/homebrew", true)
        || path_is_under_homebrew_prefix(&normalized, "/usr/local", true)
        || custom_match
    {
        Some(PackageManager::Homebrew)
    } else {
        None
    }
}

#[cfg(test)]
fn detect_macos_package_manager_path(path: &Path) -> Option<PackageManager> {
    detect_macos_package_manager_path_with_env(path, None)
}

#[cfg(any(target_os = "linux", test))]
fn detect_linux_package_manager_path_with_env(
    path: &Path,
    homebrew_prefix: Option<&OsStr>,
    home_env: Option<&OsStr>,
) -> Option<PackageManager> {
    let normalized = path.to_string_lossy();
    let custom_prefix_match = homebrew_prefix.is_some_and(|prefix| {
        let prefix_str = prefix.to_string_lossy();
        path_is_under_homebrew_prefix(&normalized, &prefix_str, false)
    });
    let home_linuxbrew_match = home_env.is_some_and(|home| {
        let home_str = home.to_string_lossy();
        let trimmed = home_str.trim();
        if !trimmed.starts_with('/') {
            return false;
        }
        let clean_home = trimmed.trim_end_matches('/');
        if clean_home.is_empty() {
            return false;
        }
        let prefix = format!("{clean_home}/.linuxbrew");
        path_is_under_homebrew_prefix(&normalized, &prefix, false)
    });
    if path_is_under_homebrew_prefix(&normalized, "/home/linuxbrew/.linuxbrew", false)
        || custom_prefix_match
        || home_linuxbrew_match
    {
        Some(PackageManager::Homebrew)
    } else {
        None
    }
}

#[cfg(test)]
fn detect_linux_package_manager_path(path: &Path) -> Option<PackageManager> {
    detect_linux_package_manager_path_with_env(path, None, None)
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
fn detect_current_exe_package_manager() -> Option<(PackageManager, PathBuf)> {
    let exe_raw = std::env::current_exe().ok()?;
    #[cfg(target_os = "windows")]
    {
        let scoop_env = std::env::var_os("SCOOP");
        let scoop_global_env = std::env::var_os("SCOOP_GLOBAL");
        let clean_raw = strip_windows_verbatim_prefix(&exe_raw);
        if let Some(pm) = detect_windows_package_manager_path_with_env(
            &clean_raw,
            scoop_env.as_deref(),
            scoop_global_env.as_deref(),
        ) {
            return Some((pm, clean_raw));
        }
        if let Ok(canonical) = fs::canonicalize(&exe_raw) {
            let clean_canonical = strip_windows_verbatim_prefix(&canonical);
            if let Some(pm) = detect_windows_package_manager_path_with_env(
                &clean_canonical,
                scoop_env.as_deref(),
                scoop_global_env.as_deref(),
            ) {
                return Some((pm, clean_canonical));
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let homebrew_prefix = std::env::var_os("HOMEBREW_PREFIX");
        if let Some(pm) =
            detect_macos_package_manager_path_with_env(&exe_raw, homebrew_prefix.as_deref())
        {
            return Some((pm, exe_raw));
        }
        if let Ok(canonical) = fs::canonicalize(&exe_raw) {
            if let Some(pm) =
                detect_macos_package_manager_path_with_env(&canonical, homebrew_prefix.as_deref())
            {
                return Some((pm, canonical));
            }
        }
        None
    }
    #[cfg(target_os = "linux")]
    {
        let homebrew_prefix = std::env::var_os("HOMEBREW_PREFIX");
        let home_env = std::env::var_os("HOME");
        if let Some(pm) = detect_linux_package_manager_path_with_env(
            &exe_raw,
            homebrew_prefix.as_deref(),
            home_env.as_deref(),
        ) {
            return Some((pm, exe_raw));
        }
        if let Ok(canonical) = fs::canonicalize(&exe_raw) {
            if let Some(pm) = detect_linux_package_manager_path_with_env(
                &canonical,
                homebrew_prefix.as_deref(),
                home_env.as_deref(),
            ) {
                return Some((pm, canonical));
            }
        }
        None
    }
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn detect_current_exe_package_manager() -> Option<(PackageManager, PathBuf)> {
    None
}

fn format_check_update_available_message(
    current_version: &str,
    latest_version: &str,
    managed_pm: Option<(PackageManager, &Path)>,
) -> String {
    match managed_pm {
        Some((pm, exe_path)) => format!(
            "Update available: v{current_version} -> {latest_version}. vdpi is managed by {} ({}); run '{}' to update.",
            pm.name(),
            exe_path.display(),
            pm.upgrade_command()
        ),
        None => format!(
            "Update available: v{current_version} -> {latest_version}. Run 'vdpi update' to install."
        ),
    }
}

fn package_manager_self_update_refusal_error(pm: PackageManager, exe_path: &Path) -> anyhow::Error {
    anyhow!(
        "refusing self-update: vdpi appears to be managed by {} ({}); run '{}' to update cleanly, or re-run 'vdpi update --force' to bypass this check",
        pm.name(),
        exe_path.display(),
        pm.upgrade_command()
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionRelation {
    Newer,   // current > installed
    Same,    // current == installed
    Older,   // current < installed
    Unknown, // either side unparseable
}

#[derive(Debug, Clone)]
pub struct ReleaseCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub release_url: String,
    pub release_notes: Vec<String>,
    pub relation: VersionRelation,
    pub asset_name: Option<String>,
    pub asset_url: Option<String>,
    pub sums_url: Option<String>,
    pub installed_service_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

/// Parses a strict `MAJOR.MINOR.PATCH` semantic version.
///
/// Accepts optional leading `"vdpi "` (case-insensitive) and optional leading `'v'`/`'V'`.
/// Rejects prerelease suffixes (`'-'`), build metadata (`'+'`), or non-numeric components.
pub fn parse_semver(raw: &str) -> Option<(u64, u64, u64)> {
    let trimmed = raw.trim();
    let token = if trimmed
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("vdpi"))
        && trimmed
            .as_bytes()
            .get(4)
            .is_some_and(u8::is_ascii_whitespace)
    {
        trimmed[4..].split_whitespace().next()?
    } else {
        trimmed
    };

    let version = token
        .strip_prefix('v')
        .or_else(|| token.strip_prefix('V'))
        .unwrap_or(token);

    if version.contains('-') || version.contains('+') {
        return None;
    }

    let mut parts = version.split('.');
    let major = parse_numeric_component(parts.next()?)?;
    let minor = parse_numeric_component(parts.next()?)?;
    let patch = parse_numeric_component(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

fn parse_numeric_component(part: &str) -> Option<u64> {
    if part.is_empty()
        || (part.len() > 1 && part.starts_with('0'))
        || !part.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    part.parse::<u64>().ok()
}

/// Compares `current` against `installed` using strict semver ordering.
pub fn compare_versions(current: &str, installed: &str) -> VersionRelation {
    match (parse_semver(current), parse_semver(installed)) {
        (Some(cur), Some(inst)) => match cur.cmp(&inst) {
            Ordering::Greater => VersionRelation::Newer,
            Ordering::Equal => VersionRelation::Same,
            Ordering::Less => VersionRelation::Older,
        },
        _ => VersionRelation::Unknown,
    }
}

/// Pure-Rust streaming RFC 6234 / FIPS 180-4 SHA-256 hasher.
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    const INIT_STATE: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    fn new() -> Self {
        Self {
            state: Self::INIT_STATE,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];

            if self.buf_len == 64 {
                compress_block(&mut self.state, &self.buf);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let (chunk, rest) = data.split_at(64);
            let block: &[u8; 64] = chunk.try_into().expect("64-byte SHA-256 block");
            compress_block(&mut self.state, block);
            data = rest;
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);

        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56 {
            self.buf[self.buf_len..64].fill(0);
            compress_block(&mut self.state, &self.buf);
            self.buf_len = 0;
        }

        self.buf[self.buf_len..56].fill(0);
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress_block(&mut self.state, &self.buf);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, word) in w[..16].iter_mut().enumerate() {
        let off = i * 4;
        *word = u32::from_be_bytes([block[off], block[off + 1], block[off + 2], block[off + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for (&k, &wi) in Sha256::K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn encode_hex_lower(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Computes the lowercase 64-character hex RFC 6234 SHA-256 digest of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    encode_hex_lower(&hasher.finalize())
}

/// Computes the lowercase 64-character hex RFC 6234 SHA-256 digest of a file in 64 KiB chunks.
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {} for SHA-256 hashing", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; SHA256_READ_CHUNK_BYTES];

    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed reading {} during SHA-256", path.display()));
            }
        }
    }

    Ok(encode_hex_lower(&hasher.finalize()))
}

/// Extracts the expected lowercase 64-character SHA-256 digest for `asset_name` from `SHA256SUMS.txt`.
pub fn parse_sha256sum_for_asset(sums_text: &str, asset_name: &str) -> Option<String> {
    let expected_basename = asset_name.rsplit(['/', '\\']).next().unwrap_or(asset_name);
    if expected_basename.is_empty()
        || expected_basename == "."
        || expected_basename == ".."
        || expected_basename.contains(['\0', '\r', '\n', ':'])
    {
        return None;
    }

    let sums_text = sums_text.strip_prefix('\u{FEFF}').unwrap_or(sums_text);
    let mut matched_hash: Option<String> = None;

    for raw_line in sums_text.lines() {
        let line = raw_line.trim_matches([' ', '\t']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(split_idx) = line.find([' ', '\t']) else {
            continue;
        };
        let hash = &line[..split_idx];
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }

        let filename_part = line[split_idx..].trim_start_matches([' ', '\t']);
        let filename_clean = filename_part.strip_prefix('*').unwrap_or(filename_part);
        if filename_clean.is_empty()
            || filename_clean.contains(['\0', '\r', ':'])
            || filename_clean.starts_with('/')
            || filename_clean.starts_with('\\')
            || filename_clean.split(['/', '\\']).any(|comp| comp == "..")
        {
            continue;
        }

        let entry_basename = filename_clean
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(filename_clean);

        if entry_basename == expected_basename {
            let normalized_hash = hash.to_ascii_lowercase();
            match &matched_hash {
                Some(existing) if *existing != normalized_hash => return None,
                Some(_) => {}
                None => matched_hash = Some(normalized_hash),
            }
        }
    }

    matched_hash
}

/// Strips a non-UNC Windows extended-length verbatim prefix (`\\?\C:\...` -> `C:\...`)
/// so canonicalized paths remain compatible with Win32 APIs such as `ShellExecuteExW`.
/// Leaves UNC verbatim paths (`\\?\UNC\...`), device paths, and regular paths unchanged.
pub fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    let Some(raw) = path.to_str() else {
        return path.to_path_buf();
    };
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 2
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes.get(2), None | Some(b'\\' | b'/'))
        {
            return PathBuf::from(rest);
        }
    }
    path.to_path_buf()
}

/// Verifies `archive_path` against the matching `asset_name` entry in `sums_text`.
pub fn verify_archive_sha256(archive_path: &Path, sums_text: &str, asset_name: &str) -> Result<()> {
    let expected = parse_sha256sum_for_asset(sums_text, asset_name)
        .ok_or_else(|| anyhow!("asset '{asset_name}' not found in SHA256SUMS.txt"))?;
    let actual = sha256_file(archive_path)?;
    if actual != expected {
        bail!("SHA-256 mismatch for {asset_name}: expected {expected}, got {actual}");
    }
    Ok(())
}

/// Returns the GitHub Release asset filename for the current OS and CPU architecture.
pub fn platform_asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Some("vdpi-windows-x86_64.zip"),
        ("macos", "aarch64" | "x86_64") => Some("vdpi-macos-universal.tar.gz"),
        ("linux", "x86_64") => Some("vdpi-linux-x86_64.tar.gz"),
        ("linux", "aarch64") => Some("vdpi-linux-arm64.tar.gz"),
        _ => None,
    }
}

#[cfg(any(target_os = "windows", test))]
fn is_stale_old_binary_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("vdpi.old") && lower.ends_with(".exe"))
        || (lower.starts_with("wintun.old") && lower.ends_with(".dll"))
}

/// Best-effort cleanup of leftover `vdpi.old*.exe` and `wintun.old*.dll` files
/// created during Windows updates.
pub fn cleanup_stale_old_binary() {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe_raw) = std::env::current_exe() else {
            return;
        };
        let exe = fs::canonicalize(&exe_raw)
            .map(|p| strip_windows_verbatim_prefix(&p))
            .unwrap_or_else(|_| strip_windows_verbatim_prefix(&exe_raw));
        let Some(dir) = exe.parent() else {
            return;
        };
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if is_stale_old_binary_name(name_str) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

struct StagingDir {
    path: PathBuf,
}

impl StagingDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        for attempt in 0u32..32 {
            let candidate = base.join(format!("vdpi-update-{pid}-{nanos}-{attempt}"));
            #[cfg(unix)]
            let create_res = {
                use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&candidate)
                    .and_then(|()| {
                        if let Err(err) =
                            fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                        {
                            let _ = fs::remove_dir(&candidate);
                            return Err(err);
                        }
                        Ok(())
                    })
            };
            #[cfg(not(unix))]
            let create_res = fs::create_dir(&candidate);

            match create_res {
                Ok(()) => return Ok(Self { path: candidate }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("failed to create staging directory {}", candidate.display())
                    });
                }
            }
        }

        bail!(
            "failed to create unique staging directory under {}",
            base.display()
        )
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn format_display_version(raw: &str) -> String {
    if let Some((major, minor, patch)) = parse_semver(raw) {
        format!("{major}.{minor}.{patch}")
    } else {
        raw.trim().trim_start_matches(['v', 'V']).to_string()
    }
}

async fn read_response_text_bounded(
    mut resp: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    if let Some(len) = resp.content_length().filter(|&len| len > max_bytes as u64) {
        bail!("{label} response too large ({len} bytes exceeds {max_bytes}-byte limit)");
    }

    let initial_cap = resp
        .content_length()
        .and_then(|len| usize::try_from(len).ok())
        .map_or(0, |len| len.min(max_bytes));
    let mut buf = Vec::with_capacity(initial_cap);

    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("failed while reading {label} response"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            bail!("{label} response exceeded {max_bytes}-byte limit");
        }
        buf.extend_from_slice(&chunk);
    }

    String::from_utf8(buf).with_context(|| format!("{label} response was not valid UTF-8"))
}

async fn download_to_file(
    client: &mut Client,
    url: &str,
    dest: &Path,
    max_bytes: u64,
) -> Result<()> {
    validate_github_download_url(url, "release archive")?;
    let mut resp = send_get_with_no_proxy_fallback(
        client,
        RedirectTargetPolicy::GitHubDownload,
        url,
        None,
        Some(DOWNLOAD_TIMEOUT),
    )
    .await
    .with_context(|| format!("failed to download {url}"))?;

    if !resp.status().is_success() {
        bail!("failed to download {url} (HTTP {})", resp.status().as_u16());
    }
    validate_github_download_url(resp.url().as_str(), "release archive redirect")?;
    if let Some(len) = resp.content_length().filter(|&len| len > max_bytes) {
        bail!(
            "refusing oversized download from {url} ({len} bytes exceeds {max_bytes}-byte limit)"
        );
    }

    let mut file =
        fs::File::create(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    let mut written: u64 = 0;

    while let Some(chunk) = resp
        .chunk()
        .await
        .with_context(|| format!("failed while streaming download from {url}"))?
    {
        written = written.saturating_add(chunk.len() as u64);
        if written > max_bytes {
            drop(file);
            let _ = fs::remove_file(dest);
            bail!("download from {url} exceeded {max_bytes}-byte limit");
        }
        file.write_all(&chunk)
            .with_context(|| format!("failed writing to {}", dest.display()))?;
    }
    file.flush()
        .with_context(|| format!("failed flushing {}", dest.display()))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn windows_system_directory() -> Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: u32) -> u32;
    }

    let mut buf = vec![0u16; 260];
    loop {
        // SAFETY: `buf` is a writable UTF-16 buffer of length `buf.len()`.
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            bail!("GetSystemDirectoryW failed while locating Windows System32 directory");
        }
        if (len as usize) < buf.len() {
            let dir = OsString::from_wide(&buf[..len as usize]);
            if dir.is_empty() {
                bail!("GetSystemDirectoryW returned an empty System32 directory path");
            }
            return Ok(PathBuf::from(dir));
        }
        buf.resize(len as usize + 1, 0);
    }
}

#[cfg(target_os = "windows")]
fn resolve_tar_command() -> Result<PathBuf> {
    let sys_dir = windows_system_directory()?;
    let system32_tar = sys_dir.join("tar.exe");
    if !system32_tar.is_file() {
        bail!(
            "Windows system tar.exe not found at {}; refusing to search PATH",
            system32_tar.display()
        );
    }
    Ok(system32_tar)
}

#[cfg(target_os = "macos")]
fn resolve_tar_command() -> Result<PathBuf> {
    let path = Path::new("/usr/bin/tar");
    if !path.is_file() {
        bail!("system tar not found at /usr/bin/tar; refusing to search PATH");
    }
    Ok(path.to_path_buf())
}

#[cfg(target_os = "linux")]
fn resolve_tar_command() -> Result<PathBuf> {
    for candidate in ["/usr/bin/tar", "/bin/tar"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    bail!("system tar not found at /usr/bin/tar or /bin/tar; refusing to search PATH")
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn validate_archive_entry(entry: &str) -> Result<()> {
    if entry.is_empty() {
        bail!("archive contains an empty entry path");
    }
    if entry.chars().any(char::is_control) {
        bail!("archive entry contains control characters: {entry:?}");
    }
    if entry.starts_with('/') || entry.starts_with('\\') {
        bail!("archive entry has absolute path: {entry}");
    }
    if entry.contains(':') {
        bail!("archive entry contains forbidden colon: {entry}");
    }
    if entry.contains("..") {
        bail!("archive entry contains parent directory traversal: {entry}");
    }
    if entry.contains(['*', '?', '[', ']']) {
        bail!("archive entry contains forbidden glob metacharacter: {entry}");
    }
    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn archive_name_matches_required(candidate: &str, required_name: &str) -> bool {
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        candidate.eq_ignore_ascii_case(required_name)
    } else {
        candidate == required_name
    }
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn same_normalized_parent(a: &[&str], b: &[&str]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b.iter()).all(|(lhs, rhs)| {
            if cfg!(any(target_os = "windows", target_os = "macos")) {
                lhs.eq_ignore_ascii_case(rhs)
            } else {
                lhs == rhs
            }
        })
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn select_archive_members(
    listing: &str,
    required_name: &str,
    optional_names: &[&str],
) -> Result<Vec<String>> {
    let mut required_match: Option<(&str, Vec<&str>)> = None;
    let mut optional_matches: Vec<Option<(&str, Vec<&str>)>> = vec![None; optional_names.len()];

    for entry in listing.lines() {
        if entry.is_empty() {
            continue;
        }
        validate_archive_entry(entry)?;

        if entry.ends_with('/') || entry.ends_with('\\') {
            continue;
        }

        let segments: Vec<&str> = entry
            .split(['/', '\\'])
            .filter(|seg| !seg.is_empty() && *seg != ".")
            .collect();

        let Some((&last, parent)) = segments.split_last() else {
            continue;
        };

        if archive_name_matches_required(last, required_name) {
            if segments.len() > MAX_EXTRACT_SEARCH_DEPTH + 1 {
                bail!("archive binary entry '{entry}' exceeds maximum nesting depth");
            }
            if let Some((prev, _)) = &required_match {
                bail!(
                    "archive contains multiple '{required_name}' entries ('{prev}' and '{entry}')"
                );
            }
            required_match = Some((entry, parent.to_vec()));
            continue;
        }

        for (idx, &opt_name) in optional_names.iter().enumerate() {
            if last.eq_ignore_ascii_case(opt_name) {
                if segments.len() > MAX_EXTRACT_SEARCH_DEPTH + 1 {
                    bail!("archive companion entry '{entry}' exceeds maximum nesting depth");
                }
                if let Some((prev, _)) = &optional_matches[idx] {
                    bail!(
                        "archive contains multiple '{opt_name}' entries ('{prev}' and '{entry}')"
                    );
                }
                optional_matches[idx] = Some((entry, parent.to_vec()));
                break;
            }
        }
    }

    let (required, required_parent) =
        required_match.ok_or_else(|| anyhow!("archive does not contain '{required_name}'"))?;
    let mut selected = Vec::with_capacity(1 + optional_names.len());
    selected.push(required.to_string());
    for (opt_entry, opt_parent) in optional_matches.into_iter().flatten() {
        if !same_normalized_parent(&required_parent, &opt_parent) {
            bail!(
                "archive companion entry '{opt_entry}' is not in the same directory as '{required}'"
            );
        }
        selected.push(opt_entry.to_string());
    }
    Ok(selected)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn select_archive_binary_member(listing: &str, bin_name: &str) -> Result<String> {
    let mut members = select_archive_members(listing, bin_name, &[])?;
    Ok(members.swap_remove(0))
}

#[cfg(any(target_os = "windows", test))]
fn verify_extracted_windows_companions_against(
    extract_dir: &Path,
    companion_members: &[String],
    sums_text: Option<&str>,
    pinned_wintun_sha: Option<&str>,
) -> Result<()> {
    if companion_members.is_empty() {
        return Ok(());
    }
    let canonical_root = fs::canonicalize(extract_dir).with_context(|| {
        format!(
            "failed to canonicalize extraction directory {}",
            extract_dir.display()
        )
    })?;
    let expected_wintun_sha = sums_text.and_then(|s| parse_sha256sum_for_asset(s, "wintun.dll"));

    for member in companion_members {
        let extracted_path = extract_dir.join(member);
        let verified_path = verify_contained_regular_file(&extracted_path, &canonical_root)?
            .ok_or_else(|| {
                anyhow!(
                    "expected companion file '{member}' was not found inside extracted archive {}",
                    extract_dir.display()
                )
            })?;

        let is_wintun = member
            .rsplit(['/', '\\'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("wintun.dll"));

        if is_wintun {
            let meta = fs::symlink_metadata(&verified_path).with_context(|| {
                format!(
                    "failed to inspect extracted wintun.dll {}",
                    verified_path.display()
                )
            })?;
            if meta.len() == 0 {
                let _ = fs::remove_file(&verified_path);
                bail!("extracted wintun.dll is empty: {}", verified_path.display());
            }
            if sums_text.is_none() && pinned_wintun_sha.is_none() {
                let _ = fs::remove_file(&verified_path);
                bail!(
                    "refusing extracted wintun.dll: SHA256SUMS.txt is absent and no explicit pinned WINTUN_DLL_SHA256 was provided"
                );
            }
            let actual_sha = match sha256_file(&verified_path) {
                Ok(sha) => sha,
                Err(err) => {
                    let _ = fs::remove_file(&verified_path);
                    return Err(err);
                }
            };
            if let Some(expected_sums_sha) = expected_wintun_sha.as_deref() {
                if !actual_sha.eq_ignore_ascii_case(expected_sums_sha) {
                    let _ = fs::remove_file(&verified_path);
                    bail!(
                        "extracted wintun.dll SHA-256 mismatch against SHA256SUMS.txt: expected {expected_sums_sha}, got {actual_sha}"
                    );
                }
            } else if sums_text.is_some() {
                // The parent release zip was already SHA-256 verified against SHA256SUMS.txt.
                // Do not fail-closed against the OLD running binary's compile-time Wintun hash
                // when SHA256SUMS.txt has no separate wintun.dll entry; let the new binary's
                // `install --upgrade` / runtime loader validate its own Wintun pin.
                debug!(
                    path = %verified_path.display(),
                    sha256 = %actual_sha,
                    "extracted wintun.dll accepted via verified archive SHA-256 (no separate SHA256SUMS.txt entry)"
                );
            }
            if let Some(expected_pinned_sha) = pinned_wintun_sha {
                if !actual_sha.eq_ignore_ascii_case(expected_pinned_sha) {
                    let _ = fs::remove_file(&verified_path);
                    bail!(
                        "extracted wintun.dll SHA-256 mismatch against pinned WINTUN_DLL_SHA256: expected {expected_pinned_sha}, got {actual_sha}"
                    );
                }
            }
        }
    }

    Ok(())
}

#[cfg(any(target_os = "windows", test))]
fn verify_extracted_windows_companions(
    extract_dir: &Path,
    companion_members: &[String],
    sums_text: Option<&str>,
) -> Result<()> {
    verify_extracted_windows_companions_against(extract_dir, companion_members, sums_text, None)
}

fn extract_archive(
    archive_path: &Path,
    extract_dir: &Path,
    bin_name: &str,
    sums_text: Option<&str>,
) -> Result<()> {
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        let tar_cmd = resolve_tar_command()?;
        let list_flag = if cfg!(target_os = "windows") {
            "-tf"
        } else {
            "-tzf"
        };
        let mut list_cmd = Command::new(&tar_cmd);
        #[cfg(target_os = "linux")]
        list_cmd.arg("--force-local");
        list_cmd.arg(list_flag).arg(archive_path);

        let list_output = list_cmd.output().with_context(|| {
            format!(
                "failed to run {} to inspect update archive",
                tar_cmd.display()
            )
        })?;
        if !list_output.status.success() {
            bail!(
                "archive inspection failed (exit {:?}): {}",
                list_output.status.code(),
                String::from_utf8_lossy(&list_output.stderr).trim()
            );
        }

        let listing = std::str::from_utf8(&list_output.stdout)
            .context("archive entry listing contains invalid UTF-8")?;
        #[cfg(target_os = "windows")]
        let members = select_archive_members(listing, bin_name, WINDOWS_OPTIONAL_ARCHIVE_MEMBERS)?;
        #[cfg(not(target_os = "windows"))]
        let member = select_archive_binary_member(listing, bin_name)?;

        let mut extract_cmd = Command::new(&tar_cmd);
        if cfg!(target_os = "windows") {
            extract_cmd.arg("-xf");
        } else {
            extract_cmd.arg("-xzf");
        }
        extract_cmd.arg(archive_path).arg("-C").arg(extract_dir);
        #[cfg(target_os = "linux")]
        {
            extract_cmd.arg("--force-local").arg("--no-wildcards");
        }
        #[cfg(unix)]
        {
            extract_cmd
                .arg("--no-same-owner")
                .arg("--no-same-permissions");
        }
        #[cfg(target_os = "windows")]
        extract_cmd.arg("--").args(&members);
        #[cfg(not(target_os = "windows"))]
        extract_cmd.arg("--").arg(member);

        let output = extract_cmd.output().with_context(|| {
            format!(
                "failed to run {} to extract update archive",
                tar_cmd.display()
            )
        })?;
        if !output.status.success() {
            bail!(
                "archive extraction failed (exit {:?}): {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        #[cfg(target_os = "windows")]
        verify_extracted_windows_companions(extract_dir, &members[1..], sums_text)?;
        #[cfg(not(target_os = "windows"))]
        let _ = sums_text;

        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (archive_path, extract_dir, bin_name, sums_text);
        bail!(
            "archive extraction is not supported on {}",
            std::env::consts::OS
        );
    }
}

fn file_name_matches_target(file_name: &OsStr, target_name: &str) -> bool {
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        file_name
            .to_str()
            .is_some_and(|name| name.eq_ignore_ascii_case(target_name))
    } else {
        file_name == OsStr::new(target_name)
    }
}

fn find_extracted_binary(extract_dir: &Path, bin_name: &str) -> Result<PathBuf> {
    let canonical_root = fs::canonicalize(extract_dir).with_context(|| {
        format!(
            "failed to canonicalize extraction directory {}",
            extract_dir.display()
        )
    })?;

    let direct = extract_dir.join(bin_name);
    if let Some(verified) = verify_contained_regular_file(&direct, &canonical_root)? {
        return Ok(verified);
    }

    find_binary_recursive(
        extract_dir,
        &canonical_root,
        bin_name,
        MAX_EXTRACT_SEARCH_DEPTH,
    )?
    .ok_or_else(|| {
        anyhow!(
            "expected binary '{bin_name}' was not found inside extracted archive {}",
            extract_dir.display()
        )
    })
}

fn find_binary_recursive(
    dir: &Path,
    canonical_root: &Path,
    target_name: &str,
    depth_remaining: usize,
) -> Result<Option<PathBuf>> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read extracted directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.file_type().is_file() && file_name_matches_target(&entry.file_name(), target_name) {
            if let Some(verified) = verify_contained_regular_file(&path, canonical_root)? {
                return Ok(Some(verified));
            }
        } else if meta.file_type().is_dir() && depth_remaining > 0 {
            let canonical_dir = fs::canonicalize(&path)?;
            if !canonical_dir.starts_with(canonical_root) {
                bail!(
                    "archive path traversal detected: {}",
                    canonical_dir.display()
                );
            }
            if let Some(found) =
                find_binary_recursive(&path, canonical_root, target_name, depth_remaining - 1)?
            {
                return Ok(Some(found));
            }
        }
    }

    Ok(None)
}

fn verify_contained_regular_file(path: &Path, canonical_root: &Path) -> Result<Option<PathBuf>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    if meta.file_type().is_symlink() {
        bail!(
            "refusing symlinked binary inside extracted archive: {}",
            path.display()
        );
    }
    if !meta.file_type().is_file() {
        return Ok(None);
    }

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize {}", path.display()))?;
    if !canonical.starts_with(canonical_root) {
        bail!(
            "archive path traversal detected: {} escapes {}",
            canonical.display(),
            canonical_root.display()
        );
    }

    let normalized = if cfg!(windows) {
        strip_windows_verbatim_prefix(&canonical)
    } else {
        canonical
    };

    Ok(Some(normalized))
}

#[cfg(target_os = "macos")]
fn ad_hoc_codesign_macos(binary_path: &Path) -> Result<()> {
    let output = Command::new("/usr/bin/codesign")
        .args(["-fs", "-"])
        .arg(binary_path)
        .output()
        .with_context(|| {
            format!(
                "failed to run /usr/bin/codesign for {}",
                binary_path.display()
            )
        })?;
    if !output.status.success() {
        bail!(
            "codesign failed for {} (exit {:?}): {}",
            binary_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_macos_codesigned(binary_path: &Path) -> Result<()> {
    let already_valid = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(binary_path)
        .output()
        .is_ok_and(|output| output.status.success());
    if already_valid {
        return Ok(());
    }
    ad_hoc_codesign_macos(binary_path)
}

#[cfg(unix)]
fn ensure_unix_executable_tree_permissions(
    staging_root: &Path,
    extracted_bin: &Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let canonical_root = fs::canonicalize(staging_root).with_context(|| {
        format!(
            "failed to canonicalize staging root {}",
            staging_root.display()
        )
    })?;
    let canonical_bin = fs::canonicalize(extracted_bin).with_context(|| {
        format!(
            "failed to canonicalize extracted binary {}",
            extracted_bin.display()
        )
    })?;
    if !canonical_bin.starts_with(&canonical_root) {
        bail!(
            "extracted binary {} escapes staging directory {}",
            canonical_bin.display(),
            canonical_root.display()
        );
    }

    // Keep StagingDir strictly owner-only (0o700); root reads/traverses 0o700 directly
    // under sudo without exposing the staging tree in /tmp to other local users.
    fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to enforce 0700 on {}", canonical_root.display()))?;

    let mut subdirs_to_chmod = Vec::new();
    let mut cursor = canonical_bin.parent();
    while let Some(dir) = cursor {
        if dir == canonical_root || dir == staging_root {
            break;
        }
        subdirs_to_chmod.push(dir.to_path_buf());
        cursor = dir.parent();
    }

    let subdir_mode = fs::Permissions::from_mode(0o700);
    for dir in subdirs_to_chmod.into_iter().rev() {
        fs::set_permissions(&dir, subdir_mode.clone())
            .with_context(|| format!("failed to chmod 0700 {}", dir.display()))?;
    }
    fs::set_permissions(&canonical_bin, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod 0755 {}", canonical_bin.display()))?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn is_unix_system_bin_path(path: &Path) -> bool {
    path == Path::new(crate::service::UNIX_SYSTEM_BIN_PATH) || path.starts_with("/usr/local/bin")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn unix_service_upgrade_needs_sudo(installed_service_path: Option<&Path>) -> bool {
    if crate::service::is_unix_root() {
        return false;
    }

    #[cfg(target_os = "macos")]
    let has_system_daemon = Path::new(crate::service::LAUNCH_DAEMON_PLIST_PATH).exists();
    #[cfg(target_os = "linux")]
    let has_system_daemon = Path::new(crate::service::SYSTEMD_SYSTEM_UNIT_PATH).exists();

    let under_system_bin = installed_service_path.is_some_and(is_unix_system_bin_path);
    if has_system_daemon || under_system_bin {
        return true;
    }

    crate::config_file::load_file_config(None, false)
        .ok()
        .and_then(|(_, file_cfg)| file_cfg.engine)
        == Some(crate::config::EngineMode::Tun)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
const TRUSTED_UNIX_SUDO_PATHS: &[&str] = &["/usr/bin/sudo", "/bin/sudo"];

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn resolve_unix_sudo_command() -> Result<PathBuf> {
    TRUSTED_UNIX_SUDO_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            anyhow!(
                "trusted sudo binary not found at /usr/bin/sudo or /bin/sudo; refusing to search PATH"
            )
        })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_unix_sudo_os_args(bin: &Path, args: &[&OsStr], action_description: &str) -> Result<()> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("Root required to {action_description} - run: sudo vdpi update");
    }

    let sudo_bin = resolve_unix_sudo_command()?;

    let status = Command::new(&sudo_bin)
        .args(["-p", "  Password: ", "--"])
        .arg(bin)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| {
            format!("Root required to {action_description} - run: sudo vdpi update")
        })?;

    if !status.success() {
        let code = status
            .code()
            .map_or_else(|| "signal".to_string(), |c| c.to_string());
        bail!("sudo canceled or failed (exit {code}) - try: sudo vdpi update");
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_unix_sudo_binary(bin: &Path, args: &[&str], action_description: &str) -> Result<()> {
    let os_args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    run_unix_sudo_os_args(bin, &os_args, action_description)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn error_is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
    })
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_SEE_MASK_NOCLOSEPROCESS: u32 = 0x0000_0040;
#[cfg(any(target_os = "windows", test))]
const WINDOWS_SEE_MASK_NOASYNC: u32 = 0x0000_0100;
#[cfg(any(target_os = "windows", test))]
const WINDOWS_SEE_MASK_FLAG_NO_UI: u32 = 0x0000_0400;
#[cfg(any(target_os = "windows", test))]
const WINDOWS_ELEVATED_SHELL_EXECUTE_MASK: u32 =
    WINDOWS_SEE_MASK_NOCLOSEPROCESS | WINDOWS_SEE_MASK_NOASYNC | WINDOWS_SEE_MASK_FLAG_NO_UI;

#[cfg(any(target_os = "windows", test))]
fn env_flag_is_truthy(val: &str) -> bool {
    let trimmed = val.trim();
    !trimmed.is_empty()
        && !matches!(
            trimmed.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
}

/// Returns `Some(reason)` when Windows UAC elevation must be refused (headless CI, SSH,
/// explicit `VDPI_NONINTERACTIVE`, or Session 0 Windows service). Intentionally does NOT
/// check `stdin().is_terminal()` / `stdout().is_terminal()` so Git Bash / MSYS2 Mintty
/// PTYs (whose pipes report `!is_terminal()` on Windows) still trigger UAC cleanly.
#[cfg(any(target_os = "windows", test))]
fn windows_elevation_blocked_reason_with<F>(
    is_service: bool,
    mut env_var: F,
) -> Option<&'static str>
where
    F: FnMut(&str) -> Option<String>,
{
    if is_service {
        return Some("running inside a non-interactive Windows service session");
    }
    if env_var("VDPI_NONINTERACTIVE")
        .as_deref()
        .is_some_and(env_flag_is_truthy)
    {
        return Some("VDPI_NONINTERACTIVE is set");
    }
    for key in [
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "TF_BUILD",
        "JENKINS_URL",
        "BUILDKITE",
        "CIRCLECI",
        "APPVEYOR",
        "TEAMCITY_VERSION",
    ] {
        if env_var(key).as_deref().is_some_and(env_flag_is_truthy) {
            return Some("running in a CI/headless environment");
        }
    }
    for key in ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"] {
        if env_var(key)
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            return Some("running inside an SSH session");
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn run_windows_elevated_binary(bin: &Path, args: &[&str]) -> Result<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    if let Some(reason) = windows_elevation_blocked_reason_with(
        crate::platform::windows::is_running_as_service(),
        |key| std::env::var(key).ok(),
    ) {
        bail!(
            "Administrator privileges are required to update the vdpi Windows service ({reason}). Re-run 'vdpi update' from an elevated Administrator terminal."
        );
    }

    type Bool = i32;
    type Dword = u32;

    const COINIT_APARTMENTTHREADED: Dword = 0x0000_0002;
    const COINIT_DISABLE_OLE1DDE: Dword = 0x0000_0004;
    const S_OK: i32 = 0;
    const S_FALSE: i32 = 1;
    const SW_HIDE: i32 = 0;
    const INFINITE: Dword = 0xFFFF_FFFF;
    const WAIT_OBJECT_0: Dword = 0;
    const ERROR_CANCELLED: Dword = 1223;

    #[repr(C)]
    struct ShellExecuteInfoW {
        cb_size: Dword,
        f_mask: Dword,
        hwnd: *mut c_void,
        lp_verb: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show: i32,
        h_inst_app: *mut c_void,
        lp_id_list: *mut c_void,
        lp_class: *const u16,
        hkey_class: *mut c_void,
        dw_hot_key: Dword,
        h_icon_or_monitor: *mut c_void,
        h_process: *mut c_void,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetLastError() -> Dword;
        fn GetSystemDirectoryW(lp_buffer: *mut u16, u_size: Dword) -> Dword;
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: Dword) -> Dword;
        fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut Dword) -> Bool;
        fn CloseHandle(h_object: *mut c_void) -> Bool;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> Bool;
    }

    #[link(name = "ole32")]
    extern "system" {
        fn CoInitializeEx(pv_reserved: *mut c_void, dw_co_init: Dword) -> i32;
        fn CoUninitialize();
    }

    struct ComStaGuard {
        should_uninitialize: bool,
    }

    impl ComStaGuard {
        fn init() -> Self {
            // SAFETY: Initializes COM STA (without OLE1 DDE) on the current thread for
            // `ShellExecuteExW`. Only `S_OK` / `S_FALSE` must be balanced by `CoUninitialize`.
            let hr = unsafe {
                CoInitializeEx(
                    ptr::null_mut(),
                    COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE,
                )
            };
            Self {
                should_uninitialize: hr == S_OK || hr == S_FALSE,
            }
        }
    }

    impl Drop for ComStaGuard {
        fn drop(&mut self) {
            if self.should_uninitialize {
                // SAFETY: Balances the matching `S_OK` / `S_FALSE` `CoInitializeEx` on this thread.
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }

    fn to_wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn resolve_system32_dir() -> PathBuf {
        let mut buf = vec![0u16; 260];
        loop {
            // SAFETY: `buf` is a valid writable UTF-16 buffer of length `buf.len()`.
            let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as Dword) };
            if len == 0 {
                break;
            }
            let len_usize = len as usize;
            if len_usize < buf.len() {
                let dir = String::from_utf16_lossy(&buf[..len_usize]);
                let trimmed = dir.trim();
                if !trimmed.is_empty() {
                    return strip_windows_verbatim_prefix(Path::new(trimmed));
                }
                break;
            }
            buf.resize(len_usize + 1, 0);
        }
        let fallback = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .filter(|v| !v.is_empty())
            .map(|root| PathBuf::from(root).join("System32"))
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32"));
        strip_windows_verbatim_prefix(&fallback)
    }

    let clean_bin = strip_windows_verbatim_prefix(bin);
    let system32_dir = resolve_system32_dir();
    let params: String = args
        .iter()
        .map(|arg| crate::service::quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");

    let verb_wide = to_wide_null(OsStr::new("runas"));
    let file_wide = to_wide_null(clean_bin.as_os_str());
    let params_wide = to_wide_null(OsStr::new(&params));
    let dir_wide = to_wide_null(system32_dir.as_os_str());

    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as Dword,
        f_mask: WINDOWS_ELEVATED_SHELL_EXECUTE_MASK,
        hwnd: ptr::null_mut(),
        lp_verb: verb_wide.as_ptr(),
        lp_file: file_wide.as_ptr(),
        lp_parameters: if params.is_empty() {
            ptr::null()
        } else {
            params_wide.as_ptr()
        },
        lp_directory: dir_wide.as_ptr(),
        n_show: SW_HIDE,
        h_inst_app: ptr::null_mut(),
        lp_id_list: ptr::null_mut(),
        lp_class: ptr::null(),
        hkey_class: ptr::null_mut(),
        dw_hot_key: 0,
        h_icon_or_monitor: ptr::null_mut(),
        h_process: ptr::null_mut(),
    };

    let _com_guard = ComStaGuard::init();
    // SAFETY: `info` and all wide-string buffers live across the `ShellExecuteExW` call.
    let ok = unsafe { ShellExecuteExW(&mut info) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            bail!(
                "UAC elevation was cancelled. Administrator privileges are required to update the vdpi Windows service."
            );
        }
        bail!("ShellExecuteExW(runas) failed with Win32 error {err}");
    }

    if info.h_process.is_null() {
        bail!("ShellExecuteExW(runas) succeeded without returning an elevated process handle");
    }

    let mut exit_code: Dword = 0;
    let wait_res = unsafe { WaitForSingleObject(info.h_process, INFINITE) };
    let wait_err = if wait_res != WAIT_OBJECT_0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };

    let exit_code_err = if wait_err.is_none() {
        let got_exit = unsafe { GetExitCodeProcess(info.h_process, &mut exit_code) };
        if got_exit == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        }
    } else {
        None
    };

    unsafe {
        let _ = CloseHandle(info.h_process);
    }

    if let Some(err) = wait_err {
        bail!(
            "WaitForSingleObject for elevated updater failed (result {wait_res}, Win32 error {err})"
        );
    }
    if let Some(err) = exit_code_err {
        bail!("GetExitCodeProcess for elevated updater failed with Win32 error {err}");
    }
    if exit_code != 0 {
        bail!("elevated updater 'install --upgrade' exited with status code {exit_code}");
    }

    Ok(())
}

fn format_child_failure(label: &str, output: &std::process::Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = stderr
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
        .map(str::trim);

    match detail {
        Some(msg) => anyhow!("{label} failed: {msg}"),
        None => anyhow!("{label} failed with exit status {:?}", output.status.code()),
    }
}

fn run_service_install(
    extracted_bin: &Path,
    staging_root: &Path,
    installed_service_path: Option<&Path>,
) -> Result<()> {
    #[cfg(unix)]
    ensure_unix_executable_tree_permissions(staging_root, extracted_bin)?;
    #[cfg(not(unix))]
    let _ = staging_root;

    #[cfg(target_os = "macos")]
    ensure_macos_codesigned(extracted_bin)?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if unix_service_upgrade_needs_sudo(installed_service_path) {
        return run_unix_sudo_binary(
            extracted_bin,
            &["install", "--upgrade"],
            "update the vdpi background service",
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = installed_service_path;

    #[cfg(target_os = "windows")]
    if !crate::platform::windows_service::is_elevated() {
        run_windows_elevated_binary(extracted_bin, &["install", "--upgrade"])?;
        crate::platform::windows::notify_wininet_refresh();
        crate::platform::windows::broadcast_environment_change();
        return Ok(());
    }

    let output = Command::new(extracted_bin)
        .args(["install", "--upgrade"])
        .stdin(Stdio::null())
        .output()
        .with_context(|| {
            format!(
                "failed to launch extracted updater binary {}",
                extracted_bin.display()
            )
        })?;

    if !output.status.success() {
        return Err(format_child_failure(
            "updated binary 'install --upgrade'",
            &output,
        ));
    }

    #[cfg(target_os = "windows")]
    if !crate::platform::windows::is_running_as_service() {
        crate::platform::windows::notify_wininet_refresh();
        crate::platform::windows::broadcast_environment_change();
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn stage_windows_file_unique(
    src: &Path,
    dir: &Path,
    prefix: &str,
    suffix: &str,
) -> Result<PathBuf> {
    let mut src_file = fs::File::open(src)
        .with_context(|| format!("failed to open source file {}", src.display()))?;

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let mut created: Option<(PathBuf, fs::File)> = None;
    for attempt in 0u32..32 {
        let candidate = dir.join(format!("{prefix}.{pid}-{nanos}-{attempt}{suffix}"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to create staged file {}", candidate.display())
                });
            }
        }
    }

    let (staged_path, mut dst_file) = created.ok_or_else(|| {
        anyhow!(
            "failed to allocate unique staged file ({prefix}.*{suffix}) under {}",
            dir.display()
        )
    })?;

    let copy_sync_res = (|| -> Result<()> {
        io::copy(&mut src_file, &mut dst_file)
            .with_context(|| format!("failed to stage file to {}", staged_path.display()))?;
        dst_file
            .sync_all()
            .with_context(|| format!("failed to sync staged file {}", staged_path.display()))?;
        Ok(())
    })();

    drop(dst_file);
    if let Err(err) = copy_sync_res {
        let _ = fs::remove_file(&staged_path);
        return Err(err);
    }

    Ok(staged_path)
}

#[cfg(target_os = "windows")]
fn unique_windows_backup_path(dir: &Path, prefix: &str, suffix: &str) -> Result<PathBuf> {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    for attempt in 0u32..32 {
        let candidate = dir.join(format!("{prefix}.{pid}-{nanos}-{attempt}{suffix}"));
        match fs::symlink_metadata(&candidate) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "failed to inspect backup path candidate {}",
                        candidate.display()
                    )
                });
            }
        }
    }

    bail!(
        "failed to allocate unique backup path ({prefix}.*{suffix}) under {}",
        dir.display()
    )
}

#[cfg(any(target_os = "windows", test))]
const WINDOWS_RENAME_RETRY_DELAYS_MS: &[u64] = &[25, 50, 100, 200, 300, 500];

#[cfg(any(target_os = "windows", test))]
fn is_transient_windows_rename_error(err: &io::Error) -> bool {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    const ERROR_USER_MAPPED_FILE: i32 = 1224;

    err.kind() == io::ErrorKind::PermissionDenied
        || matches!(
            err.raw_os_error(),
            Some(
                ERROR_ACCESS_DENIED
                    | ERROR_SHARING_VIOLATION
                    | ERROR_LOCK_VIOLATION
                    | ERROR_USER_MAPPED_FILE
            )
        )
}

#[cfg(any(target_os = "windows", test))]
fn retry_windows_rename_with<F, S>(mut op: F, mut sleep_fn: S) -> io::Result<()>
where
    F: FnMut() -> io::Result<()>,
    S: FnMut(Duration),
{
    let mut attempt = 0usize;
    loop {
        match op() {
            Ok(()) => return Ok(()),
            Err(err)
                if is_transient_windows_rename_error(&err)
                    && attempt < WINDOWS_RENAME_RETRY_DELAYS_MS.len() =>
            {
                sleep_fn(Duration::from_millis(
                    WINDOWS_RENAME_RETRY_DELAYS_MS[attempt],
                ));
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(target_os = "windows")]
fn rename_windows_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    retry_windows_rename_with(|| fs::rename(from, to), std::thread::sleep)
}

#[cfg(target_os = "windows")]
fn rollback_windows_file(backup: Option<&Path>, target: &Path) -> Result<()> {
    if let Some(backup_path) = backup {
        rename_windows_with_retry(backup_path, target).with_context(|| {
            format!(
                "failed to restore backup {} to {}",
                backup_path.display(),
                target.display()
            )
        })
    } else {
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| {
                format!("failed to remove newly placed file {}", target.display())
            }),
        }
    }
}

#[cfg(target_os = "windows")]
fn swap_staged_windows_wintun(staged_new: &Path, exe_dir: &Path) -> Result<Option<PathBuf>> {
    let target_wintun = exe_dir.join("wintun.dll");

    let target_exists = match fs::symlink_metadata(&target_wintun) {
        Ok(_) => true,
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(e) => {
            let _ = fs::remove_file(staged_new);
            return Err(e).with_context(|| {
                format!(
                    "failed to inspect existing wintun.dll {}",
                    target_wintun.display()
                )
            });
        }
    };

    let backup_path = if target_exists {
        let backup = match unique_windows_backup_path(exe_dir, "wintun.old", ".dll") {
            Ok(path) => path,
            Err(err) => {
                let _ = fs::remove_file(staged_new);
                return Err(err);
            }
        };
        if let Err(err) = rename_windows_with_retry(&target_wintun, &backup) {
            let _ = fs::remove_file(staged_new);
            return Err(err).with_context(|| {
                format!(
                    "failed to move current wintun.dll {} to {}",
                    target_wintun.display(),
                    backup.display()
                )
            });
        }
        Some(backup)
    } else {
        None
    };

    if let Err(err) = rename_windows_with_retry(staged_new, &target_wintun) {
        let mut rollback_ok = true;
        let rollback_note = match &backup_path {
            Some(backup) => match rollback_windows_file(Some(backup), &target_wintun) {
                Ok(()) => "restored previous wintun.dll".to_string(),
                Err(rb_err) => {
                    rollback_ok = false;
                    format!(
                        "rollback of previous wintun.dll FAILED: {rb_err:#}; preserved staged DLL at {}",
                        staged_new.display()
                    )
                }
            },
            None => "no previous wintun.dll to restore".to_string(),
        };
        if rollback_ok {
            let _ = fs::remove_file(staged_new);
        }
        return Err(err).with_context(|| {
            format!(
                "failed to place new wintun.dll at {} ({rollback_note})",
                target_wintun.display()
            )
        });
    }

    Ok(backup_path)
}

#[cfg(all(target_os = "windows", test))]
fn atomic_swap_windows_wintun(src_wintun: &Path, exe_dir: &Path) -> Result<()> {
    let staged_new = stage_windows_file_unique(src_wintun, exe_dir, "wintun.new", ".dll")?;
    let backup = swap_staged_windows_wintun(&staged_new, exe_dir)?;
    if let Some(backup_path) = backup {
        let _ = fs::remove_file(backup_path);
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_portable_binary_in_dir(
    extracted_bin: &Path,
    current_exe: &Path,
    exe_dir: &Path,
    expected_wintun_sha256: Option<&str>,
) -> Result<()> {
    let staged_wintun_src = extracted_bin
        .parent()
        .map(|dir| dir.join("wintun.dll"))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()));

    // Stage both vdpi.exe and (if present) wintun.dll with sync_all() before mutating live files.
    let staged_new_exe = stage_windows_file_unique(extracted_bin, exe_dir, "vdpi.new", ".exe")?;
    let staged_new_wintun = match staged_wintun_src.as_deref() {
        Some(src_wintun) => {
            let Some(expected_sha) = expected_wintun_sha256 else {
                let _ = fs::remove_file(&staged_new_exe);
                bail!("refusing to stage wintun.dll without a verified expected SHA-256 digest");
            };
            let staged_path =
                match stage_windows_file_unique(src_wintun, exe_dir, "wintun.new", ".dll") {
                    Ok(path) => path,
                    Err(err) => {
                        let _ = fs::remove_file(&staged_new_exe);
                        return Err(err);
                    }
                };
            if let Err(err) =
                crate::platform::windows_tun::verify_wintun_dll_sha256(&staged_path, expected_sha)
            {
                let _ = fs::remove_file(&staged_path);
                let _ = fs::remove_file(&staged_new_exe);
                return Err(err).with_context(|| {
                    format!(
                        "staged wintun.dll failed SHA-256 re-verification: {}",
                        staged_path.display()
                    )
                });
            }
            Some(staged_path)
        }
        None => None,
    };

    // Swap wintun.dll first (retaining wintun_backup until vdpi.exe succeeds) so a locked DLL
    // fails cleanly before vdpi.exe is ever moved.
    let target_wintun = exe_dir.join("wintun.dll");
    let (wintun_swapped, wintun_backup) = if let Some(staged_wintun) = staged_new_wintun.as_deref()
    {
        match swap_staged_windows_wintun(staged_wintun, exe_dir) {
            Ok(backup) => (true, backup),
            Err(err) => {
                let _ = fs::remove_file(&staged_new_exe);
                return Err(err);
            }
        }
    } else {
        (false, None)
    };

    let exe_backup = match unique_windows_backup_path(exe_dir, "vdpi.old", ".exe") {
        Ok(path) => path,
        Err(err) => {
            let _ = fs::remove_file(&staged_new_exe);
            if wintun_swapped {
                if let Err(rb_err) = rollback_windows_file(wintun_backup.as_deref(), &target_wintun)
                {
                    return Err(err).with_context(|| {
                        format!("also failed to roll back wintun.dll: {rb_err:#}")
                    });
                }
            }
            return Err(err);
        }
    };

    if let Err(err) = rename_windows_with_retry(current_exe, &exe_backup) {
        let _ = fs::remove_file(&staged_new_exe);
        let rollback_note = if wintun_swapped {
            match rollback_windows_file(wintun_backup.as_deref(), &target_wintun) {
                Ok(()) => " (rolled back wintun.dll)".to_string(),
                Err(rb_err) => format!(" (wintun.dll rollback FAILED: {rb_err:#})"),
            }
        } else {
            String::new()
        };
        return Err(err).with_context(|| {
            format!(
                "failed to move current binary {} to {}{rollback_note}",
                current_exe.display(),
                exe_backup.display()
            )
        });
    }

    if let Err(err) = rename_windows_with_retry(&staged_new_exe, current_exe) {
        let mut rollback_notes = Vec::new();
        let exe_rollback_ok = match rollback_windows_file(Some(&exe_backup), current_exe) {
            Ok(()) => {
                rollback_notes.push("restored previous binary".to_string());
                true
            }
            Err(rb_err) => {
                rollback_notes.push(format!("previous binary rollback FAILED: {rb_err:#}"));
                false
            }
        };
        if exe_rollback_ok {
            let _ = fs::remove_file(&staged_new_exe);
        } else {
            rollback_notes.push(format!(
                "preserved staged binary at {} for manual recovery",
                staged_new_exe.display()
            ));
        }
        if wintun_swapped {
            match rollback_windows_file(wintun_backup.as_deref(), &target_wintun) {
                Ok(()) => rollback_notes.push("restored previous wintun.dll".to_string()),
                Err(rb_err) => {
                    rollback_notes.push(format!("wintun.dll rollback FAILED: {rb_err:#}"));
                }
            }
        }
        return Err(err).with_context(|| {
            format!(
                "failed to place new binary at {} ({})",
                current_exe.display(),
                rollback_notes.join("; ")
            )
        });
    }

    if let Some(backup) = wintun_backup {
        let _ = fs::remove_file(backup);
    }

    if let Some(src_license) = extracted_bin
        .parent()
        .map(|dir| dir.join("WINTUN-LICENSE.txt"))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()))
    {
        let _ = fs::copy(src_license, exe_dir.join("WINTUN-LICENSE.txt"));
    }

    Ok(())
}

#[cfg(unix)]
fn stage_unix_executable_unique(src: &Path, dir: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut src_file = fs::File::open(src)
        .with_context(|| format!("failed to open updated binary {}", src.display()))?;

    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());

    let mut created: Option<(PathBuf, fs::File)> = None;
    for attempt in 0u32..32 {
        let candidate = dir.join(format!(".vdpi.update.{pid}-{nanos}-{attempt}.tmp"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&candidate)
        {
            Ok(file) => {
                created = Some((candidate, file));
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("failed to create staged binary {}", candidate.display())
                });
            }
        }
    }

    let (tmp_path, mut dst_file) = created.ok_or_else(|| {
        anyhow!(
            "failed to allocate unique staged binary under {}",
            dir.display()
        )
    })?;

    let copy_sync_res = (|| -> Result<()> {
        io::copy(&mut src_file, &mut dst_file)
            .with_context(|| format!("failed to copy updated binary to {}", tmp_path.display()))?;
        dst_file
            .set_permissions(fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod 0755 {}", tmp_path.display()))?;
        dst_file
            .sync_all()
            .with_context(|| format!("failed to sync staged binary {}", tmp_path.display()))?;
        Ok(())
    })();

    drop(dst_file);
    if let Err(err) = copy_sync_res {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    Ok(tmp_path)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn portable_sudo_install_args<'a>(
    extracted_bin: &'a Path,
    current_exe: &'a Path,
    bsd_safe_copy: bool,
) -> Vec<&'a OsStr> {
    let mut args = Vec::with_capacity(if bsd_safe_copy { 6 } else { 5 });
    if bsd_safe_copy {
        // macOS BSD `/usr/bin/install -S` performs an atomic safe copy (temp file + rename).
        args.push(OsStr::new("-S"));
    }
    args.push(OsStr::new("-m"));
    args.push(OsStr::new("0755"));
    args.push(OsStr::new("--"));
    args.push(extracted_bin.as_os_str());
    args.push(current_exe.as_os_str());
    args
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn replace_portable_binary_with_sudo(
    extracted_bin: &Path,
    staging_root: &Path,
    current_exe: &Path,
) -> Result<PathBuf> {
    ensure_unix_executable_tree_permissions(staging_root, extracted_bin)?;
    #[cfg(target_os = "macos")]
    ensure_macos_codesigned(extracted_bin)?;

    let install_bin = ["/usr/bin/install", "/bin/install"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or_else(|| {
            anyhow!(
                "trusted install binary not found at /usr/bin/install or /bin/install; refusing to search PATH"
            )
        })?;

    let args = portable_sudo_install_args(extracted_bin, current_exe, cfg!(target_os = "macos"));
    let action = format!("update {}", current_exe.display());
    run_unix_sudo_os_args(Path::new(install_bin), &args, &action)?;
    Ok(current_exe.to_path_buf())
}

#[cfg(target_os = "windows")]
fn verify_portable_wintun_if_present(
    extracted_bin: &Path,
    sums_text: Option<&str>,
) -> Result<Option<String>> {
    let Some(staged_wintun) = extracted_bin
        .parent()
        .map(|dir| dir.join("wintun.dll"))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()))
    else {
        return Ok(None);
    };
    let meta = fs::symlink_metadata(&staged_wintun).with_context(|| {
        format!(
            "failed to inspect extracted wintun.dll {}",
            staged_wintun.display()
        )
    })?;
    if meta.len() == 0 {
        bail!("extracted wintun.dll is empty: {}", staged_wintun.display());
    }

    if let Some(sums) = sums_text {
        let actual_sha = sha256_file(&staged_wintun)?;
        if let Some(expected_sums_sha) = parse_sha256sum_for_asset(sums, "wintun.dll") {
            if !actual_sha.eq_ignore_ascii_case(&expected_sums_sha) {
                bail!(
                    "refusing to install wintun.dll with SHA-256 mismatch against SHA256SUMS.txt: expected {expected_sums_sha}, got {actual_sha}"
                );
            }
            return Ok(Some(expected_sums_sha));
        }
        // The release zip itself was already SHA-256 verified against SHA256SUMS.txt and has
        // no separate wintun.dll entry. Do not fail-closed against the OLD running binary's
        // compile-time Wintun hash; return the extracted file's SHA-256 so the staged copy
        // in `exe_dir` is still integrity-checked before swapping, and the new binary validates
        // its own Wintun pin at load time.
        debug!(
            path = %staged_wintun.display(),
            sha256 = %actual_sha,
            "portable wintun.dll accepted via verified archive SHA-256 (no separate SHA256SUMS.txt entry)"
        );
        return Ok(Some(actual_sha));
    }

    let expected_sha256 = crate::platform::windows_tun::expected_wintun_dll_sha256()?;
    crate::platform::windows_tun::verify_wintun_dll_sha256(&staged_wintun, expected_sha256)
        .with_context(|| {
            format!(
                "refusing to install unverified wintun.dll during portable update: {}",
                staged_wintun.display()
            )
        })?;
    Ok(Some(expected_sha256.to_string()))
}

fn replace_portable_binary(
    extracted_bin: &Path,
    staging_root: &Path,
    sums_text: Option<&str>,
) -> Result<PathBuf> {
    let current_exe_raw =
        std::env::current_exe().context("failed to determine current executable path")?;
    #[cfg(unix)]
    let current_exe = fs::canonicalize(&current_exe_raw).with_context(|| {
        format!(
            "failed to canonicalize current executable {}",
            current_exe_raw.display()
        )
    })?;
    #[cfg(target_os = "windows")]
    let current_exe = {
        let canonical = fs::canonicalize(&current_exe_raw).with_context(|| {
            format!(
                "failed to canonicalize current executable {}",
                current_exe_raw.display()
            )
        })?;
        strip_windows_verbatim_prefix(&canonical)
    };
    #[cfg(not(any(unix, target_os = "windows")))]
    let current_exe = current_exe_raw;

    let exe_dir = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "current executable {} has no parent directory",
            current_exe.display()
        )
    })?;

    #[cfg(target_os = "windows")]
    {
        let _ = staging_root;
        let expected_wintun_sha = verify_portable_wintun_if_present(extracted_bin, sums_text)?;
        replace_portable_binary_in_dir(
            extracted_bin,
            &current_exe,
            exe_dir,
            expected_wintun_sha.as_deref(),
        )?;
        Ok(current_exe)
    }

    #[cfg(unix)]
    {
        let _ = sums_text;
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = staging_root;

        match stage_unix_executable_unique(extracted_bin, exe_dir) {
            Ok(tmp_path) => {
                #[cfg(target_os = "macos")]
                if let Err(err) = ensure_macos_codesigned(&tmp_path) {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(err);
                }

                match fs::rename(&tmp_path, &current_exe) {
                    Ok(()) => Ok(current_exe),
                    Err(err) => {
                        let _ = fs::remove_file(&tmp_path);
                        #[cfg(any(target_os = "macos", target_os = "linux"))]
                        if err.kind() == io::ErrorKind::PermissionDenied
                            && !crate::service::is_unix_root()
                        {
                            return replace_portable_binary_with_sudo(
                                extracted_bin,
                                staging_root,
                                &current_exe,
                            );
                        }
                        Err(err).with_context(|| {
                            format!(
                                "failed to atomically replace {} with {}",
                                current_exe.display(),
                                tmp_path.display()
                            )
                        })
                    }
                }
            }
            Err(err) => {
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if error_is_permission_denied(&err) && !crate::service::is_unix_root() {
                    return replace_portable_binary_with_sudo(
                        extracted_bin,
                        staging_root,
                        &current_exe,
                    );
                }
                Err(err)
            }
        }
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (extracted_bin, staging_root, sums_text, exe_dir);
        bail!(
            "portable self-update is not supported on {}",
            std::env::consts::OS
        )
    }
}

fn build_updater_client_with_proxy(
    target: RedirectTargetPolicy,
    use_system_proxy: bool,
) -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let user_agent = format!("vdpi/{}", env!("CARGO_PKG_VERSION"));
    let mut builder = Client::builder()
        .user_agent(&user_agent)
        .https_only(true)
        .redirect(build_redirect_policy(target))
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(API_TIMEOUT);
    if !use_system_proxy {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .context("failed to build HTTP client for updater")
}

fn build_updater_client(target: RedirectTargetPolicy) -> Result<Client> {
    build_updater_client_with_proxy(target, true)
}

fn build_direct_updater_client(target: RedirectTargetPolicy) -> Result<Client> {
    build_updater_client_with_proxy(target, false)
}

fn should_retry_direct_without_proxy(err: &reqwest::Error) -> bool {
    if err.is_redirect() {
        return false;
    }
    if err.is_connect() || err.is_timeout() {
        return true;
    }
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(cause) = source {
        let msg = cause.to_string().to_ascii_lowercase();
        if msg.contains("proxy") || msg.contains("tunnel") || msg.contains("socks") {
            return true;
        }
        source = cause.source();
    }
    false
}

async fn send_get_with_no_proxy_fallback(
    client: &mut Client,
    target: RedirectTargetPolicy,
    url: &str,
    accept_header: Option<&str>,
    timeout_override: Option<Duration>,
) -> std::result::Result<reqwest::Response, reqwest::Error> {
    let build_req = |c: &Client| {
        let mut req = c.get(url);
        if let Some(accept) = accept_header {
            req = req.header(reqwest::header::ACCEPT, accept);
        }
        if let Some(timeout) = timeout_override {
            req = req.timeout(timeout);
        }
        req
    };

    match build_req(client).send().await {
        Ok(resp) => Ok(resp),
        Err(first_err) if should_retry_direct_without_proxy(&first_err) => {
            debug!(
                url,
                error = %first_err,
                "updater request failed via default proxy settings; retrying directly without proxy"
            );
            match build_direct_updater_client(target) {
                Ok(direct_client) => {
                    let res = build_req(&direct_client).send().await;
                    if res.is_ok() {
                        *client = direct_client;
                    }
                    res
                }
                Err(_) => Err(first_err),
            }
        }
        Err(err) => Err(err),
    }
}

#[cfg(any(target_os = "windows", test))]
fn extract_windows_service_exe_path(raw_cmdline: Option<&str>) -> Option<PathBuf> {
    let trimmed = raw_cmdline?.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('"') {
        let end = rest.find('"')?;
        let inner = rest[..end].trim();
        return (!inner.is_empty()).then(|| PathBuf::from(inner));
    }
    let lower = trimmed.to_ascii_lowercase();
    if let Some(idx) = lower.find(".exe") {
        let end = idx + 4;
        if trimmed
            .as_bytes()
            .get(end)
            .is_none_or(u8::is_ascii_whitespace)
        {
            let exe = trimmed[..end].trim();
            if !exe.is_empty() {
                return Some(PathBuf::from(exe));
            }
        }
    }
    trimmed
        .split_whitespace()
        .next()
        .filter(|token| !token.is_empty())
        .map(PathBuf::from)
}

#[cfg(any(target_os = "windows", test))]
fn resolve_windows_installed_service_path(
    detected_path: Option<PathBuf>,
    scm_installed: bool,
    scm_binary_path: Option<&str>,
    default_installed_path: Option<PathBuf>,
) -> Option<PathBuf> {
    if detected_path.is_some() {
        return detected_path;
    }
    if !scm_installed {
        return None;
    }
    extract_windows_service_exe_path(scm_binary_path)
        .or(default_installed_path)
        .or_else(|| Some(PathBuf::from("vdpi.exe")))
}

fn extract_release_notes(body: Option<&str>) -> Vec<String> {
    body.map(|notes| {
        notes
            .lines()
            .map(str::trim)
            .filter_map(|line| {
                line.strip_prefix("- ")
                    .or_else(|| line.strip_prefix("* "))
                    .or_else(|| line.strip_prefix("• "))
                    .map(str::trim)
                    .filter(|text| !text.is_empty())
            })
            .take(8)
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// Queries GitHub Releases for the latest `vdpi` release and compares it strictly
/// against `current_version` without invoking blocking service/binary detection.
pub async fn check_latest_release_for_version(
    current_version: &str,
) -> Result<ReleaseCheckResult> {
    let mut client = build_updater_client(RedirectTargetPolicy::GitHubApi)?;

    debug!(
        url = GITHUB_LATEST_RELEASE_URL,
        "checking latest vdpi release"
    );
    let resp = send_get_with_no_proxy_fallback(
        &mut client,
        RedirectTargetPolicy::GitHubApi,
        GITHUB_LATEST_RELEASE_URL,
        Some("application/vnd.github+json"),
        None,
    )
    .await
    .context("failed to contact GitHub Releases API")?;

    if !resp.status().is_success() {
        bail!(
            "GitHub Releases API returned HTTP {}",
            resp.status().as_u16()
        );
    }
    validate_github_api_parsed_url(resp.url(), "GitHub Releases API redirect")?;

    let body_text =
        read_response_text_bounded(resp, MAX_API_BODY_BYTES, "GitHub Releases API").await?;
    let release: GitHubRelease = serde_json::from_str(&body_text)
        .context("failed to parse GitHub Releases API JSON response")?;

    let display_version = format_display_version(current_version);
    let relation = compare_versions(&release.tag_name, current_version);
    let release_notes = extract_release_notes(release.body.as_deref());

    let asset_name = platform_asset_name().map(str::to_string);
    let asset_url = asset_name.as_deref().and_then(|name| {
        release
            .assets
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.browser_download_url.clone())
    });
    let sums_url = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .map(|a| a.browser_download_url.clone());

    Ok(ReleaseCheckResult {
        current_version: display_version,
        latest_version: release.tag_name,
        release_url: release.html_url,
        release_notes,
        relation,
        asset_name,
        asset_url,
        sums_url,
        installed_service_path: None,
    })
}

/// Queries GitHub Releases for the latest `vdpi` release and compares it against
/// the installed (or currently running) version without printing to stdout.
pub async fn check_latest_release() -> Result<ReleaseCheckResult> {
    let installed = crate::service::detect_installed_info();
    let baseline_raw = installed
        .as_ref()
        .and_then(|info| info.installed_version.as_deref())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let mut result = check_latest_release_for_version(baseline_raw).await?;
    let detected_path = installed.map(|info| info.binary_path);
    #[cfg(target_os = "windows")]
    let service_path = if detected_path.is_some() {
        detected_path
    } else {
        let scm = crate::platform::windows_service::query_windows_service_status();
        resolve_windows_installed_service_path(
            None,
            scm.installed,
            scm.binary_path.as_deref(),
            crate::service::installed_binary_path().ok(),
        )
    };
    #[cfg(not(target_os = "windows"))]
    let service_path = detected_path;
    result.installed_service_path = service_path;
    Ok(result)
}

/// Downloads, SHA-256 verifies, extracts, and installs the release described by `check`.
///
/// Emits human-readable status lines exclusively via `on_progress` (zero `println!`),
/// returning a final summary message on success.
pub async fn apply_release_update<F>(
    check: &ReleaseCheckResult,
    force: bool,
    mut on_progress: F,
) -> Result<String>
where
    F: FnMut(&str),
{
    if matches!(
        check.relation,
        VersionRelation::Same | VersionRelation::Older
    ) && !force
    {
        return Ok(format!(
            "vdpi is already up to date (v{}).",
            check.current_version
        ));
    }
    if check.relation == VersionRelation::Unknown && !force {
        bail!(
            "cannot compare current version (v{}) with latest release '{}'; re-run with '--force' to install anyway",
            check.current_version,
            check.latest_version
        );
    }

    let asset_name = check.asset_name.as_deref().ok_or_else(|| {
        anyhow!(
            "no prebuilt release asset is available for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;

    let asset_url = check.asset_url.as_deref().ok_or_else(|| {
        anyhow!(
            "release {} does not contain asset '{asset_name}'",
            check.latest_version
        )
    })?;

    let sums_url = check.sums_url.as_deref().ok_or_else(|| {
        anyhow!(
            "release {} is missing SHA256SUMS.txt; refusing unverified update",
            check.latest_version
        )
    })?;

    validate_github_download_url(asset_url, asset_name)?;
    validate_github_download_url(sums_url, "SHA256SUMS.txt")?;

    let mut client = build_updater_client(RedirectTargetPolicy::GitHubDownload)?;
    let staging = StagingDir::new()?;
    debug!(dir = %staging.path().display(), "created update staging directory");

    on_progress("Downloading SHA256SUMS.txt...");
    let sums_resp = send_get_with_no_proxy_fallback(
        &mut client,
        RedirectTargetPolicy::GitHubDownload,
        sums_url,
        None,
        None,
    )
    .await
    .context("failed to download SHA256SUMS.txt")?;
    if !sums_resp.status().is_success() {
        bail!(
            "failed to download SHA256SUMS.txt (HTTP {})",
            sums_resp.status().as_u16()
        );
    }
    validate_github_download_url(sums_resp.url().as_str(), "SHA256SUMS.txt redirect")?;
    let sums_text =
        read_response_text_bounded(sums_resp, MAX_SUMS_BODY_BYTES, "SHA256SUMS.txt").await?;

    on_progress(&format!("Downloading {asset_name}..."));
    let archive_path = staging.path().join(asset_name);
    download_to_file(&mut client, asset_url, &archive_path, MAX_ARCHIVE_BYTES).await?;

    on_progress("Verifying SHA-256 checksum...");
    verify_archive_sha256(&archive_path, &sums_text, asset_name)?;
    on_progress("SHA-256 verified.");

    on_progress("Extracting update archive...");
    let extract_dir = staging.path().join("extract");
    fs::create_dir(&extract_dir)
        .with_context(|| format!("failed to create {}", extract_dir.display()))?;
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    extract_archive(&archive_path, &extract_dir, bin_name, Some(&sums_text))?;

    let extracted_bin = find_extracted_binary(&extract_dir, bin_name)?;

    let effective_service_path: Option<PathBuf> =
        if let Some(service_path) = check.installed_service_path.as_deref() {
            Some(service_path.to_path_buf())
        } else {
            #[cfg(target_os = "windows")]
            {
                let scm = crate::platform::windows_service::query_windows_service_status();
                resolve_windows_installed_service_path(
                    None,
                    scm.installed,
                    scm.binary_path.as_deref(),
                    crate::service::installed_binary_path().ok(),
                )
            }
            #[cfg(not(target_os = "windows"))]
            {
                None
            }
        };

    if let Some(service_path) = effective_service_path.as_deref() {
        on_progress(&format!(
            "Updating installed vdpi service ({})...",
            service_path.display()
        ));
        run_service_install(&extracted_bin, staging.path(), Some(service_path))?;
        Ok(format!(
            "Successfully updated vdpi service to {}.",
            check.latest_version
        ))
    } else {
        on_progress("Replacing vdpi binary...");
        let updated_path =
            replace_portable_binary(&extracted_bin, staging.path(), Some(&sums_text))?;
        Ok(format!(
            "Successfully updated vdpi to {} at {}.",
            check.latest_version,
            updated_path.display()
        ))
    }
}

/// Checks GitHub Releases for the latest `vdpi` release and optionally downloads,
/// verifies (SHA-256), and installs it for either service or portable deployments.
pub async fn run_update(check_only: bool, force: bool, _cfg: &RuntimeConfig) -> Result<()> {
    let check = check_latest_release().await?;

    println!("Current version : v{}", check.current_version);
    println!("Latest version  : {}", check.latest_version);
    println!("Release URL     : {}", check.release_url);

    if !check.release_notes.is_empty() {
        println!("Release notes   :");
        for bullet in &check.release_notes {
            println!("  - {bullet}");
        }
    }

    if matches!(
        check.relation,
        VersionRelation::Same | VersionRelation::Older
    ) && !force
    {
        println!("vdpi is already up to date (v{}).", check.current_version);
        return Ok(());
    }
    if check.relation == VersionRelation::Unknown && !force {
        if check_only {
            println!(
                "Cannot compare current version (v{}) with latest release '{}'. Re-run with '--force' to install anyway.",
                check.current_version, check.latest_version
            );
            return Ok(());
        }
        bail!(
            "cannot compare current version (v{}) with latest release '{}'; re-run with '--force' to install anyway",
            check.current_version,
            check.latest_version
        );
    }

    let managed_pm = detect_current_exe_package_manager();

    if check_only {
        println!(
            "{}",
            format_check_update_available_message(
                &check.current_version,
                &check.latest_version,
                managed_pm.as_ref().map(|(pm, p)| (*pm, p.as_path())),
            )
        );
        return Ok(());
    }

    if !force {
        if let Some((pm, exe_path)) = managed_pm {
            return Err(package_manager_self_update_refusal_error(pm, &exe_path));
        }
    }

    let summary = apply_release_update(&check, force, |step| {
        println!("{step}");
    })
    .await?;
    println!("{summary}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_semver_variants() {
        assert_eq!(parse_semver("0.3.4"), Some((0, 3, 4)));
        assert_eq!(parse_semver("v0.3.4"), Some((0, 3, 4)));
        assert_eq!(parse_semver("V1.20.300"), Some((1, 20, 300)));
        assert_eq!(parse_semver("vdpi 0.3.4"), Some((0, 3, 4)));
        assert_eq!(parse_semver("VDPI v0.3.4"), Some((0, 3, 4)));
        assert_eq!(parse_semver("  vdpi   0.10.0  \n"), Some((0, 10, 0)));
        assert_eq!(parse_semver("vdpi 0.3.4 (windows)"), Some((0, 3, 4)));
    }

    #[test]
    fn rejects_invalid_and_prerelease_semver() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("vdpi"), None);
        assert_eq!(parse_semver("vdpi   "), None);
        assert_eq!(parse_semver("0.3"), None);
        assert_eq!(parse_semver("0.3.4.5"), None);
        assert_eq!(parse_semver("0.3.4-rc.1"), None);
        assert_eq!(parse_semver("v1.0.0-alpha"), None);
        assert_eq!(parse_semver("0.3.4+build.1"), None);
        assert_eq!(parse_semver("vv0.3.4"), None);
        assert_eq!(parse_semver("+0.3.4"), None);
        assert_eq!(parse_semver("0.3.x"), None);
        assert_eq!(parse_semver("garbage"), None);
        assert_eq!(parse_semver("0.3.4 trailing"), None);
        // Reject multi-digit leading zeros (matching desktop parseSemverTuple)
        assert_eq!(parse_semver("01.2.3"), None);
        assert_eq!(parse_semver("0.03.4"), None);
        assert_eq!(parse_semver("0.3.04"), None);
        assert_eq!(parse_semver("v00.1.2"), None);
        // Single-digit zero components remain valid
        assert_eq!(parse_semver("0.0.0"), Some((0, 0, 0)));
    }

    #[test]
    fn compares_versions_accurately() {
        assert_eq!(compare_versions("0.10.0", "0.9.9"), VersionRelation::Newer);
        assert_eq!(
            compare_versions("v1.0.0", "0.99.99"),
            VersionRelation::Newer
        );
        assert_eq!(
            compare_versions("v0.3.4", "vdpi 0.3.4"),
            VersionRelation::Same
        );
        assert_eq!(compare_versions("0.3.3", "0.3.4"), VersionRelation::Older);
        assert_eq!(
            compare_versions("0.3.4-rc.1", "0.3.4"),
            VersionRelation::Unknown
        );
        assert_eq!(
            compare_versions("0.3.4", "unknown"),
            VersionRelation::Unknown
        );
    }

    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            sha256_hex(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                  ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            ),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        let one_million_a = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_hex(&one_million_a),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn parses_sha256sums_formats() {
        let sums = "\
# Release checksums
BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  vdpi-linux-x86_64.tar.gz
248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1 *vdpi-windows-x86_64.zip
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  ./vdpi-macos-universal.tar.gz
cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1  dist/vdpi-linux-arm64.tar.gz
short_invalid_hash  broken.tar.gz
";

        assert_eq!(
            parse_sha256sum_for_asset(sums, "vdpi-linux-x86_64.tar.gz"),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string())
        );
        assert_eq!(
            parse_sha256sum_for_asset(sums, "vdpi-windows-x86_64.zip"),
            Some("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1".to_string())
        );
        assert_eq!(
            parse_sha256sum_for_asset(sums, "vdpi-macos-universal.tar.gz"),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
        );
        assert_eq!(
            parse_sha256sum_for_asset(sums, "vdpi-linux-arm64.tar.gz"),
            Some("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1".to_string())
        );
        assert_eq!(parse_sha256sum_for_asset(sums, "broken.tar.gz"), None);
        assert_eq!(parse_sha256sum_for_asset(sums, "missing.tar.gz"), None);
    }

    #[test]
    fn verifies_archive_sha256_and_detects_tampering() {
        let staging = StagingDir::new().expect("staging dir");
        let archive_path = staging.path().join("vdpi-test.tar.gz");

        // Larger than 64 KiB so multi-chunk streaming in sha256_file is exercised.
        let mut payload = vec![0x5au8; 150_000];
        payload[0] = 0x11;
        payload[149_999] = 0x22;
        fs::write(&archive_path, &payload).expect("write test archive");

        let expected_hex = sha256_hex(&payload);
        let sums = format!("{}  ./vdpi-test.tar.gz\n", expected_hex.to_uppercase());

        verify_archive_sha256(&archive_path, &sums, "vdpi-test.tar.gz")
            .expect("valid archive must pass SHA-256 verification");

        // Tamper with a single byte and confirm verification fails.
        payload[75_000] ^= 0xff;
        fs::write(&archive_path, &payload).expect("write tampered archive");
        let err = verify_archive_sha256(&archive_path, &sums, "vdpi-test.tar.gz")
            .expect_err("tampered archive must fail SHA-256 verification");
        assert!(
            err.to_string().contains("SHA-256 mismatch"),
            "unexpected error: {err}"
        );

        let missing_err = verify_archive_sha256(&archive_path, &sums, "other.tar.gz")
            .expect_err("missing asset entry must fail");
        assert!(
            missing_err
                .to_string()
                .contains("not found in SHA256SUMS.txt"),
            "unexpected error: {missing_err}"
        );
    }

    #[test]
    fn finds_extracted_binary_safely() {
        let staging = StagingDir::new().expect("staging dir");
        let extract_dir = staging.path().join("extract");
        fs::create_dir(&extract_dir).expect("create extract dir");

        let nested = extract_dir.join("vdpi-pkg");
        fs::create_dir(&nested).expect("create nested dir");
        let bin_path = nested.join("vdpi");
        fs::write(&bin_path, b"binary-bytes").expect("write dummy bin");

        let found = find_extracted_binary(&extract_dir, "vdpi").expect("find nested binary");
        let expected = strip_windows_verbatim_prefix(
            &fs::canonicalize(&bin_path).expect("canonicalize dummy bin"),
        );
        assert_eq!(found, expected);

        let err = find_extracted_binary(&extract_dir, "nonexistent")
            .expect_err("missing binary must error");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn archive_member_selection_blocks_tar_slip_and_duplicates() {
        assert_eq!(
            select_archive_binary_member("vdpi-pkg/\nvdpi-pkg/README.md\nvdpi-pkg/vdpi\n", "vdpi")
                .expect("valid single member"),
            "vdpi-pkg/vdpi"
        );
        assert_eq!(
            select_archive_binary_member("vdpi.exe\r\n", "vdpi.exe")
                .expect("valid windows root member"),
            "vdpi.exe"
        );

        assert!(select_archive_binary_member("../evil\nvdpi\n", "vdpi").is_err());
        assert!(select_archive_binary_member("sub/../vdpi\n", "vdpi").is_err());
        assert!(select_archive_binary_member("/etc/passwd\nvdpi\n", "vdpi").is_err());
        assert!(select_archive_binary_member("\\Windows\\vdpi.exe\n", "vdpi.exe").is_err());
        assert!(select_archive_binary_member("C:\\vdpi.exe\n", "vdpi.exe").is_err());
        assert!(select_archive_binary_member("vdpi\x00evil\n", "vdpi").is_err());
        assert!(select_archive_binary_member("a/vdpi\nb/vdpi\n", "vdpi").is_err());
        assert!(select_archive_binary_member("vdpi/\n", "vdpi").is_err());
    }

    #[test]
    fn windows_multi_member_archive_selection_validates_companions() {
        let nested_listing = "\
vdpi-windows-x86_64/
vdpi-windows-x86_64/README.md
vdpi-windows-x86_64/vdpi.exe
vdpi-windows-x86_64/wintun.dll
vdpi-windows-x86_64/WINTUN-LICENSE.txt
";
        assert_eq!(
            select_archive_members(nested_listing, "vdpi.exe", WINDOWS_OPTIONAL_ARCHIVE_MEMBERS)
                .expect("valid nested windows archive"),
            vec![
                "vdpi-windows-x86_64/vdpi.exe".to_string(),
                "vdpi-windows-x86_64/wintun.dll".to_string(),
                "vdpi-windows-x86_64/WINTUN-LICENSE.txt".to_string(),
            ]
        );

        assert_eq!(
            select_archive_members(
                "vdpi.exe\r\nwintun.dll\r\n",
                "vdpi.exe",
                WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
            )
            .expect("valid flat windows archive"),
            vec!["vdpi.exe".to_string(), "wintun.dll".to_string()]
        );

        // Older / proxy-only archives without wintun.dll remain valid.
        assert_eq!(
            select_archive_members(
                "vdpi-pkg/vdpi.exe\nvdpi-pkg/wintun.dll/\n",
                "vdpi.exe",
                WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
            )
            .expect("archive without wintun.dll"),
            vec!["vdpi-pkg/vdpi.exe".to_string()]
        );

        // Depth == 3 allowed; depth > 3 rejected.
        assert_eq!(
            select_archive_members(
                "a/b/c/vdpi.exe\na/b/c/wintun.dll\n",
                "vdpi.exe",
                WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
            )
            .expect("depth 3 allowed"),
            vec!["a/b/c/vdpi.exe".to_string(), "a/b/c/wintun.dll".to_string(),]
        );
        assert!(select_archive_members(
            "vdpi.exe\na/b/c/d/wintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());

        // Duplicates (including case variants), traversal, and missing vdpi.exe rejected.
        assert!(select_archive_members(
            "vdpi.exe\na/wintun.dll\nb/wintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "vdpi.exe\nwintun.dll\nWINTUN.DLL\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "vdpi.exe\na/WINTUN-LICENSE.txt\nb/wintun-license.txt\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "../evil\nvdpi.exe\nwintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "vdpi.exe\nsub/../wintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "vdpi.exe\nC:\\wintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "wintun.dll\nWINTUN-LICENSE.txt\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
    }

    #[test]
    fn stale_old_binary_cleanup_matches_exe_and_wintun_dll() {
        assert!(is_stale_old_binary_name("vdpi.old.exe"));
        assert!(is_stale_old_binary_name("vdpi.old.1234.exe"));
        assert!(is_stale_old_binary_name("vdpi.old.1234-999999999-0.exe"));
        assert!(is_stale_old_binary_name("VDPI.OLD.EXE"));
        assert!(is_stale_old_binary_name("wintun.old.dll"));
        assert!(is_stale_old_binary_name("wintun.old.5678.dll"));
        assert!(is_stale_old_binary_name("wintun.old.5678-999999999-1.dll"));
        assert!(is_stale_old_binary_name("WINTUN.OLD.99.DLL"));

        assert!(!is_stale_old_binary_name("vdpi.exe"));
        assert!(!is_stale_old_binary_name("wintun.dll"));
        assert!(!is_stale_old_binary_name("wintun.new.1234.dll"));
        assert!(!is_stale_old_binary_name("vdpi.new.1234-999999999-0.exe"));
        assert!(!is_stale_old_binary_name("vdpi.old.dll"));
        assert!(!is_stale_old_binary_name("wintun.old.exe"));
    }

    #[test]
    fn finds_extracted_binary_at_max_depth_three_and_rejects_depth_four() {
        let staging = StagingDir::new().expect("staging dir");
        let extract_dir = staging.path().join("extract");
        let depth3 = extract_dir.join("a").join("b").join("c");
        fs::create_dir_all(&depth3).expect("create depth-3 dir");

        let bin_depth3 = depth3.join("vdpi");
        fs::write(&bin_depth3, b"depth3-binary").expect("write depth-3 binary");

        let found =
            find_extracted_binary(&extract_dir, "vdpi").expect("depth-3 binary must be discovered");
        let expected = strip_windows_verbatim_prefix(
            &fs::canonicalize(&bin_depth3).expect("canonicalize depth-3 binary"),
        );
        assert_eq!(found, expected);

        // Depth 4 must not be traversed.
        fs::remove_file(&bin_depth3).expect("remove depth-3 binary");
        let depth4 = depth3.join("d");
        fs::create_dir(&depth4).expect("create depth-4 dir");
        fs::write(depth4.join("vdpi"), b"depth4-binary").expect("write depth-4 binary");
        assert!(find_extracted_binary(&extract_dir, "vdpi").is_err());
    }

    #[test]
    fn archive_selection_blocks_globs_mismatched_companion_dirs_and_case_dups() {
        // Glob metacharacters must be rejected to prevent bsdtar fnmatch expansion.
        assert!(select_archive_binary_member("vdpi*\n", "vdpi").is_err());
        assert!(select_archive_binary_member("vdpi?\n", "vdpi").is_err());
        assert!(select_archive_binary_member("vdpi[1]\n", "vdpi").is_err());
        assert!(select_archive_binary_member("pkg/foo*bar\npkg/vdpi\n", "vdpi").is_err());

        // Normalized equivalent parent directories succeed.
        assert_eq!(
            select_archive_members(
                "./pkg/vdpi.exe\npkg\\wintun.dll\n./pkg/WINTUN-LICENSE.txt\n",
                "vdpi.exe",
                WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
            )
            .expect("normalized same-parent companions allowed"),
            vec![
                "./pkg/vdpi.exe".to_string(),
                "pkg\\wintun.dll".to_string(),
                "./pkg/WINTUN-LICENSE.txt".to_string(),
            ]
        );

        // Optional companions in a different parent directory than required binary must be rejected.
        assert!(select_archive_members(
            "vdpi.exe\nsub/wintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "sub/vdpi.exe\nwintun.dll\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());
        assert!(select_archive_members(
            "a/vdpi.exe\nb/WINTUN-LICENSE.txt\n",
            "vdpi.exe",
            WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
        )
        .is_err());

        // Case-insensitive duplicate binary names are caught on Windows and macOS.
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            assert!(select_archive_members(
                "vdpi.exe\nVDPI.EXE\n",
                "vdpi.exe",
                WINDOWS_OPTIONAL_ARCHIVE_MEMBERS
            )
            .is_err());
            assert!(select_archive_binary_member("vdpi\nVDPI\n", "vdpi").is_err());
        }
    }

    #[test]
    fn windows_companion_verification_allows_verified_archive_future_wintun_and_rejects_tampering() {
        let staging = StagingDir::new().expect("staging dir");
        let extract_dir = staging.path().join("extract");
        fs::create_dir(&extract_dir).expect("create extract dir");

        let wintun_path = extract_dir.join("wintun.dll");
        let payload = b"future-wintun-payload";
        let payload_sha = sha256_hex(payload);
        let members = vec!["wintun.dll".to_string()];

        // 1. Missing SHA256SUMS.txt altogether (with no explicit pin) must fail closed and delete wintun.dll.
        fs::write(&wintun_path, payload).expect("write wintun");
        let err = verify_extracted_windows_companions(&extract_dir, &members, None)
            .expect_err("wintun.dll without SHA256SUMS.txt must fail closed");
        assert!(
            err.to_string().contains("SHA256SUMS.txt is absent"),
            "unexpected error: {err}"
        );
        assert!(
            !wintun_path.exists(),
            "wintun.dll must be removed when SHA256SUMS.txt is absent"
        );

        // 2. SHA256SUMS.txt present for verified zip without a separate wintun.dll entry must
        //    succeed rather than failing closed against the old binary's compile-time Wintun hash.
        fs::write(&wintun_path, payload).expect("write wintun");
        let archive_only_sums = format!(
            "{}  vdpi-windows-x86_64.zip\n",
            sha256_hex(b"archive-bytes")
        );
        verify_extracted_windows_companions(&extract_dir, &members, Some(&archive_only_sums))
            .expect("wintun.dll inside verified zip without separate SHA256SUMS entry must pass");
        assert!(wintun_path.exists());

        // 3. SHA256SUMS.txt with a matching future wintun.dll hash must succeed without failing
        //    against the old binary's compile-time Wintun pin.
        let future_sums = format!("{payload_sha} *wintun.dll\n");
        verify_extracted_windows_companions(&extract_dir, &members, Some(&future_sums))
            .expect("future wintun.dll matching SHA256SUMS.txt must pass");
        assert!(wintun_path.exists());

        // 4. Mismatched SHA256SUMS.txt entry must fail and delete extracted wintun.dll.
        let bad_sums = format!("{} *wintun.dll\n", sha256_hex(b"different-wintun"));
        assert!(verify_extracted_windows_companions_against(
            &extract_dir,
            &members,
            Some(&bad_sums),
            Some(&payload_sha)
        )
        .is_err());
        assert!(
            !wintun_path.exists(),
            "mismatched wintun.dll must be removed on verification failure"
        );

        // 5. Explicit pinned_wintun_sha mismatch must still fail closed and delete wintun.dll.
        fs::write(&wintun_path, payload).expect("write wintun");
        let wrong_pin = sha256_hex(b"wrong-pin");
        let err = verify_extracted_windows_companions_against(
            &extract_dir,
            &members,
            Some(&future_sums),
            Some(&wrong_pin),
        )
        .expect_err("explicit pinned_wintun_sha mismatch must fail");
        assert!(
            err.to_string().contains("pinned WINTUN_DLL_SHA256"),
            "unexpected error: {err}"
        );
        assert!(
            !wintun_path.exists(),
            "unpinned wintun.dll must be removed on explicit pin mismatch"
        );

        // 6. Empty (0-byte) wintun.dll must fail and be removed even when archive_only_sums is present.
        fs::write(&wintun_path, b"").expect("write empty wintun");
        assert!(
            verify_extracted_windows_companions(&extract_dir, &members, Some(&archive_only_sums))
                .is_err()
        );
        assert!(
            !wintun_path.exists(),
            "empty wintun.dll must be removed on verification failure"
        );

        // 7. Matching BOTH SHA256SUMS.txt and explicit pinned hash succeeds.
        fs::write(&wintun_path, payload).expect("write valid wintun");
        verify_extracted_windows_companions_against(
            &extract_dir,
            &members,
            Some(&future_sums),
            Some(&payload_sha),
        )
        .expect("wintun.dll matching both SHA256SUMS.txt and explicit pin must pass");
        assert!(wintun_path.exists());

        // 8. Non-wintun companion (e.g. WINTUN-LICENSE.txt only) succeeds without wintun entry.
        let license_path = extract_dir.join("WINTUN-LICENSE.txt");
        fs::write(&license_path, b"GPL-2.0").expect("write license");
        verify_extracted_windows_companions(
            &extract_dir,
            &["WINTUN-LICENSE.txt".to_string()],
            Some(&archive_only_sums),
        )
        .expect("license-only companion should pass without wintun.dll entry");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_wintun_atomic_swap_creates_and_replaces() {
        let staging = StagingDir::new().expect("staging dir");
        let src_dir = staging.path().join("src");
        let exe_dir = staging.path().join("exe");
        fs::create_dir(&src_dir).expect("create src dir");
        fs::create_dir(&exe_dir).expect("create exe dir");

        let src_wintun = src_dir.join("wintun.dll");
        fs::write(&src_wintun, b"wintun-v1").expect("write v1 wintun");
        atomic_swap_windows_wintun(&src_wintun, &exe_dir).expect("fresh wintun swap");
        assert_eq!(
            fs::read(exe_dir.join("wintun.dll")).expect("read fresh wintun"),
            b"wintun-v1"
        );

        fs::write(&src_wintun, b"wintun-v2").expect("write v2 wintun");
        atomic_swap_windows_wintun(&src_wintun, &exe_dir).expect("replace wintun swap");
        assert_eq!(
            fs::read(exe_dir.join("wintun.dll")).expect("read replaced wintun"),
            b"wintun-v2"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_portable_multi_member_swap_commits_and_rolls_back_cleanly() {
        let staging = StagingDir::new().expect("staging dir");
        let src_dir = staging.path().join("src");
        let exe_dir = staging.path().join("exe");
        fs::create_dir(&src_dir).expect("create src dir");
        fs::create_dir(&exe_dir).expect("create exe dir");

        let src_exe = src_dir.join("vdpi.exe");
        let src_wintun = src_dir.join("wintun.dll");
        let src_license = src_dir.join("WINTUN-LICENSE.txt");
        fs::write(&src_exe, b"vdpi-v2").expect("write new exe");
        fs::write(&src_wintun, b"wintun-v2").expect("write new wintun");
        fs::write(&src_license, b"license-v2").expect("write new license");

        let live_exe = exe_dir.join("vdpi.exe");
        let live_wintun = exe_dir.join("wintun.dll");
        fs::write(&live_exe, b"vdpi-v1").expect("write old exe");
        fs::write(&live_wintun, b"wintun-v1").expect("write old wintun");

        // Fail closed if expected wintun SHA-256 is absent or mismatched.
        assert!(replace_portable_binary_in_dir(&src_exe, &live_exe, &exe_dir, None).is_err());
        let wrong_sha = sha256_hex(b"wrong-wintun");
        assert!(
            replace_portable_binary_in_dir(&src_exe, &live_exe, &exe_dir, Some(&wrong_sha))
                .is_err()
        );
        assert_eq!(fs::read(&live_exe).expect("live exe untouched"), b"vdpi-v1");
        assert_eq!(
            fs::read(&live_wintun).expect("live wintun untouched"),
            b"wintun-v1"
        );

        let v2_sha = sha256_hex(b"wintun-v2");
        replace_portable_binary_in_dir(&src_exe, &live_exe, &exe_dir, Some(&v2_sha))
            .expect("multi-member portable swap must succeed");
        assert_eq!(fs::read(&live_exe).expect("read new live exe"), b"vdpi-v2");
        assert_eq!(
            fs::read(&live_wintun).expect("read new live wintun"),
            b"wintun-v2"
        );
        assert_eq!(
            fs::read(exe_dir.join("WINTUN-LICENSE.txt")).expect("read license"),
            b"license-v2"
        );

        // Rollback check: when vdpi.exe move fails (missing current_exe), wintun.dll is rolled back.
        fs::write(&src_wintun, b"wintun-v3").expect("write v3 wintun");
        let v3_sha = sha256_hex(b"wintun-v3");
        let missing_exe = exe_dir.join("missing-vdpi.exe");
        assert!(
            replace_portable_binary_in_dir(&src_exe, &missing_exe, &exe_dir, Some(&v3_sha))
                .is_err()
        );
        assert_eq!(
            fs::read(&live_wintun).expect("wintun must be restored after exe rename failure"),
            b"wintun-v2"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_staging_creates_unique_0755_file_with_o_excl() {
        use std::os::unix::fs::PermissionsExt;

        let staging = StagingDir::new().expect("staging dir");
        let src_bin = staging.path().join("vdpi-src");
        fs::write(&src_bin, b"unix-binary-bytes").expect("write src bin");

        let staged_a = stage_unix_executable_unique(&src_bin, staging.path()).expect("stage a");
        let staged_b = stage_unix_executable_unique(&src_bin, staging.path()).expect("stage b");
        assert_ne!(staged_a, staged_b);
        assert_eq!(
            fs::read(&staged_a).expect("read staged a"),
            b"unix-binary-bytes"
        );
        let mode = fs::metadata(&staged_a)
            .expect("stat staged a")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);

        let staging_mode = fs::metadata(staging.path())
            .expect("stat staging dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(staging_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn unix_executable_tree_permissions_keeps_staging_dir_0700() {
        use std::os::unix::fs::PermissionsExt;

        let staging = StagingDir::new().expect("staging dir");
        let nested = staging.path().join("extract").join("pkg");
        fs::create_dir_all(&nested).expect("create nested extract dir");
        let bin = nested.join("vdpi");
        fs::write(&bin, b"unix-bin").expect("write dummy bin");
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o600)).expect("chmod 0600 bin");

        ensure_unix_executable_tree_permissions(staging.path(), &bin)
            .expect("set executable tree permissions");

        let root_mode = fs::metadata(staging.path())
            .expect("stat staging root")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            root_mode, 0o700,
            "StagingDir must remain 0o700 (never widened to 0o755)"
        );
        let nested_mode = fs::metadata(&nested)
            .expect("stat nested dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(nested_mode, 0o700);
        let bin_mode = fs::metadata(&bin)
            .expect("stat extracted bin")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bin_mode, 0o755);
    }

    #[test]
    fn trusted_unix_sudo_paths_exclude_user_writable_locations() {
        assert_eq!(TRUSTED_UNIX_SUDO_PATHS, &["/usr/bin/sudo", "/bin/sudo"]);
        assert!(!TRUSTED_UNIX_SUDO_PATHS.contains(&"/usr/local/bin/sudo"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_resolve_tar_uses_system_directory() {
        let sys_dir = windows_system_directory().expect("GetSystemDirectoryW");
        assert!(sys_dir.is_absolute(), "System32 path must be absolute");
        if sys_dir.join("tar.exe").is_file() {
            let resolved = resolve_tar_command().expect("resolve System32 tar.exe");
            assert_eq!(resolved, sys_dir.join("tar.exe"));
        }
    }

    #[test]
    fn extracts_up_to_eight_release_note_bullets() {
        let body = "\
## Highlights
- Item 1
* Item 2
  • Item 3
Plain paragraph ignored
-   
- Item 4
- Item 5
- Item 6
- Item 7
- Item 8
- Item 9
";
        let notes = extract_release_notes(Some(body));
        assert_eq!(notes.len(), 8);
        assert_eq!(notes[0], "Item 1");
        assert_eq!(notes[1], "Item 2");
        assert_eq!(notes[2], "Item 3");
        assert_eq!(notes[7], "Item 8");
        assert!(extract_release_notes(None).is_empty());
    }

    #[test]
    fn detects_unix_system_bin_paths_and_permission_denied_errors() {
        assert!(is_unix_system_bin_path(Path::new("/usr/local/bin/vdpi")));
        assert!(is_unix_system_bin_path(Path::new(
            "/usr/local/bin/sub/vdpi"
        )));
        assert!(!is_unix_system_bin_path(Path::new(
            "/Users/alice/.vdpi/bin/vdpi"
        )));

        let perm_err =
            anyhow::Error::new(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
                .context("failed to write binary");
        assert!(error_is_permission_denied(&perm_err));

        let other_err = anyhow::Error::new(io::Error::new(io::ErrorKind::NotFound, "missing"));
        assert!(!error_is_permission_denied(&other_err));
    }

    #[tokio::test]
    async fn apply_release_update_handles_up_to_date_and_invalid_urls_without_network() {
        let base_check = ReleaseCheckResult {
            current_version: "0.5.6".to_string(),
            latest_version: "v0.5.6".to_string(),
            release_url: "https://github.com/Vuln-Inc/vdpi/releases/tag/v0.5.6".to_string(),
            release_notes: vec!["- Fix".to_string()],
            relation: VersionRelation::Same,
            asset_name: Some("vdpi-windows-x86_64.zip".to_string()),
            asset_url: Some("https://example.com/vdpi.zip".to_string()),
            sums_url: Some("https://example.com/SHA256SUMS.txt".to_string()),
            installed_service_path: None,
        };

        let mut progress = Vec::new();
        let msg = apply_release_update(&base_check, false, |s| progress.push(s.to_string()))
            .await
            .expect("already up to date should return Ok");
        assert!(msg.contains("already up to date"));
        assert!(progress.is_empty());

        let mut unknown_check = base_check.clone();
        unknown_check.relation = VersionRelation::Unknown;
        let err = apply_release_update(&unknown_check, false, |_| {})
            .await
            .expect_err("unknown relation without force must fail");
        assert!(err.to_string().contains("--force"));

        let mut insecure_check = base_check.clone();
        insecure_check.relation = VersionRelation::Newer;
        insecure_check.asset_url = Some("http://github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip".to_string());
        let err = apply_release_update(&insecure_check, false, |_| {})
            .await
            .expect_err("non-HTTPS asset URL must fail");
        assert!(err.to_string().contains("non-HTTPS"));

        let mut untrusted_check = base_check;
        untrusted_check.relation = VersionRelation::Newer;
        untrusted_check.asset_url = Some("https://example.com/vdpi.zip".to_string());
        let err = apply_release_update(&untrusted_check, false, |_| {})
            .await
            .expect_err("untrusted host URL must fail");
        assert!(err.to_string().contains("untrusted download host"));
    }

    #[test]
    fn validates_github_release_download_hosts_strictly() {
        for ok_url in [
            "https://github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip",
            "https://objects.githubusercontent.com/github-production-release-asset/123",
            "https://release-assets.githubusercontent.com/github-production-release-asset/123",
            "https://codeload.github.com/Vuln-Inc/vdpi/zip/refs/tags/v0.5.6",
        ] {
            validate_github_download_url(ok_url, "asset")
                .unwrap_or_else(|e| panic!("expected allowed GitHub URL {ok_url}: {e:#}"));
        }
        for bad_url in [
            "http://github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip",
            "https://example.com/vdpi.zip",
            "https://evil-github.com/vdpi.zip",
            "https://github.com.evil.test/vdpi.zip",
            "https://github.com/OtherOrg/vdpi/releases/download/v0.5.6/vdpi.zip",
            "https://github.com/Vuln-Inc/other-repo/releases/download/v0.5.6/vdpi.zip",
            "https://github.com/Vuln-Inc/vdpi/raw/main/vdpi.zip",
            "https://github.com/Vuln-Inc/vdpi/releases/download/",
            "https://github.com/Vuln-Inc/vdpi/releases/download/../tag/v0.5.6",
            "https://github.com/Vuln-Inc/vdpi/releases/download/%2e%2e/evil.zip",
            "https://github.com:8443/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip",
            "https://user@github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip",
        ] {
            assert!(
                validate_github_download_url(bad_url, "asset").is_err(),
                "expected rejected URL: {bad_url}"
            );
        }
    }

    #[test]
    fn custom_redirect_policy_validates_every_hop_for_api_and_downloads() {
        // GitHubDownload redirect hops: valid hosts & restricted github.com path allowed up to MAX_REDIRECT_HOPS.
        for (hop, url_str) in [
            (
                1,
                "https://github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi-windows-x86_64.zip",
            ),
            (
                2,
                "https://objects.githubusercontent.com/github-production-release-asset-2e65be/123",
            ),
            (
                3,
                "https://release-assets.githubusercontent.com/github-production-release-asset/456",
            ),
            (
                MAX_REDIRECT_HOPS,
                "https://codeload.github.com/Vuln-Inc/vdpi/zip/refs/tags/v0.5.6",
            ),
        ] {
            let parsed = reqwest::Url::parse(url_str).expect("parse valid download hop");
            validate_redirect_hop(RedirectTargetPolicy::GitHubDownload, &parsed, hop)
                .unwrap_or_else(|e| panic!("hop {hop} to {url_str} must be allowed: {e:#}"));
        }

        // GitHubDownload redirect hops: untrusted hosts, HTTP downgrades, wrong github.com paths, or >5 hops rejected.
        for (hop, url_str) in [
            (1, "https://attacker.example/vdpi.zip"),
            (1, "http://objects.githubusercontent.com/asset/123"),
            (
                1,
                "https://github.com/attacker/vdpi/releases/download/v1.0.0/vdpi.zip",
            ),
            (
                1,
                "https://github.com/Vuln-Inc/vdpi/archive/refs/heads/main.zip",
            ),
            (
                1,
                "https://github.com/Vuln-Inc/vdpi/releases/download/%2e%2e/evil.zip",
            ),
            (
                MAX_REDIRECT_HOPS + 1,
                "https://objects.githubusercontent.com/github-production-release-asset/999",
            ),
        ] {
            let parsed = reqwest::Url::parse(url_str).expect("parse rejected download hop");
            assert!(
                validate_redirect_hop(RedirectTargetPolicy::GitHubDownload, &parsed, hop).is_err(),
                "expected rejected download redirect hop {hop} -> {url_str}"
            );
        }

        // GitHubApi redirect hops: strictly pinned to https://api.github.com on every hop.
        for (hop, url_str) in [
            (
                1,
                "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest",
            ),
            (
                MAX_REDIRECT_HOPS,
                "https://api.github.com/repositories/123456/releases/latest",
            ),
        ] {
            let parsed = reqwest::Url::parse(url_str).expect("parse valid api hop");
            validate_redirect_hop(RedirectTargetPolicy::GitHubApi, &parsed, hop)
                .unwrap_or_else(|e| panic!("api hop {hop} to {url_str} must be allowed: {e:#}"));
        }

        for (hop, url_str) in [
            (1, "http://api.github.com/repos/Vuln-Inc/vdpi/releases/latest"),
            (
                1,
                "https://github.com/Vuln-Inc/vdpi/releases/download/v0.5.6/vdpi.zip",
            ),
            (1, "https://objects.githubusercontent.com/latest"),
            (1, "https://api.github.com.evil.test/repos/Vuln-Inc/vdpi/releases/latest"),
            (1, "https://api.github.com:8443/repos/Vuln-Inc/vdpi/releases/latest"),
            (1, "https://token@api.github.com/repos/Vuln-Inc/vdpi/releases/latest"),
            (
                MAX_REDIRECT_HOPS + 1,
                "https://api.github.com/repos/Vuln-Inc/vdpi/releases/latest",
            ),
        ] {
            let parsed = reqwest::Url::parse(url_str).expect("parse rejected api hop");
            assert!(
                validate_redirect_hop(RedirectTargetPolicy::GitHubApi, &parsed, hop).is_err(),
                "expected rejected API redirect hop {hop} -> {url_str}"
            );
        }

        // Verify both custom-redirect HTTP clients construct cleanly without touching the network.
        build_updater_client(RedirectTargetPolicy::GitHubApi)
            .expect("API client with custom redirect policy must build");
        build_updater_client(RedirectTargetPolicy::GitHubDownload)
            .expect("download client with custom redirect policy must build");
    }

    #[test]
    fn detects_scoop_winget_and_homebrew_install_paths_and_messages() {
        // Default user & global Scoop paths.
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"C:\Users\Alice\scoop\apps\vdpi\current\vdpi.exe"),
                None,
                None,
            ),
            Some(PackageManager::Scoop)
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"C:\ProgramData\scoop\apps\vdpi\0.5.6\vdpi.exe"),
                None,
                None,
            ),
            Some(PackageManager::Scoop)
        );

        // Custom SCOOP and SCOOP_GLOBAL env var roots (with trailing slash & boundary checks).
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"D:\Tools\MyScoop\apps\vdpi\current\vdpi.exe"),
                Some(OsStr::new(r"D:\Tools\MyScoop")),
                None,
            ),
            Some(PackageManager::Scoop)
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"D:\Tools\MyScoop\shims\vdpi.exe"),
                Some(OsStr::new(r"D:\Tools\MyScoop\")),
                None,
            ),
            Some(PackageManager::Scoop)
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"D:\Tools\MyScoop2\apps\vdpi\current\vdpi.exe"),
                Some(OsStr::new(r"D:\Tools\MyScoop")),
                None,
            ),
            None
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"E:\GlobalApps\apps\vdpi\0.5.6\vdpi.exe"),
                None,
                Some(OsStr::new(r"E:/GlobalApps/")),
            ),
            Some(PackageManager::Scoop)
        );

        // User-scope AND machine-scope WinGet paths.
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(
                    r"C:\Users\Alice\AppData\Local\Microsoft\WinGet\Packages\Vuln-Inc.vdpi_Microsoft.Winget.Source_8wekyb3d8bbwe\vdpi.exe"
                ),
                None,
                None,
            ),
            Some(PackageManager::WinGet)
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(
                    r"C:\Program Files\WinGet\Packages\Vuln-Inc.vdpi_Microsoft.Winget.Source_8wekyb3d8bbwe\vdpi.exe"
                ),
                None,
                None,
            ),
            Some(PackageManager::WinGet)
        );
        assert_eq!(
            detect_windows_package_manager_path_with_env(
                Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe"),
                None,
                None,
            ),
            None
        );

        // macOS Homebrew paths (Apple Silicon + Intel) vs manual installs.
        assert_eq!(
            detect_macos_package_manager_path(Path::new("/opt/homebrew/Cellar/vdpi/0.5.6/bin/vdpi")),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_macos_package_manager_path(Path::new("/usr/local/Cellar/vdpi/0.5.6/bin/vdpi")),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_macos_package_manager_path(Path::new("/usr/local/bin/vdpi")),
            None
        );
        assert_eq!(
            detect_macos_package_manager_path(Path::new("/Users/alice/.vdpi/bin/vdpi")),
            None
        );

        // Names & exact upgrade commands.
        assert_eq!(PackageManager::Scoop.name(), "Scoop");
        assert_eq!(PackageManager::WinGet.name(), "WinGet");
        assert_eq!(PackageManager::Homebrew.name(), "Homebrew");
        assert_eq!(PackageManager::Scoop.upgrade_command(), "scoop update vdpi");
        assert_eq!(
            PackageManager::WinGet.upgrade_command(),
            "winget upgrade Vuln-Inc.vdpi"
        );
        assert_eq!(
            PackageManager::Homebrew.upgrade_command(),
            "brew upgrade vdpi"
        );

        // `--check` output must show the package manager command instead of `vdpi update`.
        let scoop_msg = format_check_update_available_message(
            "0.5.6",
            "v0.6.0",
            Some((
                PackageManager::Scoop,
                Path::new(r"C:\Users\Alice\scoop\apps\vdpi\current\vdpi.exe"),
            )),
        );
        assert!(scoop_msg.contains("scoop update vdpi"));
        assert!(!scoop_msg.contains("Run 'vdpi update' to install."));

        let winget_msg = format_check_update_available_message(
            "0.5.6",
            "v0.6.0",
            Some((
                PackageManager::WinGet,
                Path::new(r"C:\Program Files\WinGet\Packages\Vuln-Inc.vdpi\vdpi.exe"),
            )),
        );
        assert!(winget_msg.contains("winget upgrade Vuln-Inc.vdpi"));
        assert!(!winget_msg.contains("Run 'vdpi update' to install."));

        let brew_msg = format_check_update_available_message(
            "0.5.6",
            "v0.6.0",
            Some((
                PackageManager::Homebrew,
                Path::new("/opt/homebrew/Cellar/vdpi/0.5.6/bin/vdpi"),
            )),
        );
        assert!(brew_msg.contains("brew upgrade vdpi"));
        assert!(!brew_msg.contains("Run 'vdpi update' to install."));

        let unmanaged_msg = format_check_update_available_message("0.5.6", "v0.6.0", None);
        assert!(unmanaged_msg.contains("Run 'vdpi update' to install."));

        // Refusal error for non-`--check` self-update carries manager command and `--force` hint.
        let refusal = package_manager_self_update_refusal_error(
            PackageManager::Homebrew,
            Path::new("/opt/homebrew/Cellar/vdpi/0.5.6/bin/vdpi"),
        );
        let refusal_str = refusal.to_string();
        assert!(refusal_str.contains("Homebrew"));
        assert!(refusal_str.contains("brew upgrade vdpi"));
        assert!(refusal_str.contains("--force"));
    }

    #[test]
    fn detects_linuxbrew_install_paths() {
        assert_eq!(
            detect_linux_package_manager_path(Path::new(
                "/home/linuxbrew/.linuxbrew/Cellar/vdpi/0.5.6/bin/vdpi"
            )),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path(Path::new(
                "/home/linuxbrew/.linuxbrew/opt/vdpi/bin/vdpi"
            )),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path(Path::new(
                "/home/linuxbrew/.linuxbrew/Cellar/vdpi2/0.5.6/bin/vdpi"
            )),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path(Path::new(
                "/home/linuxbrew/.linuxbrew/opt/vdpi2/bin/vdpi"
            )),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path(Path::new("/usr/local/bin/vdpi")),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path(Path::new("/home/alice/.local/bin/vdpi")),
            None
        );
    }

    #[test]
    fn detects_custom_homebrew_prefix_and_home_linuxbrew_and_macos_sudo_install_args() {
        // macOS custom $HOMEBREW_PREFIX detection (case-insensitive, Cellar + opt, trailing slash).
        let custom_mac_prefix = OsStr::new("/Users/Alice/Homebrew/");
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("/Users/Alice/Homebrew/Cellar/vdpi/0.5.6/bin/vdpi"),
                Some(custom_mac_prefix),
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("/users/alice/homebrew/opt/vdpi/bin/vdpi"),
                Some(custom_mac_prefix),
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("/Users/Alice/Homebrew/Cellar/vdpi2/0.5.6/bin/vdpi"),
                Some(custom_mac_prefix),
            ),
            None
        );
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("/Users/Alice/Homebrew/bin/vdpi"),
                Some(custom_mac_prefix),
            ),
            None
        );
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("/Cellar/vdpi/0.5.6/bin/vdpi"),
                Some(OsStr::new("/")),
            ),
            None
        );
        assert_eq!(
            detect_macos_package_manager_path_with_env(
                Path::new("homebrew/Cellar/vdpi/0.5.6/bin/vdpi"),
                Some(OsStr::new("homebrew")),
            ),
            None
        );

        // Linux custom $HOMEBREW_PREFIX and $HOME/.linuxbrew detection.
        let custom_linux_prefix = OsStr::new("/opt/custom-brew/");
        let alice_home = OsStr::new("/home/alice/");
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/opt/custom-brew/Cellar/vdpi/0.5.6/bin/vdpi"),
                Some(custom_linux_prefix),
                None,
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/opt/custom-brew/opt/vdpi/bin/vdpi"),
                Some(custom_linux_prefix),
                None,
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/home/alice/.linuxbrew/Cellar/vdpi/0.5.6/bin/vdpi"),
                None,
                Some(alice_home),
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/home/alice/.linuxbrew/opt/vdpi/bin/vdpi"),
                None,
                Some(alice_home),
            ),
            Some(PackageManager::Homebrew)
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/home/alice/.linuxbrew/Cellar/vdpi2/0.5.6/bin/vdpi"),
                None,
                Some(alice_home),
            ),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/home/alice/.linuxbrew/bin/vdpi"),
                None,
                Some(alice_home),
            ),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("/.linuxbrew/Cellar/vdpi/0.5.6/bin/vdpi"),
                None,
                Some(OsStr::new("/")),
            ),
            None
        );
        assert_eq!(
            detect_linux_package_manager_path_with_env(
                Path::new("alice/.linuxbrew/Cellar/vdpi/0.5.6/bin/vdpi"),
                None,
                Some(OsStr::new("alice")),
            ),
            None
        );

        // macOS sudo install uses BSD `-S` safe-copy; Linux GNU install omits `-S`.
        let src = Path::new("/tmp/vdpi-stage/vdpi");
        let dst = Path::new("/usr/local/bin/vdpi");
        assert_eq!(
            portable_sudo_install_args(src, dst, true),
            vec![
                OsStr::new("-S"),
                OsStr::new("-m"),
                OsStr::new("0755"),
                OsStr::new("--"),
                OsStr::new("/tmp/vdpi-stage/vdpi"),
                OsStr::new("/usr/local/bin/vdpi"),
            ]
        );
        assert_eq!(
            portable_sudo_install_args(src, dst, false),
            vec![
                OsStr::new("-m"),
                OsStr::new("0755"),
                OsStr::new("--"),
                OsStr::new("/tmp/vdpi-stage/vdpi"),
                OsStr::new("/usr/local/bin/vdpi"),
            ]
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn portable_wintun_verification_handles_verified_archive_and_rejects_tampered_dll() {
        let staging = StagingDir::new().expect("staging dir");
        let exe = staging.path().join("vdpi.exe");
        fs::write(&exe, b"fake-exe").expect("write fake exe");
        assert_eq!(
            verify_portable_wintun_if_present(&exe, None)
                .expect("missing wintun.dll next to portable exe should pass"),
            None
        );

        let payload = b"future-wintun-bytes";
        let payload_sha = sha256_hex(payload);
        let wintun = staging.path().join("wintun.dll");
        fs::write(&wintun, payload).expect("write wintun");

        // Without SHA256SUMS.txt context, an unpinned DLL is still rejected against expected_wintun_dll_sha256.
        assert!(
            verify_portable_wintun_if_present(&exe, None).is_err(),
            "tampered wintun.dll without SHA256SUMS.txt must be rejected against expected_wintun_dll_sha256"
        );

        // Mismatched SHA256SUMS.txt wintun.dll entry must fail.
        let bad_sums = format!("{}  wintun.dll\n", sha256_hex(b"other-wintun"));
        assert!(verify_portable_wintun_if_present(&exe, Some(&bad_sums)).is_err());

        // Matching future SHA256SUMS.txt wintun.dll entry succeeds.
        let future_sums = format!("{payload_sha}  wintun.dll\n");
        assert_eq!(
            verify_portable_wintun_if_present(&exe, Some(&future_sums))
                .expect("matching future wintun.dll in SHA256SUMS.txt must pass"),
            Some(payload_sha.clone())
        );

        // Verified zip with archive-only SHA256SUMS.txt (no separate wintun.dll entry) succeeds
        // and returns the extracted file's SHA-256 for staging re-verification.
        let archive_only_sums = format!(
            "{}  vdpi-windows-x86_64.zip\n",
            sha256_hex(b"archive-bytes")
        );
        assert_eq!(
            verify_portable_wintun_if_present(&exe, Some(&archive_only_sums))
                .expect("verified zip without separate wintun.dll entry must pass"),
            Some(payload_sha)
        );

        // Empty (0-byte) wintun.dll is always rejected.
        fs::write(&wintun, b"").expect("write empty wintun");
        assert!(verify_portable_wintun_if_present(&exe, Some(&archive_only_sums)).is_err());
    }

    #[test]
    fn windows_rename_retry_uses_defender_backoff_and_skips_non_transient_errors() {
        // Recovers after transient PermissionDenied failures with exact backoff prefix.
        let mut sleeps = Vec::new();
        let mut attempts = 0usize;
        retry_windows_rename_with(
            || {
                attempts += 1;
                if attempts <= 3 {
                    Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "defender scan lock",
                    ))
                } else {
                    Ok(())
                }
            },
            |d| sleeps.push(d.as_millis() as u64),
        )
        .expect("transient rename errors should succeed on retry");
        assert_eq!(attempts, 4);
        assert_eq!(sleeps, vec![25, 50, 100]);

        // Exhausts the full backoff schedule on persistent Win32 sharing violation (error 32).
        let mut full_sleeps = Vec::new();
        let mut full_attempts = 0usize;
        let err = retry_windows_rename_with(
            || {
                full_attempts += 1;
                Err(io::Error::from_raw_os_error(32))
            },
            |d| full_sleeps.push(d.as_millis() as u64),
        )
        .expect_err("persistent sharing violation must eventually fail");
        assert_eq!(err.raw_os_error(), Some(32));
        assert_eq!(full_attempts, WINDOWS_RENAME_RETRY_DELAYS_MS.len() + 1);
        assert_eq!(full_sleeps, WINDOWS_RENAME_RETRY_DELAYS_MS);

        // Non-transient NotFound fails immediately without sleeping.
        let mut no_sleeps = Vec::new();
        let err = retry_windows_rename_with(
            || Err(io::Error::new(io::ErrorKind::NotFound, "missing")),
            |d| no_sleeps.push(d.as_millis() as u64),
        )
        .expect_err("NotFound must fail immediately");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(no_sleeps.is_empty());
    }

    #[test]
    fn windows_elevation_policy_allows_mintty_blocks_headless_and_sets_safe_shell_mask() {
        assert_eq!(
            WINDOWS_ELEVATED_SHELL_EXECUTE_MASK,
            WINDOWS_SEE_MASK_NOCLOSEPROCESS
                | WINDOWS_SEE_MASK_NOASYNC
                | WINDOWS_SEE_MASK_FLAG_NO_UI
        );

        // Interactive desktop / Git Bash Mintty session (no CI/SSH/service flags) is allowed.
        let mintty = |key: &str| match key {
            "MSYSTEM" => Some("MINGW64".to_string()),
            "TERM_PROGRAM" => Some("mintty".to_string()),
            "CI" => Some("false".to_string()),
            "VDPI_NONINTERACTIVE" => Some("0".to_string()),
            _ => None,
        };
        assert_eq!(windows_elevation_blocked_reason_with(false, mintty), None);

        // Session 0 Windows service is blocked.
        assert!(windows_elevation_blocked_reason_with(true, |_| None).is_some());

        // CI, SSH, and explicit VDPI_NONINTERACTIVE are blocked.
        assert!(windows_elevation_blocked_reason_with(false, |k| {
            (k == "CI").then(|| "true".to_string())
        })
        .is_some());
        assert!(windows_elevation_blocked_reason_with(false, |k| {
            (k == "GITHUB_ACTIONS").then(|| "true".to_string())
        })
        .is_some());
        assert!(windows_elevation_blocked_reason_with(false, |k| {
            (k == "SSH_CONNECTION").then(|| "10.0.0.1 5555 10.0.0.2 22".to_string())
        })
        .is_some());
        assert!(windows_elevation_blocked_reason_with(false, |k| {
            (k == "VDPI_NONINTERACTIVE").then(|| "1".to_string())
        })
        .is_some());
    }

    #[test]
    fn windows_scm_service_path_resolution_handles_quarantined_service_binary() {
        let detected = PathBuf::from(r"C:\ProgramData\vdpi\bin\vdpi.exe");
        assert_eq!(
            resolve_windows_installed_service_path(Some(detected.clone()), false, None, None),
            Some(detected)
        );

        // Not installed on disk and not registered in SCM -> portable path (None).
        assert_eq!(
            resolve_windows_installed_service_path(None, false, None, None),
            None
        );

        // Binary quarantined on disk (detected = None), but SCM reports installed with quoted path.
        assert_eq!(
            resolve_windows_installed_service_path(
                None,
                true,
                Some("\"C:\\Program Files\\vdpi\\bin\\vdpi.exe\" --service"),
                Some(PathBuf::from(r"C:\fallback\vdpi.exe")),
            ),
            Some(PathBuf::from(r"C:\Program Files\vdpi\bin\vdpi.exe"))
        );

        // Unquoted SCM binary path with spaces before `.exe`.
        assert_eq!(
            resolve_windows_installed_service_path(
                None,
                true,
                Some(r"C:\Program Files\vdpi\bin\vdpi.exe --service"),
                None,
            ),
            Some(PathBuf::from(r"C:\Program Files\vdpi\bin\vdpi.exe"))
        );

        // SCM reports installed=true with ACCESS_DENIED on config query (binary_path=None) -> fallback path.
        let fallback = PathBuf::from(r"C:\ProgramData\vdpi\bin\vdpi.exe");
        assert_eq!(
            resolve_windows_installed_service_path(None, true, None, Some(fallback.clone())),
            Some(fallback)
        );
        assert_eq!(
            resolve_windows_installed_service_path(None, true, None, None),
            Some(PathBuf::from("vdpi.exe"))
        );
    }

    #[tokio::test]
    async fn updater_direct_no_proxy_client_builds_and_detects_dead_proxy_errors() {
        build_direct_updater_client(RedirectTargetPolicy::GitHubApi)
            .expect("direct API client with no_proxy must build");
        build_direct_updater_client(RedirectTargetPolicy::GitHubDownload)
            .expect("direct download client with no_proxy must build");

        // Bind and immediately drop a loopback listener to obtain a guaranteed-dead local proxy port.
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            listener.local_addr().expect("local addr").port()
        };
        let proxy_url = format!("http://127.0.0.1:{dead_port}");
        let dead_proxy_client = Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).expect("build dead proxy"))
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("build client with dead proxy");

        let err = dead_proxy_client
            .get("https://127.0.0.1:1/")
            .send()
            .await
            .expect_err("dead local proxy must error");
        assert!(
            should_retry_direct_without_proxy(&err),
            "expected dead local proxy error to trigger direct no_proxy fallback, got: {err:#}"
        );
    }
}
