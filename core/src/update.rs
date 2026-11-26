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
const API_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_API_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_SUMS_BODY_BYTES: usize = 256 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 128 * 1024 * 1024;
const SHA256_READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_EXTRACT_SEARCH_DEPTH: usize = 3;
#[cfg(any(target_os = "windows", test))]
const WINDOWS_OPTIONAL_ARCHIVE_MEMBERS: &[&str] = &["wintun.dll", "WINTUN-LICENSE.txt"];

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
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
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
                    .mode(0o755)
                    .create(&candidate)
                    .map(|()| {
                        let _ = fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755));
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

async fn download_to_file(client: &Client, url: &str, dest: &Path, max_bytes: u64) -> Result<()> {
    let mut resp = client
        .get(url)
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("failed to download {url}"))?;

    if !resp.status().is_success() {
        bail!("failed to download {url} (HTTP {})", resp.status().as_u16());
    }
    if resp.url().scheme() != "https" {
        bail!("refusing non-HTTPS redirect destination: {}", resp.url());
    }
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
fn resolve_tar_command() -> PathBuf {
    let sys_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let system32_tar = sys_root.join("System32").join("tar.exe");
    if system32_tar.is_file() {
        system32_tar
    } else {
        PathBuf::from("tar")
    }
}

#[cfg(target_os = "macos")]
fn resolve_tar_command() -> PathBuf {
    PathBuf::from("/usr/bin/tar")
}

#[cfg(target_os = "linux")]
fn resolve_tar_command() -> PathBuf {
    for candidate in ["/usr/bin/tar", "/bin/tar"] {
        let path = Path::new(candidate);
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    PathBuf::from("tar")
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
fn verify_extracted_windows_companions(
    extract_dir: &Path,
    companion_members: &[String],
    sums_text: Option<&str>,
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
            if let Some(expected_sha) = expected_wintun_sha.as_deref() {
                let actual_sha = sha256_file(&verified_path)?;
                if !actual_sha.eq_ignore_ascii_case(expected_sha) {
                    let _ = fs::remove_file(&verified_path);
                    bail!(
                        "extracted wintun.dll SHA-256 mismatch: expected {expected_sha}, got {actual_sha}"
                    );
                }
            }
        }
    }

    Ok(())
}

fn extract_archive(
    archive_path: &Path,
    extract_dir: &Path,
    bin_name: &str,
    sums_text: Option<&str>,
) -> Result<()> {
    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        let tar_cmd = resolve_tar_command();
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

    let mode = fs::Permissions::from_mode(0o755);
    let canonical_root =
        fs::canonicalize(staging_root).unwrap_or_else(|_| staging_root.to_path_buf());
    let mut dirs_to_chmod = Vec::new();
    let mut cursor = extracted_bin.parent();
    while let Some(dir) = cursor {
        dirs_to_chmod.push(dir.to_path_buf());
        if dir == staging_root || dir == canonical_root {
            break;
        }
        cursor = dir.parent();
    }
    if !dirs_to_chmod
        .iter()
        .any(|d| d == staging_root || d == &canonical_root)
    {
        dirs_to_chmod.push(staging_root.to_path_buf());
    }

    for dir in dirs_to_chmod.into_iter().rev() {
        fs::set_permissions(&dir, mode.clone())
            .with_context(|| format!("failed to chmod 0755 {}", dir.display()))?;
    }
    fs::set_permissions(extracted_bin, mode)
        .with_context(|| format!("failed to chmod 0755 {}", extracted_bin.display()))?;
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

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run_unix_sudo_os_args(bin: &Path, args: &[&OsStr], action_description: &str) -> Result<()> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!("Root required to {action_description} - run: sudo vdpi update");
    }

    let sudo_bin = ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or("sudo");

    let status = Command::new(sudo_bin)
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

#[cfg(target_os = "windows")]
fn run_windows_elevated_binary(bin: &Path, args: &[&str]) -> Result<()> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    type Bool = i32;
    type Dword = u32;

    const SEE_MASK_NOCLOSEPROCESS: Dword = 0x0000_0040;
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
        fn WaitForSingleObject(h_handle: *mut c_void, dw_milliseconds: Dword) -> Dword;
        fn GetExitCodeProcess(h_process: *mut c_void, lp_exit_code: *mut Dword) -> Bool;
        fn CloseHandle(h_object: *mut c_void) -> Bool;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteExW(p_exec_info: *mut ShellExecuteInfoW) -> Bool;
    }

    fn to_wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    let clean_bin = strip_windows_verbatim_prefix(bin);
    let temp_dir = strip_windows_verbatim_prefix(&std::env::temp_dir());
    let params: String = args
        .iter()
        .map(|arg| crate::service::quote_windows_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");

    let verb_wide = to_wide_null(OsStr::new("runas"));
    let file_wide = to_wide_null(clean_bin.as_os_str());
    let params_wide = to_wide_null(OsStr::new(&params));
    let dir_wide = to_wide_null(temp_dir.as_os_str());

    let mut info = ShellExecuteInfoW {
        cb_size: std::mem::size_of::<ShellExecuteInfoW>() as Dword,
        f_mask: SEE_MASK_NOCLOSEPROCESS,
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

#[cfg(target_os = "windows")]
fn rollback_windows_file(backup: Option<&Path>, target: &Path) -> Result<()> {
    if let Some(backup_path) = backup {
        fs::rename(backup_path, target).with_context(|| {
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
            return Err(e).with_context(|| {
                format!(
                    "failed to inspect existing wintun.dll {}",
                    target_wintun.display()
                )
            });
        }
    };

    let backup_path = if target_exists {
        let backup = unique_windows_backup_path(exe_dir, "wintun.old", ".dll")?;
        if let Err(err) = fs::rename(&target_wintun, &backup) {
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

    if let Err(err) = fs::rename(staged_new, &target_wintun) {
        let _ = fs::remove_file(staged_new);
        let rollback_note = match &backup_path {
            Some(backup) => match rollback_windows_file(Some(backup), &target_wintun) {
                Ok(()) => "restored previous wintun.dll".to_string(),
                Err(rb_err) => format!("rollback of previous wintun.dll FAILED: {rb_err:#}"),
            },
            None => "no previous wintun.dll to restore".to_string(),
        };
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
    let backup = match swap_staged_windows_wintun(&staged_new, exe_dir) {
        Ok(backup) => backup,
        Err(err) => {
            let _ = fs::remove_file(&staged_new);
            return Err(err);
        }
    };
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
) -> Result<()> {
    let staged_wintun_src = extracted_bin
        .parent()
        .map(|dir| dir.join("wintun.dll"))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file()));

    // Stage both vdpi.exe and (if present) wintun.dll with sync_all() before mutating live files.
    let staged_new_exe = stage_windows_file_unique(extracted_bin, exe_dir, "vdpi.new", ".exe")?;
    let staged_new_wintun = match staged_wintun_src.as_deref() {
        Some(src_wintun) => {
            match stage_windows_file_unique(src_wintun, exe_dir, "wintun.new", ".dll") {
                Ok(path) => Some(path),
                Err(err) => {
                    let _ = fs::remove_file(&staged_new_exe);
                    return Err(err);
                }
            }
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
                let _ = fs::remove_file(staged_wintun);
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

    if let Err(err) = fs::rename(current_exe, &exe_backup) {
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

    if let Err(err) = fs::rename(&staged_new_exe, current_exe) {
        let _ = fs::remove_file(&staged_new_exe);
        let mut rollback_notes = Vec::new();
        match rollback_windows_file(Some(&exe_backup), current_exe) {
            Ok(()) => rollback_notes.push("restored previous binary".to_string()),
            Err(rb_err) => {
                rollback_notes.push(format!("previous binary rollback FAILED: {rb_err:#}"));
            }
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
        .unwrap_or("install");

    let args = [
        OsStr::new("-m"),
        OsStr::new("0755"),
        OsStr::new("--"),
        extracted_bin.as_os_str(),
        current_exe.as_os_str(),
    ];
    let action = format!("update {}", current_exe.display());
    run_unix_sudo_os_args(Path::new(install_bin), &args, &action)?;
    Ok(current_exe.to_path_buf())
}

fn replace_portable_binary(extracted_bin: &Path, staging_root: &Path) -> Result<PathBuf> {
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
        replace_portable_binary_in_dir(extracted_bin, &current_exe, exe_dir)?;
        Ok(current_exe)
    }

    #[cfg(unix)]
    {
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let _ = staging_root;

        match stage_unix_executable_unique(extracted_bin, exe_dir) {
            Ok(tmp_path) => {
                #[cfg(target_os = "macos")]
                if let Err(err) = ad_hoc_codesign_macos(&tmp_path) {
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
        let _ = (extracted_bin, staging_root, exe_dir);
        bail!(
            "portable self-update is not supported on {}",
            std::env::consts::OS
        )
    }
}

fn build_updater_client() -> Result<Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let user_agent = format!("vdpi/{}", env!("CARGO_PKG_VERSION"));
    Client::builder()
        .user_agent(&user_agent)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(API_TIMEOUT)
        .build()
        .context("failed to build HTTP client for updater")
}

fn extract_release_notes(body: Option<&str>) -> Vec<String> {
    body.map(|notes| {
        notes
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("- ") || line.starts_with("* "))
            .take(8)
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// Queries GitHub Releases for the latest `vdpi` release and compares it against
/// the installed (or currently running) version without printing to stdout.
pub async fn check_latest_release() -> Result<ReleaseCheckResult> {
    let client = build_updater_client()?;

    debug!(
        url = GITHUB_LATEST_RELEASE_URL,
        "checking latest vdpi release"
    );
    let resp = client
        .get(GITHUB_LATEST_RELEASE_URL)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .context("failed to contact GitHub Releases API")?;

    if !resp.status().is_success() {
        bail!(
            "GitHub Releases API returned HTTP {}",
            resp.status().as_u16()
        );
    }
    if resp.url().scheme() != "https" {
        bail!(
            "refusing non-HTTPS redirect for GitHub Releases API: {}",
            resp.url()
        );
    }

    let body_text =
        read_response_text_bounded(resp, MAX_API_BODY_BYTES, "GitHub Releases API").await?;
    let release: GitHubRelease = serde_json::from_str(&body_text)
        .context("failed to parse GitHub Releases API JSON response")?;

    let installed = crate::service::detect_installed_info();
    let baseline_raw = installed
        .as_ref()
        .and_then(|info| info.installed_version.as_deref())
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let current_version = format_display_version(baseline_raw);
    let relation = compare_versions(&release.tag_name, baseline_raw);
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
        current_version,
        latest_version: release.tag_name,
        release_url: release.html_url,
        release_notes,
        relation,
        asset_name,
        asset_url,
        sums_url,
        installed_service_path: installed.map(|info| info.binary_path),
    })
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

    if !asset_url.starts_with("https://") {
        bail!("refusing non-HTTPS download URL for {asset_name}: {asset_url}");
    }
    if !sums_url.starts_with("https://") {
        bail!("refusing non-HTTPS download URL for SHA256SUMS.txt: {sums_url}");
    }

    let client = build_updater_client()?;
    let staging = StagingDir::new()?;
    debug!(dir = %staging.path().display(), "created update staging directory");

    on_progress("Downloading SHA256SUMS.txt...");
    let sums_resp = client
        .get(sums_url)
        .send()
        .await
        .context("failed to download SHA256SUMS.txt")?;
    if !sums_resp.status().is_success() {
        bail!(
            "failed to download SHA256SUMS.txt (HTTP {})",
            sums_resp.status().as_u16()
        );
    }
    if sums_resp.url().scheme() != "https" {
        bail!(
            "refusing non-HTTPS redirect for SHA256SUMS.txt: {}",
            sums_resp.url()
        );
    }
    let sums_text =
        read_response_text_bounded(sums_resp, MAX_SUMS_BODY_BYTES, "SHA256SUMS.txt").await?;

    on_progress(&format!("Downloading {asset_name}..."));
    let archive_path = staging.path().join(asset_name);
    download_to_file(&client, asset_url, &archive_path, MAX_ARCHIVE_BYTES).await?;

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

    if let Some(service_path) = check.installed_service_path.as_deref() {
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
        let updated_path = replace_portable_binary(&extracted_bin, staging.path())?;
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
            println!("  {bullet}");
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

    if check_only {
        println!(
            "Update available: v{} -> {}. Run 'vdpi update' to install.",
            check.current_version, check.latest_version
        );
        return Ok(());
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
    fn windows_companion_verification_future_proofs_wintun_bumps_and_honors_sums() {
        let staging = StagingDir::new().expect("staging dir");
        let extract_dir = staging.path().join("extract");
        fs::create_dir(&extract_dir).expect("create extract dir");

        let wintun_path = extract_dir.join("wintun.dll");
        let future_bytes = b"future-wintun-0.15.0-payload";
        fs::write(&wintun_path, future_bytes).expect("write future wintun");

        let members = vec!["wintun.dll".to_string()];

        // When SHA256SUMS.txt has no standalone wintun.dll entry, any non-empty regular file passes.
        let archive_only_sums = format!(
            "{}  vdpi-windows-x86_64.zip\n",
            sha256_hex(b"archive-bytes")
        );
        verify_extracted_windows_companions(&extract_dir, &members, Some(&archive_only_sums))
            .expect("future wintun.dll must not fail when not explicitly pinned in SHA256SUMS.txt");

        // When SHA256SUMS.txt explicitly includes wintun.dll, matching digest passes.
        let matching_sums = format!("{} *wintun.dll\n", sha256_hex(future_bytes));
        verify_extracted_windows_companions(&extract_dir, &members, Some(&matching_sums))
            .expect("explicit matching wintun.dll hash in SHA256SUMS.txt must pass");

        // Mismatched explicit wintun.dll hash must fail and remove the extracted file.
        let bad_sums = format!("{} *wintun.dll\n", sha256_hex(b"different-wintun"));
        assert!(
            verify_extracted_windows_companions(&extract_dir, &members, Some(&bad_sums)).is_err()
        );
        assert!(
            !wintun_path.exists(),
            "mismatched wintun.dll must be removed on verification failure"
        );

        // Empty (0-byte) wintun.dll must fail and be removed even without a SHA256SUMS entry.
        fs::write(&wintun_path, b"").expect("write empty wintun");
        assert!(verify_extracted_windows_companions(&extract_dir, &members, None).is_err());
        assert!(
            !wintun_path.exists(),
            "empty wintun.dll must be removed on verification failure"
        );
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

        replace_portable_binary_in_dir(&src_exe, &live_exe, &exe_dir)
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
        let missing_exe = exe_dir.join("missing-vdpi.exe");
        assert!(replace_portable_binary_in_dir(&src_exe, &missing_exe, &exe_dir).is_err());
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
        assert_eq!(staging_mode, 0o755);
    }

    #[test]
    fn extracts_up_to_eight_release_note_bullets() {
        let body = "\
## Highlights
- Item 1
* Item 2
  - Item 3
Plain paragraph ignored
- Item 4
- Item 5
- Item 6
- Item 7
- Item 8
- Item 9
";
        let notes = extract_release_notes(Some(body));
        assert_eq!(notes.len(), 8);
        assert_eq!(notes[0], "- Item 1");
        assert_eq!(notes[1], "* Item 2");
        assert_eq!(notes[2], "- Item 3");
        assert_eq!(notes[7], "- Item 8");
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

        let mut insecure_check = base_check;
        insecure_check.relation = VersionRelation::Newer;
        insecure_check.asset_url = Some("http://example.com/vdpi.zip".to_string());
        let err = apply_release_update(&insecure_check, false, |_| {})
            .await
            .expect_err("non-HTTPS asset URL must fail");
        assert!(err.to_string().contains("non-HTTPS"));
    }
}
