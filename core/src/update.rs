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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionRelation {
    Newer,   // current > installed
    Same,    // current == installed
    Older,   // current < installed
    Unknown, // either side unparseable
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
        for (out, word) in digest.chunks_exact_mut(4).zip(self.state.iter()) {
            out.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

fn compress_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
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

/// Best-effort cleanup of leftover `vdpi.old*.exe` binaries created during Windows updates.
pub fn cleanup_stale_old_binary() {
    #[cfg(target_os = "windows")]
    {
        let Ok(exe) = std::env::current_exe() else {
            return;
        };
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
            let lower = name_str.to_ascii_lowercase();
            if lower.starts_with("vdpi.old") && lower.ends_with(".exe") {
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
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&candidate)
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
    Ok(())
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn select_archive_binary_member(listing: &str, bin_name: &str) -> Result<String> {
    let mut matched: Option<String> = None;

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

        let Some(&last) = segments.last() else {
            continue;
        };

        if last == bin_name {
            if segments.len() > MAX_EXTRACT_SEARCH_DEPTH + 1 {
                bail!("archive binary entry '{entry}' exceeds maximum nesting depth");
            }
            if let Some(prev) = &matched {
                bail!("archive contains multiple '{bin_name}' entries ('{prev}' and '{entry}')");
            }
            matched = Some(entry.to_string());
        }
    }

    matched.ok_or_else(|| anyhow!("archive does not contain '{bin_name}'"))
}

fn extract_archive(archive_path: &Path, extract_dir: &Path, bin_name: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    let tar_cmd = resolve_tar_command();
    #[cfg(target_os = "macos")]
    let tar_cmd = PathBuf::from("/usr/bin/tar");
    #[cfg(target_os = "linux")]
    let tar_cmd = PathBuf::from("tar");

    #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
    {
        let list_flag = if cfg!(target_os = "windows") {
            "-tf"
        } else {
            "-tzf"
        };
        let list_output = Command::new(&tar_cmd)
            .arg(list_flag)
            .arg(archive_path)
            .output()
            .with_context(|| {
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
        let member = select_archive_binary_member(listing, bin_name)?;

        let mut extract_cmd = Command::new(&tar_cmd);
        if cfg!(target_os = "windows") {
            extract_cmd.arg("-xf");
        } else {
            extract_cmd.arg("-xzf");
        }
        extract_cmd.arg(archive_path).arg("-C").arg(extract_dir);
        #[cfg(unix)]
        {
            extract_cmd
                .arg("--no-same-owner")
                .arg("--no-same-permissions");
        }
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
        Ok(())
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (archive_path, extract_dir, bin_name);
        bail!(
            "archive extraction is not supported on {}",
            std::env::consts::OS
        );
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
        OsStr::new(bin_name),
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
    target_name: &OsStr,
    depth_remaining: usize,
) -> Result<Option<PathBuf>> {
    if depth_remaining == 0 {
        return Ok(None);
    }

    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read extracted directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.file_type().is_file() && entry.file_name() == target_name {
            if let Some(verified) = verify_contained_regular_file(&path, canonical_root)? {
                return Ok(Some(verified));
            }
        } else if meta.file_type().is_dir() {
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

fn run_service_install(extracted_bin: &Path, cfg: &RuntimeConfig) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(extracted_bin, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod 0755 {}", extracted_bin.display()))?;
    }

    let mut args = vec!["install".to_string()];
    args.extend(crate::service::build_service_cli_args(cfg));

    let status = Command::new(extracted_bin)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| {
            format!(
                "failed to launch extracted updater binary {}",
                extracted_bin.display()
            )
        })?;

    if !status.success() {
        bail!(
            "updated binary 'install' command failed with exit status {:?}",
            status.code()
        );
    }

    Ok(())
}

fn replace_portable_binary(extracted_bin: &Path) -> Result<PathBuf> {
    let current_exe_raw =
        std::env::current_exe().context("failed to determine current executable path")?;
    #[cfg(unix)]
    let current_exe = fs::canonicalize(&current_exe_raw).with_context(|| {
        format!(
            "failed to canonicalize current executable {}",
            current_exe_raw.display()
        )
    })?;
    #[cfg(not(unix))]
    let current_exe = strip_windows_verbatim_prefix(&current_exe_raw);

    let exe_dir = current_exe.parent().ok_or_else(|| {
        anyhow!(
            "current executable {} has no parent directory",
            current_exe.display()
        )
    })?;

    #[cfg(target_os = "windows")]
    {
        let staged_new = exe_dir.join(format!("vdpi.new.{}.exe", std::process::id()));
        if let Err(err) = fs::copy(extracted_bin, &staged_new)
            .with_context(|| format!("failed to stage updated binary to {}", staged_new.display()))
        {
            let _ = fs::remove_file(&staged_new);
            return Err(err);
        }

        let preferred_backup = exe_dir.join("vdpi.old.exe");
        let backup_path =
            if preferred_backup.exists() && fs::remove_file(&preferred_backup).is_err() {
                exe_dir.join(format!("vdpi.old.{}.exe", std::process::id()))
            } else {
                preferred_backup
            };

        if let Err(err) = fs::rename(&current_exe, &backup_path) {
            let _ = fs::remove_file(&staged_new);
            return Err(err).with_context(|| {
                format!(
                    "failed to move current binary {} to {}",
                    current_exe.display(),
                    backup_path.display()
                )
            });
        }

        if let Err(err) = fs::rename(&staged_new, &current_exe) {
            let _ = fs::remove_file(staged_new);
            let _ = fs::rename(backup_path, &current_exe);
            return Err(err).with_context(|| {
                format!(
                    "failed to place new binary at {} (restored previous binary)",
                    current_exe.display()
                )
            });
        }

        Ok(current_exe)
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let tmp_path = exe_dir.join(format!(".vdpi.update.{}.tmp", std::process::id()));
        let copy_res = fs::copy(extracted_bin, &tmp_path)
            .with_context(|| format!("failed to copy updated binary to {}", tmp_path.display()));
        if let Err(err) = copy_res {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }

        if let Err(err) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err)
                .with_context(|| format!("failed to chmod 0755 {}", tmp_path.display()));
        }

        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("/usr/bin/codesign")
                .args(["-fs", "-"])
                .arg(&tmp_path)
                .output();
        }

        if let Err(err) = fs::rename(&tmp_path, &current_exe) {
            let _ = fs::remove_file(&tmp_path);
            return Err(err).with_context(|| {
                format!(
                    "failed to atomically replace {} with {}",
                    current_exe.display(),
                    tmp_path.display()
                )
            });
        }

        Ok(current_exe)
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        let _ = (extracted_bin, exe_dir);
        bail!(
            "portable self-update is not supported on {}",
            std::env::consts::OS
        )
    }
}

/// Checks GitHub Releases for the latest `vdpi` release and optionally downloads,
/// verifies (SHA-256), and installs it for either service or portable deployments.
pub async fn run_update(check_only: bool, force: bool, cfg: &RuntimeConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let user_agent = format!("vdpi/{}", env!("CARGO_PKG_VERSION"));
    let client = Client::builder()
        .user_agent(&user_agent)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(API_TIMEOUT)
        .build()
        .context("failed to build HTTP client for updater")?;

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
    let baseline = format_display_version(baseline_raw);

    println!("Current version : v{baseline}");
    println!("Latest version  : {}", release.tag_name);
    println!("Release URL     : {}", release.html_url);

    if let Some(notes) = release.body.as_deref() {
        let bullets: Vec<&str> = notes
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("- ") || line.starts_with("* "))
            .take(8)
            .collect();
        if !bullets.is_empty() {
            println!("Release notes   :");
            for bullet in bullets {
                println!("  {bullet}");
            }
        }
    }

    let relation = compare_versions(&release.tag_name, baseline_raw);
    if matches!(relation, VersionRelation::Same | VersionRelation::Older) && !force {
        println!("vdpi is already up to date (v{baseline}).");
        return Ok(());
    }

    if check_only {
        println!(
            "Update available: v{baseline} -> {}. Run 'vdpi update' to install.",
            release.tag_name
        );
        return Ok(());
    }

    let asset_name = platform_asset_name().ok_or_else(|| {
        anyhow!(
            "no prebuilt release asset is available for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;

    let asset = release
        .assets
        .iter()
        .find(|a| a.name == asset_name)
        .ok_or_else(|| {
            anyhow!(
                "release {} does not contain asset '{asset_name}'",
                release.tag_name
            )
        })?;

    let sums_asset = release
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .ok_or_else(|| {
            anyhow!(
                "release {} is missing SHA256SUMS.txt; refusing unverified update",
                release.tag_name
            )
        })?;

    if !asset.browser_download_url.starts_with("https://") {
        bail!(
            "refusing non-HTTPS download URL for {}: {}",
            asset.name,
            asset.browser_download_url
        );
    }
    if !sums_asset.browser_download_url.starts_with("https://") {
        bail!(
            "refusing non-HTTPS download URL for SHA256SUMS.txt: {}",
            sums_asset.browser_download_url
        );
    }

    let staging = StagingDir::new()?;
    debug!(dir = %staging.path().display(), "created update staging directory");

    let sums_resp = client
        .get(&sums_asset.browser_download_url)
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

    println!("Downloading {asset_name}...");
    let archive_path = staging.path().join(asset_name);
    download_to_file(
        &client,
        &asset.browser_download_url,
        &archive_path,
        MAX_ARCHIVE_BYTES,
    )
    .await?;

    verify_archive_sha256(&archive_path, &sums_text, asset_name)?;
    println!("SHA-256 verified.");

    let extract_dir = staging.path().join("extract");
    fs::create_dir(&extract_dir)
        .with_context(|| format!("failed to create {}", extract_dir.display()))?;
    let bin_name = if cfg!(windows) { "vdpi.exe" } else { "vdpi" };
    extract_archive(&archive_path, &extract_dir, bin_name)?;

    let extracted_bin = find_extracted_binary(&extract_dir, bin_name)?;

    if let Some(info) = installed {
        println!(
            "Updating installed vdpi service ({})...",
            info.binary_path.display()
        );
        run_service_install(&extracted_bin, cfg)?;
        println!("Successfully updated vdpi service to {}.", release.tag_name);
    } else {
        let updated_path = replace_portable_binary(&extracted_bin)?;
        println!(
            "Successfully updated vdpi to {} at {}.",
            release.tag_name,
            updated_path.display()
        );
    }

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
}
