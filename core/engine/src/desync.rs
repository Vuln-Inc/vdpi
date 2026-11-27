use crate::binder::OutboundBinder;
use crate::bypass::BypassPolicy;
use crate::config::{DesyncMode, RuntimeConfig};
use crate::dns::DnsResolver;
use crate::tls::{
    expected_tls_record_len, extract_http_host_splits, parse_client_hello, split_tls_records,
    split_tls_records_deep, split_tls_records_multi, ClientHelloInfo,
};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{
    copy_bidirectional_with_sizes, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Interest,
    ReadBuf,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Mutex, RwLock};
use tracing::debug;

pub const PERSISTED_CACHE_VERSION: u32 = 2;
pub const MAX_PERSISTED_HOSTS: usize = 256;
pub const PERSISTED_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;
pub const OOB_CACHE_TTL_SECS: u64 = 4 * 3600;
pub const GLOBAL_ISP_STAGE_TTL_SECS: u64 = 86_400;
pub const PERSIST_DEBOUNCE_SECS: u64 = 10;
const MAX_PERSISTED_FILE_BYTES: u64 = 512 * 1024;
const MAX_HOSTNAME_LEN: usize = 255;

const FAST_PROMOTION_QUORUM: usize = 3;
const SLOW_PROMOTION_QUORUM: usize = 5;
const MAX_PROMOTION_VOTE_HOSTS: usize = 64;
const PROMOTION_VOTE_WINDOW_SECS: u64 = 15 * 60;
const FAST_EOF_THRESHOLD: Duration = Duration::from_millis(800);
const FAST_SERVER_HELLO_THRESHOLD: Duration = Duration::from_millis(800);
const MAX_HANDSHAKE_DEADLINE: Duration = Duration::from_secs(12);
const DIRECT_PASSTHROUGH_FALLBACK_BUDGET: Duration = Duration::from_millis(2000);
const RETRY_DNS_TIMEOUT: Duration = Duration::from_millis(1500);
const MAX_DEAD_RETRY_IPS: usize = 256;
const DEAD_RETRY_IP_TTL: Duration = Duration::from_secs(60);

#[cfg(target_os = "ios")]
const RELAY_BUF_SIZE: usize = 16 * 1024;
#[cfg(target_os = "android")]
const RELAY_BUF_SIZE: usize = 64 * 1024;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
const RELAY_BUF_SIZE: usize = 128 * 1024;

const TELEMETRY_BATCH_BYTES: u64 = RELAY_BUF_SIZE as u64;

#[cfg(any(target_os = "android", target_os = "ios"))]
const IDLE_RELAY_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const IDLE_RELAY_TIMEOUT: Duration = Duration::from_secs(300);

/// Single learned hostname entry persisted in the adaptive stage cache file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedHostEntry {
    pub host: String,
    pub stage: u8,
    pub updated_at: u64,
}

/// Bounded, versioned on-disk snapshot of learned TLS desync strategies and
/// the promoted ISP-wide stage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedAdaptiveCache {
    pub version: u32,
    pub global_isp_stage: u8,
    #[serde(default)]
    pub global_isp_stage_updated_at: u64,
    pub entries: Vec<PersistedHostEntry>,
}

/// Returns the platform-standard desktop cache file path for persisting learned
/// adaptive TLS desync stages across restarts. Returns `None` on mobile targets
/// (Android/iOS), where the host app provides its sandboxed cache path via `TunnelConfig`.
pub fn default_desktop_cache_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(|dir| PathBuf::from(dir).join("vdpi").join("adaptive-cache.json"))
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|home| {
                PathBuf::from(home)
                    .join("Library")
                    .join("Caches")
                    .join("vdpi")
                    .join("adaptive-cache.json")
            })
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(xdg).join("vdpi").join("adaptive-cache.json"));
        }
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|home| {
                PathBuf::from(home)
                    .join(".cache")
                    .join("vdpi")
                    .join("adaptive-cache.json")
            })
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_valid_cache_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOSTNAME_LEN
        && !host
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
}

/// Derives a wildcard parent-domain hint key (e.g. `t0.rbxcdn.com` -> `*.rbxcdn.com`)
/// so sibling CDN shards inherit a learned non-Primary strategy without cold timeouts.
fn parent_domain_cache_key(host: &str) -> Option<String> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty()
        || trimmed.starts_with("*.")
        || !is_valid_cache_host(trimmed)
        || trimmed.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 3 || labels.iter().any(|l| l.is_empty()) {
        return None;
    }
    let last = labels[labels.len() - 1];
    let second_last = labels[labels.len() - 2];
    let is_two_part_tld = (last.len() == 2
        && matches!(
            second_last,
            "co" | "com"
                | "net"
                | "org"
                | "gov"
                | "edu"
                | "ac"
                | "mil"
                | "gen"
                | "web"
                | "biz"
                | "nom"
        ))
        || matches!(
            (second_last, last),
            ("cloudfront", "net")
                | ("amazonaws", "com")
                | ("github", "io")
                | ("pages", "dev")
                | ("workers", "dev")
                | ("akamaized", "net")
                | ("fastly", "net")
                | ("vercel", "app")
                | ("microsoft", "com")
                | ("windows", "com")
                | ("live", "com")
                | ("gvt2", "com")
                | ("azureedge", "net")
                | ("azurefd", "net")
                | ("windows", "net")
                | ("googleapis", "com")
                | ("gstatic", "com")
                | ("k12" | "bel" | "pol" | "kep" | "tsk", "tr")
        );
    let parent = if is_two_part_tld {
        if labels.len() < 4 {
            return None;
        }
        format!("*.{}.{}.{}", labels[labels.len() - 3], second_last, last)
    } else {
        format!("*.{second_last}.{last}")
    };
    is_valid_cache_host(&parent).then_some(parent)
}

fn read_bounded_cache_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(MAX_PERSISTED_FILE_BYTES + 1)
        .read_to_end(&mut buf)?;
    if (buf.len() as u64) > MAX_PERSISTED_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "persisted adaptive cache exceeds size cap",
        ));
    }
    Ok(buf)
}

#[cfg(windows)]
fn replace_file_safely(tmp_path: &Path, target_path: &Path, backup_path: &Path) -> Result<()> {
    let mut attempt = 0u64;
    let initial_err = loop {
        match std::fs::rename(tmp_path, target_path) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && attempt < 3 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(15 * attempt));
            }
            Err(e) => break e,
        }
    };

    // Never delete the existing cache without first moving it to a sibling backup
    // so a second rename failure can roll back and leave the previous cache intact.
    if target_path.exists() && std::fs::rename(target_path, backup_path).is_ok() {
        match std::fs::rename(tmp_path, target_path) {
            Ok(()) => {
                let _ = std::fs::remove_file(backup_path);
                return Ok(());
            }
            Err(retry_err) => {
                let _ = std::fs::rename(backup_path, target_path);
                let _ = std::fs::remove_file(tmp_path);
                return Err(retry_err).with_context(|| {
                    format!(
                        "failed to atomically replace cache file {} (initial error: {initial_err})",
                        target_path.display()
                    )
                });
            }
        }
    }

    let _ = std::fs::remove_file(tmp_path);
    Err(initial_err).with_context(|| {
        format!(
            "failed to atomically replace cache file {}",
            target_path.display()
        )
    })
}

fn atomic_write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    let parent_dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent_dir {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory {}", parent.display()))?;
    }

    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let base_name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .filter(|n| !n.is_empty())
        .unwrap_or(std::borrow::Cow::Borrowed("adaptive-cache"));
    let tmp_name = format!("{base_name}.{pid}.{seq}.tmp");
    let tmp_path = match parent_dir {
        Some(parent) => parent.join(&tmp_name),
        None => PathBuf::from(&tmp_name),
    };

    {
        let mut file = std::fs::File::create(&tmp_path)
            .with_context(|| format!("failed to create temp cache file {}", tmp_path.display()))?;
        if let Err(e) = file.write_all(bytes) {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e).with_context(|| {
                format!("failed to write temp cache file {}", tmp_path.display())
            });
        }
        let _ = file.sync_all();
    }

    #[cfg(windows)]
    {
        let bak_name = format!("{base_name}.{pid}.{seq}.bak");
        let backup_path = match parent_dir {
            Some(parent) => parent.join(&bak_name),
            None => PathBuf::from(&bak_name),
        };
        replace_file_safely(&tmp_path, path, &backup_path)?;
    }

    #[cfg(not(windows))]
    if let Err(rename_err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(rename_err).with_context(|| {
            format!(
                "failed to atomically rename cache file to {}",
                path.display()
            )
        });
    }

    Ok(())
}

/// Strategy learned per-hostname (and globally per ISP network) by the 7-Stage Adaptive
/// Auto-Heal TLS Engine.
///
/// Enum `u8` discriminants are kept stable for backward compatibility with persisted
/// `adaptive-cache.json` files; probing order is defined by `ALL_STAGES`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LearnedStrategy {
    /// Configured primary mode (default `Combo`: 4 wire-paced RFC-compliant TLS records
    /// split across the handshake header and SNI midpoint).
    Primary = 0,
    /// TCP Out-of-Band (`MSG_OOB`) urgent decoy byte injected right at the SNI midpoint.
    /// Real server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte seamlessly while stateful
    /// full-stream-reassembling ISP DPI boxes corrupt/miss the SNI completely.
    OobSniDesync = 1,
    /// Combined 4-record TLS split + `MSG_OOB` decoy byte injected right at the TLS
    /// record boundary inside SNI, shifting subsequent TLS record framing for DPI state machines.
    MultiRecordOob = 2,
    /// Single intact outer TLS record split across 4 wire-paced TCP segments (compatible
    /// with strict servers that reject multi-record ClientHellos while defeating active DPI).
    FineFragment = 3,
    /// Deep 12+ RFC-compliant TLS record storm (up to 10 tiny 2-byte lead records
    /// exhausting hardware DPI per-flow packet caps before SNI hits the wire + SNI splits).
    DeepRecordStorm = 4,
    /// Single intact outer TLS record with slow 2-byte SNI-only pacing (for strict
    /// servers behind stateful burst-reassembling DPI).
    SlowSniSlice = 5,
    /// Unmodified single-write passthrough (for unblocked strict WAFs/CDNs).
    DirectPassthrough = 6,
}

impl LearnedStrategy {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Primary,
            1 => Self::OobSniDesync,
            2 => Self::MultiRecordOob,
            3 => Self::FineFragment,
            4 => Self::DeepRecordStorm,
            5 => Self::SlowSniSlice,
            6 => Self::DirectPassthrough,
            _ => Self::Primary,
        }
    }

    pub fn stage_number(self) -> u8 {
        (self as u8) + 1
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Primary => "ComboMultiRecord",
            Self::OobSniDesync => "OobSniDesync",
            Self::MultiRecordOob => "MultiRecordOob",
            Self::FineFragment => "FineFragment",
            Self::DeepRecordStorm => "DeepRecordStorm",
            Self::SlowSniSlice => "SlowSniSlice",
            Self::DirectPassthrough => "DirectPassthrough",
        }
    }

    fn is_oob(self) -> bool {
        matches!(self, Self::OobSniDesync | Self::MultiRecordOob)
    }

    fn is_clean_non_oob(self) -> bool {
        matches!(
            self,
            Self::Primary | Self::FineFragment | Self::DeepRecordStorm | Self::SlowSniSlice
        )
    }

    fn allows_parent_wildcard(self) -> bool {
        matches!(
            self,
            Self::Primary | Self::FineFragment | Self::SlowSniSlice
        )
    }

    fn cache_ttl_secs(self) -> u64 {
        if self.is_oob() {
            OOB_CACHE_TTL_SECS
        } else {
            PERSISTED_CACHE_TTL_SECS
        }
    }

    fn promotion_quorum(self) -> Option<usize> {
        match self {
            Self::Primary | Self::OobSniDesync | Self::MultiRecordOob => {
                Some(FAST_PROMOTION_QUORUM)
            }
            Self::DeepRecordStorm | Self::SlowSniSlice => Some(SLOW_PROMOTION_QUORUM),
            // FineFragment is a single intact TLS record (strictly weaker against DPI than
            // multi-record Primary): cache it per-host and allow it only when demoting FROM
            // an OOB stage via `oob_alert_demotion`, never promote to it from Primary.
            Self::FineFragment | Self::DirectPassthrough => None,
        }
    }
}

#[derive(Debug, Default)]
struct PromotionVoteTracker {
    /// The `preferred_isp_stage` value these votes are voting to move away from.
    base_stage: u8,
    /// Maps candidate stage (0..=5) -> (normalized_host -> last vote timestamp in unix secs).
    votes: HashMap<u8, HashMap<String, u64>>,
}

impl PromotionVoteTracker {
    fn clear(&mut self) {
        self.base_stage = LearnedStrategy::Primary as u8;
        self.votes.clear();
    }

    fn record_vote(
        &mut self,
        current_global: LearnedStrategy,
        candidate: LearnedStrategy,
        host: &str,
        now: u64,
    ) -> bool {
        let required_quorum = if current_global.is_oob() && candidate.is_clean_non_oob() {
            FAST_PROMOTION_QUORUM
        } else {
            let Some(quorum) = candidate.promotion_quorum() else {
                return false;
            };
            quorum
        };
        if candidate == current_global || !is_valid_cache_host(host) {
            return false;
        }

        let base = current_global as u8;
        if self.base_stage != base {
            self.votes.clear();
            self.base_stage = base;
        }

        self.votes.retain(|_, host_map| {
            host_map.retain(|_, &mut ts| now.saturating_sub(ts) <= PROMOTION_VOTE_WINDOW_SECS);
            !host_map.is_empty()
        });

        let vote_key = parent_domain_cache_key(host)
            .and_then(|p| p.strip_prefix("*.").map(str::to_string))
            .unwrap_or_else(|| host.to_string());

        let host_map = self.votes.entry(candidate as u8).or_default();
        if !host_map.contains_key(&vote_key) && host_map.len() >= MAX_PROMOTION_VOTE_HOSTS {
            let oldest = host_map
                .iter()
                .min_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)))
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                host_map.remove(&oldest);
            }
        }
        host_map.insert(vote_key, now);

        if host_map.len() >= required_quorum {
            self.votes.clear();
            self.base_stage = candidate as u8;
            true
        } else {
            false
        }
    }
}

fn is_hard_block_io_error(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset | ErrorKind::BrokenPipe | ErrorKind::ConnectionAborted
    )
}

fn is_hard_block_write_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(is_hard_block_io_error)
    })
}

fn evict_oldest_adaptive_entries(
    cache: &mut HashMap<String, LearnedStrategy>,
    timestamps: &mut HashMap<String, u64>,
    max_entries: usize,
) {
    while cache.len() > max_entries {
        let oldest = cache
            .keys()
            .min_by(|a, b| {
                let ta = timestamps.get(*a).copied().unwrap_or(0);
                let tb = timestamps.get(*b).copied().unwrap_or(0);
                ta.cmp(&tb).then_with(|| a.cmp(b))
            })
            .cloned();
        let Some(victim) = oldest else {
            break;
        };
        cache.remove(&victim);
        timestamps.remove(&victim);
    }
}

fn upsert_adaptive_entry(
    cache: &mut HashMap<String, LearnedStrategy>,
    timestamps: &mut HashMap<String, u64>,
    key: String,
    stage: LearnedStrategy,
    now: u64,
) -> bool {
    if !is_valid_cache_host(&key) {
        return false;
    }
    if !cache.contains_key(&key) && cache.len() >= MAX_PERSISTED_HOSTS {
        evict_oldest_adaptive_entries(cache, timestamps, MAX_PERSISTED_HOSTS.saturating_sub(1));
    }
    let is_expired = timestamps
        .get(&key)
        .is_some_and(|&ts| now.saturating_sub(ts) > stage.cache_ttl_secs());
    let prev = cache.insert(key.clone(), stage);
    if prev != Some(stage) || !timestamps.contains_key(&key) || is_expired {
        timestamps.insert(key, now);
        return true;
    }
    false
}

#[repr(align(64))]
#[derive(Debug, Default)]
struct CacheLinePad;

/// Lock-free live engine counters shared across proxy and TUN sessions.
/// Hot byte counters (`bytes_tx` / `bytes_rx`) are isolated on separate 64-byte cache lines
/// to prevent false sharing across relay worker threads at Gigabit throughput.
#[repr(C)]
#[derive(Debug, Default)]
pub struct EngineTelemetry {
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub tls_handshakes: AtomicU64,
    pub auto_heal_escalations: AtomicU64,
    pub learned_hosts: AtomicUsize,
    pub udp_flows_active: AtomicU64,
    pub quic_blocked: AtomicU64,
    _pad_tx: CacheLinePad,
    pub bytes_tx: AtomicU64,
    _pad_rx: CacheLinePad,
    pub bytes_rx: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineTelemetrySnapshot {
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub tls_handshakes: u64,
    pub auto_heal_escalations: u64,
    pub learned_hosts: usize,
    pub udp_flows_active: u64,
    pub quic_blocked: u64,
    pub dns_queries: u64,
}

/// Wraps an upstream stream to track `bytes_tx` / `bytes_rx` with batched `Relaxed` atomic
/// updates (flushed on batch threshold, EOF, error, shutdown, and drop — never on
/// `Poll::Pending` or `poll_flush` below threshold) and a zero-syscall activity flag so idle
/// connections can be reaped without per-chunk `Instant::now()` calls or cross-core cache-line
/// contention at Gigabit speeds.
struct CountingStream<'a, S> {
    inner: S,
    telemetry: &'a EngineTelemetry,
    active: &'a AtomicBool,
    pending_rx: u64,
    pending_tx: u64,
}

impl<'a, S> CountingStream<'a, S> {
    fn new(inner: S, telemetry: &'a EngineTelemetry, active: &'a AtomicBool) -> Self {
        Self {
            inner,
            telemetry,
            active,
            pending_rx: 0,
            pending_tx: 0,
        }
    }

    #[inline]
    fn touch_activity(&self) {
        if !self.active.load(Ordering::Relaxed) {
            self.active.store(true, Ordering::Relaxed);
        }
    }

    #[inline]
    fn flush_rx(&mut self) {
        if self.pending_rx > 0 {
            let n = std::mem::take(&mut self.pending_rx);
            self.telemetry.bytes_rx.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    fn flush_tx(&mut self) {
        if self.pending_tx > 0 {
            let n = std::mem::take(&mut self.pending_tx);
            self.telemetry.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
    }
}

impl<S> Drop for CountingStream<'_, S> {
    fn drop(&mut self) {
        self.flush_rx();
        self.flush_tx();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<'_, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        match &poll {
            Poll::Ready(Ok(())) => {
                let n = buf.filled().len().saturating_sub(before);
                if n > 0 {
                    self.touch_activity();
                    self.pending_rx += n as u64;
                    if self.pending_rx >= TELEMETRY_BATCH_BYTES {
                        self.flush_rx();
                    }
                } else {
                    self.flush_rx();
                }
            }
            Poll::Ready(Err(_)) => {
                self.flush_rx();
            }
            Poll::Pending => {}
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<'_, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        match &poll {
            Poll::Ready(Ok(n)) if *n > 0 => {
                self.touch_activity();
                self.pending_tx += *n as u64;
                if self.pending_tx >= TELEMETRY_BATCH_BYTES {
                    self.flush_tx();
                }
            }
            Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                self.flush_tx();
            }
            Poll::Pending => {}
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        if self.pending_tx >= TELEMETRY_BATCH_BYTES {
            self.flush_tx();
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.flush_tx();
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct ActiveConnGuard(Arc<EngineTelemetry>);

impl ActiveConnGuard {
    fn enter(telemetry: &Arc<EngineTelemetry>) -> Self {
        telemetry.active_connections.fetch_add(1, Ordering::Relaxed);
        telemetry.total_connections.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(telemetry))
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

const ALL_STAGES: [LearnedStrategy; 7] = [
    LearnedStrategy::Primary,
    LearnedStrategy::FineFragment,
    LearnedStrategy::DeepRecordStorm,
    LearnedStrategy::SlowSniSlice,
    LearnedStrategy::OobSniDesync,
    LearnedStrategy::MultiRecordOob,
    LearnedStrategy::DirectPassthrough,
];

/// RFC 8446 Section 4.1.3 SHA-256("HelloRetryRequest") random sentinel embedded at bytes
/// 11..43 of a TLS 1.3 HelloRetryRequest ServerHello record.
const TLS13_HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

fn is_tls_hello_retry_request(record: &[u8]) -> bool {
    record.len() >= 43
        && record[0] == 0x16
        && record[1] == 0x03
        && record[5] == 0x02
        && record[11..43] == TLS13_HELLO_RETRY_REQUEST_RANDOM
}

/// Returns `true` iff `trailing` consists exclusively of complete TLS records (5-byte header +
/// full body). If a coalesced TLS 1.3 0-RTT ApplicationData record was split across TCP segments,
/// returning `false` lets `establish_initial_flight` forward once and enter `relay_bidirectional`
/// immediately instead of deadlocking waiting for `ServerHello` while the rest of the record sits
/// unread on the client socket.
fn are_trailing_tls_records_complete(mut trailing: &[u8]) -> bool {
    while !trailing.is_empty() {
        if trailing.len() < 5 {
            return false;
        }
        let rec_len = u16::from_be_bytes([trailing[3], trailing[4]]) as usize;
        let total = 5 + rec_len;
        if trailing.len() < total {
            return false;
        }
        trailing = &trailing[total..];
    }
    true
}

/// Returns `true` if `trailing` (bytes immediately following the leading `ClientHello` TLS record)
/// contains a coalesced TLS 1.3 0-RTT `ApplicationData` (`0x17`) record. Coalesced 0-RTT early
/// data must be sent strictly single-attempt and never replayed across adaptive retry stages.
fn trailing_contains_tls_app_data(mut trailing: &[u8]) -> bool {
    while !trailing.is_empty() {
        if trailing[0] == 0x17 {
            return true;
        }
        if trailing.len() < 5 {
            return false;
        }
        let rec_len = u16::from_be_bytes([trailing[3], trailing[4]]) as usize;
        let total = 5 + rec_len;
        if trailing.len() < total {
            return false;
        }
        trailing = &trailing[total..];
    }
    false
}

#[derive(Clone)]
pub struct EngineContext {
    pub config: Arc<RuntimeConfig>,
    pub dns: DnsResolver,
    pub bypass: Arc<BypassPolicy>,
    pub adaptive_cache: Arc<RwLock<HashMap<String, LearnedStrategy>>>,
    pub preferred_isp_stage: Arc<AtomicU8>,
    pub telemetry: Arc<EngineTelemetry>,
    pub outbound_binder: Option<Arc<dyn OutboundBinder>>,
    pub listener_addrs: [Option<SocketAddr>; 4],
    adaptive_timestamps: Arc<RwLock<HashMap<String, u64>>>,
    preferred_isp_stage_updated_at: Arc<AtomicU64>,
    promotion_votes: Arc<std::sync::Mutex<PromotionVoteTracker>>,
    cache_path: Arc<RwLock<Option<PathBuf>>>,
    last_persist_epoch: Arc<AtomicU64>,
    persist_scheduled: Arc<AtomicBool>,
    persist_lock: Arc<Mutex<()>>,
    dead_retry_ips: Arc<RwLock<HashMap<SocketAddr, Instant>>>,
}

impl EngineContext {
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        Self::new_with_binder(config, None)
    }

    pub fn new_with_binder(
        config: RuntimeConfig,
        binder: Option<Arc<dyn OutboundBinder>>,
    ) -> Result<Self> {
        let dns = DnsResolver::new_with_options(
            &config.dns_addr,
            config.dns_port,
            config.enable_doh,
            config.dns_ipv4_only,
            config.disable_system_dns_fallback,
            binder.clone(),
        )?;
        let bypass = BypassPolicy::new(&config.bypass_domains, &config.patterns)?;
        Ok(Self {
            config: Arc::new(config),
            dns,
            bypass: Arc::new(bypass),
            adaptive_cache: Arc::new(RwLock::new(HashMap::new())),
            preferred_isp_stage: Arc::new(AtomicU8::new(LearnedStrategy::Primary as u8)),
            telemetry: Arc::new(EngineTelemetry::default()),
            outbound_binder: binder,
            listener_addrs: [None; 4],
            adaptive_timestamps: Arc::new(RwLock::new(HashMap::new())),
            preferred_isp_stage_updated_at: Arc::new(AtomicU64::new(0)),
            promotion_votes: Arc::new(std::sync::Mutex::new(PromotionVoteTracker::default())),
            cache_path: Arc::new(RwLock::new(None)),
            last_persist_epoch: Arc::new(AtomicU64::new(0)),
            persist_scheduled: Arc::new(AtomicBool::new(false)),
            persist_lock: Arc::new(Mutex::new(())),
            dead_retry_ips: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn telemetry_snapshot(&self) -> EngineTelemetrySnapshot {
        EngineTelemetrySnapshot {
            active_connections: self.telemetry.active_connections.load(Ordering::Relaxed),
            total_connections: self.telemetry.total_connections.load(Ordering::Relaxed),
            bytes_tx: self.telemetry.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.telemetry.bytes_rx.load(Ordering::Relaxed),
            tls_handshakes: self.telemetry.tls_handshakes.load(Ordering::Relaxed),
            auto_heal_escalations: self.telemetry.auto_heal_escalations.load(Ordering::Relaxed),
            learned_hosts: self.telemetry.learned_hosts.load(Ordering::Relaxed),
            udp_flows_active: self.telemetry.udp_flows_active.load(Ordering::Relaxed),
            quic_blocked: self.telemetry.quic_blocked.load(Ordering::Relaxed),
            dns_queries: self.dns.query_count(),
        }
    }

    pub fn set_udp_flows_active(&self, n: u64) {
        self.telemetry.udp_flows_active.store(n, Ordering::Relaxed);
    }

    pub fn inc_quic_blocked(&self) {
        self.telemetry.quic_blocked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_udp_bytes(&self, tx: u64, rx: u64) {
        if tx > 0 {
            self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
        }
        if rx > 0 {
            self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
        }
    }

    pub fn preferred_stage(&self) -> LearnedStrategy {
        let raw = self.preferred_isp_stage.load(Ordering::Acquire);
        let stage = LearnedStrategy::from_u8(raw);
        if stage != LearnedStrategy::Primary {
            let updated_at = self.preferred_isp_stage_updated_at.load(Ordering::Acquire);
            if updated_at > 0
                && unix_now_secs().saturating_sub(updated_at) > GLOBAL_ISP_STAGE_TTL_SECS
            {
                if self
                    .preferred_isp_stage
                    .compare_exchange(
                        raw,
                        LearnedStrategy::Primary as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    let _ = self.preferred_isp_stage_updated_at.compare_exchange(
                        updated_at,
                        0,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                    return LearnedStrategy::Primary;
                }
                return LearnedStrategy::from_u8(self.preferred_isp_stage.load(Ordering::Acquire));
            }
        }
        stage
    }

    pub async fn learned_host_count(&self) -> usize {
        self.adaptive_cache.read().await.len()
    }

    /// Attaches an on-disk cache path and immediately loads any valid non-expired entries.
    pub async fn attach_cache_file(&self, path: PathBuf) {
        *self.cache_path.write().await = Some(path.clone());
        let loaded = self.load_persisted_cache(&path).await;
        if loaded > 0 {
            debug!(
                path = %path.display(),
                loaded,
                preferred_stage = self.preferred_stage().label(),
                "restored persisted adaptive TLS stage cache"
            );
        }
    }

    /// Returns `true` when a persistent cache file path is currently attached.
    pub async fn has_cache_file(&self) -> bool {
        self.cache_path.read().await.is_some()
    }

    /// Loads valid, non-expired adaptive TLS strategies from `path` into memory.
    /// Missing, unreadable, oversized, or corrupt files silently return `0`.
    pub async fn load_persisted_cache(&self, path: &Path) -> usize {
        let path_owned = path.to_path_buf();
        let Ok(Ok(raw)) =
            tokio::task::spawn_blocking(move || read_bounded_cache_file(&path_owned)).await
        else {
            return 0;
        };

        let Ok(parsed) = serde_json::from_slice::<PersistedAdaptiveCache>(&raw) else {
            return 0;
        };

        if parsed.version != PERSISTED_CACHE_VERSION {
            return 0;
        }

        let now = unix_now_secs();
        let max_stage = LearnedStrategy::DirectPassthrough as u8;

        // Restore ISP-wide promoted desync stage only for escalated desync stages (1..=5)
        // within the 24h TTL. Legacy v1 files missing `global_isp_stage_updated_at` (0) or
        // expired promotions safely fall back to Primary.
        let restored_global = if (1..=5).contains(&parsed.global_isp_stage)
            && parsed.global_isp_stage_updated_at > 0
            && now.saturating_sub(parsed.global_isp_stage_updated_at) <= GLOBAL_ISP_STAGE_TTL_SECS
        {
            self.preferred_isp_stage_updated_at
                .store(parsed.global_isp_stage_updated_at, Ordering::Release);
            self.preferred_isp_stage
                .store(parsed.global_isp_stage, Ordering::Release);
            LearnedStrategy::from_u8(parsed.global_isp_stage)
        } else {
            self.preferred_isp_stage
                .store(LearnedStrategy::Primary as u8, Ordering::Release);
            self.preferred_isp_stage_updated_at
                .store(0, Ordering::Release);
            LearnedStrategy::Primary
        };

        let mut deduped: HashMap<String, (LearnedStrategy, u64)> =
            HashMap::with_capacity(parsed.entries.len().min(MAX_PERSISTED_HOSTS));
        for entry in parsed.entries {
            if entry.stage > max_stage {
                continue;
            }
            let strategy = LearnedStrategy::from_u8(entry.stage);
            if now.saturating_sub(entry.updated_at) > strategy.cache_ttl_secs() {
                continue;
            }
            let host = entry.host.trim().to_ascii_lowercase();
            if !is_valid_cache_host(&host) {
                continue;
            }
            deduped
                .entry(host)
                .and_modify(|existing| {
                    if entry.updated_at > existing.1 {
                        *existing = (strategy, entry.updated_at);
                    }
                })
                .or_insert((strategy, entry.updated_at));
        }

        let mut valid_entries: Vec<(String, LearnedStrategy, u64)> = deduped
            .into_iter()
            .filter_map(|(host, (stage, updated_at))| {
                (stage != restored_global).then_some((host, stage, updated_at))
            })
            .collect();
        valid_entries.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        valid_entries.truncate(MAX_PERSISTED_HOSTS);

        let loaded = valid_entries.len();
        {
            let mut cache_guard = self.adaptive_cache.write().await;
            let mut ts_guard = self.adaptive_timestamps.write().await;
            for (host, stage, updated_at) in valid_entries {
                cache_guard.insert(host.clone(), stage);
                ts_guard.insert(host, updated_at);
            }
            cache_guard.retain(|host, stage| {
                let keep = *stage != restored_global;
                if !keep {
                    ts_guard.remove(host);
                }
                keep
            });
            evict_oldest_adaptive_entries(&mut cache_guard, &mut ts_guard, MAX_PERSISTED_HOSTS);
            self.telemetry
                .learned_hosts
                .store(cache_guard.len(), Ordering::Relaxed);
        }

        loaded
    }

    /// Snapshots learned adaptive TLS strategies (capped to `MAX_PERSISTED_HOSTS`) and
    /// writes them atomically to `path` via a sibling temporary file and rename.
    pub async fn save_persisted_cache(&self, path: &Path) -> Result<()> {
        self.save_persisted_cache_locked(path, false).await
    }

    async fn save_persisted_cache_locked(
        &self,
        path: &Path,
        skip_if_empty_and_missing: bool,
    ) -> Result<()> {
        // Strict lock order: persist_lock -> adaptive_cache -> adaptive_timestamps.
        // Holding persist_lock across snapshot + disk write prevents stale background
        // saves from resurrecting entries wiped by `clear_adaptive_cache`.
        let _persist_guard = self.persist_lock.lock().await;
        let now = unix_now_secs();
        let mut entries: Vec<PersistedHostEntry> = {
            let cache_guard = self.adaptive_cache.read().await;
            let ts_guard = self.adaptive_timestamps.read().await;
            cache_guard
                .iter()
                .filter_map(|(host, &strategy)| {
                    let normalized = host.trim().to_ascii_lowercase();
                    if !is_valid_cache_host(&normalized) {
                        return None;
                    }
                    let updated_at = ts_guard.get(host).copied().unwrap_or(now);
                    if now.saturating_sub(updated_at) > strategy.cache_ttl_secs() {
                        return None;
                    }
                    Some(PersistedHostEntry {
                        host: normalized,
                        stage: strategy as u8,
                        updated_at,
                    })
                })
                .collect()
        };

        entries.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.host.cmp(&b.host))
        });
        entries.truncate(MAX_PERSISTED_HOSTS);

        let raw_global = self.preferred_stage() as u8;
        let global_isp_stage = if (1..=5).contains(&raw_global) {
            raw_global
        } else {
            LearnedStrategy::Primary as u8
        };
        let global_isp_stage_updated_at = if global_isp_stage == LearnedStrategy::Primary as u8 {
            0
        } else {
            let stored = self.preferred_isp_stage_updated_at.load(Ordering::Acquire);
            if stored > 0 {
                stored
            } else {
                now
            }
        };

        if skip_if_empty_and_missing
            && entries.is_empty()
            && global_isp_stage == LearnedStrategy::Primary as u8
            && !tokio::fs::try_exists(path).await.unwrap_or(false)
        {
            return Ok(());
        }

        let snapshot = PersistedAdaptiveCache {
            version: PERSISTED_CACHE_VERSION,
            global_isp_stage,
            global_isp_stage_updated_at,
            entries,
        };
        let bytes =
            serde_json::to_vec(&snapshot).context("failed to serialize adaptive cache JSON")?;

        let path_owned = path.to_path_buf();
        tokio::task::spawn_blocking(move || atomic_write_file(&path_owned, &bytes))
            .await
            .context("adaptive cache persistence task panicked")??;
        self.last_persist_epoch.store(now.max(1), Ordering::Relaxed);
        Ok(())
    }

    /// Flushes the in-memory adaptive cache to the attached disk path (if any).
    pub async fn flush_persisted_cache(&self) -> Result<()> {
        let path = self.cache_path.read().await.clone();
        let Some(path) = path else {
            return Ok(());
        };
        self.save_persisted_cache_locked(&path, true).await
    }

    fn maybe_persist_cache(&self) {
        let has_path = match self.cache_path.try_read() {
            Ok(guard) => guard.is_some(),
            Err(_) => return,
        };
        if !has_path {
            return;
        }

        let now = unix_now_secs().max(1);
        let last = self.last_persist_epoch.load(Ordering::Relaxed);
        if (last == 0 || now.saturating_sub(last) >= PERSIST_DEBOUNCE_SECS)
            && self
                .last_persist_epoch
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let ctx = self.clone();
            tokio::spawn(async move {
                if let Err(e) = ctx.flush_persisted_cache().await {
                    debug!(error = %e, "background adaptive cache persist failed");
                }
            });
            return;
        }

        // Inside the debounce window: schedule a single trailing-edge flush so burst-learned
        // hosts are still persisted once the debounce interval elapses.
        if self
            .persist_scheduled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let elapsed = now.saturating_sub(self.last_persist_epoch.load(Ordering::Relaxed));
        let wait_secs = PERSIST_DEBOUNCE_SECS.saturating_sub(elapsed).max(1);
        let ctx = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;
            ctx.persist_scheduled.store(false, Ordering::Release);
            if let Err(e) = ctx.flush_persisted_cache().await {
                debug!(error = %e, "delayed adaptive cache persist failed");
            }
        });
    }

    pub async fn clear_adaptive_cache(&self) {
        // Strict lock order: persist_lock -> adaptive_cache -> adaptive_timestamps.
        // Drop map guards before spawn_blocking disk removal.
        let _persist_guard = self.persist_lock.lock().await;
        {
            let mut guard = self.adaptive_cache.write().await;
            let mut ts_guard = self.adaptive_timestamps.write().await;
            guard.clear();
            ts_guard.clear();
        }
        {
            let mut tracker = self
                .promotion_votes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            tracker.clear();
        }
        self.telemetry.learned_hosts.store(0, Ordering::Relaxed);
        self.preferred_isp_stage
            .store(LearnedStrategy::Primary as u8, Ordering::Relaxed);
        self.preferred_isp_stage_updated_at
            .store(0, Ordering::Relaxed);
        self.last_persist_epoch.store(0, Ordering::Relaxed);

        let path = self.cache_path.read().await.clone();
        if let Some(path) = path {
            let _ = tokio::task::spawn_blocking(move || {
                let _ = std::fs::remove_file(&path);
                let base_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .filter(|n| !n.is_empty())
                    .unwrap_or_else(|| "adaptive-cache".to_string());
                let prefix = format!("{base_name}.");
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                let _ = std::fs::remove_file(parent.join("adaptive-cache.tmp"));
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let file_name = entry.file_name();
                        let name = file_name.to_string_lossy();
                        if name.starts_with(&prefix)
                            && (name.ends_with(".tmp") || name.ends_with(".bak"))
                        {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            })
            .await;
        }
    }

    /// Connects directly to an already-resolved upstream `SocketAddr` with `connect_timeout`
    /// and `TCP_NODELAY`, enforcing listener-loop and unspecified-address guards.
    pub async fn connect_upstream_addr(&self, target: SocketAddr) -> Result<TcpStream> {
        let stream =
            tokio::time::timeout(self.config.connect_timeout, self.connect_upstream(target))
                .await
                .map_err(|_| {
                    anyhow!(
                        "connect {target} timed out after {:?}",
                        self.config.connect_timeout
                    )
                })?
                .with_context(|| format!("connect {target} failed"))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// Resolves `host` via DoH/DNS and connects to `(ip, port)` with Happy Eyeballs fallback and `TCP_NODELAY`.
    pub async fn connect_target(&self, host: &str, port: u16) -> Result<(TcpStream, SocketAddr)> {
        let ips = self
            .dns
            .resolve(host)
            .await
            .with_context(|| format!("DNS resolution failed for {host}"))?;

        if ips.is_empty() {
            bail!("no addresses returned for {host}");
        }

        let ordered_ips = if ips.len() > 1 {
            let guard = self.dead_retry_ips.read().await;
            if guard.is_empty() {
                ips
            } else {
                let now = Instant::now();
                let mut healthy = Vec::with_capacity(ips.len());
                let mut dead = Vec::new();
                for ip in ips {
                    let key = canonical_socket_addr(SocketAddr::new(ip, port));
                    if guard.get(&key).is_some_and(|&marked_at| {
                        now.saturating_duration_since(marked_at) < DEAD_RETRY_IP_TTL
                    }) {
                        dead.push(ip);
                    } else {
                        healthy.push(ip);
                    }
                }
                healthy.extend(dead);
                healthy
            }
        } else {
            ips
        };

        let total_ips = ordered_ips.len();
        let mut last_err = None;
        let mut failed_targets = Vec::new();

        for (idx, ip) in ordered_ips.into_iter().enumerate() {
            let target = SocketAddr::new(ip, port);
            let attempt_timeout = if idx + 1 < total_ips {
                self.config.connect_timeout.min(Duration::from_secs(3))
            } else {
                self.config.connect_timeout
            };

            match tokio::time::timeout(attempt_timeout, self.connect_upstream(target)).await {
                Ok(Ok(stream)) => {
                    let canonical_target = canonical_socket_addr(target);
                    for failed in failed_targets {
                        if canonical_socket_addr(failed) != canonical_target {
                            self.mark_dead_retry_ip(failed).await;
                        }
                    }
                    self.clear_dead_retry_ip(target).await;
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, target));
                }
                Ok(Err(e)) => {
                    failed_targets.push(target);
                    last_err = Some(anyhow!("connect {target} failed: {e}"));
                }
                Err(_) => {
                    failed_targets.push(target);
                    last_err = Some(anyhow!(
                        "connect {target} timed out after {attempt_timeout:?}"
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("failed to connect to {host}:{port}")))
    }

    async fn is_dead_retry_ip(&self, addr: SocketAddr) -> bool {
        let key = canonical_socket_addr(addr);
        let guard = self.dead_retry_ips.read().await;
        guard
            .get(&key)
            .is_some_and(|&marked_at| marked_at.elapsed() < DEAD_RETRY_IP_TTL)
    }

    async fn sync_dead_retry_ips(&self, addrs: &[SocketAddr], local_dead: &mut Vec<SocketAddr>) {
        let guard = self.dead_retry_ips.read().await;
        if guard.is_empty() {
            return;
        }
        let now = Instant::now();
        for &addr in addrs {
            if local_dead.contains(&addr) {
                continue;
            }
            let key = canonical_socket_addr(addr);
            if guard.get(&key).is_some_and(|&marked_at| {
                now.saturating_duration_since(marked_at) < DEAD_RETRY_IP_TTL
            }) {
                local_dead.push(addr);
            }
        }
    }

    async fn mark_dead_retry_ip(&self, addr: SocketAddr) {
        let key = canonical_socket_addr(addr);
        let now = Instant::now();
        let mut guard = self.dead_retry_ips.write().await;
        guard.retain(|_, &mut marked_at| {
            now.saturating_duration_since(marked_at) < DEAD_RETRY_IP_TTL
        });
        while !guard.contains_key(&key) && guard.len() >= MAX_DEAD_RETRY_IPS {
            let Some(oldest) = guard
                .iter()
                .min_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)))
                .map(|(&addr, _)| addr)
            else {
                break;
            };
            guard.remove(&oldest);
        }
        guard.insert(key, now);
    }

    async fn clear_dead_retry_ip(&self, addr: SocketAddr) {
        let key = canonical_socket_addr(addr);
        let present = {
            let guard = self.dead_retry_ips.read().await;
            guard.contains_key(&key)
        };
        if present {
            self.dead_retry_ips.write().await.remove(&key);
        }
    }

    async fn connect_upstream(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        let target = canonical_socket_addr(target);
        if target.ip().is_unspecified() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "upstream address is unspecified",
            ));
        }
        for addr in self.listener_addrs.iter().flatten() {
            if addr.port() == target.port()
                && (addr.ip().to_canonical() == target.ip()
                    || (addr.ip().is_unspecified()
                        && addr.is_ipv4() == target.is_ipv4()
                        && (target.ip().is_loopback() || can_bind_locally(target))))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "upstream points back to a proxy listener",
                ));
            }
        }
        let stream = if let Some(ref binder) = self.outbound_binder {
            let sock = if target.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            binder.bind_socket(socket2::SockRef::from(&sock), target.is_ipv4())?;
            sock.connect(target).await?
        } else {
            TcpStream::connect(target).await?
        };
        self.clear_dead_retry_ip(target).await;
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(60))
            .with_interval(Duration::from_secs(15));
        let _ = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive);
        #[cfg(target_vendor = "apple")]
        set_apple_nosigpipe(&stream);
        Ok(stream)
    }

    /// Allocates and binds an outbound UDP socket routed via `outbound_binder` (when present)
    /// with Windows `SIO_UDP_CONNRESET` disabled and optional socket buffer sizing.
    pub fn bind_outbound_udp(&self, is_ipv4: bool, buf_bytes: usize) -> std::io::Result<UdpSocket> {
        let (domain, bind_addr) = if is_ipv4 {
            (
                socket2::Domain::IPV4,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        } else {
            (
                socket2::Domain::IPV6,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            )
        };
        let sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if !is_ipv4 {
            let _ = sock.set_only_v6(true);
        }
        if let Some(ref binder) = self.outbound_binder {
            binder.bind_socket(socket2::SockRef::from(&sock), is_ipv4)?;
        }
        #[cfg(windows)]
        disable_udp_connreset(&sock);
        if buf_bytes > 0 {
            let _ = sock.set_recv_buffer_size(buf_bytes);
            let _ = sock.set_send_buffer_size(buf_bytes);
        }
        sock.bind(&bind_addr.into())?;
        sock.set_nonblocking(true)?;
        let std_sock: std::net::UdpSocket = sock.into();
        UdpSocket::from_std(std_sock)
    }

    /// Relays a bidirectional TCP tunnel between `client` and `remote`, inspecting the initial
    /// client flight to apply adaptive TLS ClientHello or HTTP Host DPI desynchronization.
    pub async fn relay_tunnel(
        &self,
        client: TcpStream,
        remote: TcpStream,
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let _ = client.set_nodelay(true);
        self.relay_stream(client, remote, known_host, remote_addr)
            .await
    }

    /// Relays any `AsyncRead + AsyncWrite` client stream (such as a proxy `TcpStream` or a
    /// userspace TUN TCP stream) to `remote` with adaptive TLS/HTTP DPI desynchronization.
    pub async fn relay_stream<C>(
        &self,
        mut client: C,
        mut remote: TcpStream,
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let _ = remote.set_nodelay(true);

        enum InitialOutcome {
            Done,
            ClientFlight(Vec<u8>),
            ServerSpokeFirst(ActiveConnGuard),
        }

        // Scope handshake buffers (`first_buf` 16.5 KiB + `remote_buf` 4 KiB) so they are
        // completely released BEFORE entering the long-lived bidirectional relay loop.
        let outcome = {
            let mut first_buf = vec![0u8; 16384 + 512];
            let mut remote_buf = vec![0u8; 4096];

            // Wait for initial client flight with a bounded idle timeout so stalled half-open
            // connections cannot pin session permits indefinitely, while staying safe for
            // server-speaks-first protocols.
            let initial_flight = tokio::time::timeout(Duration::from_secs(30), async {
                tokio::select! {
                    biased;
                    res = client.read(&mut first_buf) => Ok::<_, std::io::Error>((true, res?)),
                    res = remote.read(&mut remote_buf) => Ok::<_, std::io::Error>((false, res?)),
                }
            })
            .await;

            match initial_flight {
                Ok(Ok((true, 0))) | Ok(Ok((false, 0))) | Err(_) => InitialOutcome::Done,
                Ok(Ok((true, mut filled))) => {
                    // If the initial read returned fewer than 5 bytes (e.g. split TLS record header)
                    // and matches the TLS Handshake prefix (0x16 0x03), read up to 5 bytes under a
                    // short timeout before inspecting the outer TLS record length.
                    if filled < 5
                        && first_buf[0] == 0x16
                        && (filled == 1 || first_buf[1] == 0x03)
                        && (filled < 3 || first_buf[2] <= 0x04)
                    {
                        let _ = tokio::time::timeout(Duration::from_millis(200), async {
                            while filled < 5 {
                                let n = client.read(&mut first_buf[filled..5]).await?;
                                if n == 0 {
                                    break;
                                }
                                filled += n;
                                if (filled >= 2 && first_buf[1] != 0x03)
                                    || (filled >= 3 && first_buf[2] > 0x04)
                                {
                                    break;
                                }
                            }
                            Ok::<(), std::io::Error>(())
                        })
                        .await;
                    }
                    // If the first flight starts a TLS Handshake record (e.g. 1,800-byte Post-Quantum
                    // ClientHello), read until the complete outer TLS record has arrived before splitting records.
                    if let Some(expected_total) = expected_tls_record_len(&first_buf[..filled]) {
                        if expected_total <= first_buf.len() && filled < expected_total {
                            let _ = tokio::time::timeout(Duration::from_millis(600), async {
                                while filled < expected_total {
                                    let n =
                                        client.read(&mut first_buf[filled..expected_total]).await?;
                                    if n == 0 {
                                        break;
                                    }
                                    filled += n;
                                }
                                Ok::<(), std::io::Error>(())
                            })
                            .await;
                        }
                    }
                    first_buf.truncate(filled);
                    InitialOutcome::ClientFlight(first_buf)
                }
                Ok(Ok((false, n))) => {
                    let guard = ActiveConnGuard::enter(&self.telemetry);
                    client.write_all(&remote_buf[..n]).await?;
                    self.telemetry
                        .bytes_rx
                        .fetch_add(n as u64, Ordering::Relaxed);
                    InitialOutcome::ServerSpokeFirst(guard)
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        };

        match outcome {
            InitialOutcome::Done => Ok(()),
            InitialOutcome::ServerSpokeFirst(_guard) => {
                let _ = relay_bidirectional(&mut client, remote, &self.telemetry).await?;
                Ok(())
            }
            InitialOutcome::ClientFlight(first_buf) => {
                let _guard = ActiveConnGuard::enter(&self.telemetry);
                let established = {
                    let stream = self
                        .establish_initial_flight(
                            &mut client,
                            remote,
                            &first_buf,
                            known_host,
                            remote_addr,
                        )
                        .await?;
                    drop(first_buf);
                    stream
                };
                let _ = relay_bidirectional(&mut client, established, &self.telemetry).await?;
                Ok(())
            }
        }
    }

    /// Delivers an already-buffered initial client flight (`payload`) to `remote` with 7-stage
    /// adaptive TLS auto-healing, stale-cache eviction, and strict ServerHello validation,
    /// then enters full-speed bidirectional streaming.
    pub async fn establish_and_relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let _ = client.set_nodelay(true);
        self.establish_and_relay_stream(client, remote, payload, known_host, remote_addr)
            .await
    }

    /// Generic stream variant of [`Self::establish_and_relay`] usable with userspace TUN TCP streams.
    pub async fn establish_and_relay_stream<C>(
        &self,
        mut client: C,
        remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let _ = remote.set_nodelay(true);
        let _guard = ActiveConnGuard::enter(&self.telemetry);
        let established = self
            .establish_initial_flight(&mut client, remote, payload, known_host, remote_addr)
            .await?;
        let _ = relay_bidirectional(&mut client, established, &self.telemetry).await?;
        Ok(())
    }

    /// Sends the initial client flight to `remote` (running the 7-stage adaptive TLS auto-heal
    /// loop when applicable) and returns the ready upstream `TcpStream` so callers can drop
    /// handshake buffers before entering the bidirectional relay loop.
    async fn establish_initial_flight<C>(
        &self,
        client: &mut C,
        remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<TcpStream>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_initial_flight_with_deadline(
            client,
            remote,
            payload,
            known_host,
            remote_addr,
            MAX_HANDSHAKE_DEADLINE,
        )
        .await
    }

    async fn establish_initial_flight_with_deadline<C>(
        &self,
        client: &mut C,
        remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
        handshake_budget: Duration,
    ) -> Result<TcpStream>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        self.establish_initial_flight_inner(
            client,
            remote,
            payload,
            known_host,
            remote_addr,
            HandshakeAttemptConfig {
                budget: handshake_budget,
                preseeded_retry_addrs: None,
            },
        )
        .await
    }

    async fn establish_initial_flight_inner<C>(
        &self,
        client: &mut C,
        mut remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
        attempt_cfg: HandshakeAttemptConfig,
    ) -> Result<TcpStream>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let remote_addr = canonical_socket_addr(remote_addr);
        let remote_ip = remote_addr.ip();

        if let Some(ch_info) = parse_client_hello(payload) {
            self.telemetry
                .tls_handshakes
                .fetch_add(1, Ordering::Relaxed);
            let effective_host = ch_info.sni.as_deref().or(known_host);
            if !self.bypass.should_desync(effective_host, Some(remote_ip)) {
                debug!(host = ?effective_host, %remote_ip, "TLS passthrough (bypassed)");
                remote.write_all(payload).await?;
                self.telemetry
                    .bytes_tx
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                return Ok(remote);
            }

            let cache_key = effective_host
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|k| is_valid_cache_host(k));
            let cached_stage = match cache_key.as_ref() {
                Some(key) => self.lookup_cached_host_stage(key).await,
                None => None,
            };

            let current_global_stage = self.preferred_stage();

            // Coalesced TLS 1.3 0-RTT early data (`payload.len() > ch_info.record_total_len`):
            // - If a trailing record spans beyond `first_buf` (incomplete TLS record), blocking
            //   for `ServerHello` before forwarding the remainder deadlocks the handshake.
            // - If trailing records contain TLS 1.3 0-RTT `ApplicationData` (`0x17`), replaying
            //   early data across retry attempts risks non-idempotent request duplication.
            // In both cases apply the cached/preferred desync strategy ONCE, forward trailing
            // bytes, and enter `relay_bidirectional` immediately.
            let trailing = &payload[ch_info.record_total_len..];
            if !trailing.is_empty()
                && (!are_trailing_tls_records_complete(trailing)
                    || trailing_contains_tls_app_data(trailing))
            {
                let stage = cached_stage.unwrap_or(current_global_stage);
                self.write_tls_flight(&mut remote, payload, &ch_info, stage)
                    .await?;
                self.telemetry
                    .bytes_tx
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                return Ok(remote);
            }

            let stages = self.build_stage_order(cached_stage);
            let mut retry_addrs: Option<Vec<SocketAddr>> = attempt_cfg.preseeded_retry_addrs;
            let mut dead_retry_ips: Vec<SocketAddr> = Vec::new();

            let mut probe_buf = vec![0u8; 16384 + 512];
            let mut current_remote = Some(remote);
            let mut current_global_hard_blocked = false;
            let mut current_global_timed_out = false;
            let mut saw_tls_alert = false;
            let mut prefer_same_ip_retry = false;
            let handshake_deadline = Instant::now() + attempt_cfg.budget;
            let mut tried_direct_passthrough = false;
            let mut deadline_exceeded = false;

            for (idx, &stage) in stages.iter().enumerate() {
                let is_direct_passthrough = stage == LearnedStrategy::DirectPassthrough;
                if deadline_exceeded && (!is_direct_passthrough || tried_direct_passthrough) {
                    continue;
                }

                let now = Instant::now();
                let stage_deadline = compute_stage_deadline(now, handshake_deadline, stage);
                let remaining = stage_deadline.saturating_duration_since(now);
                if remaining.is_zero() {
                    deadline_exceeded = true;
                    debug!(
                        host = ?effective_host,
                        idx,
                        ?stage,
                        "adaptive TLS handshake deadline exceeded; skipping remaining desync stages"
                    );
                    continue;
                }

                if is_direct_passthrough {
                    tried_direct_passthrough = true;
                }

                let is_last_stage = idx + 1 == stages.len();
                let (mut stream, stream_addr) = match current_remote.take() {
                    Some(s) => (s, remote_addr),
                    None => {
                        let connected = if deadline_exceeded {
                            connect_retry_stream(
                                self,
                                remote_addr,
                                remote_addr,
                                stage_deadline,
                                &mut dead_retry_ips,
                            )
                            .await
                        } else if prefer_same_ip_retry {
                            // Stage 0 failed with a server TLS Alert or fast FIN: the server is
                            // alive and merely rejected the strategy, so dial `remote_addr` first.
                            match connect_retry_stream(
                                self,
                                remote_addr,
                                remote_addr,
                                stage_deadline,
                                &mut dead_retry_ips,
                            )
                            .await
                            {
                                Some(pair) => Some(pair),
                                None => {
                                    prefer_same_ip_retry = false;
                                    let fallback_remaining =
                                        stage_deadline.saturating_duration_since(Instant::now());
                                    let addrs = match retry_addrs.as_ref() {
                                        Some(a) => a,
                                        None => {
                                            let resolved = self
                                                .collect_retry_addrs(
                                                    known_host,
                                                    ch_info.sni.as_deref(),
                                                    remote_addr,
                                                    fallback_remaining,
                                                )
                                                .await;
                                            retry_addrs.insert(resolved)
                                        }
                                    };
                                    self.sync_dead_retry_ips(addrs, &mut dead_retry_ips).await;
                                    let alt_target = select_retry_target(
                                        addrs,
                                        remote_addr,
                                        &dead_retry_ips,
                                        idx,
                                    );
                                    if alt_target != remote_addr {
                                        connect_retry_stream(
                                            self,
                                            alt_target,
                                            remote_addr,
                                            stage_deadline,
                                            &mut dead_retry_ips,
                                        )
                                        .await
                                    } else {
                                        None
                                    }
                                }
                            }
                        } else {
                            let addrs = match retry_addrs.as_ref() {
                                Some(a) => a,
                                None => {
                                    let resolved = self
                                        .collect_retry_addrs(
                                            known_host,
                                            ch_info.sni.as_deref(),
                                            remote_addr,
                                            remaining,
                                        )
                                        .await;
                                    retry_addrs.insert(resolved)
                                }
                            };
                            self.sync_dead_retry_ips(addrs, &mut dead_retry_ips).await;
                            let alt_target =
                                select_retry_target(addrs, remote_addr, &dead_retry_ips, idx);
                            connect_retry_stream(
                                self,
                                alt_target,
                                remote_addr,
                                stage_deadline,
                                &mut dead_retry_ips,
                            )
                            .await
                        };
                        match connected {
                            Some(pair) => pair,
                            None => {
                                prefer_same_ip_retry = false;
                                continue;
                            }
                        }
                    }
                };

                let write_remaining = stage_deadline.saturating_duration_since(Instant::now());
                if write_remaining.is_zero() {
                    if is_last_stage {
                        break;
                    }
                    deadline_exceeded = true;
                    continue;
                }

                match tokio::time::timeout(
                    write_remaining,
                    self.write_tls_flight(&mut stream, payload, &ch_info, stage),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        prefer_same_ip_retry = false;
                        if !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if stage == current_global_stage && is_hard_block_write_error(&err) {
                            current_global_hard_blocked = true;
                        }
                        continue;
                    }
                    Err(_) => {
                        prefer_same_ip_retry = false;
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            "adaptive TLS handshake deadline exceeded during strategy write"
                        );
                        if is_last_stage {
                            break;
                        }
                        deadline_exceeded = true;
                        continue;
                    }
                }

                let read_remaining = stage_deadline.saturating_duration_since(Instant::now());
                if read_remaining.is_zero() {
                    if is_last_stage {
                        break;
                    }
                    deadline_exceeded = true;
                    continue;
                }

                let wait_ms = match stage {
                    _ if idx == 0 => 2200,
                    LearnedStrategy::DeepRecordStorm | LearnedStrategy::SlowSniSlice => 2000,
                    _ => 1800,
                };
                let read_timeout = Duration::from_millis(wait_ms).min(read_remaining);

                let read_started = Instant::now();
                match tokio::time::timeout(read_timeout, stream.read(&mut probe_buf)).await {
                    Ok(Ok(0)) => {
                        if !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        let elapsed = read_started.elapsed();
                        if idx == 0 && elapsed < FAST_EOF_THRESHOLD {
                            prefer_same_ip_retry = true;
                        } else if elapsed >= FAST_EOF_THRESHOLD {
                            prefer_same_ip_retry = false;
                        }
                        if stage == current_global_stage && elapsed < FAST_EOF_THRESHOLD {
                            current_global_hard_blocked = true;
                        }
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            elapsed_ms = elapsed.as_millis() as u64,
                            "TLS stage received EOF; auto-healing with next stage"
                        );
                        continue;
                    }
                    Ok(Ok(mut n)) => {
                        if n == 1 && probe_buf[0] == 0x16 {
                            let hdr_wait = read_remaining.min(Duration::from_millis(400));
                            if !hdr_wait.is_zero() {
                                let _ = tokio::time::timeout(hdr_wait, async {
                                    while n < 5 {
                                        let m = stream.read(&mut probe_buf[n..5]).await?;
                                        if m == 0 {
                                            break;
                                        }
                                        n += m;
                                        if n >= 2 && probe_buf[1] != 0x03 {
                                            break;
                                        }
                                    }
                                    Ok::<(), std::io::Error>(())
                                })
                                .await;
                            }
                        }

                        let is_valid_tls_server_hello =
                            n >= 2 && probe_buf[0] == 0x16 && probe_buf[1] == 0x03;

                        if !is_valid_tls_server_hello && !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                            if probe_buf[0] == 0x15 {
                                if idx == 0 {
                                    prefer_same_ip_retry = true;
                                }
                                if stage == current_global_stage {
                                    saw_tls_alert = true;
                                }
                                debug!(
                                    host = ?effective_host,
                                    ?stage,
                                    "upstream returned TLS Alert (0x15); auto-healing with next stage"
                                );
                            } else {
                                prefer_same_ip_retry = false;
                                // Non-TLS response on a TLS handshake (e.g. ISP injected HTTP 302/403 block page)
                                if stage == current_global_stage {
                                    current_global_hard_blocked = true;
                                }
                                debug!(
                                    host = ?effective_host,
                                    ?stage,
                                    first_byte = probe_buf[0],
                                    "non-TLS response on TLS handshake (possible DPI block injection); escalating"
                                );
                            }
                            continue;
                        }

                        let mut expected_server_record_len = None;
                        let record_stage_promotion = if is_valid_tls_server_hello {
                            let elapsed = read_started.elapsed();
                            let used_alternate_ip =
                                canonical_socket_addr(stream_addr) != remote_addr;
                            let silent_drop_recovered =
                                current_global_timed_out && elapsed < FAST_SERVER_HELLO_THRESHOLD;
                            let oob_alert_demotion = current_global_stage.is_oob()
                                && saw_tls_alert
                                && stage.is_clean_non_oob();
                            let eligible_for_promotion = idx > 0
                                && !used_alternate_ip
                                && (((current_global_hard_blocked || silent_drop_recovered)
                                    && !saw_tls_alert)
                                    || oob_alert_demotion);

                            // Finish reading the full outer ServerHello/HRR TLS record before
                            // checking HelloRetryRequest and forwarding to the client so a
                            // partial HRR read cannot either miss HRR detection (< 43 bytes)
                            // or deadlock waiting for ClientHello #2 while tail bytes remain unread.
                            if n < 5 {
                                let _ =
                                    tokio::time::timeout(Duration::from_millis(400), async {
                                        while n < 5 {
                                            let m = stream.read(&mut probe_buf[n..5]).await?;
                                            if m == 0 {
                                                break;
                                            }
                                            n += m;
                                        }
                                        Ok::<(), std::io::Error>(())
                                    })
                                    .await;
                            }
                            expected_server_record_len = expected_tls_record_len(&probe_buf[..n]);
                            if let Some(expected_total) = expected_server_record_len
                                .filter(|&total| total <= probe_buf.len() && n < total)
                            {
                                let _ =
                                    tokio::time::timeout(Duration::from_millis(1000), async {
                                        while n < expected_total {
                                            let m = stream.read(&mut probe_buf[n..]).await?;
                                            if m == 0 {
                                                break;
                                            }
                                            n += m;
                                        }
                                        Ok::<(), std::io::Error>(())
                                    })
                                    .await;
                            }
                            Some(eligible_for_promotion)
                        } else {
                            None
                        };

                        let is_hrr = is_valid_tls_server_hello
                            && expected_server_record_len
                                .is_some_and(|expected_total| n >= expected_total)
                            && is_tls_hello_retry_request(&probe_buf[..n]);

                        // Drain any trailing TLS 1.3 middlebox ChangeCipherSpec (6 bytes:
                        // `0x14 0x03 0x03 0x00 0x01 0x01`) coalesced with or immediately
                        // following HelloRetryRequest so the client receives complete records
                        // before waiting for ClientHello #2.
                        if let Some(expected_total) = expected_server_record_len.filter(|_| is_hrr)
                        {
                            let ccs_end = (expected_total + 6).min(probe_buf.len());
                            if n == expected_total && n < ccs_end {
                                n += stream.try_read(&mut probe_buf[n..ccs_end]).unwrap_or(0);
                            }
                            if n > expected_total
                                && n < ccs_end
                                && probe_buf[expected_total] == 0x14
                                && (n - expected_total < 2
                                    || probe_buf[expected_total + 1] == 0x03)
                            {
                                let _ =
                                    tokio::time::timeout(Duration::from_millis(400), async {
                                        while n < ccs_end {
                                            let m = stream
                                                .read(&mut probe_buf[n..ccs_end])
                                                .await?;
                                            if m == 0 {
                                                break;
                                            }
                                            n += m;
                                            if n - expected_total >= 2
                                                && probe_buf[expected_total + 1] != 0x03
                                            {
                                                break;
                                            }
                                        }
                                        Ok::<(), std::io::Error>(())
                                    })
                                    .await;
                            }
                        }

                        self.telemetry
                            .bytes_tx
                            .fetch_add(payload.len() as u64, Ordering::Relaxed);
                        self.telemetry
                            .bytes_rx
                            .fetch_add(n as u64, Ordering::Relaxed);
                        client.write_all(&probe_buf[..n]).await?;
                        client.flush().await?;
                        drop(probe_buf);

                        // Record learned stage only after the ServerHello has been delivered to
                        // the client so aborted/timed-out client connections never poison cache.
                        if let Some(eligible_for_promotion) = record_stage_promotion {
                            self.record_host_stage_with_escalation(
                                cache_key.as_deref(),
                                stage,
                                eligible_for_promotion,
                                idx > 0,
                            )
                            .await;
                        } else if let (Some(_), Some(key)) = (cached_stage, cache_key.as_deref()) {
                            self.evict_cached_host_stage(key).await;
                        }

                        // TLS 1.3 HelloRetryRequest (e.g. server declines iOS X25519MLKEM768
                        // key_share and requests secp256r1/x25519): forward any late-arriving
                        // server CCS bytes cleanly while waiting for ClientHello #2, then apply
                        // the exact winning desync strategy so DPI cannot drop CH #2.
                        if is_hrr {
                            let mut ch2_buf = vec![0u8; 16384 + 512];
                            let mut srv_tail = [0u8; 64];
                            let mut srv_tail_forwarded = 0usize;
                            let hrr_deadline = Instant::now() + Duration::from_secs(4);
                            let mut filled2 = 0usize;
                            loop {
                                let wait = hrr_deadline.saturating_duration_since(Instant::now());
                                if wait.is_zero() {
                                    break;
                                }
                                let next = tokio::time::timeout(wait, async {
                                    tokio::select! {
                                        biased;
                                        res = client.read(&mut ch2_buf) => Ok::<_, std::io::Error>((true, res?)),
                                        res = stream.read(&mut srv_tail) => Ok::<_, std::io::Error>((false, res?)),
                                    }
                                })
                                .await;
                                match next {
                                    Ok(Ok((true, m))) => {
                                        filled2 = m;
                                        break;
                                    }
                                    Ok(Ok((false, 0))) | Ok(Err(_)) | Err(_) => {
                                        break;
                                    }
                                    Ok(Ok((false, m))) => {
                                        client.write_all(&srv_tail[..m]).await?;
                                        client.flush().await?;
                                        self.telemetry
                                            .bytes_rx
                                            .fetch_add(m as u64, Ordering::Relaxed);
                                        srv_tail_forwarded += m;
                                        if srv_tail_forwarded >= srv_tail.len() {
                                            break;
                                        }
                                    }
                                }
                            }
                            if filled2 > 0 {
                                // Finish reading a split 6-byte ChangeCipherSpec prefix
                                // (`0x14 0x03 0x03 0x00 0x01 0x01`) before parsing CH #2.
                                if filled2 < 6
                                    && ch2_buf[0] == 0x14
                                    && (filled2 == 1 || ch2_buf[1] == 0x03)
                                {
                                    let _ = tokio::time::timeout(
                                        Duration::from_millis(400),
                                        async {
                                            while filled2 < 6 {
                                                let m = client
                                                    .read(&mut ch2_buf[filled2..6])
                                                    .await?;
                                                if m == 0 {
                                                    break;
                                                }
                                                filled2 += m;
                                                if filled2 >= 2 && ch2_buf[1] != 0x03 {
                                                    break;
                                                }
                                            }
                                            Ok::<(), std::io::Error>(())
                                        },
                                    )
                                    .await;
                                }
                                // Skip optional leading 6-byte ChangeCipherSpec record (0x14 0x03 0x03 0x00 0x01 0x01)
                                let ccs_prefix =
                                    if filled2 >= 6 && ch2_buf[0] == 0x14 && ch2_buf[1] == 0x03 {
                                        6usize
                                    } else {
                                        0usize
                                    };
                                // If CCS arrived alone or the CH #2 5-byte TLS record header was split
                                // across TCP reads, finish reading the header before inspecting record len.
                                let header_end = ccs_prefix + 5;
                                if filled2 < header_end
                                    && (filled2 == ccs_prefix
                                        || (ch2_buf[ccs_prefix] == 0x16
                                            && (filled2 - ccs_prefix < 2
                                                || ch2_buf[ccs_prefix + 1] == 0x03)
                                            && (filled2 - ccs_prefix < 3
                                                || ch2_buf[ccs_prefix + 2] <= 0x04)))
                                {
                                    let _ = tokio::time::timeout(
                                        Duration::from_millis(400),
                                        async {
                                            while filled2 < header_end {
                                                let m = client
                                                    .read(&mut ch2_buf[filled2..header_end])
                                                    .await?;
                                                if m == 0 {
                                                    break;
                                                }
                                                filled2 += m;
                                                let ch2_have = filled2 - ccs_prefix;
                                                if (ch2_have >= 1 && ch2_buf[ccs_prefix] != 0x16)
                                                    || (ch2_have >= 2
                                                        && ch2_buf[ccs_prefix + 1] != 0x03)
                                                    || (ch2_have >= 3
                                                        && ch2_buf[ccs_prefix + 2] > 0x04)
                                                {
                                                    break;
                                                }
                                            }
                                            Ok::<(), std::io::Error>(())
                                        },
                                    )
                                    .await;
                                }
                                if let Some(expected2) =
                                    expected_tls_record_len(&ch2_buf[ccs_prefix..filled2])
                                {
                                    let target_len = (ccs_prefix + expected2).min(ch2_buf.len());
                                    if filled2 < target_len {
                                        let _ = tokio::time::timeout(
                                            Duration::from_millis(600),
                                            async {
                                                while filled2 < target_len {
                                                    let m = client
                                                        .read(&mut ch2_buf[filled2..target_len])
                                                        .await?;
                                                    if m == 0 {
                                                        break;
                                                    }
                                                    filled2 += m;
                                                }
                                                Ok::<(), std::io::Error>(())
                                            },
                                        )
                                        .await;
                                    }
                                }
                                let ch2_slice = &ch2_buf[..filled2];
                                if ccs_prefix > 0 {
                                    stream.write_all(&ch2_slice[..ccs_prefix]).await?;
                                }
                                let tail = &ch2_slice[ccs_prefix..];
                                if let Some(ch2_info) = parse_client_hello(tail) {
                                    self.write_tls_flight(&mut stream, tail, &ch2_info, stage)
                                        .await?;
                                } else if !tail.is_empty() {
                                    stream.write_all(tail).await?;
                                }
                                self.telemetry
                                    .bytes_tx
                                    .fetch_add(filled2 as u64, Ordering::Relaxed);
                            }
                        }

                        return Ok(stream);
                    }
                    Ok(Err(err)) => {
                        prefer_same_ip_retry = false;
                        if !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if stage == current_global_stage && is_hard_block_io_error(&err) {
                            current_global_hard_blocked = true;
                        }
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            error = %err,
                            "TLS stage I/O error; auto-healing with next stage"
                        );
                        continue;
                    }
                    Err(_) => {
                        prefer_same_ip_retry = false;
                        if !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        if stage == current_global_stage {
                            current_global_timed_out = true;
                        }
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            "TLS stage read timed out; auto-healing with next stage"
                        );
                        continue;
                    }
                }
            }

            // If all stages failed and we had a stale cached strategy, clear it so the next attempt probes fresh.
            if let (Some(_), Some(key)) = (cached_stage, cache_key.as_deref()) {
                self.evict_cached_host_stage(key).await;
            }

            bail!(
                "all adaptive TLS handshake stages failed for {:?}",
                effective_host
            );
        }

        // Non-TLS or plain HTTP traffic
        self.write_initial_flight(&mut remote, payload, known_host, remote_ip)
            .await?;
        self.telemetry
            .bytes_tx
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(remote)
    }

    /// Records a verified TLS handshake stage for `host`, enforcing:
    /// - Exception-only `adaptive_cache`: only hosts whose stage differs from `preferred_isp_stage`
    ///   are inserted; hosts matching `preferred_isp_stage` remove any stale override entry.
    /// - Quorum-gated `HardBlock`-only promotion of `preferred_isp_stage` (>= 3 distinct hosts for
    ///   `Primary`/`OobSniDesync`/`MultiRecordOob`, >= 5 distinct hosts for slow stages
    ///   `DeepRecordStorm`/`SlowSniSlice`; `FineFragment` never promotes from `Primary`).
    #[cfg(test)]
    pub(crate) async fn record_host_stage(
        &self,
        host: Option<&str>,
        stage: LearnedStrategy,
        hard_block_promotion_eligible: bool,
    ) {
        self.record_host_stage_with_escalation(host, stage, hard_block_promotion_eligible, false)
            .await;
    }

    async fn record_host_stage_with_escalation(
        &self,
        host: Option<&str>,
        stage: LearnedStrategy,
        hard_block_promotion_eligible: bool,
        escalated: bool,
    ) {
        let Some(key) = host
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|k| is_valid_cache_host(k))
        else {
            return;
        };

        let mut cache_changed = false;
        let mut promoted = false;

        if hard_block_promotion_eligible {
            let now = unix_now_secs();
            let current_global = self.preferred_stage();
            let reached_quorum = {
                let mut tracker = self
                    .promotion_votes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                tracker.record_vote(current_global, stage, &key, now)
            };
            if reached_quorum {
                let updated_at = if stage == LearnedStrategy::Primary {
                    0
                } else {
                    now
                };
                self.preferred_isp_stage_updated_at
                    .store(updated_at, Ordering::Release);
                let prev = self.preferred_isp_stage.swap(stage as u8, Ordering::AcqRel);
                if prev != stage as u8 {
                    cache_changed = true;
                    promoted = true;
                }
            }
        }

        let parent_key_opt = parent_domain_cache_key(&key);

        // Fast-path: when no global promotion occurred, check under shared read locks whether
        // the cache already reflects `stage` (either uncached when matching `preferred_stage()`,
        // covered by an existing parent wildcard / apex on a non-escalated `idx == 0` hit, or
        // already cached with the unchanged exception `stage`) before taking exclusive write locks.
        if !promoted {
            let now = unix_now_secs();
            let current_preferred = self.preferred_stage();
            let guard = self.adaptive_cache.read().await;
            let ts_guard = self.adaptive_timestamps.read().await;
            let is_fresh = |k: &str, s: LearnedStrategy| {
                ts_guard
                    .get(k)
                    .is_none_or(|&ts| now.saturating_sub(ts) <= s.cache_ttl_secs())
            };
            let already_up_to_date = if stage == current_preferred {
                let has_exact = guard.contains_key(&key);
                let has_stale_inherited = escalated
                    && parent_key_opt.as_deref().is_some_and(|p| {
                        guard.contains_key(p)
                            || p.strip_prefix("*.").is_some_and(|apex| {
                                guard
                                    .get(apex)
                                    .is_some_and(|s| s.allows_parent_wildcard())
                            })
                    });
                !has_exact && !has_stale_inherited
            } else if !escalated
                && stage.allows_parent_wildcard()
                && parent_key_opt
                    .as_deref()
                    .is_some_and(|p| guard.get(p) == Some(&stage) && is_fresh(p, stage))
            {
                // Succeeded on attempt 0 (`idx == 0`) via an existing parent wildcard:
                // skip writing a duplicate subdomain entry and do not refresh the wildcard TTL.
                true
            } else if !escalated
                && stage.allows_parent_wildcard()
                && !guard.contains_key(&key)
                && parent_key_opt
                    .as_deref()
                    .and_then(|p| p.strip_prefix("*."))
                    .is_some_and(|apex| guard.get(apex) == Some(&stage) && is_fresh(apex, stage))
            {
                true
            } else if guard.get(&key) != Some(&stage) || !is_fresh(&key, stage) {
                false
            } else if stage != current_preferred && stage.allows_parent_wildcard() {
                parent_key_opt.as_deref().is_none_or(|parent_key| {
                    guard.get(parent_key) == Some(&stage) && is_fresh(parent_key, stage)
                })
            } else {
                true
            };
            if already_up_to_date {
                return;
            }
        }

        let now = unix_now_secs();
        {
            let mut guard = self.adaptive_cache.write().await;
            let mut ts_guard = self.adaptive_timestamps.write().await;
            let current_preferred = self.preferred_stage();

            if promoted {
                let mut removed_any = false;
                guard.retain(|h, s| {
                    let keep = *s != current_preferred;
                    if !keep {
                        ts_guard.remove(h);
                        removed_any = true;
                    }
                    keep
                });
                if removed_any {
                    cache_changed = true;
                }
            }

            if stage == current_preferred {
                if guard.remove(&key).is_some() {
                    ts_guard.remove(&key);
                    cache_changed = true;
                }
                if escalated {
                    if let Some(ref parent_key) = parent_key_opt {
                        if guard.remove(parent_key).is_some() {
                            ts_guard.remove(parent_key);
                            cache_changed = true;
                        }
                        if let Some(apex) = parent_key.strip_prefix("*.") {
                            if guard
                                .get(apex)
                                .is_some_and(|s| s.allows_parent_wildcard())
                                && guard.remove(apex).is_some()
                            {
                                ts_guard.remove(apex);
                                cache_changed = true;
                            }
                        }
                    }
                }
            } else {
                let parent_key = if stage != current_preferred && stage.allows_parent_wildcard() {
                    parent_key_opt
                } else {
                    None
                };
                let parent_already_matches = !escalated
                    && parent_key.as_deref().is_some_and(|p| {
                        guard.get(p) == Some(&stage)
                            && ts_guard
                                .get(p)
                                .is_none_or(|&ts| now.saturating_sub(ts) <= stage.cache_ttl_secs())
                    });
                if !parent_already_matches {
                    if upsert_adaptive_entry(&mut guard, &mut ts_guard, key, stage, now) {
                        cache_changed = true;
                    }
                    if let Some(parent_key) = parent_key {
                        cache_changed |=
                            upsert_adaptive_entry(&mut guard, &mut ts_guard, parent_key, stage, now);
                    }
                }
            }

            self.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }

        if cache_changed {
            self.maybe_persist_cache();
        }
    }

    async fn lookup_cached_host_stage(&self, key: &str) -> Option<LearnedStrategy> {
        let now = unix_now_secs();
        let guard = self.adaptive_cache.read().await;
        let ts_guard = self.adaptive_timestamps.read().await;
        let is_fresh = |k: &str, s: LearnedStrategy| {
            ts_guard
                .get(k)
                .is_none_or(|&ts| now.saturating_sub(ts) <= s.cache_ttl_secs())
        };
        if let Some(&stage) = guard.get(key).filter(|&&s| is_fresh(key, s)) {
            return Some(stage);
        }
        if let Some(parent_key) = parent_domain_cache_key(key) {
            if let Some(stage) = guard
                .get(&parent_key)
                .copied()
                .filter(|&s| s.allows_parent_wildcard() && is_fresh(&parent_key, s))
            {
                return Some(stage);
            }
            if let Some(apex) = parent_key.strip_prefix("*.") {
                if let Some(stage) = guard
                    .get(apex)
                    .copied()
                    .filter(|&s| s.allows_parent_wildcard() && is_fresh(apex, s))
                {
                    return Some(stage);
                }
            }
        }
        None
    }

    async fn evict_cached_host_stage(&self, key: &str) {
        let removed = {
            let mut guard = self.adaptive_cache.write().await;
            let mut ts_guard = self.adaptive_timestamps.write().await;
            let mut removed = false;
            if guard.remove(key).is_some() {
                ts_guard.remove(key);
                removed = true;
            }
            if let Some(parent_key) = parent_domain_cache_key(key) {
                if guard.remove(&parent_key).is_some() {
                    ts_guard.remove(&parent_key);
                    removed = true;
                }
                if let Some(apex) = parent_key.strip_prefix("*.") {
                    if guard
                        .get(apex)
                        .is_some_and(|s| s.allows_parent_wildcard())
                        && guard.remove(apex).is_some()
                    {
                        ts_guard.remove(apex);
                        removed = true;
                    }
                }
            }
            self.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
            removed
        };
        if removed {
            self.maybe_persist_cache();
        }
    }

    fn build_stage_order(&self, cached_stage: Option<LearnedStrategy>) -> Vec<LearnedStrategy> {
        let mut order = Vec::with_capacity(ALL_STAGES.len());
        let fragment_primary = self.config.mode == DesyncMode::Fragment;
        let is_duplicate = |order: &[LearnedStrategy], candidate: LearnedStrategy| {
            order.contains(&candidate)
                || (fragment_primary
                    && ((candidate == LearnedStrategy::FineFragment
                        && order.contains(&LearnedStrategy::Primary))
                        || (candidate == LearnedStrategy::Primary
                            && order.contains(&LearnedStrategy::FineFragment))))
        };
        if let Some(cached) = cached_stage {
            order.push(cached);
        }
        let preferred = self.preferred_stage();
        if !is_duplicate(&order, preferred) {
            order.push(preferred);
        }
        for stage in ALL_STAGES {
            if !is_duplicate(&order, stage) {
                order.push(stage);
            }
        }
        order
    }

    async fn collect_retry_addrs(
        &self,
        known_host: Option<&str>,
        sni_host: Option<&str>,
        initial_addr: SocketAddr,
        max_wait: Duration,
    ) -> Vec<SocketAddr> {
        let initial_addr = canonical_socket_addr(initial_addr);
        let mut addrs = vec![initial_addr];
        let resolve_timeout = RETRY_DNS_TIMEOUT.min(max_wait);
        if resolve_timeout.is_zero() || initial_addr.ip().is_loopback() {
            return addrs;
        }
        // Prefer caller-supplied `known_host` over untrusted ClientHello SNI when present.
        let host = known_host
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .or_else(|| sni_host.map(str::trim).filter(|h| !h.is_empty()));
        if let Some(h) = host {
            if let Ok(Ok(ips)) =
                tokio::time::timeout(resolve_timeout, self.dns.resolve_internal(h)).await
            {
                // Only rotate among public alternate IPs of the same address family that already
                // proved reachable on attempt 0 so unreachable IPv6 never stalls retries and
                // rogue DNS answers cannot SSRF into private/loopback/link-local targets.
                for ip in ips {
                    let ip = ip.to_canonical();
                    if BypassPolicy::is_non_public_ip(ip) {
                        continue;
                    }
                    if ip.is_ipv4() != initial_addr.is_ipv4() {
                        continue;
                    }
                    let sa = SocketAddr::new(ip, initial_addr.port());
                    if !addrs.contains(&sa) {
                        addrs.push(sa);
                    }
                }
            }
        }
        addrs
    }

    async fn write_tls_flight(
        &self,
        remote: &mut TcpStream,
        payload: &[u8],
        ch_info: &ClientHelloInfo,
        strategy: LearnedStrategy,
    ) -> Result<()> {
        if strategy == LearnedStrategy::DirectPassthrough
            || payload.len() <= ch_info.record_total_len
        {
            return self
                .write_tls_strategy(remote, payload, ch_info, strategy)
                .await;
        }
        // Coalesced TLS 1.3 0-RTT early data: apply DPI desync ONLY to the leading
        // ClientHello record, then immediately follow with the trailing early-data bytes.
        let (client_hello, trailing) = payload.split_at(ch_info.record_total_len);
        self.write_tls_strategy(remote, client_hello, ch_info, strategy)
            .await?;
        remote.write_all(trailing).await?;
        Ok(())
    }

    async fn write_tls_strategy(
        &self,
        remote: &mut TcpStream,
        payload: &[u8],
        ch_info: &ClientHelloInfo,
        strategy: LearnedStrategy,
    ) -> Result<()> {
        let chunk_len = self.config.chunk_size.max(1);
        match strategy {
            LearnedStrategy::Primary => match self.config.mode {
                DesyncMode::Combo => {
                    if let Some(records) = split_tls_records_multi(payload, ch_info, chunk_len) {
                        write_paced_records(remote, &records, Duration::from_millis(2), None)
                            .await?;
                    } else if let Some((rec1, rec2)) =
                        split_tls_records(payload, ch_info, chunk_len)
                    {
                        write_paced_slices(remote, &[&rec1, &rec2], Duration::from_millis(2))
                            .await?;
                    } else {
                        write_in_paced_chunks(remote, payload, chunk_len, Duration::from_millis(1))
                            .await?;
                    }
                }
                DesyncMode::TlsRecord => {
                    if let Some((rec1, rec2)) = split_tls_records(payload, ch_info, chunk_len) {
                        write_paced_slices(remote, &[&rec1, &rec2], Duration::from_millis(2))
                            .await?;
                    } else {
                        write_in_paced_chunks(remote, payload, chunk_len, Duration::from_millis(1))
                            .await?;
                    }
                }
                DesyncMode::Fragment => {
                    write_targeted_sni_slices(
                        remote,
                        payload,
                        ch_info,
                        Duration::from_millis(2),
                        false,
                    )
                    .await?;
                }
                DesyncMode::Split => {
                    let split_at = chunk_len.min(payload.len().saturating_sub(1)).max(1);
                    if payload.len() > 1 {
                        write_paced_slices(
                            remote,
                            &[&payload[..split_at], &payload[split_at..]],
                            Duration::from_millis(2),
                        )
                        .await?;
                    } else {
                        remote.write_all(payload).await?;
                    }
                }
            },
            LearnedStrategy::OobSniDesync => {
                // Inject 1 TCP Out-of-Band (MSG_OOB, URG=1) decoy byte right at the SNI midpoint.
                // Real server kernels strip the urgent byte (SO_OOBINLINE=0), while DPI stream
                // reassemblers ignore URG and see a corrupted hostname (e.g. "discaord.com").
                write_oob_sni_split(remote, payload, ch_info).await?;
            }
            LearnedStrategy::MultiRecordOob => {
                // Combine 4-record TLS splitting with a MSG_OOB decoy byte right at the boundary
                // before Record 4 so stateful DPI boxes lose TLS record framing completely.
                write_multi_record_oob(remote, payload, ch_info, chunk_len).await?;
            }
            LearnedStrategy::FineFragment => {
                // Single intact outer TLS record split across 4 wire-paced TCP segments
                // breaking both the 5-byte TLS record header and the SNI hostname midpoint.
                write_targeted_sni_slices(
                    remote,
                    payload,
                    ch_info,
                    Duration::from_millis(2),
                    false,
                )
                .await?;
            }
            LearnedStrategy::DeepRecordStorm => {
                // 12+ RFC-compliant TLS records: up to 10 tiny 2-byte lead records exhausting
                // DPI per-flow inspection packet caps BEFORE SNI appears, then SNI-split records
                // with a longer midpoint gap to defeat burst-window reassembly.
                if let Some(records) = split_tls_records_deep(payload, ch_info, chunk_len) {
                    let mid_idx = records.len().saturating_sub(2);
                    write_paced_records(
                        remote,
                        &records,
                        Duration::from_millis(4),
                        Some((mid_idx, Duration::from_millis(15))),
                    )
                    .await?;
                } else {
                    write_targeted_sni_slices(
                        remote,
                        payload,
                        ch_info,
                        Duration::from_millis(6),
                        true,
                    )
                    .await?;
                }
            }
            LearnedStrategy::SlowSniSlice => {
                // Single intact outer TLS record: breaks record header on packet 1, then slices
                // the SNI hostname itself into 2-byte paced segments with a 20ms midpoint gap.
                write_targeted_sni_slices(remote, payload, ch_info, Duration::from_millis(6), true)
                    .await?;
            }
            LearnedStrategy::DirectPassthrough => {
                remote.write_all(payload).await?;
            }
        }
        Ok(())
    }

    /// Writes an already-buffered initial request/handshake `payload` to `remote`, applying
    /// configured DPI desynchronization when eligible.
    pub async fn write_initial_flight(
        &self,
        remote: &mut TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_ip: IpAddr,
    ) -> Result<()> {
        if let Some(ch_info) = parse_client_hello(payload) {
            let effective_host = ch_info.sni.as_deref().or(known_host);
            if !self.bypass.should_desync(effective_host, Some(remote_ip)) {
                remote.write_all(payload).await?;
                return Ok(());
            }
            return self
                .write_tls_flight(remote, payload, &ch_info, LearnedStrategy::Primary)
                .await;
        }

        if let Some((http_host, hdr_split, val_split)) = extract_http_host_splits(payload) {
            let effective_host = Some(http_host.as_str()).or(known_host);
            if self.bypass.should_desync(effective_host, Some(remote_ip)) && payload.len() > 2 {
                debug!(host = %http_host, %remote_ip, "applying paced plain HTTP Host DPI split");
                if hdr_split < val_split && val_split < payload.len() {
                    write_paced_slices(
                        remote,
                        &[
                            &payload[..hdr_split],
                            &payload[hdr_split..val_split],
                            &payload[val_split..],
                        ],
                        Duration::from_millis(2),
                    )
                    .await?;
                } else {
                    write_paced_slices(
                        remote,
                        &[&payload[..val_split], &payload[val_split..]],
                        Duration::from_millis(2),
                    )
                    .await?;
                }
                return Ok(());
            }
        }

        remote.write_all(payload).await?;
        Ok(())
    }
}

struct HandshakeAttemptConfig {
    budget: Duration,
    preseeded_retry_addrs: Option<Vec<SocketAddr>>,
}

fn compute_stage_deadline(
    now: Instant,
    handshake_deadline: Instant,
    stage: LearnedStrategy,
) -> Instant {
    if stage == LearnedStrategy::DirectPassthrough {
        let min_fallback_deadline = now + DIRECT_PASSTHROUGH_FALLBACK_BUDGET;
        if handshake_deadline > min_fallback_deadline {
            handshake_deadline
        } else {
            min_fallback_deadline
        }
    } else {
        handshake_deadline
    }
}

async fn relay_bidirectional<C>(
    client: &mut C,
    remote: TcpStream,
    telemetry: &EngineTelemetry,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let active = AtomicBool::new(false);
    let mut counted = CountingStream::new(remote, telemetry, &active);
    let idle_watcher = async {
        let mut last_active = Instant::now();
        let mut check_interval = tokio::time::interval(Duration::from_secs(15));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check_interval.tick().await;
        loop {
            check_interval.tick().await;
            if active.swap(false, Ordering::Relaxed) {
                last_active = Instant::now();
            } else if last_active.elapsed() >= IDLE_RELAY_TIMEOUT {
                break;
            }
        }
    };
    tokio::select! {
        biased;
        res = copy_bidirectional_with_sizes(client, &mut counted, RELAY_BUF_SIZE, RELAY_BUF_SIZE) => res,
        _ = idle_watcher => Ok((0, 0)),
    }
}

// A wildcard listener has no concrete interface address. On a matching port,
// test whether the target belongs to this host without opening a connection.
fn can_bind_locally(mut addr: SocketAddr) -> bool {
    addr.set_port(0);
    let domain = socket2::Domain::for_address(addr);
    socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .and_then(|socket| socket.bind(&addr.into()))
        .is_ok()
}

fn canonical_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
            SocketAddr::new(addr.ip().to_canonical(), addr.port())
        }
        _ => addr,
    }
}

fn select_retry_target(
    addrs: &[SocketAddr],
    remote_addr: SocketAddr,
    dead_retry_ips: &[SocketAddr],
    idx: usize,
) -> SocketAddr {
    let live_count = addrs
        .iter()
        .skip(1)
        .filter(|addr| **addr != remote_addr && !dead_retry_ips.contains(addr))
        .count();
    if live_count == 0 {
        return remote_addr;
    }
    let pick = idx.saturating_sub(1) % live_count;
    addrs
        .iter()
        .skip(1)
        .copied()
        .filter(|addr| *addr != remote_addr && !dead_retry_ips.contains(addr))
        .nth(pick)
        .unwrap_or(remote_addr)
}

async fn connect_retry_stream(
    ctx: &EngineContext,
    target: SocketAddr,
    fallback: SocketAddr,
    deadline: Instant,
    dead_retry_ips: &mut Vec<SocketAddr>,
) -> Option<(TcpStream, SocketAddr)> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    if target != fallback && !dead_retry_ips.contains(&target) {
        if ctx.is_dead_retry_ip(target).await {
            dead_retry_ips.push(target);
        } else {
            if let Ok(Ok(s)) = tokio::time::timeout(
                Duration::from_millis(2200).min(remaining),
                ctx.connect_upstream(target),
            )
            .await
            {
                let _ = s.set_nodelay(true);
                return Some((s, target));
            }
            dead_retry_ips.push(target);
            ctx.mark_dead_retry_ip(target).await;
        }
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    if let Ok(Ok(s)) = tokio::time::timeout(
        Duration::from_millis(2200).min(remaining),
        ctx.connect_upstream(fallback),
    )
    .await
    {
        let _ = s.set_nodelay(true);
        return Some((s, fallback));
    }
    None
}

async fn write_paced_slices(
    stream: &mut TcpStream,
    slices: &[&[u8]],
    delay: Duration,
) -> Result<()> {
    for (idx, slice) in slices.iter().enumerate() {
        if slice.is_empty() {
            continue;
        }
        stream.write_all(slice).await?;
        if idx + 1 < slices.len() && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

async fn write_paced_records(
    stream: &mut TcpStream,
    records: &[Vec<u8>],
    delay: Duration,
    extra_pause: Option<(usize, Duration)>,
) -> Result<()> {
    for (idx, rec) in records.iter().enumerate() {
        if rec.is_empty() {
            continue;
        }
        stream.write_all(rec).await?;
        if idx + 1 < records.len() {
            let pause = match extra_pause {
                Some((target_idx, extra)) if idx == target_idx => extra,
                _ => delay,
            };
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
        }
    }
    Ok(())
}

async fn write_in_paced_chunks(
    stream: &mut TcpStream,
    data: &[u8],
    chunk_size: usize,
    delay: Duration,
) -> Result<()> {
    let step = chunk_size.max(1);
    let mut chunks = data.chunks(step).peekable();
    while let Some(chunk) = chunks.next() {
        stream.write_all(chunk).await?;
        if chunks.peek().is_some() && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

/// Sends a single intact outer TLS record split at strategic wire boundaries:
/// - Packet 1: `[0..2]` (breaks the 5-byte TLS record header)
/// - Packet 2: `[2..sni_start + 1]`
/// - Packet(s) across SNI: either midpoint split (fast) or 2-byte SNI slicing + 20ms midpoint gap (deep)
/// - Final packet: remainder of ClientHello
async fn write_targeted_sni_slices(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
    delay: Duration,
    slow_sni_bytes: bool,
) -> Result<()> {
    if payload.len() <= 6 {
        stream.write_all(payload).await?;
        return Ok(());
    }

    let (sni_start, sni_end) = match (ch_info.sni_payload_offset, ch_info.sni_len) {
        (Some(off), Some(len)) if len >= 2 => {
            let start = (5 + off).min(payload.len() - 1);
            let end = (5 + off + len).min(payload.len());
            (start, end)
        }
        _ => (2usize, payload.len().min(64)),
    };

    if !slow_sni_bytes {
        let cut1 = 2usize.min(sni_start);
        let cut2 = (sni_start + 1).min(sni_end).min(payload.len() - 1);
        let cut3 = (sni_start + ((sni_end - sni_start) / 2).max(1)).min(payload.len() - 1);

        let mut cuts = vec![cut1, cut2, cut3];
        cuts.sort_unstable();
        cuts.dedup();

        let mut slices = Vec::with_capacity(cuts.len() + 1);
        let mut prev = 0usize;
        for cut in cuts {
            if cut > prev && cut < payload.len() {
                slices.push(&payload[prev..cut]);
                prev = cut;
            }
        }
        if prev < payload.len() {
            slices.push(&payload[prev..]);
        }
        return write_paced_slices(stream, &slices, delay).await;
    }

    // Deep slow single-record mode: break header, send pre-SNI, then slice SNI in 2-byte packets
    // with a 20ms pause right at the SNI midpoint.
    stream.write_all(&payload[..2]).await?;
    tokio::time::sleep(delay).await;

    if sni_start > 2 {
        stream.write_all(&payload[2..sni_start]).await?;
        tokio::time::sleep(delay).await;
    }

    let sni_slice = &payload[sni_start..sni_end];
    let mid_chunk = (sni_slice.len() / 2) / 2;
    for (idx, chunk) in sni_slice.chunks(2).enumerate() {
        stream.write_all(chunk).await?;
        let pause = if idx == mid_chunk {
            Duration::from_millis(20)
        } else {
            delay
        };
        tokio::time::sleep(pause).await;
    }

    if sni_end < payload.len() {
        stream.write_all(&payload[sni_end..]).await?;
    }
    Ok(())
}

/// Sends a single intact TLS record while injecting 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`)
/// decoy byte right at the SNI hostname midpoint.
/// Destination TCP stacks strip the urgent byte (`SO_OOBINLINE=0`), while stateful DPI
/// stream reassemblers merge the decoy byte into the SNI and fail signature matching.
async fn write_oob_sni_split(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
) -> Result<()> {
    if payload.len() <= 6 {
        stream.write_all(payload).await?;
        return Ok(());
    }

    let split_at = match (ch_info.sni_payload_offset, ch_info.sni_len) {
        (Some(off), Some(len)) if len >= 2 => (5 + off + (len / 2)).clamp(1, payload.len() - 1),
        (Some(off), Some(_)) => (5 + off).clamp(1, payload.len() - 1),
        _ => (payload.len() / 2).clamp(1, payload.len() - 1),
    };

    // Keep the MSG_OOB write under 1024 bytes so the kernel transmits it atomically in a single
    // TCP segment with URG pointing directly at the trailing decoy byte (even for large
    // Post-Quantum ClientHellos where SNI appears past offset 1200).
    let oob_start = split_at.saturating_sub(1000);
    if oob_start > 0 {
        stream.write_all(&payload[..oob_start]).await?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let mut oob_chunk = Vec::with_capacity((split_at - oob_start) + 1);
    oob_chunk.extend_from_slice(&payload[oob_start..split_at]);
    oob_chunk.push(b'a');
    send_with_oob(stream, &oob_chunk).await?;

    tokio::time::sleep(Duration::from_millis(3)).await;
    stream.write_all(&payload[split_at..]).await?;
    Ok(())
}

/// Splits the ClientHello into 4 RFC-compliant TLS records and injects a 1-byte `MSG_OOB`
/// decoy right at the end of the pre-midpoint SNI record (shifting the following TLS record
/// header by 1 byte for any DPI engine that ignores TCP `URG`).
async fn write_multi_record_oob(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
    fallback_split: usize,
) -> Result<()> {
    let Some(records) = split_tls_records_multi(payload, ch_info, fallback_split) else {
        return write_oob_sni_split(stream, payload, ch_info).await;
    };

    let oob_rec_idx = records.len().saturating_sub(2);
    for (idx, rec) in records.iter().enumerate() {
        stream.write_all(rec).await?;
        if idx == oob_rec_idx {
            send_with_oob(stream, b"a").await?;
            tokio::time::sleep(Duration::from_millis(4)).await;
        } else if idx + 1 < records.len() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    Ok(())
}

async fn send_with_oob(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    // Write everything except the final urgent byte as normal TCP payload so a partial
    // write never emits duplicate TCP URG pointers or drops payload bytes mid-ClientHello.
    if data.len() > 1 {
        stream.write_all(&data[..data.len() - 1]).await?;
    }
    let oob_byte = &data[data.len() - 1..];
    loop {
        stream.writable().await?;
        let res = stream.try_io(Interest::WRITABLE, || raw_send_oob(stream, oob_byte));
        match res {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::BrokenPipe,
                    "peer closed connection during MSG_OOB send",
                )
                .into());
            }
            Ok(_) => return Ok(()),
            Err(ref e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(target_vendor = "apple")]
fn set_apple_nosigpipe(stream: &TcpStream) {
    use std::ffi::c_void;
    use std::os::unix::io::AsRawFd;

    const SOL_SOCKET: i32 = 0xffff;
    const SO_NOSIGPIPE: i32 = 0x1022;
    let one: i32 = 1;

    extern "C" {
        fn setsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *const c_void,
            optlen: u32,
        ) -> i32;
    }

    unsafe {
        let _ = setsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_NOSIGPIPE,
            (&one as *const i32).cast::<c_void>(),
            std::mem::size_of::<i32>() as u32,
        );
    }
}

#[cfg(unix)]
fn raw_send_oob(stream: &TcpStream, data: &[u8]) -> std::io::Result<usize> {
    use std::ffi::c_void;
    use std::os::unix::io::AsRawFd;

    #[cfg(target_vendor = "apple")]
    set_apple_nosigpipe(stream);

    const MSG_OOB: i32 = 0x1;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const SEND_FLAGS: i32 = MSG_OOB | 0x4000; // MSG_OOB | MSG_NOSIGNAL
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const SEND_FLAGS: i32 = MSG_OOB;

    extern "C" {
        fn send(sockfd: i32, buf: *const c_void, len: usize, flags: i32) -> isize;
    }

    let n = unsafe {
        send(
            stream.as_raw_fd(),
            data.as_ptr().cast::<c_void>(),
            data.len(),
            SEND_FLAGS,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(windows)]
fn disable_udp_connreset(sock: &socket2::Socket) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dw_io_control_code: u32,
            lpv_in_buffer: *const c_void,
            cb_in_buffer: u32,
            lpv_out_buffer: *mut c_void,
            cb_out_buffer: u32,
            lpcb_bytes_returned: *mut u32,
            lp_overlapped: *mut c_void,
            lp_completion_routine: *const c_void,
        ) -> i32;
    }

    let enable: i32 = 0; // BOOL FALSE
    let mut bytes_returned: u32 = 0;
    unsafe {
        let _ = WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&enable as *const i32).cast::<c_void>(),
            std::mem::size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null(),
        );
    }
}

#[cfg(windows)]
fn raw_send_oob(stream: &TcpStream, data: &[u8]) -> std::io::Result<usize> {
    use std::os::windows::io::AsRawSocket;

    const MSG_OOB: i32 = 0x1;
    const WSAEWOULDBLOCK: i32 = 10035;

    #[link(name = "ws2_32")]
    extern "system" {
        fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }

    let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    let n = unsafe { send(stream.as_raw_socket() as usize, data.as_ptr(), len, MSG_OOB) };
    if n < 0 {
        let code = unsafe { WSAGetLastError() };
        if code == WSAEWOULDBLOCK {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        } else {
            Err(std::io::Error::from_raw_os_error(code))
        }
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_synthetic_client_hello;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn combo_desync_rewrites_client_hello_into_valid_multi_tls_records() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let ch = build_synthetic_client_hello("discord.com", 512);
        let ch_expected = ch.clone();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            received
        });

        let mut remote = TcpStream::connect(upstream_addr).await.unwrap();
        remote.set_nodelay(true).unwrap();
        let public_ip: IpAddr = "162.159.135.232".parse().unwrap();
        ctx.write_initial_flight(&mut remote, &ch, Some("discord.com"), public_ip)
            .await
            .unwrap();
        drop(remote);

        let received = server_task.await.unwrap();
        let mut pos = 0usize;
        let mut record_count = 0usize;
        let mut reassembled = Vec::new();
        while pos < received.len() {
            assert_eq!(received[pos], 0x16);
            let rlen = u16::from_be_bytes([received[pos + 3], received[pos + 4]]) as usize;
            let body = &received[pos + 5..pos + 5 + rlen];
            assert!(!body.windows(11).any(|w| w == b"discord.com"));
            reassembled.extend_from_slice(body);
            pos += 5 + rlen;
            record_count += 1;
        }
        assert_eq!(record_count, 4);
        assert_eq!(reassembled, ch_expected[5..]);
    }

    #[tokio::test]
    async fn adaptive_auto_heal_recovers_when_strict_cdn_rejects_split_tls_record() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["strict-images\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch = build_synthetic_client_hello("cdn.strict-images.example", 256);
        let orig_rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);

        // Mock a strict image CDN that returns a fatal TLS Alert (0x15) if the first TLS record
        // was split shorter than the full ClientHello, and returns a valid ServerHello (0x16)
        // when it receives a single intact outer TLS record.
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let attempts_conn = Arc::clone(&attempts_srv);
                tokio::spawn(async move {
                    attempts_conn.fetch_add(1, Ordering::SeqCst);
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    let _ = sock.read_exact(&mut body).await;

                    if rec_len < orig_rec_len {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O',
                            ])
                            .await;
                    }

                    // Close the write half and drain pipelined input so that closing the
                    // mock socket does not reset the connection before the alert is read.
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let ch_send = ch.clone();

        let client_task = tokio::spawn(async move {
            let mut c = TcpStream::connect(proxy_addr).await.unwrap();
            c.write_all(&ch_send).await.unwrap();
            let mut reply = [0u8; 10];
            c.read_exact(&mut reply).await.unwrap();
            reply
        });

        let (accepted_client, _) = proxy_listener.accept().await.unwrap();
        let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
        ctx.relay_tunnel(
            accepted_client,
            initial_remote,
            Some("cdn.strict-images.example"),
            upstream_addr,
        )
        .await
        .unwrap();

        let reply = client_task.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O']
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("cdn.strict-images.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn escalates_to_deep_record_storm_and_promotes_isp_stage_on_dpi_block_injection() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["blocked[0-9]\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let hosts = [
            "host.blocked1.example",
            "host.blocked2.example",
            "host.blocked3.example",
            "host.blocked4.example",
            "host.blocked5.example",
        ];
        let expected_payload_len = build_synthetic_client_hello(hosts[0], 256).len() - 5;

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // Simulate a strict stateful ISP DPI box that:
        // - Injects a fake HTTP 302 block page if <= 4 TLS records arrive (Stage 1)
        // - Resets/closes connection if single-record (Stage 2)
        // - Allows connection through when >= 10 tiny lead TLS records arrive (Stage 5 DeepRecordStorm)
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut count = 0usize;
                    let mut total_payload = 0usize;
                    loop {
                        let mut hdr = [0u8; 5];
                        match tokio::time::timeout(
                            Duration::from_millis(250),
                            sock.read_exact(&mut hdr),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                                let mut body = vec![0u8; rlen];
                                if sock.read_exact(&mut body).await.is_err() {
                                    break;
                                }
                                count += 1;
                                total_payload += rlen;
                                if total_payload >= expected_payload_len {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }

                    if count == 4 {
                        // Fake ISP HTTP block-page injection on a TLS port
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                            )
                            .await;
                    } else if count == 1 {
                        // TCP RST / immediate EOF
                        drop(sock);
                    } else if count >= 10 {
                        // Valid TLS ServerHello passes through!
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'K', b'T', b'L', b'S',
                            ])
                            .await;
                    }
                });
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        for (idx, &host) in hosts.iter().enumerate() {
            let ch_send = build_synthetic_client_hello(host, 256);
            let client_task = tokio::spawn(async move {
                let mut c = TcpStream::connect(proxy_addr).await.unwrap();
                c.write_all(&ch_send).await.unwrap();
                let mut reply = [0u8; 10];
                c.read_exact(&mut reply).await.unwrap();
                reply
            });

            let (accepted_client, _) = proxy_listener.accept().await.unwrap();
            let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
            ctx.relay_tunnel(accepted_client, initial_remote, Some(host), upstream_addr)
                .await
                .unwrap();

            let reply = client_task.await.unwrap();
            assert_eq!(
                &reply,
                &[0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'K', b'T', b'L', b'S']
            );

            if idx + 1 < SLOW_PROMOTION_QUORUM {
                assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
                assert_eq!(
                    ctx.adaptive_cache.read().await.get(host).copied(),
                    Some(LearnedStrategy::DeepRecordStorm)
                );
            }
        }

        // After 5 distinct hard-blocked hosts, slow stage DeepRecordStorm is promoted globally
        // and redundant per-host overrides matching the new global stage are pruned.
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::DeepRecordStorm);
        assert_eq!(ctx.learned_host_count().await, 0);
    }

    #[tokio::test]
    async fn relay_stream_supports_generic_streams_and_records_telemetry() {
        let config = RuntimeConfig {
            system_proxy: false,
            patterns: vec!["stream\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let ch = build_synthetic_client_hello("api.stream.example", 256);

        let expected_payload_len = ch.len() - 5;
        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut total_payload = 0usize;
            while total_payload < expected_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                total_payload += rlen;
            }
            sock.write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O'])
                .await
                .unwrap();
            let _ = sock.shutdown().await;
        });

        let (mut app_side, tun_side) = tokio::io::duplex(8192);
        let ch_send = ch.clone();
        let app_task = tokio::spawn(async move {
            app_side.write_all(&ch_send).await.unwrap();
            let mut reply = [0u8; 10];
            app_side.read_exact(&mut reply).await.unwrap();
            reply
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(tun_side, remote, Some("api.stream.example"), upstream_addr)
            .await
            .unwrap();

        let reply = app_task.await.unwrap();
        server.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O']
        );

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 1);
        assert_eq!(snap.tls_handshakes, 1);
        assert_eq!(snap.learned_hosts, 0);
        assert!(snap.bytes_tx >= ch.len() as u64);
        assert!(snap.bytes_rx >= 10);
    }

    #[tokio::test]
    async fn send_with_oob_delivers_payload_and_strips_urgent_byte() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            received
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.set_nodelay(true).unwrap();
        send_with_oob(&mut client, b"").await.unwrap();
        send_with_oob(&mut client, b"PINGa").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        client.write_all(b"PONG").await.unwrap();
        drop(client);

        let received = server.await.unwrap();
        assert_eq!(received, b"PINGPONG");
    }

    struct TempCacheDir(PathBuf);

    impl TempCacheDir {
        fn new(label: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let id = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "vdpi-cache-test-{}-{}-{}",
                std::process::id(),
                label,
                id
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempCacheDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn test_engine_context() -> EngineContext {
        let config = RuntimeConfig {
            system_proxy: false,
            ..RuntimeConfig::default()
        };
        EngineContext::new(config).unwrap()
    }

    #[tokio::test]
    async fn persisted_cache_roundtrip_restores_hosts_stage_and_telemetry() {
        let tmp = TempCacheDir::new("roundtrip");
        let cache_file = tmp.file("nested/adaptive-cache.json");

        let ctx1 = test_engine_context();
        {
            let mut guard = ctx1.adaptive_cache.write().await;
            guard.insert("discord.com".to_string(), LearnedStrategy::OobSniDesync);
            guard.insert("video.example".to_string(), LearnedStrategy::FineFragment);
            // Redundant entry matching restored preferred_isp_stage should be pruned on load.
            guard.insert(
                "media.example".to_string(),
                LearnedStrategy::DeepRecordStorm,
            );
            ctx1.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }
        ctx1.preferred_isp_stage
            .store(LearnedStrategy::DeepRecordStorm as u8, Ordering::Relaxed);
        ctx1.save_persisted_cache(&cache_file).await.unwrap();
        assert!(cache_file.exists());

        let ctx2 = test_engine_context();
        ctx2.attach_cache_file(cache_file.clone()).await;
        assert!(ctx2.has_cache_file().await);
        assert_eq!(ctx2.learned_host_count().await, 2);
        assert_eq!(ctx2.telemetry_snapshot().learned_hosts, 2);
        assert_eq!(ctx2.preferred_stage(), LearnedStrategy::DeepRecordStorm);
        assert_eq!(
            ctx2.adaptive_cache.read().await.get("discord.com").copied(),
            Some(LearnedStrategy::OobSniDesync)
        );
        assert_eq!(
            ctx2.adaptive_cache
                .read()
                .await
                .get("video.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );
        assert_eq!(
            ctx2.adaptive_cache
                .read()
                .await
                .get("media.example")
                .copied(),
            None
        );
    }

    #[tokio::test]
    async fn persisted_cache_prunes_expired_entries_and_ignores_direct_passthrough_global_stage() {
        let tmp = TempCacheDir::new("expired");
        let cache_file = tmp.file("adaptive-cache.json");
        let now = unix_now_secs();

        let payload = PersistedAdaptiveCache {
            version: PERSISTED_CACHE_VERSION,
            global_isp_stage: LearnedStrategy::DirectPassthrough as u8,
            global_isp_stage_updated_at: now,
            entries: vec![
                PersistedHostEntry {
                    host: "Fresh.Example".to_string(),
                    stage: LearnedStrategy::FineFragment as u8,
                    updated_at: now.saturating_sub(OOB_CACHE_TTL_SECS + 60),
                },
                PersistedHostEntry {
                    host: "stale-oob.example".to_string(),
                    stage: LearnedStrategy::OobSniDesync as u8,
                    updated_at: now.saturating_sub(OOB_CACHE_TTL_SECS + 60),
                },
                PersistedHostEntry {
                    host: "stale.example".to_string(),
                    stage: LearnedStrategy::FineFragment as u8,
                    updated_at: now.saturating_sub(PERSISTED_CACHE_TTL_SECS + 60),
                },
                PersistedHostEntry {
                    host: "   ".to_string(),
                    stage: LearnedStrategy::Primary as u8,
                    updated_at: now,
                },
                PersistedHostEntry {
                    host: "a".repeat(300),
                    stage: LearnedStrategy::Primary as u8,
                    updated_at: now,
                },
            ],
        };
        std::fs::write(&cache_file, serde_json::to_vec(&payload).unwrap()).unwrap();

        let ctx = test_engine_context();
        let loaded = ctx.load_persisted_cache(&cache_file).await;
        assert_eq!(loaded, 1);
        assert_eq!(ctx.learned_host_count().await, 1);
        assert_eq!(ctx.telemetry_snapshot().learned_hosts, 1);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("fresh.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn persisted_cache_caps_entries_at_max_persisted_hosts() {
        let tmp = TempCacheDir::new("cap");
        let save_file = tmp.file("save-cap.json");
        let load_file = tmp.file("load-cap.json");
        let now = unix_now_secs();

        let ctx_save = test_engine_context();
        {
            let mut guard = ctx_save.adaptive_cache.write().await;
            for idx in 0..300usize {
                guard.insert(
                    format!("save-host-{idx}.example"),
                    LearnedStrategy::OobSniDesync,
                );
            }
        }
        ctx_save.save_persisted_cache(&save_file).await.unwrap();
        let saved: PersistedAdaptiveCache =
            serde_json::from_slice(&std::fs::read(&save_file).unwrap()).unwrap();
        assert_eq!(saved.entries.len(), MAX_PERSISTED_HOSTS);

        let entries: Vec<PersistedHostEntry> = (0..300u64)
            .map(|idx| PersistedHostEntry {
                host: format!("load-host-{idx}.example"),
                stage: LearnedStrategy::MultiRecordOob as u8,
                updated_at: now.saturating_sub(idx),
            })
            .collect();
        let raw = PersistedAdaptiveCache {
            version: PERSISTED_CACHE_VERSION,
            global_isp_stage: LearnedStrategy::OobSniDesync as u8,
            global_isp_stage_updated_at: now,
            entries,
        };
        std::fs::write(&load_file, serde_json::to_vec(&raw).unwrap()).unwrap();

        let ctx_load = test_engine_context();
        let loaded = ctx_load.load_persisted_cache(&load_file).await;
        assert_eq!(loaded, MAX_PERSISTED_HOSTS);
        assert_eq!(ctx_load.learned_host_count().await, MAX_PERSISTED_HOSTS);
        assert_eq!(
            ctx_load.telemetry_snapshot().learned_hosts,
            MAX_PERSISTED_HOSTS
        );
        let guard = ctx_load.adaptive_cache.read().await;
        assert!(guard.contains_key("load-host-0.example"));
        assert!(!guard.contains_key("load-host-299.example"));
    }

    #[tokio::test]
    async fn persisted_cache_returns_zero_on_missing_corrupt_or_bad_version_file() {
        let tmp = TempCacheDir::new("corrupt");
        let missing = tmp.file("does-not-exist.json");
        let corrupt = tmp.file("corrupt.json");
        let bad_ver = tmp.file("bad-version.json");

        std::fs::write(&corrupt, b"{not-valid-json!!!").unwrap();
        std::fs::write(
            &bad_ver,
            br#"{"version":99,"global_isp_stage":2,"entries":[{"host":"x.example","stage":1,"updated_at":9999999999}]}"#,
        )
        .unwrap();

        let ctx = test_engine_context();
        assert_eq!(ctx.load_persisted_cache(&missing).await, 0);
        assert_eq!(ctx.load_persisted_cache(&corrupt).await, 0);
        assert_eq!(ctx.load_persisted_cache(&bad_ver).await, 0);
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(ctx.telemetry_snapshot().learned_hosts, 0);
    }

    #[tokio::test]
    async fn clear_adaptive_cache_resets_stage_and_deletes_persisted_file() {
        let tmp = TempCacheDir::new("clear");
        let cache_file = tmp.file("adaptive-cache.json");

        let ctx = test_engine_context();
        ctx.attach_cache_file(cache_file.clone()).await;
        {
            let mut guard = ctx.adaptive_cache.write().await;
            guard.insert("blocked.example".to_string(), LearnedStrategy::SlowSniSlice);
            ctx.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }
        ctx.preferred_isp_stage
            .store(LearnedStrategy::SlowSniSlice as u8, Ordering::Relaxed);
        ctx.save_persisted_cache(&cache_file).await.unwrap();
        assert!(cache_file.exists());

        let stale_tmp = tmp.file("adaptive-cache.json.1234.0.tmp");
        let stale_bak = tmp.file("adaptive-cache.json.1234.0.bak");
        let unrelated = tmp.file("other-file.tmp");
        std::fs::write(&stale_tmp, b"tmp").unwrap();
        std::fs::write(&stale_bak, b"bak").unwrap();
        std::fs::write(&unrelated, b"keep").unwrap();

        ctx.clear_adaptive_cache().await;
        assert!(!cache_file.exists());
        assert!(!stale_tmp.exists());
        assert!(!stale_bak.exists());
        assert!(unrelated.exists());
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(ctx.telemetry_snapshot().learned_hosts, 0);
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[test]
    fn live_adaptive_cache_rejects_invalid_hosts_and_evicts_oldest_at_cap() {
        let mut cache = HashMap::new();
        let mut timestamps = HashMap::new();

        assert!(!upsert_adaptive_entry(
            &mut cache,
            &mut timestamps,
            String::new(),
            LearnedStrategy::OobSniDesync,
            100,
        ));
        assert!(!upsert_adaptive_entry(
            &mut cache,
            &mut timestamps,
            "bad host.example".to_string(),
            LearnedStrategy::OobSniDesync,
            100,
        ));
        assert!(!upsert_adaptive_entry(
            &mut cache,
            &mut timestamps,
            "x".repeat(MAX_HOSTNAME_LEN + 1),
            LearnedStrategy::OobSniDesync,
            100,
        ));
        assert!(cache.is_empty());

        for idx in 0..MAX_PERSISTED_HOSTS {
            let ts = if idx == 17 { 50 } else { 100 + idx as u64 };
            assert!(upsert_adaptive_entry(
                &mut cache,
                &mut timestamps,
                format!("host-{idx}.example"),
                LearnedStrategy::OobSniDesync,
                ts,
            ));
        }
        assert_eq!(cache.len(), MAX_PERSISTED_HOSTS);

        assert!(upsert_adaptive_entry(
            &mut cache,
            &mut timestamps,
            "newest.example".to_string(),
            LearnedStrategy::MultiRecordOob,
            999,
        ));
        assert_eq!(cache.len(), MAX_PERSISTED_HOSTS);
        assert!(!cache.contains_key("host-17.example"));
        assert!(!timestamps.contains_key("host-17.example"));
        assert_eq!(
            cache.get("newest.example").copied(),
            Some(LearnedStrategy::MultiRecordOob)
        );
    }

    #[tokio::test]
    async fn maybe_persist_cache_schedules_single_trailing_flush_inside_debounce_window() {
        let tmp = TempCacheDir::new("trailing");
        let cache_file = tmp.file("adaptive-cache.json");

        let ctx = test_engine_context();
        ctx.attach_cache_file(cache_file).await;
        ctx.last_persist_epoch
            .store(unix_now_secs().max(1), Ordering::Relaxed);
        assert!(!ctx.persist_scheduled.load(Ordering::Relaxed));

        ctx.maybe_persist_cache();
        assert!(ctx.persist_scheduled.load(Ordering::Relaxed));

        // Second call within the same debounce window stays coalesced.
        ctx.maybe_persist_cache();
        assert!(ctx.persist_scheduled.load(Ordering::Relaxed));
    }

    #[test]
    fn atomic_write_file_overwrites_safely_without_leaving_temp_files() {
        let tmp = TempCacheDir::new("atomic");
        let cache_file = tmp.file("adaptive-cache.json");

        atomic_write_file(&cache_file, br#"{"version":1,"v":"first"}"#).unwrap();
        assert_eq!(
            std::fs::read(&cache_file).unwrap(),
            br#"{"version":1,"v":"first"}"#
        );

        atomic_write_file(&cache_file, br#"{"version":1,"v":"second"}"#).unwrap();
        assert_eq!(
            std::fs::read(&cache_file).unwrap(),
            br#"{"version":1,"v":"second"}"#
        );

        let names: Vec<String> = std::fs::read_dir(&tmp.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["adaptive-cache.json"]);
    }

    #[tokio::test]
    async fn exception_only_adaptive_cache_skips_default_and_removes_stale_overrides() {
        let ctx = test_engine_context();

        // Default stage (Primary == preferred_stage) must never pollute adaptive_cache.
        ctx.record_host_stage(Some("normal.example"), LearnedStrategy::Primary, false)
            .await;
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(ctx.telemetry_snapshot().learned_hosts, 0);

        // Non-default stage is recorded as an exception.
        ctx.record_host_stage(
            Some("special.example"),
            LearnedStrategy::OobSniDesync,
            false,
        )
        .await;
        assert_eq!(ctx.learned_host_count().await, 1);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("special.example")
                .copied(),
            Some(LearnedStrategy::OobSniDesync)
        );

        // Once the host works on the preferred stage again, its stale override is evicted.
        ctx.record_host_stage(Some("special.example"), LearnedStrategy::Primary, false)
            .await;
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(ctx.telemetry_snapshot().learned_hosts, 0);
    }

    #[tokio::test]
    async fn quorum_promotion_requires_distinct_hard_block_hosts_for_fast_and_slow_stages() {
        let ctx = test_engine_context();

        // Repeated hard-block failures on the SAME host never satisfy quorum.
        for _ in 0..5 {
            ctx.record_host_stage(Some("repeat.example"), LearnedStrategy::OobSniDesync, true)
                .await;
        }
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);

        // Non-hard-block failures (timeouts, TLS alerts, alternate IP rotation) never promote.
        for idx in 0..5 {
            ctx.record_host_stage(
                Some(&format!("timeout-{idx}.example")),
                LearnedStrategy::OobSniDesync,
                false,
            )
            .await;
        }
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);

        // Keep an unrelated override to ensure promotion only prunes entries matching the promoted stage.
        ctx.record_host_stage(
            Some("custom-fine.example"),
            LearnedStrategy::FineFragment,
            false,
        )
        .await;

        // Fast stage (OobSniDesync) promotes on the 3rd distinct hard-blocked host
        // ("repeat.example" already counted as host #1).
        ctx.record_host_stage(Some("hard-2.example"), LearnedStrategy::OobSniDesync, true)
            .await;
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);

        ctx.record_host_stage(Some("hard-3.example"), LearnedStrategy::OobSniDesync, true)
            .await;
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::OobSniDesync);
        // Redundant OobSniDesync exceptions are pruned; custom FineFragment exception remains.
        assert_eq!(ctx.learned_host_count().await, 1);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("custom-fine.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );

        // FineFragment must NEVER promote global_isp_stage from Primary (even across 5+ hosts).
        let fine_ctx = test_engine_context();
        for idx in 1..=SLOW_PROMOTION_QUORUM {
            fine_ctx
                .record_host_stage(
                    Some(&format!("fine-{idx}.example")),
                    LearnedStrategy::FineFragment,
                    true,
                )
                .await;
            assert_eq!(fine_ctx.preferred_stage(), LearnedStrategy::Primary);
        }
        assert_eq!(fine_ctx.learned_host_count().await, SLOW_PROMOTION_QUORUM);

        // Slow stages (DeepRecordStorm / SlowSniSlice) require 5 distinct hard-blocked hosts.
        let slow_ctx = test_engine_context();
        for idx in 1..SLOW_PROMOTION_QUORUM {
            slow_ctx
                .record_host_stage(
                    Some(&format!("slow-{idx}.example")),
                    LearnedStrategy::SlowSniSlice,
                    true,
                )
                .await;
            assert_eq!(slow_ctx.preferred_stage(), LearnedStrategy::Primary);
        }
        slow_ctx
            .record_host_stage(Some("slow-5.example"), LearnedStrategy::SlowSniSlice, true)
            .await;
        assert_eq!(slow_ctx.preferred_stage(), LearnedStrategy::SlowSniSlice);
        assert_eq!(slow_ctx.learned_host_count().await, 0);
    }

    #[tokio::test]
    async fn persisted_cache_expires_global_isp_stage_after_24h_and_resets_v1_caches() {
        assert_eq!(PERSISTED_CACHE_VERSION, 2);
        let tmp = TempCacheDir::new("global-ttl");
        let v1_stale = tmp.file("v1-stale.json");
        let v2_no_ts = tmp.file("v2-no-ts.json");
        let expired_file = tmp.file("expired-global.json");
        let fresh_file = tmp.file("fresh-global.json");
        let now = unix_now_secs();

        // Stale v1 cache files (e.g. poisoned v0.6.2 adaptive-cache.json) auto-reset cleanly on load.
        let v1_json = format!(
            r#"{{"version":1,"global_isp_stage":3,"global_isp_stage_updated_at":{now},"entries":[{{"host":"*.microsoft.com","stage":1,"updated_at":{now}}}]}}"#
        );
        std::fs::write(&v1_stale, v1_json).unwrap();
        let ctx_v1 = test_engine_context();
        assert_eq!(ctx_v1.load_persisted_cache(&v1_stale).await, 0);
        assert_eq!(ctx_v1.preferred_stage(), LearnedStrategy::Primary);
        assert_eq!(ctx_v1.learned_host_count().await, 0);

        // Current-version JSON omitting `global_isp_stage_updated_at` deserializes cleanly
        // and safely expires the untimestamped global_isp_stage back to Primary.
        let v2_no_ts_json = format!(
            r#"{{"version":{PERSISTED_CACHE_VERSION},"global_isp_stage":4,"entries":[{{"host":"legacy.example","stage":2,"updated_at":{now}}}]}}"#
        );
        std::fs::write(&v2_no_ts, v2_no_ts_json).unwrap();

        let ctx_legacy = test_engine_context();
        assert_eq!(ctx_legacy.load_persisted_cache(&v2_no_ts).await, 1);
        assert_eq!(ctx_legacy.preferred_stage(), LearnedStrategy::Primary);

        // Expired (> 24h) global_isp_stage resets back to Primary on load.
        let expired_payload = PersistedAdaptiveCache {
            version: PERSISTED_CACHE_VERSION,
            global_isp_stage: LearnedStrategy::OobSniDesync as u8,
            global_isp_stage_updated_at: now.saturating_sub(GLOBAL_ISP_STAGE_TTL_SECS + 60),
            entries: Vec::new(),
        };
        std::fs::write(&expired_file, serde_json::to_vec(&expired_payload).unwrap()).unwrap();
        let ctx_expired = test_engine_context();
        ctx_expired
            .preferred_isp_stage
            .store(LearnedStrategy::OobSniDesync as u8, Ordering::Relaxed);
        ctx_expired.load_persisted_cache(&expired_file).await;
        assert_eq!(ctx_expired.preferred_stage(), LearnedStrategy::Primary);

        // Fresh (< 24h) global_isp_stage restores normally.
        let fresh_payload = PersistedAdaptiveCache {
            version: PERSISTED_CACHE_VERSION,
            global_isp_stage: LearnedStrategy::FineFragment as u8,
            global_isp_stage_updated_at: now.saturating_sub(60),
            entries: Vec::new(),
        };
        std::fs::write(&fresh_file, serde_json::to_vec(&fresh_payload).unwrap()).unwrap();
        let ctx_fresh = test_engine_context();
        ctx_fresh.load_persisted_cache(&fresh_file).await;
        assert_eq!(ctx_fresh.preferred_stage(), LearnedStrategy::FineFragment);
    }

    #[tokio::test]
    async fn telemetry_helpers_update_udp_quic_and_dns_snapshot_fields() {
        let ctx = test_engine_context();
        ctx.set_udp_flows_active(7);
        ctx.inc_quic_blocked();
        ctx.inc_quic_blocked();
        ctx.add_udp_bytes(120, 340);

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.udp_flows_active, 7);
        assert_eq!(snap.quic_blocked, 2);
        assert_eq!(snap.bytes_tx, 120);
        assert_eq!(snap.bytes_rx, 340);
        assert_eq!(snap.dns_queries, ctx.dns.query_count());
    }

    #[tokio::test]
    async fn bind_outbound_udp_invokes_binder_and_binds_socket() {
        #[derive(Debug, Default)]
        struct CountingBinder {
            calls: AtomicUsize,
        }

        impl OutboundBinder for CountingBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
        }

        let binder = Arc::new(CountingBinder::default());
        let binder_trait: Arc<dyn OutboundBinder> = binder.clone();
        let config = RuntimeConfig {
            system_proxy: false,
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new_with_binder(config, Some(binder_trait)).unwrap();
        let sock = ctx.bind_outbound_udp(true, 65_536).unwrap();
        let local = sock.local_addr().unwrap();
        assert!(local.is_ipv4());
        assert_ne!(local.port(), 0);
        assert_eq!(binder.calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn intermediate_stage_tls_alert_does_not_block_global_stage_promotion() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["superonline-[a-z]\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let hosts = [
            "www.superonline-a.example",
            "www.superonline-b.example",
            "www.superonline-c.example",
        ];

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempt_counter = Arc::new(AtomicUsize::new(0));
        let attempt_srv = Arc::clone(&attempt_counter);

        // Simulate Superonline/middlebox behavior per host with clean non-OOB stage order:
        // - Attempt 0 (Primary): hard-blocked via fake HTTP 302 block page
        // - Attempt 1 (FineFragment): succeeds with valid TLS ServerHello (0x16 0x03)
        // Wait — to test intermediate TLS Alert 0x15 before a fast-quorum stage, verify
        // Attempt 0 (Primary) -> HTTP 302, Attempt 1 (FineFragment) -> TLS Alert,
        // Attempt 2 (DeepRecordStorm) -> TLS Alert, Attempt 3 (SlowSniSlice) -> TLS Alert,
        // Attempt 4 (OobSniDesync, fast quorum = 3) -> ServerHello!
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let step = attempt_srv.fetch_add(1, Ordering::SeqCst) % 5;
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    let _ = sock.read_exact(&mut body).await;

                    match step {
                        0 => {
                            let _ = sock
                                .write_all(
                                    b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                                )
                                .await;
                        }
                        1..=3 => {
                            let _ = sock
                                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32])
                                .await;
                        }
                        _ => {
                            let _ = sock
                                .write_all(&[
                                    0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O',
                                ])
                                .await;
                        }
                    }

                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        for (idx, &host) in hosts.iter().enumerate() {
            let ch_send = build_synthetic_client_hello(host, 256);
            let client_task = tokio::spawn(async move {
                let mut c = TcpStream::connect(proxy_addr).await.unwrap();
                c.write_all(&ch_send).await.unwrap();
                let mut reply = [0u8; 10];
                c.read_exact(&mut reply).await.unwrap();
                reply
            });

            let (accepted_client, _) = proxy_listener.accept().await.unwrap();
            let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
            ctx.relay_tunnel(accepted_client, initial_remote, Some(host), upstream_addr)
                .await
                .unwrap();

            let reply = client_task.await.unwrap();
            assert_eq!(
                &reply,
                &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O']
            );

            if idx + 1 < FAST_PROMOTION_QUORUM {
                assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
                assert_eq!(
                    ctx.adaptive_cache.read().await.get(host).copied(),
                    Some(LearnedStrategy::OobSniDesync)
                );
            }
        }

        // Intermediate TLS Alerts (0x15) on non-Primary stages must not block global promotion.
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::OobSniDesync);
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(attempt_counter.load(Ordering::SeqCst), 15);
    }

    #[test]
    fn preferred_stage_expires_in_memory_after_24h_ttl() {
        let ctx = test_engine_context();
        let now = unix_now_secs();

        // Fresh promotion (< 24h) remains active.
        ctx.preferred_isp_stage_updated_at
            .store(now.saturating_sub(60), Ordering::Release);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::FineFragment as u8, Ordering::Release);
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::FineFragment);
        assert_eq!(
            ctx.build_stage_order(None)[0],
            LearnedStrategy::FineFragment
        );

        // Expired promotion (> 24h) atomically resets back to Primary in memory.
        ctx.preferred_isp_stage_updated_at.store(
            now.saturating_sub(GLOBAL_ISP_STAGE_TTL_SECS + 60),
            Ordering::Release,
        );
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
        assert_eq!(
            ctx.preferred_isp_stage.load(Ordering::Acquire),
            LearnedStrategy::Primary as u8
        );
        assert_eq!(
            ctx.preferred_isp_stage_updated_at.load(Ordering::Acquire),
            0
        );
        assert_eq!(ctx.build_stage_order(None)[0], LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn primary_demotion_quorum_restores_primary_from_promoted_stage() {
        let ctx = test_engine_context();
        let now = unix_now_secs();

        // Start from a promoted non-Primary ISP stage (e.g. after switching networks).
        ctx.preferred_isp_stage_updated_at
            .store(now, Ordering::Release);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::DeepRecordStorm as u8, Ordering::Release);
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::DeepRecordStorm);

        // First 2 distinct hosts falling back to Primary do not yet meet FAST_PROMOTION_QUORUM (3).
        for idx in 1..FAST_PROMOTION_QUORUM {
            ctx.record_host_stage(
                Some(&format!("demote-{idx}.example")),
                LearnedStrategy::Primary,
                true,
            )
            .await;
            assert_eq!(ctx.preferred_stage(), LearnedStrategy::DeepRecordStorm);
            assert_eq!(
                ctx.adaptive_cache
                    .read()
                    .await
                    .get(&format!("demote-{idx}.example"))
                    .copied(),
                Some(LearnedStrategy::Primary)
            );
        }

        // 3rd distinct host satisfies FAST_PROMOTION_QUORUM and demotes global stage back to Primary,
        // clearing redundant Primary overrides and resetting the promotion timestamp.
        ctx.record_host_stage(Some("demote-3.example"), LearnedStrategy::Primary, true)
            .await;
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
        assert_eq!(
            ctx.preferred_isp_stage_updated_at.load(Ordering::Acquire),
            0
        );
        assert_eq!(ctx.learned_host_count().await, 0);
    }

    #[tokio::test]
    async fn coalesced_tls13_zero_rtt_is_single_attempt_while_ccs_only_auto_heals() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["zero-rtt\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch = build_synthetic_client_hello("api.zero-rtt.example", 256);
        let orig_rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;

        // Part A: Coalesced TLS 1.3 ChangeCipherSpec + 0-RTT ApplicationData (`0x17`) must be
        // sent strictly single-attempt (never replayed across adaptive retry stages).
        let trailing_0rtt: Vec<u8> = vec![
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, // CCS
            0x17, 0x03, 0x03, 0x00, 0x08, b'0', b'R', b'T', b'T', b'D', b'A', b'T', b'A',
        ];
        assert!(trailing_contains_tls_app_data(&trailing_0rtt));
        let mut coalesced_0rtt = ch.clone();
        coalesced_0rtt.extend_from_slice(&trailing_0rtt);

        let upstream_0rtt = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_0rtt_addr = upstream_0rtt.local_addr().unwrap();
        let attempts_0rtt = Arc::new(AtomicUsize::new(0));
        let attempts_0rtt_srv = Arc::clone(&attempts_0rtt);
        let trailing_0rtt_exp = trailing_0rtt.clone();

        let srv_0rtt = tokio::spawn(async move {
            let (mut sock, _) = upstream_0rtt.accept().await.unwrap();
            attempts_0rtt_srv.fetch_add(1, Ordering::SeqCst);
            let mut got_ch = 0usize;
            while got_ch < orig_rec_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                got_ch += rlen;
            }
            let mut got_trailing = vec![0u8; trailing_0rtt_exp.len()];
            sock.read_exact(&mut got_trailing).await.unwrap();
            assert_eq!(got_trailing, trailing_0rtt_exp);
            // Reply with a TLS Alert; because 0-RTT is single-attempt, engine must not retry.
            let _ = sock
                .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                .await;
            let _ = sock.shutdown().await;
        });

        let (_app_0rtt, mut tun_0rtt) = tokio::io::duplex(8192);
        let initial_0rtt = TcpStream::connect(upstream_0rtt_addr).await.unwrap();
        let mut established_0rtt = ctx
            .establish_initial_flight(
                &mut tun_0rtt,
                initial_0rtt,
                &coalesced_0rtt,
                Some("api.zero-rtt.example"),
                upstream_0rtt_addr,
            )
            .await
            .unwrap();
        srv_0rtt.await.unwrap();
        let mut alert_reply = [0u8; 7];
        established_0rtt.read_exact(&mut alert_reply).await.unwrap();
        assert_eq!(alert_reply[0], 0x15);
        assert_eq!(attempts_0rtt.load(Ordering::SeqCst), 1);
        assert_eq!(ctx.learned_host_count().await, 0);

        // Part B: Coalesced TLS 1.3 ChangeCipherSpec (`0x14`) WITHOUT `0x17` ApplicationData
        // remains safe to auto-heal across retries while preserving trailing bytes intact.
        let trailing_ccs: Vec<u8> = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(!trailing_contains_tls_app_data(&trailing_ccs));
        let mut coalesced_ccs = ch.clone();
        coalesced_ccs.extend_from_slice(&trailing_ccs);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);
        let trailing_expected = trailing_ccs.clone();
        let trailing_ok = Arc::new(AtomicBool::new(false));
        let trailing_ok_srv = Arc::clone(&trailing_ok);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let attempts_conn = Arc::clone(&attempts_srv);
                let trailing_exp = trailing_expected.clone();
                let trailing_flag = Arc::clone(&trailing_ok_srv);
                tokio::spawn(async move {
                    attempts_conn.fetch_add(1, Ordering::SeqCst);
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    if sock.read_exact(&mut body).await.is_err() {
                        return;
                    }

                    if rec_len < orig_rec_len {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        let mut got_trailing = vec![0u8; trailing_exp.len()];
                        if sock.read_exact(&mut got_trailing).await.is_ok()
                            && got_trailing == trailing_exp
                        {
                            trailing_flag.store(true, Ordering::SeqCst);
                            let _ = sock
                                .write_all(&[
                                    0x16, 0x03, 0x03, 0x00, 0x05, b'0', b'R', b'T', b'T', b'!',
                                ])
                                .await;
                        }
                    }

                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
        let reader_task = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app_side.read_exact(&mut reply).await.unwrap();
            reply
        });

        let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
        let _established = ctx
            .establish_initial_flight(
                &mut tun_side,
                initial_remote,
                &coalesced_ccs,
                Some("api.zero-rtt.example"),
                upstream_addr,
            )
            .await
            .unwrap();

        let reply = reader_task.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'0', b'R', b'T', b'T', b'!']
        );
        assert!(trailing_ok.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("api.zero-rtt.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );
    }

    #[test]
    fn hrr_detection_trailing_record_completeness_and_parent_domain_hints() {
        let mut hrr = vec![
            0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
        ];
        hrr.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);
        assert!(is_tls_hello_retry_request(&hrr));
        let mut normal_sh = hrr.clone();
        normal_sh[11] ^= 0xFF;
        assert!(!is_tls_hello_retry_request(&normal_sh));

        // Complete CCS + 8-byte 0-RTT record vs truncated 0-RTT record
        let complete = [
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x04, 1, 2, 3, 4,
        ];
        assert!(are_trailing_tls_records_complete(&complete));
        assert!(!are_trailing_tls_records_complete(
            &complete[..complete.len() - 1]
        ));

        assert_eq!(
            parent_domain_cache_key("tr.rbxcdn.com").as_deref(),
            Some("*.rbxcdn.com")
        );
        assert_eq!(
            parent_domain_cache_key("a.b.co.uk").as_deref(),
            Some("*.b.co.uk")
        );
        assert_eq!(parent_domain_cache_key("roblox.com"), None);
        assert_eq!(parent_domain_cache_key("1.1.1.1"), None);
        // Clean non-OOB strategies always precede MSG_OOB stages
        let fine_pos = ALL_STAGES
            .iter()
            .position(|&s| s == LearnedStrategy::FineFragment)
            .unwrap();
        let oob_pos = ALL_STAGES
            .iter()
            .position(|&s| s == LearnedStrategy::OobSniDesync)
            .unwrap();
        assert!(fine_pos < oob_pos);
    }

    #[tokio::test]
    async fn direct_passthrough_fallback_still_runs_when_handshake_deadline_expires() {
        let now = Instant::now();
        let expired = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
        assert_eq!(
            compute_stage_deadline(now, expired, LearnedStrategy::SlowSniSlice),
            expired
        );
        assert!(
            compute_stage_deadline(now, expired, LearnedStrategy::DirectPassthrough)
                >= now + DIRECT_PASSTHROUGH_FALLBACK_BUDGET
        );
        let generous = now + Duration::from_secs(10);
        assert_eq!(
            compute_stage_deadline(now, generous, LearnedStrategy::DirectPassthrough),
            generous
        );

        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["strict-passthrough\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();
        let ch = build_synthetic_client_hello("ookla.strict-passthrough.example", 256);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);

        // Attempt 1 (Stage 1 Primary) stalls past the short 120ms handshake budget so stages 2..6
        // are skipped, and Attempt 2 must be the guaranteed bounded DirectPassthrough fallback.
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let step = attempts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    if step == 0 {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        drop(sock);
                    } else {
                        let mut hdr = [0u8; 5];
                        if sock.read_exact(&mut hdr).await.is_ok() {
                            let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                            let mut body = vec![0u8; rec_len];
                            if sock.read_exact(&mut body).await.is_ok() {
                                let _ = sock
                                    .write_all(&[
                                        0x16, 0x03, 0x03, 0x00, 0x05, b'P', b'A', b'S', b'S', b'7',
                                    ])
                                    .await;
                            }
                        }
                        let _ = sock.shutdown().await;
                    }
                });
            }
        });

        let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
        let reader_task = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app_side.read_exact(&mut reply).await.unwrap();
            reply
        });

        let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
        let _established = ctx
            .establish_initial_flight_with_deadline(
                &mut tun_side,
                initial_remote,
                &ch,
                Some("ookla.strict-passthrough.example"),
                upstream_addr,
                Duration::from_millis(120),
            )
            .await
            .unwrap();

        let reply = reader_task.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'P', b'A', b'S', b'S', b'7']
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("ookla.strict-passthrough.example")
                .copied(),
            Some(LearnedStrategy::DirectPassthrough)
        );
    }

    #[test]
    fn relay_buf_size_matches_platform_budget() {
        #[cfg(target_os = "ios")]
        assert_eq!(RELAY_BUF_SIZE, 16 * 1024);
        #[cfg(target_os = "android")]
        assert_eq!(RELAY_BUF_SIZE, 64 * 1024);
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        assert_eq!(RELAY_BUF_SIZE, 128 * 1024);
        assert_eq!(TELEMETRY_BATCH_BYTES, RELAY_BUF_SIZE as u64);
        assert_eq!(MAX_HANDSHAKE_DEADLINE, Duration::from_secs(12));
    }

    #[tokio::test]
    async fn relay_stream_reassembles_large_post_quantum_client_hello_across_multiple_reads() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["pq-test\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        // ~1,800+ byte ClientHello modeling Chrome / WinHTTP X25519MLKEM768 Post-Quantum flight.
        let ch = build_synthetic_client_hello("chrome.pq-test.example", 1800);
        assert!(
            ch.len() > 1700,
            "PQ ClientHello should exceed 1460-byte MSS"
        );
        let expected_payload = ch[5..].to_vec();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut reassembled = Vec::with_capacity(expected_payload.len());
            let mut record_count = 0usize;
            while reassembled.len() < expected_payload.len() {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x16);
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                assert!(!body.windows(22).any(|w| w == b"chrome.pq-test.example"));
                reassembled.extend_from_slice(&body);
                record_count += 1;
            }
            assert_eq!(reassembled, expected_payload);
            assert!(record_count >= 2);

            sock.write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, b'P', b'Q', b'_', b'O', b'K'])
                .await
                .unwrap();
            // Steady-state bulk download (> RELAY_BUF_SIZE) after handshake
            let bulk = vec![0x5Au8; 320 * 1024];
            sock.write_all(&bulk).await.unwrap();
            let _ = sock.shutdown().await;
            bulk.len()
        });

        let (mut app_side, tun_side) = tokio::io::duplex(64 * 1024);
        let ch_send = ch.clone();
        let app_task = tokio::spawn(async move {
            // Split across 2 TCP reads at standard 1460-byte Ethernet/IPv4 MSS boundary.
            app_side.write_all(&ch_send[..1460]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            app_side.write_all(&ch_send[1460..]).await.unwrap();

            let mut sh = [0u8; 10];
            app_side.read_exact(&mut sh).await.unwrap();
            let mut rest = Vec::new();
            app_side.read_to_end(&mut rest).await.unwrap();
            (sh, rest)
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(
            tun_side,
            remote,
            Some("chrome.pq-test.example"),
            upstream_addr,
        )
        .await
        .unwrap();

        let bulk_len = server.await.unwrap();
        let (sh, rest) = app_task.await.unwrap();
        assert_eq!(
            &sh,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'P', b'Q', b'_', b'O', b'K']
        );
        assert_eq!(rest.len(), bulk_len);
        assert!(rest.iter().all(|&b| b == 0x5A));

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.tls_handshakes, 1);
        assert_eq!(snap.bytes_tx, ch.len() as u64);
        assert_eq!(snap.bytes_rx, (10 + bulk_len) as u64);
    }

    #[tokio::test]
    async fn counting_stream_batches_telemetry_and_tracks_activity_without_clock_calls() {
        let telemetry = EngineTelemetry::default();
        let active = AtomicBool::new(false);

        let (mut peer, local) = tokio::io::duplex(64 * 1024);
        let mut counted = CountingStream::new(local, &telemetry, &active);

        // Small write (< TELEMETRY_BATCH_BYTES) stays batched across poll_flush until
        // threshold/shutdown/drop, while still flushing the inner stream and setting active.
        let small = b"ping-frame";
        counted.write_all(small).await.unwrap();
        assert!(active.load(Ordering::Relaxed));
        assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 0);
        counted.flush().await.unwrap();
        assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 0);

        let mut got = [0u8; 10];
        peer.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, small);

        // Large read (> TELEMETRY_BATCH_BYTES) flushes live during streaming and exact on EOF.
        let total_rx = RELAY_BUF_SIZE + 12_345;
        let writer = tokio::spawn(async move {
            let chunk = vec![0xABu8; 32 * 1024];
            let mut remaining = total_rx;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                peer.write_all(&chunk[..n]).await.unwrap();
                remaining -= n;
            }
            peer.shutdown().await.unwrap();
            peer
        });

        active.store(false, Ordering::Relaxed);
        let mut drained = Vec::with_capacity(total_rx);
        counted.read_to_end(&mut drained).await.unwrap();
        let _peer = writer.await.unwrap();
        assert_eq!(drained.len(), total_rx);
        assert!(active.load(Ordering::Relaxed));
        assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), total_rx as u64);

        // Residual TX bytes below TELEMETRY_BATCH_BYTES flush on shutdown.
        counted.shutdown().await.unwrap();
        assert_eq!(
            telemetry.bytes_tx.load(Ordering::Relaxed),
            small.len() as u64
        );

        // Residual TX bytes also flush on Drop without shutdown.
        let telemetry_drop = EngineTelemetry::default();
        let active_drop = AtomicBool::new(false);
        let (_peer2, local2) = tokio::io::duplex(1024);
        let mut counted2 = CountingStream::new(local2, &telemetry_drop, &active_drop);
        counted2.write_all(small).await.unwrap();
        counted2.flush().await.unwrap();
        assert_eq!(telemetry_drop.bytes_tx.load(Ordering::Relaxed), 0);
        drop(counted2);
        assert_eq!(
            telemetry_drop.bytes_tx.load(Ordering::Relaxed),
            small.len() as u64
        );
    }

    #[tokio::test]
    async fn hrr_split_ccs_and_pq_client_hello2_reassembles_and_desyncs() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["hrr-pq\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch1 = build_synthetic_client_hello("edge.hrr-pq.example", 512);
        let ch2 = build_synthetic_client_hello("edge.hrr-pq.example", 1750);
        let ch1_payload_len = ch1.len() - 5;
        let ch2_expected_payload = ch2[5..].to_vec();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            // Drain desynced ClientHello #1
            let mut got1 = 0usize;
            while got1 < ch1_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                got1 += rlen;
            }

            // Send TLS 1.3 HelloRetryRequest ServerHello
            let mut hrr = vec![
                0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
            ];
            hrr.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);
            hrr.extend_from_slice(&[0u8; 10]);
            sock.write_all(&hrr).await.unwrap();

            // Expect 6-byte ChangeCipherSpec followed by desynced multi-record ClientHello #2
            let mut ccs = [0u8; 6];
            sock.read_exact(&mut ccs).await.unwrap();
            assert_eq!(ccs, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

            let mut reassembled2 = Vec::with_capacity(ch2_expected_payload.len());
            let mut ch2_records = 0usize;
            while reassembled2.len() < ch2_expected_payload.len() {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x16);
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                assert!(!body.windows(19).any(|w| w == b"edge.hrr-pq.example"));
                reassembled2.extend_from_slice(&body);
                ch2_records += 1;
            }
            assert_eq!(reassembled2, ch2_expected_payload);
            assert!(ch2_records >= 2);
            let _ = sock.shutdown().await;
        });

        let (mut app_side, tun_side) = tokio::io::duplex(64 * 1024);
        let ch1_send = ch1.clone();
        let ch2_send = ch2.clone();
        let app_task = tokio::spawn(async move {
            app_side.write_all(&ch1_send).await.unwrap();
            let mut hrr_reply = [0u8; 53];
            app_side.read_exact(&mut hrr_reply).await.unwrap();

            // Send CCS alone first, then PQ ClientHello #2 split across 2 TCP reads.
            app_side
                .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            app_side.write_all(&ch2_send[..1460]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            app_side.write_all(&ch2_send[1460..]).await.unwrap();
            app_side.shutdown().await.unwrap();
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(tun_side, remote, Some("edge.hrr-pq.example"), upstream_addr)
            .await
            .unwrap();

        app_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hrr_partial_server_record_and_split_ccs_prefix_avoids_deadlock() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["hrr-partial\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch1 = build_synthetic_client_hello("edge.hrr-partial.example", 512);
        let ch2 = build_synthetic_client_hello("edge.hrr-partial.example", 512);
        let ch1_payload_len = ch1.len() - 5;
        let ch2_expected_payload = ch2[5..].to_vec();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut got1 = 0usize;
            while got1 < ch1_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                got1 += rlen;
            }

            // Send TLS 1.3 HelloRetryRequest split across 3 TCP segments (2 bytes, 42 bytes, tail).
            let mut hrr = vec![
                0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
            ];
            hrr.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);
            hrr.extend_from_slice(&[0u8; 10]);
            sock.write_all(&hrr[..2]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            sock.write_all(&hrr[2..44]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            sock.write_all(&hrr[44..]).await.unwrap();

            // Expect 6-byte ChangeCipherSpec followed by desynced multi-record ClientHello #2.
            let mut ccs = [0u8; 6];
            sock.read_exact(&mut ccs).await.unwrap();
            assert_eq!(ccs, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

            let mut reassembled2 = Vec::with_capacity(ch2_expected_payload.len());
            let mut ch2_records = 0usize;
            while reassembled2.len() < ch2_expected_payload.len() {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x16);
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                reassembled2.extend_from_slice(&body);
                ch2_records += 1;
            }
            assert_eq!(reassembled2, ch2_expected_payload);
            assert!(ch2_records >= 2);
            let _ = sock.shutdown().await;
        });

        let (mut app_side, tun_side) = tokio::io::duplex(64 * 1024);
        let ch1_send = ch1.clone();
        let ch2_send = ch2.clone();
        let app_task = tokio::spawn(async move {
            app_side.write_all(&ch1_send).await.unwrap();
            let mut hrr_reply = [0u8; 53];
            app_side.read_exact(&mut hrr_reply).await.unwrap();

            // Send CCS split across two reads (2 bytes + 4 bytes), then ClientHello #2.
            app_side.write_all(&[0x14, 0x03]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            app_side.write_all(&[0x03, 0x00, 0x01, 0x01]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            app_side.write_all(&ch2_send).await.unwrap();
            app_side.shutdown().await.unwrap();
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(
            tun_side,
            remote,
            Some("edge.hrr-partial.example"),
            upstream_addr,
        )
        .await
        .unwrap();

        app_task.await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn direct_passthrough_skips_parent_wildcard_and_eviction_removes_both_keys() {
        let ctx = test_engine_context();

        // Multi-tenant cloud, Microsoft/Google, and Turkish suffixes must be treated as two-part TLDs.
        for host in [
            "d123.cloudfront.net",
            "s3.amazonaws.com",
            "user.github.io",
            "site.pages.dev",
            "app.workers.dev",
            "tenant.akamaized.net",
            "cdn.fastly.net",
            "demo.vercel.app",
            "login.microsoft.com",
            "ctldl.windows.com",
            "auth.live.com",
            "edgedl.gvt2.com",
            "svc.azureedge.net",
            "edge.azurefd.net",
            "blob.windows.net",
            "fonts.googleapis.com",
            "www.gstatic.com",
            "school.k12.tr",
            "ankara.bel.tr",
            "egm.pol.tr",
            "corp.kep.tr",
            "kkk.tsk.tr",
        ] {
            assert_eq!(
                parent_domain_cache_key(host),
                None,
                "multi-tenant/2-part TLD {host} must not collapse into broad wildcard"
            );
        }
        assert_eq!(
            parent_domain_cache_key("sub.school.k12.tr").as_deref(),
            Some("*.school.k12.tr")
        );
        assert_eq!(
            parent_domain_cache_key("a.site.pages.dev").as_deref(),
            Some("*.site.pages.dev")
        );

        // DirectPassthrough, OOB stages, and DeepRecordStorm must never write a `*.parent` wildcard.
        for (host, stage) in [
            ("strict.vendor.example", LearnedStrategy::DirectPassthrough),
            ("oob1.oob-host.example", LearnedStrategy::OobSniDesync),
            ("oob2.moob-host.example", LearnedStrategy::MultiRecordOob),
            ("storm.storm-host.example", LearnedStrategy::DeepRecordStorm),
        ] {
            ctx.record_host_stage(Some(host), stage, false).await;
            let parent = parent_domain_cache_key(host).unwrap();
            let guard = ctx.adaptive_cache.read().await;
            assert_eq!(guard.get(host).copied(), Some(stage));
            assert!(
                !guard.contains_key(&parent),
                "{stage:?} must not auto-wildcard onto {parent}"
            );
        }

        // Non-Primary / non-DirectPassthrough writes both host and `*.parent`, and eviction
        // must remove both together (plus any inherited apex entry) so stale wildcards do not survive.
        ctx.record_host_stage(
            Some("shard1.cdn.example"),
            LearnedStrategy::FineFragment,
            false,
        )
        .await;
        ctx.record_host_stage(Some("cdn.example"), LearnedStrategy::FineFragment, false)
            .await;
        {
            let guard = ctx.adaptive_cache.read().await;
            assert_eq!(
                guard.get("shard1.cdn.example").copied(),
                Some(LearnedStrategy::FineFragment)
            );
            assert_eq!(
                guard.get("*.cdn.example").copied(),
                Some(LearnedStrategy::FineFragment)
            );
            assert_eq!(
                guard.get("cdn.example").copied(),
                Some(LearnedStrategy::FineFragment)
            );
        }
        ctx.evict_cached_host_stage("shard1.cdn.example").await;
        {
            let guard = ctx.adaptive_cache.read().await;
            assert!(!guard.contains_key("shard1.cdn.example"));
            assert!(!guard.contains_key("*.cdn.example"));
            assert!(!guard.contains_key("cdn.example"));
        }

        // Fragment mode must deduplicate FineFragment in build_stage_order.
        let frag_ctx = EngineContext::new(RuntimeConfig {
            system_proxy: false,
            mode: DesyncMode::Fragment,
            ..RuntimeConfig::default()
        })
        .unwrap();
        let frag_order = frag_ctx.build_stage_order(None);
        assert!(frag_order.contains(&LearnedStrategy::Primary));
        assert!(!frag_order.contains(&LearnedStrategy::FineFragment));
        assert_eq!(frag_order.len(), ALL_STAGES.len() - 1);
    }

    #[tokio::test]
    async fn oob_stage_demotes_to_clean_non_oob_after_three_tls_alert_hosts() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["oob-demote-[a-z]\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();
        ctx.preferred_isp_stage_updated_at
            .store(unix_now_secs(), Ordering::Release);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::OobSniDesync as u8, Ordering::Release);
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::OobSniDesync);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let step_counter = Arc::new(AtomicUsize::new(0));
        let step_srv = Arc::clone(&step_counter);

        // Even attempts (OobSniDesync) get TLS Alert 0x15; odd attempts (Primary) succeed.
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let step = step_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;

                    if step.is_multiple_of(2) {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'C', b'L', b'E', b'A', b'N',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let hosts = [
            "a.oob-demote-a.example",
            "b.oob-demote-b.example",
            "c.oob-demote-c.example",
        ];
        for (idx, &host) in hosts.iter().enumerate() {
            let ch = build_synthetic_client_hello(host, 256);
            let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
            let reader = tokio::spawn(async move {
                let mut reply = [0u8; 10];
                app_side.read_exact(&mut reply).await.unwrap();
                reply
            });
            let remote = TcpStream::connect(upstream_addr).await.unwrap();
            let _ = ctx
                .establish_initial_flight(&mut tun_side, remote, &ch, Some(host), upstream_addr)
                .await
                .unwrap();
            let reply = reader.await.unwrap();
            assert_eq!(
                &reply,
                &[0x16, 0x03, 0x03, 0x00, 0x05, b'C', b'L', b'E', b'A', b'N']
            );
            if idx + 1 < FAST_PROMOTION_QUORUM {
                assert_eq!(ctx.preferred_stage(), LearnedStrategy::OobSniDesync);
            }
        }
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn connect_retry_stream_dials_alt_target_before_fallback() {
        let ctx = test_engine_context();
        let alt_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alt_addr = alt_listener.local_addr().unwrap();
        let orig_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let orig_addr = orig_listener.local_addr().unwrap();

        let mut dead_retry_ips = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (_stream, connected) =
            connect_retry_stream(&ctx, alt_addr, orig_addr, deadline, &mut dead_retry_ips)
                .await
                .expect("should connect to alt_addr first");
        assert_eq!(connected, alt_addr);
        assert!(dead_retry_ips.is_empty());

        // When alt_addr is closed, falls back cleanly to orig_addr and marks alt_addr dead.
        drop(alt_listener);
        let (_stream2, connected2) =
            connect_retry_stream(&ctx, alt_addr, orig_addr, deadline, &mut dead_retry_ips)
                .await
                .expect("should fall back to orig_addr");
        assert_eq!(connected2, orig_addr);
        assert_eq!(dead_retry_ips, vec![alt_addr]);
    }

    #[tokio::test]
    async fn dead_alternate_ip_is_skipped_on_subsequent_retry_stages_reaching_oob() {
        let primary_ip: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let dead_ip: SocketAddr = "198.51.100.2:443".parse().unwrap();
        let live_ip: SocketAddr = "198.51.100.3:443".parse().unwrap();
        let sample_addrs = [primary_ip, dead_ip, live_ip];
        assert_eq!(select_retry_target(&sample_addrs, primary_ip, &[], 1), dead_ip);
        assert_eq!(
            select_retry_target(&sample_addrs, primary_ip, &[dead_ip], 2),
            live_ip
        );
        assert_eq!(
            select_retry_target(&sample_addrs, primary_ip, &[dead_ip, live_ip], 3),
            primary_ip
        );

        #[derive(Debug, Default)]
        struct DialCountingBinder {
            calls: AtomicUsize,
        }

        impl OutboundBinder for DialCountingBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let binder = Arc::new(DialCountingBinder::default());
        let binder_trait: Arc<dyn OutboundBinder> = binder.clone();
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["dead-alt\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new_with_binder(config, Some(binder_trait)).unwrap();

        let primary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = primary_listener.accept().await else {
                    break;
                };
                let step = attempts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;

                    if step == 0 {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                            )
                            .await;
                    } else if step < 4 {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'O', b'B', b'O', b'K',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let host = "edge.dead-alt.example";
        let ch = build_synthetic_client_hello(host, 256);
        let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
        let reader = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app_side.read_exact(&mut reply).await.unwrap();
            reply
        });

        let initial_remote = TcpStream::connect(primary_addr).await.unwrap();
        let _stream = ctx
            .establish_initial_flight_inner(
                &mut tun_side,
                initial_remote,
                &ch,
                Some(host),
                primary_addr,
                HandshakeAttemptConfig {
                    budget: MAX_HANDSHAKE_DEADLINE,
                    preseeded_retry_addrs: Some(vec![primary_addr, dead_addr]),
                },
            )
            .await
            .unwrap();

        let reply = reader.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'O', b'B', b'O', b'K']
        );
        // Stages 0..=4 hit primary_addr 5 times total; dead_addr is dialed ONLY once on stage 1
        // and skipped on stages 2, 3, and 4 (1 dead dial + 4 primary retry dials = 5 total dials).
        assert_eq!(attempts.load(Ordering::SeqCst), 5);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 5);
        assert_eq!(
            ctx.adaptive_cache.read().await.get(host).copied(),
            Some(LearnedStrategy::OobSniDesync)
        );
    }

    #[tokio::test]
    async fn dead_alternate_ip_is_skipped_across_connections_and_cleared_on_success() {
        #[derive(Debug, Default)]
        struct DialCountingBinder {
            calls: AtomicUsize,
        }

        impl OutboundBinder for DialCountingBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let binder = Arc::new(DialCountingBinder::default());
        let binder_trait: Arc<dyn OutboundBinder> = binder.clone();
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["cross-dead-[12]\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new_with_binder(config, Some(binder_trait)).unwrap();

        let primary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = primary_listener.accept().await else {
                    break;
                };
                let step = attempts_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;

                    if step.is_multiple_of(2) {
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                            )
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'R', b'E', b'T', b'R', b'Y',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        // Connection 1 discovers dead_addr once on stage 1 (1 dead dial + 1 fallback dial = 2).
        let host1 = "a.cross-dead-1.example";
        let ch1 = build_synthetic_client_hello(host1, 256);
        let (mut app1, mut tun1) = tokio::io::duplex(8192);
        let reader1 = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app1.read_exact(&mut reply).await.unwrap();
            reply
        });
        let init1 = TcpStream::connect(primary_addr).await.unwrap();
        let _stream1 = ctx
            .establish_initial_flight_inner(
                &mut tun1,
                init1,
                &ch1,
                Some(host1),
                primary_addr,
                HandshakeAttemptConfig {
                    budget: MAX_HANDSHAKE_DEADLINE,
                    preseeded_retry_addrs: Some(vec![primary_addr, dead_addr]),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            &reader1.await.unwrap(),
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'R', b'E', b'T', b'R', b'Y']
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 2);
        assert!(ctx.is_dead_retry_ip(dead_addr).await);

        // Connection 2 on a cloned EngineContext skips dead_addr completely (0 dead dials + 1 fallback dial).
        let ctx2 = ctx.clone();
        let host2 = "b.cross-dead-2.example";
        let ch2 = build_synthetic_client_hello(host2, 256);
        let (mut app2, mut tun2) = tokio::io::duplex(8192);
        let reader2 = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app2.read_exact(&mut reply).await.unwrap();
            reply
        });
        let init2 = TcpStream::connect(primary_addr).await.unwrap();
        let _stream2 = ctx2
            .establish_initial_flight_inner(
                &mut tun2,
                init2,
                &ch2,
                Some(host2),
                primary_addr,
                HandshakeAttemptConfig {
                    budget: MAX_HANDSHAKE_DEADLINE,
                    preseeded_retry_addrs: Some(vec![primary_addr, dead_addr]),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            &reader2.await.unwrap(),
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'R', b'E', b'T', b'R', b'Y']
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 3);

        // Cached dead IP is skipped directly in connect_retry_stream, and cleared if it succeeds.
        let recovered_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let recovered_addr = recovered_listener.local_addr().unwrap();
        ctx.mark_dead_retry_ip(recovered_addr).await;
        assert!(ctx.is_dead_retry_ip(recovered_addr).await);

        let mut local_dead = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let (_s, connected) =
            connect_retry_stream(&ctx, recovered_addr, primary_addr, deadline, &mut local_dead)
                .await
                .expect("should skip cached dead IP and connect to fallback");
        assert_eq!(connected, primary_addr);
        assert_eq!(local_dead, vec![recovered_addr]);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 4);

        let _recovered_stream = ctx.connect_upstream_addr(recovered_addr).await.unwrap();
        assert!(!ctx.is_dead_retry_ip(recovered_addr).await);
        assert!(!ctx.dead_retry_ips.read().await.contains_key(&recovered_addr));

        let (_s2, connected2) =
            connect_retry_stream(&ctx, recovered_addr, primary_addr, deadline, &mut Vec::new())
                .await
                .expect("should dial recovered_addr once cleared from cache");
        assert_eq!(connected2, recovered_addr);

        // Expired TTL entry is ignored and cleared once dial succeeds.
        if let Some(expired) = Instant::now().checked_sub(DEAD_RETRY_IP_TTL + Duration::from_secs(1))
        {
            ctx.dead_retry_ips
                .write()
                .await
                .insert(recovered_addr, expired);
            assert!(!ctx.is_dead_retry_ip(recovered_addr).await);
            let (_s3, connected3) =
                connect_retry_stream(&ctx, recovered_addr, primary_addr, deadline, &mut Vec::new())
                    .await
                    .expect("expired dead IP should be retried");
            assert_eq!(connected3, recovered_addr);
            assert!(!ctx.dead_retry_ips.read().await.contains_key(&recovered_addr));
        }

        // Cache stays bounded at MAX_DEAD_RETRY_IPS entries.
        for i in 0..(MAX_DEAD_RETRY_IPS + 20) {
            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, (i / 256) as u8, (i % 256) as u8)),
                443,
            );
            ctx.mark_dead_retry_ip(addr).await;
        }
        assert_eq!(ctx.dead_retry_ips.read().await.len(), MAX_DEAD_RETRY_IPS);
    }

    #[tokio::test]
    async fn alternate_ip_failover_never_promotes_and_tls_alert_retries_same_ip() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec![
                "alt-promo-[a-z]\\.example$".to_string(),
                "alt-demote-[a-z]\\.example$".to_string(),
            ],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        // Part A: Primary IP receives DPI HTTP 302 block injection on stage 0 (Primary),
        // triggering alternate-IP failover. Even when OobSniDesync succeeds on `alt_addr`
        // across FAST_PROMOTION_QUORUM (3) distinct hosts, `!used_alternate_ip` must block
        // global stage promotion so IP failover never casts a global promotion vote.
        let primary_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        let alt_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alt_addr = alt_listener.local_addr().unwrap();
        let alt_hits = Arc::new(AtomicUsize::new(0));
        let alt_hits_srv = Arc::clone(&alt_hits);

        let promo_hosts = [
            "a.alt-promo-a.example",
            "b.alt-promo-b.example",
            "c.alt-promo-c.example",
        ];

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = primary_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                        )
                        .await;
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = alt_listener.accept().await else {
                    break;
                };
                let step = alt_hits_srv.fetch_add(1, Ordering::SeqCst) % 4;
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;
                    if step < 3 {
                        // Reject FineFragment / DeepRecordStorm / SlowSniSlice with TLS Alert.
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32])
                            .await;
                    } else {
                        // Succeed on OobSniDesync on alternate IP.
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'A', b'L', b'T', b'O', b'K',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        for &host in &promo_hosts {
            let ch = build_synthetic_client_hello(host, 256);
            let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
            let reader = tokio::spawn(async move {
                let mut reply = [0u8; 10];
                app_side.read_exact(&mut reply).await.unwrap();
                reply
            });
            let remote = TcpStream::connect(primary_addr).await.unwrap();
            let _stream = ctx
                .establish_initial_flight_inner(
                    &mut tun_side,
                    remote,
                    &ch,
                    Some(host),
                    primary_addr,
                    HandshakeAttemptConfig {
                        budget: MAX_HANDSHAKE_DEADLINE,
                        preseeded_retry_addrs: Some(vec![primary_addr, alt_addr]),
                    },
                )
                .await
                .unwrap();
            let reply = reader.await.unwrap();
            assert_eq!(
                &reply,
                &[0x16, 0x03, 0x03, 0x00, 0x05, b'A', b'L', b'T', b'O', b'K']
            );
        }
        assert_eq!(alt_hits.load(Ordering::SeqCst), FAST_PROMOTION_QUORUM * 4);
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);

        // Part B: Promoted OOB stage receives a server TLS Alert (0x15) on primary IP.
        // Because the server is alive and merely rejected the strategy, retry must dial
        // `primary_oob_addr` FIRST (`alt_oob_hits == 0`) so clean Primary succeeds on the
        // same IP and demotes OOB back to Primary across 3 distinct hosts.
        ctx.preferred_isp_stage_updated_at
            .store(unix_now_secs(), Ordering::Release);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::OobSniDesync as u8, Ordering::Release);

        let primary_oob = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_oob_addr = primary_oob.local_addr().unwrap();
        let alt_oob = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let alt_oob_addr = alt_oob.local_addr().unwrap();
        let primary_oob_hits = Arc::new(AtomicUsize::new(0));
        let primary_oob_hits_srv = Arc::clone(&primary_oob_hits);
        let alt_oob_hits = Arc::new(AtomicUsize::new(0));
        let alt_oob_hits_srv = Arc::clone(&alt_oob_hits);

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = primary_oob.accept().await else {
                    break;
                };
                let step = primary_oob_hits_srv.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rlen];
                    let _ = sock.read_exact(&mut body).await;
                    if step.is_multiple_of(2) {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'C', b'L', b'E', b'A', b'N',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = alt_oob.accept().await else {
                    break;
                };
                let hits = Arc::clone(&alt_oob_hits_srv);
                tokio::spawn(async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = sock.shutdown().await;
                });
            }
        });

        let demote_hosts = [
            "a.alt-demote-a.example",
            "b.alt-demote-b.example",
            "c.alt-demote-c.example",
        ];
        for &host in &demote_hosts {
            let ch = build_synthetic_client_hello(host, 256);
            let (mut app_side, mut tun_side) = tokio::io::duplex(8192);
            let reader = tokio::spawn(async move {
                let mut reply = [0u8; 10];
                app_side.read_exact(&mut reply).await.unwrap();
                reply
            });
            let remote = TcpStream::connect(primary_oob_addr).await.unwrap();
            let _stream = ctx
                .establish_initial_flight_inner(
                    &mut tun_side,
                    remote,
                    &ch,
                    Some(host),
                    primary_oob_addr,
                    HandshakeAttemptConfig {
                        budget: MAX_HANDSHAKE_DEADLINE,
                        preseeded_retry_addrs: Some(vec![primary_oob_addr, alt_oob_addr]),
                    },
                )
                .await
                .unwrap();
            let reply = reader.await.unwrap();
            assert_eq!(
                &reply,
                &[0x16, 0x03, 0x03, 0x00, 0x05, b'C', b'L', b'E', b'A', b'N']
            );
        }
        assert_eq!(alt_oob_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            primary_oob_hits.load(Ordering::SeqCst),
            FAST_PROMOTION_QUORUM * 2
        );
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn hrr_drains_trailing_server_ccs_and_skips_incomplete_hrr() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["hrr-edge\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch1 = build_synthetic_client_hello("edge.hrr-edge.example", 512);
        let ch2 = build_synthetic_client_hello("edge.hrr-edge.example", 512);
        let ch1_payload_len = ch1.len() - 5;
        let ch2_expected_payload = ch2[5..].to_vec();

        // Subtest A: Server sends HRR followed by a delayed 6-byte middlebox CCS; client waits
        // for both HRR + server CCS before sending ClientHello #2 (must not deadlock).
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut got1 = 0usize;
            while got1 < ch1_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                got1 += rlen;
            }

            let mut hrr = vec![
                0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
            ];
            hrr.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);
            hrr.extend_from_slice(&[0u8; 10]);
            sock.write_all(&hrr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(15)).await;
            sock.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();

            let mut ccs = [0u8; 6];
            sock.read_exact(&mut ccs).await.unwrap();
            assert_eq!(ccs, [0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

            let mut reassembled2 = Vec::with_capacity(ch2_expected_payload.len());
            let mut ch2_records = 0usize;
            while reassembled2.len() < ch2_expected_payload.len() {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                assert_eq!(hdr[0], 0x16);
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                reassembled2.extend_from_slice(&body);
                ch2_records += 1;
            }
            assert_eq!(reassembled2, ch2_expected_payload);
            assert!(ch2_records >= 2);
            let _ = sock.shutdown().await;
        });

        let (mut app_side, tun_side) = tokio::io::duplex(64 * 1024);
        let ch1_send = ch1.clone();
        let ch2_send = ch2.clone();
        let app_task = tokio::spawn(async move {
            app_side.write_all(&ch1_send).await.unwrap();
            // Client waits for BOTH the 53-byte HRR AND the 6-byte trailing server CCS.
            let mut hrr_and_ccs = [0u8; 59];
            app_side.read_exact(&mut hrr_and_ccs).await.unwrap();
            assert_eq!(&hrr_and_ccs[53..], &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);

            app_side
                .write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();
            app_side.write_all(&ch2_send).await.unwrap();
            app_side.shutdown().await.unwrap();
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(tun_side, remote, Some("edge.hrr-edge.example"), upstream_addr)
            .await
            .unwrap();
        app_task.await.unwrap();
        server.await.unwrap();

        // Subtest B: Truncated HRR (45 < 53 expected_total) must NOT classify as HRR or stall
        // waiting 4s for ClientHello #2.
        let trunc_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let trunc_addr = trunc_upstream.local_addr().unwrap();
        let trunc_srv = tokio::spawn(async move {
            let (mut sock, _) = trunc_upstream.accept().await.unwrap();
            let mut got1 = 0usize;
            while got1 < ch1_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                got1 += rlen;
            }
            let mut partial_hrr = vec![
                0x16, 0x03, 0x03, 0x00, 0x30, 0x02, 0x00, 0x00, 0x2c, 0x03, 0x03,
            ];
            partial_hrr.extend_from_slice(&TLS13_HELLO_RETRY_REQUEST_RANDOM);
            partial_hrr.extend_from_slice(&[0u8; 2]); // 45 of 53 bytes
            sock.write_all(&partial_hrr).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let (mut app_side2, mut tun_side2) = tokio::io::duplex(8192);
        let reader2 = tokio::spawn(async move {
            let mut got = [0u8; 45];
            app_side2.read_exact(&mut got).await.unwrap();
            got
        });
        let remote2 = TcpStream::connect(trunc_addr).await.unwrap();
        let started = Instant::now();
        let _stream2 = ctx
            .establish_initial_flight(
                &mut tun_side2,
                remote2,
                &ch1,
                Some("edge.hrr-edge.example"),
                trunc_addr,
            )
            .await
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "incomplete HRR must not stall waiting 4s for ClientHello #2"
        );
        let _ = reader2.await.unwrap();
        trunc_srv.await.unwrap();
    }

    #[tokio::test]
    async fn apex_direct_passthrough_not_inherited_and_cached_hit_skips_write_lock() {
        let ctx = test_engine_context();

        // Apex DirectPassthrough applies only to exact host, never inherited by subdomains.
        ctx.record_host_stage(
            Some("vendor.example"),
            LearnedStrategy::DirectPassthrough,
            false,
        )
        .await;
        assert_eq!(
            ctx.lookup_cached_host_stage("vendor.example").await,
            Some(LearnedStrategy::DirectPassthrough)
        );
        assert_eq!(ctx.lookup_cached_host_stage("sub.vendor.example").await, None);

        // Even a legacy `*.parent` DirectPassthrough entry must not be inherited.
        ctx.adaptive_cache.write().await.insert(
            "*.legacy-direct.example".to_string(),
            LearnedStrategy::DirectPassthrough,
        );
        assert_eq!(
            ctx.lookup_cached_host_stage("a.legacy-direct.example").await,
            None
        );

        // Non-DirectPassthrough apex strategies remain inheritable by subdomains.
        ctx.record_host_stage(Some("cdn-ok.example"), LearnedStrategy::FineFragment, false)
            .await;
        assert_eq!(
            ctx.lookup_cached_host_stage("img.cdn-ok.example").await,
            Some(LearnedStrategy::FineFragment)
        );

        // Cached exception host hits (apex, subdomain, DirectPassthrough) must take the shared
        // read-lock fast path without ever acquiring an exclusive write lock.
        ctx.record_host_stage(
            Some("shard1.exc-sub.example"),
            LearnedStrategy::FineFragment,
            false,
        )
        .await;
        let _read_guard = ctx.adaptive_cache.read().await;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(250),
                ctx.record_host_stage(Some("cdn-ok.example"), LearnedStrategy::FineFragment, false),
            )
            .await
            .is_ok()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(250),
                ctx.record_host_stage(
                    Some("shard1.exc-sub.example"),
                    LearnedStrategy::FineFragment,
                    false,
                ),
            )
            .await
            .is_ok()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(250),
                ctx.record_host_stage(
                    Some("vendor.example"),
                    LearnedStrategy::DirectPassthrough,
                    false,
                ),
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn connect_target_deprioritizes_dead_ips_across_connections_and_clears_on_recovery() {
        #[derive(Debug)]
        struct FailingFirstDialBinder {
            calls: AtomicUsize,
            fail_remaining: AtomicUsize,
        }

        impl OutboundBinder for FailingFirstDialBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let mut cur = self.fail_remaining.load(Ordering::SeqCst);
                let mut should_fail = false;
                while let Some(next) = cur.checked_sub(1) {
                    match self.fail_remaining.compare_exchange_weak(
                        cur,
                        next,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => {
                            should_fail = true;
                            break;
                        }
                        Err(actual) => cur = actual,
                    }
                }
                if should_fail {
                    return Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "simulated SYN-blackholed dead IP",
                    ));
                }
                Ok(())
            }
        }

        let live_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live_listener.local_addr().unwrap();
        let live_port = live_addr.port();
        let dead_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), live_port);

        let accept_task = tokio::spawn(async move {
            while let Ok((_sock, _)) = live_listener.accept().await {}
        });

        let udp_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_dns_addr = udp_dns.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = udp_dns.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                let mut pos = 12usize;
                while pos < n && buf[pos] != 0 {
                    pos = pos.saturating_add(1 + usize::from(buf[pos]));
                }
                let question_end = pos.saturating_add(5);
                if question_end > n {
                    continue;
                }
                let rd = u16::from_be_bytes([buf[2], buf[3]]) & 0x0100;
                let resp_flags = 0x8080 | rd;
                let answers = [Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOCALHOST];
                let mut resp = Vec::with_capacity(12 + (question_end - 12) + answers.len() * 16);
                resp.extend_from_slice(&buf[0..2]); // TX ID
                resp.extend_from_slice(&resp_flags.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
                resp.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes()); // ANCOUNT
                resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
                resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                resp.extend_from_slice(&buf[12..question_end]);
                for v4 in answers {
                    resp.extend_from_slice(&[0xc0, 0x0c]); // QNAME pointer at offset 12
                    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH 4
                    resp.extend_from_slice(&v4.octets());
                }
                let _ = udp_dns.send_to(&resp, peer).await;
            }
        });

        let binder = Arc::new(FailingFirstDialBinder {
            calls: AtomicUsize::new(0),
            fail_remaining: AtomicUsize::new(1),
        });
        let binder_trait: Arc<dyn OutboundBinder> = binder.clone();
        let config = RuntimeConfig {
            system_proxy: false,
            dns_addr: "127.0.0.1".to_string(),
            dns_port: udp_dns_addr.port(),
            enable_doh: false,
            dns_ipv4_only: true,
            disable_system_dns_fallback: true,
            connect_timeout: Duration::from_secs(5),
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new_with_binder(config, Some(binder_trait)).unwrap();

        // Connection 1: DNS returns [dead_ip, live_ip]. First dial fails, second succeeds,
        // so dead_addr is cached in dead_retry_ips and live_addr stays clear.
        let (_s1, connected1) = ctx
            .connect_target("dead-first.example", live_port)
            .await
            .expect("second A record should succeed after first fails");
        assert_eq!(connected1, live_addr);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 2);
        assert!(ctx.is_dead_retry_ip(dead_addr).await);
        assert!(!ctx.is_dead_retry_ip(live_addr).await);

        // Connection 2 on a cloned EngineContext: dead_addr is deprioritized behind live_addr,
        // so live_addr is dialed first and succeeds immediately (only 1 dial, no 3s timeout).
        let ctx2 = ctx.clone();
        let started = Instant::now();
        let (_s2, connected2) = ctx2
            .connect_target("dead-first.example", live_port)
            .await
            .expect("healthy A record should be dialed first without touching cached dead IP");
        assert_eq!(connected2, live_addr);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 3);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "deprioritized dead IP must not burn the 3s connect timeout"
        );
        assert!(ctx2.is_dead_retry_ip(dead_addr).await);

        // If all candidates are marked dead, deprioritized IPs are still dialed as fallback,
        // and the succeeding IP is cleared from dead_retry_ips.
        ctx.mark_dead_retry_ip(live_addr).await;
        assert!(ctx.is_dead_retry_ip(live_addr).await);
        binder.fail_remaining.store(1, Ordering::SeqCst);
        let (_s3, connected3) = ctx
            .connect_target("dead-first.example", live_port)
            .await
            .expect("all-dead fallback should still connect and clear succeeding IP");
        assert_eq!(connected3, live_addr);
        assert_eq!(binder.calls.load(Ordering::SeqCst), 5);
        assert!(ctx.is_dead_retry_ip(dead_addr).await);
        assert!(!ctx.is_dead_retry_ip(live_addr).await);
        assert!(!ctx.dead_retry_ips.read().await.contains_key(&live_addr));

        // When every candidate fails (e.g. transient outage), do not poison dead_retry_ips.
        let unused_port = {
            let tmp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            tmp.local_addr().unwrap().port()
        };
        let unused_dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), unused_port);
        let unused_live = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), unused_port);
        binder.fail_remaining.store(2, Ordering::SeqCst);
        assert!(ctx
            .connect_target("dead-first.example", unused_port)
            .await
            .is_err());
        assert_eq!(binder.calls.load(Ordering::SeqCst), 7);
        assert!(!ctx.is_dead_retry_ip(unused_dead).await);
        assert!(!ctx.is_dead_retry_ip(unused_live).await);

        dns_task.abort();
        accept_task.abort();
    }

    #[tokio::test]
    async fn wildcard_cache_self_heals_without_duplication_or_ttl_refresh_and_guards_retry_ssrf() {
        // 1. Non-escalated (`idx == 0`) hit via existing parent wildcard must NOT write a
        //    duplicate subdomain entry or refresh the parent wildcard's timestamp.
        let ctx = test_engine_context();
        ctx.record_host_stage(
            Some("shard1.heal-cdn.example"),
            LearnedStrategy::FineFragment,
            false,
        )
        .await;
        let old_ts = unix_now_secs().saturating_sub(3600);
        ctx.adaptive_timestamps
            .write()
            .await
            .insert("*.heal-cdn.example".to_string(), old_ts);
        ctx.record_host_stage_with_escalation(
            Some("shard2.heal-cdn.example"),
            LearnedStrategy::FineFragment,
            false,
            false,
        )
        .await;
        {
            let guard = ctx.adaptive_cache.read().await;
            let ts_guard = ctx.adaptive_timestamps.read().await;
            assert!(!guard.contains_key("shard2.heal-cdn.example"));
            assert_eq!(ts_guard.get("*.heal-cdn.example").copied(), Some(old_ts));
        }

        // 2. Poisoned wildcard + inherited apex entry must self-heal immediately when a
        //    subdomain escalates (`idx > 0`) and recovers with `current_preferred` (Primary).
        let ctx_heal = EngineContext::new(RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["poisoned\\.example$".to_string()],
            ..RuntimeConfig::default()
        })
        .unwrap();
        {
            let mut guard = ctx_heal.adaptive_cache.write().await;
            guard.insert("*.poisoned.example".to_string(), LearnedStrategy::FineFragment);
            guard.insert("poisoned.example".to_string(), LearnedStrategy::FineFragment);
            ctx_heal
                .telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }

        let ch_heal = build_synthetic_client_hello("sub.poisoned.example", 256);
        let orig_rec_len = u16::from_be_bytes([ch_heal[3], ch_heal[4]]) as usize;
        let heal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let heal_addr = heal_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = heal_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    let _ = sock.read_exact(&mut body).await;
                    if rec_len == orig_rec_len {
                        // Reject poisoned single-record FineFragment with TLS Alert.
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        // Accept multi-record Primary recovery.
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'A', b'L', b'!',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });

        let (mut app_heal, mut tun_heal) = tokio::io::duplex(8192);
        let heal_reader = tokio::spawn(async move {
            let mut reply = [0u8; 10];
            app_heal.read_exact(&mut reply).await.unwrap();
            reply
        });
        let remote_heal = TcpStream::connect(heal_addr).await.unwrap();
        let _stream_heal = ctx_heal
            .establish_initial_flight(
                &mut tun_heal,
                remote_heal,
                &ch_heal,
                Some("sub.poisoned.example"),
                heal_addr,
            )
            .await
            .unwrap();
        assert_eq!(
            &heal_reader.await.unwrap(),
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'A', b'L', b'!']
        );
        assert_eq!(ctx_heal.learned_host_count().await, 0);
        assert_eq!(
            ctx_heal
                .lookup_cached_host_stage("other.poisoned.example")
                .await,
            None
        );

        // 3. When `global_isp_stage != Primary`, a Primary override CAN cache `*.roblox.com`.
        let ctx_primary_override = test_engine_context();
        ctx_primary_override
            .preferred_isp_stage_updated_at
            .store(unix_now_secs(), Ordering::Release);
        ctx_primary_override
            .preferred_isp_stage
            .store(LearnedStrategy::OobSniDesync as u8, Ordering::Release);
        ctx_primary_override
            .record_host_stage_with_escalation(
                Some("apis.roblox.com"),
                LearnedStrategy::Primary,
                false,
                true,
            )
            .await;
        {
            let guard = ctx_primary_override.adaptive_cache.read().await;
            assert_eq!(
                guard.get("apis.roblox.com").copied(),
                Some(LearnedStrategy::Primary)
            );
            assert_eq!(
                guard.get("*.roblox.com").copied(),
                Some(LearnedStrategy::Primary)
            );
        }
        assert_eq!(
            ctx_primary_override
                .lookup_cached_host_stage("clientsettings.roblox.com")
                .await,
            Some(LearnedStrategy::Primary)
        );

        // 4. Aborted client connection (write_all fails) must never poison adaptive_cache.
        let ctx_abort = EngineContext::new(RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["abort-check\\.example$".to_string()],
            ..RuntimeConfig::default()
        })
        .unwrap();
        let ch_abort = build_synthetic_client_hello("sub.abort-check.example", 256);
        let orig_abort_len = u16::from_be_bytes([ch_abort[3], ch_abort[4]]) as usize;
        let abort_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let abort_addr = abort_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = abort_listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    let _ = sock.read_exact(&mut body).await;
                    if rec_len < orig_abort_len {
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'K', b'!', b'!', b'!',
                            ])
                            .await;
                    }
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
                });
            }
        });
        let (app_abort, mut tun_abort) = tokio::io::duplex(8192);
        drop(app_abort); // Simulate client disconnecting before ServerHello is written.
        let remote_abort = TcpStream::connect(abort_addr).await.unwrap();
        assert!(ctx_abort
            .establish_initial_flight(
                &mut tun_abort,
                remote_abort,
                &ch_abort,
                Some("sub.abort-check.example"),
                abort_addr,
            )
            .await
            .is_err());
        assert_eq!(ctx_abort.learned_host_count().await, 0);

        // 5. `collect_retry_addrs` must canonicalize `initial_addr`, prefer `known_host` over
        //    untrusted SNI, and filter out non-public IPs (loopback/RFC1918/link-local/CGNAT).
        let udp_dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_dns_addr = udp_dns.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = udp_dns.recv_from(&mut buf).await {
                if n < 12 {
                    continue;
                }
                let mut pos = 12usize;
                while pos < n && buf[pos] != 0 {
                    pos = pos.saturating_add(1 + usize::from(buf[pos]));
                }
                let question_end = pos.saturating_add(5);
                if question_end > n {
                    continue;
                }
                let is_evil = buf[12..pos].windows(4).any(|w| w == b"evil");
                let answers: Vec<Ipv4Addr> = if is_evil {
                    vec![Ipv4Addr::new(203, 0, 113, 99)]
                } else {
                    vec![
                        Ipv4Addr::LOCALHOST,
                        Ipv4Addr::new(10, 0, 0, 5),
                        Ipv4Addr::new(169, 254, 169, 254),
                        Ipv4Addr::new(100, 64, 0, 1),
                        Ipv4Addr::new(198, 51, 100, 20),
                    ]
                };
                let rd = u16::from_be_bytes([buf[2], buf[3]]) & 0x0100;
                let resp_flags = 0x8080 | rd;
                let mut resp = Vec::with_capacity(12 + (question_end - 12) + answers.len() * 16);
                resp.extend_from_slice(&buf[0..2]);
                resp.extend_from_slice(&resp_flags.to_be_bytes());
                resp.extend_from_slice(&1u16.to_be_bytes());
                resp.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&0u16.to_be_bytes());
                resp.extend_from_slice(&buf[12..question_end]);
                for v4 in answers {
                    resp.extend_from_slice(&[0xc0, 0x0c]);
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&1u16.to_be_bytes());
                    resp.extend_from_slice(&60u32.to_be_bytes());
                    resp.extend_from_slice(&4u16.to_be_bytes());
                    resp.extend_from_slice(&v4.octets());
                }
                let _ = udp_dns.send_to(&resp, peer).await;
            }
        });

        let ctx_dns = EngineContext::new(RuntimeConfig {
            system_proxy: false,
            dns_addr: "127.0.0.1".to_string(),
            dns_port: udp_dns_addr.port(),
            enable_doh: false,
            dns_ipv4_only: true,
            disable_system_dns_fallback: true,
            ..RuntimeConfig::default()
        })
        .unwrap();

        let mapped_initial: SocketAddr = "[::ffff:198.51.100.10]:443".parse().unwrap();
        let retry_addrs = ctx_dns
            .collect_retry_addrs(
                Some("trusted.example"),
                Some("evil-sni.example"),
                mapped_initial,
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(
            retry_addrs,
            vec![
                "198.51.100.10:443".parse::<SocketAddr>().unwrap(),
                "198.51.100.20:443".parse::<SocketAddr>().unwrap(),
            ]
        );
        dns_task.abort();
    }
}
