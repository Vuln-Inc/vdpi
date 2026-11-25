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

pub const PERSISTED_CACHE_VERSION: u32 = 1;
pub const MAX_PERSISTED_HOSTS: usize = 256;
pub const PERSISTED_CACHE_TTL_SECS: u64 = 7 * 24 * 3600;
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

#[cfg(any(target_os = "android", target_os = "ios"))]
const RELAY_BUF_SIZE: usize = 16 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const RELAY_BUF_SIZE: usize = 128 * 1024;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LearnedStrategy {
    /// Stage 1: Configured primary mode (default `Combo`: 4 wire-paced RFC-compliant TLS records
    /// split across the handshake header and SNI midpoint).
    Primary = 0,
    /// Stage 2: TCP Out-of-Band (`MSG_OOB`) urgent decoy byte injected right at the SNI midpoint.
    /// Real server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte seamlessly while stateful
    /// full-stream-reassembling ISP DPI boxes corrupt/miss the SNI completely.
    OobSniDesync = 1,
    /// Stage 3: Combined 4-record TLS split + `MSG_OOB` decoy byte injected right at the TLS
    /// record boundary inside SNI, shifting subsequent TLS record framing for DPI state machines.
    MultiRecordOob = 2,
    /// Stage 4: Single intact outer TLS record split across 4 wire-paced TCP segments (compatible
    /// with strict servers that reject multi-record ClientHellos while defeating active DPI).
    FineFragment = 3,
    /// Stage 5: Deep 12+ RFC-compliant TLS record storm (up to 10 tiny 2-byte lead records
    /// exhausting hardware DPI per-flow packet caps before SNI hits the wire + SNI splits).
    DeepRecordStorm = 4,
    /// Stage 6: Single intact outer TLS record with slow 2-byte SNI-only pacing (for strict
    /// servers behind stateful burst-reassembling DPI).
    SlowSniSlice = 5,
    /// Stage 7: Unmodified single-write passthrough (for unblocked strict WAFs/CDNs).
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

    fn promotion_quorum(self) -> Option<usize> {
        match self {
            Self::Primary | Self::OobSniDesync | Self::MultiRecordOob | Self::FineFragment => {
                Some(FAST_PROMOTION_QUORUM)
            }
            Self::DeepRecordStorm | Self::SlowSniSlice => Some(SLOW_PROMOTION_QUORUM),
            Self::DirectPassthrough => None,
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
        let Some(required_quorum) = candidate.promotion_quorum() else {
            return false;
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

        let host_map = self.votes.entry(candidate as u8).or_default();
        if !host_map.contains_key(host) && host_map.len() >= MAX_PROMOTION_VOTE_HOSTS {
            let oldest = host_map
                .iter()
                .min_by(|(ka, ta), (kb, tb)| ta.cmp(tb).then_with(|| ka.cmp(kb)))
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                host_map.remove(&oldest);
            }
        }
        host_map.insert(host.to_string(), now);

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
    let prev = cache.insert(key.clone(), stage);
    timestamps.insert(key, now);
    prev != Some(stage)
}

/// Lock-free live engine counters shared across proxy and TUN sessions.
#[derive(Debug, Default)]
pub struct EngineTelemetry {
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub tls_handshakes: AtomicU64,
    pub auto_heal_escalations: AtomicU64,
    pub learned_hosts: AtomicUsize,
    pub udp_flows_active: AtomicU64,
    pub quic_blocked: AtomicU64,
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

/// Wraps an upstream `TcpStream` to update `bytes_tx` / `bytes_rx` live on every I/O completion
/// (rather than only after clean EOF), so active downloads/streams and reset sockets are counted.
struct CountingStream<S> {
    inner: S,
    telemetry: Arc<EngineTelemetry>,
}

impl<S> CountingStream<S> {
    fn new(inner: S, telemetry: Arc<EngineTelemetry>) -> Self {
        Self { inner, telemetry }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                self.telemetry
                    .bytes_rx
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                self.telemetry
                    .bytes_tx
                    .fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
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
    LearnedStrategy::OobSniDesync,
    LearnedStrategy::MultiRecordOob,
    LearnedStrategy::FineFragment,
    LearnedStrategy::DeepRecordStorm,
    LearnedStrategy::SlowSniSlice,
    LearnedStrategy::DirectPassthrough,
];

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
            if now.saturating_sub(entry.updated_at) > PERSISTED_CACHE_TTL_SECS {
                continue;
            }
            let host = entry.host.trim().to_ascii_lowercase();
            if !is_valid_cache_host(&host) {
                continue;
            }
            let strategy = LearnedStrategy::from_u8(entry.stage);
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
                    if now.saturating_sub(updated_at) > PERSISTED_CACHE_TTL_SECS {
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

        let total_ips = ips.len();
        let mut last_err = None;

        for (idx, ip) in ips.into_iter().enumerate() {
            let target = SocketAddr::new(ip, port);
            let attempt_timeout = if idx + 1 < total_ips {
                self.config.connect_timeout.min(Duration::from_secs(3))
            } else {
                self.config.connect_timeout
            };

            match tokio::time::timeout(attempt_timeout, self.connect_upstream(target)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, target));
                }
                Ok(Err(e)) => {
                    last_err = Some(anyhow!("connect {target} failed: {e}"));
                }
                Err(_) => {
                    last_err = Some(anyhow!(
                        "connect {target} timed out after {attempt_timeout:?}"
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("failed to connect to {host}:{port}")))
    }

    async fn connect_upstream(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        let target = match target {
            SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
                SocketAddr::new(target.ip().to_canonical(), target.port())
            }
            _ => target,
        };
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
                            let _ = tokio::time::timeout(Duration::from_millis(400), async {
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
        mut remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
        handshake_budget: Duration,
    ) -> Result<TcpStream>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
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
                Some(key) => self.adaptive_cache.read().await.get(key).copied(),
                None => None,
            };

            let current_global_stage = self.preferred_stage();
            let stages = self.build_stage_order(cached_stage);
            let mut retry_addrs: Option<Vec<SocketAddr>> = None;

            let mut probe_buf = vec![0u8; 16384];
            let mut current_remote = Some(remote);
            let mut current_global_hard_blocked = false;
            let mut current_global_timed_out = false;
            let mut saw_tls_alert = false;
            let handshake_deadline = Instant::now() + handshake_budget;
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
                        let alt_target = if deadline_exceeded {
                            remote_addr
                        } else {
                            let addrs = match retry_addrs.as_ref() {
                                Some(a) => a,
                                None => {
                                    let resolved = self
                                        .collect_retry_addrs(effective_host, remote_addr, remaining)
                                        .await;
                                    retry_addrs.insert(resolved)
                                }
                            };
                            if addrs.len() > 1 {
                                addrs[1 + (idx.saturating_sub(1) % (addrs.len() - 1))]
                            } else {
                                remote_addr
                            }
                        };
                        match connect_retry_stream(self, remote_addr, alt_target, stage_deadline)
                            .await
                        {
                            Some(pair) => pair,
                            None => continue,
                        }
                    }
                };

                let write_remaining = stage_deadline.saturating_duration_since(Instant::now());
                if write_remaining.is_zero() {
                    if is_direct_passthrough {
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
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            "adaptive TLS handshake deadline exceeded during strategy write"
                        );
                        if is_direct_passthrough {
                            break;
                        }
                        deadline_exceeded = true;
                        continue;
                    }
                }

                let read_remaining = stage_deadline.saturating_duration_since(Instant::now());
                if read_remaining.is_zero() {
                    if is_direct_passthrough {
                        break;
                    }
                    deadline_exceeded = true;
                    continue;
                }

                let wait_ms = match stage {
                    LearnedStrategy::DeepRecordStorm | LearnedStrategy::SlowSniSlice => 2400,
                    _ if idx == 0 => 1500,
                    _ => 2000,
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
                    Ok(Ok(n)) => {
                        let is_valid_tls_server_hello =
                            n >= 2 && probe_buf[0] == 0x16 && probe_buf[1] == 0x03;

                        if !is_valid_tls_server_hello && !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                            if probe_buf[0] == 0x15 {
                                if stage == current_global_stage {
                                    saw_tls_alert = true;
                                }
                                debug!(
                                    host = ?effective_host,
                                    ?stage,
                                    "upstream returned TLS Alert (0x15); auto-healing with next stage"
                                );
                            } else {
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

                        if is_valid_tls_server_hello {
                            let elapsed = read_started.elapsed();
                            let used_alternate_ip = stream_addr != remote_addr;
                            let silent_drop_recovered =
                                current_global_timed_out && elapsed < FAST_SERVER_HELLO_THRESHOLD;
                            let eligible_for_promotion = idx > 0
                                && (current_global_hard_blocked || silent_drop_recovered)
                                && !saw_tls_alert
                                && !used_alternate_ip;
                            self.record_host_stage(
                                cache_key.as_deref(),
                                stage,
                                eligible_for_promotion,
                            )
                            .await;
                        } else if let (Some(_), Some(key)) = (cached_stage, cache_key.as_deref()) {
                            self.evict_cached_host_stage(key).await;
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
                        return Ok(stream);
                    }
                    Ok(Err(err)) => {
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
    ///   fast stages `OobSniDesync`..=`FineFragment`, >= 5 distinct hosts for slow stages
    ///   `DeepRecordStorm`..=`SlowSniSlice`).
    pub(crate) async fn record_host_stage(
        &self,
        host: Option<&str>,
        stage: LearnedStrategy,
        hard_block_promotion_eligible: bool,
    ) {
        let Some(key) = host
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|k| is_valid_cache_host(k))
        else {
            return;
        };

        let now = unix_now_secs();
        let mut cache_changed = false;
        let mut promoted = false;

        if hard_block_promotion_eligible {
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
            } else if upsert_adaptive_entry(&mut guard, &mut ts_guard, key, stage, now) {
                cache_changed = true;
            }

            self.telemetry
                .learned_hosts
                .store(guard.len(), Ordering::Relaxed);
        }

        if cache_changed {
            self.maybe_persist_cache();
        }
    }

    async fn evict_cached_host_stage(&self, key: &str) {
        let removed = {
            let mut guard = self.adaptive_cache.write().await;
            let mut ts_guard = self.adaptive_timestamps.write().await;
            ts_guard.remove(key);
            let removed = guard.remove(key).is_some();
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
        if let Some(cached) = cached_stage {
            order.push(cached);
        }
        let preferred = self.preferred_stage();
        if !order.contains(&preferred) {
            order.push(preferred);
        }
        for stage in ALL_STAGES {
            if !order.contains(&stage) {
                order.push(stage);
            }
        }
        order
    }

    async fn collect_retry_addrs(
        &self,
        host: Option<&str>,
        initial_addr: SocketAddr,
        max_wait: Duration,
    ) -> Vec<SocketAddr> {
        let mut addrs = vec![initial_addr];
        let resolve_timeout = RETRY_DNS_TIMEOUT.min(max_wait);
        if resolve_timeout.is_zero() {
            return addrs;
        }
        if let Some(h) = host {
            if !initial_addr.ip().is_loopback() {
                if let Ok(Ok(ips)) =
                    tokio::time::timeout(resolve_timeout, self.dns.resolve_internal(h)).await
                {
                    // Only rotate among alternate IPs of the same address family that already
                    // proved reachable on attempt 0 so unreachable IPv6 never stalls retries.
                    for ip in ips {
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
    telemetry: &Arc<EngineTelemetry>,
) -> std::io::Result<(u64, u64)>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    let mut counted = CountingStream::new(remote, Arc::clone(telemetry));
    copy_bidirectional_with_sizes(client, &mut counted, RELAY_BUF_SIZE, RELAY_BUF_SIZE).await
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

async fn connect_retry_stream(
    ctx: &EngineContext,
    target: SocketAddr,
    fallback: SocketAddr,
    deadline: Instant,
) -> Option<(TcpStream, SocketAddr)> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    if let Ok(Ok(s)) = tokio::time::timeout(
        Duration::from_millis(2200).min(remaining),
        ctx.connect_upstream(target),
    )
    .await
    {
        let _ = s.set_nodelay(true);
        return Some((s, target));
    }
    if target != fallback {
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
            Some(LearnedStrategy::OobSniDesync)
        );
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::Primary);
    }

    #[tokio::test]
    async fn escalates_to_deep_record_storm_and_promotes_isp_stage_on_dpi_block_injection() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["blocked\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let hosts = [
            "host1.blocked.example",
            "host2.blocked.example",
            "host3.blocked.example",
            "host4.blocked.example",
            "host5.blocked.example",
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
                    updated_at: now.saturating_sub(60),
                },
                PersistedHostEntry {
                    host: "stale.example".to_string(),
                    stage: LearnedStrategy::OobSniDesync as u8,
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
    async fn persisted_cache_expires_global_isp_stage_after_24h_and_loads_v1_without_timestamp() {
        let tmp = TempCacheDir::new("global-ttl");
        let v1_legacy = tmp.file("v1-legacy.json");
        let expired_file = tmp.file("expired-global.json");
        let fresh_file = tmp.file("fresh-global.json");
        let now = unix_now_secs();

        // Backwards-compatible v1 JSON omitting `global_isp_stage_updated_at`: deserializes cleanly
        // and safely expires the untimestamped global_isp_stage back to Primary.
        let legacy_json = format!(
            r#"{{"version":1,"global_isp_stage":4,"entries":[{{"host":"legacy.example","stage":2,"updated_at":{now}}}]}}"#
        );
        std::fs::write(&v1_legacy, legacy_json).unwrap();

        let ctx_legacy = test_engine_context();
        assert_eq!(ctx_legacy.load_persisted_cache(&v1_legacy).await, 1);
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
            patterns: vec!["superonline\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let hosts = [
            "a.superonline.example",
            "b.superonline.example",
            "c.superonline.example",
        ];

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempt_counter = Arc::new(AtomicUsize::new(0));
        let attempt_srv = Arc::clone(&attempt_counter);

        // Simulate Superonline/middlebox behavior per host:
        // - Attempt 0 (Stage 1 Primary): hard-blocked via fake HTTP 302 block page
        // - Attempt 1 (Stage 2 OobSniDesync): server returns TLS Alert 0x15 (decode_error)
        // - Attempt 2 (Stage 3 MultiRecordOob): server returns TLS Alert 0x15 (decode_error)
        // - Attempt 3 (Stage 4 FineFragment): succeeds with valid TLS ServerHello (0x16 0x03)
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let step = attempt_srv.fetch_add(1, Ordering::SeqCst) % 4;
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
                        1 | 2 => {
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
                    Some(LearnedStrategy::FineFragment)
                );
            }
        }

        // Intermediate OOB TLS Alerts (0x15) must not block Stage 4 global promotion.
        assert_eq!(ctx.preferred_stage(), LearnedStrategy::FineFragment);
        assert_eq!(ctx.learned_host_count().await, 0);
        assert_eq!(attempt_counter.load(Ordering::SeqCst), 12);
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
    async fn coalesced_tls13_zero_rtt_auto_heals_and_preserves_trailing_early_data() {
        let config = RuntimeConfig {
            system_proxy: false,
            chunk_size: 10,
            patterns: vec!["zero-rtt\\.example$".to_string()],
            ..RuntimeConfig::default()
        };
        let ctx = EngineContext::new(config).unwrap();

        let ch = build_synthetic_client_hello("api.zero-rtt.example", 256);
        let orig_rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
        // Simulated coalesced TLS 1.3 ChangeCipherSpec + 0-RTT ApplicationData trailing bytes.
        let trailing: Vec<u8> = vec![
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, // CCS
            0x17, 0x03, 0x03, 0x00, 0x08, b'0', b'R', b'T', b'T', b'D', b'A', b'T', b'A',
        ];
        let mut coalesced = ch.clone();
        coalesced.extend_from_slice(&trailing);

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);
        let trailing_expected = trailing.clone();
        let trailing_ok = Arc::new(AtomicBool::new(false));
        let trailing_ok_srv = Arc::clone(&trailing_ok);

        // Reject split ClientHello (Stage 1 Combo) with a TLS Alert, then accept intact
        // single-record ClientHello (Stage 2 OobSniDesync) and verify trailing 0-RTT bytes arrive intact.
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
                &coalesced,
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
            Some(LearnedStrategy::OobSniDesync)
        );
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
}
