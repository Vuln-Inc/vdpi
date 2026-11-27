use crate::config::{TunProfile, MAX_MTU, MIN_MTU};
use crate::events::EventRing;
use crate::netstack::{spawn_tcp_netstack, TunNetstackTcpStream};
use crate::packet::{
    build_icmp_port_unreachable, build_icmpv6_no_route, build_truncated_dns_reply,
    ipv6_tcp_payload, max_dns_udp_payload_for_mtu, max_udp_payload_for_mtu,
};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::AbortHandle;
use tracing::debug;
use vdpi_core::desync::{EngineContext, EngineTelemetry, LearnedStrategy};

pub use crate::config::{AppBypassFn, AppBypassHook};
pub use crate::packet::{
    build_udp_packet, inspect_inbound_udp, is_blocked_quic_udp, is_dtls_packet, is_stun_packet,
    is_valid_inbound_tun_packet, InboundUdpPacket,
};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const UDP_REAPER_INTERVAL: Duration = Duration::from_secs(15);
const SLEEP_WAKE_DRIFT_THRESHOLD: Duration = Duration::from_secs(15);
const MAX_QUIC_ICMP_PER_SEC: u64 = 64;
const TCP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_SLOT_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);
const PASSTHROUGH_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const REVERSE_DNS_TTL_SECS: u64 = 300;
const STUN_FLOW_MAX_ENTRIES: usize = 256;
const STUN_FLOW_TTL_SECS: u64 = 120;
const UDP_APP_BYPASS_CACHE_MAX_ENTRIES: usize = 512;
const UDP_APP_BYPASS_POSITIVE_TTL: Duration = Duration::from_secs(3);
const UDP_APP_BYPASS_NEGATIVE_TTL: Duration = Duration::from_millis(500);
const MAX_APP_BYPASS_INFLIGHT: usize = 64;
const UDP_TELEMETRY_BATCH_BYTES: u64 = 64 * 1024;
const UDP_TELEMETRY_FLUSH_INTERVAL_SECS: u64 = 1;
const MIN_PASSTHROUGH_COPY_BUF: usize = 16 * 1024;
const MAX_PASSTHROUGH_COPY_BUF: usize = 512 * 1024;
#[cfg(not(windows))]
const TCP_KERNEL_BUF_MIN_OPT_BYTES: usize = 256 * 1024;

/// Wraps `TunNetstackTcpStream` so `poll_shutdown` flushes buffered writes and
/// polls TCP FIN cleanly within a bounded 2-second deadline without stalling
/// `tokio::io::copy_bidirectional` indefinitely on unresponsive peers.
struct TunTcpStream {
    inner: TunNetstackTcpStream,
    flushed_for_shutdown: bool,
    shutdown_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl TunTcpStream {
    fn new(inner: TunNetstackTcpStream) -> Self {
        Self {
            inner,
            flushed_for_shutdown: false,
            shutdown_deadline: None,
        }
    }
}

impl AsyncRead for TunTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.flushed_for_shutdown = false;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.flushed_for_shutdown {
            match Pin::new(&mut this.inner).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    this.flushed_for_shutdown = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    let deadline = this
                        .shutdown_deadline
                        .get_or_insert_with(|| Box::pin(tokio::time::sleep(TCP_SHUTDOWN_TIMEOUT)));
                    if deadline.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }

        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => {
                let deadline = this
                    .shutdown_deadline
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep(TCP_SHUTDOWN_TIMEOUT)));
                if deadline.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

struct PipelineAbortGuard {
    handles: Vec<AbortHandle>,
}

impl Drop for PipelineAbortGuard {
    fn drop(&mut self) {
        for h in &self.handles {
            h.abort();
        }
    }
}

#[derive(Debug, Default)]
pub struct TunStats {
    pub quic_blocked: AtomicU64,
    pub udp_flows_active: AtomicU64,
    pub active_tcp: AtomicUsize,
    pub dropped_packets: AtomicU64,
    pub tcp_sessions_dropped: AtomicU64,
}

/// RAII guard that increments `TunStats::active_tcp` on entry and guarantees a matching
/// decrement on normal return, early exit, task abort, or panic.
struct ActiveTcpGuard(Arc<TunStats>);

impl ActiveTcpGuard {
    fn enter(stats: &Arc<TunStats>) -> Self {
        stats.active_tcp.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(stats))
    }
}

impl Drop for ActiveTcpGuard {
    fn drop(&mut self) {
        self.0.active_tcp.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct ReverseDnsCache {
    max_entries: usize,
    map: RwLock<HashMap<IpAddr, (String, u64)>>,
}

impl ReverseDnsCache {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(32),
            map: RwLock::new(HashMap::new()),
        }
    }

    fn clear(&self) {
        self.map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    fn insert(&self, ip: IpAddr, domain: String) {
        self.insert_at(ip, domain, now_secs());
    }

    fn insert_at(&self, ip: IpAddr, domain: String, now: u64) {
        let mut guard = self
            .map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= self.max_entries && !guard.contains_key(&ip) {
            guard.retain(|_, (_, ts)| now.saturating_sub(*ts) < REVERSE_DNS_TTL_SECS);
            if guard.len() >= self.max_entries {
                if let Some(victim) = guard
                    .iter()
                    .min_by_key(|(_, (_, ts))| *ts)
                    .map(|(k, _)| *k)
                {
                    guard.remove(&victim);
                }
            }
        }
        guard.insert(ip, (domain, now));
    }

    fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.lookup_at(ip, now_secs())
    }

    fn lookup_at(&self, ip: IpAddr, now: u64) -> Option<String> {
        self.map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ip)
            .and_then(|(domain, ts)| {
                (now.saturating_sub(*ts) < REVERSE_DNS_TTL_SECS).then(|| domain.clone())
            })
    }

    fn should_desync_dst(&self, ip: IpAddr, ctx: &EngineContext) -> bool {
        self.should_desync_dst_at(ip, ctx, now_secs())
    }

    fn should_desync_dst_at(&self, ip: IpAddr, ctx: &EngineContext, now: u64) -> bool {
        let guard = self
            .map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let known_host = guard.get(&ip).and_then(|(domain, ts)| {
            (now.saturating_sub(*ts) < REVERSE_DNS_TTL_SECS).then_some(domain.as_str())
        });
        ctx.bypass.should_desync(known_host, Some(ip))
    }
}

/// Lock-free per-second counter capping synthesized QUIC ICMP rejects to <= 64/sec.
struct IcmpRateLimiter {
    epoch: Instant,
    /// Packed `(window_sec << 16) | (count & 0xffff)`.
    state: AtomicU64,
    max_per_sec: u64,
}

impl IcmpRateLimiter {
    fn new(max_per_sec: u64) -> Self {
        Self {
            epoch: Instant::now(),
            state: AtomicU64::new(0),
            max_per_sec: max_per_sec.min(0xffff),
        }
    }

    fn allow(&self) -> bool {
        if self.max_per_sec == 0 {
            return false;
        }
        let now_sec = self.epoch.elapsed().as_secs();
        loop {
            let prev = self.state.load(Ordering::Relaxed);
            let prev_sec = prev >> 16;
            let prev_count = prev & 0xffff;
            let next_count = if prev_sec == now_sec {
                if prev_count >= self.max_per_sec {
                    return false;
                }
                prev_count + 1
            } else {
                1
            };
            let next = (now_sec << 16) | next_count;
            if self
                .state
                .compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }
}

/// Bounded TTL cache of `(src_addr, dst_addr)` UDP/443 flows authenticated by an
/// RFC 5389 STUN or DTLS 1.0/1.2/1.3 record, allowing subsequent WebRTC TURN ChannelData,
/// RFC 9147 DTLS 1.3 unified-header ciphertext, and SRTP datagrams on the same 4-tuple
/// to pass through QUIC UDP/443 blocking.
#[derive(Debug, Default)]
struct StunFlowCache {
    entries: HashMap<(SocketAddr, SocketAddr), u64>,
}

impl StunFlowCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn record(&mut self, flow: (SocketAddr, SocketAddr), now: u64) {
        if self.entries.len() >= STUN_FLOW_MAX_ENTRIES && !self.entries.contains_key(&flow) {
            self.entries
                .retain(|_, ts| now.saturating_sub(*ts) < STUN_FLOW_TTL_SECS);
            if self.entries.len() >= STUN_FLOW_MAX_ENTRIES {
                if let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| *k)
                {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(flow, now);
    }

    fn is_authenticated_and_refresh(&mut self, flow: (SocketAddr, SocketAddr), now: u64) -> bool {
        if let Some(ts) = self.entries.get_mut(&flow) {
            if now.saturating_sub(*ts) < STUN_FLOW_TTL_SECS {
                *ts = now;
                return true;
            }
            self.entries.remove(&flow);
        }
        false
    }
}

/// Thread-safe wrapper around [`StunFlowCache`] shared between TUN ingress (`tun_to_stack`)
/// and Cone-NAT UDP reply reader tasks so inbound UDP/443 replies refresh active WebRTC/Discord
/// flows even while the local client is muted / listen-only.
#[derive(Debug, Default)]
struct SharedStunFlowCache {
    inner: RwLock<StunFlowCache>,
}

impl SharedStunFlowCache {
    fn new() -> Self {
        Self {
            inner: RwLock::new(StunFlowCache::new()),
        }
    }

    fn record(&self, flow: (SocketAddr, SocketAddr), now: u64) {
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(flow, now);
    }

    fn is_authenticated_and_refresh(&self, flow: (SocketAddr, SocketAddr), now: u64) -> bool {
        {
            let guard = self
                .inner
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.entries.get(&flow) {
                None => return false,
                Some(&ts) if ts == now => return true,
                _ => {}
            }
        }
        self.inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_authenticated_and_refresh(flow, now)
    }

    fn refresh_on_inbound_reply(
        &self,
        local_client: SocketAddr,
        remote_peer: SocketAddr,
        payload: &[u8],
        now: u64,
    ) {
        if remote_peer.port() != 443 {
            return;
        }
        let flow = (local_client, remote_peer);
        if is_stun_packet(payload) || is_dtls_packet(payload) {
            let needs_write = {
                let guard = self
                    .inner
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                guard.entries.get(&flow).copied() != Some(now)
            };
            if needs_write {
                self.record(flow, now);
            }
            return;
        }
        let _ = self.is_authenticated_and_refresh(flow, now);
    }
}

#[derive(Debug, Clone, Copy)]
struct UdpBypassCacheEntry {
    bypass: bool,
    cached_at: Instant,
    ttl: Duration,
}

impl UdpBypassCacheEntry {
    #[inline]
    fn is_fresh(self, now: Instant) -> bool {
        now.saturating_duration_since(self.cached_at) < self.ttl
    }
}

enum UdpBypassLookupState {
    Hit(bool),
    Start(watch::Sender<Option<bool>>),
    InFlight(watch::Receiver<Option<bool>>),
    Saturated,
}

/// Thread-safe, non-blocking TTL cache of UDP app-bypass verdicts keyed by `(src_ip, src_port)`
/// with per-key in-flight deduplication. `tun_to_stack` ONLY performs a fast read-only `peek`;
/// cache misses offload `AppBypassHook::should_bypass` to `tokio::task::spawn_blocking` so OS
/// socket-table scans (Win32 `GetExtendedUdpTable` / macOS `lsof`) never stall TUN demuxing.
type InFlightBypassMap = HashMap<(IpAddr, u16), watch::Receiver<Option<bool>>>;

#[derive(Debug, Default)]
struct UdpAppBypassCache {
    entries: RwLock<HashMap<(IpAddr, u16), UdpBypassCacheEntry>>,
    in_flight: Mutex<InFlightBypassMap>,
}

impl UdpAppBypassCache {
    fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    fn peek(&self, src_ip: IpAddr, src_port: u16, now: Instant) -> Option<bool> {
        let key = (src_ip, src_port);
        let guard = self
            .entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .get(&key)
            .copied()
            .filter(|entry| entry.is_fresh(now))
            .map(|entry| entry.bypass)
    }

    /// Caches a resolved app-bypass verdict. Verdicts matching `default_unknown_verdict`
    /// (`split_tunnel.should_bypass_app(None)`) may come from an unresolved racing socket
    /// (e.g., `bypass=false` in Exclude mode or `bypass=true` in Include mode) and use the
    /// shorter 500ms TTL; verdicts opposing `default_unknown_verdict` are guaranteed explicit
    /// listed-app matches and use the 3s TTL.
    fn insert(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        bypass: bool,
        default_unknown_verdict: bool,
        now: Instant,
    ) {
        let ttl = if bypass != default_unknown_verdict {
            UDP_APP_BYPASS_POSITIVE_TTL
        } else {
            UDP_APP_BYPASS_NEGATIVE_TTL
        };
        self.insert_with_ttl(src_ip, src_port, bypass, ttl, now);
    }

    fn insert_unknown(&self, src_ip: IpAddr, src_port: u16, fallback_bypass: bool, now: Instant) {
        self.insert_with_ttl(
            src_ip,
            src_port,
            fallback_bypass,
            UDP_APP_BYPASS_NEGATIVE_TTL,
            now,
        );
    }

    fn insert_with_ttl(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        bypass: bool,
        ttl: Duration,
        now: Instant,
    ) {
        let key = (src_ip, src_port);
        let mut guard = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= UDP_APP_BYPASS_CACHE_MAX_ENTRIES && !guard.contains_key(&key) {
            guard.retain(|_, entry| entry.is_fresh(now));
            if guard.len() >= UDP_APP_BYPASS_CACHE_MAX_ENTRIES {
                if let Some(oldest) = guard
                    .iter()
                    .min_by_key(|(_, entry)| entry.cached_at)
                    .map(|(k, _)| *k)
                {
                    guard.remove(&oldest);
                }
            }
        }
        guard.insert(
            key,
            UdpBypassCacheEntry {
                bypass,
                cached_at: now,
                ttl,
            },
        );
    }

    fn begin_lookup(&self, src_ip: IpAddr, src_port: u16, now: Instant) -> UdpBypassLookupState {
        let key = (src_ip, src_port);
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rx) = in_flight.get(&key) {
            return UdpBypassLookupState::InFlight(rx.clone());
        }
        if let Some(bypass) = self.peek(src_ip, src_port, now) {
            return UdpBypassLookupState::Hit(bypass);
        }
        if in_flight.len() >= MAX_APP_BYPASS_INFLIGHT {
            return UdpBypassLookupState::Saturated;
        }
        let (tx, rx) = watch::channel(None);
        in_flight.insert(key, rx);
        UdpBypassLookupState::Start(tx)
    }

    fn finish_lookup(&self, src_ip: IpAddr, src_port: u16) {
        let key = (src_ip, src_port);
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&key);
    }
}

/// RAII guard ensuring a key is always removed from `UdpAppBypassCache::in_flight` even if
/// the spawned lookup task is aborted on shutdown or panics.
struct InFlightBypassGuard {
    cache: Arc<UdpAppBypassCache>,
    src_ip: IpAddr,
    src_port: u16,
    tx: Option<watch::Sender<Option<bool>>>,
}

impl InFlightBypassGuard {
    fn new(
        cache: Arc<UdpAppBypassCache>,
        src_ip: IpAddr,
        src_port: u16,
        tx: watch::Sender<Option<bool>>,
    ) -> Self {
        Self {
            cache,
            src_ip,
            src_port,
            tx: Some(tx),
        }
    }

    fn complete(mut self, bypass: bool) {
        self.cache.finish_lookup(self.src_ip, self.src_port);
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(bypass));
        }
    }
}

impl Drop for InFlightBypassGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            self.cache.finish_lookup(self.src_ip, self.src_port);
            drop(tx);
        }
    }
}

/// Batches UDP telemetry byte counter updates (64 KiB threshold or periodic flush)
/// instead of issuing per-datagram atomic `fetch_add` ops under high PPS loads.
/// Flushes immediately on the first datagram and on `Drop`.
struct UdpByteBatcher {
    telemetry: Arc<EngineTelemetry>,
    pending_tx: u64,
    pending_rx: u64,
    last_flush_sec: u64,
    flushed_once: bool,
}

impl UdpByteBatcher {
    fn new(telemetry: Arc<EngineTelemetry>) -> Self {
        Self {
            telemetry,
            pending_tx: 0,
            pending_rx: 0,
            last_flush_sec: now_secs(),
            flushed_once: false,
        }
    }

    #[cfg(test)]
    fn new_at(telemetry: Arc<EngineTelemetry>, now_sec: u64) -> Self {
        Self {
            telemetry,
            pending_tx: 0,
            pending_rx: 0,
            last_flush_sec: now_sec,
            flushed_once: false,
        }
    }

    #[inline]
    fn has_pending(&self) -> bool {
        self.pending_tx > 0 || self.pending_rx > 0
    }

    #[inline]
    fn record_tx(&mut self, bytes: u64, now_sec: u64) {
        if bytes == 0 {
            return;
        }
        self.pending_tx = self.pending_tx.saturating_add(bytes);
        if !self.flushed_once
            || self.pending_tx >= UDP_TELEMETRY_BATCH_BYTES
            || now_sec.saturating_sub(self.last_flush_sec) >= UDP_TELEMETRY_FLUSH_INTERVAL_SECS
        {
            self.flush(now_sec);
        }
    }

    #[inline]
    fn record_rx(&mut self, bytes: u64, now_sec: u64) {
        if bytes == 0 {
            return;
        }
        self.pending_rx = self.pending_rx.saturating_add(bytes);
        if !self.flushed_once
            || self.pending_rx >= UDP_TELEMETRY_BATCH_BYTES
            || now_sec.saturating_sub(self.last_flush_sec) >= UDP_TELEMETRY_FLUSH_INTERVAL_SECS
        {
            self.flush(now_sec);
        }
    }

    #[inline]
    fn flush(&mut self, now_sec: u64) {
        if self.pending_tx > 0 {
            let n = std::mem::take(&mut self.pending_tx);
            self.telemetry.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
        if self.pending_rx > 0 {
            let n = std::mem::take(&mut self.pending_rx);
            self.telemetry.bytes_rx.fetch_add(n, Ordering::Relaxed);
        }
        self.last_flush_sec = now_sec;
        self.flushed_once = true;
    }
}

impl Drop for UdpByteBatcher {
    fn drop(&mut self) {
        if self.pending_tx > 0 {
            let n = std::mem::take(&mut self.pending_tx);
            self.telemetry.bytes_tx.fetch_add(n, Ordering::Relaxed);
        }
        if self.pending_rx > 0 {
            let n = std::mem::take(&mut self.pending_rx);
            self.telemetry.bytes_rx.fetch_add(n, Ordering::Relaxed);
        }
    }
}

#[inline]
fn is_fast_tcp_packet(pkt: &[u8]) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => pkt.len() >= 20 && pkt[9] == 6,
        Some(6) => {
            if pkt.len() < 40 {
                return false;
            }
            if pkt[6] == 6 {
                return true;
            }
            ipv6_tcp_payload(pkt).is_some()
        }
        _ => false,
    }
}

#[inline]
fn is_ipv6_tcp_port_53(pkt: &[u8]) -> bool {
    let Some(tcp) = ipv6_tcp_payload(pkt) else {
        return false;
    };
    tcp.len() >= 4 && u16::from_be_bytes([tcp[2], tcp[3]]) == 53
}

#[inline]
fn passthrough_copy_buf_size(buf_size: usize) -> usize {
    buf_size.clamp(MIN_PASSTHROUGH_COPY_BUF, MAX_PASSTHROUGH_COPY_BUF)
}

fn tune_upstream_tcp_socket(
    stream: &tokio::net::TcpStream,
    recv_buf_bytes: usize,
    send_buf_bytes: usize,
) {
    let _ = stream.set_nodelay(true);
    // On Windows, calling post-connect SO_RCVBUF / SO_SNDBUF disables TCP Receive Window
    // Auto-Tuning and caps single-stream gigabit throughput on 50ms+ RTT links. Keep
    // `TCP_NODELAY` (and keepalive set during connect) intact while letting Windows auto-tune.
    #[cfg(windows)]
    let _ = (recv_buf_bytes, send_buf_bytes);
    #[cfg(not(windows))]
    {
        // Only enlarge kernel TCP socket buffers on desktop-class profiles (>= 256 KiB) so
        // mobile/LOW_MEMORY profiles never shrink OS auto-tuned receive/send buffers.
        if recv_buf_bytes >= TCP_KERNEL_BUF_MIN_OPT_BYTES
            || send_buf_bytes >= TCP_KERNEL_BUF_MIN_OPT_BYTES
        {
            let sock_ref = socket2::SockRef::from(stream);
            if recv_buf_bytes >= TCP_KERNEL_BUF_MIN_OPT_BYTES {
                let _ = sock_ref.set_recv_buffer_size(recv_buf_bytes);
            }
            if send_buf_bytes >= TCP_KERNEL_BUF_MIN_OPT_BYTES {
                let _ = sock_ref.set_send_buffer_size(send_buf_bytes);
            }
        }
    }
}

struct UdpNatEntry {
    socket: Arc<UdpSocket>,
    last_active_secs: Arc<AtomicU64>,
    last_seq: Arc<AtomicU64>,
    abort: AbortHandle,
}

type UdpNatTable = Arc<RwLock<HashMap<(SocketAddr, bool), UdpNatEntry>>>;

fn now_secs() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs()
}

pub(crate) async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

fn bind_udp_socket_strict(
    ctx: &EngineContext,
    is_ipv4: bool,
    buf_bytes: usize,
) -> std::io::Result<UdpSocket> {
    ctx.bind_outbound_udp(is_ipv4, buf_bytes)
}

fn store_udp_flows_active(count: u64, stats: &TunStats, ctx: &EngineContext) {
    stats.udp_flows_active.store(count, Ordering::Relaxed);
    ctx.telemetry
        .udp_flows_active
        .store(count, Ordering::Relaxed);
}

fn drain_udp_nat(
    udp_nat: &UdpNatTable,
    route_gen: &AtomicU64,
    stats: &TunStats,
    ctx: &EngineContext,
) -> usize {
    let mut guard = udp_nat
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    route_gen.fetch_add(1, Ordering::AcqRel);
    let drained = guard.len();
    for (_, entry) in guard.drain() {
        entry.abort.abort();
    }
    store_udp_flows_active(0, stats, ctx);
    drained
}

/// Returns `true` only when a UDP send error indicates the entire outbound interface/route
/// is dead (`ENETUNREACH` / Windows `10051`). Single-peer `EHOSTUNREACH` / `EINVAL`
/// (Windows `10022` / `10065`) must NOT evict the shared Cone-NAT UDP socket.
fn is_fatal_udp_send_error(err: &std::io::Error) -> bool {
    if err.kind() == ErrorKind::NetworkUnreachable {
        return true;
    }
    #[cfg(unix)]
    if err.raw_os_error() == Some(libc::ENETUNREACH) {
        return true;
    }
    #[cfg(windows)]
    if err.raw_os_error() == Some(10051) {
        return true;
    }
    false
}

#[inline]
fn is_unroutable_udp_dst(dst_addr: SocketAddr) -> bool {
    if dst_addr.port() == 0 {
        return true;
    }
    match dst_addr.ip() {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn is_ipv6_unreachable_error(err: &std::io::Error) -> bool {
    if err.kind() == ErrorKind::NetworkUnreachable {
        return true;
    }
    #[cfg(unix)]
    if matches!(
        err.raw_os_error(),
        Some(libc::ENETUNREACH | libc::EAFNOSUPPORT | libc::EADDRNOTAVAIL)
    ) {
        return true;
    }
    #[cfg(windows)]
    if matches!(err.raw_os_error(), Some(10047 | 10049 | 10051)) {
        return true;
    }
    false
}

fn is_outbound_ipv6_unavailable(ctx: &EngineContext) -> bool {
    match bind_udp_socket_strict(ctx, false, 0) {
        Ok(_) => false,
        Err(err) => is_ipv6_unreachable_error(&err),
    }
}

/// Detects S3 sleep/wake transitions by checking whether wall-clock `SystemTime` jumped
/// ahead of monotonic `Instant` by more than `SLEEP_WAKE_DRIFT_THRESHOLD` (15s).
fn detect_sleep_wake_jump(
    prev_wall: SystemTime,
    curr_wall: SystemTime,
    prev_mono: Instant,
    curr_mono: Instant,
) -> Option<Duration> {
    let wall_delta = curr_wall.duration_since(prev_wall).ok()?;
    let mono_delta = curr_mono.saturating_duration_since(prev_mono);
    let drift = wall_delta.checked_sub(mono_delta)?;
    (drift > SLEEP_WAKE_DRIFT_THRESHOLD).then_some(drift)
}

#[inline]
fn try_emit_icmpv6_no_route(
    invoking_pkt: &[u8],
    limiter: &IcmpRateLimiter,
    outbound_tx: &mpsc::Sender<Vec<u8>>,
) {
    if limiter.allow() {
        if let Some(icmp_pkt) = build_icmpv6_no_route(invoking_pkt) {
            let _ = outbound_tx.try_send(icmp_pkt);
        }
    }
}

#[inline]
fn maybe_handle_ipv6_udp_unreachable(
    dst_addr: SocketAddr,
    err: &std::io::Error,
    invoking_v6_pkt: Option<&[u8]>,
    ipv6_unavailable: &AtomicBool,
    icmp_no_route_limiter: &IcmpRateLimiter,
    outbound_tx: &mpsc::Sender<Vec<u8>>,
) {
    if !dst_addr.is_ipv4() && is_ipv6_unreachable_error(err) {
        ipv6_unavailable.store(true, Ordering::Relaxed);
        if let Some(raw_pkt) = invoking_v6_pkt {
            try_emit_icmpv6_no_route(raw_pkt, icmp_no_route_limiter, outbound_tx);
        }
    }
}

/// Fair UDP burst quota for `run_priority_tun_writer`: voice/game UDP replies
/// immediately preempt bulk TCP up to this many consecutive packets before
/// yielding at least 1 queued TCP segment so sustained heavy UDP floods
/// (unblocked QUIC / uTP) can never starve TCP ACKs.
const MAX_CONSECUTIVE_UDP_PACKETS: usize = 16;

/// Priority TUN egress multiplexer: drains `udp_outbound_rx` (UDP Cone-NAT replies,
/// DNS replies, ICMP rejects) ahead of bulk TCP segments on `tcp_outbound_rx` using
/// `biased; tokio::select!`, acquiring a downstream `outbound_tx` permit first via
/// pure event-driven `outbound_tx.reserve().await` backpressure (zero timer-wheel
/// sleeps) so 1 Gbps TCP downloads run at full line rate while keeping strict UDP
/// preemption bounded by `outbound_tx`'s channel capacity. Enforces a fair UDP burst
/// quota (`MAX_CONSECUTIVE_UDP_PACKETS`) so sustained UDP floods yield at least 1
/// queued TCP packet every 16 UDP packets and can never starve TCP ACKs.
/// Returns `true` if downstream `outbound_tx` closed unexpectedly (not due to shutdown).
async fn run_priority_tun_writer(
    mut udp_outbound_rx: mpsc::Receiver<Vec<u8>>,
    mut tcp_outbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> bool {
    let mut udp_open = true;
    let mut tcp_open = true;
    let mut consecutive_udp: usize = 0;

    while udp_open || tcp_open {
        let permit = tokio::select! {
            biased;
            _ = wait_shutdown(shutdown_rx) => return false,
            res = outbound_tx.reserve() => match res {
                Ok(permit) => permit,
                Err(_) => return true,
            },
        };

        // Fair UDP burst quota: after MAX_CONSECUTIVE_UDP_PACKETS uninterrupted
        // UDP packets, yield 1 queued TCP packet if ready so sustained UDP floods
        // (unblocked QUIC / uTP) can never starve TCP ACKs.
        if udp_open && tcp_open && consecutive_udp >= MAX_CONSECUTIVE_UDP_PACKETS {
            match tcp_outbound_rx.try_recv() {
                Ok(pkt) => {
                    consecutive_udp = 0;
                    permit.send(pkt);
                    continue;
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    tcp_open = false;
                    consecutive_udp = 0;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        let (pkt, is_udp) = if udp_open {
            match udp_outbound_rx.try_recv() {
                Ok(pkt) => (pkt, true),
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    udp_open = false;
                    consecutive_udp = 0;
                    continue;
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    // UDP queue drained; reset burst counter so the next voice/game
                    // UDP burst gets immediate full preemption quota.
                    consecutive_udp = 0;
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(shutdown_rx) => return false,
                        _ = outbound_tx.closed() => return true,
                        maybe_udp = udp_outbound_rx.recv() => match maybe_udp {
                            Some(pkt) => (pkt, true),
                            None => {
                                udp_open = false;
                                continue;
                            }
                        },
                        maybe_tcp = tcp_outbound_rx.recv(), if tcp_open => match maybe_tcp {
                            Some(pkt) => (pkt, false),
                            None => {
                                tcp_open = false;
                                continue;
                            }
                        },
                    }
                }
            }
        } else {
            tokio::select! {
                biased;
                _ = wait_shutdown(shutdown_rx) => return false,
                _ = outbound_tx.closed() => return true,
                maybe_tcp = tcp_outbound_rx.recv() => match maybe_tcp {
                    Some(pkt) => (pkt, false),
                    None => {
                        tcp_open = false;
                        continue;
                    }
                },
            }
        };

        if is_udp {
            consecutive_udp = consecutive_udp.saturating_add(1);
        } else {
            consecutive_udp = 0;
        }
        permit.send(pkt);
    }
    false
}

fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
    ) {
        return true;
    }
    // Windows WSAEMSGSIZE (10040): datagram larger than recv buffer; drop datagram and continue.
    err.raw_os_error() == Some(10040)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicCheckOutcome {
    Allow,
    Drop,
    DeferAppBypassLookup,
}

fn record_quic_drop(
    pkt: &[u8],
    ctx: &EngineContext,
    stats: &TunStats,
    events: &EventRing,
    icmp_reject: Option<(&IcmpRateLimiter, &mpsc::Sender<Vec<u8>>)>,
) {
    let count = stats.quic_blocked.fetch_add(1, Ordering::Relaxed) + 1;
    ctx.telemetry.quic_blocked.fetch_add(1, Ordering::Relaxed);
    if count == 1 || count.is_multiple_of(50) {
        events.push(
            "debug",
            "quic",
            format!("redirected QUIC UDP/443 to TCP TLS ({count} packets)"),
        );
    }

    if let Some((limiter, out_tx)) = icmp_reject {
        if limiter.allow() {
            if let Some(icmp_pkt) = build_icmp_port_unreachable(pkt) {
                let _ = out_tx.try_send(icmp_pkt);
            }
        }
    }
}

/// Evaluates whether an inbound UDP/443 datagram should be dropped as QUIC, exempting
/// RFC 5389 STUN packets, DTLS 1.0/1.2/1.3 records (recording the flow so subsequent
/// RFC 9147 DTLS 1.3 unified-header ciphertext and SRTP/DTLS packets pass through),
/// subsequent TURN ChannelData / DTLS / SRTP packets on authenticated `(src_addr, dst_addr)`
/// flows, and app-bypassed flows (via fast non-blocking cache peek only).
/// Optionally emits a rate-limited ICMP Port Unreachable reply for sub-50ms browser TCP/TLS fallback.
#[allow(clippy::too_many_arguments)]
fn should_drop_inbound_quic(
    pkt: &[u8],
    udp: &InboundUdpPacket<'_>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    ctx: &EngineContext,
    rdns: &ReverseDnsCache,
    stats: &TunStats,
    events: &EventRing,
    stun_flows: &SharedStunFlowCache,
    app_bypass_cache: &UdpAppBypassCache,
    icmp_reject: Option<(&IcmpRateLimiter, &mpsc::Sender<Vec<u8>>)>,
    has_app_bypass: bool,
) -> QuicCheckOutcome {
    if udp.dst_port != 443 {
        return QuicCheckOutcome::Allow;
    }
    let now = now_secs();
    if is_stun_packet(udp.payload) {
        stun_flows.record((src_addr, dst_addr), now);
        return QuicCheckOutcome::Allow;
    }
    if stun_flows.is_authenticated_and_refresh((src_addr, dst_addr), now) {
        return QuicCheckOutcome::Allow;
    }
    if is_dtls_packet(udp.payload) {
        stun_flows.record((src_addr, dst_addr), now);
        return QuicCheckOutcome::Allow;
    }
    if !ctx.config.block_quic || !is_blocked_quic_udp(udp.dst_port, udp.payload) {
        return QuicCheckOutcome::Allow;
    }
    if !rdns.should_desync_dst(udp.dst_ip, ctx) {
        return QuicCheckOutcome::Allow;
    }
    if has_app_bypass {
        match app_bypass_cache.peek(udp.src_ip, udp.src_port, Instant::now()) {
            Some(true) => return QuicCheckOutcome::Allow,
            Some(false) => {}
            None => return QuicCheckOutcome::DeferAppBypassLookup,
        }
    }

    record_quic_drop(pkt, ctx, stats, events, icmp_reject);
    QuicCheckOutcome::Drop
}

/// Runs the pure-Rust userspace TUN packet pipeline (TCP via `vdpi_core` 7-stage desync + TCP/53 DNS,
/// zero-lag raw UDP/53 DNS interception via `vdpi_core` DoH ring, QUIC UDP/443 fallback with
/// STUN/TURN exemption, and direct Cone-NAT UDP relay).
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_pipeline(
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    run_tun_pipeline_with_route_watch(
        inbound_rx,
        outbound_tx,
        ctx,
        tun_stats,
        events,
        mtu,
        profile,
        shutdown_rx,
        None,
    )
    .await
}

/// Runs the userspace TUN packet pipeline with an optional route-change watch receiver.
/// Whenever `route_rx` fires (e.g. Wi-Fi <-> Ethernet uplink switch), all active UDP Cone-NAT
/// sockets are drained and aborted so subsequent datagrams immediately rebind to the new uplink.
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_pipeline_with_route_watch(
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
    route_rx: Option<watch::Receiver<u64>>,
) -> Result<()> {
    run_tun_pipeline_with_app_bypass(
        inbound_rx,
        outbound_tx,
        ctx,
        tun_stats,
        events,
        mtu,
        profile,
        shutdown_rx,
        route_rx,
        None,
    )
    .await
}

/// Runs the userspace TUN packet pipeline with optional route-change watching and an optional
/// per-flow [`AppBypassHook`] callback for desktop per-app split tunneling.
/// When `app_bypass` is `None`, behavior and hot-path overhead are identical to
/// [`run_tun_pipeline_with_route_watch`].
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_pipeline_with_app_bypass(
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
    mut route_rx: Option<watch::Receiver<u64>>,
    app_bypass: Option<AppBypassHook>,
) -> Result<()> {
    let clamped_mtu = mtu.clamp(MIN_MTU, MAX_MTU);

    // Internal stop signal fires whenever either the caller requests shutdown OR any core
    // pipeline task exits unexpectedly, preventing silent zombie tunnels.
    let (internal_stop_tx, mut internal_stop_rx) = watch::channel(false);
    let mut external_stop = shutdown_rx.clone();
    let bridge_stop_tx = internal_stop_tx.clone();
    let stop_bridge = tokio::spawn(async move {
        wait_shutdown(&mut external_stop).await;
        let _ = bridge_stop_tx.send(true);
    });

    // Dedicated bounded TCP ingress queue; `tun_to_stack` uses non-blocking `try_send`
    // so smoltcp TCP backpressure never freezes zero-lag DNS/UDP demuxing (TCP retransmits).
    let (tcp_in_tx, tcp_in_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity.max(64));

    // Dedicated priority egress queues: low-latency UDP/DNS/ICMP replies travel over
    // `udp_outbound_tx` (bounded by `profile.udp_reply_capacity`) and are drained strictly
    // ahead of bulk TCP segments on `tcp_outbound_tx` in the TUN writer multiplexer.
    let (tcp_outbound_tx, tcp_outbound_rx) =
        mpsc::channel::<Vec<u8>>(profile.channel_capacity.max(64));
    let (udp_outbound_tx, udp_outbound_rx) =
        mpsc::channel::<Vec<u8>>(profile.udp_reply_capacity.max(1));

    let mut stop_writer = internal_stop_rx.clone();
    let writer_stop_tx = internal_stop_tx.clone();
    let outbound_writer_task = tokio::spawn(async move {
        if run_priority_tun_writer(
            udp_outbound_rx,
            tcp_outbound_rx,
            outbound_tx,
            &mut stop_writer,
        )
        .await
        {
            let _ = writer_stop_tx.send(true);
        }
    });

    let (mut tcp_stream_rx, netstack_handle) = spawn_tcp_netstack(
        tcp_in_rx,
        tcp_outbound_tx,
        clamped_mtu,
        profile.tcp_recv_buffer_size as usize,
        profile.tcp_send_buffer_size as usize,
        profile.max_tcp_sessions,
        profile.channel_capacity.clamp(128, 4096),
        internal_stop_rx.clone(),
    )
    .context("failed to build smoltcp netstack")?;

    let runner_stop_tx = internal_stop_tx.clone();
    let runner_handle = tokio::spawn(async move {
        let _ = netstack_handle.await;
        let _ = runner_stop_tx.send(true);
    });

    let reverse_dns = Arc::new(ReverseDnsCache::new(profile.max_reverse_dns_entries));
    let tcp_slots = Arc::new(Semaphore::new(profile.max_tcp_sessions));
    let dns_slots = Arc::new(Semaphore::new(profile.max_dns_inflight));
    let udp_slow_slots = Arc::new(Semaphore::new(profile.max_udp_flows.max(16)));
    let udp_nat: UdpNatTable = Arc::new(RwLock::new(HashMap::new()));
    let udp_lru_seq = Arc::new(AtomicU64::new(0));
    let route_gen = Arc::new(AtomicU64::new(0));
    let observed_stage = Arc::new(AtomicU8::new(ctx.preferred_stage() as u8));
    let stun_flows = Arc::new(SharedStunFlowCache::new());
    let udp_app_bypass_cache = Arc::new(UdpAppBypassCache::new());
    let ipv6_unavailable = Arc::new(AtomicBool::new(is_outbound_ipv6_unavailable(&ctx)));
    let icmp_no_route_limiter = Arc::new(IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC));
    let quic_icmp_limiter = Arc::new(IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC));

    // Task 1: Zero-lag TUN ingress demux — inspect UDP ONCE and bypass smoltcp completely
    // for DNS/53, QUIC/443 (with STUN/TURN/DTLS pass-through), and Cone-NAT UDP; hand TCP
    // packets to smoltcp via non-blocking `try_send` so TCP congestion never stalls DNS/UDP.
    let in_ctx = ctx.clone();
    let in_rdns = Arc::clone(&reverse_dns);
    let in_stats = Arc::clone(&tun_stats);
    let in_events = Arc::clone(&events);
    let in_udp_outbound_tx = udp_outbound_tx;
    let in_dns_slots = Arc::clone(&dns_slots);
    let in_udp_slow_slots = Arc::clone(&udp_slow_slots);
    let in_udp_nat = Arc::clone(&udp_nat);
    let in_udp_lru_seq = Arc::clone(&udp_lru_seq);
    let in_route_gen = Arc::clone(&route_gen);
    let in_stun_flows = Arc::clone(&stun_flows);
    let in_app_bypass_cache = Arc::clone(&udp_app_bypass_cache);
    let in_ipv6_unavailable = Arc::clone(&ipv6_unavailable);
    let in_icmp_no_route_limiter = Arc::clone(&icmp_no_route_limiter);
    let in_quic_icmp_limiter = Arc::clone(&quic_icmp_limiter);
    let in_app_bypass = app_bypass.clone();
    let in_stop_root = internal_stop_rx.clone();
    let emit_quic_icmp_reject = profile.emit_quic_icmp_reject;
    let max_udp_flows = profile.max_udp_flows;
    let udp_socket_buf_bytes = profile.udp_socket_buf_bytes;
    let demux_batch_size = profile.batch_size.max(1);
    let mut stop_in = internal_stop_rx.clone();
    let in_stop_tx = internal_stop_tx.clone();
    let tun_to_stack = tokio::spawn(async move {
        let mut udp_tx_batcher = UdpByteBatcher::new(Arc::clone(&in_ctx.telemetry));
        let tx_flush_sleep =
            tokio::time::sleep(Duration::from_secs(UDP_TELEMETRY_FLUSH_INTERVAL_SECS));
        tokio::pin!(tx_flush_sleep);
        let mut tx_flush_armed = false;
        let mut pkt_batch: Vec<Vec<u8>> = Vec::with_capacity(demux_batch_size);
        'demux: loop {
            if udp_tx_batcher.has_pending() && !tx_flush_armed {
                tx_flush_sleep.as_mut().reset(
                    tokio::time::Instant::now()
                        + Duration::from_secs(UDP_TELEMETRY_FLUSH_INTERVAL_SECS),
                );
                tx_flush_armed = true;
            } else if !udp_tx_batcher.has_pending() {
                tx_flush_armed = false;
            }

            let received = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_in) => break,
                n = inbound_rx.recv_many(&mut pkt_batch, demux_batch_size) => n,
                _ = &mut tx_flush_sleep, if tx_flush_armed => {
                    udp_tx_batcher.flush(now_secs());
                    tx_flush_armed = false;
                    continue;
                }
            };
            if received == 0 {
                let _ = in_stop_tx.send(true);
                break;
            }

            for pkt in pkt_batch.drain(..) {
                // Hot-path shortcut: IPv4/IPv6 TCP frames bypass UDP header inspection completely.
                if is_fast_tcp_packet(&pkt) {
                    if pkt[0] >> 4 == 6
                        && in_ipv6_unavailable.load(Ordering::Relaxed)
                        && !is_ipv6_tcp_port_53(&pkt)
                    {
                        try_emit_icmpv6_no_route(
                            &pkt,
                            &in_icmp_no_route_limiter,
                            &in_udp_outbound_tx,
                        );
                        continue;
                    }
                    match tcp_in_tx.try_send(pkt) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // Never block `tun_to_stack` on TCP backpressure: TCP retransmits,
                            // whereas blocking here freezes DNS and UDP across the entire OS.
                            in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            let _ = in_stop_tx.send(true);
                            break 'demux;
                        }
                    }
                    continue;
                }

                if let Some(udp) = inspect_inbound_udp(&pkt) {
                    let src_addr = SocketAddr::new(udp.src_ip, udp.src_port);
                    let dst_addr = SocketAddr::new(udp.dst_ip, udp.dst_port);

                    // 1. UDP/53 DNS -> bounded DoH handler synthesizing raw IP+UDP reply onto udp_outbound_tx
                    if udp.dst_port == 53 {
                        let Ok(permit) = in_dns_slots.clone().try_acquire_owned() else {
                            in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                            continue;
                        };
                        let query = udp.payload.to_vec();
                        let dns_ctx = in_ctx.clone();
                        let rdns = Arc::clone(&in_rdns);
                        let reply_out_tx = in_udp_outbound_tx.clone();
                        let mut dns_stop = in_stop_root.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut dns_stop) => {}
                                res = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    dns_ctx.dns.resolve_wire_query(&query, dns_ctx.config.block_quic),
                                ) => {
                                    match res {
                                        Ok(Ok((resp, meta))) => {
                                            if let Some((domain, ips)) = meta {
                                                for ip in ips {
                                                    rdns.insert(ip, domain.clone());
                                                }
                                            }
                                            let max_udp = max_dns_udp_payload_for_mtu(clamped_mtu, dst_addr.is_ipv4());
                                            let wire = if resp.len() > max_udp {
                                                build_truncated_dns_reply(&query, &resp)
                                            } else {
                                                resp
                                            };
                                            if let Some(reply_pkt) = build_udp_packet(dst_addr, src_addr, &wire) {
                                                tokio::select! {
                                                    biased;
                                                    _ = wait_shutdown(&mut dns_stop) => {}
                                                    _ = reply_out_tx.send(reply_pkt) => {}
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            debug!(error = %e, "TUN DNS wire query failed");
                                        }
                                        Err(_) => {
                                            debug!("TUN UDP/53 DNS wire query timed out (5s)");
                                        }
                                    }
                                }
                            }
                        });
                        continue;
                    }

                    // 1.5. When outbound IPv6 is unavailable, emit ICMPv6 No Route so apps
                    //      immediately Happy-Eyeballs fall back to IPv4 without stalling.
                    if !dst_addr.is_ipv4() && in_ipv6_unavailable.load(Ordering::Relaxed) {
                        try_emit_icmpv6_no_route(
                            &pkt,
                            &in_icmp_no_route_limiter,
                            &in_udp_outbound_tx,
                        );
                        continue;
                    }

                    // 2. UDP/443 QUIC block (exempting RFC 5389 STUN, DTLS, and authenticated TURN/DTLS/SRTP flows)
                    let icmp_reject = emit_quic_icmp_reject
                        .then_some((in_quic_icmp_limiter.as_ref(), &in_udp_outbound_tx));
                    match should_drop_inbound_quic(
                        &pkt,
                        &udp,
                        src_addr,
                        dst_addr,
                        &in_ctx,
                        &in_rdns,
                        &in_stats,
                        &in_events,
                        &in_stun_flows,
                        &in_app_bypass_cache,
                        icmp_reject,
                        in_app_bypass.is_some(),
                    ) {
                        QuicCheckOutcome::Drop => continue,
                        QuicCheckOutcome::Allow => {}
                        QuicCheckOutcome::DeferAppBypassLookup => {
                            if let Some(hook) = in_app_bypass.clone() {
                                let Ok(permit) = in_udp_slow_slots.clone().try_acquire_owned()
                                else {
                                    in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                    continue;
                                };
                                let src_ip = udp.src_ip;
                                let src_port = udp.src_port;
                                match in_app_bypass_cache.begin_lookup(
                                    src_ip,
                                    src_port,
                                    Instant::now(),
                                ) {
                                    UdpBypassLookupState::Hit(true) => {
                                        drop(permit);
                                    }
                                    UdpBypassLookupState::Hit(false) => {
                                        drop(permit);
                                        record_quic_drop(
                                            &pkt,
                                            &in_ctx,
                                            &in_stats,
                                            &in_events,
                                            icmp_reject,
                                        );
                                        continue;
                                    }
                                    UdpBypassLookupState::Saturated => {
                                        drop(permit);
                                        in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                        continue;
                                    }
                                    ticket @ (UdpBypassLookupState::Start(_)
                                    | UdpBypassLookupState::InFlight(_)) => {
                                        let payload = udp.payload.to_vec();
                                        let cache = Arc::clone(&in_app_bypass_cache);
                                        let nat = Arc::clone(&in_udp_nat);
                                        let lru_seq = Arc::clone(&in_udp_lru_seq);
                                        let slow_route_gen = Arc::clone(&in_route_gen);
                                        let slow_stun_flows = Arc::clone(&in_stun_flows);
                                        let slow_ipv6_unavailable =
                                            Arc::clone(&in_ipv6_unavailable);
                                        let slow_icmp_limiter =
                                            Arc::clone(&in_icmp_no_route_limiter);
                                        let slow_quic_limiter =
                                            Arc::clone(&in_quic_icmp_limiter);
                                        let reply_out_tx = in_udp_outbound_tx.clone();
                                        let udp_ctx = in_ctx.clone();
                                        let udp_stats = Arc::clone(&in_stats);
                                        let udp_events = Arc::clone(&in_events);
                                        let udp_stop_root = in_stop_root.clone();
                                        let mut udp_stop = in_stop_root.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            let bypass = match ticket {
                                                UdpBypassLookupState::Start(tx) => {
                                                    let guard = InFlightBypassGuard::new(
                                                        Arc::clone(&cache),
                                                        src_ip,
                                                        src_port,
                                                        tx,
                                                    );
                                                    let lookup_res = tokio::select! {
                                                        biased;
                                                        _ = wait_shutdown(&mut udp_stop) => return,
                                                        res = tokio::task::spawn_blocking(move || {
                                                            hook.should_bypass(src_ip, src_port, true)
                                                        }) => res,
                                                    };
                                                    let default_unknown_verdict = udp_ctx
                                                        .config
                                                        .split_tunnel
                                                        .should_bypass_app(None);
                                                    let verdict = match lookup_res {
                                                        Ok(v) => {
                                                            cache.insert(
                                                                src_ip,
                                                                src_port,
                                                                v,
                                                                default_unknown_verdict,
                                                                Instant::now(),
                                                            );
                                                            v
                                                        }
                                                        Err(_) => {
                                                            cache.insert_unknown(
                                                                src_ip,
                                                                src_port,
                                                                default_unknown_verdict,
                                                                Instant::now(),
                                                            );
                                                            default_unknown_verdict
                                                        }
                                                    };
                                                    guard.complete(verdict);
                                                    verdict
                                                }
                                                UdpBypassLookupState::InFlight(mut rx) => {
                                                    let wait_res = tokio::select! {
                                                        biased;
                                                        _ = wait_shutdown(&mut udp_stop) => return,
                                                        res = rx.wait_for(|v| v.is_some()) => {
                                                            res.ok().and_then(|v| *v)
                                                        }
                                                    };
                                                    match wait_res {
                                                        Some(v) => v,
                                                        None => cache
                                                            .peek(src_ip, src_port, Instant::now())
                                                            .unwrap_or_else(|| {
                                                                udp_ctx
                                                                    .config
                                                                    .split_tunnel
                                                                    .should_bypass_app(None)
                                                            }),
                                                    }
                                                }
                                                UdpBypassLookupState::Hit(_)
                                                | UdpBypassLookupState::Saturated => unreachable!(),
                                            };

                                            if !bypass {
                                                let deferred_icmp = emit_quic_icmp_reject
                                                    .then_some((
                                                        slow_quic_limiter.as_ref(),
                                                        &reply_out_tx,
                                                    ));
                                                record_quic_drop(
                                                    &pkt,
                                                    &udp_ctx,
                                                    &udp_stats,
                                                    &udp_events,
                                                    deferred_icmp,
                                                );
                                                return;
                                            }

                                            match try_forward_udp_fast(
                                                &payload,
                                                src_addr,
                                                dst_addr,
                                                &nat,
                                                &lru_seq,
                                                &udp_ctx,
                                                &udp_stats,
                                                max_udp_flows,
                                            ) {
                                                UdpFastPath::Sent(bytes) => {
                                                    udp_ctx.add_udp_bytes(bytes as u64, 0);
                                                }
                                                UdpFastPath::Done => {}
                                                UdpFastPath::Ipv6Unreachable => {
                                                    slow_ipv6_unavailable
                                                        .store(true, Ordering::Relaxed);
                                                    try_emit_icmpv6_no_route(
                                                        &pkt,
                                                        &slow_icmp_limiter,
                                                        &reply_out_tx,
                                                    );
                                                }
                                                UdpFastPath::NeedsSlowPath(existing) => {
                                                    let invoking_v6_pkt =
                                                        (!dst_addr.is_ipv4()).then_some(pkt);
                                                    tokio::select! {
                                                        biased;
                                                        _ = wait_shutdown(&mut udp_stop) => {}
                                                        _ = forward_udp_cone_nat_slow(
                                                            payload,
                                                            invoking_v6_pkt,
                                                            src_addr,
                                                            dst_addr,
                                                            existing,
                                                            nat,
                                                            lru_seq,
                                                            slow_route_gen,
                                                            slow_stun_flows,
                                                            slow_ipv6_unavailable,
                                                            slow_icmp_limiter,
                                                            reply_out_tx,
                                                            udp_ctx,
                                                            udp_stats,
                                                            udp_stop_root,
                                                            clamped_mtu,
                                                            max_udp_flows,
                                                            udp_socket_buf_bytes,
                                                        ) => {}
                                                    }
                                                }
                                            }
                                        });
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    // 3. Direct Cone-NAT UDP relay: synchronous non-blocking fast path inline;
                    //    socket bind / WouldBlock slow paths run on bounded spawned tasks so
                    //    UDP bursts never stall DNS or TCP demuxing.
                    match try_forward_udp_fast(
                        udp.payload,
                        src_addr,
                        dst_addr,
                        &in_udp_nat,
                        &in_udp_lru_seq,
                        &in_ctx,
                        &in_stats,
                        max_udp_flows,
                    ) {
                        UdpFastPath::Sent(bytes) => {
                            udp_tx_batcher.record_tx(bytes as u64, now_secs());
                        }
                        UdpFastPath::Done => {}
                        UdpFastPath::Ipv6Unreachable => {
                            in_ipv6_unavailable.store(true, Ordering::Relaxed);
                            try_emit_icmpv6_no_route(
                                &pkt,
                                &in_icmp_no_route_limiter,
                                &in_udp_outbound_tx,
                            );
                        }
                        UdpFastPath::NeedsSlowPath(existing) => {
                            let Ok(permit) = in_udp_slow_slots.clone().try_acquire_owned() else {
                                in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            let payload = udp.payload.to_vec();
                            let invoking_v6_pkt = (!dst_addr.is_ipv4()).then_some(pkt);
                            let nat = Arc::clone(&in_udp_nat);
                            let lru_seq = Arc::clone(&in_udp_lru_seq);
                            let slow_route_gen = Arc::clone(&in_route_gen);
                            let slow_stun_flows = Arc::clone(&in_stun_flows);
                            let slow_ipv6_unavailable = Arc::clone(&in_ipv6_unavailable);
                            let slow_icmp_limiter = Arc::clone(&in_icmp_no_route_limiter);
                            let reply_out_tx = in_udp_outbound_tx.clone();
                            let udp_ctx = in_ctx.clone();
                            let udp_stats = Arc::clone(&in_stats);
                            let udp_stop_root = in_stop_root.clone();
                            let mut udp_stop = in_stop_root.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                tokio::select! {
                                    biased;
                                    _ = wait_shutdown(&mut udp_stop) => {}
                                    _ = forward_udp_cone_nat_slow(
                                        payload,
                                        invoking_v6_pkt,
                                        src_addr,
                                        dst_addr,
                                        existing,
                                        nat,
                                        lru_seq,
                                        slow_route_gen,
                                        slow_stun_flows,
                                        slow_ipv6_unavailable,
                                        slow_icmp_limiter,
                                        reply_out_tx,
                                        udp_ctx,
                                        udp_stats,
                                        udp_stop_root,
                                        clamped_mtu,
                                        max_udp_flows,
                                        udp_socket_buf_bytes,
                                    ) => {}
                                }
                            });
                        }
                    }
                    continue;
                }

                if !matches!(pkt.first().map(|b| b >> 4), Some(4 | 6)) {
                    continue;
                }
                if pkt[0] >> 4 == 6 && in_ipv6_unavailable.load(Ordering::Relaxed) {
                    try_emit_icmpv6_no_route(
                        &pkt,
                        &in_icmp_no_route_limiter,
                        &in_udp_outbound_tx,
                    );
                    continue;
                }
                match tcp_in_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Never block `tun_to_stack` on TCP backpressure: TCP retransmits,
                        // whereas blocking here freezes DNS and UDP across the entire OS.
                        in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        let _ = in_stop_tx.send(true);
                        break 'demux;
                    }
                }
            }
        }
    });

    // Task 2: Accept TCP streams from TUN — bypass `tcp_slots` for TCP/53 DNS fallback
    // and bound slot waits so saturated TCP sessions drop cleanly without deadlocking accept.
    let tcp_ctx = ctx.clone();
    let tcp_rdns = Arc::clone(&reverse_dns);
    let tcp_stats = Arc::clone(&tun_stats);
    let tcp_dns_slots = Arc::clone(&dns_slots);
    let tcp_events = Arc::clone(&events);
    let tcp_stage_tracker = Arc::clone(&observed_stage);
    let tcp_app_bypass = app_bypass;
    let tcp_relay_buf_size = profile.tcp_relay_buf_size;
    let tcp_recv_buf_size = profile.tcp_recv_buffer_size as usize;
    let tcp_send_buf_size = profile.tcp_send_buffer_size as usize;
    let tcp_stop_root = internal_stop_rx.clone();
    let mut stop_tcp = internal_stop_rx.clone();
    let tcp_stop_tx = internal_stop_tx.clone();
    let tcp_accept_task = tokio::spawn(async move {
        loop {
            let maybe_stream = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_tcp) => break,
                maybe_stream = tcp_stream_rx.recv() => maybe_stream,
            };

            let Some(stream) = maybe_stream else {
                let _ = tcp_stop_tx.send(true);
                break;
            };
            let src = stream.local_addr();
            let dst = stream.remote_addr();

            // Intercept TCP port 53 DNS fallback (RFC 1035 2-byte length framing) BEFORE
            // acquiring `tcp_slots` so DNS remains responsive even when all TCP slots are busy.
            if dst.port() == 53 {
                let conn_ctx = tcp_ctx.clone();
                let rdns = Arc::clone(&tcp_rdns);
                let conn_dns_slots = Arc::clone(&tcp_dns_slots);
                let mut conn_stop = tcp_stop_root.clone();
                let active_tcp_guard = ActiveTcpGuard::enter(&tcp_stats);
                tokio::spawn(async move {
                    let _active_tcp_guard = active_tcp_guard;
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut conn_stop) => {}
                        _ = handle_tcp_dns_stream(TunTcpStream::new(stream), conn_ctx, rdns, conn_dns_slots) => {}
                    }
                });
                continue;
            }

            let permit = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_tcp) => break,
                res = tokio::time::timeout(
                    TCP_SLOT_ACQUIRE_TIMEOUT,
                    tcp_slots.clone().acquire_owned(),
                ) => match res {
                    Ok(Ok(permit)) => permit,
                    Ok(Err(_)) => break,
                    Err(_) => {
                        tcp_stats.tcp_sessions_dropped.fetch_add(1, Ordering::Relaxed);
                        debug!(%dst, "TCP session slots saturated; dropping stream cleanly");
                        drop(stream);
                        continue;
                    }
                },
            };

            let conn_ctx = tcp_ctx.clone();
            let rdns = Arc::clone(&tcp_rdns);
            let ev = Arc::clone(&tcp_events);
            let tracker = Arc::clone(&tcp_stage_tracker);
            let conn_app_bypass = tcp_app_bypass.clone();
            let mut conn_stop = tcp_stop_root.clone();
            let active_tcp_guard = ActiveTcpGuard::enter(&tcp_stats);

            tokio::spawn(async move {
                let _permit = permit;
                let _active_tcp_guard = active_tcp_guard;

                tokio::select! {
                    biased;
                    _ = wait_shutdown(&mut conn_stop) => {}
                    _ = async {
                        let known_host = rdns.lookup(dst.ip());
                        let bypass_fallback = conn_ctx.config.split_tunnel.should_bypass_app(None);
                        let bypass_fut = async {
                            if let Some(hook) = conn_app_bypass {
                                let src_ip = src.ip();
                                let src_port = src.port();
                                tokio::task::spawn_blocking(move || {
                                    hook.should_bypass(src_ip, src_port, false)
                                })
                                .await
                                .unwrap_or(bypass_fallback)
                            } else {
                                false
                            }
                        };
                        let connect_fut = async {
                            match conn_ctx.connect_upstream_addr(dst).await {
                                Ok(remote) => Ok((remote, dst)),
                                Err(primary_err) => {
                                    // On IPv4-only networks, cached IPv6 addresses from before
                                    // tunnel start fail with ENETUNREACH after smoltcp has
                                    // already accepted the local TCP SYN. Rescue over IPv4.
                                    if dst.is_ipv6() {
                                        if let Some(host) = known_host.as_deref() {
                                            match resolve_and_connect_ipv4(&conn_ctx, host, dst.port())
                                                .await
                                            {
                                                Some(pair) => Ok(pair),
                                                None => Err(primary_err),
                                            }
                                        } else {
                                            Err(primary_err)
                                        }
                                    } else {
                                        Err(primary_err)
                                    }
                                }
                            }
                        };
                        let (bypass_dpi, upstream_res) = tokio::join!(bypass_fut, connect_fut);
                        match upstream_res {
                            Ok((remote, effective_dst)) => {
                                tune_upstream_tcp_socket(
                                    &remote,
                                    tcp_recv_buf_size,
                                    tcp_send_buf_size,
                                );
                                if bypass_dpi {
                                    debug!(%src, %effective_dst, host = ?known_host, "TUN TCP passthrough (app bypassed)");
                                    if let Err(e) = relay_tcp_passthrough(
                                        TunTcpStream::new(stream),
                                        remote,
                                        &conn_ctx,
                                        tcp_relay_buf_size,
                                    )
                                    .await
                                    {
                                        debug!(%effective_dst, host = ?known_host, error = %e, "TUN bypassed TCP relay ended");
                                    }
                                } else {
                                    if let Err(e) = conn_ctx
                                        .relay_stream(TunTcpStream::new(stream), remote, known_host.as_deref(), effective_dst)
                                        .await
                                    {
                                        debug!(%effective_dst, host = ?known_host, error = %e, "TUN TCP relay ended");
                                    }
                                    let current = conn_ctx.preferred_stage() as u8;
                                    let prev = tracker.fetch_max(current, Ordering::Relaxed);
                                    if current > prev {
                                        let stage = LearnedStrategy::from_u8(current);
                                        ev.push(
                                            "info",
                                            "auto-heal",
                                            format!(
                                                "ISP stage promoted to Stage {} ({})",
                                                stage.stage_number(),
                                                stage.label()
                                            ),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                debug!(%dst, host = ?known_host, error = %e, "TUN TCP upstream connect failed");
                            }
                        }
                    } => {}
                }
            });
        }
    });

    // Task 4: Shared 15s UDP Cone NAT idle reaper + S3 sleep/wake clock-jump detector
    let reaper_nat = Arc::clone(&udp_nat);
    let reaper_route_gen = Arc::clone(&route_gen);
    let reaper_rdns = Arc::clone(&reverse_dns);
    let reaper_ipv6_unavailable = Arc::clone(&ipv6_unavailable);
    let reaper_stats = Arc::clone(&tun_stats);
    let reaper_ctx = ctx.clone();
    let reaper_events = Arc::clone(&events);
    let mut stop_reaper = internal_stop_rx.clone();
    let udp_reaper_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(UDP_REAPER_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        let mut last_wall = SystemTime::now();
        let mut last_mono = Instant::now();
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_reaper) => break,
                _ = ticker.tick() => {
                    let curr_wall = SystemTime::now();
                    let curr_mono = Instant::now();
                    let sleep_jump = detect_sleep_wake_jump(last_wall, curr_wall, last_mono, curr_mono);
                    last_wall = curr_wall;
                    last_mono = curr_mono;

                    if let Some(drift) = sleep_jump {
                        let drained = drain_udp_nat(
                            &reaper_nat,
                            &reaper_route_gen,
                            &reaper_stats,
                            &reaper_ctx,
                        );
                        reaper_ctx.dns.clear_cache().await;
                        reaper_rdns.clear();
                        reaper_ipv6_unavailable.store(
                            is_outbound_ipv6_unavailable(&reaper_ctx),
                            Ordering::Relaxed,
                        );
                        reaper_events.push(
                            "info",
                            "udp",
                            format!(
                                "system wake detected (+{}s clock jump): drained {} UDP NAT flows and cleared DNS/rDNS cache",
                                drift.as_secs(),
                                drained
                            ),
                        );
                    } else {
                        let now = now_secs();
                        let mut guard = reaper_nat
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let active_count = reap_idle_udp_nat(
                            &mut guard,
                            now,
                            UDP_IDLE_TIMEOUT.as_secs(),
                            |e| e.last_active_secs.load(Ordering::Relaxed),
                            |evicted| evicted.abort.abort(),
                        ) as u64;
                        store_udp_flows_active(active_count, &reaper_stats, &reaper_ctx);
                    }
                }
            }
        }
    });

    let _abort_guard = PipelineAbortGuard {
        handles: vec![
            stop_bridge.abort_handle(),
            outbound_writer_task.abort_handle(),
            tun_to_stack.abort_handle(),
            tcp_accept_task.abort_handle(),
            udp_reaper_task.abort_handle(),
            runner_handle.abort_handle(),
        ],
    };

    loop {
        tokio::select! {
            biased;
            _ = wait_shutdown(&mut internal_stop_rx) => break,
            changed = async {
                match route_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_err() {
                    route_rx = None;
                    continue;
                }
                let watch_route_gen = route_rx.as_ref().map(|rx| *rx.borrow()).unwrap_or(0);
                let drained = drain_udp_nat(&udp_nat, &route_gen, &tun_stats, &ctx);
                ctx.dns.clear_cache().await;
                reverse_dns.clear();
                ipv6_unavailable.store(is_outbound_ipv6_unavailable(&ctx), Ordering::Relaxed);
                if drained > 0 {
                    events.push(
                        "info",
                        "udp",
                        format!("route change (gen {watch_route_gen}): rebound {drained} UDP NAT flows"),
                    );
                }
            }
        }
    }

    stop_bridge.abort();
    outbound_writer_task.abort();
    tun_to_stack.abort();
    tcp_accept_task.abort();
    udp_reaper_task.abort();
    runner_handle.abort();

    // Abort every Cone NAT reader task cleanly before clearing table.
    let _ = drain_udp_nat(&udp_nat, &route_gen, &tun_stats, &ctx);

    crate::flush_engine_cache(&ctx).await;

    if *shutdown_rx.borrow() {
        Ok(())
    } else {
        Err(anyhow!("TUN pipeline terminated unexpectedly"))
    }
}

struct PassthroughCountingStream<'a> {
    inner: tokio::net::TcpStream,
    telemetry: &'a EngineTelemetry,
    active: &'a AtomicBool,
    batch_bytes: u64,
    pending_rx: u64,
    pending_tx: u64,
}

impl<'a> PassthroughCountingStream<'a> {
    fn new(
        inner: tokio::net::TcpStream,
        telemetry: &'a EngineTelemetry,
        active: &'a AtomicBool,
        batch_bytes: u64,
    ) -> Self {
        Self {
            inner,
            telemetry,
            active,
            batch_bytes,
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

impl Drop for PassthroughCountingStream<'_> {
    fn drop(&mut self) {
        self.flush_rx();
        self.flush_tx();
    }
}

impl AsyncRead for PassthroughCountingStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        match &poll {
            Poll::Ready(Ok(())) => {
                let read_bytes = buf.filled().len().saturating_sub(before);
                if read_bytes > 0 {
                    this.touch_activity();
                    this.pending_rx += read_bytes as u64;
                    if this.pending_rx >= this.batch_bytes {
                        this.flush_rx();
                    }
                } else {
                    this.flush_rx();
                }
            }
            Poll::Ready(Err(_)) => {
                this.flush_rx();
            }
            Poll::Pending => {}
        }
        poll
    }
}

impl AsyncWrite for PassthroughCountingStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        match &poll {
            Poll::Ready(Ok(n)) if *n > 0 => {
                this.touch_activity();
                this.pending_tx += *n as u64;
                if this.pending_tx >= this.batch_bytes {
                    this.flush_tx();
                }
            }
            Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                this.flush_tx();
            }
            Poll::Pending => {}
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_tx >= this.batch_bytes {
            this.flush_tx();
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        this.flush_tx();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Straight-through bidirectional TCP relay for app-bypassed flows.
/// Forwards the initial TLS/HTTP payload untouched without ClientHello inspection or splitting.
async fn relay_tcp_passthrough(
    mut client: TunTcpStream,
    remote: tokio::net::TcpStream,
    ctx: &EngineContext,
    buf_size: usize,
) -> std::io::Result<()> {
    struct TelemetryConnGuard(Arc<EngineTelemetry>);
    impl Drop for TelemetryConnGuard {
        fn drop(&mut self) {
            self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    let _ = remote.set_nodelay(true);
    ctx.telemetry
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    ctx.telemetry
        .total_connections
        .fetch_add(1, Ordering::Relaxed);
    let _conn_guard = TelemetryConnGuard(Arc::clone(&ctx.telemetry));

    let copy_buf = passthrough_copy_buf_size(buf_size);
    let active = AtomicBool::new(false);
    let mut counted_remote =
        PassthroughCountingStream::new(remote, &ctx.telemetry, &active, copy_buf as u64);

    let idle_watcher = async {
        let mut last_active = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            if active.swap(false, Ordering::Relaxed) {
                last_active = Instant::now();
            } else if last_active.elapsed() >= PASSTHROUGH_IDLE_TIMEOUT {
                break;
            }
        }
    };

    tokio::select! {
        biased;
        res = tokio::io::copy_bidirectional_with_sizes(&mut client, &mut counted_remote, copy_buf, copy_buf) => {
            res.map(|_| ())
        }
        _ = idle_watcher => Ok(()),
    }
}

async fn resolve_and_connect_ipv4(
    ctx: &EngineContext,
    host: &str,
    port: u16,
) -> Option<(tokio::net::TcpStream, SocketAddr)> {
    let ips = ctx.dns.resolve(host).await.ok()?;
    for ip in ips.into_iter().filter(|ip| ip.is_ipv4()) {
        let addr = SocketAddr::new(ip, port);
        if let Ok(stream) = ctx.connect_upstream_addr(addr).await {
            return Some((stream, addr));
        }
    }
    None
}

async fn handle_tcp_dns_stream(
    mut stream: TunTcpStream,
    ctx: EngineContext,
    rdns: Arc<ReverseDnsCache>,
    dns_slots: Arc<Semaphore>,
) {
    let mut len_buf = [0u8; 2];
    for _ in 0..8 {
        match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let msg_len = usize::from(u16::from_be_bytes(len_buf));
        if !(12..=4096).contains(&msg_len) {
            break;
        }
        let mut query = vec![0u8; msg_len];
        match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let Ok(_dns_permit) = dns_slots.clone().try_acquire_owned() else {
            break;
        };
        let resolved = tokio::time::timeout(
            Duration::from_secs(6),
            ctx.dns.resolve_wire_query(&query, ctx.config.block_quic),
        )
        .await;
        match resolved {
            Ok(Ok((resp, meta))) => {
                if let Some((domain, ips)) = meta {
                    for ip in ips {
                        rdns.insert(ip, domain.clone());
                    }
                }
                let Ok(resp_len) = u16::try_from(resp.len()) else {
                    break;
                };
                let write_res = tokio::time::timeout(Duration::from_secs(5), async {
                    stream.write_all(&resp_len.to_be_bytes()).await?;
                    stream.write_all(&resp).await?;
                    stream.flush().await
                })
                .await;
                if !matches!(write_res, Ok(Ok(()))) {
                    break;
                }
            }
            _ => break,
        }
    }

    let _ = tokio::time::timeout(TCP_SHUTDOWN_TIMEOUT, async {
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
    })
    .await;
}

/// Sweeps all UDP NAT entries idle for at least `idle_timeout_secs`, invoking `on_evict`
/// for each removed entry. Returns the number of remaining active flows.
fn reap_idle_udp_nat<K, V, FLastSeen, FOnEvict>(
    map: &mut HashMap<K, V>,
    now: u64,
    idle_timeout_secs: u64,
    mut last_seen: FLastSeen,
    mut on_evict: FOnEvict,
) -> usize
where
    K: Copy + Eq + std::hash::Hash,
    FLastSeen: FnMut(&V) -> u64,
    FOnEvict: FnMut(V),
{
    let expired_keys: Vec<K> = map
        .iter()
        .filter_map(|(k, entry)| {
            (now.saturating_sub(last_seen(entry)) >= idle_timeout_secs).then_some(*k)
        })
        .collect();
    for expired_key in expired_keys {
        if let Some(evicted) = map.remove(&expired_key) {
            on_evict(evicted);
        }
    }
    map.len()
}

/// Ensures room for a new UDP NAT flow when `map` is at or above `max_flows`.
/// First purges all expired flows (`now - last_seen >= idle_timeout_secs`); if still at
/// capacity, evicts the least-recently-used flow using monotonic `lru_seq` (avoiding 1s
/// wall-clock ties). Returns the number of evicted flows.
fn make_room_in_udp_nat<K, V, FLastSeen, FLruSeq, FOnEvict>(
    map: &mut HashMap<K, V>,
    max_flows: usize,
    now: u64,
    idle_timeout_secs: u64,
    mut last_seen: FLastSeen,
    mut lru_seq: FLruSeq,
    mut on_evict: FOnEvict,
) -> usize
where
    K: Copy + Eq + std::hash::Hash,
    FLastSeen: FnMut(&V) -> u64,
    FLruSeq: FnMut(&V) -> u64,
    FOnEvict: FnMut(V),
{
    if max_flows == 0 || map.len() < max_flows {
        return 0;
    }

    let before = map.len();
    reap_idle_udp_nat(map, now, idle_timeout_secs, &mut last_seen, &mut on_evict);

    while map.len() >= max_flows {
        let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, entry)| lru_seq(entry))
            .map(|(k, _)| *k)
        else {
            break;
        };
        if let Some(evicted) = map.remove(&oldest_key) {
            on_evict(evicted);
        }
    }
    before.saturating_sub(map.len())
}

type UdpNatHandle = (Arc<UdpSocket>, Arc<AtomicU64>, Arc<AtomicU64>);

enum UdpFastPath {
    Sent(usize),
    Done,
    Ipv6Unreachable,
    NeedsSlowPath(Option<UdpNatHandle>),
}

fn evict_udp_nat_entry(
    nat: &UdpNatTable,
    key: (SocketAddr, bool),
    outbound: &Arc<UdpSocket>,
    stats: &TunStats,
    ctx: &EngineContext,
) {
    let mut guard = nat
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let evicted = if guard
        .get(&key)
        .is_some_and(|entry| Arc::ptr_eq(&entry.socket, outbound))
    {
        guard.remove(&key)
    } else {
        None
    };
    if let Some(evicted) = evicted {
        evicted.abort.abort();
    }
    store_udp_flows_active(guard.len() as u64, stats, ctx);
}

/// Updates a UDP Cone-NAT entry's activity timestamp and monotonic LRU sequence number
/// at most once per second per flow so high-PPS traffic (e.g. 100k PPS) does not bounce
/// the shared global `udp_lru_seq` cache line on every packet.
#[inline]
fn touch_udp_nat_activity(
    last_active_secs: &AtomicU64,
    last_seq: &AtomicU64,
    lru_seq: &AtomicU64,
    now: u64,
) {
    if last_active_secs.load(Ordering::Relaxed) != now
        && last_active_secs.swap(now, Ordering::Relaxed) != now
    {
        last_seq.store(
            lru_seq.fetch_add(1, Ordering::Relaxed) + 1,
            Ordering::Relaxed,
        );
    }
}

/// Non-blocking inline fast path for established UDP Cone-NAT flows.
/// Returns `UdpFastPath::NeedsSlowPath` whenever socket binding/eviction or a bounded
/// `WouldBlock` await is needed so `tun_to_stack` never stalls DNS or TCP demuxing.
#[allow(clippy::too_many_arguments)]
fn try_forward_udp_fast(
    payload: &[u8],
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    nat: &UdpNatTable,
    lru_seq: &Arc<AtomicU64>,
    ctx: &EngineContext,
    stats: &TunStats,
    max_udp_flows: usize,
) -> UdpFastPath {
    if src_addr.is_ipv4() != dst_addr.is_ipv4() || is_unroutable_udp_dst(dst_addr) {
        return UdpFastPath::Done;
    }

    let key = (src_addr, dst_addr.is_ipv4());
    let (fatal_evict, ipv6_unreach) = {
        let guard = nat
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = guard.get(&key) else {
            if max_udp_flows == 0 {
                return UdpFastPath::Done;
            }
            return UdpFastPath::NeedsSlowPath(None);
        };

        // Issue the non-blocking send under the shared read lock to avoid 3x Arc::clone + 3x
        // Arc::drop atomic refcount ops per UDP datagram on the hot path.
        match entry.socket.try_send_to(payload, dst_addr) {
            Ok(_) => {
                touch_udp_nat_activity(
                    &entry.last_active_secs,
                    &entry.last_seq,
                    lru_seq,
                    now_secs(),
                );
                return UdpFastPath::Sent(payload.len());
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                return UdpFastPath::NeedsSlowPath(Some((
                    Arc::clone(&entry.socket),
                    Arc::clone(&entry.last_active_secs),
                    Arc::clone(&entry.last_seq),
                )));
            }
            Err(e) if is_fatal_udp_send_error(&e) => {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                debug!(%dst_addr, error = %e, "evicting dead UDP NAT entry after fatal send error");
                (
                    Some(Arc::clone(&entry.socket)),
                    !dst_addr.is_ipv4() && is_ipv6_unreachable_error(&e),
                )
            }
            Err(e) => {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                if !dst_addr.is_ipv4() && is_ipv6_unreachable_error(&e) {
                    return UdpFastPath::Ipv6Unreachable;
                }
                return UdpFastPath::Done;
            }
        }
    };

    if let Some(outbound) = fatal_evict {
        evict_udp_nat_entry(nat, key, &outbound, stats, ctx);
    }
    if ipv6_unreach {
        UdpFastPath::Ipv6Unreachable
    } else {
        UdpFastPath::Done
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_udp_cone_nat_slow(
    payload: Vec<u8>,
    invoking_v6_pkt: Option<Vec<u8>>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    existing: Option<UdpNatHandle>,
    nat: UdpNatTable,
    lru_seq: Arc<AtomicU64>,
    route_gen: Arc<AtomicU64>,
    stun_flows: Arc<SharedStunFlowCache>,
    ipv6_unavailable: Arc<AtomicBool>,
    icmp_no_route_limiter: Arc<IcmpRateLimiter>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    stats: Arc<TunStats>,
    shutdown_rx: watch::Receiver<bool>,
    mtu: usize,
    max_udp_flows: usize,
    udp_socket_buf_bytes: usize,
) {
    if is_unroutable_udp_dst(dst_addr) {
        return;
    }
    let key = (src_addr, dst_addr.is_ipv4());

    let (outbound, last_active_secs, last_seq, already_would_block) = if let Some((
        outbound,
        last_active_secs,
        last_seq,
    )) = existing
    {
        (outbound, last_active_secs, last_seq, true)
    } else {
        let existing_now = {
            let guard = nat
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.get(&key).map(|entry| {
                (
                    Arc::clone(&entry.socket),
                    Arc::clone(&entry.last_active_secs),
                    Arc::clone(&entry.last_seq),
                )
            })
        };

        let handle = if let Some(found) = existing_now {
            found
        } else {
            if max_udp_flows == 0 {
                return;
            }

            // Evict idle/LRU flows BEFORE binding a new OS UDP socket to prevent EMFILE on iOS
            // and tight mobile FD budgets.
            let (reused, evicted_count) = {
                let mut guard = nat
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(entry) = guard.get(&key) {
                    (
                        Some((
                            Arc::clone(&entry.socket),
                            Arc::clone(&entry.last_active_secs),
                            Arc::clone(&entry.last_seq),
                        )),
                        0usize,
                    )
                } else {
                    let evicted = make_room_in_udp_nat(
                        &mut guard,
                        max_udp_flows,
                        now_secs(),
                        UDP_IDLE_TIMEOUT.as_secs(),
                        |e| e.last_active_secs.load(Ordering::Relaxed),
                        |e| e.last_seq.load(Ordering::Relaxed),
                        |entry| entry.abort.abort(),
                    );
                    if evicted > 0 {
                        store_udp_flows_active(guard.len() as u64, &stats, &ctx);
                    }
                    (None, evicted)
                }
            };

            if let Some(found) = reused {
                found
            } else {
                if evicted_count > 0 {
                    // Give aborted reader task(s) a scheduling turn to drop their Arc<UdpSocket> FDs.
                    tokio::task::yield_now().await;
                }
                // Capture route generation BEFORE binding so a concurrent uplink switch
                // can never race a stale socket into `udp_nat`.
                let bind_gen = route_gen.load(Ordering::Acquire);
                // Bind outside the write lock to avoid blocking concurrent UDP lookups.
                let bound =
                    match bind_udp_socket_strict(&ctx, dst_addr.is_ipv4(), udp_socket_buf_bytes) {
                        Ok(sock) => sock,
                        Err(err) => {
                            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                            maybe_handle_ipv6_udp_unreachable(
                                dst_addr,
                                &err,
                                invoking_v6_pkt.as_deref(),
                                &ipv6_unavailable,
                                &icmp_no_route_limiter,
                                &outbound_tx,
                            );
                            return;
                        }
                    };

                let mut guard = nat
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *shutdown_rx.borrow() || route_gen.load(Ordering::Acquire) != bind_gen {
                    debug!(
                        %dst_addr,
                        bind_gen,
                        "aborting stale UDP NAT insertion after route change or shutdown"
                    );
                    return;
                }
                if let Some(entry) = guard.get(&key) {
                    (
                        Arc::clone(&entry.socket),
                        Arc::clone(&entry.last_active_secs),
                        Arc::clone(&entry.last_seq),
                    )
                } else {
                    let now = now_secs();
                    make_room_in_udp_nat(
                        &mut guard,
                        max_udp_flows,
                        now,
                        UDP_IDLE_TIMEOUT.as_secs(),
                        |e| e.last_active_secs.load(Ordering::Relaxed),
                        |e| e.last_seq.load(Ordering::Relaxed),
                        |evicted| evicted.abort.abort(),
                    );

                    let sock = Arc::new(bound);
                    let last_active = Arc::new(AtomicU64::new(now));
                    let entry_seq =
                        Arc::new(AtomicU64::new(lru_seq.fetch_add(1, Ordering::Relaxed) + 1));

                    let rx_sock = Arc::clone(&sock);
                    let rx_last = Arc::clone(&last_active);
                    let rx_last_seq = Arc::clone(&entry_seq);
                    let rx_lru_seq = Arc::clone(&lru_seq);
                    let rx_stun_flows = Arc::clone(&stun_flows);
                    let rx_outbound_tx = outbound_tx.clone();
                    let rx_nat = Arc::clone(&nat);
                    let rx_stats = Arc::clone(&stats);
                    let rx_ctx = ctx.clone();
                    let mut rx_stop = shutdown_rx.clone();
                    let expect_ipv4 = dst_addr.is_ipv4();
                    let recv_buf_len = mtu.max(1500);
                    let max_reply = max_udp_payload_for_mtu(mtu, expect_ipv4).min(recv_buf_len);

                    let handle = tokio::spawn(async move {
                        let mut buf = vec![0u8; recv_buf_len];
                        let mut rx_batcher = UdpByteBatcher::new(Arc::clone(&rx_ctx.telemetry));
                        let rx_flush_sleep = tokio::time::sleep(Duration::from_secs(
                            UDP_TELEMETRY_FLUSH_INTERVAL_SECS,
                        ));
                        tokio::pin!(rx_flush_sleep);
                        let mut rx_flush_armed = false;
                        loop {
                            if rx_batcher.has_pending() && !rx_flush_armed {
                                rx_flush_sleep.as_mut().reset(
                                    tokio::time::Instant::now()
                                        + Duration::from_secs(UDP_TELEMETRY_FLUSH_INTERVAL_SECS),
                                );
                                rx_flush_armed = true;
                            } else if !rx_batcher.has_pending() {
                                rx_flush_armed = false;
                            }

                            tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut rx_stop) => break,
                                res = rx_sock.recv_from(&mut buf) => {
                                    match res {
                                        Ok((n, remote_src)) if n > 0 => {
                                            let canonical_ip = remote_src.ip().to_canonical();
                                            if canonical_ip.is_ipv4() != expect_ipv4 || n > max_reply {
                                                rx_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                                continue;
                                            }
                                            let clean_src = SocketAddr::new(canonical_ip, remote_src.port());
                                            let now = now_secs();
                                            touch_udp_nat_activity(
                                                &rx_last,
                                                &rx_last_seq,
                                                &rx_lru_seq,
                                                now,
                                            );
                                            rx_stun_flows.refresh_on_inbound_reply(
                                                src_addr,
                                                clean_src,
                                                &buf[..n],
                                                now,
                                            );
                                            rx_batcher.record_rx(n as u64, now);
                                            if let Some(raw_pkt) = build_udp_packet(clean_src, src_addr, &buf[..n]) {
                                                match rx_outbound_tx.try_send(raw_pkt) {
                                                    Ok(()) => {}
                                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                                        rx_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                                    }
                                                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                                                }
                                            } else {
                                                rx_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                            }
                                        }
                                        Ok(_) => continue,
                                        Err(e) if is_transient_udp_recv_error(&e) => continue,
                                        Err(_) => break,
                                    }
                                }
                                _ = &mut rx_flush_sleep, if rx_flush_armed => {
                                    rx_batcher.flush(now_secs());
                                    rx_flush_armed = false;
                                }
                            }
                        }
                        drop(rx_batcher);
                        let mut guard = rx_nat
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if guard
                            .get(&key)
                            .is_some_and(|e| Arc::ptr_eq(&e.socket, &rx_sock))
                        {
                            guard.remove(&key);
                        }
                        store_udp_flows_active(guard.len() as u64, &rx_stats, &rx_ctx);
                    });

                    guard.insert(
                        key,
                        UdpNatEntry {
                            socket: Arc::clone(&sock),
                            last_active_secs: Arc::clone(&last_active),
                            last_seq: Arc::clone(&entry_seq),
                            abort: handle.abort_handle(),
                        },
                    );
                    store_udp_flows_active(guard.len() as u64, &stats, &ctx);
                    (sock, last_active, entry_seq)
                }
            }
        };
        (handle.0, handle.1, handle.2, false)
    };

    // Bounded 25ms fallback on initial readiness or WouldBlock runs off `tun_to_stack`
    // so the first packet on a newly bound socket sends reliably without HoL stalls.
    let send_res = if already_would_block {
        match tokio::time::timeout(
            Duration::from_millis(25),
            outbound.send_to(&payload, dst_addr),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "udp send timed out",
            )),
        }
    } else {
        match outbound.try_send_to(&payload, dst_addr) {
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                match tokio::time::timeout(
                    Duration::from_millis(25),
                    outbound.send_to(&payload, dst_addr),
                )
                .await
                {
                    Ok(res) => res,
                    Err(_) => Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        "udp send timed out",
                    )),
                }
            }
            Err(e) => Err(e),
        }
    };

    match send_res {
        Ok(_) => {
            touch_udp_nat_activity(&last_active_secs, &last_seq, &lru_seq, now_secs());
            ctx.add_udp_bytes(payload.len() as u64, 0);
        }
        Err(e) if is_fatal_udp_send_error(&e) => {
            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            debug!(%dst_addr, error = %e, "evicting dead UDP NAT entry after fatal send error");
            evict_udp_nat_entry(&nat, key, &outbound, &stats, &ctx);
            maybe_handle_ipv6_udp_unreachable(
                dst_addr,
                &e,
                invoking_v6_pkt.as_deref(),
                &ipv6_unavailable,
                &icmp_no_route_limiter,
                &outbound_tx,
            );
        }
        Err(e) => {
            stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            maybe_handle_ipv6_udp_unreachable(
                dst_addr,
                &e,
                invoking_v6_pkt.as_deref(),
                &ipv6_unavailable,
                &icmp_no_route_limiter,
                &outbound_tx,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TunnelConfig;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use std::net::Ipv4Addr;
    use vdpi_core::dns::{decode_dns_response, encode_dns_query};

    fn build_ipv4_udp(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let builder =
            PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64).udp(src_port, dst_port);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    async fn exercise_pipeline(profile: TunProfile) {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            profile,
            stop_rx,
        ));

        // 0. Inject garbage + malformed UDP packets FIRST; pipeline must survive completely.
        in_tx.send(vec![0xff, 0xfe, 0xfd]).await.unwrap();
        let mut bad_udp = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            11111,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"bad",
        );
        bad_udp[24] = 0x05;
        in_tx.send(bad_udp).await.unwrap();

        // 1. Send a valid DNS A query for "localhost" to virtual DNS 10.0.0.2:53
        let mut dns_q = encode_dns_query("localhost", 1).unwrap();
        dns_q[0] = 0x42;
        dns_q[1] = 0x24;
        let dns_pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            53000,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            &dns_q,
        );
        in_tx.send(dns_pkt).await.unwrap();

        let reply_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let sliced = SlicedPacket::from_ip(&reply_raw).unwrap();
        let TransportSlice::Udp(udp) = sliced.transport.unwrap() else {
            panic!("expected UDP DNS reply");
        };
        assert_eq!(udp.source_port(), 53);
        assert_eq!(udp.destination_port(), 53000);
        assert_eq!(&udp.payload()[0..2], &[0x42, 0x24]);
        let (ips, _) = decode_dns_response(udp.payload(), 1).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        // 2. Send QUIC Initial (0xc0), RFC 9287 Greased (0x80), and Short-Header (0x40)
        //    UDP/443 packets to a public IP -> all 3 must be cleanly dropped and counted.
        for (src_port, payload) in [
            (54000u16, vec![0xc0; 1200]),
            (54001u16, vec![0x80; 1200]),
            (54002u16, vec![0x40; 64]),
        ] {
            let quic_pkt = build_ipv4_udp(
                Ipv4Addr::new(10, 0, 0, 1),
                src_port,
                Ipv4Addr::new(162, 159, 135, 232),
                443,
                &payload,
            );
            in_tx.send(quic_pkt).await.unwrap();
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.quic_blocked.load(Ordering::Relaxed) < 3
            || ctx.telemetry.quic_blocked.load(Ordering::Relaxed) < 3
        {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for QUIC block counters (tun_stats={}, telemetry={})",
                tun_stats.quic_blocked.load(Ordering::Relaxed),
                ctx.telemetry.quic_blocked.load(Ordering::Relaxed),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 3);
        assert_eq!(ctx.telemetry.quic_blocked.load(Ordering::Relaxed), 3);

        if profile.emit_quic_icmp_reject {
            for _ in 0..3 {
                let icmp_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert!(icmp_raw.len() >= 28);
                assert_eq!(icmp_raw[0] >> 4, 4);
                assert_eq!(icmp_raw[9], 1); // IPv4 ICMP
                assert_eq!(icmp_raw[20], 3); // Destination Unreachable
                assert_eq!(icmp_raw[21], 3); // Port Unreachable
            }
        }

        // 3. Send a regular UDP packet to a local echo server -> Cone NAT must relay both ways
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], peer).await.unwrap();
        });

        let voice_pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            55000,
            Ipv4Addr::LOCALHOST,
            echo_port,
            b"vdpi-voice-ping",
        );
        in_tx.send(voice_pkt).await.unwrap();

        let echo_reply_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        echo_task.await.unwrap();
        let sliced_echo = SlicedPacket::from_ip(&echo_reply_raw).unwrap();
        let TransportSlice::Udp(udp_echo) = sliced_echo.transport.unwrap() else {
            panic!("expected UDP echo reply");
        };
        assert_eq!(udp_echo.source_port(), echo_port);
        assert_eq!(udp_echo.destination_port(), 55000);
        assert_eq!(udp_echo.payload(), b"vdpi-voice-ping");
        assert!(ctx.telemetry.bytes_tx.load(Ordering::Relaxed) >= b"vdpi-voice-ping".len() as u64);
        assert!(ctx.telemetry.bytes_rx.load(Ordering::Relaxed) >= b"vdpi-voice-ping".len() as u64);

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
        assert_eq!(ctx.telemetry.udp_flows_active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn standard_profile_handles_malformed_dns_quic_and_udp_echo() {
        exercise_pipeline(TunProfile::STANDARD).await;
    }

    #[tokio::test]
    async fn low_memory_ios_profile_handles_malformed_dns_quic_and_udp_echo() {
        exercise_pipeline(TunProfile::LOW_MEMORY).await;
    }

    #[tokio::test]
    async fn desktop_profile_emits_icmp_port_unreachable_for_blocked_quic() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::DESKTOP,
            stop_rx,
        ));

        let quic_pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            54000,
            Ipv4Addr::new(162, 159, 135, 232),
            443,
            &[0xc0; 1200],
        );
        in_tx.send(quic_pkt).await.unwrap();

        let icmp_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(icmp_raw.len() >= 28);
        assert_eq!(icmp_raw[0] >> 4, 4);
        assert_eq!(icmp_raw[9], 1); // IPv4 ICMP
        assert_eq!(icmp_raw[20], 3); // Destination Unreachable
        assert_eq!(icmp_raw[21], 3); // Port Unreachable
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(ctx.telemetry.quic_blocked.load(Ordering::Relaxed), 1);

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[test]
    fn icmp_rate_limiter_caps_burst_at_limit() {
        let limiter = IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC);
        let allowed = (0..128).filter(|_| limiter.allow()).count();
        assert_eq!(allowed, MAX_QUIC_ICMP_PER_SEC as usize);
    }

    #[test]
    fn udp_nat_reaper_sweeps_only_idle_flows() {
        assert_eq!(UDP_IDLE_TIMEOUT, Duration::from_secs(120));
        let mut flows: HashMap<u32, u64> = HashMap::from([(1, 10), (2, 80), (3, 140), (4, 200)]);
        let mut evicted = Vec::new();
        let remaining = reap_idle_udp_nat(
            &mut flows,
            200,
            UDP_IDLE_TIMEOUT.as_secs(),
            |ts| *ts,
            |ts| evicted.push(ts),
        );
        assert_eq!(remaining, 2);
        assert!(flows.contains_key(&3));
        assert!(flows.contains_key(&4));
        evicted.sort_unstable();
        assert_eq!(evicted, vec![10, 80]);
    }

    #[test]
    fn udp_nat_eviction_purges_expired_first_then_evicts_lru_at_cap() {
        // 1. When at iOS 64-flow cap with all fresh entries in the SAME wall-clock second,
        //    monotonic `lru_seq` breaks ties and evicts the exact least-recently-used flow.
        let cap = TunProfile::LOW_MEMORY.max_udp_flows;
        let mut flows: HashMap<u32, (u64, u64)> = HashMap::new();
        for id in 0..cap as u32 {
            let seq = if id == 42 { 1 } else { 100 + u64::from(id) };
            flows.insert(id, (150, seq));
        }
        let mut evicted = Vec::new();
        let evicted_count = make_room_in_udp_nat(
            &mut flows,
            cap,
            150,
            UDP_IDLE_TIMEOUT.as_secs(),
            |(ts, _)| *ts,
            |(_, seq)| *seq,
            |entry| evicted.push(entry),
        );
        assert_eq!(evicted_count, 1);
        assert_eq!(flows.len(), cap - 1);
        assert!(!flows.contains_key(&42));
        assert_eq!(evicted, vec![(150, 1)]);

        // 2. When expired entries exist at cap, purges expired flows without evicting active ones.
        let mut mixed: HashMap<u32, (u64, u64)> =
            HashMap::from([(1, (10, 1)), (2, (20, 2)), (3, (190, 3)), (4, (195, 4))]);
        let mut evicted_mixed = Vec::new();
        let evicted_mixed_count = make_room_in_udp_nat(
            &mut mixed,
            4,
            200,
            UDP_IDLE_TIMEOUT.as_secs(),
            |(ts, _)| *ts,
            |(_, seq)| *seq,
            |(ts, _)| evicted_mixed.push(ts),
        );
        assert_eq!(evicted_mixed_count, 2);
        assert_eq!(mixed.len(), 2);
        assert!(mixed.contains_key(&3));
        assert!(mixed.contains_key(&4));
        evicted_mixed.sort_unstable();
        assert_eq!(evicted_mixed, vec![10, 20]);
    }

    #[tokio::test]
    async fn stun_to_turn_udp_443_passthrough_and_route_watch_rebind() {
        // 1. Verify StunFlowCache TTL expiry (120s) and cap (256 entries).
        let mut cache = StunFlowCache::new();
        let flow_a = (
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 135, 232)), 443),
        );
        cache.record(flow_a, 100);
        assert!(cache.is_authenticated_and_refresh(flow_a, 219));
        // Refreshed at 219 -> expires at 219 + 120 = 339.
        assert!(!cache.is_authenticated_and_refresh(flow_a, 339));

        for idx in 0..(STUN_FLOW_MAX_ENTRIES + 8) {
            let flow = (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 10_000 + idx as u16),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 135, 232)), 443),
            );
            cache.record(flow, 500 + (idx % 10) as u64);
        }
        assert_eq!(cache.entries.len(), STUN_FLOW_MAX_ENTRIES);

        // 2. End-to-end STUN -> TURN ChannelData / DTLS / SRTP pass-through on UDP/443
        //    plus route_rx UDP NAT rebind drain.
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (route_tx, route_rx) = watch::channel(0u64);

        let pipeline = tokio::spawn(run_tun_pipeline_with_route_watch(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::STANDARD,
            stop_rx,
            Some(route_rx),
        ));

        let public_turn = Ipv4Addr::new(198, 51, 100, 10);
        let client_ip = Ipv4Addr::new(10, 0, 0, 1);

        // RFC 5389 STUN Binding Request on UDP/443 authenticates `(10.0.0.1:56000, public_turn:443)`.
        let mut stun_req = [0u8; 20];
        stun_req[0..2].copy_from_slice(&[0x00, 0x01]);
        stun_req[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                56000,
                public_turn,
                443,
                &stun_req,
            ))
            .await
            .unwrap();

        // Subsequent TURN ChannelData (0x40..), DTLS (0x16..), and SRTP (0x80..) on the same
        // STUN-authenticated 4-tuple must bypass QUIC blocking.
        for payload in [
            [0x40u8, 0x00, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef].as_slice(),
            [0x16u8, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice(),
            [0x80u8, 0x6f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00].as_slice(),
        ] {
            in_tx
                .send(build_ipv4_udp(client_ip, 56000, public_turn, 443, payload))
                .await
                .unwrap();
        }

        // Unauthenticated QUIC Initial and spoofed-cookie QUIC on different source ports MUST block.
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                56001,
                public_turn,
                443,
                &[0xc0u8; 1200],
            ))
            .await
            .unwrap();
        let mut spoofed_quic = [0xc0u8; 24];
        spoofed_quic[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                56002,
                public_turn,
                443,
                &spoofed_quic,
            ))
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.quic_blocked.load(Ordering::Relaxed) < 2 {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for unauthenticated QUIC drops (got {})",
                tun_stats.quic_blocked.load(Ordering::Relaxed),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Only the 2 unauthenticated QUIC packets were dropped; STUN + TURN/DTLS/SRTP passed.
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 2);
        assert_eq!(ctx.telemetry.quic_blocked.load(Ordering::Relaxed), 2);

        // Establish a guaranteed-routable local echo UDP NAT flow, then fire `route_tx`
        // and verify all active UDP NAT flows are drained immediately for uplink rebind.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], peer).await.unwrap();
        });
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                56010,
                Ipv4Addr::LOCALHOST,
                echo_port,
                b"route-rebind-probe",
            ))
            .await
            .unwrap();
        // Drain any prior ICMP Port Unreachable frames emitted for the 2 blocked QUIC packets
        // (TunProfile::STANDARD now enables emit_quic_icmp_reject for instant TCP fallback).
        let reply_raw = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pkt = out_rx.recv().await.expect("out_rx closed");
                if inspect_inbound_udp(&pkt).is_some() {
                    break pkt;
                }
            }
        })
        .await
        .expect("timed out waiting for raw IPv4+UDP echo reply");
        echo_task.await.unwrap();
        let parsed_reply = inspect_inbound_udp(&reply_raw).expect("expected raw IPv4+UDP reply");
        assert_eq!(parsed_reply.src_port, echo_port);
        assert_eq!(parsed_reply.dst_port, 56010);
        assert_eq!(parsed_reply.payload, b"route-rebind-probe");
        assert!(tun_stats.udp_flows_active.load(Ordering::Relaxed) >= 1);

        route_tx.send(1).unwrap();
        let rebind_deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.udp_flows_active.load(Ordering::Relaxed) > 0 {
            assert!(
                Instant::now() < rebind_deadline,
                "timed out waiting for route change to drain UDP NAT flows"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(ctx.telemetry.udp_flows_active.load(Ordering::Relaxed), 0);

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[test]
    fn active_tcp_guard_decrements_on_normal_drop_and_panic_unwind() {
        let stats = Arc::new(TunStats::default());
        {
            let _g1 = ActiveTcpGuard::enter(&stats);
            let _g2 = ActiveTcpGuard::enter(&stats);
            assert_eq!(stats.active_tcp.load(Ordering::Relaxed), 2);
        }
        assert_eq!(stats.active_tcp.load(Ordering::Relaxed), 0);

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ActiveTcpGuard::enter(&stats);
            assert_eq!(stats.active_tcp.load(Ordering::Relaxed), 1);
            panic!("simulated tcp session panic");
        }));
        assert!(panicked.is_err());
        assert_eq!(stats.active_tcp.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn udp_fast_path_defers_new_flow_to_slow_path_without_blocking() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let nat: UdpNatTable = Arc::new(RwLock::new(HashMap::new()));
        let lru_seq = Arc::new(AtomicU64::new(0));
        let stats = TunStats::default();
        let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 40000);
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);

        assert!(matches!(
            try_forward_udp_fast(b"ping", src, dst, &nat, &lru_seq, &ctx, &stats, 16),
            UdpFastPath::NeedsSlowPath(None)
        ));
        assert!(matches!(
            try_forward_udp_fast(b"ping", src, dst, &nat, &lru_seq, &ctx, &stats, 0),
            UdpFastPath::Done
        ));
        assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 0);
        assert_eq!(stats.tcp_sessions_dropped.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn app_bypass_hook_bypasses_quic_blocking_for_matching_udp_flows() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let observed = Arc::new(std::sync::Mutex::new(Vec::<(IpAddr, u16, bool)>::new()));
        let observed_hook = Arc::clone(&observed);
        let hook = AppBypassHook::new(move |src_ip, src_port, is_udp| {
            observed_hook
                .lock()
                .unwrap()
                .push((src_ip, src_port, is_udp));
            is_udp && src_port == 57000
        });

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline_with_app_bypass(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::DESKTOP,
            stop_rx,
            None,
            Some(hook),
        ));

        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let public_quic = Ipv4Addr::new(162, 159, 135, 232);

        // Bypassed app source port 57000 -> QUIC UDP/443 must NOT be dropped.
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                57000,
                public_quic,
                443,
                &[0xc0u8; 1200],
            ))
            .await
            .unwrap();
        // Non-bypassed app source port 57001 -> QUIC UDP/443 MUST be dropped + ICMP rejected.
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                57001,
                public_quic,
                443,
                &[0xc0u8; 1200],
            ))
            .await
            .unwrap();

        let icmp_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(icmp_raw.len() >= 28);
        assert_eq!(icmp_raw[0] >> 4, 4);
        assert_eq!(icmp_raw[9], 1); // IPv4 ICMP
        assert_eq!(icmp_raw[20], 3); // Destination Unreachable
        assert_eq!(icmp_raw[21], 3); // Port Unreachable
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 1);
        assert_eq!(ctx.telemetry.quic_blocked.load(Ordering::Relaxed), 1);

        let hook_deadline = Instant::now() + Duration::from_secs(2);
        while observed.lock().unwrap().len() < 2 {
            assert!(
                Instant::now() < hook_deadline,
                "timed out waiting for async app_bypass hook calls (got {:?})",
                *observed.lock().unwrap(),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let mut calls = observed.lock().unwrap().clone();
        calls.sort_by_key(|&(_, port, _)| port);
        assert_eq!(
            calls,
            vec![
                (IpAddr::V4(client_ip), 57000, true),
                (IpAddr::V4(client_ip), 57001, true),
            ]
        );

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn app_bypass_hook_bypasses_tcp_dpi_desync_for_matching_tcp_flows() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let observed = Arc::new(std::sync::Mutex::new(Vec::<(IpAddr, u16, bool)>::new()));
        let observed_hook = Arc::clone(&observed);
        let hook = AppBypassHook::new(move |src_ip, src_port, is_udp| {
            observed_hook
                .lock()
                .unwrap()
                .push((src_ip, src_port, is_udp));
            !is_udp && src_port == 58000
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = listener.local_addr().unwrap().port();
        let client_hello = vdpi_core::tls::build_synthetic_client_hello("bypassed.example.com", 0);
        let expected_hello_1 = client_hello.clone();
        let expected_hello_2 = client_hello.clone();

        let server_task = tokio::spawn(async move {
            for expected in [expected_hello_1, expected_hello_2] {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; expected.len()];
                sock.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, expected);
                sock.write_all(b"OK").await.unwrap();
                let _ = sock.shutdown().await;
            }
        });

        let (in_tx, in_rx) = mpsc::channel(128);
        let (out_tx, mut out_rx) = mpsc::channel(128);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline_with_app_bypass(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::STANDARD,
            stop_rx,
            None,
            Some(hook),
        ));

        let client_ip = Ipv4Addr::new(10, 0, 0, 1);

        // Helper performing a raw IPv4 TCP handshake + sending ClientHello + receiving "OK".
        async fn run_raw_tcp_exchange(
            in_tx: &mpsc::Sender<Vec<u8>>,
            out_rx: &mut mpsc::Receiver<Vec<u8>>,
            client_ip: Ipv4Addr,
            client_port: u16,
            server_port: u16,
            payload: &[u8],
        ) {
            let client_isn: u32 = 1000;
            let mut syn = Vec::new();
            PacketBuilder::ipv4(client_ip.octets(), Ipv4Addr::LOCALHOST.octets(), 64)
                .tcp(client_port, server_port, client_isn, 65535)
                .syn()
                .write(&mut syn, &[])
                .unwrap();
            in_tx.send(syn).await.unwrap();

            let server_isn = loop {
                let raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let sliced = SlicedPacket::from_ip(&raw).unwrap();
                if let Some(TransportSlice::Tcp(tcp)) = sliced.transport {
                    if tcp.destination_port() == client_port && tcp.syn() && tcp.ack() {
                        break tcp.sequence_number();
                    }
                }
            };

            let mut ack_and_data = Vec::new();
            PacketBuilder::ipv4(client_ip.octets(), Ipv4Addr::LOCALHOST.octets(), 64)
                .tcp(client_port, server_port, client_isn + 1, 65535)
                .ack(server_isn.wrapping_add(1))
                .psh()
                .write(&mut ack_and_data, payload)
                .unwrap();
            in_tx.send(ack_and_data).await.unwrap();

            let mut received = Vec::new();
            let mut server_next_seq = server_isn.wrapping_add(1);
            let deadline = Instant::now() + Duration::from_secs(3);
            while received.len() < 2 {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let raw = tokio::time::timeout(remaining, out_rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let sliced = SlicedPacket::from_ip(&raw).unwrap();
                if let Some(TransportSlice::Tcp(tcp)) = sliced.transport {
                    if tcp.destination_port() == client_port && !tcp.payload().is_empty() {
                        received.extend_from_slice(tcp.payload());
                        server_next_seq = server_next_seq.wrapping_add(tcp.payload().len() as u32);
                    }
                }
            }
            assert_eq!(received, b"OK");

            let mut fin = Vec::new();
            PacketBuilder::ipv4(client_ip.octets(), Ipv4Addr::LOCALHOST.octets(), 64)
                .tcp(
                    client_port,
                    server_port,
                    client_isn + 1 + payload.len() as u32,
                    65535,
                )
                .ack(server_next_seq)
                .fin()
                .write(&mut fin, &[])
                .unwrap();
            let _ = in_tx.send(fin).await;
        }

        // 1. Bypassed port 58000 -> goes straight through passthrough; tls_handshakes stays 0.
        run_raw_tcp_exchange(
            &in_tx,
            &mut out_rx,
            client_ip,
            58000,
            server_port,
            &client_hello,
        )
        .await;
        assert_eq!(ctx.telemetry.tls_handshakes.load(Ordering::Relaxed), 0);
        // PassthroughCountingStream flushes sub-threshold bytes on EOF/drop rather than
        // Poll::Pending, so allow the closing passthrough task a brief turn to flush.
        let flush_deadline = Instant::now() + Duration::from_secs(2);
        while ctx.telemetry.bytes_tx.load(Ordering::Relaxed) < client_hello.len() as u64
            || ctx.telemetry.bytes_rx.load(Ordering::Relaxed) < 2
        {
            assert!(
                Instant::now() < flush_deadline,
                "timed out waiting for passthrough telemetry flush (tx={}, rx={})",
                ctx.telemetry.bytes_tx.load(Ordering::Relaxed),
                ctx.telemetry.bytes_rx.load(Ordering::Relaxed),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // 2. Non-bypassed port 58001 -> enters normal EngineContext::relay_stream; tls_handshakes becomes 1.
        run_raw_tcp_exchange(
            &in_tx,
            &mut out_rx,
            client_ip,
            58001,
            server_port,
            &client_hello,
        )
        .await;
        assert_eq!(ctx.telemetry.tls_handshakes.load(Ordering::Relaxed), 1);

        server_task.await.unwrap();

        let calls = observed.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                (IpAddr::V4(client_ip), 58000, false),
                (IpAddr::V4(client_ip), 58001, false),
            ]
        );

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
        assert_eq!(ctx.telemetry.active_connections.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn passthrough_copy_buf_preserves_desktop_256k_and_bounds_extremes() {
        assert_eq!(
            passthrough_copy_buf_size(TunProfile::DESKTOP.tcp_relay_buf_size),
            256 * 1024
        );
        assert_eq!(
            passthrough_copy_buf_size(TunProfile::STANDARD.tcp_relay_buf_size),
            32 * 1024
        );
        assert_eq!(
            passthrough_copy_buf_size(TunProfile::LOW_MEMORY.tcp_relay_buf_size),
            16 * 1024
        );
        assert_eq!(passthrough_copy_buf_size(0), MIN_PASSTHROUGH_COPY_BUF);
        assert_eq!(
            passthrough_copy_buf_size(4 * 1024 * 1024),
            MAX_PASSTHROUGH_COPY_BUF
        );
    }

    #[test]
    fn fast_tcp_packet_classifier_distinguishes_tcp_from_udp_and_garbage() {
        let mut ipv4_tcp = vec![0u8; 40];
        ipv4_tcp[0] = 0x45;
        ipv4_tcp[9] = 6;
        assert!(is_fast_tcp_packet(&ipv4_tcp));

        let mut ipv4_udp = ipv4_tcp.clone();
        ipv4_udp[9] = 17;
        assert!(!is_fast_tcp_packet(&ipv4_udp));

        let mut ipv6_tcp = vec![0u8; 60];
        ipv6_tcp[0] = 0x60;
        ipv6_tcp[6] = 6;
        assert!(is_fast_tcp_packet(&ipv6_tcp));

        let mut ipv6_udp = ipv6_tcp.clone();
        ipv6_udp[6] = 17;
        assert!(!is_fast_tcp_packet(&ipv6_udp));

        assert!(!is_fast_tcp_packet(&[]));
        assert!(!is_fast_tcp_packet(&[0x45; 10]));
        assert!(!is_fast_tcp_packet(&[0x60; 20]));
    }

    #[test]
    fn udp_app_bypass_cache_deduplicates_hook_calls_and_enforces_ttl_and_cap() {
        let cache = Arc::new(UdpAppBypassCache::new());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = Instant::now();

        // 1. Cold peek misses without blocking; begin_lookup deduplicates concurrent in-flight keys.
        assert_eq!(cache.peek(ip, 60000, t0), None);
        let tx = match cache.begin_lookup(ip, 60000, t0) {
            UdpBypassLookupState::Start(tx) => tx,
            _ => panic!("expected Start for initial cache miss"),
        };
        let rx_dup = match cache.begin_lookup(ip, 60000, t0) {
            UdpBypassLookupState::InFlight(rx) => rx,
            _ => panic!("expected InFlight deduplication for duplicate key"),
        };

        let guard = InFlightBypassGuard::new(Arc::clone(&cache), ip, 60000, tx);
        cache.insert(ip, 60000, true, false, t0);
        guard.complete(true);
        assert_eq!(*rx_dup.borrow(), Some(true));

        // 2. Exclude mode (default_unknown=false): bypass=true is a guaranteed listed-app match
        //    (3s TTL), while bypass=false may be an unresolved racing socket (500ms TTL).
        assert_eq!(
            cache.peek(ip, 60000, t0 + Duration::from_millis(2999)),
            Some(true)
        );
        assert_eq!(cache.peek(ip, 60000, t0 + UDP_APP_BYPASS_POSITIVE_TTL), None);

        cache.insert(ip, 60001, false, false, t0);
        assert_eq!(
            cache.peek(ip, 60001, t0 + Duration::from_millis(499)),
            Some(false)
        );
        assert_eq!(cache.peek(ip, 60001, t0 + UDP_APP_BYPASS_NEGATIVE_TTL), None);

        // 3. Include mode (default_unknown=true): bypass=false is a confirmed included app
        //    (3s TTL), while bypass=true may be an unresolved racing socket (500ms TTL).
        cache.insert(ip, 60004, false, true, t0);
        assert_eq!(
            cache.peek(ip, 60004, t0 + Duration::from_millis(2999)),
            Some(false)
        );
        assert_eq!(cache.peek(ip, 60004, t0 + UDP_APP_BYPASS_POSITIVE_TTL), None);

        cache.insert(ip, 60005, true, true, t0);
        assert_eq!(
            cache.peek(ip, 60005, t0 + Duration::from_millis(499)),
            Some(true)
        );
        assert_eq!(cache.peek(ip, 60005, t0 + UDP_APP_BYPASS_NEGATIVE_TTL), None);

        cache.insert_unknown(ip, 60002, true, t0);
        assert_eq!(
            cache.peek(ip, 60002, t0 + Duration::from_millis(499)),
            Some(true)
        );
        assert_eq!(cache.peek(ip, 60002, t0 + UDP_APP_BYPASS_NEGATIVE_TTL), None);

        // 4. Dropping InFlightBypassGuard without complete clears in_flight cleanly.
        {
            let tx_abort = match cache.begin_lookup(ip, 60003, t0) {
                UdpBypassLookupState::Start(tx) => tx,
                _ => panic!("expected Start for 60003"),
            };
            let _guard = InFlightBypassGuard::new(Arc::clone(&cache), ip, 60003, tx_abort);
        }
        assert!(matches!(
            cache.begin_lookup(ip, 60003, t0),
            UdpBypassLookupState::Start(_)
        ));
        cache.finish_lookup(ip, 60003);

        // 5. Capacity stays strictly bounded at UDP_APP_BYPASS_CACHE_MAX_ENTRIES.
        let t_cap = t0 + Duration::from_secs(10);
        for idx in 0..(UDP_APP_BYPASS_CACHE_MAX_ENTRIES + 32) {
            cache.insert(
                ip,
                10_000 + idx as u16,
                true,
                false,
                t_cap + Duration::from_millis((idx % 3) as u64),
            );
        }
        assert_eq!(
            cache.entries.read().unwrap().len(),
            UDP_APP_BYPASS_CACHE_MAX_ENTRIES
        );
    }

    #[test]
    fn udp_send_error_classifier_and_unroutable_dst_and_sleep_jump_detector() {
        // Only whole-interface NetworkUnreachable evicts the shared Cone-NAT UDP socket;
        // single-peer HostUnreachable / InvalidInput must NOT evict it.
        assert!(is_fatal_udp_send_error(&std::io::Error::from(
            ErrorKind::NetworkUnreachable
        )));
        assert!(!is_fatal_udp_send_error(&std::io::Error::from(
            ErrorKind::HostUnreachable
        )));
        assert!(!is_fatal_udp_send_error(&std::io::Error::from(
            ErrorKind::InvalidInput
        )));
        #[cfg(windows)]
        {
            assert!(is_fatal_udp_send_error(&std::io::Error::from_raw_os_error(
                10051
            )));
            assert!(!is_fatal_udp_send_error(&std::io::Error::from_raw_os_error(
                10022
            )));
            assert!(!is_fatal_udp_send_error(&std::io::Error::from_raw_os_error(
                10065
            )));
        }

        assert!(is_unroutable_udp_dst(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            0
        )));
        assert!(is_unroutable_udp_dst(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::BROADCAST),
            443
        )));
        assert!(is_unroutable_udp_dst(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            443
        )));
        assert!(!is_unroutable_udp_dst(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            443
        )));

        // SharedStunFlowCache inbound UDP/443 reply refresh keeps listen-only flows alive >120s.
        let shared_stun = SharedStunFlowCache::new();
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 55000);
        let peer_443 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(162, 159, 135, 232)), 443);
        shared_stun.record((client, peer_443), 100);
        shared_stun.refresh_on_inbound_reply(client, peer_443, &[0x80, 0x6f, 0, 1], 210);
        assert!(shared_stun.is_authenticated_and_refresh((client, peer_443), 320));

        // S3 sleep/wake clock-jump detector triggers only when wall-clock exceeds monotonic by >15s.
        let base_wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let base_mono = Instant::now();
        assert!(detect_sleep_wake_jump(
            base_wall,
            base_wall + Duration::from_secs(15),
            base_mono,
            base_mono
        )
        .is_none());
        assert_eq!(
            detect_sleep_wake_jump(
                base_wall,
                base_wall + Duration::from_secs(45),
                base_mono,
                base_mono
            ),
            Some(Duration::from_secs(45))
        );
        assert!(detect_sleep_wake_jump(
            base_wall,
            base_wall - Duration::from_secs(30),
            base_mono,
            base_mono
        )
        .is_none());

        // IPv6 TCP packet with extension headers is recognized by is_fast_tcp_packet.
        let mut v6_ext_tcp = vec![0u8; 68];
        v6_ext_tcp[0] = 0x60;
        v6_ext_tcp[4..6].copy_from_slice(&28u16.to_be_bytes());
        v6_ext_tcp[6] = 0; // Hop-by-Hop
        v6_ext_tcp[40] = 6; // Next Header = TCP
        v6_ext_tcp[41] = 0; // 8-byte Hop-by-Hop
        assert!(is_fast_tcp_packet(&v6_ext_tcp));
    }

    #[tokio::test]
    async fn ipv6_unavailable_emits_icmpv6_no_route_from_tun_gateway_for_happy_eyeballs() {
        #[derive(Debug)]
        struct Ipv4OnlyBinder;

        impl vdpi_core::binder::OutboundBinder for Ipv4OnlyBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                is_ipv4: bool,
            ) -> std::io::Result<()> {
                if is_ipv4 {
                    Ok(())
                } else {
                    Err(std::io::Error::from(ErrorKind::NetworkUnreachable))
                }
            }
        }

        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new_with_binder(
            cfg.into_runtime_config(),
            Some(Arc::new(Ipv4OnlyBinder)),
        )
        .unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline(
            in_rx,
            out_tx,
            ctx,
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::STANDARD,
            stop_rx,
        ));

        let src_v6: std::net::Ipv6Addr = "fd00:7664:7069::1".parse().unwrap();
        let dst_v6: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let gateway_v6: std::net::Ipv6Addr = "fd00:7664:7069::2".parse().unwrap();

        // 1. IPv6 TCP SYN -> immediate ICMPv6 Type 1 Code 0 (No Route) sourced from fd00:7664:7069::2.
        let mut syn_v6 = Vec::new();
        PacketBuilder::ipv6(src_v6.octets(), dst_v6.octets(), 64)
            .tcp(52000, 443, 1, 65535)
            .syn()
            .write(&mut syn_v6, &[])
            .unwrap();
        in_tx.send(syn_v6).await.unwrap();

        let icmp_tcp = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(icmp_tcp[0] >> 4, 6);
        assert_eq!(icmp_tcp[6], 58); // ICMPv6
        assert_eq!(&icmp_tcp[8..24], gateway_v6.octets().as_slice());
        assert_eq!(&icmp_tcp[24..40], src_v6.octets().as_slice());
        assert_eq!(icmp_tcp[40], 1); // Destination Unreachable
        assert_eq!(icmp_tcp[41], 0); // No Route

        // 2. IPv6 non-53 UDP -> immediate ICMPv6 Type 1 Code 0 (No Route).
        let udp_v6 = build_udp_packet(
            SocketAddr::new(IpAddr::V6(src_v6), 52001),
            SocketAddr::new(IpAddr::V6(dst_v6), 443),
            &[0xc0; 32],
        )
        .unwrap();
        in_tx.send(udp_v6).await.unwrap();

        let icmp_udp = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(icmp_udp[0] >> 4, 6);
        assert_eq!(icmp_udp[6], 58);
        assert_eq!(&icmp_udp[8..24], gateway_v6.octets().as_slice());
        assert_eq!(icmp_udp[40], 1);
        assert_eq!(icmp_udp[41], 0);

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn slow_app_bypass_hook_never_stalls_tun_demux_and_deduplicates_inflight() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let hook_calls = Arc::new(AtomicUsize::new(0));
        let hook_entered = Arc::new(AtomicBool::new(false));
        let hook_calls_clone = Arc::clone(&hook_calls);
        let hook_entered_clone = Arc::clone(&hook_entered);
        let hook = AppBypassHook::new(move |_ip, _port, _is_udp| {
            hook_calls_clone.fetch_add(1, Ordering::Relaxed);
            hook_entered_clone.store(true, Ordering::Release);
            let _ = release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(3));
            false
        });

        let (in_tx, in_rx) = mpsc::channel(64);
        let (out_tx, mut out_rx) = mpsc::channel(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline_with_app_bypass(
            in_rx,
            out_tx,
            ctx.clone(),
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            1500,
            TunProfile::DESKTOP,
            stop_rx,
            None,
            Some(hook),
        ));

        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let public_quic = Ipv4Addr::new(162, 159, 135, 232);

        // Send a 4-packet QUIC burst on the same source port while the blocking hook is parked.
        for _ in 0..4 {
            in_tx
                .send(build_ipv4_udp(
                    client_ip,
                    57100,
                    public_quic,
                    443,
                    &[0xc0u8; 1200],
                ))
                .await
                .unwrap();
        }

        // Immediately send a UDP/53 DNS query; it MUST complete while the hook is still blocked.
        let mut dns_q = encode_dns_query("localhost", 1).unwrap();
        dns_q[0] = 0x55;
        dns_q[1] = 0xaa;
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                53100,
                Ipv4Addr::new(10, 0, 0, 2),
                53,
                &dns_q,
            ))
            .await
            .unwrap();

        let dns_reply = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .expect("DNS reply must not stall behind slow app_bypass hook")
            .unwrap();
        let parsed_dns = inspect_inbound_udp(&dns_reply).expect("expected UDP/53 DNS reply");
        assert_eq!(parsed_dns.src_port, 53);
        assert_eq!(parsed_dns.dst_port, 53100);
        assert_eq!(&parsed_dns.payload[0..2], &[0x55, 0xaa]);

        // Wait until the single deduplicated blocking lookup has entered, then unblock it.
        let enter_deadline = Instant::now() + Duration::from_secs(2);
        while !hook_entered.load(Ordering::Acquire) {
            assert!(Instant::now() < enter_deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let _ = release_tx.send(());

        let block_deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.quic_blocked.load(Ordering::Relaxed) < 4 {
            assert!(
                Instant::now() < block_deadline,
                "timed out waiting for deferred QUIC burst drops (got {})",
                tun_stats.quic_blocked.load(Ordering::Relaxed),
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            hook_calls.load(Ordering::Relaxed),
            1,
            "in-flight deduplication must invoke app_bypass hook exactly once per key"
        );

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn route_change_during_udp_bind_aborts_stale_nat_insertion() {
        #[derive(Debug)]
        struct RouteRacingBinder(Arc<AtomicU64>);

        impl vdpi_core::binder::OutboundBinder for RouteRacingBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                // Simulate a route_rx uplink switch completing while the UDP socket is binding.
                self.0.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
        }

        let route_gen = Arc::new(AtomicU64::new(0));
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new_with_binder(
            cfg.into_runtime_config(),
            Some(Arc::new(RouteRacingBinder(Arc::clone(&route_gen)))),
        )
        .unwrap();
        let nat: UdpNatTable = Arc::new(RwLock::new(HashMap::new()));
        let lru_seq = Arc::new(AtomicU64::new(0));
        let stun_flows = Arc::new(SharedStunFlowCache::new());
        let ipv6_unavailable = Arc::new(AtomicBool::new(false));
        let icmp_limiter = Arc::new(IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC));
        let stats = Arc::new(TunStats::default());
        let (out_tx, _out_rx) = mpsc::channel(16);
        let (_stop_tx, stop_rx) = watch::channel(false);

        forward_udp_cone_nat_slow(
            b"stale-route-probe".to_vec(),
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50100),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50101),
            None,
            Arc::clone(&nat),
            lru_seq,
            Arc::clone(&route_gen),
            stun_flows,
            ipv6_unavailable,
            icmp_limiter,
            out_tx,
            ctx.clone(),
            Arc::clone(&stats),
            stop_rx,
            1500,
            16,
            0,
        )
        .await;

        assert_eq!(route_gen.load(Ordering::Acquire), 1);
        assert!(
            nat.read().unwrap().is_empty(),
            "stale socket bound before route_gen change must NOT be inserted into udp_nat"
        );
        assert_eq!(stats.udp_flows_active.load(Ordering::Relaxed), 0);
        assert_eq!(ctx.telemetry.udp_flows_active.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dtls_udp_443_authenticates_flow_for_dtls13_ciphertext_and_srtp() {
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let rdns = ReverseDnsCache::new(64);
        let stats = TunStats::default();
        let events = EventRing::new();
        let stun_flows = SharedStunFlowCache::new();
        let app_bypass_cache = UdpAppBypassCache::new();

        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let peer_ip = Ipv4Addr::new(198, 51, 100, 20);
        let src_dtls = SocketAddr::new(IpAddr::V4(client_ip), 56200);
        let dst_443 = SocketAddr::new(IpAddr::V4(peer_ip), 443);

        // 1. Outbound DTLS 1.2/1.3 ClientHello on UDP/443 records the 4-tuple in stun_flows.
        let mut dtls_hello = [0u8; 20];
        dtls_hello[0] = 0x16;
        dtls_hello[1] = 0xfe;
        dtls_hello[2] = 0xfd;
        let dtls_pkt = build_ipv4_udp(client_ip, 56200, peer_ip, 443, &dtls_hello);
        let dtls_udp = inspect_inbound_udp(&dtls_pkt).unwrap();
        assert_eq!(
            should_drop_inbound_quic(
                &dtls_pkt,
                &dtls_udp,
                src_dtls,
                dst_443,
                &ctx,
                &rdns,
                &stats,
                &events,
                &stun_flows,
                &app_bypass_cache,
                None,
                false,
            ),
            QuicCheckOutcome::Allow
        );
        assert!(stun_flows.is_authenticated_and_refresh((src_dtls, dst_443), now_secs()));

        // 2. Subsequent RFC 9147 DTLS 1.3 unified-header ciphertext (0x2f..) and SRTP (0x80..)
        //    on the authenticated 4-tuple pass through without QUIC blocking.
        for payload in [
            [0x2fu8, 0x00, 0x01, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef].as_slice(),
            [0x80u8, 0x6f, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00].as_slice(),
        ] {
            let pkt = build_ipv4_udp(client_ip, 56200, peer_ip, 443, payload);
            let udp = inspect_inbound_udp(&pkt).unwrap();
            assert_eq!(
                should_drop_inbound_quic(
                    &pkt,
                    &udp,
                    src_dtls,
                    dst_443,
                    &ctx,
                    &rdns,
                    &stats,
                    &events,
                    &stun_flows,
                    &app_bypass_cache,
                    None,
                    false,
                ),
                QuicCheckOutcome::Allow
            );
        }
        assert_eq!(stats.quic_blocked.load(Ordering::Relaxed), 0);

        // 3. Unauthenticated QUIC Initial on a different source port is still dropped.
        let quic_src = SocketAddr::new(IpAddr::V4(client_ip), 56201);
        let quic_pkt = build_ipv4_udp(client_ip, 56201, peer_ip, 443, &[0xc0u8; 1200]);
        let quic_udp = inspect_inbound_udp(&quic_pkt).unwrap();
        assert_eq!(
            should_drop_inbound_quic(
                &quic_pkt,
                &quic_udp,
                quic_src,
                dst_443,
                &ctx,
                &rdns,
                &stats,
                &events,
                &stun_flows,
                &app_bypass_cache,
                None,
                false,
            ),
            QuicCheckOutcome::Drop
        );
        assert_eq!(stats.quic_blocked.load(Ordering::Relaxed), 1);

        // 4. Inbound server DTLS reply on UDP/443 also authenticates/refreshes the flow.
        let src_inbound = SocketAddr::new(IpAddr::V4(client_ip), 56202);
        stun_flows.refresh_on_inbound_reply(src_inbound, dst_443, &dtls_hello, 500);
        assert!(stun_flows.is_authenticated_and_refresh((src_inbound, dst_443), 560));
    }

    #[tokio::test]
    async fn priority_tun_writer_drains_udp_replies_ahead_of_bulk_tcp() {
        let (udp_tx, udp_rx) = mpsc::channel::<Vec<u8>>(16);
        let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(32);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1);
        let (stop_tx, mut stop_rx) = watch::channel(false);

        for i in 0u8..16 {
            tcp_tx.send(vec![0x45, 6, i]).await.unwrap();
        }
        for i in 0u8..4 {
            udp_tx.send(vec![0x45, 17, i]).await.unwrap();
        }
        drop(udp_tx);
        drop(tcp_tx);

        let writer = tokio::spawn(async move {
            run_priority_tun_writer(udp_rx, tcp_rx, out_tx, &mut stop_rx).await
        });

        let mut received = Vec::new();
        while let Some(pkt) = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
        {
            received.push(pkt);
        }

        assert_eq!(received.len(), 20);
        assert!(
            received[..4].iter().all(|pkt| pkt[1] == 17),
            "all queued priority UDP replies must drain ahead of bulk TCP segments: {received:?}"
        );
        assert!(received[4..].iter().all(|pkt| pkt[1] == 6));

        let _ = stop_tx.send(true);
        assert!(!writer.await.unwrap());
    }

    #[tokio::test]
    async fn dropped_packets_counted_on_bind_failure_oversized_reply_and_saturated_dns() {
        // 1. Socket bind failure increments TunStats::dropped_packets.
        #[derive(Debug)]
        struct AlwaysFailBinder;

        impl vdpi_core::binder::OutboundBinder for AlwaysFailBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                Err(std::io::Error::from(ErrorKind::PermissionDenied))
            }
        }

        let fail_cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let fail_ctx = EngineContext::new_with_binder(
            fail_cfg.into_runtime_config(),
            Some(Arc::new(AlwaysFailBinder)),
        )
        .unwrap();
        let bind_stats = Arc::new(TunStats::default());
        let (bind_out_tx, _bind_out_rx) = mpsc::channel(8);
        let (_bind_stop_tx, bind_stop_rx) = watch::channel(false);
        forward_udp_cone_nat_slow(
            b"bind-fail".to_vec(),
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 50200),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50201),
            None,
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(SharedStunFlowCache::new()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC)),
            bind_out_tx,
            fail_ctx,
            Arc::clone(&bind_stats),
            bind_stop_rx,
            1500,
            16,
            0,
        )
        .await;
        assert_eq!(bind_stats.dropped_packets.load(Ordering::Relaxed), 1);

        // 2. Saturated DNS slots (max_dns_inflight = 0) and oversized inbound UDP reply (> MTU).
        let cfg = TunnelConfig {
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let tun_stats = Arc::new(TunStats::default());
        let events = Arc::new(EventRing::new());
        let profile = TunProfile {
            max_dns_inflight: 0,
            ..TunProfile::STANDARD
        };
        let (in_tx, in_rx) = mpsc::channel(32);
        let (out_tx, _out_rx) = mpsc::channel(32);
        let (stop_tx, stop_rx) = watch::channel(false);

        let pipeline = tokio::spawn(run_tun_pipeline(
            in_rx,
            out_tx,
            ctx,
            Arc::clone(&tun_stats),
            Arc::clone(&events),
            MIN_MTU,
            profile,
            stop_rx,
        ));

        let client_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dns_q = encode_dns_query("localhost", 1).unwrap();
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                53200,
                Ipv4Addr::new(10, 0, 0, 2),
                53,
                &dns_q,
            ))
            .await
            .unwrap();

        let dns_deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.dropped_packets.load(Ordering::Relaxed) < 1 {
            assert!(Instant::now() < dns_deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(tun_stats.dropped_packets.load(Ordering::Relaxed), 1);

        // Echo server responds with 1400 bytes > max_udp_payload_for_mtu(MIN_MTU=1280, true) = 1252.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let (_, peer) = echo.recv_from(&mut buf).await.unwrap();
            let oversized = vec![0xabu8; 1400];
            echo.send_to(&oversized, peer).await.unwrap();
        });
        in_tx
            .send(build_ipv4_udp(
                client_ip,
                55200,
                Ipv4Addr::LOCALHOST,
                echo_port,
                b"trigger-oversized",
            ))
            .await
            .unwrap();
        echo_task.await.unwrap();

        let oversize_deadline = Instant::now() + Duration::from_secs(2);
        while tun_stats.dropped_packets.load(Ordering::Relaxed) < 2 {
            assert!(Instant::now() < oversize_deadline);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(tun_stats.dropped_packets.load(Ordering::Relaxed), 2);

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[test]
    fn reverse_dns_cache_enforces_300s_ttl_and_clears_cleanly() {
        let cfg = TunnelConfig {
            enable_doh: false,
            bypass_domains: vec!["cdn.bypass.example".to_string()],
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let cache = ReverseDnsCache::new(64);
        let shared_cdn_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));

        cache.insert_at(shared_cdn_ip, "cdn.bypass.example".to_string(), 1000);
        assert_eq!(
            cache.lookup_at(shared_cdn_ip, 1000 + REVERSE_DNS_TTL_SECS - 1),
            Some("cdn.bypass.example".to_string())
        );
        assert!(
            !cache.should_desync_dst_at(shared_cdn_ip, &ctx, 1000 + REVERSE_DNS_TTL_SECS - 1),
            "fresh reverse-DNS entry must honor domain bypass"
        );

        // At 300s TTL expiry, stale shared-CDN entry expires cleanly.
        assert_eq!(
            cache.lookup_at(shared_cdn_ip, 1000 + REVERSE_DNS_TTL_SECS),
            None
        );
        assert!(
            cache.should_desync_dst_at(shared_cdn_ip, &ctx, 1000 + REVERSE_DNS_TTL_SECS),
            "expired reverse-DNS entry must not suppress desync indefinitely"
        );

        // Explicit clear() (invoked on sleep/wake jump and route change) empties cache immediately.
        cache.insert_at(shared_cdn_ip, "cdn.bypass.example".to_string(), 2000);
        assert!(cache.lookup_at(shared_cdn_ip, 2005).is_some());
        cache.clear();
        assert_eq!(cache.lookup_at(shared_cdn_ip, 2005), None);
    }

    #[test]
    fn ipv6_udp_send_enetunreach_flips_flag_and_emits_icmpv6_no_route() {
        let src_v6: std::net::Ipv6Addr = "fd00:7664:7069::1".parse().unwrap();
        let dst_v6: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        let gateway_v6: std::net::Ipv6Addr = "fd00:7664:7069::2".parse().unwrap();
        let dst_addr = SocketAddr::new(IpAddr::V6(dst_v6), 443);
        let invoking = build_udp_packet(
            SocketAddr::new(IpAddr::V6(src_v6), 52100),
            dst_addr,
            b"v6-udp-probe",
        )
        .unwrap();

        let ipv6_unavailable = AtomicBool::new(false);
        let limiter = IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC);
        let (out_tx, mut out_rx) = mpsc::channel(8);

        // Single-peer HostUnreachable must NOT flip ipv6_unavailable or emit ICMPv6 No Route.
        maybe_handle_ipv6_udp_unreachable(
            dst_addr,
            &std::io::Error::from(ErrorKind::HostUnreachable),
            Some(&invoking),
            &ipv6_unavailable,
            &limiter,
            &out_tx,
        );
        assert!(!ipv6_unavailable.load(Ordering::Relaxed));
        assert!(out_rx.try_recv().is_err());

        // ENETUNREACH / NetworkUnreachable flips ipv6_unavailable and emits ICMPv6 Type 1 Code 0.
        maybe_handle_ipv6_udp_unreachable(
            dst_addr,
            &std::io::Error::from(ErrorKind::NetworkUnreachable),
            Some(&invoking),
            &ipv6_unavailable,
            &limiter,
            &out_tx,
        );
        assert!(ipv6_unavailable.load(Ordering::Relaxed));
        let icmp = out_rx
            .try_recv()
            .expect("expected ICMPv6 No Route after IPv6 ENETUNREACH");
        assert_eq!(icmp[0] >> 4, 6);
        assert_eq!(icmp[6], 58); // ICMPv6
        assert_eq!(&icmp[8..24], gateway_v6.octets().as_slice());
        assert_eq!(&icmp[24..40], src_v6.octets().as_slice());
        assert_eq!(icmp[40], 1); // Destination Unreachable
        assert_eq!(icmp[41], 0); // No Route
    }

    #[test]
    fn udp_byte_batcher_batches_until_64k_or_interval_and_flushes_on_drop() {
        let cfg = TunnelConfig {
            enable_doh: false,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let telemetry = Arc::clone(&ctx.telemetry);

        {
            let mut batcher = UdpByteBatcher::new_at(Arc::clone(&telemetry), 10);

            // First datagram flushes immediately so single-packet flows are visible at once.
            batcher.record_tx(100, 10);
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 100);
            assert!(!batcher.has_pending());

            // Subsequent sub-64 KiB datagrams in the same second stay buffered (zero atomics).
            for _ in 0..60 {
                batcher.record_tx(1000, 10);
            }
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 100);
            assert!(batcher.has_pending());

            // Crossing the 64 KiB threshold flushes the entire batch in one fetch_add.
            batcher.record_tx(6000, 10);
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 66_100);
            assert!(!batcher.has_pending());

            // Sub-threshold RX buffers within the same second, then flushes on interval advance.
            batcher.record_rx(500, 10);
            assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 0);
            batcher.record_rx(200, 10 + UDP_TELEMETRY_FLUSH_INTERVAL_SECS);
            assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 700);

            // Remaining pending bytes flush cleanly on Drop.
            batcher.record_rx(300, 10 + UDP_TELEMETRY_FLUSH_INTERVAL_SECS);
            assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 700);
        }
        assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 1000);
    }

    #[tokio::test]
    async fn include_mode_inflight_waiter_fallback_uses_split_tunnel_unknown_verdict() {
        use vdpi_core::config::{SplitTunnelConfig, SplitTunnelMode};

        let include_cfg = {
            let mut rt = TunnelConfig {
                enable_doh: false,
                block_quic: true,
                ..Default::default()
            }
            .into_runtime_config();
            rt.split_tunnel = SplitTunnelConfig {
                mode: SplitTunnelMode::Include,
                apps: vec!["chrome.exe".to_string()],
            };
            rt
        };
        let include_ctx = EngineContext::new(include_cfg).unwrap();
        assert!(include_ctx.config.split_tunnel.should_bypass_app(None));

        let exclude_cfg = {
            let mut rt = TunnelConfig {
                enable_doh: false,
                block_quic: true,
                ..Default::default()
            }
            .into_runtime_config();
            rt.split_tunnel = SplitTunnelConfig {
                mode: SplitTunnelMode::Exclude,
                apps: vec!["discord.exe".to_string()],
            };
            rt
        };
        let exclude_ctx = EngineContext::new(exclude_cfg).unwrap();
        assert!(!exclude_ctx.config.split_tunnel.should_bypass_app(None));

        let cache = Arc::new(UdpAppBypassCache::new());
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = Instant::now();

        let tx = match cache.begin_lookup(ip, 61000, t0) {
            UdpBypassLookupState::Start(tx) => tx,
            _ => panic!("expected Start"),
        };
        let mut rx = match cache.begin_lookup(ip, 61000, t0) {
            UdpBypassLookupState::InFlight(rx) => rx,
            _ => panic!("expected InFlight"),
        };
        let guard = InFlightBypassGuard::new(Arc::clone(&cache), ip, 61000, tx);
        drop(guard);

        let wait_res = rx.wait_for(|v| v.is_some()).await.ok().and_then(|v| *v);
        assert_eq!(wait_res, None);

        let include_fallback = cache
            .peek(ip, 61000, Instant::now())
            .unwrap_or_else(|| include_ctx.config.split_tunnel.should_bypass_app(None));
        assert!(
            include_fallback,
            "Include-mode InFlight waiter fallback must bypass unknown apps"
        );

        let exclude_fallback = cache
            .peek(ip, 61000, Instant::now())
            .unwrap_or_else(|| exclude_ctx.config.split_tunnel.should_bypass_app(None));
        assert!(
            !exclude_fallback,
            "Exclude-mode InFlight waiter fallback must keep desync/block for unknown apps"
        );
    }

    #[tokio::test]
    async fn priority_tun_writer_caps_bulk_tcp_queue_at_64_for_low_latency_udp() {
        const OUTBOUND_CAP: usize = 64;
        const TCP_TOTAL: usize = 128;
        const UDP_TOTAL: usize = 3;

        let (udp_tx, udp_rx) = mpsc::channel::<Vec<u8>>(16);
        let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(256);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CAP);
        let out_tx_probe = out_tx.clone();
        let (stop_tx, mut stop_rx) = watch::channel(false);

        for i in 0u8..(TCP_TOTAL as u8) {
            tcp_tx.send(vec![0x45, 6, i]).await.unwrap();
        }

        let writer = tokio::spawn(async move {
            run_priority_tun_writer(udp_rx, tcp_rx, out_tx, &mut stop_rx).await
        });

        // Wait for the writer to saturate the bounded outbound channel via event-driven reserve().
        let cap_deadline = Instant::now() + Duration::from_secs(2);
        while out_tx_probe.capacity() > 0
            || tcp_tx.max_capacity().saturating_sub(tcp_tx.capacity()) > TCP_TOTAL - OUTBOUND_CAP
        {
            assert!(Instant::now() < cap_deadline);
            tokio::task::yield_now().await;
        }
        assert_eq!(out_tx_probe.capacity(), 0);
        assert_eq!(
            tcp_tx.max_capacity().saturating_sub(tcp_tx.capacity()),
            TCP_TOTAL - OUTBOUND_CAP,
            "bulk TCP must block on bounded outbound_tx capacity ({OUTBOUND_CAP}) via reserve()"
        );
        drop(tcp_tx);

        // Enqueue high-priority UDP replies while outbound_tx is full and parked on reserve().
        for i in 0u8..(UDP_TOTAL as u8) {
            udp_tx.send(vec![0x45, 17, i]).await.unwrap();
        }
        drop(udp_tx);

        // Free one downstream slot and verify immediate zero-sleep event-driven wakeup.
        let drain_start = Instant::now();
        let first = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first[1], 6);

        let wakeup_start = Instant::now();
        let wakeup_deadline = wakeup_start + Duration::from_secs(2);
        while out_tx_probe.capacity() > 0 {
            assert!(Instant::now() < wakeup_deadline);
            tokio::task::yield_now().await;
        }
        assert!(
            wakeup_start.elapsed() < Duration::from_millis(200),
            "reserve() must wake immediately when a downstream slot opens without timer sleep"
        );
        drop(out_tx_probe);

        let mut received = Vec::with_capacity(TCP_TOTAL + UDP_TOTAL);
        received.push(first);
        while let Some(pkt) = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
        {
            received.push(pkt);
        }
        let drain_elapsed = drain_start.elapsed();

        assert_eq!(received.len(), TCP_TOTAL + UDP_TOTAL);
        assert!(received[..OUTBOUND_CAP].iter().all(|pkt| pkt[1] == 6));
        assert!(
            received[OUTBOUND_CAP..OUTBOUND_CAP + UDP_TOTAL]
                .iter()
                .all(|pkt| pkt[1] == 17),
            "UDP replies arriving during saturated TCP must preempt remaining TCP backlog"
        );
        assert!(received[OUTBOUND_CAP + UDP_TOTAL..]
            .iter()
            .all(|pkt| pkt[1] == 6));
        assert!(
            drain_elapsed < Duration::from_millis(500),
            "event-driven reserve() backpressure must not stall on timer-wheel sleeps (took {drain_elapsed:?})"
        );

        let _ = stop_tx.send(true);
        assert!(!writer.await.unwrap());
    }

    #[test]
    fn touch_udp_nat_activity_bumps_lru_seq_at_most_once_per_second() {
        let last_active = AtomicU64::new(100);
        let last_seq = AtomicU64::new(1);
        let lru_seq = AtomicU64::new(1);

        for _ in 0..1000 {
            touch_udp_nat_activity(&last_active, &last_seq, &lru_seq, 100);
        }
        assert_eq!(last_active.load(Ordering::Relaxed), 100);
        assert_eq!(last_seq.load(Ordering::Relaxed), 1);
        assert_eq!(lru_seq.load(Ordering::Relaxed), 1);

        for _ in 0..100 {
            touch_udp_nat_activity(&last_active, &last_seq, &lru_seq, 101);
        }
        assert_eq!(last_active.load(Ordering::Relaxed), 101);
        assert_eq!(last_seq.load(Ordering::Relaxed), 2);
        assert_eq!(lru_seq.load(Ordering::Relaxed), 2);

        touch_udp_nat_activity(&last_active, &last_seq, &lru_seq, 102);
        assert_eq!(last_active.load(Ordering::Relaxed), 102);
        assert_eq!(last_seq.load(Ordering::Relaxed), 3);
        assert_eq!(lru_seq.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn passthrough_counting_stream_poll_flush_batches_until_threshold_and_flushes_on_shutdown_and_drop(
    ) {
        let cfg = TunnelConfig {
            enable_doh: false,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
        let telemetry = Arc::clone(&ctx.telemetry);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sink_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut drain = Vec::new();
                let _ = sock.read_to_end(&mut drain).await;
            }
        });

        let active = AtomicBool::new(false);

        {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut counted = PassthroughCountingStream::new(stream, &telemetry, &active, 1024);

            counted.write_all(&[0x41u8; 100]).await.unwrap();
            counted.flush().await.unwrap();
            assert_eq!(
                telemetry.bytes_tx.load(Ordering::Relaxed),
                0,
                "poll_flush must not flush sub-threshold pending_tx"
            );

            counted.write_all(&[0x42u8; 1000]).await.unwrap();
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 1100);

            counted.write_all(&[0x43u8; 50]).await.unwrap();
            counted.flush().await.unwrap();
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 1100);

            counted.shutdown().await.unwrap();
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 1150);
        }

        {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut counted = PassthroughCountingStream::new(stream, &telemetry, &active, 1024);
            counted.write_all(&[0x44u8; 75]).await.unwrap();
            counted.flush().await.unwrap();
            assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 1150);
        }
        assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 1225);

        sink_task.await.unwrap();
    }

    #[tokio::test]
    async fn priority_tun_writer_fair_udp_quota_prevents_tcp_starvation_and_preempts_bulk_tcp() {
        // 1. Continuous UDP flood must yield at least 1 TCP packet every MAX_CONSECUTIVE_UDP_PACKETS
        //    so TCP ACKs can never be starved by unblocked QUIC / uTP traffic.
        const UDP_FLOOD: usize = MAX_CONSECUTIVE_UDP_PACKETS * 4;
        const TCP_ACKS: usize = 8;

        let (udp_tx, udp_rx) = mpsc::channel::<Vec<u8>>(UDP_FLOOD);
        let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(TCP_ACKS);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(1);
        let (stop_tx, mut stop_rx) = watch::channel(false);

        for i in 0..UDP_FLOOD {
            udp_tx.send(vec![0x45, 17, i as u8]).await.unwrap();
        }
        for i in 0..TCP_ACKS {
            tcp_tx.send(vec![0x45, 6, i as u8]).await.unwrap();
        }
        drop(udp_tx);
        drop(tcp_tx);

        let writer = tokio::spawn(async move {
            run_priority_tun_writer(udp_rx, tcp_rx, out_tx, &mut stop_rx).await
        });

        let mut received = Vec::with_capacity(UDP_FLOOD + TCP_ACKS);
        while let Some(pkt) = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
        {
            received.push(pkt);
        }

        assert_eq!(received.len(), UDP_FLOOD + TCP_ACKS);

        let mut max_udp_run = 0usize;
        let mut current_udp_run = 0usize;
        let mut udp_seq = Vec::with_capacity(UDP_FLOOD);
        let mut tcp_seq = Vec::with_capacity(TCP_ACKS);
        let mut tcp_seen_before_udp_done = 0usize;

        for pkt in &received {
            if pkt[1] == 17 {
                current_udp_run += 1;
                max_udp_run = max_udp_run.max(current_udp_run);
                udp_seq.push(pkt[2]);
            } else {
                assert_eq!(pkt[1], 6);
                current_udp_run = 0;
                if udp_seq.len() < UDP_FLOOD {
                    tcp_seen_before_udp_done += 1;
                }
                tcp_seq.push(pkt[2]);
            }
        }

        assert_eq!(
            max_udp_run, MAX_CONSECUTIVE_UDP_PACKETS,
            "continuous UDP flood must yield to TCP after exactly {MAX_CONSECUTIVE_UDP_PACKETS} packets"
        );
        assert_eq!(
            tcp_seen_before_udp_done, 3,
            "TCP ACKs must make steady progress during a 64-packet UDP flood"
        );
        assert_eq!(
            received[MAX_CONSECUTIVE_UDP_PACKETS][1], 6,
            "first TCP ACK must be yielded right after the first {MAX_CONSECUTIVE_UDP_PACKETS} UDP packets"
        );
        assert_eq!(udp_seq, (0..UDP_FLOOD as u8).collect::<Vec<_>>());
        assert_eq!(tcp_seq, (0..TCP_ACKS as u8).collect::<Vec<_>>());

        let _ = stop_tx.send(true);
        assert!(!writer.await.unwrap());

        // 2. Voice/game UDP bursts arriving under bulk TCP load must still preempt queued TCP immediately.
        const OUTBOUND_CAP: usize = 4;
        const BULK_TCP: usize = 32;
        const VOICE_UDP: usize = 4;

        let (udp_tx, udp_rx) = mpsc::channel::<Vec<u8>>(16);
        let (tcp_tx, tcp_rx) = mpsc::channel::<Vec<u8>>(BULK_TCP);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(OUTBOUND_CAP);
        let out_tx_probe = out_tx.clone();
        let (stop_tx, mut stop_rx) = watch::channel(false);

        for i in 0..BULK_TCP {
            tcp_tx.send(vec![0x45, 6, i as u8]).await.unwrap();
        }

        let writer = tokio::spawn(async move {
            run_priority_tun_writer(udp_rx, tcp_rx, out_tx, &mut stop_rx).await
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while out_tx_probe.capacity() > 0
            || tcp_tx.max_capacity().saturating_sub(tcp_tx.capacity()) > BULK_TCP - OUTBOUND_CAP
        {
            assert!(Instant::now() < deadline);
            tokio::task::yield_now().await;
        }
        drop(out_tx_probe);
        drop(tcp_tx);

        for i in 0..VOICE_UDP {
            udp_tx.send(vec![0x45, 17, i as u8]).await.unwrap();
        }
        drop(udp_tx);

        let mut preempted = Vec::with_capacity(BULK_TCP + VOICE_UDP);
        while let Some(pkt) = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
            .await
            .unwrap()
        {
            preempted.push(pkt);
        }

        assert_eq!(preempted.len(), BULK_TCP + VOICE_UDP);
        assert!(preempted[..OUTBOUND_CAP].iter().all(|pkt| pkt[1] == 6));
        assert!(
            preempted[OUTBOUND_CAP..OUTBOUND_CAP + VOICE_UDP]
                .iter()
                .all(|pkt| pkt[1] == 17),
            "voice/game UDP burst must immediately preempt remaining bulk TCP backlog: {preempted:?}"
        );
        assert!(preempted[OUTBOUND_CAP + VOICE_UDP..]
            .iter()
            .all(|pkt| pkt[1] == 6));

        let _ = stop_tx.send(true);
        assert!(!writer.await.unwrap());
    }
}
