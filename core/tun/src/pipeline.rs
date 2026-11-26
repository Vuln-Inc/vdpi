use crate::config::{TunProfile, MAX_MTU, MIN_MTU};
use crate::events::EventRing;
use crate::netstack::{spawn_tcp_netstack, TunNetstackTcpStream};
use crate::packet::{
    build_icmp_port_unreachable, build_truncated_dns_reply, max_dns_udp_payload_for_mtu,
    max_udp_payload_for_mtu,
};
use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::AbortHandle;
use tracing::debug;
use vdpi_core::desync::{EngineContext, EngineTelemetry, LearnedStrategy};

pub use crate::config::{AppBypassFn, AppBypassHook};
pub use crate::packet::{
    build_udp_packet, inspect_inbound_udp, is_blocked_quic_udp, is_stun_packet,
    is_valid_inbound_tun_packet, InboundUdpPacket,
};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_REAPER_INTERVAL: Duration = Duration::from_secs(15);
const MAX_QUIC_ICMP_PER_SEC: u64 = 64;
const TCP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_SLOT_ACQUIRE_TIMEOUT: Duration = Duration::from_millis(250);
const PASSTHROUGH_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const STUN_FLOW_MAX_ENTRIES: usize = 256;
const STUN_FLOW_TTL_SECS: u64 = 120;

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
    map: RwLock<HashMap<IpAddr, String>>,
}

impl ReverseDnsCache {
    fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(32),
            map: RwLock::new(HashMap::new()),
        }
    }

    fn insert(&self, ip: IpAddr, domain: String) {
        let mut guard = self
            .map
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.len() >= self.max_entries && !guard.contains_key(&ip) {
            if let Some(victim) = guard.keys().next().copied() {
                guard.remove(&victim);
            }
        }
        guard.insert(ip, domain);
    }

    fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.map
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ip)
            .cloned()
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
/// RFC 5389 STUN packet, allowing subsequent WebRTC TURN ChannelData / DTLS / SRTP
/// datagrams on the same 4-tuple to pass through QUIC UDP/443 blocking.
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

fn drain_udp_nat(udp_nat: &UdpNatTable, stats: &TunStats, ctx: &EngineContext) -> usize {
    let mut guard = udp_nat
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let drained = guard.len();
    for (_, entry) in guard.drain() {
        entry.abort.abort();
    }
    store_udp_flows_active(0, stats, ctx);
    drained
}

fn is_fatal_udp_send_error(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::InvalidInput
    ) {
        return true;
    }
    #[cfg(unix)]
    if matches!(
        err.raw_os_error(),
        Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EINVAL)
    ) {
        return true;
    }
    #[cfg(windows)]
    if matches!(err.raw_os_error(), Some(10022 | 10051 | 10065)) {
        return true;
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

/// Evaluates whether an inbound UDP/443 datagram should be dropped as QUIC, exempting
/// RFC 5389 STUN packets, subsequent TURN ChannelData / DTLS / SRTP packets on
/// STUN-authenticated `(src_addr, dst_addr)` flows, and app-bypassed flows. Optionally emits
/// a rate-limited ICMP Port Unreachable reply for sub-50ms browser TCP/TLS fallback.
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
    stun_flows: &mut StunFlowCache,
    icmp_reject: Option<(&IcmpRateLimiter, &mpsc::Sender<Vec<u8>>)>,
    app_bypass: Option<&AppBypassHook>,
) -> bool {
    if udp.dst_port != 443 {
        return false;
    }
    let now = now_secs();
    if is_stun_packet(udp.payload) {
        stun_flows.record((src_addr, dst_addr), now);
        return false;
    }
    if stun_flows.is_authenticated_and_refresh((src_addr, dst_addr), now) {
        return false;
    }
    if !ctx.config.block_quic || !is_blocked_quic_udp(udp.dst_port, udp.payload) {
        return false;
    }
    let known_host = rdns.lookup(udp.dst_ip);
    if !ctx
        .bypass
        .should_desync(known_host.as_deref(), Some(udp.dst_ip))
    {
        return false;
    }
    if let Some(hook) = app_bypass {
        if hook.should_bypass(udp.src_ip, udp.src_port, true) {
            return false;
        }
    }

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
    true
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

    let (mut tcp_stream_rx, netstack_handle) = spawn_tcp_netstack(
        tcp_in_rx,
        outbound_tx.clone(),
        clamped_mtu,
        profile.tcp_recv_buffer_size as usize,
        profile.tcp_send_buffer_size as usize,
        profile.max_tcp_sessions,
        profile.channel_capacity.clamp(128, 512),
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
    let observed_stage = Arc::new(AtomicU8::new(ctx.preferred_stage() as u8));

    // Task 1: Zero-lag TUN ingress demux — inspect UDP ONCE and bypass smoltcp completely
    // for DNS/53, QUIC/443 (with STUN/TURN pass-through), and Cone-NAT UDP; hand TCP
    // packets to smoltcp via non-blocking `try_send` so TCP congestion never stalls DNS/UDP.
    let in_ctx = ctx.clone();
    let in_rdns = Arc::clone(&reverse_dns);
    let in_stats = Arc::clone(&tun_stats);
    let in_events = Arc::clone(&events);
    let in_outbound_tx = outbound_tx.clone();
    let in_dns_slots = Arc::clone(&dns_slots);
    let in_udp_slow_slots = Arc::clone(&udp_slow_slots);
    let in_udp_nat = Arc::clone(&udp_nat);
    let in_udp_lru_seq = Arc::clone(&udp_lru_seq);
    let in_app_bypass = app_bypass.clone();
    let in_stop_root = internal_stop_rx.clone();
    let emit_quic_icmp_reject = profile.emit_quic_icmp_reject;
    let max_udp_flows = profile.max_udp_flows;
    let udp_socket_buf_bytes = profile.udp_socket_buf_bytes;
    let quic_icmp_limiter = IcmpRateLimiter::new(MAX_QUIC_ICMP_PER_SEC);
    let mut stop_in = internal_stop_rx.clone();
    let in_stop_tx = internal_stop_tx.clone();
    let tun_to_stack = tokio::spawn(async move {
        let mut stun_flows = StunFlowCache::new();
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_in) => break,
                pkt = inbound_rx.recv() => {
                    let Some(pkt) = pkt else {
                        let _ = in_stop_tx.send(true);
                        break;
                    };

                    if let Some(udp) = inspect_inbound_udp(&pkt) {
                        let src_addr = SocketAddr::new(udp.src_ip, udp.src_port);
                        let dst_addr = SocketAddr::new(udp.dst_ip, udp.dst_port);

                        // 1. UDP/53 DNS -> bounded DoH handler synthesizing raw IP+UDP reply onto outbound_tx
                        if udp.dst_port == 53 {
                            let Ok(permit) = in_dns_slots.clone().try_acquire_owned() else {
                                continue;
                            };
                            let query = udp.payload.to_vec();
                            let dns_ctx = in_ctx.clone();
                            let rdns = Arc::clone(&in_rdns);
                            let reply_out_tx = in_outbound_tx.clone();
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

                        // 2. UDP/443 QUIC block (exempting RFC 5389 STUN and STUN-authenticated TURN/DTLS/SRTP flows)
                        let icmp_reject =
                            emit_quic_icmp_reject.then_some((&quic_icmp_limiter, &in_outbound_tx));
                        if should_drop_inbound_quic(
                            &pkt,
                            &udp,
                            src_addr,
                            dst_addr,
                            &in_ctx,
                            &in_rdns,
                            &in_stats,
                            &in_events,
                            &mut stun_flows,
                            icmp_reject,
                            in_app_bypass.as_ref(),
                        ) {
                            continue;
                        }

                        // 3. Direct Cone-NAT UDP relay: synchronous non-blocking fast path inline;
                        //    socket bind / WouldBlock slow paths run on bounded spawned tasks so
                        //    UDP bursts never stall DNS or TCP demuxing.
                        if let UdpFastPath::NeedsSlowPath(existing) = try_forward_udp_fast(
                            udp.payload,
                            src_addr,
                            dst_addr,
                            &in_udp_nat,
                            &in_udp_lru_seq,
                            &in_ctx,
                            &in_stats,
                            max_udp_flows,
                        ) {
                            let Ok(permit) = in_udp_slow_slots.clone().try_acquire_owned() else {
                                in_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
                                continue;
                            };
                            let payload = udp.payload.to_vec();
                            let nat = Arc::clone(&in_udp_nat);
                            let lru_seq = Arc::clone(&in_udp_lru_seq);
                            let reply_out_tx = in_outbound_tx.clone();
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
                                        src_addr,
                                        dst_addr,
                                        existing,
                                        nat,
                                        lru_seq,
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
                        continue;
                    }

                    if !matches!(pkt.first().map(|b| b >> 4), Some(4 | 6)) {
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
                            break;
                        }
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
                        let bypass_dpi = conn_app_bypass
                            .as_ref()
                            .is_some_and(|hook| hook.should_bypass(src.ip(), src.port(), false));
                        let known_host = rdns.lookup(dst.ip());
                        let upstream_res = match conn_ctx.connect_upstream_addr(dst).await {
                            Ok(remote) => Ok((remote, dst)),
                            Err(primary_err) => {
                                // On IPv4-only networks, cached IPv6 addresses from before
                                // tunnel start fail with ENETUNREACH after smoltcp has
                                // already accepted the local TCP SYN. Rescue over IPv4.
                                if dst.is_ipv6() {
                                    if let Some(host) = known_host.as_deref() {
                                        match resolve_and_connect_ipv4(&conn_ctx, host, dst.port()).await {
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
                        };
                        match upstream_res {
                            Ok((remote, effective_dst)) => {
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

    // Task 4: Shared 15s UDP Cone NAT idle reaper (replaces per-packet Tokio timers)
    let reaper_nat = Arc::clone(&udp_nat);
    let reaper_stats = Arc::clone(&tun_stats);
    let reaper_ctx = ctx.clone();
    let mut stop_reaper = internal_stop_rx.clone();
    let udp_reaper_task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(UDP_REAPER_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_reaper) => break,
                _ = ticker.tick() => {
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
    });

    let _abort_guard = PipelineAbortGuard {
        handles: vec![
            stop_bridge.abort_handle(),
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
                let route_gen = route_rx.as_ref().map(|rx| *rx.borrow()).unwrap_or(0);
                let drained = drain_udp_nat(&udp_nat, &tun_stats, &ctx);
                if drained > 0 {
                    events.push(
                        "info",
                        "udp",
                        format!("route change (gen {route_gen}): rebound {drained} UDP NAT flows"),
                    );
                }
            }
        }
    }

    stop_bridge.abort();
    tun_to_stack.abort();
    tcp_accept_task.abort();
    udp_reaper_task.abort();
    runner_handle.abort();

    // Abort every Cone NAT reader task cleanly before clearing table.
    let _ = drain_udp_nat(&udp_nat, &tun_stats, &ctx);

    crate::flush_engine_cache(&ctx).await;

    if *shutdown_rx.borrow() {
        Ok(())
    } else {
        Err(anyhow!("TUN pipeline terminated unexpectedly"))
    }
}

struct PassthroughCountingStream {
    inner: tokio::net::TcpStream,
    telemetry: Arc<EngineTelemetry>,
    started: Instant,
    last_activity_ms: Arc<AtomicU64>,
}

impl AsyncRead for PassthroughCountingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read_bytes = buf.filled().len().saturating_sub(before);
            if read_bytes > 0 {
                this.telemetry
                    .bytes_rx
                    .fetch_add(read_bytes as u64, Ordering::Relaxed);
                let elapsed_ms =
                    u64::try_from(this.started.elapsed().as_millis()).unwrap_or(u64::MAX);
                this.last_activity_ms.store(elapsed_ms, Ordering::Relaxed);
            }
        }
        poll
    }
}

impl AsyncWrite for PassthroughCountingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                this.telemetry
                    .bytes_tx
                    .fetch_add(*n as u64, Ordering::Relaxed);
                let elapsed_ms =
                    u64::try_from(this.started.elapsed().as_millis()).unwrap_or(u64::MAX);
                this.last_activity_ms.store(elapsed_ms, Ordering::Relaxed);
            }
        }
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
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

    let started = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));
    let mut counted_remote = PassthroughCountingStream {
        inner: remote,
        telemetry: Arc::clone(&ctx.telemetry),
        started,
        last_activity_ms: Arc::clone(&last_activity_ms),
    };

    let idle_watcher = async {
        let timeout_ms = u64::try_from(PASSTHROUGH_IDLE_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let last_ms = last_activity_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_ms) >= timeout_ms {
                break;
            }
        }
    };

    let copy_buf = buf_size.clamp(16 * 1024, 128 * 1024);
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
    Done,
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
    if src_addr.is_ipv4() != dst_addr.is_ipv4() {
        return UdpFastPath::Done;
    }

    let key = (src_addr, dst_addr.is_ipv4());
    let existing = {
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

    let Some((outbound, last_active_secs, last_seq)) = existing else {
        if max_udp_flows == 0 {
            return UdpFastPath::Done;
        }
        return UdpFastPath::NeedsSlowPath(None);
    };

    match outbound.try_send_to(payload, dst_addr) {
        Ok(_) => {
            last_active_secs.store(now_secs(), Ordering::Relaxed);
            last_seq.store(
                lru_seq.fetch_add(1, Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
            ctx.add_udp_bytes(payload.len() as u64, 0);
            UdpFastPath::Done
        }
        Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
            UdpFastPath::NeedsSlowPath(Some((outbound, last_active_secs, last_seq)))
        }
        Err(e) if is_fatal_udp_send_error(&e) => {
            debug!(%dst_addr, error = %e, "evicting dead UDP NAT entry after fatal send error");
            evict_udp_nat_entry(nat, key, &outbound, stats, ctx);
            UdpFastPath::Done
        }
        Err(_) => UdpFastPath::Done,
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_udp_cone_nat_slow(
    payload: Vec<u8>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    existing: Option<UdpNatHandle>,
    nat: UdpNatTable,
    lru_seq: Arc<AtomicU64>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    stats: Arc<TunStats>,
    shutdown_rx: watch::Receiver<bool>,
    mtu: usize,
    max_udp_flows: usize,
    udp_socket_buf_bytes: usize,
) {
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
                // Bind outside the write lock to avoid blocking concurrent UDP lookups.
                let Ok(bound) =
                    bind_udp_socket_strict(&ctx, dst_addr.is_ipv4(), udp_socket_buf_bytes)
                else {
                    return;
                };

                let mut guard = nat
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if *shutdown_rx.borrow() {
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
                        loop {
                            tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut rx_stop) => break,
                                res = rx_sock.recv_from(&mut buf) => {
                                    match res {
                                        Ok((n, remote_src)) if n > 0 => {
                                            let canonical_ip = remote_src.ip().to_canonical();
                                            if canonical_ip.is_ipv4() != expect_ipv4 || n > max_reply {
                                                continue;
                                            }
                                            let clean_src = SocketAddr::new(canonical_ip, remote_src.port());
                                            rx_last.store(now_secs(), Ordering::Relaxed);
                                            rx_last_seq.store(
                                                rx_lru_seq.fetch_add(1, Ordering::Relaxed) + 1,
                                                Ordering::Relaxed,
                                            );
                                            rx_ctx.add_udp_bytes(0, n as u64);
                                            if let Some(raw_pkt) = build_udp_packet(clean_src, src_addr, &buf[..n]) {
                                                match rx_outbound_tx.try_send(raw_pkt) {
                                                    Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                                                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                                                }
                                            }
                                        }
                                        Ok(_) => continue,
                                        Err(e) if is_transient_udp_recv_error(&e) => continue,
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
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
            last_active_secs.store(now_secs(), Ordering::Relaxed);
            last_seq.store(
                lru_seq.fetch_add(1, Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
            ctx.add_udp_bytes(payload.len() as u64, 0);
        }
        Err(e) if is_fatal_udp_send_error(&e) => {
            debug!(%dst_addr, error = %e, "evicting dead UDP NAT entry after fatal send error");
            evict_udp_nat_entry(&nat, key, &outbound, &stats, &ctx);
        }
        Err(_) => {}
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
        let mut flows: HashMap<u32, u64> = HashMap::from([(1, 10), (2, 40), (3, 95), (4, 100)]);
        let mut evicted = Vec::new();
        let remaining = reap_idle_udp_nat(
            &mut flows,
            100,
            UDP_IDLE_TIMEOUT.as_secs(),
            |ts| *ts,
            |ts| evicted.push(ts),
        );
        assert_eq!(remaining, 2);
        assert!(flows.contains_key(&3));
        assert!(flows.contains_key(&4));
        evicted.sort_unstable();
        assert_eq!(evicted, vec![10, 40]);
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
        let reply_raw = tokio::time::timeout(Duration::from_secs(3), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
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

        let calls = observed.lock().unwrap().clone();
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
        assert!(ctx.telemetry.bytes_tx.load(Ordering::Relaxed) >= client_hello.len() as u64);
        assert!(ctx.telemetry.bytes_rx.load(Ordering::Relaxed) >= 2);

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
}
