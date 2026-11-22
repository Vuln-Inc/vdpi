use crate::config::{TunProfile, MAX_MTU, MIN_MTU};
use crate::events::EventRing;
use anyhow::{anyhow, Context, Result};
use etherparse::{SlicedPacket, TransportSlice};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, RwLock, Semaphore};
use tokio::task::AbortHandle;
use tracing::debug;
use vdpi::desync::{EngineContext, LearnedStrategy};

const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_RECV_BUF_BYTES: usize = 4096;

#[derive(Debug, Default)]
pub struct TunStats {
    pub quic_blocked: AtomicU64,
    pub udp_flows_active: AtomicU64,
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

    async fn insert(&self, ip: IpAddr, domain: String) {
        let mut guard = self.map.write().await;
        if guard.len() >= self.max_entries && !guard.contains_key(&ip) {
            if let Some(victim) = guard.keys().next().copied() {
                guard.remove(&victim);
            }
        }
        guard.insert(ip, domain);
    }

    async fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.map.read().await.get(&ip).cloned()
    }
}

struct UdpNatEntry {
    socket: Arc<UdpSocket>,
    last_active_secs: Arc<AtomicU64>,
    abort: AbortHandle,
}

type UdpNatTable = Arc<RwLock<HashMap<(SocketAddr, bool), UdpNatEntry>>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

/// Validates an inbound IP packet read from TUN *before* feeding it into `netstack-smoltcp`.
/// Critically, `netstack-smoltcp`'s `udp::ReadHalf` terminates its Stream (returns `None`)
/// on any IPv4-fragmented or malformed UDP packet; filtering them here keeps UDP & DNS alive.
pub fn is_valid_inbound_tun_packet(pkt: &[u8]) -> bool {
    if pkt.len() < 20 {
        return false;
    }
    let version = pkt[0] >> 4;
    if version != 4 && version != 6 {
        return false;
    }
    let Ok(sliced) = SlicedPacket::from_ip(pkt) else {
        return false;
    };
    if let Some(etherparse::NetSlice::Ipv4(v4)) = &sliced.net {
        if v4.header().is_fragmenting_payload() {
            return false;
        }
    }
    if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
        let declared = usize::from(udp.length());
        let actual = 8 + udp.payload().len();
        if declared < 8 || declared != actual {
            return false;
        }
    }
    true
}

/// Detects whether a UDP/443 payload looks like QUIC traffic (including RFC 9000 Long Header
/// `0xc0`, RFC 9287 Greased Fixed-Bit Long Header `0x80`, and Short-Header 1-RTT packets).
/// When `block_quic` is enabled on a mobile TUN, dropping *all* non-empty UDP/443 datagrams for
/// desync-eligible hosts prevents half-open or migrated QUIC sessions that otherwise trigger
/// Chrome `ERR_QUIC_PROTOCOL_ERROR` instead of a clean TCP/TLS fallback.
pub fn is_blocked_quic_udp(dst_port: u16, payload: &[u8]) -> bool {
    dst_port == 443 && !payload.is_empty()
}

fn max_udp_payload_for_mtu(mtu: usize, is_ipv4: bool) -> usize {
    let overhead = if is_ipv4 { 20 + 8 } else { 40 + 8 };
    mtu.saturating_sub(overhead)
}

fn bind_udp_socket_strict(is_ipv4: bool) -> std::io::Result<UdpSocket> {
    if is_ipv4 {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;
        sock.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
        UdpSocket::from_std(sock.into())
    } else {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = sock.set_only_v6(true);
        sock.set_nonblocking(true)?;
        sock.bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).into())?;
        UdpSocket::from_std(sock.into())
    }
}

/// Runs the pure-Rust userspace TUN packet pipeline (TCP via `vdpi` 7-stage desync + TCP/53 DNS,
/// UDP/53 DNS interception via `vdpi` DoH ring, QUIC UDP/443 fallback, and Cone-NAT UDP relay).
#[allow(clippy::too_many_arguments)]
pub async fn run_tun_pipeline(
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let clamped_mtu = mtu.clamp(MIN_MTU, MAX_MTU);
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false)
        .mtu(clamped_mtu)
        .stack_buffer_size(profile.stack_buffer_size)
        .tcp_buffer_size(profile.tcp_buffer_size)
        .udp_buffer_size(profile.udp_buffer_size)
        .tcp_recv_buffer_size(profile.tcp_recv_buffer_size)
        .tcp_send_buffer_size(profile.tcp_send_buffer_size)
        .build()
        .context("failed to build smoltcp netstack")?;

    let runner = runner.ok_or_else(|| anyhow!("netstack runner missing"))?;
    let udp_socket = udp_socket.ok_or_else(|| anyhow!("netstack UDP socket missing"))?;
    let mut tcp_listener = tcp_listener.ok_or_else(|| anyhow!("netstack TCP listener missing"))?;

    // Internal stop signal fires whenever either the caller requests shutdown OR any core
    // pipeline task exits unexpectedly, preventing silent zombie tunnels.
    let (internal_stop_tx, mut internal_stop_rx) = watch::channel(false);
    let mut external_stop = shutdown_rx.clone();
    let bridge_stop_tx = internal_stop_tx.clone();
    let stop_bridge = tokio::spawn(async move {
        wait_shutdown(&mut external_stop).await;
        let _ = bridge_stop_tx.send(true);
    });

    let runner_stop_tx = internal_stop_tx.clone();
    let runner_handle = tokio::spawn(async move {
        if let Err(e) = runner.await {
            debug!(error = %e, "netstack runner exited");
        }
        let _ = runner_stop_tx.send(true);
    });

    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_reader, mut udp_writer) = udp_socket.split();
    let (udp_reply_tx, mut udp_reply_rx) = mpsc::channel::<UdpMsg>(profile.udp_reply_capacity);

    let reverse_dns = Arc::new(ReverseDnsCache::new(profile.max_reverse_dns_entries));
    let tcp_slots = Arc::new(Semaphore::new(profile.max_tcp_sessions));
    let dns_slots = Arc::new(Semaphore::new(profile.max_dns_inflight));
    let udp_nat: UdpNatTable = Arc::new(RwLock::new(HashMap::new()));
    let observed_stage = Arc::new(AtomicU8::new(ctx.preferred_stage() as u8));

    // Task 1: Forward validated inbound TUN packets -> smoltcp stack
    let mut stop_in = internal_stop_rx.clone();
    let in_stop_tx = internal_stop_tx.clone();
    let tun_to_stack = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_in) => break,
                pkt = inbound_rx.recv() => {
                    let Some(pkt) = pkt else {
                        let _ = in_stop_tx.send(true);
                        break;
                    };
                    if !is_valid_inbound_tun_packet(&pkt) {
                        continue;
                    }
                    if let Err(e) = stack_sink.send(pkt).await {
                        if e.kind() == ErrorKind::InvalidInput {
                            debug!(error = %e, "dropped invalid inbound IP packet");
                            continue;
                        }
                        let _ = in_stop_tx.send(true);
                        break;
                    }
                }
            }
        }
    });

    // Task 2: Forward smoltcp stack -> outbound TUN packets
    let mut stop_out = internal_stop_rx.clone();
    let out_stop_tx = internal_stop_tx.clone();
    let stack_to_tun = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_out) => break,
                item = stack_stream.next() => {
                    match item {
                        Some(Ok(pkt)) => {
                            if outbound_tx.send(pkt).await.is_err() {
                                let _ = out_stop_tx.send(true);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            debug!(error = %e, "stack outbound stream error");
                            let _ = out_stop_tx.send(true);
                            break;
                        }
                        None => {
                            let _ = out_stop_tx.send(true);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Task 3: Serialize UDP replies back into netstack (dropping oversized or family-mismatched frames)
    let mut stop_udp_tx = internal_stop_rx.clone();
    let udp_tx_stop_tx = internal_stop_tx.clone();
    let udp_writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_udp_tx) => break,
                msg = udp_reply_rx.recv() => {
                    let Some((data, src_addr, dst_addr)) = msg else { break; };
                    if src_addr.is_ipv4() != dst_addr.is_ipv4() {
                        debug!(%src_addr, %dst_addr, "dropped family-mismatched UDP reply");
                        continue;
                    }
                    let max_payload = max_udp_payload_for_mtu(clamped_mtu, src_addr.is_ipv4());
                    if data.is_empty() || data.len() > max_payload {
                        debug!(len = data.len(), max_payload, "dropped oversized UDP reply");
                        continue;
                    }
                    if let Err(e) = udp_writer.send((data, src_addr, dst_addr)).await {
                        if e.kind() == ErrorKind::InvalidData {
                            debug!(error = %e, "dropped malformed UDP reply");
                            continue;
                        }
                        let _ = udp_tx_stop_tx.send(true);
                        break;
                    }
                }
            }
        }
    });

    // Task 4: Accept TCP streams from TUN (intercept TCP/53 DNS + relay all others via vdpi)
    let tcp_ctx = ctx.clone();
    let tcp_rdns = Arc::clone(&reverse_dns);
    let tcp_events = Arc::clone(&events);
    let tcp_stage_tracker = Arc::clone(&observed_stage);
    let tcp_stop_root = internal_stop_rx.clone();
    let mut stop_tcp = internal_stop_rx.clone();
    let tcp_stop_tx = internal_stop_tx.clone();
    let tcp_accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_tcp) => break,
                maybe_stream = tcp_listener.next() => {
                    let Some((stream, _src, dst)) = maybe_stream else {
                        let _ = tcp_stop_tx.send(true);
                        break;
                    };
                    let Ok(permit) = tcp_slots.clone().try_acquire_owned() else {
                        continue;
                    };
                    let conn_ctx = tcp_ctx.clone();
                    let rdns = Arc::clone(&tcp_rdns);
                    let ev = Arc::clone(&tcp_events);
                    let tracker = Arc::clone(&tcp_stage_tracker);
                    let mut conn_stop = tcp_stop_root.clone();

                    tokio::spawn(async move {
                        let _permit = permit;
                        // Intercept TCP port 53 DNS fallback (RFC 1035 2-byte length framing)
                        if dst.port() == 53 {
                            tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut conn_stop) => {}
                                _ = handle_tcp_dns_stream(stream, conn_ctx, rdns) => {}
                            }
                            return;
                        }

                        tokio::select! {
                            biased;
                            _ = wait_shutdown(&mut conn_stop) => {}
                            _ = async {
                                let known_host = rdns.lookup(dst.ip()).await;
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
                                        if let Err(e) = conn_ctx
                                            .relay_stream(stream, remote, known_host.as_deref(), effective_dst)
                                            .await
                                        {
                                            debug!(%effective_dst, host = ?known_host, error = %e, "TUN TCP relay ended");
                                        }
                                        let current = conn_ctx.preferred_stage() as u8;
                                        let prev = tracker.swap(current, Ordering::Relaxed);
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
                                    Err(e) => {
                                        debug!(%dst, host = ?known_host, error = %e, "TUN TCP upstream connect failed");
                                    }
                                }
                            } => {}
                        }
                    });
                }
            }
        }
    });

    // Task 5: Handle UDP datagrams (DNS/53 -> bounded DoH ring, QUIC Initial/443 -> drop, others -> Cone NAT)
    let udp_ctx = ctx.clone();
    let udp_rdns = Arc::clone(&reverse_dns);
    let udp_stats = Arc::clone(&tun_stats);
    let udp_events = Arc::clone(&events);
    let udp_nat_rx = Arc::clone(&udp_nat);
    let udp_dns_slots = Arc::clone(&dns_slots);
    let udp_stop_root = internal_stop_rx.clone();
    let mut stop_udp_rx = internal_stop_rx.clone();
    let udp_rx_stop_tx = internal_stop_tx.clone();
    let max_udp_flows = profile.max_udp_flows;
    let udp_read_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_udp_rx) => break,
                maybe_msg = udp_reader.next() => {
                    let Some((payload, src_addr, dst_addr)) = maybe_msg else {
                        let _ = udp_rx_stop_tx.send(true);
                        break;
                    };

                    // 1. Intercept DNS queries on port 53 (bounded concurrency + shutdown-aware)
                    if dst_addr.port() == 53 {
                        let Ok(permit) = udp_dns_slots.clone().try_acquire_owned() else {
                            continue;
                        };
                        let dns_ctx = udp_ctx.clone();
                        let rdns = Arc::clone(&udp_rdns);
                        let reply_tx = udp_reply_tx.clone();
                        let mut dns_stop = udp_stop_root.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            tokio::select! {
                                biased;
                                _ = wait_shutdown(&mut dns_stop) => {}
                                res = dns_ctx.dns.resolve_wire_query(&payload, dns_ctx.config.block_quic) => {
                                    match res {
                                        Ok((resp, meta)) => {
                                            if let Some((domain, ips)) = meta {
                                                for ip in ips {
                                                    rdns.insert(ip, domain.clone()).await;
                                                }
                                            }
                                            let _ = reply_tx.send((resp, dst_addr, src_addr)).await;
                                        }
                                        Err(e) => {
                                            debug!(error = %e, "TUN DNS wire query failed");
                                        }
                                    }
                                }
                            }
                        });
                        continue;
                    }

                    // 2. Drop all QUIC UDP/443 datagrams for desync-eligible targets (including
                    //    RFC 9287 greased headers and migrated short-header sessions) so browsers
                    //    cleanly fall back to TCP/TLS without hitting ERR_QUIC_PROTOCOL_ERROR.
                    if udp_ctx.config.block_quic && is_blocked_quic_udp(dst_addr.port(), &payload) {
                        let known_host = udp_rdns.lookup(dst_addr.ip()).await;
                        if udp_ctx.bypass.should_desync(known_host.as_deref(), Some(dst_addr.ip())) {
                            let count = udp_stats.quic_blocked.fetch_add(1, Ordering::Relaxed) + 1;
                            if count == 1 || count.is_multiple_of(50) {
                                udp_events.push(
                                    "debug",
                                    "quic",
                                    format!("redirected QUIC UDP/443 to TCP TLS ({count} packets)"),
                                );
                            }
                            continue;
                        }
                    }

                    // 3. Forward general UDP via Cone NAT (Discord voice, Roblox, WebRTC, games)
                    forward_udp_cone_nat(
                        payload,
                        src_addr,
                        dst_addr,
                        &udp_nat_rx,
                        &udp_reply_tx,
                        &udp_ctx,
                        &udp_stats,
                        &udp_stop_root,
                        clamped_mtu,
                        max_udp_flows,
                    )
                    .await;
                }
            }
        }
    });

    wait_shutdown(&mut internal_stop_rx).await;

    stop_bridge.abort();
    tun_to_stack.abort();
    stack_to_tun.abort();
    udp_writer_task.abort();
    tcp_accept_task.abort();
    udp_read_task.abort();
    runner_handle.abort();

    // Abort every Cone NAT reader task cleanly before clearing table.
    {
        let mut guard = udp_nat.write().await;
        for (_, entry) in guard.drain() {
            entry.abort.abort();
        }
    }
    tun_stats.udp_flows_active.store(0, Ordering::Relaxed);

    if *shutdown_rx.borrow() {
        Ok(())
    } else {
        Err(anyhow!("TUN pipeline terminated unexpectedly"))
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
    mut stream: netstack_smoltcp::TcpStream,
    ctx: EngineContext,
    rdns: Arc<ReverseDnsCache>,
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
        match ctx
            .dns
            .resolve_wire_query(&query, ctx.config.block_quic)
            .await
        {
            Ok((resp, meta)) => {
                if let Some((domain, ips)) = meta {
                    for ip in ips {
                        rdns.insert(ip, domain.clone()).await;
                    }
                }
                let Ok(resp_len) = u16::try_from(resp.len()) else {
                    break;
                };
                if stream.write_all(&resp_len.to_be_bytes()).await.is_err()
                    || stream.write_all(&resp).await.is_err()
                {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn forward_udp_cone_nat(
    payload: Vec<u8>,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    nat: &UdpNatTable,
    reply_tx: &mpsc::Sender<UdpMsg>,
    ctx: &EngineContext,
    stats: &Arc<TunStats>,
    shutdown_rx: &watch::Receiver<bool>,
    mtu: usize,
    max_udp_flows: usize,
) {
    if src_addr.is_ipv4() != dst_addr.is_ipv4() {
        return;
    }

    let key = (src_addr, dst_addr.is_ipv4());
    let now = now_secs();

    let existing = {
        let guard = nat.read().await;
        guard.get(&key).map(|entry| {
            entry.last_active_secs.store(now, Ordering::Relaxed);
            Arc::clone(&entry.socket)
        })
    };

    let outbound = if let Some(sock) = existing {
        sock
    } else {
        // Bind outside the write lock to avoid blocking concurrent UDP lookups.
        let Ok(bound) = bind_udp_socket_strict(dst_addr.is_ipv4()) else {
            return;
        };
        let mut guard = nat.write().await;
        if let Some(entry) = guard.get(&key) {
            entry.last_active_secs.store(now, Ordering::Relaxed);
            Arc::clone(&entry.socket)
        } else {
            if guard.len() >= max_udp_flows {
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, e)| e.last_active_secs.load(Ordering::Relaxed))
                    .map(|(k, _)| *k)
                {
                    if let Some(evicted) = guard.remove(&oldest_key) {
                        evicted.abort.abort();
                    }
                }
            }

            let sock = Arc::new(bound);
            let last_active = Arc::new(AtomicU64::new(now));

            let rx_sock = Arc::clone(&sock);
            let rx_last = Arc::clone(&last_active);
            let rx_reply_tx = reply_tx.clone();
            let rx_nat = Arc::clone(nat);
            let rx_stats = Arc::clone(stats);
            let rx_ctx = ctx.clone();
            let mut rx_stop = shutdown_rx.clone();
            let expect_ipv4 = dst_addr.is_ipv4();
            let max_reply = max_udp_payload_for_mtu(mtu, expect_ipv4).min(UDP_RECV_BUF_BYTES);

            let handle = tokio::spawn(async move {
                let mut buf = vec![0u8; UDP_RECV_BUF_BYTES];
                loop {
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut rx_stop) => break,
                        res = tokio::time::timeout(UDP_IDLE_TIMEOUT, rx_sock.recv_from(&mut buf)) => {
                            match res {
                                Ok(Ok((n, remote_src))) if n > 0 => {
                                    let canonical_ip = remote_src.ip().to_canonical();
                                    if canonical_ip.is_ipv4() != expect_ipv4 || n > max_reply {
                                        continue;
                                    }
                                    let clean_src = SocketAddr::new(canonical_ip, remote_src.port());
                                    rx_last.store(now_secs(), Ordering::Relaxed);
                                    rx_ctx.telemetry.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
                                    if rx_reply_tx
                                        .send((buf[..n].to_vec(), clean_src, src_addr))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(Ok(_)) => continue,
                                Ok(Err(_)) => break,
                                Err(_) => {
                                    let idle = now_secs().saturating_sub(rx_last.load(Ordering::Relaxed));
                                    if idle >= UDP_IDLE_TIMEOUT.as_secs() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                let mut guard = rx_nat.write().await;
                if guard
                    .get(&key)
                    .is_some_and(|e| Arc::ptr_eq(&e.socket, &rx_sock))
                {
                    guard.remove(&key);
                }
                rx_stats
                    .udp_flows_active
                    .store(guard.len() as u64, Ordering::Relaxed);
            });

            guard.insert(
                key,
                UdpNatEntry {
                    socket: Arc::clone(&sock),
                    last_active_secs: last_active,
                    abort: handle.abort_handle(),
                },
            );
            stats
                .udp_flows_active
                .store(guard.len() as u64, Ordering::Relaxed);
            sock
        }
    };

    if outbound.send_to(&payload, dst_addr).await.is_ok() {
        ctx.telemetry
            .bytes_tx
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TunnelConfig;
    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use std::net::Ipv4Addr;
    use vdpi::dns::{decode_dns_response, encode_dns_query};

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

    #[test]
    fn inbound_validator_rejects_fragmented_and_malformed_udp() {
        let mut good = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"hello",
        );
        assert!(is_valid_inbound_tun_packet(&good));

        good[24] = 0x05;
        good[25] = 0xdc;
        assert!(!is_valid_inbound_tun_packet(&good));

        let mut frag = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            Ipv4Addr::new(10, 0, 0, 2),
            53,
            b"hello",
        );
        frag[6] |= 0x20;
        assert!(!is_valid_inbound_tun_packet(&frag));

        assert!(!is_valid_inbound_tun_packet(&[0x00, 0x01, 0x02]));
    }

    #[test]
    fn quic_udp_443_blocker_blocks_standard_greased_and_short_header_packets_only_on_port_443() {
        assert!(is_blocked_quic_udp(443, &vec![0xc0; 1200]));
        // RFC 9287 Greased QUIC bit (fixed bit 0x40 cleared -> 0x80)
        assert!(is_blocked_quic_udp(443, &vec![0x80; 1200]));
        // Migrated 1-RTT QUIC Short-Header packet (< 1000 bytes)
        assert!(is_blocked_quic_udp(443, &[0x40; 64]));
        assert!(!is_blocked_quic_udp(443, &[]));
        // Non-443 UDP (voice, games, DNS) must never be blocked by QUIC rule
        assert!(!is_blocked_quic_udp(50000, &vec![0xc0; 1200]));
        assert!(!is_blocked_quic_udp(53, &[0x40; 64]));
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

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 3);

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

        stop_tx.send(true).unwrap();
        pipeline.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn standard_profile_handles_malformed_dns_quic_and_udp_echo() {
        exercise_pipeline(TunProfile::STANDARD).await;
    }

    #[tokio::test]
    async fn low_memory_ios_profile_handles_malformed_dns_quic_and_udp_echo() {
        exercise_pipeline(TunProfile::LOW_MEMORY).await;
    }
}
