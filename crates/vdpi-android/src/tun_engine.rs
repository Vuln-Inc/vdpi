use crate::events::EventRing;
use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, RwLock, Semaphore};
use tracing::debug;
#[cfg(unix)]
use tracing::warn;
use vdpi::desync::{EngineContext, LearnedStrategy};

const MAX_TCP_SESSIONS: usize = 192;
const MAX_UDP_FLOWS: usize = 256;
const MAX_REVERSE_DNS_ENTRIES: usize = 2048;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct TunStats {
    pub quic_blocked: AtomicU64,
    pub udp_flows_active: AtomicU64,
}

#[derive(Debug, Default)]
struct ReverseDnsCache {
    map: RwLock<HashMap<IpAddr, String>>,
}

impl ReverseDnsCache {
    async fn insert(&self, ip: IpAddr, domain: String) {
        let mut guard = self.map.write().await;
        if guard.len() >= MAX_REVERSE_DNS_ENTRIES && !guard.contains_key(&ip) {
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
}

type UdpNatTable = Arc<RwLock<HashMap<(SocketAddr, bool), UdpNatEntry>>>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}

/// Runs the pure-Rust userspace TUN packet pipeline (TCP via `vdpi` 7-stage desync,
/// DNS port-53 interception via `vdpi` DoH ring, QUIC UDP/443 fallback, and Cone-NAT UDP relay).
pub async fn run_tun_pipeline(
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let clamped_mtu = mtu.clamp(1280, 9000);
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(true)
        .mtu(clamped_mtu)
        .stack_buffer_size(512)
        .tcp_buffer_size(256)
        .udp_buffer_size(256)
        .tcp_recv_buffer_size(64 * 1024)
        .tcp_send_buffer_size(64 * 1024)
        .build()
        .context("failed to build smoltcp netstack")?;

    let runner = runner.ok_or_else(|| anyhow!("netstack runner missing"))?;
    let udp_socket = udp_socket.ok_or_else(|| anyhow!("netstack UDP socket missing"))?;
    let mut tcp_listener = tcp_listener.ok_or_else(|| anyhow!("netstack TCP listener missing"))?;

    let runner_handle = tokio::spawn(async move {
        if let Err(e) = runner.await {
            debug!(error = %e, "netstack runner exited");
        }
    });

    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_reader, mut udp_writer) = udp_socket.split();
    let (udp_reply_tx, mut udp_reply_rx) = mpsc::channel::<UdpMsg>(512);

    let reverse_dns = Arc::new(ReverseDnsCache::default());
    let tcp_slots = Arc::new(Semaphore::new(MAX_TCP_SESSIONS));
    let udp_nat: UdpNatTable = Arc::new(RwLock::new(HashMap::new()));
    let observed_stage = Arc::new(AtomicU8::new(ctx.preferred_stage() as u8));

    // Task 1: Forward inbound TUN packets -> smoltcp stack
    let mut stop_in = shutdown_rx.clone();
    let tun_to_stack = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_in) => break,
                pkt = inbound_rx.recv() => {
                    let Some(pkt) = pkt else { break; };
                    if stack_sink.send(pkt).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task 2: Forward smoltcp stack -> outbound TUN packets
    let mut stop_out = shutdown_rx.clone();
    let stack_to_tun = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_out) => break,
                item = stack_stream.next() => {
                    match item {
                        Some(Ok(pkt)) => {
                            if outbound_tx.send(pkt).await.is_err() {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            debug!(error = %e, "stack outbound stream error");
                            break;
                        }
                        None => break,
                    }
                }
            }
        }
    });

    // Task 3: Serialize UDP replies back into netstack
    let mut stop_udp_tx = shutdown_rx.clone();
    let udp_writer_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_udp_tx) => break,
                msg = udp_reply_rx.recv() => {
                    let Some(msg) = msg else { break; };
                    if udp_writer.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Task 4: Accept TCP streams from TUN and relay through vdpi's 7-stage desync engine
    let tcp_ctx = ctx.clone();
    let tcp_rdns = Arc::clone(&reverse_dns);
    let tcp_events = Arc::clone(&events);
    let tcp_stage_tracker = Arc::clone(&observed_stage);
    let mut stop_tcp = shutdown_rx.clone();
    let tcp_accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_tcp) => break,
                maybe_stream = tcp_listener.next() => {
                    let Some((stream, _src, dst)) = maybe_stream else { break; };
                    let Ok(permit) = tcp_slots.clone().try_acquire_owned() else {
                        continue;
                    };
                    let conn_ctx = tcp_ctx.clone();
                    let rdns = Arc::clone(&tcp_rdns);
                    let ev = Arc::clone(&tcp_events);
                    let tracker = Arc::clone(&tcp_stage_tracker);
                    tokio::spawn(async move {
                        let _permit = permit;
                        let known_host = rdns.lookup(dst.ip()).await;
                        match conn_ctx.connect_upstream_addr(dst).await {
                            Ok(remote) => {
                                if let Err(e) = conn_ctx
                                    .relay_stream(stream, remote, known_host.as_deref(), dst)
                                    .await
                                {
                                    debug!(%dst, host = ?known_host, error = %e, "TUN TCP relay ended");
                                }
                                let current = conn_ctx.preferred_stage() as u8;
                                let prev = tracker.swap(current, Ordering::Relaxed);
                                if current != prev {
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
                    });
                }
            }
        }
    });

    // Task 5: Handle UDP datagrams (DNS/53 -> DoH ring, QUIC/443 -> drop, others -> Cone NAT)
    let udp_ctx = ctx.clone();
    let udp_rdns = Arc::clone(&reverse_dns);
    let udp_stats = Arc::clone(&tun_stats);
    let udp_events = Arc::clone(&events);
    let udp_nat_rx = Arc::clone(&udp_nat);
    let udp_stop_root = shutdown_rx.clone();
    let mut stop_udp_rx = shutdown_rx.clone();
    let udp_read_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_udp_rx) => break,
                maybe_msg = udp_reader.next() => {
                    let Some((payload, src_addr, dst_addr)) = maybe_msg else { break; };

                    // 1. Intercept DNS queries on port 53 and route through vdpi's anti-poisoning DNS ring
                    if dst_addr.port() == 53 {
                        let dns_ctx = udp_ctx.clone();
                        let rdns = Arc::clone(&udp_rdns);
                        let reply_tx = udp_reply_tx.clone();
                        tokio::spawn(async move {
                            match dns_ctx
                                .dns
                                .resolve_wire_query(&payload, dns_ctx.config.block_quic)
                                .await
                            {
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
                        });
                        continue;
                    }

                    // 2. Drop QUIC UDP/443 packets for desync-eligible targets so apps fall back to TCP/TLS
                    if udp_ctx.config.block_quic && dst_addr.port() == 443 {
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
                    )
                    .await;
                }
            }
        }
    });

    let _ = shutdown_rx.wait_for(|s| *s).await;

    tun_to_stack.abort();
    stack_to_tun.abort();
    udp_writer_task.abort();
    tcp_accept_task.abort();
    udp_read_task.abort();
    runner_handle.abort();
    udp_nat.write().await.clear();
    tun_stats.udp_flows_active.store(0, Ordering::Relaxed);

    Ok(())
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
) {
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
        let mut guard = nat.write().await;
        if let Some(entry) = guard.get(&key) {
            entry.last_active_secs.store(now, Ordering::Relaxed);
            Arc::clone(&entry.socket)
        } else {
            if guard.len() >= MAX_UDP_FLOWS {
                // Evict the stalest flow if NAT table is full
                if let Some(oldest_key) = guard
                    .iter()
                    .min_by_key(|(_, e)| e.last_active_secs.load(Ordering::Relaxed))
                    .map(|(k, _)| *k)
                {
                    guard.remove(&oldest_key);
                }
            }
            let bind_addr = if dst_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let Ok(sock) = UdpSocket::bind(bind_addr).await else {
                return;
            };
            let sock = Arc::new(sock);
            let last_active = Arc::new(AtomicU64::new(now));
            guard.insert(
                key,
                UdpNatEntry {
                    socket: Arc::clone(&sock),
                    last_active_secs: Arc::clone(&last_active),
                },
            );
            stats
                .udp_flows_active
                .store(guard.len() as u64, Ordering::Relaxed);

            // Spawn return-path reader for this Cone NAT socket
            let rx_sock = Arc::clone(&sock);
            let rx_reply_tx = reply_tx.clone();
            let rx_nat = Arc::clone(nat);
            let rx_stats = Arc::clone(stats);
            let rx_ctx = ctx.clone();
            let mut rx_stop = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut rx_stop) => break,
                        res = tokio::time::timeout(UDP_IDLE_TIMEOUT, rx_sock.recv_from(&mut buf)) => {
                            match res {
                                Ok(Ok((n, remote_src))) if n > 0 => {
                                    last_active.store(now_secs(), Ordering::Relaxed);
                                    rx_ctx.telemetry.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
                                    if rx_reply_tx
                                        .send((buf[..n].to_vec(), remote_src, src_addr))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Ok(Ok(_)) => continue,
                                Ok(Err(_)) | Err(_) => break,
                            }
                        }
                    }
                }
                let mut guard = rx_nat.write().await;
                guard.remove(&key);
                rx_stats
                    .udp_flows_active
                    .store(guard.len() as u64, Ordering::Relaxed);
            });

            sock
        }
    };

    if outbound.send_to(&payload, dst_addr).await.is_ok() {
        ctx.telemetry
            .bytes_tx
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
    }
}

/// Runs the TUN engine attached to a real Unix/Android `VpnService` TUN file descriptor.
/// Takes ownership of `raw_fd` and closes it automatically when the tunnel exits.
#[cfg(unix)]
pub async fn run_tun_fd(
    raw_fd: i32,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    if raw_fd < 0 {
        return Err(anyhow!("invalid TUN file descriptor: {raw_fd}"));
    }

    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    set_nonblocking(owned_fd.as_raw_fd()).context("failed to set O_NONBLOCK on TUN fd")?;
    // SAFETY: `owned_fd` exclusively owns the detached Android TUN fd and keeps it open
    // for the entire lifetime of the `AsyncFd` wrapper.
    let async_fd = Arc::new(
        unsafe { AsyncFd::register(owned_fd) }.context("failed to register TUN fd with tokio")?,
    );

    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(512);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(512);

    let read_fd = Arc::clone(&async_fd);
    let mut stop_read = shutdown_rx.clone();
    let read_buf_size = mtu.max(1500) + 128;
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; read_buf_size];
        loop {
            let mut guard = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_read) => break,
                res = read_fd.readable() => match res {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "TUN readable wait failed");
                        break;
                    }
                }
            };

            match guard.try_io(|inner| read_raw_fd(inner.as_raw_fd(), &mut buf)) {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if inbound_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => {
                    warn!(error = %e, "TUN read error");
                    break;
                }
                Err(_would_block) => continue,
            }
        }
    });

    let write_fd = Arc::clone(&async_fd);
    let mut stop_write = shutdown_rx.clone();
    let writer_task = tokio::spawn(async move {
        loop {
            let pkt = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_write) => break,
                maybe_pkt = outbound_rx.recv() => match maybe_pkt {
                    Some(p) => p,
                    None => break,
                }
            };

            loop {
                let mut guard = tokio::select! {
                    biased;
                    _ = wait_shutdown(&mut stop_write) => return,
                    res = write_fd.writable() => match res {
                        Ok(g) => g,
                        Err(e) => {
                            warn!(error = %e, "TUN writable wait failed");
                            return;
                        }
                    }
                };

                match guard.try_io(|inner| write_raw_fd(inner.as_raw_fd(), &pkt)) {
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Ok(Err(e)) => {
                        debug!(error = %e, "TUN write error");
                        break;
                    }
                    Err(_would_block) => continue,
                }
            }
        }
    });

    let pipeline_res = run_tun_pipeline(
        inbound_rx,
        outbound_tx,
        ctx,
        tun_stats,
        events,
        mtu,
        shutdown_rx,
    )
    .await;

    reader_task.abort();
    writer_task.abort();
    pipeline_res
}

#[cfg(unix)]
fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let res = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if res < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn read_raw_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(unix)]
fn write_raw_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AndroidConfig;
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
        let builder = PacketBuilder::ipv4(src_ip.octets(), dst_ip.octets(), 64)
            .udp(src_port, dst_port);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    #[tokio::test]
    async fn tun_pipeline_intercepts_dns_drops_quic_and_relays_udp() {
        let cfg = AndroidConfig {
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
            stop_rx,
        ));

        // 1. Send a DNS A query for "localhost" to virtual DNS 10.0.0.2:53
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

        // 2. Send a QUIC UDP/443 packet to a public IP -> must be dropped and counted
        let quic_pkt = build_ipv4_udp(
            Ipv4Addr::new(10, 0, 0, 1),
            54000,
            Ipv4Addr::new(162, 159, 135, 232),
            443,
            &vec![0xc0; 1200],
        );
        in_tx.send(quic_pkt).await.unwrap();

        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(tun_stats.quic_blocked.load(Ordering::Relaxed), 1);

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
}
