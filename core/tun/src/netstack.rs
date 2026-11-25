use anyhow::{anyhow, Result};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address,
        Ipv6Packet, TcpPacket,
    },
};
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, trace};

const INGRESS_DRAIN_LIMIT: usize = 128;
const POLL_BURST_LIMIT: usize = 8;
const FIN_WAIT_2_TIMEOUT: SmolDuration = SmolDuration::from_secs(15);
const LISTEN_ORPHAN_TIMEOUT: StdDuration = StdDuration::from_secs(3);
const TIME_WAIT_REAP_TIMEOUT: StdDuration = StdDuration::from_secs(2);
const CLOSING_REAP_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const DEFERRED_SYN_TTL: StdDuration = StdDuration::from_secs(2);
const MAX_DEFERRED_SYNS: usize = 32;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum HalfState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: HalfState,
    send_state: HalfState,
}

type SharedControl = Arc<Mutex<TcpSocketControl>>;

/// In-tree userspace TCP stream backed by `smoltcp` 0.14 with immediate ACKs
/// (`ack_delay = None`), Nagle disabled, RFC 7323 window scaling, and zero-copy
/// direct queue handoff to the TUN pipeline.
pub(crate) struct TunNetstackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: Arc<Notify>,
    control: SharedControl,
}

impl TunNetstackTcpStream {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.dst_addr
    }
}

impl Drop for TunNetstackTcpStream {
    fn drop(&mut self) {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(control.recv_state, HalfState::Normal) {
            control.recv_state = HalfState::Close;
        }
        if matches!(control.send_state, HalfState::Normal) {
            control.send_state = HalfState::Close;
        }
        drop(control);
        self.notify.notify_one();
    }
}

impl AsyncRead for TunNetstackTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if control.recv_buffer.is_empty() {
            if matches!(control.recv_state, HalfState::Closed) {
                return Poll::Ready(Ok(()));
            }
            if let Some(old) = control.recv_waker.replace(cx.waker().clone()) {
                if !old.will_wake(cx.waker()) {
                    old.wake();
                }
            }
            return Poll::Pending;
        }

        let unfilled = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(unfilled);
        buf.advance(n);
        drop(control);

        if n > 0 {
            self.notify.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunNetstackTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if !matches!(control.send_state, HalfState::Normal) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if control.send_buffer.is_full() {
            if let Some(old) = control.send_waker.replace(cx.waker().clone()) {
                if !old.will_wake(cx.waker()) {
                    old.wake();
                }
            }
            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);
        drop(control);

        if n > 0 {
            self.notify.notify_one();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if matches!(control.send_state, HalfState::Closed) {
            return Poll::Ready(Ok(()));
        }

        if matches!(control.send_state, HalfState::Normal) {
            control.send_state = HalfState::Close;
        }

        if let Some(old) = control.send_waker.replace(cx.waker().clone()) {
            if !old.will_wake(cx.waker()) {
                old.wake();
            }
        }
        drop(control);

        self.notify.notify_one();
        Poll::Pending
    }
}

struct VirtualRxToken(Vec<u8>);

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VirtualTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let res = f(&mut buf);
        self.0.push_back(buf);
        res
    }
}

struct VirtualDevice {
    mtu: usize,
    tx_queue_high_water: usize,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new(mtu: usize, tx_queue_high_water: usize) -> Self {
        let tx_queue_high_water = tx_queue_high_water.max(16);
        Self {
            mtu,
            tx_queue_high_water,
            rx_queue: VecDeque::with_capacity(INGRESS_DRAIN_LIMIT),
            tx_queue: VecDeque::with_capacity(INGRESS_DRAIN_LIMIT.min(tx_queue_high_water)),
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Never gate inbound RX (especially ACKs, window updates, FINs, and RSTs) on
        // `tx_queue_high_water`: inbound ACKs are what allow TX buffers to drain.
        let pkt = self.rx_queue.pop_front()?;
        Some((VirtualRxToken(pkt), VirtualTxToken(&mut self.tx_queue)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= self.tx_queue_high_water {
            return None;
        }
        Some(VirtualTxToken(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Skip redundant software RX checksum verification on OS-generated local TUN frames,
        // while always emitting valid IPv4 + TCP TX checksums required by Wintun/utun/Linux TUN.
        let mut checksum = ChecksumCapabilities::ignored();
        checksum.ipv4 = Checksum::Tx;
        checksum.tcp = Checksum::Tx;
        caps.checksum = checksum;
        caps
    }
}

struct SocketEntry {
    control: SharedControl,
    endpoints: (SocketAddr, SocketAddr),
    created_at: StdInstant,
    saw_non_listen: bool,
    fin_wait_2_shortened: bool,
    closing_since: Option<StdInstant>,
    time_wait_since: Option<StdInstant>,
}

enum EnqueueOutcome {
    Enqueued,
    Dropped,
    Deferred(Vec<u8>),
}

fn internet_checksum_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&rem) = chunks.remainder().first() {
        sum += u32::from(u16::from_be_bytes([rem, 0]));
    }
    sum
}

fn finalize_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Synthesizes a valid IPv4 or IPv6 TCP `RST+ACK` reply for an incoming SYN that cannot be
/// accepted (e.g. hard session capacity overflow), so clients fail fast instead of stalling
/// in exponential SYN retransmission backoff.
fn build_tcp_rst_ack_reply(syn_frame: &[u8]) -> Option<Vec<u8>> {
    let version = syn_frame.first()? >> 4;
    match version {
        4 => {
            let ip = Ipv4Packet::new_checked(syn_frame).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_ip = ip.dst_addr().octets();
            let dst_ip = ip.src_addr().octets();
            let ack_num = tcp.seq_number().0.wrapping_add(1);

            let mut pkt = vec![0u8; 40];
            // IPv4 header (20 bytes)
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = 6; // TCP
            pkt[12..16].copy_from_slice(&src_ip);
            pkt[16..20].copy_from_slice(&dst_ip);
            let ip_csum = finalize_checksum(internet_checksum_sum(&pkt[..20]));
            pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

            // TCP header (20 bytes): RST | ACK
            pkt[20..22].copy_from_slice(&tcp.dst_port().to_be_bytes());
            pkt[22..24].copy_from_slice(&tcp.src_port().to_be_bytes());
            pkt[24..28].copy_from_slice(&0u32.to_be_bytes());
            pkt[28..32].copy_from_slice(&ack_num.to_be_bytes());
            pkt[32] = 0x50; // data offset = 5 (20 bytes)
            pkt[33] = 0x14; // RST (0x04) | ACK (0x10)

            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&src_ip);
            pseudo[4..8].copy_from_slice(&dst_ip);
            pseudo[9] = 6;
            pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
            let tcp_csum = finalize_checksum(
                internet_checksum_sum(&pseudo) + internet_checksum_sum(&pkt[20..40]),
            );
            pkt[36..38].copy_from_slice(&tcp_csum.to_be_bytes());
            Some(pkt)
        }
        6 => {
            let ip = Ipv6Packet::new_checked(syn_frame).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            let src_ip = ip.dst_addr().octets();
            let dst_ip = ip.src_addr().octets();
            let ack_num = tcp.seq_number().0.wrapping_add(1);

            let mut pkt = vec![0u8; 60];
            // IPv6 header (40 bytes)
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
            pkt[6] = 6; // TCP
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&src_ip);
            pkt[24..40].copy_from_slice(&dst_ip);

            // TCP header (20 bytes): RST | ACK
            pkt[40..42].copy_from_slice(&tcp.dst_port().to_be_bytes());
            pkt[42..44].copy_from_slice(&tcp.src_port().to_be_bytes());
            pkt[44..48].copy_from_slice(&0u32.to_be_bytes());
            pkt[48..52].copy_from_slice(&ack_num.to_be_bytes());
            pkt[52] = 0x50;
            pkt[53] = 0x14; // RST | ACK

            let mut pseudo = [0u8; 40];
            pseudo[0..16].copy_from_slice(&src_ip);
            pseudo[16..32].copy_from_slice(&dst_ip);
            pseudo[32..36].copy_from_slice(&20u32.to_be_bytes());
            pseudo[39] = 6;
            let tcp_csum = finalize_checksum(
                internet_checksum_sum(&pseudo) + internet_checksum_sum(&pkt[40..60]),
            );
            pkt[56..58].copy_from_slice(&tcp_csum.to_be_bytes());
            Some(pkt)
        }
        _ => None,
    }
}

fn is_active_tcp_state(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::Listen | TcpState::SynReceived | TcpState::Established
    )
}

fn evict_reclaimable_socket(
    socket_set: &mut SocketSet<'static>,
    sockets: &mut HashMap<SocketHandle, SocketEntry>,
    active_endpoints: &mut HashSet<(SocketAddr, SocketAddr)>,
) -> bool {
    let mut best: Option<(SocketHandle, u8, StdInstant)> = None;
    for (&handle, entry) in sockets.iter() {
        let state = socket_set.get::<TcpSocket>(handle).state();
        let candidate = if state == TcpState::TimeWait {
            Some((0u8, entry.time_wait_since.unwrap_or(entry.created_at)))
        } else {
            entry.closing_since.map(|since| (1u8, since))
        };
        if let Some((prio, ts)) = candidate {
            let replace = match best {
                None => true,
                Some((_, best_prio, best_ts)) => (prio, ts) < (best_prio, best_ts),
            };
            if replace {
                best = Some((handle, prio, ts));
            }
        }
    }

    if let Some((handle, _, _)) = best {
        {
            let socket = socket_set.get_mut::<TcpSocket>(handle);
            socket.abort();
        }
        if let Some(entry) = sockets.remove(&handle) {
            active_endpoints.remove(&entry.endpoints);
            let mut control = entry
                .control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            control.send_state = HalfState::Closed;
            control.recv_state = HalfState::Closed;
            if let Some(w) = control.send_waker.take() {
                w.wake();
            }
            if let Some(w) = control.recv_waker.take() {
                w.wake();
            }
        }
        socket_set.remove(handle);
        true
    } else {
        false
    }
}

/// Decouples `TcpSocketControl` ring sizes from `smoltcp`'s `TcpSocketBuffer` so iOS
/// (`<= 32 KiB`) uses 16 KiB control rings while desktop (`512 KiB`) caps rings at 128 KiB.
fn control_ring_size(tcp_buffer_size: usize) -> usize {
    if tcp_buffer_size <= 32 * 1024 {
        tcp_buffer_size.min(16 * 1024)
    } else {
        tcp_buffer_size.min(128 * 1024)
    }
}

fn generate_random_seed() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5644_5049_5455_4e31),
    );
    hasher.finish()
}

fn create_interface(device: &mut VirtualDevice) -> Result<Interface> {
    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = generate_random_seed();
    let mut iface = Interface::new(iface_config, device, SmolInstant::now());
    iface.update_ip_addrs(|ip_addrs| {
        let _ = ip_addrs.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0));
        let _ = ip_addrs.push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0));
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
        .map_err(|e| anyhow!("failed to add smoltcp default IPv4 route: {e:?}"))?;
    iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
        .map_err(|e| anyhow!("failed to add smoltcp default IPv6 route: {e:?}"))?;
    iface.set_any_ip(true);
    Ok(iface)
}

/// Inspects an IPv4/IPv6 frame to see whether it is a valid TCP packet.
/// Returns `Some((src_addr, dst_addr, is_initial_syn))` for valid TCP frames.
fn inspect_tcp_frame(frame: &[u8]) -> Option<(SocketAddr, SocketAddr, bool)> {
    let version = frame.first()? >> 4;
    let (src_ip, dst_ip, payload) = match version {
        4 => {
            let ip = Ipv4Packet::new_checked(frame).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddr::V4(ip.src_addr()),
                IpAddr::V4(ip.dst_addr()),
                ip.payload(),
            )
        }
        6 => {
            let ip = Ipv6Packet::new_checked(frame).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                ip.payload(),
            )
        }
        _ => return None,
    };

    let tcp = TcpPacket::new_checked(payload).ok()?;
    let src_addr = SocketAddr::new(src_ip, tcp.src_port());
    let dst_addr = SocketAddr::new(dst_ip, tcp.dst_port());
    let is_initial_syn = tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin();
    Some((src_addr, dst_addr, is_initial_syn))
}

async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    loop {
        if rx.changed().await.is_err() || *rx.borrow() {
            return;
        }
    }
}

/// Spawns the in-tree `smoltcp` 0.14 TCP netstack runner directly bridging `tcp_in_rx`
/// and `outbound_tx` with zero intermediate channels/tasks, `ack_delay = None`,
/// `nagle = false`, `Checksum::Tx`, and poll-to-quiescence batching.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_tcp_netstack(
    mut tcp_in_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    mtu: usize,
    tcp_recv_buffer_size: usize,
    tcp_send_buffer_size: usize,
    max_tcp_sessions: usize,
    tx_queue_high_water: usize,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(
    mpsc::Receiver<TunNetstackTcpStream>,
    tokio::task::JoinHandle<()>,
)> {
    let max_tcp_sessions = max_tcp_sessions.max(1);
    let hard_handle_cap = max_tcp_sessions.saturating_mul(2);
    let control_recv_size = control_ring_size(tcp_recv_buffer_size);
    let control_send_size = control_ring_size(tcp_send_buffer_size);
    let mut device = VirtualDevice::new(mtu, tx_queue_high_water);
    let mut iface = create_interface(&mut device)?;
    let (stream_tx, stream_rx) = mpsc::channel(max_tcp_sessions.clamp(16, 256));
    let notify = Arc::new(Notify::new());

    let handle = tokio::spawn(async move {
        let mut socket_set = SocketSet::new(Vec::new());
        let mut sockets: HashMap<SocketHandle, SocketEntry> = HashMap::new();
        let mut active_endpoints: HashSet<(SocketAddr, SocketAddr)> = HashSet::new();
        let mut listening_dsts: HashSet<SocketAddr> = HashSet::new();
        let mut sockets_to_remove: Vec<SocketHandle> = Vec::new();
        let mut deferred_syns: VecDeque<(StdInstant, Vec<u8>)> = VecDeque::new();
        let mut burst_iters: usize = 0;

        let enqueue_inbound = |frame: Vec<u8>,
                               device: &mut VirtualDevice,
                               socket_set: &mut SocketSet<'static>,
                               sockets: &mut HashMap<SocketHandle, SocketEntry>,
                               active_endpoints: &mut HashSet<(SocketAddr, SocketAddr)>,
                               listening_dsts: &mut HashSet<SocketAddr>,
                               stream_tx: &mpsc::Sender<TunNetstackTcpStream>,
                               notify: &Arc<Notify>|
         -> EnqueueOutcome {
            let Some((src_addr, dst_addr, is_initial_syn)) = inspect_tcp_frame(&frame) else {
                return EnqueueOutcome::Dropped;
            };

            if is_initial_syn && !active_endpoints.contains(&(src_addr, dst_addr)) {
                // Prevent smoltcp SocketSet slot-reuse cross-wiring when multiple parallel
                // SYNs target the same dst_addr in one ingress batch: defer the second SYN
                // into `deferred_syns` WITHOUT halting `tcp_in_rx` for other flows/ACKs.
                if listening_dsts.contains(&dst_addr) {
                    return EnqueueOutcome::Deferred(frame);
                }

                // Count only active non-closing sockets (`Listen`, `SynReceived`, `Established`)
                // against `max_tcp_sessions` so `TimeWait` and closing sockets cannot starve new
                // connections, while still enforcing a hard handle cap (`2 * max_tcp_sessions`)
                // via immediate reclaim of `TimeWait`/closing handles to protect iOS Jetsam RAM.
                if sockets.len() >= hard_handle_cap {
                    let _ = evict_reclaimable_socket(socket_set, sockets, active_endpoints);
                }
                let active_count = sockets
                    .keys()
                    .filter(|&&h| is_active_tcp_state(socket_set.get::<TcpSocket>(h).state()))
                    .count();
                if active_count >= max_tcp_sessions || sockets.len() >= hard_handle_cap {
                    debug!(
                        %src_addr,
                        %dst_addr,
                        active = active_count,
                        total = sockets.len(),
                        limit = max_tcp_sessions,
                        "TCP session limit reached; sending RST+ACK"
                    );
                    if let Some(rst) = build_tcp_rst_ack_reply(&frame) {
                        device.tx_queue.push_back(rst);
                    }
                    return EnqueueOutcome::Dropped;
                }

                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; tcp_recv_buffer_size]),
                    TcpSocketBuffer::new(vec![0u8; tcp_send_buffer_size]),
                );
                // Disable delayed ACK and Nagle on local virtual TUN links to prevent
                // 10-56 ms local RTT stalls and maximize Gigabit TCP throughput.
                socket.set_ack_delay(None);
                socket.set_nagle_enabled(false);
                socket.set_keep_alive(Some(SmolDuration::from_secs(20)));
                socket.set_timeout(Some(SmolDuration::from_secs(60)));

                if let Err(err) = socket.listen(dst_addr) {
                    debug!(%src_addr, %dst_addr, error = ?err, "smoltcp listen failed");
                    return EnqueueOutcome::Dropped;
                }

                let control = Arc::new(Mutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![0u8; control_send_size]),
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![0u8; control_recv_size]),
                    recv_waker: None,
                    recv_state: HalfState::Normal,
                    send_state: HalfState::Normal,
                }));

                let stream = TunNetstackTcpStream {
                    src_addr,
                    dst_addr,
                    notify: Arc::clone(notify),
                    control: Arc::clone(&control),
                };

                if stream_tx.try_send(stream).is_err() {
                    debug!(%src_addr, %dst_addr, "accepted TCP queue full; sending RST+ACK");
                    if let Some(rst) = build_tcp_rst_ack_reply(&frame) {
                        device.tx_queue.push_back(rst);
                    }
                    return EnqueueOutcome::Dropped;
                }

                let handle = socket_set.add(socket);
                active_endpoints.insert((src_addr, dst_addr));
                listening_dsts.insert(dst_addr);
                sockets.insert(
                    handle,
                    SocketEntry {
                        control,
                        endpoints: (src_addr, dst_addr),
                        created_at: StdInstant::now(),
                        saw_non_listen: false,
                        fin_wait_2_shortened: false,
                        closing_since: None,
                        time_wait_since: None,
                    },
                );
                trace!(%src_addr, %dst_addr, "created TUN TCP socket");
            }

            device.rx_queue.push_back(frame);
            EnqueueOutcome::Enqueued
        };

        'runner: loop {
            if *shutdown_rx.borrow() {
                break;
            }

            // 1. Re-try deferred same-destination SYNs first (dropping stale >2s entries),
            //    then drain ready inbound TCP packets without ever halting `tcp_in_rx`.
            let wall_now = StdInstant::now();
            let mut ingress_drained = 0usize;
            let mut enqueued_any = false;

            let deferred_count = deferred_syns.len();
            for _ in 0..deferred_count {
                let Some((ts, frame)) = deferred_syns.pop_front() else {
                    break;
                };
                if wall_now.saturating_duration_since(ts) >= DEFERRED_SYN_TTL {
                    continue;
                }
                if ingress_drained >= INGRESS_DRAIN_LIMIT {
                    deferred_syns.push_front((ts, frame));
                    break;
                }
                match enqueue_inbound(
                    frame,
                    &mut device,
                    &mut socket_set,
                    &mut sockets,
                    &mut active_endpoints,
                    &mut listening_dsts,
                    &stream_tx,
                    &notify,
                ) {
                    EnqueueOutcome::Enqueued => {
                        ingress_drained += 1;
                        enqueued_any = true;
                    }
                    EnqueueOutcome::Dropped => {
                        ingress_drained += 1;
                    }
                    EnqueueOutcome::Deferred(frame) => {
                        deferred_syns.push_back((ts, frame));
                    }
                }
            }

            while ingress_drained < INGRESS_DRAIN_LIMIT {
                let frame = match tcp_in_rx.try_recv() {
                    Ok(frame) => frame,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break 'runner,
                };
                match enqueue_inbound(
                    frame,
                    &mut device,
                    &mut socket_set,
                    &mut sockets,
                    &mut active_endpoints,
                    &mut listening_dsts,
                    &stream_tx,
                    &notify,
                ) {
                    EnqueueOutcome::Enqueued => {
                        ingress_drained += 1;
                        enqueued_any = true;
                    }
                    EnqueueOutcome::Dropped => {
                        ingress_drained += 1;
                    }
                    EnqueueOutcome::Deferred(frame) => {
                        if deferred_syns.len() < MAX_DEFERRED_SYNS {
                            deferred_syns.push_back((wall_now, frame));
                        }
                        ingress_drained += 1;
                    }
                }
            }

            // 2. Drain application TX buffers into smoltcp BEFORE polling so segments emit immediately.
            let mut made_progress = enqueued_any;
            for (&handle, entry) in &sockets {
                let socket = socket_set.get_mut::<TcpSocket>(handle);
                let mut control = entry
                    .control
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);

                // If the application dropped the stream before the handshake completed,
                // abort immediately so it does not stall in Listen/SynReceived/FinWait1.
                if matches!(control.recv_state, HalfState::Close)
                    && matches!(control.send_state, HalfState::Close)
                    && matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
                {
                    socket.abort();
                    control.send_state = HalfState::Closed;
                    control.recv_state = HalfState::Closed;
                    made_progress = true;
                    continue;
                }

                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    match socket.send(|buf| {
                        let n = control.send_buffer.dequeue_slice(buf);
                        (n, n)
                    }) {
                        Ok(n) if n > 0 => {
                            wake_sender = true;
                            made_progress = true;
                        }
                        Ok(_) => break,
                        Err(err) => {
                            debug!(error = ?err, state = ?socket.state(), "smoltcp pre-poll send error");
                            socket.abort();
                            if matches!(control.send_state, HalfState::Normal) {
                                control.send_state = HalfState::Closed;
                            }
                            wake_sender = true;
                            break;
                        }
                    }
                }

                if matches!(control.send_state, HalfState::Close) && control.send_buffer.is_empty()
                {
                    socket.close();
                    control.send_state = HalfState::Closing;
                    made_progress = true;
                }

                if wake_sender {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            // 3. Drive smoltcp state machine (ingress + egress).
            let now = SmolInstant::now();
            if matches!(
                iface.poll(now, &mut device, &mut socket_set),
                PollResult::SocketStateChanged
            ) {
                made_progress = true;
            }

            // 4. Drain smoltcp RX buffers into application buffers, refill TX if freed, reap closed.
            sockets_to_remove.clear();
            listening_dsts.clear();
            for (&handle, entry) in &mut sockets {
                let socket = socket_set.get_mut::<TcpSocket>(handle);
                let mut control = entry
                    .control
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);

                if socket.state() == TcpState::Closed {
                    sockets_to_remove.push(handle);
                    control.send_state = HalfState::Closed;
                    control.recv_state = HalfState::Closed;
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                    continue;
                }

                // Catch streams dropped mid-tick while still in Listen/SynReceived so they
                // abort immediately and reap on the very next tick.
                if matches!(control.recv_state, HalfState::Close)
                    && matches!(control.send_state, HalfState::Close | HalfState::Closing)
                    && matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
                {
                    socket.abort();
                    control.send_state = HalfState::Closed;
                    control.recv_state = HalfState::Closed;
                    made_progress = true;
                    continue;
                }

                // Track whether this socket has ever left `Listen`. In smoltcp 0.14, receiving a
                // TCP RST in `SynReceived` clears `tuple` and reverts the socket BACK to `Listen`
                // instead of `Closed` (disabling its idle timer and poisoning `listening_dsts`).
                // Abort any reverted `Listen` socket immediately on this tick!
                if socket.state() != TcpState::Listen {
                    entry.saw_non_listen = true;
                } else if entry.saw_non_listen
                    || wall_now.saturating_duration_since(entry.created_at) >= LISTEN_ORPHAN_TIMEOUT
                {
                    socket.abort();
                    control.send_state = HalfState::Closed;
                    control.recv_state = HalfState::Closed;
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                    made_progress = true;
                    continue;
                }

                // Rapidly reclaim TIME_WAIT sockets after 2s so bursty mobile apps don't hold
                // memory or socket handles across 10s smoltcp CLOSE_DELAY windows.
                if socket.state() == TcpState::TimeWait {
                    let since = *entry.time_wait_since.get_or_insert(wall_now);
                    if wall_now.saturating_duration_since(since) >= TIME_WAIT_REAP_TIMEOUT {
                        socket.abort();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        made_progress = true;
                        continue;
                    }
                } else {
                    entry.time_wait_since = None;
                }

                // Bound half-closed / peer-dropped closing states to 5s (disabling keep-alive
                // probes that would otherwise keep resetting smoltcp's idle timer).
                if matches!(
                    socket.state(),
                    TcpState::FinWait1
                        | TcpState::FinWait2
                        | TcpState::Closing
                        | TcpState::LastAck
                        | TcpState::CloseWait
                ) && matches!(control.recv_state, HalfState::Close | HalfState::Closed)
                    && matches!(
                        control.send_state,
                        HalfState::Close | HalfState::Closing | HalfState::Closed
                    )
                {
                    if entry.closing_since.is_none() {
                        socket.set_keep_alive(None);
                        socket.set_timeout(Some(SmolDuration::from_secs(5)));
                    }
                    let since = *entry.closing_since.get_or_insert(wall_now);
                    if wall_now.saturating_duration_since(since) >= CLOSING_REAP_TIMEOUT {
                        socket.abort();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        made_progress = true;
                        continue;
                    }
                }

                // Prevent infinite FIN_WAIT_2 permit leaks: disable keep-alive probes that
                // would keep resetting smoltcp's idle timer and bound FIN_WAIT_2 to 15s.
                if socket.state() == TcpState::FinWait2 && !entry.fin_wait_2_shortened {
                    socket.set_keep_alive(None);
                    socket.set_timeout(Some(FIN_WAIT_2_TIMEOUT));
                    entry.fin_wait_2_shortened = true;
                }

                let mut wake_receiver = false;
                if matches!(control.recv_state, HalfState::Close) {
                    // Reader dropped; discard unread bytes so peer FIN can complete cleanly.
                    while socket.can_recv() {
                        if socket.recv(|buf| (buf.len(), ())).is_err() {
                            socket.abort();
                            break;
                        }
                    }
                } else {
                    while socket.can_recv() && !control.recv_buffer.is_full() {
                        match socket.recv(|buf| {
                            let n = control.recv_buffer.enqueue_slice(buf);
                            (n, n)
                        }) {
                            Ok(n) if n > 0 => {
                                wake_receiver = true;
                                made_progress = true;
                            }
                            Ok(_) => break,
                            Err(err) => {
                                debug!(error = ?err, state = ?socket.state(), "smoltcp recv error");
                                socket.abort();
                                if matches!(control.recv_state, HalfState::Normal) {
                                    control.recv_state = HalfState::Closed;
                                }
                                wake_receiver = true;
                                break;
                            }
                        }
                    }
                }

                let recv_open_states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, HalfState::Normal)
                    && !socket.may_recv()
                    && !recv_open_states.contains(&socket.state())
                {
                    control.recv_state = HalfState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Refill TX immediately if ACK freed window space during poll().
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    match socket.send(|buf| {
                        let n = control.send_buffer.dequeue_slice(buf);
                        (n, n)
                    }) {
                        Ok(n) if n > 0 => {
                            wake_sender = true;
                            made_progress = true;
                        }
                        Ok(_) => break,
                        Err(err) => {
                            debug!(error = ?err, state = ?socket.state(), "smoltcp post-poll send error");
                            socket.abort();
                            if matches!(control.send_state, HalfState::Normal) {
                                control.send_state = HalfState::Closed;
                            }
                            wake_sender = true;
                            break;
                        }
                    }
                }

                if matches!(control.send_state, HalfState::Close) && control.send_buffer.is_empty()
                {
                    socket.close();
                    control.send_state = HalfState::Closing;
                    made_progress = true;
                }

                if matches!(control.send_state, HalfState::Closing)
                    && matches!(
                        socket.state(),
                        TcpState::FinWait2 | TcpState::TimeWait | TcpState::Closed
                    )
                {
                    control.send_state = HalfState::Closed;
                    wake_sender = true;
                }

                if wake_sender {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }

                if socket.state() == TcpState::Listen {
                    listening_dsts.insert(entry.endpoints.1);
                }
            }

            for handle in sockets_to_remove.drain(..) {
                if let Some(entry) = sockets.remove(&handle) {
                    active_endpoints.remove(&entry.endpoints);
                }
                socket_set.remove(handle);
            }

            // 5. Flush emitted packets straight onto outbound_tx (zero silent drops).
            while let Some(pkt) = device.tx_queue.pop_front() {
                made_progress = true;
                match outbound_tx.try_send(pkt) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(pkt)) => {
                        tokio::select! {
                            biased;
                            _ = wait_shutdown(&mut shutdown_rx) => break 'runner,
                            res = outbound_tx.send(pkt) => {
                                if res.is_err() {
                                    break 'runner;
                                }
                            }
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break 'runner,
                }
            }

            let next_delay = iface.poll_delay(now, &socket_set);
            let deferred_ready = deferred_syns.iter().any(|(_, frame)| {
                inspect_tcp_frame(frame)
                    .is_none_or(|(_, dst_addr, _)| !listening_dsts.contains(&dst_addr))
            });
            let immediate_poll = made_progress
                || !device.rx_queue.is_empty()
                || deferred_ready
                || next_delay == Some(SmolDuration::ZERO);

            if immediate_poll {
                burst_iters += 1;
                if burst_iters >= POLL_BURST_LIMIT {
                    burst_iters = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }

            burst_iters = 0;

            let effective_delay = if !deferred_syns.is_empty() {
                let cap = SmolDuration::from_millis(50);
                Some(next_delay.map_or(cap, |d| d.min(cap)))
            } else {
                next_delay
            };

            // 6. Park cleanly until new inbound packet, stream wake, smoltcp timer, or shutdown.
            match effective_delay {
                Some(delay) => {
                    let sleep = tokio::time::sleep(std::time::Duration::from(delay));
                    tokio::pin!(sleep);
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => break 'runner,
                        maybe_pkt = tcp_in_rx.recv() => {
                            match maybe_pkt {
                                Some(frame) => {
                                    if let EnqueueOutcome::Deferred(deferred) = enqueue_inbound(
                                        frame,
                                        &mut device,
                                        &mut socket_set,
                                        &mut sockets,
                                        &mut active_endpoints,
                                        &mut listening_dsts,
                                        &stream_tx,
                                        &notify,
                                    ) {
                                        if deferred_syns.len() < MAX_DEFERRED_SYNS {
                                            deferred_syns.push_back((StdInstant::now(), deferred));
                                        }
                                    }
                                }
                                None => break 'runner,
                            }
                        }
                        _ = notify.notified() => {}
                        _ = &mut sleep => {}
                    }
                }
                None => {
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => break 'runner,
                        maybe_pkt = tcp_in_rx.recv() => {
                            match maybe_pkt {
                                Some(frame) => {
                                    if let EnqueueOutcome::Deferred(deferred) = enqueue_inbound(
                                        frame,
                                        &mut device,
                                        &mut socket_set,
                                        &mut sockets,
                                        &mut active_endpoints,
                                        &mut listening_dsts,
                                        &stream_tx,
                                        &notify,
                                    ) {
                                        if deferred_syns.len() < MAX_DEFERRED_SYNS {
                                            deferred_syns.push_back((StdInstant::now(), deferred));
                                        }
                                    }
                                }
                                None => break 'runner,
                            }
                        }
                        _ = notify.notified() => {}
                    }
                }
            }
        }
    });

    Ok((stream_rx, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn control_ring_size_decouples_ios_and_desktop_buffers() {
        assert_eq!(control_ring_size(16 * 1024), 16 * 1024);
        assert_eq!(control_ring_size(32 * 1024), 16 * 1024);
        assert_eq!(control_ring_size(64 * 1024), 64 * 1024);
        assert_eq!(control_ring_size(512 * 1024), 128 * 1024);
    }

    #[tokio::test]
    async fn tcp_netstack_jumbo_mtu_handshake_window_scaling_4mib_transfer_and_shutdown() {
        const MTU: usize = 16_384;
        const BUF: usize = 512 * 1024;
        const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(2048);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(2048);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, 64, 512, stop_rx).unwrap();

        // Build a peer smoltcp TCP client speaking raw IPv4 frames across in_tx / out_rx.
        let mut client_dev = VirtualDevice::new(MTU, 512);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x1234_5678_9abc_def0;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, SmolInstant::now());
        client_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(198, 18, 0, 1), 30));
        });
        client_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(198, 18, 0, 2))
            .unwrap();

        let mut client_sockets = SocketSet::new(Vec::new());
        let mut client_sock = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; BUF]),
            TcpSocketBuffer::new(vec![0u8; BUF]),
        );
        client_sock.set_ack_delay(None);
        client_sock.set_nagle_enabled(false);
        client_sock
            .connect(
                client_iface.context(),
                (Ipv4Address::new(1, 1, 1, 1), 443),
                45_000,
            )
            .unwrap();
        let client_handle = client_sockets.add(client_sock);

        // Emit SYN + duplicate SYN to verify SYN retransmit deduplication.
        client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);
        let syn_pkt = client_dev.tx_queue.pop_front().expect("SYN emitted");
        in_tx.send(syn_pkt.clone()).await.unwrap();
        in_tx.send(syn_pkt).await.unwrap();

        // Server accepts exactly ONE stream and writes 4 MiB + clean shutdown.
        let mut server_stream =
            tokio::time::timeout(std::time::Duration::from_secs(5), stream_rx.recv())
                .await
                .expect("accept timeout")
                .expect("accepted stream");
        assert_eq!(
            server_stream.local_addr(),
            "198.18.0.1:45000".parse().unwrap()
        );
        assert_eq!(server_stream.remote_addr(), "1.1.1.1:443".parse().unwrap());

        let server_task = tokio::spawn(async move {
            let mut req = [0u8; 4];
            server_stream.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"PING");

            let chunk = vec![0x5Au8; 64 * 1024];
            let mut remaining = PAYLOAD_BYTES;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                server_stream.write_all(&chunk[..n]).await.unwrap();
                remaining -= n;
            }
            server_stream.shutdown().await.unwrap();
        });

        let mut sent_ping = false;
        let mut received_bytes = 0usize;
        let mut saw_jumbo_segment = false;
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(10);

        loop {
            assert!(
                std::time::Instant::now() < deadline,
                "4 MiB transfer timed out at {received_bytes}/{PAYLOAD_BYTES} bytes"
            );

            while let Ok(pkt) = out_rx.try_recv() {
                if pkt.len() > 2000 {
                    saw_jumbo_segment = true;
                }
                client_dev.rx_queue.push_back(pkt);
            }

            client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);

            {
                let sock = client_sockets.get_mut::<TcpSocket>(client_handle);
                if !sent_ping && sock.can_send() {
                    sock.send_slice(b"PING").unwrap();
                    sent_ping = true;
                }
                while sock.can_recv() {
                    let n = sock
                        .recv(|buf| {
                            assert!(buf.iter().all(|&b| b == 0x5A));
                            (buf.len(), buf.len())
                        })
                        .unwrap();
                    received_bytes += n;
                }
                if received_bytes == PAYLOAD_BYTES && !sock.may_recv() {
                    sock.close();
                }
            }

            client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);

            while let Some(pkt) = client_dev.tx_queue.pop_front() {
                in_tx.send(pkt).await.unwrap();
            }

            if received_bytes == PAYLOAD_BYTES
                && client_sockets.get::<TcpSocket>(client_handle).state() == TcpState::Closed
            {
                break;
            }

            tokio::task::yield_now().await;
        }

        assert!(
            saw_jumbo_segment,
            "expected jumbo >2000B TCP segments at MTU 16384"
        );
        assert!(
            stream_rx.try_recv().is_err(),
            "duplicate SYN must not create a second stream"
        );

        server_task.await.unwrap();
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner_handle).await;
    }

    #[tokio::test]
    async fn parallel_syns_to_same_dst_enforce_session_cap_and_reap_dropped_syn_received() {
        const MTU: usize = 1500;
        const BUF: usize = 32 * 1024;
        const MAX_SESSIONS: usize = 4;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, MAX_SESSIONS, 128, stop_rx).unwrap();

        let mut client_dev = VirtualDevice::new(MTU, 128);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x0fed_cba9_8765_4321;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, SmolInstant::now());
        client_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(198, 18, 0, 1), 30));
        });
        client_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(198, 18, 0, 2))
            .unwrap();

        let mut client_sockets = SocketSet::new(Vec::new());
        for offset in 0..6u16 {
            let mut sock = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 4096]),
                TcpSocketBuffer::new(vec![0u8; 4096]),
            );
            sock.connect(
                client_iface.context(),
                (Ipv4Address::new(1, 1, 1, 1), 443),
                46_000 + offset,
            )
            .unwrap();
            client_sockets.add(sock);
        }

        client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);
        let syn_pkts: Vec<Vec<u8>> = client_dev.tx_queue.drain(..).collect();
        assert_eq!(syn_pkts.len(), 6);

        let expected_srcs: Vec<SocketAddr> = syn_pkts
            .iter()
            .map(|pkt| inspect_tcp_frame(pkt).unwrap().0)
            .collect();

        // Send all 6 parallel SYNs targeting the same 1.1.1.1:443 in a single burst.
        for pkt in &syn_pkts {
            in_tx.send(pkt.clone()).await.unwrap();
        }

        let mut accepted = Vec::with_capacity(MAX_SESSIONS);
        for expected_src in expected_srcs.iter().take(MAX_SESSIONS) {
            let stream = tokio::time::timeout(std::time::Duration::from_secs(3), stream_rx.recv())
                .await
                .expect("accept timeout")
                .expect("accepted stream");
            assert_eq!(stream.local_addr(), *expected_src);
            assert_eq!(stream.remote_addr(), "1.1.1.1:443".parse().unwrap());
            accepted.push(stream);
        }

        // Excess SYNs beyond max_tcp_sessions must be dropped cleanly.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            stream_rx.try_recv().is_err(),
            "SYNs beyond max_tcp_sessions must be dropped"
        );
        while out_rx.try_recv().is_ok() {}

        // Dropping all 4 SynReceived streams must abort and reap them immediately,
        // freeing capacity so the 5th SYN is accepted cleanly.
        drop(accepted);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        in_tx.send(syn_pkts[4].clone()).await.unwrap();

        let fifth = tokio::time::timeout(std::time::Duration::from_secs(3), stream_rx.recv())
            .await
            .expect("post-drop accept timeout")
            .expect("post-drop accepted stream");
        assert_eq!(fifth.local_addr(), expected_srcs[4]);
        assert_eq!(fifth.remote_addr(), "1.1.1.1:443".parse().unwrap());

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner_handle).await;
    }

    #[tokio::test]
    async fn syn_received_rst_revert_aborts_immediately_and_overflow_emits_rst_ack() {
        const MTU: usize = 1500;
        const BUF: usize = 32 * 1024;
        const MAX_SESSIONS: usize = 2;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, MAX_SESSIONS, 128, stop_rx).unwrap();

        let mut client_dev = VirtualDevice::new(MTU, 128);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x55aa_1234_9876_fedc;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, SmolInstant::now());
        client_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(198, 18, 0, 1), 30));
        });
        client_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(198, 18, 0, 2))
            .unwrap();

        // 1. Send SYN #1 -> enters SynReceived, then client sends RST (smoltcp 0.14 reverts to Listen!).
        let mut client_sockets = SocketSet::new(Vec::new());
        let mut s1 = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        s1.connect(
            client_iface.context(),
            (Ipv4Address::new(2, 22, 89, 36), 443),
            47_001,
        )
        .unwrap();
        let h1 = client_sockets.add(s1);
        client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);
        let syn1 = client_dev.tx_queue.pop_front().expect("SYN 1");
        in_tx.send(syn1).await.unwrap();

        let _stream1 = tokio::time::timeout(std::time::Duration::from_secs(2), stream_rx.recv())
            .await
            .expect("accept 1")
            .expect("stream 1");
        let syn_ack1 = tokio::time::timeout(std::time::Duration::from_secs(2), out_rx.recv())
            .await
            .expect("syn-ack 1")
            .expect("pkt");
        assert!(Ipv4Packet::new_checked(&syn_ack1).is_ok());

        // Abort client socket #1 -> emits RST to netstack while server socket is in SynReceived.
        client_sockets.get_mut::<TcpSocket>(h1).abort();
        client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);
        if let Some(rst1) = client_dev.tx_queue.pop_front() {
            in_tx.send(rst1).await.unwrap();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // 2. Follow-up SYN #2 to the EXACT SAME dst (2.22.89.36:443) must accept immediately
        //    (proving the reverted Listen socket did NOT poison listening_dsts!).
        let mut s2 = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        s2.connect(
            client_iface.context(),
            (Ipv4Address::new(2, 22, 89, 36), 443),
            47_002,
        )
        .unwrap();
        client_sockets.add(s2);
        let mut s3 = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        s3.connect(
            client_iface.context(),
            (Ipv4Address::new(2, 22, 89, 37), 443),
            47_003,
        )
        .unwrap();
        client_sockets.add(s3);
        let mut s4 = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 4096]),
            TcpSocketBuffer::new(vec![0u8; 4096]),
        );
        s4.connect(
            client_iface.context(),
            (Ipv4Address::new(2, 22, 89, 38), 443),
            47_004,
        )
        .unwrap();
        client_sockets.add(s4);

        client_iface.poll(SmolInstant::now(), &mut client_dev, &mut client_sockets);
        let pkts: Vec<Vec<u8>> = client_dev.tx_queue.drain(..).collect();
        assert_eq!(pkts.len(), 3);
        for pkt in pkts {
            in_tx.send(pkt).await.unwrap();
        }

        // First two fill MAX_SESSIONS = 2; third overflows and must receive a valid RST+ACK!
        let _keep2 = tokio::time::timeout(std::time::Duration::from_secs(2), stream_rx.recv())
            .await
            .expect("accept 2")
            .expect("stream 2");
        let _keep3 = tokio::time::timeout(std::time::Duration::from_secs(2), stream_rx.recv())
            .await
            .expect("accept 3")
            .expect("stream 3");

        let mut saw_rst_ack = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_millis(100), out_rx.recv()).await {
                Ok(Some(pkt)) => {
                    if let Ok(ip) = Ipv4Packet::new_checked(&pkt) {
                        if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                            if tcp.rst() && tcp.ack() && tcp.dst_port() == 47_004 {
                                assert!(ip.verify_checksum());
                                saw_rst_ack = true;
                                break;
                            }
                        }
                    }
                }
                _ => break,
            }
        }
        assert!(
            saw_rst_ack,
            "expected valid IPv4 TCP RST+ACK on session capacity overflow"
        );

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner_handle).await;
    }
}
