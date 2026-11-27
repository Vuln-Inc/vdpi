use anyhow::{anyhow, Result};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{
        tcp::{
            CongestionControl, Socket as TcpSocket, SocketBuffer as TcpSocketBuffer,
            State as TcpState,
        },
        Socket as SmolSocket,
    },
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration as StdDuration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, watch, Notify};
use tracing::{debug, trace};

const INGRESS_DRAIN_LIMIT: usize = 128;
const POLL_BURST_LIMIT: usize = 4;
const ZERO_DELAY_BACKOFF_MIN_MS: u64 = 5;
const ZERO_DELAY_BACKOFF_MAX_MS: u64 = 25;
const SMALL_TX_POOL_MAX_BYTES: usize = 128;
const SMALL_TX_POOL_ADMIT_MAX_BYTES: usize = 512;
const TX_HEADER_ZERO_LEN: usize = 100;
const FIN_WAIT_2_TIMEOUT: SmolDuration = SmolDuration::from_secs(15);
const LISTEN_ORPHAN_TIMEOUT: StdDuration = StdDuration::from_secs(3);
const TIME_WAIT_REAP_TIMEOUT: StdDuration = StdDuration::from_millis(250);
const CLOSING_REAP_TIMEOUT: StdDuration = StdDuration::from_secs(5);
const DEFERRED_SYN_TTL: StdDuration = StdDuration::from_secs(2);
const MAX_DEFERRED_SYNS: usize = 128;
const SOCKET_POOL_CAP_DESKTOP: usize = 16;
const SOCKET_POOL_CAP_LOW_MEM: usize = 8;
const POOL_IDLE_SHRINK_TIMEOUT: StdDuration = StdDuration::from_secs(30);
const SOCKET_SET_SHRINK_THRESHOLD: usize = 64;
const REAP_DELAY_FLOOR: StdDuration = StdDuration::from_millis(20);
const STALE_TIMER_SLACK: StdDuration = StdDuration::from_millis(50);
const IP_PROTO_TCP: u8 = 6;

/// Monotonic microsecond clock for `smoltcp`, anchored above `Instant::ZERO` so
/// Windows NTP clock adjustments can never move timestamps backwards or collide
/// with `smoltcp`'s `Instant::ZERO` expired-timer sentinel.
struct MonotonicClock {
    epoch: StdInstant,
}

impl MonotonicClock {
    const BASE_MICROS: i64 = 1_000_000_000;

    fn new() -> Self {
        Self {
            epoch: StdInstant::now(),
        }
    }

    #[inline]
    fn smol_from(&self, instant: StdInstant) -> SmolInstant {
        let elapsed = instant.saturating_duration_since(self.epoch).as_micros();
        let offset = i64::try_from(elapsed).unwrap_or(i64::MAX - Self::BASE_MICROS);
        SmolInstant::from_micros(Self::BASE_MICROS.saturating_add(offset))
    }

    #[inline]
    fn now(&self) -> SmolInstant {
        self.smol_from(StdInstant::now())
    }
}

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
    /// True when the reactor paused draining `smoltcp` RX because `recv_buffer` filled up.
    /// `poll_read` only notifies the reactor when this flag is set, eliminating spurious wakeups.
    rx_backpressured: bool,
}

#[cfg_attr(
    any(target_arch = "x86_64", target_arch = "aarch64"),
    repr(align(128))
)]
#[cfg_attr(
    not(any(target_arch = "x86_64", target_arch = "aarch64")),
    repr(align(64))
)]
struct CachePadded<T>(T);

struct SocketDirtyFlags {
    tx_dirty: AtomicBool,
    rx_dirty: AtomicBool,
}

/// Shared state between a `TunNetstackTcpStream` and the reactor loop.
/// `dirty` is padded to its own cache line so hot reactor dirty-flag scans never
/// false-share with `control` mutex lock/unlock traffic on application cores.
#[repr(C)]
struct SocketShared {
    dirty: CachePadded<SocketDirtyFlags>,
    control: Mutex<TcpSocketControl>,
}

impl SocketShared {
    fn new(control: TcpSocketControl) -> Self {
        Self {
            dirty: CachePadded(SocketDirtyFlags {
                tx_dirty: AtomicBool::new(false),
                rx_dirty: AtomicBool::new(false),
            }),
            control: Mutex::new(control),
        }
    }

    #[inline]
    fn lock_control(&self) -> std::sync::MutexGuard<'_, TcpSocketControl> {
        self.control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[inline]
    fn mark_tx_dirty(&self) {
        self.dirty.0.tx_dirty.store(true, Ordering::SeqCst);
    }

    #[inline]
    fn mark_rx_dirty(&self) {
        self.dirty.0.rx_dirty.store(true, Ordering::SeqCst);
    }

    /// Guarded swap so idle sockets perform only a shared `SeqCst` read (plain `MOV` on
    /// x86-64 with zero write invalidation, and formally Dekker-sound on ARMv8.3-RCPC)
    /// instead of an unconditional `SeqCst` RMW (`LOCK XCHG`) cache-line write on every
    /// reactor tick.
    #[inline]
    fn take_tx_dirty(&self) -> bool {
        self.dirty.0.tx_dirty.load(Ordering::SeqCst)
            && self.dirty.0.tx_dirty.swap(false, Ordering::SeqCst)
    }

    /// Guarded swap so idle sockets perform only a shared `SeqCst` read (plain `MOV` on
    /// x86-64 with zero write invalidation, and formally Dekker-sound on ARMv8.3-RCPC)
    /// instead of an unconditional `SeqCst` RMW (`LOCK XCHG`) cache-line write on every
    /// reactor tick.
    #[inline]
    fn take_rx_dirty(&self) -> bool {
        self.dirty.0.rx_dirty.load(Ordering::SeqCst)
            && self.dirty.0.rx_dirty.swap(false, Ordering::SeqCst)
    }
}

type SharedControl = Arc<SocketShared>;

/// In-tree userspace TCP stream backed by `smoltcp` 0.14 with immediate ACKs
/// (`ack_delay = None`), Nagle disabled, `CongestionControl::None` on the local
/// zero-loss virtual TUN hop, RFC 7323 window scaling, and batched queue handoff.
pub(crate) struct TunNetstackTcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: Arc<Notify>,
    reactor_notified: Arc<AtomicBool>,
    shared: SharedControl,
}

impl TunNetstackTcpStream {
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    /// Coalesces reactor notifications behind a shared `AtomicBool` so high-rate
    /// download streams do not hammer `Arc<Notify>` on every `poll_write`.
    /// Callers MUST store `tx_dirty` / `rx_dirty` with `Ordering::SeqCst` prior to
    /// invoking this method; the reactor clears `reactor_notified` with `SeqCst`
    /// before scanning dirty flags, guaranteeing zero lost wakeups on x86 and ARM64.
    #[inline]
    fn notify_reactor(&self) {
        if !self.reactor_notified.load(Ordering::SeqCst)
            && !self.reactor_notified.swap(true, Ordering::SeqCst)
        {
            self.notify.notify_one();
        }
    }
}

impl Drop for TunNetstackTcpStream {
    fn drop(&mut self) {
        let mut control = self.shared.lock_control();
        if matches!(control.recv_state, HalfState::Normal) {
            control.recv_state = HalfState::Close;
        }
        if matches!(control.send_state, HalfState::Normal) {
            control.send_state = HalfState::Close;
        }
        drop(control);
        self.shared.mark_tx_dirty();
        self.shared.mark_rx_dirty();
        self.notify_reactor();
    }
}

impl AsyncRead for TunNetstackTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut control = self.shared.lock_control();

        if control.recv_buffer.is_empty() {
            if matches!(control.recv_state, HalfState::Closed) {
                return Poll::Ready(Ok(()));
            }
            let old_waker = control.recv_waker.replace(cx.waker().clone());
            drop(control);
            if let Some(old) = old_waker {
                if !old.will_wake(cx.waker()) {
                    old.wake();
                }
            }
            return Poll::Pending;
        }

        let to_read = control.recv_buffer.len().min(buf.remaining());
        let unfilled = buf.initialize_unfilled_to(to_read);
        let n = control.recv_buffer.dequeue_slice(unfilled);
        buf.advance(n);
        let should_notify = if n > 0 && control.rx_backpressured {
            control.rx_backpressured = false;
            true
        } else {
            false
        };
        drop(control);

        if should_notify {
            self.shared.mark_rx_dirty();
            self.notify_reactor();
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
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut control = self.shared.lock_control();

        if !matches!(control.send_state, HalfState::Normal) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }

        if control.send_buffer.is_full() {
            let old_waker = control.send_waker.replace(cx.waker().clone());
            drop(control);
            if let Some(old) = old_waker {
                if !old.will_wake(cx.waker()) {
                    old.wake();
                }
            }
            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);
        drop(control);

        if n > 0 {
            self.shared.mark_tx_dirty();
            self.notify_reactor();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut control = self.shared.lock_control();

        if matches!(control.send_state, HalfState::Closed) {
            return Poll::Ready(Ok(()));
        }

        if matches!(control.send_state, HalfState::Normal) {
            control.send_state = HalfState::Close;
        }

        let old_waker = control.send_waker.replace(cx.waker().clone());
        drop(control);
        if let Some(old) = old_waker {
            if !old.will_wake(cx.waker()) {
                old.wake();
            }
        }

        self.shared.mark_tx_dirty();
        self.notify_reactor();
        Poll::Pending
    }
}

struct VirtualRxToken<'a> {
    buf: Vec<u8>,
    recycle: &'a mut Vec<Vec<u8>>,
    recycle_cap: usize,
    max_buf_cap: usize,
}

impl RxToken for VirtualRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let res = f(&self.buf);
        let cap = self.buf.capacity();
        if self.recycle.len() < self.recycle_cap
            && (SMALL_TX_POOL_MAX_BYTES..=self.max_buf_cap).contains(&cap)
        {
            self.recycle.push(self.buf);
        }
        res
    }
}

struct TxBufferPool {
    small: Vec<Vec<u8>>,
    large: Vec<Vec<u8>>,
    mtu: usize,
    small_cap: usize,
    large_cap: usize,
    max_buf_cap: usize,
}

impl TxBufferPool {
    fn new(mtu: usize, small_cap: usize, large_cap: usize) -> Self {
        Self {
            small: Vec::with_capacity(small_cap),
            large: Vec::with_capacity(large_cap),
            mtu,
            small_cap,
            large_cap,
            max_buf_cap: mtu.max(2048),
        }
    }

    #[inline]
    fn checkout(&mut self, len: usize) -> Vec<u8> {
        let reused = if len <= SMALL_TX_POOL_MAX_BYTES {
            self.small.pop()
        } else if len <= self.mtu {
            self.large.pop()
        } else {
            None
        };

        match reused {
            Some(mut buf) => {
                debug_assert!(buf.capacity() >= len);
                let prev_len = buf.len();
                if prev_len >= len {
                    buf.truncate(len);
                    buf[..len.min(TX_HEADER_ZERO_LEN)].fill(0);
                } else {
                    buf.resize(len, 0);
                    buf[..prev_len.min(TX_HEADER_ZERO_LEN)].fill(0);
                }
                buf
            }
            None => {
                let alloc_cap = if len <= SMALL_TX_POOL_MAX_BYTES {
                    SMALL_TX_POOL_MAX_BYTES
                } else {
                    len.max(self.mtu)
                };
                let mut buf = Vec::with_capacity(alloc_cap);
                buf.resize(len, 0);
                buf
            }
        }
    }

    #[inline]
    fn recycle_all(&mut self, incoming: &mut Vec<Vec<u8>>) {
        for buf in incoming.drain(..) {
            let cap = buf.capacity();
            if cap > self.max_buf_cap {
                continue;
            }
            if cap >= self.mtu {
                if self.large.len() < self.large_cap {
                    self.large.push(buf);
                }
            } else if (SMALL_TX_POOL_MAX_BYTES..=SMALL_TX_POOL_ADMIT_MAX_BYTES).contains(&cap)
                && self.small.len() < self.small_cap
            {
                self.small.push(buf);
            }
        }
    }
}

struct VirtualTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
    pool: &'a mut TxBufferPool,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.pool.checkout(len);
        let res = f(&mut buf);
        self.tx_queue.push_back(buf);
        res
    }
}

struct VirtualDevice {
    mtu: usize,
    tx_queue_high_water: usize,
    tx_throttled: bool,
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    rx_recycle: Vec<Vec<u8>>,
    tx_pool: TxBufferPool,
    recycle_cap: usize,
}

impl VirtualDevice {
    fn new(mtu: usize, tx_queue_high_water: usize, low_memory: bool) -> Self {
        let tx_queue_high_water = tx_queue_high_water.clamp(16, 64);
        let (small_cap, large_cap) = if low_memory {
            (16, 8)
        } else {
            (64, tx_queue_high_water.clamp(32, 64))
        };
        let recycle_cap = small_cap + large_cap;
        Self {
            mtu,
            tx_queue_high_water,
            tx_throttled: false,
            rx_queue: VecDeque::with_capacity(INGRESS_DRAIN_LIMIT),
            tx_queue: VecDeque::with_capacity(INGRESS_DRAIN_LIMIT.min(tx_queue_high_water)),
            rx_recycle: Vec::with_capacity(recycle_cap.min(INGRESS_DRAIN_LIMIT)),
            tx_pool: TxBufferPool::new(mtu, small_cap, large_cap),
            recycle_cap,
        }
    }

    #[inline]
    fn recycle_consumed_rx(&mut self) {
        if !self.rx_recycle.is_empty() {
            self.tx_pool.recycle_all(&mut self.rx_recycle);
        }
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken<'a>
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
        let max_buf_cap = self.tx_pool.max_buf_cap;
        Some((
            VirtualRxToken {
                buf: pkt,
                recycle: &mut self.rx_recycle,
                recycle_cap: self.recycle_cap,
                max_buf_cap,
            },
            VirtualTxToken {
                tx_queue: &mut self.tx_queue,
                pool: &mut self.tx_pool,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= self.tx_queue_high_water {
            self.tx_throttled = true;
            return None;
        }
        Some(VirtualTxToken {
            tx_queue: &mut self.tx_queue,
            pool: &mut self.tx_pool,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Skip redundant software RX checksum verification on OS-generated local TUN frames,
        // while always emitting valid IPv4 + TCP + ICMPv6 TX checksums required by Wintun/utun/Linux TUN.
        let mut checksum = ChecksumCapabilities::ignored();
        checksum.ipv4 = Checksum::Tx;
        checksum.tcp = Checksum::Tx;
        checksum.icmpv6 = Checksum::Tx;
        caps.checksum = checksum;
        caps
    }
}

struct SocketEntry {
    shared: SharedControl,
    endpoints: (SocketAddr, SocketAddr),
    created_at: StdInstant,
    saw_non_listen: bool,
    fin_wait_2_shortened: bool,
    is_active: bool,
    closing_since: Option<StdInstant>,
    time_wait_since: Option<StdInstant>,
    /// Reactor-owned mirrors of `TcpSocketControl` state so idle sockets require zero mutex locks.
    tx_has_pending: bool,
    rx_backpressured: bool,
    recv_open: bool,
    recv_closing: bool,
    send_closing: bool,
    app_closed_both: bool,
}

/// Bounded pool of reusable `smoltcp` `TcpSocket` instances (each owning its RX/TX `Vec<u8>`
/// ring buffers) and `TcpSocketControl` `RingBuffer`s. Eliminates ~1 MiB per-SYN heap
/// allocation/decommit cycles and Windows NT HeapLock / TLB shootdowns during connection bursts.
struct SocketBufferPool {
    sockets: Vec<TcpSocket<'static>>,
    control_recv: Vec<RingBuffer<'static, u8>>,
    control_send: Vec<RingBuffer<'static, u8>>,
    tcp_recv_size: usize,
    tcp_send_size: usize,
    control_recv_size: usize,
    control_send_size: usize,
    max_sockets: usize,
    max_control: usize,
}

impl SocketBufferPool {
    fn new(
        tcp_recv_size: usize,
        tcp_send_size: usize,
        control_recv_size: usize,
        control_send_size: usize,
        low_memory: bool,
    ) -> Self {
        let cap = if low_memory {
            SOCKET_POOL_CAP_LOW_MEM
        } else {
            SOCKET_POOL_CAP_DESKTOP
        };
        Self {
            sockets: Vec::with_capacity(cap),
            control_recv: Vec::with_capacity(cap),
            control_send: Vec::with_capacity(cap),
            tcp_recv_size,
            tcp_send_size,
            control_recv_size,
            control_send_size,
            max_sockets: cap,
            max_control: cap,
        }
    }

    #[inline]
    fn checkout_socket(&mut self) -> TcpSocket<'static> {
        self.sockets.pop().unwrap_or_else(|| {
            TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; self.tcp_recv_size]),
                TcpSocketBuffer::new(vec![0u8; self.tcp_send_size]),
            )
        })
    }

    #[inline]
    fn return_socket(&mut self, mut socket: TcpSocket<'static>) {
        if self.sockets.len() >= self.max_sockets {
            return;
        }
        if socket.recv_capacity() != self.tcp_recv_size
            || socket.send_capacity() != self.tcp_send_size
        {
            return;
        }
        // Socket is already removed from `SocketSet`, so `abort()` only sets `State::Closed`
        // (zero RST emitted). The next `socket.listen(...)` unconditionally calls `reset()`,
        // clearing both smoltcp ring buffers, assembler, RTT estimator, and TCP sequence state.
        socket.abort();
        self.sockets.push(socket);
    }

    #[inline]
    fn checkout_control_buffers(&mut self) -> (RingBuffer<'static, u8>, RingBuffer<'static, u8>) {
        let mut recv = self
            .control_recv
            .pop()
            .unwrap_or_else(|| RingBuffer::new(vec![0u8; self.control_recv_size]));
        let mut send = self
            .control_send
            .pop()
            .unwrap_or_else(|| RingBuffer::new(vec![0u8; self.control_send_size]));
        recv.clear();
        send.clear();
        (recv, send)
    }

    #[inline]
    fn return_control_recv(&mut self, mut buf: RingBuffer<'static, u8>) {
        if self.control_recv.len() < self.max_control && buf.capacity() == self.control_recv_size {
            buf.clear();
            self.control_recv.push(buf);
        }
    }

    #[inline]
    fn return_control_send(&mut self, mut buf: RingBuffer<'static, u8>) {
        if self.control_send.len() < self.max_control && buf.capacity() == self.control_send_size {
            buf.clear();
            self.control_send.push(buf);
        }
    }

    #[inline]
    fn reclaim_shared_buffers(&mut self, shared: SharedControl) {
        match Arc::try_unwrap(shared) {
            Ok(owned) => {
                let control = owned
                    .control
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                self.return_control_recv(control.recv_buffer);
                self.return_control_send(control.send_buffer);
            }
            Err(shared) => {
                let (recv_buf, send_buf) = {
                    let mut control = shared.lock_control();
                    let send_buf = if matches!(control.send_state, HalfState::Closed)
                        && control.send_buffer.capacity() == self.control_send_size
                    {
                        Some(std::mem::replace(
                            &mut control.send_buffer,
                            RingBuffer::new(Vec::new()),
                        ))
                    } else {
                        None
                    };
                    let recv_buf = if matches!(control.recv_state, HalfState::Closed)
                        && control.recv_buffer.is_empty()
                        && control.recv_buffer.capacity() == self.control_recv_size
                    {
                        Some(std::mem::replace(
                            &mut control.recv_buffer,
                            RingBuffer::new(Vec::new()),
                        ))
                    } else {
                        None
                    };
                    (recv_buf, send_buf)
                };
                if let Some(buf) = recv_buf {
                    self.return_control_recv(buf);
                }
                if let Some(buf) = send_buf {
                    self.return_control_send(buf);
                }
            }
        }
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.sockets.is_empty() && self.control_recv.is_empty() && self.control_send.is_empty()
    }

    #[inline]
    fn shrink_idle(&mut self) {
        self.sockets.clear();
        self.control_recv.clear();
        self.control_send.clear();
    }
}

#[inline]
fn sync_active_flag(entry: &mut SocketEntry, active_count: &mut usize, now_active: bool) {
    if entry.is_active != now_active {
        entry.is_active = now_active;
        if now_active {
            *active_count = active_count.saturating_add(1);
        } else {
            *active_count = active_count.saturating_sub(1);
        }
    }
}

#[inline]
fn should_reset_timer(
    is_elapsed: bool,
    timer_deadline: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
    desired: tokio::time::Instant,
) -> bool {
    is_elapsed
        || timer_deadline.is_none_or(|cur| {
            desired < cur
                || cur <= now
                || (desired > cur && cur.saturating_duration_since(now) < STALE_TIMER_SLACK)
        })
}

enum InboundTcpKind {
    Invalid,
    NonSyn,
    InitialSyn(SocketAddr, SocketAddr),
}

enum EnqueueOutcome {
    Enqueued,
    Dropped,
    Deferred(SocketAddr, Vec<u8>),
}

fn internet_checksum_sum(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let (chunks, rem) = data.as_chunks::<2>();
    for &[hi, lo] in chunks {
        sum += u32::from(u16::from_be_bytes([hi, lo]));
    }
    if let Some(&byte) = rem.first() {
        sum += u32::from(u16::from_be_bytes([byte, 0]));
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
            let tcp_payload = crate::packet::ipv6_tcp_payload(syn_frame)?;
            let tcp = TcpPacket::new_checked(tcp_payload).ok()?;
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
    active_count: &mut usize,
    buffer_pool: &mut SocketBufferPool,
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
        if let Some(entry) = sockets.remove(&handle) {
            active_endpoints.remove(&entry.endpoints);
            if entry.is_active {
                *active_count = active_count.saturating_sub(1);
            }
            let (send_waker, recv_waker) = {
                let mut control = entry.shared.lock_control();
                control.send_state = HalfState::Closed;
                control.recv_state = HalfState::Closed;
                (control.send_waker.take(), control.recv_waker.take())
            };
            if let Some(w) = send_waker {
                w.wake();
            }
            if let Some(w) = recv_waker {
                w.wake();
            }
            buffer_pool.reclaim_shared_buffers(entry.shared);
        }
        let SmolSocket::Tcp(socket) = socket_set.remove(handle);
        buffer_pool.return_socket(socket);
        true
    } else {
        false
    }
}

/// Decouples `TcpSocketControl` ring sizes from `smoltcp`'s `TcpSocketBuffer` so iOS
/// (`<= 32 KiB`) uses 16 KiB control rings, standard/desktop (`< 1 MiB`) uses 64 KiB, and
/// `>= 1 MiB` desktop buffers use 256 KiB rings to cut lock/notify frequency at 1 Gbps.
fn control_ring_size(tcp_buffer_size: usize) -> usize {
    if tcp_buffer_size <= 32 * 1024 {
        tcp_buffer_size.min(16 * 1024)
    } else if tcp_buffer_size >= 1024 * 1024 {
        tcp_buffer_size.min(256 * 1024)
    } else {
        tcp_buffer_size.min(64 * 1024)
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

fn create_interface(device: &mut VirtualDevice, now: SmolInstant) -> Result<Interface> {
    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = generate_random_seed();
    let mut iface = Interface::new(iface_config, device, now);
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

/// Fast-path classifier for inbound IPv4/IPv6 TCP frames.
/// Avoids constructing `SocketAddr` on the 99.9% non-SYN data/ACK hot path.
#[inline]
fn classify_inbound_tcp(frame: &[u8]) -> InboundTcpKind {
    let Some(&first) = frame.first() else {
        return InboundTcpKind::Invalid;
    };
    match first >> 4 {
        4 => {
            let Ok(ip) = Ipv4Packet::new_checked(frame) else {
                return InboundTcpKind::Invalid;
            };
            if ip.next_header() != IpProtocol::Tcp {
                return InboundTcpKind::Invalid;
            }
            let src_ip = ip.src_addr();
            let dst_ip = ip.dst_addr();
            if src_ip.is_unspecified() || dst_ip.is_unspecified() {
                return InboundTcpKind::Invalid;
            }
            let Ok(tcp) = TcpPacket::new_checked(ip.payload()) else {
                return InboundTcpKind::Invalid;
            };
            let src_port = tcp.src_port();
            let dst_port = tcp.dst_port();
            if src_port == 0 || dst_port == 0 {
                return InboundTcpKind::Invalid;
            }
            if tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin() {
                let src_addr = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                let dst_addr = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
                InboundTcpKind::InitialSyn(src_addr, dst_addr)
            } else {
                InboundTcpKind::NonSyn
            }
        }
        6 => {
            let Ok(ip) = Ipv6Packet::new_checked(frame) else {
                return InboundTcpKind::Invalid;
            };
            let src_ip = ip.src_addr();
            let dst_ip = ip.dst_addr();
            if src_ip.is_unspecified() || dst_ip.is_unspecified() {
                return InboundTcpKind::Invalid;
            }
            let Some(tcp_payload) = crate::packet::ipv6_tcp_payload(frame) else {
                return InboundTcpKind::Invalid;
            };
            let Ok(tcp) = TcpPacket::new_checked(tcp_payload) else {
                return InboundTcpKind::Invalid;
            };
            let src_port = tcp.src_port();
            let dst_port = tcp.dst_port();
            if src_port == 0 || dst_port == 0 {
                return InboundTcpKind::Invalid;
            }
            if tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin() {
                let src_addr = SocketAddr::new(IpAddr::V6(src_ip), src_port);
                let dst_addr = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);
                InboundTcpKind::InitialSyn(src_addr, dst_addr)
            } else {
                InboundTcpKind::NonSyn
            }
        }
        _ => InboundTcpKind::Invalid,
    }
}

/// Strips IPv6 extension headers (Hop-by-Hop `0`, Routing `43`, atomic Fragment `44`,
/// Destination Options `60`) from a validated inbound IPv6 TCP packet into a canonical
/// 40-byte IPv6 header (`NextHeader = 6`, `PayloadLength = tcp_segment.len()`) + TCP
/// segment before pushing into `device.rx_queue`, because `smoltcp` 0.14 otherwise
/// rejects IPv6 extension headers with ICMPv6 Parameter Problem.
#[inline]
fn normalize_inbound_ipv6_tcp(mut frame: Vec<u8>) -> Option<Vec<u8>> {
    if frame.len() < 40 || (frame[0] >> 4) != 6 || frame[6] == IP_PROTO_TCP {
        return Some(frame);
    }
    let (tcp_start, tcp_len) = {
        let tcp = crate::packet::ipv6_tcp_payload(&frame)?;
        let start = (tcp.as_ptr() as usize).checked_sub(frame.as_ptr() as usize)?;
        let len = tcp.len();
        let end = start.checked_add(len)?;
        if start <= 40 || end > frame.len() {
            return None;
        }
        (start, len)
    };
    let payload_len = u16::try_from(tcp_len).ok()?;
    frame.copy_within(tcp_start..tcp_start + tcp_len, 40);
    frame.truncate(40 + tcp_len);
    frame[4..6].copy_from_slice(&payload_len.to_be_bytes());
    frame[6] = IP_PROTO_TCP;
    Some(frame)
}

/// Inspects an IPv4/IPv6 frame to see whether it is a valid TCP packet.
/// Returns `Some((src_addr, dst_addr, is_initial_syn))` for valid TCP frames.
#[cfg(test)]
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
            let tcp_payload = crate::packet::ipv6_tcp_payload(frame)?;
            (
                IpAddr::V6(ip.src_addr()),
                IpAddr::V6(ip.dst_addr()),
                tcp_payload,
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

#[inline]
fn configure_local_tun_socket(socket: &mut TcpSocket<'_>) {
    // Disable delayed ACK, Nagle, and local congestion control on the zero-loss
    // in-memory TUN leg (real congestion control runs on the OS outbound socket).
    socket.set_ack_delay(None);
    socket.set_nagle_enabled(false);
    socket.set_congestion_control(CongestionControl::None);
    socket.set_keep_alive(Some(SmolDuration::from_secs(20)));
    socket.set_timeout(Some(SmolDuration::from_secs(60)));
}

#[inline]
fn is_recv_open_state(state: TcpState) -> bool {
    matches!(
        state,
        TcpState::Listen
            | TcpState::SynReceived
            | TcpState::Established
            | TcpState::FinWait1
            | TcpState::FinWait2
    )
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

/// Computes the hard handle ceiling in `smoltcp`'s `SocketSet` (including `TimeWait`/closing
/// handles): `max_tcp_sessions + 32` on `low_memory` (iOS ~50 MB Jetsam ceiling), and
/// `max_tcp_sessions + 64` on desktop.
#[inline]
fn hard_handle_cap_for(max_tcp_sessions: usize, low_memory: bool) -> usize {
    if low_memory {
        max_tcp_sessions.saturating_add(32)
    } else {
        max_tcp_sessions.saturating_add(64)
    }
}

/// Spawns the in-tree `smoltcp` 0.14 TCP netstack runner directly bridging `tcp_in_rx`
/// and `outbound_tx` with batched ingress draining before a single `iface.poll()`,
/// `ack_delay = None`, `nagle = false`, `CongestionControl::None`, `Checksum::Tx`,
/// zero-spin async readiness parking, and reusable Tokio timers.
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
    let low_memory = tcp_recv_buffer_size <= 32 * 1024;
    let hard_handle_cap = hard_handle_cap_for(max_tcp_sessions, low_memory);
    let control_recv_size = control_ring_size(tcp_recv_buffer_size);
    let control_send_size = control_ring_size(tcp_send_buffer_size);
    let clock = MonotonicClock::new();
    let mut device = VirtualDevice::new(mtu, tx_queue_high_water, low_memory);
    let mut iface = create_interface(&mut device, clock.now())?;
    let (stream_tx, stream_rx) = mpsc::channel(max_tcp_sessions.clamp(16, 256));
    let notify = Arc::new(Notify::new());
    let reactor_notified = Arc::new(AtomicBool::new(false));

    let handle = tokio::spawn(async move {
        let mut socket_set = SocketSet::new(Vec::new());
        let mut sockets: HashMap<SocketHandle, SocketEntry> = HashMap::new();
        let mut active_endpoints: HashSet<(SocketAddr, SocketAddr)> = HashSet::new();
        let mut listening_dsts: HashSet<SocketAddr> = HashSet::new();
        let mut sockets_to_remove: Vec<SocketHandle> = Vec::new();
        let mut deferred_syns: VecDeque<(StdInstant, SocketAddr, Vec<u8>)> = VecDeque::new();
        let mut rx_batch: Vec<Vec<u8>> = Vec::with_capacity(INGRESS_DRAIN_LIMIT);
        let mut buffer_pool = SocketBufferPool::new(
            tcp_recv_buffer_size,
            tcp_send_buffer_size,
            control_recv_size,
            control_send_size,
            low_memory,
        );
        let mut active_count: usize = 0;
        let mut socket_set_peak_slots: usize = 0;
        let mut idle_since: Option<StdInstant> = None;
        let mut burst_iters: usize = 0;
        let mut zero_delay_spins: u32 = 0;

        // Single reusable Tokio timer to avoid registering/cancelling a timer-wheel entry
        // tens of thousands of times per second during Gigabit packet bursts.
        let timer = tokio::time::sleep(StdDuration::from_secs(3600));
        tokio::pin!(timer);
        let mut timer_deadline: Option<tokio::time::Instant> = None;

        let enqueue_inbound = |frame: Vec<u8>,
                               wall_now: StdInstant,
                               device: &mut VirtualDevice,
                               socket_set: &mut SocketSet<'static>,
                               sockets: &mut HashMap<SocketHandle, SocketEntry>,
                               active_endpoints: &mut HashSet<(SocketAddr, SocketAddr)>,
                               listening_dsts: &mut HashSet<SocketAddr>,
                               active_count: &mut usize,
                               socket_set_peak_slots: &mut usize,
                               buffer_pool: &mut SocketBufferPool,
                               stream_tx: &mpsc::Sender<TunNetstackTcpStream>,
                               notify: &Arc<Notify>,
                               reactor_notified: &Arc<AtomicBool>|
         -> EnqueueOutcome {
            match classify_inbound_tcp(&frame) {
                InboundTcpKind::Invalid => EnqueueOutcome::Dropped,
                InboundTcpKind::NonSyn => {
                    let Some(frame) = normalize_inbound_ipv6_tcp(frame) else {
                        return EnqueueOutcome::Dropped;
                    };
                    device.rx_queue.push_back(frame);
                    EnqueueOutcome::Enqueued
                }
                InboundTcpKind::InitialSyn(src_addr, dst_addr) => {
                    let Some(frame) = normalize_inbound_ipv6_tcp(frame) else {
                        return EnqueueOutcome::Dropped;
                    };
                    if !active_endpoints.contains(&(src_addr, dst_addr)) {
                        // Prevent smoltcp SocketSet slot-reuse cross-wiring when multiple parallel
                        // SYNs target the same dst_addr in one ingress batch: defer the second SYN
                        // into `deferred_syns` WITHOUT halting `tcp_in_rx` for other flows/ACKs.
                        if listening_dsts.contains(&dst_addr) {
                            return EnqueueOutcome::Deferred(dst_addr, frame);
                        }

                        // Count only active non-closing sockets (`Listen`, `SynReceived`, `Established`)
                        // against `max_tcp_sessions` so `TimeWait` and closing sockets cannot starve new
                        // connections, while still enforcing a hard handle cap (`max_tcp_sessions + 32`
                        // on `low_memory`, `max_tcp_sessions + 64` otherwise) via immediate reclaim of
                        // `TimeWait`/closing handles.
                        if sockets.len() >= hard_handle_cap {
                            let _ = evict_reclaimable_socket(
                                socket_set,
                                sockets,
                                active_endpoints,
                                active_count,
                                buffer_pool,
                            );
                        }
                        if *active_count >= max_tcp_sessions || sockets.len() >= hard_handle_cap {
                            debug!(
                                %src_addr,
                                %dst_addr,
                                active = *active_count,
                                total = sockets.len(),
                                limit = max_tcp_sessions,
                                "TCP session limit reached; sending RST+ACK"
                            );
                            if let Some(rst) = build_tcp_rst_ack_reply(&frame) {
                                device.tx_queue.push_back(rst);
                            }
                            return EnqueueOutcome::Dropped;
                        }

                        let Ok(permit) = stream_tx.try_reserve() else {
                            debug!(%src_addr, %dst_addr, "accepted TCP queue full; sending RST+ACK");
                            if let Some(rst) = build_tcp_rst_ack_reply(&frame) {
                                device.tx_queue.push_back(rst);
                            }
                            return EnqueueOutcome::Dropped;
                        };

                        let mut socket = buffer_pool.checkout_socket();
                        configure_local_tun_socket(&mut socket);

                        if let Err(err) = socket.listen(dst_addr) {
                            debug!(%src_addr, %dst_addr, error = ?err, "smoltcp listen failed");
                            buffer_pool.return_socket(socket);
                            return EnqueueOutcome::Dropped;
                        }

                        let (recv_buffer, send_buffer) = buffer_pool.checkout_control_buffers();
                        let shared = Arc::new(SocketShared::new(TcpSocketControl {
                            send_buffer,
                            send_waker: None,
                            recv_buffer,
                            recv_waker: None,
                            recv_state: HalfState::Normal,
                            send_state: HalfState::Normal,
                            rx_backpressured: false,
                        }));

                        let stream = TunNetstackTcpStream {
                            src_addr,
                            dst_addr,
                            notify: Arc::clone(notify),
                            reactor_notified: Arc::clone(reactor_notified),
                            shared: Arc::clone(&shared),
                        };
                        permit.send(stream);

                        let handle = socket_set.add(socket);
                        active_endpoints.insert((src_addr, dst_addr));
                        listening_dsts.insert(dst_addr);
                        *active_count += 1;
                        sockets.insert(
                            handle,
                            SocketEntry {
                                shared,
                                endpoints: (src_addr, dst_addr),
                                created_at: wall_now,
                                saw_non_listen: false,
                                fin_wait_2_shortened: false,
                                is_active: true,
                                closing_since: None,
                                time_wait_since: None,
                                tx_has_pending: false,
                                rx_backpressured: false,
                                recv_open: true,
                                recv_closing: false,
                                send_closing: false,
                                app_closed_both: false,
                            },
                        );
                        *socket_set_peak_slots = (*socket_set_peak_slots).max(sockets.len());
                        trace!(%src_addr, %dst_addr, "created TUN TCP socket");
                    }

                    device.rx_queue.push_back(frame);
                    EnqueueOutcome::Enqueued
                }
            }
        };

        'runner: loop {
            if *shutdown_rx.borrow() {
                break;
            }

            // 1. Re-try deferred same-destination SYNs first (dropping stale >2s entries),
            //    then batch-drain up to `INGRESS_DRAIN_LIMIT` ready inbound IP packets into
            //    `VirtualDevice` BEFORE calling `iface.poll()` ONCE.
            let wall_now = StdInstant::now();
            let mut ingress_drained = 0usize;
            let mut enqueued_any = false;

            let deferred_count = deferred_syns.len();
            for _ in 0..deferred_count {
                let Some((ts, dst_addr, frame)) = deferred_syns.pop_front() else {
                    break;
                };
                if wall_now.saturating_duration_since(ts) >= DEFERRED_SYN_TTL {
                    continue;
                }
                if listening_dsts.contains(&dst_addr) {
                    deferred_syns.push_back((ts, dst_addr, frame));
                    continue;
                }
                if ingress_drained >= INGRESS_DRAIN_LIMIT {
                    deferred_syns.push_front((ts, dst_addr, frame));
                    break;
                }
                match enqueue_inbound(
                    frame,
                    wall_now,
                    &mut device,
                    &mut socket_set,
                    &mut sockets,
                    &mut active_endpoints,
                    &mut listening_dsts,
                    &mut active_count,
                    &mut socket_set_peak_slots,
                    &mut buffer_pool,
                    &stream_tx,
                    &notify,
                    &reactor_notified,
                ) {
                    EnqueueOutcome::Enqueued => {
                        ingress_drained += 1;
                        enqueued_any = true;
                    }
                    EnqueueOutcome::Dropped => {
                        ingress_drained += 1;
                    }
                    EnqueueOutcome::Deferred(dst_addr, frame) => {
                        deferred_syns.push_back((ts, dst_addr, frame));
                    }
                }
            }

            // Drain any packets already collected by `recv_many` when waking from park.
            for frame in rx_batch.drain(..) {
                match enqueue_inbound(
                    frame,
                    wall_now,
                    &mut device,
                    &mut socket_set,
                    &mut sockets,
                    &mut active_endpoints,
                    &mut listening_dsts,
                    &mut active_count,
                    &mut socket_set_peak_slots,
                    &mut buffer_pool,
                    &stream_tx,
                    &notify,
                    &reactor_notified,
                ) {
                    EnqueueOutcome::Enqueued => {
                        ingress_drained += 1;
                        enqueued_any = true;
                    }
                    EnqueueOutcome::Dropped => {
                        ingress_drained += 1;
                    }
                    EnqueueOutcome::Deferred(dst_addr, frame) => {
                        if deferred_syns.len() < MAX_DEFERRED_SYNS {
                            deferred_syns.push_back((wall_now, dst_addr, frame));
                        }
                        ingress_drained += 1;
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
                    wall_now,
                    &mut device,
                    &mut socket_set,
                    &mut sockets,
                    &mut active_endpoints,
                    &mut listening_dsts,
                    &mut active_count,
                    &mut socket_set_peak_slots,
                    &mut buffer_pool,
                    &stream_tx,
                    &notify,
                    &reactor_notified,
                ) {
                    EnqueueOutcome::Enqueued => {
                        ingress_drained += 1;
                        enqueued_any = true;
                    }
                    EnqueueOutcome::Dropped => {
                        ingress_drained += 1;
                    }
                    EnqueueOutcome::Deferred(dst_addr, frame) => {
                        if deferred_syns.len() < MAX_DEFERRED_SYNS {
                            deferred_syns.push_back((wall_now, dst_addr, frame));
                        }
                        ingress_drained += 1;
                    }
                }
            }
            let ingress_hit_limit = ingress_drained >= INGRESS_DRAIN_LIMIT;

            // Clear the coalesced notification latch BEFORE scanning per-socket dirty flags
            // in Steps 2 and 4 so any concurrent `poll_write`/`poll_read` either becomes visible
            // during this pass or observes `false` and issues a fresh `notify_one()`.
            reactor_notified.store(false, Ordering::SeqCst);

            // 2. Drain application TX buffers into smoltcp BEFORE polling so segments emit immediately.
            //    Skip idle sockets with zero mutex locks via per-socket `tx_dirty` atomic.
            let mut pre_poll_tx = false;
            for (&handle, entry) in &mut sockets {
                let tx_dirty = entry.shared.take_tx_dirty();
                let socket = socket_set.get_mut::<TcpSocket>(handle);
                if !(tx_dirty || (entry.tx_has_pending && socket.can_send())) {
                    continue;
                }

                let mut control = entry.shared.lock_control();

                // If the application dropped the stream before the handshake completed,
                // abort immediately so it does not stall in Listen/SynReceived/FinWait1.
                if matches!(control.recv_state, HalfState::Close)
                    && matches!(control.send_state, HalfState::Close)
                    && matches!(socket.state(), TcpState::Listen | TcpState::SynReceived)
                {
                    socket.abort();
                    control.send_state = HalfState::Closed;
                    control.recv_state = HalfState::Closed;
                    entry.tx_has_pending = false;
                    entry.recv_open = false;
                    entry.recv_closing = false;
                    entry.send_closing = false;
                    entry.app_closed_both = true;
                    pre_poll_tx = true;
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
                            pre_poll_tx = true;
                        }
                        Ok(_) => break,
                        Err(err) => {
                            debug!(error = ?err, state = ?socket.state(), "smoltcp pre-poll send error");
                            socket.abort();
                            if matches!(control.send_state, HalfState::Normal) {
                                control.send_state = HalfState::Closed;
                            }
                            wake_sender = true;
                            pre_poll_tx = true;
                            break;
                        }
                    }
                }

                if matches!(control.send_state, HalfState::Close) && control.send_buffer.is_empty()
                {
                    socket.close();
                    control.send_state = HalfState::Closing;
                    pre_poll_tx = true;
                }

                entry.tx_has_pending = !control.send_buffer.is_empty()
                    || matches!(control.send_state, HalfState::Close);
                entry.recv_open = matches!(control.recv_state, HalfState::Normal);
                entry.recv_closing = matches!(control.recv_state, HalfState::Close);
                entry.send_closing = matches!(control.send_state, HalfState::Closing);
                entry.app_closed_both =
                    matches!(control.recv_state, HalfState::Close | HalfState::Closed)
                        && matches!(
                            control.send_state,
                            HalfState::Close | HalfState::Closing | HalfState::Closed
                        );

                let send_waker = if wake_sender {
                    control.send_waker.take()
                } else {
                    None
                };
                drop(control);
                if let Some(waker) = send_waker {
                    waker.wake();
                }
            }

            // 3. Drive smoltcp state machine ONCE for the entire drained ingress/TX batch.
            let now = clock.smol_from(wall_now);
            device.tx_throttled = false;
            let poll_changed = matches!(
                iface.poll(now, &mut device, &mut socket_set),
                PollResult::SocketStateChanged
            );
            device.recycle_consumed_rx();

            // 4. Drain smoltcp RX buffers into application buffers, refill TX if freed, reap closed.
            //    Idle sockets bypass mutex locking completely.
            let mut post_poll_mutated = false;
            let mut rx_drained = false;
            let mut earliest_reap_delay: Option<StdDuration> = None;
            sockets_to_remove.clear();
            listening_dsts.clear();

            for (&handle, entry) in &mut sockets {
                let socket = socket_set.get_mut::<TcpSocket>(handle);
                let state = socket.state();

                if state == TcpState::Closed {
                    sockets_to_remove.push(handle);
                    let (send_waker, recv_waker) = {
                        let mut control = entry.shared.lock_control();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        (control.send_waker.take(), control.recv_waker.take())
                    };
                    if let Some(waker) = send_waker {
                        waker.wake();
                    }
                    if let Some(waker) = recv_waker {
                        waker.wake();
                    }
                    continue;
                }

                let rx_dirty = entry.shared.take_rx_dirty();
                let tx_dirty = entry.shared.take_tx_dirty();
                if rx_dirty {
                    entry.rx_backpressured = false;
                }

                // Track whether this socket has ever left `Listen`. In smoltcp 0.14, receiving a
                // TCP RST in `SynReceived` clears `tuple` and reverts the socket BACK to `Listen`
                // instead of `Closed` (disabling its idle timer and poisoning `listening_dsts`).
                // Abort and immediately reap any reverted `Listen` socket on this tick.
                if state != TcpState::Listen {
                    entry.saw_non_listen = true;
                } else if entry.saw_non_listen
                    || wall_now.saturating_duration_since(entry.created_at) >= LISTEN_ORPHAN_TIMEOUT
                {
                    socket.abort();
                    sockets_to_remove.push(handle);
                    let (send_waker, recv_waker) = {
                        let mut control = entry.shared.lock_control();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        (control.send_waker.take(), control.recv_waker.take())
                    };
                    if let Some(waker) = send_waker {
                        waker.wake();
                    }
                    if let Some(waker) = recv_waker {
                        waker.wake();
                    }
                    continue;
                }

                // Rapidly reclaim TIME_WAIT sockets after 250ms (local zero-reorder TUN) once
                // drained, removing directly from `socket_set` without calling `socket.abort()`
                // so smoltcp never emits an unsolicited RST for gracefully closed connections.
                if state == TcpState::TimeWait {
                    let since = *entry.time_wait_since.get_or_insert(wall_now);
                    let elapsed = wall_now.saturating_duration_since(since);
                    if elapsed >= TIME_WAIT_REAP_TIMEOUT
                        && (!socket.can_recv() || entry.recv_closing)
                    {
                        sockets_to_remove.push(handle);
                        let (send_waker, recv_waker) = {
                            let mut control = entry.shared.lock_control();
                            control.send_state = HalfState::Closed;
                            control.recv_state = HalfState::Closed;
                            (control.send_waker.take(), control.recv_waker.take())
                        };
                        if let Some(waker) = send_waker {
                            waker.wake();
                        }
                        if let Some(waker) = recv_waker {
                            waker.wake();
                        }
                        continue;
                    }
                    if elapsed < TIME_WAIT_REAP_TIMEOUT {
                        let rem = TIME_WAIT_REAP_TIMEOUT - elapsed;
                        earliest_reap_delay =
                            Some(earliest_reap_delay.map_or(rem, |d| d.min(rem)));
                    }
                } else {
                    entry.time_wait_since = None;
                }

                // Prevent infinite FIN_WAIT_2 permit leaks: disable keep-alive probes that
                // would keep resetting smoltcp's idle timer and bound FIN_WAIT_2 to 15s.
                if state == TcpState::FinWait2 && !entry.fin_wait_2_shortened {
                    socket.set_keep_alive(None);
                    socket.set_timeout(Some(FIN_WAIT_2_TIMEOUT));
                    entry.fin_wait_2_shortened = true;
                }

                // Fast path for discarded-reader sockets without locking control mutex.
                if entry.recv_closing && !rx_dirty && !tx_dirty {
                    while socket.can_recv() {
                        match socket.recv(|buf| (buf.len(), buf.len())) {
                            Ok(n) if n > 0 => {
                                rx_drained = true;
                            }
                            Ok(_) => break,
                            Err(_) => {
                                socket.abort();
                                post_poll_mutated = true;
                                break;
                            }
                        }
                    }
                }

                let need_rx_drain = socket.can_recv()
                    && (!entry.rx_backpressured || rx_dirty || entry.recv_closing);
                let need_recv_eof =
                    entry.recv_open && !socket.may_recv() && !is_recv_open_state(state);
                let need_tx_refill = tx_dirty || (entry.tx_has_pending && socket.can_send());
                let need_send_close_done = entry.send_closing
                    && matches!(
                        state,
                        TcpState::FinWait2 | TcpState::TimeWait | TcpState::Closed
                    );
                let need_lock = rx_dirty
                    || tx_dirty
                    || need_rx_drain
                    || need_recv_eof
                    || need_tx_refill
                    || need_send_close_done;

                if need_lock {
                    let mut control = entry.shared.lock_control();

                    // Catch streams dropped mid-tick while still in Listen/SynReceived so they
                    // abort immediately and reap on the very next tick.
                    if matches!(control.recv_state, HalfState::Close)
                        && matches!(control.send_state, HalfState::Close | HalfState::Closing)
                        && matches!(state, TcpState::Listen | TcpState::SynReceived)
                    {
                        socket.abort();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        let send_waker = control.send_waker.take();
                        let recv_waker = control.recv_waker.take();
                        drop(control);
                        if let Some(waker) = send_waker {
                            waker.wake();
                        }
                        if let Some(waker) = recv_waker {
                            waker.wake();
                        }
                        if state == TcpState::Listen {
                            sockets_to_remove.push(handle);
                        } else {
                            sync_active_flag(entry, &mut active_count, false);
                            post_poll_mutated = true;
                        }
                        continue;
                    }

                    let mut wake_receiver = false;
                    if matches!(control.recv_state, HalfState::Close) {
                        // Reader dropped; discard unread bytes so peer FIN can complete cleanly.
                        while socket.can_recv() {
                            match socket.recv(|buf| (buf.len(), buf.len())) {
                                Ok(n) if n > 0 => {
                                    rx_drained = true;
                                }
                                Ok(_) => break,
                                Err(_) => {
                                    socket.abort();
                                    post_poll_mutated = true;
                                    break;
                                }
                            }
                        }
                        control.rx_backpressured = false;
                    } else {
                        while socket.can_recv() && !control.recv_buffer.is_full() {
                            match socket.recv(|buf| {
                                let n = control.recv_buffer.enqueue_slice(buf);
                                (n, n)
                            }) {
                                Ok(n) if n > 0 => {
                                    wake_receiver = true;
                                    rx_drained = true;
                                }
                                Ok(_) => break,
                                Err(err) => {
                                    debug!(error = ?err, state = ?socket.state(), "smoltcp recv error");
                                    socket.abort();
                                    post_poll_mutated = true;
                                    if matches!(control.recv_state, HalfState::Normal) {
                                        control.recv_state = HalfState::Closed;
                                    }
                                    wake_receiver = true;
                                    break;
                                }
                            }
                        }
                        control.rx_backpressured =
                            socket.can_recv() && control.recv_buffer.is_full();
                    }

                    if matches!(control.recv_state, HalfState::Normal)
                        && !socket.may_recv()
                        && !is_recv_open_state(socket.state())
                    {
                        control.recv_state = HalfState::Closed;
                        wake_receiver = true;
                    }

                    let recv_waker = if wake_receiver {
                        control.recv_waker.take()
                    } else {
                        None
                    };

                    // Refill TX immediately if ACK freed window space during poll().
                    let mut wake_sender = false;
                    while socket.can_send() && !control.send_buffer.is_empty() {
                        match socket.send(|buf| {
                            let n = control.send_buffer.dequeue_slice(buf);
                            (n, n)
                        }) {
                            Ok(n) if n > 0 => {
                                wake_sender = true;
                                post_poll_mutated = true;
                            }
                            Ok(_) => break,
                            Err(err) => {
                                debug!(error = ?err, state = ?socket.state(), "smoltcp post-poll send error");
                                socket.abort();
                                post_poll_mutated = true;
                                if matches!(control.send_state, HalfState::Normal) {
                                    control.send_state = HalfState::Closed;
                                }
                                wake_sender = true;
                                break;
                            }
                        }
                    }

                    if matches!(control.send_state, HalfState::Close)
                        && control.send_buffer.is_empty()
                    {
                        socket.close();
                        control.send_state = HalfState::Closing;
                        post_poll_mutated = true;
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

                    entry.tx_has_pending = !control.send_buffer.is_empty()
                        || matches!(control.send_state, HalfState::Close);
                    entry.rx_backpressured = control.rx_backpressured;
                    entry.recv_open = matches!(control.recv_state, HalfState::Normal);
                    entry.recv_closing = matches!(control.recv_state, HalfState::Close);
                    entry.send_closing = matches!(control.send_state, HalfState::Closing);
                    entry.app_closed_both =
                        matches!(control.recv_state, HalfState::Close | HalfState::Closed)
                            && matches!(
                                control.send_state,
                                HalfState::Close | HalfState::Closing | HalfState::Closed
                            );

                    let send_waker = if wake_sender {
                        control.send_waker.take()
                    } else {
                        None
                    };
                    drop(control);

                    if let Some(waker) = recv_waker {
                        waker.wake();
                    }
                    if let Some(waker) = send_waker {
                        waker.wake();
                    }
                }

                // Bound half-closed / peer-dropped closing states to 5s (disabling keep-alive
                // probes that would otherwise keep resetting smoltcp's idle timer).
                let current_state = socket.state();
                if current_state == TcpState::TimeWait
                    && (!socket.can_recv() || entry.recv_closing)
                    && entry.time_wait_since.is_some_and(|since| {
                        wall_now.saturating_duration_since(since) >= TIME_WAIT_REAP_TIMEOUT
                    })
                {
                    sockets_to_remove.push(handle);
                    let (send_waker, recv_waker) = {
                        let mut control = entry.shared.lock_control();
                        control.send_state = HalfState::Closed;
                        control.recv_state = HalfState::Closed;
                        (control.send_waker.take(), control.recv_waker.take())
                    };
                    if let Some(waker) = send_waker {
                        waker.wake();
                    }
                    if let Some(waker) = recv_waker {
                        waker.wake();
                    }
                    continue;
                }

                if entry.app_closed_both
                    && matches!(
                        current_state,
                        TcpState::FinWait1
                            | TcpState::FinWait2
                            | TcpState::Closing
                            | TcpState::LastAck
                            | TcpState::CloseWait
                    )
                {
                    if entry.closing_since.is_none() {
                        socket.set_keep_alive(None);
                        socket.set_timeout(Some(SmolDuration::from_secs(5)));
                    }
                    let since = *entry.closing_since.get_or_insert(wall_now);
                    let elapsed = wall_now.saturating_duration_since(since);
                    if elapsed >= CLOSING_REAP_TIMEOUT {
                        socket.abort();
                        sync_active_flag(entry, &mut active_count, false);
                        let (send_waker, recv_waker) = {
                            let mut control = entry.shared.lock_control();
                            control.send_state = HalfState::Closed;
                            control.recv_state = HalfState::Closed;
                            (control.send_waker.take(), control.recv_waker.take())
                        };
                        if let Some(waker) = send_waker {
                            waker.wake();
                        }
                        if let Some(waker) = recv_waker {
                            waker.wake();
                        }
                        post_poll_mutated = true;
                        continue;
                    }
                    let rem = CLOSING_REAP_TIMEOUT - elapsed;
                    earliest_reap_delay = Some(earliest_reap_delay.map_or(rem, |d| d.min(rem)));
                }

                sync_active_flag(entry, &mut active_count, is_active_tcp_state(current_state));
                if current_state == TcpState::Listen {
                    listening_dsts.insert(entry.endpoints.1);
                }
            }

            for handle in sockets_to_remove.drain(..) {
                if let Some(entry) = sockets.remove(&handle) {
                    active_endpoints.remove(&entry.endpoints);
                    if entry.is_active {
                        active_count = active_count.saturating_sub(1);
                    }
                    buffer_pool.reclaim_shared_buffers(entry.shared);
                }
                let SmolSocket::Tcp(socket) = socket_set.remove(handle);
                buffer_pool.return_socket(socket);
            }

            debug_assert_eq!(
                active_count,
                sockets
                    .keys()
                    .filter(|&&h| is_active_tcp_state(socket_set.get::<TcpSocket>(h).state()))
                    .count()
            );

            if sockets.is_empty() {
                if socket_set_peak_slots > SOCKET_SET_SHRINK_THRESHOLD {
                    socket_set = SocketSet::new(Vec::new());
                    socket_set_peak_slots = 0;
                }
                if !buffer_pool.is_empty() {
                    let since = *idle_since.get_or_insert(wall_now);
                    let elapsed = wall_now.saturating_duration_since(since);
                    if elapsed >= POOL_IDLE_SHRINK_TIMEOUT {
                        buffer_pool.shrink_idle();
                        idle_since = None;
                    } else {
                        let rem = POOL_IDLE_SHRINK_TIMEOUT - elapsed;
                        earliest_reap_delay =
                            Some(earliest_reap_delay.map_or(rem, |d| d.min(rem)));
                    }
                } else {
                    idle_since = None;
                }
            } else {
                idle_since = None;
            }

            // 5. Flush ALL emitted outbound packets in one pass onto outbound_tx (zero silent drops).
            let tx_emitted = !device.tx_queue.is_empty();
            while let Some(pkt) = device.tx_queue.pop_front() {
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

            // 6. Decide whether genuine follow-up work remains vs parking cleanly with ZERO busy-spin.
            let post_now = clock.now();
            let next_delay = iface.poll_delay(post_now, &socket_set);
            let deferred_ready = !deferred_syns.is_empty()
                && deferred_syns
                    .iter()
                    .any(|(_, dst_addr, _)| !listening_dsts.contains(dst_addr));
            let has_pending_work = ingress_hit_limit
                || !device.rx_queue.is_empty()
                || device.tx_throttled
                || post_poll_mutated
                || deferred_ready;
            let did_smoltcp_progress = enqueued_any
                || pre_poll_tx
                || poll_changed
                || tx_emitted
                || post_poll_mutated
                || rx_drained;

            let immediate_poll = if has_pending_work {
                zero_delay_spins = 0;
                true
            } else if next_delay == Some(SmolDuration::ZERO) {
                if did_smoltcp_progress {
                    zero_delay_spins = 0;
                    true
                } else if zero_delay_spins == 0 {
                    // Allow one immediate retry (e.g. RX drain triggered `window_to_update()`).
                    zero_delay_spins = 1;
                    true
                } else {
                    // Zero-progress `PollAt::Now` guard: never busy-spin a CPU core.
                    zero_delay_spins = zero_delay_spins.saturating_add(1);
                    false
                }
            } else {
                zero_delay_spins = 0;
                false
            };

            if immediate_poll {
                burst_iters += 1;
                if burst_iters >= POLL_BURST_LIMIT {
                    burst_iters = 0;
                    tokio::task::yield_now().await;
                }
                continue;
            }

            burst_iters = 0;

            let mut effective_delay = next_delay.map(StdDuration::from);
            if matches!(effective_delay, Some(d) if d.is_zero()) {
                // Bounded non-zero backoff when `poll_delay` stays at ZERO without progress,
                // while `tcp_in_rx` and `notify` still wake immediately at 0us latency.
                let backoff_ms = (ZERO_DELAY_BACKOFF_MIN_MS
                    << (zero_delay_spins.saturating_sub(1).min(3)))
                .min(ZERO_DELAY_BACKOFF_MAX_MS);
                effective_delay = Some(StdDuration::from_millis(backoff_ms));
            }
            if !deferred_syns.is_empty() {
                let cap = StdDuration::from_millis(50);
                effective_delay = Some(effective_delay.map_or(cap, |d| d.min(cap)));
            }
            if let Some(reap_delay) = earliest_reap_delay {
                let reap_delay = reap_delay.max(REAP_DELAY_FLOOR);
                effective_delay = Some(effective_delay.map_or(reap_delay, |d| d.min(reap_delay)));
            }

            // 7. Park cleanly until batched inbound packets, stream wake, smoltcp timer, or shutdown.
            match effective_delay {
                Some(delay) => {
                    let now_tokio = tokio::time::Instant::now();
                    let desired = now_tokio + delay;
                    if should_reset_timer(timer.is_elapsed(), timer_deadline, now_tokio, desired) {
                        timer.as_mut().reset(desired);
                        timer_deadline = Some(desired);
                    }
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => break 'runner,
                        n = tcp_in_rx.recv_many(&mut rx_batch, INGRESS_DRAIN_LIMIT) => {
                            if n == 0 {
                                break 'runner;
                            }
                        }
                        _ = notify.notified() => {}
                        _ = &mut timer => {
                            timer_deadline = None;
                        }
                    }
                }
                None => {
                    timer_deadline = None;
                    tokio::select! {
                        biased;
                        _ = wait_shutdown(&mut shutdown_rx) => break 'runner,
                        n = tcp_in_rx.recv_many(&mut rx_batch, INGRESS_DRAIN_LIMIT) => {
                            if n == 0 {
                                break 'runner;
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
        assert_eq!(control_ring_size(448 * 1024), 64 * 1024);
        assert_eq!(control_ring_size(512 * 1024), 64 * 1024);
        assert_eq!(control_ring_size(1024 * 1024), 256 * 1024);
    }

    #[test]
    fn local_tun_socket_disables_ack_delay_nagle_and_congestion_control() {
        let mut sock = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; 1024 * 1024]),
            TcpSocketBuffer::new(vec![0u8; 1024 * 1024]),
        );
        configure_local_tun_socket(&mut sock);
        assert_eq!(sock.ack_delay(), None);
        assert!(!sock.nagle_enabled());
        assert_eq!(sock.congestion_control(), CongestionControl::None);
        assert_eq!(sock.recv_capacity(), 1024 * 1024);
        assert_eq!(sock.send_capacity(), 1024 * 1024);
    }

    #[test]
    fn tx_buffer_pool_recycles_small_and_large_buffers_with_zeroed_headers() {
        let mut pool = TxBufferPool::new(16_384, 8, 8);
        let mut incoming = vec![
            vec![0x11u8; 64],
            vec![0x22u8; 4096],
            vec![0xFFu8; SMALL_TX_POOL_MAX_BYTES],
            vec![0xAAu8; 16_384],
        ];
        let small_ptr = incoming[2].as_ptr();
        let large_ptr = incoming[3].as_ptr();

        pool.recycle_all(&mut incoming);
        assert!(incoming.is_empty());
        assert_eq!(pool.small.len(), 1);
        assert_eq!(pool.large.len(), 1);

        let small_out = pool.checkout(40);
        assert_eq!(small_out.len(), 40);
        assert!(small_out.capacity() >= SMALL_TX_POOL_MAX_BYTES);
        assert_eq!(small_out.as_ptr(), small_ptr);
        assert!(small_out.iter().all(|&b| b == 0));

        let large_out = pool.checkout(1500);
        assert_eq!(large_out.len(), 1500);
        assert!(large_out.capacity() >= 16_384);
        assert_eq!(large_out.as_ptr(), large_ptr);
        assert!(large_out[..TX_HEADER_ZERO_LEN].iter().all(|&b| b == 0));

        let miss_small = pool.checkout(52);
        assert_eq!(miss_small.len(), 52);
        assert!(miss_small.capacity() >= SMALL_TX_POOL_MAX_BYTES);

        let miss_large = pool.checkout(1500);
        assert_eq!(miss_large.len(), 1500);
        assert!(miss_large.capacity() >= 16_384);
    }

    #[tokio::test]
    async fn one_mib_buffers_negotiate_rfc7323_window_scale_shift_5_and_transfer_cleanly() {
        const MTU: usize = 16_384;
        const BUF_1MIB: usize = 1024 * 1024;
        const PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(2048);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(2048);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF_1MIB, BUF_1MIB, 32, 512, stop_rx).unwrap();

        let clock = MonotonicClock::new();
        let mut client_dev = VirtualDevice::new(MTU, 512, false);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x1122_3344_5566_7788;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, clock.now());
        client_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(198, 18, 0, 1), 30));
        });
        client_iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(198, 18, 0, 2))
            .unwrap();

        let mut client_sockets = SocketSet::new(Vec::new());
        let mut client_sock = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; BUF_1MIB]),
            TcpSocketBuffer::new(vec![0u8; BUF_1MIB]),
        );
        configure_local_tun_socket(&mut client_sock);
        client_sock
            .connect(
                client_iface.context(),
                (Ipv4Address::new(1, 1, 1, 1), 443),
                49_100,
            )
            .unwrap();
        let client_handle = client_sockets.add(client_sock);

        client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
        let syn_pkt = client_dev.tx_queue.pop_front().expect("SYN emitted");
        in_tx.send(syn_pkt).await.unwrap();

        let mut server_stream =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream_rx.recv())
                .await
                .expect("accept timeout")
                .expect("accepted stream");

        // Inspect SYN-ACK emitted by netstack to verify RFC 7323 Window Scale shift == 5 for 1 MiB.
        let syn_ack = tokio::time::timeout(std::time::Duration::from_secs(3), out_rx.recv())
            .await
            .expect("syn-ack timeout")
            .expect("syn-ack pkt");
        let ip = Ipv4Packet::new_checked(&syn_ack).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let tcp_repr = smoltcp::wire::TcpRepr::parse(
            &tcp,
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
            &ChecksumCapabilities::ignored(),
        )
        .unwrap();
        assert!(tcp.syn() && tcp.ack());
        assert_eq!(
            tcp_repr.window_scale,
            Some(5),
            "1 MiB RX buffer must negotiate RFC 7323 window_scale shift = 5"
        );
        client_dev.rx_queue.push_back(syn_ack);

        let server_task = tokio::spawn(async move {
            let chunk = vec![0x3Cu8; 128 * 1024];
            let mut remaining = PAYLOAD_BYTES;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                server_stream.write_all(&chunk[..n]).await.unwrap();
                remaining -= n;
            }
            server_stream.shutdown().await.unwrap();
        });

        let mut received = 0usize;
        let deadline = StdInstant::now() + StdDuration::from_secs(10);
        loop {
            assert!(
                StdInstant::now() < deadline,
                "1 MiB window-scaled transfer timed out at {received}/{PAYLOAD_BYTES}"
            );
            while let Ok(pkt) = out_rx.try_recv() {
                client_dev.rx_queue.push_back(pkt);
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            {
                let sock = client_sockets.get_mut::<TcpSocket>(client_handle);
                while sock.can_recv() {
                    received += sock
                        .recv(|buf| {
                            assert!(buf.iter().all(|&b| b == 0x3C));
                            (buf.len(), buf.len())
                        })
                        .unwrap();
                }
                if received == PAYLOAD_BYTES && !sock.may_recv() {
                    sock.close();
                }
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            while let Some(pkt) = client_dev.tx_queue.pop_front() {
                in_tx.send(pkt).await.unwrap();
            }
            if received == PAYLOAD_BYTES
                && client_sockets.get::<TcpSocket>(client_handle).state() == TcpState::Closed
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        server_task.await.unwrap();
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), runner_handle).await;
    }

    #[tokio::test]
    async fn backpressured_rx_ring_resumes_cleanly_without_stalls() {
        // Exercises RX backpressure (`control.recv_buffer` = 16 KiB < smoltcp 32 KiB < 256 KiB payload)
        // to prove `rx_backpressured` + `rx_dirty` wakes cleanly with zero stalls on LOW_MEMORY sizes.
        const MTU: usize = 1500;
        const BUF: usize = 32 * 1024;
        const PAYLOAD_BYTES: usize = 256 * 1024;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(256);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, 16, 128, stop_rx).unwrap();

        let clock = MonotonicClock::new();
        let mut client_dev = VirtualDevice::new(MTU, 128, true);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0xaaaa_bbbb_cccc_dddd;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, clock.now());
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
        configure_local_tun_socket(&mut client_sock);
        client_sock
            .connect(
                client_iface.context(),
                (Ipv4Address::new(1, 1, 1, 1), 443),
                49_200,
            )
            .unwrap();
        let client_handle = client_sockets.add(client_sock);

        client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
        in_tx
            .send(client_dev.tx_queue.pop_front().unwrap())
            .await
            .unwrap();

        let mut server_stream = tokio::time::timeout(StdDuration::from_secs(3), stream_rx.recv())
            .await
            .expect("accept timeout")
            .expect("accepted stream");

        let server_task = tokio::spawn(async move {
            let mut total = 0usize;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = server_stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                assert!(buf[..n].iter().all(|&b| b == 0x7E));
                total += n;
            }
            assert_eq!(total, PAYLOAD_BYTES);
            server_stream.shutdown().await.unwrap();
        });

        let chunk = vec![0x7Eu8; 8192];
        let mut sent = 0usize;
        let mut closed_send = false;
        let deadline = StdInstant::now() + StdDuration::from_secs(10);
        loop {
            assert!(
                StdInstant::now() < deadline,
                "RX backpressure transfer timed out at sent={sent}/{PAYLOAD_BYTES}"
            );
            while let Ok(pkt) = out_rx.try_recv() {
                client_dev.rx_queue.push_back(pkt);
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            {
                let sock = client_sockets.get_mut::<TcpSocket>(client_handle);
                while sent < PAYLOAD_BYTES && sock.can_send() {
                    let rem = (PAYLOAD_BYTES - sent).min(chunk.len());
                    let n = sock.send_slice(&chunk[..rem]).unwrap();
                    if n == 0 {
                        break;
                    }
                    sent += n;
                }
                if sent == PAYLOAD_BYTES && !closed_send && sock.can_send() {
                    sock.close();
                    closed_send = true;
                }
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            while let Some(pkt) = client_dev.tx_queue.pop_front() {
                in_tx.send(pkt).await.unwrap();
            }
            if closed_send
                && matches!(
                    client_sockets.get::<TcpSocket>(client_handle).state(),
                    TcpState::TimeWait | TcpState::Closed
                )
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        server_task.await.unwrap();
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(StdDuration::from_secs(2), runner_handle).await;
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
        let mut client_dev = VirtualDevice::new(MTU, 512, false);
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

        let mut client_dev = VirtualDevice::new(MTU, 128, true);
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

        let mut client_dev = VirtualDevice::new(MTU, 128, true);
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

    #[test]
    fn low_memory_hard_handle_cap_and_icmpv6_tx_checksum_and_ipv6_ext_hdr_tcp() {
        assert_eq!(hard_handle_cap_for(128, true), 160);
        assert_eq!(hard_handle_cap_for(512, false), 576);

        let dev = VirtualDevice::new(1500, 128, true);
        assert_eq!(dev.tx_queue_high_water, 64);
        assert_eq!(VirtualDevice::new(1500, 4, false).tx_queue_high_water, 16);
        assert_eq!(VirtualDevice::new(1500, 4096, false).tx_queue_high_water, 64);
        let caps = dev.capabilities();
        assert!(matches!(caps.checksum.ipv4, Checksum::Tx));
        assert!(matches!(caps.checksum.tcp, Checksum::Tx));
        assert!(matches!(caps.checksum.icmpv6, Checksum::Tx));

        // Build an IPv6 TCP SYN preceded by Hop-by-Hop (0) -> Destination Options (60).
        let src_ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[60u8, 0, 1, 4, 0, 0, 0, 0]);
        ext.extend_from_slice(&[6u8, 0, 1, 4, 0, 0, 0, 0]);
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&51_234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02; // SYN

        let payload_len = (ext.len() + tcp.len()) as u16;
        let mut pkt = Vec::with_capacity(40 + usize::from(payload_len));
        pkt.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(0); // Hop-by-Hop
        pkt.push(64);
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        pkt.extend_from_slice(&ext);
        pkt.extend_from_slice(&tcp);

        match classify_inbound_tcp(&pkt) {
            InboundTcpKind::InitialSyn(src, dst) => {
                assert_eq!(src, SocketAddr::new(IpAddr::V6(src_ip), 51_234));
                assert_eq!(dst, SocketAddr::new(IpAddr::V6(dst_ip), 443));
            }
            _ => panic!("expected InitialSyn for IPv6 TCP SYN with extension headers"),
        }

        let rst = build_tcp_rst_ack_reply(&pkt)
            .expect("expected valid IPv6 RST+ACK for SYN with extension headers");
        let rst_ip = Ipv6Packet::new_checked(&rst).unwrap();
        assert_eq!(rst_ip.next_header(), IpProtocol::Tcp);
        assert_eq!(rst_ip.src_addr(), dst_ip);
        assert_eq!(rst_ip.dst_addr(), src_ip);
        let rst_tcp = TcpPacket::new_checked(rst_ip.payload()).unwrap();
        assert!(rst_tcp.rst() && rst_tcp.ack());
        assert_eq!(rst_tcp.src_port(), 443);
        assert_eq!(rst_tcp.dst_port(), 51_234);
        assert_eq!(rst_tcp.ack_number().0, 0x0102_0305);
    }

    #[test]
    fn normalize_ipv6_ext_headers_and_socket_shared_cache_line_separation() {
        // Build an IPv6 TCP SYN carrying Routing (43) -> atomic Fragment (44) -> DestOpts (60) -> TCP (6).
        let src_ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst_ip = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let mut ext = Vec::new();
        ext.extend_from_slice(&[44u8, 0, 0, 0, 0, 0, 0, 0]); // Routing (43) -> Fragment (44)
        ext.extend_from_slice(&[60u8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78]); // atomic Fragment (44) -> DestOpts (60)
        ext.extend_from_slice(&[6u8, 0, 1, 4, 0, 0, 0, 0]); // DestOpts (60) -> TCP (6)

        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&51_234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x02; // SYN

        let orig_payload_len = (ext.len() + tcp.len()) as u16;
        let mut pkt = Vec::with_capacity(40 + usize::from(orig_payload_len));
        pkt.extend_from_slice(&[0x60, 0x12, 0x34, 0x56]); // Version 6 + Traffic Class / Flow Label
        pkt.extend_from_slice(&orig_payload_len.to_be_bytes());
        pkt.push(43); // Routing
        pkt.push(55); // Hop Limit
        pkt.extend_from_slice(&src_ip.octets());
        pkt.extend_from_slice(&dst_ip.octets());
        pkt.extend_from_slice(&ext);
        pkt.extend_from_slice(&tcp);

        let normalized = normalize_inbound_ipv6_tcp(pkt).expect("normalized IPv6 TCP packet");
        assert_eq!(normalized.len(), 60);
        assert_eq!(&normalized[0..4], &[0x60, 0x12, 0x34, 0x56]);
        assert_eq!(u16::from_be_bytes([normalized[4], normalized[5]]), 20);
        assert_eq!(normalized[6], IP_PROTO_TCP);
        assert_eq!(normalized[7], 55);
        let ip = Ipv6Packet::new_checked(&normalized).expect("valid canonical IPv6 packet");
        assert_eq!(ip.next_header(), IpProtocol::Tcp);
        assert_eq!(ip.src_addr(), src_ip);
        assert_eq!(ip.dst_addr(), dst_ip);
        assert_eq!(ip.payload(), &tcp);

        // Already-canonical IPv6 TCP packet passes through untouched.
        let passthrough = normalize_inbound_ipv6_tcp(normalized.clone()).expect("passthrough");
        assert_eq!(passthrough, normalized);

        // Verify SocketShared separates dirty atomics from the control Mutex cache line
        // and guarded take_{tx,rx}_dirty helpers behave cleanly.
        let shared = SocketShared::new(TcpSocketControl {
            send_buffer: RingBuffer::new(vec![0u8; 1024]),
            send_waker: None,
            recv_buffer: RingBuffer::new(vec![0u8; 1024]),
            recv_waker: None,
            recv_state: HalfState::Normal,
            send_state: HalfState::Normal,
            rx_backpressured: false,
        });
        let dirty_addr = &shared.dirty.0.tx_dirty as *const AtomicBool as usize;
        let control_addr = &shared.control as *const Mutex<TcpSocketControl> as usize;
        assert!(
            control_addr.abs_diff(dirty_addr) >= 64,
            "dirty atomics and control mutex must not share a 64B cache line"
        );
        assert!(control_addr.abs_diff(dirty_addr) >= std::mem::align_of::<CachePadded<()>>());

        assert!(!shared.take_tx_dirty());
        assert!(!shared.take_rx_dirty());
        shared.mark_tx_dirty();
        assert!(shared.take_tx_dirty());
        assert!(!shared.take_tx_dirty());
        shared.mark_rx_dirty();
        assert!(shared.take_rx_dirty());
        assert!(!shared.take_rx_dirty());
    }

    #[tokio::test]
    async fn ipv6_syn_with_dest_opts_completes_handshake_without_icmpv6_parameter_problem() {
        const MTU: usize = 1500;
        const BUF: usize = 32 * 1024;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, 16, 128, stop_rx).unwrap();

        let clock = MonotonicClock::new();
        let mut client_dev = VirtualDevice::new(MTU, 128, true);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x2001_0db8_cafe_babe;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, clock.now());

        let client_ip = Ipv6Address::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 1);
        let gateway_ip = Ipv6Address::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 2);
        let remote_ip = Ipv6Address::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        client_iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(client_ip), 64));
        });
        client_iface
            .routes_mut()
            .add_default_ipv6_route(gateway_ip)
            .unwrap();

        let mut client_sockets = SocketSet::new(Vec::new());
        let mut client_sock = TcpSocket::new(
            TcpSocketBuffer::new(vec![0u8; BUF]),
            TcpSocketBuffer::new(vec![0u8; BUF]),
        );
        configure_local_tun_socket(&mut client_sock);
        client_sock
            .connect(client_iface.context(), (remote_ip, 443), 51_443)
            .unwrap();
        let client_handle = client_sockets.add(client_sock);

        let wrap_with_dest_opts = |pkt: &[u8]| -> Vec<u8> {
            assert!(pkt.len() >= 40);
            assert_eq!(pkt[0] >> 4, 6);
            assert_eq!(pkt[6], IP_PROTO_TCP);
            let tcp_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            let tcp = &pkt[40..40 + tcp_len];
            // Destination Options (60) -> NextHeader=TCP(6), HdrExtLen=0 (8B), PadN(4).
            let dest_opts: [u8; 8] = [IP_PROTO_TCP, 0, 1, 4, 0, 0, 0, 0];
            let new_payload_len = u16::try_from(dest_opts.len() + tcp.len()).unwrap();
            let mut out = Vec::with_capacity(40 + usize::from(new_payload_len));
            out.extend_from_slice(&pkt[..40]);
            out[4..6].copy_from_slice(&new_payload_len.to_be_bytes());
            out[6] = 60; // Destination Options
            out.extend_from_slice(&dest_opts);
            out.extend_from_slice(tcp);
            out
        };

        client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
        let raw_syn = client_dev.tx_queue.pop_front().expect("IPv6 SYN emitted");
        let syn_with_dest_opts = wrap_with_dest_opts(&raw_syn);
        assert_eq!(syn_with_dest_opts[6], 60);
        in_tx.send(syn_with_dest_opts).await.unwrap();

        let mut server_stream = tokio::time::timeout(StdDuration::from_secs(3), stream_rx.recv())
            .await
            .expect("IPv6 DestOpts accept timeout")
            .expect("accepted IPv6 stream");
        assert_eq!(
            server_stream.local_addr(),
            SocketAddr::new(IpAddr::V6(client_ip), 51_443)
        );
        assert_eq!(
            server_stream.remote_addr(),
            SocketAddr::new(IpAddr::V6(remote_ip), 443)
        );

        // Verify smoltcp emits an IPv6 TCP SYN+ACK (never ICMPv6 Parameter Problem).
        let syn_ack = tokio::time::timeout(StdDuration::from_secs(3), out_rx.recv())
            .await
            .expect("IPv6 SYN+ACK timeout")
            .expect("IPv6 SYN+ACK packet");
        let syn_ack_ip = Ipv6Packet::new_checked(&syn_ack).expect("valid IPv6 SYN+ACK");
        assert_eq!(
            syn_ack_ip.next_header(),
            IpProtocol::Tcp,
            "expected IPv6 TCP SYN+ACK, not ICMPv6 Parameter Problem"
        );
        let syn_ack_tcp = TcpPacket::new_checked(syn_ack_ip.payload()).expect("valid TCP SYN+ACK");
        assert!(syn_ack_tcp.syn() && syn_ack_tcp.ack());
        assert_eq!(syn_ack_tcp.src_port(), 443);
        assert_eq!(syn_ack_tcp.dst_port(), 51_443);
        client_dev.rx_queue.push_back(syn_ack);

        let server_task = tokio::spawn(async move {
            let mut req = [0u8; 5];
            server_stream.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"HELLO");
            server_stream.write_all(b"WORLD").await.unwrap();
            server_stream.shutdown().await.unwrap();
        });

        let mut sent_hello = false;
        let mut reply = Vec::new();
        let mut client_closed = false;
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            assert!(
                StdInstant::now() < deadline,
                "IPv6 DestOpts handshake/transfer timed out (reply={reply:?})"
            );
            while let Ok(pkt) = out_rx.try_recv() {
                let ip = Ipv6Packet::new_checked(&pkt).expect("valid IPv6 reply packet");
                assert_eq!(
                    ip.next_header(),
                    IpProtocol::Tcp,
                    "expected TCP reply, not ICMPv6 Parameter Problem"
                );
                client_dev.rx_queue.push_back(pkt);
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            {
                let sock = client_sockets.get_mut::<TcpSocket>(client_handle);
                if !sent_hello && sock.can_send() {
                    sock.send_slice(b"HELLO").unwrap();
                    sent_hello = true;
                }
                while sock.can_recv() {
                    sock.recv(|buf| {
                        reply.extend_from_slice(buf);
                        (buf.len(), ())
                    })
                    .unwrap();
                }
                if reply == b"WORLD" && !sock.may_recv() && !client_closed {
                    sock.close();
                    client_closed = true;
                }
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            while let Some(pkt) = client_dev.tx_queue.pop_front() {
                in_tx.send(wrap_with_dest_opts(&pkt)).await.unwrap();
            }
            if reply == b"WORLD"
                && matches!(
                    client_sockets.get::<TcpSocket>(client_handle).state(),
                    TcpState::TimeWait | TcpState::Closed
                )
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        server_task.await.unwrap();
        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(StdDuration::from_secs(2), runner_handle).await;
    }

    #[test]
    fn classify_inbound_tcp_rejects_unspecified_ips_and_zero_ports() {
        let build_v4 = |src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8| -> Vec<u8> {
            let mut pkt = vec![0u8; 40];
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
            pkt[8] = 64;
            pkt[9] = IP_PROTO_TCP;
            pkt[12..16].copy_from_slice(&src);
            pkt[16..20].copy_from_slice(&dst);
            pkt[20..22].copy_from_slice(&sport.to_be_bytes());
            pkt[22..24].copy_from_slice(&dport.to_be_bytes());
            pkt[32] = 0x50;
            pkt[33] = flags;
            pkt
        };
        let build_v6 = |src: std::net::Ipv6Addr,
                        dst: std::net::Ipv6Addr,
                        sport: u16,
                        dport: u16,
                        flags: u8|
         -> Vec<u8> {
            let mut pkt = vec![0u8; 60];
            pkt[0] = 0x60;
            pkt[4..6].copy_from_slice(&20u16.to_be_bytes());
            pkt[6] = IP_PROTO_TCP;
            pkt[7] = 64;
            pkt[8..24].copy_from_slice(&src.octets());
            pkt[24..40].copy_from_slice(&dst.octets());
            pkt[40..42].copy_from_slice(&sport.to_be_bytes());
            pkt[42..44].copy_from_slice(&dport.to_be_bytes());
            pkt[52] = 0x50;
            pkt[53] = flags;
            pkt
        };

        assert!(matches!(
            classify_inbound_tcp(&build_v4([0, 0, 0, 0], [1, 1, 1, 1], 1234, 443, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v4([198, 18, 0, 1], [0, 0, 0, 0], 1234, 443, 0x10)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v4([198, 18, 0, 1], [1, 1, 1, 1], 0, 443, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v4([198, 18, 0, 1], [1, 1, 1, 1], 1234, 0, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v4([198, 18, 0, 1], [1, 1, 1, 1], 1234, 443, 0x02)),
            InboundTcpKind::InitialSyn(_, _)
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v4([198, 18, 0, 1], [1, 1, 1, 1], 1234, 443, 0x10)),
            InboundTcpKind::NonSyn
        ));

        let v6_src = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let v6_dst = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let v6_unspec = std::net::Ipv6Addr::UNSPECIFIED;
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_unspec, v6_dst, 1234, 443, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_src, v6_unspec, 1234, 443, 0x10)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_src, v6_dst, 0, 443, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_src, v6_dst, 1234, 0, 0x02)),
            InboundTcpKind::Invalid
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_src, v6_dst, 1234, 443, 0x02)),
            InboundTcpKind::InitialSyn(_, _)
        ));
        assert!(matches!(
            classify_inbound_tcp(&build_v6(v6_src, v6_dst, 1234, 443, 0x10)),
            InboundTcpKind::NonSyn
        ));
    }

    #[test]
    fn socket_buffer_pool_recycles_sockets_and_control_rings_and_shrinks_idle() {
        let mut pool = SocketBufferPool::new(64 * 1024, 64 * 1024, 16 * 1024, 16 * 1024, false);
        assert!(pool.is_empty());

        let mut sock = pool.checkout_socket();
        configure_local_tun_socket(&mut sock);
        let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        sock.listen(dst).unwrap();
        pool.return_socket(sock);
        assert_eq!(pool.sockets.len(), 1);

        let mut reused = pool.checkout_socket();
        assert_eq!(pool.sockets.len(), 0);
        assert_eq!(reused.state(), TcpState::Closed);
        assert_eq!(reused.recv_capacity(), 64 * 1024);
        assert_eq!(reused.send_capacity(), 64 * 1024);
        configure_local_tun_socket(&mut reused);
        reused.listen(dst).unwrap();
        pool.return_socket(reused);

        // Shared Arc with unread recv bytes: send_buffer reclaims safely while unread recv_buffer stays intact.
        let (mut recv_buf, send_buf) = pool.checkout_control_buffers();
        assert_eq!(recv_buf.enqueue_slice(b"abc"), 3);
        let shared = Arc::new(SocketShared::new(TcpSocketControl {
            send_buffer: send_buf,
            send_waker: None,
            recv_buffer: recv_buf,
            recv_waker: None,
            recv_state: HalfState::Closed,
            send_state: HalfState::Closed,
            rx_backpressured: false,
        }));
        let stream_ref = Arc::clone(&shared);
        pool.reclaim_shared_buffers(shared);
        assert_eq!(pool.control_send.len(), 1);
        assert_eq!(pool.control_recv.len(), 0);
        assert_eq!(stream_ref.lock_control().recv_buffer.len(), 3);
        drop(stream_ref);

        // Uniquely owned Arc: both control rings reclaim and clear before reuse.
        let (mut recv_buf2, mut send_buf2) = pool.checkout_control_buffers();
        assert_eq!(recv_buf2.enqueue_slice(b"hello"), 5);
        assert_eq!(send_buf2.enqueue_slice(b"world"), 5);
        let shared2 = Arc::new(SocketShared::new(TcpSocketControl {
            send_buffer: send_buf2,
            send_waker: None,
            recv_buffer: recv_buf2,
            recv_waker: None,
            recv_state: HalfState::Closed,
            send_state: HalfState::Closed,
            rx_backpressured: false,
        }));
        pool.reclaim_shared_buffers(shared2);
        assert_eq!(pool.control_recv.len(), 1);
        assert_eq!(pool.control_send.len(), 1);

        let (clean_recv, clean_send) = pool.checkout_control_buffers();
        assert!(clean_recv.is_empty());
        assert!(clean_send.is_empty());
        pool.return_control_recv(clean_recv);
        pool.return_control_send(clean_send);
        assert!(!pool.is_empty());

        pool.shrink_idle();
        assert!(pool.is_empty());
    }

    #[test]
    fn should_reset_timer_clears_stale_short_deadlines_and_keeps_far_deadlines() {
        let now = tokio::time::Instant::now();
        assert!(should_reset_timer(
            true,
            Some(now + StdDuration::from_secs(5)),
            now,
            now + StdDuration::from_secs(10),
        ));
        assert!(should_reset_timer(
            false,
            None,
            now,
            now + StdDuration::from_secs(10),
        ));
        assert!(should_reset_timer(
            false,
            Some(now + StdDuration::from_secs(10)),
            now,
            now + StdDuration::from_secs(1),
        ));
        assert!(should_reset_timer(
            false,
            Some(now),
            now,
            now + StdDuration::from_secs(1),
        ));
        assert!(should_reset_timer(
            false,
            Some(now + StdDuration::from_millis(10)),
            now,
            now + StdDuration::from_secs(10),
        ));
        assert!(!should_reset_timer(
            false,
            Some(now + StdDuration::from_millis(200)),
            now,
            now + StdDuration::from_secs(10),
        ));
    }

    #[tokio::test]
    async fn time_wait_reaps_within_250ms_without_unsolicited_rst() {
        const MTU: usize = 1500;
        const BUF: usize = 32 * 1024;

        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (stop_tx, stop_rx) = watch::channel(false);

        let (mut stream_rx, runner_handle) =
            spawn_tcp_netstack(in_rx, out_tx, MTU, BUF, BUF, 4, 64, stop_rx).unwrap();

        let clock = MonotonicClock::new();
        let mut client_dev = VirtualDevice::new(MTU, 64, true);
        let mut client_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        client_cfg.random_seed = 0x4242_1337_cafe_f00d;
        let mut client_iface = Interface::new(client_cfg, &mut client_dev, clock.now());
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
        configure_local_tun_socket(&mut client_sock);
        client_sock
            .connect(
                client_iface.context(),
                (Ipv4Address::new(1, 1, 1, 1), 443),
                49_500,
            )
            .unwrap();
        let client_handle = client_sockets.add(client_sock);

        client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
        in_tx
            .send(client_dev.tx_queue.pop_front().expect("SYN emitted"))
            .await
            .unwrap();

        let mut server_stream = tokio::time::timeout(StdDuration::from_secs(3), stream_rx.recv())
            .await
            .expect("accept timeout")
            .expect("accepted stream");

        // Server initiates active close so the netstack side transitions into TIME_WAIT.
        let server_task = tokio::spawn(async move {
            server_stream.write_all(b"BYE").await.unwrap();
            server_stream.shutdown().await.unwrap();
        });

        let mut received = Vec::new();
        let mut client_closed = false;
        let mut saw_rst = false;
        let deadline = StdInstant::now() + StdDuration::from_secs(5);
        loop {
            assert!(
                StdInstant::now() < deadline,
                "TIME_WAIT close timed out (received={received:?})"
            );
            while let Ok(pkt) = out_rx.try_recv() {
                if let Ok(ip) = Ipv4Packet::new_checked(&pkt) {
                    if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                        if tcp.rst() {
                            saw_rst = true;
                        }
                    }
                }
                client_dev.rx_queue.push_back(pkt);
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            {
                let sock = client_sockets.get_mut::<TcpSocket>(client_handle);
                while sock.can_recv() {
                    sock.recv(|buf| {
                        received.extend_from_slice(buf);
                        (buf.len(), ())
                    })
                    .unwrap();
                }
                if received == b"BYE" && !sock.may_recv() && !client_closed {
                    sock.close();
                    client_closed = true;
                }
            }
            client_iface.poll(clock.now(), &mut client_dev, &mut client_sockets);
            while let Some(pkt) = client_dev.tx_queue.pop_front() {
                in_tx.send(pkt).await.unwrap();
            }
            if received == b"BYE"
                && client_sockets.get::<TcpSocket>(client_handle).state() == TcpState::Closed
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        server_task.await.unwrap();

        // Wait past the 250ms TIME_WAIT_REAP_TIMEOUT and verify zero unsolicited RSTs are emitted.
        tokio::time::sleep(StdDuration::from_millis(350)).await;
        while let Ok(pkt) = out_rx.try_recv() {
            if let Ok(ip) = Ipv4Packet::new_checked(&pkt) {
                if let Ok(tcp) = TcpPacket::new_checked(ip.payload()) {
                    if tcp.rst() {
                        saw_rst = true;
                    }
                }
            }
        }
        assert!(
            !saw_rst,
            "TIME_WAIT reap must not emit an unsolicited TCP RST"
        );

        let _ = stop_tx.send(true);
        let _ = tokio::time::timeout(StdDuration::from_secs(2), runner_handle).await;
    }
}
