#![cfg(unix)]

use crate::config::{AppBypassHook, TunProfile, MAX_MTU, MIN_MTU};
use crate::events::EventRing;
use crate::pipeline::{run_tun_pipeline_with_app_bypass, wait_shutdown, TunStats};
use anyhow::{anyhow, Context, Result};
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tokio::task::AbortHandle;
use tracing::{debug, warn};
use vdpi_core::desync::EngineContext;

#[cfg(target_vendor = "apple")]
const TUN_PI_LEN: usize = 4;
#[cfg(not(target_vendor = "apple"))]
const TUN_PI_LEN: usize = 0;

#[cfg(target_vendor = "apple")]
const UTUN_RX_PROC_UUID_LEN: usize = 16;
#[cfg(target_vendor = "apple")]
const SYSPROTO_CONTROL: libc::c_int = 2;
#[cfg(target_vendor = "apple")]
const UTUN_OPT_FLAGS: libc::c_int = 1;
#[cfg(target_vendor = "apple")]
const UTUN_FLAGS_ENABLE_PROC_UUID: u32 = 0x0004;

/// Bounded outbound TUN TX channel depth (128 packets).
///
/// Caps the downstream FIFO ahead of the Unix TUN writer so bulk TCP flows hit
/// event-driven backpressure via `outbound_tx.reserve().await` instead of
/// queuing up to 4096 TCP packets behind `inbound` (`profile.channel_capacity`)
/// and delaying UDP voice/game preemption.
const TUN_TX_CHANNEL_CAPACITY: usize = 128;

fn outbound_channel_capacity(profile: TunProfile) -> usize {
    profile.channel_capacity.clamp(1, TUN_TX_CHANNEL_CAPACITY)
}

struct AbortOnDrop(Vec<AbortHandle>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

/// Validates and registers a Unix/Android TUN `OwnedFd` with Tokio synchronously before
/// returning control to the caller, so startup failures surface immediately and never leak the fd.
pub fn register_tun_fd(owned_fd: OwnedFd) -> Result<Arc<AsyncFd<OwnedFd>>> {
    set_nonblocking(owned_fd.as_raw_fd()).context("failed to set O_NONBLOCK on TUN fd")?;
    // SAFETY: `owned_fd` exclusively owns the detached TUN fd and keeps it open for the
    // entire lifetime of the `AsyncFd` wrapper.
    let async_fd =
        unsafe { AsyncFd::register(owned_fd) }.context("failed to register TUN fd with tokio")?;
    Ok(Arc::new(async_fd))
}

/// Runs the TUN engine attached to a registered Unix/Android `AsyncFd<OwnedFd>`.
/// Closes the TUN fd automatically when the tunnel stops or exits.
pub async fn run_registered_tun_fd(
    async_fd: Arc<AsyncFd<OwnedFd>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    run_registered_tun_fd_with_route_watch(
        async_fd,
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

/// Runs the TUN engine attached to a registered Unix/Android `AsyncFd<OwnedFd>` with an
/// optional route-change watch receiver that drains and rebinds active UDP Cone-NAT flows
/// on uplink switches. Closes the TUN fd automatically when the tunnel stops or exits.
#[allow(clippy::too_many_arguments)]
pub async fn run_registered_tun_fd_with_route_watch(
    async_fd: Arc<AsyncFd<OwnedFd>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
    route_rx: Option<watch::Receiver<u64>>,
) -> Result<()> {
    run_registered_tun_fd_with_app_bypass(
        async_fd,
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

/// Runs the TUN engine attached to a registered Unix/Android `AsyncFd<OwnedFd>` with an
/// optional route-change watch receiver and an optional per-flow [`AppBypassHook`] callback
/// for desktop per-app split tunneling. Closes the TUN fd automatically when the tunnel stops
/// or exits.
#[allow(clippy::too_many_arguments)]
pub async fn run_registered_tun_fd_with_app_bypass(
    async_fd: Arc<AsyncFd<OwnedFd>>,
    ctx: EngineContext,
    tun_stats: Arc<TunStats>,
    events: Arc<EventRing>,
    mtu: usize,
    profile: TunProfile,
    shutdown_rx: watch::Receiver<bool>,
    route_rx: Option<watch::Receiver<u64>>,
    app_bypass: Option<AppBypassHook>,
) -> Result<()> {
    let clamped_mtu = mtu.clamp(MIN_MTU, MAX_MTU);
    let io_batch_limit = profile.batch_size.clamp(16, 256);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity);
    let (outbound_tx, mut outbound_rx) =
        mpsc::channel::<Vec<u8>>(outbound_channel_capacity(profile));
    let (fd_stop_tx, fd_stop_rx) = watch::channel(false);

    let mut ext_stop = shutdown_rx.clone();
    let ext_bridge_tx = fd_stop_tx.clone();
    let ext_bridge = tokio::spawn(async move {
        wait_shutdown(&mut ext_stop).await;
        let _ = ext_bridge_tx.send(true);
    });

    let rx_pi_len = detect_rx_pi_len(async_fd.as_raw_fd());
    let tx_pi_len = rx_pi_len;
    let read_fd = Arc::clone(&async_fd);
    let mut stop_read = fd_stop_rx.clone();
    let read_stop_tx = fd_stop_tx.clone();
    let read_buf_size = clamped_mtu + rx_pi_len + 128;
    let reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; read_buf_size];
        'outer: loop {
            let mut guard = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_read) => break,
                res = read_fd.readable() => match res {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "TUN readable wait failed");
                        let _ = read_stop_tx.send(true);
                        break;
                    }
                }
            };

            let mut drained = 0usize;
            while drained < io_batch_limit {
                match guard.try_io(|inner| read_raw_fd(inner.as_raw_fd(), &mut buf)) {
                    Ok(Ok(0)) => {
                        let _ = read_stop_tx.send(true);
                        break 'outer;
                    }
                    Ok(Ok(n)) => {
                        drained += 1;
                        let Some(ip_pkt) = strip_tun_pi(&buf[..n], rx_pi_len) else {
                            debug!(bytes = n, "dropping malformed or non-IP TUN frame");
                            continue;
                        };
                        match inbound_tx.try_send(ip_pkt.to_vec()) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(pkt)) => {
                                // Drop readiness guard before awaiting channel space so backpressure
                                // stays in the kernel TUN queue instead of silently dropping TCP frames.
                                drop(guard);
                                tokio::select! {
                                    biased;
                                    _ = wait_shutdown(&mut stop_read) => break 'outer,
                                    res = inbound_tx.send(pkt) => {
                                        if res.is_err() {
                                            break 'outer;
                                        }
                                    }
                                }
                                break;
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break 'outer,
                        }
                    }
                    Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => continue,
                    Ok(Err(e)) if is_congestion_tun_errno(&e) => {
                        debug!(error = %e, "transient TUN read congestion; backing off");
                        drop(guard);
                        tokio::select! {
                            biased;
                            _ = wait_shutdown(&mut stop_read) => break 'outer,
                            _ = tokio::time::sleep(std::time::Duration::from_millis(2)) => {}
                        }
                        break;
                    }
                    Ok(Err(e)) => {
                        warn!(error = %e, "TUN read error");
                        let _ = read_stop_tx.send(true);
                        break 'outer;
                    }
                    Err(_would_block) => break,
                }
            }
            if drained >= io_batch_limit {
                tokio::task::yield_now().await;
            }
        }
    });

    let write_fd = Arc::clone(&async_fd);
    let write_stats = Arc::clone(&tun_stats);
    let mut stop_write = fd_stop_rx.clone();
    let write_stop_tx = fd_stop_tx.clone();
    let writer_task = tokio::spawn(async move {
        let mut pending: Option<Vec<u8>> = None;
        let mut congestion_retries: u8 = 0;
        'outer: loop {
            if pending.is_none() {
                let pkt = tokio::select! {
                    biased;
                    _ = wait_shutdown(&mut stop_write) => break,
                    maybe_pkt = outbound_rx.recv() => match maybe_pkt {
                        Some(p) => p,
                        None => break,
                    }
                };
                pending = Some(pkt);
                congestion_retries = 0;
            }

            let mut guard = tokio::select! {
                biased;
                _ = wait_shutdown(&mut stop_write) => break,
                res = write_fd.writable() => match res {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(error = %e, "TUN writable wait failed");
                        let _ = write_stop_tx.send(true);
                        break;
                    }
                }
            };

            let mut written = 0usize;
            while written < io_batch_limit {
                let pkt = match pending.take() {
                    Some(p) => p,
                    None => match outbound_rx.try_recv() {
                        Ok(p) => {
                            congestion_retries = 0;
                            p
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break 'outer,
                    },
                };

                match guard.try_io(|inner| write_raw_fd(inner.as_raw_fd(), &pkt, tx_pi_len)) {
                    Ok(Ok(_)) => {
                        written += 1;
                        congestion_retries = 0;
                    }
                    Ok(Err(e)) => {
                        match handle_tun_write_error(&e, &mut congestion_retries, &write_stats) {
                            TunWriteErrorAction::RetryImmediate => {
                                pending = Some(pkt);
                            }
                            TunWriteErrorAction::BackoffMs(backoff_ms) => {
                                pending = Some(pkt);
                                drop(guard);
                                tokio::select! {
                                    biased;
                                    _ = wait_shutdown(&mut stop_write) => break 'outer,
                                    _ = tokio::time::sleep(std::time::Duration::from_millis(
                                        backoff_ms,
                                    )) => {}
                                }
                                continue 'outer;
                            }
                            TunWriteErrorAction::Dropped => {
                                written += 1;
                            }
                            TunWriteErrorAction::Fatal => {
                                let _ = write_stop_tx.send(true);
                                break 'outer;
                            }
                        }
                    }
                    Err(_would_block) => {
                        pending = Some(pkt);
                        break;
                    }
                }
            }
            if written >= io_batch_limit {
                tokio::task::yield_now().await;
            }
        }
    });

    let _guard = AbortOnDrop(vec![
        ext_bridge.abort_handle(),
        reader_task.abort_handle(),
        writer_task.abort_handle(),
    ]);

    let pipeline_res = run_tun_pipeline_with_app_bypass(
        inbound_rx,
        outbound_tx,
        ctx,
        tun_stats,
        events,
        clamped_mtu,
        profile,
        fd_stop_rx,
        route_rx,
        app_bypass,
    )
    .await;

    ext_bridge.abort();
    reader_task.abort();
    writer_task.abort();
    let _ = reader_task.await;
    let _ = writer_task.await;
    drop(async_fd);

    if *shutdown_rx.borrow() {
        Ok(())
    } else {
        pipeline_res.and_then(|_| Err(anyhow!("TUN interface closed unexpectedly")))
    }
}

const MAX_TUN_WRITE_CONGESTION_RETRIES: u8 = 8;

#[derive(Debug, PartialEq, Eq)]
enum TunWriteErrorAction {
    RetryImmediate,
    BackoffMs(u64),
    Dropped,
    Fatal,
}

fn handle_tun_write_error(
    err: &std::io::Error,
    congestion_retries: &mut u8,
    tun_stats: &TunStats,
) -> TunWriteErrorAction {
    if err.kind() == ErrorKind::Interrupted {
        return TunWriteErrorAction::RetryImmediate;
    }
    if is_congestion_tun_errno(err) {
        // On iOS/macOS Skywalk utun, XNU returns ENOSPC/ENOBUFS (not EAGAIN)
        // when the pending input chain exceeds 512 packets. Back off briefly
        // instead of dropping segments or hammering XNU.
        if *congestion_retries < MAX_TUN_WRITE_CONGESTION_RETRIES {
            *congestion_retries += 1;
            return TunWriteErrorAction::BackoffMs(u64::from(*congestion_retries).min(4));
        }
        *congestion_retries = 0;
        tun_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
        debug!(error = %err, "dropping TUN packet after sustained ENOSPC/ENOBUFS");
        return TunWriteErrorAction::Dropped;
    }
    if is_fatal_tun_errno(err) {
        warn!(error = %err, "fatal TUN write error");
        return TunWriteErrorAction::Fatal;
    }
    *congestion_retries = 0;
    tun_stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
    debug!(error = %err, "transient TUN write drop");
    TunWriteErrorAction::Dropped
}

fn is_fatal_tun_errno(err: &std::io::Error) -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if err.raw_os_error() == Some(libc::EBADFD) {
        return true;
    }
    matches!(
        err.raw_os_error(),
        Some(libc::EBADF) | Some(libc::ENODEV) | Some(libc::EIO) | Some(libc::ENXIO)
    )
}

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

#[cfg(target_vendor = "apple")]
fn detect_rx_pi_len(fd: i32) -> usize {
    let mut flags: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
    // SAFETY: `flags` is an initialized `u32` whose byte size matches `len`; `getsockopt`
    // writes at most `len` bytes into `flags` and returns 0 only on valid Darwin utun fds.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_FLAGS,
            std::ptr::addr_of_mut!(flags).cast::<libc::c_void>(),
            std::ptr::addr_of_mut!(len),
        )
    };
    if rc == 0
        && (len as usize) >= std::mem::size_of::<u32>()
        && (flags & UTUN_FLAGS_ENABLE_PROC_UUID) != 0
    {
        debug!(
            flags,
            "Darwin utun UTUN_FLAGS_ENABLE_PROC_UUID enabled; stripping 20-byte RX header"
        );
        TUN_PI_LEN + UTUN_RX_PROC_UUID_LEN
    } else {
        TUN_PI_LEN
    }
}

#[cfg(not(target_vendor = "apple"))]
fn detect_rx_pi_len(_fd: i32) -> usize {
    TUN_PI_LEN
}

#[cfg(target_vendor = "apple")]
fn strip_tun_pi(frame: &[u8], rx_pi_len: usize) -> Option<&[u8]> {
    let header_len = rx_pi_len.max(TUN_PI_LEN);
    if frame.len() <= header_len {
        return None;
    }
    let family = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if family != libc::AF_INET as u32 && family != libc::AF_INET6 as u32 {
        return None;
    }
    Some(&frame[header_len..])
}

#[cfg(not(target_vendor = "apple"))]
fn strip_tun_pi(frame: &[u8], _rx_pi_len: usize) -> Option<&[u8]> {
    if frame.is_empty() {
        None
    } else {
        Some(frame)
    }
}

#[cfg(target_vendor = "apple")]
fn tun_pi_header(pkt: &[u8]) -> std::io::Result<[u8; TUN_PI_LEN]> {
    let Some(&first) = pkt.first() else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "empty TUN packet",
        ));
    };
    let family = match first >> 4 {
        4 => libc::AF_INET as u32,
        6 => libc::AF_INET6 as u32,
        _ => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "unsupported IP version for Apple utun frame",
            ));
        }
    };
    Ok(family.to_be_bytes())
}

fn read_raw_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn is_congestion_tun_errno(err: &std::io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOSPC | libc::ENOBUFS))
}

#[cfg(target_vendor = "apple")]
fn write_raw_fd(fd: i32, buf: &[u8], tx_pi_len: usize) -> std::io::Result<usize> {
    let pi4 = tun_pi_header(buf)?;
    // XNU `UTUN_HEADER_SIZE(pcb)` is 4 bytes (AF) or 20 bytes (AF + 16-byte proc UUID)
    // in BOTH RX and TX directions when `UTUN_FLAGS_ENABLE_PROC_UUID` is active.
    let mut header = [0u8; 20];
    header[..4].copy_from_slice(&pi4);
    let hdr_len = if tx_pi_len >= 20 { 20 } else { 4 };
    let iov = [
        libc::iovec {
            iov_base: header.as_ptr().cast_mut().cast(),
            iov_len: hdr_len,
        },
        libc::iovec {
            iov_base: buf.as_ptr().cast_mut().cast(),
            iov_len: buf.len(),
        },
    ];
    // SAFETY: Both `header` and `buf` are valid byte slices that remain alive for the
    // entire synchronous `writev` syscall, and `writev` only reads from the iovecs.
    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(not(target_vendor = "apple"))]
fn write_raw_fd(fd: i32, buf: &[u8], _tx_pi_len: usize) -> std::io::Result<usize> {
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
    use std::os::unix::io::FromRawFd;

    #[test]
    fn raw_fd_write_and_read_roundtrip_framing() {
        let mut fds = [-1i32; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let tx = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let rx = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let rx_pi_len = detect_rx_pi_len(rx.as_raw_fd());
        assert_eq!(rx_pi_len, TUN_PI_LEN);

        let ipv4 = [0x45u8, 0x00, 0x00, 0x14, 1, 2, 3, 4];
        let written = write_raw_fd(tx.as_raw_fd(), &ipv4, rx_pi_len).unwrap();
        assert_eq!(written, TUN_PI_LEN + ipv4.len());

        let mut buf = [0u8; 64];
        let read = read_raw_fd(rx.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(read, TUN_PI_LEN + ipv4.len());
        #[cfg(target_vendor = "apple")]
        assert_eq!(
            &buf[..TUN_PI_LEN],
            (libc::AF_INET as u32).to_be_bytes().as_slice()
        );
        assert_eq!(strip_tun_pi(&buf[..read], rx_pi_len), Some(ipv4.as_slice()));

        let ipv6 = [0x60u8, 0x00, 0x00, 0x00, 5, 6, 7, 8];
        let written6 = write_raw_fd(tx.as_raw_fd(), &ipv6, rx_pi_len).unwrap();
        assert_eq!(written6, TUN_PI_LEN + ipv6.len());

        let read6 = read_raw_fd(rx.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(read6, TUN_PI_LEN + ipv6.len());
        #[cfg(target_vendor = "apple")]
        assert_eq!(
            &buf[..TUN_PI_LEN],
            (libc::AF_INET6 as u32).to_be_bytes().as_slice()
        );
        assert_eq!(
            strip_tun_pi(&buf[..read6], rx_pi_len),
            Some(ipv6.as_slice())
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn apple_pi_validation_rejects_bad_frames_and_strips_proc_uuid() {
        assert_eq!(strip_tun_pi(&[], TUN_PI_LEN), None);
        assert_eq!(strip_tun_pi(&[0, 0, 0, 2], TUN_PI_LEN), None);
        assert_eq!(strip_tun_pi(&[0, 0, 0, 99, 0x45, 0x00], TUN_PI_LEN), None);
        assert_eq!(
            tun_pi_header(&[]).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            tun_pi_header(&[0x30, 0x00]).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        let proc_uuid_pi_len = TUN_PI_LEN + UTUN_RX_PROC_UUID_LEN;
        let mut frame = Vec::with_capacity(proc_uuid_pi_len + 4);
        frame.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        frame.extend_from_slice(&[0xAAu8; UTUN_RX_PROC_UUID_LEN]);
        assert_eq!(strip_tun_pi(&frame, proc_uuid_pi_len), None);
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 0x14]);
        assert_eq!(
            strip_tun_pi(&frame, proc_uuid_pi_len),
            Some([0x45u8, 0x00, 0x00, 0x14].as_slice())
        );
    }

    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn non_apple_strip_pi_passthrough() {
        assert_eq!(strip_tun_pi(&[], TUN_PI_LEN), None);
        let pkt = [0x45u8, 0x00, 0x00, 0x14];
        assert_eq!(strip_tun_pi(&pkt, TUN_PI_LEN), Some(pkt.as_slice()));
    }

    #[test]
    fn tun_write_error_counts_congestion_exhaustion_and_transient_drops() {
        let stats = TunStats::default();
        let mut retries = 0u8;

        let eintr = std::io::Error::new(ErrorKind::Interrupted, "interrupted");
        assert_eq!(
            handle_tun_write_error(&eintr, &mut retries, &stats),
            TunWriteErrorAction::RetryImmediate
        );
        assert_eq!(retries, 0);
        assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 0);

        let enobufs = std::io::Error::from_raw_os_error(libc::ENOBUFS);
        for attempt in 1..=MAX_TUN_WRITE_CONGESTION_RETRIES {
            assert_eq!(
                handle_tun_write_error(&enobufs, &mut retries, &stats),
                TunWriteErrorAction::BackoffMs(u64::from(attempt).min(4))
            );
            assert_eq!(retries, attempt);
            assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 0);
        }

        let enospc = std::io::Error::from_raw_os_error(libc::ENOSPC);
        assert_eq!(
            handle_tun_write_error(&enospc, &mut retries, &stats),
            TunWriteErrorAction::Dropped
        );
        assert_eq!(retries, 0);
        assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 1);

        let emsgsize = std::io::Error::from_raw_os_error(libc::EMSGSIZE);
        assert_eq!(
            handle_tun_write_error(&emsgsize, &mut retries, &stats),
            TunWriteErrorAction::Dropped
        );
        assert_eq!(retries, 0);
        assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 2);

        let ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        assert_eq!(
            handle_tun_write_error(&ebadf, &mut retries, &stats),
            TunWriteErrorAction::Fatal
        );
        assert_eq!(stats.dropped_packets.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn outbound_channel_capacity_caps_fifo_depth_below_inbound() {
        assert_eq!(TUN_TX_CHANNEL_CAPACITY, 128);
        assert_eq!(TunProfile::DESKTOP.channel_capacity, 4096);
        assert_eq!(
            outbound_channel_capacity(TunProfile::DESKTOP),
            TUN_TX_CHANNEL_CAPACITY
        );
        assert_eq!(
            outbound_channel_capacity(TunProfile::STANDARD),
            TUN_TX_CHANNEL_CAPACITY
        );
        assert_eq!(
            outbound_channel_capacity(TunProfile::LOW_MEMORY),
            TUN_TX_CHANNEL_CAPACITY
        );

        let mut small = TunProfile::LOW_MEMORY;
        small.channel_capacity = 64;
        assert_eq!(outbound_channel_capacity(small), 64);

        let mut zero = TunProfile::LOW_MEMORY;
        zero.channel_capacity = 0;
        assert_eq!(outbound_channel_capacity(zero), 1);
    }
}
