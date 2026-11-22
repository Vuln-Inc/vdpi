#![cfg(unix)]

use crate::config::{TunProfile, MAX_MTU, MIN_MTU};
use crate::events::EventRing;
use crate::pipeline::{run_tun_pipeline, wait_shutdown, TunStats};
use anyhow::{anyhow, Context, Result};
use std::io::ErrorKind;
use std::os::unix::io::{AsRawFd, OwnedFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};
use vdpi::desync::EngineContext;

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
    let clamped_mtu = mtu.clamp(MIN_MTU, MAX_MTU);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(profile.channel_capacity);
    let (fd_stop_tx, fd_stop_rx) = watch::channel(false);

    let mut ext_stop = shutdown_rx.clone();
    let ext_bridge_tx = fd_stop_tx.clone();
    let ext_bridge = tokio::spawn(async move {
        wait_shutdown(&mut ext_stop).await;
        let _ = ext_bridge_tx.send(true);
    });

    let read_fd = Arc::clone(&async_fd);
    let mut stop_read = fd_stop_rx.clone();
    let read_stop_tx = fd_stop_tx.clone();
    let read_buf_size = clamped_mtu + 128;
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
                        let _ = read_stop_tx.send(true);
                        break;
                    }
                }
            };

            match guard.try_io(|inner| read_raw_fd(inner.as_raw_fd(), &mut buf)) {
                Ok(Ok(0)) => {
                    let _ = read_stop_tx.send(true);
                    break;
                }
                Ok(Ok(n)) => {
                    if inbound_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => continue,
                Ok(Err(e)) => {
                    warn!(error = %e, "TUN read error");
                    let _ = read_stop_tx.send(true);
                    break;
                }
                Err(_would_block) => continue,
            }
        }
    });

    let write_fd = Arc::clone(&async_fd);
    let mut stop_write = fd_stop_rx.clone();
    let write_stop_tx = fd_stop_tx.clone();
    let writer_task = tokio::spawn(async move {
        'outer: loop {
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
                    _ = wait_shutdown(&mut stop_write) => break 'outer,
                    res = write_fd.writable() => match res {
                        Ok(g) => g,
                        Err(e) => {
                            warn!(error = %e, "TUN writable wait failed");
                            let _ = write_stop_tx.send(true);
                            break 'outer;
                        }
                    }
                };

                match guard.try_io(|inner| write_raw_fd(inner.as_raw_fd(), &pkt)) {
                    Ok(Ok(_)) => break,
                    Ok(Err(e)) if e.kind() == ErrorKind::Interrupted => continue,
                    Ok(Err(e)) => {
                        if is_fatal_tun_errno(&e) {
                            warn!(error = %e, "fatal TUN write error");
                            let _ = write_stop_tx.send(true);
                            break 'outer;
                        }
                        debug!(error = %e, "transient TUN write drop");
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
        clamped_mtu,
        profile,
        fd_stop_rx,
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

fn is_fatal_tun_errno(err: &std::io::Error) -> bool {
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

fn read_raw_fd(fd: i32, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn write_raw_fd(fd: i32, buf: &[u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}
