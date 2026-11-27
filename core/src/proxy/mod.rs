pub mod http;
pub mod socks;

use crate::desync::{EngineContext, EngineTelemetry};
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;
use vdpi_core::bypass::BypassPolicy;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const SPLIT_TUNNEL_RESOLVE_TIMEOUT: Duration = Duration::from_millis(250);

#[cfg(any(target_os = "android", target_os = "ios"))]
const DIRECT_RELAY_BUF_SIZE: usize = 16 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const DIRECT_RELAY_BUF_SIZE: usize = 128 * 1024;

const DIRECT_TELEMETRY_BATCH_BYTES: u64 = 256 * 1024;

#[cfg(any(target_os = "android", target_os = "ios"))]
const DIRECT_IDLE_RELAY_TIMEOUT: Duration = Duration::from_secs(120);
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const DIRECT_IDLE_RELAY_TIMEOUT: Duration = Duration::from_secs(300);

/// Matched per-app split-tunnel bypass decision for an accepted proxy client.
pub(crate) struct SplitTunnelBypass {
    app_name: Option<String>,
}

impl SplitTunnelBypass {
    pub(crate) fn log_bypass(&self, host: &str) {
        let app = self.app_name.as_deref().unwrap_or("<unknown>");
        debug!("split-tunnel: bypassing DPI desync for app={app} host={host}");
    }
}

/// Returns `true` when a proxy request for `host:port` must be rejected to prevent
/// SSRF (non-loopback peers targeting loopback/link-local/private addresses) or
/// self-reflection into `local_addr`.
pub(crate) fn is_forbidden_proxy_host(
    is_loopback_peer: bool,
    host: &str,
    port: u16,
    local_addr: Option<SocketAddr>,
) -> bool {
    let trimmed = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.');
    let ip_candidate = trimmed.split('%').next().unwrap_or(trimmed);
    let parsed_ip = ip_candidate.parse::<IpAddr>().ok();

    if !is_loopback_peer
        && (trimmed.eq_ignore_ascii_case("localhost")
            || trimmed.to_ascii_lowercase().ends_with(".localhost")
            || parsed_ip.is_some_and(BypassPolicy::is_non_public_ip))
    {
        return true;
    }
    local_addr.is_some_and(|local| {
        local.port() == port
            && parsed_ip.is_some_and(|ip| ip.to_canonical() == local.ip().to_canonical())
    })
}

/// Returns `true` when a resolved `remote_addr` must be rejected for SSRF or self-reflection.
pub(crate) fn is_forbidden_remote_addr(
    is_loopback_peer: bool,
    remote_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
) -> bool {
    let remote_ip = remote_addr.ip().to_canonical();
    if !is_loopback_peer && BypassPolicy::is_non_public_ip(remote_ip) {
        return true;
    }
    local_addr.is_some_and(|local| {
        local.port() == remote_addr.port() && local.ip().to_canonical() == remote_ip
    })
}

/// Evaluates per-app split-tunnel policy for an accepted proxy TCP client.
///
/// Fast path: returns `None` immediately with zero syscalls when
/// `ctx.config.split_tunnel.is_active()` is `false` (`SplitTunnelMode::All`).
/// Offloads blocking OS process-table lookups to Tokio's blocking pool so worker threads never stall.
pub(crate) async fn check_split_tunnel_bypass(
    ctx: &EngineContext,
    peer_addr: Option<SocketAddr>,
) -> Option<SplitTunnelBypass> {
    if !ctx.config.split_tunnel.is_active() {
        return None;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let app_name = match peer_addr {
        Some(addr) => {
            let ip = addr.ip().to_canonical();
            let port = addr.port();
            match tokio::time::timeout(
                SPLIT_TUNNEL_RESOLVE_TIMEOUT,
                tokio::task::spawn_blocking(move || {
                    crate::split_tunnel::resolve_local_app(ip, port, false)
                }),
            )
            .await
            {
                Ok(res) => res.ok().flatten(),
                Err(_) => {
                    debug!(
                        %addr,
                        "split-tunnel: resolve_local_app timed out after {SPLIT_TUNNEL_RESOLVE_TIMEOUT:?}"
                    );
                    None
                }
            }
        }
        None => None,
    };
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let app_name: Option<String> = {
        let _ = peer_addr;
        None
    };

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let should_bypass = crate::split_tunnel::should_bypass_app_with_companions(
        &ctx.config.split_tunnel,
        app_name.as_deref(),
    );
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let should_bypass = ctx
        .config
        .split_tunnel
        .should_bypass_app(app_name.as_deref());

    if should_bypass {
        Some(SplitTunnelBypass { app_name })
    } else {
        None
    }
}

/// Convenience wrapper for [`check_split_tunnel_bypass`] that avoids calling
/// `client.peer_addr()` on the `SplitTunnelMode::All` fast path.
pub(crate) async fn check_split_tunnel_bypass_stream(
    ctx: &EngineContext,
    client: &TcpStream,
) -> Option<SplitTunnelBypass> {
    if !ctx.config.split_tunnel.is_active() {
        return None;
    }
    check_split_tunnel_bypass(ctx, client.peer_addr().ok()).await
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

/// Wraps an upstream stream to track `bytes_tx` / `bytes_rx` with batched `Relaxed` atomic
/// updates (flushed on 256 KiB batch threshold, EOF, error, shutdown, and drop — never on
/// `Poll::Pending` or sub-threshold `poll_flush`) and a zero-syscall activity flag so idle
/// connections can be reaped without per-chunk `Instant::now()` calls or cross-core cache-line
/// contention.
struct DirectCountingStream<'a, S> {
    inner: S,
    telemetry: &'a EngineTelemetry,
    active: &'a AtomicBool,
    pending_rx: u64,
    pending_tx: u64,
}

impl<'a, S> DirectCountingStream<'a, S> {
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

impl<S> Drop for DirectCountingStream<'_, S> {
    fn drop(&mut self) {
        self.flush_rx();
        self.flush_tx();
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DirectCountingStream<'_, S> {
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
                    if self.pending_rx >= DIRECT_TELEMETRY_BATCH_BYTES {
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

impl<S: AsyncWrite + Unpin> AsyncWrite for DirectCountingStream<'_, S> {
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
                if self.pending_tx >= DIRECT_TELEMETRY_BATCH_BYTES {
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
        if self.pending_tx >= DIRECT_TELEMETRY_BATCH_BYTES {
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

async fn relay_direct_bidirectional(
    client: &mut TcpStream,
    remote: TcpStream,
    telemetry: &EngineTelemetry,
) -> std::io::Result<(u64, u64)> {
    let active = AtomicBool::new(false);
    let mut counted = DirectCountingStream::new(remote, telemetry, &active);
    let idle_watcher = async {
        let mut last_active = Instant::now();
        let mut check_interval = tokio::time::interval(Duration::from_secs(15));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check_interval.tick().await;
        loop {
            check_interval.tick().await;
            if active.swap(false, Ordering::Relaxed) {
                last_active = Instant::now();
            } else if last_active.elapsed() >= DIRECT_IDLE_RELAY_TIMEOUT {
                break;
            }
        }
    };
    tokio::select! {
        biased;
        res = copy_bidirectional_with_sizes(
            client,
            &mut counted,
            DIRECT_RELAY_BUF_SIZE,
            DIRECT_RELAY_BUF_SIZE,
        ) => res,
        _ = idle_watcher => Ok((0, 0)),
    }
}

/// Plain direct bidirectional TCP relay without DPI ClientHello fragmentation or HTTP splitting.
pub(crate) async fn relay_direct_tunnel(
    ctx: &EngineContext,
    mut client: TcpStream,
    remote: TcpStream,
) -> Result<()> {
    let _ = client.set_nodelay(true);
    let _ = remote.set_nodelay(true);
    let _guard = ActiveConnGuard::enter(&ctx.telemetry);
    let _ = relay_direct_bidirectional(&mut client, remote, &ctx.telemetry).await?;
    Ok(())
}

/// Writes an already-buffered initial payload directly to `remote` without DPI desync,
/// drops the buffer, and enters a plain direct bidirectional TCP relay.
pub(crate) async fn relay_direct_with_initial(
    ctx: &EngineContext,
    mut client: TcpStream,
    mut remote: TcpStream,
    initial: Vec<u8>,
) -> Result<()> {
    let _ = client.set_nodelay(true);
    let _ = remote.set_nodelay(true);
    let _guard = ActiveConnGuard::enter(&ctx.telemetry);

    if !initial.is_empty() {
        remote.write_all(&initial).await?;
        ctx.telemetry
            .bytes_tx
            .fetch_add(initial.len() as u64, Ordering::Relaxed);
    }
    drop(initial);

    let _ = relay_direct_bidirectional(&mut client, remote, &ctx.telemetry).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn split_tunnel_all_mode_is_zero_cost_bypass_noop() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();
        assert!(!ctx.config.split_tunnel.is_active());
        assert!(check_split_tunnel_bypass(&ctx, None).await.is_none());
        let sample_peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        assert!(check_split_tunnel_bypass(&ctx, Some(sample_peer))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn direct_relay_forwards_payload_unmodified_and_updates_telemetry() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut got = Vec::new();
            sock.read_to_end(&mut got).await.unwrap();
            sock.write_all(b"direct-pong").await.unwrap();
            let _ = sock.shutdown().await;
            got
        });

        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front.local_addr().unwrap();
        let ctx_srv = ctx.clone();
        let relay_task = tokio::spawn(async move {
            let (client_sock, _) = front.accept().await.unwrap();
            let remote_sock = TcpStream::connect(upstream_addr).await.unwrap();
            relay_direct_with_initial(&ctx_srv, client_sock, remote_sock, b"hello-".to_vec()).await
        });

        let mut client = TcpStream::connect(front_addr).await.unwrap();
        client.write_all(b"world").await.unwrap();
        client.shutdown().await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        drop(client);

        let received = upstream_task.await.unwrap();
        relay_task.await.unwrap().unwrap();
        assert_eq!(received, b"hello-world");
        assert_eq!(resp, b"direct-pong");

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 1);
        assert_eq!(snap.tls_handshakes, 0);
        assert_eq!(snap.bytes_tx, b"hello-world".len() as u64);
        assert_eq!(snap.bytes_rx, b"direct-pong".len() as u64);
    }

    #[tokio::test]
    async fn direct_counting_stream_batches_to_256k_skips_pending_flush_and_flushes_on_drop() {
        assert_eq!(DIRECT_TELEMETRY_BATCH_BYTES, 256 * 1024);

        let telemetry = EngineTelemetry::default();
        let active = AtomicBool::new(false);
        let (mut peer, local) = tokio::io::duplex(64 * 1024);
        let mut counted = DirectCountingStream::new(local, &telemetry, &active);

        // Small write stays batched across poll_flush until threshold/shutdown/drop while setting active.
        let small = b"ping-frame";
        counted.write_all(small).await.unwrap();
        counted.flush().await.unwrap();
        assert!(active.load(Ordering::Relaxed));
        assert_eq!(telemetry.bytes_tx.load(Ordering::Relaxed), 0);

        // Small read followed by Poll::Pending must not flush pending_rx below 256 KiB.
        peer.write_all(b"pong").await.unwrap();
        let mut rx_buf = [0u8; 4];
        counted.read_exact(&mut rx_buf).await.unwrap();
        assert_eq!(&rx_buf, b"pong");
        assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 0);

        let pending_read = std::future::poll_fn(|cx| {
            let mut probe = [0u8; 16];
            let mut read_buf = ReadBuf::new(&mut probe);
            Poll::Ready(Pin::new(&mut counted).poll_read(cx, &mut read_buf))
        })
        .await;
        assert!(pending_read.is_pending());
        assert_eq!(telemetry.bytes_rx.load(Ordering::Relaxed), 0);

        // Crossing 256 KiB flushes live during streaming; a trailing small read stays buffered
        // until Drop.
        let total_extra = DIRECT_TELEMETRY_BATCH_BYTES as usize;
        let writer = tokio::spawn(async move {
            let chunk = vec![0xABu8; 32 * 1024];
            let mut remaining = total_extra;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                peer.write_all(&chunk[..n]).await.unwrap();
                remaining -= n;
            }
            peer
        });

        let mut received = 0usize;
        let mut tmp = vec![0u8; 32 * 1024];
        while received < total_extra {
            let n = counted.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            received += n;
        }
        let mut peer = writer.await.unwrap();
        peer.write_all(b"tail").await.unwrap();
        let mut tail = [0u8; 4];
        counted.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"tail");

        let mid_rx = telemetry.bytes_rx.load(Ordering::Relaxed);
        assert!(mid_rx >= DIRECT_TELEMETRY_BATCH_BYTES);
        assert!(mid_rx < (8 + total_extra) as u64);

        drop(counted);
        drop(peer);
        assert_eq!(
            telemetry.bytes_tx.load(Ordering::Relaxed),
            small.len() as u64
        );
        assert_eq!(
            telemetry.bytes_rx.load(Ordering::Relaxed),
            (8 + total_extra) as u64
        );

        // Poll::Pending on write backpressure must not flush pending_tx; Drop flushes it.
        let telemetry_w = EngineTelemetry::default();
        let active_w = AtomicBool::new(false);
        let (peer_w, local_w) = tokio::io::duplex(16);
        let mut counted_w = DirectCountingStream::new(local_w, &telemetry_w, &active_w);
        counted_w.write_all(&[0x5Au8; 16]).await.unwrap();
        assert!(active_w.load(Ordering::Relaxed));
        assert_eq!(telemetry_w.bytes_tx.load(Ordering::Relaxed), 0);

        let pending_write = std::future::poll_fn(|cx| {
            Poll::Ready(Pin::new(&mut counted_w).poll_write(cx, b"x"))
        })
        .await;
        assert!(pending_write.is_pending());
        assert_eq!(telemetry_w.bytes_tx.load(Ordering::Relaxed), 0);

        drop(counted_w);
        drop(peer_w);
        assert_eq!(telemetry_w.bytes_tx.load(Ordering::Relaxed), 16);

        // Chunked uploads with per-chunk poll_flush retain 256 KiB TX batching;
        // residuals flush on shutdown.
        let telemetry_tx = EngineTelemetry::default();
        let active_tx = AtomicBool::new(false);
        let (mut peer_tx, local_tx) = tokio::io::duplex(64 * 1024);
        let reader_tx = tokio::spawn(async move {
            let mut sink = Vec::new();
            peer_tx.read_to_end(&mut sink).await.unwrap();
            sink.len()
        });
        let mut counted_tx = DirectCountingStream::new(local_tx, &telemetry_tx, &active_tx);
        let chunk = vec![0xCDu8; 32 * 1024];
        for _ in 0..7 {
            counted_tx.write_all(&chunk).await.unwrap();
            counted_tx.flush().await.unwrap();
        }
        assert!(active_tx.load(Ordering::Relaxed));
        assert_eq!(telemetry_tx.bytes_tx.load(Ordering::Relaxed), 0);

        counted_tx.write_all(&chunk).await.unwrap();
        counted_tx.flush().await.unwrap();
        assert_eq!(
            telemetry_tx.bytes_tx.load(Ordering::Relaxed),
            DIRECT_TELEMETRY_BATCH_BYTES
        );

        counted_tx.write_all(b"end").await.unwrap();
        counted_tx.flush().await.unwrap();
        assert_eq!(
            telemetry_tx.bytes_tx.load(Ordering::Relaxed),
            DIRECT_TELEMETRY_BATCH_BYTES
        );

        counted_tx.shutdown().await.unwrap();
        assert_eq!(
            telemetry_tx.bytes_tx.load(Ordering::Relaxed),
            DIRECT_TELEMETRY_BATCH_BYTES + 3
        );
        drop(counted_tx);
        assert_eq!(
            reader_tx.await.unwrap(),
            DIRECT_TELEMETRY_BATCH_BYTES as usize + 3
        );
    }
}
