pub mod http;
pub mod socks;

use crate::desync::{EngineContext, EngineTelemetry};
use anyhow::Result;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(any(target_os = "android", target_os = "ios"))]
const DIRECT_RELAY_BUF_SIZE: usize = 16 * 1024;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
const DIRECT_RELAY_BUF_SIZE: usize = 128 * 1024;

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

/// Evaluates per-app split-tunnel policy for an accepted proxy TCP client.
///
/// Fast path: returns `None` immediately with zero syscalls when
/// `ctx.config.split_tunnel.is_active()` is `false` (`SplitTunnelMode::All`).
pub(crate) fn check_split_tunnel_bypass(
    ctx: &EngineContext,
    peer_addr: Option<SocketAddr>,
) -> Option<SplitTunnelBypass> {
    if !ctx.config.split_tunnel.is_active() {
        return None;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let app_name = peer_addr.and_then(|addr| {
        crate::split_tunnel::resolve_local_app(addr.ip().to_canonical(), addr.port(), false)
    });
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let app_name: Option<String> = {
        let _ = peer_addr;
        None
    };

    if ctx
        .config
        .split_tunnel
        .should_bypass_app(app_name.as_deref())
    {
        Some(SplitTunnelBypass { app_name })
    } else {
        None
    }
}

/// Convenience wrapper for [`check_split_tunnel_bypass`] that avoids calling
/// `client.peer_addr()` on the `SplitTunnelMode::All` fast path.
pub(crate) fn check_split_tunnel_bypass_stream(
    ctx: &EngineContext,
    client: &TcpStream,
) -> Option<SplitTunnelBypass> {
    if !ctx.config.split_tunnel.is_active() {
        return None;
    }
    check_split_tunnel_bypass(ctx, client.peer_addr().ok())
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

struct DirectCountingStream {
    inner: TcpStream,
    telemetry: Arc<EngineTelemetry>,
    started: Instant,
    last_activity_ms: Arc<AtomicU64>,
}

impl DirectCountingStream {
    fn new(
        inner: TcpStream,
        telemetry: Arc<EngineTelemetry>,
        started: Instant,
        last_activity_ms: Arc<AtomicU64>,
    ) -> Self {
        Self {
            inner,
            telemetry,
            started,
            last_activity_ms,
        }
    }

    fn touch_activity(&self) {
        let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_activity_ms.store(elapsed, Ordering::Relaxed);
    }
}

impl AsyncRead for DirectCountingStream {
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
                self.touch_activity();
                self.telemetry
                    .bytes_rx
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        poll
    }
}

impl AsyncWrite for DirectCountingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                self.touch_activity();
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

async fn relay_direct_bidirectional(
    client: &mut TcpStream,
    remote: TcpStream,
    telemetry: &Arc<EngineTelemetry>,
) -> std::io::Result<(u64, u64)> {
    let started = Instant::now();
    let last_activity_ms = Arc::new(AtomicU64::new(0));
    let mut counted = DirectCountingStream::new(
        remote,
        Arc::clone(telemetry),
        started,
        Arc::clone(&last_activity_ms),
    );
    let idle_watcher = async {
        let timeout_ms = u64::try_from(DIRECT_IDLE_RELAY_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
        let mut check_interval = tokio::time::interval(Duration::from_secs(15));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        check_interval.tick().await;
        loop {
            check_interval.tick().await;
            let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            let last_ms = last_activity_ms.load(Ordering::Relaxed);
            if now_ms.saturating_sub(last_ms) >= timeout_ms {
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

    #[test]
    fn split_tunnel_all_mode_is_zero_cost_bypass_noop() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();
        assert!(!ctx.config.split_tunnel.is_active());
        assert!(check_split_tunnel_bypass(&ctx, None).is_none());
        let sample_peer: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        assert!(check_split_tunnel_bypass(&ctx, Some(sample_peer)).is_none());
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
}
