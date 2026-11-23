use crate::desync::EngineContext;
use crate::proxy::http::handle_http_client;
use crate::proxy::socks::{handle_socks4_client, handle_socks5_client};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

pub const REPOSITORY_URL: &str = "https://github.com/Vuln-Inc/vdpi";
const PRIMARY_FALLBACK_PORTS: &[u16] = &[18080, 18081, 18082, 28080, 38080, 48080];
const SOCKS_FALLBACK_PORTS: &[u16] = &[11080, 11081, 11082, 21080, 31080, 41080];
const MAX_CLIENT_SESSIONS: usize = 256;

pub struct BoundListeners {
    pub primary_listener: TcpListener,
    pub primary_addr: SocketAddr,
    pub socks_listener: Option<TcpListener>,
    pub socks_addr: Option<SocketAddr>,
}

/// Binds the primary protocol-autodetecting listener (HTTP + HTTPS CONNECT + SOCKS5 + SOCKS4a)
/// and optional dedicated SOCKS5 listener, automatically rotating to a free port if the
/// requested port is already in use or reserved (e.g. Windows Hyper-V/WSL2 excluded ranges).
pub fn bind_listeners(ctx: &EngineContext) -> Result<BoundListeners> {
    let (primary_listener, primary_addr) = bind_with_port_rotation(
        ctx.config.addr,
        ctx.config.port,
        PRIMARY_FALLBACK_PORTS,
        None,
    )
    .with_context(|| {
        format!(
            "failed to bind primary listener on {}:{}",
            ctx.config.addr, ctx.config.port
        )
    })?;

    if ctx.config.port == 0 {
        debug!(
            actual = primary_addr.port(),
            addr = %primary_addr,
            "bound primary listener on ephemeral port"
        );
    } else if primary_addr.port() != ctx.config.port {
        warn!(
            requested = ctx.config.port,
            actual = primary_addr.port(),
            "primary port unavailable; automatically rotated to {}",
            primary_addr
        );
    }

    let mut socks_listener = None;
    let mut socks_addr = None;

    if let Some(sp) = ctx.config.socks_port {
        match bind_with_port_rotation(
            ctx.config.addr,
            sp,
            SOCKS_FALLBACK_PORTS,
            Some(primary_addr.port()),
        ) {
            Ok((listener, addr)) => {
                if sp == 0 {
                    debug!(
                        actual = addr.port(),
                        addr = %addr,
                        "bound SOCKS5 listener on ephemeral port"
                    );
                } else if addr.port() != sp {
                    warn!(
                        requested = sp,
                        actual = addr.port(),
                        "SOCKS5 port unavailable; automatically rotated to {}",
                        addr
                    );
                }
                socks_addr = Some(addr);
                socks_listener = Some(listener);
            }
            Err(e) => {
                warn!(
                    addr = %SocketAddr::new(ctx.config.addr, sp),
                    error = %e,
                    "could not bind dedicated SOCKS5 port; SOCKS5 remains available via protocol auto-detection on primary port"
                );
            }
        }
    }

    Ok(BoundListeners {
        primary_listener,
        primary_addr,
        socks_listener,
        socks_addr,
    })
}

fn bind_with_port_rotation(
    ip: IpAddr,
    requested_port: u16,
    extra_fallbacks: &[u16],
    exclude_port: Option<u16>,
) -> std::io::Result<(TcpListener, SocketAddr)> {
    if requested_port == 0 {
        let listener = bind_reuse_tcp(SocketAddr::new(ip, 0))?;
        let addr = listener.local_addr()?;
        return Ok((listener, addr));
    }

    let mut candidates = Vec::with_capacity(28);
    candidates.push(requested_port);
    for delta in 1u16..=20 {
        if let Some(p) = requested_port.checked_add(delta) {
            if p != 0 && !candidates.contains(&p) {
                candidates.push(p);
            }
        }
    }
    for &p in extra_fallbacks {
        if p != 0 && !candidates.contains(&p) {
            candidates.push(p);
        }
    }
    // Ultimate OS-assigned free port fallback so vdpi never crashes on port exhaustion.
    candidates.push(0);

    let mut last_err = None;
    for port in candidates {
        if port != 0 && exclude_port == Some(port) {
            continue;
        }
        match bind_reuse_tcp(SocketAddr::new(ip, port)) {
            Ok(listener) => {
                let bound_addr = listener.local_addr()?;
                return Ok((listener, bound_addr));
            }
            Err(e) if matches!(e.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied) => {
                debug!(%ip, port, error = %e, "port busy or reserved; trying next port");
                last_err = Some(e);
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(ErrorKind::AddrInUse, "all candidate ports unavailable")
    }))
}

fn bind_reuse_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(not(windows))]
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// Runs the bound proxy listeners until `shutdown_rx` signals `true`.
pub async fn serve_until_shutdown(
    listeners: BoundListeners,
    ctx: EngineContext,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if !ctx.config.quiet {
        let primary = listeners
            .primary_listener
            .local_addr()
            .unwrap_or(listeners.primary_addr);
        info!(
            version = env!("CARGO_PKG_VERSION"),
            source = REPOSITORY_URL,
            primary = %primary,
            "vdpi proxy listening"
        );
    }
    serve_with_limit(listeners, ctx, shutdown_rx, MAX_CLIENT_SESSIONS).await;
    Ok(())
}

async fn serve_with_limit(
    listeners: BoundListeners,
    mut ctx: EngineContext,
    shutdown_rx: watch::Receiver<bool>,
    limit: usize,
) {
    let primary_addr = listeners
        .primary_listener
        .local_addr()
        .unwrap_or(listeners.primary_addr);
    let socks_addr = listeners
        .socks_listener
        .as_ref()
        .and_then(|listener| listener.local_addr().ok())
        .or(listeners.socks_addr);
    ctx.listener_addrs = [
        Some(primary_addr),
        socks_addr,
        ipv4_companion(&listeners.primary_listener, primary_addr),
        listeners
            .socks_listener
            .as_ref()
            .zip(socks_addr)
            .and_then(|(listener, addr)| ipv4_companion(listener, addr)),
    ];
    let slots = Arc::new(Semaphore::new(limit));
    let primary_loop = serve_listener(
        listeners.primary_listener,
        ctx.clone(),
        shutdown_rx.clone(),
        slots.clone(),
    );
    let socks_loop = async move {
        if let Some(listener) = listeners.socks_listener {
            serve_listener(listener, ctx, shutdown_rx, slots).await;
        }
    };
    tokio::join!(primary_loop, socks_loop);
}

fn ipv4_companion(listener: &TcpListener, addr: SocketAddr) -> Option<SocketAddr> {
    (addr.is_ipv6()
        && addr.ip().is_unspecified()
        && SockRef::from(listener)
            .only_v6()
            .is_ok_and(|only_v6| !only_v6))
    .then(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, addr.port())))
}

async fn serve_listener(
    listener: TcpListener,
    ctx: EngineContext,
    mut stop: watch::Receiver<bool>,
    slots: Arc<Semaphore>,
) {
    let mut sessions = JoinSet::new();
    let shutdown = async { drop(stop.wait_for(|stopped| *stopped).await) };
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = sessions.join_next() => {
                if let Err(e) = result {
                    warn!(error = %e, "client session task failed");
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        // Close excess sockets rather than queueing unbounded client tasks.
                        let Ok(slot) = slots.clone().try_acquire_owned() else {
                            continue;
                        };
                        let conn_ctx = ctx.clone();
                        sessions.spawn(async move {
                            let _slot = slot;
                            if let Err(e) = dispatch_autodetect(stream, conn_ctx).await {
                                debug!(%peer, error = %e, "connection closed with error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "proxy listener accept error");
                        tokio::select! {
                            _ = &mut shutdown => break,
                            _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                        }
                    }
                }
            }
        }
    }
    drop(listener);
    sessions.shutdown().await;
}

/// Peeks the first byte of an incoming TCP stream to automatically route SOCKS5 (`0x05`),
/// SOCKS4/4a (`0x04`), or HTTP/1.x (`CONNECT` / forward proxy).
pub async fn dispatch_autodetect(stream: TcpStream, ctx: EngineContext) -> Result<()> {
    let mut first = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(15), stream.peek(&mut first)).await??;
    if n == 0 {
        return Ok(());
    }

    match first[0] {
        0x05 => handle_socks5_client(stream, ctx).await,
        0x04 => handle_socks4_client(stream, ctx).await,
        _ => handle_http_client(stream, ctx).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn test_context(addr: &str) -> EngineContext {
        let mut config =
            CliArgs::parse_from_iter(["vdpi", "--addr", addr, "--port", "0", "--no-system-proxy"])
                .unwrap()
                .into_runtime_config();
        config.socks_port = Some(0);
        EngineContext::new(config).unwrap()
    }

    #[tokio::test]
    async fn both_listeners_share_capacity_and_shutdown_closes_active_sessions() {
        timeout(TEST_TIMEOUT, async {
            let ctx = test_context("127.0.0.1");
            let bound = bind_listeners(&ctx).unwrap();
            let primary = bound.primary_addr;
            let socks = bound.socks_addr.unwrap();
            let (stop, rx) = watch::channel(false);
            let server = tokio::spawn(serve_with_limit(bound, ctx, rx, 1));

            let mut active = TcpStream::connect(primary).await.unwrap();
            active.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0; 2];
            active.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);

            let mut overflow = TcpStream::connect(socks).await.unwrap();
            assert!(matches!(overflow.read(&mut reply).await, Ok(0)));
            drop(active);

            // Permit release can race the next accept; wait for the other listener to serve.
            let mut active = loop {
                let mut stream = TcpStream::connect(socks).await.unwrap();
                if stream.write_all(&[5, 1, 0]).await.is_ok()
                    && stream.read_exact(&mut reply).await.is_ok()
                {
                    assert_eq!(reply, [5, 0]);
                    break stream;
                }
                tokio::task::yield_now().await;
            };

            drop(stop);
            server.await.unwrap();
            assert_eq!(active.read(&mut reply).await.unwrap(), 0);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rejects_connects_to_both_listeners_including_wildcard_binds() {
        timeout(TEST_TIMEOUT, async {
            for ip in ["127.0.0.1", "0.0.0.0"] {
                let ctx = test_context(ip);
                let bound = bind_listeners(&ctx).unwrap();
                let primary = SocketAddr::from((Ipv4Addr::LOCALHOST, bound.primary_addr.port()));
                let socks =
                    SocketAddr::from((Ipv4Addr::LOCALHOST, bound.socks_addr.unwrap().port()));
                let (stop, rx) = watch::channel(false);
                let server = tokio::spawn(serve_until_shutdown(bound, ctx, rx));

                for target in [primary, socks] {
                    let mut stream = TcpStream::connect(primary).await.unwrap();
                    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
                    stream.write_all(request.as_bytes()).await.unwrap();
                    let mut response = Vec::new();
                    stream.read_to_end(&mut response).await.unwrap();
                    assert!(response.starts_with(b"HTTP/1.1 502 "));
                }

                stop.send(true).unwrap();
                server.await.unwrap().unwrap();
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn automatically_rotates_primary_and_socks_ports_when_busy() {
        let occupied_primary = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p0 = occupied_primary.local_addr().unwrap().port();
        let occupied_socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s0 = occupied_socks.local_addr().unwrap().port();

        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--port",
            &p0.to_string(),
            "--socks-port",
            &s0.to_string(),
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let bound = bind_listeners(&ctx).expect("should rotate past occupied ports");
        assert_ne!(bound.primary_addr.port(), p0);
        let socks_port = bound
            .socks_addr
            .expect("should also rotate dedicated SOCKS5 port")
            .port();
        assert_ne!(socks_port, s0);
        assert_ne!(socks_port, bound.primary_addr.port());
    }

    #[tokio::test]
    async fn ephemeral_port_zero_uses_os_assigned_ports_and_guards_self_loops() {
        timeout(TEST_TIMEOUT, async {
            let ctx = test_context("127.0.0.1");
            let mut bound = bind_listeners(&ctx).unwrap();
            let actual_primary = bound.primary_listener.local_addr().unwrap();
            let actual_socks = bound
                .socks_listener
                .as_ref()
                .unwrap()
                .local_addr()
                .unwrap();

            assert_ne!(actual_primary.port(), 0);
            assert_eq!(bound.primary_addr, actual_primary);
            assert_ne!(actual_socks.port(), 0);
            assert_eq!(bound.socks_addr, Some(actual_socks));

            // Even if BoundListeners carries a stale 0 port, serve_with_limit must populate
            // listener_addrs from the live listener's local_addr() so self-loops are blocked.
            bound.primary_addr.set_port(0);
            let (stop, rx) = watch::channel(false);
            let server = tokio::spawn(serve_until_shutdown(bound, ctx, rx));

            let mut stream = TcpStream::connect(actual_primary).await.unwrap();
            let crlf = "\x0d\x0a";
            let request = format!(
                "CONNECT {actual_primary} HTTP/1.1{crlf}Host: {actual_primary}{crlf}{crlf}"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 502 "));

            stop.send(true).unwrap();
            server.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }
}
