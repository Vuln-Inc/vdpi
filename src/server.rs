use crate::desync::EngineContext;
use crate::proxy::http::handle_http_client;
use crate::proxy::socks::{handle_socks4_client, handle_socks5_client};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, warn};

const PRIMARY_FALLBACK_PORTS: &[u16] = &[18080, 18081, 18082, 28080, 38080, 48080];
const SOCKS_FALLBACK_PORTS: &[u16] = &[11080, 11081, 11082, 21080, 31080, 41080];

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
    let (primary_listener, primary_addr) =
        bind_with_port_rotation(ctx.config.addr, ctx.config.port, PRIMARY_FALLBACK_PORTS, None)
            .with_context(|| {
                format!(
                    "failed to bind primary listener on {}:{}",
                    ctx.config.addr, ctx.config.port
                )
            })?;

    if ctx.config.port != 0 && primary_addr.port() != ctx.config.port {
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
                if sp != 0 && addr.port() != sp {
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
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::AddrInUse | ErrorKind::PermissionDenied
                ) =>
            {
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
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let primary_ctx = ctx.clone();
    let mut primary_stop = shutdown_rx.clone();

    let primary_loop = async move {
        loop {
            tokio::select! {
                _ = primary_stop.changed() => {
                    if *primary_stop.borrow() {
                        break;
                    }
                }
                accept_res = listeners.primary_listener.accept() => {
                    match accept_res {
                        Ok((stream, peer)) => {
                            let conn_ctx = primary_ctx.clone();
                            tokio::spawn(async move {
                                if let Err(e) = dispatch_autodetect(stream, conn_ctx).await {
                                    debug!(%peer, error = %e, "connection closed with error");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "accept error on primary listener");
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        }
                    }
                }
            }
        }
    };

    let socks_loop = async move {
        if let Some(socks_listener) = listeners.socks_listener {
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accept_res = socks_listener.accept() => {
                        match accept_res {
                            Ok((stream, peer)) => {
                                let conn_ctx = ctx.clone();
                                tokio::spawn(async move {
                                    if let Err(e) = dispatch_autodetect(stream, conn_ctx).await {
                                        debug!(%peer, error = %e, "SOCKS connection closed with error");
                                    }
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "accept error on SOCKS listener");
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            }
                        }
                    }
                }
            }
        } else {
            let _ = shutdown_rx.changed().await;
        }
    };

    tokio::join!(primary_loop, socks_loop);
    Ok(())
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
}
