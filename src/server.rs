use crate::desync::EngineContext;
use crate::proxy::http::handle_http_client;
use crate::proxy::socks::{handle_socks4_client, handle_socks5_client};
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, warn};

pub struct BoundListeners {
    pub primary_listener: TcpListener,
    pub primary_addr: SocketAddr,
    pub socks_listener: Option<TcpListener>,
    pub socks_addr: Option<SocketAddr>,
}

/// Binds the primary protocol-autodetecting listener (HTTP + HTTPS CONNECT + SOCKS5 + SOCKS4a)
/// and optional dedicated SOCKS5 listener with `SO_REUSEADDR`.
pub fn bind_listeners(ctx: &EngineContext) -> Result<BoundListeners> {
    let primary_target = SocketAddr::new(ctx.config.addr, ctx.config.port);
    let primary_listener = bind_reuse_tcp(primary_target)
        .with_context(|| format!("failed to bind primary listener on {primary_target}"))?;
    let primary_addr = primary_listener.local_addr()?;

    let mut socks_listener = None;
    let mut socks_addr = None;

    if let Some(sp) = ctx.config.socks_port {
        let socks_target = SocketAddr::new(ctx.config.addr, sp);
        match bind_reuse_tcp(socks_target) {
            Ok(listener) => {
                socks_addr = Some(listener.local_addr()?);
                socks_listener = Some(listener);
            }
            Err(e) => {
                warn!(
                    addr = %socks_target,
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

fn bind_reuse_tcp(addr: SocketAddr) -> Result<TcpListener> {
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
    Ok(TcpListener::from_std(std_listener)?)
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
