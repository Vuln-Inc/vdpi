use super::{
    check_split_tunnel_bypass_stream, is_forbidden_proxy_host, is_forbidden_remote_addr,
    relay_direct_tunnel, HANDSHAKE_TIMEOUT,
};
use crate::desync::EngineContext;
use anyhow::{anyhow, bail, Result};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;
use vdpi_core::binder::OutboundBinder;
use vdpi_core::bypass::BypassPolicy;

const SOCKS5_VER: u8 = 0x05;
const SOCKS4_VER: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

enum CheckedConnectError {
    Forbidden(SocketAddr),
    Connect(anyhow::Error),
}

/// Validates resolved IP candidates against SSRF and self-reflection rules BEFORE TCP `connect()`.
fn validate_resolved_connect_targets(
    ips: &[IpAddr],
    port: u16,
    is_loopback_peer: bool,
    local_addr: Option<SocketAddr>,
) -> std::result::Result<Vec<SocketAddr>, SocketAddr> {
    let mut targets = Vec::with_capacity(ips.len());
    for &ip in ips {
        let target = SocketAddr::new(normalize_ip(ip), port);
        if is_forbidden_remote_addr(is_loopback_peer, target, local_addr) {
            return Err(target);
        }
        targets.push(target);
    }
    Ok(targets)
}

async fn connect_target_checked(
    ctx: &EngineContext,
    host: &str,
    port: u16,
    is_loopback_peer: bool,
    local_addr: Option<SocketAddr>,
) -> std::result::Result<(TcpStream, SocketAddr), CheckedConnectError> {
    if is_loopback_peer {
        let (remote, remote_addr) = ctx
            .connect_target(host, port)
            .await
            .map_err(CheckedConnectError::Connect)?;
        if is_forbidden_remote_addr(true, remote_addr, local_addr) {
            drop(remote);
            return Err(CheckedConnectError::Forbidden(remote_addr));
        }
        return Ok((remote, remote_addr));
    }

    // For non-loopback peers, resolve first and verify every resolved candidate BEFORE
    // issuing any TCP connect(), preventing internal port-scanning and DNS-rebinding TOCTOU.
    let ips = ctx.dns.resolve(host).await.map_err(|e| {
        CheckedConnectError::Connect(anyhow!("DNS resolution failed for {host}: {e}"))
    })?;
    if ips.is_empty() {
        return Err(CheckedConnectError::Connect(anyhow!(
            "no addresses returned for {host}"
        )));
    }

    let targets = validate_resolved_connect_targets(&ips, port, false, local_addr)
        .map_err(CheckedConnectError::Forbidden)?;

    let total = targets.len();
    let mut last_err = None;
    for (idx, target) in targets.into_iter().enumerate() {
        let attempt_timeout = if idx + 1 < total {
            ctx.config.connect_timeout.min(Duration::from_secs(3))
        } else {
            ctx.config.connect_timeout
        };
        match tokio::time::timeout(attempt_timeout, ctx.connect_upstream_addr(target)).await {
            Ok(Ok(stream)) => return Ok((stream, target)),
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => {
                last_err = Some(anyhow!(
                    "connect {target} timed out after {attempt_timeout:?}"
                ));
            }
        }
    }

    Err(CheckedConnectError::Connect(last_err.unwrap_or_else(|| {
        anyhow!("failed to connect to {host}:{port}")
    })))
}

/// Handles a SOCKS5 (`CONNECT` and `UDP ASSOCIATE`) client connection.
pub async fn handle_socks5_client(mut client: TcpStream, ctx: EngineContext) -> Result<()> {
    let _ = client.set_nodelay(true);

    let (cmd, (target_host, known_domain, target_port)) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, read_socks5_request(&mut client)).await??;

    let peer_addr = client.peer_addr().ok();
    let is_loopback_peer = peer_addr.is_some_and(|p| p.ip().to_canonical().is_loopback());
    let local_addr = client.local_addr().ok();

    match cmd {
        CMD_CONNECT => {
            if is_forbidden_proxy_host(is_loopback_peer, &target_host, target_port, local_addr) {
                let reply = encode_socks5_reply(
                    0x02,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                );
                let _ = client.write_all(&reply).await;
                bail!("forbidden SOCKS5 CONNECT target '{target_host}:{target_port}'");
            }
            let split_bypass = check_split_tunnel_bypass_stream(&ctx, &client).await;
            debug!(host = %target_host, port = target_port, "SOCKS5 CONNECT");
            match connect_target_checked(
                &ctx,
                &target_host,
                target_port,
                is_loopback_peer,
                local_addr,
            )
            .await
            {
                Ok((remote, remote_addr)) => {
                    let reply = encode_socks5_reply(
                        0x00,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    client.write_all(&reply).await?;
                    client.flush().await?;
                    if let Some(bypass) = split_bypass {
                        bypass.log_bypass(&target_host);
                        return relay_direct_tunnel(&ctx, client, remote).await;
                    }
                    ctx.relay_tunnel(client, remote, known_domain.as_deref(), remote_addr)
                        .await
                }
                Err(CheckedConnectError::Forbidden(remote_addr)) => {
                    let reply = encode_socks5_reply(
                        0x02,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    let _ = client.write_all(&reply).await;
                    bail!("forbidden resolved SOCKS5 CONNECT target '{remote_addr}'");
                }
                Err(CheckedConnectError::Connect(e)) => {
                    debug!(host = %target_host, port = target_port, error = %e, "SOCKS5 CONNECT failed");
                    let reply = encode_socks5_reply(
                        0x04,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    let _ = client.write_all(&reply).await;
                    Err(e)
                }
            }
        }
        CMD_UDP_ASSOCIATE => {
            let split_bypass = check_split_tunnel_bypass_stream(&ctx, &client).await;
            let client_pin =
                UdpClientPin::from_request(peer_addr.map(|p| p.ip()), &target_host, target_port);
            let bind_ip = local_addr
                .map(|a| normalize_ip(a.ip()))
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let client_udp = match bind_socks_udp_socket(SocketAddr::new(bind_ip, 0), None, false) {
                Ok(sock) => Arc::new(sock),
                Err(err) => {
                    let rep = socks5_bind_error_reply_code(&err);
                    let reply = encode_socks5_reply(
                        rep,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    let _ = client.write_all(&reply).await;
                    let _ = client.flush().await;
                    let _ = client.shutdown().await;
                    return Err(err.into());
                }
            };
            let relay_local_addr = match client_udp.local_addr() {
                Ok(addr) => addr,
                Err(err) => {
                    let rep = socks5_bind_error_reply_code(&err);
                    let reply = encode_socks5_reply(
                        rep,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    let _ = client.write_all(&reply).await;
                    let _ = client.flush().await;
                    let _ = client.shutdown().await;
                    return Err(err.into());
                }
            };
            let (outbound_v4, outbound_v6) =
                match bind_outbound_udp_sockets(ctx.outbound_binder.as_deref()) {
                    Ok(pair) => pair,
                    Err(err) => {
                        let rep = socks5_bind_error_reply_code(&err);
                        let reply = encode_socks5_reply(
                            rep,
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                        );
                        let _ = client.write_all(&reply).await;
                        let _ = client.flush().await;
                        let _ = client.shutdown().await;
                        return Err(err.into());
                    }
                };

            debug!(relay_addr = %relay_local_addr, "SOCKS5 UDP ASSOCIATE established");
            let reply = encode_socks5_reply(0x00, relay_local_addr);
            client.write_all(&reply).await?;
            client.flush().await?;

            let split_bypassed = if let Some(bypass) = split_bypass {
                bypass.log_bypass("udp-associate");
                true
            } else {
                false
            };

            run_udp_associate_session(
                client,
                client_udp,
                outbound_v4,
                outbound_v6,
                ctx,
                split_bypassed,
                client_pin,
            )
            .await
        }
        other => {
            let reply =
                encode_socks5_reply(0x07, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            let _ = client.write_all(&reply).await;
            bail!("unsupported SOCKS5 command 0x{other:02x}");
        }
    }
}

async fn read_socks5_request(
    client: &mut TcpStream,
) -> Result<(u8, (String, Option<String>, u16))> {
    let mut hdr = [0u8; 2];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS5_VER {
        bail!("unexpected SOCKS5 version {}", hdr[0]);
    }
    let mut methods = [0u8; 255];
    let methods = &mut methods[..usize::from(hdr[1])];
    client.read_exact(methods).await?;
    if !methods.contains(&0x00) {
        let _ = client.write_all(&[SOCKS5_VER, 0xff]).await;
        bail!("SOCKS5 client did not offer NO AUTH (0x00)");
    }
    client.write_all(&[SOCKS5_VER, 0x00]).await?;
    client.flush().await?;

    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr).await?;
    if req_hdr[0] != SOCKS5_VER {
        bail!("invalid SOCKS5 request version {}", req_hdr[0]);
    }
    Ok((req_hdr[1], read_socks5_addr(client, req_hdr[3]).await?))
}

/// Handles a SOCKS4 / SOCKS4a `CONNECT` client connection.
pub async fn handle_socks4_client(mut client: TcpStream, ctx: EngineContext) -> Result<()> {
    let _ = client.set_nodelay(true);
    let (host, known_domain, port) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, read_socks4_request(&mut client)).await??;

    let peer_addr = client.peer_addr().ok();
    let is_loopback_peer = peer_addr.is_some_and(|p| p.ip().to_canonical().is_loopback());
    let local_addr = client.local_addr().ok();

    if is_forbidden_proxy_host(is_loopback_peer, &host, port, local_addr) {
        let _ = client.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
        bail!("forbidden SOCKS4 target '{host}:{port}'");
    }

    let split_bypass = check_split_tunnel_bypass_stream(&ctx, &client).await;
    debug!(host = %host, port = port, "SOCKS4/4a CONNECT");
    match connect_target_checked(&ctx, &host, port, is_loopback_peer, local_addr).await {
        Ok((remote, remote_addr)) => {
            client.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
            client.flush().await?;
            if let Some(bypass) = split_bypass {
                bypass.log_bypass(&host);
                return relay_direct_tunnel(&ctx, client, remote).await;
            }
            ctx.relay_tunnel(client, remote, known_domain.as_deref(), remote_addr)
                .await
        }
        Err(CheckedConnectError::Forbidden(remote_addr)) => {
            let _ = client.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            bail!("forbidden resolved SOCKS4 target '{remote_addr}'");
        }
        Err(CheckedConnectError::Connect(e)) => {
            let _ = client.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            Err(e)
        }
    }
}

async fn read_socks4_request(client: &mut TcpStream) -> Result<(String, Option<String>, u16)> {
    let mut hdr = [0u8; 8];
    client.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS4_VER || hdr[1] != CMD_CONNECT {
        let _ = client.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
        bail!("unsupported SOCKS4 header");
    }

    let port = u16::from_be_bytes([hdr[2], hdr[3]]);
    let ip = Ipv4Addr::new(hdr[4], hdr[5], hdr[6], hdr[7]);

    // Read null-terminated USERID
    read_cstring(client, 256).await?;

    // SOCKS4a: 0.0.0.x (x != 0) carries null-terminated domain after USERID
    let (host, known_domain) = if hdr[4] == 0 && hdr[5] == 0 && hdr[6] == 0 && hdr[7] != 0 {
        let domain = read_cstring(client, 512).await?;
        (domain.clone(), Some(domain))
    } else {
        (ip.to_string(), None)
    };

    Ok((host, known_domain, port))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(windows)]
fn set_exclusive_addr_use(sock: &Socket) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };

    let enable: i32 = 1;
    // SAFETY: `sock` owns a valid WinSock handle, and `enable` is a valid 4-byte BOOL option value.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enable as *const i32).cast::<u8>(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    Ok(())
}

#[cfg(windows)]
fn disable_udp_connreset(sock: &Socket) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawSocket;

    const SIO_UDP_CONNRESET: u32 = 0x9800_000C;

    #[link(name = "ws2_32")]
    extern "system" {
        fn WSAIoctl(
            s: usize,
            dw_io_control_code: u32,
            lpv_in_buffer: *const c_void,
            cb_in_buffer: u32,
            lpv_out_buffer: *mut c_void,
            cb_out_buffer: u32,
            lpcb_bytes_returned: *mut u32,
            lp_overlapped: *mut c_void,
            lp_completion_routine: *const c_void,
        ) -> i32;
    }

    let enable: i32 = 0; // BOOL FALSE
    let mut bytes_returned: u32 = 0;
    unsafe {
        let _ = WSAIoctl(
            sock.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&enable as *const i32).cast::<c_void>(),
            std::mem::size_of::<i32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null(),
        );
    }
}

const STUN_MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const RAKNET_OFFLINE_MAGIC: [u8; 16] = [
    0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
];
const MAX_STUN_FLOWS: usize = 256;
const STUN_FLOW_TTL: Duration = Duration::from_secs(120);
const STUN_FLOW_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_ALLOWED_UDP_DESTS: usize = 1024;
const ALLOWED_UDP_DEST_TTL: Duration = Duration::from_secs(300);
const ALLOWED_UDP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const UDP_SOCKET_BUF_BYTES: usize = 256 * 1024;

fn socks5_bind_error_reply_code(err: &std::io::Error) -> u8 {
    if err.kind() == ErrorKind::PermissionDenied {
        0x02
    } else {
        0x01
    }
}

type BoundUdpSockets = (Option<Arc<UdpSocket>>, Option<Arc<UdpSocket>>);

/// Binds IPv4 and IPv6 outbound UDP relay sockets before acknowledging `UDP ASSOCIATE`.
/// Succeeds as long as at least one address family binds cleanly; only returns `Err` when
/// both IPv4 and IPv6 fail to bind.
fn bind_outbound_udp_sockets(
    outbound_binder: Option<&dyn OutboundBinder>,
) -> std::io::Result<BoundUdpSockets> {
    let v4_res = bind_socks_udp_socket(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        outbound_binder,
        false,
    );
    let v6_res = bind_socks_udp_socket(
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        outbound_binder,
        true,
    );
    match (v4_res, v6_res) {
        (Ok(v4), Ok(v6)) => Ok((Some(Arc::new(v4)), Some(Arc::new(v6)))),
        (Ok(v4), Err(_)) => Ok((Some(Arc::new(v4)), None)),
        (Err(_), Ok(v6)) => Ok((None, Some(Arc::new(v6)))),
        (Err(e4), Err(_)) => Err(e4),
    }
}

/// Binds a SOCKS5 UDP socket with Windows `SO_EXCLUSIVEADDRUSE` + `SIO_UDP_CONNRESET`
/// disabled, 256 KiB send/receive buffers, and optional `OutboundBinder` routing.
fn bind_socks_udp_socket(
    bind_addr: SocketAddr,
    outbound_binder: Option<&dyn OutboundBinder>,
    only_v6: bool,
) -> std::io::Result<UdpSocket> {
    let domain = if bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if only_v6 && bind_addr.is_ipv6() {
        let _ = sock.set_only_v6(true);
    }
    #[cfg(windows)]
    set_exclusive_addr_use(&sock)?;
    if let Some(binder) = outbound_binder {
        binder.bind_socket(SockRef::from(&sock), bind_addr.is_ipv4())?;
    }
    #[cfg(windows)]
    disable_udp_connreset(&sock);
    let _ = sock.set_recv_buffer_size(UDP_SOCKET_BUF_BYTES);
    let _ = sock.set_send_buffer_size(UDP_SOCKET_BUF_BYTES);
    sock.bind(&bind_addr.into())?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

/// Returns `true` if `payload` matches an RFC 5389 STUN header:
/// first 2 bits zero, minimum length 20 bytes, magic cookie `0x2112A442` at bytes `4..8`.
fn is_stun_packet(payload: &[u8]) -> bool {
    payload.len() >= 20 && (payload[0] & 0xC0) == 0 && payload[4..8] == STUN_MAGIC_COOKIE
}

/// Returns `true` if `payload` matches a DTLS 1.0/1.2/1.3 plaintext record header
/// (`ContentType` in `0x14..=0x1a`, including RFC 9147 ACK `0x1a`, and version
/// `0xfe 0xfd`..=`0xfe 0xff`, minimum 13-byte header).
fn is_dtls_packet(payload: &[u8]) -> bool {
    payload.len() >= 13
        && matches!(payload[0], 0x14..=0x1a)
        && payload[1] == 0xfe
        && matches!(payload[2], 0xfd..=0xff)
}

/// Returns `true` if `payload` matches an RFC 9147 §4.2.3 DTLS 1.3 unified-header
/// `DTLSCiphertext` packet (`(payload[0] & 0xe0) == 0x20` and minimum length 13 bytes).
fn is_dtls13_ciphertext_packet(payload: &[u8]) -> bool {
    payload.len() >= 13 && (payload[0] & 0xe0) == 0x20
}

/// Returns `true` if `payload` matches an RFC 3550 / RFC 5764 SRTP/SRTCP packet
/// (`V=2`, top 2 bits `10`, minimum 12-byte header).
fn is_srtp_or_srtcp_packet(payload: &[u8]) -> bool {
    payload.len() >= 12 && (payload[0] & 0xc0) == 0x80
}

/// Returns `true` if `payload` contains the 16-byte RakNet offline magic sequence
/// (`00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`) used by game transports on UDP/443.
fn is_raknet_offline_packet(payload: &[u8]) -> bool {
    payload.len() >= RAKNET_OFFLINE_MAGIC.len()
        && payload[..payload.len().min(64)]
            .windows(RAKNET_OFFLINE_MAGIC.len())
            .any(|w| w == RAKNET_OFFLINE_MAGIC)
}

/// Returns `true` for transient per-peer UDP receive errors that must not terminate
/// an active SOCKS5 UDP ASSOCIATE session.
fn is_transient_udp_recv_error(err: &std::io::Error) -> bool {
    if matches!(
        err.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionRefused
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
    ) {
        return true;
    }
    #[cfg(windows)]
    if matches!(err.raw_os_error(), Some(10051 | 10052 | 10054 | 10065)) {
        return true;
    }
    // Windows WSAEMSGSIZE (10040): datagram larger than recv buffer; drop datagram and continue.
    err.raw_os_error() == Some(10040)
}

/// Returns `true` when an outbound UDP `send_to` error indicates an unreachable route/host
/// (e.g. IPv6 socket bound on a host without an IPv6 default route).
fn is_udp_unreachable_error(err: &std::io::Error) -> bool {
    let kind_unreachable = matches!(
        err.kind(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable
    );
    #[cfg(windows)]
    {
        kind_unreachable || matches!(err.raw_os_error(), Some(10049 | 10051 | 10065))
    }
    #[cfg(not(windows))]
    {
        kind_unreachable
    }
}

fn select_udp_targets(
    ips: &[IpAddr],
    has_v4: bool,
    has_v6: bool,
) -> Option<(IpAddr, Option<IpAddr>)> {
    let primary = ips
        .iter()
        .copied()
        .map(normalize_ip)
        .find(|ip| (ip.is_ipv4() && has_v4) || (ip.is_ipv6() && has_v6))?;
    let fallback_v4 = if primary.is_ipv6() && has_v4 {
        ips.iter()
            .copied()
            .map(normalize_ip)
            .find(|ip| ip.is_ipv4())
    } else {
        None
    };
    Some((primary, fallback_v4))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StunFlowAuth {
    /// Authenticated via RFC 5389 STUN (exempts WebRTC/Discord Voice SRTP, TURN, and DTLS 1.3).
    Stun,
    /// Authenticated via DTLS 1.0/1.2/1.3 plaintext record header (exempts subsequent
    /// DTLS plaintext records, RFC 9147 DTLS 1.3 unified-header ciphertext, and SRTP/SRTCP).
    Dtls,
    /// Authenticated via RakNet offline magic sequence (exempts subsequent connected RakNet frames).
    RakNet,
}

#[derive(Default)]
struct SessionStunFlows {
    entries: HashMap<SocketAddr, (Instant, StunFlowAuth)>,
}

impl SessionStunFlows {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn record(&mut self, dst: SocketAddr, auth: StunFlowAuth, now: Instant) {
        if let Some((ts, existing_auth)) = self.entries.get_mut(&dst) {
            *ts = now;
            if matches!(auth, StunFlowAuth::Stun | StunFlowAuth::RakNet) {
                *existing_auth = auth;
            }
            return;
        }
        if self.entries.len() >= MAX_STUN_FLOWS {
            self.entries
                .retain(|_, (ts, _)| now.saturating_duration_since(*ts) < STUN_FLOW_TTL);
            if self.entries.len() >= MAX_STUN_FLOWS {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, (ts, _))| *ts)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(dst, (now, auth));
    }

    fn is_authenticated_and_refresh(
        &mut self,
        dst: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) -> bool {
        if let Some((ts, auth)) = self.entries.get_mut(&dst) {
            if now.saturating_duration_since(*ts) < STUN_FLOW_TTL {
                let permitted = match *auth {
                    StunFlowAuth::Stun | StunFlowAuth::RakNet => true,
                    StunFlowAuth::Dtls => {
                        is_dtls13_ciphertext_packet(payload) || is_srtp_or_srtcp_packet(payload)
                    }
                };
                if permitted {
                    *ts = now;
                    return true;
                }
                return false;
            }
            self.entries.remove(&dst);
        }
        false
    }

    fn refresh_on_inbound(&mut self, src: SocketAddr, payload: &[u8], now: Instant) -> bool {
        if is_stun_packet(payload) {
            self.record(src, StunFlowAuth::Stun, now);
            return true;
        }
        if is_dtls_packet(payload) {
            self.record(src, StunFlowAuth::Dtls, now);
            return true;
        }
        if is_raknet_offline_packet(payload) {
            self.record(src, StunFlowAuth::RakNet, now);
            return true;
        }
        if let Some((ts, _)) = self.entries.get_mut(&src) {
            if now.saturating_duration_since(*ts) < STUN_FLOW_TTL {
                *ts = now;
                return true;
            }
            self.entries.remove(&src);
        }
        false
    }
}

fn stun_flows_is_empty(flows: &RwLock<SessionStunFlows>) -> bool {
    flows.read().ok().is_none_or(|guard| guard.is_empty())
}

fn is_stun_flow_authenticated_and_refresh(
    flows: &RwLock<SessionStunFlows>,
    dst: SocketAddr,
    payload: &[u8],
    now: Instant,
) -> bool {
    let quick_check = flows.read().ok().map(|guard| match guard.entries.get(&dst) {
        None => (false, false),
        Some(&(ts, auth)) => {
            let age = now.saturating_duration_since(ts);
            if age >= STUN_FLOW_TTL {
                (false, true)
            } else {
                let permitted = match auth {
                    StunFlowAuth::Stun | StunFlowAuth::RakNet => true,
                    StunFlowAuth::Dtls => {
                        is_dtls13_ciphertext_packet(payload) || is_srtp_or_srtcp_packet(payload)
                    }
                };
                if !permitted {
                    (false, false)
                } else {
                    (true, age >= STUN_FLOW_REFRESH_INTERVAL)
                }
            }
        }
    });
    match quick_check {
        Some((permitted, false)) => permitted,
        Some((_, true)) => flows
            .write()
            .ok()
            .is_some_and(|mut guard| guard.is_authenticated_and_refresh(dst, payload, now)),
        None => false,
    }
}

/// Evaluates whether an outbound UDP/443 packet belongs to an exempt STUN/DTLS/WebRTC/RakNet
/// flow, recording/refreshing `dst` in `flows` (including on `is_dtls_packet` matches without
/// short-circuiting) and allowing subsequent DTLS 1.3 ciphertext / SRTP / RakNet packets.
fn allow_and_track_udp_443_outbound(
    flows: &RwLock<SessionStunFlows>,
    dst: SocketAddr,
    payload: &[u8],
    now: Instant,
) -> bool {
    if is_stun_packet(payload) {
        if let Ok(mut guard) = flows.write() {
            guard.record(dst, StunFlowAuth::Stun, now);
        }
        return true;
    }
    if is_dtls_packet(payload) {
        if let Ok(mut guard) = flows.write() {
            guard.record(dst, StunFlowAuth::Dtls, now);
        }
        return true;
    }
    if is_raknet_offline_packet(payload) {
        if let Ok(mut guard) = flows.write() {
            guard.record(dst, StunFlowAuth::RakNet, now);
        }
        return true;
    }
    is_stun_flow_authenticated_and_refresh(flows, dst, payload, now)
}

/// Refreshes active UDP/443 STUN/DTLS/RakNet flows on inbound replies so muted/listen-only
/// Discord Voice/WebRTC sessions remain authenticated past `STUN_FLOW_TTL`.
fn refresh_inbound_stun_flow(
    flows: &RwLock<SessionStunFlows>,
    src: SocketAddr,
    payload: &[u8],
    now: Instant,
) -> bool {
    if src.port() != 443 {
        return false;
    }
    let is_stun = is_stun_packet(payload);
    let is_dtls = !is_stun && is_dtls_packet(payload);
    let is_raknet = !is_stun && !is_dtls && is_raknet_offline_packet(payload);
    let action = flows.read().ok().map(|guard| match guard.entries.get(&src) {
        None => (false, is_stun || is_dtls || is_raknet),
        Some(&(ts, auth)) => {
            let upgrade = (is_stun && auth != StunFlowAuth::Stun)
                || (is_raknet && auth != StunFlowAuth::RakNet);
            let age = now.saturating_duration_since(ts);
            if upgrade || age >= STUN_FLOW_REFRESH_INTERVAL {
                (true, true)
            } else {
                (true, false)
            }
        }
    });
    match action {
        Some((active, false)) => active,
        Some((_, true)) => flows
            .write()
            .ok()
            .is_some_and(|mut guard| guard.refresh_on_inbound(src, payload, now)),
        None => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UdpClientPin {
    expected_ip: Option<IpAddr>,
    pinned_ip: Option<IpAddr>,
    pinned_port: Option<u16>,
}

impl UdpClientPin {
    /// Captures the TCP control peer IP alongside any non-zero RFC 1928 §4 client
    /// `DST.ADDR`/`DST.PORT` pin declared in the `UDP ASSOCIATE` request.
    ///
    /// When the client's declared `DST.ADDR` disagrees with the TCP control peer IP
    /// (e.g. multi-homed host or NATted client reporting a private interface IP), we relax
    /// the conflicting pin back to `expected_ip` alone rather than creating an unsatisfiable
    /// filter that would silently drop 100% of UDP packets after replying `0x00`, while still
    /// preventing traffic reflection to the declared address.
    fn from_request(tcp_peer_ip: Option<IpAddr>, req_host: &str, req_port: u16) -> Self {
        let expected_ip = tcp_peer_ip.map(normalize_ip);
        let raw_pinned_ip = req_host
            .parse::<IpAddr>()
            .ok()
            .map(normalize_ip)
            .filter(|ip| !ip.is_unspecified());
        let ip_mismatch =
            matches!((expected_ip, raw_pinned_ip), (Some(exp), Some(pin)) if exp != pin);
        let pinned_ip = if ip_mismatch { None } else { raw_pinned_ip };
        let pinned_port = if ip_mismatch {
            None
        } else {
            (req_port != 0).then_some(req_port)
        };
        Self {
            expected_ip,
            pinned_ip,
            pinned_port,
        }
    }

    /// Returns the pre-bound client UDP endpoint when the client pinned a non-zero port
    /// (and any non-zero pinned IP agrees with the TCP control peer IP).
    fn initial_client_peer(&self) -> Option<SocketAddr> {
        let port = self.pinned_port?;
        let ip = match (self.expected_ip, self.pinned_ip) {
            (Some(exp), Some(pin)) if exp == pin => pin,
            (Some(_), Some(_)) => return None,
            (Some(exp), None) => exp,
            (None, Some(pin)) => pin,
            (None, None) => return None,
        };
        Some(SocketAddr::new(ip, port))
    }

    /// Returns `true` when `src_peer` satisfies the TCP peer IP and RFC 1928 pin constraints.
    fn accepts(&self, src_peer: SocketAddr) -> bool {
        let src_ip = normalize_ip(src_peer.ip());
        if self.expected_ip.is_some_and(|exp| src_ip != exp) {
            return false;
        }
        if self.pinned_ip.is_some_and(|pin| src_ip != pin) {
            return false;
        }
        if self.pinned_port.is_some_and(|port| src_peer.port() != port) {
            return false;
        }
        true
    }
}

/// Tracks outbound UDP destinations for inbound anti-amplification filtering.
///
/// - For loopback-only SOCKS5 UDP ASSOCIATE clients (`full_cone == true`), enables true
///   RFC 3489 Full-Cone NAT inbound replies once the local client has sent at least one
///   outbound UDP packet on the session (`has_sent_outbound == true`), allowing P2P
///   Full-Cone NAT checks and asymmetric ICE/WebRTC peer probes from any IP/port.
/// - For all non-loopback clients (`full_cone == false`), enforces strict `(IP, port)`
///   anti-amplification filtering with TTL expiry and bounded capacity.
#[derive(Default)]
struct AllowedUdpDestinations {
    full_cone: bool,
    has_sent_outbound: bool,
    entries: HashMap<SocketAddr, Instant>,
}

impl AllowedUdpDestinations {
    fn new(full_cone: bool) -> Self {
        Self {
            full_cone,
            has_sent_outbound: false,
            entries: HashMap::new(),
        }
    }

    fn key_for(addr: SocketAddr) -> SocketAddr {
        SocketAddr::new(normalize_ip(addr.ip()), addr.port())
    }

    fn record(&mut self, dst: SocketAddr, now: Instant) {
        self.has_sent_outbound = true;
        if self.full_cone {
            return;
        }
        let key = Self::key_for(dst);
        if self.entries.len() >= MAX_ALLOWED_UDP_DESTS && !self.entries.contains_key(&key) {
            self.entries
                .retain(|_, ts| now.saturating_duration_since(*ts) < ALLOWED_UDP_DEST_TTL);
            if self.entries.len() >= MAX_ALLOWED_UDP_DESTS {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(k, _)| *k);
                if let Some(oldest) = oldest {
                    self.entries.remove(&oldest);
                }
            }
        }
        self.entries.insert(key, now);
    }

    /// Returns `Some(needs_refresh)` when `src` is permitted to send inbound UDP to the client,
    /// or `None` if unsolicited/expired.
    fn check(&self, src: SocketAddr, now: Instant) -> Option<bool> {
        if self.full_cone {
            return self.has_sent_outbound.then_some(false);
        }
        let key = Self::key_for(src);
        let ts = self.entries.get(&key)?;
        let age = now.saturating_duration_since(*ts);
        if age >= ALLOWED_UDP_DEST_TTL {
            None
        } else {
            Some(age >= ALLOWED_UDP_REFRESH_INTERVAL)
        }
    }

    fn refresh_if_present(&mut self, src: SocketAddr, now: Instant) {
        if self.full_cone {
            return;
        }
        let key = Self::key_for(src);
        if let Some(ts) = self.entries.get_mut(&key) {
            let age = now.saturating_duration_since(*ts);
            if age < ALLOWED_UDP_DEST_TTL {
                *ts = now;
            }
        }
    }
}

fn is_allowed_inbound_source(
    allowed: &RwLock<AllowedUdpDestinations>,
    src: SocketAddr,
    now: Instant,
) -> bool {
    let check = allowed
        .read()
        .ok()
        .and_then(|guard| guard.check(src, now));
    match check {
        Some(false) => true,
        Some(true) => {
            if let Ok(mut guard) = allowed.write() {
                guard.refresh_if_present(src, now);
            }
            true
        }
        None => false,
    }
}

fn is_self_udp_target(
    target_ip: IpAddr,
    dst_port: u16,
    own_ports: &[u16],
    own_local_ips: &[IpAddr],
) -> bool {
    target_ip.is_unspecified()
        || ((target_ip.is_loopback() || own_local_ips.contains(&target_ip))
            && own_ports.contains(&dst_port))
}

async fn run_udp_associate_session(
    mut tcp_control: TcpStream,
    client_udp: Arc<UdpSocket>,
    outbound_v4: Option<Arc<UdpSocket>>,
    outbound_v6: Option<Arc<UdpSocket>>,
    ctx: EngineContext,
    split_bypassed: bool,
    client_pin: UdpClientPin,
) -> Result<()> {
    let is_loopback_peer = client_pin
        .expected_ip
        .is_some_and(|ip| ip.to_canonical().is_loopback());
    let track_quic_udp_443 = !split_bypassed && ctx.config.block_quic;
    let has_v4 = outbound_v4.is_some();
    let has_v6 = outbound_v6.is_some();
    let own_ports: Vec<u16> = [
        client_udp.local_addr().ok().map(|a| a.port()),
        outbound_v4
            .as_ref()
            .and_then(|s| s.local_addr().ok().map(|a| a.port())),
        outbound_v6
            .as_ref()
            .and_then(|s| s.local_addr().ok().map(|a| a.port())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut own_local_ips: Vec<IpAddr> = [
        tcp_control.local_addr().ok().map(|a| normalize_ip(a.ip())),
        client_udp.local_addr().ok().map(|a| normalize_ip(a.ip())),
        outbound_v4
            .as_ref()
            .and_then(|s| s.local_addr().ok().map(|a| normalize_ip(a.ip()))),
        outbound_v6
            .as_ref()
            .and_then(|s| s.local_addr().ok().map(|a| normalize_ip(a.ip()))),
        Some(normalize_ip(ctx.config.addr)),
    ]
    .into_iter()
    .flatten()
    .filter(|ip| !ip.is_unspecified())
    .collect();
    own_local_ips.sort_unstable();
    own_local_ips.dedup();

    let initial_peer = client_pin.initial_client_peer();
    let last_client_peer: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(initial_peer));
    let allowed_dests: Arc<RwLock<AllowedUdpDestinations>> =
        Arc::new(RwLock::new(AllowedUdpDestinations::new(is_loopback_peer)));
    let stun_flows: Arc<RwLock<SessionStunFlows>> =
        Arc::new(RwLock::new(SessionStunFlows::default()));

    let c2r_client_udp = Arc::clone(&client_udp);
    let c2r_out_v4 = outbound_v4.clone();
    let c2r_out_v6 = outbound_v6.clone();
    let c2r_peer = Arc::clone(&last_client_peer);
    let c2r_allowed = Arc::clone(&allowed_dests);
    let c2r_stun_flows = Arc::clone(&stun_flows);
    let c2r_ctx = ctx.clone();

    let client_to_remote = async move {
        let mut buf = vec![0u8; 65535];
        let mut cached_client_peer: Option<SocketAddr> = initial_peer;
        let mut last_recorded_dest: Option<(SocketAddr, Instant)> = None;
        let mut recorded_full_cone = false;

        loop {
            let (n, src_peer) = match c2r_client_udp.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(e) if is_transient_udp_recv_error(&e) => continue,
                Err(e) => break Err::<(), std::io::Error>(e),
            };
            if !client_pin.accepts(src_peer) {
                continue;
            }

            let Some((dst_host, is_domain, dst_port, payload)) = parse_socks5_udp_packet(&buf[..n])
            else {
                continue;
            };
            if dst_port == 0 {
                continue;
            }
            if cached_client_peer != Some(src_peer) {
                cached_client_peer = Some(src_peer);
                if let Ok(mut guard) = c2r_peer.write() {
                    *guard = Some(src_peer);
                }
            }

            // Fast-path IP literals without calling `dns.resolve`.
            let (target_ip, fallback_v4) = if let Ok(ip) = dst_host.parse::<IpAddr>() {
                let normalized = normalize_ip(ip);
                if (normalized.is_ipv4() && c2r_out_v4.is_none())
                    || (normalized.is_ipv6() && c2r_out_v6.is_none())
                {
                    continue;
                }
                (normalized, None)
            } else {
                // Reject forbidden hostnames from non-loopback peers before DNS resolution.
                if !is_loopback_peer && is_forbidden_proxy_host(false, &dst_host, dst_port, None) {
                    continue;
                }
                // Drop unauthenticated domain-targeted QUIC UDP/443 before DNS resolution.
                if !split_bypassed
                    && c2r_ctx.config.block_quic
                    && dst_port == 443
                    && !payload.is_empty()
                    && !is_stun_packet(payload)
                    && !is_dtls_packet(payload)
                    && !is_raknet_offline_packet(payload)
                    && stun_flows_is_empty(&c2r_stun_flows)
                    && c2r_ctx.bypass.should_desync(Some(dst_host.as_str()), None)
                {
                    c2r_ctx.inc_quic_blocked();
                    debug!(host = %dst_host, "dropping QUIC UDP:443 packet to force DPI-bypassed TCP fallback");
                    continue;
                }
                let Ok(ips) = c2r_ctx.dns.resolve(&dst_host).await else {
                    continue;
                };
                let Some((ip, v4_fallback)) =
                    select_udp_targets(&ips, c2r_out_v4.is_some(), c2r_out_v6.is_some())
                else {
                    continue;
                };
                let safe_v4_fallback = v4_fallback.filter(|&v4_ip| {
                    (is_loopback_peer || !BypassPolicy::is_non_public_ip(v4_ip))
                        && !is_self_udp_target(v4_ip, dst_port, &own_ports, &own_local_ips)
                });
                (ip, safe_v4_fallback)
            };

            // Enforce SSRF protection: non-loopback peers cannot relay UDP to private/link-local/loopback targets.
            if !is_loopback_peer && BypassPolicy::is_non_public_ip(target_ip) {
                continue;
            }
            // Reject unspecified targets and self-reflection back into our own UDP relay sockets.
            if is_self_udp_target(target_ip, dst_port, &own_ports, &own_local_ips) {
                continue;
            }

            let dst_sa = SocketAddr::new(target_ip, dst_port);
            let now = Instant::now();

            // If QUIC blocking is enabled, drop UDP/443 QUIC datagrams (including RFC 9287
            // greased and short-header QUIC) for non-bypassed targets, while exempting
            // RFC 5389 STUN, DTLS 1.0/1.2/1.3 (including RFC 9147 unified-header ciphertext
            // and SRTP/SRTCP on authenticated flows), RakNet offline magic, and
            // STUN/DTLS-authenticated WebRTC/Discord Voice flows.
            if !split_bypassed
                && c2r_ctx.config.block_quic
                && dst_port == 443
                && !payload.is_empty()
                && !allow_and_track_udp_443_outbound(&c2r_stun_flows, dst_sa, payload, now)
                && c2r_ctx.bypass.should_desync(
                    if is_domain {
                        Some(dst_host.as_str())
                    } else {
                        None
                    },
                    Some(target_ip),
                )
            {
                c2r_ctx.inc_quic_blocked();
                debug!(host = %dst_host, dst = %dst_sa, "dropping QUIC UDP:443 packet to force DPI-bypassed TCP fallback");
                continue;
            }

            // Record outbound activity / destination for inbound filtering (avoid lock churn on steady flows).
            if is_loopback_peer {
                if !recorded_full_cone {
                    if let Ok(mut guard) = c2r_allowed.write() {
                        guard.record(dst_sa, now);
                        recorded_full_cone = true;
                    }
                }
            } else if !matches!(
                last_recorded_dest,
                Some((prev_dst, prev_ts))
                    if prev_dst == dst_sa
                        && now.saturating_duration_since(prev_ts)
                            < ALLOWED_UDP_REFRESH_INTERVAL
            ) {
                if let Ok(mut guard) = c2r_allowed.write() {
                    guard.record(dst_sa, now);
                }
                last_recorded_dest = Some((dst_sa, now));
            }

            match dst_sa {
                SocketAddr::V4(_) => {
                    if let Some(ref v4_sock) = c2r_out_v4 {
                        let _ = v4_sock.send_to(payload, dst_sa).await;
                    }
                }
                SocketAddr::V6(_) => {
                    if let Some(ref v6_sock) = c2r_out_v6 {
                        if let Err(err) = v6_sock.send_to(payload, dst_sa).await {
                            if is_udp_unreachable_error(&err) {
                                if let (Some(v4_ip), Some(v4_sock)) =
                                    (fallback_v4, c2r_out_v4.as_ref())
                                {
                                    let v4_sa = SocketAddr::new(v4_ip, dst_port);
                                    if !split_bypassed
                                        && c2r_ctx.config.block_quic
                                        && dst_port == 443
                                        && !payload.is_empty()
                                        && !allow_and_track_udp_443_outbound(
                                            &c2r_stun_flows,
                                            v4_sa,
                                            payload,
                                            now,
                                        )
                                        && c2r_ctx.bypass.should_desync(
                                            if is_domain {
                                                Some(dst_host.as_str())
                                            } else {
                                                None
                                            },
                                            Some(v4_ip),
                                        )
                                    {
                                        c2r_ctx.inc_quic_blocked();
                                        debug!(host = %dst_host, dst = %v4_sa, "dropping QUIC UDP:443 packet on IPv4 fallback to force DPI-bypassed TCP fallback");
                                        continue;
                                    }
                                    if !is_loopback_peer {
                                        if let Ok(mut guard) = c2r_allowed.write() {
                                            guard.record(v4_sa, now);
                                        }
                                        last_recorded_dest = Some((v4_sa, now));
                                    }
                                    debug!(
                                        v6_dst = %dst_sa,
                                        v4_dst = %v4_sa,
                                        error = %err,
                                        "SOCKS5 UDP IPv6 send unreachable; falling back to IPv4"
                                    );
                                    let _ = v4_sock.send_to(payload, v4_sa).await;
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    let r2c_client_udp = Arc::clone(&client_udp);
    let r2c_peer = Arc::clone(&last_client_peer);
    let r2c_allowed = Arc::clone(&allowed_dests);
    let r2c_stun_flows = Arc::clone(&stun_flows);

    let remote_v4_to_client = async move {
        if let Some(v4_sock) = outbound_v4 {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, remote_src) = match v4_sock.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(e) if is_transient_udp_recv_error(&e) => continue,
                    Err(e) => {
                        if has_v6 {
                            debug!(error = %e, "SOCKS5 UDP IPv4 recv failed; disabling IPv4 inbound relay while preserving IPv6 session");
                            break;
                        }
                        return Err::<(), std::io::Error>(e);
                    }
                };
                let normalized_src =
                    SocketAddr::new(normalize_ip(remote_src.ip()), remote_src.port());
                let now = Instant::now();
                if !is_allowed_inbound_source(&r2c_allowed, normalized_src, now) {
                    continue;
                }
                if track_quic_udp_443 && normalized_src.port() == 443 && n > 0 {
                    let _ =
                        refresh_inbound_stun_flow(&r2c_stun_flows, normalized_src, &buf[..n], now);
                }
                if let Some(client_peer) = r2c_peer.read().ok().and_then(|g| *g) {
                    let pkt = encode_socks5_udp_packet(normalized_src, &buf[..n]);
                    let _ = r2c_client_udp.send_to(&pkt, client_peer).await;
                }
            }
        }
        std::future::pending::<std::io::Result<()>>().await
    };

    let r2c6_client_udp = Arc::clone(&client_udp);
    let r2c6_peer = Arc::clone(&last_client_peer);
    let r2c6_allowed = Arc::clone(&allowed_dests);
    let r2c6_stun_flows = Arc::clone(&stun_flows);
    let remote_v6_to_client = async move {
        if let Some(v6_sock) = outbound_v6 {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, remote_src) = match v6_sock.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(e) if is_transient_udp_recv_error(&e) => continue,
                    Err(e) => {
                        if has_v4 {
                            debug!(error = %e, "SOCKS5 UDP IPv6 recv failed; disabling IPv6 inbound relay while preserving IPv4 session");
                            break;
                        }
                        return Err::<(), std::io::Error>(e);
                    }
                };
                let normalized_src =
                    SocketAddr::new(normalize_ip(remote_src.ip()), remote_src.port());
                let now = Instant::now();
                if !is_allowed_inbound_source(&r2c6_allowed, normalized_src, now) {
                    continue;
                }
                if track_quic_udp_443 && normalized_src.port() == 443 && n > 0 {
                    let _ =
                        refresh_inbound_stun_flow(&r2c6_stun_flows, normalized_src, &buf[..n], now);
                }
                if let Some(client_peer) = r2c6_peer.read().ok().and_then(|g| *g) {
                    let pkt = encode_socks5_udp_packet(normalized_src, &buf[..n]);
                    let _ = r2c6_client_udp.send_to(&pkt, client_peer).await;
                }
            }
        }
        std::future::pending::<std::io::Result<()>>().await
    };

    let tcp_eof = async move {
        let mut sink = [0u8; 64];
        loop {
            match tcp_control.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };

    tokio::select! {
        _ = tcp_eof => {}
        _ = client_to_remote => {}
        _ = remote_v4_to_client => {}
        _ = remote_v6_to_client => {}
    }

    Ok(())
}

async fn read_socks5_addr(
    stream: &mut TcpStream,
    atyp: u8,
) -> Result<(String, Option<String>, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok((ip.to_string(), None, port))
        }
        ATYP_DOMAIN => {
            let mut len_b = [0u8; 1];
            stream.read_exact(&mut len_b).await?;
            let len = len_b[0] as usize;
            let mut dom = vec![0u8; len + 2];
            stream.read_exact(&mut dom).await?;
            let host = String::from_utf8(dom[..len].to_vec())?;
            let port = u16::from_be_bytes([dom[len], dom[len + 1]]);
            Ok((host.clone(), Some(host), port))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok((ip.to_string(), None, port))
        }
        other => bail!("unsupported SOCKS5 ATYP 0x{other:02x}"),
    }
}

async fn read_cstring(stream: &mut TcpStream, max_len: usize) -> Result<String> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await?;
        if byte[0] == 0 {
            break;
        }
        if out.len() >= max_len {
            bail!("SOCKS4 string exceeded maximum length");
        }
        out.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

pub fn encode_socks5_reply(rep: u8, bind_addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend_from_slice(&[SOCKS5_VER, rep, 0x00]);
    match bind_addr {
        SocketAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out
}

/// Parses an RFC 1928 §7 UDP datagram header: `[RSV(2), FRAG(1), ATYP(1), DST.ADDR, DST.PORT, DATA...]`.
/// Returns `(host, is_domain, port, payload)`.
pub fn parse_socks5_udp_packet(pkt: &[u8]) -> Option<(String, bool, u16, &[u8])> {
    if pkt.len() < 10 {
        return None;
    }
    // RSV must be 0x0000 and FRAG must be 0x00 (unfragmented)
    if pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
        return None;
    }

    match pkt[3] {
        ATYP_IPV4 => {
            if pkt.len() < 10 {
                return None;
            }
            let ip = Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
            let port = u16::from_be_bytes([pkt[8], pkt[9]]);
            Some((ip.to_string(), false, port, &pkt[10..]))
        }
        ATYP_DOMAIN => {
            let dlen = pkt[4] as usize;
            if pkt.len() < 5 + dlen + 2 {
                return None;
            }
            let host = std::str::from_utf8(&pkt[5..5 + dlen]).ok()?.to_string();
            let port = u16::from_be_bytes([pkt[5 + dlen], pkt[5 + dlen + 1]]);
            Some((host, true, port, &pkt[7 + dlen..]))
        }
        ATYP_IPV6 => {
            if pkt.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([pkt[20], pkt[21]]);
            Some((ip.to_string(), false, port, &pkt[22..]))
        }
        _ => None,
    }
}

/// Encodes an RFC 1928 §7 UDP datagram header around `payload`.
pub fn encode_socks5_udp_packet(src: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV=0, FRAG=0
    match src {
        SocketAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.ip().octets());
            out.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_socks5_udp_packets_ipv4_and_domain() {
        let sa: SocketAddr = "162.159.137.234:50001".parse().unwrap();
        let encoded = encode_socks5_udp_packet(sa, b"discord-voice-rtp-frame");
        let (host, is_dom, port, data) = parse_socks5_udp_packet(&encoded).unwrap();
        assert_eq!(host, "162.159.137.234");
        assert!(!is_dom);
        assert_eq!(port, 50001);
        assert_eq!(data, b"discord-voice-rtp-frame");

        // Domain ATYP=0x03 packet
        let mut dom_pkt = vec![0x00, 0x00, 0x00, ATYP_DOMAIN, 15];
        dom_pkt.extend_from_slice(b"www.roblox.com.");
        dom_pkt.extend_from_slice(&55123u16.to_be_bytes());
        dom_pkt.extend_from_slice(b"raknet-ping");

        let (dhost, d_is_dom, dport, ddata) = parse_socks5_udp_packet(&dom_pkt).unwrap();
        assert_eq!(dhost, "www.roblox.com.");
        assert!(d_is_dom);
        assert_eq!(dport, 55123);
        assert_eq!(ddata, b"raknet-ping");
    }

    #[test]
    fn rejects_self_udp_targets_including_non_loopback_bind_ips() {
        let own_ports = [50000u16, 50001u16];
        let own_local_ips = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            IpAddr::V6("fd00::50".parse().unwrap()),
        ];

        assert!(is_self_udp_target(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            53,
            &own_ports,
            &own_local_ips
        ));
        assert!(is_self_udp_target(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            50000,
            &own_ports,
            &own_local_ips
        ));
        assert!(is_self_udp_target(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            50001,
            &own_ports,
            &own_local_ips
        ));
        assert!(is_self_udp_target(
            IpAddr::V6("fd00::50".parse().unwrap()),
            50000,
            &own_ports,
            &own_local_ips
        ));
        assert!(!is_self_udp_target(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            53,
            &own_ports,
            &own_local_ips
        ));
        assert!(!is_self_udp_target(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            50000,
            &own_ports,
            &own_local_ips
        ));
    }

    #[test]
    fn stun_and_dtls_detection_exempts_webrtc_while_blocking_quic() {
        let mut stun = [0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01; // Binding Request
        stun[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(is_stun_packet(&stun));
        assert!(!is_dtls_packet(&stun));

        // Short STUN (<20 bytes) or QUIC long header with STUN cookie must NOT match STUN.
        assert!(!is_stun_packet(&stun[..19]));
        let mut spoofed_quic = stun;
        spoofed_quic[0] = 0xC0;
        assert!(!is_stun_packet(&spoofed_quic));

        // DTLS 1.2 Handshake, DTLS 1.0 ApplicationData, and DTLS 1.3 ACK (0x1a)
        let mut dtls12 = [0u8; 13];
        dtls12[0] = 0x16;
        dtls12[1] = 0xfe;
        dtls12[2] = 0xfd;
        assert!(is_dtls_packet(&dtls12));

        let mut dtls10 = [0u8; 16];
        dtls10[0] = 0x17;
        dtls10[1] = 0xfe;
        dtls10[2] = 0xff;
        assert!(is_dtls_packet(&dtls10));

        let mut dtls13_ack = [0u8; 13];
        dtls13_ack[0] = 0x1a;
        dtls13_ack[1] = 0xfe;
        dtls13_ack[2] = 0xfd;
        assert!(is_dtls_packet(&dtls13_ack));

        // Invalid DTLS content type, version, or length < 13
        let mut bad_ct = dtls13_ack;
        bad_ct[0] = 0x1b;
        assert!(!is_dtls_packet(&bad_ct));
        let mut bad_dtls = dtls12;
        bad_dtls[2] = 0xfc;
        assert!(!is_dtls_packet(&bad_dtls));
        assert!(!is_dtls_packet(&dtls12[..12]));
    }

    #[test]
    fn transient_udp_recv_errors_cover_peer_unreachable_and_wsaemsgsize() {
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionRefused,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
        ] {
            assert!(is_transient_udp_recv_error(&std::io::Error::new(
                kind,
                "transient"
            )));
        }
        assert!(is_transient_udp_recv_error(
            &std::io::Error::from_raw_os_error(10040)
        ));
        #[cfg(windows)]
        for code in [10051, 10052, 10054, 10065] {
            assert!(is_transient_udp_recv_error(
                &std::io::Error::from_raw_os_error(code)
            ));
        }
        assert!(!is_transient_udp_recv_error(&std::io::Error::new(
            ErrorKind::PermissionDenied,
            "fatal"
        )));
    }

    #[test]
    fn allowed_udp_destinations_blocks_unsolicited_inbound_sources() {
        let allowed = RwLock::new(AllowedUdpDestinations::default());
        let known: SocketAddr = "162.159.137.234:50001".parse().unwrap();
        let unknown: SocketAddr = "198.51.100.9:53".parse().unwrap();
        let now = Instant::now();

        assert!(!is_allowed_inbound_source(&allowed, known, now));
        allowed.write().unwrap().record(known, now);
        assert!(is_allowed_inbound_source(&allowed, known, now));
        assert!(!is_allowed_inbound_source(&allowed, unknown, now));
    }

    #[test]
    fn socks_ssrf_blocks_non_loopback_peer_targeting_private_and_link_local() {
        let local: SocketAddr = "192.168.1.50:1080".parse().unwrap();
        assert!(is_forbidden_proxy_host(false, "127.0.0.1", 80, Some(local)));
        assert!(is_forbidden_proxy_host(
            false,
            "169.254.169.254",
            80,
            Some(local)
        ));
        assert!(is_forbidden_proxy_host(false, "10.0.0.1", 443, Some(local)));
        assert!(is_forbidden_proxy_host(
            false,
            "fe80::1",
            443,
            Some(local)
        ));
        assert!(is_forbidden_remote_addr(
            false,
            "169.254.169.254:80".parse().unwrap(),
            Some(local)
        ));
        assert!(!is_forbidden_proxy_host(
            true,
            "192.168.1.1",
            80,
            Some(local)
        ));
        assert!(!is_forbidden_proxy_host(
            false,
            "1.1.1.1",
            443,
            Some(local)
        ));
    }

    #[test]
    fn shared_stun_flows_inbound_refresh_keeps_listen_only_flow_alive_past_ttl() {
        let flows = Arc::new(RwLock::new(SessionStunFlows::default()));
        let voice_v4: SocketAddr = "162.159.137.234:443".parse().unwrap();
        let voice_v6: SocketAddr = "[2606:4700::1]:443".parse().unwrap();
        let non_443: SocketAddr = "162.159.137.234:50001".parse().unwrap();

        let mut stun = [0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        let srtp = [0x80u8; 32];
        let t0 = Instant::now();

        // Without inbound refresh, a flow expires after STUN_FLOW_TTL (120s).
        assert!(allow_and_track_udp_443_outbound(&flows, voice_v4, &stun, t0));
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            voice_v4,
            &srtp,
            t0 + STUN_FLOW_TTL + Duration::from_secs(1)
        ));

        // With inbound UDP/443 replies while muted / listen-only, the shared RwLock flow
        // stays authenticated well past 120s without any outbound packets.
        let r2c_flows = Arc::clone(&flows);
        assert!(allow_and_track_udp_443_outbound(&flows, voice_v4, &stun, t0));
        assert!(refresh_inbound_stun_flow(
            &r2c_flows,
            voice_v4,
            &srtp,
            t0 + Duration::from_secs(80)
        ));
        assert!(refresh_inbound_stun_flow(
            &r2c_flows,
            voice_v4,
            &srtp,
            t0 + Duration::from_secs(150)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            voice_v4,
            &srtp,
            t0 + Duration::from_secs(210)
        ));

        // Non-443 inbound packets never touch SessionStunFlows.
        assert!(!refresh_inbound_stun_flow(
            &r2c_flows,
            non_443,
            &stun,
            t0 + Duration::from_secs(10)
        ));

        // IPv6 inbound STUN/443 reply also authenticates/refreshes the shared flow table.
        assert!(refresh_inbound_stun_flow(
            &r2c_flows,
            voice_v6,
            &stun,
            t0 + Duration::from_secs(10)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            voice_v6,
            &srtp,
            t0 + Duration::from_secs(60)
        ));
    }

    #[test]
    fn dtls_flow_auth_records_flow_and_allows_dtls13_unified_ciphertext() {
        let flows = Arc::new(RwLock::new(SessionStunFlows::default()));
        let peer: SocketAddr = "198.51.100.42:443".parse().unwrap();
        let t0 = Instant::now();

        let mut dtls_hello = [0u8; 24];
        dtls_hello[0] = 0x16;
        dtls_hello[1] = 0xfe;
        dtls_hello[2] = 0xfd;

        let mut dtls13_cipher = [0u8; 16];
        dtls13_cipher[0] = 0x2f; // top 3 bits 001 (0x20..=0x3f), RFC 9147 unified header
        let short_dtls13 = [0x20u8; 12];
        let quic_long = [0xc0u8; 64];
        let srtp = [0x80u8; 32];

        // RFC 9147 unified-header detector boundary checks.
        for b in 0x20u8..=0x3fu8 {
            assert!(is_dtls13_ciphertext_packet(&[b; 13]));
        }
        assert!(!is_dtls13_ciphertext_packet(&short_dtls13));
        assert!(!is_dtls13_ciphertext_packet(&[0x1fu8; 16]));
        assert!(!is_dtls13_ciphertext_packet(&[0x40u8; 16]));
        assert!(!is_dtls13_ciphertext_packet(&quic_long));

        // Unauthenticated DTLS 1.3 ciphertext must NOT bypass QUIC blocking.
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &dtls13_cipher,
            t0
        ));

        // Plaintext DTLS record header must record the flow instead of short-circuiting.
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &dtls_hello,
            t0
        ));
        assert!(!stun_flows_is_empty(&flows));

        // Subsequent DTLS 1.3 unified-header ciphertext and SRTP/SRTCP packets on the
        // authenticated DTLS flow pass, while short/QUIC packets remain blocked.
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &dtls13_cipher,
            t0 + Duration::from_secs(5)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &srtp,
            t0 + Duration::from_secs(5)
        ));
        let short_srtp = [0x80u8; 11];
        let quic_short = [0x40u8; 32];
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &short_srtp,
            t0 + Duration::from_secs(5)
        ));
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &quic_short,
            t0 + Duration::from_secs(5)
        ));
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &short_dtls13,
            t0 + Duration::from_secs(5)
        ));
        assert!(!allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &quic_long,
            t0 + Duration::from_secs(5)
        ));

        // Inbound DTLS 1.3 ciphertext reply refreshes the flow past 120s.
        assert!(refresh_inbound_stun_flow(
            &flows,
            peer,
            &dtls13_cipher,
            t0 + Duration::from_secs(90)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &dtls13_cipher,
            t0 + Duration::from_secs(160)
        ));

        // STUN upgrades a DTLS flow so subsequent WebRTC SRTP packets are also permitted.
        let mut stun = [0u8; 20];
        stun[0] = 0x00;
        stun[1] = 0x01;
        stun[4..8].copy_from_slice(&STUN_MAGIC_COOKIE);
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &stun,
            t0 + Duration::from_secs(165)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            peer,
            &srtp,
            t0 + Duration::from_secs(170)
        ));
    }

    #[test]
    fn allowed_udp_destinations_loopback_full_cone_vs_non_loopback_strict_port() {
        let now = Instant::now();
        let sent_dst: SocketAddr = "162.159.137.234:50001".parse().unwrap();
        let mapped_v6_same_port: SocketAddr = "[::ffff:162.159.137.234]:50001".parse().unwrap();
        let same_ip_diff_port: SocketAddr = "162.159.137.234:50002".parse().unwrap();
        let mapped_v6_diff_port: SocketAddr = "[::ffff:162.159.137.234]:50099".parse().unwrap();
        let other_ip: SocketAddr = "198.51.100.9:3479".parse().unwrap();
        let other_v6: SocketAddr = "[2001:db8::42]:55555".parse().unwrap();

        // Loopback client: blocks all inbound until at least one outbound UDP packet is sent,
        // then permits true RFC 3489 Full-Cone NAT replies from any IP/port for the session.
        let loopback_allowed = RwLock::new(AllowedUdpDestinations::new(true));
        assert!(!is_allowed_inbound_source(&loopback_allowed, sent_dst, now));
        assert!(!is_allowed_inbound_source(&loopback_allowed, other_ip, now));
        assert!(!is_allowed_inbound_source(&loopback_allowed, other_v6, now));

        loopback_allowed.write().unwrap().record(sent_dst, now);
        assert!(loopback_allowed.read().unwrap().has_sent_outbound);
        assert!(loopback_allowed.read().unwrap().entries.is_empty());
        assert!(is_allowed_inbound_source(&loopback_allowed, sent_dst, now));
        assert!(is_allowed_inbound_source(
            &loopback_allowed,
            same_ip_diff_port,
            now
        ));
        assert!(is_allowed_inbound_source(
            &loopback_allowed,
            mapped_v6_diff_port,
            now
        ));
        assert!(is_allowed_inbound_source(&loopback_allowed, other_ip, now));
        assert!(is_allowed_inbound_source(&loopback_allowed, other_v6, now));
        assert!(is_allowed_inbound_source(
            &loopback_allowed,
            other_ip,
            now + ALLOWED_UDP_DEST_TTL + Duration::from_secs(1)
        ));

        // Non-loopback client: strict (IP, port) anti-amplification filtering with TTL expiry.
        let remote_allowed = RwLock::new(AllowedUdpDestinations::new(false));
        assert!(!is_allowed_inbound_source(&remote_allowed, sent_dst, now));
        remote_allowed.write().unwrap().record(sent_dst, now);
        assert!(is_allowed_inbound_source(&remote_allowed, sent_dst, now));
        assert!(is_allowed_inbound_source(
            &remote_allowed,
            mapped_v6_same_port,
            now
        ));
        assert!(!is_allowed_inbound_source(
            &remote_allowed,
            same_ip_diff_port,
            now
        ));
        assert!(!is_allowed_inbound_source(
            &remote_allowed,
            mapped_v6_diff_port,
            now
        ));
        assert!(!is_allowed_inbound_source(&remote_allowed, other_ip, now));
        assert!(!is_allowed_inbound_source(&remote_allowed, other_v6, now));
        assert!(!is_allowed_inbound_source(
            &remote_allowed,
            sent_dst,
            now + ALLOWED_UDP_DEST_TTL + Duration::from_secs(1)
        ));

        // Inbound refresh extends active non-loopback (IP, port) entry past initial TTL.
        remote_allowed.write().unwrap().record(sent_dst, now);
        let refresh_t = now + ALLOWED_UDP_REFRESH_INTERVAL + Duration::from_secs(1);
        assert!(is_allowed_inbound_source(
            &remote_allowed,
            sent_dst,
            refresh_t
        ));
        assert!(is_allowed_inbound_source(
            &remote_allowed,
            sent_dst,
            now + ALLOWED_UDP_DEST_TTL + Duration::from_secs(1)
        ));
    }

    #[test]
    fn udp_client_pin_honors_rfc1928_nonzero_addr_and_port() {
        let tcp_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Unspecified 0.0.0.0:0 leaves port unpinned while enforcing TCP peer IP.
        let unpinned = UdpClientPin::from_request(Some(tcp_ip), "0.0.0.0", 0);
        assert_eq!(unpinned.initial_client_peer(), None);
        assert!(unpinned.accepts("127.0.0.1:41000".parse().unwrap()));
        assert!(!unpinned.accepts("192.168.1.9:41000".parse().unwrap()));

        // Non-zero DST.ADDR + DST.PORT pins client peer and blocks rebinding from other ports.
        let pinned = UdpClientPin::from_request(Some(tcp_ip), "127.0.0.1", 45000);
        assert_eq!(
            pinned.initial_client_peer(),
            Some("127.0.0.1:45000".parse().unwrap())
        );
        assert!(pinned.accepts("127.0.0.1:45000".parse().unwrap()));
        assert!(!pinned.accepts("127.0.0.1:45001".parse().unwrap()));
        assert!(!pinned.accepts("10.0.0.2:45000".parse().unwrap()));

        // Zero DST.ADDR + non-zero DST.PORT pins port against TCP peer IP.
        let port_only = UdpClientPin::from_request(Some(tcp_ip), "0.0.0.0", 45000);
        assert_eq!(
            port_only.initial_client_peer(),
            Some("127.0.0.1:45000".parse().unwrap())
        );
        assert!(port_only.accepts("127.0.0.1:45000".parse().unwrap()));
        assert!(!port_only.accepts("127.0.0.1:45002".parse().unwrap()));

        // Conflicting DST.ADDR relaxes to TCP control peer IP (never reflects to spoofed host,
        // and never silently drops 100% of packets from the legitimate TCP peer after 0x00).
        let lan_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mismatched = UdpClientPin::from_request(Some(lan_ip), "192.168.1.99", 45000);
        assert_eq!(mismatched.initial_client_peer(), None);
        assert!(mismatched.accepts("192.168.1.10:45000".parse().unwrap()));
        assert!(mismatched.accepts("192.168.1.10:54321".parse().unwrap()));
        assert!(!mismatched.accepts("192.168.1.99:45000".parse().unwrap()));
    }

    #[test]
    fn pre_connect_ssrf_validation_rejects_forbidden_resolved_targets() {
        let local: SocketAddr = "192.168.1.50:1080".parse().unwrap();

        assert!(validate_resolved_connect_targets(
            &[IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            80,
            false,
            Some(local)
        )
        .is_err());
        assert!(validate_resolved_connect_targets(
            &[
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            443,
            false,
            Some(local)
        )
        .is_err());
        assert!(validate_resolved_connect_targets(
            &[IpAddr::V6("::ffff:169.254.169.254".parse().unwrap())],
            80,
            false,
            Some(local)
        )
        .is_err());

        let public_ok = validate_resolved_connect_targets(
            &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            443,
            false,
            Some(local),
        )
        .unwrap();
        assert_eq!(public_ok, vec!["1.1.1.1:443".parse().unwrap()]);

        // Loopback peer may reach private LAN hosts, but still cannot reflect into local_addr.
        assert!(validate_resolved_connect_targets(
            &[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            80,
            true,
            Some(local)
        )
        .is_ok());
        assert!(validate_resolved_connect_targets(
            &[IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))],
            1080,
            true,
            Some(local)
        )
        .is_err());
    }

    #[test]
    fn raknet_offline_magic_exempts_udp_443_and_authenticates_connected_flow() {
        let flows = Arc::new(RwLock::new(SessionStunFlows::default()));
        let game_server: SocketAddr = "198.51.100.77:443".parse().unwrap();
        let t0 = Instant::now();

        // RakNet Open Connection Request 1 (0x05 + 16-byte offline magic at offset 1)
        let mut open_req = vec![0x05u8];
        open_req.extend_from_slice(&RAKNET_OFFLINE_MAGIC);
        open_req.push(0x0b); // protocol version
        assert!(is_raknet_offline_packet(&open_req));

        // RakNet Unconnected Ping (0x01 + 8-byte timestamp + 16-byte offline magic at offset 9)
        let mut ping = vec![0x01u8];
        ping.extend_from_slice(&[0u8; 8]);
        ping.extend_from_slice(&RAKNET_OFFLINE_MAGIC);
        assert!(is_raknet_offline_packet(&ping));

        // Plain QUIC packet must NOT match RakNet offline magic.
        let quic = [0xc0u8; 64];
        assert!(!is_raknet_offline_packet(&quic));
        assert!(!allow_and_track_udp_443_outbound(&flows, game_server, &quic, t0));

        // Sending RakNet offline packet exempts and records the flow for subsequent connected frames.
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            game_server,
            &open_req,
            t0
        ));
        let connected_raknet_frame = [0x84u8; 48];
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            game_server,
            &connected_raknet_frame,
            t0 + Duration::from_secs(5)
        ));
        assert!(refresh_inbound_stun_flow(
            &flows,
            game_server,
            &connected_raknet_frame,
            t0 + Duration::from_secs(90)
        ));
        assert!(allow_and_track_udp_443_outbound(
            &flows,
            game_server,
            &connected_raknet_frame,
            t0 + Duration::from_secs(160)
        ));
    }

    #[test]
    fn select_udp_targets_picks_ipv4_fallback_and_handles_single_stack_sockets() {
        let v6: IpAddr = "2606:4700::1".parse().unwrap();
        let v4: IpAddr = "162.159.137.234".parse().unwrap();

        // Dual-stack with IPv6 first returns IPv6 primary + IPv4 fallback.
        assert_eq!(select_udp_targets(&[v6, v4], true, true), Some((v6, Some(v4))));
        // Dual-stack with IPv4 first returns IPv4 primary + no fallback needed.
        assert_eq!(select_udp_targets(&[v4, v6], true, true), Some((v4, None)));
        // IPv4-only socket skips IPv6 and picks IPv4 directly.
        assert_eq!(select_udp_targets(&[v6, v4], true, false), Some((v4, None)));
        // IPv6-only socket skips IPv4 and picks IPv6 with no IPv4 fallback.
        assert_eq!(select_udp_targets(&[v4, v6], false, true), Some((v6, None)));
        // Missing matching socket family returns None.
        assert_eq!(select_udp_targets(&[v6], true, false), None);
        assert_eq!(select_udp_targets(&[v4], false, true), None);

        for kind in [
            ErrorKind::NetworkUnreachable,
            ErrorKind::HostUnreachable,
            ErrorKind::AddrNotAvailable,
        ] {
            assert!(is_udp_unreachable_error(&std::io::Error::new(
                kind,
                "unreachable"
            )));
        }
        assert!(!is_udp_unreachable_error(&std::io::Error::new(
            ErrorKind::PermissionDenied,
            "denied"
        )));
    }

    #[test]
    fn socks5_bind_error_codes_map_permission_denied_to_0x02_and_others_to_0x01() {
        assert_eq!(
            socks5_bind_error_reply_code(&std::io::Error::new(
                ErrorKind::PermissionDenied,
                "blocked"
            )),
            0x02
        );
        assert_eq!(
            socks5_bind_error_reply_code(&std::io::Error::new(ErrorKind::AddrInUse, "busy")),
            0x01
        );
    }
}
