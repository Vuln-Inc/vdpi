use super::HANDSHAKE_TIMEOUT;
use crate::desync::EngineContext;
use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

const SOCKS5_VER: u8 = 0x05;
const SOCKS4_VER: u8 = 0x04;

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Handles a SOCKS5 (`CONNECT` and `UDP ASSOCIATE`) client connection.
pub async fn handle_socks5_client(mut client: TcpStream, ctx: EngineContext) -> Result<()> {
    let _ = client.set_nodelay(true);

    let (cmd, (target_host, known_domain, target_port)) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, read_socks5_request(&mut client)).await??;

    match cmd {
        CMD_CONNECT => {
            debug!(host = %target_host, port = target_port, "SOCKS5 CONNECT");
            match ctx.connect_target(&target_host, target_port).await {
                Ok((remote, remote_addr)) => {
                    let reply = encode_socks5_reply(
                        0x00,
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    );
                    client.write_all(&reply).await?;
                    client.flush().await?;
                    ctx.relay_tunnel(client, remote, known_domain.as_deref(), remote_addr)
                        .await
                }
                Err(e) => {
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
            let bind_ip = client
                .local_addr()
                .map(|a| normalize_ip(a.ip()))
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            let client_udp = Arc::new(UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?);
            let relay_local_addr = client_udp.local_addr()?;

            debug!(relay_addr = %relay_local_addr, "SOCKS5 UDP ASSOCIATE established");
            let reply = encode_socks5_reply(0x00, relay_local_addr);
            client.write_all(&reply).await?;
            client.flush().await?;

            run_udp_associate_session(client, client_udp, ctx).await
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

    debug!(host = %host, port = port, "SOCKS4/4a CONNECT");
    match ctx.connect_target(&host, port).await {
        Ok((remote, remote_addr)) => {
            client.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await?;
            client.flush().await?;
            ctx.relay_tunnel(client, remote, known_domain.as_deref(), remote_addr)
                .await
        }
        Err(e) => {
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
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

async fn run_udp_associate_session(
    mut tcp_control: TcpStream,
    client_udp: Arc<UdpSocket>,
    ctx: EngineContext,
) -> Result<()> {
    let expected_client_ip = tcp_control.peer_addr().ok().map(|a| normalize_ip(a.ip()));
    let outbound_v4 = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let outbound_v6 = UdpSocket::bind("[::]:0").await.ok().map(Arc::new);
    let own_ports: Vec<u16> = [
        client_udp.local_addr().ok().map(|a| a.port()),
        outbound_v4.local_addr().ok().map(|a| a.port()),
        outbound_v6
            .as_ref()
            .and_then(|s| s.local_addr().ok().map(|a| a.port())),
    ]
    .into_iter()
    .flatten()
    .collect();

    let last_client_peer: Arc<tokio::sync::RwLock<Option<SocketAddr>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    let c2r_client_udp = Arc::clone(&client_udp);
    let c2r_out_v4 = Arc::clone(&outbound_v4);
    let c2r_out_v6 = outbound_v6.clone();
    let c2r_peer = Arc::clone(&last_client_peer);
    let c2r_ctx = ctx.clone();

    let client_to_remote = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src_peer) = c2r_client_udp.recv_from(&mut buf).await?;
            if let Some(expected_ip) = expected_client_ip {
                if normalize_ip(src_peer.ip()) != expected_ip {
                    continue;
                }
            }
            {
                let mut guard = c2r_peer.write().await;
                *guard = Some(src_peer);
            }

            let Some((dst_host, is_domain, dst_port, payload)) = parse_socks5_udp_packet(&buf[..n])
            else {
                continue;
            };
            if dst_port == 0 {
                continue;
            }

            // If QUIC blocking is enabled, drop all UDP/443 datagrams (including RFC 9287
            // greased and short-header QUIC) for non-bypassed targets so applications cleanly
            // fall back to DPI-bypassed TCP/443 TLS.
            if c2r_ctx.config.block_quic
                && dst_port == 443
                && !payload.is_empty()
                && c2r_ctx.bypass.should_desync(
                    if is_domain {
                        Some(dst_host.as_str())
                    } else {
                        None
                    },
                    dst_host.parse::<IpAddr>().ok(),
                )
            {
                debug!(host = %dst_host, "dropping QUIC UDP:443 packet to force DPI-bypassed TCP fallback");
                continue;
            }

            let Ok(ips) = c2r_ctx.dns.resolve(&dst_host).await else {
                continue;
            };
            let target_ip = ips
                .iter()
                .copied()
                .map(normalize_ip)
                .find(|ip| ip.is_ipv4() || c2r_out_v6.is_some());
            let Some(target_ip) = target_ip else {
                continue;
            };
            // Reject unspecified targets and self-reflection back into our own UDP relay sockets.
            if target_ip.is_unspecified()
                || (target_ip.is_loopback() && own_ports.contains(&dst_port))
            {
                continue;
            }
            let dst_sa = SocketAddr::new(target_ip, dst_port);

            match dst_sa {
                SocketAddr::V4(_) => {
                    let _ = c2r_out_v4.send_to(payload, dst_sa).await;
                }
                SocketAddr::V6(_) => {
                    if let Some(ref v6_sock) = c2r_out_v6 {
                        let _ = v6_sock.send_to(payload, dst_sa).await;
                    }
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };

    let r2c_client_udp = Arc::clone(&client_udp);
    let r2c_out_v4 = Arc::clone(&outbound_v4);
    let r2c_peer = Arc::clone(&last_client_peer);

    let remote_v4_to_client = async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, remote_src) = r2c_out_v4.recv_from(&mut buf).await?;
            if let Some(client_peer) = *r2c_peer.read().await {
                let pkt = encode_socks5_udp_packet(remote_src, &buf[..n]);
                let _ = r2c_client_udp.send_to(&pkt, client_peer).await;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    };

    let r2c6_client_udp = Arc::clone(&client_udp);
    let r2c6_peer = Arc::clone(&last_client_peer);
    let remote_v6_to_client = async move {
        if let Some(v6_sock) = outbound_v6 {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, remote_src) = v6_sock.recv_from(&mut buf).await?;
                if let Some(client_peer) = *r2c6_peer.read().await {
                    let pkt = encode_socks5_udp_packet(remote_src, &buf[..n]);
                    let _ = r2c6_client_udp.send_to(&pkt, client_peer).await;
                }
            }
        } else {
            std::future::pending::<Result<(), std::io::Error>>().await
        }
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
}
