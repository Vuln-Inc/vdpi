use crate::desync::EngineContext;
use crate::proxy::http::parse_authority;
use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, warn};
use vdpi_core::config::EngineMode;

/// Default loopback TCP port for the standalone TUN `/vdpi-health` server.
pub const DEFAULT_TUN_HEALTH_PORT: u16 = 18089;

const HEALTH_FALLBACK_PORTS: [u16; 5] = [DEFAULT_TUN_HEALTH_PORT, 18090, 18091, 28089, 0];
const MAX_STANDALONE_HEALTH_SESSIONS: usize = 8;
const MAX_HEALTH_REQUEST_BYTES: usize = 4 * 1024;
const HEALTH_READ_TIMEOUT: Duration = Duration::from_secs(2);
const HEALTH_WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const HEALTH_OVERLOAD_WRITE_TIMEOUT: Duration = Duration::from_millis(200);
const HEALTH_OVERLOAD_RESPONSE: &[u8] =
    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Dynamic runtime metadata attached to `/vdpi-health` responses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthRuntimeMeta {
    pub engine: EngineMode,
    pub tun_interface: Option<String>,
    pub physical_nic: Option<String>,
    pub vpn_conflict: Option<String>,
    pub dns_addr: Option<String>,
}

/// Callback invoked on each `/vdpi-health` scrape to snapshot live runtime metadata.
pub type HealthMetaFn = Arc<dyn Fn() -> HealthRuntimeMeta + Send + Sync>;

/// Returns the current process resident set size (RSS) in KiB using OS-native APIs.
pub fn read_self_rss_kb() -> Option<u64> {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let cb = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>()).ok()?;
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb,
            ..Default::default()
        };
        // SAFETY: `GetCurrentProcess` returns a valid pseudo-handle for the current process,
        // and `counters` is initialized with its exact byte size in `cb`.
        let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, cb) };
        if ok != 0 {
            Some((counters.WorkingSetSize as u64) / 1024)
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let resident_pages = statm.split_whitespace().nth(1)?.parse::<u64>().ok()?;
        // SAFETY: `sysconf(_SC_PAGESIZE)` is a thread-safe POSIX query taking no pointers.
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_bytes = u64::try_from(page_size).ok().filter(|&p| p > 0)?;
        Some(resident_pages.saturating_mul(page_bytes) / 1024)
    }

    #[cfg(target_os = "macos")]
    {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: `usage` points to valid zero-initialized storage for `libc::rusage`.
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc == 0 {
            // SAFETY: `getrusage` succeeded and populated `usage`.
            let usage = unsafe { usage.assume_init() };
            u64::try_from(usage.ru_maxrss)
                .ok()
                .map(|bytes| bytes / 1024)
        } else {
            None
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Redacts path, query, fragment, and userinfo from `https://` DoH URLs so
/// profile IDs or secret tokens never leak over loopback `/vdpi-health`.
fn redact_dns_addr_for_health(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 6
        && trimmed.as_bytes()[..6].eq_ignore_ascii_case(b"https:")
        && !trimmed
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        return "https://<redacted>".to_string();
    }
    vdpi_core::dns::redact_dns_for_display(trimmed)
}

/// Renders the `/vdpi-health` JSON payload containing all v0.4.2 telemetry fields plus
/// additive v0.5.0 engine, TUN, DNS, and process RSS fields.
pub fn render_health_json(ctx: &EngineContext, meta: &HealthRuntimeMeta) -> String {
    let snap = ctx.telemetry_snapshot();
    let raw_effective_dns = meta
        .dns_addr
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let cfg_dns = ctx.config.dns_addr.trim();
            (!cfg_dns.is_empty()).then_some(cfg_dns)
        });
    let effective_doh = raw_effective_dns.is_some_and(|dns| {
        vdpi_core::dns::is_effective_doh_target(dns, ctx.config.enable_doh)
    });
    let effective_dns_addr = raw_effective_dns.map(redact_dns_addr_for_health);
    let payload = serde_json::json!({
        "status": "ok",
        "service": "vdpi",
        "version": env!("CARGO_PKG_VERSION"),
        "mode": ctx.config.mode,
        "doh": effective_doh,
        "block_quic": ctx.config.block_quic,
        "active_connections": snap.active_connections,
        "total_connections": snap.total_connections,
        "bytes_tx": snap.bytes_tx,
        "bytes_rx": snap.bytes_rx,
        "tls_handshakes": snap.tls_handshakes,
        "auto_heal_escalations": snap.auto_heal_escalations,
        "learned_hosts": snap.learned_hosts,
        "isp_stage": ctx.preferred_stage().label(),
        "engine": meta.engine.as_str(),
        "tun_interface": &meta.tun_interface,
        "physical_nic": &meta.physical_nic,
        "vpn_conflict": &meta.vpn_conflict,
        "dns_addr": effective_dns_addr,
        "udp_flows_active": snap.udp_flows_active,
        "quic_blocked": snap.quic_blocked,
        "dns_queries": ctx.dns.query_count(),
        "rss_kb": read_self_rss_kb(),
    });
    format!("{payload}\n")
}

/// Returns `true` when `header_str` contains at least one `Host` header and every `Host`
/// header targets a loopback authority (enforced across all HTTP versions).
pub fn is_local_health_host(header_str: &str) -> bool {
    let mut seen_host = false;
    for line in header_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("host") {
            continue;
        }
        seen_host = true;
        let Ok((host, _)) = parse_authority(value, 80) else {
            return false;
        };
        let is_loopback = host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.to_canonical().is_loopback());
        if !is_loopback {
            return false;
        }
    }

    seen_host
}

/// Returns `true` when the request carries a browser `Origin` header or a cross-origin
/// `Sec-Fetch-Site` header (`cross-site`, `same-site`, or any value other than `none`/`same-origin`).
pub fn has_forbidden_browser_headers(header_str: &str) -> bool {
    for line in header_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("origin") {
            return true;
        }
        if name.eq_ignore_ascii_case("sec-fetch-site") {
            let val = value.trim();
            if !val.eq_ignore_ascii_case("none") && !val.eq_ignore_ascii_case("same-origin") {
                return true;
            }
        }
    }
    false
}

async fn write_health_response(client: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(HEALTH_WRITE_TIMEOUT, async {
        client.write_all(bytes).await?;
        client.flush().await?;
        let _ = client.shutdown().await;
        Ok::<(), std::io::Error>(())
    })
    .await??;
    Ok(())
}

async fn write_health_overload_response(mut client: TcpStream) {
    let _ = client.set_nodelay(true);
    let _ = tokio::time::timeout(HEALTH_OVERLOAD_WRITE_TIMEOUT, async {
        client.write_all(HEALTH_OVERLOAD_RESPONSE).await?;
        client.flush().await?;
        let _ = client.shutdown().await;
        Ok::<(), std::io::Error>(())
    })
    .await;
}

/// Handles a `/vdpi-health` HTTP request, enforcing loopback peer, loopback `Host` header,
/// no cross-origin browser headers, `GET`-only method, and a 3-second write timeout.
pub async fn handle_health_http_request(
    client: &mut TcpStream,
    method: &str,
    header_str: &str,
    ctx: &EngineContext,
    meta: &HealthRuntimeMeta,
) -> Result<()> {
    let is_loopback_peer = client
        .peer_addr()
        .is_ok_and(|p| p.ip().to_canonical().is_loopback());
    if !is_loopback_peer
        || !is_local_health_host(header_str)
        || has_forbidden_browser_headers(header_str)
    {
        let _ = write_health_response(
            client,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    if !method.eq_ignore_ascii_case("GET") {
        let _ = write_health_response(
            client,
            b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    let body = render_health_json(ctx, meta);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    write_health_response(client, resp.as_bytes()).await
}

/// Strictly binds a loopback (`127.0.0.1`) TCP listener for standalone TUN health probes,
/// rotating across `[preferred_port, 18089, 18090, 18091, 28089, 0]`.
pub fn bind_loopback_health_listener(preferred_port: u16) -> Result<std::net::TcpListener> {
    let mut candidates = Vec::with_capacity(6);
    candidates.push(preferred_port);
    for port in HEALTH_FALLBACK_PORTS {
        if !candidates.contains(&port) {
            candidates.push(port);
        }
    }

    let mut last_err = None;
    for port in candidates {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        match bind_loopback_std_listener(addr) {
            Ok(listener) => return Ok(listener),
            Err(e) if matches!(e.kind(), ErrorKind::AddrInUse | ErrorKind::PermissionDenied) => {
                debug!(%addr, error = %e, "loopback health port busy or reserved; trying next");
                last_err = Some(e);
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to bind loopback health listener on {addr}"));
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| {
            std::io::Error::new(
                ErrorKind::AddrInUse,
                "all loopback health ports unavailable",
            )
        })
        .into())
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

fn bind_loopback_std_listener(addr: SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(windows)]
    set_exclusive_addr_use(&sock)?;
    #[cfg(not(windows))]
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(64)?;
    Ok(sock.into())
}

/// Serves the standalone loopback `/vdpi-health` endpoint until `shutdown_rx` signals `true`
/// or its sender is dropped.
pub async fn serve_health_until_shutdown(
    listener: std::net::TcpListener,
    ctx: EngineContext,
    meta_fn: HealthMetaFn,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if let Err(e) = listener.set_nonblocking(true) {
        warn!(error = %e, "failed to configure loopback health listener nonblocking");
        return;
    }
    let listener = match TcpListener::from_std(listener) {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, "failed to adopt loopback health listener");
            return;
        }
    };

    let slots = Arc::new(Semaphore::new(MAX_STANDALONE_HEALTH_SESSIONS));
    let mut sessions = JoinSet::new();
    let shutdown = async { drop(shutdown_rx.wait_for(|stopped| *stopped).await) };
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(result) = sessions.join_next() => {
                if let Err(e) = result {
                    warn!(error = %e, "health session task failed");
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) => {
                        let Ok(slot) = slots.clone().try_acquire_owned() else {
                            debug!(%peer, "standalone health session limit reached; returning 503");
                            tokio::select! {
                                biased;
                                _ = &mut shutdown => break,
                                _ = write_health_overload_response(stream) => {}
                            }
                            continue;
                        };
                        let conn_ctx = ctx.clone();
                        let conn_meta_fn = Arc::clone(&meta_fn);
                        sessions.spawn(async move {
                            let _slot = slot;
                            if let Err(e) =
                                handle_standalone_health_connection(stream, conn_ctx, conn_meta_fn)
                                    .await
                            {
                                debug!(%peer, error = %e, "standalone health connection closed with error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "loopback health listener accept error");
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

async fn handle_standalone_health_connection(
    mut stream: TcpStream,
    ctx: EngineContext,
    meta_fn: HealthMetaFn,
) -> Result<()> {
    let _ = stream.set_nodelay(true);

    let mut buf = Vec::with_capacity(512);
    let mut temp = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + HEALTH_READ_TIMEOUT;
    let mut scan_from = 0;

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf[scan_from..]) {
            break scan_from + pos;
        }
        if buf.len() >= MAX_HEALTH_REQUEST_BYTES {
            let _ = write_health_response(
                &mut stream,
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            return Ok(());
        }
        scan_from = buf.len().saturating_sub(3);
        let read_limit = temp.len().min(MAX_HEALTH_REQUEST_BYTES - buf.len());
        let n = tokio::time::timeout_at(deadline, stream.read(&mut temp[..read_limit])).await??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&temp[..n]);
    };

    let header_bytes = &buf[..header_end];
    if has_bare_lf(header_bytes) {
        let _ = write_health_response(
            &mut stream,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    let Ok(header_str) = std::str::from_utf8(header_bytes) else {
        let _ = write_health_response(
            &mut stream,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    };

    let first_line = header_str
        .lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.is_empty() || target.is_empty() {
        let _ = write_health_response(
            &mut stream,
            b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    if target != "/vdpi-health" {
        let is_loopback_peer = stream
            .peer_addr()
            .is_ok_and(|p| p.ip().to_canonical().is_loopback());
        if !is_loopback_peer
            || !is_local_health_host(header_str)
            || has_forbidden_browser_headers(header_str)
        {
            let _ = write_health_response(
                &mut stream,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            return Ok(());
        }
        let _ = write_health_response(
            &mut stream,
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    let meta = meta_fn();
    handle_health_http_request(&mut stream, method, header_str, &ctx, &meta).await
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn has_bare_lf(header_bytes: &[u8]) -> bool {
    header_bytes
        .iter()
        .enumerate()
        .any(|(i, &b)| b == b'\n' && (i == 0 || header_bytes[i - 1] != b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desync::LearnedStrategy;
    use std::sync::atomic::Ordering;
    use vdpi_core::config::{DesyncMode, RuntimeConfig};

    fn test_engine_context() -> EngineContext {
        let cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: false,
            block_quic: true,
            ..Default::default()
        };
        let ctx = EngineContext::new(cfg).unwrap();
        ctx.telemetry.active_connections.store(3, Ordering::Relaxed);
        ctx.telemetry.total_connections.store(42, Ordering::Relaxed);
        ctx.telemetry.bytes_tx.store(1024, Ordering::Relaxed);
        ctx.telemetry.bytes_rx.store(8192, Ordering::Relaxed);
        ctx.telemetry.tls_handshakes.store(11, Ordering::Relaxed);
        ctx.telemetry
            .auto_heal_escalations
            .store(2, Ordering::Relaxed);
        ctx.telemetry.learned_hosts.store(5, Ordering::Relaxed);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::MultiRecordOob as u8, Ordering::Relaxed);
        ctx.set_udp_flows_active(7);
        ctx.inc_quic_blocked();
        ctx.inc_quic_blocked();
        ctx
    }

    async fn send_raw_http(addr: SocketAddr, request: &[u8]) -> String {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(request).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        String::from_utf8(resp).unwrap()
    }

    #[test]
    fn render_health_json_includes_v042_and_v050_fields_for_proxy_and_tun() {
        let ctx = test_engine_context();

        let proxy_meta = HealthRuntimeMeta {
            engine: EngineMode::Proxy,
            ..Default::default()
        };
        let proxy_body = render_health_json(&ctx, &proxy_meta);
        let proxy_json: serde_json::Value = serde_json::from_str(&proxy_body).unwrap();
        assert_eq!(proxy_json["status"].as_str(), Some("ok"));
        assert_eq!(proxy_json["service"].as_str(), Some("vdpi"));
        assert_eq!(
            proxy_json["version"].as_str(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(proxy_json["mode"].as_str(), Some("tls-record"));
        assert_eq!(proxy_json["doh"].as_bool(), Some(false));
        assert_eq!(proxy_json["block_quic"].as_bool(), Some(true));
        assert_eq!(proxy_json["active_connections"].as_u64(), Some(3));
        assert_eq!(proxy_json["total_connections"].as_u64(), Some(42));
        assert_eq!(proxy_json["bytes_tx"].as_u64(), Some(1024));
        assert_eq!(proxy_json["bytes_rx"].as_u64(), Some(8192));
        assert_eq!(proxy_json["tls_handshakes"].as_u64(), Some(11));
        assert_eq!(proxy_json["auto_heal_escalations"].as_u64(), Some(2));
        assert_eq!(proxy_json["learned_hosts"].as_u64(), Some(5));
        assert_eq!(proxy_json["isp_stage"].as_str(), Some("MultiRecordOob"));
        assert_eq!(proxy_json["engine"].as_str(), Some("proxy"));
        assert!(proxy_json["tun_interface"].is_null());
        assert!(proxy_json["physical_nic"].is_null());
        assert!(proxy_json["vpn_conflict"].is_null());
        assert_eq!(proxy_json["dns_addr"].as_str(), Some("1.1.1.1"));
        assert_eq!(proxy_json["udp_flows_active"].as_u64(), Some(7));
        assert_eq!(proxy_json["quic_blocked"].as_u64(), Some(2));
        assert_eq!(proxy_json["dns_queries"].as_u64(), Some(0));
        assert!(proxy_json.get("rss_kb").is_some());

        ctx.set_udp_flows_active(14);
        ctx.inc_quic_blocked();

        let tun_meta = HealthRuntimeMeta {
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: Some("WireGuard".to_string()),
            dns_addr: Some("https://dns.nextdns.io/secret123?token=xyz#frag".to_string()),
        };
        let tun_body = render_health_json(&ctx, &tun_meta);
        let tun_json: serde_json::Value = serde_json::from_str(&tun_body).unwrap();
        assert_eq!(tun_json["status"].as_str(), Some("ok"));
        assert_eq!(tun_json["service"].as_str(), Some("vdpi"));
        assert_eq!(tun_json["doh"].as_bool(), Some(false));
        assert_eq!(tun_json["engine"].as_str(), Some("tun"));
        assert_eq!(tun_json["tun_interface"].as_str(), Some("vdpi0"));
        assert_eq!(tun_json["physical_nic"].as_str(), Some("Ethernet"));
        assert_eq!(tun_json["vpn_conflict"].as_str(), Some("WireGuard"));
        assert_eq!(
            tun_json["dns_addr"].as_str(),
            Some("https://dns.nextdns.io")
        );
        assert_eq!(tun_json["udp_flows_active"].as_u64(), Some(14));
        assert_eq!(tun_json["quic_blocked"].as_u64(), Some(3));
        assert_eq!(tun_json["dns_queries"].as_u64(), Some(0));
    }

    #[test]
    fn redact_dns_addr_strips_doh_path_query_and_userinfo() {
        assert_eq!(redact_dns_addr_for_health("1.1.1.1"), "1.1.1.1");
        assert_eq!(redact_dns_addr_for_health("9.9.9.9:53"), "9.9.9.9:53");
        assert_eq!(
            redact_dns_addr_for_health("https://dns.nextdns.io/abc123?device=pc"),
            "https://dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_addr_for_health("HTTPS://user:secret@dns.example.com:8443/dns-query?k=v"),
            "https://dns.example.com:8443"
        );
    }

    #[test]
    fn redact_dns_addr_handles_ipv6_bracketed_doh_and_malformed_urls() {
        assert_eq!(
            redact_dns_addr_for_health("https://[2606:4700:4700::1111]/secret"),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(
            redact_dns_addr_for_health(
                "https://[2606:4700:4700::1111]:8443/secret?token=xyz#frag"
            ),
            "https://[2606:4700:4700::1111]:8443"
        );
        assert_eq!(
            redact_dns_addr_for_health(
                "HTTPS://user:secret@[2606:4700:4700::1111]:8443/dns-query?k=v"
            ),
            "https://[2606:4700:4700::1111]:8443"
        );
        assert_eq!(
            redact_dns_addr_for_health("https://[2606:4700:4700::ABCD]/secret"),
            "https://[2606:4700:4700::abcd]"
        );
        assert_eq!(
            redact_dns_addr_for_health("https://dns.example.com\\secret-token"),
            "https://dns.example.com"
        );

        for malformed in [
            "https://",
            "https:///secret-token",
            "https://?token=secret",
            "https://#secret",
            "https://user:secret@",
            "https://user:secret/secret-path",
            "https://[2606:4700:4700::1111/secret",
            "https://[2606:4700:4700::1111]junk/secret",
            "https://[not-ipv6]/secret",
            "https://[2606:4700:4700::1111]:badport/secret",
            "https://2606:4700:4700::1111/secret",
            "https://dns.example.com:badport/secret",
            "https://dns.example.com:0/secret",
            "https:user:secret@dns.example.com/token",
        ] {
            let redacted = redact_dns_addr_for_health(malformed);
            assert_eq!(
                redacted, "https://<redacted>",
                "malformed URL should redact safely: {malformed}"
            );
            assert!(!redacted.contains("secret"));
            assert!(!redacted.contains("token"));
            assert!(!redacted.contains("user"));
        }

        let spaced = redact_dns_addr_for_health("https://user:secret@host with space/token");
        assert_eq!(spaced, "https://host");
        assert!(!spaced.contains("secret"));
        assert!(!spaced.contains("token"));
        assert!(!spaced.contains("user"));

        let non_https = redact_dns_addr_for_health("http://user:secret@dns.example.com/token");
        assert_eq!(non_https, "http://dns.example.com");
        assert!(!non_https.contains("secret"));
        assert!(!non_https.contains("token"));
        assert!(!non_https.contains("user"));
    }

    #[test]
    fn render_health_json_reports_effective_doh_true_when_no_doh_with_https_url() {
        let host_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: false,
            dns_addr: "https://dns.nextdns.io/secret123".to_string(),
            ..Default::default()
        };
        let host_ctx = EngineContext::new(host_cfg).unwrap();
        let proxy_meta = HealthRuntimeMeta {
            engine: EngineMode::Proxy,
            ..Default::default()
        };
        let host_body = render_health_json(&host_ctx, &proxy_meta);
        let host_json: serde_json::Value = serde_json::from_str(&host_body).unwrap();
        assert_eq!(host_json["doh"].as_bool(), Some(true));
        assert_eq!(
            host_json["dns_addr"].as_str(),
            Some("https://dns.nextdns.io")
        );

        let v6_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: false,
            dns_addr: "https://[2606:4700:4700::1111]/secret".to_string(),
            ..Default::default()
        };
        let v6_ctx = EngineContext::new(v6_cfg).unwrap();
        let tun_meta = HealthRuntimeMeta {
            engine: EngineMode::Tun,
            ..Default::default()
        };
        let v6_body = render_health_json(&v6_ctx, &tun_meta);
        let v6_json: serde_json::Value = serde_json::from_str(&v6_body).unwrap();
        assert_eq!(v6_json["doh"].as_bool(), Some(true));
        assert_eq!(
            v6_json["dns_addr"].as_str(),
            Some("https://[2606:4700:4700::1111]")
        );

        let udp_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: false,
            dns_addr: "1.1.1.1".to_string(),
            ..Default::default()
        };
        let udp_ctx = EngineContext::new(udp_cfg).unwrap();
        let udp_body = render_health_json(&udp_ctx, &proxy_meta);
        let udp_json: serde_json::Value = serde_json::from_str(&udp_body).unwrap();
        assert_eq!(udp_json["doh"].as_bool(), Some(false));
        assert_eq!(udp_json["dns_addr"].as_str(), Some("1.1.1.1"));

        // Bare custom non-DoH IP reports doh: false even when enable_doh=true.
        let bare_custom_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: true,
            dns_addr: "76.76.2.0".to_string(),
            ..Default::default()
        };
        let bare_custom_ctx = EngineContext::new(bare_custom_cfg).unwrap();
        let bare_custom_body = render_health_json(&bare_custom_ctx, &proxy_meta);
        let bare_custom_json: serde_json::Value = serde_json::from_str(&bare_custom_body).unwrap();
        assert_eq!(bare_custom_json["doh"].as_bool(), Some(false));
        assert_eq!(bare_custom_json["dns_addr"].as_str(), Some("76.76.2.0"));

        // Known public DoH IP with enable_doh=true reports doh: true.
        let quad9_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: true,
            dns_addr: "9.9.9.9".to_string(),
            ..Default::default()
        };
        let quad9_ctx = EngineContext::new(quad9_cfg).unwrap();
        let quad9_body = render_health_json(&quad9_ctx, &proxy_meta);
        let quad9_json: serde_json::Value = serde_json::from_str(&quad9_body).unwrap();
        assert_eq!(quad9_json["doh"].as_bool(), Some(true));
        assert_eq!(quad9_json["dns_addr"].as_str(), Some("9.9.9.9"));

        // Malformed https:// URL reports doh: false and redacts safely.
        let malformed_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: true,
            dns_addr: "https://".to_string(),
            ..Default::default()
        };
        let malformed_ctx = EngineContext::new(malformed_cfg).unwrap();
        let malformed_body = render_health_json(&malformed_ctx, &proxy_meta);
        let malformed_json: serde_json::Value = serde_json::from_str(&malformed_body).unwrap();
        assert_eq!(malformed_json["doh"].as_bool(), Some(false));
        assert_eq!(
            malformed_json["dns_addr"].as_str(),
            Some("https://<redacted>")
        );
    }

    #[test]
    fn is_local_health_host_validates_loopback_and_host_requirement_for_all_versions() {
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: localhost\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: LocalHost:18089\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.2:18089\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: [::1]\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: [::1]:18089\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: [::ffff:127.0.0.1]:18089\r\n\r\n"
        ));
        assert!(is_local_health_host(
            "GET /vdpi-health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n"
        ));

        // All HTTP versions (including HTTP/1.0) require a valid loopback Host header.
        assert!(!is_local_health_host("GET /vdpi-health HTTP/1.0\r\n\r\n"));
        assert!(!is_local_health_host("GET /vdpi-health HTTP/1.1\r\n\r\n"));
        assert!(!is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: evil.example\r\n\r\n"
        ));
        assert!(!is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: 192.168.1.10:18089\r\n\r\n"
        ));
        assert!(!is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nHost: evil.example\r\n\r\n"
        ));
        assert!(!is_local_health_host(
            "GET /vdpi-health HTTP/1.1\r\nHost:\r\n\r\n"
        ));
    }

    #[test]
    fn has_forbidden_browser_headers_blocks_origin_and_cross_site_fetch() {
        assert!(!has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
        ));
        assert!(!has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: none\r\n\r\n"
        ));
        assert!(!has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-origin\r\n\r\n"
        ));
        assert!(has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n\r\n"
        ));
        assert!(has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: null\r\n\r\n"
        ));
        assert!(has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n\r\n"
        ));
        assert!(has_forbidden_browser_headers(
            "GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: same-site\r\n\r\n"
        ));
    }

    #[test]
    fn read_self_rss_kb_reports_nonzero_memory_on_desktop_os() {
        let rss = read_self_rss_kb();
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        {
            let kb = rss.expect("desktop OS should report current process RSS in KiB");
            assert!(kb > 0, "expected positive process RSS, got {kb}");
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            assert!(rss.is_none());
        }
    }

    #[test]
    fn bind_loopback_health_listener_binds_localhost_and_rotates_busy_port() {
        let occupied = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let busy_port = occupied.local_addr().unwrap().port();

        let bound = bind_loopback_health_listener(busy_port).unwrap();
        let addr = bound.local_addr().unwrap();
        assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);
        assert_ne!(addr.port(), 0);
        assert_ne!(addr.port(), busy_port);
    }

    #[tokio::test]
    async fn standalone_loopback_health_listener_serves_200_404_405_403_and_shuts_down() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let ctx = test_engine_context();
            let listener = bind_loopback_health_listener(0).unwrap();
            let addr = listener.local_addr().unwrap();
            assert_eq!(addr.ip(), Ipv4Addr::LOCALHOST);

            let meta_fn: HealthMetaFn = Arc::new(|| HealthRuntimeMeta {
                engine: EngineMode::Tun,
                tun_interface: Some("utun9".to_string()),
                physical_nic: Some("en0".to_string()),
                vpn_conflict: None,
                dns_addr: Some("https://dns.nextdns.io/secret-id?k=v".to_string()),
            });
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let server = tokio::spawn(serve_health_until_shutdown(
                listener,
                ctx,
                meta_fn,
                shutdown_rx,
            ));

            // 200 OK on GET /vdpi-health with loopback Host
            let ok_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .await;
            let (headers, body) = ok_resp.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
            assert!(headers.contains("Content-Type: application/json\r\n"));
            assert!(headers.contains("Cache-Control: no-store\r\n"));
            assert!(headers.contains("X-Content-Type-Options: nosniff\r\n"));
            assert!(headers.contains("Cross-Origin-Resource-Policy: same-origin\r\n"));
            let json: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(json["status"].as_str(), Some("ok"));
            assert_eq!(json["service"].as_str(), Some("vdpi"));
            assert_eq!(json["engine"].as_str(), Some("tun"));
            assert_eq!(json["tun_interface"].as_str(), Some("utun9"));
            assert_eq!(json["physical_nic"].as_str(), Some("en0"));
            assert!(json["vpn_conflict"].is_null());
            assert_eq!(json["dns_addr"].as_str(), Some("https://dns.nextdns.io"));
            assert_eq!(json["active_connections"].as_u64(), Some(3));
            assert_eq!(json["total_connections"].as_u64(), Some(42));
            assert_eq!(json["udp_flows_active"].as_u64(), Some(7));
            assert_eq!(json["quic_blocked"].as_u64(), Some(2));
            assert_eq!(json["dns_queries"].as_u64(), Some(0));

            // 200 OK on non-127.0.0.1 loopback Host (127.0.0.2) and IPv6 loopback ([::1])
            let alt_loopback_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.2:18089\r\n\r\n",
            )
            .await;
            assert!(alt_loopback_resp.starts_with("HTTP/1.1 200 OK\r\n"));

            let v6_loopback_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: [::1]:18089\r\n\r\n",
            )
            .await;
            assert!(v6_loopback_resp.starts_with("HTTP/1.1 200 OK\r\n"));

            // 403 Forbidden on HTTP/1.1 and HTTP/1.0 requests missing Host header
            let missing_host_resp = send_raw_http(addr, b"GET /vdpi-health HTTP/1.1\r\n\r\n").await;
            assert!(missing_host_resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            let missing_host_10 = send_raw_http(addr, b"GET /vdpi-health HTTP/1.0\r\n\r\n").await;
            assert!(missing_host_10.starts_with("HTTP/1.1 403 Forbidden\r\n"));

            // 403 Forbidden on Origin or cross-site Sec-Fetch-Site headers
            let origin_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n\r\n",
            )
            .await;
            assert!(origin_resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));
            let cross_site_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\nSec-Fetch-Site: cross-site\r\n\r\n",
            )
            .await;
            assert!(cross_site_resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));

            // 400 Bad Request on bare LF header smuggling
            let bare_lf_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\nX-Smuggled: 1\r\n\r\n",
            )
            .await;
            assert!(bare_lf_resp.starts_with("HTTP/1.1 400 Bad Request\r\n"));

            // 404 Not Found on non-health path
            let not_found_resp =
                send_raw_http(addr, b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
            assert!(not_found_resp.starts_with("HTTP/1.1 404 Not Found\r\n"));

            // 405 Method Not Allowed on POST /vdpi-health
            let post_resp = send_raw_http(
                addr,
                b"POST /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .await;
            assert!(post_resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
            assert!(post_resp.contains("Allow: GET\r\n"));

            // 403 Forbidden on non-loopback Host header (DNS rebinding guard)
            let forbidden_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            )
            .await;
            assert!(forbidden_resp.starts_with("HTTP/1.1 403 Forbidden\r\n"));

            shutdown_tx.send(true).unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn render_health_json_prefers_meta_dns_addr_for_both_doh_and_redaction() {
        // Config is plain UDP 1.1.1.1 with enable_doh=false, but live meta overrides to DoH URL.
        let udp_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: false,
            dns_addr: "1.1.1.1".to_string(),
            ..Default::default()
        };
        let udp_ctx = EngineContext::new(udp_cfg).unwrap();
        let doh_meta = HealthRuntimeMeta {
            engine: EngineMode::Tun,
            dns_addr: Some("https://dns.nextdns.io/secret-profile?k=v".to_string()),
            ..Default::default()
        };
        let doh_json: serde_json::Value =
            serde_json::from_str(&render_health_json(&udp_ctx, &doh_meta)).unwrap();
        assert_eq!(doh_json["doh"].as_bool(), Some(true));
        assert_eq!(
            doh_json["dns_addr"].as_str(),
            Some("https://dns.nextdns.io")
        );

        // Config is DoH-capable 1.1.1.1 with enable_doh=true, but live meta overrides to custom non-DoH IP.
        let doh_cfg = RuntimeConfig {
            mode: DesyncMode::TlsRecord,
            enable_doh: true,
            dns_addr: "1.1.1.1".to_string(),
            ..Default::default()
        };
        let doh_ctx = EngineContext::new(doh_cfg).unwrap();
        let custom_ip_meta = HealthRuntimeMeta {
            engine: EngineMode::Tun,
            dns_addr: Some("76.76.2.0".to_string()),
            ..Default::default()
        };
        let custom_json: serde_json::Value =
            serde_json::from_str(&render_health_json(&doh_ctx, &custom_ip_meta)).unwrap();
        assert_eq!(custom_json["doh"].as_bool(), Some(false));
        assert_eq!(custom_json["dns_addr"].as_str(), Some("76.76.2.0"));
    }

    #[tokio::test]
    async fn standalone_loopback_health_listener_returns_503_when_saturated() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let ctx = test_engine_context();
            let listener = bind_loopback_health_listener(0).unwrap();
            let addr = listener.local_addr().unwrap();
            let meta_fn: HealthMetaFn = Arc::new(HealthRuntimeMeta::default);
            let (shutdown_tx, shutdown_rx) = watch::channel(false);
            let server = tokio::spawn(serve_health_until_shutdown(
                listener,
                ctx,
                meta_fn,
                shutdown_rx,
            ));

            let mut held = Vec::with_capacity(MAX_STANDALONE_HEALTH_SESSIONS);
            for _ in 0..MAX_STANDALONE_HEALTH_SESSIONS {
                let mut stream = TcpStream::connect(addr).await.unwrap();
                // Incomplete HTTP request holds the session permit until closed or read-timed-out.
                stream.write_all(b"GET /vdpi-health ").await.unwrap();
                held.push(stream);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;

            let overload_resp = send_raw_http(
                addr,
                b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            )
            .await;
            assert!(
                overload_resp.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
                "expected 503 Service Unavailable when saturated, got: {overload_resp:?}"
            );

            drop(held);
            shutdown_tx.send(true).unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
}
