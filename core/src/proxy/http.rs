use super::{
    check_split_tunnel_bypass, is_forbidden_proxy_host, is_forbidden_remote_addr,
    relay_direct_tunnel, relay_direct_with_initial, HANDSHAKE_TIMEOUT,
};
use crate::desync::EngineContext;
use crate::health::{
    handle_health_http_request, has_forbidden_browser_headers, is_local_health_host,
    HealthRuntimeMeta,
};
use crate::platform::vpn::{detect_active_vpn, VpnScope};
use crate::tls::expected_tls_record_len;
use anyhow::{anyhow, bail, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;
use vdpi_core::bypass::IpNet;
use vdpi_core::config::{EngineMode, VpnCoexistence};

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
const PAC_WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const VPN_CONFLICT_CACHE_TTL: Duration = Duration::from_secs(5);
const VPN_CONFLICT_COLD_WAIT: Duration = Duration::from_millis(50);

struct VpnConflictCache {
    last_checked: Option<Instant>,
    scope: VpnScope,
    refreshing: bool,
    generation: u64,
}

static VPN_CONFLICT_CACHE: OnceLock<Mutex<VpnConflictCache>> = OnceLock::new();

fn vpn_conflict_cache() -> &'static Mutex<VpnConflictCache> {
    VPN_CONFLICT_CACHE.get_or_init(|| {
        Mutex::new(VpnConflictCache {
            last_checked: None,
            scope: VpnScope::None,
            refreshing: false,
            generation: 0,
        })
    })
}

fn format_proxy_vpn_conflict(policy: VpnCoexistence, scope: &VpnScope) -> Option<String> {
    let provider = scope
        .full_tunnel_provider()
        .map(str::trim)
        .filter(|p| !p.is_empty())?;
    match policy {
        VpnCoexistence::Off => None,
        VpnCoexistence::Warn => Some(format!("{provider} (warn)")),
        VpnCoexistence::AutoYield => Some(provider.to_string()),
    }
}

async fn resolve_proxy_vpn_conflict(policy: VpnCoexistence) -> Option<String> {
    if policy == VpnCoexistence::Off {
        return None;
    }

    let now = Instant::now();
    let (cached_scope, is_cold, should_refresh, expected_gen) = {
        let mut cache = vpn_conflict_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let is_cold = cache.last_checked.is_none();
        let is_stale = cache
            .last_checked
            .is_none_or(|t| now.saturating_duration_since(t) >= VPN_CONFLICT_CACHE_TTL);
        let should_refresh = is_stale && !cache.refreshing;
        if should_refresh {
            cache.refreshing = true;
        }
        (
            cache.scope.clone(),
            is_cold,
            should_refresh,
            cache.generation,
        )
    };

    if should_refresh {
        let handle = tokio::task::spawn_blocking(move || {
            struct RefreshResetGuard {
                expected_gen: u64,
            }
            impl Drop for RefreshResetGuard {
                fn drop(&mut self) {
                    let mut cache = vpn_conflict_cache()
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    if cache.generation == self.expected_gen {
                        cache.refreshing = false;
                    }
                }
            }

            let reset_guard = RefreshResetGuard { expected_gen };
            let detected = detect_active_vpn(None);
            {
                let mut cache = vpn_conflict_cache()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if cache.generation == expected_gen {
                    cache.scope = detected.clone();
                    cache.last_checked = Some(Instant::now());
                    cache.refreshing = false;
                }
            }
            std::mem::forget(reset_guard);
            detected
        });

        if is_cold {
            if let Ok(Ok(detected)) = tokio::time::timeout(VPN_CONFLICT_COLD_WAIT, handle).await {
                return format_proxy_vpn_conflict(policy, &detected);
            }
        }
    }

    format_proxy_vpn_conflict(policy, &cached_scope)
}

async fn write_http_error_and_shutdown(client: &mut TcpStream, response: &[u8]) {
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        client.write_all(response).await?;
        client.flush().await?;
        client.shutdown().await
    })
    .await;
}

async fn complete_pipelined_tls_record(client: &mut TcpStream, initial: &mut Vec<u8>) {
    if !initial.is_empty()
        && initial.len() < 5
        && initial[0] == 0x16
        && (initial.len() == 1 || initial[1] == 0x03)
        && (initial.len() < 3 || initial[2] <= 0x04)
    {
        let mut cur = initial.len();
        initial.resize(5, 0);
        let _ = tokio::time::timeout(Duration::from_millis(200), async {
            while cur < 5 {
                let n = client.read(&mut initial[cur..5]).await?;
                if n == 0 {
                    break;
                }
                cur += n;
                if (cur >= 2 && initial[1] != 0x03) || (cur >= 3 && initial[2] > 0x04) {
                    break;
                }
            }
            Ok::<(), std::io::Error>(())
        })
        .await;
        initial.truncate(cur);
    }

    if let Some(expected_len) = expected_tls_record_len(initial) {
        if expected_len <= 16896 && initial.len() < expected_len {
            let start = initial.len();
            initial.resize(expected_len, 0);
            let mut cur = start;
            let _ = tokio::time::timeout(Duration::from_millis(400), async {
                while cur < expected_len {
                    let n = client.read(&mut initial[cur..expected_len]).await?;
                    if n == 0 {
                        break;
                    }
                    cur += n;
                }
                Ok::<(), std::io::Error>(())
            })
            .await;
            initial.truncate(cur);
        }
    }
}

/// Handles an incoming HTTP/1.x proxy request or `CONNECT` tunnel on `client`.
pub async fn handle_http_client(client: TcpStream, ctx: EngineContext) -> Result<()> {
    handle_http_client_with_timeout(client, ctx, HANDSHAKE_TIMEOUT).await
}

async fn handle_http_client_with_timeout(
    mut client: TcpStream,
    ctx: EngineContext,
    handshake_timeout: Duration,
) -> Result<()> {
    let _ = client.set_nodelay(true);

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + handshake_timeout;
    let mut scan_from = 0;

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf[scan_from..]) {
            break scan_from + pos;
        }
        if buf.len() >= MAX_HTTP_HEADER_BYTES {
            write_http_error_and_shutdown(
                &mut client,
                b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            bail!("HTTP header exceeded {MAX_HTTP_HEADER_BYTES} bytes");
        }
        scan_from = buf.len().saturating_sub(3);
        let read_limit = temp.len().min(MAX_HTTP_HEADER_BYTES - buf.len());
        let n = match tokio::time::timeout_at(deadline, client.read(&mut temp[..read_limit])).await
        {
            Ok(res) => res?,
            Err(_) => {
                write_http_error_and_shutdown(
                    &mut client,
                    b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
                bail!("HTTP request header timed out after {handshake_timeout:?}");
            }
        };
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&temp[..n]);
    };

    let header_bytes = &buf[..header_end];
    let leftover = &buf[header_end..];
    if has_bare_lf(header_bytes) {
        write_http_error_and_shutdown(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        )
        .await;
        bail!("bare LF in HTTP request header");
    }
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            write_http_error_and_shutdown(
                &mut client,
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
            )
            .await;
            bail!("non-UTF8 HTTP request header");
        }
    };

    let first_line = header_str
        .lines()
        .next()
        .unwrap_or("")
        .trim_end_matches('\r');
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("HTTP/1.1");

    if !is_valid_http_method(method) || target.is_empty() {
        write_http_error_and_shutdown(
            &mut client,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
        )
        .await;
        bail!("malformed HTTP request line");
    }

    let peer_addr = client.peer_addr().ok();
    let is_loopback_peer = peer_addr.is_some_and(|p| p.ip().to_canonical().is_loopback());
    let local_addr = client.local_addr().ok();

    // Built-in local health endpoint for `vdpi status` / `vdpi doctor` / Control Center TUI
    if target == "/vdpi-health" {
        let redacted_dns = vdpi_core::dns::redact_dns_for_display(&ctx.config.dns_addr);
        let effective_doh =
            vdpi_core::dns::is_effective_doh_target(&ctx.config.dns_addr, ctx.config.enable_doh);
        let vpn_conflict = if is_loopback_peer
            && method.eq_ignore_ascii_case("GET")
            && is_local_health_host(header_str)
            && !has_forbidden_browser_headers(header_str)
        {
            resolve_proxy_vpn_conflict(ctx.config.vpn_coexistence).await
        } else {
            None
        };
        let meta = HealthRuntimeMeta {
            engine: EngineMode::Proxy,
            vpn_conflict,
            dns_addr: (!redacted_dns.is_empty()).then_some(redacted_dns),
            ..Default::default()
        };
        let health_ctx = if effective_doh != ctx.config.enable_doh {
            let mut updated = ctx.clone();
            let mut cfg = (*ctx.config).clone();
            cfg.enable_doh = effective_doh;
            updated.config = Arc::new(cfg);
            updated
        } else {
            ctx
        };
        return handle_health_http_request(&mut client, method, header_str, &health_ctx, &meta)
            .await;
    }

    // Built-in fail-open PAC endpoint for Windows/macOS system proxy auto-config
    if is_local_pac_request_target(target, local_addr) {
        return handle_pac_http_request(&mut client, method, header_str, &ctx).await;
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = match parse_authority(target, 443) {
            Ok(hp) => hp,
            Err(e) => {
                write_http_error_and_shutdown(
                    &mut client,
                    b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
                )
                .await;
                return Err(e);
            }
        };
        if is_forbidden_proxy_host(is_loopback_peer, &host, port, local_addr) {
            let status = if is_loopback_peer {
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            } else {
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            };
            write_http_error_and_shutdown(&mut client, status).await;
            bail!("forbidden HTTP CONNECT target '{host}:{port}'");
        }

        let split_bypass = check_split_tunnel_bypass(&ctx, peer_addr).await;
        debug!(host = %host, port = port, "HTTP CONNECT request");
        match connect_http_target(&ctx, &host, port, is_loopback_peer, local_addr).await {
            Ok((remote, remote_addr)) => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                client.flush().await?;

                if let Some(bypass) = split_bypass {
                    bypass.log_bypass(&host);
                    if !leftover.is_empty() {
                        let initial = leftover.to_vec();
                        drop(buf);
                        return relay_direct_with_initial(&ctx, client, remote, initial).await;
                    }
                    drop(buf);
                    return relay_direct_tunnel(&ctx, client, remote).await;
                }

                if !leftover.is_empty() {
                    let mut initial = leftover.to_vec();
                    drop(buf);
                    complete_pipelined_tls_record(&mut client, &mut initial).await;
                    return ctx
                        .establish_and_relay(client, remote, &initial, Some(&host), remote_addr)
                        .await;
                }

                drop(buf);
                return ctx
                    .relay_tunnel(client, remote, Some(&host), remote_addr)
                    .await;
            }
            Err(ConnectTargetError::Forbidden(remote_addr)) => {
                let status = if is_loopback_peer {
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                } else {
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .as_slice()
                };
                write_http_error_and_shutdown(&mut client, status).await;
                bail!("forbidden resolved HTTP CONNECT target '{remote_addr}'");
            }
            Err(ConnectTargetError::Upstream(e)) => {
                debug!(host = %host, port = port, error = %e, "HTTP CONNECT upstream failed");
                write_http_error_and_shutdown(
                    &mut client,
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
                return Err(e);
            }
        }
    }

    // Standard plain HTTP proxy request (e.g. GET http://example.com/path HTTP/1.1)
    let (host, port, origin_path) = match parse_http_proxy_target(target, header_str) {
        Ok(res) => res,
        Err(e) => {
            write_http_error_and_shutdown(
                &mut client,
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n",
            )
            .await;
            return Err(e);
        }
    };
    if is_forbidden_proxy_host(is_loopback_peer, &host, port, local_addr) {
        let status = if is_loopback_peer {
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
        } else {
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice()
        };
        write_http_error_and_shutdown(&mut client, status).await;
        bail!("forbidden HTTP proxy target '{host}:{port}'");
    }

    let split_bypass = check_split_tunnel_bypass(&ctx, peer_addr).await;
    let rewritten = rewrite_http_request(method, &origin_path, version, header_str, leftover);
    drop(buf);
    match connect_http_target(&ctx, &host, port, is_loopback_peer, local_addr).await {
        Ok((remote, remote_addr)) => {
            if let Some(bypass) = split_bypass {
                bypass.log_bypass(&host);
                return relay_direct_with_initial(&ctx, client, remote, rewritten).await;
            }
            ctx.establish_and_relay(client, remote, &rewritten, Some(&host), remote_addr)
                .await
        }
        Err(ConnectTargetError::Forbidden(remote_addr)) => {
            let status = if is_loopback_peer {
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            } else {
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .as_slice()
            };
            write_http_error_and_shutdown(&mut client, status).await;
            bail!("forbidden resolved HTTP proxy target '{remote_addr}'");
        }
        Err(ConnectTargetError::Upstream(e)) => {
            write_http_error_and_shutdown(
                &mut client,
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            Err(e)
        }
    }
}

#[derive(Debug)]
enum ConnectTargetError {
    Forbidden(SocketAddr),
    Upstream(anyhow::Error),
}

/// Validates every resolved candidate IP against SSRF and self-reflection rules before
/// initiating any outbound TCP `connect()`.
fn validate_candidate_targets(
    is_loopback_peer: bool,
    ips: &[IpAddr],
    port: u16,
    local_addr: Option<SocketAddr>,
) -> std::result::Result<(), SocketAddr> {
    for &ip in ips {
        let candidate = SocketAddr::new(ip, port);
        if is_forbidden_remote_addr(is_loopback_peer, candidate, local_addr) {
            return Err(candidate);
        }
    }
    Ok(())
}

async fn connect_http_target(
    ctx: &EngineContext,
    host: &str,
    port: u16,
    is_loopback_peer: bool,
    local_addr: Option<SocketAddr>,
) -> std::result::Result<(TcpStream, SocketAddr), ConnectTargetError> {
    if is_loopback_peer {
        let (remote, remote_addr) = ctx
            .connect_target(host, port)
            .await
            .map_err(ConnectTargetError::Upstream)?;
        if is_forbidden_remote_addr(true, remote_addr, local_addr) {
            drop(remote);
            return Err(ConnectTargetError::Forbidden(remote_addr));
        }
        return Ok((remote, remote_addr));
    }

    // For non-loopback proxy peers, resolve DNS and check ALL candidate IPs BEFORE any TCP
    // connect() so clients cannot port-scan internal RFC1918/metadata hosts via TCP SYN
    // timing or 403-vs-502 status oracle, and connect directly to validated IPs to avoid
    // DNS-rebinding TOCTOU.
    let ips = ctx
        .dns
        .resolve(host)
        .await
        .with_context(|| format!("DNS resolution failed for {host}"))
        .map_err(ConnectTargetError::Upstream)?;
    if ips.is_empty() {
        return Err(ConnectTargetError::Upstream(anyhow!(
            "no addresses returned for {host}"
        )));
    }
    validate_candidate_targets(false, &ips, port, local_addr)
        .map_err(ConnectTargetError::Forbidden)?;

    let total_ips = ips.len();
    let mut last_err = None;
    for (idx, ip) in ips.into_iter().enumerate() {
        let target = SocketAddr::new(ip, port);
        let attempt_timeout = if idx + 1 < total_ips {
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

    Err(ConnectTargetError::Upstream(
        last_err.unwrap_or_else(|| anyhow!("failed to connect to {host}:{port}")),
    ))
}

async fn write_pac_response(client: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    tokio::time::timeout(PAC_WRITE_TIMEOUT, async {
        client.write_all(bytes).await?;
        client.flush().await?;
        let _ = client.shutdown().await;
        Ok::<(), std::io::Error>(())
    })
    .await??;
    Ok(())
}

fn is_pac_path(path: &str) -> bool {
    path.eq_ignore_ascii_case("/vdpi.pac")
        || (path.len() >= 10 && path.as_bytes()[..10].eq_ignore_ascii_case(b"/vdpi.pac?"))
}

fn is_pac_local_host_match(host: &str, local_addr: Option<SocketAddr>) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    let canonical = ip.to_canonical();
    if canonical.is_loopback() {
        return true;
    }
    local_addr.is_some_and(|local| {
        let local_ip = local.ip().to_canonical();
        !local_ip.is_unspecified() && canonical == local_ip
    })
}

fn is_local_pac_peer(peer_addr: Option<SocketAddr>, local_addr: Option<SocketAddr>) -> bool {
    let Some(peer_ip) = peer_addr.map(|p| p.ip().to_canonical()) else {
        return false;
    };
    if peer_ip.is_loopback() {
        return true;
    }
    local_addr.is_some_and(|local| {
        let local_ip = local.ip().to_canonical();
        !local_ip.is_unspecified() && peer_ip == local_ip
    })
}

fn is_local_pac_host(header_str: &str, local_addr: Option<SocketAddr>) -> bool {
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
        if !is_pac_local_host_match(&host, local_addr) {
            return false;
        }
    }
    seen_host
}

fn is_local_pac_request_target(target: &str, local_addr: Option<SocketAddr>) -> bool {
    if is_pac_path(target) {
        return true;
    }
    if target.len() >= 7 && target.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
        let rest = &target[7..];
        let Some(path_idx) = rest.find('/') else {
            return false;
        };
        let authority = &rest[..path_idx];
        let path = &rest[path_idx..];
        if !is_pac_path(path) {
            return false;
        }
        let default_port = local_addr.map_or(80, |a| a.port());
        let Ok((host, port)) = parse_authority(authority, default_port) else {
            return false;
        };
        let host_matches = is_pac_local_host_match(&host, local_addr);
        let port_matches = local_addr.is_none_or(|local| port == local.port());
        return host_matches && port_matches;
    }
    false
}

fn normalize_pac_ip(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) if v4.is_unspecified() => "127.0.0.1".to_string(),
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) if v6.is_unspecified() => "[::1]".to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

fn resolve_pac_proxy_authority(local_addr: Option<SocketAddr>, ctx: &EngineContext) -> String {
    let port = local_addr
        .map(|addr| addr.port())
        .filter(|&port| port != 0)
        .or_else(|| (ctx.config.port != 0).then_some(ctx.config.port))
        .unwrap_or(8080);

    let host = local_addr
        .map(|addr| normalize_pac_ip(addr.ip()))
        .unwrap_or_else(|| normalize_pac_ip(ctx.config.addr));

    format!("{host}:{port}")
}

fn escape_js_string(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const PAC_IPV6_CIDR_HELPERS: &str = concat!(
    "function parseIpv6Part(part, allowV4) {\n",
    "  if (!part) return [];\n",
    "  var segs = part.split(\":\");\n",
    "  var out = [];\n",
    "  for (var i = 0; i < segs.length; i++) {\n",
    "    var s = segs[i];\n",
    "    if (allowV4 && i === segs.length - 1 && s.indexOf(\".\") !== -1) {\n",
    "      var v4 = s.split(\".\");\n",
    "      if (v4.length !== 4) return null;\n",
    "      var b = [];\n",
    "      for (var j = 0; j < 4; j++) {\n",
    "        if (!/^\\d{1,3}$/.test(v4[j])) return null;\n",
    "        var n = parseInt(v4[j], 10);\n",
    "        if (n > 255) return null;\n",
    "        b.push(n);\n",
    "      }\n",
    "      out.push((b[0] << 8) | b[1]);\n",
    "      out.push((b[2] << 8) | b[3]);\n",
    "    } else {\n",
    "      if (!/^[0-9a-f]{1,4}$/i.test(s)) return null;\n",
    "      out.push(parseInt(s, 16));\n",
    "    }\n",
    "  }\n",
    "  return out;\n",
    "}\n",
    "function parseIpv6Words(ip) {\n",
    "  if (!ip || ip.indexOf(\":\") === -1) return null;\n",
    "  var dc = ip.split(\"::\");\n",
    "  if (dc.length > 2) return null;\n",
    "  var left = parseIpv6Part(dc[0], dc.length === 1);\n",
    "  if (!left) return null;\n",
    "  if (dc.length === 1) return left.length === 8 ? left : null;\n",
    "  var right = parseIpv6Part(dc[1], true);\n",
    "  if (!right) return null;\n",
    "  var missing = 8 - (left.length + right.length);\n",
    "  if (missing < 1) return null;\n",
    "  var words = left.slice();\n",
    "  for (var k = 0; k < missing; k++) words.push(0);\n",
    "  for (var m = 0; m < right.length; m++) words.push(right[m]);\n",
    "  return words;\n",
    "}\n",
    "function isInNetV6(ip, net, prefixLen) {\n",
    "  var a = parseIpv6Words(ip);\n",
    "  var b = parseIpv6Words(net);\n",
    "  if (!a || !b) return false;\n",
    "  var full = Math.floor(prefixLen / 16);\n",
    "  var rem = prefixLen % 16;\n",
    "  for (var i = 0; i < full; i++) {\n",
    "    if (a[i] !== b[i]) return false;\n",
    "  }\n",
    "  if (rem > 0) {\n",
    "    var mask = (0xffff << (16 - rem)) & 0xffff;\n",
    "    if ((a[full] & mask) !== (b[full] & mask)) return false;\n",
    "  }\n",
    "  return true;\n",
    "}\n",
);

fn render_pac_bypass_clauses(bypass_domains: &[String]) -> String {
    let mut clauses = String::new();
    for raw in bypass_domains {
        let trimmed = raw.trim().to_ascii_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains('/') {
            match IpNet::parse(&trimmed) {
                Some(IpNet::V4 { network, mask }) => {
                    let net_lit = escape_js_string(&Ipv4Addr::from(network).to_string());
                    let mask_lit = escape_js_string(&Ipv4Addr::from(mask).to_string());
                    clauses.push_str(&format!(
                        " ||\n    (/^\\d{{1,3}}(?:\\.\\d{{1,3}}){{3}}$/.test(h) && isInNet(h, {net_lit}, {mask_lit}))"
                    ));
                }
                Some(IpNet::V6 { network, mask }) => {
                    let net_lit = escape_js_string(&Ipv6Addr::from(network).to_string());
                    let prefix_len = mask.count_ones();
                    clauses.push_str(&format!(
                        " ||\n    (h.indexOf(\":\") !== -1 && isInNetV6(h, {net_lit}, {prefix_len}))"
                    ));
                }
                None => {}
            }
            continue;
        }
        let unbracketed = trimmed.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            match ip.to_canonical() {
                IpAddr::V4(v4) => {
                    let lit = escape_js_string(&v4.to_string());
                    clauses.push_str(&format!(" ||\n    h === {lit}"));
                }
                IpAddr::V6(v6) => {
                    let lit = escape_js_string(&v6.to_string());
                    clauses.push_str(&format!(
                        " ||\n    (h.indexOf(\":\") !== -1 && isInNetV6(h, {lit}, 128))"
                    ));
                }
            }
            continue;
        }
        if let Some(suffix) = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('.'))
            .map(|s| s.trim_end_matches('.'))
            .filter(|s| !s.contains('*'))
        {
            if suffix.is_empty() {
                continue;
            }
            let exact = escape_js_string(suffix);
            let dot_suffix_str = format!(".{suffix}");
            let dot_suffix = escape_js_string(&dot_suffix_str);
            let utf16_len = dot_suffix_str.encode_utf16().count();
            clauses.push_str(&format!(
                " ||\n    h === {exact} ||\n    (h.length > {utf16_len} && h.slice(-{utf16_len}) === {dot_suffix})"
            ));
        } else {
            let clean = trimmed.trim_end_matches('.');
            if clean.is_empty() {
                continue;
            }
            if clean.contains('*') {
                let pat = escape_js_string(clean);
                clauses.push_str(&format!(" ||\n    shExpMatch(h, {pat})"));
            } else {
                let exact = escape_js_string(clean);
                let dot_suffix_str = format!(".{clean}");
                let dot_suffix = escape_js_string(&dot_suffix_str);
                let utf16_len = dot_suffix_str.encode_utf16().count();
                clauses.push_str(&format!(
                    " ||\n    h === {exact} ||\n    (h.length > {utf16_len} && h.slice(-{utf16_len}) === {dot_suffix})"
                ));
            }
        }
    }
    clauses
}

const PAC_DEFAULT_DIRECT_DOMAINS: &[&str] = &[
    // Riot / Valorant (strict TLS & anti-cheat)
    "riotgames.com",
    "riotgames.net",
    "riotcdn.net",
    "playvalorant.com",
    "valorant.com",
    "pvp.net",
    "rgpub.io",
    "rdatasrv.net",
    "leagueoflegends.com",
    // Unblocked mesh/VPN control-plane & bootstrap APIs (BTK-blocked consumer VPN & Proton web
    // domains are intentionally omitted so they remain reachable through vdpi)
    "cloudflareclient.com",
    "tailscale.com",
    "tailscale.io",
    "radmin-vpn.com",
    "radmin.com",
    "famatech.com",
    "expressvpn.com",
    "expressvpn.net",
    "expressapisv2.net",
    "xvnet.net",
    "xvtel.com",
    // Core unblocked Windows / Microsoft OS update, telemetry & push domains
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "smartscreen.microsoft.com",
    "wns.windows.com",
    "gvt2.com",
];

#[cfg(test)]
fn render_pac_script(proxy_authority: &str) -> String {
    render_pac_script_with_bypass(proxy_authority, &[])
}

#[cfg(test)]
fn render_pac_script_with_bypass(proxy_authority: &str, bypass_domains: &[String]) -> String {
    render_pac_script_with_policy(proxy_authority, bypass_domains, &[])
}

fn render_pac_script_with_policy(
    proxy_authority: &str,
    bypass_domains: &[String],
    include_domains: &[String],
) -> String {
    let default_direct = vdpi_core::bypass::filter_pac_default_bypass_domains(
        PAC_DEFAULT_DIRECT_DOMAINS,
        include_domains,
    );
    let mut combined_bypass = Vec::with_capacity(default_direct.len() + bypass_domains.len());
    for domain in &default_direct {
        combined_bypass.push((*domain).to_string());
    }
    for entry in bypass_domains {
        let trimmed = entry.trim();
        let stripped = trimmed
            .strip_prefix("*.")
            .or_else(|| trimmed.strip_prefix('.'))
            .unwrap_or(trimmed)
            .trim_end_matches('.');
        let is_default_dup = !trimmed.contains('/')
            && !stripped.contains('*')
            && default_direct
                .iter()
                .any(|domain| domain.eq_ignore_ascii_case(stripped));
        if !is_default_dup {
            combined_bypass.push(entry.clone());
        }
    }
    let extra_clauses = render_pac_bypass_clauses(&combined_bypass);
    let ipv6_helpers = if extra_clauses.contains("isInNetV6(") {
        PAC_IPV6_CIDR_HELPERS
    } else {
        ""
    };
    format!(
        concat!(
            "function FindProxyForURL(url, host) {{\n",
            "  if (!host) return \"DIRECT\";\n",
            "  var h = host.toLowerCase().replace(/\\.$/, \"\").replace(/^\\[|\\]$/g, \"\").replace(/%.*$/, \"\");\n",
            "  var isIpv4 = /^\\d{{1,3}}(?:\\.\\d{{1,3}}){{3}}$/.test(h);\n",
            "  if (\n",
            "    (h.indexOf(\":\") === -1 && isPlainHostName(h)) ||\n",
            "    h === \"localhost\" ||\n",
            "    h === \"0.0.0.0\" ||\n",
            "    h === \"::\" ||\n",
            "    h === \"::1\" ||\n",
            "    h === \"0:0:0:0:0:0:0:0\" ||\n",
            "    h === \"0:0:0:0:0:0:0:1\" ||\n",
            "    (isIpv4 && shExpMatch(h, \"0.*\")) ||\n",
            "    (isIpv4 && shExpMatch(h, \"127.*\")) ||\n",
            "    /^::ffff:(127\\.|7f[0-9a-f]{{2}}:)/i.test(h) ||\n",
            "    /^::ffff:(10\\.|a[0-9a-f]{{2}}:)/i.test(h) ||\n",
            "    /^::ffff:(172\\.(1[6-9]|2[0-9]|3[0-1])\\.|ac1[0-9a-f]:)/i.test(h) ||\n",
            "    /^::ffff:(192\\.168\\.|c0a8:)/i.test(h) ||\n",
            "    /^::ffff:(192\\.0\\.0\\.|c000:[0-9a-f]{{1,2}}$)/i.test(h) ||\n",
            "    /^::ffff:(169\\.254\\.|a9fe:)/i.test(h) ||\n",
            "    /^::ffff:(100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\.|64[4-7][0-9a-f]:)/i.test(h) ||\n",
            "    /^::ffff:(0\\.|[0-9a-f]{{1,2}}:)/i.test(h) ||\n",
            "    shExpMatch(h, \"*.local\") ||\n",
            "    shExpMatch(h, \"*.localhost\") ||\n",
            "    shExpMatch(h, \"*.localdomain\") ||\n",
            "    shExpMatch(h, \"*.internal\") ||\n",
            "    shExpMatch(h, \"*.lan\") ||\n",
            "    shExpMatch(h, \"*.home.arpa\") ||\n",
            "    h === \"ts.net\" ||\n",
            "    shExpMatch(h, \"*.ts.net\") ||\n",
            "    h === \"captive.apple.com\" ||\n",
            "    h === \"www.msftconnecttest.com\" ||\n",
            "    h === \"msftconnecttest.com\" ||\n",
            "    h === \"ipv6.msftconnecttest.com\" ||\n",
            "    h === \"www.msftncsi.com\" ||\n",
            "    h === \"msftncsi.com\" ||\n",
            "    h === \"dns.msftncsi.com\" ||\n",
            "    h === \"detectportal.firefox.com\" ||\n",
            "    h === \"connectivitycheck.gstatic.com\" ||\n",
            "    h === \"connectivitycheck.android.com\" ||\n",
            "    h === \"clients3.google.com\" ||\n",
            "    h === \"nmcheck.gnome.org\" ||\n",
            "    h === \"networkcheck.kde.org\" ||\n",
            "    h === \"connectivity-check.ubuntu.com\" ||\n",
            "    h === \"neverssl.com\" ||\n",
            "    h === \"lvh.me\" ||\n",
            "    shExpMatch(h, \"*.lvh.me\") ||\n",
            "    h === \"nip.io\" ||\n",
            "    shExpMatch(h, \"*.nip.io\") ||\n",
            "    h === \"sslip.io\" ||\n",
            "    shExpMatch(h, \"*.sslip.io\") ||\n",
            "    h === \"localtest.me\" ||\n",
            "    shExpMatch(h, \"*.localtest.me\") ||\n",
            "    (isIpv4 && shExpMatch(h, \"10.*\")) ||\n",
            "    (isIpv4 && shExpMatch(h, \"192.168.*\")) ||\n",
            "    (isIpv4 && shExpMatch(h, \"192.0.0.*\")) ||\n",
            "    (isIpv4 && shExpMatch(h, \"169.254.*\")) ||\n",
            "    (isIpv4 && /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(h)) ||\n",
            "    /^100\\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.\\d{{1,3}}\\.\\d{{1,3}}$/.test(h) ||\n",
            "    (h.indexOf(\":\") !== -1 && (/^f[cd][0-9a-f]{{2}}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h))){extra_clauses}\n",
            "  ) {{\n",
            "    return \"DIRECT\";\n",
            "  }}\n",
            "  return \"PROXY {proxy_authority}; DIRECT\";\n",
            "}}\n",
            "{ipv6_helpers}",
        ),
        proxy_authority = proxy_authority,
        extra_clauses = extra_clauses,
        ipv6_helpers = ipv6_helpers,
    )
}

async fn handle_pac_http_request(
    client: &mut TcpStream,
    method: &str,
    header_str: &str,
    ctx: &EngineContext,
) -> Result<()> {
    let peer_addr = client.peer_addr().ok();
    let local_addr = client.local_addr().ok();
    if !is_local_pac_peer(peer_addr, local_addr)
        || !is_local_pac_host(header_str, local_addr)
        || has_forbidden_browser_headers(header_str)
    {
        let _ = write_pac_response(
            client,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    let is_get = method.eq_ignore_ascii_case("GET");
    let is_head = method.eq_ignore_ascii_case("HEAD");
    if !is_get && !is_head {
        let _ = write_pac_response(
            client,
            b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        return Ok(());
    }

    let proxy_authority = resolve_pac_proxy_authority(local_addr, ctx);
    let body = render_pac_script_with_policy(
        &proxy_authority,
        &ctx.config.bypass_domains,
        &ctx.config.patterns,
    );
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\nCache-Control: no-cache, max-age=0, private\r\nX-Content-Type-Options: nosniff\r\nCross-Origin-Resource-Policy: same-origin\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    if is_head {
        write_pac_response(client, headers.as_bytes()).await
    } else {
        let mut resp = Vec::with_capacity(headers.len() + body.len());
        resp.extend_from_slice(headers.as_bytes());
        resp.extend_from_slice(body.as_bytes());
        write_pac_response(client, &resp).await
    }
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

fn is_valid_http_method(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Parses `host:port`, `[ipv6]:port`, or `host` with a default port.
pub fn parse_authority(authority: &str, default_port: u16) -> Result<(String, u16)> {
    let trimmed = authority.trim();
    if trimmed.is_empty() {
        bail!("empty authority");
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 bracket in '{trimmed}'"))?;
        if v6.trim().is_empty() {
            bail!("empty IPv6 host in '{trimmed}'");
        }
        let port = if after.is_empty() {
            default_port
        } else if let Some(p_str) = after.strip_prefix(':') {
            p_str.parse::<u16>()?
        } else {
            bail!("unexpected trailing characters after IPv6 bracket in '{trimmed}'");
        };
        return Ok((v6.to_string(), port));
    }

    if let Some((h, p_str)) = trimmed.rsplit_once(':').filter(|(h, _)| !h.contains(':')) {
        if h.trim().is_empty() {
            bail!("empty host in '{trimmed}'");
        }
        let port = p_str.parse::<u16>()?;
        return Ok((h.to_string(), port));
    }

    Ok((trimmed.to_string(), default_port))
}

fn parse_http_proxy_target(target: &str, header_str: &str) -> Result<(String, u16, String)> {
    let absolute_rest =
        if target.len() >= 7 && target.as_bytes()[..7].eq_ignore_ascii_case(b"http://") {
            Some(&target[7..])
        } else if target.len() >= 5 && target.as_bytes()[..5].eq_ignore_ascii_case(b"ws://") {
            Some(&target[5..])
        } else {
            None
        };

    if let Some(rest) = absolute_rest {
        let (authority, path) = match rest.find(['/', '?']) {
            Some(idx) if rest.as_bytes()[idx] == b'?' => {
                (&rest[..idx], format!("/{}", &rest[idx..]))
            }
            Some(idx) => (&rest[..idx], rest[idx..].to_string()),
            None => (rest, "/".to_string()),
        };
        let (host, port) = parse_authority(authority, 80)?;
        return Ok((host, port, path));
    }

    // Fallback: origin-form (or asterisk-form `OPTIONS *`) with Host header
    for line in header_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            let raw_auth = line[5..].trim();
            let (host, port) = parse_authority(raw_auth, 80)?;
            let path = if target.starts_with('/') || target == "*" {
                target.to_string()
            } else {
                format!("/{target}")
            };
            return Ok((host, port, path));
        }
    }

    bail!("missing host in HTTP proxy request")
}

fn rewrite_http_request(
    method: &str,
    origin_path: &str,
    version: &str,
    header_str: &str,
    body_prefix: &[u8],
) -> Vec<u8> {
    let has_upgrade = header_str.split("\r\n").skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("upgrade") && !value.trim().is_empty()
        })
    });

    let mut out = Vec::with_capacity(header_str.len() + body_prefix.len() + 24);
    out.extend_from_slice(format!("{method} {origin_path} {version}\r\n").as_bytes());

    let mut saw_upgrade_connection = false;
    for line in header_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                if !has_upgrade {
                    continue;
                }
                let tokens: Vec<&str> = value
                    .split(',')
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .collect();
                let has_upgrade_tok = tokens.iter().any(|t| t.eq_ignore_ascii_case("upgrade"));
                if !has_upgrade_tok {
                    continue;
                }
                let has_close_tok = tokens.iter().any(|t| t.eq_ignore_ascii_case("close"));
                saw_upgrade_connection = true;
                if has_close_tok {
                    let kept: Vec<&str> = tokens
                        .into_iter()
                        .filter(|t| !t.eq_ignore_ascii_case("close"))
                        .collect();
                    out.extend_from_slice(
                        format!("Connection: {}\r\n", kept.join(", ")).as_bytes(),
                    );
                    continue;
                }
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if has_upgrade {
        if !saw_upgrade_connection {
            out.extend_from_slice(b"Connection: Upgrade\r\n");
        }
        out.extend_from_slice(b"\r\n");
    } else {
        out.extend_from_slice(b"Connection: close\r\n\r\n");
    }
    out.extend_from_slice(body_prefix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use tokio::net::TcpListener;

    #[test]
    fn parses_authorities_for_domains_ipv4_and_ipv6() {
        assert_eq!(
            parse_authority("updates.discord.com:443", 443).unwrap(),
            ("updates.discord.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority("www.roblox.com", 443).unwrap(),
            ("www.roblox.com".to_string(), 443)
        );
        assert_eq!(
            parse_authority("[2606:4700::6810:85e8]:8443", 443).unwrap(),
            ("2606:4700::6810:85e8".to_string(), 8443)
        );
        assert_eq!(
            parse_authority("[::1]", 443).unwrap(),
            ("::1".to_string(), 443)
        );
    }

    #[test]
    fn rejects_malformed_authorities_and_empty_hosts() {
        assert!(parse_authority("[::1]junk", 443).is_err());
        assert!(parse_authority("[::1]:443junk", 443).is_err());
        assert!(parse_authority(":443", 443).is_err());
        assert!(parse_authority("[]:443", 443).is_err());
        assert!(parse_authority("[]", 443).is_err());
    }

    #[test]
    fn rewrites_absolute_uri_and_strips_proxy_headers() {
        let raw = "GET http://example.com:8080/hello?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nUser-Agent: curl\r\n\r\n";
        let (h, p, path) =
            parse_http_proxy_target("http://example.com:8080/hello?x=1", raw).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/hello?x=1");

        let rewritten = rewrite_http_request("GET", &path, "HTTP/1.1", raw, b"");
        let s = String::from_utf8(rewritten).unwrap();
        assert!(s.starts_with("GET /hello?x=1 HTTP/1.1\r\n"));
        assert!(!s.to_ascii_lowercase().contains("proxy-connection"));
        assert!(!s.to_ascii_lowercase().contains("keep-alive"));
        assert!(s.contains("Host: example.com:8080\r\n"));
        assert!(s.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn preserves_websocket_upgrade_and_connection_headers() {
        let raw = "GET ws://example.com:8080/socket HTTP/1.1\r\nHost: example.com:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nProxy-Connection: keep-alive\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (h, p, path) = parse_http_proxy_target("ws://example.com:8080/socket", raw).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/socket");

        let rewritten = rewrite_http_request("GET", &path, "HTTP/1.1", raw, b"");
        let s = String::from_utf8(rewritten).unwrap();
        assert!(s.starts_with("GET /socket HTTP/1.1\r\n"));
        assert!(s.contains("Upgrade: websocket\r\n"));
        assert!(s.contains("Connection: Upgrade\r\n"));
        assert!(!s.to_ascii_lowercase().contains("proxy-connection"));
        assert!(!s.to_ascii_lowercase().contains("connection: close"));
        assert!(s.ends_with("\r\n\r\n"));

        // Case-insensitive `upgrade:` and multi-token `connection:` header are preserved.
        let mixed = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nupgrade: websocket\r\nconnection: keep-alive, Upgrade\r\n\r\n";
        let mixed_rewritten = rewrite_http_request("GET", "/ws", "HTTP/1.1", mixed, b"");
        let mixed_s = String::from_utf8(mixed_rewritten).unwrap();
        assert!(mixed_s.contains("upgrade: websocket\r\n"));
        assert!(mixed_s.contains("connection: keep-alive, Upgrade\r\n"));
        assert!(!mixed_s.to_ascii_lowercase().contains("connection: close"));

        // If `Upgrade:` is present without a `Connection:` header, add `Connection: Upgrade`.
        let no_conn =
            "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        let no_conn_rewritten = rewrite_http_request("GET", "/ws", "HTTP/1.1", no_conn, b"");
        let no_conn_s = String::from_utf8(no_conn_rewritten).unwrap();
        assert!(no_conn_s.contains("Upgrade: websocket\r\n"));
        assert!(no_conn_s.ends_with("Connection: Upgrade\r\n\r\n"));

        // `Connection: keep-alive` with `Upgrade: websocket` lacks an `upgrade` token and is rewritten.
        let keep_alive_ws = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nUpgrade: websocket\r\n\r\n";
        let ka_rewritten = rewrite_http_request("GET", "/ws", "HTTP/1.1", keep_alive_ws, b"");
        let ka_s = String::from_utf8(ka_rewritten).unwrap();
        assert!(ka_s.contains("Upgrade: websocket\r\n"));
        assert!(ka_s.ends_with("Connection: Upgrade\r\n\r\n"));
        assert!(!ka_s.to_ascii_lowercase().contains("connection: keep-alive"));
        assert!(!ka_s.to_ascii_lowercase().contains("connection: close"));

        // `Connection: close` with `Upgrade: websocket` is dropped and replaced with `Connection: Upgrade`.
        let close_ws = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n";
        let close_rewritten = rewrite_http_request("GET", "/ws", "HTTP/1.1", close_ws, b"");
        let close_s = String::from_utf8(close_rewritten).unwrap();
        assert!(close_s.contains("Upgrade: websocket\r\n"));
        assert!(close_s.ends_with("Connection: Upgrade\r\n\r\n"));
        assert!(!close_s.to_ascii_lowercase().contains("connection: close"));

        // `Connection: close, Upgrade` strips `close` while preserving `Upgrade`.
        let mixed_close_ws = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nConnection: close, Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mixed_close_rewritten =
            rewrite_http_request("GET", "/ws", "HTTP/1.1", mixed_close_ws, b"");
        let mixed_close_s = String::from_utf8(mixed_close_rewritten).unwrap();
        assert!(mixed_close_s.contains("Connection: Upgrade\r\n"));
        assert!(!mixed_close_s.to_ascii_lowercase().contains("close"));

        // Empty `Upgrade:` value must NOT trigger upgrade mode.
        let empty_upgrade =
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUpgrade:   \r\nConnection: keep-alive\r\n\r\n";
        let empty_rewritten = rewrite_http_request("GET", "/", "HTTP/1.1", empty_upgrade, b"");
        let empty_s = String::from_utf8(empty_rewritten).unwrap();
        assert!(empty_s.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn rejects_non_loopback_proxy_targets_to_loopback_and_self_listener() {
        let local: SocketAddr = "192.168.1.50:8080".parse().unwrap();
        assert!(is_forbidden_proxy_host(
            false,
            "127.0.0.1",
            8080,
            Some(local)
        ));
        assert!(is_forbidden_proxy_host(
            false,
            "localhost",
            18089,
            Some(local)
        ));
        assert!(is_forbidden_proxy_host(false, "::1", 8080, Some(local)));
        assert!(is_forbidden_proxy_host(false, "0.0.0.0", 8080, Some(local)));
        assert!(is_forbidden_proxy_host(
            false,
            "192.168.1.50",
            8080,
            Some(local)
        ));
        assert!(!is_forbidden_proxy_host(
            false,
            "example.com",
            443,
            Some(local)
        ));
        assert!(!is_forbidden_proxy_host(
            true,
            "127.0.0.1",
            19000,
            Some(local)
        ));

        let loopback_target: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        assert!(is_forbidden_remote_addr(
            false,
            loopback_target,
            Some(local)
        ));
        assert!(is_forbidden_remote_addr(false, local, Some(local)));
        assert!(is_forbidden_remote_addr(true, local, Some(local)));
        assert!(!is_forbidden_remote_addr(
            true,
            loopback_target,
            Some(local)
        ));
    }

    #[tokio::test]
    async fn bare_lf_in_http_headers_returns_400() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client(sock, ctx).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\nX-Smuggled: 1\r\n\r\n",
            )
            .await
            .unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[test]
    fn handles_standard_http_methods_cleanly() {
        for method in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"] {
            assert!(is_valid_http_method(method));
            let raw = format!(
                "{method} http://example.com/api/v1/items HTTP/1.1\r\nHost: example.com\r\n\r\n"
            );
            let (h, p, path) =
                parse_http_proxy_target("http://example.com/api/v1/items", &raw).unwrap();
            assert_eq!(h, "example.com");
            assert_eq!(p, 80);
            assert_eq!(path, "/api/v1/items");

            let body = if matches!(method, "POST" | "PUT" | "PATCH") {
                b"{\"ok\":true}".as_slice()
            } else {
                b"".as_slice()
            };
            let rewritten = rewrite_http_request(method, &path, "HTTP/1.1", &raw, body);
            let s = String::from_utf8(rewritten).unwrap();
            assert!(s.starts_with(&format!("{method} /api/v1/items HTTP/1.1\r\n")));
            assert!(s.ends_with(&format!(
                "Connection: close\r\n\r\n{}",
                std::str::from_utf8(body).unwrap()
            )));
        }

        // Asterisk-form OPTIONS * with Host header preserves `*` as origin path.
        let options_raw = "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (h, p, path) = parse_http_proxy_target("*", options_raw).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
        assert_eq!(path, "*");
    }

    #[tokio::test]
    async fn oversized_http_headers_return_431() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client(sock, ctx).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let prefix = b"GET http://example.com/ HTTP/1.1\r\nX-Pad: ";
        let mut oversized = Vec::with_capacity(MAX_HTTP_HEADER_BYTES);
        oversized.extend_from_slice(prefix);
        oversized.resize(MAX_HTTP_HEADER_BYTES, b'a');
        client.write_all(&oversized).await.unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn plain_http_forwarding_updates_telemetry() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut req_buf = [0u8; 1024];
            let n = sock.read(&mut req_buf).await.unwrap();
            assert!(req_buf[..n].starts_with(b"GET /ping HTTP/1.1\r\n"));
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            let _ = sock.shutdown().await;
        });

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let ctx_srv = ctx.clone();
        let proxy_task = tokio::spawn(async move {
            let (sock, _) = proxy.accept().await.unwrap();
            handle_http_client(sock, ctx_srv).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req =
            format!("GET http://{upstream_addr}/ping HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        drop(client);

        upstream_task.await.unwrap();
        proxy_task.await.unwrap().unwrap();
        assert!(resp.ends_with(b"\r\n\r\nok"));

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 1);
        assert!(snap.bytes_tx > 0);
        assert!(snap.bytes_rx >= resp.len() as u64);
    }

    #[tokio::test]
    async fn health_endpoint_returns_enriched_live_engine_json() {
        use crate::desync::LearnedStrategy;
        use std::sync::atomic::Ordering;

        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--mode",
            "tls-record",
            "--no-doh",
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();
        ctx.telemetry.active_connections.store(2, Ordering::Relaxed);
        ctx.telemetry.total_connections.store(15, Ordering::Relaxed);
        ctx.telemetry.bytes_tx.store(1234, Ordering::Relaxed);
        ctx.telemetry.bytes_rx.store(5678, Ordering::Relaxed);
        ctx.telemetry.tls_handshakes.store(9, Ordering::Relaxed);
        ctx.telemetry
            .auto_heal_escalations
            .store(3, Ordering::Relaxed);
        ctx.telemetry.learned_hosts.store(4, Ordering::Relaxed);
        ctx.preferred_isp_stage
            .store(LearnedStrategy::OobSniDesync as u8, Ordering::Relaxed);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (sock, _) = listener.accept().await.unwrap();
                handle_http_client(sock, ctx.clone()).await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();

        let resp_str = String::from_utf8(resp).unwrap();
        let (headers, body) = resp_str.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains("Content-Type: application/json\r\n"));

        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["status"].as_str(), Some("ok"));
        assert_eq!(json["service"].as_str(), Some("vdpi"));
        assert_eq!(json["version"].as_str(), Some(env!("CARGO_PKG_VERSION")));
        assert_eq!(json["mode"].as_str(), Some("tls-record"));
        assert_eq!(json["doh"].as_bool(), Some(false));
        assert_eq!(json["block_quic"].as_bool(), Some(true));
        assert_eq!(json["active_connections"].as_u64(), Some(2));
        assert_eq!(json["total_connections"].as_u64(), Some(15));
        assert_eq!(json["bytes_tx"].as_u64(), Some(1234));
        assert_eq!(json["bytes_rx"].as_u64(), Some(5678));
        assert_eq!(json["tls_handshakes"].as_u64(), Some(9));
        assert_eq!(json["auto_heal_escalations"].as_u64(), Some(3));
        assert_eq!(json["learned_hosts"].as_u64(), Some(4));
        assert_eq!(json["isp_stage"].as_str(), Some("OobSniDesync"));

        let mut post_client = TcpStream::connect(addr).await.unwrap();
        post_client
            .write_all(b"POST /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut post_resp = Vec::new();
        post_client.read_to_end(&mut post_resp).await.unwrap();
        let post_str = String::from_utf8(post_resp).unwrap();
        assert!(post_str.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(post_str.contains("Allow: GET\r\n"));

        let mut foreign_client = TcpStream::connect(addr).await.unwrap();
        foreign_client
            .write_all(b"GET /vdpi-health HTTP/1.1\r\nHost: evil.example\r\n\r\n")
            .await
            .unwrap();
        let mut foreign_resp = Vec::new();
        foreign_client.read_to_end(&mut foreign_resp).await.unwrap();
        let foreign_str = String::from_utf8(foreign_resp).unwrap();
        assert!(foreign_str.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pac_endpoint_serves_fail_open_script_and_enforces_security() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"])
            .unwrap()
            .into_runtime_config();
        cfg.bypass_domains = vec![
            "*.corp.example".to_string(),
            "bank.example.org".to_string(),
            "bad\"quote\\inject".to_string(),
        ];
        let ctx = EngineContext::new(cfg).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            for _ in 0..10 {
                let (sock, _) = listener.accept().await.unwrap();
                handle_http_client(sock, ctx.clone()).await?;
            }
            Ok::<(), anyhow::Error>(())
        });

        // 1. GET /vdpi.pac with explicit loopback Host:port
        let mut get_client = TcpStream::connect(addr).await.unwrap();
        let get_req = format!(
            "GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        get_client.write_all(get_req.as_bytes()).await.unwrap();
        let mut get_resp = Vec::new();
        get_client.read_to_end(&mut get_resp).await.unwrap();
        let get_str = String::from_utf8(get_resp).unwrap();
        let (headers, body) = get_str.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(
            headers.contains("Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n")
        );
        assert!(headers.contains("Cache-Control: no-cache, max-age=0, private\r\n"));
        assert!(headers.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(headers.contains("Cross-Origin-Resource-Policy: same-origin\r\n"));
        assert!(headers.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(headers.contains("Connection: close"));
        assert!(body.contains("function FindProxyForURL(url, host)"));
        assert!(body.contains("if (!host) return \"DIRECT\";"));
        assert!(body.contains("var h = host.toLowerCase()"));
        assert!(body.contains("shExpMatch(h, \"127.*\")"));
        assert!(body.contains("h === \"0.0.0.0\""));
        assert!(body.contains("h === \"::\""));
        assert!(body.contains("h === \"0:0:0:0:0:0:0:1\""));
        assert!(body.contains("h === \"ts.net\""));
        assert!(body.contains("shExpMatch(h, \"*.ts.net\")"));
        assert!(body.contains("shExpMatch(h, \"*.lan\")"));
        assert!(body.contains("shExpMatch(h, \"*.home.arpa\")"));
        assert!(body.contains("shExpMatch(h, \"*.localdomain\")"));
        assert!(body.contains("\"corp.example\""));
        assert!(body.contains("\"bank.example.org\""));
        assert!(body.contains("\"bad\\\"quote\\\\inject\""));
        assert!(body.contains(&format!(
            "return \"PROXY 127.0.0.1:{}; DIRECT\";",
            addr.port()
        )));
        assert!(!body.contains("dnsResolve"));

        // 2. GET /vdpi.pac?v=1 query string variant
        let mut query_client = TcpStream::connect(addr).await.unwrap();
        let query_req = format!(
            "GET /vdpi.pac?v=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        query_client.write_all(query_req.as_bytes()).await.unwrap();
        let mut query_resp = Vec::new();
        query_client.read_to_end(&mut query_resp).await.unwrap();
        let query_str = String::from_utf8(query_resp).unwrap();
        let (query_headers, query_body) = query_str.split_once("\r\n\r\n").unwrap();
        assert!(query_headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(query_body, body);

        // 3. Absolute-URI GET http://127.0.0.1:<port>/vdpi.pac
        let mut abs_client = TcpStream::connect(addr).await.unwrap();
        let abs_req = format!(
            "GET http://127.0.0.1:{}/vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port(),
            addr.port()
        );
        abs_client.write_all(abs_req.as_bytes()).await.unwrap();
        let mut abs_resp = Vec::new();
        abs_client.read_to_end(&mut abs_resp).await.unwrap();
        let abs_str = String::from_utf8(abs_resp).unwrap();
        let (abs_headers, abs_body) = abs_str.split_once("\r\n\r\n").unwrap();
        assert!(abs_headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert_eq!(abs_body, body);

        // 4. Spoofed Host port must NOT be reflected into PAC authority (uses local_addr)
        let mut spoof_client = TcpStream::connect(addr).await.unwrap();
        spoof_client
            .write_all(b"GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:9999\r\n\r\n")
            .await
            .unwrap();
        let mut spoof_resp = Vec::new();
        spoof_client.read_to_end(&mut spoof_resp).await.unwrap();
        let spoof_str = String::from_utf8(spoof_resp).unwrap();
        let (_, spoof_body) = spoof_str.split_once("\r\n\r\n").unwrap();
        assert!(spoof_body.contains(&format!(
            "return \"PROXY 127.0.0.1:{}; DIRECT\";",
            addr.port()
        )));
        assert!(!spoof_body.contains("9999"));

        // 5. HEAD /vdpi.pac returns headers only (with full Content-Length)
        let mut head_client = TcpStream::connect(addr).await.unwrap();
        let head_req = format!(
            "HEAD /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        head_client.write_all(head_req.as_bytes()).await.unwrap();
        let mut head_resp = Vec::new();
        head_client.read_to_end(&mut head_resp).await.unwrap();
        let head_str = String::from_utf8(head_resp).unwrap();
        let (head_headers, head_body) = head_str.split_once("\r\n\r\n").unwrap();
        assert!(head_headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(head_headers
            .contains("Content-Type: application/x-ns-proxy-autoconfig; charset=utf-8\r\n"));
        assert!(head_headers.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(head_body.is_empty());

        // 6. POST /vdpi.pac returns 405 Method Not Allowed
        let mut post_client = TcpStream::connect(addr).await.unwrap();
        let post_req = format!(
            "POST /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        post_client.write_all(post_req.as_bytes()).await.unwrap();
        let mut post_resp = Vec::new();
        post_client.read_to_end(&mut post_resp).await.unwrap();
        let post_str = String::from_utf8(post_resp).unwrap();
        assert!(post_str.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(post_str.contains("Allow: GET, HEAD\r\n"));

        // 7. Non-loopback Host returns 403 Forbidden
        let mut foreign_client = TcpStream::connect(addr).await.unwrap();
        foreign_client
            .write_all(b"GET /vdpi.pac HTTP/1.1\r\nHost: evil.example\r\n\r\n")
            .await
            .unwrap();
        let mut foreign_resp = Vec::new();
        foreign_client.read_to_end(&mut foreign_resp).await.unwrap();
        let foreign_str = String::from_utf8(foreign_resp).unwrap();
        assert!(foreign_str.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        // 8. Missing Host on HTTP/1.1 returns 403 Forbidden
        let mut missing_host_client = TcpStream::connect(addr).await.unwrap();
        missing_host_client
            .write_all(b"GET /vdpi.pac HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut missing_host_resp = Vec::new();
        missing_host_client
            .read_to_end(&mut missing_host_resp)
            .await
            .unwrap();
        let missing_host_str = String::from_utf8(missing_host_resp).unwrap();
        assert!(missing_host_str.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        // 9. Origin header returns 403 Forbidden (XSSI protection)
        let mut origin_client = TcpStream::connect(addr).await.unwrap();
        origin_client
            .write_all(
                format!(
                    "GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nOrigin: https://evil.example\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut origin_resp = Vec::new();
        origin_client.read_to_end(&mut origin_resp).await.unwrap();
        let origin_str = String::from_utf8(origin_resp).unwrap();
        assert!(origin_str.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        // 10. Cross-site Sec-Fetch-Site returns 403 Forbidden
        let mut fetch_site_client = TcpStream::connect(addr).await.unwrap();
        fetch_site_client
            .write_all(
                format!(
                    "GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nSec-Fetch-Site: cross-site\r\n\r\n",
                    addr.port()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut fetch_site_resp = Vec::new();
        fetch_site_client
            .read_to_end(&mut fetch_site_resp)
            .await
            .unwrap();
        let fetch_site_str = String::from_utf8(fetch_site_resp).unwrap();
        assert!(fetch_site_str.starts_with("HTTP/1.1 403 Forbidden\r\n"));

        server.await.unwrap().unwrap();
    }

    #[test]
    fn pac_authority_normalizes_unspecified_bind_addresses() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"])
            .unwrap()
            .into_runtime_config();
        cfg.addr = "0.0.0.0".parse().unwrap();
        cfg.port = 18080;
        let ctx_v4 = EngineContext::new(cfg.clone()).unwrap();
        assert_eq!(resolve_pac_proxy_authority(None, &ctx_v4), "127.0.0.1:18080");

        cfg.addr = "::".parse().unwrap();
        cfg.port = 18081;
        let ctx_v6 = EngineContext::new(cfg).unwrap();
        assert_eq!(resolve_pac_proxy_authority(None, &ctx_v6), "[::1]:18081");
        assert_eq!(
            resolve_pac_proxy_authority(Some("[::1]:19090".parse().unwrap()), &ctx_v6),
            "[::1]:19090"
        );
        assert!(render_pac_script("[::1]:18081").contains("PROXY [::1]:18081; DIRECT"));
    }

    #[test]
    fn pac_script_uses_172_16_31_regex_and_does_not_bypass_public_ipv6() {
        let script = render_pac_script("127.0.0.1:8080");

        // 172.16.0.0/12 must use JS RegExp instead of broken shExpMatch character classes.
        assert!(script.contains("/^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(h)"));
        assert!(!script.contains("shExpMatch(h, \"172.1[6-9].*\")"));
        assert!(!script.contains("shExpMatch(h, \"172.2[0-9].*\")"));
        assert!(!script.contains("shExpMatch(h, \"172.3[0-1].*\")"));

        let re_172 = regex::Regex::new(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.").unwrap();
        for private_172 in [
            "172.16.0.1",
            "172.19.255.255",
            "172.20.0.1",
            "172.29.12.34",
            "172.30.0.1",
            "172.31.255.254",
        ] {
            assert!(re_172.is_match(private_172), "expected match for {private_172}");
        }
        for public_172 in ["172.15.255.255", "172.32.0.1", "172.160.0.1", "10.172.16.0.1"] {
            assert!(
                !re_172.is_match(public_172),
                "unexpected match for {public_172}"
            );
        }

        // isPlainHostName must be guarded against IPv6 literals containing ':'.
        assert!(script.contains("(h.indexOf(\":\") === -1 && isPlainHostName(h))"));
        assert!(!script.contains("\n    isPlainHostName(h) ||"));

        // Public IPv6 literals must not match the IPv6 ULA/link-local clauses or plain-host guard.
        let re_ula = regex::Regex::new(r"^f[cd][0-9a-f]{2}:").unwrap();
        let re_ll = regex::Regex::new(r"^fe[89ab][0-9a-f]:").unwrap();
        for public_v6 in [
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2a00:1450:4001:829::200e",
        ] {
            assert!(public_v6.contains(':'));
            assert!(!re_ula.is_match(public_v6));
            assert!(!re_ll.is_match(public_v6));
        }

        // 0.0.0.0/8, RFC 6890 192.0.0.0/24, WHATWG hex-canonicalized & dotted IPv4-mapped prefixes, and loopback dev domains.
        for expected in [
            "var isIpv4 = /^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(h);",
            "(isIpv4 && shExpMatch(h, \"0.*\"))",
            "(isIpv4 && shExpMatch(h, \"127.*\"))",
            "(isIpv4 && shExpMatch(h, \"10.*\"))",
            "(isIpv4 && shExpMatch(h, \"192.168.*\"))",
            "(isIpv4 && shExpMatch(h, \"169.254.*\"))",
            "(isIpv4 && /^172\\.(1[6-9]|2[0-9]|3[0-1])\\./.test(h))",
            "/^::ffff:(127\\.|7f[0-9a-f]{2}:)/i.test(h)",
            "/^::ffff:(10\\.|a[0-9a-f]{2}:)/i.test(h)",
            "/^::ffff:(172\\.(1[6-9]|2[0-9]|3[0-1])\\.|ac1[0-9a-f]:)/i.test(h)",
            "/^::ffff:(192\\.168\\.|c0a8:)/i.test(h)",
            "/^::ffff:(192\\.0\\.0\\.|c000:[0-9a-f]{1,2}$)/i.test(h)",
            "/^::ffff:(169\\.254\\.|a9fe:)/i.test(h)",
            "/^::ffff:(100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\.|64[4-7][0-9a-f]:)/i.test(h)",
            "/^::ffff:(0\\.|[0-9a-f]{1,2}:)/i.test(h)",
            "(isIpv4 && shExpMatch(h, \"192.0.0.*\"))",
            "h === \"lvh.me\"",
            "shExpMatch(h, \"*.lvh.me\")",
            "h === \"nip.io\"",
            "shExpMatch(h, \"*.nip.io\")",
            "h === \"sslip.io\"",
            "shExpMatch(h, \"*.sslip.io\")",
            "h === \"localtest.me\"",
            "shExpMatch(h, \"*.localtest.me\")",
        ] {
            assert!(script.contains(expected), "missing PAC clause: {expected}");
        }

        // Bare unguarded shExpMatch prefixes must NOT appear (would falsely bypass hostnames like 0.pool.ntp.org / 0.gravatar.com).
        for unguarded in [
            "\n    shExpMatch(h, \"0.*\") ||",
            "\n    shExpMatch(h, \"127.*\") ||",
            "\n    shExpMatch(h, \"10.*\") ||",
            "\n    shExpMatch(h, \"192.168.*\") ||",
            "\n    shExpMatch(h, \"169.254.*\") ||",
        ] {
            assert!(
                !script.contains(unguarded),
                "unexpected unguarded shExpMatch IPv4 prefix clause: {unguarded}"
            );
        }

        // IPv4 literal guard matches real IPv4 targets while excluding numeric-prefix hostnames like 0.pool.ntp.org and 0.gravatar.com.
        let re_ipv4_guard = regex::Regex::new(r"^\d{1,3}(?:\.\d{1,3}){3}$").unwrap();
        let ds_lite_net = IpNet::parse("192.0.0.0/24").unwrap();
        for ipv4_host in [
            "0.0.0.1",
            "0.1.2.3",
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.168.1.1",
        ] {
            assert!(
                re_ipv4_guard.is_match(ipv4_host),
                "expected isIpv4 match for {ipv4_host}"
            );
        }
        assert!(ds_lite_net.contains("192.0.0.1".parse().unwrap()));
        assert!(ds_lite_net.contains("192.0.0.170".parse().unwrap()));
        assert!(!ds_lite_net.contains("192.0.1.1".parse().unwrap()));
        for non_ipv4_hostname in [
            "0.pool.ntp.org",
            "0.gravatar.com",
            "10.cdn.example.com",
            "127.static.example.org",
            "192.168.example.com",
            "169.254.example.com",
            "172.16.example.com",
            "example.com",
        ] {
            assert!(
                !re_ipv4_guard.is_match(non_ipv4_hostname),
                "real hostname must NOT match isIpv4 guard or bypass PAC: {non_ipv4_hostname}"
            );
        }
        for legacy in [
            "shExpMatch(h, \"::ffff:127.*\")",
            "shExpMatch(h, \"::ffff:7f00:*\")",
            "shExpMatch(h, \"::ffff:10.*\")",
            "shExpMatch(h, \"::ffff:192.168.*\")",
            "shExpMatch(h, \"::ffff:172.*\")",
        ] {
            assert!(
                !script.contains(legacy),
                "unexpected legacy shExpMatch IPv4-mapped clause: {legacy}"
            );
        }
        assert!(!script.contains("isInNet"));
        assert!(!script.contains("dnsResolve"));
    }

    #[test]
    fn pac_script_ipv4_mapped_ipv6_regexes_cover_whatwg_hex_and_exclude_public_172() {
        let script = render_pac_script("127.0.0.1:8080");
        let patterns = [
            r"^::ffff:(127\.|7f[0-9a-f]{2}:)",
            r"^::ffff:(10\.|a[0-9a-f]{2}:)",
            r"^::ffff:(172\.(1[6-9]|2[0-9]|3[0-1])\.|ac1[0-9a-f]:)",
            r"^::ffff:(192\.168\.|c0a8:)",
            r"^::ffff:(192\.0\.0\.|c000:[0-9a-f]{1,2}$)",
            r"^::ffff:(169\.254\.|a9fe:)",
            r"^::ffff:(100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|64[4-7][0-9a-f]:)",
            r"^::ffff:(0\.|[0-9a-f]{1,2}:)",
        ];
        for pat in patterns {
            let clause = format!("/{pat}/i.test(h)");
            assert!(
                script.contains(&clause),
                "missing IPv4-mapped IPv6 PAC regex clause: {clause}"
            );
        }
        let compiled: Vec<regex::Regex> = patterns
            .iter()
            .map(|p| regex::Regex::new(&format!("(?i){p}")).unwrap())
            .collect();
        let matches_any = |host: &str| compiled.iter().any(|re| re.is_match(host));

        // Dotted-quad AND WHATWG hex-canonicalized private/loopback/link-local/CGNAT/unspecified
        for private_mapped in [
            "::ffff:127.0.0.1",
            "::ffff:127.255.255.254",
            "::ffff:7f00:1",
            "::ffff:7fff:fffe",
            "::FFFF:7F00:1",
            "::ffff:10.0.0.1",
            "::ffff:10.255.0.1",
            "::ffff:a00:1",
            "::ffff:aff:fe01",
            "::ffff:172.16.0.1",
            "::ffff:172.20.1.5",
            "::ffff:172.31.255.254",
            "::ffff:ac10:1",
            "::ffff:ac1f:fffe",
            "::ffff:192.168.1.1",
            "::ffff:c0a8:101",
            "::ffff:c0a8:1",
            "::ffff:192.0.0.1",
            "::ffff:c000:0",
            "::ffff:c000:1",
            "::ffff:c000:aa",
            "::ffff:c000:ff",
            "::ffff:169.254.169.254",
            "::ffff:a9fe:a9fe",
            "::ffff:100.64.0.1",
            "::ffff:100.100.1.1",
            "::ffff:100.127.255.254",
            "::ffff:6440:1",
            "::ffff:647f:fffe",
            "::ffff:0.0.0.0",
            "::ffff:0.0.0.1",
            "::ffff:0.1.0.0",
            "::ffff:0.255.255.255",
            "::ffff:0:0",
            "::ffff:0:1",
            "::ffff:1:0",
            "::ffff:ff:ffff",
        ] {
            assert!(
                matches_any(private_mapped),
                "expected IPv4-mapped IPv6 bypass for {private_mapped}"
            );
        }

        // Public IPv4-mapped IPv6 targets (including Google 172.217.*, Cloudflare 172.64.*, and 192.0.1.1 / 192.0.78.24) must NOT bypass.
        for public_mapped in [
            "::ffff:172.217.0.1",
            "::ffff:acd9:1",
            "::ffff:172.64.0.1",
            "::ffff:ac40:1",
            "::ffff:172.15.255.255",
            "::ffff:ac0f:ffff",
            "::ffff:172.32.0.1",
            "::ffff:ac20:1",
            "::ffff:100.63.255.255",
            "::ffff:643f:ffff",
            "::ffff:100.128.0.1",
            "::ffff:6480:1",
            "::ffff:1.0.0.0",
            "::ffff:100:0",
            "::ffff:1.1.1.1",
            "::ffff:101:101",
            "::ffff:8.8.8.8",
            "::ffff:808:808",
            "::ffff:192.0.1.1",
            "::ffff:c000:101",
            "::ffff:c000:4e18",
            "::ffff:192.169.0.1",
            "::ffff:c0a9:1",
            "::ffff:169.253.0.1",
            "::ffff:a9fd:1",
            "::ffff:128.0.0.1",
            "::ffff:8000:1",
            "::ffff:11.0.0.1",
            "::ffff:b00:1",
        ] {
            assert!(
                !matches_any(public_mapped),
                "public IPv4-mapped IPv6 must NOT bypass PAC: {public_mapped}"
            );
        }
    }

    #[test]
    fn pac_script_bypasses_builtin_captive_portal_domains() {
        let script = render_pac_script("127.0.0.1:8080");
        let domains = [
            "captive.apple.com",
            "www.msftconnecttest.com",
            "msftconnecttest.com",
            "ipv6.msftconnecttest.com",
            "www.msftncsi.com",
            "msftncsi.com",
            "dns.msftncsi.com",
            "detectportal.firefox.com",
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "clients3.google.com",
            "nmcheck.gnome.org",
            "networkcheck.kde.org",
            "connectivity-check.ubuntu.com",
            "neverssl.com",
        ];
        assert_eq!(domains.len(), 15);
        for domain in domains {
            let expected = format!("h === \"{domain}\"");
            assert!(
                script.contains(&expected),
                "missing captive-portal PAC bypass: {expected}"
            );
        }
    }

    #[test]
    fn pac_bypass_clauses_convert_ipv4_cidr_to_is_in_net() {
        let entries = vec![
            "10.20.0.0/16".to_string(),
            "192.168.55.99/24".to_string(),
            "203.0.113.7/32".to_string(),
            "2001:db8::/32".to_string(),
            "10.20.0.0/99".to_string(),
            "https://example.com/path".to_string(),
        ];
        let clauses = render_pac_bypass_clauses(&entries);
        assert!(clauses.contains("isInNet(h, \"10.20.0.0\", \"255.255.0.0\")"));
        assert!(clauses.contains("isInNet(h, \"192.168.55.0\", \"255.255.255.0\")"));
        assert!(clauses.contains("isInNet(h, \"203.0.113.7\", \"255.255.255.255\")"));
        assert!(clauses.contains("isInNetV6(h, \"2001:db8::\", 32)"));
        assert!(!clauses.contains("/99"));
        assert!(!clauses.contains("example.com"));

        let script = render_pac_script_with_bypass("127.0.0.1:8080", &["10.20.0.0/16".to_string()]);
        assert!(script.contains("isInNet(h, \"10.20.0.0\", \"255.255.0.0\")"));
        assert!(!script.contains("function isInNetV6"));
        assert!(!script.contains("dnsResolve"));
    }

    #[test]
    fn pac_bypass_clauses_emit_ipv6_cidr_prefix_matches() {
        let entries = vec![
            "2001::/16".to_string(),
            "2001:db8::/32".to_string(),
            "2001:db8:abcd:ffff::/48".to_string(),
            "2001:db8:0:1::beef/64".to_string(),
            "2001:db8::1/128".to_string(),
            "fe80::/10".to_string(),
            "[fd12:3456::]/32".to_string(),
            "::ffff:10.20.0.0/112".to_string(),
            "2001:db8::/129".to_string(),
            "2001:db8::/abc".to_string(),
        ];
        let clauses = render_pac_bypass_clauses(&entries);
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001::\", 16))"));
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001:db8::\", 32))"));
        assert!(
            clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001:db8:abcd::\", 48))")
        );
        assert!(
            clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001:db8:0:1::\", 64))")
        );
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001:db8::1\", 128))"));
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"fe80::\", 10))"));
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"fd12:3456::\", 32))"));
        assert!(clauses.contains("isInNet(h, \"10.20.0.0\", \"255.255.0.0\")"));
        assert!(!clauses.contains("/129"));
        assert!(!clauses.contains("/abc"));

        let script = render_pac_script_with_bypass(
            "127.0.0.1:8080",
            &["2001:db8::/32".to_string(), "2001:db8:0:1::/64".to_string()],
        );
        assert!(script.contains("isInNetV6(h, \"2001:db8::\", 32)"));
        assert!(script.contains("isInNetV6(h, \"2001:db8:0:1::\", 64)"));
        assert!(script.contains("function parseIpv6Words(ip)"));
        assert!(script.contains("function isInNetV6(ip, net, prefixLen)"));
        assert!(!script.contains("dnsResolve"));
    }

    #[tokio::test]
    async fn health_endpoint_populates_vpn_conflict_for_full_tunnel_vpn() {
        let mullvad = VpnScope::FullTunnel {
            provider: "Mullvad".to_string(),
            iface: "Mullvad".to_string(),
            kill_switch: true,
        };
        let split = VpnScope::SplitOverlay {
            providers: vec!["Tailscale".to_string()],
        };
        assert_eq!(
            format_proxy_vpn_conflict(VpnCoexistence::AutoYield, &mullvad).as_deref(),
            Some("Mullvad")
        );
        assert_eq!(
            format_proxy_vpn_conflict(VpnCoexistence::Warn, &mullvad).as_deref(),
            Some("Mullvad (warn)")
        );
        assert_eq!(
            format_proxy_vpn_conflict(VpnCoexistence::Off, &mullvad),
            None
        );
        assert_eq!(
            format_proxy_vpn_conflict(VpnCoexistence::AutoYield, &split),
            None
        );
        assert_eq!(
            format_proxy_vpn_conflict(VpnCoexistence::AutoYield, &VpnScope::None),
            None
        );

        struct CacheResetGuard;
        impl Drop for CacheResetGuard {
            fn drop(&mut self) {
                let mut cache = vpn_conflict_cache()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                cache.generation = cache.generation.wrapping_add(1);
                cache.last_checked = None;
                cache.scope = VpnScope::None;
                cache.refreshing = false;
            }
        }
        let _reset = CacheResetGuard;
        {
            let mut cache = vpn_conflict_cache()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.generation = cache.generation.wrapping_add(1);
            cache.last_checked = Some(Instant::now());
            cache.scope = mullvad;
            cache.refreshing = false;
        }

        for (policy, expected) in [
            (VpnCoexistence::AutoYield, Some("Mullvad")),
            (VpnCoexistence::Warn, Some("Mullvad (warn)")),
            (VpnCoexistence::Off, None),
        ] {
            let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy", "--no-doh"])
                .unwrap()
                .into_runtime_config();
            cfg.vpn_coexistence = policy;
            let ctx = EngineContext::new(cfg).unwrap();

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                handle_http_client(sock, ctx).await
            });

            let mut client = TcpStream::connect(addr).await.unwrap();
            client
                .write_all(b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
            let mut resp = Vec::new();
            client.read_to_end(&mut resp).await.unwrap();
            let resp_str = String::from_utf8(resp).unwrap();
            let (headers, body) = resp_str.split_once("\r\n\r\n").unwrap();
            assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));

            let json: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(json["vpn_conflict"].as_str(), expected);
            server.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn health_endpoint_redacts_doh_token_and_respects_effective_doh_state() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy", "--no-doh"])
            .unwrap()
            .into_runtime_config();
        cfg.dns_addr = "https://dns.nextdns.io/abc123?token=xyz".to_string();
        let ctx = EngineContext::new(cfg).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client(sock, ctx).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        let resp_str = String::from_utf8(resp).unwrap();
        let (headers, body) = resp_str.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));

        let json: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(json["doh"].as_bool(), Some(true));
        let dns_addr = json["dns_addr"].as_str().unwrap();
        assert!(dns_addr.starts_with("https://dns.nextdns.io"));
        assert!(!dns_addr.contains("abc123"));
        assert!(!dns_addr.contains("token"));
        assert!(!dns_addr.contains("xyz"));

        server.await.unwrap().unwrap();

        // Bare custom non-DoH IP (e.g. 76.76.2.0) must report `doh: false` even when enable_doh=true.
        let mut custom_cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"])
            .unwrap()
            .into_runtime_config();
        custom_cfg.enable_doh = true;
        custom_cfg.dns_addr = "76.76.2.0".to_string();
        let custom_ctx = EngineContext::new(custom_cfg).unwrap();

        let custom_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let custom_addr = custom_listener.local_addr().unwrap();

        let custom_server = tokio::spawn(async move {
            let (sock, _) = custom_listener.accept().await.unwrap();
            handle_http_client(sock, custom_ctx).await
        });

        let mut custom_client = TcpStream::connect(custom_addr).await.unwrap();
        custom_client
            .write_all(b"GET /vdpi-health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .unwrap();
        let mut custom_resp = Vec::new();
        custom_client.read_to_end(&mut custom_resp).await.unwrap();
        let custom_resp_str = String::from_utf8(custom_resp).unwrap();
        let (custom_headers, custom_body) = custom_resp_str.split_once("\r\n\r\n").unwrap();
        assert!(custom_headers.starts_with("HTTP/1.1 200 OK\r\n"));

        let custom_json: serde_json::Value = serde_json::from_str(custom_body).unwrap();
        assert_eq!(custom_json["doh"].as_bool(), Some(false));
        assert_eq!(custom_json["dns_addr"].as_str(), Some("76.76.2.0"));

        custom_server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn preconnect_ssrf_blocks_forbidden_candidates_before_tcp_connect() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let local: SocketAddr = "192.168.1.50:8080".parse().unwrap();

        // Pure candidate list validation checks ALL resolved IPs before any connect.
        assert_eq!(
            validate_candidate_targets(false, &["10.0.0.5".parse().unwrap()], 22, Some(local)),
            Err("10.0.0.5:22".parse().unwrap())
        );
        assert_eq!(
            validate_candidate_targets(
                false,
                &["169.254.169.254".parse().unwrap()],
                80,
                Some(local)
            ),
            Err("169.254.169.254:80".parse().unwrap())
        );
        // Mixed public + private A records must be rejected before dialing even the public IP.
        assert_eq!(
            validate_candidate_targets(
                false,
                &[
                    "93.184.216.34".parse().unwrap(),
                    "192.168.1.1".parse().unwrap(),
                ],
                443,
                Some(local)
            ),
            Err("192.168.1.1:443".parse().unwrap())
        );
        assert!(validate_candidate_targets(
            false,
            &["::ffff:169.254.169.254".parse().unwrap()],
            80,
            Some(local)
        )
        .is_err());
        assert!(validate_candidate_targets(
            false,
            &["fd00::1".parse().unwrap()],
            443,
            Some(local)
        )
        .is_err());
        assert!(validate_candidate_targets(
            false,
            &[
                "93.184.216.34".parse().unwrap(),
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            ],
            443,
            Some(local)
        )
        .is_ok());
        assert!(validate_candidate_targets(
            true,
            &["127.0.0.1".parse().unwrap()],
            19000,
            Some(local)
        )
        .is_ok());
        assert_eq!(
            validate_candidate_targets(
                true,
                &["192.168.1.50".parse().unwrap()],
                8080,
                Some(local)
            ),
            Err(local)
        );

        // Async pre-connect verification: a listening local socket must NEVER receive a TCP SYN
        // when a non-loopback peer resolves to loopback/RFC1918/metadata addresses.
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy", "--no-doh"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let internal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let internal_port = internal_listener.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicBool::new(false));
        let accepted_flag = Arc::clone(&accepted);
        let watcher = tokio::spawn(async move {
            if internal_listener.accept().await.is_ok() {
                accepted_flag.store(true, Ordering::SeqCst);
            }
        });

        assert!(matches!(
            connect_http_target(&ctx, "127.0.0.1", internal_port, false, Some(local)).await,
            Err(ConnectTargetError::Forbidden(_))
        ));
        assert!(matches!(
            connect_http_target(&ctx, "rebind.localhost", internal_port, false, Some(local)).await,
            Err(ConnectTargetError::Forbidden(_))
        ));
        assert!(matches!(
            connect_http_target(&ctx, "169.254.169.254", 80, false, Some(local)).await,
            Err(ConnectTargetError::Forbidden(addr)) if addr == "169.254.169.254:80".parse::<SocketAddr>().unwrap()
        ));
        assert!(matches!(
            connect_http_target(&ctx, "10.0.0.1", 22, false, Some(local)).await,
            Err(ConnectTargetError::Forbidden(addr)) if addr == "10.0.0.1:22".parse::<SocketAddr>().unwrap()
        ));

        tokio::time::sleep(Duration::from_millis(20)).await;
        watcher.abort();
        assert!(
            !accepted.load(Ordering::SeqCst),
            "forbidden target must be blocked before initiating TCP connect"
        );
    }

    #[tokio::test]
    async fn pac_endpoint_uses_no_cache_private_and_bypasses_riot_unblocked_vpn_and_msft_domains() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"])
            .unwrap()
            .into_runtime_config();
        // Duplicate of a built-in PAC bypass should not be emitted twice.
        cfg.bypass_domains = vec!["*.riotgames.com".to_string()];
        let ctx = EngineContext::new(cfg).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client(sock, ctx).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        server.await.unwrap().unwrap();

        let resp_str = String::from_utf8(resp).unwrap();
        let (headers, body) = resp_str.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains("Cache-Control: no-cache, max-age=0, private\r\n"));
        assert!(!headers.contains("no-store"));
        assert!(!headers.contains("max-age=30"));

        let direct_branch = body
            .rsplit_once("return \"DIRECT\";")
            .expect("PAC script must contain DIRECT return")
            .0;

        for domain in [
            "riotgames.com",
            "riotgames.net",
            "riotcdn.net",
            "playvalorant.com",
            "valorant.com",
            "pvp.net",
            "rgpub.io",
            "rdatasrv.net",
            "leagueoflegends.com",
            "cloudflareclient.com",
            "tailscale.com",
            "tailscale.io",
            "radmin-vpn.com",
            "radmin.com",
            "famatech.com",
            "expressvpn.com",
            "expressapisv2.net",
            "xvnet.net",
            "windowsupdate.com",
            "update.microsoft.com",
            "delivery.mp.microsoft.com",
            "smartscreen.microsoft.com",
            "wns.windows.com",
            "gvt2.com",
        ] {
            let exact = format!("h === \"{domain}\"");
            let suffix = format!("\".{domain}\"");
            assert!(
                direct_branch.contains(&exact),
                "missing PAC exact DIRECT clause for {domain}"
            );
            assert!(
                direct_branch.contains(&suffix),
                "missing PAC subdomain DIRECT clause for {domain}"
            );
        }

        // BTK-blocked consumer VPN & Proton web domains must NOT bypass the proxy by default.
        for blocked_vpn_domain in [
            "proton.me",
            "protonvpn.com",
            "mullvad.net",
            "nordvpn.com",
            "surfshark.com",
            "windscribe.com",
            "cyberghostvpn.com",
            "privateinternetaccess.com",
            "pia-dns.com",
            "ipvanish.com",
            "tunnelbear.com",
            "adguard-vpn.com",
            "hotspotshield.com",
            "warp.plus",
        ] {
            assert!(
                !direct_branch.contains(blocked_vpn_domain),
                "BTK-blocked consumer VPN/Proton domain must not be default DIRECT: {blocked_vpn_domain}"
            );
        }

        // Built-in + user duplicate `*.riotgames.com` must only appear once.
        assert_eq!(body.matches("h === \"riotgames.com\"").count(), 1);
    }

    #[tokio::test]
    async fn pac_endpoint_respects_include_domain_overrides_for_riot_and_vpn_defaults() {
        let mut cfg = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"])
            .unwrap()
            .into_runtime_config();
        cfg.patterns = vec![
            "auth.riotgames.com".to_string(),
            "*.tailscale.com".to_string(),
            r"\.expressvpn\.com$".to_string(),
        ];
        // Explicit user bypass still wins over include_domains.
        cfg.bypass_domains = vec!["expressvpn.com".to_string()];
        let ctx = EngineContext::new(cfg).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client(sock, ctx).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET /vdpi.pac HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            addr.port()
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        server.await.unwrap().unwrap();

        let resp_str = String::from_utf8(resp).unwrap();
        let (_, body) = resp_str.split_once("\r\n\r\n").unwrap();

        // Overridden defaults are omitted so included targets reach the proxy.
        assert!(!body.contains("h === \"riotgames.com\""));
        assert!(!body.contains("h === \"tailscale.com\""));
        // Explicit user bypass still remains DIRECT.
        assert!(body.contains("h === \"expressvpn.com\""));
        // Unrelated Riot, mesh VPN, and OS update domains stay DIRECT.
        assert!(body.contains("h === \"valorant.com\""));
        assert!(body.contains("h === \"tailscale.io\""));
        assert!(body.contains("h === \"radmin-vpn.com\""));
        assert!(body.contains("h === \"windowsupdate.com\""));
    }

    #[test]
    fn pac_bypass_clauses_emit_is_in_net_v6_for_bare_ipv6_and_guard_multi_wildcards() {
        let entries = vec![
            "2001:0db8::1".to_string(),
            "[fd00::42]".to_string(),
            "*.foo.*.example.com".to_string(),
            "*.".to_string(),
            "198.51.100.7".to_string(),
        ];
        let clauses = render_pac_bypass_clauses(&entries);
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"2001:db8::1\", 128))"));
        assert!(clauses.contains("(h.indexOf(\":\") !== -1 && isInNetV6(h, \"fd00::42\", 128))"));
        assert!(clauses.contains("shExpMatch(h, \"*.foo.*.example.com\")"));
        assert!(!clauses.contains("h === \"foo.*.example.com\""));
        assert!(!clauses.contains("shExpMatch(h, \"*\")"));
        assert!(clauses.contains("h === \"198.51.100.7\""));

        let script = render_pac_script_with_bypass("127.0.0.1:8080", &["2001:db8::1".to_string()]);
        assert!(script.contains("isInNetV6(h, \"2001:db8::1\", 128)"));
        assert!(script.contains("function isInNetV6(ip, net, prefixLen)"));
    }

    #[test]
    fn pac_path_is_case_insensitive_and_allows_non_loopback_local_addr_match() {
        let lan_local: SocketAddr = "192.168.1.50:8080".parse().unwrap();
        let lan_same_peer: SocketAddr = "192.168.1.50:54321".parse().unwrap();
        let lan_other_peer: SocketAddr = "192.168.1.99:54321".parse().unwrap();

        assert!(is_local_pac_request_target("/VDPI.PAC", Some(lan_local)));
        assert!(is_local_pac_request_target("/Vdpi.Pac?v=2", Some(lan_local)));
        assert!(is_local_pac_request_target(
            "http://192.168.1.50:8080/VDPI.PAC?ts=1",
            Some(lan_local)
        ));
        assert!(!is_local_pac_request_target(
            "http://192.168.1.99:8080/vdpi.pac",
            Some(lan_local)
        ));
        assert!(!is_local_pac_request_target("/vdpi.pac.bak", Some(lan_local)));

        assert!(is_local_pac_peer(Some(lan_same_peer), Some(lan_local)));
        assert!(!is_local_pac_peer(Some(lan_other_peer), Some(lan_local)));

        let lan_host_hdr = "GET /VDPI.PAC HTTP/1.1\r\nHost: 192.168.1.50:8080\r\n\r\n";
        let other_host_hdr = "GET /VDPI.PAC HTTP/1.1\r\nHost: 192.168.1.99:8080\r\n\r\n";
        assert!(is_local_pac_host(lan_host_hdr, Some(lan_local)));
        assert!(!is_local_pac_host(other_host_hdr, Some(lan_local)));
    }

    #[tokio::test]
    async fn http_handshake_timeout_returns_408_and_shuts_down_cleanly() {
        let cli = CliArgs::parse_from_iter(["vdpi", "--no-system-proxy"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            handle_http_client_with_timeout(sock, ctx, Duration::from_millis(50)).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n")
            .await
            .unwrap();

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).await.unwrap();
        assert_eq!(
            resp,
            b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn connect_pipelined_tls_record_reassembles_split_header_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        record.extend_from_slice(&[0xab; 16]);
        let rest_of_record = record[2..].to_vec();

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            // Send remaining 3 header bytes + 16-byte record body in two chunks.
            client.write_all(&rest_of_record[..3]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client.write_all(&rest_of_record[3..]).await.unwrap();
            let _ = client.shutdown().await;
        });

        let (mut server_sock, _) = listener.accept().await.unwrap();
        let mut initial = record[..2].to_vec();
        complete_pipelined_tls_record(&mut server_sock, &mut initial).await;
        client_task.await.unwrap();
        assert_eq!(initial, record);
    }
}
