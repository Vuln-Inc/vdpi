use super::HANDSHAKE_TIMEOUT;
use crate::desync::EngineContext;
use crate::tls::expected_tls_record_len;
use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;

/// Handles an incoming HTTP/1.x proxy request or `CONNECT` tunnel on `client`.
pub async fn handle_http_client(mut client: TcpStream, ctx: EngineContext) -> Result<()> {
    let _ = client.set_nodelay(true);

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    let mut scan_from = 0;

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf[scan_from..]) {
            break scan_from + pos;
        }
        if buf.len() >= MAX_HTTP_HEADER_BYTES {
            let _ = client
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            let _ = client.flush().await;
            bail!("HTTP header exceeded {MAX_HTTP_HEADER_BYTES} bytes");
        }
        scan_from = buf.len().saturating_sub(3);
        let read_limit = temp.len().min(MAX_HTTP_HEADER_BYTES - buf.len());
        let n = tokio::time::timeout_at(deadline, client.read(&mut temp[..read_limit])).await??;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&temp[..n]);
    };

    let header_bytes = &buf[..header_end];
    let leftover = &buf[header_end..];
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
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
        let _ = client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            .await;
        bail!("malformed HTTP request line");
    }

    // Built-in local health endpoint for `vdpi status` / `vdpi doctor`
    if target == "/vdpi-health" {
        let body = format!(
            "{{\"status\":\"ok\",\"service\":\"vdpi\",\"version\":\"{}\"}}\n",
            env!("CARGO_PKG_VERSION")
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(resp.as_bytes()).await?;
        client.flush().await?;
        return Ok(());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = match parse_authority(target, 443) {
            Ok(hp) => hp,
            Err(e) => {
                let _ = client
                    .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                    .await;
                return Err(e);
            }
        };

        debug!(host = %host, port = port, "HTTP CONNECT request");
        match ctx.connect_target(&host, port).await {
            Ok((remote, remote_addr)) => {
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                client.flush().await?;

                if !leftover.is_empty() {
                    let mut initial = leftover.to_vec();
                    drop(buf);
                    if let Some(expected_len) = expected_tls_record_len(&initial) {
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
                    return ctx
                        .establish_and_relay(client, remote, &initial, Some(&host), remote_addr)
                        .await;
                }

                drop(buf);
                return ctx
                    .relay_tunnel(client, remote, Some(&host), remote_addr)
                    .await;
            }
            Err(e) => {
                debug!(host = %host, port = port, error = %e, "HTTP CONNECT upstream failed");
                let _ = client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                return Err(e);
            }
        }
    }

    // Standard plain HTTP proxy request (e.g. GET http://example.com/path HTTP/1.1)
    let (host, port, origin_path) = match parse_http_proxy_target(target, header_str) {
        Ok(res) => res,
        Err(e) => {
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Err(e);
        }
    };

    let rewritten = rewrite_http_request(method, &origin_path, version, header_str, leftover);
    drop(buf);
    match ctx.connect_target(&host, port).await {
        Ok((remote, remote_addr)) => {
            ctx.establish_and_relay(client, remote, &rewritten, Some(&host), remote_addr)
                .await
        }
        Err(e) => {
            let _ = client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            Err(e)
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
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
        let port = if let Some(p_str) = after.strip_prefix(':') {
            p_str.parse::<u16>()?
        } else {
            default_port
        };
        return Ok((v6.to_string(), port));
    }

    if let Some((h, p_str)) = trimmed.rsplit_once(':') {
        if !h.contains(':') {
            let port = p_str.parse::<u16>()?;
            return Ok((h.to_string(), port));
        }
    }

    Ok((trimmed.to_string(), default_port))
}

fn parse_http_proxy_target(target: &str, header_str: &str) -> Result<(String, u16, String)> {
    let absolute_rest = if target.len() >= 7
        && target.as_bytes()[..7].eq_ignore_ascii_case(b"http://")
    {
        Some(&target[7..])
    } else if target.len() >= 5 && target.as_bytes()[..5].eq_ignore_ascii_case(b"ws://") {
        Some(&target[5..])
    } else {
        None
    };

    if let Some(rest) = absolute_rest {
        let (authority, path) = match rest.find(['/', '?']) {
            Some(idx) if rest.as_bytes()[idx] == b'?' => (&rest[..idx], format!("/{}", &rest[idx..])),
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
        line.split_once(':')
            .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case("upgrade"))
    });

    let mut out = Vec::with_capacity(header_str.len() + body_prefix.len() + 24);
    out.extend_from_slice(format!("{method} {origin_path} {version}\r\n").as_bytes());

    let mut saw_connection = false;
    for line in header_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("proxy-connection")
                || name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                if has_upgrade {
                    saw_connection = true;
                } else {
                    continue;
                }
            }
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if has_upgrade {
        if !saw_connection {
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
        let no_conn = "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        let no_conn_rewritten = rewrite_http_request("GET", "/ws", "HTTP/1.1", no_conn, b"");
        let no_conn_s = String::from_utf8(no_conn_rewritten).unwrap();
        assert!(no_conn_s.contains("Upgrade: websocket\r\n"));
        assert!(no_conn_s.ends_with("Connection: Upgrade\r\n\r\n"));
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
        let req = format!(
            "GET http://{upstream_addr}/ping HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"
        );
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
}
