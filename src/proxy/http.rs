use crate::desync::EngineContext;
use crate::tls::expected_tls_record_len;
use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;

/// Handles an incoming HTTP/1.x proxy request or `CONNECT` tunnel on `client`.
pub async fn handle_http_client(mut client: TcpStream, ctx: EngineContext) -> Result<()> {
    let _ = client.set_nodelay(true);

    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];

    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() >= MAX_HTTP_HEADER_BYTES {
            let _ = client
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n",
                )
                .await;
            bail!("HTTP header exceeded {MAX_HTTP_HEADER_BYTES} bytes");
        }
        let n = tokio::time::timeout(Duration::from_secs(15), client.read(&mut temp)).await??;
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

    if method.is_empty() || target.is_empty() {
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
    match ctx.connect_target(&host, port).await {
        Ok((mut remote, remote_addr)) => {
            ctx.write_initial_flight(&mut remote, &rewritten, Some(&host), remote_addr.ip())
                .await?;
            let _ = copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
            Ok(())
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
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("HTTP://"))
    {
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        let (host, port) = parse_authority(authority, 80)?;
        return Ok((host, port, path.to_string()));
    }

    // Fallback: origin-form with Host header
    for line in header_str.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        if line.len() >= 5 && line.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            let raw_auth = line[5..].trim();
            let (host, port) = parse_authority(raw_auth, 80)?;
            let path = if target.starts_with('/') {
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
    let mut out = Vec::with_capacity(header_str.len() + body_prefix.len());
    out.extend_from_slice(format!("{method} {origin_path} {version}\r\n").as_bytes());

    for line in header_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let lower_prefix = line.as_bytes();
        if lower_prefix.len() >= 16 && lower_prefix[..16].eq_ignore_ascii_case(b"proxy-connection")
        {
            continue;
        }
        if lower_prefix.len() >= 19
            && lower_prefix[..19].eq_ignore_ascii_case(b"proxy-authorization")
        {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body_prefix);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let raw = "GET http://example.com:8080/hello?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\nUser-Agent: curl\r\n\r\n";
        let (h, p, path) =
            parse_http_proxy_target("http://example.com:8080/hello?x=1", raw).unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/hello?x=1");

        let rewritten = rewrite_http_request("GET", &path, "HTTP/1.1", raw, b"");
        let s = String::from_utf8(rewritten).unwrap();
        assert!(s.starts_with("GET /hello?x=1 HTTP/1.1\r\n"));
        assert!(!s.to_ascii_lowercase().contains("proxy-connection"));
        assert!(s.contains("Host: example.com:8080\r\n"));
    }
}
