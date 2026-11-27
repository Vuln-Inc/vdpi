use crate::config::TunnelConfig;
use anyhow::{anyhow, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Serialize;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vdpi_core::desync::EngineContext;

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub target: String,
    pub passed: bool,
    pub latency_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub checks: Vec<DoctorCheck>,
}

/// Builds a real, RFC-compliant TLS 1.3 + TLS 1.2 ClientHello using `rustls` so production
/// servers reply with a genuine TLS `ServerHello` instead of rejecting synthetic probes.
pub fn build_real_tls_client_hello(host: &str) -> Result<Vec<u8>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = ClientConfig::builder()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid TLS SNI hostname '{host}'"))?;
    let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
    let mut out = Vec::with_capacity(512);
    conn.write_tls(&mut out)?;
    if out.len() < 5 || out[0] != 0x16 {
        return Err(anyhow!("rustls did not emit a TLS handshake record"));
    }
    Ok(out)
}

fn is_valid_host_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

fn is_valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().is_ok()
}

/// Validates and extracts `host[:port]` (stripping any `userinfo@`) from an `https://`
/// authority, supporting RFC 3986 bracketed IPv6 literals and rejecting malformed
/// authorities so secrets stuffed into invalid URLs never leak.
fn parse_valid_doh_authority(authority: &str) -> Option<&str> {
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }

    if let Some(after_open) = host_port.strip_prefix('[') {
        let (ipv6_str, remainder) = after_open.split_once(']')?;
        ipv6_str.parse::<Ipv6Addr>().ok()?;
        if remainder.is_empty() {
            return Some(host_port);
        }
        let port = remainder.strip_prefix(':')?;
        return is_valid_port(port).then_some(host_port);
    }

    if host_port.contains(['[', ']']) {
        return None;
    }

    let (host, port_opt) = match host_port.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    if let Some(port) = port_opt {
        if !is_valid_port(port) {
            return None;
        }
    }

    let host_no_dot = host.strip_suffix('.').unwrap_or(host);
    if host_no_dot.is_empty() || host_no_dot.len() > 253 {
        return None;
    }
    host_no_dot
        .split('.')
        .all(is_valid_host_label)
        .then_some(host_port)
}

fn split_http_scheme(trimmed: &str) -> Option<(&'static str, &str)> {
    if trimmed
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        Some(("https://", &trimmed[8..]))
    } else if trimmed
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
    {
        Some(("http://", &trimmed[7..]))
    } else {
        None
    }
}

/// Redacts custom `https://` and `http://` URL path/query/userinfo tokens so NextDNS/ControlD
/// profile identifiers or proxy credentials are never leaked in doctor diagnostics or telemetry.
/// Bracketed IPv6 hosts are preserved; malformed URLs collapse to `<scheme>[redacted]` so raw
/// secrets can never leak.
fn redact_dns_addr(dns_addr: &str) -> String {
    let trimmed = dns_addr.trim();
    let Some((scheme, rest)) = split_http_scheme(trimmed) else {
        return trimmed.to_string();
    };

    let (authority, suffix) = match rest.find(['/', '?', '#']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    let Some(host_port) = parse_valid_doh_authority(authority) else {
        return format!("{scheme}[redacted]");
    };
    if !suffix.is_empty() && suffix != "/" {
        format!("{scheme}{host_port}/[redacted]")
    } else {
        format!("{scheme}{host_port}")
    }
}

fn find_http_scheme_ascii_ci(s: &str, from: usize) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    if bytes.len().saturating_sub(from) < 7 {
        return None;
    }
    for i in from..=bytes.len() - 7 {
        if bytes
            .get(i..i + 8)
            .is_some_and(|w| w.eq_ignore_ascii_case(b"https://"))
        {
            return Some((i, 8));
        }
        if bytes[i..i + 7].eq_ignore_ascii_case(b"http://") {
            return Some((i, 7));
        }
    }
    None
}

/// Redacts any embedded `https://` or `http://` URLs inside diagnostic/error detail strings
/// (e.g. `reqwest` or DNS resolver errors) so raw DoH tokens or credentials never leak in reports.
fn redact_urls_in_detail(detail: &str) -> String {
    let Some(first) = find_http_scheme_ascii_ci(detail, 0) else {
        return detail.to_string();
    };

    let mut out = String::with_capacity(detail.len());
    let mut cursor = 0usize;
    let mut next_match = Some(first);

    while let Some((start, scheme_len)) = next_match {
        out.push_str(&detail[cursor..start]);

        let rest = &detail[start..];
        let rel_end = rest
            .char_indices()
            .find(|&(_, ch)| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '<' | '>' | '`')
            })
            .map(|(idx, _)| idx)
            .unwrap_or(rest.len());

        let mut url_end = start + rel_end;
        // Strip trailing wrapper/sentence punctuation without stripping a closing
        // IPv6 bracket (`]`) or balanced delimiters inside the URL itself.
        while url_end > start + scheme_len {
            let candidate = &detail[start..url_end];
            let last = candidate.as_bytes()[candidate.len() - 1];
            let should_trim = match last {
                b',' | b';' | b'.' | b':' => true,
                b')' => {
                    candidate.bytes().filter(|&b| b == b')').count()
                        > candidate.bytes().filter(|&b| b == b'(').count()
                }
                b']' => {
                    candidate.bytes().filter(|&b| b == b']').count()
                        > candidate.bytes().filter(|&b| b == b'[').count()
                }
                b'}' => {
                    candidate.bytes().filter(|&b| b == b'}').count()
                        > candidate.bytes().filter(|&b| b == b'{').count()
                }
                _ => false,
            };
            if should_trim {
                url_end -= 1;
            } else {
                break;
            }
        }

        out.push_str(&redact_dns_addr(&detail[start..url_end]));
        cursor = url_end;
        next_match = find_http_scheme_ascii_ci(detail, cursor);
    }

    out.push_str(&detail[cursor..]);
    out
}

/// Runs live connectivity probes using `vdpi`'s real DoH resolver and 7-stage TLS desync engine.
pub async fn run_doctor(cfg: &TunnelConfig) -> DoctorReport {
    run_doctor_with_binder(cfg, None).await
}

/// Runs live connectivity probes using `vdpi`'s real DoH resolver and 7-stage TLS desync engine
/// with an optional outbound socket [`vdpi_core::binder::OutboundBinder`].
pub async fn run_doctor_with_binder(
    cfg: &TunnelConfig,
    binder: Option<Arc<dyn vdpi_core::binder::OutboundBinder>>,
) -> DoctorReport {
    let ctx = match crate::build_engine_context_with_binder(cfg.clone(), binder).await {
        Ok(c) => c,
        Err(e) => {
            return DoctorReport {
                ok: false,
                checks: vec![DoctorCheck {
                    name: "Engine Init".into(),
                    target: "vdpi-core".into(),
                    passed: false,
                    latency_ms: 0,
                    detail: redact_urls_in_detail(&format!("failed to initialize engine: {e}")),
                }],
            };
        }
    };

    // 1. Anti-poisoning DoH / DNS ring check (bounded timeout so offline networks never stall)
    let dns_target = format!("{} -> discord.com", redact_dns_addr(&ctx.config.dns_addr));
    let dns_start = Instant::now();
    let dns_check =
        match tokio::time::timeout(Duration::from_secs(8), ctx.dns.resolve("discord.com")).await {
            Ok(Ok(ips)) if !ips.is_empty() => DoctorCheck {
                name: "DNS Ring".into(),
                target: dns_target,
                passed: true,
                latency_ms: dns_start.elapsed().as_millis() as u64,
                detail: format!("resolved {} ({} records)", ips[0], ips.len()),
            },
            Ok(Ok(_)) => DoctorCheck {
                name: "DNS Ring".into(),
                target: dns_target,
                passed: false,
                latency_ms: dns_start.elapsed().as_millis() as u64,
                detail: "no usable IP records returned".into(),
            },
            Ok(Err(e)) => DoctorCheck {
                name: "DNS Ring".into(),
                target: dns_target,
                passed: false,
                latency_ms: dns_start.elapsed().as_millis() as u64,
                detail: redact_urls_in_detail(&e.to_string()),
            },
            Err(_) => DoctorCheck {
                name: "DNS Ring".into(),
                target: dns_target,
                passed: false,
                latency_ms: dns_start.elapsed().as_millis() as u64,
                detail: "DNS resolution timed out (8s)".into(),
            },
        };

    // 2..4. Run live TLS ClientHello -> ServerHello probes concurrently so full 7-stage
    // escalation finishes quickly without sequential stalls.
    let (c1, c2, c3) = tokio::join!(
        probe_tls_target(&ctx, "Discord API", "discord.com", 443),
        probe_tls_target(&ctx, "Discord Gateway", "gateway.discord.gg", 443),
        probe_tls_target(&ctx, "Roblox Web", "www.roblox.com", 443),
    );

    let checks = vec![dns_check, c1, c2, c3];
    let ok = checks.iter().all(|c| c.passed);
    DoctorReport { ok, checks }
}

async fn probe_tls_target(ctx: &EngineContext, name: &str, host: &str, port: u16) -> DoctorCheck {
    let start = Instant::now();
    let target = format!("{host}:{port}");

    let (remote, remote_addr) =
        match tokio::time::timeout(Duration::from_secs(10), ctx.connect_target(host, port)).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                return DoctorCheck {
                    name: name.into(),
                    target,
                    passed: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    detail: redact_urls_in_detail(&format!("connect failed: {e}")),
                };
            }
            Err(_) => {
                return DoctorCheck {
                    name: name.into(),
                    target,
                    passed: false,
                    latency_ms: start.elapsed().as_millis() as u64,
                    detail: "TCP connect timed out (10s)".into(),
                };
            }
        };

    probe_connected_tls_target(ctx, name, host, target, remote, remote_addr, start).await
}

async fn probe_connected_tls_target(
    ctx: &EngineContext,
    name: &str,
    host: &str,
    target: String,
    remote: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    start: Instant,
) -> DoctorCheck {
    let ch = match build_real_tls_client_hello(host) {
        Ok(bytes) => bytes,
        Err(e) => {
            return DoctorCheck {
                name: name.into(),
                target,
                passed: false,
                latency_ms: start.elapsed().as_millis() as u64,
                detail: format!("ClientHello build failed: {e}"),
            };
        }
    };

    let (mut client_side, engine_side) = tokio::io::duplex(32 * 1024);

    let relay_ctx = ctx.clone();
    let host_owned = host.to_string();
    let relay_task = tokio::spawn(async move {
        relay_ctx
            .relay_stream(engine_side, remote, Some(&host_owned), remote_addr)
            .await
    });

    if let Err(e) = client_side.write_all(&ch).await {
        relay_task.abort();
        return DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms: start.elapsed().as_millis() as u64,
            detail: format!("write probe failed: {e}"),
        };
    }

    // Read at least 6 bytes (5-byte TLS record header + 1-byte handshake message type) with an 18s
    // ceiling to accommodate full 7-stage adaptive escalation on strict ISPs.
    let read_res = tokio::time::timeout(Duration::from_secs(18), async {
        let mut head = [0u8; 6];
        let mut filled = 0usize;
        while filled < head.len() {
            let n = client_side.read(&mut head[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        Ok::<([u8; 6], usize), std::io::Error>((head, filled))
    })
    .await;

    drop(client_side);
    relay_task.abort();
    let _ = relay_task.await;

    let latency_ms = start.elapsed().as_millis() as u64;
    match read_res {
        Ok(Ok((head, filled)))
            if filled >= 6 && head[0] == 0x16 && head[1] == 0x03 && head[5] == 0x02 =>
        {
            let detail = if ctx.bypass.is_bypassed(Some(host), Some(remote_addr.ip())) {
                "TLS ServerHello via bypassed (direct)".to_string()
            } else {
                let learned = ctx
                    .adaptive_cache
                    .read()
                    .await
                    .get(&host.to_ascii_lowercase())
                    .copied()
                    .unwrap_or_else(|| ctx.preferred_stage());
                format!(
                    "TLS ServerHello via Stage {} ({})",
                    learned.stage_number(),
                    learned.label()
                )
            };
            DoctorCheck {
                name: name.into(),
                target,
                passed: true,
                latency_ms,
                detail,
            }
        }
        Ok(Ok((head, filled))) if filled > 0 => DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms,
            detail: format!(
                "unexpected TLS reply (type=0x{:02x}, len={filled})",
                head[0]
            ),
        },
        Ok(Ok(_)) => DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms,
            detail: "connection closed before ServerHello".into(),
        },
        Ok(Err(e)) => DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms,
            detail: format!("read error: {e}"),
        },
        Err(_) => DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms,
            detail: "TLS handshake timed out".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn real_tls_client_hello_completes_server_hello_against_rustls_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["doctor.test".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let srv_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(sock).await;
        });

        let mut runtime_cfg = TunnelConfig::default().into_runtime_config();
        runtime_cfg.patterns = vec!["doctor\\.test$".into()];
        let ctx = EngineContext::new(runtime_cfg).unwrap();
        let remote = ctx.connect_upstream_addr(addr).await.unwrap();
        let check = probe_connected_tls_target(
            &ctx,
            "Local TLS",
            "doctor.test",
            addr.to_string(),
            remote,
            addr,
            Instant::now(),
        )
        .await;
        let _ = srv.await;

        assert!(check.passed, "expected TLS ServerHello to pass: {check:?}");
        assert!(check.detail.contains("TLS ServerHello"));
    }

    #[test]
    fn redact_dns_addr_masks_custom_doh_paths_and_queries() {
        assert_eq!(redact_dns_addr("1.1.1.1"), "1.1.1.1");
        assert_eq!(
            redact_dns_addr("2606:4700:4700::1111"),
            "2606:4700:4700::1111"
        );
        assert_eq!(
            redact_dns_addr("https://dns.nextdns.io/abc123"),
            "https://dns.nextdns.io/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://dns.nextdns.io/abc123/My-Desktop?foo=bar"),
            "https://dns.nextdns.io/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://freedns.controld.com/p2"),
            "https://freedns.controld.com/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("HTTPS://dns.nextdns.io?token=secret"),
            "https://dns.nextdns.io/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://user:pass@dns.example.com/secret-id"),
            "https://dns.example.com/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]/dns-query"),
            "https://[2606:4700:4700::1111]/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://dns.nextdns.io"),
            "https://dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_addr("https://dns.nextdns.io/"),
            "https://dns.nextdns.io"
        );
    }

    #[test]
    fn redact_dns_addr_handles_ipv6_bracketed_and_malformed_urls() {
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]/secret-token?k=v"),
            "https://[2606:4700:4700::1111]/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]:8443/secret-token?k=v"),
            "https://[2606:4700:4700::1111]:8443/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("HTTPS://user:pass@[2606:4700:4700::1111]:8443/secret-token#frag"),
            "https://[2606:4700:4700::1111]:8443/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]"),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]/"),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(
            redact_dns_addr("https://[2606:4700:4700::1111]?token=secret"),
            "https://[2606:4700:4700::1111]/[redacted]"
        );

        let malformed = [
            "https://",
            "https:///secret-token",
            "https://?token=secret",
            "https://user:secret@",
            "https://user:secret@/path",
            "https://[2606:4700:4700::1111/secret-token",
            "https://[not-ipv6-secret]/dns-query",
            "https://[2606:4700:4700::1111]extra-secret/dns-query",
            "https://[2606:4700:4700::1111]:notaport/secret",
            "https://dns.nextdns.io:secret-token/path",
            "https://dns.nextdns.io\\secret-token",
            "https://2606:4700:4700::1111/secret-token",
            "https://dns.nextdns.io secret-token",
        ];
        for raw in malformed {
            let redacted = redact_dns_addr(raw);
            assert_eq!(
                redacted, "https://[redacted]",
                "expected malformed URL {raw:?} to collapse to https://[redacted]"
            );
            assert!(!redacted.contains("secret"));
            assert!(!redacted.contains("notaport"));
        }
    }

    #[test]
    fn redact_urls_in_detail_masks_embedded_doh_urls_in_errors() {
        assert_eq!(
            redact_urls_in_detail("DNS resolution timed out (8s)"),
            "DNS resolution timed out (8s)"
        );
        assert_eq!(
            redact_urls_in_detail(
                "error sending request for url (https://dns.nextdns.io/abc123/My-Phone?token=xyz): connection refused"
            ),
            "error sending request for url (https://dns.nextdns.io/[redacted]): connection refused"
        );
        assert_eq!(
            redact_urls_in_detail(
                "HTTP status server error (500) for url (https://[2606:4700:4700::1111]/secret-token?k=v): upstream failed"
            ),
            "HTTP status server error (500) for url (https://[2606:4700:4700::1111]/[redacted]): upstream failed"
        );
        assert_eq!(
            redact_urls_in_detail(
                "error sending request for url (https://[2606:4700:4700::1111]): connection reset"
            ),
            "error sending request for url (https://[2606:4700:4700::1111]): connection reset"
        );
        assert_eq!(
            redact_urls_in_detail(
                "error sending request for url (https://[2606:4700:4700::1111]:8443/secret-token): timeout"
            ),
            "error sending request for url (https://[2606:4700:4700::1111]:8443/[redacted]): timeout"
        );
        assert_eq!(
            redact_urls_in_detail(
                "DoH failed for 'HTTPS://user:pass@dns.nextdns.io/prof1?a=1', fallback <https://[2606:4700:4700::1111]/prof2>."
            ),
            "DoH failed for 'https://dns.nextdns.io/[redacted]', fallback <https://[2606:4700:4700::1111]/[redacted]>."
        );
        assert_eq!(
            redact_urls_in_detail(
                "invalid DoH endpoint (https://[bad-ipv6/secret-token): parse error"
            ),
            "invalid DoH endpoint (https://[redacted]): parse error"
        );
        assert_eq!(
            redact_urls_in_detail(
                "invalid DoH endpoint (https:///top-secret): empty host"
            ),
            "invalid DoH endpoint (https://[redacted]): empty host"
        );
        assert_eq!(
            redact_urls_in_detail(
                "bağlantı hatası (https://dns.nextdns.io/gizli?k=1): reddedildi"
            ),
            "bağlantı hatası (https://dns.nextdns.io/[redacted]): reddedildi"
        );
    }

    #[test]
    fn redact_dns_addr_and_detail_mask_http_and_https_urls() {
        assert_eq!(
            redact_dns_addr("http://user:pass@proxy.local:8080/secret?k=v"),
            "http://proxy.local:8080/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("HTTP://dns.example.com/profile123"),
            "http://dns.example.com/[redacted]"
        );
        assert_eq!(
            redact_dns_addr("http://[2606:4700:4700::1111]:8080/secret"),
            "http://[2606:4700:4700::1111]:8080/[redacted]"
        );
        assert_eq!(redact_dns_addr("http://example.com"), "http://example.com");
        assert_eq!(redact_dns_addr("http://example.com/"), "http://example.com");
        assert_eq!(redact_dns_addr("http://"), "http://[redacted]");
        assert_eq!(redact_dns_addr("http:///secret-path"), "http://[redacted]");
        assert_eq!(
            redact_dns_addr("http://user:secret@/path"),
            "http://[redacted]"
        );

        assert_eq!(
            redact_urls_in_detail(
                "proxy connect error for url (http://user:secret@proxy.example.com:8080/auth?k=1): refused"
            ),
            "proxy connect error for url (http://proxy.example.com:8080/[redacted]): refused"
        );
        assert_eq!(
            redact_urls_in_detail(
                "mixed HTTP://alice:pw@a.test/tok1, fallback <https://bob:pw@b.test/tok2>."
            ),
            "mixed http://a.test/[redacted], fallback <https://b.test/[redacted]>."
        );
        assert_eq!(
            redact_urls_in_detail("bad endpoint (http:///top-secret): parse error"),
            "bad endpoint (http://[redacted]): parse error"
        );
    }

    #[tokio::test]
    async fn probe_connected_tls_target_reports_bypassed_direct_when_host_is_bypassed() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["doctor.test".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
        let srv_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(sock).await;
        });

        let mut runtime_cfg = TunnelConfig {
            bypass_domains: vec!["doctor.test".into()],
            ..Default::default()
        }
        .into_runtime_config();
        runtime_cfg.patterns = vec!["doctor\\.test$".into()];
        let ctx = EngineContext::new(runtime_cfg).unwrap();
        let remote = ctx.connect_upstream_addr(addr).await.unwrap();
        let check = probe_connected_tls_target(
            &ctx,
            "Bypassed TLS",
            "doctor.test",
            addr.to_string(),
            remote,
            addr,
            Instant::now(),
        )
        .await;
        let _ = srv.await;

        assert!(check.passed, "expected bypassed TLS ServerHello to pass: {check:?}");
        assert!(
            check.detail.contains("bypassed (direct)"),
            "expected bypassed attribution, got: {}",
            check.detail
        );
        assert!(
            !check.detail.contains("Stage "),
            "bypassed host must not misattribute preferred stage: {}",
            check.detail
        );
    }

    #[tokio::test]
    async fn run_doctor_with_binder_routes_outbound_probes_through_binder() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountingRejectBinder(Arc<AtomicUsize>);

        impl vdpi_core::binder::OutboundBinder for CountingRejectBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "synthetic binder reject",
                ))
            }
        }

        let calls = Arc::new(AtomicUsize::new(0));
        let binder: Arc<dyn vdpi_core::binder::OutboundBinder> =
            Arc::new(CountingRejectBinder(Arc::clone(&calls)));
        let cfg = TunnelConfig {
            dns_addr: "1.1.1.1".into(),
            enable_doh: true,
            ..Default::default()
        };

        let report = tokio::time::timeout(
            Duration::from_secs(5),
            run_doctor_with_binder(&cfg, Some(binder)),
        )
        .await
        .expect("run_doctor_with_binder should fail fast when binder rejects");

        assert!(!report.ok);
        assert_eq!(report.checks.len(), 4);
        assert!(
            calls.load(Ordering::SeqCst) > 0,
            "expected doctor probes to invoke OutboundBinder"
        );
    }
}
