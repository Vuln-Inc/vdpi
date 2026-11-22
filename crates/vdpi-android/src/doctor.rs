use crate::config::AndroidConfig;
use anyhow::{anyhow, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vdpi::desync::EngineContext;

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

/// Runs live connectivity probes using `vdpi`'s real DoH resolver and 7-stage TLS desync engine.
pub async fn run_doctor(cfg: &AndroidConfig) -> DoctorReport {
    let runtime_cfg = cfg.clone().into_runtime_config();
    let ctx = match EngineContext::new(runtime_cfg) {
        Ok(c) => c,
        Err(e) => {
            return DoctorReport {
                ok: false,
                checks: vec![DoctorCheck {
                    name: "Engine Init".into(),
                    target: "vdpi-core".into(),
                    passed: false,
                    latency_ms: 0,
                    detail: format!("failed to initialize engine: {e}"),
                }],
            };
        }
    };

    // 1. Anti-poisoning DoH / DNS ring check
    let dns_start = Instant::now();
    let dns_check = match ctx.dns.resolve("discord.com").await {
        Ok(ips) if !ips.is_empty() => DoctorCheck {
            name: "DNS Ring".into(),
            target: format!("{} -> discord.com", ctx.config.dns_addr),
            passed: true,
            latency_ms: dns_start.elapsed().as_millis() as u64,
            detail: format!("resolved {} ({} records)", ips[0], ips.len()),
        },
        Ok(_) => DoctorCheck {
            name: "DNS Ring".into(),
            target: format!("{} -> discord.com", ctx.config.dns_addr),
            passed: false,
            latency_ms: dns_start.elapsed().as_millis() as u64,
            detail: "no usable IP records returned".into(),
        },
        Err(e) => DoctorCheck {
            name: "DNS Ring".into(),
            target: format!("{} -> discord.com", ctx.config.dns_addr),
            passed: false,
            latency_ms: dns_start.elapsed().as_millis() as u64,
            detail: e.to_string(),
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

async fn probe_tls_target(
    ctx: &EngineContext,
    name: &str,
    host: &str,
    port: u16,
) -> DoctorCheck {
    let start = Instant::now();
    let target = format!("{host}:{port}");

    let (remote, remote_addr) = match ctx.connect_target(host, port).await {
        Ok(pair) => pair,
        Err(e) => {
            return DoctorCheck {
                name: name.into(),
                target,
                passed: false,
                latency_ms: start.elapsed().as_millis() as u64,
                detail: format!("connect failed: {e}"),
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

    let latency_ms = start.elapsed().as_millis() as u64;
    match read_res {
        Ok(Ok((head, filled)))
            if filled >= 6 && head[0] == 0x16 && head[1] == 0x03 && head[5] == 0x02 =>
        {
            let learned = ctx
                .adaptive_cache
                .read()
                .await
                .get(&host.to_ascii_lowercase())
                .copied()
                .unwrap_or_else(|| ctx.preferred_stage());
            DoctorCheck {
                name: name.into(),
                target,
                passed: true,
                latency_ms,
                detail: format!(
                    "TLS ServerHello via Stage {} ({})",
                    learned.stage_number(),
                    learned.label()
                ),
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

        let cfg = AndroidConfig::default();
        let ctx = EngineContext::new(cfg.into_runtime_config()).unwrap();
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
}
