use crate::config::AndroidConfig;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vdpi::desync::EngineContext;
use vdpi::tls::build_synthetic_client_hello;

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

    let mut checks = Vec::with_capacity(4);

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
    checks.push(dns_check);

    // 2..4. Live TLS ClientHello -> ServerHello probes through vdpi's adaptive 7-stage engine
    let targets = [
        ("Discord API", "discord.com", 443u16),
        ("Discord Gateway", "gateway.discord.gg", 443u16),
        ("Roblox Web", "www.roblox.com", 443u16),
    ];

    for (name, host, port) in targets {
        checks.push(probe_tls_target(&ctx, name, host, port).await);
    }

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

    let ch = build_synthetic_client_hello(host, 512);
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

    let mut reply = [0u8; 64];
    let read_res = tokio::time::timeout(Duration::from_secs(7), client_side.read(&mut reply)).await;
    drop(client_side);
    relay_task.abort();

    let latency_ms = start.elapsed().as_millis() as u64;
    match read_res {
        Ok(Ok(n)) if n >= 2 && reply[0] == 0x16 && reply[1] == 0x03 => {
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
                detail: format!("TLS ServerHello via Stage {} ({})", learned.stage_number(), learned.label()),
            }
        }
        Ok(Ok(n)) if n > 0 => DoctorCheck {
            name: name.into(),
            target,
            passed: false,
            latency_ms,
            detail: format!("unexpected non-TLS reply (0x{:02x})", reply[0]),
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
