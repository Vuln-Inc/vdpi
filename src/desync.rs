use crate::bypass::BypassPolicy;
use crate::config::{DesyncMode, RuntimeConfig};
use crate::dns::DnsResolver;
use crate::tls::{
    expected_tls_record_len, extract_http_host_split, parse_client_hello, split_tls_records,
    ClientHelloInfo,
};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::debug;

/// Strategy learned per-hostname by the 3-Stage Adaptive Auto-Heal TLS Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnedStrategy {
    /// Configured primary desync mode (default `Combo`: SNI record split + chunked pre-SNI record).
    Primary,
    /// Single-record fine TCP segment fragmentation across the SNI header (compatible with servers
    /// that forbid multi-record ClientHellos while still defeating active fiber DPI).
    FineFragment,
    /// Unmodified single-record passthrough (for strict non-blocked CDNs/WAFs).
    DirectPassthrough,
}

#[derive(Clone)]
pub struct EngineContext {
    pub config: Arc<RuntimeConfig>,
    pub dns: DnsResolver,
    pub bypass: Arc<BypassPolicy>,
    pub adaptive_cache: Arc<RwLock<HashMap<String, LearnedStrategy>>>,
}

impl EngineContext {
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        let dns = DnsResolver::new(
            &config.dns_addr,
            config.dns_port,
            config.enable_doh,
            config.dns_ipv4_only,
        )?;
        let bypass = BypassPolicy::new(&config.bypass_domains, &config.patterns)?;
        Ok(Self {
            config: Arc::new(config),
            dns,
            bypass: Arc::new(bypass),
            adaptive_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Resolves `host` via DoH/DNS and connects to `(ip, port)` with Happy Eyeballs fallback and `TCP_NODELAY`.
    pub async fn connect_target(&self, host: &str, port: u16) -> Result<(TcpStream, SocketAddr)> {
        let ips = self
            .dns
            .resolve(host)
            .await
            .with_context(|| format!("DNS resolution failed for {host}"))?;

        if ips.is_empty() {
            bail!("no addresses returned for {host}");
        }

        let total_ips = ips.len();
        let mut last_err = None;

        for (idx, ip) in ips.into_iter().enumerate() {
            let target = SocketAddr::new(ip, port);
            let attempt_timeout = if idx + 1 < total_ips {
                self.config.connect_timeout.min(Duration::from_secs(3))
            } else {
                self.config.connect_timeout
            };

            match tokio::time::timeout(attempt_timeout, TcpStream::connect(target)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, target));
                }
                Ok(Err(e)) => {
                    last_err = Some(anyhow!("connect {target} failed: {e}"));
                }
                Err(_) => {
                    last_err = Some(anyhow!(
                        "connect {target} timed out after {attempt_timeout:?}"
                    ));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("failed to connect to {host}:{port}")))
    }

    /// Relays a bidirectional TCP tunnel between `client` and `remote`, inspecting the initial
    /// client flight to apply adaptive TLS ClientHello or HTTP Host DPI desynchronization.
    pub async fn relay_tunnel(
        &self,
        mut client: TcpStream,
        mut remote: TcpStream,
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let _ = client.set_nodelay(true);
        let _ = remote.set_nodelay(true);

        let mut first_buf = vec![0u8; 16384 + 512];
        let mut remote_buf = [0u8; 4096];
        let mut filled: usize;

        // Wait for initial client flight, while remaining safe for server-speaks-first protocols.
        tokio::select! {
            biased;
            res = client.read(&mut first_buf) => {
                let n = res?;
                if n == 0 {
                    return Ok(());
                }
                filled = n;
            }
            res = remote.read(&mut remote_buf) => {
                let n = res?;
                if n == 0 {
                    return Ok(());
                }
                client.write_all(&remote_buf[..n]).await?;
                let _ = copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
                return Ok(());
            }
        }

        // If the first flight starts a TLS Handshake record (e.g. 1,800-byte Post-Quantum ClientHello),
        // read until the complete outer TLS record has arrived before splitting records.
        if let Some(expected_total) = expected_tls_record_len(&first_buf[..filled]) {
            if expected_total <= first_buf.len() && filled < expected_total {
                let _ = tokio::time::timeout(Duration::from_millis(400), async {
                    while filled < expected_total {
                        let n = client.read(&mut first_buf[filled..expected_total]).await?;
                        if n == 0 {
                            break;
                        }
                        filled += n;
                    }
                    Ok::<(), std::io::Error>(())
                })
                .await;
            }
        }

        let payload = &first_buf[..filled];
        self.establish_and_relay(client, remote, payload, known_host, remote_addr)
            .await
    }

    /// Delivers an already-buffered initial client flight (`payload`) to `remote` with 3-stage
    /// adaptive TLS auto-healing and then enters full-speed bidirectional streaming.
    pub async fn establish_and_relay(
        &self,
        mut client: TcpStream,
        mut remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let remote_ip = remote_addr.ip();

        if let Some(ch_info) = parse_client_hello(payload) {
            let effective_host = ch_info.sni.as_deref().or(known_host);
            if !self.bypass.should_desync(effective_host, Some(remote_ip)) {
                debug!(host = ?effective_host, %remote_ip, "TLS passthrough (bypassed)");
                remote.write_all(payload).await?;
                remote.flush().await?;
                let _ = copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
                return Ok(());
            }

            let cache_key = effective_host.map(|h| h.to_ascii_lowercase());
            if let Some(ref key) = cache_key {
                let cached = self.adaptive_cache.read().await.get(key).copied();
                if let Some(strategy) = cached {
                    self.write_tls_strategy(&mut remote, payload, &ch_info, strategy)
                        .await?;
                    let _ =
                        copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
                    return Ok(());
                }
            }

            // If additional bytes were coalesced after the first TLS record, skip active probing.
            if payload.len() != ch_info.record_total_len {
                self.write_tls_strategy(&mut remote, payload, &ch_info, LearnedStrategy::Primary)
                    .await?;
                let _ = copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
                return Ok(());
            }

            // 3-Stage Adaptive Auto-Heal Handshake Probe:
            // Stage 1: Configured Primary mode (e.g. Combo TLS record split + TCP segmenting)
            // Stage 2: Fine single-record TCP segment fragmentation (for servers rejecting multi-record ClientHello)
            // Stage 3: Clean single-record passthrough (for unblocked strict CDNs/WAFs)
            let stages = [
                LearnedStrategy::Primary,
                LearnedStrategy::FineFragment,
                LearnedStrategy::DirectPassthrough,
            ];
            let mut probe_buf = vec![0u8; 16384];
            let mut current_remote = Some(remote);

            for (idx, &stage) in stages.iter().enumerate() {
                let mut stream = match current_remote.take() {
                    Some(s) => s,
                    None => {
                        match tokio::time::timeout(
                            Duration::from_millis(2500),
                            TcpStream::connect(remote_addr),
                        )
                        .await
                        {
                            Ok(Ok(s)) => {
                                let _ = s.set_nodelay(true);
                                s
                            }
                            _ => continue,
                        }
                    }
                };

                if self
                    .write_tls_strategy(&mut stream, payload, &ch_info, stage)
                    .await
                    .is_err()
                {
                    continue;
                }

                let wait_ms = if idx == 0 { 1600 } else { 2200 };
                match tokio::time::timeout(
                    Duration::from_millis(wait_ms),
                    stream.read(&mut probe_buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        let first_byte = probe_buf[0];
                        // 0x15 is a TLS Alert record (e.g. illegal_parameter from strict servers on multi-record ClientHello).
                        // If a stage receives a TLS Alert and more fallback stages remain, heal automatically!
                        if first_byte == 0x15 && idx + 1 < stages.len() {
                            debug!(
                                host = ?effective_host,
                                ?stage,
                                "upstream returned TLS Alert (0x15); auto-healing with next stage"
                            );
                            continue;
                        }

                        if let Some(key) = cache_key {
                            let mut guard = self.adaptive_cache.write().await;
                            if guard.len() > 4096 {
                                guard.clear();
                            }
                            guard.insert(key, stage);
                        }

                        client.write_all(&probe_buf[..n]).await?;
                        client.flush().await?;
                        let _ =
                            copy_bidirectional_with_sizes(&mut client, &mut stream, 65536, 65536)
                                .await;
                        return Ok(());
                    }
                    _ => {
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            "TLS stage reset or timed out; auto-healing with next stage"
                        );
                        continue;
                    }
                }
            }

            bail!(
                "all adaptive TLS handshake stages failed for {:?}",
                effective_host
            );
        }

        // Non-TLS or plain HTTP traffic
        self.write_initial_flight(&mut remote, payload, known_host, remote_ip)
            .await?;
        let _ = copy_bidirectional_with_sizes(&mut client, &mut remote, 65536, 65536).await;
        Ok(())
    }

    async fn write_tls_strategy(
        &self,
        remote: &mut TcpStream,
        payload: &[u8],
        ch_info: &ClientHelloInfo,
        strategy: LearnedStrategy,
    ) -> Result<()> {
        let chunk_len = self.config.chunk_size.max(1);
        match strategy {
            LearnedStrategy::Primary => match self.config.mode {
                DesyncMode::Combo => {
                    if let Some((rec1, rec2)) = split_tls_records(payload, ch_info, chunk_len) {
                        write_in_chunks(remote, &rec1, chunk_len).await?;
                        remote.write_all(&rec2).await?;
                        remote.flush().await?;
                    } else {
                        write_in_chunks(remote, payload, chunk_len).await?;
                    }
                }
                DesyncMode::TlsRecord => {
                    if let Some((rec1, rec2)) = split_tls_records(payload, ch_info, chunk_len) {
                        remote.write_all(&rec1).await?;
                        remote.flush().await?;
                        remote.write_all(&rec2).await?;
                        remote.flush().await?;
                    } else {
                        write_in_chunks(remote, payload, chunk_len).await?;
                    }
                }
                DesyncMode::Fragment => {
                    write_in_chunks(remote, payload, chunk_len).await?;
                }
                DesyncMode::Split => {
                    let split_at = chunk_len.min(payload.len().saturating_sub(1)).max(1);
                    if payload.len() > 1 {
                        remote.write_all(&payload[..split_at]).await?;
                        remote.flush().await?;
                        remote.write_all(&payload[split_at..]).await?;
                        remote.flush().await?;
                    } else {
                        remote.write_all(payload).await?;
                    }
                }
            },
            LearnedStrategy::FineFragment => {
                // Keep a single outer TLS record (100% compatible with servers that reject multi-record
                // ClientHellos), but slice the bytes up through the end of the SNI extension into
                // 2-byte TCP segments with TCP_NODELAY so active DPI state machines fail SNI reassembly.
                let sni_end = match (ch_info.sni_payload_offset, ch_info.sni_len) {
                    (Some(off), Some(len)) => (5 + off + len).min(payload.len()),
                    _ => payload.len().min(64),
                };
                write_in_chunks(remote, &payload[..sni_end], 2).await?;
                if sni_end < payload.len() {
                    remote.write_all(&payload[sni_end..]).await?;
                    remote.flush().await?;
                }
            }
            LearnedStrategy::DirectPassthrough => {
                remote.write_all(payload).await?;
                remote.flush().await?;
            }
        }
        Ok(())
    }

    /// Writes an already-buffered initial request/handshake `payload` to `remote`, applying
    /// configured DPI desynchronization when eligible.
    pub async fn write_initial_flight(
        &self,
        remote: &mut TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_ip: IpAddr,
    ) -> Result<()> {
        if let Some(ch_info) = parse_client_hello(payload) {
            let effective_host = ch_info.sni.as_deref().or(known_host);
            if !self.bypass.should_desync(effective_host, Some(remote_ip)) {
                remote.write_all(payload).await?;
                remote.flush().await?;
                return Ok(());
            }
            return self
                .write_tls_strategy(remote, payload, &ch_info, LearnedStrategy::Primary)
                .await;
        }

        if let Some((http_host, split_at)) = extract_http_host_split(payload) {
            let effective_host = Some(http_host.as_str()).or(known_host);
            if self.bypass.should_desync(effective_host, Some(remote_ip)) && payload.len() > 1 {
                debug!(host = %http_host, %remote_ip, "applying plain HTTP Host DPI split");
                remote.write_all(&payload[..split_at]).await?;
                remote.flush().await?;
                remote.write_all(&payload[split_at..]).await?;
                remote.flush().await?;
                return Ok(());
            }
        }

        remote.write_all(payload).await?;
        remote.flush().await?;
        Ok(())
    }
}

async fn write_in_chunks(stream: &mut TcpStream, data: &[u8], chunk_size: usize) -> Result<()> {
    let step = chunk_size.max(1);
    for chunk in data.chunks(step) {
        stream.write_all(chunk).await?;
        stream.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use crate::tls::build_synthetic_client_hello;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn combo_desync_rewrites_client_hello_into_two_valid_tls_records() {
        let cli =
            CliArgs::parse_from_iter(["vdpi", "--no-system-proxy", "--chunk-size", "10"]).unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        let ch = build_synthetic_client_hello("discord.com", 512);
        let ch_expected = ch.clone();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut received = Vec::new();
            sock.read_to_end(&mut received).await.unwrap();
            received
        });

        let mut remote = TcpStream::connect(upstream_addr).await.unwrap();
        remote.set_nodelay(true).unwrap();
        let public_ip: IpAddr = "162.159.135.232".parse().unwrap();
        ctx.write_initial_flight(&mut remote, &ch, Some("discord.com"), public_ip)
            .await
            .unwrap();
        drop(remote);

        let received = server_task.await.unwrap();
        assert_eq!(received.len(), ch_expected.len() + 5);
        assert_eq!(received[0], 0x16);
        let r1_len = u16::from_be_bytes([received[3], received[4]]) as usize;
        assert_eq!(received[5 + r1_len], 0x16);
        let r2_len =
            u16::from_be_bytes([received[5 + r1_len + 3], received[5 + r1_len + 4]]) as usize;

        let mut reassembled = Vec::new();
        reassembled.extend_from_slice(&received[5..5 + r1_len]);
        reassembled.extend_from_slice(&received[5 + r1_len + 5..5 + r1_len + 5 + r2_len]);
        assert_eq!(reassembled, ch_expected[5..]);
    }

    #[tokio::test]
    async fn adaptive_auto_heal_recovers_when_strict_cdn_rejects_split_tls_record() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--chunk-size",
            "10",
            "--include",
            "strict-images\\.example$",
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let ch = build_synthetic_client_hello("cdn.strict-images.example", 256);
        let orig_rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_srv = Arc::clone(&attempts);

        // Mock a strict image CDN that returns a fatal TLS Alert (0x15) if the first TLS record
        // was split shorter than the full ClientHello, and returns a valid ServerHello (0x16)
        // when it receives a single intact outer TLS record.
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                let attempts_conn = Arc::clone(&attempts_srv);
                tokio::spawn(async move {
                    attempts_conn.fetch_add(1, Ordering::SeqCst);
                    let mut hdr = [0u8; 5];
                    if sock.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    let mut body = vec![0u8; rec_len];
                    let _ = sock.read_exact(&mut body).await;

                    if rec_len < orig_rec_len {
                        // Reject multi-record split with TLS Alert illegal_parameter (0x15)
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        // Accept single-record FineFragment and send ServerHello (0x16)
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O',
                            ])
                            .await;
                    }
                });
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let ch_send = ch.clone();

        let client_task = tokio::spawn(async move {
            let mut c = TcpStream::connect(proxy_addr).await.unwrap();
            c.write_all(&ch_send).await.unwrap();
            let mut reply = [0u8; 10];
            c.read_exact(&mut reply).await.unwrap();
            reply
        });

        let (accepted_client, _) = proxy_listener.accept().await.unwrap();
        let initial_remote = TcpStream::connect(upstream_addr).await.unwrap();
        ctx.relay_tunnel(
            accepted_client,
            initial_remote,
            Some("cdn.strict-images.example"),
            upstream_addr,
        )
        .await
        .unwrap();

        let reply = client_task.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O']
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("cdn.strict-images.example")
                .copied(),
            Some(LearnedStrategy::FineFragment)
        );
    }
}
