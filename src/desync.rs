use crate::bypass::BypassPolicy;
use crate::config::{DesyncMode, RuntimeConfig};
use crate::dns::DnsResolver;
use crate::tls::{
    expected_tls_record_len, extract_http_host_splits, parse_client_hello, split_tls_records,
    split_tls_records_deep, split_tls_records_multi, ClientHelloInfo,
};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::debug;

/// Strategy learned per-hostname (and globally per ISP network) by the 7-Stage Adaptive
/// Auto-Heal TLS Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LearnedStrategy {
    /// Stage 1: Configured primary mode (default `Combo`: 4 wire-paced RFC-compliant TLS records
    /// split across the handshake header and SNI midpoint).
    Primary = 0,
    /// Stage 2: TCP Out-of-Band (`MSG_OOB`) urgent decoy byte injected right at the SNI midpoint.
    /// Real server TCP stacks (`SO_OOBINLINE=0`) strip the urgent byte seamlessly while stateful
    /// full-stream-reassembling ISP DPI boxes corrupt/miss the SNI completely.
    OobSniDesync = 1,
    /// Stage 3: Combined 4-record TLS split + `MSG_OOB` decoy byte injected right at the TLS
    /// record boundary inside SNI, shifting subsequent TLS record framing for DPI state machines.
    MultiRecordOob = 2,
    /// Stage 4: Single intact outer TLS record split across 4 wire-paced TCP segments (compatible
    /// with strict servers that reject multi-record ClientHellos while defeating active DPI).
    FineFragment = 3,
    /// Stage 5: Deep 12+ RFC-compliant TLS record storm (up to 10 tiny 2-byte lead records
    /// exhausting hardware DPI per-flow packet caps before SNI hits the wire + SNI splits).
    DeepRecordStorm = 4,
    /// Stage 6: Single intact outer TLS record with slow 2-byte SNI-only pacing (for strict
    /// servers behind stateful burst-reassembling DPI).
    SlowSniSlice = 5,
    /// Stage 7: Unmodified single-write passthrough (for unblocked strict WAFs/CDNs).
    DirectPassthrough = 6,
}

impl LearnedStrategy {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Primary,
            1 => Self::OobSniDesync,
            2 => Self::MultiRecordOob,
            3 => Self::FineFragment,
            4 => Self::DeepRecordStorm,
            5 => Self::SlowSniSlice,
            6 => Self::DirectPassthrough,
            _ => Self::Primary,
        }
    }

    pub fn stage_number(self) -> u8 {
        (self as u8) + 1
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Primary => "ComboMultiRecord",
            Self::OobSniDesync => "OobSniDesync",
            Self::MultiRecordOob => "MultiRecordOob",
            Self::FineFragment => "FineFragment",
            Self::DeepRecordStorm => "DeepRecordStorm",
            Self::SlowSniSlice => "SlowSniSlice",
            Self::DirectPassthrough => "DirectPassthrough",
        }
    }

    fn is_desync(self) -> bool {
        !matches!(self, Self::DirectPassthrough)
    }
}

/// Lock-free live engine counters shared across proxy and TUN sessions.
#[derive(Debug, Default)]
pub struct EngineTelemetry {
    pub active_connections: AtomicUsize,
    pub total_connections: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub tls_handshakes: AtomicU64,
    pub auto_heal_escalations: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EngineTelemetrySnapshot {
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub tls_handshakes: u64,
    pub auto_heal_escalations: u64,
}

struct ActiveConnGuard(Arc<EngineTelemetry>);

impl ActiveConnGuard {
    fn enter(telemetry: &Arc<EngineTelemetry>) -> Self {
        telemetry.active_connections.fetch_add(1, Ordering::Relaxed);
        telemetry.total_connections.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(telemetry))
    }
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

const ALL_STAGES: [LearnedStrategy; 7] = [
    LearnedStrategy::Primary,
    LearnedStrategy::OobSniDesync,
    LearnedStrategy::MultiRecordOob,
    LearnedStrategy::FineFragment,
    LearnedStrategy::DeepRecordStorm,
    LearnedStrategy::SlowSniSlice,
    LearnedStrategy::DirectPassthrough,
];

#[derive(Clone)]
pub struct EngineContext {
    pub config: Arc<RuntimeConfig>,
    pub dns: DnsResolver,
    pub bypass: Arc<BypassPolicy>,
    pub adaptive_cache: Arc<RwLock<HashMap<String, LearnedStrategy>>>,
    pub preferred_isp_stage: Arc<AtomicU8>,
    pub telemetry: Arc<EngineTelemetry>,
    pub(crate) listener_addrs: [Option<SocketAddr>; 4],
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
            preferred_isp_stage: Arc::new(AtomicU8::new(LearnedStrategy::Primary as u8)),
            telemetry: Arc::new(EngineTelemetry::default()),
            listener_addrs: [None; 4],
        })
    }

    pub fn telemetry_snapshot(&self) -> EngineTelemetrySnapshot {
        EngineTelemetrySnapshot {
            active_connections: self.telemetry.active_connections.load(Ordering::Relaxed),
            total_connections: self.telemetry.total_connections.load(Ordering::Relaxed),
            bytes_tx: self.telemetry.bytes_tx.load(Ordering::Relaxed),
            bytes_rx: self.telemetry.bytes_rx.load(Ordering::Relaxed),
            tls_handshakes: self.telemetry.tls_handshakes.load(Ordering::Relaxed),
            auto_heal_escalations: self.telemetry.auto_heal_escalations.load(Ordering::Relaxed),
        }
    }

    pub fn preferred_stage(&self) -> LearnedStrategy {
        LearnedStrategy::from_u8(self.preferred_isp_stage.load(Ordering::Relaxed))
    }

    pub async fn learned_host_count(&self) -> usize {
        self.adaptive_cache.read().await.len()
    }

    pub async fn clear_adaptive_cache(&self) {
        self.adaptive_cache.write().await.clear();
        self.preferred_isp_stage
            .store(LearnedStrategy::Primary as u8, Ordering::Relaxed);
    }

    /// Connects directly to an already-resolved upstream `SocketAddr` with `connect_timeout`
    /// and `TCP_NODELAY`, enforcing listener-loop and unspecified-address guards.
    pub async fn connect_upstream_addr(&self, target: SocketAddr) -> Result<TcpStream> {
        let stream =
            tokio::time::timeout(self.config.connect_timeout, self.connect_upstream(target))
                .await
                .map_err(|_| {
                    anyhow!(
                        "connect {target} timed out after {:?}",
                        self.config.connect_timeout
                    )
                })?
                .with_context(|| format!("connect {target} failed"))?;
        let _ = stream.set_nodelay(true);
        Ok(stream)
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

            match tokio::time::timeout(attempt_timeout, self.connect_upstream(target)).await {
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

    async fn connect_upstream(&self, target: SocketAddr) -> std::io::Result<TcpStream> {
        let target = match target {
            SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_some() => {
                SocketAddr::new(target.ip().to_canonical(), target.port())
            }
            _ => target,
        };
        if target.ip().is_unspecified() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "upstream address is unspecified",
            ));
        }
        for addr in self.listener_addrs.iter().flatten() {
            if addr.port() == target.port()
                && (addr.ip().to_canonical() == target.ip()
                    || (addr.ip().is_unspecified()
                        && addr.is_ipv4() == target.is_ipv4()
                        && (target.ip().is_loopback() || can_bind_locally(target))))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "upstream points back to a proxy listener",
                ));
            }
        }
        TcpStream::connect(target).await
    }

    /// Relays a bidirectional TCP tunnel between `client` and `remote`, inspecting the initial
    /// client flight to apply adaptive TLS ClientHello or HTTP Host DPI desynchronization.
    pub async fn relay_tunnel(
        &self,
        client: TcpStream,
        remote: TcpStream,
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let _ = client.set_nodelay(true);
        self.relay_stream(client, remote, known_host, remote_addr)
            .await
    }

    /// Relays any `AsyncRead + AsyncWrite` client stream (such as a proxy `TcpStream` or a
    /// userspace TUN TCP stream) to `remote` with adaptive TLS/HTTP DPI desynchronization.
    pub async fn relay_stream<C>(
        &self,
        mut client: C,
        mut remote: TcpStream,
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
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
                let _guard = ActiveConnGuard::enter(&self.telemetry);
                client.write_all(&remote_buf[..n]).await?;
                self.telemetry.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
                drop(first_buf);
                let (tx, rx) = copy_bidirectional(&mut client, &mut remote).await?;
                self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
                self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
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
        self.establish_and_relay_stream(client, remote, payload, known_host, remote_addr)
            .await
    }

    /// Delivers an already-buffered initial client flight (`payload`) to `remote` with 7-stage
    /// adaptive TLS auto-healing, stale-cache eviction, and strict ServerHello validation,
    /// then enters full-speed bidirectional streaming.
    pub async fn establish_and_relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        self.establish_and_relay_stream(client, remote, payload, known_host, remote_addr)
            .await
    }

    /// Generic stream variant of [`Self::establish_and_relay`] usable with userspace TUN TCP streams.
    pub async fn establish_and_relay_stream<C>(
        &self,
        mut client: C,
        mut remote: TcpStream,
        payload: &[u8],
        known_host: Option<&str>,
        remote_addr: SocketAddr,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        let _guard = ActiveConnGuard::enter(&self.telemetry);
        let remote_ip = remote_addr.ip();

        if let Some(ch_info) = parse_client_hello(payload) {
            self.telemetry
                .tls_handshakes
                .fetch_add(1, Ordering::Relaxed);
            let effective_host = ch_info.sni.as_deref().or(known_host);
            if !self.bypass.should_desync(effective_host, Some(remote_ip)) {
                debug!(host = ?effective_host, %remote_ip, "TLS passthrough (bypassed)");
                remote.write_all(payload).await?;
                self.telemetry
                    .bytes_tx
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                let (tx, rx) = copy_bidirectional(&mut client, &mut remote).await?;
                self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
                self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
                return Ok(());
            }

            let cache_key = effective_host.map(|h| h.to_ascii_lowercase());
            let cached_stage = match cache_key.as_ref() {
                Some(key) => self.adaptive_cache.read().await.get(key).copied(),
                None => None,
            };

            // If additional bytes were coalesced after the first TLS record, send with preferred strategy.
            if payload.len() != ch_info.record_total_len {
                let stage = cached_stage.unwrap_or_else(|| {
                    LearnedStrategy::from_u8(self.preferred_isp_stage.load(Ordering::Relaxed))
                });
                self.write_tls_strategy(&mut remote, payload, &ch_info, stage)
                    .await?;
                self.telemetry
                    .bytes_tx
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
                let (tx, rx) = copy_bidirectional(&mut client, &mut remote).await?;
                self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
                self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
                return Ok(());
            }

            let stages = self.build_stage_order(cached_stage);
            let retry_addrs = self.collect_retry_addrs(effective_host, remote_addr).await;

            let mut probe_buf = vec![0u8; 16384];
            let mut current_remote = Some(remote);
            let mut saw_network_block = false;
            let mut saw_tls_alert = false;

            for (idx, &stage) in stages.iter().enumerate() {
                let mut stream = match current_remote.take() {
                    Some(s) => s,
                    None => {
                        let target = retry_addrs[idx % retry_addrs.len()];
                        match connect_retry_stream(self, target, remote_addr).await {
                            Some(s) => s,
                            None => continue,
                        }
                    }
                };

                if self
                    .write_tls_strategy(&mut stream, payload, &ch_info, stage)
                    .await
                    .is_err()
                {
                    saw_network_block = true;
                    continue;
                }

                let wait_ms = match stage {
                    LearnedStrategy::DeepRecordStorm | LearnedStrategy::SlowSniSlice => 2400,
                    _ if idx == 0 => 1500,
                    _ => 2000,
                };

                let is_last_stage = idx + 1 == stages.len();
                match tokio::time::timeout(
                    Duration::from_millis(wait_ms),
                    stream.read(&mut probe_buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => {
                        let is_valid_tls_server_hello =
                            n >= 2 && probe_buf[0] == 0x16 && probe_buf[1] == 0x03;

                        if !is_valid_tls_server_hello && !is_last_stage {
                            self.telemetry
                                .auto_heal_escalations
                                .fetch_add(1, Ordering::Relaxed);
                            if probe_buf[0] == 0x15 {
                                saw_tls_alert = true;
                                debug!(
                                    host = ?effective_host,
                                    ?stage,
                                    "upstream returned TLS Alert (0x15); auto-healing with next stage"
                                );
                            } else {
                                // Non-TLS response on a TLS handshake (e.g. ISP injected HTTP 302/403 block page)
                                saw_network_block = true;
                                debug!(
                                    host = ?effective_host,
                                    ?stage,
                                    first_byte = probe_buf[0],
                                    "non-TLS response on TLS handshake (possible DPI block injection); escalating"
                                );
                            }
                            continue;
                        }

                        if is_valid_tls_server_hello {
                            if let Some(key) = cache_key {
                                let mut guard = self.adaptive_cache.write().await;
                                if guard.len() > 4096 {
                                    guard.clear();
                                }
                                guard.insert(key, stage);
                            }

                            // If earlier desync stage failed due to ISP RST/block/timeout (not server TLS Alert),
                            // promote this winning desync stage globally so subsequent domains skip failed probes.
                            if idx > 0 && saw_network_block && !saw_tls_alert && stage.is_desync() {
                                self.preferred_isp_stage
                                    .store(stage as u8, Ordering::Relaxed);
                            }
                        }

                        self.telemetry
                            .bytes_tx
                            .fetch_add(payload.len() as u64, Ordering::Relaxed);
                        self.telemetry
                            .bytes_rx
                            .fetch_add(n as u64, Ordering::Relaxed);
                        client.write_all(&probe_buf[..n]).await?;
                        client.flush().await?;
                        drop(probe_buf);
                        let (tx, rx) = copy_bidirectional(&mut client, &mut stream).await?;
                        self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
                        self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
                        return Ok(());
                    }
                    _ => {
                        self.telemetry
                            .auto_heal_escalations
                            .fetch_add(1, Ordering::Relaxed);
                        saw_network_block = true;
                        debug!(
                            host = ?effective_host,
                            ?stage,
                            "TLS stage reset, closed, or timed out; auto-healing with next stage"
                        );
                        continue;
                    }
                }
            }

            // If all stages failed and we had a stale cached strategy, clear it so the next attempt probes fresh.
            if cached_stage.is_some() {
                if let Some(key) = cache_key {
                    self.adaptive_cache.write().await.remove(&key);
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
        self.telemetry
            .bytes_tx
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        let (tx, rx) = copy_bidirectional(&mut client, &mut remote).await?;
        self.telemetry.bytes_tx.fetch_add(tx, Ordering::Relaxed);
        self.telemetry.bytes_rx.fetch_add(rx, Ordering::Relaxed);
        Ok(())
    }

    fn build_stage_order(&self, cached_stage: Option<LearnedStrategy>) -> Vec<LearnedStrategy> {
        let mut order = Vec::with_capacity(ALL_STAGES.len());
        if let Some(cached) = cached_stage {
            order.push(cached);
        }
        let preferred = LearnedStrategy::from_u8(self.preferred_isp_stage.load(Ordering::Relaxed));
        if !order.contains(&preferred) {
            order.push(preferred);
        }
        for stage in ALL_STAGES {
            if !order.contains(&stage) {
                order.push(stage);
            }
        }
        order
    }

    async fn collect_retry_addrs(
        &self,
        host: Option<&str>,
        initial_addr: SocketAddr,
    ) -> Vec<SocketAddr> {
        let mut addrs = vec![initial_addr];
        if let Some(h) = host {
            if !initial_addr.ip().is_loopback() {
                if let Ok(ips) = self.dns.resolve(h).await {
                    // Only rotate among alternate IPs of the same address family that already
                    // proved reachable on attempt 0 so unreachable IPv6 never stalls retries.
                    for ip in ips {
                        if ip.is_ipv4() != initial_addr.is_ipv4() {
                            continue;
                        }
                        let sa = SocketAddr::new(ip, initial_addr.port());
                        if !addrs.contains(&sa) {
                            addrs.push(sa);
                        }
                    }
                }
            }
        }
        addrs
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
                    if let Some(records) = split_tls_records_multi(payload, ch_info, chunk_len) {
                        write_paced_records(remote, &records, Duration::from_millis(2), None)
                            .await?;
                    } else if let Some((rec1, rec2)) =
                        split_tls_records(payload, ch_info, chunk_len)
                    {
                        write_paced_slices(remote, &[&rec1, &rec2], Duration::from_millis(2))
                            .await?;
                    } else {
                        write_in_paced_chunks(remote, payload, chunk_len, Duration::from_millis(1))
                            .await?;
                    }
                }
                DesyncMode::TlsRecord => {
                    if let Some((rec1, rec2)) = split_tls_records(payload, ch_info, chunk_len) {
                        write_paced_slices(remote, &[&rec1, &rec2], Duration::from_millis(2))
                            .await?;
                    } else {
                        write_in_paced_chunks(remote, payload, chunk_len, Duration::from_millis(1))
                            .await?;
                    }
                }
                DesyncMode::Fragment => {
                    write_targeted_sni_slices(
                        remote,
                        payload,
                        ch_info,
                        Duration::from_millis(2),
                        false,
                    )
                    .await?;
                }
                DesyncMode::Split => {
                    let split_at = chunk_len.min(payload.len().saturating_sub(1)).max(1);
                    if payload.len() > 1 {
                        write_paced_slices(
                            remote,
                            &[&payload[..split_at], &payload[split_at..]],
                            Duration::from_millis(2),
                        )
                        .await?;
                    } else {
                        remote.write_all(payload).await?;
                    }
                }
            },
            LearnedStrategy::OobSniDesync => {
                // Inject 1 TCP Out-of-Band (MSG_OOB, URG=1) decoy byte right at the SNI midpoint.
                // Real server kernels strip the urgent byte (SO_OOBINLINE=0), while DPI stream
                // reassemblers ignore URG and see a corrupted hostname (e.g. "discaord.com").
                write_oob_sni_split(remote, payload, ch_info).await?;
            }
            LearnedStrategy::MultiRecordOob => {
                // Combine 4-record TLS splitting with a MSG_OOB decoy byte right at the boundary
                // before Record 4 so stateful DPI boxes lose TLS record framing completely.
                write_multi_record_oob(remote, payload, ch_info, chunk_len).await?;
            }
            LearnedStrategy::FineFragment => {
                // Single intact outer TLS record split across 4 wire-paced TCP segments
                // breaking both the 5-byte TLS record header and the SNI hostname midpoint.
                write_targeted_sni_slices(
                    remote,
                    payload,
                    ch_info,
                    Duration::from_millis(2),
                    false,
                )
                .await?;
            }
            LearnedStrategy::DeepRecordStorm => {
                // 12+ RFC-compliant TLS records: up to 10 tiny 2-byte lead records exhausting
                // DPI per-flow inspection packet caps BEFORE SNI appears, then SNI-split records
                // with a longer midpoint gap to defeat burst-window reassembly.
                if let Some(records) = split_tls_records_deep(payload, ch_info, chunk_len) {
                    let mid_idx = records.len().saturating_sub(2);
                    write_paced_records(
                        remote,
                        &records,
                        Duration::from_millis(4),
                        Some((mid_idx, Duration::from_millis(15))),
                    )
                    .await?;
                } else {
                    write_targeted_sni_slices(
                        remote,
                        payload,
                        ch_info,
                        Duration::from_millis(6),
                        true,
                    )
                    .await?;
                }
            }
            LearnedStrategy::SlowSniSlice => {
                // Single intact outer TLS record: breaks record header on packet 1, then slices
                // the SNI hostname itself into 2-byte paced segments with a 20ms midpoint gap.
                write_targeted_sni_slices(remote, payload, ch_info, Duration::from_millis(6), true)
                    .await?;
            }
            LearnedStrategy::DirectPassthrough => {
                remote.write_all(payload).await?;
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
                return Ok(());
            }
            return self
                .write_tls_strategy(remote, payload, &ch_info, LearnedStrategy::Primary)
                .await;
        }

        if let Some((http_host, hdr_split, val_split)) = extract_http_host_splits(payload) {
            let effective_host = Some(http_host.as_str()).or(known_host);
            if self.bypass.should_desync(effective_host, Some(remote_ip)) && payload.len() > 2 {
                debug!(host = %http_host, %remote_ip, "applying paced plain HTTP Host DPI split");
                if hdr_split < val_split && val_split < payload.len() {
                    write_paced_slices(
                        remote,
                        &[
                            &payload[..hdr_split],
                            &payload[hdr_split..val_split],
                            &payload[val_split..],
                        ],
                        Duration::from_millis(2),
                    )
                    .await?;
                } else {
                    write_paced_slices(
                        remote,
                        &[&payload[..val_split], &payload[val_split..]],
                        Duration::from_millis(2),
                    )
                    .await?;
                }
                return Ok(());
            }
        }

        remote.write_all(payload).await?;
        Ok(())
    }
}

// A wildcard listener has no concrete interface address. On a matching port,
// test whether the target belongs to this host without opening a connection.
fn can_bind_locally(mut addr: SocketAddr) -> bool {
    addr.set_port(0);
    let domain = socket2::Domain::for_address(addr);
    socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .and_then(|socket| socket.bind(&addr.into()))
        .is_ok()
}

async fn connect_retry_stream(
    ctx: &EngineContext,
    target: SocketAddr,
    fallback: SocketAddr,
) -> Option<TcpStream> {
    if let Ok(Ok(s)) =
        tokio::time::timeout(Duration::from_millis(2200), ctx.connect_upstream(target)).await
    {
        let _ = s.set_nodelay(true);
        return Some(s);
    }
    if target != fallback {
        if let Ok(Ok(s)) =
            tokio::time::timeout(Duration::from_millis(2200), ctx.connect_upstream(fallback)).await
        {
            let _ = s.set_nodelay(true);
            return Some(s);
        }
    }
    None
}

async fn write_paced_slices(
    stream: &mut TcpStream,
    slices: &[&[u8]],
    delay: Duration,
) -> Result<()> {
    for (idx, slice) in slices.iter().enumerate() {
        if slice.is_empty() {
            continue;
        }
        stream.write_all(slice).await?;
        if idx + 1 < slices.len() && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

async fn write_paced_records(
    stream: &mut TcpStream,
    records: &[Vec<u8>],
    delay: Duration,
    extra_pause: Option<(usize, Duration)>,
) -> Result<()> {
    for (idx, rec) in records.iter().enumerate() {
        if rec.is_empty() {
            continue;
        }
        stream.write_all(rec).await?;
        if idx + 1 < records.len() {
            let pause = match extra_pause {
                Some((target_idx, extra)) if idx == target_idx => extra,
                _ => delay,
            };
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
        }
    }
    Ok(())
}

async fn write_in_paced_chunks(
    stream: &mut TcpStream,
    data: &[u8],
    chunk_size: usize,
    delay: Duration,
) -> Result<()> {
    let step = chunk_size.max(1);
    let mut chunks = data.chunks(step).peekable();
    while let Some(chunk) = chunks.next() {
        stream.write_all(chunk).await?;
        if chunks.peek().is_some() && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    Ok(())
}

/// Sends a single intact outer TLS record split at strategic wire boundaries:
/// - Packet 1: `[0..2]` (breaks the 5-byte TLS record header)
/// - Packet 2: `[2..sni_start + 1]`
/// - Packet(s) across SNI: either midpoint split (fast) or 2-byte SNI slicing + 20ms midpoint gap (deep)
/// - Final packet: remainder of ClientHello
async fn write_targeted_sni_slices(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
    delay: Duration,
    slow_sni_bytes: bool,
) -> Result<()> {
    if payload.len() <= 6 {
        stream.write_all(payload).await?;
        return Ok(());
    }

    let (sni_start, sni_end) = match (ch_info.sni_payload_offset, ch_info.sni_len) {
        (Some(off), Some(len)) if len >= 2 => {
            let start = (5 + off).min(payload.len() - 1);
            let end = (5 + off + len).min(payload.len());
            (start, end)
        }
        _ => (2usize, payload.len().min(64)),
    };

    if !slow_sni_bytes {
        let cut1 = 2usize.min(sni_start);
        let cut2 = (sni_start + 1).min(sni_end).min(payload.len() - 1);
        let cut3 = (sni_start + ((sni_end - sni_start) / 2).max(1)).min(payload.len() - 1);

        let mut cuts = vec![cut1, cut2, cut3];
        cuts.sort_unstable();
        cuts.dedup();

        let mut slices = Vec::with_capacity(cuts.len() + 1);
        let mut prev = 0usize;
        for cut in cuts {
            if cut > prev && cut < payload.len() {
                slices.push(&payload[prev..cut]);
                prev = cut;
            }
        }
        if prev < payload.len() {
            slices.push(&payload[prev..]);
        }
        return write_paced_slices(stream, &slices, delay).await;
    }

    // Deep slow single-record mode: break header, send pre-SNI, then slice SNI in 2-byte packets
    // with a 20ms pause right at the SNI midpoint.
    stream.write_all(&payload[..2]).await?;
    tokio::time::sleep(delay).await;

    if sni_start > 2 {
        stream.write_all(&payload[2..sni_start]).await?;
        tokio::time::sleep(delay).await;
    }

    let sni_slice = &payload[sni_start..sni_end];
    let mid_chunk = (sni_slice.len() / 2) / 2;
    for (idx, chunk) in sni_slice.chunks(2).enumerate() {
        stream.write_all(chunk).await?;
        let pause = if idx == mid_chunk {
            Duration::from_millis(20)
        } else {
            delay
        };
        tokio::time::sleep(pause).await;
    }

    if sni_end < payload.len() {
        stream.write_all(&payload[sni_end..]).await?;
    }
    Ok(())
}

/// Sends a single intact TLS record while injecting 1 TCP Out-of-Band (`MSG_OOB`, `URG=1`)
/// decoy byte right at the SNI hostname midpoint.
/// Destination TCP stacks strip the urgent byte (`SO_OOBINLINE=0`), while stateful DPI
/// stream reassemblers merge the decoy byte into the SNI and fail signature matching.
async fn write_oob_sni_split(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
) -> Result<()> {
    if payload.len() <= 6 {
        stream.write_all(payload).await?;
        return Ok(());
    }

    let split_at = match (ch_info.sni_payload_offset, ch_info.sni_len) {
        (Some(off), Some(len)) if len >= 2 => (5 + off + (len / 2)).clamp(1, payload.len() - 1),
        (Some(off), Some(_)) => (5 + off).clamp(1, payload.len() - 1),
        _ => (payload.len() / 2).clamp(1, payload.len() - 1),
    };

    // Keep the MSG_OOB write under 1024 bytes so the kernel transmits it atomically in a single
    // TCP segment with URG pointing directly at the trailing decoy byte (even for large
    // Post-Quantum ClientHellos where SNI appears past offset 1200).
    let oob_start = split_at.saturating_sub(1000);
    if oob_start > 0 {
        stream.write_all(&payload[..oob_start]).await?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let mut oob_chunk = Vec::with_capacity((split_at - oob_start) + 1);
    oob_chunk.extend_from_slice(&payload[oob_start..split_at]);
    oob_chunk.push(b'a');
    send_with_oob(stream, &oob_chunk).await?;

    tokio::time::sleep(Duration::from_millis(3)).await;
    stream.write_all(&payload[split_at..]).await?;
    Ok(())
}

/// Splits the ClientHello into 4 RFC-compliant TLS records and injects a 1-byte `MSG_OOB`
/// decoy right at the end of the pre-midpoint SNI record (shifting the following TLS record
/// header by 1 byte for any DPI engine that ignores TCP `URG`).
async fn write_multi_record_oob(
    stream: &mut TcpStream,
    payload: &[u8],
    ch_info: &ClientHelloInfo,
    fallback_split: usize,
) -> Result<()> {
    let Some(records) = split_tls_records_multi(payload, ch_info, fallback_split) else {
        return write_oob_sni_split(stream, payload, ch_info).await;
    };

    let oob_rec_idx = records.len().saturating_sub(2);
    for (idx, rec) in records.iter().enumerate() {
        if idx == oob_rec_idx && rec.len() <= 1024 {
            let mut with_oob = Vec::with_capacity(rec.len() + 1);
            with_oob.extend_from_slice(rec);
            with_oob.push(b'a');
            send_with_oob(stream, &with_oob).await?;
            tokio::time::sleep(Duration::from_millis(4)).await;
        } else {
            stream.write_all(rec).await?;
            if idx + 1 < records.len() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    }
    Ok(())
}

async fn send_with_oob(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    use tokio::io::Interest;

    let mut sent = 0usize;
    while sent < data.len() {
        stream.writable().await?;
        let slice = &data[sent..];
        let res = stream.try_io(Interest::WRITABLE, || raw_send_oob(stream, slice));
        match res {
            Ok(0) => bail!("peer closed connection during MSG_OOB send"),
            Ok(n) => sent += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn raw_send_oob(stream: &TcpStream, data: &[u8]) -> std::io::Result<usize> {
    use std::ffi::c_void;
    use std::os::unix::io::AsRawFd;

    const MSG_OOB: i32 = 0x1;
    extern "C" {
        fn send(sockfd: i32, buf: *const c_void, len: usize, flags: i32) -> isize;
    }

    let n = unsafe {
        send(
            stream.as_raw_fd(),
            data.as_ptr().cast::<c_void>(),
            data.len(),
            MSG_OOB,
        )
    };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

#[cfg(windows)]
fn raw_send_oob(stream: &TcpStream, data: &[u8]) -> std::io::Result<usize> {
    use std::os::windows::io::AsRawSocket;

    const MSG_OOB: i32 = 0x1;
    const WSAEWOULDBLOCK: i32 = 10035;

    #[link(name = "ws2_32")]
    extern "system" {
        fn send(s: usize, buf: *const u8, len: i32, flags: i32) -> i32;
        fn WSAGetLastError() -> i32;
    }

    let len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    let n = unsafe { send(stream.as_raw_socket() as usize, data.as_ptr(), len, MSG_OOB) };
    if n < 0 {
        let code = unsafe { WSAGetLastError() };
        if code == WSAEWOULDBLOCK {
            Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
        } else {
            Err(std::io::Error::from_raw_os_error(code))
        }
    } else {
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliArgs;
    use crate::tls::build_synthetic_client_hello;
    use std::sync::atomic::AtomicUsize;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn combo_desync_rewrites_client_hello_into_valid_multi_tls_records() {
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
        let mut pos = 0usize;
        let mut record_count = 0usize;
        let mut reassembled = Vec::new();
        while pos < received.len() {
            assert_eq!(received[pos], 0x16);
            let rlen = u16::from_be_bytes([received[pos + 3], received[pos + 4]]) as usize;
            let body = &received[pos + 5..pos + 5 + rlen];
            assert!(!body.windows(11).any(|w| w == b"discord.com"));
            reassembled.extend_from_slice(body);
            pos += 5 + rlen;
            record_count += 1;
        }
        assert_eq!(record_count, 4);
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
                        let _ = sock
                            .write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2f])
                            .await;
                    } else {
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O',
                            ])
                            .await;
                    }

                    // Close the write half and drain pipelined input so that closing the
                    // mock socket does not reset the connection before the alert is read.
                    let _ = sock.shutdown().await;
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        tokio::io::copy(&mut sock, &mut tokio::io::sink()),
                    )
                    .await;
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
            Some(LearnedStrategy::OobSniDesync)
        );
    }

    #[tokio::test]
    async fn escalates_to_deep_record_storm_and_promotes_isp_stage_on_dpi_block_injection() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--chunk-size",
            "10",
            "--include",
            "blocked\\.example$",
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let ch = build_synthetic_client_hello("chat.blocked.example", 256);
        let expected_payload_len = ch.len() - 5;

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();

        // Simulate a strict stateful ISP DPI box that:
        // - Injects a fake HTTP 302 block page if <= 4 TLS records arrive (Stage 1)
        // - Resets/closes connection if single-record (Stage 2)
        // - Allows connection through when >= 10 tiny lead TLS records arrive (Stage 3 DeepRecordStorm)
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut count = 0usize;
                    let mut total_payload = 0usize;
                    loop {
                        let mut hdr = [0u8; 5];
                        match tokio::time::timeout(
                            Duration::from_millis(80),
                            sock.read_exact(&mut hdr),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {
                                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                                let mut body = vec![0u8; rlen];
                                if sock.read_exact(&mut body).await.is_err() {
                                    break;
                                }
                                count += 1;
                                total_payload += rlen;
                                if total_payload >= expected_payload_len {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }

                    if count == 4 {
                        // Fake ISP HTTP block-page injection on a TLS port
                        let _ = sock
                            .write_all(
                                b"HTTP/1.1 302 Found\r\nLocation: http://blocked.isp/\r\n\r\n",
                            )
                            .await;
                    } else if count == 1 {
                        // TCP RST / immediate EOF
                        drop(sock);
                    } else if count >= 10 {
                        // Valid TLS ServerHello passes through!
                        let _ = sock
                            .write_all(&[
                                0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'K', b'T', b'L', b'S',
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
            Some("chat.blocked.example"),
            upstream_addr,
        )
        .await
        .unwrap();

        let reply = client_task.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'O', b'K', b'T', b'L', b'S']
        );
        assert_eq!(
            ctx.adaptive_cache
                .read()
                .await
                .get("chat.blocked.example")
                .copied(),
            Some(LearnedStrategy::DeepRecordStorm)
        );
        assert_eq!(
            LearnedStrategy::from_u8(ctx.preferred_isp_stage.load(Ordering::Relaxed)),
            LearnedStrategy::DeepRecordStorm
        );
    }

    #[tokio::test]
    async fn relay_stream_supports_generic_streams_and_records_telemetry() {
        let cli = CliArgs::parse_from_iter([
            "vdpi",
            "--no-system-proxy",
            "--include",
            "stream\\.example$",
        ])
        .unwrap();
        let ctx = EngineContext::new(cli.into_runtime_config()).unwrap();

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let ch = build_synthetic_client_hello("api.stream.example", 256);

        let expected_payload_len = ch.len() - 5;
        let server = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut total_payload = 0usize;
            while total_payload < expected_payload_len {
                let mut hdr = [0u8; 5];
                sock.read_exact(&mut hdr).await.unwrap();
                let rlen = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; rlen];
                sock.read_exact(&mut body).await.unwrap();
                total_payload += rlen;
            }
            sock.write_all(&[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O'])
                .await
                .unwrap();
            let _ = sock.shutdown().await;
        });

        let (mut app_side, tun_side) = tokio::io::duplex(8192);
        let ch_send = ch.clone();
        let app_task = tokio::spawn(async move {
            app_side.write_all(&ch_send).await.unwrap();
            let mut reply = [0u8; 10];
            app_side.read_exact(&mut reply).await.unwrap();
            reply
        });

        let remote = ctx.connect_upstream_addr(upstream_addr).await.unwrap();
        ctx.relay_stream(tun_side, remote, Some("api.stream.example"), upstream_addr)
            .await
            .unwrap();

        let reply = app_task.await.unwrap();
        server.await.unwrap();
        assert_eq!(
            &reply,
            &[0x16, 0x03, 0x03, 0x00, 0x05, b'H', b'E', b'L', b'L', b'O']
        );

        let snap = ctx.telemetry_snapshot();
        assert_eq!(snap.active_connections, 0);
        assert_eq!(snap.total_connections, 1);
        assert_eq!(snap.tls_handshakes, 1);
        assert!(snap.bytes_tx >= ch.len() as u64);
        assert!(snap.bytes_rx >= 10);
    }
}
