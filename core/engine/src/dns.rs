use crate::binder::OutboundBinder;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket, UdpSocket};
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::debug;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SVCB: u16 = 64;
const QTYPE_HTTPS: u16 = 65;
const QCLASS_IN: u16 = 1;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_CACHED_IPS: usize = 32;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;
const MAX_BOUND_DOH_HEADER_BYTES: usize = 16 * 1024;
const MAX_BOUND_DOH_RAW_BYTES: usize = MAX_DNS_MESSAGE_BYTES + MAX_BOUND_DOH_HEADER_BYTES;
const FIREFOX_CANARY_DOMAIN: &str = "use-application-dns.net";

static PROCESS_EPOCH: OnceLock<Instant> = OnceLock::new();
static BOUND_DOH_ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
static UDP_TX_COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

fn monotonic_ms() -> u64 {
    let epoch = PROCESS_EPOCH.get_or_init(Instant::now);
    let ms = Instant::now().saturating_duration_since(*epoch).as_millis();
    // Reserve 0 for "no backoff active" so deadlines are always >= 1.
    u64::try_from(ms).unwrap_or(u64::MAX).saturating_add(1)
}

fn next_udp_tx_id() -> u16 {
    let epoch = PROCESS_EPOCH.get_or_init(Instant::now);
    let nanos = Instant::now().saturating_duration_since(*epoch).as_nanos() as u64;
    let seq = UDP_TX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut x = seq.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ nanos.rotate_left(17);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    let id = (x as u16) ^ ((x >> 16) as u16);
    if id == 0 {
        1
    } else {
        id
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    nxdomain: bool,
    has_a_lookup: bool,
    has_aaaa_lookup: bool,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
enum DnsOutcome {
    Records(Vec<IpAddr>, Duration),
    NxDomain(Duration),
}

#[derive(Debug, Clone)]
struct ResolvedOutcome {
    outcome: DnsOutcome,
    has_a_lookup: bool,
    has_aaaa_lookup: bool,
}

#[derive(Debug)]
enum DnsDecodeError {
    ProtocolError(u16),
    Malformed(anyhow::Error),
}

#[derive(Debug)]
enum DohError {
    Transport(anyhow::Error),
    ProtocolError { endpoint: String, rcode: u16 },
}

#[derive(Clone)]
pub struct DnsResolver {
    enable_doh: bool,
    ipv4_only: bool,
    udp_dns_servers: Vec<SocketAddr>,
    doh_endpoints: Vec<String>,
    preferred_doh_idx: Arc<AtomicUsize>,
    preferred_udp_idx: Arc<AtomicUsize>,
    doh_backoff_until_ms: Arc<AtomicU64>,
    query_count: Arc<AtomicU64>,
    http: Client,
    outbound_binder: Option<Arc<dyn OutboundBinder>>,
    bound_tls_connector: Option<TlsConnector>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl DnsResolver {
    pub fn new(dns_addr: &str, dns_port: u16, enable_doh: bool, ipv4_only: bool) -> Result<Self> {
        Self::new_with_binder(dns_addr, dns_port, enable_doh, ipv4_only, None)
    }

    pub fn new_with_binder(
        dns_addr: impl AsRef<str>,
        dns_port: u16,
        enable_doh: bool,
        ipv4_only: bool,
        outbound_binder: Option<Arc<dyn OutboundBinder>>,
    ) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // `.no_proxy()` prevents vdpi from routing its own DoH traffic through itself
        // when HTTP_PROXY / HTTPS_PROXY environment variables are active.
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(2000))
            .connect_timeout(Duration::from_millis(1200))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(2)
            .tcp_nodelay(true)
            .build()
            .context("failed to build DoH HTTP client")?;

        let bound_tls_connector = if outbound_binder.is_some() {
            Some(build_bound_tls_connector()?)
        } else {
            None
        };

        let dns_addr = dns_addr.as_ref();
        let udp_dns_servers = build_udp_dns_servers(dns_addr, dns_port);
        let doh_endpoints = build_doh_endpoints(dns_addr);

        Ok(Self {
            enable_doh,
            ipv4_only,
            udp_dns_servers,
            doh_endpoints,
            preferred_doh_idx: Arc::new(AtomicUsize::new(0)),
            preferred_udp_idx: Arc::new(AtomicUsize::new(0)),
            doh_backoff_until_ms: Arc::new(AtomicU64::new(0)),
            query_count: Arc::new(AtomicU64::new(0)),
            http,
            outbound_binder,
            bound_tls_connector,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn query_count(&self) -> u64 {
        self.query_count.load(Ordering::Relaxed)
    }

    fn is_doh_in_backoff(&self) -> bool {
        let until_ms = self.doh_backoff_until_ms.load(Ordering::Relaxed);
        until_ms != 0 && monotonic_ms() < until_ms
    }

    fn set_doh_backoff(&self, duration: Duration) {
        let dur_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        let until_ms = monotonic_ms().saturating_add(dur_ms);
        self.doh_backoff_until_ms.store(until_ms, Ordering::Relaxed);
    }

    fn clear_doh_backoff(&self) {
        self.doh_backoff_until_ms.store(0, Ordering::Relaxed);
    }

    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
        self.clear_doh_backoff();
    }

    /// Resolves `host` into an ordered list of IP addresses (IPv4 preferred before IPv6).
    /// Resistant to ISP port-53 DNS hijacking by cascading through RFC 8484 DoH providers
    /// and non-standard port 1253 UDP DNS before falling back to OS resolution.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.resolve_with_metric(host, true).await
    }

    /// Internal resolution helper that does not increment user-facing `query_count` telemetry
    /// (used for lazy TLS retry address rotation).
    pub async fn resolve_internal(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.resolve_with_metric(host, false).await
    }

    async fn resolve_with_metric(&self, host: &str, count_metric: bool) -> Result<Vec<IpAddr>> {
        match self.resolve_outcome(host, count_metric).await? {
            DnsOutcome::Records(ips, _) if !ips.is_empty() => Ok(ips),
            DnsOutcome::NxDomain(_) => bail!("NXDOMAIN for {host}"),
            DnsOutcome::Records(_, _) => bail!("no IP addresses resolved for {host}"),
        }
    }

    async fn resolve_outcome(&self, host: &str, count_metric: bool) -> Result<DnsOutcome> {
        if count_metric {
            self.query_count.fetch_add(1, Ordering::Relaxed);
        }
        let normalized = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if normalized.is_empty() || normalized.len() > MAX_DNS_NAME_BYTES {
            bail!("invalid hostname length");
        }

        // 1. Direct IP literal
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            return Ok(DnsOutcome::Records(vec![ip], Duration::from_secs(300)));
        }

        // 2. Localhost fast-path
        if normalized == "localhost" {
            let ips = if self.ipv4_only {
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            } else {
                vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ]
            };
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(300)));
        }

        // 3. mDNS (.local) via OS resolver (unfiltered because LAN IPs are expected).
        //    Disabled when outbound_binder is active (TUN mode) to prevent system DNS recursion.
        if normalized.ends_with(".local") {
            if self.outbound_binder.is_some() {
                return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
            }
            let ips = self.resolve_via_system(&normalized, false).await?;
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(60)));
        }

        // 4. In-memory TTL cache lookup (including negative NXDOMAIN cache)
        {
            let guard = self.cache.read().await;
            if let Some(entry) = guard.get(&normalized) {
                let now = Instant::now();
                if now < entry.expires_at {
                    let rem = entry.expires_at.saturating_duration_since(now);
                    if entry.nxdomain {
                        return Ok(DnsOutcome::NxDomain(rem));
                    }
                    if entry.has_a_lookup
                        && (self.ipv4_only || entry.has_aaaa_lookup)
                        && !entry.ips.is_empty()
                    {
                        return Ok(DnsOutcome::Records(entry.ips.clone(), rem));
                    }
                }
            }
        }

        // 5. Multi-tier unpoisoned resolution:
        //    Tier A: RFC 8484 DNS-over-HTTPS (only transport failures trip the 30s circuit-breaker;
        //            protocol NXDOMAIN/NODATA/SERVFAIL replies never trip DoH backoff!)
        //    Tier B: Non-standard port 1253 / 443 / 5353 + backup UDP DNS
        //    Tier C: System resolver fallback (with sinkhole IP filtering; skipped in TUN mode)
        let resolved = if self.enable_doh && !self.is_doh_in_backoff() {
            match self.resolve_via_doh(&normalized).await {
                Ok(resolved) => resolved,
                Err(err) => {
                    match &err {
                        DohError::Transport(cause) => {
                            debug!(
                                domain = %normalized,
                                error = %cause,
                                "DoH transport failed; tripping 30s backoff"
                            );
                            self.set_doh_backoff(Duration::from_secs(30));
                        }
                        DohError::ProtocolError { endpoint, rcode } => {
                            debug!(
                                domain = %normalized,
                                endpoint = %endpoint,
                                rcode = rcode,
                                "DoH returned DNS protocol error; falling back without tripping backoff"
                            );
                        }
                    }
                    self.resolve_udp_or_system(&normalized).await?
                }
            }
        } else {
            self.resolve_udp_or_system(&normalized).await?
        };

        match &resolved.outcome {
            DnsOutcome::NxDomain(ttl) => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: Vec::new(),
                        nxdomain: true,
                        has_a_lookup: true,
                        has_aaaa_lookup: true,
                        expires_at: Instant::now() + (*ttl).min(Duration::from_secs(60)),
                    },
                );
            }
            DnsOutcome::Records(ips, ttl) if !ips.is_empty() && ips.len() <= MAX_CACHED_IPS => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: ips.clone(),
                        nxdomain: false,
                        has_a_lookup: resolved.has_a_lookup,
                        has_aaaa_lookup: resolved.has_aaaa_lookup,
                        expires_at: Instant::now() + *ttl,
                    },
                );
            }
            _ => {}
        }

        Ok(resolved.outcome)
    }

    async fn resolve_single_qtype(
        &self,
        host: &str,
        qtype: u16,
        count_metric: bool,
        disable_system_fallback: bool,
    ) -> Result<DnsOutcome> {
        if count_metric {
            self.query_count.fetch_add(1, Ordering::Relaxed);
        }
        let no_system_fallback = disable_system_fallback || self.outbound_binder.is_some();
        let normalized = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if normalized.is_empty() || normalized.len() > MAX_DNS_NAME_BYTES {
            bail!("invalid hostname length");
        }

        // 1. Direct IP literal
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            let matches_family = match qtype {
                QTYPE_A => ip.is_ipv4(),
                QTYPE_AAAA => ip.is_ipv6(),
                _ => false,
            };
            let ips = if matches_family { vec![ip] } else { Vec::new() };
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(300)));
        }

        // 2. Localhost fast-path
        if normalized == "localhost" {
            let ips = match qtype {
                QTYPE_A => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                QTYPE_AAAA if !self.ipv4_only => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                _ => Vec::new(),
            };
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(300)));
        }

        // 3. mDNS (.local) via OS resolver (disabled in TUN mode to prevent system DNS recursion)
        if normalized.ends_with(".local") {
            if no_system_fallback {
                return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
            }
            let ips: Vec<IpAddr> = self
                .resolve_via_system(&normalized, false)
                .await?
                .into_iter()
                .filter(|ip| match qtype {
                    QTYPE_A => ip.is_ipv4(),
                    QTYPE_AAAA => ip.is_ipv6(),
                    _ => false,
                })
                .collect();
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(60)));
        }

        // 4. In-memory TTL cache lookup respecting per-family coverage
        {
            let guard = self.cache.read().await;
            if let Some(entry) = guard.get(&normalized) {
                let now = Instant::now();
                if now < entry.expires_at {
                    let rem = entry.expires_at.saturating_duration_since(now);
                    if entry.nxdomain {
                        return Ok(DnsOutcome::NxDomain(rem));
                    }
                    let family_cached = match qtype {
                        QTYPE_A => entry.has_a_lookup,
                        QTYPE_AAAA => entry.has_aaaa_lookup,
                        _ => false,
                    };
                    if family_cached {
                        let matching: Vec<IpAddr> = entry
                            .ips
                            .iter()
                            .copied()
                            .filter(|ip| match qtype {
                                QTYPE_A => ip.is_ipv4(),
                                QTYPE_AAAA => ip.is_ipv6(),
                                _ => false,
                            })
                            .collect();
                        if !matching.is_empty() || qtype == QTYPE_AAAA {
                            return Ok(DnsOutcome::Records(matching, rem));
                        }
                    }
                }
            }
        }

        // 5. Query ONLY the requested qtype so `QTYPE_A` never stalls waiting on `QTYPE_AAAA`.
        let outcome = if self.enable_doh && !self.is_doh_in_backoff() {
            match self.query_doh_type(&normalized, qtype).await {
                Ok(outcome) => outcome,
                Err(err) => {
                    match &err {
                        DohError::Transport(cause) => {
                            debug!(
                                domain = %normalized,
                                qtype = qtype,
                                error = %cause,
                                "DoH transport failed; tripping 30s backoff"
                            );
                            self.set_doh_backoff(Duration::from_secs(30));
                        }
                        DohError::ProtocolError { endpoint, rcode } => {
                            debug!(
                                domain = %normalized,
                                qtype = qtype,
                                endpoint = %endpoint,
                                rcode = rcode,
                                "DoH returned DNS protocol error; falling back without tripping backoff"
                            );
                        }
                    }
                    self.resolve_udp_or_system_type(&normalized, qtype, no_system_fallback)
                        .await?
                }
            }
        } else {
            self.resolve_udp_or_system_type(&normalized, qtype, no_system_fallback)
                .await?
        };

        // 6. Merge result into shared TTL cache while preserving IPv4-first ordering
        match &outcome {
            DnsOutcome::NxDomain(ttl) => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: Vec::new(),
                        nxdomain: true,
                        has_a_lookup: true,
                        has_aaaa_lookup: true,
                        expires_at: Instant::now() + (*ttl).min(Duration::from_secs(60)),
                    },
                );
            }
            DnsOutcome::Records(ips, ttl)
                if ips.len() <= MAX_CACHED_IPS && (!ips.is_empty() || qtype == QTYPE_AAAA) =>
            {
                let now = Instant::now();
                let effective_ttl = if ips.is_empty() {
                    (*ttl).min(Duration::from_secs(60))
                } else {
                    *ttl
                };
                let mut guard = self.cache.write().await;
                let merged = if let Some(existing) = guard.get(&normalized) {
                    if now < existing.expires_at && !existing.nxdomain {
                        let mut combined = merge_ips_v4_first(&existing.ips, ips);
                        combined.truncate(MAX_CACHED_IPS);
                        Some(CacheEntry {
                            ips: combined,
                            nxdomain: false,
                            has_a_lookup: existing.has_a_lookup || qtype == QTYPE_A,
                            has_aaaa_lookup: existing.has_aaaa_lookup
                                || qtype == QTYPE_AAAA
                                || self.ipv4_only,
                            expires_at: existing.expires_at.min(now + effective_ttl),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };
                let entry = merged.unwrap_or_else(|| CacheEntry {
                    ips: ips.clone(),
                    nxdomain: false,
                    has_a_lookup: qtype == QTYPE_A,
                    has_aaaa_lookup: qtype == QTYPE_AAAA || self.ipv4_only,
                    expires_at: now + effective_ttl,
                });
                insert_cache_entry(&mut guard, normalized, entry);
            }
            _ => {}
        }

        Ok(outcome)
    }

    async fn resolve_udp_or_system(&self, domain: &str) -> Result<ResolvedOutcome> {
        match self.resolve_via_udp(domain).await {
            Ok(resolved) => match &resolved.outcome {
                DnsOutcome::NxDomain(_) => Ok(resolved),
                DnsOutcome::Records(ips, _) if !ips.is_empty() => Ok(resolved),
                DnsOutcome::Records(_, _) if self.outbound_binder.is_some() => {
                    bail!("UDP DNS returned no records for {domain} (system DNS disabled in TUN mode)")
                }
                DnsOutcome::Records(_, _) => {
                    let sys = self.resolve_via_system(domain, true).await?;
                    Ok(ResolvedOutcome {
                        outcome: DnsOutcome::Records(sys, Duration::from_secs(60)),
                        has_a_lookup: true,
                        has_aaaa_lookup: !self.ipv4_only,
                    })
                }
            },
            Err(e) if self.outbound_binder.is_some() => Err(e),
            Err(_) => {
                let sys = self.resolve_via_system(domain, true).await?;
                Ok(ResolvedOutcome {
                    outcome: DnsOutcome::Records(sys, Duration::from_secs(60)),
                    has_a_lookup: true,
                    has_aaaa_lookup: !self.ipv4_only,
                })
            }
        }
    }

    async fn resolve_udp_or_system_type(
        &self,
        domain: &str,
        qtype: u16,
        disable_system_fallback: bool,
    ) -> Result<DnsOutcome> {
        let no_system = disable_system_fallback || self.outbound_binder.is_some();
        match self.query_udp_type(domain, qtype).await {
            Ok(DnsOutcome::NxDomain(ttl)) => Ok(DnsOutcome::NxDomain(ttl)),
            Ok(DnsOutcome::Records(ips, ttl))
                if !ips.is_empty() || qtype == QTYPE_AAAA || no_system =>
            {
                Ok(DnsOutcome::Records(ips, ttl))
            }
            Err(e) if no_system => Err(e),
            _ => {
                let sys: Vec<IpAddr> = self
                    .resolve_via_system(domain, true)
                    .await?
                    .into_iter()
                    .filter(|ip| match qtype {
                        QTYPE_A => ip.is_ipv4(),
                        QTYPE_AAAA => ip.is_ipv6(),
                        _ => false,
                    })
                    .collect();
                Ok(DnsOutcome::Records(sys, Duration::from_secs(60)))
            }
        }
    }

    async fn resolve_via_doh(
        &self,
        domain: &str,
    ) -> std::result::Result<ResolvedOutcome, DohError> {
        if self.ipv4_only {
            let outcome = self.query_doh_type(domain, QTYPE_A).await?;
            let is_nx = matches!(outcome, DnsOutcome::NxDomain(_));
            return Ok(ResolvedOutcome {
                outcome,
                has_a_lookup: true,
                has_aaaa_lookup: is_nx,
            });
        }

        let (v4_res, v6_res) = tokio::join!(
            self.query_doh_type(domain, QTYPE_A),
            tokio::time::timeout(
                Duration::from_millis(700),
                self.query_doh_type(domain, QTYPE_AAAA)
            )
        );

        let mut ips = Vec::new();
        let mut min_ttl = Duration::from_secs(300);
        let mut has_a_lookup = false;
        let mut has_aaaa_lookup = false;
        let mut v4_nxdomain = false;
        let mut protocol_err: Option<DohError> = None;

        match v4_res {
            Ok(DnsOutcome::NxDomain(ttl)) => {
                has_a_lookup = true;
                v4_nxdomain = true;
                min_ttl = min_ttl.min(ttl);
            }
            Ok(DnsOutcome::Records(v4, ttl)) => {
                has_a_lookup = true;
                if !v4.is_empty() {
                    min_ttl = min_ttl.min(ttl);
                    ips.extend(v4);
                }
            }
            Err(err @ DohError::ProtocolError { .. }) => {
                protocol_err = Some(err);
            }
            Err(DohError::Transport(_)) => {}
        }

        // CNAME-only empty AAAA responses (such as www.roblox.com) are normal and must never
        // discard valid IPv4 A records — and an empty AAAA response must never mask an A failure.
        match v6_res {
            Ok(Ok(DnsOutcome::NxDomain(ttl))) => {
                has_aaaa_lookup = true;
                min_ttl = min_ttl.min(ttl);
            }
            Ok(Ok(DnsOutcome::Records(v6, ttl))) => {
                has_aaaa_lookup = true;
                if !v6.is_empty() {
                    min_ttl = min_ttl.min(ttl);
                    for ip in v6 {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
            Ok(Err(err @ DohError::ProtocolError { .. })) if protocol_err.is_none() => {
                protocol_err = Some(err);
            }
            _ => {}
        }

        if !ips.is_empty() {
            return Ok(ResolvedOutcome {
                outcome: DnsOutcome::Records(ips, min_ttl),
                has_a_lookup,
                has_aaaa_lookup,
            });
        }
        if v4_nxdomain {
            return Ok(ResolvedOutcome {
                outcome: DnsOutcome::NxDomain(min_ttl.min(Duration::from_secs(30))),
                has_a_lookup: true,
                has_aaaa_lookup: true,
            });
        }
        if has_a_lookup {
            return Ok(ResolvedOutcome {
                outcome: DnsOutcome::Records(Vec::new(), min_ttl.min(Duration::from_secs(60))),
                has_a_lookup,
                has_aaaa_lookup,
            });
        }
        if let Some(err) = protocol_err {
            return Err(err);
        }
        Err(DohError::Transport(anyhow!(
            "DoH transport failed for {domain}"
        )))
    }

    async fn query_doh_type(
        &self,
        domain: &str,
        qtype: u16,
    ) -> std::result::Result<DnsOutcome, DohError> {
        let wire_query = encode_dns_query(domain, qtype).map_err(DohError::Transport)?;
        let count = self.doh_endpoints.len();
        if count == 0 {
            return Err(DohError::Transport(anyhow!("no DoH endpoints configured")));
        }

        let mut protocol_err: Option<DohError> = None;
        let mut last_transport_err: Option<anyhow::Error> = None;

        // Fast-path: try the currently sticky healthy DoH endpoint first.
        let start = self.preferred_doh_idx.load(Ordering::Relaxed) % count;
        match send_doh_request(
            &self.http,
            self.outbound_binder.as_deref(),
            self.bound_tls_connector.as_ref(),
            &self.doh_endpoints[start],
            &wire_query,
            qtype,
        )
        .await
        {
            Ok(parsed) => {
                debug!(
                    domain = %domain,
                    qtype = qtype,
                    endpoint = %self.doh_endpoints[start],
                    "DoH query succeeded"
                );
                return Ok(parsed);
            }
            Err(err @ DohError::ProtocolError { .. }) => {
                protocol_err = Some(err);
            }
            Err(DohError::Transport(err)) => {
                last_transport_err = Some(err);
            }
        }

        // Preferred DoH endpoint failed: race ALL remaining DoH endpoints concurrently.
        let mut join_set = tokio::task::JoinSet::new();
        for offset in 1..count {
            let idx = (start + offset) % count;
            let http = self.http.clone();
            let outbound_binder = self.outbound_binder.clone();
            let bound_tls = self.bound_tls_connector.clone();
            let endpoint = self.doh_endpoints[idx].clone();
            let query = wire_query.clone();
            join_set.spawn(async move {
                let res = send_doh_request(
                    &http,
                    outbound_binder.as_deref(),
                    bound_tls.as_ref(),
                    &endpoint,
                    &query,
                    qtype,
                )
                .await;
                (idx, endpoint, res)
            });
        }

        while let Some(joined) = join_set.join_next().await {
            if let Ok((idx, endpoint, res)) = joined {
                match res {
                    Ok(parsed) => {
                        self.preferred_doh_idx.store(idx, Ordering::Relaxed);
                        join_set.abort_all();
                        debug!(
                            domain = %domain,
                            qtype = qtype,
                            endpoint = %endpoint,
                            "DoH failover succeeded and promoted endpoint"
                        );
                        return Ok(parsed);
                    }
                    Err(err @ DohError::ProtocolError { .. }) => {
                        if protocol_err.is_none() {
                            protocol_err = Some(err);
                        }
                    }
                    Err(DohError::Transport(e)) => last_transport_err = Some(e),
                }
            }
        }

        if let Some(err) = protocol_err {
            return Err(err);
        }

        Err(DohError::Transport(
            last_transport_err.unwrap_or_else(|| anyhow!("no DoH endpoints reachable")),
        ))
    }

    async fn resolve_via_udp(&self, domain: &str) -> Result<ResolvedOutcome> {
        if self.ipv4_only {
            let outcome = self.query_udp_type(domain, QTYPE_A).await?;
            let is_nx = matches!(outcome, DnsOutcome::NxDomain(_));
            return Ok(ResolvedOutcome {
                outcome,
                has_a_lookup: true,
                has_aaaa_lookup: is_nx,
            });
        }
        let (v4_res, v6_res) = tokio::join!(
            self.query_udp_type(domain, QTYPE_A),
            tokio::time::timeout(
                Duration::from_millis(800),
                self.query_udp_type(domain, QTYPE_AAAA)
            )
        );
        let mut ips = Vec::new();
        let mut min_ttl = Duration::from_secs(300);
        let mut has_a_lookup = false;
        let mut has_aaaa_lookup = false;
        let mut nxdomain = false;

        if let Ok(outcome) = v4_res {
            has_a_lookup = true;
            match outcome {
                DnsOutcome::NxDomain(ttl) => {
                    nxdomain = true;
                    min_ttl = min_ttl.min(ttl);
                }
                DnsOutcome::Records(v4, ttl) => {
                    if !v4.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        ips.extend(v4);
                    }
                }
            }
        }
        if let Ok(Ok(outcome)) = v6_res {
            has_aaaa_lookup = true;
            match outcome {
                DnsOutcome::NxDomain(ttl) => {
                    min_ttl = min_ttl.min(ttl);
                }
                DnsOutcome::Records(v6, ttl) => {
                    if !v6.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        for ip in v6 {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
            }
        }
        if !ips.is_empty() {
            Ok(ResolvedOutcome {
                outcome: DnsOutcome::Records(ips, min_ttl),
                has_a_lookup,
                has_aaaa_lookup,
            })
        } else if nxdomain {
            Ok(ResolvedOutcome {
                outcome: DnsOutcome::NxDomain(min_ttl.min(Duration::from_secs(30))),
                has_a_lookup: true,
                has_aaaa_lookup: true,
            })
        } else {
            bail!("UDP DNS resolution failed for {domain}")
        }
    }

    async fn query_udp_type(&self, domain: &str, qtype: u16) -> Result<DnsOutcome> {
        let wire_query = encode_dns_query(domain, qtype)?;
        let count = self.udp_dns_servers.len();
        if count == 0 {
            bail!("no UDP DNS servers configured");
        }

        let start = self.preferred_udp_idx.load(Ordering::Relaxed) % count;
        let mut last_err = None;

        for offset in 0..count {
            let idx = (start + offset) % count;
            let server = self.udp_dns_servers[idx];
            match send_udp_dns_raw(server, &wire_query, self.outbound_binder.as_deref()).await {
                Ok(buf) => match decode_dns_outcome(&buf, qtype) {
                    Ok(DnsOutcome::NxDomain(ttl)) => {
                        if offset > 0 {
                            self.preferred_udp_idx.store(idx, Ordering::Relaxed);
                        }
                        return Ok(DnsOutcome::NxDomain(ttl));
                    }
                    Ok(DnsOutcome::Records(ips, ttl)) => {
                        let had_ips = !ips.is_empty();
                        let clean = filter_poisoned_ips(ips);
                        let is_tc =
                            buf.len() >= 4 && (u16::from_be_bytes([buf[2], buf[3]]) & 0x0200) != 0;
                        if had_ips && clean.is_empty() {
                            last_err = Some(anyhow!(
                                "UDP DNS {server} returned only poisoned/sinkhole IPs"
                            ));
                        } else if !clean.is_empty() || !is_tc {
                            if offset > 0 && !clean.is_empty() {
                                self.preferred_udp_idx.store(idx, Ordering::Relaxed);
                            }
                            return Ok(DnsOutcome::Records(clean, ttl));
                        } else {
                            last_err = Some(anyhow!("UDP DNS {server} returned truncated reply"));
                        }
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("UDP DNS resolution failed for {domain}")))
    }

    async fn resolve_via_system(&self, domain: &str, filter_poison: bool) -> Result<Vec<IpAddr>> {
        if self.outbound_binder.is_some() {
            bail!(
                "system DNS lookup disabled when outbound_binder is active (TUN recursion guard)"
            );
        }
        let addrs = lookup_host((domain, 443u16))
            .await
            .with_context(|| format!("system DNS lookup failed for {domain}"))?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(ip) => {
                    let addr = IpAddr::V4(ip);
                    if (!filter_poison || !is_poisoned_public_ip(addr)) && !v4.contains(&addr) {
                        v4.push(addr);
                    }
                }
                IpAddr::V6(ip) if !self.ipv4_only => {
                    let addr = IpAddr::V6(ip);
                    if (!filter_poison || !is_poisoned_public_ip(addr)) && !v6.contains(&addr) {
                        v6.push(addr);
                    }
                }
                IpAddr::V6(_) => {}
            }
        }
        v4.extend(v6);
        if v4.is_empty() {
            bail!("system DNS returned no usable records for {domain}");
        }
        Ok(v4)
    }

    /// Answers a raw RFC 1035 DNS wire query (as intercepted from a TUN interface on UDP/53 or TCP/53),
    /// routing `A` and `AAAA` queries through the anti-poisoning DoH / non-port-53 DNS ring
    /// and returning `(wire_response, resolved_domain_ips)` so callers can populate reverse-DNS
    /// metadata without Fake-IP translation.
    pub async fn resolve_wire_query(
        &self,
        query: &[u8],
        block_https_svcb: bool,
    ) -> Result<(Vec<u8>, Option<(String, Vec<IpAddr>)>)> {
        let parsed = parse_dns_question(query)?;
        let question_slice = &query[12..parsed.question_end];

        // Firefox TRR canary domain: resolve_wire_query is exclusively TUN DNS interception, so
        // unconditionally return synthetic NXDOMAIN to keep Firefox DNS inside TUN's anti-poisoning DoH.
        if parsed
            .qname
            .trim_end_matches('.')
            .eq_ignore_ascii_case(FIREFOX_CANARY_DOMAIN)
        {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            return Ok((
                build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 3, &[], 60),
                None,
            ));
        }

        // Suppress SVCB (type 64) and HTTPS (type 65) records when QUIC blocking is enabled so
        // browsers and apps don't receive HTTP/3 Alt-Svc hints that bypass TCP TLS desync.
        if block_https_svcb && matches!(parsed.qtype, QTYPE_SVCB | QTYPE_HTTPS) {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            return Ok((
                build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 0, &[], 60),
                None,
            ));
        }

        if parsed.qclass == QCLASS_IN && matches!(parsed.qtype, QTYPE_A | QTYPE_AAAA) {
            if parsed.qtype == QTYPE_AAAA && self.ipv4_only {
                self.query_count.fetch_add(1, Ordering::Relaxed);
                return Ok((
                    build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 0, &[], 60),
                    None,
                ));
            }

            // Query only the requested RR type so `QTYPE_A` never stalls waiting on `QTYPE_AAAA`.
            // Always disable OS `lookup_host` fallback here to prevent TUN DNS recursion loops.
            match self
                .resolve_single_qtype(&parsed.qname, parsed.qtype, true, true)
                .await
            {
                Ok(DnsOutcome::NxDomain(_)) => {
                    return Ok((
                        build_dns_wire_response(
                            parsed.tx_id,
                            parsed.flags,
                            question_slice,
                            3,
                            &[],
                            30,
                        ),
                        None,
                    ));
                }
                Ok(DnsOutcome::Records(ips, ttl)) => {
                    let matching: Vec<IpAddr> = ips
                        .into_iter()
                        .filter(|ip| match parsed.qtype {
                            QTYPE_A => ip.is_ipv4(),
                            QTYPE_AAAA => ip.is_ipv6(),
                            _ => false,
                        })
                        .collect();
                    let ttl_secs = ttl.as_secs().clamp(15, 3600) as u32;
                    let resp = build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        question_slice,
                        0,
                        &matching,
                        ttl_secs,
                    );
                    let meta = if matching.is_empty() {
                        None
                    } else {
                        Some((parsed.qname, matching))
                    };
                    return Ok((resp, meta));
                }
                Err(_) => {
                    return Ok((
                        build_dns_wire_response(
                            parsed.tx_id,
                            parsed.flags,
                            question_slice,
                            2,
                            &[],
                            0,
                        ),
                        None,
                    ));
                }
            }
        }

        // Forward other RR types (SRV, TXT, MX, PTR, etc.) over DoH (respecting backoff) or UDP fallback.
        self.query_count.fetch_add(1, Ordering::Relaxed);
        if self.enable_doh && !self.is_doh_in_backoff() {
            if let Ok(mut raw) = self.query_doh_raw(query).await {
                if raw.len() >= 12 {
                    raw[0..2].copy_from_slice(&parsed.tx_id.to_be_bytes());
                    return Ok((raw, None));
                }
            }
        }

        if let Ok(mut raw) = self.query_udp_raw(query).await {
            if raw.len() >= 12 {
                raw[0..2].copy_from_slice(&parsed.tx_id.to_be_bytes());
                return Ok((raw, None));
            }
        }

        Ok((
            build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 2, &[], 0),
            None,
        ))
    }

    async fn query_doh_raw(&self, wire_query: &[u8]) -> Result<Vec<u8>> {
        let count = self.doh_endpoints.len();
        if count == 0 {
            bail!("no DoH endpoints configured");
        }
        let mut normalized_query = wire_query.to_vec();
        if normalized_query.len() >= 2 {
            normalized_query[0] = 0;
            normalized_query[1] = 0;
        }
        let start = self.preferred_doh_idx.load(Ordering::Relaxed) % count;
        if let Ok(bytes) = send_doh_wire(
            &self.http,
            self.outbound_binder.as_deref(),
            self.bound_tls_connector.as_ref(),
            &self.doh_endpoints[start],
            &normalized_query,
        )
        .await
        {
            return Ok(bytes);
        }
        for offset in 1..count.min(3) {
            let idx = (start + offset) % count;
            if let Ok(bytes) = send_doh_wire(
                &self.http,
                self.outbound_binder.as_deref(),
                self.bound_tls_connector.as_ref(),
                &self.doh_endpoints[idx],
                &normalized_query,
            )
            .await
            {
                self.preferred_doh_idx.store(idx, Ordering::Relaxed);
                return Ok(bytes);
            }
        }
        bail!("raw DoH query failed")
    }

    async fn query_udp_raw(&self, wire_query: &[u8]) -> Result<Vec<u8>> {
        let count = self.udp_dns_servers.len();
        if count == 0 {
            bail!("no UDP DNS servers configured");
        }
        let start = self.preferred_udp_idx.load(Ordering::Relaxed) % count;
        for offset in 0..count.min(3) {
            let idx = (start + offset) % count;
            if let Ok(bytes) = send_udp_dns_raw(
                self.udp_dns_servers[idx],
                wire_query,
                self.outbound_binder.as_deref(),
            )
            .await
            {
                let is_tc =
                    bytes.len() >= 4 && (u16::from_be_bytes([bytes[2], bytes[3]]) & 0x0200) != 0;
                if !is_tc {
                    if offset > 0 {
                        self.preferred_udp_idx.store(idx, Ordering::Relaxed);
                    }
                    return Ok(bytes);
                }
            }
        }
        bail!("raw UDP DNS query failed")
    }
}

async fn send_udp_dns_raw(
    server: SocketAddr,
    wire_query: &[u8],
    outbound_binder: Option<&dyn OutboundBinder>,
) -> Result<Vec<u8>> {
    if wire_query.len() < 12 {
        bail!("UDP DNS query shorter than 12-byte header");
    }
    let tx_id = next_udp_tx_id();
    let tx_bytes = tx_id.to_be_bytes();
    let mut outbound_query = wire_query.to_vec();
    outbound_query[0..2].copy_from_slice(&tx_bytes);

    let sock = if let Some(binder) = outbound_binder {
        let (domain, bind_addr) = if server.is_ipv4() {
            (
                socket2::Domain::IPV4,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        } else {
            (
                socket2::Domain::IPV6,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            )
        };
        let raw = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if !server.is_ipv4() {
            let _ = raw.set_only_v6(true);
        }
        binder.bind_socket(socket2::SockRef::from(&raw), server.is_ipv4())?;
        raw.bind(&bind_addr.into())?;
        raw.set_nonblocking(true)?;
        let std_sock: std::net::UdpSocket = raw.into();
        UdpSocket::from_std(std_sock)?
    } else {
        let bind_addr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        UdpSocket::bind(bind_addr).await?
    };
    sock.connect(server).await?;
    sock.send(&outbound_query).await?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_millis(1000), sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("UDP DNS timeout from {server}"))??;
    let resp = &buf[..n];
    if resp.len() < 12 {
        bail!("UDP DNS response shorter than 12-byte header from {server}");
    }
    if resp[0..2] != tx_bytes {
        bail!("UDP DNS response TXID mismatch from {server}");
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    if (flags & 0x8000) == 0 {
        bail!("UDP DNS response missing QR=1 bit from {server}");
    }
    Ok(resp.to_vec())
}

struct ParsedDnsQuestion {
    tx_id: u16,
    flags: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
}

fn parse_dns_question(buf: &[u8]) -> Result<ParsedDnsQuestion> {
    if buf.len() < 12 {
        bail!("DNS query shorter than 12-byte header");
    }
    let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) != 0 {
        bail!("DNS packet is a response (QR=1), not a query");
    }
    let opcode = (flags >> 11) & 0x0f;
    if opcode != 0 {
        bail!("unsupported DNS OPCODE {opcode}");
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        bail!("DNS query has no questions");
    }

    let (qname, pos) = read_dns_name(buf, 12)?;
    if pos + 4 > buf.len() {
        bail!("truncated DNS question footer");
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);

    Ok(ParsedDnsQuestion {
        tx_id,
        flags,
        qname,
        qtype,
        qclass,
        question_end: pos + 4,
    })
}

fn read_dns_name(buf: &[u8], mut pos: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut steps = 0usize;
    loop {
        if pos >= buf.len() {
            bail!("DNS name out of bounds");
        }
        steps += 1;
        if steps > 128 {
            bail!("DNS name exceeded label limit");
        }
        let len = buf[pos];
        if len == 0 {
            return Ok((labels.join("."), pos + 1));
        }
        if (len & 0b1100_0000) != 0 {
            bail!("compression pointer not supported in DNS query question");
        }
        let end = pos + 1 + (len as usize);
        if end > buf.len() {
            bail!("truncated DNS label");
        }
        let label = std::str::from_utf8(&buf[pos + 1..end])
            .context("non-UTF8 DNS label")?
            .to_ascii_lowercase();
        labels.push(label);
        pos = end;
    }
}

fn build_dns_wire_response(
    tx_id: u16,
    req_flags: u16,
    question_slice: &[u8],
    rcode: u8,
    answers: &[IpAddr],
    ttl_secs: u32,
) -> Vec<u8> {
    let rd = req_flags & 0x0100;
    // QR=1 (0x8000), RA=1 (0x0080), preserve RD, set RCODE
    let resp_flags = 0x8080 | rd | u16::from(rcode & 0x0f);
    let ancount = u16::try_from(answers.len()).unwrap_or(u16::MAX);

    let mut out = Vec::with_capacity(12 + question_slice.len() + answers.len() * 28);
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0
    out.extend_from_slice(question_slice);

    for ip in answers.iter().take(usize::from(ancount)) {
        // Compression pointer to QNAME at offset 12 (0xC00C)
        out.extend_from_slice(&[0xc0, 0x0c]);
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&QTYPE_A.to_be_bytes());
                out.extend_from_slice(&QCLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl_secs.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&QTYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&QCLASS_IN.to_be_bytes());
                out.extend_from_slice(&ttl_secs.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

fn insert_cache_entry(cache: &mut HashMap<String, CacheEntry>, key: String, entry: CacheEntry) {
    if cache.len() >= MAX_CACHE_ENTRIES && !cache.contains_key(&key) {
        let now = Instant::now();
        cache.retain(|_, v| now < v.expires_at);
        // TTL alone doesn't cap a burst of unique answers, all of which may be fresh.
        if cache.len() >= MAX_CACHE_ENTRIES {
            if let Some(victim) = cache.keys().next().cloned() {
                cache.remove(&victim);
            }
        }
    }
    cache.insert(key, entry);
}

fn merge_ips_v4_first(existing: &[IpAddr], added: &[IpAddr]) -> Vec<IpAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in existing.iter().chain(added.iter()).copied() {
        if ip.is_ipv4() {
            if !v4.contains(&ip) {
                v4.push(ip);
            }
        } else if !v6.contains(&ip) {
            v6.push(ip);
        }
    }
    v4.extend(v6);
    v4
}

fn load_pem_file_into_store(path: &Path, roots: &mut rustls::RootCertStore) {
    if let Ok(iter) = CertificateDer::pem_file_iter(path) {
        roots.add_parsable_certificates(iter.flatten());
    }
}

fn load_system_pem_roots(roots: &mut rustls::RootCertStore) {
    if let Some(env_file) = std::env::var_os("SSL_CERT_FILE") {
        load_pem_file_into_store(Path::new(&env_file), roots);
    }
    #[cfg(unix)]
    {
        const CA_FILES: &[&str] = &[
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/ca-bundle.pem",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
            "/etc/ssl/cert.pem",
        ];
        for path in CA_FILES {
            load_pem_file_into_store(Path::new(path), roots);
        }
        const CA_DIRS: &[&str] = &[
            "/apex/com.android.conscrypt/cacerts",
            "/system/etc/security/cacerts",
        ];
        for dir in CA_DIRS {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        load_pem_file_into_store(&p, roots);
                    }
                }
            }
        }
    }
}

fn bound_doh_root_store() -> Arc<rustls::RootCertStore> {
    BOUND_DOH_ROOTS
        .get_or_init(|| {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            load_system_pem_roots(&mut roots);
            Arc::new(roots)
        })
        .clone()
}

fn build_bound_tls_connector() -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = bound_doh_root_store();
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure rustls protocol versions for bound DoH")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(cfg)))
}

struct BoundDohTarget {
    addr: SocketAddr,
    host_header: String,
    path: String,
    server_name: ServerName<'static>,
}

fn parse_bound_doh_endpoint(endpoint: &str) -> Result<BoundDohTarget> {
    let rest = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("bound DoH endpoint must use https://: {endpoint}"))?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/dns-query"),
    };
    let (ip, port, host_header) = if let Some(after_open) = authority.strip_prefix('[') {
        let close = after_open
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 bracket in DoH endpoint: {endpoint}"))?;
        let ip_str = &after_open[..close];
        let ip: IpAddr = ip_str
            .parse()
            .with_context(|| format!("invalid IPv6 literal in DoH endpoint: {endpoint}"))?;
        let tail = &after_open[close + 1..];
        let port = if let Some(port_str) = tail.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .with_context(|| format!("invalid port in DoH endpoint: {endpoint}"))?
        } else if tail.is_empty() {
            443
        } else {
            bail!("unexpected trailing characters in DoH authority: {endpoint}");
        };
        let host_header = if port == 443 {
            format!("[{ip}]")
        } else {
            format!("[{ip}]:{port}")
        };
        (ip, port, host_header)
    } else {
        let (host_str, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>()
                    .with_context(|| format!("invalid port in DoH endpoint: {endpoint}"))?,
            ),
            None => (authority, 443),
        };
        let ip: IpAddr = host_str
            .parse()
            .with_context(|| format!("bound DoH requires IP-literal endpoint: {endpoint}"))?;
        let host_header = if port == 443 {
            ip.to_string()
        } else {
            format!("{ip}:{port}")
        };
        (ip, port, host_header)
    };

    Ok(BoundDohTarget {
        addr: SocketAddr::new(ip, port),
        host_header,
        path: path.to_string(),
        server_name: ServerName::from(ip),
    })
}

struct HttpDohHead {
    body_offset: usize,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_http_doh_head(raw: &[u8], endpoint: &str) -> Result<Option<HttpDohHead>> {
    let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        if raw.len() > MAX_BOUND_DOH_HEADER_BYTES {
            bail!("DoH HTTP headers exceeded {MAX_BOUND_DOH_HEADER_BYTES} bytes from {endpoint}");
        }
        return Ok(None);
    };
    let head_str = std::str::from_utf8(&raw[..pos])
        .with_context(|| format!("non-UTF8 DoH HTTP response headers from {endpoint}"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("empty DoH HTTP response from {endpoint}"))?;
    let mut parts = status_line.split_ascii_whitespace();
    let _version = parts
        .next()
        .ok_or_else(|| anyhow!("malformed DoH HTTP status line from {endpoint}"))?;
    let status_code = parts
        .next()
        .ok_or_else(|| anyhow!("missing DoH HTTP status code from {endpoint}"))?;
    if status_code != "200" {
        bail!("DoH HTTP status {status_code} from {endpoint}");
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim();
            let val = val.trim();
            if name.eq_ignore_ascii_case("content-length") {
                let cl = val.parse::<usize>().with_context(|| {
                    format!("invalid DoH Content-Length '{val}' from {endpoint}")
                })?;
                if cl > MAX_DNS_MESSAGE_BYTES {
                    bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
                }
                content_length = Some(cl);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && val.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    Ok(Some(HttpDohHead {
        body_offset: pos + 4,
        content_length,
        chunked,
    }))
}

fn decode_chunked_body(input: &[u8], max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_crlf) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line =
            std::str::from_utf8(&input[pos..pos + rel_crlf]).context("non-UTF8 HTTP chunk size")?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid HTTP chunk size '{size_hex}'"))?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            if input[pos..].starts_with(b"\r\n")
                || input[pos..].windows(4).any(|w| w == b"\r\n\r\n")
            {
                return Ok(Some(out));
            }
            return Ok(None);
        }
        if chunk_len > max_bytes.saturating_sub(out.len()) {
            bail!("DoH response exceeded {max_bytes} bytes");
        }
        if pos + chunk_len + 2 > input.len() {
            return Ok(None);
        }
        out.extend_from_slice(&input[pos..pos + chunk_len]);
        pos += chunk_len;
        if &input[pos..pos + 2] != b"\r\n" {
            bail!("malformed HTTP chunk terminator");
        }
        pos += 2;
    }
}

async fn send_doh_bound_tls(
    binder: &dyn OutboundBinder,
    connector: &TlsConnector,
    endpoint: &str,
    wire_query: &[u8],
) -> Result<Vec<u8>> {
    let target = parse_bound_doh_endpoint(endpoint)?;
    let sock = if target.addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    binder.bind_socket(socket2::SockRef::from(&sock), target.addr.is_ipv4())?;

    let tcp = tokio::time::timeout(Duration::from_millis(1200), sock.connect(target.addr))
        .await
        .map_err(|_| anyhow!("bound DoH TCP connect timeout to {}", target.addr))??;
    let _ = tcp.set_nodelay(true);

    tokio::time::timeout(Duration::from_millis(2000), async move {
        let mut tls = connector
            .connect(target.server_name, tcp)
            .await
            .with_context(|| format!("bound DoH TLS handshake failed to {endpoint}"))?;

        let req_head = format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            target.path,
            target.host_header,
            wire_query.len()
        );
        tls.write_all(req_head.as_bytes()).await?;
        tls.write_all(wire_query).await?;
        tls.flush().await?;

        let mut raw = Vec::with_capacity(1024);
        let mut parsed_head: Option<HttpDohHead> = None;
        let mut buf = [0u8; 4096];

        loop {
            match tls.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if n > MAX_BOUND_DOH_RAW_BYTES.saturating_sub(raw.len()) {
                        bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
                    }
                    raw.extend_from_slice(&buf[..n]);

                    if parsed_head.is_none() {
                        parsed_head = parse_http_doh_head(&raw, endpoint)?;
                    }
                    if let Some(ref head) = parsed_head {
                        let body = &raw[head.body_offset..];
                        if head.chunked {
                            if let Some(decoded) =
                                decode_chunked_body(body, MAX_DNS_MESSAGE_BYTES)?
                            {
                                return Ok(decoded);
                            }
                        } else if let Some(cl) = head.content_length {
                            if body.len() >= cl {
                                return Ok(body[..cl].to_vec());
                            }
                        } else if body.len() > MAX_DNS_MESSAGE_BYTES {
                            bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Some HTTP/1.1 servers close TCP after `Connection: close` without TLS close_notify.
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        let head = match parsed_head {
            Some(h) => h,
            None => parse_http_doh_head(&raw, endpoint)?
                .ok_or_else(|| anyhow!("incomplete DoH HTTP response headers from {endpoint}"))?,
        };
        let body = &raw[head.body_offset..];
        if head.chunked {
            decode_chunked_body(body, MAX_DNS_MESSAGE_BYTES)?
                .ok_or_else(|| anyhow!("truncated chunked DoH response from {endpoint}"))
        } else if let Some(cl) = head.content_length {
            if body.len() < cl {
                bail!(
                    "truncated DoH response from {endpoint} (got {} of {cl} bytes)",
                    body.len()
                );
            }
            Ok(body[..cl].to_vec())
        } else {
            if body.len() > MAX_DNS_MESSAGE_BYTES {
                bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
            }
            Ok(body.to_vec())
        }
    })
    .await
    .map_err(|_| anyhow!("bound DoH exchange timeout to {endpoint}"))?
}

async fn send_doh_wire(
    http: &Client,
    outbound_binder: Option<&dyn OutboundBinder>,
    bound_tls: Option<&TlsConnector>,
    endpoint: &str,
    wire_query: &[u8],
) -> Result<Vec<u8>> {
    if let (Some(binder), Some(connector)) = (outbound_binder, bound_tls) {
        send_doh_bound_tls(binder, connector, endpoint, wire_query).await
    } else {
        send_doh_request_raw(http, endpoint, wire_query).await
    }
}

async fn send_doh_request_raw(http: &Client, endpoint: &str, wire_query: &[u8]) -> Result<Vec<u8>> {
    let mut resp = http
        .post(endpoint)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire_query.to_vec())
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("DoH HTTP status {} from {}", resp.status(), endpoint);
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_DNS_MESSAGE_BYTES as u64)
    {
        bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if chunk.len() > MAX_DNS_MESSAGE_BYTES - bytes.len() {
            bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn send_doh_request(
    http: &Client,
    outbound_binder: Option<&dyn OutboundBinder>,
    bound_tls: Option<&TlsConnector>,
    endpoint: &str,
    wire_query: &[u8],
    qtype: u16,
) -> std::result::Result<DnsOutcome, DohError> {
    let bytes = send_doh_wire(http, outbound_binder, bound_tls, endpoint, wire_query)
        .await
        .map_err(DohError::Transport)?;
    match decode_dns_outcome_classified(&bytes, qtype) {
        Ok(DnsOutcome::NxDomain(ttl)) => Ok(DnsOutcome::NxDomain(ttl)),
        Ok(DnsOutcome::Records(ips, ttl)) => {
            let had_ips = !ips.is_empty();
            let clean = filter_poisoned_ips(ips);
            if had_ips && clean.is_empty() {
                Err(DohError::Transport(anyhow!(
                    "DoH endpoint {endpoint} returned only poisoned/sinkhole IPs"
                )))
            } else {
                Ok(DnsOutcome::Records(clean, ttl))
            }
        }
        Err(DnsDecodeError::ProtocolError(rcode)) => Err(DohError::ProtocolError {
            endpoint: endpoint.to_string(),
            rcode,
        }),
        Err(DnsDecodeError::Malformed(err)) => Err(DohError::Transport(err)),
    }
}

fn build_doh_endpoints(dns_addr: &str) -> Vec<String> {
    let mut list = Vec::new();
    let trimmed = dns_addr.trim();
    if trimmed.starts_with("https://") {
        list.push(trimmed.to_string());
    } else if !trimmed.is_empty() {
        let stripped = trimmed.trim_matches(|c| c == '[' || c == ']');
        let primary = match stripped {
            "1.1.1.1" | "1.0.0.1" => format!("https://{stripped}/dns-query"),
            "8.8.8.8" | "8.8.4.4" => format!("https://{stripped}/dns-query"),
            "9.9.9.9" | "149.112.112.112" => format!("https://{stripped}/dns-query"),
            other if other.parse::<Ipv4Addr>().is_ok() => format!("https://{other}/dns-query"),
            other if other.parse::<Ipv6Addr>().is_ok() => format!("https://[{other}]/dns-query"),
            _ => "https://1.1.1.1/dns-query".to_string(),
        };
        list.push(primary);
    }

    // Multi-provider IP-literal DoH ring interleaved across independent networks
    // (Cloudflare, Google, AdGuard Unfiltered, Quad9 — no SNI required, resilient to ISP IP blocks)
    for fallback in [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://94.140.14.140/dns-query",
        "https://9.9.9.9/dns-query",
        "https://1.0.0.1/dns-query",
        "https://94.140.14.141/dns-query",
        "https://149.112.112.112/dns-query",
        "https://8.8.4.4/dns-query",
    ] {
        if !list.iter().any(|x| x == fallback) {
            list.push(fallback.to_string());
        }
    }
    list
}

fn build_udp_dns_servers(dns_addr: &str, dns_port: u16) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    let trimmed_dns = dns_addr.trim().trim_matches(|c| c == '[' || c == ']');
    // Non-standard ports (1253, 443, 5353) bypass transparent ISP port-53 DNS interceptors
    // on strict fiber and broadband networks worldwide.
    if let Ok(ip) = trimmed_dns.parse::<IpAddr>() {
        if dns_port != 53 {
            servers.push(SocketAddr::new(ip, dns_port));
        }
    }
    for (ip, port) in [
        (Ipv4Addr::new(77, 88, 8, 8), 1253),
        (Ipv4Addr::new(208, 67, 222, 222), 443),
        (Ipv4Addr::new(77, 88, 8, 1), 1253),
        (Ipv4Addr::new(208, 67, 220, 220), 443),
        (Ipv4Addr::new(208, 67, 222, 222), 5353),
    ] {
        let sa = SocketAddr::new(IpAddr::V4(ip), port);
        if !servers.contains(&sa) {
            servers.push(sa);
        }
    }
    if let Ok(ip) = trimmed_dns.parse::<IpAddr>() {
        let sa = SocketAddr::new(ip, dns_port);
        if !servers.contains(&sa) {
            servers.push(sa);
        }
    }
    for (ip, port) in [
        (Ipv4Addr::new(1, 1, 1, 1), 53),
        (Ipv4Addr::new(8, 8, 8, 8), 53),
    ] {
        let sa = SocketAddr::new(IpAddr::V4(ip), port);
        if !servers.contains(&sa) {
            servers.push(sa);
        }
    }
    servers
}

/// Returns `true` when an IP returned by an external DNS server for a public hostname is an
/// obvious sinkhole or ISP block-page address that must never be cached.
pub fn is_poisoned_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_broadcast()
                || matches!(
                    v4.octets(),
                    [198, 18 | 19, ..]
                        | [195, 175, 39, 39]
                        | [195, 175, 39, 40]
                        | [195, 175, 39, 49]
                        | [195, 175, 39, 50]
                )
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| is_poisoned_public_ip(IpAddr::V4(v4)))
        }
    }
}

fn filter_poisoned_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| !is_poisoned_public_ip(*ip))
        .collect()
}

/// Encodes an RFC 1035 / RFC 8484 DNS wire query (ID = 0 per RFC 8484 section 4.1 recommendation).
pub fn encode_dns_query(domain: &str, qtype: u16) -> Result<Vec<u8>> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&[
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);

    for label in domain.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            bail!("invalid DNS label in '{domain}'");
        }
        msg.push(bytes.len() as u8);
        msg.extend_from_slice(bytes);
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Ok(msg)
}

/// Decodes a DNS wire response and extracts matching `A` or `AAAA` records along with a clamped TTL.
pub fn decode_dns_response(buf: &[u8], expected_qtype: u16) -> Result<(Vec<IpAddr>, Duration)> {
    match decode_dns_outcome(buf, expected_qtype)? {
        DnsOutcome::Records(ips, ttl) => Ok((ips, ttl)),
        DnsOutcome::NxDomain(_) => bail!("DNS response returned RCODE 3 (NXDOMAIN)"),
    }
}

fn decode_dns_outcome(buf: &[u8], expected_qtype: u16) -> Result<DnsOutcome> {
    decode_dns_outcome_classified(buf, expected_qtype).map_err(|err| match err {
        DnsDecodeError::ProtocolError(rcode) => anyhow!("DNS response returned RCODE {rcode}"),
        DnsDecodeError::Malformed(e) => e,
    })
}

fn decode_dns_outcome_classified(
    buf: &[u8],
    expected_qtype: u16,
) -> std::result::Result<DnsOutcome, DnsDecodeError> {
    if buf.len() < 12 {
        return Err(DnsDecodeError::Malformed(anyhow!(
            "DNS response shorter than 12-byte header"
        )));
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) == 0 {
        return Err(DnsDecodeError::Malformed(anyhow!(
            "DNS packet does not have QR response bit set"
        )));
    }
    let truncated = (flags & 0x0200) != 0;
    let rcode = flags & 0x000f;
    if rcode == 3 {
        if truncated {
            return Err(DnsDecodeError::Malformed(anyhow!(
                "DNS response truncated (TC=1)"
            )));
        }
        return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
    }
    if rcode != 0 {
        if truncated {
            return Err(DnsDecodeError::Malformed(anyhow!(
                "DNS response truncated (TC=1) with RCODE {rcode}"
            )));
        }
        return Err(DnsDecodeError::ProtocolError(rcode));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos).map_err(DnsDecodeError::Malformed)?;
        if pos + 4 > buf.len() {
            return Err(DnsDecodeError::Malformed(anyhow!(
                "truncated DNS question section"
            )));
        }
        pos += 4;
    }

    let mut ips = Vec::new();
    let mut min_ttl_secs: Option<u64> = None;

    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos).map_err(DnsDecodeError::Malformed)?;
        if pos + 10 > buf.len() {
            return Err(DnsDecodeError::Malformed(anyhow!(
                "truncated DNS resource record header"
            )));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let ttl =
            u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]) as u64;
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > buf.len() {
            return Err(DnsDecodeError::Malformed(anyhow!(
                "truncated DNS resource record rdata"
            )));
        }

        if rclass == QCLASS_IN && rtype == expected_qtype {
            match (rtype, rdlength) {
                (QTYPE_A, 4) => {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        buf[pos],
                        buf[pos + 1],
                        buf[pos + 2],
                        buf[pos + 3],
                    ));
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                    min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |cur| cur.min(ttl)));
                }
                (QTYPE_AAAA, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[pos..pos + 16]);
                    let ip = IpAddr::V6(Ipv6Addr::from(octets));
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                    min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |cur| cur.min(ttl)));
                }
                _ => {}
            }
        } else if rclass == QCLASS_IN && rtype == QTYPE_CNAME {
            // Fold CNAME chain TTLs into the effective answer TTL (including CNAME-only NODATA).
            min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |cur| cur.min(ttl)));
        }

        pos += rdlength;
    }

    if truncated && ips.is_empty() {
        return Err(DnsDecodeError::Malformed(anyhow!(
            "DNS response truncated (TC=1) with no matching answers"
        )));
    }

    let clamped_ttl = Duration::from_secs(min_ttl_secs.unwrap_or(120).clamp(30, 3600));
    Ok(DnsOutcome::Records(ips, clamped_ttl))
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Result<usize> {
    let mut steps = 0usize;
    loop {
        if pos >= buf.len() {
            bail!("DNS name out of bounds");
        }
        steps += 1;
        if steps > 128 {
            bail!("DNS name exceeded label limit");
        }
        let len = buf[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if (len & 0b1100_0000) == 0b1100_0000 {
            if pos + 1 >= buf.len() {
                bail!("truncated DNS compression pointer");
            }
            return Ok(pos + 2);
        }
        if (len & 0b1100_0000) != 0 {
            bail!("unsupported DNS label header bits");
        }
        pos += 1 + (len as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binder::NoopBinder;

    #[derive(Debug, Default)]
    struct CountingBinder {
        calls: AtomicUsize,
    }

    impl OutboundBinder for CountingBinder {
        fn bind_socket(&self, _sock: socket2::SockRef<'_>, _is_ipv4: bool) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn dns_cache_is_bounded_even_when_every_answer_is_fresh() {
        let mut cache = HashMap::new();
        let entry = CacheEntry {
            ips: vec![Ipv4Addr::LOCALHOST.into()],
            nxdomain: false,
            has_a_lookup: true,
            has_aaaa_lookup: true,
            expires_at: Instant::now() + Duration::from_secs(3600),
        };
        for i in 0..MAX_CACHE_ENTRIES * 2 {
            insert_cache_entry(&mut cache, format!("{i}.example"), entry.clone());
            assert!(cache.len() <= MAX_CACHE_ENTRIES);
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        assert!(cache.contains_key(&format!("{}.example", MAX_CACHE_ENTRIES * 2 - 1)));
    }

    #[test]
    fn cache_insertion_purges_expired_entries_before_evicting_active() {
        let mut cache = HashMap::new();
        let expired_at = Instant::now();
        let expired = CacheEntry {
            ips: vec![Ipv4Addr::LOCALHOST.into()],
            nxdomain: false,
            has_a_lookup: true,
            has_aaaa_lookup: true,
            expires_at: expired_at,
        };
        let active = CacheEntry {
            ips: vec![Ipv4Addr::LOCALHOST.into()],
            nxdomain: false,
            has_a_lookup: true,
            has_aaaa_lookup: true,
            expires_at: expired_at + Duration::from_secs(3600),
        };
        cache.insert("expired.example".to_string(), expired);
        for i in 0..(MAX_CACHE_ENTRIES - 1) {
            cache.insert(format!("active-{i}.example"), active.clone());
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);

        // Ensure monotonic clock has advanced past `expired_at` so `now < expired_at` is false.
        std::thread::sleep(Duration::from_millis(2));
        insert_cache_entry(&mut cache, "new-active.example".to_string(), active);
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        assert!(!cache.contains_key("expired.example"));
        assert!(cache.contains_key("new-active.example"));
        assert!(cache.contains_key("active-0.example"));
    }

    #[test]
    fn encodes_and_decodes_cname_plus_a_and_cname_only_aaaa() {
        let q = encode_dns_query("www.roblox.com", QTYPE_A).unwrap();
        assert_eq!(&q[12..16], &[3, b'w', b'w', b'w']);

        let mut resp = Vec::new();
        resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        resp.extend_from_slice(&q[12..]);
        resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 128, 116, 31, 3,
        ]);

        let (ips_v4, ttl) = decode_dns_response(&resp, QTYPE_A).unwrap();
        assert_eq!(ips_v4, vec![IpAddr::V4(Ipv4Addr::new(128, 116, 31, 3))]);
        assert_eq!(ttl, Duration::from_secs(60));

        let mut aaaa_nodata = Vec::new();
        aaaa_nodata.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ]);
        aaaa_nodata.extend_from_slice(&q[12..]);
        aaaa_nodata.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
        ]);

        let (ips_v6, _) = decode_dns_response(&aaaa_nodata, QTYPE_AAAA).unwrap();
        assert!(ips_v6.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires public DNS and DoH connectivity"]
    async fn resolves_discord_and_roblox_via_live_doh() {
        let resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        let roblox_ips = resolver.resolve("www.roblox.com").await.unwrap();
        assert!(!roblox_ips.is_empty());
        assert!(roblox_ips[0].is_ipv4());

        let discord_ips = resolver.resolve("updates.discord.com").await.unwrap();
        assert!(!discord_ips.is_empty());
    }

    #[test]
    fn filters_sinkhole_and_isp_blockpage_ips() {
        assert!(is_poisoned_public_ip("0.0.0.0".parse().unwrap()));
        assert!(is_poisoned_public_ip("127.0.0.1".parse().unwrap()));
        assert!(is_poisoned_public_ip("::".parse().unwrap()));
        assert!(is_poisoned_public_ip("::1".parse().unwrap()));
        assert!(is_poisoned_public_ip("195.175.39.39".parse().unwrap()));
        assert!(is_poisoned_public_ip("198.18.0.1".parse().unwrap()));
        assert!(is_poisoned_public_ip("198.19.255.254".parse().unwrap()));
        assert!(is_poisoned_public_ip("::ffff:0.0.0.0".parse().unwrap()));
        assert!(is_poisoned_public_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_poisoned_public_ip(
            "::ffff:195.175.39.39".parse().unwrap()
        ));
        assert!(is_poisoned_public_ip("::ffff:198.18.0.5".parse().unwrap()));
        assert!(!is_poisoned_public_ip("198.17.0.1".parse().unwrap()));
        assert!(!is_poisoned_public_ip("198.20.0.1".parse().unwrap()));
        assert!(!is_poisoned_public_ip(
            "::ffff:93.184.216.34".parse().unwrap()
        ));
        assert!(!is_poisoned_public_ip("162.159.135.232".parse().unwrap()));
        assert!(!is_poisoned_public_ip("128.116.31.3".parse().unwrap()));
    }

    #[tokio::test]
    async fn answers_wire_dns_queries_for_localhost_and_blocks_https_svcb_when_enabled() {
        let resolver = DnsResolver::new("1.1.1.1", 53, false, false).unwrap();

        let mut query = encode_dns_query("localhost", QTYPE_A).unwrap();
        query[0] = 0xab;
        query[1] = 0xcd;

        let (resp, meta) = resolver.resolve_wire_query(&query, true).await.unwrap();
        assert_eq!(&resp[0..2], &[0xab, 0xcd]);
        let (ips, _) = decode_dns_response(&resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(
            meta,
            Some((
                "localhost".to_string(),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            ))
        );

        for (qtype, tx) in [(QTYPE_SVCB, [0x12, 0x33]), (QTYPE_HTTPS, [0x12, 0x34])] {
            let mut rr_query = encode_dns_query("discord.com", qtype).unwrap();
            rr_query[0] = tx[0];
            rr_query[1] = tx[1];
            let (rr_resp, rr_meta) = resolver.resolve_wire_query(&rr_query, true).await.unwrap();
            assert_eq!(&rr_resp[0..2], &tx);
            assert_eq!(u16::from_be_bytes([rr_resp[2], rr_resp[3]]) & 0x000f, 0);
            assert_eq!(u16::from_be_bytes([rr_resp[6], rr_resp[7]]), 0);
            assert!(rr_meta.is_none());
        }
        assert!(resolver.query_count() >= 3);
    }

    #[test]
    fn decodes_nxdomain_distinctly_rejects_qr1_and_formats_ipv6_doh() {
        let mut nx_resp = vec![
            0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        nx_resp
            .extend_from_slice(&encode_dns_query("does-not-exist.invalid", QTYPE_A).unwrap()[12..]);
        assert!(matches!(
            decode_dns_outcome(&nx_resp, QTYPE_A).unwrap(),
            DnsOutcome::NxDomain(_)
        ));

        // QR=1 packets must be rejected as queries
        assert!(parse_dns_question(&nx_resp).is_err());

        // IPv6 literals must be bracketed in DoH URLs
        let endpoints = build_doh_endpoints("2606:4700:4700::1111");
        assert_eq!(endpoints[0], "https://[2606:4700:4700::1111]/dns-query");
    }

    #[test]
    fn treats_truncated_tc_dns_reply_with_zero_answers_as_error() {
        let q = encode_dns_query("truncated.example", QTYPE_A).unwrap();

        // QR=1 (0x8000) | TC=1 (0x0200) | RD=1 (0x0100) | RA=1 (0x0080) => 0x8380, ANCOUNT=0
        let mut tc_empty = vec![
            0x00, 0x00, 0x83, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        tc_empty.extend_from_slice(&q[12..]);
        assert!(decode_dns_outcome(&tc_empty, QTYPE_A).is_err());
        assert!(decode_dns_response(&tc_empty, QTYPE_A).is_err());
        assert!(decode_dns_outcome(&tc_empty, QTYPE_AAAA).is_err());

        // TC=1 with CNAME-only answer (no A record parsed) must also fail as truncated.
        let mut tc_cname_only = vec![
            0x00, 0x00, 0x83, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        tc_cname_only.extend_from_slice(&q[12..]);
        tc_cname_only.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        assert!(decode_dns_outcome(&tc_cname_only, QTYPE_A).is_err());

        // TC=1 with a valid A answer still returns the parsed record.
        let mut tc_with_a = vec![
            0x00, 0x00, 0x83, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        tc_with_a.extend_from_slice(&q[12..]);
        tc_with_a.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        let (ips, _) = decode_dns_response(&tc_with_a, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[tokio::test]
    async fn resolve_via_udp_falls_through_after_tc_truncated_reply() {
        let tc_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tc_addr = tc_server.local_addr().unwrap();
        let ok_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = ok_server.local_addr().unwrap();

        let tc_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = tc_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            let mut resp = Vec::new();
            resp.extend_from_slice(&parsed.tx_id.to_be_bytes());
            resp.extend_from_slice(&0x8380u16.to_be_bytes()); // QR=1, TC=1, RD=1, RA=1
            resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
            resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT=0
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&buf[12..parsed.question_end]);
            tc_server.send_to(&resp, peer).await.unwrap();
        });

        let ok_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = ok_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &buf[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            ok_server.send_to(&resp, peer).await.unwrap();
        });

        let mut resolver = DnsResolver::new("127.0.0.1", 53, false, true).unwrap();
        resolver.udp_dns_servers = vec![tc_addr, ok_addr];
        let resolved = resolver.resolve_via_udp("example.com").await.unwrap();
        tc_task.await.unwrap();
        ok_task.await.unwrap();

        assert!(resolved.has_a_lookup);
        match resolved.outcome {
            DnsOutcome::Records(ips, _) => {
                assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
            }
            DnsOutcome::NxDomain(_) => panic!("expected A record after TC=1 fallback"),
        }
    }

    #[tokio::test]
    async fn firefox_canary_returns_nxdomain_when_outbound_binder_is_active() {
        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let bound_resolver =
            DnsResolver::new_with_binder("1.1.1.1", 53, false, false, Some(binder)).unwrap();
        let unbound_resolver = DnsResolver::new("1.1.1.1", 53, false, false).unwrap();

        for resolver in [&bound_resolver, &unbound_resolver] {
            for qtype in [QTYPE_A, QTYPE_AAAA, QTYPE_SVCB, QTYPE_HTTPS] {
                let mut query = encode_dns_query("use-application-dns.net", qtype).unwrap();
                query[0] = 0x55;
                query[1] = 0xaa;

                let (resp, meta) = resolver.resolve_wire_query(&query, true).await.unwrap();
                assert_eq!(&resp[0..2], &[0x55, 0xaa]);
                let flags = u16::from_be_bytes([resp[2], resp[3]]);
                assert_eq!(flags & 0x8000, 0x8000, "QR bit must be set");
                assert_eq!(flags & 0x000f, 3, "RCODE must be 3 (NXDOMAIN)");
                assert_eq!(
                    u16::from_be_bytes([resp[6], resp[7]]),
                    0,
                    "ANCOUNT must be 0"
                );
                assert!(meta.is_none());
            }
            assert_eq!(resolver.query_count(), 4);
        }

        // TUN wire queries must also disable OS `lookup_host` fallback even without outbound_binder.
        let mut local_query = encode_dns_query("printer.local", QTYPE_A).unwrap();
        local_query[0] = 0x77;
        local_query[1] = 0x88;
        let (local_resp, local_meta) = unbound_resolver
            .resolve_wire_query(&local_query, true)
            .await
            .unwrap();
        assert_eq!(&local_resp[0..2], &[0x77, 0x88]);
        assert_eq!(
            u16::from_be_bytes([local_resp[2], local_resp[3]]) & 0x000f,
            3
        );
        assert!(local_meta.is_none());
    }

    #[tokio::test]
    async fn lock_free_doh_backoff_trips_clears_and_expires() {
        let resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        assert!(!resolver.is_doh_in_backoff());

        resolver.set_doh_backoff(Duration::from_secs(30));
        assert!(resolver.is_doh_in_backoff());

        resolver.clear_cache().await;
        assert!(!resolver.is_doh_in_backoff());

        resolver.set_doh_backoff(Duration::from_millis(25));
        assert!(resolver.is_doh_in_backoff());
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!resolver.is_doh_in_backoff());
    }

    #[tokio::test]
    async fn qtype_a_wire_query_returns_without_aaaa_stall_and_binds_udp_socket() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            assert_eq!(parsed.qtype, QTYPE_A);
            let resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &buf[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            udp_server.send_to(&resp, peer).await.unwrap();
        });

        let counter = Arc::new(CountingBinder::default());
        let binder: Arc<dyn OutboundBinder> = counter.clone();
        let mut resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, false, false, Some(binder)).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];

        let mut query = encode_dns_query("fast-a.example", QTYPE_A).unwrap();
        query[0] = 0x11;
        query[1] = 0x22;

        let started = Instant::now();
        let (resp, meta) = resolver.resolve_wire_query(&query, true).await.unwrap();
        let elapsed = started.elapsed();
        server_task.await.unwrap();

        assert!(
            elapsed < Duration::from_millis(400),
            "QTYPE_A wire query stalled for {elapsed:?} waiting on AAAA"
        );
        assert_eq!(counter.calls.load(Ordering::Relaxed), 1);
        let (ips, _) = decode_dns_response(&resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(
            meta,
            Some((
                "fast-a.example".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
            ))
        );
    }

    #[tokio::test]
    async fn system_dns_recursion_guard_blocks_lookup_when_binder_is_active() {
        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let resolver =
            DnsResolver::new_with_binder("1.1.1.1", 53, false, false, Some(binder)).unwrap();
        assert!(resolver
            .resolve_via_system("localhost", false)
            .await
            .is_err());
    }

    #[test]
    fn bound_doh_endpoint_parser_and_http_response_helpers() {
        let v4 = parse_bound_doh_endpoint("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(v4.addr, "1.1.1.1:443".parse::<SocketAddr>().unwrap());
        assert_eq!(v4.host_header, "1.1.1.1");
        assert_eq!(v4.path, "/dns-query");

        let v6 = parse_bound_doh_endpoint("https://[2606:4700:4700::1111]:8443/dns-query").unwrap();
        assert_eq!(
            v6.addr,
            "[2606:4700:4700::1111]:8443".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(v6.host_header, "[2606:4700:4700::1111]:8443");
        assert_eq!(v6.path, "/dns-query");

        assert!(parse_bound_doh_endpoint("http://1.1.1.1/dns-query").is_err());
        assert!(parse_bound_doh_endpoint("https://dns.google/dns-query").is_err());

        let ok_head = parse_http_doh_head(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 12\r\n\r\n",
            "https://1.1.1.1/dns-query",
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok_head.content_length, Some(12));
        assert!(!ok_head.chunked);

        assert!(parse_http_doh_head(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "https://1.1.1.1/dns-query",
        )
        .is_err());

        assert!(parse_http_doh_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n",
            "https://1.1.1.1/dns-query",
        )
        .is_err());

        let decoded = decode_chunked_body(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n", 64)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, b"abcdef");
    }

    #[tokio::test]
    async fn send_doh_bound_tls_binds_socket_and_exchanges_dns_over_tls() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert_key.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()),
        );
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 2048];
            let (head_end, body_len) = loop {
                let n = tls.read(&mut buf).await.unwrap();
                assert!(n > 0);
                req.extend_from_slice(&buf[..n]);
                if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = std::str::from_utf8(&req[..pos]).unwrap();
                    assert!(head.starts_with("POST /dns-query HTTP/1.1\r\n"));
                    assert!(head
                        .to_ascii_lowercase()
                        .contains("content-type: application/dns-message"));
                    assert!(head
                        .to_ascii_lowercase()
                        .contains("accept: application/dns-message"));
                    assert!(head.to_ascii_lowercase().contains("connection: close"));
                    let cl: usize = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                v.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap();
                    if req.len() >= pos + 4 + cl {
                        break (pos + 4, cl);
                    }
                }
            };
            let query = &req[head_end..head_end + body_len];
            let parsed = parse_dns_question(query).unwrap();
            let wire_resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &query[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                120,
            );
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                wire_resp.len()
            );
            tls.write_all(http_resp.as_bytes()).await.unwrap();
            tls.write_all(&wire_resp).await.unwrap();
            tls.flush().await.unwrap();
            let _ = tls.shutdown().await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let binder = CountingBinder::default();
        let query = encode_dns_query("bound-doh.example", QTYPE_A).unwrap();
        let endpoint = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let raw_resp = send_doh_bound_tls(&binder, &connector, &endpoint, &query)
            .await
            .unwrap();
        server_task.await.unwrap();

        assert_eq!(binder.calls.load(Ordering::Relaxed), 1);
        let (ips, _) = decode_dns_response(&raw_resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    fn make_local_doh_tls_pair() -> (Arc<rustls::ServerConfig>, TlsConnector) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = CertificateDer::from(cert_key.cert);
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert_key.key_pair.serialize_der()),
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        (
            Arc::new(server_cfg),
            TlsConnector::from(Arc::new(client_cfg)),
        )
    }

    async fn read_doh_test_request(
        tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Vec<u8> {
        let mut req = Vec::new();
        let mut buf = [0u8; 2048];
        let (head_end, body_len) = loop {
            let n = tls.read(&mut buf).await.unwrap();
            assert!(n > 0);
            req.extend_from_slice(&buf[..n]);
            if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = std::str::from_utf8(&req[..pos]).unwrap();
                let cl: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            v.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap();
                if req.len() >= pos + 4 + cl {
                    break (pos + 4, cl);
                }
            }
        };
        req[head_end..head_end + body_len].to_vec()
    }

    async fn write_doh_test_response(
        tls: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        wire_resp: &[u8],
    ) {
        let http_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            wire_resp.len()
        );
        tls.write_all(http_resp.as_bytes()).await.unwrap();
        tls.write_all(wire_resp).await.unwrap();
        tls.flush().await.unwrap();
        let _ = tls.shutdown().await;
    }

    #[tokio::test]
    async fn bound_doh_production_connector_rejects_untrusted_self_signed_cert() {
        let (server_cfg, _) = make_local_doh_tls_pair();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });

        let connector = build_bound_tls_connector().unwrap();
        let binder = NoopBinder;
        let query = encode_dns_query("untrusted.example", QTYPE_A).unwrap();
        let endpoint = format!("https://127.0.0.1:{}/dns-query", addr.port());
        let err = send_doh_bound_tls(&binder, &connector, &endpoint, &query)
            .await
            .expect_err("production bound DoH connector must reject untrusted self-signed cert");
        assert!(
            err.to_string().contains("TLS handshake failed"),
            "unexpected error: {err:#}"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn doh_servfail_does_not_trip_global_backoff() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    2, // SERVFAIL
                    &[],
                    0,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder)).unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.doh_endpoints = vec![format!("https://127.0.0.1:{}/dns-query", addr.port())];
        resolver.udp_dns_servers = Vec::new();

        assert!(resolver.resolve("servfail.example").await.is_err());
        assert!(
            !resolver.is_doh_in_backoff(),
            "single-domain DoH SERVFAIL must not trip global 30s DoH backoff"
        );

        let q = encode_dns_query("servfail-wire.example", QTYPE_A).unwrap();
        let (resp, meta) = resolver.resolve_wire_query(&q, true).await.unwrap();
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x000f, 2);
        assert!(meta.is_none());
        assert!(
            !resolver.is_doh_in_backoff(),
            "single-domain wire DoH SERVFAIL must not trip global 30s DoH backoff"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn doh_poisoned_reply_fails_over_to_healthy_endpoint() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let poisoned_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_cfg));
        let healthy_acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let poisoned_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let poisoned_addr = poisoned_listener.local_addr().unwrap();
        let healthy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy_addr = healthy_listener.local_addr().unwrap();

        let poisoned_task = tokio::spawn(async move {
            let (tcp, _) = poisoned_listener.accept().await.unwrap();
            let mut tls = poisoned_acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let parsed = parse_dns_question(&query).unwrap();
            let wire_resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &query[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(195, 175, 39, 39))],
                60,
            );
            write_doh_test_response(&mut tls, &wire_resp).await;
        });

        let healthy_task = tokio::spawn(async move {
            let (tcp, _) = healthy_listener.accept().await.unwrap();
            let mut tls = healthy_acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let parsed = parse_dns_question(&query).unwrap();
            let wire_resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &query[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                120,
            );
            write_doh_test_response(&mut tls, &wire_resp).await;
        });

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder)).unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.doh_endpoints = vec![
            format!("https://127.0.0.1:{}/dns-query", poisoned_addr.port()),
            format!("https://127.0.0.1:{}/dns-query", healthy_addr.port()),
        ];
        resolver.udp_dns_servers = Vec::new();

        let ips = resolver.resolve("clean.example").await.unwrap();
        poisoned_task.await.unwrap();
        healthy_task.await.unwrap();

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert!(!resolver.is_doh_in_backoff());
        assert_eq!(resolver.preferred_doh_idx.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn udp_query_randomizes_nonzero_txid_handles_v6_only_a_nodata_and_cname_ttl() {
        // CNAME TTL (40s) shorter than A TTL (300s) must be folded into min_ttl_secs.
        let q = encode_dns_query("cname-ttl.example", QTYPE_A).unwrap();
        let mut cname_resp = Vec::new();
        cname_resp.extend_from_slice(&[
            0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        ]);
        cname_resp.extend_from_slice(&q[12..]);
        cname_resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 40, 0x00, 0x02, 0xc0, 0x0c,
        ]);
        cname_resp.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        let (_, folded_ttl) = decode_dns_response(&cname_resp, QTYPE_A).unwrap();
        assert_eq!(folded_ttl, Duration::from_secs(40));

        // Genuine IPv6-only QTYPE_A NODATA reply over UDP must succeed with empty Vec and non-zero TXID.
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let nodata_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            assert_ne!(parsed.tx_id, 0, "outbound UDP DNS TXID must be non-zero");
            let resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &buf[12..parsed.question_end],
                0,
                &[],
                60,
            );
            udp_server.send_to(&resp, peer).await.unwrap();
        });

        let mut resolver = DnsResolver::new("127.0.0.1", 53, false, false).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];
        let outcome = resolver
            .query_udp_type("v6only.example", QTYPE_A)
            .await
            .unwrap();
        nodata_task.await.unwrap();
        match outcome {
            DnsOutcome::Records(ips, _) => assert!(ips.is_empty()),
            DnsOutcome::NxDomain(_) => panic!("expected empty NODATA for IPv6-only QTYPE_A"),
        }

        // query_udp_raw must reject TC=1 replies and fail over to the next UDP server.
        let tc_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tc_addr = tc_server.local_addr().unwrap();
        let ok_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = ok_server.local_addr().unwrap();

        let tc_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = tc_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            let mut resp = Vec::new();
            resp.extend_from_slice(&parsed.tx_id.to_be_bytes());
            resp.extend_from_slice(&0x8380u16.to_be_bytes()); // QR=1, TC=1
            resp.extend_from_slice(&1u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&buf[12..parsed.question_end]);
            tc_server.send_to(&resp, peer).await.unwrap();
        });
        let ok_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = ok_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &buf[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            ok_server.send_to(&resp, peer).await.unwrap();
        });

        resolver.udp_dns_servers = vec![tc_addr, ok_addr];
        resolver.preferred_udp_idx.store(0, Ordering::Relaxed);
        let raw = resolver.query_udp_raw(&q).await.unwrap();
        tc_task.await.unwrap();
        ok_task.await.unwrap();
        assert_eq!(u16::from_be_bytes([raw[2], raw[3]]) & 0x0200, 0);
        let (ips, _) = decode_dns_response(&raw, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }

    #[tokio::test]
    async fn resolve_via_udp_timeout_does_not_mark_aaaa_lookup_cached() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let Ok(Ok((n, peer))) =
                    tokio::time::timeout(Duration::from_secs(2), udp_server.recv_from(&mut buf))
                        .await
                else {
                    break;
                };
                let parsed = parse_dns_question(&buf[..n]).unwrap();
                if parsed.qtype == QTYPE_A {
                    let resp = build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &buf[12..parsed.question_end],
                        0,
                        &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                        300,
                    );
                    udp_server.send_to(&resp, peer).await.unwrap();
                }
            }
        });

        let mut resolver = DnsResolver::new("127.0.0.1", 53, false, false).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];
        let ips = resolver.resolve("slow-aaaa.example").await.unwrap();
        server_task.await.unwrap();

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        let guard = resolver.cache.read().await;
        let entry = guard.get("slow-aaaa.example").unwrap();
        assert!(entry.has_a_lookup);
        assert!(
            !entry.has_aaaa_lookup,
            "timed-out AAAA lookup must not be cached as completed"
        );
    }
}
