use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::RwLock;
use tracing::debug;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;
const QTYPE_HTTPS: u16 = 65;
const QCLASS_IN: u16 = 1;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_CACHED_IPS: usize = 32;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    nxdomain: bool,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
enum DnsOutcome {
    Records(Vec<IpAddr>, Duration),
    NxDomain(Duration),
}

#[derive(Clone)]
pub struct DnsResolver {
    enable_doh: bool,
    ipv4_only: bool,
    udp_dns_servers: Vec<SocketAddr>,
    doh_endpoints: Vec<String>,
    preferred_doh_idx: Arc<AtomicUsize>,
    preferred_udp_idx: Arc<AtomicUsize>,
    doh_backoff_until: Arc<RwLock<Option<Instant>>>,
    query_count: Arc<AtomicU64>,
    http: Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl DnsResolver {
    pub fn new(dns_addr: &str, dns_port: u16, enable_doh: bool, ipv4_only: bool) -> Result<Self> {
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

        let udp_dns_servers = build_udp_dns_servers(dns_addr, dns_port);
        let doh_endpoints = build_doh_endpoints(dns_addr);

        Ok(Self {
            enable_doh,
            ipv4_only,
            udp_dns_servers,
            doh_endpoints,
            preferred_doh_idx: Arc::new(AtomicUsize::new(0)),
            preferred_udp_idx: Arc::new(AtomicUsize::new(0)),
            doh_backoff_until: Arc::new(RwLock::new(None)),
            query_count: Arc::new(AtomicU64::new(0)),
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn query_count(&self) -> u64 {
        self.query_count.load(Ordering::Relaxed)
    }

    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
        *self.doh_backoff_until.write().await = None;
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

        // 3. mDNS (.local) via OS resolver (unfiltered because LAN IPs are expected)
        if normalized.ends_with(".local") {
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
                    if !entry.ips.is_empty() {
                        return Ok(DnsOutcome::Records(entry.ips.clone(), rem));
                    }
                }
            }
        }

        // 5. Multi-tier unpoisoned resolution:
        //    Tier A: RFC 8484 DNS-over-HTTPS (only transport failures trip the 30s circuit-breaker;
        //            protocol NXDOMAIN/NODATA replies return directly without DoH failover!)
        //    Tier B: Non-standard port 1253 / 443 / 5353 + backup UDP DNS
        //    Tier C: System resolver fallback (with sinkhole IP filtering)
        let doh_in_backoff = self
            .doh_backoff_until
            .read()
            .await
            .is_some_and(|until| Instant::now() < until);

        let outcome = if self.enable_doh && !doh_in_backoff {
            match self.resolve_via_doh(&normalized).await {
                Ok(DnsOutcome::NxDomain(ttl)) => DnsOutcome::NxDomain(ttl),
                Ok(DnsOutcome::Records(ips, ttl)) if !ips.is_empty() => {
                    DnsOutcome::Records(ips, ttl)
                }
                Ok(DnsOutcome::Records(_, ttl)) => DnsOutcome::Records(Vec::new(), ttl),
                Err(_) => {
                    *self.doh_backoff_until.write().await =
                        Some(Instant::now() + Duration::from_secs(30));
                    self.resolve_udp_or_system(&normalized).await?
                }
            }
        } else {
            self.resolve_udp_or_system(&normalized).await?
        };

        match &outcome {
            DnsOutcome::NxDomain(ttl) => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: Vec::new(),
                        nxdomain: true,
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
                        expires_at: Instant::now() + *ttl,
                    },
                );
            }
            _ => {}
        }

        Ok(outcome)
    }

    async fn resolve_udp_or_system(&self, domain: &str) -> Result<DnsOutcome> {
        match self.resolve_via_udp(domain).await {
            Ok(DnsOutcome::NxDomain(ttl)) => Ok(DnsOutcome::NxDomain(ttl)),
            Ok(DnsOutcome::Records(ips, ttl)) if !ips.is_empty() => {
                Ok(DnsOutcome::Records(ips, ttl))
            }
            _ => {
                let sys = self.resolve_via_system(domain, true).await?;
                Ok(DnsOutcome::Records(sys, Duration::from_secs(60)))
            }
        }
    }

    async fn resolve_via_doh(&self, domain: &str) -> Result<DnsOutcome> {
        if self.ipv4_only {
            return match self.query_doh_type(domain, QTYPE_A).await? {
                DnsOutcome::NxDomain(ttl) => Ok(DnsOutcome::NxDomain(ttl)),
                DnsOutcome::Records(ips, ttl) => {
                    Ok(DnsOutcome::Records(filter_poisoned_ips(ips), ttl))
                }
            };
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
        let mut v4_succeeded = false;
        let mut v4_nxdomain = false;
        let mut v6_nxdomain = false;

        match v4_res {
            Ok(DnsOutcome::NxDomain(ttl)) => {
                v4_succeeded = true;
                v4_nxdomain = true;
                min_ttl = min_ttl.min(ttl);
            }
            Ok(DnsOutcome::Records(v4, ttl)) => {
                v4_succeeded = true;
                let clean_v4 = filter_poisoned_ips(v4);
                if !clean_v4.is_empty() {
                    min_ttl = min_ttl.min(ttl);
                    ips.extend(clean_v4);
                }
            }
            Err(_) => {}
        }

        // CNAME-only empty AAAA responses (such as www.roblox.com) are normal and must never
        // discard valid IPv4 A records — and an empty AAAA response must never mask an A failure.
        match v6_res {
            Ok(Ok(DnsOutcome::NxDomain(ttl))) => {
                v6_nxdomain = true;
                min_ttl = min_ttl.min(ttl);
            }
            Ok(Ok(DnsOutcome::Records(v6, ttl))) => {
                let clean_v6 = filter_poisoned_ips(v6);
                if !clean_v6.is_empty() {
                    min_ttl = min_ttl.min(ttl);
                    for ip in clean_v6 {
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
            _ => {}
        }

        if !ips.is_empty() {
            return Ok(DnsOutcome::Records(ips, min_ttl));
        }
        if v4_nxdomain && (v6_nxdomain || ips.is_empty()) {
            return Ok(DnsOutcome::NxDomain(min_ttl.min(Duration::from_secs(30))));
        }
        if v4_succeeded {
            return Ok(DnsOutcome::Records(Vec::new(), min_ttl.min(Duration::from_secs(60))));
        }
        bail!("DoH transport failed for {domain}")
    }

    async fn query_doh_type(&self, domain: &str, qtype: u16) -> Result<DnsOutcome> {
        let wire_query = encode_dns_query(domain, qtype)?;
        let count = self.doh_endpoints.len();
        if count == 0 {
            bail!("no DoH endpoints configured");
        }

        // Fast-path: try the currently sticky healthy DoH endpoint first.
        let start = self.preferred_doh_idx.load(Ordering::Relaxed) % count;
        if let Ok(parsed) =
            send_doh_request(&self.http, &self.doh_endpoints[start], &wire_query, qtype).await
        {
            debug!(
                domain = %domain,
                qtype = qtype,
                endpoint = %self.doh_endpoints[start],
                "DoH query succeeded"
            );
            return Ok(parsed);
        }

        // Preferred DoH transport failed: race ALL remaining DoH endpoints concurrently.
        let mut join_set = tokio::task::JoinSet::new();
        for offset in 1..count {
            let idx = (start + offset) % count;
            let http = self.http.clone();
            let endpoint = self.doh_endpoints[idx].clone();
            let query = wire_query.clone();
            join_set.spawn(async move {
                let res = send_doh_request(&http, &endpoint, &query, qtype).await;
                (idx, endpoint, res)
            });
        }

        let mut last_err = None;
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
                    Err(e) => last_err = Some(e),
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no DoH endpoints reachable")))
    }

    async fn resolve_via_udp(&self, domain: &str) -> Result<DnsOutcome> {
        if self.ipv4_only {
            return self.query_udp_type(domain, QTYPE_A).await;
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
        let mut nxdomain = false;

        if let Ok(outcome) = v4_res {
            match outcome {
                DnsOutcome::NxDomain(ttl) => {
                    nxdomain = true;
                    min_ttl = min_ttl.min(ttl);
                }
                DnsOutcome::Records(v4, ttl) => {
                    min_ttl = min_ttl.min(ttl);
                    ips.extend(v4);
                }
            }
        }
        if let Ok(Ok(DnsOutcome::Records(v6, ttl))) = v6_res {
            min_ttl = min_ttl.min(ttl);
            for ip in v6 {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        if !ips.is_empty() {
            Ok(DnsOutcome::Records(ips, min_ttl))
        } else if nxdomain {
            Ok(DnsOutcome::NxDomain(min_ttl.min(Duration::from_secs(30))))
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
            match send_udp_dns_raw(server, &wire_query).await {
                Ok(buf) => match decode_dns_outcome(&buf, qtype) {
                    Ok(DnsOutcome::NxDomain(ttl)) => {
                        if offset > 0 {
                            self.preferred_udp_idx.store(idx, Ordering::Relaxed);
                        }
                        return Ok(DnsOutcome::NxDomain(ttl));
                    }
                    Ok(DnsOutcome::Records(ips, ttl)) => {
                        let clean = filter_poisoned_ips(ips);
                        let is_tc =
                            buf.len() >= 4 && (u16::from_be_bytes([buf[2], buf[3]]) & 0x0200) != 0;
                        if !clean.is_empty() || (qtype == QTYPE_AAAA && !is_tc) {
                            if offset > 0 && !clean.is_empty() {
                                self.preferred_udp_idx.store(idx, Ordering::Relaxed);
                            }
                            return Ok(DnsOutcome::Records(clean, ttl));
                        }
                        last_err = Some(anyhow!("UDP DNS {server} returned poisoned/empty reply"));
                    }
                    Err(e) => last_err = Some(e),
                },
                Err(e) => last_err = Some(e),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("UDP DNS resolution failed for {domain}")))
    }

    async fn resolve_via_system(&self, domain: &str, filter_poison: bool) -> Result<Vec<IpAddr>> {
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

        // Suppress HTTPS/SVCB (type 65) records when QUIC blocking is enabled so browsers and apps
        // don't receive HTTP/3 Alt-Svc hints that bypass TCP TLS desync.
        if block_https_svcb && parsed.qtype == QTYPE_HTTPS {
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

            match self.resolve_outcome(&parsed.qname, true).await {
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
        let doh_in_backoff = self
            .doh_backoff_until
            .read()
            .await
            .is_some_and(|until| Instant::now() < until);

        if self.enable_doh && !doh_in_backoff {
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
        if let Ok(bytes) =
            send_doh_request_raw(&self.http, &self.doh_endpoints[start], &normalized_query).await
        {
            return Ok(bytes);
        }
        for offset in 1..count.min(3) {
            let idx = (start + offset) % count;
            if let Ok(bytes) =
                send_doh_request_raw(&self.http, &self.doh_endpoints[idx], &normalized_query).await
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
            if let Ok(bytes) = send_udp_dns_raw(self.udp_dns_servers[idx], wire_query).await {
                return Ok(bytes);
            }
        }
        bail!("raw UDP DNS query failed")
    }
}

async fn send_udp_dns_raw(server: SocketAddr, wire_query: &[u8]) -> Result<Vec<u8>> {
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    sock.connect(server).await?;
    sock.send(wire_query).await?;
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_millis(1000), sock.recv(&mut buf))
        .await
        .map_err(|_| anyhow!("UDP DNS timeout from {server}"))??;
    Ok(buf[..n].to_vec())
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
        // TTL alone doesn't cap a burst of unique answers, all of which may be fresh.
        if let Some(victim) = cache.keys().next().cloned() {
            cache.remove(&victim);
        }
    }
    cache.insert(key, entry);
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
    endpoint: &str,
    wire_query: &[u8],
    qtype: u16,
) -> Result<DnsOutcome> {
    let bytes = send_doh_request_raw(http, endpoint, wire_query).await?;
    decode_dns_outcome(&bytes, qtype)
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
                    [195, 175, 39, 39]
                        | [195, 175, 39, 40]
                        | [195, 175, 39, 49]
                        | [195, 175, 39, 50]
                )
        }
        IpAddr::V6(v6) => v6.is_unspecified() || v6.is_loopback(),
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
    if buf.len() < 12 {
        bail!("DNS response shorter than 12-byte header");
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if (flags & 0x8000) == 0 {
        bail!("DNS packet does not have QR response bit set");
    }
    let truncated = (flags & 0x0200) != 0;
    let rcode = flags & 0x000f;
    if rcode == 3 {
        if truncated {
            bail!("DNS response truncated (TC=1)");
        }
        return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
    }
    if rcode != 0 {
        bail!("DNS response returned RCODE {rcode}");
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 4 > buf.len() {
            bail!("truncated DNS question section");
        }
        pos += 4;
    }

    let mut ips = Vec::new();
    let mut min_ttl_secs: Option<u64> = None;

    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            bail!("truncated DNS resource record header");
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let ttl =
            u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]) as u64;
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlength > buf.len() {
            bail!("truncated DNS resource record rdata");
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
        } else if rtype == QTYPE_CNAME {
            // Gracefully skip CNAME chains (including CNAME-only NODATA AAAA responses)
        }

        pos += rdlength;
    }

    if truncated && ips.is_empty() {
        bail!("DNS response truncated (TC=1) with no matching answers");
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

    #[test]
    fn dns_cache_is_bounded_even_when_every_answer_is_fresh() {
        let mut cache = HashMap::new();
        let entry = CacheEntry {
            ips: vec![Ipv4Addr::LOCALHOST.into()],
            nxdomain: false,
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

        let mut https_query = encode_dns_query("discord.com", QTYPE_HTTPS).unwrap();
        https_query[0] = 0x12;
        https_query[1] = 0x34;
        let (https_resp, https_meta) = resolver
            .resolve_wire_query(&https_query, true)
            .await
            .unwrap();
        assert_eq!(&https_resp[0..2], &[0x12, 0x34]);
        assert_eq!(u16::from_be_bytes([https_resp[6], https_resp[7]]), 0);
        assert!(https_meta.is_none());
        assert!(resolver.query_count() >= 2);
    }

    #[test]
    fn decodes_nxdomain_distinctly_rejects_qr1_and_formats_ipv6_doh() {
        let mut nx_resp = vec![
            0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        nx_resp.extend_from_slice(&encode_dns_query("does-not-exist.invalid", QTYPE_A).unwrap()[12..]);
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
        let outcome = resolver.resolve_via_udp("example.com").await.unwrap();
        tc_task.await.unwrap();
        ok_task.await.unwrap();

        match outcome {
            DnsOutcome::Records(ips, _) => {
                assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
            }
            DnsOutcome::NxDomain(_) => panic!("expected A record after TC=1 fallback"),
        }
    }
}
