use crate::binder::OutboundBinder;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpSocket, UdpSocket};
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::debug;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_SOA: u16 = 6;
const QTYPE_AAAA: u16 = 28;
const QTYPE_SVCB: u16 = 64;
const QTYPE_HTTPS: u16 = 65;
const QTYPE_ANY: u16 = 255;
const QCLASS_IN: u16 = 1;
const MAX_CACHE_ENTRIES: usize = 4096;
const MAX_CACHED_IPS: usize = 32;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;
const MAX_BOUND_DOH_HEADER_BYTES: usize = 16 * 1024;
const MAX_BOUND_DOH_RAW_BYTES: usize = MAX_DNS_MESSAGE_BYTES + MAX_BOUND_DOH_HEADER_BYTES;
const MAX_DOH_FAILOVER_CONCURRENCY: usize = 2;
const DOH_FAILURE_THRESHOLD: usize = 3;
const DOH_BACKOFF_SECS: u64 = 5;
const BOUND_DOH_TOTAL_TIMEOUT: Duration = Duration::from_millis(1800);
const DOH_RING_MAX_WAIT: Duration = Duration::from_millis(3400);
const DOH_RAW_MAX_WAIT: Duration = Duration::from_millis(3400);
const AAAA_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(30);
const UDP_DPI_RACE_GRACE_MS: u64 = 120;
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
    aaaa_retry_after: Option<Instant>,
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
    SinkholeRejected { endpoint: String },
}

fn is_failover_protocol_rcode(rcode: u16) -> bool {
    matches!(rcode, 2 | 5)
}

impl std::fmt::Display for DohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(err) => {
                let redacted = redact_urls_in_text(&err.to_string());
                write!(f, "DoH transport error: {redacted}")
            }
            Self::ProtocolError { endpoint, rcode } => write!(
                f,
                "DoH returned DNS protocol error (RCODE {rcode}) from {}",
                redact_dns_for_display(endpoint)
            ),
            Self::SinkholeRejected { endpoint } => write!(
                f,
                "DoH returned poisoned/sinkhole IP from {}",
                redact_dns_for_display(endpoint)
            ),
        }
    }
}

type DohAttemptResult = (usize, String, std::result::Result<DnsOutcome, DohError>);

fn doh_http_client_builder() -> reqwest::ClientBuilder {
    // `.no_proxy()` prevents vdpi from routing its own DoH traffic through itself
    // when HTTP_PROXY / HTTPS_PROXY environment variables are active.
    // HTTP/2 + TCP keepalives detect half-open desktop/NAT sockets promptly instead of
    // hanging multiplexed DoH streams for repeated 2s timeouts. On mobile (Android/iOS),
    // disable idle HTTP/2 keepalive pings so cellular modems can return to RRC_IDLE.
    let builder = Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(2000))
        .connect_timeout(Duration::from_millis(1200))
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .tcp_nodelay(true)
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .http2_keep_alive_interval(Some(Duration::from_secs(20)))
        .http2_keep_alive_timeout(Duration::from_secs(5));
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.http2_keep_alive_while_idle(false);
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder.http2_keep_alive_while_idle(true);
    builder
}

fn build_doh_http_client() -> Result<Client> {
    doh_http_client_builder()
        .build()
        .context("failed to build DoH HTTP client")
}

fn build_pinned_doh_http_client(
    host: &str,
    addrs: &[SocketAddr],
    #[cfg(test)] extra_root_cert_der: Option<&[u8]>,
) -> Result<Client> {
    // Disable redirects so a custom DoH server can never redirect onto an unbootstrapped
    // hostname and trigger an OS GaiResolver lookup inside TUN mode.
    #[cfg_attr(not(test), allow(unused_mut))]
    let mut builder = doh_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, addrs);
    #[cfg(test)]
    if let Some(der) = extra_root_cert_der {
        let cert = reqwest::Certificate::from_der(der)
            .context("failed to parse test DoH root certificate")?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .context("failed to build bootstrapped DoH HTTP client")
}

struct CustomHostnameDohState {
    ips: Vec<IpAddr>,
    expires_at: Instant,
    pinned_http: Option<Client>,
    last_failed_at: Option<Instant>,
}

struct CustomHostnameDoh {
    request_url: String,
    host: String,
    port: u16,
    host_header: String,
    path_and_query: String,
    state: RwLock<CustomHostnameDohState>,
    bootstrap_lock: tokio::sync::Mutex<()>,
}

impl CustomHostnameDoh {
    fn new(
        request_url: String,
        host: String,
        port: u16,
        host_header: String,
        path_and_query: String,
    ) -> Self {
        Self {
            request_url,
            host,
            port,
            host_header,
            path_and_query,
            state: RwLock::new(CustomHostnameDohState {
                ips: Vec::new(),
                expires_at: Instant::now(),
                pinned_http: None,
                last_failed_at: None,
            }),
            bootstrap_lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn clear(&self) {
        let mut guard = self.state.write().await;
        guard.ips.clear();
        guard.expires_at = Instant::now();
        guard.pinned_http = None;
        guard.last_failed_at = None;
    }

    async fn record_transport_failure(&self) {
        let mut guard = self.state.write().await;
        guard.ips.clear();
        guard.expires_at = Instant::now();
        guard.pinned_http = None;
        guard.last_failed_at = Some(Instant::now());
    }
}

#[derive(Clone)]
pub struct DnsResolver {
    enable_doh: bool,
    ipv4_only: Arc<AtomicBool>,
    disable_system_dns_fallback: bool,
    udp_dns_servers: Vec<SocketAddr>,
    doh_endpoints: Vec<String>,
    custom_primary_doh_endpoint: Option<String>,
    custom_doh: Option<Arc<CustomHostnameDoh>>,
    custom_udp_primary: Option<SocketAddr>,
    user_custom_udp_server: Option<SocketAddr>,
    preferred_doh_idx: Arc<AtomicUsize>,
    preferred_udp_idx: Arc<AtomicUsize>,
    doh_backoff_until_ms: Arc<AtomicU64>,
    doh_consecutive_failures: Arc<AtomicUsize>,
    query_count: Arc<AtomicU64>,
    http: Arc<std::sync::RwLock<Client>>,
    outbound_binder: Option<Arc<dyn OutboundBinder>>,
    bound_tls_connector: Option<TlsConnector>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    #[cfg(test)]
    test_root_cert_der: Option<Vec<u8>>,
    #[cfg(test)]
    test_port53_servers: Vec<SocketAddr>,
    #[cfg(test)]
    test_force_system_dns_error: bool,
}

impl DnsResolver {
    pub fn new(dns_addr: &str, dns_port: u16, enable_doh: bool, ipv4_only: bool) -> Result<Self> {
        Self::new_with_options(dns_addr, dns_port, enable_doh, ipv4_only, false, None)
    }

    pub fn new_with_binder(
        dns_addr: impl AsRef<str>,
        dns_port: u16,
        enable_doh: bool,
        ipv4_only: bool,
        outbound_binder: Option<Arc<dyn OutboundBinder>>,
    ) -> Result<Self> {
        Self::new_with_options(
            dns_addr,
            dns_port,
            enable_doh,
            ipv4_only,
            false,
            outbound_binder,
        )
    }

    pub fn new_with_options(
        dns_addr: impl AsRef<str>,
        dns_port: u16,
        enable_doh: bool,
        ipv4_only: bool,
        disable_system_dns_fallback: bool,
        outbound_binder: Option<Arc<dyn OutboundBinder>>,
    ) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let http = build_doh_http_client()?;

        let bound_tls_connector = if outbound_binder.is_some() {
            Some(build_bound_tls_connector()?)
        } else {
            None
        };

        let dns_addr = dns_addr.as_ref();
        let trimmed_dns = dns_addr.trim();
        let parsed_explicit_doh = parse_doh_url_validated(trimmed_dns).ok();
        let effective_doh = effective_enable_doh(trimmed_dns, enable_doh);
        let effective_port = if dns_port == 0 { 53 } else { dns_port };
        let bare_custom_ip = if parsed_explicit_doh.is_none() {
            parse_bare_dns_ip(trimmed_dns)
        } else {
            None
        };
        let custom_udp_primary = bare_custom_ip
            .filter(|ip| !is_known_public_doh_ip(*ip))
            .map(|ip| SocketAddr::new(ip, effective_port));
        let user_custom_udp_server = bare_custom_ip
            .filter(|ip| !is_unfiltered_default_dns_ip(*ip))
            .map(|ip| SocketAddr::new(ip, effective_port));

        // Always build the full dual-stack UDP and DoH endpoint lists so `set_ipv4_only(false)`
        // can dynamically enable IPv6 endpoints after uplink detection without rebuilding the resolver.
        let udp_dns_servers = build_udp_dns_servers(dns_addr, dns_port, false);
        let require_ip_literal = disable_system_dns_fallback || outbound_binder.is_some();
        let doh_endpoints = build_doh_endpoints(
            dns_addr,
            outbound_binder.is_some(),
            require_ip_literal,
            false,
        );
        let custom_primary_doh_endpoint = if let Some(ref parsed) = parsed_explicit_doh {
            match parsed.host {
                DohHost::Ip(_) => Some(parsed.request_url.clone()),
                DohHost::Domain(_) => None,
            }
        } else {
            bare_custom_ip
                .filter(|ip| is_known_public_doh_ip(*ip) && !is_unfiltered_default_dns_ip(*ip))
                .map(|ip| match ip {
                    IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
                    IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
                })
        };
        let custom_doh = parsed_explicit_doh.and_then(|parsed| match parsed.host {
            DohHost::Domain(host) => Some(Arc::new(CustomHostnameDoh::new(
                parsed.request_url,
                host,
                parsed.port,
                parsed.host_header,
                parsed.path_and_query,
            ))),
            DohHost::Ip(_) => None,
        });

        Ok(Self {
            enable_doh: effective_doh,
            ipv4_only: Arc::new(AtomicBool::new(ipv4_only)),
            disable_system_dns_fallback,
            udp_dns_servers,
            doh_endpoints,
            custom_primary_doh_endpoint,
            custom_doh,
            custom_udp_primary,
            user_custom_udp_server,
            preferred_doh_idx: Arc::new(AtomicUsize::new(0)),
            preferred_udp_idx: Arc::new(AtomicUsize::new(0)),
            doh_backoff_until_ms: Arc::new(AtomicU64::new(0)),
            doh_consecutive_failures: Arc::new(AtomicUsize::new(0)),
            query_count: Arc::new(AtomicU64::new(0)),
            http: Arc::new(std::sync::RwLock::new(http)),
            outbound_binder,
            bound_tls_connector,
            cache: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(test)]
            test_root_cert_der: None,
            #[cfg(test)]
            test_port53_servers: Vec::new(),
            #[cfg(test)]
            test_force_system_dns_error: false,
        })
    }

    pub fn set_ipv4_only(&self, ipv4_only: bool) {
        self.ipv4_only.store(ipv4_only, Ordering::Release);
    }

    pub fn is_ipv4_only(&self) -> bool {
        self.ipv4_only.load(Ordering::Acquire)
    }

    fn endpoint_allows_sinkhole(&self, endpoint: &str) -> bool {
        self.custom_primary_doh_endpoint
            .as_deref()
            .is_some_and(|primary| primary == endpoint)
            || is_filtering_doh_endpoint(endpoint)
    }

    fn udp_server_allows_sinkhole_and_loopback(&self, server: SocketAddr) -> bool {
        self.user_custom_udp_server
            .is_some_and(|custom| custom == server)
            || is_filtering_dns_ip(server.ip())
    }

    fn active_custom_udp_primary(&self) -> Option<SocketAddr> {
        let primary = self.custom_udp_primary?;
        if self.is_ipv4_only() && primary.is_ipv6() {
            return None;
        }
        if !self.udp_dns_servers.contains(&primary) {
            return None;
        }
        Some(primary)
    }

    fn eligible_doh_indices(&self, ip_literal_only: bool) -> Vec<usize> {
        let v4_only = self.is_ipv4_only();
        self.doh_endpoints
            .iter()
            .enumerate()
            .filter(|(_, ep)| {
                (!ip_literal_only || is_ip_literal_doh_endpoint(ep))
                    && (!v4_only || !is_ipv6_doh_endpoint(ep))
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn eligible_udp_indices(&self) -> Vec<usize> {
        let v4_only = self.is_ipv4_only();
        self.udp_dns_servers
            .iter()
            .enumerate()
            .filter(|(_, sa)| !v4_only || sa.is_ipv4())
            .map(|(i, _)| i)
            .collect()
    }

    #[cfg(test)]
    fn is_udp_port53(&self, server: SocketAddr) -> bool {
        server.port() == 53 || self.test_port53_servers.contains(&server)
    }

    #[cfg(not(test))]
    fn is_udp_port53(&self, server: SocketAddr) -> bool {
        server.port() == 53
    }

    fn maybe_promote_udp_server(&self, idx: usize) {
        let Some(candidate) = self.udp_dns_servers.get(idx) else {
            return;
        };
        if self.is_udp_port53(*candidate) {
            let is_user_primary = idx == 0 && self.user_custom_udp_server == Some(*candidate);
            let has_eligible_non53 = self
                .eligible_udp_indices()
                .into_iter()
                .any(|i| !self.is_udp_port53(self.udp_dns_servers[i]));
            if !is_user_primary && has_eligible_non53 {
                return;
            }
        }
        self.preferred_udp_idx.store(idx, Ordering::Relaxed);
    }

    fn is_system_dns_disabled(&self) -> bool {
        self.disable_system_dns_fallback || self.outbound_binder.is_some()
    }

    fn should_route_to_system_resolver(
        &self,
        normalized: &str,
        disable_system_fallback: bool,
    ) -> bool {
        !(disable_system_fallback || self.is_system_dns_disabled())
            && is_lan_or_private_hostname(normalized)
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
        self.doh_consecutive_failures.store(0, Ordering::Relaxed);
    }

    fn record_doh_success(&self) {
        self.doh_consecutive_failures.store(0, Ordering::Relaxed);
    }

    fn record_doh_transport_failure(&self) -> bool {
        let failures = self
            .doh_consecutive_failures
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        if failures >= DOH_FAILURE_THRESHOLD {
            self.doh_consecutive_failures.store(0, Ordering::Relaxed);
            self.set_doh_backoff(Duration::from_secs(DOH_BACKOFF_SECS));
            true
        } else {
            false
        }
    }

    fn http_client(&self) -> Client {
        self.http
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
        self.clear_doh_backoff();
        self.preferred_doh_idx.store(0, Ordering::Relaxed);
        self.preferred_udp_idx.store(0, Ordering::Relaxed);
        if let Some(custom) = &self.custom_doh {
            custom.clear().await;
        }
        // Rebuild the pooled HTTP/2 client on route change / wake so dead half-open
        // connections from the previous network path are evicted immediately.
        if let Ok(fresh) = build_doh_http_client() {
            *self
                .http
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
        }
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

        // 2. Localhost fast-path (RFC 6761 §6.3: localhost and *.localhost)
        if normalized == "localhost" || normalized.ends_with(".localhost") {
            let ips = if self.is_ipv4_only() {
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            } else {
                vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ]
            };
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(300)));
        }

        // 3. mDNS / Corporate Active Directory (.local):
        //    - Check the TTL cache first so subsequent connections to corporate AD `.local`
        //      hostnames cached from `active_custom_udp_primary()` never re-pay OS mDNS timeouts.
        //    - In TUN mode / when system DNS fallback is disabled: if an explicit custom bare-IP
        //      UDP server (e.g. corporate --dns 10.0.0.53) is configured, query it directly and
        //      cache the answer; otherwise return synthetic NXDOMAIN to prevent OS DNS recursion.
        //    - In Proxy mode: try the OS resolver first (unfiltered because LAN IPs are expected);
        //      if OS resolution fails and `active_custom_udp_primary()` is configured, fall back
        //      to querying that server directly (never public DoH) and cache successful answers.
        if normalized.ends_with(".local") {
            if let Some(cached) = self.lookup_cache_outcome(&normalized).await {
                return Ok(cached);
            }
            if self.is_system_dns_disabled() {
                if let Some(custom_udp) = self.active_custom_udp_primary() {
                    debug!(
                        domain = %normalized,
                        server = %custom_udp,
                        "TUN mode .local hostname; querying custom bare-IP UDP server directly"
                    );
                    let resolved = self
                        .resolve_via_single_udp_server(custom_udp, &normalized)
                        .await?;
                    self.store_cache_resolved(normalized, &resolved).await;
                    return Ok(resolved.outcome);
                }
                return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
            }
            match self.resolve_via_system(&normalized, false).await {
                Ok(ips) => return Ok(DnsOutcome::Records(ips, Duration::from_secs(60))),
                Err(sys_err) => {
                    if let Some(custom_udp) = self.active_custom_udp_primary() {
                        debug!(
                            domain = %normalized,
                            server = %custom_udp,
                            error = %sys_err,
                            "system DNS failed for .local hostname; falling back to custom bare-IP UDP server"
                        );
                        let resolved = self
                            .resolve_via_single_udp_server(custom_udp, &normalized)
                            .await?;
                        if matches!(
                            resolved.outcome,
                            DnsOutcome::Records(ref ips, _) if !ips.is_empty()
                        ) {
                            self.store_cache_resolved(normalized, &resolved).await;
                        }
                        return Ok(resolved.outcome);
                    }
                    return Err(sys_err);
                }
            }
        }

        // 3b. Single-label LAN hostnames and private/local suffixes (*.lan, *.home.arpa,
        //     *.internal, *.localdomain, *.ts.net) route to the OS resolver in Proxy mode
        //     instead of leaking internal names to public DoH. When OS resolution fails and
        //     an explicit custom bare-IP UDP server (e.g. corporate --dns 10.0.0.53) is
        //     configured, fall back to querying that server directly (never public DoH).
        if self.should_route_to_system_resolver(&normalized, false) {
            match self.resolve_via_system(&normalized, false).await {
                Ok(ips) => return Ok(DnsOutcome::Records(ips, Duration::from_secs(60))),
                Err(sys_err) => {
                    if let Some(custom_udp) = self.active_custom_udp_primary() {
                        debug!(
                            domain = %normalized,
                            server = %custom_udp,
                            error = %sys_err,
                            "system DNS failed for LAN/private hostname; falling back to custom bare-IP UDP server"
                        );
                        let resolved = self
                            .resolve_via_single_udp_server(custom_udp, &normalized)
                            .await?;
                        return Ok(resolved.outcome);
                    }
                    return Err(sys_err);
                }
            }
        }

        // 4. In-memory TTL cache lookup (including negative NXDOMAIN cache)
        if let Some(cached) = self.lookup_cache_outcome(&normalized).await {
            return Ok(cached);
        }

        // 5. Multi-tier unpoisoned resolution:
        //    Tier 0 (when user configured a custom/corporate bare IP without known IP-SAN DoH,
        //            e.g. 76.76.2.0 or 10.0.0.53): query that server over UDP first.
        //    Tier A: RFC 8484 DNS-over-HTTPS (only consecutive full-ring transport failures trip
        //            the short 5s circuit-breaker; single-provider failover and protocol
        //            NXDOMAIN/NODATA/SERVFAIL replies never trip DoH backoff!)
        //    Tier B: Non-standard port 1253 / 443 / 5353 + backup UDP DNS
        //    Tier C: System resolver fallback (with sinkhole IP filtering; skipped in TUN mode)
        let resolved = if let Some(primary) = self.active_custom_udp_primary() {
            match self.resolve_via_single_udp_server(primary, &normalized).await {
                Ok(resolved) => resolved,
                Err(cause) => {
                    debug!(
                        domain = %normalized,
                        server = %primary,
                        error = %cause,
                        "custom bare-IP UDP DNS failed; falling back to DoH/backup ring"
                    );
                    self.resolve_doh_or_udp_or_system(&normalized, Some(primary))
                        .await?
                }
            }
        } else {
            self.resolve_doh_or_udp_or_system(&normalized, None).await?
        };

        self.store_cache_resolved(normalized, &resolved).await;

        Ok(resolved.outcome)
    }

    async fn resolve_doh_or_udp_or_system(
        &self,
        normalized: &str,
        skip_udp_server: Option<SocketAddr>,
    ) -> Result<ResolvedOutcome> {
        if self.enable_doh && !self.is_doh_in_backoff() {
            match self.resolve_via_doh(normalized).await {
                Ok(resolved) => {
                    self.record_doh_success();
                    Ok(resolved)
                }
                Err(DohError::ProtocolError { endpoint, rcode })
                    if is_failover_protocol_rcode(rcode) =>
                {
                    let redacted = redact_dns_for_display(&endpoint);
                    debug!(
                        domain = %normalized,
                        endpoint = %redacted,
                        rcode = rcode,
                        "all DoH endpoints returned SERVFAIL/REFUSED; falling back to non-port-53 UDP without tripping DoH backoff"
                    );
                    let err = DohError::ProtocolError { endpoint, rcode };
                    self.resolve_via_udp_filtered(normalized, skip_udp_server, true)
                        .await
                        .map_err(|_| anyhow!("{err} for {normalized}"))
                }
                Err(err @ (DohError::ProtocolError { .. } | DohError::SinkholeRejected { .. })) => {
                    debug!(
                        domain = %normalized,
                        error = %err,
                        "DoH returned DNS-level rejection; failing without UDP fallback"
                    );
                    bail!("{err} for {normalized}");
                }
                Err(DohError::Transport(cause)) => {
                    let redacted_cause = redact_urls_in_text(&cause.to_string());
                    if self.record_doh_transport_failure() {
                        debug!(
                            domain = %normalized,
                            error = %redacted_cause,
                            backoff_secs = DOH_BACKOFF_SECS,
                            "all DoH endpoints failed transport consecutively; tripping short backoff"
                        );
                    } else {
                        debug!(
                            domain = %normalized,
                            error = %redacted_cause,
                            "transient DoH transport failure; keeping DoH active"
                        );
                    }
                    self.resolve_udp_or_system_excluding(normalized, skip_udp_server)
                        .await
                }
            }
        } else {
            self.resolve_udp_or_system_excluding(normalized, skip_udp_server)
                .await
        }
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
        let no_system_fallback = disable_system_fallback || self.is_system_dns_disabled();
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

        // 2. Localhost fast-path (RFC 6761 §6.3: localhost and *.localhost)
        if normalized == "localhost" || normalized.ends_with(".localhost") {
            let ips = match qtype {
                QTYPE_A => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                QTYPE_AAAA if !self.is_ipv4_only() => vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
                _ => Vec::new(),
            };
            return Ok(DnsOutcome::Records(ips, Duration::from_secs(300)));
        }

        // 3. mDNS / Corporate Active Directory (.local):
        //    - Check the TTL cache first so subsequent connections to corporate AD `.local`
        //      hostnames cached from `active_custom_udp_primary()` never re-pay OS mDNS timeouts.
        //    - In TUN mode / when system DNS fallback is disabled: if an explicit custom bare-IP
        //      UDP server (e.g. corporate --dns 10.0.0.53) is configured, query it directly and
        //      cache the answer; otherwise return synthetic NXDOMAIN to prevent OS DNS recursion.
        //    - In Proxy mode: try the OS resolver first; if OS resolution fails and
        //      `active_custom_udp_primary()` is configured, fall back to querying that server
        //      directly (never public DoH) and cache successful answers.
        if normalized.ends_with(".local") {
            if let Some(cached) = self.lookup_cache_qtype(&normalized, qtype).await {
                return Ok(cached);
            }
            if no_system_fallback {
                if let Some(custom_udp) = self.active_custom_udp_primary() {
                    debug!(
                        domain = %normalized,
                        qtype = qtype,
                        server = %custom_udp,
                        "TUN mode .local hostname; querying custom bare-IP UDP server directly"
                    );
                    let outcome = self
                        .query_single_udp_server_type(custom_udp, &normalized, qtype)
                        .await?;
                    self.store_cache_qtype(normalized, qtype, &outcome).await;
                    return Ok(outcome);
                }
                return Ok(DnsOutcome::NxDomain(Duration::from_secs(30)));
            }
            match self.resolve_via_system(&normalized, false).await {
                Ok(sys_ips) => {
                    let ips: Vec<IpAddr> = sys_ips
                        .into_iter()
                        .filter(|ip| match qtype {
                            QTYPE_A => ip.is_ipv4(),
                            QTYPE_AAAA => ip.is_ipv6(),
                            _ => false,
                        })
                        .collect();
                    return Ok(DnsOutcome::Records(ips, Duration::from_secs(60)));
                }
                Err(sys_err) => {
                    if let Some(custom_udp) = self.active_custom_udp_primary() {
                        debug!(
                            domain = %normalized,
                            qtype = qtype,
                            server = %custom_udp,
                            error = %sys_err,
                            "system DNS failed for .local hostname; falling back to custom bare-IP UDP server"
                        );
                        let outcome = self
                            .query_single_udp_server_type(custom_udp, &normalized, qtype)
                            .await?;
                        if matches!(outcome, DnsOutcome::Records(_, _)) {
                            self.store_cache_qtype(normalized, qtype, &outcome).await;
                        }
                        return Ok(outcome);
                    }
                    return Err(sys_err);
                }
            }
        }

        // 3b. Single-label LAN hostnames and private/local suffixes via OS resolver in Proxy mode.
        //     When OS resolution fails and an explicit custom bare-IP UDP server (e.g. corporate
        //     --dns 10.0.0.53) is configured, fall back to querying that server directly.
        if self.should_route_to_system_resolver(&normalized, disable_system_fallback) {
            match self.resolve_via_system(&normalized, false).await {
                Ok(sys_ips) => {
                    let ips: Vec<IpAddr> = sys_ips
                        .into_iter()
                        .filter(|ip| match qtype {
                            QTYPE_A => ip.is_ipv4(),
                            QTYPE_AAAA => ip.is_ipv6(),
                            _ => false,
                        })
                        .collect();
                    return Ok(DnsOutcome::Records(ips, Duration::from_secs(60)));
                }
                Err(sys_err) => {
                    if let Some(custom_udp) = self.active_custom_udp_primary() {
                        debug!(
                            domain = %normalized,
                            qtype = qtype,
                            server = %custom_udp,
                            error = %sys_err,
                            "system DNS failed for LAN/private hostname; falling back to custom bare-IP UDP server"
                        );
                        return self
                            .query_single_udp_server_type(custom_udp, &normalized, qtype)
                            .await;
                    }
                    return Err(sys_err);
                }
            }
        }

        // 4. In-memory TTL cache lookup respecting per-family coverage
        if let Some(cached) = self.lookup_cache_qtype(&normalized, qtype).await {
            return Ok(cached);
        }

        // 5. Query ONLY the requested qtype so `QTYPE_A` never stalls waiting on `QTYPE_AAAA`.
        let outcome = if let Some(primary) = self.active_custom_udp_primary() {
            match self
                .query_single_udp_server_type(primary, &normalized, qtype)
                .await
            {
                Ok(outcome) => outcome,
                Err(cause) => {
                    debug!(
                        domain = %normalized,
                        qtype = qtype,
                        server = %primary,
                        error = %cause,
                        "custom bare-IP UDP DNS failed; falling back to DoH/backup ring"
                    );
                    self.resolve_doh_or_udp_or_system_type(
                        &normalized,
                        qtype,
                        no_system_fallback,
                        Some(primary),
                    )
                    .await?
                }
            }
        } else {
            self.resolve_doh_or_udp_or_system_type(&normalized, qtype, no_system_fallback, None)
                .await?
        };

        // 6. Merge result into shared TTL cache while preserving IPv4-first ordering
        self.store_cache_qtype(normalized, qtype, &outcome).await;

        Ok(outcome)
    }

    async fn lookup_cache_outcome(&self, normalized: &str) -> Option<DnsOutcome> {
        let guard = self.cache.read().await;
        let entry = guard.get(normalized)?;
        let now = Instant::now();
        if now >= entry.expires_at {
            return None;
        }
        let rem = entry.expires_at.saturating_duration_since(now);
        if entry.nxdomain {
            return Some(DnsOutcome::NxDomain(rem));
        }
        let ipv4_only = self.is_ipv4_only();
        let aaaa_satisfied = ipv4_only
            || entry.has_aaaa_lookup
            || entry.aaaa_retry_after.is_some_and(|until| now < until);
        if entry.has_a_lookup && aaaa_satisfied && !entry.ips.is_empty() {
            let ips: Vec<IpAddr> = if ipv4_only {
                entry.ips.iter().copied().filter(IpAddr::is_ipv4).collect()
            } else {
                entry.ips.clone()
            };
            if !ips.is_empty() {
                return Some(DnsOutcome::Records(ips, rem));
            }
        }
        None
    }

    async fn store_cache_resolved(&self, normalized: String, resolved: &ResolvedOutcome) {
        match &resolved.outcome {
            DnsOutcome::NxDomain(ttl) if !ttl.is_zero() => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: Vec::new(),
                        nxdomain: true,
                        has_a_lookup: true,
                        has_aaaa_lookup: true,
                        aaaa_retry_after: None,
                        expires_at: Instant::now() + (*ttl).min(Duration::from_secs(60)),
                    },
                );
            }
            DnsOutcome::Records(ips, ttl) if !ips.is_empty() && ips.len() <= MAX_CACHED_IPS => {
                let now = Instant::now();
                let aaaa_retry_after =
                    if !self.is_ipv4_only() && resolved.has_a_lookup && !resolved.has_aaaa_lookup {
                        Some(now + AAAA_TIMEOUT_COOLDOWN)
                    } else {
                        None
                    };
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: ips.clone(),
                        nxdomain: false,
                        has_a_lookup: resolved.has_a_lookup,
                        has_aaaa_lookup: resolved.has_aaaa_lookup,
                        aaaa_retry_after,
                        expires_at: now + *ttl,
                    },
                );
            }
            _ => {}
        }
    }

    async fn lookup_cache_qtype(&self, normalized: &str, qtype: u16) -> Option<DnsOutcome> {
        let guard = self.cache.read().await;
        let entry = guard.get(normalized)?;
        let now = Instant::now();
        if now >= entry.expires_at {
            return None;
        }
        let rem = entry.expires_at.saturating_duration_since(now);
        if entry.nxdomain {
            return Some(DnsOutcome::NxDomain(rem));
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
                return Some(DnsOutcome::Records(matching, rem));
            }
        }
        None
    }

    async fn store_cache_qtype(&self, normalized: String, qtype: u16, outcome: &DnsOutcome) {
        match outcome {
            DnsOutcome::NxDomain(ttl) if !ttl.is_zero() => {
                let mut guard = self.cache.write().await;
                insert_cache_entry(
                    &mut guard,
                    normalized,
                    CacheEntry {
                        ips: Vec::new(),
                        nxdomain: true,
                        has_a_lookup: true,
                        has_aaaa_lookup: true,
                        aaaa_retry_after: None,
                        expires_at: Instant::now() + (*ttl).min(Duration::from_secs(60)),
                    },
                );
            }
            DnsOutcome::Records(ips, ttl)
                if (!ips.is_empty() || (qtype == QTYPE_AAAA && !ttl.is_zero()))
                    && ips.len() <= MAX_CACHED_IPS =>
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
                        let has_aaaa_lookup = existing.has_aaaa_lookup || qtype == QTYPE_AAAA;
                        Some(CacheEntry {
                            ips: combined,
                            nxdomain: false,
                            has_a_lookup: existing.has_a_lookup || qtype == QTYPE_A,
                            has_aaaa_lookup,
                            aaaa_retry_after: if has_aaaa_lookup {
                                None
                            } else {
                                existing.aaaa_retry_after
                            },
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
                    has_aaaa_lookup: qtype == QTYPE_AAAA,
                    aaaa_retry_after: None,
                    expires_at: now + effective_ttl,
                });
                insert_cache_entry(&mut guard, normalized, entry);
            }
            _ => {}
        }
    }

    async fn resolve_doh_or_udp_or_system_type(
        &self,
        normalized: &str,
        qtype: u16,
        no_system_fallback: bool,
        skip_udp_server: Option<SocketAddr>,
    ) -> Result<DnsOutcome> {
        if self.enable_doh && !self.is_doh_in_backoff() {
            match self.query_doh_type(normalized, qtype).await {
                Ok(outcome) => {
                    self.record_doh_success();
                    Ok(outcome)
                }
                Err(DohError::ProtocolError { endpoint, rcode })
                    if is_failover_protocol_rcode(rcode) =>
                {
                    let redacted = redact_dns_for_display(&endpoint);
                    debug!(
                        domain = %normalized,
                        qtype = qtype,
                        endpoint = %redacted,
                        rcode = rcode,
                        "all DoH endpoints returned SERVFAIL/REFUSED; falling back to non-port-53 UDP without tripping DoH backoff"
                    );
                    let err = DohError::ProtocolError { endpoint, rcode };
                    self.query_udp_type_filtered(normalized, qtype, skip_udp_server, true)
                        .await
                        .map_err(|_| anyhow!("{err} for {normalized}"))
                }
                Err(err @ (DohError::ProtocolError { .. } | DohError::SinkholeRejected { .. })) => {
                    debug!(
                        domain = %normalized,
                        qtype = qtype,
                        error = %err,
                        "DoH returned DNS-level rejection; failing without UDP fallback"
                    );
                    bail!("{err} for {normalized}");
                }
                Err(DohError::Transport(cause)) => {
                    let redacted_cause = redact_urls_in_text(&cause.to_string());
                    if self.record_doh_transport_failure() {
                        debug!(
                            domain = %normalized,
                            qtype = qtype,
                            error = %redacted_cause,
                            backoff_secs = DOH_BACKOFF_SECS,
                            "all DoH endpoints failed transport consecutively; tripping short backoff"
                        );
                    } else {
                        debug!(
                            domain = %normalized,
                            qtype = qtype,
                            error = %redacted_cause,
                            "transient DoH transport failure; keeping DoH active"
                        );
                    }
                    self.resolve_udp_or_system_type_excluding(
                        normalized,
                        qtype,
                        no_system_fallback,
                        skip_udp_server,
                    )
                    .await
                }
            }
        } else {
            self.resolve_udp_or_system_type_excluding(
                normalized,
                qtype,
                no_system_fallback,
                skip_udp_server,
            )
            .await
        }
    }

    #[cfg(test)]
    async fn resolve_udp_or_system(&self, domain: &str) -> Result<ResolvedOutcome> {
        self.resolve_udp_or_system_excluding(domain, None).await
    }

    async fn resolve_udp_or_system_excluding(
        &self,
        domain: &str,
        skip_udp_server: Option<SocketAddr>,
    ) -> Result<ResolvedOutcome> {
        match self.resolve_via_udp_excluding(domain, skip_udp_server).await {
            Ok(resolved) => match &resolved.outcome {
                DnsOutcome::NxDomain(_) => Ok(resolved),
                DnsOutcome::Records(ips, _) if !ips.is_empty() => Ok(resolved),
                DnsOutcome::Records(_, _) if self.is_system_dns_disabled() => {
                    bail!("UDP DNS returned no records for {domain} (system DNS disabled)")
                }
                DnsOutcome::Records(_, _) => {
                    let sys = self.resolve_via_system(domain, true).await?;
                    Ok(ResolvedOutcome {
                        outcome: DnsOutcome::Records(sys, Duration::from_secs(60)),
                        has_a_lookup: true,
                        has_aaaa_lookup: !self.is_ipv4_only(),
                    })
                }
            },
            Err(e) if self.is_system_dns_disabled() => Err(e),
            Err(_) => {
                let sys = self.resolve_via_system(domain, true).await?;
                Ok(ResolvedOutcome {
                    outcome: DnsOutcome::Records(sys, Duration::from_secs(60)),
                    has_a_lookup: true,
                    has_aaaa_lookup: !self.is_ipv4_only(),
                })
            }
        }
    }

    async fn resolve_udp_or_system_type_excluding(
        &self,
        domain: &str,
        qtype: u16,
        disable_system_fallback: bool,
        skip_udp_server: Option<SocketAddr>,
    ) -> Result<DnsOutcome> {
        let no_system = disable_system_fallback || self.is_system_dns_disabled();
        match self
            .query_udp_type_excluding(domain, qtype, skip_udp_server)
            .await
        {
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
        if self.is_ipv4_only() {
            let outcome = self.query_doh_type(domain, QTYPE_A).await?;
            let is_nx = matches!(outcome, DnsOutcome::NxDomain(_));
            return Ok(ResolvedOutcome {
                outcome,
                has_a_lookup: true,
                has_aaaa_lookup: is_nx,
            });
        }

        let (v4_res, v6_res) = join_a_and_aaaa(
            Box::pin(self.query_doh_type(domain, QTYPE_A)),
            Box::pin(self.query_doh_type(domain, QTYPE_AAAA)),
            Duration::from_millis(700),
            |res| matches!(res, Ok(DnsOutcome::Records(ips, _)) if !ips.is_empty()),
            |res| matches!(res, Ok(DnsOutcome::NxDomain(_))),
        )
        .await;

        let mut ips = Vec::new();
        let mut min_ttl = Duration::from_secs(300);
        let mut has_a_lookup = false;
        let mut has_aaaa_lookup = false;
        let mut v4_nxdomain = false;
        let mut protocol_err: Option<DohError> = None;
        let mut sinkhole_err: Option<DohError> = None;

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
            Err(err @ DohError::SinkholeRejected { .. }) => {
                sinkhole_err = Some(err);
            }
            Err(DohError::Transport(_)) => {}
        }

        // CNAME-only empty AAAA responses (such as www.roblox.com) are normal and must never
        // discard valid IPv4 A records — and an empty AAAA response must never mask an A failure.
        match v6_res {
            Some(Ok(DnsOutcome::NxDomain(ttl))) => {
                has_aaaa_lookup = true;
                min_ttl = min_ttl.min(ttl);
            }
            Some(Ok(DnsOutcome::Records(v6, ttl))) => {
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
            Some(Err(err @ DohError::ProtocolError { .. })) if protocol_err.is_none() => {
                protocol_err = Some(err);
            }
            Some(Err(err @ DohError::SinkholeRejected { .. })) if sinkhole_err.is_none() => {
                sinkhole_err = Some(err);
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
        if let Some(err) = sinkhole_err {
            return Err(err);
        }
        Err(DohError::Transport(anyhow!(
            "DoH transport failed for {domain}"
        )))
    }

    fn spawn_doh_attempt(
        &self,
        join_set: &mut tokio::task::JoinSet<DohAttemptResult>,
        idx: usize,
        wire_query: &[u8],
        qtype: u16,
        require_ip_literal: bool,
    ) {
        let http = self.http_client();
        let outbound_binder = self.outbound_binder.clone();
        let bound_tls = self.bound_tls_connector.clone();
        let endpoint = self.doh_endpoints[idx].clone();
        let allow_sinkhole = self.endpoint_allows_sinkhole(&endpoint);
        let query = wire_query.to_vec();
        join_set.spawn(async move {
            let res = send_doh_request(
                &http,
                outbound_binder.as_deref(),
                bound_tls.as_ref(),
                &endpoint,
                &query,
                qtype,
                require_ip_literal,
                allow_sinkhole,
            )
            .await;
            (idx, endpoint, res)
        });
    }

    async fn bootstrap_custom_doh_host(
        &self,
        custom: &CustomHostnameDoh,
    ) -> Result<(Vec<IpAddr>, Duration)> {
        let mut ips = Vec::new();
        let mut min_ttl = Duration::from_secs(300);

        // Tier 1: Bootstrap via IP-literal DoH endpoints ONLY (never via custom_doh itself
        // and never via OS DNS) so hostname-based DoH cannot deadlock on itself.
        if let Ok(wire_a) = encode_dns_query(&custom.host, QTYPE_A) {
            if self.is_ipv4_only() {
                if let Ok(DnsOutcome::Records(v4, ttl)) = self
                    .query_doh_ring_type(&custom.host, &wire_a, QTYPE_A, true)
                    .await
                {
                    if !v4.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        ips.extend(v4);
                    }
                }
            } else if let Ok(wire_aaaa) = encode_dns_query(&custom.host, QTYPE_AAAA) {
                let (v4_res, v6_res) = join_a_and_aaaa(
                    Box::pin(self.query_doh_ring_type(&custom.host, &wire_a, QTYPE_A, true)),
                    Box::pin(self.query_doh_ring_type(&custom.host, &wire_aaaa, QTYPE_AAAA, true)),
                    Duration::from_millis(700),
                    |res| matches!(res, Ok(DnsOutcome::Records(v4, _)) if !v4.is_empty()),
                    |res| matches!(res, Ok(DnsOutcome::NxDomain(_))),
                )
                .await;
                if let Ok(DnsOutcome::Records(v4, ttl)) = v4_res {
                    if !v4.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        ips.extend(v4);
                    }
                }
                if let Some(Ok(DnsOutcome::Records(v6, ttl))) = v6_res {
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

        // Tier 2: IP-literal UDP DNS fallback (still zero OS DNS recursion).
        if ips.is_empty() {
            if let Ok(resolved) = self.resolve_via_udp(&custom.host).await {
                if let DnsOutcome::Records(udp_ips, ttl) = resolved.outcome {
                    if !udp_ips.is_empty() {
                        min_ttl = min_ttl.min(ttl);
                        ips = udp_ips;
                    }
                }
            }
        }

        // Tier 3: OS resolver fallback ONLY when system DNS fallback is permitted (proxy mode).
        if ips.is_empty() && !self.is_system_dns_disabled() {
            if let Ok(sys_ips) = self.resolve_via_system(&custom.host, true).await {
                if !sys_ips.is_empty() {
                    min_ttl = Duration::from_secs(60);
                    ips = sys_ips;
                }
            }
        }

        if self.is_ipv4_only() {
            ips.retain(IpAddr::is_ipv4);
        }
        ips.retain(|ip| validate_dns_ip_addr(*ip).is_ok());

        if ips.is_empty() {
            bail!(
                "failed to bootstrap custom DoH host '{}' via bootstrap DNS",
                custom.host
            );
        }

        Ok((
            ips,
            min_ttl.clamp(Duration::from_secs(60), Duration::from_secs(3600)),
        ))
    }

    async fn ensure_custom_doh_bootstrapped(
        &self,
        custom: &CustomHostnameDoh,
    ) -> Result<(Vec<IpAddr>, Option<Client>)> {
        {
            let guard = custom.state.read().await;
            if !guard.ips.is_empty() && Instant::now() < guard.expires_at {
                return Ok((guard.ips.clone(), guard.pinned_http.clone()));
            }
            if guard
                .last_failed_at
                .is_some_and(|t| t.elapsed() < Duration::from_secs(DOH_BACKOFF_SECS))
            {
                bail!("custom DoH '{}' in short failure cooldown", custom.host);
            }
        }

        let _singleflight = custom.bootstrap_lock.lock().await;
        {
            let guard = custom.state.read().await;
            if !guard.ips.is_empty() && Instant::now() < guard.expires_at {
                return Ok((guard.ips.clone(), guard.pinned_http.clone()));
            }
            if guard
                .last_failed_at
                .is_some_and(|t| t.elapsed() < Duration::from_secs(DOH_BACKOFF_SECS))
            {
                bail!("custom DoH '{}' in short failure cooldown", custom.host);
            }
        }

        let (ips, ttl) = match self.bootstrap_custom_doh_host(custom).await {
            Ok(res) => res,
            Err(err) => {
                custom.record_transport_failure().await;
                return Err(err);
            }
        };

        let pinned_http = if self.outbound_binder.is_none() {
            let addrs: Vec<SocketAddr> = ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, custom.port))
                .collect();
            Some(build_pinned_doh_http_client(
                &custom.host,
                &addrs,
                #[cfg(test)]
                self.test_root_cert_der.as_deref(),
            )?)
        } else {
            None
        };

        debug!(
            host = %custom.host,
            ips = ?ips,
            ttl_secs = ttl.as_secs(),
            "bootstrapped custom DoH hostname"
        );

        let mut guard = custom.state.write().await;
        guard.ips = ips.clone();
        guard.expires_at = Instant::now() + ttl;
        guard.pinned_http = pinned_http.clone();
        guard.last_failed_at = None;
        Ok((ips, pinned_http))
    }

    async fn send_custom_doh_wire(
        &self,
        custom: &CustomHostnameDoh,
        wire_query: &[u8],
    ) -> Result<Vec<u8>> {
        let (ips, pinned_http) = self.ensure_custom_doh_bootstrapped(custom).await?;
        let ipv4_only = self.is_ipv4_only();
        let v4_filtered: Vec<IpAddr> = if ipv4_only {
            ips.iter().copied().filter(IpAddr::is_ipv4).collect()
        } else {
            Vec::new()
        };

        let result = if ipv4_only && v4_filtered.is_empty() {
            Err(anyhow!(
                "no IPv4 addresses available for custom DoH host '{}' while ipv4_only is active",
                custom.host
            ))
        } else if let (Some(binder), Some(connector)) = (
            self.outbound_binder.as_deref(),
            self.bound_tls_connector.as_ref(),
        ) {
            let server_name = ServerName::try_from(custom.host.clone())
                .map_err(|_| anyhow!("invalid TLS SNI hostname '{}'", custom.host))?;
            let mut last_err = None;
            let mut ok_bytes = None;
            let candidates = select_dual_stack_candidates(if ipv4_only {
                &v4_filtered
            } else {
                &ips
            });
            for ip in candidates {
                let target = BoundDohTarget {
                    addr: SocketAddr::new(ip, custom.port),
                    host_header: custom.host_header.clone(),
                    path: custom.path_and_query.clone(),
                    server_name: server_name.clone(),
                };
                match send_doh_bound_tls_target(
                    binder,
                    connector,
                    &target,
                    &custom.request_url,
                    wire_query,
                )
                .await
                {
                    Ok(bytes) => {
                        ok_bytes = Some(bytes);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            ok_bytes.ok_or_else(|| {
                last_err.unwrap_or_else(|| anyhow!("bound custom DoH failed for {}", custom.host))
            })
        } else {
            let effective_ips: &[IpAddr] = if ipv4_only { &v4_filtered } else { &ips };
            let client = match pinned_http {
                Some(c) if !(ipv4_only && ips.iter().any(IpAddr::is_ipv6)) => c,
                _ => {
                    let addrs: Vec<SocketAddr> = effective_ips
                        .iter()
                        .map(|ip| SocketAddr::new(*ip, custom.port))
                        .collect();
                    build_pinned_doh_http_client(
                        &custom.host,
                        &addrs,
                        #[cfg(test)]
                        self.test_root_cert_der.as_deref(),
                    )?
                }
            };
            send_doh_request_pinned(&client, &custom.request_url, wire_query).await
        };

        if result.is_err() {
            custom.record_transport_failure().await;
        }
        result
    }

    async fn query_custom_doh_type(
        &self,
        custom: &CustomHostnameDoh,
        domain: &str,
        wire_query: &[u8],
        qtype: u16,
    ) -> std::result::Result<DnsOutcome, DohError> {
        let bytes = self
            .send_custom_doh_wire(custom, wire_query)
            .await
            .map_err(DohError::Transport)?;
        let outcome = classify_doh_wire_reply(&bytes, qtype, &custom.request_url, true)?;
        let redacted = redact_dns_for_display(&custom.request_url);
        debug!(
            domain = %domain,
            qtype = qtype,
            endpoint = %redacted,
            "custom bootstrapped DoH query succeeded"
        );
        Ok(outcome)
    }

    async fn query_doh_type(
        &self,
        domain: &str,
        qtype: u16,
    ) -> std::result::Result<DnsOutcome, DohError> {
        let wire_query = encode_dns_query(domain, qtype).map_err(DohError::Transport)?;

        // When a custom hostname DoH URL is configured (e.g. https://dns.nextdns.io/abc123),
        // resolve its host via our IP-literal bootstrap ring first and connect over a pinned or
        // socket-bound TLS channel. Never query the custom endpoint to resolve its own hostname.
        if let Some(custom) = &self.custom_doh {
            if !domain.eq_ignore_ascii_case(&custom.host) {
                match self
                    .query_custom_doh_type(custom, domain, &wire_query, qtype)
                    .await
                {
                    Ok(outcome) => return Ok(outcome),
                    Err(DohError::ProtocolError { endpoint, rcode })
                        if is_failover_protocol_rcode(rcode) =>
                    {
                        let redacted = redact_dns_for_display(&endpoint);
                        debug!(
                            domain = %domain,
                            qtype = qtype,
                            endpoint = %redacted,
                            rcode = rcode,
                            "custom hostname DoH returned SERVFAIL/REFUSED; failing over to IP-literal DoH ring"
                        );
                    }
                    Err(
                        err @ (DohError::ProtocolError { .. } | DohError::SinkholeRejected { .. }),
                    ) => {
                        return Err(err);
                    }
                    Err(DohError::Transport(cause)) => {
                        let redacted = redact_dns_for_display(&custom.request_url);
                        let redacted_cause = redact_urls_in_text(&cause.to_string());
                        debug!(
                            domain = %domain,
                            qtype = qtype,
                            endpoint = %redacted,
                            error = %redacted_cause,
                            "custom hostname DoH failed; falling back to IP-literal DoH ring"
                        );
                    }
                }
            }
        }

        self.query_doh_ring_type(domain, &wire_query, qtype, self.custom_doh.is_some())
            .await
    }

    async fn query_doh_ring_type(
        &self,
        domain: &str,
        wire_query: &[u8],
        qtype: u16,
        ip_literal_only: bool,
    ) -> std::result::Result<DnsOutcome, DohError> {
        let eligible = self.eligible_doh_indices(ip_literal_only);
        let count = eligible.len();
        if count == 0 {
            return Err(DohError::Transport(anyhow!("no DoH endpoints configured")));
        }

        let deadline = tokio::time::Instant::now() + DOH_RING_MAX_WAIT;
        let mut protocol_err: Option<DohError> = None;
        let mut sinkhole_err: Option<DohError> = None;
        let mut last_transport_err: Option<anyhow::Error> = None;
        let require_ip_literal = ip_literal_only || self.is_system_dns_disabled();

        // Fast-path: try the currently sticky healthy DoH endpoint first.
        let pref = self.preferred_doh_idx.load(Ordering::Relaxed);
        let start_pos = eligible.iter().position(|&idx| idx == pref).unwrap_or(0);
        let start_idx = eligible[start_pos];
        let start_allow_sinkhole = self.endpoint_allows_sinkhole(&self.doh_endpoints[start_idx]);
        let http = self.http_client();
        let first_res = match tokio::time::timeout_at(
            deadline,
            send_doh_request(
                &http,
                self.outbound_binder.as_deref(),
                self.bound_tls_connector.as_ref(),
                &self.doh_endpoints[start_idx],
                wire_query,
                qtype,
                require_ip_literal,
                start_allow_sinkhole,
            ),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(DohError::Transport(anyhow!(
                "DoH ring query budget exceeded for {domain}"
            ))),
        };
        match first_res {
            Ok(parsed) => {
                let redacted = redact_dns_for_display(&self.doh_endpoints[start_idx]);
                debug!(
                    domain = %domain,
                    qtype = qtype,
                    endpoint = %redacted,
                    "DoH query succeeded"
                );
                return Ok(parsed);
            }
            Err(DohError::ProtocolError { endpoint, rcode }) => {
                let err = DohError::ProtocolError { endpoint, rcode };
                if start_allow_sinkhole && !is_failover_protocol_rcode(rcode) {
                    return Err(err);
                }
                protocol_err = Some(err);
            }
            Err(err @ DohError::SinkholeRejected { .. }) => {
                sinkhole_err = Some(err);
            }
            Err(DohError::Transport(err)) => {
                last_transport_err = Some(err);
            }
        }

        // Preferred DoH endpoint failed: race remaining endpoints with bounded concurrency
        // (at most MAX_DOH_FAILOVER_CONCURRENCY = 2 in flight per query) and within the
        // ring budget so concurrent bursts cannot exhaust tight mobile FD limits and UDP
        // fallback still fits inside TUN's 5s window.
        let mut remaining_indices = (1..count).map(|offset| eligible[(start_pos + offset) % count]);
        let mut join_set: tokio::task::JoinSet<DohAttemptResult> = tokio::task::JoinSet::new();
        if tokio::time::Instant::now() < deadline {
            for _ in 0..MAX_DOH_FAILOVER_CONCURRENCY {
                let Some(idx) = remaining_indices.next() else {
                    break;
                };
                self.spawn_doh_attempt(&mut join_set, idx, wire_query, qtype, require_ip_literal);
            }
        }

        while !join_set.is_empty() {
            let joined = match tokio::time::timeout_at(deadline, join_set.join_next()).await {
                Ok(Some(joined)) => joined,
                Ok(None) => break,
                Err(_) => {
                    join_set.abort_all();
                    last_transport_err.get_or_insert_with(|| {
                        anyhow!("DoH ring query budget exceeded for {domain}")
                    });
                    break;
                }
            };
            if let Ok((idx, endpoint, res)) = joined {
                match res {
                    Ok(parsed) => {
                        self.preferred_doh_idx.store(idx, Ordering::Relaxed);
                        join_set.abort_all();
                        let redacted = redact_dns_for_display(&endpoint);
                        debug!(
                            domain = %domain,
                            qtype = qtype,
                            endpoint = %redacted,
                            "DoH failover succeeded and promoted endpoint"
                        );
                        return Ok(parsed);
                    }
                    Err(err @ DohError::ProtocolError { .. }) => {
                        if protocol_err.is_none() {
                            protocol_err = Some(err);
                        }
                    }
                    Err(err @ DohError::SinkholeRejected { .. }) => {
                        if sinkhole_err.is_none() {
                            sinkhole_err = Some(err);
                        }
                    }
                    Err(DohError::Transport(e)) => last_transport_err = Some(e),
                }
            }
            if tokio::time::Instant::now() < deadline {
                if let Some(next_idx) = remaining_indices.next() {
                    self.spawn_doh_attempt(
                        &mut join_set,
                        next_idx,
                        wire_query,
                        qtype,
                        require_ip_literal,
                    );
                }
            }
        }

        if let Some(err) = protocol_err {
            return Err(err);
        }
        if let Some(err) = sinkhole_err {
            return Err(err);
        }

        Err(DohError::Transport(
            last_transport_err.unwrap_or_else(|| anyhow!("no DoH endpoints reachable")),
        ))
    }

    async fn resolve_via_single_udp_server(
        &self,
        server: SocketAddr,
        domain: &str,
    ) -> Result<ResolvedOutcome> {
        if self.is_ipv4_only() {
            let outcome = self
                .query_single_udp_server_type(server, domain, QTYPE_A)
                .await?;
            let is_nx = matches!(outcome, DnsOutcome::NxDomain(_));
            return Ok(ResolvedOutcome {
                outcome,
                has_a_lookup: true,
                has_aaaa_lookup: is_nx,
            });
        }
        let (v4_res, v6_res) = join_a_and_aaaa(
            Box::pin(self.query_single_udp_server_type(server, domain, QTYPE_A)),
            Box::pin(self.query_single_udp_server_type(server, domain, QTYPE_AAAA)),
            Duration::from_millis(800),
            |res| matches!(res, Ok(DnsOutcome::Records(ips, _)) if !ips.is_empty()),
            |res| matches!(res, Ok(DnsOutcome::NxDomain(_))),
        )
        .await;
        combine_udp_v4_v6_results(domain, v4_res, v6_res)
    }

    async fn resolve_via_udp(&self, domain: &str) -> Result<ResolvedOutcome> {
        self.resolve_via_udp_excluding(domain, None).await
    }

    async fn resolve_via_udp_excluding(
        &self,
        domain: &str,
        skip_server: Option<SocketAddr>,
    ) -> Result<ResolvedOutcome> {
        self.resolve_via_udp_filtered(domain, skip_server, false)
            .await
    }

    async fn resolve_via_udp_filtered(
        &self,
        domain: &str,
        skip_server: Option<SocketAddr>,
        non_port53_only: bool,
    ) -> Result<ResolvedOutcome> {
        if self.is_ipv4_only() {
            let outcome = self
                .query_udp_type_filtered(domain, QTYPE_A, skip_server, non_port53_only)
                .await?;
            let is_nx = matches!(outcome, DnsOutcome::NxDomain(_));
            return Ok(ResolvedOutcome {
                outcome,
                has_a_lookup: true,
                has_aaaa_lookup: is_nx,
            });
        }
        let (v4_res, v6_res) = join_a_and_aaaa(
            Box::pin(self.query_udp_type_filtered(domain, QTYPE_A, skip_server, non_port53_only)),
            Box::pin(self.query_udp_type_filtered(
                domain,
                QTYPE_AAAA,
                skip_server,
                non_port53_only,
            )),
            Duration::from_millis(800),
            |res| matches!(res, Ok(DnsOutcome::Records(ips, _)) if !ips.is_empty()),
            |res| matches!(res, Ok(DnsOutcome::NxDomain(_))),
        )
        .await;
        combine_udp_v4_v6_results(domain, v4_res, v6_res)
    }

    async fn query_single_udp_server_type(
        &self,
        server: SocketAddr,
        domain: &str,
        qtype: u16,
    ) -> Result<DnsOutcome> {
        let wire_query = encode_dns_query(domain, qtype)?;
        match self
            .query_udp_server_once(server, &wire_query, qtype, false)
            .await
        {
            Ok(outcome) => Ok(outcome),
            Err(UdpServerError::UntrustedNegative { outcome, .. }) => Ok(outcome),
            Err(err) => Err(err.into_anyhow()),
        }
    }

    async fn query_udp_server_once(
        &self,
        server: SocketAddr,
        wire_query: &[u8],
        qtype: u16,
        prior_poisoned: bool,
    ) -> std::result::Result<DnsOutcome, UdpServerError> {
        let trust_filtering = self.udp_server_allows_sinkhole_and_loopback(server);
        let untrusted_port53 = self.is_udp_port53(server) && !trust_filtering;
        let mut suspect_negative: Option<DnsOutcome> = None;
        let mut saw_poisoned_ip = false;

        let res = send_udp_dns_matching(
            server,
            wire_query,
            self.outbound_binder.as_deref(),
            |resp, saw_poisoned_on_socket| {
                let saw_poisoned = prior_poisoned || saw_poisoned_on_socket;
                match decode_dns_outcome(resp, qtype) {
                    Ok(DnsOutcome::NxDomain(ttl)) => {
                        if untrusted_port53 {
                            if !saw_poisoned_ip && suspect_negative.is_none() {
                                suspect_negative = Some(DnsOutcome::NxDomain(Duration::ZERO));
                            }
                            UdpReplyDecision::PoisonedWaitForRace(anyhow!(
                                "untrusted port-53 UDP DNS {server} returned immediate NXDOMAIN"
                            ))
                        } else {
                            let effective_ttl = if should_cache_udp_negative(
                                server,
                                trust_filtering,
                                saw_poisoned,
                            ) {
                                ttl
                            } else {
                                Duration::ZERO
                            };
                            UdpReplyDecision::Accept(DnsOutcome::NxDomain(effective_ttl))
                        }
                    }
                    Ok(DnsOutcome::Records(ips, ttl)) => {
                        let had_ips = !ips.is_empty();
                        let clean = filter_poisoned_udp_ips(ips, trust_filtering);
                        let is_tc =
                            resp.len() >= 4 && (u16::from_be_bytes([resp[2], resp[3]]) & 0x0200) != 0;
                        if had_ips && clean.is_empty() {
                            saw_poisoned_ip = true;
                            suspect_negative = None;
                            UdpReplyDecision::PoisonedWaitForRace(anyhow!(
                                "UDP DNS {server} returned only poisoned/sinkhole IPs"
                            ))
                        } else if !clean.is_empty() {
                            UdpReplyDecision::Accept(DnsOutcome::Records(clean, ttl))
                        } else if !is_tc {
                            if untrusted_port53 {
                                if !saw_poisoned_ip && suspect_negative.is_none() {
                                    suspect_negative =
                                        Some(DnsOutcome::Records(Vec::new(), Duration::ZERO));
                                }
                                UdpReplyDecision::PoisonedWaitForRace(anyhow!(
                                    "untrusted port-53 UDP DNS {server} returned empty NODATA"
                                ))
                            } else {
                                let effective_ttl = if should_cache_udp_negative(
                                    server,
                                    trust_filtering,
                                    saw_poisoned,
                                ) {
                                    ttl
                                } else {
                                    Duration::ZERO
                                };
                                UdpReplyDecision::Accept(DnsOutcome::Records(clean, effective_ttl))
                            }
                        } else {
                            UdpReplyDecision::Reject(anyhow!(
                                "UDP DNS {server} returned truncated reply"
                            ))
                        }
                    }
                    Err(e) => UdpReplyDecision::Reject(e),
                }
            },
        )
        .await;

        match res {
            Ok(outcome) => Ok(outcome),
            Err(UdpServerError::Poisoned(err)) => {
                if let Some(outcome) = suspect_negative {
                    Err(UdpServerError::UntrustedNegative { outcome, err })
                } else {
                    Err(UdpServerError::Poisoned(err))
                }
            }
            Err(other) => Err(other),
        }
    }

    #[cfg(test)]
    async fn query_udp_type(&self, domain: &str, qtype: u16) -> Result<DnsOutcome> {
        self.query_udp_type_excluding(domain, qtype, None).await
    }

    async fn query_udp_type_excluding(
        &self,
        domain: &str,
        qtype: u16,
        skip_server: Option<SocketAddr>,
    ) -> Result<DnsOutcome> {
        self.query_udp_type_filtered(domain, qtype, skip_server, false)
            .await
    }

    async fn query_udp_type_filtered(
        &self,
        domain: &str,
        qtype: u16,
        skip_server: Option<SocketAddr>,
        non_port53_only: bool,
    ) -> Result<DnsOutcome> {
        let wire_query = encode_dns_query(domain, qtype)?;
        let eligible: Vec<usize> = self
            .eligible_udp_indices()
            .into_iter()
            .filter(|&idx| {
                let sa = self.udp_dns_servers[idx];
                skip_server != Some(sa) && (!non_port53_only || !self.is_udp_port53(sa))
            })
            .collect();
        let count = eligible.len();
        if count == 0 {
            bail!("no UDP DNS servers configured");
        }

        let pref = self.preferred_udp_idx.load(Ordering::Relaxed);
        let start_pos = eligible.iter().position(|&idx| idx == pref).unwrap_or(0);
        let mut last_err = None;
        let mut saw_poisoned = false;
        let mut pending_untrusted_negative: Option<DnsOutcome> = None;

        for offset in 0..count {
            let idx = eligible[(start_pos + offset) % count];
            let server = self.udp_dns_servers[idx];
            match self
                .query_udp_server_once(server, &wire_query, qtype, saw_poisoned)
                .await
            {
                Ok(DnsOutcome::NxDomain(ttl)) => {
                    if offset > 0 && !ttl.is_zero() {
                        self.maybe_promote_udp_server(idx);
                    }
                    return Ok(DnsOutcome::NxDomain(ttl));
                }
                Ok(DnsOutcome::Records(ips, ttl)) => {
                    if offset > 0 && !ips.is_empty() {
                        self.maybe_promote_udp_server(idx);
                    }
                    return Ok(DnsOutcome::Records(ips, ttl));
                }
                Err(UdpServerError::UntrustedNegative { outcome, err }) => {
                    saw_poisoned = true;
                    let has_remaining_non53 = ((offset + 1)..count).any(|next_offset| {
                        let next_idx = eligible[(start_pos + next_offset) % count];
                        !self.is_udp_port53(self.udp_dns_servers[next_idx])
                    });
                    if !has_remaining_non53 {
                        return Ok(outcome);
                    }
                    pending_untrusted_negative.get_or_insert(outcome);
                    last_err = Some(err);
                }
                Err(err) => {
                    if err.is_poisoned() {
                        saw_poisoned = true;
                    }
                    last_err = Some(err.into_anyhow());
                }
            }
        }

        if let Some(outcome) = pending_untrusted_negative {
            return Ok(outcome);
        }

        Err(last_err.unwrap_or_else(|| anyhow!("UDP DNS resolution failed for {domain}")))
    }

    async fn resolve_via_system(&self, domain: &str, filter_poison: bool) -> Result<Vec<IpAddr>> {
        if self.is_system_dns_disabled() {
            bail!("system DNS lookup disabled (TUN recursion guard)");
        }
        #[cfg(test)]
        if self.test_force_system_dns_error {
            bail!("simulated system DNS lookup failure for {domain}");
        }
        let addrs = lookup_host((domain, 443u16))
            .await
            .with_context(|| format!("system DNS lookup failed for {domain}"))?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let ipv4_only = self.is_ipv4_only();
        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(ip) => {
                    let addr = IpAddr::V4(ip);
                    if (!filter_poison || !is_poisoned_public_ip(addr)) && !v4.contains(&addr) {
                        v4.push(addr);
                    }
                }
                IpAddr::V6(ip) if !ipv4_only => {
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

        let ipv4_only = self.is_ipv4_only();

        // Suppress SVCB (type 64) and HTTPS (type 65) records when QUIC blocking is enabled so
        // browsers and apps don't receive HTTP/3 Alt-Svc hints that bypass TCP TLS desync, OR
        // when `ipv4_only` is active to prevent `ipv6hint` leaks when `block_quic = false`.
        if (block_https_svcb || ipv4_only) && matches!(parsed.qtype, QTYPE_SVCB | QTYPE_HTTPS) {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            return Ok((
                build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 0, &[], 60),
                None,
            ));
        }

        // Suppress QTYPE_ANY (type 255) when `ipv4_only` is active so raw forwarding cannot
        // return AAAA/HTTPS/SVCB records containing IPv6 addresses.
        if ipv4_only && parsed.qtype == QTYPE_ANY {
            self.query_count.fetch_add(1, Ordering::Relaxed);
            return Ok((
                build_dns_wire_response(parsed.tx_id, parsed.flags, question_slice, 0, &[], 60),
                None,
            ));
        }

        if parsed.qclass == QCLASS_IN && matches!(parsed.qtype, QTYPE_A | QTYPE_AAAA) {
            if parsed.qtype == QTYPE_AAAA && ipv4_only {
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
                Ok(DnsOutcome::NxDomain(ttl)) => {
                    let neg_ttl = if ttl.is_zero() { 0 } else { 30 };
                    return Ok((
                        build_dns_wire_response(
                            parsed.tx_id,
                            parsed.flags,
                            question_slice,
                            3,
                            &[],
                            neg_ttl,
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
                    let ttl_secs = if matching.is_empty() && ttl.is_zero() {
                        0
                    } else {
                        ttl.as_secs().clamp(15, 300) as u32
                    };
                    let resp = build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        question_slice,
                        0,
                        &matching,
                        ttl_secs,
                    );
                    let non_unspec: Vec<IpAddr> = matching
                        .into_iter()
                        .filter(|ip| !ip.is_unspecified())
                        .collect();
                    let meta = if non_unspec.is_empty() {
                        None
                    } else {
                        Some((parsed.qname, non_unspec))
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

        // Forward other RR types (SRV, TXT, MX, PTR, etc.) via custom bare-IP UDP first (if
        // configured), then DoH (respecting backoff), then UDP fallback.
        self.query_count.fetch_add(1, Ordering::Relaxed);
        if let Some(primary) = self.active_custom_udp_primary() {
            if let Ok(mut raw) =
                send_udp_dns_raw(primary, query, self.outbound_binder.as_deref()).await
            {
                if is_valid_raw_dns_reply(&raw, true) && raw.len() >= 12 {
                    raw[0..2].copy_from_slice(&parsed.tx_id.to_be_bytes());
                    return Ok((raw, None));
                }
            }
        }
        if self.enable_doh && !self.is_doh_in_backoff() {
            if let Ok(mut raw) = self.query_doh_raw(query).await {
                self.record_doh_success();
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
        let mut normalized_query = wire_query.to_vec();
        if normalized_query.len() >= 2 {
            normalized_query[0] = 0;
            normalized_query[1] = 0;
        }
        let deadline = tokio::time::Instant::now() + DOH_RAW_MAX_WAIT;

        if let Some(custom) = &self.custom_doh {
            let queries_self = parse_dns_question(wire_query).is_ok_and(|q| {
                q.qname
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&custom.host)
            });
            if !queries_self {
                match tokio::time::timeout_at(
                    deadline,
                    self.send_custom_doh_wire(custom, &normalized_query),
                )
                .await
                {
                    Ok(Ok(bytes)) if is_valid_raw_dns_reply(&bytes, false) => return Ok(bytes),
                    Err(_) => bail!("raw DoH query budget exceeded"),
                    _ => {}
                }
            }
        }

        let ip_literal_only = self.custom_doh.is_some();
        let eligible = self.eligible_doh_indices(ip_literal_only);
        let count = eligible.len();
        if count == 0 {
            bail!("no DoH endpoints configured");
        }
        let pref = self.preferred_doh_idx.load(Ordering::Relaxed);
        let start_pos = eligible.iter().position(|&idx| idx == pref).unwrap_or(0);
        let require_ip_literal = ip_literal_only || self.is_system_dns_disabled();
        let http = self.http_client();
        for offset in 0..count.min(3) {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let idx = eligible[(start_pos + offset) % count];
            let bytes = match tokio::time::timeout_at(
                deadline,
                send_doh_wire(
                    &http,
                    self.outbound_binder.as_deref(),
                    self.bound_tls_connector.as_ref(),
                    &self.doh_endpoints[idx],
                    &normalized_query,
                    require_ip_literal,
                ),
            )
            .await
            {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(_)) => continue,
                Err(_) => break,
            };
            if is_valid_raw_dns_reply(&bytes, false) {
                if offset > 0 {
                    self.preferred_doh_idx.store(idx, Ordering::Relaxed);
                }
                return Ok(bytes);
            }
        }
        bail!("raw DoH query failed")
    }

    async fn query_udp_raw(&self, wire_query: &[u8]) -> Result<Vec<u8>> {
        let eligible = self.eligible_udp_indices();
        let count = eligible.len();
        if count == 0 {
            bail!("no UDP DNS servers configured");
        }
        let pref = self.preferred_udp_idx.load(Ordering::Relaxed);
        let start_pos = eligible.iter().position(|&idx| idx == pref).unwrap_or(0);
        for offset in 0..count {
            let idx = eligible[(start_pos + offset) % count];
            let Ok(bytes) = send_udp_dns_raw(
                self.udp_dns_servers[idx],
                wire_query,
                self.outbound_binder.as_deref(),
            )
            .await
            else {
                continue;
            };
            if is_valid_raw_dns_reply(&bytes, true) {
                if offset > 0 {
                    self.maybe_promote_udp_server(idx);
                }
                return Ok(bytes);
            }
        }
        bail!("raw UDP DNS query failed")
    }
}

fn combine_udp_v4_v6_results(
    domain: &str,
    v4_res: Result<DnsOutcome>,
    v6_res: Option<Result<DnsOutcome>>,
) -> Result<ResolvedOutcome> {
    let mut ips = Vec::new();
    let mut min_ttl = Duration::from_secs(300);
    let mut nx_ttl = Duration::from_secs(300);
    let mut has_a_lookup = false;
    let mut has_aaaa_lookup = false;
    let mut nxdomain = false;

    if let Ok(outcome) = v4_res {
        has_a_lookup = true;
        match outcome {
            DnsOutcome::NxDomain(ttl) => {
                nxdomain = true;
                nx_ttl = nx_ttl.min(ttl);
                if !ttl.is_zero() {
                    min_ttl = min_ttl.min(ttl);
                }
            }
            DnsOutcome::Records(v4, ttl) => {
                if !v4.is_empty() {
                    min_ttl = min_ttl.min(ttl);
                    ips.extend(v4);
                }
            }
        }
    }
    if let Some(Ok(outcome)) = v6_res {
        has_aaaa_lookup = true;
        match outcome {
            DnsOutcome::NxDomain(ttl) => {
                nx_ttl = nx_ttl.min(ttl);
                if !ttl.is_zero() {
                    min_ttl = min_ttl.min(ttl);
                }
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
            outcome: DnsOutcome::NxDomain(nx_ttl.min(Duration::from_secs(30))),
            has_a_lookup: true,
            has_aaaa_lookup: true,
        })
    } else {
        bail!("UDP DNS resolution failed for {domain}")
    }
}

async fn join_a_and_aaaa<FA, FV6, TA, TV6>(
    v4_fut: FA,
    v6_fut: FV6,
    v6_grace: Duration,
    has_ipv4: impl Fn(&TA) -> bool,
    is_nxdomain: impl Fn(&TA) -> bool,
) -> (TA, Option<TV6>)
where
    FA: std::future::Future<Output = TA>,
    FV6: std::future::Future<Output = TV6>,
{
    let started = Instant::now();
    tokio::pin!(v4_fut);
    tokio::pin!(v6_fut);

    tokio::select! {
        v4 = &mut v4_fut => {
            if is_nxdomain(&v4) {
                (v4, None)
            } else if has_ipv4(&v4) {
                let remaining = v6_grace.saturating_sub(started.elapsed());
                let v6 = tokio::time::timeout(remaining, &mut v6_fut).await.ok();
                (v4, v6)
            } else {
                let v6 = tokio::time::timeout(Duration::from_millis(2000), &mut v6_fut)
                    .await
                    .ok();
                (v4, v6)
            }
        }
        v6 = &mut v6_fut => {
            let v4 = v4_fut.await;
            (v4, Some(v6))
        }
    }
}

fn select_dual_stack_candidates(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut selected = Vec::with_capacity(2);
    if let Some(&v4) = ips.iter().find(|ip| ip.is_ipv4()) {
        selected.push(v4);
    }
    if let Some(&v6) = ips.iter().find(|ip| ip.is_ipv6()) {
        selected.push(v6);
    }
    for &ip in ips {
        if selected.len() >= 2 {
            break;
        }
        if !selected.contains(&ip) {
            selected.push(ip);
        }
    }
    selected
}

fn is_valid_raw_dns_reply(bytes: &[u8], reject_truncated: bool) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let is_response = (flags & 0x8000) != 0;
    let is_tc = (flags & 0x0200) != 0;
    let rcode = flags & 0x000f;
    is_response && !(reject_truncated && is_tc) && !matches!(rcode, 2 | 5)
}

fn is_loopback_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn should_cache_udp_negative(
    server: SocketAddr,
    allow_sinkhole_and_loopback: bool,
    saw_poisoned: bool,
) -> bool {
    if saw_poisoned {
        return false;
    }
    server.port() != 53 || allow_sinkhole_and_loopback
}

fn dns_reply_matches_question(
    resp: &[u8],
    expected_qname: &str,
    expected_qtype: u16,
    expected_qclass: u16,
) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if qdcount == 0 {
        return false;
    }
    let Ok((qname, pos)) = read_dns_name(resp, 12) else {
        return false;
    };
    if pos + 4 > resp.len() {
        return false;
    }
    let qtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    let qclass = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
    qname.eq_ignore_ascii_case(expected_qname)
        && qtype == expected_qtype
        && qclass == expected_qclass
}

enum UdpReplyDecision<T> {
    Accept(T),
    PoisonedWaitForRace(anyhow::Error),
    Reject(anyhow::Error),
}

enum UdpServerError {
    Poisoned(anyhow::Error),
    UntrustedNegative {
        outcome: DnsOutcome,
        err: anyhow::Error,
    },
    Other(anyhow::Error),
}

impl UdpServerError {
    fn into_anyhow(self) -> anyhow::Error {
        match self {
            Self::Poisoned(e) | Self::UntrustedNegative { err: e, .. } | Self::Other(e) => e,
        }
    }

    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned(_) | Self::UntrustedNegative { .. })
    }
}

async fn send_udp_dns_matching<T, F>(
    server: SocketAddr,
    wire_query: &[u8],
    outbound_binder: Option<&dyn OutboundBinder>,
    mut classify: F,
) -> std::result::Result<T, UdpServerError>
where
    F: FnMut(&[u8], bool) -> UdpReplyDecision<T>,
{
    let expected_q = parse_dns_question(wire_query).map_err(UdpServerError::Other)?;
    let tx_id = next_udp_tx_id();
    let tx_bytes = tx_id.to_be_bytes();
    let mut outbound_query = wire_query.to_vec();
    outbound_query[0..2].copy_from_slice(&tx_bytes);

    // Skip outbound interface binding when targeting loopback (127.0.0.0/8 or ::1) so
    // local resolvers like dnsmasq, Unbound, and systemd-resolved work in TUN mode.
    let effective_binder = outbound_binder.filter(|_| !is_loopback_dns_ip(server.ip()));
    let sock = if let Some(binder) = effective_binder {
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
        let raw = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
            .map_err(|e| UdpServerError::Other(e.into()))?;
        if !server.is_ipv4() {
            let _ = raw.set_only_v6(true);
        }
        binder
            .bind_socket(socket2::SockRef::from(&raw), server.is_ipv4())
            .map_err(|e| UdpServerError::Other(e.into()))?;
        raw.bind(&bind_addr.into())
            .map_err(|e| UdpServerError::Other(e.into()))?;
        raw.set_nonblocking(true)
            .map_err(|e| UdpServerError::Other(e.into()))?;
        let std_sock: std::net::UdpSocket = raw.into();
        UdpSocket::from_std(std_sock).map_err(|e| UdpServerError::Other(e.into()))?
    } else {
        let bind_addr = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| UdpServerError::Other(e.into()))?
    };
    sock.connect(server)
        .await
        .map_err(|e| UdpServerError::Other(e.into()))?;
    sock.send(&outbound_query)
        .await
        .map_err(|e| UdpServerError::Other(e.into()))?;
    let mut buf = [0u8; 4096];
    let mut deadline = Instant::now() + Duration::from_millis(1000);
    let mut poisoned_err: Option<anyhow::Error> = None;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(match poisoned_err {
                Some(err) => UdpServerError::Poisoned(err),
                None => UdpServerError::Other(anyhow!("UDP DNS timeout from {server}")),
            });
        };
        if remaining.is_zero() {
            return Err(match poisoned_err {
                Some(err) => UdpServerError::Poisoned(err),
                None => UdpServerError::Other(anyhow!("UDP DNS timeout from {server}")),
            });
        }
        let n = match tokio::time::timeout(remaining, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(UdpServerError::Other(e.into())),
            Err(_) => {
                return Err(match poisoned_err {
                    Some(err) => UdpServerError::Poisoned(err),
                    None => UdpServerError::Other(anyhow!("UDP DNS timeout from {server}")),
                });
            }
        };
        let resp = &buf[..n];
        if resp.len() < 12 || resp[0..2] != tx_bytes {
            continue;
        }
        let flags = u16::from_be_bytes([resp[2], resp[3]]);
        if (flags & 0x8000) == 0 {
            continue;
        }
        if !dns_reply_matches_question(resp, &expected_q.qname, expected_q.qtype, expected_q.qclass)
        {
            continue;
        }
        match classify(resp, poisoned_err.is_some()) {
            UdpReplyDecision::Accept(val) => return Ok(val),
            UdpReplyDecision::Reject(err) => return Err(UdpServerError::Other(err)),
            UdpReplyDecision::PoisonedWaitForRace(err) => {
                if poisoned_err.is_none() {
                    poisoned_err = Some(err);
                    deadline =
                        deadline.min(Instant::now() + Duration::from_millis(UDP_DPI_RACE_GRACE_MS));
                }
            }
        }
    }
}

async fn send_udp_dns_raw(
    server: SocketAddr,
    wire_query: &[u8],
    outbound_binder: Option<&dyn OutboundBinder>,
) -> Result<Vec<u8>> {
    send_udp_dns_matching(server, wire_query, outbound_binder, |resp, _| {
        UdpReplyDecision::Accept(resp.to_vec())
    })
    .await
    .map_err(UdpServerError::into_anyhow)
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
    let include_negative_soa = answers.is_empty() && ttl_secs > 0 && matches!(rcode, 0 | 3);
    let nscount = u16::from(include_negative_soa);

    let extra_cap = if include_negative_soa {
        35
    } else {
        answers.len() * 28
    };
    let mut out = Vec::with_capacity(12 + question_slice.len() + extra_cap);
    out.extend_from_slice(&tx_id.to_be_bytes());
    out.extend_from_slice(&resp_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&nscount.to_be_bytes()); // NSCOUNT
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

    if include_negative_soa {
        // Minimal RFC 2308 Authority SOA RR so OS stub resolvers (mDNSResponder, dnscache)
        // negatively cache HTTPS/SVCB/AAAA NODATA and NXDOMAIN replies.
        out.extend_from_slice(&[0xc0, 0x0c]); // NAME: pointer to QNAME at offset 12
        out.extend_from_slice(&QTYPE_SOA.to_be_bytes()); // TYPE = SOA (6)
        out.extend_from_slice(&QCLASS_IN.to_be_bytes()); // CLASS = IN (1)
        out.extend_from_slice(&ttl_secs.to_be_bytes()); // TTL
        out.extend_from_slice(&23u16.to_be_bytes()); // RDLENGTH = 2 + 1 + 5*4 = 23
        out.extend_from_slice(&[0xc0, 0x0c]); // MNAME: pointer to QNAME at offset 12
        out.push(0x00); // RNAME: root (.)
        out.extend_from_slice(&1u32.to_be_bytes()); // SERIAL = 1
        out.extend_from_slice(&3600u32.to_be_bytes()); // REFRESH = 3600
        out.extend_from_slice(&600u32.to_be_bytes()); // RETRY = 600
        out.extend_from_slice(&86400u32.to_be_bytes()); // EXPIRE = 86400
        out.extend_from_slice(&ttl_secs.to_be_bytes()); // MINIMUM = ttl_secs
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum DohHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDohUrl {
    normalized_url: String,
    request_url: String,
    host: DohHost,
    port: u16,
    host_header: String,
    path_and_query: String,
}

fn validate_dns_ip_addr(ip: IpAddr) -> std::result::Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err("DNS IP cannot be 0.0.0.0".to_string());
            }
            if v4.is_multicast() {
                return Err("DNS IP cannot be a multicast address".to_string());
            }
            if v4.is_broadcast() {
                return Err("DNS IP cannot be a broadcast address".to_string());
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err("DNS IP cannot be ::".to_string());
            }
            if v6.is_multicast() {
                return Err("DNS IP cannot be a multicast address".to_string());
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                validate_dns_ip_addr(IpAddr::V4(v4))?;
            }
        }
    }
    Ok(())
}

fn parse_doh_port(port_str: &str) -> std::result::Result<u16, String> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Invalid port in DoH URL (must be 1-65535)".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| "Invalid port in DoH URL (must be 1-65535)".to_string())?;
    if port == 0 {
        return Err("Invalid port in DoH URL (must be 1-65535)".to_string());
    }
    Ok(port)
}

fn validate_doh_hostname(raw: &str) -> std::result::Result<String, String> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    let lower = trimmed.to_ascii_lowercase();
    if lower.is_empty() || lower.len() > MAX_DNS_NAME_BYTES {
        return Err("Invalid hostname in DoH URL".to_string());
    }
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return Err("Invalid hostname in DoH URL".to_string());
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid hostname in DoH URL".to_string());
        }
    }
    let tld = labels.last().copied().unwrap_or("");
    if !tld.bytes().any(|b| b.is_ascii_alphabetic()) {
        return Err("Invalid hostname or IPv4 address in DoH URL".to_string());
    }
    Ok(lower)
}

fn validate_doh_path_and_query(suffix: &str) -> std::result::Result<(), String> {
    let bytes = suffix.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err("Invalid percent-encoding in DoH URL path".to_string());
            }
            i += 3;
            continue;
        }
        let allowed = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'?'
                    | b':'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            );
        if !allowed {
            return Err("Invalid character in DoH URL path or query".to_string());
        }
        i += 1;
    }
    Ok(())
}

fn parse_doh_url_validated(raw: &str) -> std::result::Result<ParsedDohUrl, String> {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Err("DoH URL must start with https://".to_string());
    };
    if !scheme.eq_ignore_ascii_case("https") {
        if scheme.eq_ignore_ascii_case("http") {
            return Err("DoH URL must use https:// (http:// is not supported)".to_string());
        }
        return Err("DoH URL must start with https://".to_string());
    }
    if rest.contains('#') {
        return Err("DoH URL cannot contain a '#' fragment".to_string());
    }
    let (authority, raw_suffix) = match rest.find(['/', '?']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err("DoH URL is missing a hostname or IP".to_string());
    }
    if authority.contains('@') {
        return Err("DoH URL cannot contain userinfo (@)".to_string());
    }

    let (host, explicit_port) = if let Some(after_open) = authority.strip_prefix('[') {
        let Some(close) = after_open.find(']') else {
            return Err("Unclosed '[' in IPv6 DoH URL".to_string());
        };
        let ip_str = &after_open[..close];
        let v6: Ipv6Addr = ip_str
            .parse()
            .map_err(|_| "Invalid IPv6 address in DoH URL".to_string())?;
        validate_dns_ip_addr(IpAddr::V6(v6))?;
        let tail = &after_open[close + 1..];
        let port = if let Some(port_str) = tail.strip_prefix(':') {
            Some(parse_doh_port(port_str)?)
        } else if tail.is_empty() {
            None
        } else {
            return Err("Invalid characters after IPv6 address in DoH URL".to_string());
        };
        (DohHost::Ip(IpAddr::V6(v6)), port)
    } else {
        if authority.contains('[') || authority.contains(']') {
            return Err("Invalid brackets in DoH URL host".to_string());
        }
        if authority.matches(':').count() > 1 {
            return Err("Wrap IPv6 DoH hosts in [...] brackets".to_string());
        }
        let (host_raw, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(parse_doh_port(p)?)),
            None => (authority, None),
        };
        if host_raw.is_empty() {
            return Err("DoH URL is missing a hostname or IP".to_string());
        }
        if let Ok(v4) = host_raw.parse::<Ipv4Addr>() {
            validate_dns_ip_addr(IpAddr::V4(v4))?;
            (DohHost::Ip(IpAddr::V4(v4)), port)
        } else {
            let domain = validate_doh_hostname(host_raw)?;
            (DohHost::Domain(domain), port)
        }
    };

    if !raw_suffix.is_empty() {
        validate_doh_path_and_query(raw_suffix)?;
    }

    let port = explicit_port.unwrap_or(443);
    let host_for_url = match &host {
        DohHost::Ip(IpAddr::V4(v4)) => v4.to_string(),
        DohHost::Ip(IpAddr::V6(v6)) => format!("[{v6}]"),
        DohHost::Domain(d) => d.clone(),
    };
    let host_header = if port == 443 {
        host_for_url.clone()
    } else {
        format!("{host_for_url}:{port}")
    };
    let authority_normalized = match explicit_port {
        Some(p) => format!("{host_for_url}:{p}"),
        None => host_for_url,
    };
    let (normalized_suffix, path_and_query) = if raw_suffix.is_empty() {
        (String::new(), "/dns-query".to_string())
    } else if raw_suffix.starts_with('?') {
        let pq = format!("/dns-query{raw_suffix}");
        (pq.clone(), pq)
    } else if let Some(query) = raw_suffix.strip_prefix("/?") {
        let pq = format!("/dns-query?{query}");
        (pq.clone(), pq)
    } else {
        (raw_suffix.to_string(), raw_suffix.to_string())
    };
    let normalized_url = format!("https://{authority_normalized}{normalized_suffix}");
    let request_url = format!("https://{authority_normalized}{path_and_query}");

    Ok(ParsedDohUrl {
        normalized_url,
        request_url,
        host,
        port,
        host_header,
        path_and_query,
    })
}

/// Returns whether DoH is effectively active for `dns_addr` and `enable_doh`.
///
/// Explicit valid `https://` DoH URLs always enable DoH even when `enable_doh` is `false`.
pub fn effective_enable_doh(dns_addr: &str, enable_doh: bool) -> bool {
    enable_doh || parse_doh_url_validated(dns_addr.trim()).is_ok()
}

/// Returns whether `dns_addr` is actively targeted via DoH as the primary resolver.
///
/// Returns `true` if `dns_addr` is a valid `https://` DoH URL (regardless of `enable_doh`),
/// or if `enable_doh` is `true` and `dns_addr` parses as a known public DoH IP
/// (`is_known_public_doh_ip`). Returns `false` for bare custom non-DoH IPs (e.g. `76.76.2.0`
/// or `10.0.0.53`) so banners and dashboards never mislabel UDP-first custom IPs as DoH.
pub fn is_effective_doh_target(dns_addr: &str, enable_doh: bool) -> bool {
    let trimmed = dns_addr.trim();
    if parse_doh_url_validated(trimmed).is_ok() {
        return true;
    }
    enable_doh && parse_bare_dns_ip(trimmed).is_some_and(is_known_public_doh_ip)
}

fn starts_with_ignore_ascii_case(s: &str, prefix: &[u8]) -> bool {
    s.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn redact_authority_for_display(rest: &str, allow_single_label: bool) -> Option<String> {
    // Split at the first path, query, fragment, backslash, whitespace, or control delimiter.
    let (authority, remainder) = match rest.find(|c: char| {
        matches!(c, '/' | '?' | '#' | '\\') || c.is_whitespace() || c.is_control()
    }) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    // If `@` appears anywhere after the first delimiter (e.g.
    // `https://secretuser?p@dns.nextdns.io/a1b2c3` or
    // `https://secretuser/pass@dns.nextdns.io/a1b2c3`), `authority` may actually be a
    // credential/username whose password contained `?`/`/`/`#`/`\`/whitespace. Fail closed
    // so userinfo can never leak as a hostname.
    if remainder.contains('@') {
        return None;
    }

    if authority.is_empty() {
        return None;
    }

    // Strip any userinfo (`user:pass@`), using `rsplit_once` so passwords containing `@` cannot leak.
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hp)| hp);
    if host_port.is_empty() {
        return None;
    }

    if let Some(after_open) = host_port.strip_prefix('[') {
        let close = after_open.find(']')?;
        let ip_str = &after_open[..close];
        let v6 = ip_str.parse::<Ipv6Addr>().ok()?;
        let tail = &after_open[close + 1..];
        if tail.is_empty() {
            Some(format!("[{v6}]"))
        } else if let Some(port_str) = tail.strip_prefix(':') {
            let port = parse_doh_port(port_str).ok()?;
            Some(format!("[{v6}]:{port}"))
        } else {
            None
        }
    } else {
        if host_port.contains('[')
            || host_port.contains(']')
            || host_port.matches(':').count() > 1
        {
            return None;
        }
        let (host_raw, port_opt) = match host_port.split_once(':') {
            Some((h, p)) => (h, Some(parse_doh_port(p).ok()?)),
            None => (host_port, None),
        };
        if host_raw.is_empty() {
            return None;
        }
        let host_norm = if let Ok(v4) = host_raw.parse::<Ipv4Addr>() {
            v4.to_string()
        } else {
            let lower = host_raw.trim_end_matches('.').to_ascii_lowercase();
            if lower.is_empty()
                || lower.len() > MAX_DNS_NAME_BYTES
                || !lower
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
                || lower.starts_with('.')
                || lower.starts_with('-')
                || lower.ends_with('-')
                || lower.contains("..")
                || (!allow_single_label && !lower.contains('.'))
            {
                return None;
            }
            lower
        };
        Some(match port_opt {
            Some(port) => format!("{host_norm}:{port}"),
            None => host_norm,
        })
    }
}

/// Redacts sensitive userinfo, path, query, and fragment tokens from a DNS server string for
/// safe display, logging, and error messages.
///
/// - Valid or malformed `https://` / `http://` URLs retain only `scheme://host[:port]`
///   (preserving IPv6 brackets, e.g. `https://[2606:4700:4700::1111]/secret` ->
///   `https://[2606:4700:4700::1111]`) and return `https://<redacted>` (never leaking raw
///   secrets) when the host portion is missing or malformed.
/// - Scheme-without-slashes inputs (`https:dns.nextdns.io/a1b2c3`, `http:host/secret`) return
///   `https://<redacted>` / `http://<redacted>`.
/// - Scheme-less URL-like inputs containing `/`, `?`, `@`, `#`, or `\` strip secrets and return
///   only a validated IP or multi-label host[:port], or `<redacted>` when malformed.
/// - Bare IP addresses or non-URL strings are returned trimmed.
pub fn redact_dns_for_display(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if starts_with_ignore_ascii_case(trimmed, b"https:")
        && !starts_with_ignore_ascii_case(trimmed, b"https://")
    {
        return "https://<redacted>".to_string();
    }
    if starts_with_ignore_ascii_case(trimmed, b"http:")
        && !starts_with_ignore_ascii_case(trimmed, b"http://")
    {
        return "http://<redacted>".to_string();
    }

    let Some((scheme, rest)) = trimmed.split_once("://") else {
        if trimmed.contains(['/', '?', '@', '#', '\\']) {
            return redact_authority_for_display(trimmed, false)
                .unwrap_or_else(|| "<redacted>".to_string());
        }
        return trimmed.to_string();
    };
    let scheme_lower = scheme.to_ascii_lowercase();
    let valid_scheme = !scheme_lower.is_empty()
        && scheme_lower
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    let redacted_fallback = if scheme_lower == "https" {
        "https://<redacted>".to_string()
    } else if valid_scheme {
        format!("{scheme_lower}://<redacted>")
    } else {
        "<redacted>".to_string()
    };

    if !valid_scheme {
        return redacted_fallback;
    }

    let Some(normalized_host_port) = redact_authority_for_display(rest, true) else {
        return redacted_fallback;
    };

    if scheme_lower == "https" {
        format!("https://{normalized_host_port}")
    } else {
        format!("{scheme_lower}://{normalized_host_port}")
    }
}

/// Redacts embedded `https://`, `http://`, and malformed `https:` / `http:` URLs inside
/// free-form text (logs, errors, status messages) using [`redact_dns_for_display`] so path
/// tokens, queries, fragments, and userinfo credentials never leak into UI or logs.
pub fn redact_urls_in_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    while cursor < input.len() {
        let rest = &input[cursor..];
        let mut found: Option<(usize, usize, bool)> = None;
        for (idx, _) in rest.char_indices() {
            let tail = &rest[idx..];
            if starts_with_ignore_ascii_case(tail, b"https://") {
                found = Some((idx, 8, true));
                break;
            }
            if starts_with_ignore_ascii_case(tail, b"http://") {
                found = Some((idx, 7, true));
                break;
            }
            let scheme_colon_len = if starts_with_ignore_ascii_case(tail, b"https:") {
                Some(6usize)
            } else if starts_with_ignore_ascii_case(tail, b"http:") {
                Some(5usize)
            } else {
                None
            };
            if let Some(prefix_len) = scheme_colon_len {
                let prev_is_alnum = input[..cursor + idx]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_ascii_alphanumeric());
                if !prev_is_alnum {
                    found = Some((idx, prefix_len, false));
                    break;
                }
            }
        }
        let Some((rel_start, prefix_len, has_slashes)) = found else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..rel_start]);
        let url_slice = &rest[rel_start..];
        let mut rel_end = url_slice.len();
        for (idx, ch) in url_slice.char_indices() {
            if ch.is_whitespace() || ch.is_control() || matches!(ch, '"' | '<' | '>') {
                rel_end = idx;
                break;
            }
        }
        let mut token = &url_slice[..rel_end];
        let mut trailing_start = rel_end;
        while trailing_start > prefix_len {
            let Some(last) = token.chars().next_back() else {
                break;
            };
            let strip = match last {
                '.' | ':' | ',' | ';' | '\'' => true,
                ')' => {
                    token.bytes().filter(|&b| b == b')').count()
                        > token.bytes().filter(|&b| b == b'(').count()
                }
                ']' => {
                    token.bytes().filter(|&b| b == b']').count()
                        > token.bytes().filter(|&b| b == b'[').count()
                }
                _ => false,
            };
            if strip {
                trailing_start -= last.len_utf8();
                token = &url_slice[..trailing_start];
            } else {
                break;
            }
        }
        if !has_slashes && trailing_start <= prefix_len {
            out.push_str(&url_slice[..prefix_len]);
            cursor += rel_start + prefix_len;
            continue;
        }
        out.push_str(&redact_dns_for_display(token));
        cursor += rel_start + trailing_start;
    }
    out
}

fn is_lan_or_private_hostname(normalized: &str) -> bool {
    !normalized.contains('.')
        || normalized.ends_with(".lan")
        || normalized == "home.arpa"
        || normalized.ends_with(".home.arpa")
        || normalized.ends_with(".internal")
        || normalized.ends_with(".localdomain")
        || normalized.ends_with(".ts.net")
}

/// Validates and normalizes a custom DNS server input (IPv4, IPv6, or `https://` DoH URL).
///
/// Returns a normalized string ready for config persistence and `DnsResolver::new*`, or a short
/// human-friendly error suitable for inline TUI / CLI display.
pub fn validate_custom_dns_input(raw: &str) -> std::result::Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("DNS server cannot be empty".to_string());
    }
    if trimmed.chars().any(char::is_control) {
        return Err("DNS server cannot contain control characters".to_string());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err("DNS server cannot contain whitespace".to_string());
    }

    if trimmed.contains("://") {
        return parse_doh_url_validated(trimmed).map(|parsed| parsed.normalized_url);
    }

    let ip_opt = if trimmed.starts_with('[') || trimmed.ends_with(']') {
        trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
            .map(IpAddr::V6)
    } else {
        trimmed.parse::<IpAddr>().ok()
    };

    match ip_opt {
        Some(ip) => {
            validate_dns_ip_addr(ip)?;
            Ok(ip.to_string())
        }
        None => Err("Enter a valid IPv4/IPv6 address or https:// DoH URL".to_string()),
    }
}

struct BoundDohTarget {
    addr: SocketAddr,
    host_header: String,
    path: String,
    server_name: ServerName<'static>,
}

fn parse_bound_doh_endpoint(endpoint: &str) -> Result<BoundDohTarget> {
    let redacted = redact_dns_for_display(endpoint);
    let parsed = parse_doh_url_validated(endpoint).map_err(|msg| anyhow!("{msg}: {redacted}"))?;
    let DohHost::Ip(ip) = parsed.host else {
        bail!("bound DoH requires IP-literal endpoint: {redacted}");
    };
    Ok(BoundDohTarget {
        addr: SocketAddr::new(ip, parsed.port),
        host_header: parsed.host_header,
        path: parsed.path_and_query,
        server_name: ServerName::from(ip),
    })
}

struct HttpDohHead {
    body_offset: usize,
    content_length: Option<usize>,
    chunked: bool,
}

fn parse_http_doh_head(raw: &[u8], endpoint: &str) -> Result<Option<HttpDohHead>> {
    let redacted = redact_dns_for_display(endpoint);
    let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        if raw.len() > MAX_BOUND_DOH_HEADER_BYTES {
            bail!("DoH HTTP headers exceeded {MAX_BOUND_DOH_HEADER_BYTES} bytes from {redacted}");
        }
        return Ok(None);
    };
    if pos > MAX_BOUND_DOH_HEADER_BYTES {
        bail!("DoH HTTP headers exceeded {MAX_BOUND_DOH_HEADER_BYTES} bytes from {redacted}");
    }
    let head_str = std::str::from_utf8(&raw[..pos])
        .with_context(|| format!("non-UTF8 DoH HTTP response headers from {redacted}"))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("empty DoH HTTP response from {redacted}"))?;
    let mut parts = status_line.split_ascii_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| anyhow!("malformed DoH HTTP status line from {redacted}"))?;
    if !version.starts_with("HTTP/") {
        bail!("malformed DoH HTTP status line from {redacted}");
    }
    let status_code = parts
        .next()
        .ok_or_else(|| anyhow!("missing DoH HTTP status code from {redacted}"))?;
    if status_code != "200" {
        bail!("DoH HTTP status {status_code} from {redacted}");
    }

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim();
            let val = val.trim();
            if name.eq_ignore_ascii_case("content-length") {
                let cl = val.parse::<usize>().with_context(|| {
                    format!("invalid DoH Content-Length '{val}' from {redacted}")
                })?;
                if cl > MAX_DNS_MESSAGE_BYTES {
                    bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
                }
                if content_length.is_some_and(|prev| prev != cl) {
                    bail!("conflicting DoH Content-Length headers from {redacted}");
                }
                content_length = Some(cl);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && val
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
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

fn decode_http_chunked_body(input: &[u8], max_bytes: usize) -> Result<Option<Vec<u8>>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        let Some(rel_crlf) = input[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line =
            std::str::from_utf8(&input[pos..pos + rel_crlf]).context("non-UTF8 HTTP chunk size")?;
        let size_hex = size_line
            .split_once(';')
            .map_or(size_line, |(size, _)| size)
            .trim();
        if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid HTTP chunk size '{size_hex}'");
        }
        let chunk_len = usize::from_str_radix(size_hex, 16)
            .with_context(|| format!("invalid HTTP chunk size '{size_hex}'"))?;
        pos += rel_crlf + 2;
        if chunk_len == 0 {
            let rest = &input[pos..];
            if rest.starts_with(b"\r\n") || rest.windows(4).any(|w| w == b"\r\n\r\n") {
                return Ok(Some(out));
            }
            return Ok(None);
        }
        if chunk_len > max_bytes.saturating_sub(out.len()) {
            bail!("DoH response exceeded {max_bytes} bytes");
        }
        let Some(chunk_end) = pos.checked_add(chunk_len) else {
            bail!("DoH response exceeded {max_bytes} bytes");
        };
        let Some(next_pos) = chunk_end.checked_add(2) else {
            bail!("DoH response exceeded {max_bytes} bytes");
        };
        if next_pos > input.len() {
            return Ok(None);
        }
        out.extend_from_slice(&input[pos..chunk_end]);
        if &input[chunk_end..next_pos] != b"\r\n" {
            bail!("malformed HTTP chunk terminator");
        }
        pos = next_pos;
    }
}

fn parse_http_doh_response(
    raw: &[u8],
    parsed_head: &mut Option<HttpDohHead>,
    endpoint: &str,
    eof: bool,
) -> Result<Option<Vec<u8>>> {
    let redacted = redact_dns_for_display(endpoint);
    if parsed_head.is_none() {
        *parsed_head = parse_http_doh_head(raw, endpoint)?;
    }
    let Some(head) = parsed_head.as_ref() else {
        if eof {
            bail!("incomplete DoH HTTP response headers from {redacted}");
        }
        return Ok(None);
    };

    let body = &raw[head.body_offset..];
    if head.chunked {
        match decode_http_chunked_body(body, MAX_DNS_MESSAGE_BYTES)? {
            Some(decoded) => Ok(Some(decoded)),
            None if eof => bail!("truncated chunked DoH response from {redacted}"),
            None => Ok(None),
        }
    } else if let Some(cl) = head.content_length {
        if body.len() >= cl {
            Ok(Some(body[..cl].to_vec()))
        } else if eof {
            bail!(
                "truncated DoH response from {redacted} (got {} of {cl} bytes)",
                body.len()
            );
        } else {
            Ok(None)
        }
    } else if body.len() > MAX_DNS_MESSAGE_BYTES {
        bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
    } else if eof {
        Ok(Some(body.to_vec()))
    } else {
        Ok(None)
    }
}

async fn send_doh_bound_tls(
    binder: &dyn OutboundBinder,
    connector: &TlsConnector,
    endpoint: &str,
    wire_query: &[u8],
) -> Result<Vec<u8>> {
    let target = parse_bound_doh_endpoint(endpoint)?;
    send_doh_bound_tls_target(binder, connector, &target, endpoint, wire_query).await
}

async fn send_doh_bound_tls_target(
    binder: &dyn OutboundBinder,
    connector: &TlsConnector,
    target: &BoundDohTarget,
    endpoint: &str,
    wire_query: &[u8],
) -> Result<Vec<u8>> {
    let redacted = redact_dns_for_display(endpoint);
    let sock = if target.addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    if !is_loopback_dns_ip(target.addr.ip()) {
        binder.bind_socket(socket2::SockRef::from(&sock), target.addr.is_ipv4())?;
    }

    let addr = target.addr;
    let server_name = target.server_name.clone();
    let req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        target.path,
        target.host_header,
        wire_query.len()
    );

    let redacted_inner = redacted.clone();
    tokio::time::timeout(BOUND_DOH_TOTAL_TIMEOUT, async {
        let tcp = sock
            .connect(addr)
            .await
            .with_context(|| format!("bound DoH TCP connect failed to {addr}"))?;
        let _ = tcp.set_nodelay(true);

        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("bound DoH TLS handshake failed to {redacted_inner}"))?;

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

                    if let Some(body) =
                        parse_http_doh_response(&raw, &mut parsed_head, &redacted_inner, false)?
                    {
                        return Ok(body);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Some HTTP/1.1 servers close TCP after `Connection: close` without TLS close_notify.
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }

        parse_http_doh_response(&raw, &mut parsed_head, &redacted_inner, true)?
            .ok_or_else(|| anyhow!("incomplete DoH HTTP response from {redacted_inner}"))
    })
    .await
    .map_err(|_| anyhow!("bound DoH exchange timeout to {redacted}"))?
}

async fn send_doh_wire(
    http: &Client,
    outbound_binder: Option<&dyn OutboundBinder>,
    bound_tls: Option<&TlsConnector>,
    endpoint: &str,
    wire_query: &[u8],
    require_ip_literal: bool,
) -> Result<Vec<u8>> {
    if let (Some(binder), Some(connector)) = (outbound_binder, bound_tls) {
        send_doh_bound_tls(binder, connector, endpoint, wire_query).await
    } else {
        send_doh_request_raw(http, endpoint, wire_query, require_ip_literal).await
    }
}

async fn send_doh_request_pinned(
    http: &Client,
    endpoint: &str,
    wire_query: &[u8],
) -> Result<Vec<u8>> {
    send_doh_http_post(http, endpoint, wire_query).await
}

async fn send_doh_request_raw(
    http: &Client,
    endpoint: &str,
    wire_query: &[u8],
    require_ip_literal: bool,
) -> Result<Vec<u8>> {
    if require_ip_literal && !is_ip_literal_doh_endpoint(endpoint) {
        let redacted = redact_dns_for_display(endpoint);
        bail!(
            "hostname-based DoH endpoint rejected when system DNS fallback is disabled: {redacted}"
        );
    }
    send_doh_http_post(http, endpoint, wire_query).await
}

async fn send_doh_http_post(http: &Client, endpoint: &str, wire_query: &[u8]) -> Result<Vec<u8>> {
    let redacted = redact_dns_for_display(endpoint);
    let mut resp = http
        .post(endpoint)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(wire_query.to_vec())
        .send()
        .await
        .map_err(|e| anyhow!("DoH HTTP request failed to {redacted}: {}", e.without_url()))?;
    if !resp.status().is_success() {
        bail!("DoH HTTP status {} from {redacted}", resp.status());
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_DNS_MESSAGE_BYTES as u64)
    {
        bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow!("DoH HTTP body read failed from {redacted}: {}", e.without_url()))?
    {
        if chunk.len() > MAX_DNS_MESSAGE_BYTES - bytes.len() {
            bail!("DoH response exceeded {MAX_DNS_MESSAGE_BYTES} bytes");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn classify_doh_wire_reply(
    bytes: &[u8],
    qtype: u16,
    endpoint: &str,
    allow_sinkhole: bool,
) -> std::result::Result<DnsOutcome, DohError> {
    let redacted = redact_dns_for_display(endpoint);
    match decode_dns_outcome_classified(bytes, qtype) {
        Ok(DnsOutcome::NxDomain(ttl)) => Ok(DnsOutcome::NxDomain(ttl)),
        Ok(DnsOutcome::Records(ips, ttl)) => {
            let had_ips = !ips.is_empty();
            let clean = filter_poisoned_doh_ips(ips, allow_sinkhole);
            if had_ips && clean.is_empty() {
                // Treat sinkholed/poisoned answers as a distinct DNS-level rejection rather than
                // a transport outage or upstream SERVFAIL/REFUSED so a single sinkholed domain
                // can NEVER trip global DoH backoff or fall back to plaintext UDP.
                Err(DohError::SinkholeRejected { endpoint: redacted })
            } else {
                Ok(DnsOutcome::Records(clean, ttl))
            }
        }
        Err(DnsDecodeError::ProtocolError(rcode)) => Err(DohError::ProtocolError {
            endpoint: redacted,
            rcode,
        }),
        Err(DnsDecodeError::Malformed(err)) => Err(DohError::Transport(err)),
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_doh_request(
    http: &Client,
    outbound_binder: Option<&dyn OutboundBinder>,
    bound_tls: Option<&TlsConnector>,
    endpoint: &str,
    wire_query: &[u8],
    qtype: u16,
    require_ip_literal: bool,
    allow_sinkhole: bool,
) -> std::result::Result<DnsOutcome, DohError> {
    let bytes = send_doh_wire(
        http,
        outbound_binder,
        bound_tls,
        endpoint,
        wire_query,
        require_ip_literal,
    )
    .await
    .map_err(DohError::Transport)?;
    classify_doh_wire_reply(&bytes, qtype, endpoint, allow_sinkhole)
}

fn parse_bare_dns_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    let ip_opt = if trimmed.starts_with('[') || trimmed.ends_with(']') {
        trimmed
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
            .map(IpAddr::V6)
    } else {
        trimmed.parse::<IpAddr>().ok()
    };
    ip_opt.filter(|ip| validate_dns_ip_addr(*ip).is_ok())
}

fn is_unfiltered_default_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            [1, 1, 1, 1]
                | [1, 0, 0, 1]
                | [8, 8, 8, 8]
                | [8, 8, 4, 4]
                | [94, 140, 14, 140 | 141]
        ),
        IpAddr::V6(v6) => matches!(
            v6.segments(),
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111 | 0x1001]
                | [0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888 | 0x8844]
        ),
    }
}

/// Returns `true` only for known public DNS IP addresses whose TLS certificates include an IP
/// Subject Alternative Name (IP-SAN) and serve RFC 8484 DoH at `https://<ip>/dns-query`.
///
/// Arbitrary custom/corporate bare IPs (e.g. `76.76.2.0`, `10.0.0.53`, `192.168.1.1`) do not
/// serve IP-SAN DoH and must be queried over UDP instead of synthesizing a broken `https://IP/dns-query`.
fn is_known_public_doh_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            // Cloudflare (Standard, Security, Family)
            [1, 1, 1, 1..=3]
                | [1, 0, 0, 1..=3]
                // Google Public DNS
                | [8, 8, 8, 8]
                | [8, 8, 4, 4]
                // Quad9
                | [9, 9, 9, 9]
                | [149, 112, 112, 112]
                // AdGuard DNS (Default, Family, Unfiltered)
                | [94, 140, 14, 14 | 15 | 140 | 141]
                | [94, 140, 15, 15 | 16]
        ),
        IpAddr::V6(v6) => matches!(
            v6.segments(),
            // Cloudflare IPv6 (Standard, Security, Family, DNS64)
            [
                0x2606,
                0x4700,
                0x4700,
                0,
                0,
                0,
                0,
                0x1111 | 0x1001 | 0x1112 | 0x1002 | 0x1113 | 0x1003 | 0x0064 | 0x6400
            ]
                // Google IPv6 (Standard, DNS64)
                | [
                    0x2001,
                    0x4860,
                    0x4860,
                    0,
                    0,
                    0,
                    0,
                    0x8888 | 0x8844 | 0x6464 | 0x0064
                ]
                // Quad9 IPv6
                | [0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe | 0x0009]
                // AdGuard IPv6 (Default, Family, Unfiltered)
                | [0x2a10, 0x50c0, 0, 0, 0, 0, 0x0ad1 | 0x0ad2 | 0xbad1 | 0xbad2 | 0x0001 | 0x0002, 0x00ff]
        ),
    }
}

fn is_filtering_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            // Cloudflare Security & Family (1.1.1.2, 1.0.0.2, 1.1.1.3, 1.0.0.3)
            [1, 1, 1, 2 | 3]
                | [1, 0, 0, 2 | 3]
                // AdGuard DNS Default & Family
                | [94, 140, 14, 14 | 15]
                | [94, 140, 15, 15 | 16]
                // Control D filtering resolvers
                | [76, 76, 2 | 10, 1..=5]
        ),
        IpAddr::V6(v6) => matches!(
            v6.segments(),
            [0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1112 | 0x1002 | 0x1113 | 0x1003]
                | [0x2a10, 0x50c0, 0, 0, 0, 0, 0x0ad1 | 0x0ad2 | 0xbad1 | 0xbad2, 0x00ff]
        ),
    }
}

fn is_filtering_doh_endpoint(endpoint: &str) -> bool {
    let Ok(target) = parse_bound_doh_endpoint(endpoint) else {
        return false;
    };
    is_filtering_dns_ip(target.addr.ip())
}

fn is_ip_literal_doh_endpoint(endpoint: &str) -> bool {
    parse_bound_doh_endpoint(endpoint).is_ok()
}

fn is_ipv6_doh_endpoint(endpoint: &str) -> bool {
    parse_doh_url_validated(endpoint)
        .is_ok_and(|parsed| matches!(parsed.host, DohHost::Ip(IpAddr::V6(_))))
}

fn is_http2_only_doh_endpoint(endpoint: &str) -> bool {
    let Ok(target) = parse_bound_doh_endpoint(endpoint) else {
        return false;
    };
    match target.addr.ip() {
        IpAddr::V4(ip) => {
            ip == Ipv4Addr::new(9, 9, 9, 9) || ip == Ipv4Addr::new(149, 112, 112, 112)
        }
        IpAddr::V6(ip) => {
            ip == Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x00fe)
                || ip == Ipv6Addr::new(0x2620, 0x00fe, 0, 0, 0, 0, 0, 0x0009)
        }
    }
}

fn build_doh_endpoints(
    dns_addr: &str,
    bound_http1: bool,
    require_ip_literal: bool,
    ipv4_only: bool,
) -> Vec<String> {
    let mut list = Vec::new();
    let trimmed = dns_addr.trim();
    let mut explicit_ipv6 = false;
    if let Ok(parsed) = parse_doh_url_validated(trimmed) {
        match parsed.host {
            DohHost::Ip(ip) => {
                if ip.is_ipv6() {
                    explicit_ipv6 = true;
                }
                if !ipv4_only || ip.is_ipv4() {
                    list.push(parsed.request_url);
                }
            }
            DohHost::Domain(_) => {
                if !require_ip_literal {
                    list.push(parsed.request_url);
                }
            }
        }
    } else if let Some(ip) = parse_bare_dns_ip(trimmed) {
        if ip.is_ipv6() {
            explicit_ipv6 = true;
        }
        if is_known_public_doh_ip(ip) && (!ipv4_only || ip.is_ipv4()) {
            let primary = match ip {
                IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
                IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
            };
            list.push(primary);
        }
    }

    // Multi-provider IP-literal DoH ring across independent networks
    // (Cloudflare, Google, AdGuard Unfiltered, Quad9 — no SNI required, resilient to ISP IP blocks).
    // Keep IPv4 DoH endpoints ahead of IPv6 DoH endpoints unless the user explicitly configured
    // an IPv6 DNS server so Proxy mode and dual-stack TUN don't stick onto flaky IPv6 DoH.
    let fallbacks: &[&str] = if ipv4_only {
        &[
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://94.140.14.140/dns-query",
            "https://9.9.9.9/dns-query",
            "https://1.0.0.1/dns-query",
            "https://94.140.14.141/dns-query",
            "https://149.112.112.112/dns-query",
            "https://8.8.4.4/dns-query",
        ]
    } else if explicit_ipv6 {
        &[
            "https://[2606:4700:4700::1111]/dns-query",
            "https://[2001:4860:4860::8888]/dns-query",
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://94.140.14.140/dns-query",
            "https://9.9.9.9/dns-query",
            "https://1.0.0.1/dns-query",
            "https://94.140.14.141/dns-query",
            "https://149.112.112.112/dns-query",
            "https://8.8.4.4/dns-query",
        ]
    } else {
        &[
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://94.140.14.140/dns-query",
            "https://9.9.9.9/dns-query",
            "https://1.0.0.1/dns-query",
            "https://94.140.14.141/dns-query",
            "https://149.112.112.112/dns-query",
            "https://8.8.4.4/dns-query",
            "https://[2606:4700:4700::1111]/dns-query",
            "https://[2001:4860:4860::8888]/dns-query",
        ]
    };
    for fallback in fallbacks {
        if !list.iter().any(|x| x == fallback) {
            list.push((*fallback).to_string());
        }
    }

    if bound_http1 {
        // Bound TLS DoH speaks HTTP/1.1 ALPN; Quad9 rejects HTTP/1.1 with HTTP 505.
        list.retain(|ep| !is_http2_only_doh_endpoint(ep));
    }
    if require_ip_literal {
        list.retain(|ep| is_ip_literal_doh_endpoint(ep));
    }
    list
}

fn build_udp_dns_servers(dns_addr: &str, dns_port: u16, ipv4_only: bool) -> Vec<SocketAddr> {
    const V6_UDP_FALLBACKS: [Ipv6Addr; 2] = [
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    ];

    let mut servers = Vec::new();
    let effective_port = if dns_port == 0 { 53 } else { dns_port };
    let trimmed = dns_addr.trim();
    let raw_custom_ip = parse_bare_dns_ip(trimmed);
    let custom_ip = raw_custom_ip.filter(|ip| !ipv4_only || ip.is_ipv4());
    let explicit_ipv6 = raw_custom_ip.is_some_and(|ip| ip.is_ipv6())
        || parse_doh_url_validated(trimmed)
            .is_ok_and(|parsed| matches!(parsed.host, DohHost::Ip(IpAddr::V6(_))));

    let push_unique = |list: &mut Vec<SocketAddr>, sa: SocketAddr| {
        if !list.contains(&sa) {
            list.push(sa);
        }
    };

    // Put user-configured non-default custom bare IPs (e.g. 76.76.2.0 or corporate 10.0.0.53)
    // FIRST even on port 53, and always put any custom non-53 server or explicit IPv6 server first.
    if let Some(ip) = custom_ip {
        if effective_port != 53 || !is_unfiltered_default_dns_ip(ip) || ip.is_ipv6() {
            push_unique(&mut servers, SocketAddr::new(ip, effective_port));
        }
    }

    if explicit_ipv6 && !ipv4_only {
        for ip in V6_UDP_FALLBACKS {
            push_unique(&mut servers, SocketAddr::new(IpAddr::V6(ip), 53));
        }
    }

    // Non-standard ports (1253, 443, 5353) bypass transparent ISP port-53 DNS interceptors
    // on strict fiber and broadband networks worldwide. Keep all non-port-53 IPv4 servers
    // ahead of port-53 IPv6 servers unless the user explicitly configured an IPv6 DNS server.
    for (ip, port) in [
        (Ipv4Addr::new(77, 88, 8, 8), 1253),
        (Ipv4Addr::new(208, 67, 222, 222), 443),
        (Ipv4Addr::new(77, 88, 8, 1), 1253),
        (Ipv4Addr::new(208, 67, 220, 220), 443),
        (Ipv4Addr::new(208, 67, 222, 222), 5353),
    ] {
        push_unique(&mut servers, SocketAddr::new(IpAddr::V4(ip), port));
    }
    if let Some(ip) = custom_ip {
        push_unique(&mut servers, SocketAddr::new(ip, effective_port));
    }
    for (ip, port) in [
        (Ipv4Addr::new(1, 1, 1, 1), 53),
        (Ipv4Addr::new(8, 8, 8, 8), 53),
    ] {
        push_unique(&mut servers, SocketAddr::new(IpAddr::V4(ip), port));
    }
    if !explicit_ipv6 && !ipv4_only {
        for ip in V6_UDP_FALLBACKS {
            push_unique(&mut servers, SocketAddr::new(IpAddr::V6(ip), 53));
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
                        | [195, 175, 254, 2]
                )
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_poisoned_public_ip(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // Well-known NAT64 prefix 64:ff9b::/96 (RFC 6052): inspect embedded IPv4.
            if segs[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                let octets = v6.octets();
                let embedded_v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_poisoned_public_ip(IpAddr::V4(embedded_v4));
            }
            v6.is_unspecified()
                || v6.is_loopback()
                // RFC 6666 discard-only prefix 100::/64
                || segs[..4] == [0x0100, 0, 0, 0]
        }
    }
}

/// DoH-specific poisoning check: authenticated DoH replies legitimately return loopback
/// (`127.0.0.0/8`, `::1` for `lvh.me`, `nip.io`, `sslip.io`, `localtest.me`), and custom or
/// filtering DoH endpoints intentionally return `0.0.0.0` / `::` to block ads/trackers.
fn is_poisoned_doh_ip(ip: IpAddr, allow_sinkhole: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            (!allow_sinkhole && v4.is_unspecified())
                || v4.is_broadcast()
                || matches!(
                    v4.octets(),
                    [198, 18 | 19, ..]
                        | [195, 175, 39, 39]
                        | [195, 175, 39, 40]
                        | [195, 175, 39, 49]
                        | [195, 175, 39, 50]
                        | [195, 175, 254, 2]
                )
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_poisoned_doh_ip(IpAddr::V4(v4), allow_sinkhole);
            }
            let segs = v6.segments();
            if segs[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                let octets = v6.octets();
                let embedded_v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_poisoned_doh_ip(IpAddr::V4(embedded_v4), allow_sinkhole);
            }
            (!allow_sinkhole && v6.is_unspecified()) || segs[..4] == [0x0100, 0, 0, 0]
        }
    }
}

fn filter_poisoned_ips(ips: Vec<IpAddr>) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| !is_poisoned_public_ip(*ip))
        .collect()
}

fn filter_poisoned_doh_ips(ips: Vec<IpAddr>, allow_sinkhole: bool) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|ip| !is_poisoned_doh_ip(*ip, allow_sinkhole))
        .collect()
}

fn filter_poisoned_udp_ips(ips: Vec<IpAddr>, allow_sinkhole_and_loopback: bool) -> Vec<IpAddr> {
    if allow_sinkhole_and_loopback {
        filter_poisoned_doh_ips(ips, true)
    } else {
        filter_poisoned_ips(ips)
    }
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
            aaaa_retry_after: None,
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
            aaaa_retry_after: None,
            expires_at: expired_at,
        };
        let active = CacheEntry {
            ips: vec![Ipv4Addr::LOCALHOST.into()],
            nxdomain: false,
            has_a_lookup: true,
            has_aaaa_lookup: true,
            aaaa_retry_after: None,
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
        assert!(is_poisoned_public_ip("195.175.254.2".parse().unwrap()));
        assert!(is_poisoned_public_ip("198.18.0.1".parse().unwrap()));
        assert!(is_poisoned_public_ip("198.19.255.254".parse().unwrap()));
        assert!(is_poisoned_public_ip("100::".parse().unwrap()));
        assert!(is_poisoned_public_ip("100::1".parse().unwrap()));
        assert!(!is_poisoned_public_ip("100:0:0:1::1".parse().unwrap()));
        assert!(is_poisoned_public_ip("64:ff9b::195.175.254.2".parse().unwrap()));
        assert!(is_poisoned_public_ip("64:ff9b::0.0.0.0".parse().unwrap()));
        assert!(is_poisoned_public_ip("64:ff9b::127.0.0.1".parse().unwrap()));
        assert!(!is_poisoned_public_ip("64:ff9b::1.1.1.1".parse().unwrap()));
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
        let endpoints = build_doh_endpoints("2606:4700:4700::1111", false, false, false);
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
        // Loopback targets (127.0.0.0/8) skip outbound_binder so local dnsmasq/Unbound works in TUN mode.
        assert_eq!(counter.calls.load(Ordering::Relaxed), 0);
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

        let decoded = decode_http_chunked_body(b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n", 64)
            .unwrap()
            .unwrap();
        assert_eq!(decoded, b"abcdef");
    }

    #[test]
    fn decode_http_chunked_body_handles_chunks_extensions_trailers_and_errors() {
        let multi =
            decode_http_chunked_body(b"4;ext=1\r\nabcd\r\nA\r\n0123456789\r\n0\r\n\r\n", 64)
                .unwrap()
                .unwrap();
        assert_eq!(multi, b"abcd0123456789");

        let with_trailers = decode_http_chunked_body(b"3\r\ndns\r\n0\r\nX-Trailer: ok\r\n\r\n", 64)
            .unwrap()
            .unwrap();
        assert_eq!(with_trailers, b"dns");

        let empty = decode_http_chunked_body(b"0\r\n\r\n", 64).unwrap().unwrap();
        assert!(empty.is_empty());

        assert!(decode_http_chunked_body(b"4\r\nab", 64).unwrap().is_none());
        assert!(decode_http_chunked_body(b"4\r\nabcd\r\n0\r\n", 64)
            .unwrap()
            .is_none());
        assert!(decode_http_chunked_body(b"0\r\nX-Trailer: ok\r\n", 64)
            .unwrap()
            .is_none());

        assert!(decode_http_chunked_body(b"z\r\n\r\n", 64).is_err());
        assert!(decode_http_chunked_body(b"+4\r\nabcd\r\n0\r\n\r\n", 64).is_err());
        assert!(decode_http_chunked_body(b"\r\n", 64).is_err());
        assert!(decode_http_chunked_body(b"4\r\nabcdXX0\r\n\r\n", 64).is_err());
        assert!(decode_http_chunked_body(b"5\r\nhello\r\n0\r\n\r\n", 4).is_err());
    }

    #[test]
    fn parse_http_doh_response_handles_content_length_chunked_and_eof() {
        let endpoint = "https://1.1.1.1/dns-query";

        // Content-Length (case-insensitive): incremental arrival and fast return before EOF.
        let mut head = None;
        let mut raw = b"HTTP/1.1 200 OK\r\ncOnTeNt-LeNgTh: 6\r\n".to_vec();
        assert!(parse_http_doh_response(&raw, &mut head, endpoint, false)
            .unwrap()
            .is_none());
        raw.extend_from_slice(b"\r\nab");
        assert!(parse_http_doh_response(&raw, &mut head, endpoint, false)
            .unwrap()
            .is_none());
        assert!(parse_http_doh_response(&raw, &mut head, endpoint, true).is_err());
        raw.extend_from_slice(b"cdefEXTRA");
        let body = parse_http_doh_response(&raw, &mut head, endpoint, false)
            .unwrap()
            .unwrap();
        assert_eq!(body, b"abcdef");

        // Transfer-Encoding: chunked (case-insensitive): incremental decode and fast return before EOF.
        let mut chunked_head = None;
        let mut chunked_raw =
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: gzip, CHUNKED\r\n\r\n4\r\nabcd\r\n".to_vec();
        assert!(
            parse_http_doh_response(&chunked_raw, &mut chunked_head, endpoint, false)
                .unwrap()
                .is_none()
        );
        assert!(parse_http_doh_response(&chunked_raw, &mut chunked_head, endpoint, true).is_err());
        chunked_raw.extend_from_slice(b"2\r\nef\r\n0\r\n\r\n");
        let chunked_body =
            parse_http_doh_response(&chunked_raw, &mut chunked_head, endpoint, false)
                .unwrap()
                .unwrap();
        assert_eq!(chunked_body, b"abcdef");

        // Fallback to EOF when neither Content-Length nor Transfer-Encoding: chunked is present.
        let mut eof_head = None;
        let eof_raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\nraw-dns";
        assert!(
            parse_http_doh_response(eof_raw, &mut eof_head, endpoint, false)
                .unwrap()
                .is_none()
        );
        let eof_body = parse_http_doh_response(eof_raw, &mut eof_head, endpoint, true)
            .unwrap()
            .unwrap();
        assert_eq!(eof_body, b"raw-dns");

        // Conflicting Content-Length and malformed status line are rejected.
        let mut bad_head = None;
        assert!(parse_http_doh_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nabcd",
            &mut bad_head,
            endpoint,
            true,
        )
        .is_err());
        let mut bad_status_head = None;
        assert!(parse_http_doh_response(
            b"BAD 200 OK\r\nContent-Length: 0\r\n\r\n",
            &mut bad_status_head,
            endpoint,
            true,
        )
        .is_err());
    }

    #[tokio::test]
    async fn send_doh_bound_tls_fast_returns_on_content_length_and_decodes_chunked() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (cl_release_tx, cl_release_rx) = tokio::sync::oneshot::channel::<()>();
        let (chunked_release_tx, chunked_release_rx) = tokio::sync::oneshot::channel::<()>();

        let server_task = tokio::spawn(async move {
            // 1. Content-Length response held open (no FIN/close_notify until released).
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
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
            let http_resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                wire_resp.len()
            );
            tls.write_all(http_resp.as_bytes()).await.unwrap();
            tls.write_all(&wire_resp).await.unwrap();
            tls.flush().await.unwrap();
            let _ = cl_release_rx.await;
            drop(tls);

            // 2. Chunked HTTP/1.1 response split across two flushes and held open.
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let parsed = parse_dns_question(&query).unwrap();
            let wire_resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &query[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
                60,
            );
            let mid = wire_resp.len() / 2;
            let chunk1_head = format!("{mid:x}\r\n");
            let chunk2_head = format!("{:x}\r\n", wire_resp.len() - mid);
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
            tls.write_all(chunk1_head.as_bytes()).await.unwrap();
            tls.write_all(&wire_resp[..mid]).await.unwrap();
            tls.write_all(b"\r\n").await.unwrap();
            tls.flush().await.unwrap();
            tls.write_all(chunk2_head.as_bytes()).await.unwrap();
            tls.write_all(&wire_resp[mid..]).await.unwrap();
            tls.write_all(b"\r\n0\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
            let _ = chunked_release_rx.await;
            drop(tls);
        });

        let binder = NoopBinder;
        let endpoint = format!("https://127.0.0.1:{}/dns-query", addr.port());

        let q1 = encode_dns_query("fast-cl.example", QTYPE_A).unwrap();
        let raw_cl = send_doh_bound_tls(&binder, &connector, &endpoint, &q1)
            .await
            .unwrap();
        let _ = cl_release_tx.send(());
        let (ips_cl, _) = decode_dns_response(&raw_cl, QTYPE_A).unwrap();
        assert_eq!(ips_cl, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);

        let q2 = encode_dns_query("chunked-doh.example", QTYPE_A).unwrap();
        let raw_chunked = send_doh_bound_tls(&binder, &connector, &endpoint, &q2)
            .await
            .unwrap();
        let _ = chunked_release_tx.send(());
        let (ips_chunked, _) = decode_dns_response(&raw_chunked, QTYPE_A).unwrap();
        assert_eq!(ips_chunked, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        server_task.await.unwrap();
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

        // Loopback targets skip outbound_binder so local DNS servers work in TUN mode.
        assert_eq!(binder.calls.load(Ordering::Relaxed), 0);
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

    #[test]
    fn bound_doh_skips_quad9_http2_only_endpoints() {
        let bound_q9 = build_doh_endpoints("9.9.9.9", true, true, false);
        assert!(!bound_q9.is_empty());
        assert!(!bound_q9.iter().any(|ep| ep.contains("9.9.9.9")));
        assert!(!bound_q9.iter().any(|ep| ep.contains("149.112.112.112")));
        assert!(bound_q9.iter().any(|ep| ep == "https://1.1.1.1/dns-query"));

        let bound_q9_alt = build_doh_endpoints("149.112.112.112", true, true, false);
        assert!(!bound_q9_alt.iter().any(|ep| ep.contains("9.9.9.9")));
        assert!(!bound_q9_alt.iter().any(|ep| ep.contains("149.112.112.112")));

        let unbound_q9 = build_doh_endpoints("9.9.9.9", false, false, false);
        assert_eq!(unbound_q9[0], "https://9.9.9.9/dns-query");
        assert!(unbound_q9
            .iter()
            .any(|ep| ep == "https://149.112.112.112/dns-query"));

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let resolver =
            DnsResolver::new_with_binder("9.9.9.9", 53, true, false, Some(binder)).unwrap();
        assert!(!resolver
            .doh_endpoints
            .iter()
            .any(|ep| ep.contains("9.9.9.9") || ep.contains("149.112.112.112")));
    }

    #[test]
    fn build_dns_wire_response_appends_rfc2308_soa_for_negative_replies() {
        let q = encode_dns_query("nodata.example", QTYPE_HTTPS).unwrap();
        let question_slice = &q[12..];

        for (rcode, ttl_secs) in [(0u8, 60u32), (3u8, 30u32)] {
            let resp =
                build_dns_wire_response(0x1234, 0x0100, question_slice, rcode, &[], ttl_secs);
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
            assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 1);
            let auth = &resp[12 + question_slice.len()..];
            assert_eq!(auth.len(), 35);
            assert_eq!(&auth[0..2], &[0xc0, 0x0c]);
            assert_eq!(u16::from_be_bytes([auth[2], auth[3]]), QTYPE_SOA);
            assert_eq!(u16::from_be_bytes([auth[4], auth[5]]), QCLASS_IN);
            assert_eq!(
                u32::from_be_bytes([auth[6], auth[7], auth[8], auth[9]]),
                ttl_secs
            );
            assert_eq!(u16::from_be_bytes([auth[10], auth[11]]), 23);
            assert_eq!(&auth[12..14], &[0xc0, 0x0c]);
            assert_eq!(auth[14], 0x00);
            assert_eq!(
                u32::from_be_bytes([auth[15], auth[16], auth[17], auth[18]]),
                1
            );
            assert_eq!(
                u32::from_be_bytes([auth[19], auth[20], auth[21], auth[22]]),
                3600
            );
            assert_eq!(
                u32::from_be_bytes([auth[23], auth[24], auth[25], auth[26]]),
                600
            );
            assert_eq!(
                u32::from_be_bytes([auth[27], auth[28], auth[29], auth[30]]),
                86400
            );
            assert_eq!(
                u32::from_be_bytes([auth[31], auth[32], auth[33], auth[34]]),
                ttl_secs
            );
        }

        let positive = build_dns_wire_response(
            0x1234,
            0x0100,
            question_slice,
            0,
            &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            60,
        );
        assert_eq!(u16::from_be_bytes([positive[8], positive[9]]), 0);

        let servfail = build_dns_wire_response(0x1234, 0x0100, question_slice, 2, &[], 60);
        assert_eq!(u16::from_be_bytes([servfail[8], servfail[9]]), 0);

        let zero_ttl = build_dns_wire_response(0x1234, 0x0100, question_slice, 0, &[], 0);
        assert_eq!(u16::from_be_bytes([zero_ttl[8], zero_ttl[9]]), 0);
    }

    #[tokio::test]
    async fn send_udp_dns_raw_skips_stray_packets_and_raw_queries_fail_over() {
        // Unit checks for raw DNS reply validation helper.
        assert!(!is_valid_raw_dns_reply(&[0u8; 11], false));
        let mut hdr = [0u8; 12];
        hdr[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // QR=0
        assert!(!is_valid_raw_dns_reply(&hdr, false));
        hdr[2..4].copy_from_slice(&0x8182u16.to_be_bytes()); // SERVFAIL
        assert!(!is_valid_raw_dns_reply(&hdr, false));
        hdr[2..4].copy_from_slice(&0x8185u16.to_be_bytes()); // REFUSED
        assert!(!is_valid_raw_dns_reply(&hdr, false));
        hdr[2..4].copy_from_slice(&0x8380u16.to_be_bytes()); // TC=1
        assert!(!is_valid_raw_dns_reply(&hdr, true));
        assert!(is_valid_raw_dns_reply(&hdr, false));
        hdr[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // NOERROR
        assert!(is_valid_raw_dns_reply(&hdr, true));
        hdr[2..4].copy_from_slice(&0x8183u16.to_be_bytes()); // NXDOMAIN
        assert!(is_valid_raw_dns_reply(&hdr, true));

        // 1. send_udp_dns_raw skips short, mismatched-TXID, and QR=0 datagrams.
        let stray_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stray_addr = stray_server.local_addr().unwrap();
        let stray_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = stray_server.recv_from(&mut buf).await.unwrap();
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            let qslice = &buf[12..parsed.question_end];
            // Short packet
            stray_server.send_to(&[0u8; 4], peer).await.unwrap();
            // Wrong TXID
            let wrong_tx = build_dns_wire_response(
                parsed.tx_id ^ 0xffff,
                parsed.flags,
                qslice,
                0,
                &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
                60,
            );
            stray_server.send_to(&wrong_tx, peer).await.unwrap();
            // Matching TXID but QR=0
            let mut qr0 = buf[..n].to_vec();
            qr0[2] &= 0x7f;
            stray_server.send_to(&qr0, peer).await.unwrap();
            // Valid response
            let good = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                qslice,
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            stray_server.send_to(&good, peer).await.unwrap();
        });

        let q = encode_dns_query("stray-udp.example", QTYPE_A).unwrap();
        let stray_resp = send_udp_dns_raw(stray_addr, &q, None).await.unwrap();
        stray_task.await.unwrap();
        let (ips, _) = decode_dns_response(&stray_resp, QTYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);

        // 2. query_udp_raw fails over SERVFAIL, REFUSED, TC=1 past index 3 (beyond old .min(3) cap).
        let s0 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a0 = s0.local_addr().unwrap();
        let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a1 = s1.local_addr().unwrap();
        let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a2 = s2.local_addr().unwrap();
        let s3 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a3 = s3.local_addr().unwrap();

        let t0 = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = s0.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp =
                build_dns_wire_response(p.tx_id, p.flags, &buf[12..p.question_end], 2, &[], 0);
            s0.send_to(&resp, peer).await.unwrap();
        });
        let t1 = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = s1.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp =
                build_dns_wire_response(p.tx_id, p.flags, &buf[12..p.question_end], 5, &[], 0);
            s1.send_to(&resp, peer).await.unwrap();
        });
        let t2 = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = s2.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let mut resp =
                build_dns_wire_response(p.tx_id, p.flags, &buf[12..p.question_end], 0, &[], 0);
            resp[2] |= 0x02; // TC=1
            s2.send_to(&resp, peer).await.unwrap();
        });
        let t3 = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = s3.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            s3.send_to(&resp, peer).await.unwrap();
        });

        let mut resolver = DnsResolver::new("127.0.0.1", 53, false, true).unwrap();
        resolver.udp_dns_servers = vec![a0, a1, a2, a3];
        let raw_udp = resolver.query_udp_raw(&q).await.unwrap();
        t0.await.unwrap();
        t1.await.unwrap();
        t2.await.unwrap();
        t3.await.unwrap();
        let (udp_ips, _) = decode_dns_response(&raw_udp, QTYPE_A).unwrap();
        assert_eq!(udp_ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(resolver.preferred_udp_idx.load(Ordering::Relaxed), 3);

        // 3. query_doh_raw rejects REFUSED (RCODE=5) and fails over to the next DoH endpoint.
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let refused_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_cfg));
        let ok_acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let refused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused_addr = refused_listener.local_addr().unwrap();
        let ok_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = ok_listener.local_addr().unwrap();

        let refused_task = tokio::spawn(async move {
            let (tcp, _) = refused_listener.accept().await.unwrap();
            let mut tls = refused_acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let p = parse_dns_question(&query).unwrap();
            let wire_resp =
                build_dns_wire_response(p.tx_id, p.flags, &query[12..p.question_end], 5, &[], 0);
            write_doh_test_response(&mut tls, &wire_resp).await;
        });
        let ok_task = tokio::spawn(async move {
            let (tcp, _) = ok_listener.accept().await.unwrap();
            let mut tls = ok_acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let p = parse_dns_question(&query).unwrap();
            let wire_resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &query[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                60,
            );
            write_doh_test_response(&mut tls, &wire_resp).await;
        });

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut doh_resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder)).unwrap();
        doh_resolver.bound_tls_connector = Some(connector);
        doh_resolver.doh_endpoints = vec![
            format!("https://127.0.0.1:{}/dns-query", refused_addr.port()),
            format!("https://127.0.0.1:{}/dns-query", ok_addr.port()),
        ];
        let raw_doh = doh_resolver.query_doh_raw(&q).await.unwrap();
        refused_task.await.unwrap();
        ok_task.await.unwrap();
        let (doh_ips, _) = decode_dns_response(&raw_doh, QTYPE_A).unwrap();
        assert_eq!(doh_ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(doh_resolver.preferred_doh_idx.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn disable_system_dns_fallback_blocks_os_dns_without_forcing_bound_tls() {
        let mut resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, false, true, None).unwrap();
        resolver.udp_dns_servers = Vec::new();

        assert!(resolver.outbound_binder.is_none());
        assert!(resolver.bound_tls_connector.is_none());
        assert!(resolver.is_system_dns_disabled());

        // Direct system lookup must fail closed even when outbound_binder is None.
        assert!(resolver
            .resolve_via_system("localhost", false)
            .await
            .is_err());

        // `.local` must return synthetic NXDOMAIN without calling OS resolver.
        assert!(matches!(
            resolver
                .resolve_outcome("printer.local", false)
                .await
                .unwrap(),
            DnsOutcome::NxDomain(_)
        ));
        assert!(resolver.resolve("printer.local").await.is_err());

        // UDP fallback paths must fail closed instead of falling back to OS lookup_host.
        assert!(resolver.resolve_udp_or_system("example.com").await.is_err());
        assert!(resolver
            .resolve_single_qtype("example.com", QTYPE_A, false, false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn hostname_doh_filtering_and_ipv6_doh_fallback_endpoints() {
        let v6_cf = "https://[2606:4700:4700::1111]/dns-query";
        let v6_google = "https://[2001:4860:4860::8888]/dns-query";

        // When system DNS fallback is disabled (e.g. iOS TUN with outbound_binder == None),
        // hostname-based custom DoH URLs are stripped to prevent GaiResolver -> utun deadlocks,
        // pooled HTTP/2 Quad9 remains enabled, and all IPv4 DoH endpoints stay ahead of IPv6
        // fallbacks unless IPv6 was explicitly configured.
        let strict = build_doh_endpoints("https://dns.google/dns-query", false, true, false);
        assert!(!strict.iter().any(|ep| ep.contains("dns.google")));
        assert!(strict.iter().all(|ep| is_ip_literal_doh_endpoint(ep)));
        assert!(strict.iter().any(|ep| ep == "https://9.9.9.9/dns-query"));
        assert_eq!(strict[0], "https://1.1.1.1/dns-query");
        let v6_cf_pos = strict.iter().position(|ep| ep == v6_cf).unwrap();
        let v6_google_pos = strict.iter().position(|ep| ep == v6_google).unwrap();
        assert!(
            strict[..v6_cf_pos]
                .iter()
                .all(|ep| !is_ipv6_doh_endpoint(ep)),
            "IPv4 DoH endpoints must precede IPv6 fallbacks by default: {strict:?}"
        );
        assert!(v6_cf_pos < v6_google_pos);

        // Explicitly configuring an IPv6 DNS server keeps IPv6 DoH endpoints ahead of IPv4.
        let explicit_v6 = build_doh_endpoints("2606:4700:4700::1111", false, true, false);
        assert_eq!(explicit_v6[0], v6_cf);
        assert_eq!(explicit_v6[1], v6_google);

        // When system DNS fallback is enabled (proxy mode), custom hostname DoH URLs are kept.
        let permissive = build_doh_endpoints("https://dns.google/dns-query", false, false, false);
        assert_eq!(permissive[0], "https://dns.google/dns-query");
        assert!(permissive.iter().any(|ep| ep == v6_cf));
        assert!(permissive.iter().any(|ep| ep == v6_google));

        // When ipv4_only is set, IPv6 DoH fallbacks are omitted.
        let v4_only = build_doh_endpoints("1.1.1.1", false, true, true);
        assert!(!v4_only.iter().any(|ep| ep == v6_cf));
        assert!(!v4_only.iter().any(|ep| ep == v6_google));

        // DnsResolver::new_with_options filters hostname DoH and rejects it at send time too.
        let resolver = DnsResolver::new_with_options(
            "https://dns.google/dns-query",
            53,
            true,
            false,
            true,
            None,
        )
        .unwrap();
        assert!(!resolver
            .doh_endpoints
            .iter()
            .any(|ep| ep.contains("dns.google")));
        assert!(resolver.doh_endpoints.iter().any(|ep| ep == v6_cf));
        assert!(resolver.doh_endpoints.iter().any(|ep| ep == v6_google));

        let q = encode_dns_query("example.com", QTYPE_A).unwrap();
        assert!(send_doh_request_raw(
            &resolver.http_client(),
            "https://dns.google/dns-query",
            &q,
            true
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn doh_failover_caps_concurrent_backup_attempts_at_two() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak_in_flight = Arc::new(AtomicUsize::new(0));

        let mut endpoints = Vec::new();
        let mut tasks = Vec::new();

        for idx in 0..4usize {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_cfg));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            endpoints.push(format!("https://127.0.0.1:{}/dns-query", addr.port()));

            let in_flight_srv = Arc::clone(&in_flight);
            let peak_srv = Arc::clone(&peak_in_flight);
            tasks.push(tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();

                if idx > 0 {
                    let cur = in_flight_srv.fetch_add(1, Ordering::SeqCst) + 1;
                    peak_srv.fetch_max(cur, Ordering::SeqCst);
                    let delay_ms = if idx == 1 { 20 } else { 40 };
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    in_flight_srv.fetch_sub(1, Ordering::SeqCst);
                }

                let ip = if idx == 3 {
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
                } else {
                    IpAddr::V4(Ipv4Addr::new(195, 175, 39, 39))
                };
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    0,
                    &[ip],
                    60,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }));
        }

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder)).unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.doh_endpoints = endpoints;
        resolver.udp_dns_servers = Vec::new();

        let ips = resolver.resolve("bounded-failover.example").await.unwrap();
        for task in tasks {
            task.await.unwrap();
        }

        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(resolver.preferred_doh_idx.load(Ordering::Relaxed), 3);
        assert!(
            peak_in_flight.load(Ordering::SeqCst) <= MAX_DOH_FAILOVER_CONCURRENCY,
            "DoH failover exceeded 2 concurrent backup requests: peak={}",
            peak_in_flight.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn validate_custom_dns_input_accepts_and_normalizes_ipv4_ipv6_and_doh_urls() {
        // IPv4
        assert_eq!(validate_custom_dns_input("76.76.2.0").unwrap(), "76.76.2.0");
        assert_eq!(
            validate_custom_dns_input("  94.140.14.15  ").unwrap(),
            "94.140.14.15"
        );
        assert_eq!(validate_custom_dns_input("127.0.0.1").unwrap(), "127.0.0.1");

        // IPv6 (bare, bracketed, and unnormalized)
        assert_eq!(
            validate_custom_dns_input("2606:4700:4700::1111").unwrap(),
            "2606:4700:4700::1111"
        );
        assert_eq!(
            validate_custom_dns_input("[2606:4700:4700::1111]").unwrap(),
            "2606:4700:4700::1111"
        );
        assert_eq!(
            validate_custom_dns_input("[2606:4700:4700:0000:0000:0000:0000:1111]").unwrap(),
            "2606:4700:4700::1111"
        );
        assert_eq!(validate_custom_dns_input("::1").unwrap(), "::1");

        // Custom https:// DoH URLs (hostnames, IP literals, ports, paths, queries)
        assert_eq!(
            validate_custom_dns_input("https://dns.nextdns.io/abc123").unwrap(),
            "https://dns.nextdns.io/abc123"
        );
        assert_eq!(
            validate_custom_dns_input("  HTTPS://DNS.NextDNS.io/AbC123  ").unwrap(),
            "https://dns.nextdns.io/AbC123"
        );
        assert_eq!(
            validate_custom_dns_input("https://freedns.controld.com/p2").unwrap(),
            "https://freedns.controld.com/p2"
        );
        assert_eq!(
            validate_custom_dns_input("https://1.1.1.1/dns-query").unwrap(),
            "https://1.1.1.1/dns-query"
        );
        assert_eq!(
            validate_custom_dns_input("https://dns.quad9.net:443/dns-query").unwrap(),
            "https://dns.quad9.net:443/dns-query"
        );
        assert_eq!(
            validate_custom_dns_input("https://[2606:4700:4700:0::1111]:8443/dns-query").unwrap(),
            "https://[2606:4700:4700::1111]:8443/dns-query"
        );
        assert_eq!(
            validate_custom_dns_input("https://doh.example.com/dns-query?token=a1_b2").unwrap(),
            "https://doh.example.com/dns-query?token=a1_b2"
        );
        assert_eq!(
            validate_custom_dns_input("https://dns.nextdns.io").unwrap(),
            "https://dns.nextdns.io"
        );
    }

    #[test]
    fn validate_custom_dns_input_rejects_invalid_schemes_ips_whitespace_and_garbage() {
        let invalid_cases = [
            "",
            "   ",
            "76.76.2.0 1.1.1.1",
            "https://dns.nextdns.io/abc 123",
            "76.76.2.0\x00",
            "\x1b76.76.2.0",
            "https://dns.nextdns.io/abc\r\nX-Injected: 1",
            "0.0.0.0",
            "::",
            "[::]",
            "::ffff:0.0.0.0",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "https://0.0.0.0/dns-query",
            "https://[::]/dns-query",
            "https://224.0.0.1/dns-query",
            "http://1.1.1.1/dns-query",
            "http://dns.nextdns.io/abc123",
            "HTTP://dns.google/dns-query",
            "ftp://1.1.1.1/dns-query",
            "https://",
            "https:///dns-query",
            "https://garbage",
            "https://999.999.999.999/dns-query",
            "https://-bad.example.com/dns-query",
            "https://bad-.example.com/dns-query",
            "https://a..b.com/dns-query",
            "https://dns.quad9.net:0/dns-query",
            "https://dns.quad9.net:65536/dns-query",
            "https://dns.quad9.net:abc/dns-query",
            "https://dns.quad9.net:/dns-query",
            "https://user:pass@dns.nextdns.io/abc123",
            "https://dns.nextdns.io/abc123#frag",
            "https://dns.nextdns.io/abc%ZZ",
            "https://2606:4700:4700::1111/dns-query",
            "[1.1.1.1]",
            "[2606:4700:4700::1111",
            "not-a-dns",
            "999.999.999.999",
        ];

        for raw in invalid_cases {
            let err = validate_custom_dns_input(raw)
                .expect_err(&format!("expected invalid custom DNS input: {raw:?}"));
            assert!(
                !err.is_empty(),
                "error message should be non-empty for {raw:?}"
            );
        }
    }

    #[test]
    fn custom_ip_and_custom_doh_resolver_configuration() {
        // Arbitrary custom IPv4 (e.g. Control D 76.76.2.0) does NOT synthesize a broken
        // IP-SAN DoH URL; instead it queries UDP/53 first and falls back to public DoH.
        let r_v4 = DnsResolver::new("76.76.2.0", 53, true, false).unwrap();
        assert!(r_v4.custom_doh.is_none());
        assert!(!r_v4.doh_endpoints.iter().any(|ep| ep.contains("76.76.2.0")));
        assert_eq!(r_v4.doh_endpoints[0], "https://1.1.1.1/dns-query");
        assert_eq!(
            r_v4.custom_udp_primary,
            Some("76.76.2.0:53".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            r_v4.udp_dns_servers[0],
            "76.76.2.0:53".parse::<SocketAddr>().unwrap()
        );

        // Arbitrary custom IPv6 with brackets and custom UDP port
        let r_v6 = DnsResolver::new("[2606:4700:4700:0::1111]", 5353, true, false).unwrap();
        assert!(r_v6.custom_doh.is_none());
        assert_eq!(
            r_v6.doh_endpoints[0],
            "https://[2606:4700:4700::1111]/dns-query"
        );
        assert_eq!(
            r_v6.udp_dns_servers[0],
            "[2606:4700:4700::1111]:5353".parse::<SocketAddr>().unwrap()
        );

        // Custom hostname DoH URL in strict TUN mode: custom_doh is active while doh_endpoints
        // stays strictly IP-literal for zero-deadlock bootstrapping and fallback.
        let r_nextdns = DnsResolver::new_with_options(
            "https://dns.nextdns.io/abc123",
            53,
            true,
            false,
            true,
            None,
        )
        .unwrap();
        let custom = r_nextdns
            .custom_doh
            .as_ref()
            .expect("custom hostname DoH must be configured");
        assert_eq!(custom.host, "dns.nextdns.io");
        assert_eq!(custom.port, 443);
        assert_eq!(custom.host_header, "dns.nextdns.io");
        assert_eq!(custom.path_and_query, "/abc123");
        assert_eq!(custom.request_url, "https://dns.nextdns.io/abc123");
        assert!(r_nextdns
            .doh_endpoints
            .iter()
            .all(|ep| is_ip_literal_doh_endpoint(ep)));

        // Custom DoH URL with explicit :443 port and path
        let r_q9 =
            DnsResolver::new("https://dns.quad9.net:443/dns-query", 53, true, false).unwrap();
        let q9_custom = r_q9.custom_doh.as_ref().unwrap();
        assert_eq!(q9_custom.host, "dns.quad9.net");
        assert_eq!(q9_custom.port, 443);
        assert_eq!(q9_custom.host_header, "dns.quad9.net");
        assert_eq!(q9_custom.path_and_query, "/dns-query");

        // Unusable IP (0.0.0.0) passed directly is ignored in favor of healthy defaults.
        let r_unspec = DnsResolver::new("0.0.0.0", 53, true, false).unwrap();
        assert_eq!(r_unspec.doh_endpoints[0], "https://1.1.1.1/dns-query");
        assert!(!r_unspec
            .udp_dns_servers
            .iter()
            .any(|sa| sa.ip().is_unspecified()));
    }

    #[tokio::test]
    async fn custom_hostname_doh_bootstraps_via_ip_literal_ring_and_avoids_self_deadlock() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let bootstrap_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bootstrap_addr = bootstrap_listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = bootstrap_listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                assert_eq!(parsed.qname, "dns.nextdns.io");
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    0,
                    &[IpAddr::V4(Ipv4Addr::new(45, 90, 28, 10))],
                    300,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver = DnsResolver::new_with_binder(
            "https://dns.nextdns.io/abc123",
            53,
            true,
            true,
            Some(binder),
        )
        .unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.doh_endpoints = vec![format!(
            "https://127.0.0.1:{}/dns-query",
            bootstrap_addr.port()
        )];
        resolver.udp_dns_servers = Vec::new();

        // 1. Bootstrapping resolves dns.nextdns.io via the IP-literal ring (no OS DNS, no recursion).
        let custom = resolver.custom_doh.as_ref().unwrap();
        let (bootstrapped_ips, _) = resolver
            .ensure_custom_doh_bootstrapped(custom)
            .await
            .unwrap();
        assert_eq!(
            bootstrapped_ips,
            vec![IpAddr::V4(Ipv4Addr::new(45, 90, 28, 10))]
        );

        // 2. Resolving the DoH host itself bypasses custom_doh and uses the IP-literal ring directly.
        let self_ips = resolver.resolve("dns.nextdns.io").await.unwrap();
        assert_eq!(self_ips, vec![IpAddr::V4(Ipv4Addr::new(45, 90, 28, 10))]);

        server_task.await.unwrap();
    }

    fn make_hostname_doh_tls_pair(
        hostname: &str,
    ) -> (Arc<rustls::ServerConfig>, TlsConnector, Vec<u8>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert_key = rcgen::generate_simple_self_signed(vec![hostname.to_string()]).unwrap();
        let cert_der_bytes = cert_key.cert.der().to_vec();
        let cert_der = CertificateDer::from(cert_der_bytes.clone());
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
            cert_der_bytes,
        )
    }

    #[tokio::test]
    async fn custom_hostname_doh_works_over_bound_and_pinned_http_and_fails_over() {
        let hostname = "custom-doh.example";
        let (custom_server_cfg, custom_connector, custom_cert_der) =
            make_hostname_doh_tls_pair(hostname);
        let custom_acceptor = tokio_rustls::TlsAcceptor::from(custom_server_cfg);
        let custom_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let custom_addr = custom_listener.local_addr().unwrap();
        let custom_url = format!("https://{hostname}:{}/abc123", custom_addr.port());

        let custom_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = custom_listener.accept().await.unwrap();
                let mut tls = custom_acceptor.accept(tcp).await.unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 2048];
                let (head_end, body_len) = loop {
                    let n = tls.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    req.extend_from_slice(&buf[..n]);
                    if let Some(pos) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = std::str::from_utf8(&req[..pos]).unwrap();
                        assert!(
                            head.starts_with("POST /abc123 HTTP/1.1\r\n"),
                            "unexpected custom DoH request line: {head}"
                        );
                        assert!(
                            head.to_ascii_lowercase()
                                .contains("host: custom-doh.example"),
                            "missing custom Host header: {head}"
                        );
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
                    &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                    120,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        // 1. Bound TUN mode: connects to bootstrapped IP with SNI=custom-doh.example and custom path.
        let counter = Arc::new(CountingBinder::default());
        let binder: Arc<dyn OutboundBinder> = counter.clone();
        let mut bound_resolver =
            DnsResolver::new_with_binder(&custom_url, 53, true, true, Some(binder)).unwrap();
        bound_resolver.bound_tls_connector = Some(custom_connector);
        bound_resolver.doh_endpoints = Vec::new();
        bound_resolver.udp_dns_servers = Vec::new();
        {
            let custom = bound_resolver.custom_doh.as_ref().unwrap();
            let mut state = custom.state.write().await;
            state.ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
            state.expires_at = Instant::now() + Duration::from_secs(300);
        }
        let bound_ips = bound_resolver
            .resolve("bound-target.example")
            .await
            .unwrap();
        assert_eq!(bound_ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        // Loopback target skips outbound_binder.
        assert_eq!(counter.calls.load(Ordering::Relaxed), 0);

        // 2. Unbound TUN mode (disable_system_dns_fallback = true): uses reqwest resolve_to_addrs
        //    pinned to the bootstrapped IP so zero OS DNS lookup occurs.
        let mut pinned_resolver =
            DnsResolver::new_with_options(&custom_url, 53, true, true, true, None).unwrap();
        pinned_resolver.test_root_cert_der = Some(custom_cert_der);
        pinned_resolver.doh_endpoints = Vec::new();
        pinned_resolver.udp_dns_servers = Vec::new();
        {
            let custom = pinned_resolver.custom_doh.as_ref().unwrap();
            let pinned_http = build_pinned_doh_http_client(
                &custom.host,
                &[custom_addr],
                pinned_resolver.test_root_cert_der.as_deref(),
            )
            .unwrap();
            let mut state = custom.state.write().await;
            state.ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
            state.expires_at = Instant::now() + Duration::from_secs(300);
            state.pinned_http = Some(pinned_http);
        }
        let pinned_ips = pinned_resolver
            .resolve("pinned-target.example")
            .await
            .unwrap();
        assert_eq!(
            pinned_ips,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );

        custom_task.await.unwrap();

        // 3. Failover: when custom hostname DoH cannot bootstrap/connect, falls back cleanly to
        //    the IP-literal DoH ring without deadlocking.
        let (fb_server_cfg, fb_connector) = make_local_doh_tls_pair();
        let fb_acceptor = tokio_rustls::TlsAcceptor::from(fb_server_cfg);
        let fb_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb_listener.local_addr().unwrap();

        let fb_task = tokio::spawn(async move {
            let (tcp, _) = fb_listener.accept().await.unwrap();
            let mut tls = fb_acceptor.accept(tcp).await.unwrap();
            let query = read_doh_test_request(&mut tls).await;
            let parsed = parse_dns_question(&query).unwrap();
            let wire_resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &query[12..parsed.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
                120,
            );
            write_doh_test_response(&mut tls, &wire_resp).await;
        });

        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut failover_resolver = DnsResolver::new_with_binder(
            format!("https://dead-custom.example:{dead_port}/abc123"),
            53,
            true,
            true,
            Some(binder),
        )
        .unwrap();
        failover_resolver.bound_tls_connector = Some(fb_connector);
        failover_resolver.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", fb_addr.port())];
        failover_resolver.udp_dns_servers = Vec::new();
        {
            let custom = failover_resolver.custom_doh.as_ref().unwrap();
            let mut state = custom.state.write().await;
            state.ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
            state.expires_at = Instant::now() + Duration::from_secs(300);
        }

        let fb_ips = failover_resolver
            .resolve("fallback-after-custom.example")
            .await
            .unwrap();
        fb_task.await.unwrap();
        assert_eq!(fb_ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert!(!failover_resolver.is_doh_in_backoff());
    }

    #[tokio::test]
    async fn custom_and_filtering_doh_preserves_sinkhole_loopback_and_blocks_udp_protocol_fallback() {
        // 1. DoH replies allow 127.0.0.0/8 and ::1 (fixes lvh.me, nip.io, sslip.io, localtest.me)
        //    even on unfiltered resolvers, while still blocking Turkish ISP block-page IPs.
        assert!(!is_poisoned_doh_ip("127.0.0.1".parse().unwrap(), false));
        assert!(!is_poisoned_doh_ip("127.0.0.42".parse().unwrap(), false));
        assert!(!is_poisoned_doh_ip("::1".parse().unwrap(), false));
        assert!(is_poisoned_doh_ip("0.0.0.0".parse().unwrap(), false));
        assert!(is_poisoned_doh_ip("::".parse().unwrap(), false));
        assert!(!is_poisoned_doh_ip("0.0.0.0".parse().unwrap(), true));
        assert!(!is_poisoned_doh_ip("::".parse().unwrap(), true));
        assert!(is_poisoned_doh_ip("195.175.254.2".parse().unwrap(), true));
        assert!(is_poisoned_doh_ip("100::1".parse().unwrap(), true));
        assert!(is_poisoned_doh_ip(
            "64:ff9b::195.175.254.2".parse().unwrap(),
            true
        ));

        // Filtering DoH presets are recognized for sinkhole preservation.
        assert!(is_filtering_doh_endpoint("https://94.140.14.14/dns-query"));
        assert!(is_filtering_doh_endpoint("https://1.1.1.3/dns-query"));
        assert!(!is_filtering_doh_endpoint("https://1.1.1.1/dns-query"));
        assert!(!is_filtering_doh_endpoint("https://94.140.14.140/dns-query"));

        // 2. Custom hostname DoH returning 0.0.0.0 (NextDNS/ControlD ad-blocking) stands without
        //    failing over to the unfiltered IP-literal DoH ring.
        let hostname = "adblock-doh.example";
        let (custom_server_cfg, custom_connector, _) = make_hostname_doh_tls_pair(hostname);
        let custom_acceptor = tokio_rustls::TlsAcceptor::from(custom_server_cfg);
        let custom_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let custom_addr = custom_listener.local_addr().unwrap();
        let custom_url = format!("https://{hostname}:{}/abc123", custom_addr.port());

        let custom_task = tokio::spawn(async move {
            for reply_ip in [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            ] {
                let (tcp, _) = custom_listener.accept().await.unwrap();
                let mut tls = custom_acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    0,
                    &[reply_ip],
                    60,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        let fallback_hits = Arc::new(AtomicUsize::new(0));
        let fallback_hits_srv = Arc::clone(&fallback_hits);
        let (fb_cfg, _) = make_local_doh_tls_pair();
        let fb_acceptor = tokio_rustls::TlsAcceptor::from(fb_cfg);
        let fb_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fb_addr = fb_listener.local_addr().unwrap();
        let fb_task = tokio::spawn(async move {
            if let Ok((tcp, _)) = fb_listener.accept().await {
                fallback_hits_srv.fetch_add(1, Ordering::SeqCst);
                let _ = fb_acceptor.accept(tcp).await;
            }
        });

        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver =
            DnsResolver::new_with_binder(&custom_url, 53, true, true, Some(binder)).unwrap();
        resolver.bound_tls_connector = Some(custom_connector);
        resolver.doh_endpoints = vec![format!("https://127.0.0.1:{}/dns-query", fb_addr.port())];
        resolver.udp_dns_servers = Vec::new();
        {
            let custom = resolver.custom_doh.as_ref().unwrap();
            let mut state = custom.state.write().await;
            state.ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
            state.expires_at = Instant::now() + Duration::from_secs(300);
        }

        // Ad-blocked domain returns 0.0.0.0 directly without touching the fallback DoH ring.
        let blocked = resolver.resolve("ads.tracker.example").await.unwrap();
        assert_eq!(blocked, vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);

        // Local dev domain returning 127.0.0.1 over DoH is preserved intact.
        let local_dev = resolver.resolve("app.lvh.me").await.unwrap();
        assert_eq!(local_dev, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(fallback_hits.load(Ordering::SeqCst), 0);

        custom_task.await.unwrap();
        fb_task.abort();

        // 3. DoH SERVFAIL must NEVER fall back to plaintext port-53 UDP, DOES fall back to
        //    non-port-53 UDP when all DoH endpoints return SERVFAIL (without tripping global DoH
        //    backoff), and synthetic sinkhole rejection (0.0.0.0 on unfiltered DoH) must NEVER
        //    fall back to UDP at all.
        let (sf_cfg, sf_connector) = make_local_doh_tls_pair();
        let sf_acceptor = tokio_rustls::TlsAcceptor::from(sf_cfg);
        let sf_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sf_addr = sf_listener.local_addr().unwrap();
        let sf_task = tokio::spawn(async move {
            for reply_mode in [2u8, 2u8, 0u8] {
                let (tcp, _) = sf_listener.accept().await.unwrap();
                let mut tls = sf_acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                let wire_resp = if reply_mode == 0 {
                    build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &query[12..parsed.question_end],
                        0,
                        &[IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
                        60,
                    )
                } else {
                    build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &query[12..parsed.question_end],
                        reply_mode, // SERVFAIL
                        &[],
                        0,
                    )
                };
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        let p53_hits = Arc::new(AtomicUsize::new(0));
        let p53_hits_srv = Arc::clone(&p53_hits);
        let p53_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let p53_addr = p53_sock.local_addr().unwrap();
        let p53_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if p53_sock.recv_from(&mut buf).await.is_ok() {
                p53_hits_srv.fetch_add(1, Ordering::SeqCst);
            }
        });

        let non53_hits = Arc::new(AtomicUsize::new(0));
        let non53_hits_srv = Arc::clone(&non53_hits);
        let non53_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let non53_addr = non53_sock.local_addr().unwrap();
        let non53_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = non53_sock.recv_from(&mut buf).await {
                non53_hits_srv.fetch_add(1, Ordering::SeqCst);
                let parsed = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &buf[12..parsed.question_end],
                    0,
                    &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                    120,
                );
                non53_sock.send_to(&resp, peer).await.unwrap();
            }
        });

        let binder2: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut sf_resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder2)).unwrap();
        sf_resolver.bound_tls_connector = Some(sf_connector);
        sf_resolver.doh_endpoints = vec![format!("https://127.0.0.1:{}/dns-query", sf_addr.port())];
        sf_resolver.udp_dns_servers = vec![p53_addr];
        sf_resolver.test_port53_servers = vec![p53_addr];

        // 3a. With only port-53 UDP configured, SERVFAIL fails closed without touching port-53.
        assert!(sf_resolver.resolve("dnssec-broken.example").await.is_err());
        assert_eq!(
            p53_hits.load(Ordering::SeqCst),
            0,
            "DoH SERVFAIL must not fall back to plaintext port-53 UDP"
        );
        assert!(!sf_resolver.is_doh_in_backoff());

        // 3b. With non-port-53 UDP available, all-DoH SERVFAIL falls back to non-port-53 UDP.
        sf_resolver.udp_dns_servers = vec![p53_addr, non53_addr];
        let recovered = sf_resolver.resolve("servfail-recover.example").await.unwrap();
        assert_eq!(recovered, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(p53_hits.load(Ordering::SeqCst), 0);
        assert_eq!(non53_hits.load(Ordering::SeqCst), 1);
        assert!(!sf_resolver.is_doh_in_backoff());

        // 3c. Synthetic sinkhole rejection (0.0.0.0 on unfiltered DoH) must NOT fall back to UDP.
        assert!(sf_resolver.resolve("sinkhole-reject.example").await.is_err());
        assert_eq!(p53_hits.load(Ordering::SeqCst), 0);
        assert_eq!(non53_hits.load(Ordering::SeqCst), 1);
        assert!(!sf_resolver.is_doh_in_backoff());

        sf_task.await.unwrap();
        p53_task.abort();
        non53_task.await.unwrap();
    }

    #[tokio::test]
    async fn custom_doh_normalization_no_doh_override_udp_order_and_localhost_subdomains() {
        // 1. Round-trip normalization for https://host?no-ecs=1 and https://host/?no-ecs=1
        let norm1 = validate_custom_dns_input("https://doh.example.com?no-ecs=1").unwrap();
        assert_eq!(norm1, "https://doh.example.com/dns-query?no-ecs=1");
        let norm2 = validate_custom_dns_input(&norm1).unwrap();
        assert_eq!(norm2, norm1);
        let norm3 = validate_custom_dns_input("https://doh.example.com/?no-ecs=1").unwrap();
        assert_eq!(norm3, "https://doh.example.com/dns-query?no-ecs=1");
        let parsed = parse_doh_url_validated(&norm3).unwrap();
        assert_eq!(parsed.path_and_query, "/dns-query?no-ecs=1");

        // 2. Explicit https:// DoH URL keeps DoH active even when enable_doh == false.
        let r_explicit = DnsResolver::new("https://dns.nextdns.io/abc123", 53, false, false).unwrap();
        assert!(r_explicit.enable_doh);
        assert!(r_explicit.custom_doh.is_some());

        // 3. Non-default bare custom IP goes FIRST in build_udp_dns_servers even on port 53;
        //    default 1.1.1.1:53 stays behind non-standard ports; IPv6 UDP fallbacks appended when !ipv4_only.
        let custom_udp = build_udp_dns_servers("76.76.2.0", 53, false);
        assert_eq!(custom_udp[0], "76.76.2.0:53".parse::<SocketAddr>().unwrap());
        assert!(custom_udp.contains(&"[2606:4700:4700::1111]:53".parse().unwrap()));
        assert!(custom_udp.contains(&"[2001:4860:4860::8888]:53".parse().unwrap()));

        let corp_udp = build_udp_dns_servers("10.0.0.53", 53, true);
        assert_eq!(corp_udp[0], "10.0.0.53:53".parse::<SocketAddr>().unwrap());
        assert!(!corp_udp.iter().any(|sa| sa.is_ipv6()));

        let default_udp = build_udp_dns_servers("1.1.1.1", 53, false);
        assert_ne!(default_udp[0].port(), 53);

        // 4. Port-53 UDP servers must never be promoted into preferred_udp_idx over non-53 servers.
        let mut promo_resolver = DnsResolver::new("1.1.1.1", 53, false, true).unwrap();
        promo_resolver.udp_dns_servers = vec![
            "77.88.8.8:1253".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            "208.67.222.222:443".parse().unwrap(),
        ];
        promo_resolver.maybe_promote_udp_server(1);
        assert_eq!(promo_resolver.preferred_udp_idx.load(Ordering::Relaxed), 0);
        promo_resolver.maybe_promote_udp_server(2);
        assert_eq!(promo_resolver.preferred_udp_idx.load(Ordering::Relaxed), 2);

        // 5. *.localhost fast-path resolves to loopback without network calls.
        let local_ips = promo_resolver.resolve("app.dev.localhost").await.unwrap();
        assert_eq!(local_ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        let q = encode_dns_query("api.localhost", QTYPE_A).unwrap();
        let (resp, _) = promo_resolver.resolve_wire_query(&q, true).await.unwrap();
        let (wire_ips, _) = decode_dns_response(&resp, QTYPE_A).unwrap();
        assert_eq!(wire_ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

        // 6. select_dual_stack_candidates picks at least one IPv4 + one IPv6 when both exist.
        let mixed = vec![
            "45.90.28.10".parse().unwrap(),
            "45.90.30.10".parse().unwrap(),
            "2a07:a8c0::".parse().unwrap(),
            "2a07:a8c1::".parse().unwrap(),
        ];
        let picked = select_dual_stack_candidates(&mixed);
        assert_eq!(picked.len(), 2);
        assert!(picked.iter().any(IpAddr::is_ipv4));
        assert!(picked.iter().any(IpAddr::is_ipv6));
    }

    #[tokio::test]
    async fn ipv6_only_host_waits_for_aaaa_past_700ms_and_skips_caching_empty_a_nodata() {
        // 1. join_a_and_aaaa does NOT cut off AAAA at 25ms when QTYPE_A returned 0 IPv4 records,
        //    but DOES cut off AAAA when QTYPE_A returned >= 1 IPv4 record.
        let (a_empty, v6_full) = join_a_and_aaaa(
            async { Vec::<IpAddr>::new() },
            async {
                tokio::time::sleep(Duration::from_millis(80)).await;
                vec![IpAddr::V6("2001:db8::1".parse().unwrap())]
            },
            Duration::from_millis(25),
            |ips| !ips.is_empty(),
            |_| false,
        )
        .await;
        assert!(a_empty.is_empty());
        assert_eq!(
            v6_full,
            Some(vec![IpAddr::V6("2001:db8::1".parse().unwrap())])
        );

        let (a_hit, v6_cutoff) = join_a_and_aaaa(
            async { vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))] },
            async {
                tokio::time::sleep(Duration::from_millis(120)).await;
                vec![IpAddr::V6("2001:db8::1".parse().unwrap())]
            },
            Duration::from_millis(25),
            |ips| !ips.is_empty(),
            |_| false,
        )
        .await;
        assert_eq!(a_hit.len(), 1);
        assert!(v6_cutoff.is_none());

        // 2. Transient empty QTYPE_A NODATA must NOT be cached (must not blackhole IPv4 for 60s),
        //    whereas empty QTYPE_AAAA NODATA IS cached briefly (<= 60s).
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let queries_seen = Arc::new(AtomicUsize::new(0));
        let queries_srv = Arc::clone(&queries_seen);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..3 {
                let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
                queries_srv.fetch_add(1, Ordering::SeqCst);
                let parsed = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &buf[12..parsed.question_end],
                    0,
                    &[],
                    300,
                );
                udp_server.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut resolver = DnsResolver::new("127.0.0.1", 53, false, false).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];
        let q_a = encode_dns_query("transient-empty-a.example", QTYPE_A).unwrap();
        let (resp1, meta1) = resolver.resolve_wire_query(&q_a, true).await.unwrap();
        assert!(meta1.is_none());
        assert!(decode_dns_response(&resp1, QTYPE_A).unwrap().0.is_empty());

        // Second QTYPE_A query must hit upstream again (not blackholed in cache).
        let (resp2, meta2) = resolver.resolve_wire_query(&q_a, true).await.unwrap();
        assert!(meta2.is_none());
        assert!(decode_dns_response(&resp2, QTYPE_A).unwrap().0.is_empty());
        assert!(resolver
            .cache
            .read()
            .await
            .get("transient-empty-a.example")
            .is_none());

        // Empty QTYPE_AAAA NODATA is cached so the second AAAA query hits cache.
        let q_aaaa = encode_dns_query("v4only-aaaa-nodata.example", QTYPE_AAAA).unwrap();
        let (resp_aaaa1, _) = resolver.resolve_wire_query(&q_aaaa, true).await.unwrap();
        assert!(decode_dns_response(&resp_aaaa1, QTYPE_AAAA)
            .unwrap()
            .0
            .is_empty());
        let (resp_aaaa2, _) = resolver.resolve_wire_query(&q_aaaa, true).await.unwrap();
        assert!(decode_dns_response(&resp_aaaa2, QTYPE_AAAA)
            .unwrap()
            .0
            .is_empty());

        server_task.await.unwrap();
        assert_eq!(queries_seen.load(Ordering::SeqCst), 3);

        let guard = resolver.cache.read().await;
        let entry = guard.get("v4only-aaaa-nodata.example").unwrap();
        assert!(!entry.has_a_lookup);
        assert!(entry.has_aaaa_lookup);
        assert!(entry.expires_at.saturating_duration_since(Instant::now()) <= Duration::from_secs(60));
    }

    #[tokio::test]
    async fn dynamic_ipv4_only_flip_toggles_ipv6_endpoints_and_resolution() {
        let resolver = DnsResolver::new("1.1.1.1", 53, true, true).unwrap();
        let cloned = resolver.clone();
        assert!(resolver.is_ipv4_only());
        assert!(cloned.is_ipv4_only());

        // Initially ipv4_only=true: DoH and UDP eligible sets exclude IPv6 endpoints.
        assert!(resolver
            .eligible_doh_indices(false)
            .iter()
            .all(|&idx| !is_ipv6_doh_endpoint(&resolver.doh_endpoints[idx])));
        assert!(resolver
            .eligible_udp_indices()
            .iter()
            .all(|&idx| resolver.udp_dns_servers[idx].is_ipv4()));
        assert_eq!(
            resolver.resolve("localhost").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );

        // Flip IPv6 on dynamically via set_ipv4_only(false); cloned handles see it immediately.
        resolver.set_ipv4_only(false);
        assert!(!resolver.is_ipv4_only());
        assert!(!cloned.is_ipv4_only());
        assert!(resolver
            .eligible_doh_indices(false)
            .iter()
            .any(|&idx| resolver.doh_endpoints[idx] == "https://[2606:4700:4700::1111]/dns-query"));
        assert!(resolver
            .eligible_udp_indices()
            .iter()
            .any(|&idx| resolver.udp_dns_servers[idx].is_ipv6()));
        assert_eq!(
            cloned.resolve("localhost").await.unwrap(),
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );

        // Flip back to ipv4_only=true hides IPv6 endpoints again.
        cloned.set_ipv4_only(true);
        assert!(resolver.is_ipv4_only());
        assert!(resolver
            .eligible_doh_indices(false)
            .iter()
            .all(|&idx| !is_ipv6_doh_endpoint(&resolver.doh_endpoints[idx])));
        assert!(resolver
            .eligible_udp_indices()
            .iter()
            .all(|&idx| resolver.udp_dns_servers[idx].is_ipv4()));

        // Caching a QTYPE_A lookup while ipv4_only=true must NOT mark has_aaaa_lookup=true,
        // so flipping ipv4_only=false afterwards can still query AAAA without waiting for TTL expiry.
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for expected_qtype in [QTYPE_A, QTYPE_AAAA] {
                let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
                let parsed = parse_dns_question(&buf[..n]).unwrap();
                assert_eq!(parsed.qtype, expected_qtype);
                let answer = if expected_qtype == QTYPE_A {
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
                } else {
                    IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap())
                };
                let resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &buf[12..parsed.question_end],
                    0,
                    &[answer],
                    300,
                );
                udp_server.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut dyn_res = DnsResolver::new("1.1.1.1", 53, false, true).unwrap();
        dyn_res.udp_dns_servers = vec![udp_addr];
        let q_a = encode_dns_query("dyn-v6.example", QTYPE_A).unwrap();
        let (resp_a, _) = dyn_res.resolve_wire_query(&q_a, true).await.unwrap();
        assert_eq!(
            decode_dns_response(&resp_a, QTYPE_A).unwrap().0,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        {
            let guard = dyn_res.cache.read().await;
            let entry = guard.get("dyn-v6.example").unwrap();
            assert!(entry.has_a_lookup);
            assert!(!entry.has_aaaa_lookup);
        }

        dyn_res.set_ipv4_only(false);
        let q_aaaa = encode_dns_query("dyn-v6.example", QTYPE_AAAA).unwrap();
        let (resp_aaaa, _) = dyn_res.resolve_wire_query(&q_aaaa, true).await.unwrap();
        srv.await.unwrap();
        assert_eq!(
            decode_dns_response(&resp_aaaa, QTYPE_AAAA).unwrap().0,
            vec![IpAddr::V6(
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
            )]
        );
    }

    #[tokio::test]
    async fn bare_custom_ip_queries_udp_first_without_synthesizing_broken_doh_url() {
        // Known public DoH IPs synthesize https://<ip>/dns-query; arbitrary bare IPs do not.
        for known in [
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "8.8.4.4",
            "9.9.9.9",
            "149.112.112.112",
            "94.140.14.14",
            "94.140.15.15",
            "1.1.1.2",
            "1.1.1.3",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
            "2620:fe::fe",
            "2a10:50c0::ad1:ff",
        ] {
            let ip: IpAddr = known.parse().unwrap();
            assert!(
                is_known_public_doh_ip(ip),
                "expected known public DoH IP: {known}"
            );
            let eps = build_doh_endpoints(known, false, false, false);
            let expected = match ip {
                IpAddr::V4(v4) => format!("https://{v4}/dns-query"),
                IpAddr::V6(v6) => format!("https://[{v6}]/dns-query"),
            };
            assert_eq!(eps[0], expected, "expected primary DoH for {known}");
        }

        for custom_bare in ["76.76.2.0", "10.0.0.53", "192.168.1.1", "127.0.0.1"] {
            let ip: IpAddr = custom_bare.parse().unwrap();
            assert!(!is_known_public_doh_ip(ip));
            let eps = build_doh_endpoints(custom_bare, false, false, false);
            assert!(
                !eps.iter().any(|ep| ep.contains(custom_bare)),
                "must not synthesize DoH URL for arbitrary bare IP {custom_bare}: {eps:?}"
            );
            assert_eq!(eps[0], "https://1.1.1.1/dns-query");
        }

        // Under default enable_doh=true, a custom bare IP is queried over UDP first; if it
        // fails, resolution falls back cleanly to DoH.
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // 1. First query succeeds over UDP.
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let p1 = parse_dns_question(&buf[..n]).unwrap();
            let resp1 = build_dns_wire_response(
                p1.tx_id,
                p1.flags,
                &buf[12..p1.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))],
                120,
            );
            udp_server.send_to(&resp1, peer).await.unwrap();

            // 2. Second query returns SERVFAIL on custom UDP, triggering DoH fallback.
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let p2 = parse_dns_question(&buf[..n]).unwrap();
            let resp2 = build_dns_wire_response(
                p2.tx_id,
                p2.flags,
                &buf[12..p2.question_end],
                2, // SERVFAIL
                &[],
                0,
            );
            udp_server.send_to(&resp2, peer).await.unwrap();
        });

        let (server_cfg, connector) = make_local_doh_tls_pair();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
        let doh_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doh_addr = doh_listener.local_addr().unwrap();
        let doh_hits = Arc::new(AtomicUsize::new(0));
        let doh_hits_srv = Arc::clone(&doh_hits);
        let doh_task = tokio::spawn(async move {
            let (tcp, _) = doh_listener.accept().await.unwrap();
            doh_hits_srv.fetch_add(1, Ordering::SeqCst);
            let mut tls = acceptor.accept(tcp).await.unwrap();
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
        let mut resolver = DnsResolver::new_with_binder(
            "127.0.0.1",
            udp_addr.port(),
            true,
            true,
            Some(binder),
        )
        .unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.doh_endpoints = vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        resolver.udp_dns_servers = vec![udp_addr];

        let ips1 = resolver.resolve("corp-app.example").await.unwrap();
        assert_eq!(ips1, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))]);
        assert_eq!(
            doh_hits.load(Ordering::SeqCst),
            0,
            "custom bare IP must be queried via UDP before DoH"
        );

        let ips2 = resolver.resolve("fallback-doh.example").await.unwrap();
        assert_eq!(ips2, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(doh_hits.load(Ordering::SeqCst), 1);

        udp_task.await.unwrap();
        doh_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_port53_demotion_recovery_clear_cache_and_non53_ipv4_first_ordering() {
        // 1. Non-port-53 IPv4 UDP servers stay ahead of port-53 IPv6 servers unless IPv6 was
        //    explicitly configured.
        let default_udp = build_udp_dns_servers("1.1.1.1", 53, false);
        let cf_v6: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let google_v6: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let cf_v6_pos = default_udp
            .iter()
            .position(|&sa| sa == cf_v6)
            .expect("Cloudflare IPv6 UDP server missing");
        let google_v6_pos = default_udp
            .iter()
            .position(|&sa| sa == google_v6)
            .expect("Google IPv6 UDP server missing");
        for non53 in [
            "77.88.8.8:1253",
            "208.67.222.222:443",
            "77.88.8.1:1253",
            "208.67.220.220:443",
            "208.67.222.222:5353",
        ] {
            let sa: SocketAddr = non53.parse().unwrap();
            let pos = default_udp
                .iter()
                .position(|&s| s == sa)
                .expect("non-port-53 IPv4 UDP server missing");
            assert!(
                pos < cf_v6_pos && pos < google_v6_pos,
                "non-port-53 IPv4 server {sa} (pos {pos}) must precede IPv6 port-53 servers ({cf_v6_pos}, {google_v6_pos})"
            );
        }

        // Explicitly configuring an IPv6 DNS server places IPv6 UDP servers ahead of IPv4.
        let explicit_v6_udp = build_udp_dns_servers("2606:4700:4700::1111", 53, false);
        assert_eq!(explicit_v6_udp[0], cf_v6);
        assert_eq!(explicit_v6_udp[1], google_v6);

        // 2. User custom index-0 port-53 server can be promoted back after transient failover.
        let custom_resolver = DnsResolver::new("76.76.2.0", 53, false, false).unwrap();
        assert_eq!(
            custom_resolver.udp_dns_servers[0],
            "76.76.2.0:53".parse::<SocketAddr>().unwrap()
        );
        custom_resolver.maybe_promote_udp_server(1);
        assert_eq!(custom_resolver.preferred_udp_idx.load(Ordering::Relaxed), 1);
        custom_resolver.maybe_promote_udp_server(0);
        assert_eq!(
            custom_resolver.preferred_udp_idx.load(Ordering::Relaxed),
            0,
            "user custom index-0 port-53 server must be promotable back"
        );

        // 3. Port-53 UDP servers (v4 or v6) must NEVER be promoted when ANY non-port-53 server
        //    exists in the eligible set, and clear_cache resets both preferred_udp_idx and preferred_doh_idx.
        let default_resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        let v4_p53_idx = default_resolver
            .udp_dns_servers
            .iter()
            .position(|&sa| sa == "1.1.1.1:53".parse::<SocketAddr>().unwrap())
            .unwrap();
        let v6_p53_idx = default_resolver
            .udp_dns_servers
            .iter()
            .position(|&sa| sa == cf_v6)
            .unwrap();
        default_resolver.maybe_promote_udp_server(v4_p53_idx);
        assert_eq!(
            default_resolver.preferred_udp_idx.load(Ordering::Relaxed),
            0,
            "port-53 IPv4 server must not be promoted when non-53 UDP servers exist"
        );
        default_resolver.maybe_promote_udp_server(v6_p53_idx);
        assert_eq!(
            default_resolver.preferred_udp_idx.load(Ordering::Relaxed),
            0,
            "port-53 IPv6 server must not be promoted when non-53 UDP servers exist"
        );

        default_resolver.maybe_promote_udp_server(2);
        assert_eq!(default_resolver.preferred_udp_idx.load(Ordering::Relaxed), 2);
        default_resolver
            .preferred_doh_idx
            .store(3, Ordering::Relaxed);
        default_resolver.clear_cache().await;
        assert_eq!(
            default_resolver.preferred_udp_idx.load(Ordering::Relaxed),
            0,
            "clear_cache must reset preferred_udp_idx to 0"
        );
        assert_eq!(
            default_resolver.preferred_doh_idx.load(Ordering::Relaxed),
            0,
            "clear_cache must reset preferred_doh_idx to 0"
        );
    }

    #[tokio::test]
    async fn custom_and_filtering_udp_servers_preserve_sinkhole_and_loopback_replies() {
        for addr in [
            "76.76.2.2",
            "94.140.14.14",
            "1.1.1.3",
            "10.0.0.53",
            "192.168.1.1",
        ] {
            let r = DnsResolver::new(addr, 53, false, true).unwrap();
            let sa: SocketAddr = format!("{addr}:53").parse().unwrap();
            assert!(
                r.udp_server_allows_sinkhole_and_loopback(sa),
                "expected sinkhole/loopback preservation for custom/filtering UDP {sa}"
            );
        }
        let default_r = DnsResolver::new("1.1.1.1", 53, false, true).unwrap();
        assert!(!default_r.udp_server_allows_sinkhole_and_loopback("1.1.1.1:53".parse().unwrap()));
        assert!(!default_r
            .udp_server_allows_sinkhole_and_loopback("77.88.8.8:1253".parse().unwrap()));

        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for reply_ip in [
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),        // ad-block 0.0.0.0 -> preserved
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42)), // loopback -> preserved
                IpAddr::V4(Ipv4Addr::new(195, 175, 39, 39)), // ISP poison -> still rejected
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),        // on default unfiltered -> rejected
            ] {
                let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[reply_ip],
                    60,
                );
                udp_server.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut custom_resolver =
            DnsResolver::new_with_options("127.0.0.1", udp_addr.port(), false, true, true, None)
                .unwrap();
        custom_resolver.udp_dns_servers = vec![udp_addr];

        assert_eq!(
            custom_resolver.resolve("ads.blocked.example").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)]
        );
        assert_eq!(
            custom_resolver.resolve("local.dev.example").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 42))]
        );
        assert!(
            custom_resolver.resolve("isp-poison.example").await.is_err(),
            "known ISP block-page IPs must still be rejected on custom UDP"
        );

        let mut default_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        default_resolver.udp_dns_servers = vec![udp_addr];
        assert!(
            default_resolver
                .resolve("unfiltered-sinkhole.example")
                .await
                .is_err(),
            "0.0.0.0 on default unfiltered UDP server must still be rejected as poisoning"
        );

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn udp_dpi_race_validates_qname_waits_for_clean_reply_and_skips_caching_poisoned_negatives() {
        // 1. send_udp_dns_raw rejects packets whose echoed QNAME does not match the query.
        let qname_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let qname_addr = qname_srv.local_addr().unwrap();
        let qname_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = qname_srv.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let wrong_q = encode_dns_query("spoofed-other.example", QTYPE_A).unwrap();
            let wrong_resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &wrong_q[12..],
                0,
                &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))],
                60,
            );
            qname_srv.send_to(&wrong_resp, peer).await.unwrap();

            let right_resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            qname_srv.send_to(&right_resp, peer).await.unwrap();
        });

        let q = encode_dns_query("expected-qname.example", QTYPE_A).unwrap();
        let raw = send_udp_dns_raw(qname_addr, &q, None).await.unwrap();
        qname_task.await.unwrap();
        assert_eq!(
            decode_dns_response(&raw, QTYPE_A).unwrap().0,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );

        // 2. When a poisoned IP arrives first (DPI race), keep reading the same socket briefly
        //    (~120ms) and accept the legitimate reply arriving right behind it.
        let race_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let race_addr = race_srv.local_addr().unwrap();
        let race_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = race_srv.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let poisoned = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(195, 175, 39, 39))],
                60,
            );
            race_srv.send_to(&poisoned, peer).await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            let legit = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                120,
            );
            race_srv.send_to(&legit, peer).await.unwrap();
        });

        let mut race_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        race_resolver.udp_dns_servers = vec![race_addr];
        let raced_ips = race_resolver.resolve("dpi-race.example").await.unwrap();
        race_task.await.unwrap();
        assert_eq!(raced_ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);

        // 3. Port-53 / poisoned-server NXDOMAIN and NODATA replies are NOT cached.
        assert!(!should_cache_udp_negative(
            "1.1.1.1:53".parse().unwrap(),
            false,
            false
        ));
        assert!(!should_cache_udp_negative(
            "77.88.8.8:1253".parse().unwrap(),
            false,
            true
        ));
        assert!(should_cache_udp_negative(
            "77.88.8.8:1253".parse().unwrap(),
            false,
            false
        ));
        assert!(should_cache_udp_negative(
            "10.0.0.53:53".parse().unwrap(),
            true,
            false
        ));

        let poison_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let poison_addr = poison_srv.local_addr().unwrap();
        let neg_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let neg_addr = neg_srv.local_addr().unwrap();

        let poison_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = poison_srv.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let poisoned = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[IpAddr::V4(Ipv4Addr::new(195, 175, 39, 39))],
                    60,
                );
                poison_srv.send_to(&poisoned, peer).await.unwrap();
            }
        });
        let neg_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // First query: NXDOMAIN; second query: empty NODATA
            for rcode in [3u8, 0u8] {
                let (n, peer) = neg_srv.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    rcode,
                    &[],
                    60,
                );
                neg_srv.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut neg_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        neg_resolver.udp_dns_servers = vec![poison_addr, neg_addr];

        let nx_res = neg_resolver
            .resolve_single_qtype("poisoned-nx.example", QTYPE_A, false, true)
            .await
            .unwrap();
        assert!(matches!(nx_res, DnsOutcome::NxDomain(ttl) if ttl.is_zero()));
        let nodata_res = neg_resolver
            .resolve_single_qtype("poisoned-nodata.example", QTYPE_A, false, true)
            .await
            .unwrap();
        assert!(matches!(nodata_res, DnsOutcome::Records(ref ips, ttl) if ips.is_empty() && ttl.is_zero()));

        poison_task.await.unwrap();
        neg_task.await.unwrap();

        let cache = neg_resolver.cache.read().await;
        assert!(!cache.contains_key("poisoned-nx.example"));
        assert!(!cache.contains_key("poisoned-nodata.example"));
    }

    #[tokio::test]
    async fn outbound_binder_skipped_for_loopback_and_called_for_non_loopback() {
        #[derive(Debug, Default)]
        struct FailingCountingBinder {
            calls: AtomicUsize,
        }

        impl OutboundBinder for FailingCountingBinder {
            fn bind_socket(
                &self,
                _sock: socket2::SockRef<'_>,
                _is_ipv4: bool,
            ) -> std::io::Result<()> {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "intercepted non-loopback bind",
                ))
            }
        }

        assert!(is_loopback_dns_ip("127.0.0.1".parse().unwrap()));
        assert!(is_loopback_dns_ip("127.0.0.53".parse().unwrap()));
        assert!(is_loopback_dns_ip("127.255.255.254".parse().unwrap()));
        assert!(is_loopback_dns_ip("::1".parse().unwrap()));
        assert!(is_loopback_dns_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(!is_loopback_dns_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_loopback_dns_ip("10.0.0.53".parse().unwrap()));
        assert!(!is_loopback_dns_ip("2606:4700:4700::1111".parse().unwrap()));

        // 1. Loopback UDP succeeds without calling outbound_binder (even if binder always fails).
        let udp_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_srv.local_addr().unwrap();
        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = udp_srv.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                0,
                &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                60,
            );
            udp_srv.send_to(&resp, peer).await.unwrap();
        });

        let failing_binder = FailingCountingBinder::default();
        let q = encode_dns_query("local-dnsmasq.example", QTYPE_A).unwrap();
        let raw = send_udp_dns_raw(udp_addr, &q, Some(&failing_binder))
            .await
            .unwrap();
        udp_task.await.unwrap();
        assert_eq!(failing_binder.calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            decode_dns_response(&raw, QTYPE_A).unwrap().0,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );

        // 2. Non-loopback UDP and non-loopback bound DoH DO call outbound_binder (aborted inside
        //    the test binder before any network traffic occurs).
        let err_udp = send_udp_dns_raw(
            "192.0.2.1:53".parse().unwrap(),
            &q,
            Some(&failing_binder),
        )
        .await
        .expect_err("non-loopback UDP must invoke outbound_binder");
        assert!(err_udp.to_string().contains("intercepted non-loopback bind"));
        assert_eq!(failing_binder.calls.load(Ordering::Relaxed), 1);

        let (_, connector) = make_local_doh_tls_pair();
        let err_doh = send_doh_bound_tls(
            &failing_binder,
            &connector,
            "https://192.0.2.1/dns-query",
            &q,
        )
        .await
        .expect_err("non-loopback bound DoH must invoke outbound_binder");
        assert!(err_doh.to_string().contains("intercepted non-loopback bind"));
        assert_eq!(failing_binder.calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn lan_and_private_hostnames_route_to_system_in_proxy_mode_not_tun() {
        for lan_host in [
            "nas",
            "router",
            "box.lan",
            "sub.box.lan",
            "home.arpa",
            "printer.home.arpa",
            "api.corp.internal",
            "workstation.localdomain",
            "laptop.tail1234.ts.net",
        ] {
            assert!(
                is_lan_or_private_hostname(lan_host),
                "expected LAN/private hostname: {lan_host}"
            );
        }
        for public_host in [
            "example.com",
            "myplan.com",
            "ts.net",
            "notts.net",
            "cloudflare.com",
        ] {
            assert!(
                !is_lan_or_private_hostname(public_host),
                "unexpected LAN/private classification: {public_host}"
            );
        }

        // Proxy mode routes LAN/private names to OS resolver; TUN mode & wire queries do not.
        let proxy_resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        assert!(proxy_resolver.should_route_to_system_resolver("nas", false));
        assert!(proxy_resolver.should_route_to_system_resolver("box.lan", false));
        assert!(proxy_resolver.should_route_to_system_resolver("printer.home.arpa", false));
        assert!(proxy_resolver.should_route_to_system_resolver("api.corp.internal", false));
        assert!(proxy_resolver.should_route_to_system_resolver("host.localdomain", false));
        assert!(proxy_resolver.should_route_to_system_resolver("node.tail123.ts.net", false));
        assert!(!proxy_resolver.should_route_to_system_resolver("example.com", false));
        assert!(!proxy_resolver.should_route_to_system_resolver("box.lan", true));

        let tun_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        assert!(!tun_resolver.should_route_to_system_resolver("nas", false));
        assert!(!tun_resolver.should_route_to_system_resolver("node.tail123.ts.net", false));

        // In TUN mode with a custom local/corporate UDP server, LAN & *.ts.net names resolve
        // through the configured upstream instead of returning synthetic NXDOMAIN.
        let udp_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_srv.local_addr().unwrap();
        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, peer) = udp_srv.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))],
                    60,
                );
                udp_srv.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut custom_tun =
            DnsResolver::new_with_options("127.0.0.1", udp_addr.port(), false, true, true, None)
                .unwrap();
        custom_tun.udp_dns_servers = vec![udp_addr];
        assert_eq!(
            custom_tun.resolve("nas").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))]
        );
        assert_eq!(
            custom_tun.resolve("node.tail123.ts.net").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))]
        );
        srv_task.await.unwrap();
    }

    #[test]
    fn effective_enable_doh_redact_dns_for_display_and_doh_error_redaction() {
        // 1. effective_enable_doh
        assert!(effective_enable_doh("https://dns.nextdns.io/abc123", false));
        assert!(effective_enable_doh(
            "  HTTPS://freedns.controld.com/p2  ",
            false
        ));
        assert!(!effective_enable_doh("1.1.1.1", false));
        assert!(effective_enable_doh("1.1.1.1", true));
        assert!(effective_enable_doh("76.76.2.0", true));
        assert!(!effective_enable_doh("http://1.1.1.1/dns-query", false));

        // 2. redact_dns_for_display: valid IPv4, IPv6, hostname DoH URLs, and bare IPs
        assert_eq!(
            redact_dns_for_display("https://[2606:4700:4700::1111]/secret"),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(
            redact_dns_for_display("https://[2606:4700:4700:0::1111]:8443/secret?a=1#frag"),
            "https://[2606:4700:4700::1111]:8443"
        );
        assert_eq!(
            redact_dns_for_display("https://dns.nextdns.io/abc123secret"),
            "https://dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_for_display("https://user:p@ssword@dns.nextdns.io/abc123?tok=1#f"),
            "https://dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_for_display("https://user:secret@[2606:4700:4700::1111]/secret"),
            "https://[2606:4700:4700::1111]"
        );
        assert_eq!(redact_dns_for_display("1.1.1.1"), "1.1.1.1");
        assert_eq!(
            redact_dns_for_display("2606:4700:4700::1111"),
            "2606:4700:4700::1111"
        );

        // 3. Malformed https:// URLs must NEVER leak raw secret tokens.
        for malformed in [
            "https://",
            "https:///topsecret123",
            "https://?token=topsecret123",
            "https://#topsecret123",
            "https://user:topsecret123@",
            "https://user:topsecret123@/path",
            "https://[2606:4700:4700::1111/topsecret123",
            "https://2606:4700:4700::1111/topsecret123",
            "https://dns.nextdns.io:notaport/topsecret123",
            "https://dns.nextdns.io\\topsecret123",
            "https://bad_host/topsecret123",
        ] {
            let redacted = redact_dns_for_display(malformed);
            assert!(
                !redacted.contains("topsecret123"),
                "secret leaked for {malformed:?} -> {redacted:?}"
            );
        }

        // 4. DohError Display redacts both ProtocolError endpoints and embedded Transport URLs.
        let proto_err = DohError::ProtocolError {
            endpoint: "https://dns.nextdns.io/my-nextdns-token".to_string(),
            rcode: 2,
        };
        let proto_msg = proto_err.to_string();
        assert!(proto_msg.contains("https://dns.nextdns.io"));
        assert!(proto_msg.contains("RCODE 2"));
        assert!(!proto_msg.contains("my-nextdns-token"));

        let transport_err = DohError::Transport(anyhow!(
            "error sending request for url (https://freedns.controld.com/my-controld-token?foo=bar)"
        ));
        let transport_msg = transport_err.to_string();
        assert!(transport_msg.contains("https://freedns.controld.com"));
        assert!(!transport_msg.contains("my-controld-token"));
        assert!(!transport_msg.contains("foo=bar"));
    }

    #[test]
    fn is_effective_doh_target_and_redact_urls_in_text() {
        // Explicit valid https:// DoH URLs are always DoH targets regardless of enable_doh.
        assert!(is_effective_doh_target(
            "https://dns.nextdns.io/abc123",
            false
        ));
        assert!(is_effective_doh_target(
            "  HTTPS://freedns.controld.com/p2  ",
            false
        ));
        assert!(is_effective_doh_target(
            "https://1.1.1.1/dns-query",
            false
        ));
        assert!(is_effective_doh_target(
            "https://[2606:4700:4700::1111]/dns-query",
            true
        ));

        // Known public IP-SAN DoH IPs are DoH targets only when enable_doh == true.
        for known in [
            "1.1.1.1",
            "1.0.0.1",
            "8.8.8.8",
            "9.9.9.9",
            "94.140.14.14",
            "2606:4700:4700::1111",
            "[2606:4700:4700::1111]",
            "2001:4860:4860::8888",
        ] {
            assert!(
                is_effective_doh_target(known, true),
                "expected DoH target when enable_doh=true: {known}"
            );
            assert!(
                !is_effective_doh_target(known, false),
                "expected non-DoH target when enable_doh=false: {known}"
            );
        }

        // Bare custom non-DoH IPs (UDP-first) must NEVER be mislabeled as DoH targets.
        for custom_udp in ["76.76.2.0", "10.0.0.53", "192.168.1.1", "127.0.0.1"] {
            assert!(
                !is_effective_doh_target(custom_udp, true),
                "bare custom non-DoH IP must not be labeled DoH: {custom_udp}"
            );
            assert!(!is_effective_doh_target(custom_udp, false));
        }

        // Invalid / non-https / empty inputs are never DoH targets.
        for invalid in [
            "",
            "   ",
            "0.0.0.0",
            "http://1.1.1.1/dns-query",
            "https://garbage",
            "not-a-dns",
        ] {
            assert!(!is_effective_doh_target(invalid, true));
            assert!(!is_effective_doh_target(invalid, false));
        }

        // Public redact_urls_in_text scrubs embedded URLs while preserving surrounding text.
        let scrubbed = redact_urls_in_text(
            "failed https://dns.nextdns.io/secret-profile?foo=bar and http://user:pw@example.com/tok.",
        );
        assert!(scrubbed.contains("https://dns.nextdns.io"));
        assert!(scrubbed.contains("http://example.com."));
        assert!(!scrubbed.contains("secret-profile"));
        assert!(!scrubbed.contains("foo=bar"));
        assert!(!scrubbed.contains("user:pw"));
        assert!(!scrubbed.contains("/tok"));
    }

    #[test]
    fn redact_privacy_audit_round1_findings() {
        // PRIV-01: scheme-without-slashes (`https:`, `http:`) and scheme-less URL-like inputs
        // containing `/`, `?`, `@`, `#`, or `\` must never return raw secret tokens.
        assert_eq!(
            redact_dns_for_display("https:dns.nextdns.io/a1b2c3"),
            "https://<redacted>"
        );
        assert_eq!(
            redact_dns_for_display("HTTPS:user:pass@dns.nextdns.io/a1b2c3"),
            "https://<redacted>"
        );
        assert_eq!(
            redact_dns_for_display("http:host/secret"),
            "http://<redacted>"
        );
        assert_eq!(
            redact_dns_for_display("HTTP:/secret?tok=1"),
            "http://<redacted>"
        );
        assert_eq!(
            redact_dns_for_display("dns.nextdns.io/a1b2c3"),
            "dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_for_display("dns.nextdns.io?token=a1b2c3"),
            "dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_for_display("user:pass@dns.nextdns.io/secret"),
            "dns.nextdns.io"
        );
        assert_eq!(
            redact_dns_for_display("user:pass@host/secret"),
            "<redacted>"
        );
        assert_eq!(redact_dns_for_display("a1b2c3/MyDevice"), "<redacted>");
        assert_eq!(redact_dns_for_display("1.1.1.1/secret"), "1.1.1.1");
        assert_eq!(
            redact_dns_for_display("[2606:4700:4700::1111]/secret"),
            "[2606:4700:4700::1111]"
        );
        assert_eq!(redact_dns_for_display("1.1.1.1"), "1.1.1.1");
        assert_eq!(redact_dns_for_display("9.9.9.9:53"), "9.9.9.9:53");
        assert_eq!(
            redact_dns_for_display("2606:4700:4700::1111"),
            "2606:4700:4700::1111"
        );

        // PRIV-02: `@` appearing after `?`, `/`, `#`, `\`, or whitespace must never leak the
        // preceding credential/username segment as a hostname.
        for sneaky in [
            "https://secretuser?p@dns.nextdns.io/a1b2c3",
            "https://secret.user?p@dns.nextdns.io/a1b2c3",
            "https://secretuser/pass@dns.nextdns.io/a1b2c3",
            "https://secretuser#frag@dns.nextdns.io/a1b2c3",
            "https://secretuser\\pass@dns.nextdns.io/a1b2c3",
            "https://secretuser pass@dns.nextdns.io/a1b2c3",
        ] {
            let redacted = redact_dns_for_display(sneaky);
            assert_eq!(
                redacted, "https://<redacted>",
                "userinfo before delimiter leaked for {sneaky:?}"
            );
            assert!(!redacted.contains("secret"));
            assert!(!redacted.contains("a1b2c3"));
        }
        assert_eq!(
            redact_dns_for_display("secretuser?p@dns.nextdns.io/a1b2c3"),
            "<redacted>"
        );
        assert_eq!(
            redact_dns_for_display("https://user:secret@host with space/token"),
            "https://host"
        );

        // PRIV-03: redact_urls_in_text must not prematurely stop at valid DoH URL characters
        // `(`, `)`, `'`, `,`, `;` inside a URL, while safely preserving trailing sentence
        // punctuation, and must also scrub `https:` / `http:` tokens missing `//`.
        assert_eq!(
            redact_urls_in_text("failed https://dns.nextdns.io/a1b2c3/My(PC)"),
            "failed https://dns.nextdns.io"
        );
        assert_eq!(
            redact_urls_in_text(
                "error sending request for url (https://dns.nextdns.io/a1b2c3/My(PC)): timed out"
            ),
            "error sending request for url (https://dns.nextdns.io): timed out"
        );
        assert_eq!(
            redact_urls_in_text(
                "failed https://dns.nextdns.io/a1b2c3?tags=a,secret_token, retrying"
            ),
            "failed https://dns.nextdns.io, retrying"
        );
        assert_eq!(
            redact_urls_in_text(
                "failed https://dns.nextdns.io/a1b2c3/Arda's-PC;k=secret_val; next"
            ),
            "failed https://dns.nextdns.io; next"
        );
        assert_eq!(
            redact_urls_in_text(
                "DoH failed for 'HTTPS://user:pass@dns.nextdns.io/prof1?a=1', fallback <https://[2606:4700:4700::1111]/prof2>."
            ),
            "DoH failed for 'https://dns.nextdns.io', fallback <https://[2606:4700:4700::1111]>."
        );
        assert_eq!(
            redact_urls_in_text("bad https:dns.nextdns.io/a1b2c3/My(PC) and (http:host/secret), ok"),
            "bad https://<redacted> and (http://<redacted>), ok"
        );
        assert_eq!(
            redact_urls_in_text("http: timeout while checking 'https:'"),
            "http: timeout while checking 'https:'"
        );
        assert_eq!(
            redact_urls_in_text("bad https://secretuser?p@dns.nextdns.io/a1b2c3 done"),
            "bad https://<redacted> done"
        );
    }

    #[tokio::test]
    async fn port53_forged_nxdomain_and_nodata_race_and_failover() {
        // 1. Untrusted port-53 forged NXDOMAIN and empty NODATA wait UDP_DPI_RACE_GRACE_MS
        //    on the same socket and accept the legitimate trailing reply.
        let race_srv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let race_addr = race_srv.local_addr().unwrap();
        let race_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for (forged_rcode, legit_ip) in [
                (3u8, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
                (0u8, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))),
            ] {
                let (n, peer) = race_srv.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let forged = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    forged_rcode,
                    &[],
                    60,
                );
                race_srv.send_to(&forged, peer).await.unwrap();
                tokio::time::sleep(Duration::from_millis(25)).await;
                let legit = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[legit_ip],
                    120,
                );
                race_srv.send_to(&legit, peer).await.unwrap();
            }
        });

        let mut race_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        race_resolver.udp_dns_servers = vec![race_addr];
        race_resolver.test_port53_servers = vec![race_addr];

        assert_eq!(
            race_resolver
                .resolve("forged-nx-race.example")
                .await
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(
            race_resolver
                .resolve("forged-nodata-race.example")
                .await
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))]
        );
        race_task.await.unwrap();

        // 2. When no trailing reply arrives on an untrusted port-53 server and a non-53 UDP
        //    server remains, fail over to the non-53 server for both forged NXDOMAIN and NODATA.
        let forged_p53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged_p53_addr = forged_p53.local_addr().unwrap();
        let clean_non53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let clean_non53_addr = clean_non53.local_addr().unwrap();

        let forged_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for rcode in [3u8, 0u8] {
                let (n, peer) = forged_p53.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    rcode,
                    &[],
                    60,
                );
                forged_p53.send_to(&resp, peer).await.unwrap();
            }
        });
        let clean_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for ip in [
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
            ] {
                let (n, peer) = clean_non53.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[ip],
                    120,
                );
                clean_non53.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut failover_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        failover_resolver.udp_dns_servers = vec![forged_p53_addr, clean_non53_addr];
        failover_resolver.test_port53_servers = vec![forged_p53_addr];

        assert_eq!(
            failover_resolver
                .resolve("forged-nx-failover.example")
                .await
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))]
        );
        assert_eq!(
            failover_resolver.preferred_udp_idx.load(Ordering::Relaxed),
            1,
            "clean non-53 server should be promoted after untrusted port-53 failover"
        );
        failover_resolver
            .preferred_udp_idx
            .store(0, Ordering::Relaxed);
        assert_eq!(
            failover_resolver
                .resolve("forged-nodata-failover.example")
                .await
                .unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11))]
        );
        forged_task.await.unwrap();
        clean_task.await.unwrap();

        // 3. When NO non-53 servers remain, untrusted port-53 NXDOMAIN resolves to an
        //    uncached NxDomain(0) after the race grace instead of failing with SERVFAIL.
        let solo_p53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let solo_p53_addr = solo_p53.local_addr().unwrap();
        let solo_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = solo_p53.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                3,
                &[],
                60,
            );
            solo_p53.send_to(&resp, peer).await.unwrap();
        });

        let mut solo_resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        solo_resolver.udp_dns_servers = vec![solo_p53_addr];
        solo_resolver.test_port53_servers = vec![solo_p53_addr];

        let solo_outcome = solo_resolver
            .resolve_single_qtype("real-nx-solo-p53.example", QTYPE_A, false, true)
            .await
            .unwrap();
        solo_task.await.unwrap();
        assert!(matches!(solo_outcome, DnsOutcome::NxDomain(ttl) if ttl.is_zero()));
        assert!(!solo_resolver
            .cache
            .read()
            .await
            .contains_key("real-nx-solo-p53.example"));

        // 4. Trusted custom/filtering port-53 server accepts NXDOMAIN immediately without
        //    failing over to the backup non-53 server.
        let trusted_p53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let trusted_p53_addr = trusted_p53.local_addr().unwrap();
        let backup_non53 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backup_non53_addr = backup_non53.local_addr().unwrap();
        let backup_hits = Arc::new(AtomicUsize::new(0));
        let backup_hits_srv = Arc::clone(&backup_hits);

        let trusted_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = trusted_p53.recv_from(&mut buf).await.unwrap();
            let p = parse_dns_question(&buf[..n]).unwrap();
            let resp = build_dns_wire_response(
                p.tx_id,
                p.flags,
                &buf[12..p.question_end],
                3,
                &[],
                60,
            );
            trusted_p53.send_to(&resp, peer).await.unwrap();
        });
        let backup_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if backup_non53.recv_from(&mut buf).await.is_ok() {
                backup_hits_srv.fetch_add(1, Ordering::SeqCst);
            }
        });

        let mut trusted_resolver = DnsResolver::new_with_options(
            "127.0.0.1",
            trusted_p53_addr.port(),
            false,
            true,
            true,
            None,
        )
        .unwrap();
        trusted_resolver.udp_dns_servers = vec![trusted_p53_addr, backup_non53_addr];
        trusted_resolver.test_port53_servers = vec![trusted_p53_addr];
        assert!(trusted_resolver.udp_server_allows_sinkhole_and_loopback(trusted_p53_addr));

        let trusted_outcome = trusted_resolver
            .query_udp_type("adblock-nx.example", QTYPE_A)
            .await
            .unwrap();
        trusted_task.await.unwrap();
        backup_task.abort();
        assert!(matches!(trusted_outcome, DnsOutcome::NxDomain(ttl) if !ttl.is_zero()));
        assert_eq!(
            backup_hits.load(Ordering::SeqCst),
            0,
            "trusted custom port-53 NXDOMAIN must not fail over"
        );
    }

    #[tokio::test]
    async fn proxy_mode_lan_and_single_label_falls_back_to_custom_udp_primary() {
        let corp_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let corp_udp_addr = corp_udp.local_addr().unwrap();
        let corp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for (expected_name, reply_ip) in [
                ("intranet", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))),
                ("git.corp.internal", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 43))),
                ("nas.lan", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 44))),
            ] {
                let (n, peer) = corp_udp.recv_from(&mut buf).await.unwrap();
                let p = parse_dns_question(&buf[..n]).unwrap();
                assert_eq!(p.qname, expected_name);
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[reply_ip],
                    60,
                );
                corp_udp.send_to(&resp, peer).await.unwrap();
            }
        });

        let doh_hits = Arc::new(AtomicUsize::new(0));
        let doh_hits_srv = Arc::clone(&doh_hits);
        let doh_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doh_addr = doh_listener.local_addr().unwrap();
        let doh_task = tokio::spawn(async move {
            if doh_listener.accept().await.is_ok() {
                doh_hits_srv.fetch_add(1, Ordering::SeqCst);
            }
        });

        // 1. Proxy mode with explicit custom bare-IP UDP server (e.g. corporate --dns 10.0.0.53):
        //    when OS DNS fails for single-label / private suffixes, falls back to custom_udp
        //    without leaking to public DoH.
        let mut proxy_corp =
            DnsResolver::new("127.0.0.1", corp_udp_addr.port(), true, true).unwrap();
        proxy_corp.udp_dns_servers = vec![corp_udp_addr];
        proxy_corp.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        proxy_corp.test_force_system_dns_error = true;

        assert!(proxy_corp.should_route_to_system_resolver("intranet", false));
        assert!(proxy_corp.should_route_to_system_resolver("git.corp.internal", false));
        assert!(proxy_corp.should_route_to_system_resolver("nas.lan", false));
        assert_eq!(proxy_corp.active_custom_udp_primary(), Some(corp_udp_addr));

        assert_eq!(
            proxy_corp.resolve("intranet").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))]
        );
        assert_eq!(
            proxy_corp.resolve("git.corp.internal").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 43))]
        );
        let single_qtype = proxy_corp
            .resolve_single_qtype("nas.lan", QTYPE_A, false, false)
            .await
            .unwrap();
        assert!(matches!(
            single_qtype,
            DnsOutcome::Records(ref ips, _)
                if ips.as_slice() == [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 44))]
        ));
        corp_task.await.unwrap();
        assert_eq!(
            doh_hits.load(Ordering::SeqCst),
            0,
            "LAN/private fallback must never leak to DoH"
        );

        // 2. Proxy mode with default public DoH IP (1.1.1.1 -> no custom_udp_primary):
        //    still returns the system DNS error without leaking internal names to DoH/UDP.
        let mut proxy_default = DnsResolver::new("1.1.1.1", 53, true, true).unwrap();
        proxy_default.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        proxy_default.udp_dns_servers = Vec::new();
        proxy_default.test_force_system_dns_error = true;

        assert_eq!(proxy_default.active_custom_udp_primary(), None);
        assert!(proxy_default.resolve("intranet").await.is_err());
        assert!(proxy_default
            .resolve_single_qtype("git.corp.internal", QTYPE_A, false, false)
            .await
            .is_err());
        doh_task.abort();
        assert_eq!(doh_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn combine_udp_v4_v6_results_preserves_valid_ttl_on_zero_nxdomain() {
        let v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let v6 = IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());

        // 1. Valid A records + uncached AAAA NxDomain(Duration::ZERO) from a solo untrusted
        //    port-53 server must keep A's positive cache TTL instead of clamping it to zero.
        let res = combine_udp_v4_v6_results(
            "v4-only.example",
            Ok(DnsOutcome::Records(vec![v4], Duration::from_secs(120))),
            Some(Ok(DnsOutcome::NxDomain(Duration::ZERO))),
        )
        .unwrap();
        assert!(res.has_a_lookup);
        assert!(res.has_aaaa_lookup);
        assert!(matches!(
            res.outcome,
            DnsOutcome::Records(ref ips, ttl)
                if ips.as_slice() == [v4] && ttl == Duration::from_secs(120)
        ));

        // 2. Positive AAAA NxDomain TTL still clamps the combined record TTL normally.
        let clamped = combine_udp_v4_v6_results(
            "v4-only-clamped.example",
            Ok(DnsOutcome::Records(vec![v4], Duration::from_secs(120))),
            Some(Ok(DnsOutcome::NxDomain(Duration::from_secs(30)))),
        )
        .unwrap();
        assert!(matches!(
            clamped.outcome,
            DnsOutcome::Records(ref ips, ttl)
                if ips.as_slice() == [v4] && ttl == Duration::from_secs(30)
        ));

        // 3. Symmetric case: uncached A NxDomain(Duration::ZERO) + valid AAAA records keeps
        //    AAAA's positive cache TTL.
        let v6_only = combine_udp_v4_v6_results(
            "v6-only.example",
            Ok(DnsOutcome::NxDomain(Duration::ZERO)),
            Some(Ok(DnsOutcome::Records(vec![v6], Duration::from_secs(90)))),
        )
        .unwrap();
        assert!(matches!(
            v6_only.outcome,
            DnsOutcome::Records(ref ips, ttl)
                if ips.as_slice() == [v6] && ttl == Duration::from_secs(90)
        ));

        // 4. When both families return no records and either returned an uncached zero-TTL
        //    NxDomain, the combined NxDomain stays uncached (Duration::ZERO).
        let nx_zero_v6 = combine_udp_v4_v6_results(
            "missing-a.example",
            Ok(DnsOutcome::NxDomain(Duration::from_secs(30))),
            Some(Ok(DnsOutcome::NxDomain(Duration::ZERO))),
        )
        .unwrap();
        assert!(matches!(
            nx_zero_v6.outcome,
            DnsOutcome::NxDomain(ttl) if ttl.is_zero()
        ));

        let nx_zero_v4 = combine_udp_v4_v6_results(
            "missing-b.example",
            Ok(DnsOutcome::NxDomain(Duration::ZERO)),
            Some(Ok(DnsOutcome::NxDomain(Duration::from_secs(30)))),
        )
        .unwrap();
        assert!(matches!(
            nx_zero_v4.outcome,
            DnsOutcome::NxDomain(ttl) if ttl.is_zero()
        ));
    }

    #[tokio::test]
    async fn resolve_outcome_ipv4_only_cache_hit_filters_v6_and_misses_on_v6_only() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let queries_seen = Arc::new(AtomicUsize::new(0));
        let queries_seen_srv = Arc::clone(&queries_seen);
        let fresh_v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));
        let srv_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            queries_seen_srv.fetch_add(1, Ordering::SeqCst);
            let parsed = parse_dns_question(&buf[..n]).unwrap();
            assert_eq!(parsed.qname, "v6only-cached-flip.example");
            assert_eq!(parsed.qtype, QTYPE_A);
            let resp = build_dns_wire_response(
                parsed.tx_id,
                parsed.flags,
                &buf[12..parsed.question_end],
                0,
                &[fresh_v4],
                120,
            );
            udp_server.send_to(&resp, peer).await.unwrap();
        });

        let mut resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, false, true, None).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];

        let cached_v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let cached_v6 = IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());
        {
            let mut guard = resolver.cache.write().await;
            guard.insert(
                "dual-cached-flip.example".to_string(),
                CacheEntry {
                    ips: vec![cached_v4, cached_v6],
                    nxdomain: false,
                    has_a_lookup: true,
                    has_aaaa_lookup: true,
                    aaaa_retry_after: None,
                    expires_at: Instant::now() + Duration::from_secs(120),
                },
            );
            guard.insert(
                "v6only-cached-flip.example".to_string(),
                CacheEntry {
                    ips: vec![cached_v6],
                    nxdomain: false,
                    has_a_lookup: true,
                    has_aaaa_lookup: true,
                    aaaa_retry_after: None,
                    expires_at: Instant::now() + Duration::from_secs(120),
                },
            );
        }

        // Before switching to ipv4_only=true, both dual-stack and IPv6-only entries hit cache.
        assert_eq!(
            resolver.resolve("dual-cached-flip.example").await.unwrap(),
            vec![cached_v4, cached_v6]
        );
        assert_eq!(
            resolver
                .resolve("v6only-cached-flip.example")
                .await
                .unwrap(),
            vec![cached_v6]
        );
        assert_eq!(queries_seen.load(Ordering::SeqCst), 0);

        // After switching to ipv4_only=true:
        // - dual-stack cache hit filters out IPv6 and returns only IPv4 without hitting network.
        // - IPv6-only cache entry becomes empty after filtering -> treated as cache miss so a
        //   fresh QTYPE_A lookup runs instead of returning stale IPv6-only cached IPs.
        resolver.set_ipv4_only(true);
        assert_eq!(
            resolver.resolve("dual-cached-flip.example").await.unwrap(),
            vec![cached_v4]
        );
        assert_eq!(queries_seen.load(Ordering::SeqCst), 0);

        assert_eq!(
            resolver
                .resolve("v6only-cached-flip.example")
                .await
                .unwrap(),
            vec![fresh_v4]
        );
        srv_task.await.unwrap();
        assert_eq!(queries_seen.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_mode_corporate_ad_dot_local_falls_back_to_custom_udp_primary() {
        let corp_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let corp_udp_addr = corp_udp.local_addr().unwrap();
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let udp_hits_srv = Arc::clone(&udp_hits);
        let corp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, peer)) = corp_udp.recv_from(&mut buf).await else {
                    break;
                };
                udp_hits_srv.fetch_add(1, Ordering::SeqCst);
                let p = parse_dns_question(&buf[..n]).unwrap();
                let reply_ip = match p.qname.as_str() {
                    "dc01.corp.local" => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54)),
                    "files.ad.local" => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 55)),
                    "intranet.corp.local" => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 56)),
                    "erp.corp.local" => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 57)),
                    other => panic!("unexpected .local query: {other}"),
                };
                let resp = build_dns_wire_response(
                    p.tx_id,
                    p.flags,
                    &buf[12..p.question_end],
                    0,
                    &[reply_ip],
                    60,
                );
                corp_udp.send_to(&resp, peer).await.unwrap();
            }
        });

        let doh_hits = Arc::new(AtomicUsize::new(0));
        let doh_hits_srv = Arc::clone(&doh_hits);
        let doh_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let doh_addr = doh_listener.local_addr().unwrap();
        let doh_task = tokio::spawn(async move {
            if doh_listener.accept().await.is_ok() {
                doh_hits_srv.fetch_add(1, Ordering::SeqCst);
            }
        });

        // 1. Proxy mode with explicit custom bare-IP UDP server (e.g. corporate --dns 10.0.0.53):
        //    when OS DNS fails for Active Directory `.local`, fall back to custom_udp without
        //    leaking to public DoH, and cache successful answers so subsequent lookups hit the
        //    DNS TTL cache without re-paying OS mDNS timeouts or re-querying UDP.
        let mut proxy_corp =
            DnsResolver::new("127.0.0.1", corp_udp_addr.port(), true, true).unwrap();
        proxy_corp.udp_dns_servers = vec![corp_udp_addr];
        proxy_corp.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        proxy_corp.test_force_system_dns_error = true;

        assert_eq!(proxy_corp.active_custom_udp_primary(), Some(corp_udp_addr));
        assert_eq!(
            proxy_corp.resolve("dc01.corp.local").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54))]
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
        assert!(proxy_corp
            .cache
            .read()
            .await
            .contains_key("dc01.corp.local"));
        // Second resolve hits cache directly without calling OS DNS or custom_udp again.
        assert_eq!(
            proxy_corp.resolve("dc01.corp.local").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 54))]
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 1);

        let single_qtype = proxy_corp
            .resolve_single_qtype("files.ad.local", QTYPE_A, false, false)
            .await
            .unwrap();
        assert!(matches!(
            single_qtype,
            DnsOutcome::Records(ref ips, _)
                if ips.as_slice() == [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 55))]
        ));
        assert_eq!(udp_hits.load(Ordering::SeqCst), 2);
        assert!(proxy_corp
            .cache
            .read()
            .await
            .contains_key("files.ad.local"));
        // Second single-qtype lookup hits cache directly.
        let single_qtype_cached = proxy_corp
            .resolve_single_qtype("files.ad.local", QTYPE_A, false, false)
            .await
            .unwrap();
        assert!(matches!(
            single_qtype_cached,
            DnsOutcome::Records(ref ips, _)
                if ips.as_slice() == [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 55))]
        ));
        assert_eq!(udp_hits.load(Ordering::SeqCst), 2);
        assert_eq!(
            doh_hits.load(Ordering::SeqCst),
            0,
            ".local fallback must never leak to DoH"
        );

        // 2. Proxy mode with default public DoH IP (1.1.1.1 -> no custom_udp_primary):
        //    returns the system DNS error without leaking `.local` to DoH/UDP.
        let mut proxy_default = DnsResolver::new("1.1.1.1", 53, true, true).unwrap();
        proxy_default.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        proxy_default.udp_dns_servers = Vec::new();
        proxy_default.test_force_system_dns_error = true;

        assert_eq!(proxy_default.active_custom_udp_primary(), None);
        assert!(proxy_default.resolve("dc01.corp.local").await.is_err());
        assert!(proxy_default
            .resolve_single_qtype("files.ad.local", QTYPE_A, false, false)
            .await
            .is_err());

        // 3. TUN mode (disable_system_dns_fallback=true) with explicit custom corporate bare-IP
        //    UDP server queries custom_udp directly for `.local` hostnames and caches the answer.
        let mut tun_corp = DnsResolver::new_with_options(
            "127.0.0.1",
            corp_udp_addr.port(),
            true,
            true,
            true,
            None,
        )
        .unwrap();
        tun_corp.udp_dns_servers = vec![corp_udp_addr];
        tun_corp.doh_endpoints =
            vec![format!("https://127.0.0.1:{}/dns-query", doh_addr.port())];
        assert!(tun_corp.is_system_dns_disabled());
        assert_eq!(tun_corp.active_custom_udp_primary(), Some(corp_udp_addr));

        assert_eq!(
            tun_corp.resolve("intranet.corp.local").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 56))]
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 3);
        // Cached hit in TUN mode does not re-query custom_udp.
        assert_eq!(
            tun_corp.resolve("intranet.corp.local").await.unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 56))]
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 3);

        let tun_single = tun_corp
            .resolve_single_qtype("erp.corp.local", QTYPE_A, false, false)
            .await
            .unwrap();
        assert!(matches!(
            tun_single,
            DnsOutcome::Records(ref ips, _)
                if ips.as_slice() == [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 57))]
        ));
        assert_eq!(udp_hits.load(Ordering::SeqCst), 4);
        let wire_q = encode_dns_query("erp.corp.local", QTYPE_A).unwrap();
        let (wire_resp, wire_meta) = tun_corp.resolve_wire_query(&wire_q, true).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([wire_resp[2], wire_resp[3]]) & 0x000f,
            0
        );
        assert_eq!(
            wire_meta,
            Some((
                "erp.corp.local".to_string(),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 57))],
            ))
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 4);

        // 4. TUN mode WITHOUT custom corporate bare-IP UDP server (e.g. default 1.1.1.1)
        //    still returns synthetic NXDOMAIN for `.local`.
        let tun_default =
            DnsResolver::new_with_options("1.1.1.1", 53, true, true, true, None).unwrap();
        assert_eq!(tun_default.active_custom_udp_primary(), None);
        assert!(matches!(
            tun_default
                .resolve_outcome("printer.local", false)
                .await
                .unwrap(),
            DnsOutcome::NxDomain(_)
        ));
        assert!(matches!(
            tun_default
                .resolve_single_qtype("printer.local", QTYPE_A, false, false)
                .await
                .unwrap(),
            DnsOutcome::NxDomain(_)
        ));

        corp_task.abort();
        doh_task.abort();
        assert_eq!(doh_hits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dns64_ipv6_addresses_are_known_public_doh_ips() {
        for dns64 in [
            "2606:4700:4700::64",
            "2606:4700:4700::6400",
            "2001:4860:4860::6464",
            "2001:4860:4860::64",
        ] {
            let ip: IpAddr = dns64.parse().unwrap();
            assert!(
                is_known_public_doh_ip(ip),
                "expected DNS64 IPv6 to be recognized as known public DoH IP: {dns64}"
            );
            assert!(is_effective_doh_target(dns64, true));
            assert!(!is_effective_doh_target(dns64, false));

            let expected = format!("https://[{ip}]/dns-query");
            let eps = build_doh_endpoints(dns64, false, false, false);
            assert_eq!(eps[0], expected);

            let resolver = DnsResolver::new(dns64, 53, true, false).unwrap();
            assert!(resolver.enable_doh);
            assert_eq!(resolver.active_custom_udp_primary(), None);
            assert_eq!(resolver.doh_endpoints[0], expected);
        }

        for non_dns64 in ["2606:4700:4700::65", "2001:4860:4860::65"] {
            let ip: IpAddr = non_dns64.parse().unwrap();
            assert!(!is_known_public_doh_ip(ip));
        }
    }

    #[tokio::test]
    async fn wire_query_suppresses_aaaa_https_svcb_and_any_when_ipv4_only_and_on_dynamic_flip() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let udp_hits = Arc::new(AtomicUsize::new(0));
        let udp_hits_srv = Arc::clone(&udp_hits);
        let v4_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let v6_ip: IpAddr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap();

        let srv = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..3 {
                let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
                udp_hits_srv.fetch_add(1, Ordering::SeqCst);
                let parsed = parse_dns_question(&buf[..n]).unwrap();
                let resp = match parsed.qtype {
                    QTYPE_A => build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &buf[12..parsed.question_end],
                        0,
                        &[v4_ip],
                        3600,
                    ),
                    QTYPE_AAAA => build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &buf[12..parsed.question_end],
                        0,
                        &[v6_ip],
                        3600,
                    ),
                    _ => build_dns_wire_response(
                        parsed.tx_id,
                        parsed.flags,
                        &buf[12..parsed.question_end],
                        0,
                        &[],
                        60,
                    ),
                };
                udp_server.send_to(&resp, peer).await.unwrap();
            }
        });

        let mut resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, true, true, None).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];

        // With ipv4_only=true and block_https_svcb=false, AAAA/HTTPS/SVCB/ANY are all suppressed
        // locally with synthetic NODATA+SOA without contacting upstream.
        for qtype in [QTYPE_AAAA, QTYPE_HTTPS, QTYPE_SVCB, QTYPE_ANY] {
            let q = encode_dns_query("leak-check.example", qtype).unwrap();
            let (resp, meta) = resolver.resolve_wire_query(&q, false).await.unwrap();
            assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x000f, 0);
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
            assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 1);
            assert!(meta.is_none());
        }
        assert_eq!(udp_hits.load(Ordering::SeqCst), 0);

        // QTYPE_A still resolves upstream and clamps wire TTL from 3600s to <= 300s.
        let q_a = encode_dns_query("leak-check.example", QTYPE_A).unwrap();
        let (resp_a, meta_a) = resolver.resolve_wire_query(&q_a, false).await.unwrap();
        let (ips_a, ttl_a) = decode_dns_response(&resp_a, QTYPE_A).unwrap();
        assert_eq!(ips_a, vec![v4_ip]);
        assert_eq!(ttl_a, Duration::from_secs(300));
        assert_eq!(meta_a, Some(("leak-check.example".to_string(), vec![v4_ip])));
        assert_eq!(udp_hits.load(Ordering::SeqCst), 1);

        // Dynamic flip to ipv4_only=false stops suppressing AAAA and HTTPS (when block_https_svcb=false).
        resolver.set_ipv4_only(false);
        let q_aaaa = encode_dns_query("leak-check.example", QTYPE_AAAA).unwrap();
        let (resp_aaaa, meta_aaaa) = resolver.resolve_wire_query(&q_aaaa, false).await.unwrap();
        let (ips_aaaa, ttl_aaaa) = decode_dns_response(&resp_aaaa, QTYPE_AAAA).unwrap();
        assert_eq!(ips_aaaa, vec![v6_ip]);
        assert_eq!(ttl_aaaa, Duration::from_secs(300));
        assert_eq!(
            meta_aaaa,
            Some(("leak-check.example".to_string(), vec![v6_ip]))
        );
        assert_eq!(udp_hits.load(Ordering::SeqCst), 2);

        let q_https = encode_dns_query("leak-check.example", QTYPE_HTTPS).unwrap();
        let _ = resolver.resolve_wire_query(&q_https, false).await.unwrap();
        assert_eq!(udp_hits.load(Ordering::SeqCst), 3);

        // Dynamic flip back to ipv4_only=true immediately re-enables suppression.
        resolver.set_ipv4_only(true);
        for qtype in [QTYPE_AAAA, QTYPE_HTTPS, QTYPE_SVCB, QTYPE_ANY] {
            let q = encode_dns_query("leak-check-2.example", qtype).unwrap();
            let (resp, meta) = resolver.resolve_wire_query(&q, false).await.unwrap();
            assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x000f, 0);
            assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
            assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 1);
            assert!(meta.is_none());
        }
        assert_eq!(udp_hits.load(Ordering::SeqCst), 3);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn clear_cache_resets_preferred_doh_idx_and_join_a_and_aaaa_fast_returns_nxdomain() {
        let resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        resolver.preferred_doh_idx.store(2, Ordering::Relaxed);
        resolver.preferred_udp_idx.store(3, Ordering::Relaxed);
        resolver.clear_cache().await;
        assert_eq!(resolver.preferred_doh_idx.load(Ordering::Relaxed), 0);
        assert_eq!(resolver.preferred_udp_idx.load(Ordering::Relaxed), 0);

        let started = Instant::now();
        let (v4, v6) = join_a_and_aaaa(
            async { Ok::<DnsOutcome, anyhow::Error>(DnsOutcome::NxDomain(Duration::from_secs(30))) },
            async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                Ok::<DnsOutcome, anyhow::Error>(DnsOutcome::Records(
                    vec![IpAddr::V6("2001:db8::1".parse().unwrap())],
                    Duration::from_secs(60),
                ))
            },
            Duration::from_millis(700),
            |res| matches!(res, Ok(DnsOutcome::Records(ips, _)) if !ips.is_empty()),
            |res| matches!(res, Ok(DnsOutcome::NxDomain(_))),
        )
        .await;
        assert!(matches!(v4, Ok(DnsOutcome::NxDomain(_))));
        assert!(v6.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "join_a_and_aaaa must return immediately on v4 NxDomain without waiting for AAAA"
        );
    }

    #[tokio::test]
    async fn doh_servfail_and_refused_fail_over_ring_and_custom_doh_refuses_ipv6_when_ipv4_only() {
        let (server_cfg, connector) = make_local_doh_tls_pair();
        let err_acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&server_cfg));
        let ok_acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);

        let err_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let err_addr = err_listener.local_addr().unwrap();
        let ok_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ok_addr = ok_listener.local_addr().unwrap();

        let err_task = tokio::spawn(async move {
            for rcode in [2u8, 5u8] {
                let (tcp, _) = err_listener.accept().await.unwrap();
                let mut tls = err_acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    rcode,
                    &[],
                    0,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });
        let ok_task = tokio::spawn(async move {
            for ip in [
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
            ] {
                let (tcp, _) = ok_listener.accept().await.unwrap();
                let mut tls = ok_acceptor.accept(tcp).await.unwrap();
                let query = read_doh_test_request(&mut tls).await;
                let parsed = parse_dns_question(&query).unwrap();
                let wire_resp = build_dns_wire_response(
                    parsed.tx_id,
                    parsed.flags,
                    &query[12..parsed.question_end],
                    0,
                    &[ip],
                    120,
                );
                write_doh_test_response(&mut tls, &wire_resp).await;
            }
        });

        let err_ep = format!("https://127.0.0.1:{}/dns-query", err_addr.port());
        let ok_ep = format!("https://127.0.0.1:{}/dns-query", ok_addr.port());
        let binder: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let mut resolver =
            DnsResolver::new_with_binder("127.0.0.1", 53, true, true, Some(binder)).unwrap();
        resolver.bound_tls_connector = Some(connector);
        resolver.custom_primary_doh_endpoint = Some(err_ep.clone());
        resolver.doh_endpoints = vec![err_ep, ok_ep];
        resolver.udp_dns_servers = Vec::new();

        // SERVFAIL (2) on primary filtering DoH fails over to backup DoH.
        let ips1 = resolver.resolve("servfail-failover.example").await.unwrap();
        assert_eq!(ips1, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert!(!resolver.is_doh_in_backoff());

        // Reset preferred_doh_idx to 0 and test REFUSED (5) failover too.
        resolver.preferred_doh_idx.store(0, Ordering::Relaxed);
        let ips2 = resolver.resolve("refused-failover.example").await.unwrap();
        assert_eq!(ips2, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35))]);
        assert!(!resolver.is_doh_in_backoff());

        err_task.await.unwrap();
        ok_task.await.unwrap();

        // send_custom_doh_wire must error instead of falling back to IPv6 when ipv4_only=true.
        let binder2: Arc<dyn OutboundBinder> = Arc::new(NoopBinder);
        let custom_resolver = DnsResolver::new_with_binder(
            "https://ipv6-only-doh.example/dns-query",
            53,
            true,
            true,
            Some(binder2),
        )
        .unwrap();
        let custom = custom_resolver.custom_doh.as_ref().unwrap();
        {
            let mut state = custom.state.write().await;
            state.ips = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
            state.expires_at = Instant::now() + Duration::from_secs(300);
        }
        let wire_q = encode_dns_query("example.com", QTYPE_A).unwrap();
        assert!(
            custom_resolver
                .send_custom_doh_wire(custom, &wire_q)
                .await
                .is_err(),
            "send_custom_doh_wire must refuse IPv6 fallback when ipv4_only is true"
        );
    }

    #[tokio::test]
    async fn aaaa_timeout_uses_short_cooldown_instead_of_repeated_cache_miss_stalls() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp_server.local_addr().unwrap();
        let a_queries = Arc::new(AtomicUsize::new(0));
        let a_queries_srv = Arc::clone(&a_queries);

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
                    a_queries_srv.fetch_add(1, Ordering::SeqCst);
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

        let mut resolver =
            DnsResolver::new_with_options("1.1.1.1", 53, false, false, true, None).unwrap();
        resolver.udp_dns_servers = vec![udp_addr];

        let first = resolver.resolve("cooldown-aaaa.example").await.unwrap();
        assert_eq!(first, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        server_task.await.unwrap();
        assert_eq!(a_queries.load(Ordering::SeqCst), 1);

        // Second resolve() during the short AAAA timeout cooldown serves cached IPv4 immediately
        // instead of stalling on another 700-800ms AAAA timeout.
        let started = Instant::now();
        let second = resolver.resolve("cooldown-aaaa.example").await.unwrap();
        assert_eq!(second, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "cached IPv4 must be served immediately during AAAA timeout cooldown"
        );
        assert_eq!(a_queries.load(Ordering::SeqCst), 1);
    }
}
