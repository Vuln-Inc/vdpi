use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::RwLock;
use tracing::debug;

const QTYPE_A: u16 = 1;
const QTYPE_CNAME: u16 = 5;
const QTYPE_AAAA: u16 = 28;
const QCLASS_IN: u16 = 1;

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct DnsResolver {
    enable_doh: bool,
    ipv4_only: bool,
    udp_dns_servers: Vec<SocketAddr>,
    doh_endpoints: Vec<String>,
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
            .timeout(Duration::from_millis(2500))
            .connect_timeout(Duration::from_millis(1500))
            .pool_idle_timeout(Duration::from_secs(90))
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
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Resolves `host` into an ordered list of IP addresses (IPv4 preferred before IPv6).
    /// Resistant to ISP port-53 DNS hijacking by cascading through RFC 8484 DoH providers
    /// and non-standard port 1253 UDP DNS before falling back to OS resolution.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let normalized = host
            .trim()
            .trim_matches(|c| c == '[' || c == ']')
            .trim_end_matches('.')
            .to_ascii_lowercase();

        if normalized.is_empty() {
            bail!("empty hostname");
        }

        // 1. Direct IP literal
        if let Ok(ip) = normalized.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // 2. Localhost fast-path
        if normalized == "localhost" {
            return if self.ipv4_only {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            } else {
                Ok(vec![
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                ])
            };
        }

        // 3. mDNS (.local) via OS resolver
        if normalized.ends_with(".local") {
            return self.resolve_via_system(&normalized).await;
        }

        // 4. In-memory TTL cache lookup
        {
            let guard = self.cache.read().await;
            if let Some(entry) = guard.get(&normalized) {
                if Instant::now() < entry.expires_at && !entry.ips.is_empty() {
                    return Ok(entry.ips.clone());
                }
            }
        }

        // 5. Multi-tier unpoisoned resolution:
        //    Tier A: RFC 8484 DNS-over-HTTPS (Cloudflare / Google / Quad9 IP endpoints)
        //    Tier B: Non-standard port 1253 + backup UDP DNS (bypasses ISP port-53 transparent proxies)
        //    Tier C: System resolver fallback
        let (ips, ttl) = if self.enable_doh {
            match self.resolve_via_doh(&normalized).await {
                Ok(res) if !res.0.is_empty() => res,
                _ => match self.resolve_via_udp(&normalized).await {
                    Ok(res) if !res.0.is_empty() => res,
                    _ => {
                        let sys = self.resolve_via_system(&normalized).await?;
                        (sys, Duration::from_secs(60))
                    }
                },
            }
        } else {
            match self.resolve_via_udp(&normalized).await {
                Ok(res) if !res.0.is_empty() => res,
                _ => {
                    let sys = self.resolve_via_system(&normalized).await?;
                    (sys, Duration::from_secs(60))
                }
            }
        };

        if ips.is_empty() {
            bail!("no IP addresses resolved for {normalized}");
        }

        {
            let mut guard = self.cache.write().await;
            if guard.len() > 4096 {
                let now = Instant::now();
                guard.retain(|_, v| v.expires_at > now);
            }
            guard.insert(
                normalized,
                CacheEntry {
                    ips: ips.clone(),
                    expires_at: Instant::now() + ttl,
                },
            );
        }

        Ok(ips)
    }

    async fn resolve_via_doh(&self, domain: &str) -> Result<(Vec<IpAddr>, Duration)> {
        if self.ipv4_only {
            return self.query_doh_type(domain, QTYPE_A).await;
        }

        let (v4_res, v6_res) = tokio::join!(
            self.query_doh_type(domain, QTYPE_A),
            self.query_doh_type(domain, QTYPE_AAAA)
        );

        let mut ips = Vec::new();
        let mut min_ttl = Duration::from_secs(300);

        if let Ok((v4, ttl)) = v4_res {
            if !v4.is_empty() {
                min_ttl = min_ttl.min(ttl);
                ips.extend(v4);
            }
        }

        // CNAME-only empty AAAA responses (such as www.roblox.com) are normal and must never
        // discard valid IPv4 A records.
        if let Ok((v6, ttl)) = v6_res {
            if !v6.is_empty() {
                min_ttl = min_ttl.min(ttl);
                for ip in v6 {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }

        if ips.is_empty() {
            bail!("DoH returned no A/AAAA records for {domain}");
        }

        Ok((ips, min_ttl))
    }

    async fn query_doh_type(&self, domain: &str, qtype: u16) -> Result<(Vec<IpAddr>, Duration)> {
        let wire_query = encode_dns_query(domain, qtype)?;
        let mut last_err = None;

        for endpoint in &self.doh_endpoints {
            match self
                .http
                .post(endpoint)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .body(wire_query.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => match resp.bytes().await {
                    Ok(bytes) => match decode_dns_response(&bytes, qtype) {
                        Ok(parsed) => {
                            debug!(
                                domain = %domain,
                                qtype = qtype,
                                endpoint = %endpoint,
                                count = parsed.0.len(),
                                "DoH query succeeded"
                            );
                            return Ok(parsed);
                        }
                        Err(e) => last_err = Some(e),
                    },
                    Err(e) => last_err = Some(e.into()),
                },
                Ok(resp) => {
                    last_err = Some(anyhow!(
                        "DoH HTTP status {} from {}",
                        resp.status(),
                        endpoint
                    ));
                }
                Err(e) => {
                    last_err = Some(e.into());
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("no DoH endpoints reachable")))
    }

    async fn resolve_via_udp(&self, domain: &str) -> Result<(Vec<IpAddr>, Duration)> {
        let wire_query = encode_dns_query(domain, QTYPE_A)?;
        let mut last_err = None;

        for &server in &self.udp_dns_servers {
            let bind_addr = if server.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let Ok(sock) = UdpSocket::bind(bind_addr).await else {
                continue;
            };
            if sock.connect(server).await.is_err() {
                continue;
            }
            if sock.send(&wire_query).await.is_err() {
                continue;
            }

            let mut buf = [0u8; 2048];
            match tokio::time::timeout(Duration::from_millis(1200), sock.recv(&mut buf)).await {
                Ok(Ok(n)) => match decode_dns_response(&buf[..n], QTYPE_A) {
                    Ok(parsed) if !parsed.0.is_empty() => return Ok(parsed),
                    Ok(_) => {}
                    Err(e) => last_err = Some(e),
                },
                Ok(Err(e)) => last_err = Some(e.into()),
                Err(_) => last_err = Some(anyhow!("UDP DNS timeout from {server}")),
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow!("UDP DNS resolution failed for {domain}")))
    }

    async fn resolve_via_system(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let addrs = lookup_host((domain, 443u16))
            .await
            .with_context(|| format!("system DNS lookup failed for {domain}"))?;

        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for sa in addrs {
            match sa.ip() {
                IpAddr::V4(ip) => {
                    let addr = IpAddr::V4(ip);
                    if !v4.contains(&addr) {
                        v4.push(addr);
                    }
                }
                IpAddr::V6(ip) if !self.ipv4_only => {
                    let addr = IpAddr::V6(ip);
                    if !v6.contains(&addr) {
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
}

fn build_doh_endpoints(dns_addr: &str) -> Vec<String> {
    let mut list = Vec::new();
    let trimmed = dns_addr.trim();
    if trimmed.starts_with("https://") {
        list.push(trimmed.to_string());
    } else if !trimmed.is_empty() {
        let primary = match trimmed {
            "1.1.1.1" | "1.0.0.1" => format!("https://{trimmed}/dns-query"),
            "8.8.8.8" | "8.8.4.4" => format!("https://{trimmed}/dns-query"),
            "9.9.9.9" | "149.112.112.112" => format!("https://{trimmed}/dns-query"),
            other if other.parse::<Ipv4Addr>().is_ok() => format!("https://{other}/dns-query"),
            _ => "https://1.1.1.1/dns-query".to_string(),
        };
        list.push(primary);
    }

    // Multi-provider IP-literal DoH ring (no SNI required, immune to ISP domain-based DPI blocks)
    for fallback in [
        "https://1.1.1.1/dns-query",
        "https://1.0.0.1/dns-query",
        "https://8.8.8.8/dns-query",
        "https://8.8.4.4/dns-query",
        "https://9.9.9.9/dns-query",
    ] {
        if !list.iter().any(|x| x == fallback) {
            list.push(fallback.to_string());
        }
    }
    list
}

fn build_udp_dns_servers(dns_addr: &str, dns_port: u16) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    if let Ok(ip) = dns_addr.trim().parse::<IpAddr>() {
        servers.push(SocketAddr::new(ip, dns_port));
    }
    // Non-standard port 1253 on 77.88.8.8 / 77.88.8.1 bypasses transparent ISP port-53 DNS interceptors
    // on fiber providers (such as Superonline, Kablonet, and Turk Telekom).
    for (ip, port) in [
        (Ipv4Addr::new(77, 88, 8, 8), 1253),
        (Ipv4Addr::new(77, 88, 8, 1), 1253),
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
    if buf.len() < 12 {
        bail!("DNS response shorter than 12-byte header");
    }

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000f;
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

    let clamped_ttl = Duration::from_secs(min_ttl_secs.unwrap_or(120).clamp(30, 3600));
    Ok((ips, clamped_ttl))
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
    async fn resolves_discord_and_roblox_via_live_doh() {
        let resolver = DnsResolver::new("1.1.1.1", 53, true, false).unwrap();
        let roblox_ips = resolver.resolve("www.roblox.com").await.unwrap();
        assert!(!roblox_ips.is_empty());
        assert!(roblox_ips[0].is_ipv4());

        let discord_ips = resolver.resolve("updates.discord.com").await.unwrap();
        assert!(!discord_ips.is_empty());
    }
}
