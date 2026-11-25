use anyhow::{Context, Result};
use regex::{RegexSet, RegexSetBuilder};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};

/// Built-in domains and wildcards that should never undergo TLS ClientHello fragmentation
/// (local mDNS, private networks, Tailscale, government portals, payment gateways,
/// banking WAFs, and anti-cheat/game services).
pub const DEFAULT_BYPASS_PATTERNS: &[&str] = &[
    // Local / private networks & Tailscale
    "localhost",
    "*.local",
    "*.lan",
    "*.internal",
    "*.home.arpa",
    "*.ts.net",
    // Government, military, international & Turkish public-sector domains
    "*.gov",
    "*.mil",
    "*.int",
    "*.gov.uk",
    "*.gov.tr",
    "*.bel.tr",
    "*.pol.tr",
    "*.tsk.tr",
    "*.kep.tr",
    "*.edu.tr",
    "*.org.tr",
    "*.osym.gov.tr",
    "*.edevlet.gov.tr",
    "*.turkiye.gov.tr",
    // Payment gateways & Turkish banking WAFs
    "*.bkm.com.tr",
    "*.paratika.com.tr",
    "*.halkbank.com.tr",
    "*.isbank.com.tr",
    "*.akbank.com",
    "*.akbank.com.tr",
    "*.garanti.com.tr",
    "*.garantibbva.com.tr",
    "*.ziraatbank.com.tr",
    "*.yapikredi.com.tr",
    "*.vakifbank.com.tr",
    "*.qnb.com.tr",
    "*.qnbfinansbank.com",
    "*.qnbfinansbank.com.tr",
    "*.denizbank.com",
    "*.enpara.com",
    "*.ing.com.tr",
    "*.teb.com.tr",
    "*.kuveytturk.com.tr",
    "*.albaraka.com.tr",
    "*.odeabank.com.tr",
    "*.iyzico.com",
    "*.iyzipay.com",
    "*.paytr.com",
    "*.papara.com",
    // Sensitive Turkish platforms & telecom
    "*.sahibinden.com",
    "*.shbdn.com",
    "*.turktelekom.com.tr",
    "*.pttavm.com",
    // Riot / Valorant (strict TLS & anti-cheat)
    "*.riotgames.com",
    "*.riotcdn.net",
    "*.playvalorant.com",
    "*.pvp.net",
    "*.rgpub.io",
];

/// Classification of a connection target for DPI bypass decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassClass {
    /// Local/private LAN, loopback, CGNAT, multicast, reserved, or private tailnet destination.
    LocalLan,
    /// Public destination that should pass through untouched (gov, banking, anti-cheat,
    /// custom `--bypass` rules/CIDRs, or excluded by `--include` filters).
    SensitiveDirect,
    /// Public destination eligible for DPI desynchronization.
    DesyncEligible,
}

/// Pure-Rust IPv4/IPv6 CIDR prefix matcher (avoids extra crate dependencies).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl IpNet {
    /// Parses a CIDR string like `203.0.113.0/24` or `2001:db8::/32`.
    pub fn parse(cidr: &str) -> Option<Self> {
        let (addr_part, prefix_part) = cidr.trim().split_once('/')?;
        let addr_clean = addr_part.trim().trim_matches(['[', ']']);
        let prefix_clean = prefix_part.trim();
        if prefix_clean.is_empty() || !prefix_clean.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix_len: u8 = prefix_clean.parse().ok()?;
        match addr_clean.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return None;
                }
                let mask = u32::MAX
                    .checked_shl(u32::from(32 - prefix_len))
                    .unwrap_or(0);
                Some(Self::V4 {
                    network: u32::from(v4) & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return None;
                }
                if let Some(v4) = v6.to_ipv4_mapped().filter(|_| prefix_len >= 96) {
                    let v4_prefix = prefix_len - 96;
                    let mask = u32::MAX.checked_shl(u32::from(32 - v4_prefix)).unwrap_or(0);
                    return Some(Self::V4 {
                        network: u32::from(v4) & mask,
                        mask,
                    });
                }
                let mask = u128::MAX
                    .checked_shl(u32::from(128 - prefix_len))
                    .unwrap_or(0);
                Some(Self::V6 {
                    network: u128::from(v6) & mask,
                    mask,
                })
            }
        }
    }

    /// Creates a host-exact `/32` or `/128` network from a single IP address,
    /// normalizing IPv4-mapped IPv6 addresses to `IpNet::V4`.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4 {
                network: u32::from(v4),
                mask: u32::MAX,
            },
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    Self::V4 {
                        network: u32::from(v4),
                        mask: u32::MAX,
                    }
                } else {
                    Self::V6 {
                        network: u128::from(v6),
                        mask: u128::MAX,
                    }
                }
            }
        }
    }

    /// Returns `true` if `ip` belongs to this CIDR prefix (including IPv4-mapped IPv6 for IPv4 nets).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (*self, ip) {
            (Self::V4 { network, mask }, IpAddr::V4(v4)) => (u32::from(v4) & mask) == network,
            (Self::V4 { network, mask }, IpAddr::V6(v6)) => v6
                .to_ipv4_mapped()
                .is_some_and(|v4| (u32::from(v4) & mask) == network),
            (Self::V6 { network, mask }, IpAddr::V6(v6)) => (u128::from(v6) & mask) == network,
            (Self::V6 { .. }, IpAddr::V4(_)) => false,
        }
    }
}

/// Determines whether a connection to `(host, ip)` should undergo DPI desynchronization
/// or pass through untouched.
#[derive(Debug, Clone)]
pub struct BypassPolicy {
    bypass_regexes: RegexSet,
    bypass_cidrs: Vec<IpNet>,
    target_patterns: Option<RegexSet>,
}

impl BypassPolicy {
    pub fn new(extra_bypass: &[String], include_patterns: &[String]) -> Result<Self> {
        let mut bypass_exprs =
            Vec::with_capacity(DEFAULT_BYPASS_PATTERNS.len() + extra_bypass.len());
        let mut bypass_cidrs = Vec::new();
        for pat in DEFAULT_BYPASS_PATTERNS {
            if let Some(expr) = wildcard_to_regex(pat) {
                bypass_exprs.push(expr);
            }
        }
        for pat in extra_bypass {
            let trimmed = pat.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.contains('/') {
                if let Some(net) = IpNet::parse(trimmed) {
                    bypass_cidrs.push(net);
                } else {
                    tracing::warn!(entry = trimmed, "ignoring invalid CIDR bypass rule");
                }
            } else if let Ok(ip) = trimmed.trim_matches(['[', ']']).parse::<IpAddr>() {
                bypass_cidrs.push(IpNet::from_ip(ip));
            } else if let Some(expr) = wildcard_to_regex(trimmed) {
                bypass_exprs.push(expr);
            }
        }

        let bypass_regexes =
            RegexSet::new(&bypass_exprs).context("failed to compile bypass wildcard rules")?;

        let target_patterns = if include_patterns.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(include_patterns)
                    .case_insensitive(true)
                    .build()
                    .context("failed to compile --include regular expressions")?,
            )
        };

        Ok(Self {
            bypass_regexes,
            bypass_cidrs,
            target_patterns,
        })
    }

    /// Returns `true` if `ip` is non-public (loopback, private RFC1918, link-local,
    /// unspecified / `0.0.0.0/8`, broadcast, CGNAT, multicast, reserved, benchmark,
    /// IETF protocol assignments, or IPv6 ULA / link-local / site-local / discard /
    /// NAT64 local-use or non-public embedded IPv4 / multicast / IPv4-mapped non-public).
    pub fn is_non_public_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // "This network" 0.0.0.0/8 (RFC 1122 / RFC 6890, includes 0.0.0.0)
                octets[0] == 0
                    || v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    // CGNAT 100.64.0.0/10 (RFC 6598)
                    || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
                    // IETF protocol assignments 192.0.0.0/24 (RFC 6890)
                    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
                    // Benchmarking 198.18.0.0/15 (RFC 2544)
                    || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
                    // Reserved for future use 240.0.0.0/4 (RFC 1112)
                    || octets[0] >= 240
            }
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    return Self::is_non_public_ip(IpAddr::V4(mapped_v4));
                }
                let segs = v6.segments();
                // Well-known NAT64 prefix 64:ff9b::/96 (RFC 6052): check embedded IPv4.
                if segs[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                    let octets = v6.octets();
                    let embedded_v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                    return Self::is_non_public_ip(IpAddr::V4(embedded_v4));
                }
                let first = segs[0];
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    // Local-use NAT64 64:ff9b:1::/48 (RFC 8215)
                    || segs[..3] == [0x0064, 0xff9b, 0x0001]
                    // Discard-only 100::/64 (RFC 6666)
                    || segs[..4] == [0x0100, 0, 0, 0]
                    // Unique local fc00::/7 (RFC 4193)
                    || (first & 0xfe00) == 0xfc00
                    // Link-local fe80::/10 (RFC 4291)
                    || (first & 0xffc0) == 0xfe80
                    // Deprecated site-local fec0::/10 (RFC 3879)
                    || (first & 0xffc0) == 0xfec0
            }
        }
    }

    fn matches_bypass_cidr(&self, ip: IpAddr) -> bool {
        self.bypass_cidrs.iter().any(|net| net.contains(ip))
    }

    /// Classifies `(host, ip)` as `LocalLan`, `SensitiveDirect`, or `DesyncEligible`.
    pub fn classify(&self, host: Option<&str>, ip: Option<IpAddr>) -> BypassClass {
        let non_public_resolved = ip.is_some_and(Self::is_non_public_ip);
        let loopback_resolved = ip.is_some_and(|addr| match addr {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
            }
        });
        if non_public_resolved && (self.target_patterns.is_none() || !loopback_resolved) {
            return BypassClass::LocalLan;
        }

        if let Some(raw_host) = host {
            let clean = normalize_host(raw_host);
            if !clean.is_empty() {
                if let Ok(host_ip) = clean.parse::<IpAddr>() {
                    if Self::is_non_public_ip(host_ip) || non_public_resolved {
                        return BypassClass::LocalLan;
                    }
                    if self.matches_bypass_cidr(host_ip)
                        || ip.is_some_and(|resolved| self.matches_bypass_cidr(resolved))
                    {
                        return BypassClass::SensitiveDirect;
                    }
                    if let Some(ref include) = self.target_patterns {
                        return if include.is_match(clean.as_ref()) {
                            BypassClass::DesyncEligible
                        } else {
                            BypassClass::SensitiveDirect
                        };
                    }
                    return BypassClass::DesyncEligible;
                }

                if is_local_hostname(clean.as_ref()) {
                    return BypassClass::LocalLan;
                }
                if self.bypass_regexes.is_match(clean.as_ref()) {
                    return BypassClass::SensitiveDirect;
                }
                if ip.is_some_and(|resolved| self.matches_bypass_cidr(resolved)) {
                    return BypassClass::SensitiveDirect;
                }
                if let Some(ref include) = self.target_patterns {
                    return if include.is_match(clean.as_ref()) {
                        BypassClass::DesyncEligible
                    } else if non_public_resolved {
                        BypassClass::LocalLan
                    } else {
                        BypassClass::SensitiveDirect
                    };
                }
                return BypassClass::DesyncEligible;
            }
        }

        if let Some(resolved_ip) = ip {
            if non_public_resolved {
                return BypassClass::LocalLan;
            }
            if self.matches_bypass_cidr(resolved_ip) {
                return BypassClass::SensitiveDirect;
            }
            if let Some(ref include) = self.target_patterns {
                return if include.is_match(&resolved_ip.to_string()) {
                    BypassClass::DesyncEligible
                } else {
                    BypassClass::SensitiveDirect
                };
            }
            return BypassClass::DesyncEligible;
        }

        if self.target_patterns.is_some() {
            BypassClass::SensitiveDirect
        } else {
            BypassClass::DesyncEligible
        }
    }

    /// Returns `true` if the given hostname or IP literal should bypass DPI fragmentation.
    pub fn is_bypassed(&self, host: Option<&str>, resolved_ip: Option<IpAddr>) -> bool {
        self.classify(host, resolved_ip) != BypassClass::DesyncEligible
    }

    /// Returns `true` if DPI desynchronization should be applied to `(host, resolved_ip)`.
    pub fn should_desync(&self, host: Option<&str>, resolved_ip: Option<IpAddr>) -> bool {
        self.classify(host, resolved_ip) == BypassClass::DesyncEligible
    }
}

/// Normalizes a hostname or bracketed IP literal (stripping IPv6 `%zone` suffixes)
/// without allocating when already lowercase.
fn normalize_host(raw: &str) -> Cow<'_, str> {
    let trimmed = raw.trim().trim_matches(['[', ']']).trim_end_matches('.');
    let trimmed = if trimmed.contains(':') {
        trimmed.split_once('%').map_or(trimmed, |(addr, _)| addr)
    } else {
        trimmed
    };
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// Returns `true` if an already-normalized lowercase hostname belongs to a local/private namespace.
fn is_local_hostname(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "local" | "lan" | "internal" | "home.arpa" | "ts.net"
    ) || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".ts.net")
}

/// Converts a proxy bypass wildcard (like `*.gov`, `.example.com`, or `*.example.com`)
/// into an anchored case-insensitive regex, returning `None` for empty patterns.
fn wildcard_to_regex(pattern: &str) -> Option<String> {
    let p = pattern.trim().to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.").or_else(|| p.strip_prefix('.')) {
        let suffix = suffix.trim_end_matches('.');
        if suffix.is_empty() {
            return None;
        }
        let escaped = regex::escape(suffix);
        Some(format!(r"^(?:.+\.)?{escaped}$"))
    } else {
        let p = p.trim_end_matches('.');
        if p.is_empty() {
            return None;
        }
        if p.contains('*') {
            let mut out = String::from("^");
            for (i, part) in p.split('*').enumerate() {
                if i > 0 {
                    out.push_str(".*");
                }
                out.push_str(&regex::escape(part));
            }
            out.push('$');
            Some(out)
        } else {
            let escaped = regex::escape(p);
            Some(format!(r"^(?:.+\.)?{escaped}$"))
        }
    }
}

/// Builds a deduplicated `NO_PROXY` comma-separated string suitable for desktop runtimes and `libcurl`.
pub fn build_no_proxy_value(extra: &[String]) -> String {
    let mut items: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "::1".into(),
        "0.0.0.0".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        "100.64.0.0/10".into(),
        "fc00::/7".into(),
        "fe80::/10".into(),
    ];

    for pat in DEFAULT_BYPASS_PATTERNS {
        let cleaned = pat.trim().trim_start_matches('*');
        if !cleaned.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(cleaned)) {
            items.push(cleaned.to_string());
        }
    }

    for entry in extra {
        let cleaned = entry.trim().trim_start_matches('*');
        if !cleaned.is_empty() && !items.iter().any(|x| x.eq_ignore_ascii_case(cleaned)) {
            items.push(cleaned.to_string());
        }
    }

    items.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn desyncs_discord_and_roblox_while_bypassing_gov_and_banks() {
        let policy = BypassPolicy::new(&[], &[]).unwrap();

        assert!(policy.should_desync(Some("discord.com"), None));
        assert!(policy.should_desync(Some("updates.discord.com"), None));
        assert!(policy.should_desync(Some("gateway.discord.gg"), None));
        assert!(policy.should_desync(Some("www.roblox.com"), None));
        assert!(policy.should_desync(Some("apis.roblox.com"), None));

        assert!(!policy.should_desync(Some("www.usa.gov"), None));
        assert!(!policy.should_desync(Some("www.gov.uk"), None));
        assert!(!policy.should_desync(Some("router.home.arpa"), None));
        assert!(!policy.should_desync(Some("turkiye.gov.tr"), None));
        assert!(!policy.should_desync(Some("ais.osym.gov.tr"), None));
        assert!(!policy.should_desync(Some("www.isbank.com.tr"), None));
        assert!(!policy.should_desync(Some("www.sahibinden.com"), None));
        assert!(!policy.should_desync(Some("bkm.com.tr"), None));
        assert!(!policy.should_desync(Some("paratika.com.tr"), None));
        assert!(!policy.should_desync(Some("my-mac.local"), None));
        assert!(!policy.should_desync(Some("192.168.1.1"), None));
        assert!(!policy.should_desync(Some("discord.com"), Some(ip("127.0.0.1"))));
    }

    #[test]
    fn honors_custom_include_patterns() {
        let policy =
            BypassPolicy::new(&[], &[r"(discord|roblox)\.(com|gg|media)$".into()]).unwrap();
        assert!(policy.should_desync(Some("updates.discord.com"), None));
        assert!(policy.should_desync(Some("www.roblox.com"), None));
        assert!(!policy.should_desync(Some("example.com"), None));
        assert_eq!(
            policy.classify(Some("discord.com"), Some(ip("192.168.1.1"))),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("example.com"), Some(ip("127.0.0.1"))),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("discord.com"), Some(ip("127.0.0.1"))),
            BypassClass::DesyncEligible
        );
    }

    #[test]
    fn detects_multicast_reserved_benchmark_and_ietf_non_public_ips() {
        // IPv4 multicast 224.0.0.0/4
        assert!(BypassPolicy::is_non_public_ip(ip("224.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("224.0.0.251")));
        assert!(BypassPolicy::is_non_public_ip(ip("239.255.255.250")));
        assert!(!BypassPolicy::is_non_public_ip(ip("223.255.255.255")));

        // IPv4 reserved 240.0.0.0/4
        assert!(BypassPolicy::is_non_public_ip(ip("240.0.0.0")));
        assert!(BypassPolicy::is_non_public_ip(ip("240.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("254.1.2.3")));
        assert!(BypassPolicy::is_non_public_ip(ip("255.255.255.255")));

        // IPv4 benchmark 198.18.0.0/15
        assert!(BypassPolicy::is_non_public_ip(ip("198.18.0.0")));
        assert!(BypassPolicy::is_non_public_ip(ip("198.18.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("198.19.255.255")));
        assert!(!BypassPolicy::is_non_public_ip(ip("198.17.255.255")));
        assert!(!BypassPolicy::is_non_public_ip(ip("198.20.0.0")));

        // IPv4 IETF protocol assignments 192.0.0.0/24
        assert!(BypassPolicy::is_non_public_ip(ip("192.0.0.0")));
        assert!(BypassPolicy::is_non_public_ip(ip("192.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("192.0.0.255")));
        assert!(!BypassPolicy::is_non_public_ip(ip("192.0.1.1")));

        // IPv4 CGNAT 100.64.0.0/10
        assert!(BypassPolicy::is_non_public_ip(ip("100.64.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("100.127.255.254")));
        assert!(!BypassPolicy::is_non_public_ip(ip("100.63.255.255")));
        assert!(!BypassPolicy::is_non_public_ip(ip("100.128.0.1")));

        // IPv6 multicast ff00::/8 & IPv4-mapped non-public
        assert!(BypassPolicy::is_non_public_ip(ip("ff00::")));
        assert!(BypassPolicy::is_non_public_ip(ip("ff02::1")));
        assert!(BypassPolicy::is_non_public_ip(ip("ff05::1:3")));
        assert!(BypassPolicy::is_non_public_ip(ip("::ffff:224.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("::ffff:198.18.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("::ffff:240.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("::ffff:192.0.0.1")));

        // Public IPv4 & IPv6
        assert!(!BypassPolicy::is_non_public_ip(ip("1.1.1.1")));
        assert!(!BypassPolicy::is_non_public_ip(ip("162.159.135.232")));
        assert!(!BypassPolicy::is_non_public_ip(ip("::ffff:1.1.1.1")));
        assert!(!BypassPolicy::is_non_public_ip(ip("2606:4700:4700::1111")));
    }

    #[test]
    fn bypasses_turkish_banks_gov_tailscale_and_riot_with_clean_wildcards() {
        for pat in DEFAULT_BYPASS_PATTERNS {
            if pat.contains('*') {
                assert!(
                    pat.starts_with("*."),
                    "wildcard default pattern should use `*.` boundary: {pat}"
                );
            }
        }

        let policy = BypassPolicy::new(&[], &[]).unwrap();

        // Tailscale
        assert_eq!(
            policy.classify(Some("laptop.tail1234.ts.net"), None),
            BypassClass::LocalLan
        );
        assert!(policy.is_bypassed(Some("ts.net"), None));

        // Riot / Valorant
        for host in [
            "riotgames.com",
            "auth.riotgames.com",
            "valorant.dyn.riotcdn.net",
            "playvalorant.com",
            "eu.playvalorant.com",
        ] {
            assert_eq!(
                policy.classify(Some(host), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for {host}"
            );
            assert!(!policy.should_desync(Some(host), None));
        }

        // Turkish gov, banks & payment gateways
        for host in [
            "edevlet.gov.tr",
            "giris.edevlet.gov.tr",
            "turkiye.gov.tr",
            "www.turkiye.gov.tr",
            "enpara.com",
            "www.enpara.com",
            "qnbfinansbank.com",
            "www.qnbfinansbank.com",
            "www.denizbank.com",
            "www.ing.com.tr",
            "www.teb.com.tr",
            "www.kuveytturk.com.tr",
            "www.albaraka.com.tr",
            "www.odeabank.com.tr",
            "api.iyzico.com",
            "www.paytr.com",
            "example.org.tr",
            "isbank.com.tr",
        ] {
            assert_eq!(
                policy.classify(Some(host), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for {host}"
            );
            assert!(policy.is_bypassed(Some(host), None));
        }

        // Fixed `*.` wildcards must not falsely match unrelated suffix collisions
        for host in [
            "notorg.tr",
            "fake-isbank.com.tr",
            "myenpara.com",
            "fakepaytr.com",
            "myts.net",
        ] {
            assert_eq!(
                policy.classify(Some(host), None),
                BypassClass::DesyncEligible,
                "expected DesyncEligible for {host}"
            );
            assert!(policy.should_desync(Some(host), None));
        }
    }

    #[test]
    fn supports_ipv4_and_ipv6_cidrs_and_bare_ips() {
        let policy = BypassPolicy::new(
            &[
                "203.0.113.0/24".into(),
                "2001:db8::/32".into(),
                "198.51.100.7".into(),
                "not-a-cidr/99".into(),
            ],
            &[],
        )
        .unwrap();

        assert_eq!(
            policy.classify(Some("203.0.113.1"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("discord.com"), Some(ip("203.0.113.254"))),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(None, Some(ip("::ffff:203.0.113.42"))),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("203.0.114.1"), None),
            BypassClass::DesyncEligible
        );

        assert_eq!(
            policy.classify(Some("[2001:db8::1]"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("discord.com"), Some(ip("2001:db8:ffff::1"))),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(None, Some(ip("2001:db9::1"))),
            BypassClass::DesyncEligible
        );

        assert_eq!(
            policy.classify(Some("198.51.100.7"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("198.51.100.8"), None),
            BypassClass::DesyncEligible
        );

        // Edge CIDR parsing & prefix lengths
        assert!(IpNet::parse("0.0.0.0/0").unwrap().contains(ip("1.1.1.1")));
        assert!(IpNet::parse("::/0").unwrap().contains(ip("2606:4700::1")));
        assert!(IpNet::parse("1.2.3.4/32").unwrap().contains(ip("1.2.3.4")));
        assert!(!IpNet::parse("1.2.3.4/32").unwrap().contains(ip("1.2.3.5")));
        assert!(IpNet::parse("2001:db8::1/128")
            .unwrap()
            .contains(ip("2001:db8::1")));
        assert!(IpNet::parse("1.2.3.4/33").is_none());
        assert!(IpNet::parse("2001:db8::/129").is_none());
        assert!(IpNet::parse("1.2.3.4/+24").is_none());
        assert!(IpNet::parse("foo/bar").is_none());
    }

    #[test]
    fn classifies_targets_and_uses_zero_alloc_host_normalization() {
        let policy = BypassPolicy::new(&[], &[]).unwrap();

        assert_eq!(
            policy.classify(Some("localhost"), None),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("printer.local"), None),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(None, Some(ip("224.0.0.251"))),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(None, Some(ip("198.18.0.1"))),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(None, Some(ip("ff02::1"))),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("WWW.ISBANK.COM.TR."), Some(ip("1.1.1.1"))),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("discord.com"), Some(ip("162.159.135.232"))),
            BypassClass::DesyncEligible
        );

        assert!(matches!(
            normalize_host("discord.com"),
            Cow::Borrowed("discord.com")
        ));
        assert!(matches!(
            normalize_host("  discord.com.  "),
            Cow::Borrowed("discord.com")
        ));
        assert!(matches!(
            normalize_host("[2001:db8::1]"),
            Cow::Borrowed("2001:db8::1")
        ));
        assert!(matches!(
            normalize_host("Discord.COM."),
            Cow::Owned(ref s) if s == "discord.com"
        ));
        assert!(matches!(
            normalize_host("[fe80::1%eth0]"),
            Cow::Borrowed("fe80::1")
        ));
        assert_eq!(
            policy.classify(Some("[fe80::1%eth0]"), None),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("fe80::1%25en0"), None),
            BypassClass::LocalLan
        );
    }

    #[test]
    fn normalizes_leading_dot_bypass_rules_and_skips_empty_patterns() {
        let policy = BypassPolicy::new(
            &[".example.com".into(), ".".into(), "*.".into(), "   ".into()],
            &[],
        )
        .unwrap();

        assert_eq!(
            policy.classify(Some("example.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("sub.example.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("notexample.com"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("discord.com"), None),
            BypassClass::DesyncEligible
        );
    }

    #[test]
    fn matches_include_patterns_case_insensitively() {
        let policy = BypassPolicy::new(&[], &[r"Discord\.COM$".into()]).unwrap();

        assert!(policy.should_desync(Some("discord.com"), None));
        assert!(policy.should_desync(Some("DISCORD.COM"), None));
        assert!(policy.should_desync(Some("Updates.Discord.Com"), None));
        assert!(!policy.should_desync(Some("example.com"), None));
    }

    #[test]
    fn detects_this_network_and_extended_ipv6_non_public_ranges() {
        // IPv4 0.0.0.0/8
        assert!(BypassPolicy::is_non_public_ip(ip("0.0.0.0")));
        assert!(BypassPolicy::is_non_public_ip(ip("0.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("0.255.255.255")));
        assert!(!BypassPolicy::is_non_public_ip(ip("1.0.0.1")));

        // IPv6 64:ff9b:1::/48, 100::/64, fec0::/10
        assert!(BypassPolicy::is_non_public_ip(ip("64:ff9b:1::1")));
        assert!(BypassPolicy::is_non_public_ip(ip("64:ff9b:1::1.1.1.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("100::")));
        assert!(BypassPolicy::is_non_public_ip(ip("100::1")));
        assert!(!BypassPolicy::is_non_public_ip(ip("100:0:0:1::1")));
        assert!(BypassPolicy::is_non_public_ip(ip("fec0::1")));
        assert!(BypassPolicy::is_non_public_ip(ip("feff::1")));

        // IPv6 NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
        assert!(BypassPolicy::is_non_public_ip(ip("64:ff9b::192.168.1.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("64:ff9b::127.0.0.1")));
        assert!(BypassPolicy::is_non_public_ip(ip("64:ff9b::0.0.0.1")));
        assert!(!BypassPolicy::is_non_public_ip(ip("64:ff9b::1.1.1.1")));
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6_cidrs_and_bare_ips() {
        let mapped_net = IpNet::parse("::ffff:203.0.113.0/120").unwrap();
        assert!(matches!(mapped_net, IpNet::V4 { .. }));
        assert!(mapped_net.contains(ip("203.0.113.42")));
        assert!(mapped_net.contains(ip("::ffff:203.0.113.42")));
        assert!(!mapped_net.contains(ip("203.0.114.1")));

        let mapped_host = IpNet::from_ip(ip("::ffff:198.51.100.7"));
        assert!(matches!(mapped_host, IpNet::V4 { .. }));
        assert!(mapped_host.contains(ip("198.51.100.7")));
        assert!(mapped_host.contains(ip("::ffff:198.51.100.7")));
        assert!(!mapped_host.contains(ip("198.51.100.8")));

        let policy = BypassPolicy::new(
            &[
                "::ffff:203.0.113.0/120".into(),
                "::ffff:198.51.100.7".into(),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(
            policy.classify(Some("203.0.113.99"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("198.51.100.7"), None),
            BypassClass::SensitiveDirect
        );
    }

    #[test]
    fn bypasses_additional_turkish_bank_payment_and_riot_domains_and_syncs_no_proxy() {
        let policy = BypassPolicy::new(&[], &[]).unwrap();
        for host in [
            "api.iyzipay.com",
            "iyzipay.com",
            "www.garanti.com.tr",
            "www.qnbfinansbank.com.tr",
            "na.pvp.net",
            "cdn.rgpub.io",
        ] {
            assert_eq!(
                policy.classify(Some(host), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for {host}"
            );
        }

        let no_proxy = build_no_proxy_value(&[]);
        for expected in [
            "fc00::/7,fe80::/10",
            ",.paratika.com.tr,",
            ",.iyzipay.com,",
            ",.garanti.com.tr,",
            ",.qnbfinansbank.com.tr,",
            ",.pvp.net,",
            ",.rgpub.io",
        ] {
            assert!(
                no_proxy.contains(expected),
                "expected NO_PROXY to contain `{expected}`, got: {no_proxy}"
            );
        }
    }
}
