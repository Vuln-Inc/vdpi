use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr};

/// Built-in domains and wildcards that should never undergo TLS ClientHello fragmentation
/// (local mDNS, private networks, Tailscale, government portals, payment gateways,
/// banking WAFs, and anti-cheat/game services).
pub const DEFAULT_BYPASS_PATTERNS: &[&str] = &[
    // Local / private networks & Tailscale
    "localhost",
    "*.localhost",
    "*.localdomain",
    "*.local",
    "*.lan",
    "*.internal",
    "*.home.arpa",
    "*.ts.net",
    // OS captive-portal & connectivity probe domains
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
    "msftncsi.com",
    "dns.msftncsi.com",
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "detectportal.firefox.com",
    "nmcheck.gnome.org",
    "networkcheck.kde.org",
    "connectivity-check.ubuntu.com",
    "ping.archlinux.org",
    "neverssl.com",
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
    "*.k12.tr",
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
    "*.ziraatkatilim.com.tr",
    "*.yapikredi.com.tr",
    "*.vakifbank.com.tr",
    "*.vakifkatilim.com.tr",
    "*.emlakkatilim.com.tr",
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
    "*.sekerbank.com.tr",
    "*.fibabanka.com.tr",
    "*.anadolubank.com.tr",
    "*.burgan.com.tr",
    "*.alternatifbank.com.tr",
    "*.hsbc.com.tr",
    "*.turkiyefinans.com.tr",
    "*.aktifbank.com.tr",
    "*.nkolay.com",
    "*.iyzico.com",
    "*.iyzipay.com",
    "*.paytr.com",
    "*.papara.com",
    "*.troyodeme.com",
    "*.tosla.com",
    "*.param.com.tr",
    "*.ininal.com",
    // Sensitive Turkish platforms & telecom
    "*.sahibinden.com",
    "*.shbdn.com",
    "*.turktelekom.com.tr",
    "*.turkcell.com.tr",
    "*.vodafone.com.tr",
    "*.superonline.net",
    "*.turk.net",
    "*.kablonet.com.tr",
    "*.turksat.com.tr",
    "*.ttnet.com.tr",
    "*.pttavm.com",
    // Riot / Valorant (strict TLS & anti-cheat)
    "*.riotgames.com",
    "*.riotgames.net",
    "*.riotcdn.net",
    "*.playvalorant.com",
    "*.valorant.com",
    "*.pvp.net",
    "*.rgpub.io",
    "*.rdatasrv.net",
    "*.leagueoflegends.com",
    // Third-party VPN control-plane, auth & bootstrap APIs
    "*.mullvad.net",
    "*.protonvpn.com",
    "*.proton.me",
    "*.nordvpn.com",
    "*.surfshark.com",
    "*.cloudflareclient.com",
    "*.tailscale.com",
    "*.expressvpn.com",
    "*.expressvpn.net",
    "*.expressapisv2.net",
    "*.xvnet.net",
    "*.xvtel.com",
    "*.windscribe.com",
    "*.cyberghostvpn.com",
    "*.privateinternetaccess.com",
    "*.pia-dns.com",
    "*.ipvanish.com",
    "*.tunnelbear.com",
    "*.adguard-vpn.com",
    "*.hotspotshield.com",
    "*.warp.plus",
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
    default_bypass_regexes: RegexSet,
    user_bypass_regexes: RegexSet,
    bypass_cidrs: Vec<IpNet>,
    target_patterns: Option<RegexSet>,
}

impl BypassPolicy {
    pub fn new(extra_bypass: &[String], include_patterns: &[String]) -> Result<Self> {
        let mut default_bypass_exprs = Vec::with_capacity(DEFAULT_BYPASS_PATTERNS.len());
        let mut user_bypass_exprs = Vec::with_capacity(extra_bypass.len());
        let mut bypass_cidrs = Vec::new();
        for pat in DEFAULT_BYPASS_PATTERNS {
            if let Some(expr) = wildcard_to_regex(pat) {
                default_bypass_exprs.push(expr);
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
                user_bypass_exprs.push(expr);
            }
        }

        let default_bypass_regexes = RegexSet::new(&default_bypass_exprs)
            .context("failed to compile default bypass wildcard rules")?;
        let user_bypass_regexes = RegexSet::new(&user_bypass_exprs)
            .context("failed to compile user bypass wildcard rules")?;

        let include_exprs: Vec<String> = include_patterns
            .iter()
            .map(String::as_str)
            .filter_map(include_pattern_to_regex)
            .collect();
        let target_patterns = if include_exprs.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(&include_exprs)
                    .case_insensitive(true)
                    .build()
                    .context("failed to compile --include regular expressions")?,
            )
        };

        Ok(Self {
            default_bypass_regexes,
            user_bypass_regexes,
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
                if self.user_bypass_regexes.is_match(clean.as_ref()) {
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
                if self.default_bypass_regexes.is_match(clean.as_ref()) {
                    return BypassClass::SensitiveDirect;
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

/// Returns `true` if an already-normalized lowercase hostname belongs to a reserved local/private
/// DNS namespace (such as `localhost`, `.local`, `.home.arpa`, or `.ts.net`).
fn is_local_namespace(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "localdomain" | "local" | "lan" | "internal" | "home.arpa" | "ts.net"
    ) || host.ends_with(".localhost")
        || host.ends_with(".localdomain")
        || host.ends_with(".local")
        || host.ends_with(".lan")
        || host.ends_with(".internal")
        || host.ends_with(".home.arpa")
        || host.ends_with(".ts.net")
}

/// Returns `true` if an already-normalized lowercase hostname belongs to a local/private namespace
/// (including single-label plain hostnames such as `router` or `nas`).
fn is_local_hostname(host: &str) -> bool {
    (!host.contains('.') && !host.contains(':')) || is_local_namespace(host)
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

fn is_plain_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_plain_domain_hostname(host: &str) -> bool {
    let trimmed = host.trim_end_matches('.');
    trimmed.contains('.') && trimmed.split('.').all(is_plain_domain_label)
}

/// Translates `--include` / `include_domains` entries that are leading `*.`
/// wildcards (e.g. `*.example.org`), leading-dot domain patterns
/// (e.g. `.example.org`), or plain multi-label domain hostnames without regex
/// metacharacters (e.g. `service.gov.tr`) using [`wildcard_to_regex`], while
/// preserving explicit raw regular expressions (`^`, `$`, `\`, `[`, `+`, `?`,
/// `(`, `|`, etc.) for CLI compatibility.
fn include_pattern_to_regex(pattern: &str) -> Option<String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix("*.") {
        let rest_trimmed = rest.trim_end_matches('.');
        if !rest_trimmed.is_empty() && rest_trimmed.split('.').all(is_plain_domain_label) {
            return wildcard_to_regex(trimmed);
        }
    } else if let Some(rest) = trimmed.strip_prefix('.') {
        if is_plain_domain_hostname(rest) {
            return wildcard_to_regex(trimmed);
        }
    } else if is_plain_domain_hostname(trimmed) {
        return wildcard_to_regex(trimmed);
    }
    Some(trimmed.to_string())
}

/// Extracts lowercase multi-label hostname candidates from an `--include` pattern
/// (supporting both plain domains/wildcards like `forum.org.tr` / `*.org.tr` and
/// regex forms like `^forum\.org\.tr$` or `(discord\.com|forum\.org\.tr)$`).
fn extract_include_domain_candidates(pattern: &str) -> Vec<String> {
    let trimmed = pattern.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Vec::new();
    }

    let unescaped = trimmed.replace(r"\.", ".").replace(r"\-", "-");
    let mut candidates = Vec::new();
    for segment in unescaped.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        // Ignore prefix fragments such as `org.tr.` in `org\.tr\.(example|test)\.com$`.
        if segment.is_empty() || segment.ends_with('.') {
            continue;
        }
        let cleaned = segment.trim_start_matches('.').trim_matches('-');
        if cleaned.contains('.') {
            candidates.push(cleaned.to_ascii_lowercase());
        }
    }
    candidates
}

/// Returns `true` if a non-local `DEFAULT_BYPASS_PATTERNS` entry is overridden by any
/// configured `include_domains` pattern.
fn default_pattern_overridden_by_includes(
    pat: &str,
    cleaned: &str,
    include_regexes: &[Regex],
    include_candidates: &[String],
) -> bool {
    if include_regexes.is_empty() && include_candidates.is_empty() {
        return false;
    }

    let base = cleaned.trim_start_matches('.').to_ascii_lowercase();
    if base.is_empty() || is_local_namespace(&base) {
        return false;
    }

    let sample_subdomain = format!("a.{base}");
    if include_regexes
        .iter()
        .any(|re| re.is_match(&base) || re.is_match(cleaned) || re.is_match(&sample_subdomain))
    {
        return true;
    }

    if include_candidates.is_empty() {
        return false;
    }
    let Some(expr) = wildcard_to_regex(pat) else {
        return false;
    };
    let Ok(pat_re) = Regex::new(&expr) else {
        return false;
    };
    include_candidates.iter().any(|cand| pat_re.is_match(cand))
}

fn compile_include_override_matchers(include_domains: &[String]) -> (Vec<Regex>, Vec<String>) {
    let mut include_regexes = Vec::new();
    let mut include_candidates = Vec::new();
    for raw in include_domains {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(re) = include_pattern_to_regex(trimmed)
            .and_then(|expr| RegexBuilder::new(&expr).case_insensitive(true).build().ok())
        {
            include_regexes.push(re);
        }
        include_candidates.extend(extract_include_domain_candidates(trimmed));
    }
    (include_regexes, include_candidates)
}

/// Filters `domains` (bare domain suffixes such as `"riotgames.com"` or `"mullvad.net"`),
/// omitting any non-local domain overridden by `include_domains`.
pub fn filter_pac_default_bypass_domains<'a>(
    domains: &[&'a str],
    include_domains: &[String],
) -> Vec<&'a str> {
    if include_domains.is_empty() {
        return domains.to_vec();
    }
    let (include_regexes, include_candidates) = compile_include_override_matchers(include_domains);
    if include_regexes.is_empty() && include_candidates.is_empty() {
        return domains.to_vec();
    }
    domains
        .iter()
        .copied()
        .filter(|domain| {
            let trimmed = domain.trim();
            let cleaned = trimmed.trim_start_matches('*');
            !default_pattern_overridden_by_includes(
                trimmed,
                cleaned,
                &include_regexes,
                &include_candidates,
            )
        })
        .collect()
}

/// Builds a deduplicated `NO_PROXY` comma-separated string suitable for desktop runtimes and `libcurl`.
pub fn build_no_proxy_value(extra: &[String]) -> String {
    build_no_proxy_value_with_includes(extra, &[])
}

/// Builds a deduplicated `NO_PROXY` comma-separated string suitable for desktop runtimes and `libcurl`,
/// skipping any non-local `DEFAULT_BYPASS_PATTERNS` entry matched by `include_domains` so `--include`
/// overrides built-in bypasses (such as `.org.tr`) consistently in `NO_PROXY` as well.
pub fn build_no_proxy_value_with_includes(
    extra: &[String],
    include_domains: &[String],
) -> String {
    let mut items: Vec<String> = vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "127.0.0.0/8".into(),
        "::1".into(),
        "0.0.0.0".into(),
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.0.0.0/24".into(),
        "192.168.0.0/16".into(),
        "169.254.0.0/16".into(),
        "100.64.0.0/10".into(),
        "fc00::/7".into(),
        "fe80::/10".into(),
    ];

    let (include_regexes, include_candidates) = compile_include_override_matchers(include_domains);

    for pat in DEFAULT_BYPASS_PATTERNS {
        let cleaned = pat.trim().trim_start_matches('*');
        if cleaned.is_empty() {
            continue;
        }
        if default_pattern_overridden_by_includes(
            pat,
            cleaned,
            &include_regexes,
            &include_candidates,
        ) {
            continue;
        }
        if !items.iter().any(|x| x.eq_ignore_ascii_case(cleaned)) {
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

    #[test]
    fn bypasses_captive_portals_local_namespaces_and_missing_turkish_portals() {
        let policy = BypassPolicy::new(&[], &[]).unwrap();

        for captive in [
            "www.msftconnecttest.com",
            "msftconnecttest.com",
            "ipv6.msftconnecttest.com",
            "www.msftncsi.com",
            "msftncsi.com",
            "dns.msftncsi.com",
            "captive.apple.com",
            "connectivitycheck.gstatic.com",
            "connectivitycheck.android.com",
            "clients3.google.com",
            "detectportal.firefox.com",
            "nmcheck.gnome.org",
            "networkcheck.kde.org",
            "connectivity-check.ubuntu.com",
            "ping.archlinux.org",
            "neverssl.com",
        ] {
            assert_eq!(
                policy.classify(Some(captive), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for captive portal {captive}"
            );
        }

        for local in [
            "router",
            "nas",
            "intranet",
            "app.localhost",
            "dev.localdomain",
            "localdomain",
        ] {
            assert_eq!(
                policy.classify(Some(local), None),
                BypassClass::LocalLan,
                "expected LocalLan for {local}"
            );
        }

        for tr_portal in [
            "www.turkcell.com.tr",
            "www.vodafone.com.tr",
            "www.superonline.net",
            "www.turk.net",
            "www.ziraatkatilim.com.tr",
            "www.fibabanka.com.tr",
            "www.sekerbank.com.tr",
            "www.turkiyefinans.com.tr",
            "www.kablonet.com.tr",
        ] {
            assert_eq!(
                policy.classify(Some(tr_portal), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for {tr_portal}"
            );
        }
    }

    #[test]
    fn include_overrides_default_bypass_while_user_bypass_and_local_lan_remain_highest() {
        let policy = BypassPolicy::new(
            &["blocked.org.tr".into(), "203.0.113.0/24".into()],
            &[r"\.org\.tr$".into(), r"localhost$".into(), r"^nas$".into()],
        )
        .unwrap();

        // Explicit --include overrides DEFAULT_BYPASS_PATTERNS (*.org.tr)
        assert_eq!(
            policy.classify(Some("forum.org.tr"), None),
            BypassClass::DesyncEligible
        );
        // Explicit user --bypass (domain and CIDR) still wins over --include
        assert_eq!(
            policy.classify(Some("blocked.org.tr"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("forum.org.tr"), Some(ip("203.0.113.10"))),
            BypassClass::SensitiveDirect
        );
        // LocalLan (localhost, *.localhost, single-label hostnames, LAN IPs) still wins over --include
        assert_eq!(
            policy.classify(Some("app.localhost"), None),
            BypassClass::LocalLan
        );
        assert_eq!(policy.classify(Some("nas"), None), BypassClass::LocalLan);
        assert_eq!(
            policy.classify(Some("forum.org.tr"), Some(ip("192.168.1.5"))),
            BypassClass::LocalLan
        );
        // Unmatched hosts are still excluded by --include
        assert_eq!(
            policy.classify(Some("discord.com"), None),
            BypassClass::SensitiveDirect
        );
    }

    #[test]
    fn build_no_proxy_value_includes_loopback_cidr_and_new_captive_portal_domains() {
        let no_proxy = build_no_proxy_value(&[]);
        let entries: Vec<&str> = no_proxy.split(',').collect();

        for expected in [
            "127.0.0.1",
            "127.0.0.0/8",
            "192.0.0.0/24",
            "msftncsi.com",
            "dns.msftncsi.com",
            "ipv6.msftconnecttest.com",
            "connectivitycheck.android.com",
            "ping.archlinux.org",
            "neverssl.com",
            ".org.tr",
        ] {
            assert!(
                entries.contains(&expected),
                "expected NO_PROXY to contain `{expected}`, got: {no_proxy}"
            );
        }
    }

    #[test]
    fn build_no_proxy_value_with_includes_skips_overridden_defaults_and_keeps_locals_and_extra() {
        // Regex --include matching .org.tr skips .org.tr while retaining explicit user bypasses
        // and unrelated default entries.
        let with_regex =
            build_no_proxy_value_with_includes(&["blocked.org.tr".into()], &[r"\.org\.tr$".into()]);
        let entries: Vec<&str> = with_regex.split(',').collect();
        assert!(!entries.contains(&".org.tr"));
        assert!(entries.contains(&"blocked.org.tr"));
        assert!(entries.contains(&"127.0.0.0/8"));
        assert!(entries.contains(&".gov.tr"));
        assert!(entries.contains(&".isbank.com.tr"));
        assert!(entries.contains(&"localhost"));
        assert!(entries.contains(&".localhost"));
        assert!(entries.contains(&".local"));
        assert!(entries.contains(&".ts.net"));

        // Subdomain include patterns (plain or anchored regex) also omit the broader .org.tr default.
        for include_pat in ["forum.org.tr", r"^forum\.org\.tr$", "*.org.tr"] {
            let no_proxy =
                build_no_proxy_value_with_includes(&[], &[include_pat.into(), "   ".into()]);
            let items: Vec<&str> = no_proxy.split(',').collect();
            assert!(
                !items.contains(&".org.tr"),
                "expected `{include_pat}` to omit `.org.tr` from NO_PROXY"
            );
            assert!(
                items.contains(&".gov.tr"),
                "expected `{include_pat}` to keep `.gov.tr` in NO_PROXY"
            );
        }

        // Broad --include patterns must still never strip local/private namespaces or loopback CIDRs.
        let with_broad =
            build_no_proxy_value_with_includes(&[], &[r"localhost$".into(), r".*".into()]);
        let broad_items: Vec<&str> = with_broad.split(',').collect();
        for local in [
            "localhost",
            "127.0.0.1",
            "127.0.0.0/8",
            "192.0.0.0/24",
            ".localhost",
            ".localdomain",
            ".local",
            ".lan",
            ".internal",
            ".home.arpa",
            ".ts.net",
        ] {
            assert!(
                broad_items.contains(&local),
                "expected local entry `{local}` to remain in NO_PROXY"
            );
        }
        assert!(!broad_items.contains(&".org.tr"));
        assert!(!broad_items.contains(&"ping.archlinux.org"));
        assert!(!broad_items.contains(&"neverssl.com"));

        // Guard against false-positive stripping from group labels or domain prefixes.
        let with_unrelated = build_no_proxy_value_with_includes(
            &[],
            &[
                r"(gov|discord)\.example\.com$".into(),
                r"org\.tr\.(example|test)\.com$".into(),
            ],
        );
        let unrelated_items: Vec<&str> = with_unrelated.split(',').collect();
        assert!(unrelated_items.contains(&".gov"));
        assert!(unrelated_items.contains(&".org.tr"));
    }

    #[test]
    fn include_patterns_translate_wildcards_and_plain_hostnames_while_preserving_raw_regex() {
        let policy = BypassPolicy::new(
            &[],
            &[
                "*.example.org".into(),
                "service.gov.tr".into(),
                r"^(api|cdn)\.raw-regex\.(com|net)$".into(),
            ],
        )
        .unwrap();

        // Leading `*.` wildcard matches apex and subdomains case-insensitively, anchored.
        assert_eq!(
            policy.classify(Some("example.org"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("sub.example.org"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("DEEP.SUB.EXAMPLE.ORG"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("notexample.org"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("exampleXorg.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("example.org.evil.com"), None),
            BypassClass::SensitiveDirect
        );

        // Plain domain hostname is translated with escaped dots and anchors (and overrides default *.gov.tr).
        assert_eq!(
            policy.classify(Some("service.gov.tr"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("portal.service.gov.tr"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("SERVICE.GOV.TR"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("serviceXgovYtr.evil.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("serviceXgovYtr"), None),
            BypassClass::LocalLan
        );
        assert_eq!(
            policy.classify(Some("evilservice.gov.tr"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("service.gov.tr.evil.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("other.gov.tr"), None),
            BypassClass::SensitiveDirect
        );

        // Explicit raw regex syntax remains supported for CLI backward compatibility.
        assert_eq!(
            policy.classify(Some("api.raw-regex.com"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("cdn.raw-regex.net"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("web.raw-regex.com"), None),
            BypassClass::SensitiveDirect
        );

        // Invalid raw regex still fails compilation.
        assert!(BypassPolicy::new(&[], &["[unclosed".into()]).is_err());
    }

    #[test]
    fn include_patterns_translate_leading_dot_domains_matching_bypass_domains() {
        assert_eq!(
            include_pattern_to_regex(".example.org").as_deref(),
            Some(r"^(?:.+\.)?example\.org$")
        );
        assert_eq!(
            include_pattern_to_regex(".example.org.").as_deref(),
            Some(r"^(?:.+\.)?example\.org$")
        );
        // Raw regexes and single-label leading-dot patterns remain untouched.
        assert_eq!(include_pattern_to_regex(".*").as_deref(), Some(".*"));
        assert_eq!(include_pattern_to_regex(".+").as_deref(), Some(".+"));
        assert_eq!(include_pattern_to_regex(".foo").as_deref(), Some(".foo"));
        assert_eq!(
            include_pattern_to_regex("..example.org").as_deref(),
            Some("..example.org")
        );

        let policy =
            BypassPolicy::new(&[], &[".example.org".into(), ".service.gov.tr".into()]).unwrap();

        // Leading-dot domain matches apex and subdomains case-insensitively, anchored.
        assert_eq!(
            policy.classify(Some("example.org"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("sub.example.org"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("DEEP.SUB.EXAMPLE.ORG"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("notexample.org"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("exampleXorg.com"), None),
            BypassClass::SensitiveDirect
        );
        assert_eq!(
            policy.classify(Some("example.org.evil.com"), None),
            BypassClass::SensitiveDirect
        );

        // Leading-dot domain also overrides built-in default bypasses (*.gov.tr).
        assert_eq!(
            policy.classify(Some("service.gov.tr"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("portal.service.gov.tr"), None),
            BypassClass::DesyncEligible
        );
        assert_eq!(
            policy.classify(Some("other.gov.tr"), None),
            BypassClass::SensitiveDirect
        );

        // Leading-dot include pattern also omits the overridden default from NO_PROXY.
        let no_proxy = build_no_proxy_value_with_includes(&[], &[".org.tr".into()]);
        let entries: Vec<&str> = no_proxy.split(',').collect();
        assert!(!entries.contains(&".org.tr"));
        assert!(entries.contains(&".gov.tr"));
    }

    #[test]
    fn bypasses_extended_riot_and_vpn_bootstrap_domains_and_filters_pac_defaults() {
        let policy = BypassPolicy::new(&[], &[]).unwrap();

        for host in [
            "riotgames.net",
            "edge.riotgames.net",
            "valorant.com",
            "api.valorant.com",
            "rdatasrv.net",
            "data.rdatasrv.net",
            "leagueoflegends.com",
            "auth.leagueoflegends.com",
            "mullvad.net",
            "api.mullvad.net",
            "protonvpn.com",
            "api.protonvpn.com",
            "proton.me",
            "vpn-api.proton.me",
            "nordvpn.com",
            "api.nordvpn.com",
            "surfshark.com",
            "api.surfshark.com",
            "cloudflareclient.com",
            "api.cloudflareclient.com",
            "tailscale.com",
            "controlplane.tailscale.com",
        ] {
            assert_eq!(
                policy.classify(Some(host), None),
                BypassClass::SensitiveDirect,
                "expected SensitiveDirect for {host}"
            );
            assert!(!policy.should_desync(Some(host), None));
        }

        for unrelated in [
            "notriotgames.net",
            "fakevalorant.com",
            "fakemullvad.net",
            "notproton.me",
            "mytailscale.com",
        ] {
            assert_eq!(
                policy.classify(Some(unrelated), None),
                BypassClass::DesyncEligible,
                "expected DesyncEligible for {unrelated}"
            );
        }

        let no_proxy = build_no_proxy_value(&[]);
        let entries: Vec<&str> = no_proxy.split(',').collect();
        for expected in [
            ".riotgames.net",
            ".valorant.com",
            ".rdatasrv.net",
            ".leagueoflegends.com",
            ".mullvad.net",
            ".protonvpn.com",
            ".proton.me",
            ".nordvpn.com",
            ".surfshark.com",
            ".cloudflareclient.com",
            ".tailscale.com",
        ] {
            assert!(
                entries.contains(&expected),
                "expected NO_PROXY to contain `{expected}`, got: {no_proxy}"
            );
        }

        let pac_domains = ["riotgames.com", "valorant.com", "mullvad.net", "proton.me"];
        assert_eq!(
            filter_pac_default_bypass_domains(&pac_domains, &[]),
            vec!["riotgames.com", "valorant.com", "mullvad.net", "proton.me"]
        );
        assert_eq!(
            filter_pac_default_bypass_domains(
                &pac_domains,
                &["auth.riotgames.com".into(), r"\.proton\.me$".into()]
            ),
            vec!["valorant.com", "mullvad.net"]
        );
    }
}
