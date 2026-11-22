use anyhow::{Context, Result};
use regex::RegexSet;
use std::net::IpAddr;

/// Built-in domains and wildcards that should never undergo TLS ClientHello fragmentation
/// (local mDNS, private networks, government portals, payment gateways, and banking WAFs).
pub const DEFAULT_BYPASS_PATTERNS: &[&str] = &[
    "localhost",
    "*.local",
    "*.lan",
    "*.internal",
    "*.home.arpa",
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
    "*org.tr",
    "*osym.gov.tr",
    "*bkm.com.tr",
    "paratika.com.tr",
    "*.paratika.com.tr",
    "*halkbank.com.tr",
    "*isbank.com.tr",
    "*akbank.com",
    "*akbank.com.tr",
    "*garantibbva.com.tr",
    "*ziraatbank.com.tr",
    "*yapikredi.com.tr",
    "*vakifbank.com.tr",
    "*qnb.com.tr",
    "*denizbank.com",
    "*enpara.com",
    "*iyzico.com",
    "*paytr.com",
    "*papara.com",
    "*sahibinden.com",
    "*shbdn.com",
    "*turktelekom.com.tr",
    "*pttavm.com",
];

/// Determines whether a connection to `(host, ip)` should undergo DPI desynchronization
/// or pass through untouched.
#[derive(Debug, Clone)]
pub struct BypassPolicy {
    bypass_regexes: RegexSet,
    target_patterns: Option<RegexSet>,
}

impl BypassPolicy {
    pub fn new(extra_bypass: &[String], include_patterns: &[String]) -> Result<Self> {
        let mut bypass_exprs =
            Vec::with_capacity(DEFAULT_BYPASS_PATTERNS.len() + extra_bypass.len());
        for pat in DEFAULT_BYPASS_PATTERNS {
            bypass_exprs.push(wildcard_to_regex(pat));
        }
        for pat in extra_bypass {
            let trimmed = pat.trim();
            if !trimmed.is_empty() && !trimmed.contains('/') {
                bypass_exprs.push(wildcard_to_regex(trimmed));
            }
        }

        let bypass_regexes =
            RegexSet::new(&bypass_exprs).context("failed to compile bypass wildcard rules")?;

        let target_patterns = if include_patterns.is_empty() {
            None
        } else {
            Some(
                RegexSet::new(include_patterns)
                    .context("failed to compile --include regular expressions")?,
            )
        };

        Ok(Self {
            bypass_regexes,
            target_patterns,
        })
    }

    /// Returns `true` if `ip` is loopback, private RFC1918, link-local, CGNAT, or unspecified.
    pub fn is_non_public_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    /// Returns `true` if the given hostname or IP literal should bypass DPI fragmentation.
    pub fn is_bypassed(&self, host: Option<&str>, resolved_ip: Option<IpAddr>) -> bool {
        if let Some(raw_host) = host {
            let clean = raw_host
                .trim()
                .trim_matches(|c| c == '[' || c == ']')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if clean.is_empty() {
                return false;
            }
            if let Ok(ip) = clean.parse::<IpAddr>() {
                return Self::is_non_public_ip(ip);
            }
            if self.bypass_regexes.is_match(&clean) {
                return true;
            }
            if let Some(ref include) = self.target_patterns {
                return !include.is_match(&clean);
            }
        }

        if let Some(ip) = resolved_ip {
            if Self::is_non_public_ip(ip) {
                return true;
            }
        }

        false
    }

    /// Returns `true` if DPI desynchronization should be applied to `(host, resolved_ip)`.
    pub fn should_desync(&self, host: Option<&str>, resolved_ip: Option<IpAddr>) -> bool {
        !self.is_bypassed(host, resolved_ip)
    }
}

/// Converts a proxy bypass wildcard (like `*.gov` or `*.example.com`) into an
/// anchored case-insensitive regex.
fn wildcard_to_regex(pattern: &str) -> String {
    let p = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        let escaped = regex::escape(suffix);
        format!(r"^(?:.+\.)?{escaped}$")
    } else if p.contains('*') {
        let mut out = String::from("^");
        for (i, part) in p.split('*').enumerate() {
            if i > 0 {
                out.push_str(".*");
            }
            out.push_str(&regex::escape(part));
        }
        out.push('$');
        out
    } else {
        let escaped = regex::escape(&p);
        format!(r"^(?:.+\.)?{escaped}$")
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
        ".local".into(),
        ".lan".into(),
        ".internal".into(),
        ".home.arpa".into(),
        ".gov".into(),
        ".gov.uk".into(),
        ".gov.tr".into(),
        ".bel.tr".into(),
        ".edu.tr".into(),
        ".org.tr".into(),
        ".osym.gov.tr".into(),
        ".bkm.com.tr".into(),
        "paratika.com.tr".into(),
        ".halkbank.com.tr".into(),
        ".isbank.com.tr".into(),
        ".akbank.com".into(),
        ".akbank.com.tr".into(),
        ".garantibbva.com.tr".into(),
        ".ziraatbank.com.tr".into(),
        ".yapikredi.com.tr".into(),
        ".vakifbank.com.tr".into(),
        ".sahibinden.com".into(),
        ".shbdn.com".into(),
        ".turktelekom.com.tr".into(),
        ".pttavm.com".into(),
    ];

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
        assert!(!policy.should_desync(Some("discord.com"), Some("127.0.0.1".parse().unwrap())));
    }

    #[test]
    fn honors_custom_include_patterns() {
        let policy =
            BypassPolicy::new(&[], &[r"(discord|roblox)\.(com|gg|media)$".into()]).unwrap();
        assert!(policy.should_desync(Some("updates.discord.com"), None));
        assert!(policy.should_desync(Some("www.roblox.com"), None));
        assert!(!policy.should_desync(Some("example.com"), None));
    }
}
