//! Cross-platform read-only VPN conflict detector.
//!
//! Distinguishes full-tunnel VPNs (Class A, which own global default or `/1`
//! split-default routes and conflict with `vdpi`'s TUN/proxy routing) from
//! split-tunnel mesh overlays (Class B, e.g. Tailscale without an exit node or
//! ZeroTier) while strictly ignoring `vdpi`'s own TUN adapter and local
//! virtualization/container adapters (Hyper-V, WSL, Docker, VMware, VirtualBox,
//! Npcap, Bluetooth, loopback).

#[cfg(any(target_os = "macos", target_os = "linux", test))]
use std::collections::BTreeMap;
#[cfg(any(target_os = "windows", test))]
use std::collections::HashMap;

/// Active VPN / overlay scope detected on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnScope {
    /// No active VPN or mesh overlay detected.
    None,
    /// One or more active VPN/mesh overlay adapters exist without owning a
    /// global default route (e.g. Tailscale without exit node, ZeroTier).
    SplitOverlay { providers: Vec<String> },
    /// An active VPN adapter owns a global default or split-default (`/1`)
    /// route, capturing system-wide traffic.
    FullTunnel {
        provider: String,
        iface: String,
        kill_switch: bool,
    },
}

impl VpnScope {
    /// Returns the provider name when a full-tunnel VPN is active.
    pub fn full_tunnel_provider(&self) -> Option<&str> {
        match self {
            Self::FullTunnel { provider, .. } => Some(provider.as_str()),
            Self::None | Self::SplitOverlay { .. } => None,
        }
    }

    /// Returns `true` if a full-tunnel VPN is active.
    pub fn is_full_tunnel(&self) -> bool {
        matches!(self, Self::FullTunnel { .. })
    }
}

/// Returns `true` for local/virtual/container/self interfaces that must never
/// be classified as third-party VPNs.
pub fn is_excluded_non_vpn_adapter(name: &str, description: &str) -> bool {
    let name_lower = name.trim().to_ascii_lowercase();
    let desc_lower = description.trim().to_ascii_lowercase();

    // Never flag vdpi's own TUN interface.
    if name_lower.starts_with("vdpi") || has_ascii_token(&desc_lower, "vdpi") {
        return true;
    }

    // Loopback adapters.
    if name_lower == "lo"
        || name_lower == "lo0"
        || name_lower.contains("loopback")
        || desc_lower.contains("loopback")
    {
        return true;
    }

    // Linux container / bridge / libvirt virtual interfaces.
    if is_linux_container_or_bridge_iface(&name_lower) {
        return true;
    }

    // Hyper-V / WSL / Docker / VMware / VirtualBox / Npcap / Bluetooth /
    // Windows IPv6 transition tunnels (Teredo, ISATAP, 6to4, IPHTTPS).
    const EXCLUDED_SUBSTRINGS: &[&str] = &[
        "vethernet",
        "hyper-v",
        "docker",
        "vmware",
        "vmnet",
        "virtualbox",
        "vboxnet",
        "vbox",
        "npcap",
        "bluetooth",
        "teredo",
        "isatap",
        "6to4",
        "iphttps",
        "ip-https",
    ];

    if EXCLUDED_SUBSTRINGS
        .iter()
        .any(|needle| name_lower.contains(needle) || desc_lower.contains(needle))
    {
        return true;
    }

    // WSL (matched as a token or prefix to avoid accidental substring hits).
    if has_ascii_token(&name_lower, "wsl")
        || has_ascii_token(&desc_lower, "wsl")
        || name_lower.starts_with("wsl")
    {
        return true;
    }

    // Linux Bluetooth PAN interfaces (bnep0, bnep1, ...).
    if is_prefix_followed_by_digit(&name_lower, "bnep") {
        return true;
    }

    false
}

/// Classifies an adapter's name and description into a known VPN or mesh
/// overlay provider, returning `None` for physical NICs and excluded
/// virtualization/container/self adapters.
pub fn classify_vpn_adapter_name(name: &str, description: &str) -> Option<&'static str> {
    if is_excluded_non_vpn_adapter(name, description) {
        return None;
    }

    let name_lower = name.trim().to_ascii_lowercase();
    let desc_lower = description.trim().to_ascii_lowercase();

    if name_lower.is_empty() && desc_lower.is_empty() {
        return None;
    }

    let has_any = |needles: &[&str]| -> bool {
        needles
            .iter()
            .any(|needle| name_lower.contains(needle) || desc_lower.contains(needle))
    };

    // Match brand-specific providers before generic WireGuard / OpenVPN so
    // adapters like "Mullvad" ("WireGuard Tunnel") or "Surfshark" ("TAP-Windows")
    // resolve to their actual provider.
    if has_any(&["mullvad"]) {
        return Some("Mullvad");
    }
    if has_any(&["nordlynx", "nordvpn", "nordlayer"]) {
        return Some("NordVPN");
    }
    if has_any(&["protonvpn", "proton vpn"])
        || name_lower.starts_with("proton")
        || has_ascii_token(&desc_lower, "proton")
    {
        return Some("ProtonVPN");
    }
    if has_any(&["cloudflarewarp", "cloudflare warp", "cloudflare", "cfwarp"])
        || name_lower.starts_with("warp")
        || has_ascii_token(&name_lower, "warp")
        || has_ascii_token(&desc_lower, "warp")
    {
        return Some("Cloudflare WARP");
    }
    if has_any(&["tailscale"]) {
        return Some("Tailscale");
    }
    if has_any(&["expressvpn", "express vpn", "lightway"]) {
        return Some("ExpressVPN");
    }
    if has_any(&["surfshark"]) {
        return Some("Surfshark");
    }
    if has_any(&["anyconnect", "cisco secure client", "cisco vpn", "cscotun"]) {
        return Some("Cisco AnyConnect");
    }
    if has_any(&["globalprotect", "pangp", "palo alto"])
        || is_prefix_followed_by_digit(&name_lower, "gpd")
    {
        return Some("GlobalProtect");
    }
    // Check FortiClient before IVPN so "fortivpn" never matches "ivpn".
    if has_any(&["forticlient", "fortinet", "fortissl", "fortivpn", "fctvpn"]) {
        return Some("FortiClient");
    }
    if has_any(&[
        "ivanti",
        "pulse secure",
        "junos pulse",
        "juniper network connect",
        "pulsevpn",
        "pulse-vpn",
    ]) {
        return Some("Ivanti/Pulse");
    }
    if has_any(&["windscribe"]) {
        return Some("Windscribe");
    }
    if has_ascii_token(&name_lower, "ivpn")
        || has_ascii_token(&desc_lower, "ivpn")
        || name_lower.starts_with("ivpn")
    {
        return Some("IVPN");
    }
    if has_any(&["zerotier"]) || is_zerotier_iface_name(&name_lower) {
        return Some("ZeroTier");
    }
    if has_any(&["amnezia", "awg-quick"]) || is_amneziawg_iface_name(&name_lower) {
        return Some("AmneziaVPN");
    }
    if has_any(&["adguard"]) {
        return Some("AdGuard VPN");
    }
    if has_any(&["outline"]) {
        return Some("Outline VPN");
    }
    if has_any(&["sing-box", "singbox"]) {
        return Some("sing-box");
    }
    if has_any(&["mihomo"]) {
        return Some("Mihomo");
    }
    if has_any(&["wireguard", "wg-quick"]) || is_wireguard_iface_name(&name_lower) {
        return Some("WireGuard");
    }
    if has_any(&["openvpn", "ovpn", "tap-windows", "tap-win", "tap0901"]) {
        return Some("OpenVPN");
    }
    if has_any(&["wan miniport (ikev2)"]) {
        return Some("IKEv2 VPN");
    }
    if has_any(&["wan miniport (sstp)"]) {
        return Some("SSTP VPN");
    }
    if has_any(&["wan miniport (l2tp)"]) {
        return Some("L2TP VPN");
    }
    if has_any(&["wan miniport (pptp)"]) {
        return Some("PPTP VPN");
    }
    if has_any(&["wintun"]) {
        return Some("Wintun VPN");
    }

    None
}

/// Detects an active VPN or split-tunnel overlay on the current host in
/// read-only mode, excluding `self_tun_name` (e.g. `Some("vdpi0")`).
pub fn detect_active_vpn(self_tun_name: Option<&str>) -> VpnScope {
    #[cfg(target_os = "windows")]
    {
        detect_windows(self_tun_name)
    }

    #[cfg(target_os = "macos")]
    {
        detect_macos(self_tun_name)
    }

    #[cfg(target_os = "linux")]
    {
        detect_linux(self_tun_name)
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = self_tun_name;
        VpnScope::None
    }
}

fn has_ascii_token(haystack: &str, token: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|part| part == token)
}

fn is_prefix_followed_by_digit(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|rest| rest.bytes().next())
        .is_some_and(|b| b.is_ascii_digit())
}

fn is_linux_container_or_bridge_iface(name_lower: &str) -> bool {
    name_lower.starts_with("docker")
        || name_lower.starts_with("br-")
        || name_lower.starts_with("veth")
        || name_lower.starts_with("virbr")
        || name_lower.starts_with("podman")
        || name_lower.starts_with("lxcbr")
        || name_lower.starts_with("lxdbr")
        || name_lower.starts_with("cni")
        || name_lower.starts_with("flannel")
        || name_lower.starts_with("calico")
}

fn is_amneziawg_iface_name(name_lower: &str) -> bool {
    if name_lower == "awg" {
        return true;
    }
    name_lower
        .strip_prefix("awg")
        .and_then(|rest| rest.bytes().next())
        .is_some_and(|first| first.is_ascii_digit() || first == b'-' || first == b'_')
}

fn is_wireguard_iface_name(name_lower: &str) -> bool {
    if name_lower == "wg" || is_amneziawg_iface_name(name_lower) {
        return true;
    }
    name_lower
        .strip_prefix("wg")
        .and_then(|rest| rest.bytes().next())
        .is_some_and(|first| first.is_ascii_digit() || first == b'-' || first == b'_')
}

fn is_zerotier_iface_name(name_lower: &str) -> bool {
    name_lower
        .strip_prefix("zt")
        .is_some_and(|rest| rest.len() >= 6 && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
fn is_self_interface(name: &str, self_tun_name: Option<&str>) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("vdpi") {
        return true;
    }
    if let Some(self_name) = self_tun_name {
        let self_trimmed = self_name.trim();
        if !self_trimmed.is_empty() && trimmed.eq_ignore_ascii_case(self_trimmed) {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GlobalRouteFlags {
    pub(crate) v4_default: bool,
    pub(crate) v4_lower_half: bool, // 0.0.0.0/1
    pub(crate) v4_upper_half: bool, // 128.0.0.0/1
    pub(crate) v6_default: bool,
    pub(crate) v6_lower_half: bool, // ::/1
    pub(crate) v6_upper_half: bool, // 8000::/1
    #[cfg(any(target_os = "windows", target_os = "linux", test))]
    pub(crate) best_v4_metric: Option<u32>,
    #[cfg(any(target_os = "windows", target_os = "linux", test))]
    pub(crate) best_v6_metric: Option<u32>,
}

#[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux", test))]
impl GlobalRouteFlags {
    fn has_v4_split_default(self) -> bool {
        self.v4_lower_half && self.v4_upper_half
    }

    fn has_v6_split_default(self) -> bool {
        self.v6_lower_half && self.v6_upper_half
    }

    fn has_split_default(self) -> bool {
        self.has_v4_split_default() || self.has_v6_split_default()
    }

    #[cfg(any(target_os = "linux", test))]
    fn has_full_tunnel_route(self) -> bool {
        self.v4_default
            || self.has_v4_split_default()
            || self.v6_default
            || self.has_v6_split_default()
    }

    #[cfg(any(target_os = "windows", target_os = "linux", test))]
    fn record_v4_metric(&mut self, metric: u32) {
        self.best_v4_metric = Some(match self.best_v4_metric {
            Some(existing) => existing.min(metric),
            None => metric,
        });
    }

    #[cfg(any(target_os = "windows", target_os = "linux", test))]
    fn record_v6_metric(&mut self, metric: u32) {
        self.best_v6_metric = Some(match self.best_v6_metric {
            Some(existing) => existing.min(metric),
            None => metric,
        });
    }

    #[cfg(any(target_os = "windows", target_os = "linux", test))]
    fn merge_from(&mut self, other: Self) {
        self.v4_default |= other.v4_default;
        self.v4_lower_half |= other.v4_lower_half;
        self.v4_upper_half |= other.v4_upper_half;
        self.v6_default |= other.v6_default;
        self.v6_lower_half |= other.v6_lower_half;
        self.v6_upper_half |= other.v6_upper_half;
        if let Some(m) = other.best_v4_metric {
            self.record_v4_metric(m);
        }
        if let Some(m) = other.best_v6_metric {
            self.record_v6_metric(m);
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn best_any_metric(self) -> Option<u32> {
        match (self.best_v4_metric, self.best_v6_metric) {
            (Some(v4), Some(v6)) => Some(v4.min(v6)),
            (Some(v4), None) => Some(v4),
            (None, Some(v6)) => Some(v6),
            (None, None) => None,
        }
    }
}

// ============================================================================
// Windows implementation (native Win32 IP Helper API, zero subprocesses)
// ============================================================================

#[cfg(any(target_os = "windows", test))]
const WIN_IF_TYPE_PPP: u32 = 23;
#[cfg(any(target_os = "windows", test))]
const WIN_IF_TYPE_LOOPBACK: u32 = 24;
#[cfg(any(target_os = "windows", test))]
const WIN_IF_TYPE_PROP_VIRTUAL: u32 = 53;
#[cfg(any(target_os = "windows", test))]
const WIN_IF_TYPE_TUNNEL: u32 = 131;

#[cfg(any(target_os = "windows", test))]
fn is_windows_loopback_or_transition_tunnel(adapter: &WindowsAdapter) -> bool {
    if adapter.if_type == WIN_IF_TYPE_LOOPBACK {
        return true;
    }
    let name_lower = adapter.friendly_name.trim().to_ascii_lowercase();
    let desc_lower = adapter.description.trim().to_ascii_lowercase();
    if name_lower == "lo"
        || name_lower == "lo0"
        || name_lower.contains("loopback")
        || desc_lower.contains("loopback")
    {
        return true;
    }
    const TRANSITION_TUNNELS: &[&str] = &["teredo", "isatap", "6to4", "iphttps", "ip-https"];
    TRANSITION_TUNNELS
        .iter()
        .any(|needle| name_lower.contains(needle) || desc_lower.contains(needle))
}

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone)]
pub(crate) struct WindowsAdapter {
    pub(crate) friendly_name: String,
    pub(crate) description: String,
    pub(crate) luid: u64,
    pub(crate) if_index: u32,
    pub(crate) ipv6_if_index: u32,
    pub(crate) if_type: u32,
    pub(crate) ipv4_metric: u32,
    pub(crate) ipv6_metric: u32,
}

#[cfg(any(target_os = "windows", test))]
fn is_windows_virtual_tunnel_if_type(if_type: u32) -> bool {
    matches!(
        if_type,
        WIN_IF_TYPE_PROP_VIRTUAL | WIN_IF_TYPE_TUNNEL | WIN_IF_TYPE_PPP
    )
}

#[cfg(any(target_os = "windows", test))]
fn windows_winning_effective_metric(
    adapter: &WindowsAdapter,
    flags: GlobalRouteFlags,
    other_best_v4_metric: Option<u32>,
    other_best_v6_metric: Option<u32>,
    allow_tie: bool,
) -> Option<u32> {
    let mut best: Option<u32> = None;
    let mut record = |m: u32| {
        best = Some(match best {
            Some(cur) => cur.min(m),
            None => m,
        });
    };

    if flags.has_v4_split_default() {
        record(
            adapter
                .ipv4_metric
                .saturating_add(flags.best_v4_metric.unwrap_or(0)),
        );
    } else if flags.v4_default {
        let eff = adapter
            .ipv4_metric
            .saturating_add(flags.best_v4_metric.unwrap_or(0));
        let wins = match other_best_v4_metric {
            None => true,
            Some(phys) if allow_tie => eff <= phys,
            Some(phys) => eff < phys,
        };
        if wins {
            record(eff);
        }
    }

    if flags.has_v6_split_default() {
        record(
            adapter
                .ipv6_metric
                .saturating_add(flags.best_v6_metric.unwrap_or(0)),
        );
    } else if flags.v6_default {
        let eff = adapter
            .ipv6_metric
            .saturating_add(flags.best_v6_metric.unwrap_or(0));
        // On IPv4-only hosts (other_best_v6_metric == None && other_best_v4_metric.is_some()),
        // an adapter carrying only an IPv6 `::/0` route must not false-positive as a full-tunnel
        // VPN when it does not also capture IPv4 traffic.
        let wins = match other_best_v6_metric {
            None => other_best_v4_metric.is_none(),
            Some(phys) if allow_tie => eff <= phys,
            Some(phys) => eff < phys,
        };
        if wins {
            record(eff);
        }
    }

    best
}

#[cfg(any(target_os = "windows", test))]
pub(crate) fn evaluate_windows_vpn_scope(
    adapters: &[WindowsAdapter],
    routes_by_luid: &HashMap<u64, GlobalRouteFlags>,
    routes_by_index: &HashMap<u32, GlobalRouteFlags>,
    self_tun_name: Option<&str>,
) -> VpnScope {
    if adapters.is_empty() {
        return VpnScope::None;
    }

    let lookup_flags = |adapter: &WindowsAdapter| -> GlobalRouteFlags {
        if let Some(&flags) = (adapter.luid != 0)
            .then(|| routes_by_luid.get(&adapter.luid))
            .flatten()
        {
            return flags;
        }
        let mut merged = GlobalRouteFlags::default();
        for idx in [adapter.if_index, adapter.ipv6_if_index] {
            let Some(&flags) = (idx != 0).then(|| routes_by_index.get(&idx)).flatten() else {
                continue;
            };
            merged.merge_from(flags);
        }
        merged
    };

    // Pass 1: track best physical NIC `/0` effective metric per address family
    // so standby/high-metric VPN `/0` routes do not cause false-positive yields.
    let mut other_best_v4_metric: Option<u32> = None;
    let mut other_best_v6_metric: Option<u32> = None;

    for adapter in adapters {
        if is_self_interface(&adapter.friendly_name, self_tun_name)
            || is_excluded_non_vpn_adapter(&adapter.friendly_name, &adapter.description)
        {
            continue;
        }
        let classified = classify_vpn_adapter_name(&adapter.friendly_name, &adapter.description);
        if classified.is_some() || is_windows_virtual_tunnel_if_type(adapter.if_type) {
            continue;
        }

        let flags = lookup_flags(adapter);
        if flags.v4_default {
            let eff = adapter
                .ipv4_metric
                .saturating_add(flags.best_v4_metric.unwrap_or(0));
            other_best_v4_metric = Some(match other_best_v4_metric {
                Some(cur) => cur.min(eff),
                None => eff,
            });
        }
        if flags.v6_default {
            let eff = adapter
                .ipv6_metric
                .saturating_add(flags.best_v6_metric.unwrap_or(0));
            other_best_v6_metric = Some(match other_best_v6_metric {
                Some(cur) => cur.min(eff),
                None => eff,
            });
        }
    }

    // Fallback for VM guests (Hyper-V, VMware, VirtualBox) where the primary internet
    // adapter is matched by `is_excluded_non_vpn_adapter`: if Pass 1 found zero physical
    // defaults, scan non-VPN host/VM adapters so standby VPN `/0` routes do not
    // false-positive as sole-default / kill-switch full tunnels.
    if other_best_v4_metric.is_none() && other_best_v6_metric.is_none() {
        for adapter in adapters {
            if is_self_interface(&adapter.friendly_name, self_tun_name)
                || is_windows_loopback_or_transition_tunnel(adapter)
            {
                continue;
            }
            if classify_vpn_adapter_name(&adapter.friendly_name, &adapter.description).is_some() {
                continue;
            }
            let is_excluded_vm_nic =
                is_excluded_non_vpn_adapter(&adapter.friendly_name, &adapter.description);
            if !is_excluded_vm_nic && is_windows_virtual_tunnel_if_type(adapter.if_type) {
                continue;
            }

            let flags = lookup_flags(adapter);
            if flags.v4_default {
                let eff = adapter
                    .ipv4_metric
                    .saturating_add(flags.best_v4_metric.unwrap_or(0));
                other_best_v4_metric = Some(match other_best_v4_metric {
                    Some(cur) => cur.min(eff),
                    None => eff,
                });
            }
            if flags.v6_default {
                let eff = adapter
                    .ipv6_metric
                    .saturating_add(flags.best_v6_metric.unwrap_or(0));
                other_best_v6_metric = Some(match other_best_v6_metric {
                    Some(cur) => cur.min(eff),
                    None => eff,
                });
            }
        }
    }

    struct FullTunnelCandidate {
        provider: &'static str,
        iface: String,
        flags: GlobalRouteFlags,
        effective_metric: u32,
    }

    let mut full_tunnels: Vec<FullTunnelCandidate> = Vec::new();
    let mut split_overlays: Vec<String> = Vec::new();

    // Pass 2: evaluate VPN and unnamed virtual/tunnel adapters.
    for adapter in adapters {
        if is_self_interface(&adapter.friendly_name, self_tun_name)
            || is_excluded_non_vpn_adapter(&adapter.friendly_name, &adapter.description)
        {
            continue;
        }

        let flags = lookup_flags(adapter);
        let classified = classify_vpn_adapter_name(&adapter.friendly_name, &adapter.description);

        if let Some(provider) = classified {
            if let Some(effective_metric) = windows_winning_effective_metric(
                adapter,
                flags,
                other_best_v4_metric,
                other_best_v6_metric,
                true,
            ) {
                full_tunnels.push(FullTunnelCandidate {
                    provider,
                    iface: adapter.friendly_name.clone(),
                    flags,
                    effective_metric,
                });
            } else {
                split_overlays.push(provider.to_string());
            }
        } else if let Some(effective_metric) = is_windows_virtual_tunnel_if_type(adapter.if_type)
            .then(|| {
                windows_winning_effective_metric(
                    adapter,
                    flags,
                    other_best_v4_metric,
                    other_best_v6_metric,
                    false,
                )
            })
            .flatten()
        {
            // Unknown VPN client owning `/1` split-default or beating physical NIC `/0`.
            full_tunnels.push(FullTunnelCandidate {
                provider: "VPN",
                iface: adapter.friendly_name.clone(),
                flags,
                effective_metric,
            });
        }
    }

    if !full_tunnels.is_empty() {
        // Prefer split-default (`/1` beats `/0` via LPM), then lowest effective metric.
        full_tunnels.sort_by(|a, b| {
            b.flags
                .has_split_default()
                .cmp(&a.flags.has_split_default())
                .then_with(|| a.effective_metric.cmp(&b.effective_metric))
                .then_with(|| a.iface.cmp(&b.iface))
        });
        let winner = &full_tunnels[0];
        let other_has_v4_default = other_best_v4_metric.is_some();
        let other_has_v6_default = other_best_v6_metric.is_some();
        let kill_switch = !other_has_v4_default
            && (winner.flags.v4_default || (winner.flags.v6_default && !other_has_v6_default));

        return VpnScope::FullTunnel {
            provider: winner.provider.to_string(),
            iface: winner.iface.clone(),
            kill_switch,
        };
    }

    if !split_overlays.is_empty() {
        split_overlays.sort();
        split_overlays.dedup();
        return VpnScope::SplitOverlay {
            providers: split_overlays,
        };
    }

    VpnScope::None
}

#[cfg(target_os = "windows")]
mod win_detect {
    use super::{evaluate_windows_vpn_scope, GlobalRouteFlags, VpnScope, WindowsAdapter};
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetAdaptersAddresses, GetIpForwardTable2, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    #[derive(Clone, Copy)]
    enum GlobalRouteKind {
        V4Default,
        V4LowerHalf,
        V4UpperHalf,
        V6Default,
        V6LowerHalf,
        V6UpperHalf,
    }

    impl GlobalRouteKind {
        fn apply(self, flags: &mut GlobalRouteFlags, metric: u32) {
            match self {
                Self::V4Default => {
                    flags.v4_default = true;
                    flags.record_v4_metric(metric);
                }
                Self::V4LowerHalf => {
                    flags.v4_lower_half = true;
                    flags.record_v4_metric(metric);
                }
                Self::V4UpperHalf => {
                    flags.v4_upper_half = true;
                    flags.record_v4_metric(metric);
                }
                Self::V6Default => {
                    flags.v6_default = true;
                    flags.record_v6_metric(metric);
                }
                Self::V6LowerHalf => {
                    flags.v6_lower_half = true;
                    flags.record_v6_metric(metric);
                }
                Self::V6UpperHalf => {
                    flags.v6_upper_half = true;
                    flags.record_v6_metric(metric);
                }
            }
        }
    }

    struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

    impl Drop for MibTableGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeMibTable(self.0.cast());
                }
            }
        }
    }

    unsafe fn pwstr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while len < 4096 && *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16_lossy(slice)
    }

    fn enumerate_up_adapters() -> Vec<WindowsAdapter> {
        let flags = GAA_FLAG_SKIP_UNICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_DNS_SERVER;
        let elem_size = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>().max(1);
        let mut byte_len: u32 = 32 * 1024;

        for _ in 0..4 {
            let count = (byte_len as usize).div_ceil(elem_size).max(1);
            let mut buf = vec![IP_ADAPTER_ADDRESSES_LH::default(); count];
            let mut actual_bytes = (buf.len() * elem_size) as u32;

            let status = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    flags,
                    std::ptr::null(),
                    buf.as_mut_ptr(),
                    &mut actual_bytes,
                )
            };

            if status == ERROR_BUFFER_OVERFLOW {
                byte_len = actual_bytes.max(byte_len.saturating_mul(2));
                continue;
            }
            if status != NO_ERROR {
                return Vec::new();
            }

            let mut adapters = Vec::new();
            let mut cur: *const IP_ADAPTER_ADDRESSES_LH = buf.as_ptr();
            while !cur.is_null() {
                let adapter = unsafe { &*cur };
                if adapter.OperStatus == IfOperStatusUp
                    && adapter.IfType != IF_TYPE_SOFTWARE_LOOPBACK
                {
                    let friendly_name = unsafe { pwstr_to_string(adapter.FriendlyName) };
                    let description = unsafe { pwstr_to_string(adapter.Description) };
                    let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                    let luid = unsafe { adapter.Luid.Value };

                    adapters.push(WindowsAdapter {
                        friendly_name,
                        description,
                        luid,
                        if_index,
                        ipv6_if_index: adapter.Ipv6IfIndex,
                        if_type: adapter.IfType,
                        ipv4_metric: adapter.Ipv4Metric,
                        ipv6_metric: adapter.Ipv6Metric,
                    });
                }
                cur = adapter.Next;
            }
            return adapters;
        }

        Vec::new()
    }

    fn enumerate_global_routes() -> (
        HashMap<u64, GlobalRouteFlags>,
        HashMap<u32, GlobalRouteFlags>,
    ) {
        let mut by_luid: HashMap<u64, GlobalRouteFlags> = HashMap::new();
        let mut by_index: HashMap<u32, GlobalRouteFlags> = HashMap::new();

        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
        if status != NO_ERROR || table_ptr.is_null() {
            return (by_luid, by_index);
        }
        let _guard = MibTableGuard(table_ptr);

        let num_entries = unsafe { (*table_ptr).NumEntries as usize };
        if num_entries == 0 {
            return (by_luid, by_index);
        }

        let rows: &[MIB_IPFORWARD_ROW2] = unsafe {
            let first = std::ptr::addr_of!((*table_ptr).Table).cast::<MIB_IPFORWARD_ROW2>();
            std::slice::from_raw_parts(first, num_entries)
        };

        for row in rows {
            let prefix_len = row.DestinationPrefix.PrefixLength;
            if prefix_len > 1 {
                continue;
            }

            let family = unsafe { row.DestinationPrefix.Prefix.si_family };
            let kind = if family == AF_INET {
                let b = unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_un_b };
                let octets = [b.s_b1, b.s_b2, b.s_b3, b.s_b4];
                if prefix_len == 0 && octets == [0, 0, 0, 0] {
                    Some(GlobalRouteKind::V4Default)
                } else if prefix_len == 1 && octets == [0, 0, 0, 0] {
                    Some(GlobalRouteKind::V4LowerHalf)
                } else if prefix_len == 1 && octets == [128, 0, 0, 0] {
                    Some(GlobalRouteKind::V4UpperHalf)
                } else {
                    None
                }
            } else if family == AF_INET6 {
                let bytes = unsafe { row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte };
                if prefix_len == 0 && bytes == [0u8; 16] {
                    Some(GlobalRouteKind::V6Default)
                } else if prefix_len == 1 && bytes == [0u8; 16] {
                    Some(GlobalRouteKind::V6LowerHalf)
                } else if prefix_len == 1 && bytes[0] == 0x80 && bytes[1..].iter().all(|&x| x == 0)
                {
                    Some(GlobalRouteKind::V6UpperHalf)
                } else {
                    None
                }
            } else {
                None
            };

            let Some(kind) = kind else {
                continue;
            };

            let luid = unsafe { row.InterfaceLuid.Value };
            let if_index = row.InterfaceIndex;
            let metric = row.Metric;

            if luid != 0 {
                kind.apply(by_luid.entry(luid).or_default(), metric);
            }
            if if_index != 0 {
                kind.apply(by_index.entry(if_index).or_default(), metric);
            }
        }

        (by_luid, by_index)
    }

    pub(super) fn detect_windows(self_tun_name: Option<&str>) -> VpnScope {
        let adapters = enumerate_up_adapters();
        if adapters.is_empty() {
            return VpnScope::None;
        }

        let (routes_by_luid, routes_by_index) = enumerate_global_routes();
        evaluate_windows_vpn_scope(&adapters, &routes_by_luid, &routes_by_index, self_tun_name)
    }
}

#[cfg(target_os = "windows")]
fn detect_windows(self_tun_name: Option<&str>) -> VpnScope {
    win_detect::detect_windows(self_tun_name)
}

// ============================================================================
// macOS implementation (`netstat -rn -f inet` / `inet6`, ignoring Apple utun)
// ============================================================================

#[cfg(any(target_os = "macos", test))]
fn is_macos_vpn_iface(iface: &str) -> bool {
    let lower = iface.trim().to_ascii_lowercase();
    is_prefix_followed_by_digit(&lower, "utun")
        || is_prefix_followed_by_digit(&lower, "ppp")
        || is_prefix_followed_by_digit(&lower, "ipsec")
        || is_wireguard_iface_name(&lower)
        || classify_vpn_adapter_name(iface, "").is_some()
}

#[cfg(any(target_os = "macos", test))]
fn infer_macos_provider(iface: &str, is_tailscale_overlay: bool) -> &'static str {
    if let Some(provider) = classify_vpn_adapter_name(iface, "") {
        return provider;
    }
    if is_tailscale_overlay {
        return "Tailscale";
    }
    let lower = iface.trim().to_ascii_lowercase();
    if is_wireguard_iface_name(&lower) {
        return "WireGuard";
    }
    if is_prefix_followed_by_digit(&lower, "ipsec") {
        return "IPsec VPN";
    }
    if is_prefix_followed_by_digit(&lower, "ppp") {
        return "PPP VPN";
    }
    "VPN"
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default)]
struct MacosNetstatParsed {
    routes: BTreeMap<String, GlobalRouteFlags>,
    tailscale_ifaces: BTreeMap<String, bool>,
    overlay_ifaces: BTreeMap<String, &'static str>,
    v4_default_order: Vec<String>,
    v6_default_order: Vec<String>,
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_netstat_table(output: &str, is_ipv6: bool, parsed: &mut MacosNetstatParsed) {
    let mut netif_col: usize = 3;

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("Routing tables") || line.starts_with("Internet") {
            continue;
        }

        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 {
            continue;
        }

        if cols[0].eq_ignore_ascii_case("Destination") {
            if let Some(idx) = cols.iter().position(|c| c.eq_ignore_ascii_case("Netif")) {
                netif_col = idx;
            }
            continue;
        }

        let dest = cols[0];
        let flags_str = cols[2];
        let Some(&iface) = cols.get(netif_col) else {
            continue;
        };

        // Ignore down routes and interface-scoped routes (`I`), which do not
        // capture unscoped global traffic.
        if !flags_str.contains('U') || flags_str.contains('I') {
            continue;
        }

        if is_ipv6 {
            if dest == "default" || dest == "::/0" {
                parsed
                    .routes
                    .entry(iface.to_string())
                    .or_default()
                    .v6_default = true;
                parsed.v6_default_order.push(iface.to_string());
            } else if dest == "::/1" {
                parsed
                    .routes
                    .entry(iface.to_string())
                    .or_default()
                    .v6_lower_half = true;
            } else if dest.eq_ignore_ascii_case("8000::/1") {
                parsed
                    .routes
                    .entry(iface.to_string())
                    .or_default()
                    .v6_upper_half = true;
            } else if dest.to_ascii_lowercase().starts_with("fd7a:115c:a1e0:") {
                parsed.tailscale_ifaces.insert(iface.to_string(), true);
            }
        } else if dest == "default" || dest == "0.0.0.0/0" {
            parsed
                .routes
                .entry(iface.to_string())
                .or_default()
                .v4_default = true;
            parsed.v4_default_order.push(iface.to_string());
        } else if dest == "0/1" || dest == "0.0.0.0/1" {
            parsed
                .routes
                .entry(iface.to_string())
                .or_default()
                .v4_lower_half = true;
        } else if dest == "128/1" || dest == "128.0/1" || dest == "128.0.0.0/1" {
            parsed
                .routes
                .entry(iface.to_string())
                .or_default()
                .v4_upper_half = true;
        } else if dest == "100.64/10" || dest == "100.64.0.0/10" {
            parsed.tailscale_ifaces.insert(iface.to_string(), true);
        }

        if let Some(provider) = classify_vpn_adapter_name(iface, "") {
            parsed.overlay_ifaces.insert(iface.to_string(), provider);
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_netstat_routes_detailed(
    inet_output: &str,
    inet6_output: &str,
    self_tun_name: Option<&str>,
) -> (VpnScope, bool) {
    let mut parsed = MacosNetstatParsed::default();
    parse_macos_netstat_table(inet_output, false, &mut parsed);
    parse_macos_netstat_table(inet6_output, true, &mut parsed);

    // Track the first unscoped `default` per family in `netstat` line order
    // (after excluding vdpi's own TUN and non-VPN adapters) so a lower-priority
    // `utun` default listed after `en0` does not false-positive as `FullTunnel`.
    let primary_v4_default = parsed.v4_default_order.iter().find(|iface| {
        !is_self_interface(iface, self_tun_name) && !is_excluded_non_vpn_adapter(iface, "")
    });
    let primary_v6_default = parsed.v6_default_order.iter().find(|iface| {
        !is_self_interface(iface, self_tun_name) && !is_excluded_non_vpn_adapter(iface, "")
    });

    let mut other_has_v4_default = false;
    let mut other_has_v6_default = false;
    for (iface, &flags) in &parsed.routes {
        if is_self_interface(iface, self_tun_name) || is_excluded_non_vpn_adapter(iface, "") {
            continue;
        }
        if !is_macos_vpn_iface(iface) {
            if flags.v4_default {
                other_has_v4_default = true;
            }
            if flags.v6_default {
                other_has_v6_default = true;
            }
        }
    }

    let mut full_tunnels: Vec<(&'static str, String, GlobalRouteFlags, bool)> = Vec::new();

    for (iface, &flags) in &parsed.routes {
        if is_self_interface(iface, self_tun_name) || is_excluded_non_vpn_adapter(iface, "") {
            continue;
        }

        if is_macos_vpn_iface(iface) {
            let wins_v4_default =
                flags.v4_default && primary_v4_default.is_some_and(|primary| primary == iface);
            let wins_v6_default = flags.v6_default
                && (other_has_v6_default || !other_has_v4_default)
                && primary_v6_default.is_some_and(|primary| primary == iface);
            if flags.has_split_default() || wins_v4_default || wins_v6_default {
                let is_ts = parsed.tailscale_ifaces.contains_key(iface);
                let provider = infer_macos_provider(iface, is_ts);
                full_tunnels.push((provider, iface.clone(), flags, is_ts));
            }
        }
    }

    if !full_tunnels.is_empty() {
        full_tunnels.sort_by(|a, b| {
            b.2.has_split_default()
                .cmp(&a.2.has_split_default())
                .then_with(|| a.1.cmp(&b.1))
        });
        let &(provider, ref iface, flags, is_ts) = &full_tunnels[0];
        let kill_switch = !other_has_v4_default
            && (flags.v4_default || (flags.v6_default && !other_has_v6_default));

        return (
            VpnScope::FullTunnel {
                provider: provider.to_string(),
                iface: iface.clone(),
                kill_switch,
            },
            is_ts,
        );
    }

    let mut split_overlays: Vec<String> = Vec::new();
    for iface in parsed.tailscale_ifaces.keys() {
        if !is_self_interface(iface, self_tun_name)
            && !is_excluded_non_vpn_adapter(iface, "")
            && is_macos_vpn_iface(iface)
        {
            split_overlays.push("Tailscale".to_string());
        }
    }
    for (iface, &provider) in &parsed.overlay_ifaces {
        if !is_self_interface(iface, self_tun_name) && !is_excluded_non_vpn_adapter(iface, "") {
            split_overlays.push(provider.to_string());
        }
    }

    if !split_overlays.is_empty() {
        split_overlays.sort();
        split_overlays.dedup();
        return (
            VpnScope::SplitOverlay {
                providers: split_overlays,
            },
            false,
        );
    }

    (VpnScope::None, false)
}

#[cfg(test)]
fn parse_macos_netstat_routes(
    inet_output: &str,
    inet6_output: &str,
    self_tun_name: Option<&str>,
) -> VpnScope {
    parse_macos_netstat_routes_detailed(inet_output, inet6_output, self_tun_name).0
}

#[cfg(any(target_os = "macos", test))]
fn is_macos_split_overlay_provider(provider: &str) -> bool {
    matches!(provider, "Tailscale" | "ZeroTier")
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_scutil_connected_service(text: &str, is_tailscale_overlay: bool) -> Option<String> {
    for line in text.lines() {
        if !line.contains("(Connected)") {
            continue;
        }
        let Some(start) = line.find('"') else {
            continue;
        };
        let rest = &line[start + 1..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        let svc = rest[..end].trim();
        if svc.is_empty() || is_excluded_non_vpn_adapter(svc, "") {
            continue;
        }
        if let Some(known) = classify_vpn_adapter_name(svc, "") {
            if is_macos_split_overlay_provider(known) && !is_tailscale_overlay {
                continue;
            }
            return Some(known.to_string());
        }
        return Some(svc.to_string());
    }
    None
}

#[cfg(target_os = "macos")]
fn detect_macos(self_tun_name: Option<&str>) -> VpnScope {
    use std::process::Command;

    let inet_out = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let inet6_out = Command::new("/usr/sbin/netstat")
        .args(["-rn", "-f", "inet6"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();

    let (mut scope, is_tailscale_overlay) =
        parse_macos_netstat_routes_detailed(&inet_out, &inet6_out, self_tun_name);

    // Enrich generic `"VPN"` label from `scutil --nc list` only when a full
    // tunnel was already confirmed via the routing table.
    if let VpnScope::FullTunnel {
        ref mut provider, ..
    } = scope
    {
        if let Some(connected_name) = (provider == "VPN")
            .then(|| query_macos_connected_vpn_service(is_tailscale_overlay))
            .flatten()
        {
            *provider = connected_name;
        }
    }

    scope
}

#[cfg(target_os = "macos")]
fn query_macos_connected_vpn_service(is_tailscale_overlay: bool) -> Option<String> {
    use std::process::Command;

    let output = Command::new("/usr/sbin/scutil")
        .args(["--nc", "list"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_macos_scutil_connected_service(&text, is_tailscale_overlay)
}

// ============================================================================
// Linux implementation (`/sys/class/net/*` + `/proc/net/route` + `ip rule`)
// ============================================================================

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct LinuxIpRuleSummary {
    custom_tables: Vec<String>,
    has_fwmark_bypass_rule: bool,
    has_suppress_prefix_zero: bool,
    has_global_kill_switch_rule: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxIfaceKind {
    Other,
    WireGuard,
    Tun,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxUpIface {
    name: String,
    kind: LinuxIfaceKind,
}

#[cfg(any(target_os = "linux", test))]
impl LinuxUpIface {
    #[cfg(test)]
    fn other(name: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: LinuxIfaceKind::Other,
        }
    }

    #[cfg(test)]
    fn with_kind(name: &str, kind: LinuxIfaceKind) -> Self {
        Self {
            name: name.to_string(),
            kind,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_uevent_is_wireguard(uevent: &str) -> bool {
    uevent.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.eq_ignore_ascii_case("DEVTYPE=wireguard")
            || trimmed.eq_ignore_ascii_case("DEVTYPE=amneziawg")
    })
}

#[cfg(any(target_os = "linux", test))]
fn is_linux_generic_vpn_iface(iface: &str) -> bool {
    let lower = iface.trim().to_ascii_lowercase();
    is_prefix_followed_by_digit(&lower, "tun")
        || is_prefix_followed_by_digit(&lower, "tap")
        || is_prefix_followed_by_digit(&lower, "utun")
        || is_prefix_followed_by_digit(&lower, "ppp")
        || is_prefix_followed_by_digit(&lower, "ipsec")
        || is_prefix_followed_by_digit(&lower, "xfrm")
        || is_prefix_followed_by_digit(&lower, "gpd")
        || is_prefix_followed_by_digit(&lower, "cscotun")
        || is_wireguard_iface_name(&lower)
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_proc_route(contents: &str) -> BTreeMap<String, GlobalRouteFlags> {
    let mut routes: BTreeMap<String, GlobalRouteFlags> = BTreeMap::new();

    for raw_line in contents.lines().skip(1) {
        let cols: Vec<&str> = raw_line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }

        let iface = cols[0];
        let Ok(dest_raw) = u32::from_str_radix(cols[1], 16) else {
            continue;
        };
        let Ok(flags_val) = u32::from_str_radix(cols[3], 16) else {
            continue;
        };
        // RTF_UP = 0x0001
        if flags_val & 0x0001 == 0 {
            continue;
        }
        let metric = cols[6].parse::<u32>().unwrap_or(0);
        let Ok(mask_raw) = u32::from_str_radix(cols[7], 16) else {
            continue;
        };

        // Linux `/proc/net/route` prints 32-bit IPv4 addresses in host byte order.
        let dest = dest_raw.to_ne_bytes();
        let mask = mask_raw.to_ne_bytes();

        if dest == [0, 0, 0, 0] && mask == [0, 0, 0, 0] {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_default = true;
            entry.record_v4_metric(metric);
        } else if dest == [0, 0, 0, 0] && mask == [128, 0, 0, 0] {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_lower_half = true;
            entry.record_v4_metric(metric);
        } else if dest == [128, 0, 0, 0] && mask == [128, 0, 0, 0] {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_upper_half = true;
            entry.record_v4_metric(metric);
        }
    }

    routes
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_proc_ipv6_route(contents: &str, routes: &mut BTreeMap<String, GlobalRouteFlags>) {
    for raw_line in contents.lines() {
        let cols: Vec<&str> = raw_line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let dest = cols[0];
        let Ok(prefix_len) = u8::from_str_radix(cols[1], 16) else {
            continue;
        };
        if prefix_len > 1 {
            continue;
        }
        let Ok(metric) = u32::from_str_radix(cols[5], 16) else {
            continue;
        };
        let Ok(flags_val) = u32::from_str_radix(cols[8], 16) else {
            continue;
        };
        // RTF_UP = 0x0001
        if flags_val & 0x0001 == 0 {
            continue;
        }
        let iface = cols[9];

        if prefix_len == 0 && dest == "00000000000000000000000000000000" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_default = true;
            entry.record_v6_metric(metric);
        } else if prefix_len == 1 && dest == "00000000000000000000000000000000" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_lower_half = true;
            entry.record_v6_metric(metric);
        } else if prefix_len == 1 && dest.eq_ignore_ascii_case("80000000000000000000000000000000") {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_upper_half = true;
            entry.record_v6_metric(metric);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn is_vdpi_self_ip_rule(tokens: &[&str]) -> bool {
    if tokens
        .first()
        .and_then(|t| t.strip_suffix(':'))
        .is_some_and(|prio| matches!(prio, "5480" | "5485" | "5490" | "5500"))
    {
        return true;
    }
    for pair in tokens.windows(2) {
        if pair[0] == "fwmark" {
            let mark_str = pair[1].split('/').next().unwrap_or(pair[1]);
            let parsed_mark = mark_str
                .strip_prefix("0x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| mark_str.parse::<u32>().ok());
            if parsed_mark == Some(0x5644) {
                return true;
            }
        }
        if (pair[0] == "lookup" || pair[0] == "table") && pair[1] == "202" {
            return true;
        }
    }
    false
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ip_rules(output: &str) -> LinuxIpRuleSummary {
    let mut summary = LinuxIpRuleSummary::default();

    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let tokens: Vec<&str> = lower.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }

        // Ignore vdpi's own policy rules (priorities 5480/5485/5490/5500,
        // fwmark 0x5644, lookup 202) so vdpi0's own `suppress_prefixlength 0`
        // rule never contaminates third-party VPN kill-switch detection.
        if is_vdpi_self_ip_rule(&tokens) {
            continue;
        }

        let has_scoped_selector = tokens.iter().any(|&tok| {
            matches!(
                tok,
                "to" | "iif" | "oif" | "uidrange" | "ipproto" | "sport" | "dport"
            )
        });

        if !has_scoped_selector && lower.contains("suppress_prefixlength 0") {
            summary.has_suppress_prefix_zero = true;
        }

        let is_not_fwmark = lower.contains("not from all fwmark")
            || (lower.contains("not ") && lower.contains("fwmark"));
        let has_positive_fwmark = lower.contains("fwmark") && !is_not_fwmark;

        if !has_scoped_selector
            && is_not_fwmark
            && (tokens.contains(&"lookup") || tokens.contains(&"table"))
        {
            summary.has_fwmark_bypass_rule = true;
        }

        // Only count global reject rules (e.g. `from all blackhole` or
        // `not from all fwmark 0x... unreachable`), never positive-fwmark or
        // scoped selector rules like Tailscale's `from all fwmark 0x80000/0xff0000 unreachable`.
        if !has_scoped_selector
            && (lower.contains("blackhole")
                || lower.contains("prohibit")
                || lower.contains("unreachable"))
            && !has_positive_fwmark
            && (lower.contains("from all") || is_not_fwmark)
        {
            summary.has_global_kill_switch_rule = true;
        }

        // Collect custom routing tables referenced by global `from all ... lookup <table>`
        // or `not from all fwmark ... lookup <table>`, rejecting scoped selectors.
        if !has_scoped_selector
            && !has_positive_fwmark
            && (lower.contains("from all") || is_not_fwmark)
        {
            // Use original-case tokens to preserve named routing tables.
            let orig_tokens: Vec<&str> = line.split_whitespace().collect();
            let Some(pos) = orig_tokens
                .iter()
                .position(|t| t.eq_ignore_ascii_case("lookup") || t.eq_ignore_ascii_case("table"))
            else {
                continue;
            };
            let Some(&table) = orig_tokens.get(pos + 1) else {
                continue;
            };
            let table_lower = table.to_ascii_lowercase();
            if !matches!(
                table_lower.as_str(),
                "local" | "main" | "default" | "0" | "253" | "254" | "255"
            ) && !summary.custom_tables.iter().any(|t| t == table)
            {
                summary.custom_tables.push(table.to_string());
            }
        }
    }

    summary
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_ip_route_table(
    output: &str,
    is_ipv6: bool,
    routes: &mut BTreeMap<String, GlobalRouteFlags>,
) {
    for raw_line in output.lines() {
        let tokens: Vec<&str> = raw_line.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        let dest = tokens[0];
        let Some(dev_pos) = tokens.iter().position(|&t| t == "dev") else {
            continue;
        };
        let Some(&iface) = tokens.get(dev_pos + 1) else {
            continue;
        };
        let metric = tokens
            .iter()
            .position(|&t| t == "metric")
            .and_then(|pos| tokens.get(pos + 1))
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);

        if dest == "default" {
            let entry = routes.entry(iface.to_string()).or_default();
            if is_ipv6 {
                entry.v6_default = true;
                entry.record_v6_metric(metric);
            } else {
                entry.v4_default = true;
                entry.record_v4_metric(metric);
            }
        } else if dest == "0.0.0.0/0" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_default = true;
            entry.record_v4_metric(metric);
        } else if dest == "0.0.0.0/1" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_lower_half = true;
            entry.record_v4_metric(metric);
        } else if dest == "128.0.0.0/1" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v4_upper_half = true;
            entry.record_v4_metric(metric);
        } else if dest == "::/0" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_default = true;
            entry.record_v6_metric(metric);
        } else if dest == "::/1" {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_lower_half = true;
            entry.record_v6_metric(metric);
        } else if dest.eq_ignore_ascii_case("8000::/1") {
            let entry = routes.entry(iface.to_string()).or_default();
            entry.v6_upper_half = true;
            entry.record_v6_metric(metric);
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn evaluate_linux_vpn_scope(
    up_ifaces: &[LinuxUpIface],
    main_routes: &BTreeMap<String, GlobalRouteFlags>,
    policy_routes: &BTreeMap<String, GlobalRouteFlags>,
    rules: &LinuxIpRuleSummary,
    self_tun_name: Option<&str>,
) -> VpnScope {
    let iface_kinds: BTreeMap<&str, LinuxIfaceKind> = up_ifaces
        .iter()
        .map(|iface| (iface.name.as_str(), iface.kind))
        .collect();

    let mut other_best_v4_metric: Option<u32> = None;
    let mut other_best_v6_metric: Option<u32> = None;

    for (iface, &flags) in main_routes {
        if is_self_interface(iface, self_tun_name) || is_excluded_non_vpn_adapter(iface, "") {
            continue;
        }
        let kind = iface_kinds
            .get(iface.as_str())
            .copied()
            .unwrap_or(LinuxIfaceKind::Other);
        let is_vpn = classify_vpn_adapter_name(iface, "").is_some()
            || is_linux_generic_vpn_iface(iface)
            || kind != LinuxIfaceKind::Other;
        if !is_vpn {
            if flags.v4_default {
                let m = flags.best_v4_metric.unwrap_or(0);
                other_best_v4_metric = Some(match other_best_v4_metric {
                    Some(cur) => cur.min(m),
                    None => m,
                });
            }
            if flags.v6_default {
                let m = flags.best_v6_metric.unwrap_or(0);
                other_best_v6_metric = Some(match other_best_v6_metric {
                    Some(cur) => cur.min(m),
                    None => m,
                });
            }
        }
    }

    let other_has_v4_default = other_best_v4_metric.is_some();
    let other_has_v6_default = other_best_v6_metric.is_some();

    let mut candidates: BTreeMap<String, (GlobalRouteFlags, bool)> = BTreeMap::new();
    for (iface, &flags) in main_routes {
        candidates.insert(iface.clone(), (flags, false));
    }
    for (iface, &flags) in policy_routes {
        let entry = candidates
            .entry(iface.clone())
            .or_insert_with(|| (GlobalRouteFlags::default(), false));
        entry.0.merge_from(flags);
        if flags.has_full_tunnel_route() {
            entry.1 = true;
        }
    }

    struct FullTunnelHit {
        provider: &'static str,
        iface: String,
        flags: GlobalRouteFlags,
        via_policy_table: bool,
    }

    let mut full_tunnels: Vec<FullTunnelHit> = Vec::new();
    for (iface, &(flags, via_policy_table)) in &candidates {
        if is_self_interface(iface, self_tun_name) || is_excluded_non_vpn_adapter(iface, "") {
            continue;
        }
        if !flags.has_full_tunnel_route() {
            continue;
        }
        // Only count interfaces that are currently UP when sysfs list is provided.
        if !up_ifaces.is_empty() && !iface_kinds.contains_key(iface.as_str()) {
            continue;
        }

        // Compare `main`-table `/0` VPN route metrics against physical NIC `/0`
        // metrics when not routed via a policy table or `/1` split-default.
        if !via_policy_table && !flags.has_split_default() {
            let v4_wins = flags.v4_default
                && match other_best_v4_metric {
                    None => true,
                    Some(phys) => flags.best_v4_metric.unwrap_or(0) <= phys,
                };
            let v6_wins = flags.v6_default
                && match other_best_v6_metric {
                    None => other_best_v4_metric.is_none(),
                    Some(phys) => flags.best_v6_metric.unwrap_or(0) <= phys,
                };
            if !v4_wins && !v6_wins {
                continue;
            }
        }

        let kind = iface_kinds
            .get(iface.as_str())
            .copied()
            .unwrap_or(LinuxIfaceKind::Other);
        let provider = if let Some(known) = classify_vpn_adapter_name(iface, "") {
            Some(known)
        } else if kind == LinuxIfaceKind::WireGuard {
            Some("WireGuard")
        } else if kind == LinuxIfaceKind::Tun || is_linux_generic_vpn_iface(iface) {
            Some("VPN")
        } else {
            None
        };

        if let Some(provider) = provider {
            full_tunnels.push(FullTunnelHit {
                provider,
                iface: iface.clone(),
                flags,
                via_policy_table,
            });
        }
    }

    if !full_tunnels.is_empty() {
        full_tunnels.sort_by(|a, b| {
            b.via_policy_table
                .cmp(&a.via_policy_table)
                .then_with(|| {
                    b.flags
                        .has_split_default()
                        .cmp(&a.flags.has_split_default())
                })
                .then_with(|| {
                    a.flags
                        .best_any_metric()
                        .unwrap_or(u32::MAX)
                        .cmp(&b.flags.best_any_metric().unwrap_or(u32::MAX))
                })
                .then_with(|| a.iface.cmp(&b.iface))
        });
        let winner = &full_tunnels[0];
        let policy_kill_switch = winner.via_policy_table
            && rules.has_fwmark_bypass_rule
            && rules.has_suppress_prefix_zero;
        let sole_default_kill_switch = !other_has_v4_default
            && (winner.flags.v4_default || (winner.flags.v6_default && !other_has_v6_default));
        let kill_switch =
            rules.has_global_kill_switch_rule || policy_kill_switch || sole_default_kill_switch;

        return VpnScope::FullTunnel {
            provider: winner.provider.to_string(),
            iface: winner.iface.clone(),
            kill_switch,
        };
    }

    let mut split_overlays: Vec<String> = Vec::new();
    for iface in up_ifaces {
        if is_self_interface(&iface.name, self_tun_name)
            || is_excluded_non_vpn_adapter(&iface.name, "")
        {
            continue;
        }
        if let Some(provider) = classify_vpn_adapter_name(&iface.name, "") {
            split_overlays.push(provider.to_string());
        } else if iface.kind == LinuxIfaceKind::WireGuard {
            split_overlays.push("WireGuard".to_string());
        }
    }

    if !split_overlays.is_empty() {
        split_overlays.sort();
        split_overlays.dedup();
        return VpnScope::SplitOverlay {
            providers: split_overlays,
        };
    }

    VpnScope::None
}

#[cfg(target_os = "linux")]
fn enumerate_linux_up_ifaces(self_tun_name: Option<&str>) -> Vec<LinuxUpIface> {
    let mut up = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return up;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_self_interface(&name, self_tun_name) || is_excluded_non_vpn_adapter(&name, "") {
            continue;
        }

        let base = entry.path();
        let operstate = std::fs::read_to_string(base.join("operstate"))
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let is_up = if operstate == "up" {
            true
        } else if operstate == "unknown" || operstate.is_empty() {
            // Virtual TUN / WireGuard devices frequently report `operstate == "unknown"`
            // while UP (`IFF_UP = 0x1`).
            std::fs::read_to_string(base.join("flags"))
                .ok()
                .and_then(|s| {
                    let trimmed = s.trim();
                    let hex = trimmed
                        .strip_prefix("0x")
                        .or_else(|| trimmed.strip_prefix("0X"))
                        .unwrap_or(trimmed);
                    u32::from_str_radix(hex, 16).ok()
                })
                .is_some_and(|flags| flags & 0x1 != 0)
        } else {
            false
        };

        if is_up {
            let is_wg = std::fs::read_to_string(base.join("uevent"))
                .ok()
                .is_some_and(|uevent| parse_linux_uevent_is_wireguard(&uevent));
            let kind = if is_wg {
                LinuxIfaceKind::WireGuard
            } else if base.join("tun_flags").exists() {
                LinuxIfaceKind::Tun
            } else {
                LinuxIfaceKind::Other
            };
            up.push(LinuxUpIface { name, kind });
        }
    }

    up.sort_by(|a, b| a.name.cmp(&b.name));
    up
}

#[cfg(any(target_os = "linux", test))]
const LINUX_IP_BIN_CANDIDATES: [&str; 4] = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];

#[cfg(target_os = "linux")]
fn resolve_linux_ip_bin() -> &'static str {
    for candidate in LINUX_IP_BIN_CANDIDATES {
        if std::path::Path::new(candidate).is_file() {
            return candidate;
        }
    }
    "/usr/sbin/ip"
}

#[cfg(target_os = "linux")]
fn detect_linux(self_tun_name: Option<&str>) -> VpnScope {
    use std::process::Command;

    let up_ifaces = enumerate_linux_up_ifaces(self_tun_name);

    let mut main_routes = std::fs::read_to_string("/proc/net/route")
        .map(|s| parse_linux_proc_route(&s))
        .unwrap_or_default();
    if let Ok(v6) = std::fs::read_to_string("/proc/net/ipv6_route") {
        parse_linux_proc_ipv6_route(&v6, &mut main_routes);
    }

    let ip_bin = resolve_linux_ip_bin();
    let ip4_rule_out = Command::new(ip_bin)
        .args(["-4", "rule", "show"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let ip6_rule_out = Command::new(ip_bin)
        .args(["-6", "rule", "show"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut combined_rules = ip4_rule_out;
    if !combined_rules.is_empty() && !combined_rules.ends_with('\n') {
        combined_rules.push('\n');
    }
    combined_rules.push_str(&ip6_rule_out);
    let rules = parse_linux_ip_rules(&combined_rules);

    let mut policy_routes: BTreeMap<String, GlobalRouteFlags> = BTreeMap::new();
    for table in rules.custom_tables.iter().take(8) {
        if let Some(out) = Command::new(ip_bin)
            .args(["route", "show", "table", table])
            .output()
            .ok()
            .filter(|o| o.status.success())
        {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_linux_ip_route_table(&text, false, &mut policy_routes);
        }
        if let Some(out) = Command::new(ip_bin)
            .args(["-6", "route", "show", "table", table])
            .output()
            .ok()
            .filter(|o| o.status.success())
        {
            let text = String::from_utf8_lossy(&out.stdout);
            parse_linux_ip_route_table(&text, true, &mut policy_routes);
        }
    }

    evaluate_linux_vpn_scope(
        &up_ifaces,
        &main_routes,
        &policy_routes,
        &rules,
        self_tun_name,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_ipv4_host_order(octets: [u8; 4]) -> String {
        format!("{:08X}", u32::from_ne_bytes(octets))
    }

    #[test]
    fn vpn_scope_helpers_behave_as_expected() {
        assert!(!VpnScope::None.is_full_tunnel());
        assert_eq!(VpnScope::None.full_tunnel_provider(), None);

        let split = VpnScope::SplitOverlay {
            providers: vec!["Tailscale".to_string()],
        };
        assert!(!split.is_full_tunnel());
        assert_eq!(split.full_tunnel_provider(), None);

        let full = VpnScope::FullTunnel {
            provider: "Mullvad".to_string(),
            iface: "Mullvad".to_string(),
            kill_switch: true,
        };
        assert!(full.is_full_tunnel());
        assert_eq!(full.full_tunnel_provider(), Some("Mullvad"));
    }

    #[test]
    fn classifies_all_known_vpn_providers() {
        let cases = [
            ("Mullvad", "WireGuard Tunnel", Some("Mullvad")),
            ("wg0-mullvad", "", Some("Mullvad")),
            ("wg0", "WireGuard Tunnel", Some("WireGuard")),
            ("wg-home", "", Some("WireGuard")),
            (
                "Local Area Connection 2",
                "TAP-Windows Adapter V9",
                Some("OpenVPN"),
            ),
            (
                "OpenVPN Wintun",
                "OpenVPN Data Channel Offload",
                Some("OpenVPN"),
            ),
            ("NordLynx", "NordLynx Tunnel", Some("NordVPN")),
            ("Ethernet 4", "NordVPN TAP-Windows6", Some("NordVPN")),
            ("ProtonVPN", "ProtonVPN Tunnel", Some("ProtonVPN")),
            (
                "CloudflareWARP",
                "Cloudflare WARP Virtual Adapter",
                Some("Cloudflare WARP"),
            ),
            ("Tailscale", "Tailscale Tunnel", Some("Tailscale")),
            ("tailscale0", "", Some("Tailscale")),
            ("ExpressVPN", "ExpressVPN Lightway", Some("ExpressVPN")),
            ("Surfshark", "Surfshark WireGuard", Some("Surfshark")),
            (
                "Cisco AnyConnect",
                "Cisco AnyConnect Secure Mobility Client",
                Some("Cisco AnyConnect"),
            ),
            ("cscotun0", "", Some("Cisco AnyConnect")),
            (
                "Ethernet 5",
                "PANGP Virtual Ethernet Adapter Secure",
                Some("GlobalProtect"),
            ),
            ("gpd0", "", Some("GlobalProtect")),
            (
                "Fortinet SSL VPN",
                "FortiClient Virtual Ethernet Adapter",
                Some("FortiClient"),
            ),
            ("fortivpn0", "", Some("FortiClient")),
            (
                "Ivanti Secure Access",
                "Pulse Secure Virtual Adapter",
                Some("Ivanti/Pulse"),
            ),
            (
                "WindscribeWireguard",
                "WireGuard Tunnel",
                Some("Windscribe"),
            ),
            ("IVPN", "IVPN WireGuard Tunnel", Some("IVPN")),
            (
                "ZeroTier One [a1b2c3d4]",
                "ZeroTier Virtual Port",
                Some("ZeroTier"),
            ),
            ("zt3jn4x8ab", "", Some("ZeroTier")),
            ("AmneziaWG", "AmneziaWG Tunnel", Some("AmneziaVPN")),
            ("AdGuard VPN", "AdGuard Wintun Adapter", Some("AdGuard VPN")),
            ("Outline", "TAP-Windows Adapter V9", Some("Outline VPN")),
            ("sing-box", "Wintun Userspace Tunnel", Some("sing-box")),
            ("Mihomo", "Mihomo Meta Tunnel", Some("Mihomo")),
            ("Work VPN", "WAN Miniport (IKEv2)", Some("IKEv2 VPN")),
            ("Corp SSTP", "WAN Miniport (SSTP)", Some("SSTP VPN")),
            ("Home L2TP", "WAN Miniport (L2TP)", Some("L2TP VPN")),
            ("Legacy PPTP", "WAN Miniport (PPTP)", Some("PPTP VPN")),
            ("WAN Miniport (IP)", "WAN Miniport (IP)", None),
            (
                "WAN Miniport (Network Monitor)",
                "WAN Miniport (Network Monitor)",
                None,
            ),
            (
                "CustomTunnel",
                "Wintun Userspace Tunnel",
                Some("Wintun VPN"),
            ),
            ("Ethernet", "Intel(R) Ethernet Controller I225-V", None),
            ("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz", None),
        ];

        for (name, desc, expected) in cases {
            assert_eq!(
                classify_vpn_adapter_name(name, desc),
                expected,
                "name={name:?} desc={desc:?}"
            );
        }
    }

    #[test]
    fn excludes_self_and_non_vpn_virtual_adapters() {
        let excluded = [
            ("vdpi0", "Wintun Userspace Tunnel"),
            ("vdpi", ""),
            (
                "vEthernet (Default Switch)",
                "Hyper-V Virtual Ethernet Adapter",
            ),
            ("vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter #2"),
            (
                "vEthernet (WSL (Hyper-V firewall))",
                "Hyper-V Virtual Ethernet Adapter",
            ),
            ("docker0", ""),
            ("br-1a2b3c4d5e6f", ""),
            ("veth9f8e7d6", ""),
            ("virbr0", ""),
            (
                "VMware Network Adapter VMnet1",
                "VMware Virtual Ethernet Adapter for VMnet1",
            ),
            ("VMnet8", ""),
            (
                "VirtualBox Host-Only Network",
                "VirtualBox Host-Only Ethernet Adapter",
            ),
            ("vboxnet0", ""),
            (
                "Npcap Loopback Adapter",
                "Microsoft KM-TEST Loopback Adapter",
            ),
            (
                "Bluetooth Network Connection",
                "Bluetooth Device (Personal Area Network)",
            ),
            (
                "Loopback Pseudo-Interface 1",
                "Software Loopback Interface 1",
            ),
            (
                "Teredo Tunneling Pseudo-Interface",
                "Microsoft Teredo Tunneling Adapter",
            ),
            ("isatap.{12345678}", "Microsoft ISATAP Adapter"),
            ("6TO4 Adapter", "Microsoft 6to4 Adapter"),
            ("IPHTTPSInterface", "Microsoft IP-HTTPS Platform Interface"),
            ("lo", ""),
            ("lo0", ""),
        ];

        for (name, desc) in excluded {
            assert!(
                is_excluded_non_vpn_adapter(name, desc),
                "expected excluded: name={name:?} desc={desc:?}"
            );
            assert_eq!(
                classify_vpn_adapter_name(name, desc),
                None,
                "excluded adapter must never classify as VPN: name={name:?} desc={desc:?}"
            );
        }

        assert!(!is_excluded_non_vpn_adapter("Mullvad", "WireGuard Tunnel"));
        assert!(!is_excluded_non_vpn_adapter(
            "Local Area Connection 2",
            "TAP-Windows Adapter V9"
        ));
        assert!(!is_excluded_non_vpn_adapter("tailscale0", ""));
    }

    #[test]
    fn macos_netstat_ignores_apple_system_utun_without_global_routes() {
        let inet = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
127                127.0.0.1          UCS                   lo0
169.254            link#14            UCS                   en0      !
192.168.1          link#14            UCS                   en0      !
";
        let inet6 = "\
Routing tables

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGcg            en0
fe80::%utun0/64                         fe80::1111%utun0                UcI           utun0
fe80::%utun1/64                         fe80::2222%utun1                UcI           utun1
";
        assert_eq!(
            parse_macos_netstat_routes(inet, inet6, Some("utun9")),
            VpnScope::None
        );
    }

    #[test]
    fn macos_netstat_detects_split_default_and_excludes_self_tun() {
        let inet = "\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
0/1                10.8.0.1           UGSc                utun4
128.0/1            10.8.0.1           UGSc                utun4
10.8.0/24          10.8.0.2           UGSc                utun4
";
        assert_eq!(
            parse_macos_netstat_routes(inet, "", Some("utun9")),
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "utun4".to_string(),
                kill_switch: false,
            }
        );

        // If `utun4` is vdpi's own TUN, it must not flag itself.
        assert_eq!(
            parse_macos_netstat_routes(inet, "", Some("utun4")),
            VpnScope::None
        );
    }

    #[test]
    fn macos_netstat_detects_ipv6_split_default_and_tailscale_split_overlay() {
        let inet6_split = "\
Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::1%en0                     UGcg            en0
::/1                                    link#22                         UCS           utun5
8000::/1                                link#22                         UCS           utun5
";
        assert_eq!(
            parse_macos_netstat_routes("", inet6_split, None),
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "utun5".to_string(),
                kill_switch: false,
            }
        );

        let inet_ts = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
100.64/10          link#20            UCS                 utun3
";
        assert_eq!(
            parse_macos_netstat_routes(inet_ts, "", None),
            VpnScope::SplitOverlay {
                providers: vec!["Tailscale".to_string()],
            }
        );
    }

    #[test]
    fn macos_netstat_detects_sole_default_kill_switch() {
        let inet = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            link#21            UCSg                utun4
default            192.168.1.1        UGScIg                en0
";
        assert_eq!(
            parse_macos_netstat_routes(inet, "", None),
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "utun4".to_string(),
                kill_switch: true,
            }
        );
    }

    #[test]
    fn linux_proc_route_parses_split_default_and_excludes_self_and_docker() {
        let z = hex_ipv4_host_order([0, 0, 0, 0]);
        let half = hex_ipv4_host_order([128, 0, 0, 0]);
        let gw_eth = hex_ipv4_host_order([192, 168, 1, 1]);
        let gw_tun = hex_ipv4_host_order([10, 8, 0, 1]);

        let proc_route = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n\
             tun0\t{z}\t{gw_tun}\t0003\t0\t0\t0\t{half}\t0\t0\t0\n\
             tun0\t{half}\t{gw_tun}\t0003\t0\t0\t0\t{half}\t0\t0\t0\n\
             docker0\t{z}\t{gw_eth}\t0003\t0\t0\t0\t{z}\t0\t0\t0\n"
        );

        let parsed = parse_linux_proc_route(&proc_route);
        assert!(parsed.get("eth0").is_some_and(|f| f.v4_default));
        assert!(parsed.get("tun0").is_some_and(|f| f.has_v4_split_default()));

        let up = vec![
            LinuxUpIface::other("eth0"),
            LinuxUpIface::other("tun0"),
            LinuxUpIface::other("docker0"),
            LinuxUpIface::other("vdpi0"),
        ];
        let scope = evaluate_linux_vpn_scope(
            &up,
            &parsed,
            &BTreeMap::new(),
            &LinuxIpRuleSummary::default(),
            Some("vdpi0"),
        );
        assert_eq!(
            scope,
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "tun0".to_string(),
                kill_switch: false,
            }
        );

        // If the split-default belongs to `vdpi0` itself, return `VpnScope::None`.
        let self_only = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n\
             vdpi0\t{z}\t{gw_tun}\t0003\t0\t0\t0\t{half}\t0\t0\t0\n\
             vdpi0\t{half}\t{gw_tun}\t0003\t0\t0\t0\t{half}\t0\t0\t0\n"
        );
        let parsed_self = parse_linux_proc_route(&self_only);
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[LinuxUpIface::other("eth0"), LinuxUpIface::other("vdpi0")],
                &parsed_self,
                &BTreeMap::new(),
                &LinuxIpRuleSummary::default(),
                Some("vdpi0"),
            ),
            VpnScope::None
        );
    }

    #[test]
    fn linux_ip_rules_distinguish_mullvad_fwmark_full_tunnel_from_tailscale_split_overlay() {
        let z = hex_ipv4_host_order([0, 0, 0, 0]);
        let gw_eth = hex_ipv4_host_order([192, 168, 1, 1]);
        let main_proc = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n"
        );
        let main_routes = parse_linux_proc_route(&main_proc);

        // Case 1: Mullvad / wg-quick fwmark policy table with default route.
        let mullvad_rules = parse_linux_ip_rules(
            "0:\tfrom all lookup local\n\
             32764:\tfrom all lookup main suppress_prefixlength 0\n\
             32765:\tnot from all fwmark 0x6d6f6c65 lookup 1836018789\n\
             32766:\tfrom all lookup main\n\
             32767:\tfrom all lookup default\n",
        );
        assert_eq!(mullvad_rules.custom_tables, vec!["1836018789".to_string()]);
        assert!(mullvad_rules.has_fwmark_bypass_rule);
        assert!(mullvad_rules.has_suppress_prefix_zero);

        let mut mullvad_policy = BTreeMap::new();
        parse_linux_ip_route_table(
            "default dev wg0-mullvad scope link\n",
            false,
            &mut mullvad_policy,
        );

        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::other("wg0-mullvad"),
                ],
                &main_routes,
                &mullvad_policy,
                &mullvad_rules,
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "Mullvad".to_string(),
                iface: "wg0-mullvad".to_string(),
                kill_switch: true,
            }
        );

        // Case 2: Tailscale without exit node (table 52 has only 100.64.0.0/10).
        let ts_rules = parse_linux_ip_rules(
            "0:\tfrom all lookup local\n\
             5210:\tfrom all fwmark 0x80000/0xff0000 lookup main\n\
             5230:\tfrom all fwmark 0x80000/0xff0000 lookup default\n\
             5250:\tfrom all fwmark 0x80000/0xff0000 unreachable\n\
             5270:\tfrom all lookup 52\n\
             32766:\tfrom all lookup main\n",
        );
        assert_eq!(ts_rules.custom_tables, vec!["52".to_string()]);
        assert!(!ts_rules.has_global_kill_switch_rule);

        let mut ts_policy = BTreeMap::new();
        parse_linux_ip_route_table(
            "100.64.0.0/10 dev tailscale0 scope link\n",
            false,
            &mut ts_policy,
        );

        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::other("tailscale0"),
                ],
                &main_routes,
                &ts_policy,
                &ts_rules,
                Some("vdpi0"),
            ),
            VpnScope::SplitOverlay {
                providers: vec!["Tailscale".to_string()],
            }
        );
    }

    #[test]
    fn linux_proc_ipv6_route_parses_split_default() {
        let v6_table = "\
00000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000001 wg0\n\
80000000000000000000000000000000 01 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000001 wg0\n";
        let mut routes = BTreeMap::new();
        parse_linux_proc_ipv6_route(v6_table, &mut routes);
        assert!(routes.get("wg0").is_some_and(|f| f.has_v6_split_default()));

        assert_eq!(
            evaluate_linux_vpn_scope(
                &[LinuxUpIface::other("eth0"), LinuxUpIface::other("wg0")],
                &routes,
                &BTreeMap::new(),
                &LinuxIpRuleSummary::default(),
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "WireGuard".to_string(),
                iface: "wg0".to_string(),
                kill_switch: false,
            }
        );
    }

    #[test]
    fn windows_evaluate_vpn_scope_table_driven_cases() {
        const WIN_IF_TYPE_ETHERNET: u32 = 6;

        fn adapter(
            friendly_name: &str,
            description: &str,
            luid: u64,
            if_index: u32,
            if_type: u32,
            ipv4_metric: u32,
            ipv6_metric: u32,
        ) -> WindowsAdapter {
            WindowsAdapter {
                friendly_name: friendly_name.to_string(),
                description: description.to_string(),
                luid,
                if_index,
                ipv6_if_index: if_index,
                if_type,
                ipv4_metric,
                ipv6_metric,
            }
        }

        fn v4_default(metric: u32) -> GlobalRouteFlags {
            GlobalRouteFlags {
                v4_default: true,
                best_v4_metric: Some(metric),
                ..GlobalRouteFlags::default()
            }
        }

        fn v4_split(metric: u32) -> GlobalRouteFlags {
            GlobalRouteFlags {
                v4_lower_half: true,
                v4_upper_half: true,
                best_v4_metric: Some(metric),
                ..GlobalRouteFlags::default()
            }
        }

        fn v6_default(metric: u32) -> GlobalRouteFlags {
            GlobalRouteFlags {
                v6_default: true,
                best_v6_metric: Some(metric),
                ..GlobalRouteFlags::default()
            }
        }

        struct Case {
            name: &'static str,
            adapters: Vec<WindowsAdapter>,
            luid_routes: Vec<(u64, GlobalRouteFlags)>,
            index_routes: Vec<(u32, GlobalRouteFlags)>,
            self_tun: Option<&'static str>,
            expected: VpnScope,
        }

        let eth = adapter(
            "Ethernet",
            "Intel(R) Ethernet Controller I225-V",
            1,
            10,
            WIN_IF_TYPE_ETHERNET,
            25,
            25,
        );

        let cases = [
            Case {
                name: "mullvad v4 /0 beats physical ethernet metric",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (2, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Mullvad".to_string(),
                    iface: "Mullvad".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "wireguard /1 split-default always wins via LPM even with higher metric",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "wg0",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        500,
                        500,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (2, v4_split(100))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "WireGuard".to_string(),
                    iface: "wg0".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "standby high-metric /0 vpn route does NOT yield",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        200,
                        200,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (2, v4_default(50))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::SplitOverlay {
                    providers: vec!["Mullvad".to_string()],
                },
            },
            Case {
                name: "ipv4 adapter metric is never added to ipv6 route metric",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "WireGuard",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,   // low ipv4 adapter metric
                        200, // high ipv6 adapter metric -> eff v6 = 250 > phys 25
                    ),
                ],
                luid_routes: vec![(1, v6_default(0)), (2, v6_default(50))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::SplitOverlay {
                    providers: vec!["WireGuard".to_string()],
                },
            },
            Case {
                name: "ipv6 /0 wins when ipv6 effective metric beats physical even if ipv4 loses",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        500, // v4 eff = 510 > 25
                        5,   // v6 eff = 5 <= 25
                    ),
                ],
                luid_routes: vec![
                    (
                        1,
                        GlobalRouteFlags {
                            v4_default: true,
                            v6_default: true,
                            best_v4_metric: Some(0),
                            best_v6_metric: Some(0),
                            ..GlobalRouteFlags::default()
                        },
                    ),
                    (
                        2,
                        GlobalRouteFlags {
                            v4_default: true,
                            v6_default: true,
                            best_v4_metric: Some(10),
                            best_v6_metric: Some(0),
                            ..GlobalRouteFlags::default()
                        },
                    ),
                ],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Mullvad".to_string(),
                    iface: "Mullvad".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "tailscale split overlay without default route never yields",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Tailscale",
                        "Tailscale Tunnel",
                        3,
                        30,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::SplitOverlay {
                    providers: vec!["Tailscale".to_string()],
                },
            },
            Case {
                name: "tailscale exit node with lower-metric /0 yields as full tunnel",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Tailscale",
                        "Tailscale Tunnel",
                        3,
                        30,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (3, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Tailscale".to_string(),
                    iface: "Tailscale".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "vdpi0 self-exclusion ignores own wintun routes",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "vdpi0",
                        "Wintun Userspace Tunnel",
                        4,
                        40,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        0,
                        0,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (4, v4_split(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::None,
            },
            Case {
                name: "hyper-v, wsl, docker, vmware, teredo, isatap, 6to4, iphttps excluded",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "vEthernet (Default Switch)",
                        "Hyper-V Virtual Ethernet Adapter",
                        10,
                        100,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        1,
                        1,
                    ),
                    adapter(
                        "vEthernet (WSL)",
                        "Hyper-V Virtual Ethernet Adapter #2",
                        11,
                        101,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        1,
                        1,
                    ),
                    adapter(
                        "docker0",
                        "Docker Virtual Adapter",
                        12,
                        102,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        1,
                        1,
                    ),
                    adapter(
                        "VMware Network Adapter VMnet8",
                        "VMware Virtual Ethernet Adapter for VMnet8",
                        13,
                        103,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        1,
                        1,
                    ),
                    adapter(
                        "Teredo Tunneling Pseudo-Interface",
                        "Microsoft Teredo Tunneling Adapter",
                        14,
                        104,
                        WIN_IF_TYPE_TUNNEL,
                        1,
                        1,
                    ),
                    adapter(
                        "IPHTTPSInterface",
                        "Microsoft IP-HTTPS Platform Interface",
                        15,
                        105,
                        WIN_IF_TYPE_TUNNEL,
                        1,
                        1,
                    ),
                ],
                luid_routes: vec![
                    (1, v4_default(0)),
                    (10, v4_default(0)),
                    (11, v4_split(0)),
                    (12, v4_default(0)),
                    (13, v4_default(0)),
                    (14, v6_default(0)),
                    (15, v6_default(0)),
                ],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::None,
            },
            Case {
                name: "windows built-in WAN Miniport IKEv2 full tunnel",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Work VPN",
                        "WAN Miniport (IKEv2)",
                        20,
                        200,
                        WIN_IF_TYPE_PPP,
                        10,
                        10,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (20, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "IKEv2 VPN".to_string(),
                    iface: "Work VPN".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "unnamed virtual tunnel /0 beating physical NIC yields as VPN",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Corp Tunnel",
                        "Custom Virtual Tunnel Adapter",
                        21,
                        201,
                        WIN_IF_TYPE_TUNNEL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (21, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "VPN".to_string(),
                    iface: "Corp Tunnel".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "unnamed virtual tunnel /0 not beating physical NIC does not yield",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Standby Tunnel",
                        "Custom Virtual Tunnel Adapter",
                        22,
                        202,
                        WIN_IF_TYPE_TUNNEL,
                        50,
                        50,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (22, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::None,
            },
            Case {
                name: "kill-switch detected when physical NIC has no default route",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        2,
                        20,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(2, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Mullvad".to_string(),
                    iface: "Mullvad".to_string(),
                    kill_switch: true,
                },
            },
            Case {
                name: "fallback route lookup by if_index when luid is zero",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        0,
                        25,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0))],
                index_routes: vec![(25, v4_default(0))],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Mullvad".to_string(),
                    iface: "Mullvad".to_string(),
                    kill_switch: false,
                },
            },
            Case {
                name: "ipv6-only ::/0 on ipv4-only host does not false-positive as full tunnel",
                adapters: vec![
                    eth.clone(),
                    adapter(
                        "Tailscale",
                        "Tailscale Tunnel",
                        30,
                        300,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        50,
                        5,
                    ),
                ],
                luid_routes: vec![(1, v4_default(0)), (30, v6_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::SplitOverlay {
                    providers: vec!["Tailscale".to_string()],
                },
            },
            Case {
                name: "vm guest hyper-v nic falls back in pass 1 so standby vpn does not false-positive",
                adapters: vec![
                    adapter(
                        "Ethernet",
                        "Microsoft Hyper-V Network Adapter",
                        40,
                        400,
                        WIN_IF_TYPE_ETHERNET,
                        25,
                        25,
                    ),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        41,
                        401,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        200,
                        200,
                    ),
                ],
                luid_routes: vec![(40, v4_default(0)), (41, v4_default(50))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::SplitOverlay {
                    providers: vec!["Mullvad".to_string()],
                },
            },
            Case {
                name: "vm guest hyper-v nic still yields when active vpn beats its metric",
                adapters: vec![
                    adapter(
                        "Ethernet",
                        "Microsoft Hyper-V Network Adapter",
                        40,
                        400,
                        WIN_IF_TYPE_ETHERNET,
                        25,
                        25,
                    ),
                    adapter(
                        "Mullvad",
                        "WireGuard Tunnel",
                        41,
                        401,
                        WIN_IF_TYPE_PROP_VIRTUAL,
                        5,
                        5,
                    ),
                ],
                luid_routes: vec![(40, v4_default(0)), (41, v4_default(0))],
                index_routes: vec![],
                self_tun: Some("vdpi0"),
                expected: VpnScope::FullTunnel {
                    provider: "Mullvad".to_string(),
                    iface: "Mullvad".to_string(),
                    kill_switch: false,
                },
            },
        ];

        for case in cases {
            let luid_map: HashMap<u64, GlobalRouteFlags> = case.luid_routes.into_iter().collect();
            let index_map: HashMap<u32, GlobalRouteFlags> = case.index_routes.into_iter().collect();
            let actual =
                evaluate_windows_vpn_scope(&case.adapters, &luid_map, &index_map, case.self_tun);
            assert_eq!(actual, case.expected, "case failed: {}", case.name);
        }
    }

    #[test]
    fn macos_netstat_respects_first_unscoped_default_order_and_scutil_skips_overlays() {
        // Lower-priority `utun4` listed AFTER `en0` must NOT false-positive as FullTunnel.
        let inet_lower_prio = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            link#21            UCSg                utun4
";
        assert_eq!(
            parse_macos_netstat_routes(inet_lower_prio, "", Some("utun9")),
            VpnScope::None
        );

        // Self TUN (`utun9`) listed first, followed by `en0`, then standby `utun4` -> still None.
        let inet_self_first = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            link#29            UCSg                utun9
default            192.168.1.1        UGScg                 en0
default            link#21            UCSg                utun4
";
        assert_eq!(
            parse_macos_netstat_routes(inet_self_first, "", Some("utun9")),
            VpnScope::None
        );

        // Higher-priority `utun4` listed BEFORE `en0` IS a FullTunnel.
        let inet_higher_prio = "\
Internet:
Destination        Gateway            Flags               Netif Expire
default            link#21            UCSg                utun4
default            192.168.1.1        UGScg                 en0
";
        assert_eq!(
            parse_macos_netstat_routes(inet_higher_prio, "", Some("utun9")),
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "utun4".to_string(),
                kill_switch: false,
            }
        );

        // scutil --nc list with only Tailscale/ZeroTier connected must NOT mislabel
        // a non-Tailscale daemon VPN (like Mullvad) when is_tailscale_overlay == false.
        let scutil_overlay_only = "\
Available network connection services in the current set (*=enabled):
* (Connected)      11111111-2222-3333-4444-555555555555 VPN (io.tailscale.ipn.macos) \"Tailscale\" [VPN:io.tailscale.ipn.macos]
* (Connected)      66666666-7777-8888-9999-000000000000 VPN (com.zerotier.one) \"ZeroTier One\" [VPN:com.zerotier.one]
";
        assert_eq!(
            parse_macos_scutil_connected_service(scutil_overlay_only, false),
            None
        );
        assert_eq!(
            parse_macos_scutil_connected_service(scutil_overlay_only, true),
            Some("Tailscale".to_string())
        );

        // When both Tailscale and a real full-tunnel service are connected, skip Tailscale.
        let scutil_mixed = "\
* (Connected)      11111111-2222-3333-4444-555555555555 VPN (io.tailscale.ipn.macos) \"Tailscale\" [VPN:io.tailscale.ipn.macos]
* (Connected)      aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee VPN (net.mullvad.vpn) \"Mullvad VPN\" [VPN:net.mullvad.vpn]
";
        assert_eq!(
            parse_macos_scutil_connected_service(scutil_mixed, false),
            Some("Mullvad".to_string())
        );
    }

    #[test]
    fn linux_sysfs_kinds_self_rule_filter_scoped_rules_and_main_metric_comparison() {
        assert!(parse_linux_uevent_is_wireguard(
            "DEVTYPE=wireguard\nINTERFACE=se-sto-wg-001\nIFINDEX=14\n"
        ));
        assert!(!parse_linux_uevent_is_wireguard(
            "INTERFACE=eth0\nIFINDEX=2\n"
        ));

        // vdpi's own rules (5480/5485/5490/5500, fwmark 0x5644, lookup 202) and scoped
        // selectors (to/iif/oif/uidrange/ipproto/sport/dport) must be ignored.
        let rules_with_self_and_scoped = parse_linux_ip_rules(
            "0:\tfrom all lookup local\n\
             1000:\tfrom all to 10.0.0.0/8 lookup 100\n\
             1001:\tfrom all iif eth1 lookup 101\n\
             1002:\tfrom all oif eth1 lookup 102\n\
             1003:\tfrom all uidrange 1000-1000 lookup 103\n\
             1004:\tfrom all ipproto tcp lookup 104\n\
             1005:\tfrom all sport 443 lookup 105\n\
             1006:\tfrom all dport 53 lookup 106\n\
             1007:\tfrom all uidrange 1000-1000 blackhole\n\
             5480:\tfrom all fwmark 0x5644 lookup main\n\
             5485:\tfrom all fwmark 0x5644 unreachable\n\
             5490:\tfrom all lookup main suppress_prefixlength 0\n\
             5500:\tfrom all iif lo lookup 202\n\
             6000:\tfrom all fwmark 0x5644/0xffff lookup 202\n\
             32766:\tfrom all lookup main\n",
        );
        assert!(rules_with_self_and_scoped.custom_tables.is_empty());
        assert!(!rules_with_self_and_scoped.has_suppress_prefix_zero);
        assert!(!rules_with_self_and_scoped.has_fwmark_bypass_rule);
        assert!(!rules_with_self_and_scoped.has_global_kill_switch_rule);

        // Arbitrary-named WireGuard interface (`se-sto-wg-001`) detected via DEVTYPE=wireguard
        // on IPv6 policy table from combined `ip -4 rule show` + `ip -6 rule show`.
        let z = hex_ipv4_host_order([0, 0, 0, 0]);
        let gw_eth = hex_ipv4_host_order([192, 168, 1, 1]);
        let gw_vpn = hex_ipv4_host_order([10, 2, 0, 1]);
        let main_proc = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n"
        );
        let main_routes = parse_linux_proc_route(&main_proc);

        let wg_rules = parse_linux_ip_rules(
            "0:\tfrom all lookup local\n\
             5490:\tfrom all lookup main suppress_prefixlength 0\n\
             32764:\tfrom all lookup main suppress_prefixlength 0\n\
             32765:\tnot from all fwmark 0xca6c lookup 51820\n",
        );
        assert_eq!(wg_rules.custom_tables, vec!["51820".to_string()]);
        assert!(wg_rules.has_suppress_prefix_zero);
        assert!(wg_rules.has_fwmark_bypass_rule);

        let mut wg_policy = BTreeMap::new();
        parse_linux_ip_route_table("default dev se-sto-wg-001\n", true, &mut wg_policy);

        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("se-sto-wg-001", LinuxIfaceKind::WireGuard),
                ],
                &main_routes,
                &wg_policy,
                &wg_rules,
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "WireGuard".to_string(),
                iface: "se-sto-wg-001".to_string(),
                kill_switch: true,
            }
        );

        // Arbitrary-named TUN (`nl-free-01`) with lower-metric main `/0` beats eth0 (metric 100).
        let tun_wins_proc = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n\
             nl-free-01\t{z}\t{gw_vpn}\t0003\t0\t0\t50\t{z}\t0\t0\t0\n"
        );
        let tun_wins_routes = parse_linux_proc_route(&tun_wins_proc);
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("nl-free-01", LinuxIfaceKind::Tun),
                ],
                &tun_wins_routes,
                &BTreeMap::new(),
                &LinuxIpRuleSummary::default(),
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "VPN".to_string(),
                iface: "nl-free-01".to_string(),
                kill_switch: false,
            }
        );

        // Standby high-metric main `/0` VPN route (metric 500 > eth0 metric 100) must NOT yield.
        let standby_proc = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n\
             wg0\t{z}\t{gw_vpn}\t0003\t0\t0\t500\t{z}\t0\t0\t0\n"
        );
        let standby_routes = parse_linux_proc_route(&standby_proc);
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("wg0", LinuxIfaceKind::WireGuard),
                ],
                &standby_routes,
                &BTreeMap::new(),
                &LinuxIpRuleSummary::default(),
                Some("vdpi0"),
            ),
            VpnScope::SplitOverlay {
                providers: vec!["WireGuard".to_string()],
            }
        );
    }

    #[test]
    fn linux_amneziawg_iface_and_devtype_detection() {
        assert!(is_wireguard_iface_name("awg"));
        assert!(is_wireguard_iface_name("awg0"));
        assert!(is_wireguard_iface_name("awg-home"));
        assert!(is_wireguard_iface_name("awg_1"));
        assert!(!is_wireguard_iface_name("awdl0"));
        assert!(!is_wireguard_iface_name("awgn"));

        assert!(is_linux_generic_vpn_iface("awg0"));
        assert!(!is_linux_generic_vpn_iface("awdl0"));

        assert_eq!(classify_vpn_adapter_name("awg0", ""), Some("AmneziaVPN"));
        assert_eq!(
            classify_vpn_adapter_name("awg-home", ""),
            Some("AmneziaVPN")
        );
        assert_eq!(classify_vpn_adapter_name("awg", ""), Some("AmneziaVPN"));
        assert_eq!(classify_vpn_adapter_name("awdl0", ""), None);

        assert!(parse_linux_uevent_is_wireguard(
            "DEVTYPE=amneziawg\nINTERFACE=awg0\nIFINDEX=15\n"
        ));
        assert!(parse_linux_uevent_is_wireguard(
            "DEVTYPE=amneziawg\nINTERFACE=de-fra-01\nIFINDEX=16\n"
        ));

        let z = hex_ipv4_host_order([0, 0, 0, 0]);
        let gw_eth = hex_ipv4_host_order([192, 168, 1, 1]);
        let main_proc = format!(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
             eth0\t{z}\t{gw_eth}\t0003\t0\t0\t100\t{z}\t0\t0\t0\n"
        );
        let main_routes = parse_linux_proc_route(&main_proc);

        let awg_rules = parse_linux_ip_rules(
            "0:\tfrom all lookup local\n\
             32764:\tfrom all lookup main suppress_prefixlength 0\n\
             32765:\tnot from all fwmark 0xca6c lookup 51820\n",
        );

        // Named `awg0` with policy-table default route -> FullTunnel as AmneziaVPN.
        let mut awg_policy = BTreeMap::new();
        parse_linux_ip_route_table("default dev awg0\n", false, &mut awg_policy);
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("awg0", LinuxIfaceKind::WireGuard),
                ],
                &main_routes,
                &awg_policy,
                &awg_rules,
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "AmneziaVPN".to_string(),
                iface: "awg0".to_string(),
                kill_switch: true,
            }
        );

        // Active `awg0` without a winning global default route -> SplitOverlay as AmneziaVPN.
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("awg0", LinuxIfaceKind::WireGuard),
                ],
                &main_routes,
                &BTreeMap::new(),
                &LinuxIpRuleSummary::default(),
                Some("vdpi0"),
            ),
            VpnScope::SplitOverlay {
                providers: vec!["AmneziaVPN".to_string()],
            }
        );

        // Arbitrary-named interface classified via `DEVTYPE=amneziawg` -> FullTunnel as WireGuard.
        let mut custom_policy = BTreeMap::new();
        parse_linux_ip_route_table("default dev de-fra-01\n", false, &mut custom_policy);
        assert_eq!(
            evaluate_linux_vpn_scope(
                &[
                    LinuxUpIface::other("eth0"),
                    LinuxUpIface::with_kind("de-fra-01", LinuxIfaceKind::WireGuard),
                ],
                &main_routes,
                &custom_policy,
                &awg_rules,
                Some("vdpi0"),
            ),
            VpnScope::FullTunnel {
                provider: "WireGuard".to_string(),
                iface: "de-fra-01".to_string(),
                kill_switch: true,
            }
        );
    }

    #[test]
    fn linux_ip_bin_candidates_match_trusted_bin_prefixes() {
        assert_eq!(
            LINUX_IP_BIN_CANDIDATES,
            ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
        );
        let expected: Vec<String> = crate::platform::linux_tun::TRUSTED_BIN_PREFIXES
            .iter()
            .map(|prefix| format!("{prefix}/ip"))
            .collect();
        let actual: Vec<String> = LINUX_IP_BIN_CANDIDATES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(actual, expected);
    }
}
