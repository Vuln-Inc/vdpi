//! Windows Wintun + IP Helper API transparent TUN backend.
//!
//! Architecture & safety invariants:
//! - **Pinned supply chain**: `wintun.dll` (0.14.1, amd64/arm64) is resolved strictly from
//!   trusted on-disk locations (`current_exe()`, `fs::canonicalize(current_exe())`,
//!   `%ProgramFiles%\vdpi\bin`, or the runtime cache under `%ProgramData%\vdpi\runtime` /
//!   `%LOCALAPPDATA%\vdpi\runtime`) — or materialized into the hidden runtime cache from an
//!   embedded WHQL-signed payload compiled into `vdpi.exe` (never writing next to `vdpi.exe`
//!   and never searching CWD or `PATH`) — rejecting UNC paths, NTFS reparse points, and
//!   non-fixed drives, hardening `%ProgramData%\vdpi\runtime` with a restricted DACL, verifying
//!   against [`expected_wintun_dll_sha256`] while held open with `FILE_SHARE_READ`, and
//!   loading via `GetFinalPathNameByHandleW` + `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`
//!   pinned for process lifetime in a `OnceLock<Arc<WintunApi>>`.
//! - **Isolated routing & orphan recovery**: Zero routes or DNS entries are ever mutated on
//!   the physical NIC. All disjoint public IPv4 complement CIDRs (when an IPv4 uplink exists)
//!   and `2000::/3` + RFC 6052 NAT64 `64:ff9b::/96` (when IPv6 TUN is active) are installed
//!   exclusively on the `vdpi0` Wintun LUID. Clean teardown closes `vdpi0` and atomically removes
//!   its routes/DNS; if an abrupt termination (such as `TerminateProcess` or `taskkill /F`) leaves
//!   an orphaned `vdpi0` adapter behind, startup and [`cleanup_orphan_wintun_adapter`] close it
//!   via Wintun and remove lingering PnP device nodes via SetupAPI (`DIF_REMOVE`) to restore host
//!   connectivity.
//! - **Live uplink tracking**: `NotifyRouteChange2(AF_UNSPEC, ...)` and
//!   `NotifyUnicastIpAddressChange(AF_UNSPEC, ...)` trigger a debounced off-callback physical
//!   uplink re-detection that atomically updates [`DynamicOutboundBinder`], flushes the
//!   Windows DNS resolver cache on uplink switches, and notifies route-change watchers (such
//!   as `VpnGuard`). Sleep/wake events can also force immediate reconciliation via
//!   `WindowsTunSession::force_reconcile_uplink`.

#[cfg(any(target_os = "windows", test))]
use crate::update::sha256_hex;
use crate::update::{sha256_file, strip_windows_verbatim_prefix};
use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Optional WHQL-signed `wintun.dll` (`amd64`, v0.14.1) embedded directly into `vdpi.exe`
/// when built with `VDPI_EMBED_WINTUN_DLL` pointing at the verified DLL.
#[cfg(all(target_os = "windows", target_arch = "x86_64", vdpi_embedded_wintun))]
const EMBEDDED_WINTUN_DLL: &[u8] = include_bytes!(env!("VDPI_EMBEDDED_WINTUN_PATH"));

/// Pinned Wintun release version.
pub const WINTUN_VERSION: &str = "0.14.1";
/// Pinned SHA-256 of the upstream `wintun-0.14.1.zip` release archive.
pub const WINTUN_ZIP_SHA256: &str =
    "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
/// Pinned SHA-256 of `wintun/bin/amd64/wintun.dll` from Wintun 0.14.1.
pub const WINTUN_DLL_AMD64_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
/// Pinned SHA-256 of `wintun/bin/arm64/wintun.dll` from Wintun 0.14.1.
pub const WINTUN_DLL_ARM64_SHA256: &str =
    "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80";

/// Returns the pinned SHA-256 hex digest for the `wintun.dll` binary matching the current
/// CPU architecture (`x86_64` -> `amd64`, `aarch64` -> `arm64`).
pub fn expected_wintun_dll_sha256() -> Result<&'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(WINTUN_DLL_AMD64_SHA256)
    }
    #[cfg(target_arch = "aarch64")]
    {
        Ok(WINTUN_DLL_ARM64_SHA256)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        bail!(
            "unsupported CPU architecture '{}' for pinned wintun.dll v{WINTUN_VERSION}",
            std::env::consts::ARCH
        )
    }
}

/// Deterministic Wintun adapter name.
pub const VDPI_TUN_NAME: &str = "vdpi0";
/// IPv4 address assigned to the `vdpi0` Wintun interface (`/30`).
pub const VDPI_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// IPv4 prefix length assigned to `vdpi0`.
pub const VDPI_TUN_PREFIX_V4: u8 = 30;
/// Virtual IPv4 DNS server configured on `vdpi0` (intercepted by the userspace TUN stack).
pub const VDPI_TUN_DNS_V4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
/// IPv6 ULA address assigned to `vdpi0` when IPv6 TUN mode is active (`/126`).
pub const VDPI_TUN_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 1);
/// IPv6 prefix length assigned to `vdpi0`.
pub const VDPI_TUN_PREFIX_V6: u8 = 126;
/// Virtual IPv6 DNS server configured on `vdpi0` when IPv6 TUN mode is active
/// (intercepted by the userspace TUN stack).
pub const VDPI_TUN_DNS_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 2);
/// Link MTU configured on `vdpi0` (matches `vdpi_tun::config::DESKTOP_MTU`; Wintun 0.14.1
/// supports up to 65,535 bytes natively via `NlMtu`).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub const VDPI_TUN_MTU: u32 = vdpi_tun::config::DESKTOP_MTU as u32;
/// Link MTU configured on `vdpi0`.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub const VDPI_TUN_MTU: u32 = 16_384;

/// Windows NDIS `IF_TYPE_ETHERNET_CSMACD`.
pub const NDIS_IF_TYPE_ETHERNET: u32 = 6;
/// Windows NDIS `IF_TYPE_SOFTWARE_LOOPBACK`.
pub const NDIS_IF_TYPE_LOOPBACK: u32 = 24;
/// Windows NDIS `IF_TYPE_PROP_VIRTUAL`.
pub const NDIS_IF_TYPE_PROP_VIRTUAL: u32 = 53;
/// Windows NDIS `IF_TYPE_IEEE80211`.
pub const NDIS_IF_TYPE_WIFI: u32 = 71;
/// Windows NDIS `IF_TYPE_TUNNEL`.
pub const NDIS_IF_TYPE_TUNNEL: u32 = 131;

/// Non-routable / private / special-use IPv4 CIDRs intentionally excluded from `vdpi0`
/// so LAN, CGNAT, loopback, link-local, multicast, and reserved traffic always stays
/// on the host's native routing table.
pub const EXCLUDED_IPV4_CIDRS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),      // RFC 1122 "this network"
    (Ipv4Addr::new(10, 0, 0, 0), 8),     // RFC 1918 private
    (Ipv4Addr::new(100, 64, 0, 0), 10),  // RFC 6598 CGNAT
    (Ipv4Addr::new(127, 0, 0, 0), 8),    // RFC 1122 loopback
    (Ipv4Addr::new(169, 254, 0, 0), 16), // RFC 3927 link-local / APIPA
    (Ipv4Addr::new(172, 16, 0, 0), 12),  // RFC 1918 private
    (Ipv4Addr::new(192, 0, 0, 0), 24),   // RFC 6890 IETF protocol assignments (DS-Lite / NAT64)
    (Ipv4Addr::new(192, 168, 0, 0), 16), // RFC 1918 private
    (Ipv4Addr::new(224, 0, 0, 0), 4),    // RFC 5771 multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),    // RFC 1112 reserved + limited broadcast
];

/// Exact minimal binary-trie complement of `0.0.0.0/0` minus [`EXCLUDED_IPV4_CIDRS`].
///
/// Every entry is pairwise disjoint, has zero overlap with any excluded range, and the union
/// of `PUBLIC_IPV4_COMPLEMENT_CIDRS` and `EXCLUDED_IPV4_CIDRS` partitions all 2^32 IPv4
/// addresses exactly (`3,702,390,528 + 592,576,768 = 4,294,967,296`).
pub const PUBLIC_IPV4_COMPLEMENT_CIDRS: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(1, 0, 0, 0), 8),
    (Ipv4Addr::new(2, 0, 0, 0), 7),
    (Ipv4Addr::new(4, 0, 0, 0), 6),
    (Ipv4Addr::new(8, 0, 0, 0), 7),
    (Ipv4Addr::new(11, 0, 0, 0), 8),
    (Ipv4Addr::new(12, 0, 0, 0), 6),
    (Ipv4Addr::new(16, 0, 0, 0), 4),
    (Ipv4Addr::new(32, 0, 0, 0), 3),
    (Ipv4Addr::new(64, 0, 0, 0), 3),
    (Ipv4Addr::new(96, 0, 0, 0), 6),
    (Ipv4Addr::new(100, 0, 0, 0), 10),
    (Ipv4Addr::new(100, 128, 0, 0), 9),
    (Ipv4Addr::new(101, 0, 0, 0), 8),
    (Ipv4Addr::new(102, 0, 0, 0), 7),
    (Ipv4Addr::new(104, 0, 0, 0), 5),
    (Ipv4Addr::new(112, 0, 0, 0), 5),
    (Ipv4Addr::new(120, 0, 0, 0), 6),
    (Ipv4Addr::new(124, 0, 0, 0), 7),
    (Ipv4Addr::new(126, 0, 0, 0), 8),
    (Ipv4Addr::new(128, 0, 0, 0), 3),
    (Ipv4Addr::new(160, 0, 0, 0), 5),
    (Ipv4Addr::new(168, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 0, 0, 0), 9),
    (Ipv4Addr::new(169, 128, 0, 0), 10),
    (Ipv4Addr::new(169, 192, 0, 0), 11),
    (Ipv4Addr::new(169, 224, 0, 0), 12),
    (Ipv4Addr::new(169, 240, 0, 0), 13),
    (Ipv4Addr::new(169, 248, 0, 0), 14),
    (Ipv4Addr::new(169, 252, 0, 0), 15),
    (Ipv4Addr::new(169, 255, 0, 0), 16),
    (Ipv4Addr::new(170, 0, 0, 0), 7),
    (Ipv4Addr::new(172, 0, 0, 0), 12),
    (Ipv4Addr::new(172, 32, 0, 0), 11),
    (Ipv4Addr::new(172, 64, 0, 0), 10),
    (Ipv4Addr::new(172, 128, 0, 0), 9),
    (Ipv4Addr::new(173, 0, 0, 0), 8),
    (Ipv4Addr::new(174, 0, 0, 0), 7),
    (Ipv4Addr::new(176, 0, 0, 0), 4),
    (Ipv4Addr::new(192, 0, 1, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 23),
    (Ipv4Addr::new(192, 0, 4, 0), 22),
    (Ipv4Addr::new(192, 0, 8, 0), 21),
    (Ipv4Addr::new(192, 0, 16, 0), 20),
    (Ipv4Addr::new(192, 0, 32, 0), 19),
    (Ipv4Addr::new(192, 0, 64, 0), 18),
    (Ipv4Addr::new(192, 0, 128, 0), 17),
    (Ipv4Addr::new(192, 1, 0, 0), 16),
    (Ipv4Addr::new(192, 2, 0, 0), 15),
    (Ipv4Addr::new(192, 4, 0, 0), 14),
    (Ipv4Addr::new(192, 8, 0, 0), 13),
    (Ipv4Addr::new(192, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 32, 0, 0), 11),
    (Ipv4Addr::new(192, 64, 0, 0), 10),
    (Ipv4Addr::new(192, 128, 0, 0), 11),
    (Ipv4Addr::new(192, 160, 0, 0), 13),
    (Ipv4Addr::new(192, 169, 0, 0), 16),
    (Ipv4Addr::new(192, 170, 0, 0), 15),
    (Ipv4Addr::new(192, 172, 0, 0), 14),
    (Ipv4Addr::new(192, 176, 0, 0), 12),
    (Ipv4Addr::new(192, 192, 0, 0), 10),
    (Ipv4Addr::new(193, 0, 0, 0), 8),
    (Ipv4Addr::new(194, 0, 0, 0), 7),
    (Ipv4Addr::new(196, 0, 0, 0), 6),
    (Ipv4Addr::new(200, 0, 0, 0), 5),
    (Ipv4Addr::new(208, 0, 0, 0), 4),
];

/// Returns `true` if `ip` belongs to the IPv4 CIDR `(network, prefix_len)`.
#[inline]
pub fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0u32
    } else if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

/// Returns `true` if `ip` is covered by [`PUBLIC_IPV4_COMPLEMENT_CIDRS`].
#[inline]
pub fn is_routed_public_ipv4(ip: Ipv4Addr) -> bool {
    PUBLIC_IPV4_COMPLEMENT_CIDRS
        .iter()
        .any(|&(net, prefix)| ipv4_in_cidr(ip, net, prefix))
}

/// Candidate default-route network interface evaluated by [`rank_physical_uplink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkCandidate {
    /// Windows `NET_LUID.Value`.
    pub luid: u64,
    /// Windows `NET_IFINDEX` used with `IP_UNICAST_IF` / `IPV6_UNICAST_IF`.
    pub if_index: u32,
    /// Human-readable adapter alias (e.g. `"Ethernet"`, `"Wi-Fi"`).
    pub alias: String,
    /// Driver / hardware description (e.g. `"Intel(R) Wi-Fi 6E AX211"`).
    pub description: String,
    /// NDIS interface type (`IF_TYPE_*`).
    pub if_type: u32,
    /// `true` when `OperStatus == IfOperStatusUp`.
    pub is_up: bool,
    /// Route metric from `MIB_IPFORWARD_ROW2.Metric`.
    pub route_metric: u32,
    /// Interface metric from `MIB_IPINTERFACE_ROW.Metric`.
    pub iface_metric: u32,
    /// `true` when the interface has at least one usable unicast IP for the address family.
    pub has_unicast_ip: bool,
}

impl UplinkCandidate {
    /// Effective Windows route priority (`route.Metric + iface.Metric`, saturating).
    #[inline]
    pub fn combined_metric(&self) -> u32 {
        self.route_metric.saturating_add(self.iface_metric)
    }
}

/// Lowercase substrings identifying virtual, VPN, loopback, or internal hypervisor adapters
/// that must never be selected as the physical outbound uplink.
const VIRTUAL_ADAPTER_TOKENS: &[&str] = &[
    "vdpi",
    "wintun",
    "wireguard",
    "tailscale",
    "zerotier",
    "tap-windows",
    "tap-nordvpn",
    "openvpn",
    "nordlynx",
    "protonvpn",
    "mullvad",
    "cloudflare warp",
    "warp",
    "sing-box",
    "mihomo",
    "tun2socks",
    "anyconnect",
    "fortinet",
    "globalprotect",
    "palo alto",
    "pulse secure",
    "juniper",
    "wan miniport",
    "teredo",
    "isatap",
    "6to4",
    "loopback",
    "wsl",
    "default switch",
    "host-only",
    "vmware",
    "virtualbox",
    "vboxnet",
    "docker",
    "qemu",
    "parallels",
    "npcap",
    "microsoft wi-fi direct",
    "microsoft kernel debug",
];

/// Lowercase substrings identifying internal Hyper-V virtual switches that must be
/// excluded even when falling back to Hyper-V External Virtual Switches (`vEthernet (...)`).
const HYPERV_INTERNAL_SWITCH_TOKENS: &[&str] = &[
    "wsl",
    "default switch",
    "docker",
    "host-only",
];

/// Lowercase word-boundary tokens identifying NAT Hyper-V virtual switches (matched with
/// non-alphanumeric boundaries so names such as `External Native` or `International` are
/// never falsely excluded).
const HYPERV_INTERNAL_SWITCH_WORDS: &[&str] = &["nat"];

/// Returns `true` if `needle` appears in `haystack` bounded on both sides by start/end of
/// string or non-alphanumeric characters (case-sensitive; callers pass lowercase).
fn contains_ascii_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut start = 0;
    while let Some(rel) = haystack[start..].find(needle) {
        let idx = start + rel;
        let end = idx + needle.len();
        let left_ok = match haystack[..idx].chars().next_back() {
            Some(c) => !c.is_alphanumeric(),
            None => true,
        };
        let right_ok = match haystack[end..].chars().next() {
            Some(c) => !c.is_alphanumeric(),
            None => true,
        };
        if left_ok && right_ok {
            return true;
        }
        start = idx + needle.chars().next().map_or(1, char::len_utf8);
    }
    false
}

#[inline]
fn is_hyperv_vethernet_lower(alias_lower: &str, desc_lower: &str) -> bool {
    alias_lower.contains("vethernet") || desc_lower.contains("hyper-v")
}

#[inline]
fn is_hyperv_vethernet(alias: &str, description: &str) -> bool {
    is_hyperv_vethernet_lower(&alias.to_ascii_lowercase(), &description.to_ascii_lowercase())
}

/// Returns `true` when an adapter is loopback, tunnel, proprietary virtual, or matches
/// known VPN/hypervisor/internal-switch/virtual NIC naming patterns.
///
/// Non-internal Hyper-V External Virtual Switches (e.g. `vEthernet (External)`) are NOT
/// rejected here so [`rank_physical_uplink`] can use them as a fallback when no bare
/// physical NIC holds a default route.
pub fn is_virtual_or_excluded_adapter(if_type: u32, alias: &str, description: &str) -> bool {
    if matches!(
        if_type,
        NDIS_IF_TYPE_LOOPBACK | NDIS_IF_TYPE_TUNNEL | NDIS_IF_TYPE_PROP_VIRTUAL
    ) {
        return true;
    }

    let alias_lower = alias.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    if VIRTUAL_ADAPTER_TOKENS
        .iter()
        .any(|tok| alias_lower.contains(tok) || desc_lower.contains(tok))
    {
        return true;
    }

    is_hyperv_vethernet_lower(&alias_lower, &desc_lower)
        && (HYPERV_INTERNAL_SWITCH_TOKENS
            .iter()
            .any(|tok| alias_lower.contains(tok) || desc_lower.contains(tok))
            || HYPERV_INTERNAL_SWITCH_WORDS.iter().any(|word| {
                contains_ascii_word(&alias_lower, word) || contains_ascii_word(&desc_lower, word)
            }))
}

/// Selects the highest-priority physical uplink from `candidates`.
///
/// Filters out `vdpi_luid`, zero LUID/index entries, non-operational interfaces, interfaces
/// without a usable unicast IP, and virtual/VPN/loopback/internal-switch adapters. Prefers
/// bare physical NICs first (lowest `route_metric + iface_metric`, breaking ties by
/// `if_index`, then `luid`), and falls back to non-internal Hyper-V External Virtual
/// Switches (`vEthernet (External)`) only when no bare physical NIC has a default route.
pub fn rank_physical_uplink(
    candidates: &[UplinkCandidate],
    vdpi_luid: u64,
) -> Option<&UplinkCandidate> {
    let is_eligible = |c: &&UplinkCandidate| {
        c.luid != 0
            && c.luid != vdpi_luid
            && c.if_index != 0
            && c.is_up
            && c.has_unicast_ip
            && !is_virtual_or_excluded_adapter(c.if_type, &c.alias, &c.description)
    };

    if let Some(physical) = candidates
        .iter()
        .filter(|c| is_eligible(c) && !is_hyperv_vethernet(&c.alias, &c.description))
        .min_by_key(|c| (c.combined_metric(), c.if_index, c.luid))
    {
        return Some(physical);
    }

    candidates
        .iter()
        .filter(|c| is_eligible(c) && is_hyperv_vethernet(&c.alias, &c.description))
        .min_by_key(|c| (c.combined_metric(), c.if_index, c.luid))
}

fn push_unique_path(out: &mut Vec<PathBuf>, candidate: PathBuf) {
    let dup = out.iter().any(|existing| {
        existing == &candidate
            || (cfg!(windows)
                && existing
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&candidate.to_string_lossy()))
    });
    if !dup {
        out.push(candidate);
    }
}

fn runtime_wintun_dll_filename() -> String {
    format!("wintun-{WINTUN_VERSION}.dll")
}

/// Returns ordered, deduplicated absolute candidate paths for `wintun.dll` located strictly
/// beside `exe_path` and (when distinct, e.g. WinGet symlink shims) beside `canonical_exe_path`.
///
/// Rejects UNC paths (`\\server\share`, `//server/share`, `\\?\UNC\...`), Win32 device
/// namespace paths (`\\.\...`), and non-drive verbatim paths before any filesystem probing.
/// Never searches CWD or `PATH`.
pub fn resolve_wintun_dll_candidates(
    exe_path: &Path,
    canonical_exe_path: Option<&Path>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::with_capacity(2);

    let push_dir = |out: &mut Vec<PathBuf>, candidate_exe: &Path| {
        if is_unc_or_device_path(candidate_exe) {
            return;
        }
        let cleaned = strip_windows_verbatim_prefix(candidate_exe);
        if is_unc_or_device_path(&cleaned) {
            return;
        }
        let Some(dir) = cleaned.parent() else {
            return;
        };
        if dir.as_os_str().is_empty() || is_unc_or_device_path(dir) {
            return;
        }
        push_unique_path(out, dir.join("wintun.dll"));
    };

    push_dir(&mut out, exe_path);
    if let Some(canon) = canonical_exe_path {
        push_dir(&mut out, canon);
    }

    out
}

/// Returns `true` if `path` is a UNC path (standard `\\server\share`, forward-slash
/// `//server/share`, or verbatim `\\?\UNC\server\share`, case-insensitive), Win32 device
/// namespace (`\\.\...`), or a non-drive verbatim path (such as `\\?\Volume{...}\...`).
fn is_unc_or_device_path(path: &Path) -> bool {
    let raw = path.to_string_lossy();
    let bytes = raw.as_bytes();
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        let rb = rest.as_bytes();
        if rb.len() >= 4
            && rest[..3].eq_ignore_ascii_case("UNC")
            && matches!(rb[3], b'\\' | b'/')
        {
            return true;
        }
        let is_drive = rb.len() >= 3
            && rb[0].is_ascii_alphabetic()
            && rb[1] == b':'
            && matches!(rb[2], b'\\' | b'/');
        return !is_drive;
    }
    if raw.starts_with(r"\\.\") || raw.starts_with("//./") {
        return true;
    }
    bytes.len() >= 2 && matches!(bytes[0], b'\\' | b'/') && matches!(bytes[1], b'\\' | b'/')
}

/// Extracts the Win32 drive root (e.g. `"C:\\"`) from a local path (with or without `\\?\`
/// prefix), returning `None` for UNC paths, device paths, or relative paths.
#[cfg(any(target_os = "windows", test))]
fn extract_local_drive_root(path: &Path) -> Option<String> {
    if is_unc_or_device_path(path) {
        return None;
    }
    let stripped = strip_windows_verbatim_prefix(path);
    let raw = stripped.to_str()?;
    let bytes = raw.as_bytes();
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
    {
        let drive = (bytes[0] as char).to_ascii_uppercase();
        Some(format!("{drive}:\\"))
    } else {
        None
    }
}

/// Win32 `ERROR_ALREADY_EXISTS` (183).
#[cfg(any(target_os = "windows", test))]
const WIN32_ERROR_ALREADY_EXISTS: u32 = 183;
/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)` (`0x8007_00B7`).
#[cfg(any(target_os = "windows", test))]
const HRESULT_ERROR_ALREADY_EXISTS: u32 = 0x8007_00B7;
/// Win32 `ERROR_DEVICE_NOT_AVAILABLE` (4319).
#[cfg(any(target_os = "windows", test))]
const WIN32_ERROR_DEVICE_NOT_AVAILABLE: u32 = 4319;

/// Returns `true` when a `WintunCreateAdapter` error code indicates a stale/tearing-down
/// `vdpi0` adapter that should be cleaned up via SetupAPI and retried.
#[cfg(any(target_os = "windows", test))]
#[inline]
fn is_retryable_adapter_create_error(err: u32) -> bool {
    matches!(
        err,
        WIN32_ERROR_ALREADY_EXISTS
            | HRESULT_ERROR_ALREADY_EXISTS
            | WIN32_ERROR_DEVICE_NOT_AVAILABLE
    )
}

/// Deterministic string form of `VDPI_WINTUN_GUID` (`NetCfgInstanceId` in Windows registry).
#[cfg(any(target_os = "windows", test))]
const VDPI_WINTUN_GUID_STR: &str = "{76647069-5769-6e74-756e-563035300001}";

/// Returns `true` when SetupAPI device properties identify an orphaned `vdpi0` Wintun device
/// node (never matching third-party Wintun adapters such as WireGuard, Tailscale, or Mullvad,
/// nor physical NICs).
#[cfg(any(target_os = "windows", test))]
fn is_orphan_vdpi_wintun_device(
    hardware_ids: &[String],
    device_desc: Option<&str>,
    friendly_name: Option<&str>,
    net_cfg_instance_id: Option<&str>,
) -> bool {
    if net_cfg_instance_id
        .is_some_and(|id| id.trim().eq_ignore_ascii_case(VDPI_WINTUN_GUID_STR))
    {
        return true;
    }

    let is_wintun = hardware_ids
        .iter()
        .any(|id| id.to_ascii_lowercase().contains("wintun"))
        || device_desc.is_some_and(|s| s.to_ascii_lowercase().contains("wintun"))
        || friendly_name.is_some_and(|s| s.to_ascii_lowercase().contains("wintun"));
    if !is_wintun {
        return false;
    }

    let matches_vdpi_label = |label: &str| {
        let lower = label.to_ascii_lowercase();
        contains_ascii_word(&lower, VDPI_TUN_NAME) || contains_ascii_word(&lower, "vdpi")
    };
    friendly_name.is_some_and(matches_vdpi_label) || device_desc.is_some_and(matches_vdpi_label)
}

/// Returns `true` when `token` parses as either of vdpi's virtual TUN DNS addresses
/// (`198.18.0.2` or `fd00:7664:7069::2`, matching canonical and expanded IPv6 forms).
#[cfg(any(target_os = "windows", test))]
fn is_vdpi_dns_ip(token: &str) -> bool {
    match token.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip == VDPI_TUN_DNS_V4,
        Ok(std::net::IpAddr::V6(ip)) => ip == VDPI_TUN_DNS_V6,
        Err(_) => false,
    }
}

/// Strips vdpi's virtual TUN DNS IPs (`198.18.0.2`, `fd00:7664:7069::2`) from a Windows
/// `Tcpip`/`Tcpip6` `NameServer` registry string (comma- or whitespace-delimited).
///
/// Returns `Some(cleaned)` only when at least one vdpi DNS IP was present and removed
/// (`Some(String::new())` when no other DNS servers remain), or `None` if `raw` does not
/// reference any vdpi DNS IP.
#[cfg(any(target_os = "windows", test))]
fn strip_vdpi_dns_servers(raw: &str) -> Option<String> {
    let mut removed_any = false;
    let mut kept: Vec<&str> = Vec::new();
    for token in raw.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        if token.is_empty() {
            continue;
        }
        if is_vdpi_dns_ip(token) {
            removed_any = true;
        } else {
            kept.push(token);
        }
    }
    if !removed_any {
        return None;
    }
    let sep = if raw.contains(',') { "," } else { " " };
    Some(kept.join(sep))
}

/// Returns ordered, deduplicated hidden runtime-cache paths used to store or materialize the
/// pinned `wintun.dll` (`%ProgramData%\vdpi\runtime\wintun-0.14.1.dll`, then
/// `%LOCALAPPDATA%\vdpi\runtime\wintun-0.14.1.dll`, then `<temp>\vdpi-runtime\wintun-0.14.1.dll`).
///
/// Never includes the directory containing `vdpi.exe` and rejects UNC/device roots.
fn resolve_runtime_wintun_cache_targets(
    program_data: Option<&Path>,
    local_app_data: Option<&Path>,
    temp_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let filename = runtime_wintun_dll_filename();
    let mut out: Vec<PathBuf> = Vec::with_capacity(3);

    for root in [program_data, local_app_data].into_iter().flatten() {
        if is_unc_or_device_path(root) {
            continue;
        }
        let cleaned = strip_windows_verbatim_prefix(root);
        if !cleaned.as_os_str().is_empty() && !is_unc_or_device_path(&cleaned) {
            push_unique_path(
                &mut out,
                cleaned.join("vdpi").join("runtime").join(&filename),
            );
        }
    }

    if let Some(tmp) = temp_dir {
        if !is_unc_or_device_path(tmp) {
            let cleaned = strip_windows_verbatim_prefix(tmp);
            if !cleaned.as_os_str().is_empty() && !is_unc_or_device_path(&cleaned) {
                push_unique_path(&mut out, cleaned.join("vdpi-runtime").join(&filename));
            }
        }
    }

    out
}

/// Returns `(primary_candidates, cache_candidates)` for resolving `wintun.dll` on disk:
/// - `primary_candidates`: beside `exe_path`, beside `canonical_exe_path`, and
///   `%ProgramFiles%\vdpi\bin\wintun.dll` (a SHA-256 mismatch in any primary location is fatal).
/// - `cache_candidates`: hidden runtime cache locations (`%ProgramData%\vdpi\runtime`,
///   `%LOCALAPPDATA%\vdpi\runtime`, and `<temp>\vdpi-runtime`).
fn resolve_all_wintun_dll_candidates(
    exe_path: &Path,
    canonical_exe_path: Option<&Path>,
    program_files: Option<&Path>,
    program_data: Option<&Path>,
    local_app_data: Option<&Path>,
    temp_dir: Option<&Path>,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut primary = resolve_wintun_dll_candidates(exe_path, canonical_exe_path);
    if let Some(pf) = program_files {
        if !is_unc_or_device_path(pf) {
            let cleaned = strip_windows_verbatim_prefix(pf);
            if !cleaned.as_os_str().is_empty() && !is_unc_or_device_path(&cleaned) {
                push_unique_path(
                    &mut primary,
                    cleaned.join("vdpi").join("bin").join("wintun.dll"),
                );
            }
        }
    }

    let cache = resolve_runtime_wintun_cache_targets(program_data, local_app_data, temp_dir);
    (primary, cache)
}

/// Verifies that the file at `path` matches `expected_sha256` (case-insensitive lowercase hex).
pub fn verify_wintun_dll_sha256(path: &Path, expected_sha256: &str) -> Result<()> {
    let actual = sha256_file(path)
        .with_context(|| format!("failed to compute SHA-256 of {}", path.display()))?;
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        bail!(
            "wintun.dll SHA-256 verification failed for {}: expected {expected_sha256}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

/// Returns `true` if `ip` is in the IPv6 Global Unicast range (`2000::/3`).
#[inline]
pub fn is_ipv6_global_unicast(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xe000) == 0x2000
}

/// Returns `true` when IPv6 should be configured on `vdpi0`: either explicitly requested
/// with an active global-unicast IPv6 uplink, or automatically on an IPv6-only uplink
/// (`!has_v4_uplink && has_v6_uplink`).
#[cfg(any(target_os = "windows", test))]
#[inline]
fn should_enable_tun_ipv6(tun_ipv6: bool, has_v4_uplink: bool, has_v6_uplink: bool) -> bool {
    has_v6_uplink && (tun_ipv6 || !has_v4_uplink)
}

/// Tracks which address families' routes/addresses/DNS are currently installed on `vdpi0`.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunStackState {
    /// Whether `PUBLIC_IPV4_COMPLEMENT_CIDRS` are currently installed on `vdpi0`.
    ipv4_routes_installed: bool,
    /// Whether IPv6 (`VDPI_TUN_IPV6`, `VDPI_TUN_DNS_V6`, `2000::/3`, `64:ff9b::/96`) is currently
    /// active on `vdpi0`.
    ipv6_active: bool,
}

/// Concrete delta of `vdpi0` route/address/DNS mutations required when the active physical
/// uplink transitions between IPv4-only, dual-stack, IPv6-only, or offline states.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunRoamingPlan {
    /// Add all `PUBLIC_IPV4_COMPLEMENT_CIDRS` to `vdpi0`.
    add_ipv4_routes: bool,
    /// Remove all `PUBLIC_IPV4_COMPLEMENT_CIDRS` from `vdpi0`.
    remove_ipv4_routes: bool,
    /// Configure `VDPI_TUN_IPV6`, IPv6 interface MTU/metric, `VDPI_TUN_DNS_V6`, `2000::/3`, and
    /// RFC 6052 NAT64 `64:ff9b::/96`.
    enable_ipv6: bool,
    /// Remove `2000::/3` + `64:ff9b::/96`, clear IPv6 DNS (`VDPI_TUN_DNS_V6`), and delete
    /// `VDPI_TUN_IPV6`.
    disable_ipv6: bool,
    /// Expected post-transition state once all mutations succeed.
    next_state: TunStackState,
}

#[cfg(any(target_os = "windows", test))]
impl TunRoamingPlan {
    #[inline]
    fn has_changes(&self) -> bool {
        self.add_ipv4_routes || self.remove_ipv4_routes || self.enable_ipv6 || self.disable_ipv6
    }
}

/// Computes the minimal `vdpi0` IPv4/IPv6 roaming delta for a physical uplink change.
///
/// During transient offline/handoff windows (`!has_v4_uplink && !has_v6_uplink`), preserves
/// `current` unchanged to avoid route-table thrashing while fail-closed outbound binding
/// prevents leaks until an uplink returns.
#[cfg(any(target_os = "windows", test))]
fn plan_tun_roaming_transition(
    current: TunStackState,
    tun_ipv6: bool,
    has_v4_uplink: bool,
    has_v6_uplink: bool,
) -> TunRoamingPlan {
    if !has_v4_uplink && !has_v6_uplink {
        return TunRoamingPlan {
            add_ipv4_routes: false,
            remove_ipv4_routes: false,
            enable_ipv6: false,
            disable_ipv6: false,
            next_state: current,
        };
    }

    let want_v4_routes = has_v4_uplink;
    let want_v6_active = should_enable_tun_ipv6(tun_ipv6, has_v4_uplink, has_v6_uplink);
    let next_state = TunStackState {
        ipv4_routes_installed: want_v4_routes,
        ipv6_active: want_v6_active,
    };

    TunRoamingPlan {
        add_ipv4_routes: want_v4_routes && !current.ipv4_routes_installed,
        remove_ipv4_routes: !want_v4_routes && current.ipv4_routes_installed,
        enable_ipv6: want_v6_active && !current.ipv6_active,
        disable_ipv6: !want_v6_active && current.ipv6_active,
        next_state,
    }
}

/// Strips a `\\?\` verbatim prefix only when the resulting path stays within 240 UTF-16 code
/// units (safely under Win32 `MAX_PATH = 260`), preserving `\\?\` for long paths.
#[cfg(any(target_os = "windows", test))]
fn normalize_load_library_path(path: &Path) -> PathBuf {
    let stripped = strip_windows_verbatim_prefix(path);
    if stripped.to_string_lossy().encode_utf16().count() <= 240 {
        stripped
    } else {
        path.to_path_buf()
    }
}

#[cfg(any(target_os = "windows", test))]
fn atomic_write_verified_wintun_dll(
    target: &Path,
    bytes: &[u8],
    expected_sha256: &str,
    is_program_data: bool,
) -> Result<()> {
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("runtime cache path has no parent: {}", target.display()))?;

    #[cfg(target_os = "windows")]
    win32::prepare_runtime_cache_dir(parent, target, is_program_data)?;

    #[cfg(not(target_os = "windows"))]
    {
        let _ = is_program_data;
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create wintun runtime directory {}",
                parent.display()
            )
        })?;
    }

    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wintun.dll");
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!("{file_name}.tmp.{pid}.{seq}"));

    let write_res = (|| -> Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(win32::FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut tmp_file = opts
            .open(&tmp_path)
            .with_context(|| format!("failed to create staging file {}", tmp_path.display()))?;
        #[cfg(target_os = "windows")]
        win32::verify_open_handle_not_reparse_point(&tmp_file, &tmp_path, false)?;
        tmp_file
            .write_all(bytes)
            .with_context(|| format!("failed to write staging file {}", tmp_path.display()))?;
        tmp_file
            .sync_all()
            .with_context(|| format!("failed to sync staging file {}", tmp_path.display()))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    #[cfg(target_os = "windows")]
    if let Err(err) = win32::reject_reparse_point_before_rename(target) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(rename_err) = std::fs::rename(&tmp_path, target) {
        let _ = std::fs::remove_file(&tmp_path);
        // Another concurrent vdpi instance may have already materialized and loaded the exact
        // verified DLL at `target` (holding a loaded image mapping that blocks replacement).
        #[cfg(target_os = "windows")]
        win32::reject_reparse_point_before_rename(target)?;
        if target.is_file() && verify_wintun_dll_sha256(target, expected_sha256).is_ok() {
            return Ok(());
        }
        return Err(rename_err).with_context(|| {
            format!(
                "failed to atomically install wintun.dll into {}",
                target.display()
            )
        });
    }

    verify_wintun_dll_sha256(target, expected_sha256)?;
    Ok(())
}

/// Verifies `embedded_bytes` against `expected_sha256` and atomically writes it into the first
/// writable hidden runtime cache destination in `targets`.
///
/// Never writes into the directory containing `vdpi.exe`.
#[cfg(any(target_os = "windows", test))]
fn extract_verified_embedded_wintun_dll(
    embedded_bytes: &[u8],
    expected_sha256: &str,
    targets: &[PathBuf],
    program_data_vdpi_dir: Option<&Path>,
) -> Result<PathBuf> {
    let actual = sha256_hex(embedded_bytes);
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        bail!(
            "embedded wintun.dll SHA-256 verification failed: expected {expected_sha256}, got {actual}"
        );
    }

    let mut errors: Vec<String> = Vec::new();
    for target in targets {
        let is_program_data = program_data_vdpi_dir.is_some_and(|pd| target.starts_with(pd));
        match atomic_write_verified_wintun_dll(
            target,
            embedded_bytes,
            expected_sha256,
            is_program_data,
        ) {
            Ok(()) => return Ok(target.clone()),
            Err(err) => errors.push(format!("{}: {err:#}", target.display())),
        }
    }

    bail!(
        "failed to materialize embedded wintun.dll into any runtime cache directory ({})",
        errors.join("; ")
    )
}

fn env_non_empty_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

#[allow(clippy::too_many_arguments)]
fn resolve_or_materialize_wintun_dll(
    exe: &Path,
    canonical_exe: Option<&Path>,
    program_files: Option<&Path>,
    program_data: Option<&Path>,
    local_app_data: Option<&Path>,
    temp_dir: Option<&Path>,
    expected_sha256: &str,
    embedded_bytes: Option<&[u8]>,
) -> Result<PathBuf> {
    let (primary_candidates, cache_candidates) = resolve_all_wintun_dll_candidates(
        exe,
        canonical_exe,
        program_files,
        program_data,
        local_app_data,
        temp_dir,
    );
    let program_data_vdpi_dir = program_data
        .filter(|p| !is_unc_or_device_path(p))
        .map(strip_windows_verbatim_prefix)
        .filter(|p| !p.as_os_str().is_empty() && !is_unc_or_device_path(p))
        .map(|p| p.join("vdpi"));

    // 1. Check explicit installation / sibling locations first. A tampered DLL or local NTFS
    //    reparse point / symlink here is always fatal (checked via `GetFileAttributesW` BEFORE
    //    `.is_file()` or hashing so a local symlink to a UNC share cannot leak Net-NTLMv2).
    for cand in &primary_candidates {
        if is_unc_or_device_path(cand) {
            continue;
        }
        #[cfg(target_os = "windows")]
        let exists_regular_file = win32::probe_existing_regular_file_no_reparse(cand, false)?;
        #[cfg(not(target_os = "windows"))]
        let exists_regular_file = cand.is_file();

        if exists_regular_file {
            verify_wintun_dll_sha256(cand, expected_sha256)?;
            return Ok(cand.clone());
        }
    }

    // 2. Check existing hidden runtime cache copies. Reject NTFS reparse points / junctions via
    //    `GetFileAttributesW` BEFORE calling `.is_file()` or hashing so a local symlink to a UNC
    //    share cannot leak Net-NTLMv2; if embedded bytes are compiled in and a cached copy was
    //    truncated or corrupted, allow embedded extraction to self-heal it.
    let mut first_cache_hash_err: Option<anyhow::Error> = None;
    for cand in &cache_candidates {
        if is_unc_or_device_path(cand) {
            continue;
        }
        #[cfg(target_os = "windows")]
        let exists_regular_file = match win32::probe_existing_regular_file_no_reparse(cand, true) {
            Ok(found) => found,
            Err(err) => {
                if first_cache_hash_err.is_none() {
                    first_cache_hash_err = Some(err);
                }
                continue;
            }
        };
        #[cfg(not(target_os = "windows"))]
        let exists_regular_file = cand.is_file();

        if exists_regular_file {
            #[cfg(target_os = "windows")]
            {
                let is_program_data = program_data_vdpi_dir
                    .as_deref()
                    .is_some_and(|pd| cand.starts_with(pd));
                if let Err(err) = win32::ensure_runtime_cache_path_safe(cand, is_program_data) {
                    if first_cache_hash_err.is_none() {
                        first_cache_hash_err = Some(err);
                    }
                    continue;
                }
            }
            match verify_wintun_dll_sha256(cand, expected_sha256) {
                Ok(()) => return Ok(cand.clone()),
                Err(err) => {
                    if first_cache_hash_err.is_none() {
                        first_cache_hash_err = Some(err);
                    }
                }
            }
        }
    }

    // 3. Materialize the verified embedded DLL strictly into the hidden runtime cache
    //    (%ProgramData%\vdpi\runtime -> %LOCALAPPDATA%\vdpi\runtime -> <temp>\vdpi-runtime),
    //    never beside vdpi.exe.
    #[cfg(any(target_os = "windows", test))]
    if let Some(bytes) = embedded_bytes {
        return extract_verified_embedded_wintun_dll(
            bytes,
            expected_sha256,
            &cache_candidates,
            program_data_vdpi_dir.as_deref(),
        );
    }
    #[cfg(not(any(target_os = "windows", test)))]
    let _ = (&program_data_vdpi_dir, embedded_bytes);

    if let Some(err) = first_cache_hash_err {
        return Err(err);
    }

    let checked = primary_candidates
        .iter()
        .chain(cache_candidates.iter())
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let arch_label = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    bail!(
        "wintun.dll (v{WINTUN_VERSION}) not found beside vdpi executable or runtime cache \
         (checked: {checked}); place the verified {arch_label} wintun.dll next to vdpi.exe"
    )
}

/// Locates `wintun.dll` from trusted on-disk locations (beside `vdpi.exe`, its canonical symlink
/// target, `%ProgramFiles%\vdpi\bin`, or the hidden runtime cache) and verifies its SHA-256
/// digest against [`expected_wintun_dll_sha256`].
///
/// When no verified on-disk copy exists and `vdpi.exe` was built with an embedded WHQL-signed
/// `wintun.dll`, verifies the embedded bytes and atomically materializes them into the hidden
/// runtime cache (`%ProgramData%\vdpi\runtime\wintun-0.14.1.dll`, falling back to
/// `%LOCALAPPDATA%\vdpi\runtime\wintun-0.14.1.dll`, then `<temp>\vdpi-runtime\wintun-0.14.1.dll`),
/// never writing into the directory containing `vdpi.exe`.
///
/// Never falls back to CWD or `PATH`. Exposed publicly so CLI `doctor` and preflight checks
/// can verify Wintun readiness cleanly.
pub fn find_verified_wintun_dll() -> Result<PathBuf> {
    let expected_sha256 = expected_wintun_dll_sha256()?;
    let exe = std::env::current_exe().context("failed to determine current executable path")?;
    let canonical = std::fs::canonicalize(&exe).ok();

    #[cfg(target_os = "windows")]
    let program_files = Some(crate::platform::windows::known_program_files_dir());
    #[cfg(not(target_os = "windows"))]
    let program_files: Option<PathBuf> = None;

    #[cfg(target_os = "windows")]
    let program_data = Some(crate::platform::windows::known_program_data_dir());
    #[cfg(not(target_os = "windows"))]
    let program_data: Option<PathBuf> = None;

    let local_app_data = cfg!(target_os = "windows")
        .then(|| env_non_empty_path("LOCALAPPDATA"))
        .flatten();
    let temp_dir = cfg!(target_os = "windows").then(std::env::temp_dir);

    #[cfg(all(target_os = "windows", target_arch = "x86_64", vdpi_embedded_wintun))]
    let embedded_bytes: Option<&[u8]> = Some(EMBEDDED_WINTUN_DLL);
    #[cfg(not(all(target_os = "windows", target_arch = "x86_64", vdpi_embedded_wintun)))]
    let embedded_bytes: Option<&[u8]> = None;

    resolve_or_materialize_wintun_dll(
        &exe,
        canonical.as_deref(),
        program_files.as_deref(),
        program_data.as_deref(),
        local_app_data.as_deref(),
        temp_dir.as_deref(),
        expected_sha256,
        embedded_bytes,
    )
}

#[cfg(target_os = "windows")]
mod win32 {
    use super::*;
    use crate::binder::{DynamicOutboundBinder, OutboundBinder, OutboundTarget};
    use anyhow::anyhow;
    use std::collections::HashMap;
    use std::ffi::{c_void, OsStr, OsString};
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::mem;
    use std::net::IpAddr;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, watch};
    use tracing::{debug, info, trace, warn};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{
        CloseHandle, FreeLibrary, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
        ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_MORE_DATA, ERROR_NOT_FOUND,
        ERROR_NO_MORE_ITEMS, ERROR_OBJECT_ALREADY_EXISTS, FILETIME, HANDLE, HMODULE, NO_ERROR,
        WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToGuid,
        CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
        DeleteUnicastIpAddressEntry, FreeMibTable, GetIfTable2, GetIpForwardTable2,
        GetIpInterfaceEntry, GetIpInterfaceTable, GetUnicastIpAddressTable,
        InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
        NotifyRouteChange2, NotifyUnicastIpAddressChange, SetIpInterfaceEntry,
        DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6,
        DNS_SETTING_NAMESERVER, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE, MIB_NOTIFICATION_TYPE,
        MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
    use windows_sys::Win32::Networking::WinSock::{
        IpDadStatePreferred, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR,
        IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegDeleteKeyW, RegDeleteValueW, RegEnumKeyExW, RegOpenKeyExW,
        RegQueryInfoKeyW, RegQueryValueExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
        KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, REG_EXPAND_SZ, REG_SZ,
        REG_VALUE_TYPE,
    };
    use windows_sys::Win32::System::Threading::{
        ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    };

    /// Fixed deterministic GUID for `vdpi0` so Windows never spawns `vdpi0 2`, `vdpi0 3`, etc.
    const VDPI_WINTUN_GUID: GUID = GUID::from_u128(0x7664_7069_5769_6e74_756e_5630_3530_0001);
    /// Windows `GUID_DEVCLASS_NET` (`{4d36e972-e325-11ce-bfc1-08002be10318}`).
    const GUID_DEVCLASS_NET: GUID = GUID::from_u128(0x4d36_e972_e325_11ce_bfc1_0800_2be1_0318);
    /// Wintun adapter tunnel type label shown in Device Manager / NDIS.
    const VDPI_WINTUN_TUNNEL_TYPE: &str = "vdpi";
    /// Wintun ring buffer capacity: 16 MiB per direction (32 MiB total kernel ring).
    const WINTUN_RING_CAPACITY: u32 = 0x0100_0000;
    /// Bounded Tokio channel depth for inbound IP packets (matches `TunProfile::DESKTOP`, 4096).
    pub(super) const TUN_CHANNEL_CAPACITY: usize =
        vdpi_tun::config::TunProfile::DESKTOP.channel_capacity;
    /// Bounded Tokio channel depth for outbound IP packets (matches [`TX_BATCH_LIMIT`] = 128)
    /// so bulk TCP bursts cannot queue thousands of frames ahead of latency-sensitive UDP/DNS
    /// replies, preserving gigabit throughput with sub-ms UDP preemption.
    pub(super) const TUN_TX_CHANNEL_CAPACITY: usize = 128;
    /// Maximum outbound IP packets drained per wakeup via `blocking_recv_many`.
    pub(super) const TX_BATCH_LIMIT: usize = 128;
    /// Maximum inbound IP packets drained per burst from `WintunReceivePacket` before handing
    /// off to the async channel (continues draining until `ERROR_NO_MORE_ITEMS` before waiting).
    pub(super) const RX_BURST_LIMIT: usize = 128;
    /// Maximum IP packet size supported by Wintun.
    const WINTUN_MAX_IP_PACKET_SIZE: usize = 65_535;
    /// Interface metric assigned to `vdpi0`.
    const VDPI_INTERFACE_METRIC: u32 = 5;
    /// Quiet window for coalescing route-change bursts during NIC handoffs.
    const ROUTE_DEBOUNCE_WINDOW_MS: u32 = 250;
    /// Hard cap on continuous route-change debouncing so updates are never starved.
    const ROUTE_DEBOUNCE_MAX_WAIT: Duration = Duration::from_millis(1500);
    /// Windows registry subkey holding per-interface IPv4 Tcpip parameters (`NameServer`, etc.).
    const TCPIP_INTERFACES_SUBKEY: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    /// Windows registry subkey holding per-interface IPv6 Tcpip6 parameters (`NameServer`, etc.).
    const TCPIP6_INTERFACES_SUBKEY: &str =
        r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";
    /// Win32 `FILE_SHARE_READ`: allows `LoadLibraryExW` to map the DLL while blocking writes,
    /// renames, and deletes on the open handle to eliminate TOCTOU races.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    /// Win32 `FILE_SHARE_WRITE`.
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    /// Win32 `FILE_SHARE_DELETE`.
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    /// Win32 `FILE_FLAG_BACKUP_SEMANTICS`: required to obtain a handle to a directory via `CreateFileW`.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// Win32 `FILE_FLAG_OPEN_REPARSE_POINT`: opens a file/directory/junction itself without
    /// following NTFS reparse points.
    pub(super) const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// Win32 `FILE_READ_ATTRIBUTES` access right (sufficient for `GetFileInformationByHandle`).
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    /// Win32 `READ_CONTROL` access right.
    const READ_CONTROL: u32 = 0x0002_0000;
    /// Win32 `WRITE_DAC` access right (required for handle-based `SetSecurityInfo`).
    const WRITE_DAC: u32 = 0x0004_0000;
    /// Win32 `WRITE_OWNER` access right (required for handle-based `SetSecurityInfo` owner change).
    const WRITE_OWNER: u32 = 0x0008_0000;
    /// Win32 `OPEN_EXISTING` creation disposition for `CreateFileW`.
    const OPEN_EXISTING: u32 = 3;
    /// Global Unicast IPv6 route destination (`2000::/3`).
    pub(super) const VDPI_IPV6_GLOBAL_PREFIX: Ipv6Addr = Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0);
    /// Global Unicast IPv6 route prefix length (`3`).
    pub(super) const VDPI_IPV6_GLOBAL_PREFIX_LEN: u8 = 3;
    /// RFC 6052 Well-Known NAT64 IPv6 route destination (`64:ff9b::/96`).
    pub(super) const VDPI_IPV6_NAT64_PREFIX: Ipv6Addr =
        Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0);
    /// RFC 6052 Well-Known NAT64 IPv6 route prefix length (`96`).
    pub(super) const VDPI_IPV6_NAT64_PREFIX_LEN: u8 = 96;
    /// IPv6 prefixes routed through `vdpi0` whenever IPv6 TUN mode is active:
    /// Global Unicast (`2000::/3`) and RFC 6052 Well-Known NAT64 (`64:ff9b::/96`).
    pub(super) const VDPI_IPV6_TUN_ROUTES: &[(Ipv6Addr, u8)] = &[
        (VDPI_IPV6_GLOBAL_PREFIX, VDPI_IPV6_GLOBAL_PREFIX_LEN),
        (VDPI_IPV6_NAT64_PREFIX, VDPI_IPV6_NAT64_PREFIX_LEN),
    ];
    /// Win32 `FILE_NAME_NORMALIZED | VOLUME_NAME_DOS` flag for `GetFinalPathNameByHandleW`.
    const FILE_NAME_NORMALIZED: u32 = 0x0000_0000;
    /// Win32 `DRIVE_FIXED` return value from `GetDriveTypeW`.
    const DRIVE_FIXED: u32 = 3;
    /// Win32 `INVALID_FILE_ATTRIBUTES` sentinel from `GetFileAttributesW`.
    const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
    /// Win32 `FILE_ATTRIBUTE_DIRECTORY` flag.
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    /// Win32 `FILE_ATTRIBUTE_REPARSE_POINT` flag (junctions, symlinks, mount points).
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    /// Win32 `ERROR_FILE_NOT_FOUND` (2).
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    /// Win32 `ERROR_PATH_NOT_FOUND` (3).
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    /// Win32 `ERROR_INSUFFICIENT_BUFFER` (122).
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    /// Win32 `ERROR_DIRECTORY` (267): returned when a path component is a regular file.
    const ERROR_DIRECTORY: u32 = 267;
    /// Win32 `ERROR_INVALID_OWNER` (1307): returned when a non-elevated caller attempts to
    /// assign ownership to Builtin Administrators.
    const ERROR_INVALID_OWNER: u32 = 1307;
    /// Win32 `ERROR_PRIVILEGE_NOT_HELD` (1314).
    const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;
    /// Win32 `INVALID_HANDLE_VALUE` sentinel (`(HANDLE)-1`).
    const INVALID_HANDLE_PTR: *mut c_void = -1isize as *mut c_void;
    /// SDDL for `%ProgramData%\vdpi` and `%ProgramData%\vdpi\runtime` directories:
    /// owner set to Builtin Administrators (`O:BA`, `S-1-5-32-544`), protected DACL granting
    /// SYSTEM (`SY`) and Builtin Administrators (`BA`) full control (`FA`), and Builtin Users
    /// (`BU`) read/execute only (`FRFX`), inherited by objects and containers (`OICI`).
    const PROGRAM_DATA_RUNTIME_DIR_SDDL: &str =
        "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";
    /// SDDL for pre-existing direct child files inside `%ProgramData%\vdpi`:
    /// owner set to Builtin Administrators (`O:BA`, `S-1-5-32-544`), protected DACL granting
    /// SYSTEM (`SY`) and Builtin Administrators (`BA`) full control (`FA`), and Builtin Users
    /// (`BU`) read/execute only (`FRFX`).
    const PROGRAM_DATA_RUNTIME_FILE_SDDL: &str =
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)";
    /// Win32 `SDDL_REVISION_1`.
    const SDDL_REVISION_1: u32 = 1;
    /// Win32 `SE_FILE_OBJECT` (`SE_OBJECT_TYPE`).
    const SE_FILE_OBJECT: u32 = 1;
    /// Win32 `OWNER_SECURITY_INFORMATION`.
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    /// Win32 `DACL_SECURITY_INFORMATION`.
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    /// Win32 `PROTECTED_DACL_SECURITY_INFORMATION`.
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
    /// SetupAPI device registry property IDs (`setupapi.h`).
    const SPDRP_DEVICEDESC: u32 = 0x0000_0000;
    const SPDRP_HARDWAREID: u32 = 0x0000_0001;
    const SPDRP_FRIENDLYNAME: u32 = 0x0000_000C;
    /// SetupAPI class installer function code for device removal (`DIF_REMOVE`).
    const DIF_REMOVE: u32 = 0x0000_0005;
    /// SetupAPI scope flag for global device removal (`DI_REMOVEDEVICE_GLOBAL`).
    const DI_REMOVEDEVICE_GLOBAL: u32 = 0x0000_0001;
    /// SetupAPI device registry key scope (`DICS_FLAG_GLOBAL`) and type (`DIREG_DRV`).
    const DICS_FLAG_GLOBAL: u32 = 0x0000_0001;
    const DIREG_DRV: u32 = 0x0000_0002;
    /// Upper size bound for `wintun.dll` reads before SHA-256 verification (16 MiB).
    const MAX_WINTUN_DLL_BYTES: u64 = 16 * 1024 * 1024;
    /// Bounded exponential backoff delays when recreating a tearing-down Wintun adapter.
    const ADAPTER_RETRY_DELAYS_MS: &[u64] = &[50, 100, 200, 400, 600];
    /// Retry delays when `SetInterfaceDnsSettings` briefly returns `ERROR_NOT_FOUND` on a new NIC.
    const DNS_NOT_FOUND_RETRY_DELAYS_MS: &[u64] = &[50, 100, 200, 400];

    /// Process-lifetime cache for the verified `wintun.dll` handle/export table.
    ///
    /// Wintun 0.14.1 schedules an asynchronous Windows threadpool callback
    /// (`DoOrphanedDeviceCleanup`) when closing adapters; keeping the verified module pinned
    /// for process lifetime (never calling `FreeLibrary`) eliminates the UAF crash completely.
    static WINTUN_API_CACHE: OnceLock<Arc<WintunApi>> = OnceLock::new();
    static WINTUN_API_INIT_LOCK: Mutex<()> = Mutex::new(());

    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(dead_code)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    #[allow(dead_code)]
    struct ByHandleFileInformation {
        dw_file_attributes: u32,
        ft_creation_time: FILETIME,
        ft_last_access_time: FILETIME,
        ft_last_write_time: FILETIME,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateDirectoryW(
            lp_path_name: *const u16,
            lp_security_attributes: *mut c_void,
        ) -> i32;
        fn CreateEventW(
            lp_event_attributes: *const c_void,
            b_manual_reset: i32,
            b_initial_state: i32,
            lp_name: *const u16,
        ) -> HANDLE;
        fn CreateFileW(
            lp_file_name: *const u16,
            dw_desired_access: u32,
            dw_share_mode: u32,
            lp_security_attributes: *mut c_void,
            dw_creation_disposition: u32,
            dw_flags_and_attributes: u32,
            h_template_file: HANDLE,
        ) -> HANDLE;
        fn GetDriveTypeW(lp_root_path_name: *const u16) -> u32;
        fn GetFileAttributesW(lp_file_name: *const u16) -> u32;
        fn GetFileInformationByHandle(
            h_file: HANDLE,
            lp_file_information: *mut ByHandleFileInformation,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            h_file: HANDLE,
            lpsz_file_path: *mut u16,
            cch_file_path: u32,
            dw_flags: u32,
        ) -> u32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    type WintunAdapterHandle = *mut c_void;
    type WintunSessionHandle = *mut c_void;

    type WintunCreateAdapterFn = unsafe extern "system" fn(
        name: *const u16,
        tunnel_type: *const u16,
        requested_guid: *const GUID,
    ) -> WintunAdapterHandle;
    type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> WintunAdapterHandle;
    type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: WintunAdapterHandle);
    type WintunDeleteDriverFn = unsafe extern "system" fn() -> i32;
    type WintunGetAdapterLuidFn =
        unsafe extern "system" fn(adapter: WintunAdapterHandle, luid: *mut NET_LUID_LH);
    type WintunStartSessionFn = unsafe extern "system" fn(
        adapter: WintunAdapterHandle,
        capacity: u32,
    ) -> WintunSessionHandle;
    type WintunEndSessionFn = unsafe extern "system" fn(session: WintunSessionHandle);
    type WintunGetReadWaitEventFn =
        unsafe extern "system" fn(session: WintunSessionHandle) -> HANDLE;
    type WintunReceivePacketFn =
        unsafe extern "system" fn(session: WintunSessionHandle, packet_size: *mut u32) -> *const u8;
    type WintunReleaseReceivePacketFn =
        unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);
    type WintunAllocateSendPacketFn =
        unsafe extern "system" fn(session: WintunSessionHandle, packet_size: u32) -> *mut u8;
    type WintunSendPacketFn =
        unsafe extern "system" fn(session: WintunSessionHandle, packet: *const u8);

    type SetInterfaceDnsSettingsFn =
        unsafe extern "system" fn(interface: GUID, settings: *const DNS_INTERFACE_SETTINGS) -> u32;
    type DnsFlushResolverCacheFn = unsafe extern "system" fn() -> i32;

    type ConvertStringSecurityDescriptorToSecurityDescriptorWFn = unsafe extern "system" fn(
        string_security_descriptor: *const u16,
        string_sd_revision: u32,
        security_descriptor: *mut *mut c_void,
        security_descriptor_size: *mut u32,
    ) -> i32;
    type GetSecurityDescriptorOwnerFn = unsafe extern "system" fn(
        p_security_descriptor: *mut c_void,
        p_owner: *mut *mut c_void,
        lpb_owner_defaulted: *mut i32,
    ) -> i32;
    type GetSecurityDescriptorDaclFn = unsafe extern "system" fn(
        p_security_descriptor: *mut c_void,
        lpb_dacl_present: *mut i32,
        p_dacl: *mut *mut c_void,
        lpb_dacl_defaulted: *mut i32,
    ) -> i32;
    type SetSecurityInfoFn = unsafe extern "system" fn(
        handle: HANDLE,
        object_type: u32,
        security_info: u32,
        psid_owner: *mut c_void,
        psid_group: *mut c_void,
        p_dacl: *mut c_void,
        p_sacl: *mut c_void,
    ) -> u32;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SpDevinfoData {
        cb_size: u32,
        class_guid: GUID,
        dev_inst: u32,
        reserved: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SpClassInstallHeader {
        cb_size: u32,
        install_function: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SpRemoveDeviceParams {
        class_install_header: SpClassInstallHeader,
        scope: u32,
        hw_profile: u32,
    }

    type SetupDiGetClassDevsWFn = unsafe extern "system" fn(
        class_guid: *const GUID,
        enumerator: *const u16,
        hwnd_parent: *mut c_void,
        flags: u32,
    ) -> *mut c_void;
    type SetupDiDestroyDeviceInfoListFn =
        unsafe extern "system" fn(device_info_set: *mut c_void) -> i32;
    type SetupDiEnumDeviceInfoFn = unsafe extern "system" fn(
        device_info_set: *mut c_void,
        member_index: u32,
        device_info_data: *mut SpDevinfoData,
    ) -> i32;
    type SetupDiGetDeviceRegistryPropertyWFn = unsafe extern "system" fn(
        device_info_set: *mut c_void,
        device_info_data: *const SpDevinfoData,
        property: u32,
        property_reg_data_type: *mut u32,
        property_buffer: *mut u8,
        property_buffer_size: u32,
        required_size: *mut u32,
    ) -> i32;
    type SetupDiSetClassInstallParamsWFn = unsafe extern "system" fn(
        device_info_set: *mut c_void,
        device_info_data: *mut SpDevinfoData,
        class_install_params: *const SpClassInstallHeader,
        class_install_params_size: u32,
    ) -> i32;
    type SetupDiCallClassInstallerFn = unsafe extern "system" fn(
        install_function: u32,
        device_info_set: *mut c_void,
        device_info_data: *mut SpDevinfoData,
    ) -> i32;
    type SetupDiOpenDevRegKeyFn = unsafe extern "system" fn(
        device_info_set: *mut c_void,
        device_info_data: *mut SpDevinfoData,
        scope: u32,
        hw_profile: u32,
        key_type: u32,
        sam_desired: u32,
    ) -> HKEY;

    /// Send/Sync wrapper around an opaque Win32 handle (`HANDLE`, `HMODULE`, Wintun handles).
    #[derive(Clone, Copy)]
    struct SendHandle(*mut c_void);

    // SAFETY: Win32 kernel handles, HMODULEs, and Wintun adapter/session handles are process-global
    // opaque handles safe to transfer/share across OS threads under Wintun's documented threading
    // rules (single RX reader thread, single TX writer thread, synchronized teardown).
    unsafe impl Send for SendHandle {}
    unsafe impl Sync for SendHandle {}

    impl SendHandle {
        #[inline]
        fn as_raw(self) -> *mut c_void {
            self.0
        }

        #[inline]
        fn is_null(self) -> bool {
            self.0.is_null()
        }
    }

    /// RAII wrapper for a dynamically loaded Win32 `HMODULE`.
    struct ModuleGuard(HMODULE);

    impl ModuleGuard {
        fn into_raw(mut self) -> HMODULE {
            let h = self.0;
            self.0 = ptr::null_mut();
            h
        }
    }

    impl Drop for ModuleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = FreeLibrary(self.0);
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    /// RAII wrapper for memory allocated by Win32 `LocalAlloc` (freed via `LocalFree`).
    struct LocalMemGuard(*mut c_void);

    impl Drop for LocalMemGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = LocalFree(self.0);
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    /// RAII wrapper for a Win32 `HANDLE` closed via `CloseHandle`.
    struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        #[inline]
        fn as_raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_PTR {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    /// RAII wrapper for SetupAPI `HDEVINFO` handles (freed via `SetupDiDestroyDeviceInfoList`).
    struct DevInfoListGuard {
        handle: *mut c_void,
        destroy: SetupDiDestroyDeviceInfoListFn,
    }

    impl Drop for DevInfoListGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() && self.handle != INVALID_HANDLE_PTR {
                unsafe {
                    let _ = (self.destroy)(self.handle);
                }
                self.handle = INVALID_HANDLE_PTR;
            }
        }
    }

    /// RAII wrapper for Win32 `HKEY` handles (closed via `RegCloseKey`).
    struct RegKeyGuard(HKEY);

    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_PTR {
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    /// RAII wrapper for a Win32 event handle created by `CreateEventW`.
    struct OwnedEvent(SendHandle);

    impl OwnedEvent {
        fn new(manual_reset: bool) -> Result<Self> {
            let h = unsafe { CreateEventW(ptr::null(), i32::from(manual_reset), 0, ptr::null()) };
            if h.is_null() {
                let err = unsafe { GetLastError() };
                bail!("CreateEventW failed with Win32 error {err}");
            }
            Ok(Self(SendHandle(h)))
        }

        fn into_raw(mut self) -> SendHandle {
            let h = self.0;
            self.0 = SendHandle(ptr::null_mut());
            h
        }
    }

    impl Drop for OwnedEvent {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    let _ = CloseHandle(self.0.as_raw());
                }
                self.0 = SendHandle(ptr::null_mut());
            }
        }
    }

    /// RAII guard for IP Helper MIB tables allocated by Windows and freed via `FreeMibTable`.
    struct MibTableGuard<T> {
        ptr: *mut T,
    }

    impl<T> MibTableGuard<T> {
        fn new(ptr: *mut T) -> Self {
            Self { ptr }
        }

        #[inline]
        fn as_ptr(&self) -> *const T {
            self.ptr
        }
    }

    impl<T> Drop for MibTableGuard<T> {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe { FreeMibTable(self.ptr.cast()) };
                self.ptr = ptr::null_mut();
            }
        }
    }

    fn verify_open_file_sha256(file: &mut File, path: &Path, expected_sha256: &str) -> Result<()> {
        let mut buf = Vec::new();
        file.by_ref()
            .take(MAX_WINTUN_DLL_BYTES + 1)
            .read_to_end(&mut buf)
            .with_context(|| {
                format!("failed to read {} for SHA-256 verification", path.display())
            })?;
        if buf.len() as u64 > MAX_WINTUN_DLL_BYTES {
            bail!(
                "wintun.dll at {} exceeds maximum expected size ({MAX_WINTUN_DLL_BYTES} bytes)",
                path.display()
            );
        }
        let actual = sha256_hex(&buf);
        if !actual.eq_ignore_ascii_case(expected_sha256) {
            bail!(
                "wintun.dll SHA-256 verification failed for {}: expected {expected_sha256}, got {actual}",
                path.display()
            );
        }
        Ok(())
    }

    /// Resolves the normalized final filesystem path of an already-open Win32 file handle via
    /// `GetFinalPathNameByHandleW` so `LoadLibraryExW` cannot be redirected by an NTFS junction
    /// swap between `open` and DLL load.
    pub(super) fn final_path_from_file(file: &File) -> Result<PathBuf> {
        let handle: HANDLE = file.as_raw_handle();
        let mut buf = vec![0u16; 512];
        for _ in 0..4 {
            let len = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    FILE_NAME_NORMALIZED,
                )
            };
            if len == 0 {
                let err = unsafe { GetLastError() };
                bail!("GetFinalPathNameByHandleW failed with Win32 error {err}");
            }
            let len_usize = len as usize;
            if len_usize < buf.len() {
                return Ok(PathBuf::from(OsString::from_wide(&buf[..len_usize])));
            }
            if len_usize > 32_768 {
                bail!("GetFinalPathNameByHandleW returned oversized path length {len_usize}");
            }
            buf.resize(len_usize + 1, 0);
        }
        bail!("GetFinalPathNameByHandleW did not converge on a stable path length")
    }

    /// Loaded `advapi32.dll` handle, handle-based `SetSecurityInfo` proc, Builtin Administrators
    /// owner SID (`O:BA`, `S-1-5-32-544`), and parsed [`PROGRAM_DATA_RUNTIME_DIR_SDDL`] /
    /// [`PROGRAM_DATA_RUNTIME_FILE_SDDL`] security descriptors + DACL pointers.
    pub(super) struct ProgramDataDaclContext {
        _dir_sd_guard: LocalMemGuard,
        _file_sd_guard: LocalMemGuard,
        _advapi32: ModuleGuard,
        dir_sd_ptr: *mut c_void,
        owner_sid_ptr: *mut c_void,
        dir_dacl_ptr: *mut c_void,
        file_dacl_ptr: *mut c_void,
        set_security_info: SetSecurityInfoFn,
    }

    impl ProgramDataDaclContext {
        pub(super) fn load() -> Result<Self> {
            let advapi32_w = encode_wide("advapi32.dll");
            let hmod = unsafe {
                LoadLibraryExW(
                    advapi32_w.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if hmod.is_null() {
                let err = unsafe { GetLastError() };
                bail!("LoadLibraryExW(advapi32.dll) failed with Win32 error {err}");
            }
            let mod_guard = ModuleGuard(hmod);

            let convert_sd: ConvertStringSecurityDescriptorToSecurityDescriptorWFn = unsafe {
                load_proc(hmod, c"ConvertStringSecurityDescriptorToSecurityDescriptorW")?
            };
            let get_owner: GetSecurityDescriptorOwnerFn =
                unsafe { load_proc(hmod, c"GetSecurityDescriptorOwner")? };
            let get_dacl: GetSecurityDescriptorDaclFn =
                unsafe { load_proc(hmod, c"GetSecurityDescriptorDacl")? };
            let set_security_info: SetSecurityInfoFn =
                unsafe { load_proc(hmod, c"SetSecurityInfo")? };

            let parse_sd = |sddl: &str| -> Result<(LocalMemGuard, *mut c_void, *mut c_void)> {
                let sddl_w = encode_wide(sddl);
                let mut sd_ptr: *mut c_void = ptr::null_mut();
                let mut sd_size: u32 = 0;
                let ok = unsafe {
                    convert_sd(
                        sddl_w.as_ptr(),
                        SDDL_REVISION_1,
                        &mut sd_ptr,
                        &mut sd_size,
                    )
                };
                if ok == 0 || sd_ptr.is_null() {
                    let err = unsafe { GetLastError() };
                    bail!(
                        "ConvertStringSecurityDescriptorToSecurityDescriptorW failed with Win32 error {err}"
                    );
                }
                let sd_guard = LocalMemGuard(sd_ptr);

                let mut dacl_present: i32 = 0;
                let mut dacl_ptr: *mut c_void = ptr::null_mut();
                let mut dacl_defaulted: i32 = 0;
                let dacl_ok = unsafe {
                    get_dacl(
                        sd_ptr,
                        &mut dacl_present,
                        &mut dacl_ptr,
                        &mut dacl_defaulted,
                    )
                };
                if dacl_ok == 0 || dacl_present == 0 || dacl_ptr.is_null() {
                    let err = unsafe { GetLastError() };
                    bail!("GetSecurityDescriptorDacl failed with Win32 error {err}");
                }
                Ok((sd_guard, sd_ptr, dacl_ptr))
            };

            let (dir_sd_guard, dir_sd_ptr, dir_dacl_ptr) = parse_sd(PROGRAM_DATA_RUNTIME_DIR_SDDL)?;
            let (file_sd_guard, _file_sd_ptr, file_dacl_ptr) =
                parse_sd(PROGRAM_DATA_RUNTIME_FILE_SDDL)?;

            let mut owner_sid_ptr: *mut c_void = ptr::null_mut();
            let mut owner_defaulted: i32 = 0;
            let owner_ok =
                unsafe { get_owner(dir_sd_ptr, &mut owner_sid_ptr, &mut owner_defaulted) };
            if owner_ok == 0 || owner_sid_ptr.is_null() {
                let err = unsafe { GetLastError() };
                bail!("GetSecurityDescriptorOwner failed with Win32 error {err}");
            }

            Ok(Self {
                _dir_sd_guard: dir_sd_guard,
                _file_sd_guard: file_sd_guard,
                _advapi32: mod_guard,
                dir_sd_ptr,
                owner_sid_ptr,
                dir_dacl_ptr,
                file_dacl_ptr,
                set_security_info,
            })
        }

        fn security_attributes(&self) -> SecurityAttributes {
            SecurityAttributes {
                n_length: mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: self.dir_sd_ptr,
                b_inherit_handle: 0,
            }
        }

        fn apply_to_handle(
            &self,
            handle: HANDLE,
            path: &Path,
            is_dir: bool,
            can_write_owner: bool,
        ) -> Result<()> {
            let dacl_ptr = if is_dir {
                self.dir_dacl_ptr
            } else {
                self.file_dacl_ptr
            };
            let mut rc = if can_write_owner {
                unsafe {
                    (self.set_security_info)(
                        handle,
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION
                            | DACL_SECURITY_INFORMATION
                            | PROTECTED_DACL_SECURITY_INFORMATION,
                        self.owner_sid_ptr,
                        ptr::null_mut(),
                        dacl_ptr,
                        ptr::null_mut(),
                    )
                }
            } else {
                ERROR_ACCESS_DENIED
            };
            if rc != NO_ERROR
                && !crate::platform::windows_service::is_elevated()
                && matches!(
                    rc,
                    ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD
                )
            {
                debug!(
                    path = %path.display(),
                    error = rc,
                    "non-elevated process cannot assign Administrators owner; falling back to DACL-only hardening"
                );
                rc = unsafe {
                    (self.set_security_info)(
                        handle,
                        SE_FILE_OBJECT,
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        dacl_ptr,
                        ptr::null_mut(),
                    )
                };
            }
            if rc != NO_ERROR {
                bail!(
                    "SetSecurityInfo({}) failed with Win32 error {rc}",
                    path.display()
                );
            }
            debug!(
                path = %path.display(),
                is_dir,
                "hardened ProgramData runtime object owner and DACL via verified handle"
            );
            Ok(())
        }
    }

    /// Opens an existing file or directory WITHOUT following NTFS reparse points / junctions
    /// (`FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`).
    ///
    /// Returns `Ok(None)` when `require_exists == false` and the object does not exist.
    fn open_handle_no_reparse(
        path: &Path,
        desired_access: u32,
        share_mode: u32,
        require_exists: bool,
    ) -> Result<Option<OwnedHandle>> {
        let wide = encode_wide_os(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                desired_access,
                share_mode,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_PTR {
            let err = unsafe { GetLastError() };
            if !require_exists && (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                return Ok(None);
            }
            bail!(
                "CreateFileW({}) failed with Win32 error {err}",
                path.display()
            );
        }
        Ok(Some(OwnedHandle(handle)))
    }

    /// Validates an already-open Win32 handle via `GetFileInformationByHandle`, rejecting
    /// NTFS reparse points / junctions and returning `true` when the object is a directory.
    fn inspect_handle_is_dir_no_reparse(handle: HANDLE, path: &Path) -> Result<bool> {
        let mut info = ByHandleFileInformation::default();
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            bail!(
                "GetFileInformationByHandle({}) failed with Win32 error {err}",
                path.display()
            );
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            bail!(
                "refusing to use NTFS reparse point / junction at {}",
                path.display()
            );
        }
        Ok((info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
    }

    /// Validates an already-open Win32 handle via `GetFileInformationByHandle`, rejecting
    /// NTFS reparse points / junctions and verifying directory vs. regular-file type.
    fn verify_handle_attributes(handle: HANDLE, path: &Path, require_dir: bool) -> Result<()> {
        let is_dir = inspect_handle_is_dir_no_reparse(handle, path)?;
        if require_dir && !is_dir {
            bail!("expected directory at {}", path.display());
        }
        if !require_dir && is_dir {
            bail!("expected regular file, found directory at {}", path.display());
        }
        Ok(())
    }

    /// Queries `GetFileAttributesW` without traversing symlinks/reparse points on the final
    /// path component. Returns `Ok(None)` when the path does not exist or cannot be stat'd.
    fn get_attrs_no_follow(path: &Path) -> Result<Option<u32>> {
        let wide = encode_wide_os(path.as_os_str());
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            let err = unsafe { GetLastError() };
            if matches!(
                err,
                ERROR_FILE_NOT_FOUND
                    | ERROR_PATH_NOT_FOUND
                    | ERROR_DIRECTORY
                    | ERROR_ACCESS_DENIED
            ) {
                return Ok(None);
            }
            bail!(
                "GetFileAttributesW({}) failed with Win32 error {err}",
                path.display()
            );
        }
        Ok(Some(attrs))
    }

    /// Inspects `GetFileAttributesW` on `path` (and, for runtime cache paths, top-down on its
    /// `vdpi` and `runtime` parent directories) BEFORE calling `.is_file()` or hashing, rejecting
    /// `FILE_ATTRIBUTE_REPARSE_POINT` so a local symlink pointing to a UNC share cannot trigger
    /// an outbound SMB connection / Net-NTLMv2 credential leak.
    pub(super) fn probe_existing_regular_file_no_reparse(
        path: &Path,
        check_cache_parents: bool,
    ) -> Result<bool> {
        if check_cache_parents {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                if let Some(vdpi_dir) = runtime_vdpi_parent_dir(parent) {
                    match get_attrs_no_follow(vdpi_dir)? {
                        None => return Ok(false),
                        Some(attrs) => {
                            if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                                bail!(
                                    "refusing to use NTFS reparse point / junction at {}",
                                    vdpi_dir.display()
                                );
                            }
                            if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                                return Ok(false);
                            }
                        }
                    }
                }
                match get_attrs_no_follow(parent)? {
                    None => return Ok(false),
                    Some(attrs) => {
                        if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                            bail!(
                                "refusing to use NTFS reparse point / junction at {}",
                                parent.display()
                            );
                        }
                        if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                            return Ok(false);
                        }
                    }
                }
            }
        }

        match get_attrs_no_follow(path)? {
            None => Ok(false),
            Some(attrs) => {
                if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                    bail!(
                        "refusing to use NTFS reparse point / symlink at {}",
                        path.display()
                    );
                }
                Ok((attrs & FILE_ATTRIBUTE_DIRECTORY) == 0)
            }
        }
    }

    pub(super) fn verify_open_handle_not_reparse_point(
        file: &File,
        path: &Path,
        require_dir: bool,
    ) -> Result<()> {
        verify_handle_attributes(file.as_raw_handle(), path, require_dir)
    }

    fn verify_existing_dir_no_reparse(path: &Path) -> Result<()> {
        let handle = open_handle_no_reparse(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            true,
        )?
        .ok_or_else(|| anyhow!("expected existing directory at {}", path.display()))?;
        verify_handle_attributes(handle.as_raw(), path, true)
    }

    /// Rejects NTFS reparse points / junctions on `target` (if it exists) and its parent
    /// directory using handle-based `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS |
    /// FILE_FLAG_OPEN_REPARSE_POINT)` + `GetFileInformationByHandle`.
    pub(super) fn reject_reparse_point_before_rename(target: &Path) -> Result<()> {
        if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
            verify_existing_dir_no_reparse(parent)?;
        }
        if let Some(handle) = open_handle_no_reparse(
            target,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        )? {
            verify_handle_attributes(handle.as_raw(), target, false)?;
        }
        Ok(())
    }

    /// Ensures ancestor directories above `vdpi`/`runtime` exist using `CreateDirectoryW`
    /// without invoking `std::fs::create_dir_all`.
    fn ensure_ancestor_dirs_exist(dir: &Path) -> Result<()> {
        let mut missing: Vec<PathBuf> = Vec::new();
        let mut cur = dir;
        loop {
            if cur.as_os_str().is_empty() {
                break;
            }
            let wide = encode_wide_os(cur.as_os_str());
            let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
            if attrs != INVALID_FILE_ATTRIBUTES {
                if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
                    bail!("ancestor path is not a directory: {}", cur.display());
                }
                break;
            }
            let err = unsafe { GetLastError() };
            if err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND {
                bail!(
                    "GetFileAttributesW({}) failed with Win32 error {err}",
                    cur.display()
                );
            }
            missing.push(cur.to_path_buf());
            let Some(p) = cur.parent() else {
                break;
            };
            if p == cur {
                break;
            }
            cur = p;
        }

        for ancestor in missing.into_iter().rev() {
            let wide = encode_wide_os(ancestor.as_os_str());
            let ok = unsafe { CreateDirectoryW(wide.as_ptr(), ptr::null_mut()) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                if err != ERROR_ALREADY_EXISTS {
                    bail!(
                        "CreateDirectoryW({}) failed with Win32 error {err}",
                        ancestor.display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Opens `path` without following reparse points requesting `WRITE_DAC | WRITE_OWNER` so
    /// both NTFS owner and protected DACL can be updated atomically via `SetSecurityInfo`.
    /// When running non-elevated (e.g. unit tests), falls back to `WRITE_DAC` only if
    /// `WRITE_OWNER` is denied.
    fn open_handle_for_hardening(
        path: &Path,
        share_mode: u32,
        require_exists: bool,
    ) -> Result<Option<(OwnedHandle, bool)>> {
        match open_handle_no_reparse(
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            share_mode,
            require_exists,
        ) {
            Ok(Some(handle)) => Ok(Some((handle, true))),
            Ok(None) => Ok(None),
            Err(err) if !crate::platform::windows_service::is_elevated() => {
                debug!(
                    path = %path.display(),
                    error = %err,
                    "non-elevated process could not open handle with WRITE_OWNER; falling back to WRITE_DAC"
                );
                Ok(open_handle_no_reparse(
                    path,
                    FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                    share_mode,
                    require_exists,
                )?
                .map(|handle| (handle, false)))
            }
            Err(err) => Err(err),
        }
    }

    /// Applies the Builtin Administrators NTFS owner (`O:BA`, `S-1-5-32-544`) and restricted
    /// protected DACL ([`PROGRAM_DATA_RUNTIME_DIR_SDDL`]) to an existing `%ProgramData%\vdpi`
    /// or `%ProgramData%\vdpi\runtime` directory — plus every pre-existing direct child file
    /// and directory inside it — using a TOCTOU-free handle flow:
    /// `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)` ->
    /// `GetFileInformationByHandle` -> handle-based `SetSecurityInfo`.
    pub(super) fn harden_program_data_dir_dacl(
        path: &Path,
        dacl_ctx: &ProgramDataDaclContext,
    ) -> Result<()> {
        let (handle, can_write_owner) = open_handle_for_hardening(
            path,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            true,
        )?
        .ok_or_else(|| anyhow!("directory missing before DACL hardening: {}", path.display()))?;
        verify_handle_attributes(handle.as_raw(), path, true)?;
        dacl_ctx.apply_to_handle(handle.as_raw(), path, true, can_write_owner)?;

        // Verify and harden pre-existing direct child files/directories so an attacker who
        // pre-created `%ProgramData%\vdpi` and planted child objects cannot retain NTFS
        // ownership, permissive DACLs, or hidden junctions/symlinks on them.
        let entries = std::fs::read_dir(path).with_context(|| {
            format!(
                "failed to enumerate direct children of {} during ProgramData hardening",
                path.display()
            )
        })?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed to read directory entry inside {} during ProgramData hardening",
                    path.display()
                )
            })?;
            let child_path = entry.path();
            let Some((child_handle, child_can_write_owner)) = open_handle_for_hardening(
                &child_path,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                false,
            )?
            else {
                continue;
            };
            let is_dir = inspect_handle_is_dir_no_reparse(child_handle.as_raw(), &child_path)?;
            dacl_ctx.apply_to_handle(
                child_handle.as_raw(),
                &child_path,
                is_dir,
                child_can_write_owner,
            )?;
        }

        Ok(())
    }

    /// Test-only helper that restores a permissive DACL on a temporary test path so unit tests
    /// running non-elevated can cleanly delete hardened temp directories on teardown.
    #[cfg(test)]
    pub(super) fn reset_test_path_dacl_for_cleanup(path: &Path, is_dir: bool) {
        let advapi32_w = encode_wide("advapi32.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                advapi32_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if hmod.is_null() {
            return;
        }
        let _mod_guard = ModuleGuard(hmod);
        let Ok(convert_sd) = (unsafe {
            load_proc::<ConvertStringSecurityDescriptorToSecurityDescriptorWFn>(
                hmod,
                c"ConvertStringSecurityDescriptorToSecurityDescriptorW",
            )
        }) else {
            return;
        };
        let Ok(get_dacl) =
            (unsafe { load_proc::<GetSecurityDescriptorDaclFn>(hmod, c"GetSecurityDescriptorDacl") })
        else {
            return;
        };
        let Ok(set_security_info) =
            (unsafe { load_proc::<SetSecurityInfoFn>(hmod, c"SetSecurityInfo") })
        else {
            return;
        };
        let sddl_w = encode_wide(if is_dir {
            "D:(A;OICI;FA;;;WD)"
        } else {
            "D:(A;;FA;;;WD)"
        });
        let mut sd_ptr: *mut c_void = ptr::null_mut();
        let mut sd_size: u32 = 0;
        let ok = unsafe { convert_sd(sddl_w.as_ptr(), SDDL_REVISION_1, &mut sd_ptr, &mut sd_size) };
        if ok == 0 || sd_ptr.is_null() {
            return;
        }
        let _sd_guard = LocalMemGuard(sd_ptr);
        let mut dacl_present: i32 = 0;
        let mut dacl_ptr: *mut c_void = ptr::null_mut();
        let mut dacl_defaulted: i32 = 0;
        let dacl_ok =
            unsafe { get_dacl(sd_ptr, &mut dacl_present, &mut dacl_ptr, &mut dacl_defaulted) };
        if dacl_ok == 0 || dacl_present == 0 || dacl_ptr.is_null() {
            return;
        }
        if let Ok(Some(handle)) = open_handle_no_reparse(
            path,
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            false,
        ) {
            unsafe {
                let _ = set_security_info(
                    handle.as_raw(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl_ptr,
                    ptr::null_mut(),
                );
            }
        }
    }

    /// Atomically creates `path` via `CreateDirectoryW(&SECURITY_ATTRIBUTES)` when hardening
    /// (zero permissive-ACL creation window), then verifies the open handle via
    /// `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)` +
    /// `GetFileInformationByHandle` and applies handle-based `SetSecurityInfo` when hardening.
    fn create_and_verify_runtime_dir(
        path: &Path,
        dacl_ctx: Option<&ProgramDataDaclContext>,
    ) -> Result<()> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            ensure_ancestor_dirs_exist(parent)?;
        }

        let wide = encode_wide_os(path.as_os_str());
        let mut ok = if let Some(ctx) = dacl_ctx {
            let mut sa = ctx.security_attributes();
            unsafe { CreateDirectoryW(wide.as_ptr(), (&mut sa as *mut SecurityAttributes).cast()) }
        } else {
            unsafe { CreateDirectoryW(wide.as_ptr(), ptr::null_mut()) }
        };
        if ok == 0 {
            let mut err = unsafe { GetLastError() };
            if dacl_ctx.is_some()
                && err == ERROR_INVALID_OWNER
                && !crate::platform::windows_service::is_elevated()
            {
                ok = unsafe { CreateDirectoryW(wide.as_ptr(), ptr::null_mut()) };
                err = if ok == 0 {
                    unsafe { GetLastError() }
                } else {
                    NO_ERROR
                };
            }
            if ok == 0 && err != ERROR_ALREADY_EXISTS {
                bail!(
                    "CreateDirectoryW({}) failed with Win32 error {err}",
                    path.display()
                );
            }
        }

        if let Some(ctx) = dacl_ctx {
            harden_program_data_dir_dacl(path, ctx)
        } else {
            verify_existing_dir_no_reparse(path)
        }
    }

    fn runtime_vdpi_parent_dir(runtime_dir: &Path) -> Option<&Path> {
        let is_runtime = runtime_dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("runtime"));
        if !is_runtime {
            return None;
        }
        runtime_dir.parent().filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("vdpi"))
        })
    }

    /// Validates an existing runtime-cache DLL path against NTFS reparse points on its
    /// `vdpi` dir, `runtime` dir, and target file via handle-based checks, and hardens
    /// `%ProgramData%\vdpi` + `%ProgramData%\vdpi\runtime` DACLs via handle-based
    /// `SetSecurityInfo` when running elevated.
    pub(super) fn ensure_runtime_cache_path_safe(
        target: &Path,
        is_program_data: bool,
    ) -> Result<()> {
        let parent = target.parent().ok_or_else(|| {
            anyhow!("runtime cache path has no parent: {}", target.display())
        })?;
        let harden = is_program_data && crate::platform::windows_service::is_elevated();
        let dacl_ctx = if harden {
            Some(ProgramDataDaclContext::load()?)
        } else {
            None
        };

        if let Some(vdpi_dir) = runtime_vdpi_parent_dir(parent) {
            if let Some(ctx) = dacl_ctx.as_ref() {
                harden_program_data_dir_dacl(vdpi_dir, ctx)?;
            } else {
                verify_existing_dir_no_reparse(vdpi_dir)?;
            }
        }
        if let Some(ctx) = dacl_ctx.as_ref() {
            harden_program_data_dir_dacl(parent, ctx)?;
        } else {
            verify_existing_dir_no_reparse(parent)?;
        }
        let target_handle = open_handle_no_reparse(
            target,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            true,
        )?
        .ok_or_else(|| anyhow!("runtime cache target missing: {}", target.display()))?;
        verify_handle_attributes(target_handle.as_raw(), target, false)?;
        Ok(())
    }

    /// Atomically creates and validates the runtime cache directory hierarchy (`vdpi` and
    /// `runtime` dirs) using `CreateDirectoryW(&SECURITY_ATTRIBUTES)` + handle-based
    /// `CreateFileW(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)` +
    /// `GetFileInformationByHandle` + `SetSecurityInfo`, eliminating junction-swap TOCTOU races.
    pub(super) fn prepare_runtime_cache_dir(
        parent: &Path,
        target: &Path,
        is_program_data: bool,
    ) -> Result<()> {
        let harden = is_program_data && crate::platform::windows_service::is_elevated();
        let dacl_ctx = if harden {
            Some(ProgramDataDaclContext::load()?)
        } else {
            None
        };

        if let Some(vdpi_dir) = runtime_vdpi_parent_dir(parent) {
            create_and_verify_runtime_dir(vdpi_dir, dacl_ctx.as_ref())?;
        }

        create_and_verify_runtime_dir(parent, dacl_ctx.as_ref())?;
        reject_reparse_point_before_rename(target)?;
        Ok(())
    }

    /// Dynamically resolved Wintun 0.14.1 export table backed by a verified `wintun.dll`.
    ///
    /// Cached for process lifetime in [`WINTUN_API_CACHE`]; `module` is intentionally never
    /// freed via `FreeLibrary` so Wintun 0.14.1's asynchronous Windows threadpool
    /// `DoOrphanedDeviceCleanup` work item can never execute inside an unmapped DLL.
    struct WintunApi {
        #[allow(dead_code)]
        module: SendHandle,
        create_adapter: WintunCreateAdapterFn,
        open_adapter: WintunOpenAdapterFn,
        close_adapter: WintunCloseAdapterFn,
        delete_driver: Option<WintunDeleteDriverFn>,
        get_adapter_luid: WintunGetAdapterLuidFn,
        start_session: WintunStartSessionFn,
        end_session: WintunEndSessionFn,
        get_read_wait_event: WintunGetReadWaitEventFn,
        receive_packet: WintunReceivePacketFn,
        release_receive_packet: WintunReleaseReceivePacketFn,
        allocate_send_packet: WintunAllocateSendPacketFn,
        send_packet: WintunSendPacketFn,
    }

    impl WintunApi {
        fn load_verified() -> Result<Arc<Self>> {
            if let Some(cached) = WINTUN_API_CACHE.get() {
                return Ok(Arc::clone(cached));
            }
            let _init_guard = WINTUN_API_INIT_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = WINTUN_API_CACHE.get() {
                return Ok(Arc::clone(cached));
            }
            let api = Self::load_verified_uncached()?;
            let _ = WINTUN_API_CACHE.set(Arc::clone(&api));
            Ok(api)
        }

        fn load_verified_uncached() -> Result<Arc<Self>> {
            let expected_sha256 = expected_wintun_dll_sha256()?;
            let dll_path = find_verified_wintun_dll()?;

            let canonical_dll = std::fs::canonicalize(&dll_path).unwrap_or(dll_path);
            let open_path = normalize_load_library_path(&canonical_dll);

            // Open once with `FILE_SHARE_READ` only (denying concurrent write/delete/rename) and
            // keep the handle open across `GetFinalPathNameByHandleW` + `LoadLibraryExW` to
            // eliminate both file-swap and NTFS junction TOCTOU races.
            let mut pinned_file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&open_path)
                .with_context(|| {
                    format!(
                        "failed to open {} with FILE_SHARE_READ for SHA-256 verification",
                        open_path.display()
                    )
                })?;

            verify_open_file_sha256(&mut pinned_file, &open_path, expected_sha256)?;

            let final_path = final_path_from_file(&pinned_file).with_context(|| {
                format!(
                    "failed to resolve final handle path for {}",
                    open_path.display()
                )
            })?;
            if is_unc_or_device_path(&final_path) {
                bail!(
                    "refusing to load wintun.dll from UNC or non-local path: {}",
                    final_path.display()
                );
            }
            let drive_root = extract_local_drive_root(&final_path).ok_or_else(|| {
                anyhow!(
                    "refusing to load wintun.dll from path without a local drive root: {}",
                    final_path.display()
                )
            })?;
            let drive_root_w = encode_wide(&drive_root);
            let drive_type = unsafe { GetDriveTypeW(drive_root_w.as_ptr()) };
            if drive_type != DRIVE_FIXED {
                bail!(
                    "refusing to load wintun.dll from non-fixed drive {} \
                     (GetDriveTypeW={drive_type}, expected DRIVE_FIXED={DRIVE_FIXED}): {}",
                    drive_root,
                    final_path.display()
                );
            }

            let load_path = normalize_load_library_path(&final_path);

            let wide_path = encode_wide_os(load_path.as_os_str());
            let module = unsafe {
                LoadLibraryExW(
                    wide_path.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if module.is_null() {
                let err = unsafe { GetLastError() };
                drop(pinned_file);
                bail!(
                    "LoadLibraryExW({}) failed with Win32 error {err}",
                    load_path.display()
                );
            }
            drop(pinned_file);
            let guard = ModuleGuard(module);

            let api = unsafe {
                Self {
                    module: SendHandle(module),
                    create_adapter: load_proc(module, c"WintunCreateAdapter")?,
                    open_adapter: load_proc(module, c"WintunOpenAdapter")?,
                    close_adapter: load_proc(module, c"WintunCloseAdapter")?,
                    delete_driver: load_proc::<WintunDeleteDriverFn>(
                        module,
                        c"WintunDeleteDriver",
                    )
                    .ok(),
                    get_adapter_luid: load_proc(module, c"WintunGetAdapterLUID")?,
                    start_session: load_proc(module, c"WintunStartSession")?,
                    end_session: load_proc(module, c"WintunEndSession")?,
                    get_read_wait_event: load_proc(module, c"WintunGetReadWaitEvent")?,
                    receive_packet: load_proc(module, c"WintunReceivePacket")?,
                    release_receive_packet: load_proc(module, c"WintunReleaseReceivePacket")?,
                    allocate_send_packet: load_proc(module, c"WintunAllocateSendPacket")?,
                    send_packet: load_proc(module, c"WintunSendPacket")?,
                }
            };
            let _ = guard.into_raw();
            debug!(path = %load_path.display(), "loaded SHA-256 verified wintun.dll (pinned for process lifetime)");
            Ok(Arc::new(api))
        }
    }

    /// Startup rollback guard that closes the Wintun adapter if setup fails mid-way.
    struct AdapterGuard {
        wintun: Arc<WintunApi>,
        handle: SendHandle,
    }

    impl AdapterGuard {
        fn into_raw(mut self) -> SendHandle {
            let h = self.handle;
            self.handle = SendHandle(ptr::null_mut());
            h
        }
    }

    impl Drop for AdapterGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                let mut luid_raw = NET_LUID_LH::default();
                unsafe { (self.wintun.get_adapter_luid)(self.handle.as_raw(), &mut luid_raw) };
                let luid = unsafe { luid_raw.Value };
                let _ = cleanup_vdpi_luid_routes_and_dns(luid);
                unsafe { (self.wintun.close_adapter)(self.handle.as_raw()) };
                self.handle = SendHandle(ptr::null_mut());
                let _ = delete_residual_vdpi_tcpip_interface_keys();
                flush_dns_resolver_cache();
            }
        }
    }

    /// Startup rollback guard that ends the Wintun session if setup fails mid-way.
    struct SessionGuard {
        wintun: Arc<WintunApi>,
        handle: SendHandle,
    }

    impl SessionGuard {
        fn into_raw(mut self) -> SendHandle {
            let h = self.handle;
            self.handle = SendHandle(ptr::null_mut());
            h
        }
    }

    impl Drop for SessionGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { (self.wintun.end_session)(self.handle.as_raw()) };
                self.handle = SendHandle(ptr::null_mut());
            }
        }
    }

    /// Startup rollback guard that resets `DynamicOutboundBinder` if `start()` fails mid-way.
    struct BinderResetGuard {
        binder: Option<Arc<DynamicOutboundBinder>>,
    }

    impl BinderResetGuard {
        fn disarm(&mut self) {
            self.binder = None;
        }
    }

    impl Drop for BinderResetGuard {
        fn drop(&mut self) {
            if let Some(binder) = self.binder.take() {
                binder.update(OutboundTarget::default());
            }
        }
    }

    unsafe fn load_proc<T>(module: HMODULE, symbol: &'static std::ffi::CStr) -> Result<T> {
        debug_assert_eq!(mem::size_of::<T>(), mem::size_of::<usize>());
        let proc = GetProcAddress(module, symbol.as_ptr().cast::<u8>()).ok_or_else(|| {
            let err = GetLastError();
            let name = symbol.to_string_lossy();
            anyhow!("GetProcAddress({name}) failed with Win32 error {err}")
        })?;
        Ok(mem::transmute_copy(&proc))
    }

    fn encode_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn encode_wide_os(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn utf16_array_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    #[inline]
    fn ipv4_to_in_addr(ip: Ipv4Addr) -> IN_ADDR {
        IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_ne_bytes(ip.octets()),
            },
        }
    }

    #[inline]
    fn in_addr_to_ipv4(addr: IN_ADDR) -> Ipv4Addr {
        let bytes = unsafe { addr.S_un.S_addr }.to_ne_bytes();
        Ipv4Addr::from(bytes)
    }

    #[inline]
    fn ipv6_to_in6_addr(ip: Ipv6Addr) -> IN6_ADDR {
        IN6_ADDR {
            u: IN6_ADDR_0 { Byte: ip.octets() },
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct UplinkEndpoint {
        pub(super) luid: u64,
        pub(super) if_index: u32,
        pub(super) alias: String,
        pub(super) combined_metric: u32,
        pub(super) gateway: IpAddr,
        /// Sorted, deduplicated preferred local unicast IP addresses on this physical uplink.
        pub(super) local_addrs: Vec<IpAddr>,
    }

    /// Snapshot of the active physical uplink identity (interface LUID, if_index, gateway,
    /// sorted local unicast IPv4/IPv6 addresses, and IPv4/IPv6 availability) used to suppress
    /// spurious `route_tx` notifications on unrelated route-table events while still detecting
    /// SSID roaming across networks sharing the same gateway (e.g. `192.168.1.1`).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) struct UplinkSignature {
        pub(super) v4: Option<(u64, u32, IpAddr, Vec<IpAddr>)>,
        pub(super) v6: Option<(u64, u32, IpAddr, Vec<IpAddr>)>,
    }

    #[derive(Debug, Clone, Default)]
    pub(super) struct DetectedUplink {
        pub(super) nic_name: Option<String>,
        pub(super) v4: Option<UplinkEndpoint>,
        pub(super) v6: Option<UplinkEndpoint>,
    }

    impl DetectedUplink {
        pub(super) fn signature(&self) -> UplinkSignature {
            let normalize = |addrs: &[IpAddr]| {
                let mut sorted = addrs.to_vec();
                sorted.sort_unstable();
                sorted.dedup();
                sorted
            };
            UplinkSignature {
                v4: self
                    .v4
                    .as_ref()
                    .map(|u| (u.luid, u.if_index, u.gateway, normalize(&u.local_addrs))),
                v6: self
                    .v6
                    .as_ref()
                    .map(|u| (u.luid, u.if_index, u.gateway, normalize(&u.local_addrs))),
            }
        }

        fn to_outbound_target(&self) -> OutboundTarget {
            OutboundTarget {
                nic_name: self.nic_name.clone(),
                if_index_v4: self.v4.as_ref().map(|u| u.if_index),
                if_index_v6: self.v6.as_ref().map(|u| u.if_index),
                fwmark: None,
                fail_closed: true,
            }
        }
    }

    struct IfMetadata {
        if_index: u32,
        alias: String,
        description: String,
        if_type: u32,
        is_up: bool,
    }

    /// Detects the active physical IPv4 and IPv6 uplinks via Windows IP Helper APIs
    /// (`GetIfTable2`, `GetIpInterfaceTable`, `GetUnicastIpAddressTable`, `GetIpForwardTable2`),
    /// always freeing every MIB table with `FreeMibTable`.
    fn detect_physical_uplink(vdpi_luid: u64) -> Result<DetectedUplink> {
        // 1. Enumerate interfaces for LUID -> metadata.
        let mut raw_if_table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        let rc = unsafe { GetIfTable2(&mut raw_if_table) };
        if rc != NO_ERROR {
            bail!("GetIfTable2 failed with Win32 error {rc}");
        }
        let if_table = MibTableGuard::new(raw_if_table);
        let mut if_map: HashMap<u64, IfMetadata> = HashMap::new();
        let if_count = unsafe { (*if_table.as_ptr()).NumEntries } as usize;
        if if_count > 0 {
            let rows = unsafe {
                let first = std::ptr::addr_of!((*if_table.as_ptr()).Table).cast::<MIB_IF_ROW2>();
                std::slice::from_raw_parts(first, if_count)
            };
            for row in rows {
                let luid = unsafe { row.InterfaceLuid.Value };
                if_map.insert(
                    luid,
                    IfMetadata {
                        if_index: row.InterfaceIndex,
                        alias: utf16_array_to_string(&row.Alias),
                        description: utf16_array_to_string(&row.Description),
                        if_type: row.Type,
                        is_up: row.OperStatus == IfOperStatusUp,
                    },
                );
            }
        }

        // 2. Enumerate IP interface rows to obtain per-family interface metrics.
        let mut raw_ip_if_table: *mut MIB_IPINTERFACE_TABLE = ptr::null_mut();
        let rc = unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut raw_ip_if_table) };
        if rc != NO_ERROR {
            bail!("GetIpInterfaceTable failed with Win32 error {rc}");
        }
        let ip_if_table = MibTableGuard::new(raw_ip_if_table);
        let mut iface_metric_v4: HashMap<u64, u32> = HashMap::new();
        let mut iface_metric_v6: HashMap<u64, u32> = HashMap::new();
        let ip_if_count = unsafe { (*ip_if_table.as_ptr()).NumEntries } as usize;
        if ip_if_count > 0 {
            let rows = unsafe {
                let first =
                    std::ptr::addr_of!((*ip_if_table.as_ptr()).Table).cast::<MIB_IPINTERFACE_ROW>();
                std::slice::from_raw_parts(first, ip_if_count)
            };
            for row in rows {
                let luid = unsafe { row.InterfaceLuid.Value };
                if row.Family == AF_INET {
                    iface_metric_v4.insert(luid, row.Metric);
                } else if row.Family == AF_INET6 {
                    iface_metric_v6.insert(luid, row.Metric);
                }
            }
        }

        // 3. Enumerate unicast addresses so interfaces without usable IPs are excluded and
        //    local unicast IPv4/IPv6 addresses are captured in `UplinkSignature`.
        let mut raw_unicast: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        let rc = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut raw_unicast) };
        if rc != NO_ERROR {
            bail!("GetUnicastIpAddressTable failed with Win32 error {rc}");
        }
        let unicast_table = MibTableGuard::new(raw_unicast);
        let mut unicast_v4: HashMap<u64, Vec<Ipv4Addr>> = HashMap::new();
        let mut unicast_v6: HashMap<u64, Vec<Ipv6Addr>> = HashMap::new();
        let unicast_count = unsafe { (*unicast_table.as_ptr()).NumEntries } as usize;
        if unicast_count > 0 {
            let rows = unsafe {
                let first = std::ptr::addr_of!((*unicast_table.as_ptr()).Table)
                    .cast::<MIB_UNICASTIPADDRESS_ROW>();
                std::slice::from_raw_parts(first, unicast_count)
            };
            for row in rows {
                if row.DadState != IpDadStatePreferred || row.PreferredLifetime == 0 {
                    continue;
                }
                let luid = unsafe { row.InterfaceLuid.Value };
                let family = unsafe { row.Address.si_family };
                if family == AF_INET {
                    let ip = in_addr_to_ipv4(unsafe { row.Address.Ipv4.sin_addr });
                    if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_link_local() {
                        unicast_v4.entry(luid).or_default().push(ip);
                    }
                } else if family == AF_INET6 {
                    let ip = Ipv6Addr::from(unsafe { row.Address.Ipv6.sin6_addr.u.Byte });
                    if is_ipv6_global_unicast(ip) {
                        unicast_v6.entry(luid).or_default().push(ip);
                    }
                }
            }
        }

        // 4. Enumerate default routes (`PrefixLength == 0`) from the IP forward table.
        let mut raw_fwd: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw_fwd) };
        if rc != NO_ERROR {
            bail!("GetIpForwardTable2 failed with Win32 error {rc}");
        }
        let fwd_table = MibTableGuard::new(raw_fwd);
        let mut candidates_v4: Vec<UplinkCandidate> = Vec::new();
        let mut gateways_v4: Vec<Ipv4Addr> = Vec::new();
        let mut candidates_v6: Vec<UplinkCandidate> = Vec::new();
        let mut gateways_v6: Vec<Ipv6Addr> = Vec::new();
        let fwd_count = unsafe { (*fwd_table.as_ptr()).NumEntries } as usize;
        if fwd_count > 0 {
            let rows = unsafe {
                let first =
                    std::ptr::addr_of!((*fwd_table.as_ptr()).Table).cast::<MIB_IPFORWARD_ROW2>();
                std::slice::from_raw_parts(first, fwd_count)
            };
            for row in rows {
                if row.Loopback || row.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let luid = unsafe { row.InterfaceLuid.Value };
                let Some(meta) = if_map.get(&luid) else {
                    continue;
                };
                let if_index = if meta.if_index != 0 {
                    meta.if_index
                } else {
                    row.InterfaceIndex
                };
                let family = unsafe { row.DestinationPrefix.Prefix.si_family };
                if family == AF_INET {
                    let prefix_ip =
                        in_addr_to_ipv4(unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr });
                    if !prefix_ip.is_unspecified() {
                        continue;
                    }
                    let gateway = in_addr_to_ipv4(unsafe { row.NextHop.Ipv4.sin_addr });
                    candidates_v4.push(UplinkCandidate {
                        luid,
                        if_index,
                        alias: meta.alias.clone(),
                        description: meta.description.clone(),
                        if_type: meta.if_type,
                        is_up: meta.is_up,
                        route_metric: row.Metric,
                        iface_metric: iface_metric_v4.get(&luid).copied().unwrap_or(0),
                        has_unicast_ip: unicast_v4.contains_key(&luid),
                    });
                    gateways_v4.push(gateway);
                } else if family == AF_INET6 {
                    let prefix_ip = Ipv6Addr::from(unsafe {
                        row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte
                    });
                    if !prefix_ip.is_unspecified() {
                        continue;
                    }
                    let gateway = Ipv6Addr::from(unsafe { row.NextHop.Ipv6.sin6_addr.u.Byte });
                    candidates_v6.push(UplinkCandidate {
                        luid,
                        if_index,
                        alias: meta.alias.clone(),
                        description: meta.description.clone(),
                        if_type: meta.if_type,
                        is_up: meta.is_up,
                        route_metric: row.Metric,
                        iface_metric: iface_metric_v6.get(&luid).copied().unwrap_or(0),
                        has_unicast_ip: unicast_v6.contains_key(&luid),
                    });
                    gateways_v6.push(gateway);
                }
            }
        }

        let v4 = rank_physical_uplink(&candidates_v4, vdpi_luid).map(|c| {
            let gateway = candidates_v4
                .iter()
                .position(|x| std::ptr::eq(x, c))
                .and_then(|idx| gateways_v4.get(idx).copied())
                .unwrap_or(Ipv4Addr::UNSPECIFIED);
            let mut local_addrs: Vec<IpAddr> = unicast_v4
                .get(&c.luid)
                .map(|ips| ips.iter().copied().map(IpAddr::V4).collect())
                .unwrap_or_default();
            local_addrs.sort_unstable();
            local_addrs.dedup();
            UplinkEndpoint {
                luid: c.luid,
                if_index: c.if_index,
                alias: c.alias.clone(),
                combined_metric: c.combined_metric(),
                gateway: IpAddr::V4(gateway),
                local_addrs,
            }
        });
        let v6 = rank_physical_uplink(&candidates_v6, vdpi_luid).map(|c| {
            let gateway = candidates_v6
                .iter()
                .position(|x| std::ptr::eq(x, c))
                .and_then(|idx| gateways_v6.get(idx).copied())
                .unwrap_or(Ipv6Addr::UNSPECIFIED);
            let mut local_addrs: Vec<IpAddr> = unicast_v6
                .get(&c.luid)
                .map(|ips| ips.iter().copied().map(IpAddr::V6).collect())
                .unwrap_or_default();
            local_addrs.sort_unstable();
            local_addrs.dedup();
            UplinkEndpoint {
                luid: c.luid,
                if_index: c.if_index,
                alias: c.alias.clone(),
                combined_metric: c.combined_metric(),
                gateway: IpAddr::V6(gateway),
                local_addrs,
            }
        });
        let nic_name = v4
            .as_ref()
            .map(|u| u.alias.clone())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                v6.as_ref()
                    .map(|u| u.alias.clone())
                    .filter(|s| !s.is_empty())
            });

        Ok(DetectedUplink { nic_name, v4, v6 })
    }

    fn setupdi_read_property_strings(
        get_prop: SetupDiGetDeviceRegistryPropertyWFn,
        dev_info: *mut c_void,
        dev_data: &SpDevinfoData,
        property: u32,
    ) -> Vec<String> {
        let mut buf = vec![0u16; 256];
        let mut reg_type: u32 = 0;
        let mut required_bytes: u32 = 0;

        let mut ok = unsafe {
            get_prop(
                dev_info,
                dev_data,
                property,
                &mut reg_type,
                buf.as_mut_ptr().cast::<u8>(),
                (buf.len() * mem::size_of::<u16>()) as u32,
                &mut required_bytes,
            )
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_INSUFFICIENT_BUFFER && required_bytes > 0 && required_bytes <= 65_536 {
                let needed_u16 = (required_bytes as usize).div_ceil(mem::size_of::<u16>());
                buf.resize(needed_u16, 0);
                ok = unsafe {
                    get_prop(
                        dev_info,
                        dev_data,
                        property,
                        &mut reg_type,
                        buf.as_mut_ptr().cast::<u8>(),
                        (buf.len() * mem::size_of::<u16>()) as u32,
                        &mut required_bytes,
                    )
                };
            }
        }
        if ok == 0 {
            return Vec::new();
        }
        let u16_len = if required_bytes > 0 {
            ((required_bytes as usize) / mem::size_of::<u16>()).min(buf.len())
        } else {
            buf.len()
        };
        buf[..u16_len]
            .split(|&c| c == 0)
            .filter(|slice| !slice.is_empty())
            .map(String::from_utf16_lossy)
            .collect()
    }

    #[inline]
    fn guids_equal(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    fn format_guid_braced(guid: &GUID) -> String {
        format!(
            "{{{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        )
    }

    fn encode_reg_utf16_bytes(value: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity((value.len() + 1) * 2);
        for unit in value.encode_utf16().chain(std::iter::once(0u16)) {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    fn read_reg_string_value(hkey: HKEY, value_name: &str) -> Option<(String, REG_VALUE_TYPE)> {
        let name_w = encode_wide(value_name);
        let mut reg_type: REG_VALUE_TYPE = 0;
        let mut buf = vec![0u16; 128];
        let mut cb_data = (buf.len() * mem::size_of::<u16>()) as u32;
        let mut status = unsafe {
            RegQueryValueExW(
                hkey,
                name_w.as_ptr(),
                ptr::null(),
                &mut reg_type,
                buf.as_mut_ptr().cast::<u8>(),
                &mut cb_data,
            )
        };
        if status == ERROR_MORE_DATA && cb_data > 0 && cb_data <= 65_536 {
            let needed_u16 = (cb_data as usize).div_ceil(mem::size_of::<u16>());
            buf.resize(needed_u16, 0);
            cb_data = (buf.len() * mem::size_of::<u16>()) as u32;
            status = unsafe {
                RegQueryValueExW(
                    hkey,
                    name_w.as_ptr(),
                    ptr::null(),
                    &mut reg_type,
                    buf.as_mut_ptr().cast::<u8>(),
                    &mut cb_data,
                )
            };
        }
        if status != NO_ERROR || (reg_type != REG_SZ && reg_type != REG_EXPAND_SZ) {
            return None;
        }
        let u16_count = ((cb_data as usize) / mem::size_of::<u16>()).min(buf.len());
        Some((utf16_array_to_string(&buf[..u16_count]), reg_type))
    }

    fn write_reg_string_value(
        hkey: HKEY,
        value_name: &str,
        value: &str,
        reg_type: REG_VALUE_TYPE,
    ) -> Result<()> {
        let name_w = encode_wide(value_name);
        let bytes = encode_reg_utf16_bytes(value);
        let cb_data = u32::try_from(bytes.len())
            .context("registry string value exceeds u32 byte length")?;
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                name_w.as_ptr(),
                0,
                reg_type,
                bytes.as_ptr(),
                cb_data,
            )
        };
        if rc != NO_ERROR {
            bail!("RegSetValueExW({value_name}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn setupdi_read_net_cfg_instance_id(
        open_dev_reg_key: SetupDiOpenDevRegKeyFn,
        dev_info: *mut c_void,
        dev_data: &mut SpDevinfoData,
    ) -> Option<String> {
        let hkey = unsafe {
            open_dev_reg_key(
                dev_info,
                dev_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                KEY_READ,
            )
        };
        if hkey.is_null() || hkey == INVALID_HANDLE_PTR {
            return None;
        }
        let _key_guard = RegKeyGuard(hkey);
        let (text, _) = read_reg_string_value(hkey, "NetCfgInstanceId")?;
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Enumerates all `GUID_DEVCLASS_NET` devices (with `flags = 0`, covering both present and
    /// non-present/phantom nodes) via dynamically loaded `setupapi.dll`.
    ///
    /// When `remove` is `false`, returns `true` on the first matching orphaned `vdpi0` Wintun
    /// device node without mutating anything. When `remove` is `true`, invokes
    /// `SetupDiCallClassInstaller(DIF_REMOVE)` on every matching node and returns `true` if any
    /// device was removed. Never touches third-party Wintun adapters.
    fn scan_orphan_wintun_devices_via_setupapi(remove: bool) -> bool {
        let setupapi_w = encode_wide("setupapi.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                setupapi_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if hmod.is_null() {
            debug!("could not load setupapi.dll for orphan Wintun device inspection");
            return false;
        }
        let _mod_guard = ModuleGuard(hmod);

        let Ok(get_class_devs) =
            (unsafe { load_proc::<SetupDiGetClassDevsWFn>(hmod, c"SetupDiGetClassDevsW") })
        else {
            return false;
        };
        let Ok(destroy_list) = (unsafe {
            load_proc::<SetupDiDestroyDeviceInfoListFn>(hmod, c"SetupDiDestroyDeviceInfoList")
        }) else {
            return false;
        };
        let Ok(enum_dev) =
            (unsafe { load_proc::<SetupDiEnumDeviceInfoFn>(hmod, c"SetupDiEnumDeviceInfo") })
        else {
            return false;
        };
        let Ok(get_prop) = (unsafe {
            load_proc::<SetupDiGetDeviceRegistryPropertyWFn>(
                hmod,
                c"SetupDiGetDeviceRegistryPropertyW",
            )
        }) else {
            return false;
        };
        let call_installer = if remove {
            match unsafe {
                load_proc::<SetupDiCallClassInstallerFn>(hmod, c"SetupDiCallClassInstaller")
            } {
                Ok(f) => Some(f),
                Err(_) => return false,
            }
        } else {
            None
        };
        let set_install_params = if remove {
            unsafe {
                load_proc::<SetupDiSetClassInstallParamsWFn>(hmod, c"SetupDiSetClassInstallParamsW")
                    .ok()
            }
        } else {
            None
        };
        let open_dev_reg_key =
            unsafe { load_proc::<SetupDiOpenDevRegKeyFn>(hmod, c"SetupDiOpenDevRegKey").ok() };

        // Pass flags = 0 (not just DIGCF_PRESENT) so both present and non-present/phantom
        // orphaned `vdpi0` Wintun device nodes in GUID_DEVCLASS_NET are matched.
        let dev_info =
            unsafe { get_class_devs(&GUID_DEVCLASS_NET, ptr::null(), ptr::null_mut(), 0) };
        if dev_info.is_null() || dev_info == INVALID_HANDLE_PTR {
            let err = unsafe { GetLastError() };
            debug!(error = err, "SetupDiGetClassDevsW(GUID_DEVCLASS_NET) failed");
            return false;
        }
        let _list_guard = DevInfoListGuard {
            handle: dev_info,
            destroy: destroy_list,
        };

        let mut matched_or_removed = false;
        let mut index: u32 = 0;
        loop {
            let mut dev_data = SpDevinfoData {
                cb_size: mem::size_of::<SpDevinfoData>() as u32,
                class_guid: GUID::default(),
                dev_inst: 0,
                reserved: 0,
            };
            let ok = unsafe { enum_dev(dev_info, index, &mut dev_data) };
            if ok == 0 {
                break;
            }
            index = index.saturating_add(1);

            let hardware_ids =
                setupdi_read_property_strings(get_prop, dev_info, &dev_data, SPDRP_HARDWAREID);
            let device_descs =
                setupdi_read_property_strings(get_prop, dev_info, &dev_data, SPDRP_DEVICEDESC);
            let friendly_names =
                setupdi_read_property_strings(get_prop, dev_info, &dev_data, SPDRP_FRIENDLYNAME);
            let net_cfg_id = open_dev_reg_key.and_then(|open_fn| {
                setupdi_read_net_cfg_instance_id(open_fn, dev_info, &mut dev_data)
            });

            if !is_orphan_vdpi_wintun_device(
                &hardware_ids,
                device_descs.first().map(String::as_str),
                friendly_names.first().map(String::as_str),
                net_cfg_id.as_deref(),
            ) {
                continue;
            }

            if !remove {
                return true;
            }

            warn!(
                adapter = VDPI_TUN_NAME,
                friendly = ?friendly_names.first(),
                desc = ?device_descs.first(),
                net_cfg_id = ?net_cfg_id,
                "removing orphaned vdpi Wintun device via SetupDiCallClassInstaller(DIF_REMOVE)"
            );

            if let Some(set_params) = set_install_params {
                let params = SpRemoveDeviceParams {
                    class_install_header: SpClassInstallHeader {
                        cb_size: mem::size_of::<SpClassInstallHeader>() as u32,
                        install_function: DIF_REMOVE,
                    },
                    scope: DI_REMOVEDEVICE_GLOBAL,
                    hw_profile: 0,
                };
                let _ = unsafe {
                    set_params(
                        dev_info,
                        &mut dev_data,
                        &params.class_install_header,
                        mem::size_of::<SpRemoveDeviceParams>() as u32,
                    )
                };
            }

            if let Some(installer) = call_installer {
                let rm_ok = unsafe { installer(DIF_REMOVE, dev_info, &mut dev_data) };
                if rm_ok != 0 {
                    matched_or_removed = true;
                } else {
                    let err = unsafe { GetLastError() };
                    warn!(
                        error = err,
                        adapter = VDPI_TUN_NAME,
                        "SetupDiCallClassInstaller(DIF_REMOVE) failed for orphaned vdpi Wintun device"
                    );
                }
            }
        }

        matched_or_removed
    }

    fn remove_orphan_wintun_devices_via_setupapi() -> bool {
        scan_orphan_wintun_devices_via_setupapi(true)
    }

    fn lookup_vdpi_luid_by_guid() -> u64 {
        let mut luid = NET_LUID_LH::default();
        let rc = unsafe { ConvertInterfaceGuidToLuid(&VDPI_WINTUN_GUID, &mut luid) };
        if rc == NO_ERROR {
            unsafe { luid.Value }
        } else {
            0
        }
    }

    fn clear_interface_dns_by_guid(guid: GUID) -> bool {
        let iphlpapi_w = encode_wide("iphlpapi.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                iphlpapi_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if hmod.is_null() {
            return false;
        }
        let _guard = ModuleGuard(hmod);
        let set_dns = match unsafe {
            load_proc::<SetInterfaceDnsSettingsFn>(hmod, c"SetInterfaceDnsSettings")
        } {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut empty_v4 = encode_wide("");
        let settings_v4 = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: u64::from(DNS_SETTING_NAMESERVER),
            NameServer: empty_v4.as_mut_ptr(),
            ..Default::default()
        };
        let rc_v4 = unsafe { set_dns(guid, &settings_v4) };

        let mut empty_v6 = encode_wide("");
        let settings_v6 = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: u64::from(DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER),
            NameServer: empty_v6.as_mut_ptr(),
            ..Default::default()
        };
        let rc_v6 = unsafe { set_dns(guid, &settings_v6) };

        if rc_v4 != NO_ERROR && rc_v4 != ERROR_NOT_FOUND && rc_v4 != ERROR_FILE_NOT_FOUND {
            debug!(
                error = rc_v4,
                "SetInterfaceDnsSettings(clear IPv4 DNS) returned non-fatal error"
            );
        }
        if rc_v6 != NO_ERROR && rc_v6 != ERROR_NOT_FOUND && rc_v6 != ERROR_FILE_NOT_FOUND {
            debug!(
                error = rc_v6,
                "SetInterfaceDnsSettings(clear IPv6 DNS) returned non-fatal error"
            );
        }

        rc_v4 == NO_ERROR || rc_v6 == NO_ERROR
    }

    /// Explicitly removes every IPv4/IPv6 route associated with `luid` (or targeting a vdpi
    /// virtual TUN/DNS next-hop) via `GetIpForwardTable2`/`DeleteIpForwardEntry2` and clears
    /// IPv4 & IPv6 DNS settings on `VDPI_WINTUN_GUID` via `SetInterfaceDnsSettings(empty)`.
    ///
    /// Returns `(routes_removed, dns_cleared)`.
    fn cleanup_vdpi_luid_routes_and_dns(luid: u64) -> (bool, bool) {
        let mut routes_removed = false;

        let mut raw_fwd: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut raw_fwd) };
        if rc == NO_ERROR && !raw_fwd.is_null() {
            let fwd_table = MibTableGuard::new(raw_fwd);
            let fwd_count = unsafe { (*fwd_table.as_ptr()).NumEntries } as usize;
            if fwd_count > 0 {
                let rows = unsafe {
                    let first =
                        ptr::addr_of!((*fwd_table.as_ptr()).Table).cast::<MIB_IPFORWARD_ROW2>();
                    std::slice::from_raw_parts(first, fwd_count)
                };
                for row in rows {
                    let row_luid = unsafe { row.InterfaceLuid.Value };
                    let luid_match = luid != 0 && row_luid == luid;
                    let next_hop_match = match unsafe { row.NextHop.si_family } {
                        AF_INET => {
                            let nh = in_addr_to_ipv4(unsafe { row.NextHop.Ipv4.sin_addr });
                            nh == VDPI_TUN_IPV4 || nh == VDPI_TUN_DNS_V4
                        }
                        AF_INET6 => {
                            let nh = Ipv6Addr::from(unsafe { row.NextHop.Ipv6.sin6_addr.u.Byte });
                            nh == VDPI_TUN_IPV6 || nh == VDPI_TUN_DNS_V6
                        }
                        _ => false,
                    };
                    if !luid_match && !next_hop_match {
                        continue;
                    }
                    let del_rc = unsafe { DeleteIpForwardEntry2(row) };
                    if del_rc == NO_ERROR {
                        routes_removed = true;
                    } else if del_rc != ERROR_NOT_FOUND {
                        debug!(
                            luid = row_luid,
                            error = del_rc,
                            "DeleteIpForwardEntry2 returned non-fatal error during vdpi route teardown"
                        );
                    }
                }
            }
        }

        let mut dns_cleared = clear_interface_dns_by_guid(VDPI_WINTUN_GUID);
        if luid != 0 {
            let net_luid = NET_LUID_LH { Value: luid };
            let mut luid_guid = GUID::default();
            if unsafe { ConvertInterfaceLuidToGuid(&net_luid, &mut luid_guid) } == NO_ERROR
                && !guids_equal(&luid_guid, &VDPI_WINTUN_GUID)
                && clear_interface_dns_by_guid(luid_guid)
            {
                dns_cleared = true;
            }
        }

        (routes_removed, dns_cleared)
    }

    /// Deletes residual `NameServer` / `DhcpNameServer` values (and removes the interface subkey
    /// if empty) under `Tcpip` and `Tcpip6` `Parameters\Interfaces\{VDPI_WINTUN_GUID}` via
    /// native Advapi32 (`RegDeleteValueW` / `RegDeleteKeyW`), ignoring `ERROR_FILE_NOT_FOUND`.
    fn delete_residual_vdpi_tcpip_interface_keys() -> bool {
        let mut changed = false;

        for parent in [TCPIP_INTERFACES_SUBKEY, TCPIP6_INTERFACES_SUBKEY] {
            let subkey = format!(r"{parent}\{VDPI_WINTUN_GUID_STR}");
            let subkey_w = encode_wide(&subkey);
            let mut hkey: HKEY = ptr::null_mut();
            let open_rc = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    subkey_w.as_ptr(),
                    0,
                    KEY_QUERY_VALUE | KEY_SET_VALUE,
                    &mut hkey,
                )
            };
            if open_rc == ERROR_FILE_NOT_FOUND || open_rc == ERROR_PATH_NOT_FOUND {
                continue;
            }
            if open_rc != NO_ERROR {
                debug!(
                    subkey = %subkey,
                    error = open_rc,
                    "RegOpenKeyExW failed during residual vdpi Tcpip interface key cleanup"
                );
                continue;
            }

            let is_empty = {
                let key_guard = RegKeyGuard(hkey);
                for value_name in ["NameServer", "DhcpNameServer"] {
                    let value_w = encode_wide(value_name);
                    let del_val_rc = unsafe { RegDeleteValueW(key_guard.0, value_w.as_ptr()) };
                    if del_val_rc == NO_ERROR {
                        changed = true;
                    } else if del_val_rc != ERROR_FILE_NOT_FOUND {
                        debug!(
                            subkey = %subkey,
                            value = value_name,
                            error = del_val_rc,
                            "RegDeleteValueW returned non-fatal error during vdpi Tcpip cleanup"
                        );
                    }
                }

                let mut subkey_count: u32 = 0;
                let mut value_count: u32 = 0;
                let info_rc = unsafe {
                    RegQueryInfoKeyW(
                        key_guard.0,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null(),
                        &mut subkey_count,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        &mut value_count,
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                info_rc == NO_ERROR && subkey_count == 0 && value_count == 0
            };

            if is_empty {
                let del_key_rc = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, subkey_w.as_ptr()) };
                if del_key_rc == NO_ERROR {
                    changed = true;
                } else if del_key_rc != ERROR_FILE_NOT_FOUND && del_key_rc != ERROR_PATH_NOT_FOUND {
                    debug!(
                        subkey = %subkey,
                        error = del_key_rc,
                        "RegDeleteKeyW returned non-fatal error for empty vdpi Tcpip interface key"
                    );
                }
            }
        }

        changed
    }

    /// Attempts to unload/remove the Wintun kernel driver via optional `WintunDeleteDriver` when
    /// no Wintun adapter holds a reference. Wintun itself refcounts safely, so this is a no-op if
    /// another Wintun adapter (WireGuard, Tailscale, Mullvad, etc.) is active.
    pub fn try_delete_unused_wintun_driver() -> bool {
        let Ok(wintun) = WintunApi::load_verified() else {
            return false;
        };
        let Some(delete_driver) = wintun.delete_driver else {
            return false;
        };
        let ok = unsafe { delete_driver() };
        if ok != 0 {
            debug!("WintunDeleteDriver removed unused Wintun kernel driver");
            true
        } else {
            let err = unsafe { GetLastError() };
            debug!(
                error = err,
                "WintunDeleteDriver did not remove driver (in use or already absent)"
            );
            false
        }
    }

    /// Returns `true` when an orphaned `vdpi0` Wintun LUID, `GetIfTable2` alias/GUID entry, or
    /// present/phantom SetupAPI `GUID_DEVCLASS_NET` device node exists on the host.
    pub fn has_orphan_wintun_device_or_luid() -> bool {
        if lookup_vdpi_luid_by_guid() != 0 {
            return true;
        }

        let mut raw_if_table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        let rc = unsafe { GetIfTable2(&mut raw_if_table) };
        if rc == NO_ERROR && !raw_if_table.is_null() {
            let if_table = MibTableGuard::new(raw_if_table);
            let if_count = unsafe { (*if_table.as_ptr()).NumEntries } as usize;
            if if_count > 0 {
                let rows = unsafe {
                    let first = ptr::addr_of!((*if_table.as_ptr()).Table).cast::<MIB_IF_ROW2>();
                    std::slice::from_raw_parts(first, if_count)
                };
                for row in rows {
                    if guids_equal(&row.InterfaceGuid, &VDPI_WINTUN_GUID)
                        || utf16_array_to_string(&row.Alias).eq_ignore_ascii_case(VDPI_TUN_NAME)
                    {
                        return true;
                    }
                }
            }
        }

        scan_orphan_wintun_devices_via_setupapi(false)
    }

    /// Best-effort cleanup of an orphaned `vdpi0` Wintun adapter left behind by an abrupt
    /// process termination (e.g. `TerminateProcess` or `taskkill /F`).
    ///
    /// Resolves the `vdpi0` LUID via `ConvertInterfaceGuidToLuid(&VDPI_WINTUN_GUID)` even if
    /// `WintunOpenAdapter` or `wintun.dll` loading fails (e.g. Defender quarantine), explicitly
    /// deletes routes and DNS BEFORE closing any open Wintun handle, runs SetupAPI `DIF_REMOVE`
    /// (`flags = 0`) for present and phantom device nodes, deletes residual Tcpip/Tcpip6
    /// registry keys, and always flushes the Windows DNS resolver cache. Returns `true` when any
    /// orphaned adapter, route, DNS entry, or registry state was cleaned.
    pub fn cleanup_orphan_wintun_adapter() -> bool {
        let mut cleaned = false;
        let mut luid = lookup_vdpi_luid_by_guid();
        let mut routes_dns_cleaned = false;

        if let Ok(wintun) = WintunApi::load_verified() {
            let name_w = encode_wide(VDPI_TUN_NAME);
            let handle = unsafe { (wintun.open_adapter)(name_w.as_ptr()) };
            if !handle.is_null() {
                if luid == 0 {
                    let mut luid_raw = NET_LUID_LH::default();
                    unsafe { (wintun.get_adapter_luid)(handle, &mut luid_raw) };
                    luid = unsafe { luid_raw.Value };
                }
                warn!(
                    adapter = VDPI_TUN_NAME,
                    luid,
                    "found orphaned Wintun adapter via WintunOpenAdapter; cleaning routes/DNS and closing handle"
                );
                let _ = cleanup_vdpi_luid_routes_and_dns(luid);
                routes_dns_cleaned = true;
                unsafe { (wintun.close_adapter)(handle) };
                cleaned = true;
            }
        }

        if !routes_dns_cleaned {
            let (routes_removed, dns_cleared) = cleanup_vdpi_luid_routes_and_dns(luid);
            if routes_removed || dns_cleared {
                cleaned = true;
            }
        }

        if remove_orphan_wintun_devices_via_setupapi() {
            cleaned = true;
        }

        if delete_residual_vdpi_tcpip_interface_keys() {
            cleaned = true;
        }

        flush_dns_resolver_cache();
        cleaned
    }

    /// Performs a full Windows TUN and DNS reset:
    /// 1. Cleans up `vdpi0` LUID routes/DNS, closes any orphaned Wintun adapter and SetupAPI
    ///    nodes, deletes residual `vdpi0` Tcpip/Tcpip6 interface keys, and attempts
    ///    `try_delete_unused_wintun_driver()`.
    /// 2. Scans `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` and
    ///    `Tcpip6\Parameters\Interfaces` via `RegEnumKeyExW`, stripping `198.18.0.2` or
    ///    `fd00:7664:7069::2` from any interface `NameServer` value.
    /// 3. Always flushes the Windows DNS resolver cache.
    ///
    /// Returns `(tun_changed, dns_override_changed, errors)`.
    pub fn reset_windows_tun_and_dns_defaults() -> (bool, bool, Vec<String>) {
        let mut tun_changed = false;
        let mut dns_override_changed = false;
        let mut errors: Vec<String> = Vec::new();

        let luid = lookup_vdpi_luid_by_guid();
        let (routes_removed, dns_cleared) = cleanup_vdpi_luid_routes_and_dns(luid);
        if routes_removed || dns_cleared {
            tun_changed = true;
        }
        if cleanup_orphan_wintun_adapter() {
            tun_changed = true;
        }
        if delete_residual_vdpi_tcpip_interface_keys() {
            tun_changed = true;
        }
        if try_delete_unused_wintun_driver() {
            tun_changed = true;
        }

        for parent_path in [TCPIP_INTERFACES_SUBKEY, TCPIP6_INTERFACES_SUBKEY] {
            let parent_w = encode_wide(parent_path);
            let mut parent_hkey: HKEY = ptr::null_mut();
            let open_rc = unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    parent_w.as_ptr(),
                    0,
                    KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                    &mut parent_hkey,
                )
            };
            if open_rc == ERROR_FILE_NOT_FOUND || open_rc == ERROR_PATH_NOT_FOUND {
                continue;
            }
            if open_rc != NO_ERROR {
                errors.push(format!(
                    "RegOpenKeyExW(HKLM\\{parent_path}) failed with Win32 error {open_rc}"
                ));
                continue;
            }
            let parent_guard = RegKeyGuard(parent_hkey);

            let mut name_buf = vec![0u16; 260];
            let mut index: u32 = 0;
            while index < 65_536 {
                let mut name_len = name_buf.len() as u32;
                let enum_rc = unsafe {
                    RegEnumKeyExW(
                        parent_guard.0,
                        index,
                        name_buf.as_mut_ptr(),
                        &mut name_len,
                        ptr::null(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if enum_rc == ERROR_NO_MORE_ITEMS {
                    break;
                }
                if enum_rc == ERROR_MORE_DATA {
                    if name_buf.len() >= 4096 {
                        index = index.saturating_add(1);
                        continue;
                    }
                    name_buf.resize(name_buf.len() * 2, 0);
                    continue;
                }
                let cur_index = index;
                index = index.saturating_add(1);
                if enum_rc != NO_ERROR {
                    errors.push(format!(
                        "RegEnumKeyExW(HKLM\\{parent_path}, index={cur_index}) failed with Win32 error {enum_rc}"
                    ));
                    continue;
                }

                let subkey_name =
                    String::from_utf16_lossy(&name_buf[..(name_len as usize).min(name_buf.len())]);
                if subkey_name.is_empty() {
                    continue;
                }

                let subkey_w = encode_wide(&subkey_name);
                let mut sub_hkey: HKEY = ptr::null_mut();
                let sub_open_rc = unsafe {
                    RegOpenKeyExW(
                        parent_guard.0,
                        subkey_w.as_ptr(),
                        0,
                        KEY_QUERY_VALUE,
                        &mut sub_hkey,
                    )
                };
                if sub_open_rc != NO_ERROR {
                    continue;
                }
                let sub_guard = RegKeyGuard(sub_hkey);

                let Some((current_ns, reg_kind)) = read_reg_string_value(sub_guard.0, "NameServer")
                else {
                    continue;
                };
                let Some(cleaned_ns) = strip_vdpi_dns_servers(&current_ns) else {
                    continue;
                };
                drop(sub_guard);

                let mut write_hkey: HKEY = ptr::null_mut();
                let write_open_rc = unsafe {
                    RegOpenKeyExW(
                        parent_guard.0,
                        subkey_w.as_ptr(),
                        0,
                        KEY_SET_VALUE,
                        &mut write_hkey,
                    )
                };
                if write_open_rc != NO_ERROR {
                    errors.push(format!(
                        "RegOpenKeyExW(HKLM\\{parent_path}\\{subkey_name}, KEY_SET_VALUE) failed with Win32 error {write_open_rc}"
                    ));
                    continue;
                }
                let write_guard = RegKeyGuard(write_hkey);
                if let Err(err) =
                    write_reg_string_value(write_guard.0, "NameServer", &cleaned_ns, reg_kind)
                {
                    errors.push(format!(
                        "failed to clean vdpi DNS from HKLM\\{parent_path}\\{subkey_name}\\NameServer: {err:#}"
                    ));
                } else {
                    info!(
                        path = %format!(r"HKLM\{parent_path}\{subkey_name}"),
                        before = %current_ns,
                        after = %cleaned_ns,
                        "stripped residual vdpi DNS server from Windows interface NameServer"
                    );
                    dns_override_changed = true;
                }
            }
        }

        flush_dns_resolver_cache();
        (tun_changed, dns_override_changed, errors)
    }

    fn create_or_recreate_adapter(wintun: &Arc<WintunApi>) -> Result<AdapterGuard> {
        let name_w = encode_wide(VDPI_TUN_NAME);
        let tunnel_type_w = encode_wide(VDPI_WINTUN_TUNNEL_TYPE);

        // If an abrupt termination (e.g. Defender TerminateProcess or taskkill /F) left an
        // orphaned zombie `vdpi0` adapter behind, clean its routes/DNS, open and close it
        // cleanly (and remove any lingering PnP node via SetupAPI) before creating a fresh adapter.
        let orphan = unsafe { (wintun.open_adapter)(name_w.as_ptr()) };
        if !orphan.is_null() {
            warn!(
                adapter = VDPI_TUN_NAME,
                "closing orphaned Wintun adapter left from a previous run before recreating"
            );
            let mut luid_raw = NET_LUID_LH::default();
            unsafe { (wintun.get_adapter_luid)(orphan, &mut luid_raw) };
            let _ = cleanup_vdpi_luid_routes_and_dns(unsafe { luid_raw.Value });
            unsafe { (wintun.close_adapter)(orphan) };
            let _ = remove_orphan_wintun_devices_via_setupapi();
            let _ = delete_residual_vdpi_tcpip_interface_keys();
        }

        let mut handle = unsafe {
            (wintun.create_adapter)(name_w.as_ptr(), tunnel_type_w.as_ptr(), &VDPI_WINTUN_GUID)
        };
        let mut last_err = if handle.is_null() {
            unsafe { GetLastError() }
        } else {
            NO_ERROR
        };

        for (attempt, &delay_ms) in ADAPTER_RETRY_DELAYS_MS.iter().enumerate() {
            if !handle.is_null() || !is_retryable_adapter_create_error(last_err) {
                break;
            }
            warn!(
                adapter = VDPI_TUN_NAME,
                attempt = attempt + 1,
                delay_ms,
                error = last_err,
                error_hex = %format!("{last_err:#010x}"),
                "stale Wintun adapter still tearing down; running SetupAPI cleanup and retrying"
            );
            let stale = unsafe { (wintun.open_adapter)(name_w.as_ptr()) };
            if !stale.is_null() {
                let mut luid_raw = NET_LUID_LH::default();
                unsafe { (wintun.get_adapter_luid)(stale, &mut luid_raw) };
                let _ = cleanup_vdpi_luid_routes_and_dns(unsafe { luid_raw.Value });
                unsafe { (wintun.close_adapter)(stale) };
            }
            let _ = remove_orphan_wintun_devices_via_setupapi();
            let _ = delete_residual_vdpi_tcpip_interface_keys();
            thread::sleep(Duration::from_millis(delay_ms));
            handle = unsafe {
                (wintun.create_adapter)(name_w.as_ptr(), tunnel_type_w.as_ptr(), &VDPI_WINTUN_GUID)
            };
            if handle.is_null() {
                last_err = unsafe { GetLastError() };
            }
        }

        if handle.is_null() {
            if last_err == ERROR_ACCESS_DENIED {
                bail!(
                    "WintunCreateAdapter({VDPI_TUN_NAME}) failed with Win32 error {last_err} \
                     (Administrator privileges are required to create a Wintun interface)"
                );
            }
            if is_retryable_adapter_create_error(last_err) {
                bail!(
                    "WintunCreateAdapter({VDPI_TUN_NAME}) failed with Win32 error {last_err} \
                     ({last_err:#010x}) after {} retries",
                    ADAPTER_RETRY_DELAYS_MS.len()
                );
            }
            bail!("WintunCreateAdapter({VDPI_TUN_NAME}) failed with Win32 error {last_err}");
        }

        Ok(AdapterGuard {
            wintun: Arc::clone(wintun),
            handle: SendHandle(handle),
        })
    }

    fn assign_ipv4_address(vdpi_luid: u64, ip: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: ipv4_to_in_addr(ip),
            ..Default::default()
        };
        row.OnLinkPrefixLength = prefix_len;
        row.DadState = IpDadStatePreferred;
        let rc = unsafe { CreateUnicastIpAddressEntry(&row) };
        if rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS {
            bail!("CreateUnicastIpAddressEntry({ip}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn assign_ipv6_address(vdpi_luid: u64, ip: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.Address.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(ip),
            ..Default::default()
        };
        row.OnLinkPrefixLength = prefix_len;
        row.DadState = IpDadStatePreferred;
        let rc = unsafe { CreateUnicastIpAddressEntry(&row) };
        if rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS {
            bail!("CreateUnicastIpAddressEntry({ip}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn delete_ipv6_address(vdpi_luid: u64, ip: Ipv6Addr) -> Result<()> {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.Address.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(ip),
            ..Default::default()
        };
        let rc = unsafe { DeleteUnicastIpAddressEntry(&row) };
        if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
            bail!("DeleteUnicastIpAddressEntry({ip}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn configure_ip_interface(vdpi_luid: u64, family: u16, mtu: u32, metric: u32) -> Result<()> {
        let mut if_row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut if_row) };
        if_row.Family = family;
        if_row.InterfaceLuid.Value = vdpi_luid;
        let rc = unsafe { GetIpInterfaceEntry(&mut if_row) };
        if rc != NO_ERROR {
            bail!("GetIpInterfaceEntry(family={family}) failed with Win32 error {rc}");
        }
        if family == AF_INET {
            // Mandatory on IPv4: GetIpInterfaceEntry leaves SitePrefixLength set to 0xFFFFFFFF,
            // which causes SetIpInterfaceEntry to fail with ERROR_INVALID_PARAMETER (87).
            if_row.SitePrefixLength = 0;
        }
        if_row.NlMtu = mtu;
        if_row.UseAutomaticMetric = false;
        if_row.Metric = metric;
        let rc = unsafe { SetIpInterfaceEntry(&mut if_row) };
        if rc != NO_ERROR {
            bail!("SetIpInterfaceEntry(family={family}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn add_ipv4_route(vdpi_luid: u64, dest: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.DestinationPrefix.Prefix.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: ipv4_to_in_addr(dest),
            ..Default::default()
        };
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.NextHop.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: ipv4_to_in_addr(Ipv4Addr::UNSPECIFIED),
            ..Default::default()
        };
        row.Metric = 0;
        let rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS {
            bail!("CreateIpForwardEntry2({dest}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn delete_ipv4_route(vdpi_luid: u64, dest: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.DestinationPrefix.Prefix.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: ipv4_to_in_addr(dest),
            ..Default::default()
        };
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.NextHop.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: ipv4_to_in_addr(Ipv4Addr::UNSPECIFIED),
            ..Default::default()
        };
        let rc = unsafe { DeleteIpForwardEntry2(&row) };
        if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
            bail!("DeleteIpForwardEntry2({dest}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn add_ipv6_route(vdpi_luid: u64, dest: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.DestinationPrefix.Prefix.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(dest),
            ..Default::default()
        };
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.NextHop.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(Ipv6Addr::UNSPECIFIED),
            ..Default::default()
        };
        row.Metric = 0;
        let rc = unsafe { CreateIpForwardEntry2(&row) };
        if rc != NO_ERROR && rc != ERROR_OBJECT_ALREADY_EXISTS {
            bail!("CreateIpForwardEntry2({dest}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn delete_ipv6_route(vdpi_luid: u64, dest: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid.Value = vdpi_luid;
        row.DestinationPrefix.Prefix.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(dest),
            ..Default::default()
        };
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.NextHop.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: ipv6_to_in6_addr(Ipv6Addr::UNSPECIFIED),
            ..Default::default()
        };
        let rc = unsafe { DeleteIpForwardEntry2(&row) };
        if rc != NO_ERROR && rc != ERROR_NOT_FOUND {
            bail!("DeleteIpForwardEntry2({dest}/{prefix_len}) failed with Win32 error {rc}");
        }
        Ok(())
    }

    fn set_interface_dns_via_registry(guid: &GUID, is_v6: bool, name_server: &str) -> Result<()> {
        let parent = if is_v6 {
            TCPIP6_INTERFACES_SUBKEY
        } else {
            TCPIP_INTERFACES_SUBKEY
        };
        let guid_str = format_guid_braced(guid);
        let subkey = format!(r"{parent}\{guid_str}");
        let subkey_w = encode_wide(&subkey);
        let mut hkey: HKEY = ptr::null_mut();
        let open_rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey_w.as_ptr(),
                0,
                KEY_SET_VALUE,
                &mut hkey,
            )
        };
        if open_rc != NO_ERROR {
            if name_server.is_empty()
                && (open_rc == ERROR_FILE_NOT_FOUND || open_rc == ERROR_PATH_NOT_FOUND)
            {
                return Ok(());
            }
            bail!("RegOpenKeyExW(HKLM\\{subkey}, KEY_SET_VALUE) failed with Win32 error {open_rc}");
        }
        let key_guard = RegKeyGuard(hkey);
        write_reg_string_value(key_guard.0, "NameServer", name_server, REG_SZ)?;
        debug!(
            subkey = %subkey,
            name_server = %name_server,
            ipv6 = is_v6,
            "updated interface DNS NameServer via Advapi32 registry fallback"
        );
        Ok(())
    }

    /// Configures a static IPv4 or IPv6 DNS server on `vdpi0` via dynamically loaded
    /// `SetInterfaceDnsSettings` (Windows 10 2004+ / Windows 11), retrying briefly on
    /// `ERROR_NOT_FOUND` and falling back directly to Advapi32 `RegSetValueExW` on
    /// `Tcpip{,6}\Parameters\Interfaces\{GUID}\NameServer` if `SetInterfaceDnsSettings` is
    /// unavailable on older Windows builds.
    fn configure_interface_dns(vdpi_luid: u64, dns_server: IpAddr) -> Result<()> {
        let luid = NET_LUID_LH { Value: vdpi_luid };
        let mut guid = GUID::default();
        let rc = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if rc != NO_ERROR {
            bail!("ConvertInterfaceLuidToGuid failed with Win32 error {rc}");
        }

        let is_v6 = dns_server.is_ipv6();
        let iphlpapi_w = encode_wide("iphlpapi.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                iphlpapi_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if !hmod.is_null() {
            let _guard = ModuleGuard(hmod);
            if let Ok(set_dns) =
                unsafe { load_proc::<SetInterfaceDnsSettingsFn>(hmod, c"SetInterfaceDnsSettings") }
            {
                let mut dns_w = encode_wide(&dns_server.to_string());
                let flags = if is_v6 {
                    u64::from(DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER)
                } else {
                    u64::from(DNS_SETTING_NAMESERVER)
                };
                let settings = DNS_INTERFACE_SETTINGS {
                    Version: DNS_INTERFACE_SETTINGS_VERSION1,
                    Flags: flags,
                    NameServer: dns_w.as_mut_ptr(),
                    ..Default::default()
                };
                let mut status = unsafe { set_dns(guid, &settings) };
                for &delay_ms in DNS_NOT_FOUND_RETRY_DELAYS_MS {
                    if status != ERROR_NOT_FOUND {
                        break;
                    }
                    debug!(
                        dns = %dns_server,
                        ipv6 = is_v6,
                        delay_ms,
                        "SetInterfaceDnsSettings returned ERROR_NOT_FOUND; retrying"
                    );
                    thread::sleep(Duration::from_millis(delay_ms));
                    status = unsafe { set_dns(guid, &settings) };
                }
                if status == NO_ERROR {
                    debug!(
                        dns = %dns_server,
                        ipv6 = is_v6,
                        "configured vdpi0 DNS via SetInterfaceDnsSettings"
                    );
                    return Ok(());
                }
                bail!("SetInterfaceDnsSettings({dns_server}) failed with Win32 error {status}");
            }
        }

        // Pre-2004 Windows 10 fallback when `SetInterfaceDnsSettings` is unavailable:
        // write `NameServer` directly via Advapi32 without spawning any child process.
        set_interface_dns_via_registry(&guid, is_v6, &dns_server.to_string())
    }

    fn configure_interface_dns_v4(vdpi_luid: u64, dns_server: Ipv4Addr) -> Result<()> {
        configure_interface_dns(vdpi_luid, IpAddr::V4(dns_server))
    }

    fn configure_interface_dns_v6(vdpi_luid: u64, dns_server: Ipv6Addr) -> Result<()> {
        configure_interface_dns(vdpi_luid, IpAddr::V6(dns_server))
    }

    /// Clears static IPv6 DNS servers on `vdpi0` via `SetInterfaceDnsSettings` (empty
    /// `NameServer` with `DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER`), falling back directly
    /// to Advapi32 `RegSetValueExW` on `Tcpip6\Parameters\Interfaces\{GUID}\NameServer` if
    /// `SetInterfaceDnsSettings` is unavailable.
    fn clear_interface_dns_v6(vdpi_luid: u64) -> Result<()> {
        let luid = NET_LUID_LH { Value: vdpi_luid };
        let mut guid = GUID::default();
        let rc = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if rc != NO_ERROR {
            bail!("ConvertInterfaceLuidToGuid failed with Win32 error {rc}");
        }

        let iphlpapi_w = encode_wide("iphlpapi.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                iphlpapi_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if !hmod.is_null() {
            let _guard = ModuleGuard(hmod);
            if let Ok(set_dns) =
                unsafe { load_proc::<SetInterfaceDnsSettingsFn>(hmod, c"SetInterfaceDnsSettings") }
            {
                let mut empty_w = encode_wide("");
                let settings = DNS_INTERFACE_SETTINGS {
                    Version: DNS_INTERFACE_SETTINGS_VERSION1,
                    Flags: u64::from(DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER),
                    NameServer: empty_w.as_mut_ptr(),
                    ..Default::default()
                };
                let status = unsafe { set_dns(guid, &settings) };
                if status == NO_ERROR || status == ERROR_NOT_FOUND {
                    debug!("cleared vdpi0 IPv6 DNS via SetInterfaceDnsSettings");
                    return Ok(());
                }
                bail!("SetInterfaceDnsSettings(clear IPv6 DNS) failed with Win32 error {status}");
            }
        }

        // Pre-2004 Windows 10 fallback when `SetInterfaceDnsSettings` is unavailable.
        set_interface_dns_via_registry(&guid, true, "")
    }

    /// Applies a [`TunRoamingPlan`] to `vdpi0` using make-before-break ordering (enabling the
    /// incoming address family before tearing down the outgoing one) and updates `ipv6_active`.
    fn apply_tun_roaming_plan(
        vdpi_luid: u64,
        mut state: TunStackState,
        plan: TunRoamingPlan,
        ipv6_active: &AtomicBool,
    ) -> TunStackState {
        if plan.add_ipv4_routes {
            let mut all_ok = true;
            for &(dest, prefix_len) in PUBLIC_IPV4_COMPLEMENT_CIDRS {
                if let Err(err) = add_ipv4_route(vdpi_luid, dest, prefix_len) {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        dest = %dest,
                        prefix_len,
                        error = %err,
                        "failed to add IPv4 route on vdpi0 during uplink roaming"
                    );
                    all_ok = false;
                    break;
                }
            }
            if all_ok {
                state.ipv4_routes_installed = true;
            }
        }

        if plan.enable_ipv6 {
            let enable_res = (|| -> Result<()> {
                assign_ipv6_address(vdpi_luid, VDPI_TUN_IPV6, VDPI_TUN_PREFIX_V6)?;
                configure_ip_interface(vdpi_luid, AF_INET6, VDPI_TUN_MTU, VDPI_INTERFACE_METRIC)?;
                configure_interface_dns_v6(vdpi_luid, VDPI_TUN_DNS_V6)?;
                for &(dest, prefix_len) in VDPI_IPV6_TUN_ROUTES {
                    add_ipv6_route(vdpi_luid, dest, prefix_len)?;
                }
                Ok(())
            })();
            match enable_res {
                Ok(()) => {
                    state.ipv6_active = true;
                    ipv6_active.store(true, Ordering::Release);
                }
                Err(err) => {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        error = %err,
                        "failed to enable IPv6 on vdpi0 during uplink roaming; rolling back partial IPv6 config"
                    );
                    for &(dest, prefix_len) in VDPI_IPV6_TUN_ROUTES {
                        let _ = delete_ipv6_route(vdpi_luid, dest, prefix_len);
                    }
                    let _ = clear_interface_dns_v6(vdpi_luid);
                    let _ = delete_ipv6_address(vdpi_luid, VDPI_TUN_IPV6);
                    state.ipv6_active = false;
                    ipv6_active.store(false, Ordering::Release);
                }
            }
        }

        if plan.remove_ipv4_routes {
            let mut all_ok = true;
            for &(dest, prefix_len) in PUBLIC_IPV4_COMPLEMENT_CIDRS {
                if let Err(err) = delete_ipv4_route(vdpi_luid, dest, prefix_len) {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        dest = %dest,
                        prefix_len,
                        error = %err,
                        "failed to remove IPv4 route from vdpi0 during uplink roaming"
                    );
                    all_ok = false;
                }
            }
            if all_ok {
                state.ipv4_routes_installed = false;
            }
        }

        if plan.disable_ipv6 {
            let mut route_ok = true;
            for &(dest, prefix_len) in VDPI_IPV6_TUN_ROUTES {
                if let Err(err) = delete_ipv6_route(vdpi_luid, dest, prefix_len) {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        dest = %dest,
                        prefix_len,
                        error = %err,
                        "failed to remove IPv6 route from vdpi0 during uplink roaming"
                    );
                    route_ok = false;
                }
            }
            let dns_ok = match clear_interface_dns_v6(vdpi_luid) {
                Ok(()) => true,
                Err(err) => {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        error = %err,
                        "failed to clear IPv6 DNS on vdpi0 during uplink roaming"
                    );
                    false
                }
            };
            let addr_ok = match delete_ipv6_address(vdpi_luid, VDPI_TUN_IPV6) {
                Ok(()) => true,
                Err(err) => {
                    warn!(
                        iface = VDPI_TUN_NAME,
                        error = %err,
                        "failed to remove IPv6 address from vdpi0 during uplink roaming"
                    );
                    false
                }
            };
            if route_ok {
                ipv6_active.store(false, Ordering::Release);
            }
            if route_ok && dns_ok && addr_ok {
                state.ipv6_active = false;
            }
        }

        state
    }

    /// Best-effort call to `DnsFlushResolverCache()` in `dnsapi.dll`.
    ///
    /// Clears stale ISP-poisoned DNS entries from Windows `Dnscache` so browsers (such as Chrome)
    /// drop pre-TUN sockets and pick up the TUN interface immediately without a restart.
    fn flush_dns_resolver_cache() {
        let dnsapi_w = encode_wide("dnsapi.dll");
        let hmod = unsafe {
            LoadLibraryExW(
                dnsapi_w.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if hmod.is_null() {
            debug!("could not load dnsapi.dll to flush DNS resolver cache");
            return;
        }
        let _guard = ModuleGuard(hmod);
        if let Ok(flush_fn) =
            unsafe { load_proc::<DnsFlushResolverCacheFn>(hmod, c"DnsFlushResolverCache") }
        {
            let ok = unsafe { flush_fn() };
            debug!(ok = (ok != 0), "invoked DnsFlushResolverCache()");
        }
    }

    /// Lock-free shared state read inside the `NotifyRouteChange2` callback.
    struct RouteNotifyContext {
        vdpi_luid: u64,
        generation: AtomicU64,
        force_reconcile_gen: AtomicU64,
        wake_event: SendHandle,
    }

    impl Drop for RouteNotifyContext {
        fn drop(&mut self) {
            if !self.wake_event.is_null() {
                unsafe {
                    let _ = CloseHandle(self.wake_event.as_raw());
                }
                self.wake_event = SendHandle(ptr::null_mut());
            }
        }
    }

    /// Wrapper making the raw callback context pointer `Send` for storage on [`WindowsTunSession`].
    struct NotifyCtxPtr(*const RouteNotifyContext);

    // SAFETY: The raw pointer was produced via `Arc::into_raw` and is only reclaimed via
    // `Arc::from_raw` in `WindowsTunSession::drop` AFTER `CancelMibChangeNotify2` guarantees
    // that no further Windows callbacks can observe it.
    unsafe impl Send for NotifyCtxPtr {}

    /// Lock-free `NotifyRouteChange2` callback: never calls any `iphlpapi` function,
    /// ignores mutations on `vdpi_luid`, and signals the off-callback debounce thread.
    unsafe extern "system" fn route_change_callback(
        caller_context: *const c_void,
        row: *const MIB_IPFORWARD_ROW2,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if caller_context.is_null() {
            return;
        }
        let ctx = &*caller_context.cast::<RouteNotifyContext>();
        if !row.is_null() {
            let row_luid = (*row).InterfaceLuid.Value;
            if row_luid == ctx.vdpi_luid {
                return;
            }
        }
        ctx.generation.fetch_add(1, Ordering::SeqCst);
        let _ = SetEvent(ctx.wake_event.as_raw());
    }

    /// Lock-free `NotifyUnicastIpAddressChange` callback: never calls any `iphlpapi` function,
    /// ignores mutations on `vdpi_luid`, and signals the off-callback debounce thread so DAD
    /// tentative-to-preferred transitions on Wi-Fi/Hotspot/Ethernet handoff immediately wake
    /// uplink detection.
    unsafe extern "system" fn unicast_ip_change_callback(
        caller_context: *const c_void,
        row: *const MIB_UNICASTIPADDRESS_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        if caller_context.is_null() {
            return;
        }
        let ctx = &*caller_context.cast::<RouteNotifyContext>();
        if !row.is_null() {
            let row_luid = (*row).InterfaceLuid.Value;
            if row_luid == ctx.vdpi_luid {
                return;
            }
        }
        ctx.generation.fetch_add(1, Ordering::SeqCst);
        let _ = SetEvent(ctx.wake_event.as_raw());
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_route_watcher_thread(
        ctx: Arc<RouteNotifyContext>,
        stop_event: SendHandle,
        stop_flag: Arc<AtomicBool>,
        binder: Arc<DynamicOutboundBinder>,
        route_tx: watch::Sender<u64>,
        vdpi_luid: u64,
        initial_uplink: UplinkSignature,
        tun_ipv6: bool,
        initial_stack_state: TunStackState,
        ipv6_active: Arc<AtomicBool>,
    ) -> Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("vdpi-route-watch".to_string())
            .spawn(move || {
                let handles = [ctx.wake_event.as_raw(), stop_event.as_raw()];
                let mut route_epoch: u64 = 0;
                let mut last_sig = initial_uplink;
                let mut stack_state = initial_stack_state;
                let mut last_force_gen: u64 = 0;

                loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let wait =
                        unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if wait != WAIT_OBJECT_0 || stop_flag.load(Ordering::Acquire) {
                        break;
                    }

                    // Coalesce bursty Windows route-table transitions (e.g. Wi-Fi <-> Ethernet).
                    let burst_start = Instant::now();
                    let mut last_gen = ctx.generation.load(Ordering::Acquire);
                    loop {
                        let debounce_wait = unsafe {
                            WaitForSingleObject(stop_event.as_raw(), ROUTE_DEBOUNCE_WINDOW_MS)
                        };
                        if debounce_wait == WAIT_OBJECT_0 || stop_flag.load(Ordering::Acquire) {
                            return;
                        }
                        let next_gen = ctx.generation.load(Ordering::Acquire);
                        if next_gen == last_gen || burst_start.elapsed() >= ROUTE_DEBOUNCE_MAX_WAIT
                        {
                            last_gen = next_gen;
                            break;
                        }
                        last_gen = next_gen;
                    }

                    let cur_force_gen = ctx.force_reconcile_gen.load(Ordering::SeqCst);
                    let forced = cur_force_gen != last_force_gen;
                    last_force_gen = cur_force_gen;

                    // Clear any wake signal latched during the debounce window to prevent a
                    // spurious second re-detection, re-checking `generation` so concurrent
                    // callbacks arriving before `ResetEvent` are never missed.
                    unsafe {
                        let _ = ResetEvent(ctx.wake_event.as_raw());
                    }
                    if ctx.generation.load(Ordering::SeqCst) != last_gen {
                        unsafe {
                            let _ = SetEvent(ctx.wake_event.as_raw());
                        }
                    }

                    match detect_physical_uplink(vdpi_luid) {
                        Ok(uplink) => {
                            let next_sig = uplink.signature();
                            let target = uplink.to_outbound_target();
                            let prev = binder.snapshot();
                            let roaming_plan = plan_tun_roaming_transition(
                                stack_state,
                                tun_ipv6,
                                uplink.v4.is_some(),
                                uplink.v6.is_some(),
                            );
                            let uplink_changed = next_sig != last_sig
                                || target != prev
                                || roaming_plan.has_changes();
                            if uplink_changed || forced {
                                if uplink_changed {
                                    info!(
                                        nic = ?target.nic_name,
                                        if_v4 = ?target.if_index_v4,
                                        if_v6 = ?target.if_index_v6,
                                        gw_v4 = ?uplink.v4.as_ref().map(|u| u.gateway),
                                        gw_v6 = ?uplink.v6.as_ref().map(|u| u.gateway),
                                        addrs_v4 = ?uplink.v4.as_ref().map(|u| u.local_addrs.as_slice()),
                                        addrs_v6 = ?uplink.v6.as_ref().map(|u| u.local_addrs.as_slice()),
                                        "Windows physical uplink changed; updated outbound binder"
                                    );
                                } else {
                                    info!(
                                        nic = ?target.nic_name,
                                        if_v4 = ?target.if_index_v4,
                                        if_v6 = ?target.if_index_v6,
                                        "forced Windows uplink reconciliation triggered"
                                    );
                                }
                                binder.update(target);
                                last_sig = next_sig;
                                if roaming_plan.has_changes() {
                                    let prev_v4_routes = stack_state.ipv4_routes_installed;
                                    let prev_ipv6 = stack_state.ipv6_active;
                                    stack_state = apply_tun_roaming_plan(
                                        vdpi_luid,
                                        stack_state,
                                        roaming_plan,
                                        &ipv6_active,
                                    );
                                    info!(
                                        iface = VDPI_TUN_NAME,
                                        prev_v4_routes,
                                        next_v4_routes = stack_state.ipv4_routes_installed,
                                        prev_ipv6,
                                        next_ipv6 = stack_state.ipv6_active,
                                        "reconciled vdpi0 IPv4/IPv6 routes and DNS after uplink roaming"
                                    );
                                    if stack_state != roaming_plan.next_state {
                                        warn!(
                                            iface = VDPI_TUN_NAME,
                                            actual_v4_routes = stack_state.ipv4_routes_installed,
                                            desired_v4_routes = roaming_plan.next_state.ipv4_routes_installed,
                                            actual_ipv6 = stack_state.ipv6_active,
                                            desired_ipv6 = roaming_plan.next_state.ipv6_active,
                                            "partial vdpi0 roaming reconciliation; will retry on next uplink event"
                                        );
                                    }
                                }
                                flush_dns_resolver_cache();
                                route_epoch = route_epoch.saturating_add(1);
                                let _ = route_tx.send(route_epoch);
                            } else {
                                debug!(
                                    nic = ?target.nic_name,
                                    "route change observed; active physical uplink unchanged"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to re-detect physical uplink after route change");
                            if forced {
                                route_epoch = route_epoch.saturating_add(1);
                                let _ = route_tx.send(route_epoch);
                            }
                        }
                    }
                }
            })
            .context("failed to spawn Windows route watcher thread")
    }

    /// Spawns the Wintun RX reader thread at normal OS priority (never elevated above MMCSS
    /// audio threads such as VoiceMeeter).
    fn spawn_rx_thread(
        wintun: Arc<WintunApi>,
        session: SendHandle,
        read_event: SendHandle,
        stop_event: SendHandle,
        stop_flag: Arc<AtomicBool>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
    ) -> Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("vdpi-wintun-rx".to_string())
            .spawn(move || {
                let handles = [read_event.as_raw(), stop_event.as_raw()];
                let mut burst: Vec<Vec<u8>> = Vec::with_capacity(RX_BURST_LIMIT);

                'outer: loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }

                    // Drain queued IP packets in full bursts from WintunReceivePacket until the
                    // ring reports ERROR_NO_MORE_ITEMS before waiting on WaitForMultipleObjects.
                    loop {
                        burst.clear();
                        let mut ring_empty = false;

                        while burst.len() < RX_BURST_LIMIT {
                            if stop_flag.load(Ordering::Acquire) {
                                break 'outer;
                            }
                            let mut pkt_size: u32 = 0;
                            let pkt_ptr =
                                unsafe { (wintun.receive_packet)(session.as_raw(), &mut pkt_size) };
                            if !pkt_ptr.is_null() {
                                let pkt = unsafe {
                                    std::slice::from_raw_parts(pkt_ptr, pkt_size as usize).to_vec()
                                };
                                // Release ring slot immediately before touching the async channel.
                                unsafe {
                                    (wintun.release_receive_packet)(session.as_raw(), pkt_ptr);
                                }
                                burst.push(pkt);
                                continue;
                            }

                            let err = unsafe { GetLastError() };
                            if err == ERROR_NO_MORE_ITEMS {
                                ring_empty = true;
                                break;
                            }
                            if err == ERROR_HANDLE_EOF {
                                debug!("Wintun RX ring reached EOF; exiting RX thread");
                                break 'outer;
                            }
                            warn!(error = err, "WintunReceivePacket failed; exiting RX thread");
                            break 'outer;
                        }

                        for pkt in burst.drain(..) {
                            match inbound_tx.try_send(pkt) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(pkt)) => {
                                    // Backpressure rather than silently dropping TCP segments
                                    // (smoltcp lacks sender SACK, so a single drop triggers an RTO stall).
                                    if stop_flag.load(Ordering::Acquire) {
                                        break 'outer;
                                    }
                                    if inbound_tx.blocking_send(pkt).is_err() {
                                        break 'outer;
                                    }
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break 'outer;
                                }
                            }
                        }

                        if ring_empty {
                            break;
                        }
                    }

                    let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if wait == WAIT_OBJECT_0 {
                        continue;
                    }
                    if wait == WAIT_OBJECT_0 + 1 {
                        break;
                    }
                    let err = unsafe { GetLastError() };
                    warn!(
                        wait,
                        error = err,
                        "WaitForMultipleObjects failed in Wintun RX"
                    );
                    break;
                }
            })
            .context("failed to spawn Wintun RX thread")
    }

    fn send_wintun_packet(
        wintun: &WintunApi,
        session: SendHandle,
        stop_flag: &AtomicBool,
        pkt: &[u8],
        yielded_in_burst: &mut bool,
    ) -> bool {
        if pkt.is_empty() || pkt.len() > WINTUN_MAX_IP_PACKET_SIZE {
            return true;
        }
        let mut dst = unsafe { (wintun.allocate_send_packet)(session.as_raw(), pkt.len() as u32) };
        if dst.is_null() {
            let mut err = unsafe { GetLastError() };
            if err == ERROR_BUFFER_OVERFLOW {
                if stop_flag.load(Ordering::Acquire) {
                    return false;
                }
                // With a 16 MiB ring, overflow only happens under true saturation. Yield at most
                // once per drained burst (never per-packet up to TX_BATCH_LIMIT times, and never
                // with microsecond sleeps or spin loops that spike Windows DPC/audio latency such
                // as VoiceMeeter), then tail-drop fast so TCP congestion control adapts naturally.
                if !*yielded_in_burst {
                    *yielded_in_burst = true;
                    thread::yield_now();
                    dst = unsafe {
                        (wintun.allocate_send_packet)(session.as_raw(), pkt.len() as u32)
                    };
                    if dst.is_null() {
                        err = unsafe { GetLastError() };
                    }
                }
            }
            if dst.is_null() {
                if err == ERROR_BUFFER_OVERFLOW {
                    trace!(
                        len = pkt.len(),
                        "Wintun TX ring full; tail-dropping outbound packet"
                    );
                    return true;
                }
                if err == ERROR_HANDLE_EOF {
                    debug!("Wintun TX ring reached EOF; exiting TX thread");
                    return false;
                }
                warn!(error = err, "WintunAllocateSendPacket failed");
                return true;
            }
        }
        unsafe {
            ptr::copy_nonoverlapping(pkt.as_ptr(), dst, pkt.len());
            (wintun.send_packet)(session.as_raw(), dst);
        }
        true
    }

    /// Spawns the Wintun TX writer thread at normal OS priority (never elevated above MMCSS
    /// audio threads such as VoiceMeeter).
    fn spawn_tx_thread(
        wintun: Arc<WintunApi>,
        session: SendHandle,
        stop_flag: Arc<AtomicBool>,
        mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("vdpi-wintun-tx".to_string())
            .spawn(move || {
                let mut batch: Vec<Vec<u8>> = Vec::with_capacity(TX_BATCH_LIMIT);
                'outer: loop {
                    batch.clear();
                    let count = outbound_rx.blocking_recv_many(&mut batch, TX_BATCH_LIMIT);
                    if count == 0 || stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let mut yielded_in_burst = false;
                    for pkt in batch.drain(..) {
                        if stop_flag.load(Ordering::Acquire) {
                            break 'outer;
                        }
                        if !send_wintun_packet(
                            &wintun,
                            session,
                            &stop_flag,
                            &pkt,
                            &mut yielded_in_burst,
                        ) {
                            break 'outer;
                        }
                    }
                }
            })
            .context("failed to spawn Wintun TX thread")
    }

    /// Running Windows Wintun transparent TUN session with live physical uplink tracking
    /// and deterministic resource teardown on [`Drop`].
    pub struct WindowsTunSession {
        binder: Arc<DynamicOutboundBinder>,
        wintun: Arc<WintunApi>,
        adapter: SendHandle,
        session: SendHandle,
        stop_event: SendHandle,
        stop_flag: Arc<AtomicBool>,
        outbound_tx_wake: Option<mpsc::Sender<Vec<u8>>>,
        notify_ctx: Arc<RouteNotifyContext>,
        notify_handle: Option<SendHandle>,
        notify_ctx_raw: Option<NotifyCtxPtr>,
        unicast_notify_handle: Option<SendHandle>,
        unicast_notify_ctx_raw: Option<NotifyCtxPtr>,
        route_thread: Option<JoinHandle<()>>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
        vdpi_luid: u64,
        ipv6_active: Arc<AtomicBool>,
    }

    /// Tuple returned by [`WindowsTunSession::start`]: the running session handle,
    /// inbound packet receiver, outbound packet sender, and route-change watcher.
    pub type WindowsTunStartParts = (
        WindowsTunSession,
        mpsc::Receiver<Vec<u8>>,
        mpsc::Sender<Vec<u8>>,
        watch::Receiver<u64>,
    );

    impl WindowsTunSession {
        /// Starts the `vdpi0` Wintun adapter, configures IP/MTU/DNS and disjoint public routes
        /// strictly on `vdpi0`, binds `binder` to the active physical uplink, and launches
        /// dedicated RX, TX, and `NotifyRouteChange2` + `NotifyUnicastIpAddressChange` watcher
        /// threads.
        pub fn start(
            binder: Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
        ) -> Result<WindowsTunStartParts> {
            if !crate::platform::windows_service::is_elevated() {
                bail!(
                    "Administrator privileges are required to start Windows TUN mode ({VDPI_TUN_NAME}); \
                     re-run from an elevated Administrator terminal or use the Windows service"
                );
            }

            // Preflight physical uplink detection BEFORE creating/recreating the kernel `vdpi0`
            // adapter so airplane-mode / offline standby retries never churn Wintun adapters.
            let preflight_uplink = detect_physical_uplink(0)?;
            if preflight_uplink.v4.is_none() && preflight_uplink.v6.is_none() {
                bail!(
                    "no active physical network uplink detected; connect to Wi-Fi or Ethernet and retry"
                );
            }

            let wintun = WintunApi::load_verified()?;
            let adapter_guard = create_or_recreate_adapter(&wintun)?;

            let mut luid_raw = NET_LUID_LH::default();
            unsafe { (wintun.get_adapter_luid)(adapter_guard.handle.as_raw(), &mut luid_raw) };
            let vdpi_luid = unsafe { luid_raw.Value };
            if vdpi_luid == 0 {
                bail!("WintunGetAdapterLUID returned zero LUID");
            }

            // Detect physical uplink BEFORE installing any routes on `vdpi0`.
            let uplink = detect_physical_uplink(vdpi_luid)?;
            if uplink.v4.is_none() && uplink.v6.is_none() {
                bail!(
                    "no active physical network uplink detected; connect to Wi-Fi or Ethernet and retry"
                );
            }
            let initial_uplink_sig = uplink.signature();
            binder.update(uplink.to_outbound_target());
            let mut binder_guard = BinderResetGuard {
                binder: Some(Arc::clone(&binder)),
            };
            info!(
                nic = ?uplink.nic_name,
                v4_if = ?uplink.v4.as_ref().map(|u| (u.if_index, u.luid, u.combined_metric, u.gateway)),
                v6_if = ?uplink.v6.as_ref().map(|u| (u.if_index, u.luid, u.combined_metric, u.gateway)),
                "detected Windows physical uplink"
            );

            // Configure `vdpi0` IPv4 address, MTU, metric, DNS, and (when an IPv4 uplink exists)
            // disjoint public routes. On IPv6-only uplinks (`uplink.v4.is_none()`), skip
            // `PUBLIC_IPV4_COMPLEMENT_CIDRS` so Windows never funnels unroutable IPv4 traffic into
            // `vdpi0`.
            assign_ipv4_address(vdpi_luid, VDPI_TUN_IPV4, VDPI_TUN_PREFIX_V4)?;
            configure_ip_interface(vdpi_luid, AF_INET, VDPI_TUN_MTU, VDPI_INTERFACE_METRIC)?;
            configure_interface_dns_v4(vdpi_luid, VDPI_TUN_DNS_V4)?;
            let routes_v4_installed = if uplink.v4.is_some() {
                for &(dest, prefix_len) in PUBLIC_IPV4_COMPLEMENT_CIDRS {
                    add_ipv4_route(vdpi_luid, dest, prefix_len)?;
                }
                PUBLIC_IPV4_COMPLEMENT_CIDRS.len()
            } else {
                info!(
                    iface = VDPI_TUN_NAME,
                    "IPv6-only physical uplink detected; skipping PUBLIC_IPV4_COMPLEMENT_CIDRS installation"
                );
                0
            };

            // Configure IPv6 ULA, DNS, global unicast (`2000::/3`), and RFC 6052 NAT64
            // (`64:ff9b::/96`) routes when requested and backed by an active global-unicast IPv6
            // uplink, or automatically on an IPv6-only uplink (`uplink.v4.is_none() &&
            // uplink.v6.is_some()`).
            let ipv6_only_uplink = uplink.v4.is_none() && uplink.v6.is_some();
            let ipv6_enabled =
                should_enable_tun_ipv6(tun_ipv6, uplink.v4.is_some(), uplink.v6.is_some());
            if ipv6_only_uplink && !tun_ipv6 {
                info!(
                    iface = VDPI_TUN_NAME,
                    "IPv6-only physical uplink detected; auto-enabling IPv6 on Wintun adapter"
                );
            }
            if ipv6_enabled {
                assign_ipv6_address(vdpi_luid, VDPI_TUN_IPV6, VDPI_TUN_PREFIX_V6)?;
                configure_ip_interface(vdpi_luid, AF_INET6, VDPI_TUN_MTU, VDPI_INTERFACE_METRIC)?;
                configure_interface_dns_v6(vdpi_luid, VDPI_TUN_DNS_V6)?;
                for &(dest, prefix_len) in VDPI_IPV6_TUN_ROUTES {
                    add_ipv6_route(vdpi_luid, dest, prefix_len)?;
                }
            }
            let initial_stack_state = TunStackState {
                ipv4_routes_installed: uplink.v4.is_some(),
                ipv6_active: ipv6_enabled,
            };
            let ipv6_active = Arc::new(AtomicBool::new(ipv6_enabled));

            // Start Wintun packet ring session (16 MiB per ring).
            let raw_session = unsafe {
                (wintun.start_session)(adapter_guard.handle.as_raw(), WINTUN_RING_CAPACITY)
            };
            if raw_session.is_null() {
                let err = unsafe { GetLastError() };
                bail!("WintunStartSession failed with Win32 error {err}");
            }
            let session_guard = SessionGuard {
                wintun: Arc::clone(&wintun),
                handle: SendHandle(raw_session),
            };

            let read_event =
                SendHandle(unsafe { (wintun.get_read_wait_event)(session_guard.handle.as_raw()) });
            if read_event.is_null() {
                let err = unsafe { GetLastError() };
                bail!("WintunGetReadWaitEvent returned null (Win32 error {err})");
            }

            let stop_event = OwnedEvent::new(true)?;
            let stop_flag = Arc::new(AtomicBool::new(false));
            let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(TUN_CHANNEL_CAPACITY);
            let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL_CAPACITY);
            let outbound_tx_wake = outbound_tx.clone();
            let (route_tx, route_rx) = watch::channel::<u64>(0);

            // Register live `NotifyRouteChange2` + `NotifyUnicastIpAddressChange` watchers
            // before spawning I/O threads so both route transitions and DAD tentative-to-preferred
            // transitions immediately wake uplink detection.
            let route_wake_event = OwnedEvent::new(false)?;
            let notify_ctx = Arc::new(RouteNotifyContext {
                vdpi_luid,
                generation: AtomicU64::new(0),
                force_reconcile_gen: AtomicU64::new(0),
                wake_event: route_wake_event.into_raw(),
            });
            let cb_ctx_raw = Arc::into_raw(Arc::clone(&notify_ctx));
            let mut notify_handle: HANDLE = ptr::null_mut();
            let rc = unsafe {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(route_change_callback),
                    cb_ctx_raw.cast(),
                    false,
                    &mut notify_handle,
                )
            };
            if rc != NO_ERROR {
                unsafe { drop(Arc::from_raw(cb_ctx_raw)) };
                bail!("NotifyRouteChange2 failed with Win32 error {rc}");
            }

            let unicast_cb_ctx_raw = Arc::into_raw(Arc::clone(&notify_ctx));
            let mut unicast_notify_handle: HANDLE = ptr::null_mut();
            let rc = unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(unicast_ip_change_callback),
                    unicast_cb_ctx_raw.cast(),
                    false,
                    &mut unicast_notify_handle,
                )
            };
            if rc != NO_ERROR {
                unsafe { drop(Arc::from_raw(unicast_cb_ctx_raw)) };
                let cancel_rc = unsafe { CancelMibChangeNotify2(notify_handle) };
                if cancel_rc == NO_ERROR {
                    unsafe { drop(Arc::from_raw(cb_ctx_raw)) };
                } else {
                    warn!(
                        error = cancel_rc,
                        "CancelMibChangeNotify2 failed during rollback; leaking route callback context Arc to prevent UAF"
                    );
                }
                bail!("NotifyUnicastIpAddressChange failed with Win32 error {rc}");
            }

            // Construct the session immediately so Drop handles clean rollback if any thread
            // spawn fails.
            let mut tun_session = Self {
                binder: Arc::clone(&binder),
                wintun: Arc::clone(&wintun),
                adapter: adapter_guard.into_raw(),
                session: session_guard.into_raw(),
                stop_event: stop_event.into_raw(),
                stop_flag: Arc::clone(&stop_flag),
                outbound_tx_wake: Some(outbound_tx_wake),
                notify_ctx: Arc::clone(&notify_ctx),
                notify_handle: Some(SendHandle(notify_handle)),
                notify_ctx_raw: Some(NotifyCtxPtr(cb_ctx_raw)),
                unicast_notify_handle: Some(SendHandle(unicast_notify_handle)),
                unicast_notify_ctx_raw: Some(NotifyCtxPtr(unicast_cb_ctx_raw)),
                route_thread: None,
                rx_thread: None,
                tx_thread: None,
                vdpi_luid,
                ipv6_active: Arc::clone(&ipv6_active),
            };
            binder_guard.disarm();

            tun_session.route_thread = Some(spawn_route_watcher_thread(
                notify_ctx,
                tun_session.stop_event,
                Arc::clone(&stop_flag),
                binder,
                route_tx,
                vdpi_luid,
                initial_uplink_sig,
                tun_ipv6,
                initial_stack_state,
                ipv6_active,
            )?);
            tun_session.rx_thread = Some(spawn_rx_thread(
                Arc::clone(&wintun),
                tun_session.session,
                read_event,
                tun_session.stop_event,
                Arc::clone(&stop_flag),
                inbound_tx,
            )?);
            tun_session.tx_thread = Some(spawn_tx_thread(
                wintun,
                tun_session.session,
                stop_flag,
                outbound_rx,
            )?);

            // Flush Windows Dnscache once routes, DNS, and Wintun I/O threads are live so
            // browsers immediately drop stale ISP-poisoned DNS entries and pre-TUN sockets.
            flush_dns_resolver_cache();

            info!(
                iface = VDPI_TUN_NAME,
                ipv4 = %VDPI_TUN_IPV4,
                dns = %VDPI_TUN_DNS_V4,
                dns_v6 = ?ipv6_enabled.then_some(VDPI_TUN_DNS_V6),
                routes_v4 = routes_v4_installed,
                ipv6 = ipv6_enabled,
                "Windows Wintun transparent TUN session started"
            );

            Ok((tun_session, inbound_rx, outbound_tx, route_rx))
        }

        /// Wakes the route-watcher thread to immediately re-evaluate the physical uplink and
        /// bump the `route_tx` watch channel (used on Windows sleep/wake `PBT_APMRESUME*`
        /// events so uplink bindings refresh and stale UDP NAT sessions drain promptly).
        pub fn force_reconcile_uplink(&self) {
            if self.stop_flag.load(Ordering::Acquire) {
                return;
            }
            self.notify_ctx
                .force_reconcile_gen
                .fetch_add(1, Ordering::SeqCst);
            self.notify_ctx.generation.fetch_add(1, Ordering::SeqCst);
            if !self.notify_ctx.wake_event.is_null() {
                unsafe {
                    let _ = SetEvent(self.notify_ctx.wake_event.as_raw());
                }
            }
        }

        /// Returns `true` when IPv6 routing (`2000::/3`, `64:ff9b::/96`) and DNS are active on
        /// `vdpi0`.
        pub fn is_ipv6_active(&self) -> bool {
            self.ipv6_active.load(Ordering::Acquire)
        }

        /// Returns the current physical uplink adapter label (updated live on NIC switches).
        pub fn physical_nic_name(&self) -> Option<String> {
            self.binder.physical_nic_name()
        }

        /// Returns the Wintun interface name (`"vdpi0"`).
        pub fn iface_name(&self) -> &'static str {
            VDPI_TUN_NAME
        }
    }

    impl Drop for WindowsTunSession {
        fn drop(&mut self) {
            debug!(
                iface = VDPI_TUN_NAME,
                luid = self.vdpi_luid,
                ipv6 = self.ipv6_active.load(Ordering::Acquire),
                "tearing down Windows Wintun session"
            );

            // 1. Unregister route-change and unicast-IP notifications FIRST so Windows drains
            //    and halts all callbacks before we reclaim each callback context. If cancellation
            //    fails, intentionally leak that callback Arc so late OS callbacks can never UAF.
            let cancel_notify = |handle_opt: &mut Option<SendHandle>,
                                 ctx_opt: &mut Option<NotifyCtxPtr>,
                                 kind: &str| {
                let cancelled_cleanly = match handle_opt.take().filter(|h| !h.is_null()) {
                    Some(handle) => {
                        let rc = unsafe { CancelMibChangeNotify2(handle.as_raw()) };
                        if rc == NO_ERROR {
                            true
                        } else {
                            warn!(
                                kind,
                                error = rc,
                                "CancelMibChangeNotify2 failed; leaking callback context Arc to prevent UAF"
                            );
                            false
                        }
                    }
                    None => true,
                };
                if let Some(NotifyCtxPtr(raw)) = ctx_opt
                    .take()
                    .filter(|p| cancelled_cleanly && !p.0.is_null())
                {
                    unsafe { drop(Arc::from_raw(raw)) };
                }
            };
            cancel_notify(&mut self.notify_handle, &mut self.notify_ctx_raw, "route");
            cancel_notify(
                &mut self.unicast_notify_handle,
                &mut self.unicast_notify_ctx_raw,
                "unicast-ip",
            );

            // 2. Signal all worker threads to stop and wake RX, TX, and route watcher threads.
            self.stop_flag.store(true, Ordering::Release);
            if !self.stop_event.is_null() {
                unsafe {
                    let _ = SetEvent(self.stop_event.as_raw());
                }
            }
            if let Some(wake_tx) = self.outbound_tx_wake.take() {
                let _ = wake_tx.try_send(Vec::new());
                drop(wake_tx);
            }

            // 3. Join all threads before closing the Wintun session or adapter.
            if let Some(handle) = self.route_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.rx_thread.take() {
                let _ = handle.join();
            }
            if let Some(handle) = self.tx_thread.take() {
                let _ = handle.join();
            }

            // 4. End Wintun session, explicitly delete `vdpi0` routes & DNS BEFORE closing the
            //    adapter, close adapter, clean residual Tcpip/Tcpip6 interface keys, close stop
            //    event, reset the outbound binder, and always flush the DNS resolver cache.
            if !self.session.is_null() {
                unsafe { (self.wintun.end_session)(self.session.as_raw()) };
                self.session = SendHandle(ptr::null_mut());
            }
            let _ = cleanup_vdpi_luid_routes_and_dns(self.vdpi_luid);
            if !self.adapter.is_null() {
                unsafe { (self.wintun.close_adapter)(self.adapter.as_raw()) };
                self.adapter = SendHandle(ptr::null_mut());
            }
            let _ = delete_residual_vdpi_tcpip_interface_keys();
            if !self.stop_event.is_null() {
                unsafe {
                    let _ = CloseHandle(self.stop_event.as_raw());
                }
                self.stop_event = SendHandle(ptr::null_mut());
            }

            // Reset binder so yielded/standby state does not remain pinned with
            // `fail_closed: true` to the previous physical interface.
            self.binder.update(OutboundTarget::default());

            flush_dns_resolver_cache();
        }
    }
}

#[cfg(target_os = "windows")]
pub use win32::{
    cleanup_orphan_wintun_adapter, has_orphan_wintun_device_or_luid,
    reset_windows_tun_and_dns_defaults, try_delete_unused_wintun_driver, WindowsTunSession,
    WindowsTunStartParts,
};

#[cfg(not(target_os = "windows"))]
/// No-op on non-Windows platforms.
pub fn cleanup_orphan_wintun_adapter() -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
/// No-op on non-Windows platforms.
pub fn has_orphan_wintun_device_or_luid() -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
/// No-op on non-Windows platforms.
pub fn reset_windows_tun_and_dns_defaults() -> (bool, bool, Vec<String>) {
    (false, false, Vec::new())
}

#[cfg(not(target_os = "windows"))]
/// No-op on non-Windows platforms.
pub fn try_delete_unused_wintun_driver() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn cidr_bounds(net: Ipv4Addr, prefix: u8) -> (u32, u32) {
        assert!((1..=32).contains(&prefix), "invalid prefix /{prefix}");
        let mask = u32::MAX << (32 - prefix);
        let start = u32::from(net);
        assert_eq!(
            start & !mask,
            0,
            "CIDR {net}/{prefix} has non-zero host bits"
        );
        let end = start | !mask;
        (start, end)
    }

    fn cidrs_overlap(a: (Ipv4Addr, u8), b: (Ipv4Addr, u8)) -> bool {
        let (a_start, a_end) = cidr_bounds(a.0, a.1);
        let (b_start, b_end) = cidr_bounds(b.0, b.1);
        a_start <= b_end && b_start <= a_end
    }

    fn cidr_size(prefix: u8) -> u64 {
        1u64 << (32 - u32::from(prefix))
    }

    #[test]
    fn pinned_wintun_constants_are_valid_sha256_and_expected_tun_addrs() {
        assert_eq!(WINTUN_VERSION, "0.14.1");
        assert_eq!(WINTUN_ZIP_SHA256.len(), 64);
        assert!(WINTUN_ZIP_SHA256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(WINTUN_DLL_AMD64_SHA256.len(), 64);
        assert!(WINTUN_DLL_AMD64_SHA256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(WINTUN_DLL_ARM64_SHA256.len(), 64);
        assert!(WINTUN_DLL_ARM64_SHA256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_ne!(WINTUN_DLL_AMD64_SHA256, WINTUN_DLL_ARM64_SHA256);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            expected_wintun_dll_sha256().unwrap(),
            WINTUN_DLL_AMD64_SHA256
        );
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            expected_wintun_dll_sha256().unwrap(),
            WINTUN_DLL_ARM64_SHA256
        );
        assert_eq!(VDPI_TUN_NAME, "vdpi0");
        assert_eq!(VDPI_TUN_IPV4, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(VDPI_TUN_DNS_V4, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(
            VDPI_TUN_DNS_V6,
            Ipv6Addr::new(0xfd00, 0x7664, 0x7069, 0, 0, 0, 0, 2)
        );
        assert_eq!(VDPI_TUN_DNS_V6.to_string(), "fd00:7664:7069::2");
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        assert_eq!(VDPI_TUN_MTU, vdpi_tun::config::DESKTOP_MTU as u32);
    }

    #[test]
    fn public_ipv4_complement_exact_disjoint_partition_of_entire_ipv4_space() {
        // 1. Pairwise disjointness across all public complement CIDRs.
        for (i, &a) in PUBLIC_IPV4_COMPLEMENT_CIDRS.iter().enumerate() {
            for &b in &PUBLIC_IPV4_COMPLEMENT_CIDRS[i + 1..] {
                assert!(
                    !cidrs_overlap(a, b),
                    "public CIDRs {}/{} and {}/{} overlap",
                    a.0,
                    a.1,
                    b.0,
                    b.1
                );
            }
        }

        // 2. Pairwise disjointness between every public CIDR and every excluded CIDR.
        for &pub_cidr in PUBLIC_IPV4_COMPLEMENT_CIDRS {
            for &ex_cidr in EXCLUDED_IPV4_CIDRS {
                assert!(
                    !cidrs_overlap(pub_cidr, ex_cidr),
                    "public CIDR {}/{} overlaps excluded CIDR {}/{}",
                    pub_cidr.0,
                    pub_cidr.1,
                    ex_cidr.0,
                    ex_cidr.1
                );
            }
        }

        // 3. Exact cardinality proof: |public| + |excluded| == 2^32.
        let public_count: u64 = PUBLIC_IPV4_COMPLEMENT_CIDRS
            .iter()
            .map(|&(_, p)| cidr_size(p))
            .sum();
        let excluded_count: u64 = EXCLUDED_IPV4_CIDRS.iter().map(|&(_, p)| cidr_size(p)).sum();
        assert_eq!(
            public_count + excluded_count,
            1u64 << 32,
            "public ({public_count}) + excluded ({excluded_count}) must equal 2^32"
        );
    }

    #[test]
    fn public_ipv4_complement_routes_public_and_excludes_all_private_and_special_ips() {
        let must_route = [
            Ipv4Addr::new(1, 0, 0, 0),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(9, 255, 255, 255),
            Ipv4Addr::new(11, 0, 0, 0),
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 0),
            Ipv4Addr::new(126, 255, 255, 255),
            Ipv4Addr::new(128, 0, 0, 0),
            Ipv4Addr::new(128, 116, 5, 33),
            Ipv4Addr::new(162, 159, 135, 232),
            Ipv4Addr::new(169, 253, 255, 255),
            Ipv4Addr::new(169, 255, 0, 0),
            Ipv4Addr::new(172, 15, 255, 255),
            Ipv4Addr::new(172, 32, 0, 0),
            Ipv4Addr::new(192, 0, 1, 0),
            Ipv4Addr::new(192, 167, 255, 255),
            Ipv4Addr::new(192, 169, 0, 0),
            Ipv4Addr::new(198, 18, 0, 2),
            Ipv4Addr::new(223, 255, 255, 255),
        ];
        for ip in must_route {
            assert!(
                is_routed_public_ipv4(ip),
                "expected public IP {ip} to be routed via vdpi0"
            );
        }

        let must_exclude = [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 255, 255, 255),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 255, 255, 254),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 127, 255, 254),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(127, 255, 255, 254),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(169, 254, 255, 254),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(172, 31, 255, 254),
            Ipv4Addr::new(192, 0, 0, 0),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 0, 0, 170),
            Ipv4Addr::new(192, 0, 0, 255),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 255, 254),
            Ipv4Addr::new(224, 0, 0, 251),
            Ipv4Addr::new(239, 255, 255, 250),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 255),
        ];
        for ip in must_exclude {
            assert!(
                !is_routed_public_ipv4(ip),
                "expected private/reserved IP {ip} to be excluded from vdpi0"
            );
        }
    }

    #[test]
    fn rank_physical_uplink_skips_virtual_vpn_loopback_vdpi_and_picks_lowest_metric() {
        let vdpi_luid = 0xAA00_0001;
        let candidates = vec![
            UplinkCandidate {
                luid: vdpi_luid,
                if_index: 2,
                alias: "vdpi0".into(),
                description: "vdpi Tunnel".into(),
                if_type: NDIS_IF_TYPE_ETHERNET,
                is_up: true,
                route_metric: 0,
                iface_metric: 5,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x1001,
                if_index: 1,
                alias: "Loopback Pseudo-Interface 1".into(),
                description: "Software Loopback Interface 1".into(),
                if_type: NDIS_IF_TYPE_LOOPBACK,
                is_up: true,
                route_metric: 0,
                iface_metric: 1,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x1002,
                if_index: 9,
                alias: "vEthernet (WSL)".into(),
                description: "Hyper-V Virtual Ethernet Adapter".into(),
                if_type: NDIS_IF_TYPE_ETHERNET,
                is_up: true,
                route_metric: 0,
                iface_metric: 10,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x1003,
                if_index: 10,
                alias: "wg0".into(),
                description: "WireGuard Tunnel".into(),
                if_type: NDIS_IF_TYPE_PROP_VIRTUAL,
                is_up: true,
                route_metric: 0,
                iface_metric: 5,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x1004,
                if_index: 11,
                alias: "Ethernet 2".into(),
                description: "Realtek PCIe GbE Family Controller".into(),
                if_type: NDIS_IF_TYPE_ETHERNET,
                is_up: false,
                route_metric: 0,
                iface_metric: 5,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x1005,
                if_index: 12,
                alias: "Ethernet 3".into(),
                description: "Intel(R) Ethernet Controller I225-V".into(),
                if_type: NDIS_IF_TYPE_ETHERNET,
                is_up: true,
                route_metric: 0,
                iface_metric: 10,
                has_unicast_ip: false,
            },
            UplinkCandidate {
                luid: 0x2001,
                if_index: 15,
                alias: "Wi-Fi".into(),
                description: "Intel(R) Wi-Fi 6E AX211 160MHz".into(),
                if_type: NDIS_IF_TYPE_WIFI,
                is_up: true,
                route_metric: 0,
                iface_metric: 45,
                has_unicast_ip: true,
            },
            UplinkCandidate {
                luid: 0x2002,
                if_index: 14,
                alias: "Ethernet".into(),
                description: "Realtek Gaming 2.5GbE Family Controller".into(),
                if_type: NDIS_IF_TYPE_ETHERNET,
                is_up: true,
                route_metric: 5,
                iface_metric: 25,
                has_unicast_ip: true,
            },
        ];

        let winner = rank_physical_uplink(&candidates, vdpi_luid).expect("physical uplink");
        assert_eq!(winner.alias, "Ethernet");
        assert_eq!(winner.if_index, 14);
        assert_eq!(winner.combined_metric(), 30);

        // When only virtual/down adapters remain, ranking returns None.
        assert!(rank_physical_uplink(&candidates[..6], vdpi_luid).is_none());
    }

    #[test]
    fn resolve_wintun_dll_candidates_supports_winget_symlinks_and_deduplicates() {
        let links_dir = PathBuf::from("C:/Users/Arda/AppData/Local/Microsoft/WinGet/Links");
        let pkg_dir =
            PathBuf::from("C:/Users/Arda/AppData/Local/Microsoft/WinGet/Packages/VulnInc.vdpi");
        let shim = links_dir.join("vdpi.exe");
        let real = PathBuf::from(
            r"\\?\C:/Users/Arda/AppData/Local/Microsoft/WinGet/Packages/VulnInc.vdpi/vdpi.exe",
        );
        let cands = resolve_wintun_dll_candidates(&shim, Some(&real));
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0], links_dir.join("wintun.dll"));
        assert_eq!(cands[1], pkg_dir.join("wintun.dll"));

        // Same directory with verbatim prefix deduplicates to a single entry on every OS.
        let direct_dir = PathBuf::from("C:/Program Files/vdpi");
        let direct = direct_dir.join("vdpi.exe");
        let direct_canon = Path::new(r"\\?\C:/Program Files/vdpi/vdpi.exe");
        let deduped = resolve_wintun_dll_candidates(&direct, Some(direct_canon));
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0], direct_dir.join("wintun.dll"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_tun_session_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<WindowsTunSession>();
    }

    #[test]
    fn verify_wintun_dll_sha256_accepts_matching_hash_and_rejects_tampered_bytes() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vdpi-wintun-sha-test-{}-{}.dll",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"vdpi-wintun-test-payload").unwrap();

        let expected = crate::update::sha256_hex(b"vdpi-wintun-test-payload");
        assert!(verify_wintun_dll_sha256(&path, &expected).is_ok());

        let err = verify_wintun_dll_sha256(&path, WINTUN_DLL_AMD64_SHA256)
            .expect_err("tampered dll must fail SHA-256 verification");
        assert!(err.to_string().contains("SHA-256 verification failed"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ipv6_global_unicast_restricts_to_2000_slash_3() {
        assert!(is_ipv6_global_unicast("2000::1".parse().unwrap()));
        assert!(is_ipv6_global_unicast(
            "2001:4860:4860::8888".parse().unwrap()
        ));
        assert!(is_ipv6_global_unicast("2606:4700::1111".parse().unwrap()));
        assert!(is_ipv6_global_unicast("3fff:ffff::1".parse().unwrap()));

        assert!(!is_ipv6_global_unicast("::".parse().unwrap()));
        assert!(!is_ipv6_global_unicast("::1".parse().unwrap()));
        assert!(!is_ipv6_global_unicast("fe80::1".parse().unwrap()));
        assert!(!is_ipv6_global_unicast("fc00::1".parse().unwrap()));
        assert!(!is_ipv6_global_unicast(
            "fd00:7664:7069::1".parse().unwrap()
        ));
        assert!(!is_ipv6_global_unicast("ff02::1".parse().unwrap()));
    }

    #[test]
    fn normalize_load_library_path_strips_short_verbatim_and_preserves_long() {
        let short = Path::new(r"\\?\C:\Program Files\vdpi\wintun.dll");
        assert_eq!(
            normalize_load_library_path(short),
            PathBuf::from(r"C:\Program Files\vdpi\wintun.dll")
        );

        let long_dir = "a".repeat(240);
        let long_verbatim = PathBuf::from(format!(r"\\?\C:\{long_dir}\wintun.dll"));
        assert_eq!(normalize_load_library_path(&long_verbatim), long_verbatim);
    }

    #[test]
    fn resolve_all_wintun_dll_candidates_orders_primary_and_hidden_runtime_cache() {
        let exe_dir = PathBuf::from("C:/Users/Arda/Desktop/vdpi");
        let exe = exe_dir.join("vdpi.exe");
        let pf = PathBuf::from("C:/Program Files");
        let pd = PathBuf::from("C:/ProgramData");
        let lad = PathBuf::from("C:/Users/Arda/AppData/Local");
        let tmp = PathBuf::from("C:/Users/Arda/AppData/Local/Temp");

        let (primary, cache) = resolve_all_wintun_dll_candidates(
            &exe,
            None,
            Some(&pf),
            Some(&pd),
            Some(&lad),
            Some(&tmp),
        );

        assert_eq!(
            primary,
            vec![
                exe_dir.join("wintun.dll"),
                pf.join("vdpi").join("bin").join("wintun.dll"),
            ]
        );
        let runtime_name = format!("wintun-{WINTUN_VERSION}.dll");
        assert_eq!(
            cache,
            vec![
                pd.join("vdpi").join("runtime").join(&runtime_name),
                lad.join("vdpi").join("runtime").join(&runtime_name),
                tmp.join("vdpi-runtime").join(&runtime_name),
            ]
        );
        assert!(cache.iter().all(|p| p.parent() != Some(exe_dir.as_path())));
    }

    #[test]
    fn embedded_wintun_materializes_only_into_runtime_cache_with_fallbacks_and_never_beside_exe() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vdpi-embed-wintun-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);

        let exe_dir = root.join("user-folder");
        let pf_dir = root.join("ProgramFiles");
        let pd_dir = root.join("ProgramData");
        let lad_dir = root.join("LocalAppData");
        let tmp_dir = root.join("Temp");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let exe = exe_dir.join("vdpi.exe");

        let payload = b"verified-embedded-wintun-dll-test-bytes";
        let expected_sha = sha256_hex(payload);

        // 1. Tampered embedded bytes must be rejected and write nothing anywhere.
        let bad_err = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&pd_dir),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            Some(b"tampered-bytes"),
        )
        .expect_err("tampered embedded payload must fail SHA-256 verification");
        assert!(bad_err.to_string().contains("SHA-256 verification failed"));
        assert_eq!(std::fs::read_dir(&exe_dir).unwrap().count(), 0);
        assert!(!pd_dir.exists());

        // 2. Valid embedded bytes materialize into ProgramData runtime cache; exe_dir stays clean.
        let materialized = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&pd_dir),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect("embedded extraction into ProgramData runtime cache");
        let runtime_name = format!("wintun-{WINTUN_VERSION}.dll");
        let expected_pd = pd_dir.join("vdpi").join("runtime").join(&runtime_name);
        assert_eq!(materialized, expected_pd);
        assert_eq!(std::fs::read(&materialized).unwrap(), payload);
        assert_eq!(
            std::fs::read_dir(&exe_dir).unwrap().count(),
            0,
            "vdpi.exe folder must remain completely clean"
        );
        // No staging temp files left behind.
        let runtime_entries: Vec<_> = std::fs::read_dir(expected_pd.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(runtime_entries, vec![runtime_name.clone()]);

        // 3. Subsequent resolution reuses the verified cached copy without needing embedded bytes.
        let cached = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&pd_dir),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            None,
        )
        .expect("cached runtime DLL reuse");
        assert_eq!(cached, expected_pd);

        // 4. Corrupt runtime cache copy is self-healed when verified embedded bytes are available.
        std::fs::write(&expected_pd, b"corrupted").unwrap();
        let healed = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&pd_dir),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect("self-heal corrupt runtime cache");
        assert_eq!(healed, expected_pd);
        assert_eq!(std::fs::read(&healed).unwrap(), payload);

        // 5. Unwritable ProgramData falls back to LOCALAPPDATA; unwritable LOCALAPPDATA falls
        //    back to temp_dir/vdpi-runtime — never writing next to vdpi.exe.
        let blocked_pd = root.join("blocked-pd-file");
        std::fs::write(&blocked_pd, b"not-a-directory").unwrap();
        let lad_path = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&blocked_pd),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect("fallback to LOCALAPPDATA runtime cache");
        let expected_lad = lad_dir.join("vdpi").join("runtime").join(&runtime_name);
        assert_eq!(lad_path, expected_lad);
        assert_eq!(std::fs::read(&lad_path).unwrap(), payload);
        assert_eq!(std::fs::read_dir(&exe_dir).unwrap().count(), 0);

        let blocked_lad = root.join("blocked-lad-file");
        std::fs::write(&blocked_lad, b"not-a-directory").unwrap();
        let tmp_path = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&blocked_pd),
            Some(&blocked_lad),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect("fallback to temp vdpi-runtime cache");
        let expected_tmp = tmp_dir.join("vdpi-runtime").join(&runtime_name);
        assert_eq!(tmp_path, expected_tmp);
        assert_eq!(std::fs::read(&tmp_path).unwrap(), payload);
        assert_eq!(std::fs::read_dir(&exe_dir).unwrap().count(), 0);

        // 6. On-disk ProgramFiles candidate takes precedence over cache/embedded extraction.
        let pf_dll = pf_dir.join("vdpi").join("bin").join("wintun.dll");
        std::fs::create_dir_all(pf_dll.parent().unwrap()).unwrap();
        std::fs::write(&pf_dll, payload).unwrap();
        let from_pf = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&blocked_pd),
            Some(&blocked_lad),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect("ProgramFiles candidate resolution");
        assert_eq!(from_pf, pf_dll);

        // 7. A tampered sibling DLL beside vdpi.exe must always fail fatally.
        let tampered_sibling = exe_dir.join("wintun.dll");
        std::fs::write(&tampered_sibling, b"evil-dll").unwrap();
        let sibling_err = resolve_or_materialize_wintun_dll(
            &exe,
            None,
            Some(&pf_dir),
            Some(&pd_dir),
            Some(&lad_dir),
            Some(&tmp_dir),
            &expected_sha,
            Some(payload),
        )
        .expect_err("tampered sibling wintun.dll must fail fatally");
        assert!(sibling_err
            .to_string()
            .contains("SHA-256 verification failed"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rank_physical_uplink_allows_hyperv_external_vethernet_fallback_and_excludes_internal_switches()
    {
        let vdpi_luid = 0xAA00_0001;
        let mk = |luid: u64, if_index: u32, alias: &str, desc: &str, metric: u32| UplinkCandidate {
            luid,
            if_index,
            alias: alias.into(),
            description: desc.into(),
            if_type: NDIS_IF_TYPE_ETHERNET,
            is_up: true,
            route_metric: 0,
            iface_metric: metric,
            has_unicast_ip: true,
        };

        let internal_only = vec![
            mk(
                0x3001,
                20,
                "vEthernet (WSL)",
                "Hyper-V Virtual Ethernet Adapter",
                5,
            ),
            mk(
                0x3002,
                21,
                "vEthernet (Default Switch)",
                "Hyper-V Virtual Ethernet Adapter #2",
                5,
            ),
            mk(
                0x3003,
                22,
                "vEthernet (DockerNAT)",
                "Hyper-V Virtual Ethernet Adapter #3",
                5,
            ),
            mk(
                0x3004,
                23,
                "vEthernet (NAT)",
                "Hyper-V Virtual Ethernet Adapter #4",
                5,
            ),
            mk(
                0x3005,
                24,
                "vEthernet (Host-Only)",
                "Hyper-V Virtual Ethernet Adapter #5",
                5,
            ),
        ];
        assert!(rank_physical_uplink(&internal_only, vdpi_luid).is_none());

        // When no bare physical NIC holds a default route, a non-internal Hyper-V External
        // Virtual Switch is selected as fallback.
        let mut with_external = internal_only.clone();
        with_external.push(mk(
            0x3006,
            25,
            "vEthernet (External)",
            "Hyper-V Virtual Ethernet Adapter #6",
            15,
        ));
        let fallback = rank_physical_uplink(&with_external, vdpi_luid)
            .expect("external Hyper-V vSwitch fallback");
        assert_eq!(fallback.alias, "vEthernet (External)");
        assert_eq!(fallback.if_index, 25);

        // When a bare physical NIC is present, it always beats Hyper-V External vEthernet
        // even if the vSwitch has a lower metric.
        let mut with_physical = with_external;
        with_physical.push(mk(
            0x3007,
            26,
            "Ethernet",
            "Intel(R) Ethernet Controller I225-V",
            35,
        ));
        let physical =
            rank_physical_uplink(&with_physical, vdpi_luid).expect("bare physical NIC preferred");
        assert_eq!(physical.alias, "Ethernet");
        assert_eq!(physical.if_index, 26);
    }

    #[test]
    fn should_enable_tun_ipv6_auto_enables_for_ipv6_only_uplink() {
        assert!(!should_enable_tun_ipv6(false, true, true));
        assert!(should_enable_tun_ipv6(true, true, true));
        assert!(!should_enable_tun_ipv6(true, true, false));
        assert!(should_enable_tun_ipv6(false, false, true));
        assert!(should_enable_tun_ipv6(true, false, true));
        assert!(!should_enable_tun_ipv6(false, false, false));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn final_path_from_file_resolves_pinned_handle_path() {
        use std::os::windows::fs::OpenOptionsExt;

        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vdpi-final-path-test-{}-{}.tmp",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"vdpi-final-path-check").unwrap();

        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001)
            .open(&path)
            .unwrap();
        let resolved = win32::final_path_from_file(&file).expect("GetFinalPathNameByHandleW");
        drop(file);

        let normalized = normalize_load_library_path(&resolved);
        assert_eq!(
            normalized.file_name(),
            path.file_name(),
            "resolved final path must refer to the opened file"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_winmm_timer_hijacking_or_overflow_sleep_and_gigabit_batching_enabled() {
        let src = include_str!("windows_tun.rs");
        assert!(
            !src.contains(concat!("timeBegin", "Period")),
            "windows_tun.rs must not hijack Windows multimedia timer resolution"
        );
        assert!(
            !src.contains(concat!("timeEnd", "Period")),
            "windows_tun.rs must not call multimedia timer teardown"
        );
        assert!(
            !src.contains(concat!("winmm", ".dll")),
            "windows_tun.rs must not load winmm"
        );
        assert!(
            !src.contains(concat!("TimerResolution", "Guard")),
            "multimedia timer guard must be removed"
        );
        assert!(
            !src.contains(concat!("TX_OVERFLOW_RETRY", "_SLEEP")),
            "microsecond TX overflow sleep loop must be removed"
        );
        assert!(
            src.contains("DnsFlushResolverCache"),
            "windows_tun.rs must flush Windows DNS cache on TUN start and teardown"
        );
        assert!(
            src.contains("mpsc::channel::<Vec<u8>>(TUN_CHANNEL_CAPACITY)"),
            "inbound channel must keep TUN_CHANNEL_CAPACITY (4096)"
        );
        assert!(
            src.contains("mpsc::channel::<Vec<u8>>(TUN_TX_CHANNEL_CAPACITY)"),
            "outbound channel must use TUN_TX_CHANNEL_CAPACITY (128) for sub-ms UDP preemption"
        );
        #[cfg(target_os = "windows")]
        {
            assert_eq!(win32::TUN_CHANNEL_CAPACITY, 4096);
            assert_eq!(win32::TUN_TX_CHANNEL_CAPACITY, 128);
            assert_eq!(win32::TUN_TX_CHANNEL_CAPACITY, win32::TX_BATCH_LIMIT);
            assert_eq!(win32::TX_BATCH_LIMIT, 128);
            assert_eq!(win32::RX_BURST_LIMIT, 128);
        }
    }

    #[test]
    fn hyperv_nat_matching_uses_word_boundaries_and_preserves_native_and_international_vswitches() {
        let vdpi_luid = 0xAA00_0001;
        let mk = |luid: u64, if_index: u32, alias: &str, desc: &str, metric: u32| UplinkCandidate {
            luid,
            if_index,
            alias: alias.into(),
            description: desc.into(),
            if_type: NDIS_IF_TYPE_ETHERNET,
            is_up: true,
            route_metric: 0,
            iface_metric: metric,
            has_unicast_ip: true,
        };

        // True NAT switches must still be excluded.
        assert!(is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (NAT)",
            "Hyper-V Virtual Ethernet Adapter",
        ));
        assert!(is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (NAT Switch)",
            "Hyper-V Virtual Ethernet Adapter #2",
        ));
        assert!(is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (Internal-NAT)",
            "Hyper-V Virtual Ethernet Adapter #3",
        ));
        assert!(is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (DockerNAT)",
            "Hyper-V Virtual Ethernet Adapter #4",
        ));

        // Substring false-positives containing "nat" inside another word must NOT be excluded.
        assert!(!is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (External Native)",
            "Hyper-V Virtual Ethernet Adapter #5",
        ));
        assert!(!is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (International)",
            "Hyper-V Virtual Ethernet Adapter #6",
        ));
        assert!(!is_virtual_or_excluded_adapter(
            NDIS_IF_TYPE_ETHERNET,
            "vEthernet (External)",
            "Hyper-V Virtual Ethernet Adapter (Native)",
        ));

        let candidates = vec![
            mk(
                0x4001,
                30,
                "vEthernet (NAT)",
                "Hyper-V Virtual Ethernet Adapter",
                5,
            ),
            mk(
                0x4002,
                31,
                "vEthernet (External Native)",
                "Hyper-V Virtual Ethernet Adapter #2",
                15,
            ),
            mk(
                0x4003,
                32,
                "vEthernet (International)",
                "Hyper-V Virtual Ethernet Adapter #3",
                25,
            ),
        ];
        let winner = rank_physical_uplink(&candidates, vdpi_luid)
            .expect("External Native Hyper-V vSwitch must be eligible as fallback");
        assert_eq!(winner.alias, "vEthernet (External Native)");
        assert_eq!(winner.if_index, 31);

        let intl_only = vec![
            candidates[0].clone(),
            candidates[2].clone(),
        ];
        let intl_winner = rank_physical_uplink(&intl_only, vdpi_luid)
            .expect("International Hyper-V vSwitch must be eligible as fallback");
        assert_eq!(intl_winner.alias, "vEthernet (International)");
        assert_eq!(intl_winner.if_index, 32);
    }

    #[test]
    fn unc_and_device_paths_are_rejected_for_wintun_loading_and_cache_targets() {
        let rejected = [
            r"\\?\UNC\attacker\share\wintun.dll",
            r"\\?\unc\attacker\share\wintun.dll",
            r"\\?\UNC/attacker/share/wintun.dll",
            r"\\attacker\share\wintun.dll",
            r"//attacker/share/wintun.dll",
            r"\\.\GLOBALROOT\Device\LanmanRedirector\attacker\share\wintun.dll",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\wintun.dll",
        ];
        for raw in rejected {
            let p = Path::new(raw);
            assert!(
                is_unc_or_device_path(p),
                "expected UNC/device path to be rejected: {raw}"
            );
            assert_eq!(
                extract_local_drive_root(p),
                None,
                "UNC/device path must not yield a local drive root: {raw}"
            );
        }

        assert!(!is_unc_or_device_path(Path::new(
            r"\\?\C:\ProgramData\vdpi\runtime\wintun-0.14.1.dll"
        )));
        assert_eq!(
            extract_local_drive_root(Path::new(
                r"\\?\C:\ProgramData\vdpi\runtime\wintun-0.14.1.dll"
            )),
            Some(r"C:\".to_string())
        );
        assert_eq!(
            extract_local_drive_root(Path::new(r"d:/vdpi/wintun.dll")),
            Some(r"D:\".to_string())
        );
        assert_eq!(extract_local_drive_root(Path::new("wintun.dll")), None);

        // Runtime cache candidate resolution drops poisoned UNC env roots while keeping local paths.
        let targets = resolve_runtime_wintun_cache_targets(
            Some(Path::new(r"\\attacker\ProgramData")),
            Some(Path::new(r"\\?\UNC\attacker\LocalAppData")),
            Some(Path::new(r"C:\Temp")),
        );
        assert_eq!(
            targets,
            vec![PathBuf::from(r"C:\Temp")
                .join("vdpi-runtime")
                .join(format!("wintun-{WINTUN_VERSION}.dll"))]
        );
    }

    #[test]
    fn retryable_adapter_create_error_classification_and_orphan_device_matching() {
        // Retryable WintunCreateAdapter teardown/collision codes.
        assert!(is_retryable_adapter_create_error(183)); // ERROR_ALREADY_EXISTS
        assert!(is_retryable_adapter_create_error(0x8007_00B7)); // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)
        assert!(is_retryable_adapter_create_error(4319)); // ERROR_DEVICE_NOT_AVAILABLE

        // Non-retryable codes must fail immediately without retry churn.
        assert!(!is_retryable_adapter_create_error(0)); // NO_ERROR
        assert!(!is_retryable_adapter_create_error(2)); // ERROR_FILE_NOT_FOUND
        assert!(!is_retryable_adapter_create_error(5)); // ERROR_ACCESS_DENIED
        assert!(!is_retryable_adapter_create_error(87)); // ERROR_INVALID_PARAMETER

        // SetupAPI orphan device matching strictly targets vdpi0 Wintun nodes.
        assert!(is_orphan_vdpi_wintun_device(
            &["Wintun".to_string()],
            Some("vdpi Tunnel"),
            Some("vdpi Tunnel"),
            None,
        ));
        assert!(is_orphan_vdpi_wintun_device(
            &["ROOT\\Wintun".to_string()],
            Some("Wintun Userspace Tunnel"),
            Some("vdpi0"),
            None,
        ));
        assert!(is_orphan_vdpi_wintun_device(
            &[],
            None,
            None,
            Some("{76647069-5769-6E74-756E-563035300001}"),
        ));

        // Third-party Wintun adapters and physical NICs must NEVER be matched.
        assert!(!is_orphan_vdpi_wintun_device(
            &["Wintun".to_string()],
            Some("WireGuard Tunnel"),
            Some("WireGuard Tunnel"),
            Some("{11111111-2222-3333-4444-555555555555}"),
        ));
        assert!(!is_orphan_vdpi_wintun_device(
            &["Wintun".to_string()],
            Some("Tailscale Tunnel"),
            Some("Tailscale"),
            None,
        ));
        assert!(!is_orphan_vdpi_wintun_device(
            &["PCI\\VEN_8086&DEV_15F3".to_string()],
            Some("Intel(R) Ethernet Controller I225-V"),
            Some("Ethernet"),
            None,
        ));
    }

    #[test]
    fn resolve_wintun_dll_candidates_filters_unc_and_device_sibling_paths() {
        let unc_exes = [
            r"\\attacker\share\vdpi.exe",
            r"//attacker/share/vdpi.exe",
            r"\\?\UNC\attacker\share\vdpi.exe",
            r"\\?\unc\attacker\share\vdpi.exe",
            r"\\.\GLOBALROOT\Device\LanmanRedirector\attacker\share\vdpi.exe",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\vdpi.exe",
        ];
        for raw in unc_exes {
            let p = Path::new(raw);
            assert!(
                resolve_wintun_dll_candidates(p, None).is_empty(),
                "UNC/device exe path must yield zero sibling candidates: {raw}"
            );
            assert!(
                resolve_wintun_dll_candidates(p, Some(p)).is_empty(),
                "UNC/device canonical exe path must yield zero sibling candidates: {raw}"
            );
        }

        // Local exe with UNC canonical target keeps only the local sibling.
        let local_dir = PathBuf::from("C:/Program Files/vdpi");
        let local_exe = local_dir.join("vdpi.exe");
        let unc_canon = Path::new(r"\\?\UNC\attacker\share\vdpi.exe");
        assert_eq!(
            resolve_wintun_dll_candidates(&local_exe, Some(unc_canon)),
            vec![local_dir.join("wintun.dll")]
        );

        // UNC exe with local canonical target drops the UNC sibling and keeps the local one.
        let unc_exe = Path::new(r"\\attacker\share\vdpi.exe");
        let local_canon = Path::new(r"\\?\C:/Program Files/vdpi/vdpi.exe");
        assert_eq!(
            resolve_wintun_dll_candidates(unc_exe, Some(local_canon)),
            vec![local_dir.join("wintun.dll")]
        );

        // Combined candidate resolution drops all UNC/device primary & cache roots.
        let (primary, cache) = resolve_all_wintun_dll_candidates(
            unc_exe,
            Some(unc_canon),
            Some(Path::new(r"\\attacker\ProgramFiles")),
            Some(Path::new(r"\\attacker\ProgramData")),
            Some(Path::new(r"\\?\UNC\attacker\LocalAppData")),
            Some(Path::new(r"C:\Temp")),
        );
        assert!(primary.is_empty());
        assert_eq!(
            cache,
            vec![PathBuf::from(r"C:\Temp")
                .join("vdpi-runtime")
                .join(format!("wintun-{WINTUN_VERSION}.dll"))]
        );
    }

    #[test]
    fn plan_tun_roaming_transition_covers_ipv4_dual_stack_ipv6_and_offline_roaming() {
        let v4_only = TunStackState {
            ipv4_routes_installed: true,
            ipv6_active: false,
        };
        let dual_v6_on = TunStackState {
            ipv4_routes_installed: true,
            ipv6_active: true,
        };
        let v6_only = TunStackState {
            ipv4_routes_installed: false,
            ipv6_active: true,
        };

        // 1. tun_ipv6 = false:
        //    IPv4-only -> IPv6-only removes IPv4 complement CIDRs and auto-enables IPv6.
        let p = plan_tun_roaming_transition(v4_only, false, false, true);
        assert!(p.has_changes());
        assert!(!p.add_ipv4_routes);
        assert!(p.remove_ipv4_routes);
        assert!(p.enable_ipv6);
        assert!(!p.disable_ipv6);
        assert_eq!(p.next_state, v6_only);

        //    IPv6-only -> IPv4-only restores IPv4 complement CIDRs and disables IPv6.
        let p = plan_tun_roaming_transition(v6_only, false, true, false);
        assert!(p.has_changes());
        assert!(p.add_ipv4_routes);
        assert!(!p.remove_ipv4_routes);
        assert!(!p.enable_ipv6);
        assert!(p.disable_ipv6);
        assert_eq!(p.next_state, v4_only);

        //    IPv6-only -> dual-stack (tun_ipv6=false) restores IPv4 routes and drops auto IPv6.
        let p = plan_tun_roaming_transition(v6_only, false, true, true);
        assert!(p.has_changes());
        assert!(p.add_ipv4_routes);
        assert!(!p.remove_ipv4_routes);
        assert!(!p.enable_ipv6);
        assert!(p.disable_ipv6);
        assert_eq!(p.next_state, v4_only);

        //    IPv4-only -> dual-stack (tun_ipv6=false) requires no changes.
        let p = plan_tun_roaming_transition(v4_only, false, true, true);
        assert!(!p.has_changes());
        assert_eq!(p.next_state, v4_only);

        // 2. tun_ipv6 = true:
        //    IPv4-only -> dual-stack enables IPv6 while preserving IPv4 complement CIDRs.
        let p = plan_tun_roaming_transition(v4_only, true, true, true);
        assert!(p.has_changes());
        assert!(!p.add_ipv4_routes);
        assert!(!p.remove_ipv4_routes);
        assert!(p.enable_ipv6);
        assert!(!p.disable_ipv6);
        assert_eq!(p.next_state, dual_v6_on);

        //    Dual-stack -> IPv6-only removes IPv4 routes while keeping IPv6 active.
        let p = plan_tun_roaming_transition(dual_v6_on, true, false, true);
        assert!(p.has_changes());
        assert!(!p.add_ipv4_routes);
        assert!(p.remove_ipv4_routes);
        assert!(!p.enable_ipv6);
        assert!(!p.disable_ipv6);
        assert_eq!(p.next_state, v6_only);

        //    IPv6-only -> dual-stack adds IPv4 routes while keeping IPv6 active.
        let p = plan_tun_roaming_transition(v6_only, true, true, true);
        assert!(p.has_changes());
        assert!(p.add_ipv4_routes);
        assert!(!p.remove_ipv4_routes);
        assert!(!p.enable_ipv6);
        assert!(!p.disable_ipv6);
        assert_eq!(p.next_state, dual_v6_on);

        //    Dual-stack -> IPv4-only disables IPv6 while keeping IPv4 routes.
        let p = plan_tun_roaming_transition(dual_v6_on, true, true, false);
        assert!(p.has_changes());
        assert!(!p.add_ipv4_routes);
        assert!(!p.remove_ipv4_routes);
        assert!(!p.enable_ipv6);
        assert!(p.disable_ipv6);
        assert_eq!(p.next_state, v4_only);

        // 3. Transient offline (!has_v4 && !has_v6) holds current state steady without churn.
        for state in [v4_only, dual_v6_on, v6_only] {
            for tun_ipv6 in [false, true] {
                let p = plan_tun_roaming_transition(state, tun_ipv6, false, false);
                assert!(!p.has_changes());
                assert_eq!(p.next_state, state);
            }
        }

        // 4. Exhaustive mutual-exclusion invariant across all states & uplink combinations.
        for v4_installed in [false, true] {
            for v6_active in [false, true] {
                let cur = TunStackState {
                    ipv4_routes_installed: v4_installed,
                    ipv6_active: v6_active,
                };
                for tun_ipv6 in [false, true] {
                    for has_v4 in [false, true] {
                        for has_v6 in [false, true] {
                            let p = plan_tun_roaming_transition(cur, tun_ipv6, has_v4, has_v6);
                            assert!(!(p.add_ipv4_routes && p.remove_ipv4_routes));
                            assert!(!(p.enable_ipv6 && p.disable_ipv6));
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn ipv6_tun_routes_include_global_unicast_and_rfc6052_nat64() {
        assert_eq!(
            win32::VDPI_IPV6_GLOBAL_PREFIX,
            "2000::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(win32::VDPI_IPV6_GLOBAL_PREFIX_LEN, 3);
        assert_eq!(
            win32::VDPI_IPV6_NAT64_PREFIX,
            "64:ff9b::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(win32::VDPI_IPV6_NAT64_PREFIX.to_string(), "64:ff9b::");
        assert_eq!(win32::VDPI_IPV6_NAT64_PREFIX_LEN, 96);
        assert_eq!(
            win32::VDPI_IPV6_TUN_ROUTES,
            &[
                (
                    win32::VDPI_IPV6_GLOBAL_PREFIX,
                    win32::VDPI_IPV6_GLOBAL_PREFIX_LEN
                ),
                (
                    win32::VDPI_IPV6_NAT64_PREFIX,
                    win32::VDPI_IPV6_NAT64_PREFIX_LEN
                ),
            ]
        );
        // RFC 6052 well-known prefix is outside 2000::/3 and therefore requires its own route.
        assert!(!is_ipv6_global_unicast(win32::VDPI_IPV6_NAT64_PREFIX));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn uplink_signature_detects_ssid_roaming_on_shared_gateway_and_normalizes_addr_order() {
        use std::net::IpAddr;

        let mk_v4 = |addrs: Vec<IpAddr>| win32::DetectedUplink {
            nic_name: Some("Wi-Fi".into()),
            v4: Some(win32::UplinkEndpoint {
                luid: 0x2001,
                if_index: 15,
                alias: "Wi-Fi".into(),
                combined_metric: 45,
                gateway: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                local_addrs: addrs,
            }),
            v6: None,
        };

        // Roaming between two SSIDs that share 192.168.1.1 on the same Wi-Fi adapter must
        // produce distinct signatures once the local DHCP IPv4 address changes.
        let ssid_a = mk_v4(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))]).signature();
        let ssid_b = mk_v4(vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 107))]).signature();
        assert_ne!(ssid_a, ssid_b);

        // Identical local address sets reported in different order or with duplicates must
        // normalize to the exact same signature to avoid spurious route_tx flaps.
        let ordered = mk_v4(vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        ])
        .signature();
        let reordered_dup = mk_v4(vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)),
        ])
        .signature();
        assert_eq!(ordered, reordered_dup);

        // IPv6 prefix/address changes behind the same link-local gateway also change signature.
        let mk_v6 = |addrs: Vec<IpAddr>| win32::DetectedUplink {
            nic_name: Some("Wi-Fi".into()),
            v4: None,
            v6: Some(win32::UplinkEndpoint {
                luid: 0x2001,
                if_index: 15,
                alias: "Wi-Fi".into(),
                combined_metric: 45,
                gateway: IpAddr::V6("fe80::1".parse().unwrap()),
                local_addrs: addrs,
            }),
        };
        let v6_a = mk_v6(vec![IpAddr::V6("2001:db8:1::10".parse().unwrap())]).signature();
        let v6_b = mk_v6(vec![IpAddr::V6("2001:db8:2::20".parse().unwrap())]).signature();
        assert_ne!(v6_a, v6_b);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn program_data_hardening_sets_owner_sddl_and_hardens_preexisting_direct_children() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vdpi-pd-harden-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);

        let vdpi_dir = root.join("vdpi");
        let child_dir = vdpi_dir.join("runtime");
        let child_file = vdpi_dir.join("preexisting.dat");
        std::fs::create_dir_all(&child_dir).unwrap();
        std::fs::write(&child_file, b"preexisting-child").unwrap();

        let ctx = win32::ProgramDataDaclContext::load()
            .expect("ProgramDataDaclContext with O:BA owner SID must load cleanly");

        // Must succeed both initially and idempotently (falling back cleanly to DACL-only
        // when the test runner is non-elevated).
        win32::harden_program_data_dir_dacl(&vdpi_dir, &ctx)
            .expect("initial hardening of dir and pre-existing direct children");
        win32::harden_program_data_dir_dacl(&vdpi_dir, &ctx)
            .expect("idempotent re-hardening of dir and direct children");

        // Restore permissive DACLs before deleting temp artifacts when running non-elevated.
        win32::reset_test_path_dacl_for_cleanup(&child_file, false);
        win32::reset_test_path_dacl_for_cleanup(&child_dir, true);
        win32::reset_test_path_dacl_for_cleanup(&vdpi_dir, true);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn probe_existing_regular_file_rejects_reparse_points_on_primary_and_cache_candidates() {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "vdpi-reparse-probe-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);

        let exe_dir = root.join("exe");
        let pd_dir = root.join("ProgramData");
        let target_dir = root.join("real-target");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::create_dir_all(&pd_dir).unwrap();
        std::fs::create_dir_all(&target_dir).unwrap();

        let regular_file = exe_dir.join("regular.dll");
        std::fs::write(&regular_file, b"payload").unwrap();

        assert!(win32::probe_existing_regular_file_no_reparse(&regular_file, false).unwrap());
        assert!(!win32::probe_existing_regular_file_no_reparse(&exe_dir, false).unwrap());
        assert!(
            !win32::probe_existing_regular_file_no_reparse(&exe_dir.join("missing.dll"), false)
                .unwrap()
        );

        // NTFS directory junctions can be created unprivileged via `mklink /J`.
        let primary_junction = exe_dir.join("wintun.dll");
        let pd_vdpi_junction = pd_dir.join("vdpi");
        let mk_primary = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &primary_junction.to_string_lossy(),
                &target_dir.to_string_lossy(),
            ])
            .output();
        if let Ok(out) = mk_primary {
            if out.status.success() {
                let err = win32::probe_existing_regular_file_no_reparse(&primary_junction, false)
                    .expect_err("reparse point on primary candidate must be rejected");
                assert!(err.to_string().contains("reparse point"));

                let exe = exe_dir.join("vdpi.exe");
                let expected = sha256_hex(b"payload");
                let resolve_err = resolve_or_materialize_wintun_dll(
                    &exe,
                    None,
                    None,
                    Some(&pd_dir),
                    None,
                    None,
                    &expected,
                    None,
                )
                .expect_err("resolve_or_materialize_wintun_dll must reject primary reparse point");
                assert!(resolve_err.to_string().contains("reparse point"));
                let _ = std::fs::remove_dir(&primary_junction);
            }
        }

        let mk_cache = std::process::Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &pd_vdpi_junction.to_string_lossy(),
                &target_dir.to_string_lossy(),
            ])
            .output();
        if let Ok(out) = mk_cache {
            if out.status.success() {
                let runtime_dll = pd_vdpi_junction
                    .join("runtime")
                    .join(format!("wintun-{WINTUN_VERSION}.dll"));
                let err = win32::probe_existing_regular_file_no_reparse(&runtime_dll, true)
                    .expect_err("reparse point on cache parent directory must be rejected");
                assert!(err.to_string().contains("reparse point"));
                let _ = std::fs::remove_dir(&pd_vdpi_junction);
            }
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strip_vdpi_dns_servers_removes_only_vdpi_v4_and_v6_dns_ips() {
        // Unrelated or empty NameServer values return None (no registry write needed).
        assert_eq!(strip_vdpi_dns_servers(""), None);
        assert_eq!(strip_vdpi_dns_servers("   "), None);
        assert_eq!(strip_vdpi_dns_servers("1.1.1.1,8.8.8.8"), None);
        assert_eq!(strip_vdpi_dns_servers("2606:4700:4700::1111"), None);
        // Must not false-match IPs that only share a string prefix with vdpi DNS.
        assert_eq!(strip_vdpi_dns_servers("198.18.0.20,8.8.8.8"), None);
        assert_eq!(strip_vdpi_dns_servers("fd00:7664:7069::20"), None);
        assert_eq!(strip_vdpi_dns_servers("198.18.0.1"), None);

        // Single vdpi IPv4 or IPv6 DNS resets to empty string.
        assert_eq!(strip_vdpi_dns_servers("198.18.0.2"), Some(String::new()));
        assert_eq!(
            strip_vdpi_dns_servers("fd00:7664:7069::2"),
            Some(String::new())
        );
        // Expanded / uppercase IPv6 form is matched via IpAddr parsing.
        assert_eq!(
            strip_vdpi_dns_servers("FD00:7664:7069:0000:0000:0000:0000:0002"),
            Some(String::new())
        );
        assert_eq!(
            strip_vdpi_dns_servers("198.18.0.2,fd00:7664:7069::2"),
            Some(String::new())
        );

        // Mixed lists strip only vdpi IPs and preserve remaining resolvers + delimiter style.
        assert_eq!(
            strip_vdpi_dns_servers("198.18.0.2,1.1.1.1"),
            Some("1.1.1.1".to_string())
        );
        assert_eq!(
            strip_vdpi_dns_servers("1.1.1.1,198.18.0.2,8.8.8.8"),
            Some("1.1.1.1,8.8.8.8".to_string())
        );
        assert_eq!(
            strip_vdpi_dns_servers("1.1.1.1 198.18.0.2 8.8.8.8"),
            Some("1.1.1.1 8.8.8.8".to_string())
        );
        assert_eq!(
            strip_vdpi_dns_servers("FD00:7664:7069:0:0:0:0:2,2606:4700:4700::1111"),
            Some("2606:4700:4700::1111".to_string())
        );
    }

    #[test]
    fn windows_tun_has_no_netsh_dns_fallback_or_shell_out() {
        let src = include_str!("windows_tun.rs");
        assert!(
            !src.contains(concat!("netsh", ".exe")),
            "windows_tun.rs must not contain legacy netsh DNS shell-out binaries"
        );
    }
}
