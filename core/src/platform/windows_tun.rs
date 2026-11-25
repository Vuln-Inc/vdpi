//! Windows Wintun + IP Helper API transparent TUN backend.
//!
//! Architecture & safety invariants:
//! - **Pinned supply chain**: `wintun.dll` (0.14.1, amd64/arm64) is resolved strictly beside
//!   `current_exe()` or `fs::canonicalize(current_exe())` (for WinGet symlink shims) —
//!   never from CWD or `PATH` — and verified against [`expected_wintun_dll_sha256`] while held
//!   open with `FILE_SHARE_READ` across `LoadLibraryExW(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`.
//! - **Crash-proof routing**: Zero routes or DNS entries are ever mutated on the physical
//!   NIC. All disjoint public IPv4 complement CIDRs (and `2000::/3` when IPv6 TUN is active)
//!   are installed exclusively on the `vdpi0` Wintun LUID. If the process crashes, is killed
//!   with `taskkill /F`, or power is lost, Windows destroys `vdpi0` and immediately restores
//!   normal host connectivity.
//! - **Live uplink tracking**: `NotifyRouteChange2(AF_UNSPEC, ...)` triggers a debounced
//!   off-callback physical uplink re-detection that atomically updates [`DynamicOutboundBinder`]
//!   and notifies route-change watchers (such as `VpnGuard`).

use crate::update::{sha256_file, strip_windows_verbatim_prefix};
use anyhow::{bail, Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

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
/// Link MTU configured on `vdpi0`.
pub const VDPI_TUN_MTU: u32 = 1500;

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
    (Ipv4Addr::new(192, 168, 0, 0), 16), // RFC 1918 private
    (Ipv4Addr::new(224, 0, 0, 0), 4),    // RFC 5771 multicast
    (Ipv4Addr::new(240, 0, 0, 0), 4),    // RFC 1112 reserved + limited broadcast
];

/// Exact minimal binary-trie complement of `0.0.0.0/0` minus [`EXCLUDED_IPV4_CIDRS`].
///
/// Every entry is pairwise disjoint, has zero overlap with any excluded range, and the union
/// of `PUBLIC_IPV4_COMPLEMENT_CIDRS` and `EXCLUDED_IPV4_CIDRS` partitions all 2^32 IPv4
/// addresses exactly (`3,702,390,784 + 592,576,512 = 4,294,967,296`).
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
    (Ipv4Addr::new(192, 0, 0, 0), 9),
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

/// Lowercase substrings identifying virtual, VPN, loopback, or hypervisor adapters that
/// must never be selected as the physical outbound uplink.
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
    "hyper-v",
    "vethernet",
    "wsl",
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

/// Returns `true` when an adapter is loopback, tunnel, proprietary virtual, or matches
/// known VPN/hypervisor/virtual NIC naming patterns.
pub fn is_virtual_or_excluded_adapter(if_type: u32, alias: &str, description: &str) -> bool {
    if matches!(
        if_type,
        NDIS_IF_TYPE_LOOPBACK | NDIS_IF_TYPE_TUNNEL | NDIS_IF_TYPE_PROP_VIRTUAL
    ) {
        return true;
    }

    let alias_lower = alias.to_ascii_lowercase();
    let desc_lower = description.to_ascii_lowercase();
    VIRTUAL_ADAPTER_TOKENS
        .iter()
        .any(|tok| alias_lower.contains(tok) || desc_lower.contains(tok))
}

/// Selects the highest-priority physical uplink from `candidates`.
///
/// Filters out `vdpi_luid`, zero LUID/index entries, non-operational interfaces, interfaces
/// without a usable unicast IP, and virtual/VPN/loopback/hypervisor adapters, then chooses
/// the lowest `route_metric + iface_metric` (breaking ties deterministically by `if_index`,
/// then `luid`).
pub fn rank_physical_uplink(
    candidates: &[UplinkCandidate],
    vdpi_luid: u64,
) -> Option<&UplinkCandidate> {
    candidates
        .iter()
        .filter(|c| {
            c.luid != 0
                && c.luid != vdpi_luid
                && c.if_index != 0
                && c.is_up
                && c.has_unicast_ip
                && !is_virtual_or_excluded_adapter(c.if_type, &c.alias, &c.description)
        })
        .min_by_key(|c| (c.combined_metric(), c.if_index, c.luid))
}

/// Returns ordered, deduplicated absolute candidate paths for `wintun.dll` located strictly
/// beside `exe_path` and (when distinct, e.g. WinGet symlink shims) beside `canonical_exe_path`.
///
/// Never searches CWD or `PATH`.
pub fn resolve_wintun_dll_candidates(
    exe_path: &Path,
    canonical_exe_path: Option<&Path>,
) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::with_capacity(2);

    let push_dir = |out: &mut Vec<PathBuf>, candidate_exe: &Path| {
        let cleaned = strip_windows_verbatim_prefix(candidate_exe);
        let Some(dir) = cleaned.parent() else {
            return;
        };
        if dir.as_os_str().is_empty() {
            return;
        }
        let dll = dir.join("wintun.dll");
        let dup = out.iter().any(|existing| {
            existing == &dll
                || (cfg!(windows)
                    && existing
                        .to_string_lossy()
                        .eq_ignore_ascii_case(&dll.to_string_lossy()))
        });
        if !dup {
            out.push(dll);
        }
    };

    push_dir(&mut out, exe_path);
    if let Some(canon) = canonical_exe_path {
        push_dir(&mut out, canon);
    }

    out
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

/// Locates `wintun.dll` beside the running executable (or its canonical symlink target)
/// and verifies its SHA-256 digest against [`expected_wintun_dll_sha256`].
///
/// Never falls back to CWD or `PATH`. Exposed publicly so CLI `doctor` and preflight checks
/// can verify Wintun readiness cleanly.
pub fn find_verified_wintun_dll() -> Result<PathBuf> {
    let expected_sha256 = expected_wintun_dll_sha256()?;
    let exe = std::env::current_exe().context("failed to determine current executable path")?;
    let canonical = std::fs::canonicalize(&exe).ok();
    let candidates = resolve_wintun_dll_candidates(&exe, canonical.as_deref());

    for cand in &candidates {
        if cand.is_file() {
            verify_wintun_dll_sha256(cand, expected_sha256)?;
            return Ok(cand.clone());
        }
    }

    let checked = candidates
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let arch_label = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "amd64"
    };
    bail!(
        "wintun.dll (v{WINTUN_VERSION}) not found beside vdpi executable (checked: {checked}); \
         place the verified {arch_label} wintun.dll next to vdpi.exe"
    )
}

#[cfg(target_os = "windows")]
mod win32 {
    use super::*;
    use crate::binder::{DynamicOutboundBinder, OutboundBinder, OutboundTarget};
    use crate::update::sha256_hex;
    use anyhow::anyhow;
    use std::collections::{HashMap, HashSet};
    use std::ffi::{c_void, OsStr};
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::mem;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, watch};
    use tracing::{debug, info, trace, warn};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{
        CloseHandle, FreeLibrary, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
        ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NOT_FOUND, ERROR_NO_MORE_ITEMS,
        ERROR_OBJECT_ALREADY_EXISTS, HANDLE, HMODULE, NO_ERROR, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid,
        CreateIpForwardEntry2, CreateUnicastIpAddressEntry, FreeMibTable, GetIfTable2,
        GetIpForwardTable2, GetIpInterfaceEntry, GetIpInterfaceTable, GetUnicastIpAddressTable,
        InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
        NotifyRouteChange2, SetIpInterfaceEntry, DNS_INTERFACE_SETTINGS,
        DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, MIB_IF_ROW2,
        MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
        MIB_IPINTERFACE_TABLE, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW,
        MIB_UNICASTIPADDRESS_TABLE,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
    use windows_sys::Win32::Networking::WinSock::{
        IpDadStatePreferred, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR,
        IN_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    };
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    use windows_sys::Win32::System::Threading::{
        ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
    };

    /// Fixed deterministic GUID for `vdpi0` so Windows never spawns `vdpi0 2`, `vdpi0 3`, etc.
    const VDPI_WINTUN_GUID: GUID = GUID::from_u128(0x7664_7069_5769_6e74_756e_5630_3530_0001);
    /// Wintun adapter tunnel type label shown in Device Manager / NDIS.
    const VDPI_WINTUN_TUNNEL_TYPE: &str = "vdpi";
    /// Wintun ring buffer capacity: 4 MiB per direction.
    const WINTUN_RING_CAPACITY: u32 = 0x0040_0000;
    /// Bounded Tokio channel depth for inbound/outbound IP packets.
    const TUN_CHANNEL_CAPACITY: usize = 512;
    /// Maximum IP packet size supported by Wintun.
    const WINTUN_MAX_IP_PACKET_SIZE: usize = 65_535;
    /// Interface metric assigned to `vdpi0`.
    const VDPI_INTERFACE_METRIC: u32 = 5;
    /// Quiet window for coalescing route-change bursts during NIC handoffs.
    const ROUTE_DEBOUNCE_WINDOW_MS: u32 = 250;
    /// Hard cap on continuous route-change debouncing so updates are never starved.
    const ROUTE_DEBOUNCE_MAX_WAIT: Duration = Duration::from_millis(1500);
    /// Win32 process creation flag to hide `netsh` console window on pre-2004 Win10 fallback.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    /// Win32 `FILE_SHARE_READ`: allows `LoadLibraryExW` to map the DLL while blocking writes,
    /// renames, and deletes on the open handle to eliminate TOCTOU races.
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    /// Upper size bound for `wintun.dll` reads before SHA-256 verification (16 MiB).
    const MAX_WINTUN_DLL_BYTES: u64 = 16 * 1024 * 1024;
    /// Bounded exponential backoff delays when recreating a tearing-down Wintun adapter.
    const ADAPTER_RETRY_DELAYS_MS: &[u64] = &[50, 100, 200, 400, 600];
    /// Retry delays when `SetInterfaceDnsSettings` briefly returns `ERROR_NOT_FOUND` on a new NIC.
    const DNS_NOT_FOUND_RETRY_DELAYS_MS: &[u64] = &[50, 100, 200, 400];

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateEventW(
            lp_event_attributes: *const c_void,
            b_manual_reset: i32,
            b_initial_state: i32,
            lp_name: *const u16,
        ) -> HANDLE;
    }

    type WintunAdapterHandle = *mut c_void;
    type WintunSessionHandle = *mut c_void;

    type WintunCreateAdapterFn = unsafe extern "system" fn(
        name: *const u16,
        tunnel_type: *const u16,
        requested_guid: *const GUID,
    ) -> WintunAdapterHandle;
    type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: WintunAdapterHandle);
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

    /// Dynamically resolved Wintun 0.14.1 export table backed by a verified `wintun.dll`.
    struct WintunApi {
        module: SendHandle,
        create_adapter: WintunCreateAdapterFn,
        close_adapter: WintunCloseAdapterFn,
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
            let expected_sha256 = expected_wintun_dll_sha256()?;
            let exe =
                std::env::current_exe().context("failed to determine current executable path")?;
            let canonical_exe = std::fs::canonicalize(&exe).ok();
            let candidates = resolve_wintun_dll_candidates(&exe, canonical_exe.as_deref());

            let Some(dll_path) = candidates.iter().find(|p| p.is_file()).cloned() else {
                let checked = candidates
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                let arch_label = if cfg!(target_arch = "aarch64") {
                    "arm64"
                } else {
                    "amd64"
                };
                bail!(
                    "wintun.dll (v{WINTUN_VERSION}) not found beside vdpi executable (checked: {checked}); \
                     place the verified {arch_label} wintun.dll next to vdpi.exe"
                );
            };

            let canonical_dll = std::fs::canonicalize(&dll_path).unwrap_or(dll_path);
            let load_path = normalize_load_library_path(&canonical_dll);

            // Open once with `FILE_SHARE_READ` only (denying concurrent write/delete/rename) and
            // keep the handle open across `LoadLibraryExW` to eliminate the TOCTOU window.
            let mut pinned_file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(&load_path)
                .with_context(|| {
                    format!(
                        "failed to open {} with FILE_SHARE_READ for SHA-256 verification",
                        load_path.display()
                    )
                })?;

            verify_open_file_sha256(&mut pinned_file, &load_path, expected_sha256)?;

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
                    create_adapter: load_proc(module, b"WintunCreateAdapter\0")?,
                    close_adapter: load_proc(module, b"WintunCloseAdapter\0")?,
                    get_adapter_luid: load_proc(module, b"WintunGetAdapterLUID\0")?,
                    start_session: load_proc(module, b"WintunStartSession\0")?,
                    end_session: load_proc(module, b"WintunEndSession\0")?,
                    get_read_wait_event: load_proc(module, b"WintunGetReadWaitEvent\0")?,
                    receive_packet: load_proc(module, b"WintunReceivePacket\0")?,
                    release_receive_packet: load_proc(module, b"WintunReleaseReceivePacket\0")?,
                    allocate_send_packet: load_proc(module, b"WintunAllocateSendPacket\0")?,
                    send_packet: load_proc(module, b"WintunSendPacket\0")?,
                }
            };
            let _ = guard.into_raw();
            debug!(path = %load_path.display(), "loaded SHA-256 verified wintun.dll");
            Ok(Arc::new(api))
        }
    }

    impl Drop for WintunApi {
        fn drop(&mut self) {
            if !self.module.is_null() {
                unsafe {
                    let _ = FreeLibrary(self.module.as_raw());
                }
                self.module = SendHandle(ptr::null_mut());
            }
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
                unsafe { (self.wintun.close_adapter)(self.handle.as_raw()) };
                self.handle = SendHandle(ptr::null_mut());
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

    unsafe fn load_proc<T>(module: HMODULE, symbol: &'static [u8]) -> Result<T> {
        debug_assert!(symbol.ends_with(b"\0"));
        debug_assert_eq!(mem::size_of::<T>(), mem::size_of::<usize>());
        let proc = GetProcAddress(module, symbol.as_ptr()).ok_or_else(|| {
            let err = GetLastError();
            let name = String::from_utf8_lossy(&symbol[..symbol.len().saturating_sub(1)]);
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

    #[derive(Debug, Clone)]
    struct UplinkEndpoint {
        luid: u64,
        if_index: u32,
        alias: String,
        combined_metric: u32,
    }

    #[derive(Debug, Clone, Default)]
    struct DetectedUplink {
        nic_name: Option<String>,
        v4: Option<UplinkEndpoint>,
        v6: Option<UplinkEndpoint>,
    }

    impl DetectedUplink {
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

        // 3. Enumerate unicast addresses so interfaces without usable IPs are excluded.
        let mut raw_unicast: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        let rc = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut raw_unicast) };
        if rc != NO_ERROR {
            bail!("GetUnicastIpAddressTable failed with Win32 error {rc}");
        }
        let unicast_table = MibTableGuard::new(raw_unicast);
        let mut has_unicast_v4: HashSet<u64> = HashSet::new();
        let mut has_unicast_v6: HashSet<u64> = HashSet::new();
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
                        has_unicast_v4.insert(luid);
                    }
                } else if family == AF_INET6 {
                    let ip = Ipv6Addr::from(unsafe { row.Address.Ipv6.sin6_addr.u.Byte });
                    if is_ipv6_global_unicast(ip) {
                        has_unicast_v6.insert(luid);
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
        let mut candidates_v6: Vec<UplinkCandidate> = Vec::new();
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
                    candidates_v4.push(UplinkCandidate {
                        luid,
                        if_index,
                        alias: meta.alias.clone(),
                        description: meta.description.clone(),
                        if_type: meta.if_type,
                        is_up: meta.is_up,
                        route_metric: row.Metric,
                        iface_metric: iface_metric_v4.get(&luid).copied().unwrap_or(0),
                        has_unicast_ip: has_unicast_v4.contains(&luid),
                    });
                } else if family == AF_INET6 {
                    let prefix_ip = Ipv6Addr::from(unsafe {
                        row.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte
                    });
                    if !prefix_ip.is_unspecified() {
                        continue;
                    }
                    candidates_v6.push(UplinkCandidate {
                        luid,
                        if_index,
                        alias: meta.alias.clone(),
                        description: meta.description.clone(),
                        if_type: meta.if_type,
                        is_up: meta.is_up,
                        route_metric: row.Metric,
                        iface_metric: iface_metric_v6.get(&luid).copied().unwrap_or(0),
                        has_unicast_ip: has_unicast_v6.contains(&luid),
                    });
                }
            }
        }

        let v4 = rank_physical_uplink(&candidates_v4, vdpi_luid).map(|c| UplinkEndpoint {
            luid: c.luid,
            if_index: c.if_index,
            alias: c.alias.clone(),
            combined_metric: c.combined_metric(),
        });
        let v6 = rank_physical_uplink(&candidates_v6, vdpi_luid).map(|c| UplinkEndpoint {
            luid: c.luid,
            if_index: c.if_index,
            alias: c.alias.clone(),
            combined_metric: c.combined_metric(),
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

    fn create_or_recreate_adapter(wintun: &Arc<WintunApi>) -> Result<AdapterGuard> {
        let name_w = encode_wide(VDPI_TUN_NAME);
        let tunnel_type_w = encode_wide(VDPI_WINTUN_TUNNEL_TYPE);

        let mut handle = unsafe {
            (wintun.create_adapter)(name_w.as_ptr(), tunnel_type_w.as_ptr(), &VDPI_WINTUN_GUID)
        };
        let mut last_err = if handle.is_null() {
            unsafe { GetLastError() }
        } else {
            NO_ERROR
        };

        for (attempt, &delay_ms) in ADAPTER_RETRY_DELAYS_MS.iter().enumerate() {
            if !handle.is_null() || last_err != ERROR_ALREADY_EXISTS {
                break;
            }
            warn!(
                adapter = VDPI_TUN_NAME,
                attempt = attempt + 1,
                delay_ms,
                "stale Wintun adapter still tearing down (ERROR_ALREADY_EXISTS); retrying"
            );
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
            if last_err == ERROR_ALREADY_EXISTS {
                bail!(
                    "WintunCreateAdapter({VDPI_TUN_NAME}) failed with Win32 error {last_err} \
                     (ERROR_ALREADY_EXISTS) after {} retries",
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

    fn interface_alias_from_luid(vdpi_luid: u64) -> String {
        let luid = NET_LUID_LH { Value: vdpi_luid };
        let mut buf = [0u16; 257];
        let rc = unsafe { ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) };
        if rc == NO_ERROR {
            let alias = utf16_array_to_string(&buf);
            if !alias.is_empty() {
                return alias;
            }
        }
        VDPI_TUN_NAME.to_string()
    }

    fn resolve_system32_netsh() -> PathBuf {
        let root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
        root.join("System32").join("netsh.exe")
    }

    /// Configures a static IPv4 or IPv6 DNS server on `vdpi0` via dynamically loaded
    /// `SetInterfaceDnsSettings` (Windows 10 2004+ / Windows 11), retrying briefly on
    /// `ERROR_NOT_FOUND` and falling back to `%SystemRoot%\System32\netsh.exe` only on older
    /// Windows 10 builds where `SetInterfaceDnsSettings` is absent from `iphlpapi.dll`.
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
            if let Ok(set_dns) = unsafe {
                load_proc::<SetInterfaceDnsSettingsFn>(hmod, b"SetInterfaceDnsSettings\0")
            } {
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

        // Pre-2004 Windows 10 fallback when `SetInterfaceDnsSettings` is unavailable.
        let alias = interface_alias_from_luid(vdpi_luid);
        let netsh = resolve_system32_netsh();
        debug!(
            alias = %alias,
            dns = %dns_server,
            ipv6 = is_v6,
            netsh = %netsh.display(),
            "SetInterfaceDnsSettings unavailable; falling back to netsh"
        );
        let out = if is_v6 {
            Command::new(&netsh)
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    &format!("name={alias}"),
                    "source=static",
                    &format!("address={dns_server}"),
                    "validate=no",
                ])
                .output()
                .with_context(|| {
                    format!(
                        "failed to run {} fallback for IPv6 DNS configuration",
                        netsh.display()
                    )
                })?
        } else {
            Command::new(&netsh)
                .creation_flags(CREATE_NO_WINDOW)
                .args([
                    "interface",
                    "ip",
                    "set",
                    "dns",
                    &format!("name={alias}"),
                    "source=static",
                    &format!("addr={dns_server}"),
                    "validate=no",
                ])
                .output()
                .with_context(|| {
                    format!(
                        "failed to run {} fallback for IPv4 DNS configuration",
                        netsh.display()
                    )
                })?
        };
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            bail!("netsh DNS configuration failed ({}): {detail}", out.status);
        }
        Ok(())
    }

    fn configure_interface_dns_v4(vdpi_luid: u64, dns_server: Ipv4Addr) -> Result<()> {
        configure_interface_dns(vdpi_luid, IpAddr::V4(dns_server))
    }

    fn configure_interface_dns_v6(vdpi_luid: u64, dns_server: Ipv6Addr) -> Result<()> {
        configure_interface_dns(vdpi_luid, IpAddr::V6(dns_server))
    }

    /// Best-effort call to `DnsFlushResolverCache()` in `dnsapi.dll`.
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
            unsafe { load_proc::<DnsFlushResolverCacheFn>(hmod, b"DnsFlushResolverCache\0") }
        {
            let ok = unsafe { flush_fn() };
            trace!(ok = (ok != 0), "invoked DnsFlushResolverCache()");
        }
    }

    /// Lock-free shared state read inside the `NotifyRouteChange2` callback.
    struct RouteNotifyContext {
        vdpi_luid: u64,
        generation: AtomicU64,
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

    fn spawn_route_watcher_thread(
        ctx: Arc<RouteNotifyContext>,
        stop_event: SendHandle,
        stop_flag: Arc<AtomicBool>,
        binder: Arc<DynamicOutboundBinder>,
        route_tx: watch::Sender<u64>,
        vdpi_luid: u64,
    ) -> Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("vdpi-route-watch".to_string())
            .spawn(move || {
                let handles = [ctx.wake_event.as_raw(), stop_event.as_raw()];
                let mut route_epoch: u64 = 0;

                loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    let wait =
                        unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                    if wait != WAIT_OBJECT_0 || stop_flag.load(Ordering::Acquire) {
                        break;
                    }

                    // Emit an immediate signal when `NotifyRouteChange2` wakes so VPN guards
                    // (e.g. `VpnGuard`) can yield in ~0ms without waiting for the debounce window.
                    route_epoch = route_epoch.saturating_add(1);
                    let _ = route_tx.send(route_epoch);

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
                            let target = uplink.to_outbound_target();
                            let prev = binder.snapshot();
                            if target != prev {
                                info!(
                                    nic = ?target.nic_name,
                                    if_v4 = ?target.if_index_v4,
                                    if_v6 = ?target.if_index_v6,
                                    "Windows physical uplink changed; updated outbound binder"
                                );
                                binder.update(target);
                            } else {
                                debug!(
                                    nic = ?target.nic_name,
                                    "route change observed; physical uplink unchanged"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to re-detect physical uplink after route change");
                        }
                    }
                    // Notify route watchers unconditionally even if physical uplink detection
                    // failed (e.g. a VPN kill-switch removed the physical default route).
                    route_epoch = route_epoch.saturating_add(1);
                    let _ = route_tx.send(route_epoch);
                }
            })
            .context("failed to spawn Windows route watcher thread")
    }

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

                'outer: loop {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }

                    // Drain every queued IP packet per wakeup to minimize syscall overhead.
                    loop {
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
                            unsafe { (wintun.release_receive_packet)(session.as_raw(), pkt_ptr) };

                            match inbound_tx.try_send(pkt) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    trace!("Wintun RX channel full; dropping inbound packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break 'outer;
                                }
                            }
                            continue;
                        }

                        let err = unsafe { GetLastError() };
                        if err == ERROR_NO_MORE_ITEMS {
                            break;
                        }
                        if err == ERROR_HANDLE_EOF {
                            debug!("Wintun RX ring reached EOF; exiting RX thread");
                            break 'outer;
                        }
                        warn!(error = err, "WintunReceivePacket failed; exiting RX thread");
                        break 'outer;
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

    fn spawn_tx_thread(
        wintun: Arc<WintunApi>,
        session: SendHandle,
        stop_flag: Arc<AtomicBool>,
        mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Result<JoinHandle<()>> {
        thread::Builder::new()
            .name("vdpi-wintun-tx".to_string())
            .spawn(move || {
                while let Some(pkt) = outbound_rx.blocking_recv() {
                    if stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    if pkt.is_empty() || pkt.len() > WINTUN_MAX_IP_PACKET_SIZE {
                        continue;
                    }
                    let dst = unsafe {
                        (wintun.allocate_send_packet)(session.as_raw(), pkt.len() as u32)
                    };
                    if dst.is_null() {
                        let err = unsafe { GetLastError() };
                        if err == ERROR_BUFFER_OVERFLOW {
                            trace!(
                                len = pkt.len(),
                                "Wintun TX ring full; dropping outbound packet"
                            );
                            continue;
                        }
                        if err == ERROR_HANDLE_EOF {
                            debug!("Wintun TX ring reached EOF; exiting TX thread");
                            break;
                        }
                        warn!(error = err, "WintunAllocateSendPacket failed");
                        continue;
                    }
                    unsafe {
                        ptr::copy_nonoverlapping(pkt.as_ptr(), dst, pkt.len());
                        (wintun.send_packet)(session.as_raw(), dst);
                    }
                }
            })
            .context("failed to spawn Wintun TX thread")
    }

    /// Running Windows Wintun transparent TUN session with live physical uplink tracking
    /// and deterministic, crash-proof resource teardown on [`Drop`].
    pub struct WindowsTunSession {
        binder: Arc<DynamicOutboundBinder>,
        wintun: Arc<WintunApi>,
        adapter: SendHandle,
        session: SendHandle,
        stop_event: SendHandle,
        stop_flag: Arc<AtomicBool>,
        outbound_tx_wake: Option<mpsc::Sender<Vec<u8>>>,
        notify_handle: Option<SendHandle>,
        notify_ctx_raw: Option<NotifyCtxPtr>,
        route_thread: Option<JoinHandle<()>>,
        rx_thread: Option<JoinHandle<()>>,
        tx_thread: Option<JoinHandle<()>>,
        vdpi_luid: u64,
        ipv6_enabled: bool,
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
        /// dedicated RX, TX, and `NotifyRouteChange2` watcher threads.
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
            binder.update(uplink.to_outbound_target());
            let mut binder_guard = BinderResetGuard {
                binder: Some(Arc::clone(&binder)),
            };
            info!(
                nic = ?uplink.nic_name,
                v4_if = ?uplink.v4.as_ref().map(|u| (u.if_index, u.luid, u.combined_metric)),
                v6_if = ?uplink.v6.as_ref().map(|u| (u.if_index, u.luid, u.combined_metric)),
                "detected Windows physical uplink"
            );

            // Configure `vdpi0` IPv4 address, MTU, metric, DNS, and disjoint public routes.
            assign_ipv4_address(vdpi_luid, VDPI_TUN_IPV4, VDPI_TUN_PREFIX_V4)?;
            configure_ip_interface(vdpi_luid, AF_INET, VDPI_TUN_MTU, VDPI_INTERFACE_METRIC)?;
            configure_interface_dns_v4(vdpi_luid, VDPI_TUN_DNS_V4)?;
            for &(dest, prefix_len) in PUBLIC_IPV4_COMPLEMENT_CIDRS {
                add_ipv4_route(vdpi_luid, dest, prefix_len)?;
            }

            // Configure IPv6 ULA, DNS, and global unicast route (`2000::/3`) only when requested
            // and backed by an active global-unicast IPv6 physical uplink.
            let ipv6_enabled = tun_ipv6 && uplink.v6.is_some();
            if ipv6_enabled {
                assign_ipv6_address(vdpi_luid, VDPI_TUN_IPV6, VDPI_TUN_PREFIX_V6)?;
                configure_ip_interface(vdpi_luid, AF_INET6, VDPI_TUN_MTU, VDPI_INTERFACE_METRIC)?;
                configure_interface_dns_v6(vdpi_luid, VDPI_TUN_DNS_V6)?;
                add_ipv6_route(vdpi_luid, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)?;
            }

            flush_dns_resolver_cache();

            // Start Wintun packet ring session (4 MiB per ring).
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
            let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(TUN_CHANNEL_CAPACITY);
            let outbound_tx_wake = outbound_tx.clone();
            let (route_tx, route_rx) = watch::channel::<u64>(0);

            // Register live `NotifyRouteChange2` watcher before spawning I/O threads.
            let route_wake_event = OwnedEvent::new(false)?;
            let notify_ctx = Arc::new(RouteNotifyContext {
                vdpi_luid,
                generation: AtomicU64::new(0),
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
                notify_handle: Some(SendHandle(notify_handle)),
                notify_ctx_raw: Some(NotifyCtxPtr(cb_ctx_raw)),
                route_thread: None,
                rx_thread: None,
                tx_thread: None,
                vdpi_luid,
                ipv6_enabled,
            };
            binder_guard.disarm();

            tun_session.route_thread = Some(spawn_route_watcher_thread(
                notify_ctx,
                tun_session.stop_event,
                Arc::clone(&stop_flag),
                binder,
                route_tx,
                vdpi_luid,
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

            info!(
                iface = VDPI_TUN_NAME,
                ipv4 = %VDPI_TUN_IPV4,
                dns = %VDPI_TUN_DNS_V4,
                dns_v6 = ?ipv6_enabled.then_some(VDPI_TUN_DNS_V6),
                routes_v4 = PUBLIC_IPV4_COMPLEMENT_CIDRS.len(),
                ipv6 = ipv6_enabled,
                "Windows Wintun transparent TUN session started"
            );

            Ok((tun_session, inbound_rx, outbound_tx, route_rx))
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
                ipv6 = self.ipv6_enabled,
                "tearing down Windows Wintun session"
            );

            // 1. Unregister route-change notifications FIRST so Windows drains and halts all
            //    callbacks before we reclaim the callback context. If cancellation fails,
            //    intentionally leak the callback Arc so late OS callbacks can never UAF.
            let cancelled_cleanly = match self.notify_handle.take().filter(|h| !h.is_null()) {
                Some(handle) => {
                    let rc = unsafe { CancelMibChangeNotify2(handle.as_raw()) };
                    if rc == NO_ERROR {
                        true
                    } else {
                        warn!(
                            error = rc,
                            "CancelMibChangeNotify2 failed; leaking route callback context Arc to prevent UAF"
                        );
                        false
                    }
                }
                None => true,
            };
            if let Some(NotifyCtxPtr(raw)) = self
                .notify_ctx_raw
                .take()
                .filter(|p| cancelled_cleanly && !p.0.is_null())
            {
                unsafe { drop(Arc::from_raw(raw)) };
            }

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

            // 4. End Wintun session, close adapter (atomically wiping all `vdpi0` routes/DNS),
            //    close stop event, reset the outbound binder, and flush the DNS resolver cache.
            if !self.session.is_null() {
                unsafe { (self.wintun.end_session)(self.session.as_raw()) };
                self.session = SendHandle(ptr::null_mut());
            }
            if !self.adapter.is_null() {
                unsafe { (self.wintun.close_adapter)(self.adapter.as_raw()) };
                self.adapter = SendHandle(ptr::null_mut());
            }
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
pub use win32::{WindowsTunSession, WindowsTunStartParts};

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
}
