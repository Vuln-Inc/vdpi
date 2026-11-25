//! macOS desktop `utun` backend (`PF_SYSTEM` / `SYSPROTO_CONTROL`), physical uplink
//! detection for `IP_BOUND_IF` / `IPV6_BOUND_IF`, split-route + `-ifscope` + LAN exclusion
//! management, native `SCDynamicStore` session-scoped DNS on `utunN`, and a detached
//! `setsid()` crash-cleanup guard.
//!
//! Pure parsing helpers and the crash-guard serde schema live outside `#[cfg(target_os = "macos")]`
//! so they compile and unit-test cleanly on Windows, Linux, and macOS alike.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Virtual IPv4 address assigned to the local `utun` interface.
pub const MACOS_TUN_IPV4: &str = "198.18.0.1";

/// Peer / virtual DNS IPv4 address assigned on the point-to-point `utun` link.
pub const MACOS_TUN_DNS_V4: &str = "198.18.0.2";

/// IPv4 point-to-point netmask for `198.18.0.1/30`.
pub const MACOS_TUN_NETMASK_V4: &str = "255.255.255.252";

/// Virtual IPv6 address assigned to `utun` when `--tun-ipv6` is enabled.
pub const MACOS_TUN_IPV6: &str = "fd00:7664:7069::1";

/// Virtual DNS IPv6 address published via `SCDynamicStore` when `--tun-ipv6` is enabled.
pub const MACOS_TUN_DNS_V6: &str = "fd00:7664:7069::2";

/// Fallback MTU configured on the macOS `utun` interface when Jumbo MTUs are rejected.
pub const MACOS_TUN_MTU: u16 = 1500;

/// Hidden CLI flag used to invoke the detached macOS TUN crash-cleanup guard process.
pub const MACOS_TUN_GUARD_ARG: &str = "--internal-macos-tun-guard";

/// Crash-recovery state file persisted atomically (mode `0600`) before mutating routes or DNS.
pub const MACOS_TUN_STATE_PATH: &str = "/Library/Application Support/vdpi/macos-tun-state.json";

/// Restrictive file permissions (`0600`) applied to [`MACOS_TUN_STATE_PATH`].
pub const MACOS_TUN_STATE_MODE: u32 = 0o600;

/// Returns `true` if `name` identifies a virtual, tunnel, loopback, or Apple peer-to-peer
/// interface that must never be selected as the physical outbound uplink.
pub fn is_virtual_macos_interface(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("utun")
        || lower.starts_with("tun")
        || lower.starts_with("tap")
        || lower.starts_with("wg")
        || lower.starts_with("ap")
        || lower.starts_with("lo")
        || lower.starts_with("awdl")
        || lower.starts_with("llw")
        || lower.starts_with("ipsec")
        || lower.starts_with("ppp")
        || lower.starts_with("gif")
        || lower.starts_with("stf")
        || lower.starts_with("bridge")
        || lower.starts_with("feth")
        || lower.starts_with("vmenet")
        || lower.starts_with("anpi")
        || lower.starts_with("pktap")
}

/// Parses the stdout of `/sbin/route -n get default` (or `-inet6 default`) and returns
/// `(interface, Option<gateway>)` for a non-virtual physical interface.
///
/// Rejects virtual interfaces (`utun*`, `tun*`, `tap*`, `wg*`, `ap*`, `lo*`, `awdl*`,
/// `ipsec*`, `ppp*`, etc.), rejects routes without `UP` or with `BLACKHOLE`/`REJECT` flags,
/// and ignores link-layer pseudo-gateways such as `link#6`.
pub fn parse_route_get_default(stdout: &str) -> Option<(String, Option<String>)> {
    let mut interface: Option<String> = None;
    let mut gateway: Option<String> = None;
    let mut flags: Option<String> = None;

    for line in stdout.lines() {
        let Some((key, val)) = line.trim().split_once(':') else {
            continue;
        };
        let key = key.trim();
        let val = val.trim();
        if val.is_empty() {
            continue;
        }
        if key.eq_ignore_ascii_case("interface") {
            interface = Some(val.to_string());
        } else if key.eq_ignore_ascii_case("gateway")
            && val
                .split('%')
                .next()
                .unwrap_or("")
                .parse::<IpAddr>()
                .is_ok()
        {
            gateway = Some(val.to_string());
        } else if key.eq_ignore_ascii_case("flags") {
            flags = Some(val.to_string());
        }
    }

    if let Some(flags_val) = flags {
        let trimmed = flags_val
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        let mut has_up = false;
        for flag in trimmed.split(',').map(str::trim) {
            if flag.eq_ignore_ascii_case("UP") {
                has_up = true;
            } else if flag.eq_ignore_ascii_case("BLACKHOLE") || flag.eq_ignore_ascii_case("REJECT")
            {
                return None;
            }
        }
        if !has_up {
            return None;
        }
    }

    let iface = interface?;
    if is_virtual_macos_interface(&iface) {
        return None;
    }
    Some((iface, gateway))
}

/// Parses stdout from `/usr/sbin/networksetup -getdnsservers <service>`.
///
/// Keeps only valid IPv4/IPv6 addresses (`IpAddr`), automatically returning an empty `Vec`
/// when DNS is managed via DHCP (`"There aren't any DNS Servers set on ..."`) or ignoring
/// non-IP diagnostic lines.
pub fn parse_dns_servers_output(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.parse::<IpAddr>().is_ok())
        .map(ToOwned::to_owned)
        .collect()
}

/// Sanitizes a service's current DNS servers before recording them as original DNS.
///
/// Never records [`MACOS_TUN_DNS_V4`] (`198.18.0.2`) as an original server; if the current
/// list is `[MACOS_TUN_DNS_V4]` with no prior backup, returns an empty `Vec` (DHCP).
pub fn sanitize_original_dns_servers(servers: Vec<String>) -> Vec<String> {
    servers
        .into_iter()
        .filter(|srv| srv.trim() != MACOS_TUN_DNS_V4)
        .collect()
}

/// Returns `true` if `current` equals `[MACOS_TUN_DNS_V4]`, indicating `vdpi` still owns
/// the service's DNS configuration.
pub fn is_vdpi_owned_dns_servers(current: &[String]) -> bool {
    current.len() == 1 && current[0].trim() == MACOS_TUN_DNS_V4
}

/// Returns `true` if a raw Darwin `PF_ROUTE` message header represents a routing table,
/// interface, or address state change relevant to VPN detection and uplink rebinding.
pub fn is_relevant_pf_route_msg(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    // Darwin <net/route.h>: bytes 0..2 = rtm_msglen, byte 2 = rtm_version (5), byte 3 = rtm_type.
    const RTM_VERSION: u8 = 5;
    const RTM_ADD: u8 = 0x01;
    const RTM_DELETE: u8 = 0x02;
    const RTM_CHANGE: u8 = 0x03;
    const RTM_REDIRECT: u8 = 0x06;
    const RTM_NEWADDR: u8 = 0x0c;
    const RTM_DELADDR: u8 = 0x0d;
    const RTM_IFINFO: u8 = 0x0e;
    const RTM_IFINFO2: u8 = 0x12;

    buf[2] == RTM_VERSION
        && matches!(
            buf[3],
            RTM_ADD
                | RTM_DELETE
                | RTM_CHANGE
                | RTM_REDIRECT
                | RTM_NEWADDR
                | RTM_DELADDR
                | RTM_IFINFO
                | RTM_IFINFO2
        )
}

/// Single routing-table entry installed by `MacosTunSession` and symmetrically removed
/// during normal `Drop` or crash-guard recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRoute {
    /// Destination CIDR prefix or `"default"` (e.g. `"1.0.0.0/8"`, `"10.0.0.0/8"`, `"2000::/3"`, `"default"`).
    pub destination: String,
    /// `true` for `-inet6` routes, `false` for IPv4 `-inet` routes.
    #[serde(default)]
    pub is_ipv6: bool,
    /// Interface name for `-interface <name>` routes.
    #[serde(default)]
    pub interface: Option<String>,
    /// Gateway IP address for physical-gateway LAN exclusion or `-ifscope` default routes.
    #[serde(default)]
    pub gateway: Option<String>,
    /// Optional Darwin interface scope (`-ifscope <iface>`) for `IP_BOUND_IF` default routes.
    #[serde(default)]
    pub ifscope: Option<String>,
}

/// Snapshot of a macOS network service's DNS configuration prior to TUN activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServiceSnapshot {
    /// `networksetup` service name (e.g. `"Wi-Fi"`, `"USB 10/100/1000 LAN"`).
    pub service: String,
    /// Original DNS servers; empty indicates DHCP/automatic (`Empty` in `networksetup`).
    #[serde(default)]
    pub original_servers: Vec<String>,
}

/// Complete rollback payload sent over stdin to the detached macOS TUN crash guard and
/// atomically persisted to [`MACOS_TUN_STATE_PATH`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosTunGuardState {
    /// Kernel-assigned `utun` interface name (e.g. `"utun4"`).
    pub iface_name: String,
    /// Routes installed by `vdpi`, deleted in reverse order on cleanup.
    #[serde(default)]
    pub routes: Vec<ManagedRoute>,
    /// Per-service DNS snapshots restored via `networksetup -setdnsservers`.
    #[serde(default)]
    pub dns_snapshots: Vec<DnsServiceSnapshot>,
}

impl MacosTunGuardState {
    /// Atomically persists this state as JSON to `path` with mode `0600`.
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialize macOS TUN state file")?;
        write_file_atomic(path, &json, MACOS_TUN_STATE_MODE)
    }

    /// Loads persisted crash-recovery state from `path`, returning `Ok(None)` if absent.
    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        match fs::read_to_string(path) {
            Ok(raw) => {
                let state = serde_json::from_str(&raw).with_context(|| {
                    format!(
                        "failed to deserialize macOS TUN state from {}",
                        path.display()
                    )
                })?;
                Ok(Some(state))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

fn write_file_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("macos-tun-state.json");
    let tmp = parent.join(format!(
        ".{base}.vdpi.tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let write_res = (|| -> Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        let mut file = opts
            .open(&tmp)
            .with_context(|| format!("failed to create temp file {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to chmod temp file {}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write temp file {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temp file {}", tmp.display()))?;
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp, path) {
        #[cfg(windows)]
        {
            let _ = fs::remove_file(path);
            if fs::rename(&tmp, path).is_ok() {
                return Ok(());
            }
        }
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                tmp.display()
            )
        });
    }

    Ok(())
}

/// Serializes [`MacosTunGuardState`] as a single newline-delimited JSON payload for the
/// detached crash guard's stdin pipe.
pub fn build_macos_tun_cleanup_payload(state: &MacosTunGuardState) -> Result<String> {
    let mut line = serde_json::to_string(state)
        .context("failed to serialize macOS TUN cleanup guard state")?;
    line.push('\n');
    Ok(line)
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{
        build_macos_tun_cleanup_payload, is_relevant_pf_route_msg, is_vdpi_owned_dns_servers,
        parse_dns_servers_output, parse_route_get_default, MacosTunGuardState, ManagedRoute,
        MACOS_TUN_DNS_V4, MACOS_TUN_DNS_V6, MACOS_TUN_GUARD_ARG, MACOS_TUN_IPV4, MACOS_TUN_IPV6,
        MACOS_TUN_MTU, MACOS_TUN_NETMASK_V4, MACOS_TUN_STATE_PATH,
    };
    use crate::binder::{DynamicOutboundBinder, OutboundTarget};
    use crate::platform::macos::list_configurable_network_services;
    use anyhow::{bail, Context, Result};
    use std::ffi::{c_void, CStr, CString};
    use std::fs;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};
    use tokio::sync::watch;
    use tracing::{debug, info, warn};

    const UTUN_CONTROL_NAME: &CStr = c"com.apple.net.utun_control";
    const GUARD_READY: &str = "ready";

    const RFC1918_EXCLUSIONS: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
    const LINK_LOCAL_EXCLUSIONS: &[&str] = &["169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"];

    /// Non-zero-anchor IPv4 split routes covering `1.0.0.0..=255.255.255.255` while leaving
    /// `0.0.0.0/8` untouched so `IP_BOUND_IF` on Ventura/Sonoma/Sequoia/Tahoe never hits
    /// `ENETUNREACH`.
    const IPV4_SPLIT_ROUTES: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];

    const ROUTE_DEBOUNCE_WINDOW: Duration = Duration::from_millis(350);
    const ROUTE_DEBOUNCE_MAX_WAIT: Duration = Duration::from_millis(1500);

    const SC_STORE_NAME: &str = "com.vdpi.tun";
    const SC_KEY_SERVICE: &str = "State:/Network/Service/com.vdpi.tun/Service";
    const SC_KEY_IPV4: &str = "State:/Network/Service/com.vdpi.tun/IPv4";
    const SC_KEY_IPV6: &str = "State:/Network/Service/com.vdpi.tun/IPv6";
    const SC_KEY_DNS: &str = "State:/Network/Service/com.vdpi.tun/DNS";

    type CFTypeRef = *const c_void;
    type CFAllocatorRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFBooleanRef = *const c_void;
    type CFNumberRef = *const c_void;
    type CFArrayRef = *const c_void;
    type CFDictionaryRef = *const c_void;
    type SCDynamicStoreRef = *const c_void;
    type CFIndex = isize;
    type CFStringEncoding = u32;
    type CFNumberType = CFIndex;
    type Boolean = u8;

    const K_CF_STRING_ENCODING_UTF8: CFStringEncoding = 0x0800_0100;
    const K_CF_NUMBER_SINT32_TYPE: CFNumberType = 3;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        static kCFBooleanTrue: CFBooleanRef;
        static kCFTypeArrayCallBacks: usize;
        static kCFTypeDictionaryKeyCallBacks: usize;
        static kCFTypeDictionaryValueCallBacks: usize;

        fn CFRelease(cf: CFTypeRef);
        fn CFStringCreateWithBytes(
            alloc: CFAllocatorRef,
            bytes: *const u8,
            num_bytes: CFIndex,
            encoding: CFStringEncoding,
            is_external_representation: Boolean,
        ) -> CFStringRef;
        fn CFNumberCreate(
            allocator: CFAllocatorRef,
            the_type: CFNumberType,
            value_ptr: *const c_void,
        ) -> CFNumberRef;
        fn CFArrayCreate(
            allocator: CFAllocatorRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            callbacks: *const c_void,
        ) -> CFArrayRef;
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            num_values: CFIndex,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;
    }

    #[link(name = "SystemConfiguration", kind = "framework")]
    extern "C" {
        static kSCDynamicStoreUseSessionKeys: CFStringRef;

        fn SCDynamicStoreCreateWithOptions(
            allocator: CFAllocatorRef,
            name: CFStringRef,
            store_options: CFDictionaryRef,
            callout: *const c_void,
            context: *mut c_void,
        ) -> SCDynamicStoreRef;
        fn SCDynamicStoreSetValue(
            store: SCDynamicStoreRef,
            key: CFStringRef,
            value: CFTypeRef,
        ) -> Boolean;
        fn SCDynamicStoreRemoveValue(store: SCDynamicStoreRef, key: CFStringRef) -> Boolean;
        fn SCError() -> libc::c_int;
        fn SCErrorString(status: libc::c_int) -> *const libc::c_char;
    }

    struct CfOwned(CFTypeRef);

    impl CfOwned {
        fn from_raw(raw: CFTypeRef, label: &str) -> Result<Self> {
            if raw.is_null() {
                bail!("CoreFoundation failed to allocate {label}");
            }
            Ok(Self(raw))
        }

        fn as_ptr(&self) -> CFTypeRef {
            self.0
        }
    }

    impl Drop for CfOwned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a valid non-null +1 retained CoreFoundation object owned by `Self`.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    fn cf_string(s: &str) -> Result<CfOwned> {
        let len = CFIndex::try_from(s.len()).context("CFString length overflow")?;
        // SAFETY: `s.as_ptr()` is valid for `len` UTF-8 bytes; `CFStringCreateWithBytes`
        // copies the bytes into a newly allocated +1 retained `CFString`.
        let raw = unsafe {
            CFStringCreateWithBytes(ptr::null(), s.as_ptr(), len, K_CF_STRING_ENCODING_UTF8, 0)
        };
        CfOwned::from_raw(raw, "CFString")
    }

    fn cf_number_i32(value: i32) -> Result<CfOwned> {
        // SAFETY: `value` is a valid stack `i32` matching `K_CF_NUMBER_SINT32_TYPE` (3).
        let raw = unsafe {
            CFNumberCreate(
                ptr::null(),
                K_CF_NUMBER_SINT32_TYPE,
                ptr::from_ref(&value).cast::<c_void>(),
            )
        };
        CfOwned::from_raw(raw, "CFNumber(i32)")
    }

    fn cf_array(items: &[&CfOwned]) -> Result<CfOwned> {
        let ptrs: Vec<CFTypeRef> = items.iter().map(|item| item.as_ptr()).collect();
        let len = CFIndex::try_from(ptrs.len()).context("CFArray length overflow")?;
        // SAFETY: `ptrs` holds `len` valid `CFTypeRef` pointers; `kCFTypeArrayCallBacks`
        // retains each element so the returned `CFArray` independently owns its entries.
        let raw = unsafe {
            CFArrayCreate(
                ptr::null(),
                ptrs.as_ptr(),
                len,
                ptr::addr_of!(kCFTypeArrayCallBacks).cast::<c_void>(),
            )
        };
        CfOwned::from_raw(raw, "CFArray")
    }

    fn cf_dict_raw(entries: &[(CFTypeRef, CFTypeRef)]) -> Result<CfOwned> {
        let mut keys: Vec<CFTypeRef> = Vec::with_capacity(entries.len());
        let mut vals: Vec<CFTypeRef> = Vec::with_capacity(entries.len());
        for &(k, v) in entries {
            keys.push(k);
            vals.push(v);
        }
        let len = CFIndex::try_from(entries.len()).context("CFDictionary length overflow")?;
        // SAFETY: `keys` and `vals` each contain `len` valid `CFTypeRef` pointers;
        // `kCFTypeDictionaryKeyCallBacks` and `kCFTypeDictionaryValueCallBacks` retain
        // every key and value inside the newly allocated `CFDictionary`.
        let raw = unsafe {
            CFDictionaryCreate(
                ptr::null(),
                keys.as_ptr(),
                vals.as_ptr(),
                len,
                ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast::<c_void>(),
                ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast::<c_void>(),
            )
        };
        CfOwned::from_raw(raw, "CFDictionary")
    }

    fn sc_last_error() -> String {
        // SAFETY: `SCError` and `SCErrorString` are thread-safe SystemConfiguration getters;
        // `SCErrorString` returns a static NUL-terminated C string (or null).
        unsafe {
            let code = SCError();
            let msg = SCErrorString(code);
            if msg.is_null() {
                format!("SCError({code})")
            } else {
                let desc = CStr::from_ptr(msg).to_string_lossy();
                format!("{desc} (SCError {code})")
            }
        }
    }

    /// Session-scoped `SCDynamicStore` handle (`kSCDynamicStoreUseSessionKeys = true`) publishing
    /// transient `com.vdpi.tun` service/IP/DNS state bound to `utunN`.
    ///
    /// Because all keys are session-scoped, macOS `configd` automatically removes them within
    /// 1-3 seconds even on `SIGKILL` or process crash without ever touching `preferences.plist`.
    struct ScDynamicStoreDnsSession {
        store: SCDynamicStoreRef,
        published_keys: Vec<&'static str>,
    }

    // SAFETY: `SCDynamicStoreRef` may be transferred sequentially between threads;
    // `ScDynamicStoreDnsSession` exclusively owns the handle, never shares it concurrently,
    // and only mutates or releases it via `&mut self` (setup / `Drop`).
    unsafe impl Send for ScDynamicStoreDnsSession {}

    impl ScDynamicStoreDnsSession {
        fn install(iface_name: &str, ipv6_active: bool) -> Result<Self> {
            let store_name = cf_string(SC_STORE_NAME)?;
            // SAFETY: `kSCDynamicStoreUseSessionKeys` and `kCFBooleanTrue` are immutable
            // framework-exported `CFStringRef` / `CFBooleanRef` constants.
            let (use_session_keys, cf_true) =
                unsafe { (kSCDynamicStoreUseSessionKeys, kCFBooleanTrue) };
            if use_session_keys.is_null() || cf_true.is_null() {
                bail!(
                    "macOS CoreFoundation/SystemConfiguration session-key symbols resolved to null"
                );
            }
            let options = cf_dict_raw(&[(use_session_keys, cf_true)])?;

            // SAFETY: `store_name` and `options` are valid CoreFoundation objects; callout and
            // context pointers are null.
            let store = unsafe {
                SCDynamicStoreCreateWithOptions(
                    ptr::null(),
                    store_name.as_ptr(),
                    options.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                )
            };
            if store.is_null() {
                bail!(
                    "SCDynamicStoreCreateWithOptions failed: {}",
                    sc_last_error()
                );
            }

            let mut session = Self {
                store,
                published_keys: Vec::with_capacity(4),
            };

            // 1. Service rank (added FIRST, removed LAST so configd never promotes utun as primary).
            let k_primary_rank = cf_string("PrimaryRank")?;
            let v_never = cf_string("Never")?;
            let service_dict = cf_dict_raw(&[(k_primary_rank.as_ptr(), v_never.as_ptr())])?;
            session.set_value(SC_KEY_SERVICE, &service_dict)?;

            // 2. IPv4 binding to utunN.
            let k_addresses = cf_string("Addresses")?;
            let k_router = cf_string("Router")?;
            let k_interface_name = cf_string("InterfaceName")?;
            let v_iface = cf_string(iface_name)?;

            let v_ipv4_addr = cf_string(MACOS_TUN_IPV4)?;
            let v_ipv4_addrs = cf_array(&[&v_ipv4_addr])?;
            let ipv4_dict = cf_dict_raw(&[
                (k_addresses.as_ptr(), v_ipv4_addrs.as_ptr()),
                (k_router.as_ptr(), v_ipv4_addr.as_ptr()),
                (k_interface_name.as_ptr(), v_iface.as_ptr()),
            ])?;
            session.set_value(SC_KEY_IPV4, &ipv4_dict)?;

            // 3. Optional IPv6 binding to utunN.
            if ipv6_active {
                let v_ipv6_addr = cf_string(MACOS_TUN_IPV6)?;
                let v_ipv6_addrs = cf_array(&[&v_ipv6_addr])?;
                let ipv6_dict = cf_dict_raw(&[
                    (k_addresses.as_ptr(), v_ipv6_addrs.as_ptr()),
                    (k_router.as_ptr(), v_ipv6_addr.as_ptr()),
                    (k_interface_name.as_ptr(), v_iface.as_ptr()),
                ])?;
                session.set_value(SC_KEY_IPV6, &ipv6_dict)?;
            }

            // 4. Supplemental match-all DNS resolver scoped to com.vdpi.tun.
            let k_server_addresses = cf_string("ServerAddresses")?;
            let k_match_domains = cf_string("SupplementalMatchDomains")?;
            let k_match_orders = cf_string("SupplementalMatchOrders")?;
            let k_match_no_search = cf_string("SupplementalMatchDomainsNoSearch")?;

            let v_dns_v4 = cf_string(MACOS_TUN_DNS_V4)?;
            let v_dns_v6 = if ipv6_active {
                Some(cf_string(MACOS_TUN_DNS_V6)?)
            } else {
                None
            };
            let mut dns_servers: Vec<&CfOwned> = vec![&v_dns_v4];
            if let Some(ref v6) = v_dns_v6 {
                dns_servers.push(v6);
            }
            let v_server_addresses = cf_array(&dns_servers)?;

            let v_empty_domain = cf_string("")?;
            let v_match_domains = cf_array(&[&v_empty_domain])?;

            let v_order_one = cf_number_i32(1)?;
            let v_match_orders = cf_array(&[&v_order_one])?;

            let v_no_search_one = cf_number_i32(1)?;

            let dns_dict = cf_dict_raw(&[
                (k_server_addresses.as_ptr(), v_server_addresses.as_ptr()),
                (k_match_domains.as_ptr(), v_match_domains.as_ptr()),
                (k_match_orders.as_ptr(), v_match_orders.as_ptr()),
                (k_match_no_search.as_ptr(), v_no_search_one.as_ptr()),
            ])?;
            session.set_value(SC_KEY_DNS, &dns_dict)?;

            flush_macos_dns_cache();
            Ok(session)
        }

        fn set_value(&mut self, key: &'static str, value: &CfOwned) -> Result<()> {
            let cf_key = cf_string(key)?;
            // SAFETY: `self.store`, `cf_key`, and `value` are valid non-null CoreFoundation refs.
            let ok = unsafe { SCDynamicStoreSetValue(self.store, cf_key.as_ptr(), value.as_ptr()) };
            if ok == 0 {
                bail!("SCDynamicStoreSetValue({key}) failed: {}", sc_last_error());
            }
            self.published_keys.push(key);
            Ok(())
        }
    }

    impl Drop for ScDynamicStoreDnsSession {
        fn drop(&mut self) {
            let had_keys = !self.published_keys.is_empty();
            for key in self.published_keys.iter().rev() {
                if let Ok(cf_key) = cf_string(key) {
                    // SAFETY: `self.store` and `cf_key` are valid non-null CoreFoundation refs.
                    let ok = unsafe { SCDynamicStoreRemoveValue(self.store, cf_key.as_ptr()) };
                    if ok == 0 {
                        debug!(
                            key = *key,
                            error = %sc_last_error(),
                            "SCDynamicStoreRemoveValue returned false during cleanup"
                        );
                    }
                }
            }
            if !self.store.is_null() {
                // SAFETY: `self.store` is exclusively owned (+1 retain count) by `Self`.
                unsafe { CFRelease(self.store) };
                self.store = ptr::null();
            }
            if had_keys {
                flush_macos_dns_cache();
            }
        }
    }

    /// Opens a dynamically assigned macOS `utunN` kernel control socket, configures
    /// `FD_CLOEXEC` and `O_NONBLOCK`, and returns `(OwnedFd, iface_name)`.
    pub fn open_utun() -> Result<(OwnedFd, String)> {
        // SAFETY: Standard POSIX/Darwin PF_SYSTEM control socket creation.
        let raw_fd =
            unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error())
                .context("socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) failed");
        }
        // SAFETY: `raw_fd` is a newly created, exclusively owned descriptor; wrapping it
        // immediately guarantees no fd leak on any subsequent error path.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let fd = owned_fd.as_raw_fd();

        // Set FD_CLOEXEC early so helper subprocesses never inherit the utun fd.
        set_fd_cloexec(fd)?;

        // SAFETY: `ctl_info` is a POD C struct zero-initialized before populating `ctl_name`.
        let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let ctl_name_bytes = UTUN_CONTROL_NAME.to_bytes_with_nul();
        debug_assert!(ctl_name_bytes.len() <= info.ctl_name.len());
        // SAFETY: `ctl_name_bytes` (27 bytes including NUL) fits inside `ctl_name` (96 bytes)
        // and the buffers do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(
                ctl_name_bytes.as_ptr().cast::<libc::c_char>(),
                info.ctl_name.as_mut_ptr(),
                ctl_name_bytes.len(),
            );
        }

        // SAFETY: `fd` is a valid PF_SYSTEM socket and `info` matches CTLIOCGINFO.
        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, ptr::from_mut(&mut info)) } < 0 {
            return Err(io::Error::last_os_error()).context(
                "ioctl(CTLIOCGINFO, com.apple.net.utun_control) failed (root/sudo required)",
            );
        }

        // SAFETY: `sockaddr_ctl` is a POD C struct zero-initialized before setting fields.
        let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
        addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0; // Request next free utun unit from kernel.

        // SAFETY: `addr` is properly sized and aligned for `connect()` on `PF_SYSTEM`.
        if unsafe {
            libc::connect(
                fd,
                ptr::from_ref(&addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error())
                .context("connect(sockaddr_ctl) failed for utun (root/sudo required)");
        }

        let mut ifname_buf = [0u8; 64];
        let mut ifname_len = ifname_buf.len() as libc::socklen_t;
        // SAFETY: `ifname_buf` is writable for `ifname_len` bytes and receives NUL-terminated name.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                libc::UTUN_OPT_IFNAME,
                ifname_buf.as_mut_ptr().cast::<libc::c_void>(),
                &mut ifname_len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error())
                .context("getsockopt(UTUN_OPT_IFNAME) failed on utun socket");
        }

        let used = (ifname_len as usize).min(ifname_buf.len());
        let nul_pos = ifname_buf[..used]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(used);
        let iface_name = String::from_utf8(ifname_buf[..nul_pos].to_vec())
            .context("kernel returned non-UTF-8 utun interface name")?;
        if iface_name.is_empty() {
            bail!("kernel returned empty utun interface name");
        }

        set_nonblocking(fd)?;

        Ok((owned_fd, iface_name))
    }

    struct RouteMonitor {
        stop_flag: Arc<AtomicBool>,
        stop_write_fd: OwnedFd,
        thread: Option<JoinHandle<()>>,
    }

    impl RouteMonitor {
        fn start(
            binder: Arc<DynamicOutboundBinder>,
            route_tx: Arc<watch::Sender<u64>>,
            managed_ifscope_v4: Arc<Mutex<Option<ManagedRoute>>>,
            managed_ifscope_v6: Arc<Mutex<Option<ManagedRoute>>>,
            ipv6_active: bool,
        ) -> Result<Self> {
            let route_fd = open_pf_route_socket()?;
            let (stop_read_fd, stop_write_fd) = create_stop_pipe()?;
            let stop_flag = Arc::new(AtomicBool::new(false));
            let thread_stop_flag = Arc::clone(&stop_flag);

            let handle = thread::Builder::new()
                .name("vdpi-macos-route-watch".to_string())
                .spawn(move || {
                    run_pf_route_monitor_loop(
                        route_fd,
                        stop_read_fd,
                        thread_stop_flag,
                        binder,
                        route_tx,
                        managed_ifscope_v4,
                        managed_ifscope_v6,
                        ipv6_active,
                    );
                })
                .context("failed to spawn macOS PF_ROUTE monitoring thread")?;

            Ok(Self {
                stop_flag,
                stop_write_fd,
                thread: Some(handle),
            })
        }
    }

    impl Drop for RouteMonitor {
        fn drop(&mut self) {
            self.stop_flag.store(true, Ordering::Release);
            let byte: u8 = 1;
            // SAFETY: `stop_write_fd` is a valid non-blocking pipe write descriptor.
            let _ = unsafe {
                libc::write(
                    self.stop_write_fd.as_raw_fd(),
                    ptr::from_ref(&byte).cast::<c_void>(),
                    1,
                )
            };
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
        }
    }

    /// Active macOS desktop `utun` session owning `-ifscope` default routes, split routes,
    /// LAN exclusions, native `SCDynamicStore` session DNS, outbound binder state, a
    /// `PF_ROUTE` monitor, and a detached crash-recovery guard.
    pub struct MacosTunSession {
        binder: Arc<DynamicOutboundBinder>,
        physical_nic: String,
        mtu: u16,
        guard_state: MacosTunGuardState,
        guard_child: Option<Child>,
        dns_session: Option<ScDynamicStoreDnsSession>,
        managed_ifscope_v4: Arc<Mutex<Option<ManagedRoute>>>,
        managed_ifscope_v6: Arc<Mutex<Option<ManagedRoute>>>,
        route_tx: Arc<watch::Sender<u64>>,
        route_monitor: Option<RouteMonitor>,
    }

    impl MacosTunSession {
        /// Starts a macOS desktop `utun` session:
        /// 1. Verifies root privileges, recovers any stale crash-recovery state on disk, and
        ///    heals any legacy v0.5.x `networksetup` DNS stuck on `198.18.0.2`.
        /// 2. Detects the physical default uplink and binds `DynamicOutboundBinder` via `IP_BOUND_IF`.
        /// 3. Opens `utunN` and configures `198.18.0.1 <-> 198.18.0.2` (Jumbo MTU fallback, optional IPv6).
        /// 4. Atomically persists crash-recovery state before mutating routes.
        /// 5. Installs explicit `-ifscope` default route(s), LAN/special exclusion routes, and
        ///    8 non-zero-anchor IPv4 split routes (`1.0.0.0/8`..`128.0.0.0/1`, optional `2000::/3`).
        /// 6. Publishes transient `SCDynamicStore` session keys bound to `utunN` and flushes DNS cache.
        /// 7. Starts the `PF_ROUTE` live route/uplink monitor and arms the detached `setsid()` crash guard.
        pub fn start(
            binder: Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
        ) -> Result<(Self, OwnedFd)> {
            // SAFETY: `geteuid()` is always safe to call and has no failure modes.
            if unsafe { libc::geteuid() } != 0 {
                bail!("macOS TUN mode requires root privileges (re-run with sudo)");
            }

            recover_stale_macos_tun_state();
            heal_legacy_networksetup_dns();

            let (phys_iface, phys_gw) = detect_physical_default_v4()?;
            let if_index_v4 = if_name_to_index(&phys_iface)?;
            let phys_v6 = detect_physical_default_v6();
            let if_index_v6 = phys_v6
                .as_ref()
                .and_then(|(iface6, _)| if_name_to_index(iface6).ok());

            binder.update(OutboundTarget {
                nic_name: Some(phys_iface.clone()),
                if_index_v4: Some(if_index_v4),
                if_index_v6,
                fwmark: None,
                fail_closed: true,
            });

            let mut rollback = StartupRollback {
                binder: &binder,
                state: MacosTunGuardState::default(),
                state_persisted: false,
                committed: false,
            };

            let (tun_fd, iface_name) = open_utun()?;
            rollback.state.iface_name = iface_name.clone();

            let (mtu, ipv6_active) = configure_utun_interface(&iface_name, tun_ipv6)?;

            // Persist initial crash-recovery state atomically (0600) BEFORE mutating routes.
            save_macos_tun_state(&rollback.state)?;
            rollback.state_persisted = true;

            // Install explicit `-ifscope <phys_iface>` default routes BEFORE split routes so
            // `IP_BOUND_IF` / `IPV6_BOUND_IF` outbound sockets always resolve a scoped default.
            let mut initial_ifscope_v4: Option<ManagedRoute> = None;
            if let Some(ref gw) = phys_gw {
                let route = ManagedRoute {
                    destination: "default".to_string(),
                    is_ipv6: false,
                    interface: None,
                    gateway: Some(gw.clone()),
                    ifscope: Some(phys_iface.clone()),
                };
                match add_managed_route(&route, true) {
                    Ok(true) => {
                        initial_ifscope_v4 = Some(route.clone());
                        rollback.state.routes.push(route);
                        save_macos_tun_state(&rollback.state)?;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(
                            iface = %phys_iface,
                            gateway = %gw,
                            error = %e,
                            "failed to install -ifscope IPv4 default route for IP_BOUND_IF"
                        );
                    }
                }
            }

            let mut initial_ifscope_v6: Option<ManagedRoute> = None;
            if ipv6_active {
                if let Some((ref iface6, Some(ref gw6))) = phys_v6 {
                    let route = ManagedRoute {
                        destination: "default".to_string(),
                        is_ipv6: true,
                        interface: None,
                        gateway: Some(gw6.clone()),
                        ifscope: Some(iface6.clone()),
                    };
                    match add_managed_route(&route, true) {
                        Ok(true) => {
                            initial_ifscope_v6 = Some(route.clone());
                            rollback.state.routes.push(route);
                            save_macos_tun_state(&rollback.state)?;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(
                                iface = %iface6,
                                gateway = %gw6,
                                error = %e,
                                "failed to install -ifscope IPv6 default route for IPV6_BOUND_IF"
                            );
                        }
                    }
                }
            }

            // Install LAN exclusions before split routes so local networks stay reachable
            // directly on the physical NIC.
            for prefix in RFC1918_EXCLUSIONS {
                let route = ManagedRoute {
                    destination: (*prefix).to_string(),
                    is_ipv6: false,
                    interface: phys_gw.is_none().then(|| phys_iface.clone()),
                    gateway: phys_gw.clone(),
                    ifscope: None,
                };
                match add_managed_route(&route, true) {
                    Ok(true) => {
                        rollback.state.routes.push(route);
                        save_macos_tun_state(&rollback.state)?;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(prefix, error = %e, "failed to install RFC1918 exclusion route")
                    }
                }
            }

            for prefix in LINK_LOCAL_EXCLUSIONS {
                let route = ManagedRoute {
                    destination: (*prefix).to_string(),
                    is_ipv6: false,
                    interface: Some(phys_iface.clone()),
                    gateway: None,
                    ifscope: None,
                };
                match add_managed_route(&route, true) {
                    Ok(true) => {
                        rollback.state.routes.push(route);
                        save_macos_tun_state(&rollback.state)?;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        warn!(
                            prefix,
                            error = %e,
                            "failed to install link-local/multicast/reserved exclusion route"
                        );
                    }
                }
            }

            // Install 8 non-zero-anchor IPv4 split routes on utunN (leaving 0.0.0.0/8 untouched
            // so `IP_BOUND_IF` never hits ENETUNREACH on macOS Ventura/Sonoma/Sequoia/Tahoe).
            // `allow_existing = false` ensures pre-existing conflicting routes fail startup cleanly.
            for prefix in IPV4_SPLIT_ROUTES {
                let route = ManagedRoute {
                    destination: (*prefix).to_string(),
                    is_ipv6: false,
                    interface: Some(iface_name.clone()),
                    gateway: None,
                    ifscope: None,
                };
                rollback.state.routes.push(route.clone());
                save_macos_tun_state(&rollback.state)?;
                if let Err(e) = add_managed_route(&route, false).with_context(|| {
                    format!("failed to install split route {prefix} on {iface_name}")
                }) {
                    rollback.state.routes.pop();
                    let _ = save_macos_tun_state(&rollback.state);
                    return Err(e);
                }
            }

            if ipv6_active {
                let route = ManagedRoute {
                    destination: "2000::/3".to_string(),
                    is_ipv6: true,
                    interface: Some(iface_name.clone()),
                    gateway: None,
                    ifscope: None,
                };
                rollback.state.routes.push(route.clone());
                save_macos_tun_state(&rollback.state)?;
                if let Err(e) = add_managed_route(&route, false).with_context(|| {
                    format!("failed to install IPv6 split route 2000::/3 on {iface_name}")
                }) {
                    rollback.state.routes.pop();
                    let _ = save_macos_tun_state(&rollback.state);
                    return Err(e);
                }
            }

            // Publish transient session-scoped SCDynamicStore DNS keys bound to utunN.
            // If any later startup step fails, dropping `dns_session` automatically cleans them up.
            let dns_session = ScDynamicStoreDnsSession::install(&iface_name, ipv6_active)?;

            // Start the PF_ROUTE monitoring thread after initial route setup so our own
            // startup mutations do not trigger spurious notifications.
            let managed_ifscope_v4 = Arc::new(Mutex::new(initial_ifscope_v4));
            let managed_ifscope_v6 = Arc::new(Mutex::new(initial_ifscope_v6));
            let (route_tx, _) = watch::channel::<u64>(0);
            let route_tx = Arc::new(route_tx);
            let route_monitor = RouteMonitor::start(
                Arc::clone(&binder),
                Arc::clone(&route_tx),
                Arc::clone(&managed_ifscope_v4),
                Arc::clone(&managed_ifscope_v6),
                ipv6_active,
            )?;

            // Arm the detached crash guard so SIGKILL still restores managed routes immediately.
            let guard_child = spawn_detached_guard(&rollback.state)?;

            let guard_state = std::mem::take(&mut rollback.state);
            rollback.committed = true;
            drop(rollback);

            info!(
                iface = %guard_state.iface_name,
                physical_nic = %phys_iface,
                mtu,
                if_index_v4,
                ?if_index_v6,
                routes = guard_state.routes.len(),
                tun_ipv6,
                ipv6_active,
                "macOS desktop utun session active"
            );

            Ok((
                Self {
                    binder,
                    physical_nic: phys_iface,
                    mtu,
                    guard_state,
                    guard_child: Some(guard_child),
                    dns_session: Some(dns_session),
                    managed_ifscope_v4,
                    managed_ifscope_v6,
                    route_tx,
                    route_monitor: Some(route_monitor),
                },
                tun_fd,
            ))
        }

        /// Returns the kernel-assigned `utun` interface name (e.g. `"utun4"`).
        pub fn iface_name(&self) -> &str {
            &self.guard_state.iface_name
        }

        /// Returns the detected physical uplink interface name (e.g. `"en0"`).
        pub fn physical_nic_name(&self) -> &str {
            &self.physical_nic
        }

        /// Returns the active MTU configured on the `utun` interface (e.g. `16384`, `9000`, or `1500`).
        pub fn mtu(&self) -> u16 {
            self.mtu
        }

        /// Returns a live watch receiver signaled immediately on macOS `PF_ROUTE` changes.
        pub fn route_change_rx(&self) -> watch::Receiver<u64> {
            self.route_tx.subscribe()
        }
    }

    impl Drop for MacosTunSession {
        fn drop(&mut self) {
            // Stop the PF_ROUTE monitor before tearing down routes so our own route
            // deletions do not trigger spurious notifications or uplink rebind probes.
            drop(self.route_monitor.take());

            // Remove session-scoped SCDynamicStore DNS keys and flush mDNSResponder first so
            // macOS immediately stops targeting `198.18.0.2`.
            drop(self.dns_session.take());

            // Clean up any dynamically swapped `-ifscope` default route added by `RouteMonitor`.
            if let Some(route) = self
                .managed_ifscope_v4
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                delete_managed_route(&route);
            }
            if let Some(route) = self
                .managed_ifscope_v6
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                delete_managed_route(&route);
            }

            let mut restored_by_guard = false;
            if let Some(mut child) = self.guard_child.take() {
                // Closing the stdin pipe delivers EOF to the detached crash guard, which
                // immediately removes managed routes and flushes mDNSResponder.
                drop(child.stdin.take());
                match child.wait() {
                    Ok(status) if status.success() => {
                        restored_by_guard = true;
                    }
                    result => {
                        warn!(
                            ?result,
                            "macOS TUN crash guard did not exit cleanly; performing direct rollback"
                        );
                    }
                }
            }
            if !restored_by_guard {
                restore_macos_tun_state(&self.guard_state);
            }
            self.binder.update(OutboundTarget::default());
            debug!(iface = %self.guard_state.iface_name, "macOS TUN session stopped and cleaned up");
        }
    }

    /// Entry point invoked by `vdpi --internal-macos-tun-guard`.
    ///
    /// Ignores `SIGTERM`, `SIGINT`, and `SIGHUP`, reads the JSON [`MacosTunGuardState`] line
    /// from stdin, acknowledges readiness on stdout, blocks until stdin EOF (normal Drop or
    /// parent `SIGKILL`), and immediately restores all managed routes, DNS servers, and
    /// macOS DNS caches.
    pub fn run_macos_tun_cleanup_guard() -> Result<()> {
        // Ignore termination/hangup signals before signaling readiness so the guard always
        // survives long enough to observe parent EOF and complete route/DNS rollback.
        // SAFETY: `SIG_IGN` is a valid signal disposition for `SIGTERM`, `SIGINT`, and `SIGHUP`.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }

        let mut input = io::stdin().lock();
        let mut line = String::new();
        let n = input
            .read_line(&mut line)
            .context("failed to read macOS TUN guard state from stdin")?;
        if n == 0 || line.trim().is_empty() {
            return Ok(());
        }
        let state: MacosTunGuardState = serde_json::from_str(line.trim())
            .context("failed to parse macOS TUN guard state JSON")?;

        {
            let mut out = io::stdout().lock();
            writeln!(out, "{GUARD_READY}")?;
            out.flush()?;
        }

        // Block until the parent process drops the pipe or dies unexpectedly (SIGKILL).
        let mut drain = [0u8; 64];
        loop {
            match input.read(&mut drain) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }

        restore_macos_tun_state(&state);
        Ok(())
    }

    struct StartupRollback<'a> {
        binder: &'a DynamicOutboundBinder,
        state: MacosTunGuardState,
        state_persisted: bool,
        committed: bool,
    }

    impl Drop for StartupRollback<'_> {
        fn drop(&mut self) {
            if !self.committed {
                if self.state_persisted {
                    restore_macos_tun_state(&self.state);
                }
                self.binder.update(OutboundTarget::default());
            }
        }
    }

    fn save_macos_tun_state(state: &MacosTunGuardState) -> Result<()> {
        state
            .save_to_path(Path::new(MACOS_TUN_STATE_PATH))
            .with_context(|| format!("failed to persist macOS TUN state to {MACOS_TUN_STATE_PATH}"))
    }

    fn remove_macos_tun_state_file() {
        let path = Path::new(MACOS_TUN_STATE_PATH);
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => {
                warn!(
                    path = MACOS_TUN_STATE_PATH,
                    error = %e,
                    "failed to remove macOS TUN crash-recovery state file"
                );
            }
        }
    }

    fn recover_stale_macos_tun_state() {
        let path = Path::new(MACOS_TUN_STATE_PATH);
        match MacosTunGuardState::load_from_path(path) {
            Ok(Some(stale)) => {
                warn!(
                    iface = %stale.iface_name,
                    routes = stale.routes.len(),
                    dns_services = stale.dns_snapshots.len(),
                    path = MACOS_TUN_STATE_PATH,
                    "found stale macOS TUN crash-recovery state; restoring before startup"
                );
                restore_macos_tun_state(&stale);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(
                    path = MACOS_TUN_STATE_PATH,
                    error = %e,
                    "failed to load stale macOS TUN state file; removing corrupt file"
                );
                remove_macos_tun_state_file();
            }
        }
    }

    fn open_pf_route_socket() -> Result<OwnedFd> {
        // SAFETY: Standard BSD/Darwin routing socket creation for all address families.
        let raw_fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error())
                .context("socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC) failed");
        }
        // SAFETY: `raw_fd` is a newly created, exclusively owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        set_fd_cloexec(fd.as_raw_fd())?;
        set_nonblocking(fd.as_raw_fd())?;
        Ok(fd)
    }

    fn create_stop_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds: [libc::c_int; 2] = [-1, -1];
        // SAFETY: `fds` is a valid 2-element `c_int` array for `pipe(2)`.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error())
                .context("pipe() failed for macOS route watcher");
        }
        // SAFETY: `pipe(2)` succeeded and returned two newly created, exclusively owned fds.
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        set_fd_cloexec(read_fd.as_raw_fd())?;
        set_fd_cloexec(write_fd.as_raw_fd())?;
        set_nonblocking(read_fd.as_raw_fd())?;
        set_nonblocking(write_fd.as_raw_fd())?;
        Ok((read_fd, write_fd))
    }

    #[allow(clippy::too_many_arguments)]
    fn run_pf_route_monitor_loop(
        route_fd: OwnedFd,
        stop_read_fd: OwnedFd,
        stop_flag: Arc<AtomicBool>,
        binder: Arc<DynamicOutboundBinder>,
        route_tx: Arc<watch::Sender<u64>>,
        managed_ifscope_v4: Arc<Mutex<Option<ManagedRoute>>>,
        managed_ifscope_v6: Arc<Mutex<Option<ManagedRoute>>>,
        ipv6_active: bool,
    ) {
        let mut pending_rebind: Option<(Instant, Instant)> = None;
        let mut buf = [0u8; 4096];

        loop {
            if stop_flag.load(Ordering::Acquire) {
                break;
            }

            let timeout_ms: libc::c_int = match pending_rebind {
                None => -1,
                Some((burst_start, deadline)) => {
                    let effective = deadline.min(burst_start + ROUTE_DEBOUNCE_MAX_WAIT);
                    let rem = effective.saturating_duration_since(Instant::now());
                    libc::c_int::try_from(rem.as_millis()).unwrap_or(libc::c_int::MAX)
                }
            };

            let mut pfds = [
                libc::pollfd {
                    fd: route_fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: stop_read_fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            // SAFETY: `pfds` points to two valid `pollfd` entries with open file descriptors.
            let rc =
                unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout_ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                warn!(error = %err, "PF_ROUTE poll() failed; stopping macOS route watcher");
                break;
            }

            if stop_flag.load(Ordering::Acquire) || (pfds[1].revents & libc::POLLIN) != 0 {
                break;
            }

            if (pfds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                warn!(
                    revents = pfds[0].revents,
                    "PF_ROUTE socket closed or errored; stopping macOS route watcher"
                );
                break;
            }

            if (pfds[0].revents & libc::POLLIN) != 0 {
                let mut relevant_seen = false;
                loop {
                    // SAFETY: `route_fd` is valid and `buf` is writable for `buf.len()` bytes.
                    let n = unsafe {
                        libc::read(
                            route_fd.as_raw_fd(),
                            buf.as_mut_ptr().cast::<c_void>(),
                            buf.len(),
                        )
                    };
                    if n < 0 {
                        let err = io::Error::last_os_error();
                        match err.kind() {
                            io::ErrorKind::Interrupted => continue,
                            io::ErrorKind::WouldBlock => break,
                            _ => {
                                warn!(
                                    error = %err,
                                    "PF_ROUTE read() failed; stopping macOS route watcher"
                                );
                                return;
                            }
                        }
                    }
                    if n == 0 {
                        break;
                    }
                    if is_relevant_pf_route_msg(&buf[..n as usize]) {
                        relevant_seen = true;
                    }
                }

                if relevant_seen {
                    // Notify route-change watchers (e.g. VpnGuard) immediately.
                    route_tx.send_modify(|epoch| *epoch = epoch.saturating_add(1));

                    let now = Instant::now();
                    let next_deadline = now + ROUTE_DEBOUNCE_WINDOW;
                    pending_rebind = Some(match pending_rebind {
                        Some((burst_start, _)) => (burst_start, next_deadline),
                        None => (now, next_deadline),
                    });
                }
            }

            if let Some((burst_start, deadline)) = pending_rebind {
                let now = Instant::now();
                if now >= deadline
                    || now.saturating_duration_since(burst_start) >= ROUTE_DEBOUNCE_MAX_WAIT
                {
                    pending_rebind = None;
                    rebind_physical_uplink(
                        &binder,
                        &managed_ifscope_v4,
                        &managed_ifscope_v6,
                        ipv6_active,
                    );
                }
            }
        }
    }

    fn sync_managed_ifscope_route(
        slot: &Mutex<Option<ManagedRoute>>,
        is_ipv6: bool,
        new_iface: &str,
        new_gw: Option<&str>,
    ) {
        let mut guard = slot.lock().unwrap_or_else(|e| e.into_inner());
        let desired = new_gw.map(|gw| ManagedRoute {
            destination: "default".to_string(),
            is_ipv6,
            interface: None,
            gateway: Some(gw.to_string()),
            ifscope: Some(new_iface.to_string()),
        });

        if *guard == desired {
            return;
        }

        if let Some(old) = guard.take() {
            delete_managed_route(&old);
        }

        if let Some(route) = desired {
            match add_managed_route(&route, true) {
                Ok(true) => {
                    *guard = Some(route);
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(
                        iface = %new_iface,
                        gateway = ?new_gw,
                        is_ipv6,
                        error = %e,
                        "failed to install -ifscope default route on new macOS uplink"
                    );
                }
            }
        }
    }

    fn rebind_physical_uplink(
        binder: &DynamicOutboundBinder,
        managed_ifscope_v4: &Mutex<Option<ManagedRoute>>,
        managed_ifscope_v6: &Mutex<Option<ManagedRoute>>,
        ipv6_active: bool,
    ) {
        let (phys_iface, phys_gw) = match detect_physical_default_v4() {
            Ok(found) => found,
            Err(e) => {
                debug!(
                    error = %e,
                    "failed to re-detect physical default IPv4 uplink after macOS route change"
                );
                return;
            }
        };

        let if_index_v4 = match if_name_to_index(&phys_iface) {
            Ok(idx) => idx,
            Err(e) => {
                warn!(
                    iface = %phys_iface,
                    error = %e,
                    "failed to resolve interface index for detected macOS uplink"
                );
                return;
            }
        };

        let phys_v6 = detect_physical_default_v6();
        let if_index_v6 = phys_v6
            .as_ref()
            .and_then(|(iface6, _)| if_name_to_index(iface6).ok());

        let next = OutboundTarget {
            nic_name: Some(phys_iface.clone()),
            if_index_v4: Some(if_index_v4),
            if_index_v6,
            fwmark: None,
            fail_closed: true,
        };

        let target_changed = binder.snapshot() != next;
        let v4_gw_changed = {
            let guard = managed_ifscope_v4.lock().unwrap_or_else(|e| e.into_inner());
            guard.as_ref().is_some_and(|old| {
                old.ifscope.as_deref() != Some(phys_iface.as_str())
                    || old.gateway.as_deref() != phys_gw.as_deref()
            })
        };
        let v6_gw_changed = ipv6_active && {
            let guard = managed_ifscope_v6.lock().unwrap_or_else(|e| e.into_inner());
            let desired_iface = phys_v6.as_ref().map(|(iface, _)| iface.as_str());
            let desired_gw = phys_v6.as_ref().and_then(|(_, gw)| gw.as_deref());
            guard.as_ref().is_some_and(|old| {
                old.ifscope.as_deref() != desired_iface || old.gateway.as_deref() != desired_gw
            })
        };

        if target_changed || v4_gw_changed || v6_gw_changed {
            sync_managed_ifscope_route(managed_ifscope_v4, false, &phys_iface, phys_gw.as_deref());
            if ipv6_active {
                if let Some((ref iface6, ref gw6)) = phys_v6 {
                    sync_managed_ifscope_route(managed_ifscope_v6, true, iface6, gw6.as_deref());
                } else if let Some(old6) = managed_ifscope_v6
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                {
                    delete_managed_route(&old6);
                }
            }
        }

        if target_changed {
            info!(
                nic = ?next.nic_name,
                if_index_v4 = ?next.if_index_v4,
                if_index_v6 = ?next.if_index_v6,
                "macOS physical uplink changed; updated outbound binder"
            );
            binder.update(next);
        } else {
            debug!(
                nic = ?next.nic_name,
                "macOS route change observed; physical uplink unchanged"
            );
        }
    }

    fn set_fd_cloexec(fd: libc::c_int) -> Result<()> {
        // SAFETY: `fd` is a valid open file descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error()).context("fcntl(F_GETFD) failed");
        }
        // SAFETY: `fd` is a valid open file descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error()).context("fcntl(F_SETFD, FD_CLOEXEC) failed");
        }
        Ok(())
    }

    fn set_nonblocking(fd: libc::c_int) -> Result<()> {
        // SAFETY: `fd` is a valid open file descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error()).context("fcntl(F_GETFL) failed");
        }
        // SAFETY: `fd` is a valid open file descriptor.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error()).context("fcntl(F_SETFL, O_NONBLOCK) failed");
        }
        Ok(())
    }

    fn if_name_to_index(iface: &str) -> Result<u32> {
        let c_name =
            CString::new(iface).with_context(|| format!("invalid interface name {iface:?}"))?;
        // SAFETY: `c_name` is a valid NUL-terminated C string.
        let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if idx == 0 {
            bail!("if_nametoindex({iface:?}) returned 0 (interface does not exist)");
        }
        Ok(idx)
    }

    fn detect_physical_default_v4() -> Result<(String, Option<String>)> {
        let out = Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .context("failed to execute /sbin/route -n get default")?;
        if !out.status.success() {
            bail!(
                "/sbin/route -n get default exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        parse_route_get_default(&stdout).context(
            "no physical default IPv4 interface found (disconnect any active VPN holding the default route)",
        )
    }

    fn detect_physical_default_v6() -> Option<(String, Option<String>)> {
        let out = Command::new("/sbin/route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        parse_route_get_default(&stdout)
    }

    fn configure_utun_interface(iface_name: &str, tun_ipv6: bool) -> Result<(u16, bool)> {
        let preferred_mtu = u16::try_from(vdpi_tun::config::DESKTOP_MTU).unwrap_or(MACOS_TUN_MTU);
        let mut mtu_candidates: Vec<u16> = Vec::with_capacity(3);
        for candidate in [preferred_mtu, 9000, MACOS_TUN_MTU] {
            if !mtu_candidates.contains(&candidate) {
                mtu_candidates.push(candidate);
            }
        }

        let mut configured_mtu: Option<u16> = None;
        let mut last_err: Option<anyhow::Error> = None;
        for candidate in mtu_candidates {
            let mtu_str = candidate.to_string();
            match run_cmd(
                "/sbin/ifconfig",
                &[
                    iface_name,
                    "inet",
                    MACOS_TUN_IPV4,
                    MACOS_TUN_DNS_V4,
                    "netmask",
                    MACOS_TUN_NETMASK_V4,
                    "mtu",
                    &mtu_str,
                    "up",
                ],
            ) {
                Ok(()) => {
                    configured_mtu = Some(candidate);
                    break;
                }
                Err(e) => {
                    warn!(
                        iface = %iface_name,
                        mtu = candidate,
                        error = %e,
                        "ifconfig rejected utun MTU; trying lower fallback"
                    );
                    last_err = Some(e);
                }
            }
        }

        let mtu = match configured_mtu {
            Some(m) => m,
            None => {
                return Err(last_err
                    .unwrap_or_else(|| anyhow::anyhow!("no candidate MTU succeeded"))
                    .context(format!("failed to configure IPv4 on {iface_name}")));
            }
        };

        if !tun_ipv6 {
            return Ok((mtu, false));
        }
        match run_cmd(
            "/sbin/ifconfig",
            &[iface_name, "inet6", MACOS_TUN_IPV6, "prefixlen", "64", "up"],
        ) {
            Ok(()) => Ok((mtu, true)),
            Err(e) => {
                warn!(
                    iface = %iface_name,
                    error = %e,
                    "failed to configure IPv6 on utun interface; skipping IPv6 route"
                );
                Ok((mtu, false))
            }
        }
    }

    fn managed_route_args<'a>(action: &'a str, route: &'a ManagedRoute) -> Option<Vec<&'a str>> {
        let family = if route.is_ipv6 { "-inet6" } else { "-inet" };
        let mut args: Vec<&'a str> = Vec::with_capacity(10);
        args.push("-n");
        args.push(action);
        args.push(family);
        if route.destination == "default" {
            args.push("default");
        } else {
            args.push("-net");
            args.push(&route.destination);
        }

        if let Some(ref gw) = route.gateway {
            args.push(gw);
        } else {
            let iface = route.interface.as_deref()?;
            args.push("-interface");
            args.push(iface);
        }

        if let Some(ref scope) = route.ifscope {
            args.push("-ifscope");
            args.push(scope);
        }

        Some(args)
    }

    fn add_managed_route(route: &ManagedRoute, allow_existing: bool) -> Result<bool> {
        let Some(args) = managed_route_args("add", route) else {
            bail!(
                "managed route {} specifies neither gateway nor interface",
                route.destination
            );
        };

        let out = Command::new("/sbin/route")
            .args(&args)
            .output()
            .with_context(|| format!("failed to execute /sbin/route {args:?}"))?;

        // On macOS, `/sbin/route -n add` can exit 0 even when printing "File exists" or
        // "writing to routing socket:". Inspect stdout/stderr BEFORE trusting exit status!
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let has_file_exists = stderr.contains("File exists") || stdout.contains("File exists");
        let has_routing_socket_err = stderr.contains("writing to routing socket:")
            || stdout.contains("writing to routing socket:");

        if has_file_exists {
            if allow_existing {
                debug!(
                    destination = %route.destination,
                    "route already exists in macOS table; skipping so existing route is preserved"
                );
                return Ok(false);
            }
            bail!(
                "/sbin/route {:?} failed (File exists, status {}): {} {}",
                args,
                out.status,
                stdout.trim(),
                stderr.trim()
            );
        }

        if !out.status.success() || has_routing_socket_err {
            bail!(
                "/sbin/route {:?} exited {}: {} {}",
                args,
                out.status,
                stdout.trim(),
                stderr.trim()
            );
        }

        Ok(true)
    }

    fn delete_managed_route(route: &ManagedRoute) {
        let Some(args) = managed_route_args("delete", route) else {
            debug!(
                destination = %route.destination,
                "skipping managed route delete without explicit gateway or interface"
            );
            return;
        };

        let _ = Command::new("/sbin/route").args(args).output();
    }

    fn get_service_dns_servers(service: &str) -> Result<Vec<String>> {
        let out = Command::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", service])
            .output()
            .with_context(|| {
                format!("failed to execute /usr/sbin/networksetup -getdnsservers {service:?}")
            })?;
        if !out.status.success() {
            bail!(
                "/usr/sbin/networksetup -getdnsservers {:?} exited {}: {}",
                service,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(parse_dns_servers_output(&String::from_utf8_lossy(
            &out.stdout,
        )))
    }

    /// One-time migration cleanup for upgrades from v0.5.0/v0.5.1: if any physical macOS network
    /// service still has persistent `networksetup` DNS stuck on `[198.18.0.2]`, reset it to
    /// `Empty` (DHCP) so Wi-Fi/Ethernet DNS heals automatically.
    fn heal_legacy_networksetup_dns() {
        let services = match list_configurable_network_services() {
            Ok(svcs) => svcs,
            Err(e) => {
                debug!(
                    error = %e,
                    "failed to list macOS network services for legacy v0.5.x DNS migration check"
                );
                return;
            }
        };

        let mut healed = false;
        for service in services {
            let current = match get_service_dns_servers(&service) {
                Ok(servers) => servers,
                Err(e) => {
                    debug!(
                        service = %service,
                        error = %e,
                        "failed to inspect macOS network service DNS during migration check"
                    );
                    continue;
                }
            };

            if is_vdpi_owned_dns_servers(&current) {
                warn!(
                    service = %service,
                    "found leftover v0.5.x networksetup DNS (198.18.0.2); resetting service to Empty (DHCP)"
                );
                match run_cmd(
                    "/usr/sbin/networksetup",
                    &["-setdnsservers", &service, "Empty"],
                ) {
                    Ok(()) => {
                        healed = true;
                    }
                    Err(e) => {
                        warn!(
                            service = %service,
                            error = %e,
                            "failed to reset legacy v0.5.x networksetup DNS to Empty"
                        );
                    }
                }
            }
        }

        if healed {
            flush_macos_dns_cache();
        }
    }

    fn restore_macos_tun_state(state: &MacosTunGuardState) {
        for route in state.routes.iter().rev() {
            delete_managed_route(route);
        }

        let mut clean_restore = true;
        for snap in &state.dns_snapshots {
            let current = match get_service_dns_servers(&snap.service) {
                Ok(servers) => servers,
                Err(e) => {
                    warn!(
                        service = %snap.service,
                        error = %e,
                        "failed to query current macOS DNS servers during restore; skipping service"
                    );
                    continue;
                }
            };

            if !is_vdpi_owned_dns_servers(&current) {
                debug!(
                    service = %snap.service,
                    current = ?current,
                    "macOS DNS servers changed externally (VPN or user); skipping DNS restore"
                );
                continue;
            }

            let res = if snap.original_servers.is_empty() {
                run_cmd(
                    "/usr/sbin/networksetup",
                    &["-setdnsservers", &snap.service, "Empty"],
                )
            } else {
                let mut args: Vec<&str> = Vec::with_capacity(2 + snap.original_servers.len());
                args.push("-setdnsservers");
                args.push(&snap.service);
                for srv in &snap.original_servers {
                    args.push(srv.as_str());
                }
                run_cmd("/usr/sbin/networksetup", &args)
            };

            if let Err(e) = res {
                warn!(
                    service = %snap.service,
                    error = %e,
                    "failed to restore original macOS DNS servers"
                );
                clean_restore = false;
            }
        }

        flush_macos_dns_cache();
        if clean_restore {
            remove_macos_tun_state_file();
        }
    }

    fn flush_macos_dns_cache() {
        let _ = Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .output();
        let _ = Command::new("/usr/bin/killall")
            .args(["-HUP", "mDNSResponder"])
            .output();
    }

    fn spawn_detached_guard(state: &MacosTunGuardState) -> Result<Child> {
        let payload = build_macos_tun_cleanup_payload(state)?;
        let exe = std::env::current_exe().context("failed to locate current vdpi executable")?;

        let mut cmd = Command::new(exe);
        cmd.arg(MACOS_TUN_GUARD_ARG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        // Detach into a new session so terminal SIGHUP/SIGINT only reaches the parent process
        // and the guard survives to restore routes + DNS if the parent is killed abruptly.
        // SAFETY: `setsid()` is async-signal-safe and permitted in `pre_exec`.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .context("failed to spawn detached macOS TUN crash guard")?;

        let init_res: Result<()> = (|| {
            {
                let stdin = child
                    .stdin
                    .as_mut()
                    .context("macOS TUN crash guard stdin was not piped")?;
                stdin
                    .write_all(payload.as_bytes())
                    .context("failed to send cleanup payload to macOS TUN crash guard")?;
                stdin
                    .flush()
                    .context("failed to flush cleanup payload to macOS TUN crash guard")?;
            }

            let stdout = child
                .stdout
                .take()
                .context("macOS TUN crash guard stdout was not piped")?;
            let mut ready_line = String::new();
            BufReader::new(stdout)
                .read_line(&mut ready_line)
                .context("failed to read readiness line from macOS TUN crash guard")?;
            if ready_line.trim() != GUARD_READY {
                bail!(
                    "macOS TUN crash guard failed to initialize: {:?}",
                    ready_line.trim()
                );
            }
            Ok(())
        })();

        if let Err(err) = init_res {
            drop(child.stdin.take());
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }

        Ok(child)
    }

    fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
        let out = Command::new(program)
            .args(args)
            .output()
            .with_context(|| format!("failed to execute {program} {args:?}"))?;
        if !out.status.success() {
            bail!(
                "{program} {:?} exited {}: {}",
                args,
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub use imp::{open_utun, run_macos_tun_cleanup_guard, MacosTunSession};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_virtual_and_physical_macos_interfaces() {
        for virtual_if in [
            "utun0", "utun12", "UTUN3", "tun0", "tap0", "wg0", "ap0", "ap1", "lo0", "awdl0",
            "llw0", "ipsec0", "ppp0", "gif0", "stf0", "bridge0", "feth0", "vmenet0", "anpi0",
            "pktap0", "", "   ",
        ] {
            assert!(
                is_virtual_macos_interface(virtual_if),
                "expected {virtual_if:?} to be classified as virtual"
            );
        }

        for physical_if in ["en0", "en1", "en7", "pdp_ip0"] {
            assert!(
                !is_virtual_macos_interface(physical_if),
                "expected {physical_if:?} to be classified as physical"
            );
        }
    }

    #[test]
    fn parses_physical_route_get_default_output() {
        let sample = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
";
        assert_eq!(
            parse_route_get_default(sample),
            Some(("en0".to_string(), Some("192.168.1.1".to_string())))
        );

        let ipv6_sample = "\
   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
";
        assert_eq!(
            parse_route_get_default(ipv6_sample),
            Some(("en0".to_string(), Some("fe80::1%en0".to_string())))
        );

        let link_gateway_sample = "\
   route to: default
destination: default
    gateway: link#6
  interface: en5
";
        assert_eq!(
            parse_route_get_default(link_gateway_sample),
            Some(("en5".to_string(), None))
        );

        let no_gateway_sample = "\
   route to: default
  interface: en1
";
        assert_eq!(
            parse_route_get_default(no_gateway_sample),
            Some(("en1".to_string(), None))
        );
    }

    #[test]
    fn rejects_virtual_interfaces_bad_flags_and_missing_routes_in_route_get_default() {
        for iface in [
            "utun3", "tun0", "tap0", "wg0", "ap1", "lo0", "awdl0", "ipsec0", "ppp0",
        ] {
            let sample = format!(
                "   route to: default\ndestination: default\n    gateway: 10.0.0.1\n  interface: {iface}\n      flags: <UP,GATEWAY,DONE>\n"
            );
            assert_eq!(
                parse_route_get_default(&sample),
                None,
                "virtual interface {iface} should be rejected"
            );
        }

        let down_route = "\
   route to: default
destination: default
    gateway: 192.168.1.1
  interface: en0
      flags: <GATEWAY,DONE,STATIC>
";
        assert_eq!(parse_route_get_default(down_route), None);

        let blackhole_route = "\
   route to: default
destination: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,BLACKHOLE,STATIC>
";
        assert_eq!(parse_route_get_default(blackhole_route), None);

        let reject_route = "\
   route to: default
destination: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,REJECT,STATIC>
";
        assert_eq!(parse_route_get_default(reject_route), None);

        assert_eq!(
            parse_route_get_default("route: writing to routing socket: not in table\n"),
            None
        );
        assert_eq!(parse_route_get_default(""), None);
    }

    #[test]
    fn parses_networksetup_dns_servers_output() {
        assert!(
            parse_dns_servers_output("There aren't any DNS Servers set on Wi-Fi.\n").is_empty()
        );
        assert_eq!(
            parse_dns_servers_output(
                "1.1.1.1\n 8.8.8.8 \n2606:4700:4700::1111\n** Error: invalid\n\n"
            ),
            vec![
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
                "2606:4700:4700::1111".to_string()
            ]
        );
    }

    #[test]
    fn sanitizes_original_dns_and_checks_vdpi_ownership() {
        assert!(sanitize_original_dns_servers(vec![MACOS_TUN_DNS_V4.to_string()]).is_empty());
        assert_eq!(
            sanitize_original_dns_servers(vec![
                MACOS_TUN_DNS_V4.to_string(),
                "1.1.1.1".to_string()
            ]),
            vec!["1.1.1.1".to_string()]
        );
        assert_eq!(
            sanitize_original_dns_servers(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]),
            vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
        );

        assert!(is_vdpi_owned_dns_servers(&[MACOS_TUN_DNS_V4.to_string()]));
        assert!(!is_vdpi_owned_dns_servers(&[]));
        assert!(!is_vdpi_owned_dns_servers(&["1.1.1.1".to_string()]));
        assert!(!is_vdpi_owned_dns_servers(&[
            MACOS_TUN_DNS_V4.to_string(),
            "1.1.1.1".to_string()
        ]));
    }

    #[test]
    fn classifies_pf_route_messages() {
        assert!(is_relevant_pf_route_msg(&[16, 0, 5, 0x01])); // RTM_ADD
        assert!(is_relevant_pf_route_msg(&[16, 0, 5, 0x02])); // RTM_DELETE
        assert!(is_relevant_pf_route_msg(&[16, 0, 5, 0x03])); // RTM_CHANGE
        assert!(is_relevant_pf_route_msg(&[16, 0, 5, 0x0c])); // RTM_NEWADDR
        assert!(is_relevant_pf_route_msg(&[16, 0, 5, 0x12])); // RTM_IFINFO2
        assert!(!is_relevant_pf_route_msg(&[16, 0, 5, 0x04])); // RTM_GET
        assert!(!is_relevant_pf_route_msg(&[16, 0, 5, 0x07])); // RTM_MISS
        assert!(!is_relevant_pf_route_msg(&[16, 0, 4, 0x01])); // wrong version
        assert!(!is_relevant_pf_route_msg(&[16, 0, 5])); // too short
    }

    #[test]
    fn rejects_link_layer_and_non_ip_gateways_in_route_get_default() {
        let link14_sample = "\
   route to: default
destination: default
       mask: default
    gateway: link#14
  interface: en0
      flags: <UP,CLONING,UCS,STATIC,GLOBAL>
";
        assert_eq!(
            parse_route_get_default(link14_sample),
            Some(("en0".to_string(), None))
        );

        let upper_link_sample = "\
   route to: default
destination: default
    gateway: LINK#14
  interface: en0
      flags: <UP,STATIC>
";
        assert_eq!(
            parse_route_get_default(upper_link_sample),
            Some(("en0".to_string(), None))
        );

        let mac_gateway_sample = "\
   route to: default
destination: default
    gateway: aa:bb:cc:dd:ee:ff
  interface: en0
      flags: <UP,STATIC>
";
        assert_eq!(
            parse_route_get_default(mac_gateway_sample),
            Some(("en0".to_string(), None))
        );
    }

    #[test]
    fn managed_route_ifscope_serde_defaults_and_roundtrips() {
        let legacy_json = r#"{"destination":"10.0.0.0/8","is_ipv6":false,"interface":null,"gateway":"192.168.1.1"}"#;
        let decoded: ManagedRoute = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(
            decoded,
            ManagedRoute {
                destination: "10.0.0.0/8".to_string(),
                is_ipv6: false,
                interface: None,
                gateway: Some("192.168.1.1".to_string()),
                ifscope: None,
            }
        );

        let scoped = ManagedRoute {
            destination: "default".to_string(),
            is_ipv6: false,
            interface: None,
            gateway: Some("192.168.1.1".to_string()),
            ifscope: Some("en0".to_string()),
        };
        let encoded = serde_json::to_string(&scoped).unwrap();
        let roundtripped: ManagedRoute = serde_json::from_str(&encoded).unwrap();
        assert_eq!(roundtripped, scoped);
    }

    #[test]
    fn macos_tun_guard_state_serde_and_atomic_file_roundtrip() {
        let state = MacosTunGuardState {
            iface_name: "utun4".to_string(),
            routes: vec![
                ManagedRoute {
                    destination: "default".to_string(),
                    is_ipv6: false,
                    interface: None,
                    gateway: Some("192.168.1.1".to_string()),
                    ifscope: Some("en0".to_string()),
                },
                ManagedRoute {
                    destination: "10.0.0.0/8".to_string(),
                    is_ipv6: false,
                    interface: None,
                    gateway: Some("192.168.1.1".to_string()),
                    ifscope: None,
                },
                ManagedRoute {
                    destination: "169.254.0.0/16".to_string(),
                    is_ipv6: false,
                    interface: Some("en0".to_string()),
                    gateway: None,
                    ifscope: None,
                },
                ManagedRoute {
                    destination: "240.0.0.0/4".to_string(),
                    is_ipv6: false,
                    interface: Some("en0".to_string()),
                    gateway: None,
                    ifscope: None,
                },
                ManagedRoute {
                    destination: "1.0.0.0/8".to_string(),
                    is_ipv6: false,
                    interface: Some("utun4".to_string()),
                    gateway: None,
                    ifscope: None,
                },
                ManagedRoute {
                    destination: "128.0.0.0/1".to_string(),
                    is_ipv6: false,
                    interface: Some("utun4".to_string()),
                    gateway: None,
                    ifscope: None,
                },
                ManagedRoute {
                    destination: "2000::/3".to_string(),
                    is_ipv6: true,
                    interface: Some("utun4".to_string()),
                    gateway: None,
                    ifscope: None,
                },
            ],
            dns_snapshots: vec![
                DnsServiceSnapshot {
                    service: "Wi-Fi".to_string(),
                    original_servers: Vec::new(),
                },
                DnsServiceSnapshot {
                    service: "USB 10/100/1000 LAN".to_string(),
                    original_servers: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
                },
            ],
        };

        let payload = build_macos_tun_cleanup_payload(&state).unwrap();
        assert!(payload.ends_with('\n'));
        assert_eq!(
            payload.matches('\n').count(),
            1,
            "guard stdin payload must be a single newline-delimited JSON line"
        );

        let decoded: MacosTunGuardState = serde_json::from_str(payload.trim()).unwrap();
        assert_eq!(decoded, state);

        let tmp_path = std::env::temp_dir().join(format!(
            "vdpi-macos-tun-state-test-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&tmp_path);
        assert_eq!(MacosTunGuardState::load_from_path(&tmp_path).unwrap(), None);

        state.save_to_path(&tmp_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&tmp_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, MACOS_TUN_STATE_MODE);
        }
        let loaded = MacosTunGuardState::load_from_path(&tmp_path).unwrap();
        assert_eq!(loaded, Some(state));
        let _ = fs::remove_file(&tmp_path);
    }
}
