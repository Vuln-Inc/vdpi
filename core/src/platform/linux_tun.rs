//! Linux desktop `/dev/net/tun` + `SO_MARK` policy routing backend.
//!
//! Pure constants, state persistence, policy rule specifications, and `/etc/resolv.conf`
//! marker-guarded helpers are compiled cross-OS so they remain unit-testable on Windows,
//! macOS, and Linux. Kernel TUN creation, `iproute2` orchestration, and 3-backend DNS
//! management are gated to `#[cfg(target_os = "linux")]`.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default Linux TUN network interface name.
pub const LINUX_TUN_IFACE: &str = "vdpi0";
/// IPv4 address/prefix assigned to the virtual TUN interface (RFC 2544 benchmark space).
pub const LINUX_TUN_IPV4_CIDR: &str = "198.18.0.1/30";
/// Virtual IPv4 DNS server routed into `vdpi0` for DoH interception.
pub const LINUX_TUN_DNS_V4: &str = "198.18.0.2";
/// IPv6 ULA address/prefix assigned to `vdpi0` when `tun_ipv6` is enabled.
pub const LINUX_TUN_IPV6_CIDR: &str = "fd00:7664:7069::1/126";
/// Virtual IPv6 DNS server routed into `vdpi0` when `tun_ipv6` is enabled.
pub const LINUX_TUN_DNS_V6: &str = "fd00:7664:7069::2";
/// Default MTU configured on `vdpi0` (matches `vdpi_tun::config::DESKTOP_MTU`; Linux
/// `/dev/net/tun` supports up to 65,535 bytes).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub const LINUX_TUN_MTU: u16 = vdpi_tun::config::DESKTOP_MTU as u16;
/// Default MTU configured on `vdpi0`.
#[cfg(any(target_os = "android", target_os = "ios"))]
pub const LINUX_TUN_MTU: u16 = 16_384;
/// Default transmit queue length configured on `vdpi0`.
pub const LINUX_TUN_TXQUEUELEN: u32 = 4096;
/// Descending `txqueuelen` fallback ladder tried when bringing up `vdpi0`, keeping Gigabit
/// burst headroom (4096 -> 2000 -> 1000) instead of dropping straight to the 500-packet default.
pub const LINUX_TUN_TXQUEUELEN_LADDER: [u32; 3] = [LINUX_TUN_TXQUEUELEN, 2000, 1000];
/// Linux `SO_MARK` fwmark (`"VD"`) applied to `vdpi`'s own outbound sockets.
pub const VDPI_SO_MARK: u32 = 0x5644;
/// Bitmask applied to `fwmark` policy rules so upper mark bits (e.g. Tailscale/WireGuard)
/// are preserved without interference.
pub const VDPI_SO_MARK_MASK: u32 = 0xffff;
/// Dedicated `iproute2` routing table holding the default route via `vdpi0`.
pub const VDPI_ROUTE_TABLE: u32 = 202;

/// Policy rule priorities in `5480..=5500` sit cleanly BELOW Tailscale (`5210..=5270`)
/// so Tailscale mesh traffic and exit nodes never conflict with `vdpi`.
///
/// Routes `vdpi`'s own `SO_MARK`-tagged sockets through `main` (physical uplink).
pub const PRIO_VDPI_MARK: u32 = 5480;
/// Fail-closed guard for `SO_MARK`-tagged sockets when `main` has no route (e.g. uplink down),
/// preventing marked sockets from falling through to `PRIO_VDPI_TABLE` and looping into `vdpi0`.
///
/// Using a dedicated guard rule avoids combining `not` with `iif lo` in a single `ip rule`
/// (in Linux `fib_rule_match`, `FIB_RULE_INVERT` negates the entire selector conjunction,
/// so `iif lo not fwmark ...` would invert `iif lo` and hijack forwarded Docker traffic).
pub const PRIO_VDPI_MARK_GUARD: u32 = 5485;
/// Preserves all non-default routes in `main` (LAN, Docker bridges, link-local, split-tunnel `wg*`).
pub const PRIO_SUPPRESS_MAIN: u32 = 5490;
/// Sends locally originated (`iif lo`) default-route traffic to table `202` (`vdpi0`),
/// leaving forwarded Docker container and VM traffic untouched.
pub const PRIO_VDPI_TABLE: u32 = 5500;

/// All policy rule priorities managed by `vdpi` on Linux.
pub const VDPI_RULE_PRIORITIES: [u32; 4] = [
    PRIO_VDPI_MARK,
    PRIO_VDPI_MARK_GUARD,
    PRIO_SUPPRESS_MAIN,
    PRIO_VDPI_TABLE,
];

/// Header marker written to vdpi-managed `/etc/resolv.conf` and NetworkManager drop-in files.
pub const RESOLV_CONF_MARKER: &str = "# Managed by vdpi TUN mode";
/// Ephemeral runtime state directory (wiped automatically on reboot).
pub const LINUX_TUN_STATE_DIR: &str = "/run/vdpi";
/// Crash-recovery state file persisted while Linux TUN mode is active.
pub const LINUX_TUN_STATE_PATH: &str = "/run/vdpi/tun-state.json";
/// Exclusive single-instance lock file held for the lifetime of a live Linux TUN session.
pub const LINUX_TUN_LOCK_PATH: &str = "/run/vdpi/tun.lock";
/// Persistent state directory surviving reboot for `/etc/resolv.conf` recovery.
pub const LINUX_TUN_PERSIST_DIR: &str = "/var/lib/vdpi";
/// Ephemeral NetworkManager drop-in path used when NetworkManager manages DNS.
pub const NM_DNS_CONF_PATH: &str = "/run/NetworkManager/conf.d/99-vdpi-dns.conf";
/// System resolver configuration path used by the direct `/etc/resolv.conf` fallback backend.
pub const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
/// Name Service Switch configuration path checked for active `nss-resolve` (`systemd-resolved`).
pub const NSSWITCH_CONF_PATH: &str = "/etc/nsswitch.conf";
/// Persistent backup location for the original `/etc/resolv.conf` contents while TUN mode is active.
pub const RESOLV_CONF_BACKUP_PATH: &str = "/var/lib/vdpi/resolv.conf.orig";
/// Persistent metadata file storing original `/etc/resolv.conf` symlink target across reboots.
pub const RESOLV_CONF_META_PATH: &str = "/var/lib/vdpi/resolv-meta.json";
/// Legacy tmpfs backup path accepted during state-path validation for upgrades.
pub const LEGACY_RESOLV_CONF_BACKUP_PATH: &str = "/run/vdpi/resolv.conf.orig";
/// Sysctl path controlling global IPv4 reverse-path filtering (`max(all, dev)`).
pub const ALL_RP_FILTER_PATH: &str = "/proc/sys/net/ipv4/conf/all/rp_filter";
/// Fixed trusted system prefixes searched for privileged Linux networking binaries.
pub const TRUSTED_BIN_PREFIXES: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];
/// Internal CLI flag invoked by systemd `ExecStopPost=+/usr/local/bin/vdpi --internal-linux-tun-cleanup`.
pub const LINUX_TUN_CLEANUP_ARG: &str = "--internal-linux-tun-cleanup";
/// Linux `IFNAMSIZ` (15 ASCII bytes + NUL terminator).
pub const LINUX_IFNAMSIZ: usize = 16;
/// Linux `CAP_NET_ADMIN` capability bit index (`<linux/capability.h>`).
pub const CAP_NET_ADMIN_BIT: u32 = 12;
/// Bitmask for Linux `CAP_NET_ADMIN` (`1 << 12 = 0x1000`).
pub const CAP_NET_ADMIN_MASK: u64 = 1u64 << CAP_NET_ADMIN_BIT;
/// Error message returned when Linux TUN startup lacks root or `CAP_NET_ADMIN` privileges,
/// aligned with the CLI guidance in `main.rs`.
pub const LINUX_TUN_PRIVILEGE_ERROR: &str = "Linux TUN mode requires root privileges (euid=0) or CAP_NET_ADMIN; run with `sudo vdpi --tun start` or install the systemd system service (`sudo vdpi install --tun`)";

/// Active Linux DNS management backend chosen during TUN startup.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LinuxDnsBackend {
    SystemdResolved,
    NetworkManager,
    ResolvConf,
    #[default]
    None,
}

/// Persisted Linux TUN runtime state stored at [`LINUX_TUN_STATE_PATH`] (`/run/vdpi/tun-state.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinuxTunState {
    pub iface: String,
    pub route_table: u32,
    pub fwmark: u32,
    pub ipv6_enabled: bool,
    pub dns_backend: LinuxDnsBackend,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nm_conf_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolv_backup_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolv_symlink_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_all_rp_filter: Option<u8>,
    pub pid: u32,
}

/// Persistent metadata stored at [`RESOLV_CONF_META_PATH`] (`/var/lib/vdpi/resolv-meta.json`)
/// so symlink restoration of `/etc/resolv.conf` survives power loss and reboot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvBackupMeta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

impl ResolvBackupMeta {
    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json =
            serde_json::to_string_pretty(self).context("failed to serialize ResolvBackupMeta")?;
        write_file_atomic(path, &json, 0o644)
    }

    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        match fs::read_to_string(path) {
            Ok(raw) => Ok(Some(
                serde_json::from_str(&raw).context("failed to deserialize ResolvBackupMeta")?,
            )),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

impl LinuxTunState {
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("failed to serialize LinuxTunState")
    }

    pub fn from_json_str(raw: &str) -> Result<Self> {
        serde_json::from_str(raw).context("failed to deserialize LinuxTunState")
    }

    pub fn save_to_path(&self, path: &Path) -> Result<()> {
        let json = self.to_json_pretty()?;
        write_file_atomic(path, &json, 0o644)
    }

    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        match fs::read_to_string(path) {
            Ok(raw) => Ok(Some(Self::from_json_str(&raw)?)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

/// Declarative `ip rule add` specification generated for IPv4 (and optionally IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRuleSpec {
    pub priority: u32,
    pub ipv6: bool,
    pub args: Vec<String>,
}

/// Returns `true` when IPv4 default routing (`ip -4 route replace default ... table 202` and
/// `-4` policy rules) should be installed.
///
/// On a pure IPv6-only host (`!has_ipv4_uplink && include_ipv6`), IPv4 default routing is skipped
/// so Linux never captures unroutable IPv4 traffic into `vdpi0` (matching Windows and macOS).
/// When neither uplink is present yet (e.g. starting offline before DHCP completes), IPv4 routing
/// remains enabled so traffic is captured once an IPv4 uplink comes up.
pub fn should_install_ipv4_routing(has_ipv4_uplink: bool, include_ipv6: bool) -> bool {
    has_ipv4_uplink || !include_ipv6
}

/// Active physical uplink signature observed from Linux's `main` routing table and interface
/// address tables (excluding `vdpi0`, loopback, and container/VM virtual interfaces).
///
/// Includes gateway and sorted, deduplicated local unicast IPv4/IPv6 addresses so rapid
/// same-NIC Wi-Fi SSID roams on `wlan0` (even when switching between routers sharing a common
/// gateway like `192.168.1.1`) are detected and trigger DNS cache flush + `route_tx`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxUplinkSignature {
    pub has_v4: bool,
    pub v4_nic: Option<String>,
    pub v4_gateway: Option<String>,
    pub v4_local_addrs: Vec<Ipv4Addr>,
    pub has_v6: bool,
    pub v6_nic: Option<String>,
    pub v6_gateway: Option<String>,
    pub v6_local_addrs: Vec<Ipv6Addr>,
}

impl LinuxUplinkSignature {
    /// Builds an uplink signature from the detected IPv4 and IPv6 default-route interfaces
    /// without gateway or local unicast address metadata.
    pub fn from_nics(v4_nic: Option<String>, v6_nic: Option<String>) -> Self {
        Self::from_details(v4_nic, None, Vec::new(), v6_nic, None, Vec::new())
    }

    /// Builds a full uplink signature including gateway and normalized (sorted, deduplicated)
    /// local unicast IPv4/IPv6 addresses of the active physical uplink(s).
    pub fn from_details(
        v4_nic: Option<String>,
        v4_gateway: Option<String>,
        mut v4_local_addrs: Vec<Ipv4Addr>,
        v6_nic: Option<String>,
        v6_gateway: Option<String>,
        mut v6_local_addrs: Vec<Ipv6Addr>,
    ) -> Self {
        let has_v4 = v4_nic.is_some();
        let has_v6 = v6_nic.is_some();
        if has_v4 {
            v4_local_addrs.sort_unstable();
            v4_local_addrs.dedup();
        } else {
            v4_local_addrs.clear();
        }
        if has_v6 {
            v6_local_addrs.sort_unstable();
            v6_local_addrs.dedup();
        } else {
            v6_local_addrs.clear();
        }
        Self {
            has_v4,
            v4_nic,
            v4_gateway: if has_v4 { v4_gateway } else { None },
            v4_local_addrs,
            has_v6,
            v6_nic,
            v6_gateway: if has_v6 { v6_gateway } else { None },
            v6_local_addrs,
        }
    }

    /// Returns the preferred physical uplink interface name (IPv4 first, falling back to IPv6).
    pub fn preferred_nic(&self) -> Option<&str> {
        self.v4_nic.as_deref().or(self.v6_nic.as_deref())
    }

    /// Returns the signature as a `(has_v4, v4_nic, has_v6, v6_nic)` tuple.
    pub fn as_tuple(&self) -> (bool, Option<&str>, bool, Option<&str>) {
        (
            self.has_v4,
            self.v4_nic.as_deref(),
            self.has_v6,
            self.v6_nic.as_deref(),
        )
    }
}

/// Idle `poll(2)` interval for the Linux route watcher so sleep/wake clock jumps are detected
/// even if no netlink route event arrives immediately after resume.
pub const LINUX_ROUTE_IDLE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Minimum wall-vs-monotonic clock skew or excess monotonic jump treated as a Linux sleep/wake
/// cycle or significant clock jump requiring forced reconciliation (stale UDP NAT drain,
/// DNS cache flush, and `/etc/resolv.conf` re-assertion).
pub const LINUX_WAKE_TIME_JUMP_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(5);

/// Returns `true` when elapsed monotonic (`Instant`, `CLOCK_MONOTONIC` on Linux) and
/// wall-clock (`SystemTime`, `CLOCK_REALTIME`) deltas indicate a Linux suspend/resume cycle
/// or significant clock jump requiring forced reconciliation even when the active uplink
/// signature is unchanged.
///
/// On Linux, `CLOCK_MONOTONIC` pauses during suspend while `CLOCK_REALTIME` continues
/// advancing, producing a wall-vs-monotonic skew >= [`LINUX_WAKE_TIME_JUMP_THRESHOLD`].
/// Also catches backward wall-clock steps and monotonic elapsed time exceeding
/// `expected_max_wait + LINUX_WAKE_TIME_JUMP_THRESHOLD`.
pub fn detect_wake_or_time_jump(
    instant_elapsed: std::time::Duration,
    wall_delta: std::result::Result<std::time::Duration, std::time::Duration>,
    expected_max_wait: std::time::Duration,
) -> bool {
    if instant_elapsed >= expected_max_wait.saturating_add(LINUX_WAKE_TIME_JUMP_THRESHOLD) {
        return true;
    }
    match wall_delta {
        Ok(wall_forward) => {
            wall_forward.abs_diff(instant_elapsed) >= LINUX_WAKE_TIME_JUMP_THRESHOLD
        }
        Err(wall_backward) => wall_backward >= LINUX_WAKE_TIME_JUMP_THRESHOLD,
    }
}

/// Action to take for an address family (`-4` or `-6`) when reconciling a Linux uplink change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyRoutingAction {
    /// Keep the family's existing TUN routing and policy rules unchanged.
    Keep,
    /// Install table 202 default route and policy rules `5480..=5500` (plus `LINUX_TUN_IPV6_CIDR` for `-6`).
    Install,
    /// Remove policy rules `5480..=5500` and flush table 202 (plus remove `LINUX_TUN_IPV6_CIDR` for `-6`).
    Remove,
}

/// Planned reconciliation actions produced when comparing previous and current Linux uplink
/// signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UplinkTransitionPlan {
    /// `true` when the active uplink signature (NICs, gateways, or local unicast IPs) changed.
    pub signature_changed: bool,
    /// Desired IPv4 TUN routing state (`-4` policy rules + table 202 default route).
    pub desired_ipv4_active: bool,
    /// Desired IPv6 TUN routing state (`-6` policy rules + table 202 + `LINUX_TUN_IPV6_CIDR` + `LINUX_TUN_DNS_V6`).
    pub desired_ipv6_active: bool,
    /// Action for IPv4 routing (`-4` rules + table 202).
    pub ipv4_action: FamilyRoutingAction,
    /// Action for IPv6 routing (`-6` rules + table 202 + `LINUX_TUN_IPV6_CIDR`).
    pub ipv6_action: FamilyRoutingAction,
    /// `true` when DNS configuration must add or remove `LINUX_TUN_DNS_V6`.
    pub dns_v6_changed: bool,
    /// `true` when managed `/etc/resolv.conf` should be verified and re-asserted if overwritten.
    pub reassert_resolv_conf: bool,
    /// `true` when `flush_linux_dns_cache()` and `route_tx` emission should run.
    pub notify_route_change: bool,
}

/// Computes whether IPv6 TUN addressing, policy routing, and DNS should be active for the given
/// `tun_ipv6` setting and physical uplink availability.
///
/// Active whenever a physical IPv6 default route exists and either `tun_ipv6` was requested
/// or no physical IPv4 default route is present (auto-enabled on IPv6-only uplinks).
pub fn compute_desired_ipv6_active(tun_ipv6: bool, has_v4: bool, has_v6: bool) -> bool {
    has_v6 && (tun_ipv6 || !has_v4)
}

/// Plans dynamic IPv4/IPv6 routing, DNS, and route-change notification actions for a Linux
/// uplink probe result.
///
/// When `current_sig == previous_sig` (such as periodic IPv6 RA refreshes or same-NIC DHCP
/// renewals), suppresses `flush_linux_dns_cache()` and `route_tx` (`notify_route_change == false`)
/// while keeping `reassert_resolv_conf == true` so an overwritten `/etc/resolv.conf` is still
/// detected and re-asserted.
///
/// During transient offline transitions (`!current_sig.has_v4 && !current_sig.has_v6`),
/// preserves the existing IPv4/IPv6 stack state to avoid route/DNS thrashing across brief
/// handoffs (`IPv6-only -> Offline -> IPv6-only`, matching `windows_tun.rs`).
pub fn plan_uplink_transition(
    previous_sig: &LinuxUplinkSignature,
    current_sig: &LinuxUplinkSignature,
    current_ipv4_active: bool,
    current_ipv6_active: bool,
    tun_ipv6: bool,
) -> UplinkTransitionPlan {
    plan_uplink_transition_with_resync(
        previous_sig,
        current_sig,
        current_ipv4_active,
        current_ipv6_active,
        tun_ipv6,
        false,
    )
}

/// Plans dynamic IPv4/IPv6 routing, DNS, and route-change notification actions with an
/// optional `force_resync` flag used after Linux sleep/wake clock jumps so waking onto the
/// same Wi-Fi NIC still drains stale UDP NAT (`route_tx`), flushes DNS cache, and re-asserts
/// `/etc/resolv.conf`.
pub fn plan_uplink_transition_with_resync(
    previous_sig: &LinuxUplinkSignature,
    current_sig: &LinuxUplinkSignature,
    current_ipv4_active: bool,
    current_ipv6_active: bool,
    tun_ipv6: bool,
    force_resync: bool,
) -> UplinkTransitionPlan {
    let signature_changed = previous_sig != current_sig;
    if !signature_changed && !force_resync {
        return UplinkTransitionPlan {
            signature_changed: false,
            desired_ipv4_active: current_ipv4_active,
            desired_ipv6_active: current_ipv6_active,
            ipv4_action: FamilyRoutingAction::Keep,
            ipv6_action: FamilyRoutingAction::Keep,
            dns_v6_changed: false,
            reassert_resolv_conf: true,
            notify_route_change: false,
        };
    }

    // During transient offline windows (`!has_v4 && !has_v6`), preserve existing IPv4/IPv6
    // stack state instead of tearing down IPv6 and installing IPv4 while offline (matching
    // `windows_tun.rs`). Fail-closed outbound binding prevents leaks until an uplink returns.
    if !current_sig.has_v4 && !current_sig.has_v6 {
        return UplinkTransitionPlan {
            signature_changed,
            desired_ipv4_active: current_ipv4_active,
            desired_ipv6_active: current_ipv6_active,
            ipv4_action: FamilyRoutingAction::Keep,
            ipv6_action: FamilyRoutingAction::Keep,
            dns_v6_changed: false,
            reassert_resolv_conf: true,
            notify_route_change: true,
        };
    }

    let desired_ipv6_active =
        compute_desired_ipv6_active(tun_ipv6, current_sig.has_v4, current_sig.has_v6);
    let desired_ipv4_active =
        should_install_ipv4_routing(current_sig.has_v4, desired_ipv6_active);

    let ipv4_action = match (current_ipv4_active, desired_ipv4_active) {
        (false, true) => FamilyRoutingAction::Install,
        (true, false) => FamilyRoutingAction::Remove,
        _ => FamilyRoutingAction::Keep,
    };
    let ipv6_action = match (current_ipv6_active, desired_ipv6_active) {
        (false, true) => FamilyRoutingAction::Install,
        (true, false) => FamilyRoutingAction::Remove,
        _ => FamilyRoutingAction::Keep,
    };

    let dns_v6_changed = desired_ipv6_active != current_ipv6_active;

    UplinkTransitionPlan {
        signature_changed,
        desired_ipv4_active,
        desired_ipv6_active,
        ipv4_action,
        ipv6_action,
        dns_v6_changed,
        reassert_resolv_conf: true,
        notify_route_change: true,
    }
}

/// Builds the ordered `ip rule add` specifications for the requested address families.
pub fn build_policy_rules_for_families(
    fwmark: u32,
    route_table: u32,
    include_ipv4: bool,
    include_ipv6: bool,
) -> Vec<IpRuleSpec> {
    let mut specs = Vec::with_capacity(
        (usize::from(include_ipv4) + usize::from(include_ipv6)) * VDPI_RULE_PRIORITIES.len(),
    );
    let mark_hex = format!("0x{fwmark:x}/0x{VDPI_SO_MARK_MASK:x}");
    let table_str = route_table.to_string();

    for &(enabled, ipv6) in &[(include_ipv4, false), (include_ipv6, true)] {
        if !enabled {
            continue;
        }
        specs.push(IpRuleSpec {
            priority: PRIO_VDPI_MARK,
            ipv6,
            args: vec![
                "priority".into(),
                PRIO_VDPI_MARK.to_string(),
                "fwmark".into(),
                mark_hex.clone(),
                "lookup".into(),
                "main".into(),
            ],
        });
        specs.push(IpRuleSpec {
            priority: PRIO_VDPI_MARK_GUARD,
            ipv6,
            args: vec![
                "priority".into(),
                PRIO_VDPI_MARK_GUARD.to_string(),
                "fwmark".into(),
                mark_hex.clone(),
                "unreachable".into(),
            ],
        });
        specs.push(IpRuleSpec {
            priority: PRIO_SUPPRESS_MAIN,
            ipv6,
            args: vec![
                "priority".into(),
                PRIO_SUPPRESS_MAIN.to_string(),
                "lookup".into(),
                "main".into(),
                "suppress_prefixlength".into(),
                "0".into(),
            ],
        });
        specs.push(IpRuleSpec {
            priority: PRIO_VDPI_TABLE,
            ipv6,
            args: vec![
                "priority".into(),
                PRIO_VDPI_TABLE.to_string(),
                "iif".into(),
                "lo".into(),
                "lookup".into(),
                table_str.clone(),
            ],
        });
    }

    specs
}

/// Builds the ordered `ip rule add` specifications for `vdpi`'s `SO_MARK` policy routing.
pub fn build_policy_rules(fwmark: u32, route_table: u32, include_ipv6: bool) -> Vec<IpRuleSpec> {
    build_policy_rules_for_families(fwmark, route_table, true, include_ipv6)
}

/// Validates a Linux network interface name against `IFNAMSIZ` and kernel character constraints.
pub fn validate_tun_iface_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("Linux TUN interface name must not be empty");
    }
    if name.len() >= LINUX_IFNAMSIZ {
        bail!(
            "Linux TUN interface name '{name}' exceeds max length {}",
            LINUX_IFNAMSIZ - 1
        );
    }
    if name == "." || name == ".." || name.starts_with('-') {
        bail!("Linux TUN interface name '{name}' is not allowed");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'/' && b != b':' && b != b'%')
    {
        bail!("Linux TUN interface name '{name}' contains invalid characters");
    }
    Ok(())
}

/// Validates that a persisted NetworkManager drop-in path is strictly vdpi's managed path.
pub fn is_valid_state_nm_conf_path(path: &str) -> bool {
    path == NM_DNS_CONF_PATH
}

/// Validates that a persisted `/etc/resolv.conf` backup path points to a vdpi-owned backup location.
pub fn is_valid_state_resolv_backup_path(path: &str) -> bool {
    path == RESOLV_CONF_BACKUP_PATH || path == LEGACY_RESOLV_CONF_BACKUP_PATH
}

/// Validates a persisted `/etc/resolv.conf` symlink target before recreating it on Linux.
pub fn is_valid_resolv_symlink_target(target: &str) -> bool {
    !target.is_empty()
        && !target.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r')
        && (target.starts_with('/') || target.starts_with("../"))
}

/// Returns `true` when `/etc/nsswitch.conf` has an active `resolve` entry on its `hosts:` line
/// ahead of `dns` (as used by Arch/Fedora `nss-resolve` setups with non-stub
/// `/run/systemd/resolve/resolv.conf`).
pub fn nsswitch_uses_systemd_resolve(nsswitch_contents: &str) -> bool {
    for line in nsswitch_contents.lines() {
        let uncommented = line.split('#').next().unwrap_or("").trim();
        if uncommented.is_empty() {
            continue;
        }
        let Some((db, rest)) = uncommented.split_once(':') else {
            continue;
        };
        if !db.trim().eq_ignore_ascii_case("hosts") {
            continue;
        }
        let mut in_bracket = false;
        for token in rest.split_whitespace() {
            if in_bracket {
                if token.contains(']') {
                    in_bracket = false;
                }
                continue;
            }
            if let Some(prefix) = token.split('[').next() {
                if token.contains('[') && !token.contains(']') {
                    in_bracket = true;
                }
                if prefix == "resolve" {
                    return true;
                }
                if prefix == "dns" {
                    return false;
                }
            }
        }
    }
    false
}

/// Parses the `CapEff:` field from `/proc/self/status` contents and returns `true` when
/// `CAP_NET_ADMIN` (bit 12, `0x1000`) is set in the effective capability set.
pub fn proc_status_has_cap_net_admin(status_contents: &str) -> bool {
    for line in status_contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key.trim() != "CapEff" {
            continue;
        }
        let hex = value
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        // Bit 12 always resides in the lowest 64 bits (last 16 hex digits).
        let low_hex = if hex.len() > 16 {
            &hex[hex.len() - 16..]
        } else {
            hex
        };
        return u64::from_str_radix(low_hex, 16)
            .is_ok_and(|mask| (mask & CAP_NET_ADMIN_MASK) != 0);
    }
    false
}

/// Returns `true` when `/etc/resolv.conf` points exclusively at `systemd-resolved`'s local stub
/// listener (all configured `nameserver` entries are `127.0.0.53` / `127.0.0.54`, or when file
/// contents are unavailable/empty, symlinked to `stub-resolv.conf`).
pub fn resolv_conf_points_to_systemd_stub(
    symlink_target: Option<&str>,
    contents: Option<&str>,
) -> bool {
    if let Some(text) = contents {
        let mut saw_nameserver = false;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            if parts.next() == Some("nameserver") {
                saw_nameserver = true;
                if !matches!(parts.next(), Some("127.0.0.53" | "127.0.0.54")) {
                    return false;
                }
            }
        }
        if saw_nameserver {
            return true;
        }
    }
    if let Some(target) = symlink_target {
        if target.trim().contains("stub-resolv.conf") {
            return true;
        }
    }
    false
}

/// Returns `true` when host resolver configuration indicates `systemd-resolved` actually owns
/// host DNS: either `/etc/resolv.conf` points at `systemd-resolved`'s local stub listener
/// (`stub-resolv.conf` / `127.0.0.53` / `127.0.0.54`), or `/etc/nsswitch.conf` has an active
/// `resolve` entry ahead of `dns` on its `hosts:` database line (Arch/Fedora non-stub
/// `/run/systemd/resolve/resolv.conf` setups).
pub fn resolv_conf_uses_systemd_resolved(
    symlink_target: Option<&str>,
    contents: Option<&str>,
    nsswitch_contents: Option<&str>,
) -> bool {
    if resolv_conf_points_to_systemd_stub(symlink_target, contents) {
        return true;
    }
    nsswitch_contents.is_some_and(nsswitch_uses_systemd_resolve)
}

/// Returns `true` when `/etc/nsswitch.conf` routes glibc lookups through `nss-resolve`
/// (`resolve` before `dns`), yet `/etc/resolv.conf` does NOT point exclusively at
/// `systemd-resolved`'s local stub (`127.0.0.53` / `127.0.0.54`).
///
/// In that configuration, non-glibc resolvers (Go, musl, Chromium, Flatpak/Snap) read
/// `/etc/resolv.conf` directly and would leak DNS to ISP resolvers unless `/etc/resolv.conf`
/// is also rewritten to point at `vdpi`'s virtual DNS listener.
pub fn needs_resolv_conf_override_with_systemd_resolved(
    symlink_target: Option<&str>,
    contents: Option<&str>,
    nsswitch_contents: Option<&str>,
) -> bool {
    nsswitch_contents.is_some_and(nsswitch_uses_systemd_resolve)
        && !resolv_conf_points_to_systemd_stub(symlink_target, contents)
}

/// Returns `true` when `NetworkManager --print-config` indicates NetworkManager does not manage
/// `/etc/resolv.conf` (`dns=none` or `rc-manager=unmanaged`).
pub fn nm_config_disables_dns_management(config_output: &str) -> bool {
    for line in config_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((key, val)) = trimmed.split_once('=') {
            let key = key.trim();
            let val = val.trim();
            if (key.eq_ignore_ascii_case("dns") && val.eq_ignore_ascii_case("none"))
                || (key.eq_ignore_ascii_case("rc-manager") && val.eq_ignore_ascii_case("unmanaged"))
            {
                return true;
            }
        }
    }
    false
}

/// Returns `true` when `contents` carries the [`RESOLV_CONF_MARKER`] header line.
pub fn is_vdpi_managed_resolv_conf(contents: &str) -> bool {
    contents
        .lines()
        .any(|line| line.trim() == RESOLV_CONF_MARKER)
}

/// Renders the managed `/etc/resolv.conf` contents pointing at `vdpi`'s virtual DNS listener.
pub fn render_resolv_conf(dns_v4: &str, dns_v6: Option<&str>) -> String {
    render_resolv_conf_preserving(dns_v4, dns_v6, None)
}

/// Renders the managed `/etc/resolv.conf` contents pointing at `vdpi`'s virtual DNS listener
/// while preserving any `search`, `domain`, and `options` directives from `original_contents`.
pub fn render_resolv_conf_preserving(
    dns_v4: &str,
    dns_v6: Option<&str>,
    original_contents: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str(RESOLV_CONF_MARKER);
    out.push('\n');
    out.push_str(
        "# Do not edit while vdpi TUN mode is active; original config is restored automatically.\n",
    );
    out.push_str("nameserver ");
    out.push_str(dns_v4);
    out.push('\n');
    if let Some(v6) = dns_v6.map(str::trim).filter(|s| !s.is_empty()) {
        out.push_str("nameserver ");
        out.push_str(v6);
        out.push('\n');
    }

    let mut saw_options = false;
    let mut saw_edns0 = false;
    if let Some(orig) = original_contents {
        for raw_line in orig.lines() {
            let uncommented = raw_line.split(['#', ';']).next().unwrap_or("").trim();
            if uncommented.is_empty() {
                continue;
            }
            let mut parts = uncommented.split_whitespace();
            let Some(keyword) = parts.next() else {
                continue;
            };
            if !matches!(keyword, "search" | "domain" | "options") {
                continue;
            }
            let args: Vec<&str> = parts.collect();
            if args.is_empty() {
                continue;
            }
            if keyword == "options" {
                saw_options = true;
                if args.contains(&"edns0") {
                    saw_edns0 = true;
                }
            }
            out.push_str(keyword);
            for arg in args {
                out.push(' ');
                out.push_str(arg);
            }
            out.push('\n');
        }
    }

    if !saw_options {
        out.push_str("options edns0 trust-ad\n");
    } else if !saw_edns0 {
        out.push_str("options edns0\n");
    }
    out
}

/// Renders the ephemeral NetworkManager drop-in (`/run/NetworkManager/conf.d/99-vdpi-dns.conf`).
pub fn render_nm_dns_conf(dns_v4: &str, dns_v6: Option<&str>) -> String {
    let servers = match dns_v6.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v6) => format!("{dns_v4},{v6}"),
        None => dns_v4.to_string(),
    };
    format!("{RESOLV_CONF_MARKER}\n[global-dns-domain-*]\nservers={servers}\n")
}

/// Outcome of attempting to restore a marker-guarded `resolv.conf`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvRestoreOutcome {
    /// Restored original file contents from backup.
    RestoredFromBackup,
    /// Restored original symlink target.
    RestoredSymlink,
    /// Skipped overwriting because `resolv.conf` no longer carries [`RESOLV_CONF_MARKER`].
    SkippedExternallyModified,
    /// Nothing to restore (`resolv.conf` was absent or had no backup).
    NothingToRestore,
}

/// Backs up an unmanaged `resolv.conf` and its original symlink target to persistent storage
/// without modifying `resolv_path` yet.
///
/// When `resolv_path` already carries [`RESOLV_CONF_MARKER`], existing backup and saved symlink
/// metadata are preserved intact so restarts never clobber original recovery state.
pub fn prepare_resolv_conf_backup(
    resolv_path: &Path,
    backup_path: &Path,
    meta_path: &Path,
) -> Result<Option<String>> {
    let existing_text = fs::read_to_string(resolv_path).ok();
    let already_managed = existing_text
        .as_deref()
        .is_some_and(is_vdpi_managed_resolv_conf);

    let saved_meta_target = ResolvBackupMeta::load_from_path(meta_path)
        .ok()
        .flatten()
        .and_then(|meta| meta.symlink_target)
        .filter(|t| !t.is_empty());

    if already_managed {
        return Ok(saved_meta_target);
    }

    let current_symlink = read_symlink_target_if_link(resolv_path).filter(|t| !t.is_empty());

    if let Some(text) = existing_text.as_deref() {
        write_file_atomic(backup_path, text, 0o644)
            .with_context(|| format!("failed to back up {}", resolv_path.display()))?;
    }

    if let Some(ref target) = current_symlink {
        let meta = ResolvBackupMeta {
            symlink_target: Some(target.clone()),
        };
        meta.save_to_path(meta_path)
            .with_context(|| format!("failed to persist {}", meta_path.display()))?;
    } else {
        remove_file_if_exists(meta_path)?;
    }

    Ok(current_symlink)
}

/// Atomically installs a marker-guarded `resolv.conf`, backing up any pre-existing non-vdpi file.
///
/// Returns the original symlink target (if `resolv_path` was a symlink on Unix) so restore can
/// recreate the symlink intact.
pub fn install_resolv_conf_at(
    resolv_path: &Path,
    backup_path: &Path,
    dns_v4: &str,
    dns_v6: Option<&str>,
) -> Result<Option<String>> {
    let existing = fs::read_to_string(resolv_path).ok();
    let already_managed = existing.as_deref().is_some_and(is_vdpi_managed_resolv_conf);
    let symlink_target = if already_managed {
        None
    } else {
        read_symlink_target_if_link(resolv_path)
    };

    if !already_managed && !backup_path.exists() {
        if let Some(text) = existing.as_deref() {
            write_file_atomic(backup_path, text, 0o644)
                .with_context(|| format!("failed to back up {}", resolv_path.display()))?;
        }
    }

    let directive_source = if already_managed {
        fs::read_to_string(backup_path).ok()
    } else {
        existing
    };
    let managed = render_resolv_conf_preserving(dns_v4, dns_v6, directive_source.as_deref());
    write_file_atomic(resolv_path, &managed, 0o644)
        .with_context(|| format!("failed to write managed {}", resolv_path.display()))?;
    Ok(symlink_target)
}

/// Returns `true` when a vdpi-managed `resolv.conf` must be re-written to match `(dns_v4, dns_v6)`:
/// either the file is missing/unreadable, an external daemon (DHCP/NetworkManager) overwrote it
/// and stripped [`RESOLV_CONF_MARKER`], or its `nameserver` lines no longer match `(dns_v4, dns_v6)`.
pub fn resolv_conf_needs_reassert(
    current_contents: Option<&str>,
    dns_v4: &str,
    dns_v6: Option<&str>,
) -> bool {
    let Some(contents) = current_contents else {
        return true;
    };
    if !is_vdpi_managed_resolv_conf(contents) {
        return true;
    }
    let mut expected: Vec<&str> = vec![dns_v4.trim()];
    if let Some(v6) = dns_v6.map(str::trim).filter(|s| !s.is_empty()) {
        expected.push(v6);
    }
    let actual: Vec<&str> = contents
        .lines()
        .filter_map(|line| {
            let uncommented = line.split(['#', ';']).next().unwrap_or("").trim();
            let mut parts = uncommented.split_whitespace();
            if parts.next() == Some("nameserver") {
                parts.next()
            } else {
                None
            }
        })
        .collect();
    actual != expected
}

/// Re-asserts a vdpi-managed `resolv.conf` at `resolv_path` if DHCP/NetworkManager overwrote it
/// (missing [`RESOLV_CONF_MARKER`]) or its configured `nameserver` entries no longer match
/// `(dns_v4, dns_v6)`.
///
/// Pre-TUN backup state at `backup_path` is never overwritten. Returns `Ok(true)` when
/// `resolv_path` was rewritten and `Ok(false)` when it already matched.
pub fn reassert_managed_resolv_conf_at(
    resolv_path: &Path,
    backup_path: &Path,
    dns_v4: &str,
    dns_v6: Option<&str>,
) -> Result<bool> {
    let current = fs::read_to_string(resolv_path).ok();
    if !resolv_conf_needs_reassert(current.as_deref(), dns_v4, dns_v6) {
        return Ok(false);
    }

    let externally_overwritten = current
        .as_deref()
        .is_some_and(|text| !is_vdpi_managed_resolv_conf(text));
    let directive_source = if externally_overwritten {
        current
    } else {
        fs::read_to_string(backup_path).ok().or(current)
    };
    let managed = render_resolv_conf_preserving(dns_v4, dns_v6, directive_source.as_deref());
    write_file_atomic(resolv_path, &managed, 0o644)
        .with_context(|| format!("failed to re-assert managed {}", resolv_path.display()))?;
    Ok(true)
}

/// Restores `resolv_path` using persistent symlink metadata from `meta_path` (falling back to
/// `fallback_symlink_target` when `meta_path` is absent) and removes `meta_path` on success.
pub fn restore_resolv_conf_with_meta(
    resolv_path: &Path,
    backup_path: &Path,
    meta_path: &Path,
    fallback_symlink_target: Option<&str>,
) -> Result<ResolvRestoreOutcome> {
    let meta_target = ResolvBackupMeta::load_from_path(meta_path)
        .ok()
        .flatten()
        .and_then(|meta| meta.symlink_target)
        .filter(|t| !t.is_empty() && !t.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r'));
    let effective_target = meta_target.as_deref().or(fallback_symlink_target);
    let outcome = restore_resolv_conf_at(resolv_path, backup_path, effective_target)?;
    remove_file_if_exists(meta_path)?;
    Ok(outcome)
}

/// Restores `resolv_path` if and only if it still carries [`RESOLV_CONF_MARKER`].
pub fn restore_resolv_conf_at(
    resolv_path: &Path,
    backup_path: &Path,
    symlink_target: Option<&str>,
) -> Result<ResolvRestoreOutcome> {
    let current = match fs::read_to_string(resolv_path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            remove_file_if_exists(backup_path)?;
            return Ok(ResolvRestoreOutcome::NothingToRestore);
        }
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", resolv_path.display()));
        }
    };

    if !is_vdpi_managed_resolv_conf(&current) {
        remove_file_if_exists(backup_path)?;
        return Ok(ResolvRestoreOutcome::SkippedExternallyModified);
    }

    #[cfg(unix)]
    if let Some(target) = symlink_target.filter(|t| !t.is_empty()) {
        replace_with_symlink_atomic(resolv_path, Path::new(target))?;
        remove_file_if_exists(backup_path)?;
        return Ok(ResolvRestoreOutcome::RestoredSymlink);
    }

    #[cfg(not(unix))]
    let _ = symlink_target;

    match fs::read_to_string(backup_path) {
        Ok(original) => {
            write_file_atomic(resolv_path, &original, 0o644)
                .with_context(|| format!("failed to restore {}", resolv_path.display()))?;
            remove_file_if_exists(backup_path)?;
            Ok(ResolvRestoreOutcome::RestoredFromBackup)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Ok(ResolvRestoreOutcome::NothingToRestore)
        }
        Err(err) => Err(err).with_context(|| format!("failed to read {}", backup_path.display())),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn is_non_uplink_route_dev(dev: &str, exclude_iface: &str) -> bool {
    dev.is_empty()
        || dev == exclude_iface
        || dev == "lo"
        || dev.starts_with("docker")
        || dev.starts_with("virbr")
        || dev.starts_with("br-")
        || dev.starts_with("veth")
        || dev.starts_with("podman")
        || dev.starts_with("cni")
        || dev.starts_with("lxcbr")
        || dev.starts_with("vboxnet")
        || dev.starts_with("vmnet")
        || dev.starts_with("tailscale")
}

/// Extracts the primary physical uplink `(dev, gateway)` from `ip route show default` output,
/// excluding `linkdown` routes, the virtual TUN interface, loopback, Tailscale, and
/// container/VM bridge interfaces (`lo`, `docker*`, `virbr*`, `br-*`, `veth*`, `podman*`,
/// `cni*`, `lxcbr*`, `vboxnet*`, `vmnet*`, `tailscale*`).
pub fn parse_default_route_dev_and_gateway(
    route_output: &str,
    exclude_iface: &str,
) -> Option<(String, Option<String>)> {
    for line in route_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first().copied() != Some("default") {
            continue;
        }
        if tokens.contains(&"linkdown") {
            continue;
        }
        let Some(pos) = tokens.iter().position(|&t| t == "dev") else {
            continue;
        };
        if let Some(&dev) = tokens
            .get(pos + 1)
            .filter(|&&d| !is_non_uplink_route_dev(d, exclude_iface))
        {
            let gateway = tokens
                .iter()
                .position(|&t| t == "via")
                .and_then(|via_pos| {
                    // Handle both `via 192.168.1.1` and `via inet6 fe80::1` (`iproute2` RFC 5549).
                    match tokens.get(via_pos + 1).copied() {
                        Some("inet" | "inet6") => tokens.get(via_pos + 2).copied(),
                        other => other,
                    }
                })
                .filter(|gw| !gw.is_empty())
                .map(|gw| {
                    gw.parse::<IpAddr>()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|_| gw.to_string())
                });
            return Some((dev.to_string(), gateway));
        }
    }
    None
}

/// Extracts the primary physical uplink interface name from `ip route show default` output,
/// excluding `linkdown` routes, the virtual TUN interface, loopback, Tailscale, and
/// container/VM bridge interfaces (`lo`, `docker*`, `virbr*`, `br-*`, `veth*`, `podman*`,
/// `cni*`, `lxcbr*`, `vboxnet*`, `vmnet*`, `tailscale*`).
pub fn parse_default_route_dev(route_output: &str, exclude_iface: &str) -> Option<String> {
    parse_default_route_dev_and_gateway(route_output, exclude_iface).map(|(dev, _)| dev)
}

fn is_usable_local_unicast_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_multicast()
        && !ip.is_broadcast()
}

fn is_usable_local_unicast_ipv6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    let is_link_local = (seg0 & 0xffc0) == 0xfe80;
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !is_link_local
}

fn addr_line_has_unusable_scope_or_flags(tokens: &[&str]) -> bool {
    tokens
        .windows(2)
        .any(|w| {
            (w[0] == "scope" && matches!(w[1], "host" | "link"))
                || (w[0] == "preferred_lft" && w[1] == "0sec")
        })
        || tokens
            .iter()
            .any(|&t| matches!(t, "tentative" | "dadfailed" | "deprecated"))
}

/// Extracts sorted, deduplicated usable local unicast IPv4 addresses from `ip -4 addr show`
/// (both default multi-line and `-o` one-line formats), skipping `scope host`/`scope link`,
/// `tentative`/`dadfailed`/`deprecated`, loopback, link-local, unspecified, and multicast IPs.
pub fn parse_local_unicast_ipv4_addrs(addr_output: &str) -> Vec<Ipv4Addr> {
    let mut addrs = Vec::new();
    for line in addr_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(pos) = tokens.iter().position(|&t| t == "inet") else {
            continue;
        };
        if addr_line_has_unusable_scope_or_flags(&tokens) {
            continue;
        }
        if let Some(raw_ip) = tokens.get(pos + 1).and_then(|tok| tok.split('/').next()) {
            if let Ok(ip) = raw_ip.parse::<Ipv4Addr>() {
                if is_usable_local_unicast_ipv4(ip) {
                    addrs.push(ip);
                }
            }
        }
    }
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// Extracts sorted, deduplicated usable local unicast IPv6 addresses from `ip -6 addr show`
/// (both default multi-line and `-o` one-line formats), skipping `scope host`/`scope link`,
/// `tentative`/`dadfailed`/`deprecated`, loopback, link-local (`fe80::/10`), unspecified, and
/// multicast IPs.
pub fn parse_local_unicast_ipv6_addrs(addr_output: &str) -> Vec<Ipv6Addr> {
    let mut addrs = Vec::new();
    for line in addr_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(pos) = tokens.iter().position(|&t| t == "inet6") else {
            continue;
        };
        if addr_line_has_unusable_scope_or_flags(&tokens) {
            continue;
        }
        if let Some(raw_ip) = tokens.get(pos + 1).and_then(|tok| tok.split('/').next()) {
            if let Ok(ip) = raw_ip.parse::<Ipv6Addr>() {
                if is_usable_local_unicast_ipv6(ip) {
                    addrs.push(ip);
                }
            }
        }
    }
    addrs.sort_unstable();
    addrs.dedup();
    addrs
}

/// Returns `true` when an `ip monitor route` output line represents a potentially relevant
/// physical uplink/routing change rather than loopback, `vdpi`'s own TUN interface, Tailscale,
/// or container/VM bridge churn (`docker*`, `virbr*`, `br-*`, `veth*`, `podman*`, `cni*`,
/// `lxcbr*`, `vboxnet*`, `vmnet*`, `tailscale*`).
pub fn is_relevant_route_monitor_line(line: &str, tun_iface: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if let Some(pos) = tokens.iter().position(|&t| t == "dev") {
        if let Some(&dev) = tokens.get(pos + 1) {
            if is_non_uplink_route_dev(dev, tun_iface) {
                return false;
            }
        }
    }
    true
}

/// Computes the per-user fallback runtime state directory used when running non-root
/// (`CAP_NET_ADMIN`, `geteuid() != 0`) and [`LINUX_TUN_STATE_DIR`] (`/run/vdpi`) is not writable
/// (`EACCES`).
///
/// Prefers `$XDG_RUNTIME_DIR/vdpi` when `xdg_runtime_dir` is a non-empty absolute path (other
/// than `/`), otherwise falls back to `/tmp/vdpi-run-<uid>`.
pub fn fallback_user_runtime_dir(xdg_runtime_dir: Option<&str>, uid: u32) -> PathBuf {
    if let Some(xdg) = xdg_runtime_dir
        .map(str::trim)
        .filter(|dir| dir.starts_with('/') && !dir.trim_end_matches('/').is_empty())
    {
        PathBuf::from(format!("{}/vdpi", xdg.trim_end_matches('/')))
    } else {
        PathBuf::from(format!("/tmp/vdpi-run-{uid}"))
    }
}

fn read_symlink_target_if_link(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_symlink() {
        return None;
    }
    fs::read_link(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(unix)]
fn replace_with_symlink_atomic(path: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    static SYM_SEQ: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("resolv.conf");
    let tmp = parent.join(format!(
        ".{base}.vdpi.sym.{}.{}",
        std::process::id(),
        SYM_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_file(&tmp);
    symlink(target, &tmp)
        .with_context(|| format!("failed to create temp symlink {}", tmp.display()))?;
    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err).with_context(|| format!("failed to replace {}", path.display()));
    }
    Ok(())
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
        .unwrap_or("vdpi-file");
    let tmp = parent.join(format!(
        ".{base}.vdpi.tmp.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));

    let write_res = (|| -> Result<()> {
        let mut file = File::create(&tmp)
            .with_context(|| format!("failed to create temp file {}", tmp.display()))?;
        file.write_all(contents.as_bytes())
            .with_context(|| format!("failed to write temp file {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temp file {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(mode);
            fs::set_permissions(&tmp, perms)
                .with_context(|| format!("failed to chmod temp file {}", tmp.display()))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
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

#[cfg(target_os = "linux")]
mod imp {
    use super::{
        build_policy_rules_for_families, compute_desired_ipv6_active, detect_wake_or_time_jump,
        fallback_user_runtime_dir, is_relevant_route_monitor_line, is_valid_resolv_symlink_target,
        is_valid_state_nm_conf_path, is_valid_state_resolv_backup_path,
        needs_resolv_conf_override_with_systemd_resolved, nm_config_disables_dns_management,
        parse_default_route_dev_and_gateway, parse_local_unicast_ipv4_addrs,
        parse_local_unicast_ipv6_addrs, plan_uplink_transition_with_resync,
        prepare_resolv_conf_backup, proc_status_has_cap_net_admin, read_symlink_target_if_link,
        reassert_managed_resolv_conf_at, remove_file_if_exists, render_nm_dns_conf,
        render_resolv_conf_preserving, resolv_conf_uses_systemd_resolved, restore_resolv_conf_at,
        should_install_ipv4_routing, validate_tun_iface_name, write_file_atomic,
        FamilyRoutingAction, LinuxDnsBackend, LinuxTunState, LinuxUplinkSignature,
        ResolvBackupMeta, ALL_RP_FILTER_PATH, LINUX_IFNAMSIZ, LINUX_ROUTE_IDLE_POLL_INTERVAL,
        LINUX_TUN_DNS_V4, LINUX_TUN_DNS_V6, LINUX_TUN_IFACE, LINUX_TUN_IPV4_CIDR,
        LINUX_TUN_IPV6_CIDR, LINUX_TUN_LOCK_PATH, LINUX_TUN_MTU, LINUX_TUN_PRIVILEGE_ERROR,
        LINUX_TUN_STATE_DIR, LINUX_TUN_STATE_PATH, LINUX_TUN_TXQUEUELEN_LADDER, NM_DNS_CONF_PATH,
        NSSWITCH_CONF_PATH, RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_META_PATH, RESOLV_CONF_PATH,
        TRUSTED_BIN_PREFIXES, VDPI_ROUTE_TABLE, VDPI_SO_MARK,
    };
    use crate::binder::{DynamicOutboundBinder, OutboundTarget};
    use anyhow::{anyhow, bail, Context, Result};
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant, SystemTime};
    use tokio::sync::watch;
    use tracing::{debug, info, warn};

    const _: () = assert!(LINUX_IFNAMSIZ == libc::IFNAMSIZ);

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    // `_IOW('T', 202, int)` = 0x4004_54ca; fits cleanly in both glibc `c_ulong` and musl `c_int`.
    const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
    const RESOLVECTL_DNS_MAX_RETRIES: u32 = 3;
    const RESOLVECTL_DNS_BACKOFF: Duration = Duration::from_millis(75);
    const ROUTE_WATCH_DEBOUNCE: Duration = Duration::from_millis(400);
    const ROUTE_WATCH_MAX_DEBOUNCE: Duration = Duration::from_millis(1200);

    #[repr(C)]
    struct IfReq {
        ifr_name: [u8; libc::IFNAMSIZ],
        ifr_flags: libc::c_short,
        _pad: [u8; 22],
    }

    /// Opens a non-persistent Linux `/dev/net/tun` device (`IFF_TUN | IFF_NO_PI`).
    ///
    /// Because `TUNSETPERSIST` is intentionally NOT enabled, the kernel automatically destroys
    /// the virtual interface whenever the returned `OwnedFd` closes (including on `SIGKILL`).
    pub fn open_tun_device(name: &str) -> Result<OwnedFd> {
        let (fd, _) = open_tun_device_named(name)?;
        Ok(fd)
    }

    fn open_tun_device_named(name: &str) -> Result<(OwnedFd, String)> {
        validate_tun_iface_name(name)?;

        // SAFETY: `c"/dev/net/tun"` is a static NUL-terminated C string passed to `open(2)`.
        let raw_fd = unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw_fd < 0 {
            let err = io::Error::last_os_error();
            return Err(err).context(
                "failed to open /dev/net/tun (ensure root or CAP_NET_ADMIN and tun kernel module)",
            );
        }
        // SAFETY: `raw_fd` was just returned by `open(2)` and is exclusively owned here.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let mut ifr = IfReq {
            ifr_name: [0u8; libc::IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            _pad: [0u8; 22],
        };
        let name_bytes = name.as_bytes();
        ifr.ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // SAFETY: `owned_fd` is a valid `/dev/net/tun` descriptor and `ifr` matches Linux `struct ifreq`.
        let rc = unsafe {
            libc::ioctl(
                owned_fd.as_raw_fd(),
                TUNSETIFF,
                std::ptr::from_mut(&mut ifr),
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            let hint = if err.kind() == io::ErrorKind::PermissionDenied {
                " (ensure root or CAP_NET_ADMIN)"
            } else {
                " (ensure root or CAP_NET_ADMIN and that the interface is not already in use)"
            };
            return Err(err).with_context(|| {
                format!("ioctl(TUNSETIFF) failed while creating Linux TUN interface '{name}'{hint}")
            });
        }

        let assigned_len = ifr
            .ifr_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(ifr.ifr_name.len());
        let assigned_name = std::str::from_utf8(&ifr.ifr_name[..assigned_len])
            .unwrap_or(name)
            .to_string();

        Ok((owned_fd, assigned_name))
    }

    #[derive(Debug, Clone)]
    struct LinuxRuntimePaths {
        state_dir: PathBuf,
        state_path: PathBuf,
        lock_path: PathBuf,
    }

    impl LinuxRuntimePaths {
        fn from_dir(state_dir: PathBuf) -> Self {
            let state_path = state_dir.join("tun-state.json");
            let lock_path = state_dir.join("tun.lock");
            Self {
                state_dir,
                state_path,
                lock_path,
            }
        }

        fn system_default() -> Self {
            Self {
                state_dir: PathBuf::from(LINUX_TUN_STATE_DIR),
                state_path: PathBuf::from(LINUX_TUN_STATE_PATH),
                lock_path: PathBuf::from(LINUX_TUN_LOCK_PATH),
            }
        }
    }

    fn is_dir_writable(dir: &Path) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path = CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))?;
        // SAFETY: `c_path` is a valid NUL-terminated path passed to `access(2)`.
        if unsafe { libc::access(c_path.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn verify_owned_dir(dir: &Path, uid: u32) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt;

        let meta = fs::symlink_metadata(dir)?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to use non-directory or symlink runtime path {}",
                    dir.display()
                ),
            ));
        }
        if meta.uid() != uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "runtime directory {} is owned by uid {}, expected {}",
                    dir.display(),
                    meta.uid(),
                    uid
                ),
            ));
        }
        Ok(())
    }

    fn prepare_runtime_dir(dir: &Path, user_fallback_uid: Option<u32>) -> io::Result<()> {
        if let Some(uid) = user_fallback_uid {
            use std::os::unix::fs::DirBuilderExt;

            if fs::symlink_metadata(dir).is_ok() {
                verify_owned_dir(dir, uid)?;
            } else {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(dir)?;
                verify_owned_dir(dir, uid)?;
            }
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        } else {
            fs::create_dir_all(dir)?;
        }

        is_dir_writable(dir)
    }

    enum LockOpenError {
        PermissionDenied(io::Error),
        AlreadyLocked,
        Other(anyhow::Error),
    }

    fn try_open_and_flock(
        paths: &LinuxRuntimePaths,
        user_fallback_uid: Option<u32>,
        write_pid: bool,
    ) -> std::result::Result<File, LockOpenError> {
        if let Err(err) = prepare_runtime_dir(&paths.state_dir, user_fallback_uid) {
            if err.kind() == io::ErrorKind::PermissionDenied {
                return Err(LockOpenError::PermissionDenied(err));
            }
            return Err(LockOpenError::Other(
                anyhow::Error::new(err)
                    .context(format!("failed to create {}", paths.state_dir.display())),
            ));
        }

        let mut lock_file = match fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&paths.lock_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                return Err(LockOpenError::PermissionDenied(err));
            }
            Err(err) => {
                return Err(LockOpenError::Other(anyhow::Error::new(err).context(
                    format!(
                        "failed to open Linux TUN lock file {}",
                        paths.lock_path.display()
                    ),
                )));
            }
        };

        // SAFETY: `lock_file` is an open file descriptor exclusively owned here.
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Err(LockOpenError::AlreadyLocked);
            }
            return Err(LockOpenError::Other(anyhow::Error::new(err).context(
                format!(
                    "failed to acquire exclusive lock on {}",
                    paths.lock_path.display()
                ),
            )));
        }

        if write_pid {
            let _ = lock_file.set_len(0);
            let _ = writeln!(lock_file, "{}", std::process::id());
            let _ = lock_file.flush();
        }
        Ok(lock_file)
    }

    fn acquire_lock_with_fallback(
        write_pid: bool,
        fail_on_locked: bool,
    ) -> Result<Option<(File, LinuxRuntimePaths)>> {
        let primary = LinuxRuntimePaths::system_default();
        let primary_err = match try_open_and_flock(&primary, None, write_pid) {
            Ok(file) => return Ok(Some((file, primary))),
            Err(LockOpenError::AlreadyLocked) => {
                if fail_on_locked {
                    bail!(
                        "another vdpi Linux TUN instance is already running (lock held on {})",
                        primary.lock_path.display()
                    );
                }
                info!(
                    lock = %primary.lock_path.display(),
                    "another vdpi Linux TUN instance is active; skipping cleanup"
                );
                return Ok(None);
            }
            Err(LockOpenError::PermissionDenied(err)) => err,
            Err(LockOpenError::Other(err)) => return Err(err),
        };

        // SAFETY: `geteuid(2)` is always safe to call and never fails.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Err(anyhow::Error::new(primary_err).context(format!(
                "failed to access Linux TUN runtime directory {}",
                primary.state_dir.display()
            )));
        }

        let xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        let mut fallback_dirs = vec![fallback_user_runtime_dir(xdg.as_deref(), euid)];
        let tmp_dir = fallback_user_runtime_dir(None, euid);
        if fallback_dirs[0] != tmp_dir {
            fallback_dirs.push(tmp_dir);
        }

        let mut last_err: Option<anyhow::Error> = None;
        for dir in fallback_dirs {
            let candidate = LinuxRuntimePaths::from_dir(dir);
            match try_open_and_flock(&candidate, Some(euid), write_pid) {
                Ok(file) => {
                    info!(
                        system_dir = LINUX_TUN_STATE_DIR,
                        fallback_dir = %candidate.state_dir.display(),
                        euid,
                        error = %primary_err,
                        "non-root CAP_NET_ADMIN cannot write to /run/vdpi; falling back to per-user runtime directory"
                    );
                    return Ok(Some((file, candidate)));
                }
                Err(LockOpenError::AlreadyLocked) => {
                    if fail_on_locked {
                        bail!(
                            "another vdpi Linux TUN instance is already running (lock held on {})",
                            candidate.lock_path.display()
                        );
                    }
                    info!(
                        lock = %candidate.lock_path.display(),
                        "another vdpi Linux TUN instance is active; skipping cleanup"
                    );
                    return Ok(None);
                }
                Err(LockOpenError::PermissionDenied(err)) => {
                    last_err = Some(anyhow::Error::new(err).context(format!(
                        "failed to access fallback Linux TUN runtime directory {}",
                        candidate.state_dir.display()
                    )));
                }
                Err(LockOpenError::Other(err)) => {
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow::Error::new(primary_err).context(format!(
                "failed to access Linux TUN runtime directory {}",
                primary.state_dir.display()
            ))
        }))
    }

    fn acquire_tun_lock() -> Result<(File, LinuxRuntimePaths)> {
        acquire_lock_with_fallback(true, true)?
            .ok_or_else(|| anyhow!("failed to acquire Linux TUN lock"))
    }

    fn try_acquire_cleanup_lock() -> Result<Option<(File, LinuxRuntimePaths)>> {
        acquire_lock_with_fallback(false, false)
    }

    fn has_tun_privileges() -> bool {
        // SAFETY: `geteuid(2)` is always safe to call and never fails.
        if unsafe { libc::geteuid() } == 0 {
            return true;
        }
        fs::read_to_string("/proc/self/status")
            .ok()
            .is_some_and(|status| proc_status_has_cap_net_admin(&status))
    }

    fn set_fd_nonblocking(fd: libc::c_int) -> io::Result<()> {
        // SAFETY: `fd` is a valid open pipe descriptor owned by the caller.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: adding `O_NONBLOCK` to our own pipe read descriptor is safe.
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn flush_linux_dns_cache() {
        if let Some(resolvectl) = resolve_trusted_bin("resolvectl") {
            let _ = Command::new(resolvectl).arg("flush-caches").output();
        }
    }

    struct RouteWatcherConfig {
        tun_iface: String,
        tun_ipv6: bool,
        binder: Arc<DynamicOutboundBinder>,
        ipv6_active: Arc<AtomicBool>,
        dns_reverted: Arc<AtomicBool>,
        state: Arc<Mutex<LinuxTunState>>,
        state_path: PathBuf,
        initial_signature: LinuxUplinkSignature,
        initial_ipv4_routing_active: bool,
    }

    struct RouteWatcherContext {
        iface: String,
        tun_ipv6: bool,
        binder: Arc<DynamicOutboundBinder>,
        ipv6_active: Arc<AtomicBool>,
        dns_reverted: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        state: Arc<Mutex<LinuxTunState>>,
        state_path: PathBuf,
        route_tx: watch::Sender<u64>,
        last_signature: LinuxUplinkSignature,
        ipv4_routing_active: bool,
    }

    impl RouteWatcherContext {
        fn reconcile_uplink_change(&mut self, force_resync: bool) {
            let current_sig = detect_uplink_signature(&self.iface);
            let current_v6_active = self.ipv6_active.load(Ordering::Acquire);
            let plan = plan_uplink_transition_with_resync(
                &self.last_signature,
                &current_sig,
                self.ipv4_routing_active,
                current_v6_active,
                self.tun_ipv6,
                force_resync,
            );

            if !plan.signature_changed && !force_resync {
                // On same-NIC DHCP renewals the uplink signature stays unchanged, yet DHCP may
                // still overwrite `/etc/resolv.conf`. Verify and re-assert managed
                // `/etc/resolv.conf` while keeping DNS cache flush and `route_tx` suppressed.
                if plan.reassert_resolv_conf {
                    let state_guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    if !self.stop.load(Ordering::Acquire)
                        && !self.dns_reverted.load(Ordering::Acquire)
                    {
                        let dns_v6 = current_v6_active.then_some(LINUX_TUN_DNS_V6);
                        sync_linux_dns_on_transition(
                            &self.iface,
                            LINUX_TUN_DNS_V4,
                            dns_v6,
                            false,
                            true,
                            &self.state_path,
                            &state_guard,
                        );
                    }
                }
                debug!(
                    iface = %self.iface,
                    has_v4 = current_sig.has_v4,
                    v4_nic = ?current_sig.v4_nic,
                    v4_gw = ?current_sig.v4_gateway,
                    v4_addrs = ?current_sig.v4_local_addrs,
                    has_v6 = current_sig.has_v6,
                    v6_nic = ?current_sig.v6_nic,
                    v6_gw = ?current_sig.v6_gateway,
                    v6_addrs = ?current_sig.v6_local_addrs,
                    "Linux route event observed; active uplink signature unchanged (skipping DNS flush and route_tx)"
                );
                return;
            }

            info!(
                iface = %self.iface,
                force_resync,
                prev_v4 = self.last_signature.has_v4,
                prev_v4_nic = ?self.last_signature.v4_nic,
                prev_v4_gw = ?self.last_signature.v4_gateway,
                prev_v4_addrs = ?self.last_signature.v4_local_addrs,
                prev_v6 = self.last_signature.has_v6,
                prev_v6_nic = ?self.last_signature.v6_nic,
                prev_v6_gw = ?self.last_signature.v6_gateway,
                prev_v6_addrs = ?self.last_signature.v6_local_addrs,
                has_v4 = current_sig.has_v4,
                v4_nic = ?current_sig.v4_nic,
                v4_gw = ?current_sig.v4_gateway,
                v4_addrs = ?current_sig.v4_local_addrs,
                has_v6 = current_sig.has_v6,
                v6_nic = ?current_sig.v6_nic,
                v6_gw = ?current_sig.v6_gateway,
                v6_addrs = ?current_sig.v6_local_addrs,
                "Linux uplink reconciliation triggered; syncing routing and DNS"
            );

            let next_target = OutboundTarget {
                nic_name: current_sig.preferred_nic().map(str::to_string),
                if_index_v4: None,
                if_index_v6: None,
                fwmark: Some(VDPI_SO_MARK),
                fail_closed: true,
            };
            if self.binder.snapshot() != next_target {
                info!(
                    iface = %self.iface,
                    nic = ?next_target.nic_name,
                    "Linux physical uplink changed; updated outbound binder"
                );
                self.binder.update(next_target);
            }

            let mut routing_mutations_ok = true;

            // Phase 1: Install newly required routing families before tearing down old ones so
            // traffic never hits a leak or blackhole window during IPv4/IPv6 roaming.
            if plan.ipv4_action == FamilyRoutingAction::Install {
                match install_ipv4_routing(&self.iface, VDPI_ROUTE_TABLE, VDPI_SO_MARK) {
                    Ok(()) => {
                        self.ipv4_routing_active = true;
                        info!(
                            iface = %self.iface,
                            table = VDPI_ROUTE_TABLE,
                            "installed Linux IPv4 TUN default route and -4 policy rules after uplink change"
                        );
                    }
                    Err(err) => {
                        routing_mutations_ok = false;
                        warn!(
                            iface = %self.iface,
                            error = %err,
                            "failed to install Linux IPv4 TUN routing after uplink change"
                        );
                    }
                }
            }

            let mut next_v6_active = match plan.ipv6_action {
                FamilyRoutingAction::Install => {
                    match configure_ipv6_addr(&self.iface).and_then(|()| {
                        install_ipv6_routing(&self.iface, VDPI_ROUTE_TABLE, VDPI_SO_MARK)
                    }) {
                        Ok(()) => {
                            info!(
                                iface = %self.iface,
                                table = VDPI_ROUTE_TABLE,
                                addr = LINUX_TUN_IPV6_CIDR,
                                "enabled Linux IPv6 TUN address, default route, and -6 policy rules after uplink change"
                            );
                            true
                        }
                        Err(err) => {
                            routing_mutations_ok = false;
                            warn!(
                                iface = %self.iface,
                                error = %err,
                                "failed to enable Linux IPv6 TUN routing on uplink transition; rolling back IPv6 state"
                            );
                            let _ = remove_policy_rules(VDPI_SO_MARK, VDPI_ROUTE_TABLE, true);
                            let _ = flush_route_table(VDPI_ROUTE_TABLE, true);
                            remove_ipv6_addr(&self.iface);
                            false
                        }
                    }
                }
                FamilyRoutingAction::Remove => false,
                FamilyRoutingAction::Keep => current_v6_active,
            };

            let ipv6_changed = next_v6_active != current_v6_active;
            if ipv6_changed {
                self.ipv6_active.store(next_v6_active, Ordering::Release);
                info!(
                    iface = %self.iface,
                    prev_ipv6_active = current_v6_active,
                    ipv6_active = next_v6_active,
                    "Linux TUN ipv6_active updated dynamically on uplink transition"
                );
            }

            // Phase 2: Synchronize DNS backends (`LINUX_TUN_DNS_V6`) and re-assert managed
            // `/etc/resolv.conf` if DHCP/NetworkManager overwrote it, serialized against
            // `LinuxTunSession::revert_dns_early()`.
            {
                let mut state_guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if !self.stop.load(Ordering::Acquire) && !self.dns_reverted.load(Ordering::Acquire)
                {
                    state_guard.ipv6_enabled = next_v6_active;
                    let dns_v6 = next_v6_active.then_some(LINUX_TUN_DNS_V6);
                    sync_linux_dns_on_transition(
                        &self.iface,
                        LINUX_TUN_DNS_V4,
                        dns_v6,
                        ipv6_changed,
                        plan.reassert_resolv_conf,
                        &self.state_path,
                        &state_guard,
                    );
                }
            }

            // Phase 3: Remove obsolete routing families after installations and DNS updates.
            if plan.ipv4_action == FamilyRoutingAction::Remove && next_v6_active {
                match remove_ipv4_routing(VDPI_ROUTE_TABLE, VDPI_SO_MARK) {
                    Ok(()) => {
                        self.ipv4_routing_active = false;
                        info!(
                            iface = %self.iface,
                            table = VDPI_ROUTE_TABLE,
                            "removed Linux IPv4 TUN default route and -4 policy rules for IPv6-only uplink"
                        );
                    }
                    Err(err) => {
                        routing_mutations_ok = false;
                        warn!(
                            iface = %self.iface,
                            error = %err,
                            "failed to remove Linux IPv4 TUN routing for IPv6-only uplink"
                        );
                    }
                }
            } else if plan.ipv4_action == FamilyRoutingAction::Remove && !next_v6_active {
                // IPv6 installation failed so IPv4 removal was deferred; retry on next event.
                routing_mutations_ok = false;
            }

            if plan.ipv6_action == FamilyRoutingAction::Remove {
                if let Err(err) = remove_ipv6_routing(&self.iface, VDPI_ROUTE_TABLE, VDPI_SO_MARK) {
                    routing_mutations_ok = false;
                    next_v6_active = true;
                    self.ipv6_active.store(true, Ordering::Release);
                    let mut state_guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    state_guard.ipv6_enabled = true;
                    warn!(
                        iface = %self.iface,
                        error = %err,
                        "failed to remove Linux IPv6 TUN routing after uplink change; will retry on next route event"
                    );
                } else {
                    info!(
                        iface = %self.iface,
                        table = VDPI_ROUTE_TABLE,
                        addr = LINUX_TUN_IPV6_CIDR,
                        "removed Linux IPv6 TUN address, default route, and -6 policy rules after uplink change"
                    );
                }
            }

            // Only advance `self.last_signature` after all Phase 1/3 routing mutations succeed so
            // any transient `ip rule`/`ip route` failure retries cleanly on the next route event.
            if routing_mutations_ok {
                self.last_signature = current_sig;
            } else {
                warn!(
                    iface = %self.iface,
                    "preserving previous Linux uplink signature so failed routing mutation(s) retry on the next route event"
                );
            }

            // Phase 4: Flush DNS cache and emit `route_tx` on uplink signature change or wake.
            if plan.notify_route_change {
                flush_linux_dns_cache();
                self.route_tx.send_modify(|epoch| {
                    *epoch = epoch.saturating_add(1);
                });
                debug!(
                    iface = %self.iface,
                    ipv4_active = self.ipv4_routing_active,
                    ipv6_active = next_v6_active,
                    force_resync,
                    "Linux uplink transition complete; flushed DNS cache and notified TUN pipeline"
                );
            }
        }
    }

    #[derive(Debug)]
    struct LinuxRouteWatcher {
        stop: Arc<AtomicBool>,
        child: Arc<Mutex<Option<Child>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl LinuxRouteWatcher {
        fn spawn(cfg: RouteWatcherConfig) -> Result<(Self, watch::Receiver<u64>)> {
            let ip_bin = require_trusted_bin("ip")?;
            let mut child = Command::new(&ip_bin)
                .args(["monitor", "route"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| {
                    format!("failed to spawn `{} monitor route`", ip_bin.display())
                })?;

            let Some(mut stdout) = child.stdout.take() else {
                let _ = child.kill();
                let _ = child.wait();
                bail!("`ip monitor route` child did not expose stdout pipe");
            };

            let stdout_fd = stdout.as_raw_fd();
            if let Err(err) = set_fd_nonblocking(stdout_fd) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err).context("failed to set O_NONBLOCK on `ip monitor route` stdout");
            }

            let (route_tx, route_rx) = watch::channel::<u64>(0);
            let stop = Arc::new(AtomicBool::new(false));
            let child_slot = Arc::new(Mutex::new(Some(child)));

            let bg_stop = Arc::clone(&stop);
            let bg_child = Arc::clone(&child_slot);
            let mut ctx = RouteWatcherContext {
                iface: cfg.tun_iface,
                tun_ipv6: cfg.tun_ipv6,
                binder: cfg.binder,
                ipv6_active: cfg.ipv6_active,
                dns_reverted: cfg.dns_reverted,
                stop: Arc::clone(&stop),
                state: cfg.state,
                state_path: cfg.state_path,
                route_tx,
                last_signature: cfg.initial_signature,
                ipv4_routing_active: cfg.initial_ipv4_routing_active,
            };

            let handle = match std::thread::Builder::new()
                .name("vdpi-linux-route-watch".to_string())
                .spawn(move || {
                    let mut pending_deadline: Option<Instant> = None;
                    let mut first_pending_at: Option<Instant> = None;
                    let mut pending_force_resync = false;
                    let mut buf = [0u8; 4096];
                    let mut line_carry = String::new();
                    let mut last_instant = Instant::now();
                    let mut last_wall = SystemTime::now();

                    loop {
                        if bg_stop.load(Ordering::Acquire) {
                            break;
                        }

                        let expected_wait = match pending_deadline {
                            Some(deadline) => {
                                let now = Instant::now();
                                if now >= deadline {
                                    pending_deadline = None;
                                    first_pending_at = None;
                                    let force_resync = std::mem::take(&mut pending_force_resync);
                                    if !bg_stop.load(Ordering::Acquire) {
                                        ctx.reconcile_uplink_change(force_resync);
                                    }
                                    last_instant = Instant::now();
                                    last_wall = SystemTime::now();
                                    continue;
                                }
                                deadline.saturating_duration_since(now)
                            }
                            None => LINUX_ROUTE_IDLE_POLL_INTERVAL,
                        };
                        let timeout_ms =
                            i32::try_from(expected_wait.as_nanos().div_ceil(1_000_000))
                                .unwrap_or(i32::MAX)
                                .max(1) as libc::c_int;

                        let mut pfd = libc::pollfd {
                            fd: stdout_fd,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        // SAFETY: `pfd` is a valid stack-allocated `pollfd` with `nfds == 1`.
                        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                        let poll_err = (rc < 0).then(io::Error::last_os_error);

                        if bg_stop.load(Ordering::Acquire) {
                            break;
                        }

                        let now_instant = Instant::now();
                        let now_wall = SystemTime::now();
                        let instant_elapsed = now_instant.saturating_duration_since(last_instant);
                        let wall_delta = now_wall
                            .duration_since(last_wall)
                            .map_err(|err| err.duration());
                        last_instant = now_instant;
                        last_wall = now_wall;

                        if detect_wake_or_time_jump(instant_elapsed, wall_delta, expected_wait) {
                            info!(
                                iface = %ctx.iface,
                                instant_elapsed_ms = instant_elapsed.as_millis(),
                                ?wall_delta,
                                "Linux sleep/wake or clock jump detected; scheduling forced uplink reconciliation"
                            );
                            pending_force_resync = true;
                            let first = *first_pending_at.get_or_insert(now_instant);
                            let next_deadline = (now_instant + ROUTE_WATCH_DEBOUNCE)
                                .min(first + ROUTE_WATCH_MAX_DEBOUNCE);
                            pending_deadline = Some(next_deadline);
                        }

                        if let Some(err) = poll_err {
                            if err.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            warn!(
                                error = %err,
                                "Linux route watcher poll() failed; stopping route watcher"
                            );
                            break;
                        }
                        if rc == 0 {
                            continue;
                        }

                        if (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
                            let mut saw_relevant = false;
                            let mut eof = false;
                            loop {
                                match stdout.read(&mut buf) {
                                    Ok(0) => {
                                        eof = true;
                                        break;
                                    }
                                    Ok(n) => {
                                        let chunk = String::from_utf8_lossy(&buf[..n]);
                                        line_carry.push_str(&chunk);
                                        while let Some(nl) = line_carry.find('\n') {
                                            let line = line_carry[..nl].trim();
                                            if is_relevant_route_monitor_line(line, &ctx.iface) {
                                                saw_relevant = true;
                                            }
                                            line_carry.drain(..=nl);
                                        }
                                        if line_carry.len() > 8192 {
                                            if is_relevant_route_monitor_line(
                                                line_carry.trim(),
                                                &ctx.iface,
                                            ) {
                                                saw_relevant = true;
                                            }
                                            line_carry.clear();
                                        }
                                    }
                                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {
                                        continue;
                                    }
                                    Err(err) => {
                                        warn!(
                                            error = %err,
                                            "Linux route watcher read failed; stopping route watcher"
                                        );
                                        eof = true;
                                        break;
                                    }
                                }
                            }
                            if saw_relevant {
                                let now = Instant::now();
                                let first = *first_pending_at.get_or_insert(now);
                                let next_deadline = (now + ROUTE_WATCH_DEBOUNCE)
                                    .min(first + ROUTE_WATCH_MAX_DEBOUNCE);
                                pending_deadline = Some(next_deadline);
                            }
                            if eof || (pfd.revents & libc::POLLNVAL) != 0 {
                                break;
                            }
                        } else if (pfd.revents & libc::POLLNVAL) != 0 {
                            break;
                        }
                    }

                    drop(stdout);
                    let mut guard = bg_child.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(mut c) = guard.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                }) {
                Ok(handle) => handle,
                Err(err) => {
                    let mut guard = child_slot.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some(mut c) = guard.take() {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    return Err(err).context("failed to spawn Linux route watcher thread");
                }
            };

            Ok((
                Self {
                    stop,
                    child: child_slot,
                    thread: Some(handle),
                },
                route_rx,
            ))
        }
    }

    impl Drop for LinuxRouteWatcher {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            {
                let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(child) = guard.as_mut() {
                    let _ = child.kill();
                }
            }
            if let Some(handle) = self.thread.take() {
                let _ = handle.join();
            }
            let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(mut child) = guard.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    struct ConfiguredNetworkState {
        applied_txqueuelen: Option<u32>,
        uplink_signature: LinuxUplinkSignature,
        ipv4_routing_active: bool,
        ipv6_active: bool,
    }

    /// Active Linux desktop TUN session managing interface config, `SO_MARK` policy routing,
    /// route-change monitoring, and 3-backend DNS configuration with automatic rollback on `Drop`.
    #[derive(Debug)]
    pub struct LinuxTunSession {
        iface: String,
        binder: Arc<DynamicOutboundBinder>,
        ipv6_active: Arc<AtomicBool>,
        route_watch_rx: Option<watch::Receiver<u64>>,
        route_watcher: Option<LinuxRouteWatcher>,
        runtime_paths: LinuxRuntimePaths,
        cleaned: bool,
        dns_reverted: Arc<AtomicBool>,
        state: Arc<Mutex<LinuxTunState>>,
        _lock_file: File,
    }

    impl LinuxTunSession {
        /// Starts Linux TUN networking: verifies root or `CAP_NET_ADMIN` privileges, acquires the
        /// single-instance `flock`, recovers any stale crash state, opens `/dev/net/tun`,
        /// configures IP/MTU/RPF, updates `DynamicOutboundBinder` with `SO_MARK`, installs table
        /// `202` + policy rules `5480..=5500`, activates DNS interception, and starts the
        /// `ip monitor route` handoff watcher.
        pub fn start(
            binder: Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
        ) -> Result<(Self, OwnedFd)> {
            if !has_tun_privileges() {
                bail!("{LINUX_TUN_PRIVILEGE_ERROR}");
            }

            let (lock_file, runtime_paths) = acquire_tun_lock()?;

            if let Err(err) = cleanup_linux_tun_state_locked(&runtime_paths) {
                warn!(error = %err, "stale Linux TUN state recovery reported an issue");
            }

            let (tun_fd, iface) = open_tun_device_named(LINUX_TUN_IFACE)?;

            let mut state = LinuxTunState {
                iface: iface.clone(),
                route_table: VDPI_ROUTE_TABLE,
                fwmark: VDPI_SO_MARK,
                ipv6_enabled: false,
                dns_backend: LinuxDnsBackend::None,
                nm_conf_path: None,
                resolv_backup_path: None,
                resolv_symlink_target: None,
                prev_all_rp_filter: None,
                pid: std::process::id(),
            };
            state
                .save_to_path(&runtime_paths.state_path)
                .context("failed to persist initial Linux TUN state")?;

            let configured = match Self::configure_network(
                &iface,
                &binder,
                tun_ipv6,
                &runtime_paths.state_path,
                &mut state,
            ) {
                Ok(cfg) => cfg,
                Err(err) => {
                    binder.update(OutboundTarget::default());
                    let _ = cleanup_linux_tun_state_locked(&runtime_paths);
                    return Err(err);
                }
            };

            let ipv6_active = Arc::new(AtomicBool::new(configured.ipv6_active));
            let dns_reverted = Arc::new(AtomicBool::new(false));
            let dns_backend = state.dns_backend;
            let shared_state = Arc::new(Mutex::new(state));

            let (route_watcher, route_watch_rx) = match LinuxRouteWatcher::spawn(
                RouteWatcherConfig {
                    tun_iface: iface.clone(),
                    tun_ipv6,
                    binder: Arc::clone(&binder),
                    ipv6_active: Arc::clone(&ipv6_active),
                    dns_reverted: Arc::clone(&dns_reverted),
                    state: Arc::clone(&shared_state),
                    state_path: runtime_paths.state_path.clone(),
                    initial_signature: configured.uplink_signature,
                    initial_ipv4_routing_active: configured.ipv4_routing_active,
                },
            ) {
                Ok((watcher, rx)) => (Some(watcher), Some(rx)),
                Err(err) => {
                    warn!(
                        iface = %iface,
                        error = %err,
                        "failed to start Linux route watcher (`ip monitor route`); continuing without automatic handoff notifications"
                    );
                    (None, None)
                }
            };

            let ipv6_active_now = ipv6_active.load(Ordering::Acquire);
            let fwmark_hex = format!("0x{VDPI_SO_MARK:x}");
            info!(
                iface = %iface,
                mtu = LINUX_TUN_MTU,
                txqueuelen = ?configured.applied_txqueuelen,
                table = VDPI_ROUTE_TABLE,
                fwmark = %fwmark_hex,
                ipv6 = ipv6_active_now,
                dns = ?dns_backend,
                state_path = %runtime_paths.state_path.display(),
                "Linux desktop TUN session active"
            );

            Ok((
                Self {
                    iface,
                    binder,
                    ipv6_active,
                    route_watch_rx,
                    route_watcher,
                    runtime_paths,
                    cleaned: false,
                    dns_reverted,
                    state: shared_state,
                    _lock_file: lock_file,
                },
                tun_fd,
            ))
        }

        /// Returns the kernel-assigned Linux TUN interface name (typically `"vdpi0"`).
        pub fn iface_name(&self) -> &str {
            &self.iface
        }

        /// Returns `true` when IPv6 TUN addressing and policy routing are active on this session
        /// (activated at startup or auto-enabled on an IPv6-only uplink, updated dynamically on
        /// uplink transitions).
        pub fn is_ipv6_active(&self) -> bool {
            self.ipv6_active.load(Ordering::Acquire)
        }

        /// Takes the debounced route-change watch receiver driven by `ip monitor route` so the
        /// caller can pass it into the TUN pipeline for Wi-Fi/Hotspot/Ethernet handoff handling.
        pub fn take_route_watch(&mut self) -> Option<tokio::sync::watch::Receiver<u64>> {
            self.route_watch_rx.take()
        }

        /// Idempotently reverts Linux DNS configuration early (for example, before closing
        /// `tun_fd` during shutdown) while leaving full routing and state teardown to `Drop`.
        pub fn revert_dns_early(&self) {
            if self.dns_reverted.swap(true, Ordering::AcqRel) {
                return;
            }
            let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let state = LinuxTunState::load_from_path(&self.runtime_paths.state_path)
                .ok()
                .flatten()
                .or_else(|| Some(guard.clone()));
            let mut errors = Vec::new();
            cleanup_linux_dns(&self.iface, state.as_ref(), &mut errors);
            if !errors.is_empty() {
                warn!(
                    iface = %self.iface,
                    errors = %errors.join("; "),
                    "early Linux TUN DNS revert reported error(s)"
                );
            }
        }

        fn configure_network(
            iface: &str,
            binder: &Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
            state_path: &Path,
            state: &mut LinuxTunState,
        ) -> Result<ConfiguredNetworkState> {
            let mtu_str = LINUX_TUN_MTU.to_string();

            run_ip(&["-4", "addr", "replace", LINUX_TUN_IPV4_CIDR, "dev", iface])
                .context("failed to assign IPv4 address to TUN interface")?;
            let mut applied_txqueuelen: Option<u32> = None;
            for qlen in LINUX_TUN_TXQUEUELEN_LADDER {
                let qlen_str = qlen.to_string();
                match run_ip(&[
                    "link",
                    "set",
                    "dev",
                    iface,
                    "mtu",
                    &mtu_str,
                    "txqueuelen",
                    &qlen_str,
                    "up",
                ]) {
                    Ok(()) => {
                        applied_txqueuelen = Some(qlen);
                        break;
                    }
                    Err(err) => {
                        warn!(
                            iface = %iface,
                            txqueuelen = qlen,
                            error = %err,
                            "ip link set with txqueuelen failed; trying smaller fallback"
                        );
                    }
                }
            }
            if applied_txqueuelen.is_none() {
                run_ip(&["link", "set", "dev", iface, "mtu", &mtu_str, "up"])
                    .context("failed to bring up Linux TUN interface")?;
            }

            configure_loose_rp_filter(iface, state_path, state);

            let uplink_signature = detect_uplink_signature(iface);
            let has_v4 = uplink_signature.has_v4;
            let has_v6 = uplink_signature.has_v6;
            let auto_enable_ipv6 = !tun_ipv6 && has_v6 && !has_v4;
            if auto_enable_ipv6 {
                info!(
                    iface = %iface,
                    "IPv6-only host detected (physical IPv6 default route with no IPv4 default route); auto-enabling IPv6 TUN mode"
                );
            }

            let desired_ipv6 = compute_desired_ipv6_active(tun_ipv6, has_v4, has_v6);
            let want_ipv6 = if desired_ipv6 {
                match configure_ipv6_addr(iface) {
                    Ok(()) => true,
                    Err(err) if has_v4 => {
                        warn!(
                            iface = %iface,
                            error = %err,
                            "IPv6 TUN address setup unavailable; continuing in IPv4-only TUN mode"
                        );
                        false
                    }
                    Err(err) => {
                        return Err(err).context(
                            "IPv6 TUN address setup failed on IPv6-only host (no physical IPv4 default route)",
                        );
                    }
                }
            } else {
                if tun_ipv6 && !has_v6 {
                    warn!(
                        iface = %iface,
                        "no non-TUN IPv6 default route found in main table; skipping IPv6 TUN policy routing to avoid blackholing IPv4-only host"
                    );
                }
                false
            };

            binder.update(OutboundTarget {
                nic_name: uplink_signature.preferred_nic().map(str::to_string),
                if_index_v4: None,
                if_index_v6: None,
                fwmark: Some(VDPI_SO_MARK),
                fail_closed: true,
            });

            let (ipv4_routing_active, ipv6_active) =
                install_routing(iface, VDPI_ROUTE_TABLE, VDPI_SO_MARK, want_ipv6, has_v4)?;
            state.ipv6_enabled = ipv6_active;

            let dns_v6 = ipv6_active.then_some(LINUX_TUN_DNS_V6);
            configure_linux_dns(iface, LINUX_TUN_DNS_V4, dns_v6, state_path, state)?;

            state
                .save_to_path(state_path)
                .context("failed to persist active Linux TUN state")?;

            Ok(ConfiguredNetworkState {
                applied_txqueuelen,
                uplink_signature,
                ipv4_routing_active,
                ipv6_active,
            })
        }
    }

    impl Drop for LinuxTunSession {
        fn drop(&mut self) {
            // Stop the `ip monitor route` child before tearing down routes/rules so our own
            // cleanup does not trigger spurious notifications and the child is reaped cleanly.
            drop(self.route_watcher.take());
            if !self.cleaned {
                self.cleaned = true;
                self.binder.update(OutboundTarget::default());
                if let Err(err) = cleanup_linux_tun_state_locked(&self.runtime_paths) {
                    warn!(
                        iface = %self.iface,
                        error = %err,
                        "failed to clean up Linux TUN state on drop"
                    );
                }
            }
        }
    }

    /// Idempotently tears down `vdpi`'s Linux TUN policy rules, routing table `202`,
    /// `rp_filter` override, DNS configuration (including persistent `/var/lib/vdpi` backups),
    /// and runtime `tun-state.json`.
    ///
    /// Acquires a non-blocking exclusive `flock` on the runtime lock file first; if another
    /// live `vdpi` instance holds the lock, returns `Ok(())` immediately without touching the
    /// active TUN session (safe for systemd `ExecStopPost=+/usr/local/bin/vdpi --internal-linux-tun-cleanup`).
    pub fn cleanup_linux_tun_state() -> Result<()> {
        let Some((_lock_file, runtime_paths)) = try_acquire_cleanup_lock()? else {
            return Ok(());
        };
        cleanup_linux_tun_state_locked(&runtime_paths)
    }

    fn cleanup_linux_tun_state_locked(runtime_paths: &LinuxRuntimePaths) -> Result<()> {
        let mut cleanup_errors: Vec<String> = Vec::new();
        let state_path = runtime_paths.state_path.as_path();
        let state = match LinuxTunState::load_from_path(state_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                warn!(
                    path = %state_path.display(),
                    error = %err,
                    "failed to load Linux TUN state file; proceeding with default cleanup"
                );
                if err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
                {
                    cleanup_errors.push(format!("{err:#}"));
                }
                None
            }
        };

        let iface = match state.as_ref().map(|s| s.iface.as_str()) {
            Some(candidate) => match validate_tun_iface_name(candidate) {
                Ok(()) => candidate,
                Err(err) => {
                    warn!(
                        iface = %candidate,
                        error = %err,
                        "ignoring invalid interface name in Linux TUN state; falling back to default"
                    );
                    LINUX_TUN_IFACE
                }
            },
            None => LINUX_TUN_IFACE,
        };
        let route_table = match state.as_ref().map(|s| s.route_table) {
            Some(table) if table == VDPI_ROUTE_TABLE => table,
            Some(other) => {
                warn!(
                    route_table = other,
                    expected = VDPI_ROUTE_TABLE,
                    "ignoring unexpected route_table in Linux TUN state; falling back to default"
                );
                VDPI_ROUTE_TABLE
            }
            None => VDPI_ROUTE_TABLE,
        };
        let fwmark = match state.as_ref().map(|s| s.fwmark) {
            Some(mark) if mark == VDPI_SO_MARK => mark,
            Some(other) => {
                warn!(
                    fwmark = other,
                    expected = VDPI_SO_MARK,
                    "ignoring unexpected fwmark in Linux TUN state; falling back to default"
                );
                VDPI_SO_MARK
            }
            None => VDPI_SO_MARK,
        };

        if let Err(err) = remove_policy_rules(fwmark, route_table, false) {
            warn!(error = %err, "failed to remove IPv4 Linux TUN policy rules");
            cleanup_errors.push(format!("{err:#}"));
        }
        if let Err(err) = remove_policy_rules(fwmark, route_table, true) {
            warn!(error = %err, "failed to remove IPv6 Linux TUN policy rules");
            cleanup_errors.push(format!("{err:#}"));
        }
        if let Err(err) = flush_route_table(route_table, false) {
            warn!(table = route_table, error = %err, "failed to flush IPv4 Linux TUN route table");
            cleanup_errors.push(format!("{err:#}"));
        }
        if let Err(err) = flush_route_table(route_table, true) {
            warn!(table = route_table, error = %err, "failed to flush IPv6 Linux TUN route table");
            cleanup_errors.push(format!("{err:#}"));
        }

        if let Some(prev) = state.as_ref().and_then(|s| s.prev_all_rp_filter) {
            if prev <= 2 {
                if let Err(err) = fs::write(ALL_RP_FILTER_PATH, format!("{prev}\n")) {
                    warn!(
                        path = ALL_RP_FILTER_PATH,
                        prev,
                        error = %err,
                        "failed to restore /proc/sys/net/ipv4/conf/all/rp_filter"
                    );
                    cleanup_errors.push(format!(
                        "failed to restore {ALL_RP_FILTER_PATH} to {prev}: {err}"
                    ));
                }
            } else {
                warn!(
                    prev,
                    "ignoring out-of-range prev_all_rp_filter value in Linux TUN state"
                );
            }
        }

        cleanup_linux_dns(iface, state.as_ref(), &mut cleanup_errors);

        // Non-persistent TUN disappears when closed; delete defensively if still present.
        match require_trusted_bin("ip") {
            Ok(ip_bin) => {
                if let Err(err) = run_ip_cleanup(&ip_bin, &["link", "del", "dev", iface], false) {
                    warn!(iface = %iface, error = %err, "failed to delete Linux TUN interface");
                    cleanup_errors.push(format!("{err:#}"));
                }
            }
            Err(err) => {
                warn!(error = %err, "ip binary unavailable during Linux TUN interface cleanup");
                cleanup_errors.push(format!("{err:#}"));
            }
        }

        match fs::remove_file(state_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(
                    path = %state_path.display(),
                    error = %err,
                    "failed to remove Linux TUN state file"
                );
                cleanup_errors.push(format!(
                    "failed to remove {}: {err}",
                    state_path.display()
                ));
            }
        }

        if !cleanup_errors.is_empty() {
            bail!(
                "Linux TUN cleanup failed with {} error(s): {}",
                cleanup_errors.len(),
                cleanup_errors.join("; ")
            );
        }

        debug!(iface = %iface, table = route_table, "cleaned up Linux TUN state");
        Ok(())
    }

    fn configure_loose_rp_filter(iface: &str, state_path: &Path, state: &mut LinuxTunState) {
        let path = format!("/proc/sys/net/ipv4/conf/{iface}/rp_filter");
        if let Err(err) = fs::write(&path, "2\n") {
            warn!(
                path = %path,
                error = %err,
                "failed to set loose rp_filter=2 on Linux TUN interface"
            );
        }

        let prev_all = fs::read_to_string(ALL_RP_FILTER_PATH)
            .ok()
            .and_then(|raw| raw.trim().parse::<u8>().ok());
        if prev_all == Some(1) {
            state.prev_all_rp_filter = Some(1);
            if let Err(err) = state.save_to_path(state_path) {
                warn!(
                    path = %state_path.display(),
                    error = %err,
                    "failed to persist prev_all_rp_filter snapshot before relaxing rp_filter"
                );
            }
            if let Err(err) = fs::write(ALL_RP_FILTER_PATH, "2\n") {
                state.prev_all_rp_filter = None;
                warn!(
                    path = ALL_RP_FILTER_PATH,
                    error = %err,
                    "failed to set loose rp_filter=2 on all interfaces"
                );
            }
        }
    }

    fn configure_ipv6_addr(iface: &str) -> Result<()> {
        if fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
            .is_ok_and(|disabled| disabled.trim() == "1")
        {
            bail!("kernel IPv6 is disabled");
        }
        run_ip(&["-6", "addr", "replace", LINUX_TUN_IPV6_CIDR, "dev", iface])
            .context("failed to assign IPv6 address to TUN interface")
    }

    fn remove_ipv6_addr(iface: &str) {
        if let Some(ip_bin) = resolve_trusted_bin("ip") {
            if let Err(err) = run_ip_cleanup(
                &ip_bin,
                &["-6", "addr", "del", LINUX_TUN_IPV6_CIDR, "dev", iface],
                true,
            ) {
                let lower = err.to_string().to_ascii_lowercase();
                if !lower.contains("cannot assign requested address") {
                    warn!(
                        iface = %iface,
                        error = %err,
                        "failed to remove IPv6 address from Linux TUN interface"
                    );
                }
            }
        }
    }

    fn detect_physical_default_route(
        family: &str,
        exclude_iface: &str,
    ) -> Option<(String, Option<String>)> {
        let ip_bin = resolve_trusted_bin("ip")?;
        let output = Command::new(&ip_bin)
            .args([family, "route", "show", "table", "main", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_default_route_dev_and_gateway(&stdout, exclude_iface)
    }

    fn detect_local_unicast_ipv4_addrs(nic: &str) -> Vec<Ipv4Addr> {
        let Some(ip_bin) = resolve_trusted_bin("ip") else {
            return Vec::new();
        };
        let Ok(output) = Command::new(&ip_bin)
            .args(["-4", "-o", "addr", "show", "dev", nic, "scope", "global"])
            .output()
        else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_local_unicast_ipv4_addrs(&stdout)
    }

    fn detect_local_unicast_ipv6_addrs(nic: &str) -> Vec<Ipv6Addr> {
        let Some(ip_bin) = resolve_trusted_bin("ip") else {
            return Vec::new();
        };
        let Ok(output) = Command::new(&ip_bin)
            .args(["-6", "-o", "addr", "show", "dev", nic, "scope", "global"])
            .output()
        else {
            return Vec::new();
        };
        if !output.status.success() {
            return Vec::new();
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_local_unicast_ipv6_addrs(&stdout)
    }

    fn detect_uplink_signature(exclude_iface: &str) -> LinuxUplinkSignature {
        let (v4_nic, v4_gateway, v4_local_addrs) =
            match detect_physical_default_route("-4", exclude_iface) {
                Some((nic, gw)) => {
                    let addrs = detect_local_unicast_ipv4_addrs(&nic);
                    (Some(nic), gw, addrs)
                }
                None => (None, None, Vec::new()),
            };
        let (v6_nic, v6_gateway, v6_local_addrs) =
            match detect_physical_default_route("-6", exclude_iface) {
                Some((nic, gw)) => {
                    let addrs = detect_local_unicast_ipv6_addrs(&nic);
                    (Some(nic), gw, addrs)
                }
                None => (None, None, Vec::new()),
            };
        LinuxUplinkSignature::from_details(
            v4_nic,
            v4_gateway,
            v4_local_addrs,
            v6_nic,
            v6_gateway,
            v6_local_addrs,
        )
    }

    fn install_routing(
        iface: &str,
        route_table: u32,
        fwmark: u32,
        include_ipv6: bool,
        has_ipv4_uplink: bool,
    ) -> Result<(bool, bool)> {
        let ipv4_active = if should_install_ipv4_routing(has_ipv4_uplink, include_ipv6) {
            install_ipv4_routing(iface, route_table, fwmark)?;
            true
        } else {
            info!(
                iface = %iface,
                table = route_table,
                "IPv6-only host detected (no physical IPv4 default route); skipping IPv4 TUN default route and -4 policy rules"
            );
            false
        };

        if !include_ipv6 {
            return Ok((ipv4_active, false));
        }

        match install_ipv6_routing(iface, route_table, fwmark) {
            Ok(()) => Ok((ipv4_active, true)),
            Err(err) if has_ipv4_uplink => {
                warn!(
                    iface = %iface,
                    error = %err,
                    "IPv6 TUN policy routing failed (kernel may lack CONFIG_IPV6_MULTIPLE_TABLES); falling back cleanly to IPv4-only TUN mode"
                );
                let _ = remove_policy_rules(fwmark, route_table, true);
                let _ = flush_route_table(route_table, true);
                remove_ipv6_addr(iface);
                Ok((ipv4_active, false))
            }
            Err(err) => {
                let _ = remove_policy_rules(fwmark, route_table, true);
                let _ = flush_route_table(route_table, true);
                Err(err)
            }
        }
    }

    fn install_ipv4_routing(iface: &str, route_table: u32, fwmark: u32) -> Result<()> {
        let table_str = route_table.to_string();

        run_ip(&[
            "-4", "route", "replace", "default", "dev", iface, "table", &table_str,
        ])
        .context("failed to install IPv4 default route in TUN policy table")?;

        remove_policy_rules(fwmark, route_table, false)?;

        for spec in build_policy_rules_for_families(fwmark, route_table, true, false) {
            let mut argv = Vec::with_capacity(spec.args.len() + 3);
            argv.push("-4");
            argv.push("rule");
            argv.push("add");
            for arg in &spec.args {
                argv.push(arg.as_str());
            }
            run_ip(&argv).with_context(|| {
                format!(
                    "failed to install -4 policy rule at priority {}",
                    spec.priority
                )
            })?;
        }

        Ok(())
    }

    fn remove_ipv4_routing(route_table: u32, fwmark: u32) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if let Err(err) = remove_policy_rules(fwmark, route_table, false) {
            errors.push(format!("{err:#}"));
        }
        if let Err(err) = flush_route_table(route_table, false) {
            errors.push(format!("{err:#}"));
        }
        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }
        Ok(())
    }

    fn install_ipv6_routing(iface: &str, route_table: u32, fwmark: u32) -> Result<()> {
        let table_str = route_table.to_string();

        run_ip(&[
            "-6", "route", "replace", "default", "dev", iface, "table", &table_str,
        ])
        .context("failed to install IPv6 default route in TUN policy table")?;

        remove_policy_rules(fwmark, route_table, true)?;

        for spec in build_policy_rules_for_families(fwmark, route_table, false, true) {
            let mut argv = Vec::with_capacity(spec.args.len() + 3);
            argv.push("-6");
            argv.push("rule");
            argv.push("add");
            for arg in &spec.args {
                argv.push(arg.as_str());
            }
            run_ip(&argv).with_context(|| {
                format!(
                    "failed to install -6 policy rule at priority {}",
                    spec.priority
                )
            })?;
        }

        Ok(())
    }

    fn remove_ipv6_routing(iface: &str, route_table: u32, fwmark: u32) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();
        if let Err(err) = remove_policy_rules(fwmark, route_table, true) {
            errors.push(format!("{err:#}"));
        }
        if let Err(err) = flush_route_table(route_table, true) {
            errors.push(format!("{err:#}"));
        }
        remove_ipv6_addr(iface);
        if !errors.is_empty() {
            bail!("{}", errors.join("; "));
        }
        Ok(())
    }

    fn remove_policy_rules(fwmark: u32, route_table: u32, ipv6: bool) -> Result<()> {
        let ip_bin = require_trusted_bin("ip")?;
        let family = if ipv6 { "-6" } else { "-4" };
        let specs = build_policy_rules_for_families(fwmark, route_table, !ipv6, ipv6);

        for spec in specs {
            let mut argv = Vec::with_capacity(spec.args.len() + 3);
            argv.push(family);
            argv.push("rule");
            argv.push("del");
            for arg in &spec.args {
                argv.push(arg.as_str());
            }
            for _ in 0..8 {
                if !run_ip_cleanup(&ip_bin, &argv, ipv6)? {
                    break;
                }
            }
        }
        Ok(())
    }

    fn flush_route_table(route_table: u32, ipv6: bool) -> Result<()> {
        let ip_bin = require_trusted_bin("ip")?;
        let family = if ipv6 { "-6" } else { "-4" };
        let table_str = route_table.to_string();
        run_ip_cleanup(
            &ip_bin,
            &[family, "route", "flush", "table", &table_str],
            ipv6,
        )
        .map(|_| ())
    }

    fn configure_linux_dns(
        iface: &str,
        dns_v4: &str,
        dns_v6: Option<&str>,
        state_path: &Path,
        state: &mut LinuxTunState,
    ) -> Result<()> {
        let resolv_path = Path::new(RESOLV_CONF_PATH);
        let backup_path = Path::new(RESOLV_CONF_BACKUP_PATH);
        let meta_path = Path::new(RESOLV_CONF_META_PATH);

        if is_systemd_resolved_active() {
            let symlink_target = read_symlink_target_if_link(resolv_path);
            let resolv_contents = fs::read_to_string(resolv_path).ok();
            let nsswitch_contents = fs::read_to_string(NSSWITCH_CONF_PATH).ok();
            let override_non_stub_resolv = needs_resolv_conf_override_with_systemd_resolved(
                symlink_target.as_deref(),
                resolv_contents.as_deref(),
                nsswitch_contents.as_deref(),
            );

            state.dns_backend = LinuxDnsBackend::SystemdResolved;
            if override_non_stub_resolv {
                let saved_symlink =
                    prepare_resolv_conf_backup(resolv_path, backup_path, meta_path)?;
                state.resolv_backup_path = Some(RESOLV_CONF_BACKUP_PATH.to_string());
                if let Some(target) = saved_symlink {
                    state.resolv_symlink_target = Some(target);
                }
            }
            state
                .save_to_path(state_path)
                .context(
                    "failed to persist Linux TUN DNS state before configuring systemd-resolved",
                )?;
            configure_systemd_resolved_dns(iface, dns_v4, dns_v6)?;
            if override_non_stub_resolv {
                let original_resolv = fs::read_to_string(backup_path).ok();
                let managed =
                    render_resolv_conf_preserving(dns_v4, dns_v6, original_resolv.as_deref());
                write_file_atomic(resolv_path, &managed, 0o644).with_context(|| {
                    format!(
                        "failed to write managed {RESOLV_CONF_PATH} alongside non-stub systemd-resolved"
                    )
                })?;
                info!(
                    path = RESOLV_CONF_PATH,
                    "also configured non-stub /etc/resolv.conf alongside systemd-resolved to prevent non-glibc DNS leaks"
                );
            }
            return Ok(());
        }

        if is_network_manager_dns_active() {
            state.dns_backend = LinuxDnsBackend::NetworkManager;
            state.nm_conf_path = Some(NM_DNS_CONF_PATH.to_string());
            state
                .save_to_path(state_path)
                .context(
                    "failed to persist Linux TUN DNS state before configuring NetworkManager",
                )?;
            configure_network_manager_dns(dns_v4, dns_v6)?;
            return Ok(());
        }

        let symlink_target = prepare_resolv_conf_backup(resolv_path, backup_path, meta_path)?;
        state.dns_backend = LinuxDnsBackend::ResolvConf;
        state.resolv_backup_path = Some(RESOLV_CONF_BACKUP_PATH.to_string());
        if let Some(target) = symlink_target {
            state.resolv_symlink_target = Some(target);
        }
        state
            .save_to_path(state_path)
            .context("failed to persist Linux TUN DNS state before updating /etc/resolv.conf")?;

        let original_resolv = fs::read_to_string(backup_path).ok();
        let managed = render_resolv_conf_preserving(dns_v4, dns_v6, original_resolv.as_deref());
        write_file_atomic(resolv_path, &managed, 0o644)
            .with_context(|| format!("failed to write managed {RESOLV_CONF_PATH}"))?;
        Ok(())
    }

    fn sync_linux_dns_on_transition(
        iface: &str,
        dns_v4: &str,
        dns_v6: Option<&str>,
        dns_v6_changed: bool,
        reassert_resolv_conf: bool,
        state_path: &Path,
        state: &LinuxTunState,
    ) {
        let backup_path = state
            .resolv_backup_path
            .as_deref()
            .filter(|p| is_valid_state_resolv_backup_path(p))
            .unwrap_or(RESOLV_CONF_BACKUP_PATH);

        match state.dns_backend {
            LinuxDnsBackend::SystemdResolved => {
                if dns_v6_changed {
                    if let Err(err) = configure_systemd_resolved_dns(iface, dns_v4, dns_v6) {
                        warn!(
                            iface = %iface,
                            dns_v6 = ?dns_v6,
                            error = %err,
                            "failed to update systemd-resolved DNS servers on uplink transition"
                        );
                    }
                }
                if state.resolv_backup_path.is_some() && (dns_v6_changed || reassert_resolv_conf) {
                    match reassert_managed_resolv_conf_at(
                        Path::new(RESOLV_CONF_PATH),
                        Path::new(backup_path),
                        dns_v4,
                        dns_v6,
                    ) {
                        Ok(true) => {
                            info!(
                                path = RESOLV_CONF_PATH,
                                dns_v6 = ?dns_v6,
                                "re-asserted managed /etc/resolv.conf alongside non-stub systemd-resolved"
                            );
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                path = RESOLV_CONF_PATH,
                                error = %err,
                                "failed to re-assert managed /etc/resolv.conf alongside systemd-resolved"
                            );
                        }
                    }
                }
            }
            LinuxDnsBackend::NetworkManager => {
                if dns_v6_changed {
                    if let Err(err) = configure_network_manager_dns(dns_v4, dns_v6) {
                        warn!(
                            dns_v6 = ?dns_v6,
                            error = %err,
                            "failed to update NetworkManager DNS drop-in on uplink transition"
                        );
                    }
                }
            }
            LinuxDnsBackend::ResolvConf => {
                if dns_v6_changed || reassert_resolv_conf {
                    match reassert_managed_resolv_conf_at(
                        Path::new(RESOLV_CONF_PATH),
                        Path::new(backup_path),
                        dns_v4,
                        dns_v6,
                    ) {
                        Ok(true) => {
                            info!(
                                path = RESOLV_CONF_PATH,
                                dns_v6 = ?dns_v6,
                                "re-asserted managed /etc/resolv.conf after Linux uplink change"
                            );
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                path = RESOLV_CONF_PATH,
                                error = %err,
                                "failed to re-assert managed /etc/resolv.conf after Linux uplink change"
                            );
                        }
                    }
                }
            }
            LinuxDnsBackend::None => {}
        }

        if dns_v6_changed {
            if let Err(err) = state.save_to_path(state_path) {
                warn!(
                    path = %state_path.display(),
                    error = %err,
                    "failed to persist updated Linux TUN state after uplink transition"
                );
            }
        }
    }

    fn is_systemd_resolved_active() -> bool {
        let Some(resolvectl) = resolve_trusted_bin("resolvectl") else {
            return false;
        };
        let resolv_path = Path::new(RESOLV_CONF_PATH);
        let symlink_target = read_symlink_target_if_link(resolv_path);
        let contents = fs::read_to_string(resolv_path).ok();
        let nsswitch_contents = fs::read_to_string(NSSWITCH_CONF_PATH).ok();
        if !resolv_conf_uses_systemd_resolved(
            symlink_target.as_deref(),
            contents.as_deref(),
            nsswitch_contents.as_deref(),
        ) {
            return false;
        }
        Command::new(resolvectl)
            .arg("status")
            .output()
            .is_ok_and(|out| out.status.success())
    }

    fn is_resolvectl_iface_race(detail: &str) -> bool {
        let lower = detail.to_ascii_lowercase();
        lower.contains("unknown interface")
            || lower.contains("not known")
            || lower.contains("no such device")
            || lower.contains("failed to resolve interface")
            || lower.contains("link not found")
    }

    fn configure_systemd_resolved_dns(
        iface: &str,
        dns_v4: &str,
        dns_v6: Option<&str>,
    ) -> Result<()> {
        let resolvectl = require_trusted_bin("resolvectl")?;
        let mut dns_args = vec!["dns", iface, dns_v4];
        if let Some(v6) = dns_v6 {
            dns_args.push(v6);
        }

        for attempt in 0..=RESOLVECTL_DNS_MAX_RETRIES {
            match run_cmd_path(&resolvectl, &dns_args) {
                Ok(()) => break,
                Err(err)
                    if attempt < RESOLVECTL_DNS_MAX_RETRIES
                        && is_resolvectl_iface_race(&err.to_string()) =>
                {
                    debug!(
                        iface = %iface,
                        attempt = attempt + 1,
                        error = %err,
                        "systemd-resolved has not indexed TUN interface yet; retrying resolvectl dns"
                    );
                    std::thread::sleep(RESOLVECTL_DNS_BACKOFF);
                }
                Err(err) => return Err(err),
            }
        }

        run_cmd_path(&resolvectl, &["domain", iface, "~."])?;
        run_cmd_path(&resolvectl, &["default-route", iface, "true"])?;
        if let Err(err) = run_cmd_path(&resolvectl, &["dnssec", iface, "no"]) {
            warn!(
                iface = %iface,
                error = %err,
                "optional `resolvectl dnssec no` failed; continuing"
            );
        }
        if let Err(err) = run_cmd_path(&resolvectl, &["dnsovertls", iface, "no"]) {
            warn!(
                iface = %iface,
                error = %err,
                "optional `resolvectl dnsovertls no` failed; continuing"
            );
        }
        let _ = Command::new(&resolvectl).arg("flush-caches").output();
        Ok(())
    }

    fn is_network_manager_dns_active() -> bool {
        let Some(nmcli) = resolve_trusted_bin("nmcli") else {
            return false;
        };
        let running = Command::new(nmcli)
            .args(["-t", "-f", "RUNNING", "general", "status"])
            .output()
            .is_ok_and(|out| {
                out.status.success()
                    && String::from_utf8_lossy(&out.stdout)
                        .trim()
                        .eq_ignore_ascii_case("running")
            });
        if !running {
            return false;
        }
        // Skip NetworkManager DNS drop-in when NM is configured with `dns=none`
        // or `rc-manager=unmanaged`.
        let nm_dns_disabled = resolve_trusted_bin("NetworkManager").is_some_and(|nm_bin| {
            Command::new(nm_bin)
                .arg("--print-config")
                .output()
                .is_ok_and(|out| {
                    out.status.success()
                        && nm_config_disables_dns_management(&String::from_utf8_lossy(&out.stdout))
                })
        });
        !nm_dns_disabled
    }

    fn configure_network_manager_dns(dns_v4: &str, dns_v6: Option<&str>) -> Result<()> {
        let conf = render_nm_dns_conf(dns_v4, dns_v6);
        write_file_atomic(Path::new(NM_DNS_CONF_PATH), &conf, 0o644)
            .context("failed to write NetworkManager DNS drop-in")?;
        reload_network_manager_dns()
    }

    fn reload_network_manager_dns() -> Result<()> {
        if let Some(nmcli) = resolve_trusted_bin("nmcli") {
            let ok = Command::new(nmcli)
                .args(["general", "reload"])
                .output()
                .is_ok_and(|out| out.status.success());
            if ok {
                return Ok(());
            }
        }
        if let Some(systemctl) = resolve_trusted_bin("systemctl") {
            let ok = Command::new(systemctl)
                .args(["reload", "NetworkManager"])
                .output()
                .is_ok_and(|out| out.status.success());
            if ok {
                return Ok(());
            }
        }
        bail!("failed to reload NetworkManager after updating DNS configuration")
    }

    fn cleanup_linux_dns(
        iface: &str,
        state: Option<&LinuxTunState>,
        cleanup_errors: &mut Vec<String>,
    ) {
        let try_resolved = match state {
            Some(s) => s.dns_backend == LinuxDnsBackend::SystemdResolved,
            None => true,
        };
        if let Some(resolvectl) = try_resolved
            .then(|| resolve_trusted_bin("resolvectl"))
            .flatten()
        {
            let _ = Command::new(&resolvectl).args(["revert", iface]).output();
            let _ = Command::new(&resolvectl).arg("flush-caches").output();
        }

        let nm_path = match state.and_then(|s| s.nm_conf_path.as_deref()) {
            Some(candidate) if is_valid_state_nm_conf_path(candidate) => candidate,
            Some(invalid) => {
                warn!(
                    path = %invalid,
                    "ignoring unexpected nm_conf_path in Linux TUN state"
                );
                NM_DNS_CONF_PATH
            }
            None => NM_DNS_CONF_PATH,
        };
        match fs::remove_file(nm_path) {
            Ok(()) => {
                if let Err(err) = reload_network_manager_dns() {
                    warn!(error = %err, "failed to reload NetworkManager during DNS cleanup");
                    cleanup_errors.push(format!("{err:#}"));
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(path = %nm_path, error = %err, "failed to remove NetworkManager DNS drop-in");
                cleanup_errors.push(format!("failed to remove {nm_path}: {err}"));
            }
        }

        let backup_path = match state.and_then(|s| s.resolv_backup_path.as_deref()) {
            Some(candidate) if is_valid_state_resolv_backup_path(candidate) => candidate,
            Some(invalid) => {
                warn!(
                    path = %invalid,
                    "ignoring unexpected resolv_backup_path in Linux TUN state"
                );
                RESOLV_CONF_BACKUP_PATH
            }
            None => RESOLV_CONF_BACKUP_PATH,
        };
        let state_symlink_target = match state.and_then(|s| s.resolv_symlink_target.as_deref()) {
            Some(candidate) if is_valid_resolv_symlink_target(candidate) => Some(candidate),
            Some(invalid) => {
                warn!(
                    target = %invalid,
                    "ignoring invalid resolv_symlink_target in Linux TUN state"
                );
                None
            }
            None => None,
        };
        let meta_path = Path::new(RESOLV_CONF_META_PATH);
        let meta_symlink_target = match ResolvBackupMeta::load_from_path(meta_path) {
            Ok(Some(meta)) => match meta.symlink_target {
                Some(candidate) if is_valid_resolv_symlink_target(&candidate) => Some(candidate),
                Some(invalid) => {
                    warn!(
                        path = RESOLV_CONF_META_PATH,
                        target = %invalid,
                        "ignoring invalid symlink_target in persistent resolv metadata"
                    );
                    None
                }
                None => None,
            },
            Ok(None) => None,
            Err(err) => {
                warn!(
                    path = RESOLV_CONF_META_PATH,
                    error = %err,
                    "failed to load persistent resolv metadata"
                );
                if err
                    .downcast_ref::<io::Error>()
                    .is_some_and(|io_err| io_err.kind() == io::ErrorKind::PermissionDenied)
                {
                    cleanup_errors.push(format!("{err:#}"));
                }
                None
            }
        };
        let effective_symlink_target = meta_symlink_target.as_deref().or(state_symlink_target);

        match restore_resolv_conf_at(
            Path::new(RESOLV_CONF_PATH),
            Path::new(backup_path),
            effective_symlink_target,
        ) {
            Ok(_) => {
                if let Err(err) = remove_file_if_exists(meta_path) {
                    warn!(
                        path = RESOLV_CONF_META_PATH,
                        error = %err,
                        "failed to remove persistent resolv metadata"
                    );
                    cleanup_errors.push(format!("{err:#}"));
                }
            }
            Err(err) => {
                warn!(error = %err, "failed to restore /etc/resolv.conf during Linux TUN cleanup");
                cleanup_errors.push(format!("{err:#}"));
            }
        }
    }

    fn is_executable_file(path: &Path) -> bool {
        fs::metadata(path)
            .is_ok_and(|meta| meta.is_file() && (meta.permissions().mode() & 0o111) != 0)
    }

    fn resolve_trusted_bin(name: &str) -> Option<PathBuf> {
        if name.is_empty() || name.contains('/') || name.contains('\0') {
            return None;
        }
        for prefix in TRUSTED_BIN_PREFIXES {
            let candidate = Path::new(prefix).join(name);
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    fn require_trusted_bin(name: &str) -> Result<PathBuf> {
        resolve_trusted_bin(name).ok_or_else(|| {
            anyhow!(
                "required system binary '{name}' was not found in trusted paths ({})",
                TRUSTED_BIN_PREFIXES.join(", ")
            )
        })
    }

    fn is_benign_ip_cleanup_error(ipv6: bool, detail: &str) -> bool {
        let lower = detail.to_ascii_lowercase();
        if lower.contains("no such file or directory")
            || lower.contains("cannot find device")
            || lower.contains("no such device")
            || lower.contains("does not exist")
        {
            return true;
        }
        ipv6 && (lower.contains("address family not supported")
            || lower.contains("operation not supported")
            || lower.contains("protocol not supported"))
    }

    fn run_ip(args: &[&str]) -> Result<()> {
        let ip_bin = require_trusted_bin("ip")?;
        run_cmd_path(&ip_bin, args)
    }

    fn run_ip_cleanup(ip_bin: &Path, args: &[&str], ipv6: bool) -> Result<bool> {
        let output = Command::new(ip_bin).args(args).output().with_context(|| {
            format!(
                "failed to execute `{} {}`",
                ip_bin.display(),
                args.join(" ")
            )
        })?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        if is_benign_ip_cleanup_error(ipv6, &detail) {
            return Ok(false);
        }
        bail!(
            "`{} {}` exited with {}: {detail}",
            ip_bin.display(),
            args.join(" "),
            output.status
        );
    }

    fn run_cmd_path(program: &Path, args: &[&str]) -> Result<()> {
        let output = Command::new(program).args(args).output().with_context(|| {
            format!(
                "failed to execute `{} {}`",
                program.display(),
                args.join(" ")
            )
        })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            bail!(
                "`{} {}` exited with {}: {detail}",
                program.display(),
                args.join(" "),
                output.status
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use imp::{cleanup_linux_tun_state, open_tun_device, LinuxTunSession};

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_test_dir(label: &str) -> PathBuf {
        static DIR_SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vdpi-linux-tun-test-{label}-{}-{}",
            std::process::id(),
            DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create test temp dir");
        dir
    }

    #[test]
    fn policy_rule_specs_sit_below_tailscale_and_preserve_lan_and_docker() {
        // Tailscale policy rules occupy 5210..=5270; vdpi sits cleanly below at 5480..=5500.
        const TAILSCALE_MAX_PRIO: u32 = 5270;
        const MAIN_DEFAULT_PRIO: u32 = 32766;

        const {
            assert!(TAILSCALE_MAX_PRIO < PRIO_VDPI_MARK);
            assert!(PRIO_VDPI_MARK < PRIO_VDPI_MARK_GUARD);
            assert!(PRIO_VDPI_MARK_GUARD < PRIO_SUPPRESS_MAIN);
            assert!(PRIO_SUPPRESS_MAIN < PRIO_VDPI_TABLE);
            assert!(PRIO_VDPI_TABLE < MAIN_DEFAULT_PRIO);
        }

        let v4_only = build_policy_rules(VDPI_SO_MARK, VDPI_ROUTE_TABLE, false);
        assert_eq!(v4_only.len(), 4);
        assert!(v4_only.iter().all(|r| !r.ipv6));
        assert_eq!(
            v4_only[0].args,
            vec![
                "priority",
                "5480",
                "fwmark",
                "0x5644/0xffff",
                "lookup",
                "main"
            ]
        );
        assert_eq!(
            v4_only[1].args,
            vec!["priority", "5485", "fwmark", "0x5644/0xffff", "unreachable"]
        );
        assert_eq!(
            v4_only[2].args,
            vec![
                "priority",
                "5490",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0"
            ]
        );
        assert_eq!(
            v4_only[3].args,
            vec!["priority", "5500", "iif", "lo", "lookup", "202"]
        );
        assert!(
            !v4_only[3].args.iter().any(|a| a == "not"),
            "iif lo rule must not combine FIB_RULE_INVERT (`not`), which would invert iif lo"
        );

        let dual_stack = build_policy_rules(VDPI_SO_MARK, VDPI_ROUTE_TABLE, true);
        assert_eq!(dual_stack.len(), 8);
        assert_eq!(dual_stack.iter().filter(|r| !r.ipv6).count(), 4);
        assert_eq!(dual_stack.iter().filter(|r| r.ipv6).count(), 4);
        for (v4, v6) in dual_stack[..4].iter().zip(&dual_stack[4..]) {
            assert_eq!(v4.priority, v6.priority);
            assert_eq!(v4.args, v6.args);
        }
    }

    #[test]
    fn linux_tun_state_serde_roundtrip_and_file_persistence() {
        let dir = unique_test_dir("state");
        let path = dir.join("tun-state.json");

        assert_eq!(LinuxTunState::load_from_path(&path).unwrap(), None);

        let state = LinuxTunState {
            iface: LINUX_TUN_IFACE.to_string(),
            route_table: VDPI_ROUTE_TABLE,
            fwmark: VDPI_SO_MARK,
            ipv6_enabled: true,
            dns_backend: LinuxDnsBackend::ResolvConf,
            nm_conf_path: None,
            resolv_backup_path: Some(RESOLV_CONF_BACKUP_PATH.to_string()),
            resolv_symlink_target: Some("/run/systemd/resolve/stub-resolv.conf".to_string()),
            prev_all_rp_filter: Some(1),
            pid: 4242,
        };

        let raw = state.to_json_pretty().unwrap();
        assert!(raw.contains("\"dns_backend\": \"resolv-conf\""));
        assert!(raw.contains("\"prev_all_rp_filter\": 1"));
        assert!(!raw.contains("nm_conf_path"));
        assert_eq!(LinuxTunState::from_json_str(&raw).unwrap(), state);

        state.save_to_path(&path).unwrap();
        let loaded = LinuxTunState::load_from_path(&path).unwrap();
        assert_eq!(loaded, Some(state));

        let nm_state = LinuxTunState {
            iface: LINUX_TUN_IFACE.to_string(),
            route_table: VDPI_ROUTE_TABLE,
            fwmark: VDPI_SO_MARK,
            ipv6_enabled: false,
            dns_backend: LinuxDnsBackend::NetworkManager,
            nm_conf_path: Some(NM_DNS_CONF_PATH.to_string()),
            resolv_backup_path: None,
            resolv_symlink_target: None,
            prev_all_rp_filter: None,
            pid: 777,
        };
        let nm_raw = nm_state.to_json_pretty().unwrap();
        assert!(!nm_raw.contains("prev_all_rp_filter"));
        assert_eq!(LinuxTunState::from_json_str(&nm_raw).unwrap(), nm_state);

        // Legacy JSON missing `prev_all_rp_filter` must deserialize cleanly via #[serde(default)].
        let legacy_json = r#"{
            "iface": "vdpi0",
            "route_table": 202,
            "fwmark": 22084,
            "ipv6_enabled": false,
            "dns_backend": "none",
            "pid": 123
        }"#;
        let legacy = LinuxTunState::from_json_str(legacy_json).unwrap();
        assert_eq!(legacy.prev_all_rp_filter, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolv_conf_marker_guard_handles_backup_restart_restore_and_external_edits() {
        let dir = unique_test_dir("resolv");
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.orig");

        let original = "# ISP DHCP\nnameserver 192.168.1.1\nsearch lan\n";
        fs::write(&resolv, original).unwrap();
        assert!(!is_vdpi_managed_resolv_conf(original));

        // First install backs up the original file and writes the marker-guarded config.
        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, Some(LINUX_TUN_DNS_V6)).unwrap();
        let managed = fs::read_to_string(&resolv).unwrap();
        assert!(is_vdpi_managed_resolv_conf(&managed));
        assert!(managed.contains("nameserver 198.18.0.2\n"));
        assert!(managed.contains("nameserver fd00:7664:7069::2\n"));
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        // Second install (crash + restart) must NOT clobber the original backup with vdpi's file.
        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap();
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        // Clean restore brings back the exact original file and deletes the backup.
        let outcome = restore_resolv_conf_at(&resolv, &backup, None).unwrap();
        assert_eq!(outcome, ResolvRestoreOutcome::RestoredFromBackup);
        assert_eq!(fs::read_to_string(&resolv).unwrap(), original);
        assert!(!backup.exists());

        // If an external daemon or user overwrites resolv.conf (marker gone), restore must NOT clobber it.
        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap();
        let external = "# Written by dhclient\nnameserver 9.9.9.9\n";
        fs::write(&resolv, external).unwrap();
        let outcome = restore_resolv_conf_at(&resolv, &backup, None).unwrap();
        assert_eq!(outcome, ResolvRestoreOutcome::SkippedExternallyModified);
        assert_eq!(fs::read_to_string(&resolv).unwrap(), external);
        assert!(!backup.exists());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn renders_nm_dns_conf_and_validates_iface_names() {
        let v4_conf = render_nm_dns_conf(LINUX_TUN_DNS_V4, None);
        assert!(v4_conf.starts_with(RESOLV_CONF_MARKER));
        assert!(v4_conf.contains("[global-dns-domain-*]\nservers=198.18.0.2\n"));

        let dual_conf = render_nm_dns_conf(LINUX_TUN_DNS_V4, Some(LINUX_TUN_DNS_V6));
        assert!(dual_conf.contains("servers=198.18.0.2,fd00:7664:7069::2\n"));

        assert!(validate_tun_iface_name(LINUX_TUN_IFACE).is_ok());
        assert!(validate_tun_iface_name("").is_err());
        assert!(validate_tun_iface_name("1234567890123456").is_err());
        assert!(validate_tun_iface_name("vdpi 0").is_err());
        assert!(validate_tun_iface_name("vdpi/0").is_err());
        assert!(validate_tun_iface_name(".").is_err());
        assert!(validate_tun_iface_name("..").is_err());
        assert!(validate_tun_iface_name("-vdpi0").is_err());
        assert!(validate_tun_iface_name("vdpi%d").is_err());
    }

    #[test]
    fn parses_physical_default_route_interface_skipping_tun() {
        let sample = "\
default dev vdpi0 scope link metric 50
default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.42 metric 600
";
        assert_eq!(
            parse_default_route_dev(sample, LINUX_TUN_IFACE).as_deref(),
            Some("wlan0")
        );
        assert_eq!(
            parse_default_route_dev("default dev vdpi0 scope link\n", LINUX_TUN_IFACE),
            None
        );

        let ipv6_sample = "\
default dev vdpi0 metric 1024 pref medium
default via fe80::1 dev eth0 proto ra metric 100 pref medium
";
        assert_eq!(
            parse_default_route_dev(ipv6_sample, LINUX_TUN_IFACE).as_deref(),
            Some("eth0")
        );
    }

    #[test]
    fn detects_systemd_resolved_and_nm_dns_disable_configs() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        assert_eq!(LINUX_TUN_MTU, vdpi_tun::config::DESKTOP_MTU as u16);
        assert_eq!(LINUX_TUN_TXQUEUELEN, 4096);
        assert_eq!(LINUX_TUN_TXQUEUELEN_LADDER, [4096, 2000, 1000]);

        assert!(resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/stub-resolv.conf"),
            None,
            None
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            Some("../run/systemd/resolve/stub-resolv.conf"),
            None,
            None
        ));
        // Non-stub `/run/systemd/resolve/resolv.conf` without nsswitch `resolve` returns false.
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            None,
            None
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("../run/systemd/resolve/resolv.conf"),
            None,
            None
        ));
        // Arch/Fedora non-stub `/run/systemd/resolve/resolv.conf` WITH active nsswitch `resolve`.
        assert!(resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            Some("nameserver 1.1.1.1\n"),
            Some("hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n")
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            None,
            Some("hosts: files myhostname mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns\n")
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            None,
            Some("# hosts: files resolve [!UNAVAIL=return] dns\nhosts: files dns\n")
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            None,
            Some("hosts: files dns resolve\n")
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            None,
            Some("# generated\nnameserver 127.0.0.53\noptions edns0\n"),
            None
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            None,
            Some("nameserver 127.0.0.54\n"),
            None
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            None,
            Some("# nameserver 127.0.0.53\nnameserver 1.1.1.1\n"),
            None
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/var/run/NetworkManager/resolv.conf"),
            Some("nameserver 192.168.1.1\n"),
            None
        ));

        assert!(nm_config_disables_dns_management("[main]\ndns=none\n"));
        assert!(nm_config_disables_dns_management(
            "[main]\nrc-manager=unmanaged\n"
        ));
        assert!(nm_config_disables_dns_management(
            "[main]\nrc-manager = unmanaged\n"
        ));
        assert!(!nm_config_disables_dns_management(
            "[main]\n# dns=none\n# rc-manager=unmanaged\ndns=default\nrc-manager=symlink\n"
        ));
    }

    #[test]
    fn validates_persisted_state_paths() {
        assert!(is_valid_state_nm_conf_path(NM_DNS_CONF_PATH));
        assert!(!is_valid_state_nm_conf_path("/etc/passwd"));

        assert!(is_valid_state_resolv_backup_path(RESOLV_CONF_BACKUP_PATH));
        assert!(is_valid_state_resolv_backup_path(
            LEGACY_RESOLV_CONF_BACKUP_PATH
        ));
        assert!(!is_valid_state_resolv_backup_path("/etc/shadow"));

        assert!(is_valid_resolv_symlink_target(
            "/run/systemd/resolve/stub-resolv.conf"
        ));
        assert!(is_valid_resolv_symlink_target(
            "../run/systemd/resolve/stub-resolv.conf"
        ));
        assert!(!is_valid_resolv_symlink_target(""));
        assert!(!is_valid_resolv_symlink_target("/etc/foo\nbar"));
        assert!(!is_valid_resolv_symlink_target("relative.conf"));
    }

    #[test]
    fn persistent_resolv_backup_and_meta_survive_reboot_without_runtime_state() {
        let dir = unique_test_dir("resolv-persist");
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.orig");
        let meta = dir.join("resolv-meta.json");

        let original = "nameserver 192.168.10.1\n";
        fs::write(&resolv, original).unwrap();

        let sym = prepare_resolv_conf_backup(&resolv, &backup, &meta).unwrap();
        assert_eq!(sym, None);
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert!(!meta.exists());

        let managed = render_resolv_conf(LINUX_TUN_DNS_V4, None);
        write_file_atomic(&resolv, &managed, 0o644).unwrap();

        // Simulate reboot: runtime state is gone (fallback_symlink_target = None).
        let outcome = restore_resolv_conf_with_meta(&resolv, &backup, &meta, None).unwrap();
        assert_eq!(outcome, ResolvRestoreOutcome::RestoredFromBackup);
        assert_eq!(fs::read_to_string(&resolv).unwrap(), original);
        assert!(!backup.exists());
        assert!(!meta.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let upstream = dir.join("stub-resolv.conf");
            fs::write(&upstream, "nameserver 127.0.0.53\n").unwrap();
            fs::remove_file(&resolv).unwrap();
            symlink(&upstream, &resolv).unwrap();

            let first_target = prepare_resolv_conf_backup(&resolv, &backup, &meta).unwrap();
            assert_eq!(first_target.as_deref(), upstream.to_str());
            assert!(meta.exists());

            // Overwrite resolv.conf with managed regular file.
            write_file_atomic(&resolv, &managed, 0o644).unwrap();

            // Second prepare while managed must NOT clobber saved symlink target.
            let second_target = prepare_resolv_conf_backup(&resolv, &backup, &meta).unwrap();
            assert_eq!(second_target.as_deref(), upstream.to_str());

            // Restore with no runtime state recovers the original symlink from persistent meta.
            let outcome = restore_resolv_conf_with_meta(&resolv, &backup, &meta, None).unwrap();
            assert_eq!(outcome, ResolvRestoreOutcome::RestoredSymlink);
            assert_eq!(fs::read_link(&resolv).unwrap(), upstream);
            assert!(!backup.exists());
            assert!(!meta.exists());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_default_route_dev_filters_linkdown_loopback_and_virtual_bridges() {
        let filtered_then_physical = "\
default via 192.168.1.1 dev eth0 proto dhcp metric 100 linkdown
default dev lo scope link metric 10
default via 172.17.0.1 dev docker0 proto static metric 20
default via 172.18.0.1 dev docker_gwbridge metric 30
default via 192.168.122.1 dev virbr0 metric 40
default via 172.20.0.1 dev br-a1b2c3d4e5f6 metric 50
default via 10.200.0.1 dev veth9f8e7d6 metric 60
default dev vdpi0 scope link metric 70
default via 192.168.1.1 dev wlp2s0 proto dhcp src 192.168.1.55 metric 600
";
        assert_eq!(
            parse_default_route_dev(filtered_then_physical, LINUX_TUN_IFACE).as_deref(),
            Some("wlp2s0")
        );

        let only_non_uplink = "\
default via fe80::1 dev eth0 proto ra metric 100 pref medium linkdown
default dev lo metric 10
default dev docker0 metric 20
default dev virbr0 metric 30
default dev br-deadbeef metric 40
default dev veth1234 metric 50
default dev vdpi0 metric 60
";
        assert_eq!(
            parse_default_route_dev(only_non_uplink, LINUX_TUN_IFACE),
            None
        );

        // Regular host bridge (e.g. `br0`) is not a Docker `br-*` bridge and remains eligible.
        let host_bridge = "default via 10.0.0.1 dev br0 proto static metric 100\n";
        assert_eq!(
            parse_default_route_dev(host_bridge, LINUX_TUN_IFACE).as_deref(),
            Some("br0")
        );
    }

    #[test]
    fn parses_cap_net_admin_from_proc_self_status_cap_eff() {
        assert_eq!(CAP_NET_ADMIN_BIT, 12);
        assert_eq!(CAP_NET_ADMIN_MASK, 0x1000);

        let exact_cap = "\
Name:\tvdpi
Uid:\t1000\t1000\t1000\t1000
CapInh:\t0000000000000000
CapPrm:\t0000000000001000
CapEff:\t0000000000001000
CapBnd:\t000001ffffffffff
CapAmb:\t0000000000001000
";
        assert!(proc_status_has_cap_net_admin(exact_cap));

        let root_caps = "CapEff:\t000001ffffffffff\n";
        assert!(proc_status_has_cap_net_admin(root_caps));

        // Permitted/ambient only (not effective) must NOT pass.
        let permitted_only = "\
CapPrm:\t0000000000001000
CapEff:\t0000000000000000
CapAmb:\t0000000000001000
";
        assert!(!proc_status_has_cap_net_admin(permitted_only));

        // Adjacent bits set (0..=11 and 13) without bit 12 must NOT pass.
        assert!(!proc_status_has_cap_net_admin("CapEff:\t0000000000002fff\n"));
        assert!(!proc_status_has_cap_net_admin("CapEff:\t0000000000000000\n"));
        assert!(!proc_status_has_cap_net_admin("CapEff:\tnot_hex\n"));
        assert!(!proc_status_has_cap_net_admin("Name:\tvdpi\n"));

        // Future >64-bit capability mask still checks low 64 bits cleanly.
        assert!(proc_status_has_cap_net_admin(
            "CapEff:\t000000010000000000001000\n"
        ));
        assert!(!proc_status_has_cap_net_admin(
            "CapEff:\t000000010000000000000000\n"
        ));
    }

    #[test]
    fn resolv_conf_preserves_search_domain_options_and_detects_non_stub_nss_resolve_leak() {
        // Non-stub `/run/systemd/resolve/resolv.conf` with active `nss-resolve` MUST also
        // override `/etc/resolv.conf` so Go/musl/Chromium/Flatpak/Snap do not leak DNS.
        let nss_resolve = "hosts: mymachines resolve [!UNAVAIL=return] files myhostname dns\n";
        assert!(needs_resolv_conf_override_with_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            Some("nameserver 192.168.1.1\nsearch corp.local\n"),
            Some(nss_resolve)
        ));
        // Mixed stub + ISP fallback also needs `/etc/resolv.conf` override.
        assert!(needs_resolv_conf_override_with_systemd_resolved(
            None,
            Some("nameserver 127.0.0.53\nnameserver 192.168.1.1\n"),
            Some(nss_resolve)
        ));
        // Pure stub listener (`127.0.0.53`) does NOT need `/etc/resolv.conf` override.
        assert!(!needs_resolv_conf_override_with_systemd_resolved(
            Some("/run/systemd/resolve/stub-resolv.conf"),
            Some("nameserver 127.0.0.53\noptions edns0 trust-ad\n"),
            Some(nss_resolve)
        ));
        // Without `resolve` before `dns`, nss-resolve override does not apply.
        assert!(!needs_resolv_conf_override_with_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            Some("nameserver 192.168.1.1\n"),
            Some("hosts: files dns\n")
        ));

        // Preserves `search`, `domain`, and custom `options` while stripping ISP nameservers.
        let orig = "\
# Generated by NetworkManager
nameserver 192.168.1.1
nameserver 8.8.8.8
search corp.example.com home.arpa # office domains
domain corp.example.com
options ndots:2 timeout:3 ; custom resolver tuning
# search commented.example
";
        let rendered =
            render_resolv_conf_preserving(LINUX_TUN_DNS_V4, Some(LINUX_TUN_DNS_V6), Some(orig));
        assert!(rendered.starts_with(RESOLV_CONF_MARKER));
        assert!(rendered.contains("nameserver 198.18.0.2\n"));
        assert!(rendered.contains("nameserver fd00:7664:7069::2\n"));
        assert!(!rendered.contains("192.168.1.1"));
        assert!(!rendered.contains("8.8.8.8"));
        assert!(rendered.contains("search corp.example.com home.arpa\n"));
        assert!(rendered.contains("domain corp.example.com\n"));
        assert!(rendered.contains("options ndots:2 timeout:3\n"));
        assert!(rendered.contains("options edns0\n"));
        assert!(!rendered.contains("commented.example"));

        // When original already includes `edns0`, do not append a duplicate `options edns0` line.
        let orig_with_edns0 = "nameserver 1.1.1.1\nsearch lan\noptions edns0 trust-ad\n";
        let rendered_edns0 =
            render_resolv_conf_preserving(LINUX_TUN_DNS_V4, None, Some(orig_with_edns0));
        assert!(rendered_edns0.contains("search lan\n"));
        assert_eq!(rendered_edns0.matches("options ").count(), 1);
        assert!(rendered_edns0.contains("options edns0 trust-ad\n"));

        // End-to-end file install preserves search/domain across initial install and restart.
        let dir = unique_test_dir("resolv-search-preserve");
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.orig");
        fs::write(&resolv, orig).unwrap();

        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap();
        let first_managed = fs::read_to_string(&resolv).unwrap();
        assert!(first_managed.contains("search corp.example.com home.arpa\n"));
        assert!(first_managed.contains("domain corp.example.com\n"));
        assert!(first_managed.contains("options ndots:2 timeout:3\n"));

        // Re-install while already managed still preserves search/domain from the backup file.
        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, Some(LINUX_TUN_DNS_V6)).unwrap();
        let second_managed = fs::read_to_string(&resolv).unwrap();
        assert!(second_managed.contains("search corp.example.com home.arpa\n"));
        assert!(second_managed.contains("domain corp.example.com\n"));
        assert!(second_managed.contains("nameserver fd00:7664:7069::2\n"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_monitor_line_filters_docker_vm_veth_tun_and_loopback() {
        // Blank / whitespace lines are ignored.
        assert!(!is_relevant_route_monitor_line("", LINUX_TUN_IFACE));
        assert!(!is_relevant_route_monitor_line("   \t  ", LINUX_TUN_IFACE));

        // Own TUN interface and loopback routes are ignored.
        assert!(!is_relevant_route_monitor_line(
            "default dev vdpi0 table 202 scope link",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "Deleted 198.18.0.0/30 dev vdpi0 proto kernel scope link src 198.18.0.1",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "local 127.0.0.1 dev lo table local proto kernel scope host src 127.0.0.1",
            LINUX_TUN_IFACE
        ));

        // Container / VM churn (`docker*`, `virbr*`, `br-*`, `veth*`) must be ignored so it
        // never triggers UDP Cone-NAT drains or spurious handoffs.
        assert!(!is_relevant_route_monitor_line(
            "172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "Deleted 172.18.0.0/16 dev docker_gwbridge proto kernel scope link src 172.18.0.1",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "192.168.122.0/24 dev virbr0 proto kernel scope link src 192.168.122.1",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "Deleted 192.168.122.0/24 dev virbr1-nic proto kernel scope link",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "172.20.0.0/16 dev br-a1b2c3d4e5f6 proto kernel scope link src 172.20.0.1",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "fe80::/64 dev veth9f8e7d6 proto kernel metric 256 pref medium",
            LINUX_TUN_IFACE
        ));
        assert!(!is_relevant_route_monitor_line(
            "Deleted fe80::/64 dev veth1234@if2 proto kernel metric 256 pref medium",
            LINUX_TUN_IFACE
        ));

        // Physical uplinks, host bridges (`br0`), and `dev`-less default route events remain relevant.
        assert!(is_relevant_route_monitor_line(
            "default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.42 metric 600",
            LINUX_TUN_IFACE
        ));
        assert!(is_relevant_route_monitor_line(
            "Deleted default via 192.168.1.1 dev eth0 proto dhcp metric 100",
            LINUX_TUN_IFACE
        ));
        assert!(is_relevant_route_monitor_line(
            "default via fe80::1 dev enp3s0 proto ra metric 100 pref medium",
            LINUX_TUN_IFACE
        ));
        assert!(is_relevant_route_monitor_line(
            "default via 10.0.0.1 dev br0 proto static metric 100",
            LINUX_TUN_IFACE
        ));
        assert!(is_relevant_route_monitor_line(
            "Deleted default via 192.168.1.1",
            LINUX_TUN_IFACE
        ));
    }

    #[test]
    fn ipv6_only_host_skips_ipv4_default_route_and_policy_rules() {
        // Pure IPv6-only host (`!has_ipv4_uplink && include_ipv6`) skips `-4` default route & rules.
        assert!(!should_install_ipv4_routing(false, true));
        // Dual-stack, IPv4-only, and offline-startup cases keep IPv4 routing enabled.
        assert!(should_install_ipv4_routing(true, true));
        assert!(should_install_ipv4_routing(true, false));
        assert!(should_install_ipv4_routing(false, false));

        // On an IPv6-only host, policy rule generation emits ONLY `-6` rules and zero `-4` rules.
        let ipv6_only_rules = build_policy_rules_for_families(
            VDPI_SO_MARK,
            VDPI_ROUTE_TABLE,
            should_install_ipv4_routing(false, true),
            true,
        );
        assert_eq!(ipv6_only_rules.len(), 4);
        assert!(ipv6_only_rules.iter().all(|rule| rule.ipv6));
        assert_eq!(
            ipv6_only_rules
                .iter()
                .map(|rule| rule.priority)
                .collect::<Vec<_>>(),
            VDPI_RULE_PRIORITIES.to_vec()
        );
        assert_eq!(
            ipv6_only_rules[3].args,
            vec!["priority", "5500", "iif", "lo", "lookup", "202"]
        );

        let dual_stack_rules = build_policy_rules_for_families(
            VDPI_SO_MARK,
            VDPI_ROUTE_TABLE,
            should_install_ipv4_routing(true, true),
            true,
        );
        assert_eq!(dual_stack_rules.len(), 8);
        assert_eq!(dual_stack_rules.iter().filter(|r| !r.ipv6).count(), 4);
        assert_eq!(dual_stack_rules.iter().filter(|r| r.ipv6).count(), 4);

        assert!(build_policy_rules_for_families(VDPI_SO_MARK, VDPI_ROUTE_TABLE, false, false).is_empty());
    }

    #[test]
    fn fallback_user_runtime_dir_prefers_xdg_runtime_dir_else_tmp_uid() {
        assert_eq!(
            fallback_user_runtime_dir(Some("/run/user/1000"), 1000),
            PathBuf::from("/run/user/1000/vdpi")
        );
        assert_eq!(
            fallback_user_runtime_dir(Some("/run/user/1000/"), 1000),
            PathBuf::from("/run/user/1000/vdpi")
        );
        assert_eq!(
            fallback_user_runtime_dir(None, 1000),
            PathBuf::from("/tmp/vdpi-run-1000")
        );
        assert_eq!(
            fallback_user_runtime_dir(Some(""), 1001),
            PathBuf::from("/tmp/vdpi-run-1001")
        );
        assert_eq!(
            fallback_user_runtime_dir(Some("   "), 1001),
            PathBuf::from("/tmp/vdpi-run-1001")
        );
        assert_eq!(
            fallback_user_runtime_dir(Some("relative/runtime"), 1001),
            PathBuf::from("/tmp/vdpi-run-1001")
        );
        assert_eq!(
            fallback_user_runtime_dir(Some("/"), 1001),
            PathBuf::from("/tmp/vdpi-run-1001")
        );
    }

    #[test]
    fn uplink_signature_change_only_gating_suppresses_ra_refresh_and_unchanged_churn() {
        let dual_wlan =
            LinuxUplinkSignature::from_nics(Some("wlan0".into()), Some("wlan0".into()));
        assert_eq!(dual_wlan.as_tuple(), (true, Some("wlan0"), true, Some("wlan0")));
        assert_eq!(dual_wlan.preferred_nic(), Some("wlan0"));

        let v6_only_wwan = LinuxUplinkSignature::from_nics(None, Some("wwan0".into()));
        assert_eq!(v6_only_wwan.as_tuple(), (false, None, true, Some("wwan0")));
        assert_eq!(v6_only_wwan.preferred_nic(), Some("wwan0"));

        let offline = LinuxUplinkSignature::from_nics(None, None);
        assert_eq!(offline.as_tuple(), (false, None, false, None));
        assert_eq!(offline.preferred_nic(), None);

        // Periodic IPv6 RA refresh / same-NIC DHCP renewal on dual-stack must NOT flush DNS
        // or emit `route_tx`, while still checking `/etc/resolv.conf` in case DHCP overwrote it.
        let ra_refresh = plan_uplink_transition(&dual_wlan, &dual_wlan, true, true, true);
        assert!(!ra_refresh.signature_changed);
        assert!(!ra_refresh.notify_route_change);
        assert!(!ra_refresh.dns_v6_changed);
        assert!(ra_refresh.reassert_resolv_conf);
        assert_eq!(ra_refresh.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(ra_refresh.ipv6_action, FamilyRoutingAction::Keep);

        // Even when IPv6 fell back to disabled at startup (e.g. kernel lacks
        // CONFIG_IPV6_MULTIPLE_TABLES), an unchanged RA refresh must stay a no-op.
        let ra_after_fallback = plan_uplink_transition(&dual_wlan, &dual_wlan, true, false, true);
        assert!(!ra_after_fallback.signature_changed);
        assert!(!ra_after_fallback.notify_route_change);
        assert_eq!(ra_after_fallback.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!ra_after_fallback.desired_ipv6_active);

        // Unchanged IPv6-only or offline signatures also suppress notifications.
        let v6_unchanged =
            plan_uplink_transition(&v6_only_wwan, &v6_only_wwan, false, true, false);
        assert!(!v6_unchanged.signature_changed);
        assert!(!v6_unchanged.notify_route_change);

        let offline_unchanged = plan_uplink_transition(&offline, &offline, true, false, true);
        assert!(!offline_unchanged.signature_changed);
        assert!(!offline_unchanged.notify_route_change);

        // Real NIC-to-NIC roam (`wlan0` -> `eth0`) MUST notify and re-assert `/etc/resolv.conf`.
        let v4_wlan = LinuxUplinkSignature::from_nics(Some("wlan0".into()), None);
        let v4_eth = LinuxUplinkSignature::from_nics(Some("eth0".into()), None);
        let nic_roam = plan_uplink_transition(&v4_wlan, &v4_eth, true, false, false);
        assert!(nic_roam.signature_changed);
        assert!(nic_roam.notify_route_change);
        assert!(nic_roam.reassert_resolv_conf);
        assert!(!nic_roam.dns_v6_changed);
        assert_eq!(nic_roam.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(nic_roam.ipv6_action, FamilyRoutingAction::Keep);

        // Changing only the IPv6 uplink NIC on a dual-stack host counts as a signature change.
        let split_nics =
            LinuxUplinkSignature::from_nics(Some("wlan0".into()), Some("eth0".into()));
        let v6_nic_change = plan_uplink_transition(&dual_wlan, &split_nics, true, true, true);
        assert!(v6_nic_change.signature_changed);
        assert!(v6_nic_change.notify_route_change);
    }

    #[test]
    fn dynamic_v4_v6_uplink_transition_planning_covers_all_roaming_modes() {
        let v4_only = LinuxUplinkSignature::from_nics(Some("wlan0".into()), None);
        let dual_stack =
            LinuxUplinkSignature::from_nics(Some("wlan0".into()), Some("wlan0".into()));
        let v6_only = LinuxUplinkSignature::from_nics(None, Some("wwan0".into()));
        let offline = LinuxUplinkSignature::from_nics(None, None);

        // 1. IPv4-only -> Dual-stack with `tun_ipv6 = true`: install IPv6, keep IPv4.
        let p = plan_uplink_transition(&v4_only, &dual_stack, true, false, true);
        assert!(p.signature_changed && p.notify_route_change && p.reassert_resolv_conf);
        assert!(p.desired_ipv4_active && p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Install);
        assert!(p.dns_v6_changed);

        // 2. IPv4-only -> Dual-stack with `tun_ipv6 = false`: keep IPv4-only routing, still notify.
        let p = plan_uplink_transition(&v4_only, &dual_stack, true, false, false);
        assert!(p.signature_changed && p.notify_route_change);
        assert!(p.desired_ipv4_active && !p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!p.dns_v6_changed);

        // 3. Dual-stack -> IPv4-only with `tun_ipv6 = true`: remove IPv6, keep IPv4.
        let p = plan_uplink_transition(&dual_stack, &v4_only, true, true, true);
        assert!(p.signature_changed && p.notify_route_change);
        assert!(p.desired_ipv4_active && !p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Remove);
        assert!(p.dns_v6_changed);

        // 4. IPv4-only -> IPv6-only with `tun_ipv6 = false`: auto-enable IPv6 and remove IPv4.
        let p = plan_uplink_transition(&v4_only, &v6_only, true, false, false);
        assert!(p.signature_changed && p.notify_route_change);
        assert!(!p.desired_ipv4_active && p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Remove);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Install);
        assert!(p.dns_v6_changed);

        // 5. IPv6-only -> IPv4-only with `tun_ipv6 = false`: install IPv4 and remove IPv6.
        let p = plan_uplink_transition(&v6_only, &v4_only, false, true, false);
        assert!(p.signature_changed && p.notify_route_change);
        assert!(p.desired_ipv4_active && !p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Install);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Remove);
        assert!(p.dns_v6_changed);

        // 6. IPv6-only -> Dual-stack with `tun_ipv6 = false`: install IPv4 and drop auto-IPv6.
        let p = plan_uplink_transition(&v6_only, &dual_stack, false, true, false);
        assert!(p.desired_ipv4_active && !p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Install);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Remove);
        assert!(p.dns_v6_changed);

        // 7. IPv6-only -> Dual-stack with `tun_ipv6 = true`: install IPv4 and keep IPv6.
        let p = plan_uplink_transition(&v6_only, &dual_stack, false, true, true);
        assert!(p.desired_ipv4_active && p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Install);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!p.dns_v6_changed);

        // 8. Dual-stack -> IPv6-only with `tun_ipv6 = true`: remove IPv4 and keep IPv6.
        let p = plan_uplink_transition(&dual_stack, &v6_only, true, true, true);
        assert!(!p.desired_ipv4_active && p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Remove);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!p.dns_v6_changed);

        // 9. Dual-stack (`tun_ipv6 = false`) -> IPv6-only: auto-enable IPv6 and remove IPv4.
        let p = plan_uplink_transition(&dual_stack, &v6_only, true, false, false);
        assert!(!p.desired_ipv4_active && p.desired_ipv6_active);
        assert_eq!(p.ipv4_action, FamilyRoutingAction::Remove);
        assert_eq!(p.ipv6_action, FamilyRoutingAction::Install);
        assert!(p.dns_v6_changed);

        // 10. IPv6-only -> Offline -> IPv6-only preserves existing IPv6-only stack state while
        // offline instead of tearing down IPv6 and installing IPv4 (matching `windows_tun.rs`).
        let to_offline = plan_uplink_transition(&v6_only, &offline, false, true, false);
        assert!(!to_offline.desired_ipv4_active && to_offline.desired_ipv6_active);
        assert_eq!(to_offline.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(to_offline.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!to_offline.dns_v6_changed && to_offline.notify_route_change);

        let back_v6 = plan_uplink_transition(&offline, &v6_only, false, true, false);
        assert!(!back_v6.desired_ipv4_active && back_v6.desired_ipv6_active);
        assert_eq!(back_v6.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(back_v6.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!back_v6.dns_v6_changed && back_v6.notify_route_change);
    }

    #[test]
    fn reassert_managed_resolv_conf_recovers_from_dhcp_overwrite_and_v6_toggle() {
        let dir = unique_test_dir("resolv-reassert");
        let resolv = dir.join("resolv.conf");
        let backup = dir.join("resolv.conf.orig");

        let original = "# Original ISP\nnameserver 192.168.1.1\nsearch home.arpa\n";
        fs::write(&resolv, original).unwrap();
        install_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap();

        // Already matching IPv4-only managed file needs no rewrite.
        assert!(!reassert_managed_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap());

        // Enabling IPv6 DNS rewrites managed file to include LINUX_TUN_DNS_V6 while preserving backup.
        assert!(reassert_managed_resolv_conf_at(
            &resolv,
            &backup,
            LINUX_TUN_DNS_V4,
            Some(LINUX_TUN_DNS_V6)
        )
        .unwrap());
        let with_v6 = fs::read_to_string(&resolv).unwrap();
        assert!(is_vdpi_managed_resolv_conf(&with_v6));
        assert!(with_v6.contains("nameserver 198.18.0.2\n"));
        assert!(with_v6.contains("nameserver fd00:7664:7069::2\n"));
        assert!(with_v6.contains("search home.arpa\n"));
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);
        assert!(!reassert_managed_resolv_conf_at(
            &resolv,
            &backup,
            LINUX_TUN_DNS_V4,
            Some(LINUX_TUN_DNS_V6)
        )
        .unwrap());

        // Simulate DHCP/NetworkManager overwriting `/etc/resolv.conf` on roam.
        let dhcp_overwrite = "# Generated by NetworkManager\nnameserver 10.20.30.1\nsearch cafe.local\n";
        fs::write(&resolv, dhcp_overwrite).unwrap();
        assert!(resolv_conf_needs_reassert(
            Some(dhcp_overwrite),
            LINUX_TUN_DNS_V4,
            None
        ));

        assert!(reassert_managed_resolv_conf_at(&resolv, &backup, LINUX_TUN_DNS_V4, None).unwrap());
        let recovered = fs::read_to_string(&resolv).unwrap();
        assert!(is_vdpi_managed_resolv_conf(&recovered));
        assert!(recovered.contains("nameserver 198.18.0.2\n"));
        assert!(!recovered.contains(LINUX_TUN_DNS_V6));
        assert!(!recovered.contains("10.20.30.1"));
        assert!(recovered.contains("search cafe.local\n"));
        // Pre-TUN original backup must never be clobbered by DHCP re-assertion.
        assert_eq!(fs::read_to_string(&backup).unwrap(), original);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn container_vm_and_tailscale_interfaces_filtered_from_routes_and_monitor() {
        let noisy_default_routes = "\
default via 10.88.0.1 dev podman0 metric 10
default via 10.89.0.1 dev podman1 metric 15
default via 10.244.0.1 dev cni0 metric 20
default via 10.88.1.1 dev cni-podman0 metric 25
default via 10.0.3.1 dev lxcbr0 metric 30
default via 192.168.56.1 dev vboxnet0 metric 35
default via 192.168.100.1 dev vmnet1 metric 40
default via 172.16.42.1 dev vmnet8 metric 45
default dev tailscale0 metric 50
default via 192.168.1.1 dev enp0s31f6 proto dhcp metric 100
";
        assert_eq!(
            parse_default_route_dev(noisy_default_routes, LINUX_TUN_IFACE).as_deref(),
            Some("enp0s31f6")
        );

        let only_container_vm_routes = "\
default dev podman0 metric 10
default dev cni-podman0 metric 20
default dev lxcbr0 metric 30
default dev vboxnet0 metric 40
default dev vmnet8 metric 50
default dev tailscale0 metric 60
";
        assert_eq!(
            parse_default_route_dev(only_container_vm_routes, LINUX_TUN_IFACE),
            None
        );

        // Route monitor lines for podman/cni/lxcbr/vboxnet/vmnet/tailscale must be ignored.
        for noisy_line in [
            "10.88.0.0/16 dev podman0 proto kernel scope link src 10.88.0.1",
            "Deleted fe80::/64 dev podman1@if4 proto kernel metric 256",
            "10.244.0.0/24 dev cni0 proto kernel scope link src 10.244.0.1",
            "Deleted 10.88.1.0/24 dev cni-podman0 proto kernel scope link",
            "10.0.3.0/24 dev lxcbr0 proto kernel scope link src 10.0.3.1",
            "192.168.56.0/24 dev vboxnet0 proto kernel scope link src 192.168.56.1",
            "192.168.100.0/24 dev vmnet1 proto kernel scope link src 192.168.100.1",
            "Deleted 172.16.42.0/24 dev vmnet8 proto kernel scope link",
            "100.64.0.0/10 dev tailscale0 table 52 scope link",
            "Deleted default dev tailscale0 table 52",
        ] {
            assert!(
                !is_relevant_route_monitor_line(noisy_line, LINUX_TUN_IFACE),
                "expected noisy route monitor line to be filtered: {noisy_line}"
            );
        }

        // Physical uplinks remain relevant.
        assert!(is_relevant_route_monitor_line(
            "default via fe80::1 dev wwan0 proto ra metric 100 pref medium",
            LINUX_TUN_IFACE
        ));
    }

    #[test]
    fn linux_tun_privilege_error_matches_main_cli_guidance() {
        assert!(LINUX_TUN_PRIVILEGE_ERROR.contains("sudo vdpi --tun start"));
        assert!(LINUX_TUN_PRIVILEGE_ERROR.contains("sudo vdpi install --tun"));
        assert!(!LINUX_TUN_PRIVILEGE_ERROR.contains("grant cap_net_admin"));
    }

    #[test]
    fn same_nic_wifi_ssid_roam_detected_via_gateway_and_local_unicast_ips() {
        // Default route parser extracts `(dev, normalized_gateway)` while skipping linkdown/TUN.
        let v4_route = "\
default dev vdpi0 scope link metric 50
default via 192.168.0.1 dev eth0 proto dhcp metric 100 linkdown
default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.42 metric 600
";
        assert_eq!(
            parse_default_route_dev_and_gateway(v4_route, LINUX_TUN_IFACE),
            Some(("wlan0".to_string(), Some("192.168.1.1".to_string())))
        );

        let v6_route = "\
default dev vdpi0 metric 1024 pref medium
default via fe80::0001 dev wlan0 proto ra metric 600 pref medium
";
        assert_eq!(
            parse_default_route_dev_and_gateway(v6_route, LINUX_TUN_IFACE),
            Some(("wlan0".to_string(), Some("fe80::1".to_string())))
        );

        // RFC 5549 `via inet6` and gateway-less point-to-point defaults also parse cleanly.
        assert_eq!(
            parse_default_route_dev_and_gateway(
                "default via inet6 fe80::2 dev eth0 proto bgp metric 100\n",
                LINUX_TUN_IFACE
            ),
            Some(("eth0".to_string(), Some("fe80::2".to_string())))
        );
        assert_eq!(
            parse_default_route_dev_and_gateway(
                "default dev ppp0 scope link\n",
                LINUX_TUN_IFACE
            ),
            Some(("ppp0".to_string(), None))
        );

        // Local unicast IPv4 parser handles `-o` and multi-line output, sorts + deduplicates,
        // and filters loopback, link-local, scope host/link, tentative, and deprecated entries.
        let ip4_out = "\
3: wlan0    inet 192.168.1.87/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0\\       valid_lft 86399sec preferred_lft 86399sec
3: wlan0    inet 192.168.1.42/24 brd 192.168.1.255 scope global secondary wlan0\\       valid_lft 86399sec preferred_lft 86399sec
3: wlan0    inet 192.168.1.87/24 scope global wlan0
3: wlan0    inet 169.254.10.20/16 scope link wlan0
3: wlan0    inet 127.0.0.1/8 scope host lo
3: wlan0    inet 10.0.0.5/24 scope global tentative wlan0
3: wlan0    inet 10.0.0.6/24 scope global deprecated wlan0\\       valid_lft 60sec preferred_lft 0sec
";
        assert_eq!(
            parse_local_unicast_ipv4_addrs(ip4_out),
            vec![
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(192, 168, 1, 87),
            ]
        );

        // Local unicast IPv6 parser keeps global unicast + ULA and skips fe80::/10, ::1,
        // tentative, dadfailed, and deprecated addresses.
        let ip6_out = "\
3: wlan0    inet6 2001:db8:2::42/64 scope global dynamic noprefixroute \\       valid_lft 86399sec preferred_lft 14399sec
3: wlan0    inet6 fd12:3456:789a::10/64 scope global noprefixroute \\       valid_lft forever preferred_lft forever
3: wlan0    inet6 2001:db8:1::99/64 scope global tentative dynamic \\       valid_lft 86399sec preferred_lft 14399sec
3: wlan0    inet6 2001:db8:1::88/64 scope global deprecated \\       valid_lft 3600sec preferred_lft 0sec
3: wlan0    inet6 fe80::a8bb:ccff:fedd:eeff/64 scope link noprefixroute \\       valid_lft forever preferred_lft forever
1: lo       inet6 ::1/128 scope host \\       valid_lft forever preferred_lft forever
";
        assert_eq!(
            parse_local_unicast_ipv6_addrs(ip6_out),
            vec![
                "2001:db8:2::42".parse::<Ipv6Addr>().unwrap(),
                "fd12:3456:789a::10".parse::<Ipv6Addr>().unwrap(),
            ]
        );

        // `from_details` normalizes local IP ordering and duplicates so identical networks match.
        let ssid_a_order1 = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![
                Ipv4Addr::new(192, 168, 1, 50),
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(192, 168, 1, 42),
            ],
            None,
            None,
            Vec::new(),
        );
        let ssid_a_order2 = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![
                Ipv4Addr::new(192, 168, 1, 42),
                Ipv4Addr::new(192, 168, 1, 50),
            ],
            None,
            None,
            Vec::new(),
        );
        assert_eq!(ssid_a_order1, ssid_a_order2);

        // Same-NIC DHCP renewal with identical gateway + local IPs suppresses DNS flush & route_tx
        // while keeping `reassert_resolv_conf == true` to catch DHCP `/etc/resolv.conf` overwrites.
        let dhcp_renew = plan_uplink_transition(&ssid_a_order1, &ssid_a_order2, true, false, false);
        assert!(!dhcp_renew.signature_changed);
        assert!(!dhcp_renew.notify_route_change);
        assert!(dhcp_renew.reassert_resolv_conf);
        assert_eq!(dhcp_renew.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(dhcp_renew.ipv6_action, FamilyRoutingAction::Keep);

        // Rapid same-NIC Wi-Fi SSID roam on `wlan0` sharing gateway `192.168.1.1` but receiving a
        // different local IPv4 MUST trigger DNS cache flush + `route_tx`.
        let ssid_b_same_gw = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![Ipv4Addr::new(192, 168, 1, 87)],
            None,
            None,
            Vec::new(),
        );
        let roam_local_ip =
            plan_uplink_transition(&ssid_a_order1, &ssid_b_same_gw, true, false, false);
        assert!(roam_local_ip.signature_changed);
        assert!(roam_local_ip.notify_route_change);
        assert!(roam_local_ip.reassert_resolv_conf);
        assert_eq!(roam_local_ip.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(roam_local_ip.ipv6_action, FamilyRoutingAction::Keep);

        // Same-NIC Wi-Fi SSID roam on `wlan0` with changed gateway also triggers notification.
        let ssid_c_diff_gw = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("10.0.0.1".into()),
            vec![Ipv4Addr::new(192, 168, 1, 87)],
            None,
            None,
            Vec::new(),
        );
        let roam_gw = plan_uplink_transition(&ssid_b_same_gw, &ssid_c_diff_gw, true, false, false);
        assert!(roam_gw.signature_changed);
        assert!(roam_gw.notify_route_change);

        // Same-NIC IPv6-only SSID roam on `wlan0` with identical link-local gateway `fe80::1`
        // but a new global IPv6 address triggers notification.
        let v6_ssid_a = LinuxUplinkSignature::from_details(
            None,
            None,
            Vec::new(),
            Some("wlan0".into()),
            Some("fe80::1".into()),
            vec!["2001:db8:1::42".parse().unwrap()],
        );
        let v6_ssid_b = LinuxUplinkSignature::from_details(
            None,
            None,
            Vec::new(),
            Some("wlan0".into()),
            Some("fe80::1".into()),
            vec!["2001:db8:2::42".parse().unwrap()],
        );
        let roam_v6 = plan_uplink_transition(&v6_ssid_a, &v6_ssid_b, false, true, false);
        assert!(roam_v6.signature_changed);
        assert!(roam_v6.notify_route_change);
        assert!(roam_v6.reassert_resolv_conf);
        assert!(!roam_v6.dns_v6_changed);
        assert_eq!(roam_v6.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(roam_v6.ipv6_action, FamilyRoutingAction::Keep);
    }

    #[test]
    fn transient_offline_transitions_preserve_existing_stack_state() {
        let v6_only = LinuxUplinkSignature::from_details(
            None,
            None,
            Vec::new(),
            Some("wlan0".into()),
            Some("fe80::1".into()),
            vec!["2001:db8::42".parse().unwrap()],
        );
        let v4_only = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![Ipv4Addr::new(192, 168, 1, 42)],
            None,
            None,
            Vec::new(),
        );
        let dual_stack = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![Ipv4Addr::new(192, 168, 1, 42)],
            Some("wlan0".into()),
            Some("fe80::1".into()),
            vec!["2001:db8::42".parse().unwrap()],
        );
        let offline = LinuxUplinkSignature::from_nics(None, None);

        // IPv6-only -> Offline -> IPv6-only must NOT tear down IPv6 or install IPv4 while offline.
        let v6_to_offline = plan_uplink_transition(&v6_only, &offline, false, true, false);
        assert!(v6_to_offline.signature_changed);
        assert!(v6_to_offline.notify_route_change);
        assert!(v6_to_offline.reassert_resolv_conf);
        assert!(!v6_to_offline.desired_ipv4_active);
        assert!(v6_to_offline.desired_ipv6_active);
        assert_eq!(v6_to_offline.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(v6_to_offline.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!v6_to_offline.dns_v6_changed);

        let offline_to_v6 = plan_uplink_transition(
            &offline,
            &v6_only,
            v6_to_offline.desired_ipv4_active,
            v6_to_offline.desired_ipv6_active,
            false,
        );
        assert!(offline_to_v6.signature_changed);
        assert!(offline_to_v6.notify_route_change);
        assert!(!offline_to_v6.desired_ipv4_active);
        assert!(offline_to_v6.desired_ipv6_active);
        assert_eq!(offline_to_v6.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(offline_to_v6.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!offline_to_v6.dns_v6_changed);

        // IPv6-only -> Offline -> IPv4-only switches cleanly once the IPv4 uplink comes up.
        let offline_to_v4 = plan_uplink_transition(
            &offline,
            &v4_only,
            v6_to_offline.desired_ipv4_active,
            v6_to_offline.desired_ipv6_active,
            false,
        );
        assert!(offline_to_v4.desired_ipv4_active);
        assert!(!offline_to_v4.desired_ipv6_active);
        assert_eq!(offline_to_v4.ipv4_action, FamilyRoutingAction::Install);
        assert_eq!(offline_to_v4.ipv6_action, FamilyRoutingAction::Remove);
        assert!(offline_to_v4.dns_v6_changed);

        // Dual-stack -> Offline -> Dual-stack also preserves both families without churn.
        let dual_to_offline = plan_uplink_transition(&dual_stack, &offline, true, true, true);
        assert!(dual_to_offline.desired_ipv4_active && dual_to_offline.desired_ipv6_active);
        assert_eq!(dual_to_offline.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(dual_to_offline.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!dual_to_offline.dns_v6_changed);

        let offline_to_dual = plan_uplink_transition(
            &offline,
            &dual_stack,
            dual_to_offline.desired_ipv4_active,
            dual_to_offline.desired_ipv6_active,
            true,
        );
        assert!(offline_to_dual.desired_ipv4_active && offline_to_dual.desired_ipv6_active);
        assert_eq!(offline_to_dual.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(offline_to_dual.ipv6_action, FamilyRoutingAction::Keep);
        assert!(!offline_to_dual.dns_v6_changed);
    }

    #[test]
    fn wake_clock_jump_detection_and_same_nic_forced_resync() {
        use std::time::Duration;

        let idle = LINUX_ROUTE_IDLE_POLL_INTERVAL;
        let threshold = LINUX_WAKE_TIME_JUMP_THRESHOLD;

        // Normal awake idle timeout (1s monotonic, 1s wall): no wake.
        assert!(!detect_wake_or_time_jump(idle, Ok(idle), idle));
        // Slight wall-clock NTP slew below threshold: no wake.
        assert!(!detect_wake_or_time_jump(
            idle,
            Ok(idle + Duration::from_secs(2)),
            idle
        ));
        // Small backward wall-clock adjustment below threshold: no wake.
        assert!(!detect_wake_or_time_jump(
            Duration::from_millis(100),
            Err(Duration::from_secs(4)),
            idle
        ));
        // Linux suspend where CLOCK_MONOTONIC paused (100ms) while CLOCK_REALTIME advanced (30s): wake.
        assert!(detect_wake_or_time_jump(
            Duration::from_millis(100),
            Ok(Duration::from_secs(30)),
            idle
        ));
        // Exact threshold skew between wall and monotonic clocks: wake.
        assert!(detect_wake_or_time_jump(
            Duration::from_millis(50),
            Ok(Duration::from_millis(50) + threshold),
            idle
        ));
        // Significant backward wall-clock jump: wake.
        assert!(detect_wake_or_time_jump(
            Duration::from_millis(100),
            Err(threshold),
            idle
        ));
        // Monotonic elapsed time exceeding expected poll wait + threshold: wake.
        assert!(detect_wake_or_time_jump(
            idle + threshold,
            Ok(idle + threshold),
            idle
        ));

        // Waking onto the exact same Wi-Fi NIC/gateway/IP (`force_resync = true`) MUST still
        // drain stale UDP NAT (`notify_route_change = true`), flush DNS cache, and re-assert
        // `/etc/resolv.conf` while keeping active routing unchanged.
        let same_wifi = LinuxUplinkSignature::from_details(
            Some("wlan0".into()),
            Some("192.168.1.1".into()),
            vec![Ipv4Addr::new(192, 168, 1, 42)],
            None,
            None,
            Vec::new(),
        );
        let normal = plan_uplink_transition_with_resync(
            &same_wifi,
            &same_wifi,
            true,
            false,
            false,
            false,
        );
        assert!(!normal.signature_changed);
        assert!(!normal.notify_route_change);
        assert!(normal.reassert_resolv_conf);

        let after_wake = plan_uplink_transition_with_resync(
            &same_wifi,
            &same_wifi,
            true,
            false,
            false,
            true,
        );
        assert!(!after_wake.signature_changed);
        assert!(after_wake.notify_route_change);
        assert!(after_wake.reassert_resolv_conf);
        assert!(!after_wake.dns_v6_changed);
        assert_eq!(after_wake.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(after_wake.ipv6_action, FamilyRoutingAction::Keep);

        // Waking while offline also preserves existing stack state while forcing NAT/DNS refresh.
        let offline = LinuxUplinkSignature::from_nics(None, None);
        let offline_wake = plan_uplink_transition_with_resync(
            &offline,
            &offline,
            false,
            true,
            false,
            true,
        );
        assert!(!offline_wake.signature_changed);
        assert!(offline_wake.notify_route_change);
        assert!(offline_wake.reassert_resolv_conf);
        assert!(!offline_wake.desired_ipv4_active && offline_wake.desired_ipv6_active);
        assert_eq!(offline_wake.ipv4_action, FamilyRoutingAction::Keep);
        assert_eq!(offline_wake.ipv6_action, FamilyRoutingAction::Keep);
    }
}
