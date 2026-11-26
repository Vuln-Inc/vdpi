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
use std::path::Path;
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

/// Builds the ordered `ip rule add` specifications for `vdpi`'s `SO_MARK` policy routing.
pub fn build_policy_rules(fwmark: u32, route_table: u32, include_ipv6: bool) -> Vec<IpRuleSpec> {
    let mut specs = Vec::with_capacity(if include_ipv6 { 8 } else { 4 });
    let families: &[bool] = if include_ipv6 {
        &[false, true]
    } else {
        &[false]
    };
    let mark_hex = format!("0x{fwmark:x}/0x{VDPI_SO_MARK_MASK:x}");
    let table_str = route_table.to_string();

    for &ipv6 in families {
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

/// Returns `true` when `/etc/resolv.conf` indicates `systemd-resolved`'s stub listener actually
/// owns host DNS (either via a symlink targeting `stub-resolv.conf` or pointing at stub listeners
/// `127.0.0.53` / `127.0.0.54`).
///
/// Non-stub `/run/systemd/resolve/resolv.conf` lists upstream nameservers directly and bypasses
/// `systemd-resolved`'s stub listener, so it must return `false`.
pub fn resolv_conf_uses_systemd_resolved(
    symlink_target: Option<&str>,
    contents: Option<&str>,
) -> bool {
    if let Some(target) = symlink_target {
        let normalized = target.trim();
        if normalized.contains("stub-resolv.conf") {
            return true;
        }
    }
    if let Some(text) = contents {
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let mut parts = trimmed.split_whitespace();
            if parts.next() == Some("nameserver")
                && matches!(parts.next(), Some("127.0.0.53" | "127.0.0.54"))
            {
                return true;
            }
        }
    }
    false
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
    out.push_str("options edns0 trust-ad\n");
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

    let managed = render_resolv_conf(dns_v4, dns_v6);
    write_file_atomic(resolv_path, &managed, 0o644)
        .with_context(|| format!("failed to write managed {}", resolv_path.display()))?;
    Ok(symlink_target)
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

/// Extracts the primary physical uplink interface name from `ip -4 route show default` output,
/// excluding the virtual TUN interface itself.
pub fn parse_default_route_dev(route_output: &str, exclude_iface: &str) -> Option<String> {
    for line in route_output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first().copied() != Some("default") {
            continue;
        }
        let Some(pos) = tokens.iter().position(|&t| t == "dev") else {
            continue;
        };
        if let Some(&dev) = tokens
            .get(pos + 1)
            .filter(|&&d| !d.is_empty() && d != exclude_iface)
        {
            return Some(dev.to_string());
        }
    }
    None
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
        build_policy_rules, is_valid_resolv_symlink_target, is_valid_state_nm_conf_path,
        is_valid_state_resolv_backup_path, nm_config_disables_dns_management,
        parse_default_route_dev, prepare_resolv_conf_backup, read_symlink_target_if_link,
        remove_file_if_exists, render_nm_dns_conf, render_resolv_conf,
        resolv_conf_uses_systemd_resolved, restore_resolv_conf_at, validate_tun_iface_name,
        write_file_atomic, IpRuleSpec, LinuxDnsBackend, LinuxTunState, ResolvBackupMeta,
        ALL_RP_FILTER_PATH, LINUX_IFNAMSIZ, LINUX_TUN_DNS_V4, LINUX_TUN_DNS_V6, LINUX_TUN_IFACE,
        LINUX_TUN_IPV4_CIDR, LINUX_TUN_IPV6_CIDR, LINUX_TUN_LOCK_PATH, LINUX_TUN_MTU,
        LINUX_TUN_STATE_DIR, LINUX_TUN_STATE_PATH, LINUX_TUN_TXQUEUELEN_LADDER, NM_DNS_CONF_PATH,
        RESOLV_CONF_BACKUP_PATH, RESOLV_CONF_META_PATH, RESOLV_CONF_PATH, TRUSTED_BIN_PREFIXES,
        VDPI_ROUTE_TABLE, VDPI_SO_MARK,
    };
    use crate::binder::{DynamicOutboundBinder, OutboundTarget};
    use anyhow::{anyhow, bail, Context, Result};
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::time::Duration;
    use tracing::{debug, info, warn};

    const _: () = assert!(LINUX_IFNAMSIZ == libc::IFNAMSIZ);

    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;
    // `_IOW('T', 202, int)` = 0x4004_54ca; fits cleanly in both glibc `c_ulong` and musl `c_int`.
    const TUNSETIFF: libc::Ioctl = 0x4004_54ca;
    const RESOLVECTL_DNS_MAX_RETRIES: u32 = 3;
    const RESOLVECTL_DNS_BACKOFF: Duration = Duration::from_millis(75);

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

    fn acquire_tun_lock() -> Result<File> {
        fs::create_dir_all(LINUX_TUN_STATE_DIR)
            .with_context(|| format!("failed to create {LINUX_TUN_STATE_DIR}"))?;
        let mut lock_file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(LINUX_TUN_LOCK_PATH)
            .with_context(|| format!("failed to open Linux TUN lock file {LINUX_TUN_LOCK_PATH}"))?;

        // SAFETY: `lock_file` is an open file descriptor exclusively owned here.
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                bail!(
                    "another vdpi Linux TUN instance is already running (lock held on {LINUX_TUN_LOCK_PATH})"
                );
            }
            return Err(err).with_context(|| {
                format!("failed to acquire exclusive lock on {LINUX_TUN_LOCK_PATH}")
            });
        }

        let _ = lock_file.set_len(0);
        let _ = writeln!(lock_file, "{}", std::process::id());
        let _ = lock_file.flush();
        Ok(lock_file)
    }

    fn try_acquire_cleanup_lock() -> Result<Option<File>> {
        fs::create_dir_all(LINUX_TUN_STATE_DIR)
            .with_context(|| format!("failed to create {LINUX_TUN_STATE_DIR}"))?;
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(LINUX_TUN_LOCK_PATH)
            .with_context(|| format!("failed to open Linux TUN lock file {LINUX_TUN_LOCK_PATH}"))?;

        // SAFETY: `lock_file` is an open file descriptor exclusively owned here.
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err).with_context(|| {
                format!("failed to acquire exclusive lock on {LINUX_TUN_LOCK_PATH}")
            });
        }
        Ok(Some(lock_file))
    }

    /// Active Linux desktop TUN session managing interface config, `SO_MARK` policy routing,
    /// and 3-backend DNS configuration with automatic rollback on `Drop`.
    #[derive(Debug)]
    pub struct LinuxTunSession {
        iface: String,
        binder: Arc<DynamicOutboundBinder>,
        cleaned: bool,
        _lock_file: File,
    }

    impl LinuxTunSession {
        /// Starts Linux TUN networking: verifies root privileges, acquires the single-instance
        /// `flock`, recovers any stale crash state, opens `/dev/net/tun`, configures IP/MTU/RPF,
        /// updates `DynamicOutboundBinder` with `SO_MARK`, installs table `202` + policy rules
        /// `5480..=5500`, and activates DNS interception.
        pub fn start(
            binder: Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
        ) -> Result<(Self, OwnedFd)> {
            // SAFETY: `geteuid(2)` is always safe to call and never fails.
            if unsafe { libc::geteuid() } != 0 {
                bail!(
                    "Linux TUN mode requires root privileges (euid=0); run with sudo or as a systemd root service"
                );
            }

            let lock_file = acquire_tun_lock()?;

            if let Err(err) = cleanup_linux_tun_state_locked() {
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
                .save_to_path(Path::new(LINUX_TUN_STATE_PATH))
                .context("failed to persist initial Linux TUN state")?;

            let applied_txqueuelen =
                match Self::configure_network(&iface, &binder, tun_ipv6, &mut state) {
                    Ok(qlen) => qlen,
                    Err(err) => {
                        binder.update(OutboundTarget::default());
                        let _ = cleanup_linux_tun_state_locked();
                        return Err(err);
                    }
                };

            let fwmark_hex = format!("0x{VDPI_SO_MARK:x}");
            info!(
                iface = %iface,
                mtu = LINUX_TUN_MTU,
                txqueuelen = ?applied_txqueuelen,
                table = VDPI_ROUTE_TABLE,
                fwmark = %fwmark_hex,
                ipv6 = state.ipv6_enabled,
                dns = ?state.dns_backend,
                "Linux desktop TUN session active"
            );

            Ok((
                Self {
                    iface,
                    binder,
                    cleaned: false,
                    _lock_file: lock_file,
                },
                tun_fd,
            ))
        }

        /// Returns the kernel-assigned Linux TUN interface name (typically `"vdpi0"`).
        pub fn iface_name(&self) -> &str {
            &self.iface
        }

        fn configure_network(
            iface: &str,
            binder: &Arc<DynamicOutboundBinder>,
            tun_ipv6: bool,
            state: &mut LinuxTunState,
        ) -> Result<Option<u32>> {
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

            configure_loose_rp_filter(iface, state);

            let ipv6_active = if tun_ipv6 {
                match configure_ipv6_addr(iface) {
                    Ok(()) => true,
                    Err(err) => {
                        warn!(
                            iface = %iface,
                            error = %err,
                            "IPv6 TUN address setup unavailable; continuing in IPv4-only TUN mode"
                        );
                        false
                    }
                }
            } else {
                false
            };
            state.ipv6_enabled = ipv6_active;

            let physical_nic = detect_default_physical_nic(iface);
            binder.update(OutboundTarget {
                nic_name: physical_nic,
                if_index_v4: None,
                if_index_v6: None,
                fwmark: Some(VDPI_SO_MARK),
                fail_closed: true,
            });

            install_routing(iface, VDPI_ROUTE_TABLE, VDPI_SO_MARK, ipv6_active)?;

            let dns_v6 = ipv6_active.then_some(LINUX_TUN_DNS_V6);
            configure_linux_dns(iface, LINUX_TUN_DNS_V4, dns_v6, state)?;

            state
                .save_to_path(Path::new(LINUX_TUN_STATE_PATH))
                .context("failed to persist active Linux TUN state")?;

            Ok(applied_txqueuelen)
        }
    }

    impl Drop for LinuxTunSession {
        fn drop(&mut self) {
            if !self.cleaned {
                self.cleaned = true;
                self.binder.update(OutboundTarget::default());
                if let Err(err) = cleanup_linux_tun_state_locked() {
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
    /// and `/run/vdpi/tun-state.json`.
    ///
    /// Acquires a non-blocking exclusive `flock` on [`LINUX_TUN_LOCK_PATH`] first; if another
    /// live `vdpi` instance holds the lock, returns `Ok(())` immediately without touching the
    /// active TUN session (safe for systemd `ExecStopPost=+/usr/local/bin/vdpi --internal-linux-tun-cleanup`).
    pub fn cleanup_linux_tun_state() -> Result<()> {
        let Some(_lock_file) = try_acquire_cleanup_lock()? else {
            info!(
                lock = LINUX_TUN_LOCK_PATH,
                "another vdpi Linux TUN instance is active; skipping cleanup"
            );
            return Ok(());
        };
        cleanup_linux_tun_state_locked()
    }

    fn cleanup_linux_tun_state_locked() -> Result<()> {
        let mut cleanup_errors: Vec<String> = Vec::new();
        let state_path = Path::new(LINUX_TUN_STATE_PATH);
        let state = match LinuxTunState::load_from_path(state_path) {
            Ok(loaded) => loaded,
            Err(err) => {
                warn!(
                    path = LINUX_TUN_STATE_PATH,
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
                    path = LINUX_TUN_STATE_PATH,
                    error = %err,
                    "failed to remove Linux TUN state file"
                );
                cleanup_errors.push(format!("failed to remove {LINUX_TUN_STATE_PATH}: {err}"));
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

    fn configure_loose_rp_filter(iface: &str, state: &mut LinuxTunState) {
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
            if let Err(err) = state.save_to_path(Path::new(LINUX_TUN_STATE_PATH)) {
                warn!(
                    path = LINUX_TUN_STATE_PATH,
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

    fn detect_default_physical_nic(exclude_iface: &str) -> Option<String> {
        let ip_bin = resolve_trusted_bin("ip")?;
        let output = Command::new(ip_bin)
            .args(["-4", "route", "show", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_default_route_dev(&stdout, exclude_iface)
    }

    fn install_routing(
        iface: &str,
        route_table: u32,
        fwmark: u32,
        include_ipv6: bool,
    ) -> Result<()> {
        let table_str = route_table.to_string();

        run_ip(&[
            "-4", "route", "replace", "default", "dev", iface, "table", &table_str,
        ])
        .context("failed to install IPv4 default route in TUN policy table")?;

        if include_ipv6 {
            run_ip(&[
                "-6", "route", "replace", "default", "dev", iface, "table", &table_str,
            ])
            .context("failed to install IPv6 default route in TUN policy table")?;
        }

        remove_policy_rules(fwmark, route_table, false)?;
        if include_ipv6 {
            remove_policy_rules(fwmark, route_table, true)?;
        }

        for spec in build_policy_rules(fwmark, route_table, include_ipv6) {
            let family = if spec.ipv6 { "-6" } else { "-4" };
            let mut argv = Vec::with_capacity(spec.args.len() + 3);
            argv.push(family);
            argv.push("rule");
            argv.push("add");
            for arg in &spec.args {
                argv.push(arg.as_str());
            }
            run_ip(&argv).with_context(|| {
                format!(
                    "failed to install {family} policy rule at priority {}",
                    spec.priority
                )
            })?;
        }

        Ok(())
    }

    fn remove_policy_rules(fwmark: u32, route_table: u32, ipv6: bool) -> Result<()> {
        let ip_bin = require_trusted_bin("ip")?;
        let family = if ipv6 { "-6" } else { "-4" };
        let specs: Vec<IpRuleSpec> = build_policy_rules(fwmark, route_table, ipv6)
            .into_iter()
            .filter(|spec| spec.ipv6 == ipv6)
            .collect();

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
        state: &mut LinuxTunState,
    ) -> Result<()> {
        if is_systemd_resolved_active() {
            state.dns_backend = LinuxDnsBackend::SystemdResolved;
            state
                .save_to_path(Path::new(LINUX_TUN_STATE_PATH))
                .context(
                    "failed to persist Linux TUN DNS state before configuring systemd-resolved",
                )?;
            configure_systemd_resolved_dns(iface, dns_v4, dns_v6)?;
            return Ok(());
        }

        if is_network_manager_dns_active() {
            state.dns_backend = LinuxDnsBackend::NetworkManager;
            state.nm_conf_path = Some(NM_DNS_CONF_PATH.to_string());
            state
                .save_to_path(Path::new(LINUX_TUN_STATE_PATH))
                .context(
                    "failed to persist Linux TUN DNS state before configuring NetworkManager",
                )?;
            configure_network_manager_dns(dns_v4, dns_v6)?;
            return Ok(());
        }

        let symlink_target = prepare_resolv_conf_backup(
            Path::new(RESOLV_CONF_PATH),
            Path::new(RESOLV_CONF_BACKUP_PATH),
            Path::new(RESOLV_CONF_META_PATH),
        )?;
        state.dns_backend = LinuxDnsBackend::ResolvConf;
        state.resolv_backup_path = Some(RESOLV_CONF_BACKUP_PATH.to_string());
        if let Some(target) = symlink_target {
            state.resolv_symlink_target = Some(target);
        }
        state
            .save_to_path(Path::new(LINUX_TUN_STATE_PATH))
            .context("failed to persist Linux TUN DNS state before updating /etc/resolv.conf")?;

        let managed = render_resolv_conf(dns_v4, dns_v6);
        write_file_atomic(Path::new(RESOLV_CONF_PATH), &managed, 0o644)
            .with_context(|| format!("failed to write managed {RESOLV_CONF_PATH}"))?;
        Ok(())
    }

    fn is_systemd_resolved_active() -> bool {
        let Some(resolvectl) = resolve_trusted_bin("resolvectl") else {
            return false;
        };
        let resolv_path = Path::new(RESOLV_CONF_PATH);
        let symlink_target = read_symlink_target_if_link(resolv_path);
        let contents = fs::read_to_string(resolv_path).ok();
        if !resolv_conf_uses_systemd_resolved(symlink_target.as_deref(), contents.as_deref()) {
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
    use std::path::PathBuf;

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
    }

    #[test]
    fn detects_systemd_resolved_and_nm_dns_disable_configs() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        assert_eq!(LINUX_TUN_MTU, vdpi_tun::config::DESKTOP_MTU as u16);
        assert_eq!(LINUX_TUN_TXQUEUELEN, 4096);
        assert_eq!(LINUX_TUN_TXQUEUELEN_LADDER, [4096, 2000, 1000]);

        assert!(resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/stub-resolv.conf"),
            None
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            Some("../run/systemd/resolve/stub-resolv.conf"),
            None
        ));
        // Non-stub `/run/systemd/resolve/resolv.conf` bypasses systemd-resolved's stub listener.
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/run/systemd/resolve/resolv.conf"),
            None
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("../run/systemd/resolve/resolv.conf"),
            None
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            None,
            Some("# generated\nnameserver 127.0.0.53\noptions edns0\n")
        ));
        assert!(resolv_conf_uses_systemd_resolved(
            None,
            Some("nameserver 127.0.0.54\n")
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            None,
            Some("# nameserver 127.0.0.53\nnameserver 1.1.1.1\n")
        ));
        assert!(!resolv_conf_uses_systemd_resolved(
            Some("/var/run/NetworkManager/resolv.conf"),
            Some("nameserver 192.168.1.1\n")
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
}
