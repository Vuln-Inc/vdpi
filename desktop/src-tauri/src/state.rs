use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use vdpi::service::ServiceState;
use vdpi_core::config::{EngineMode, SplitTunnelMode, VpnCoexistence};

use crate::models::{
    DesktopStatusSnapshotDto, EngineModeDto, GuiPreferencesDto, ServiceOperationDto,
    ServiceStateDto, SplitTunnelModeDto, VpnCoexistenceDto, WintunStatusDto,
};

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Minimum elapsed time between two `RateTracker` samples required to compute
/// a fresh throughput rate; sub-threshold back-to-back calls return the last
/// computed rate without advancing the baseline.
pub const MIN_RATE_ELAPSED: Duration = Duration::from_millis(250);

/// Default TTL for cached slow local probes (service manager, installed binary
/// version, Wintun DLL check, config file, split-tunnel settings, and VPN
/// conflict detection).
pub const STATIC_PROBE_CACHE_TTL: Duration = Duration::from_secs(45);

/// Default restoring guard window applied by [`DesktopAppState::set_restoring`]
/// when restoring the main window from the system tray.
pub const DEFAULT_RESTORING_GUARD_DURATION: Duration = Duration::from_millis(350);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateSample {
    bytes_rx: u64,
    bytes_tx: u64,
    sampled_at: Instant,
}

/// Computes receive and transmit throughput in bytes per second from monotonic
/// cumulative byte counters, re-baselining cleanly when counters reset (for
/// example after a daemon restart).
#[derive(Debug, Default, Clone)]
pub struct RateTracker {
    previous: Option<RateSample>,
    last_rx_rate_bps: u64,
    last_tx_rate_bps: u64,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears the stored baseline and cached rates so the next sample starts fresh.
    pub fn reset(&mut self) {
        self.previous = None;
        self.last_rx_rate_bps = 0;
        self.last_tx_rate_bps = 0;
    }

    /// Returns the most recently computed `(rx_rate_bps, tx_rate_bps)`.
    pub const fn last_rates(&self) -> (u64, u64) {
        (self.last_rx_rate_bps, self.last_tx_rate_bps)
    }

    /// Records a cumulative `(bytes_rx, bytes_tx)` observation at `now` and
    /// returns `(rx_rate_bps, tx_rate_bps)` in bytes per second.
    ///
    /// - The first sample establishes the baseline and returns `(0, 0)`.
    /// - If either counter decreases relative to the previous sample, the
    ///   tracker treats it as a counter reset, re-baselines to the new values,
    ///   and returns `(0, 0)` without underflowing.
    /// - If `now` is earlier than the previous sample timestamp or less than
    ///   [`MIN_RATE_ELAPSED`] has elapsed, the tracker preserves its baseline
    ///   and returns the last computed rates so rapid back-to-back polls do not
    ///   spike or dip to zero.
    pub fn sample(&mut self, bytes_rx: u64, bytes_tx: u64, now: Instant) -> (u64, u64) {
        let Some(prev) = self.previous else {
            self.previous = Some(RateSample {
                bytes_rx,
                bytes_tx,
                sampled_at: now,
            });
            self.last_rx_rate_bps = 0;
            self.last_tx_rate_bps = 0;
            return (0, 0);
        };

        if bytes_rx < prev.bytes_rx || bytes_tx < prev.bytes_tx {
            self.previous = Some(RateSample {
                bytes_rx,
                bytes_tx,
                sampled_at: now,
            });
            self.last_rx_rate_bps = 0;
            self.last_tx_rate_bps = 0;
            return (0, 0);
        }

        let Some(elapsed) = now.checked_duration_since(prev.sampled_at) else {
            return (self.last_rx_rate_bps, self.last_tx_rate_bps);
        };
        if elapsed < MIN_RATE_ELAPSED {
            return (self.last_rx_rate_bps, self.last_tx_rate_bps);
        }
        let elapsed_ns = elapsed.as_nanos();

        let delta_rx = u128::from(bytes_rx - prev.bytes_rx);
        let delta_tx = u128::from(bytes_tx - prev.bytes_tx);

        let rx_rate = ((delta_rx * NANOS_PER_SEC) / elapsed_ns).min(u128::from(u64::MAX)) as u64;
        let tx_rate = ((delta_tx * NANOS_PER_SEC) / elapsed_ns).min(u128::from(u64::MAX)) as u64;

        self.previous = Some(RateSample {
            bytes_rx,
            bytes_tx,
            sampled_at: now,
        });
        self.last_rx_rate_bps = rx_rate;
        self.last_tx_rate_bps = tx_rate;
        (rx_rate, tx_rate)
    }
}

/// Cached values from slow local probes reused across fast telemetry polls
/// until [`STATIC_PROBE_CACHE_TTL`] expires or a state-mutating action
/// invalidates the cache.
#[derive(Debug, Clone)]
pub struct StaticProbeEntry {
    pub installed_version: Option<String>,
    pub bundled_engine_version: Option<String>,
    pub can_install_from_bundle: bool,
    pub running_from_readonly_dmg: bool,
    pub wintun: WintunStatusDto,
    pub config_path: String,
    pub logs_dir: String,
    pub tray_supported: bool,
    pub split_tunnel_mode: SplitTunnelModeDto,
    pub split_tunnel_count: usize,
    pub config_warning: Option<String>,
    pub configured_engine: EngineModeDto,
    pub service_state: ServiceStateDto,
    pub vpn_conflict: Option<String>,
    pub fallback_dns: String,
    pub cached_at: Instant,
}

impl StaticProbeEntry {
    /// Returns `true` when this entry was captured less than `ttl` before `now`.
    pub fn is_fresh_within(&self, now: Instant, ttl: Duration) -> bool {
        now.checked_duration_since(self.cached_at)
            .is_some_and(|age| age < ttl)
    }

    /// Returns `true` when this entry is still within [`STATIC_PROBE_CACHE_TTL`].
    pub fn is_fresh(&self, now: Instant) -> bool {
        self.is_fresh_within(now, STATIC_PROBE_CACHE_TTL)
    }
}

/// TTL-bounded cache for slow desktop probes, invalidated immediately after
/// any service or configuration mutation.
#[derive(Debug, Default, Clone)]
pub struct StaticProbeCache {
    entry: Option<StaticProbeEntry>,
}

impl StaticProbeCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached slow-probe values if present and younger than
    /// [`STATIC_PROBE_CACHE_TTL`].
    pub fn get(&self, now: Instant) -> Option<StaticProbeEntry> {
        self.get_with_ttl(now, STATIC_PROBE_CACHE_TTL)
    }

    /// Returns the cached slow-probe values if present and younger than `ttl`.
    pub fn get_with_ttl(&self, now: Instant, ttl: Duration) -> Option<StaticProbeEntry> {
        self.entry
            .as_ref()
            .filter(|entry| entry.is_fresh_within(now, ttl))
            .cloned()
    }

    /// Stores a freshly collected slow-probe entry in the cache.
    pub fn set(&mut self, entry: StaticProbeEntry) {
        self.entry = Some(entry);
    }

    /// Clears any cached slow-probe entry so the next status collection re-probes.
    pub fn invalidate(&mut self) {
        self.entry = None;
    }

    /// Returns `true` if a cached entry exists and is still fresh at `now`.
    pub fn is_fresh(&self, now: Instant) -> bool {
        self.entry
            .as_ref()
            .is_some_and(|entry| entry.is_fresh(now))
    }
}

/// File identity `(path, len, mtime)` used by [`BinaryMetadataCache`] to avoid
/// re-spawning `vdpi --version` or re-hashing `wintun.dll` across 45-second
/// static-probe refreshes when the inspected files on disk have not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryFileMetadata {
    pub path: PathBuf,
    pub len: u64,
    pub mtime: Option<SystemTime>,
}

impl BinaryFileMetadata {
    pub fn from_metadata(path: PathBuf, meta: &std::fs::Metadata) -> Self {
        Self {
            path,
            len: meta.len(),
            mtime: meta.modified().ok(),
        }
    }

    /// Captures `(path, len, mtime)` following symlinks; returns `None` when
    /// the path does not exist or is not a regular file.
    pub fn from_path(path: &Path) -> Option<Self> {
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() {
            return None;
        }
        Some(Self::from_metadata(path.to_path_buf(), &meta))
    }

    /// Captures `(path, len, mtime)` via `symlink_metadata` without following
    /// symlinks or Windows reparse points; returns `None` when missing, a
    /// symlink/reparse point, or not a regular file.
    pub fn from_regular_file(path: &Path) -> Option<Self> {
        let meta = std::fs::symlink_metadata(path).ok()?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                return None;
            }
        }
        if meta.file_type().is_symlink() || !meta.is_file() {
            return None;
        }
        Some(Self::from_metadata(path.to_path_buf(), &meta))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachedInstalledVersion {
    metadata: BinaryFileMetadata,
    version: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedWintunVerification {
    metadata: Vec<BinaryFileMetadata>,
    strict_primary: bool,
    wintun: WintunStatusDto,
}

/// File-metadata-keyed cache for expensive binary probes (`installed_version`
/// subprocess spawn, bundled sidecar `--version` spawn, and `wintun.dll` SHA-256
/// verification).
///
/// Entries persist across [`STATIC_PROBE_CACHE_TTL`] expirations while the
/// inspected file `(path, len, mtime)` metadata stays identical, and are
/// cleared whenever [`DesktopAppState::invalidate_static_cache`] is called.
#[derive(Debug, Default, Clone)]
pub struct BinaryMetadataCache {
    installed_version: Option<CachedInstalledVersion>,
    bundled_version: Option<CachedInstalledVersion>,
    wintun: Option<CachedWintunVerification>,
}

impl BinaryMetadataCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cached `installed_version` result when `metadata` matches
    /// the stored `(path, len, mtime)` key.
    pub fn get_installed_version(&self, metadata: &BinaryFileMetadata) -> Option<Option<String>> {
        self.installed_version
            .as_ref()
            .filter(|entry| &entry.metadata == metadata)
            .map(|entry| entry.version.clone())
    }

    /// Stores a probed `installed_version` keyed by its binary file metadata.
    pub fn set_installed_version(&mut self, metadata: BinaryFileMetadata, version: Option<String>) {
        self.installed_version = Some(CachedInstalledVersion { metadata, version });
    }

    /// Clears the cached `installed_version` (for example when no installed
    /// binary is currently present on disk).
    pub fn clear_installed_version(&mut self) {
        self.installed_version = None;
    }

    /// Returns the cached `bundled_engine_version` result when `metadata` matches
    /// the stored `(path, len, mtime)` key.
    pub fn get_bundled_version(&self, metadata: &BinaryFileMetadata) -> Option<Option<String>> {
        self.bundled_version
            .as_ref()
            .filter(|entry| &entry.metadata == metadata)
            .map(|entry| entry.version.clone())
    }

    /// Stores a probed `bundled_engine_version` keyed by its binary file metadata.
    pub fn set_bundled_version(&mut self, metadata: BinaryFileMetadata, version: Option<String>) {
        self.bundled_version = Some(CachedInstalledVersion { metadata, version });
    }

    /// Clears the cached `bundled_engine_version` (for example when the bundled
    /// sidecar is absent).
    pub fn clear_bundled_version(&mut self) {
        self.bundled_version = None;
    }

    /// Returns the cached `WintunStatusDto` when the set of existing candidate
    /// file `(path, len, mtime)` keys and `strict_primary` mode match, updating
    /// `required` to reflect the currently configured engine mode.
    pub fn get_wintun_with_mode(
        &self,
        metadata: &[BinaryFileMetadata],
        required: bool,
        strict_primary: bool,
    ) -> Option<WintunStatusDto> {
        self.wintun
            .as_ref()
            .filter(|entry| {
                entry.strict_primary == strict_primary && entry.metadata.as_slice() == metadata
            })
            .map(|entry| WintunStatusDto {
                required,
                ready: entry.wintun.ready,
                message: entry.wintun.message.clone(),
            })
    }

    /// Returns the cached `WintunStatusDto` for non-strict candidate probing.
    pub fn get_wintun(
        &self,
        metadata: &[BinaryFileMetadata],
        required: bool,
    ) -> Option<WintunStatusDto> {
        self.get_wintun_with_mode(metadata, required, false)
    }

    /// Stores a verified `WintunStatusDto` keyed by the inspected candidate
    /// files' `(path, len, mtime)` metadata and `strict_primary` mode.
    pub fn set_wintun_with_mode(
        &mut self,
        metadata: Vec<BinaryFileMetadata>,
        wintun: WintunStatusDto,
        strict_primary: bool,
    ) {
        self.wintun = Some(CachedWintunVerification {
            metadata,
            strict_primary,
            wintun,
        });
    }

    /// Stores a verified `WintunStatusDto` for non-strict candidate probing.
    pub fn set_wintun(&mut self, metadata: Vec<BinaryFileMetadata>, wintun: WintunStatusDto) {
        self.set_wintun_with_mode(metadata, wintun, false);
    }

    /// Clears all cached binary metadata entries so the next probe re-runs
    /// version detection and `wintun.dll` SHA-256 verification.
    pub fn invalidate(&mut self) {
        self.installed_version = None;
        self.bundled_version = None;
        self.wintun = None;
    }
}

/// Returns `true` when `op` is a mutating install/upgrade/repair/uninstall or
/// network-reset operation during which status polls and diagnostics should pause.
pub const fn is_mutating_install_operation(op: Option<ServiceOperationDto>) -> bool {
    matches!(
        op,
        Some(
            ServiceOperationDto::Installing
                | ServiceOperationDto::Upgrading
                | ServiceOperationDto::Repairing
                | ServiceOperationDto::Uninstalling
                | ServiceOperationDto::ResettingNetwork
        )
    )
}

/// Shared runtime state managed by Tauri for the desktop application.
#[derive(Debug)]
pub struct DesktopAppState {
    /// Serializes all service and configuration mutations across Tauri
    /// commands and tray actions.
    pub action_lock: Arc<tokio::sync::Mutex<()>>,
    /// Serializes GUI preference writes independently of `action_lock` so
    /// saving local preferences never blocks behind long-running elevated
    /// service actions.
    pub prefs_lock: tokio::sync::Mutex<()>,
    /// Serializes status snapshot collection so `RateTracker` never observes
    /// out-of-order concurrent probes.
    pub snapshot_lock: Mutex<()>,
    /// Monotonic counter assigning strictly increasing `snapshot_seq` numbers.
    pub snapshot_seq: AtomicU64,
    pub rate_tracker: Mutex<RateTracker>,
    pub preferences: RwLock<GuiPreferencesDto>,
    pub is_quitting: AtomicBool,
    /// Deadline until which the main window is treated as restoring from tray
    /// so transient `WindowEvent::Resized` events do not bounce it back into
    /// the tray.
    pub restoring_until: Mutex<Option<Instant>>,
    /// Tracks the currently executing mutating service operation (if any) so
    /// the status poller can skip disruptive disk/binary probes during
    /// install/upgrade/repair/uninstall and surface pending state to the UI.
    pub active_operation: Mutex<Option<ServiceOperationDto>>,
    pub last_snapshot: RwLock<Option<Arc<DesktopStatusSnapshotDto>>>,
    pub static_probe_cache: Mutex<StaticProbeCache>,
    pub binary_metadata_cache: Mutex<BinaryMetadataCache>,
}

impl Default for DesktopAppState {
    fn default() -> Self {
        Self::new(GuiPreferencesDto::default())
    }
}

impl DesktopAppState {
    pub fn new(preferences: GuiPreferencesDto) -> Self {
        Self {
            action_lock: Arc::new(tokio::sync::Mutex::new(())),
            prefs_lock: tokio::sync::Mutex::new(()),
            snapshot_lock: Mutex::new(()),
            snapshot_seq: AtomicU64::new(0),
            rate_tracker: Mutex::new(RateTracker::new()),
            preferences: RwLock::new(preferences),
            is_quitting: AtomicBool::new(false),
            restoring_until: Mutex::new(None),
            active_operation: Mutex::new(None),
            last_snapshot: RwLock::new(None),
            static_probe_cache: Mutex::new(StaticProbeCache::new()),
            binary_metadata_cache: Mutex::new(BinaryMetadataCache::new()),
        }
    }

    /// Returns the next strictly increasing snapshot sequence number (starting at `1`).
    pub fn next_snapshot_seq(&self) -> u64 {
        self.snapshot_seq.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn preferences(&self) -> GuiPreferencesDto {
        self.preferences
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn set_preferences(&self, preferences: GuiPreferencesDto) {
        let mut guard = self
            .preferences
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = preferences;
    }

    pub fn is_quitting(&self) -> bool {
        self.is_quitting.load(Ordering::SeqCst)
    }

    pub fn set_quitting(&self, quitting: bool) {
        self.is_quitting.store(quitting, Ordering::SeqCst);
    }

    pub fn active_operation(&self) -> Option<ServiceOperationDto> {
        *self
            .active_operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn set_active_operation(&self, operation: Option<ServiceOperationDto>) {
        let mut guard = self
            .active_operation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = operation;
    }

    /// Returns `true` while an install, upgrade, repair, or uninstall operation
    /// is actively modifying the installed service binaries so the background
    /// poller avoids probing or locking binaries mid-swap.
    pub fn is_mutating_install_operation_active(&self) -> bool {
        is_mutating_install_operation(self.active_operation())
    }

    /// Marks the main window as restoring for `duration` so transient resize
    /// events emitted during unminimize/show do not bounce it back to tray.
    pub fn mark_restoring_for(&self, duration: Duration) {
        let mut guard = self
            .restoring_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if duration.is_zero() {
            *guard = None;
            return;
        }
        let now = Instant::now();
        let target = now.checked_add(duration).unwrap_or(now);
        *guard = Some(match *guard {
            Some(existing) if existing > target => existing,
            _ => target,
        });
    }

    fn is_restoring_at(&self, now: Instant) -> bool {
        let mut guard = self
            .restoring_until
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match *guard {
            Some(until) if now < until => true,
            Some(_) => {
                *guard = None;
                false
            }
            None => false,
        }
    }

    /// Returns `true` while `Instant::now()` is strictly before the active
    /// restoring guard deadline.
    pub fn is_restoring(&self) -> bool {
        self.is_restoring_at(Instant::now())
    }

    /// Thin compatibility helper over [`Self::mark_restoring_for`]: `true`
    /// arms a 350ms restoring guard window, and `false` clears it immediately.
    pub fn set_restoring(&self, restoring: bool) {
        if restoring {
            self.mark_restoring_for(DEFAULT_RESTORING_GUARD_DURATION);
        } else {
            let mut guard = self
                .restoring_until
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *guard = None;
        }
    }

    pub fn sample_rates(&self, bytes_rx: u64, bytes_tx: u64, now: Instant) -> (u64, u64) {
        let mut tracker = self
            .rate_tracker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tracker.sample(bytes_rx, bytes_tx, now)
    }

    pub fn reset_rates(&self) {
        let mut tracker = self
            .rate_tracker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        tracker.reset();
    }

    pub fn last_snapshot(&self) -> Option<Arc<DesktopStatusSnapshotDto>> {
        self.last_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Stores `snap` only if its `snapshot_seq` is strictly greater than the
    /// currently cached snapshot's sequence number, preventing stale concurrent
    /// snapshots from overwriting newer state.
    pub fn set_last_snapshot(&self, snap: Arc<DesktopStatusSnapshotDto>) {
        let mut guard = self
            .last_snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = guard.as_ref() {
            if snap.snapshot_seq <= existing.snapshot_seq {
                return;
            }
        }
        *guard = Some(snap);
    }

    pub fn cached_static_probes(&self, now: Instant) -> Option<StaticProbeEntry> {
        self.static_probe_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(now)
    }

    pub fn set_static_probe_cache(&self, entry: StaticProbeEntry) {
        let mut cache = self
            .static_probe_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.set(entry);
    }

    pub fn cached_installed_version(
        &self,
        metadata: &BinaryFileMetadata,
    ) -> Option<Option<String>> {
        self.binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_installed_version(metadata)
    }

    pub fn set_cached_installed_version(
        &self,
        metadata: BinaryFileMetadata,
        version: Option<String>,
    ) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.set_installed_version(metadata, version);
    }

    pub fn clear_cached_installed_version(&self) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.clear_installed_version();
    }

    pub fn cached_bundled_version(
        &self,
        metadata: &BinaryFileMetadata,
    ) -> Option<Option<String>> {
        self.binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_bundled_version(metadata)
    }

    pub fn set_cached_bundled_version(
        &self,
        metadata: BinaryFileMetadata,
        version: Option<String>,
    ) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.set_bundled_version(metadata, version);
    }

    pub fn clear_cached_bundled_version(&self) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.clear_bundled_version();
    }

    pub fn cached_wintun_status(
        &self,
        metadata: &[BinaryFileMetadata],
        required: bool,
    ) -> Option<WintunStatusDto> {
        self.binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_wintun(metadata, required)
    }

    pub fn cached_wintun_status_with_mode(
        &self,
        metadata: &[BinaryFileMetadata],
        required: bool,
        strict_primary: bool,
    ) -> Option<WintunStatusDto> {
        self.binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_wintun_with_mode(metadata, required, strict_primary)
    }

    pub fn set_cached_wintun_status(
        &self,
        metadata: Vec<BinaryFileMetadata>,
        wintun: WintunStatusDto,
    ) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.set_wintun(metadata, wintun);
    }

    pub fn set_cached_wintun_status_with_mode(
        &self,
        metadata: Vec<BinaryFileMetadata>,
        wintun: WintunStatusDto,
        strict_primary: bool,
    ) {
        let mut cache = self
            .binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.set_wintun_with_mode(metadata, wintun, strict_primary);
    }

    /// Invalidates cached slow probes and binary metadata caches so the next
    /// status snapshot refreshes service, config, binary version, Wintun,
    /// split-tunnel, and VPN conflict state.
    pub fn invalidate_static_cache(&self) {
        self.static_probe_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .invalidate();
        self.binary_metadata_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .invalidate();
    }
}

pub const fn engine_mode_to_dto(mode: EngineMode) -> EngineModeDto {
    match mode {
        EngineMode::Tun => EngineModeDto::Tun,
        EngineMode::Proxy => EngineModeDto::Proxy,
    }
}

pub const fn engine_mode_from_dto(mode: EngineModeDto) -> EngineMode {
    match mode {
        EngineModeDto::Tun => EngineMode::Tun,
        EngineModeDto::Proxy => EngineMode::Proxy,
    }
}

pub const fn split_tunnel_mode_to_dto(mode: SplitTunnelMode) -> SplitTunnelModeDto {
    match mode {
        SplitTunnelMode::All => SplitTunnelModeDto::All,
        SplitTunnelMode::Exclude => SplitTunnelModeDto::Exclude,
        SplitTunnelMode::Include => SplitTunnelModeDto::Include,
    }
}

pub const fn split_tunnel_mode_from_dto(mode: SplitTunnelModeDto) -> SplitTunnelMode {
    match mode {
        SplitTunnelModeDto::All => SplitTunnelMode::All,
        SplitTunnelModeDto::Exclude => SplitTunnelMode::Exclude,
        SplitTunnelModeDto::Include => SplitTunnelMode::Include,
    }
}

pub const fn vpn_coexistence_to_dto(mode: VpnCoexistence) -> VpnCoexistenceDto {
    match mode {
        VpnCoexistence::AutoYield => VpnCoexistenceDto::AutoYield,
        VpnCoexistence::Warn => VpnCoexistenceDto::Warn,
        VpnCoexistence::Off => VpnCoexistenceDto::Off,
    }
}

pub const fn vpn_coexistence_from_dto(mode: VpnCoexistenceDto) -> VpnCoexistence {
    match mode {
        VpnCoexistenceDto::AutoYield => VpnCoexistence::AutoYield,
        VpnCoexistenceDto::Warn => VpnCoexistence::Warn,
        VpnCoexistenceDto::Off => VpnCoexistence::Off,
    }
}

pub const fn service_state_to_dto(state: ServiceState) -> ServiceStateDto {
    match state {
        ServiceState::Running => ServiceStateDto::Running,
        ServiceState::Stopped => ServiceStateDto::Stopped,
        ServiceState::NotInstalled => ServiceStateDto::NotInstalled,
    }
}

pub const fn service_state_from_dto(state: ServiceStateDto) -> ServiceState {
    match state {
        ServiceStateDto::Running => ServiceState::Running,
        ServiceStateDto::Stopped => ServiceState::Stopped,
        ServiceStateDto::NotInstalled => ServiceState::NotInstalled,
    }
}

impl From<EngineMode> for EngineModeDto {
    fn from(value: EngineMode) -> Self {
        engine_mode_to_dto(value)
    }
}

impl From<EngineModeDto> for EngineMode {
    fn from(value: EngineModeDto) -> Self {
        engine_mode_from_dto(value)
    }
}

impl From<SplitTunnelMode> for SplitTunnelModeDto {
    fn from(value: SplitTunnelMode) -> Self {
        split_tunnel_mode_to_dto(value)
    }
}

impl From<SplitTunnelModeDto> for SplitTunnelMode {
    fn from(value: SplitTunnelModeDto) -> Self {
        split_tunnel_mode_from_dto(value)
    }
}

impl From<VpnCoexistence> for VpnCoexistenceDto {
    fn from(value: VpnCoexistence) -> Self {
        vpn_coexistence_to_dto(value)
    }
}

impl From<VpnCoexistenceDto> for VpnCoexistence {
    fn from(value: VpnCoexistenceDto) -> Self {
        vpn_coexistence_from_dto(value)
    }
}

impl From<ServiceState> for ServiceStateDto {
    fn from(value: ServiceState) -> Self {
        service_state_to_dto(value)
    }
}

impl From<ServiceStateDto> for ServiceState {
    fn from(value: ServiceStateDto) -> Self {
        service_state_from_dto(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ThemePreferenceDto;

    fn sample_snapshot(seq: u64, service_state: ServiceStateDto) -> DesktopStatusSnapshotDto {
        DesktopStatusSnapshotDto {
            snapshot_seq: seq,
            app_version: "0.6.0".to_string(),
            platform: "windows".to_string(),
            service_state,
            installed_version: Some("0.6.0".to_string()),
            configured_engine: EngineModeDto::Tun,
            live: None,
            vpn_conflict: None,
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            split_tunnel_mode: SplitTunnelModeDto::Exclude,
            split_tunnel_count: 2,
            config_path: "C:/vdpi/config.toml".to_string(),
            logs_dir: "C:/vdpi/logs".to_string(),
            tray_supported: true,
            config_warning: None,
            bundled_engine_version: Some("0.6.0".to_string()),
            cli_version_relation: crate::models::CliVersionRelationDto::UpToDate,
            can_install_from_bundle: true,
            live_version_stale: false,
            pending_operation: None,
            running_from_readonly_dmg: false,
        }
    }

    fn sample_static_probe(cached_at: Instant) -> StaticProbeEntry {
        StaticProbeEntry {
            installed_version: Some("0.6.0".to_string()),
            bundled_engine_version: Some("0.6.0".to_string()),
            can_install_from_bundle: true,
            running_from_readonly_dmg: false,
            wintun: WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
            config_path: "C:/vdpi/config.toml".to_string(),
            logs_dir: "C:/vdpi/logs".to_string(),
            tray_supported: true,
            split_tunnel_mode: SplitTunnelModeDto::Exclude,
            split_tunnel_count: 3,
            config_warning: Some("fallback config".to_string()),
            configured_engine: EngineModeDto::Tun,
            service_state: ServiceStateDto::Running,
            vpn_conflict: Some("WireGuard".to_string()),
            fallback_dns: "1.1.1.1".to_string(),
            cached_at,
        }
    }

    #[test]
    fn rate_tracker_first_sample_establishes_baseline_with_zero_rate() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();

        assert_eq!(tracker.last_rates(), (0, 0));
        assert_eq!(tracker.sample(10_000, 20_000, t0), (0, 0));
        assert_eq!(tracker.last_rates(), (0, 0));
    }

    #[test]
    fn rate_tracker_computes_bytes_per_second_across_intervals() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();

        assert_eq!(tracker.sample(1_000, 2_000, t0), (0, 0));

        // 1 second elapsed: +4_096 rx, +8_192 tx => (4_096, 8_192) B/s
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(tracker.sample(5_096, 10_192, t1), (4_096, 8_192));
        assert_eq!(tracker.last_rates(), (4_096, 8_192));

        // 500 ms elapsed: +500 rx, +1_500 tx => (1_000, 3_000) B/s
        let t2 = t1 + Duration::from_millis(500);
        assert_eq!(tracker.sample(5_596, 11_692, t2), (1_000, 3_000));

        // 2 seconds elapsed: +10_000 rx, +0 tx => (5_000, 0) B/s
        let t3 = t2 + Duration::from_secs(2);
        assert_eq!(tracker.sample(15_596, 11_692, t3), (5_000, 0));

        // Idle interval: 1 second elapsed, no new bytes => (0, 0) B/s
        let t4 = t3 + Duration::from_secs(1);
        assert_eq!(tracker.sample(15_596, 11_692, t4), (0, 0));
    }

    #[test]
    fn rate_tracker_enforces_minimum_elapsed_threshold() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);

        assert_eq!(tracker.sample(1_000, 2_000, t0), (0, 0));
        assert_eq!(tracker.sample(5_000, 10_000, t1), (4_000, 8_000));

        // Sub-250ms back-to-back call with no new bytes keeps last rate instead
        // of dipping to zero.
        let t_short_idle = t1 + Duration::from_millis(50);
        assert_eq!(tracker.sample(5_000, 10_000, t_short_idle), (4_000, 8_000));

        // Sub-250ms back-to-back call with a burst keeps last rate instead of
        // spiking, and preserves the t1 baseline.
        let t_short_burst = t1 + Duration::from_millis(100);
        assert_eq!(
            tracker.sample(105_000, 210_000, t_short_burst),
            (4_000, 8_000)
        );

        // Just under 250ms still returns the previous rate.
        let t_just_under = t1 + Duration::from_millis(249);
        assert_eq!(tracker.sample(7_000, 14_000, t_just_under), (4_000, 8_000));

        // Exactly 250ms computes against the preserved t1 baseline:
        // +2_500 rx / 0.25s = 10_000 B/s, +5_000 tx / 0.25s = 20_000 B/s.
        let t_threshold = t1 + MIN_RATE_ELAPSED;
        assert_eq!(
            tracker.sample(7_500, 15_000, t_threshold),
            (10_000, 20_000)
        );
        assert_eq!(tracker.last_rates(), (10_000, 20_000));

        // A counter reset within < 250ms still re-baselines immediately to (0, 0).
        let t_reset = t_threshold + Duration::from_millis(50);
        assert_eq!(tracker.sample(100, 200, t_reset), (0, 0));
        assert_eq!(tracker.last_rates(), (0, 0));
    }

    #[test]
    fn rate_tracker_handles_counter_resets_cleanly() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();

        assert_eq!(tracker.sample(50_000, 80_000, t0), (0, 0));
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(tracker.sample(60_000, 100_000, t1), (10_000, 20_000));

        // Both counters reset (daemon restarted): returns (0, 0) and re-baselines.
        let t2 = t1 + Duration::from_secs(1);
        assert_eq!(tracker.sample(1_000, 2_000, t2), (0, 0));
        assert_eq!(tracker.last_rates(), (0, 0));

        // Subsequent sample computes rate from the new baseline.
        let t3 = t2 + Duration::from_secs(1);
        assert_eq!(tracker.sample(3_500, 7_000, t3), (2_500, 5_000));

        // Single-direction counter reset (rx decreases while tx increases).
        let t4 = t3 + Duration::from_secs(1);
        assert_eq!(tracker.sample(100, 9_000, t4), (0, 0));
        let t5 = t4 + Duration::from_secs(1);
        assert_eq!(tracker.sample(600, 10_000, t5), (500, 1_000));

        // Single-direction counter reset (tx decreases while rx increases).
        let t6 = t5 + Duration::from_secs(1);
        assert_eq!(tracker.sample(1_200, 50, t6), (0, 0));
        let t7 = t6 + Duration::from_secs(1);
        assert_eq!(tracker.sample(2_200, 550, t7), (1_000, 500));
    }

    #[test]
    fn rate_tracker_handles_zero_and_non_monotonic_elapsed_time() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t1 + Duration::from_secs(1);

        assert_eq!(tracker.sample(1_000, 2_000, t0), (0, 0));
        assert_eq!(tracker.sample(2_000, 4_000, t1), (1_000, 2_000));

        // Zero elapsed time keeps last rate and preserves baseline.
        assert_eq!(tracker.sample(2_500, 5_000, t1), (1_000, 2_000));

        // Non-monotonic timestamp (earlier than previous sample) does not panic
        // or corrupt the baseline.
        assert_eq!(tracker.sample(2_600, 5_200, t0), (1_000, 2_000));

        // Next valid timestamp computes against the preserved t1 baseline.
        assert_eq!(tracker.sample(5_000, 10_000, t2), (3_000, 6_000));
    }

    #[test]
    fn rate_tracker_saturates_extreme_rates_without_overflow() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();
        let t1 = t0 + MIN_RATE_ELAPSED;

        assert_eq!(tracker.sample(0, 0, t0), (0, 0));
        assert_eq!(
            tracker.sample(u64::MAX, u64::MAX, t1),
            (u64::MAX, u64::MAX)
        );
    }

    #[test]
    fn rate_tracker_reset_clears_baseline_and_rates() {
        let mut tracker = RateTracker::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        let t2 = t1 + Duration::from_secs(1);
        let t3 = t2 + Duration::from_secs(1);

        tracker.sample(100, 200, t0);
        assert_eq!(tracker.sample(1_100, 2_200, t1), (1_000, 2_000));

        tracker.reset();
        assert_eq!(tracker.last_rates(), (0, 0));

        // After reset, the next sample re-establishes a baseline with (0, 0).
        assert_eq!(tracker.sample(10_000, 20_000, t2), (0, 0));
        assert_eq!(tracker.sample(10_500, 21_500, t3), (500, 1_500));
    }

    #[test]
    fn engine_mode_conversions_round_trip() {
        let pairs = [
            (EngineMode::Tun, EngineModeDto::Tun),
            (EngineMode::Proxy, EngineModeDto::Proxy),
        ];

        for (core_val, dto_val) in pairs {
            assert_eq!(engine_mode_to_dto(core_val), dto_val);
            assert_eq!(engine_mode_from_dto(dto_val), core_val);
            assert_eq!(EngineModeDto::from(core_val), dto_val);
            assert_eq!(EngineMode::from(dto_val), core_val);
        }
    }

    #[test]
    fn split_tunnel_mode_conversions_round_trip() {
        let pairs = [
            (SplitTunnelMode::All, SplitTunnelModeDto::All),
            (SplitTunnelMode::Exclude, SplitTunnelModeDto::Exclude),
            (SplitTunnelMode::Include, SplitTunnelModeDto::Include),
        ];

        for (core_val, dto_val) in pairs {
            assert_eq!(split_tunnel_mode_to_dto(core_val), dto_val);
            assert_eq!(split_tunnel_mode_from_dto(dto_val), core_val);
            assert_eq!(SplitTunnelModeDto::from(core_val), dto_val);
            assert_eq!(SplitTunnelMode::from(dto_val), core_val);
        }
    }

    #[test]
    fn vpn_coexistence_conversions_round_trip() {
        let pairs = [
            (VpnCoexistence::AutoYield, VpnCoexistenceDto::AutoYield),
            (VpnCoexistence::Warn, VpnCoexistenceDto::Warn),
            (VpnCoexistence::Off, VpnCoexistenceDto::Off),
        ];

        for (core_val, dto_val) in pairs {
            assert_eq!(vpn_coexistence_to_dto(core_val), dto_val);
            assert_eq!(vpn_coexistence_from_dto(dto_val), core_val);
            assert_eq!(VpnCoexistenceDto::from(core_val), dto_val);
            assert_eq!(VpnCoexistence::from(dto_val), core_val);
        }
    }

    #[test]
    fn service_state_conversions_round_trip() {
        let pairs = [
            (ServiceState::Running, ServiceStateDto::Running),
            (ServiceState::Stopped, ServiceStateDto::Stopped),
            (ServiceState::NotInstalled, ServiceStateDto::NotInstalled),
        ];

        for (core_val, dto_val) in pairs {
            assert_eq!(service_state_to_dto(core_val), dto_val);
            assert_eq!(service_state_from_dto(dto_val), core_val);
            assert_eq!(ServiceStateDto::from(core_val), dto_val);
            assert_eq!(ServiceState::from(dto_val), core_val);
        }
    }

    #[test]
    fn desktop_app_state_enforces_monotonic_snapshot_sequence() {
        let state = DesktopAppState::default();

        assert_eq!(state.next_snapshot_seq(), 1);
        assert_eq!(state.next_snapshot_seq(), 2);
        assert_eq!(state.next_snapshot_seq(), 3);
        assert!(state.last_snapshot().is_none());

        let snap_2 = Arc::new(sample_snapshot(2, ServiceStateDto::Running));
        state.set_last_snapshot(Arc::clone(&snap_2));
        let cached = state.last_snapshot().expect("snapshot 2 cached");
        assert!(Arc::ptr_eq(&cached, &snap_2));
        assert_eq!(cached.snapshot_seq, 2);
        assert_eq!(cached.service_state, ServiceStateDto::Running);

        // Older snapshot sequence must be ignored.
        let snap_1 = Arc::new(sample_snapshot(1, ServiceStateDto::Stopped));
        state.set_last_snapshot(snap_1);
        let after_stale = state.last_snapshot().expect("snapshot 2 retained");
        assert!(Arc::ptr_eq(&after_stale, &snap_2));
        assert_eq!(after_stale.snapshot_seq, 2);
        assert_eq!(after_stale.service_state, ServiceStateDto::Running);

        // Duplicate sequence number must also be ignored.
        let snap_2_dup = Arc::new(sample_snapshot(2, ServiceStateDto::NotInstalled));
        state.set_last_snapshot(snap_2_dup);
        let after_dup = state.last_snapshot().expect("snapshot 2 retained");
        assert!(Arc::ptr_eq(&after_dup, &snap_2));
        assert_eq!(after_dup.service_state, ServiceStateDto::Running);

        // Strictly newer sequence replaces the cached snapshot.
        let snap_3 = Arc::new(sample_snapshot(3, ServiceStateDto::Stopped));
        state.set_last_snapshot(Arc::clone(&snap_3));
        let after_new = state.last_snapshot().expect("snapshot 3 cached");
        assert!(Arc::ptr_eq(&after_new, &snap_3));
        assert_eq!(after_new.snapshot_seq, 3);
        assert_eq!(after_new.service_state, ServiceStateDto::Stopped);
    }

    #[test]
    fn static_probe_cache_respects_ttl_and_invalidation() {
        let state = DesktopAppState::default();
        let t0 = Instant::now();

        assert!(state.cached_static_probes(t0).is_none());

        let entry = sample_static_probe(t0);
        state.set_static_probe_cache(entry);

        // Fresh at t0 and just before the 45s TTL boundary.
        let fresh = state
            .cached_static_probes(t0 + Duration::from_secs(44))
            .expect("cache should be fresh before 45s TTL");
        assert_eq!(fresh.installed_version.as_deref(), Some("0.6.0"));
        assert!(fresh.wintun.required && fresh.wintun.ready);
        assert_eq!(fresh.config_path, "C:/vdpi/config.toml");
        assert_eq!(fresh.logs_dir, "C:/vdpi/logs");
        assert!(fresh.tray_supported);
        assert_eq!(fresh.split_tunnel_mode, SplitTunnelModeDto::Exclude);
        assert_eq!(fresh.split_tunnel_count, 3);
        assert_eq!(fresh.config_warning.as_deref(), Some("fallback config"));
        assert_eq!(fresh.configured_engine, EngineModeDto::Tun);
        assert_eq!(fresh.service_state, ServiceStateDto::Running);
        assert_eq!(fresh.vpn_conflict.as_deref(), Some("WireGuard"));
        assert_eq!(fresh.fallback_dns, "1.1.1.1");

        // Expired at and beyond 45s.
        assert!(state
            .cached_static_probes(t0 + STATIC_PROBE_CACHE_TTL)
            .is_none());
        assert!(state
            .cached_static_probes(t0 + Duration::from_secs(60))
            .is_none());

        // Re-populate at t1 and verify non-monotonic timestamps do not return cached values.
        let t1 = t0 + Duration::from_secs(60);
        state.set_static_probe_cache(sample_static_probe(t1));
        assert!(state.cached_static_probes(t0).is_none());
        assert!(state
            .cached_static_probes(t1 + Duration::from_secs(1))
            .is_some());

        // Explicit invalidation clears the cache immediately.
        state.invalidate_static_cache();
        assert!(state
            .cached_static_probes(t1 + Duration::from_secs(1))
            .is_none());
    }

    #[test]
    fn desktop_app_state_defaults_and_mutations_work() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DesktopAppState>();

        let state = DesktopAppState::default();
        assert_eq!(state.preferences(), GuiPreferencesDto::default());
        assert!(!state.is_quitting());
        assert!(!state.is_restoring());
        assert!(state.last_snapshot().is_none());

        // Ensure action, prefs, and snapshot locks are acquirable, and that
        // `prefs_lock` is completely independent of `action_lock`.
        {
            let _action_guard = state
                .action_lock
                .try_lock()
                .expect("action_lock should be acquirable");
            assert!(
                state.prefs_lock.try_lock().is_ok(),
                "prefs_lock must remain acquirable while action_lock is held"
            );
        }
        assert!(state.snapshot_lock.lock().is_ok());

        let updated_prefs = GuiPreferencesDto {
            theme: ThemePreferenceDto::Dark,
            language: crate::models::LanguagePreferenceDto::Tr,
            keep_in_tray_on_close: true,
            minimize_to_tray: true,
            start_minimized_to_tray: false,
            show_taskbar_icon_when_minimized: false,
        };
        state.set_preferences(updated_prefs.clone());
        assert_eq!(state.preferences(), updated_prefs);

        state.set_quitting(true);
        assert!(state.is_quitting());

        state.set_restoring(true);
        assert!(state.is_restoring());
        state.set_restoring(false);
        assert!(!state.is_restoring());

        let t0 = Instant::now();
        assert_eq!(state.sample_rates(1_000, 2_000, t0), (0, 0));
        assert_eq!(
            state.sample_rates(3_000, 6_000, t0 + Duration::from_secs(2)),
            (1_000, 2_000)
        );
        state.reset_rates();
        assert_eq!(
            state.sample_rates(5_000, 10_000, t0 + Duration::from_secs(3)),
            (0, 0)
        );

        let seq = state.next_snapshot_seq();
        let snapshot = Arc::new(sample_snapshot(seq, ServiceStateDto::Running));
        state.set_last_snapshot(snapshot);
        let cached = state.last_snapshot().expect("cached snapshot");
        assert_eq!(cached.snapshot_seq, seq);
        assert_eq!(cached.service_state, ServiceStateDto::Running);
        assert_eq!(cached.configured_engine, EngineModeDto::Tun);
        assert_eq!(cached.split_tunnel_mode, SplitTunnelModeDto::Exclude);
        assert_eq!(cached.split_tunnel_count, 2);
    }

    #[test]
    fn restoring_guard_tracks_deadline_and_helper_compatibility() {
        let state = DesktopAppState::default();
        assert!(!state.is_restoring());

        state.mark_restoring_for(Duration::from_secs(10));
        assert!(state.is_restoring());

        let stored_deadline = *state
            .restoring_until
            .lock()
            .expect("lock restoring_until");
        let until = stored_deadline.expect("deadline should be stored");
        assert!(state.is_restoring_at(until - Duration::from_millis(1)));
        assert!(!state.is_restoring_at(until));
        // Expired deadline is cleaned up to None on read.
        assert!(state
            .restoring_until
            .lock()
            .expect("lock restoring_until")
            .is_none());

        // Zero duration clears any active guard immediately.
        state.mark_restoring_for(Duration::from_secs(10));
        assert!(state.is_restoring());
        state.mark_restoring_for(Duration::ZERO);
        assert!(!state.is_restoring());

        // Compatibility helper: true arms 350ms window, false clears immediately.
        let before = Instant::now();
        state.set_restoring(true);
        assert!(state.is_restoring());
        let armed = state
            .restoring_until
            .lock()
            .expect("lock restoring_until")
            .expect("set_restoring(true) arms deadline");
        assert!(armed >= before + DEFAULT_RESTORING_GUARD_DURATION);
        state.set_restoring(false);
        assert!(!state.is_restoring());
    }

    #[test]
    fn binary_metadata_cache_keys_by_file_metadata_and_clears_on_invalidation() {
        let state = DesktopAppState::default();
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let t1 = t0 + Duration::from_secs(5);

        let bin_key = BinaryFileMetadata {
            path: PathBuf::from("C:/vdpi/bin/vdpi.exe"),
            len: 1_024_000,
            mtime: Some(t0),
        };
        let bin_key_same = bin_key.clone();
        let bin_key_len_changed = BinaryFileMetadata {
            len: 1_024_512,
            ..bin_key.clone()
        };
        let bin_key_mtime_changed = BinaryFileMetadata {
            mtime: Some(t1),
            ..bin_key.clone()
        };
        let bin_key_path_changed = BinaryFileMetadata {
            path: PathBuf::from("C:/other/vdpi.exe"),
            ..bin_key.clone()
        };

        assert!(state.cached_installed_version(&bin_key).is_none());
        state.set_cached_installed_version(bin_key.clone(), Some("0.6.0".to_string()));
        assert_eq!(
            state.cached_installed_version(&bin_key_same),
            Some(Some("0.6.0".to_string()))
        );
        assert!(state.cached_installed_version(&bin_key_len_changed).is_none());
        assert!(state
            .cached_installed_version(&bin_key_mtime_changed)
            .is_none());
        assert!(state
            .cached_installed_version(&bin_key_path_changed)
            .is_none());

        let dll_key = BinaryFileMetadata {
            path: PathBuf::from("C:/vdpi/bin/wintun.dll"),
            len: 420_000,
            mtime: Some(t0),
        };
        let dll_key_modified = BinaryFileMetadata {
            mtime: Some(t1),
            ..dll_key.clone()
        };

        state.set_cached_wintun_status(
            vec![dll_key.clone()],
            WintunStatusDto {
                required: true,
                ready: true,
                message: None,
            },
        );

        let hit_tun = state
            .cached_wintun_status(std::slice::from_ref(&dll_key), true)
            .expect("wintun cache hit for TUN");
        assert!(hit_tun.required);
        assert!(hit_tun.ready);
        assert!(hit_tun.message.is_none());

        // Switching engine mode updates `required` dynamically on cache hit.
        let hit_proxy = state
            .cached_wintun_status(std::slice::from_ref(&dll_key), false)
            .expect("wintun cache hit for Proxy");
        assert!(!hit_proxy.required);
        assert!(hit_proxy.ready);
        assert!(hit_proxy.message.is_none());

        // Metadata changes or candidate list changes miss the cache.
        assert!(state
            .cached_wintun_status(std::slice::from_ref(&dll_key_modified), true)
            .is_none());
        assert!(state.cached_wintun_status(&[], true).is_none());

        // `invalidate_static_cache()` clears BOTH static_probe_cache and binary_metadata_cache.
        let now = Instant::now();
        state.set_static_probe_cache(sample_static_probe(now));
        state.invalidate_static_cache();
        assert!(state.cached_static_probes(now).is_none());
        assert!(state.cached_installed_version(&bin_key).is_none());
        assert!(state
            .cached_wintun_status(std::slice::from_ref(&dll_key), true)
            .is_none());
    }

    #[test]
    fn active_operation_tracks_mutating_install_lifecycle_and_bundled_version_cache() {
        let state = DesktopAppState::default();
        assert_eq!(state.active_operation(), None);
        assert!(!state.is_mutating_install_operation_active());

        for op in [
            ServiceOperationDto::Installing,
            ServiceOperationDto::Upgrading,
            ServiceOperationDto::Repairing,
            ServiceOperationDto::Uninstalling,
            ServiceOperationDto::ResettingNetwork,
        ] {
            state.set_active_operation(Some(op));
            assert_eq!(state.active_operation(), Some(op));
            assert!(state.is_mutating_install_operation_active());
        }

        for op in [
            ServiceOperationDto::Resuming,
            ServiceOperationDto::Pausing,
            ServiceOperationDto::SwitchingEngine,
            ServiceOperationDto::SavingConfig,
        ] {
            state.set_active_operation(Some(op));
            assert_eq!(state.active_operation(), Some(op));
            assert!(!state.is_mutating_install_operation_active());
        }

        state.set_active_operation(None);
        assert!(!state.is_mutating_install_operation_active());

        let bundled_key = BinaryFileMetadata {
            path: PathBuf::from("C:/app/resources/vdpi.exe"),
            len: 2_048_000,
            mtime: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        };
        assert!(state.cached_bundled_version(&bundled_key).is_none());
        state.set_cached_bundled_version(bundled_key.clone(), Some("0.6.1".to_string()));
        assert_eq!(
            state.cached_bundled_version(&bundled_key),
            Some(Some("0.6.1".to_string()))
        );
        state.invalidate_static_cache();
        assert!(state.cached_bundled_version(&bundled_key).is_none());
    }
}
