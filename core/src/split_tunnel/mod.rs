//! Cross-platform desktop split-tunnel application discovery, fuzzy search
//! ranking, and TTL-cached local socket-to-process resolution.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod tui;

/// Default cache time-to-live for local socket-to-process lookups.
pub const DEFAULT_SOCKET_CACHE_TTL: Duration = Duration::from_millis(1500);

/// Default maximum number of entries retained in [`ProcessSocketResolver`].
pub const DEFAULT_SOCKET_CACHE_MAX_ENTRIES: usize = 1024;

/// Discovery origin and priority tier for a desktop application entry.
///
/// Variant ordering is deliberate (`Running < Popular < Installed < Custom`) so
/// sorting places active processes first, followed by recognized popular apps,
/// other installed apps, and manually configured custom entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AppCategory {
    Running,
    Popular,
    Installed,
    Custom,
}

/// A desktop application discovered on the host or referenced in user config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredApp {
    pub display_name: String,
    pub exe_name: String,
    pub path: Option<String>,
    pub is_running: bool,
    pub category: AppCategory,
}

struct PopularAppSeed {
    display_name: &'static str,
    /// Normalized executable names (matching [`normalize_exe`], lowercase, no `.exe`).
    normalized_names: &'static [&'static str],
}

/// Curated well-known desktop applications used strictly to enrich display names
/// and classify discovered apps as [`AppCategory::Popular`]. Entries here are
/// never injected into discovery results unless actually discovered on the host
/// or explicitly configured by the user.
const POPULAR_APPS: &[PopularAppSeed] = &[
    PopularAppSeed {
        display_name: "Discord",
        normalized_names: &["discord"],
    },
    PopularAppSeed {
        display_name: "Discord PTB",
        normalized_names: &["discordptb", "discord-ptb"],
    },
    PopularAppSeed {
        display_name: "Discord Canary",
        normalized_names: &["discordcanary", "discord-canary"],
    },
    PopularAppSeed {
        display_name: "Roblox",
        normalized_names: &[
            "robloxplayerbeta",
            "robloxplayerlauncher",
            "robloxplayer",
            "sober",
        ],
    },
    PopularAppSeed {
        display_name: "Google Chrome",
        normalized_names: &[
            "chrome",
            "google chrome",
            "google-chrome",
            "google-chrome-stable",
        ],
    },
    PopularAppSeed {
        display_name: "Microsoft Edge",
        normalized_names: &[
            "msedge",
            "microsoft edge",
            "microsoft-edge",
            "microsoft-edge-stable",
        ],
    },
    PopularAppSeed {
        display_name: "Mozilla Firefox",
        normalized_names: &["firefox", "firefox-bin", "firefox-esr"],
    },
    PopularAppSeed {
        display_name: "Brave Browser",
        normalized_names: &["brave", "brave browser", "brave-browser"],
    },
    PopularAppSeed {
        display_name: "Opera",
        normalized_names: &["opera"],
    },
    PopularAppSeed {
        display_name: "Opera GX",
        normalized_names: &["opera_gx", "opera gx"],
    },
    PopularAppSeed {
        display_name: "Steam",
        normalized_names: &["steam", "steam_osx"],
    },
    PopularAppSeed {
        display_name: "Telegram",
        normalized_names: &["telegram", "telegram-desktop", "telegram desktop"],
    },
    PopularAppSeed {
        display_name: "Spotify",
        normalized_names: &["spotify"],
    },
    PopularAppSeed {
        display_name: "Epic Games Launcher",
        normalized_names: &["epicgameslauncher", "epic games launcher"],
    },
    PopularAppSeed {
        display_name: "Riot Client",
        normalized_names: &["riotclientservices", "riotclientux", "riot client"],
    },
    PopularAppSeed {
        display_name: "Valorant",
        normalized_names: &["valorant", "valorant-win64-shipping"],
    },
    PopularAppSeed {
        display_name: "League of Legends",
        normalized_names: &["leagueclient", "leagueclientux", "league of legends"],
    },
    PopularAppSeed {
        display_name: "OBS Studio",
        normalized_names: &["obs64", "obs32", "obs", "obs studio"],
    },
    PopularAppSeed {
        display_name: "Visual Studio Code",
        normalized_names: &["code", "code-oss", "visual studio code"],
    },
    PopularAppSeed {
        display_name: "WhatsApp",
        normalized_names: &["whatsapp", "whatsapp.root"],
    },
    PopularAppSeed {
        display_name: "Slack",
        normalized_names: &["slack"],
    },
    PopularAppSeed {
        display_name: "Zoom",
        normalized_names: &["zoom", "zoom.us"],
    },
    PopularAppSeed {
        display_name: "Signal",
        normalized_names: &["signal", "signal-desktop"],
    },
    PopularAppSeed {
        display_name: "Vivaldi",
        normalized_names: &["vivaldi", "vivaldi-bin"],
    },
    PopularAppSeed {
        display_name: "Arc",
        normalized_names: &["arc"],
    },
    PopularAppSeed {
        display_name: "Chromium",
        normalized_names: &["chromium", "chromium-browser"],
    },
    PopularAppSeed {
        display_name: "Battle.net",
        normalized_names: &["battle.net"],
    },
    PopularAppSeed {
        display_name: "EA App",
        normalized_names: &["eadesktop"],
    },
    PopularAppSeed {
        display_name: "Minecraft Launcher",
        normalized_names: &["minecraft", "minecraftlauncher", "minecraft-launcher"],
    },
    PopularAppSeed {
        display_name: "VLC Media Player",
        normalized_names: &["vlc"],
    },
    PopularAppSeed {
        display_name: "qBittorrent",
        normalized_names: &["qbittorrent"],
    },
];

/// Normalizes an executable name or path for split-tunnel comparison.
pub fn normalize_exe(raw: &str) -> String {
    vdpi_core::config::normalize_split_app_name(raw)
}

/// Returns the curated human-readable display name if `exe_name` matches a
/// well-known popular desktop application.
pub fn popular_app_display_name(exe_name: &str) -> Option<&'static str> {
    let norm = normalize_exe(exe_name);
    if norm.is_empty() {
        return None;
    }
    let stem = norm.strip_suffix(".app").unwrap_or(&norm);
    POPULAR_APPS
        .iter()
        .find(|seed| seed.normalized_names.contains(&stem))
        .map(|seed| seed.display_name)
}

/// Returns `true` if `exe_name` matches a well-known popular desktop application.
pub fn is_popular_app(exe_name: &str) -> bool {
    popular_app_display_name(exe_name).is_some()
}

/// Cleans and validates a user-entered custom application string.
///
/// Trims whitespace, strips matching surrounding single or double quotes,
/// extracts the trailing filename component if a filesystem path was pasted
/// (supporting both `/` and `\` separators), and rejects empty strings,
/// whitespace-only inputs, control characters, and non-executable path markers.
pub fn canonical_exe_entry(raw: &str) -> Option<String> {
    if raw.chars().any(char::is_control) {
        return None;
    }

    let mut cleaned = raw.trim();
    loop {
        let unwrapped = cleaned
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| {
                cleaned
                    .strip_prefix('\'')
                    .and_then(|s| s.strip_suffix('\''))
            });
        match unwrapped {
            Some(inner) => cleaned = inner.trim(),
            None => break,
        }
    }

    if cleaned.is_empty() {
        return None;
    }

    let without_trailing_sep = cleaned.trim_end_matches(['/', '\\']);
    if without_trailing_sep.is_empty() {
        return None;
    }

    let file_name = without_trailing_sep
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(without_trailing_sep)
        .trim();

    if file_name.is_empty()
        || file_name == "."
        || file_name == ".."
        || file_name.ends_with(':')
        || normalize_exe(file_name).is_empty()
    {
        return None;
    }

    Some(file_name.to_string())
}

#[derive(Debug, Clone, Copy)]
struct LowerChar {
    ch: char,
    is_boundary: bool,
}

fn to_lower_chars(input: &str) -> Vec<LowerChar> {
    let mut out = Vec::with_capacity(input.len());
    let mut prev: Option<char> = None;

    for ch in input.chars() {
        let boundary_here = match prev {
            None => true,
            Some(p) => {
                !p.is_alphanumeric()
                    || (p.is_lowercase() && ch.is_uppercase())
                    || (p.is_ascii_alphabetic() && ch.is_ascii_digit())
            }
        };
        for (idx, lc) in ch.to_lowercase().enumerate() {
            out.push(LowerChar {
                ch: lc,
                is_boundary: idx == 0 && boundary_here,
            });
        }
        prev = Some(ch);
    }

    out
}

fn score_candidate(query_chars: &[char], candidate_orig: &str) -> Option<i32> {
    if candidate_orig.is_empty() {
        return None;
    }

    let cand = to_lower_chars(candidate_orig);
    if cand.is_empty() {
        return None;
    }

    let q_len = query_chars.len();
    let c_len = cand.len();

    if c_len == q_len && cand.iter().zip(query_chars).all(|(c, q)| c.ch == *q) {
        return Some(1000);
    }

    if c_len >= q_len && cand.iter().zip(query_chars).all(|(c, q)| c.ch == *q) {
        return Some(800);
    }

    if c_len >= q_len {
        let mut found_substring = false;
        for start in 1..=(c_len - q_len) {
            if cand[start..start + q_len]
                .iter()
                .zip(query_chars)
                .all(|(c, q)| c.ch == *q)
            {
                if cand[start].is_boundary {
                    return Some(650);
                }
                found_substring = true;
            }
        }
        if found_substring {
            return Some(500);
        }
    }

    // Ordered subsequence (fuzzy) match: evaluate every valid start position of
    // `query_chars[0]` to avoid greedy traps and reward consecutive runs,
    // word-boundary hits, and tight spans (capped strictly below 500).
    let mut best_fuzzy: Option<i32> = None;
    let mut positions = Vec::with_capacity(q_len);

    for start in 0..c_len {
        if cand[start].ch != query_chars[0] {
            continue;
        }
        positions.clear();
        positions.push(start);

        let mut cursor = start + 1;
        let mut matched_all = true;
        for &q_ch in &query_chars[1..] {
            if let Some(rel) = cand[cursor..].iter().position(|c| c.ch == q_ch) {
                let pos = cursor + rel;
                positions.push(pos);
                cursor = pos + 1;
            } else {
                matched_all = false;
                break;
            }
        }

        if !matched_all {
            continue;
        }

        let consecutive = positions.windows(2).filter(|w| w[1] == w[0] + 1).count() as i32;
        let boundary_hits = positions
            .iter()
            .filter(|&&pos| cand[pos].is_boundary)
            .count() as i32;
        let span = (positions[q_len - 1] - positions[0] + 1) as i32;
        let gaps = span - (q_len as i32);

        let consecutive_bonus = (consecutive * 25).min(150);
        let boundary_bonus = (boundary_hits * 15).min(60);
        let span_bonus = (60 - gaps * 5).max(0);
        let bonus = (consecutive_bonus + boundary_bonus + span_bonus).min(250);
        let score = 200 + bonus;

        best_fuzzy = Some(best_fuzzy.map_or(score, |prev| prev.max(score)));
    }

    best_fuzzy
}

/// Computes a case-insensitive relevance score for `query` against `app`.
///
/// Matches against `app.display_name`, `app.exe_name`, and `normalize_exe(&app.exe_name)`:
/// - Empty or whitespace-only query: `Some(0)`
/// - Exact match: `1000`
/// - Prefix match: `800`
/// - Word-boundary match: `650`
/// - Substring match: `500`
/// - Ordered subsequence (fuzzy) match: `200..=450` (with bonuses for
///   consecutive characters, word boundaries, and tight spans)
/// - No match: `None`
pub fn fuzzy_score(query: &str, app: &DiscoveredApp) -> Option<i32> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Some(0);
    }

    let query_chars: Vec<char> = trimmed.to_lowercase().chars().collect();
    if query_chars.is_empty() {
        return Some(0);
    }

    let normalized_exe = normalize_exe(&app.exe_name);
    let candidates = [
        app.display_name.as_str(),
        app.exe_name.as_str(),
        normalized_exe.as_str(),
    ];

    candidates
        .into_iter()
        .filter_map(|cand| score_candidate(&query_chars, cand))
        .max()
}

/// Filters `apps` by `query` and sorts results by match relevance, falling back
/// to `(is_running desc, category asc, display_name lowercase asc)` on ties
/// (and when `query` is empty).
pub fn filter_and_rank_apps<'a>(apps: &'a [DiscoveredApp], query: &str) -> Vec<&'a DiscoveredApp> {
    let mut scored: Vec<(i32, &'a DiscoveredApp)> = apps
        .iter()
        .filter_map(|app| fuzzy_score(query, app).map(|score| (score, app)))
        .collect();

    scored.sort_by(|(score_a, a), (score_b, b)| {
        score_b
            .cmp(score_a)
            .then_with(|| b.is_running.cmp(&a.is_running))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
            .then_with(|| normalize_exe(&a.exe_name).cmp(&normalize_exe(&b.exe_name)))
    });

    scored.into_iter().map(|(_, app)| app).collect()
}

fn display_name_quality(name: &str, exe_name: &str, popular_name: Option<&str>) -> u8 {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if let Some(pop) = popular_name {
        if trimmed == pop {
            return 4;
        }
    }
    let lowered = trimmed.to_lowercase();
    if lowered == exe_name.trim().to_lowercase()
        || lowered.ends_with(".exe")
        || lowered.ends_with(".app")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return 1;
    }
    if lowered == normalize_exe(exe_name) && trimmed == lowered {
        return 2;
    }
    3
}

fn pick_better_display_name(
    current: &str,
    candidate: &str,
    exe_name: &str,
    popular_name: Option<&str>,
) -> String {
    let cur_q = display_name_quality(current, exe_name, popular_name);
    let cand_q = display_name_quality(candidate, exe_name, popular_name);
    if cand_q > cur_q {
        candidate.trim().to_string()
    } else if cur_q > 0 {
        current.trim().to_string()
    } else {
        candidate.trim().to_string()
    }
}

fn pick_better_path(current: Option<String>, candidate: Option<String>) -> Option<String> {
    let cur = current.filter(|p| !p.trim().is_empty());
    let cand = candidate.filter(|p| !p.trim().is_empty());
    cur.or(cand)
}

fn merge_discovered_apps(
    platform_apps: Vec<DiscoveredApp>,
    configured_apps: &[String],
) -> Vec<DiscoveredApp> {
    let mut by_key: HashMap<String, DiscoveredApp> = HashMap::new();

    for app in platform_apps {
        let exe_clean =
            canonical_exe_entry(&app.exe_name).unwrap_or_else(|| app.exe_name.trim().to_string());
        let key = normalize_exe(&exe_clean);
        if key.is_empty() {
            continue;
        }

        let pop_name = popular_app_display_name(&exe_clean);
        let incoming_display = app.display_name.trim().to_string();
        let incoming_path = app.path.filter(|p| !p.trim().is_empty());

        match by_key.get_mut(&key) {
            Some(existing) => {
                existing.is_running |= app.is_running;
                existing.path = pick_better_path(existing.path.take(), incoming_path);
                existing.display_name = pick_better_display_name(
                    &existing.display_name,
                    &incoming_display,
                    &existing.exe_name,
                    pop_name,
                );
                if existing.category != AppCategory::Running
                    && app.category < existing.category
                    && (app.category != AppCategory::Running || existing.is_running)
                {
                    existing.category = app.category;
                }
            }
            None => {
                let initial_category = if app.is_running {
                    AppCategory::Running
                } else if app.category == AppCategory::Running {
                    AppCategory::Installed
                } else {
                    app.category
                };
                by_key.insert(
                    key,
                    DiscoveredApp {
                        display_name: incoming_display,
                        exe_name: exe_clean,
                        path: incoming_path,
                        is_running: app.is_running,
                        category: initial_category,
                    },
                );
            }
        }
    }

    // Finalize display name enrichment and category classification for all
    // platform-discovered apps before appending unfound custom configured apps.
    for app in by_key.values_mut() {
        let pop_name = popular_app_display_name(&app.exe_name);
        if let Some(nice_name) = pop_name {
            if display_name_quality(&app.display_name, &app.exe_name, Some(nice_name)) <= 2 {
                app.display_name = nice_name.to_string();
            }
        }
        if app.display_name.trim().is_empty() {
            app.display_name = app.exe_name.clone();
        }

        app.category = if app.is_running {
            AppCategory::Running
        } else if pop_name.is_some() {
            AppCategory::Popular
        } else if app.category == AppCategory::Custom {
            AppCategory::Custom
        } else {
            AppCategory::Installed
        };
    }

    // Append configured apps not already discovered on the host as `AppCategory::Custom`.
    for raw in configured_apps {
        let Some(canonical) = canonical_exe_entry(raw) else {
            continue;
        };
        let key = normalize_exe(&canonical);
        if key.is_empty() || by_key.contains_key(&key) {
            continue;
        }
        let display_name = popular_app_display_name(&canonical)
            .map(str::to_string)
            .unwrap_or_else(|| canonical.clone());
        by_key.insert(
            key,
            DiscoveredApp {
                display_name,
                exe_name: canonical,
                path: None,
                is_running: false,
                category: AppCategory::Custom,
            },
        );
    }

    let mut apps: Vec<DiscoveredApp> = by_key.into_values().collect();
    apps.sort_by(|a, b| {
        b.is_running
            .cmp(&a.is_running)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| {
                a.display_name
                    .to_lowercase()
                    .cmp(&b.display_name.to_lowercase())
            })
            .then_with(|| normalize_exe(&a.exe_name).cmp(&normalize_exe(&b.exe_name)))
    });
    apps
}

fn discover_platform_apps() -> Vec<DiscoveredApp> {
    #[cfg(target_os = "windows")]
    {
        windows::discover_platform_apps()
    }
    #[cfg(target_os = "macos")]
    {
        macos::discover_platform_apps()
    }
    #[cfg(target_os = "linux")]
    {
        linux::discover_platform_apps()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

fn lookup_local_port_process(local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        windows::lookup_local_port_process(local_ip, local_port, is_udp)
    }
    #[cfg(target_os = "macos")]
    {
        macos::lookup_local_port_process(local_ip, local_port, is_udp)
    }
    #[cfg(target_os = "linux")]
    {
        linux::lookup_local_port_process(local_ip, local_port, is_udp)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (local_ip, local_port, is_udp);
        None
    }
}

/// Discovers running and installed desktop applications on the current host,
/// merges and deduplicates them by [`normalize_exe`], enriches recognized
/// popular apps, includes any unfound `configured_apps` as
/// [`AppCategory::Custom`], and sorts by
/// `(is_running desc, category asc, display_name lowercase asc)`.
pub fn discover_apps(configured_apps: &[String]) -> Vec<DiscoveredApp> {
    merge_discovered_apps(discover_platform_apps(), configured_apps)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SocketCacheKey {
    local_ip: IpAddr,
    local_port: u16,
    is_udp: bool,
}

#[derive(Debug, Clone)]
struct SocketCacheEntry {
    app_name: Option<String>,
    cached_at: Instant,
}

type SocketLookupFn = dyn Fn(IpAddr, u16, bool) -> Option<String> + Send + Sync;

/// Thread-safe, TTL-cached resolver mapping local socket endpoints
/// `(local_ip, local_port, is_udp)` to the owning application executable name.
pub struct ProcessSocketResolver {
    cache: Mutex<HashMap<SocketCacheKey, SocketCacheEntry>>,
    ttl: Duration,
    max_entries: usize,
    lookup_fn: Box<SocketLookupFn>,
}

impl fmt::Debug for ProcessSocketResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.len();
        f.debug_struct("ProcessSocketResolver")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("cached_entries", &len)
            .finish()
    }
}

impl Default for ProcessSocketResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessSocketResolver {
    /// Creates a resolver with the default 1500ms TTL and 1024-entry capacity
    /// backed by the host platform socket table lookup.
    pub fn new() -> Self {
        Self::with_config(DEFAULT_SOCKET_CACHE_TTL, DEFAULT_SOCKET_CACHE_MAX_ENTRIES)
    }

    /// Creates a resolver with custom cache TTL and maximum entry capacity
    /// backed by the host platform socket table lookup.
    pub fn with_config(ttl: Duration, max_entries: usize) -> Self {
        Self::with_lookup(ttl, max_entries, lookup_local_port_process)
    }

    fn with_lookup<F>(ttl: Duration, max_entries: usize, lookup_fn: F) -> Self
    where
        F: Fn(IpAddr, u16, bool) -> Option<String> + Send + Sync + 'static,
    {
        Self {
            cache: Mutex::new(HashMap::new()),
            ttl,
            max_entries,
            lookup_fn: Box::new(lookup_fn),
        }
    }

    /// Resolves the executable name owning `(local_ip, local_port, is_udp)`,
    /// serving fresh hits from the in-memory TTL cache and querying the OS
    /// socket table outside the cache lock on misses or expired entries.
    pub fn resolve(&self, local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<String> {
        let key = SocketCacheKey {
            local_ip,
            local_port,
            is_udp,
        };

        if !self.ttl.is_zero() && self.max_entries > 0 {
            let now = Instant::now();
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = guard.get(&key) {
                if now.saturating_duration_since(entry.cached_at) < self.ttl {
                    return entry.app_name.clone();
                }
            }
        }

        let resolved = (self.lookup_fn)(local_ip, local_port, is_udp);

        if !self.ttl.is_zero() && self.max_entries > 0 {
            let cached_at = Instant::now();
            let mut guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !guard.contains_key(&key) && guard.len() >= self.max_entries {
                let ttl = self.ttl;
                guard.retain(|_, entry| cached_at.saturating_duration_since(entry.cached_at) < ttl);
                if guard.len() >= self.max_entries {
                    if let Some(oldest_key) = guard
                        .iter()
                        .min_by_key(|(_, entry)| entry.cached_at)
                        .map(|(k, _)| *k)
                    {
                        guard.remove(&oldest_key);
                    }
                }
            }
            guard.insert(
                key,
                SocketCacheEntry {
                    app_name: resolved.clone(),
                    cached_at,
                },
            );
        }

        resolved
    }

    /// Clears all cached entries.
    pub fn clear(&self) {
        let mut guard = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
    }

    /// Returns the number of entries currently stored in the cache.
    pub fn len(&self) -> usize {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Returns `true` if the cache currently contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

static GLOBAL_RESOLVER: OnceLock<ProcessSocketResolver> = OnceLock::new();

/// Returns the process-wide TTL-cached [`ProcessSocketResolver`] singleton.
pub fn global_resolver() -> &'static ProcessSocketResolver {
    GLOBAL_RESOLVER.get_or_init(ProcessSocketResolver::new)
}

/// Resolves the owning local application executable name for a local socket
/// endpoint using [`global_resolver`].
pub fn resolve_local_app(local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<String> {
    global_resolver().resolve(local_ip, local_port, is_udp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    fn make_app(
        display_name: &str,
        exe_name: &str,
        path: Option<&str>,
        is_running: bool,
        category: AppCategory,
    ) -> DiscoveredApp {
        DiscoveredApp {
            display_name: display_name.to_string(),
            exe_name: exe_name.to_string(),
            path: path.map(str::to_string),
            is_running,
            category,
        }
    }

    #[test]
    fn canonical_exe_entry_cleans_paths_quotes_and_rejects_invalid_inputs() {
        assert_eq!(
            canonical_exe_entry("  Discord.exe  "),
            Some("Discord.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry(r#" "C:\Program Files\Discord\Discord.exe" "#),
            Some("Discord.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry("'/usr/bin/firefox'"),
            Some("firefox".to_string())
        );
        assert_eq!(
            canonical_exe_entry("/Applications/Google Chrome.app/"),
            Some("Google Chrome.app".to_string())
        );
        assert_eq!(
            canonical_exe_entry(r#" "'C:\Games\Roblox\RobloxPlayerBeta.exe'" "#),
            Some("RobloxPlayerBeta.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry("Google Chrome"),
            Some("Google Chrome".to_string())
        );

        for invalid in [
            "",
            "   ",
            "\"\"",
            "''",
            "\"   \"",
            "/",
            r"\",
            r"C:\",
            ".",
            "..",
            ".exe",
            "discord\0.exe",
            "discord\n.exe",
            "discord\r.exe",
            "discord\t.exe",
            "\x1b[31mdiscord.exe",
        ] {
            assert_eq!(
                canonical_exe_entry(invalid),
                None,
                "expected None for invalid entry {invalid:?}"
            );
        }
    }

    #[test]
    fn fuzzy_score_ranks_tiers_in_strict_order() {
        let chrome = make_app(
            "Google Chrome",
            "chrome.exe",
            None,
            false,
            AppCategory::Popular,
        );
        let roblox = make_app(
            "Roblox",
            "RobloxPlayerBeta.exe",
            None,
            false,
            AppCategory::Popular,
        );
        let discord = make_app("Discord", "discord.exe", None, true, AppCategory::Running);
        let scattered = make_app(
            "Data Sync Console",
            "datasyncconsole.exe",
            None,
            false,
            AppCategory::Installed,
        );

        // Empty / whitespace query -> Some(0)
        assert_eq!(fuzzy_score("", &discord), Some(0));
        assert_eq!(fuzzy_score("   ", &discord), Some(0));

        // Exact = 1000 (via display_name, exe_name, or normalized exe)
        assert_eq!(fuzzy_score("discord", &discord), Some(1000));
        assert_eq!(fuzzy_score("DISCORD.EXE", &discord), Some(1000));
        assert_eq!(fuzzy_score("chrome", &chrome), Some(1000));

        // Prefix = 800
        let prefix = fuzzy_score("disc", &discord).expect("prefix match");
        assert_eq!(prefix, 800);

        // Word-boundary = 650 (space separator and camelCase boundary)
        let word_space = fuzzy_score(
            "chrome",
            &make_app(
                "Google Chrome",
                "google-chrome",
                None,
                false,
                AppCategory::Popular,
            ),
        )
        .expect("word boundary via space");
        assert_eq!(word_space, 650);
        let word_camel = fuzzy_score("player", &roblox).expect("word boundary via camelCase");
        assert_eq!(word_camel, 650);

        // Substring = 500
        let substring = fuzzy_score("hrom", &chrome).expect("substring match");
        assert_eq!(substring, 500);

        // Ordered subsequence (fuzzy) = 200..=450
        let fuzzy_tight = fuzzy_score("dsc", &discord).expect("tight subsequence");
        let fuzzy_wide = fuzzy_score("dsc", &scattered).expect("wide subsequence");
        assert!((200..500).contains(&fuzzy_tight));
        assert!((200..500).contains(&fuzzy_wide));
        assert!(
            fuzzy_tight > fuzzy_wide,
            "tight/consecutive subsequence ({fuzzy_tight}) should outrank scattered ({fuzzy_wide})"
        );

        // Strict tier ordering
        assert!(1000 > prefix);
        assert!(prefix > word_space);
        assert!(word_space > substring);
        assert!(substring > fuzzy_tight);

        // Non-match -> None
        assert_eq!(fuzzy_score("zzzz", &discord), None);
        assert_eq!(fuzzy_score("dcq", &discord), None);
        assert_eq!(fuzzy_score("drocsid", &discord), None);
    }

    #[test]
    fn filter_and_rank_apps_orders_default_and_searched_results() {
        let apps = vec![
            make_app("Zeta Tool", "zeta.exe", None, false, AppCategory::Installed),
            make_app("Custom App", "custom.exe", None, false, AppCategory::Custom),
            make_app("Spotify", "spotify.exe", None, false, AppCategory::Popular),
            make_app("Discord", "discord.exe", None, true, AppCategory::Running),
            make_app(
                "Alpha Note",
                "alpha.exe",
                None,
                false,
                AppCategory::Installed,
            ),
            make_app("Chrome", "chrome.exe", None, true, AppCategory::Running),
        ];

        // Empty query preserves default TUI order:
        // (is_running desc, category asc, display_name lowercase asc)
        let default_ranked: Vec<&str> = filter_and_rank_apps(&apps, "")
            .into_iter()
            .map(|a| a.display_name.as_str())
            .collect();
        assert_eq!(
            default_ranked,
            vec![
                "Chrome",
                "Discord",
                "Spotify",
                "Alpha Note",
                "Zeta Tool",
                "Custom App",
            ]
        );

        // Non-empty query ranks exact > prefix > word-boundary > substring > fuzzy
        let search_pool = vec![
            make_app(
                "App Code Runner",
                "runner.exe",
                None,
                false,
                AppCategory::Installed,
            ),
            make_app(
                "Visual Studio Code",
                "vseditor.exe",
                None,
                false,
                AppCategory::Installed,
            ),
            make_app(
                "Decode Tool",
                "decode.exe",
                None,
                false,
                AppCategory::Installed,
            ),
            make_app(
                "CodeBlocks",
                "codeblocks.exe",
                None,
                false,
                AppCategory::Installed,
            ),
            make_app("Code", "code.exe", None, false, AppCategory::Popular),
            make_app(
                "Unrelated",
                "other.exe",
                None,
                false,
                AppCategory::Installed,
            ),
        ];
        let ranked: Vec<&str> = filter_and_rank_apps(&search_pool, "code")
            .into_iter()
            .map(|a| a.display_name.as_str())
            .collect();
        assert_eq!(ranked[0], "Code");
        assert_eq!(ranked[1], "CodeBlocks");
        assert!(ranked[2..4].contains(&"App Code Runner"));
        assert!(ranked[2..4].contains(&"Visual Studio Code"));
        assert_eq!(ranked[4], "Decode Tool");
        assert!(!ranked.contains(&"Unrelated"));
    }

    #[test]
    fn merge_discovered_apps_deduplicates_enriches_and_sorts_cleanly() {
        let platform = vec![
            // Running process with raw exe name and no nice display name
            make_app(
                "discord.exe",
                "Discord.exe",
                None,
                true,
                AppCategory::Running,
            ),
            // Installed entry for the same exe with nice name and full path
            make_app(
                "Discord",
                "discord.exe",
                Some(r"C:\Users\alice\AppData\Local\Discord\Discord.exe"),
                false,
                AppCategory::Installed,
            ),
            // Running popular app with ugly exe-based name (should enrich to "Roblox")
            make_app(
                "RobloxPlayerBeta.exe",
                "RobloxPlayerBeta.exe",
                Some(r"C:\Games\Roblox\RobloxPlayerBeta.exe"),
                true,
                AppCategory::Running,
            ),
            // Non-running popular app (should enrich and get AppCategory::Popular)
            make_app(
                "obs64.exe",
                "obs64.exe",
                Some(r"C:\Program Files\obs-studio\bin\64bit\obs64.exe"),
                false,
                AppCategory::Installed,
            ),
            // Regular installed apps (non-popular)
            make_app(
                "Zebra Utility",
                "zebra.exe",
                Some(r"C:\Tools\zebra.exe"),
                false,
                AppCategory::Installed,
            ),
            make_app(
                "Alpha Editor",
                "alpha.exe",
                Some(r"C:\Tools\alpha.exe"),
                false,
                AppCategory::Installed,
            ),
            // Duplicate running helper of the same exe
            make_app(
                "Discord.exe",
                "DISCORD.EXE",
                None,
                true,
                AppCategory::Running,
            ),
        ];

        let configured = vec![
            // Already discovered -> must NOT create a duplicate custom entry
            "discord.exe".to_string(),
            // Not discovered on disk -> added as Custom (and deduplicated against next)
            r#""C:\MyApps\CustomGame.exe""#.to_string(),
            "customgame.exe".to_string(),
            // Invalid entries -> ignored
            "   ".to_string(),
            "bad\0name.exe".to_string(),
        ];

        let merged = merge_discovered_apps(platform, &configured);

        let summary: Vec<(&str, bool, AppCategory)> = merged
            .iter()
            .map(|a| (a.display_name.as_str(), a.is_running, a.category))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("Discord", true, AppCategory::Running),
                ("Roblox", true, AppCategory::Running),
                ("OBS Studio", false, AppCategory::Popular),
                ("Alpha Editor", false, AppCategory::Installed),
                ("Zebra Utility", false, AppCategory::Installed),
                ("CustomGame.exe", false, AppCategory::Custom),
            ]
        );

        // Merged Discord entry preserved both `is_running` and `path`
        let discord = &merged[0];
        assert_eq!(
            discord.path.as_deref(),
            Some(r"C:\Users\alice\AppData\Local\Discord\Discord.exe")
        );

        // Uninstalled popular apps (e.g. Spotify, Chrome) must NOT be synthesized
        assert!(
            !merged
                .iter()
                .any(|a| normalize_exe(&a.exe_name) == "spotify"),
            "uninstalled popular apps must not be synthesized"
        );
    }

    #[test]
    fn process_socket_resolver_caches_hits_misses_expires_and_evicts() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);

        let resolver = ProcessSocketResolver::with_lookup(
            Duration::from_millis(60),
            2,
            move |_ip, port, is_udp| {
                let n = calls_ref.fetch_add(1, Ordering::SeqCst) + 1;
                if port == 9999 {
                    None
                } else {
                    let proto = if is_udp { "udp" } else { "tcp" };
                    Some(format!("app-{proto}-{port}-{n}.exe"))
                }
            },
        );

        let ip4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let ip6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // Cache miss -> lookup called once; subsequent call within TTL -> cache hit
        let first = resolver.resolve(ip4, 50001, false);
        assert_eq!(first.as_deref(), Some("app-tcp-50001-1.exe"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let second = resolver.resolve(ip4, 50001, false);
        assert_eq!(second, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Different protocol (UDP vs TCP) is a distinct cache key
        let udp = resolver.resolve(ip4, 50001, true);
        assert_eq!(udp.as_deref(), Some("app-udp-50001-2.exe"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(resolver.len(), 2);

        // Inserting a 3rd key with max_entries = 2 evicts the oldest entry and keeps len <= 2
        let third = resolver.resolve(ip6, 50002, false);
        assert_eq!(third.as_deref(), Some("app-tcp-50002-3.exe"));
        assert_eq!(resolver.len(), 2);

        // Negative (None) lookup is also cached within TTL
        assert_eq!(resolver.resolve(ip4, 9999, false), None);
        let after_miss = calls.load(Ordering::SeqCst);
        assert_eq!(resolver.resolve(ip4, 9999, false), None);
        assert_eq!(calls.load(Ordering::SeqCst), after_miss);

        // Wait past TTL -> entry expires and triggers a fresh lookup
        thread::sleep(Duration::from_millis(90));
        let refreshed = resolver.resolve(ip6, 50002, false);
        assert!(refreshed.is_some());
        assert_ne!(refreshed, third);

        // Explicit clear empties cache
        resolver.clear();
        assert!(resolver.is_empty());
    }
}
