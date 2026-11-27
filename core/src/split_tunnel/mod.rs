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

/// Default cache time-to-live for negative (`None`) local socket lookups so
/// short-lived or racing sockets are re-checked sooner than the full positive TTL
/// without thrashing OS socket/process tables.
pub const DEFAULT_NEGATIVE_SOCKET_CACHE_TTL: Duration = Duration::from_millis(500);

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
        normalized_names: &["discord", "com.discordapp.discord"],
    },
    PopularAppSeed {
        display_name: "Discord PTB",
        normalized_names: &["discordptb", "discord-ptb", "discord ptb"],
    },
    PopularAppSeed {
        display_name: "Discord Canary",
        normalized_names: &["discordcanary", "discord-canary", "discord canary"],
    },
    PopularAppSeed {
        display_name: "Roblox",
        normalized_names: &[
            "robloxplayerbeta",
            "robloxplayerlauncher",
            "robloxplayer",
            "sober",
            "org.vinegarhq.sober",
        ],
    },
    PopularAppSeed {
        display_name: "Bloxstrap",
        normalized_names: &["bloxstrap"],
    },
    PopularAppSeed {
        display_name: "Google Chrome",
        normalized_names: &[
            "chrome",
            "google chrome",
            "google-chrome",
            "google-chrome-stable",
            "com.google.chrome",
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
        normalized_names: &[
            "firefox",
            "firefox-bin",
            "firefox-esr",
            "org.mozilla.firefox",
        ],
    },
    PopularAppSeed {
        display_name: "Safari",
        normalized_names: &["safari"],
    },
    PopularAppSeed {
        display_name: "Brave Browser",
        normalized_names: &[
            "brave",
            "brave browser",
            "brave-browser",
            "com.brave.browser",
        ],
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
        normalized_names: &["steam", "steam_osx", "com.valvesoftware.steam"],
    },
    PopularAppSeed {
        display_name: "Telegram",
        normalized_names: &[
            "telegram",
            "telegram-desktop",
            "telegram desktop",
            "org.telegram.desktop",
        ],
    },
    PopularAppSeed {
        display_name: "Spotify",
        normalized_names: &["spotify", "com.spotify.client"],
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
        normalized_names: &["obs64", "obs32", "obs", "obs studio", "com.obsproject.studio"],
    },
    PopularAppSeed {
        display_name: "Visual Studio Code",
        normalized_names: &[
            "code",
            "code-oss",
            "visual studio code",
            "com.visualstudio.code",
        ],
    },
    PopularAppSeed {
        display_name: "WhatsApp",
        normalized_names: &["whatsapp", "whatsapp.root"],
    },
    PopularAppSeed {
        display_name: "Slack",
        normalized_names: &["slack", "com.slack.slack"],
    },
    PopularAppSeed {
        display_name: "Zoom",
        normalized_names: &["zoom", "zoom.us", "us.zoom.zoom"],
    },
    PopularAppSeed {
        display_name: "Signal",
        normalized_names: &["signal", "signal-desktop", "org.signal.signal"],
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
        normalized_names: &["vlc", "org.videolan.vlc"],
    },
    PopularAppSeed {
        display_name: "qBittorrent",
        normalized_names: &["qbittorrent", "org.qbittorrent.qbittorrent"],
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

/// Symmetric cross-platform companion executable groups (normalized lowercase
/// names without `.exe` or `.app` suffixes). Selecting any member of a group
/// expands split-tunnel matching to every other member in the same group.
const COMPANION_GROUPS: &[&[&str]] = &[
    // Discord (Windows, macOS, Linux / Flatpak)
    &[
        "discord",
        "discordptb",
        "discord-ptb",
        "discord ptb",
        "discordcanary",
        "discord-canary",
        "discord canary",
        "discord_clips",
        "discord helper",
        "com.discordapp.discord",
    ],
    // Roblox (Windows, macOS, Linux / Sober Flatpak, Bloxstrap, Fishstrap)
    &[
        "robloxplayerbeta",
        "robloxplayerlauncher",
        "robloxplayerinstaller",
        "bloxstrap",
        "fishstrap",
        "robloxplayer",
        "sober",
        "org.vinegarhq.sober",
    ],
    // Riot Client / Valorant / Vanguard / League of Legends
    &[
        "riotclientservices",
        "riotclientux",
        "riotclientuxrender",
        "riotclientcrashhandler",
        "valorant",
        "valorant-win64-shipping",
        "vgc",
        "vgm",
        "vgtray",
        "leagueclient",
        "leagueclientux",
        "leagueclientuxrender",
        "league of legends",
    ],
    // Steam (Windows, macOS, Linux / Flatpak)
    &[
        "steam",
        "steam_osx",
        "steamwebhelper",
        "steamservice",
        "gameoverlayui",
        "com.valvesoftware.steam",
    ],
    // Epic Games Launcher & EOS overlay
    &[
        "epicgameslauncher",
        "epic games launcher",
        "epicwebhelper",
        "eosoverlayrenderer-win64-shipping",
    ],
    // Browser Flatpak bridges
    &[
        "firefox",
        "firefox-bin",
        "firefox-esr",
        "org.mozilla.firefox",
    ],
    &[
        "chrome",
        "google chrome",
        "google-chrome",
        "google-chrome-stable",
        "com.google.chrome",
    ],
    &[
        "chromium",
        "chromium-browser",
        "org.chromium.chromium",
    ],
];

enum NormalizedApp<'a> {
    /// Pure-ASCII filename slice with surrounding quotes, path components, and
    /// any trailing `.exe` suffix stripped; compare case-insensitively.
    Ascii(&'a str),
    /// Non-ASCII fallback normalized via [`normalize_exe`].
    Owned(String),
}

fn strip_ascii_suffix_ignore_case<'a>(s: &'a str, suffix: &str) -> &'a str {
    if let Some(prefix_len) = s.len().checked_sub(suffix.len()) {
        if s.as_bytes()[prefix_len..].eq_ignore_ascii_case(suffix.as_bytes()) {
            return &s[..prefix_len];
        }
    }
    s
}

impl<'a> NormalizedApp<'a> {
    fn from_raw(raw: &'a str) -> Self {
        let unquoted = raw.trim().trim_matches(['"', '\'']).trim();
        let file_name = unquoted
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(unquoted)
            .trim()
            .trim_matches(['"', '\''])
            .trim();
        if file_name.is_ascii() {
            Self::Ascii(strip_ascii_suffix_ignore_case(file_name, ".exe").trim())
        } else {
            Self::Owned(normalize_exe(raw))
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Ascii(s) => s.is_empty(),
            Self::Owned(s) => s.is_empty(),
        }
    }

    fn eq_normalized(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ascii(a), Self::Ascii(b)) => a.eq_ignore_ascii_case(b),
            (Self::Ascii(a), Self::Owned(b)) | (Self::Owned(b), Self::Ascii(a)) => {
                a.eq_ignore_ascii_case(b.as_str())
            }
            (Self::Owned(a), Self::Owned(b)) => a == b,
        }
    }

    fn eq_lowercase_ascii(&self, target: &str) -> bool {
        match self {
            Self::Ascii(s) => s.eq_ignore_ascii_case(target),
            Self::Owned(s) => s.as_str() == target,
        }
    }

    fn stem_eq_lowercase_ascii(&self, target: &str) -> bool {
        match self {
            Self::Ascii(s) => strip_ascii_suffix_ignore_case(s, ".app").eq_ignore_ascii_case(target),
            Self::Owned(s) => s.strip_suffix(".app").unwrap_or(s.as_str()) == target,
        }
    }
}

/// Returns the symmetric companion executable group (normalized names) that
/// belongs to the same user-facing application as `exe_name`, so split-tunnel
/// matching covers multi-process launchers, overlays, helpers, and Flatpak
/// app IDs bidirectionally across Windows, macOS, and Linux.
pub fn companion_executables_for(exe_name: &str) -> &'static [&'static str] {
    let norm = NormalizedApp::from_raw(exe_name);
    if norm.is_empty() {
        return &[];
    }
    COMPANION_GROUPS
        .iter()
        .copied()
        .find(|group| {
            group
                .iter()
                .any(|&member| norm.stem_eq_lowercase_ascii(member))
        })
        .unwrap_or(&[])
}

fn strip_cli_args_after_extension(s: &str) -> &str {
    const EXTENSIONS: &[&str] = &[".exe", ".app", ".appimage", ".bat", ".cmd"];
    let lower = s.to_ascii_lowercase();
    let mut earliest_end: Option<usize> = None;

    for ext in EXTENSIONS {
        let mut search_from = 0;
        while let Some(rel) = lower[search_from..].find(ext) {
            let ext_start = search_from + rel;
            let ext_end = ext_start + ext.len();
            let preceded_by_name = ext_start > 0
                && !matches!(lower.as_bytes()[ext_start - 1], b'/' | b'\\' | b' ' | b'\t');
            let followed_by_ws = lower[ext_end..]
                .chars()
                .next()
                .is_some_and(char::is_whitespace);
            if preceded_by_name && followed_by_ws {
                earliest_end = Some(earliest_end.map_or(ext_end, |prev| prev.min(ext_end)));
                break;
            }
            search_from = ext_end;
        }
    }

    if let Some(end) = earliest_end {
        return &s[..end];
    }

    // Fallback for unquoted extensionless command lines (e.g. `/usr/bin/firefox --new-window`).
    let bytes = s.as_bytes();
    for idx in 1..bytes.len().saturating_sub(3) {
        if bytes[idx].is_ascii_whitespace()
            && bytes[idx + 1] == b'-'
            && bytes[idx + 2] == b'-'
            && bytes[idx + 3].is_ascii_alphanumeric()
        {
            return s[..idx].trim_end();
        }
    }

    s
}

/// Cleans and validates a user-entered custom application string.
///
/// Trims whitespace, unwraps leading single/double-quoted tokens (discarding
/// any trailing shortcut CLI arguments after the closing quote), strips
/// trailing CLI arguments after executable extensions or `--` flags, extracts
/// the trailing filename component if a filesystem path was pasted (supporting
/// both `/` and `\` separators), and rejects empty strings, whitespace-only
/// inputs, control characters, and non-executable path markers.
pub fn canonical_exe_entry(raw: &str) -> Option<String> {
    if raw.chars().any(char::is_control) {
        return None;
    }

    let mut cleaned = raw.trim();
    loop {
        let mut chars = cleaned.chars();
        let Some(quote @ ('"' | '\'')) = chars.next() else {
            break;
        };
        let rest_after_open = chars.as_str();
        let Some(close_idx) = rest_after_open.find(quote) else {
            break;
        };
        let after_close = &rest_after_open[close_idx + quote.len_utf8()..];
        if after_close.is_empty() || after_close.starts_with(char::is_whitespace) {
            cleaned = rest_after_open[..close_idx].trim();
        } else {
            break;
        }
    }

    cleaned = strip_cli_args_after_extension(cleaned).trim();

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
        // Normalize decomposed/Turkish `İ` (`i\u{0307}`) and dotless `ı` (`\u{0131}`) to ASCII `'i'`.
        if ch == '\u{0307}' {
            continue;
        }
        let boundary_here = match prev {
            None => true,
            Some(p) => {
                !p.is_alphanumeric()
                    || (p.is_lowercase() && ch.is_uppercase())
                    || (p.is_ascii_alphabetic() && ch.is_ascii_digit())
            }
        };
        for (idx, lc) in ch
            .to_lowercase()
            .filter(|&c| c != '\u{0307}')
            .map(|c| if c == '\u{0131}' { 'i' } else { c })
            .enumerate()
        {
            out.push(LowerChar {
                ch: lc,
                is_boundary: idx == 0 && boundary_here,
            });
        }
        prev = Some(ch);
    }

    out
}

fn score_fuzzy_positions(cand: &[LowerChar], positions: &[usize]) -> i32 {
    let q_len = positions.len() as i32;
    let consecutive = positions.windows(2).filter(|w| w[1] == w[0] + 1).count() as i32;
    let boundary_hits = positions
        .iter()
        .filter(|&&pos| cand[pos].is_boundary)
        .count() as i32;
    let span = (positions[positions.len() - 1] - positions[0] + 1) as i32;
    let gaps = span - q_len;

    let consecutive_bonus = (consecutive * 25).min(150);
    let boundary_bonus = (boundary_hits * 15).min(60);
    let span_bonus = (60 - gaps * 5).max(0);
    let bonus = (consecutive_bonus + boundary_bonus + span_bonus).min(250);
    200 + bonus
}

fn score_candidate(query_chars: &[char], candidate_orig: &str) -> Option<i32> {
    if candidate_orig.is_empty() || query_chars.is_empty() {
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

    if q_len < 2 {
        return None;
    }

    // Tightened ordered subsequence (fuzzy) match (capped strictly below 500):
    // 1. Word-boundary / acronym chain: starts on a word boundary and every
    //    subsequent character is either consecutive or on a word boundary.
    // 2. Tight boundary-anchored subsequence: starts on a word boundary with
    //    bounded gaps (`gaps <= q_len`, `max_gap <= 3`) and at least one
    //    consecutive pair or second word boundary, preventing short queries
    //    like `vgc` or `riot` from matching unrelated long names.
    let mut best_fuzzy: Option<i32> = None;
    let mut positions = Vec::with_capacity(q_len);

    for start in 0..c_len {
        if !cand[start].is_boundary || cand[start].ch != query_chars[0] {
            continue;
        }

        // Strategy 1: boundary/consecutive acronym chain (e.g. "dsc" -> "Data Sync Console").
        positions.clear();
        positions.push(start);
        let mut cursor = start + 1;
        let mut matched_acronym = true;
        for &q_ch in &query_chars[1..] {
            if cursor < c_len && cand[cursor].ch == q_ch {
                positions.push(cursor);
                cursor += 1;
            } else if let Some(rel) = cand[cursor..]
                .iter()
                .position(|c| c.is_boundary && c.ch == q_ch)
            {
                let pos = cursor + rel;
                positions.push(pos);
                cursor = pos + 1;
            } else {
                matched_acronym = false;
                break;
            }
        }
        if matched_acronym && positions[q_len - 1] - positions[0] < 32 {
            let score = score_fuzzy_positions(&cand, &positions);
            best_fuzzy = Some(best_fuzzy.map_or(score, |prev| prev.max(score)));
        }

        // Strategy 2: tight boundary-anchored subsequence (e.g. "dsc" -> "Discord").
        positions.clear();
        positions.push(start);
        let mut cursor = start + 1;
        let mut matched_tight = true;
        for &q_ch in &query_chars[1..] {
            if let Some(rel) = cand[cursor..].iter().position(|c| c.ch == q_ch) {
                let pos = cursor + rel;
                positions.push(pos);
                cursor = pos + 1;
            } else {
                matched_tight = false;
                break;
            }
        }
        if !matched_tight {
            continue;
        }

        let span = positions[q_len - 1] - positions[0] + 1;
        let gaps = span - q_len;
        let max_gap = positions
            .windows(2)
            .map(|w| w[1] - w[0] - 1)
            .max()
            .unwrap_or(0);
        let consecutive = positions.windows(2).filter(|w| w[1] == w[0] + 1).count();
        let boundary_hits = positions
            .iter()
            .filter(|&&pos| cand[pos].is_boundary)
            .count();

        let tight_enough = if q_len == 2 {
            gaps <= 1
        } else {
            gaps <= q_len && max_gap <= 3 && (consecutive >= 1 || boundary_hits >= 2)
        };

        if tight_enough {
            let score = score_fuzzy_positions(&cand, &positions);
            best_fuzzy = Some(best_fuzzy.map_or(score, |prev| prev.max(score)));
        }
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

    let query_chars: Vec<char> = to_lower_chars(trimmed).into_iter().map(|c| c.ch).collect();
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

/// Filters `apps` by `query` and sorts results by match relevance (boosting
/// actively running prefix/exact matches above non-running exact matches),
/// falling back to `(is_running desc, category asc, display_name lowercase asc)`
/// on ties (and when `query` is empty).
pub fn filter_and_rank_apps<'a>(apps: &'a [DiscoveredApp], query: &str) -> Vec<&'a DiscoveredApp> {
    let has_query = !query.trim().is_empty();
    let mut scored: Vec<(i32, &'a DiscoveredApp)> = apps
        .iter()
        .filter_map(|app| {
            fuzzy_score(query, app).map(|base_score| {
                let rank_score = if has_query && app.is_running {
                    if base_score >= 800 {
                        base_score + 250
                    } else if base_score >= 500 {
                        base_score + 100
                    } else {
                        base_score
                    }
                } else {
                    base_score
                };
                (rank_score, app)
            })
        })
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
        if pop == "Opera" {
            if trimmed == "Opera / Opera GX" {
                return 6;
            }
            if trimmed == "Opera GX" {
                return 5;
            }
        }
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
    negative_ttl: Duration,
    max_entries: usize,
    lookup_fn: Box<SocketLookupFn>,
}

impl fmt::Debug for ProcessSocketResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.len();
        f.debug_struct("ProcessSocketResolver")
            .field("ttl", &self.ttl)
            .field("negative_ttl", &self.negative_ttl)
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
    /// Creates a resolver with the default 1500ms positive TTL, 500ms negative TTL,
    /// and 1024-entry capacity backed by the host platform socket table lookup.
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
            negative_ttl: ttl.min(DEFAULT_NEGATIVE_SOCKET_CACHE_TTL),
            max_entries,
            lookup_fn: Box::new(lookup_fn),
        }
    }

    fn entry_ttl(&self, entry: &SocketCacheEntry) -> Duration {
        if entry.app_name.is_some() {
            self.ttl
        } else {
            self.negative_ttl
        }
    }

    /// Resolves the executable name owning `(local_ip, local_port, is_udp)`,
    /// canonicalizing IPv4-mapped IPv6 addresses, serving fresh hits from the
    /// in-memory TTL cache, and querying the OS socket table outside the cache
    /// lock on misses or expired entries.
    pub fn resolve(&self, local_ip: IpAddr, local_port: u16, is_udp: bool) -> Option<String> {
        let canonical_ip = local_ip.to_canonical();
        let key = SocketCacheKey {
            local_ip: canonical_ip,
            local_port,
            is_udp,
        };

        let cache_enabled = !self.ttl.is_zero() && self.max_entries > 0;
        let now = if cache_enabled {
            let now = Instant::now();
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = guard.get(&key) {
                if now.saturating_duration_since(entry.cached_at) < self.entry_ttl(entry) {
                    return entry.app_name.clone();
                }
            }
            Some(now)
        } else {
            None
        };

        let resolved = (self.lookup_fn)(canonical_ip, local_port, is_udp);

        if let Some(cached_at) = now {
            let mut guard = self
                .cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let should_insert = guard
                .get(&key)
                .is_none_or(|existing| existing.cached_at <= cached_at);
            if should_insert {
                if !guard.contains_key(&key) && guard.len() >= self.max_entries {
                    let prune_now = Instant::now();
                    let ttl = self.ttl;
                    let negative_ttl = self.negative_ttl;
                    guard.retain(|_, entry| {
                        let entry_ttl = if entry.app_name.is_some() {
                            ttl
                        } else {
                            negative_ttl
                        };
                        prune_now.saturating_duration_since(entry.cached_at) < entry_ttl
                    });
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

/// Expands a [`vdpi_core::config::SplitTunnelConfig`] with companion helper/launcher
/// executables (via [`companion_executables_for`]) for runtime matching without
/// mutating the user's persisted app list.
pub fn expand_split_tunnel_companions(
    split: &vdpi_core::config::SplitTunnelConfig,
) -> vdpi_core::config::SplitTunnelConfig {
    let mut expanded = split.clone();
    let mut seen: std::collections::HashSet<String> = expanded
        .apps
        .iter()
        .map(|app| normalize_exe(app))
        .filter(|n| !n.is_empty())
        .collect();

    for app in &split.apps {
        for &companion in companion_executables_for(app) {
            let norm = normalize_exe(companion);
            if !norm.is_empty() && seen.insert(norm) {
                expanded.apps.push(companion.to_string());
            }
        }
    }

    expanded
}

fn matches_split_app_with_companions(
    split: &vdpi_core::config::SplitTunnelConfig,
    exe_name: Option<&str>,
) -> bool {
    let Some(exe) = exe_name else {
        return false;
    };
    if split.apps.is_empty() {
        return false;
    }
    let target = NormalizedApp::from_raw(exe);
    if target.is_empty() {
        return false;
    }

    // Fast path: direct normalized match against `split.apps`.
    if split
        .apps
        .iter()
        .any(|app| NormalizedApp::from_raw(app).eq_normalized(&target))
    {
        return true;
    }

    // Companion path: `expand_split_tunnel_companions` appends bare companion
    // names from `COMPANION_GROUPS` (without `.app`), so `target` itself must
    // match a group member directly and some configured entry's companion stem
    // (with optional `.app` stripped) must belong to that same group.
    let Some(target_group) = COMPANION_GROUPS.iter().copied().find(|group| {
        group
            .iter()
            .any(|&member| target.eq_lowercase_ascii(member))
    }) else {
        return false;
    };

    split.apps.iter().any(|app| {
        let configured = NormalizedApp::from_raw(app);
        target_group
            .iter()
            .any(|&member| configured.stem_eq_lowercase_ascii(member))
    })
}

/// Evaluates split-tunnel bypass policy for `exe_name` with companion executable
/// expansion applied, without allocating on the hot path.
pub fn should_bypass_app_with_companions(
    split: &vdpi_core::config::SplitTunnelConfig,
    exe_name: Option<&str>,
) -> bool {
    match split.mode {
        vdpi_core::config::SplitTunnelMode::All => false,
        vdpi_core::config::SplitTunnelMode::Exclude => {
            matches_split_app_with_companions(split, exe_name)
        }
        vdpi_core::config::SplitTunnelMode::Include => {
            !matches_split_app_with_companions(split, exe_name)
        }
    }
}

fn has_configured_split_apps(split: &vdpi_core::config::SplitTunnelConfig) -> bool {
    split
        .apps
        .iter()
        .any(|app| !NormalizedApp::from_raw(app).is_empty())
}

fn build_tun_app_bypass_hook_with_resolver<F>(
    split: &vdpi_core::config::SplitTunnelConfig,
    resolver: F,
) -> Option<vdpi_tun::config::AppBypassHook>
where
    F: Fn(IpAddr, u16, bool) -> Option<String> + Send + Sync + 'static,
{
    match split.mode {
        vdpi_core::config::SplitTunnelMode::All => None,
        vdpi_core::config::SplitTunnelMode::Exclude => {
            if !has_configured_split_apps(split) {
                return None;
            }
            let cfg = split.clone();
            Some(vdpi_tun::config::AppBypassHook::new(
                move |src_ip, src_port, is_udp| {
                    let app = resolver(src_ip, src_port, is_udp);
                    should_bypass_app_with_companions(&cfg, app.as_deref())
                },
            ))
        }
        vdpi_core::config::SplitTunnelMode::Include => {
            if !has_configured_split_apps(split) {
                return Some(vdpi_tun::config::AppBypassHook::new(|_, _, _| true));
            }
            let cfg = split.clone();
            Some(vdpi_tun::config::AppBypassHook::new(
                move |src_ip, src_port, is_udp| {
                    let app = resolver(src_ip, src_port, is_udp);
                    should_bypass_app_with_companions(&cfg, app.as_deref())
                },
            ))
        }
    }
}

/// Builds an optional per-flow TUN bypass hook from `split` for desktop TUN
/// sessions. Returns `None` when split tunneling is in `All` mode or in
/// `Exclude` mode with no normalized target apps (zero OS lookups), and returns
/// a constant-`true` hook in `Include` mode with no normalized target apps
/// without touching OS socket/process tables.
pub fn build_tun_app_bypass_hook(
    split: &vdpi_core::config::SplitTunnelConfig,
) -> Option<vdpi_tun::config::AppBypassHook> {
    build_tun_app_bypass_hook_with_resolver(split, resolve_local_app)
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

    #[test]
    fn negative_socket_cache_expires_faster_than_positive_hits() {
        assert_eq!(DEFAULT_NEGATIVE_SOCKET_CACHE_TTL, Duration::from_millis(500));

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);

        let resolver = ProcessSocketResolver::with_lookup(
            Duration::from_millis(1500),
            16,
            move |_ip, port, _is_udp| {
                calls_ref.fetch_add(1, Ordering::SeqCst);
                if port == 40000 {
                    None
                } else {
                    Some("discord.exe".to_string())
                }
            },
        );

        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(resolver.resolve(ip, 40000, false), None);
        assert_eq!(resolver.resolve(ip, 40001, false).as_deref(), Some("discord.exe"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Within 500ms (even past the old 100ms mark) both stay cached
        thread::sleep(Duration::from_millis(150));
        assert_eq!(resolver.resolve(ip, 40000, false), None);
        assert_eq!(resolver.resolve(ip, 40001, false).as_deref(), Some("discord.exe"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // After ~550ms (> 500ms negative TTL, < 1500ms positive TTL), only None expires
        thread::sleep(Duration::from_millis(400));
        assert_eq!(resolver.resolve(ip, 40001, false).as_deref(), Some("discord.exe"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert_eq!(resolver.resolve(ip, 40000, false), None);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn process_socket_resolver_canonicalizes_ipv4_mapped_ipv6_and_stamps_before_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen_ips = Arc::new(Mutex::new(Vec::new()));
        let calls_ref = Arc::clone(&calls);
        let seen_ref = Arc::clone(&seen_ips);

        let resolver = ProcessSocketResolver::with_lookup(
            Duration::from_millis(500),
            16,
            move |ip, port, _is_udp| {
                calls_ref.fetch_add(1, Ordering::SeqCst);
                seen_ref.lock().unwrap().push(ip);
                Some(format!("app-{port}.exe"))
            },
        );

        let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let v4_mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());

        // Resolving via IPv4-mapped IPv6 passes canonical IPv4 to `lookup_fn` and
        // shares the exact same cache entry as native IPv4.
        assert_eq!(
            resolver.resolve(v4_mapped, 51234, false).as_deref(),
            Some("app-51234.exe")
        );
        assert_eq!(
            resolver.resolve(v4, 51234, false).as_deref(),
            Some("app-51234.exe")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*seen_ips.lock().unwrap(), vec![v4]);

        // Reverse order: native IPv4 warms the cache for IPv4-mapped IPv6 too.
        let lan_v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let lan_mapped = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped());
        assert_eq!(
            resolver.resolve(lan_v4, 51235, true).as_deref(),
            Some("app-51235.exe")
        );
        assert_eq!(
            resolver.resolve(lan_mapped, 51235, true).as_deref(),
            Some("app-51235.exe")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(*seen_ips.lock().unwrap(), vec![v4, lan_v4]);

        // `cached_at` is captured BEFORE invoking `lookup_fn`: a 45ms lookup with a
        // 60ms TTL must expire after sleeping 25ms (45 + 25 = 70ms >= 60ms).
        let slow_calls = Arc::new(AtomicUsize::new(0));
        let slow_calls_ref = Arc::clone(&slow_calls);
        let slow_resolver = ProcessSocketResolver::with_lookup(
            Duration::from_millis(60),
            16,
            move |_ip, _port, _is_udp| {
                slow_calls_ref.fetch_add(1, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(45));
                Some("slow.exe".to_string())
            },
        );
        assert_eq!(
            slow_resolver.resolve(v4, 60000, false).as_deref(),
            Some("slow.exe")
        );
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);

        thread::sleep(Duration::from_millis(25));
        assert_eq!(
            slow_resolver.resolve(v4, 60000, false).as_deref(),
            Some("slow.exe")
        );
        assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn companion_executables_expand_bidirectionally_across_platforms() {
        assert!(companion_executables_for("unknown.exe").is_empty());
        assert!(companion_executables_for("").is_empty());

        // Every member in every companion group must resolve symmetrically to its full group.
        for &group in COMPANION_GROUPS {
            assert!(group.len() >= 2);
            for &member in group {
                let resolved = companion_executables_for(member);
                assert_eq!(
                    resolved, group,
                    "companion_executables_for({member:?}) must be symmetric"
                );
                let with_exe = format!("{member}.exe");
                assert_eq!(companion_executables_for(&with_exe), group);
                let with_app = format!("{member}.app");
                assert_eq!(companion_executables_for(&with_app), group);
            }
        }

        // Discord group bidirectional expansion (Windows, macOS, Linux/Flatpak)
        let discord_from_flatpak = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["com.discordapp.Discord".to_string()],
        };
        for member in [
            "Discord.exe",
            "DiscordPTB.exe",
            "DiscordCanary.exe",
            "discord_clips.exe",
            "Discord Helper",
            "com.discordapp.Discord",
        ] {
            assert!(
                should_bypass_app_with_companions(&discord_from_flatpak, Some(member)),
                "expected Discord Flatpak selection to cover {member}"
            );
        }
        let discord_from_helper = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["Discord Helper".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &discord_from_helper,
            Some("Discord.exe")
        ));
        assert!(should_bypass_app_with_companions(
            &discord_from_helper,
            Some("com.discordapp.Discord")
        ));

        // Roblox group bidirectional expansion (Windows, macOS, Sober Flatpak, Bloxstrap, Fishstrap)
        let roblox_from_fishstrap = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["Fishstrap.exe".to_string()],
        };
        for member in [
            "RobloxPlayerBeta.exe",
            "RobloxPlayerLauncher.exe",
            "RobloxPlayerInstaller.exe",
            "Bloxstrap.exe",
            "Fishstrap.exe",
            "RobloxPlayer",
            "org.vinegarhq.Sober",
        ] {
            assert!(
                should_bypass_app_with_companions(&roblox_from_fishstrap, Some(member)),
                "expected Fishstrap selection to cover {member}"
            );
        }
        let roblox_from_sober = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["org.vinegarhq.Sober".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &roblox_from_sober,
            Some("RobloxPlayerBeta.exe")
        ));

        // Riot / Valorant / Vanguard / League bidirectional expansion
        let riot_from_valorant = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["VALORANT-Win64-Shipping.exe".to_string()],
        };
        for member in [
            "RiotClientServices.exe",
            "RiotClientUx.exe",
            "RiotClientUxRender.exe",
            "RiotClientCrashHandler.exe",
            "VALORANT.exe",
            "VALORANT-Win64-Shipping.exe",
            "vgc.exe",
            "vgm.exe",
            "vgtray.exe",
            "LeagueClient.exe",
            "LeagueClientUx.exe",
            "LeagueClientUxRender.exe",
            "League of Legends.exe",
        ] {
            assert!(
                should_bypass_app_with_companions(&riot_from_valorant, Some(member)),
                "expected VALORANT selection to cover {member}"
            );
        }
        let riot_from_vgc = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: vec!["vgc.exe".to_string()],
        };
        // Include mode: Riot companions stay included (not bypassed), unrelated apps bypass.
        assert!(!should_bypass_app_with_companions(
            &riot_from_vgc,
            Some("RiotClientServices.exe")
        ));
        assert!(!should_bypass_app_with_companions(
            &riot_from_vgc,
            Some("League of Legends.exe")
        ));
        assert!(should_bypass_app_with_companions(
            &riot_from_vgc,
            Some("chrome.exe")
        ));

        // Steam group bidirectional expansion
        let steam_from_overlay = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["GameOverlayUI.exe".to_string()],
        };
        for member in [
            "steam.exe",
            "steam_osx",
            "steamwebhelper.exe",
            "steamservice.exe",
            "GameOverlayUI.exe",
            "com.valvesoftware.Steam",
        ] {
            assert!(
                should_bypass_app_with_companions(&steam_from_overlay, Some(member)),
                "expected GameOverlayUI selection to cover {member}"
            );
        }

        // Epic group bidirectional expansion
        let epic_from_eos = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["EOSOverlayRenderer-Win64-Shipping.exe".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &epic_from_eos,
            Some("EpicGamesLauncher.exe")
        ));
        assert!(should_bypass_app_with_companions(
            &epic_from_eos,
            Some("EpicWebHelper.exe")
        ));

        // Browser Flatpak bridges (bidirectional)
        let firefox_flatpak = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["org.mozilla.firefox".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &firefox_flatpak,
            Some("firefox.exe")
        ));
        let chrome_native = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["google-chrome".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &chrome_native,
            Some("com.google.Chrome")
        ));
        assert!(should_bypass_app_with_companions(
            &chrome_native,
            Some("chrome.exe")
        ));
        let chromium_flatpak = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["org.chromium.Chromium".to_string()],
        };
        assert!(should_bypass_app_with_companions(
            &chromium_flatpak,
            Some("chromium")
        ));
        assert!(!should_bypass_app_with_companions(
            &chromium_flatpak,
            Some("firefox")
        ));
    }

    #[test]
    fn canonical_exe_entry_strips_shortcut_cli_arguments() {
        assert_eq!(
            canonical_exe_entry(
                r#""C:\Riot Games\Riot Client\RiotClientServices.exe" --launch-product=valorant --launch-patchline=live"#
            ),
            Some("RiotClientServices.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry(
                r#""C:\Program Files\Discord\Discord.exe" --profile="Work Profile""#
            ),
            Some("Discord.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry("'/usr/bin/firefox' --new-window --private-window"),
            Some("firefox".to_string())
        );
        assert_eq!(
            canonical_exe_entry(
                r"C:\Riot Games\Riot Client\RiotClientServices.exe --launch-product=valorant"
            ),
            Some("RiotClientServices.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry("Discord.exe --start-minimized"),
            Some("Discord.exe".to_string())
        );
        assert_eq!(
            canonical_exe_entry(r"C:\Games\VALORANT.EXE /silent"),
            Some("VALORANT.EXE".to_string())
        );
        assert_eq!(
            canonical_exe_entry("/Applications/Google Chrome.app --incognito"),
            Some("Google Chrome.app".to_string())
        );
        assert_eq!(
            canonical_exe_entry("/usr/bin/firefox --new-window"),
            Some("firefox".to_string())
        );
        assert_eq!(
            canonical_exe_entry("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Some("Google Chrome".to_string())
        );
        assert_eq!(
            canonical_exe_entry("League of Legends"),
            Some("League of Legends".to_string())
        );
        assert_eq!(
            canonical_exe_entry(r#""" --launch-product=valorant"#),
            None
        );
    }

    #[test]
    fn search_ranking_boosts_running_prefix_and_rejects_noisy_fuzzy_and_handles_turkish_i() {
        let apps = vec![
            make_app("Discord", "Discord.exe", None, false, AppCategory::Popular),
            make_app(
                "Discord PTB",
                "DiscordPTB.exe",
                None,
                true,
                AppCategory::Running,
            ),
        ];
        let ranked = filter_and_rank_apps(&apps, "discord");
        assert_eq!(ranked[0].exe_name, "DiscordPTB.exe");
        assert_eq!(ranked[1].exe_name, "Discord.exe");

        let nvidia = make_app(
            "NVIDIA GeForce NOW",
            "GeForceNOW.exe",
            None,
            false,
            AppCategory::Installed,
        );
        let dotnet = make_app(
            ".NET Windows Desktop Runtime",
            "dotnet.exe",
            None,
            false,
            AppCategory::Installed,
        );
        let ms_dotnet = make_app(
            "Microsoft Windows Desktop Runtime",
            "dotnet.exe",
            None,
            false,
            AppCategory::Installed,
        );
        assert_eq!(fuzzy_score("vgc", &nvidia), None);
        assert_eq!(fuzzy_score("riot", &dotnet), None);
        assert_eq!(fuzzy_score("riot", &ms_dotnet), None);

        // Turkish capital dotted İ (`i\u{0307}`) and dotless ı (`\u{0131}`) normalize to ASCII `i`
        let turkish_app = make_app("İstanbul App", "istanbul.exe", None, false, AppCategory::Installed);
        assert_eq!(fuzzy_score("istanbul app", &turkish_app), Some(1000));
        assert_eq!(fuzzy_score("İSTANBUL APP", &turkish_app), Some(1000));
        let discord = make_app("Discord", "Discord.exe", None, false, AppCategory::Popular);
        assert_eq!(fuzzy_score("DİSCORD", &discord), Some(1000));
        assert_eq!(fuzzy_score("dıscord", &discord), Some(1000));

        let riot = make_app(
            "Riot Client",
            "RiotClientServices.exe",
            None,
            false,
            AppCategory::Popular,
        );
        assert_eq!(fuzzy_score("rıot", &riot), Some(800));

        let bank = make_app(
            "Garanti Bankası",
            "garanti.exe",
            None,
            false,
            AppCategory::Installed,
        );
        assert_eq!(fuzzy_score("bankasi", &bank), Some(650));
        assert_eq!(fuzzy_score("bankası", &bank), Some(650));

        let bank_exact = make_app("Bankası", "bank.exe", None, false, AppCategory::Installed);
        assert_eq!(fuzzy_score("bankasi", &bank_exact), Some(1000));
    }

    #[test]
    fn should_bypass_app_with_companions_matches_expanded_config_exactly() {
        let mut seen_members = std::collections::HashSet::new();
        for &group in COMPANION_GROUPS {
            for &member in group {
                assert!(!member.is_empty());
                assert!(member.is_ascii());
                assert_eq!(normalize_exe(member), member);
                assert!(!member.ends_with(".app"));
                assert!(
                    seen_members.insert(member),
                    "duplicate companion member {member:?} across COMPANION_GROUPS"
                );
            }
        }

        let mut app_lists: Vec<Vec<&str>> = vec![
            vec![],
            vec!["", "   ", ".exe", "\"\"", "' '", r"C:\dir\"],
            vec![".app"],
            vec!["Discord.exe"],
            vec!["Discord.app"],
            vec!["Discord.APP"],
            vec!["Discord.app.exe"],
            vec!["Discord.exe.app"],
            vec!["Discord .exe"],
            vec!["Discord .app"],
            vec!["DİSCORD.EXE"],
            vec!["dıscord.exe"],
            vec!["DİSCORD.APP"],
            vec![r#" "C:\Program Files\Discord\Discord.exe" "#],
            vec![r"C:\Users\İstanbul\Discord.exe"],
            vec!["com.discordapp.Discord"],
            vec!["Fishstrap.exe"],
            vec!["VALORANT-Win64-Shipping.exe"],
            vec!["RİOTCLİENTSERVİCES.EXE"],
            vec!["GameOverlayUI.exe"],
            vec!["EOSOverlayRenderer-Win64-Shipping.exe"],
            vec!["'/usr/bin/firefox'"],
            vec!["Google Chrome.app"],
            vec!["org.chromium.Chromium"],
            vec!["customapp.exe"],
            vec!["İstanbul.exe"],
            vec!["ΜΟΥΣΙΚΗ.exe"],
            vec!["Discord.exe", "customapp.exe", "   ", "org.mozilla.firefox"],
        ];
        for &group in COMPANION_GROUPS {
            for &member in group {
                app_lists.push(vec![member]);
            }
        }

        let mut probes: Vec<Option<&str>> = vec![
            None,
            Some(""),
            Some("   "),
            Some(".exe"),
            Some("\"\""),
            Some(".app"),
            Some(r"C:\dir\"),
            Some("Discord.exe"),
            Some("DISCORD.EXE"),
            Some("Discord .exe"),
            Some("Discord.app"),
            Some("Discord.APP"),
            Some("DiscordPTB.exe"),
            Some("DiscordPTB.app"),
            Some("Discord.app.exe"),
            Some("Discord.exe.app"),
            Some("Discord .app"),
            Some("DİSCORD.EXE"),
            Some("dıscordptb.exe"),
            Some("DİSCORD.APP"),
            Some(r#" 'C:\Users\Alice\AppData\Local\DiscordPTB\DiscordPTB.exe' "#),
            Some(r"C:\Users\İstanbul\DiscordPTB.exe"),
            Some("RobloxPlayerBeta.exe"),
            Some("org.vinegarhq.Sober"),
            Some("RiotClientServices.exe"),
            Some("League of Legends.exe"),
            Some("steamwebhelper.exe"),
            Some("EpicGamesLauncher.exe"),
            Some("firefox.exe"),
            Some("Google Chrome"),
            Some("Google Chrome.app"),
            Some("com.google.Chrome"),
            Some("chromium"),
            Some("customapp.exe"),
            Some("CUSTOMAPP"),
            Some("İstanbul.exe"),
            Some("istanbul.exe"),
            Some("ΜΟΥΣΙΚΗ.exe"),
            Some("μουσικη.exe"),
            Some("notepad.exe"),
            Some("spotify.exe"),
        ];
        for &group in COMPANION_GROUPS {
            for &member in group {
                probes.push(Some(member));
            }
        }

        let modes = [
            vdpi_core::config::SplitTunnelMode::All,
            vdpi_core::config::SplitTunnelMode::Exclude,
            vdpi_core::config::SplitTunnelMode::Include,
        ];

        for mode in modes {
            for apps in &app_lists {
                let cfg = vdpi_core::config::SplitTunnelConfig {
                    mode,
                    apps: apps.iter().map(|s| (*s).to_string()).collect(),
                };
                let expanded = expand_split_tunnel_companions(&cfg);
                for &exe in &probes {
                    let expected = expanded.should_bypass_app(exe);
                    let actual = should_bypass_app_with_companions(&cfg, exe);
                    assert_eq!(
                        actual, expected,
                        "mismatch for mode={mode:?}, apps={apps:?}, exe={exe:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn build_tun_app_bypass_hook_uses_companion_policy_and_skips_all_mode() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        let all_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::All,
            apps: vec!["Discord.exe".to_string()],
        };
        assert!(build_tun_app_bypass_hook(&all_cfg).is_none());

        let exclude_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["Discord.exe".to_string()],
        };
        let exclude_hook = build_tun_app_bypass_hook_with_resolver(&exclude_cfg, |_ip, port, _| {
            match port {
                1000 => Some("Discord.exe".to_string()),
                1001 => Some("DiscordPTB.exe".to_string()),
                1002 => Some("chrome.exe".to_string()),
                _ => None,
            }
        })
        .expect("exclude mode should produce hook");
        assert!(exclude_hook.should_bypass(ip, 1000, false));
        assert!(exclude_hook.should_bypass(ip, 1001, true));
        assert!(!exclude_hook.should_bypass(ip, 1002, false));
        assert!(!exclude_hook.should_bypass(ip, 1003, false));

        let include_cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Include,
            apps: vec!["vgc.exe".to_string()],
        };
        let include_hook = build_tun_app_bypass_hook_with_resolver(&include_cfg, |_ip, port, _| {
            match port {
                2000 => Some("RiotClientServices.exe".to_string()),
                2001 => Some("chrome.exe".to_string()),
                _ => None,
            }
        })
        .expect("include mode should produce hook");
        assert!(!include_hook.should_bypass(ip, 2000, false));
        assert!(include_hook.should_bypass(ip, 2001, false));
        assert!(include_hook.should_bypass(ip, 2002, true));
    }

    #[test]
    fn build_tun_app_bypass_hook_empty_normalized_apps_skips_os_lookups() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        for empty_apps in [
            vec![],
            vec![
                "".to_string(),
                "   ".to_string(),
                ".exe".to_string(),
                "\"\"".to_string(),
                r"C:\dir\".to_string(),
            ],
        ] {
            let exclude_calls = Arc::new(AtomicUsize::new(0));
            let exclude_calls_ref = Arc::clone(&exclude_calls);
            let exclude_cfg = vdpi_core::config::SplitTunnelConfig {
                mode: vdpi_core::config::SplitTunnelMode::Exclude,
                apps: empty_apps.clone(),
            };
            let exclude_hook =
                build_tun_app_bypass_hook_with_resolver(&exclude_cfg, move |_ip, _port, _| {
                    exclude_calls_ref.fetch_add(1, Ordering::SeqCst);
                    Some("Discord.exe".to_string())
                });
            assert!(
                exclude_hook.is_none(),
                "Exclude mode with empty normalized app list {empty_apps:?} must return None"
            );
            assert_eq!(exclude_calls.load(Ordering::SeqCst), 0);

            let include_calls = Arc::new(AtomicUsize::new(0));
            let include_calls_ref = Arc::clone(&include_calls);
            let include_cfg = vdpi_core::config::SplitTunnelConfig {
                mode: vdpi_core::config::SplitTunnelMode::Include,
                apps: empty_apps.clone(),
            };
            let include_hook =
                build_tun_app_bypass_hook_with_resolver(&include_cfg, move |_ip, _port, _| {
                    include_calls_ref.fetch_add(1, Ordering::SeqCst);
                    Some("Discord.exe".to_string())
                })
                .expect("Include mode with empty normalized app list must return constant-true hook");
            assert!(include_hook.should_bypass(ip, 1234, false));
            assert!(include_hook.should_bypass(ip, 5678, true));
            assert_eq!(include_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn popular_apps_and_companions_include_macos_discord_variants_and_safari() {
        assert_eq!(popular_app_display_name("Discord PTB.app"), Some("Discord PTB"));
        assert_eq!(
            popular_app_display_name("Discord Canary.app"),
            Some("Discord Canary")
        );
        assert_eq!(popular_app_display_name("Safari.app"), Some("Safari"));
        assert!(is_popular_app("safari"));

        let cfg = vdpi_core::config::SplitTunnelConfig {
            mode: vdpi_core::config::SplitTunnelMode::Exclude,
            apps: vec!["Discord".to_string()],
        };
        assert!(should_bypass_app_with_companions(&cfg, Some("Discord PTB")));
        assert!(should_bypass_app_with_companions(
            &cfg,
            Some("Discord Canary")
        ));
    }
}
