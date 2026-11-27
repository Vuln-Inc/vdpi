use std::collections::HashSet;
use std::path::Path;

use vdpi::config_file::{
    load_file_config_or_default, sanitize_split_tunnel_apps, save_file_config_atomic,
    system_config_path, user_config_path, validate_split_tunnel_apps, FileConfig,
    CONFIG_SCHEMA_VERSION, MAX_SPLIT_TUNNEL_APPS,
};
use vdpi::service::{detect_service_state, load_configured_split_tunnel, ServiceState};
use vdpi::split_tunnel::{
    companion_executables_for, discover_apps, normalize_exe, AppCategory, DiscoveredApp,
};
use vdpi_core::config::{SplitTunnelConfig, SplitTunnelMode};
use vdpi_core::dns::redact_urls_in_text;

use crate::models::{
    ActionResultDto, AppCategoryDto, DiscoveredAppItemDto, SplitTunnelModeDto,
    SplitTunnelPayloadDto, SplitTunnelPresetDto, SplitTunnelSaveRequestDto,
};
use crate::sidecar::{apply_config_via_temp_file, SidecarOutcome};

const EMPTY_INCLUDE_WARNING: &str =
    "Warning: empty Include protects no apps until at least one application is added.";

const BROWSER_EXES: &[&str] = &[
    "chrome",
    "google chrome",
    "google-chrome",
    "google-chrome-stable",
    "com.google.chrome",
    "msedge",
    "microsoft edge",
    "microsoft-edge",
    "microsoft-edge-stable",
    "com.microsoft.edge",
    "firefox",
    "firefox-bin",
    "firefox-esr",
    "org.mozilla.firefox",
    "librewolf",
    "waterfox",
    "floorp",
    "zen",
    "zen-bin",
    "brave",
    "brave browser",
    "brave-browser",
    "com.brave.browser",
    "opera",
    "opera_gx",
    "opera gx",
    "com.opera.opera",
    "vivaldi",
    "vivaldi-bin",
    "com.vivaldi.vivaldi",
    "arc",
    "safari",
    "chromium",
    "chromium-browser",
    "org.chromium.chromium",
    "torbrowser",
    "mullvadbrowser",
    "yandex",
];

const COMMUNICATION_EXES: &[&str] = &[
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
    "vesktop",
    "dev.vencord.vesktop",
    "armcord",
    "telegram",
    "telegram-desktop",
    "telegram desktop",
    "org.telegram.desktop",
    "whatsapp",
    "whatsapp.root",
    "slack",
    "com.slack.slack",
    "zoom",
    "zoom.us",
    "us.zoom.zoom",
    "signal",
    "signal-desktop",
    "org.signal.signal",
    "teams",
    "ms-teams",
    "msteams",
    "teams-for-linux",
    "skype",
    "element",
    "element-desktop",
    "im.riot.riot",
    "teamspeak",
    "ts3client_win64",
    "ts3client_win32",
    "ts5client",
    "mumble",
    "guilded",
    "viber",
    "wechat",
    "thunderbird",
    "mailspring",
    "outlook",
    "olk",
];

const GAME_EXES: &[&str] = &[
    "robloxplayerbeta",
    "robloxplayerlauncher",
    "robloxplayerinstaller",
    "robloxplayer",
    "bloxstrap",
    "fishstrap",
    "sober",
    "org.vinegarhq.sober",
    "steam",
    "steam_osx",
    "steamwebhelper",
    "steamservice",
    "gameoverlayui",
    "com.valvesoftware.steam",
    "epicgameslauncher",
    "epic games launcher",
    "epicwebhelper",
    "eosoverlayrenderer-win64-shipping",
    "riotclientservices",
    "riotclientux",
    "riotclientuxrender",
    "riot client",
    "valorant",
    "valorant-win64-shipping",
    "vgc",
    "vgtray",
    "leagueclient",
    "leagueclientux",
    "leagueclientuxrender",
    "league of legends",
    "battle.net",
    "battlenet",
    "eadesktop",
    "eabackgroundservice",
    "origin",
    "upc",
    "ubisoftconnect",
    "galaxyclient",
    "playnite.desktopapp",
    "heroic",
    "com.heroicgameslauncher.hgl",
    "lutris",
    "net.lutris.lutris",
    "prismlauncher",
    "org.prismlauncher.prismlauncher",
    "minecraft",
    "minecraftlauncher",
    "minecraft-launcher",
    "curseforge",
    "overwolf",
    "cs2",
    "csgo",
    "dota2",
    "fortniteclient-win64-shipping",
    "r5apex",
    "genshinimpact",
    "starrail",
    "gta5",
    "gtav",
    "fivem",
    "tslgame",
    "overwatch",
    "rocketleague",
    "eldenring",
    "cyberpunk2077",
    "warframe.x64",
    "destiny2",
    "rainbowsix",
    "osu!",
    "osu",
];

const MEDIA_EXES: &[&str] = &[
    "obs",
    "obs64",
    "obs32",
    "obs studio",
    "com.obsproject.studio",
    "streamlabs obs",
    "streamlabs",
    "spotify",
    "com.spotify.client",
    "vlc",
    "org.videolan.vlc",
    "mpv",
    "io.mpv.mpv",
    "mpc-hc",
    "mpc-hc64",
    "mpc-be",
    "mpc-be64",
    "potplayer",
    "potplayermini64",
    "kodi",
    "plex",
    "plexmediaplayer",
    "jellyfinmediaplayer",
    "itunes",
    "applemusic",
    "tidal",
    "deezer",
    "foobar2000",
    "aimp",
    "winamp",
    "audacity",
    "handbrake",
    "davinci resolve",
    "resolve",
    "adobe premiere pro",
    "afterfx",
    "stremio",
    "freetube",
    "twitch",
    "medal",
];

fn current_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn preset(
    id: &str,
    label: &str,
    description: &str,
    apps: &[&str],
    group_tag: &str,
) -> SplitTunnelPresetDto {
    SplitTunnelPresetDto {
        id: id.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        apps: apps.iter().map(|s| (*s).to_string()).collect(),
        group_tag: group_tag.to_string(),
    }
}

fn curated_presets_for_platform(platform: &str) -> Vec<SplitTunnelPresetDto> {
    match platform {
        "windows" => vec![
            preset(
                "discord",
                "Discord",
                "Discord stable, PTB, and Canary voice/chat clients",
                &["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
                "communication",
            ),
            preset(
                "roblox",
                "Roblox",
                "Roblox Player, launcher, and Bloxstrap",
                &[
                    "RobloxPlayerBeta.exe",
                    "RobloxPlayerLauncher.exe",
                    "Bloxstrap.exe",
                ],
                "games",
            ),
            preset(
                "valorant-riot",
                "Valorant & Riot",
                "Valorant, Riot Client, Vanguard, and League of Legends",
                &[
                    "VALORANT.exe",
                    "VALORANT-Win64-Shipping.exe",
                    "RiotClientServices.exe",
                    "RiotClientUx.exe",
                    "vgc.exe",
                    "vgtray.exe",
                    "LeagueClient.exe",
                    "League of Legends.exe",
                ],
                "games",
            ),
            preset(
                "steam",
                "Steam",
                "Steam client, web helper, and in-game overlay",
                &["steam.exe", "steamwebhelper.exe", "GameOverlayUI.exe"],
                "games",
            ),
            preset(
                "web-browsers",
                "Web Browsers",
                "Chrome, Edge, Firefox, Brave, Opera, and Vivaldi",
                &[
                    "chrome.exe",
                    "msedge.exe",
                    "firefox.exe",
                    "brave.exe",
                    "opera.exe",
                    "vivaldi.exe",
                ],
                "browsers",
            ),
            preset(
                "obs-studio",
                "OBS Studio",
                "OBS Studio 64-bit and 32-bit streaming and recording",
                &["obs64.exe", "obs32.exe"],
                "media",
            ),
        ],
        "macos" => vec![
            preset(
                "discord",
                "Discord",
                "Discord stable, PTB, and Canary voice/chat clients",
                &["Discord", "Discord PTB", "Discord Canary"],
                "communication",
            ),
            preset(
                "roblox",
                "Roblox",
                "Roblox Player and installer on macOS",
                &["RobloxPlayer", "RobloxPlayerInstaller"],
                "games",
            ),
            preset(
                "league-of-legends",
                "League of Legends",
                "Riot Client and League of Legends on macOS",
                &[
                    "RiotClientServices",
                    "RiotClientUx",
                    "LeagueClient",
                    "League of Legends",
                ],
                "games",
            ),
            preset(
                "steam",
                "Steam",
                "Steam client and web helper on macOS",
                &["steam_osx", "Steam", "steamwebhelper"],
                "games",
            ),
            preset(
                "web-browsers",
                "Web Browsers",
                "Chrome, Safari, Firefox, Brave, Edge, and Arc",
                &[
                    "Google Chrome",
                    "Safari",
                    "firefox",
                    "Brave Browser",
                    "Microsoft Edge",
                    "Arc",
                ],
                "browsers",
            ),
            preset(
                "obs-studio",
                "OBS Studio",
                "OBS Studio streaming and recording",
                &["OBS"],
                "media",
            ),
        ],
        _ => vec![
            preset(
                "discord",
                "Discord",
                "Discord native, Flatpak, and Vesktop voice/chat clients",
                &[
                    "discord",
                    "discord-ptb",
                    "discord-canary",
                    "com.discordapp.Discord",
                    "vesktop",
                    "dev.vencord.Vesktop",
                ],
                "communication",
            ),
            preset(
                "roblox",
                "Roblox",
                "Roblox via Sober native and Flatpak runtime",
                &["sober", "org.vinegarhq.Sober"],
                "games",
            ),
            preset(
                "linux-gaming",
                "Linux Gaming",
                "Heroic Games Launcher, Lutris, and Prism Launcher (native and Flatpak)",
                &[
                    "heroic",
                    "com.heroicgameslauncher.hgl",
                    "lutris",
                    "net.lutris.Lutris",
                    "prismlauncher",
                    "org.prismlauncher.PrismLauncher",
                ],
                "games",
            ),
            preset(
                "steam",
                "Steam",
                "Steam native, web helper, and Flatpak client",
                &["steam", "steamwebhelper", "com.valvesoftware.Steam"],
                "games",
            ),
            preset(
                "web-browsers",
                "Web Browsers",
                "Firefox, Chrome, Chromium, Brave, Vivaldi, and Opera (native and Flatpak)",
                &[
                    "firefox",
                    "firefox-esr",
                    "org.mozilla.firefox",
                    "google-chrome",
                    "google-chrome-stable",
                    "com.google.Chrome",
                    "chromium",
                    "chromium-browser",
                    "brave-browser",
                    "com.brave.Browser",
                    "vivaldi-bin",
                    "opera",
                ],
                "browsers",
            ),
            preset(
                "obs-studio",
                "OBS Studio",
                "OBS Studio native and Flatpak streaming/recording",
                &["obs", "com.obsproject.Studio"],
                "media",
            ),
        ],
    }
}

/// Returns curated one-click split-tunnel presets with platform-appropriate executable names.
pub fn curated_presets() -> Vec<SplitTunnelPresetDto> {
    curated_presets_for_platform(current_platform())
}

/// Classifies an application into a UI group tag:
/// `"games"`, `"browsers"`, `"communication"`, `"media"`, or `"other"`.
pub fn classify_group_tag(exe_name: &str, display_name: &str) -> &'static str {
    let norm = normalize_exe(exe_name);
    let stem = norm.strip_suffix(".app").unwrap_or(&norm);

    if BROWSER_EXES.contains(&stem) {
        return "browsers";
    }
    if COMMUNICATION_EXES.contains(&stem) {
        return "communication";
    }
    if GAME_EXES.contains(&stem)
        || stem.ends_with("-win64-shipping")
        || stem.ends_with("-win32-shipping")
    {
        return "games";
    }
    if MEDIA_EXES.contains(&stem) {
        return "media";
    }

    let display = display_name.trim().to_ascii_lowercase();

    if display == "arc"
        || display == "arc browser"
        || [
            "chrome",
            "chromium",
            "firefox",
            "microsoft edge",
            "msedge",
            "brave",
            "opera",
            "vivaldi",
            "safari",
            "librewolf",
            "waterfox",
            "floorp",
            "browser",
        ]
        .iter()
        .any(|kw| display.contains(kw))
    {
        return "browsers";
    }

    if display == "signal"
        || display == "teams"
        || display == "zoom"
        || [
            "discord",
            "telegram",
            "whatsapp",
            "slack",
            "zoom.us",
            "zoom workplace",
            "zoom meetings",
            "signal desktop",
            "microsoft teams",
            "skype",
            "teamspeak",
            "mumble",
            "guilded",
            "viber",
            "thunderbird",
            "vesktop",
        ]
        .iter()
        .any(|kw| display.contains(kw))
    {
        return "communication";
    }

    if [
        "roblox",
        "bloxstrap",
        "steam",
        "valorant",
        "riot client",
        "riot games",
        "league of legends",
        "epic games",
        "battle.net",
        "ea app",
        "ubisoft",
        "minecraft",
        "fortnite",
        "counter-strike",
        "dota",
        "apex legends",
        "genshin",
        "overwatch",
        "rocket league",
        "playnite",
        "heroic",
        "lutris",
        "curseforge",
        "xbox",
    ]
    .iter()
    .any(|kw| display.contains(kw))
    {
        return "games";
    }

    if display == "obs"
        || display == "vlc"
        || display == "mpv"
        || [
            "obs studio",
            "obs-studio",
            "streamlabs",
            "spotify",
            "vlc media",
            "mpv media",
            "media player",
            "potplayer",
            "kodi",
            "plex",
            "jellyfin",
            "tidal",
            "deezer",
            "audacity",
            "stremio",
            "freetube",
            "apple music",
            "itunes",
        ]
        .iter()
        .any(|kw| display.contains(kw))
    {
        return "media";
    }

    "other"
}

fn mode_to_dto(mode: SplitTunnelMode) -> SplitTunnelModeDto {
    match mode {
        SplitTunnelMode::All => SplitTunnelModeDto::All,
        SplitTunnelMode::Exclude => SplitTunnelModeDto::Exclude,
        SplitTunnelMode::Include => SplitTunnelModeDto::Include,
    }
}

fn mode_from_dto(mode: SplitTunnelModeDto) -> SplitTunnelMode {
    match mode {
        SplitTunnelModeDto::All => SplitTunnelMode::All,
        SplitTunnelModeDto::Exclude => SplitTunnelMode::Exclude,
        SplitTunnelModeDto::Include => SplitTunnelMode::Include,
    }
}

fn category_to_dto(category: AppCategory) -> AppCategoryDto {
    match category {
        AppCategory::Popular => AppCategoryDto::Popular,
        AppCategory::Running => AppCategoryDto::Running,
        AppCategory::Installed => AppCategoryDto::Installed,
        AppCategory::Custom => AppCategoryDto::Custom,
    }
}

fn is_flatpak_app_id(name: &str) -> bool {
    let mut parts = name.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    let Some(third) = parts.next() else {
        return false;
    };
    !second.is_empty()
        && !third.is_empty()
        && matches!(
            first,
            "com" | "org" | "io" | "net" | "app" | "us" | "im" | "me" | "dev" | "tv"
        )
}

fn is_companion_for_platform(companion: &str, platform: &str) -> bool {
    let lower = companion.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }

    // Reverse-DNS Flatpak app IDs (e.g. `com.discordapp.discord`, `org.vinegarhq.sober`)
    // are Linux-only.
    if is_flatpak_app_id(&lower) {
        return platform == "linux";
    }

    // Windows-specific suffixes and executables.
    if lower.ends_with("-win64-shipping")
        || lower.ends_with("-win32-shipping")
        || matches!(
            lower.as_str(),
            "discordptb"
                | "discordcanary"
                | "discord_clips"
                | "robloxplayerbeta"
                | "robloxplayerlauncher"
                | "bloxstrap"
                | "fishstrap"
                | "valorant"
                | "vgc"
                | "vgtray"
                | "steamservice"
                | "epicgameslauncher"
                | "chrome"
        )
    {
        return platform == "windows";
    }

    // macOS-specific helper/bundle executables.
    if lower.ends_with(" helper")
        || lower.ends_with("_osx")
        || matches!(
            lower.as_str(),
            "discord ptb"
                | "discord canary"
                | "robloxplayer"
                | "epic games launcher"
                | "google chrome"
        )
    {
        return platform == "macos";
    }

    // Linux-specific native binary names and runtimes.
    if matches!(
        lower.as_str(),
        "discord-ptb"
            | "discord-canary"
            | "sober"
            | "firefox-bin"
            | "firefox-esr"
            | "google-chrome"
            | "google-chrome-stable"
            | "chromium-browser"
    ) {
        return platform == "linux";
    }

    // Executables shared between Windows and macOS only (not available natively on Linux).
    if matches!(
        lower.as_str(),
        "robloxplayerinstaller"
            | "riotclientservices"
            | "riotclientux"
            | "riotclientuxrender"
            | "leagueclient"
            | "leagueclientux"
            | "leagueclientuxrender"
            | "league of legends"
            | "epicwebhelper"
    ) {
        return matches!(platform, "windows" | "macos");
    }

    // Cross-platform executables (`discord`, `steam`, `steamwebhelper`, `gameoverlayui`,
    // `firefox`, `chromium`, etc.) apply on all desktop platforms.
    true
}

fn enrich_discovered_app_for_platform(app: DiscoveredApp, platform: &str) -> DiscoveredAppItemDto {
    let normalized_key = normalize_exe(&app.exe_name);
    let stem = normalized_key.strip_suffix(".app").unwrap_or(&normalized_key);
    let companions = companion_executables_for(&app.exe_name)
        .iter()
        .copied()
        .filter(|&c| {
            c != stem
                && c != normalized_key.as_str()
                && is_companion_for_platform(c, platform)
        })
        .map(str::to_string)
        .collect();
    let group_tag = classify_group_tag(&app.exe_name, &app.display_name).to_string();

    DiscoveredAppItemDto {
        display_name: app.display_name,
        exe_name: app.exe_name,
        normalized_key,
        path: app.path,
        is_running: app.is_running,
        category: category_to_dto(app.category),
        companions,
        group_tag,
    }
}

fn enrich_discovered_app(app: DiscoveredApp) -> DiscoveredAppItemDto {
    enrich_discovered_app_for_platform(app, current_platform())
}

fn build_split_tunnel_payload_from(
    cfg: SplitTunnelConfig,
    discovered: Vec<DiscoveredApp>,
) -> SplitTunnelPayloadDto {
    let selected_apps = sanitize_split_tunnel_apps(&cfg.apps);
    let discovered_apps = discovered.into_iter().map(enrich_discovered_app).collect();

    SplitTunnelPayloadDto {
        mode: mode_to_dto(cfg.mode),
        selected_apps,
        discovered_apps,
        presets: curated_presets(),
    }
}

/// Builds the full desktop split-tunnel payload from active configuration, host app discovery,
/// companion enrichment, group tagging, and curated presets.
pub fn build_split_tunnel_payload() -> SplitTunnelPayloadDto {
    let cfg = load_configured_split_tunnel();
    let discovered = discover_apps(&cfg.apps);
    build_split_tunnel_payload_from(cfg, discovered)
}

fn is_empty_include(cfg: &SplitTunnelConfig) -> bool {
    cfg.mode == SplitTunnelMode::Include && cfg.apps.is_empty()
}

fn append_empty_include_warning(message: String, cfg: &SplitTunnelConfig) -> String {
    if is_empty_include(cfg) {
        if message.ends_with('.') {
            format!("{message} {EMPTY_INCLUDE_WARNING}")
        } else {
            format!("{message}. {EMPTY_INCLUDE_WARNING}")
        }
    } else {
        message
    }
}

fn append_truncation_notice(message: String, truncated_count: usize) -> String {
    if truncated_count == 0 {
        return message;
    }
    let noun = if truncated_count == 1 { "app" } else { "apps" };
    let notice = format!(
        "Notice: split tunnel app list exceeded the maximum of {MAX_SPLIT_TUNNEL_APPS} apps; truncated {truncated_count} extra {noun}."
    );
    if message.ends_with('.') {
        format!("{message} {notice}")
    } else {
        format!("{message}. {notice}")
    }
}

fn count_unique_normalized_apps(apps: &[String]) -> usize {
    let mut seen = HashSet::with_capacity(apps.len());
    for raw in apps {
        if let Some(cleaned) = sanitize_split_tunnel_apps(std::slice::from_ref(raw))
            .into_iter()
            .next()
        {
            let key = normalize_exe(&cleaned);
            if !key.is_empty() {
                seen.insert(key);
            }
        }
    }
    seen.len()
}

fn redact_anyhow_error(err: &anyhow::Error) -> String {
    redact_urls_in_text(&format!("{err:#}"))
}

fn is_system_service_installed() -> bool {
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::query_windows_service_status().installed
    }
    #[cfg(target_os = "macos")]
    {
        vdpi::service::launch_daemon_plist_path().exists()
    }
    #[cfg(target_os = "linux")]
    {
        vdpi::service::systemd_system_unit_path().exists()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

fn is_process_elevated() -> bool {
    #[cfg(target_os = "windows")]
    {
        vdpi::platform::windows_service::is_elevated()
    }
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is always safe to call and has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(any(target_os = "windows", unix)))]
    {
        false
    }
}

fn load_user_config_or_seed_from_system(
    user_path: &Path,
    system_fallback_path: Option<&Path>,
) -> anyhow::Result<FileConfig> {
    match load_file_config_or_default(Some(user_path), false)? {
        (Some(_), file_cfg) => Ok(file_cfg),
        (None, _) => {
            if let Some(fallback) = system_fallback_path.filter(|fb| *fb != user_path) {
                if let Ok((Some(_), sys_cfg)) = load_file_config_or_default(Some(fallback), true) {
                    return Ok(sys_cfg);
                }
            }
            Ok(FileConfig::default())
        }
    }
}

fn save_split_tunnel_to_user_config(
    path: &Path,
    system_fallback_path: Option<&Path>,
    cfg: &SplitTunnelConfig,
) -> anyhow::Result<String> {
    let mut file_cfg = load_user_config_or_seed_from_system(path, system_fallback_path)?;
    file_cfg.schema_version.get_or_insert(CONFIG_SCHEMA_VERSION);
    file_cfg.split_tunnel_mode = Some(cfg.mode);
    file_cfg.split_tunnel_apps = Some(cfg.apps.clone());
    save_file_config_atomic(path, &file_cfg)?;
    let summary = cfg.summary_label();
    Ok(append_empty_include_warning(
        format!("Split tunneling saved: {summary}"),
        cfg,
    ))
}

#[allow(clippy::too_many_arguments)]
fn save_split_tunnel_config_with<FDetect, FApplySidecar>(
    req: SplitTunnelSaveRequestDto,
    user_cfg_path: &Path,
    system_cfg_path: &Path,
    system_service_installed: bool,
    needs_elevation: bool,
    detect_service: FDetect,
    apply_sidecar: FApplySidecar,
) -> ActionResultDto
where
    FDetect: FnOnce() -> ServiceState,
    FApplySidecar: FnOnce(&FileConfig, bool, bool) -> SidecarOutcome,
{
    let mut validated_apps = match validate_split_tunnel_apps(&req.apps) {
        Ok(apps) => sanitize_split_tunnel_apps(&apps),
        Err(err) => {
            return ActionResultDto {
                ok: false,
                message: redact_anyhow_error(&err),
                needs_restart: None,
                cancelled: None,
            };
        }
    };
    validated_apps.truncate(MAX_SPLIT_TUNNEL_APPS);
    let truncated_count = if req.apps.len() > MAX_SPLIT_TUNNEL_APPS {
        count_unique_normalized_apps(&req.apps).saturating_sub(MAX_SPLIT_TUNNEL_APPS)
    } else {
        0
    };

    let cfg = SplitTunnelConfig {
        mode: mode_from_dto(req.mode),
        apps: validated_apps,
    };

    let service_state = detect_service();
    let service_installed = service_state != ServiceState::NotInstalled;
    let service_running = service_state == ServiceState::Running;
    let restart_service = req.apply_live && service_running;

    if system_service_installed || (service_installed && restart_service) {
        let mut file_cfg = match if system_service_installed {
            load_file_config_or_default(Some(system_cfg_path), true).map(|(_, loaded)| loaded)
        } else {
            load_user_config_or_seed_from_system(user_cfg_path, Some(system_cfg_path))
        } {
            Ok(loaded) => loaded,
            Err(err) => {
                return ActionResultDto {
                    ok: false,
                    message: format!(
                        "Failed to load existing configuration: {}",
                        redact_anyhow_error(&err)
                    ),
                    needs_restart: None,
                    cancelled: None,
                };
            }
        };
        file_cfg.schema_version.get_or_insert(CONFIG_SCHEMA_VERSION);
        file_cfg.split_tunnel_mode = Some(cfg.mode);
        file_cfg.split_tunnel_apps = Some(cfg.apps.clone());

        let elevate = system_service_installed && needs_elevation;
        return match apply_sidecar(&file_cfg, elevate, restart_service) {
            SidecarOutcome::Ok(_) => {
                let summary = cfg.summary_label();
                let base_msg = if restart_service {
                    format!("Split tunneling saved: {summary} (service restarted)")
                } else if service_running {
                    format!(
                        "Split tunneling saved: {summary}. Restart protection to apply changes."
                    )
                } else {
                    format!("Split tunneling saved: {summary}")
                };
                ActionResultDto {
                    ok: true,
                    message: append_truncation_notice(
                        append_empty_include_warning(base_msg, &cfg),
                        truncated_count,
                    ),
                    needs_restart: Some(service_running && !restart_service),
                    cancelled: None,
                }
            }
            SidecarOutcome::SavedNeedsRestart(msg) => {
                let summary = cfg.summary_label();
                let detail = redact_urls_in_text(msg.trim());
                let base_msg = if detail.is_empty() {
                    format!(
                        "Split tunneling saved: {summary}. Restart protection to apply changes."
                    )
                } else {
                    format!("Split tunneling saved: {summary}. {detail}")
                };
                ActionResultDto {
                    ok: true,
                    message: append_truncation_notice(
                        append_empty_include_warning(base_msg, &cfg),
                        truncated_count,
                    ),
                    needs_restart: Some(true),
                    cancelled: None,
                }
            }
            SidecarOutcome::Cancelled => ActionResultDto {
                ok: false,
                message: "Administrator authorization was cancelled. Split tunneling settings were not changed.".to_string(),
                needs_restart: None,
                cancelled: Some(true),
            },
            SidecarOutcome::Err(err) => ActionResultDto {
                ok: false,
                message: format!(
                    "Failed to apply split tunneling settings: {}",
                    redact_urls_in_text(&err)
                ),
                needs_restart: None,
                cancelled: None,
            },
        };
    }

    match save_split_tunnel_to_user_config(user_cfg_path, Some(system_cfg_path), &cfg) {
        Ok(message) => ActionResultDto {
            ok: true,
            message: append_truncation_notice(message, truncated_count),
            needs_restart: if service_running { Some(true) } else { None },
            cancelled: None,
        },
        Err(err) => ActionResultDto {
            ok: false,
            message: format!(
                "Failed to save split tunneling settings: {}",
                redact_anyhow_error(&err)
            ),
            needs_restart: None,
            cancelled: None,
        },
    }
}

/// Sanitizes, validates, and persists split-tunnel configuration.
///
/// When a system service is installed (regardless of `req.apply_live`), persists
/// to the system `config.toml` via [`crate::sidecar::apply_config_via_temp_file`]
/// (restarting the running service only when `req.apply_live` is `true`). When
/// a user-scoped service is running and `req.apply_live` is `true`, delegates to
/// the non-elevated CLI sidecar. Otherwise persists atomically to the user's
/// `config.toml`.
pub fn save_split_tunnel_config(req: SplitTunnelSaveRequestDto) -> ActionResultDto {
    let user_path = user_config_path();
    let sys_path = system_config_path();
    let system_installed = is_system_service_installed();
    let needs_elevation = system_installed && !is_process_elevated();
    save_split_tunnel_config_with(
        req,
        &user_path,
        &sys_path,
        system_installed,
        needs_elevation,
        detect_service_state,
        apply_config_via_temp_file,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use vdpi::config_file::load_file_config;
    use vdpi_core::config::EngineMode;

    static TEMP_DIR_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "vdpi-desktop-split-test-{label}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp test dir");
            Self(dir)
        }

        fn config_path(&self) -> PathBuf {
            self.0.join("config.toml")
        }

        fn system_config_path(&self) -> PathBuf {
            self.0.join("system-config.toml")
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn curated_presets_cover_expected_ids_and_valid_platform_entries() {
        let cases: &[(&str, &[&str])] = &[
            (
                "windows",
                &[
                    "discord",
                    "roblox",
                    "valorant-riot",
                    "steam",
                    "web-browsers",
                    "obs-studio",
                ],
            ),
            (
                "macos",
                &[
                    "discord",
                    "roblox",
                    "league-of-legends",
                    "steam",
                    "web-browsers",
                    "obs-studio",
                ],
            ),
            (
                "linux",
                &[
                    "discord",
                    "roblox",
                    "linux-gaming",
                    "steam",
                    "web-browsers",
                    "obs-studio",
                ],
            ),
        ];

        for &(platform, expected_ids) in cases {
            let presets = curated_presets_for_platform(platform);
            let ids: Vec<&str> = presets.iter().map(|p| p.id.as_str()).collect();
            assert_eq!(ids, expected_ids, "preset IDs mismatch for {platform}");

            for preset in &presets {
                assert!(
                    !preset.label.trim().is_empty(),
                    "preset {} label must be non-empty",
                    preset.id
                );
                assert!(
                    !preset.description.trim().is_empty(),
                    "preset {} description must be non-empty",
                    preset.id
                );
                assert!(
                    !preset.apps.is_empty(),
                    "preset {} must list at least one executable on {platform}",
                    preset.id
                );
                assert!(
                    matches!(
                        preset.group_tag.as_str(),
                        "games" | "browsers" | "communication" | "media"
                    ),
                    "invalid preset group_tag {} for {}",
                    preset.group_tag,
                    preset.id
                );

                let sanitized = validate_split_tunnel_apps(&preset.apps)
                    .expect("curated preset apps must pass validation");
                assert_eq!(
                    sanitized.len(),
                    preset.apps.len(),
                    "curated preset {} on {platform} should not contain duplicates or invalid entries",
                    preset.id
                );

                for app in &preset.apps {
                    if platform == "windows" {
                        assert!(
                            app.to_ascii_lowercase().ends_with(".exe"),
                            "Windows preset {} entry {app:?} should end with .exe",
                            preset.id
                        );
                    } else {
                        assert!(
                            !app.to_ascii_lowercase().ends_with(".exe"),
                            "{platform} preset {} entry {app:?} should not use .exe",
                            preset.id
                        );
                    }
                    assert_eq!(
                        classify_group_tag(app, &preset.label),
                        preset.group_tag.as_str(),
                        "group tag mismatch for {app:?} in preset {} on {platform}",
                        preset.id
                    );
                }
            }
        }

        // Windows-specific preset checks
        let win = curated_presets_for_platform("windows");
        let win_riot = win.iter().find(|p| p.id == "valorant-riot").unwrap();
        for expected in [
            "VALORANT-Win64-Shipping.exe",
            "RiotClientServices.exe",
            "vgc.exe",
            "vgtray.exe",
            "League of Legends.exe",
        ] {
            assert!(
                win_riot.apps.iter().any(|a| a == expected),
                "Windows Valorant & Riot preset missing {expected}"
            );
        }
        let win_steam = win.iter().find(|p| p.id == "steam").unwrap();
        assert!(win_steam.apps.iter().any(|a| a == "steam.exe"));
        assert!(win_steam.apps.iter().any(|a| a == "steamwebhelper.exe"));

        // macOS-specific preset checks
        let mac = curated_presets_for_platform("macos");
        assert!(
            !mac.iter().any(|p| p.id == "valorant-riot"),
            "macOS must not include Valorant & Riot preset"
        );
        assert!(
            mac.iter().all(|p| {
                !p.label.to_ascii_lowercase().contains("valorant")
                    && p.apps
                        .iter()
                        .all(|a| !a.to_ascii_lowercase().contains("valorant"))
            }),
            "macOS presets must not reference Valorant"
        );
        let mac_lol = mac.iter().find(|p| p.id == "league-of-legends").unwrap();
        assert_eq!(mac_lol.label, "League of Legends");
        assert!(mac_lol.apps.iter().any(|a| a == "League of Legends"));
        let mac_discord = mac.iter().find(|p| p.id == "discord").unwrap();
        assert_eq!(
            mac_discord.apps,
            vec!["Discord", "Discord PTB", "Discord Canary"]
        );
        let mac_steam = mac.iter().find(|p| p.id == "steam").unwrap();
        assert!(mac_steam.apps.iter().any(|a| a == "steamwebhelper"));

        // Linux-specific preset checks
        let linux = curated_presets_for_platform("linux");
        assert!(
            !linux.iter().any(|p| p.id == "valorant-riot"),
            "Linux must not include Valorant & Riot preset"
        );
        assert!(
            linux.iter().all(|p| {
                !p.label.to_ascii_lowercase().contains("valorant")
                    && p.apps
                        .iter()
                        .all(|a| !a.to_ascii_lowercase().contains("valorant"))
            }),
            "Linux presets must not reference Valorant"
        );
        let linux_gaming = linux.iter().find(|p| p.id == "linux-gaming").unwrap();
        assert_eq!(linux_gaming.label, "Linux Gaming");
        assert_eq!(
            linux_gaming.apps,
            vec![
                "heroic",
                "com.heroicgameslauncher.hgl",
                "lutris",
                "net.lutris.Lutris",
                "prismlauncher",
                "org.prismlauncher.PrismLauncher",
            ]
        );
        let linux_discord = linux.iter().find(|p| p.id == "discord").unwrap();
        assert!(linux_discord.apps.iter().any(|a| a == "vesktop"));
        assert!(linux_discord
            .apps
            .iter()
            .any(|a| a == "dev.vencord.Vesktop"));
        let linux_browsers = linux.iter().find(|p| p.id == "web-browsers").unwrap();
        for expected in [
            "firefox-esr",
            "google-chrome-stable",
            "chromium-browser",
            "org.mozilla.firefox",
            "com.google.Chrome",
            "com.brave.Browser",
        ] {
            assert!(
                linux_browsers.apps.iter().any(|a| a == expected),
                "Linux Web Browsers preset missing {expected}"
            );
        }

        let current = curated_presets();
        assert_eq!(current.len(), 6);
    }

    #[test]
    fn classify_group_tag_assigns_expected_categories() {
        assert_eq!(classify_group_tag("Discord.exe", "Discord"), "communication");
        assert_eq!(classify_group_tag("Discord PTB", ""), "communication");
        assert_eq!(classify_group_tag("Discord Canary", ""), "communication");
        assert_eq!(classify_group_tag("vesktop", ""), "communication");
        assert_eq!(
            classify_group_tag("dev.vencord.Vesktop", ""),
            "communication"
        );
        assert_eq!(
            classify_group_tag("com.discordapp.Discord", "Discord"),
            "communication"
        );
        assert_eq!(
            classify_group_tag("telegram-desktop", "Telegram"),
            "communication"
        );
        assert_eq!(classify_group_tag("Slack.app", "Slack"), "communication");

        assert_eq!(classify_group_tag("RobloxPlayerBeta.exe", "Roblox"), "games");
        assert_eq!(
            classify_group_tag("VALORANT-Win64-Shipping.exe", "Valorant"),
            "games"
        );
        assert_eq!(
            classify_group_tag("MyUnrealGame-Win64-Shipping.exe", "My Unreal Game"),
            "games"
        );
        assert_eq!(classify_group_tag("steam_osx", "Steam"), "games");
        assert_eq!(classify_group_tag("heroic", ""), "games");
        assert_eq!(
            classify_group_tag("com.heroicgameslauncher.hgl", ""),
            "games"
        );
        assert_eq!(classify_group_tag("lutris", ""), "games");
        assert_eq!(classify_group_tag("net.lutris.Lutris", ""), "games");
        assert_eq!(classify_group_tag("prismlauncher", ""), "games");
        assert_eq!(
            classify_group_tag("org.prismlauncher.PrismLauncher", ""),
            "games"
        );

        assert_eq!(classify_group_tag("chrome.exe", "Google Chrome"), "browsers");
        assert_eq!(classify_group_tag("firefox", "Mozilla Firefox"), "browsers");
        assert_eq!(classify_group_tag("Safari", "Safari"), "browsers");
        assert_eq!(classify_group_tag("custom-web", "Zen Browser"), "browsers");

        assert_eq!(classify_group_tag("obs64.exe", "OBS Studio"), "media");
        assert_eq!(classify_group_tag("spotify", "Spotify"), "media");
        assert_eq!(classify_group_tag("vlc.exe", "VLC Media Player"), "media");

        assert_eq!(classify_group_tag("Code.exe", "Visual Studio Code"), "other");
        assert_eq!(classify_group_tag("qbittorrent.exe", "qBittorrent"), "other");
        // Verify narrow display-name matching avoids substring false positives.
        assert_eq!(classify_group_tag("jobsched.exe", "Jobs Scheduler"), "other");
        assert_eq!(classify_group_tag("archiver.exe", "Archive Manager"), "other");
        assert_eq!(
            classify_group_tag("ledger.exe", "Knowledge Base"),
            "other"
        );
    }

    #[test]
    fn enrich_discovered_app_filters_companions_to_target_platform() {
        let make_app = |display: &str, exe: &str| DiscoveredApp {
            display_name: display.to_string(),
            exe_name: exe.to_string(),
            path: None,
            is_running: false,
            category: AppCategory::Installed,
        };

        // Windows Discord: keeps Windows companions, hides macOS helper & Linux/Flatpak names.
        let win_discord =
            enrich_discovered_app_for_platform(make_app("Discord", "Discord.exe"), "windows");
        assert!(win_discord.companions.iter().any(|c| c == "discordptb"));
        assert!(win_discord.companions.iter().any(|c| c == "discordcanary"));
        assert!(win_discord.companions.iter().any(|c| c == "discord_clips"));
        for forbidden in [
            "discord",
            "discord helper",
            "discord-ptb",
            "discord-canary",
            "com.discordapp.discord",
        ] {
            assert!(
                !win_discord.companions.iter().any(|c| c == forbidden),
                "Windows Discord companions must not include {forbidden:?}: {:?}",
                win_discord.companions
            );
        }

        // Windows Roblox: keeps Bloxstrap/Fishstrap/launcher, hides macOS & Linux Sober.
        let win_roblox = enrich_discovered_app_for_platform(
            make_app("Roblox", "RobloxPlayerBeta.exe"),
            "windows",
        );
        assert!(win_roblox.companions.iter().any(|c| c == "bloxstrap"));
        assert!(win_roblox.companions.iter().any(|c| c == "fishstrap"));
        for forbidden in ["sober", "org.vinegarhq.sober", "robloxplayer"] {
            assert!(
                !win_roblox.companions.iter().any(|c| c == forbidden),
                "Windows Roblox companions must not include {forbidden:?}: {:?}",
                win_roblox.companions
            );
        }

        // Windows Steam: hides macOS steam_osx & Linux Flatpak.
        let win_steam =
            enrich_discovered_app_for_platform(make_app("Steam", "steam.exe"), "windows");
        assert!(win_steam.companions.iter().any(|c| c == "steamwebhelper"));
        assert!(win_steam.companions.iter().any(|c| c == "steamservice"));
        assert!(!win_steam.companions.iter().any(|c| c == "steam_osx"));
        assert!(!win_steam
            .companions
            .iter()
            .any(|c| c == "com.valvesoftware.steam"));

        // Windows Firefox: hides Linux-only binaries & Flatpak ID.
        let win_ff =
            enrich_discovered_app_for_platform(make_app("Firefox", "firefox.exe"), "windows");
        assert!(
            win_ff.companions.is_empty(),
            "Windows Firefox should not expose Linux companions: {:?}",
            win_ff.companions
        );

        // macOS Discord: keeps macOS helper, hides Windows & Linux companions.
        let mac_discord =
            enrich_discovered_app_for_platform(make_app("Discord", "Discord"), "macos");
        assert!(mac_discord.companions.iter().any(|c| c == "discord helper"));
        for forbidden in [
            "discordptb",
            "discordcanary",
            "discord_clips",
            "discord-ptb",
            "com.discordapp.discord",
        ] {
            assert!(
                !mac_discord.companions.iter().any(|c| c == forbidden),
                "macOS Discord companions must not include {forbidden:?}"
            );
        }

        // macOS League: hides Windows-only Valorant & Vanguard companions.
        let mac_lol = enrich_discovered_app_for_platform(
            make_app("League of Legends", "LeagueClient"),
            "macos",
        );
        assert!(mac_lol.companions.iter().any(|c| c == "riotclientservices"));
        assert!(mac_lol.companions.iter().any(|c| c == "league of legends"));
        for forbidden in ["valorant", "valorant-win64-shipping", "vgc", "vgtray"] {
            assert!(
                !mac_lol.companions.iter().any(|c| c == forbidden),
                "macOS League companions must not include {forbidden:?}"
            );
        }

        // Linux Discord & Roblox & Firefox: keep native/Flatpak companions, hide Windows/macOS.
        let linux_discord =
            enrich_discovered_app_for_platform(make_app("Discord", "discord"), "linux");
        assert!(linux_discord.companions.iter().any(|c| c == "discord-ptb"));
        assert!(linux_discord
            .companions
            .iter()
            .any(|c| c == "com.discordapp.discord"));
        for forbidden in ["discordptb", "discordcanary", "discord_clips", "discord helper"] {
            assert!(
                !linux_discord.companions.iter().any(|c| c == forbidden),
                "Linux Discord companions must not include {forbidden:?}"
            );
        }

        let linux_sober =
            enrich_discovered_app_for_platform(make_app("Roblox", "sober"), "linux");
        assert_eq!(linux_sober.companions, vec!["org.vinegarhq.sober"]);

        let linux_ff =
            enrich_discovered_app_for_platform(make_app("Firefox", "firefox"), "linux");
        assert!(linux_ff.companions.iter().any(|c| c == "firefox-esr"));
        assert!(linux_ff
            .companions
            .iter()
            .any(|c| c == "org.mozilla.firefox"));
    }

    #[test]
    fn build_payload_enriches_normalized_keys_companions_and_group_tags() {
        let cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec![
                "\"C:\\Program Files\\Discord\\Discord.exe\" --start-minimized".to_string(),
                "discord.exe".to_string(),
                "  ".to_string(),
            ],
        };
        let discovered = vec![
            DiscoveredApp {
                display_name: "Discord".to_string(),
                exe_name: "Discord.exe".to_string(),
                path: Some("C:\\Users\\test\\Discord.exe".to_string()),
                is_running: true,
                category: AppCategory::Running,
            },
            DiscoveredApp {
                display_name: "Custom Tool".to_string(),
                exe_name: "my-tool.exe".to_string(),
                path: None,
                is_running: false,
                category: AppCategory::Custom,
            },
        ];

        let payload = build_split_tunnel_payload_from(cfg, discovered);
        assert_eq!(payload.mode, SplitTunnelModeDto::Exclude);
        assert_eq!(payload.selected_apps, vec!["Discord.exe"]);
        assert_eq!(payload.presets.len(), 6);
        assert_eq!(payload.discovered_apps.len(), 2);

        let discord = &payload.discovered_apps[0];
        assert_eq!(discord.normalized_key, "discord");
        assert_eq!(discord.group_tag, "communication");
        assert_eq!(discord.category, AppCategoryDto::Running);
        assert!(discord.is_running);
        assert!(!discord.companions.is_empty());
        assert!(
            !discord.companions.iter().any(|c| c == "discord"),
            "companions should exclude self"
        );
        match current_platform() {
            "windows" => {
                assert!(discord.companions.iter().any(|c| c == "discordptb"));
                assert!(!discord.companions.iter().any(|c| c == "discord helper"));
                assert!(!discord
                    .companions
                    .iter()
                    .any(|c| c == "com.discordapp.discord"));
            }
            "macos" => {
                assert!(discord.companions.iter().any(|c| c == "discord helper"));
                assert!(!discord.companions.iter().any(|c| c == "discordptb"));
            }
            _ => {
                assert!(discord.companions.iter().any(|c| c == "discord-ptb"));
                assert!(!discord.companions.iter().any(|c| c == "discordptb"));
            }
        }

        let custom = &payload.discovered_apps[1];
        assert_eq!(custom.normalized_key, "my-tool");
        assert_eq!(custom.group_tag, "other");
        assert_eq!(custom.category, AppCategoryDto::Custom);
        assert!(custom.companions.is_empty());
    }

    #[test]
    fn save_sanitizes_deduplicates_and_rejects_control_characters() {
        let dir = TempDirGuard::new("sanitize");
        let cfg_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // Seed unrelated keys to verify atomic save preserves them.
        let initial = FileConfig {
            engine: Some(EngineMode::Tun),
            dns_addr: Some("1.1.1.1".to_string()),
            ..Default::default()
        };
        save_file_config_atomic(&cfg_path, &initial).expect("seed config");

        let res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec![
                    "\"C:\\Games\\Steam\\steam.exe\" -silent".to_string(),
                    "STEAM.EXE".to_string(),
                    "  /usr/bin/firefox --new-window  ".to_string(),
                    "   ".to_string(),
                    "".to_string(),
                ],
                apply_live: false,
            },
            &cfg_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("sidecar not called when service not installed"),
        );

        assert!(res.ok, "expected save ok, got: {}", res.message);
        assert_eq!(res.needs_restart, None);
        assert_eq!(res.cancelled, None);
        assert!(res.message.contains("Exclude (2 apps)"));

        let (_, reloaded) = load_file_config(Some(&cfg_path), false).expect("reload config");
        assert_eq!(reloaded.engine, Some(EngineMode::Tun));
        assert_eq!(reloaded.dns_addr.as_deref(), Some("1.1.1.1"));
        assert_eq!(reloaded.split_tunnel_mode, Some(SplitTunnelMode::Exclude));
        assert_eq!(
            reloaded.split_tunnel_apps,
            Some(vec!["steam.exe".to_string(), "firefox".to_string()])
        );

        // Control characters/newlines must be rejected without touching config.
        let invalid = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["good.exe".to_string(), "bad\napp.exe".to_string()],
                apply_live: true,
            },
            &cfg_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| unreachable!("invalid input must fail before sidecar apply"),
        );
        assert!(!invalid.ok);
        assert!(invalid.message.contains("control characters"));
        assert_eq!(invalid.needs_restart, None);
        assert_eq!(invalid.cancelled, None);
    }

    #[test]
    fn save_routes_system_service_via_sidecar_and_user_config_when_uninstalled() {
        let dir = TempDirGuard::new("routing");
        let user_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // Seed system config to verify sidecar receives merged system FileConfig (not user config).
        let sys_seed = FileConfig {
            engine: Some(EngineMode::Tun),
            dns_addr: Some("https://dns.nextdns.io/secret-profile".to_string()),
            ..Default::default()
        };
        save_file_config_atomic(&sys_path, &sys_seed).expect("seed system config");

        // 1. System service installed + Running + apply_live = true -> sidecar(elevate=true, restart=true)
        let called = Cell::new(false);
        let res_sys_live = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |file_cfg, elevate, restart| {
                called.set(true);
                assert!(elevate, "system service update must elevate when needed");
                assert!(restart, "apply_live + Running must restart service");
                assert_eq!(file_cfg.engine, Some(EngineMode::Tun));
                assert_eq!(
                    file_cfg.dns_addr.as_deref(),
                    Some("https://dns.nextdns.io/secret-profile")
                );
                assert_eq!(file_cfg.split_tunnel_mode, Some(SplitTunnelMode::Exclude));
                assert_eq!(
                    file_cfg.split_tunnel_apps,
                    Some(vec!["Discord.exe".to_string()])
                );
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(called.get());
        assert!(res_sys_live.ok);
        assert_eq!(res_sys_live.needs_restart, Some(false));
        assert_eq!(res_sys_live.cancelled, None);
        assert!(res_sys_live.message.contains("service restarted"));
        assert!(
            !user_path.exists(),
            "system service save must never write to user_config_path"
        );

        // 2. System service installed + Running + apply_live = false -> STILL uses sidecar(elevate=true, restart=false)!
        let deferred_called = Cell::new(false);
        let res_sys_deferred = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["steam.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |file_cfg, elevate, restart| {
                deferred_called.set(true);
                assert!(elevate);
                assert!(!restart, "apply_live=false must not restart running service");
                assert_eq!(file_cfg.engine, Some(EngineMode::Tun));
                assert_eq!(
                    file_cfg.split_tunnel_apps,
                    Some(vec!["steam.exe".to_string()])
                );
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(deferred_called.get());
        assert!(res_sys_deferred.ok);
        assert_eq!(res_sys_deferred.needs_restart, Some(true));
        assert_eq!(res_sys_deferred.cancelled, None);
        assert!(
            !user_path.exists(),
            "deferred system service save must not write to user_config_path"
        );

        // 3. System service installed + Stopped + apply_live = true -> sidecar(elevate=false when already elevated, restart=false)
        let stopped_called = Cell::new(false);
        let res_sys_stopped = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Include,
                apps: vec!["firefox.exe".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            false,
            || ServiceState::Stopped,
            |file_cfg, elevate, restart| {
                stopped_called.set(true);
                assert!(!elevate);
                assert!(!restart, "stopped service must not pass --restart");
                assert_eq!(file_cfg.split_tunnel_mode, Some(SplitTunnelMode::Include));
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(stopped_called.get());
        assert!(res_sys_stopped.ok);
        assert_eq!(res_sys_stopped.needs_restart, Some(false));
        assert_eq!(res_sys_stopped.cancelled, None);

        // 4. User-scoped service (not system) + Running + apply_live = true -> non-elevated sidecar restart
        let user_svc_called = Cell::new(false);
        let res_user_live = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["discord".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::Running,
            |_file_cfg, elevate, restart| {
                user_svc_called.set(true);
                assert!(!elevate);
                assert!(restart);
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(user_svc_called.get());
        assert!(res_user_live.ok);
        assert_eq!(res_user_live.needs_restart, Some(false));

        // 5. User-scoped service + Running + apply_live = false -> saves user config and flags needs_restart = Some(true)
        let res_user_deferred = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["steam.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::Running,
            |_, _, _| unreachable!("apply_live is false for user-scoped service"),
        );
        assert!(res_user_deferred.ok);
        assert_eq!(res_user_deferred.needs_restart, Some(true));
        assert!(user_path.is_file());

        // 6. NotInstalled + apply_live = true -> saves user config directly
        let res_not_installed = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::All,
                apps: vec![],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service is not installed"),
        );
        assert!(res_not_installed.ok);
        assert_eq!(res_not_installed.needs_restart, None);
        assert_eq!(res_not_installed.cancelled, None);
    }

    #[test]
    fn save_maps_sidecar_cancellation_and_redacts_all_error_messages() {
        let dir = TempDirGuard::new("errors");
        let user_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // SidecarOutcome::Cancelled -> cancelled: Some(true)
        let cancelled = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| SidecarOutcome::Cancelled,
        );
        assert!(!cancelled.ok);
        assert_eq!(cancelled.cancelled, Some(true));
        assert_eq!(cancelled.needs_restart, None);
        assert!(cancelled.message.to_ascii_lowercase().contains("cancelled"));

        // SidecarOutcome::Err -> URL secrets redacted
        let sidecar_err = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| {
                SidecarOutcome::Err(
                    "apply-file failed for https://alice:supersecret@dns.nextdns.io/prof123?tok=xyz"
                        .to_string(),
                )
            },
        );
        assert!(!sidecar_err.ok);
        assert_eq!(sidecar_err.cancelled, None);
        assert!(sidecar_err.message.contains("https://dns.nextdns.io"));
        assert!(!sidecar_err.message.contains("supersecret"));
        assert!(!sidecar_err.message.contains("prof123"));
        assert!(!sidecar_err.message.contains("tok=xyz"));

        // Corrupt system config containing a secret URL -> load error redacted
        fs::write(
            &sys_path,
            "dns_addr = \"https://bob:pw999@dns.nextdns.io/leakedpath?k=1\ninvalid = [",
        )
        .expect("write corrupt system config");
        let corrupt_sys = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| unreachable!("corrupt system config must fail before sidecar"),
        );
        assert!(!corrupt_sys.ok);
        assert_eq!(corrupt_sys.cancelled, None);
        assert!(!corrupt_sys.message.contains("pw999"));
        assert!(!corrupt_sys.message.contains("leakedpath"));

        // Corrupt user config containing a secret URL -> save error redacted
        fs::write(
            &user_path,
            "dns_addr = \"https://user:pw777@dns.nextdns.io/usersecret?k=2\ninvalid = [",
        )
        .expect("write corrupt user config");
        let corrupt_user = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service not installed"),
        );
        assert!(!corrupt_user.ok);
        assert_eq!(corrupt_user.cancelled, None);
        assert!(!corrupt_user.message.contains("pw777"));
        assert!(!corrupt_user.message.contains("usersecret"));
    }

    #[test]
    fn empty_include_mode_persists_fail_closed_with_warning() {
        let dir = TempDirGuard::new("empty-include");
        let cfg_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // Explicit empty apps list and blank-only entries both normalize to empty Include.
        for raw_apps in [vec![], vec!["   ".to_string(), "\"\"".to_string()]] {
            let res = save_split_tunnel_config_with(
                SplitTunnelSaveRequestDto {
                    mode: SplitTunnelModeDto::Include,
                    apps: raw_apps,
                    apply_live: false,
                },
                &cfg_path,
                &sys_path,
                false,
                false,
                || ServiceState::NotInstalled,
                |_, _, _| unreachable!("service not installed"),
            );

            assert!(res.ok, "empty Include must persist fail-closed, got: {}", res.message);
            assert!(
                res.message.contains("Include (0 apps)"),
                "expected summary label in message: {}",
                res.message
            );
            assert!(
                res.message.contains(EMPTY_INCLUDE_WARNING),
                "expected fail-closed warning in message: {}",
                res.message
            );

            let (_, reloaded) = load_file_config(Some(&cfg_path), false).expect("reload config");
            assert_eq!(reloaded.split_tunnel_mode, Some(SplitTunnelMode::Include));
            assert_eq!(reloaded.split_tunnel_apps, Some(Vec::new()));

            let runtime_split = SplitTunnelConfig {
                mode: reloaded.split_tunnel_mode.unwrap(),
                apps: reloaded.split_tunnel_apps.unwrap(),
            };
            assert!(
                runtime_split.should_bypass_app(Some("Discord.exe")),
                "empty Include must fail-closed (bypass all apps)"
            );
            assert!(runtime_split.should_bypass_app(None));
        }

        // System service live apply path also attaches the empty Include warning.
        let live_res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Include,
                apps: vec![],
                apply_live: true,
            },
            &cfg_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |file_cfg, elevate, restart| {
                assert!(elevate);
                assert!(restart);
                assert_eq!(file_cfg.split_tunnel_mode, Some(SplitTunnelMode::Include));
                assert_eq!(file_cfg.split_tunnel_apps, Some(Vec::new()));
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(live_res.ok);
        assert!(live_res.message.contains(EMPTY_INCLUDE_WARNING));
        assert!(!live_res.message.contains(".."));
        assert_eq!(live_res.needs_restart, Some(false));
        assert_eq!(live_res.cancelled, None);

        // System service deferred apply path attaches warning cleanly without double period.
        let deferred_res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Include,
                apps: vec![],
                apply_live: false,
            },
            &cfg_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, elevate, restart| {
                assert!(elevate);
                assert!(!restart);
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(deferred_res.ok);
        assert!(deferred_res.message.contains(EMPTY_INCLUDE_WARNING));
        assert!(!deferred_res.message.contains(".."));
        assert_eq!(deferred_res.needs_restart, Some(true));
        assert_eq!(deferred_res.cancelled, None);
    }

    #[test]
    fn curated_presets_have_unique_ids_and_unique_normalized_apps_per_preset() {
        for platform in ["windows", "macos", "linux"] {
            let presets = curated_presets_for_platform(platform);
            let mut seen_ids = HashSet::new();
            for p in &presets {
                assert!(seen_ids.insert(p.id.as_str()), "duplicate preset id {}", p.id);
                let mut seen_apps = HashSet::new();
                for app in &p.apps {
                    let norm = normalize_exe(app);
                    assert!(
                        !norm.is_empty(),
                        "preset {} app {app:?} normalized to empty",
                        p.id
                    );
                    assert!(
                        seen_apps.insert(norm.clone()),
                        "duplicate normalized app {norm:?} in preset {} on {platform}",
                        p.id
                    );
                }
            }
        }
    }

    #[test]
    fn save_to_user_config_seeds_from_system_config_when_missing() {
        let dir = TempDirGuard::new("seed-from-system");
        let user_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // Simulate a non-purge uninstall: system config still exists, user config does not.
        let sys_cfg = FileConfig {
            engine: Some(EngineMode::Tun),
            dns_addr: Some("https://dns.nextdns.io/kept-profile".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            ..Default::default()
        };
        save_file_config_atomic(&sys_path, &sys_cfg).expect("seed system config");
        assert!(!user_path.exists());

        let res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service is not installed"),
        );
        assert!(res.ok, "expected save ok, got: {}", res.message);

        let (_, reloaded) = load_file_config(Some(&user_path), false).expect("reload user config");
        assert_eq!(reloaded.engine, Some(EngineMode::Tun));
        assert_eq!(
            reloaded.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/kept-profile")
        );
        assert_eq!(reloaded.doh, Some(true));
        assert_eq!(reloaded.block_quic, Some(true));
        assert_eq!(reloaded.split_tunnel_mode, Some(SplitTunnelMode::Exclude));
        assert_eq!(
            reloaded.split_tunnel_apps,
            Some(vec!["Discord.exe".to_string()])
        );

        // Once user config exists, it takes precedence over system config.
        let updated_sys = FileConfig {
            engine: Some(EngineMode::Proxy),
            dns_addr: Some("9.9.9.9".to_string()),
            ..Default::default()
        };
        save_file_config_atomic(&sys_path, &updated_sys).expect("update system config");

        let res_second = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Include,
                apps: vec!["steam.exe".to_string()],
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service is not installed"),
        );
        assert!(res_second.ok);

        let (_, reloaded_second) =
            load_file_config(Some(&user_path), false).expect("reload existing user config");
        assert_eq!(reloaded_second.engine, Some(EngineMode::Tun));
        assert_eq!(
            reloaded_second.dns_addr.as_deref(),
            Some("https://dns.nextdns.io/kept-profile")
        );
        assert_eq!(
            reloaded_second.split_tunnel_mode,
            Some(SplitTunnelMode::Include)
        );
        assert_eq!(
            reloaded_second.split_tunnel_apps,
            Some(vec!["steam.exe".to_string()])
        );
    }

    #[test]
    fn save_truncates_apps_above_max_limit_with_explicit_notice() {
        let dir = TempDirGuard::new("max-apps-cap");
        let user_path = dir.config_path();
        let sys_path = dir.system_config_path();

        // Exactly MAX_SPLIT_TUNNEL_APPS unique apps + duplicates/blanks -> NO truncation notice.
        let mut at_limit: Vec<String> = (0..MAX_SPLIT_TUNNEL_APPS)
            .map(|i| format!("app-{i}.exe"))
            .collect();
        at_limit.push("APP-0.EXE".to_string());
        at_limit.push("\"C:\\Games\\app-1.exe\" --flag".to_string());
        at_limit.push("   ".to_string());

        let exact_res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: at_limit,
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service not installed"),
        );
        assert!(exact_res.ok, "expected save ok, got: {}", exact_res.message);
        assert!(
            !exact_res.message.to_ascii_lowercase().contains("truncated"),
            "exact 256 unique apps with duplicates must not report truncation: {}",
            exact_res.message
        );

        // Exceeding MAX_SPLIT_TUNNEL_APPS unique apps -> capped at 256 + explicit notice in message.
        let oversized: Vec<String> = (0..(MAX_SPLIT_TUNNEL_APPS + 5))
            .map(|i| format!("proc-{i}.exe"))
            .collect();

        let user_truncated = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: oversized.clone(),
                apply_live: false,
            },
            &user_path,
            &sys_path,
            false,
            false,
            || ServiceState::NotInstalled,
            |_, _, _| unreachable!("service not installed"),
        );
        assert!(user_truncated.ok);
        assert!(
            user_truncated.message.contains("256")
                && user_truncated.message.contains("truncated 5 extra apps"),
            "expected explicit truncation notice, got: {}",
            user_truncated.message
        );
        assert!(!user_truncated.message.contains(".."));

        let (_, reloaded) = load_file_config(Some(&user_path), false).expect("reload user config");
        assert_eq!(
            reloaded.split_tunnel_apps.as_ref().map(Vec::len),
            Some(MAX_SPLIT_TUNNEL_APPS)
        );

        // Sidecar save path also enforces MAX_SPLIT_TUNNEL_APPS and appends truncation notice.
        let sidecar_truncated = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: oversized,
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |file_cfg, elevate, restart| {
                assert!(elevate);
                assert!(restart);
                assert_eq!(
                    file_cfg.split_tunnel_apps.as_ref().map(Vec::len),
                    Some(MAX_SPLIT_TUNNEL_APPS)
                );
                SidecarOutcome::Ok(String::new())
            },
        );
        assert!(sidecar_truncated.ok);
        assert!(
            sidecar_truncated.message.contains("256")
                && sidecar_truncated.message.contains("truncated 5 extra apps"),
            "expected truncation notice on sidecar save, got: {}",
            sidecar_truncated.message
        );
        assert!(!sidecar_truncated.message.contains(".."));
    }

    #[test]
    fn save_handles_sidecar_saved_needs_restart_cleanly() {
        let dir = TempDirGuard::new("saved-needs-restart");
        let user_path = dir.config_path();
        let sys_path = dir.system_config_path();

        let res = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Exclude,
                apps: vec!["Discord.exe".to_string()],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| {
                SidecarOutcome::SavedNeedsRestart(
                    "Saved config for https://u:pw@dns.nextdns.io/secret123?k=1; restart failed."
                        .to_string(),
                )
            },
        );
        assert!(res.ok, "SavedNeedsRestart must return ok=true");
        assert_eq!(res.needs_restart, Some(true));
        assert_eq!(res.cancelled, None);
        assert!(res.message.contains("Exclude (1 app)"));
        assert!(res.message.contains("https://dns.nextdns.io"));
        assert!(!res.message.contains("secret123"));
        assert!(!res.message.contains("k=1"));
        assert!(!res.message.contains(".."));

        // Empty detail falls back to restart prompt and appends empty-include warning cleanly.
        let empty_detail = save_split_tunnel_config_with(
            SplitTunnelSaveRequestDto {
                mode: SplitTunnelModeDto::Include,
                apps: vec![],
                apply_live: true,
            },
            &user_path,
            &sys_path,
            true,
            true,
            || ServiceState::Running,
            |_, _, _| SidecarOutcome::SavedNeedsRestart("   ".to_string()),
        );
        assert!(empty_detail.ok);
        assert_eq!(empty_detail.needs_restart, Some(true));
        assert_eq!(empty_detail.cancelled, None);
        assert!(empty_detail.message.contains("Restart protection"));
        assert!(empty_detail.message.contains(EMPTY_INCLUDE_WARNING));
        assert!(!empty_detail.message.contains(".."));
    }
}
