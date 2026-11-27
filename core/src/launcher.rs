#[cfg(not(any(target_os = "android", target_os = "ios")))]
use anyhow::Context;
use anyhow::Result;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use vdpi::config::EngineMode;
use vdpi::i18n::{self, Lang};
use vdpi::server::REPOSITORY_URL;
use vdpi::service::{ControlCenterStatus, InstalledInfo, LiveEngineStatus, ServiceState};
use vdpi::update::VersionRelation;
use vdpi_core::config::{SplitTunnelConfig, SplitTunnelMode};

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tui;

#[cfg(test)]
#[inline]
pub(super) fn active_lang() -> Lang {
    i18n::active_lang_with_fallback(Lang::En)
}

#[cfg(not(test))]
#[inline]
pub(super) fn active_lang() -> Lang {
    i18n::active_lang()
}

#[inline]
pub(super) fn tr(en: &'static str, tr_text: &'static str) -> &'static str {
    i18n::tr_for(active_lang(), en, tr_text)
}

fn persist_language_to_config_at(path: &Path, lang: Lang) -> Result<()> {
    let (_, mut file_cfg) = vdpi::config_file::load_file_config_or_default(Some(path), false)?;
    file_cfg
        .schema_version
        .get_or_insert(vdpi::config_file::CONFIG_SCHEMA_VERSION);
    file_cfg.language = Some(lang.code().to_string());
    vdpi::config_file::save_file_config_atomic(path, &file_cfg)
}

#[cfg(not(test))]
fn persist_language_to_config(lang: Lang) -> Result<()> {
    persist_language_to_config_at(&vdpi::config_file::user_config_path(), lang)
}

#[cfg(test)]
fn persist_language_to_config(_lang: Lang) -> Result<()> {
    Ok(())
}

pub(super) fn toggle_and_persist_language() -> String {
    let next = active_lang().toggle();
    i18n::set_language_pref(Some(next));
    let save_err = persist_language_to_config(next).err();
    if active_lang() != next {
        return match next {
            Lang::En => "Language saved (overridden by VDPI_LANG).".to_string(),
            Lang::Tr => "Dil kaydedildi (VDPI_LANG etkin).".to_string(),
        };
    }
    match (next, save_err) {
        (Lang::En, None) => "Language set to English.".to_string(),
        (Lang::Tr, None) => "Dil Türkçe olarak ayarlandı.".to_string(),
        (Lang::En, Some(_)) => {
            "Language set to English (warning: failed to save config).".to_string()
        }
        (Lang::Tr, Some(_)) => {
            "Dil Türkçe olarak ayarlandı (uyarı: yapılandırma kaydedilemedi).".to_string()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Run,
    Unattended,
    Install,
    Update,
    PauseService,
    ResumeService,
    SwitchEngine(EngineMode),
    SelectDns,
    SetDns(String),
    SplitTunnel,
    Dashboard,
    Doctor,
    Uninstall,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsPreset {
    pub name: &'static str,
    pub addr: &'static str,
    pub hint: &'static str,
}

pub const DNS_PRESETS: [DnsPreset; 6] = [
    DnsPreset {
        name: "Cloudflare",
        addr: "1.1.1.1",
        hint: "Fast, privacy-focused public DNS (default).",
    },
    DnsPreset {
        name: "Google",
        addr: "8.8.8.8",
        hint: "Global low-latency public DNS.",
    },
    DnsPreset {
        name: "AdGuard",
        addr: "94.140.14.14",
        hint: "Blocks ads, trackers, and phishing domains.",
    },
    DnsPreset {
        name: "AdGuard Unfiltered",
        addr: "94.140.14.140",
        hint: "Privacy-focused DNS without ad filtering.",
    },
    DnsPreset {
        name: "Quad9",
        addr: "9.9.9.9",
        hint: "Blocks known malware and phishing domains.",
    },
    DnsPreset {
        name: "Cloudflare Family",
        addr: "1.1.1.3",
        hint: "Blocks malware and adult content.",
    },
];

pub(super) fn dns_preset_hint(preset: &DnsPreset) -> &'static str {
    match active_lang() {
        Lang::En => preset.hint,
        Lang::Tr => match preset.addr {
            "1.1.1.1" => "Hızlı, gizlilik odaklı genel DNS (varsayılan).",
            "8.8.8.8" => "Küresel düşük gecikmeli genel DNS.",
            "94.140.14.14" => "Reklam, izleyici ve oltalama alan adlarını engeller.",
            "94.140.14.140" => "Reklam filtrelemesiz, gizlilik odaklı DNS.",
            "9.9.9.9" => "Bilinen zararlı yazılım ve oltalama alan adlarını engeller.",
            "1.1.1.3" => "Zararlı yazılım ve yetişkin içeriğini engeller.",
            _ => preset.hint,
        },
    }
}

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub(super) const CUSTOM_DNS_HINT: &str = "Enter any custom IPv4, IPv6, or https:// DoH URL.";

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub(super) fn custom_dns_hint() -> &'static str {
    tr(
        CUSTOM_DNS_HINT,
        "Özel bir IPv4, IPv6 veya https:// DoH adresi girin.",
    )
}

pub(super) fn is_custom_dns(addr: &str) -> bool {
    let trimmed = addr.trim();
    !trimmed.is_empty()
        && !DNS_PRESETS
            .iter()
            .any(|p| p.addr.eq_ignore_ascii_case(trimmed))
}

fn redact_custom_dns_display(addr: &str) -> String {
    let redacted = vdpi_core::dns::redact_dns_for_display(addr);
    if let Some(host) = redacted.strip_prefix("https://") {
        return host.to_string();
    }
    redacted
}

pub(super) fn shorten_custom_dns(addr: &str, max_chars: usize) -> String {
    let trimmed = addr.trim();
    let redacted = redact_custom_dns_display(trimmed);
    let display = if redacted.is_empty() {
        trimmed
    } else {
        redacted.as_str()
    };
    if max_chars == 0 {
        return String::new();
    }
    if display.chars().count() <= max_chars {
        return display.to_string();
    }
    if max_chars == 1 {
        return display.chars().take(1).collect();
    }
    let mut out: String = display.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

pub fn format_dns_label(addr: &str) -> String {
    let trimmed = addr.trim();
    if let Some(preset) = DNS_PRESETS
        .iter()
        .find(|p| p.addr.eq_ignore_ascii_case(trimmed))
    {
        format!("{} ({})", preset.name, preset.addr)
    } else if trimmed.is_empty() {
        format!("{} ({})", DNS_PRESETS[0].name, DNS_PRESETS[0].addr)
    } else {
        let prefix = tr("Custom", "Özel");
        format!("{prefix} ({})", shorten_custom_dns(trimmed, 28))
    }
}

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub(super) fn dns_preset_index(addr: &str) -> usize {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return 0;
    }
    DNS_PRESETS
        .iter()
        .position(|p| p.addr.eq_ignore_ascii_case(trimmed))
        .unwrap_or(DNS_PRESETS.len())
}

fn format_split_summary(split: &SplitTunnelConfig) -> String {
    match active_lang() {
        Lang::En => split.summary_label(),
        Lang::Tr => {
            let count = split.apps.len();
            match split.mode {
                SplitTunnelMode::All => "Tüm uygulamalar".to_string(),
                SplitTunnelMode::Exclude => format!("Hariç tut ({count} uygulama)"),
                SplitTunnelMode::Include => format!("Dahil et ({count} uygulama)"),
            }
        }
    }
}

fn dns_server_item(current_dns: &str) -> MenuItem {
    MenuItem::new(
        Choice::SelectDns,
        format!(
            "{} · {}",
            tr("Choose DNS server", "DNS sunucusu seç"),
            format_dns_label(current_dns)
        ),
        tr(
            "Pick a preset or enter a custom DNS / DoH server.",
            "Hazır bir sunucu seçin veya özel DNS / DoH adresi girin.",
        ),
    )
}

fn split_tunnel_item(split: &SplitTunnelConfig) -> MenuItem {
    MenuItem::new(
        Choice::SplitTunnel,
        format!(
            "{} · {}",
            tr("Split tunneling", "Bölünmüş tünel"),
            format_split_summary(split)
        ),
        tr(
            "Choose which apps use or bypass anti-DPI (with live search).",
            "Hangi uygulamaların anti-DPI kullanacağını veya atlayacağını seçin (canlı arama).",
        ),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub(super) enum StatusTone {
    Active,  // emerald (service running / DPI active)
    Accent,  // ice-blue (update available)
    Warning, // amber (service paused / downgrade / unreadable)
    Neutral, // muted steel (not installed / offline)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StatusRow {
    pub label: String,
    pub value: String,
    #[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
    pub tone: StatusTone,
    pub badge: Option<(String, StatusTone)>,
}

impl StatusRow {
    fn new(label: impl Into<String>, value: impl Into<String>, tone: StatusTone) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            tone,
            badge: None,
        }
    }

    fn with_badge(mut self, badge: Option<(String, StatusTone)>) -> Self {
        self.badge = badge;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MenuItem {
    pub choice: Choice,
    pub title: String,
    pub hint: String,
}

impl MenuItem {
    fn new(choice: Choice, title: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            choice,
            title: title.into(),
            hint: hint.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LauncherMenu {
    pub status_rows: Vec<StatusRow>,
    pub notice: Option<String>,
    pub items: Vec<MenuItem>,
}

fn format_mode_label(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("combo") {
        "Combo"
    } else if trimmed.eq_ignore_ascii_case("tls-record") || trimmed.eq_ignore_ascii_case("tlsrec") {
        "TLS Record"
    } else if trimmed.eq_ignore_ascii_case("fragment") || trimmed.eq_ignore_ascii_case("chunk") {
        "Fragment"
    } else if trimmed.eq_ignore_ascii_case("split") {
        "Split"
    } else {
        trimmed
    }
}

fn build_service_status_row(status: &ControlCenterStatus) -> StatusRow {
    let label = tr("Service", "Servis");
    let is_tr = active_lang() == Lang::Tr;
    match (status.service_state, status.installed.as_ref()) {
        (ServiceState::NotInstalled, None) => StatusRow::new(
            label,
            tr("Not installed", "Kurulu değil"),
            StatusTone::Neutral,
        ),
        (ServiceState::NotInstalled, Some(info)) => {
            let value = match info.installed_version.as_deref() {
                Some(ver) if is_tr => format!("Kurulu v{ver} (servis kayıtlı değil)"),
                Some(ver) => format!("Installed v{ver} (service not registered)"),
                None => tr(
                    "Installed (version unreadable, service not registered)",
                    "Kurulu (sürüm okunamadı, servis kayıtlı değil)",
                )
                .to_string(),
            };
            StatusRow::new(label, value, StatusTone::Warning)
        }
        (ServiceState::Running, Some(info)) => match info.relation {
            VersionRelation::Newer => {
                let old = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("unknown", "bilinmiyor"));
                let new = info.current_version;
                let value = if is_tr {
                    format!("Çalışıyor · v{old} -> v{new} güncelleme hazır")
                } else {
                    format!("Running · v{old} -> v{new} update ready")
                };
                StatusRow::new(label, value, StatusTone::Accent)
            }
            VersionRelation::Same => {
                let value = if is_tr {
                    format!("Çalışıyor · v{}", info.current_version)
                } else {
                    format!("Running · v{}", info.current_version)
                };
                StatusRow::new(label, value, StatusTone::Active)
            }
            VersionRelation::Older => {
                let inst = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("newer", "daha yeni"));
                let cur = info.current_version;
                let value = if is_tr {
                    format!("Çalışıyor · v{inst} (bu v{cur} sürümünden yeni)")
                } else {
                    format!("Running · v{inst} (newer than this v{cur})")
                };
                StatusRow::new(label, value, StatusTone::Warning)
            }
            VersionRelation::Unknown => StatusRow::new(
                label,
                tr("Running · version unreadable", "Çalışıyor · sürüm okunamadı"),
                StatusTone::Warning,
            ),
        },
        (ServiceState::Running, None) => {
            let value = match status
                .live_engine
                .as_ref()
                .and_then(|live| live.version.as_deref())
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                Some(ver) if is_tr => {
                    format!("Çalışıyor · v{}", ver.trim_start_matches(['v', 'V']))
                }
                Some(ver) => format!("Running · v{}", ver.trim_start_matches(['v', 'V'])),
                None => tr("Running", "Çalışıyor").to_string(),
            };
            StatusRow::new(label, value, StatusTone::Active)
        }
        (ServiceState::Stopped, Some(info)) => match info.relation {
            VersionRelation::Newer => {
                let old = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("unknown", "bilinmiyor"));
                let new = info.current_version;
                let value = if is_tr {
                    format!("Duraklatıldı · v{old} -> v{new} güncelleme hazır")
                } else {
                    format!("Paused · v{old} -> v{new} update ready")
                };
                StatusRow::new(label, value, StatusTone::Accent)
            }
            VersionRelation::Same => {
                let value = if is_tr {
                    format!(
                        "Duraklatıldı · v{} (geçici olarak durduruldu)",
                        info.current_version
                    )
                } else {
                    format!("Paused · v{} (temporarily stopped)", info.current_version)
                };
                StatusRow::new(label, value, StatusTone::Warning)
            }
            VersionRelation::Older => {
                let inst = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("newer", "daha yeni"));
                let cur = info.current_version;
                let value = if is_tr {
                    format!("Duraklatıldı · v{inst} (bu v{cur} sürümünden yeni)")
                } else {
                    format!("Paused · v{inst} (newer than this v{cur})")
                };
                StatusRow::new(label, value, StatusTone::Warning)
            }
            VersionRelation::Unknown => StatusRow::new(
                label,
                tr(
                    "Paused · version unreadable (temporarily stopped)",
                    "Duraklatıldı · sürüm okunamadı (geçici olarak durduruldu)",
                ),
                StatusTone::Warning,
            ),
        },
        (ServiceState::Stopped, None) => StatusRow::new(
            label,
            tr(
                "Paused (temporarily stopped)",
                "Duraklatıldı (geçici olarak durduruldu)",
            ),
            StatusTone::Warning,
        ),
    }
}

const fn engine_label(engine: EngineMode) -> &'static str {
    match engine {
        EngineMode::Tun => "TUN",
        EngineMode::Proxy => "Proxy",
    }
}

fn format_rss_mb(rss_kb: Option<u64>) -> Option<String> {
    let kb = rss_kb.filter(|&kb| kb > 0)?;
    let mb = (kb.saturating_add(512) / 1024).max(1);
    Some(format!("{mb} MB"))
}

fn build_anti_dpi_row(live: &LiveEngineStatus, configured_dns: &str) -> StatusRow {
    let mut parts: Vec<String> = Vec::new();
    if let Some(mode) = live
        .mode
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
    {
        parts.push(format_mode_label(mode).to_string());
    }
    if let Some(doh) = live.doh {
        let dns_addr = live
            .dns_addr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| configured_dns.trim());
        let is_doh = if dns_addr.is_empty() {
            doh
        } else {
            vdpi_core::dns::is_effective_doh_target(dns_addr, doh)
        };
        let label = if is_doh {
            tr("DoH on", "DoH açık")
        } else {
            tr("DoH off", "DoH kapalı")
        };
        parts.push(label.to_string());
    }
    if let Some(block_quic) = live.block_quic {
        let label = if block_quic {
            tr("QUIC blocked", "QUIC engelli")
        } else {
            tr("QUIC allowed", "QUIC açık")
        };
        parts.push(label.to_string());
    }

    let active_word = tr("Active", "Etkin");
    let value = if parts.is_empty() {
        if live.engine == EngineMode::Tun {
            active_word.to_string()
        } else {
            format!("{active_word} · {}", SocketAddr::new(live.addr, live.port))
        }
    } else {
        format!("{active_word} · {}", parts.join(" · "))
    };
    StatusRow::new("Anti-DPI", value, StatusTone::Active)
}

fn build_engine_row(status: &ControlCenterStatus) -> StatusRow {
    let row_label = tr("Engine", "Motor");
    let badge = status
        .live_engine
        .as_ref()
        .and_then(|l| l.vpn_conflict.as_deref())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .or_else(|| {
            status
                .vpn_conflict
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
        })
        .map(|v| (format!("VPN: {v}"), StatusTone::Warning));

    if let Some(live) = status.live_engine.as_ref() {
        let value = match live.engine {
            EngineMode::Tun => {
                let mut parts = vec!["TUN".to_string()];
                if let Some(iface) = live
                    .tun_interface
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    parts.push(iface.to_string());
                }
                if let Some(nic) = live
                    .physical_nic
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    parts.push(nic.to_string());
                }
                if let Some(rss) = format_rss_mb(live.rss_kb) {
                    let current_len: usize = parts.iter().map(|p| p.chars().count()).sum::<usize>()
                        + parts.len().saturating_sub(1) * 3;
                    let max_len = if badge.is_some() { 38 } else { 48 };
                    if current_len + 3 + rss.len() <= max_len {
                        parts.push(rss);
                    }
                }
                parts.join(" · ")
            }
            EngineMode::Proxy => format!("Proxy · {}", SocketAddr::new(live.addr, live.port)),
        };

        return StatusRow::new(row_label, value, StatusTone::Active).with_badge(badge);
    }

    let label = engine_label(status.configured_engine);
    let state_suffix = match status.service_state {
        ServiceState::Stopped => tr("paused", "duraklatıldı"),
        ServiceState::Running | ServiceState::NotInstalled => tr("selected", "seçili"),
    };
    StatusRow::new(
        row_label,
        format!("{label} ({state_suffix})"),
        StatusTone::Neutral,
    )
    .with_badge(badge)
}

fn build_status_rows(status: &ControlCenterStatus, configured_dns: &str) -> Vec<StatusRow> {
    let anti_dpi_row = if let Some(live) = status.live_engine.as_ref() {
        build_anti_dpi_row(live, configured_dns)
    } else if status.service_state == ServiceState::Running {
        StatusRow::new(
            "Anti-DPI",
            tr(
                "Starting or listening on custom port",
                "Başlatılıyor veya özel portta dinliyor",
            ),
            StatusTone::Warning,
        )
    } else {
        StatusRow::new(
            "Anti-DPI",
            tr(
                "Offline · routes & proxies restored",
                "Çevrimdışı · yönlendirmeler ve proxy geri yüklendi",
            ),
            StatusTone::Neutral,
        )
    };

    vec![
        build_service_status_row(status),
        build_engine_row(status),
        anti_dpi_row,
    ]
}

fn pause_or_resume_item(service_state: ServiceState) -> Option<MenuItem> {
    match service_state {
        ServiceState::Running => Some(MenuItem::new(
            Choice::PauseService,
            tr("Pause background service", "Arka plan servisini duraklat"),
            tr(
                "Temporarily stops vdpi and restores routes & proxies.",
                "vdpi'yi geçici olarak durdurur, yönlendirme ve proxy ayarlarını geri yükler.",
            ),
        )),
        ServiceState::Stopped => Some(MenuItem::new(
            Choice::ResumeService,
            tr("Resume background service", "Arka plan servisini sürdür"),
            tr(
                "Starts the service and re-enables routes & proxies.",
                "Servisi başlatır, yönlendirme ve proxy ayarlarını yeniden etkinleştirir.",
            ),
        )),
        ServiceState::NotInstalled => None,
    }
}

fn uninstall_item() -> MenuItem {
    MenuItem::new(
        Choice::Uninstall,
        tr("Uninstall vdpi", "vdpi'yi kaldır"),
        tr(
            "Removes service and restores network settings.",
            "Servisi kaldırır ve ağ ayarlarını geri yükler.",
        ),
    )
}

fn doctor_item() -> MenuItem {
    MenuItem::new(
        Choice::Doctor,
        tr("Run diagnostics", "Tanılama çalıştır"),
        tr(
            "Tests DNS and bypass connectivity.",
            "DNS ve atlatma bağlantısını test eder.",
        ),
    )
}

fn active_or_configured_engine(status: &ControlCenterStatus) -> EngineMode {
    status
        .live_engine
        .as_ref()
        .map_or(status.configured_engine, |live| live.engine)
}

#[cfg(target_os = "macos")]
const TUN_IFACE_LABEL: &str = "utun";
#[cfg(not(target_os = "macos"))]
const TUN_IFACE_LABEL: &str = "vdpi0";

fn switch_engine_item(current: EngineMode) -> MenuItem {
    match current {
        EngineMode::Proxy => {
            let hint = match active_lang() {
                Lang::En => format!(
                    "All apps, Roblox & Discord voice via {TUN_IFACE_LABEL} (requires Admin)."
                ),
                Lang::Tr => format!(
                    "{TUN_IFACE_LABEL} üzerinden tüm uygulamalar, Roblox ve Discord ses (Yönetici gerekir)."
                ),
            };
            MenuItem::new(
                Choice::SwitchEngine(EngineMode::Tun),
                tr("Switch to TUN mode", "TUN moduna geç"),
                hint,
            )
        }
        EngineMode::Tun => MenuItem::new(
            Choice::SwitchEngine(EngineMode::Proxy),
            tr("Switch to Proxy mode", "Proxy moduna geç"),
            tr(
                "Browsers & apps - no Admin, lightweight, VPN-friendly.",
                "Tarayıcı ve uygulamalar - Yönetici gerektirmez, hafif, VPN uyumlu.",
            ),
        ),
    }
}

fn dashboard_item() -> MenuItem {
    MenuItem::new(
        Choice::Dashboard,
        tr("Open live dashboard", "Canlı paneli aç"),
        tr(
            "Real-time throughput, connections, ISP stage & diagnostics.",
            "Gerçek zamanlı hız, bağlantılar, İSS aşaması ve tanılama.",
        ),
    )
}

fn quit_item() -> MenuItem {
    MenuItem::new(
        Choice::Cancel,
        tr("Quit", "Çıkış"),
        tr(
            "Exit without changing anything.",
            "Hiçbir değişiklik yapmadan çık.",
        ),
    )
}

fn build_same_version_items(
    service_state: ServiceState,
    current_engine: EngineMode,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    has_live_engine: bool,
) -> Vec<MenuItem> {
    let update_online = || {
        MenuItem::new(
            Choice::Update,
            tr(
                "Check for updates online",
                "Güncellemeleri çevrimiçi denetle",
            ),
            tr(
                "Checks GitHub Releases and updates automatically.",
                "GitHub sürümlerini kontrol eder ve otomatik günceller.",
            ),
        )
    };
    let run_this_session = || {
        MenuItem::new(
            Choice::Run,
            tr(
                "Run directly (this session)",
                "Doğrudan çalıştır (bu oturum)",
            ),
            tr(
                "Active while this terminal is open.",
                "Bu terminal açık kaldığı sürece etkindir.",
            ),
        )
    };

    match service_state {
        ServiceState::Running => {
            let mut items = Vec::with_capacity(if has_live_engine { 9 } else { 8 });
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.extend([
                MenuItem::new(
                    Choice::PauseService,
                    tr("Pause background service", "Arka plan servisini duraklat"),
                    tr(
                        "Temporarily stops vdpi and restores routes & proxies.",
                        "vdpi'yi geçici olarak durdurur, yönlendirme ve proxy ayarlarını geri yükler.",
                    ),
                ),
                switch_engine_item(current_engine),
                dns_server_item(configured_dns),
                split_tunnel_item(split_tunnel),
                doctor_item(),
                update_online(),
                uninstall_item(),
                quit_item(),
            ]);
            items
        }
        ServiceState::Stopped => {
            let mut items = Vec::with_capacity(9);
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.push(MenuItem::new(
                Choice::ResumeService,
                tr("Resume background service", "Arka plan servisini sürdür"),
                tr(
                    "Starts the service and re-enables routes & proxies.",
                    "Servisi başlatır, yönlendirme ve proxy ayarlarını yeniden etkinleştirir.",
                ),
            ));
            items.push(switch_engine_item(current_engine));
            items.push(dns_server_item(configured_dns));
            items.push(split_tunnel_item(split_tunnel));
            if !has_live_engine {
                items.push(run_this_session());
            }
            items.extend([doctor_item(), update_online(), uninstall_item(), quit_item()]);
            items
        }
        ServiceState::NotInstalled => {
            let mut items = Vec::with_capacity(9);
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.push(MenuItem::new(
                Choice::Install,
                tr("Reinstall / repair service", "Servisi yeniden kur / onar"),
                tr(
                    "Rewrites the background service and restarts it.",
                    "Arka plan servisini yeniden yazar ve başlatır.",
                ),
            ));
            items.push(switch_engine_item(current_engine));
            items.push(dns_server_item(configured_dns));
            items.push(split_tunnel_item(split_tunnel));
            if !has_live_engine {
                items.push(run_this_session());
            }
            items.extend([doctor_item(), update_online(), uninstall_item(), quit_item()]);
            items
        }
    }
}

#[cfg(test)]
pub(super) fn build_menu(status: &ControlCenterStatus, notice: Option<&str>) -> LauncherMenu {
    build_menu_with_dns(status, notice, DNS_PRESETS[0].addr)
}

#[allow(dead_code)]
pub(super) fn build_menu_with_dns(
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
) -> LauncherMenu {
    build_menu_with_options(
        status,
        notice,
        configured_dns,
        &SplitTunnelConfig::default(),
    )
}

pub(super) fn build_menu_with_options(
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
) -> LauncherMenu {
    let status_rows = build_status_rows(status, configured_dns);
    let notice = notice
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let current_engine = active_or_configured_engine(status);
    let has_live_engine = status.live_engine.is_some();
    let is_tr = active_lang() == Lang::Tr;

    let items = match (status.installed.as_ref(), status.service_state) {
        (None, ServiceState::NotInstalled) => {
            let mut items = Vec::with_capacity(if has_live_engine { 8 } else { 7 });
            if has_live_engine {
                items.push(dashboard_item());
            }
            items.extend([
                MenuItem::new(
                    Choice::Run,
                    tr("Run directly", "Doğrudan çalıştır"),
                    tr(
                        "Active while this terminal is open.",
                        "Bu terminal açık kaldığı sürece etkindir.",
                    ),
                ),
                switch_engine_item(current_engine),
                MenuItem::new(
                    Choice::Install,
                    tr(
                        "Install for automatic startup",
                        "Otomatik başlatma için kur",
                    ),
                    tr(
                        "Runs in the background after you close it.",
                        "Kapattıktan sonra arka planda çalışmaya devam eder.",
                    ),
                ),
                dns_server_item(configured_dns),
                split_tunnel_item(split_tunnel),
                doctor_item(),
                quit_item(),
            ]);
            items
        }
        (None, service_state) => build_same_version_items(
            service_state,
            current_engine,
            configured_dns,
            split_tunnel,
            has_live_engine,
        ),
        (Some(info), service_state) => match info.relation {
            VersionRelation::Newer => {
                let old = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("unknown", "bilinmiyor"));
                let new = info.current_version;
                let mut items = Vec::with_capacity(9);
                items.push(MenuItem::new(
                    Choice::Install,
                    if is_tr {
                        format!("Kurulu vdpi'yi güncelle (v{old} -> v{new})")
                    } else {
                        format!("Update installed vdpi (v{old} -> v{new})")
                    },
                    tr(
                        "Replaces the installed service and restarts cleanly.",
                        "Kurulu servisi günceller ve temiz biçimde yeniden başlatır.",
                    ),
                ));
                if has_live_engine {
                    items.push(dashboard_item());
                }
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
                if service_state != ServiceState::Running && !has_live_engine {
                    items.push(MenuItem::new(
                        Choice::Run,
                        tr(
                            "Run directly without updating",
                            "Güncellemeden doğrudan çalıştır",
                        ),
                        tr(
                            "Active while this terminal is open.",
                            "Bu terminal açık kaldığı sürece etkindir.",
                        ),
                    ));
                }
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
            VersionRelation::Same => build_same_version_items(
                service_state,
                current_engine,
                configured_dns,
                split_tunnel,
                has_live_engine,
            ),
            VersionRelation::Older => {
                let inst = info
                    .installed_version
                    .as_deref()
                    .unwrap_or_else(|| tr("newer", "daha yeni"));
                let cur = info.current_version;
                let mut items = Vec::with_capacity(9);
                if has_live_engine {
                    items.push(dashboard_item());
                }
                if service_state != ServiceState::Running && !has_live_engine {
                    items.push(MenuItem::new(
                        Choice::Run,
                        tr("Run directly", "Doğrudan çalıştır"),
                        if is_tr {
                            format!("Kurulu v{inst} sürümüne dokunma.")
                        } else {
                            format!("Keep installed v{inst} untouched.")
                        },
                    ));
                }
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
                items.push(MenuItem::new(
                    Choice::Install,
                    if is_tr {
                        format!("Kurulu vdpi sürümünü düşür (v{inst} -> v{cur})")
                    } else {
                        format!("Downgrade installed vdpi (v{inst} -> v{cur})")
                    },
                    if is_tr {
                        format!("Kurulu v{inst} sürümünü bu eski v{cur} ikilisiyle değiştirir.")
                    } else {
                        format!("Replaces installed v{inst} with this older v{cur} binary.")
                    },
                ));
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
            VersionRelation::Unknown => {
                let cur = info.current_version;
                let mut items = Vec::with_capacity(9);
                if has_live_engine {
                    items.push(dashboard_item());
                }
                items.push(MenuItem::new(
                    Choice::Install,
                    if is_tr {
                        format!("Kurulu vdpi'yi güncelle / onar (v{cur})")
                    } else {
                        format!("Update / repair installed vdpi (to v{cur})")
                    },
                    tr(
                        "Replaces the installed service and restarts cleanly.",
                        "Kurulu servisi günceller ve temiz biçimde yeniden başlatır.",
                    ),
                ));
                if let Some(toggle) = pause_or_resume_item(service_state) {
                    items.push(toggle);
                }
                items.push(switch_engine_item(current_engine));
                items.push(dns_server_item(configured_dns));
                items.push(split_tunnel_item(split_tunnel));
                if service_state != ServiceState::Running && !has_live_engine {
                    items.push(MenuItem::new(
                        Choice::Run,
                        tr("Run directly", "Doğrudan çalıştır"),
                        tr(
                            "Active while this terminal is open.",
                            "Bu terminal açık kaldığı sürece etkindir.",
                        ),
                    ));
                }
                items.push(uninstall_item());
                items.push(quit_item());
                items
            }
        },
    };

    LauncherMenu {
        status_rows,
        notice,
        items,
    }
}

/// Legacy v0.5.x builds wrote a `run-directly` marker next to the binary to skip
/// the launcher on subsequent double-clicks. Control Center is now always the
/// interactive entry point, so remove any stale marker on sight (best-effort)
/// and never bypass Control Center.
fn migrate_legacy_preference_at(marker_path: Option<&Path>) {
    if let Some(path) = marker_path.filter(|p| p.is_file()) {
        let _ = fs::remove_file(path);
    }
}

fn should_auto_run(
    _explicit: bool,
    _marker_path: Option<&Path>,
    _status: &ControlCenterStatus,
) -> bool {
    false
}

#[allow(dead_code)]
pub fn choose<F>(
    explicit: bool,
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    refresh: F,
) -> Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    choose_with_options(
        explicit,
        status,
        notice,
        configured_dns,
        &SplitTunnelConfig::default(),
        refresh,
    )
}

pub fn choose_with_options<F>(
    explicit: bool,
    status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    mut refresh: F,
) -> Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    #[cfg(not(test))]
    i18n::init_from_config();

    let state = preference_path();
    migrate_legacy_preference_at(state.as_deref());
    if should_auto_run(explicit, state.as_deref(), status) {
        return Ok(Choice::Run);
    }

    let selected = if io::stdin().is_terminal() && io::stdout().is_terminal() {
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            if env::var("TERM").as_deref() == Ok("dumb") {
                read_choice_with_options(
                    io::stdin().lock(),
                    io::stderr().lock(),
                    status,
                    notice,
                    configured_dns,
                    split_tunnel,
                    &mut refresh,
                )?
            } else {
                let color = env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());
                match tui::choose_with_options(
                    color,
                    status,
                    notice,
                    configured_dns,
                    split_tunnel,
                    &mut refresh,
                ) {
                    Ok(choice) => choice,
                    Err(_) => read_choice_with_options(
                        io::stdin().lock(),
                        io::stderr().lock(),
                        status,
                        notice,
                        configured_dns,
                        split_tunnel,
                        &mut refresh,
                    )
                    .context("running the terminal launcher")?,
                }
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            read_choice_with_options(
                io::stdin().lock(),
                io::stderr().lock(),
                status,
                notice,
                configured_dns,
                split_tunnel,
                &mut refresh,
            )?
        }
    } else if explicit {
        anyhow::bail!("no interactive launcher available; use `vdpi start` or `vdpi install`");
    } else {
        // Noninteractive bare invocations retain the existing foreground behavior.
        return Ok(Choice::Unattended);
    };

    Ok(selected)
}

pub fn print_run_notice() {
    let run_label = tr("Run directly", "Doğrudan çalıştır");
    let run_notice = tr(
        "vdpi is running without installation. Run `vdpi install` to enable automatic startup.",
        "vdpi kurulumsuz çalışıyor. Otomatik başlatma için `vdpi install` komutunu çalıştırın.",
    );
    eprintln!("  {run_label}  |  {run_notice}");
    eprintln!("  GitHub        |  {REPOSITORY_URL}");
}

#[cfg(any(windows, test))]
#[allow(dead_code)]
fn write_pause_prompt(
    mut input: impl BufRead,
    mut output: impl Write,
    msg: &str,
) -> io::Result<()> {
    let trimmed = msg.trim();
    writeln!(output)?;
    if !trimmed.is_empty() {
        for line in trimmed.lines() {
            writeln!(output, "  {line}")?;
        }
    }
    writeln!(
        output,
        "  {}",
        tr(
            "Press Enter to close this window.",
            "Bu pencereyi kapatmak için Enter'a basın."
        )
    )?;
    output.flush()?;
    let _ = input.read_line(&mut String::new())?;
    Ok(())
}

/// Pauses before exit when running in a dedicated Windows console window
/// (such as a double-clicked `vdpi.exe`), printing `msg` if non-empty so fatal
/// errors remain visible before the window closes.
#[allow(dead_code)]
pub fn pause_on_own_console(msg: &str) {
    #[cfg(not(windows))]
    let _ = msg;
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        let _ = write_pause_prompt(io::stdin().lock(), io::stderr().lock(), msg);
    }
}

#[allow(dead_code)]
pub fn install_finished(result: &Result<()>, installed_before: Option<&InstalledInfo>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(not(windows))]
    let _ = installed_before;
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        let msg = match result {
            Ok(()) => format!(
                "{}\nGitHub: {REPOSITORY_URL}",
                install_success_message(installed_before)
            ),
            Err(error) => format!(
                "{}: {error:#}",
                tr("Installation did not finish", "Kurulum tamamlanamadı")
            ),
        };
        pause_on_own_console(&msg);
    }
}

#[cfg(any(windows, test))]
#[allow(dead_code)]
fn install_success_message(installed_before: Option<&InstalledInfo>) -> String {
    match installed_before {
        Some(info) if info.relation == VersionRelation::Newer => match active_lang() {
            Lang::En => format!("vdpi updated to v{} and restarted.", info.current_version),
            Lang::Tr => format!(
                "vdpi v{} sürümüne güncellendi ve yeniden başlatıldı.",
                info.current_version
            ),
        },
        _ => tr(
            "vdpi is installed and starts automatically.",
            "vdpi kuruldu ve otomatik olarak başlayacak.",
        )
        .to_string(),
    }
}

#[allow(dead_code)]
pub fn update_finished(result: &Result<()>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        let msg = match result {
            Ok(()) => format!(
                "{}\nGitHub: {REPOSITORY_URL}",
                tr("Update completed.", "Güncelleme tamamlandı.")
            ),
            Err(error) => format!(
                "{}: {error:#}",
                tr("Update did not finish", "Güncelleme tamamlanamadı")
            ),
        };
        pause_on_own_console(&msg);
    }
}

#[allow(dead_code)]
pub fn uninstall_finished(result: &Result<()>) {
    if result.is_ok() {
        clear_preference();
    }
    #[cfg(windows)]
    if io::stdin().is_terminal() && has_own_console() {
        let msg = match result {
            Ok(()) => format!(
                "{}\nGitHub: {REPOSITORY_URL}",
                tr(
                    "vdpi has been uninstalled and routes & proxies restored.",
                    "vdpi kaldırıldı, yönlendirme ve proxy ayarları geri yüklendi.",
                )
            ),
            Err(error) => format!(
                "{}: {error:#}",
                tr("Uninstall did not finish", "Kaldırma tamamlanamadı")
            ),
        };
        pause_on_own_console(&msg);
    }
}

#[allow(dead_code)]
pub fn wait_for_continue_if_interactive() {
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        eprintln!(
            "\n  {}",
            tr(
                "Press Enter to return to vdpi Control Center...",
                "vdpi Kontrol Merkezi'ne dönmek için Enter'a basın...",
            )
        );
        let _ = io::stdin().read_line(&mut String::new());
    }
}

#[cfg(windows)]
#[allow(dead_code)]
fn has_own_console() -> bool {
    let mut processes = [0; 2];
    // SAFETY: `processes` is writable for two process IDs; `GetConsoleWindow` and
    // `IsWindowVisible` are safe Win32 queries when `hwnd` is non-null.
    unsafe {
        if windows_sys::Win32::System::Console::GetConsoleProcessList(processes.as_mut_ptr(), 2)
            != 1
        {
            return false;
        }
        let hwnd = windows_sys::Win32::System::Console::GetConsoleWindow();
        !hwnd.is_null() && windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible(hwnd) != 0
    }
}

pub fn clear_preference() {
    if let Some(path) = preference_path() {
        if let Err(e) = fs::remove_file(path) {
            if e.kind() != io::ErrorKind::NotFound {
                match active_lang() {
                    Lang::En => {
                        eprintln!("vdpi could not clear the previous run-only choice: {e}");
                    }
                    Lang::Tr => {
                        eprintln!("vdpi önceki yalnızca-çalıştır tercihini temizleyemedi: {e}");
                    }
                }
            }
        }
    }
}

fn preference_path() -> Option<PathBuf> {
    Some(env::current_exe().ok()?.parent()?.join("run-directly"))
}

pub(super) fn localize_custom_dns_error(err: &str) -> std::borrow::Cow<'_, str> {
    if active_lang() != Lang::Tr {
        return std::borrow::Cow::Borrowed(err);
    }
    let translated = match err {
        "DNS server cannot be empty" => "DNS sunucusu boş olamaz",
        "DNS server cannot contain control characters" => {
            "DNS sunucusu kontrol karakterleri içeremez"
        }
        "DNS server cannot contain whitespace" => "DNS sunucusu boşluk içeremez",
        "Enter a valid IPv4/IPv6 address or https:// DoH URL" => {
            "Geçerli bir IPv4/IPv6 adresi veya https:// DoH adresi girin"
        }
        "DNS IP cannot be 0.0.0.0" => "DNS IP adresi 0.0.0.0 olamaz",
        "DNS IP cannot be ::" => "DNS IP adresi :: olamaz",
        "DNS IP cannot be a multicast address" => {
            "DNS IP adresi çoklu yayın (multicast) adresi olamaz"
        }
        "DNS IP cannot be a broadcast address" => "DNS IP adresi yayın (broadcast) adresi olamaz",
        "Invalid port in DoH URL (must be 1-65535)" => {
            "DoH adresinde geçersiz port (1-65535 arasında olmalı)"
        }
        "Invalid hostname in DoH URL" => "DoH adresinde geçersiz alan adı",
        "Invalid hostname or IPv4 address in DoH URL" => {
            "DoH adresinde geçersiz alan adı veya IPv4 adresi"
        }
        "Invalid percent-encoding in DoH URL path" => "DoH adres yolunda geçersiz yüzde kodlaması",
        "Invalid character in DoH URL path or query" => {
            "DoH adres yolunda veya sorgusunda geçersiz karakter"
        }
        "DoH URL must start with https://" => "DoH adresi https:// ile başlamalıdır",
        "DoH URL must use https:// (http:// is not supported)" => {
            "DoH adresi https:// kullanmalıdır (http:// desteklenmez)"
        }
        "DoH URL cannot contain a '#' fragment" => "DoH adresi '#' bölümü içeremez",
        "DoH URL is missing a hostname or IP" => "DoH adresinde alan adı veya IP eksik",
        "DoH URL cannot contain userinfo (@)" => "DoH adresi kullanıcı bilgisi (@) içeremez",
        "Unclosed '[' in IPv6 DoH URL" => "IPv6 DoH adresinde kapatılmamış '[' karakteri",
        "Invalid IPv6 address in DoH URL" => "DoH adresinde geçersiz IPv6 adresi",
        "Invalid characters after IPv6 address in DoH URL" => {
            "DoH adresinde IPv6 adresinden sonra geçersiz karakterler"
        }
        "Invalid brackets in DoH URL host" => "DoH sunucu adında geçersiz köşeli parantezler",
        "Wrap IPv6 DoH hosts in [...] brackets" => "IPv6 DoH sunucularını [...] içine alın",
        _ => return std::borrow::Cow::Borrowed(err),
    };
    std::borrow::Cow::Borrowed(translated)
}

fn print_console_menu(output: &mut impl Write, menu: &LauncherMenu) -> io::Result<()> {
    writeln!(
        output,
        "\n  vdpi v{}  [g: {}]  |  {REPOSITORY_URL}",
        env!("CARGO_PKG_VERSION"),
        active_lang().badge()
    )?;
    for row in &menu.status_rows {
        if let Some((badge, _)) = &row.badge {
            writeln!(output, "  {:<8}  {}  [{badge}]", row.label, row.value)?;
        } else {
            writeln!(output, "  {:<8}  {}", row.label, row.value)?;
        }
    }
    if let Some(notice) = &menu.notice {
        writeln!(output, "  {:<8}  {notice}", tr("Notice", "Bilgi"))?;
    }
    writeln!(output)?;

    for (index, item) in menu.items.iter().enumerate() {
        writeln!(
            output,
            "  {}  {}\n     {}\n",
            index + 1,
            item.title,
            item.hint
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn read_choice<F>(
    input: impl BufRead,
    output: impl Write,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    read_choice_with_options(
        input,
        output,
        initial_status,
        notice,
        DNS_PRESETS[0].addr,
        &SplitTunnelConfig::default(),
        refresh,
    )
}

fn read_custom_dns_input(
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> io::Result<Option<String>> {
    let mut answer = String::new();
    loop {
        write!(
            output,
            "  {}",
            tr(
                "Enter custom DNS (IPv4, IPv6, or https:// DoH URL, or b back): ",
                "Özel DNS girin (IPv4, IPv6 veya https:// DoH adresi, geri için b): ",
            )
        )?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(None);
        }
        let trimmed = answer.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("b")
            || trimmed.eq_ignore_ascii_case("q")
        {
            return Ok(None);
        }
        match vdpi_core::dns::validate_custom_dns_input(trimmed) {
            Ok(normalized) => return Ok(Some(normalized)),
            Err(err) => {
                writeln!(
                    output,
                    "  {}: {}",
                    tr("Invalid DNS server", "Geçersiz DNS sunucusu"),
                    localize_custom_dns_error(&err)
                )?;
            }
        }
    }
}

fn read_dns_choice(
    input: &mut impl BufRead,
    output: &mut impl Write,
    configured_dns: &str,
) -> io::Result<Option<String>> {
    let custom_slot = DNS_PRESETS.len() + 1;
    let custom_active = is_custom_dns(configured_dns);
    let current_label = format_dns_label(configured_dns);
    match active_lang() {
        Lang::En => writeln!(output, "\n  Choose DNS server (current: {current_label})")?,
        Lang::Tr => writeln!(output, "\n  DNS sunucusu seç (mevcut: {current_label})")?,
    }
    let active_tag = tr(" [active]", " [etkin]");
    for (idx, preset) in DNS_PRESETS.iter().enumerate() {
        let active = if preset.addr.eq_ignore_ascii_case(configured_dns.trim()) {
            active_tag
        } else {
            ""
        };
        writeln!(
            output,
            "  {}  {:<18} {:<15} {}{active}",
            idx + 1,
            preset.name,
            preset.addr,
            dns_preset_hint(preset)
        )?;
    }
    let custom_label = tr("Custom DNS", "Özel DNS");
    if custom_active {
        writeln!(
            output,
            "  {custom_slot}  {:<18} {}{active_tag}",
            custom_label,
            redact_custom_dns_display(configured_dns)
        )?;
    } else {
        writeln!(
            output,
            "  {custom_slot}  {:<18} {}",
            custom_label,
            tr("IP or https:// DoH URL", "IP veya https:// DoH adresi")
        )?;
    }
    let mut answer = String::new();
    loop {
        match active_lang() {
            Lang::En => write!(output, "  Choose DNS [1-{custom_slot} / b back]: ")?,
            Lang::Tr => write!(output, "  DNS seçin [1-{custom_slot} / b geri]: ")?,
        }
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(None);
        }
        let trimmed = answer.trim();
        if trimmed.is_empty()
            || trimmed.eq_ignore_ascii_case("b")
            || trimmed.eq_ignore_ascii_case("q")
        {
            return Ok(None);
        }
        if let Ok(num) = trimmed.parse::<usize>() {
            if let Some(preset) = num.checked_sub(1).and_then(|i| DNS_PRESETS.get(i)) {
                return Ok(Some(preset.addr.to_string()));
            }
            if num == custom_slot {
                if let Some(custom) = read_custom_dns_input(input, output)? {
                    return Ok(Some(custom));
                }
                continue;
            }
        }
        match active_lang() {
            Lang::En => writeln!(
                output,
                "  Enter a number from 1 to {custom_slot}, or b to go back."
            )?,
            Lang::Tr => writeln!(
                output,
                "  1 ile {custom_slot} arasında bir sayı girin veya geri dönmek için b yazın."
            )?,
        }
    }
}

fn read_choice_with_options<F>(
    mut input: impl BufRead,
    mut output: impl Write,
    initial_status: &ControlCenterStatus,
    notice: Option<&str>,
    configured_dns: &str,
    split_tunnel: &SplitTunnelConfig,
    mut refresh: F,
) -> io::Result<Choice>
where
    F: FnMut() -> ControlCenterStatus,
{
    let mut menu = build_menu_with_options(initial_status, notice, configured_dns, split_tunnel);
    if menu.items.is_empty() {
        return Ok(Choice::Cancel);
    }

    print_console_menu(&mut output, &menu)?;

    let mut answer = String::new();
    loop {
        let count = menu.items.len();
        let choices: Vec<String> = (1..=count)
            .map(|n| n.to_string())
            .chain([
                "d".to_string(),
                "s".to_string(),
                "r".to_string(),
                "g".to_string(),
                "q".to_string(),
            ])
            .collect();
        let prompt_choices = choices.join(" / ");

        write!(output, "  {} [{prompt_choices}]: ", tr("Choose", "Seçin"))?;
        output.flush()?;
        answer.clear();
        if input.read_line(&mut answer)? == 0 {
            return Ok(Choice::Cancel);
        }
        let trimmed = answer.trim();
        if trimmed.eq_ignore_ascii_case("q") {
            return Ok(Choice::Cancel);
        }
        if trimmed.eq_ignore_ascii_case("g") {
            let notice_msg = toggle_and_persist_language();
            let latest = refresh();
            menu = build_menu_with_options(
                &latest,
                Some(&notice_msg),
                configured_dns,
                split_tunnel,
            );
            if menu.items.is_empty() {
                return Ok(Choice::Cancel);
            }
            print_console_menu(&mut output, &menu)?;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("r") {
            let latest = refresh();
            menu = build_menu_with_options(
                &latest,
                Some(tr("Status refreshed.", "Durum yenilendi.")),
                configured_dns,
                split_tunnel,
            );
            if menu.items.is_empty() {
                return Ok(Choice::Cancel);
            }
            print_console_menu(&mut output, &menu)?;
            continue;
        }
        if trimmed.eq_ignore_ascii_case("m") {
            if let Some(item) = menu
                .items
                .iter()
                .find(|item| matches!(item.choice, Choice::SwitchEngine(_)))
            {
                return Ok(item.choice.clone());
            }
        }
        if trimmed.eq_ignore_ascii_case("s")
            && menu
                .items
                .iter()
                .any(|item| item.choice == Choice::SplitTunnel)
        {
            return Ok(Choice::SplitTunnel);
        }
        if trimmed.eq_ignore_ascii_case("d") {
            if let Some(addr) = read_dns_choice(&mut input, &mut output, configured_dns)? {
                return Ok(Choice::SetDns(addr));
            }
            print_console_menu(&mut output, &menu)?;
            continue;
        }
        if let Some(item) = trimmed
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| menu.items.get(i))
        {
            if item.choice == Choice::SelectDns {
                if let Some(addr) = read_dns_choice(&mut input, &mut output, configured_dns)? {
                    return Ok(Choice::SetDns(addr));
                }
                print_console_menu(&mut output, &menu)?;
                continue;
            }
            if item.choice == Choice::Uninstall {
                write!(
                    output,
                    "  {}",
                    tr(
                        "Confirm uninstall? This stops the service, removes files & PATH, and restores routes & proxies. [y/N]: ",
                        "Kaldırmayı onaylıyor musunuz? Servis durdurulur, dosyalar ve PATH kaldırılır, yönlendirme ve proxy ayarları geri yüklenir. [e/H]: ",
                    )
                )?;
                output.flush()?;
                answer.clear();
                if input.read_line(&mut answer)? == 0 {
                    return Ok(Choice::Cancel);
                }
                let confirm = answer.trim();
                if confirm.eq_ignore_ascii_case("y")
                    || confirm.eq_ignore_ascii_case("yes")
                    || confirm.eq_ignore_ascii_case("e")
                    || confirm.eq_ignore_ascii_case("evet")
                {
                    return Ok(Choice::Uninstall);
                }
                writeln!(
                    output,
                    "  {}",
                    tr("Uninstall canceled.", "Kaldırma iptal edildi.")
                )?;
                continue;
            }
            return Ok(item.choice.clone());
        }
        match active_lang() {
            Lang::En => writeln!(
                output,
                "  Enter a number from 1 to {count}, r to refresh, or q to quit."
            )?,
            Lang::Tr => writeln!(
                output,
                "  1 ile {count} arasında bir sayı girin, yenilemek için r, çıkmak için q yazın."
            )?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_info(
        installed_version: Option<&str>,
        current_version: &'static str,
        relation: VersionRelation,
    ) -> InstalledInfo {
        InstalledInfo {
            binary_path: PathBuf::from("/usr/local/bin/vdpi"),
            installed_version: installed_version.map(str::to_string),
            current_version,
            relation,
            running_from_installed: relation == VersionRelation::Same,
        }
    }

    fn sample_live_proxy_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: Some(1080),
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(3),
            total_connections: Some(42),
            learned_hosts: Some(7),
            isp_stage: Some("balanced".to_string()),
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            dns_addr: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: Some(14_336),
            bytes_rx: Some(1_048_576),
            bytes_tx: Some(262_144),
            tls_handshakes: Some(28),
            auto_heal_escalations: Some(1),
        }
    }

    fn sample_live_tun_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 18089,
            socks_port: None,
            version: Some("0.5.0".to_string()),
            mode: Some("combo".to_string()),
            doh: Some(true),
            block_quic: Some(true),
            active_connections: Some(5),
            total_connections: Some(120),
            learned_hosts: Some(9),
            isp_stage: Some("balanced".to_string()),
            engine: EngineMode::Tun,
            tun_interface: Some("vdpi0".to_string()),
            physical_nic: Some("Ethernet".to_string()),
            vpn_conflict: None,
            dns_addr: None,
            udp_flows_active: Some(12),
            quic_blocked: Some(42),
            dns_queries: Some(89),
            rss_kb: Some(16_384),
            bytes_rx: Some(4_194_304),
            bytes_tx: Some(524_288),
            tls_handshakes: Some(64),
            auto_heal_escalations: Some(2),
        }
    }

    fn sample_minimal_live_engine() -> LiveEngineStatus {
        LiveEngineStatus {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 8080,
            socks_port: None,
            version: Some("0.3.2".to_string()),
            mode: None,
            doh: None,
            block_quic: None,
            active_connections: None,
            total_connections: None,
            learned_hosts: None,
            isp_stage: None,
            engine: EngineMode::Proxy,
            tun_interface: None,
            physical_nic: None,
            vpn_conflict: None,
            dns_addr: None,
            udp_flows_active: None,
            quic_blocked: None,
            dns_queries: None,
            rss_kb: None,
            bytes_rx: None,
            bytes_tx: None,
            tls_handshakes: None,
            auto_heal_escalations: None,
        }
    }

    fn fresh_status() -> ControlCenterStatus {
        ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        }
    }

    #[test]
    fn build_menu_fresh_install() {
        let menu = build_menu(&fresh_status(), None);
        assert_eq!(menu.notice, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Not installed", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Offline · routes & proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(menu.items.len(), 7);
        assert_eq!(menu.items[0].choice, Choice::Run);
        assert_eq!(menu.items[0].title, "Run directly");
        assert_eq!(menu.items[1].choice, Choice::SwitchEngine(EngineMode::Tun));
        assert_eq!(menu.items[1].title, "Switch to TUN mode");
        assert_eq!(
            menu.items[1].hint,
            format!("All apps, Roblox & Discord voice via {TUN_IFACE_LABEL} (requires Admin).")
        );
        assert_eq!(menu.items[2].choice, Choice::Install);
        assert_eq!(menu.items[2].title, "Install for automatic startup");
        assert_eq!(menu.items[3].choice, Choice::SelectDns);
        assert!(menu.items[3].title.contains("Cloudflare (1.1.1.1)"));
        assert_eq!(
            menu.items[3].hint,
            "Pick a preset or enter a custom DNS / DoH server."
        );
        assert_eq!(menu.items[4].choice, Choice::SplitTunnel);
        assert_eq!(menu.items[4].title, "Split tunneling · All apps");
        assert_eq!(
            menu.items[4].hint,
            "Choose which apps use or bypass anti-DPI (with live search)."
        );
        assert_eq!(menu.items[5].choice, Choice::Doctor);
        assert_eq!(menu.items[5].title, "Run diagnostics");
        assert_eq!(menu.items[5].hint, "Tests DNS and bypass connectivity.");
        assert_eq!(menu.items[6].choice, Choice::Cancel);
        assert_eq!(menu.items[6].title, "Quit");

        let mut fresh_tun = fresh_status();
        fresh_tun.configured_engine = EngineMode::Tun;
        let tun_menu = build_menu(&fresh_tun, None);
        assert_eq!(
            tun_menu.status_rows[1],
            StatusRow::new("Engine", "TUN (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            tun_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );
        assert_eq!(tun_menu.items[1].title, "Switch to Proxy mode");
        assert_eq!(
            tun_menu.items[1].hint,
            "Browsers & apps - no Admin, lightweight, VPN-friendly."
        );
    }

    #[test]
    fn build_menu_running_proxy_mode_and_minimal_fallback() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, Some("Service resumed - anti-DPI active."));
        assert_eq!(
            menu.notice.as_deref(),
            Some("Service resumed - anti-DPI active.")
        );
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new("Service", "Running · v0.5.0", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        assert_eq!(
            menu.items
                .iter()
                .map(|i| i.choice.clone())
                .collect::<Vec<_>>(),
            vec![
                Choice::Dashboard,
                Choice::PauseService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Doctor,
                Choice::Update,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let mut proxy_with_vpn = sample_live_proxy_engine();
        proxy_with_vpn.vpn_conflict = Some("WireGuard".to_string());
        let vpn_proxy_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(proxy_with_vpn),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let vpn_proxy_menu = build_menu(&vpn_proxy_status, None);
        assert_eq!(
            vpn_proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
                .with_badge(Some(("VPN: WireGuard".to_string(), StatusTone::Warning)))
        );

        let minimal_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_minimal_live_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let minimal_menu = build_menu(&minimal_status, None);
        assert_eq!(
            minimal_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
        );
        assert_eq!(
            minimal_menu.status_rows[2],
            StatusRow::new("Anti-DPI", "Active · 127.0.0.1:8080", StatusTone::Active)
        );

        let custom_port_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let custom_menu = build_menu(&custom_port_status, None);
        assert_eq!(custom_menu.status_rows.len(), 3);
        assert_eq!(
            custom_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
        );
        assert_eq!(
            custom_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Starting or listening on custom port",
                StatusTone::Warning
            )
        );
    }

    #[test]
    fn build_menu_running_tun_mode_and_vpn_badge() {
        let tun_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let tun_menu = build_menu(&tun_status, None);
        assert_eq!(tun_menu.status_rows.len(), 3);
        assert_eq!(
            tun_menu.status_rows[0],
            StatusRow::new("Service", "Running · v0.5.0", StatusTone::Active)
        );
        assert_eq!(
            tun_menu.status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Ethernet · 16 MB",
                StatusTone::Active
            )
        );
        assert_eq!(
            tun_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        assert_eq!(tun_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(
            tun_menu.items[2],
            MenuItem::new(
                Choice::SwitchEngine(EngineMode::Proxy),
                "Switch to Proxy mode",
                "Browsers & apps - no Admin, lightweight, VPN-friendly.",
            )
        );

        // TUN without RSS reports interface + uplink cleanly.
        let mut no_rss_tun = sample_live_tun_engine();
        no_rss_tun.rss_kb = None;
        let no_rss_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(no_rss_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            build_menu(&no_rss_status, None).status_rows[1],
            StatusRow::new("Engine", "TUN · vdpi0 · Ethernet", StatusTone::Active)
        );

        // TUN + VPN conflict attaches a warning badge.
        let mut vpn_tun = sample_live_tun_engine();
        vpn_tun.vpn_conflict = Some("Mullvad".to_string());
        let vpn_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(vpn_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let vpn_menu = build_menu(&vpn_status, None);
        assert_eq!(
            vpn_menu.status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Ethernet · 16 MB",
                StatusTone::Active
            )
            .with_badge(Some(("VPN: Mullvad".to_string(), StatusTone::Warning)))
        );

        // Very long physical NIC name omits RSS so the status row stays compact.
        let mut long_nic_tun = sample_live_tun_engine();
        long_nic_tun.physical_nic = Some("Realtek PCIe GbE Family Controller".to_string());
        let long_nic_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(long_nic_tun),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            build_menu(&long_nic_status, None).status_rows[1],
            StatusRow::new(
                "Engine",
                "TUN · vdpi0 · Realtek PCIe GbE Family Controller",
                StatusTone::Active
            )
        );
    }

    #[test]
    fn build_menu_paused_same_version() {
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.5.0 (temporarily stopped)",
                StatusTone::Warning
            )
        );
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "TUN (paused)", StatusTone::Neutral)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Offline · routes & proxies restored",
                StatusTone::Neutral
            )
        );
        assert_eq!(
            menu.items
                .iter()
                .map(|i| i.choice.clone())
                .collect::<Vec<_>>(),
            vec![
                Choice::ResumeService,
                Choice::SwitchEngine(EngineMode::Proxy),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Run,
                Choice::Doctor,
                Choice::Update,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let paused_proxy = ControlCenterStatus {
            configured_engine: EngineMode::Proxy,
            ..status
        };
        let proxy_menu = build_menu(&paused_proxy, None);
        assert_eq!(
            proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (paused)", StatusTone::Neutral)
        );
        assert_eq!(
            proxy_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Tun)
        );
    }

    #[test]
    fn build_menu_newer_older_unknown_and_unregistered_binary() {
        let newer_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&newer_running, None);
        assert_eq!(menu.status_rows.len(), 3);
        assert_eq!(
            menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Running · v0.4.2 -> v0.5.0 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(
            menu.items
                .iter()
                .map(|i| i.choice.clone())
                .collect::<Vec<_>>(),
            vec![
                Choice::Install,
                Choice::Dashboard,
                Choice::PauseService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let newer_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let stopped_menu = build_menu(&newer_stopped, None);
        assert_eq!(
            stopped_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Paused · v0.4.2 -> v0.5.0 update ready",
                StatusTone::Accent
            )
        );
        assert_eq!(stopped_menu.items[1].choice, Choice::ResumeService);
        assert_eq!(
            stopped_menu.items[2].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );
        assert!(stopped_menu.items.iter().any(|i| i.choice == Choice::Run));

        let older = ControlCenterStatus {
            installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let older_menu = build_menu(&older, None);
        assert_eq!(older_menu.status_rows[0].tone, StatusTone::Warning);
        assert_eq!(
            older_menu
                .items
                .iter()
                .map(|i| i.choice.clone())
                .collect::<Vec<_>>(),
            vec![
                Choice::PauseService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Install,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let older_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let older_stopped_menu = build_menu(&older_stopped, None);
        assert_eq!(older_stopped_menu.items[0].choice, Choice::Run);

        let unknown = ControlCenterStatus {
            installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let unknown_menu = build_menu(&unknown, None);
        assert_eq!(unknown_menu.status_rows[0].tone, StatusTone::Warning);
        assert_eq!(
            unknown_menu
                .items
                .iter()
                .map(|i| i.choice.clone())
                .collect::<Vec<_>>(),
            vec![
                Choice::Install,
                Choice::ResumeService,
                Choice::SwitchEngine(EngineMode::Tun),
                Choice::SelectDns,
                Choice::SplitTunnel,
                Choice::Run,
                Choice::Uninstall,
                Choice::Cancel,
            ]
        );

        let unknown_running = ControlCenterStatus {
            installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let unknown_running_menu = build_menu(&unknown_running, None);
        assert!(!unknown_running_menu
            .items
            .iter()
            .any(|i| i.choice == Choice::Run));

        let unregistered = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let unreg_menu = build_menu(&unregistered, None);
        assert_eq!(
            unreg_menu.status_rows[0],
            StatusRow::new(
                "Service",
                "Installed v0.5.0 (service not registered)",
                StatusTone::Warning
            )
        );
        assert_eq!(
            unreg_menu.items[1].choice,
            Choice::SwitchEngine(EngineMode::Proxy)
        );
    }

    #[test]
    fn console_handles_refresh_badge_switch_engine_uninstall_confirm_and_reprompts() {
        let fresh = fresh_status();
        let mut output = Vec::new();
        assert_eq!(
            read_choice(
                &b"\nno\n0\n9\n3\n"[..],
                &mut output,
                &fresh,
                None,
                fresh_status
            )
            .unwrap(),
            Choice::Install
        );
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Run directly"));
        assert!(output.contains("Switch to TUN mode"));
        assert!(output.contains("Install for automatic startup"));
        assert!(output.contains("Split tunneling · All apps"));
        assert!(output.contains("Run diagnostics"));
        assert!(output.contains("Enter a number from 1 to 7, r to refresh, or q to quit."));
        assert!(output.contains("Choose [1 / 2 / 3 / 4 / 5 / 6 / 7 / d / s / r / g / q]: "));
        assert!(output.contains("[g: EN]"));
        assert!(output.contains(REPOSITORY_URL));
        assert!(!output.contains('\x1b'));

        // Console 's' / 'S' shortcut selects SplitTunnel directly.
        assert_eq!(
            read_choice(&b"s\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SplitTunnel
        );
        assert_eq!(
            read_choice(&b"S\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SplitTunnel
        );

        // Console 'd' shortcut opens DNS preset picker and selects AdGuard on '3'.
        let mut dns_out = Vec::new();
        assert_eq!(
            read_choice(&b"d\n3\n"[..], &mut dns_out, &fresh, None, fresh_status).unwrap(),
            Choice::SetDns("94.140.14.14".to_string())
        );
        let dns_out = String::from_utf8(dns_out).unwrap();
        assert!(dns_out.contains("AdGuard"));
        assert!(dns_out.contains("94.140.14.14"));
        assert!(dns_out.contains("Custom DNS"));
        assert!(dns_out.contains("Choose DNS [1-7 / b back]: "));

        // Console renders inline [VPN: Mullvad] badge, returns Dashboard on slot 1 and SwitchEngine on slot 3.
        let mut tun_with_vpn = sample_live_tun_engine();
        tun_with_vpn.vpn_conflict = Some("Mullvad".to_string());
        let running_tun = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(tun_with_vpn),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        assert_eq!(
            read_choice(&b"1\n"[..], Vec::new(), &running_tun, None, || {
                running_tun.clone()
            })
            .unwrap(),
            Choice::Dashboard
        );
        let mut tun_out = Vec::new();
        assert_eq!(
            read_choice(&b"3\n"[..], &mut tun_out, &running_tun, None, || {
                running_tun.clone()
            })
            .unwrap(),
            Choice::SwitchEngine(EngineMode::Proxy)
        );
        let tun_out = String::from_utf8(tun_out).unwrap();
        assert!(tun_out.contains("Engine    TUN · vdpi0 · Ethernet · 16 MB  [VPN: Mullvad]"));
        assert!(tun_out.contains("Open live dashboard"));
        assert!(tun_out.contains("Switch to Proxy mode"));

        // Shortcut 'm' also triggers SwitchEngine in console fallback.
        assert_eq!(
            read_choice(&b"m\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SwitchEngine(EngineMode::Tun)
        );

        // Refresh transitions from Running -> Stopped and allows selecting ResumeService.
        let running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let paused = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let mut refresh_out = Vec::new();
        assert_eq!(
            read_choice(&b"r\n1\n"[..], &mut refresh_out, &running, None, || {
                paused.clone()
            })
            .unwrap(),
            Choice::ResumeService
        );
        let refresh_out = String::from_utf8(refresh_out).unwrap();
        assert!(refresh_out.contains("Status refreshed."));
        assert!(refresh_out.contains("Resume background service"));

        // Uninstall requires explicit confirmation: 'n' returns to menu, 'y' confirms.
        let mut confirm_out = Vec::new();
        assert_eq!(
            read_choice(
                &b"8\nn\n8\ny\n"[..],
                &mut confirm_out,
                &running,
                None,
                || { running.clone() }
            )
            .unwrap(),
            Choice::Uninstall
        );
        let confirm_out = String::from_utf8(confirm_out).unwrap();
        assert!(confirm_out.contains("Confirm uninstall?"));
        assert!(confirm_out.contains("Uninstall canceled."));

        // EOF cancels cleanly.
        assert_eq!(
            read_choice(&b""[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::Cancel
        );
    }

    #[test]
    fn legacy_run_directly_marker_never_bypasses_control_center_and_is_migrated() {
        let dir =
            env::temp_dir().join(format!("vdpi-launcher-autorun-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let marker = dir.join("run-directly");
        fs::write(&marker, b"").unwrap();

        let fresh = fresh_status();
        let installed_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let installed_stopped = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let service_without_bin = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let bin_without_service = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };

        // Even with a pre-existing v0.5.x `run-directly` marker on disk,
        // Control Center is never bypassed.
        assert!(!should_auto_run(false, Some(&marker), &fresh));
        assert!(!should_auto_run(true, Some(&marker), &fresh));
        assert!(!should_auto_run(false, None, &fresh));
        assert!(!should_auto_run(false, Some(&marker), &installed_running));
        assert!(!should_auto_run(false, Some(&marker), &installed_stopped));
        assert!(!should_auto_run(false, Some(&marker), &service_without_bin));
        assert!(!should_auto_run(false, Some(&marker), &bin_without_service));
        assert!(marker.is_file());

        // Migration removes the stale legacy marker cleanly and is idempotent.
        migrate_legacy_preference_at(Some(&marker));
        assert!(!marker.exists());
        migrate_legacy_preference_at(Some(&marker));
        migrate_legacy_preference_at(None);

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_success_message_distinguishes_update_from_fresh_install() {
        let newer = sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer);
        let same = sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same);
        let older = sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older);
        let unknown = sample_info(None, "0.5.0", VersionRelation::Unknown);

        assert_eq!(
            install_success_message(Some(&newer)),
            "vdpi updated to v0.5.0 and restarted."
        );
        assert_eq!(
            install_success_message(None),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&same)),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&older)),
            "vdpi is installed and starts automatically."
        );
        assert_eq!(
            install_success_message(Some(&unknown)),
            "vdpi is installed and starts automatically."
        );
    }

    #[test]
    fn format_mode_label_maps_known_modes_and_preserves_unknown() {
        assert_eq!(format_mode_label("combo"), "Combo");
        assert_eq!(format_mode_label(" COMBO "), "Combo");
        assert_eq!(format_mode_label("tls-record"), "TLS Record");
        assert_eq!(format_mode_label("tlsrec"), "TLS Record");
        assert_eq!(format_mode_label("fragment"), "Fragment");
        assert_eq!(format_mode_label("chunk"), "Fragment");
        assert_eq!(format_mode_label("split"), "Split");
        assert_eq!(format_mode_label("custom-mode"), "custom-mode");
    }

    #[test]
    fn ipv6_live_engine_address_uses_brackets() {
        let mut live = sample_minimal_live_engine();
        live.addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        live.port = 8080;
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(live),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu(&status, None);
        assert_eq!(
            menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · [::1]:8080", StatusTone::Active)
        );
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new("Anti-DPI", "Active · [::1]:8080", StatusTone::Active)
        );
    }

    #[test]
    fn vpn_conflict_badge_visible_across_non_live_and_proxy_states_and_hints_mention_routes() {
        // NotInstalled with top-level status.vpn_conflict shows badge.
        let mut fresh_vpn = fresh_status();
        fresh_vpn.vpn_conflict = Some("Mullvad".to_string());
        let fresh_menu = build_menu(&fresh_vpn, None);
        assert_eq!(
            fresh_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy (selected)", StatusTone::Neutral)
                .with_badge(Some(("VPN: Mullvad".to_string(), StatusTone::Warning)))
        );

        // Paused service with top-level status.vpn_conflict shows badge and updated hints.
        let paused_vpn = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: None,
            configured_engine: EngineMode::Tun,
            vpn_conflict: Some("WireGuard".to_string()),
        };
        let paused_menu = build_menu(&paused_vpn, None);
        assert_eq!(
            paused_menu.status_rows[1],
            StatusRow::new("Engine", "TUN (paused)", StatusTone::Neutral)
                .with_badge(Some(("VPN: WireGuard".to_string(), StatusTone::Warning)))
        );
        assert!(paused_menu.items[0].hint.contains("routes & proxies"));
        let uninstall_item = paused_menu
            .items
            .iter()
            .find(|item| item.choice == Choice::Uninstall)
            .expect("uninstall item");
        assert_eq!(
            uninstall_item.hint,
            "Removes service and restores network settings."
        );
        assert!(uninstall_item.hint.chars().count() <= 60);

        // Live proxy with live.vpn_conflict = None falls back to status.vpn_conflict.
        let proxy_fallback = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: Some("ProtonVPN".to_string()),
        };
        let proxy_menu = build_menu(&proxy_fallback, None);
        assert_eq!(
            proxy_menu.status_rows[1],
            StatusRow::new("Engine", "Proxy · 127.0.0.1:8080", StatusTone::Active)
                .with_badge(Some(("VPN: ProtonVPN".to_string(), StatusTone::Warning)))
        );
        assert_eq!(proxy_menu.items[1].choice, Choice::PauseService);
        assert!(proxy_menu.items[1].hint.contains("routes & proxies"));

        // Live vpn_conflict takes precedence over top-level status.vpn_conflict.
        let mut live_override = sample_live_tun_engine();
        live_override.vpn_conflict = Some("Tailscale".to_string());
        let override_status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(live_override),
            configured_engine: EngineMode::Tun,
            vpn_conflict: Some("Mullvad".to_string()),
        };
        assert_eq!(
            build_menu(&override_status, None).status_rows[1].badge,
            Some(("VPN: Tailscale".to_string(), StatusTone::Warning))
        );
    }

    #[test]
    fn dashboard_item_present_when_live_engine_active_and_within_nine_slots() {
        let same_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let same_menu = build_menu(&same_running, None);
        assert_eq!(same_menu.items.len(), 9);
        assert_eq!(
            same_menu.items[0],
            MenuItem::new(
                Choice::Dashboard,
                "Open live dashboard",
                "Real-time throughput, connections, ISP stage & diagnostics.",
            )
        );

        let newer_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let newer_menu = build_menu(&newer_running, None);
        assert!(newer_menu.items.len() <= 9);
        assert_eq!(newer_menu.items[0].choice, Choice::Install);
        assert_eq!(newer_menu.items[1].choice, Choice::Dashboard);
        assert!(!newer_menu.items.iter().any(|i| i.choice == Choice::Run));

        let older_running = ControlCenterStatus {
            installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let older_menu = build_menu(&older_running, None);
        assert!(older_menu.items.len() <= 9);
        assert_eq!(older_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(older_menu.items[1].choice, Choice::PauseService);
        assert!(!older_menu.items.iter().any(|i| i.choice == Choice::Run));

        let unknown_running = ControlCenterStatus {
            installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let unknown_menu = build_menu(&unknown_running, None);
        assert!(unknown_menu.items.len() <= 9);
        assert_eq!(unknown_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(unknown_menu.items[1].choice, Choice::Install);
        assert!(!unknown_menu.items.iter().any(|i| i.choice == Choice::Run));

        let running_daemon_no_install = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::Running,
            live_engine: Some(sample_live_tun_engine()),
            configured_engine: EngineMode::Tun,
            vpn_conflict: None,
        };
        let daemon_menu = build_menu(&running_daemon_no_install, None);
        assert_eq!(daemon_menu.items.len(), 9);
        assert_eq!(daemon_menu.items[0].choice, Choice::Dashboard);

        let standalone_live_not_installed = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let standalone_menu = build_menu(&standalone_live_not_installed, None);
        assert_eq!(standalone_menu.items.len(), 8);
        assert_eq!(standalone_menu.items[0].choice, Choice::Dashboard);

        let stopped_with_live = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Stopped,
            live_engine: Some(sample_live_proxy_engine()),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let stopped_live_menu = build_menu(&stopped_with_live, None);
        assert_eq!(stopped_live_menu.items.len(), 9);
        assert_eq!(stopped_live_menu.items[0].choice, Choice::Dashboard);
        assert_eq!(stopped_live_menu.items[1].choice, Choice::ResumeService);
    }

    #[test]
    fn dashboard_item_absent_when_offline_or_paused() {
        let cases = [
            fresh_status(),
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Tun,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::Running,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
                service_state: ServiceState::Running,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
                service_state: ServiceState::Stopped,
                live_engine: None,
                configured_engine: EngineMode::Proxy,
                vpn_conflict: None,
            },
            ControlCenterStatus {
                installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
                service_state: ServiceState::NotInstalled,
                live_engine: None,
                configured_engine: EngineMode::Tun,
                vpn_conflict: None,
            },
        ];

        for status in &cases {
            let menu = build_menu(status, None);
            assert!(menu.items.len() <= 9);
            assert!(
                !menu
                    .items
                    .iter()
                    .any(|item| item.choice == Choice::Dashboard),
                "Choice::Dashboard should be absent when live_engine is None"
            );
        }
    }

    #[test]
    fn split_tunnel_item_present_with_summary_and_within_nine_slots_in_all_branches() {
        use vdpi_core::config::SplitTunnelMode;

        let exclude_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["discord.exe".to_string(), "steam.exe".to_string()],
        };
        let include_cfg = SplitTunnelConfig {
            mode: SplitTunnelMode::Include,
            apps: vec!["chrome.exe".to_string()],
        };

        let all_item = split_tunnel_item(&SplitTunnelConfig::default());
        assert_eq!(all_item.choice, Choice::SplitTunnel);
        assert_eq!(all_item.title, "Split tunneling · All apps");
        assert_eq!(
            all_item.hint,
            "Choose which apps use or bypass anti-DPI (with live search)."
        );

        let exclude_item = split_tunnel_item(&exclude_cfg);
        assert_eq!(exclude_item.title, "Split tunneling · Exclude (2 apps)");

        let include_item = split_tunnel_item(&include_cfg);
        assert_eq!(include_item.title, "Split tunneling · Include (1 app)");

        let states = [
            ServiceState::NotInstalled,
            ServiceState::Running,
            ServiceState::Stopped,
        ];
        let installs = [
            None,
            Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            Some(sample_info(Some("0.4.2"), "0.5.0", VersionRelation::Newer)),
            Some(sample_info(Some("0.6.0"), "0.5.0", VersionRelation::Older)),
            Some(sample_info(None, "0.5.0", VersionRelation::Unknown)),
        ];
        let lives = [None, Some(sample_live_proxy_engine())];

        for service_state in states {
            for installed in &installs {
                for live_engine in &lives {
                    let status = ControlCenterStatus {
                        installed: installed.clone(),
                        service_state,
                        live_engine: live_engine.clone(),
                        configured_engine: EngineMode::Proxy,
                        vpn_conflict: None,
                    };
                    let menu =
                        build_menu_with_options(&status, None, DNS_PRESETS[0].addr, &exclude_cfg);
                    assert!(
                        menu.items.len() <= 9,
                        "branch ({installed:?}, {service_state:?}, live={}) exceeded 9 items: {}",
                        live_engine.is_some(),
                        menu.items.len()
                    );
                    let split = menu
                        .items
                        .iter()
                        .find(|item| item.choice == Choice::SplitTunnel)
                        .expect("every menu branch must include Choice::SplitTunnel");
                    assert_eq!(split.title, "Split tunneling · Exclude (2 apps)");
                    for item in &menu.items {
                        assert!(
                            item.hint.chars().count() <= 60,
                            "hint exceeds 60-col card budget ({} chars): '{}'",
                            item.hint.chars().count(),
                            item.hint
                        );
                        assert!(
                            !item.hint.contains("DNS ring"),
                            "hint must not contain 'DNS ring' jargon: '{}'",
                            item.hint
                        );
                    }
                    if service_state == ServiceState::Running {
                        assert!(
                            !menu.items.iter().any(|item| item.choice == Choice::Run),
                            "running service branch ({installed:?}, live={}) must not offer Run directly",
                            live_engine.is_some()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn custom_dns_helpers_and_console_picker_validate_and_return_normalized() {
        assert!(!is_custom_dns("1.1.1.1"));
        assert!(!is_custom_dns(""));
        assert!(is_custom_dns("76.76.2.0"));
        assert!(is_custom_dns("https://dns.nextdns.io/abc123"));

        assert_eq!(dns_preset_index("1.1.1.1"), 0);
        assert_eq!(dns_preset_index(""), 0);
        assert_eq!(dns_preset_index("9.9.9.9"), 4);
        assert_eq!(dns_preset_index("76.76.2.0"), DNS_PRESETS.len());
        assert_eq!(
            dns_preset_index("https://dns.nextdns.io/abc123"),
            DNS_PRESETS.len()
        );

        assert_eq!(format_dns_label("1.1.1.1"), "Cloudflare (1.1.1.1)");
        assert_eq!(format_dns_label(""), "Cloudflare (1.1.1.1)");
        assert_eq!(format_dns_label("76.76.2.0"), "Custom (76.76.2.0)");
        assert_eq!(
            format_dns_label("https://dns.nextdns.io/abc123"),
            "Custom (dns.nextdns.io)"
        );
        assert_eq!(
            format_dns_label("https://user:secret@dns.nextdns.io/abc123/my-pc?token=xyz"),
            "Custom (dns.nextdns.io)"
        );

        let fresh = fresh_status();

        // Console [7] Custom DNS rejects invalid input, reprompts, and accepts valid IPv4.
        let mut ip_out = Vec::new();
        assert_eq!(
            read_choice(
                &b"d\n7\nnot-a-dns\n76.76.2.0\n"[..],
                &mut ip_out,
                &fresh,
                None,
                fresh_status
            )
            .unwrap(),
            Choice::SetDns("76.76.2.0".to_string())
        );
        let ip_out = String::from_utf8(ip_out).unwrap();
        assert!(ip_out.contains("Invalid DNS server:"));
        assert!(ip_out.contains("Custom DNS"));

        // Console [7] Custom DNS accepts valid https:// DoH URL and shows [active] when configured.
        let mut doh_out = Vec::new();
        assert_eq!(
            read_choice_with_options(
                &b"d\n7\nhttps://dns.nextdns.io/abc123\n"[..],
                &mut doh_out,
                &fresh,
                None,
                "76.76.2.0",
                &SplitTunnelConfig::default(),
                fresh_status
            )
            .unwrap(),
            Choice::SetDns("https://dns.nextdns.io/abc123".to_string())
        );
        let doh_out = String::from_utf8(doh_out).unwrap();
        assert!(doh_out.contains("76.76.2.0 [active]"));

        // Console DNS picker redacts active https:// DoH URL paths/tokens.
        let mut redacted_out = Vec::new();
        assert_eq!(
            read_choice_with_options(
                &b"d\nb\nq\n"[..],
                &mut redacted_out,
                &fresh,
                None,
                "https://dns.nextdns.io/secret-profile-id?token=topsecret",
                &SplitTunnelConfig::default(),
                fresh_status
            )
            .unwrap(),
            Choice::Cancel
        );
        let redacted_out = String::from_utf8(redacted_out).unwrap();
        assert!(redacted_out.contains("dns.nextdns.io [active]"));
        assert!(!redacted_out.contains("secret-profile-id"));
        assert!(!redacted_out.contains("topsecret"));

        // Pressing 'b' in custom DNS prompt returns to DNS list where a preset can be chosen.
        assert_eq!(
            read_choice(&b"d\n7\nb\n2\n"[..], Vec::new(), &fresh, None, fresh_status).unwrap(),
            Choice::SetDns("8.8.8.8".to_string())
        );
    }

    #[test]
    fn malformed_doh_urls_fail_closed_and_never_leak_secrets() {
        let cases = [
            ("https:///secret", "<redacted>", "Custom (<redacted>)"),
            (
                r"https://dns.nextdns.io\secret",
                "dns.nextdns.io",
                "Custom (dns.nextdns.io)",
            ),
            ("https://user:secret@", "<redacted>", "Custom (<redacted>)"),
            ("https://bad_host/secret", "<redacted>", "Custom (<redacted>)"),
            (
                "https://[2606:4700:4700::1111]/secret",
                "[2606:4700:4700::1111]",
                "Custom ([2606:4700:4700::1111])",
            ),
        ];

        let fresh = fresh_status();
        for (raw, expected_display, expected_label) in cases {
            let redacted = redact_custom_dns_display(raw);
            assert_eq!(redacted, expected_display, "raw={raw}");
            assert_eq!(shorten_custom_dns(raw, 28), expected_display, "raw={raw}");
            assert_eq!(format_dns_label(raw), expected_label, "raw={raw}");
            assert!(!redacted.contains("secret"), "leaked secret for raw={raw}");
            assert!(!redacted.contains("user"), "leaked user for raw={raw}");

            let mut out = Vec::new();
            assert_eq!(
                read_choice_with_options(
                    &b"d\nb\nq\n"[..],
                    &mut out,
                    &fresh,
                    None,
                    raw,
                    &SplitTunnelConfig::default(),
                    fresh_status
                )
                .unwrap(),
                Choice::Cancel
            );
            let out = String::from_utf8(out).unwrap();
            assert!(
                out.contains(&format!("{expected_display} [active]")),
                "missing expected display '{expected_display}' for raw={raw}:\n{out}"
            );
            assert!(!out.contains("secret"), "console picker leaked secret for raw={raw}:\n{out}");
            assert!(!out.contains("user"), "console picker leaked user for raw={raw}:\n{out}");
        }
    }

    #[test]
    fn anti_dpi_row_uses_effective_doh_for_custom_doh_urls() {
        let mut live = sample_live_proxy_engine();
        live.doh = Some(false);
        live.dns_addr = Some("https://dns.nextdns.io/abc123".to_string());
        let status = ControlCenterStatus {
            installed: Some(sample_info(Some("0.5.0"), "0.5.0", VersionRelation::Same)),
            service_state: ServiceState::Running,
            live_engine: Some(live),
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let menu = build_menu_with_dns(&status, None, "1.1.1.1");
        assert_eq!(
            menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );

        // When live telemetry omits dns_addr, fall back to configured_dns.
        let mut live_no_dns = sample_live_proxy_engine();
        live_no_dns.doh = Some(false);
        live_no_dns.dns_addr = None;
        let fallback_status = ControlCenterStatus {
            live_engine: Some(live_no_dns),
            ..status.clone()
        };
        let fallback_doh_menu =
            build_menu_with_dns(&fallback_status, None, "https://dns.nextdns.io/abc123");
        assert_eq!(
            fallback_doh_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        let fallback_udp_menu = build_menu_with_dns(&fallback_status, None, "1.1.1.1");
        assert_eq!(
            fallback_udp_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH off · QUIC blocked",
                StatusTone::Active
            )
        );

        // Live plain IP takes precedence over a configured https:// URL.
        let mut live_ip = sample_live_proxy_engine();
        live_ip.doh = Some(false);
        live_ip.dns_addr = Some("1.1.1.1".to_string());
        let live_ip_status = ControlCenterStatus {
            live_engine: Some(live_ip),
            ..status.clone()
        };
        let live_ip_menu =
            build_menu_with_dns(&live_ip_status, None, "https://dns.nextdns.io/abc123");
        assert_eq!(
            live_ip_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH off · QUIC blocked",
                StatusTone::Active
            )
        );

        // Bare custom non-DoH IPs (e.g. ControlD bare IP or LAN resolver) report DoH off even when live.doh=true.
        for custom_ip in ["76.76.2.0", "10.0.0.53"] {
            let mut live_custom = sample_live_proxy_engine();
            live_custom.doh = Some(true);
            live_custom.dns_addr = Some(custom_ip.to_string());
            let custom_status = ControlCenterStatus {
                live_engine: Some(live_custom),
                ..status.clone()
            };
            let custom_menu = build_menu_with_dns(&custom_status, None, "1.1.1.1");
            assert_eq!(
                custom_menu.status_rows[2],
                StatusRow::new(
                    "Anti-DPI",
                    "Active · Combo · DoH off · QUIC blocked",
                    StatusTone::Active
                )
            );
        }

        // Configured bare non-DoH IP fallback when live telemetry omits dns_addr also reports DoH off.
        let mut live_fallback_custom = sample_live_proxy_engine();
        live_fallback_custom.doh = Some(true);
        live_fallback_custom.dns_addr = None;
        let fallback_custom_status = ControlCenterStatus {
            live_engine: Some(live_fallback_custom),
            ..status.clone()
        };
        let fallback_custom_menu = build_menu_with_dns(&fallback_custom_status, None, "76.76.2.0");
        assert_eq!(
            fallback_custom_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH off · QUIC blocked",
                StatusTone::Active
            )
        );

        // Known public DoH IP reports DoH on when enabled and DoH off when disabled.
        let mut live_quad9 = sample_live_proxy_engine();
        live_quad9.doh = Some(true);
        live_quad9.dns_addr = Some("9.9.9.9".to_string());
        let quad9_on_menu = build_menu_with_dns(
            &ControlCenterStatus {
                live_engine: Some(live_quad9.clone()),
                ..status.clone()
            },
            None,
            "1.1.1.1",
        );
        assert_eq!(
            quad9_on_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH on · QUIC blocked",
                StatusTone::Active
            )
        );
        live_quad9.doh = Some(false);
        let quad9_off_menu = build_menu_with_dns(
            &ControlCenterStatus {
                live_engine: Some(live_quad9),
                ..status
            },
            None,
            "1.1.1.1",
        );
        assert_eq!(
            quad9_off_menu.status_rows[2],
            StatusRow::new(
                "Anti-DPI",
                "Active · Combo · DoH off · QUIC blocked",
                StatusTone::Active
            )
        );
    }

    #[test]
    fn write_pause_prompt_formats_single_multiline_and_empty_messages() {
        let mut out = Vec::new();
        write_pause_prompt(&b"\n"[..], &mut out, "Fatal: port 8080 in use").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "\n  Fatal: port 8080 in use\n  Press Enter to close this window.\n"
        );

        let mut multi_out = Vec::new();
        write_pause_prompt(&b"\n"[..], &mut multi_out, "Line 1\nLine 2").unwrap();
        assert_eq!(
            String::from_utf8(multi_out).unwrap(),
            "\n  Line 1\n  Line 2\n  Press Enter to close this window.\n"
        );

        let mut empty_out = Vec::new();
        write_pause_prompt(&b"\n"[..], &mut empty_out, "   ").unwrap();
        assert_eq!(
            String::from_utf8(empty_out).unwrap(),
            "\n  Press Enter to close this window.\n"
        );
    }

    #[test]
    fn builds_turkish_menu_status_rows_and_dns_labels() {
        let _guard = i18n::push_thread_lang(Some(Lang::Tr));
        let status = ControlCenterStatus {
            installed: None,
            service_state: ServiceState::NotInstalled,
            live_engine: None,
            configured_engine: EngineMode::Proxy,
            vpn_conflict: None,
        };
        let split = SplitTunnelConfig {
            mode: SplitTunnelMode::Exclude,
            apps: vec!["discord.exe".to_string()],
        };
        let menu = build_menu_with_options(&status, None, "https://dns.nextdns.io/abc123", &split);
        assert_eq!(menu.status_rows[0].label, "Servis");
        assert_eq!(menu.status_rows[0].value, "Kurulu değil");
        assert_eq!(menu.status_rows[1].label, "Motor");
        assert_eq!(menu.status_rows[1].value, "Proxy (seçili)");
        assert_eq!(menu.status_rows[2].label, "Anti-DPI");
        assert!(menu.status_rows[2].value.contains("Çevrimdışı"));
        assert_eq!(menu.items[0].title, "Doğrudan çalıştır");
        assert_eq!(menu.items[1].title, "TUN moduna geç");
        assert_eq!(menu.items[2].title, "Otomatik başlatma için kur");
        assert!(menu.items[3].title.contains("DNS sunucusu seç · Özel (dns.nextdns.io)"));
        assert_eq!(
            menu.items[4].title,
            "Bölünmüş tünel · Hariç tut (1 uygulama)"
        );
        assert_eq!(menu.items[5].title, "Tanılama çalıştır");
        assert_eq!(menu.items[5].hint, "DNS ve atlatma bağlantısını test eder.");
        assert_eq!(menu.items[6].title, "Çıkış");
        assert!(dns_preset_hint(&DNS_PRESETS[0]).contains("varsayılan"));
        assert_eq!(
            localize_custom_dns_error("DNS server cannot be empty"),
            "DNS sunucusu boş olamaz"
        );
        assert_eq!(
            localize_custom_dns_error("DoH URL must use https:// (http:// is not supported)"),
            "DoH adresi https:// kullanmalıdır (http:// desteklenmez)"
        );
    }

    #[test]
    fn persist_language_to_config_at_preserves_existing_keys() {
        let dir = env::temp_dir().join(format!("vdpi-launcher-lang-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("config.toml");
        let seed = vdpi::config_file::FileConfig {
            schema_version: Some(1),
            engine: Some(EngineMode::Tun),
            ..Default::default()
        };
        vdpi::config_file::save_file_config_atomic(&path, &seed).expect("seed config");

        persist_language_to_config_at(&path, Lang::Tr).expect("persist tr");
        let (_, loaded) =
            vdpi::config_file::load_file_config(Some(&path), false).expect("reload config");
        assert_eq!(loaded.engine, Some(EngineMode::Tun));
        assert_eq!(loaded.language.as_deref(), Some("tr"));

        persist_language_to_config_at(&path, Lang::En).expect("persist en");
        let (_, loaded_en) =
            vdpi::config_file::load_file_config(Some(&path), false).expect("reload config");
        assert_eq!(loaded_en.language.as_deref(), Some("en"));

        let _ = fs::remove_dir_all(&dir);
    }
}
