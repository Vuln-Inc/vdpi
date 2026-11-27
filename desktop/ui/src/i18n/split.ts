import type { SplitTunnelPreset } from "../types";
import { createTranslator, type ResolvedLanguage } from "./context";

const en = {
  title: "Split Tunneling",
    modeAllLabel: "Protect All Apps",
    modeAllDesc: "Protect every application with vdpi.",
    modeExcludeLabel: "Exclude Selected",
    modeExcludeDesc:
      "Selected apps connect directly (skip vdpi); protect everything else with vdpi.",
    modeIncludeLabel: "Include Only",
    modeIncludeDesc:
      "Protect only selected apps with vdpi; all other apps connect directly (skip vdpi).",
    subtitleAll:
      "All applications are protected with vdpi. Pick a preset or toggle any app to connect directly (skip vdpi).",
    subtitleExcludeEmpty:
      "All applications are protected with vdpi. Select apps below to connect directly (skip vdpi).",
    subtitleExcludeOne:
      "{count} app will connect directly (skip vdpi); all other apps are protected with vdpi.",
    subtitleExcludeMany:
      "{count} apps will connect directly (skip vdpi); all other apps are protected with vdpi.",
    subtitleIncludeEmpty:
      "Only selected applications will be protected with vdpi.",
    subtitleIncludeOne:
      "Only {count} selected app will be protected with vdpi; everything else connects directly.",
    subtitleIncludeMany:
      "Only {count} selected apps will be protected with vdpi; everything else connects directly.",
    proxyBannerTitle:
      "Per-app split tunneling requires Full-PC (TUN) mode",
    proxyBannerDesc:
      "You are currently in Proxy mode. You can still edit your app list here, and rules will apply once you switch to Full-PC (TUN) mode.",
    proxyBannerSwitching: "Switching...",
    proxyBannerSwitch: "Switch to Full-PC (TUN)",
    notInstalledBannerTitle: "Service not installed yet",
    notInstalledBannerDesc:
      "Your split tunneling rules save to config.toml now and take effect once vdpi is installed.",
    notInstalledBannerAction: "Open Installation",
    errorBannerTitle: "Split tunneling error",
    retry: "Retry",
    loadFailed: "Failed to load split tunneling configuration.",
    saveFailed: "Failed to save split tunneling settings.",
    saveCancelled: "Save cancelled.",
    saveEmptyIncludeRestart:
      "Saved Include Only with 0 apps selected - no apps will be protected (restart service to apply).",
    saveEmptyInclude:
      "Saved Include Only with 0 apps selected - no apps will be protected until you add at least one.",
    saveSuccessRestart:
      "Split tunnel settings saved (restart service to apply).",
    saveSuccess: "Split tunnel settings saved and applied.",
    sectionRoutingMode: "Routing Mode",
    ariaModeGroup: "Split tunneling mode",
    emptyIncludeTitle:
      "0 apps selected - no apps will be protected until you add at least one",
    emptyIncludeDesc:
      "Choose a quick preset below, toggle apps from the list, or add a custom app to protect with vdpi.",
    sectionQuickPresets: "Quick Presets",
    presetsAutoSwitchHint:
      "Clicking a preset switches to Exclude Selected automatically",
    sectionApplications: "Applications",
    ariaSearchApps: "Search applications",
    searchPlaceholderWin:
      "Search apps or executables (e.g. Discord, chrome.exe)...",
    searchPlaceholderUnix:
      "Search apps or executables (e.g. Discord, firefox)...",
    ariaClearSearch: "Clear search",
    clear: "Clear",
    addCustomApp: "Add custom app",
    refreshTitle: "Refresh running apps",
    refreshing: "Refreshing...",
    refresh: "Refresh",
    refreshedToast: "Refreshed running apps ({count} running)",
    customAppFallbackName: "Custom App",
    ariaCustomAppInput: "Add custom app executable or shortcut command",
    customPlaceholderWin: "Add custom app (e.g. valorant.exe)",
    customPlaceholderUnix: "Add custom app (e.g. firefox)",
    add: "Add",
    browsing: "Browsing...",
    browse: "Browse...",
    pickerError: "Could not open executable file picker.",
    customErrorShortcut:
      "Windows shortcut (.lnk) files are not supported directly - select the target .exe file or enter its executable name (e.g. valorant.exe).",
    customErrorInvalidWin:
      "Enter a valid executable name or path (e.g. valorant.exe).",
    customErrorInvalidUnix:
      "Enter a valid executable name or path (e.g. firefox).",
    maxAppsLimit:
      "Maximum {max} apps allowed - remove one before adding another.",
    maxAppsLimitPreset:
      "Maximum {max} apps allowed - remove an app before adding {label}.",
    maxAppsPartialPreset:
      "Maximum {max} apps reached - added {added} of {total} apps from {label}.",
    maxAppsSaveLimit:
      "Maximum {max} apps allowed - remove {excess} before saving.",
    toastSwitchExcludeUpdated:
      "Switched to Exclude Selected and updated {name}",
    toastSwitchExcludeSkip:
      "Switched to Exclude Selected - {name} will connect directly (skip vdpi)",
    toastSwitchExcludePresetRemoved:
      "Switched to Exclude Selected and removed {label} from exclusions",
    toastSwitchExcludeAlready:
      "Switched to Exclude Selected ({exe} is already selected)",
    toastAlreadySelected: "{exe} is already in your selection",
    toastAddedCustom: "Added {exe}",
    ariaFilterApps: "Filter applications",
    filterAll: "All",
    filterSelected: "Selected ({count})",
    filterRunning: "Running ({count})",
    filterGames: "Games",
    filterBrowsers: "Browsers",
    filterCommunication: "Communication",
    filterMedia: "Media",
    clearSelected: "Clear selected",
    showingAppsOne: "Showing {visible} of {total} app",
    showingAppsMany: "Showing {visible} of {total} apps",
    metaToggleSwitchHint: "Toggle any app to switch to Exclude Selected",
    metaSelectedOfMax: "{count} / {max} selected",
    metaSelected: "{count} selected",
    loadingApps: "Loading applications...",
    emptySearchTitle: 'No apps matching "{query}"',
    emptySelectedTitle: "No apps selected yet",
    emptyRunningTitle: "No running apps detected",
    emptyCategoryTitle: "No apps found in this category",
    emptySearchDesc:
      "Try a different search term or use Add custom app above.",
    emptySelectedDesc: "Use a quick preset or toggle apps from the All list.",
    emptyDefaultDesc: "Click Refresh or switch back to All.",
    emptyClearSearch: "Clear search",
    emptyShowAll: "Show all apps",
    ariaAppList: "Split tunneling applications",
    unsavedTitle: "Unsaved Changes",
    diffMode: "Mode: {mode}",
    diffAdded: "+{count} added",
    diffRemoved: "-{count} removed",
    diffEmptyInclude: "0 apps selected - nothing protected",
    discard: "Discard",
    saving: "Saving...",
    saveApply: "Save & Apply",
    saveConfig: "Save to Config",
    ariaPresetsGroup: "App presets",
    presetTooltipSelected: "{matched}/{total} selected",
    presetTooltipAppOne: "{total} app",
    presetTooltipAppMany: "{total} apps",
    presetDiscordLabel: "Discord",
    presetDiscordDesc:
      "Discord stable, PTB, and Canary voice/chat clients",
    presetRobloxLabel: "Roblox",
    presetRobloxDesc: "Roblox Player, launcher, and Bloxstrap",
    presetValorantLabel: "Valorant & Riot",
    presetValorantDesc:
      "Valorant, Riot Client, Vanguard, and League of Legends",
    presetSteamLabel: "Steam",
    presetSteamDesc: "Steam client, web helper, and in-game overlay",
    presetBrowsersLabel: "Web Browsers",
    presetBrowsersDesc: "Chrome, Edge, Firefox, Brave, Opera, and Vivaldi",
    presetObsLabel: "OBS Studio",
    presetObsDesc:
      "OBS Studio 64-bit and 32-bit streaming and recording",
    switchExclude: "Exclude {name} ({exe})",
    switchInclude: "Include {name} ({exe})",
    switchAll: "{name} ({exe}) - switches to Exclude Selected",
    badgeRunning: "Running",
    companionBadgeOne: "+{count} companion",
    companionBadgeMany: "+{count} companions",
    companionAriaHideOne:
      "Hide {count} companion process matched with {name}",
    companionAriaHideMany:
      "Hide {count} companion processes matched with {name}",
    companionAriaShowOne:
      "Show {count} companion process matched with {name}",
    companionAriaShowMany:
      "Show {count} companion processes matched with {name}",
    companionRegionAria: "{name} companion processes",
    companionNote: "Matched together with {name}:",
};

export type SplitStringKey = keyof typeof en;

const tr: Record<SplitStringKey, string> = {
    title: "Bölünmüş Tünel",
    modeAllLabel: "Tüm Uygulamaları Koru",
    modeAllDesc: "Tüm uygulamaları vdpi ile koru.",
    modeExcludeLabel: "Seçilenleri Hariç Tut",
    modeExcludeDesc:
      "Seçilen uygulamalar doğrudan bağlanır (vdpi atlanır); diğerleri vdpi ile korunur.",
    modeIncludeLabel: "Yalnızca Seçilenler",
    modeIncludeDesc:
      "Yalnızca seçilen uygulamalar vdpi ile korunur; diğerleri doğrudan bağlanır.",
    subtitleAll:
      "Tüm uygulamalar vdpi ile korunuyor. Doğrudan bağlanacak uygulamaları seçmek için bir hazır ayar veya uygulama açın.",
    subtitleExcludeEmpty:
      "Tüm uygulamalar vdpi ile korunuyor. Doğrudan bağlanacak (vdpi atlanacak) uygulamaları aşağıdan seçin.",
    subtitleExcludeOne:
      "{count} uygulama doğrudan bağlanacak (vdpi atlanacak); diğer tüm uygulamalar vdpi ile korunacak.",
    subtitleExcludeMany:
      "{count} uygulama doğrudan bağlanacak (vdpi atlanacak); diğer tüm uygulamalar vdpi ile korunacak.",
    subtitleIncludeEmpty:
      "Yalnızca seçilen uygulamalar vdpi ile korunacak.",
    subtitleIncludeOne:
      "Yalnızca seçilen {count} uygulama vdpi ile korunacak; diğerleri doğrudan bağlanacak.",
    subtitleIncludeMany:
      "Yalnızca seçilen {count} uygulama vdpi ile korunacak; diğerleri doğrudan bağlanacak.",
    proxyBannerTitle:
      "Uygulama bazlı bölünmüş tünel için Tam PC (TUN) modu gerekir",
    proxyBannerDesc:
      "Şu anda Proxy modundasınız. Uygulama listenizi buradan düzenleyebilirsiniz; kurallar Tam PC (TUN) moduna geçtiğinizde uygulanır.",
    proxyBannerSwitching: "Geçiliyor...",
    proxyBannerSwitch: "Tam PC (TUN) Moduna Geç",
    notInstalledBannerTitle: "Servis henüz kurulmadı",
    notInstalledBannerDesc:
      "Bölünmüş tünel kurallarınız şimdi config.toml dosyasına kaydedilir ve vdpi kurulduğunda etkinleşir.",
    notInstalledBannerAction: "Kuruluma Git",
    errorBannerTitle: "Bölünmüş tünel hatası",
    retry: "Tekrar Dene",
    loadFailed: "Bölünmüş tünel yapılandırması yüklenemedi.",
    saveFailed: "Bölünmüş tünel ayarları kaydedilemedi.",
    saveCancelled: "Kaydetme iptal edildi.",
    saveEmptyIncludeRestart:
      "Yalnızca Seçilenler modu 0 uygulama ile kaydedildi - hiçbir uygulama korunmayacak (uygulamak için hizmeti yeniden başlatın).",
    saveEmptyInclude:
      "Yalnızca Seçilenler modu 0 uygulama ile kaydedildi - en az bir uygulama ekleyene kadar hiçbir uygulama korunmayacak.",
    saveSuccessRestart:
      "Bölünmüş tünel ayarları kaydedildi (uygulamak için hizmeti yeniden başlatın).",
    saveSuccess: "Bölünmüş tünel ayarları kaydedildi ve uygulandı.",
    sectionRoutingMode: "Yönlendirme Modu",
    ariaModeGroup: "Bölünmüş tünel modu",
    emptyIncludeTitle:
      "0 uygulama seçili - en az bir uygulama ekleyene kadar hiçbir uygulama korunmaz",
    emptyIncludeDesc:
      "Aşağıdan bir hazır ayar seçin, listeden uygulama açın veya vdpi ile korumak için özel uygulama ekleyin.",
    sectionQuickPresets: "Hızlı Ayarlar",
    presetsAutoSwitchHint:
      "Bir hazır ayara tıklamak otomatik olarak Seçilenleri Hariç Tut moduna geçer",
    sectionApplications: "Uygulamalar",
    ariaSearchApps: "Uygulamalarda ara",
    searchPlaceholderWin:
      "Uygulama veya dosya adı ara (örn. Discord, chrome.exe)...",
    searchPlaceholderUnix:
      "Uygulama veya dosya adı ara (örn. Discord, firefox)...",
    ariaClearSearch: "Aramayı temizle",
    clear: "Temizle",
    addCustomApp: "Özel uygulama ekle",
    refreshTitle: "Çalışan uygulamaları yenile",
    refreshing: "Yenileniyor...",
    refresh: "Yenile",
    refreshedToast: "Çalışan uygulamalar yenilendi ({count} çalışıyor)",
    customAppFallbackName: "Özel Uygulama",
    ariaCustomAppInput: "Özel uygulama dosyası veya kısayol komutu ekle",
    customPlaceholderWin: "Özel uygulama ekle (örn. valorant.exe)",
    customPlaceholderUnix: "Özel uygulama ekle (örn. firefox)",
    add: "Ekle",
    browsing: "Seçiliyor...",
    browse: "Gözat...",
    pickerError: "Uygulama dosya seçicisi açılamadı.",
    customErrorShortcut:
      "Windows kısayol (.lnk) dosyaları doğrudan desteklenmez - hedef .exe dosyasını seçin veya dosya adını yazın (örn. valorant.exe).",
    customErrorInvalidWin:
      "Geçerli bir uygulama adı veya yolu girin (örn. valorant.exe).",
    customErrorInvalidUnix:
      "Geçerli bir uygulama adı veya yolu girin (örn. firefox).",
    maxAppsLimit:
      "En fazla {max} uygulamaya izin verilir - yeni eklemeden önce birini kaldırın.",
    maxAppsLimitPreset:
      "En fazla {max} uygulamaya izin verilir - {label} eklemeden önce bir uygulamayı kaldırın.",
    maxAppsPartialPreset:
      "En fazla {max} uygulama sınırına ulaşıldı - {label} içinden {added}/{total} uygulama eklendi.",
    maxAppsSaveLimit:
      "En fazla {max} uygulamaya izin verilir - kaydetmeden önce {excess} uygulama kaldırın.",
    toastSwitchExcludeUpdated:
      "Seçilenleri Hariç Tut moduna geçildi ve {name} güncellendi",
    toastSwitchExcludeSkip:
      "Seçilenleri Hariç Tut moduna geçildi - {name} doğrudan bağlanacak (vdpi atlanacak)",
    toastSwitchExcludePresetRemoved:
      "Seçilenleri Hariç Tut moduna geçildi ve {label} hariç tutulanlardan kaldırıldı",
    toastSwitchExcludeAlready:
      "Seçilenleri Hariç Tut moduna geçildi ({exe} zaten seçili)",
    toastAlreadySelected: "{exe} zaten seçiminizde",
    toastAddedCustom: "{exe} eklendi",
    ariaFilterApps: "Uygulamaları filtrele",
    filterAll: "Tümü",
    filterSelected: "Seçili ({count})",
    filterRunning: "Çalışan ({count})",
    filterGames: "Oyunlar",
    filterBrowsers: "Tarayıcılar",
    filterCommunication: "İletişim",
    filterMedia: "Medya",
    clearSelected: "Seçimi temizle",
    showingAppsOne: "{total} uygulamadan {visible} gösteriliyor",
    showingAppsMany: "{total} uygulamadan {visible} gösteriliyor",
    metaToggleSwitchHint:
      "Seçilenleri Hariç Tut moduna geçmek için bir uygulama açın",
    metaSelectedOfMax: "{count} / {max} seçili",
    metaSelected: "{count} seçili",
    loadingApps: "Uygulamalar yükleniyor...",
    emptySearchTitle: '"{query}" ile eşleşen uygulama yok',
    emptySelectedTitle: "Henüz uygulama seçilmedi",
    emptyRunningTitle: "Çalışan uygulama algılanmadı",
    emptyCategoryTitle: "Bu kategoride uygulama bulunamadı",
    emptySearchDesc:
      "Farklı bir arama terimi deneyin veya yukarıdan Özel uygulama ekle seçeneğini kullanın.",
    emptySelectedDesc: "Hızlı ayar kullanın veya Tümü listesinden uygulama seçin.",
    emptyDefaultDesc: "Yenile'ye tıklayın veya Tümü sekmesine dönün.",
    emptyClearSearch: "Aramayı temizle",
    emptyShowAll: "Tüm uygulamaları göster",
    ariaAppList: "Bölünmüş tünel uygulamaları",
    unsavedTitle: "Kaydedilmemiş Değişiklikler",
    diffMode: "Mod: {mode}",
    diffAdded: "+{count} eklendi",
    diffRemoved: "-{count} kaldırıldı",
    diffEmptyInclude: "0 uygulama seçili - koruma yok",
    discard: "Vazgeç",
    saving: "Kaydediliyor...",
    saveApply: "Kaydet ve Uygula",
    saveConfig: "Yapılandırmaya Kaydet",
    ariaPresetsGroup: "Uygulama hazır ayarları",
    presetTooltipSelected: "{matched}/{total} seçili",
    presetTooltipAppOne: "{total} uygulama",
    presetTooltipAppMany: "{total} uygulama",
    presetDiscordLabel: "Discord",
    presetDiscordDesc:
      "Discord kararlı, PTB ve Canary ses/sohbet istemcileri",
    presetRobloxLabel: "Roblox",
    presetRobloxDesc: "Roblox Player, başlatıcı ve Bloxstrap",
    presetValorantLabel: "Valorant & Riot",
    presetValorantDesc:
      "Valorant, Riot Client, Vanguard ve League of Legends",
    presetSteamLabel: "Steam",
    presetSteamDesc: "Steam istemcisi, web yardımcısı ve oyun içi arayüz",
    presetBrowsersLabel: "Web Tarayıcıları",
    presetBrowsersDesc: "Chrome, Edge, Firefox, Brave, Opera ve Vivaldi",
    presetObsLabel: "OBS Studio",
    presetObsDesc: "OBS Studio 64-bit ve 32-bit yayın ve kayıt",
    switchExclude: "{name} ({exe}) hariç tut",
    switchInclude: "{name} ({exe}) dahil et",
    switchAll: "{name} ({exe}) - Seçilenleri Hariç Tut moduna geçer",
    badgeRunning: "Çalışıyor",
    companionBadgeOne: "+{count} yardımcı",
    companionBadgeMany: "+{count} yardımcı",
    companionAriaHideOne:
      "{name} ile eşleşen {count} yardımcı işlemi gizle",
    companionAriaHideMany:
      "{name} ile eşleşen {count} yardımcı işlemi gizle",
    companionAriaShowOne:
      "{name} ile eşleşen {count} yardımcı işlemi göster",
    companionAriaShowMany:
      "{name} ile eşleşen {count} yardımcı işlemi göster",
    companionRegionAria: "{name} yardımcı işlemleri",
    companionNote: "{name} ile birlikte eşleşir:",
};

export const SPLIT_STRINGS: {
  en: Record<SplitStringKey, string>;
  tr: Record<SplitStringKey, string>;
} = { en, tr };

export const tSplit = createTranslator(SPLIT_STRINGS);

const PRESET_KEY_MAP: Record<
  string,
  { label: SplitStringKey; desc: SplitStringKey }
> = {
  discord: { label: "presetDiscordLabel", desc: "presetDiscordDesc" },
  roblox: { label: "presetRobloxLabel", desc: "presetRobloxDesc" },
  "valorant-riot": { label: "presetValorantLabel", desc: "presetValorantDesc" },
  steam: { label: "presetSteamLabel", desc: "presetSteamDesc" },
  "web-browsers": { label: "presetBrowsersLabel", desc: "presetBrowsersDesc" },
  "obs-studio": { label: "presetObsLabel", desc: "presetObsDesc" },
};

export function localizePresetLabel(
  lang: ResolvedLanguage,
  preset: SplitTunnelPreset,
): string {
  if (lang === "en") return preset.label;
  const mapping = PRESET_KEY_MAP[preset.id];
  return mapping ? tSplit(lang, mapping.label) : preset.label;
}

export function localizePresetDescription(
  lang: ResolvedLanguage,
  preset: SplitTunnelPreset,
): string {
  if (lang === "en") return preset.description;
  const mapping = PRESET_KEY_MAP[preset.id];
  return mapping ? tSplit(lang, mapping.desc) : preset.description;
}
