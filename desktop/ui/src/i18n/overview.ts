import { createTranslator, type ResolvedLanguage } from "./context";

const en = {
  // Engine
  engineLabel: "Engine",
  engineTun: "TUN",
  engineProxy: "Proxy",
  engineDescTun:
    "Full-PC virtual adapter covering all apps, games, Discord voice (UDP), and DNS without proxy setup.",
  engineDescProxy:
    "Local HTTP/SOCKS5 proxy on 127.0.0.1 for web browsers and proxy-aware TCP apps (does not cover Discord voice or most games).",
  engineSwitchingTo: "Switching engine to {engine}...",
  engineSwitching: "Switching engine...",

  // Headlines
  headlineChecking: "Checking status...",
  headlineNotInstalled: "Service Not Installed",
  headlineYielded: "Yielded to VPN",
  headlineStarting: "Starting...",
  headlineProtected: "Protected",
  headlinePaused: "Paused",

  // Subtitles
  subtitleReadingStatus: "Reading service status...",
  subtitleServiceRequired: "Background service required",
  subtitleAdminPrompt: "Admin prompt may appear",
  subtitleActiveTunnel: "Active tunnel: {vpn}",
  subtitleAutoResumes: "Auto-resumes on VPN disconnect",
  subtitleTunAdapter: "TUN adapter",
  subtitleLocalProxy: "Local proxy",
  subtitleWaitingTelemetry: "Waiting for live telemetry...",
  subtitleVia: "{iface} via {nic}",
  subtitleProtectionPaused: "Protection paused",
  subtitleServiceStopped: "Service stopped",

  // Primary button
  btnSettingUp: "Setting up...",
  btnConnecting: "Connecting...",
  btnPausing: "Pausing...",
  btnUpdating: "Updating...",
  btnChecking: "Checking...",
  btnSetUpAndConnect: "Set Up & Connect",
  btnPause: "Pause",
  btnConnect: "Connect",

  // VPN conflict banner
  vpnYieldedTitle: "Yielded to active VPN",
  vpnDetectedTitle: "Full-tunnel VPN detected",
  vpnYieldedDesc:
    "Active full-tunnel interface ({vpn}) detected. Protection paused automatically to prevent routing conflicts and will resume once the VPN disconnects.",
  vpnWarnDesc:
    "Active full-tunnel interface ({vpn}) detected while coexistence is set to warn. Traffic may bypass or conflict with the VPN tunnel.",
  vpnRunningDesc:
    "Active full-tunnel interface ({vpn}) detected while protection is running. Traffic may bypass or conflict with the VPN tunnel.",
  vpnIdleDesc:
    "Active full-tunnel interface ({vpn}) detected. Protection will yield automatically if connected while this VPN is active.",
  vpnAction: "VPN Coexistence",

  // Wintun banner
  wintunInvalidTitle: "Full-PC driver invalid (wintun.dll)",
  wintunMissingTitle: "Full-PC driver missing (wintun.dll)",
  wintunDetailWithNote:
    "{detail}. Proxy mode only covers web browsers (not Discord voice or games).",
  wintunDefaultDesc:
    "Place wintun.dll in the app folder for full-PC TUN protection. Proxy mode only covers web browsers (not Discord voice or games).",
  wintunStillInvalid:
    "wintun.dll is still invalid (hash verification failed). Replace it with an official copy and re-check.",
  wintunStillMissing: "wintun.dll is still missing from the app folder.",
  wintunDetectedReady: "wintun.dll detected. Full-PC (TUN) mode is ready.",
  wintunRecheckError: "Could not re-check wintun.dll status.",
  btnOpenAppFolder: "Open App Folder",
  btnRecheck: "Re-check",
  btnSwitchToProxy: "Switch to Proxy",

  // One-time setup banner
  setupRequiredTitle: "One-time setup required",
  setupRequiredDesc:
    "Click Set Up & Connect above to install the background service and start protection. An administrator prompt may appear to approve the setup.",
  btnOpenSettings: "Open Settings",

  // Telemetry metrics
  metricsAria: "Live telemetry",
  metricSessionTransfer: "Session Transfer",
  metricTotal: "Total {value}",
  metricDns: "DNS",
  dnsSystemDefault: "System default",
  metricQueries: "{count} queries",
  metricConnections: "Connections",
  connAdaptive: "Adaptive: {stage}",
  connMode: "Mode: {mode}",
  connAdaptiveReady: "Adaptive ready",
  connIdle: "Idle",
  metricProtection: "Protection",
  metricQuicBlocked: "{count} QUIC blocked",
  splitAll: "Split: All apps",
  splitExcludeOne: "Split: 1 excluded",
  splitExcludeMany: "Split: {count} excluded",
  splitIncludeOne: "Split: 1 included",
  splitIncludeMany: "Split: {count} included",

  // Chart card
  chartAria: "Throughput history",
  chartTitle: "Throughput",
  chartCaption: "60s window",
  chartPausedSetup: "Setup required",
  chartPausedDefault: "Protection paused",

  // Activity card
  activityAria: "Recent activity",
  activityTitle: "Activity",
  btnCopy: "Copy",
  btnCopied: "Copied",
  btnClear: "Clear",
  activityEmpty: "No activity recorded in this session.",
  catEngine: "Engine",
  catDns: "DNS",
  catVpn: "VPN",
  catSplit: "Split",
  catSystem: "System",

  // Adaptive stages
  stageCombo: "Combo",
  stageOobSni: "OOB SNI",
  stageMultiOob: "Multi + OOB",
  stageFineFragment: "Fine Fragment",
  stageDeepStorm: "Deep Storm",
  stageSlowSni: "Slow SNI",
  stagePassthrough: "Passthrough",

  // Engine switch dialog
  confirmProxyTitle: "Switch engine to Proxy?",
  confirmTunTitle: "Switch engine to TUN?",
  confirmProxyDesc:
    "Switching engines restarts protection and will briefly interrupt active games, voice calls, and ongoing connections. Proxy mode only covers web browsers (not Discord voice or most games).{adminNote}",
  confirmTunDesc:
    "Switching engines restarts protection and will briefly interrupt active games, voice calls, and ongoing connections while the full-PC TUN adapter starts.{adminNote}",
  confirmAdminWindows:
    " A Windows administrator prompt may appear to restart the background service.",
  confirmAdminMac:
    " A macOS administrator password prompt may appear to restart the background service.",
  confirmProxyBtn: "Switch to Proxy",
  confirmTunBtn: "Switch to TUN",
  cancel: "Cancel",
} as const;

type OverviewDict = Record<keyof typeof en, string>;

const tr: OverviewDict = {
  // Engine
  engineLabel: "Motor",
  engineTun: "TUN",
  engineProxy: "Proxy",
  engineDescTun:
    "Proxy ayarı gerektirmeden tüm uygulamaları, oyunları, Discord sesini (UDP) ve DNS'i kapsayan tam PC sanal bağdaştırıcısı.",
  engineDescProxy:
    "Web tarayıcıları ve proxy destekli TCP uygulamaları için 127.0.0.1 üzerinde yerel HTTP/SOCKS5 proxy (Discord sesini ve çoğu oyunu kapsamaz).",
  engineSwitchingTo: "{engine} motoruna geçiliyor...",
  engineSwitching: "Motor değiştiriliyor...",

  // Headlines
  headlineChecking: "Durum kontrol ediliyor...",
  headlineNotInstalled: "Servis Kurulu Değil",
  headlineYielded: "VPN'e Öncelik Verildi",
  headlineStarting: "Başlatılıyor...",
  headlineProtected: "Korunuyor",
  headlinePaused: "Duraklatıldı",

  // Subtitles
  subtitleReadingStatus: "Servis durumu okunuyor...",
  subtitleServiceRequired: "Arka plan servisi gerekli",
  subtitleAdminPrompt: "Yönetici onayı istenebilir",
  subtitleActiveTunnel: "Etkin tünel: {vpn}",
  subtitleAutoResumes: "VPN kesilince otomatik devam eder",
  subtitleTunAdapter: "TUN bağdaştırıcısı",
  subtitleLocalProxy: "Yerel proxy",
  subtitleWaitingTelemetry: "Canlı telemetri bekleniyor...",
  subtitleVia: "{iface} ({nic})",
  subtitleProtectionPaused: "Koruma duraklatıldı",
  subtitleServiceStopped: "Servis durduruldu",

  // Primary button
  btnSettingUp: "Kuruluyor...",
  btnConnecting: "Bağlanıyor...",
  btnPausing: "Duraklatılıyor...",
  btnUpdating: "Güncelleniyor...",
  btnChecking: "Kontrol ediliyor...",
  btnSetUpAndConnect: "Kur ve Bağlan",
  btnPause: "Duraklat",
  btnConnect: "Bağlan",

  // VPN conflict banner
  vpnYieldedTitle: "Etkin VPN'e öncelik verildi",
  vpnDetectedTitle: "Tam tünelli VPN algılandı",
  vpnYieldedDesc:
    "Etkin tam tünelli arayüz ({vpn}) algılandı. Yönlendirme çakışmalarını önlemek için koruma otomatik olarak duraklatıldı; VPN bağlantısı kesilince devam edecektir.",
  vpnWarnDesc:
    "Birlikte çalışma ayarı uyarı modundayken etkin tam tünelli arayüz ({vpn}) algılandı. Trafik VPN tünelini atlayabilir veya çakışabilir.",
  vpnRunningDesc:
    "Koruma çalışırken etkin tam tünelli arayüz ({vpn}) algılandı. Trafik VPN tünelini atlayabilir veya çakışabilir.",
  vpnIdleDesc:
    "Etkin tam tünelli arayüz ({vpn}) algılandı. Bu VPN etkinken bağlanılırsa koruma otomatik olarak öncelik verir.",
  vpnAction: "VPN Uyumu",

  // Wintun banner
  wintunInvalidTitle: "Tam PC sürücüsü geçersiz (wintun.dll)",
  wintunMissingTitle: "Tam PC sürücüsü eksik (wintun.dll)",
  wintunDetailWithNote:
    "{detail}. Proxy modu yalnızca web tarayıcılarını kapsar (Discord sesini veya oyunları değil).",
  wintunDefaultDesc:
    "Tam PC TUN koruması için wintun.dll dosyasını uygulama klasörüne yerleştirin. Proxy modu yalnızca web tarayıcılarını kapsar (Discord sesini veya oyunları değil).",
  wintunStillInvalid:
    "wintun.dll hâlâ geçersiz (karma doğrulaması başarısız). Resmi bir kopyayla değiştirip yeniden kontrol edin.",
  wintunStillMissing: "wintun.dll uygulama klasöründe hâlâ eksik.",
  wintunDetectedReady: "wintun.dll algılandı. Tam PC (TUN) modu hazır.",
  wintunRecheckError: "wintun.dll durumu yeniden kontrol edilemedi.",
  btnOpenAppFolder: "Uygulama Klasörünü Aç",
  btnRecheck: "Yeniden Kontrol Et",
  btnSwitchToProxy: "Proxy'ye Geç",

  // One-time setup banner
  setupRequiredTitle: "Tek seferlik kurulum gerekli",
  setupRequiredDesc:
    "Arka plan servisini kurmak ve korumayı başlatmak için yukarıdaki Kur ve Bağlan düğmesine tıklayın. Kurulumu onaylamak için yönetici istemi görünebilir.",
  btnOpenSettings: "Ayarları Aç",

  // Telemetry metrics
  metricsAria: "Canlı telemetri",
  metricSessionTransfer: "Oturum Aktarımı",
  metricTotal: "Toplam {value}",
  metricDns: "DNS",
  dnsSystemDefault: "Sistem varsayılanı",
  metricQueries: "{count} sorgu",
  metricConnections: "Bağlantılar",
  connAdaptive: "Uyarlamalı: {stage}",
  connMode: "Mod: {mode}",
  connAdaptiveReady: "Uyarlamalı hazır",
  connIdle: "Boşta",
  metricProtection: "Koruma",
  metricQuicBlocked: "{count} QUIC engellendi",
  splitAll: "Tünel: Tüm uygulamalar",
  splitExcludeOne: "Tünel: 1 hariç",
  splitExcludeMany: "Tünel: {count} hariç",
  splitIncludeOne: "Tünel: 1 dahil",
  splitIncludeMany: "Tünel: {count} dahil",

  // Chart card
  chartAria: "Veri akışı geçmişi",
  chartTitle: "Veri Akışı",
  chartCaption: "60 sn pencere",
  chartPausedSetup: "Kurulum gerekli",
  chartPausedDefault: "Koruma duraklatıldı",

  // Activity card
  activityAria: "Son etkinlikler",
  activityTitle: "Etkinlik",
  btnCopy: "Kopyala",
  btnCopied: "Kopyalandı",
  btnClear: "Temizle",
  activityEmpty: "Bu oturumda kayıtlı etkinlik yok.",
  catEngine: "Motor",
  catDns: "DNS",
  catVpn: "VPN",
  catSplit: "Tünel",
  catSystem: "Sistem",

  // Adaptive stages
  stageCombo: "Kombo",
  stageOobSni: "OOB SNI",
  stageMultiOob: "Çoklu + OOB",
  stageFineFragment: "İnce Parça",
  stageDeepStorm: "Derin Akış",
  stageSlowSni: "Yavaş SNI",
  stagePassthrough: "Doğrudan",

  // Engine switch dialog
  confirmProxyTitle: "Motor Proxy olarak değiştirilsin mi?",
  confirmTunTitle: "Motor TUN olarak değiştirilsin mi?",
  confirmProxyDesc:
    "Motor değiştirmek korumayı yeniden başlatır; etkin oyunlar, sesli aramalar ve mevcut bağlantılar kısa süreliğine kesilir. Proxy modu yalnızca web tarayıcılarını kapsar (Discord sesini veya çoğu oyunu değil).{adminNote}",
  confirmTunDesc:
    "Motor değiştirmek korumayı yeniden başlatır; tam PC TUN bağdaştırıcısı başlarken etkin oyunlar, sesli aramalar ve mevcut bağlantılar kısa süreliğine kesilir.{adminNote}",
  confirmAdminWindows:
    " Arka plan servisini yeniden başlatmak için Windows yönetici onayı istenebilir.",
  confirmAdminMac:
    " Arka plan servisini yeniden başlatmak için macOS yönetici parolası istenebilir.",
  confirmProxyBtn: "Proxy'ye Geç",
  confirmTunBtn: "TUN'a Geç",
  cancel: "İptal",
};

export const tOverview = createTranslator<OverviewDict>({ en, tr });

export function formatStageLabelLocalized(
  lang: ResolvedLanguage,
  stage: string,
): string {
  switch (stage) {
    case "ComboMultiRecord":
    case "Combo":
      return tOverview(lang, "stageCombo");
    case "OobSniDesync":
    case "OOB SNI":
      return tOverview(lang, "stageOobSni");
    case "MultiRecordOob":
    case "Multi + OOB":
      return tOverview(lang, "stageMultiOob");
    case "FineFragment":
    case "Fine Fragment":
      return tOverview(lang, "stageFineFragment");
    case "DeepRecordStorm":
    case "Deep Storm":
      return tOverview(lang, "stageDeepStorm");
    case "SlowSniSlice":
    case "Slow SNI":
      return tOverview(lang, "stageSlowSni");
    case "DirectPassthrough":
    case "Passthrough":
      return tOverview(lang, "stagePassthrough");
    default:
      return stage;
  }
}

export function localizeActivityMessage(
  lang: ResolvedLanguage,
  message: string,
): string {
  if (lang !== "tr") return message;

  switch (message) {
    case "Service not installed":
      return "Servis kurulu değil";
    case "Protection yielded to VPN":
      return "Koruma VPN'e öncelik verdi";
    case "Protection paused":
      return "Koruma duraklatıldı";
    case "ISP bypass stage reset":
      return "ISS aşma aşaması sıfırlandı";
    default:
      break;
  }

  const activeMatch = /^Protection active \((TUN|Proxy)\)$/.exec(message);
  if (activeMatch) {
    return `Koruma etkin (${activeMatch[1]})`;
  }

  const switchedMatch = /^Engine switched to (TUN|Proxy)$/.exec(message);
  if (switchedMatch) {
    return `Motor ${switchedMatch[1]} olarak değiştirildi`;
  }

  const vpnDetected = /^VPN conflict detected: (.+)$/.exec(message);
  if (vpnDetected) {
    return `VPN çakışması algılandı: ${vpnDetected[1]}`;
  }

  const vpnCleared = /^VPN conflict cleared \((.+)\)$/.exec(message);
  if (vpnCleared) {
    return `VPN çakışması giderildi (${vpnCleared[1]})`;
  }

  const stageMatch = /^ISP bypass stage: (.+)$/.exec(message);
  if (stageMatch) {
    return `ISS aşma aşaması: ${formatStageLabelLocalized("tr", stageMatch[1])}`;
  }

  return message;
}
