import type { DiagnosticCheckItem } from "../types";
import { createTranslator, type ResolvedLanguage } from "./context";

const en = {
  title: "Diagnostics",
    copyReport: "Copy Redacted Report",
    copied: "Copied",
    runDiagnostics: "Run Diagnostics",
    runningDiagnostics: "Running...",
    subtitleFallback: "Read-only network, DNS, and runtime health checks.",
    engineTun: "TUN engine",
    engineProxy: "Proxy engine",
    stateNotInstalled: "Service not installed",
    stateRunning: "Service running",
    stateStopped: "Service stopped",
    vpnDetected: "VPN detected ({iface})",
    readOnlyShort: "100% read-only",
    probeVpnLabel: "VPN coexistence",
    probeVpnDesc:
      "Detects active full-tunnel VPN adapters and routing conflicts.",
    probeWintunLabel: "Wintun driver",
    probeWintunDesc:
      "Verifies wintun.dll presence and SHA-256 integrity on disk.",
    probeDnsLabel: "DNS / DoH",
    probeDnsDesc:
      "Probes configured resolver reachability and encrypted DNS responses.",
    probeDiscordLabel: "Discord",
    probeDiscordDesc:
      "Checks Discord HTTPS gateway reachability and TLS latency.",
    probeRobloxLabel: "Roblox",
    probeRobloxDesc: "Tests Roblox client endpoints and connection latency.",
    probeRuntimeLabel: "Runtime hygiene",
    probeRuntimeDesc:
      "Inspects background service health, config state, and runtime files.",
    checkEncryptedDns: "Encrypted DNS (DoH)",
    checkUpstreamDns: "Upstream DNS (UDP)",
    statusIdle: "Idle",
    statusRunning: "Running",
    statusPass: "Pass",
    statusWarn: "Warn",
    statusFail: "Fail",
    errorFallback: "Unable to complete diagnostics. Try again in a moment.",
    clipboardUnavailable: "Clipboard API unavailable.",
    copyCommandFailed: "Copy command failed.",
    toastCopied: "Redacted diagnostics report copied to clipboard.",
    toastCopyFailed: "Failed to copy report: {message}",
    runErrorTitle: "Diagnostics failed to run",
    notInstalledBannerTitle: "Service not installed yet",
    notInstalledBannerDesc:
      "Probes test your direct connection until vdpi is installed. Open Installation to set up the background service.",
    notInstalledBannerAction: "Open Installation",
    retry: "Retry",
    allPassedTitle: "All checks passed ({passed}/{total})",
    allPassedDescWin:
      "Completed at {time} · All connectivity, driver, DNS, and runtime probes succeeded.",
    allPassedDescUnix:
      "Completed at {time} · All connectivity, DNS, and runtime probes succeeded.",
    failedTitle: "Diagnostics failed ({passed}/{total})",
    warnTitle: "Diagnostics finished with warnings ({passed}/{total})",
    issueFailedCount: "{count} failed",
    issueWarnOne: "1 warning",
    issueWarnMany: "{count} warnings",
    issueFallback: "one or more checks need attention",
    summaryIssueDesc:
      "Completed at {time} · {breakdown}. Review details below or copy the redacted report.",
    ariaRecoveryActions: "Recovery actions",
    suggestedActions: "Suggested actions",
    actionStarting: "Starting...",
    actionStartProtection: "Start Protection",
    actionInstallingService: "Installing...",
    actionInstallService: "Install Service",
    actionOpenInstallation: "Open Installation",
    actionGoOverview: "Go to Overview",
    actionSwitchingProxy: "Switching to Proxy...",
    actionSwitchProxy: "Switch to Proxy",
    actionOpenSettings: "Open Settings",
    actionOpenAppFolder: "Open App Folder",
    actionOpenLogs: "Open Logs",
    runningCardTitle: "Running diagnostics...",
    runningCardDescWin:
      "Probing VPN coexistence, Wintun driver, DNS/DoH, Discord, Roblox, and runtime hygiene. This is read-only and will not interrupt active connections.",
    runningCardDescUnix:
      "Probing VPN coexistence, DNS/DoH, Discord, Roblox, and runtime hygiene. This is read-only and will not interrupt active connections.",
    ariaResultsCard: "Diagnostic check results",
    resultsTitle: "Check Results",
    statusChangedNote: "Status changed since last run",
    refreshingProbes: "Refreshing probes...",
    ranAtOne: "Ran at {time} · {count} check",
    ranAtMany: "Ran at {time} · {count} checks",
    colCheck: "Check",
    colTarget: "Target",
    colLatency: "Latency",
    colStatus: "Status",
    previewReport: "Preview redacted report",
    hide: "Hide",
    show: "Show",
    privacyNote:
      "Redacted report strips custom DoH tokens, credentials, private LAN IPs, and user home paths.",
    ariaEmptyCard: "Diagnostics overview",
    emptyTitle: "Ready to run diagnostics",
    emptyDesc:
      "Run a quick end-to-end health check to verify your network environment and vdpi setup. Probes are strictly read-only and never alter configuration, routes, or running services.",
    readonlyBadge: "100% read-only & non-destructive",
    ariaChecksIncluded: "Checks included",
};

export type DiagnosticsStringKey = keyof typeof en;

const tr: Record<DiagnosticsStringKey, string> = {
    title: "Tanılama",
    copyReport: "Maskeli Raporu Kopyala",
    copied: "Kopyalandı",
    runDiagnostics: "Tanılamayı Çalıştır",
    runningDiagnostics: "Çalıştırılıyor...",
    subtitleFallback: "Salt okunur ağ, DNS ve çalışma durumu denetimleri.",
    engineTun: "TUN motoru",
    engineProxy: "Proxy motoru",
    stateNotInstalled: "Hizmet kurulu değil",
    stateRunning: "Hizmet çalışıyor",
    stateStopped: "Hizmet durduruldu",
    vpnDetected: "VPN algılandı ({iface})",
    readOnlyShort: "%100 salt okunur",
    probeVpnLabel: "VPN uyumluluğu",
    probeVpnDesc:
      "Etkin tam tünelli VPN bağdaştırıcılarını ve yönlendirme çakışmalarını algılar.",
    probeWintunLabel: "Wintun sürücüsü",
    probeWintunDesc:
      "Diskte wintun.dll varlığını ve SHA-256 bütünlüğünü doğrular.",
    probeDnsLabel: "DNS / DoH",
    probeDnsDesc:
      "Yapılandırılan sunucunun erişilebilirliğini ve şifreli DNS yanıtlarını test eder.",
    probeDiscordLabel: "Discord",
    probeDiscordDesc:
      "Discord HTTPS ağ geçidi erişilebilirliğini ve TLS gecikmesini kontrol eder.",
    probeRobloxLabel: "Roblox",
    probeRobloxDesc:
      "Roblox istemci uç noktalarını ve bağlantı gecikmesini test eder.",
    probeRuntimeLabel: "Çalışma durumu",
    probeRuntimeDesc:
      "Arka plan hizmeti sağlığını, yapılandırma durumunu ve çalışma dosyalarını inceler.",
    checkEncryptedDns: "Şifreli DNS (DoH)",
    checkUpstreamDns: "Üst DNS (UDP)",
    statusIdle: "Boşta",
    statusRunning: "Çalışıyor",
    statusPass: "Geçti",
    statusWarn: "Uyarı",
    statusFail: "Hata",
    errorFallback: "Tanılama tamamlanamadı. Birazdan tekrar deneyin.",
    clipboardUnavailable: "Pano API'si kullanılamıyor.",
    copyCommandFailed: "Kopyalama komutu başarısız oldu.",
    toastCopied: "Maskelenmiş tanılama raporu panoya kopyalandı.",
    toastCopyFailed: "Rapor kopyalanamadı: {message}",
    runErrorTitle: "Tanılama çalıştırılamadı",
    notInstalledBannerTitle: "Servis henüz kurulmadı",
    notInstalledBannerDesc:
      "vdpi kurulana kadar denetimler doğrudan bağlantınızı test eder. Arka plan servisini kurmak için Kurulum sekmesini açın.",
    notInstalledBannerAction: "Kuruluma Git",
    retry: "Tekrar Dene",
    allPassedTitle: "Tüm denetimler geçti ({passed}/{total})",
    allPassedDescWin:
      "{time} itibarıyla tamamlandı · Tüm bağlantı, sürücü, DNS ve çalışma denetimleri başarılı.",
    allPassedDescUnix:
      "{time} itibarıyla tamamlandı · Tüm bağlantı, DNS ve çalışma denetimleri başarılı.",
    failedTitle: "Tanılama başarısız ({passed}/{total})",
    warnTitle: "Tanılama uyarılarla tamamlandı ({passed}/{total})",
    issueFailedCount: "{count} başarısız",
    issueWarnOne: "1 uyarı",
    issueWarnMany: "{count} uyarı",
    issueFallback: "bir veya daha fazla denetim ilgi gerektiriyor",
    summaryIssueDesc:
      "{time} itibarıyla tamamlandı · {breakdown}. Aşağıdaki ayrıntıları inceleyin veya maskeli raporu kopyalayın.",
    ariaRecoveryActions: "Kurtarma eylemleri",
    suggestedActions: "Önerilen eylemler",
    actionStarting: "Başlatılıyor...",
    actionStartProtection: "Korumayı Başlat",
    actionInstallingService: "Kuruluyor...",
    actionInstallService: "Servisi Kur",
    actionOpenInstallation: "Kuruluma Git",
    actionGoOverview: "Genel Bakışa Git",
    actionSwitchingProxy: "Proxy'ye Geçiliyor...",
    actionSwitchProxy: "Proxy'ye Geç",
    actionOpenSettings: "Ayarları Aç",
    actionOpenAppFolder: "Uygulama Klasörünü Aç",
    actionOpenLogs: "Günlükleri Aç",
    runningCardTitle: "Tanılama çalıştırılıyor...",
    runningCardDescWin:
      "VPN uyumluluğu, Wintun sürücüsü, DNS/DoH, Discord, Roblox ve çalışma durumu test ediliyor. Bu işlem salt okunurdur ve etkin bağlantıları kesmez.",
    runningCardDescUnix:
      "VPN uyumluluğu, DNS/DoH, Discord, Roblox ve çalışma durumu test ediliyor. Bu işlem salt okunurdur ve etkin bağlantıları kesmez.",
    ariaResultsCard: "Tanılama denetim sonuçları",
    resultsTitle: "Denetim Sonuçları",
    statusChangedNote: "Son çalıştırmadan beri durum değişti",
    refreshingProbes: "Denetimler yenileniyor...",
    ranAtOne: "{time} · {count} denetim",
    ranAtMany: "{time} · {count} denetim",
    colCheck: "Denetim",
    colTarget: "Hedef",
    colLatency: "Gecikme",
    colStatus: "Durum",
    previewReport: "Maskeli raporu önizle",
    hide: "Gizle",
    show: "Göster",
    privacyNote:
      "Maskeli rapor özel DoH belirteçlerini, kimlik bilgilerini, yerel LAN IP'lerini ve kullanıcı klasör yollarını temizler.",
    ariaEmptyCard: "Tanılama özeti",
    emptyTitle: "Tanılamayı çalıştırmaya hazır",
    emptyDesc:
      "Ağ ortamınızı ve vdpi kurulumunuzu doğrulamak için hızlı bir uçtan uca sağlık denetimi çalıştırın. Denetimler tamamen salt okunurdur; yapılandırmayı, rotaları veya çalışan hizmetleri değiştirmez.",
    readonlyBadge: "%100 salt okunur ve güvenli",
    ariaChecksIncluded: "Dahil edilen denetimler",
};

export const DIAGNOSTICS_STRINGS: {
  en: Record<DiagnosticsStringKey, string>;
  tr: Record<DiagnosticsStringKey, string>;
} = { en, tr };

export const tDiagnostics = createTranslator(DIAGNOSTICS_STRINGS);

const CHECK_NAME_KEY_MAP: Record<string, DiagnosticsStringKey> = {
  "vpn coexistence": "probeVpnLabel",
  "wintun driver": "probeWintunLabel",
  "dns / doh": "probeDnsLabel",
  "encrypted dns (doh)": "checkEncryptedDns",
  "upstream dns (udp)": "checkUpstreamDns",
  discord: "probeDiscordLabel",
  roblox: "probeRobloxLabel",
  "runtime hygiene": "probeRuntimeLabel",
};

export function localizeCheckName(
  lang: ResolvedLanguage,
  check: DiagnosticCheckItem,
): string {
  if (lang === "en") return check.name;
  const key = CHECK_NAME_KEY_MAP[check.name.trim().toLowerCase()];
  return key ? tDiagnostics(lang, key) : check.name;
}
